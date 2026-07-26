#!/usr/bin/env node
//
// Item 8 PR-D — CT merge, active-workspace scheduling, and authenticated
// bounded manual passive discovery. DB-backed and CI-blocking; no network.
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = (...parts) => pathToFileURL(path.join(root, "workers", "scan-api", "src", ...parts)).href;
const {
  BRAND_CT_QUERY_CAP,
  BRAND_CT_RESPONSE_MAX_BYTES,
  discoverBrandCandidatesForWorkspace,
  runBrandPassiveDiscoverySweep,
} = await import(src("engines", "brand-passive-discovery.js"));
const {
  BRAND_MANUAL_DISCOVERY_BURST_LIMIT,
  BRAND_MANUAL_DISCOVERY_HOURLY_LIMIT,
  BRAND_MANUAL_DISCOVERY_TIMEOUT_MS,
  brandRoutes,
} = await import(src("routes", "brand.js"));
const { upsertBrandAssets } = await import(src("engines", "asset-persistence.js"));
const { brandCandidateToApi } = await import(src("engines", "brand-protection.js"));
const { consumeApiRateLimit } = await import(src("lib", "rate-limit.js"));

let pass = 0, fail = 0;
const ok = (name, condition, detail = "") => {
  if (condition) pass++;
  else { fail++; console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
};
const eq = (name, got, want) => ok(
  name,
  JSON.stringify(got) === JSON.stringify(want),
  `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`,
);

function createDb() {
  const db = new DatabaseSync(":memory:");
  db.exec(`
    CREATE TABLE workspaces (
      id TEXT PRIMARY KEY, owner_user_id TEXT, name TEXT, deleted_at TEXT
    );
    CREATE TABLE domains (
      id TEXT PRIMARY KEY, domain TEXT, created_at TEXT
    );
    CREATE TABLE workspace_domains (
      workspace_id TEXT, domain_id TEXT, verification_status TEXT
    );
    CREATE TABLE workspace_brand_profiles (
      id TEXT PRIMARY KEY, workspace_id TEXT UNIQUE, brand_name TEXT,
      primary_domain TEXT, keywords_json TEXT, protected_domains_json TEXT,
      created_at TEXT, updated_at TEXT
    );
    CREATE TABLE workspace_brand_assets (
      id TEXT PRIMARY KEY, workspace_id TEXT, domain TEXT, candidate_domain TEXT,
      variant_type TEXT, similarity_score INTEGER, risk_level TEXT,
      risk_reasons TEXT, evidence_json TEXT, dns_resolves INTEGER,
      https_available INTEGER, mx_present INTEGER, ip_address TEXT, status TEXT,
      classification TEXT, brand_profile_id TEXT, first_seen TEXT, last_seen TEXT,
      last_checked_at TEXT, registrar_or_whois_summary TEXT,
      managed_case_ref TEXT, campaign_ref TEXT, customer_validation TEXT,
      customer_disposition TEXT, history_marker TEXT,
      created_at TEXT, updated_at TEXT,
      UNIQUE(workspace_id, domain, candidate_domain)
    );
    CREATE TABLE audit_events (
      id TEXT PRIMARY KEY, workspace_id TEXT, user_id TEXT, actor_type TEXT,
      event_type TEXT, entity_type TEXT, entity_id TEXT, description TEXT,
      metadata_json TEXT, created_at TEXT
    );
    CREATE TABLE api_rate_limits (
      id TEXT PRIMARY KEY, scope TEXT, scope_id TEXT, action TEXT,
      window_start TEXT, window_seconds INTEGER, request_count INTEGER,
      created_at TEXT, updated_at TEXT
    );
    CREATE TABLE managed_cases (
      id TEXT PRIMARY KEY, workspace_id TEXT, case_type TEXT, finding_id TEXT,
      status TEXT, evidence_json TEXT, created_at TEXT, updated_at TEXT
    );
    CREATE TABLE managed_case_events (
      id TEXT PRIMARY KEY, case_id TEXT, workspace_id TEXT, action TEXT,
      detail_json TEXT, created_at TEXT
    );
    CREATE TABLE brand_abuse_campaigns (
      id TEXT PRIMARY KEY, workspace_id TEXT, brand_profile_id TEXT,
      linked_domains TEXT, linked_ips TEXT, first_seen_at TEXT,
      last_seen_at TEXT, created_at TEXT, updated_at TEXT
    );
    CREATE TABLE brand_evidence_bundles (
      id TEXT PRIMARY KEY, workspace_id TEXT, case_id TEXT, version INTEGER,
      content_hash TEXT, bundle_json TEXT, captured_at TEXT, created_at TEXT
    );
    CREATE TABLE notification_events (
      id TEXT PRIMARY KEY, workspace_id TEXT, type TEXT, created_at TEXT
    );
  `);
  return db;
}

function d1(db, intercept = null) {
  return {
    prepare(sql) {
      if (intercept) {
        const replacement = intercept(sql);
        if (replacement) return replacement;
      }
      const statement = db.prepare(sql);
      const bound = (...args) => ({
        all: async () => ({ results: statement.all(...args) }),
        first: async () => statement.get(...args) ?? null,
        run: async () => statement.run(...args),
      });
      return {
        bind: (...args) => bound(...args),
        all: async () => ({ results: statement.all() }),
        first: async () => statement.get() ?? null,
        run: async () => statement.run(),
      };
    },
  };
}

function seedWorkspace(db, {
  id = "ws1",
  domainId = "d1",
  domain = "qevlaxom.com",
  deletedAt = null,
  verified = true,
  profile = true,
} = {}) {
  db.prepare("INSERT INTO workspaces VALUES (?,?,?,?)")
    .run(id, `owner_${id}`, id, deletedAt);
  db.prepare("INSERT INTO domains VALUES (?,?,?)")
    .run(domainId, domain, "2026-01-01T00:00:00Z");
  db.prepare("INSERT INTO workspace_domains VALUES (?,?,?)")
    .run(id, domainId, verified ? "verified" : "unverified");
  if (profile) {
    db.prepare("INSERT INTO workspace_brand_profiles VALUES (?,?,?,?,?,?,?,?)")
      .run(`profile_${id}`, id, domain.split(".")[0], domain, "[]",
        JSON.stringify([domain]), "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z");
  }
}

function seedCandidate(db, {
  id = "bra_existing",
  workspaceId = "ws1",
  domain = "qevlaxom.com",
  candidate = "xn--evlaxom-ryh.com",
  classification = "unreviewed",
  riskLevel = "low",
  evidence = [
    { signal: "generated_only", value: true },
    { signal: "unrelated_historical_evidence", value: "retain" },
  ],
  firstSeen = "2026-01-01T00:00:00Z",
  lastSeen = "2026-01-02T00:00:00Z",
} = {}) {
  db.prepare(`
    INSERT INTO workspace_brand_assets
      (id, workspace_id, domain, candidate_domain, variant_type,
       similarity_score, risk_level, risk_reasons, evidence_json,
       dns_resolves, https_available, mx_present, status, classification,
       first_seen, last_seen, managed_case_ref, campaign_ref,
       customer_validation, customer_disposition, history_marker,
       created_at, updated_at)
    VALUES (?,?,?,?,?,100,?,?,?,NULL,NULL,NULL,'unverified',?,?,?,?,?,?,?,?,?,?)
  `).run(
    id, workspaceId, domain, candidate, "homoglyph_idn", riskLevel,
    JSON.stringify(["not_registered_watchlist", "unrelated_customer_context"]),
    JSON.stringify(evidence), classification, firstSeen, lastSeen,
    "case_keep", "campaign_keep", "validated_by_customer", "customer_keep",
    "history_keep", firstSeen, lastSeen,
  );
}

function ctEntry(id = 501) {
  return {
    id,
    name_value: "ԛevlaxom.com\nxn--evlaxom-ryh.com",
    common_name: "xn--evlaxom-ryh.com",
    serial_number: "AA501",
    issuer_name: "Controlled Test CA",
    entry_timestamp: "2026-07-26T12:00:00Z",
    not_before: "2026-07-26T11:59:00Z",
    not_after: "2026-10-24T11:59:00Z",
  };
}

function ctFetch(body = [ctEntry()]) {
  return async () => ({
    ok: true,
    headers: { get: (name) => name === "content-type" ? "application/json" : null },
    json: async () => body,
  });
}

// ── B1: collision merge, canonical dedupe, monotonicity, preservation ───────
{
  const db = createDb();
  seedWorkspace(db);
  seedCandidate(db);
  db.prepare("INSERT INTO managed_cases VALUES (?,?,?,?,?,?,?,?)")
    .run("case_keep", "ws1", "brand_abuse", "bra_existing", "monitoring",
      '{"historical":true}', "2026-01-03T00:00:00Z", "2026-01-03T00:00:00Z");
  db.prepare("INSERT INTO managed_case_events VALUES (?,?,?,?,?,?)")
    .run("event_keep", "case_keep", "ws1", "case_opened",
      '{"campaign_id":"campaign_keep"}', "2026-01-03T00:00:00Z");
  db.prepare("INSERT INTO brand_abuse_campaigns VALUES (?,?,?,?,?,?,?,?,?)")
    .run("campaign_keep", "ws1", "profile_ws1",
      '["xn--evlaxom-ryh.com"]', "[]", "2026-01-03T00:00:00Z",
      "2026-01-03T00:00:00Z", "2026-01-03T00:00:00Z", "2026-01-03T00:00:00Z");
  db.prepare("INSERT INTO brand_evidence_bundles VALUES (?,?,?,?,?,?,?,?)")
    .run("bundle_keep", "ws1", "case_keep", 1, "hash_keep",
      '{"historical":true}', "2026-01-03T00:00:00Z", "2026-01-03T00:00:00Z");
  const linkedHistoryBefore = {
    cases: db.prepare("SELECT * FROM managed_cases").all(),
    events: db.prepare("SELECT * FROM managed_case_events").all(),
    campaigns: db.prepare("SELECT * FROM brand_abuse_campaigns").all(),
    bundles: db.prepare("SELECT * FROM brand_evidence_bundles").all(),
  };
  const env = { cybermeters_db: d1(db) };
  const stats = await discoverBrandCandidatesForWorkspace(env, "ws1", {
    fetchImpl: ctFetch(),
    now: "2026-07-26T13:00:00Z",
  });
  const row = db.prepare("SELECT * FROM workspace_brand_assets WHERE id='bra_existing'").get();
  const evidence = JSON.parse(row.evidence_json);
  const reasons = JSON.parse(row.risk_reasons);
  eq("B1 collision keeps one canonical row",
    db.prepare("SELECT COUNT(*) n FROM workspace_brand_assets WHERE workspace_id='ws1' AND candidate_domain='xn--evlaxom-ryh.com'").get().n, 1);
  eq("B1 collision keeps candidate id", row.id, "bra_existing");
  eq("B1 Unicode/A-label pair merges once", stats.observed, 1);
  eq("B1 existing row counted as merged, not inserted", [stats.inserted, stats.merged], [0, 1]);
  ok("B1 adds ct_observed", evidence.some((item) => item.signal === "ct_observed" && item.value === true));
  eq("B1 adds one stable CT metadata entry",
    evidence.filter((item) => item.signal === "ct_observation").length, 1);
  ok("B1 retains unrelated historical evidence",
    evidence.some((item) => item.signal === "unrelated_historical_evidence" && item.value === "retain"));
  ok("B1 retains unrelated risk reason", reasons.includes("unrelated_customer_context"));
  eq("B1 CT-only IDN stays low", row.risk_level, "low");
  eq("B1 preserves first_seen exactly", row.first_seen, "2026-01-01T00:00:00Z");
  eq("B1 refreshes last_seen", row.last_seen, "2026-07-26T13:00:00Z");
  eq("B1 preserves case/campaign/customer/history fields",
    [row.managed_case_ref, row.campaign_ref, row.customer_validation,
      row.customer_disposition, row.history_marker],
    ["case_keep", "campaign_keep", "validated_by_customer", "customer_keep", "history_keep"]);

  const evidenceOnce = row.evidence_json;
  await discoverBrandCandidatesForWorkspace(env, "ws1", {
    fetchImpl: ctFetch(),
    now: "2026-07-26T13:00:00Z",
  });
  const repeatSame = db.prepare("SELECT * FROM workspace_brand_assets WHERE id='bra_existing'").get();
  eq("B1 identical repeat leaves evidence byte-idempotent", repeatSame.evidence_json, evidenceOnce);
  eq("B1 identical repeat leaves one CT metadata entry",
    JSON.parse(repeatSame.evidence_json).filter((item) => item.signal === "ct_observation").length, 1);
  await discoverBrandCandidatesForWorkspace(env, "ws1", {
    fetchImpl: ctFetch([{ ...ctEntry(), issuer_name: "Changed upstream rendering" }]),
    now: "2026-07-26T13:00:00Z",
  });
  const repeatSameIdentity = db.prepare(
    "SELECT evidence_json FROM workspace_brand_assets WHERE id='bra_existing'",
  ).get();
  eq("B1 stable CT identity dedupes upstream metadata rendering changes",
    repeatSameIdentity.evidence_json, evidenceOnce);
  await discoverBrandCandidatesForWorkspace(env, "ws1", {
    fetchImpl: ctFetch(),
    now: "2026-07-27T13:00:00Z",
  });
  const repeatLater = db.prepare("SELECT * FROM workspace_brand_assets WHERE id='bra_existing'").get();
  eq("B1 later repeat advances last_seen monotonically", repeatLater.last_seen, "2026-07-27T13:00:00Z");
  eq("B1 later repeat still leaves evidence byte-idempotent", repeatLater.evidence_json, evidenceOnce);
  eq("B1 repeated CT leaves canonical case/event/campaign/bundle history byte-stable", {
    cases: db.prepare("SELECT * FROM managed_cases").all(),
    events: db.prepare("SELECT * FROM managed_case_events").all(),
    campaigns: db.prepare("SELECT * FROM brand_abuse_campaigns").all(),
    bundles: db.prepare("SELECT * FROM brand_evidence_bundles").all(),
  }, linkedHistoryBefore);
  eq("B1 repeated CT creates no alert side effect",
    db.prepare("SELECT COUNT(*) n FROM notification_events").get().n, 0);
}

// The scan/generated path reuses the same merge and cannot erase CT evidence.
{
  const db = createDb();
  seedWorkspace(db);
  seedCandidate(db, {
    evidence: [
      { signal: "ct_observed", value: true },
      { signal: "ct_observation", value: { source: "crt.sh", entry_id: "501" } },
      { signal: "unrelated_historical_evidence", value: "retain" },
    ],
  });
  await upsertBrandAssets("d1", {
    domains: [{
      candidate_domain: "xn--evlaxom-ryh.com",
      variant_type: "homoglyph_idn",
    }],
  }, { cybermeters_db: d1(db) });
  const row = db.prepare("SELECT id,evidence_json FROM workspace_brand_assets").get();
  const evidence = JSON.parse(row.evidence_json);
  eq("B1 generated scan reuses canonical row", row.id, "bra_existing");
  ok("B1 generated scan cannot erase CT evidence",
    evidence.some((item) => item.signal === "ct_observed" && item.value === true) &&
    evidence.some((item) => item.signal === "ct_observation" && item.value.entry_id === "501"));
  ok("B1 generated scan preserves unrelated history",
    evidence.some((item) => item.signal === "unrelated_historical_evidence"));
}

// Upstream response bytes are bounded before JSON parsing.
{
  const db = createDb();
  seedWorkspace(db);
  const stats = await discoverBrandCandidatesForWorkspace(
    { cybermeters_db: d1(db) }, "ws1",
    {
      fetchImpl: async () => ({
        ok: true,
        headers: { get: (name) => name === "content-type"
          ? "application/json"
          : String(BRAND_CT_RESPONSE_MAX_BYTES + 1) },
        text: async () => { throw new Error("oversized_body_should_not_be_read"); },
      }),
    },
  );
  eq("B2a CT response-byte cap is pinned", BRAND_CT_RESPONSE_MAX_BYTES, 1_000_000);
  ok("B2a oversized upstream responses fail incomplete",
    stats.failed === BRAND_CT_QUERY_CAP && stats.incomplete === true && stats.observed === 0);
}

// Customer decisions always outrank the engine observation.
for (const classification of ["suspicious", "owned", "benign", "false_positive", "dismissed"]) {
  const db = createDb();
  seedWorkspace(db);
  seedCandidate(db, {
    classification,
    riskLevel: ["owned", "benign", "false_positive", "dismissed"].includes(classification)
      ? "info" : "high",
  });
  const before = db.prepare("SELECT * FROM workspace_brand_assets").get();
  await discoverBrandCandidatesForWorkspace(
    { cybermeters_db: d1(db) }, "ws1",
    { fetchImpl: ctFetch(), now: "2026-07-26T13:00:00Z" },
  );
  const after = db.prepare("SELECT * FROM workspace_brand_assets").get();
  eq(`B1 ${classification} classification preserved`, after.classification, classification);
  ok(`B1 ${classification} receives CT evidence`,
    JSON.parse(after.evidence_json).some((item) => item.signal === "ct_observed" && item.value === true));
  if (["owned", "benign", "false_positive", "dismissed"].includes(classification)) {
    eq(`B1 ${classification} protected risk remains unchanged`, after.risk_level, before.risk_level);
    eq(`B1 ${classification} protected reasons remain unchanged`, after.risk_reasons, before.risk_reasons);
    const api = brandCandidateToApi(after, {
      brand_name: "qevlaxom",
      primary_domain: "qevlaxom.com",
    });
    eq(`B1 ${classification} stays protected at the API boundary`,
      [api.classification, api.risk_level, api.action_required],
      [classification, "info", false]);
  }
  eq(`B1 ${classification} keeps linked history`,
    [after.managed_case_ref, after.campaign_ref, after.history_marker],
    ["case_keep", "campaign_keep", "history_keep"]);
}

// Malformed/incomplete CT rows cannot create positive evidence.
{
  const db = createDb();
  seedWorkspace(db);
  seedCandidate(db);
  const before = db.prepare("SELECT evidence_json,last_seen FROM workspace_brand_assets").get();
  const stats = await discoverBrandCandidatesForWorkspace(
    { cybermeters_db: d1(db) }, "ws1",
    { fetchImpl: ctFetch([{ name_value: "xn--evlaxom-ryh.com" }]), now: "2026-07-26T13:00:00Z" },
  );
  const after = db.prepare("SELECT evidence_json,last_seen FROM workspace_brand_assets").get();
  eq("B1 incomplete CT row is not observed", stats.observed, 0);
  ok("B1 incomplete CT row is reported as skipped/incomplete",
    stats.skipped > 0 && stats.incomplete === true);
  eq("B1 incomplete CT row adds no evidence", after, before);
}

// A failed guarded write cannot leave a half-positive row.
{
  const db = createDb();
  seedWorkspace(db);
  seedCandidate(db);
  const before = db.prepare("SELECT evidence_json,risk_level,last_seen FROM workspace_brand_assets").get();
  const env = {
    cybermeters_db: d1(db, (sql) => sql.trim().startsWith("UPDATE workspace_brand_assets")
      ? { bind: () => ({ run: async () => { throw new Error("forced_write_failure"); } }) }
      : null),
  };
  const stats = await discoverBrandCandidatesForWorkspace(env, "ws1", {
    fetchImpl: ctFetch(),
    now: "2026-07-26T13:00:00Z",
  });
  const after = db.prepare("SELECT evidence_json,risk_level,last_seen FROM workspace_brand_assets").get();
  ok("B1 transaction/error path reports failure", stats.failed > 0 && stats.incomplete);
  eq("B1 transaction/error path leaves no partial positive state", after, before);
}

// ── B2b: active workspace eligibility precedes top-N selection ──────────────
{
  const db = createDb();
  seedWorkspace(db, { id: "ws_active", domainId: "da", domain: "acme.com" });
  seedWorkspace(db, {
    id: "ws_deleted", domainId: "dd", domain: "deleted.com",
    deletedAt: "2026-07-25T00:00:00Z",
  });
  for (let i = 0; i < 2; i++) {
    seedCandidate(db, {
      id: `active_${i}`, workspaceId: "ws_active", domain: "acme.com",
      candidate: `candidate${i}.acme.co`,
    });
  }
  for (let i = 0; i < 8; i++) {
    seedCandidate(db, {
      id: `deleted_${i}`, workspaceId: "ws_deleted", domain: "deleted.com",
      candidate: `candidate${i}.deleted.net`,
    });
  }
  const fetched = [];
  const sweep = await runBrandPassiveDiscoverySweep(
    { cybermeters_db: d1(db) },
    {
      workspacesPerDay: 1,
      fetchImpl: async (url) => {
        fetched.push(decodeURIComponent(url));
        return { ok: true, headers: { get: () => "application/json" }, json: async () => [] };
      },
    },
  );
  eq("B2b one active workspace consumes the bounded slot", sweep.workspaces, 1);
  ok("B2b active workspace is fetched", fetched.some((url) => url.includes("acme")));
  ok("B2b deleted high-count workspace gets no CT fetch", fetched.every((url) => !url.includes("deleted")));
  eq("B2b deleted tenant does not displace active tenant", sweep.skipped_workspaces, 0);
  eq("B2b deleted tenant receives no persistence",
    db.prepare("SELECT COUNT(*) n FROM workspace_brand_assets WHERE workspace_id='ws_deleted'").get().n, 8);
}

function routeContext(db, {
  workspaceId = "ws_route",
  authenticated = true,
  member = true,
  rateLimit = async () => null,
} = {}) {
  const request = new Request(
    `https://api.example/api/workspaces/${workspaceId}/brand/discovery`,
    { method: "POST" },
  );
  return {
    request,
    url: new URL(request.url),
    env: { cybermeters_db: d1(db) },
    json: (body, status = 200) => Response.json(body, { status }),
    requireAuth: async () => authenticated ? { id: "user_route" } : null,
    requireWorkspaceRole: async () => member ? { role: "analyst" } : null,
    consumeApiRateLimit: rateLimit,
  };
}

// ── B2a: auth, tenant, active/profile/domain gates ───────────────────────────
{
  const db = createDb();
  seedWorkspace(db, { id: "ws_route", domainId: "dr" });
  eq("B2a unauthenticated request denied",
    (await brandRoutes(routeContext(db, { authenticated: false }))).status, 401);
  eq("B2a non-member/cross-tenant request denied without lookup",
    (await brandRoutes(routeContext(db, { member: false }))).status, 403);
}
{
  const db = createDb();
  seedWorkspace(db, {
    id: "ws_deleted", domainId: "dd", deletedAt: "2026-07-25T00:00:00Z",
  });
  let fetches = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => { fetches++; return new Response("[]"); };
  const response = await brandRoutes(routeContext(db, { workspaceId: "ws_deleted" }));
  globalThis.fetch = originalFetch;
  eq("B2a soft-deleted workspace denied", response.status, 404);
  eq("B2a soft-deleted workspace causes no CT fetch", fetches, 0);
}
{
  const db = createDb();
  seedWorkspace(db, { id: "ws_route", domainId: "dr", profile: false });
  eq("B2a persisted Brand profile required",
    (await brandRoutes(routeContext(db))).status, 409);
}
{
  const db = createDb();
  seedWorkspace(db, { id: "ws_route", domainId: "dr", verified: false });
  eq("B2a canonical verified-domain entitlement required",
    (await brandRoutes(routeContext(db))).status, 403);
}

// Valid route: same engine, bounded fan-out, B1 merge, honest result and audit.
{
  const db = createDb();
  seedWorkspace(db, { id: "ws_route", domainId: "dr" });
  seedCandidate(db, { workspaceId: "ws_route" });
  const rateCalls = [];
  const originalFetch = globalThis.fetch;
  let fetches = 0;
  globalThis.fetch = async () => {
    fetches++;
    return new Response(JSON.stringify([ctEntry()]), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  const response = await brandRoutes(routeContext(db, {
    rateLimit: async (...args) => { rateCalls.push(args); return null; },
  }));
  const body = await response.json();
  globalThis.fetch = originalFetch;
  eq("B2a authorised active workspace succeeds", response.status, 200);
  ok("B2a fan-out is bounded", fetches > 0 && fetches <= BRAND_CT_QUERY_CAP, `fetches=${fetches}`);
  eq("B2a B1 merge is reported honestly", [body.inserted, body.merged], [0, 1]);
  eq("B2a summary exposes required fields",
    ["attempted", "observed", "inserted", "merged", "updated", "excluded",
      "skipped", "failed", "partial", "incomplete"].every((key) => key in body), true);
  eq("B2a exact bounds are returned",
    body.bounds,
    { query_cap: 4, candidate_cap: 50, timeout_ms_per_query: 2500, retries: 0 });
  ok("B2a route invokes fail-closed atomic burst and hourly guards",
    rateCalls.length === 2 &&
    rateCalls.every((call) => call[5]?.failClosed === true && call[5]?.atomic === true) &&
    rateCalls[0][3] === BRAND_MANUAL_DISCOVERY_BURST_LIMIT &&
    rateCalls[1][3] === BRAND_MANUAL_DISCOVERY_HOURLY_LIMIT);
  eq("B2a configured per-query deadline is pinned", BRAND_MANUAL_DISCOVERY_TIMEOUT_MS, 2500);
  ok("B2a response preserves non-verdict wording",
    /not proof of abuse/i.test(body.evidence_boundary) &&
    !/confirmed phishing|malicious/i.test(JSON.stringify(body)));
  const audits = db.prepare("SELECT event_type,metadata_json FROM audit_events ORDER BY created_at,id").all();
  ok("B2a request and completion are audited",
    audits.some((row) => row.event_type === "brand_passive_discovery_requested") &&
    audits.some((row) => row.event_type === "brand_passive_discovery_completed"));
  ok("B2a audit metadata contains no secrets",
    audits.every((row) => !/token|secret|authorization|certificate body/i.test(row.metadata_json || "")));
  eq("B2a discovery creates no managed case",
    db.prepare("SELECT COUNT(*) n FROM managed_cases").get().n, 0);
  eq("B2a discovery sends no notification",
    db.prepare("SELECT COUNT(*) n FROM notification_events").get().n, 0);

  const evidenceOnce = db.prepare("SELECT evidence_json FROM workspace_brand_assets WHERE id='bra_existing'").get().evidence_json;
  globalThis.fetch = async () => new Response(JSON.stringify([ctEntry()]), {
    status: 200, headers: { "content-type": "application/json" },
  });
  const second = await brandRoutes(routeContext(db));
  globalThis.fetch = originalFetch;
  eq("B2a duplicate invocation succeeds idempotently", second.status, 200);
  eq("B2a duplicate invocation creates no candidate",
    db.prepare("SELECT COUNT(*) n FROM workspace_brand_assets WHERE id='bra_existing'").get().n, 1);
  eq("B2a duplicate invocation does not duplicate evidence",
    db.prepare("SELECT evidence_json FROM workspace_brand_assets WHERE id='bra_existing'").get().evidence_json,
    evidenceOnce);
}

// Partial and total upstream failure are not rendered as empty/healthy success.
{
  const db = createDb();
  seedWorkspace(db, { id: "ws_route", domainId: "dr" });
  const originalFetch = globalThis.fetch;
  let n = 0;
  globalThis.fetch = async () => {
    n++;
    return n === 1
      ? new Response(JSON.stringify([ctEntry()]), { status: 200, headers: { "content-type": "application/json" } })
      : new Response("upstream unavailable", { status: 503 });
  };
  const partialResponse = await brandRoutes(routeContext(db));
  const partial = await partialResponse.json();
  globalThis.fetch = async () => new Response("upstream unavailable", { status: 503 });
  const failedResponse = await brandRoutes(routeContext(db));
  const failedBody = await failedResponse.json();
  globalThis.fetch = originalFetch;
  eq("B2a partial upstream result remains 200 with explicit incompleteness", partialResponse.status, 200);
  ok("B2a partial upstream failure reported honestly",
    partial.partial === true && partial.incomplete === true && partial.failed > 0);
  eq("B2a total upstream failure is not empty/healthy success", failedResponse.status, 502);
  ok("B2a total failure is explicit",
    failedBody.incomplete === true && failedBody.failed > 0 &&
    failedBody.error === "brand_discovery_upstream_unavailable");
}

// Atomic D1 window is the cross-isolate concurrency claim.
{
  const db = createDb();
  const env = { cybermeters_db: d1(db) };
  const scopes = [{ scope: "workspace", scope_id: "ws_atomic" }];
  const first = await consumeApiRateLimit(
    env, scopes, "brand_passive_discovery_burst", 1, 60,
    { failClosed: true, atomic: true },
  );
  const second = await consumeApiRateLimit(
    env, scopes, "brand_passive_discovery_burst", 1, 60,
    { failClosed: true, atomic: true },
  );
  eq("B2a first atomic concurrency claim succeeds", first, null);
  eq("B2a overlapping/repeated claim is rate-limited", second?.status, 429);
}

console.log(`\nBrand passive discovery PR-D: ${pass}/${pass + fail} passed`);
if (fail) process.exit(1);
console.log("Brand passive discovery PR-D validation passed");
