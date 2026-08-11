#!/usr/bin/env node
//
// H-01 — Brand candidate soft-delete persistence boundary.
// DB-backed and CI-blocking. No network, production, or migration access.
//
// The behavioural fixtures cover every current Brand producer/write/link family:
// generated scan persistence, passive CT persistence, manual/scheduled DNS and
// HTTP enrichment, profile loading/linking, case production, audit production,
// route/profile/classification writes, and domain-removal lifecycle writes.
// Static inventory assertions pin the private route/case/link statements that
// cannot be invoked in isolation without weakening their real authorization path.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const source = (relative) => fs.readFileSync(path.join(root, relative), "utf8");
const worker = (...parts) => pathToFileURL(path.join(root, "workers", "scan-api", "src", ...parts)).href;

const {
  persistBrandCandidateObservation,
  upsertBrandAssets,
} = await import(worker("engines", "asset-persistence.js"));
const {
  discoverBrandCandidatesForWorkspace,
  runBrandPassiveDiscoverySweep,
} = await import(worker("engines", "brand-passive-discovery.js"));
const {
  enrichBrandCandidatesDns,
  runBrandDnsEnrichmentSweep,
} = await import(worker("engines", "brand-dns-enrichment.js"));
const {
  enrichBrandCandidatesHttp,
  runBrandHttpEnrichmentSweep,
} = await import(worker("engines", "brand-http-enrichment.js"));
const { loadWorkspaceBrandProfile } = await import(worker("engines", "brand-protection.js"));
const { createBrandCaseForCandidate, createBrandCasesForWorkspace } = await import(worker("engines", "brand-cases.js"));
const { createAuditEvent } = await import(worker("lib", "events.js"));
const { brandRoutes } = await import(worker("routes", "brand.js"));

const NOW = "2026-08-11T12:00:00.000Z";
const DELETED = "2026-08-11T11:59:00.000Z";
const EXPECTED_ASSERTIONS = 57;

let passed = 0;
let failed = 0;
const failures = [];
function check(id, condition, detail = "") {
  if (condition) passed++;
  else {
    failed++;
    failures.push(id);
    console.error(`FAIL ${id}${detail ? ` — ${detail}` : ""}`);
  }
}
function equal(id, got, want) {
  check(id, JSON.stringify(got) === JSON.stringify(want),
    `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);
}

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
      workspace_id TEXT, domain_id TEXT, verification_status TEXT,
      UNIQUE(workspace_id, domain_id)
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
      customer_disposition TEXT, history_marker TEXT, created_at TEXT, updated_at TEXT,
      UNIQUE(workspace_id, domain, candidate_domain)
    );
    CREATE TABLE audit_events (
      id TEXT PRIMARY KEY, workspace_id TEXT, user_id TEXT, actor_type TEXT,
      event_type TEXT, entity_type TEXT, entity_id TEXT, description TEXT,
      metadata_json TEXT, created_at TEXT
    );
    CREATE TABLE asset_events (
      id TEXT PRIMARY KEY, workspace_id TEXT, domain_id TEXT, scan_id TEXT,
      event_type TEXT, hostname TEXT, severity TEXT, description TEXT, created_at TEXT
    );
    CREATE TABLE managed_cases (
      id TEXT PRIMARY KEY, workspace_id TEXT, case_type TEXT, domain_key TEXT,
      domain TEXT, finding_id TEXT, source_finding_type TEXT, remediation_id TEXT,
      asset_ref TEXT, title TEXT, description TEXT, status TEXT, severity TEXT,
      source TEXT, evidence_json TEXT, recommended_actions_json TEXT,
      created_by TEXT, created_at TEXT, updated_at TEXT
    );
    CREATE TABLE managed_case_events (
      id TEXT PRIMARY KEY, case_id TEXT, workspace_id TEXT, actor_type TEXT,
      actor_id TEXT, from_status TEXT, to_status TEXT, action TEXT,
      detail_json TEXT, created_at TEXT
    );
    CREATE TABLE brand_abuse_campaigns (
      id TEXT PRIMARY KEY, workspace_id TEXT, brand_profile_id TEXT,
      linked_domains TEXT, linked_ips TEXT, first_seen_at TEXT, last_seen_at TEXT,
      created_at TEXT, updated_at TEXT
    );
    CREATE TABLE brand_evidence_bundles (
      id TEXT PRIMARY KEY, workspace_id TEXT, case_id TEXT, version INTEGER,
      content_hash TEXT, bundle_json TEXT, captured_at TEXT, created_at TEXT
    );
    CREATE TABLE notification_events (
      id TEXT PRIMARY KEY, workspace_id TEXT, user_id TEXT, type TEXT,
      severity TEXT, title TEXT, message TEXT, metadata_json TEXT,
      status TEXT, created_at TEXT
    );
  `);
  return db;
}

function d1(db, hooks = {}) {
  return {
    prepare(sql) {
      const statement = db.prepare(sql);
      const execute = (kind, args) => {
        hooks.before?.({ sql, kind, args, db });
        let value;
        if (kind === "all") value = { results: statement.all(...args) };
        else if (kind === "first") value = statement.get(...args) ?? null;
        else value = statement.run(...args);
        hooks.after?.({ sql, kind, args, db, value });
        return value;
      };
      const bound = (...args) => ({
        all: async () => execute("all", args),
        first: async () => execute("first", args),
        run: async () => execute("run", args),
      });
      return {
        bind: (...args) => bound(...args),
        all: async () => execute("all", []),
        first: async () => execute("first", []),
        run: async () => execute("run", []),
      };
    },
  };
}

function seedWorkspace(db, {
  id = "ws_a", domainId = "dom_a", domain = "acme.test", deletedAt = null,
  profile = true,
} = {}) {
  db.prepare("INSERT INTO workspaces VALUES (?,?,?,?)")
    .run(id, `owner_${id}`, id, deletedAt);
  db.prepare("INSERT INTO domains VALUES (?,?,?)")
    .run(domainId, domain, "2026-01-01T00:00:00.000Z");
  db.prepare("INSERT INTO workspace_domains VALUES (?,?,?)")
    .run(id, domainId, "verified");
  if (profile) {
    db.prepare("INSERT INTO workspace_brand_profiles VALUES (?,?,?,?,?,?,?,?)")
      .run(`profile_${id}`, id, domain.split(".")[0], domain, "[]",
        JSON.stringify([domain]), NOW, NOW);
  }
}

function seedCandidate(db, {
  id = "bra_a", workspaceId = "ws_a", domain = "acme.test",
  candidate = "acme-login.test", dns = null, https = null,
  profileId = "profile_ws_a",
} = {}) {
  db.prepare(`
    INSERT INTO workspace_brand_assets
      (id, workspace_id, domain, candidate_domain, variant_type,
       similarity_score, risk_level, risk_reasons, evidence_json,
       dns_resolves, https_available, mx_present, ip_address, status,
       classification, brand_profile_id, first_seen, last_seen,
       last_checked_at, managed_case_ref, campaign_ref, customer_validation,
       customer_disposition, history_marker, created_at, updated_at)
    VALUES (?,?,?,?,?,90,'high','["history_reason"]','[{"signal":"history","value":"keep"}]',
            ?,?,NULL,NULL,'unverified','unreviewed',?,?,?,?,
            'case_keep','campaign_keep','customer_keep','disposition_keep','history_keep',?,?)
  `).run(id, workspaceId, domain, candidate, "substitution", dns, https, profileId,
    NOW, NOW, null, NOW, NOW);
}

function tableBytes(db) {
  const tables = [
    "workspace_brand_assets", "workspace_brand_profiles", "audit_events",
    "asset_events", "managed_cases", "managed_case_events",
    "brand_abuse_campaigns", "brand_evidence_bundles", "notification_events",
  ];
  return Object.fromEntries(tables.map((table) => [table,
    JSON.stringify(db.prepare(`SELECT * FROM ${table} ORDER BY id`).all())]));
}

function observation(candidateDomain = "acme-login.test") {
  return {
    workspaceId: "ws_a",
    domain: "acme.test",
    candidateDomain,
    variantType: "substitution",
    similarity: 90,
    evidence: [{ signal: "newly_seen", value: true }],
    now: NOW,
  };
}

function ctFetch(onFetch = null) {
  return async () => {
    onFetch?.();
    return {
      ok: true,
      headers: { get: (name) => name === "content-type" ? "application/json" : null },
      json: async () => [{
        id: 501,
        name_value: "acme-login.test",
        common_name: "acme-login.test",
        serial_number: "AA501",
        issuer_name: "Fixture CA",
        entry_timestamp: NOW,
        not_before: NOW,
        not_after: "2026-11-11T12:00:00.000Z",
      }],
    };
  };
}

async function callBrandRoute(db, {
  pathname, body, hooks = {}, access = true,
}) {
  const url = new URL(`https://api.cybermeters.test${pathname}`);
  const request = new Request(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  const response = await brandRoutes({
    request,
    env: { cybermeters_db: d1(db, hooks) },
    url,
    json: (value, status = 200) => new Response(JSON.stringify(value), {
      status, headers: { "content-type": "application/json" },
    }),
    requireAuth: async () => ({ id: "user_a" }),
    requireWorkspaceRole: async () => access ? { role: "admin" } : null,
    consumeApiRateLimit: async () => ({ allowed: true }),
  });
  return response;
}

// A. Direct canonical persistence: active, soft-delete, cross-tenant, and race.
{
  const db = createDb();
  seedWorkspace(db);
  const active = await persistBrandCandidateObservation(
    { cybermeters_db: d1(db) }, observation(),
  );
  check("H01-ACTIVE-DIRECT", active.status === "inserted" &&
    db.prepare("SELECT COUNT(*) n FROM workspace_brand_assets WHERE workspace_id='ws_a'").get().n === 1);
}
{
  const db = createDb();
  seedWorkspace(db, { deletedAt: DELETED });
  const result = await persistBrandCandidateObservation(
    { cybermeters_db: d1(db) }, observation(),
  );
  equal("H01-DELETED-DIRECT", [result.status,
    db.prepare("SELECT COUNT(*) n FROM workspace_brand_assets").get().n], ["failed", 0]);
}
{
  const db = createDb();
  seedWorkspace(db);
  const env = { cybermeters_db: d1(db) };
  const first = await persistBrandCandidateObservation(env, observation());
  db.prepare("UPDATE workspaces SET deleted_at=? WHERE id='ws_a'").run(DELETED);
  const before = tableBytes(db);
  const repeat = await persistBrandCandidateObservation(env, observation());
  equal("H01-DELETED-DIRECT-EXISTING-READ", [first.status, repeat.status, tableBytes(db)],
    ["inserted", "failed", before]);
}
{
  const db = createDb();
  seedWorkspace(db);
  seedWorkspace(db, { id: "ws_b", domainId: "dom_b", domain: "beta.test" });
  const result = await persistBrandCandidateObservation(
    { cybermeters_db: d1(db) }, { ...observation("beta-login.test"), domain: "beta.test" },
  );
  equal("H01-CROSS-TENANT-DIRECT", [result.status,
    db.prepare("SELECT COUNT(*) n FROM workspace_brand_assets").get().n], ["failed", 0]);
}
{
  const db = createDb();
  seedWorkspace(db);
  seedCandidate(db);
  let deleted = false;
  const env = { cybermeters_db: d1(db, {
    after: ({ sql, kind }) => {
      if (!deleted && kind === "first" && /SELECT id, workspace_id, domain, candidate_domain/.test(sql)) {
        db.prepare("UPDATE workspaces SET deleted_at=? WHERE id='ws_a'").run(DELETED);
        deleted = true;
      }
    },
  }) };
  const before = tableBytes(db);
  const result = await persistBrandCandidateObservation(env, observation());
  equal("H01-RACE-DIRECT-UPDATE", [result.status, tableBytes(db)], ["failed", before]);
}

// B. Generated scan and passive-CT producers.
{
  const db = createDb();
  seedWorkspace(db, { deletedAt: DELETED });
  let candidateReads = 0;
  await upsertBrandAssets("dom_a", { domains: [{
    candidate_domain: "acme-scan.test", variant_type: "substitution",
  }] }, { cybermeters_db: d1(db, { before: ({ sql }) => {
    if (/FROM workspace_brand_assets a/.test(sql)) candidateReads++;
  } }) });
  equal("H01-DELETED-SCAN-PRODUCER", [candidateReads,
    db.prepare("SELECT COUNT(*) n FROM workspace_brand_assets").get().n], [0, 0]);
}
{
  const db = createDb();
  seedWorkspace(db);
  seedCandidate(db, { candidate: "acme-race.test", profileId: null });
  const before = tableBytes(db);
  let deleted = false;
  const env = { cybermeters_db: d1(db, {
    after: ({ sql, kind }) => {
      if (!deleted && kind === "all" && /FROM workspace_domains wd/.test(sql)) {
        db.prepare("UPDATE workspaces SET deleted_at=? WHERE id='ws_a'").run(DELETED);
        deleted = true;
      }
    },
  }) };
  await upsertBrandAssets("dom_a", { domains: [{
    candidate_domain: "acme-race.test", variant_type: "substitution",
  }] }, env);
  equal("H01-RACE-SCAN-PRODUCER", tableBytes(db), before);
}
{
  const db = createDb();
  seedWorkspace(db, { deletedAt: DELETED });
  let fetches = 0;
  const stats = await discoverBrandCandidatesForWorkspace(
    { cybermeters_db: d1(db) }, "ws_a",
    { fetchImpl: async (url) => { fetches++; return (ctFetch())(url); }, now: NOW },
  );
  equal("H01-DELETED-PASSIVE-DIRECT", [fetches, stats.inserted,
    db.prepare("SELECT COUNT(*) n FROM workspace_brand_assets").get().n], [0, 0, 0]);
}
{
  const db = createDb();
  seedWorkspace(db);
  const stats = await discoverBrandCandidatesForWorkspace(
    { cybermeters_db: d1(db) }, "ws_a",
    { fetchImpl: ctFetch(() => db.prepare("UPDATE workspaces SET deleted_at=? WHERE id='ws_a'").run(DELETED)), now: NOW },
  );
  equal("H01-RACE-PASSIVE-CT", [stats.inserted,
    db.prepare("SELECT COUNT(*) n FROM workspace_brand_assets").get().n], [0, 0]);
}
{
  const db = createDb();
  seedWorkspace(db, { id: "ws_active", domainId: "dom_active", domain: "active.test" });
  seedWorkspace(db, { id: "ws_deleted", domainId: "dom_deleted", domain: "deleted.test", deletedAt: DELETED });
  seedCandidate(db, { id: "bra_active", workspaceId: "ws_active", domain: "active.test", candidate: "active-login.test", profileId: "profile_ws_active" });
  seedCandidate(db, { id: "bra_deleted", workspaceId: "ws_deleted", domain: "deleted.test", candidate: "deleted-login.test", profileId: "profile_ws_deleted" });
  let deletedFetched = false;
  const stats = await runBrandPassiveDiscoverySweep({ cybermeters_db: d1(db) }, {
    workspacesPerDay: 2,
    fetchImpl: async (url) => { if (decodeURIComponent(url).includes("deleted")) deletedFetched = true; return (ctFetch())(url); },
    now: NOW,
  });
  equal("H01-DELETED-PASSIVE-SCHEDULE", [stats.workspaces, deletedFetched], [1, false]);
}

// C. DNS and HTTP manual/scheduled enrichment; deletion during external I/O.
{
  const db = createDb();
  seedWorkspace(db);
  seedCandidate(db);
  const stats = await enrichBrandCandidatesDns({ cybermeters_db: d1(db) }, "ws_a", {
    dnsQuery: async () => ({ Status: 0, Answer: [{ type: 1, data: "203.0.113.10" }] }),
    now: NOW,
  });
  const row = db.prepare("SELECT dns_resolves,status,ip_address FROM workspace_brand_assets").get();
  equal("H01-ACTIVE-DNS-PRESERVED", [stats.checked, row], [1,
    { dns_resolves: 1, status: "active", ip_address: "203.0.113.10" }]);
}
{
  const db = createDb();
  seedWorkspace(db, { deletedAt: DELETED });
  seedCandidate(db);
  const before = tableBytes(db);
  let probes = 0;
  const stats = await enrichBrandCandidatesDns({ cybermeters_db: d1(db) }, "ws_a", {
    dnsQuery: async () => { probes++; return { Status: 0, Answer: [{ type: 1, data: "203.0.113.10" }] }; },
    now: NOW,
  });
  equal("H01-DELETED-DNS-MANUAL", [probes, stats.checked, tableBytes(db)], [0, 0, before]);
}
{
  const db = createDb();
  seedWorkspace(db);
  seedCandidate(db);
  const before = tableBytes(db);
  const stats = await enrichBrandCandidatesDns({ cybermeters_db: d1(db) }, "ws_a", {
    dnsQuery: async () => {
      db.prepare("UPDATE workspaces SET deleted_at=? WHERE id='ws_a'").run(DELETED);
      return { Status: 0, Answer: [{ type: 1, data: "203.0.113.10" }] };
    },
    now: NOW,
    fireEvents: true,
  });
  equal("H01-RACE-DNS-WRITE-EVENT", [stats.checked, tableBytes(db)], [0, before]);
}
{
  const db = createDb();
  seedWorkspace(db, { deletedAt: DELETED });
  seedCandidate(db);
  let probes = 0;
  const stats = await runBrandDnsEnrichmentSweep({ cybermeters_db: d1(db) }, {
    dnsQuery: async () => { probes++; return { Status: 3, Answer: [] }; },
  });
  equal("H01-DELETED-DNS-SCHEDULE", [probes, stats.workspaces, stats.checked], [0, 0, 0]);
}
{
  const db = createDb();
  seedWorkspace(db);
  seedCandidate(db);
  let armed = false;
  const env = { cybermeters_db: d1(db, {
    after: ({ sql, kind }) => {
      if (armed && kind === "first" && /SELECT wd\.domain_id/.test(sql)) {
        db.prepare("UPDATE workspaces SET deleted_at=? WHERE id='ws_a'").run(DELETED);
        armed = false;
      }
      if (kind === "run" && /UPDATE workspace_brand_assets/.test(sql)) armed = true;
    },
  }) };
  const stats = await enrichBrandCandidatesDns(env, "ws_a", {
    dnsQuery: async () => ({ Status: 0, Answer: [{ type: 1, data: "203.0.113.10" }] }),
    now: NOW,
    fireEvents: true,
  });
  equal("H01-RACE-DNS-EVENT-INSERT", [stats.checked,
    db.prepare("SELECT COUNT(*) n FROM asset_events").get().n], [1, 0]);
}
{
  const db = createDb();
  seedWorkspace(db);
  seedCandidate(db);
  let eventInsertAttempts = 0;
  const env = { cybermeters_db: d1(db, {
    after: ({ sql, kind }) => {
      if (kind === "run" && /UPDATE workspace_brand_assets/.test(sql)) {
        db.prepare("UPDATE workspaces SET deleted_at=? WHERE id='ws_a'").run(DELETED);
      }
    },
    before: ({ sql }) => {
      if (/INSERT OR IGNORE INTO asset_events/.test(sql)) eventInsertAttempts++;
    },
  }) };
  const stats = await enrichBrandCandidatesDns(env, "ws_a", {
    dnsQuery: async () => ({ Status: 0, Answer: [{ type: 1, data: "203.0.113.10" }] }),
    now: NOW,
    fireEvents: true,
  });
  equal("H01-RACE-DNS-EVENT-DOMAIN-READ", [stats.checked, eventInsertAttempts,
    db.prepare("SELECT COUNT(*) n FROM asset_events").get().n], [1, 0, 0]);
}
{
  const db = createDb();
  seedWorkspace(db);
  seedCandidate(db, { dns: 1 });
  const stats = await enrichBrandCandidatesHttp({ cybermeters_db: d1(db) }, "ws_a", {
    probeFetch: async () => new Response("<input type=password>", { status: 200 }),
    now: NOW,
  });
  const row = db.prepare("SELECT https_available,evidence_json FROM workspace_brand_assets").get();
  check("H01-ACTIVE-HTTP-PRESERVED", stats.checked === 1 && row.https_available === 1 &&
    JSON.parse(row.evidence_json).some((item) => item.signal === "looks_like_login"));
}
{
  const db = createDb();
  seedWorkspace(db);
  seedCandidate(db, { dns: 1 });
  const before = tableBytes(db);
  const stats = await enrichBrandCandidatesHttp({ cybermeters_db: d1(db) }, "ws_a", {
    probeFetch: async () => {
      db.prepare("UPDATE workspaces SET deleted_at=? WHERE id='ws_a'").run(DELETED);
      return new Response("<form><input type=password></form>", { status: 200 });
    },
    now: NOW,
  });
  equal("H01-RACE-HTTP-WRITE", [stats.checked, tableBytes(db)], [0, before]);
}
{
  const db = createDb();
  seedWorkspace(db, { deletedAt: DELETED });
  seedCandidate(db, { dns: 1 });
  const before = tableBytes(db);
  let probes = 0;
  const stats = await enrichBrandCandidatesHttp({ cybermeters_db: d1(db) }, "ws_a", {
    probeFetch: async () => { probes++; return new Response("ok", { status: 200 }); },
    now: NOW,
  });
  equal("H01-DELETED-HTTP-MANUAL", [probes, stats.checked, tableBytes(db)], [0, 0, before]);
}
{
  const db = createDb();
  seedWorkspace(db, { deletedAt: DELETED });
  seedCandidate(db, { dns: 1 });
  let probes = 0;
  const stats = await runBrandHttpEnrichmentSweep({ cybermeters_db: d1(db) }, {
    probeFetch: async () => { probes++; return new Response("ok", { status: 200 }); },
  });
  equal("H01-DELETED-HTTP-SCHEDULE", [probes, stats.workspaces, stats.checked], [0, 0, 0]);
}

// D. Profiles, case production, audit/event side effects, and history bytes.
{
  const db = createDb();
  seedWorkspace(db);
  const profile = await loadWorkspaceBrandProfile({ cybermeters_db: d1(db) }, "ws_a");
  equal("H01-ACTIVE-PROFILE-PRESERVED", profile?.id, "profile_ws_a");
}
{
  const db = createDb();
  seedWorkspace(db, { deletedAt: DELETED });
  const profile = await loadWorkspaceBrandProfile({ cybermeters_db: d1(db) }, "ws_a");
  equal("H01-DELETED-PROFILE-READ", profile, null);
}
{
  const db = createDb();
  seedWorkspace(db, { deletedAt: DELETED });
  seedCandidate(db);
  const result = await createBrandCasesForWorkspace({ cybermeters_db: d1(db) }, "ws_a");
  equal("H01-DELETED-CASE-PRODUCER", [result.opened,
    db.prepare("SELECT COUNT(*) n FROM managed_cases").get().n], [0, 0]);
}
{
  const db = createDb();
  seedWorkspace(db, { deletedAt: DELETED });
  await createAuditEvent({ cybermeters_db: d1(db) }, {
    workspace_id: "ws_a", event_type: "brand_passive_discovery_completed",
    entity_type: "brand_profile", entity_id: "profile_ws_a",
    active_workspace_required: true,
  });
  equal("H01-DELETED-AUDIT-EVENT",
    db.prepare("SELECT COUNT(*) n FROM audit_events").get().n, 0);
}
{
  const db = createDb();
  seedWorkspace(db);
  seedCandidate(db, { dns: 1 });
  const candidate = db.prepare("SELECT * FROM workspace_brand_assets WHERE id='bra_a'").get();
  const before = tableBytes(db);
  let deleted = false;
  const result = await createBrandCaseForCandidate({ cybermeters_db: d1(db, {
    after: ({ sql, kind }) => {
      if (!deleted && kind === "first" && /SELECT \* FROM managed_cases/.test(sql)) {
        db.prepare("UPDATE workspaces SET deleted_at=? WHERE id='ws_a'").run(DELETED);
        deleted = true;
      }
    },
  }) }, "ws_a", candidate);
  equal("H01-RACE-CASE-INSERT", [result.opened, result.reason, tableBytes(db)],
    [false, "workspace_inactive_or_candidate_ineligible", before]);
}
{
  const db = createDb();
  seedWorkspace(db, { domain: "acme.com", profile: false });
  const before = tableBytes(db);
  let deleted = false;
  const response = await callBrandRoute(db, {
    pathname: "/api/workspaces/ws_a/brand/profile",
    body: { brand_name: "Acme", primary_domain: "acme.com", keywords: [], protected_domains: ["acme.com"] },
    hooks: { after: ({ sql, kind }) => {
      if (!deleted && kind === "all" && /SELECT d\.domain FROM workspace_domains wd/.test(sql)) {
        db.prepare("UPDATE workspaces SET deleted_at=? WHERE id='ws_a'").run(DELETED);
        deleted = true;
      }
    } },
  });
  equal("H01-RACE-PROFILE-WRITE", [response.status, tableBytes(db)], [404, before]);
}
{
  const db = createDb();
  seedWorkspace(db);
  seedCandidate(db);
  const before = tableBytes(db);
  let deleted = false;
  const response = await callBrandRoute(db, {
    pathname: "/api/workspaces/ws_a/brand/candidates/bra_a/classify",
    body: { classification: "suspicious" },
    hooks: { after: ({ sql, kind }) => {
      if (!deleted && kind === "first" && /SELECT id, workspace_id, domain, candidate_domain/.test(sql)) {
        db.prepare("UPDATE workspaces SET deleted_at=? WHERE id='ws_a'").run(DELETED);
        deleted = true;
      }
    } },
  });
  equal("H01-RACE-CLASSIFICATION-WRITE", [response.status, tableBytes(db)], [404, before]);
}
{
  const db = createDb();
  seedWorkspace(db);
  const before = tableBytes(db);
  const response = await callBrandRoute(db, {
    pathname: "/api/workspaces/ws_a/brand/profile",
    body: { brand_name: "Foreign", primary_domain: "acme.test", keywords: [], protected_domains: ["acme.test"] },
    access: false,
  });
  equal("H01-CROSS-TENANT-PROFILE-WRITE", [response.status, tableBytes(db)], [403, before]);
}
{
  const db = createDb();
  seedWorkspace(db);
  const result = await createAuditEvent({ cybermeters_db: d1(db) }, {
    workspace_id: "ws_a", event_type: "brand_passive_discovery_completed",
    entity_type: "brand_profile", entity_id: "profile_ws_a",
    active_workspace_required: true,
  });
  equal("H01-ACTIVE-AUDIT-PRESERVED", [result,
    db.prepare("SELECT COUNT(*) n FROM audit_events").get().n], [true, 1]);
}
{
  const db = createDb();
  seedWorkspace(db, { deletedAt: DELETED });
  seedCandidate(db);
  db.prepare("INSERT INTO audit_events VALUES (?,?,?,?,?,?,?,?,?,?)")
    .run("audit_keep", "ws_a", null, "system", "historical", "brand_candidate", "bra_a", "keep", "{}", NOW);
  db.prepare("INSERT INTO asset_events VALUES (?,?,?,?,?,?,?,?,?)")
    .run("asset_event_keep", "ws_a", "dom_a", null, "historical", "acme-login.test", "high", "keep", NOW);
  db.prepare(`INSERT INTO managed_cases
    (id, workspace_id, case_type, domain_key, domain, finding_id, remediation_id,
     title, description, status, severity, source, evidence_json, created_at, updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run("case_keep", "ws_a", "brand_abuse", "brand_protection", "acme-login.test", "bra_a", null, "keep", "keep", "monitoring", "high", "brand_candidate", "{}", NOW, NOW);
  db.prepare("INSERT INTO managed_case_events VALUES (?,?,?,?,?,?,?,?,?,?)")
    .run("case_event_keep", "case_keep", "ws_a", "system", null, null, "monitoring", "keep", "{}", NOW);
  db.prepare("INSERT INTO brand_abuse_campaigns VALUES (?,?,?,?,?,?,?,?,?)")
    .run("campaign_keep", "ws_a", "profile_ws_a", "[]", "[]", NOW, NOW, NOW, NOW);
  db.prepare("INSERT INTO brand_evidence_bundles VALUES (?,?,?,?,?,?,?,?)")
    .run("bundle_keep", "ws_a", "case_keep", 1, "hash", "{}", NOW, NOW);
  db.prepare("INSERT INTO notification_events VALUES (?,?,?,?,?,?,?,?,?,?)")
    .run("notification_keep", "ws_a", null, "brand", "high", "keep", "keep", "{}", "unread", NOW);
  const before = tableBytes(db);
  const env = { cybermeters_db: d1(db) };
  await persistBrandCandidateObservation(env, observation());
  await upsertBrandAssets("dom_a", { domains: [{ candidate_domain: "acme-new.test", variant_type: "substitution" }] }, env);
  await enrichBrandCandidatesDns(env, "ws_a", { dnsQuery: async () => ({ Status: 3, Answer: [] }), fireEvents: true });
  await enrichBrandCandidatesHttp(env, "ws_a", { probeFetch: async () => new Response("ok", { status: 200 }) });
  await createBrandCasesForWorkspace(env, "ws_a");
  equal("H01-HISTORICAL-BYTE-PRESERVATION", tableBytes(db), before);
}

// E. Exhaustive current source inventory. Every private Brand candidate write,
// profile-link, route classification, and case candidate path carries the same
// canonical active-workspace authority at its SQL boundary.
const asset = source("workers/scan-api/src/engines/asset-persistence.js");
const passive = source("workers/scan-api/src/engines/brand-passive-discovery.js");
const dns = source("workers/scan-api/src/engines/brand-dns-enrichment.js");
const http = source("workers/scan-api/src/engines/brand-http-enrichment.js");
const protection = source("workers/scan-api/src/engines/brand-protection.js");
const cases = source("workers/scan-api/src/engines/brand-cases.js");
const routes = source("workers/scan-api/src/routes/brand.js");
const workspaces = source("workers/scan-api/src/routes/workspaces-core.js");
const events = source("workers/scan-api/src/lib/events.js");

const persistSegment = asset.slice(
  asset.indexOf("export async function persistBrandCandidateObservation"),
  asset.indexOf("// ── Identity Asset Discovery"),
);
const initialReadSegment = persistSegment.slice(
  persistSegment.indexOf("let existing;"), persistSegment.indexOf("const state ="),
);
const winnerReadSegment = persistSegment.slice(
  persistSegment.indexOf("const winner ="), persistSegment.indexOf("if (winner?.id"),
);
const verifyReadSegment = persistSegment.slice(
  persistSegment.indexOf("const verified ="), persistSegment.indexOf("if (verified &&"),
);
const persistInsertSegment = persistSegment.slice(
  persistSegment.indexOf("`WITH candidate"), persistSegment.indexOf("const winner ="),
);
const persistUpdateSegment = persistSegment.slice(
  persistSegment.indexOf("`UPDATE workspace_brand_assets"), persistSegment.indexOf("const verified ="),
);
const hasActiveDomainRead = (segment) => segment.includes("FROM workspace_brand_assets a") &&
  segment.includes("FROM workspaces w") && segment.includes("JOIN workspace_domains wd") &&
  segment.includes("w.deleted_at IS NULL") && segment.includes("lower(d.domain) = lower(a.domain)");
check("H01-SOURCE-CANONICAL-INITIAL-READ", hasActiveDomainRead(initialReadSegment));
check("H01-SOURCE-CANONICAL-WINNER-READ", hasActiveDomainRead(winnerReadSegment));
check("H01-SOURCE-CANONICAL-VERIFY-READ", hasActiveDomainRead(verifyReadSegment));
check("H01-SOURCE-CANONICAL-PERSIST-INSERT", /INSERT OR IGNORE INTO workspace_brand_assets[\s\S]*?SELECT[\s\S]*?WHERE EXISTS[\s\S]*?w\.deleted_at IS NULL/.test(persistInsertSegment));
check("H01-SOURCE-CANONICAL-PERSIST-UPDATE", /UPDATE workspace_brand_assets[\s\S]*?candidate_domain = \?[\s\S]*?EXISTS[\s\S]*?w\.deleted_at IS NULL/.test(persistUpdateSegment));
const scanAuthorizer = asset.slice(
  asset.indexOf("export async function upsertBrandAssets"),
  asset.indexOf("// The active workspace/domain membership read"),
);
check("H01-SOURCE-SCAN-AUTHORIZER", /FROM workspace_domains wd\s+JOIN workspaces w[\s\S]{0,180}?w\.deleted_at IS NULL/.test(scanAuthorizer));
check("H01-SOURCE-SCAN-PROFILE-LINK", /SET brand_profile_id[\s\S]*?WHERE workspace_id = \?[\s\S]*?EXISTS[\s\S]*?deleted_at IS NULL/.test(asset));
check("H01-SOURCE-PASSIVE-PRODUCER", /FROM workspaces w\s+JOIN workspace_domains wd[\s\S]{0,220}?w\.deleted_at IS NULL/.test(passive));
const dnsSelect = dns.slice(dns.indexOf("export function selectBrandCandidatesSql"), dns.indexOf("async function fireResolvingAssetEvent"));
const dnsEvent = dns.slice(dns.indexOf("async function fireResolvingAssetEvent"), dns.indexOf("function runChanges"));
const dnsEnrich = dns.slice(dns.indexOf("export async function enrichBrandCandidatesDns"), dns.indexOf("export async function runBrandDnsEnrichmentSweep"));
const dnsSweep = dns.slice(dns.indexOf("export async function runBrandDnsEnrichmentSweep"));
const dnsEventRead = dnsEvent.slice(0, dnsEvent.indexOf("const evType"));
const dnsEventInsert = dnsEvent.slice(dnsEvent.indexOf("INSERT OR IGNORE INTO asset_events"));
const dnsUpdate = dnsEnrich.slice(
  dnsEnrich.indexOf("UPDATE workspace_brand_assets"), dnsEnrich.indexOf("if (runChanges(result)"),
);
check("H01-SOURCE-DNS-SELECT", hasActiveDomainRead(dnsSelect));
check("H01-SOURCE-DNS-UPDATE", /UPDATE workspace_brand_assets[\s\S]*?EXISTS[\s\S]*?deleted_at IS NULL/.test(dnsUpdate));
check("H01-SOURCE-DNS-SWEEP", /JOIN workspaces w[\s\S]*?deleted_at IS NULL/.test(dnsSweep));
check("H01-SOURCE-DNS-EVENT-READ", /SELECT wd\.domain_id[\s\S]*?deleted_at IS NULL/.test(dnsEventRead));
check("H01-SOURCE-DNS-EVENT-INSERT",
  /INSERT OR IGNORE INTO asset_events[\s\S]*?WHERE EXISTS[\s\S]*?deleted_at IS NULL/.test(dnsEventInsert));
const httpSelect = http.slice(http.indexOf("export function selectBrandHttpCandidatesSql"), http.indexOf("function parseJsonArray"));
const httpEnrich = http.slice(http.indexOf("export async function enrichBrandCandidatesHttp"), http.indexOf("export async function runBrandHttpEnrichmentSweep"));
const httpSweep = http.slice(http.indexOf("export async function runBrandHttpEnrichmentSweep"));
check("H01-SOURCE-HTTP-SELECT", hasActiveDomainRead(httpSelect));
check("H01-SOURCE-HTTP-UPDATE", /UPDATE workspace_brand_assets[\s\S]*?EXISTS[\s\S]*?deleted_at IS NULL/.test(httpEnrich));
check("H01-SOURCE-HTTP-SWEEP", /JOIN workspaces w[\s\S]*?deleted_at IS NULL/.test(httpSweep));
const profilePersistedRead = protection.slice(
  protection.indexOf("export async function loadWorkspaceBrandProfile"), protection.indexOf("if (persisted)"),
);
check("H01-SOURCE-PROFILE-READ", /FROM workspace_brand_profiles[\s\S]*?JOIN workspaces[\s\S]*?deleted_at IS NULL/.test(profilePersistedRead));
const caseCandidateQueries = [
  cases.slice(cases.indexOf("async function candidateForCase"), cases.indexOf("function bundleRowToApi")),
  cases.slice(cases.indexOf("async function candidateById"), cases.indexOf("export async function createBrandCaseForCandidate")),
  cases.slice(cases.indexOf("export async function createBrandCasesForWorkspace"), cases.indexOf("export async function createBrandCaseForCandidateId")),
];
const caseCandidateUpdates = cases.slice(
  cases.indexOf("async function updateCandidateClassification"),
  cases.indexOf("export async function reviewBrandCase"),
);
check("H01-SOURCE-CASE-READS", caseCandidateQueries.every((segment) =>
  segment.includes("workspace_brand_assets") && segment.includes("workspaces w") &&
  segment.includes("workspace_domains wd") && segment.includes("w.deleted_at IS NULL")));
check("H01-SOURCE-CASE-UPDATES",
  (caseCandidateUpdates.match(/UPDATE workspace_brand_assets/g) || []).length === 2 &&
  (caseCandidateUpdates.match(/w\.deleted_at IS NULL/g) || []).length === 2);
const caseInsert = cases.slice(
  cases.indexOf("INSERT INTO managed_cases"), cases.indexOf("const row = await getBrandCase"),
);
check("H01-SOURCE-CASE-INSERT", /SELECT[\s\S]*?WHERE EXISTS[\s\S]*?workspace_brand_assets[\s\S]*?deleted_at IS NULL/.test(caseInsert));
const routeProfileWrite = routes.slice(routes.indexOf("// POST /brand/profile"), routes.indexOf("// GET /brand/summary"));
const routeClassificationStart = routes.indexOf("// POST /brand/candidates/:id/classify");
const routeClassificationWrite = routes.slice(routeClassificationStart,
  routes.indexOf("return json({ error: \"Method not allowed\"", routeClassificationStart));
const routeLegacyRefresh = routes.slice(routes.indexOf("// ── POST /brand-monitoring/refresh"), routes.indexOf("// ── GET /brand-monitoring/summary"));
const routeProfileInsert = routeProfileWrite.slice(
  routeProfileWrite.indexOf("INSERT INTO workspace_brand_profiles"),
  routeProfileWrite.indexOf("if (runChanges(profileWrite)"),
);
const routeLegacyInsert = routeLegacyRefresh.slice(
  routeLegacyRefresh.indexOf("`WITH candidate"), routeLegacyRefresh.indexOf("} catch { /* non-fatal */ }"),
);
check("H01-SOURCE-ROUTE-PROFILE-WRITE", /INSERT INTO workspace_brand_profiles[\s\S]*?WHERE EXISTS[\s\S]*?deleted_at IS NULL/.test(routeProfileInsert));
check("H01-SOURCE-ROUTE-CLASSIFICATION-WRITE", /UPDATE workspace_brand_assets[\s\S]*?EXISTS[\s\S]*?deleted_at IS NULL/.test(routeClassificationWrite));
check("H01-SOURCE-ROUTE-LEGACY-INSERT", /INSERT OR IGNORE INTO workspace_brand_assets[\s\S]*?WHERE EXISTS[\s\S]*?deleted_at IS NULL/.test(routeLegacyInsert));
const routeProfileLink = routeProfileWrite.slice(
  routeProfileWrite.indexOf("UPDATE workspace_brand_assets"),
  routeProfileWrite.indexOf("const row = await env.cybermeters_db"),
);
const legacyLinkStart = routeLegacyRefresh.lastIndexOf("UPDATE workspace_brand_assets");
const routeLegacyLink = routeLegacyRefresh.slice(legacyLinkStart);
check("H01-SOURCE-ROUTE-PROFILE-LINKS",
  (routes.match(/UPDATE workspace_brand_assets/g) || []).length === 3 &&
  [routeProfileLink, routeLegacyLink].every((segment) =>
    segment.includes("UPDATE workspace_brand_assets") &&
    segment.includes("w.deleted_at IS NULL")));
check("H01-SOURCE-DOMAIN-REMOVAL-WRITE", /UPDATE workspace_brand_assets\s+SET status = 'inactive'[\s\S]{0,520}?EXISTS[\s\S]{0,220}?deleted_at IS NULL/.test(workspaces));
check("H01-SOURCE-AUDIT-GUARD", /active_workspace_required[\s\S]*?INSERT INTO audit_events[\s\S]*?WHERE EXISTS[\s\S]*?deleted_at IS NULL/.test(events));

check("H01-ASSERTION-COUNT", passed + failed + 1 === EXPECTED_ASSERTIONS,
  `got ${passed + failed + 1} want ${EXPECTED_ASSERTIONS}`);

console.log(`\nBrand H-01 soft-delete persistence: ${passed}/${passed + failed} assertions passed`);
if (failed || passed + failed !== EXPECTED_ASSERTIONS) process.exit(1);
console.log("Brand H-01 soft-delete persistence validation passed");
