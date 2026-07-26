#!/usr/bin/env node
//
// Brand passive discovery (Certificate Transparency) — PR-B. CI-blocking.
//
// Proves the fix for the nested-host half of the lookalike-coverage blocker
// (brand audit 2026-07-20): generation cannot enumerate arbitrary nested hosts on
// a lookalike base, so the founder's exact example `acme.com` →
// `office365password.acme.co` was undiscoverable. PR-B discovers it passively from
// CT logs, with a strict registrable-base membership filter to control false
// positives, honest CT-observed evidence, and a high-not-critical risk cap until a
// host is confirmed live.
//
// Guards the regressions this feature could introduce:
//   1. false-positive blow-up — a brand-token CT search returns every cert naming
//      the token worldwide; only hosts on a GENERATED lookalike base may be kept.
//   2. own-domain ingestion — the customer's own hosts must never be ingested.
//   3. score dishonesty — a CT-observed-but-not-live host must reach 'high' (real
//      cert evidence) but NEVER 'critical' (reserved for confirmed-live), and the
//      API serializer must agree with the persisted band.
//   4. tenant isolation — every read/write is workspace-scoped.
//
// Node 24+.
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href;

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

const {
  brandCtQueryUrl, parseCtResponseHostnames, buildLookalikeBaseSet,
  filterDiscoveredHosts, buildDiscoveredCandidateRisk,
  discoverBrandCandidatesForWorkspace, runBrandPassiveDiscoverySweep,
  BRAND_CT_HOST_CAP,
} = await import(eng("brand-passive-discovery.js"));
const { scoreBrandCandidateRisk, brandCandidateToApi, normalizeBrandVariantType } =
  await import(eng("brand-protection.js"));

// ── 1. Query URL construction + short-token guard ────────────────────────────
ok("brand token builds a crt.sh identity query", /crt\.sh\/\?q=.*acme.*&output=json/.test(brandCtQueryUrl("acme") || ""));
ok("query uses LIKE wildcards for token-anywhere match", (brandCtQueryUrl("acme") || "").includes("%25acme%25"));
eq("1-2 char token refused (matches most of the internet)", brandCtQueryUrl("ab"), null);
eq("empty brand refused", brandCtQueryUrl(""), null);

// ── 2. CT response parsing (name_value newlines, common_name, wildcards) ─────
{
  const raw = [
    { name_value: "office365password.acme.co\n*.acme.co", common_name: "acme.co" },
    { name_value: "www.acme.com", common_name: "acme.com" },
    { name_value: "bogus", common_name: "" },              // not a hostname (no dot) → dropped
    { common_name: "login.acme.net" },
  ];
  const hosts = parseCtResponseHostnames(raw);
  ok("nested host parsed", hosts.includes("office365password.acme.co"));
  ok("wildcard prefix stripped to base", hosts.includes("acme.co"));
  ok("common_name-only host parsed", hosts.includes("login.acme.net"));
  ok("non-hostname dropped", !hosts.includes("bogus"));
  eq("non-array body → empty", parseCtResponseHostnames({}), []);
}

// ── 3. Strict membership filter (the founder example + false-positive control) ─
{
  const bases = buildLookalikeBaseSet("acme", "com");
  ok("acme.co is a generated lookalike base", bases.has("acme.co"));
  ok("acme.net is a generated lookalike base", bases.has("acme.net"));
  ok("own domain acme.com is NOT a lookalike base", !bases.has("acme.com"));

  const discovered = [
    "office365password.acme.co",   // KEEP — nested on a lookalike base
    "login.acme.net",              // KEEP — nested on a lookalike base
    "acme.co",                     // KEEP — bare lookalike base (tld_variation)
    "www.acme.com",                // DROP — own registrable
    "shop.acme.com",               // DROP — own registrable
    "acme-widgets.com",            // DROP — unrelated legit company, base not a lookalike
    "totallyunrelated.example",    // DROP — no brand relation at all
  ];
  const kept = filterDiscoveredHosts(discovered, {
    brand: "acme", tld: "com",
    ownRegistrables: new Set(["acme.com"]),
    lookalikeBases: bases,
  });
  const keptDomains = kept.map((k) => k.candidate_domain);
  ok("FOUNDER EXAMPLE office365password.acme.co is discovered", keptDomains.includes("office365password.acme.co"));
  ok("nested login.acme.net kept", keptDomains.includes("login.acme.net"));
  ok("bare lookalike base acme.co kept", keptDomains.includes("acme.co"));
  ok("own host www.acme.com dropped", !keptDomains.includes("www.acme.com"));
  ok("own host shop.acme.com dropped", !keptDomains.includes("shop.acme.com"));
  ok("unrelated acme-widgets.com dropped", !keptDomains.includes("acme-widgets.com"));
  ok("wholly unrelated host dropped", !keptDomains.includes("totallyunrelated.example"));
  eq("office365password.acme.co typed as nested_host",
    kept.find((k) => k.candidate_domain === "office365password.acme.co")?.variant_type, "nested_host");
  eq("bare base acme.co typed as tld_variation",
    kept.find((k) => k.candidate_domain === "acme.co")?.variant_type, "tld_variation");
  ok("output is deterministic (sorted)", JSON.stringify(keptDomains) === JSON.stringify([...keptDomains].sort()));
  eq("nested_host normalizes canonically", normalizeBrandVariantType("nested_host"), "nested_host");
}

// ── 4. Host cap ──────────────────────────────────────────────────────────────
{
  const bases = new Set(["acme.co"]);
  const many = Array.from({ length: BRAND_CT_HOST_CAP + 20 }, (_, i) => `h${String(i).padStart(3, "0")}.acme.co`);
  const kept = filterDiscoveredHosts(many, { brand: "acme", tld: "com", ownRegistrables: new Set(), lookalikeBases: bases });
  ok("host cap enforced", kept.length === BRAND_CT_HOST_CAP, `got ${kept.length}`);
}

// ── 5. Risk honesty — CT-observed reaches high but not critical until live ───
{
  const host = { candidate_domain: "office365password.acme.co", registrable: "acme.co", variant_type: "nested_host", is_nested: true };
  const { risk, evidence } = buildDiscoveredCandidateRisk(host, "acme");
  ok("CT-observed nested credential host is at least high", ["high", "critical"].includes(risk.risk_level), `got ${risk.risk_level}`);
  ok("CT-observed-not-live is NOT critical", risk.risk_level !== "critical", `got ${risk.risk_level}`);
  ok("risk cites the CT observation", risk.reasons.includes("observed_in_certificate_log"));
  ok("risk records the not-yet-live cap reason", risk.reasons.includes("certificate_observed_not_yet_live"));
  ok("evidence carries ct_observed", evidence.some((e) => e.signal === "ct_observed" && e.value === true));
  ok("evidence carries nested_host", evidence.some((e) => e.signal === "nested_host" && e.value === true));

  // The cap must be load-bearing: a CT-only host whose raw signals SUM above the
  // critical threshold (nested 20 + similarity 35 + brand-kw 8 + login 12 + ct 12
  // = 87) is still held at 'high' because it is not confirmed live. Removing the
  // 84 cap would let it read 'critical' on speculation.
  const hot = scoreBrandCandidateRisk({
    variant_type: "nested_host", similarity_score: 100, contains_brand_keyword: true,
    looks_like_login: true, ct_observed: true, classification: "unreviewed",
  });
  eq("CT-only host above critical-raw is capped to high", hot.risk_level, "high");

  // Escalation: same host confirmed live + mail-capable → may reach critical.
  const live = scoreBrandCandidateRisk({
    variant_type: "nested_host", similarity_score: 100, contains_brand_keyword: true,
    ct_observed: true, dns_active: true, mx_present: true, looks_like_login: true, classification: "unreviewed",
  });
  ok("CT + DNS + MX confirmed can reach critical", live.risk_level === "critical", `got ${live.risk_level}`);

  // Honesty floor: WITHOUT ct_observed and without DNS/MX, a bare permutation stays watchlisted.
  const speculative = scoreBrandCandidateRisk({
    variant_type: "nested_host", similarity_score: 100, contains_brand_keyword: true, classification: "unreviewed",
  });
  eq("no CT + no live → watchlist low", speculative.risk_level, "low");
}

// ── 6. API serializer agrees with the persisted band (no silent disagreement) ─
{
  const row = {
    id: "bra_x", workspace_id: "ws1", domain: "acme.com",
    candidate_domain: "office365password.acme.co", variant_type: "nested_host",
    similarity_score: 100, risk_level: "high", dns_resolves: null, https_available: null,
    status: "unverified", classification: "unreviewed",
    evidence_json: JSON.stringify([{ signal: "ct_observed", value: true }, { signal: "nested_host", value: true }]),
    first_seen: new Date().toISOString(), last_seen: new Date().toISOString(),
  };
  const api = brandCandidateToApi(row, { brand_name: "acme", primary_domain: "acme.com" });
  ok("serializer preserves high band for CT-observed host", ["high", "critical"].includes(api.risk_level), `got ${api.risk_level}`);
  ok("serializer surfaces ct_observed evidence", api.evidence.some((e) => e.signal === "ct_observed"));
  ok("serializer surfaces nested_host evidence", api.evidence.some((e) => e.signal === "nested_host"));
  ok("serializer flags action_required for a high CT host", api.action_required === true);

  // A row WITHOUT ct evidence must fall back to the watchlist cap — proving the
  // serializer reads the durable signal rather than assuming it.
  const bare = brandCandidateToApi({ ...row, evidence_json: JSON.stringify([]) }, { brand_name: "acme", primary_domain: "acme.com" });
  ok("non-CT nested row falls to low without the signal", bare.risk_level === "low", `got ${bare.risk_level}`);
}

// ── 7. End-to-end discovery + persistence with a mocked CT + tenant isolation ─
{
  const db = new DatabaseSync(":memory:");
  db.exec(`
    CREATE TABLE workspaces (id TEXT PRIMARY KEY, deleted_at TEXT);
    CREATE TABLE workspace_domains (workspace_id TEXT, domain_id TEXT);
    CREATE TABLE domains (id TEXT PRIMARY KEY, domain TEXT, created_at TEXT);
    CREATE TABLE workspace_brand_assets (
      id TEXT PRIMARY KEY, workspace_id TEXT, domain TEXT, candidate_domain TEXT, variant_type TEXT,
      similarity_score INTEGER, risk_level TEXT, risk_reasons TEXT, evidence_json TEXT,
      dns_resolves INTEGER, https_available INTEGER, mx_present INTEGER, ip_address TEXT, status TEXT,
      classification TEXT, first_seen TEXT, last_seen TEXT, last_checked_at TEXT, created_at TEXT, updated_at TEXT,
      UNIQUE (workspace_id, domain, candidate_domain));
  `);
  db.prepare("INSERT INTO workspaces VALUES (?,NULL)").run("ws1");
  db.prepare("INSERT INTO workspaces VALUES (?,NULL)").run("ws2");
  db.prepare("INSERT INTO workspaces VALUES (?,?)").run("ws_deleted", "2026-07-25T00:00:00Z");
  db.prepare("INSERT INTO domains VALUES (?,?,?)").run("d1", "acme.com", "2026-01-01T00:00:00Z");
  db.prepare("INSERT INTO workspace_domains VALUES (?,?)").run("ws1", "d1");
  db.prepare("INSERT INTO domains VALUES (?,?,?)").run("d2", "other.com", "2026-01-01T00:00:00Z");
  db.prepare("INSERT INTO workspace_domains VALUES (?,?)").run("ws2", "d2");
  db.prepare("INSERT INTO domains VALUES (?,?,?)").run("d3", "deleted.com", "2026-01-01T00:00:00Z");
  db.prepare("INSERT INTO workspace_domains VALUES (?,?)").run("ws_deleted", "d3");
  // Give both workspaces a seed candidate so the sweep selects them.
  for (const [ws, dom] of [["ws1", "acme.com"], ["ws2", "other.com"]]) {
    db.prepare(`INSERT INTO workspace_brand_assets (id, workspace_id, domain, candidate_domain, variant_type, dns_resolves, status, classification, first_seen, last_seen, created_at, updated_at)
                VALUES (?,?,?,?,?,NULL,'unverified','unreviewed',?,?,?,?)`)
      .run("seed_" + ws, ws, dom, "seed." + dom, "tld_variation", "t", "t", "t", "t");
  }
  for (let i = 0; i < 5; i++) {
    db.prepare(`INSERT INTO workspace_brand_assets (id, workspace_id, domain, candidate_domain, variant_type, dns_resolves, status, classification, first_seen, last_seen, created_at, updated_at)
                VALUES (?,?,?,?,?,NULL,'unverified','unreviewed',?,?,?,?)`)
      .run(`deleted_${i}`, "ws_deleted", "deleted.com", `candidate${i}.deleted.net`, "tld_variation", "t", "t", "t", "t");
  }
  db.prepare(`INSERT INTO workspace_brand_assets
    (id, workspace_id, domain, candidate_domain, variant_type, similarity_score,
     risk_level, risk_reasons, evidence_json, dns_resolves, https_available,
     status, classification, first_seen, last_seen, created_at, updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,NULL,NULL,'unverified','unreviewed',?,?,?,?)`)
    .run("generated_acme_co", "ws1", "acme.com", "acme.co", "tld_variation", 100,
      "low", "[]", JSON.stringify([{ signal: "generated_only", value: true }]),
      "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z",
      "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z");

  const env = { cybermeters_db: {
    prepare(sql) {
      const st = db.prepare(sql);
      // D1 statements support both .bind(...).all() and a bind-less .all()/.run()/.first().
      return {
        bind: (...a) => ({ all: async () => ({ results: st.all(...a) }), run: async () => st.run(...a), first: async () => st.get(...a) ?? null }),
        all: async () => ({ results: st.all() }),
        run: async () => st.run(),
        first: async () => st.get() ?? null,
      };
    },
  } };

  const ctBody = [
    { id: 101, name_value: "office365password.acme.co\nlogin.acme.net", common_name: "acme.co" },
    { id: 102, name_value: "www.acme.com", common_name: "acme.com" },        // own → dropped
    { id: 103, name_value: "unrelated-acme-inc.com" },                        // base not a lookalike → dropped
  ];
  const fetchImpl = async () => ({ ok: true, headers: { get: () => "application/json" }, json: async () => ctBody });

  const stats = await discoverBrandCandidatesForWorkspace(env, "ws1", { fetchImpl });
  ok("discovery queried CT", stats.queried === true);
  ok("discovery kept the in-scope hosts", stats.discovered >= 2, `got ${stats.discovered}`);
  ok("out-of-scope hosts counted as dropped", stats.dropped_out_of_scope >= 2, `got ${stats.dropped_out_of_scope}`);

  const ws1rows = db.prepare("SELECT candidate_domain, variant_type, evidence_json FROM workspace_brand_assets WHERE workspace_id='ws1' AND candidate_domain LIKE '%.acme.%'").all();
  const ws1domains = ws1rows.map((r) => r.candidate_domain);
  ok("office365password.acme.co persisted for ws1", ws1domains.includes("office365password.acme.co"));
  ok("own host www.acme.com NOT persisted", !ws1domains.includes("www.acme.com"));
  ok("unrelated host NOT persisted", !ws1domains.includes("unrelated-acme-inc.com"));
  ok("persisted nested host carries ct_observed evidence",
    JSON.parse(ws1rows.find((r) => r.candidate_domain === "office365password.acme.co")?.evidence_json || "[]")
      .some((e) => e.signal === "ct_observed"));
  const collided = db.prepare("SELECT id, evidence_json, first_seen, last_seen FROM workspace_brand_assets WHERE workspace_id='ws1' AND candidate_domain='acme.co'").get();
  eq("B1 collision keeps the canonical candidate id", collided?.id, "generated_acme_co");
  ok("B1 collision merges ct_observed into the existing generated row",
    JSON.parse(collided?.evidence_json || "[]").some((e) => e.signal === "ct_observed" && e.value === true));
  eq("B1 collision preserves first_seen", collided?.first_seen, "2026-01-01T00:00:00Z");
  ok("B1 collision refreshes last_seen monotonically", collided?.last_seen > "2026-01-01T00:00:00Z");

  // Tenant isolation: nothing landed in ws2 from ws1's discovery.
  const ws2leak = db.prepare("SELECT COUNT(*) c FROM workspace_brand_assets WHERE workspace_id='ws2' AND candidate_domain LIKE '%acme%'").get().c;
  eq("no ws1 discovery leaked into ws2", ws2leak, 0);

  // Idempotency: a second run inserts no duplicates.
  const before = db.prepare("SELECT COUNT(*) c FROM workspace_brand_assets WHERE workspace_id='ws1'").get().c;
  await discoverBrandCandidatesForWorkspace(env, "ws1", { fetchImpl });
  const after = db.prepare("SELECT COUNT(*) c FROM workspace_brand_assets WHERE workspace_id='ws1'").get().c;
  eq("second discovery is idempotent (no duplicate rows)", after, before);

  // Sweep bound: with perDay=1 and two eligible workspaces, one is deferred (logged, not silent).
  const sweepFetches = [];
  const sweep = await runBrandPassiveDiscoverySweep(env, {
    fetchImpl: async (url) => {
      sweepFetches.push(url);
      return fetchImpl(url);
    },
    workspacesPerDay: 1,
  });
  eq("sweep respects the per-day workspace cap", sweep.workspaces, 1);
  ok("sweep reports the deferred workspace count (no silent truncation)", sweep.skipped_workspaces >= 1, `got ${sweep.skipped_workspaces}`);
  ok("B2b deleted top-count workspace cannot consume the bounded slot",
    sweepFetches.every((url) => !decodeURIComponent(url).includes("deleted")));
}

// ── 8. Transient CT failure never fabricates state ───────────────────────────
{
  const db = new DatabaseSync(":memory:");
  db.exec(`CREATE TABLE workspaces (id TEXT PRIMARY KEY, deleted_at TEXT);
           CREATE TABLE workspace_domains (workspace_id TEXT, domain_id TEXT);
           CREATE TABLE domains (id TEXT PRIMARY KEY, domain TEXT, created_at TEXT);
           CREATE TABLE workspace_brand_assets (id TEXT PRIMARY KEY, workspace_id TEXT, domain TEXT, candidate_domain TEXT, variant_type TEXT, similarity_score INTEGER, risk_level TEXT, risk_reasons TEXT, evidence_json TEXT, dns_resolves INTEGER, https_available INTEGER, mx_present INTEGER, ip_address TEXT, status TEXT, classification TEXT, first_seen TEXT, last_seen TEXT, last_checked_at TEXT, created_at TEXT, updated_at TEXT, UNIQUE(workspace_id,domain,candidate_domain));`);
  db.prepare("INSERT INTO workspaces VALUES (?,NULL)").run("ws1");
  db.prepare("INSERT INTO domains VALUES (?,?,?)").run("d1", "acme.com", "t");
  db.prepare("INSERT INTO workspace_domains VALUES (?,?)").run("ws1", "d1");
  const env = { cybermeters_db: { prepare(sql){ const st=db.prepare(sql); return { bind:(...a)=>({ all:async()=>({results:st.all(...a)}), run:async()=>st.run(...a), first:async()=>st.get(...a)??null }) }; } } };
  const stats = await discoverBrandCandidatesForWorkspace(env, "ws1", { fetchImpl: async () => ({ ok: false, status: 502, headers: { get: () => "application/json" }, json: async () => [] }) });
  ok("HTTP error is marked queried", stats.queried === true);
  eq("nothing discovered on transient failure", stats.discovered, 0);
  eq("no rows written on transient failure", db.prepare("SELECT COUNT(*) c FROM workspace_brand_assets").get().c, 0);
}

console.log(`\nvalidate-brand-passive-discovery: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
