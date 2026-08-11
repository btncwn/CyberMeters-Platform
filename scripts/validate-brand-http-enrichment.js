#!/usr/bin/env node
//
// Brand HTTP/TLS live enrichment — PR-C. CI-blocking.
//
// The final signal layer of the Brand Protection sprint: for lookalike candidates
// DNS has confirmed live, probe the live web surface to set https_available and
// detect a real login/password form. Proves the honesty + safety contract:
//   1. SSRF safety — a brand candidate is attacker-influenced; the probe MUST go
//      through an SSRF-safe fetcher, and a blocked (null) target must NEVER become
//      a positive OR negative fact.
//   2. tri-state https_available — NULL not probed / 0 no HTTPS / 1 served;
//      transient failures never coerce to 0.
//   3. DNS gate — only dns_resolves=1 candidates are probed.
//   4. live login detection — a password/login form in the body sets
//      looks_like_login; the serializer reads it so a lookalike whose NAME has no
//      login word but whose live page harvests credentials still scores it, and
//      DNS+HTTPS+login can honestly reach 'critical'.
//   5. tenant isolation + idempotency.
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
  detectLoginSurface, probeCandidateHttp, httpOutcomeToPersistence,
  mergeHttpEvidence, selectBrandHttpCandidatesSql,
  enrichBrandCandidatesHttp, runBrandHttpEnrichmentSweep,
} = await import(eng("brand-http-enrichment.js"));
const { brandCandidateToApi, scoreBrandCandidateRisk } = await import(eng("brand-protection.js"));

function createBrandAuthorityTables(db) {
  db.exec(`CREATE TABLE workspaces (id TEXT PRIMARY KEY, deleted_at TEXT);
    CREATE TABLE domains (id TEXT PRIMARY KEY, domain TEXT);
    CREATE TABLE workspace_domains (workspace_id TEXT, domain_id TEXT, UNIQUE(workspace_id, domain_id));`);
}

function seedBrandAuthority(db, workspaceId) {
  const domainId = `dom_${workspaceId}`;
  db.prepare("INSERT OR IGNORE INTO workspaces (id, deleted_at) VALUES (?, NULL)").run(workspaceId);
  db.prepare("INSERT OR IGNORE INTO domains (id, domain) VALUES (?, 'acme.com')").run(domainId);
  db.prepare("INSERT OR IGNORE INTO workspace_domains (workspace_id, domain_id) VALUES (?, ?)")
    .run(workspaceId, domainId);
}

// helpers to fake Response objects
const resp = (status, body = "") => ({ status, text: async () => body });

// ── 1. Login-surface detection ───────────────────────────────────────────────
ok("password input detected", detectLoginSurface('<form><input type="password" name="pw"></form>'));
ok("password input detected (unquoted)", detectLoginSurface("<input type=password>"));
ok("password by name detected", detectLoginSurface('<input name="passwd">'));
ok("otp/mfa field detected", detectLoginSurface('<input name="otp">'));
ok("plain marketing page → no login surface", !detectLoginSurface("<h1>Welcome to our shop</h1><input type=text name=q>"));
eq("empty body → no login", detectLoginSurface(""), false);

// ── 2. Probe outcomes ────────────────────────────────────────────────────────
{
  const served = await probeCandidateHttp("acme.co", async () => resp(200, '<input type="password">'));
  eq("2xx with password form → served + login", [served.outcome, served.https_available, served.looks_like_login], ["served", 1, true]);
  const servedNoLogin = await probeCandidateHttp("acme.co", async () => resp(200, "<h1>hi</h1>"));
  eq("2xx no form → served, login false", [servedNoLogin.outcome, servedNoLogin.https_available, servedNoLogin.looks_like_login], ["served", 1, false]);
  const err4xx = await probeCandidateHttp("acme.co", async () => resp(404, "<input type=password>"));
  eq("4xx served HTTPS but login not read from error body", [err4xx.outcome, err4xx.https_available, err4xx.looks_like_login], ["served", 1, false]);
  const blocked = await probeCandidateHttp("acme.co", async () => null); // SSRF-blocked
  eq("SSRF-blocked target → transient (never a fact)", blocked.outcome, "transient");
  const threw = await probeCandidateHttp("acme.co", async () => { throw new Error("timeout"); });
  eq("probe throw → transient", threw.outcome, "transient");
}

// ── 3. Persistence mapping (tri-state; transient never persists) ─────────────
eq("served → https 1", httpOutcomeToPersistence({ outcome: "served", https_available: 1, looks_like_login: true }), { https_available: 1, looks_like_login: true });
eq("no_https → https 0", httpOutcomeToPersistence({ outcome: "no_https" }), { https_available: 0, looks_like_login: false });
eq("transient → null (do not persist)", httpOutcomeToPersistence({ outcome: "transient" }), null);

// ── 4. Evidence merge preserves prior signals ────────────────────────────────
{
  const prior = JSON.stringify([{ signal: "ct_observed", value: true }, { signal: "nested_host", value: true }]);
  const merged = mergeHttpEvidence(prior, { https_available: 1, looks_like_login: true });
  ok("ct_observed preserved", merged.some((e) => e.signal === "ct_observed" && e.value === true));
  ok("nested_host preserved", merged.some((e) => e.signal === "nested_host" && e.value === true));
  ok("https_active added", merged.some((e) => e.signal === "https_active" && e.value === true));
  ok("looks_like_login added", merged.some((e) => e.signal === "looks_like_login" && e.value === true));
  const noLogin = mergeHttpEvidence("[]", { https_available: 1, looks_like_login: false });
  ok("no login signal when none detected", !noLogin.some((e) => e.signal === "looks_like_login"));
}

// ── 5. Selection SQL gates on dns_resolves = 1 ───────────────────────────────
{
  const sql = selectBrandHttpCandidatesSql();
  ok("selection requires dns_resolves = 1", /dns_resolves\s*=\s*1/.test(sql));
  ok("selection is workspace-scoped", /workspace_id\s*=\s*\?/.test(sql));
  ok("selection skips closed classifications", /NOT IN \('owned','ignored','false_positive'\)/.test(sql));
}

// ── 6. Live login lifts the serializer band; DNS+HTTPS+login → critical ──────
{
  // A TLD-swap whose HOSTNAME has no login word (acme.co, sld 'acme'), but whose
  // live page harvested credentials — must still score the login signal.
  const row = {
    id: "b1", workspace_id: "ws1", domain: "acme.com", candidate_domain: "acme.co",
    variant_type: "tld_variation", similarity_score: 100, risk_level: "high",
    dns_resolves: 1, https_available: 1, status: "active", classification: "unreviewed",
    evidence_json: JSON.stringify([{ signal: "ct_observed", value: true }, { signal: "https_active", value: true }, { signal: "looks_like_login", value: true }]),
    first_seen: new Date().toISOString(), last_seen: new Date().toISOString(),
  };
  const api = brandCandidateToApi(row, { brand_name: "acme", primary_domain: "acme.com" });
  ok("live login + DNS + HTTPS reaches critical", api.risk_level === "critical", `got ${api.risk_level}`);
  ok("serializer surfaces looks_like_login", api.evidence.some((e) => e.signal === "looks_like_login"));

  // Tipping point: the live login signal is what must be load-bearing. A nested
  // host confirmed DNS-live + HTTPS-serving but with NO brand keyword and NO CT is
  // 'high'; adding the live login form pushes it to 'critical'.
  const withoutLogin = scoreBrandCandidateRisk({ variant_type: "nested_host", similarity_score: 100, dns_active: true, https_active: true, classification: "unreviewed" });
  eq("DNS+HTTPS, no login → high", withoutLogin.risk_level, "high");
  const withLogin = scoreBrandCandidateRisk({ variant_type: "nested_host", similarity_score: 100, dns_active: true, https_active: true, looks_like_login: true, classification: "unreviewed" });
  eq("DNS+HTTPS+live login → critical", withLogin.risk_level, "critical");

  // Same tipping point THROUGH the serializer — proves brandCandidateToApi reads
  // the LIVE looks_like_login signal (not just the hostname). The subdomain label
  // 'xy' contains neither the brand nor a login word, so only the persisted live
  // signal can supply the login score.
  const baseRow = {
    id: "b2", workspace_id: "ws1", domain: "acme.com", candidate_domain: "xy.acme.co",
    variant_type: "nested_host", similarity_score: 100, risk_level: "high",
    dns_resolves: 1, https_available: 1, status: "active", classification: "unreviewed",
    first_seen: new Date().toISOString(), last_seen: new Date().toISOString(),
  };
  const apiNoLogin = brandCandidateToApi({ ...baseRow, evidence_json: JSON.stringify([{ signal: "https_active", value: true }]) }, { brand_name: "acme", primary_domain: "acme.com" });
  eq("serializer: DNS+HTTPS, no live login → high", apiNoLogin.risk_level, "high");
  const apiLogin = brandCandidateToApi({ ...baseRow, evidence_json: JSON.stringify([{ signal: "https_active", value: true }, { signal: "looks_like_login", value: true }]) }, { brand_name: "acme", primary_domain: "acme.com" });
  eq("serializer: DNS+HTTPS+live login → critical", apiLogin.risk_level, "critical");
}

// ── 7. End-to-end enrichment + tenant isolation + idempotency ────────────────
{
  const db = new DatabaseSync(":memory:");
  db.exec(`CREATE TABLE workspace_brand_assets (
    id TEXT PRIMARY KEY, workspace_id TEXT, domain TEXT, candidate_domain TEXT, variant_type TEXT,
    similarity_score INTEGER, risk_level TEXT, risk_reasons TEXT, evidence_json TEXT,
    dns_resolves INTEGER, https_available INTEGER, ip_address TEXT, status TEXT,
    classification TEXT, first_seen TEXT, last_seen TEXT, last_checked_at TEXT, created_at TEXT, updated_at TEXT,
    UNIQUE(workspace_id,domain,candidate_domain));`);
  createBrandAuthorityTables(db);
  const ins = (ws, cand, dns, https, cls = "unreviewed") => {
    seedBrandAuthority(db, ws);
    db.prepare(`INSERT INTO workspace_brand_assets (id,workspace_id,domain,candidate_domain,variant_type,risk_level,evidence_json,dns_resolves,https_available,status,classification,first_seen,last_seen,last_checked_at,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
      .run(`id_${ws}_${cand}`, ws, "acme.com", cand, "nested_host", "high",
           JSON.stringify([{ signal: "ct_observed", value: true }]), dns, https, "active", cls, "t", "t", null, "t", "t");
  };
  ins("ws1", "office365password.acme.co", 1, null);  // DNS live, HTTPS unknown → probed
  ins("ws1", "notresolving.acme.co", 0, null);        // DNS dead → NOT probed
  ins("ws1", "owned.acme.co", 1, null, "owned");       // closed → NOT probed
  ins("ws2", "other.acme.co", 1, null);                // different tenant

  const env = { cybermeters_db: { prepare(sql){ const st=db.prepare(sql); return {
    bind:(...a)=>({ all:async()=>({results:st.all(...a)}), run:async()=>st.run(...a), first:async()=>st.get(...a)??null }),
    all:async()=>({results:st.all()}), run:async()=>st.run(), first:async()=>st.get()??null }; } } };

  // Fake SSRF-safe fetcher: the credential host serves a login form.
  const probeFetch = async (url) => url.includes("office365password") ? resp(200, '<input type="password">') : resp(200, "<h1>ok</h1>");

  const stats = await enrichBrandCandidatesHttp(env, "ws1", { probeFetch });
  eq("only the DNS-live, open candidate was selected", stats.selected, 1);
  eq("one served", stats.served, 1);
  eq("one login surface found", stats.login_surfaces, 1);

  const row = db.prepare("SELECT https_available, evidence_json FROM workspace_brand_assets WHERE candidate_domain='office365password.acme.co'").get();
  eq("https_available persisted = 1", row.https_available, 1);
  ok("looks_like_login persisted", JSON.parse(row.evidence_json).some((e) => e.signal === "looks_like_login" && e.value === true));
  ok("prior ct_observed preserved through merge", JSON.parse(row.evidence_json).some((e) => e.signal === "ct_observed"));

  const dead = db.prepare("SELECT https_available FROM workspace_brand_assets WHERE candidate_domain='notresolving.acme.co'").get();
  eq("DNS-dead candidate never probed (https stays NULL)", dead.https_available, null);
  const owned = db.prepare("SELECT https_available FROM workspace_brand_assets WHERE candidate_domain='owned.acme.co'").get();
  eq("closed candidate never probed", owned.https_available, null);
  const ws2 = db.prepare("SELECT https_available FROM workspace_brand_assets WHERE workspace_id='ws2'").get();
  eq("tenant isolation: ws2 untouched by ws1 enrichment", ws2.https_available, null);

  // Idempotency: re-running selects nothing (https already set, not stale).
  const again = await enrichBrandCandidatesHttp(env, "ws1", { probeFetch });
  eq("second run selects nothing (not stale)", again.selected, 0);

  // Sweep bound reporting.
  ins("ws3", "x.acme.co", 1, null);
  const sweep = await runBrandHttpEnrichmentSweep(env, { probeFetch, workspacesPerTick: 1 });
  eq("sweep respects per-tick cap", sweep.workspaces, 1);
  ok("sweep reports skipped workspaces (no silent truncation)", sweep.skipped_workspaces >= 1, `got ${sweep.skipped_workspaces}`);
}

// ── 8. Transient failure never writes state ──────────────────────────────────
{
  const db = new DatabaseSync(":memory:");
  db.exec(`CREATE TABLE workspace_brand_assets (id TEXT PRIMARY KEY, workspace_id TEXT, domain TEXT, candidate_domain TEXT, variant_type TEXT, risk_level TEXT, evidence_json TEXT, dns_resolves INTEGER, https_available INTEGER, ip_address TEXT, status TEXT, classification TEXT, first_seen TEXT, last_seen TEXT, last_checked_at TEXT, created_at TEXT, updated_at TEXT, UNIQUE(workspace_id,domain,candidate_domain));`);
  createBrandAuthorityTables(db);
  seedBrandAuthority(db, "ws1");
  db.prepare(`INSERT INTO workspace_brand_assets (id,workspace_id,domain,candidate_domain,variant_type,risk_level,evidence_json,dns_resolves,https_available,status,classification,first_seen,last_seen,created_at,updated_at) VALUES ('i1','ws1','acme.com','acme.co','tld_variation','high','[]',1,NULL,'active','unreviewed','t','t','t','t')`).run();
  const env = { cybermeters_db: { prepare(sql){ const st=db.prepare(sql); return { bind:(...a)=>({ all:async()=>({results:st.all(...a)}), run:async()=>st.run(...a), first:async()=>st.get(...a)??null }), all:async()=>({results:st.all()}), run:async()=>st.run(), first:async()=>st.get()??null }; } } };
  const stats = await enrichBrandCandidatesHttp(env, "ws1", { probeFetch: async () => null }); // always SSRF-blocked/transient
  eq("transient: nothing checked", stats.checked, 0);
  eq("transient: https_available stays NULL", db.prepare("SELECT https_available FROM workspace_brand_assets WHERE id='i1'").get().https_available, null);
}

console.log(`\nvalidate-brand-http-enrichment: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
