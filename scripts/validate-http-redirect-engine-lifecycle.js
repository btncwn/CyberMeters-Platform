#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-http-redirect-engine-lifecycle.js  (CI-blocking)
//
// PR-A2 — real runScanEngine → scoring → D1 / report / customer projection, plus
// lifecycle non-progression.
//
// The fixture harness proves the classifier and the scoring gate in isolation.
// This proves the WHOLE pipeline: a Cloudflare-signed edge response on http://
// must not persist the definitive medium "HTTP Does Not Redirect to HTTPS"
// finding, must not publish a healthy/complete Website Security verdict, and must
// not resolve an OPEN redirect condition or advance its managed case.
//
// Real D1 (schema + migrations), real R2 shim, no network. Node 24+.
// ─────────────────────────────────────────────────────────────────────────────
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engUrl = (f) => pathToFileURL(path.join(root, "workers/scan-api/src/engines", f)).href;
const { runScanEngine } = await import(engUrl("scan-engine.js"));
const { moduleCompletionGate } = await import(engUrl("asm-cases.js"));

const NOW = "2026-07-28T13:00:00.000Z";
const NOW_MS = Date.parse(NOW);
const EXPECTED_MUTANTS = 8;

let passed = 0, failed = 0, killed = 0;
const ok = (name, cond, detail = "") => {
  if (cond) passed += 1;
  else { failed += 1; console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
};

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (f) => { try { db.exec(fs.readFileSync(f, "utf8")); } catch { /* schema/migration overlap */ } };
  apply(path.join(root, "database/schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database/migrations")).filter((n) => n.endsWith(".sql")).sort()) {
    apply(path.join(root, "database/migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}
function makeD1(db) {
  const stmt = (sql, args = []) => ({
    __sql: sql, bind: (...b) => stmt(sql, b),
    first: async (c) => { const r = db.prepare(sql).get(...args) ?? null; return c && r ? r[c] : r; },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid || 0) } }; },
  });
  return {
    prepare: (s) => stmt(s),
    batch: async (l) => { const o = []; db.exec("BEGIN"); try { for (const s of l) o.push(/^\s*select/i.test(s.__sql) ? await s.all() : await s.run()); db.exec("COMMIT"); return o; } catch (e) { db.exec("ROLLBACK"); throw e; } },
    exec: async (s) => { db.exec(s); return { count: 0, duration: 0 }; },
  };
}
function makeR2(store) {
  return {
    get: async (k) => { const b = store.get(String(k)); return b == null ? null : { text: async () => b, json: async () => JSON.parse(b) }; },
    put: async (k, b) => { store.set(String(k), String(b)); return {}; },
    delete: async (k) => { store.delete(String(k)); return {}; },
    head: async () => null, list: async () => ({ objects: [] }),
  };
}
const json = (b, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { "content-type": "application/json" } });

// An OPEN redirect condition + linked managed case whose ordinary prerequisites
// would allow a later verification. Nothing about lifecycle POLICY changes here;
// the proof is that canonical incomplete scan quality already defers the transition.
function seedOpenRedirectCondition(db) {
  db.prepare(`INSERT INTO website_security_conditions
      (id, workspace_id, domain_id, domain, condition_key, observed_severity, observed_title,
       detecting_module, monitoring_status, monitoring_reason, recurrence_type, recurrence_band,
       first_seen_at, last_seen_at, last_changed_at, last_scan_id, last_scan_quality,
       linked_case_id, created_at, updated_at)
     VALUES ('wsc-redir','ws','dom','example.com','ssl_no_http_redirect','medium','HTTP Does Not Redirect to HTTPS',
       'ssl','observed','observed_in_scan','condition_persisting','medium',
       datetime('now','-5 days'), datetime('now','-1 day'), datetime('now','-5 days'),
       'scan-old','complete','mc-redir', datetime('now','-5 days'), datetime('now','-1 day'))`).run();
  db.prepare(`INSERT INTO managed_cases
      (id, workspace_id, case_type, domain_key, domain, finding_id, asset_ref, severity,
       status, evidence_json, recommended_actions_json, created_at, updated_at)
     VALUES ('mc-redir','ws','website_case','website_security','example.com','ssl_no_http_redirect','example.com','medium',
       'awaiting_verification','{}','[]', datetime('now','-5 days'), datetime('now','-1 day'))`).run();
}

// `httpMode` decides ONLY what http:// answers; https:// always serves a genuine
// origin 200, so any difference is attributable to the redirect observation alone.
async function trace(httpMode, { seed = false, deadlineMs = "19000" } = {}) {
  const db = buildDb(); const store = new Map();
  const env = {
    cybermeters_db: makeD1(db), cybermeters_reports: makeR2(store),
    SCAN_CAPACITY_MODE: "legacy", SCAN_SUBREQUEST_LIMIT: "200",
    SCAN_DEADLINE_MS: deadlineMs, APP_VERSION: "pra2-trace",
  };
  db.prepare("INSERT INTO users (id, email) VALUES ('usr','o@example.com')").run();
  db.prepare("INSERT INTO workspaces (id, name, deleted_at) VALUES ('ws','PR-A2',NULL)").run();
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('dom','usr','example.com')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws','dom')").run();
  db.prepare(`INSERT INTO scans (id, workspace_id, domain_id, domain, status, scan_quality, created_at)
              VALUES ('scan-r2','ws','dom','example.com','running',NULL,?)`).run(NOW);
  if (seed) seedOpenRedirectCondition(db);

  const prevFetch = globalThis.fetch, prevErr = console.error;
  globalThis.fetch = async (input) => {
    const url = new URL(String(input)); const host = url.hostname;
    if (
      host === "www.cisa.gov" &&
      url.pathname.endsWith("known_exploited_vulnerabilities.json")
    ) {
      return json({
        title: "CISA Known Exploited Vulnerabilities Catalog",
        catalogVersion: "fixture",
        dateReleased: "2026-07-29T00:00:00.000Z",
        count: 0,
        vulnerabilities: [],
      });
    }
    if (host === "services.nvd.nist.gov") {
      return json({ resultsPerPage: 0, totalResults: 0, vulnerabilities: [] });
    }
    if (host === "crt.sh") return json([]);
    if (host === "api.certspotter.com") return json([{
      id: "c1", not_before: "2026-06-27T00:00:00.000Z", not_after: "2026-09-25T00:00:00.000Z",
      issuer: { name: "PR-A2 Fixture CA" }, dns_names: ["example.com", "www.example.com"],
    }]);
    if (host === "cloudflare-dns.com" || host === "dns.google") {
      const name = String(url.searchParams.get("name") || "").toLowerCase();
      const type = String(url.searchParams.get("type") || "A").toUpperCase();
      if (name === "example.com" && type === "A") return json({ Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] });
      return json({ Status: 0, Answer: [] });
    }
    if (url.protocol === "http:") {
      // Sequential: hop 1 is a GENUINE origin 301 onto another HTTP URL; the REQUIRED
      // hop 2 is a Cloudflare-signed 522 with no usable Location.
      if (httpMode === "seq_edge_hop2") {
        return host === "example.com"
          ? new Response("", { status: 301, headers: { location: "http://www.example.com/", server: "nginx" } })
          : new Response("edge", { status: 522, headers: { server: "cloudflare", "content-type": "text/html" } });
      }
      if (httpMode === "edge") return new Response("edge", { status: 522, headers: { server: "cloudflare", "content-type": "text/html" } });
      if (httpMode === "no_redirect") return new Response("<html></html>", { status: 200, headers: { server: "nginx", "content-type": "text/html" } });
      return new Response("", { status: 301, headers: { location: `https://${host}/`, server: "nginx" } });
    }
    return new Response("<html><title>Example</title></html>", { status: 200, headers: { server: "nginx", "content-type": "text/html" } });
  };
  console.error = () => {};
  try {
    await runScanEngine("scan-r2", "dom", "ws", "example.com", env,
      { now: () => NOW_MS, executionContext: "queue", trigger: "manual" });
  } catch { /* asserted from D1, not from a throw */ }
  finally { globalThis.fetch = prevFetch; console.error = prevErr; }

  const raw = store.get("reports/scan-r2.json");
  const report = raw ? JSON.parse(raw) : null;
  return {
    db, report,
    ssl: report?.modules?.ssl || {},
    quality: db.prepare("SELECT scan_quality FROM scans WHERE id='scan-r2'").get()?.scan_quality ?? null,
    titles: db.prepare("SELECT title FROM findings WHERE scan_id='scan-r2'").all().map((r) => r.title),
    domains: Object.fromEntries(db.prepare("SELECT domain_key, state, coverage, summary FROM cyber_mot_domain_states WHERE scan_id='scan-r2'").all().map((r) => [r.domain_key, r])),
  };
}

// ── T1 — Cloudflare edge on http:// ─────────────────────────────────────────
console.log("── T1. Cloudflare-signed edge on http:// ──");
const edgeT = await trace("edge");
ok("T1: a report was produced", edgeT.report !== null);
ok("T1: chain is NOT validated and records the edge state",
  edgeT.ssl.http_redirect_chain?.http_redirect_validated === false &&
  edgeT.ssl.http_redirect_chain?.observation_state === "cloudflare_edge_error",
  JSON.stringify(edgeT.ssl.http_redirect_chain));
ok('T1: NO definitive "HTTP Does Not Redirect to HTTPS" persisted to D1',
  !edgeT.titles.includes("HTTP Does Not Redirect to HTTPS"), edgeT.titles.join(" | "));
{
  const f = (edgeT.report?.findings || []).find((x) => x.id === "ssl_no_http_redirect");
  ok("T1: any surviving redirect observation carries NO score impact",
    !f || Number(f.score_impact || 0) === 0, JSON.stringify(f && { s: f.severity, i: f.score_impact }));
}
ok("T1: SSL module carries canonical incompleteness for the redirect gap",
  edgeT.ssl.incomplete === true && edgeT.ssl.incomplete_reason === "http_redirect_not_observed",
  JSON.stringify({ i: edgeT.ssl.incomplete, r: edgeT.ssl.incomplete_reason }));
ok("T1: scan_quality is partial (report + D1)",
  edgeT.report?.scan_quality?.status === "partial" && edgeT.quality === "partial",
  JSON.stringify({ rep: edgeT.report?.scan_quality?.status, d1: edgeT.quality }));
{
  const ws = edgeT.domains.website_security || {};
  ok("T1: website_security is NOT a healthy/complete verdict",
    ws.state !== "assessed_healthy" && ws.coverage !== "complete", JSON.stringify(ws));
  ok('T1: …and does NOT say "Assessed — no material issue observed"',
    !/Assessed — no material issue observed/.test(String(ws.summary || "")), String(ws.summary));
}
ok("T1: independently reliable sibling CT evidence remains publishable",
  (edgeT.ssl.cert_not_after || edgeT.ssl.cert_issuer) != null,
  JSON.stringify({ na: edgeT.ssl.cert_not_after, iss: edgeT.ssl.cert_issuer }));

// ── T2 — genuine origin, genuinely no redirect (positive control) ───────────
console.log("\n── T2. genuine origin without a redirect (positive control) ──");
const plainT = await trace("no_redirect");
ok('T2: the definitive "HTTP Does Not Redirect to HTTPS" IS persisted',
  plainT.titles.includes("HTTP Does Not Redirect to HTTPS"), plainT.titles.join(" | "));
ok("T2: SSL module is NOT incomplete (evidence was fully observed)",
  plainT.ssl.incomplete !== true, JSON.stringify(plainT.ssl.incomplete_reason));
ok("T2: scan_quality is complete", plainT.quality === "complete", String(plainT.quality));

// ── T3 — genuine redirect ───────────────────────────────────────────────────
console.log("\n── T3. genuine HTTP→HTTPS redirect ──");
const redirT = await trace("redirect");
ok("T3: chain validated + redirect observed",
  redirT.ssl.http_redirect_chain?.http_redirect_validated === true &&
  redirT.ssl.http_redirects_to_https === true);
ok("T3: NO redirect finding of any kind",
  !redirT.titles.includes("HTTP Does Not Redirect to HTTPS"), redirT.titles.join(" | "));
ok("T3: scan_quality is complete", redirT.quality === "complete", String(redirT.quality));

// ── L — lifecycle / case non-progression ────────────────────────────────────
console.log("\n── L. lifecycle / case non-progression on withheld redirect evidence ──");
const lifeT = await trace("edge", { seed: true });
const condAfter = lifeT.db.prepare("SELECT monitoring_status FROM website_security_conditions WHERE id='wsc-redir'").get() || {};
const caseAfter = lifeT.db.prepare("SELECT status, verified_at FROM managed_cases WHERE id='mc-redir'").get() || {};
const events = lifeT.db.prepare("SELECT event_type FROM website_security_events WHERE record_id='wsc-redir'").all().map((r) => r.event_type);
console.log(`   BEFORE  condition=observed  case=awaiting_verification`);
console.log(`   AFTER   condition=${condAfter.monitoring_status}  case=${caseAfter.status}  events=[${events.join(", ")}]`);
ok("L: NO condition_resolved event (disappearance is not removal)",
  !events.includes("condition_resolved"), events.join(","));
ok("L: condition did NOT progress to no_longer_observed",
  condAfter.monitoring_status !== "no_longer_observed", String(condAfter.monitoring_status));
ok("L: case did NOT advance to verification/resolution",
  !["verification_requested", "verifying", "resolved", "verified"].includes(caseAfter.status),
  String(caseAfter.status));
ok("L: case was NOT verified (verified_at null)", caseAfter.verified_at == null, String(caseAfter.verified_at));
ok("L: the CANONICAL gate is what defers it (no redirect-specific bypass)",
  moduleCompletionGate({ ssl: { incomplete: true } }, { status: "partial", modules_skipped: ["ssl"] }).canVerify("ssl") === false &&
  moduleCompletionGate({ ssl: {} }, { status: "complete", modules_skipped: [] }).canVerify("ssl") === true);

// ── T4 — SEQUENTIAL: genuine hop 1, Cloudflare-signed hop 2 ─────────────────
console.log("\n── T4. sequential second hop unobserved (P1-1) ──");
const seqT = await trace("seq_edge_hop2");
{
  const c = seqT.ssl.http_redirect_chain || {};
  ok("T4: chain NOT validated (hop 1 does not rescue the required hop 2)",
    c.http_redirect_validated === false, String(c.http_redirect_validated));
  ok("T4: CHAIN-level state is the failing hop's, not hop 1's origin_response",
    c.observation_state === "cloudflare_edge_error", String(c.observation_state));
  ok("T4: both hops retained in bounded provenance",
    (c.hop_observations || []).length === 2 &&
    c.hop_observations[0].state === "origin_response" &&
    c.hop_observations[1].state === "cloudflare_edge_error",
    JSON.stringify(c.hop_observations));
  ok("T4: SSL module incomplete via the canonical contract",
    seqT.ssl.incomplete === true && seqT.ssl.incomplete_reason === "http_redirect_not_observed",
    JSON.stringify({ i: seqT.ssl.incomplete, r: seqT.ssl.incomplete_reason }));
  ok("T4: scan_quality is partial (report + D1)",
    seqT.report?.scan_quality?.status === "partial" && seqT.quality === "partial",
    JSON.stringify({ rep: seqT.report?.scan_quality?.status, d1: seqT.quality }));
  ok('T4: NO definitive "HTTP Does Not Redirect to HTTPS" persisted',
    !seqT.titles.includes("HTTP Does Not Redirect to HTTPS"), seqT.titles.join(" | "));
  const f = (seqT.report?.findings || []).find((x) => x.id === "ssl_no_http_redirect");
  ok("T4: no redirect score impact", !f || Number(f.score_impact || 0) === 0, JSON.stringify(f?.score_impact));
  const ws = seqT.domains.website_security || {};
  ok("T4: website_security is not a healthy/complete verdict",
    ws.state !== "assessed_healthy" && ws.coverage !== "complete", JSON.stringify(ws));
}
// Lifecycle non-progression on the sequential shape.
const seqLife = await trace("seq_edge_hop2", { seed: true });
{
  const cond = seqLife.db.prepare("SELECT monitoring_status FROM website_security_conditions WHERE id='wsc-redir'").get() || {};
  const cse = seqLife.db.prepare("SELECT status, verified_at FROM managed_cases WHERE id='mc-redir'").get() || {};
  const ev = seqLife.db.prepare("SELECT event_type FROM website_security_events WHERE record_id='wsc-redir'").all().map((r) => r.event_type);
  console.log(`   T4 lifecycle AFTER  condition=${cond.monitoring_status} case=${cse.status} events=[${ev.join(", ")}]`);
  ok("T4: no condition_resolved on the sequential shape", !ev.includes("condition_resolved"), ev.join(","));
  ok("T4: case did not advance or verify",
    cse.status === "awaiting_verification" && cse.verified_at == null, String(cse.status));
}

// ── T5 — DEADLINE: no HTTP probe ran at all ─────────────────────────────────
console.log("\n── T5. deadline-deferred SSL (no HTTP probe ran) ──");
const dlT = await trace("redirect", { deadlineMs: "0", seed: true });
{
  const c = dlT.ssl.http_redirect_chain || {};
  ok("T5: redirect evidence is explicitly not_assessed",
    c.observation_state === "not_assessed" && c.http_redirect_validated === false,
    JSON.stringify(c.observation_state));
  ok('T5: NO "HTTP Does Not Redirect to HTTPS" persisted (P1-2)',
    !dlT.titles.includes("HTTP Does Not Redirect to HTTPS"), dlT.titles.join(" | "));
  const f = (dlT.report?.findings || []).find((x) => x.id === "ssl_no_http_redirect");
  ok("T5: no redirect score impact", !f || Number(f.score_impact || 0) === 0, JSON.stringify(f?.score_impact));
  ok("T5: scan_quality is partial", dlT.quality === "partial", String(dlT.quality));
  const cond = dlT.db.prepare("SELECT monitoring_status FROM website_security_conditions WHERE id='wsc-redir'").get() || {};
  const cse = dlT.db.prepare("SELECT status, verified_at FROM managed_cases WHERE id='mc-redir'").get() || {};
  const ev = dlT.db.prepare("SELECT event_type FROM website_security_events WHERE record_id='wsc-redir'").all().map((r) => r.event_type);
  ok("T5: no condition_resolved and no case verification",
    !ev.includes("condition_resolved") && cse.status === "awaiting_verification" && cse.verified_at == null,
    `${cond.monitoring_status} / ${cse.status} / [${ev.join(",")}]`);
}

// ── M — mutations (anchor-guarded, pinned) ──────────────────────────────────
console.log("\n── M. mutation proof ──");
const SSL = path.join(root, "workers/scan-api/src/engines/ssl-scan.js");
const SCORING = path.join(root, "workers/scan-api/src/engines/scoring.js");
const SCAN_ENGINE = path.join(root, "workers/scan-api/src/engines/scan-engine.js");
let seq = 0;
async function withMutant({ target, from, to }, run) {
  const original = fs.readFileSync(target, "utf8");
  const mutated = original.replace(from, to);
  if (mutated === original) return { applied: false };
  const name = `.${path.basename(target, ".js")}.mutant.${process.pid}.${++seq}.js`;
  const file = path.join(path.dirname(target), name);
  fs.writeFileSync(file, mutated);
  try { return { applied: true, result: await run(await import(`${pathToFileURL(file).href}?t=${Date.now()}-${Math.random()}`)) }; }
  finally { fs.rmSync(file, { force: true }); }
}
const realFetch = globalThis.fetch;
const noCt = { get: async () => null, set: async () => {} };
async function sslOf(mod, httpImpl) {
  globalThis.fetch = async (input) => {
    const url = new URL(String(input));
    if (url.protocol === "https:") return new Response("<html></html>", { status: 200, headers: { server: "nginx" } });
    return httpImpl(url);
  };
  const e = console.error; console.error = () => {};
  try { return await mod.runSslModule("example.com", { ctCache: noCt }); }
  finally { globalThis.fetch = realFetch; console.error = e; }
}
const edgeResp = () => new Response("edge", { status: 522, headers: { server: "cloudflare" } });

const MUTATIONS = [
  {
    name: "M1 an edge Response is restored as redirect-validated",
    target: SSL,
    from: "  let redirectEvidenceObserved = httpObservation.transport_observed === true;",
    to:   "  let redirectEvidenceObserved = httpRes !== null;",
    check: async (mod) => (await sslOf(mod, edgeResp)).http_redirect_chain.http_redirect_validated === true,
  },
  {
    name: "M2 the SECOND-hop classifier is bypassed",
    target: SSL,
    from: "        if (hop2Observation.transport_observed === true) {",
    to:   "        if (hop2 !== null) {",
    check: async (mod) => {
      // hop1 genuine http→http, hop2 a Cloudflare edge error that CLAIMS an https
      // Location. Bypassing the classifier reads the edge page as a real redirect.
      const m = await sslOf(mod, (url) => url.hostname === "example.com"
        ? new Response("", { status: 301, headers: { location: "http://www.example.com/", server: "nginx" } })
        : new Response("", { status: 301, headers: { location: "https://www.example.com/", server: "cloudflare" } }));
      return m.http_redirects_to_https === true;
    },
  },
  {
    name: "M3 incomplete evidence is restored to DEFINITIVE scoring",
    target: SCORING,
    from: "    const redirectValidated       = isHttpRedirectPositivelyAbsent(modules.ssl);",
    to:   "    const redirectValidated       = true;",
    check: async (mod) => {
      // A chain explicitly marked NOT validated but carrying a stale legacy-shaped
      // true would again reach the definitive branch.
      const r = mod.computeScore({
        ssl: { https_available: null, http_redirect_chain: { http_redirect_validated: true, observation_state: "cloudflare_edge_error" } },
        headers: { headers: {} }, dns: {}, email_security: {},
      }, "example.com");
      const f = (r.findings || []).find((x) => x.id === "ssl_no_http_redirect");
      return !!f && Number(f.score_impact) === -5;
    },
  },
  {
    name: "M4 module incompleteness for the redirect gap is dropped",
    target: SSL,
    from: "    ...((httpsAvailable === true && redirectEvidenceObserved) ? {} : {",
    to:   "    ...((httpsAvailable === true) ? {} : {",
    check: async (mod) => (await sslOf(mod, edgeResp)).incomplete !== true,
  },
  {
    name: "M6 hop 1's state overrides an incomplete REQUIRED second hop",
    target: SSL,
    from: "          redirectEvidenceObserved = false;\n          chainObservation = hop2Observation;",
    to:   "          chainObservation = httpObservation;",
    check: async (mod) => {
      const m = await sslOf(mod, (url) => url.hostname === "example.com"
        ? new Response("", { status: 301, headers: { location: "http://www.example.com/", server: "nginx" } })
        : new Response("edge", { status: 522, headers: { server: "cloudflare" } }));
      // hop 1's origin_response would again be published as the chain verdict.
      return m.http_redirect_chain.http_redirect_validated === true ||
             m.http_redirect_chain.observation_state === "origin_response";
    },
  },
  {
    name: "M7 the `!== false` missing-field semantics are restored in scoring",
    target: SCORING,
    from: "    const redirectValidated       = isHttpRedirectPositivelyAbsent(modules.ssl);",
    to:   "    const redirectValidated       = modules.ssl?.http_redirect_chain?.http_redirect_validated !== false;",
    check: async (mod) => {
      // An ABSENT chain (PR-A1 deadline fallback shape) would again be definitive.
      const r = mod.computeScore({ ssl: { https_available: null }, headers: { headers: {} }, dns: {}, email_security: {} }, "example.com");
      const f = (r.findings || []).find((x) => x.id === "ssl_no_http_redirect");
      return !!f && Number(f.score_impact) === -5;
    },
  },
  {
    name: "M8 second-hop-derived module incompleteness is dropped",
    target: SSL,
    from: "          redirectEvidenceObserved = false;",
    to:   "          redirectEvidenceObserved = true;",
    check: async (mod) => {
      const m = await sslOf(mod, (url) => url.hostname === "example.com"
        ? new Response("", { status: 301, headers: { location: "http://www.example.com/", server: "nginx" } })
        : new Response("edge", { status: 522, headers: { server: "cloudflare" } }));
      return m.incomplete !== true;
    },
  },
  {
    name: "M5 a GENUINE origin redirect is incorrectly suppressed",
    target: SSL,
    from: "      if (loc1.startsWith(\"https://\")) {",
    to:   "      if (false) {",
    check: async (mod) => {
      const m = await sslOf(mod, () => new Response("", { status: 301, headers: { location: "https://example.com/", server: "nginx" } }));
      return m.http_redirects_to_https !== true;   // the real redirect stops being seen
    },
  },
];
for (const m of MUTATIONS) {
  const r = await withMutant(m, (mod) => m.check(mod));
  ok(`${m.name} :: mutation APPLIED (anchor matches product source)`, r.applied,
    "anchor not found — this mutation tests NOTHING");
  if (!r.applied) continue;
  if (r.result === true) killed += 1;
  ok(`${m.name} :: defect REAPPEARS when mutated`, r.result === true);
}
ok(`mutants killed: ${killed}/${EXPECTED_MUTANTS} (pinned)`, killed === EXPECTED_MUTANTS,
  `expected exactly ${EXPECTED_MUTANTS}, killed ${killed}`);
ok(`mutation table length pinned at ${EXPECTED_MUTANTS}`, MUTATIONS.length === EXPECTED_MUTANTS);
const strays = fs.readdirSync(path.join(root, "workers/scan-api/src/engines")).filter((f) => f.includes(".mutant."));
ok("no mutant file left behind", strays.length === 0, strays.join(", "));

console.log(`\nhttp-redirect engine+lifecycle: ${passed}/${passed + failed} passed; ${killed}/${EXPECTED_MUTANTS} mutants killed`);
if (failed) { console.error("http-redirect-engine-lifecycle validation FAILED"); process.exit(1); }
console.log("http-redirect-engine-lifecycle validation passed");
