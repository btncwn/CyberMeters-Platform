#!/usr/bin/env node
//
// Aggregate scan-ownership tenant isolation. CI-blocking. Node 24+.
//
// THE DEFECT: workspace_domains' PK is (workspace_id, domain_id), so one domain
// can be co-linked to two workspaces. Aggregate dashboard/portfolio reads
// attributed scans by that domain LINK (`JOIN workspace_domains wd ON
// s.domain_id = wd.domain_id WHERE wd.workspace_id = ?`) instead of by the scan's
// OWN owner (s.workspace_id). A member of workspace B could therefore read
// values derived from workspace A's scans (remediation titles/reasons, finding
// titles/counts, scores, timings, scan-quality context, email-policy values
// derived from A's stored report) through B's own entitled aggregate routes.
// A second, quieter consequence: "latest scan per domain" was ranked GLOBALLY,
// so A's newer scan also DISPLACED B's own older, legitimate scan.
//
// THE CONTRACT this suite proves, per affected route:
//   1. B never sees A-derived (or NULL-owner-derived) values;
//   2. B still sees its OWN older scan (no over-correction / deny-all);
//   3. the R2 report keys of A's and the NULL-owner scans are NEVER read
//      (ownership is decided before any R2 key is derived);
//   4. an exact created_at tie between A and B resolves to B's scan for B;
//   5. B is refused A's workspace routes (403), anonymous is refused (401);
//   6. A's owner still sees A's data (the foreign data is real, not vacuous).
//
// Drives the REAL worker fetch() against a REAL in-memory SQLite with schema +
// migrations applied (same instrument as validate-f021-scan-read-tenant-isolation.js).
// Stored reports carry valid Phase-5 evidence so projected scores are published
// rather than suppressed — a suppressed score would make "A's score is absent"
// vacuous.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const workerPath = path.join(root, "workers", "scan-api", "src", "index.js");

async function loadWorker() {
  globalThis.fetch = async () => { throw new Error("network disabled"); };
  AbortSignal.timeout = () => undefined;
  return import(pathToFileURL(workerPath).href);
}

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering/dup — schema converges */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  return db;
}

function makeD1(db) {
  const wrap = (sql, args) => ({
    __sql: sql, __args: args,
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all:   async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run:   async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid ?? 0) } }; },
  });
  return {
    prepare(sql) { const b = wrap(sql, []); b.bind = (...args) => wrap(sql, args); return b; },
    async batch(stmts) { return Promise.all(stmts.map((s) => (/^\s*(with|select)/i.test(s.__sql) ? s.all() : s.run()))); },
    async exec(sql) { db.exec(sql); return { count: 0, duration: 0 }; },
  };
}

// ── Fixture identities ──────────────────────────────────────────────────────
const SHARED = "shared-tenant.com";   // co-linked to A and B (must satisfy isValidDomain)
const TIE    = "tie-tenant.com";      // co-linked; A and B scans share one created_at

// Every scan carries values unique to its owner: score, finding/remediation
// titles, and the DMARC policy its stored report records.
const SCANS = {
  // B — legitimate, OLDER than every foreign scan on the same domain.
  scan_b_old:      { ws: "wsB", dom: "dom1", domain: SHARED, age: "-10 days", score: 41, quality: "complete", policy: "reject",
                     findings: [["critical", "FINDING-B-OWN-CRIT"], ["high", "FINDING-B-OWN-HIGH"]], rem: "REMEDIATION-B-OWN" },
  // Equal-timestamp control: B's id sorts LOWER than A's tie scan, so a global
  // (created_at DESC, id DESC) rank would pick A.
  scan_b_tie:      { ws: "wsB", dom: "dom2", domain: TIE,    at: "TIE", score: 43, quality: "complete", policy: "reject",
                     findings: [["critical", "FINDING-B-TIE-CRIT"]], rem: "REMEDIATION-B-TIE" },
  // A — foreign, NEWER than B's scan on the shared domain.
  scan_x_a_new:    { ws: "wsA", dom: "dom1", domain: SHARED, age: "-2 days",  score: 97, quality: "complete", policy: "none",
                     findings: [["critical", "FINDING-A-FOREIGN-CRIT"], ["critical", "FINDING-A-FOREIGN-CRIT2"], ["high", "FINDING-A-FOREIGN-HIGH"]], rem: "REMEDIATION-A-FOREIGN" },
  scan_x_a_tie:    { ws: "wsA", dom: "dom2", domain: TIE,    at: "TIE", score: 99, quality: "complete", policy: "none",
                     findings: [["critical", "FINDING-A-TIE-CRIT"], ["high", "FINDING-A-TIE-HIGH"]], rem: "REMEDIATION-A-TIE" },
  // A's newest scan is provider-degraded: it would leak as B's "latest quality".
  scan_x_a_partial:{ ws: "wsA", dom: "dom1", domain: SHARED, age: "-12 hours", score: 55, quality: "partial", policy: "none",
                     findings: [["critical", "FINDING-A-PARTIAL-CRIT"]], rem: "REMEDIATION-A-PARTIAL" },
  // Owner UNKNOWN, newest of all. Must never be attributed to anyone.
  scan_x_null:     { ws: null,  dom: "dom1", domain: SHARED, age: "-6 hours", score: 13, quality: "complete", policy: "quarantine",
                     findings: [["critical", "FINDING-NULL-CRIT"]], rem: "REMEDIATION-NULL" },
};
const OWN_IDS = ["scan_b_old", "scan_b_tie"];
const FOREIGN_IDS = Object.keys(SCANS).filter((id) => !OWN_IDS.includes(id));
const FOREIGN_MARKERS = [
  "FINDING-A-", "REMEDIATION-A-", "FINDING-NULL", "REMEDIATION-NULL", "DMARC-MARK-A", "DMARC-MARK-NULL",
];

const r2Gets = [];
function reportFor(id) {
  const s = SCANS[id];
  const mark = s.ws === "wsB" ? "DMARC-MARK-B" : s.ws === "wsA" ? "DMARC-MARK-A" : "DMARC-MARK-NULL";
  return {
    scan_id: id, domain: s.domain, status: "completed",
    modules: {
      // Valid Phase-5 evidence: projected scores stay published.
      cve_intelligence: {
        technologies_checked: ["nginx"], lookup_statuses: { nginx: { status: "complete" } },
        results: { nginx: [] }, total_cves: 0, critical_count: 0, high_count: 0,
        source: "nvd_api", cve_coverage: "complete",
      },
      known_exploited_vulnerabilities: {},
      email_security_intelligence: {},
      email_security: {
        spf: { present: true, status: "valid" },
        dkim: { present: true, status: "valid" },
        dmarc: { present: true, policy: s.policy, record: `v=DMARC1; p=${s.policy}; rua=mailto:${mark}@example.net` },
      },
    },
  };
}
function makeEnv(db) {
  const r2 = {
    get: async (key) => {
      const k = String(key ?? "");
      r2Gets.push(k);
      const m = /^reports\/([^/]+)\.json$/.exec(k);
      if (m && SCANS[m[1]]) { const rep = reportFor(m[1]); return { json: async () => rep, text: async () => JSON.stringify(rep) }; }
      return null;
    },
    put: async () => ({}), head: async () => null, delete: async () => ({}), list: async () => ({ objects: [] }),
  };
  return {
    cybermeters_db: makeD1(db), cybermeters_reports: r2,
    MFA_ENCRYPTION_KEY: "agg-own-mfa-key", STRIPE_WEBHOOK_SECRET: "whsec_test", STRIPE_SECRET_KEY: "sk_test_x",
    STRIPE_PRICE_MAP: "{}", ALLOWED_ORIGIN: "https://app.cybermeters.com", FRONTEND_URL: "https://app.cybermeters.com",
    APP_VERSION: "test", RESEND_API_KEY: "", ADMIN_EMAILS: "",
  };
}
const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };

let passed = 0, failed = 0; const results = [];
let section = "General";
function ok(name, cond, detail = "") {
  if (cond) { passed++; results.push(`PASS [${section}] ${name}`); }
  else      { failed++; results.push(`FAIL [${section}] ${name}${detail ? ` — ${detail}` : ""}`); }
}
const foreignKeysRead = () => r2Gets.filter((k) => FOREIGN_IDS.some((id) => k.includes(id)));
const foreignMarkersIn = (body) => FOREIGN_MARKERS.filter((m) => String(body).includes(m));

async function main() {
  const mod = await loadWorker();
  const worker = mod.default;
  const { hashToken } = mod;
  const db = buildDb();
  const env = makeEnv(db);

  const seedErrors = [];
  const run = (sql, ...a) => { try { db.prepare(sql).run(...a); } catch (e) { seedErrors.push(`${e.message} :: ${sql.slice(0, 80)}`); } };

  // alice owns A; bob owns B and is authorised ONLY on B. Both on an entitled
  // plan so the gated aggregate routes are actually reached.
  const T = { alice: "raw-agg-alice", bob: "raw-agg-bob" };
  for (const [uid, email] of [["alice", "alice@a.example"], ["bob", "bob@b.example"]]) {
    run("INSERT INTO users (id,email,name,plan,status,email_verified,mfa_enabled) VALUES (?,?,?,'business','active',1,0)", uid, email, uid);
    run("INSERT INTO user_sessions (id,user_id,token_hash,expires_at) VALUES (?,?,?,datetime('now','+1 day'))", `sess-${uid}`, uid, await hashToken(T[uid]));
    run("INSERT INTO subscriptions (id,owner_user_id,plan,status,subscription_status,current_period_end,created_at) VALUES (?,?,'business','active','active',datetime('now','+30 days'),datetime('now'))", `sub-${uid}`, uid);
  }
  run("INSERT INTO workspaces (id,owner_user_id,name) VALUES ('wsA','alice','Alpha')");
  run("INSERT INTO workspaces (id,owner_user_id,name) VALUES ('wsB','bob','Bravo')");
  run("INSERT INTO workspace_members (id,workspace_id,user_id,role) VALUES ('mA','wsA','alice','owner')");
  run("INSERT INTO workspace_members (id,workspace_id,user_id,role) VALUES ('mB','wsB','bob','owner')");

  // ── THE FIXTURE: each domain co-linked to BOTH workspaces ─────────────────
  for (const [id, name] of [["dom1", SHARED], ["dom2", TIE]]) {
    run("INSERT INTO domains (id,user_id,domain,verification_status) VALUES (?,?,?,'verified')", id, "alice", name);
    for (const ws of ["wsA", "wsB"]) {
      run("INSERT INTO workspace_domains (workspace_id,domain_id,verification_status,verified_at) VALUES (?,?,'verified',datetime('now'))", ws, id);
    }
  }
  const tieAt = db.prepare("SELECT datetime('now','-5 days') AS t").get().t;
  for (const [id, s] of Object.entries(SCANS)) {
    const at = s.at === "TIE" ? tieAt : db.prepare("SELECT datetime('now', ?) AS t").get(s.age).t;
    s.created_at = at;
    run(`INSERT INTO scans (id,workspace_id,domain_id,domain,score,rating,status,scan_quality,created_at)
         VALUES (?,?,?,?,?,'fair','completed',?,?)`, id, s.ws, s.dom, s.domain, s.score, s.quality, at);
    s.findings.forEach(([sev, title], i) =>
      run("INSERT INTO findings (id,scan_id,finding_slug,severity,title,created_at) VALUES (?,?,?,?,?,?)",
        `f-${id}-${i}`, id, `fixture_${sev}_${i}`, sev, title, at));
    run("INSERT INTO remediation_items (id,scan_id,priority,title,reason,created_at) VALUES (?,?,'1',?,?,?)",
      `r-${id}`, id, s.rem, `${s.rem}-REASON`, at);
  }

  // ── FIXTURE PRECONDITIONS — negative assertions are vacuous if these fail ──
  section = "fixture-preconditions";
  ok(`no seeding errors (${seedErrors[0] ?? "none"})`, seedErrors.length === 0);
  const links = db.prepare("SELECT domain_id, COUNT(*) AS n FROM workspace_domains GROUP BY domain_id").all();
  ok("each fixture domain is co-linked to BOTH workspaces", links.length === 2 && links.every((l) => l.n === 2));
  ok("bob is a member of wsB only",
    JSON.stringify(db.prepare("SELECT workspace_id FROM workspace_members WHERE user_id='bob'").all().map((r) => r.workspace_id)) === '["wsB"]');
  ok("A's shared-domain scan is NEWER than B's", SCANS.scan_x_a_new.created_at > SCANS.scan_b_old.created_at);
  ok("NULL-owner scan is the newest completed scan on the shared domain",
    db.prepare("SELECT id FROM scans WHERE domain_id='dom1' AND scan_quality='complete' ORDER BY created_at DESC LIMIT 1").get().id === "scan_x_null");
  ok("tie scans share one created_at and A's id sorts higher",
    SCANS.scan_b_tie.created_at === SCANS.scan_x_a_tie.created_at && "scan_x_a_tie" > "scan_b_tie");
  ok("NULL-owner scan has NULL workspace_id",
    db.prepare("SELECT workspace_id FROM scans WHERE id='scan_x_null'").get().workspace_id === null);

  const call = async (p, tok) => {
    const headers = tok ? { Authorization: `Bearer ${tok}` } : {};
    const r = await worker.fetch(new Request(`https://api.test${p}`, { headers }), env, ctx);
    const body = await r.text();
    let data; try { data = JSON.parse(body); } catch { data = null; }
    return { status: r.status, body, data };
  };

  // ── 0. AUTH / AUTHZ CONTROLS ──────────────────────────────────────────────
  section = "authz-controls";
  for (const p of ["/api/workspaces/wsA/executive-dashboard", "/api/workspaces/wsA/posture",
                   "/api/workspaces/wsA/posture/timeline", "/api/workspaces/wsA/identity-exposure",
                   `/api/workspaces/wsA/domains/${SHARED}/bec-exposure`, "/api/workspaces/wsA/related-changes"]) {
    r2Gets.length = 0;
    const r = await call(p, T.bob);
    ok(`bob is refused A's ${p} (403)`, r.status === 403, `status ${r.status}`);
    ok(`no foreign R2 key read while refusing ${p}`, foreignKeysRead().length === 0);
  }
  const anon = await call("/api/workspaces/wsB/executive-dashboard", null);
  ok("anonymous request is refused (401)", anon.status === 401, `status ${anon.status}`);

  // Each check: run as bob against B, assert own values + no foreign values +
  // no foreign R2 read. `own` asserts B's legitimate (older) data is present.
  const B_CRIT = SCANS.scan_b_old.findings.filter(([s]) => s === "critical").length
               + SCANS.scan_b_tie.findings.filter(([s]) => s === "critical").length;   // 2
  const B_HIGH = 1;
  const B_AVG  = (SCANS.scan_b_old.score + SCANS.scan_b_tie.score) / 2;                // 42
  const probe = async (name, p, own) => {
    section = name;
    r2Gets.length = 0;
    const r = await call(p, T.bob);
    ok(`${name} reaches the aggregate (200)`, r.status === 200, `status ${r.status} ${r.body.slice(0, 160)}`);
    const leaked = foreignMarkersIn(r.body);
    ok(`${name} shows no A-derived or NULL-owner-derived values`, leaked.length === 0, leaked.join(","));
    const keys = foreignKeysRead();
    ok(`${name} never reads a foreign or NULL-owner R2 report key`, keys.length === 0, keys.join(","));
    for (const [label, fn] of own) {
      let v = false; try { v = fn(r.data, r.body); } catch { v = false; }
      ok(`${name} ${label}`, v, JSON.stringify(r.data)?.slice(0, 300));
    }
    return r;
  };

  // ── 1. Executive dashboard ────────────────────────────────────────────────
  await probe("executive-dashboard", "/api/workspaces/wsB/executive-dashboard", [
    ["keeps B's own remediation (older legitimate scan)", (d) => d.remediation.fix_now.some((x) => x.title === "REMEDIATION-B-OWN")],
    ["keeps B's own tie-scan remediation", (d) => d.remediation.fix_now.some((x) => x.title === "REMEDIATION-B-TIE")],
    ["remediation contains ONLY B's items", (d) => d.remediation.fix_now.length === 2],
    ["last_scan_at is B's own latest scan, not A's/NULL's", (d) => d.summary.last_scan_at === SCANS.scan_b_tie.created_at],
    ["critical count is B's own", (d) => d.summary.critical_findings === B_CRIT],
    ["top risks are B's own findings", (d, b) => b.includes("FINDING-B-OWN-CRIT") && b.includes("FINDING-B-TIE-CRIT")],
  ]);

  // ── 2. Posture + timeline ─────────────────────────────────────────────────
  await probe("posture", "/api/workspaces/wsB/posture", [
    ["critical_findings is B's own 30-day count", (d) => d.critical_findings === B_CRIT],
    ["avg_score_last_30d is B's own (valid Phase-5 evidence, published)", (d) => d.avg_score_last_30d === Math.round(B_AVG)],
  ]);
  await probe("posture-timeline", "/api/workspaces/wsB/posture/timeline", [
    ["daily critical findings total B's own count", (d) =>
      d.timeline.reduce((n, x) => n + Number(x.critical_findings || 0), 0) === B_CRIT],
    ["no critical entry on A's/NULL's scan days", (d) => {
      const days = new Map(d.timeline.map((x) => [x.day, Number(x.critical_findings || 0)]));
      return [SCANS.scan_x_a_new, SCANS.scan_x_a_partial, SCANS.scan_x_null]
        .every((s) => (days.get(s.created_at.slice(0, 10)) ?? 0) === 0
          || s.created_at.slice(0, 10) === SCANS.scan_b_old.created_at.slice(0, 10));
    }],
  ]);

  // ── 3. Identity exposure (email-policy values derived from stored reports) ─
  await probe("identity-exposure", "/api/workspaces/wsB/identity-exposure", [
    ["evaluates B's own two domains", (d) => d.signals.email_spoofing.checked_domains === 2],
    ["policy values are B's own ('reject'), not A's 'none' or NULL's 'quarantine'", (d) =>
      d.signals.email_spoofing.details.every((x) => x.dmarc_policy === "reject")],
    ["reads exactly B's own report keys", () =>
      JSON.stringify([...new Set(r2Gets)].filter((k) => k.startsWith("reports/")).sort())
        === JSON.stringify(["reports/scan_b_old.json", "reports/scan_b_tie.json"])],
  ]);

  // ── 4. BEC exposure (sender-provenance email modules) ─────────────────────
  await probe("bec-exposure", `/api/workspaces/wsB/domains/${SHARED}/bec-exposure`, [
    ["derives from B's own report only", () =>
      JSON.stringify([...new Set(r2Gets)].filter((k) => k.startsWith("reports/"))) === '["reports/scan_b_old.json"]'],
    ["does not report A's 'none' policy", (d, b) => !/"dmarc_policy":"none"/.test(b)],
  ]);

  // ── 5. Related changes assessment context ─────────────────────────────────
  await probe("related-changes", "/api/workspaces/wsB/related-changes", [
    ["complete_scans counts B's own scans only", (d) => d.assessment.complete_scans === 2],
    ["latest_scan_quality is B's own ('complete', not A's 'partial')", (d) => d.assessment.latest_scan_quality === "complete"],
  ]);

  // ── 6. Portfolio (bob's accessible set is exactly [wsB]) ──────────────────
  await probe("portfolio-overview", "/api/portfolio/overview", [
    ["critical_findings is B's own latest-per-domain count", (d) => d.critical_findings === B_CRIT],
    ["high_findings is B's own", (d) => d.high_findings === B_HIGH],
    ["average_score is B's own latest complete average (Phase-5 verified)", (d) => d.average_score === B_AVG
      && d.score_evidence_coverage.reads_verified === 2],
    ["highest-risk workspace is wsB with B's own count", (d) => d.highest_risk_workspace?.id === "wsB"
      && d.highest_risk_workspace.critical_findings === B_CRIT],
  ]);
  const custRow = (d) => d.workspaces.find((x) => x.workspace_id === "wsB");
  await probe("portfolio-workspaces", "/api/portfolio/workspaces", [
    ["lists exactly one row (wsB)", (d) => d.workspaces.length === 1 && custRow(d)],
    ["wsB row critical count is B's own", (d) => custRow(d).critical_findings === B_CRIT],
    ["wsB row high count is B's own", (d) => custRow(d).high_findings === B_HIGH],
    ["wsB row latest_score is B's own (Phase-5 verified)", (d) => custRow(d).latest_score === B_AVG
      && custRow(d).score_evidence_coverage.reads_verified === 2],
    ["wsB row last_scan_at is B's own latest complete scan", (d) => custRow(d).last_scan_at === SCANS.scan_b_tie.created_at],
  ]);
  await probe("portfolio-executive-summary", "/api/portfolio/executive-summary", [
    ["portfolio avg_score is B's own", (d) => d.portfolio.avg_score === B_AVG],
    ["top attention row carries B's own counts", (d) => d.top_attention[0].workspace_id === "wsB"
      && d.top_attention[0].critical_findings === B_CRIT && d.top_attention[0].high_findings === B_HIGH],
  ]);
  await probe("portfolio-trends", "/api/portfolio/trends", [
    ["trend days are exactly B's own scan days", (d) => {
      const scanDays = d.trend.filter((x) => Number(x.scans || 0) > 0).map((x) => x.date).sort();
      return JSON.stringify(scanDays) === JSON.stringify([SCANS.scan_b_tie.created_at.slice(0, 10), SCANS.scan_b_old.created_at.slice(0, 10)].sort());
    }],
    ["trend critical/high totals are B's own", (d) =>
      d.trend.reduce((n, x) => n + x.critical_findings, 0) === B_CRIT
      && d.trend.reduce((n, x) => n + x.high_findings, 0) === B_HIGH],
    ["trend scores are B's own", (d) => d.trend.filter((x) => x.average_score != null)
      .every((x) => [SCANS.scan_b_old.score, SCANS.scan_b_tie.score].includes(x.average_score))],
  ]);
  const domRow = (d, id) => d.domains.find((x) => x.workspace_id === "wsB" && x.domain_id === id);
  await probe("portfolio-domains", "/api/portfolio/domains", [
    ["lists exactly B's two domain rows", (d) => d.domains.length === 2 && d.domains.every((x) => x.workspace_id === "wsB")],
    ["shared domain row carries B's own older score", (d) => domRow(d, "dom1").overall_score === SCANS.scan_b_old.score],
    ["tie domain row carries B's own score (equal timestamp resolves to owner)", (d) => domRow(d, "dom2").overall_score === SCANS.scan_b_tie.score],
  ]);
  await probe("portfolio-domain-detail", "/api/portfolio/domains/wsB/dom1", [
    ["shared domain detail carries B's own older score", (d) => d.workspace_id === "wsB" && d.overall_score === SCANS.scan_b_old.score],
  ]);
  section = "portfolio-domain-detail";
  {
    const r = await call("/api/portfolio/domains/wsA/dom1", T.bob);
    ok("bob is refused A's portfolio domain detail (404, no existence oracle)", r.status === 404, `status ${r.status}`);
  }

  // ── 7. POSITIVE CONTROL — A's owner sees A's data (foreign data is real) ──
  section = "owner-positive-control";
  const aDash = await call("/api/workspaces/wsA/executive-dashboard", T.alice);
  ok("alice reaches A's executive dashboard", aDash.status === 200, `status ${aDash.status}`);
  ok("alice sees A's own remediation", aDash.body.includes("REMEDIATION-A-FOREIGN"));
  ok("alice does not see B's remediation", !aDash.body.includes("REMEDIATION-B-"));
  ok("alice does not see the NULL-owner remediation", !aDash.body.includes("REMEDIATION-NULL"));

  console.log(results.join("\n"));
  console.log(`\nAggregate scan-ownership isolation: ${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}
main().catch((e) => { console.error(e); process.exit(1); });
