#!/usr/bin/env node
//
// Website Security — findings from the site's own sign-in pages (PR14b).
// Page-discovery observations become canonical findings ONLY for pages with an
// observed password field; they flow through the Website Security lifecycle
// (record → case → alert) and are never "fixed" unless the sign-in pages were
// actually re-observed on a page check that was not cut short.
//
// Drives the REAL emitter, registry, lifecycle, case layer and alert pipeline
// against the REAL schema. Node 24+.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href;
const S = await import(eng("signin-page-findings.js"));
const { resolveRemediation } = await import(eng("remediation-registry.js"));
const L = await import(eng("website-security-lifecycle.js"));
const { buildScanQuality } = await import(eng("scan-engine.js"));
const { CYBER_MOT_DOMAINS } = await import(eng("cyber-mot-domains.js"));
const { WEBSITE_CASE_RECURRENCES } = await import(eng("website-security-cases.js"));
const { severityForRecurrence, INHERIT_SEVERITY } = await import(eng("alert-consumers.js"));
const { isAsmManagedFinding } = await import(eng("asm-cases.js"));
const model = await import(eng("managed-case-model.js"));

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

// ── Fixtures: page_discovery module results ─────────────────────────────────
const home = (hsts = true) => ({ path: "/", source: "homepage", outcome: "observed", https: true, password_field: false,
  security_headers: { present: hsts ? ["strict-transport-security"] : [], missing: hsts ? [] : ["strict-transport-security"] }, cookies: [], forms: [] });
const login = (over = {}) => ({ path: "/login", source: "homepage_link", outcome: "observed", https: true, password_field: true, sensitive_kind: "login", sensitive_basis: "password_field",
  requested_url: "https://acme.test/login", final_url: "https://acme.test/login",
  security_headers: { present: ["strict-transport-security"], missing: [] },
  cookies: [{ name: "sid", secure: true, httponly: true, samesite: "lax" }],
  forms: [{ method: "post", action_kind: "same_origin", action_scheme: "https", action_host: null, has_password: true }], ...over });
const disc = (pages, { coverage = "complete", partial = [] } = {}) => ({ source: "page_discovery", version: "t", coverage, partial_reasons: partial, pages });
const CROSS = { forms: [{ method: "post", action_kind: "other_origin", action_scheme: "https", action_host: "collector.example", has_password: true }] };
const HTTPFORM = { forms: [{ method: "post", action_kind: "same_origin", action_scheme: "http", action_host: null, has_password: true }] };
const NOHSTS = { security_headers: { present: [], missing: ["strict-transport-security"] } };
const BADCOOKIE = { cookies: [{ name: "sid", secure: false, httponly: true, samesite: null }, { name: "pref", secure: true }] };

// ── 1. Emitter ──────────────────────────────────────────────────────────────
{
  const all = S.signInPageFindings(disc([home(), login({ ...CROSS, ...NOHSTS, ...BADCOOKIE }), login({ path: "/admin/login", ...HTTPFORM })]), { domain: "acme.test", checkedAt: "2026-10-11T00:00:00Z" });
  eq("emitter: one finding per condition", all.map((f) => f.id).sort(), [...S.SIGNIN_CONDITION_KEYS].sort());
  const by = Object.fromEntries(all.map((f) => [f.id, f]));
  eq("emitter: severities", S.SIGNIN_CONDITION_KEYS.map((k) => by[k].severity), ["medium", "high", "medium", "medium"]);
  ok("emitter: explicit finding_type (score_impact 0 would make it an observation)", all.every((f) => f.finding_type === "finding" && f.score_impact === 0 && f.module === "page_discovery"));
  eq("emitter: cross-origin names the receiving host, not a verdict", by.https_signin_form_cross_origin.evidence.observed_value.hosts, ["collector.example"]);
  ok("emitter: wording states what was observed — no phishing/theft claim", all.every((f) => !/phish|steal|theft|attack|malicious|compromis/i.test(`${f.title} ${f.description}`)));
  eq("emitter: cookie names only", by.https_signin_cookie_no_secure.evidence.observed_value.cookie_names, ["sid"]);
  ok("emitter: evidence carries paths, hosts and names only", !/<form|SECRETVALUE/.test(JSON.stringify(all)));
  eq("emitter: page with a sign-in ADDRESS but no password field never counts",
    S.signInPageFindings(disc([home(), login({ password_field: false, sensitive_basis: "path", ...CROSS })])), []);
  eq("emitter: no HSTS finding when the homepage lacks HSTS too (site-wide condition says it)",
    S.signInPageFindings(disc([home(false), login(NOHSTS)])).map((f) => f.id), []);
  eq("emitter: page check not run → nothing", S.signInPageFindings(disc([], { coverage: "not_run" })), []);
  eq("emitter: page served over http counts as insecure", S.signInPageFindings(disc([home(), login({ https: false })])).map((f) => f.id), ["https_signin_form_insecure"]);
  ok("emitter ids are Website Security by the canonical domain regex", all.every((f) => CYBER_MOT_DOMAINS.find((d) => d.domain_key === "website_security").match(f)));
  ok("emitter ids never open an ASM case", all.every((f) => !isAsmManagedFinding(f)));
}

// ── 2. Present / clear / deferred ───────────────────────────────────────────
{
  const st = (key, d) => S.evaluateSignInCondition(key, d).state;
  eq("present on any sign-in page", st("https_signin_form_cross_origin", disc([home(), login(CROSS)])), "present");
  eq("clear only with observed sign-in pages on a full check", st("https_signin_form_cross_origin", disc([home(), login()])), "clear");
  eq("no sign-in page observed → deferred, never fixed", st("https_signin_form_cross_origin", disc([home()])), "deferred");
  eq("not run → deferred", st("https_signin_form_cross_origin", disc([], { coverage: "not_run" })), "deferred");
  eq("time-cut check → deferred", st("https_signin_form_cross_origin", disc([home(), login()], { coverage: "partial", partial: ["time_budget"] })), "deferred");
  eq("page-limit partial does not hide sign-in pages → clear", st("https_signin_form_cross_origin", disc([home(), login()], { coverage: "partial", partial: ["page_limit"] })), "clear");
  eq("HSTS: homepage stopped sending HSTS → deferred (site-wide condition owns it)", st("https_signin_no_hsts", disc([home(false), login()])), "deferred");
  eq("cookie: zero cookies proves nothing → deferred", st("https_signin_cookie_no_secure", disc([home(), login({ cookies: [] })])), "deferred");
  eq("cookie: secure cookies observed → clear", st("https_signin_cookie_no_secure", disc([home(), login()])), "clear");
}

// ── 3. Registry, cases, alerts ──────────────────────────────────────────────
for (const key of S.SIGNIN_CONDITION_KEYS) {
  const r = resolveRemediation({ finding_type: key });
  eq(`${key}: resolves to one canonical remediation`, r.status, "resolved");
  eq(`${key}: externally re-observable (https_recheck)`, r.verification_method, "https_recheck");
  const spec = L.websiteConditionSpec(key);
  ok(`${key}: lifecycle spec on page_discovery`, spec?.module === "page_discovery");
  ok(`${key}: recurrence opens a case`, WEBSITE_CASE_RECURRENCES.has(spec?.recurrence));
  eq(`${key}: recurrence is graded`, severityForRecurrence("website_security", spec?.recurrence), INHERIT_SEVERITY);
}
eq("form conditions own their remediations", ["https_signin_form_cross_origin", "https_signin_form_insecure", "https_signin_no_hsts", "https_signin_cookie_no_secure"].map((k) => resolveRemediation({ finding_type: k }).remediation_id),
  ["web.signin.form_offsite", "web.signin.form_http", "web.header.hsts", "web.signin.cookie_secure"]);

// ── 4. Lifecycle on the real schema ─────────────────────────────────────────
function buildDb() {
  const db = new DatabaseSync(":memory:");
  // schema.sql already contains most migrations: only that overlap is tolerated.
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch (e) { if (!/^(?:duplicate column name|no such table|table \S+ already exists|index \S+ already exists)/.test(e.message)) throw e; } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((n) => n.endsWith(".sql")).sort()) apply(path.join(root, "database", "migrations", f));
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}
function makeD1(db) {
  const wrap = (sql, args) => ({
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
  });
  return {
    prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; },
    async batch(list) { const out = []; for (const x of list) out.push(await x.run()); return out; },
  };
}
{
  const db = buildDb();
  const prevFetch = globalThis.fetch;
  globalThis.fetch = async (url) => (String(url).includes("resend.com")
    ? new Response(JSON.stringify({ id: "email_1" }), { status: 200, headers: { "content-type": "application/json" } })
    : new Response("{}", { status: 200 }));
  db.prepare("INSERT INTO users (id, email, name, plan, created_at) VALUES ('u1','o@example.com','o','professional',datetime('now'))").run();
  db.prepare("UPDATE users SET email_verified = 1 WHERE id = 'u1'").run();
  db.prepare(`INSERT INTO subscriptions (id, owner_user_id, plan, subscription_status, status, current_period_end, created_at, updated_at)
              VALUES ('s1','u1','professional','active','active',datetime('now','+30 days'),datetime('now'),datetime('now'))`).run();
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('ws1','u1','Acme')").run();
  db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES ('m1','ws1','u1','owner')").run();
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('d1','u1','acme.test')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id, verification_status) VALUES ('ws1','d1','verified')").run();
  db.prepare(`INSERT OR IGNORE INTO alert_activation (id, workspace_id, domain_key, activated_at, baseline_count, created_at)
              VALUES ('act_ws1','ws1','website_security','2020-01-01 00:00:00',0,datetime('now'))`).run();
  const env = { cybermeters_db: makeD1(db), ALERT_EMAIL_FROM: "alerts@cybermeters.com", RESEND_API_KEY: "re_test", FRONTEND_URL: "https://app.cybermeters.com" };
  const MODULES = { dns: { resolves: true }, ssl: { https_available: true, https_probe_executed: true }, headers: { accessible: true, headers_assessed: true }, email_security: {} };
  const run = (scan, discovery, { quality = buildScanQuality(MODULES) } = {}) => {
    const modules = { ...MODULES, page_discovery: discovery };
    const findings = S.signInPageFindings(discovery, { domain: "acme.test" });
    return L.evaluateWebsiteSecurityForScan(env, { workspace_id: "ws1", domain_id: "d1", domain: "acme.test", scan_id: scan, findings, modules, scanQuality: quality });
  };
  const cond = (key) => db.prepare("SELECT * FROM website_security_conditions WHERE workspace_id='ws1' AND condition_key=?").get(key);
  const cases = () => db.prepare("SELECT * FROM managed_cases WHERE workspace_id='ws1' AND case_type='website_case'").all();
  const notifs = () => db.prepare("SELECT * FROM notification_events WHERE workspace_id='ws1'").all();
  try {
    await run("scan_0", disc([home(), login()]));                                  // clean baseline pass
    const r1 = await run("scan_1", disc([home(), login(CROSS)]));
    eq("new sign-in condition is observed", cond("https_signin_form_cross_origin")?.monitoring_status, "observed");
    eq("…opens exactly one Website case", cases().filter((c) => c.finding_id === cond("https_signin_form_cross_origin").id).length, 1);
    ok("…and alerts once", r1.alerts === 1 && notifs().length >= 1, JSON.stringify(r1));
    // The customer walks the case to awaiting_verification (the real path).
    let kase = cases().find((c) => c.finding_id === cond("https_signin_form_cross_origin").id);
    for (const target of ["triaged", "assigned", "approved", "action_in_progress", "awaiting_verification"]) {
      const d = model.canTransitionCase({ case: kase, target_status: target, actor: { actor_type: "customer", actor_id: "u1" }, owner_ref: "u1" });
      if (!d.ok) break;
      db.prepare("UPDATE managed_cases SET status=? WHERE id=?").run(d.case.status, kase.id);
      kase = cases().find((c) => c.id === kase.id);
    }
    const before = kase;
    await run("scan_2", disc([home()]));                                            // sign-in page not found this time
    eq("sign-in page not observed → unknown, never fixed", [cond("https_signin_form_cross_origin").monitoring_status, cond("https_signin_form_cross_origin").unknown_reason], ["unknown", "no_sign_in_page_observed"]);
    await run("scan_3", disc([], { coverage: "not_run" }));
    eq("page check not run → still unknown", cond("https_signin_form_cross_origin").monitoring_status, "unknown");
    await run("scan_4", disc([home(), login()], { coverage: "partial", partial: ["fetch_timeout"] }));
    eq("cut-short page check → still unknown", cond("https_signin_form_cross_origin").monitoring_status, "unknown");
    eq("no inconclusive pass verified the case", cases().find((c) => c.id === before.id)?.status, "awaiting_verification");
    await run("scan_5", disc([home(), login()]));
    eq("sign-in page re-observed clean on a full check → no longer observed", cond("https_signin_form_cross_origin").monitoring_status, "no_longer_observed");
    eq("…with the honest reason", cond("https_signin_form_cross_origin").monitoring_reason, "sign_in_pages_observed_and_clear");
    const after = before ? cases().find((c) => c.id === before.id) : null;
    eq("CyberMeters' own re-observation of the sign-in page verified the case", [before?.status, after?.status], ["awaiting_verification", "verified"]);
    const r6 = await run("scan_6", disc([home(), login(CROSS)]));
    ok("reappearance alerts again", r6.alerts === 1, JSON.stringify(r6));
  } finally {
    globalThis.fetch = prevFetch;
  }
}

// ── 5. Engine wiring ────────────────────────────────────────────────────────
{
  const engine = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "scan-engine.js"), "utf8");
  const at = engine.indexOf("signInPageFindings(modules.page_discovery");
  ok("engine: findings pushed after the page check", at > engine.indexOf('modules.page_discovery = pageRun.thrown'));
  ok("engine: findings pushed after computeScore (CMS unchanged)", at > engine.indexOf("computeScore("));
  const life = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "website-security-lifecycle.js"), "utf8");
  ok("lifecycle: absence is never inferred from the page_discovery module gate", /signInObservation\?\.state === "clear"/.test(life) && /else if \(signInObservation\)/.test(life));
}

console.log(`validate-website-signin-findings: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
