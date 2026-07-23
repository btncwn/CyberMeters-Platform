#!/usr/bin/env node
//
// SPF-RUA corroboration (PR-B) — safety-critical suite. The RUA report's OWN SPF
// result is authoritative; local membership only decides whether an ALREADY-
// OBSERVED failure came from outside the resolved authorised set. Covers the five
// safety gates, the wording tiers (enforcing vs softfail/neutral vs
// comparison-unavailable), dedupe, external-scope honesty, and a wiring smoke test
// through the real emitManagedAlert path. CI-blocking. Requires Node 24+.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const C = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "spf-corroboration.js")).href);
const { evaluateSpfAuthorizationCorroboration, recordSpfRuaCorroboration, SPF_CORROBORATION_TIER, SPF_UNAUTHORISED_REMEDIATION_ID } = C;
const { canonicalizeCidr } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "spf-resolver.js")).href);

let pass = 0, fail = 0;
const results = [];
const ok = (name, cond) => { cond ? (pass++, results.push(`PASS ${name}`)) : (fail++, results.push(`FAIL ${name}`)); };
const NOW = "2026-07-21T00:00:00.000Z";

const complete = (cidrs) => ({ resolution_status: "complete", resolved_pass_authorisations: cidrs });
const AUTH = complete([canonicalizeCidr("192.0.2.0/24", "ip4"), canonicalizeCidr("2001:db8::/32", "ip6")]);
const evalC = (over) => evaluateSpfAuthorizationCorroboration({ domain: "acme.example", resolvedAuthorization: AUTH, spfPolicy: "strong", nowIso: NOW, ...over });

// ── The five safety gates ─────────────────────────────────────────────────────
// gate 2: only an OBSERVED hard SPF failure is acted on.
ok("pass result → no finding (only observed failure is acted on)",
   evalC({ sources: [{ source_ip: "203.0.113.9", spf_result: "pass", spf_domain: "acme.example" }] }).findings.length === 0);
ok("softfail result → no finding (not a hard failure)",
   evalC({ sources: [{ source_ip: "203.0.113.9", spf_result: "softfail", spf_domain: "acme.example" }] }).findings.length === 0);
// gate 1: no source_ip → no verdict.
ok("missing source_ip → no verdict",
   evalC({ sources: [{ source_ip: "", spf_result: "fail", spf_domain: "acme.example" }] }).findings.length === 0);
// gate 5: attribution must be unambiguous.
ok("fail attributed to a DIFFERENT domain → skipped (unambiguous attribution)",
   evalC({ sources: [{ source_ip: "203.0.113.9", spf_result: "fail", spf_domain: "other-tenant.example" }] }).findings.length === 0);
ok("fail attributed to a SUBDOMAIN of the monitored domain → evaluated",
   evalC({ sources: [{ source_ip: "203.0.113.9", spf_result: "fail", spf_domain: "mail.acme.example" }] }).findings.length === 1);

// ── The core positive: complete + fail + not-contained + -all → CONFIRMED ─────
{
  const r = evalC({ sources: [{ source_ip: "203.0.113.9", spf_result: "fail", spf_domain: "acme.example", message_count: 42 }] });
  ok("confirmed unauthorised (complete + fail + not-contained + -all)",
     r.findings.length === 1 && r.findings[0].tier === SPF_CORROBORATION_TIER.UNAUTHORISED_CONFIRMED);
  ok("confirmed finding carries the canonical remediation id", r.findings[0].remediation_id === SPF_UNAUTHORISED_REMEDIATION_ID);
  ok("confirmed finding dedupe_key is per (domain, source_ip)", r.findings[0].dedupe_key === "spf_unauthorised:acme.example:203.0.113.9");
  ok("comparison_performed is true for a complete resolution", r.comparison_performed === true);
  ok("firm wording references the -all policy and the observed failure", /not authorised|impersonation/i.test(r.findings[0].message) && /SPF failure/i.test(r.findings[0].message));
}

// ── Contained IP + fail → NO finding (alignment issue, not authorisation) ─────
ok("a fail from an IP INSIDE the authorised set is NOT an unauthorised-source finding",
   evalC({ sources: [{ source_ip: "192.0.2.50", spf_result: "fail", spf_domain: "acme.example" }] }).findings.length === 0);
ok("ip6 inside the authorised set is likewise not flagged",
   evalC({ sources: [{ source_ip: "2001:db8:dead::1", spf_result: "fail", spf_domain: "acme.example" }] }).findings.length === 0);

// ── ~all / ?all → cautious tier (softfail/neutral != hard reject) ─────────────
{
  const soft = evaluateSpfAuthorizationCorroboration({ domain: "acme.example", resolvedAuthorization: AUTH, spfPolicy: "soft", nowIso: NOW,
    sources: [{ source_ip: "203.0.113.9", spf_result: "fail", spf_domain: "acme.example" }] });
  ok("~all policy → cautious tier, not the firm confirmed tier",
     soft.findings[0].tier === SPF_CORROBORATION_TIER.UNAUTHORISED_SOFT_POLICY);
  ok("cautious wording says receivers MAY not reject", /may not reject/i.test(soft.findings[0].message));
  const neutral = evaluateSpfAuthorizationCorroboration({ domain: "acme.example", resolvedAuthorization: AUTH, spfPolicy: "neutral", nowIso: NOW,
    sources: [{ source_ip: "203.0.113.9", spf_result: "fail", spf_domain: "acme.example" }] });
  ok("?all policy → cautious tier", neutral.findings[0].tier === SPF_CORROBORATION_TIER.UNAUTHORISED_SOFT_POLICY);
}

// ── Resolution not complete → LIMITED wording, never a complete-comparison claim ─
for (const status of ["partial", "temperror", "permerror"]) {
  const auth = { resolution_status: status, resolved_pass_authorisations: status === "partial" ? [canonicalizeCidr("192.0.2.0/24", "ip4")] : null };
  const r = evaluateSpfAuthorizationCorroboration({ domain: "acme.example", resolvedAuthorization: auth, spfPolicy: "strong", nowIso: NOW,
    sources: [{ source_ip: "203.0.113.9", spf_result: "fail", spf_domain: "acme.example" }] });
  ok(`${status} resolution → FAIL_COMPARISON_UNAVAILABLE tier`, r.findings[0]?.tier === SPF_CORROBORATION_TIER.FAIL_COMPARISON_UNAVAILABLE);
  ok(`${status} resolution → never claims a complete comparison`, /unavailable/i.test(r.findings[0]?.message) && !/not authorised by/i.test(r.findings[0]?.message));
  ok(`${status} resolution → comparison_performed is false`, r.comparison_performed === false);
}

// A partial resolution where the IP IS contained still cannot make an authorisation
// claim (we did not have a complete set) → limited wording, not "contained".
{
  const auth = { resolution_status: "partial", resolved_pass_authorisations: [canonicalizeCidr("203.0.113.0/24", "ip4")] };
  const r = evaluateSpfAuthorizationCorroboration({ domain: "acme.example", resolvedAuthorization: auth, spfPolicy: "strong", nowIso: NOW,
    sources: [{ source_ip: "203.0.113.9", spf_result: "fail", spf_domain: "acme.example" }] });
  ok("partial + (would-be-contained) IP → still limited wording (no authorisation claim)",
     r.findings[0]?.tier === SPF_CORROBORATION_TIER.FAIL_COMPARISON_UNAVAILABLE);
}

// ── Dedupe: the same source IP appears once even across duplicate RUA rows ────
{
  const r = evalC({ sources: [
    { source_ip: "203.0.113.9", spf_result: "fail", spf_domain: "acme.example" },
    { source_ip: "203.0.113.9", spf_result: "fail", spf_domain: "acme.example" },
  ] });
  ok("duplicate RUA rows for one IP → a single finding", r.findings.length === 1);
}

// ── Wiring smoke test through the real emitManagedAlert path ──────────────────
function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* converge */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) apply(path.join(root, "database", "migrations", f));
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}
function makeD1(db) {
  const wrap = (sql, args) => ({
    __sql: sql,
    first: async () => db.prepare(sql).get(...args) ?? null,
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes, last_row_id: 0 } }; },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; }, async batch(s) { return Promise.all(s.map((x) => (/^\s*select/i.test(x.__sql) ? x.all() : x.run()))); } };
}
{
  const db = buildDb();
  const env = { cybermeters_db: makeD1(db), RESEND_API_KEY: "", cybermeters_reports: { get: async () => null } };
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('wsS','u','WS')").run();
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('dS','u','acme.example')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('wsS','dS')").run();
  db.prepare(`INSERT INTO dmarc_aggregate_reports
    (id, workspace_id, domain, external_report_id, source, created_at)
    VALUES ('rep1','wsS','acme.example','spf-authority-1','manual_paste',datetime('now'))`).run();
  const rec = (ip, res, i) => db.prepare(`INSERT INTO dmarc_aggregate_records (id, report_id, workspace_id, domain, source_ip, message_count, spf_result, spf_domain, created_at) VALUES (?, 'rep1','wsS','acme.example', ?, 5, ?, 'acme.example', datetime('now'))`).run(`rec${i}`, ip, res);
  rec("203.0.113.9", "fail", 1);   // outside the /24 authorised set → should alert
  rec("192.0.2.7", "fail", 2);     // inside the authorised set → must NOT alert
  rec("203.0.113.50", "pass", 3);  // pass → must NOT alert
  const modules = { email_security: { spf: AUTH, spf_detail: { policy_strength: "strong" } } };
  const REAL = new Date().toISOString();
  const out = await recordSpfRuaCorroboration("scanS", "dS", "acme.example", modules, env, { nowIso: REAL });
  ok("wiring: exactly one alert emitted (the outside-set fail source)", out.emitted === 1);
  const notif = db.prepare("SELECT type, dedupe_key, severity FROM notification_events WHERE workspace_id='wsS'").all();
  ok("wiring: a canonical notification_events row was written", notif.length === 1 && notif[0].type === "email_spf_unauthorised_source");
  ok("wiring: alert carries the per-source dedupe_key", notif[0].dedupe_key === "spf_unauthorised:acme.example:203.0.113.9");
  // Re-run: dedupe_key + activation watermark mean no second alert for the same source.
  const out2 = await recordSpfRuaCorroboration("scanS2", "dS", "acme.example", modules, env, { nowIso: new Date().toISOString() });
  ok("wiring: re-run does not emit a duplicate for the same source (dedupe holds)", db.prepare("SELECT COUNT(*) AS n FROM notification_events WHERE workspace_id='wsS'").get().n === 1);
}

// A temperror resolution at scan time → no firm alert; limited-wording only.
{
  const db = buildDb();
  const env = { cybermeters_db: makeD1(db), RESEND_API_KEY: "", cybermeters_reports: { get: async () => null } };
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('wsT','u','WS')").run();
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('dT','u','acme.example')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('wsT','dT')").run();
  db.prepare(`INSERT INTO dmarc_aggregate_reports
    (id, workspace_id, domain, external_report_id, source, created_at)
    VALUES ('rep','wsT','acme.example','spf-authority-2','signed_upload',datetime('now'))`).run();
  db.prepare(`INSERT INTO dmarc_aggregate_records (id, report_id, workspace_id, domain, source_ip, message_count, spf_result, spf_domain, created_at) VALUES ('t1','rep','wsT','acme.example','203.0.113.9',5,'fail','acme.example', datetime('now'))`).run();
  const modules = { email_security: { spf: { resolution_status: "temperror", resolved_pass_authorisations: null }, spf_detail: { policy_strength: "strong" } } };
  const out = await recordSpfRuaCorroboration("scanT", "dT", "acme.example", modules, env, { nowIso: new Date().toISOString() });
  const notif = db.prepare("SELECT title, message FROM notification_events WHERE workspace_id='wsT'").all();
  ok("temperror scan: emits the limited-wording tier only (no firm 'not authorised' claim)",
     out.emitted === 1 && notif.length === 1 && /unavailable/i.test(notif[0].message) && !/not authorised by/i.test(notif[0].message));
}

// ── report ───────────────────────────────────────────────────────────────────
console.log(`\nSPF-RUA corroboration: ${pass}/${pass + fail} passed`);
if (fail) { for (const r of results.filter((r) => r.startsWith("FAIL"))) console.log("  " + r); console.error("spf-corroboration validation FAILED"); process.exit(1); }
console.log("spf-corroboration validation passed");
