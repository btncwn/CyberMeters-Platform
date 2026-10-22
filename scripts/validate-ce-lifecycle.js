#!/usr/bin/env node
//
// Cyber Essentials external-evidence lifecycle — mutation-tested, CI-blocking.
//
// The eighth and last canonical alerting domain, and the one with the most ways to
// be dishonest. This suite proves the four rules of its ownership decision:
//
//   1. QUESTIONNAIRE ANSWERS CANNOT CREATE A SECURITY OCCURRENCE. The evaluator
//      calls buildCyberEssentialsReadiness DIRECTLY, never getCyberEssentialsSnapshot
//      — which is where answers gate display, and through which a customer flipping
//      one answer to "unknown" would mint an alert from a form edit.
//   2. NO EVIDENCE => UNKNOWN. Never a grade, in either direction.
//   3. A SCORE MOVING IS NOT AN EVENT. State comes from the SET of failing canonical
//      remediation ids, not the percentage.
//   4. UNSUPPORTED CONTROLS STAY SILENT. access_control, malware_protection and
//      patch_management_readiness declare external_coverage "none" in the repo's
//      authoritative metadata. Email-auth proxies do not measure user access control
//      or endpoint AV, and certificate/ASM proxies do not measure patching. None can alert.
//
// Every assertion drives the REAL evaluator against the REAL schema and the REAL
// readiness engine.
//
// Node 24+.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const srcPath = (...p) => path.join(root, "workers", "scan-api", "src", ...p);
const eng = (f) => pathToFileURL(srcPath("engines", f)).href;

const {
  evaluateCyberEssentialsLifecycle, gradeCeControl, ceControlIsExternallyAssessable,
  CE_DOMAIN_KEY, CE_RECURRENCE_NOT_READY, CE_RECURRENCE_WORSENED,
  CE_RECURRENCE_FINDING_TYPE, CE_NON_ALERTABLE_EVENT_TYPES,
  CE_EVENT_WORKSPACE_BASELINE, CE_EVENT_BASELINE, CE_EVENT_RECOVERED, CE_EVENT_UNKNOWN,
  CE_EVENT_IMPROVED,
} = await import(eng("ce-lifecycle.js"));
const { findConditionOccurrence, LIFECYCLE_EVENT_SOURCES, MONITORING_CHANGED } = await import(eng("alert-occurrence.js"));
const { severityForRecurrence } = await import(eng("alert-consumers.js"));
const { resolveRemediation } = await import(eng("remediation-registry.js"));
const { CE_QUESTIONS } = await import(pathToFileURL(srcPath("lib", "cyber-essentials.js")).href);

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* additive drift tolerated */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}
function makeD1(db) {
  const api = {
    prepare(sql) {
      const wrap = (args) => ({
        __sql: sql, __args: args,
        first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
        all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
        run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
      });
      const b = wrap([]); b.bind = (...a) => wrap(a); return b;
    },
    async batch(stmts) {
      return stmts.map((st) => ({ results: db.prepare(st.__sql).all(...(st.__args || [])), success: true, meta: {} }));
    },
  };
  return api;
}

const db = buildDb();
const realFetch = globalThis.fetch;
globalThis.fetch = async (url) => (String(url).includes("resend.com")
  ? new Response(JSON.stringify({ id: "email_1" }), { status: 200, headers: { "content-type": "application/json" } })
  : new Response("{}", { status: 200 }));

db.prepare("INSERT INTO users (id, email, name, plan, created_at) VALUES ('u1','o@example.com','o','professional',datetime('now'))").run();
db.prepare("UPDATE users SET email_verified = 1 WHERE id = 'u1'").run();
db.prepare(`INSERT INTO subscriptions (id, owner_user_id, plan, subscription_status, status, current_period_end, created_at, updated_at)
            VALUES ('s1','u1','professional','active','active',datetime('now','+30 days'),datetime('now'),datetime('now'))`).run();
for (const [w, n] of [["ws1", "Acme"], ["ws2", "Other"], ["wsDead", "Dead"]]) {
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES (?,'u1',?)").run(w, n);
  db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?,?, 'u1','owner')").run(`m_${w}`, w);
}
db.prepare("UPDATE workspaces SET deleted_at = datetime('now') WHERE id = 'wsDead'").run();
db.prepare("INSERT INTO domains (id, user_id, domain, created_at) VALUES ('d1','u1','acme.example.com',datetime('now'))").run();
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws1','d1')").run();

// The R2 report the workspace's own latest scan produced. Swapped per scenario.
let REPORT = null;
const env = {
  cybermeters_db: makeD1(db),
  cybermeters_reports: { get: async () => (REPORT ? { json: async () => REPORT } : null) },
  ALERT_EMAIL_FROM: "alerts@cybermeters.com",
  RESEND_API_KEY: "re_test",
};

function activate(ws, at) {
  db.prepare(`INSERT OR IGNORE INTO alert_activation (id, workspace_id, domain_key, activated_at, baseline_count, created_at)
              VALUES (?, ?, 'cyber_essentials_readiness', ?, 0, datetime('now'))`).run(`act_${ws}`, ws, at);
}
const setScan = (ws, id) => {
  db.prepare("DELETE FROM scans WHERE workspace_id = ?").run(ws);
  db.prepare(`INSERT INTO scans (id, domain_id, workspace_id, domain, score, rating, status, scan_quality, created_at)
              VALUES (?, 'd1', ?, 'acme.example.com', 70, 'fair', 'completed', 'complete', datetime('now'))`).run(id, ws);
};
const notifs = (ws) => db.prepare("SELECT * FROM notification_events WHERE workspace_id=?").all(ws);
const recs = (ws) => db.prepare("SELECT * FROM cyber_essentials_control_records WHERE workspace_id=?").all(ws);
const recFor = (ws, k) => db.prepare("SELECT * FROM cyber_essentials_control_records WHERE workspace_id=? AND control_key=?").get(ws, k);
const allEvents = (id) => db.prepare("SELECT * FROM cyber_essentials_events WHERE record_id=? ORDER BY created_at, rowid").all(id);
const occurrences = (id) => allEvents(id)
  .filter((e) => e.event_type === MONITORING_CHANGED)
  .filter((e) => { try { return JSON.parse(e.detail_json || "{}").to_recurrence_type != null; } catch { return false; } });

// Report shapes. HEALTHY: every externally observable control supported.
const HEALTHY = () => ({ modules: {
  headers: { accessible: true, headers_assessed: true, values: { "strict-transport-security": "max-age=63072000", "content-security-policy": "default-src 'self'" }, present: [], missing: [] },
  ssl: { https_available: true, https_probe_executed: true, http_redirects_to_https: true },
  email_security: { spf: { present: true }, dmarc: { present: true, policy: "reject" }, dkim: { present: true } },
} });
// HSTS + CSP absent, observed: secure_configuration becomes not ready.
const NO_HEADERS = () => ({ modules: {
  headers: { accessible: true, headers_assessed: true, values: {}, present: [], missing: ["strict-transport-security", "content-security-policy"] },
  ssl: { https_available: true, https_probe_executed: true, http_redirects_to_https: true },
  email_security: { spf: { present: true }, dmarc: { present: true, policy: "reject" }, dkim: { present: true } },
} });
// The headers probe never executed (post-#105 shape): evidence unknown, not a gap.
const HEADERS_DEAD = () => ({ modules: {
  headers: { accessible: false, incomplete: true, incomplete_reason: "probe_not_executed" },
  ssl: { https_available: true, https_probe_executed: true, http_redirects_to_https: true },
  email_security: { spf: { present: true }, dmarc: { present: true, policy: "reject" }, dkim: { present: true } },
} });

// HSTS fixed, CSP still absent: secure_configuration stays not ready with one gap fewer.
const CSP_ONLY = () => ({ modules: {
  headers: { accessible: true, headers_assessed: true, values: { "strict-transport-security": "max-age=63072000" }, present: [], missing: ["content-security-policy"] },
  ssl: { https_available: true, https_probe_executed: true, http_redirects_to_https: true },
  email_security: { spf: { present: true }, dmarc: { present: true, policy: "reject" }, dkim: { present: true } },
} });

const run = (ws, scanId = "scan_1") => evaluateCyberEssentialsLifecycle(env, ws, { scanId });

// healthy → both headers missing → HSTS fixed → HSTS lost again (a gap the CSP-only
// set does not hold), through `evaluate`.
// Returns what the customer was told at each step for secure_configuration.
async function improvementScenario(evaluate, ws) {
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES (?,'u1',?)").run(ws, ws);
  db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?,?, 'u1','owner')").run(`m_${ws}`, ws);
  activate(ws, "2026-06-01T00:00:00Z");
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES (?, 'd1')").run(ws);
  const sc = () => notifs(ws).filter((x) => /secure_configuration/.test(x.metadata_json || ""));
  setScan(ws, `${ws}_s1`); REPORT = HEALTHY();    await evaluate(env, ws, { scanId: `${ws}_s1` });
  setScan(ws, `${ws}_s2`); REPORT = NO_HEADERS(); await evaluate(env, ws, { scanId: `${ws}_s2` });
  const afterDeterioration = sc().length;
  setScan(ws, `${ws}_s3`); REPORT = CSP_ONLY();   const improvedRun = await evaluate(env, ws, { scanId: `${ws}_s3` });
  const afterImprovement = sc();
  setScan(ws, `${ws}_s4`); REPORT = NO_HEADERS(); await evaluate(env, ws, { scanId: `${ws}_s4` });
  return { afterDeterioration, afterImprovement, improvedRun, afterNewGap: sc(), record: recFor(ws, "secure_configuration") };
}

// ── 1. Registration ────────────────────────────────────────────────────────
{
  const src = LIFECYCLE_EVENT_SOURCES[CE_DOMAIN_KEY];
  ok("cyber_essentials_readiness is registered as an occurrence source", Boolean(src));
  eq("the source is the append-only events table",
     [src?.table, src?.fk, src?.type_column], ["cyber_essentials_events", "record_id", "event_type"]);
  const cols = db.prepare("PRAGMA table_info(cyber_essentials_events)").all().map((c) => c.name);
  for (const c of ["id", "record_id", "workspace_id", "event_type", "detail_json", "created_at"]) {
    ok(`cyber_essentials_events has the column the resolver reads: ${c}`, cols.includes(c));
  }
  for (const r of [CE_RECURRENCE_NOT_READY, CE_RECURRENCE_WORSENED]) {
    eq(`${r}: graded medium — a review item, not a second incident`, severityForRecurrence(CE_DOMAIN_KEY, r), "medium");
    const ft = CE_RECURRENCE_FINDING_TYPE[r];
    ok(`${r}: maps to a finding_type`, Boolean(ft));
    const rem = resolveRemediation({ finding_type: ft });
    ok(`${r}: resolves canonical remediation copy (never the "review required" fallback)`, rem?.status === "resolved");
    eq(`${r}: the remediation is CE's own`, rem?.domain_key, CE_DOMAIN_KEY);
    ok(`${r}: the copy states the certification limitation`,
       (rem?.limitations || []).some((l) => /does not certify/i.test(l)));
  }
  ok("recovery/baseline/unknown are not the alertable vocabulary",
     CE_NON_ALERTABLE_EVENT_TYPES.every((t) => t !== MONITORING_CHANGED));
}

// ── 2. RULE 4 — unsupported control themes can never alert ─────────────────
// This is the repo's own honesty metadata, not my opinion.
{
  const coverage = Object.fromEntries(CE_QUESTIONS.map((c) => [c.control_key, c.external_coverage]));
  eq("access_control declares NO external coverage", coverage.access_control, "none");
  eq("malware_protection declares NO external coverage", coverage.malware_protection, "none");
  eq("boundary_protection is externally observable (partial)", coverage.boundary_protection, "partial");
  eq("secure_configuration is externally observable (partial)", coverage.secure_configuration, "partial");
  // Reclassified in readiness methodology revision 2: it was scored from certificate expiry,
  // certificate risk and the ASM backlog, none of which measures automatic updates,
  // unsupported-software removal, a review process or 14-day patching.
  eq("patch_management_readiness declares NO external coverage", coverage.patch_management_readiness, "none");

  ok("access_control is refused as an alert source", !ceControlIsExternallyAssessable("access_control"));
  ok("malware_protection is refused as an alert source", !ceControlIsExternallyAssessable("malware_protection"));
  ok("boundary_protection is accepted", ceControlIsExternallyAssessable("boundary_protection"));

  // Even handed a category that LOOKS not-ready, the grader refuses to make it one.
  const g = gradeCeControl({ key: "access_control", label: "User Access Control", unknown: [], remediations: [{ remediation_id: "email.dmarc.enforce", customer_title: "x" }] });
  eq("a 'none'-coverage control is not_externally_assessable, whatever its proxies say", g.state, "not_externally_assessable");
  eq("...and carries no fingerprint to alert on", g.fingerprint, null);
  eq("...and names why", g.reason, "control_not_externally_observable");
}

// ── 3. RULE 2 — no evidence is UNKNOWN, never a grade ──────────────────────
{
  REPORT = null;                       // no scan at all
  db.prepare("DELETE FROM scans WHERE workspace_id='ws1'").run();
  const r = await run("ws1");
  eq("no external evidence => the lifecycle says nothing", r.skipped, "no_external_evidence");
  eq("...and creates no records", recs("ws1").length, 0);
  eq("...and alerts nobody", notifs("ws1").length, 0);
}

// ── 4. THE FLOOD GUARD — a pre-existing not-ready posture stays silent ─────
{
  setScan("ws1", "scan_seed");
  REPORT = NO_HEADERS();               // secure_configuration already not ready
  const r = await run("ws1", "scan_seed");
  eq("the seeding pass examined every control", r.evaluated, 5);
  eq("THE FLOOD GUARD: a pre-existing posture raises ZERO alerts", r.alerts, 0);
  eq("...and is marked as the seeding pass", r.seeding, true);
  eq("...and writes no notification", notifs("ws1").length, 0);
  eq("every control got a record", recs("ws1").length, 5);

  const sc = recFor("ws1", "secure_configuration");
  eq("a pre-existing not-ready control is marked baseline", sc.monitoring_status, "baseline");
  eq("...its externally evidenced state is recorded honestly", sc.readiness_state, "not_ready");
  eq("...with exactly one baseline event", allEvents(sc.id).length, 1);
  eq("...which is not an occurrence", allEvents(sc.id)[0].event_type, CE_EVENT_BASELINE);
  eq("...so it has NO occurrence", occurrences(sc.id).length, 0);

  const ac = recFor("ws1", "access_control");
  eq("an unassessable control is persisted as such", ac.readiness_state, "not_externally_assessable");
  eq("...and records why it can never alert", ac.external_coverage, "none");

  const marker = allEvents("ws1").filter((e) => e.event_type === CE_EVENT_WORKSPACE_BASELINE);
  eq("the workspace baseline marker was written exactly once", marker.length, 1);

  // Pass two, identical evidence: still silent (the PR-B3 pass-two trap).
  await run("ws1", "scan_seed2");
  eq("an unchanged re-evaluation stays silent", notifs("ws1").length, 0);
  eq("...and appends no occurrence", occurrences(sc.id).length, 0);
  eq("...and the record stays baseline", recFor("ws1", "secure_configuration").monitoring_status, "baseline");
}

// ── 5. RULE 1 — a questionnaire answer cannot create an occurrence ─────────
// The proof is structural AND behavioural: the engine never touches the table, and
// writing answers changes nothing.
{
  const src = fs.readFileSync(srcPath("engines", "ce-lifecycle.js"), "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
  ok("the evaluator never reads cyber_essentials_answers", !/cyber_essentials_answers/.test(src));
  ok("the evaluator never routes through the questionnaire display gate",
     !/getCyberEssentialsSnapshot/.test(src));
  ok("the evaluator calls the answer-free external verdict directly",
     /buildCyberEssentialsReadiness\(/.test(src));

  const before = notifs("ws1").length;
  const occBefore = occurrences(recFor("ws1", "secure_configuration").id).length;
  for (const q of ["q1", "q2", "q3", "q4"]) {
    db.prepare(`INSERT INTO cyber_essentials_answers (id, workspace_id, control_key, question_key, answer, answered_by, updated_at)
                VALUES (?, 'ws1', 'secure_configuration', ?, 'no', 'u1', datetime('now'))`).run(`ce_${q}`, q);
  }
  await run("ws1", "scan_after_answers");
  eq("answering the questionnaire 'no' creates no occurrence", occurrences(recFor("ws1", "secure_configuration").id).length, occBefore);
  eq("...and no alert", notifs("ws1").length, before);
  // And flipping one back to unknown — the exact snapshot-gate trap.
  db.prepare("UPDATE cyber_essentials_answers SET answer='unknown' WHERE workspace_id='ws1' AND question_key='q1'").run();
  await run("ws1", "scan_after_unknown");
  eq("flipping an answer to 'unknown' creates no occurrence", occurrences(recFor("ws1", "secure_configuration").id).length, occBefore);
  eq("...and no alert", notifs("ws1").length, before);
}

// ── 6. A genuine readiness deterioration alerts exactly once ───────────────
{
  // ws2: a clean baseline, then a real deterioration. Watermark pre-set because
  // emitManagedAlert gates on observed_at > activated_at with a strict `>` at second
  // precision; real assessments are scans apart.
  activate("ws2", "2026-06-01T00:00:00Z");
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws2','d1')").run();
  setScan("ws2", "w2_s1");
  REPORT = HEALTHY();
  const seed = await run("ws2", "w2_s1");
  eq("the clean seeding pass baselines every control", seed.seeding, true);
  eq("...and alerts nobody", notifs("ws2").length, 0);
  eq("a healthy externally observable control is recorded ready", recFor("ws2", "secure_configuration").readiness_state, "ready");

  // Now HSTS + CSP genuinely disappear, observed.
  setScan("ws2", "w2_s2");
  REPORT = NO_HEADERS();
  const r = await run("ws2", "w2_s2");
  const sc = recFor("ws2", "secure_configuration");
  eq("a real deterioration is recorded not_ready", sc.readiness_state, "not_ready");
  eq("...minting exactly ONE occurrence for THIS control", occurrences(sc.id).length, 1);
  // NO_HEADERS makes boundary_protection not-ready too (its `!hsts && !csp` gap), so
  // two control themes genuinely deteriorated and two alerts is correct. What must
  // never happen is two alerts for ONE theme — asserted above, per record.
  eq("...one alert per deteriorated theme, no more", notifs("ws2").length, r.alerts);
  ok("...and only externally assessable themes alerted",
     notifs("ws2").every((x) => /secure_configuration|boundary_protection/.test(x.metadata_json || "")),
     JSON.stringify(notifs("ws2").map((x) => x.type)));
  ok("...all three non-externally-assessable controls alerted NOBODY",
     !notifs("ws2").some((x) => /access_control|malware_protection|patch_management_readiness/.test(x.metadata_json || "")));

  const n = notifs("ws2").filter((x) => /secure_configuration/.test(x.metadata_json || "")).at(-1);
  eq("the alert is attributed to CE", n.domain_key, CE_DOMAIN_KEY);
  eq("the alert kind is namespaced", n.type, `cyber_essentials_readiness.${CE_RECURRENCE_NOT_READY}`);
  eq("...graded as a review item, not a second incident", n.severity, "medium");
  ok("...and carries CE's own remediation copy, not a fallback", !/review required/i.test(n.title), n.title);
  ok("...and never claims certification", !/certified|compliant|audit pass/i.test(`${n.title} ${n.message}`));

  // The notification's evidence must NAME what moved.
  const d = JSON.parse(occurrences(sc.id)[0].detail_json);
  eq("the occurrence names the control theme", d.control_key, "secure_configuration");
  ok("...and its human label", Boolean(d.control_label));
  ok("...names the exact external evidence", Array.isArray(d.external_evidence) && d.external_evidence.length > 0);
  eq("...names the previous externally evidenced state", d.previous_readiness_state, "ready");
  eq("...names the current one", d.current_readiness_state, "not_ready");
  eq("...names the assessment identity", d.assessment_scan_id, "w2_s2");
  ok("...and states the honest limitation", /does not certify/i.test(d.limitation || ""));

  // Parity: the resolver finds what the evaluator wrote.
  const occ = await findConditionOccurrence(env, {
    workspace_id: "ws2", domain_key: CE_DOMAIN_KEY, record_id: sc.id, recurrence_type: CE_RECURRENCE_NOT_READY,
  });
  ok("the resolver RESOLVES the evaluator's own transition", occ !== null);
  eq("occurrence id is the event id", occ?.occurrence_id, occurrences(sc.id)[0].id);

  // Unchanged: silent.
  const steady = notifs("ws2").length;
  setScan("ws2", "w2_s3");
  await run("ws2", "w2_s3");
  eq("an unchanged re-assessment appends no occurrence", occurrences(sc.id).length, 1);
  eq("...and sends nothing", notifs("ws2").length, steady);
}

// ── 6b. A gap clearing is an improvement — never "worsened" (P1, 21 Oct 2026) ──
// Live: HSTS was fixed on a control that still had another gap, and the customer was
// emailed "has worsened". Direction must come from the evidence sets.
{
  const s = await improvementScenario(evaluateCyberEssentialsLifecycle, "ws_imp");
  eq("the deterioration alerted once for secure_configuration", s.afterDeterioration, 1);
  eq("HSTS fixed while CSP is still missing sends NOTHING", s.afterImprovement.length, 1);
  ok("...never a 'worsened' alert", !s.afterImprovement.some((x) => x.type.endsWith(CE_RECURRENCE_WORSENED)),
     JSON.stringify(s.afterImprovement.map((x) => x.type)));
  eq("...the pass counts it as an improvement", s.improvedRun.improved >= 1, true);
  const ev = db.prepare("SELECT * FROM cyber_essentials_events WHERE record_id=? AND event_type=?").all(s.record.id, CE_EVENT_IMPROVED);
  eq("...recorded as history: one control_evidence_improved event", ev.length, 1);
  eq("...naming both evidence sets", [JSON.parse(ev[0].detail_json).from_evidence_fingerprint, JSON.parse(ev[0].detail_json).to_evidence_fingerprint],
     ["web.header.csp|web.header.hsts", "web.header.csp"]);
  ok("the improvement event can never alert", CE_NON_ALERTABLE_EVENT_TYPES.includes(CE_EVENT_IMPROVED));
  eq("a genuinely NEW gap afterwards still alerts", s.afterNewGap.length, 2);
  eq("...and that one IS 'worsened'", s.afterNewGap.at(-1).type, `cyber_essentials_readiness.${CE_RECURRENCE_WORSENED}`);
  eq("...the control is still not ready", s.record.readiness_state, "not_ready");
}

// ── 7. RULE 3 — a score moving is not an event ────────────────────────────
// Same failing evidence SET, different counts/score. The fingerprint is the refs, so
// nothing transitions.
{
  const before = notifs("ws2").length;
  const sc = recFor("ws2", "secure_configuration");
  const fp = sc.evidence_fingerprint;
  const occBefore = occurrences(sc.id).length;

  const g1 = gradeCeControl({ key: "boundary_protection", unknown: [], remediations: [{ remediation_id: "ce.backlog.remediate" }] });
  const g2 = gradeCeControl({ key: "boundary_protection", unknown: [], remediations: [{ remediation_id: "ce.backlog.remediate" }] });
  eq("the same failing evidence yields the same fingerprint regardless of counts", g1.fingerprint, g2.fingerprint);
  const g3 = gradeCeControl({ key: "boundary_protection", unknown: [], remediations: [{ remediation_id: "ce.backlog.remediate" }, { remediation_id: "web.header.hsts" }] });
  ok("a genuinely NEW gap changes the fingerprint", g3.fingerprint !== g1.fingerprint);
  ok("the fingerprint is order-independent (a set, not a list)",
     gradeCeControl({ key: "boundary_protection", unknown: [], remediations: [{ remediation_id: "web.header.hsts" }, { remediation_id: "ce.backlog.remediate" }] }).fingerprint === g3.fingerprint);

  setScan("ws2", "w2_s4");
  REPORT = NO_HEADERS();               // identical evidence set
  await run("ws2", "w2_s4");
  eq("re-assessing identical evidence appends no occurrence", occurrences(sc.id).length, occBefore);
  eq("...and alerts nobody", notifs("ws2").length, before);
  eq("...and the fingerprint is unchanged", recFor("ws2", "secure_configuration").evidence_fingerprint, fp);
}

// ── 8. Unknown is not a fix, and not a failure ────────────────────────────
{
  const before = notifs("ws2").length;
  const sc = recFor("ws2", "secure_configuration");
  setScan("ws2", "w2_s5");
  REPORT = HEADERS_DEAD();             // the probe never executed
  await run("ws2", "w2_s5");
  const after = recFor("ws2", "secure_configuration");
  eq("uncollected evidence is UNKNOWN, not ready and not not-ready", after.readiness_state, "unknown");
  eq("...recorded as control_evidence_unknown", allEvents(sc.id).at(-1).event_type, CE_EVENT_UNKNOWN);
  ok("...never as a recovery", !allEvents(sc.id).some((e) => e.event_type === CE_EVENT_RECOVERED));
  eq("...and alerts nobody", notifs("ws2").length, before);
  ok("...and names the signals it could not observe", Boolean(after.unknown_json) && after.unknown_json !== "[]");
}

// ── 9. Verified recovery, then re-entry ──────────────────────────────────
{
  const sc = recFor("ws2", "secure_configuration");
  setScan("ws2", "w2_s6");
  REPORT = HEALTHY();                  // genuinely fixed, observed
  await run("ws2", "w2_s6");
  eq("external evidence supporting readiness again is a recovery", recFor("ws2", "secure_configuration").readiness_state, "ready");
  eq("...persisted as history", allEvents(sc.id).at(-1).event_type, CE_EVENT_RECOVERED);
  const beforeNotif = notifs("ws2").length;

  db.prepare("DELETE FROM alert_deliveries WHERE workspace_id='ws2'").run();   // model the gap between scans
  setScan("ws2", "w2_s7");
  REPORT = NO_HEADERS();               // it comes back
  await run("ws2", "w2_s7");
  eq("re-entry after a recovery is not_ready again", recFor("ws2", "secure_configuration").readiness_state, "not_ready");
  ok("...and mints a NEW occurrence", occurrences(sc.id).length >= 2);
  ok("...and alerts again", notifs("ws2").length > beforeNotif);
}

// ── 10. Isolation, soft delete, and no sender in the engine ──────────────
{
  ok("ws1's records are ws1's only", recs("ws1").every((r) => r.workspace_id === "ws1"));
  ok("ws2's records are ws2's only", recs("ws2").every((r) => r.workspace_id === "ws2"));
  const mine = recFor("ws2", "secure_configuration");
  const cross = await findConditionOccurrence(env, {
    workspace_id: "ws1", domain_key: CE_DOMAIN_KEY, record_id: mine.id, recurrence_type: CE_RECURRENCE_NOT_READY,
  });
  eq("an occurrence never resolves across tenants", cross, null);

  const dead = await run("wsDead", "sd");
  eq("a soft-deleted workspace is nonexistent to the lifecycle", dead.skipped, "workspace_inactive");
  eq("...and gets no records", recs("wsDead").length, 0);

  const src = fs.readFileSync(srcPath("engines", "ce-lifecycle.js"), "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
  ok("alerts only through the canonical consumer", src.includes("emitLifecycleAlert("));
  ok("no hand-rolled notification write", !/createNotificationEvent\(/.test(src));
  ok("no direct outbound channel send", !/deliverWorkspaceAlert\(/.test(src));
  ok("no direct emit that bypasses the watermark", !/emitManagedAlert\(/.test(src));
  ok("builds the canonical transition detail", src.includes("buildMonitoringTransitionDetail("));
  ok("guards the append with isMonitoringTransition", src.includes("isMonitoringTransition("));
  ok("the transition carries to_recurrence_type", /to_recurrence_type/.test(src));
  ok("the score is never the trigger", !/\.score\b/.test(src));
}

// ── 11. MUTATION — would this suite catch the regressions? ───────────────
{
  const original = fs.readFileSync(srcPath("engines", "ce-lifecycle.js"), "utf8");

  // (a) Let unsupported controls alert.
  const openCoverage = original.replace(
    '  if (coverage !== "partial") {',
    '  if (false) {',
  );
  ok("MUTATION (a) applied — the coverage gate is where this suite thinks it is", openCoverage !== original);

  // (b) Route through the questionnaire display gate.
  const viaSnapshot = original.replace(
    "    const readiness = await buildCyberEssentialsReadiness(workspaceId, env).catch(() => null);",
    "    const readiness = await getCyberEssentialsSnapshot(workspaceId, env).catch(() => null);",
  );
  ok("MUTATION (b) applied — the direct call is where this suite thinks it is", viaSnapshot !== original);

  // (c) Direction from "the band moved" again (the live P1).
  const anyChange = original.replace(
    "      if (rec.readiness_state === \"not_ready\" && previousRefs.size > 0 && !gainedGap) {",
    "      if (false) {",
  ).replace(
    "      const worsened = rec.readiness_state === \"not_ready\" && previousRefs.size > 0 && gainedGap;",
    "      const worsened = rec.readiness_state === \"not_ready\" && rec.recurrence_band && band !== rec.recurrence_band;",
  );
  ok("MUTATION (c) applied — the direction check is where this suite thinks it is", anyChange !== original && !anyChange.includes("&& !gainedGap)"));
  // (d) The comparison inverted: a cleared gap is "gained", a new one is not.
  const inverted = original.replace(
    ".some((id) => !previousRefs.has(id));",
    ".every((id) => previousRefs.has(id));",
  );
  ok("MUTATION (d) applied — the set comparison is where this suite thinks it is", inverted !== original);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cm-ce-lc-"));
  try {
    for (const [tag, code, ws] of [["c", anyChange, "ws_mut_c"], ["d", inverted, "ws_mut_d"]]) {
      const tmpM = srcPath("engines", `.ce-lifecycle.mutant.${tag}.${path.basename(dir)}.js`);
      fs.writeFileSync(tmpM, code);
      const m = await import(pathToFileURL(tmpM).href);
      const s = await improvementScenario(m.evaluateCyberEssentialsLifecycle, ws);
      ok(`MUTANT (${tag}): a cleared gap now reaches the customer as 'worsened' — the live P1, reproduced`,
         s.afterImprovement.some((x) => x.type.endsWith(CE_RECURRENCE_WORSENED)), JSON.stringify(s.afterImprovement.map((x) => x.type)));
    }
    const tmp = srcPath("engines", `.ce-lifecycle.mutant.a.${path.basename(dir)}.js`);
    fs.writeFileSync(tmp, openCoverage);
    const mA = await import(pathToFileURL(tmp).href);
    const g = mA.gradeCeControl({ key: "access_control", label: "User Access Control", unknown: [], remediations: [{ remediation_id: "email.dmarc.enforce" }] });
    eq("MUTANT (a): without the coverage gate, access_control becomes an alertable not_ready — the unsupported proxy claim, reproduced",
       g.state, "not_ready");
    ok("MUTANT (a): ...and gains a fingerprint to alert on", Boolean(g.fingerprint));
  } finally {
    for (const f of fs.readdirSync(srcPath("engines")).filter((f) => f.startsWith(".ce-lifecycle.mutant."))) {
      fs.rmSync(srcPath("engines", f), { force: true });
    }
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// ── Verifier retry (22 Oct 2026, Executive 15:45 (3)) ───────────────────────
// sheshire.co.uk: Secure Configuration recovered while its case was 'detected';
// verifyCeCaseFromRecovery ran only on that transition, so a case marked ready
// later was never verified. While a control STAYS ready, the verifier is retried
// quietly on every evaluation.
{
  const model = await import(eng("managed-case-model.js"));
  const retryScenario = async (evaluate, ws) => {
    db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES (?,'u1',?)").run(ws, ws);
    db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?,?, 'u1','owner')").run(`m_${ws}`, ws);
    activate(ws, "2026-06-01T00:00:00Z");
    db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES (?, 'd1')").run(ws);
    setScan(ws, `${ws}_s1`); REPORT = HEALTHY();    await evaluate(env, ws, { scanId: `${ws}_s1` });
    setScan(ws, `${ws}_s2`); REPORT = NO_HEADERS(); await evaluate(env, ws, { scanId: `${ws}_s2` });
    setScan(ws, `${ws}_s3`); REPORT = HEALTHY();    await evaluate(env, ws, { scanId: `${ws}_s3` }); // recovered while 'detected'
    let k = db.prepare("SELECT * FROM managed_cases WHERE workspace_id=? ORDER BY created_at LIMIT 1").get(ws);
    if (!k) return { opened: false };
    const eventsBefore = db.prepare("SELECT COUNT(*) AS n FROM managed_case_events WHERE case_id=?").get(k.id).n;
    setScan(ws, `${ws}_s3b`); REPORT = HEALTHY();   await evaluate(env, ws, { scanId: `${ws}_s3b` }); // retry on 'detected'
    const quiet = db.prepare("SELECT COUNT(*) AS n FROM managed_case_events WHERE case_id=?").get(k.id).n === eventsBefore;
    for (const t of ["triaged", "assigned", "approved", "action_in_progress", "awaiting_verification"]) {
      const d = model.canTransitionCase({ case: k, target_status: t, actor: { actor_type: "customer", actor_id: "u1" }, owner_ref: "u1" });
      if (!d.ok) return { opened: true, drove: false, at: t };
      db.prepare("UPDATE managed_cases SET status=? WHERE id=?").run(d.case.status, k.id);
      k = db.prepare("SELECT * FROM managed_cases WHERE id=?").get(k.id);
    }
    setScan(ws, `${ws}_s4`); REPORT = HEALTHY();    await evaluate(env, ws, { scanId: `${ws}_s4` }); // still ready, no transition
    return { opened: true, drove: true, quiet, after: db.prepare("SELECT status FROM managed_cases WHERE id=?").get(k.id).status };
  };
  const real = await retryScenario(evaluateCyberEssentialsLifecycle, "ws_retry");
  ok("CE retry: the deterioration opened a case and the customer reached awaiting_verification", real.opened && real.drove, JSON.stringify(real));
  ok("CE retry: a 'detected' case collects no note from the per-pass retry", real.quiet === true);
  eq("CE retry: the next pass while still ready verifies the case", real.after, "verified");
  const original = fs.readFileSync(srcPath("engines", "ce-lifecycle.js"), "utf8");
  const anchor = '        if (g.state === "ready") {\n          await verifyCeCaseFromRecovery(env, {';
  ok("CE retry mutant anchor present once", original.split(anchor).length === 2);
  const tmp = srcPath("engines", `.ce-lifecycle.mutant.retry.${process.pid}.js`);
  try {
    fs.writeFileSync(tmp, original.replace(anchor, '        if (false) {\n          await verifyCeCaseFromRecovery(env, {'));
    const m = await import(pathToFileURL(tmp).href);
    const mutant = await retryScenario(m.evaluateCyberEssentialsLifecycle, "ws_retry_m");
    eq("CE retry MUTANT (single-shot) is caught: the case stays awaiting_verification", mutant.after, "awaiting_verification");
  } finally { fs.rmSync(tmp, { force: true }); }
}

globalThis.fetch = realFetch;
console.log(`\nce-lifecycle: ${pass} passed, ${fail} failed`);
if (fail > 0) { console.error("ce-lifecycle validation FAILED"); process.exit(1); }
console.log("ce-lifecycle validation passed");
