#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-email-deadline-evidence.js  (CI-blocking)
//
// Email Deadline → Whole-Scan Failure P1.
//
// THE HARM (reproduced end-to-end before the fix, base da8b1f3e). The primary
// email module's deadline fallback was `markDeadlineDeferred({ spf:{}, dmarc:{},
// dkim:{} })` — a shape that does not match the completed runEmailModule
// contract. When ONLY email_security exceeded its 750ms hard cap under the
// normal 19000ms budget:
//
//   • scoring read the ABSENT spf_evidence_status as "observed" and fabricated
//     the high "Missing SPF Record" finding (-10) from a probe that never ran,
//     plus a DKIM observation claiming selectors were probed;
//   • the remediation gate checked ONLY email_security_intelligence (and a
//     deadline-deferred intelligence result passed it too) — never the primary
//     module actually handed to the builder;
//   • buildEmailRemediationActions dereferenced the missing spf_detail
//     (`Cannot read properties of undefined (reading 'raw')`), the TypeError
//     escaped to the engine's outer catch, and the ENTIRE scan finalized
//     "failed" with findings:[] — every sibling module's completed evidence
//     was discarded.
//
// THE FIX. The fallback is the canonical unassessed email result owned by
// email-scan.js (tri-state nulls, null detail contract, not_yet_assessed A1
// evidence statuses); remediation generation is gated on the PRIMARY module's
// publishable evidence (isPublishableEmailEvidence) while the intelligence
// module proves its OWN completion; the builder itself refuses non-publishable
// evidence and never converts an unobserved probe into "SPF missing" /
// "DMARC missing" / "publish this record".
//
// Production carries eight failed scans. No causal attribution to this defect
// has been proven; they are recorded as UNATTRIBUTED and are not relabelled.
//
// Sections: A contract + refusal matrix · B real-engine traces (deferred email,
// positive no-SPF control, deferred intelligence) · L lifecycle/case
// non-progression · M pinned mutations (killed via fresh-process engine /
// customer-output traces, never a source regex).
// Real modules, real D1 (schema + migrations), real R2 shim, no network. Node 24+.
// ─────────────────────────────────────────────────────────────────────────────
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const selfPath = fileURLToPath(import.meta.url);
const root = path.join(path.dirname(selfPath), "..");
const engUrl = (f) => pathToFileURL(path.join(root, "workers/scan-api/src/engines", f)).href;
const { computeScore } = await import(engUrl("scoring.js"));
const { runScanEngine } = await import(engUrl("scan-engine.js"));
const { isPublishableModuleEvidence, markDeadlineDeferred, skippedModuleResult } = await import(engUrl("scan-budget.js"));
const { deadlineDeferredEmailModuleResult, runEmailModule, applyDmarcbisEmailCompatibilityProjection } = await import(engUrl("email-scan.js"));
const {
  buildDkimDetail, buildDmarcPolicyJourney, buildEmailRemediationActions,
  hasCanonicalEmailDetailContract, isPublishableEmailEvidence,
  parseBimiRecord, parseDmarcRecord, parseSpfRecord,
} = await import(engUrl("email-analysis.js"));
const { enrichSpf, enrichDkim } = await import(engUrl("email-intel.js"));
const { moduleCompletionGate } = await import(engUrl("asm-cases.js"));

const NOW = "2026-07-29T09:00:00.000Z";
const NOW_MS = Date.parse(NOW);
const EXPECTED_MUTANTS = 7;

const SPF_RECORD = "v=spf1 include:_spf.google.com -all";
const DMARC_REJECT = "v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com";
const DMARC_NONE = "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com";

// ── shared harness ───────────────────────────────────────────────────────────
function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (f) => { try { db.exec(fs.readFileSync(f, "utf8")); } catch { /* overlap */ } };
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

// One mock per trace variant. Every module's lookups answer normally; the
// variant delays ONLY what drives its specific deadline:
//   deferred-email — DKIM selector + BIMI probes hang past email's 750ms hard
//     cap, so email_security (and email_security alone) takes its fallback.
//   no-spf         — everything fast; the root TXT has NO SPF record and DMARC
//     is p=none: the genuine completed positive controls.
//   deferred-intel — email probes fast; the MTA-STS policy fetch hangs past the
//     1000ms phase-5 cap, so the intelligence trio defers while the primary
//     email module completes.
function mockFetch(variant) {
  const dmarcRecord = variant === "no-spf" ? DMARC_NONE : DMARC_REJECT;
  const includeSpf = variant !== "no-spf";
  return async (input) => {
    const url = new URL(String(input)); const host = url.hostname;
    if (variant === "deferred-intel" && host.startsWith("mta-sts.")) {
      return new Promise((res) => setTimeout(() => res(new Response("", { status: 404 })), 2_500));
    }
    if (host === "cloudflare-dns.com" || host === "dns.google") {
      const type = String(url.searchParams.get("type") || "A").toUpperCase();
      const name = String(url.searchParams.get("name") || "").toLowerCase();
      const answer = () => {
        if (name === "example.com" && type === "A") return json({ Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] });
        if (name === "example.com" && type === "MX") return json({ Status: 0, Answer: [{ type: 15, data: "10 mail.example.com." }] });
        if (name === "example.com" && type === "NS") return json({ Status: 0, Answer: [{ type: 2, data: "ns1.example.com." }] });
        if (name === "example.com" && type === "TXT") {
          return includeSpf ? json({ Status: 0, Answer: [{ type: 16, data: `"${SPF_RECORD}"` }] }) : json({ Status: 0, Answer: [] });
        }
        if (name === "_dmarc.example.com" && type === "TXT") return json({ Status: 0, Answer: [{ type: 16, data: `"${dmarcRecord}"` }] });
        return json({ Status: 0, Answer: [] });
      };
      if (variant === "deferred-email" && (name.includes("._domainkey.") || name.startsWith("default._bimi."))) {
        return new Promise((res) => setTimeout(() => res(answer()), 1_500));
      }
      return answer();
    }
    if (host === "crt.sh" || host === "api.certspotter.com") return json([]);
    return new Response("<html></html>", { status: 200, headers: { server: "nginx", "content-type": "text/html" } });
  };
}

function seedEmailCase(db) {
  db.prepare(`INSERT INTO managed_cases
      (id, workspace_id, case_type, domain_key, domain, finding_id, asset_ref, severity,
       status, evidence_json, recommended_actions_json, created_at, updated_at)
     VALUES ('mc-em','ws','email_case','email_protection','example.com','email_missing_spf','example.com','high',
       'awaiting_verification','{}','[]', datetime('now','-5 days'), datetime('now','-1 day'))`).run();
}

// The REAL production path: runScanEngine under the normal 19000ms budget with a
// frozen engine clock, so the ONLY thing that can end a module is its own hard
// cap on a real timer (raceModuleDeadline → onDeadline → fallback).
async function trace(variant, { seed = false } = {}) {
  const db = buildDb(); const store = new Map();
  const env = {
    cybermeters_db: makeD1(db), cybermeters_reports: makeR2(store),
    SCAN_CAPACITY_MODE: "legacy", SCAN_SUBREQUEST_LIMIT: "200",
    SCAN_DEADLINE_MS: "19000", APP_VERSION: "email-deadline-p1",
  };
  db.prepare("INSERT INTO users (id, email) VALUES ('usr','o@example.com')").run();
  db.prepare("INSERT INTO workspaces (id, name, deleted_at) VALUES ('ws','EMAIL-P1',NULL)").run();
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('dom','usr','example.com')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws','dom')").run();
  db.prepare(`INSERT INTO scans (id, workspace_id, domain_id, domain, status, scan_quality, created_at)
              VALUES ('scan-em','ws','dom','example.com','running',NULL,?)`).run(NOW);
  if (seed) seedEmailCase(db);

  const prevFetch = globalThis.fetch, prevLog = console.log, prevErr = console.error, prevWarn = console.warn;
  globalThis.fetch = mockFetch(variant);
  console.log = () => {}; console.error = () => {}; console.warn = () => {};
  let escaped = null;
  try {
    await runScanEngine("scan-em", "dom", "ws", "example.com", env,
      { now: () => NOW_MS, executionContext: "queue", trigger: "manual" });
  } catch (e) {
    escaped = `${e?.name}: ${e?.message}`;
  } finally {
    globalThis.fetch = prevFetch;
    console.log = prevLog; console.error = prevErr; console.warn = prevWarn;
  }

  const raw = store.get("reports/scan-em.json");
  const report = raw ? JSON.parse(raw) : null;
  const scanRow = db.prepare("SELECT status, scan_quality FROM scans WHERE id='scan-em'").get() || {};
  const email = report?.modules?.email_security ?? null;
  const intel = report?.modules?.email_security_intelligence ?? null;
  return {
    db, report, escaped,
    dbStatus: scanRow.status ?? null,
    quality: scanRow.scan_quality ?? null,
    reportQuality: report?.scan_quality?.status ?? null,
    reportError: report?.error ?? null,
    email, intel,
    emailActions: (email?.remediation_actions ?? []).map((a) => a.id),
    findingIds: (report?.findings || []).map((f) => f.id),
    titles: db.prepare("SELECT title FROM findings WHERE scan_id='scan-em'").all().map((r) => r.title),
    audits: db.prepare("SELECT event_type FROM audit_events").all().map((r) => r.event_type),
    motEmail: db.prepare("SELECT state, coverage, summary FROM cyber_mot_domain_states WHERE scan_id='scan-em' AND domain_key='email_protection'").get() || {},
    caseAfter: seed ? (db.prepare("SELECT status, verified_at FROM managed_cases WHERE id='mc-em'").get() || {}) : null,
  };
}

// Customer-output surface for the builder-level mutants: the action arrays
// buildEmailRemediationActions returns ARE modules.email_security.
// remediation_actions, served verbatim by the scan API.
function builderFlagsProbe() {
  const def = (o, k, v) => Object.defineProperty(o, k, { value: v, enumerable: false });
  const mk = ({ extras = {}, spfStatus = "observed", dkimStatus = "observed", dmarcStatus = "observed", dmarcRaw = null } = {}) => {
    const dmarcDetail = parseDmarcRecord(dmarcRaw, dmarcRaw ? 1 : 0);
    const d = {
      spf_detail: parseSpfRecord(null, 0),
      dmarc_detail: dmarcDetail,
      dkim_detail: buildDkimDetail({}),
      bimi_readiness: parseBimiRecord(null, dmarcDetail),
      policy_journey: buildDmarcPolicyJourney(dmarcDetail),
      ...extras,
    };
    def(d, "spf_evidence_status", spfStatus);
    def(d, "dkim_evidence_status", dkimStatus);
    def(d, "dmarc_evidence_status", dmarcStatus);
    return d;
  };
  const idsOf = (details) => {
    try { return { ids: buildEmailRemediationActions("example.com", details).map((a) => a.id), threw: null }; }
    catch (e) { return { ids: null, threw: `${e?.name}: ${e?.message}` }; }
  };
  // Deferred module shape as it exists AFTER the DMARCbis projection mutated it
  // (dmarc_detail is an object, spf_detail is still null) — the exact shape that
  // crashed the whole scan pre-fix.
  const projectedDeferred = applyDmarcbisEmailCompatibilityProjection(
    "example.com", deadlineDeferredEmailModuleResult(), null);
  return {
    fallback: idsOf(deadlineDeferredEmailModuleResult()),
    projectedDeferred: idsOf(projectedDeferred),
    executedFalse: idsOf(mk({ extras: { executed: false } })),
    incompleteTrue: idsOf(mk({ extras: { incomplete: true } })),
    deadlineOutcome: idsOf(mk({ extras: { outcome: "deadline_exceeded" } })),
    skipped: idsOf(mk({ extras: { skipped: true } })),
    errored: idsOf(mk({ extras: { error: "email module failed" } })),
    missingContract: idsOf({ spf_detail: parseSpfRecord(null, 0) }),
    unavailableSpf: idsOf(mk({ spfStatus: "unavailable" })),
    notYetAssessedSpf: idsOf(mk({ spfStatus: "not_yet_assessed" })),
    unavailableDmarc: idsOf(mk({ dmarcStatus: "unavailable" })),
    positiveMissing: idsOf(mk()),
    positiveMonitorOnly: idsOf(mk({ dmarcRaw: DMARC_NONE })),
    positiveMultiSpf: idsOf(mk({ extras: { spf_detail: parseSpfRecord(SPF_RECORD, 2) } })),
    positivePermissiveAll: idsOf(mk({ extras: { spf_detail: parseSpfRecord("v=spf1 +all", 1) } })),
  };
}

// ── child modes (fresh process → mutated-in-place files are actually loaded) ──
const childArg = process.argv.find((a) => a.startsWith("--child="));
if (childArg) {
  const mode = childArg.slice("--child=".length);
  let out;
  if (mode === "builder-flags") out = builderFlagsProbe();
  else {
    const t = await trace(mode);
    out = {
      escaped: t.escaped, dbStatus: t.dbStatus, quality: t.quality,
      reportQuality: t.reportQuality, reportError: t.reportError,
      titles: t.titles, findingIds: t.findingIds, emailActions: t.emailActions,
      emailExecuted: t.email?.executed ?? null, emailOutcome: t.email?.outcome ?? null,
      hasMtaStsDetail: !!(t.email && Object.prototype.hasOwnProperty.call(t.email, "mta_sts_detail")),
      motEmail: t.motEmail,
    };
  }
  process.stdout.write(JSON.stringify(out));
  process.exit(0);
}

let passed = 0, failed = 0, killed = 0;
const ok = (name, cond, detail = "") => {
  if (cond) passed += 1;
  else { failed += 1; console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
};

// ── A. CONTRACT + REFUSAL MATRIX ─────────────────────────────────────────────
console.log("── A. canonical fallback contract + non-publishable refusal matrix ──");
{
  // A completed run of the REAL producer (fast probes, core-owned DMARC), so
  // conformance is measured against the live contract, not a hand-written copy.
  const prevFetch = globalThis.fetch;
  globalThis.fetch = mockFetch("complete");
  const completed = await runEmailModule("example.com", { dmarcOwnedByCore: true });
  globalThis.fetch = prevFetch;
  const fb = deadlineDeferredEmailModuleResult();
  const missing = Object.keys(completed).filter((k) => !(k in fb));
  ok("A1: fallback carries EVERY enumerable key of the completed contract",
    missing.length === 0, `missing: ${missing.join(", ")}`);
  ok("A1: presence is the tri-state null — never false (not measured ≠ measured absent)",
    fb.spf.present === null && fb.dmarc.present === null && fb.dkim.present === null);
  ok("A1: the detail contract is explicitly null (non-publishable), not fabricated parses",
    fb.spf_detail === null && fb.dmarc_detail === null && fb.dkim_detail === null &&
    fb.bimi_readiness === null && fb.policy_journey === null);
  ok("A1: deferral is explicit — executed:false, incomplete:true, deadline outcome, stable reason",
    fb.executed === false && fb.incomplete === true &&
    fb.outcome === "deadline_exceeded" && fb.reason === "scan_deadline_exhausted");
  ok("A1: A1 evidence statuses are not_yet_assessed and NON-ENUMERABLE (API shape preserved)",
    fb.spf_evidence_status === "not_yet_assessed" && fb.dkim_evidence_status === "not_yet_assessed" &&
    !Object.keys(fb).includes("spf_evidence_status"));
  ok("A1: remediation_actions is an explicit empty list", Array.isArray(fb.remediation_actions) && fb.remediation_actions.length === 0);
  ok("A1: each call returns a FRESH object (no shared mutable fallback between scans)",
    deadlineDeferredEmailModuleResult() !== deadlineDeferredEmailModuleResult());
  const rt = JSON.parse(JSON.stringify(fb));
  ok("A1: JSON round-trip (R2 persistence) preserves the tri-state nulls and flags",
    rt.spf.present === null && rt.spf_detail === null && rt.executed === false && rt.incomplete === true);

  ok("A2: fallback is NOT publishable email evidence", !isPublishableEmailEvidence(fb));
  ok("A2: completed module IS publishable email evidence (positive control)",
    isPublishableEmailEvidence(completed) && hasCanonicalEmailDetailContract(completed));
  ok("A2: executed:false is non-publishable", !isPublishableModuleEvidence({ executed: false }));
  ok("A2: incomplete:true is non-publishable", !isPublishableModuleEvidence({ incomplete: true }));
  ok("A2: deadline outcome is non-publishable", !isPublishableModuleEvidence({ outcome: "deadline_exceeded" }));
  ok("A2: skippedModuleResult is non-publishable", !isPublishableModuleEvidence(skippedModuleResult("email_security")));
  ok("A2: errored module is non-publishable", !isPublishableModuleEvidence({ error: "x" }));
  ok("A2: missing detail contract is non-publishable even with no flags",
    !isPublishableEmailEvidence({ spf_detail: null, dmarc_detail: {}, dkim_detail: {}, bimi_readiness: {} }));

  // The old bare fallback (the removed shape) must ALSO be refused: legacy R2
  // reports carrying it can never rebuild into fabricated remediation.
  const legacyBare = markDeadlineDeferred({ spf: {}, dmarc: {}, dkim: {}, source: "email_security" });
  ok("A2: the REMOVED bare fallback shape is refused too", !isPublishableEmailEvidence(legacyBare));
}
{
  const flags = builderFlagsProbe();
  ok("A3: builder REFUSES the fallback without throwing → []",
    flags.fallback.threw === null && flags.fallback.ids.length === 0, JSON.stringify(flags.fallback));
  ok("A3: builder survives the post-projection deferred shape (the exact pre-fix crash input) → []",
    flags.projectedDeferred.threw === null && flags.projectedDeferred.ids.length === 0, JSON.stringify(flags.projectedDeferred));
  for (const [k, label] of [
    ["executedFalse", "executed:false"], ["incompleteTrue", "incomplete:true"],
    ["deadlineOutcome", "deadline outcome"], ["skipped", "skipped"], ["errored", "error"],
    ["missingContract", "missing detail contract"],
  ]) {
    ok(`A3: ${label} evidence creates NO actions`,
      flags[k].threw === null && flags[k].ids.length === 0, JSON.stringify(flags[k]));
  }
  ok("A4: an UNAVAILABLE SPF probe never becomes 'SPF missing' / 'publish this record'",
    !flags.unavailableSpf.ids.includes("spf_missing"), JSON.stringify(flags.unavailableSpf.ids));
  ok("A4: a not-yet-assessed SPF probe never becomes 'SPF missing'",
    !flags.notYetAssessedSpf.ids.includes("spf_missing"), JSON.stringify(flags.notYetAssessedSpf.ids));
  ok("A4: an UNAVAILABLE DMARC observation never becomes 'DMARC missing'",
    !flags.unavailableDmarc.ids.includes("dmarc_missing"), JSON.stringify(flags.unavailableDmarc.ids));
  ok("A5: POSITIVE — a completed OBSERVED assessment proving SPF absent still creates spf_missing",
    flags.positiveMissing.ids.includes("spf_missing"), JSON.stringify(flags.positiveMissing.ids));
  ok("A5: POSITIVE — a completed OBSERVED assessment proving DMARC absent still creates dmarc_missing",
    flags.positiveMissing.ids.includes("dmarc_missing"), JSON.stringify(flags.positiveMissing.ids));
  ok("A5: POSITIVE — a genuine p=none policy still creates dmarc_policy_monitoring_only",
    flags.positiveMonitorOnly.ids.includes("dmarc_policy_monitoring_only"), JSON.stringify(flags.positiveMonitorOnly.ids));
  ok("A5: POSITIVE — genuine multiple SPF records still create spf_multiple_records",
    flags.positiveMultiSpf.ids.includes("spf_multiple_records"), JSON.stringify(flags.positiveMultiSpf.ids));
  ok("A5: POSITIVE — a genuine +all policy still creates spf_permissive_all",
    flags.positivePermissiveAll.ids.includes("spf_permissive_all"), JSON.stringify(flags.positivePermissiveAll.ids));
}
{
  // Scoring + intelligence honesty gates read the conforming fallback as
  // unobserved — and their positive controls still fire on observed absence.
  const projected = applyDmarcbisEmailCompatibilityProjection("example.com", deadlineDeferredEmailModuleResult(), null);
  const { findings } = computeScore({ dns: { has_mx: true }, ssl: {}, headers: { headers: {} }, email_security: projected }, "example.com");
  ok("A6: scoring emits NO Missing SPF finding from the fallback",
    !findings.some((f) => f.id === "email_missing_spf"), findings.map((f) => f.id).join("|"));
  ok("A6: scoring emits NO fabricated DKIM observation from the fallback",
    !findings.some((f) => f.id === "email_dkim_not_detected"));
  const observedMissing = { spf: { present: false }, dmarc: { present: false }, dkim: { present: false, selectors_probed: ["default"] } };
  Object.defineProperty(observedMissing, "spf_evidence_status", { value: "observed", enumerable: false });
  Object.defineProperty(observedMissing, "dkim_evidence_status", { value: "observed", enumerable: false });
  const positive = computeScore({ dns: { has_mx: true }, ssl: {}, headers: { headers: {} }, email_security: observedMissing }, "example.com").findings;
  ok("A6: POSITIVE — observed SPF absence still scores email_missing_spf (-10)",
    positive.some((f) => f.id === "email_missing_spf" && Number(f.score_impact) === -10));
  ok("A6: POSITIVE — observed DKIM non-detection still emits the informational observation",
    positive.some((f) => f.id === "email_dkim_not_detected"));
  ok("A7: email-intel reads the fallback SPF as unobserved (finding + impact gated)",
    enrichSpf(deadlineDeferredEmailModuleResult()).observation_unavailable === true);
  ok("A7: email-intel reads the fallback DKIM as unobserved",
    enrichDkim(deadlineDeferredEmailModuleResult()).observation_unavailable === true);
}

// ── B. REAL runScanEngine — email exceeds its 750ms hard cap ─────────────────
console.log("\n── B. REAL runScanEngine, 19000ms budget, ONLY email past its hard cap ──");
const t1 = await trace("deferred-email");
ok("B: no exception escaped the engine", t1.escaped === null, String(t1.escaped));
ok("B: the scan reached a terminal COMPLETED state (not failed)",
  t1.dbStatus === "completed" && t1.report?.status === "completed",
  JSON.stringify({ db: t1.dbStatus, rep: t1.report?.status, err: t1.reportError }));
ok("B: scan_quality.status is partial (report + D1 agree)",
  t1.reportQuality === "partial" && t1.quality === "partial",
  JSON.stringify({ rep: t1.reportQuality, d1: t1.quality }));
ok("B: the email module took the DEADLINE fallback (hard-cap race)",
  t1.email?.executed === false && t1.email?.incomplete === true && t1.email?.outcome === "deadline_exceeded",
  JSON.stringify({ e: t1.email?.executed, i: t1.email?.incomplete, o: t1.email?.outcome }));
ok("B: persisted email evidence is explicitly unassessed (tri-state nulls, null details)",
  t1.email?.spf?.present === null && t1.email?.spf_detail === null && t1.email?.dkim_detail === null);
ok("B: NO fabricated missing-SPF/DMARC finding in the report",
  !t1.findingIds.some((id) => ["email_missing_spf", "email_missing_dmarc"].includes(id)),
  t1.findingIds.join("|"));
ok("B: NO fabricated DKIM observation in the report",
  !t1.findingIds.includes("email_dkim_not_detected"));
ok('B: NO "Missing SPF Record" persisted to D1', !t1.titles.includes("Missing SPF Record"), t1.titles.join(" | "));
ok("B: NO fabricated remediation actions on the deferred module",
  Array.isArray(t1.email?.remediation_actions) && t1.email.remediation_actions.length === 0,
  JSON.stringify(t1.emailActions));
ok("B: the completed intelligence module's OWN gates suppress its missing-SPF finding",
  !!t1.intel && !(t1.intel.findings || []).some((f) => f.id === "email_intel_spf_missing"),
  JSON.stringify((t1.intel?.findings || []).map((f) => f.id)));
ok("B: sibling-module findings REMAIN publishable (evidence not discarded)",
  t1.titles.length > 0, String(t1.titles.length));
ok("B: every persisted finding is non-email (nothing fabricated, nothing lost)",
  (t1.report?.findings || []).every((f) => f.module !== "email_security"),
  t1.findingIds.join("|"));
ok("B: the customer email domain is EVIDENCE-INSUFFICIENT — never healthy, never complete",
  t1.motEmail.state === "evidence_insufficient" && t1.motEmail.coverage !== "complete",
  JSON.stringify(t1.motEmail));
ok("B: no scan_failed audit — the scan did not fail", !t1.audits.includes("scan_failed"), t1.audits.join("|"));

// ── B2. POSITIVE engine control: completed scan, genuinely missing SPF ──────
console.log("\n── B2. positive control: fast probes, NO SPF record, DMARC p=none ──");
const t2 = await trace("no-spf");
ok("B2: control scan completed", t2.dbStatus === "completed", JSON.stringify({ db: t2.dbStatus, err: t2.reportError }));
ok("B2: the email module genuinely EXECUTED", t2.email?.executed !== false && t2.email?.outcome !== "deadline_exceeded");
ok("B2: observed SPF absence still produces the email_missing_spf finding",
  t2.findingIds.includes("email_missing_spf"), t2.findingIds.join("|"));
ok('B2: …and persists "Missing SPF Record" to D1', t2.titles.includes("Missing SPF Record"));
ok("B2: …and the spf_missing remediation action IS created",
  t2.emailActions.includes("spf_missing"), JSON.stringify(t2.emailActions));
ok("B2: the genuine p=none policy still surfaces monitoring-only remediation",
  t2.emailActions.includes("dmarc_policy_monitoring_only"), JSON.stringify(t2.emailActions));

// ── B3. Independent intelligence validation: intel deferred, email completed ──
console.log("\n── B3. intelligence deferred (phase-5 cap), primary email COMPLETED ──");
const t3 = await trace("deferred-intel");
ok("B3: scan completed terminally", t3.dbStatus === "completed", JSON.stringify({ db: t3.dbStatus, err: t3.reportError }));
ok("B3: the intelligence trio deferred", t3.intel?.outcome === "deadline_exceeded", JSON.stringify(t3.intel?.outcome));
ok("B3: deferred intel no longer fabricates transport detail for checks that never ran",
  !!t3.email && !Object.prototype.hasOwnProperty.call(t3.email, "mta_sts_detail"),
  JSON.stringify(Object.keys(t3.email || {})));
ok("B3: the COMPLETED primary module keeps its own genuine remediation evidence",
  t3.email?.executed !== false && Array.isArray(t3.email?.remediation_actions),
  JSON.stringify(t3.emailActions));

// ── L. LIFECYCLE / CASE NON-PROGRESSION ─────────────────────────────────────
console.log("\n── L. email case non-progression on the incomplete observation ──");
const lf = await trace("deferred-email", { seed: true });
console.log(`   BEFORE case=awaiting_verification    AFTER case=${lf.caseAfter.status} verified_at=${lf.caseAfter.verified_at}`);
ok("L: the email case did NOT advance to verification/resolution",
  !["verification_requested", "verifying", "resolved", "verified"].includes(lf.caseAfter.status), String(lf.caseAfter.status));
ok("L: the email case was NOT verified", lf.caseAfter.verified_at == null, String(lf.caseAfter.verified_at));
ok("L: it remains awaiting_verification", lf.caseAfter.status === "awaiting_verification", String(lf.caseAfter.status));
ok("L: the CANONICAL gate refuses email verification on a partial scan",
  moduleCompletionGate({ email_security: deadlineDeferredEmailModuleResult() },
    { status: "partial", modules_skipped: ["email_security"] }).canVerify("email_security") === false);
ok("L: the same gate ALLOWS it on a complete scan (positive control)",
  moduleCompletionGate({ email_security: {} }, { status: "complete", modules_skipped: [] }).canVerify("email_security") === true);

// ── M. MUTATIONS (anchor-guarded, pinned, killed in a FRESH process) ────────
// Each mutant is applied IN PLACE, exercised through a child process that
// imports the mutated module graph and runs the real engine trace or the
// customer-output builder surface, then restored. A mutant is killed only when
// the child's CUSTOMER-VISIBLE output regresses (fabricated finding/action,
// fabricated transport detail, suppressed positive control, or a failed scan).
console.log("\n── M. mutation proof ──");
const SCAN_ENGINE = path.join(root, "workers/scan-api/src/engines/scan-engine.js");
const SCAN_BUDGET = path.join(root, "workers/scan-api/src/engines/scan-budget.js");
const EMAIL_ANALYSIS = path.join(root, "workers/scan-api/src/engines/email-analysis.js");

function runChild(mode) {
  const out = execFileSync(process.execPath, [selfPath, `--child=${mode}`], {
    cwd: root, timeout: 180_000, maxBuffer: 32 * 1024 * 1024,
  });
  return JSON.parse(String(out));
}
async function withMutant(edits, run) {
  const originals = new Map();
  for (const { target, from, to } of edits) {
    const src = originals.get(target) ?? fs.readFileSync(target, "utf8");
    if (!originals.has(target)) originals.set(target, src);
    const current = fs.readFileSync(target, "utf8");
    const count = current.split(from).length - 1;
    if (count !== 1) return { applied: false, reason: `anchor x${count} in ${path.basename(target)}` };
    fs.writeFileSync(target, current.replace(from, to));
  }
  try { return { applied: true, result: await run() }; }
  finally { for (const [target, src] of originals) fs.writeFileSync(target, src); }
}

const MUTATIONS = [
  {
    name: "M1 the mismatched bare fallback schema is restored",
    edits: [{
      target: SCAN_ENGINE,
      from: "runCappedModule(\"email_security\",       { fallback: deadlineDeferredEmailModuleResult,",
      to:   "runCappedModule(\"email_security\",       { fallback: () => markDeadlineDeferred({ spf: {}, dmarc: {}, dkim: {}, source: \"email_security\" }),",
    }],
    // The bare shape has no evidence statuses → scoring again fabricates the
    // Missing SPF Record for a probe that never ran (customer D1 + report).
    check: () => {
      const r = runChild("deferred-email");
      return r.titles.includes("Missing SPF Record") || r.dbStatus === "failed";
    },
  },
  {
    name: "M2 the wrong-module-only completion guard is restored",
    edits: [{
      target: SCAN_ENGINE,
      from: "    const emailIntelUsable =\n      isPublishableModuleEvidence(modules.email_security_intelligence) && emailApplicability.applicable;",
      to:   "    const emailIntelUsable =\n      !modules.email_security_intelligence.error && !modules.email_security_intelligence.skipped && emailApplicability.applicable;",
    }],
    // A deadline-deferred intelligence result passes the old guard → the report
    // fabricates MTA-STS transport detail for a probe that never ran.
    check: () => runChild("deferred-intel").hasMtaStsDetail === true,
  },
  {
    name: "M3 executed:false is accepted as publishable evidence",
    edits: [{
      target: SCAN_BUDGET,
      from: "    && mod.executed !== false\n",
      to:   "",
    }],
    check: () => {
      const f = runChild("builder-flags").executedFalse;
      return Array.isArray(f.ids) && f.ids.includes("spf_missing");
    },
  },
  {
    name: "M4 incomplete:true is accepted as publishable evidence",
    edits: [{
      target: SCAN_BUDGET,
      from: "    && mod.incomplete !== true\n",
      to:   "",
    }],
    check: () => {
      const f = runChild("builder-flags").incompleteTrue;
      return Array.isArray(f.ids) && f.ids.includes("spf_missing");
    },
  },
  {
    name: "M5 the unsafe detail dereference is restored (builder refusal + engine primary gate removed)",
    edits: [
      {
        target: EMAIL_ANALYSIS,
        from: "  if (!isPublishableEmailEvidence(details)) return [];\n",
        to:   "",
      },
      {
        target: SCAN_ENGINE,
        from: "    if (emailIntelUsable && isPublishableEmailEvidence(modules.email_security)) {",
        to:   "    if (emailIntelUsable) {",
      },
    ],
    // The deferred module reaches the builder again; its null spf_detail is
    // dereferenced and the WHOLE scan fails — the original P1.
    check: () => {
      const r = runChild("deferred-email");
      return r.dbStatus === "failed" && /raw/.test(String(r.reportError || ""));
    },
  },
  {
    name: "M6 the genuine completed missing-SPF positive control is suppressed",
    edits: [{
      target: EMAIL_ANALYSIS,
      from: "  if (!spf.raw) {\n    if (!spfUnobserved) {",
      to:   "  if (!spf.raw) {\n    if (false) {",
    }],
    // A real completed scan proving SPF absent must still create spf_missing;
    // the mutant silently drops the legitimate action.
    check: () => {
      const r = runChild("no-spf");
      return !r.emailActions.includes("spf_missing");
    },
  },
  {
    name: "M7 an unobserved SPF probe is converted into 'SPF missing' again",
    edits: [{
      target: EMAIL_ANALYSIS,
      from: "  const spfUnobserved = isEmailProbeUnobserved(details.spf_evidence_status);",
      to:   "  const spfUnobserved = false;",
    }],
    check: () => {
      const f = runChild("builder-flags").unavailableSpf;
      return Array.isArray(f.ids) && f.ids.includes("spf_missing");
    },
  },
];

for (const m of MUTATIONS) {
  const { applied, reason, result } = await withMutant(m.edits, async () => m.check());
  if (!applied) { failed += 1; console.error(`FAIL ${m.name} — mutation anchor missing (${reason})`); continue; }
  if (result === true) { killed += 1; console.log(`KILLED ${m.name}`); }
  else { failed += 1; console.error(`FAIL ${m.name} — mutant SURVIVED (defect not reintroduced or not detected)`); }
}
ok(`M: all ${EXPECTED_MUTANTS} pinned mutants applied and killed`, killed === EXPECTED_MUTANTS, `${killed}/${EXPECTED_MUTANTS}`);

console.log(`\n${passed} passed, ${failed} failed, ${killed}/${EXPECTED_MUTANTS} mutants killed`);
process.exit(failed ? 1 : 0);
