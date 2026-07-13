#!/usr/bin/env node
//
// Enforcement-readiness v2 runtime proof. Epic #6 of the Managed DMARC Policy
// Journey — unify the two divergent readiness engines behind one structured,
// explainable model: a 7-check evidence set → numeric score → tri-state status,
// surfaced alongside the legacy milestone keys (which must stay unchanged).
// Drives buildEnforcementReadinessChecks + buildDmarcEnforcementReadiness.
// Pure functions, no DB. Node 24+. CI-blocking.
//
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "rua-routing.js")).href);
const { buildEnforcementReadinessChecks, buildDmarcEnforcementReadiness, ENFORCEMENT_CHECK_WEIGHTS } = eng;

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };
const check = (r, id) => r.checks.find((c) => c.id === id);

// A fully-healthy, enforcement-ready domain.
const healthy = { days_with_data: 30, total_messages: 5000, pass_rate: 99,
  unknown_senders: 0, high_volume_failed_senders: 0, threat_senders: 0, suspicious_senders: 0, days_since_change: 10 };

// ── Structured model shape ────────────────────────────────────────────────────
const h = buildEnforcementReadinessChecks(healthy);
ok("exactly 7 checks are produced", h.checks.length === 7);
ok("weights sum to 100 (score is a clean percentage)", Object.values(ENFORCEMENT_CHECK_WEIGHTS).reduce((a, b) => a + b, 0) === 100);
ok("every check carries id/label/status/detail/weight", h.checks.every((c) => c.id && c.label && c.status && c.detail && typeof c.weight === "number"));

// ── Tri-state status boundaries ───────────────────────────────────────────────
ok("healthy domain → ready, score 100", h.status === "ready" && h.score === 100);

const noData = buildEnforcementReadinessChecks({});
ok("no evidence → not_ready, low score", noData.status === "not_ready" && noData.score < 55);

const midway = buildEnforcementReadinessChecks({ days_with_data: 10, total_messages: 500, pass_rate: 96,
  unknown_senders: 1, high_volume_failed_senders: 0, threat_senders: 0, suspicious_senders: 1, days_since_change: 2 });
ok("partially-ready domain → approaching", midway.status === "approaching" && midway.score >= 55 && midway.score < 100);

// ── Hard blockers can never sit inside a 'ready' verdict ───────────────────────
const withThreat = buildEnforcementReadinessChecks({ ...healthy, threat_senders: 1 });
ok("an active impersonation threat fails the no_active_threats check", check(withThreat, "no_active_threats").status === "fail");
ok("a single hard fail caps status below ready", withThreat.status !== "ready");

const withMisaligned = buildEnforcementReadinessChecks({ ...healthy, high_volume_failed_senders: 2 });
ok("high-volume alignment failure is a hard fail", check(withMisaligned, "sender_alignment").status === "fail");
ok("alignment failure blocks ready", withMisaligned.status !== "ready");

// ── Individual check gradations ───────────────────────────────────────────────
ok("pass_rate 99 → pass", check(buildEnforcementReadinessChecks({ ...healthy, pass_rate: 99 }), "dmarc_pass_rate").status === "pass");
ok("pass_rate 96 → warn", check(buildEnforcementReadinessChecks({ ...healthy, pass_rate: 96 }), "dmarc_pass_rate").status === "warn");
ok("pass_rate 90 → fail", check(buildEnforcementReadinessChecks({ ...healthy, pass_rate: 90 }), "dmarc_pass_rate").status === "fail");
ok("reporting_window 30d → pass", check(buildEnforcementReadinessChecks({ ...healthy, days_with_data: 30 }), "reporting_window").status === "pass");
ok("reporting_window 8d → warn", check(buildEnforcementReadinessChecks({ ...healthy, days_with_data: 8 }), "reporting_window").status === "warn");
ok("reporting_window 3d → fail", check(buildEnforcementReadinessChecks({ ...healthy, days_with_data: 3 }), "reporting_window").status === "fail");
ok("3 unknown senders → classification fail", check(buildEnforcementReadinessChecks({ ...healthy, unknown_senders: 3 }), "sender_classification").status === "fail");
ok("1 unknown sender → classification warn", check(buildEnforcementReadinessChecks({ ...healthy, unknown_senders: 1 }), "sender_classification").status === "warn");
ok("suspicious sender (no threat) → warn, not fail", check(buildEnforcementReadinessChecks({ ...healthy, suspicious_senders: 2 }), "no_active_threats").status === "warn");
ok("no recent change → soak_time n/a passes", check(buildEnforcementReadinessChecks({ ...healthy, days_since_change: null }), "soak_time").status === "pass");
ok("change 0 days ago → soak_time fail", check(buildEnforcementReadinessChecks({ ...healthy, days_since_change: 0 }), "soak_time").status === "fail");

// ── Score monotonicity: worse evidence never scores higher ────────────────────
ok("degrading pass rate lowers the score",
   buildEnforcementReadinessChecks({ ...healthy, pass_rate: 99 }).score >= buildEnforcementReadinessChecks({ ...healthy, pass_rate: 90 }).score);

// ── Legacy milestone keys are preserved unchanged (backward compatibility) ─────
const legacy = buildDmarcEnforcementReadiness(healthy);
ok("legacy ready_for_quarantine still present", typeof legacy.ready_for_quarantine === "boolean");
ok("legacy ready_for_reject still present", typeof legacy.ready_for_reject === "boolean");
ok("legacy confidence/blockers/next_step/explanation preserved",
   typeof legacy.confidence === "string" && Array.isArray(legacy.blockers) && typeof legacy.next_step === "string" && typeof legacy.explanation === "string");
ok("v2 fields (status/score/checks) merged onto the same object",
   typeof legacy.status === "string" && typeof legacy.score === "number" && Array.isArray(legacy.checks) && legacy.checks.length === 7);
ok("healthy domain is legacy-ready for reject AND v2-ready (engines agree)",
   legacy.ready_for_reject === true && legacy.status === "ready");
const notReadyLegacy = buildDmarcEnforcementReadiness({ days_with_data: 2, total_messages: 10, pass_rate: 80, unknown_senders: 5 });
ok("unhealthy domain is legacy-not-ready AND v2-not-ready (engines agree)",
   notReadyLegacy.ready_for_quarantine === false && notReadyLegacy.status === "not_ready");

console.log(`\nEnforcement readiness v2: ${pass}/${pass + fail} passed`);
if (fail) { console.error("enforcement-readiness-v2 validation FAILED"); process.exit(1); }
console.log("enforcement-readiness-v2 validation passed");
