// ── ASM managed-case machine (neutral definition) ──────────────────────────
// The Attack Surface (asm_exposure) case-type state machine, extracted to a leaf
// module so BOTH asm-cases.js and the universal managed-case-model.js can import
// it without an import cycle (the model registers this machine; asm-cases routes
// its transitions through the model's validator). Imports only case-workflow.js.
import { createCaseMachine, requireExpiry, requireField, requireReason } from "./case-workflow.js";

export const ASM_CASE_TYPE = "asm_exposure";
export const ASM_CASE_STATES = [
  "open", "triage", "owner_assigned", "remediation_in_progress",
  "verification_requested", "verifying", "resolved",
  "risk_acceptance_requested", "risk_accepted", "false_positive",
  "verification_failed", "reopened", "closed",
];

export const ASM_CASE_MACHINE = createCaseMachine({
  states: ASM_CASE_STATES,
  transitions: {
    open: ["triage"],
    triage: ["owner_assigned", "false_positive"],
    owner_assigned: ["remediation_in_progress", "risk_acceptance_requested", "false_positive"],
    remediation_in_progress: ["verification_requested", "risk_acceptance_requested", "false_positive", "closed"],
    verification_requested: ["verifying"],
    // `verifying → verification_requested` is the concurrency RELEASE edge used to
    // free a stuck verification claim (deferred probe result); it was previously
    // performed by a raw compare-and-set outside the machine. Declaring it here
    // (additive — no existing edge changed) lets that release be validated by the
    // universal validator instead of bypassing it.
    verifying: ["resolved", "verification_failed", "verification_requested"],
    verification_failed: ["remediation_in_progress", "verification_requested", "risk_acceptance_requested"],
    resolved: ["reopened", "closed"],
    reopened: ["remediation_in_progress"],
    risk_acceptance_requested: ["risk_accepted", "remediation_in_progress"],
    risk_accepted: ["triage"],
    false_positive: [],
    closed: [],
  },
  terminals: ["false_positive", "closed"],
  guards: {
    owner_assigned: [requireField("owner_ref")],
    remediation_in_progress: [requireField("owner_ref")],
    risk_acceptance_requested: [requireReason],
    risk_accepted: [requireReason, requireExpiry],
    false_positive: [requireReason],
    verification_failed: [requireReason],
  },
});

// States only CyberMeters (system actor) may set.
export const SYSTEM_ONLY_CASE_STATES = new Set([
  "verifying", "resolved", "verification_failed", "reopened",
]);
