// ── Brand managed-case machine (neutral definition) ────────────────────────
// The Brand Protection (brand_abuse) case-type state machine, extracted to a leaf
// module so BOTH brand-cases.js and the universal managed-case-model.js can
// import it without an import cycle. Imports only case-workflow.js.
import { createCaseMachine, requireActor, requireField, requireReason } from "./case-workflow.js";

export const BRAND_CASE_TYPE = "brand_abuse";
export const BRAND_CASE_STATES = [
  "detected", "triage", "confirmed_abuse", "customer_approval", "evidence_ready",
  "takedown_submitted", "provider_followup", "verification_pending", "resolved",
  "false_positive", "duplicate", "provider_no_response", "escalated", "reappeared", "closed",
];

export const BRAND_CASE_MACHINE = createCaseMachine({
  states: BRAND_CASE_STATES,
  transitions: {
    detected: ["triage"],
    triage: ["confirmed_abuse", "false_positive", "duplicate"],
    confirmed_abuse: ["customer_approval"],
    customer_approval: ["evidence_ready"],
    evidence_ready: ["takedown_submitted"],
    takedown_submitted: ["provider_followup"],
    provider_followup: ["verification_pending", "provider_no_response", "escalated"],
    verification_pending: ["resolved", "provider_no_response", "escalated"],
    resolved: ["reappeared", "closed"],
    reappeared: ["confirmed_abuse"],
    provider_no_response: ["provider_followup", "escalated", "closed"],
    escalated: ["provider_followup", "verification_pending", "closed"],
    false_positive: [],
    duplicate: [],
    closed: [],
  },
  terminals: ["false_positive", "duplicate", "closed"],
  guards: {
    confirmed_abuse: [requireReason],
    false_positive: [requireReason],
    duplicate: [requireReason],
    customer_approval: [requireReason],
    evidence_ready: [(_row, ctx) => requireActor(ctx)],
    takedown_submitted: [requireField("submission_reference")],
    provider_no_response: [requireReason],
  },
});

export const BRAND_SYSTEM_ONLY_STATES = new Set(["resolved", "reappeared", "provider_no_response"]);
