// ── Universal Managed-Case Model ───────────────────────────────────────────
// One shared case platform across all eight Cyber MOT domains. It does NOT
// replace the existing Attack Surface (asm_exposure) and Brand (brand_abuse)
// state machines — it registers them alongside a canonical BASE lifecycle used
// by the six domains that do not yet have a bespoke workflow, and provides:
//   • CANONICAL_CASE_STATES / CANONICAL_TERMINAL_STATES — the machine-stable base
//     lifecycle vocabulary (never display labels);
//   • CASE_TYPE_REGISTRY — one entry per case_type mapping it to a domain_key, a
//     state machine, its system-only states and its verification support;
//   • CANONICAL_PHASE_MAP — every state of every case_type folded onto ONE
//     canonical phase, so a cross-domain queue can display heterogeneous cases;
//   • canTransitionCase(...) — the single transition validator every universal
//     route/action must go through. It enforces the case_type's machine, the
//     system-only rule, and the universal invariants (verified requires
//     verification evidence; accepted-risk / false-positive are never verified;
//     reopen preserves history; canonical timestamps are stamped).
//
// The existing managed_cases table + managed_case_events append-only log are the
// storage substrate (extended additively by migration 082). No parallel tables.

import { applyCaseTransition, createCaseMachine, isTerminal, canTransition,
  requireActor, requireReason, requireField, requireExpiry } from "./case-workflow.js";
import { ASM_CASE_TYPE, ASM_CASE_MACHINE, ASM_CASE_STATES, SYSTEM_ONLY_CASE_STATES } from "./asm-cases.js";
import { BRAND_CASE_TYPE, BRAND_CASE_MACHINE, BRAND_CASE_STATES, BRAND_SYSTEM_ONLY_STATES } from "./brand-cases.js";
import { CYBER_MOT_DOMAINS } from "./cyber-mot-domains.js";
import { findingRemediation } from "./remediation-registry.js";

// The eight canonical domain keys are DERIVED from the Cyber MOT model so they
// can never drift from it.
export const CANONICAL_DOMAIN_KEYS = Object.freeze(CYBER_MOT_DOMAINS.map((d) => d.domain_key));
const DOMAIN_KEY_SET = new Set(CANONICAL_DOMAIN_KEYS);

// ── Canonical base lifecycle ────────────────────────────────────────────────
// Machine-stable keys — persistence identity, never the display label.
export const CANONICAL_CASE_STATES = Object.freeze([
  "detected",
  "triaged",
  "assigned",
  "approved",              // Approved / Accepted to act
  "action_in_progress",
  "awaiting_verification",
  "verified",
  "monitoring",
  "reopened",
]);
// Terminal / exceptional outcomes — NONE of these is "verified".
export const CANONICAL_TERMINAL_STATES = Object.freeze([
  "rejected",
  "accepted_risk",
  "false_positive",
  "closed_no_action",
  "superseded",
]);
const ALL_BASE_STATES = [...CANONICAL_CASE_STATES, ...CANONICAL_TERMINAL_STATES];

// The BASE machine used by domains without a bespoke workflow yet.
export const BASE_CASE_MACHINE = createCaseMachine({
  states: ALL_BASE_STATES,
  transitions: {
    detected:              ["triaged", "false_positive", "superseded"],
    triaged:               ["assigned", "rejected", "false_positive", "superseded"],
    assigned:              ["approved", "accepted_risk", "rejected", "false_positive"],
    approved:              ["action_in_progress", "accepted_risk"],
    action_in_progress:    ["awaiting_verification", "accepted_risk", "closed_no_action"],
    awaiting_verification: ["verified", "action_in_progress"],
    verified:              ["monitoring", "reopened", "closed_no_action"],
    monitoring:            ["reopened", "closed_no_action"],
    reopened:              ["action_in_progress", "triaged"],
    accepted_risk:         ["triaged"], // re-triage on expiry — exceptional, NOT terminal
    rejected:              [],
    false_positive:        [],
    closed_no_action:      [],
    superseded:            [],
  },
  terminals: ["rejected", "false_positive", "closed_no_action", "superseded"],
  guards: {
    assigned:         [requireField("owner_ref")],
    approved:         [requireActor],
    action_in_progress: [],
    accepted_risk:    [requireReason, requireExpiry],
    rejected:         [requireReason],
    false_positive:   [requireReason],
    closed_no_action: [requireReason],
    superseded:       [requireReason],
    // `verified` is additionally gated by the universal verification rule in
    // canTransitionCase — the machine edge alone never verifies.
  },
});
// Base states only reachable via product verification (not customer-set).
export const BASE_SYSTEM_ONLY_STATES = new Set(["verified"]);

// ── Canonical phase folding ─────────────────────────────────────────────────
// Every state of every registered case_type folds onto ONE canonical phase, so a
// cross-domain queue can render heterogeneous cases with one vocabulary. This
// changes NO stored value — it is a read-time display projection.
const BASE_PHASE = Object.fromEntries(ALL_BASE_STATES.map((s) => [s, s]));
const ASM_PHASE = {
  open: "detected", triage: "triaged", owner_assigned: "assigned",
  remediation_in_progress: "action_in_progress",
  verification_requested: "awaiting_verification", verifying: "awaiting_verification",
  resolved: "verified", risk_acceptance_requested: "action_in_progress",
  risk_accepted: "accepted_risk", false_positive: "false_positive",
  verification_failed: "action_in_progress", reopened: "reopened", closed: "closed_no_action",
};
const BRAND_PHASE = {
  detected: "detected", triage: "triaged", confirmed_abuse: "assigned",
  customer_approval: "approved", evidence_ready: "action_in_progress",
  takedown_submitted: "action_in_progress", provider_followup: "action_in_progress",
  verification_pending: "awaiting_verification", resolved: "verified",
  false_positive: "false_positive", duplicate: "superseded",
  provider_no_response: "action_in_progress", escalated: "action_in_progress",
  reappeared: "reopened", closed: "closed_no_action",
};

// ── Case-type registry — one entry per case_type ────────────────────────────
// Existing ASM/Brand keep their own machines (full backward compatibility); the
// other six domains use the base machine. Verification support is honest: only
// ASM and Brand can be product-verified today; the rest are manual/unsupported
// this episode (no bespoke domain workflow is built here).
function baseEntry(domain_key, case_type) {
  return {
    case_type, domain_key,
    machine: BASE_CASE_MACHINE,
    states: ALL_BASE_STATES,
    phase: BASE_PHASE,
    system_only: BASE_SYSTEM_ONLY_STATES,
    verified_states: new Set(["verified"]),
    verification_support: "manual", // no automated verifier wired this episode
    base: true,
  };
}

export const CASE_TYPE_REGISTRY = Object.freeze({
  [ASM_CASE_TYPE]: {
    case_type: ASM_CASE_TYPE, domain_key: "attack_surface",
    machine: ASM_CASE_MACHINE, states: ASM_CASE_STATES, phase: ASM_PHASE,
    system_only: SYSTEM_ONLY_CASE_STATES, verified_states: new Set(["resolved"]),
    verification_support: "automated", base: false,
  },
  [BRAND_CASE_TYPE]: {
    case_type: BRAND_CASE_TYPE, domain_key: "brand_protection",
    machine: BRAND_CASE_MACHINE, states: BRAND_CASE_STATES, phase: BRAND_PHASE,
    system_only: BRAND_SYSTEM_ONLY_STATES, verified_states: new Set(["resolved"]),
    verification_support: "automated", base: false,
  },
  email_case:          baseEntry("email_protection", "email_case"),
  certificate_case:    baseEntry("certificates_trust", "certificate_case"),
  cyber_essentials_case: baseEntry("cyber_essentials_readiness", "cyber_essentials_case"),
  website_case:        baseEntry("website_security", "website_case"),
  identity_case:       baseEntry("identity_exposure", "identity_case"),
  shadow_it_case:      baseEntry("shadow_it_unmanaged_technology", "shadow_it_case"),
});

// domain_key → default case_type (used when opening a case for a domain).
export const DEFAULT_CASE_TYPE_BY_DOMAIN = Object.freeze(
  Object.fromEntries(Object.values(CASE_TYPE_REGISTRY).map((e) => [e.domain_key, e.case_type])),
);

export function caseTypeEntry(caseType) {
  return CASE_TYPE_REGISTRY[String(caseType)] || null;
}
export function isValidDomainKey(key) { return DOMAIN_KEY_SET.has(String(key)); }

// The canonical phase for a case's raw status (cross-domain display). Unknown
// state → "detected" is NOT assumed; returns null so callers stay honest.
export function canonicalPhaseFor(caseType, status) {
  const entry = caseTypeEntry(caseType);
  if (!entry) return null;
  return entry.phase[String(status)] ?? null;
}

// Is a target state a "verified" state for this case_type?
function isVerifiedTarget(entry, target) {
  return entry.verified_states.has(String(target));
}

// Verification evidence must be a domain/finding-specific verification RESULT —
// a scan merely completing is never sufficient (rule: scan completion alone
// cannot verify). We accept an explicit verified flag or a "fixed" probe
// decision with complete completeness.
function hasVerificationEvidence(evidence) {
  if (!evidence || typeof evidence !== "object") return false;
  if (evidence.scan_completed_only === true) return false;
  if (evidence.verified === true) return true;
  if (evidence.decision === "fixed" && evidence.completeness === "complete") return true;
  if (evidence.decision === "verified" && evidence.completeness === "complete") return true;
  return false;
}

// Canonical-lifecycle timestamp for a target phase.
const PHASE_TIMESTAMP = {
  approved: "approved_at",
  action_in_progress: "action_started_at",
  awaiting_verification: "awaiting_verification_at",
  verified: "verified_at",
  monitoring: "monitoring_started_at",
  reopened: "reopened_at",
  accepted_risk: "accepted_at",
  rejected: "closed_at",
  false_positive: "closed_at",
  closed_no_action: "closed_at",
  superseded: "closed_at",
};

// ── The single universal transition validator ───────────────────────────────
// canTransitionCase({ case, target_status, actor, evidence, reason })
// No universal route or frontend action may bypass this. It:
//   • resolves the case_type machine (existing ASM/Brand or base);
//   • blocks a non-system actor from setting a system-only state;
//   • enforces the machine edge + guards + terminal immutability (applyCaseTransition);
//   • enforces the VERIFIED rule — a verified target needs a system actor AND
//     verification evidence (a bare scan completion is rejected);
//   • guarantees accepted-risk / false-positive are never the verified phase;
//   • preserves prior evidence/history on reopen (never clears it);
//   • stamps the canonical-lifecycle timestamp for the target phase;
//   • returns an append-only event descriptor for the caller to persist.
// Pure — performs no DB writes.
export function canTransitionCase(opts = {}) {
  const { case: caseRecord, target_status, actor = {}, evidence = null, reason = null } = opts;
  if (!caseRecord || typeof caseRecord !== "object") return { ok: false, code: "no_case", error: "No case provided." };
  const entry = caseTypeEntry(caseRecord.case_type);
  if (!entry) return { ok: false, code: "unknown_case_type", error: `Unknown case_type "${caseRecord.case_type}".` };

  const target = String(target_status || "");
  const actorType = actor.actor_type || "customer";
  const actorId = actor.actor_id || actor.id || null;

  // System-only states cannot be set by a customer/manual actor.
  if (entry.system_only?.has?.(target) && actorType !== "system") {
    return { ok: false, code: "system_only", error: "This step is verified by CyberMeters and cannot be set manually." };
  }

  // Verified rule — a scan completing is never enough; require a system actor
  // and a domain/finding-specific verification result.
  if (isVerifiedTarget(entry, target)) {
    if (actorType !== "system") {
      return { ok: false, code: "verify_requires_system", error: "Only CyberMeters verification can mark a case verified." };
    }
    if (!hasVerificationEvidence(evidence)) {
      return { ok: false, code: "verify_requires_evidence", error: "Verification evidence is required; a completed scan alone does not verify a case." };
    }
  }

  // Delegate edge + guard + terminal-immutability enforcement to the machine.
  const ctx = {
    actor_type: actorType, actor_id: actorId, actor: actorId,
    reason, now: opts.now || new Date().toISOString(),
  };
  if (opts.risk_accepted_until != null) ctx.risk_accepted_until = opts.risk_accepted_until;
  if (opts.owner_ref != null) ctx.owner_ref = opts.owner_ref;
  if (opts.submission_reference != null) ctx.submission_reference = opts.submission_reference;

  const result = applyCaseTransition(entry.machine, caseRecord, target, ctx);
  if (!result.ok) return { ok: false, code: "invalid_transition", error: result.error };

  const next = result.case;
  const phase = entry.phase[target] ?? null;
  const tsField = PHASE_TIMESTAMP[phase];
  if (tsField && !next[tsField]) next[tsField] = ctx.now;
  // Reopen must preserve prior evidence/history — never clear evidence_json.
  // (applyCaseTransition already spreads the record; we assert the invariant.)
  if (phase === "reopened") next.evidence_json = caseRecord.evidence_json ?? next.evidence_json ?? null;

  const event = {
    case_id: caseRecord.id,
    workspace_id: caseRecord.workspace_id,
    actor_type: actorType,
    actor_id: actorId,
    from_status: caseRecord.status,
    to_status: target,
    action: opts.action || `transition_${target}`,
    detail_json: evidence ? JSON.stringify({ evidence }) : null,
  };
  return { ok: true, case: next, canonical_phase: phase, event };
}

// Resolve the canonical remediation_id for a case's source finding (or null).
export function caseRemediationId(caseRecord) {
  const ft = caseRecord?.source_finding_type || caseRecord?.finding_id;
  const r = ft ? findingRemediation({ id: ft, finding_type: "finding" }) : null;
  return r?.remediation_id ?? null;
}
