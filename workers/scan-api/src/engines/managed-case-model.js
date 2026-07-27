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
  requireActor, requireReason, requireField, requireExpiry,
  newManagedCaseId, newCaseEventId } from "./case-workflow.js";
import { ASM_CASE_TYPE, ASM_CASE_MACHINE, ASM_CASE_STATES, SYSTEM_ONLY_CASE_STATES } from "./asm-case-machine.js";
import { BRAND_CASE_TYPE, BRAND_CASE_MACHINE, BRAND_CASE_STATES, BRAND_SYSTEM_ONLY_STATES } from "./brand-case-machine.js";
import { CYBER_MOT_DOMAINS } from "./cyber-mot-domains.js";
import { findingRemediation, getRemediationById } from "./remediation-registry.js";

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
    // Guards are invoked as guard(caseRecord, ctx). requireActor takes the CTX as its only
    // argument, so it must be wrapped — passed bare it received the case record, looked for
    // an actor_id that is never on a case row, and refused EVERY approval. That made
    // `approved` unreachable for all six base domains, and with it awaiting_verification and
    // verified: the whole managed lifecycle dead-ended at `assigned`. brand-case-machine.js
    // has always wrapped it correctly; this line did not.
    approved:         [(_row, ctx) => requireActor(ctx)],
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
// Base (manual-verification) domains have NO system-only states this episode:
// `verified` is reachable by manual attestation from an allowed actor, gated by
// the verification-evidence contract (structured attestation required). ASM/Brand
// keep their own system-only sets (their `resolved` stays CyberMeters-only).
export const BASE_SYSTEM_ONLY_STATES = new Set();

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
    initial_state: "detected",
    phase: BASE_PHASE,
    system_only: BASE_SYSTEM_ONLY_STATES,
    verified_states: new Set(["verified"]),
    verification_support: "manual", // no automated verifier wired for this domain
    base: true,
  };
}

// ── Registry-derived verification support ───────────────────────────────────
// A case_type is the WRONG grain for "how is this verified", and assuming otherwise gets
// both possible answers wrong for Email Protection:
//
//   hosted_record_disconnected → email.hosted_dmarc.reconnect      → dns_recheck
//   hosted_rolled_back_auto    → email.hosted_dmarc.auto_rollback_review → manual_attestation
//   sender_unrecognised        → email.sender.review_unrecognised   → manual_attestation
//
// Blanket `automated` would make three of Email's six case-producing conditions
// UNVERIFIABLE FOREVER — no system verifier can exist for a thing the registry says the
// product cannot observe. Blanket `manual` lets a customer's assertion conclude
// verification for a DNS record CyberMeters re-observes itself, which is the rule this
// increment exists to preserve.
//
// The Canonical Remediation Registry has ALREADY decided this, per finding. CLAUDE.md
// makes it the source of truth for remediation meaning "including ... verification
// method", and its vocabulary is explicit: `manual_attestation // customer confirms;
// product cannot observe it`. So the case model asks the registry rather than guessing per
// domain:
//
//   verification_method === "manual_attestation"  → the product cannot observe this;
//                                                   a structured attestation from an
//                                                   identified actor is the honest ceiling
//   anything else (dns_recheck, https_recheck,     → the product CAN observe this, so only
//   certificate_recheck, rescan, receiver_reports,   CyberMeters' own observation verifies
//   external)                                        and the customer cannot conclude it
//   unsupported                                    → nothing verifies it
//
// This is not a new product semantic. It is CLAUDE.md's existing rule — "Verification
// requires structured, METHOD-APPROPRIATE evidence" — read literally: attestation is
// method-appropriate exactly where the registry says observation is impossible.
//
// ── Which case types derive their support from the registry ─────────────────
// M5.b adds certificate_case, and the audit that added it is the reason to state WHY the
// other two are still absent rather than leaving it to inference:
//
//   certificate_case  → DERIVED. Certificates & Trust holds SIX different verification
//     methods across ten remediations — the most diverse domain on the platform — so a
//     blanket answer is wrong in both directions at once. Under the old blanket `manual`,
//     a customer could attest an EXPIRED certificate "verified" (registry:
//     `certificate_recheck` — CyberMeters re-observes certificates on every scan), and
//     could attest a Certificate Transparency blackout resolved (registry: `unsupported`
//     — nothing can verify it). Both were reproduced before this change.
//
//   identity_case     → NOT derived, and correctly so: all eight identity_* remediations
//     are `manual_attestation`, so the blanket and the registry already agree. Deriving
//     would add indirection and change nothing.
//   shadow_it_case    → NOT derived, same reason: its one remediation is
//     `manual_attestation`.
//
// Both were checked against the registry, not assumed. If either ever gains an observable
// finding, it belongs in this set and the guard in validate-m5b-certificate-verification.js
// will fail until it is added.
const REGISTRY_DERIVED_VERIFICATION = new Set([
  "email_case", "website_case", "cyber_essentials_case", "certificate_case",
]);

/**
 * How may THIS case be verified? Derived from its own canonical remediation where the
 * case_type opts in; otherwise the case_type's declared support.
 *
 * Fails CLOSED: a case whose remediation cannot be resolved gets "unsupported" rather than
 * the more permissive "manual" — an unknown finding is not an invitation to self-certify.
 */
export function verificationSupportForCase(caseRecord = {}) {
  const entry = caseTypeEntry(caseRecord.case_type);
  if (!entry) return "unsupported";
  if (!REGISTRY_DERIVED_VERIFICATION.has(entry.case_type)) return entry.verification_support;

  const rem = caseRecord.remediation_id ? getRemediationById(caseRecord.remediation_id) : null;
  return verificationSupportForMethod(rem?.verification_method ?? null);
}

/**
 * The ONE method→support mapping. Extracted (M5.c) so the reporting snapshot can
 * derive per-finding verification support from the registry's verification_method
 * without growing a second copy of this table — the "two vocabularies, one slot"
 * class of defect started exactly that way.
 */
export function verificationSupportForMethod(method) {
  if (!method) return "unsupported";
  if (method === "unsupported") return "unsupported";
  if (method === "manual_attestation") return "manual";
  // `external` is NOT automated. "Automated" means a reachable CyberMeters system verifier
  // concluded it from our own observation; `external` means an INDEPENDENT THIRD PARTY must
  // — a certification body, an auditor. CyberMeters cannot conclude it from a scan, and the
  // customer cannot attest it either: the whole point is that someone else says so.
  //
  // Mapping it to "automated" (which the old `? "manual" : "automated"` did) made it
  // system-only against a system verifier that does not exist, so such a case would have been
  // unverifiable forever while LOOKING like ordinary automated verification. Its own state
  // says the true thing: no verification path exists on this platform today. If a real
  // third-party evidence workflow is ever built, THAT increment gives this a verifier.
  if (method === "external") return "external";
  return "automated";
}

// ── Available transitions (canonical, backend-derived) ──────────────────────
// The ONE place the customer-facing "what can I do next" list is computed — from
// the case_type's own machine, the current status, and the case's per-finding
// verification support. The frontend renders exactly this and derives NO
// transition itself (no second copy of the state machine). Labels are display
// text; requirement flags mirror the machine's guards so the UI can collect the
// same input canTransitionCase enforces. Never exposes rule IDs, guard internals
// or provider data.
//
// Only base-lifecycle case types expose generic transitions here; ASM and Brand
// keep their bespoke flows (empty list — untouched). A verified target is offered
// to a customer ONLY where the honest ceiling is a manual attestation; automated
// / external / unsupported verification is never a customer button (CyberMeters
// or an independent third party concludes those, so advertising it would be a
// dead control canTransitionCase would refuse).
const BASE_TRANSITION_META = Object.freeze({
  triaged:               { label: "Begin triage" },
  assigned:              { label: "Move to Assigned", owner: true },
  approved:              { label: "Approve to act" },
  action_in_progress:    { label: "Start remediation" },
  awaiting_verification: { label: "Submit for verification" },
  verified:              { label: "Record customer attestation", verify: true },
  monitoring:            { label: "Move to monitoring" },
  reopened:              { label: "Reopen case" },
  accepted_risk:         { label: "Accept risk", note: true, expiry: true },
  rejected:              { label: "Reject case", note: true },
  false_positive:        { label: "Mark false positive", note: true },
  closed_no_action:      { label: "Close — no action needed", note: true },
  superseded:            { label: "Mark superseded", note: true },
});

export function availableTransitionsForCase(caseRecord = {}, { actor_type = "customer" } = {}) {
  const entry = caseTypeEntry(caseRecord.case_type);
  if (!entry || !entry.base) return []; // ASM/Brand use bespoke flows — no generic controls
  const from = String(caseRecord.status || "");
  const targets = entry.machine.transitions[from] || [];
  const hasOwner = Boolean(String(caseRecord.owner_ref ?? "").trim());
  const out = [];
  for (const target of targets) {
    // System-only states are never a manual/customer action.
    if (entry.system_only?.has?.(target) && actor_type !== "system") continue;
    const meta = BASE_TRANSITION_META[target];
    // Fail closed: never advertise a target we have no honest label for.
    if (!meta) continue;
    const isVerify = entry.verified_states.has(target);
    let verification_mode = null;
    if (isVerify) {
      verification_mode = verificationSupportForCase(caseRecord);
      // Customer can conclude a verified target only by manual attestation.
      if (actor_type !== "system" && verification_mode !== "manual") continue;
    }
    out.push({
      target_status: target,
      label: meta.label,
      requires_owner: Boolean(meta.owner) && !hasOwner,
      requires_note: Boolean(meta.note),
      requires_expiry: Boolean(meta.expiry),
      requires_attestation: Boolean(isVerify && verification_mode === "manual"),
      verification_mode,
    });
  }
  return out;
}

export const CASE_TYPE_REGISTRY = Object.freeze({
  [ASM_CASE_TYPE]: {
    case_type: ASM_CASE_TYPE, domain_key: "attack_surface",
    machine: ASM_CASE_MACHINE, states: ASM_CASE_STATES, phase: ASM_PHASE,
    initial_state: "open",
    system_only: SYSTEM_ONLY_CASE_STATES, verified_states: new Set(["resolved"]),
    verification_support: "automated", base: false,
  },
  [BRAND_CASE_TYPE]: {
    case_type: BRAND_CASE_TYPE, domain_key: "brand_protection",
    machine: BRAND_CASE_MACHINE, states: BRAND_CASE_STATES, phase: BRAND_PHASE,
    initial_state: "detected",
    system_only: BRAND_SYSTEM_ONLY_STATES, verified_states: new Set(["resolved"]),
    verification_support: "automated", base: false,
  },
  // These three derive verification support from each case's own canonical remediation —
  // see verificationSupportForCase. The `manual` below is only the fallback for a case
  // whose remediation cannot be resolved; the registry decides the real answer.
  email_case:          baseEntry("email_protection", "email_case"),
  cyber_essentials_case: baseEntry("cyber_essentials_readiness", "cyber_essentials_case"),
  website_case:        baseEntry("website_security", "website_case"),
  // Unchanged — closed increments with their own verification stories.
  certificate_case:    baseEntry("certificates_trust", "certificate_case"),
  identity_case:       baseEntry("identity_exposure", "identity_case"),
  shadow_it_case:      baseEntry("shadow_it_unmanaged_technology", "shadow_it_case"),
});

// domain_key → default case_type (used when opening a case for a domain).
export const DEFAULT_CASE_TYPE_BY_DOMAIN = Object.freeze(
  Object.fromEntries(Object.values(CASE_TYPE_REGISTRY).map((e) => [e.domain_key, e.case_type])),
);

// ── Canonical case-ownership assignment (M5.e) ──────────────────────────────
// The ONE assignment path for every case type. Persists owner atomically,
// appends an assignment_changed event (append-only evidence), refuses an empty
// owner (a case is never assigned to nobody, and an owner is never fabricated),
// and leaves unassigned cases visibly unassigned.
export const CASE_OWNER_TYPES = Object.freeze(["person", "team", "vendor", "unknown"]);

// Is user_id an ACTIVE member of workspace_id? Membership is a single row in
// workspace_members — removal (member-remove and account deletion) is a hard
// DELETE, and the table has no status/removed_at column, so a row's existence IS
// active membership. This is the canonical assignee/owner membership check
// (reused by the universal /assign and /transition paths). Fails CLOSED — any
// read error returns false so an assignment is never granted on a failed lookup.
export async function isActiveWorkspaceMember(env, workspace_id, user_id) {
  if (!workspace_id || !user_id) return false;
  const row = await env.cybermeters_db
    .prepare(`SELECT id FROM workspace_members WHERE workspace_id = ? AND user_id = ? LIMIT 1`)
    .bind(workspace_id, user_id).first().catch(() => null);
  return Boolean(row);
}

export async function assignCaseOwner(env, caseRow, { owner_type, owner_ref, actor_type = "customer", actor_id = null, assigned_user_id = null } = {}) {
  if (!caseRow?.id || !caseRow?.workspace_id) {
    return { ok: false, code: "invalid_case", error: "Case not found." };
  }
  const ref = String(owner_ref ?? "").trim().slice(0, 255);
  if (!ref) {
    return { ok: false, code: "owner_ref_required", error: "An owner is required to assign this case." };
  }
  // `assigned_user_id`, when present, is the platform-USER link and must
  // reference an ACTIVE member of THIS workspace — never a foreign-workspace
  // user, a removed member, or a non-existent id. `owner_ref` stays free text (a
  // team or vendor may not be a platform user); only the user link is validated.
  // Fail CLOSED: a non-member assignee is refused before any write, so the case
  // owner is never fabricated and never crosses a tenant boundary. Empty /
  // whitespace-only assignee is treated as "no user link" (owner_ref only).
  const assignee = String(assigned_user_id ?? "").trim() || null;
  if (assignee && !(await isActiveWorkspaceMember(env, caseRow.workspace_id, assignee))) {
    return { ok: false, code: "assignee_not_member", error: "The assignee must be an active member of this workspace." };
  }
  const type = CASE_OWNER_TYPES.includes(owner_type) ? owner_type : "unknown";
  // Idempotent no-op: a repeated identical assignment (same owner_type, owner_ref
  // and user link) records no NEW fact, so it must not append another
  // assignment_changed event or bump updated_at — an append-only log stays honest
  // only when every row is a real change. The /transition path already guards this
  // (owner_ref !== row.owner_ref); the canonical writer must too.
  const curType = caseRow.owner_type ?? null;
  const curRef = caseRow.owner_ref ?? null;
  const curAssignee = caseRow.assigned_user_id ?? null;
  if (curRef === ref && curType === type && curAssignee === assignee) {
    return { ok: true, case: caseRow, idempotent: true };
  }
  const now = new Date().toISOString();
  const res = await env.cybermeters_db
    .prepare(`UPDATE managed_cases
        SET owner_type = ?, owner_ref = ?, assigned_by = ?, assigned_user_id = ?, updated_at = ?
      WHERE id = ? AND workspace_id = ?`)
    .bind(type, ref, actor_id ?? actor_type, assignee, now, caseRow.id, caseRow.workspace_id)
    .run();
  if ((res.meta?.changes ?? 0) === 0) {
    return { ok: false, code: "not_found", error: "Case not found." };
  }
  const updated = { ...caseRow, owner_type: type, owner_ref: ref, assigned_by: actor_id ?? actor_type, assigned_user_id: assignee, updated_at: now };
  // Append-only evidence; a failed event write surfaces as an error rather than
  // silently losing the audit trail (assignment itself is idempotent to retry).
  await env.cybermeters_db
    .prepare(`INSERT INTO managed_case_events
        (id, case_id, workspace_id, actor_type, actor_id, from_status, to_status, action, detail_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`)
    .bind(newCaseEventId(), caseRow.id, caseRow.workspace_id, actor_type, actor_id,
          caseRow.status, caseRow.status, "assignment_changed",
          JSON.stringify({ owner_type: type, owner_ref: ref, assigned_user_id: assignee }))
    .run();
  return { ok: true, case: updated };
}

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

// ── Verification evidence contract ──────────────────────────────────────────
// A verified transition needs a STRUCTURED verification result — never a bare
// flag, a completed scan, or a customer note. Every verification evidence object
// must carry: verification_method, verification_result, evidence_type,
// observed_at, and an evidence_reference OR a structured observation.
export const VERIFICATION_RESULTS = Object.freeze(["fixed", "verified", "still_present", "inconclusive", "failed"]);
const POSITIVE_RESULTS = new Set(["fixed", "verified"]);

// Returns { ok, reason }. `support` is the case_type's verification_support
// ("automated" | "manual"); `actor` gates manual attestation.
export function validateVerificationEvidence(evidence, { support = "automated", actor = {} } = {}) {
  if (!evidence || typeof evidence !== "object") return { ok: false, reason: "verification_evidence_missing" };
  // A bare scan completion or a customer note never verifies.
  if (evidence.scan_completed_only === true) return { ok: false, reason: "scan_completion_not_verification" };
  if (evidence.note_only === true) return { ok: false, reason: "note_not_verification" };
  const method = String(evidence.verification_method || "");
  const result = String(evidence.verification_result || "");
  if (!method || method === "unsupported") return { ok: false, reason: "verification_unsupported" };
  if (!VERIFICATION_RESULTS.includes(result)) return { ok: false, reason: "verification_result_invalid" };
  // Failed / inconclusive / still-present never become verified.
  if (!POSITIVE_RESULTS.has(result)) return { ok: false, reason: "verification_not_positive" };
  if (!evidence.evidence_type) return { ok: false, reason: "evidence_type_missing" };
  if (!evidence.observed_at || !Number.isFinite(Date.parse(evidence.observed_at))) return { ok: false, reason: "observed_at_missing" };
  const hasObservation = evidence.evidence_reference != null ||
    (evidence.observation != null && typeof evidence.observation === "object") ||
    (evidence.attestation != null && typeof evidence.attestation === "object");
  if (!hasObservation) return { ok: false, reason: "observation_missing" };
  // Manual attestation requires a structured attestation AND an identified actor
  // (the route enforces the actor's role).
  if (method === "manual_attestation") {
    if (!evidence.attestation || typeof evidence.attestation !== "object") return { ok: false, reason: "attestation_required" };
    if (!actor.actor_id) return { ok: false, reason: "attestation_actor_required" };
  } else {
    // Automated verification requires an explicit machine result + observation.
    if (support === "automated" && evidence.observation == null && evidence.evidence_reference == null) {
      return { ok: false, reason: "automated_observation_required" };
    }
  }
  return { ok: true };
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

  // 1) Edge legality FIRST — an illegal/terminal transition is rejected before
  //    any authorization or evidence question (clear error precedence).
  const ctx = {
    actor_type: actorType, actor_id: actorId, actor: actorId,
    reason, now: opts.now || new Date().toISOString(),
  };
  if (opts.risk_accepted_until != null) ctx.risk_accepted_until = opts.risk_accepted_until;
  if (opts.owner_ref != null) ctx.owner_ref = opts.owner_ref;
  if (opts.submission_reference != null) ctx.submission_reference = opts.submission_reference;

  const result = applyCaseTransition(entry.machine, caseRecord, target, ctx);
  if (!result.ok) return { ok: false, code: "invalid_transition", error: result.error };

  // 2) System-only states cannot be set by a customer/manual actor.
  if (entry.system_only?.has?.(target) && actorType !== "system") {
    return { ok: false, code: "system_only", error: "This step is verified by CyberMeters and cannot be set manually." };
  }

  // 3) Verified rule — a scan completing is never enough. AUTOMATED case types
  //    (ASM/Brand) can only be verified by CyberMeters (system actor) with a valid
  //    automated result; MANUAL case types (the six base domains) verify via a
  //    structured attestation from an identified actor. Both go through the
  //    verification-evidence contract; failed/inconclusive never verifies.
  if (isVerifiedTarget(entry, target)) {
    // Per-CASE, not per-case_type: the registry already says how each finding is verified,
    // and the same domain can hold both an observable condition and one the product
    // genuinely cannot see. See verificationSupportForCase.
    const support = verificationSupportForCase(caseRecord);
    if (support === "unsupported") {
      return { ok: false, code: "verify_unsupported", error: "CyberMeters cannot verify this finding, so this case cannot be marked verified." };
    }
    // `external` needs independent third-party evidence (a certification body, an auditor).
    // CyberMeters cannot conclude it from its own scan, and a customer attestation is not
    // third-party evidence either. No workflow for accepting such evidence exists yet, so the
    // honest answer is that this cannot be concluded here at all — by anyone.
    if (support === "external") {
      return { ok: false, code: "verify_requires_external_evidence", error: "This is confirmed by an independent third party, not by a CyberMeters scan or by your own confirmation." };
    }
    if (support === "automated" && actorType !== "system") {
      return { ok: false, code: "verify_requires_system", error: "Only CyberMeters verification can mark this case verified." };
    }
    const v = validateVerificationEvidence(evidence, { support, actor: { actor_id: actorId, actor_type: actorType } });
    if (!v.ok) {
      return { ok: false, code: "verify_requires_evidence", error: `Verification evidence is required (${v.reason}); a completed scan or a note alone does not verify a case.`, reason: v.reason };
    }
  }

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

// ── Append-only event taxonomy ──────────────────────────────────────────────
// The canonical event types every UNIVERSAL write uses. Legacy ASM/Brand event
// `action` strings remain readable, but new universal writes use these. Each
// type declares the keys its detail_json must carry (deterministic shape).
export const CASE_EVENT_TYPES = Object.freeze({
  case_created:              ["domain_key", "case_type", "source_finding_type", "source_scan_id", "remediation_id"],
  status_changed:            ["from_status", "to_status", "reason"],
  assignment_changed:        ["owner_type", "owner_ref", "assigned_user_id"],
  evidence_added:            ["evidence_type", "evidence_reference"],
  verification_requested:    ["verification_method"],
  verification_completed:    ["verification_method", "verification_result", "evidence_type", "observed_at"],
  comment_added:             ["comment"],
  external_action_recorded:  ["action_type", "reference"],
  case_reopened:             ["previous_status", "reason"],
});

// Build a canonical, deterministic detail_json for an event type. Missing keys
// are set to null so the shape is stable; unknown keys are dropped.
export function buildCaseEventDetail(type, values = {}) {
  const keys = CASE_EVENT_TYPES[type];
  if (!keys) throw new Error(`managed-case-model: unknown event type "${type}"`);
  const detail = {};
  for (const k of keys) detail[k] = values[k] ?? null;
  return detail;
}
export function isCanonicalEventType(type) {
  return Object.prototype.hasOwnProperty.call(CASE_EVENT_TYPES, type);
}

// ── Universal case-creation primitive ───────────────────────────────────────
// createManagedCase — the ONE way registered domain workflows open a case.
// Existing bespoke machines keep their own registry-owned initial state (ASM
// `open`; Brand `detected`) while base-lifecycle domains use `detected`.
// Enforces valid domain/case_type + their match,
// an active (non-soft-deleted) workspace and domain link, canonical remediation
// linkage (or explicit null), registry-owned initial state, deduplication against an
// open case for the same source, source finding/scan linkage, a creation
// timestamp, an append-only `case_created` event, and tenant integrity. Pure of
// side effects beyond the two writes. Returns { ok, created, case } or
// { ok:false, code }.
export async function createManagedCase(env, {
  workspace_id, domain_key, case_type, source_finding_type = null, source_finding_id = null,
  source_scan_id = null, domain = null, asset_ref = null, title = null, summary = null,
  severity = "medium", priority = null, evidence = null, recommended_actions = null, actor = {},
} = {}) {
  if (!workspace_id) return { ok: false, code: "workspace_required" };
  if (!isValidDomainKey(domain_key)) return { ok: false, code: "invalid_domain_key" };
  const entry = caseTypeEntry(case_type);
  if (!entry) return { ok: false, code: "invalid_case_type" };
  if (entry.domain_key !== domain_key) return { ok: false, code: "domain_case_type_mismatch" };

  // Active workspace (not soft-deleted).
  const ws = await env.cybermeters_db
    .prepare(`SELECT id FROM workspaces WHERE id = ? AND deleted_at IS NULL`)
    .bind(workspace_id).first().catch(() => null);
  if (!ws) return { ok: false, code: "workspace_inactive" };

  // If a domain is supplied it must be linked to this workspace (active).
  if (domain) {
    const link = await env.cybermeters_db
      .prepare(`SELECT d.id FROM domains d JOIN workspace_domains wd ON wd.domain_id = d.id
                JOIN workspaces w ON w.id = wd.workspace_id
                WHERE wd.workspace_id = ? AND d.domain = ? AND w.deleted_at IS NULL LIMIT 1`)
      .bind(workspace_id, domain).first().catch(() => null);
    if (!link) return { ok: false, code: "domain_ineligible" };
  }

  // Canonical remediation linkage (or explicit null).
  const remediation_id = source_finding_type
    ? (findingRemediation({ id: source_finding_type, finding_type: "finding" })?.remediation_id ?? null)
    : null;

  const findingKey = source_finding_id || source_finding_type || null;
  // Deduplicate against an OPEN case for the same source (non-terminal).
  if (findingKey) {
    const domainClause = domain ? "AND domain = ?" : "";
    const existing = await env.cybermeters_db
      .prepare(`SELECT * FROM managed_cases
                WHERE workspace_id = ? AND case_type = ? AND finding_id = ?
                  ${domainClause}
                  AND status NOT IN ('rejected','false_positive','closed_no_action','superseded','closed')
                LIMIT 1`)
      .bind(workspace_id, case_type, findingKey, ...(domain ? [domain] : []))
      .first().catch(() => null);
    if (existing) return { ok: true, created: false, case: existing };
  }

  const id = newManagedCaseId();
  const now = new Date().toISOString();
  // The registry owns the persisted starting state. Base/Brand cases begin at
  // `detected`; the backward-compatible ASM machine begins at `open`.
  const initialStatus = entry.initial_state || entry.states?.[0];
  if (!initialStatus || !entry.states.includes(initialStatus)) {
    return { ok: false, code: "invalid_initial_state" };
  }
  const row = {
    id, workspace_id, case_type, domain_key, domain, finding_id: findingKey,
    source_finding_type, source_scan_id, remediation_id, asset_ref,
    title, summary, severity: severity || "medium", priority,
    status: initialStatus, evidence_json: evidence ? JSON.stringify(evidence) : null,
    recommended_actions_json: recommended_actions
      ? JSON.stringify(recommended_actions)
      : null,
    created_at: now, updated_at: now,
  };
  // INSERT OR IGNORE closes the read→insert race against the existing partial
  // unique index. Only the winning writer appends case_created.
  const inserted = await env.cybermeters_db
    .prepare(`INSERT OR IGNORE INTO managed_cases
      (id, workspace_id, case_type, domain_key, domain, finding_id, source_finding_type,
       source_scan_id, remediation_id, asset_ref, title, summary, severity, priority,
       status, evidence_json, recommended_actions_json, created_by, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(id, workspace_id, case_type, domain_key, domain, findingKey, source_finding_type,
      source_scan_id, remediation_id, asset_ref, title, summary, row.severity, priority,
      initialStatus, row.evidence_json, row.recommended_actions_json,
      actor.actor_id || "system", now, now)
    .run();
  if ((inserted?.meta?.changes ?? 1) === 0) {
    const domainClause = domain ? "AND domain = ?" : "";
    const existing = findingKey
      ? await env.cybermeters_db
        .prepare(`SELECT * FROM managed_cases
                  WHERE workspace_id = ? AND case_type = ? AND finding_id = ?
                    ${domainClause}
                    AND status NOT IN ('rejected','false_positive','closed_no_action','superseded','closed')
                  LIMIT 1`)
        .bind(workspace_id, case_type, findingKey, ...(domain ? [domain] : []))
        .first().catch(() => null)
      : null;
    return existing
      ? { ok: true, created: false, case: existing }
      : { ok: false, code: "case_insert_conflict" };
  }
  // Append-only case_created event (canonical taxonomy).
  await env.cybermeters_db
    .prepare(`INSERT INTO managed_case_events
      (id, case_id, workspace_id, actor_type, actor_id, from_status, to_status, action, detail_json, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'case_created', ?, datetime('now'))`)
    .bind(newCaseEventId(), id, workspace_id, actor.actor_type || "system", actor.actor_id || null,
      null, initialStatus,
      JSON.stringify(buildCaseEventDetail("case_created", { domain_key, case_type, source_finding_type, source_scan_id, remediation_id })))
    .run();
  return { ok: true, created: true, case: row };
}
