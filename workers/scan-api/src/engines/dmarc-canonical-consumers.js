// ── Canonical DMARC consumer mapping (ADR-003 §7 / §11) ──────────────────────
//
// ONE source of truth for how backend truth consumers (scoring, Cyber MOT,
// email-intel) translate the canonical `dmarc_state.enforcement_level` produced
// by deriveDmarcState() into their own verdicts. Consumers import from here
// instead of independently re-deriving enforcement from raw p / pct / sp /
// present / valid (ADR-003 binding rule: no consumer re-derives enforcement).
//
// This module holds NO derivation logic — it only classifies an already-derived
// canonical level. The level itself comes exclusively from deriveDmarcState().
//
// A level absent from these maps is a fail-closed signal, not silently healthy.

import { DMARC_ENFORCEMENT_LEVELS } from "./dmarc-state.js";

// Scoring is score-neutral for the two "we made no observation" levels — they
// must receive neither penalty nor credit (ADR-003 §11). Everything else is a
// real observed state and is scored on its own merits.
export const DMARC_SCORE_NEUTRAL_LEVELS = Object.freeze(
  new Set(["not_yet_assessed", "not_observed"])
);

export function isDmarcScoreNeutral(level) {
  return DMARC_SCORE_NEUTRAL_LEVELS.has(level);
}

// Cyber MOT contribution per ADR-003 §7 bridge. `skip` = defer to the domain's
// normal module-presence/finding logic (used for not_yet_assessed, which the
// module-assessed checks already handle honestly). `evidence_insufficient` =
// the DMARC lookup was attempted but not obtained (never healthy off a
// non-observation). The enforcing-but-not-reject and invalid/monitoring/no_record
// levels are observed weaknesses → issue_detected. Only reject_enforced is
// assessed_healthy.
export const DMARC_MOT_CONTRIBUTION = Object.freeze({
  not_yet_assessed:    "skip",
  not_observed:        "evidence_insufficient",
  no_record:           "issue_detected",
  invalid_record:      "issue_detected",
  monitoring:          "issue_detected",
  partial_quarantine:  "issue_detected",
  quarantine_enforced: "issue_detected",
  partial_reject:      "issue_detected",
  reject_enforced:     "assessed_healthy",
});

// email-intel display status enum (FULLY_PROTECTED / PARTIAL_PROTECTED /
// REPORTING_ONLY / MISSING / ERROR) mapped from the canonical level. Backend
// truth: the missing/score finding is gated on the canonical level (see
// isDmarcScoreNeutral), so a not_observed domain never emits a "missing DMARC"
// finding or penalty even though its display status has no dedicated enum value
// yet (an honest frontend status is deferred to the excluded frontend PR).
export const DMARC_INTEL_STATUS = Object.freeze({
  not_yet_assessed:    "MISSING",
  not_observed:        "MISSING",
  no_record:           "MISSING",
  invalid_record:      "ERROR",
  monitoring:          "REPORTING_ONLY",
  partial_quarantine:  "PARTIAL_PROTECTED",
  quarantine_enforced: "PARTIAL_PROTECTED",
  partial_reject:      "PARTIAL_PROTECTED",
  reject_enforced:     "FULLY_PROTECTED",
});

// CI/self-check: every canonical enforcement level must have a consumer mapping,
// so a future level added to the model cannot silently fall through to healthy.
export function assertConsumerMappingsComplete() {
  const missing = [];
  for (const level of DMARC_ENFORCEMENT_LEVELS) {
    if (!(level in DMARC_MOT_CONTRIBUTION)) missing.push(`mot:${level}`);
    if (!(level in DMARC_INTEL_STATUS)) missing.push(`intel:${level}`);
  }
  return missing;
}
