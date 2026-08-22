// BL-1 canonical first-observation copy. MUST stay byte-identical to
// SHADOW_IT_FIRST_OBSERVATION_LABEL in workers/scan-api/src/engines/shadow-it-inventory.js
// — validator-pinned on both sides. Observation is not a verdict: the words
// `unauthorised`/`unapproved`/`malicious` are forbidden here.
export const SHADOW_IT_FIRST_OBSERVATION_LABEL = "Newly observed technology — not yet reviewed";

// Shared presentation for the Shadow IT approved inventory. Maps a server-owned
// classification / monitoring status to a display label + tone. The frontend
// NEVER decides which classification is valid or which actions are allowed —
// those come from the backend classification service; screens only display the
// state and POST an action the server validates. No invented states.

// Classification labels (must match backend SHADOW_IT_CLASSIFICATIONS — the
// customer decision). Ownership is a SEPARATE server-derived dimension below.
export const CLASSIFICATION_META = {
  // "Not yet classified" — never "unapproved"/"unauthorised": absence of a
  // customer decision (or of an approved-inventory comparison) is not a verdict.
  unreviewed:    { label: 'Not yet classified', tone: 'slate' },
  approved:      { label: 'Approved',      tone: 'green'  },
  rejected:      { label: 'Rejected',      tone: 'red'    },
  exception:     { label: 'Exception',     tone: 'amber'  },
  retired:       { label: 'Retired',       tone: 'slate'  },
}

// Server-derived ownership status (must match backend SHADOW_IT_OWNERSHIP_STATUSES).
export const OWNERSHIP_META = {
  known:   { label: 'Owned',         tone: 'green' },
  partial: { label: 'Partial owner', tone: 'amber' },
  missing: { label: 'Owner missing', tone: 'red'   },
}

// Monitoring status labels (must match backend monitoring_status values).
export const MONITORING_META = {
  observed:            { label: 'Observed',            tone: 'blue'  },
  no_longer_observed:  { label: 'No longer observed',  tone: 'slate' },
  reappeared:          { label: 'Reappeared',          tone: 'red'   },
}

// Managed onboarding lifecycle (must match backend `onboarding_status`, which the
// classification service sets from begin_onboarding / mark_onboarded only).
export const ONBOARDING_META = {
  in_progress: { label: 'Onboarding in progress', tone: 'blue'  },
  onboarded:   { label: 'Onboarded',              tone: 'green' },
}

// Managed removal lifecycle. `removal_status` is what the CUSTOMER asserted;
// `removal_verified` is what CyberMeters could observe about that assertion.
//
// ── PERSISTED DOMAIN (backend, legacy-capable) ──────────────────────────────
// `database/migrations/084-shadow-it-monitoring.sql:19-22` declares FOUR values:
//
//     null | verified | contradicted | unverified
//
// and stores them in an UNCONSTRAINED `TEXT` column. There is no CHECK
// constraint and no cleanup migration, so a legacy or future row may carry
// `verified` — or a value outside that list entirely. The evaluation pass in
// `shadow-it-inventory.js` BEGINS from the persisted value and only
// conditionally overwrites it.
//
// ── SERIALIZER BOUNDARY (measured, not assumed) ─────────────────────────────
// What is STORED is not always what ARRIVES. The single serializer behind every
// read path — `shadowItItemToApi`, used by the list (`:1078`), the single-item
// read (`:1082`) and the action result (`:1005`) — reads at
// `workers/scan-api/src/engines/shadow-it-inventory.js:1043`:
//
//     removal_verified: row.removal_verified || null
//
// `||` is falsy-normalizing, not a pass-through. So:
//
//   * a stored EMPTY STRING is normalized to `null` before this module sees it —
//     it never arrives as `''`;
//   * every NON-EMPTY string arrives unchanged.
//
// The values demonstrated at that boundary by execution are listed below. No
// claim is made about any value outside that exercised set.
//
// CORRECTION HISTORY (F-54). Two earlier revisions of this file were wrong in
// opposite directions, and both are corrected here:
//   * too NARROW — claimed the domain was only `contradicted | unverified | null`
//     and that no `verified` value existed. Independent verification reproduced
//     a schema-valid `verified` reaching the serializer.
//   * too WIDE — claimed the serializer passed the stored value "straight
//     through", which mischaracterised the empty string. The measured expression
//     normalizes it to `null`.
// The rendering below never changed under either correction: it was already
// fail-closed against every one of these inputs.
//
// ── PRESENTATION CONTRACT (this module — fail-closed, independent) ──────────
// Whatever value arrives, this module renders exactly one of two things:
//
//   * `contradicted`  -> the loud continuing-observation contradiction;
//   * anything else   -> the CUSTOMER's assertion, and when
//                        `removal_status === 'removed'` it is stated explicitly
//                        as not verified by CyberMeters.
//
// A stored `verified` is therefore never promoted into customer-facing
// confirmation. CyberMeters does not certify removal: disappearance from
// external observation does not prove it. Whether any production row currently
// holds `verified` is NOT MEASURED — absence must not be inferred.

// The domain exactly as DECLARED by migration 084. The column is unconstrained,
// so this is the declared set and NOT an exhaustive guarantee — treat any input
// as possible and rely on the fail-closed contract above, never on this list.
export const REMOVAL_VERIFIED_DECLARED_DOMAIN = Object.freeze([
  null, 'verified', 'contradicted', 'unverified',
])

// ── The measured serializer boundary ────────────────────────────────────────
// These two lists are not prose. `scripts/validate-f47-shadow-it-ui-actions-
// mutations.js` executes the REAL `shadowItItemToApi` over a stored row for each
// value below and fails if the observed behaviour disagrees, so the claim in this
// file is checked against the actual expression rather than trusted.
//
// Stored values DEMONSTRATED to be normalized to `null` by `|| null`. This is the
// exercised falsy set for a TEXT column; it is not a claim that no other falsy
// value exists.
export const REMOVAL_VERIFIED_NORMALIZED_TO_NULL = Object.freeze([''])

// Stored values DEMONSTRATED to arrive unchanged. Every entry is non-empty, and
// the claim extends to exactly these values — not to "any value".
export const REMOVAL_VERIFIED_PASSES_THROUGH = Object.freeze([
  'verified', 'unverified', 'contradicted', 'CONFIRMED', 'verification_grade_a', 'true',
])

// The single value that may render the loud contradiction. Every other value —
// declared, legacy or unknown — is presentation-equivalent to "unverified".
export const REMOVAL_VERIFIED_CONTRADICTED = 'contradicted'

export const REMOVAL_META = {
  in_progress: { label: 'Removal in progress', tone: 'blue' },
  removed:     { label: 'Marked removed',      tone: 'slate' },
}

export const TONE_CLASS = {
  slate: 'bg-slate-50 text-slate-600 border-slate-200',
  blue:  'bg-blue-50 text-blue-700 border-blue-200',
  green: 'bg-green-50 text-green-700 border-green-200',
  amber: 'bg-amber-50 text-amber-700 border-amber-200',
  red:   'bg-red-50 text-red-700 border-red-200',
}

const humanize = (s) => s ? String(s).replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()) : '—'

export function classificationMeta(c) {
  return CLASSIFICATION_META[c] || { label: humanize(c), tone: 'slate' }
}
export function monitoringMeta(s) {
  return MONITORING_META[s] || { label: humanize(s), tone: 'slate' }
}
export function ownershipMeta(s) {
  return OWNERSHIP_META[s] || { label: humanize(s), tone: 'slate' }
}
export function toneClass(tone) {
  return TONE_CLASS[tone] || TONE_CLASS.slate
}

export function onboardingMeta(s) {
  return s ? (ONBOARDING_META[s] || { label: humanize(s), tone: 'slate' }) : null
}

// Removal is the one place a customer assertion and an external observation can
// disagree, so the two are rendered as ONE honest sentence rather than a bare
// status. `contradicted` means the technology is STILL OBSERVED after the
// customer said it was removed — that is louder than the assertion, never
// quieter.
//
// Every other value takes the same path by design, and that is the fail-closed
// property: `unverified` (the ordinary case), `null` (no signal — absence is not
// evidence), a legacy `verified`, and any unknown future value all render the
// customer's assertion without confirmation. The test for a value we do NOT
// recognise is deliberately the same as for one we do, so a new backend value
// can never arrive here and be read as certification by default.
export function removalMeta(status, verified) {
  if (!status) return null
  const base = REMOVAL_META[status] || { label: humanize(status), tone: 'slate' }
  if (verified === 'contradicted') {
    return { label: `${base.label} — still observed, contradicts the assertion`, tone: 'red' }
  }
  if (status === 'removed') {
    return { label: `${base.label} — your assertion, not verified by CyberMeters`, tone: 'amber' }
  }
  return base
}

// Honest reminders shown in the UI.
export const SHADOW_IT_SCOPE_NOTE =
  'Externally observed technology only — no internal-network, endpoint, CASB or EDR visibility. Classification is your decision: approved is not a security guarantee, and rejected is not removal.'
