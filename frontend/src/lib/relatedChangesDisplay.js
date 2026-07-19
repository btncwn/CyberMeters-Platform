// Presentation-only descriptors for the workspace "Related Changes" surface
// (M6 Phase B1). This is the ONE place the frontend maps a backend-owned
// related-change field (rule_id, direction, customer_state, completeness,
// confidence) to a display label and a calm, neutral tone.
//
// Hard rules this file exists to keep:
//   1. The frontend NEVER derives a security verdict, severity or risk level.
//      It renders exactly what the backend returns. These maps translate an
//      enum to human wording — they do not compute meaning.
//   2. Vocabulary lock. A related change is a deterministic correlation of
//      independent observations that CHANGED TOGETHER. It is NOT an attack
//      chain, compromise, incident, anomaly or threat. Change is not
//      compromise. Every string below stays inside the approved vocabulary:
//      "related changes", "change cluster", "observed in the same period",
//      "may be connected", "confirm whether planned", "requires verification".
//   3. Unknown enum values fall back to a neutral, honest label derived from
//      the raw string — never a fabricated or optimistic status.

// ── Tone classes (shared visual grammar with caseDisplay) ────────────────────
// Colour is presentation of a backend-owned state, not a derived severity.
export const TONE_CLASS = {
  slate: 'bg-slate-50 text-slate-600 border-slate-200',
  blue: 'bg-blue-50 text-blue-700 border-blue-200',
  indigo: 'bg-indigo-50 text-indigo-700 border-indigo-200',
  amber: 'bg-amber-50 text-amber-700 border-amber-200',
  green: 'bg-green-50 text-green-700 border-green-200',
  red: 'bg-red-50 text-red-700 border-red-200',
};

/** @param {string} tone */
export function toneClass(tone) {
  return TONE_CLASS[tone] || TONE_CLASS.slate;
}

// ── Rule labels (presentation only — NOT a source of truth for meaning) ──────
// The backend owns what each rule means; these are human titles for display.
export const RULE_LABELS = {
  new_host_with_cert: 'New host with a new or changed certificate',
  new_host_with_identity: 'New host with a login or identity surface',
  identity_with_cert: 'Login or admin surface with a certificate change',
  email_config_with_host_or_cert: 'Email-authentication change with a new host or certificate',
  new_sender_with_email_config: 'New sending source with an email-authentication change',
  shadow_it_with_host_or_cert: 'Unapproved technology with a new host or certificate',
};

/**
 * Human title for a rule. Unknown rule ids fall back to a readable form of the
 * raw key rather than an invented label.
 * @param {string | null | undefined} ruleId
 * @returns {string}
 */
export function ruleLabel(ruleId) {
  if (!ruleId) return 'Related change';
  if (RULE_LABELS[ruleId]) return RULE_LABELS[ruleId];
  const words = String(ruleId).replace(/_/g, ' ').trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : 'Related change';
}

// ── Direction (materialisation) — a neutral tag, never a threat level ────────
export const DIRECTION_META = {
  appeared: { label: 'Appeared', tone: 'blue' },
  changed: { label: 'Changed', tone: 'blue' },
  degraded: { label: 'Degraded', tone: 'amber' },
};

/**
 * @param {string | null | undefined} direction
 * @returns {{ label: string, tone: string }}
 */
export function directionMeta(direction) {
  if (direction && DIRECTION_META[direction]) return DIRECTION_META[direction];
  const raw = direction ? String(direction) : 'unknown';
  const label = raw.charAt(0).toUpperCase() + raw.slice(1);
  return { label, tone: 'slate' };
}

// ── Customer state — the review status the customer sets ─────────────────────
// `new` is system-only (it means "not yet reviewed"); the customer can move a
// cluster to expected / unrelated / unexpected_confirmed but never back to new.
export const CUSTOMER_STATE_META = {
  new: {
    label: 'Needs review',
    tone: 'amber',
    description: 'Observed but not yet reviewed. Confirm whether these changes were planned.',
  },
  expected: {
    label: 'Expected — planned',
    tone: 'green',
    description: 'You confirmed these changes were planned.',
  },
  unrelated: {
    label: 'Not related',
    tone: 'slate',
    description: 'You confirmed these changes are not connected.',
  },
  unexpected_confirmed: {
    label: 'Confirmed unexpected',
    tone: 'red',
    description: 'You confirmed these changes were not planned. This requires verification.',
  },
};

/**
 * @param {string | null | undefined} state
 * @returns {{ label: string, tone: string, description: string }}
 */
export function customerStateMeta(state) {
  if (state && CUSTOMER_STATE_META[state]) return CUSTOMER_STATE_META[state];
  const raw = state ? String(state) : 'unknown';
  const label = raw.replace(/_/g, ' ');
  return { label: label.charAt(0).toUpperCase() + label.slice(1), tone: 'slate', description: '' };
}

// The feedback actions a customer may take. `new` is intentionally absent — it
// is a system state, not something a customer can assert.
export const FEEDBACK_OPTIONS = [
  { state: 'expected', label: 'Mark expected (planned)' },
  { state: 'unrelated', label: 'Mark unrelated' },
  { state: 'unexpected_confirmed', label: 'Confirm unexpected' },
];

// The filter options for the list view — includes the system `new` state so a
// customer can find the clusters still awaiting review.
export const CUSTOMER_STATE_FILTERS = ['new', 'expected', 'unrelated', 'unexpected_confirmed'];

// ── Completeness ─────────────────────────────────────────────────────────────
export const COMPLETENESS_META = {
  complete: { label: 'Complete evidence', tone: 'slate' },
  partial: { label: 'Partial evidence', tone: 'amber' },
};

/**
 * @param {string | null | undefined} completeness
 * @returns {{ label: string, tone: string }}
 */
export function completenessMeta(completeness) {
  if (completeness && COMPLETENESS_META[completeness]) return COMPLETENESS_META[completeness];
  return { label: 'Evidence completeness unknown', tone: 'slate' };
}

// ── Confidence ───────────────────────────────────────────────────────────────
// Confidence is always the literal string "correlated" — a deterministic match,
// never a probability. Render it as such; never as a percentage.
/**
 * @param {string | null | undefined} confidence
 * @returns {string}
 */
export function confidenceLabel(confidence) {
  if (confidence === 'correlated') return 'Correlated (deterministic)';
  return confidence ? String(confidence) : 'Correlated (deterministic)';
}

// ── Signal-family count wording (explanation first, number second) ───────────
/**
 * @param {number | null | undefined} count
 * @returns {string}
 */
export function signalFamilyText(count) {
  const n = Number.isFinite(count) ? Number(count) : 0;
  return `${n} independent signal ${n === 1 ? 'family' : 'families'}`;
}

/**
 * @param {number | null | undefined} count
 * @returns {string}
 */
export function producerText(count) {
  const n = Number.isFinite(count) ? Number(count) : 0;
  return `${n} independent ${n === 1 ? 'producer' : 'producers'}`;
}

// ── Evidence producer family (presentation only) ─────────────────────────────
export const PRODUCER_FAMILY_LABELS = {
  host: 'Host / attack surface',
  cert: 'Certificate',
  certificate: 'Certificate',
  identity: 'Login / identity surface',
  email_config: 'Email authentication',
  sender: 'Sending source',
  shadow_it: 'Unapproved technology',
};

/**
 * @param {string | null | undefined} family
 * @returns {string}
 */
export function producerFamilyLabel(family) {
  if (!family) return 'Observation';
  if (PRODUCER_FAMILY_LABELS[family]) return PRODUCER_FAMILY_LABELS[family];
  const words = String(family).replace(/_/g, ' ').trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : 'Observation';
}

/**
 * Empty-state copy. Distinguishes three honest situations so an empty list never
 * implies a clean verdict when correlation simply has not run yet:
 *   (a) insufficient history / not yet assessed  — fewer than two complete assessments
 *   (b) incomplete/failed correlation            — latest assessment did not complete
 *   (c) assessed, no related changes             — complete history, nothing correlated
 * Wording stays inside the vocabulary lock: no attack, incident, anomaly, unusualness,
 * AI, or "healthy / secure / all clear" verdict language — a related change is a
 * deterministic correlation, and its absence is a factual "none observed", never a
 * security verdict.
 * @param {{complete_scans?: number, correlation_possible?: boolean, latest_scan_quality?: string|null} | null} assessment
 * @param {boolean} hasFilter
 * @returns {{ title: string, description: string }}
 */
export function emptyStateFor(assessment, hasFilter) {
  if (hasFilter) {
    return {
      title: 'No related changes with this review status.',
      description: 'No change clusters match the selected review state. Clear the filter to see all related changes.',
    };
  }
  const completeScans = Number(assessment?.complete_scans ?? 0);
  const possible = Boolean(assessment?.correlation_possible);
  const latestQuality = assessment?.latest_scan_quality ?? null;
  // (a) insufficient history / not yet assessed
  if (!possible) {
    if (completeScans <= 0) {
      return {
        title: 'Not yet assessed',
        description: 'Related changes are found by comparing your completed assessments. They will appear here once your assessments have run.',
      };
    }
    return {
      title: 'Not enough history yet',
      description: 'Related changes compare two or more completed assessments of the same domain. Run another assessment to establish a comparison.',
    };
  }
  // (b) incomplete / failed correlation for the latest assessment
  if (latestQuality && latestQuality !== 'complete') {
    return {
      title: 'Latest assessment was incomplete',
      description: 'The most recent assessment did not complete, so related changes for it are not available yet. They are reviewed after the next complete assessment.',
    };
  }
  // (c) assessed, no related changes
  return {
    title: 'No related changes observed in this period.',
    description: 'When two or more independent signal families change together on the same domain in the same period, the change cluster appears here for you to confirm whether it was planned.',
  };
}

// The single honesty note shown on every related-changes surface. Kept here so
// the wording is identical everywhere and stays inside the vocabulary lock.
export const HONESTY_NOTE =
  'Related changes are correlated observations that may be connected. Change is not compromise — confirm whether each was planned.';

/**
 * Format an ISO timestamp as a short date. Returns an em dash for empty values
 * so a missing timestamp never renders as an invalid date.
 * @param {string | null | undefined} iso
 * @returns {string}
 */
export function shortDate(iso) {
  if (!iso) return '—';
  return String(iso).slice(0, 10);
}
