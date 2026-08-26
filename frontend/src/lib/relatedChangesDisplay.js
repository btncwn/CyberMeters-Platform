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
// The cert half of a rule says "a certificate signal", never "a new or changed
// certificate": the rule's cert family also matches standing conditions
// (sensitive hostname in CT, expiring soon), so a more specific claim in the
// title could say more than the evidence. The exact observation is named per
// evidence row via EVENT_TYPE_LABELS below.
export const RULE_LABELS = {
  new_host_with_cert: 'New host with a certificate signal',
  new_host_with_identity: 'New host with a possible identity-facing hostname',
  identity_with_cert: 'Possible identity-facing hostname with a certificate signal',
  email_config_with_host_or_cert: 'Email-authentication change with a new host or a certificate signal',
  new_sender_with_email_config: 'New sending source with an email-authentication change',
  shadow_it_with_host_or_cert: 'Unapproved technology with a new host or a certificate signal',
};

// R1 P2 CLASS FIX: every map lookup in this file is OWN-property only. Plain
// objects inherit from Object.prototype, so an attacker-influenced or unknown
// key ('constructor', 'toString', '__proto__') would otherwise resolve truthy —
// leaking a link, or rendering a prototype object as a React child (measured:
// the '__proto__' family crashed the detail page through the label path).
/**
 * Human title for a rule. Unknown rule ids fall back to a readable form of the
 * raw key rather than an invented label.
 * @param {string | null | undefined} ruleId
 * @returns {string}
 */
export function ruleLabel(ruleId) {
  if (!ruleId) return 'Related change';
  if (Object.hasOwn(RULE_LABELS, ruleId)) return RULE_LABELS[ruleId];
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
  if (direction && Object.hasOwn(DIRECTION_META, direction)) return DIRECTION_META[direction];
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
  if (state && Object.hasOwn(CUSTOMER_STATE_META, state)) return CUSTOMER_STATE_META[state];
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
  if (completeness && Object.hasOwn(COMPLETENESS_META, completeness)) return COMPLETENESS_META[completeness];
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
  if (Object.hasOwn(PRODUCER_FAMILY_LABELS, family)) return PRODUCER_FAMILY_LABELS[family];
  const words = String(family).replace(/_/g, ' ').trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : 'Observation';
}

// ── Evidence event subtypes (presentation only) ──────────────────────────────
// Each label states exactly what the producer records — no more, no other — so
// the heading and the evidence tell the same story. A standing condition (e.g.
// a sensitive hostname observed in certificate-transparency logs) is never
// presented as a new or changed certificate. Internal enum values are never
// rendered raw.
export const EVENT_TYPE_LABELS = {
  // asset family (asset-inventory + exposed-service events)
  new_asset_discovered: 'New asset discovered',
  asset_reappeared: 'Asset reappeared',
  dns_ip_changed: 'DNS IP address changed',
  dns_cname_changed: 'DNS CNAME record changed',
  dns_redirect_changed: 'Redirect target changed',
  takeover_risk_detected: 'Takeover risk detected',
  wildcard_dns_detected: 'Wildcard DNS detected',
  exposed_service_detected: 'Exposed service detected',
  // email-authentication configuration
  email_spf_changed: 'SPF record changed',
  email_spf_authorization_changed: 'SPF authorised senders changed',
  email_dmarc_policy_changed: 'DMARC policy changed',
  email_dkim_changed: 'DKIM configuration changed',
  // certificate family
  certificate_new_detected: 'New certificate detected',
  certificate_new_san_detected: 'New certificate hostname detected',
  certificate_new_issuer_detected: 'Certificate issuer changed',
  certificate_growth_detected: 'Certificate hostname count grew',
  certificate_sensitive_host_detected: 'Sensitive hostname observed in certificate-transparency logs',
  certificate_expiring_soon: 'Certificate expiring soon',
  // other producers
  email_sender_new_source: 'New sending source observed',
  // Stored wire vocabulary stays identity_surface_observed (IC-1); display
  // projects the proposition honestly without rewriting historical rows.
  identity_surface_observed: 'Possible identity-facing hostname observed',
  brand_candidate_active_dns: 'Lookalike candidate resolving in DNS',
  brand_candidate_active_http: 'Lookalike candidate responding over HTTPS',
  brand_campaign_linked: 'Linked brand campaign observed',
  shadow_it_observed: 'Unapproved technology observed',
};

/**
 * Honest label for an evidence event subtype. Unknown subtypes fall back to a
 * readable form of the raw key rather than an invented claim; empty input
 * yields an empty string so callers can omit the line entirely.
 * @param {string | null | undefined} eventType
 * @returns {string}
 */
export function eventTypeLabel(eventType) {
  if (!eventType) return '';
  if (Object.hasOwn(EVENT_TYPE_LABELS, eventType)) return EVENT_TYPE_LABELS[eventType];
  const words = String(eventType).replace(/_/g, ' ').trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : '';
}

// Group-key separator: a control character that can never appear in the
// material fields, so joined keys cannot collide.
const GROUP_KEY_SEP = String.fromCharCode(0);

/**
 * Presentation-level collapse of identical repeated observations. Standing-
 * condition producers (pre-#172) appended the same evidence pointer once per
 * scan, so one condition could render as ~10 identical rows. Underlying
 * evidence records are never merged or discarded — this groups rows whose
 * every material field is identical and reports an honest repeat count with
 * first/last observed times.
 *
 * Material identity: producer family, source table, event subtype, the
 * rendered entity identity (entity_key, or the source_record_id it falls back
 * to), and evidence_ref when it carries meaning beyond the row pointer (e.g.
 * a brand candidate domain — for most producers evidence_ref simply repeats
 * source_record_id). Rows differing in ANY material field never collapse.
 * @param {Array<object> | null | undefined} evidence
 * @returns {Array<object>} groups in first-appearance order, each the first
 *   row plus { occurrence_count, first_observed_at, last_observed_at }
 */
export function groupEvidencePointers(evidence) {
  const groups = new Map();
  for (const e of evidence || []) {
    const identity = e?.entity_key || e?.source_record_id || '';
    const ref = e?.evidence_ref && e.evidence_ref !== e.source_record_id ? String(e.evidence_ref) : '';
    const key = [e?.producer_family ?? '', e?.source_table ?? '', e?.source_event_type ?? '', identity, ref].join(GROUP_KEY_SEP);
    const at = e?.observed_at || null;
    const g = groups.get(key);
    if (!g) {
      groups.set(key, { ...e, occurrence_count: 1, first_observed_at: at, last_observed_at: at });
    } else {
      g.occurrence_count += 1;
      if (at && (!g.first_observed_at || at < g.first_observed_at)) g.first_observed_at = at;
      if (at && (!g.last_observed_at || at > g.last_observed_at)) g.last_observed_at = at;
    }
  }
  return [...groups.values()];
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

// ── Item 12B CL-2: canonical customer surface per evidence producer family ──
// A deep link is offered ONLY where a canonical customer route already exists
// for the signal's family; every other source stays a NAMED, non-link pointer.
// Keys cover both the adapter's family strings and the persisted legacy
// aliases already present in evidence rows (host/sender/certificate).
export const EVIDENCE_SURFACE_ROUTES = Object.freeze({
  asset: '/exposure',
  host: '/exposure',
  cert: '/ws/certificates',
  certificate: '/ws/certificates',
  email_config: '/ws/email-protection',
  email_sender: '/ws/email-protection',
  sender: '/ws/email-protection',
  identity: '/ws/identity-assets',
  brand: '/ws/brand-monitoring',
  shadow_it: '/ws/shadow-it',
})

/**
 * @param {string | null | undefined} family
 * @returns {string | null} canonical route, or null when none exists (no link).
 */
export function evidenceSurfaceRoute(family) {
  // OWN-property lookup only (R1 P2): a plain object inherits from
  // Object.prototype, so an inherited name ('constructor', 'toString',
  // '__proto__') would otherwise resolve truthy and leak a link. Fail closed:
  // anything that is not an own key renders as a named, non-link pointer.
  return typeof family === 'string' && Object.hasOwn(EVIDENCE_SURFACE_ROUTES, family)
    ? EVIDENCE_SURFACE_ROUTES[family]
    : null
}

// ── Item 12B CL-1: correlation basis (12A frozen contract) ──────────────────
// correlation_basis: 'exact_host' (re-validated, producer supplies linkage_host)
// or 'legacy_domain_only' (earlier domain-only correlation, NOT re-validated).
// Absent or unknown values FAIL CLOSED to the weaker legacy claim — the
// re-validated wording may only ever come from an explicit 'exact_host'.
export function correlationBasisMeta(basis) {
  if (basis === 'exact_host') return { revalidated: true }
  return { revalidated: false }
}

/**
 * Display form of an evidence entity key: strips one known machine prefix
 * (host:/domain:/campaign:) and nothing else — never invents an entity.
 * @param {string | null | undefined} entityKey
 * @returns {string}
 */
export function entityHostLabel(entityKey) {
  const raw = entityKey ? String(entityKey) : ''
  const m = raw.match(/^(?:host|domain|campaign):(.+)$/)
  return m ? m[1] : raw
}

/**
 * The exact shared entity across ALL evidence rows, or null. The claim is
 * strict: every row must carry the identical raw entity_key and there must be
 * at least two rows — anything less is "do not name the same host".
 * @param {Array<{entity_key?: string}>} evidence
 * @returns {string | null}
 */
export function sharedEvidenceHost(evidence) {
  const keys = (evidence || []).map((e) => e?.entity_key).filter(Boolean)
  if (keys.length < 2) return null
  const first = keys[0]
  return keys.every((k) => k === first) ? entityHostLabel(first) : null
}

// The single honesty note shown on every related-changes surface. Kept here so
// the wording is identical everywhere and stays inside the vocabulary lock.
export const HONESTY_NOTE =
  'Related changes are correlated observations that may be connected. Change is not compromise — confirm whether each was planned.';

// Fallback for the backend's workspace-scope note (the API supplies the
// canonical `workspace_scope_note`; this renders only when a response predates
// that field). Related changes are correlated per WORKSPACE, so a cluster may
// affect a different domain in this workspace than whatever view it appears in.
export const WORKSPACE_SCOPE_NOTE =
  'This list is workspace-level: related changes are correlated across all domains in this workspace. Each entry names the domain it affects.';

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
