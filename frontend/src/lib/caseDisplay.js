// Shared canonical-phase presentation for managed cases across all eight Cyber
// MOT domains. This is the ONE place the frontend maps a case's canonical phase
// to a display label/tone, so cross-domain queues render consistently and no
// screen re-invents a divergent state map. The frontend NEVER decides legal
// transitions — those are enforced by the backend universal validator
// (canTransitionCase); screens only display the phase and send a target status
// the server validates.

// ── The verification vocabulary rule (canonical, cross-domain) ───────────────
// `verified` is ONE canonical phase but TWO different customer facts, and calling both
// "Verified" is the difference between a claim we can stand behind and one we cannot:
//
//   verification_support 'automated' → CyberMeters re-observed the fix itself
//                                      (registry method dns_recheck / https_recheck /
//                                      receiver_reports / …). "Verified by CyberMeters".
//   verification_support 'manual'    → the registry says the product CANNOT observe this
//                                      fix, so the case rests on the customer's word.
//                                      NEVER "Verified", NEVER "Confirmed".
//
// The words "Verified" and "Confirmed" are reserved for what CyberMeters itself observed.
// This is CLAUDE.md's standing rule read literally — "Customer assertion and CyberMeters
// external verification are different states", and "Do not mark states 'Verified' … unless
// evidence supports the exact label". The tone matters as much as the word: green reads as
// "settled" at a glance, so an attestation is deliberately not green.
//
// The frontend does not DERIVE this — `verification_support` is computed by the backend
// from the canonical remediation registry and arrives on the case.
export const ATTESTED_LABEL = 'Attested by customer — not externally verifiable';

// Canonical phases (must match managed-case-model.js CANONICAL_CASE_STATES +
// CANONICAL_TERMINAL_STATES). Labels are presentation only.
export const CANONICAL_PHASE_META = {
  detected:              { label: 'Detected',              tone: 'slate'  },
  triaged:               { label: 'Triaged',               tone: 'blue'   },
  assigned:              { label: 'Assigned',              tone: 'blue'   },
  approved:              { label: 'Approved',              tone: 'indigo' },
  action_in_progress:    { label: 'Action in progress',    tone: 'amber'  },
  awaiting_verification: { label: 'Awaiting verification', tone: 'amber'  },
  // NOT a usable label on its own — `verified` is support-dependent, so this entry is the
  // honest floor (the weaker of the two claims) for any consumer that reads the map
  // directly. Go through phaseMeta(phase, verification_support) to get the real one.
  verified:              { label: ATTESTED_LABEL,          tone: 'blue'   },
  monitoring:            { label: 'Monitoring',            tone: 'green'  },
  reopened:              { label: 'Reopened',              tone: 'red'    },
  // Terminal / exceptional — none of these is "Verified".
  rejected:              { label: 'Rejected',              tone: 'slate'  },
  accepted_risk:         { label: 'Accepted risk',         tone: 'slate'  },
  false_positive:        { label: 'False positive',        tone: 'slate'  },
  closed_no_action:      { label: 'Closed (no action)',    tone: 'slate'  },
  superseded:            { label: 'Superseded',            tone: 'slate'  },
};

export const TONE_CLASS = {
  slate:  'bg-slate-50 text-slate-600 border-slate-200',
  blue:   'bg-blue-50 text-blue-700 border-blue-200',
  indigo: 'bg-indigo-50 text-indigo-700 border-indigo-200',
  amber:  'bg-amber-50 text-amber-700 border-amber-200',
  green:  'bg-green-50 text-green-700 border-green-200',
  red:    'bg-red-50 text-red-700 border-red-200',
};

// Present a canonical phase. Unknown/missing phase falls back to a neutral label
// derived from the raw string — never a fabricated status.
//
// `verificationSupport` is the case's backend-computed support. It only ever changes the
// `verified` phase, and it FAILS CLOSED: a case that reaches `verified` without telling us
// how it may be verified is presented as an attestation, never as CyberMeters' own
// observation. Guessing "automated" from silence is exactly the optimistic-healthy default
// the platform forbids; the honest fallback is the weaker claim.
export function phaseMeta(phase, verificationSupport = null) {
  if (phase === 'verified') {
    return verificationSupport === 'automated'
      ? { label: 'Verified by CyberMeters', tone: 'green' }
      : { label: ATTESTED_LABEL, tone: 'blue' };
  }
  if (phase && CANONICAL_PHASE_META[phase]) return CANONICAL_PHASE_META[phase];
  const label = phase ? String(phase).replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()) : 'Unknown';
  return { label, tone: 'slate' };
}

export function phaseClass(phase, verificationSupport = null) {
  return TONE_CLASS[phaseMeta(phase, verificationSupport).tone] || TONE_CLASS.slate;
}

// The eight canonical domain-key display names (for grouping the cross-domain
// queue). Keys must match the backend CANONICAL_DOMAIN_KEYS.
export const DOMAIN_KEY_LABELS = {
  email_protection: 'Email Protection',
  brand_protection: 'Brand Protection',
  attack_surface: 'Attack Surface',
  certificates_trust: 'Certificates & Trust',
  cyber_essentials_readiness: 'Cyber Essentials Readiness',
  website_security: 'Website Security',
  identity_exposure: 'Identity Exposure',
  shadow_it_unmanaged_technology: 'Shadow IT & Unmanaged Technology',
};

export function domainKeyLabel(key) {
  return DOMAIN_KEY_LABELS[key] || (key ? String(key).replace(/_/g, ' ') : 'Unassigned');
}
