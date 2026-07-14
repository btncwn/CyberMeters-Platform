// Shared canonical-phase presentation for managed cases across all eight Cyber
// MOT domains. This is the ONE place the frontend maps a case's canonical phase
// to a display label/tone, so cross-domain queues render consistently and no
// screen re-invents a divergent state map. The frontend NEVER decides legal
// transitions — those are enforced by the backend universal validator
// (canTransitionCase); screens only display the phase and send a target status
// the server validates.

// Canonical phases (must match managed-case-model.js CANONICAL_CASE_STATES +
// CANONICAL_TERMINAL_STATES). Labels are presentation only.
export const CANONICAL_PHASE_META = {
  detected:              { label: 'Detected',              tone: 'slate'  },
  triaged:               { label: 'Triaged',               tone: 'blue'   },
  assigned:              { label: 'Assigned',              tone: 'blue'   },
  approved:              { label: 'Approved',              tone: 'indigo' },
  action_in_progress:    { label: 'Action in progress',    tone: 'amber'  },
  awaiting_verification: { label: 'Awaiting verification', tone: 'amber'  },
  verified:              { label: 'Verified',              tone: 'green'  },
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
export function phaseMeta(phase) {
  if (phase && CANONICAL_PHASE_META[phase]) return CANONICAL_PHASE_META[phase];
  const label = phase ? String(phase).replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()) : 'Unknown';
  return { label, tone: 'slate' };
}

export function phaseClass(phase) {
  return TONE_CLASS[phaseMeta(phase).tone] || TONE_CLASS.slate;
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
