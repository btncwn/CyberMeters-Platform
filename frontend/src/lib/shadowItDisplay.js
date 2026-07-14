// Shared presentation for the Shadow IT approved inventory. Maps a server-owned
// classification / monitoring status to a display label + tone. The frontend
// NEVER decides which classification is valid or which actions are allowed —
// those come from the backend classification service; screens only display the
// state and POST an action the server validates. No invented states.

// Classification labels (must match backend SHADOW_IT_CLASSIFICATIONS).
export const CLASSIFICATION_META = {
  unreviewed:    { label: 'Unreviewed',    tone: 'slate'  },
  approved:      { label: 'Approved',      tone: 'green'  },
  rejected:      { label: 'Rejected',      tone: 'red'    },
  exception:     { label: 'Exception',     tone: 'amber'  },
  unknown_owner: { label: 'Unknown owner', tone: 'amber'  },
  retired:       { label: 'Retired',       tone: 'slate'  },
}

// Monitoring status labels (must match backend monitoring_status values).
export const MONITORING_META = {
  observed:            { label: 'Observed',            tone: 'blue'  },
  no_longer_observed:  { label: 'No longer observed',  tone: 'slate' },
  reappeared:          { label: 'Reappeared',          tone: 'red'   },
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
export function toneClass(tone) {
  return TONE_CLASS[tone] || TONE_CLASS.slate
}

// Honest reminders shown in the UI.
export const SHADOW_IT_SCOPE_NOTE =
  'Externally observed technology only — no internal-network, endpoint, CASB or EDR visibility. Classification is your decision: approved is not a security guarantee, and rejected is not removal.'
