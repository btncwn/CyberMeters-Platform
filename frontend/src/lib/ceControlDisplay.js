// Presentation for the Cyber Essentials EXTERNAL-EVIDENCE control lifecycle (mig 090).
//
// This is NOT the questionnaire. The CE page already renders a self-assessment merge whose
// vocabulary is self_attested_only / externally_corroborated / contradicted_by_scan /
// externally_confirmed_gap — that is what the CUSTOMER said, reconciled with what we saw.
// The records here are the other half: what CyberMeters observed from outside, with no
// answer involved at all (the evaluator calls buildCyberEssentialsReadiness directly and
// never reads the questionnaire, so a form edit can never mint one of these).
//
// Keeping the two vocabularies visually distinct is the point. Merging them into one
// "control status" is exactly how a self-attested answer would start looking verified.
//
// THERE IS NO `verified` STATE, HERE OR IN THE BACKEND. The strongest thing this product
// can say about a CE control is that the externally observable part of it looks aligned.
// CyberMeters does not certify Cyber Essentials.

export const READINESS_META = {
  ready: {
    label: 'Externally aligned',
    tone: 'green',
    // Deliberately not "Passing" or "Compliant": we saw the outside of a partial control.
    hint: 'The externally observable part of this control looks aligned. Not a pass, and not certification.',
  },
  not_ready: {
    label: 'Gap observed',
    tone: 'red',
    hint: 'External evidence shows a gap against this control.',
  },
  unknown: {
    label: 'Not determined',
    tone: 'slate',
    hint: 'Some signals for this control could not be observed on the latest scan. Not a pass and not a gap.',
  },
  not_externally_assessable: {
    label: 'Not visible externally',
    tone: 'slate',
    hint: 'Nothing about this control can be observed from outside your network. Its absence from the findings is not evidence that it passes.',
  },
}

export const COVERAGE_META = {
  partial: { label: 'Partial external coverage', tone: 'amber' },
  none:    { label: 'No external coverage',      tone: 'slate' },
}

export const TONE_CLASS = {
  green: 'bg-emerald-50 text-emerald-700 border-emerald-100',
  amber: 'bg-amber-50 text-amber-700 border-amber-100',
  red:   'bg-red-50 text-red-700 border-red-100',
  slate: 'bg-gray-100 text-gray-600 border-gray-200',
}
export const toneClass = (tone) => TONE_CLASS[tone] || TONE_CLASS.slate

// An unrecognised state falls back to neutral, never to green: a value this build does not
// know is not evidence that a control is fine.
export const readinessMeta = (s) => READINESS_META[s] || { label: s || 'Unknown', tone: 'slate', hint: 'State not recognised by this version.' }
export const coverageMeta  = (c) => COVERAGE_META[c]  || { label: 'Coverage unknown', tone: 'slate' }

export const controlLabel = (item) =>
  item?.control_label || String(item?.control_key || '').replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase())

// Shown above the section so the two vocabularies can never be read as one list.
export const EXTERNAL_SECTION_NOTE =
  'What CyberMeters could observe from outside, without your answers. This is indicative only — '
  + 'coverage is partial by nature, and controls marked "Not visible externally" cannot be checked this way at all. '
  + 'CyberMeters does not certify Cyber Essentials.'
