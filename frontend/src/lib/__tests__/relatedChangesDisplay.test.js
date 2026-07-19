import { describe, it, expect } from 'vitest'
import {
  ruleLabel,
  RULE_LABELS,
  directionMeta,
  customerStateMeta,
  CUSTOMER_STATE_META,
  completenessMeta,
  confidenceLabel,
  signalFamilyText,
  producerText,
  producerFamilyLabel,
  toneClass,
  TONE_CLASS,
  shortDate,
  FEEDBACK_OPTIONS,
  CUSTOMER_STATE_FILTERS,
  HONESTY_NOTE,
  emptyStateFor,
} from '../relatedChangesDisplay'

// The vocabulary lock is enforced by the backend + a CI validator; the frontend
// mirror keeps it out of every presentation string this module produces.
const FORBIDDEN = [
  'attack chain',
  'compromise',
  'malicious',
  'behavioural threat',
  'incident',
  'anomaly',
  'anomalous',
  'statistically unusual',
  'threat detected',
]

function assertClean(str) {
  const lower = String(str).toLowerCase()
  for (const word of FORBIDDEN) {
    expect(lower).not.toContain(word)
  }
}

describe('ruleLabel', () => {
  it('maps every known rule id to a human title', () => {
    for (const key of Object.keys(RULE_LABELS)) {
      expect(ruleLabel(key)).toBe(RULE_LABELS[key])
    }
  })

  it('falls back to a readable form for unknown rule ids', () => {
    expect(ruleLabel('some_new_rule')).toBe('Some new rule')
  })

  it('returns a neutral default for empty input', () => {
    expect(ruleLabel(null)).toBe('Related change')
    expect(ruleLabel(undefined)).toBe('Related change')
    expect(ruleLabel('')).toBe('Related change')
  })

  it('never emits forbidden vocabulary', () => {
    for (const key of Object.keys(RULE_LABELS)) assertClean(ruleLabel(key))
  })
})

describe('directionMeta', () => {
  it('maps appeared/changed/degraded to neutral tags', () => {
    expect(directionMeta('appeared').label).toBe('Appeared')
    expect(directionMeta('changed').label).toBe('Changed')
    expect(directionMeta('degraded').label).toBe('Degraded')
  })

  it('falls back to a titled raw label with a neutral tone', () => {
    const m = directionMeta('sideways')
    expect(m.label).toBe('Sideways')
    expect(m.tone).toBe('slate')
  })

  it('handles missing direction', () => {
    expect(directionMeta(null).label).toBe('Unknown')
  })
})

describe('customerStateMeta', () => {
  it('maps every known customer state', () => {
    for (const key of Object.keys(CUSTOMER_STATE_META)) {
      expect(customerStateMeta(key)).toBe(CUSTOMER_STATE_META[key])
    }
  })

  it('new is presented as "Needs review", not a verdict', () => {
    expect(customerStateMeta('new').label).toBe('Needs review')
  })

  it('unexpected_confirmed asks for verification, never claims compromise', () => {
    const m = customerStateMeta('unexpected_confirmed')
    expect(m.description).toContain('requires verification')
    assertClean(m.label)
    assertClean(m.description)
  })

  it('falls back for an unknown state', () => {
    const m = customerStateMeta('weird_state')
    expect(m.label).toBe('Weird state')
    expect(m.tone).toBe('slate')
  })

  it('handles missing state', () => {
    expect(customerStateMeta(null).label).toBe('Unknown')
  })
})

describe('completenessMeta', () => {
  it('maps complete and partial', () => {
    expect(completenessMeta('complete').label).toBe('Complete evidence')
    expect(completenessMeta('partial').label).toBe('Partial evidence')
    expect(completenessMeta('partial').tone).toBe('amber')
  })

  it('falls back for unknown completeness', () => {
    expect(completenessMeta('half').label).toBe('Evidence completeness unknown')
    expect(completenessMeta(null).label).toBe('Evidence completeness unknown')
  })
})

describe('confidenceLabel', () => {
  it('renders "correlated" as deterministic, never a probability', () => {
    expect(confidenceLabel('correlated')).toBe('Correlated (deterministic)')
    expect(confidenceLabel('correlated')).not.toMatch(/%|probab/i)
  })

  it('echoes any other value and defaults when missing', () => {
    expect(confidenceLabel('other')).toBe('other')
    expect(confidenceLabel(null)).toBe('Correlated (deterministic)')
  })
})

describe('count wording (explanation first, number second)', () => {
  it('pluralises signal families', () => {
    expect(signalFamilyText(1)).toBe('1 independent signal family')
    expect(signalFamilyText(3)).toBe('3 independent signal families')
    expect(signalFamilyText(null)).toBe('0 independent signal families')
  })

  it('pluralises producers', () => {
    expect(producerText(1)).toBe('1 independent producer')
    expect(producerText(2)).toBe('2 independent producers')
    expect(producerText(undefined)).toBe('0 independent producers')
  })
})

describe('producerFamilyLabel', () => {
  it('maps known producer families', () => {
    expect(producerFamilyLabel('host')).toBe('Host / attack surface')
    expect(producerFamilyLabel('cert')).toBe('Certificate')
    expect(producerFamilyLabel('email_config')).toBe('Email authentication')
  })

  it('falls back to a readable form and a default', () => {
    expect(producerFamilyLabel('new_family')).toBe('New family')
    expect(producerFamilyLabel(null)).toBe('Observation')
    expect(producerFamilyLabel('')).toBe('Observation')
  })
})

describe('toneClass', () => {
  it('returns a class for a known tone and a slate default otherwise', () => {
    expect(toneClass('green')).toBe(TONE_CLASS.green)
    expect(toneClass('nonsense')).toBe(TONE_CLASS.slate)
  })
})

describe('shortDate', () => {
  it('slices an ISO string to a date', () => {
    expect(shortDate('2026-07-19T10:00:00Z')).toBe('2026-07-19')
  })

  it('returns an em dash for empty input', () => {
    expect(shortDate(null)).toBe('—')
    expect(shortDate('')).toBe('—')
  })
})

describe('option lists', () => {
  it('feedback options never let a customer set the system-only "new" state', () => {
    const states = FEEDBACK_OPTIONS.map((o) => o.state)
    expect(states).toEqual(['expected', 'unrelated', 'unexpected_confirmed'])
    expect(states).not.toContain('new')
  })

  it('filter list includes new so unreviewed clusters are findable', () => {
    expect(CUSTOMER_STATE_FILTERS).toContain('new')
  })
})

describe('honesty note', () => {
  it('states change is not compromise and asks to confirm whether planned', () => {
    expect(HONESTY_NOTE).toContain('Change is not compromise')
    expect(HONESTY_NOTE).toContain('confirm whether each was planned')
    assertClean(HONESTY_NOTE.replace('Change is not compromise', ''))
  })
})

describe('emptyStateFor — three-way distinction', () => {
  // No presentation string here may imply a security verdict ("healthy / secure /
  // all clear / protected") — an empty list is a factual "none observed", not a verdict.
  const VERDICT_WORDS = ['healthy', 'secure', 'all clear', 'protected', 'safe', 'no threats']
  const assertNoVerdict = (s) => {
    const lower = String(s).toLowerCase()
    for (const w of VERDICT_WORDS) expect(lower).not.toContain(w)
  }

  it('(filter) explains an empty filtered view without a verdict', () => {
    const e = emptyStateFor({ complete_scans: 5, correlation_possible: true, latest_scan_quality: 'complete' }, true)
    expect(e.title.toLowerCase()).toContain('review status')
    assertClean(e.title); assertClean(e.description); assertNoVerdict(e.title); assertNoVerdict(e.description)
  })

  it('(a) not yet assessed when there is no complete assessment', () => {
    const e = emptyStateFor({ complete_scans: 0, correlation_possible: false, latest_scan_quality: null }, false)
    expect(e.title).toBe('Not yet assessed')
    assertClean(e.description); assertNoVerdict(e.description)
  })

  it('(a) insufficient history with a single complete assessment', () => {
    const e = emptyStateFor({ complete_scans: 1, correlation_possible: false, latest_scan_quality: 'complete' }, false)
    expect(e.title.toLowerCase()).toContain('history')
    assertClean(e.description); assertNoVerdict(e.description)
  })

  it('(b) incomplete correlation when the latest assessment did not complete', () => {
    const e = emptyStateFor({ complete_scans: 2, correlation_possible: true, latest_scan_quality: 'partial' }, false)
    expect(e.title.toLowerCase()).toContain('incomplete')
    assertClean(e.description); assertNoVerdict(e.description)
  })

  it('(c) assessed with no related changes — factual, never a verdict', () => {
    const e = emptyStateFor({ complete_scans: 3, correlation_possible: true, latest_scan_quality: 'complete' }, false)
    expect(e.title).toContain('No related changes observed')
    assertClean(e.title); assertClean(e.description); assertNoVerdict(e.title); assertNoVerdict(e.description)
  })

  it('degrades safely when the assessment context is missing', () => {
    const e = emptyStateFor(null, false)
    expect(e.title).toBe('Not yet assessed')
    assertClean(e.description)
  })
})
