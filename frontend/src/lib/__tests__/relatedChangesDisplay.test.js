import { describe, it, expect } from 'vitest'
import {
  ruleLabel,
  RULE_LABELS,
  eventTypeLabel,
  EVENT_TYPE_LABELS,
  groupEvidencePointers,
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

  it('never claims a specific certificate story the evidence may not tell', () => {
    // The cert family of a rule also matches standing conditions (sensitive
    // hostname in CT, expiring soon) — a title claiming "new or changed
    // certificate" would say more than the evidence. (A6 P3, 20 Jul 2026.)
    for (const key of Object.keys(RULE_LABELS)) {
      expect(RULE_LABELS[key].toLowerCase()).not.toContain('new or changed certificate')
      expect(RULE_LABELS[key].toLowerCase()).not.toContain('certificate change')
    }
    expect(RULE_LABELS.new_host_with_cert).toBe('New host with a certificate signal')
  })
})

describe('eventTypeLabel — evidence subtype tells the same story as the producer', () => {
  it('maps every known subtype to honest wording, never the raw enum', () => {
    for (const key of Object.keys(EVENT_TYPE_LABELS)) {
      const label = eventTypeLabel(key)
      expect(label).toBe(EVENT_TYPE_LABELS[key])
      expect(label).not.toContain('_')
      assertClean(label)
    }
  })

  it('a standing sensitive-host condition is never presented as a new or changed certificate', () => {
    const label = eventTypeLabel('certificate_sensitive_host_detected')
    expect(label).toBe('Sensitive hostname observed in certificate-transparency logs')
    expect(label.toLowerCase()).not.toContain('new')
    expect(label.toLowerCase()).not.toContain('changed')
  })

  it('falls back to a readable form for unknown subtypes and empty for missing input', () => {
    expect(eventTypeLabel('some_future_event')).toBe('Some future event')
    expect(eventTypeLabel(null)).toBe('')
    expect(eventTypeLabel('')).toBe('')
  })
})

describe('groupEvidencePointers — presentation-level collapse only', () => {
  const pointer = (over = {}) => ({
    producer_family: 'cert',
    source_table: 'asset_events',
    source_record_id: 'r-1',
    source_event_type: 'certificate_sensitive_host_detected',
    entity_key: 'host:api.example.com',
    observed_at: '2026-07-10T00:00:00Z',
    evidence_ref: 'r-1',
    ...over,
  })

  it('collapses identical repeated observations into one row with an honest count and first/last seen', () => {
    // Pre-#172 standing-condition producers appended the same pointer once per
    // scan — ~10 identical rows for one condition.
    const rows = Array.from({ length: 10 }, (_, i) =>
      pointer({
        source_record_id: `r-${i}`,
        evidence_ref: `r-${i}`,
        observed_at: `2026-07-${String(i + 5).padStart(2, '0')}T00:00:00Z`,
      }),
    )
    const groups = groupEvidencePointers(rows)
    expect(groups).toHaveLength(1)
    expect(groups[0].occurrence_count).toBe(10)
    expect(groups[0].first_observed_at).toBe('2026-07-05T00:00:00Z')
    expect(groups[0].last_observed_at).toBe('2026-07-14T00:00:00Z')
  })

  it('never collapses observations that differ in any material field', () => {
    const rows = [
      pointer(),
      pointer({ source_record_id: 'r-2', evidence_ref: 'r-2', source_event_type: 'certificate_expiring_soon' }),
      pointer({ source_record_id: 'r-3', evidence_ref: 'r-3', entity_key: 'host:www.example.com' }),
      pointer({ source_record_id: 'r-4', evidence_ref: 'r-4', producer_family: 'host' }),
      pointer({ source_record_id: 'r-5', evidence_ref: 'r-5', source_table: 'certificate_lifecycle_events' }),
    ]
    expect(groupEvidencePointers(rows)).toHaveLength(5)
  })

  it('keeps brand candidates distinct — evidence_ref that is not the row pointer is material', () => {
    const rows = [
      pointer({
        producer_family: 'brand', source_table: 'workspace_brand_assets',
        entity_key: 'brand-target:example.com', source_record_id: 'b-1', evidence_ref: 'examp1e.com',
      }),
      pointer({
        producer_family: 'brand', source_table: 'workspace_brand_assets',
        entity_key: 'brand-target:example.com', source_record_id: 'b-2', evidence_ref: 'exarnple.com',
      }),
    ]
    expect(groupEvidencePointers(rows)).toHaveLength(2)
  })

  it('single observations pass through unchanged with a count of one', () => {
    const groups = groupEvidencePointers([pointer()])
    expect(groups).toHaveLength(1)
    expect(groups[0].occurrence_count).toBe(1)
    expect(groups[0].entity_key).toBe('host:api.example.com')
  })

  it('handles empty and missing input', () => {
    expect(groupEvidencePointers([])).toEqual([])
    expect(groupEvidencePointers(null)).toEqual([])
  })

  it('preserves first-appearance order across groups', () => {
    const rows = [
      pointer({ source_event_type: 'certificate_new_detected' }),
      pointer({ source_record_id: 'r-2', evidence_ref: 'r-2' }),
      pointer({ source_event_type: 'certificate_new_detected', source_record_id: 'r-3', evidence_ref: 'r-3' }),
    ]
    const groups = groupEvidencePointers(rows)
    expect(groups.map((g) => g.source_event_type)).toEqual([
      'certificate_new_detected',
      'certificate_sensitive_host_detected',
    ])
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
