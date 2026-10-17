import { scanDurationMs, median, expectedDuration, aboutDuration, elapsedLabel, scanProgressCopy, rememberSample, rememberedSamples, SAMPLE_WINDOW } from '../scanDuration'

// Expected duration = median of the last 10 completed scans of the domain
// (workspace fallback under 3 samples); elapsed is a count-up; no history
// invents nothing; past 2× the median the scan is "taking longer than usual".

const sample = (domain, seconds, day) => ({ domain, durationMs: seconds * 1000, completedAt: `2026-10-${String(day).padStart(2, '0')}T08:00:00Z` })

describe('scanDurationMs and median', () => {
  it('measures completed_at − started_at and rejects unusable or negative spans', () => {
    expect(scanDurationMs('2026-10-16T08:00:00Z', '2026-10-16T08:01:30Z')).toBe(90000)
    expect(scanDurationMs('2026-10-16 08:00:00', '2026-10-16 08:00:20')).toBe(20000)
    expect(scanDurationMs('2026-10-16T08:01:00Z', '2026-10-16T08:00:00Z')).toBeNull()
    expect(scanDurationMs(null, '2026-10-16T08:00:00Z')).toBeNull()
    expect(scanDurationMs('nope', '2026-10-16T08:00:00Z')).toBeNull()
  })
  it('takes the median, even or odd', () => {
    expect(median([30, 10, 20])).toBe(20)
    expect(median([10, 40, 20, 30])).toBe(25)
    expect(median([])).toBeNull()
    expect(median([NaN, -1, 5])).toBe(5)
  })
})

describe('expectedDuration', () => {
  it('uses the domain\'s newest ten samples when it has at least three', () => {
    const samples = [sample('a.example', 60, 1), ...Array.from({ length: 12 }, (_, i) => sample('a.example', 100 + i * 10, 2 + i)), sample('b.example', 900, 15)]
    const est = expectedDuration({ domain: 'A.example', samples })
    expect(est.basis).toBe('domain')
    expect(est.count).toBe(SAMPLE_WINDOW)
    // newest ten: 120…210 s → median (160+170)/2 s
    expect(est.medianMs).toBe(165000)
  })
  it('falls back to the workspace\'s newest ten when the domain has fewer than three', () => {
    const samples = [sample('a.example', 60, 1), sample('a.example', 80, 2), sample('b.example', 100, 3), sample('c.example', 120, 4)]
    expect(expectedDuration({ domain: 'a.example', samples })).toEqual({ medianMs: 90000, basis: 'workspace', count: 4 })
  })
  it('returns null with no history at all', () => {
    expect(expectedDuration({ domain: 'a.example', samples: [] })).toBeNull()
    expect(expectedDuration({})).toBeNull()
  })
})

describe('labels', () => {
  it('rounds the expectation to whole minutes and never shows a fraction or a negative', () => {
    expect(aboutDuration(20000)).toBe('under a minute')
    expect(aboutDuration(50000)).toBe('about 1 min')
    expect(aboutDuration(150000)).toBe('about 3 min')
    expect(aboutDuration(-5)).toBeNull()
  })
  it('counts elapsed time up from zero', () => {
    expect(elapsedLabel(40000)).toBe('40 s')
    expect(elapsedLabel(80000)).toBe('1 min 20 s')
    expect(elapsedLabel(-3000)).toBe('0 s')
    expect(elapsedLabel(NaN)).toBe('0 s')
  })
})

describe('scanProgressCopy', () => {
  const estimate = { medianMs: 120000, basis: 'domain', count: 7 }
  it('distinguishes queued from running and states the basis of the expectation', () => {
    expect(scanProgressCopy({ status: 'queued', elapsedMs: 40000, estimate, domain: 'a.example' })).toMatchObject({
      heading: 'Scan queued', timer: 'Queued for 40 s', expectation: 'Usually takes about 2 min, based on your last 7 scans of this domain.', longRunning: false,
    })
    expect(scanProgressCopy({ status: 'running', elapsedMs: 80000, estimate: { ...estimate, basis: 'workspace' } })).toMatchObject({
      heading: 'Scan in progress', timer: 'Running for 1 min 20 s', expectation: 'Usually takes about 2 min, based on your last 7 scans.',
    })
  })
  it('says first scan with no history and invents no number', () => {
    const copy = scanProgressCopy({ status: 'running', elapsedMs: 5000, estimate: null, domain: 'a.example' })
    expect(copy.expectation).toBe('First scan of a.example; usually a few minutes.')
    expect(copy.expectation).not.toMatch(/\d/)
    expect(copy.longRunning).toBe(false)
  })
  it('flags a run past twice the median as taking longer than usual, but never a queue', () => {
    expect(scanProgressCopy({ status: 'running', elapsedMs: 240001, estimate })).toMatchObject({ longRunning: true, longRunningText: 'Taking longer than usual; it is still running.' })
    expect(scanProgressCopy({ status: 'running', elapsedMs: 240000, estimate }).longRunning).toBe(false)
    expect(scanProgressCopy({ status: 'queued', elapsedMs: 900000, estimate }).longRunning).toBe(false)
  })
})

describe('local sample memory', () => {
  beforeEach(() => localStorage.clear())
  it('remembers a completed scan once per id, scoped to the workspace', () => {
    rememberSample({ workspaceId: 'ws1', scanId: 's1', domain: 'A.example', startedAt: '2026-10-16T08:00:00Z', completedAt: '2026-10-16T08:01:00Z' })
    rememberSample({ workspaceId: 'ws1', scanId: 's1', domain: 'a.example', startedAt: '2026-10-16T08:00:00Z', completedAt: '2026-10-16T08:01:00Z' })
    rememberSample({ workspaceId: 'ws2', scanId: 's2', domain: 'a.example', startedAt: '2026-10-16T08:00:00Z', completedAt: '2026-10-16T08:03:00Z' })
    expect(rememberSample({ workspaceId: 'ws1', scanId: 's3', domain: 'a.example', startedAt: null, completedAt: '2026-10-16T08:03:00Z' })).toBeNull()
    expect(rememberedSamples('ws1')).toHaveLength(1)
    expect(rememberedSamples('ws1')[0]).toMatchObject({ scanId: 's1', domain: 'a.example', durationMs: 60000 })
    expect(rememberedSamples(null)).toEqual([])
  })
})
