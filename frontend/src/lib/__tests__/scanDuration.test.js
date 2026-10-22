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
      heading: 'Scan queued', timer: 'Queued for 40 s', expectation: 'Usually takes about 2 min, based on your last 7 complete scans of this domain.', longRunning: false,
    })
    expect(scanProgressCopy({ status: 'running', elapsedMs: 80000, estimate: { ...estimate, basis: 'workspace' } })).toMatchObject({
      heading: 'Scan in progress', timer: 'Running for 1 min 20 s', expectation: 'Usually takes about 2 min, based on your last 7 complete scans.',
    })
  })
  it('without complete-scan history it states the documented range, not a guess from partial runs', () => {
    const copy = scanProgressCopy({ status: 'running', elapsedMs: 5000, estimate: null })
    expect(copy.expectation).toBe('A full check usually takes 5–15 minutes.')
    expect(copy.longRunning).toBe(false)
  })
  it('says so plainly at 15 and at 30 minutes, never for a queue', () => {
    const at = (min) => scanProgressCopy({ status: 'running', elapsedMs: min * 60000, estimate })
    expect(at(14.9).longRunning).toBe(false)
    expect(at(15).longRunningText).toBe('This is taking longer than most checks. It is still running; you can leave this page and come back.')
    expect(at(29.9).longRunningText).toMatch(/^This is taking longer than most checks/)
    expect(at(30).longRunningText).toBe('This check has been running for over 30 minutes. It is still running; if it cannot finish, we will mark what could not be completed rather than guess.')
    expect(scanProgressCopy({ status: 'queued', elapsedMs: 31 * 60000, estimate }).longRunning).toBe(false)
  })
  it('names the stage from the API in one table, and says nothing for an unknown one', () => {
    const stage = (s) => scanProgressCopy({ status: 'running', elapsedMs: 60000, estimate, progress: { stage: s } }).stage
    expect(stage('discovery_complete')).toBe('Now checking: the hosts and services found for this domain.')
    expect(stage('phase5_intelligence')).toBe('Now checking: technology and known-vulnerability information.')
    expect(stage('finalizing')).toBe('Now checking: putting the results together.')
    expect(stage(null)).toBeNull()
    expect(stage('something_new')).toBeNull()
    expect(scanProgressCopy({ status: 'queued', elapsedMs: 1000, estimate, progress: { stage: 'finalizing' } }).stage).toBeNull()
  })
  it('a scan the API marks as gone quiet says so honestly', () => {
    expect(scanProgressCopy({ status: 'running', elapsedMs: 20 * 60000, estimate, progress: { stale: true } }).stale)
      .toBe('This check has gone quiet. If it does not resume, we will mark what could not be completed rather than guess.')
    expect(scanProgressCopy({ status: 'running', elapsedMs: 60000, estimate, progress: { stale: false } }).stale).toBeNull()
  })
})

describe('local sample memory', () => {
  beforeEach(() => localStorage.clear())
  it('remembers a completed scan once per id, scoped to the workspace', () => {
    rememberSample({ workspaceId: 'ws1', scanId: 's1', domain: 'A.example', startedAt: '2026-10-16T08:00:00Z', completedAt: '2026-10-16T08:01:00Z', quality: 'complete' })
    rememberSample({ workspaceId: 'ws1', scanId: 's1', domain: 'a.example', startedAt: '2026-10-16T08:00:00Z', completedAt: '2026-10-16T08:01:00Z', quality: 'complete' })
    rememberSample({ workspaceId: 'ws2', scanId: 's2', domain: 'a.example', startedAt: '2026-10-16T08:00:00Z', completedAt: '2026-10-16T08:03:00Z', quality: 'complete' })
    expect(rememberSample({ workspaceId: 'ws1', scanId: 's3', domain: 'a.example', startedAt: null, completedAt: '2026-10-16T08:03:00Z', quality: 'complete' })).toBeNull()
    expect(rememberedSamples('ws1')).toHaveLength(1)
    expect(rememberedSamples('ws1')[0]).toMatchObject({ scanId: 's1', domain: 'a.example', durationMs: 60000 })
    expect(rememberedSamples(null)).toEqual([])
  })
})

describe('only complete scans estimate a full check (founder, 22 Oct 2026)', () => {
  it('a partial scan is never remembered as a sample', () => {
    localStorage.clear()
    expect(rememberSample({ workspaceId: 'ws9', scanId: 'p1', domain: 'a.example', startedAt: '2026-10-16T08:00:00Z', completedAt: '2026-10-16T08:00:40Z', quality: 'partial' })).toBeNull()
    expect(rememberSample({ workspaceId: 'ws9', scanId: 'p2', domain: 'a.example', startedAt: '2026-10-16T08:00:00Z', completedAt: '2026-10-16T08:00:40Z' })).toBeNull()
    expect(rememberedSamples('ws9')).toEqual([])
  })
  it('samples remembered before quality was recorded are ignored', () => {
    localStorage.setItem('cybermeters_scan_duration_samples', JSON.stringify([{ workspaceId: 'ws8', scanId: 'old', domain: 'a.example', durationMs: 40000, completedAt: 1 }]))
    expect(rememberedSamples('ws8')).toEqual([])
  })
  it('one sample reads in the singular', () => {
    expect(scanProgressCopy({ status: 'running', elapsedMs: 1000, estimate: { medianMs: 120000, basis: 'workspace', count: 1 } }).expectation)
      .toBe('Usually takes about 2 min, based on your last complete scan.')
  })
})
