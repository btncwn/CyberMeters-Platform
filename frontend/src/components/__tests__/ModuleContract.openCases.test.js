import { describe, expect, it } from 'vitest'
import { resolveNextAction } from '../module/ModuleContract'

const entry = (key, extra = {}) => ({ domain_key: key, state: 'issue_detected', coverage: 'complete', finding_count: 0, finding_details: [], ...extra })
// S1-SHELL-V2: never "no issue" beside an open case without the relationship stated.
describe('resolveNextAction: open cases with no new issue', () => {
  it('names the open cases and makes reviewing them the one action', () => {
    const next = resolveNextAction({ request: 'ok', entry: entry('email_protection', { state: 'assessed_healthy', coverage: 'partial' }), cases: [
      { id: 'c1', domain_key: 'email_protection', status: 'detected', canonical_phase: 'detected' },
      { id: 'c2', domain_key: 'email_protection', status: 'triaged', canonical_phase: 'triaged' },
    ] })
    expect(next).toMatchObject({ title: '2 cases from earlier are still open', label: 'Review 2 cases', tab: 'cases' })
    expect(next.body).toMatch(/found no new issue in this area, but these cases were opened earlier/)
    expect(next.title).not.toMatch(/No issue found|Nothing to fix/)
  })
  it('one case reads in the singular; another area\u2019s case is not this page\u2019s job', () => {
    const one = resolveNextAction({ request: 'ok', entry: entry('email_protection', { state: 'assessed_healthy' }), cases: [
      { id: 'c1', domain_key: 'email_protection', status: 'detected', canonical_phase: 'detected' },
      { id: 'c9', domain_key: 'website_security', status: 'detected', canonical_phase: 'detected' },
    ] })
    expect(one).toMatchObject({ title: '1 case from earlier is still open', label: 'Review 1 case' })
    const none = resolveNextAction({ request: 'ok', entry: entry('email_protection', { state: 'assessed_healthy' }), cases: [
      { id: 'c9', domain_key: 'website_security', status: 'detected', canonical_phase: 'detected' },
    ] })
    expect(none.title).toBe('Nothing to fix from the latest assessment')
  })
})
