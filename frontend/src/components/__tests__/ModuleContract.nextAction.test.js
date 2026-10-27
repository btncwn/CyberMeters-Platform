import { describe, expect, it } from 'vitest'
import { resolveNextAction } from '../module/ModuleContract'

const entry = (domain_key, extra = {}) => ({ domain_key, state: 'issue_detected', coverage: 'complete', finding_count: 0, finding_details: [], ...extra })
const resolved = (finding_id, customer_title) => ({ finding_id, status: 'resolved', customer_title, recommended_action: 'Do the registered thing.' })

describe('resolveNextAction: the area’s primary job', () => {
  it('a step done in a specific place opens it (the same row the Overview shows)', () => {
    const next = resolveNextAction({ request: 'ok', entry: entry('email_protection', { finding_count: 1, finding_details: [resolved('email_intel_mta_sts_missing', 'Publish MTA-STS')] }) })
    expect(next).toMatchObject({ label: 'Set up MTA-STS', to: '/ws/email-protection?tab=settings#mta-sts-setup' })
  })

  it('a registry-mapped finding elsewhere still reviews the finding', () => {
    const next = resolveNextAction({ request: 'ok', entry: entry('website_security', { finding_count: 1, finding_details: [resolved('header_weak_hsts', 'Add or strengthen HSTS')] }) })
    expect(next).toMatchObject({ title: 'Add or strengthen HSTS', label: 'Review this finding', tab: 'findings' })
  })

  it('with nothing left to fix, a case awaiting verification opens, saying how it is verified', () => {
    const base = { request: 'ok', entry: entry('certificates_trust', { state: 'assessed_healthy' }) }
    const auto = resolveNextAction({ ...base, cases: [{ id: 'c1', domain_key: 'certificates_trust', status: 'awaiting_verification', verification_support: 'automated', title: 'Renew the certificate' }] })
    expect(auto).toMatchObject({ label: 'Open the case to verify', to: '/ws/cases/c1' })
    expect(auto.body).toMatch(/CyberMeters re-checks this fix from its own observation/)
    const manual = resolveNextAction({ ...base, cases: [{ id: 'c2', domain_key: 'certificates_trust', status: 'awaiting_verification', verification_support: 'manual' }] })
    expect(manual.body).toMatch(/attested by you, not verified/)
  })

  it('a case from another area never becomes this page’s job', () => {
    const next = resolveNextAction({ request: 'ok', entry: entry('attack_surface', { state: 'assessed_healthy' }), cases: [{ id: 'c9', domain_key: 'email_protection', status: 'awaiting_verification' }] })
    expect(next.label).not.toBe('Open the case to verify')
  })

  it('a page’s own next action still wins', () => {
    const own = { title: 'Answer the questionnaire', label: 'Start questionnaire', to: '/x' }
    expect(resolveNextAction({ nextAction: own, request: 'ok', entry: entry('cyber_essentials_readiness') })).toBe(own)
  })

  // A page's fallback (CE self-declared answers, 27 Oct 2026) replaces only the
  // generic run-a-scan / all-clear endings; findings and cases keep priority.
  describe('fallbackNextAction', () => {
    const fallback = { title: 'Review your self-declared answers', label: 'Review your self-declared answers', to: '/ws/cyber-essentials?tab=findings#questionnaire' }
    it('replaces "Run a scan to assess this area" for a not-assessed area', () => {
      expect(resolveNextAction({ request: 'ok', entry: entry('cyber_essentials_readiness', { state: 'not_assessed' }) })).toMatchObject({ title: 'Run a scan to assess this area' })
      expect(resolveNextAction({ fallbackNextAction: fallback, request: 'ok', entry: entry('cyber_essentials_readiness', { state: 'not_assessed' }) })).toBe(fallback)
    })
    it('replaces the all-clear too', () => {
      expect(resolveNextAction({ fallbackNextAction: fallback, request: 'ok', entry: entry('cyber_essentials_readiness', { state: 'assessed_healthy' }) })).toBe(fallback)
    })
    it('never outranks an external finding, a case ready to verify or an open case', () => {
      const withFinding = entry('cyber_essentials_readiness', { finding_count: 1, finding_details: [resolved('header_weak_hsts', 'Add or strengthen HSTS')] })
      expect(resolveNextAction({ fallbackNextAction: fallback, request: 'ok', entry: withFinding })).toMatchObject({ label: 'Review this finding' })
      const quiet = entry('cyber_essentials_readiness', { state: 'not_assessed' })
      expect(resolveNextAction({ fallbackNextAction: fallback, request: 'ok', entry: quiet, cases: [{ id: 'c1', domain_key: 'cyber_essentials_readiness', status: 'awaiting_verification', verification_support: 'manual' }] }))
        .toMatchObject({ label: 'Open the case to verify' })
      expect(resolveNextAction({ fallbackNextAction: fallback, request: 'ok', entry: quiet, cases: [{ id: 'c2', domain_key: 'cyber_essentials_readiness', status: 'action_required' }] }))
        .toMatchObject({ label: 'Review 1 case', tab: 'cases' })
    })
    it('loading and failed reads stay honest', () => {
      expect(resolveNextAction({ fallbackNextAction: fallback, request: 'loading' })).toMatchObject({ title: 'Reading the latest assessment…' })
      expect(resolveNextAction({ fallbackNextAction: fallback, request: 'error' })).toMatchObject({ title: 'The latest assessment could not be read' })
    })
  })
})
