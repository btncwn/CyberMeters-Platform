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
})
