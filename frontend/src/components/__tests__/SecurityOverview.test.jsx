import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import SecurityOverview, { domainsRequestState, recommendedNextAction, requestManagedCases } from '../overview/SecurityOverview'
import StatusChip from '../StatusChip'
import { MODULES } from '../../lib/moduleRegistry'
import { api } from '../../api'

// One component set renders the overview for a direct customer and for an
// MSP-selected customer. These tests feed it backend shapes for several
// personas and pin that it never settles a state the backend did not give.

vi.mock('../../api', () => ({ api: {} }))

const FOUNDER_ORDER = ['Email Protection', 'Attack Surface', 'Website Security', 'Identity Exposure', 'Shadow IT & Unmanaged Technology', 'Certificates & Trust', 'Brand Protection', 'Cyber Essentials Readiness']
const KEYS = MODULES.map((m) => m.domainKey)

const row = (domain_key, state, extra = {}) => ({ domain_key, display_name: domain_key, state, summary: `${domain_key} summary`, finding_count: 0, limitations: [], ...extra })
const eight = (state = 'not_yet_assessed') => KEYS.map((k) => row(k, state))

function show(props) {
  return render(<MemoryRouter><SecurityOverview workspaceName="Example Ltd" domains={eight()} domainsRequest="ok" cases={[]} casesRequest="ok" signals={{ domainCount: 1, hasCompletedScan: false }} {...props} /></MemoryRouter>)
}
const cards = () => screen.getAllByRole('article')
const chipOf = (card) => card.querySelector('[data-status]').dataset.status

describe('SecurityOverview — one overview for every persona', () => {
  it('renders the eight areas in founder order with a Field Guide link and an area link each', () => {
    show()
    const list = cards()
    expect(list.map((c) => within(c).getByRole('heading').textContent)).toEqual(FOUNDER_ORDER)
    for (const c of list) {
      expect(within(c).getByRole('link', { name: 'Field Guide' }).getAttribute('href')).toMatch(/^\/guide\/[a-z-]+$/)
    }
    expect(within(list[0]).getByRole('link', { name: 'Open Email Protection' })).toHaveAttribute('href', '/ws/email-protection')
    expect(within(list[1]).getByRole('link', { name: 'Review Attack Surface' })).toHaveAttribute('href', '/assets')
  })

  it('single-domain direct customer before any scan: every area is Not assessed, nothing is Established', () => {
    show({ domains: eight('not_yet_assessed') })
    expect(cards().map(chipOf)).toEqual(Array(8).fill('not_assessed'))
    expect(screen.queryByText('Established')).not.toBeInTheDocument()
    expect(screen.getByText('Run a scan')).toHaveAttribute('href', '/scans/new')
  })

  it('MSP-selected customer with mixed backend states: the words follow the backend row by row', () => {
    const domains = [
      row('email_protection', 'issue_detected', { finding_count: 3 }),
      row('attack_surface', 'assessed_healthy', { evidence_freshness: 'stale', freshness_reason: 'Last assessed 60 days ago — this evidence is stale and may no longer reflect the current posture.' }),
      row('website_security', 'provisional'),
      row('identity_exposure', 'evidence_insufficient'),
      row('shadow_it_unmanaged_technology', 'monitoring_only', { coverage: 'complete' }),
      row('certificates_trust', 'assessed_healthy'),
      row('brand_protection', 'customer_input_required'),
      row('cyber_essentials_readiness', 'unavailable'),
    ]
    show({ workspaceName: 'Customer A', domains, signals: { domainCount: 4, hasCompletedScan: true, critical: 1, high: 2 } })
    expect(cards().map(chipOf)).toEqual(['action_required', 'stale', 'provisional', 'evidence_insufficient', 'established', 'established', 'customer_input', 'evidence_insufficient'])
    expect(screen.getByText(/Every area for Customer A/)).toBeInTheDocument()
    expect(within(cards()[0]).getByText(/3 findings/)).toBeInTheDocument()
    expect(within(cards()[1]).getByText(/this evidence is stale/)).toBeInTheDocument()
    expect(screen.getByText('Review attack surface')).toHaveAttribute('href', '/assets')
  })

  it('open cases are counted per area from the case list and link to Operations for that area', () => {
    const cases = [
      { case_id: 'c1', domain_key: 'email_protection', canonical_phase: 'triaged', verification_support: 'automated' },
      { case_id: 'c2', domain_key: 'email_protection', canonical_phase: 'verified', verification_support: 'manual' },
      { case_id: 'c3', domain_key: 'brand_protection', canonical_phase: 'reopened', verification_support: 'manual' },
      { case_id: 'c4', domain_key: 'brand_protection', canonical_phase: 'rejected' },
    ]
    show({ cases })
    const email = cards()[0]
    const brand = cards()[6]
    expect(within(email).getByRole('link', { name: '1 open case' })).toHaveAttribute('href', '/ws/cases?domain_key=email_protection')
    expect(within(brand).getByRole('link', { name: '1 open case' })).toHaveAttribute('href', '/ws/cases?domain_key=brand_protection')
    expect(within(cards()[2]).getByRole('link', { name: '0 open cases' })).toBeInTheDocument()
  })

  it('while the eight-domain read is pending every area shows Loading', () => {
    show({ domains: null, domainsRequest: 'loading' })
    expect(cards().map(chipOf)).toEqual(Array(8).fill('loading'))
  })

  it('a failed read shows Error on all eight and never a settled word', () => {
    show({ domains: null, domainsRequest: 'error' })
    expect(cards().map(chipOf)).toEqual(Array(8).fill('error'))
    expect(screen.getAllByText(/could not be read/)).toHaveLength(8)
  })

  it('a malformed or short backend set is treated as a failed read (never fewer than eight, never settled)', () => {
    show({ domains: [row('email_protection', 'assessed_healthy')], domainsRequest: 'ok' })
    expect(cards()).toHaveLength(8)
    expect(cards().map(chipOf)).toEqual(Array(8).fill('error'))
    expect(domainsRequestState([], 'ok')).toBe('error')
    expect(domainsRequestState(eight(), 'ok')).toBe('ok')
    expect(domainsRequestState(eight().map((d) => ({ ...d, state: 7 })), 'ok')).toBe('error')
  })

  it('a failed case read says so instead of showing zero cases', () => {
    show({ cases: null, casesRequest: 'error' })
    expect(screen.getAllByText(/cases not read/)).toHaveLength(8)
    expect(screen.queryByText('0 open cases')).not.toBeInTheDocument()
  })

  it('the recommended next action is the same ladder for both surfaces', () => {
    expect(recommendedNextAction({ domainCount: 0 }).to).toBe('/ws/dashboard')
    expect(recommendedNextAction({ domainCount: 1, hasCompletedScan: false }).to).toBe('/scans/new')
    expect(recommendedNextAction({ domainCount: 1, hasCompletedScan: true, scorecard: { certificate_risks: { risk_level: 'high' } } }).to).toBe('/ws/certificates')
    expect(recommendedNextAction({ domainCount: 1, hasCompletedScan: true, scorecard: { brand_risks: { high: 2 } } }).to).toBe('/ws/brand-monitoring')
    expect(recommendedNextAction({ domainCount: 1, hasCompletedScan: true, critical: 1 }).to).toBe('/assets')
    expect(recommendedNextAction({ domainCount: 1, hasCompletedScan: true }).to).toBe('/ws/email-protection')
  })

  it('a missing API function is a failed request, not an empty success', async () => {
    await expect(requestManagedCases('ws1')).rejects.toBeInstanceOf(TypeError)
    api.getManagedCases = vi.fn(async () => ({ cases: [] }))
    await expect(requestManagedCases('ws1')).resolves.toEqual({ cases: [] })
    expect(api.getManagedCases).toHaveBeenCalledWith('ws1', { limit: 200 })
  })
})

describe('StatusChip', () => {
  it('renders the vocabulary word and falls back to Error for anything else', () => {
    render(<><StatusChip status="ready_to_verify" /><StatusChip status="healthy" /><StatusChip /></>)
    expect(screen.getByText('Ready to verify')).toHaveAttribute('data-status', 'ready_to_verify')
    expect(screen.getAllByText('Error')).toHaveLength(2)
  })
})
