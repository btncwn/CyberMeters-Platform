import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import LiveTlsEvidence from '../LiveTlsEvidence'
import CertificatesPage from '../../pages/ws/CertificatesPage'
import { api } from '../../api'
import { ReportTimeLabelled } from '../../lib/reportTime'

vi.mock('../../hooks/useWorkspace', () => ({ useWorkspace: () => ({ wsId: 'synthetic-workspace', wsName: 'Synthetic workspace' }) }))
vi.mock('../../api', () => ({ api: { getWorkspaceCertificates: vi.fn(), getWorkspaceCertificatesTimeline: vi.fn() } }))

const fingerprint = `sha256:${'a'.repeat(64)}`
const leaf = { collection_performed: true, collection_complete: true, certificate_identity: fingerprint, subject: 'CN=public.example.test', issuer: 'CN=Test issuer', dns_names: ['public.example.test'], not_before: '2026-10-01T00:00:00Z', not_after: '2026-11-01T00:00:00Z' }
const fixture = () => ({
  leaf_collected: true, leaf_certificate: { ...leaf }, observed_at: '2026-10-09T00:00:00Z', endpoint: { address: '8.8.8.8', port: 443, hostname: 'public.example.test' }, protocol: 'TLSv1.3', cipher: 'TLS_AES_256_GCM_SHA384',
  hostname_match: { assessment_performed: true, result: 'matched', reference_hostname: 'public.example.test', certificate_identity: fingerprint },
  trust_store_validation: { validation_performed: true, validation_result: 'valid', certificate_identity: fingerprint, trust_store_context: { name: 'Synthetic CA roots', version: 'fixture-1', sha256: 'b'.repeat(64) } },
  runtime_chain: { collection_performed: true, collection_complete: false, observation_scope: 'node_tls_issuer_chain', certificates: [{ ...leaf, subject: 'CN=Issuer', certificate_identity: `sha256:${'c'.repeat(64)}` }] },
  presented_chain: { collection_performed: false }, revocation_assurance: { status: 'unknown' },
})

describe('Live TLS evidence presentation', () => {
  it('shows the actual leaf, connection, identity and named trust-store evidence separately', () => {
    const { container } = render(<LiveTlsEvidence evidence={fixture()} />)
    expect(screen.getByText('Live TLS evidence — certificate observed')).toBeInTheDocument()
    expect(screen.getByText(fingerprint)).toBeInTheDocument()
    expect(screen.getByText('8.8.8.8:443')).toBeInTheDocument()
    expect(screen.getByText('TLSv1.3 / TLS_AES_256_GCM_SHA384')).toBeInTheDocument()
    expect(screen.getAllByText('1 Nov 2026, 00:00 UTC')).toHaveLength(2)
    expect(screen.getByText('Matched the recorded identity')).toBeInTheDocument()
    expect(screen.getByText('Valid against the recorded trust store')).toBeInTheDocument()
    expect(screen.getByText('Synthetic CA roots · fixture-1')).toBeInTheDocument()
    expect(container).not.toHaveTextContent('Certificate is secure')
  })

  it('inside a report that states its zone once, times carry no per-line UTC suffix', () => {
    const { container } = render(<ReportTimeLabelled.Provider value={true}><LiveTlsEvidence evidence={fixture()} /></ReportTimeLabelled.Provider>)
    expect(screen.getAllByText('1 Nov 2026, 00:00')).toHaveLength(2)
    expect(container).not.toHaveTextContent('UTC')
  })

  it('names the server name sent (SNI), the serial number and the key of the observed leaf', () => {
    const evidence = fixture()
    evidence.leaf_certificate.serial_number = '04A1B2'
    evidence.leaf_certificate.public_key_algorithm = 'ec'
    evidence.leaf_certificate.public_key_size_bits = 256
    render(<LiveTlsEvidence evidence={evidence} />)
    expect(within(screen.getByText('Name sent (SNI)').parentElement).getByText('public.example.test')).toBeInTheDocument()
    expect(within(screen.getByText('Endpoint (address and port)').parentElement).getByText('8.8.8.8:443')).toBeInTheDocument()
    expect(screen.getByText('04A1B2')).toBeInTheDocument()
    expect(screen.getByText('EC 256-bit')).toBeInTheDocument()
  })

  it('does not promote the runtime issuer chain or TLS success into wire-chain or revocation proof', () => {
    render(<LiveTlsEvidence evidence={fixture()} />)
    expect(screen.getByText('Runtime-observed issuer chain (1 recorded)')).toBeInTheDocument()
    expect(screen.getByText(/may include a root from its trust store/)).toHaveTextContent('not the exact chain')
    expect(screen.getByText('Exact presented chain: unknown. Revocation / OCSP status: not assessed.')).toBeInTheDocument()
    expect(screen.queryByText(/Revocation.*valid/i)).not.toBeInTheDocument()
  })

  it('keeps an invalid trust result and hostname mismatch visible beside an observed leaf', () => {
    const evidence = fixture()
    evidence.hostname_match.result = 'mismatched'
    evidence.trust_store_validation.validation_result = 'invalid'
    evidence.trust_store_validation.reason = 'CERT_HAS_EXPIRED'
    render(<LiveTlsEvidence evidence={evidence} />)
    expect(screen.getByText('Did not match the recorded identity')).toBeInTheDocument()
    expect(screen.getByText('Invalid against the recorded trust store')).toBeInTheDocument()
    expect(screen.getByText('Validation detail: CERT_HAS_EXPIRED')).toBeInTheDocument()
    expect(screen.queryByText('Valid against the recorded trust store')).not.toBeInTheDocument()
  })

  it('does not attach positive match or trust assertions from another certificate', () => {
    const evidence = fixture()
    evidence.hostname_match.certificate_identity = 'different'
    evidence.trust_store_validation.certificate_identity = 'different'
    render(<LiveTlsEvidence evidence={evidence} />)
    expect(screen.getAllByText('Not established')).toHaveLength(2)
    expect(screen.queryByText('Matched the recorded identity')).not.toBeInTheDocument()
    expect(screen.queryByText('Valid against the recorded trust store')).not.toBeInTheDocument()
  })

  it('does not claim named trust validation when its trust-store context was not recorded', () => {
    const evidence = fixture()
    delete evidence.trust_store_validation.trust_store_context
    render(<LiveTlsEvidence evidence={evidence} />)
    expect(screen.getByText('Not established')).toBeInTheDocument()
    expect(screen.queryByText('Valid against the recorded trust store')).not.toBeInTheDocument()
  })

  it('shows partial endpoint coverage and retains every unmeasured endpoint', () => {
    const evidence = fixture()
    evidence.all_planned_endpoints_observed = false
    evidence.endpoint_observations = [
      { address: '8.8.8.8', port: 443, state: 'open', tls: fixture() },
      { address: '8.8.4.4', port: 443, state: 'timeout', tls: null },
      { address: '2001:4860:4860::8888', port: 443, state: 'not_run', tls: null },
    ]
    render(<LiveTlsEvidence evidence={evidence} />)
    expect(screen.getByText(/Endpoint coverage is incomplete/)).toBeInTheDocument()
    expect(screen.getByText('Endpoint observations (3)')).toBeInTheDocument()
    expect(screen.getByText('8.8.4.4:443 — Timed out')).toBeInTheDocument()
    expect(screen.getByText('[2001:4860:4860::8888]:443 — Not run')).toBeInTheDocument()
    expect(screen.getAllByText('Live TLS was not observed for this endpoint.')).toHaveLength(2)
    expect(screen.queryByText('All planned endpoints were observed in this run.')).not.toBeInTheDocument()
  })

  it('keeps absent or incomplete live evidence unknown, never valid', () => {
    const { rerender, container } = render(<LiveTlsEvidence evidence={null} />)
    expect(container).toBeEmptyDOMElement()
    rerender(<LiveTlsEvidence evidence={{ ...fixture(), leaf_collected: false, all_planned_endpoints_observed: false }} />)
    expect(screen.getByText('Live TLS evidence — not fully observed')).toBeInTheDocument()
    expect(screen.getByText(/the certificate currently served is unknown/)).toBeInTheDocument()
    expect(screen.queryByText('Valid against the recorded trust store')).not.toBeInTheDocument()
    expect(screen.queryByText(fingerprint)).not.toBeInTheDocument()
  })

  it('renders certificate-controlled strings as inert text', () => {
    const evidence = fixture()
    evidence.leaf_certificate.subject = '<img src=x onerror=alert(1)>'
    evidence.leaf_certificate.dns_names = ['<script>alert(1)</script>']
    const { container } = render(<LiveTlsEvidence evidence={evidence} />)
    expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeInTheDocument()
    expect(screen.getByText('<script>alert(1)</script>')).toBeInTheDocument()
    expect(container.querySelector('img,script')).toBeNull()
  })

  it('exposes live evidence on the existing Certificates page while preserving historical log-only records', async () => {
    const assurance = { signals: {}, signal_order: [], summary: { ct_only: true }, scope_note: 'Certificate signals are reported separately.' }
    api.getWorkspaceCertificates.mockResolvedValue({ certificates: [
      { domain: 'live.example.test', certificate_assurance: { ...assurance, summary: { ct_only: false } }, live_tls: fixture(),
        tls_assessment: { source: 'tls_assessment', quality: 'partial', endpoints: [], coverage: {} },
        finding_actions: [{ finding_id: 'certificate_expiring_soon', status: 'resolved', customer_title: 'Renew the certificate before expiry', recommended_action: 'Schedule renewal and confirm the replacement.', owner_type: 'customer_it', verification_method: 'certificate_recheck' }],
        ca_concentration: { concentration_level: 'high', issuer_count: 1, dominant_ca_owner: 'Recorded CA', observations: ['One issuer observed.'] },
        wildcard_warning: 'Wildcard DNS observed.', san_hostnames: ['live.example.test', 'admin.example.test'],
        days_until_expiry: 23 },
      { domain: 'historic.example.test', issuer: 'Historical issuer', certificate_assurance: assurance, live_tls: null, days_until_expiry: null },
    ] })
    api.getWorkspaceCertificatesTimeline.mockResolvedValue({})
    // The page body lives on the Findings tab of the area contract (16 Oct 2026).
    render(<MemoryRouter initialEntries={['/ws/certificates?tab=findings']}><CertificatesPage /></MemoryRouter>)
    expect(await screen.findByText(fingerprint)).toBeInTheDocument()
    expect(screen.getByText('Historical log record only')).toBeInTheDocument()
    expect(screen.getByText('Historical issuer')).toBeInTheDocument()
    expect(screen.getByText('Renew the certificate before expiry')).toBeInTheDocument()
    expect(screen.getByText('Schedule renewal and confirm the replacement.')).toBeInTheDocument()
    expect(screen.getByText('Owner: IT / DNS Administrator')).toBeInTheDocument()
    expect(screen.queryByText('Certificate expiring soon')).not.toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'TLS security assessment' })).toHaveTextContent('Partial')
    expect(screen.getByText('CA concentration: high')).toBeInTheDocument()
    expect(screen.getByText('Wildcard DNS: Wildcard DNS observed.')).toBeInTheDocument()
    expect(screen.getByText('SAN hostnames: live.example.test, admin.example.test')).toBeInTheDocument()
    const summaries = screen.getAllByText(/Certificate evidence ·/)
    expect(summaries).toHaveLength(2)
    expect(within(summaries[1].closest('section')).queryByTestId('live-tls-evidence')).not.toBeInTheDocument()
  })

  it('shows a certificate read failure instead of an empty inventory', async () => {
    api.getWorkspaceCertificates.mockRejectedValueOnce(new Error('network failed'))
    api.getWorkspaceCertificatesTimeline.mockResolvedValue({})
    render(<MemoryRouter initialEntries={['/ws/certificates?tab=findings']}><CertificatesPage /></MemoryRouter>)
    expect(await screen.findByText('Could not load certificate evidence.')).toBeInTheDocument()
    expect(screen.queryByText('Run a scan to start certificate and trust monitoring')).not.toBeInTheDocument()
  })
})
