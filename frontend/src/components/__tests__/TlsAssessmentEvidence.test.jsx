import { render, screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import LiveTlsEvidence, { TlsAssessmentEvidence } from '../LiveTlsEvidence'

const stamp = '2026-10-13T10:00:00Z'
const receipt = (overrides = {}) => ({
  source: 'tls_assessment', version: 'cybermeters-tls-profile/1', policy_version: 'rfc9325-2022/1', quality: 'partial',
  coverage: { planned: 6, completed: 2, uncertain: 1, unexecutable: 1, not_authorized: 1, not_applicable: 1 },
  endpoints: [{ hostname: 'mail.example.com', sni: 'mail.example.com', address: '2001:4860:4860::8888', port: 587, transport: 'tcp', application_protocol: 'smtp', dns_observed_at: stamp, observed_at: stamp, checks: [] }],
  ...overrides,
})
const withChecks = checks => {
  const data = receipt()
  data.endpoints[0].checks = checks.map(row => ({ control: 'protocol', state: 'uncertain', observed_at: stamp, engine: { family: 'openssl', version: '3.fixture', build_id: 'manifest-fixture', sandboxed: true }, ...row }))
  return data
}

describe('TLS assessment evidence', () => {
  it('keeps absent receipts and missing endpoint checks unknown', () => {
    const { rerender, container } = render(<TlsAssessmentEvidence />)
    expect(screen.getByText('Deep TLS checks: not recorded.')).toBeInTheDocument()
    rerender(<TlsAssessmentEvidence assessment={receipt({ quality: 'not_run', endpoints: [], coverage: { planned: 6, completed: 0 } })} />)
    expect(screen.getByText(/No endpoint checks recorded/)).toHaveTextContent('unknown')
    expect(screen.getByText('Completed: 0')).toBeInTheDocument()
    expect(screen.getByText('Uncertain: Not recorded')).toBeInTheDocument()
    expect(container).not.toHaveTextContent('Complete for the recorded scope')
    expect(container).not.toHaveTextContent('secure service')
  })

  it('shows every coverage state and the complete endpoint identity', () => {
    render(<TlsAssessmentEvidence assessment={receipt()} />)
    expect(screen.getByText(/mail.example.com · \[2001:4860:4860::8888\]:587 · smtp/)).toBeInTheDocument()
    expect(screen.getByText(/SNI: mail.example.com · Transport: tcp/)).toHaveTextContent('13 Oct 2026, 10:00 UTC')
    expect(screen.getByText(/Partial — some checks remain unresolved/)).toBeInTheDocument()
    for (const value of ['Planned: 6', 'Completed: 2', 'Uncertain: 1', 'Could not execute: 1', 'Not authorized: 1', 'Not applicable: 1']) expect(screen.getByText(value)).toBeInTheDocument()
    // No checks and no recorded deferral: said in plain words, never "Not recorded" (founder live run, 24 Oct 2026).
    expect(screen.getByTestId('tls-endpoint-not-tested')).toHaveTextContent('Not tested in this scan — no TLS checks were planned for this address. Its TLS status remains unknown.')
  })

  it('preserves rejected, uncertain, unauthorized and unexecutable checks without converting them to findings', () => {
    const checks = ['accepted', 'rejected', 'uncertain', 'not_authorized', 'not_applicable', 'unexecutable'].map((state, index) => ({ control: `control_${index}`, state, protocol: 'TLS1.2', cipher_id: '0xc02f' }))
    const { container } = render(<TlsAssessmentEvidence assessment={withChecks(checks)} />)
    for (const label of ['Accepted', 'Rejected', 'Uncertain', 'Not authorized', 'Not applicable', 'Could not execute']) expect(screen.getByText(new RegExp(`TLS1.2 · 0xc02f — ${label}$`))).toBeInTheDocument()
    expect(container).not.toHaveTextContent('Confirmed by the recorded test')
    expect(container).toHaveTextContent('support alone do not establish a vulnerability')
  })

  it('separates the server chain from the built trust path and displays reproducible trust evidence', () => {
    const evidence = { certificates: { trust: 'invalid', hostname: false, dates: true, evaluation_at: stamp, trust_bundle_sha256: 'bundle-hash', reason: 'untrusted_chain', offered_chain: [{ sha256: 'offered-leaf', spki_sha256: 'leaf-key', key_type: 'RSA', key_bits: 2048, signature_algorithm: 'sha256WithRSAEncryption', not_before: stamp, not_after: '2026-11-13T10:00:00Z', self_signed: false, ca: false }], trusted_chain: ['offered-leaf', 'scanner-root'] } }
    render(<TlsAssessmentEvidence assessment={withChecks([{ control: 'certificate', evidence }])} />)
    const offered = screen.getByText('Server-offered chain (1 recorded)').closest('details')
    const built = screen.getByText('Built trust path (2 recorded)').closest('details')
    expect(offered).toHaveTextContent('offered-leaf')
    expect(offered).not.toHaveTextContent('scanner-root')
    expect(built).toHaveTextContent('scanner-root')
    expect(within(screen.getByText('Certificate trust result').parentElement).getByText('Invalid')).toBeInTheDocument()
    expect(screen.getByText('bundle-hash')).toBeInTheDocument()
    expect(screen.getByText('Certificate validation detail: untrusted chain')).toBeInTheDocument()
    expect(screen.getByText(/Trust store: Not recorded for this assessment/)).toBeInTheDocument()
  })

  it.each(['signature_valid', 'cert_id_match', 'fresh'])('does not label an OCSP good status verified when %s is missing', key => {
    const ocsp = { state: 'good', signature_valid: true, cert_id_match: true, fresh: true }
    delete ocsp[key]
    render(<TlsAssessmentEvidence assessment={withChecks([{ control: 'ocsp', evidence: { ocsp } }])} />)
    expect(screen.getByText('Stapled OCSP: Status not verified')).toBeInTheDocument()
    expect(screen.queryByText(/Good status in the verified staple/)).not.toBeInTheDocument()
  })

  it('shows verified revocation only with all proof axes and distinguishes an absent staple', () => {
    render(<TlsAssessmentEvidence assessment={withChecks([
      { control: 'ocsp', evidence: { ocsp: { state: 'revoked', signature_valid: true, cert_id_match: true, fresh: true, this_update: stamp, next_update: '2026-10-14T10:00:00Z' } } },
      { control: 'ocsp_absent', evidence: { ocsp: { state: 'absent' } } },
    ])} />)
    expect(screen.getByText('Stapled OCSP: Revoked status in the verified staple')).toBeInTheDocument()
    expect(screen.getByText('Stapled OCSP: No stapled response observed')).toBeInTheDocument()
    expect(screen.getByText(/This update: 13 Oct 2026/)).toHaveTextContent('Next update: 14 Oct 2026')
  })

  it('renders finite negotiated and vulnerability evidence without exposing raw secret or SAN fields', () => {
    const data = withChecks([{ control: 'heartbleed', state: 'uncertain', evidence: {
      negotiated: { version: 'TLS1.2', cipher: 'TLS_RSA_WITH_AES_128_CBC_SHA', cipher_bits: 128, group: 'none', group_bits: 0, pfs: false, alpn: 'http/1.1', sni_sent: true },
      extensions: { ems: null, compression: false, secure_renegotiation: true, session_reused: true, early_data_max: 0 },
      vulnerability: { status: 'unknown', profile: 'bounded-fixture', completed_vectors: 0, planned_vectors: 1 },
      raw_memory: 'SECRET_MEMORY', serial_number: 'SECRET_SERIAL', dns_names: ['SECRET_SAN'],
    } }])
    data.costs = { connections: 2, bytes_sent: 12, bytes_received: 20, duration_ms: 30, unknown_attempts: 1, charged_connections: 3, charged_bytes: 2048 }
    data.limitations = ['probe_timeout']
    const { container } = render(<TlsAssessmentEvidence assessment={data} />)
    expect(screen.getByText('TLS1.2 / TLS_RSA_WITH_AES_128_CBC_SHA')).toBeInTheDocument()
    expect(screen.getByText('Vulnerability test: Unknown')).toBeInTheDocument()
    expect(screen.getByText(/Vectors completed: 0 \/ 1/)).toBeInTheDocument()
    expect(screen.getByText(/Budget charged: 3 connections \/ 2048 bytes/)).toBeInTheDocument()
    expect(screen.getByText('probe timeout')).toBeInTheDocument()
    expect(container).not.toHaveTextContent('SECRET_')
    expect(container).not.toHaveTextContent('Confirmed by the recorded test')
  })

  it('keeps legacy leaf uncertainty scoped when a separate deep receipt is present', () => {
    render(<LiveTlsEvidence evidence={{ leaf_collected: false, tls_assessment: receipt() }} />)
    expect(screen.getByText(/The live-leaf capture above does not establish/)).toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'TLS security assessment' })).toBeInTheDocument()
    expect(screen.queryByText('Exact presented chain: unknown. Revocation / OCSP status: not assessed.')).not.toBeInTheDocument()
  })
})
