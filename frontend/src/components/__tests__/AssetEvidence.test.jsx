import React from 'react'
import { render, screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import AssetEvidence from '../AssetEvidence'

// The shape engines/asset-evidence.js returns for a name the latest scan
// measured (taken from a lab run of the real scan engine).
const recorded = {
  version: 'asset-evidence-v1',
  check_pack_version: '2026.10.1',
  status: 'recorded',
  customer_message: null,
  latest_scan: { scan_id: 'scan_2', observed_at: '2026-10-02T10:00:00.000Z', evidence_recorded: true },
  scope: {
    state: 'in_scope', domain: 'acme.test', relation: 'under_domain',
    label: 'Under acme.test, which this workspace verified with a DNS TXT record.',
  },
  seen_in: {
    status: 'recorded',
    recorded_since: '2026-10-01T09:00:00.000Z',
    first_source: 'tls_certificate_name',
    sources: [
      { source: 'tls_certificate_name', first_seen_at: '2026-10-01T09:00:00.000Z', last_seen_at: '2026-10-02T10:00:00.000Z' },
      { source: 'dns_wordlist', first_seen_at: '2026-10-02T10:00:00.000Z', last_seen_at: '2026-10-02T10:00:00.000Z' },
    ],
    note: null,
  },
  dns: {
    status: 'checked',
    checked_at: '2026-10-02T10:00:00.000Z',
    families: [
      { family: 'IPv4 (A)', outcome: 'nodata', label: 'The name exists but has no address of this type', values: [] },
      { family: 'IPv6 (AAAA)', outcome: 'answer', label: 'Answered with an address', values: ['2001:db8::6'] },
    ],
    alias_chain: [],
    uncertain: null,
  },
  service: {
    status: 'checked',
    checked_at: '2026-10-02T10:00:00.000Z',
    answered: true,
    attempts: [{ protocol: 'HTTPS', port: 443, outcome: 'responded', status: 200, label: 'Answered with HTTP 200' }],
    address_family_note: 'The web request does not record whether it connected over IPv4 or IPv6.',
  },
  findings: {
    measured_at: '2026-10-02T10:00:00.000Z',
    items: [{
      finding_type: 'asset_exposure_sensitive_tool',
      title: 'Sensitive Management Tool Exposed',
      severity: 'high',
      check_id: 'exposure.sensitive_tool',
      check_version: '2026.10.1',
      rule: 'A request to the host returns the interface of a known management or monitoring tool.',
      measured_label: 'HTTPS port 443 answered with HTTP 200 and the page title "phpMyAdmin"',
    }],
    more: 0,
  },
  not_checked: [
    { part: 'service_ipv6', label: 'The name has IPv6 addresses, but the web check does not record which address family it connected over, so an answer is not proof the service works over IPv6.' },
    { part: 'other_ports', label: "Only HTTPS (port 443) and HTTP (port 80) are requested. Other ports are not scanned without the owner's permission." },
  ],
}

describe('AssetEvidence', () => {
  it('keeps hint, scope, DNS answer, service answer, finding and gaps as separate facts', () => {
    render(<AssetEvidence evidence={recorded} />)
    expect(screen.getByText('Under acme.test, which this workspace verified with a DNS TXT record.')).toBeInTheDocument()
    const seen = screen.getByRole('list', { name: 'Where this name was seen' })
    expect(within(seen).getAllByRole('listitem').map((item) => item.textContent)).toEqual([
      expect.stringMatching(/^Named in your website certificate, first seen .+, last seen .+$/),
      expect.stringMatching(/^DNS lookup \(extended name list\), seen .+$/),
    ])
    const dns = screen.getByRole('region', { name: 'DNS answer' })
    expect(within(dns).getByText('IPv4 (A)')).toBeInTheDocument()
    expect(within(dns).getByText('The name exists but has no address of this type')).toBeInTheDocument()
    expect(within(dns).getByText('2001:db8::6')).toBeInTheDocument()
    const web = screen.getByRole('region', { name: 'Web service' })
    expect(web).toHaveTextContent('HTTPS on port 443: Answered with HTTP 200')
    expect(web).toHaveTextContent('The web request does not record whether it connected over IPv4 or IPv6.')
    const findings = screen.getByRole('region', { name: 'Findings' })
    expect(findings).toHaveTextContent('Sensitive Management Tool Exposed')
    expect(findings).toHaveTextContent('Measured: HTTPS port 443 answered with HTTP 200 and the page title "phpMyAdmin"')
    expect(findings).toHaveTextContent('Check exposure.sensitive_tool, version 2026.10.1: A request to the host returns the interface')
    const gaps = screen.getByRole('region', { name: 'Not checked' })
    expect(within(gaps).getAllByRole('listitem')).toHaveLength(2)
    expect(gaps).toHaveTextContent('an answer is not proof the service works over IPv6')
  })

  it('never reads zero findings as no risk', () => {
    render(<AssetEvidence evidence={{ ...recorded, findings: { measured_at: recorded.findings.measured_at, items: [], more: 0 } }} />)
    const findings = screen.getByRole('region', { name: 'Findings' })
    expect(findings).toHaveTextContent('No finding was raised from these measurements. Anything listed under Not checked was not assessed.')
    expect(findings).not.toHaveTextContent(/no risk|secure|safe/i)
  })

  it('says when a name predates per-name evidence and invents none', () => {
    render(<AssetEvidence evidence={{
      version: 'asset-evidence-v1',
      status: 'not_recorded',
      customer_message: 'This name was recorded before CyberMeters kept per-name evidence. DNS, web and finding evidence appear from the next scan that checks it.',
      scope: { state: 'in_scope', label: 'Under acme.test, which this workspace verified.' },
      seen_in: { status: 'not_recorded', first_source: 'dns_bruteforce', sources: [], note: 'Where this name was seen is recorded per source from its next scan. Until then only the source that first found it is known.' },
      dns: { status: 'not_recorded', checked_at: null },
      service: { status: 'not_recorded', checked_at: null },
      findings: null,
      not_checked: [{ part: 'other_ports', label: "Only HTTPS (port 443) and HTTP (port 80) are requested. Other ports are not scanned without the owner's permission." }],
    }} />)
    expect(screen.getByText(/recorded before CyberMeters kept per-name evidence/)).toBeInTheDocument()
    expect(screen.getByText('DNS lookup')).toBeInTheDocument()
    expect(screen.getByText(/\(the source that first found it\)/)).toBeInTheDocument()
    expect(screen.queryByRole('region', { name: 'DNS answer' })).not.toBeInTheDocument()
    expect(screen.queryByRole('region', { name: 'Web service' })).not.toBeInTheDocument()
    expect(screen.queryByRole('region', { name: 'Findings' })).not.toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'Not checked' })).toBeInTheDocument()
  })

  it('states names not measured recently instead of showing an empty answer', () => {
    render(<AssetEvidence evidence={{ ...recorded, dns: { status: 'not_checked', checked_at: null }, service: { status: 'not_checked', checked_at: null } }} />)
    expect(screen.getByRole('region', { name: 'DNS answer' })).toHaveTextContent('DNS was not asked about this name in the recent scans.')
    expect(screen.getByRole('region', { name: 'Web service' })).toHaveTextContent('No web request was made to this name in the recent scans.')
  })

  it('shows the backend message when evidence could not be read, and nothing without evidence', () => {
    const { container, rerender } = render(<AssetEvidence evidence={{ version: 'asset-evidence-v1', status: 'unavailable', customer_message: 'Evidence for this name could not be read.' }} />)
    expect(screen.getByText('Evidence for this name could not be read.')).toBeInTheDocument()
    rerender(<AssetEvidence evidence={undefined} />)
    expect(container).toBeEmptyDOMElement()
  })
})
