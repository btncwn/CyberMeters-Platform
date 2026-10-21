import { render, screen, within, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { EmailProtectionOverview, EmailPostureHero, BecExposure, MxRecordsCard, MailTransportCard } from '../WorkspaceEmailProtectionPage'
import { api } from '../../../api'

vi.mock('../../../api', () => ({ BASE: 'https://api.example.test/api', api: { getDmarcIngestEndpoint: vi.fn(), getBecExposureScore: vi.fn(), verifyDmarcDns: vi.fn() } }))

const senders = { senders: [{ id: 'sender-a' }], summary: { total_messages: 119, aligned_messages: 119, failed_messages: 0 } }
const tile = (name) => within(screen.getByText(name).parentElement)
const show = (dmarc) => render(<EmailProtectionOverview wsId="test-workspace" domain="example.test" dmarc={dmarc} senderData={senders} />)

beforeEach(() => { api.getDmarcIngestEndpoint.mockResolvedValue({ endpoint: null }) })

describe('Email overview message evidence scope', () => {
  it('separates auto-ingested DMARC compliance from uploaded BEC evidence and shows the BEC score once', async () => {
    api.getBecExposureScore.mockResolvedValue({ exposure_score: 24, exposure_level: 'low', evidence: { pass_rate: null, total_messages: 0, reports_received: false }, reasons: [], recommended_actions: [] })
    api.verifyDmarcDns.mockResolvedValue({ status: 'verified', policy: 'none' })
    render(<>
      <EmailPostureHero wsId="test-workspace" domain="example.test" dmarc={{ traffic_by_source: { auto_ingested: { total_messages: 46, pass_rate: 100 }, customer_uploaded: { total_messages: 0, pass_rate: null } } }} />
      <BecExposure wsId="test-workspace" domain="example.test" />
    </>)
    expect(screen.getByText('Automatically ingested RUA · DMARC compliance')).toBeInTheDocument()
    expect(screen.getByText('100%')).toBeInTheDocument()
    expect(screen.getByText(/of 46 messages passed/)).toBeInTheDocument()
    expect(await screen.findByText('Pass rate in reports you uploaded: not measured')).toBeInTheDocument()
    await waitFor(() => expect(screen.getAllByText(/24\/100/)).toHaveLength(1))
  })
  it('labels the 46-message traffic block from the auto-received RUA source', () => {
    show({ period_days: 30, traffic: { total_messages: 46, aligned_messages: 46, failed_messages: 0 },
      traffic_by_source: { auto_ingested: { total_messages: 46 }, customer_uploaded: { total_messages: 0 } } })
    const observed = tile('Messages observed')
    expect(observed.getByText('46')).toBeInTheDocument()
    expect(observed.getByText(/automatically received RUA reports/)).toBeInTheDocument()
    expect(observed.queryByText(/customer-uploaded reports/)).not.toBeInTheDocument()
  })
  it('keeps reporting-window totals and alignment counts together despite a larger sender inventory', () => {
    show({ period_days: 30, traffic: { total_messages: 33, aligned_messages: 31, failed_messages: 2 } })
    expect(tile('Messages observed').getByText('33')).toBeInTheDocument()
    expect(tile('Aligned messages').getByText('31')).toBeInTheDocument()
    expect(tile('Unaligned messages').getByText('2')).toBeInTheDocument()
    expect(screen.queryByText('119')).not.toBeInTheDocument()
    expect(screen.getAllByText(/Last 30 days/)).toHaveLength(3)
  })

  it('keeps a measured empty period at zero instead of borrowing older evidence', () => {
    show({ period_days: 7, traffic: { total_messages: 0, aligned_messages: 0, failed_messages: 0 } })
    for (const name of ['Messages observed', 'Aligned messages', 'Unaligned messages']) expect(tile(name).getByText('0')).toBeInTheDocument()
    expect(screen.queryByText('119')).not.toBeInTheDocument()
  })

  it('leaves missing window counts unknown even when sender inventory is available', () => {
    show({ period_days: 30, traffic: { total_messages: 33 } })
    expect(tile('Messages observed').getByText('33')).toBeInTheDocument()
    expect(tile('Aligned messages').getByText('Waiting')).toBeInTheDocument()
    expect(tile('Unaligned messages').getByText('Waiting')).toBeInTheDocument()
  })

  it('does not substitute inventory counters when the reporting summary is unavailable', () => {
    show(null)
    for (const name of ['Messages observed', 'Aligned messages', 'Unaligned messages']) expect(tile(name).getByText('Waiting')).toBeInTheDocument()
    expect(screen.queryByText('119')).not.toBeInTheDocument()
  })
})

describe('Email authentication MX records', () => {
  it('shows MX records from the already loaded intelligence module without claiming STARTTLS was tested', () => {
    render(<MxRecordsCard intelligence={{ starttls: { mx_records: [{ host: 'mail.example.test', priority: 10 }] } }} />)
    expect(screen.getByText('mail.example.test · priority 10')).toBeInTheDocument()
    expect(screen.getByText(/Mail transport was not tested in this scan/)).toBeInTheDocument()
  })

  it('distinguishes unavailable MX evidence from an observed empty list', () => {
    const view = render(<MxRecordsCard intelligence={null} />)
    expect(screen.getByText('MX evidence was not available in this assessment.')).toBeInTheDocument()
    view.rerender(<MxRecordsCard intelligence={{ starttls: { mx_records: [] } }} />)
    expect(screen.getByText('No MX records were recorded in this assessment.')).toBeInTheDocument()
  })
})

describe('Mail transport encryption', () => {
  it('shows completed STARTTLS evidence and keeps MTA-STS and TLS-RPT distinct', () => {
    render(<MailTransportCard transport={{ hosts: [{host:'mail.example.test',state:'tested',starttls_offered:true,
      tls_version:'tls1_3',cipher:'TLS_AES_128_GCM_SHA256',cipher_class:'not_flagged_weak',
      certificate_hostname_match:true,chain_validity:'valid',certificate_expires_at:'2026-11-17T00:00:00.000Z'}] }}
      mtaSts={{policy_found:true,mode:'enforce'}} tlsRpt={{record_found:true}} />)
    expect(screen.getByText(/STARTTLS offered · TLS handshake completed/)).toBeInTheDocument()
    expect(screen.getByText(/TLS 1\.3/)).toBeInTheDocument()
    expect(screen.getByText(/enforce policy observed; DNS activation not separately checked/)).toBeInTheDocument()
    expect(screen.getByText(/reporting record observed/)).toBeInTheDocument()
    expect(screen.getByText(/does not prove that all mail delivery is encrypted/)).toBeInTheDocument()
  })

  it('shows absent STARTTLS and unreachable mail servers without a secure claim', () => {
    render(<MailTransportCard transport={{ hosts: [
      {host:'absent.example.test',state:'not_offered',starttls_offered:false},
      {host:'unreachable.example.test',state:'not_tested',starttls_offered:null},
    ] }} mtaSts={{policy_found:false}} tlsRpt={{record_found:false}} />)
    expect(screen.getByText('STARTTLS not offered')).toBeInTheDocument()
    expect(screen.getByText('Not tested — connection or TLS evidence unavailable')).toBeInTheDocument()
    expect(screen.getByText(/enforcement not confirmed/)).toBeInTheDocument()
  })

  it('labels an observed weak cipher', () => {
    render(<MailTransportCard transport={{ hosts: [{host:'weak.example.test',state:'tested',
      tls_version:'tls1_2',cipher:'RC4-SHA',cipher_class:'weak',certificate_hostname_match:false,
      chain_validity:'invalid'}] }} />)
    expect(screen.getByText(/weak cipher/)).toBeInTheDocument()
    expect(screen.getByText(/Hostname mismatched/)).toBeInTheDocument()
    expect(screen.getByText(/Chain invalid/)).toBeInTheDocument()
  })
})
