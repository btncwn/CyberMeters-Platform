import { render, screen, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { EmailProtectionOverview } from '../WorkspaceEmailProtectionPage'
import { api } from '../../../api'

vi.mock('../../../api', () => ({ BASE: 'https://api.example.test/api', api: { getDmarcIngestEndpoint: vi.fn() } }))

const senders = { senders: [{ id: 'sender-a' }], summary: { total_messages: 119, aligned_messages: 119, failed_messages: 0 } }
const tile = (name) => within(screen.getByText(name).parentElement)
const show = (dmarc) => render(<EmailProtectionOverview wsId="test-workspace" domain="example.test" dmarc={dmarc} senderData={senders} />)

beforeEach(() => { api.getDmarcIngestEndpoint.mockResolvedValue({ endpoint: null }) })

describe('Email overview message evidence scope', () => {
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
