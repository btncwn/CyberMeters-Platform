import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { beforeEach, describe, it, expect, vi } from 'vitest'
import CertificateLifecyclePage from '../CertificateLifecyclePage'
import { api } from '../../../api'

// Founder, 20 Oct 2026: Verify gave no feedback, could be pressed repeatedly,
// and "Owner missing" read as if the linked case had no owner.

vi.mock('../../../api', () => ({
  api: { getCertificateLifecycle: vi.fn(), certificateLifecycleVerify: vi.fn(), certificateLifecycleAction: vi.fn() },
}))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: () => ({ wsId: 'ws1', loading: false }) }))

const row = {
  certificate_lifecycle_id: 'lc1', primary_hostname: 'shop.example.com', renewal_readiness: 'high', days_remaining: 9,
  coverage_status: 'complete', ownership_status: 'missing', recurrence_type: 'owner_missing',
  verification_status: 'not_verified', renewal_status: 'awaiting_verification',
}

function mount() {
  return render(
    <MemoryRouter initialEntries={['/ws/certificates/lifecycle']}>
      <Routes><Route path="/ws/certificates/lifecycle" element={<CertificateLifecyclePage />} /></Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  api.getCertificateLifecycle.mockResolvedValue({ items: [row], counts: {}, actions: ['request_verification'] })
})

describe('Verify', () => {
  it("shows the verifier's result and its reason in the backend's words", async () => {
    api.certificateLifecycleVerify.mockResolvedValue({ item: { ...row, verification_status: 'inconclusive',
      verification_detail: { verification_result: 'inconclusive', reason: 'The certificate CyberMeters sees is still the previous one. No new certificate has been observed yet.' } } })
    mount()
    fireEvent.click(await screen.findByRole('button', { name: 'Verify' }))
    const result = await screen.findByTestId('verify-result')
    expect(result).toHaveAttribute('role', 'status')
    expect(result).toHaveTextContent('Inconclusive. The certificate CyberMeters sees is still the previous one.')
  })

  it('is disabled while the request runs, and a second press sends nothing', async () => {
    let release
    api.certificateLifecycleVerify.mockImplementation(() => new Promise((resolve) => { release = resolve }))
    mount()
    const button = await screen.findByRole('button', { name: 'Verify' })
    fireEvent.click(button)
    fireEvent.click(button)
    await waitFor(() => expect(screen.getByRole('button', { name: 'Checking…' })).toBeDisabled())
    fireEvent.click(screen.getByRole('button', { name: 'Checking…' }))
    expect(api.certificateLifecycleVerify).toHaveBeenCalledTimes(1)
    await act(async () => { release({ item: { ...row, verification_status: 'verified_replaced', verification_detail: { verification_result: 'verified', reason: 'CyberMeters observed a new, distinct certificate with a later expiry on the expected hostnames.' } } }) })
    expect(await screen.findByTestId('verify-result')).toHaveTextContent('Verified. CyberMeters observed a new, distinct certificate')
    expect(screen.getByRole('button', { name: 'Verify' })).not.toBeDisabled()
  })

  it('a failed request says nothing was changed, never a verdict', async () => {
    api.certificateLifecycleVerify.mockRejectedValue(new Error('network'))
    mount()
    fireEvent.click(await screen.findByRole('button', { name: 'Verify' }))
    expect(await screen.findByTestId('verify-result')).toHaveTextContent('The check could not be run just now. Nothing was changed')
  })
})

describe('owner labels', () => {
  it("names whose owner is missing: the certificate's, not the case's", async () => {
    mount()
    const cell = (await screen.findByText('Certificate owner not set')).closest('td')
    expect(within(cell).getByText('certificate owner not set')).toBeInTheDocument()
    expect(screen.queryByText('Owner missing')).toBeNull()
    expect(screen.queryByText('owner missing')).toBeNull()
  })
})
