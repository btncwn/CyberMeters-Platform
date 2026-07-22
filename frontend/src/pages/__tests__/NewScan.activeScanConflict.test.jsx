import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import NewScan from '../NewScan'
import { api } from '../../api'
import { friendlyHttpError } from '../../lib/httpErrors'
import { safeErrorMessage } from '../../lib/newScanVerification'

// PR-2 pre-merge contract (409 active-scan conflict).
//
// The backend's admission guard returns the constant customer-safe body
//   { error: 'A scan is already active for this domain.', code: 'active_scan_exists' }
// and the EXISTING frontend pipeline must render that message with no runtime
// change: friendlyHttpError passes a human server string through verbatim,
// request() attaches err.code, and NewScan's catch routes any code that is not
// verification/plan/rate through safeErrorMessage into the inline ErrorAlert.
// This suite proves that chain — if any link starts rewriting, swallowing or
// enriching the message, it reddens here.

vi.mock('../../hooks/useWorkspace', () => ({
  useWorkspace: () => ({ wsId: 'ws_turhan', wsName: 'Turhan Workspace', workspaces: [], loading: false, setWorkspace: () => {} }),
}))

const DOMAIN = 'cybermeters.com'
const DOMAIN_ID = 'domain_31d8ebf3'
const CONFLICT_MESSAGE = 'A scan is already active for this domain.'

// The exact error shape api.request() produces for the backend's 409 body:
// friendlyHttpError keeps the human string as message + status, then request()
// copies err.code across.
const activeScanConflictError = () => {
  const e = friendlyHttpError({ status: 409 }, { error: CONFLICT_MESSAGE, code: 'active_scan_exists' })
  e.code = 'active_scan_exists'
  return e
}

function renderPage() {
  return render(<MemoryRouter><NewScan /></MemoryRouter>)
}

beforeEach(() => {
  vi.restoreAllMocks()
  // Verified domain: Start Scan is enabled and goes straight to createScan.
  vi.spyOn(api, 'getWorkspaceDomains').mockResolvedValue({
    workspace_id: 'ws_turhan',
    domains: [{ domain_id: DOMAIN_ID, domain: DOMAIN, verification_status: 'verified', verified_at: '2026-07-15T10:50:00Z' }],
  })
  vi.spyOn(api, 'createScan').mockResolvedValue({ scan: { id: 'scan_1' } })
})

async function submitScan(u) {
  await u.type(screen.getByRole('textbox'), DOMAIN)
  const btn = screen.getByRole('button', { name: /Start Scan/i })
  await waitFor(() => expect(btn).toBeEnabled())
  await u.click(btn)
}

describe('active_scan_exists renders the canonical message', () => {
  it('shows exactly the backend sentence in the inline error alert', async () => {
    api.createScan.mockRejectedValue(activeScanConflictError())
    const u = userEvent.setup()
    renderPage()
    await submitScan(u)
    expect(await screen.findByText(CONFLICT_MESSAGE)).toBeInTheDocument()
  })

  it('renders no internal identifier, machine code or database detail', async () => {
    api.createScan.mockRejectedValue(activeScanConflictError())
    const u = userEvent.setup()
    renderPage()
    await submitScan(u)
    await screen.findByText(CONFLICT_MESSAGE)
    const dom = document.body.textContent
    expect(dom).not.toMatch(/active_scan_exists/)
    expect(dom).not.toMatch(/scan_[a-z0-9]{4,}/i)
    expect(dom).not.toMatch(/UNIQUE|constraint|SQLITE|D1_/i)
    expect(dom).not.toMatch(/created_at|workspace_id|domain_id/)
  })

  it('does not navigate away or claim success on the conflict', async () => {
    api.createScan.mockRejectedValue(activeScanConflictError())
    const u = userEvent.setup()
    renderPage()
    await submitScan(u)
    await screen.findByText(CONFLICT_MESSAGE)
    expect(screen.queryByText(/Scan started/i)).toBeNull()
  })
})

describe('unrelated 409s keep their existing behaviour', () => {
  it('a different descriptive 409 message still renders verbatim', async () => {
    const other = friendlyHttpError({ status: 409 }, { error: 'Report not ready: scan has not completed' })
    api.createScan.mockRejectedValue(other)
    const u = userEvent.setup()
    renderPage()
    await submitScan(u)
    expect(await screen.findByText('Report not ready: scan has not completed')).toBeInTheDocument()
    expect(screen.queryByText(CONFLICT_MESSAGE)).toBeNull()
  })

  it('a bodyless 409 still degrades to the generic retry copy', () => {
    expect(friendlyHttpError({ status: 409 }, {}).message).toBe('Something went wrong. Please try again.')
  })
})

describe('pipeline links (unit)', () => {
  it('friendlyHttpError passes the canonical sentence through verbatim with status 409', () => {
    const e = friendlyHttpError({ status: 409 }, { error: CONFLICT_MESSAGE, code: 'active_scan_exists' })
    expect(e.message).toBe(CONFLICT_MESSAGE)
    expect(e.status).toBe(409)
  })

  it('safeErrorMessage renders the sentence, never the machine code', () => {
    expect(safeErrorMessage(activeScanConflictError())).toBe(CONFLICT_MESSAGE)
    // Even if only the code survived, the customer sees neutral copy — never
    // the snake_case identifier.
    expect(safeErrorMessage(Object.assign(new Error('active_scan_exists'), { code: 'active_scan_exists' })))
      .toBe('We could not start this scan. Please try again or contact support.')
  })
})
