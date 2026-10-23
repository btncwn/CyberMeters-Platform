import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import ScanNowButton from '../ScanNowButton'

// Item 15 fix D (Executive, 23 Oct 2026): a scan of a domain that does not
// exist in public DNS reads "could not assess", never "did not complete".
const starter = vi.hoisted(() => ({ value: null }))
vi.mock('../../hooks/useScanStarter', () => ({
  useScanStarter: () => starter.value,
  isActiveScan: (status) => ['queued', 'running', 'processing'].includes(status),
  SCAN_STARTED_TEXT: 'Scan started',
}))

const base = {
  domains: ['lapsed.example'], loadFailed: false, starting: false, note: null, refused: null,
  start: () => {}, canRescan: true, roleKnown: true, ownerName: null,
}

describe('ScanNowButton after a finished scan', () => {
  it('a domain that does not exist: could not assess, never "did not complete"', () => {
    starter.value = { ...base, started: { id: 'scan_nx', domain: 'lapsed.example', status: 'failed', outcome: 'domain_not_found' } }
    render(<MemoryRouter><ScanNowButton workspaceId="ws" domain="lapsed.example" /></MemoryRouter>)
    expect(screen.getByText(/Could not assess lapsed\.example: the domain does not exist in public DNS\./)).toBeInTheDocument()
    expect(screen.queryByText(/did not complete/)).toBeNull()
  })

  it('any other failed scan keeps the existing wording', () => {
    starter.value = { ...base, started: { id: 'scan_f', domain: 'lapsed.example', status: 'failed', outcome: null } }
    render(<MemoryRouter><ScanNowButton workspaceId="ws" domain="lapsed.example" /></MemoryRouter>)
    expect(screen.getByText(/The scan of lapsed\.example did not complete\./)).toBeInTheDocument()
  })
})
