import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, expect, it, vi } from 'vitest'
import WorkspaceCasesPage from '../WorkspaceCasesPage'
import { api } from '../../../api'
vi.mock('../../../api', () => ({ api: { getCases: vi.fn() } }))
vi.mock('../../../hooks/useWorkspace', () => ({ useWorkspace: () => ({ wsId: 'ws1', loading: false }) }))
beforeEach(() => { api.getCases.mockReset(); api.getCases.mockResolvedValue({ cases: [] }) })
it('carries the service link into the existing queue and lets the customer switch services', async () => {
  render(<MemoryRouter initialEntries={['/ws/cases?domain_key=website_security']}><WorkspaceCasesPage /></MemoryRouter>)
  await waitFor(() => expect(api.getCases).toHaveBeenLastCalledWith('ws1', { domain_key: 'website_security', limit: 100 }))
  fireEvent.change(screen.getByLabelText('Filter cases by service'), { target: { value: 'email_protection' } })
  await waitFor(() => expect(api.getCases).toHaveBeenLastCalledWith('ws1', { domain_key: 'email_protection', limit: 100 }))
})
it('ignores an unsupported service filter', async () => {
  render(<MemoryRouter initialEntries={['/ws/cases?domain_key=unrecognised']}><WorkspaceCasesPage /></MemoryRouter>)
  await waitFor(() => expect(api.getCases).toHaveBeenLastCalledWith('ws1', { limit: 100 }))
})
