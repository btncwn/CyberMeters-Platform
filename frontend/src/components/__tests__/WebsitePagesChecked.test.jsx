import React from 'react'
import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import WebsitePagesChecked from '../WebsitePagesChecked'
import { api } from '../../api'

vi.mock('../../api', () => ({ api: { getWebsiteSecurityPages: vi.fn() } }))

beforeEach(() => { vi.resetAllMocks() })

describe('WebsitePagesChecked', () => {
  it('shows each domain with coverage, sensitive pages and observed facts', async () => {
    api.getWebsiteSecurityPages.mockResolvedValue({
      scope_note: 'This is not a full crawl.',
      domains: [{
        domain_id: 'd1', domain: 'acme.test',
        latest_run: { coverage: 'partial', counts: { observed: 15, max_pages: 15 }, partial_reasons: ['page_limit'] },
        pages: [
          { id: 'p1', path: '/login', sensitive_kind: 'login', monitoring_status: 'observed', first_seen_at: '2026-10-01T00:00:00Z', last_seen_at: '2026-10-11T00:00:00Z',
            observation: { https: true, security_headers: { missing: ['strict-transport-security'] }, forms: [{ action_kind: 'other_origin', action_host: 'collector.example', has_password: true }], cookies: [], mixed_content: { count: 0 }, third_party_scripts: [] } },
          { id: 'p2', path: '/old', sensitive_kind: null, monitoring_status: 'not_found', observation: null },
        ],
      }],
    })
    render(<WebsitePagesChecked workspaceId="ws1" />)
    expect(await screen.findByText('acme.test')).toBeInTheDocument()
    expect(api.getWebsiteSecurityPages).toHaveBeenCalledWith('ws1')
    expect(screen.getByText(/Partial: the page limit was reached/)).toBeInTheDocument()
    expect(screen.getByText('Sign-in page')).toBeInTheDocument()
    expect(screen.getByText('Password form sends to collector.example')).toBeInTheDocument()
    expect(screen.getByText('HSTS header not sent')).toBeInTheDocument()
    expect(screen.getByText('Not found')).toBeInTheDocument()
    expect(screen.getByText('This is not a full crawl.')).toBeInTheDocument()
  })

  it('a load failure is visible, not an empty success', async () => {
    api.getWebsiteSecurityPages.mockRejectedValue(new Error('503'))
    render(<WebsitePagesChecked workspaceId="ws1" />)
    expect(await screen.findByRole('alert')).toHaveTextContent('Pages could not be loaded.')
  })

  it('a domain without pages says so plainly', async () => {
    api.getWebsiteSecurityPages.mockResolvedValue({ domains: [{ domain_id: 'd1', domain: 'acme.test', latest_run: null, pages: [] }] })
    render(<WebsitePagesChecked workspaceId="ws1" />)
    expect(await screen.findByText('No pages recorded for this domain yet.')).toBeInTheDocument()
    expect(screen.getByText(/next full scan/)).toBeInTheDocument()
  })
})
