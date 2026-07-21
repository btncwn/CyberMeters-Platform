import { render, screen } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { appPath } from '../components/NotificationBell'
import { api } from '../api'
import WorkspaceRelatedChangeDetailPage from '../pages/ws/WorkspaceRelatedChangeDetailPage'

// Workstream C — bounded, non-destructive DOM-XSS safety in jsdom. Proves the two
// frontend defences that matter: React auto-escapes stored/reflected data rendered
// as text, and the alert-deep-link sanitiser (appPath) rejects dangerous targets.
// No browser automation against production; no intrusive payloads.

const XSS = '<script>window.__xss_fired = true</script>'
const IMG = '"><img src=x onerror="window.__xss_fired=true">'

describe('appPath — alert deep-link sanitiser', () => {
  it('accepts a same-origin absolute path', () => {
    expect(appPath('/ws/related-changes/abc')).toBe('/ws/related-changes/abc')
  })
  it('rejects a javascript: URL', () => {
    expect(appPath('javascript:alert(1)')).toBeNull()
  })
  it('rejects a data: URL', () => {
    expect(appPath('data:text/html,<script>alert(1)</script>')).toBeNull()
  })
  it('rejects a protocol-relative URL (//evil.example)', () => {
    expect(appPath('//evil.example/phish')).toBeNull()
  })
  it('rejects a cross-origin absolute URL', () => {
    expect(appPath('https://evil.example/phish')).toBeNull()
  })
  it('rejects non-string / empty input', () => {
    expect(appPath(null)).toBeNull()
    expect(appPath('')).toBeNull()
    expect(appPath({})).toBeNull()
  })
  it('preserves the path + query + hash of a same-origin absolute URL', () => {
    const here = window.location.origin
    expect(appPath(`${here}/scans/1?tab=email#spf`)).toBe('/scans/1?tab=email#spf')
  })
})

vi.mock('../api', () => ({ api: { getRelatedChange: vi.fn() } }))
vi.mock('../hooks/useWorkspace', () => ({
  useWorkspace: () => ({ wsId: 'ws1', wsName: 'Acme', workspaces: [], loading: false }),
}))

describe('React escapes stored data rendered on the Related Changes detail', () => {
  beforeEach(() => { delete window.__xss_fired; api.getRelatedChange.mockReset() })

  it('an XSS payload in evidence / domain is rendered as inert text, never executed', async () => {
    api.getRelatedChange.mockResolvedValue({
      can_manage: false,
      related_change: {
        id: 'rc1', registrable_domain: XSS, rule_id: 'new_host_with_cert',
        direction: 'appeared', signal_family_count: 2, independent_producer_count: 2,
        confidence: 'correlated', completeness: 'complete', customer_state: 'new',
        first_seen: '2026-07-10T00:00:00Z', last_seen: '2026-07-12T00:00:00Z',
        recurrence_count: 1, linked_case_id: null,
      },
      evidence: [
        { producer_family: 'host', source_table: 'assets', source_record_id: 'a-1',
          source_event_type: 'host_appeared', entity_key: IMG,
          observed_at: '2026-07-11T00:00:00Z', evidence_ref: 'ref-1' },
      ],
    })
    const { container } = render(
      <MemoryRouter initialEntries={['/ws/related-changes/rc1']}>
        <Routes><Route path="/ws/related-changes/:id" element={<WorkspaceRelatedChangeDetailPage />} /></Routes>
      </MemoryRouter>,
    )
    await screen.findByText('Related evidence')
    // The payload never executed as script/handler…
    expect(window.__xss_fired).toBeUndefined()
    // …no live <script> or <img onerror> element was injected from the data…
    expect(container.querySelector('script')).toBeNull()
    expect(container.querySelector('img[onerror]')).toBeNull()
    // …and the payload survives as inert TEXT (React-escaped), proving it was
    // rendered, not stripped — the entity_key text node contains the literal string.
    expect(container.textContent).toContain('onerror')
  })
})
