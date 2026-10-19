import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import DmarcCheckerPage from '../DmarcCheckerPage'
import SpfCheckerPage from '../SpfCheckerPage'
import ToolsIndexPage from '../ToolsIndexPage'

const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

const DMARC_RESULT = {
  schema: 'free-tool-dmarc.v1', tool: 'dmarc', domain: 'example.com', checked_at: '2026-10-19T12:00:00.000Z',
  verdict: { level: 'attention', headline: 'Monitoring only (p=none)', summary: 'Reports are requested, but failing mail is still delivered.' },
  record: { dns_name: '_dmarc.example.com', values: ['v=DMARC1; p=none; rua=mailto:d@example.com'], inherited: false },
  tags: [{ tag: 'p', value: 'none', meaning: 'No action: receivers send reports but deliver failing mail as normal.' }],
  ladder: { steps: [{ policy: 'none', label: 'Monitor', detail: 'p=none' }, { policy: 'quarantine', label: 'Quarantine', detail: 'q' }, { policy: 'reject', label: 'Reject', detail: 'r' }], current: 'none' },
  reporting: { rua: [{ uri: 'mailto:d@example.com', status: 'not_required_same_organisational_domain', label: 'Same organisational domain', message: null }], ruf: [] },
  checked: [{ label: 'Policy', state: 'warn', detail: 'The domain publishes a no-action DMARC policy.' }],
  not_checked: [{ label: 'Whether receivers apply your policy', reason: 'Each receiver decides.' }],
  why_it_matters: 'DMARC tells receiving mail servers what to do.',
  next_step: { title: 'Move from monitoring to quarantine', explanation: 'Changed p=none to p=quarantine.', record: { type: 'TXT', name: '_dmarc.example.com', value: 'v=DMARC1; p=quarantine; rua=mailto:d@example.com' }, cautions: ['Check reports first.'] },
}

const SPF_RESULT = {
  schema: 'free-tool-spf.v1', tool: 'spf', domain: 'example.com', checked_at: '2026-10-19T12:00:00.000Z',
  verdict: { level: 'risk', headline: 'include:gone.example has no SPF record', summary: 'Permanent error.' },
  records: ['v=spf1 include:gone.example ~all'],
  lookups: { used: 1, limit: 10 }, void_lookups: { used: 1, limit: 2 },
  all: { qualifier: '~', label: '~all: other senders soft-fail', detail: 'Soft failure.' },
  tree: { domain: 'example.com', via: 'root', lookups: 1, status: 'evaluated', stopped: null, children: [
    { domain: 'gone.example', via: 'include', lookups: 0, status: 'no_spf_record', stopped: 'included_domain_no_spf', stopped_reason: 'This include points at a domain with no SPF record.', children: [] },
  ] },
  checked: [], not_checked: [], why_it_matters: 'SPF lists the servers allowed to send.',
  next_step: { title: 'Replace the SPF record with this one', explanation: 'Removed include:gone.example.', record: { type: 'TXT', name: 'example.com', value: 'v=spf1 ~all' }, replaces: ['v=spf1 include:gone.example ~all'] },
}

let routes
function installFetch(extra = {}) {
  routes = {
    'GET /tools/config': () => json({ available: true, turnstile_site_key: 'site-key' }),
    ...extra,
  }
  const fetchMock = vi.fn(async (url, init = {}) => {
    const path = String(url).replace(/^.*\/api/, '')
    const handler = routes[`${init.method || 'GET'} ${path}`]
    if (!handler) throw new Error(`unexpected request ${init.method} ${path}`)
    return handler(init.body ? JSON.parse(init.body) : undefined)
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

const renderAt = (ui) => render(<MemoryRouter>{ui}</MemoryRouter>)

async function runCheck(name = /Check DMARC/) {
  fireEvent.change(await screen.findByLabelText('Domain'), { target: { value: 'example.com' } })
  const button = screen.getByRole('button', { name })
  await waitFor(() => expect(button).not.toBeDisabled())
  fireEvent.click(button)
}

beforeEach(() => {
  window.turnstile = {
    render: vi.fn((_el, options) => { options.callback('turnstile-token'); return 'widget-1' }),
    reset: vi.fn(),
    remove: vi.fn(),
  }
  window.history.replaceState({}, '', '/tools/dmarc-checker')
})
afterEach(() => { vi.unstubAllGlobals(); delete window.turnstile })

describe('free tools', () => {
  it('runs the DMARC check with the human-check token and shows verdict, limits of the check and the record to paste', async () => {
    const fetchMock = installFetch({ 'POST /tools/dmarc/check': () => json({ status: 'ok', cached: false, result: DMARC_RESULT, share: { url: 'https://cybermeters.com/tools/dmarc-checker#share=v1.a.b', expires_at: '2026-10-26T12:00:00.000Z' } }) })
    renderAt(<DmarcCheckerPage />)
    await runCheck()
    expect(await screen.findByRole('heading', { name: 'Monitoring only (p=none)' })).toBeInTheDocument()
    const body = JSON.parse(fetchMock.mock.calls.find(([u]) => String(u).endsWith('/tools/dmarc/check'))[1].body)
    expect(body).toEqual({ domain: 'example.com', turnstile_token: 'turnstile-token' })
    expect(window.turnstile.render.mock.calls[0][1]).toMatchObject({ sitekey: 'site-key', action: 'tool_dmarc' })
    expect(screen.getByRole('heading', { name: 'What we could not check' })).toBeInTheDocument()
    expect(screen.getByText('Whether receivers apply your policy.')).toBeInTheDocument()
    expect(screen.getByText('v=DMARC1; p=quarantine; rua=mailto:d@example.com')).toBeInTheDocument()
    expect(screen.getByText(/Monitor — you are here/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Copy share link' })).toBeInTheDocument()
    expect(window.turnstile.reset).toHaveBeenCalled()
  })

  it('shows a used-up allowance as a calm notice with the reset time and a trial offer', async () => {
    installFetch({ 'POST /tools/dmarc/check': () => json({ status: 'limit_reached', scope: 'ip', reset_at: '2026-10-20T09:15:00.000Z', trial_url: 'https://app.cybermeters.com/signup' }, 429) })
    renderAt(<DmarcCheckerPage />)
    await runCheck()
    expect(await screen.findByRole('heading', { name: "That's today's free checks" })).toBeInTheDocument()
    expect(screen.getByText(/You can run another after/)).toBeInTheDocument()
    const notice = screen.getByRole('heading', { name: "That's today's free checks" }).closest('section')
    expect(within(notice).getByRole('link', { name: 'Start a 14-day trial' })).toHaveAttribute('href', 'https://app.cybermeters.com/signup')
  })

  it('on a busy day takes an email with consent instead of turning the visitor away', async () => {
    const fetchMock = installFetch({
      'POST /tools/dmarc/check': () => json({ status: 'capacity_paused', can_defer: true }, 429),
      'POST /tools/dmarc/defer': () => json({ status: 'queued', message: 'We will email the DMARC result for example.com to me@example.com.' }),
    })
    renderAt(<DmarcCheckerPage />)
    await runCheck()
    expect(await screen.findByRole('heading', { name: 'Free checks are very busy today' })).toBeInTheDocument()
    const send = screen.getByRole('button', { name: 'Email me the result' })
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'me@example.com' } })
    expect(send).toBeDisabled()
    fireEvent.click(screen.getByRole('checkbox'))
    await waitFor(() => expect(send).not.toBeDisabled())
    fireEvent.click(send)
    expect(await screen.findByText(/We will email the DMARC result/)).toBeInTheDocument()
    const body = JSON.parse(fetchMock.mock.calls.find(([u]) => String(u).endsWith('/tools/dmarc/defer'))[1].body)
    expect(body).toMatchObject({ domain: 'example.com', email: 'me@example.com', consent: true, turnstile_token: 'turnstile-token' })
  })

  it('says the tools are unavailable when the server has no human check configured', async () => {
    installFetch({ 'GET /tools/config': () => json({ available: false, turnstile_site_key: null }) })
    renderAt(<DmarcCheckerPage />)
    expect(await screen.findByText(/Free checks are not available right now/)).toBeInTheDocument()
    expect(window.turnstile.render).not.toHaveBeenCalled()
  })

  it('opens a shared link only after the server verifies it', async () => {
    window.history.replaceState({}, '', '/tools/dmarc-checker#share=v1.body.sig')
    const fetchMock = installFetch({ 'POST /tools/share': () => json({ status: 'ok', result: DMARC_RESULT, expires_at: '2026-10-26T12:00:00.000Z' }) })
    renderAt(<DmarcCheckerPage />)
    expect(await screen.findByRole('heading', { name: 'Monitoring only (p=none)' })).toBeInTheDocument()
    expect(screen.getByText(/shared link valid until/)).toBeInTheDocument()
    const body = JSON.parse(fetchMock.mock.calls.find(([u]) => String(u).endsWith('/tools/share'))[1].body)
    expect(body).toEqual({ token: 'v1.body.sig' })
  })

  it('an expired shared link says so and still offers a new check', async () => {
    window.history.replaceState({}, '', '/tools/dmarc-checker#share=v1.body.sig')
    installFetch({ 'POST /tools/share': () => json({ status: 'expired_link' }, 400) })
    renderAt(<DmarcCheckerPage />)
    expect(await screen.findByText(/This shared link has expired/)).toBeInTheDocument()
    expect(screen.getByLabelText('Domain')).toBeInTheDocument()
  })

  it('shows the SPF include tree, the lookup budget and the corrected record', async () => {
    window.history.replaceState({}, '', '/tools/spf-checker')
    installFetch({ 'POST /tools/spf/check': () => json({ status: 'ok', cached: true, result: SPF_RESULT, share: null }) })
    renderAt(<SpfCheckerPage />)
    await runCheck(/Check SPF/)
    expect(await screen.findByRole('heading', { name: 'Include tree' })).toBeInTheDocument()
    expect(screen.getByText('include:gone.example')).toBeInTheDocument()
    expect(screen.getByText('This include points at a domain with no SPF record.')).toBeInTheDocument()
    expect(screen.getByRole('img', { name: 'DNS lookups: 1 of 10' })).toBeInTheDocument()
    expect(screen.getByText('v=spf1 ~all')).toBeInTheDocument()
    expect(screen.getByText(/a recent check of the same domain, reused for up to 10 minutes/)).toBeInTheDocument()
  })

  it('the tools index links to both tools', () => {
    vi.stubGlobal('fetch', vi.fn(() => { throw new Error('Unexpected network request') }))
    renderAt(<ToolsIndexPage />)
    expect(screen.getByRole('heading', { level: 1, name: 'Free email security checks' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'DMARC checker' })).toHaveAttribute('href', '/tools/dmarc-checker')
    expect(screen.getByRole('link', { name: 'SPF checker' })).toHaveAttribute('href', '/tools/spf-checker')
    expect(fetch).not.toHaveBeenCalled()
  })
})
