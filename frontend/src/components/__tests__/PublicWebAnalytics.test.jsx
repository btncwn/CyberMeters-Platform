import { render } from '@testing-library/react'
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom'
import { useEffect } from 'react'
import PublicWebAnalytics, { BEACON_ID, BEACON_SRC, DEFAULT_SITE_TOKEN, analyticsToken, isPublicAnalyticsRoute } from '../PublicWebAnalytics'

// Cookieless analytics on the public website only (18 Oct 2026): present on the
// landing page, pricing, free scan, free tools and legal pages; absent on every
// signed-in route, on preview hosts and without a valid site token.

const TOKEN = '0123456789abcdef0123456789abcdef'
const MARKETING = 'cybermeters.com'
const APP = 'app.cybermeters.com'
const beacon = () => document.getElementById(BEACON_ID)

function renderAt(path, hostname, token = TOKEN) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <PublicWebAnalytics hostname={hostname} token={token} />
    </MemoryRouter>,
  )
}

afterEach(() => { beacon()?.remove() })

describe('beacon absent inside the app', () => {
  it.each([
    [APP, '/dashboard'], [APP, '/'], [APP, '/ws/email-protection'], [APP, '/ws/attack-surface?tab=findings'],
    [APP, '/account'], [APP, '/scans/scan_1'], [APP, '/login'], [APP, '/signup'], [APP, '/invitations/cmi_x'],
    [MARKETING, '/dashboard'], [MARKETING, '/ws/email-protection'],
  ])('%s%s', (host, path) => {
    renderAt(path, host)
    expect(beacon()).toBeNull()
    expect(isPublicAnalyticsRoute(host, path)).toBe(false)
  })
})

describe('beacon present on the public website', () => {
  it.each([
    [MARKETING, '/'], [MARKETING, '/tools/dmarc-check'], [MARKETING, '/privacy'], [MARKETING, '/cookies'],
    [APP, '/pricing'], [APP, '/free-scan'], [APP, '/tools/spf-check'], [APP, '/tools'], [APP, '/terms'], [APP, '/dpa'],
    ['www.cybermeters.com', '/'],
  ])('%s%s', (host, path) => {
    renderAt(path, host)
    const s = beacon()
    expect(s).not.toBeNull()
    expect(s.getAttribute('src')).toBe(BEACON_SRC)
    expect(s.getAttribute('type')).toBe('module')
    expect(s.defer).toBe(true)
    expect(JSON.parse(s.getAttribute('data-cf-beacon'))).toEqual({ token: TOKEN, spa: false })
  })
})

describe('never loads by accident', () => {
  it('not on preview or local hosts', () => {
    for (const host of ['localhost', '127.0.0.1', 'pr-680.cybermeters.pages.dev']) {
      renderAt('/pricing', host)
      expect(beacon()).toBeNull()
    }
  })
  it('not without a valid site token', () => {
    for (const t of ['', null, 'not-a-token', `${TOKEN}"}<script>`]) {
      const { unmount } = render(<MemoryRouter initialEntries={['/']}><PublicWebAnalytics hostname={MARKETING} token={t} /></MemoryRouter>)
      expect(beacon()).toBeNull()
      unmount()
    }
    expect(analyticsToken(` ${TOKEN} `)).toBe(TOKEN)
  })
  it('with no override, the committed public site token is used', () => {
    expect(DEFAULT_SITE_TOKEN).toBe('5e0144918d8746b899039b3e0354f9ba')
    expect(analyticsToken()).toBe(DEFAULT_SITE_TOKEN)
    render(<MemoryRouter initialEntries={['/']}><PublicWebAnalytics hostname={MARKETING} /></MemoryRouter>)
    expect(JSON.parse(beacon().getAttribute('data-cf-beacon')).token).toBe(DEFAULT_SITE_TOKEN)
  })
  it('loads once, and a later move into the app adds nothing', () => {
    function GoTo({ to }) { const nav = useNavigate(); useEffect(() => { nav(to) }, [nav, to]); return null }
    render(
      <MemoryRouter initialEntries={['/pricing']}>
        <PublicWebAnalytics hostname={APP} token={TOKEN} />
        <Routes><Route path="/pricing" element={<GoTo to="/dashboard" />} /><Route path="*" element={null} /></Routes>
      </MemoryRouter>,
    )
    expect(document.querySelectorAll(`#${BEACON_ID}`)).toHaveLength(1)
  })
})

describe('the Cookie Policy says so', () => {
  it('section 5 states cookieless public-site analytics, not used inside the app', async () => {
    const { default: CookiePolicyPage } = await import('../../pages/CookiePolicyPage')
    const { getByTestId } = render(<MemoryRouter><CookiePolicyPage /></MemoryRouter>)
    expect(getByTestId('cookieless-analytics')).toHaveTextContent(
      'We use cookieless, privacy-first analytics on our public website to count visits. No cookies, no cross-site tracking, not used inside the app.',
    )
  })
})
