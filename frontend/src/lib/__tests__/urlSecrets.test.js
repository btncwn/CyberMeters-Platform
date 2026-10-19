import { describe, it, expect, vi } from 'vitest'
import {
  captureUrlSecrets, extractUrlSecrets, returnLocation, secretRoute, urlSecret, urlWithSecretsInFragment,
} from '../urlSecrets'

const INVITE = `cmi_${'a'.repeat(64)}`
const HEX = 'f'.repeat(64)
const INTENT = 'i'.repeat(43)

const at = (href) => {
  const u = new URL(href, 'https://app.cybermeters.com')
  return { pathname: u.pathname, search: u.search, hash: u.hash }
}

describe('extractUrlSecrets', () => {
  it.each([
    ['invitation, new link', `/invitations#t=${INVITE}`, { invitationToken: INVITE }, '/invitations'],
    ['invitation, older link', `/invitations/${INVITE}`, { invitationToken: INVITE }, '/invitations'],
    ['password reset, new link', `/reset-password#t=${HEX}`, { resetToken: HEX }, '/reset-password'],
    ['password reset, older link', `/reset-password?token=${HEX}`, { resetToken: HEX }, '/reset-password'],
    ['email verification, new link', `/verify-email#t=${HEX}&next=%2Finvitations%2F${INVITE}`,
      { verificationToken: HEX, invitationReturn: `/invitations/${INVITE}` }, '/verify-email'],
    ['email verification, older redirect', `/verify-email?success=1&next=%2Finvitations%2F${INVITE}`,
      { invitationReturn: `/invitations/${INVITE}` }, '/verify-email?success=1'],
    ['email verification, new redirect', `/verify-email?error=x#next=%2Finvitations%2F${INVITE}`,
      { invitationReturn: `/invitations/${INVITE}` }, '/verify-email?error=x'],
    ['Microsoft one-time code, new redirect', `/auth/microsoft/callback#otc=${HEX}`, { otc: HEX }, '/auth/microsoft/callback'],
    ['Microsoft one-time code, older redirect', `/auth/microsoft/callback?otc=${HEX}`, { otc: HEX }, '/auth/microsoft/callback'],
    ['MCP intent, new link', `/mcp/connect#intent=${INTENT}`, { mcpIntent: INTENT }, '/mcp/connect'],
    ['MCP intent, older link', `/mcp/connect?intent=${INTENT}`, { mcpIntent: INTENT }, '/mcp/connect'],
  ])('%s: reads the secret and leaves no trace of it in the URL', (_, href, secrets, url) => {
    const found = extractUrlSecrets(at(href))
    expect(found.secrets).toEqual(secrets)
    expect(found.url).toBe(url)
    for (const value of Object.values(secrets)) {
      expect(found.url).not.toContain(value)
      expect(found.url).not.toContain(encodeURIComponent(value))
    }
  })

  it('keeps every other query value on a token route', () => {
    expect(extractUrlSecrets(at(`/auth/microsoft/callback?otc=${HEX}&ms_error=x`)).url).toBe('/auth/microsoft/callback?ms_error=x')
  })

  it('leaves URLs without a secret alone', () => {
    for (const href of ['/', '/dashboard?tab=1', '/pricing#faq', '/verify-email?success=1', '/reset-password', '/invitations']) {
      expect(extractUrlSecrets(at(href))).toBeNull()
    }
  })

  it('ignores a value that cannot be a token', () => {
    // …and still removes it from the address.
    expect(extractUrlSecrets(at('/reset-password#t=%20'))).toEqual({ secrets: {}, url: '/reset-password' })
    expect(extractUrlSecrets(at(`/reset-password?token=${'x'.repeat(600)}`))).toEqual({ secrets: {}, url: '/reset-password' })
  })
})

describe('captureUrlSecrets', () => {
  function fakeWindow(href, state = null) {
    const win = {
      location: at(href),
      history: { state, replaceState: vi.fn((next, _title, url) => { win.history.state = next; win.location = at(url) }) },
    }
    return win
  }

  it('replaces the address with the clean URL and keeps the secret in router state', () => {
    const win = fakeWindow(`/reset-password#t=${HEX}`)
    captureUrlSecrets(win)
    expect(win.history.replaceState).toHaveBeenCalledTimes(1)
    expect(`${win.location.pathname}${win.location.search}${win.location.hash}`).toBe('/reset-password')
    expect(win.history.state.usr.urlSecrets).toEqual({ resetToken: HEX })
  })

  it('keeps router state already on the entry (a reload of a cleaned page)', () => {
    const win = fakeWindow(`/invitations/${INVITE}`, { key: 'k1', idx: 0, usr: { from: '/x', urlSecrets: { other: 'y' } } })
    captureUrlSecrets(win)
    expect(win.history.state).toEqual({ key: 'k1', idx: 0, usr: { from: '/x', urlSecrets: { other: 'y', invitationToken: INVITE } } })
  })

  it('does nothing for a URL without a secret', () => {
    const win = fakeWindow('/dashboard?tab=1')
    expect(captureUrlSecrets(win)).toBeNull()
    expect(win.history.replaceState).not.toHaveBeenCalled()
  })

  it('runs before any other application code: it is the first import of main.jsx', async () => {
    const { readFileSync } = await import('node:fs')
    const { resolve } = await import('node:path')
    const main = readFileSync(resolve(__dirname, '../../main.jsx'), 'utf8')
    const firstImport = main.split('\n').find(line => line.startsWith('import '))
    expect(firstImport).toBe("import './lib/urlSecretsOnLoad'")
  })
})

describe('moving a secret inside the app', () => {
  it('turns an invitation or MCP return path into a clean path plus router state', () => {
    expect(secretRoute(`/invitations/${INVITE}`)).toEqual({ to: '/invitations', state: { urlSecrets: { invitationToken: INVITE } } })
    expect(secretRoute(`/mcp/connect?intent=${INTENT}`)).toEqual({ to: '/mcp/connect', state: { urlSecrets: { mcpIntent: INTENT } } })
    expect(secretRoute('/dashboard')).toEqual({ to: '/dashboard', state: undefined })
    expect(secretRoute('/mcp/connect?intent=short')).toEqual({ to: '/mcp/connect?intent=short', state: undefined })
  })

  it('gives login the same return shapes it always used, from router state', () => {
    expect(returnLocation({ pathname: '/invitations', search: '', state: { urlSecrets: { invitationToken: INVITE } } }))
      .toEqual({ pathname: `/invitations/${INVITE}`, search: '' })
    expect(returnLocation({ pathname: '/mcp/connect', search: '', state: { urlSecrets: { mcpIntent: INTENT } } }))
      .toEqual({ pathname: '/mcp/connect', search: `?intent=${INTENT}` })
    expect(returnLocation({ pathname: '/ws/cases', search: '?x=1', state: null })).toEqual({ pathname: '/ws/cases', search: '?x=1' })
  })

  it('forwards to the app host with the secret back in the fragment, never the query', () => {
    const url = urlWithSecretsInFragment('https://app.cybermeters.com', { pathname: '/reset-password', search: '', state: { urlSecrets: { resetToken: HEX } } })
    expect(url).toBe(`https://app.cybermeters.com/reset-password#t=${HEX}`)
    expect(urlWithSecretsInFragment('https://app.cybermeters.com', { pathname: '/login', search: '?a=1' })).toBe('https://app.cybermeters.com/login?a=1')
  })

  it('reads only a well-formed secret from router state', () => {
    expect(urlSecret({ state: { urlSecrets: { otc: HEX } } }, 'otc')).toBe(HEX)
    expect(urlSecret({ state: { urlSecrets: { otc: 42 } } }, 'otc')).toBeNull()
    expect(urlSecret({ state: null }, 'otc')).toBeNull()
  })
})
