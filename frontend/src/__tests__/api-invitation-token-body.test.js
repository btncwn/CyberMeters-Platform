import { afterEach, describe, expect, it, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { api } from '../api'

// Invitation token out of the API request path (founder, 20 Oct 2026): access
// logs and analytics record request paths, so the token travels in the JSON
// body of a POST and never appears in any URL the app requests.

const TOKEN = `cmi_${'a'.repeat(64)}`

afterEach(() => vi.unstubAllGlobals())

function stubFetch(body) {
  const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } }))
  vi.stubGlobal('fetch', fetch)
  return fetch
}

describe('invitation token never appears in a request URL', () => {
  it.each([
    ['preview', () => api.getInvitationPreview(TOKEN), '/invitations/preview'],
    ['accept', () => api.acceptWorkspaceInvitation(TOKEN), '/invitations/accept'],
  ])('%s sends the token in the POST body only', async (_, call, path) => {
    const fetch = stubFetch({ success: true })
    await call()
    expect(fetch).toHaveBeenCalledTimes(1)
    const [url, init] = fetch.mock.calls[0]
    expect(String(url).endsWith(path)).toBe(true)
    expect(String(url)).not.toContain(TOKEN)
    expect(String(url)).not.toContain(encodeURIComponent(TOKEN))
    expect(init.method).toBe('POST')
    expect(JSON.parse(init.body)).toEqual({ token: TOKEN })
  })

  it('no API call builds an invitation path from a token', () => {
    const source = readFileSync(resolve(__dirname, '../api.js'), 'utf8')
    expect(source).not.toMatch(/`\/invitations\/\$\{/)
  })
})
