import { afterEach, describe, expect, it, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { buildFeedbackPayload, feedbackPath, noteErrorCode, recentErrorCode, sendFeedback } from '../feedback'
import { validateFeedback } from '../../../../workers/scan-api/src/routes/ops-intake.js'

// "Something wrong?" (founder, 20 Oct 2026): the report carries the message,
// the page path, the build and an error code, matching the POST /api/feedback
// contract, and nothing that identifies the visitor unless they type it.

const UUID = '0f8fad5b-d9cb-469f-a165-70867728950e'
const CONTRACT_FIELDS = ['build', 'error_code', 'message', 'path', 'surface', 'tool']

afterEach(() => vi.unstubAllGlobals())

describe('feedback payload', () => {
  it('has exactly the contract fields', () => {
    const payload = buildFeedbackPayload({ message: '  The SPF card says none  ', surface: 'free_tool', tool: 'spf-checker', errorCode: 'Invalid_Domain', pathname: '/tools/spf-checker', build: UUID })
    expect(Object.keys(payload).sort()).toEqual(CONTRACT_FIELDS)
    expect(payload).toEqual({ message: 'The SPF card says none', surface: 'free_tool', tool: 'spf-checker', path: '/tools/spf-checker', build: UUID, error_code: 'invalid_domain' })
  })

  it('never sends a query, a fragment or a secret-looking path segment', () => {
    expect(feedbackPath('/tools/dmarc-checker?d=x#share=abc')).toBe('/tools/dmarc-checker')
    expect(feedbackPath(`/invitations/cmi_${'a'.repeat(64)}`)).toBe('/invitations/:redacted')
    expect(feedbackPath(`/reset-password/${'f'.repeat(64)}`)).toBe('/reset-password/:redacted')
    expect(feedbackPath(`/x/${'Ab_-'.repeat(10)}`)).toBe('/x/:redacted')
    expect(feedbackPath('/workspaces/ws_1/email-protection')).toBe('/workspaces/ws_1/email-protection')
    expect(feedbackPath(`/${'a/'.repeat(150)}`).length).toBeLessThanOrEqual(200)
  })

  it('drops values the API would refuse instead of sending them', () => {
    const payload = buildFeedbackPayload({ message: 'x', surface: 'app', tool: 'spf-checker', errorCode: 'Not a code!', build: 'local' })
    expect(payload.tool).toBeNull()
    expect(payload.error_code).toBeNull()
    expect(payload.build).toBe('dev')
    expect(buildFeedbackPayload({ message: 'y'.repeat(2500), surface: 'app' }).message).toHaveLength(2000)
  })

  it('offers the last error code only on the same page and only for a while', () => {
    noteErrorCode('plan_limit_exceeded', '/workspaces/ws_1/domains')
    expect(recentErrorCode('/workspaces/ws_1/domains')).toBe('plan_limit_exceeded')
    expect(recentErrorCode('/workspaces/ws_1/cases')).toBeNull()
    expect(recentErrorCode('/workspaces/ws_1/domains', Date.now() + 11 * 60 * 1000)).toBeNull()
  })
})

describe('sending', () => {
  it('posts anonymously: no session header, no cookies, path only in the body', async () => {
    localStorage.setItem('cybermeters_auth_token', 'session-secret')
    const fetchImpl = vi.fn().mockResolvedValue(new Response('{"ok":true}', { status: 202 }))
    const payload = buildFeedbackPayload({ message: 'hi', surface: 'app', pathname: '/dashboard', build: UUID })
    await expect(sendFeedback(payload, { base: 'https://api.example/api', fetchImpl })).resolves.toBe('sent')
    const [url, init] = fetchImpl.mock.calls[0]
    expect(url).toBe('https://api.example/api/feedback')
    expect(init.method).toBe('POST')
    expect(init.credentials).toBe('omit')
    expect(Object.keys(init.headers)).toEqual(['Content-Type'])
    expect(init.body).not.toContain('session-secret')
    expect(JSON.parse(init.body)).toEqual(payload)
    localStorage.clear()
  })

  it.each([[202, 'sent'], [429, 'rate_limited'], [404, 'failed'], [400, 'failed'], [503, 'failed']])('HTTP %i → %s', async (status, outcome) => {
    const fetchImpl = vi.fn().mockResolvedValue(new Response('{}', { status }))
    await expect(sendFeedback({}, { fetchImpl })).resolves.toBe(outcome)
  })

  it('a network failure is "failed", never a thrown error', async () => {
    await expect(sendFeedback({}, { fetchImpl: vi.fn().mockRejectedValue(new TypeError('offline')) })).resolves.toBe('failed')
  })
})

describe('privacy policy', () => {
  it('states what a report keeps and for how long', () => {
    const page = readFileSync(resolve(__dirname, '../../pages/PrivacyPage.jsx'), 'utf8')
    expect(page).toMatch(/we keep your message, the page path and the app version for 90 days/)
    expect(page).toMatch(/We do not store your IP address with it, and nothing identifies you unless you type it/)
  })
})

describe('the API accepts what the button sends', () => {
  it.each([
    ['free tool with an error code', { message: 'Wrong record', surface: 'free_tool', tool: 'dmarc-checker', errorCode: 'Lookup_Failed', pathname: '/tools/dmarc-checker', build: UUID }],
    ['free scan, dev build', { message: 'Odd', surface: 'free_scan', errorCode: 'http_429', pathname: '/free-scan', build: null }],
    ['app page with a token in the path', { message: 'Broken', surface: 'app', tool: 'spf-checker', errorCode: 'Not valid!', pathname: `/invitations/cmi_${'b'.repeat(64)}`, build: 'local' }],
  ])('%s', (_, input) => {
    const accepted = validateFeedback(buildFeedbackPayload(input))
    expect(accepted).not.toBeNull()
    expect(accepted.path).not.toMatch(/cmi_/)
  })
})
