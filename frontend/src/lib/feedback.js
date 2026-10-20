// "Something wrong?" feedback (founder, 20 Oct 2026). One text box; the page
// path, the build and the last error code on this page are attached. Nothing
// else: no session token, no account id, no query string, no fragment — the
// only personal data is what the visitor types.
//
// Contract with the API (POST /api/feedback): message (1–2000), surface
// (free_scan | free_tool | app), tool (free_tool only), path ("/…", ≤200, no
// ? # whitespace or backslash), build (uuid or "dev"), error_code
// (^[a-z0-9_.-]{1,64}$ or null). 202 sent · 429 rate_limited · anything else
// failed. The server redacts secret-looking path segments too.

import { RUNNING_BUILD_ID } from './appVersion'

export const FEEDBACK_MAX_CHARS = 2000
const ERROR_CODE_RE = /^[a-z0-9_.-]{1,64}$/
const TOOL_RE = /^[a-z0-9-]{1,40}$/
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
// Invitation tokens, 32+ hex or base64url characters: never sent.
const SECRET_SEGMENT_RE = /^(cmi_.*|[0-9a-f]{32,}|[A-Za-z0-9_-]{32,})$/i
const ERROR_MEMORY_MS = 10 * 60 * 1000

let lastError = null

/** Remember the last API error code shown on this path, for a report sent soon after. */
export function noteErrorCode(code, path = currentPath()) {
  const normalised = normaliseErrorCode(code)
  if (normalised) lastError = { code: normalised, path, at: Date.now() }
}

export function recentErrorCode(path = currentPath(), now = Date.now()) {
  return lastError && lastError.path === path && now - lastError.at < ERROR_MEMORY_MS ? lastError.code : null
}

export function normaliseErrorCode(code) {
  if (typeof code !== 'string') return null
  const lower = code.trim().toLowerCase()
  return ERROR_CODE_RE.test(lower) ? lower : null
}

function currentPath() {
  return typeof window === 'undefined' ? '/' : window.location.pathname
}

/** The page path only: no query, no fragment, secret-looking segments redacted. */
export function feedbackPath(pathname = currentPath()) {
  const bare = String(pathname || '/').split(/[?#]/)[0]
  const segments = bare.split('/').map((segment) => {
    let decoded = segment
    try { decoded = decodeURIComponent(segment) } catch { /* keep as is */ }
    return SECRET_SEGMENT_RE.test(decoded) ? ':redacted' : segment
  })
  const path = segments.join('/').replace(/[\s\\]/g, '')
  const safe = path.startsWith('/') ? path : `/${path}`
  return safe.length > 200 ? safe.slice(0, 200) : safe
}

export function buildFeedbackPayload({ message, surface, tool = null, errorCode = null, pathname, build = RUNNING_BUILD_ID } = {}) {
  return {
    message: String(message || '').trim().slice(0, FEEDBACK_MAX_CHARS),
    surface,
    tool: surface === 'free_tool' && typeof tool === 'string' && TOOL_RE.test(tool) ? tool : null,
    path: feedbackPath(pathname),
    build: typeof build === 'string' && UUID_RE.test(build) ? build : 'dev',
    error_code: normaliseErrorCode(errorCode),
  }
}

/** Send a report. Resolves to 'sent', 'rate_limited' or 'failed'; never throws. */
export async function sendFeedback(payload, { base = import.meta.env.VITE_API_BASE_URL || '', fetchImpl = globalThis.fetch } = {}) {
  try {
    const res = await fetchImpl(`${base}/feedback`, {
      method: 'POST',
      cache: 'no-store',
      credentials: 'omit',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
    if (res.status === 202) return 'sent'
    if (res.status === 429) return 'rate_limited'
    return 'failed'
  } catch {
    return 'failed'
  }
}
