/**
 * Build a friendly Error from a non-OK response, hiding technical detail.
 * Prefers a human-readable message from the server; otherwise maps the status
 * class to a calm, actionable message (never a bare "HTTP 500").
 * @param {Response | { status: number }} res
 * @param {any} err  Parsed error body (may be a fallback object).
 * @returns {Error & { status?: number, code?: string, outcome?: string, readiness?: unknown, report_availability?: unknown, domain_id?: string, workspace_id?: string, range_consent?: string }}
 *   domain_id/workspace_id name the EXACT workspace-domain record a scan was
 *   gated on, so the caller can start verification for that record rather than
 *   guessing between duplicate links (see routes/scans.js).
 */
import { customerCodeLabel } from './customerReasonText.js'

// A snake_case machine code ("invalid_json_body") is never customer text.
const MACHINE_CODE = /^[a-z0-9]+(_[a-z0-9]+)+$/

export function friendlyHttpError(res, err) {
  // A human-readable server string ("Invalid email or password") is kept as the
  // message. A machine code the UI switches on ("email_verification_required",
  // "invalid_active_checks") NEVER becomes the message (Executive 24 Oct 2026):
  // it stays on e.error / e.code for callers to switch on, and the message is its
  // customer copy where one exists, else the server's human detail, else the
  // status-based text below.
  const raw = err && typeof err.error === 'string' ? err.error.trim() : ''
  const detail = err && typeof err.message === 'string' ? err.message.trim() : ''
  // Attach the HTTP status so callers can branch (e.g. 403 permission handling)
  // without parsing message strings. Additive — messages are unchanged.
  // domain_id/workspace_id carry the EXACT workspace-domain record a scan was
  // gated on, so the caller can start verification for that record instead of
  // guessing between duplicate links (see routes/scans.js).
  /** @param {Error & { status?: number, code?: string, outcome?: string, readiness?: unknown, report_availability?: unknown, domain_id?: string, workspace_id?: string, range_consent?: string }} e */
  const withStatus = (e) => { e.status = res.status; return e }
  // A bare HTTP status word ("Forbidden", "Unauthorized", …) is a machine token,
  // not a customer message — it leaks raw protocol detail and reads as a bug.
  // When that's all the server gave us, prefer any human-readable `message`, then
  // fall through to the friendly status-based text below. Genuinely descriptive
  // server strings (e.g. "Forbidden — admin role required") still pass through.
  const BARE_HTTP_WORD = /^(forbidden|unauthorized|not found|bad request|internal server error|conflict|too many requests|service unavailable|gateway timeout|method not allowed)$/i
  const isBareWord = BARE_HTTP_WORD.test(raw)
  if (raw && MACHINE_CODE.test(raw)) {
    const humanDetail = detail && !MACHINE_CODE.test(detail) ? detail : null
    const e = withStatus(new Error(customerCodeLabel(raw) || humanDetail || statusText(res.status)))
    e.error = raw
    e.code = raw
    return e
  }
  if (raw && !isBareWord) return withStatus(new Error(raw))
  if (isBareWord && detail) return withStatus(new Error(detail))
  return withStatus(new Error(statusText(res.status)))
}

function statusText(status) {
  if (status >= 500) return 'Something went wrong on our end. Please try again in a moment.'
  if (status === 404) return 'We couldn’t find what you were looking for.'
  if (status === 403) return 'You don’t have access to this. Try switching workspace or contact your admin.'
  if (status === 429) return 'Too many requests right now. Please wait a moment and try again.'
  return 'Something went wrong. Please try again.'
}
