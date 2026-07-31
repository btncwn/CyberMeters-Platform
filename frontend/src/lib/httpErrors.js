/**
 * Build a friendly Error from a non-OK response, hiding technical detail.
 * Prefers a human-readable message from the server; otherwise maps the status
 * class to a calm, actionable message (never a bare "HTTP 500").
 * @param {Response | { status: number }} res
 * @param {any} err  Parsed error body (may be a fallback object).
 * @returns {Error & { status?: number, code?: string, readiness?: unknown, report_availability?: unknown, domain_id?: string, workspace_id?: string }}
 *   domain_id/workspace_id name the EXACT workspace-domain record a scan was
 *   gated on, so the caller can start verification for that record rather than
 *   guessing between duplicate links (see routes/scans.js).
 */
export function friendlyHttpError(res, err) {
  // Preserve any server-provided error string verbatim. Some are human-readable
  // ("Invalid email or password"); others are machine codes the UI switches on
  // ("email_verification_required", "plan_feature_required"). Rewriting either
  // would break existing flows, so we only synthesise a message when the body is
  // empty — which is exactly the case that used to surface a bare "HTTP 500".
  const raw = err && typeof err.error === 'string' ? err.error.trim() : ''
  const detail = err && typeof err.message === 'string' ? err.message.trim() : ''
  // Attach the HTTP status so callers can branch (e.g. 403 permission handling)
  // without parsing message strings. Additive — messages are unchanged.
  // domain_id/workspace_id carry the EXACT workspace-domain record a scan was
  // gated on, so the caller can start verification for that record instead of
  // guessing between duplicate links (see routes/scans.js).
  /** @param {Error & { status?: number, code?: string, readiness?: unknown, report_availability?: unknown, domain_id?: string, workspace_id?: string }} e */
  const withStatus = (e) => { e.status = res.status; return e }
  // A bare HTTP status word ("Forbidden", "Unauthorized", …) is a machine token,
  // not a customer message — it leaks raw protocol detail and reads as a bug.
  // When that's all the server gave us, prefer any human-readable `message`, then
  // fall through to the friendly status-based text below. Genuinely descriptive
  // server strings (e.g. "Forbidden — admin role required") still pass through.
  const BARE_HTTP_WORD = /^(forbidden|unauthorized|not found|bad request|internal server error|conflict|too many requests|service unavailable|gateway timeout|method not allowed)$/i
  const isBareWord = BARE_HTTP_WORD.test(raw)
  if (raw && !isBareWord) return withStatus(new Error(raw))
  if (isBareWord && detail) return withStatus(new Error(detail))
  if (res.status >= 500) return withStatus(new Error('Something went wrong on our end. Please try again in a moment.'))
  if (res.status === 404) return withStatus(new Error('We couldn’t find what you were looking for.'))
  if (res.status === 403) return withStatus(new Error('You don’t have access to this. Try switching workspace or contact your admin.'))
  if (res.status === 429) return withStatus(new Error('Too many requests right now. Please wait a moment and try again.'))
  return withStatus(new Error('Something went wrong. Please try again.'))
}
