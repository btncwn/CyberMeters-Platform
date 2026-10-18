// Invitation flow helpers (P1, 18 Oct 2026) — presentation and routing only.
//
// The invitation must survive signup → email verification → login, and the
// accept screen must never show a raw API error. The return path is accepted
// ONLY when it is exactly /invitations/cmi_<64 hex> (the same allow-list the
// Worker applies), so it can never become an open redirect.
export const INVITATION_PATH_RE = /^\/invitations\/cmi_[0-9a-f]{64}$/
export const PENDING_INVITE_KEY = 'cybermeters_pending_invite'
const DISMISSED_KEY = 'cybermeters_invite_dismissed'

export function invitationPathFor(token) {
  const path = `/invitations/${String(token || '')}`
  return INVITATION_PATH_RE.test(path) ? path : null
}

/** The path if it is an allow-listed invitation path, else null. */
export function safeInvitationPath(value) {
  const path = typeof value === 'string' ? value.trim() : (value?.pathname || '')
  return INVITATION_PATH_RE.test(path) ? path : null
}

export function tokenFromInvitationPath(path) {
  const safe = safeInvitationPath(path)
  return safe ? safe.slice('/invitations/'.length) : null
}

// ── The pending invitation this browser has seen (safety net) ────────────────
function storage() { try { return window.localStorage } catch { return null } }
export function rememberPendingInvite(token) {
  if (!invitationPathFor(token)) return
  try { storage()?.setItem(PENDING_INVITE_KEY, token) } catch { /* storage unavailable */ }
}
export function pendingInviteToken() {
  try {
    const token = storage()?.getItem(PENDING_INVITE_KEY)
    return invitationPathFor(token) ? token : null
  } catch { return null }
}
export function clearPendingInvite() {
  try { storage()?.removeItem(PENDING_INVITE_KEY) } catch { /* storage unavailable */ }
}
/** "Not now" hides the banner for this browser session only. */
export function dismissPendingInvite(token) {
  try { window.sessionStorage.setItem(DISMISSED_KEY, token) } catch { /* storage unavailable */ }
}
export function isPendingInviteDismissed(token) {
  try { return window.sessionStorage.getItem(DISMISSED_KEY) === token } catch { return false }
}

// ── Plain-English errors for accepting an invitation ─────────────────────────
// The API answers with short internal strings ("Unauthorized", "Invitation is
// cancelled", HTTP statuses). None of them may reach the screen.
export const INVITATION_ERRORS = Object.freeze({
  sign_in_required: 'Sign in with the invited email address to accept this invitation.',
  email_mismatch: 'This invitation was sent to a different email address. Sign out and continue with the invited address.',
  expired: 'This invitation has expired. Ask the person who invited you to send a new one.',
  already_accepted: 'This invitation has already been accepted. Sign in to open the workspace.',
  revoked: 'This invitation was withdrawn by the workspace. Ask them to send a new one if you still need access.',
  not_found: 'This invitation link is not valid. Check the link in your email, or ask for a new invitation.',
  member_limit: 'The workspace has reached its member limit. Ask the workspace owner to free a seat or upgrade their plan.',
  unavailable: 'The invitation could not be accepted right now. Please try again in a moment.',
})

/** Map an accept/preview failure to one of INVITATION_ERRORS' keys. */
export function invitationErrorKind(error) {
  const status = Number(error?.status) || 0
  const text = String(error?.code || error?.error || error?.message || '').toLowerCase()
  if (text.includes('plan_limit') || text.includes('member limit')) return 'member_limit'
  if (text.includes('does not match') || text.includes('email mismatch') || text.includes('different email')) return 'email_mismatch'
  // A lapsed session is a sign-in problem, not an expired invitation.
  if (status === 401 || text.includes('unauthorized') || text.includes('session expired') || text.includes('sign in')) return 'sign_in_required'
  if (status === 410 || text.includes('expired')) return 'expired'
  if (text.includes('accepted')) return 'already_accepted'
  if (text.includes('cancel') || text.includes('revok') || text.includes('withdrawn')) return 'revoked'
  if (status === 404 || text.includes('not found')) return 'not_found'
  if (status === 403) return 'email_mismatch'
  return 'unavailable'
}

export function invitationErrorMessage(error) {
  return INVITATION_ERRORS[invitationErrorKind(error)]
}
