import {
  INVITATION_ERRORS, invitationErrorKind, invitationErrorMessage, safeInvitationPath, invitationPathFor,
  tokenFromInvitationPath, rememberPendingInvite, pendingInviteToken, clearPendingInvite,
  dismissPendingInvite, isPendingInviteDismissed,
} from '../invitationFlow'

// The invitation must survive signup → verification → login, only through an
// allow-listed /invitations/cmi_<64 hex> path, and no raw API error may render.

const TOKEN = `cmi_${'a'.repeat(64)}`

describe('invitation return path allow-list', () => {
  it('accepts exactly /invitations/cmi_<64 hex>', () => {
    expect(safeInvitationPath(`/invitations/${TOKEN}`)).toBe(`/invitations/${TOKEN}`)
    expect(safeInvitationPath({ pathname: `/invitations/${TOKEN}` })).toBe(`/invitations/${TOKEN}`)
    expect(invitationPathFor(TOKEN)).toBe(`/invitations/${TOKEN}`)
    expect(tokenFromInvitationPath(`/invitations/${TOKEN}`)).toBe(TOKEN)
  })
  it('rejects anything else — no open redirect', () => {
    for (const bad of ['https://evil.example/invitations/' + TOKEN, '//evil.example', `/invitations/${TOKEN}/../dashboard`, `/invitations/${TOKEN}?x=1`, '/invitations/abc', '/dashboard', '', null, `/invitations/cmi_${'A'.repeat(64)}`]) {
      expect(safeInvitationPath(bad)).toBeNull()
    }
    expect(invitationPathFor('../../x')).toBeNull()
  })
})

describe('accept-invitation errors in plain English', () => {
  const cases = [
    [{ message: 'Session expired. Please sign in again.' }, 'sign_in_required'],
    [{ message: 'Unauthorized', status: 401 }, 'sign_in_required'],
    [{ message: 'Invitation email does not match authenticated user', status: 403 }, 'email_mismatch'],
    [{ message: 'Invitation expired', status: 410 }, 'expired'],
    [{ message: 'Invitation is expired', status: 409 }, 'expired'],
    [{ message: 'Invitation is accepted', status: 409 }, 'already_accepted'],
    [{ message: 'Invitation is cancelled', status: 409 }, 'revoked'],
    [{ message: 'Invitation not found', status: 404 }, 'not_found'],
    [{ message: 'Plan limit reached', code: 'plan_limit_exceeded' }, 'member_limit'],
    [{ message: 'Internal Server Error', status: 500 }, 'unavailable'],
    [{}, 'unavailable'],
  ]
  it.each(cases)('%o → %s', (error, kind) => {
    expect(invitationErrorKind(error)).toBe(kind)
    expect(invitationErrorMessage(error)).toBe(INVITATION_ERRORS[kind])
  })
  it('never returns a raw API string or a status code', () => {
    for (const [error] of cases) {
      const text = invitationErrorMessage(error)
      expect(text).not.toMatch(/Unauthorized|Forbidden|\b(401|403|404|409|410|500)\b|does not match authenticated user|Internal Server Error/)
    }
  })
})

describe('pending invitation memory', () => {
  beforeEach(() => { localStorage.clear(); sessionStorage.clear() })
  it('remembers only a valid token, clears it, and "Not now" lasts for the session', () => {
    rememberPendingInvite('not-a-token')
    expect(pendingInviteToken()).toBeNull()
    rememberPendingInvite(TOKEN)
    expect(pendingInviteToken()).toBe(TOKEN)
    expect(isPendingInviteDismissed(TOKEN)).toBe(false)
    dismissPendingInvite(TOKEN)
    expect(isPendingInviteDismissed(TOKEN)).toBe(true)
    clearPendingInvite()
    expect(pendingInviteToken()).toBeNull()
  })
})
