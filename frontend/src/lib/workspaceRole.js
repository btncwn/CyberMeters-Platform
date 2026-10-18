// Workspace role → what the UI offers (18 Oct 2026). ONE place in the frontend
// for the permission rule. It mirrors the backend's ROLE_RANK and
// PERMISSION_MIN_ROLE (workers/scan-api/src/index.js) for the permissions the UI
// gates on; a validator keeps the two identical. The backend stays the
// authority: this only decides what to offer, and an unknown role offers what
// it always did (the backend refuses, and the refusal reads in plain English).

export const ROLE_RANK = Object.freeze({ viewer: 0, analyst: 1, admin: 2, owner: 3 })

export const PERMISSION_MIN_ROLE = Object.freeze({
  'domain:add': 'admin',
  'domain:verify': 'admin',
  'domain:remove': 'admin',
  'scan:create': 'analyst',
})

/** true / false for a known role; null when the role is unknown. */
export function roleCan(role, permission) {
  const rank = ROLE_RANK[String(role || '').toLowerCase()]
  const min = ROLE_RANK[PERMISSION_MIN_ROLE[permission]]
  if (rank === undefined || min === undefined) return null
  return rank >= min
}

/**
 * Scanning a typed domain adds it to the workspace and proves ownership first,
 * so it needs the domain permissions as well as scan:create. Only a known role
 * that lacks them is refused; an unknown role is offered the box as before.
 */
export function canScanNewDomain(role) {
  const checks = ['domain:add', 'domain:verify', 'scan:create'].map((p) => roleCan(role, p))
  if (checks.some((c) => c === null)) return true
  return checks.every(Boolean)
}

/**
 * Rescanning a domain this workspace has already verified needs scan:create
 * only — the analyst's job (decision, 18 Oct 2026). Unknown role: offered.
 */
export function canRescanVerifiedDomain(role) {
  const can = roleCan(role, 'scan:create')
  return can === null ? true : can
}

/**
 * What the UI offers for scanning: 'full' (add, verify and scan any domain),
 * 'rescan' (rescan already-verified domains only) or 'none'.
 */
export function scanAccessFor(role) {
  if (canScanNewDomain(role)) return 'full'
  return canRescanVerifiedDomain(role) ? 'rescan' : 'none'
}

/** The role on the active workspace from the workspace list the API returns. */
export function activeWorkspaceRole(workspaces, wsId) {
  const ws = (Array.isArray(workspaces) ? workspaces : []).find((w) => w?.id === wsId)
  return ws?.role ? String(ws.role).toLowerCase() : null
}

/** The sentence for a member who can rescan verified domains but not add new ones. */
export const RESCAN_ONLY_MESSAGE = 'Only workspace admins can add new domains. You can rescan domains this workspace has already verified.'

/** The one sentence for a member who cannot add domains or start scans. */
export function scanNotPermittedMessage(ownerName) {
  const who = String(ownerName || '').trim() || 'the workspace owner'
  return `Only workspace admins can add domains and start scans. Ask ${who} if you need one scanned.`
}

/**
 * A role refusal from the domain or scan endpoints. The backend's role refusals
 * carry no machine code; a coded 403 (verification required, a plan or domain
 * limit) is a different answer with its own handling, never "ask the owner".
 */
export function isForbidden(err) {
  const forbiddenText = /^forbidden\b/i.test(String(err?.message || ''))
  if (err?.code) return forbiddenText
  return err?.status === 403 || forbiddenText
}
