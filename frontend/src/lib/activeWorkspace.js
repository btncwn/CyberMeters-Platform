// The active workspace this browser shows, and its life across accounts
// (19 Oct 2026).
//
// The active workspace id and name are kept in localStorage so every screen can
// read them. They belong to the signed-in account: signing in as account B after
// account A showed A's workspace name in B's dashboard heading (the API refused
// A's data, so nothing leaked, but the screen named the wrong business). Now
// they are cleared on sign-out and whenever a different account signs in, and
// the stored id is checked against the workspaces the account really has.
//
// Every change goes out as one in-page event, so the heading and the shell
// update in the same tab, not only on another tab's `storage` event.

export const WS_ID_KEY = 'cybermeters_workspace_id'
export const WS_NAME_KEY = 'cybermeters_workspace_name'
export const ACTIVE_WORKSPACE_EVENT = 'cybermeters:active-workspace'
// A domain was added, removed or verified: lists of the workspace's domains refetch (C-47 F04).
export const WORKSPACE_DOMAINS_EVENT = 'cybermeters:workspace-domains-changed'

export function notifyWorkspaceDomainsChanged() {
  try { window.dispatchEvent(new Event(WORKSPACE_DOMAINS_EVENT)) } catch { /* no window */ }
}

// Everything stored about the signed-in account's workspaces. The pending
// invitation and dismissed hints are left alone: they belong to the browser and
// must survive "sign out and continue as the invited address".
const ACCOUNT_WORKSPACE_KEYS = [WS_ID_KEY, WS_NAME_KEY, 'cybermeters_joined_via_invite']

function store() {
  try { return globalThis.localStorage } catch { return null }
}

function notify() {
  try {
    window.dispatchEvent(new Event(ACTIVE_WORKSPACE_EVENT))
    // Older listeners re-read on any `storage` event.
    window.dispatchEvent(new Event('storage'))
  } catch { /* no window (tests, workers) */ }
}

export function readActiveWorkspace() {
  const s = store()
  return { id: s?.getItem(WS_ID_KEY) || null, name: s?.getItem(WS_NAME_KEY) || '' }
}

export function setActiveWorkspace(id, name) {
  const s = store()
  try {
    if (id) {
      s?.setItem(WS_ID_KEY, id)
      s?.setItem(WS_NAME_KEY, name || '')
    } else {
      s?.removeItem(WS_ID_KEY)
      s?.removeItem(WS_NAME_KEY)
    }
  } catch { /* storage unavailable */ }
  notify()
}

/** Sign-out, an expired session, or a different account signing in. */
export function clearAccountWorkspaceState() {
  const s = store()
  for (const key of ACCOUNT_WORKSPACE_KEYS) {
    try { s?.removeItem(key) } catch { /* storage unavailable */ }
  }
  notify()
}

/**
 * The workspace to show from the account's own list: the stored one when the
 * account still has it, else the server default, a workspace it owns, or the
 * first. Null when the account has none.
 */
export function pickActiveWorkspace(workspaces, storedId, defaultId) {
  const list = Array.isArray(workspaces) ? workspaces.filter(w => w?.id) : []
  return list.find(w => w.id === storedId)
    ?? list.find(w => w.id === defaultId)
    ?? list.find(w => w.role === 'owner')
    ?? list[0]
    ?? null
}

/**
 * Check the stored workspace against GET /workspaces once the account is
 * known. Replaces a stale id (another account's, a deleted workspace, lost
 * access) and refreshes a renamed one. A failed request leaves things as they
 * are: the API still refuses data from a workspace the account cannot read.
 */
export async function validateActiveWorkspace(api) {
  let data
  try { data = await api.getWorkspaces() } catch { return null }
  const list = Array.isArray(data?.workspaces) ? data.workspaces : []
  const stored = readActiveWorkspace()
  const pick = pickActiveWorkspace(list, stored.id, data?.default_workspace_id)
  if (!pick) {
    if (stored.id || stored.name) setActiveWorkspace(null, null)
    return null
  }
  if (pick.id !== stored.id || (pick.name || '') !== stored.name) setActiveWorkspace(pick.id, pick.name)
  return pick
}
