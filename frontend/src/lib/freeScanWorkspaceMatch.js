// Does a domain from the public free scan belong to one of the signed-in
// visitor's own workspaces? Only ever called for a signed-in visitor, and only
// with that visitor's own workspace list, so the page never reveals whether a
// domain is anyone else's. An anonymous visitor gets no extra request at all.

export const MAX_WORKSPACES_CHECKED = 10

export function comparableDomain(value) {
  return String(value || '').trim().toLowerCase().replace(/\.$/, '').replace(/^www\./, '')
}

// { workspace_id, workspace_name, verified } for the first workspace holding
// the domain (a verified link wins), or null. Read failures read as no match,
// so the page falls back to exactly what it shows today.
export async function findOwnWorkspaceForDomain(api, domain) {
  const target = comparableDomain(domain)
  if (!target) return null
  let workspaces
  try {
    workspaces = (await api.getWorkspaces())?.workspaces
  } catch {
    return null
  }
  const list = (Array.isArray(workspaces) ? workspaces : []).filter((ws) => ws?.id).slice(0, MAX_WORKSPACES_CHECKED)
  const results = await Promise.allSettled(list.map((ws) => api.getWorkspaceDomains(ws.id)))
  let found = null
  results.forEach((res, index) => {
    if (res.status !== 'fulfilled') return
    const match = (res.value?.domains || []).find((d) => comparableDomain(d?.domain) === target)
    if (!match) return
    const entry = { workspace_id: list[index].id, workspace_name: list[index].name || 'your workspace', verified: String(match.verification_status || '').toLowerCase() === 'verified' }
    if (entry.verified && !found?.verified) found = entry
    else if (!found) found = entry
  })
  return found
}
