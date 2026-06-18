const BASE =
  import.meta.env.VITE_API_BASE_URL ||
  'https://cybermeters-platform.ttrnn47.workers.dev/api'

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.json()
}

export const api = {
  /** GET /api/scans */
  getScans: () => request('/scans'),

  /** GET /api/scans/:id */
  getScan: (id) => request(`/scans/${id}`),

  /** GET /api/scans/:id/report */
  getScanReport: (id) => request(`/scans/${id}/report`),

  /** GET /api/domain/:domain/history */
  getDomainHistory: (domain) => request(`/domain/${encodeURIComponent(domain)}/history`),

  /** POST /api/scan  body: { domain, workspace_id? } */
  createScan: (domain, workspaceId) =>
    request('/scan', {
      method: 'POST',
      body: JSON.stringify({ domain, ...(workspaceId ? { workspace_id: workspaceId } : {}) }),
    }),

  /** GET /api/schedules */
  getSchedules: () => request('/schedules'),

  /** POST /api/schedules  body: { domain, frequency } */
  createSchedule: (domain, frequency) =>
    request('/schedules', {
      method: 'POST',
      body: JSON.stringify({ domain, frequency }),
    }),

  /** DELETE /api/schedules/:id */
  deleteSchedule: (id) =>
    request(`/schedules/${id}`, { method: 'DELETE' }),

  // ── Workspaces ────────────────────────────────────────────────────────

  /** GET /api/workspaces */
  getWorkspaces: () => request('/workspaces'),

  /** POST /api/workspaces  body: { name } */
  createWorkspace: (name) =>
    request('/workspaces', {
      method: 'POST',
      body: JSON.stringify({ name }),
    }),

  /** GET /api/workspaces/:id  (includes stats) */
  getWorkspace: (id) => request(`/workspaces/${id}`),

  /** GET /api/workspaces/:id/domains */
  getWorkspaceDomains: (id) => request(`/workspaces/${id}/domains`),

  /** POST /api/workspaces/:id/domains  body: { domain } */
  addDomainToWorkspace: (workspaceId, domain) =>
    request(`/workspaces/${workspaceId}/domains`, {
      method: 'POST',
      body: JSON.stringify({ domain }),
    }),

  /** DELETE /api/workspaces/:id/domains/:domainId */
  removeDomainFromWorkspace: (workspaceId, domainId) =>
    request(`/workspaces/${workspaceId}/domains/${domainId}`, { method: 'DELETE' }),

  /** GET /api/scans?workspace_id= */
  getWorkspaceScans: (workspaceId) => request(`/scans?workspace_id=${workspaceId}`),

  /**
   * GET /api/workspaces/:id/report
   * Returns a Blob (application/pdf) — bypasses the JSON request() helper.
   */
  getWorkspaceReport: async (id) => {
    const res = await fetch(`${BASE}/workspaces/${id}/report`, {
      headers: { Accept: 'application/pdf' },
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }))
      throw new Error(err.error || `HTTP ${res.status}`)
    }
    return res.blob()
  },
}
