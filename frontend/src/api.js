import { TOKEN_KEY } from './context/AuthContext'

const BASE =
  import.meta.env.VITE_API_BASE_URL ||
  'https://cybermeters-platform.ttrnn47.workers.dev/api'

function getAuthHeaders() {
  const token = localStorage.getItem(TOKEN_KEY)
  return token ? { Authorization: `Bearer ${token}` } : {}
}

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...getAuthHeaders(),
    },
    ...options,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.json()
}

export const api = {
  // ── Authentication ────────────────────────────────────────────────────────

  /** POST /api/auth/signup */
  authSignup: (email, password, name) =>
    request('/auth/signup', {
      method: 'POST',
      body: JSON.stringify({ email, password, name }),
    }),

  /** POST /api/auth/login  → { token, user } */
  authLogin: (email, password) =>
    request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    }),

  /** GET /api/auth/me  → { id, email, name, plan } */
  authMe: () => request('/auth/me'),

  /** POST /api/auth/logout */
  authLogout: () => request('/auth/logout', { method: 'POST' }),

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

  // ── Asset Inventory ───────────────────────────────────────────────────────

  /** GET /api/workspaces/:id/assets  (optional ?status=active|inactive &limit=N) */
  getWorkspaceAssets: (id) => request(`/workspaces/${id}/assets?limit=500`),

  /** GET /api/workspaces/:id/assets/summary */
  getWorkspaceAssetsSummary: (id) => request(`/workspaces/${id}/assets/summary`),

  /** GET /api/workspaces/:id/assets/timeline */
  getWorkspaceAssetsTimeline: (id) => request(`/workspaces/${id}/assets/timeline`),

  /** GET /api/workspaces/:id/assets/:assetId */
  getWorkspaceAsset: (workspaceId, assetId) =>
    request(`/workspaces/${workspaceId}/assets/${assetId}`),

  // ── Workspace Intelligence APIs ───────────────────────────────────────────

  /** GET /api/workspaces/:id/scorecard */
  getWorkspaceScorecard: (id) => request(`/workspaces/${id}/scorecard`),

  /** GET /api/workspaces/:id/scorecard/report */
  getWorkspaceScorecardReport: (id) => request(`/workspaces/${id}/scorecard/report`),

  /** GET /api/workspaces/:id/posture */
  getWorkspacePosture: (id) => request(`/workspaces/${id}/posture`),

  /** GET /api/workspaces/:id/posture/timeline */
  getWorkspacePostureTimeline: (id) => request(`/workspaces/${id}/posture/timeline`),

  /** GET /api/workspaces/:id/vendors  optional: ?status=&risk_level=&category= */
  getWorkspaceVendors: (id, params = {}) => {
    const q = new URLSearchParams(params).toString()
    return request(`/workspaces/${id}/vendors${q ? `?${q}` : ''}`)
  },

  /** GET /api/workspaces/:id/vendors/summary */
  getWorkspaceVendorsSummary: (id) => request(`/workspaces/${id}/vendors/summary`),

  /** GET /api/workspaces/:id/third-party-assets */
  getWorkspaceThirdPartyAssets: (id) => request(`/workspaces/${id}/third-party-assets`),

  /** GET /api/workspaces/:id/saas-exposure */
  getWorkspaceSaasExposure: (id) => request(`/workspaces/${id}/saas-exposure`),

  /** GET /api/workspaces/:id/cloud-assets  optional: ?category=&provider= */
  getWorkspaceCloudAssets: (id, params = {}) => {
    const q = new URLSearchParams(params).toString()
    return request(`/workspaces/${id}/cloud-assets${q ? `?${q}` : ''}`)
  },

  /** GET /api/workspaces/:id/admin-surfaces  optional: ?severity=&category= */
  getWorkspaceAdminSurfaces: (id, params = {}) => {
    const q = new URLSearchParams(params).toString()
    return request(`/workspaces/${id}/admin-surfaces${q ? `?${q}` : ''}`)
  },

  /** GET /api/workspaces/:id/certificates */
  getWorkspaceCertificates: (id) => request(`/workspaces/${id}/certificates`),

  /** GET /api/workspaces/:id/certificates/timeline */
  getWorkspaceCertificatesTimeline: (id) => request(`/workspaces/${id}/certificates/timeline`),

  /** GET /api/workspaces/:id/brand-monitoring  optional: ?status=&risk_level=&variant_type= */
  getWorkspaceBrandMonitoring: (id, params = {}) => {
    const q = new URLSearchParams(params).toString()
    return request(`/workspaces/${id}/brand-monitoring${q ? `?${q}` : ''}`)
  },

  /** GET /api/workspaces/:id/brand-monitoring/summary */
  getWorkspaceBrandMonitoringSummary: (id) => request(`/workspaces/${id}/brand-monitoring/summary`),

  /** POST /api/workspaces/:id/brand-monitoring/refresh */
  refreshBrandMonitoring: (id) =>
    request(`/workspaces/${id}/brand-monitoring/refresh`, { method: 'POST' }),

  /** GET /api/workspaces/:id/alerts */
  getWorkspaceAlerts: (id) => request(`/workspaces/${id}/alerts`),

  // ── Workspace Executive Reports ───────────────────────────────────────────

  /** GET /api/workspaces/:id/reports  optional: ?report_type=&status= */
  getWorkspaceReports: (workspaceId, params = {}) => {
    const q = new URLSearchParams(params).toString()
    return request(`/workspaces/${workspaceId}/reports${q ? `?${q}` : ''}`)
  },

  /** POST /api/workspaces/:id/reports/generate  body: { report_type } */
  generateWorkspaceReport: (workspaceId, reportType = 'manual') =>
    request(`/workspaces/${workspaceId}/reports/generate`, {
      method: 'POST',
      body: JSON.stringify({ report_type: reportType }),
    }),

  /** GET /api/workspaces/:id/reports/:reportId */
  getWorkspaceReportById: (workspaceId, reportId) =>
    request(`/workspaces/${workspaceId}/reports/${reportId}`),

  /**
   * Returns the absolute download URL for a report PDF.
   * Use in window.open() or as an <a href>.
   * Not a fetch — the browser handles the download directly.
   */
  getWorkspaceReportDownloadUrl: (workspaceId, reportId) =>
    `${BASE}/workspaces/${workspaceId}/reports/${reportId}/download`,

  // ── Notifications ─────────────────────────────────────────────────────────

  /**
   * GET /api/workspaces/:id/notifications
   * Optional ?status=unread|read  ?limit=N
   */
  getWorkspaceNotifications: (workspaceId, params = {}) => {
    const q = new URLSearchParams(params).toString()
    return request(`/workspaces/${workspaceId}/notifications${q ? `?${q}` : ''}`)
  },

  /**
   * POST /api/workspaces/:id/notifications/:notifId/read
   * Pass notifId = "all" to mark all unread as read.
   */
  markNotificationRead: (workspaceId, notifId) =>
    request(`/workspaces/${workspaceId}/notifications/${notifId}/read`, { method: 'POST' }),

  // ── Domain Ownership Verification ────────────────────────────────────────

  /**
   * POST /api/domains/:id/verification
   * Generate a verification token. Returns DNS + HTML instructions.
   */
  generateDomainVerification: (domainId) =>
    request(`/domains/${domainId}/verification`, { method: 'POST' }),

  /**
   * POST /api/domains/:id/verify
   * Trigger the actual DNS TXT / HTML file check. Returns success/failure detail.
   */
  verifyDomain: (domainId) =>
    request(`/domains/${domainId}/verify`, { method: 'POST' }),

  // ── Customer Onboarding / Workspace Health ───────────────────────────────

  /** GET /api/workspaces/:id/summary */
  getWorkspaceSummary: (id) => request(`/workspaces/${id}/summary`),

  /** GET /api/workspaces/:id/health */
  getWorkspaceHealth: (id) => request(`/workspaces/${id}/health`),

  /** POST /api/workspaces/:id/domains/import  body: { domains: string[] } */
  importWorkspaceDomains: (id, domains) =>
    request(`/workspaces/${id}/domains/import`, {
      method: 'POST',
      body: JSON.stringify({ domains }),
    }),

  // ── Portfolio APIs ────────────────────────────────────────────────────────

  /** GET /api/portfolio/overview */
  getPortfolioOverview: () => request('/portfolio/overview'),

  /** GET /api/portfolio/workspaces */
  getPortfolioWorkspaces: () => request('/portfolio/workspaces'),

  /** GET /api/portfolio/alerts  optional: ?limit=N */
  getPortfolioAlerts: (limit = 50) => request(`/portfolio/alerts?limit=${limit}`),

  /** GET /api/portfolio/trends */
  getPortfolioTrends: () => request('/portfolio/trends'),

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
