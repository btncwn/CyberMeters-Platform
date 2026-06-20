import { TOKEN_KEY, USER_KEY } from './context/authKeys'

const BASE =
  import.meta.env.VITE_API_BASE_URL ||
  'https://cybermeters-platform.ttrnn47.workers.dev/api'

function getAuthHeaders() {
  const token = localStorage.getItem(TOKEN_KEY)
  return token ? { Authorization: `Bearer ${token}` } : {}
}

/**
 * Called by AuthProvider on mount to register the logout callback.
 * This lets the module-level request() helper trigger a logout without
 * importing React hooks (which can only be used inside components).
 */
let _onUnauthorized = null
export function registerUnauthorizedHandler(fn) {
  _onUnauthorized = fn
}

/**
 * Validate the current session token against /api/auth/me.
 * Returns the user object on success, or null if the token is missing/expired.
 *
 * Deliberately bypasses the 401 auto-logout handler so AuthContext can
 * manage the React state transition itself (soft React Router redirect
 * instead of a hard window.location redirect, preserving the intended URL).
 */
export async function validateSession() {
  const token = localStorage.getItem(TOKEN_KEY)
  if (!token) return null
  try {
    const res = await fetch(`${BASE}/auth/me`, {
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
    })
    if (!res.ok) return null
    return res.json()
  } catch {
    return null
  }
}

/**
 * Handle a 401 response: clear local auth state and redirect to /login.
 * Fires _onUnauthorized (registered by AuthProvider) to clear React state,
 * then hard-redirects so the router reinitialises with no token.
 */
function handleUnauthorized() {
  // Clear storage directly — safe to call even if _onUnauthorized isn't set yet
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(USER_KEY)
  if (_onUnauthorized) {
    _onUnauthorized()
  }
  // Hard redirect — clears all in-memory React state cleanly
  if (typeof window !== 'undefined' && !window.location.pathname.startsWith('/login')) {
    window.location.href = '/login'
  }
}

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...getAuthHeaders(),
    },
    ...options,
  })
  if (res.status === 401) {
    handleUnauthorized()
    throw new Error('Session expired. Please sign in again.')
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.json()
}

async function requestBlob(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: {
      ...getAuthHeaders(),
    },
    ...options,
  })
  if (res.status === 401) {
    handleUnauthorized()
    throw new Error('Session expired. Please sign in again.')
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.blob()
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

  /** GET /api/workspaces/:id/reports/:reportId/download */
  downloadWorkspaceReport: (workspaceId, reportId) =>
    requestBlob(`/workspaces/${workspaceId}/reports/${reportId}/download`),

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

  // ── Account / Customer Portal ────────────────────────────────────────────

  /**
   * GET /api/account/profile
   * Returns { user, company, subscription }
   */
  getAccountProfile: () => request('/account/profile'),

  /**
   * PATCH /api/account/profile
   * Body: { name }
   */
  updateAccountProfile: (data) =>
    request('/account/profile', {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  /** GET /api/account/company */
  getCompanyProfile: () => request('/account/company'),

  /** PUT /api/account/company */
  updateCompanyProfile: (data) =>
    request('/account/company', {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  /**
   * GET /api/account/subscription
   * Returns manual subscription foundation for the authenticated account.
   */
  getSubscription: () => request('/account/subscription'),

  /**
   * GET /api/account/subscription/limits
   * Returns { plan, limits, usage } — current plan limits and usage counts.
   */
  getSubscriptionLimits: () => request('/account/subscription/limits'),

  /** GET /api/account/api-tokens */
  getApiTokens: () => request('/account/api-tokens'),

  /** POST /api/account/api-tokens  body: { name } */
  createApiToken: (name) =>
    request('/account/api-tokens', {
      method: 'POST',
      body: JSON.stringify({ name }),
    }),

  /** DELETE /api/account/api-tokens/:id */
  revokeApiToken: (id) =>
    request(`/account/api-tokens/${id}`, { method: 'DELETE' }),

  // ── Workspace Activity (Audit Trail) ─────────────────────────────────────

  /**
   * GET /api/workspaces/:id/activity
   * Optional: ?limit=N &offset=N &event_type=X
   */
  getWorkspaceActivity: (workspaceId, params = {}) => {
    const q = new URLSearchParams(params).toString()
    return request(`/workspaces/${workspaceId}/activity${q ? `?${q}` : ''}`)
  },

  // ── Scheduled Reports ────────────────────────────────────────────────────

  /** GET /api/workspaces/:id/scheduled-reports */
  getScheduledReports: (workspaceId) =>
    request(`/workspaces/${workspaceId}/scheduled-reports`),

  /**
   * POST /api/workspaces/:id/scheduled-reports
   * Body: { report_type, frequency }  frequency ∈ 'weekly' | 'monthly' | 'quarterly'
   */
  createScheduledReport: (workspaceId, report_type, frequency) =>
    request(`/workspaces/${workspaceId}/scheduled-reports`, {
      method: 'POST',
      body: JSON.stringify({ report_type, frequency }),
    }),

  /**
   * PATCH /api/workspaces/:id/scheduled-reports/:srId
   * Body: { enabled: boolean }
   */
  updateScheduledReport: (workspaceId, srId, enabled) =>
    request(`/workspaces/${workspaceId}/scheduled-reports/${srId}`, {
      method: 'PATCH',
      body: JSON.stringify({ enabled }),
    }),

  /** DELETE /api/workspaces/:id/scheduled-reports/:srId */
  deleteScheduledReport: (workspaceId, srId) =>
    request(`/workspaces/${workspaceId}/scheduled-reports/${srId}`, { method: 'DELETE' }),

  // ── Workspace Members (RBAC) ─────────────────────────────────────────────

  /** GET /api/workspaces/:id/members  → { members: [...] } */
  getWorkspaceMembers: (workspaceId) =>
    request(`/workspaces/${workspaceId}/members`),

  /**
   * POST /api/workspaces/:id/members
   * Body: { email, role }   role ∈ 'viewer' | 'analyst' | 'admin' | 'owner'
   * Requires owner role.
   */
  addWorkspaceMember: (workspaceId, email, role) =>
    request(`/workspaces/${workspaceId}/members`, {
      method: 'POST',
      body: JSON.stringify({ email, role }),
    }),

  /**
   * DELETE /api/workspaces/:id/members/:memberId
   * Requires owner role.
   */
  removeWorkspaceMember: (workspaceId, memberId) =>
    request(`/workspaces/${workspaceId}/members/${memberId}`, { method: 'DELETE' }),

  /** GET /api/workspaces/:id/invitations */
  getWorkspaceInvitations: (workspaceId) =>
    request(`/workspaces/${workspaceId}/invitations`),

  /**
   * POST /api/workspaces/:id/invitations
   * Body: { email, role }   role ∈ 'viewer' | 'analyst' | 'admin'
   */
  createWorkspaceInvitation: (workspaceId, email, role) =>
    request(`/workspaces/${workspaceId}/invitations`, {
      method: 'POST',
      body: JSON.stringify({ email, role }),
    }),

  /** POST /api/invitations/:token/accept */
  acceptWorkspaceInvitation: (token) =>
    request(`/invitations/${encodeURIComponent(token)}/accept`, { method: 'POST' }),

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
      headers: {
        Accept: 'application/pdf',
        ...getAuthHeaders(),
      },
    })
    if (res.status === 401) {
      handleUnauthorized()
      throw new Error('Session expired. Please sign in again.')
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }))
      throw new Error(err.error || `HTTP ${res.status}`)
    }
    return res.blob()
  },
}
