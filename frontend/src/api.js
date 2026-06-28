import { TOKEN_KEY, USER_KEY } from './context/authKeys'

export const BASE = import.meta.env.VITE_API_BASE_URL
if (!BASE) {
  console.error(
    '[CyberMeters] VITE_API_BASE_URL is not set. ' +
    'Add it to your .env file, e.g. VITE_API_BASE_URL=https://api.cybermeters.com'
  )
}

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
 * Handle a 401 response: clear local auth state and let React Router navigate to /login.
 * Fires _onUnauthorized (registered by AuthProvider) to clear React state.
 * ProtectedRoute will redirect to /login once isAuthenticated becomes false.
 * No hard redirect — avoids disruptive page reloads and the logout race condition
 * where background polls (e.g. NotificationBell) trigger a spurious redirect after
 * the user has already clicked "Sign out".
 */
function handleUnauthorized() {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(USER_KEY)
  if (_onUnauthorized) {
    _onUnauthorized()
    // ProtectedRoute handles navigation to /login via React Router
    // once isAuthenticated becomes false. No hard redirect needed.
    return
  }
  // Fallback: _onUnauthorized not yet registered (e.g. called before AuthProvider mounts).
  if (typeof window !== 'undefined' && !window.location.pathname.startsWith('/login')) {
    window.location.href = '/login'
  }
}

/**
 * Fire-and-forget server-side session invalidation using a pre-captured token.
 * Exported for use by Layout.handleLogout(), which snapshots the token and clears
 * local auth state before calling this — preventing the 401 race condition.
 */
export function logoutWithToken(rawToken) {
  if (!rawToken || !BASE) return
  fetch(`${BASE}/auth/logout`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${rawToken}`,
    },
  }).catch(() => {})
}

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    // Disable browser cache so scan status, workspace data, and other dynamic
    // API responses are always fetched fresh. The server also sends Cache-Control:
    // no-store, but belt-and-suspenders prevents stale-while-revalidate surprises.
    cache: 'no-store',
    headers: {
      'Content-Type': 'application/json',
      ...getAuthHeaders(),
    },
    ...options,
  })
  if (res.status === 401) {
    // Only treat this as a session expiry if the client actually had a session.
    // Without a token the 401 means "wrong credentials" (e.g. from the login
    // endpoint), so we surface the server's real error message instead of a
    // misleading "Session expired" string.
    const hadToken = !!localStorage.getItem(TOKEN_KEY)
    if (hadToken) {
      handleUnauthorized()
      throw new Error('Session expired. Please sign in again.')
    }
    const err = await res.json().catch(() => ({ error: 'Authentication failed' }))
    throw new Error(err.error || 'Authentication failed')
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }))
    if (err.error === 'plan_limit_exceeded') {
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('cybermeters:plan-limit', { detail: err }))
      }
      const limitError = new Error('Plan limit reached')
      limitError.code     = 'plan_limit_exceeded'
      limitError.resource = err.resource
      limitError.limit    = err.limit
      limitError.usage    = err.usage
      throw limitError
    }
    // Hourly scan rate limit — route through the same upgrade modal so the
    // user sees one consistent experience rather than a raw error alert.
    if (err.code === 'rate_limit_exceeded') {
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('cybermeters:plan-limit', {
          detail: {
            ...err,
            // Normalise to the shape the modal expects
            error:           'plan_limit_exceeded',
            resource:        err.action ?? 'scans_per_hour',
            upgrade_message: err.upgrade_message ?? 'You have reached the hourly scan limit on your current plan.',
          },
        }))
      }
      const rateError = new Error('Scan limit reached')
      rateError.code = 'rate_limit_exceeded'
      throw rateError
    }
    if (err.error === 'plan_feature_required') {
      const gateError = new Error(`Feature requires upgrade: ${err.feature ?? ''}`)
      gateError.error         = 'plan_feature_required'
      gateError.feature       = err.feature
      gateError.required_plan = err.required_plan
      gateError.upgrade_url   = err.upgrade_url
      throw gateError
    }
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
    if (err.error === 'plan_limit_exceeded') {
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('cybermeters:plan-limit', { detail: err }))
      }
      const limitError = new Error('Plan limit reached')
      limitError.code     = 'plan_limit_exceeded'
      limitError.resource = err.resource
      limitError.limit    = err.limit
      limitError.usage    = err.usage
      throw limitError
    }
    if (err.code === 'rate_limit_exceeded') {
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('cybermeters:plan-limit', {
          detail: {
            ...err,
            error:           'plan_limit_exceeded',
            resource:        err.action ?? 'scans_per_hour',
            upgrade_message: err.upgrade_message ?? 'You have reached the hourly scan limit on your current plan.',
          },
        }))
      }
      const rateError = new Error('Scan limit reached')
      rateError.code = 'rate_limit_exceeded'
      throw rateError
    }
    if (err.error === 'plan_feature_required') {
      const gateError = new Error(`Feature requires upgrade: ${err.feature ?? ''}`)
      gateError.error         = 'plan_feature_required'
      gateError.feature       = err.feature
      gateError.required_plan = err.required_plan
      gateError.upgrade_url   = err.upgrade_url
      throw gateError
    }
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

  /**
   * POST /api/auth/exchange
   * Exchanges the one-time code (OTC) from the Microsoft OAuth redirect for
   * the session bearer token and user metadata. The OTC is valid for 30 seconds
   * and is single-use. Returns { token, id, email, name, plan }.
   */
  exchangeOAuthCode: (code) =>
    request('/auth/exchange', {
      method: 'POST',
      body: JSON.stringify({ code }),
    }),

  /** POST /api/auth/resend-verification → { success } */
  resendVerification: (email) =>
    request('/auth/resend-verification', {
      method: 'POST',
      body: JSON.stringify({ email }),
    }),

  /** POST /api/auth/forgot-password → { success, message } */
  forgotPassword: (email) =>
    request('/auth/forgot-password', {
      method: 'POST',
      body: JSON.stringify({ email }),
    }),

  /** POST /api/auth/reset-password → { success, message } */
  resetPassword: (token, password) =>
    request('/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({ token, password }),
    }),

  // ── MFA / TOTP ─────────────────────────────────────────────────────────────

  /** GET /api/auth/mfa/status → { mfa_enabled, mfa_enabled_at } */
  getMfaStatus: () => request('/auth/mfa/status'),

  /** POST /api/auth/mfa/setup → { otpauth_uri, secret_base32 } */
  setupMfa: () =>
    request('/auth/mfa/setup', { method: 'POST' }),

  /** POST /api/auth/mfa/verify-setup → { success, recovery_codes[] } */
  verifyMfaSetup: (code) =>
    request('/auth/mfa/verify-setup', {
      method: 'POST',
      body: JSON.stringify({ code }),
    }),

  /** POST /api/auth/mfa/challenge → { token, user } (login second factor) */
  mfaChallenge: (challenge_token, code) =>
    request('/auth/mfa/challenge', {
      method: 'POST',
      body: JSON.stringify({ challenge_token, code }),
    }),

  /** POST /api/auth/mfa/recovery-code → { token, user, warning? } */
  mfaRecoveryCode: (challenge_token, recovery_code) =>
    request('/auth/mfa/recovery-code', {
      method: 'POST',
      body: JSON.stringify({ challenge_token, recovery_code }),
    }),

  /** POST /api/auth/mfa/disable → { success } (requires code or password) */
  disableMfa: ({ code = null, password = null } = {}) =>
    request('/auth/mfa/disable', {
      method: 'POST',
      body: JSON.stringify({ code, password }),
    }),

  /** GET /api/scans */
  getScans: () => request('/scans'),

  /** GET /api/scans/:id */
  getScan: (id) => request(`/scans/${id}`),

  /** GET /api/scans/:id/report */
  getScanReport: (id) => request(`/scans/${id}/report`),

  /** GET /api/scans/:id/executive-report-v2 — Intelligence Engine report contract */
  getExecutiveReportV2: (id) => request(`/scans/${id}/executive-report-v2`),

  /** GET /api/platform/accuracy */
  getPlatformAccuracy: () => request('/platform/accuracy'),

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

  /** GET /api/workspaces — returns { workspaces, default_workspace_id } */
  getWorkspaces: () => request('/workspaces'),

  /**
   * POST /api/account/bootstrap
   * Idempotent: creates a default workspace for new users who have none.
   * If the user already has workspaces, returns the first one without creating.
   * Returns { workspace: { id, name, created_at }, created: bool }
   */
  bootstrapWorkspace: () =>
    request('/account/bootstrap', { method: 'POST', body: '{}' }),

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

  /** GET /api/workspaces/:id/executive-dashboard */
  getExecutiveDashboard: (id) => request(`/workspaces/${id}/executive-dashboard`),

  /** GET /api/workspaces/:id/scorecard */
  getWorkspaceScorecard: (id) => request(`/workspaces/${id}/scorecard`),

  /** GET /api/workspaces/:id/scorecard/report */
  getWorkspaceScorecardReport: (id) => request(`/workspaces/${id}/scorecard/report`),

  /** GET /api/workspaces/:id/cyber-essentials-readiness */
  getWorkspaceCyberEssentialsReadiness: (id) =>
    request(`/workspaces/${id}/cyber-essentials-readiness`),

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

  /** GET /api/workspaces/:id/identity-assets  optional: ?identity_type=&provider=&min_risk_score= */
  getWorkspaceIdentityAssets: (id, params = {}) => {
    const q = new URLSearchParams(params).toString()
    return request(`/workspaces/${id}/identity-assets${q ? `?${q}` : ''}`)
  },

  /** GET /api/workspaces/:id/identity-assets/summary */
  getWorkspaceIdentitySummary: (id) => request(`/workspaces/${id}/identity-assets/summary`),

  /** GET /api/workspaces/:id/vendor-relationships */
  getVendorRelationships: (id, params = {}) => {
    const q = new URLSearchParams(params).toString()
    return request(`/workspaces/${id}/vendor-relationships${q ? `?${q}` : ''}`)
  },

  /** GET /api/workspaces/:id/business-risk */
  getWorkspaceBusinessRisk: (id) => request(`/workspaces/${id}/business-risk`),

  /** GET /api/workspaces/:id/supply-chain */
  getWorkspaceSupplyChain: (id) => request(`/workspaces/${id}/supply-chain`),

  // ── Audit Log ─────────────────────────────────────────────────────────────

  /** GET /api/workspaces/:id/audit-events */
  getWorkspaceAuditEvents: (id, filters = {}) => {
    const params = new URLSearchParams()
    if (filters.limit)        params.set('limit',         String(filters.limit))
    if (filters.offset)       params.set('offset',        String(filters.offset))
    if (filters.event_type)   params.set('event_type',    filters.event_type)
    if (filters.actor_user_id) params.set('actor_user_id', filters.actor_user_id)
    if (filters.entity_type)  params.set('entity_type',   filters.entity_type)
    if (filters.entity_id)    params.set('entity_id',     filters.entity_id)
    if (filters.date_from)    params.set('date_from',     filters.date_from)
    if (filters.date_to)      params.set('date_to',       filters.date_to)
    if (filters.search)       params.set('search',        filters.search)
    const qs = params.toString()
    return request(`/workspaces/${id}/audit-events${qs ? `?${qs}` : ''}`)
  },

  /** GET /api/workspaces/:id/audit-events/export?format=csv|json */
  exportWorkspaceAuditEvents: async (id, filters = {}, format = 'csv') => {
    const params = new URLSearchParams({ format })
    if (filters.limit)        params.set('limit',         String(filters.limit))
    if (filters.event_type)   params.set('event_type',    filters.event_type)
    if (filters.actor_user_id) params.set('actor_user_id', filters.actor_user_id)
    if (filters.entity_type)  params.set('entity_type',   filters.entity_type)
    if (filters.entity_id)    params.set('entity_id',     filters.entity_id)
    if (filters.date_from)    params.set('date_from',     filters.date_from)
    if (filters.date_to)      params.set('date_to',       filters.date_to)
    if (filters.search)       params.set('search',        filters.search)
    const res = await fetch(`${BASE}/workspaces/${id}/audit-events/export?${params}`, {
      headers: getAuthHeaders(),
    })
    if (res.status === 401) { handleUnauthorized(); throw new Error('Session expired.') }
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }))
      throw new Error(err.error || `HTTP ${res.status}`)
    }
    return res.blob()
  },

  /** GET /api/workspaces/:id/alerts */
  getWorkspaceAlerts: (id) => request(`/workspaces/${id}/alerts`),

  // ── Workspace Executive Reports ───────────────────────────────────────────

  /** GET /api/workspaces/:id/reports  optional: ?report_type=&status= */
  getWorkspaceReports: (workspaceId, params = {}) => {
    const q = new URLSearchParams(params).toString()
    return request(`/workspaces/${workspaceId}/reports${q ? `?${q}` : ''}`)
  },

  /** GET /api/workspaces/:id/report-retention */
  getWorkspaceReportRetention: (workspaceId) =>
    request(`/workspaces/${workspaceId}/report-retention`),

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

  /** DELETE /api/workspaces/:id/reports/:reportId */
  deleteWorkspaceReport: (workspaceId, reportId) =>
    request(`/workspaces/${workspaceId}/reports/${reportId}`, { method: 'DELETE' }),

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

  /**
   * GET /api/workspaces/:id/notification-preferences
   * Returns { workspace_id, user_id, email_frequency }
   */
  getNotificationPreferences: (workspaceId) =>
    request(`/workspaces/${workspaceId}/notification-preferences`),

  /**
   * PUT /api/workspaces/:id/notification-preferences
   * Body: { email_frequency: 'all_alerts' | 'critical_only' | 'daily_digest' | 'disabled' }
   */
  updateNotificationPreferences: (workspaceId, prefs) =>
    request(`/workspaces/${workspaceId}/notification-preferences`, {
      method: 'PUT',
      body: JSON.stringify(prefs),
    }),

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

  /** GET /api/domains/:id — domain details including verification fields */
  getDomain: (domainId) =>
    request(`/domains/${domainId}`),

  /** POST /api/domains/:id/check-verification — DNS TXT probe only, no status change */
  checkDnsVerification: (domainId) =>
    request(`/domains/${domainId}/check-verification`, { method: 'POST' }),

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
   * GET /api/workspaces/:id/subscription
   * Returns workspace-level subscription state: plan, status, trial_active,
   * trial_remaining_days, trial_start, trial_end, limits, features.
   */
  getWorkspaceSubscription: (workspaceId) =>
    request(`/workspaces/${workspaceId}/subscription`),

  /**
   * GET /api/plans  — public, no auth required
   * Returns static plan metadata: pricing, limits, features.
   */
  getPlans: () => request('/plans'),

  /**
   * GET /api/account/subscription/limits
   * Returns { plan, limits, usage } — current plan limits and usage counts.
   */
  getSubscriptionLimits: () => request('/account/subscription/limits'),

  /**
   * GET /api/account/usage
   * Returns { plan, limits, usage: { workspaces, domains, users } }.
   */
  getAccountUsage: () => request('/account/usage'),

  /** GET /api/billing/plans */
  getBillingPlans: () => request('/billing/plans'),

  /** POST /api/billing/checkout */
  createCheckoutSession: ({ plan, interval = 'monthly', success_url, cancel_url }) =>
    request('/billing/checkout', {
      method: 'POST',
      body: JSON.stringify({ plan, interval, success_url, cancel_url }),
    }),

  /** POST /api/billing/portal */
  createBillingPortalSession: (return_url) =>
    request('/billing/portal', {
      method: 'POST',
      body: JSON.stringify({ return_url }),
    }),

  /** GET /api/account/api-tokens */
  getApiTokens: () => request('/account/api-tokens'),

  /** POST /api/account/api-tokens  body: { name, scope, workspace_id?, expires_at? } */
  createApiToken: ({ name, scope = 'read', workspace_id = null, expires_at = null } = {}) =>
    request('/account/api-tokens', {
      method: 'POST',
      body: JSON.stringify({ name, scope, workspace_id, expires_at }),
    }),

  /** DELETE /api/account/api-tokens/:id */
  revokeApiToken: (id) =>
    request(`/account/api-tokens/${id}`, { method: 'DELETE' }),

  // ── Workspace Storage & Retention ────────────────────────────────────────

  /**
   * GET /api/workspaces/:id/storage
   * Returns { report_count, storage_bytes, storage_mb, retention_days, auto_cleanup }
   */
  getWorkspaceStorage: (workspaceId) =>
    request(`/workspaces/${workspaceId}/storage`),

  /**
   * GET /api/workspaces/:id/retention
   * Returns { retention_days, auto_cleanup, plan, plan_max_days }
   */
  getWorkspaceRetention: (workspaceId) =>
    request(`/workspaces/${workspaceId}/retention`),

  /**
   * PUT /api/workspaces/:id/retention
   * Body: { retention_days, auto_cleanup }
   * Returns updated retention policy.
   */
  updateWorkspaceRetention: (workspaceId, body) =>
    request(`/workspaces/${workspaceId}/retention`, {
      method: 'PUT',
      body: JSON.stringify(body),
    }),

  // ── Account Privacy & Data ──────────────────────────────────────────────

  /**
   * GET /api/account/export
   * Returns the raw Response so the caller can consume the blob for download.
   * Does NOT go through the JSON request() helper — we need the raw Response.
   */
  exportAccountData: () => {
    const headers = { ...getAuthHeaders(), Accept: 'application/json' }
    return fetch(`${BASE}/api/account/export`, { method: 'GET', headers })
  },

  /**
   * POST /api/account/delete-request
   * Submits an account deletion request. Returns { request_id, status, message }.
   */
  requestAccountDeletion: () =>
    request('/account/delete-request', { method: 'POST' }),

  /**
   * POST /api/workspaces/:id/delete-request
   * Submits a workspace deletion request. Returns { request_id, status, message }.
   */
  requestWorkspaceDeletion: (workspaceId) =>
    request(`/workspaces/${workspaceId}/delete-request`, { method: 'POST' }),

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

  /**
   * PATCH /api/workspaces/:id/members/:memberId
   * Body: { role }   role ∈ 'viewer' | 'analyst' | 'admin'
   * Requires owner role.
   */
  updateMemberRole: (workspaceId, memberId, role) =>
    request(`/workspaces/${workspaceId}/members/${memberId}`, {
      method: 'PATCH',
      body: JSON.stringify({ role }),
    }),

  /**
   * DELETE /api/workspaces/:id/invitations/:invitationId
   * Cancel a pending invitation. Requires admin or owner role.
   */
  cancelWorkspaceInvitation: (workspaceId, invitationId) =>
    request(`/workspaces/${workspaceId}/invitations/${invitationId}`, { method: 'DELETE' }),

  /**
   * GET /api/invitations/:token — public preview, no auth required.
   * Returns workspace_name, invited_by_name, role, expires_at, status.
   */
  getInvitationPreview: (token) =>
    request(`/invitations/${encodeURIComponent(token)}`),

  /** POST /api/invitations/:token/accept */
  acceptWorkspaceInvitation: (token) =>
    request(`/invitations/${encodeURIComponent(token)}/accept`, { method: 'POST' }),

  // ── Billing ───────────────────────────────────────────────────────────────

  /** GET /api/billing/plans — public plan metadata, pricing, limits */
  getBillingPlans: () => request('/billing/plans'),

  /**
   * POST /api/billing/checkout
   * Body: { plan, interval, success_url, cancel_url }
   * Returns: { checkout_url, session_id }
   */
  startCheckout: (plan, interval = 'monthly', success_url, cancel_url) =>
    request('/billing/checkout', {
      method: 'POST',
      body: JSON.stringify({ plan, interval, success_url, cancel_url }),
    }),

  /**
   * POST /api/billing/portal
   * Body: { return_url }
   * Returns: { portal_url }
   */
  openBillingPortal: (return_url) =>
    request('/billing/portal', {
      method: 'POST',
      body: JSON.stringify({ return_url }),
    }),

  /**
   * POST /api/workspaces/:id/billing/checkout
   * Workspace-scoped checkout. Workspace owner only.
   * Body: { plan, interval? }  interval defaults to 'monthly'.
   * Returns: { url, session_id }
   */
  startWorkspaceCheckout: (workspaceId, plan, interval = 'monthly') =>
    request(`/workspaces/${workspaceId}/billing/checkout`, {
      method: 'POST',
      body: JSON.stringify({ plan, interval }),
    }),

  /**
   * POST /api/workspaces/:id/billing/portal
   * Opens Stripe Customer Portal for workspace billing management.
   * Workspace owner only. Requires existing Stripe customer.
   * Returns: { url, session_id }
   */
  openWorkspaceBillingPortal: (workspaceId) =>
    request(`/workspaces/${workspaceId}/billing/portal`, {
      method: 'POST',
      body: '{}',
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

  /** GET /api/portfolio/risk — MSP portfolio risk intelligence */
  getPortfolioRisk: () => request('/portfolio/risk'),

  // ── Account Security ──────────────────────────────────────────────────────

  /** GET /api/account/login-history */
  getLoginHistory: () => request('/account/login-history'),

  /** GET /api/account/sessions */
  getActiveSessions: () => request('/account/sessions'),

  /** POST /api/account/sessions/:id/revoke */
  revokeSession: (sessionId) => request(`/account/sessions/${sessionId}/revoke`, { method: 'POST' }),

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

  // ── Public Free Scan (no auth required) ──────────────────────────────────

  /**
   * POST /api/free-scan
   * Anonymous — no auth token sent.
   * Body: { domain: string }
   * Returns: { domain, score, risk_level, severity_counts, total_findings,
   *            preview_findings, hidden_count, modules_scanned, scanned_at }
   */
  runFreeScan: (domain) =>
    fetch(`${BASE}/api/free-scan`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ domain }),
    }).then(async res => {
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`)
      return data
    }),
}
