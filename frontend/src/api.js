// @ts-check
import { TOKEN_KEY, USER_KEY } from './context/authKeys'
import { friendlyHttpError } from './lib/httpErrors'

/**
 * Shared API contract types — see src/types/api.d.ts (kept in lockstep with
 * docs/openapi.json and the backend pipeline tests).
 * @typedef {import('./types/api').ApiError} ApiError
 * @typedef {import('./types/api').User} User
 * @typedef {import('./types/api').LoginResponse} LoginResponse
 * @typedef {import('./types/api').MfaStatus} MfaStatus
 * @typedef {import('./types/api').WorkspaceList} WorkspaceList
 * @typedef {import('./types/api').WorkspaceDetail} WorkspaceDetail
 * @typedef {import('./types/api').WorkspaceDomain} WorkspaceDomain
 * @typedef {import('./types/api').NotificationList} NotificationList
 * @typedef {import('./types/api').AuditEventList} AuditEventList
 * @typedef {import('./types/api').ScanList} ScanList
 * @typedef {import('./types/api').Scan} Scan
 * @typedef {import('./types/api').ReportList} ReportList
 * @typedef {import('./types/api').Subscription} Subscription
 * @typedef {import('./types/api').DomainVerification} DomainVerification
 */

// The value MUST end in /api: requests below interpolate BASE and a BARE path
// (`${BASE}${path}`), and the API serves /api/* — so the prefix comes from here.
// The hint printed below is the one a developer copies; without /api it 404s.
export const BASE = import.meta.env.VITE_API_BASE_URL
if (!BASE) {
  console.error(
    '[CyberMeters] VITE_API_BASE_URL is not set. ' +
    'Copy frontend/.env.example to frontend/.env — the value must include the ' +
    'trailing /api, e.g. VITE_API_BASE_URL=https://api.cybermeters.com/api'
  )
}

/** @returns {Record<string, string>} */
function getAuthHeaders() {
  const token = localStorage.getItem(TOKEN_KEY)
  return token ? { Authorization: `Bearer ${token}` } : {}
}

/**
 * Called by AuthProvider on mount to register the logout callback.
 * This lets the module-level request() helper trigger a logout without
 * importing React hooks (which can only be used inside components).
 */
/** @type {(() => void) | null} */
let _onUnauthorized = null
/** @param {() => void} fn */
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
 * @returns {Promise<User | null>}
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
 * @param {string | null | undefined} rawToken
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

/**
 * Wrap fetch so that network-level failures (offline, DNS failure, CORS, the API
 * being unreachable) surface a friendly, actionable message instead of the raw
 * browser "Failed to fetch" / "Load failed" TypeError. Every caller goes through
 * here, so error states across the app stay customer-friendly.
 * @param {string} url
 * @param {RequestInit} [init]
 * @returns {Promise<Response>}
 */
async function safeFetch(url, init) {
  try {
    return await fetch(url, init)
  } catch {
    const netErr = /** @type {ApiError} */ (new Error("We couldn't reach CyberMeters. Please check your internet connection and try again."))
    netErr.code = 'network_error'
    throw netErr
  }
}

/**
 * Authenticated JSON request. Throws an {@link ApiError} on any failure —
 * decorated with status/code/plan-gate context so callers branch on fields,
 * never on message strings.
 * @param {string} path  API path starting with '/'.
 * @param {RequestInit} [options]
 * @returns {Promise<any>}  Parsed JSON body; annotate call sites for shapes.
 */
async function request(path, options = {}) {
  const res = await safeFetch(`${BASE}${path}`, {
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
    // Planned maintenance — the whole API is intentionally down. Announce it so a
    // global overlay can take over, and surface the server's friendly message
    // instead of the bare "maintenance" code.
    if (res.status === 503 && err.code === 'maintenance') {
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('cybermeters:maintenance'))
      }
      const maintErr = /** @type {ApiError} */ (new Error(err.message || 'CyberMeters is undergoing scheduled maintenance and will be back shortly.'))
      maintErr.code = 'maintenance'
      maintErr.status = 503
      throw maintErr
    }
    if (err.error === 'plan_limit_exceeded') {
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('cybermeters:plan-limit', { detail: err }))
      }
      const limitError = /** @type {ApiError} */ (new Error('Plan limit reached'))
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
      const rateError = /** @type {ApiError} */ (new Error('Scan limit reached'))
      rateError.code = 'rate_limit_exceeded'
      throw rateError
    }
    if (err.error === 'plan_feature_required') {
      const gateError = /** @type {ApiError} */ (new Error(`Feature requires upgrade: ${err.feature ?? ''}`))
      gateError.error         = 'plan_feature_required'
      gateError.feature       = err.feature
      gateError.required_plan = err.required_plan
      gateError.upgrade_url   = err.upgrade_url
      throw gateError
    }
    const httpError = friendlyHttpError(res, err)
    // Preserve machine-readable context (e.g. the readiness interlock details
    // from hosted-DMARC policy changes) so callers can branch without
    // string-matching on messages.
    if (err.code) httpError.code = err.code
    if (err.readiness) httpError.readiness = err.readiness
    // Domain-ownership gate: carry the EXACT record the server gated on, so the
    // caller can start verification for that record rather than guessing between
    // duplicate workspace/domain links. Machine-readable context only — the
    // message itself is untouched.
    if (err.error === 'domain_verification_required') {
      httpError.code = 'domain_verification_required'
      httpError.domain_id = err.domain_id
      httpError.workspace_id = err.workspace_id
    }
    throw httpError
  }
  return res.json()
}

/**
 * Authenticated request returning a Blob (PDF/CSV downloads). Same ApiError
 * decoration as request().
 * @param {string} path
 * @param {RequestInit} [options]
 * @returns {Promise<Blob>}
 */
async function requestBlob(path, options = {}) {
  const res = await safeFetch(`${BASE}${path}`, {
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
    // Planned maintenance — the whole API is intentionally down. Announce it so a
    // global overlay can take over, and surface the server's friendly message
    // instead of the bare "maintenance" code.
    if (res.status === 503 && err.code === 'maintenance') {
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('cybermeters:maintenance'))
      }
      const maintErr = /** @type {ApiError} */ (new Error(err.message || 'CyberMeters is undergoing scheduled maintenance and will be back shortly.'))
      maintErr.code = 'maintenance'
      maintErr.status = 503
      throw maintErr
    }
    if (err.error === 'plan_limit_exceeded') {
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('cybermeters:plan-limit', { detail: err }))
      }
      const limitError = /** @type {ApiError} */ (new Error('Plan limit reached'))
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
      const rateError = /** @type {ApiError} */ (new Error('Scan limit reached'))
      rateError.code = 'rate_limit_exceeded'
      throw rateError
    }
    if (err.error === 'plan_feature_required') {
      const gateError = /** @type {ApiError} */ (new Error(`Feature requires upgrade: ${err.feature ?? ''}`))
      gateError.error         = 'plan_feature_required'
      gateError.feature       = err.feature
      gateError.required_plan = err.required_plan
      gateError.upgrade_url   = err.upgrade_url
      throw gateError
    }
    throw friendlyHttpError(res, err)
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
  /**
   * @param {string} email
   * @param {string} password
   * @returns {Promise<LoginResponse>} `{token, user}` or `{mfa_required, challenge_token}`.
   */
  authLogin: (email, password) =>
    request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    }),

  /** GET /api/auth/me  → { id, email, name, plan } */
  /** @returns {Promise<User>} */
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
  /** @returns {Promise<MfaStatus>} */
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
  /**
   * @param {string} challenge_token
   * @param {string} code
   * @returns {Promise<LoginResponse>}
   */
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
  /** @returns {Promise<ScanList>} */
  getScans: () => request('/scans'),

  /** GET /api/scans/:id */
  /** @param {string} id */
  getScan: (id) => request(`/scans/${id}`),

  /** GET /api/scans/:id/report */
  getScanReport: (id) => request(`/scans/${id}/report`),

  /** GET /api/scans/:id/executive-report-v2 — Intelligence Engine report contract */
  getExecutiveReportV2: (id) => request(`/scans/${id}/executive-report-v2`),

  /** GET /api/scans/:id/report/pdf → per-scan PDF (Blob, application/pdf) */
  getScanReportPdf: (id) => requestBlob(`/scans/${id}/report/pdf`),

  /** GET /api/platform/accuracy */
  getPlatformAccuracy: () => request('/platform/accuracy'),

  /** GET /api/domain/:domain/history */
  getDomainHistory: (domain) => request(`/domain/${encodeURIComponent(domain)}/history`),

  /** POST /api/scan  body: { domain, workspace_id? } */
  /**
   * @param {string} domain
   * @param {string} [workspaceId]
   */
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
  /** @returns {Promise<WorkspaceList>} */
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
  /**
   * @param {string} id
   * @returns {Promise<WorkspaceDetail>} `{workspace, stats}`.
   */
  getWorkspace: (id) => request(`/workspaces/${id}`),

  /** GET /api/workspaces/:id/domains */
  /** @param {string} id */
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

  /** GET /api/workspaces/:id/exposure/feed — Exposure Timeline change feed.
   *  params: { limit, offset, severity, category, event_type, hostname, since, until } */
  getExposureFeed: (id, params = {}) => {
    const q = new URLSearchParams(
      Object.entries(params).filter(([, v]) => v != null && v !== '')
    ).toString()
    return request(`/workspaces/${id}/exposure/feed${q ? `?${q}` : ''}`)
  },

  /** GET /api/workspaces/:id/managed-cases — Managed ASM remediation cases */
  getManagedCases: (id, params = {}) => {
    const q = new URLSearchParams(
      Object.entries(params).filter(([, v]) => v != null && v !== '')
    ).toString()
    return request(`/workspaces/${id}/managed-cases${q ? `?${q}` : ''}`)
  },

  /** POST /api/workspaces/:id/managed-cases/:caseId/assign */
  assignManagedCaseOwner: (id, caseId, payload) =>
    request(`/workspaces/${id}/managed-cases/${encodeURIComponent(caseId)}/assign`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  /** POST /api/workspaces/:id/managed-cases/:caseId/transition */
  transitionManagedCase: (id, caseId, payload) =>
    request(`/workspaces/${id}/managed-cases/${encodeURIComponent(caseId)}/transition`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  /** GET /api/workspaces/:id/cases — universal cross-domain managed cases */
  getCases: (id, params = {}) => {
    const q = new URLSearchParams(
      Object.entries(params).filter(([, v]) => v != null && v !== '')
    ).toString()
    return request(`/workspaces/${id}/cases${q ? `?${q}` : ''}`)
  },

  /** GET /api/workspaces/:id/cases/:caseId — single case + append-only history */
  getCase: (id, caseId) =>
    request(`/workspaces/${id}/cases/${encodeURIComponent(caseId)}`),

  /** POST /api/workspaces/:id/cases/:caseId/transition — validated by the backend */
  transitionCase: (id, caseId, payload) =>
    request(`/workspaces/${id}/cases/${encodeURIComponent(caseId)}/transition`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  /** GET /api/workspaces/:id/shadow-it/inventory — externally-observed technology inventory */
  getShadowItInventory: (id, params = {}) => {
    const q = new URLSearchParams(
      Object.entries(params).filter(([, v]) => v != null && v !== '')
    ).toString()
    return request(`/workspaces/${id}/shadow-it/inventory${q ? `?${q}` : ''}`)
  },

  /** GET /api/workspaces/:id/shadow-it/inventory/:itemId — item + history + linked case */
  getShadowItItem: (id, itemId) =>
    request(`/workspaces/${id}/shadow-it/inventory/${encodeURIComponent(itemId)}`),

  /** POST /api/workspaces/:id/shadow-it/inventory/:itemId/action — classify/assign/lifecycle */
  shadowItAction: (id, itemId, payload) =>
    request(`/workspaces/${id}/shadow-it/inventory/${encodeURIComponent(itemId)}/action`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  /** GET /api/workspaces/:id/assets/:assetId */
  getWorkspaceAsset: (workspaceId, assetId) =>
    request(`/workspaces/${workspaceId}/assets/${assetId}`),

  // ── Workspace Intelligence APIs ───────────────────────────────────────────

  /** GET /api/workspaces/:id/executive-dashboard */
  getExecutiveDashboard: (id) => request(`/workspaces/${id}/executive-dashboard`),

  // Canonical eight-domain Cyber MOT coverage states (always returns eight, even
  // with no scan). Server-resolved; the frontend never derives domain states.
  getCyberMotDomains: (id) => request(`/workspaces/${id}/cyber-mot-domains`),

  /** GET /api/workspaces/:id/scorecard */
  getWorkspaceScorecard: (id) => request(`/workspaces/${id}/scorecard`),

  /** GET /api/workspaces/:id/scorecard/report */
  getWorkspaceScorecardReport: (id) => request(`/workspaces/${id}/scorecard/report`),

  /** GET /api/workspaces/:id/cyber-essentials-readiness */
  getWorkspaceCyberEssentialsReadiness: (id) =>
    request(`/workspaces/${id}/cyber-essentials-readiness`),

  /** GET /api/workspaces/:id/cyber-essentials/answers */
  getWorkspaceCyberEssentialsAnswers: (id) =>
    request(`/workspaces/${id}/cyber-essentials/answers`),

  /** PUT /api/workspaces/:id/cyber-essentials/answers */
  saveWorkspaceCyberEssentialsAnswers: (id, answers) =>
    request(`/workspaces/${id}/cyber-essentials/answers`, {
      method: 'PUT',
      body: JSON.stringify({ answers }),
    }),

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

  // ── Certificates Managed Lifecycle ────────────────────────────────────────
  /** GET /api/workspaces/:id/certificates/lifecycle  optional: ?renewal_readiness=&lifecycle_state=&coverage_status= */
  getCertificateLifecycle: (id, params = {}) => {
    const q = new URLSearchParams(params).toString()
    return request(`/workspaces/${id}/certificates/lifecycle${q ? `?${q}` : ''}`)
  },

  /** GET /api/workspaces/:id/certificates/lifecycle/:recId — record + history + linked case */
  getCertificateLifecycleRecord: (id, recId) =>
    request(`/workspaces/${id}/certificates/lifecycle/${encodeURIComponent(recId)}`),

  /** POST /api/workspaces/:id/certificates/lifecycle/:recId/action — ownership/planning/lifecycle */
  certificateLifecycleAction: (id, recId, body) =>
    request(`/workspaces/${id}/certificates/lifecycle/${encodeURIComponent(recId)}/action`, {
      method: 'POST', body: JSON.stringify(body),
    }),

  /** POST /api/workspaces/:id/certificates/lifecycle/:recId/verify — request external verification */
  certificateLifecycleVerify: (id, recId) =>
    request(`/workspaces/${id}/certificates/lifecycle/${encodeURIComponent(recId)}/verify`, {
      method: 'POST', body: JSON.stringify({}),
    }),

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

  // ── Brand Protection Intelligence v1 ──────────────────────────────────────
  /** GET /api/workspaces/:id/brand/profile */
  getBrandProfile: (id) => request(`/workspaces/${id}/brand/profile`),
  /** POST /api/workspaces/:id/brand/profile  body: { brand_name, primary_domain, keywords[], protected_domains[] } */
  updateBrandProfile: (id, payload) =>
    request(`/workspaces/${id}/brand/profile`, { method: 'POST', body: JSON.stringify(payload) }),
  /** GET /api/workspaces/:id/brand/summary */
  getBrandSummary: (id) => request(`/workspaces/${id}/brand/summary`),
  /** GET /api/workspaces/:id/brand/candidates  optional params */
  getBrandCandidates: (id, params = {}) => {
    const q = new URLSearchParams(params).toString()
    return request(`/workspaces/${id}/brand/candidates${q ? `?${q}` : ''}`)
  },
  /** GET /api/workspaces/:id/brand/candidates/:candidateId */
  getBrandCandidate: (id, candidateId) =>
    request(`/workspaces/${id}/brand/candidates/${candidateId}`),
  /** POST /api/workspaces/:id/brand/candidates/:candidateId/classify  body: { classification } */
  classifyBrandCandidate: (id, candidateId, classification) =>
    request(`/workspaces/${id}/brand/candidates/${candidateId}/classify`, {
      method: 'POST', body: JSON.stringify({ classification }),
    }),
  /** GET /api/workspaces/:id/brand/cases */
  getBrandCases: (id, params = {}) => {
    const q = new URLSearchParams(params).toString()
    return request(`/workspaces/${id}/brand/cases${q ? `?${q}` : ''}`)
  },
  /** GET /api/workspaces/:id/brand/cases/:caseId */
  getBrandCase: (id, caseId) => request(`/workspaces/${id}/brand/cases/${caseId}`),
  /** POST /api/workspaces/:id/brand/cases/:caseId/review */
  reviewBrandCase: (id, caseId, payload) =>
    request(`/workspaces/${id}/brand/cases/${caseId}/review`, { method: 'POST', body: JSON.stringify(payload) }),
  /** POST /api/workspaces/:id/brand/cases/:caseId/approve */
  approveBrandTakedown: (id, caseId, payload = {}) =>
    request(`/workspaces/${id}/brand/cases/${caseId}/approve`, { method: 'POST', body: JSON.stringify(payload) }),
  /** POST /api/workspaces/:id/brand/cases/:caseId/submission */
  recordBrandTakedownSubmission: (id, caseId, payload) =>
    request(`/workspaces/${id}/brand/cases/${caseId}/submission`, { method: 'POST', body: JSON.stringify(payload) }),

  /** GET /api/workspaces/:id/identity-assets  optional: ?identity_type=&provider=&min_risk_score= */
  getWorkspaceIdentityAssets: (id, params = {}) => {
    const q = new URLSearchParams(params).toString()
    return request(`/workspaces/${id}/identity-assets${q ? `?${q}` : ''}`)
  },

  /** GET /api/workspaces/:id/identity-assets/summary */
  getWorkspaceIdentitySummary: (id) => request(`/workspaces/${id}/identity-assets/summary`),

  /** GET /api/workspaces/:id/identity-exposure — consolidated Identity Exposure
   *  (exposed login surfaces + active impersonation infra + email spoofing) */
  getIdentityExposure: (id) => request(`/workspaces/${id}/identity-exposure`),

  // ── Identity Exposure Managed Workflow (managed identity surfaces) ─────────
  /** GET /api/workspaces/:id/identity-surfaces  optional: ?customer_classification=&risk_status=&monitoring_status=&surface_type= */
  getIdentitySurfaces: (id, params = {}) => {
    const q = new URLSearchParams(params).toString()
    return request(`/workspaces/${id}/identity-surfaces${q ? `?${q}` : ''}`)
  },

  /** GET /api/workspaces/:id/identity-surfaces/:recId — record + history + linked case */
  getIdentitySurface: (id, recId) =>
    request(`/workspaces/${id}/identity-surfaces/${encodeURIComponent(recId)}`),

  /** POST /api/workspaces/:id/identity-surfaces/:recId/action — classify/assign/remediate */
  identitySurfaceAction: (id, recId, body) =>
    request(`/workspaces/${id}/identity-surfaces/${encodeURIComponent(recId)}/action`, {
      method: 'POST', body: JSON.stringify(body),
    }),

  /** POST /api/workspaces/:id/identity-surfaces/:recId/verify — request external verification */
  identitySurfaceVerify: (id, recId) =>
    request(`/workspaces/${id}/identity-surfaces/${encodeURIComponent(recId)}/verify`, {
      method: 'POST', body: JSON.stringify({}),
    }),

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
  /**
   * Professional-gated (403 plan_feature_required below that plan).
   * @param {string} id
   * @param {{limit?: number, offset?: number, event_type?: string, actor_user_id?: string, entity_type?: string, entity_id?: string, date_from?: string, date_to?: string, search?: string}} [filters]
   * @returns {Promise<AuditEventList>}
   */
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
  /**
   * @param {string} workspaceId
   * @param {{limit?: number, offset?: number}} [params]
   * @returns {Promise<ReportList>}
   */
  getWorkspaceReports: (workspaceId, params = {}) => {
    const q = new URLSearchParams(/** @type {Record<string, string>} */ (params)).toString()
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

  // ── DMARC Sender Intelligence ─────────────────────────────────────────────

  /** POST /api/workspaces/:id/domains/:domain/dmarc-reports/import  body: { filename?, xml } */
  importDmarcReport: (workspaceId, domain, payload) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/dmarc-reports/import`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  /** GET /api/workspaces/:id/domains/:domain/email-senders */
  getEmailSenders: (workspaceId, domain) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/email-senders`),

  /** POST /api/workspaces/:id/domains/:domain/email-senders/:sourceId/classify  body: { classification, notes? } */
  classifyEmailSender: (workspaceId, domain, sourceId, payload) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/email-senders/${sourceId}/classify`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  /** GET /api/workspaces/:id/domains/:domain/dmarc-summary?days=30 */
  getDmarcSummary: (workspaceId, domain, days = 30) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/dmarc-summary?days=${days}`),

  /** POST /api/workspaces/:id/restore → undo a workspace soft-delete inside the 30-day window */
  restoreWorkspace: (workspaceId) =>
    request(`/workspaces/${workspaceId}/restore`, { method: 'POST' }),

  /** POST /api/workspaces/:id/domains/:domain/validate-source  body: { headers } → instant sender verdict */
  validateEmailSource: (workspaceId, domain, headers) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/validate-source`, {
      method: 'POST',
      body: JSON.stringify({ headers }),
    }),

  /** GET /api/workspaces/:id/domains/:domain/finding-waivers → accepted-risk list for a domain */
  getFindingWaivers: (workspaceId, domain) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/finding-waivers`),

  /** POST /api/workspaces/:id/domains/:domain/finding-waivers  body: { finding_id, reason? } */
  waiveFinding: (workspaceId, domain, findingId, reason) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/finding-waivers`, {
      method: 'POST',
      body: JSON.stringify({ finding_id: findingId, reason: reason || undefined }),
    }),

  /** DELETE /api/workspaces/:id/domains/:domain/finding-waivers/:findingId → restore the finding */
  unwaiveFinding: (workspaceId, domain, findingId) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/finding-waivers/${encodeURIComponent(findingId)}`, {
      method: 'DELETE',
    }),

  /** GET /api/workspaces/:id/alert-channels → { channels } */
  getAlertChannels: (workspaceId) =>
    request(`/workspaces/${workspaceId}/alert-channels`),

  /** POST /api/workspaces/:id/alert-channels  body: { channel_type, webhook_url } → { channel, secret? } */
  createAlertChannel: (workspaceId, channelType, webhookUrl) =>
    request(`/workspaces/${workspaceId}/alert-channels`, {
      method: 'POST',
      body: JSON.stringify({ channel_type: channelType, webhook_url: webhookUrl }),
    }),

  /** POST /api/workspaces/:id/alert-channels/:cid/test → { delivered } */
  testAlertChannel: (workspaceId, channelId) =>
    request(`/workspaces/${workspaceId}/alert-channels/${encodeURIComponent(channelId)}/test`, {
      method: 'POST',
    }),

  /** DELETE /api/workspaces/:id/alert-channels/:cid */
  deleteAlertChannel: (workspaceId, channelId) =>
    request(`/workspaces/${workspaceId}/alert-channels/${encodeURIComponent(channelId)}`, {
      method: 'DELETE',
    }),

  /** GET /api/workspaces/:id/domains/:domain/dmarc-reports?limit=50 → imported report history */
  getDmarcReportHistory: (workspaceId, domain, limit = 50) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/dmarc-reports?limit=${limit}`),

  /** GET /api/workspaces/:id/domains/:domain/spf-analysis → live SPF chain health (lookup budget, flattening) */
  getSpfAnalysis: (workspaceId, domain) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/spf-analysis`),

  /** Remediation Registry — every gap + live detection, and the exact generated fix */
  getRemediations: (workspaceId, domain) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/remediations`),
  getRemediationFix: (workspaceId, domain, id) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/remediations/${encodeURIComponent(id)}`),
  verifyRemediation: (workspaceId, domain, id) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/remediations/${encodeURIComponent(id)}/verify`),

  /** Hosted DMARC (managed record) — Hosted Records Engine */
  getHostedDmarc: (workspaceId, domain) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/hosted-dmarc`),
  createHostedDmarc: (workspaceId, domain) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/hosted-dmarc`, { method: 'POST' }),
  verifyHostedDmarc: (workspaceId, domain) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/hosted-dmarc/verify`),
  deleteHostedDmarc: (workspaceId, domain) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/hosted-dmarc`, { method: 'DELETE' }),

  // Hosted TLS-RPT (Phase C) — host the _smtp._tls record via CNAME delegation.
  getHostedTlsRpt: (workspaceId, domain) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/hosted-tls-rpt`),
  createHostedTlsRpt: (workspaceId, domain) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/hosted-tls-rpt`, { method: 'POST' }),
  verifyHostedTlsRpt: (workspaceId, domain) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/hosted-tls-rpt/verify`),
  deleteHostedTlsRpt: (workspaceId, domain) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/hosted-tls-rpt`, { method: 'DELETE' }),
  // Hosted MTA-STS (guided hybrid) — host only the _mta-sts DNS policy ID.
  getHostedMtaSts: (workspaceId, domain) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/hosted-mta-sts`),
  createHostedMtaSts: (workspaceId, domain) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/hosted-mta-sts`, { method: 'POST' }),
  verifyHostedMtaSts: (workspaceId, domain) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/hosted-mta-sts/verify`),
  deleteHostedMtaSts: (workspaceId, domain) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/hosted-mta-sts`, { method: 'DELETE' }),
  getTlsRptReports: (workspaceId, domain) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/tls-rpt/reports`),

  /** Self-Driving DMARC (Phase B): ladder-step change, rollback, autopilot */
  setHostedDmarcPolicy: (workspaceId, domain, policy, pct, confirm = false) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/hosted-dmarc`, {
      method: 'PUT',
      body: JSON.stringify({ policy, pct, confirm: confirm || undefined }),
    }),
  rollbackHostedDmarc: (workspaceId, domain) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/hosted-dmarc/rollback`, { method: 'POST' }),
  setHostedDmarcAutopilot: (workspaceId, domain, enabled) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/hosted-dmarc/autopilot`, {
      method: 'PUT',
      body: JSON.stringify({ enabled: Boolean(enabled) }),
    }),

  // ── Managed DMARC change-workflow — analyst review queue (Level 3) ─────────
  /** GET /api/workspaces/:id/dmarc/change-requests[?state=] → { queue, requests } */
  listDmarcChangeRequests: (workspaceId, state) =>
    request(`/workspaces/${workspaceId}/dmarc/change-requests${state ? `?state=${encodeURIComponent(state)}` : ''}`),
  /** POST /api/workspaces/:id/dmarc/change-requests → propose a policy change */
  createDmarcChangeRequest: (workspaceId, payload) =>
    request(`/workspaces/${workspaceId}/dmarc/change-requests`, { method: 'POST', body: JSON.stringify(payload) }),
  /** POST /api/workspaces/:id/dmarc/change-requests/:cid/transition → approve/reject/… */
  transitionDmarcChangeRequest: (workspaceId, changeId, payload) =>
    request(`/workspaces/${workspaceId}/dmarc/change-requests/${encodeURIComponent(changeId)}/transition`, {
      method: 'POST', body: JSON.stringify(payload),
    }),

  /** GET /api/workspaces/:id/domains/:domain/bec-exposure → BEC Exposure Score (higher = worse) */
  getBecExposureScore: (workspaceId, domain) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/bec-exposure`),

  // ── DMARC Signed Upload key (Assisted DMARC Upload v1) ────────────────────

  /** GET /api/workspaces/:id/domains/:domain/dmarc-ingest-endpoint → { endpoint|null } (never the token) */
  getDmarcIngestEndpoint: (workspaceId, domain) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/dmarc-ingest-endpoint`),

  /** Live read-only DNS verification for the current CyberMeters RUA address. */
  verifyDmarcDns: (workspaceId, domain) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/dmarc-dns-check`),

  /** POST .../dmarc-ingest-endpoint → { created, endpoint } (raw token only on first creation) */
  createDmarcIngestEndpoint: (workspaceId, domain) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/dmarc-ingest-endpoint`, {
      method: 'POST',
    }),

  /** POST .../dmarc-ingest-endpoint/rotate → { rotated, endpoint } (new raw token, once) */
  rotateDmarcIngestEndpoint: (workspaceId, domain) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/dmarc-ingest-endpoint/rotate`, {
      method: 'POST',
    }),

  /** POST .../dmarc-ingest-endpoint/revoke → { revoked, endpoint } */
  revokeDmarcIngestEndpoint: (workspaceId, domain) =>
    request(`/workspaces/${workspaceId}/domains/${encodeURIComponent(domain)}/dmarc-ingest-endpoint/revoke`, {
      method: 'POST',
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
  /**
   * The list returns `metadata` ALREADY PARSED (raw `metadata_json` is dropped
   * server-side) — the NotificationBell regression contract, under test in
   * NotificationBell.test.jsx and typed in AppNotification.
   * @param {string} workspaceId
   * @param {{limit?: number, offset?: number}} [params]
   * @returns {Promise<NotificationList>}
   */
  getWorkspaceNotifications: (workspaceId, params = {}) => {
    const q = new URLSearchParams(/** @type {Record<string, string>} */ (params)).toString()
    return request(`/workspaces/${workspaceId}/notifications${q ? `?${q}` : ''}`)
  },

  /**
   * POST /api/workspaces/:id/notifications/:notifId/read
   * Pass notifId = "all" to mark all unread as read.
   */
  /**
   * @param {string} workspaceId
   * @param {string | 'all'} notifId  Pass 'all' to bulk-clear.
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
   * Generate a verification token for a specific workspace-domain relationship.
   * `workspaceId` makes the target explicit; the backend auto-resolves it when the
   * domain is linked to exactly one of the caller's workspaces.
   */
  generateDomainVerification: (domainId, workspaceId) =>
    request(`/domains/${domainId}/verification`, {
      method: 'POST',
      ...(workspaceId ? { body: JSON.stringify({ workspace_id: workspaceId }) } : {}),
    }),

  /**
   * POST /api/domains/:id/verify
   * Trigger the actual DNS TXT / HTML file check for a specific workspace-domain
   * relationship. `workspaceId` optional (see generateDomainVerification).
   */
  verifyDomain: (domainId, workspaceId) =>
    request(`/domains/${domainId}/verify`, {
      method: 'POST',
      ...(workspaceId ? { body: JSON.stringify({ workspace_id: workspaceId }) } : {}),
    }),

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

  /** GET /api/account/report-branding — white-label brand + plan availability */
  getReportBranding: () => request('/account/report-branding'),

  /** PUT /api/account/report-branding — set logo/accent/white-label toggle */
  updateReportBranding: (data) =>
    request('/account/report-branding', {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  /**
   * GET /api/account/subscription
   * Returns manual subscription foundation for the authenticated account.
   * @returns {Promise<{subscription: Subscription}>}
   */
  getSubscription: () => request('/account/subscription'),

  /**
   * GET /api/workspaces/:id/subscription
   * Returns workspace-level subscription state: plan, status, trial_active,
   * trial_remaining_days, trial_start, trial_end, limits, features.
   * @param {string} workspaceId
   * @returns {Promise<{subscription: Subscription}>}
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

  /**
   * POST /api/account/api-tokens — `name` is required by the server.
   * @param {{name?: string, scope?: 'read' | 'write', workspace_id?: string | null, expires_at?: string | null}} [opts]
   */
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
    return fetch(`${BASE}/account/export`, { method: 'GET', headers })
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
  // (getBillingPlans lives in the earlier billing cluster — the type gate
  // caught a duplicate key here that silently shadowed it.)

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

  /** GET /api/portfolio/executive-summary — portfolio-level exec summary */
  getPortfolioExecutiveSummary: () => request('/portfolio/executive-summary'),

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
    fetch(`${BASE}/free-scan`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ domain }),
    }).then(async res => {
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`)
      return data
    }),
}
