/**
 * Shared API contract types — the frontend half of the OpenAPI spec
 * (docs/openapi.json) and of the shapes the backend pipeline tests prove
 * (scripts/validate-pipeline.js). Types-only (.d.ts): never imported at
 * runtime, referenced from JSDoc via import('./types/api').
 *
 * Rule: only add fields verified against the worker or the pipeline tests.
 * A missing field is an addition away; a wrong field is a silent bug.
 */

// ── Plans / billing ───────────────────────────────────────────────────────────

export type PlanId = 'free' | 'starter' | 'professional' | 'business' | 'enterprise';

export interface Subscription {
  plan: PlanId;
  subscription_status?: string | null;
  billing_interval?: string | null;
  current_period_end?: string | null;
  cancel_at_period_end?: number | boolean | null;
  payment_failed_at?: string | null;
  stripe_customer_id?: string | null;
  stripe_subscription_id?: string | null;
}

/** The 403 body gated endpoints return (proven by the pipeline feature-gate test). */
export interface PlanFeatureRequiredError {
  error: 'plan_feature_required';
  feature?: string;
  required_plan: PlanId;
  upgrade_url?: string;
}

// ── Errors thrown by the api client ───────────────────────────────────────────

/**
 * Every error request()/requestBlob() throws is a plain Error decorated with
 * machine-readable context so callers can branch without string-matching.
 */
export interface ApiError extends Error {
  /** HTTP status of the failed response (absent on network errors). */
  status?: number;
  /** Machine code: 'network_error' | 'plan_limit_exceeded' | 'rate_limit_exceeded' | server codes. */
  code?: string;
  /** Set on plan-gate errors: 'plan_feature_required'. */
  error?: string;
  feature?: string;
  required_plan?: PlanId;
  upgrade_url?: string;
  /** plan_limit_exceeded context. */
  resource?: string;
  limit?: number;
  usage?: number;
  /** Hosted-DMARC policy readiness interlock details. */
  readiness?: unknown;
}

// ── Auth ──────────────────────────────────────────────────────────────────────

export interface User {
  id: string;
  email: string;
  name: string | null;
  plan: PlanId;
}

/**
 * POST /auth/login — a union: with MFA enabled the session token is withheld
 * until the TOTP challenge completes (proven by the pipeline login tests).
 */
export type LoginResponse =
  | { token: string; user: User }
  | { mfa_required: true; challenge_token: string };

export interface MfaStatus {
  enabled: boolean;
  pending?: boolean;
}

// ── Pagination (Sprint 3 contract, proven via the pipeline) ───────────────────

export interface Pagination {
  limit: number;
  offset: number;
  /** Items in THIS page. */
  count: number;
  has_more: boolean;
  /** Total matching rows — present where the endpoint counts them. */
  total?: number;
}

// ── Workspaces ────────────────────────────────────────────────────────────────

export interface Workspace {
  id: string;
  name: string;
  created_at?: string;
  role?: string;
}

export interface WorkspaceStats {
  total_domains: number;
  total_scans: number;
  cyber_score_average: number | null;
  latest_scan?: string | null;
}

/** GET /workspaces/:id (proven by the pipeline tenant-isolation test). */
export interface WorkspaceDetail {
  workspace: Workspace;
  stats: WorkspaceStats;
}

export interface WorkspaceList {
  workspaces: Workspace[];
  default_workspace_id?: string | null;
}

export interface WorkspaceDomain {
  id: string;
  domain: string;
  verification_status?: string;
  verified_at?: string | null;
}

// ── Notifications (the NotificationBell regression contract) ─────────────────

/**
 * The list API returns `metadata` ALREADY PARSED as an object and does not
 * return the raw `metadata_json` string (it is set undefined server-side).
 * Reading only `metadata_json` broke click-through once — the type now
 * records that lesson: treat `metadata` as the source of truth.
 */
export interface AppNotification {
  id: string;
  status: 'unread' | 'read';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  type?: string;
  title: string;
  message?: string;
  created_at: string;
  metadata?: { scan_id?: string; report_id?: string; [k: string]: unknown } | null;
  /** Legacy raw JSON string — only in older payloads; prefer `metadata`. */
  metadata_json?: string | null;
}

export interface NotificationList {
  notifications: AppNotification[];
  unread_count: number;
  pagination?: Pagination;
}

// ── Audit events (professional-gated; proven by the pipeline gate test) ───────

export interface AuditEvent {
  id: string;
  event_type: string;
  entity_type?: string | null;
  entity_id?: string | null;
  description?: string | null;
  actor_user_id?: string | null;
  workspace_id?: string;
  created_at: string;
}

export interface AuditEventList {
  events: AuditEvent[];
  pagination: Pagination;
}

// ── Scans ─────────────────────────────────────────────────────────────────────

export interface Scan {
  id: string;
  domain: string;
  status: string;
  created_at?: string;
  workspace_id?: string | null;
  cyber_score?: number | null;
}

export interface ScanList {
  scans: Scan[];
  workspace_id?: string;
}

// ── Reports ───────────────────────────────────────────────────────────────────

export interface WorkspaceReport {
  id: string;
  report_type?: string;
  status?: string;
  created_at: string;
}

export interface ReportList {
  reports: WorkspaceReport[];
  pagination?: Pagination;
}

// ── Domain ownership verification ─────────────────────────────────────────────

export interface DomainVerification {
  domain?: string;
  verification_status?: string;
  txt_record?: string;
  verified?: boolean;
}

// The closed set of terminal outcomes from POST /api/domains/:id/verify. Every
// response carries exactly one. Mirrors VERIFICATION_OUTCOMES in the Worker
// (workers/scan-api/src/lib/domain-verification.js) — keep the two in step.
export type DomainVerifyOutcome =
  | 'already_verified'
  | 'verified_dns_txt'
  | 'verified_html_file'
  | 'dns_not_found'
  | 'dns_mismatch'
  | 'dns_lookup_error'
  | 'unauthorized'
  | 'domain_link_not_found'
  | 'workspace_ambiguous'
  | 'no_token'
  | 'persistence_zero_rows'
  | 'persistence_unexpected_rows'
  | 'persistence_confirmation_failed'
  | 'internal_error';

// Response of POST /api/domains/:id/verify.
//
// IMPORTANT: `verification_status: 'verified'` here is NOT a licence to show the
// customer a verified state. It reports what the backend proved at the moment of
// the write; the UI's trust contract requires a reread of the authoritative row
// from GET /api/workspaces/:id/domains. See isAuthoritativeVerified() and
// verifyResponseClaimsSuccess() in src/lib/newScanVerification.js.
//
// The identity fields on a success are re-read from the persisted workspace_domains
// row, so they cannot describe a record that was not written. No token material is
// returned on failure — the customer's record comes from the /verification init
// response or GET /api/domains/:id.
export interface DomainVerifyResult {
  success: boolean;
  verification_status?: 'verified' | 'failed';
  outcome?: DomainVerifyOutcome;
  request_id?: string;
  domain?: string;
  domain_id?: string;
  workspace_id?: string;
  /** Canonical method field. `verification_method` is the legacy alias. */
  method?: string | null;
  verification_method?: string | null;
  /** Persisted timestamp, re-read from the row. Absent on every failure. */
  verified_at?: string | null;
  message?: string;
  error?: string;
  checks?: {
    dns_txt?: { checked: boolean; host?: string; result?: string; error?: string | null };
    html_file?: { checked: boolean; url?: string; result?: string; error?: string | null };
  };
  auto_recheck?: { enabled: boolean; method: string; interval: string; window_hours: number };
}
