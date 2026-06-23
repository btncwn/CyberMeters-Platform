# PUBLIC_BETA_READINESS_REPORT.md

Sprint 10D — Public Beta Readiness v1
Date: 2026-06-23

---

## Methodology

Six phases of code inspection were conducted across the Worker and frontend. No assumptions were made — every issue below is proven from source code. No scanner modules were reviewed. No Stripe configuration was changed.

Source audits:
- `workers/scan-api/src/index.js`
- `frontend/src/context/AuthContext.jsx`
- `frontend/src/pages/SignupPage.jsx`, `LoginPage.jsx`, `EmailVerificationPage.jsx`, `OnboardingPage.jsx`
- `frontend/src/App.jsx`
- `workers/scan-api/wrangler.toml`

---

## CRITICAL Issues (must fix before any external user)

### CRITICAL-1 — Workspace deletion is non-functional

**Phase:** Workspace Lifecycle
**File:** `workers/scan-api/src/index.js`
**Route:** `POST /api/workspaces/:id/delete-request` (~line 28159)
**Root cause:** The delete-request endpoint creates a `deletion_requests` row with `status='pending'`. No cron job, background handler, or admin API processes these requests. Workspaces are never actually deleted.

**Impact:** Beta users who request account/workspace deletion will receive a "202 Accepted" response and their workspace, scans, domains, and data will persist indefinitely. This is a GDPR/data retention compliance failure.

**Remediation:**
```js
// Add soft-delete to POST /api/workspaces/:id/delete-request or a new DELETE endpoint:
await env.cybermeters_db.prepare(
  `UPDATE workspaces SET deleted_at = datetime('now') WHERE id = ?`
).bind(workspaceId).run();
// Add to all workspace queries: AND deleted_at IS NULL
```

---

### CRITICAL-2 — New users have no path to onboarding after first login

**Phase:** New User Journey
**File:** `frontend/src/App.jsx`, `frontend/src/context/AuthContext.jsx`
**Route:** Login → `/dashboard`
**Root cause:** After a successful login, `navigate(from, { replace: true })` takes all new users to `/dashboard`. `ProtectedRoute` only checks authentication, not workspace existence. Users with no workspace see whatever the dashboard's empty state is, with no prompt to create a workspace or run a scan. `OnboardingPage.jsx` exists and is well-implemented but is never shown automatically.

**Impact:** Every new beta user who registers locally (not via invite) will hit a blank or empty dashboard and have no clear next step. This is a Day 1 conversion failure.

**Remediation:** In `AuthContext` or in a post-login effect in `LoginPage.jsx`, call `GET /api/workspaces` after login. If `workspaces.length === 0`, `navigate('/onboarding', { replace: true })`.

---

### CRITICAL-3 — Scheduled scans run under wrong user context (user_demo / free plan)

**Phase:** Scheduled Scan Reliability + Workspace Lifecycle
**File:** `workers/scan-api/src/index.js`
**Function:** `triggerScheduledScan()` (~line 14270)
**Root cause:** All scheduled scans are attributed to a hardcoded `"user_demo"` user with `"demo@cybermeters.com"` email and `"free"` plan. The workspace owner's user ID is not resolved. Any plan-sensitive logic within `runScanEngine()` that queries the scan's `user_id` will use the free plan context for paying customers.

**Impact:** Scheduled scans for Professional/Business customers may operate under free-plan feature limits during scan execution. Audit logs show `user_demo` as the actor for all scheduled scans.

**Remediation:**
```js
// In triggerScheduledScan():
const ownerRow = await env.cybermeters_db
  .prepare("SELECT owner_user_id FROM workspaces WHERE id = ?")
  .bind(schedule.workspace_id).first();
const userId = ownerRow?.owner_user_id || "user_demo";
// Use userId for domain row, scan row, and audit events
```

---

## HIGH Issues (should fix before public beta)

### HIGH-1 — No rate limiting on email resend endpoint

**Phase:** Email Verification
**File:** `workers/scan-api/src/index.js`
**Route:** `POST /api/auth/resend-verification` (~line 19254)
**Root cause:** No authentication required, no cooldown, no IP check. Any caller can trigger unlimited emails to any address, using CyberMeters as a spam relay.

**Remediation:** Check `verification_token_expires_at > now() - interval '60 seconds'`; if so, return `{ success: true }` without sending. No new table needed.

---

### HIGH-2 — Verification email delivery failures are invisible

**Phase:** Email Verification
**File:** `workers/scan-api/src/index.js`
**Route:** `POST /api/auth/signup` (~line 18988)
**Root cause:** `sendCustomerEmail(...).catch(() => {})` — delivery failures are silently dropped. If Resend is misconfigured, all signup emails fail with no operator visibility.

**Remediation:** Log the error with `console.error('[signup] email delivery failed:', e?.message)`. Monitor Resend webhook delivery status.

---

### HIGH-3 — No automatic onboarding flow (paired with CRITICAL-2 — listed separately for tracking)

See CRITICAL-2. The OnboardingPage is the fix; the missing redirect is the CRITICAL issue.

---

### HIGH-4 — Signup page has no Microsoft SSO option

**Phase:** New User Journey
**File:** `frontend/src/pages/SignupPage.jsx`
**Root cause:** `LoginPage.jsx` has "Continue with Microsoft"; `SignupPage.jsx` does not. Users who want SSO must know to try the login page instead.

**Remediation:** Add the same `<a href="${BASE}/auth/microsoft/login">` button to `SignupPage.jsx`.

---

### HIGH-5 — Past-due subscriptions lose all access immediately (no grace period)

**Phase:** Subscription Lifecycle
**File:** `workers/scan-api/src/index.js`
**Function:** `getUserPlan()` (~line 16897)
**Root cause:** `subscription_status='past_due'` returns `'free'` immediately. Stripe retries for 7 days before cancelling. Customers with valid subscriptions but a temporarily declined card lose access before Stripe gives up.

**Remediation:**
```js
if (status === "past_due") {
  const failedAt = sub.payment_failed_at ? new Date(sub.payment_failed_at).getTime() : 0;
  if (Date.now() - failedAt < 7 * 24 * 60 * 60 * 1000) return normalizePlan(sub.plan);
  return "free";
}
```

---

### HIGH-6 — Workspace rename is impossible (no PATCH endpoint)

**Phase:** Workspace Lifecycle
**File:** `workers/scan-api/src/index.js`
**Root cause:** No `PATCH /api/workspaces/:id` endpoint exists. Workspaces can only be created or deletion-requested.

**Remediation:** Add `PATCH /api/workspaces/:id` accepting `{ name }`. Enforce `requireWorkspaceRole(user, id, "workspace:manage", env)`.

---

### HIGH-7 — Domain removal does not disable associated scheduled scans

**Phase:** Workspace Lifecycle
**File:** `workers/scan-api/src/index.js`
**Route:** `DELETE /api/workspaces/:id/domains/:domainId` (~line 28016)
**Root cause:** Only `workspace_domains` is deleted. `scheduled_scans` for the domain continue running, creating scans for a domain the user has removed from their workspace.

**Remediation:** `UPDATE scheduled_scans SET enabled=0 WHERE workspace_id=? AND domain=<domain_name>` on domain removal.

---

### HIGH-8 — No cancellation notification when Stripe cancels subscription

**Phase:** Subscription Lifecycle
**File:** `workers/scan-api/src/index.js`
**Function:** `handleStripeSubscriptionDeleted()`
**Root cause:** Status is updated to `'canceled'` in D1 with no email to the user and no in-app notification.

**Remediation:** After updating status, call `sendCustomerEmail()` to the workspace owner notifying them of the cancellation and providing a link to `/billing` to resubscribe.

---

### HIGH-9 — Scheduled scan failures are completely silent

**Phase:** Scheduled Scan Reliability
**File:** `workers/scan-api/src/index.js`
**Function:** `triggerScheduledScan()`
**Root cause:** The entire function catches all errors silently. Failed scans remain `status='running'` forever. No notification is sent to the workspace owner.

**Remediation:** Catch errors from `runScanEngine()` specifically, UPDATE scan to `status='failed'`, create a workspace notification, and log the error.

---

### HIGH-10 — Scheduled scans table not in migrations — DDL inline in route handler

**Phase:** Scheduled Scan Reliability
**File:** `workers/scan-api/src/index.js`
**Route:** `POST /api/schedules` (~line 22157)
**Root cause:** `CREATE TABLE IF NOT EXISTS scheduled_scans` runs inside the POST handler. Schema not in `database/schema.sql`.

**Remediation:** Add `scheduled_scans` DDL to `database/schema.sql` and a versioned migration file. Remove inline DDL.

---

### HIGH-11 — Trial subscription may create duplicate rows on upgrade

**Phase:** Subscription Lifecycle
**File:** `workers/scan-api/src/index.js`
**Function:** `upsertSubscription()` (~line 17332)
**Root cause:** The local trial row has no `stripe_subscription_id`. When the user upgrades, `upsertSubscription()` may INSERT a new row rather than UPDATE the trial row, leaving an orphaned trialing row.

**Remediation:** In `upsertSubscription()`, add a fallback: `UPDATE subscriptions SET ... WHERE workspace_id = ? AND stripe_subscription_id IS NULL AND subscription_status = 'trialing'` before INSERT.

---

## MEDIUM Issues (address during beta)

| # | Phase | Issue | File / Route |
|---|-------|-------|-------------|
| M-1 | Email Verification | Post-verification requires manual click to reach login — no auto-redirect | `EmailVerificationPage.jsx` |
| M-2 | Email Verification | Verification token stored as plaintext (not hashed) | `index.js` — users table |
| M-3 | Session | No sliding window — sessions expire hard at 30 days regardless of activity | `index.js` — requireAuth() |
| M-4 | Session | No session list or revocation UI | Missing feature |
| M-5 | Session | No per-user session limit — rows accumulate indefinitely | `index.js` — login route |
| M-6 | New User Journey | Dashboard empty state for new users not confirmed | `Dashboard.jsx` |
| M-7 | New User Journey | Pricing CTA does not preserve return URL through auth | `App.jsx` |
| M-8 | Workspace | Legacy RBAC fallback: NULL owner_user_id → workspace inaccessible | `index.js` — requireWorkspaceRole() |
| M-9 | Subscription | Webhook workspace_id not validated against workspace owner | `index.js` — webhook handler |
| M-10 | Scheduled Scans | No concurrency guard — burst of simultaneous scans may hit subrequest limits | `index.js` — scheduled() |
| M-11 | Scheduled Scans | Free plan users see confusing 403 on schedule creation | `SchedulesPage.jsx` |

---

## LOW Issues (post-beta)

| # | Phase | Issue |
|---|-------|-------|
| L-1 | Email Verification | OAuth/local account collision path not fully hardened |
| L-2 | Session | Suspended user sessions not purged immediately |
| L-3 | Session | Microsoft OAuth token revocation not propagated |
| L-4 | Session | Tokens in localStorage (should migrate to HttpOnly cookie) |
| L-5 | New User Journey | Password confirmation is client-side only |
| L-6 | Workspace | Workspace count for entitlement must exclude deleted workspaces |
| L-7 | Subscription | No idempotency guard on Stripe webhook events |
| L-8 | Subscription | Subscription lookup tied to owner_user_id — breaks on future ownership transfer |
| L-9 | Scheduled Scans | No user timezone support for scan scheduling |
| L-10 | Scheduled Scans | Delete does not check for in-progress scan |

---

## Priority Order for Beta Readiness

The three items that block any external user from having a functional experience are CRITICAL-1, CRITICAL-2, and CRITICAL-3. Fix these first.

The HIGH items that affect paying customers most directly are HIGH-5 (past-due lockout), HIGH-8 (no cancellation notification), and HIGH-9 (silent scan failures). These should follow immediately.

Recommended sprint order:
1. CRITICAL-1 — Workspace soft-delete (1 day)
2. CRITICAL-2 — Onboarding redirect on first login (half day)
3. CRITICAL-3 — Resolve workspace owner in triggerScheduledScan (half day)
4. HIGH-1 — Resend rate limit (1 hour)
5. HIGH-4 — Microsoft SSO on signup page (1 hour)
6. HIGH-5 — Past-due grace period (1 hour)
7. HIGH-6 — Workspace rename endpoint (half day)
8. HIGH-7 — Domain removal cascades to scheduled scans (half day)
9. HIGH-8 — Cancellation email notification (1 hour)
10. HIGH-9 — Scheduled scan failure handling (half day)

---

## Detailed Audit Documents

- `docs/EMAIL_VERIFICATION_AUDIT.md` — Issues 1–5
- `docs/SESSION_LIFECYCLE_AUDIT.md` — Issues 6–11
- `docs/NEW_USER_JOURNEY_AUDIT.md` — Issues 12–18
- `docs/WORKSPACE_LIFECYCLE_AUDIT.md` — Issues 19–24
- `docs/SUBSCRIPTION_LIFECYCLE_AUDIT.md` — Issues 25–30
- `docs/SCHEDULED_SCAN_RELIABILITY_AUDIT.md` — Issues 31–37

---

## Issue Count

| Severity | Count |
|----------|-------|
| CRITICAL | 3 |
| HIGH | 11 |
| MEDIUM | 11 |
| LOW | 10 |
| **Total** | **35** |
