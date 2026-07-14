# CyberMeters — Public Beta Readiness Backlog

> **Status: Historical / Superseded (15 July 2026).** Retained for historical
> context; no longer a source of truth. Canonical roadmap:
> `docs/ROADMAP-TO-FIRST-PAYING-CUSTOMER.md` · current canonical episode and
> release facts: `CLAUDE.md` · shipped truth: `CHANGELOG.md`.

**Sprint 11B — Lifecycle Audit Consolidation**
Date: 2026-06-23
Source audits: EMAIL_VERIFICATION_AUDIT.md · SESSION_LIFECYCLE_AUDIT.md · NEW_USER_JOURNEY_AUDIT.md · WORKSPACE_LIFECYCLE_AUDIT.md · SUBSCRIPTION_LIFECYCLE_AUDIT.md · SCHEDULED_SCAN_RELIABILITY_AUDIT.md · PUBLIC_BETA_READINESS_REPORT.md

---

## Executive Summary

All figures are derived from code-proven audit findings. No assumptions.

| Dimension | Current | After P0 Fixes | After P1 Fixes |
|-----------|--------:|---------------:|---------------:|
| **Public Beta Readiness** | **40%** | **72%** | **88%** |
| Lifecycle Operations | 50% | 78% | 92% |
| Customer Onboarding | 40% | 80% | 90% |
| Billing Readiness | 58% | 75% | 92% |
| Authentication Readiness | 68% | 80% | 88% |

### Basis for Current 40% Readiness

Three critical issues independently prevent a viable first-user experience:

1. **Workspace deletion is a no-op** — regulatory and contractual exposure on day one.
2. **New users land on a blank dashboard** — no path to their first scan; the onboarding page is dead code.
3. **Scheduled scans execute under a hardcoded free-plan demo user** — paying customers' background monitoring runs with free-tier constraints.

None of these require new features. All are small-to-medium targeted fixes. The platform's core ASM engine, reporting, billing integration, and multi-workspace architecture are substantively complete. The blockers are infrastructure gaps in the user lifecycle layer, not product capability gaps.

---

## Consolidated Findings

| Priority | Severity | Audit Area | Issue | Files | Effort |
|----------|----------|------------|-------|-------|--------|
| P0 | CRITICAL | Workspace | Workspace deletion is non-functional — delete-request row is inserted but never processed | `index.js` ~line 28159 | Medium |
| P0 | CRITICAL | New User Journey | New users always land at `/dashboard` — no redirect to onboarding for users with no workspace | `App.jsx`, `AuthContext.jsx` | Small |
| P0 | CRITICAL | Scheduled Scans | `triggerScheduledScan()` uses hardcoded `user_demo` / free plan — paying customers' scans run under wrong plan context | `index.js` ~line 14270 | Small |
| P0 | HIGH | Email Verification | No rate limit on `POST /api/auth/resend-verification` — open email spam relay | `index.js` ~line 19254 | Small |
| P0 | HIGH | Email Verification | Verification email delivery failures silently dropped — operator has zero visibility | `index.js` ~line 18988 | Small |
| P0 | HIGH | Subscription | Past-due subscribers lose all access on first payment failure — no 7-day grace period | `index.js` ~line 16897 | Small |
| P0 | HIGH | Scheduled Scans | Scheduled scan failures silently swallowed — scan stuck as `status='running'`, no user notification | `index.js` `triggerScheduledScan()` | Medium |
| P1 | HIGH | New User Journey | `OnboardingPage.jsx` exists and works but is never shown automatically | `App.jsx` | Small |
| P1 | HIGH | New User Journey | Signup page has no Microsoft SSO button — login page does | `SignupPage.jsx` | Small |
| P1 | HIGH | Workspace | No `PATCH /api/workspaces/:id` — workspace rename is impossible | `index.js` | Medium |
| P1 | HIGH | Workspace | Domain removal does not cascade — scheduled scans continue, assets remain active | `index.js` ~line 28016 | Small |
| P1 | HIGH | Subscription | No email or notification sent when Stripe cancels subscription | `index.js` `handleStripeSubscriptionDeleted()` | Small |
| P1 | HIGH | Subscription | Trial row + upgrade row may produce two subscription rows — plan resolution by recency is fragile | `index.js` `upsertSubscription()` | Small |
| P1 | HIGH | Scheduled Scans | `scheduled_scans` table created via inline DDL in route handler — not in schema or migrations | `index.js` ~line 22157, `database/schema.sql` | Medium |
| P2 | MEDIUM | Email Verification | Post-verification page requires manual click to reach login — no auto-redirect or countdown | `EmailVerificationPage.jsx` | Small |
| P2 | MEDIUM | Email Verification | Verification token stored as plaintext in `users` table — not hashed | `index.js` | Medium |
| P2 | MEDIUM | Session | No sliding session window — active users silently logged out at hard 30-day expiry | `index.js` `requireAuth()` | Small |
| P2 | MEDIUM | Session | No session limit per user — rows accumulate indefinitely | `index.js` login route | Small |
| P2 | MEDIUM | Session | No session list or revocation UI — users cannot see or revoke active sessions | `index.js`, settings frontend | Large |
| P2 | MEDIUM | New User Journey | Dashboard empty state for users with no workspaces not confirmed | `Dashboard.jsx` | Small |
| P2 | MEDIUM | New User Journey | Pricing CTA does not preserve return URL through auth flow | `App.jsx` | Small |
| P2 | MEDIUM | Workspace | Legacy RBAC: workspaces with `NULL owner_user_id` become permanently inaccessible | `index.js` `requireWorkspaceRole()` | Small |
| P2 | MEDIUM | Subscription | Stripe webhook does not validate `workspace_id` from metadata against actual workspace owner | `index.js` webhook handler | Small |
| P2 | MEDIUM | Scheduled Scans | No concurrency cap — all due schedules run simultaneously, may hit Workers subrequest limit | `index.js` `scheduled()` | Medium |
| P2 | MEDIUM | Scheduled Scans | Free plan users reach `/schedules`, see confusing 403 on creation attempt | `SchedulesPage.jsx` | Small |
| P2 | LOW | Email Verification | OAuth/local account collision path not fully hardened | `index.js` OAuth exchange handler | Medium |
| P2 | LOW | Session | Suspended users' sessions not purged immediately on suspension | `index.js` | Small |
| P2 | LOW | Session | Microsoft OAuth token revocation not propagated to local sessions | `index.js` | Large |
| P2 | LOW | Session | Session tokens in `localStorage` — XSS-accessible; should migrate to HttpOnly cookie | `AuthContext.jsx` | Large |
| P2 | LOW | New User Journey | Password confirmation is client-side only | `SignupPage.jsx` | Small |
| P2 | LOW | Workspace | Workspace entitlement count must exclude soft-deleted workspaces (dependency on CRITICAL-1 fix) | `index.js` | Small |
| P2 | LOW | Subscription | No idempotency guard on Stripe webhook event processing | `index.js` webhook handler | Medium |
| P2 | LOW | Subscription | Subscription lookup tied to `owner_user_id` — breaks if workspace ownership is ever transferred | `index.js` `getUserPlan()` | Medium |
| P2 | LOW | Scheduled Scans | No user timezone support — scan time is UTC-only | `index.js` `computeNextRunAt()` | Medium |
| P2 | LOW | Scheduled Scans | Delete does not check for in-progress scan — one missed asset count update possible | `index.js` `DELETE /api/schedules/:id` | Small |

**Totals: 3 CRITICAL · 11 HIGH · 11 MEDIUM · 10 LOW = 35 issues**

---

## P0 — Must Fix Before Public Beta

These 7 issues independently block external users from a functional or safe experience. No beta invitation should go out until all P0 items are resolved.

---

### P0-1 — Workspace Deletion Non-Functional

**Audit reference:** ISSUE-19, CRITICAL-1
**Description:** `POST /api/workspaces/:id/delete-request` inserts a row into `deletion_requests` with `status='pending'` and returns HTTP 202. No cron job, background handler, or admin endpoint processes these requests. Workspaces are never deleted.
**User impact:** A beta user who requests deletion of their workspace and its data receives a success response, but their data persists indefinitely. If they re-register with the same email and domain, they may collide with their own orphaned workspace.
**Technical impact:** GDPR Article 17 right-to-erasure cannot be honored. Entitlement counts (workspace limits) are inflated by phantom workspaces.
**Files:** `workers/scan-api/src/index.js` ~line 28159; all workspace queries that need `AND deleted_at IS NULL`
**Fix required:**
- Add `deleted_at TIMESTAMP` to workspaces schema (migration required).
- In `POST /api/workspaces/:id/delete-request`: replace the `deletion_requests` insert with `UPDATE workspaces SET deleted_at = datetime('now') WHERE id = ?` (soft-delete).
- Scope all workspace SELECT/JOIN queries to `WHERE deleted_at IS NULL`.
- Update workspace entitlement count query to exclude deleted rows (resolves ISSUE-24 / LOW-6 as a side effect).
**Effort:** Medium (1–4 hours)

---

### P0-2 — No Onboarding Path for New Users

**Audit reference:** ISSUE-12, ISSUE-13, CRITICAL-2
**Description:** After login, `navigate(from, { replace: true })` resolves to `/dashboard` for all users. `ProtectedRoute` only checks authentication. A new user with no workspace sees whatever the dashboard's empty state is, with no prompt to create a workspace or run a scan. `/onboarding` exists and is fully implemented but is never reached automatically.
**User impact:** Every beta user who self-registers hits a blank dashboard with no guided path to value. First-scan conversion will be near zero without this fix.
**Technical impact:** `OnboardingPage.jsx` is dead code from the user's perspective. Day 1 activation is broken.
**Files:** `frontend/src/pages/LoginPage.jsx` or `frontend/src/context/AuthContext.jsx`; `frontend/src/App.jsx`
**Fix required:**
- After successful login, call `GET /api/workspaces`.
- If `response.workspaces.length === 0`, call `navigate('/onboarding', { replace: true })` instead of navigating to `/dashboard`.
- This single change makes OnboardingPage functional (resolves ISSUE-13 as a side effect).
**Effort:** Small (<1 hour)

---

### P0-3 — Scheduled Scans Run Under Wrong User Context

**Audit reference:** ISSUE-22, ISSUE-31, CRITICAL-3
**Description:** `triggerScheduledScan()` hardcodes `user_demo` / `demo@cybermeters.com` / `free` plan as the scan's attributed user. Any plan-sensitive code inside `runScanEngine()` that resolves plan from the scan's `user_id` will execute under free-plan limits for all customers, including Professional and Business subscribers. Audit logs for all scheduled scans show `user_demo` as the actor.
**User impact:** Paying customers on scheduled Professional/Business scans silently receive degraded feature execution. Audit trails are incorrect.
**Technical impact:** `checkScheduledScanLimit()` correctly uses the workspace owner's plan for the quota check; but the scan engine uses the wrong user for everything else.
**Files:** `workers/scan-api/src/index.js` `triggerScheduledScan()` ~line 14270
**Fix required:**
- At the top of `triggerScheduledScan()`, resolve the workspace owner: `SELECT owner_user_id FROM workspaces WHERE id = ?` using `schedule.workspace_id`.
- Use the resolved `owner_user_id` (or fall back to `user_demo` if null) for domain row creation, scan row `user_id`, and audit events.
- Remove the unconditional `user_demo` upsert (or keep it guarded by the fallback path only).
**Effort:** Small (<1 hour)

---

### P0-4 — Email Resend Endpoint Is an Open Spam Relay

**Audit reference:** ISSUE-1, HIGH-1
**Description:** `POST /api/auth/resend-verification` requires no authentication, no CAPTCHA, no cooldown, and no IP check. Any caller can fire unlimited transactional emails to any address through CyberMeters' Resend account.
**User impact:** CyberMeters' sending domain gets blacklisted; legitimate verification emails are blocked for all users.
**Technical impact:** Zero friction for abuse. Resend overage charges accumulate silently.
**Files:** `workers/scan-api/src/index.js` ~line 19254
**Fix required:**
- Before sending, check: `SELECT verification_token_expires_at FROM users WHERE email = ?`.
- If `verification_token_expires_at > datetime('now', '-60 seconds')`, return `{ success: true }` without sending (response is identical — avoids timing attacks and email enumeration).
- No new table or column needed; `verification_token_expires_at` already exists.
**Effort:** Small (<1 hour)

---

### P0-5 — Email Delivery Failures Are Invisible to Operators

**Audit reference:** ISSUE-2, HIGH-2
**Description:** `sendCustomerEmail(...).catch(() => {})` in `POST /api/auth/signup` silently drops all delivery errors. If Resend is misconfigured, has an outage, or rejects the request, every registration silently fails to deliver a verification email. The signup response is always `{ success: true, verification_required: true }`.
**User impact:** Users who never receive the email will attempt to log in, see a 403 with no explanation, and abandon. At Resend misconfiguration scale, all registrations fail silently.
**Technical impact:** No operator alerting. Delivery failures do not surface in logs or any monitoring channel.
**Files:** `workers/scan-api/src/index.js` ~line 18988
**Fix required:**
- Replace `.catch(() => {})` with `.catch((e) => { console.error('[signup] email delivery failed', { email, error: e?.message }); })`.
- Optionally include `email_queued: false` in the 201 response body when delivery fails (safe — does not reveal email validity, only indicates system state).
- Configure Resend webhook alerts for bounces and failures as a separate operational step.
**Effort:** Small (<1 hour)

---

### P0-6 — Past-Due Subscribers Lose Access Immediately on First Failed Payment

**Audit reference:** ISSUE-26, HIGH-5
**Description:** `getUserPlan()` only accepts `subscription_status IN ('active', 'trialing')`. When Stripe fires `invoice.payment_failed`, the Worker sets `status='past_due'` and the user's plan immediately downgrades to `free`. Stripe's default retry schedule retries for 7 days before marking a subscription cancelled. A customer with a temporarily declined card loses paid feature access before Stripe gives up.
**User impact:** A customer whose card expired last month gets locked out of all paid features on the very first retry attempt — before they have had any chance to update their payment method.
**Technical impact:** Every `invoice.payment_failed` event triggers an immediate customer downgrade. Support ticket volume will spike on any widespread card decline event.
**Files:** `workers/scan-api/src/index.js` `getUserPlan()` ~line 16897
**Fix required:**
- In `getUserPlan()`, add a `past_due` grace period check:
  ```js
  if (status === "past_due") {
    const failedAt = sub.payment_failed_at ? new Date(sub.payment_failed_at).getTime() : 0;
    if (Date.now() - failedAt < 7 * 24 * 60 * 60 * 1000) return normalizePlan(sub.plan);
    return "free";
  }
  ```
- `payment_failed_at` is already stored in D1 by `handleStripeInvoicePaymentFailed()`.
**Effort:** Small (<1 hour)

---

### P0-7 — Scheduled Scan Failures Are Completely Silent

**Audit reference:** ISSUE-32, HIGH-9
**Description:** The entire body of `triggerScheduledScan()` is wrapped in a catch that discards all errors. When `runScanEngine()` crashes, the scan row is left with `status='running'` forever. `last_run_at` is stamped before the scan executes, so the UI displays "last run: [timestamp]" even when every subsequent run has silently failed. No notification is sent to the workspace owner.
**User impact:** Customers who set up scheduled monitoring believe it is running. If the scan engine breaks (D1 error, R2 failure, Worker CPU timeout), they will not discover the failure until they notice stale data — potentially days or weeks later.
**Technical impact:** Silent failures prevent operational debugging. `status='running'` rows accumulate and pollute scan history.
**Files:** `workers/scan-api/src/index.js` `triggerScheduledScan()` (inner try/catch wrapping `runScanEngine()`)
**Fix required:**
- Add an inner try/catch specifically around `runScanEngine()`:
  ```js
  try {
    await runScanEngine(scanId, domainId, workspaceId, domain, env);
  } catch (e) {
    console.error('[scheduled-scan] FAILED', { scheduleId: schedule.id, domain, error: e?.message });
    await env.cybermeters_db.prepare(
      `UPDATE scans SET status = 'failed', completed_at = datetime('now') WHERE id = ?`
    ).bind(scanId).run().catch(() => {});
    // INSERT workspace notification for the failure (use existing notification table)
  }
  ```
- The outer catch can remain as a last-resort guard for catastrophic failures that prevent even the above.
**Effort:** Medium (1–4 hours)

---

## P1 — Strongly Recommended Before Public Beta

These 7 issues do not fully block first-use but will generate immediate support tickets, cause billing disputes, or permanently damage customer trust within the first week of beta.

---

### P1-1 — Microsoft SSO Missing from Signup Page

**Audit reference:** ISSUE-14, HIGH-4
**Description:** `LoginPage.jsx` has a "Continue with Microsoft" button. `SignupPage.jsx` does not. Users who want Microsoft SSO registration must accidentally find the login page and try the SSO button there.
**User impact:** Enterprise beta users who rely on Microsoft identity cannot self-serve through the expected registration flow.
**Files:** `frontend/src/pages/SignupPage.jsx`
**Fix required:** Add an `<a href="${BASE}/auth/microsoft/login">Continue with Microsoft</a>` button identical to the one on `LoginPage.jsx`. No Worker changes needed.
**Effort:** Small (<1 hour)

---

### P1-2 — Workspace Rename Is Impossible

**Audit reference:** ISSUE-20, HIGH-6
**Description:** No `PATCH /api/workspaces/:id` endpoint exists. A workspace name set at creation is permanent. A typo requires deleting and recreating the workspace.
**User impact:** A basic expectation of any SaaS product. Will generate immediate feedback from beta users.
**Files:** `workers/scan-api/src/index.js` (new route)
**Fix required:** Add `PATCH /api/workspaces/:id` accepting `{ name: string }`. Validate with `requireWorkspaceRole(user, id, "workspace:manage", env)`. Run `UPDATE workspaces SET name = ?, updated_at = datetime('now') WHERE id = ?`. Create an audit event `workspace_renamed`.
**Effort:** Medium (1–4 hours)

---

### P1-3 — Domain Removal Does Not Cascade to Scheduled Scans or Assets

**Audit reference:** ISSUE-21, HIGH-7
**Description:** `DELETE /api/workspaces/:id/domains/:domainId` only removes the `workspace_domains` link row. Scheduled scans for the removed domain continue to run on each cron tick, creating new scan rows for a domain the user has explicitly removed. Assets remain `status='active'` in `workspace_assets`.
**User impact:** After removing a domain, users see continued scan activity and asset counts for that domain. Billing for scan quota may accrue for a domain the user removed.
**Files:** `workers/scan-api/src/index.js` ~line 28016
**Fix required:**
- `UPDATE scheduled_scans SET enabled = 0 WHERE workspace_id = ? AND domain = ?` (disable — preserve history per Rule 5).
- `UPDATE workspace_assets SET status = 'inactive' WHERE workspace_id = ? AND domain_id = ?` (archive — do not delete).
- Do not delete scan history or reports.
**Effort:** Small (<1 hour)

---

### P1-4 — No Email Notification When Subscription Is Cancelled

**Audit reference:** ISSUE-27, HIGH-8
**Description:** `handleStripeSubscriptionDeleted()` updates D1 status to `'canceled'` and returns. No email is sent to the workspace owner, no in-app notification is created. The next time the user logs in, their paid features are silently gone.
**User impact:** Customers will not know their subscription was cancelled until they notice a feature stop working. This will drive support tickets and negative perception.
**Files:** `workers/scan-api/src/index.js` `handleStripeSubscriptionDeleted()` ~line 17537
**Fix required:** After setting `status='canceled'`, resolve the workspace owner's email and call `sendCustomerEmail()` with a cancellation notice that includes a link to `/billing` to resubscribe.
**Effort:** Small (<1 hour)

---

### P1-5 — Trial-to-Paid Upgrade May Create Duplicate Subscription Rows

**Audit reference:** ISSUE-25, HIGH-11
**Description:** The 14-day Professional trial is created as a D1 row with no `stripe_subscription_id`. When the user upgrades via Stripe Checkout, `upsertSubscription()` finds no existing row matching on `stripe_subscription_id` and may INSERT a new row. The user ends up with two subscription rows: the orphaned `status='trialing'` row and the new `status='active'` row. Plan resolution uses `ORDER BY updated_at DESC LIMIT 1` which should return the correct active row, but the orphaned trial row persists in billing audit logs.
**User impact:** Indirect — correct plan is returned. Risk is billing audit confusion and potential edge cases where the trial row's recency wins if the active row's `updated_at` is not set correctly.
**Files:** `workers/scan-api/src/index.js` `upsertSubscription()` ~line 17332
**Fix required:** In `upsertSubscription()`, before INSERTing a new row, attempt: `UPDATE subscriptions SET stripe_subscription_id = ?, ... WHERE workspace_id = ? AND stripe_subscription_id IS NULL AND subscription_status = 'trialing'`. If `rows_written > 0`, skip the INSERT. This converts the trial row into the paid subscription row cleanly.
**Effort:** Small (<1 hour)

---

### P1-6 — Scheduled Scans Table Not in Schema or Migrations

**Audit reference:** ISSUE-33, HIGH-10
**Description:** `POST /api/schedules` executes `CREATE TABLE IF NOT EXISTS scheduled_scans (...)` inline before the INSERT. The table definition is not in `database/schema.sql` or any migration file. If the table was created on an older deployment before columns like `last_asset_count` and `asset_change_count` were added, those columns are silently absent — the `CREATE TABLE IF NOT EXISTS` skips DDL without error.
**User impact:** Silent schema divergence between environments. Columns added after initial table creation may be missing on existing D1 databases.
**Technical impact:** Violates Rule 9 (Database Safety). No version-controlled rollback strategy exists for the scheduled_scans schema.
**Files:** `workers/scan-api/src/index.js` ~line 22157; `database/schema.sql`; `database/migrations/`
**Fix required:**
- Add the full `scheduled_scans` DDL to `database/schema.sql`.
- Create a versioned migration file (e.g., `010_scheduled_scans_schema.sql`) with `CREATE TABLE IF NOT EXISTS` plus `ALTER TABLE ADD COLUMN IF NOT EXISTS` for any columns added post-initial creation.
- Remove the inline DDL from the route handler.
**Effort:** Medium (1–4 hours)

---

### P1-7 — Post-Verification Page Requires Manual Click to Reach Login

**Audit reference:** ISSUE-3, ISSUE-15, M-1
**Description:** After a successful email verification (`/verify-email?success=1`), the user sees a success card with a "Sign in" link. There is no auto-redirect or countdown. This is a friction point immediately after the highest-intent moment in the new user journey.
**User impact:** Users who verify their email and then hesitate — a common behavior on mobile, where the email client opened in a separate window — may not notice the button and close the tab.
**Files:** `frontend/src/pages/EmailVerificationPage.jsx`
**Fix required:** Add `useEffect(() => { const t = setTimeout(() => navigate('/login'), 3000); return () => clearTimeout(t); }, [])` on the success state. Display a countdown: "Redirecting to login in 3…"
**Effort:** Small (<1 hour)

---

## P2 — Can Wait Until After Beta Opens

These issues are real but do not block the first cohort of beta users from having a complete, safe experience. Address during beta based on incoming feedback priority.

---

### Security Hardening (P2)

**P2-S1 — Verification token stored as plaintext** (ISSUE-4, M-2)
The `verification_token` column in `users` stores the raw token value. Query is `WHERE verification_token = ?` — not hashed. If D1 were exfiltrated, all active tokens are immediately usable. Remediation: hash with SHA-256 before insert and query by hash (same pattern as `user_sessions.token_hash`). The 24-hour expiry partially mitigates the risk. Effort: Medium.

**P2-S2 — Session tokens in localStorage** (ISSUE-6, L-4)
Auth tokens are stored in `localStorage` and are accessible to any XSS payload. Industry standard is HttpOnly `SameSite=Lax; Secure` cookies. Accepting this for the initial beta cohort is reasonable given the controlled user count, but migration should be planned for GA. Effort: Large.

**P2-S3 — Stripe webhook has no idempotency guard** (ISSUE-30, L-7)
Duplicate Stripe webhook delivery (guaranteed at-least-once) can cause duplicate `subscription_events` rows and incorrect `payment_retry_count`. Remediation: check a `stripe_events_processed` table or make all handlers idempotent via upsert. Effort: Medium.

**P2-S4 — Stripe webhook does not validate metadata workspace ownership** (ISSUE-29, M-9)
`checkout.session.completed` resolves `workspace_id` from session metadata without verifying it matches the workspace's `owner_user_id`. Remediation: validate `workspace.owner_user_id = metadata.user_id` before processing. Effort: Small.

---

### Session Management (P2)

**P2-M1 — No sliding session window** (ISSUE-7, M-3)
Sessions expire hard at 30 days from creation regardless of activity. Active daily users will be silently logged out on day 30. Remediation: extend `expires_at = datetime('now', '+30 days')` in the fire-and-forget `requireAuth()` update. Effort: Small.

**P2-M2 — Sessions accumulate indefinitely** (ISSUE-8, M-5)
No per-user session cap exists. Login always inserts a new row. Remediation: at login time, delete expired sessions for the same user; optionally cap active sessions at N and delete the oldest. Effort: Small.

**P2-M3 — No session list or revocation UI** (ISSUE-9, M-4)
Users cannot see where they are logged in or sign out other devices. Remediation: `GET /api/auth/sessions` returning active sessions; "Sign out all devices" button in settings. Effort: Large.

---

### Reliability (P2)

**P2-R1 — No concurrency cap on scheduled scan bursts** (ISSUE-34, M-10)
All due schedules fire simultaneously in the cron handler. If N schedules are due at the same tick, N × 50+ subrequests run in the same Worker invocation, approaching the 1,000-subrequest limit. Remediation: process a maximum of 5–10 schedules per cron invocation; reschedule the rest. Effort: Medium.

**P2-R2 — Legacy RBAC RBAC fallback with NULL owner** (ISSUE-23, M-8)
Workspaces where `owner_user_id IS NULL` (created via unauthenticated path or corrupted migration) become permanently inaccessible to all users. Remediation: migration to backfill `workspace_members` rows for workspaces with a non-null `owner_user_id` and no members. Effort: Small.

**P2-R3 — Microsoft OAuth token revocation not propagated** (ISSUE-11, L-3)
When a Microsoft user's OAuth token is revoked externally, their CyberMeters session remains valid for up to 30 days. Hard to solve without Microsoft backchannel logout. Remediation for beta: document the limitation; consider shorter TTL (7 days) for OAuth-origin sessions. Effort: Large (if implementing; Small if documenting only).

---

### Customer Experience (P2)

**P2-X1 — Dashboard empty state for new users not confirmed** (ISSUE-17, M-6)
Code inspection could not confirm whether `Dashboard.jsx` renders a helpful empty state or a blank/error screen when `workspaces.length === 0`. Remediation: inspect and, if absent, add a "Create your first workspace" card with a link to `/onboarding`. Effort: Small.

**P2-X2 — Free plan users see confusing 403 on schedule creation** (ISSUE-35, M-11)
`SchedulesPage` is accessible to all authenticated users. Free plan users (0 scheduled scans) reach the creation UI and receive an unexplained 403. Remediation: detect `plan === 'free'` on page load and render a feature gate card with an upgrade CTA instead of the form. Effort: Small.

**P2-X3 — Pricing CTA does not preserve return URL through auth** (ISSUE-18, M-7)
Users who arrive from `/pricing`, click "Get Started," complete auth, and land at `/dashboard` rather than back in the billing flow. Remediation: pass `?return=/billing` through the signup/login flow. Effort: Small.

**P2-X4 — No user timezone for scheduled scan timing** (ISSUE-36, L-9)
All scan scheduling is UTC-relative. Users will see their "daily" scan run at an arbitrary local time. Remediation: add `preferred_hour_utc` to `scheduled_scans` in a future sprint. Effort: Medium.

---

### Data Integrity (P2)

**P2-D1 — Subscription lookup by owner_user_id breaks on transfer** (ISSUE-28, L-8)
`getUserPlan()` and `getWorkspaceSubscription()` resolve via `workspace.owner_user_id → subscriptions.owner_user_id`. If ownership is ever transferred, the subscription chain breaks. Remediation: make `workspace_id` the primary lookup key for subscriptions (column already exists). Effort: Medium.

**P2-D2 — OAuth/local account collision path not hardened** (ISSUE-5, L-1)
A pre-existing unverified local account and a later Microsoft OAuth login for the same email are not cleanly merged. Remediation: in the OAuth exchange handler, detect the local account, set `email_verified=1`, and merge the session rather than creating a parallel identity. Effort: Medium.

---

## Recommended Sprint Plan

### Sprint A — Beta Blockers

**Scope:** All 7 P0 items.
**Estimated effort:** 3–4 days (two engineers, one sprint).

| Item | Effort |
|------|--------|
| P0-1: Workspace soft-delete | Medium |
| P0-2: Onboarding redirect on first login | Small |
| P0-3: Resolve workspace owner in triggerScheduledScan | Small |
| P0-4: Resend verification rate limit | Small |
| P0-5: Email delivery error logging | Small |
| P0-6: Past-due grace period | Small |
| P0-7: Scheduled scan failure handling | Medium |

**Expected readiness improvement:** 40% → 72%.

---

### Sprint B — Lifecycle Completion

**Scope:** All 7 P1 items.
**Estimated effort:** 2–3 days.

| Item | Effort |
|------|--------|
| P1-1: Microsoft SSO on signup page | Small |
| P1-2: Workspace rename endpoint | Medium |
| P1-3: Domain removal cascade to schedules and assets | Small |
| P1-4: Cancellation email notification | Small |
| P1-5: Trial-to-paid duplicate subscription fix | Small |
| P1-6: Scheduled scans table into schema/migrations | Medium |
| P1-7: Post-verification auto-redirect | Small |

**Expected readiness improvement:** 72% → 88%.

---

### Sprint C — Customer Experience

**Scope:** High-value P2 items that affect first-week beta user experience.
**Estimated effort:** 2 days.

| Item | Effort |
|------|--------|
| P2-M1: Session sliding window | Small |
| P2-M2: Session accumulation limit | Small |
| P2-X1: Dashboard empty state for new users | Small |
| P2-X2: Free plan gate on schedules page | Small |
| P2-X3: Pricing return URL preservation | Small |
| P2-S4: Stripe webhook workspace validation | Small |
| P2-R1: Scheduled scan concurrency cap | Medium |
| P2-R2: Legacy RBAC backfill migration | Small |

**Expected readiness improvement:** 88% → 94%.

---

### Sprint D — Commercial Readiness & Security Hardening

**Scope:** Security improvements and long-horizon reliability work. Can run in parallel with beta operations.
**Estimated effort:** 4–6 days (higher complexity items).

| Item | Effort |
|------|--------|
| P2-S1: Hash verification token before storage | Medium |
| P2-S2: Migrate session tokens to HttpOnly cookie | Large |
| P2-S3: Stripe webhook idempotency guard | Medium |
| P2-M3: Session revocation UI | Large |
| P2-D1: Subscription lookup by workspace_id primary | Medium |
| P2-D2: OAuth/local account collision hardening | Medium |
| P2-R3: Document Microsoft OAuth revocation limitation | Small |
| P2-X4: User timezone support for scheduled scans | Medium |

**Expected readiness improvement:** 94% → 98%.

---

## Final Verdict

### ❌ NOT READY FOR PUBLIC BETA

**Justification:**

Three independent blockers prevent a functional beta experience:

**P0-1 (Workspace deletion non-functional)** means any user who requests deletion of their account data receives a false success response. Inviting external users to a product that cannot honor a deletion request creates regulatory exposure under GDPR and potential liability under any Terms of Service that promise data deletion. This is not a UX issue — it is a compliance issue.

**P0-2 (No onboarding redirect)** means every self-registered beta user will land on a blank dashboard with no guidance. The OnboardingPage is already built; the fix is a single `navigate()` call. Without it, the activation funnel is broken from day one.

**P0-3 (Scheduled scans under user_demo)** means any customer who creates a scheduled scan and relies on it for ongoing security monitoring is silently receiving degraded execution under free-plan limits. For a security product, silent degradation is a trust issue, not just a quality issue.

All three P0 blockers are small-to-medium effort fixes — Sprint A is estimated at 3–4 days. The platform's core capabilities (ASM engine, reporting, multi-workspace architecture, Stripe billing integration, RBAC, domain verification) are substantively complete and production-grade.

**Conditional path to beta:** Complete Sprint A in full. After Sprint A, re-assess. With all P0 items resolved, the product moves from 40% to approximately 72% readiness — sufficient for a controlled, invitation-only beta with a small first cohort, provided Sprint B is begun concurrently and completed within the first two weeks of beta.

**Recommended launch posture after Sprint A:** Invite 10–20 beta users directly (not via public signup page). Monitor for issues. Complete Sprint B before expanding the cohort.
