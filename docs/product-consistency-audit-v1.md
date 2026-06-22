# CyberMeters — Product Consistency, Verification, Billing & UX Audit

Version: June 2026

---

## Executive Summary

This sprint audited six product areas through direct code tracing. Three code-level fixes were implemented immediately. Three issues require product decisions or medium-term engineering work before they can be resolved.

**Overall assessment: Private Beta Ready — with caveats listed below.**

---

## Issue 1 — Domain Verification Workflow

### Findings

The domain verification flow (`POST /api/domains/:id/verify`, DNS TXT + HTML file checks) is fully implemented in the Worker and frontend (`DomainVerifyPage.jsx`). However, the `POST /api/scan` endpoint performs **zero verification checks**. All of the following work regardless of `verification_status`:

- Manual scans
- Scheduled scans
- Report generation
- Historical tracking
- Asset inventory

The `verification_status` column (`unverified` / `pending` / `verified` / `failed`) exists in the database and is tracked in audit events, but it gates nothing at the API layer.

### Root Cause

The verification system was built as a UX and anti-abuse tool, not as a hard enforcement gate. The `POST /api/scan` handler checks auth, workspace role, and plan quota only. No verification check is present.

### Recommendation: Model A (soft-gate)

CyberMeters scans publicly visible information — DNS records, SSL certificates, security headers. This is not private data. Blocking scans on unverified domains would cause a damaging onboarding cliff: a user who wants to scan their own domain can't until they complete a multi-step DNS TXT process.

**Recommended model:**

| Feature | Unverified | Verified |
|---|---|---|
| Manual scans | ✓ Allowed | ✓ Allowed |
| Scan reports | ✓ Allowed | ✓ Allowed |
| Domain history | ✓ Allowed | ✓ Allowed |
| Scheduled scans | ✓ Allowed (current) | ✓ Allowed |
| Monitoring alerts | ✓ Allowed (current) | ✓ Allowed |
| Compliance reports | ✓ Allowed (current) | ✓ Allowed + "Verified Owner" badge |

The key change is not enforcement but **UX clarity**. Currently, the "Unverified" badge appears with no explanation. Users see it and assume something is broken. The fix is messaging, not gating.

**Future gate (medium-term):** Scheduled scans could require verified domains once the verification flow is polished and well-explained. This is a product decision, not a current bug.

### UX Fix Required (not implemented — product decision)

In the domain table on `WorkspaceDetailPage`, the verification badge should include a tooltip or inline text:

> "Unverified — scans work. Verify ownership to unlock compliance badges."

This removes the implication that the platform is in an error state.

---

## Issue 2 — Scan Status Synchronization ✅ FIXED

### Finding

`ScansPage.jsx` loaded the scan list once on mount. If a scan was running when the user navigated to `/scans`, the status showed "Running" permanently — the page had no polling, only a manual Refresh button. The user had to navigate to `ScanDetail` (which does auto-poll at 4s) to see the completed status.

### Root Cause

`ScanDetail.jsx` has auto-poll logic:
```js
const ACTIVE  = new Set(['queued', 'running', 'processing'])
const POLL_MS = 4000
// ...
useEffect(() => {
  if (ACTIVE.has(scan.status)) {
    pollRef.current = setInterval(() => load(true), POLL_MS)
  }
}, [scan?.status])
```

`ScansPage.jsx` had no equivalent — only a `useEffect(() => { load() }, [load])` that ran once.

### Fix Applied

Added conditional auto-poll to `ScansPage.jsx`:
- Polls every **6 seconds** (slightly longer than ScanDetail's 4s to reduce API pressure)
- Only when at least one scan has an active status (`queued`, `running`, `processing`)
- Clears the interval when all scans reach terminal status
- Interval is cleaned up on component unmount

**File modified:** `frontend/src/pages/ScansPage.jsx`

---

## Issue 3 — Navigation Information Architecture ✅ FIXED (partial)

### Finding

The navigation contained three visually similar terms: "Portfolio", "Workspace", "Workspaces". User perception was:

- "Workspace" and "Workspaces" look identical at a glance
- The distinction between them is not obvious from the label alone
- "Portfolio" appearing adjacent to "Workspace" compounds the confusion

### Current nav item mapping

| Label | Route | Content |
|---|---|---|
| Dashboard | /dashboard | Personal/account overview |
| Portfolio | /portfolio | Cross-workspace analytics |
| **Workspace** | /ws/dashboard | Security posture for current workspace |
| **Workspaces** | /workspaces | Workspace list and management |
| Assets | /assets | Asset inventory |
| Scans | /scans | Scan history |
| Schedules | /schedules | Scheduled scan management |
| Reports | /reports | Report library |
| Billing | /billing | Subscription management |
| Academy | /academy | Learning resources |
| Settings | /settings | Account settings |

### Root Cause

"Workspace" (pointing to `/ws/dashboard`) is a security posture dashboard — it shows risk score, active alerts, finding categories, and domain health. The label "Workspace" does not describe this content. "Workspaces" (pointing to `/workspaces`) is workspace management.

The two labels look like duplicates because they share the word "workspace", even though they serve completely different purposes.

### Fix Applied

Renamed "Workspace" → **"Security"** in the navigation.

"Security" accurately describes the content of `/ws/dashboard` (security posture, findings, alerts, risk score). "Workspaces" remains unchanged as the management page.

**New nav:**
Dashboard | Portfolio | **Security** | Workspaces | Assets | Scans | Schedules | Reports | Billing | Academy | Settings

**File modified:** `frontend/src/components/Layout.jsx`

### Remaining IA Recommendations (medium-term, product decision)

The Portfolio / Security / Workspaces hierarchy still has room to improve as the product scales:

1. **Portfolio** should become "All Workspaces" or "Portfolio View" — makes the relationship to individual workspaces explicit.

2. **Security** (currently a flat page) should eventually be context-aware — showing the security dashboard for the *selected* workspace from the WorkspaceSelector dropdown. Today it reads from `localStorage('cybermeters_workspace_id')`, which works but isn't discoverable.

3. As the workspace-level feature set grows (Scorecard, Vendors, Brand Monitoring, etc.), consider a **secondary navigation** pattern — a sidebar or sub-nav within the Security section — rather than adding more top-level nav items.

---

## Issue 4 — Scan Finding Quality

### Findings

Tested domain: `blackbullbarbers.co.uk`

The observed uncertain findings are working as intended:

| Finding | Status | Assessment |
|---|---|---|
| HTTP Redirect — Validation Uncertain | confidence 50 | Correct: site returned non-200, scanner couldn't confirm destination |
| Missing Headers (Unverified) | confidence 60 | Correct: headers not readable when no 200 response |
| DKIM Could Not Be Verified | confidence 70 | Correct: common DKIM selectors not present |
| DNSSEC Not Enabled | confidence 90 | Correct: DNS query confirmed — reliable |
| DMARC Monitor Only | confidence 90 | Correct: DNS TXT record parsed — reliable |

The finding quality system (confidence scores, "Needs Verification" labels, evidence framework) is working correctly. The Worker already has conditional scoring logic at line 6602: "High-severity, high-confidence, verified HTTPS 200 response — score it."

### Root Cause of Perception Issue

The score is displayed as a number (e.g., 62/100) without any explanation of confidence weighting. A user seeing "62" doesn't know that low-confidence findings are weighted less, so the platform can appear to be penalising them for things it couldn't even confirm.

### Recommendations

**Quick win (not implemented — product decision):**
Add a score explanation tooltip: "This score is calculated from verified findings. Unverified findings are shown for awareness but contribute less to your score."

**Medium-term:**
The report could show two tracks: "Confirmed Issues" (high confidence) and "To Investigate" (uncertain, low confidence). This would make the uncertainty model visible to users who care about auditing it.

**No code changes required** — the backend confidence model is correct. This is a UI explanation gap.

---

## Issue 5 — Billing Entitlement Validation ✅ PARTIALLY FIXED

### Finding A — Two billing pages, one unreachable

`BillingPage.jsx` was imported in `App.jsx` but never mounted at any route. The `/billing` route renders `SubscriptionPage.jsx`. `BillingPage.jsx` is dead code — a 827-line file that users never see.

**Fix applied:** Removed dead `import BillingPage from './pages/BillingPage'` from `App.jsx`. Added comment explaining the file is retained for future use.

### Finding B — BillingPage.jsx has wrong entitlements

`BillingPage.jsx` contains hardcoded plan feature lists that contradict the backend `PLAN_LIMITS`:

| Metric | Backend | BillingPage.jsx |
|---|---|---|
| Starter domains | 10 | 25 ❌ |
| Starter users | 3 | 5 ❌ |
| Starter scheduled scans | 5 (global) | 3/workspace ❌ |
| Professional users | 10 | 25 ❌ |
| Business workspaces | 50 | "Unlimited" ❌ |
| Business domains | 1000 | 500 ❌ |
| Business users | 50 | 100 ❌ |

**Impact:** None currently — BillingPage is never rendered. However, if this file is ever mounted at a route, it will show customers incorrect entitlements. The file should either be deleted or corrected before it is used.

### Finding C — SubscriptionPage.jsx is correct

`SubscriptionPage.jsx` (the actual `/billing` page) pulls limits from `GET /api/workspaces/:id/subscription` which returns data from the authoritative `PLAN_LIMITS` object in the Worker. The displayed values are always backend-accurate.

### Finding D — Backend PLAN_LIMITS vs external documentation

The following mismatches exist between backend limits and `BillingPage.jsx` display text. These are for reference when the pricing page / marketing copy is updated:

| Plan | Backend workspaces | Backend domains | Backend users | Backend sched. scans |
|---|---|---|---|---|
| Free | 1 | 3 | 1 | 0 |
| Starter | 3 | 10 | 3 | 5 |
| Professional | 10 | 100 | 10 | 20 |
| Business | 50 | 1000 | 50 | 100 |
| Enterprise | unlimited | unlimited | unlimited | unlimited |

The `PricingPage.jsx` and any marketing copy should match these backend values.

### Finding E — Enforcement model is backend-authoritative

Backend enforcement is present for: domains per account, workspaces, scheduled scans, scans per month, scan burst rate. Frontend limits are informational only. This is correct architecture — backend is the gate.

One gap: the frontend `UpgradePromptModal` in `Layout.jsx` fires for `plan_limit_exceeded` errors but only shows generic copy ("Upgrade options are not connected yet"). This means when a user hits a limit, the CTA is broken. Medium-priority fix: wire the upgrade modal to `handleUpgrade('professional')` with a relevant message.

---

## Issue 6 — Authentication & Session UX

### Finding A — Microsoft SSO works, token-in-URL is a known concern

The Microsoft OAuth flow works end-to-end:
1. User clicks "Sign in with Microsoft" → backend redirects to Microsoft Entra
2. Microsoft redirects back to Worker `/api/auth/microsoft/callback`
3. Worker validates id_token, creates session, redirects to `/auth/microsoft/callback?token=X&id=Y&email=Z&name=N&plan=P`
4. `MicrosoftCallbackPage.jsx` reads params, calls `login()`, navigates to `/dashboard`

Microsoft accounts are auto-verified (`email_verified = 1` at creation). Login gate is bypassed for OAuth users. This is correct.

**Known issue:** The session token appears in URL query params. This means the raw token is in browser history, referrer headers, and any server access logs. For private beta this is acceptable; before public launch the token delivery mechanism should switch to an HTTP-only cookie or POST body.

### Finding B — Session persistence is correct

Sessions: 30-day expiry, SHA-256 hashed in `user_sessions`. `validateSession()` calls `GET /api/auth/me` on app mount. If the token is expired, `requireAuth` returns null, and the app clears state and redirects to login.

The logout race condition fix (Sprint 14C) is in place: `logout()` is called before `logoutWithToken()`, preventing the race window where background polls could trigger `handleUnauthorized()`.

### Finding C — Email/password registration is production-ready

- Signup sends verification email (fire-and-forget, succeeds even if email delivery fails)
- Login gate enforces `email_verified = 1` for local accounts
- Resend verification works
- Password reset flow is implemented
- All existing users are grandfathered as verified (migration 049)

### Finding D — Auth is private-beta ready

The only gap before public launch: token-in-URL for Microsoft OAuth. Everything else (login, signup, verification, logout, session expiry, race condition) is production-quality.

---

## Summary of Code Changes

| File | Change | Issue |
|---|---|---|
| `frontend/src/pages/ScansPage.jsx` | Add auto-poll when active scans present | Issue 2 |
| `frontend/src/components/Layout.jsx` | Rename "Workspace" → "Security" in nav | Issue 3 |
| `frontend/src/App.jsx` | Remove dead `BillingPage` import | Issue 5 |

---

## Quick Wins (Implemented)

1. **Scan list auto-poll** — scans now update without navigating to detail page
2. **Nav rename** — "Security" vs "Workspaces" is unambiguous; no route changes required
3. **Dead import removed** — bundle no longer includes unused 827-line component

---

## Medium-Term Improvements (Product Decision Required)

1. **Domain verification UX copy** — add tooltip/inline text explaining that unverified domains still work; verification unlocks compliance badges
2. **Score explanation tooltip** — clarify that uncertain findings are weighted less, not excluded
3. **UpgradePromptModal CTA** — wire "Upgrade options are not connected yet" copy to actual checkout flow
4. **BillingPage.jsx** — either delete or correct plan limits before mounting at any route
5. **WorkspaceNav secondary navigation** — as workspace-level pages grow, add a sidebar or sub-nav within "Security" section

---

## High-Risk Changes (Approval Required Before Implementation)

1. **Microsoft OAuth token-in-URL** — switch to HTTP-only cookie or POST body redirect. Breaking change to OAuth callback flow. Required before public launch.
2. **Scheduled scan verification gate** — require verified domain to create a scheduled scan. Improves abuse prevention but adds friction. Do not implement until verification flow UX is significantly improved.
3. **Portfolio label change** — renaming "Portfolio" to "All Workspaces" or another term touches a primary nav item and any customer documentation. Low code risk, medium communication risk.

---

## Beta Readiness Assessment

| Area | Private Beta | Public Beta | Commercial Launch |
|---|---|---|---|
| Core scanning | ✅ Ready | ✅ Ready | ✅ Ready |
| Authentication (email/password) | ✅ Ready | ✅ Ready | ✅ Ready |
| Authentication (Microsoft SSO) | ✅ Ready | ⚠️ Token-in-URL | ❌ Fix required |
| Scan status display | ✅ Fixed | ✅ Fixed | ✅ Fixed |
| Navigation clarity | ✅ Improved | ✅ Improved | ⚠️ Consider full IA |
| Billing (subscription page) | ✅ Ready | ✅ Ready | ✅ Ready |
| Domain verification UX | ⚠️ Confusing badge | ⚠️ Confusing badge | ❌ Fix required |
| Billing entitlements (backend) | ✅ Correct | ✅ Correct | ✅ Correct |
| Billing entitlements (frontend) | ✅ Correct (SubscriptionPage) | ✅ Correct | ⚠️ BillingPage.jsx stale |
| Finding quality | ✅ Ready | ✅ Ready | ✅ Ready |
| Upgrade CTA wiring | ⚠️ "Not connected" | ❌ Fix required | ❌ Fix required |

**Verdict: Private Beta — YES. Public Beta — not until Microsoft OAuth token delivery and upgrade CTA are addressed.**
