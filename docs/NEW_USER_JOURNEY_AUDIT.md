# NEW_USER_JOURNEY_AUDIT.md

Sprint 10D — Phase 3
Date: 2026-06-23
Auditor: Code inspection (no assumptions)

---

## Scope

Files inspected:
- `frontend/src/App.jsx` — routing and ProtectedRoute logic
- `frontend/src/pages/SignupPage.jsx`
- `frontend/src/pages/EmailVerificationPage.jsx`
- `frontend/src/pages/LoginPage.jsx`
- `frontend/src/pages/OnboardingPage.jsx` (partial)
- `frontend/src/context/AuthContext.jsx`
- `workers/scan-api/src/index.js` — POST /api/workspaces (auto-creates trial)

---

## Expected Journey (10 Steps)

```
1. User visits /signup
2. Fills name, email, password → POST /api/auth/signup
3. Lands on "Check your email" screen (SignupPage done=true)
4. Clicks verification link in email → Worker redirects to /verify-email?success=1
5. EmailVerificationPage shows success → user clicks "Sign in"
6. Lands on /login
7. Enters credentials → POST /api/auth/login → receives token
8. AuthContext stores token → navigates to /dashboard
9. User sees dashboard (potentially empty)
10. User navigates to /onboarding or creates workspace/runs scan
```

---

## Findings

### ISSUE-12 — CRITICAL — No automatic onboarding redirect for new users

**File:** `frontend/src/App.jsx`, `frontend/src/context/AuthContext.jsx`
**Root cause:** After first login, all users land at `/dashboard` (via `navigate(from, { replace: true })` with `from` defaulting to `'/dashboard'`). There is no logic to detect "this is a new user with no workspace or scan" and redirect to `/onboarding`.

`ProtectedRoute` only checks authentication — it does not check workspace existence, onboarding completion, or any new-user signal.

```jsx
// App.jsx — ProtectedRoute
function ProtectedRoute({ children }) {
  if (isLoading) return <Spinner />
  if (!isAuthenticated) return <Navigate to="/login" ... />
  return children   // no new-user check — all users go to /dashboard
}

// LoginPage.jsx
navigate(from, { replace: true })  // from = '/dashboard' for new users
```

**Impact for beta:** A new user who has never created a workspace will see whatever the Dashboard's empty state is. There is no guided path to "create a workspace → add a domain → run a scan." This is a Day 1 experience failure.

**Remediation:** After successful login, call `GET /api/workspaces`. If the result is `{ workspaces: [] }`, redirect to `/onboarding`. This check should happen in `AuthContext` or in a `NewUserGuard` wrapper around ProtectedRoute.

---

### ISSUE-13 — HIGH — OnboardingPage exists but is never shown automatically

**File:** `frontend/src/App.jsx`
**Root cause:** `/onboarding` is a valid protected route that renders `<OnboardingPage />`. The page appears to implement a guided step-by-step flow (workspace → domain → verify → scan). However, no part of the authentication or dashboard flow directs users to it.

```jsx
// App.jsx
<Route path="onboarding" element={<OnboardingPage />} />
// No <Navigate to="onboarding" /> on login for new users
```

**Impact for beta:** The onboarding page is dead code from the user's perspective. Users who discover it manually will have a good first experience; users who don't will be stuck on an empty dashboard.

**Remediation:** See ISSUE-12. One redirect from dashboard → onboarding for workspaceless users is the fix for both.

---

### ISSUE-14 — HIGH — Signup form has no Microsoft SSO option

**File:** `frontend/src/pages/SignupPage.jsx`
**Root cause:** `LoginPage.jsx` has a "Continue with Microsoft" button. `SignupPage.jsx` does not. A user who wants to use Microsoft SSO must know to go to the login page first and click the SSO button there (which will create their account on first use via the OAuth exchange handler).

This is not discoverable from the signup page.

**Remediation:** Add a "Sign up with Microsoft" button to `SignupPage.jsx` identical to the one on `LoginPage.jsx`. Both point to the same Worker endpoint `${BASE}/auth/microsoft/login`.

---

### ISSUE-15 — MEDIUM — After email verification, no auto-redirect to login

**File:** `frontend/src/pages/EmailVerificationPage.jsx`
**Root cause:** (Already documented as ISSUE-3 in Phase 1 audit.) After `?success=1`, the user sees a success card with a "Sign in" link. There is no 3-second countdown redirect.

This is a friction point specifically for new users who are completing their first-ever flow and may not realize they need to click the button.

**Remediation:** `useEffect(() => { setTimeout(() => navigate('/login'), 3000) }, [])` with countdown display.

---

### ISSUE-16 — MEDIUM — Password confirmation field not validated server-side

**File:** `frontend/src/pages/SignupPage.jsx`
**Root cause:** The "Confirm password" field is validated client-side only. The Worker's `POST /api/auth/signup` accepts `password` without a `confirm_password` parameter. While this is standard (confirmation is a UX layer, not a security layer), if the JS form is bypassed, a user could register with a typo in their password and have no recovery path other than "Forgot password."

**Remediation:** Low priority. Client-side validation is sufficient. Ensure `ForgotPasswordPage` is reachable from the post-signup verification screen.

---

### ISSUE-17 — MEDIUM — Dashboard "empty state" behavior for new users not verified

**File:** `frontend/src/pages/Dashboard.jsx` (not inspected — insufficient data)
**Root cause:** Cannot confirm from code inspection whether the Dashboard shows a helpful empty state for users with no workspaces/scans or whether it renders an error/blank screen.

**Remediation:** Inspect `Dashboard.jsx`. If `workspaces.length === 0`, the component should render a "Create your first workspace" card with a link to `/onboarding` rather than an empty list or error.

---

### ISSUE-18 — LOW — /pricing route is public but checkout requires auth

**File:** `frontend/src/App.jsx`
**Root cause:** `/pricing` is a public (non-ProtectedRoute) page. A new user who has not yet registered can view pricing. When they click "Get Started" on a plan, the checkout flow requires authentication. The redirect after login for checkout is not preserved — users land at `/dashboard` after signing in from a pricing CTA.

**Remediation:** Pass `?return=/billing` or similar state through the signup/login flow so that users who arrived from pricing land on the billing page after authentication.

---

## Journey Status

| Step | Status | Issue |
|------|--------|-------|
| 1. Visit /signup | ✓ Works | — |
| 2. Submit signup form | ✓ Works | ISSUE-14: No Microsoft SSO on signup page |
| 3. "Check your email" screen | ✓ Works | — |
| 4. Click verification link | ✓ Works | — |
| 5. /verify-email?success=1 | ✓ Renders | ISSUE-15: No auto-redirect to login |
| 6. /login | ✓ Works | — |
| 7. Enter credentials | ✓ Works | — |
| 8. Redirected after login | ✓ Works | ISSUE-12/13: Goes to dashboard, not onboarding |
| 9. Dashboard | ? Unknown | ISSUE-17: Empty state not confirmed |
| 10. Guided to first scan | ✗ Missing | ISSUE-12: No guidance path |

---

## Summary

| # | Severity | Issue |
|---|----------|-------|
| 12 | CRITICAL | No automatic onboarding redirect for new users (no workspace = stuck at dashboard) |
| 13 | HIGH | OnboardingPage is never shown automatically — dead code for new users |
| 14 | HIGH | Signup page has no Microsoft SSO option |
| 15 | MEDIUM | No auto-redirect after email verification success |
| 16 | MEDIUM | Password confirmation is client-side only |
| 17 | MEDIUM | Dashboard empty state for new users not confirmed |
| 18 | LOW | Pricing CTA does not preserve return URL through auth |
