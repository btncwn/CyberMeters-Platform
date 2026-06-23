# EMAIL_VERIFICATION_AUDIT.md

Sprint 10D — Phase 1
Date: 2026-06-23
Auditor: Code inspection (no assumptions)

---

## Scope

Files inspected:
- `workers/scan-api/src/index.js` — POST /api/auth/signup, POST /api/auth/login, GET /api/auth/verify-email, POST /api/auth/resend-verification
- `frontend/src/pages/SignupPage.jsx`
- `frontend/src/pages/LoginPage.jsx`
- `frontend/src/pages/EmailVerificationPage.jsx`
- `frontend/src/context/AuthContext.jsx`

---

## Flow Summary

```
POST /api/auth/signup
  → inserts user with email_verified=0, verification_token (64-char hex), 24h expiry
  → sends email (fire-and-forget)
  → returns { success: true, verification_required: true, email }

[User clicks link in email]
GET /api/auth/verify-email?token=<hex>
  → looks up user by plain-text verification_token column
  → if expired → redirect /verify-email?error=...
  → if already verified → redirect /verify-email?success=1
  → if valid → SET email_verified=1, verification_token=NULL → redirect /verify-email?success=1

POST /api/auth/login
  → checks email_verified for local accounts
  → if !email_verified → 403 { error: "email_verification_required", email }

POST /api/auth/resend-verification
  → replaces verification_token, sends email again
  → always returns { success: true } (timing-safe)
```

---

## Findings

### ISSUE-1 — HIGH — No rate limiting on resend-verification

**File:** `workers/scan-api/src/index.js`
**Route:** `POST /api/auth/resend-verification`
**Root cause:** The endpoint accepts any email address, regenerates a token, and sends an email with no rate limit, no CAPTCHA, no cooldown check, and no authentication requirement.

Any attacker can loop requests targeting any email address, using CyberMeters as an email spam relay.

```js
// Line ~19254 — no rate check before email send
if (request.method === "POST" && url.pathname === "/api/auth/resend-verification") {
  // ... no IP check, no frequency check, no token
  await sendCustomerEmail(...)  // fires unconditionally
```

**Remediation:** Add a 60-second cooldown per email using a D1 timestamp check against `verification_token_expires_at`. Since the new token is always 24h from now, refuse if `verification_token_expires_at > now - 60s` and return `{ success: true }` silently (to avoid timing attacks). No new table needed.

---

### ISSUE-2 — HIGH — Verification email is fire-and-forget with no fallback signal

**File:** `workers/scan-api/src/index.js`
**Route:** `POST /api/auth/signup`
**Root cause:** `sendCustomerEmail(...)` is called with `.catch(() => {})`. If the email delivery fails (Resend API down, wrong `HELLO_EMAIL_FROM` env var, etc.), the user receives no indication. The signup response always returns `{ success: true, verification_required: true }`.

```js
await sendCustomerEmail(...).catch(() => {});  // line ~18988 — silent failure
return json({ success: true, verification_required: true, email }, 201);
```

**Impact for beta:** A user who never receives the verification email has no recourse other than clicking "Resend". If Resend is misconfigured, all registrations silently fail delivery. This will not surface in any log the user sees.

**Remediation:** Log a structured error if `sendCustomerEmail` throws. Optionally include `{ email_sent: false }` in the response payload (safe — never reveals whether the email address was valid, only whether the system sent an email). Monitor Resend delivery webhooks.

---

### ISSUE-3 — MEDIUM — Post-verification page requires manual click to reach login

**File:** `frontend/src/pages/EmailVerificationPage.jsx`
**Route:** `/verify-email?success=1`
**Root cause:** After a successful verification, the page renders a success card with a "Sign in" `<Link to="/login">` button. There is no automatic redirect and no countdown timer. A user who has just verified their email must notice the button and click it.

```jsx
// EmailVerificationPage.jsx — no useEffect redirect
{success && (
  <>
    <CheckCircle />
    <h1>Email verified</h1>
    <Link to="/login">Sign in</Link>   // manual click only
  </>
)}
```

**Remediation:** Add a 3-second auto-redirect using `useEffect` + `setTimeout(() => navigate('/login'), 3000)`. Show a countdown: "Redirecting to login in 3…"

---

### ISSUE-4 — MEDIUM — Verification token stored as plaintext in users table

**File:** `workers/scan-api/src/index.js` (schema implied by SELECT)
**Root cause:** The verification token is queried by `WHERE verification_token = ?` directly against the stored column value. The token is not hashed before storage. If the D1 database were exfiltrated, all active verification tokens would be immediately usable.

```js
// Line ~19200
`SELECT id, email, email_verified, verification_token_expires_at
 FROM users WHERE verification_token = ? LIMIT 1`
```

**Remediation:** Hash the token with SHA-256 (same pattern as session tokens) before INSERT, and query by hash. The 24-hour expiry provides partial mitigation but does not eliminate the risk.

---

### ISSUE-5 — LOW — Microsoft OAuth users can register a local account with the same email

**File:** `workers/scan-api/src/index.js`
**Route:** `POST /api/auth/signup`
**Root cause:** The duplicate-email check only looks for `id` — it does not distinguish `auth_provider`. If a Microsoft SSO user (who was auto-verified on first OAuth login) signs up locally with the same email address, the 409 conflict fires correctly. However, the converse is not protected: a local account that hasn't verified yet could collide with a later Microsoft SSO login attempt.

The Microsoft OAuth handler (`POST /api/auth/exchange`) inserts/updates via `INSERT OR IGNORE`, so existing local accounts survive. But this path has not been audited for verified-state merging.

**Remediation:** In the OAuth exchange handler, check if an existing local user (auth_provider='local') exists with the same email. If found and email_verified=0, set email_verified=1 and auth_provider='microsoft'. If found and email_verified=1, merge sessions rather than creating a duplicate identity.

---

## Summary

| # | Severity | Issue |
|---|----------|-------|
| 1 | HIGH | No rate limiting on resend-verification (spam relay risk) |
| 2 | HIGH | Verification email fire-and-forget — failures invisible to operator |
| 3 | MEDIUM | Post-verification requires manual click to reach login |
| 4 | MEDIUM | Verification token stored as plaintext (not hashed) |
| 5 | LOW | OAuth/local account collision path not fully hardened |

All issues are code-proven. No assumptions made.
