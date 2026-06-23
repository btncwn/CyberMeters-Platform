# SESSION_LIFECYCLE_AUDIT.md

Sprint 10D — Phase 2
Date: 2026-06-23
Auditor: Code inspection (no assumptions)

---

## Scope

Files inspected:
- `workers/scan-api/src/index.js` — requireAuth(), POST /api/auth/login, POST /api/auth/logout, GET /api/auth/me
- `frontend/src/context/AuthContext.jsx`
- `frontend/src/api.js` (inferred from AuthContext imports: `validateSession`, `registerUnauthorizedHandler`)

---

## Session Architecture

```
Login:
  POST /api/auth/login → generates 30-day session token (raw hex)
  → hash stored in user_sessions (token_hash)
  → raw token returned to client → stored in localStorage['cybermeters_auth_token']

Every request:
  Authorization: Bearer <raw_token>
  Worker: SHA-256(raw) → lookup user_sessions WHERE token_hash=? AND expires_at > now()

On mount (AuthContext):
  if localStorage has token → validateSession() → GET /api/auth/me
  if 401 → logout() → clear localStorage

Logout:
  POST /api/auth/logout with Bearer token
  → DELETE FROM user_sessions WHERE token_hash=?
  → localStorage.removeItem(TOKEN_KEY)

Unauthorized (401) in any API call:
  registerUnauthorizedHandler(logout) → triggers logout() globally
```

---

## Findings

### ISSUE-6 — HIGH — Sessions stored in localStorage (no HttpOnly cookie)

**File:** `frontend/src/context/AuthContext.jsx`
**Root cause:** The session token is stored in `localStorage` under `'cybermeters_auth_token'`. Any XSS vulnerability in the React frontend can exfiltrate the token directly via `localStorage.getItem('cybermeters_auth_token')`.

```js
// AuthContext.jsx
const login = useCallback((newToken, newUser) => {
  localStorage.setItem(TOKEN_KEY, newToken)   // token in localStorage — XSS accessible
  ...
```

HttpOnly cookies are immune to JavaScript access and are the industry standard for session token storage.

**Remediation:** Migrate to HttpOnly `SameSite=Lax; Secure` cookies. The Worker sets `Set-Cookie` on login response; client does not touch the cookie — the browser attaches it automatically. The Authorization header path can remain for API tokens (different use case).

**Priority note:** This is the correct architecture for a public beta. localStorage tokens are acceptable for early development but not for a product serving external customers.

---

### ISSUE-7 — MEDIUM — Session expiry is not extended on activity (no sliding window)

**File:** `workers/scan-api/src/index.js`
**Root cause:** Sessions expire exactly 30 days after creation. `requireAuth()` updates `last_seen_at` (fire-and-forget) but does NOT extend `expires_at`. An active user will be silently logged out on day 30.

```js
// requireAuth() — fires update but does NOT extend expires_at
env.cybermeters_db
  .prepare("UPDATE user_sessions SET last_seen_at = datetime('now') WHERE id = ?")
  .bind(session.session_id)
  .run()
  .catch(() => {});  // fire-and-forget — expires_at unchanged
```

**Impact for beta:** A customer who onboards on day 1 and is active daily will be silently logged out on day 30 with no warning. This looks like a product bug.

**Remediation:** On each successful `requireAuth()` call, extend `expires_at = datetime('now', '+30 days')` in the same fire-and-forget update. This creates a true 30-day sliding window.

---

### ISSUE-8 — MEDIUM — No per-user session limit — sessions accumulate indefinitely

**File:** `workers/scan-api/src/index.js`
**Root cause:** `POST /api/auth/login` always INSERTs a new session row without checking or limiting existing sessions per user. A user who logs in daily for a year accumulates 365 session rows. These are only cleaned up when they expire (30 days after creation) or when the user explicitly logs out.

There is no `GET /api/auth/sessions` endpoint for users to review or revoke individual sessions.

**Remediation:** At login time, after inserting the new session, delete sessions for the same user that are already expired. Optionally, keep a maximum of N concurrent active sessions and delete the oldest when the limit is exceeded.

---

### ISSUE-9 — MEDIUM — No session list or revocation UI

**File:** None (feature is absent)
**Root cause:** Beta users expect to see "Where am I logged in?" and "Sign out all devices." There is no `GET /api/auth/sessions` endpoint and no frontend page for session management.

**Remediation:** Add `GET /api/auth/sessions` returning `[{ id, created_at, last_seen_at, ip_address, user_agent }]` for the authenticated user. Add a "Security" settings section with a "Sign out all other devices" button.

---

### ISSUE-10 — LOW — Suspended users with existing sessions are rejected by requireAuth but plan cache is not invalidated

**File:** `workers/scan-api/src/index.js`
**Root cause:** `requireAuth()` correctly returns null if `session.status === "suspended"`. However, `getEffectivePlan()` queries by `user_id` and is called separately — a suspended user whose session is rejected will not reach `getEffectivePlan()`, so this is not exploitable. The session remains in D1 until it expires (up to 30 days), which wastes storage but has no security impact since the row is always checked.

**Remediation:** On account suspension, DELETE all sessions for that user_id immediately rather than waiting for natural expiry.

---

### ISSUE-11 — LOW — Microsoft OAuth sessions are not differentiated from local sessions

**File:** `workers/scan-api/src/index.js`
**Root cause:** When a Microsoft OAuth user's token is revoked on the Microsoft side (e.g., conditional access policy, password reset), CyberMeters has no webhook or backchannel to know. The local session in `user_sessions` remains valid until it expires.

**Remediation:** This is a hard problem (requires Microsoft backchannel logout). For beta, document the limitation. Mitigation: shorter session TTL for OAuth-origin sessions (7 days) or a periodic re-validation check.

---

## Session Token Security Verified ✓

The following properties were confirmed correct:
- Token is 64-char raw hex, SHA-256 hashed before storage ✓
- `requireAuth()` always checks `expires_at > datetime('now')` ✓
- Logout deletes the session row from D1 immediately ✓
- `registerUnauthorizedHandler(logout)` wires all 401 responses to local logout ✓
- On mount, AuthContext validates the stored token server-side before trusting it ✓
- MFA challenge tokens use a separate table (`mfa_challenges`) with 10-minute TTL ✓

---

## Summary

| # | Severity | Issue |
|---|----------|-------|
| 6 | HIGH | Tokens in localStorage — XSS-accessible |
| 7 | MEDIUM | No sliding window — users logged out after 30 days regardless of activity |
| 8 | MEDIUM | No session limit — rows accumulate indefinitely per user |
| 9 | MEDIUM | No session list or revocation UI |
| 10 | LOW | Suspended user sessions not purged immediately |
| 11 | LOW | Microsoft OAuth revocation not propagated |
