# Founder Live Microsoft-SSO Acceptance Script

Purpose: the **minimal** manual actions that cannot be automated, to accept the
Microsoft (Entra) SSO login path against a **real** identity provider. Everything
that is deterministic and does not need a live IdP is already proven in CI by
`scripts/validate-oauth-callback-readiness.js` (state CSRF single-use/TTL,
config/error gates, OTC single-use, nonce binding) and
`scripts/validate-auth-coverage.js` B5 (id_token claim validation:
alg/aud/exp/nbf/iss/tid/oid/nonce), plus `scripts/validate-sso-linking-guard.js`
(nOAuth single-tenant `tid` enforcement) and `scripts/validate-auth-session-hardening.js`
(SSO MFA gate). This script covers ONLY what a real Microsoft round-trip adds:
the live token exchange, the RS256/JWKS signature verification, and the browser
redirect handoff.

Do not run this until the Worker + Pages carrying the SSO code are deployed and
the Azure App Registration is configured. This is a founder action; the engineer
does not perform it.

## Prerequisites (config, not code)

- Azure App Registration exists; `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`,
  `AZURE_TENANT_ID` set as Worker secrets. For account auto-linking safety,
  `AZURE_TENANT_ID` MUST be a specific tenant GUID (single-tenant), never
  `common` / `organizations` / `consumers` — a multi-tenant alias disables
  email-based auto-linking by design (nOAuth guard).
- Redirect URI registered in Azure EXACTLY matches
  `https://<app-domain>/api/auth/microsoft/callback` (and `MICROSOFT_REDIRECT_URI`
  if set).
- A Microsoft test account in the configured tenant.
- A second Microsoft test account for the cross-account check (optional but
  recommended).

## Minimal acceptance steps

1. **Happy-path new account.** In a clean browser, click "Sign in with Microsoft".
   Complete the Microsoft prompt with a test account that has NO existing
   CyberMeters account. Expect: redirect back to the app, landed signed-in, a new
   `users` row with `auth_provider='microsoft'`, `microsoft_oid` set,
   `email_verified=1`. Confirm the URL never contained the bearer token (only a
   short `otc` parameter).

2. **Returning account (oid match).** Sign out, sign in again with the same
   account. Expect: same user row reused (matched by `microsoft_oid`), a new
   session, `last_login_at` advanced.

3. **Account-linking (single-tenant only).** With a pre-existing
   email/password account whose email equals a tenant test account, sign in via
   Microsoft. Expect: the existing account is linked (`microsoft_oid` populated),
   and if it was unverified it becomes `email_verified=1` / `status='active'`.
   Confirm you are signed into the SAME account (no duplicate).

4. **MFA-enabled account.** On an account with MFA enabled, sign in via Microsoft.
   Expect: NO session yet — the app presents the MFA challenge (same UI as
   password login), and only after a valid TOTP/recovery code is a session
   issued. This proves SSO does not bypass the second factor.

5. **Suspended account.** Suspend a test account, attempt Microsoft sign-in.
   Expect: redirect to `/login` with a "suspended" message and NO session.

6. **Consent-denied / provider error.** Start the Microsoft sign-in and cancel at
   the Microsoft consent screen. Expect: redirect to `/login` with a generic
   "sign-in was cancelled or failed" message and NO session.

7. **Cross-account isolation (recommended).** Sign in as account A, note the
   workspace(s) visible. Sign in as account B in a separate session; confirm B
   sees none of A's workspaces (this is already covered by the tenant-isolation
   suites, but confirm once through the live SSO session).

## Evidence to capture

For each step: the resulting HTTP status/redirect, the signed-in identity, the
relevant `audit_events` row (`signup` / `USER_LOGIN_MICROSOFT` /
`mfa_challenge_issued`), and confirmation the bearer token never appeared in a URL.
Record PASS/FAIL per step. A single FAIL blocks the SSO release item.

## What is already proven (do not re-test manually)

- id_token claim validation (aud/iss/exp/nbf/tid/oid/nonce, RS256 alg pin) — CI.
- CSRF `state` single-use + TTL, missing-param and unconfigured-instance handling,
  provider-error redirect — CI (real router).
- OTC single-use + 5-minute TTL, MFA-challenge handoff shape — CI (real router).
- nOAuth single-tenant `tid` enforcement + the email-link gate value — CI.
- SSO MFA gate wiring (challenge issued instead of a session) — CI.
