# CyberMeters — OWASP ASVS 5.0 Level 2 Gap Assessment

> A verifiable, requirement-by-requirement check of CyberMeters against the
> **OWASP Application Security Verification Standard (ASVS) 5.0**, targeting
> **Level 2** (the right bar for an app that processes payments, security data
> and multi-tenant customer records). This maps each ASVS chapter to what we
> actually implement, with evidence and gaps — not a checkbox exercise.

**Owner:** Lead Engineer. **Last updated:** 2026-07-11. Living document.
**Legend:** ✅ meets L2 · 🟡 partial · ⬜ gap · N/A not applicable to the stack.

Companion to `docs/THREAT-MODEL.md` and `docs/SECURITY-SDLC-ROADMAP.md`.
Format per row: `Status — evidence / gap`.

---

## Summary

| ASVS 5.0 chapter | L2 status |
|---|---|
| 1. Encoding & Sanitization | ✅ |
| 2. Validation & Business Logic | 🟡 |
| 3. Web Frontend Security | ✅ |
| 4. API & Web Service | ✅ |
| 5. File Handling | ✅ |
| 6. Authentication | ✅ |
| 7. Session Management | ✅ |
| 8. Authorization | ✅ |
| 9. Self-contained Tokens | 🟡 |
| 10. OAuth & OIDC | ✅ |
| 11. Cryptography | ✅ |
| 12. Secure Communication | ✅ |
| 13. Configuration | 🟡 |
| 14. Data Protection | 🟡 |
| 15. Secure Coding & Architecture | ✅ |
| 16. Logging & Error Handling | 🟡 |

**Overall:** at or near ASVS L2. The 🟡 chapters have concrete, tracked gaps
(below); none is a public-beta blocker.

---

## Chapter detail

### 1 — Encoding & Sanitization ✅
- Output encoding: all email templates route interpolation through `escapeEmailHtml`; the SPA has **no** `dangerouslySetInnerHTML` / `innerHTML` / `eval` / `new Function` (grep-verified in the red-team pass).
- Injection: **all** D1 queries are parameterised (`.bind()`); no string-built SQL. SAST (Semgrep p/security-audit + p/owasp-top-ten) runs in CI and is clean.

### 2 — Validation & Business Logic 🟡
- Input validation: email/domain/plan validated server-side; bounded integers (`parseBoundedInteger`); 1 MB body / 2 KB URL caps.
- Business-logic abuse: trial recycling and signup enumeration **closed** with regression coverage; quota enforcement present.
- 🟡 Gap: formalise the full business-logic abuse matrix as automated tests (roadmap P1#4); strict Stripe event-id replay guard (P0#5).

### 3 — Web Frontend Security ✅
- CSP (`script-src 'self'`, `frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'self'`), X-Frame DENY, `X-Content-Type-Options: nosniff`, Referrer-Policy, Permissions-Policy — all live (verified).
- No cookies → no CSRF surface; auth is a Bearer token in the Authorization header.

### 4 — API & Web Service ✅
- Auth enforced on every protected route (401), tenant scope on every workspace route (CI-blocking matrix, 57 assertions).
- CORS restricted to `app.cybermeters.com` (does not reflect arbitrary Origins). OpenAPI spec validated in CI. Unknown verbs rejected (501/405).

### 5 — File Handling ✅
- The only "upload" is DMARC XML via a token-authenticated endpoint: size-capped, XML-bomb (DOCTYPE/ENTITY) guarded, never expands entities, deduped. R2 objects private, served only via a role-gated download.

### 6 — Authentication ✅
- PBKDF2-SHA256 (100k iterations) password hashing; email verification required; login brute-force limit (10/15min); generic error messages (no enumeration).
- MFA/TOTP with encrypted secrets, single-use challenges, single-use recovery codes, and **fail-closed throttles on every proof endpoint**.

### 7 — Session Management ✅
- Session token = 64-char random, stored as SHA-256 hash; 30-day expiry; revoked on logout and on password reset; session listing available. No fixation (fresh token per login).

### 8 — Authorization ✅
- Deny-by-default: `requireAuth` → `requireWorkspaceRole`/`requireDomainRole`/`requireScanReadAccess` with a role hierarchy; API-token workspace scope enforced. The domain existence oracle is closed. **CI-blocking cross-tenant matrix** guards regressions.

### 9 — Self-contained Tokens 🟡
- Session/API tokens are opaque + server-side (D1-backed), not self-contained JWTs — good (no client-side trust). The Microsoft **id_token** JWT is validated on SSO.
- 🟡 Note: confirm id_token signature/issuer/audience/expiry checks are complete (`validateMicrosoftIdToken`) — schedule an explicit test.

### 10 — OAuth & OIDC ✅
- Microsoft SSO: CSRF `state` (10-min TTL), one-time-code exchange (5-min TTL, single-use), no token in URL, `validateFrontendRedirectUrl` blocks open redirects.

### 11 — Cryptography ✅
- PBKDF2 for passwords; TOTP secrets encrypted at rest; tokens SHA-256 hashed; HMAC-SHA256 verification for Stripe webhooks; WebCrypto throughout. No home-rolled crypto.
- 🟡 Minor: document a key-rotation procedure for `MFA_ENCRYPTION_KEY` (in IR plan; needs an MFA re-enrolment path).

### 12 — Secure Communication ✅
- HTTPS enforced; HSTS (`max-age=31536000; includeSubDomains`); TLS terminated at Cloudflare. Third-party calls (Stripe/Resend/CF) over HTTPS.

### 13 — Configuration 🟡
- Secrets via `wrangler secret` (never committed; CI secret-scan). Worker lockfiles committed; `npm audit` 0. Manual deploy discipline + rollback IDs.
- 🟡 Gaps: pin CI action SHAs; add SAST ✅(now added)/SBOM; **staging parity** with prod (roadmap P1#7).

### 14 — Data Protection ✅→🟡
- Tenant data isolated per workspace; PII minimised; audit metadata redaction (`sanitizeAuditMetadata`); soft-delete + 30-day purge (verified). UK GDPR / ICO path in the IR plan.
- 🟡 Gaps: **central console-log redaction helper** (P0#7); a standing test that purge removes ALL owned rows + R2 objects; a proven **restore drill** (P0#8).

### 15 — Secure Coding & Architecture ✅
- Deny-by-default auth; server-side authorization only (frontend trusted for nothing); dependency lockfiles + audit; 27 frontend tests + 6 backend harnesses + tenant matrix + SAST, all CI-blocking. Manual, reviewed, reversible deploys.

### 16 — Logging & Error Handling 🟡
- Errors: `serverError()` returns generic messages + a correlation `request_id`; no SQL/stack/secret/existence leak (verified). Security events in `audit_events`, separate from app logs.
- 🟡 Gaps: **automated alerting** on error-rate / auth-failure / cron-health (P0#9); central log redaction helper (P0#7).

---

## Prioritised gaps to reach clean ASVS L2

| # | Gap | Chapter | Roadmap |
|---|---|---|---|
| 1 | Automated security alerting (error-rate / auth-failure / cron) | 16 | P0#9 |
| 2 | Central console-log redaction helper | 14, 16 | P0#7 |
| 3 | Proven backup restore drill (D1 + R2) with RPO/RTO | 14 | P0#8 |
| 4 | Strict Stripe event-id replay idempotency + test | 2 | P0#5 |
| 5 | Purge-completeness regression test | 14 | P1#10 |
| 6 | Explicit id_token (Microsoft) validation test | 9 | — |
| 7 | Pin CI action SHAs + SBOM + staging parity | 13 | P1#3/#7/#8 |

All tracked; none blocks invite-only or public beta on its own.
