# CyberMeters — Threat Model

> Threat modelling finds design weaknesses that a pentest (which tests running
> code on one date) can miss. This document walks each critical flow through
> **STRIDE** — Spoofing · Tampering · Repudiation · Information disclosure ·
> Denial of service · Elevation of privilege — records the control we already
> have (with evidence), and flags residual risk to close.

**Owner:** Lead Engineer. **Last updated:** 2026-07-11. Living document — revisit
when a flow changes or a new one ships. Companion to
`docs/SECURITY-SDLC-ROADMAP.md` and `docs/INCIDENT-RESPONSE-PLAN.md`.

**Legend:** ✅ controlled · 🟡 partial / residual risk · ⬜ gap

---

## System overview (trust boundaries)

```
Public internet ──HTTPS──► Cloudflare Pages (SPA)  ──fetch──►  Worker API (scan-api)
                                                                  │
   ┌──────────────────────────────────────────────────────────────┤
   ▼                 ▼                 ▼               ▼            ▼
  D1 (tenant data)  R2 (reports)   Stripe (billing)  Resend (mail)  CF DNS/Email-Routing
```

**Trust boundaries:** (1) browser ↔ Worker (all auth here; the SPA is untrusted).
(2) Worker ↔ D1/R2 (every query scoped by workspace + ownership). (3) Worker ↔
third parties (Stripe/Resend/Cloudflare — secrets, signature verification).
**Core assumption:** the frontend enforces nothing; every authorization decision
is made server-side in the Worker.

---

## Per-flow STRIDE

### 1. Registration & email verification
| Threat | Control | Status |
|---|---|---|
| S — account created for someone else's email | Verification token (24h) required to activate; **signup no longer reveals whether an email exists** (identical 201, security notice to owner) `429f2e0` | ✅ |
| T — tamper verification token | Token stored as hash; single-use; expiry enforced | ✅ |
| I — email enumeration | Removed on signup and forgot-password (generic responses) | ✅ |
| D — signup flood | Rate-limited 5/hour/IP | ✅ |
| E — self-grant elevated plan | New account = Free; trial is once-per-owner `5b57af3` | ✅ |
Residual: none material.

### 2. Password reset
| S/T | Reset token single-use, 1h expiry; **all sessions invalidated on reset** | ✅ |
| I | Generic "if an account exists…" response — no enumeration | ✅ |
| D | Rate-limited 5/15min | ✅ |
Residual: none material.

### 3. MFA / TOTP
| Threat | Control | Status |
|---|---|---|
| S — bypass second factor | TOTP verified server-side; challenge is single-use (`used_at` set regardless of outcome) | ✅ |
| T — replay a challenge | Single-use challenge token | ✅ |
| I — leak TOTP secret | Secret encrypted at rest (`MFA_ENCRYPTION_KEY`); redacted from audit metadata | ✅ |
| D — brute-force the proof | **Fail-closed throttles on verify-setup / challenge / disable / recovery-code** `27d597f`,`a7ea6e5` | ✅ |
| E — disable MFA on a hijacked session | Disable requires a TOTP code or current password + throttled | ✅ |
Residual: rotating `MFA_ENCRYPTION_KEY` breaks existing secrets — documented in IR plan.

### 4. Microsoft SSO / OTC exchange
| S — forge the callback | CSRF `state` validated (D1, 10-min TTL); id_token JWT validated | ✅ |
| T/replay — reuse the one-time code | OTC single-use, 5-min TTL, deleted on exchange | ✅ |
| I — token in URL | No bearer token in the redirect; OTC exchanged server-side | ✅ |
| Open redirect | `validateFrontendRedirectUrl` rejects off-origin targets | ✅ |
Residual: none material.

### 5. Workspace create & invitation
| Threat | Control | Status |
|---|---|---|
| S — accept an invite as another workspace | **Invite token cannot cross workspaces** (tenant matrix invariant 7) | ✅ |
| T — self-invite as owner | Invite role gated by `requireWorkspaceRole('workspace:invite')`; matrix asserts viewer/foreign cannot | ✅ |
| D — invite spam (cost/reputation) | **Fail-closed** rate limit 10/hr + 25/day per workspace `4af86f7` | ✅ |
| E — low-priv performs admin action | Matrix invariant 5: viewer blocked from invite/member/delete/settings | ✅ |
Residual: none material.

### 6. Domain ownership verification
| S — claim a domain you don't own | Persistent monitoring / RUA / hosted-DMARC require DNS-TXT verification (`requireDomainRole`) | ✅ |
| I — cross-tenant domain existence oracle | **Closed** — verify routes return identical 404 for foreign vs nonexistent `4783ef6` | ✅ |
Residual: one-shot passive scan is intentionally ownership-free (public data only) — disclosed in the scan UI copy.

### 7. Scan start & scheduled scans
| T — run a scan as another workspace | Scan bound to caller's workspace; `requireScanReadAccess` on reads | ✅ |
| D — cost amplification via repeated scans | Quota-gated (fail-open on transient DB error, documented/accepted) | 🟡 |
| I — read another tenant's scan/report | Matrix: foreign cannot read scans/reports; R2 download gated by `requireWorkspaceRole` | ✅ |
Residual: 🟡 tighten scan-start rate limit if abuse observed (IR §5.11); scan of public data on unowned domains is disclosed.

### 8. R2 report access
| S/I — reach another tenant's report | Bucket private; served only via a `requireWorkspaceRole`-gated download; keys not guessable-to-access | ✅ |
| T — object key replay | Key alone grants nothing without workspace membership | ✅ |
Residual: none material.

### 9. DMARC XML import (RUA ingest)
| S — ingest for a domain you don't control | Per-workspace+domain upload token; cross-org auth via RFC 7489 `_report._dmarc` | ✅ |
| T/D — decompression / XML bomb | Size cap + XML-bomb (DOCTYPE/ENTITY) guards; dedup on `external_report_id` | ✅ |
| I — inject via report `org_name` etc. | Rendered through `escapeEmailHtml`; SQL parameterised | ✅ |
Residual: add an explicit parser-DoS regression test (roadmap business-logic).

### 10. Stripe checkout & webhook
| S — forge a webhook | **Signature verified before JSON.parse** (400 unsigned, verified live) | ✅ |
| T/replay — flip subscription state | Upsert-not-insert avoids duplicate state; Stripe is source of truth | 🟡 |
| T — client-priced checkout | Price resolved server-side from `STRIPE_PRICE_MAP`; no client price accepted | ✅ |
Residual: 🟡 add a strict processed-event-id replay guard + test (roadmap P0#5).

### 11. API token lifecycle
| S — use a token outside its workspace | `token_workspace_id` enforced on all route modules (tenant matrix); session-only routes reject tokens | ✅ |
| T — escalate token scope | Token scope fixed at creation | ✅ |
| I — token in logs | Redacted from audit metadata | ✅ |
Residual: none material; revoke path documented in IR §5.2.

### 12. Workspace delete / restore / purge
| T — read soft-deleted data | Matrix invariant 6: soft-deleted workspace unreadable | ✅ |
| E — recycle a deleted workspace for a fresh trial | **Closed** — trial once-per-owner survives soft-delete `5b57af3` | ✅ |
| R — deny the deletion happened | Audit event on delete-request/restore/purge | ✅ |
Residual: 🟡 standing test that purge removes ALL owned rows + R2 objects (orphan class).

### 13. Admin / platform routes
| E — non-admin reaches admin routes | `isPlatformAdmin` (allowlist via `ADMIN_EMAILS`); all admin routes gated | ✅ |
| R — untraced admin action | Every admin action audited | ✅ |
Residual: privileged-access review at scale (roadmap P2).

### 14. Outbound email (Resend / lifecycle)
| D — used as a spam relay | Sends only to account-scoped recipients; invite send fail-closed limited | ✅ |
| T — template injection | All interpolation through `escapeEmailHtml` | ✅ |
Residual: none material.

### 15. Rate limiting (cross-cutting)
| D — bypass by keying only on IP | Auth/cost paths key on IP; workspace/user scoping where relevant | 🟡 |
Residual: 🟡 broaden keys (user_id/workspace_id/email) on more endpoints (roadmap).

### 16. Cron / background processing
| T — double-run causes duplicate side effects | Retry sweeps are claim-then-send (at-least-once, dedup rows); asset-alert dedup per (workspace, scan) | ✅ |
| D — a cron task fails silently | Each task wrapped, non-fatal, logged | 🟡 |
Residual: 🟡 automated cron-health alerting (roadmap P0#9).

---

## Cross-cutting controls (verified)

- **Transport/headers:** HSTS, CSP (`script-src 'self'`, `frame-ancestors none`, `object-src none`), X-Frame DENY, nosniff, Referrer-Policy, Permissions-Policy.
- **Tenant isolation:** enforced in every query by `workspace_id` + ownership; CI-blocking matrix (`validate-tenant-isolation.js`, 57 assertions).
- **Error handling:** `serverError()` returns generic messages + a correlation `request_id`; no SQL/stack/secret/existence leak.
- **Sessions:** token stored as SHA-256 hash, 30-day expiry, revoked on logout/reset.
- **No cookies** → no CSRF surface (token in Authorization header only).

## Top residual risks (ranked)

1. 🟡 **Stripe webhook replay** — add a processed-event-id idempotency guard + test.
2. 🟡 **Automated alerting** — error-rate / auth-failure / cron-health alerts (needs Cloudflare dashboard).
3. 🟡 **Scan-start / broader rate-limit tuning** — tighten if abuse observed.
4. 🟡 **Purge-completeness regression test** — prove no orphaned rows/objects.

None are public-beta blockers; all are tracked in the Secure SDLC roadmap.
