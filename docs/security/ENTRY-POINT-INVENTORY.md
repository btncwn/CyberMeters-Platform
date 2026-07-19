# CyberMeters — Canonical Entry-Point Inventory

> **Generated** by `scripts/security/build-entry-point-inventory.js` from Worker source.
> Do not edit by hand — run the builder and commit. CI gate:
> `scripts/validate-entry-point-inventory.js` fails on any drift or unverified gap.

This inventory is a **structural** enumeration of every security-relevant
entry point (HTTP handler sites, the scheduled/cron handler, the inbound-email
handler) and the authorization guards that lexically govern each one. It is not a
semantic proof; its two guarantees are (1) a new route cannot silently escape the
inventory, and (2) no workspace/ownership/account/admin-scoped handler lacks an auth
guard without an explicit, documented public-allowlist reason.

## Coverage summary

- **Total entry points:** 234
- **Auth-guarded:** 213
- **Unauthenticated (public by design):** 21
- **Sensitive-scope gaps (unauthed workspace/resource/account/admin/portfolio, non-public):** 0

| Scope | Handlers | Auth-guarded |
|---|---:|---:|
| account | 21 | 21 |
| admin | 2 | 2 |
| email | 1 | 1 |
| portfolio | 9 | 9 |
| preflight | 1 | 0 |
| public-or-global | 37 | 19 |
| unknown | 46 | 46 |
| webhook | 2 | 0 |
| workspace | 115 | 115 |

## Public allowlist (unauthenticated by design)

Each unauthenticated entry point matches one of these documented reasons. Any
unauthenticated sensitive-scope handler NOT covered here fails the CI gate.

| Pattern | Reason |
|---|---|
| `/^\/health$/` | liveness probe — no tenant data |
| `/^\/ready$/` | readiness probe — no tenant data |
| `/^\/$/` | root banner — no tenant data |
| `/^\/\.well-known\//` | security.txt / well-known — public by spec |
| `/^\/api\/health$/` | health alias — no tenant data |
| `/^\/api\/version$/` | version banner — no tenant data |
| `/^\/api\/plans$/` | public pricing catalogue — no tenant data |
| `/signup\|register/` | account creation — pre-auth by definition |
| `/login\|\/session$/` | authentication endpoint — pre-auth by definition |
| `/verify-email\|verify\/\|resend/` | email verification — token-gated, pre-auth |
| `/password\|reset\|forgot/` | password reset — token-gated, pre-auth |
| `/\/auth\/(microsoft\|sso\|oauth\|callback)/` | SSO/OAuth — provider-token gated |
| `/\/auth\/exchange/` | one-time-code → session exchange — pre-auth by definition |
| `/\/auth\/logout/` | logout — Bearer-token gated (deletes that session); unauthed is a no-op |
| `/\/auth\/mfa\//` | login MFA challenge/recovery — challenge-token gated, fail-closed IP throttle, pre-full-auth |
| `/webhook/` | Stripe webhook — HMAC signature verified before parse |
| `/\/billing\/plans/` | public billing catalogue — no Stripe price IDs, no tenant data |
| `/\/free-scan/` | public lead-gen scan — SSRF-guarded, gated preview, rate-limited |
| `/\/api\/invitations\//` | invitation token flow — opaque-token gated, pre-membership |
| `/dmarc-ingest\|\/ingest\/\|\/rua\|\/tlsrpt\|\/inbound/` | report ingestion — endpoint-key / DMARC-trust gated (key binds the workspace) |
| `/^OPTIONS$/` | CORS preflight — no body, no tenant data |

## Entry points by file

### `workers/scan-api/src/email/inbound.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| EMAIL | `email()` | 1 | email | ✓ | cloudflare-email-routing, dmarc-trust |

### `workers/scan-api/src/index.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| OPTIONS | `(none)` | 1946 | preflight | public | — |
| GET | `/health` | 1951 | public-or-global | public | — |
| GET | `/ready` | 1967 | public-or-global | public | — |

### `workers/scan-api/src/routes/account.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `/api/account/onboarding-state` | 25 | account | ✓ | requireAuth, getAccessibleWorkspaceIds* |
| POST | `/api/account/bootstrap` | 135 | account | ✓ | requireAuth, getAccessibleWorkspaceIds* |
| GET | `/api/account/profile` | 204 | account | ✓ | requireAuth |
| PATCH | `/api/account/profile` | 255 | account | ✓ | requireAuth |
| GET | `/api/account/company` | 299 | account | ✓ | requireAuth |
| PUT | `/api/account/company` | 319 | account | ✓ | requireAuth |
| GET | `/api/account/report-branding` | 398 | account | ✓ | requireAuth |
| PUT | `/api/account/report-branding` | 428 | account | ✓ | requireAuth |
| GET | `/api/account/subscription` | 510 | account | ✓ | requireAuth |
| GET | `/api/account/subscription/features` | 549 | account | ✓ | requireAuth |
| GET | `/api/account/usage` | 567 | account | ✓ | requireAuth |
| GET | `/api/account/subscription/limits` | 588 | account | ✓ | requireAuth |
| GET | `/api/admin/subscriptions` | 612 | admin | ✓ | isPlatformAdmin, requireAuth |
| GET | `/api/account/api-tokens` | 659 | account | ✓ | requireAuth |
| POST | `/api/account/api-tokens` | 681 | account | ✓ | requireAuth, requireWorkspaceAccess |
| DELETE | `/^\/api\/account\/api-tokens\/([^/` | 743 | account | ✓ | requireAuth |
| GET | `/api/account/login-history` | 781 | account | ✓ | requireAuth |
| GET | `/api/account/sessions` | 840 | account | ✓ | requireAuth |
| POST | `/^\/api\/account\/sessions\/([^/` | 890 | account | ✓ | requireAuth |
| GET | `/api/account/export` | 936 | account | ✓ | requireAuth |
| POST | `/api/account/delete-request` | 1032 | account | ✓ | requireAuth |
| GET | `/api/platform/accuracy` | 1068 | admin | ✓ | requireAuth, getAccessibleWorkspaceIds* |

### `workers/scan-api/src/routes/attack-surface.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `/^\/api\/workspaces\/([^/` | 40 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 57 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 62 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 89 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 118 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 143 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 252 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 413 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 521 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 788 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 1053 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 1165 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 1304 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 1450 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 1552 | workspace | ✓ | requireAuth, requireWorkspaceRole |

### `workers/scan-api/src/routes/auth.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| POST | `/api/auth/signup` | 24 | public-or-global | public | — |
| POST | `/api/auth/login` | 166 | public-or-global | public | — |
| GET | `/api/auth/me` | 330 | account | ✓ | requireAuth |
| POST | `/api/auth/logout` | 343 | public-or-global | public | — |
| GET | `/api/auth/verify-email` | 380 | public-or-global | public | — |
| POST | `/api/auth/resend-verification` | 471 | public-or-global | public | — |
| GET | `/api/auth/microsoft/login` | 587 | public-or-global | public | — |
| GET | `/api/auth/microsoft/callback` | 648 | public-or-global | public | — |
| POST | `/api/auth/exchange` | 934 | public-or-global | public | — |
| POST | `/api/auth/forgot-password` | 997 | public-or-global | public | — |
| POST | `/api/auth/reset-password` | 1099 | public-or-global | public | — |
| GET | `/api/auth/mfa/status` | 1212 | public-or-global | ✓ | requireAuth |
| POST | `/api/auth/mfa/setup` | 1234 | public-or-global | ✓ | requireAuth |
| POST | `/api/auth/mfa/verify-setup` | 1271 | public-or-global | ✓ | requireAuth |
| POST | `/api/auth/mfa/challenge` | 1340 | public-or-global | public | — |
| POST | `/api/auth/mfa/recovery-code` | 1439 | public-or-global | public | — |
| POST | `/api/auth/mfa/disable` | 1536 | public-or-global | ✓ | requireAuth |

### `workers/scan-api/src/routes/billing.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| POST | `/api/free-scan` | 41 | public-or-global | public | — |
| GET | `/^\/api\/workspaces\/([^/` | 221 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/api/plans` | 278 | public-or-global | public | — |
| POST | `/^\/api\/workspaces\/([^/` | 288 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| POST | `/^\/api\/workspaces\/([^/` | 440 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |

### `workers/scan-api/src/routes/brand.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `/^\/api\/workspaces\/([^/` | 49 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 54 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 101 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 122 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 133 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 138 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 158 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 168 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 182 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 204 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 262 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 267 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 331 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| POST | `(none)` | 331 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| POST | `(none)` | 360 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 457 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 510 | unknown | ✓ | requireAuth, requireWorkspaceRole |

### `workers/scan-api/src/routes/certificates-lifecycle.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `(none)` | 40 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 65 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| POST | `(none)` | 78 | unknown | ✓ | requireAuth, requireWorkspaceRole |

### `workers/scan-api/src/routes/cyber-essentials-controls.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `(none)` | 58 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 79 | unknown | ✓ | requireAuth, requireWorkspaceRole |

### `workers/scan-api/src/routes/domains.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| POST | `/^\/api\/workspaces\/([^/` | 26 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| POST | `/^\/api\/domains\/([^/` | 159 | public-or-global | ✓ | requireAuth |
| POST | `/^\/api\/domains\/([^/` | 262 | public-or-global | ✓ | requireAuth |
| GET | `/^\/api\/domains\/([^/` | 643 | public-or-global | ✓ | requireAuth, requireDomainRole |
| POST | `/^\/api\/domains\/([^/` | 683 | public-or-global | ✓ | requireAuth, requireDomainRole |

### `workers/scan-api/src/routes/email-protection.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| POST | `/^\/api\/workspaces\/([^/` | 104 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 153 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 190 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 235 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 303 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| PUT | `/^\/api\/workspaces\/([^/` | 323 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 385 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| PUT | `/^\/api\/workspaces\/([^/` | 399 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 420 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 434 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| DELETE | `/^\/api\/workspaces\/([^/` | 505 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 541 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 554 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 598 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 672 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 676 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 687 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| DELETE | `/^\/api\/workspaces\/([^/` | 741 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 792 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 797 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 815 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| DELETE | `/^\/api\/workspaces\/([^/` | 862 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 888 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 929 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 998 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 1020 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 1073 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 1113 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 1132 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 1179 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 1199 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 1284 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 1325 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 1408 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 1415 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 1450 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| DELETE | `/^\/api\/workspaces\/([^/` | 1464 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 1505 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 1516 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| DELETE | `/^\/api\/workspaces\/([^/` | 1540 | workspace | ✓ | requireAuth, requireWorkspaceRole |

### `workers/scan-api/src/routes/executive-dashboard.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `/^\/api\/workspaces\/([^/` | 27 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 58 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| GET | `/^\/api\/workspaces\/([^/` | 354 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 419 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 437 | workspace | ✓ | requireAuth, requireWorkspaceRole |

### `workers/scan-api/src/routes/global-billing.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `/api/billing/plans` | 23 | public-or-global | public | — |
| POST | `/api/dmarc-ingest` | 42 | webhook | public | — |
| GET | `/api/billing/subscription` | 148 | public-or-global | ✓ | requireAuth |
| POST | `/api/billing/webhook` | 188 | webhook | public | — |
| POST | `/api/billing/checkout` | 500 | public-or-global | ✓ | requireAuth |
| POST | `/api/billing/portal` | 645 | public-or-global | ✓ | requireAuth |

### `workers/scan-api/src/routes/identity-exposure.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `(none)` | 45 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 71 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| POST | `(none)` | 84 | unknown | ✓ | requireAuth, requireWorkspaceRole |

### `workers/scan-api/src/routes/managed-cases.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `(none)` | 90 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| POST | `(none)` | 115 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 151 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| POST | `(none)` | 163 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| POST | `(none)` | 181 | unknown | ✓ | requireAuth, requireWorkspaceRole |

### `workers/scan-api/src/routes/portfolio.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `/^\/api\/workspaces\/([^/` | 56 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/api/portfolio/overview` | 101 | portfolio | ✓ | requireAuth, getAccessibleWorkspaceIds* |
| GET | `/api/portfolio/workspaces` | 230 | portfolio | ✓ | requireAuth, getAccessibleWorkspaceIds* |
| GET | `/api/portfolio/executive-summary` | 252 | portfolio | ✓ | requireAuth, getAccessibleWorkspaceIds* |
| GET | `/api/portfolio/alerts` | 271 | portfolio | ✓ | requireAuth, getAccessibleWorkspaceIds* |
| GET | `/api/portfolio/trends` | 394 | portfolio | ✓ | requireAuth, getAccessibleWorkspaceIds* |
| GET | `/api/portfolio/risk` | 501 | portfolio | ✓ | requireAuth, getAccessibleWorkspaceIds* |
| GET | `/api/portfolio/domains` | 528 | portfolio | ✓ | requireAuth, getAccessibleWorkspaceIds* |
| GET | `/api/portfolio/maturity` | 594 | portfolio | ✓ | requireAuth, getAccessibleWorkspaceIds* |
| GET | `/^\/api\/portfolio\/domains\/([^/` | 620 | portfolio | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/api/workspaces` | 645 | public-or-global | ✓ | requireAuth, getAccessibleWorkspaceIds* |
| POST | `/api/workspaces` | 678 | public-or-global | ✓ | requireAuth |

### `workers/scan-api/src/routes/scans.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| POST | `/api/scan` | 32 | public-or-global | ✓ | requireAuth, requireWorkspaceRole, getAccessibleWorkspaceIds*, getWorkspaceBillingUserId* |
| GET | `/api/scans` | 240 | public-or-global | ✓ | requireAuth, requireWorkspaceRole, getAccessibleWorkspaceIds* |
| GET | `(none)` | 376 | unknown | ✓ | requireAuth, requireScanReadAccess, requireWorkspaceRole, getAccessibleWorkspaceIds*, getWorkspaceBillingUserId* |
| GET | `(none)` | 436 | unknown | ✓ | requireAuth, requireScanReadAccess, requireWorkspaceRole, getAccessibleWorkspaceIds*, getWorkspaceBillingUserId* |
| GET | `(none)` | 484 | unknown | ✓ | requireAuth, requireScanReadAccess, requireWorkspaceRole, getAccessibleWorkspaceIds*, getWorkspaceBillingUserId* |
| GET | `(none)` | 526 | unknown | ✓ | requireAuth, requireScanReadAccess, requireWorkspaceRole, getAccessibleWorkspaceIds*, getWorkspaceBillingUserId* |
| GET | `(none)` | 650 | unknown | ✓ | requireAuth, requireScanReadAccess, requireWorkspaceRole, getAccessibleWorkspaceIds*, getWorkspaceBillingUserId* |
| GET | `(none)` | 723 | unknown | ✓ | requireAuth, requireScanReadAccess, requireWorkspaceRole, getAccessibleWorkspaceIds*, getWorkspaceBillingUserId* |
| POST | `/api/schedules` | 757 | public-or-global | ✓ | requireAuth, requireWorkspaceRole, getAccessibleWorkspaceIds* |
| GET | `/api/schedules` | 855 | public-or-global | ✓ | requireAuth, getAccessibleWorkspaceIds* |
| DELETE | `(none)` | 885 | unknown | ✓ | requireAuth, requireScanReadAccess, requireWorkspaceRole, getAccessibleWorkspaceIds*, getWorkspaceBillingUserId* |

### `workers/scan-api/src/routes/shadow-it.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `(none)` | 37 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 61 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| POST | `(none)` | 73 | unknown | ✓ | requireAuth, requireWorkspaceRole |

### `workers/scan-api/src/routes/website-security.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `(none)` | 59 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 111 | unknown | ✓ | requireAuth, requireWorkspaceRole |

### `workers/scan-api/src/routes/workspace-activity.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `/^\/api\/workspaces\/([^/` | 21 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| GET | `/^\/api\/workspaces\/([^/` | 146 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 275 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 349 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 427 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| PUT | `/^\/api\/workspaces\/([^/` | 465 | workspace | ✓ | requireAuth, requireWorkspaceRole |

### `workers/scan-api/src/routes/workspace-analytics.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `/^\/api\/workspaces\/([^/` | 24 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| GET | `/^\/api\/workspaces\/([^/` | 75 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| GET | `(none)` | 112 | unknown | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| PUT | `(none)` | 112 | unknown | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| PUT | `(none)` | 129 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 226 | unknown | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| GET | `(none)` | 282 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 344 | unknown | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |

### `workers/scan-api/src/routes/workspace-insights.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `/api/validation/benchmark` | 40 | public-or-global | ✓ | requireAuth |
| GET | `/^\/api\/workspaces\/([^/` | 164 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| GET | `/^\/api\/workspaces\/([^/` | 260 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 352 | workspace | ✓ | requireAuth, requireWorkspaceRole |

### `workers/scan-api/src/routes/workspace-intel.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `/^\/api\/workspaces\/([^/` | 23 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 37 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 125 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| GET | `/^\/api\/workspaces\/([^/` | 202 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |

### `workers/scan-api/src/routes/workspace-members.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `/^\/api\/workspaces\/([^/` | 19 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 46 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| GET | `/^\/api\/workspaces\/([^/` | 245 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 276 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| DELETE | `/^\/api\/workspaces\/([^/` | 365 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| PATCH | `/^\/api\/workspaces\/([^\/]+)\/members\/([^\/]+)$/` | 425 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| DELETE | `/^\/api\/workspaces\/([^\/]+)\/invitations\/([^\/]+)$/` | 488 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/invitations\/([^/` | 527 | public-or-global | public | — |
| POST | `/^\/api\/invitations\/([^/` | 561 | public-or-global | ✓ | requireAuth, getWorkspaceBillingUserId* |

### `workers/scan-api/src/routes/workspace-reports.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| POST | `/^\/api\/workspaces\/([^/` | 20 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 49 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 63 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| PUT | `/^\/api\/workspaces\/([^/` | 78 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| GET | `/^\/api\/workspaces\/([^/` | 132 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 183 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 216 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| DELETE | `/^\/api\/workspaces\/([^/` | 256 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 311 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 357 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 379 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 404 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 433 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| PUT | `/^\/api\/workspaces\/([^/` | 476 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| DELETE | `/^\/api\/workspaces\/([^/` | 521 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 553 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 578 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| DELETE | `/^\/api\/workspaces\/([^/` | 647 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| PATCH | `/^\/api\/workspaces\/([^/` | 686 | workspace | ✓ | requireAuth, requireWorkspaceRole |

### `workers/scan-api/src/routes/workspaces-core.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `(none)` | 54 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| PATCH | `(none)` | 158 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| DELETE | `(none)` | 189 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 249 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| POST | `(none)` | 294 | unknown | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| POST | `/^\/api\/workspaces\/([^/` | 380 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 465 | workspace | ✓ | requireAuth |

_`*` = workspace-scoping helper (getAccessibleWorkspaceIds / getWorkspaceBillingUserId)._
