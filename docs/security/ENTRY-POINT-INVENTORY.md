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

- **Total entry points:** 301
- **Auth-guarded:** 262
- **Unauthenticated (public by design):** 39
- **Sensitive-scope gaps (unauthed workspace/resource/account/admin/portfolio, non-public):** 0

| Scope | Handlers | Auth-guarded |
|---|---:|---:|
| account | 26 | 26 |
| admin | 2 | 2 |
| email | 1 | 1 |
| portfolio | 9 | 9 |
| preflight | 3 | 0 |
| public-or-global | 40 | 20 |
| unknown | 79 | 65 |
| webhook | 2 | 0 |
| workspace | 139 | 139 |

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
| OPTIONS | `(none)` | 2646 | preflight | public | — |
| DELETE | `(none)` | 2652 | unknown | **GAP** | — |
| GET | `(none)` | 2652 | unknown | **GAP** | — |
| HEAD | `(none)` | 2652 | unknown | **GAP** | — |
| PATCH | `(none)` | 2652 | unknown | **GAP** | — |
| POST | `(none)` | 2652 | unknown | **GAP** | — |
| PUT | `(none)` | 2652 | unknown | **GAP** | — |
| GET | `/health` | 2657 | public-or-global | public | — |
| GET | `/ready` | 2676 | public-or-global | public | — |

### `workers/scan-api/src/routes/account.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `/api/account/onboarding-state` | 28 | account | ✓ | requireAuth, getAccessibleWorkspaceIds* |
| POST | `/api/account/bootstrap` | 138 | account | ✓ | requireAuth, getAccessibleWorkspaceIds* |
| GET | `/api/account/profile` | 207 | account | ✓ | requireAuth |
| PATCH | `/api/account/profile` | 258 | account | ✓ | requireAuth |
| GET | `/api/account/company` | 302 | account | ✓ | requireAuth |
| PUT | `/api/account/company` | 322 | account | ✓ | requireAuth |
| GET | `/api/account/report-branding` | 401 | account | ✓ | requireAuth |
| PUT | `/api/account/report-branding` | 431 | account | ✓ | requireAuth |
| GET | `/api/account/subscription` | 516 | account | ✓ | requireAuth |
| GET | `/api/account/usage` | 551 | account | ✓ | requireAuth |
| GET | `/api/account/subscription/limits` | 572 | account | ✓ | requireAuth |
| GET | `/api/admin/subscriptions` | 597 | admin | ✓ | isPlatformAdmin, requireAuth |
| GET | `/api/account/api-tokens` | 644 | account | ✓ | requireAuth |
| POST | `/api/account/api-tokens` | 666 | account | ✓ | requireAuth, requireWorkspaceAccess |
| DELETE | `/^\/api\/account\/api-tokens\/([^/` | 737 | account | ✓ | requireAuth |
| GET | `/api/account/login-history` | 775 | account | ✓ | requireAuth |
| GET | `/api/account/sessions` | 834 | account | ✓ | requireAuth |
| POST | `/^\/api\/account\/sessions\/([^/` | 884 | account | ✓ | requireAuth |
| GET | `/api/account/export` | 930 | account | ✓ | requireAuth |
| POST | `/api/account/delete-request` | 1026 | account | ✓ | requireAuth |
| GET | `/api/platform/accuracy` | 1086 | admin | ✓ | requireAuth, getAccessibleWorkspaceIds* |

### `workers/scan-api/src/routes/attack-surface.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `/^\/api\/workspaces\/([^/` | 498 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 526 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 536 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 563 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 592 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 617 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 739 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 991 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 1099 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 1462 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 1755 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 1860 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 1992 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 2137 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 2239 | workspace | ✓ | requireAuth, requireWorkspaceRole |

### `workers/scan-api/src/routes/auth.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| POST | `/api/auth/signup` | 76 | public-or-global | public | — |
| POST | `/api/auth/login` | 222 | public-or-global | public | — |
| GET | `/api/auth/me` | 386 | account | ✓ | requireAuth |
| POST | `/api/auth/logout` | 399 | public-or-global | public | — |
| GET | `/api/auth/verify-email` | 436 | public-or-global | public | — |
| POST | `/api/auth/resend-verification` | 527 | public-or-global | public | — |
| POST | `/api/auth/microsoft/start` | 649 | public-or-global | public | — |
| GET | `/api/auth/microsoft/login` | 710 | public-or-global | public | — |
| GET | `/api/auth/microsoft/callback` | 730 | public-or-global | public | — |
| POST | `/api/auth/exchange` | 991 | public-or-global | public | — |
| POST | `/api/auth/forgot-password` | 1106 | public-or-global | public | — |
| POST | `/api/auth/reset-password` | 1208 | public-or-global | public | — |
| GET | `/api/auth/mfa/status` | 1364 | public-or-global | ✓ | requireAuth |
| POST | `/api/auth/mfa/setup` | 1386 | public-or-global | ✓ | requireAuth |
| POST | `/api/auth/mfa/verify-setup` | 1427 | public-or-global | ✓ | requireAuth |
| POST | `/api/auth/mfa/challenge` | 1501 | public-or-global | public | — |
| POST | `/api/auth/mfa/recovery-code` | 1602 | public-or-global | public | — |
| POST | `/api/auth/mfa/disable` | 1699 | public-or-global | ✓ | requireAuth |

### `workers/scan-api/src/routes/billing.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| POST | `/api/free-scan` | 72 | public-or-global | public | — |
| GET | `/^\/api\/workspaces\/([^/` | 295 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| GET | `/api/plans` | 363 | public-or-global | public | — |
| POST | `/^\/api\/workspaces\/([^/` | 405 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| POST | `/^\/api\/workspaces\/([^/` | 686 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |

### `workers/scan-api/src/routes/brand.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `/^\/api\/workspaces\/([^/` | 54 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 59 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 140 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 161 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 172 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 177 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 197 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 207 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 221 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 243 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 301 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 306 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 383 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| POST | `(none)` | 383 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| POST | `(none)` | 412 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 554 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 607 | unknown | ✓ | requireAuth, requireWorkspaceRole |

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

### `workers/scan-api/src/routes/discovery-hostname-lists.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| DELETE | `(none)` | 66 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| PUT | `(none)` | 66 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| DELETE | `(none)` | 78 | unknown | ✓ | requireAuth, requireWorkspaceRole |

### `workers/scan-api/src/routes/dns-connections.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `/^\/api\/workspaces\/([^\/]+)\/dns-connections$/` | 51 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^\/]+)\/domains\/([^\/]+)\/dns-connec` | 90 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| PUT | `/^\/api\/workspaces\/([^\/]+)\/domains\/([^\/]+)\/dns-connec` | 91 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| DELETE | `/^\/api\/workspaces\/([^\/]+)\/domains\/([^\/]+)\/dns-connec` | 95 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| POST | `/^\/api\/workspaces\/([^\/]+)\/domains\/([^\/]+)\/dns-change` | 96 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^\/]+)\/domains\/([^\/]+)\/dns-change` | 100 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| POST | `/^\/api\/workspaces\/([^\/]+)\/domains\/([^\/]+)\/dns-change` | 101 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^\/]+)\/domains\/([^\/]+)\/dns-change` | 105 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^\/]+)\/domains\/([^\/]+)\/dns-change` | 109 | workspace | ✓ | requireAuth, requireWorkspaceRole |

### `workers/scan-api/src/routes/domains.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| POST | `/^\/api\/workspaces\/([^/` | 58 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| POST | `/^\/api\/domains\/([^/` | 192 | public-or-global | ✓ | requireAuth |
| POST | `/^\/api\/domains\/([^/` | 299 | public-or-global | ✓ | requireAuth |
| POST | `/^\/api\/domains\/([^/` | 346 | public-or-global | ✓ | requireAuth |
| GET | `/^\/api\/domains\/([^/` | 719 | public-or-global | ✓ | requireAuth, requireDomainRole |
| POST | `/^\/api\/domains\/([^/` | 759 | public-or-global | ✓ | requireAuth, requireDomainRole |

### `workers/scan-api/src/routes/email-protection.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| POST | `/^\/api\/workspaces\/([^/` | 114 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 163 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 200 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 245 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 313 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| PUT | `/^\/api\/workspaces\/([^/` | 358 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 420 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| PUT | `/^\/api\/workspaces\/([^/` | 434 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 455 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 469 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| DELETE | `/^\/api\/workspaces\/([^/` | 540 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 576 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 589 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 633 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 707 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 711 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 722 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| DELETE | `/^\/api\/workspaces\/([^/` | 776 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 827 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 832 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 850 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| DELETE | `/^\/api\/workspaces\/([^/` | 897 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 923 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 988 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 1057 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 1079 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 1132 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 1172 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 1191 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 1238 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 1258 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 1371 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 1412 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 1516 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 1523 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 1558 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| DELETE | `/^\/api\/workspaces\/([^/` | 1572 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 1613 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 1624 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| DELETE | `/^\/api\/workspaces\/([^/` | 1648 | workspace | ✓ | requireAuth, requireWorkspaceRole |

### `workers/scan-api/src/routes/executive-dashboard.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `/^\/api\/workspaces\/([^/` | 54 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 91 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| GET | `/^\/api\/workspaces\/([^/` | 414 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 479 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 497 | workspace | ✓ | requireAuth, requireWorkspaceRole |

### `workers/scan-api/src/routes/global-billing.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `/api/billing/plans` | 25 | public-or-global | public | — |
| POST | `/api/dmarc-ingest` | 44 | webhook | public | — |
| GET | `/api/billing/subscription` | 151 | public-or-global | ✓ | requireAuth |
| POST | `/api/billing/webhook` | 179 | webhook | public | — |
| POST | `/api/billing/checkout` | 572 | public-or-global | ✓ | requireAuth |
| POST | `/api/billing/portal` | 627 | public-or-global | ✓ | requireAuth |

### `workers/scan-api/src/routes/identity-exposure.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `(none)` | 46 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 75 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| POST | `(none)` | 88 | unknown | ✓ | requireAuth, requireWorkspaceRole |

### `workers/scan-api/src/routes/identity-public-secrets.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `/^\/api\/workspaces\/([^\/]+)\/identity-public-sources$/` | 22 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^\/]+)\/identity-public-sources$/` | 27 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |

### `workers/scan-api/src/routes/identity-workforce.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `/^\/api\/workspaces\/([^\/]+)\/identity-workforce$/` | 60 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| PATCH | `(none)` | 65 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| POST | `(none)` | 65 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^\/]+)\/identity-response\/([^\/]+)\/` | 71 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| POST | `/^\/api\/workspaces\/([^\/]+)\/identity-workforce$/` | 85 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| PATCH | `/^\/api\/workspaces\/([^\/]+)\/identity-workforce\/([^\/]+)$` | 101 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| POST | `/^\/api\/workspaces\/([^\/]+)\/identity-workforce\/([^\/]+)$` | 113 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| POST | `/^\/api\/workspaces\/([^\/]+)\/identity-response\/preview$/` | 135 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| POST | `/^\/api\/workspaces\/([^\/]+)\/identity-response\/([^\/]+)\/` | 154 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |

### `workers/scan-api/src/routes/managed-cases.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `(none)` | 95 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| POST | `(none)` | 130 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 197 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| POST | `(none)` | 228 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| POST | `(none)` | 246 | unknown | ✓ | requireAuth, requireWorkspaceRole |

### `workers/scan-api/src/routes/mcp-oauth-browser.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| OPTIONS | `(none)` | 263 | preflight | public | — |

### `workers/scan-api/src/routes/mcp-oauth-server.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `(none)` | 288 | unknown | **GAP** | — |
| GET | `(none)` | 311 | unknown | **GAP** | — |
| POST | `(none)` | 311 | unknown | **GAP** | — |
| GET | `(none)` | 328 | unknown | **GAP** | — |
| OPTIONS | `(none)` | 451 | preflight | public | — |
| GET | `/api/mcp/oauth/connections` | 458 | public-or-global | **GAP** | — |
| POST | `(none)` | 536 | unknown | **GAP** | — |

### `workers/scan-api/src/routes/network-assets.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `(none)` | 42 | unknown | ✓ | requireWorkspaceRole, getWorkspaceBillingUserId* |
| GET | `(none)` | 52 | unknown | **GAP** | — |
| POST | `(none)` | 61 | unknown | ✓ | requireWorkspaceRole |
| GET | `(none)` | 77 | unknown | **GAP** | — |
| GET | `(none)` | 96 | unknown | **GAP** | — |
| POST | `(none)` | 106 | unknown | ✓ | requireWorkspaceRole, getWorkspaceBillingUserId* |

### `workers/scan-api/src/routes/portfolio.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `/^\/api\/workspaces\/([^/` | 90 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/api/portfolio/overview` | 139 | portfolio | ✓ | requireAuth, getAccessibleWorkspaceIds* |
| GET | `/api/portfolio/workspaces` | 293 | portfolio | ✓ | requireAuth, getAccessibleWorkspaceIds* |
| GET | `/api/portfolio/executive-summary` | 318 | portfolio | ✓ | requireAuth, getAccessibleWorkspaceIds* |
| GET | `/api/portfolio/alerts` | 340 | portfolio | ✓ | requireAuth, getAccessibleWorkspaceIds* |
| GET | `/api/portfolio/trends` | 518 | portfolio | ✓ | requireAuth, getAccessibleWorkspaceIds* |
| GET | `/api/portfolio/risk` | 653 | portfolio | ✓ | requireAuth, getAccessibleWorkspaceIds* |
| GET | `/api/portfolio/domains` | 680 | portfolio | ✓ | requireAuth, getAccessibleWorkspaceIds* |
| GET | `/api/portfolio/maturity` | 747 | portfolio | ✓ | requireAuth, getAccessibleWorkspaceIds* |
| GET | `/^\/api\/portfolio\/domains\/([^/` | 773 | portfolio | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/api/workspaces` | 807 | public-or-global | ✓ | requireAuth, getAccessibleWorkspaceIds* |
| POST | `/api/workspaces` | 840 | public-or-global | ✓ | requireAuth |

### `workers/scan-api/src/routes/related-changes.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `(none)` | 69 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 99 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| POST | `(none)` | 126 | unknown | ✓ | requireAuth, requireWorkspaceRole |

### `workers/scan-api/src/routes/scans.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| POST | `/api/scan` | 131 | public-or-global | ✓ | requireAuth, requireWorkspaceRole, getAccessibleWorkspaceIds*, getWorkspaceBillingUserId* |
| GET | `/api/scans` | 388 | public-or-global | ✓ | requireAuth, requireWorkspaceRole, getAccessibleWorkspaceIds* |
| GET | `(none)` | 515 | unknown | ✓ | requireAuth, requireScanReadAccess, requireWorkspaceRole, getAccessibleWorkspaceIds*, getWorkspaceBillingUserId* |
| GET | `(none)` | 612 | unknown | ✓ | requireAuth, requireScanReadAccess, requireWorkspaceRole, getAccessibleWorkspaceIds*, getWorkspaceBillingUserId* |
| GET | `(none)` | 677 | unknown | ✓ | requireAuth, requireScanReadAccess, requireWorkspaceRole, getAccessibleWorkspaceIds*, getWorkspaceBillingUserId* |
| GET | `(none)` | 735 | unknown | ✓ | requireAuth, requireScanReadAccess, requireWorkspaceRole, getAccessibleWorkspaceIds*, getWorkspaceBillingUserId* |
| GET | `(none)` | 923 | unknown | ✓ | requireAuth, requireScanReadAccess, requireWorkspaceRole, getAccessibleWorkspaceIds*, getWorkspaceBillingUserId* |
| GET | `(none)` | 1002 | unknown | ✓ | requireAuth, requireScanReadAccess, requireWorkspaceRole, getAccessibleWorkspaceIds*, getWorkspaceBillingUserId* |
| POST | `/api/schedules` | 1046 | public-or-global | ✓ | requireAuth, requireWorkspaceRole, getAccessibleWorkspaceIds* |
| GET | `/api/schedules` | 1146 | public-or-global | ✓ | requireAuth, getAccessibleWorkspaceIds* |
| DELETE | `(none)` | 1184 | unknown | ✓ | requireAuth, requireScanReadAccess, requireWorkspaceRole, getAccessibleWorkspaceIds*, getWorkspaceBillingUserId* |

### `workers/scan-api/src/routes/shadow-it.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `(none)` | 37 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 67 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| POST | `(none)` | 79 | unknown | ✓ | requireAuth, requireWorkspaceRole |

### `workers/scan-api/src/routes/tls-authorization.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `(none)` | 31 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| POST | `(none)` | 41 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| PUT | `(none)` | 41 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| PUT | `(none)` | 53 | unknown | ✓ | requireAuth, requireWorkspaceRole |

### `workers/scan-api/src/routes/website-security.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `/^\/api\/workspaces\/([^/` | 58 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 112 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 164 | unknown | ✓ | requireAuth, requireWorkspaceRole |

### `workers/scan-api/src/routes/website-sign-in.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| DELETE | `(none)` | 81 | unknown | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| PUT | `(none)` | 81 | unknown | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| DELETE | `(none)` | 105 | unknown | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| PUT | `(none)` | 111 | unknown | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |

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
| GET | `/^\/api\/workspaces\/([^/` | 31 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 87 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| GET | `(none)` | 134 | unknown | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| PUT | `(none)` | 134 | unknown | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| PUT | `(none)` | 151 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 248 | unknown | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| GET | `(none)` | 304 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 366 | unknown | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |

### `workers/scan-api/src/routes/workspace-branding.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `/^\/api\/workspaces\/([^\/]+)\/branding$/` | 67 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| GET | `/^\/api\/workspaces\/([^\/]+)\/branding\/logo$/` | 76 | workspace | ✓ | requireAuth |
| PUT | `/^\/api\/workspaces\/([^\/]+)\/branding$/` | 79 | workspace | ✓ | requireAuth |
| DELETE | `/^\/api\/workspaces\/([^\/]+)\/branding\/logo$/` | 87 | workspace | ✓ | requireAuth |
| PUT | `/^\/api\/workspaces\/([^\/]+)\/branding\/logo$/` | 93 | workspace | ✓ | requireAuth |
| GET | `/api/account/branding/profiles` | 121 | account | ✓ | requireAuth |
| GET | `/^\/api\/account\/branding\/profiles\/([^\/]+)$/` | 125 | account | ✓ | requireAuth |
| POST | `/api/account/branding/profiles` | 163 | account | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| PUT | `/^\/api\/account\/branding\/profiles\/([^\/]+)$/` | 164 | account | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| DELETE | `/^\/api\/account\/branding\/profiles\/([^\/]+)$/` | 165 | account | ✓ | requireAuth |

### `workers/scan-api/src/routes/workspace-insights.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `/api/validation/benchmark` | 46 | public-or-global | ✓ | isPlatformAdmin, requireAuth |
| GET | `/^\/api\/workspaces\/([^/` | 182 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| GET | `/^\/api\/workspaces\/([^/` | 278 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 382 | workspace | ✓ | requireAuth, requireWorkspaceRole |

### `workers/scan-api/src/routes/workspace-intel.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `/^\/api\/workspaces\/([^/` | 33 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 47 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 165 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| GET | `/^\/api\/workspaces\/([^/` | 242 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |

### `workers/scan-api/src/routes/workspace-members.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `/^\/api\/workspaces\/([^/` | 56 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 83 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| GET | `/^\/api\/workspaces\/([^/` | 326 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 357 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| DELETE | `/^\/api\/workspaces\/([^/` | 446 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| PATCH | `/^\/api\/workspaces\/([^\/]+)\/members\/([^\/]+)$/` | 508 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| DELETE | `/^\/api\/workspaces\/([^\/]+)\/invitations\/([^\/]+)$/` | 573 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/invitations\/([^/` | 612 | public-or-global | public | — |
| POST | `/^\/api\/invitations\/([^/` | 646 | public-or-global | ✓ | requireAuth, getWorkspaceBillingUserId* |

### `workers/scan-api/src/routes/workspace-reports.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| POST | `/^\/api\/workspaces\/([^/` | 21 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 52 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 66 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| PUT | `/^\/api\/workspaces\/([^/` | 81 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| GET | `/^\/api\/workspaces\/([^/` | 135 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 186 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 219 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| DELETE | `/^\/api\/workspaces\/([^/` | 259 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 314 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 360 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 382 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 407 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 436 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| PUT | `/^\/api\/workspaces\/([^/` | 479 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| DELETE | `/^\/api\/workspaces\/([^/` | 524 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/^\/api\/workspaces\/([^/` | 556 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| POST | `/^\/api\/workspaces\/([^/` | 581 | workspace | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| DELETE | `/^\/api\/workspaces\/([^/` | 650 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| PATCH | `/^\/api\/workspaces\/([^/` | 689 | workspace | ✓ | requireAuth, requireWorkspaceRole |

### `workers/scan-api/src/routes/workspaces-core.js`

| Method | Path | Line | Scope | Auth | Guards |
|---|---|---:|---|---|---|
| GET | `(none)` | 61 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| PATCH | `(none)` | 188 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| DELETE | `(none)` | 220 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| GET | `(none)` | 305 | unknown | ✓ | requireAuth, requireWorkspaceRole |
| POST | `(none)` | 388 | unknown | ✓ | requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId* |
| POST | `/^\/api\/workspaces\/([^/` | 477 | workspace | ✓ | requireAuth, requireWorkspaceRole |
| GET | `/api/account/deleted-workspaces` | 577 | account | ✓ | requireAuth |
| POST | `/^\/api\/workspaces\/([^/` | 644 | workspace | ✓ | requireAuth |

_`*` = workspace-scoping helper (getAccessibleWorkspaceIds / getWorkspaceBillingUserId)._
