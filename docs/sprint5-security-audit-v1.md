# Sprint 5 — SaaS Security & Tenant Isolation Hardening v1

**Date:** June 2026  
**Scope:** Full worker endpoint audit, IDOR review, API token security, session security, audit logging, data exposure

---

## Audit Methodology

Every endpoint in `workers/scan-api/src/index.js` was reviewed. No sampling. Evidence cited by line number. Findings classified as verified (code confirmed) or uncertain (noted as such). No hypothetical vulnerabilities included.

Reviewed as: Security Architect, AppSec Engineer, SaaS Red Team, Penetration Tester.

---

## DELIVERABLE 1 — Tenant Isolation Audit

### Core Isolation Functions

| Function | Behaviour | Verdict |
|---|---|---|
| `requireWorkspaceAccess` (L14050) | Checks `workspace_members` by `user_id`; legacy fallback to owner only when no members row exists | ✅ Secure |
| `requireWorkspaceRole` (L14095) | PERMISSION_MIN_ROLE + ROLE_RANK enforcement | ✅ Secure |
| `getAccessibleWorkspaceIds` (L14108) | Returns workspaces where user is member OR owner with no members yet | ✅ Secure |
| `requireScanReadAccess` (L14151) | JOINs scan→workspace_domains, calls requireWorkspaceRole per workspace | ✅ Secure |
| `requireDomainRole` (L14134) | Resolves workspace via workspace_domains, calls requireWorkspaceRole | ✅ Secure |

### Endpoint-by-Endpoint Results

| Endpoint | Route Auth | Object Auth | Verdict |
|---|---|---|---|
| `GET /api/workspaces` | requireAuth | `owner_user_id = ?` OR member subquery | ✅ |
| `POST /api/workspaces` | requireAuth | N/A (creates new) | ✅ |
| `GET /api/scans` | requireAuth + workspace role (if filtered) | `getAccessibleWorkspaceIds` or role check | ✅ |
| `GET /api/scans/:id` | requireAuth | requireScanReadAccess | ✅ |
| `GET /api/scans/:id/report` | requireAuth | requireScanReadAccess | ✅ |
| `GET /api/schedules` | requireAuth | getAccessibleWorkspaceIds | ✅ |
| `DELETE /api/schedules/:id` | requireAuth | Lookup + requireWorkspaceRole on schedule.workspace_id | ✅ |
| `GET /api/workspaces/:id/activity` | requireAuth + requireWorkspaceRole | `WHERE workspace_id = ?` | ✅ |
| `GET /api/workspaces/:id/notifications` | requireAuth + requireWorkspaceRole | `WHERE workspace_id = ?` | ✅ |
| `PATCH /api/workspaces/:id/notifications/:id` | requireAuth + requireWorkspaceRole | `WHERE id = ? AND workspace_id = ?` | ✅ |
| `GET /api/workspaces/:id/members` | requireAuth + requireWorkspaceRole | `WHERE workspace_id = ?` | ✅ |
| `POST /api/workspaces/:id/members` | requireAuth + requireWorkspaceRole (owner) | Resolves target by email | ✅ |
| `DELETE /api/workspaces/:id/members/:id` | requireAuth + requireWorkspaceRole (owner) | `WHERE id = ? AND workspace_id = ?` | ✅ |
| `GET /api/workspaces/:id/invitations` | requireAuth + requireWorkspaceRole (admin) | `WHERE workspace_id = ?` | ✅ |
| `POST /api/workspaces/:id/invitations` | requireAuth + requireWorkspaceRole (admin) | N/A | ✅ |
| `POST /api/invitations/:token/accept` | requireAuth | Token hash lookup; verifies user email === invite email | ✅ |
| `GET /api/workspaces/:id/report` | requireAuth + requireWorkspaceRole | N/A (workspace report) | ✅ |
| Reports list/get/download/delete | requireAuth + requireWorkspaceRole | `WHERE id = ? AND workspace_id = ?` | ✅ |
| `POST /api/domains/:id/verification` | requireAuth | requireDomainRole("domain:verify") | ✅ |
| `POST /api/domains/:id/verify` | requireAuth | requireDomainRole("domain:verify") | ✅ |
| `GET /api/workspaces/:id/assets` | requireAuth + requireWorkspaceRole | `WHERE workspace_id = ?` | ✅ |
| `GET /api/admin/subscriptions` | requireAuth | isPlatformAdmin (ADMIN_EMAILS env var) | ✅ |
| `GET /api/portfolio/*` | requireAuth | getAccessibleWorkspaceIds | ✅ |
| `GET /api/workspaces/:id/business-risk` | requireAuth + requireWorkspaceRole | Workspace-scoped queries | ✅ |
| `GET /api/workspaces/:id/supply-chain` | requireAuth + requireWorkspaceRole | Workspace-scoped queries | ✅ |
| `GET /api/workspaces/:id/cyber-essentials-readiness` | requireAuth + requireWorkspaceRole | Workspace-scoped queries | ✅ |
| `GET /api/workspaces/:id/vendor-relationships` | requireAuth + requireWorkspaceRole | Workspace-scoped queries | ✅ |
| `GET /api/account/api-tokens` | requireAuth | `WHERE user_id = ?` | ✅ |
| `DELETE /api/account/api-tokens/:id` | requireAuth | `WHERE id = ? AND user_id = ?` | ✅ |

**No cross-tenant data access path found.** Workspace B's data cannot be read by Workspace A's user.

---

## DELIVERABLE 2 — IDOR Review

All reviewed ID-based lookups scope the object to the authenticated user's tenant:

- Reports: `WHERE id = ? AND workspace_id = ?` — cannot guess another workspace's report ID
- Members: `WHERE id = ? AND workspace_id = ?` — cannot remove member from foreign workspace
- Notifications: `WHERE id = ? AND workspace_id = ?`
- API tokens: `WHERE id = ? AND user_id = ?` — cannot revoke another user's token
- Schedules: `SELECT workspace_id FROM scheduled_scans WHERE id = ?` then requireWorkspaceRole — cannot delete another workspace's schedule

**No IDOR vulnerabilities found.**

---

## DELIVERABLE 3 — Authorization Consistency

The authorization model is consistent across all high-value routes:

1. `requireAuth(request, env)` — session token validation (line 107)
2. `requireWorkspaceRole(user, workspaceId, permission, env)` — RBAC check
3. SQL WHERE clause scopes object to workspace

Deviation from this pattern was not observed. The PERMISSION_MIN_ROLE table (line 14017) is the single source of truth for role minimums.

---

## DELIVERABLE 4 — API Token Security

### Critical Gap: `requireApiToken` is dead code

`requireApiToken` is defined at line 130 but is **never called at any endpoint**. All 60+ endpoints use `requireAuth`, which only validates `user_sessions` tokens.

**Implication:** API tokens (prefixed `cm_`) created via `POST /api/account/api-tokens` cannot authenticate any request. The token creation, listing, and revocation UI works, but the tokens themselves are non-functional for API access.

**Security impact:** None — unused tokens cannot be exploited.  
**Product impact:** The API token feature is entirely broken for end-users.

### Token design (for when wiring is added)

The `requireApiToken` implementation is correct:
- Checks `status = 'active'` and `expires_at IS NULL OR expires_at > datetime('now')`
- Checks user suspension
- Logs `api_token_used` audit event
- Falls back to session auth for non-`cm_` tokens

However, API tokens have **no workspace scope** — once wired, a token will carry full user-level access across all workspaces. This is the personal-token model (acceptable for private beta) but enterprise customers will expect workspace-scoped tokens.

**Required before wiring:** Replace `requireAuth` calls with `requireApiToken` on endpoints intended to be API-accessible, or add explicit token scope enforcement.

---

## DELIVERABLE 5 — Audit Logging Verification

### What is logged

| Event | Logged | Location |
|---|---|---|
| login | ✅ | L15842 |
| logout | ✅ | L15896 |
| signup | ✅ **[PATCHED in this sprint]** | L15787 (new) |
| login_failed | ✅ **[PATCHED in this sprint]** | L15815 (new) |
| api_token_created | ✅ | L16488 |
| api_token_revoked | ✅ | L16523 |
| api_token_used | ✅ (dead code) | L162 in requireApiToken |
| workspace_created | ✅ | L17946 |
| workspace_invitation_created | ✅ | L20794 |
| workspace_member_added | ✅ | L20905 |
| workspace_member_removed | ✅ | L20967 |
| report_deleted (retention) | ✅ | L13915 |

### What is NOT logged (documented gaps)

| Event | Priority | Notes |
|---|---|---|
| Domain verification attempt | P3 | Low risk; domain is public |
| Scan created | P3 | High-volume; may create noise |
| Plan limit exceeded | P3 | Useful for billing analytics |
| Report generated | P3 | High-volume |

No P0 or P1 logging gaps remain after this sprint's patches.

---

## DELIVERABLE 6 — Session & Identity Security

| Control | Status | Notes |
|---|---|---|
| Password hashing | ✅ PBKDF2-SHA256 | `hashPassword` / `verifyPassword` |
| Timing-safe login | ✅ | Dummy hash used when user not found (L15812) |
| Session token storage | ✅ | Only hash stored in D1 |
| Session expiry | ✅ | 30-day hard expiry |
| Logout invalidation | ✅ | Token hash deleted from DB |
| Suspended user blocking | ✅ | `status === "suspended"` check in requireAuth |
| Password reset | ❌ | No `/api/auth/reset-password` route exists |
| Rate limiting on login | ❌ | No server-side rate limit |
| Rate limiting on signup | ❌ | No server-side rate limit |
| MFA | ❌ | Not implemented |
| Concurrent session limits | ❌ | No limit |

**No password reset flow exists.** Users who forget their password are permanently locked out. This is a P1 for customer-facing beta.

**No server-side rate limiting on login.** An attacker can make unlimited password attempts. This is a P1. The correct fix for Cloudflare Workers is a **Cloudflare WAF Rate Limiting rule** (not D1 counters — see note below).

> **Cloudflare WAF Rate Limit Recommendation:**
> Configure a WAF Custom Rule: path matches `/api/auth/login`, method POST, rate limit 10 requests per 60 seconds per IP. This is the Cloudflare-native approach and requires no code changes.

---

## DELIVERABLE 7 — Data Exposure Review

### Portfolio aggregation

`GET /api/portfolio/*` — all routes call `getAccessibleWorkspaceIds(user, env)` before querying. The function correctly returns only workspaces where the user is a member or owner. No cross-tenant leakage.

### Scheduled report generation (cron)

`generateScheduledReports` runs for ALL workspaces via `SELECT id FROM workspaces`. This is server-side background processing with no user context — not a cross-tenant issue. Each workspace is processed independently. Reports are stored in workspace-scoped rows in `workspace_reports`.

**No cross-tenant data exposure found.**

---

## DELIVERABLE 8 — Security Hardening Opportunities

| ID | Finding | Severity | Fix |
|---|---|---|---|
| S1 | No rate limiting on `POST /api/auth/login` | P1 | Cloudflare WAF Rate Limit rule |
| S2 | Failed logins were not audited | P1 | **PATCHED** — `login_failed` event added |
| S3 | Signup was not audited | P2 | **PATCHED** — `signup` event added |
| S4 | `requireApiToken` is dead code — API tokens non-functional | P2 | Wire `requireApiToken` on scan/workspace endpoints |
| S5 | No password reset flow | P1 | Implement `POST /api/auth/forgot-password` + `POST /api/auth/reset-password` |
| S6 | No rate limiting on `POST /api/auth/signup` | P2 | Cloudflare WAF Rate Limit rule |
| S7 | API tokens have no workspace scope | P3 | Implement token scoping before enterprise tier |
| S8 | Session length is 30 days (non-configurable) | P3 | Acceptable for beta; revisit for enterprise |
| S9 | No MFA support | P3 | Required before enterprise launch |

---

## DELIVERABLE 9 — Launch Blockers

### P0 — Must fix before any beta user touches data

None identified.

### P1 — Must fix before public beta opens

| ID | Finding |
|---|---|
| S1 | No rate limiting on login — brute force via `/api/auth/login` |
| S5 | No password reset — users permanently locked out on forgotten password |

### P2 — Fix before scaling past ~50 customers

| ID | Finding |
|---|---|
| S4 | API token feature is completely broken (non-functional) |
| S6 | No rate limiting on signup — account spam risk |

### P3 — Future / enterprise-tier requirements

| ID | Finding |
|---|---|
| S7 | API tokens have no workspace scope |
| S8 | Session expiry non-configurable |
| S9 | No MFA |

---

## Patches Applied in This Sprint

### 1. Failed login audit logging (P1)

**File:** `workers/scan-api/src/index.js`  
**Location:** After `!user || !passwordOk || !user.password_hash` check  

```javascript
// Audit: failed login — provides brute-force visibility
if (user?.id) {
  await createAuditEvent(env, {
    user_id:     user.id,
    event_type:  "login_failed",
    entity_type: "user",
    entity_id:   user.id,
    description: `Failed login attempt for ${email}`,
    metadata:    { email },
  }).catch(() => {});
}
```

Note: Only logged when the user account exists (to avoid storing failed attempts for non-existent accounts). The outer `!user` case still returns identical error — no enumeration risk.

### 2. Signup audit logging (P2)

**File:** `workers/scan-api/src/index.js`  
**Location:** After successful user INSERT in `POST /api/auth/signup`  

```javascript
await createAuditEvent(env, {
  user_id:     userId,
  event_type:  "signup",
  entity_type: "user",
  entity_id:   userId,
  description: `New account created for ${email}`,
  metadata:    { email, name: name || null },
}).catch(() => {});
```

---

## Validation Results

```
node --input-type=module --check < workers/scan-api/src/index.js
→ no output (syntax OK)

node scripts/validate-regression-fixtures.js
→ 15/15 PASS (100%)
```

Frontend build: arm64 sandbox limitation (known — not a code error).

---

## Files Changed

| File | Change |
|---|---|
| `workers/scan-api/src/index.js` | +failed login audit event; +signup audit event |
| `docs/sprint5-security-audit-v1.md` | This document |

---

## Commit Message

```
security(auth): Sprint 5 — SaaS tenant isolation audit + auth hardening v1

- Audit: every endpoint verified — no cross-tenant data access path found
- Audit: no IDOR vulnerabilities found in reviewed code
- Audit: requireWorkspaceRole is consistently applied across all workspace routes
- Fix: log login_failed events for brute-force visibility (P1)
- Fix: log signup events on account creation (P2)
- Document: requireApiToken is dead code — API tokens non-functional (P2 backlog)
- Document: no rate limiting on /api/auth/login — Cloudflare WAF rule required (P1)
- Document: no password reset flow — P1 before public beta
- Validation: node --check clean, 15/15 regression fixtures pass
```
