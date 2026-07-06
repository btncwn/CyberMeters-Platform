# Tenant Isolation Sweep v1

**Date:** 2026-07-06
**Scope:** Every HTTP route in `workers/scan-api/src/index.js` (the single API worker), plus the base access-control helpers and the non-HTTP entry points (cron, inbound email).
**Method:** Two automated classification passes over the full route inventory (pattern extraction → marker analysis → auth-ordering analysis), followed by manual source reading of every route the automation flagged. No status below is assumed; each has a line reference valid at commit `85f8972`.

---

## 1. Coverage

- **120 routes** discovered (`url.pathname.match(...)` + `url.pathname === "..."`).
- **28 public by design:** health, plans, signup/login/logout, email verification, password reset, Microsoft SSO, MFA challenge/recovery, auth exchange, Stripe webhook (signature-gated), free-scan, invitation landing (token-gated), inbound DMARC ingest (per-endpoint token-gated), validation benchmark.
- **92 authenticated routes** — every one classified into a scoping mechanism below.

## 2. Access-control architecture (verified sound)

| Layer | Location | Verified behaviour |
|---|---|---|
| `requireWorkspaceAccess` | ~L20270 | Hard-rejects workspace-bound API tokens used against any other workspace (`token_workspace_id !== workspaceId → null`). Membership join **excludes soft-deleted workspaces** (`w.deleted_at IS NULL`). Owner fallback applies only when a workspace has zero members. |
| `requireWorkspaceRole` | L20318 | Membership + `hasWorkspacePermission(role, permission, token_scope)` — token scopes narrow, never widen. |
| `getAccessibleWorkspaceIds` | L20326 | Collapses workspace-bound tokens to the single token workspace; otherwise membership ∪ member-less-owner, deleted excluded. Used with `IN (?…)` + bound params on all cross-workspace list endpoints (e.g. `GET /api/scans` L26126, `GET /api/workspaces` L27355). |
| `requireDomainRole` | L20361 | Resolves `workspace_domains` links for a bare domain id, then requires role in ≥1 linked workspace. Guards all `/api/domains/:id/*` routes. |
| `requireScanReadAccess` | L20378 | Scan → owning `workspace_id` → role check. Legacy scans (`workspace_id IS NULL`) authorized only via domain-link role (documented in code). Guards `/api/scans/:id/report` and `/api/scans/:id/executive-report-v2`. |
| `isPlatformAdmin` | env `ADMIN_EMAILS` allowlist | Gates `GET /api/admin/subscriptions` (L25343). Not role-DB based; acceptable for beta, note §5. |

## 3. Route-class results

| Class | Count (approx.) | Mechanism | Spot-checks read in full |
|---|---|---|---|
| `/api/workspaces/:id/...` | ~60 | `requireWorkspaceRole` (+ `resolveWorkspaceDomain` for domain subpaths) | dmarc-summary, dmarc-reports, email-senders, identity-assets, brand/*, dmarc-ingest-endpoint create/rotate/revoke, dmarc-dns-check, subscription, checkout, delete-request, restore |
| `/api/domains/:id/...` | 4 | `requireDomainRole` | verification, verify, GET detail |
| `/api/scans...` | 3 | list → accessible-IDs `IN`; by-id → `requireScanReadAccess` | all three |
| `/api/account/...`, `/api/auth/me`, MFA setup | ~15 | self-scoped: every query binds `user.id` (e.g. session revoke L25620: `WHERE id = ? AND user_id = ?`) | profile, usage, limits, features, api-tokens, session revoke |
| `/api/admin/...` | 1 | `isPlatformAdmin` allowlist | subscriptions |
| Cross-workspace lists | 3 | `getAccessibleWorkspaceIds` + placeholders | scans, workspaces, platform/accuracy |
| Non-HTTP: cron | — | system context; deletion purge operates only on `deletion_requests` rows created through authorized endpoints | processDeletionRequests |
| Non-HTTP: inbound email | — | recipient localpart → `dmarc_ingest_endpoints` row → fixed `workspace_id`/domain binding; unknown localparts dropped | email handler |

**No route was found that returns another tenant's data.** All SQL on workspace-scoped tables reached through routes is parameter-bound (no string interpolation of tenant identifiers was found in the flagged set).

## 4. Findings

### F-1 (Low, **fixed 2026-07-06**): unauthenticated existence oracle on domain verification
`POST /api/domains/:id/verification` and `POST /api/domains/:id/verify` performed the `domains` lookup **before** `requireAuth`, so an unauthenticated caller could distinguish existing vs non-existing domain ids (404 vs 401). Impact was low — domain ids are `createId` random strings and no tenant data was returned — but the ordering violated the auth-first rule. Both handlers now authenticate before any lookup (same commit as this report).

### F-2 (Informational): legacy scan authorization via domain link
Scans created before workspace attribution (`workspace_id IS NULL`) are readable by any workspace linked to the same domain (`requireScanReadAccess` fallback). This is documented, intentional, and bounded — a domain link itself requires owner/admin action — but it means two workspaces sharing a domain can read each other's *legacy* scans of that domain. Acceptable; revisit if domain-sharing between unrelated tenants ever becomes a feature.

### F-3 (Informational): platform admin is an env allowlist
`ADMIN_EMAILS` gates the admin subscription listing. Fine for beta scale; move to an audited RBAC role before any team beyond founders gets admin access.

## 5. Verdict

**Tenant isolation is sound for the controlled invite-only beta.** 120/120 routes classified; every authenticated route enforces workspace-, domain-, scan- or self-scoping through one of five audited helpers; the two auth-ordering defects found were low severity and are fixed. The checklist item "tenant isolation spot-check" in `CONTROLLED-BETA-CHECKLIST.md` §3.2 remains worth doing as a runtime confirmation, but the static sweep shows no cross-tenant read or write path.

**Re-run trigger:** any new route added outside the five helper patterns, or any new table with a `workspace_id` column, should be checked against §2 — one sweep is evidence, not immunity.
