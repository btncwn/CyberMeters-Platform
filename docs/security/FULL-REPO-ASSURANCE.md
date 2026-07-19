# CyberMeters — Full-Repo Security Assurance

> **Scope:** repository-wide tenant-isolation, authentication, authorization and
> evidence-integrity assurance. **Status:** engineering-complete; authenticated
> browser two-tenant acceptance is a release-gate activity (see §8). **Last run:**
> 2026-07-19, against `main` @ `c5e7390` (App-Probe Reliability PR #185 merged;
> migration `095`; tag `v2026.07.19-2`).

This document is the canonical index for the full-repo assurance programme. It
records what was assessed, how, and the honest result. It does **not** claim
perfect security — it establishes defensible, automated, regression-proof evidence
that the platform's critical entry points and tenant-owned resource classes hold
their isolation invariants within the assessed scope.

Everything here is enforced by CI-blocking validators (see §12), so the properties
cannot silently regress.

---

## 1. Assurance scope

| Area | In scope | Out of scope |
|---|---|---|
| Worker HTTP entry points (routes, cron, email) | ✅ inventoried + auth-coverage gated | — |
| Tenant-owned D1 resource classes | ✅ all 83 tables classified | — |
| Static SQL/authorization patterns | ✅ audited + suppression-gated | — |
| Two-tenant dynamic authorization | ✅ real router, real SQLite | — |
| Property-based authorization | ✅ deterministic, seeded | — |
| D1 ↔ R2 lineage | ✅ ownership-scoped reads proven | — |
| Frontend workspace-switch isolation | ✅ server-authoritative + unit-tested | — |
| Production read-only integrity | ✅ runbook (release-gate execution) | live write/backfill (never) |
| Authenticated **browser** two-tenant E2E | controlled-env proof done | live-prod run = release gate |

---

## 2. Threat / invariant contracts

The **12 tenant-isolation invariants** (canonical, in `scripts/security/lib/tenant-resources.js`):

1. own resource succeeds
2. foreign resource safely fails
3. nonexistent resource behaves equivalently (no existence oracle)
4. deleted workspace fails per policy
5. deleted membership fails
6. soft-deleted resource follows policy
7. guessed ID does not bypass access
8. hostname alone is never ownership
9. `resource.workspace_id` must equal the authorised workspace_id
10. same hostname in two workspaces remains isolated
11. read and write paths separately covered
12. background producers preserve workspace identity

**Canonical authorization property:** for every user U and tenant-owned resource R,
if U lacks current authorised access to `R.workspace_id`, no operation may disclose,
mutate, resolve, remove, score, report, alert on, or otherwise influence R.

---

## 3. Entry-point inventory (Phase 1)

- **Tool:** `scripts/security/build-entry-point-inventory.js` → `scripts/security/entry-point-inventory.json` + `docs/security/ENTRY-POINT-INVENTORY.md`
- **Gate:** `scripts/validate-entry-point-inventory.js` (drift + auth-coverage)
- **Result:** **234 entry points** — 213 auth-guarded, 21 unauthenticated (all matched to a documented public-allowlist reason), **0 sensitive-scope gaps**. All **115/115 workspace-scoped**, 21/21 account, 2/2 admin, 9/9 portfolio handlers carry an auth guard in their lexical ancestry.
- The inventory is re-derived from source on every CI run: a new route, or a change to a route's guard set, fails the drift gate until the builder is re-run and reviewed. The 21 public entry points were each read and confirmed public-by-design (health/ready, signup/login, token-gated auth flows, Stripe webhook (HMAC-verified), endpoint-key-gated ingest, invitation preview, CORS preflight).

## 4. Tenant-isolation invariant matrix (Phase 2)

- **Tool:** `scripts/security/build-tenant-isolation-matrix.js` → `scripts/security/tenant-isolation-matrix.json` + `docs/security/TENANT-ISOLATION-MATRIX.md`
- **Gate:** `scripts/validate-tenant-isolation-matrix.js`
- **Result:** **83 tables, 0 unclassified**, 79 tenant-owned + 4 infra/identity, grouped into **30 resource classes**; **17 classes** carry dynamic-harness coverage. Ownership is derived from the live schema, so a class cannot claim a column its tables do not have. A new tenant-owned table that is not triaged into a class fails the gate. A class that claims dynamic-harness coverage must be backed by a marker present in the harness source (anti-tautology).

## 5. Static tenant-query audit (Phase 3)

- **Tool:** `scripts/security/lib/tenant-query-audit.js`; report `docs/security/TENANT-QUERY-AUDIT.md`
- **Gate:** `scripts/validate-tenant-query-audit.js`; suppressions `scripts/security/tenant-query-audit-suppressions.json`
- **Result:** 958 SQL sites scanned → **261 findings**. High-signal blocking detectors: `hostname_only_ownership` (**0**), `global_latest_fallback` (2), `r2_key_not_workspace_bound` (11), `body_workspace_trust` (8) — all **19 unique fingerprints suppressed** with a manually-verified reason + security contract; **0 unsuppressed**. The 240 `unscoped_tenant_query` findings are informational: they touch a tenant table without an inline predicate but sit behind an out-of-band guard (an authenticated workspace-authorized route — proven by §3 — or an already-scoped scan/subscription context).
- A tenant column is counted as scoping only when used as an actual predicate (`workspace_id = ?`, `IN`, `IS`), never when it merely appears in a `SELECT` column list — so `SELECT workspace_id FROM scans WHERE id = ?` is correctly treated as unscoped. Under this stricter check the platform still has **zero** hostname-only or global-latest IDOR patterns.
- Suppression fingerprints are line-independent, so they survive unrelated edits but go stale when the guarded statement itself changes, forcing re-review. A stale suppression fails the gate.

## 6. Dynamic two-tenant harness (Phase 4)

- **Existing:** `scripts/validate-tenant-isolation.js` — 107 assertions, four actors (admin/viewer/foreign/non-member), 7 invariants over ~23 workspace-scoped GETs, writes, admin actions, soft-delete, invite redirection, and R2 report ownership with owner positive controls.
- **Added:** `scripts/validate-tenant-isolation-extended.js` — **15 assertions** for: **invariant 10** (the exact same hostname `shared.example` seeded in both tenants; the tenant-B owner is denied on tenant-A despite owning the identical hostname, and each owner sees only their own row — no cross-tenant merge); **invariant 5 dynamic** (a removed member can read before removal and is denied after, existence-oracle preserved); and **Identity Exposure** foreign/anon denial with an owner positive control.
- Both drive the **real** Worker `fetch()` router against a **real** in-memory SQLite with the full schema + migrations applied — not a mock.

## 7. Property-based authorization (Phase 5)

- **Tool/Gate:** `scripts/validate-authz-properties.js`
- **Approach:** a deterministic Mulberry32 PRNG (no framework) generates combinations across {actor, membership status, workspace deleted-state, route, operation, target (own / foreign-real / nonexistent / guessed), same/different hostname}. Every generated actor lacks access, so the oracle is uniform: **every case must be denied, leak no marker, and mutate nothing.**
- **Result:** seed `0x0c1a55e5`, **500 cases → 729 assertions, 0 failures.** Anti-tautology controls assert the owner leaks each marker / gets 200 (so a "no-leak" pass is never vacuous), and each call uses a unique client IP so rate-limiting never masks the authorization logic. Post-run assertions confirm no protected resource was mutated by any write attempt.

## 8. Authenticated acceptance (Phase 6)

- **Frontend cache isolation:** `useWorkspace` is server-authoritative — it validates the cached workspace ID against the server list on mount and falls back if stale, so a foreign/stale workspace cannot persist. This is unit-tested (`frontend/src/hooks/__tests__/useWorkspace.test.jsx`, incl. "falls back to server default when the cached workspace is stale"); logout clears token/user/workspace state.
- **Controlled-environment proof:** the dynamic + extended + property harnesses drive the real router with two tenants and prove cross-tenant denial at the HTTP layer; the frontend suite (285 tests) proves workspace-switch isolation at the cache layer.
- **Release-gate activity:** authenticated **browser** two-tenant E2E against a full running stack requires live D1/R2 bindings and controlled accounts; per the operating rules this is performed at the final release gate on founder-controlled test workspaces. It is **not** claimed as complete here.

## 9. D1 ↔ R2 lineage (Phase 7)

Report/snapshot objects are proven ownership-scoped, not key-guessable: the base
harness serves a marker-bearing R2 object only for the owning scan's key and shows
foreign/non-member/anon denial with an **owner positive control** (the owner reads
the marker, so the denials are ownership checks, not "not found"). The property
suite repeats this for `/api/scans/:id/report` (R2-MARKER). The production integrity
runbook (§10) adds orphan/lineage checks binding snapshots and reports back to a
resolvable workspace.

## 10. Production read-only integrity (Phase 9)

- **Runbook:** `scripts/security/production-integrity-assertions.sql` — 12 read-only checks (scan/domain lineage conflicts, asset/domain conflicts, snapshot/scan workspace conflicts, case-domain membership, active schedules under deleted workspaces, orphan members/cases/invitations/domains, snapshots/cases without a resolvable workspace). Every statement is a `SELECT` that counts anomalies; a healthy DB returns 0. It cannot write.
- **Gate:** `scripts/validate-production-integrity-sql.js` executes every query against the in-memory schema (12/12 valid, 0 anomalies on empty), so the runbook is guaranteed executable before a founder runs it against production at the release gate.

## 11. Mutation catalogue (Phase 8)

Each mutation was applied to the source, the relevant gate observed to **fail**, then
the source restored and the gate observed to **pass**. "Demonstrated" = the mutation
was run this session; "covered" = caught by an existing positive/negative control.

| # | Mutation | Caught by | Evidence |
|---|---|---|---|
| 1 | route auth guard removed (`requireWorkspaceRole` always-allow) | property suite + extended harness | **demonstrated** — property 512/729, extended 8/15 |
| 2 | workspace membership check removed | (same mutation) | **demonstrated** |
| 3 | `resource.workspace_id` check removed from a query | static audit (`hostname_only_ownership`) | **demonstrated** — unsuppressed finding fails CI |
| 4 | hostname-only ownership | static audit detector | covered (detector = 0 in healthy tree) |
| 5 | `deleted_at` filter removed | base harness invariant 6 + property suite | **demonstrated** — base 106/107, property 720/729 |
| 6–11 | foreign scan/asset/report/case/alert/R2 accepted | base + extended + property (marker no-leak) | demonstrated via mutation #1 |
| 12 | global latest-record fallback | static audit (`global_latest_fallback`) | covered |
| 13 | frontend cache key missing workspace | `useWorkspace` stale-fallback unit test | covered |
| 14 | request-body role trusted | static audit (`body_workspace_trust`) + role-ceiling | covered |
| 15 | request-body plan/workspace trusted | static audit (`body_workspace_trust`) | covered |
| 16 | foreign/nonexistent parity removed | base + extended + property existence-oracle | covered |
| 17 | background writer loses workspace scope | matrix background-producer + static audit | covered |
| 18 | failed authorization emits a lifecycle event | property post-run no-mutation assertions | covered |
| 19 | same hostname merges tenant records | extended harness invariant 10 | **demonstrated** |
| 20 | route added without inventory entry | entry-point drift gate | **demonstrated** — new/flipped entry fails |
| 21 | new tenant table left un-triaged | matrix completeness gate | **demonstrated** |

## 12. CI gates (Phase 12)

Wired into `.github/workflows/ci.yml` (all CI-blocking):

- `validate-entry-point-inventory.js`
- `validate-tenant-isolation-matrix.js`
- `validate-tenant-query-audit.js`
- `validate-tenant-isolation-extended.js`
- `validate-authz-properties.js`
- `validate-production-integrity-sql.js`

Alongside the pre-existing `validate-tenant-isolation.js`, `validate-security-contracts.js`,
`validate-integration.js`, `validate-workspace-integrity.js`, `validate-migrations.js`,
`validate-ci-governance.js` and the full harness suite. Regression run 2026-07-19:
frontend **285/285**, regression fixtures **220/220**, worker syntax OK, frontend build OK,
wrangler dry-run OK, `git diff --check` clean.

## 13. Findings (Phase 10)

**No open P0, P1 or P2 defects were found within the assessed scope.** Every static
finding was manually re-verified and resolved to a documented, contract-backed
out-of-band guard; every dynamic, property and mutation check passes; and the
mutations confirm the checks bite. No source behaviour required a fix — the
deliverable is the assurance tooling and the evidence it produces.

## 14. Known limitations

- The entry-point inventory and static audit are **structural**, not a formal semantic
  proof; their guarantee is regression-proofing (a new route/guard change or a lost
  workspace predicate fails CI), backed by the dynamic + property runtime proofs.
- The 196 informational `unscoped_tenant_query` findings rest on out-of-band guards
  (proven at the route layer by §3), not on inline predicates.
- Authenticated **browser** two-tenant E2E and the production integrity runbook run at
  the founder-controlled release gate; they are not executed in CI (no live bindings).
- In-memory SQLite (`node:sqlite`) substitutes for D1/R2 in the harnesses; it exercises
  the real router and query text but not Cloudflare-runtime edge cases.

## 15. Assurance statement

> The platform's critical entry points and tenant-owned resource classes have been
> systematically assessed against defined authentication, authorisation, tenant-isolation
> and evidence-integrity invariants. Automated static, dynamic, mutation and
> property-based tests found no known open P0, P1 or P2 defects within the assessed scope.
