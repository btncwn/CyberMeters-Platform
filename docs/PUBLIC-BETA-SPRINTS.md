# CyberMeters — Public Beta Sprint Plan (10 sprints)

> Sequenced backlog to close the gap between "controlled-beta ready" and
> "enterprise-credible public beta". Ordered **lowest risk / easiest first →
> highest risk / most important last**, so early sprints ship fast visible
> progress and the deep architectural work comes only after the safety net
> (tests, observability) is in place. Each sprint is independently shippable and
> leaves standalone progress — stop at any point without a broken state.
>
> Grounded in the 7 due-diligence passes run 2026-07-07/08, all verified against
> the code. Baseline scores (evidence-based): Security 86, Reliability 78,
> Performance 74, Production Readiness 70, Engineering 68, Operations 64,
> Enterprise Readiness 60, Technical Maturity 62, Competitive 58, Architecture
> 55, DX 55, Maintainability 52. The ladder below targets the low scores without
> regressing the high ones.
>
> Not blockers for the current two-domain private beta (that is live). These
> gate **public** beta + enterprise credibility.

---

## Sprint 1 — Release hygiene & versioning  ·  risk: LOW  ·  effort: Low
**Goal:** every deploy is traceable and reversible on demand.
**Why (evidence):** deploys are manual `wrangler deploy`; no release tags, no
version surfaced, rollback is ad-hoc (see `OPERATIONS.md`). CI does not deploy.
**Tasks:**
- Adopt a version string (e.g. `APP_VERSION` var) surfaced at `GET /health` and in `[request-error]` logs.
- Git tag on each production deploy (`vYYYY.MM.DD-n`); short internal CHANGELOG.
- CI: record the deployed Version ID as a build artifact/summary.
- Document the rollback drill in `OPERATIONS.md` and actually run it once (dry).
**Risk:** ops/CI + one health field only; no product code path changes.
**DoD:** `/health` returns version; a tag exists for the current prod deploy; rollback rehearsed and noted.

## Sprint 2 — API contract documentation (OpenAPI)  ·  risk: LOW  ·  effort: Low-Med
**Goal:** a single machine-readable description of the API surface.
**Why:** no OpenAPI/spec exists; enterprise procurement + integration expect one. Zero runtime change.
**Tasks:**
- Generate an OpenAPI 3.1 doc covering the public + authenticated routes (auth model, error shape `{error, code, request_id}`, rate-limit headers).
- Commit as `docs/openapi.yaml`; keep it a build-checked artifact (lint in CI).
**Risk:** documentation artifact only.
**DoD:** `docs/openapi.yaml` validates in CI; covers every route family.

## Sprint 3 — Consistent pagination contract  ·  risk: LOW-MED  ·  effort: Med
**Goal:** one pagination shape across all list endpoints.
**Why (evidence):** 181 `LIMIT` clauses but only 12 `limit` / 3 `offset` query params — pagination is ad-hoc and inconsistent. Enterprise API consumers expect a stable contract.
**Tasks:**
- Define a shared list-response helper `{ items, page: { limit, offset|cursor, total, has_more } }`.
- Migrate list endpoints (scans, reports, notifications, members, assets, audit log) to it.
- Verify the frontend consumers still parse each (check `frontend/src/api.js` call sites before changing a response).
**Risk:** touches list response shapes — must confirm each frontend consumer.
**DoD:** every list endpoint returns the shared shape; frontend build + manual smoke green.

## Sprint 4 — Residual security hardening  ·  risk: LOW-MED  ·  effort: Med
**Goal:** close the last verified security backlog items.
**Why (evidence):** `probeAsset` uses `redirect: "follow"` (defence-in-depth, not a live vuln on Workers); inbound DMARC reports are domain-matched but not sender-authenticated (`task_7117978b`, in flight).
**Tasks:**
- `probeAsset` → `redirect: "manual"` (align with the other probers already doing this).
- Land the DMARC report-authenticity work from `task_7117978b` (DKIM-of-reporter / anomaly-flag / envelope recorded).
- Re-run the security-contract suite; add contracts for any new logic.
**Risk:** isolated functions; ingestion path must not destabilise (two domains live).
**DoD:** hardening merged; `validate-security-contracts.js` extended and green.

## Sprint 5 — Observability layer  ·  risk: MED  ·  effort: Med
**Goal:** see failures before customers report them.
**Why (evidence):** observability is `wrangler tail` + CF analytics + `audit_events` only — no metrics, no alerting (SRE gap flagged in DD).
**Tasks:**
- Emit structured metrics (Cloudflare Analytics Engine or Sentry): scan success/fail, email-delivery, webhook outcomes, cron durations, 5xx rate.
- Alerting hooks on error-rate / cron-failure / stuck-scan thresholds.
- Add a `/ready` readiness probe (D1 + R2 reachability) alongside `/health`.
**Risk:** additive instrumentation; keep it fail-open so telemetry never breaks a request.
**DoD:** a dashboard shows the key rates; one alert fires in a test; `/ready` reflects dependency health.

## Sprint 6 — Integration test harness  ·  risk: MED  ·  effort: Med-High
**Why (evidence):** tests were 218 scoring fixtures + 36 security contracts (pure functions). No flow tests touched the database.
**Approach:** a real in-memory SQLite (`node:sqlite`) wrapped in a D1-compatible
adapter — high fidelity (real JOINs / NULL / ordering), not a hand-programmed
mock. CI pinned to Node 24 for determinism.

### Phase 1 — Authorization integration — DONE (`scripts/validate-integration.js`, 18 assertions, CI-blocking)
Scoped accurately: this phase is **authorization**, not the whole pipeline.
- Tenant isolation: cross-tenant access proven to 403 (`userB(ws1) → ws2 → denied`).
- RBAC via `requireWorkspaceRole` (access + permission matrix together).
- API-token workspace boundary.
- Legacy owner fallback (workspace with no member rows).
- Soft-delete inaccessibility.
- `getAccessibleWorkspaceIds` filtering (excludes foreign tenants + soft-deleted).

### Phase 2 — request-pipeline integration — DONE (`scripts/validate-pipeline.js`, 22 assertions in 7 sections, CI-blocking)
Drives the worker's real `fetch(request)` (router → middleware → `requireAuth` →
RBAC → D1 → Response) against a real in-memory SQLite seeded with the **actual
schema** (schema.sql + all migrations, best-effort) — the true integration layer,
not leaf functions. Every assertion is verified on the response body / DB state,
and tests are grouped into named sections (Health, Auth gate, Tenant isolation,
Login/session, Billing, Pagination, Rate limiting) so the suite stays navigable
as it grows.
- **End-to-end request pipeline** proven: `GET /health` → 200 drives the whole chain.
- **Auth gate at the HTTP layer:** unauthenticated / invalid-token → 401.
- **Tenant isolation end to end:** owner reads OWN workspace → 200 with the real
  record; same user+token → FOREIGN workspace → 403, no data leak.
- **Login / session lifecycle:** wrong password → 401 (no token); correct → 200 +
  session token; token authenticates `/api/auth/me` as the right user; logout;
  the same token is then dead → 401.
- **Stripe webhook → entitlement → feature gate:** unsigned → 4xx; wrong-secret
  signature → 400 (forgery rejected); a correctly-signed
  `customer.subscription.created` upserts the subscription to professional/active
  in D1 — and the professional-gated audit-events endpoint flips from
  403 `plan_feature_required` to 200 on the same token. The upgrade demonstrably
  *takes effect*.
- **Pagination contract via HTTP:** limit honoured, `{limit, offset, count,
  has_more, total}` correct, offset walks to the last page (audit-events;
  the harness also caught that the endpoint self-audits each view).
- **Login rate limiting:** hammering login trips 429 within the 10/15-min window,
  stays tripped, and never 5xxs.
- **CSRF: N/A by architecture (verified):** auth is a Bearer token in the
  `Authorization` header; the API sets no cookies (all Set-Cookie references in
  the worker are the *scanner* checking customers' sites). No ambient credential
  → nothing for a cross-site request to ride.

### Phase 3 — remaining tail (incremental, on the now-existing harness)
- **More billing events:** `invoice.payment_failed` → grace → downgrade;
  `customer.subscription.deleted`; `checkout.session.completed`.
- **Domain verify lifecycle** end to end (initiate → DNS TXT → verified → auto-retry).
- **Permission inheritance** if/when a workspace→project→resource hierarchy exists.
**DoD (Phases 1 & 2, met):** flow + pipeline tests green in CI; a cross-tenant
access attempt proven to 403; login lifecycle and webhook→entitlement proven end to end.

## Sprint 7 — Frontend test layer — DONE (24 tests / 6 files, CI-blocking)  ·  risk: MED  ·  effort: Med
**Goal:** protect the customer-facing critical paths from regression.
**Why (evidence):** **zero** frontend test tooling existed. Notification-click and blank-screen incidents were caught only by luck/manual checks.
**Shipped:** Vitest + Testing Library (`vitest.config.js` separate from the build
config; jsdom ^26; setup replaces Node 22+'s undefined global storage getters
with an in-memory Storage). `npm test` blocks CI before the build step.
- **NotificationBell click-through** — the real regression: parsed `metadata` →
  `/scans/:id`; legacy `metadata_json` string still works; report → `/reports`;
  target-less clicks don't break navigation.
- **ProtectedRoute** (extracted from App.jsx, same JSX): loading holds the
  spinner (no premature redirect); unauthenticated → `/login`; authed → children.
- **ChunkErrorBoundary**: one auto-reload on stale chunks + loading state; budget
  refuses the second and shows the customer-safe card (manual always allowed);
  non-chunk errors never leak raw text; `clearReloadBudget` restores after a
  healthy boot.
- **SafeBoundary**: contains throwing widgets, fallback only, no raw error.
- **WorkspaceNav**: four services, no cross-service sub-item mixing, accordion
  toggle (the fixed bug), sub-items inherit the parent service colour.
- **PlanGate**: 403 `plan_feature_required` renders the upgrade wall — the
  frontend half of the contract the backend pipeline test proves server-side.
**DoD (met):** critical components under test; CI blocks on frontend test failure.

## Sprint 8 — TypeScript foundation (incremental)  ·  risk: MED-HIGH  ·  effort: High
**Goal:** compile-time safety on the highest-churn surfaces.
**Why (evidence):** no `tsconfig`, plain JS/JSX across ~37k worker lines + frontend. No type contract between frontend and API (DD maturity gap).
**Tasks:**
- Add `tsconfig` with `allowJs`, `checkJs` incremental; no big-bang rewrite.
- Type the API client (`frontend/src/api.js`) + shared response/domain types first (pairs with the OpenAPI from Sprint 2).
- Convert new files to `.ts/.tsx`; leave the monolith JS until Sprint 9-10.
**Risk:** build-tooling change; keep JS interop working, ship in slices.
**DoD:** typed API client + shared types; CI type-check step; build unbroken.

## Sprint 9 — Worker decomposition, phase 1  ·  risk: HIGH  ·  effort: High
**Goal:** carve fault-isolated seams out of the monolith without behaviour change.
**Why (evidence):** single `workers/scan-api/src/index.js` = **~37,258 lines** handling API + cron + email + scan + scoring + PDF. Deploy = whole system; no isolation; 1.6 MB re-parse each deploy. #1 architectural weakness (Architecture 55, Maintainability 52).
**Tasks:**
- Extract **cron/scheduler** and the **inbound email handler** into separate modules (shared lib for D1/helpers), behaviour-identical.
- Regression + security + integration suites must stay green throughout (that safety net is why this comes after Sprints 6-7).
- Keep one deploy first; module boundaries prove out before splitting deploys.
**Risk:** touches the whole system; only safe now because tests exist.
**DoD:** cron + email in their own modules; all suites green; no behaviour delta observed on the two live domains.

## Sprint 10 — Worker decomposition, phase 2 + fault isolation  ·  risk: HIGHEST  ·  effort: High
**Goal:** independently deployable, fault-isolated services.
**Why:** completes the architectural win — a scanner fault can't take down the API; independent deploys; smaller cold-parse.
**Tasks:**
- Split remaining seams: **api / scanner / reports** (scanner triggered via queue or service binding).
- Separate deploys per service; per-service health.
- Load/quota headroom check at target public-beta scale.
- Update `OPERATIONS.md` + `docs/openapi.yaml` to the new topology.
**Risk:** highest — service boundaries, queue semantics, deploy choreography.
**DoD:** services deploy independently; a forced scanner failure leaves the API healthy; scale headroom confirmed.

---

## Sequencing rationale
1-4 are cheap, additive, mostly non-code-path → fast visible progress + enterprise checkboxes, near-zero regression risk.
5-7 build the **safety net** (observability + tests) — deliberately BEFORE the risky refactor.
8 adds type safety on top of the now-documented API.
9-10 are the deep architectural work (monolith split), done last because they are only safe once tests + observability exist to catch regressions.

**No sprint blocks the current private beta.** If the two-domain beta surfaces
real friction (e.g. blackbullbarbers' first DMARC report exposes an ingestion
issue), that jumps the queue — real-user signal always outranks this backlog.
