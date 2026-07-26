# Item 9 P3 — Certificate Renewal Lifecycle

## Before

### Goal

Extend the existing certificate lifecycle with evidence-isolated renewal
transitions, append-only replacement relationships, deterministic event/case
dedupe and canonical system-only case closure/reopen. A customer assertion or
the first scan that sees a replacement must never verify a certificate case.

### Exact Pre-Change Map

- `scan-engine.js` called `upsertCertificateObservation` and then
  `correlateCertificateLifecycle`; P2 already persisted the P1 per-signal model
  inside `certificate_observations.evidence_json.signal_completeness`.
- `certificate_observations` (migration 031) was the append-only identity/evidence
  store. `certificate_lifecycle` and `certificate_lifecycle_events` (migration
  085) held the current managed view and event history.
- `certificate-policy.js` was the canonical source for renewal bands and case
  thresholds.
- `certificate-lifecycle.js` selected the certificate with the furthest expiry,
  so a more recently observed shorter replacement could remain hidden. A changed
  composite certificate key alone was treated as a replacement.
- The lifecycle emitted a generic replacement event but did not independently
  record renewed, renewal failed, issuer changed, SAN changed, wildcard changed
  or renewal-band transitions.
- Replacement verification could run on the first observation of a new
  certificate. It did not require publishable live-serving evidence for each
  necessary signal or a later CyberMeters re-observation.
- `openOrReopenCertificateCase` already used `createManagedCase` and
  `canTransitionCase`, but repeated unchanged monitoring passes could append
  recurrence audit rows. Case closure had an existing system verifier but did not
  enforce the complete later-re-observation evidence gate at its boundary.
- Workspace lifecycle reads/writes were scoped by `workspace_id`; active
  workspace checks, purge ordering and the universal case substrate already
  existed.

### Design Decision

1. Keep migration 031 observations immutable and choose current state by latest
   `last_seen`, with deterministic tie-breakers. Preserve previous/current
   observation IDs in append-only replacement relationship events.
2. Derive leaf, issuer, SAN, expiry and wildcard changes independently from P1
   signal completeness. An incomplete signal neither suppresses a reliable
   sibling change nor invents its own change. Composite-key drift with no
   comparable changed signal remains evidence-insufficient.
3. Emit deterministic `replaced`, `renewed`, `renewal_failed`,
   `issuer_changed`, `san_changed`, `wildcard_changed` and
   `renewal_band_changed` events through the existing lifecycle event table.
4. Treat the first replacement scan as awaiting verification. Close only after
   CyberMeters later re-observes the same new leaf using publishable,
   monitoring-healthy live-TLS leaf, expiry and SAN evidence, with expected
   hostname coverage and expiry advancement.
5. Keep CT issuance separate from live serving. CT-only replacement history is
   observable lifecycle evidence, but cannot produce verification or close a
   case.
6. Route case creation through `createManagedCase`, and closure/reopen through
   `canTransitionCase`. Use deterministic event identities so unchanged
   re-evaluation cannot duplicate cases or history.
7. Prove the behaviour with pure deterministic fixtures, load-bearing mutations
   and a faithful three-scan `runScanEngine` trace using only fixture-backed
   network edges.

### Scope Boundaries

- No CAA, chain-validation, hostname-mismatch, weak-algorithm or
  expired-intermediate expansion (P4).
- No snapshot, API, report or PDF parity (P5).
- No new probe, CT lookup, table, migration or parallel certificate/case system.
- No production deploy or migration application.
- No domain, DNS, TLS, CT fixture, certificate issuance/renewal or live
  acceptance action.
- No Item 10 work.

### Risks and Compatibility

- Historical lifecycle rows and event vocabulary remain readable. The older
  `replacement_detected` event type stays accepted for historical compatibility;
  new relationships use the more precise additive `replaced` event.
- Historical observations that predate per-signal completeness remain unknown
  for change/verification purposes; the code does not synthesize healthy or
  live-serving evidence.
- Current P2 production inputs are CT issuance projections, so real
  system-verified closure remains unavailable until an approved live-TLS source
  produces the required evidence. This is intentional fail-closed behaviour.
- The lifecycle query remains one bounded workspace read plus grouped in-memory
  correlation; no per-observation read loop or second authoritative store is
  introduced.

## After

### Summary

The canonical certificate lifecycle now records evidence-isolated renewal and
replacement transitions, preserves append-only relationship history, suppresses
duplicate event/case churn, and permits case closure only from a later
method-appropriate CyberMeters live re-observation.

### Files

- `.github/workflows/ci.yml`
- `docs/ITEM-9-P3-CERTIFICATE-RENEWAL-LIFECYCLE.md`
- `scripts/fixtures/item9-p3-certificate-renewal-lifecycle.json`
- `scripts/validate-certificate-lifecycle.js`
- `scripts/validate-item9-certificate-p3-engine-trace.js`
- `scripts/validate-item9-certificate-p3-mutations.js`
- `scripts/validate-item9-certificate-p3-renewal-lifecycle.js`
- `scripts/validate-m5b-certificate-verification.js`
- `workers/scan-api/src/engines/certificate-lifecycle.js`

### Schema and Migrations

No migration. The next numbered migration remains 102. Existing
`certificate_observations`, `certificate_lifecycle`,
`certificate_lifecycle_events`, `managed_cases` and `managed_case_events`
structures are reused. No migration was applied.

### Behavioural Changes

- Current lifecycle state follows the latest re-observation, not the certificate
  with the furthest expiry.
- Replacement requires a changed certificate identity plus at least one reliable
  independently changed signal.
- Renewal, failure, issuer, SAN, wildcard and band events are append-only and
  deterministic; replay does not duplicate them.
- A missing/incomplete issuer does not erase reliable SAN or expiry changes and
  does not invent an issuer change.
- CT-only observations may record issued-certificate replacement history but
  cannot elevate live-serving or verification state.
- The first replacement observation stays `awaiting_verification`. Only a later
  complete live-serving re-observation can verify the lifecycle and close the
  linked case through the canonical system transition.
- Failed/contradictory later evidence reopens the same canonical case; it does not
  rewrite replacement history or create a duplicate case.
- Soft-deleted workspaces are skipped; reads/writes remain workspace scoped and
  cross-tenant records remain unchanged.

### Tests and Regression

- Deterministic renewal/lifecycle fixture: 63 assertions.
- Load-bearing mutation proof: eight mutants, 16 assertions.
- Faithful three-scan `runScanEngine` trace: 46 assertions.
- Existing certificate lifecycle and M5.b verification validators were updated
  to express the per-signal evidence contract and remain required by CI.
- Worker syntax, focused certificate/managed-case/tenant/purge regressions,
  Wrangler dry run, diff checks and the full GitHub Actions gate are required
  before review handoff.

### PR and Merge

PR pending. Codex must not merge it. Any reviewed-head change requires a new
Claude pre-merge review.

### Deployment IDs

Not deployed — founder-gated.

### Production Proof

Engineering-only proof: the faithful trace executes the real `runScanEngine`
three times, uses the production certificate observation/lifecycle callers,
records one replacement relationship and independent changed-signal events,
preserves the old observation, refuses CT-only verification, dedupes an unchanged
third scan, enforces the 19,000 ms scan and 9,000 ms SSL allocations with no more
than six SSL subrequests, excludes a soft-deleted workspace and preserves an
unrelated tenant.

Founder-controlled live renewal acceptance is deferred to Item 14 and is not
claimed.

### Rollback

Revert this focused PR. No schema rollback, destructive data operation or
historical rewrite is required. Append-only events produced by the new code
remain honest historical observations and can be ignored by the older reader.

### Residual Risks

- The current production P2 evidence ceiling is CT issuance, not a peer
  live-serving certificate. Therefore automatic verified closure intentionally
  cannot occur from current CT-only evidence.
- Historical rows without P1 completeness cannot be reclassified without new
  evidence and stay unknown.
- Founder-controlled renewal/live acceptance remains deferred to Item 14.

### Confirmation Later Phases Were Not Started

Item 9 P4/P5, Item 10, deployment, migration, DNS/TLS/CT changes, certificate
issuance/renewal and live acceptance were not started.
