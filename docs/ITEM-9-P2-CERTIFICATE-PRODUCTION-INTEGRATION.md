# Item 9 P2 — Certificate Per-Signal Production Integration

## Before

### Goal

Connect the Item 9 P1 per-signal certificate completeness model to the existing
production scan and persistence paths without adding probes, CT lookups, tables,
customer report surfaces or lifecycle policy.

### Exact Pre-Change Map

- `scan-engine.js` created one per-scan `ctCache` and passed that same instance to
  `runSslModule` and `runSubdomainsModule`. The SSL module retained its existing
  9,000 ms allocation and conservative six-subrequest cost inside the 19,000 ms
  executable scan budget.
- `ssl-scan.js` used the shared cache for crt.sh with CertSpotter fallback while
  independently probing HTTPS/HTTP. Certificate fields were a CT issuance
  projection; the Worker HTTP fetch surface did not expose a served leaf or chain.
- `signal-monitoring-state.js` already resolved provider-specific CT health from
  one cache health snapshot: both providers available was healthy, one available
  was degraded, both unavailable was unavailable.
- `cert-intel.js` correlated the SSL CT projection with subdomain CT inventory but
  did not call the P1 completeness adapter. It also collapsed an unexecuted
  tri-state HTTPS probe to `false`, which could create a `no_https` signal.
- `certificate-signal-completeness.js` contained the pure P1 adapter. It already
  refused to manufacture live leaf, chain or parallel-set evidence from CT or
  historical certificate data.
- `certificate_observations.evidence_json` (migration 031) was the existing
  additive certificate evidence container. Observation identity and all updates
  were already scoped by `workspace_id`, `domain_id` and `certificate_key`.
- `cert-events.js` discovered workspaces from `workspace_domains` without checking
  `workspaces.deleted_at`. The purge list already covered
  `certificate_observations`, and already ordered
  `certificate_lifecycle_events` before `certificate_lifecycle`.
- Canonical M5.c snapshots, certificate lifecycle/cases, trust-policy depth,
  customer APIs, reports and PDFs were separate downstream systems.

### Design Decision

1. Attach `deriveCertificateSignalCompletenessFromModules` inside the existing
   certificate-intelligence engine, using the scan engine's already-derived
   monitoring states and the same CT cache health snapshot.
2. Add collection-scope metadata to the existing SSL result. It explicitly says
   that peer leaf/chain and simultaneous endpoint certificate sets were not
   collected. This metadata performs no I/O.
3. Preserve CT-scoped positive SAN/issuer/expiry/wildcard observations when one
   provider remains available. Keep leaf, chain and
   `parallel_certificate_set` unknown until live TLS evidence exists.
4. Persist the model in the existing
   `certificate_observations.evidence_json.signal_completeness` field. No schema
   change or new authoritative store is required.
5. Filter certificate observation/event fan-out through active workspaces. Keep
   every observation read/write keyed by workspace and domain.
6. Add deterministic module fixtures, load-bearing mutations and the first
   faithful `runScanEngine` trace. Only external network edges are fixture-backed.

### Scope Boundaries

- No canonical snapshot, API, report or PDF parity work (P5).
- No renewal lifecycle, dedupe or case close/reopen work (P3).
- No CAA, chain validation, hostname mismatch, weak-algorithm or intermediate
  policy expansion (P4).
- No new table or migration.
- No production deploy, migration application, live domain/DNS/TLS/CT action,
  certificate issuance/renewal or founder live acceptance.
- No Item 10 work.

### Risks and Compatibility

- The raw scan report gains additive fields inside existing certificate module
  objects. Historical reports remain unchanged; readers receive no synthesized
  values for reports that lack the new fields.
- Existing legacy certificate fields remain available. An unexecuted HTTPS probe
  now stays `unknown` in certificate intelligence instead of becoming a false
  unavailable/critical result.
- Provider degradation is signal-scoped. A reliable active-service observation is
  retained when CT is unavailable, and a CT issuance observation cannot become a
  live leaf/service assertion.
- D1 evidence JSON grows, but does not add query fan-out or a second persistence
  path. The completeness model is derived once per scan before workspace fan-out.

## After

### Summary

The P1 model is connected to the real scan engine and existing certificate
observation persistence. SSL now declares its actual collection ceiling, the
shared CT cache remains the only CT provider path, and soft-deleted workspaces are
excluded from certificate observation/event writes.

### Files

- `.github/workflows/ci.yml`
- `docs/ITEM-9-P2-CERTIFICATE-PRODUCTION-INTEGRATION.md`
- `scripts/fixtures/item9-p2-certificate-deadlines.json`
- `scripts/validate-item9-certificate-p2-integration.js`
- `scripts/validate-item9-certificate-p2-mutations.js`
- `scripts/validate-item9-certificate-p2-engine-trace.js`
- `workers/scan-api/src/engines/ssl-scan.js`
- `workers/scan-api/src/engines/cert-intel.js`
- `workers/scan-api/src/engines/cert-events.js`
- `workers/scan-api/src/engines/scan-engine.js`

### Schema and Migrations

No migration. The next numbered migration remains 102. Per-signal evidence is
stored additively in migration 031's existing
`certificate_observations.evidence_json`; no migration was applied.

### Behavioural Changes

- Production certificate intelligence now carries
  `signal_completeness` for all nine P1 certificate signals.
- SSL declares that its current Worker surface collects active HTTP service and
  CT issuance projection, but not peer leaf, peer chain, trust-store validation or
  simultaneous endpoint certificate sets.
- CT provider failure affects CT-scoped signals only. Sibling active-service
  evidence remains independently usable.
- CT-only and historical multiplicity cannot raise leaf, chain,
  active-service or `parallel_certificate_set`.
- An unexecuted HTTPS probe no longer creates `no_https` or a critical certificate
  risk result.
- Certificate persistence excludes soft-deleted workspaces and remains
  workspace/domain/certificate-key scoped.
- Provider-unavailable evidence remains in the raw scan module and does not create
  an identity-less pseudo-certificate observation or churn event.

### Tests and Regression

- Deterministic complete/degraded/provider-timeout integration: 52 assertions.
- Load-bearing mutation proof: eight mutants, 16 assertions.
- Faithful `runScanEngine` trace: 41 assertions.
- Existing P1, CT cache/provider, scan-budget, purge, tenant and full CI gates are
  required before handoff.

### PR and Merge

PR pending. This PR must not be merged by Codex; reviewed head changes require a
fresh Claude pre-merge review.

### Deployment IDs

Not deployed — founder-gated.

### Production Proof

Engineering-only behavioural proof: the faithful trace executes the real
`runScanEngine`, writes the additive raw R2 module evidence, persists independent
workspace rows in D1, excludes a soft-deleted workspace, preserves an unrelated
tenant's byte-identical row and records the 9,000 ms SSL allocation with no more
than six observed SSL subrequests.

The fourth proof, founder-controlled live acceptance, is deferred to Item 14 and
is not claimed here.

### Rollback

Revert this focused PR. No schema rollback, data rewrite or backfill is required.
Historical observations remain valid; newly written additive JSON fields are
ignored by older code.

### Residual Risks

- The current Cloudflare Worker HTTP surface still cannot expose peer leaf/chain
  bytes or a declared trust-store validation result; those signals honestly remain
  incomplete.
- `parallel_certificate_set` remains incomplete until bounded simultaneous live
  endpoint certificate collection exists.
- Founder-controlled renewal/live acceptance remains deferred to Item 14.

### Confirmation Later Phases Were Not Started

Item 9 P3/P4/P5, Item 10, live renewal, DNS/TLS/CT changes, deployment and live
acceptance were not started.
