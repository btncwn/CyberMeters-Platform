# Item 9 P5 — Certificate Customer-Surface Parity

Date: 26 July 2026
Canonical base: `3f22ef084626cec649263c4649d27b3520196264`

## Before

### Goal

Carry the P1–P4 certificate completeness, lifecycle and trust-policy contract to
the existing customer APIs, immutable canonical snapshot, Executive Report and
PDF without creating a second certificate truth source.

### Exact Pre-Change Map

- `workers/scan-api/src/engines/certificate-signal-completeness.js` owns the
  canonical fifteen-signal P1/P4 model, completeness state, evidence-grade
  contract, source type, provenance, corroboration and cited authorities.
- `workers/scan-api/src/engines/cert-intel.js` attaches that model to the
  production certificate-intelligence module. P2 persists the same object below
  `certificate_observations.evidence_json.signal_completeness`.
- `workers/scan-api/src/engines/certificate-lifecycle.js` and the append-only
  certificate observation/event records own temporal replacement, renewal and
  verification state. P3 uses the universal managed-case transition machine.
- `workers/scan-api/src/routes/attack-surface.js` served
  `/api/workspaces/:workspace_id/certificates`, but returned the older
  certificate/L2 shape and dropped the P1–P4 completeness model. Its latest-scan
  lookup also performed one scan query per protected domain.
- `workers/scan-api/src/routes/certificates-lifecycle.js` reused the canonical
  lifecycle service, but its customer response did not join the current and
  previous immutable observation evidence. It therefore could not present
  replacement and simultaneous-live-certificate context consistently.
- `workers/scan-api/src/engines/report-snapshot.js` was the sole immutable
  snapshot writer. It froze eight-domain/reporting facts, but no certificate
  signal or lifecycle presentation block.
- `workers/scan-api/src/routes/scans.js` served a verified snapshot verbatim and
  rendered completed reports from it. No certificate assurance projection was
  available to those API consumers.
- `workers/scan-api/src/engines/executive-report.js` and
  `workers/scan-api/src/engines/pdf.js` were pure snapshot readers, so neither
  could display P1–P4 certificate semantics until the canonical snapshot carried
  them.
- `frontend/src/pages/ws/CertificatesPage.jsx` contained presentation
  derivations that could label HTTPS plus in-date expiry as “CT evidence
  healthy”. That conflated CT, live service, expiry and trust.
- `frontend/src/pages/ws/CertificateLifecyclePage.jsx` rendered
  `replacement_detected_at` independently from the parallel-certificate signal,
  so no shared precedence wording existed.
- Existing persisted snapshots are checksum-protected R2 objects referenced by
  `scan_report_snapshots`. Readers never update those objects.

### Design Decision

Add one pure `certificate-customer-presentation-v1` adapter over the canonical
P1–P4 object. The adapter does not parse certificates, perform probes or derive
trust facts. It only maps canonical evidence to:

- the customer states `observed`, `not_observed`, `unknown`, `unavailable` and
  `incomplete`;
- customer explanations and the trust ceiling;
- evidence grade, source type, provenance, corroboration and cited authorities;
- one deterministic relationship presentation for temporal replacement versus
  a simultaneous live certificate set.

The snapshot writer freezes that adapter additively under
`certificate_assurance`. The snapshot schema version and outer contract remain
unchanged. A reader of a historical snapshot without the block returns a
notice-only `not_recorded` projection whose signals are `not_observed`; it does
not write, backfill or infer a favourable state.

The lifecycle API obtains current and previous observation evidence in the same
bounded, workspace-scoped JOIN as the lifecycle row. Snapshot finalization uses
one separately bounded workspace-and-domain-scoped JOIN because importing the
full lifecycle service into the scan-finalize graph would create an engine
dependency cycle. Both paths call the same pure presentation adapter.

Presentation precedence is:

1. temporal replacement remains the primary lifecycle fact;
2. a simultaneous live set remains a separate observation scope;
3. if the same identities support both, one
   `replacement_with_parallel_transition_context` explanation is shown;
4. otherwise both contexts are disclosed without claiming they are the same
   pair;
5. raw append-only identities and evidence remain unchanged.

### Standards and Evidence Meaning

The presentation preserves the authority objects emitted by P4:

- RFC 5280;
- RFC 8659 for CAA;
- RFC 6960 for OCSP;
- RFC 9162 for Certificate Transparency, with RFC 6962 retained only as
  explicitly obsolete legacy CT context where the provider evidence requires it;
- CA/Browser Forum TLS Baseline Requirements v2.2.8, dated 16 June 2026,
  accessed 26 July 2026.

Each authority retains its requirement type, so a protocol/profile requirement
is not relabelled as `product_policy`.

### Scope Boundaries

- Additive customer presentation only.
- No new certificate, trust, lifecycle, remediation or case system.
- No P1–P4 derivation is copied into a renderer.
- No new probe, CT lookup or subrequest.
- No snapshot rewrite or backfill.
- No migration.
- No deployment, DNS/TLS/CT fixture, issuance, renewal or live acceptance.
- No Item 10 or broad UI redesign.

### Risks and Compatibility

- Historical snapshots cannot contain evidence that was never frozen. The
  reader therefore discloses `not_recorded` instead of querying current
  certificate/lifecycle tables.
- Cloudflare Worker fetch still cannot guarantee peer-chain, stapled OCSP or a
  declared trust-store observation. Those signal states remain independently
  unknown, unavailable or incomplete.
- Snapshot size grows additively. Lifecycle reads are capped at 100 records and
  use one bounded JOIN.
- The standalone email Worker bundles the shared PDF/report import closure.
  P5 therefore changes that runtime artefact as a demonstrated shared-contract
  effect. Its closure-derived version/manifest must be stamped, while deployment
  remains separately founder-gated.
- Existing route fields remain unchanged; P5 fields are additive.
- The certificate inventory latest-scan read is changed from N+1 queries to one
  workspace-scoped window query. R2 report reads remain parallel and bounded by
  the workspace’s protected domains. Legacy scans with no
  `scans.workspace_id` remain readable only when the mandatory
  `workspace_domains` JOIN proves membership in the requested workspace;
  scans attributed to another workspace remain excluded.

## After

### Summary

All requested customer surfaces consume the same
`certificate-customer-presentation-v1` projection. CT issuance cannot promote a
live leaf; missing evidence cannot become a pass; legacy snapshots remain
immutable; replacement/parallel wording has one deterministic precedence; and
the evidence contract reaches JSON and PDF technical output without losing its
meaning.

### Schema and Migrations

No schema change and no migration. Migration `102` is not created or applied.

### Behavioural Changes

- Certificate inventory and lifecycle APIs expose additive
  `certificate_assurance`.
- New canonical snapshots freeze additive `certificate_assurance`, including
  bounded lifecycle presentation.
- Snapshot, completed report and Executive Report APIs expose identical frozen
  certificate semantics.
- Assessment and Executive PDFs show the same certificate summary, signal
  states, relationship explanation, trust ceiling and technical evidence
  metadata.
- The Certificates page displays backend-owned signal states and no longer
  labels CT/HTTPS/expiry evidence as healthy trust.
- The Lifecycle page renders the canonical relationship explanation instead of
  a standalone replacement label.
- The email Worker closure manifest records the real shared PDF/report artefact
  change; this is traceability, not a deployment or a symmetry-only release.

### Tests and Regression

- Deterministic parity and legacy snapshot fixtures.
- Six load-bearing source mutations:
  unknown-to-observed, CT-only-to-live, missing-to-observed,
  replacement/parallel contradiction, legacy synthesis and provenance loss.
- Real `runScanEngine` trace through D1 observation persistence, immutable R2
  snapshot integrity, certificate/snapshot/report APIs, Executive Report and
  PDF.
- Existing P1–P4, lifecycle, M5.c and M5.d regression validators.
- Frontend unit/coverage/build, Worker syntax, Wrangler dry-run, SAST and CI
  remain release gates.

### PR and Merge

Focused P5 PR only. Merge is founder-gated after Claude pre-merge review.

### Deployment IDs

Scan API and email Worker artefacts are not deployed — founder-gated. The email
artefact changed because it bundles the shared PDF/report closure.

### Production Proof

The engineering proof is deterministic and uses the real production scan
engine with injected network edges and in-memory D1/R2. Founder-controlled live
acceptance is not claimed and remains deferred to Item 14.

### Rollback

Revert the P5 commit. No database or persisted historical snapshot rollback is
required. Snapshots already created by the P5 writer remain valid schema-v1
objects; older readers ignore the additive field.

### Residual Risks

Cloudflare Worker fetch, peer-chain, live hostname validation, stapled OCSP and
declared trust-store evidence are not guaranteed for every live endpoint.
Unobservable facts remain `unknown`, `unavailable` or `incomplete`. Founder
controlled non-Worker TLS-probe feasibility/coverage remains on the Item 14
radar, with final confirmation in Item 18.

### Confirmation

Item 10, deployment, migration, DNS/TLS/CT fixture work, certificate issuance,
certificate renewal and live acceptance were not started.
