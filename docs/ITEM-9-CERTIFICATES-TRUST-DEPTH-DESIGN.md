# Item 9 — Certificates & Trust Depth

Status: design baseline for P1

Baseline: `origin/main` at `5fe0ebef02478a4d9f13915da2a78cade6eed3a9`

Release boundary: engineering only; controlled live renewal is deferred to Item 14

## Goal

Extend the existing Certificates & Trust systems so every certificate signal has
independent evidence completeness, observation scope, provenance and Evidence-Grade
metadata. A failed or incomplete signal must not erase a reliable sibling signal, create
a false change, or present an unknown as absent or healthy.

The target signals are:

1. leaf certificate;
2. certificate chain;
3. subject alternative names (SANs);
4. issuer;
5. expiry;
6. Certificate Transparency (CT);
7. wildcard use;
8. parallel certificate set;
9. active service.

## Exact Pre-Change Map

### Scan orchestration and budget

- `workers/scan-api/src/engines/scan-engine.js`
  - creates one `createCertificateTransparencyCache(...)` instance per scan;
  - passes that same cache to `runSslModule(...)` and `runSubdomainsModule(...)`;
  - runs the default network modules concurrently under `runCappedModule(...)`;
  - derives `modules.certificate_intelligence` with a zero-I/O pure function;
  - writes the scan report before the certificate observation/lifecycle follow-up;
  - then calls `insertCertificateEvents(...)`,
    `upsertCertificateObservation(...)`, and
    `correlateCertificateLifecycle(...)`.
- `workers/scan-api/src/engines/scan-budget.js`
  - has a 19,000 ms executable scan budget and 5,000 ms finalisation reserve;
  - caps `ssl` at 9,000 ms and six estimated subrequests;
  - supplies the canonical deadline/deferred result and outbound accounting.
- `workers/scan-api/src/engines/ct-provider-cache.js`
  - owns crt.sh and CertSpotter provider isolation, bounded retry, provider timeout,
    in-flight dedupe, shared parsing and provider-health telemetry;
  - distinguishes a successful empty result from an unavailable provider.

### Certificate evidence derivation

- `workers/scan-api/src/engines/ssl-scan.js`
  - probes HTTPS/HTTP reachability with HEAD requests;
  - concurrently consumes the shared CT cache;
  - selects the furthest-future unexpired CT issuance covering the root domain;
  - projects that CT entry into `cert_issuer`, `cert_not_after`, SAN and wildcard
    fields;
  - does **not** parse the certificate actively served by TLS and does not collect a
    chain.
- `workers/scan-api/src/engines/cert-analysis.js`
  - normalises issuers, maps CA owners/vendors, derives crypto metadata when supplied,
    detects apparent self-signing, derives expiry bands and CA concentration;
  - does not perform network or trust-path validation.
- `workers/scan-api/src/engines/cert-intel.js`
  - correlates SSL, CT hostname and brute-force evidence;
  - emits expiry, sensitive-host, wildcard-DNS, shared-certificate and CT-health
    signals;
  - already carries `evidence_source: "certificate_transparency"` and
    `live_certificate_verified: false`;
  - has one module-wide `incomplete` flag for total CT blackout, but no independent
    completeness record for the nine Item 9 signals.
- `workers/scan-api/src/engines/cert-trust-l2.js`
  - computes read-time findings from current CT/report evidence plus
    `certificate_observations` history;
  - leaves chain validity, root trust and OCSP unknown;
  - currently infers expiry, self-signed, issuer/SAN/wildcard and multiple-unexpired-
    issuance observations from CT/history rather than a live served-certificate capture;
  - those historical/CT observations do not meet Item 9's
    `parallel_certificate_set` definition because they are not simultaneous endpoint
    observations.

### Persistence, lifecycle and managed cases

- Migration `031-certificate-intelligence-v2.sql`
  - provides workspace/domain-scoped `certificate_observations`;
  - preserves one row per surrogate certificate key
    (`issuer|subject|expiry|sorted SANs`);
  - stores parsed evidence in `evidence_json`.
- `workers/scan-api/src/engines/cert-events.js`
  - writes/refreshes `certificate_observations`;
  - emits CT-derived asset events for new certificate, issuer, SAN, expiry, sensitive
    hosts and growth;
  - does not persist per-signal completeness or a live-vs-CT identity relationship.
- Migration `085-certificate-lifecycle.sql`
  - provides one workspace/domain/primary-host lifecycle record;
  - references current and previous observation rows;
  - keeps ownership, renewal planning, verification, monitoring and linked case state;
  - provides append-only `certificate_lifecycle_events`.
- `workers/scan-api/src/engines/certificate-policy.js`
  - is the canonical source for renewal readiness bands and start-by policy.
- `workers/scan-api/src/engines/certificate-lifecycle.js`
  - selects the observation with the furthest-future expiry as the current certificate;
  - preserves the prior observation link when the surrogate identity changes;
  - separates customer-recorded replacement from product verification;
  - verifies only when a distinct observed identity has acceptable declared-host
    coverage and a later expiry;
  - creates/reopens `certificate_case` only through `createManagedCase(...)` and
    `canTransitionCase(...)`.
- Migrations `076-managed-cases.sql` and `082-universal-managed-cases.sql`
  - provide the existing workspace-scoped universal managed-case substrate and
    append-only case history.

### API, snapshot, reporting and UI

- `workers/scan-api/src/routes/attack-surface.js`
  - exposes workspace-scoped `/certificates` and `/certificates/timeline`;
  - folds latest R2 scan data with D1 certificate history;
  - computes L2 trust findings on read.
- `workers/scan-api/src/routes/certificates-lifecycle.js`
  - exposes the workspace-scoped lifecycle list, detail/history and action routes;
  - applies auth/RBAC and soft-delete gates;
  - is non-enumerating for foreign/nonexistent lifecycle records.
- `workers/scan-api/src/engines/report-snapshot.js`
  - is the only immutable canonical snapshot writer;
  - freezes eight-domain state, findings, remediation, verification support and
    Evidence-Grade summaries;
  - explicitly sets `live_certificate_verified: false` for Certificates & Trust;
  - has no certificate per-signal contract block today.
- `workers/scan-api/src/engines/pdf.js`
  - renders the canonical snapshot rather than re-deriving certificate truth.
- `frontend/src/pages/ws/CertificateLifecyclePage.jsx` and
  `frontend/src/lib/certificateLifecycleDisplay.js`
  - render backend-owned readiness, coverage, ownership and verification state;
  - explicitly distinguish customer-recorded renewal from CyberMeters verification.
- `workers/scan-api/src/engines/remediation-registry.js`
  - already owns canonical certificate remediation for expiry, HTTPS installation,
    self-signed certificates, CA concentration, CT incompleteness, anomalies, coverage,
    intelligence review and CAA.

### Existing validation

The current suite already guards:

- shared CT cache and provider failure isolation;
- CT-blackout evidence honesty;
- SSL/CT concurrency;
- scan deadline/finalisation;
- certificate renewal bands and lifecycle;
- certificate case verification honesty;
- Certificate & Trust L2 unknowns;
- canonical remediation and snapshot/report parity.

It does not yet prove nine independent certificate signal states or that CT evidence
cannot promote a live-serving signal.

## Design Decision

### 1. Reuse the canonical monitoring-state vocabulary

P1 introduces no second completeness state machine. Each certificate signal uses the
existing backend-owned values:

- `monitoring_healthy`;
- `monitoring_degraded`;
- `signal_unavailable`;
- `evidence_incomplete`.

The per-signal contract adds an orthogonal observation value:

- `present`;
- `absent`;
- `unknown`.

The resolver enforces:

- `absent` is publishable only when completeness is `monitoring_healthy`;
- `signal_unavailable` and `evidence_incomplete` always normalise the observation to
  `unknown` and the value to `null`;
- `monitoring_degraded` may preserve a positive observation from available evidence,
  but it may not claim absence or healthy coverage;
- a supposedly complete signal without value/provenance fails closed to
  `evidence_incomplete`;
- one signal is never derived from another signal's completeness state.

### 2. Make observation scope mandatory

Every signal declares one of these scopes:

- `live_tls`;
- `live_tls_endpoint_set`;
- `ct_issuance`;
- `dns_policy`;
- `historical_observation`;
- `live_http_service`;
- `unobserved`.

CT-derived SAN, issuer, expiry or wildcard evidence therefore describes an issued/logged
certificate only. It cannot populate:

- live leaf identity;
- live chain state;
- live hostname match;
- active-serving certificate identity;
- root trust, OCSP, revocation or private-key state;
- `parallel_certificate_set`.

`parallel_certificate_set` has one precise meaning: multiple simultaneously observed,
non-identical certificates for the same protected hostname. Every member must identify
its observation source, endpoint/context, certificate identity, observation time and
completeness. The set must be captured inside one bounded live observation window no
longer than the existing 9,000 ms SSL module cap. Historical rows and multiple CT
issuances cannot complete this signal. Multiplicity alone is not labelled a
misconfiguration, attack, compromise or malicious activity.

### 3. Keep external TLS validation separate from internal key assurance

The nine Item 9 signals are externally observable certificate/service signals. They do
not model or infer:

- private-key security;
- internal keystore health;
- a complete internal certificate inventory;
- absence of key compromise.

The model publishes this boundary explicitly as an unsupported
`internal_key_assurance` family. A live leaf, an unexpired leaf, a complete presented
chain or trust validation against one declared trust store cannot promote any internal
key-assurance value.

Revocation is also independent. A missing stapled-OCSP response or other revocation
evidence degrades only that future revocation signal. It cannot erase a reliable leaf,
SAN, issuer, expiry, wildcard, active-service or simultaneous-endpoint observation.

### 4. Carry the Evidence-Grade contract with every signal

Each resolved signal contains:

- `observable_ceiling`;
- `beta_target`;
- `minimum_publishable`;
- `degrade_behavior`;
- `required_corroboration`;
- `achieved_grade`;
- `publishable`;
- `source_type`;
- `corroboration_status`;
- provenance and authority citations;
- explicit limitations.

The initial contract is:

| Signal | Ceiling | Beta target | Minimum | Degrade behaviour | Required corroboration |
| --- | --- | --- | --- | --- | --- |
| leaf | L5 | L4 | L2 | show unknown; never substitute CT | independent source |
| chain | L5 | L4 | L3 | show unknown trust path | independent path |
| SAN | L5 | L4 | L2 | retain scoped positive evidence; never infer absence | independent source |
| issuer | L5 | L4 | L2 | retain scoped positive evidence; never infer trust | independent source |
| expiry | L5 | L4 | L2 | retain scoped date; never infer live deployment | independent source |
| CT | L5 | L2 | L1 | show degraded/unavailable provider state | independent path |
| wildcard | L5 | L4 | L2 | retain scoped positive evidence; never infer live use | independent source |
| parallel certificate set | L5 | L3 | L2 | show unknown unless simultaneous endpoint observations are complete | independent source |
| active service | L5 | L3 | L1 | show unknown when the live probe did not execute | repeated |

The contract is an acceptance target, not a claim that P1 or the current production
engine has achieved those grades.

### 5. Pin standards and product-policy boundaries

Standards baseline pinned for this design on **26 July 2026**:

- X.509 fields and path validation: RFC 5280 §§4.1, 4.1.2.4, 4.1.2.5,
  4.2.1.6 and 6.
- TLS certificate presentation and signature algorithms: RFC 8446
  §§4.2.3 and 4.4.2.
- Service identity and wildcard matching: RFC 9525 §§6.3 and 7.1. RFC 5280
  does not define wildcard matching semantics.
- OCSP: RFC 6960 (June 2013); no OCSP result is claimed without an actual response and its
  validation provenance.
- CAA: RFC 8659 (November 2019), which obsoletes RFC 6844. RFC 6844 is cited only
  as legacy context.
- CT: RFC 6962 (June 2013) defines CT v1. RFC 9162 (December 2021) is the current
  CT v2 specification and obsoletes RFC 6962. Both citations preserve protocol
  provenance; neither turns a logged issuance into live-serving evidence.
- CA/Browser Forum TLS Baseline Requirements **v2.2.8, dated 16 June 2026,
  accessed 26 July 2026**. This is a versioned public-trust issuance baseline, not
  a blanket CyberMeters “compliant” verdict.
- Parallel-certificate risk, renewal bands and anomaly severity are
  `product_policy`, not blanket RFC conformance claims.

Standard-provenance records distinguish `MUST`/`SHOULD` requirements, protocol
definitions and CyberMeters product policy.

### 6. P1 data shape

P1 is pure and side-effect free:

```text
deriveCertificateSignalCompleteness({
  evidenceBySignal,
  observedAt,
  engineVersion
})
  -> {
       model_version,
       signals: {
         <signal>: {
           completeness_state,
           complete,
           observation,
           value,
           observation_scope,
           achieved_grade,
           publishable,
           grade_contract,
           source_type,
           corroboration_status,
           provenance,
           authorities,
           reasons,
           limitations
         }
       },
       assurance_families: {
         external_tls_validation: { ... },
         internal_key_assurance: {
           supported: false,
           private_key_security: "unknown",
           internal_keystore_health: "unknown",
           internal_certificate_inventory: "unknown",
           absence_of_key_compromise: "unknown"
         }
       },
       summary
     }
```

A second pure adapter accepts the current scan modules plus canonical monitoring
state. It can safely expose CT-scoped SAN/issuer/expiry/wildcard evidence and direct
HTTP-service reachability, but it must return `unknown` for live leaf, chain and
`parallel_certificate_set` until those simultaneous endpoint inputs exist.

### 7. Later persistence and API additions

P1 makes no schema or response change. Subject to P1 review:

- P2 will add the resolved per-signal block to the scan report and persistence.
  If queryable D1 state is required, migration 102 will add JSON/provenance columns
  to the existing certificate tables rather than create a parallel certificate
  system.
- Certificate identity and replacement relationships remain append-only:
  an observation row may refresh last-seen evidence for the same identity, but it is
  never rewritten to mean a different certificate; lifecycle events record replacement
  direction.
- Existing API fields remain unchanged. P2/P5 add a `signal_completeness` object and
  provenance fields; old readers ignore them.
- The snapshot outer schema remains version 1. P5 adds an optional
  `protocol_evidence.certificates` subtree. Existing snapshot bytes are never rebuilt
  or rewritten; dual readers treat absence as historical unavailability.

## PR Sequence

### P1 — design + pure signal model

- this design note;
- pure definitions, normaliser and current-module adapter;
- deterministic complete/degraded/unavailable/isolation fixtures;
- load-bearing mutations;
- no production caller, `runScanEngine` trace, schema, API or renderer change.

### P2 — production integration and bounded persistence

- wire the P1 resolver into `ssl-scan.js`/certificate intelligence;
- reuse the shared CT cache and provider health;
- add live-TLS inputs only within the existing 9,000 ms / six-subrequest SSL cap;
- add complete/degraded/provider-timeout deadline fixtures;
- add the first mandatory real `runScanEngine`/e2e trace for the integrated capability;
- prove the 19,000 ms whole-scan envelope and sibling-module survival;
- persist per-signal evidence additively and tenant-scoped.

### P3 — renewal and replacement lifecycle

- canonical renewed/failed/replaced/issuer-changed/SAN-changed/wildcard events;
- explicit replacement relationships and dedupe;
- case close/reopen only through the universal machine;
- verification only from CyberMeters' later complete, method-appropriate
  re-observation.

### P4 — trust-policy depth

- CAA;
- live chain state and expired intermediate;
- hostname mismatch;
- weak algorithms;
- CT-only vs live-serving distinction;
- canonical remediation coverage and evidence-grade authority metadata.

### P5 — snapshot, API, report and PDF parity

- additive API/snapshot fields and dual readers;
- immutable historical-snapshot compatibility;
- customer wording and technical evidence appendix;
- PDF/API/UI parity without frontend verdict derivation;
- Item 14 controlled-renewal acceptance runbook.

## Scope Boundaries

P1 does not:

- issue, renew or purchase a certificate;
- change DNS, TLS or a CT fixture;
- add a network request;
- alter the 19,000 ms / 9,000 ms / six-subrequest budget;
- change D1/R2 persistence;
- change scoring, alerts, cases or verification;
- change an API, snapshot, report, PDF or frontend;
- deploy;
- start Item 10;
- touch PR #232 or governance documents;
- reactivate suspended automation.

## Risks and Compatibility

### CT record mistaken for live service state

Mitigation: mandatory `observation_scope` plus an invariant that CT inputs cannot fill
leaf, chain or active-serving identity.

### Incomplete sibling suppresses a reliable diff

Mitigation: the resolver normalises each signal independently and exposes no global
“all certificate evidence complete” switch for comparison logic.

### Provider fallback produces false absence

Mitigation: degraded evidence may preserve a positive observation but cannot publish
absence.

### Grade metadata overstates the evidence

Mitigation: achieved grade fails to L0 for unavailable/incomplete/unknown evidence,
cannot exceed the declared ceiling, and is not publishable below
`minimum_publishable`.

### API and snapshot breakage

Mitigation: P1 has no caller. Later additions are optional fields, the outer snapshot
schema stays compatible, and old immutable snapshots are not rebuilt.

### Scan-budget regression

Mitigation: P1 performs no I/O. P2 must prove complete, degraded and timeout traces
within the existing envelope before production integration is accepted.

## Acceptance and Release Boundary

Every production capability requires:

1. deterministic fixtures;
2. a mutation that reintroduces the defect and makes the suite red;
3. a faithful `runScanEngine` trace after production integration;
4. founder live acceptance.

This is a capability-level proof model, not four proofs per PR. P1 supplies proofs 1
and 2 for the pure model and must not fabricate proof 3 while no production caller
exists. P2 supplies the first real engine trace when it connects the capability to
production.

For Item 9, proof 4 is deliberately deferred to the controlled Item 14 session. CI
green, merge and code-only deployment are not live acceptance. Only a Worker whose
runtime artefact changed may later be deployed with founder approval; email-ingest is
not redeployed for symmetry. No Codex session may perform the controlled renewal
independently.
