# Item 10 — Attack Surface Depth

Date: 27 July 2026

Canonical base: `3910dbb86c2a0e7ea7be612e8bd5584ff949f738`
(`origin/main`, Item 10 P1 merged through PR #326)

Status: P2 production integration implemented; CI/PR review pending. No merge,
deploy or live acceptance.

## Before

### Goal

Make the nine Attack Surface signals independently reliable, introduce an
unambiguous cross-scan asset lifecycle, and review the founder-flagged
`www.email.blackbullbarbers.co.uk` alert without disabling the alert pipeline.
Founder-controlled live acceptance remains deferred to Item 14.

### Exact Pre-Change Map

- `workers/scan-api/src/engines/scan-engine.js` runs the underlying discovery,
  DNS, HTTP, technology, exposure/admin, takeover, CVE, KEV and cloud-storage
  modules independently. Their result shapes are heterogeneous and there is no
  canonical per-signal state block.
- `subdomains-scan.js` exposes per-CT-provider errors and a separate bounded
  DNS-bruteforce result. A degraded CT pass can retain positive observations, but
  an empty degraded pass cannot support a negative conclusion.
- `dns-scan.js` distinguishes `resolution_assessed` from transport/SERVFAIL
  failure. An authoritative NOERROR/NXDOMAIN result can establish scoped DNS
  absence; a resolver failure cannot.
- `asset-intel.js` distinguishes reachable service, authoritative no-service,
  timed-out/unexecuted probes and server-error incompleteness. Admin-surface
  detection is a pure dependent fingerprint pass and already prevents
  unavailable evidence from becoming assessed healthy.
- `takeover-scan.js` distinguishes confirmed risks, unconfirmed candidates,
  lookup failures and completed no-candidate checks.
- `vuln-intel.js` does not preserve per-technology NVD outcomes:
  `lookupCvesForTechnology()` returns an empty array for a valid zero-result
  response and for every provider/network failure. Therefore a current zero-CVE
  result after at least one lookup is ambiguous and cannot be `not_observed`.
  KEV catalogue unavailability is already explicit.
- `cloud-storage-scan.js` uses only evidence-backed candidates, but its negative
  result still depends on the completeness of discovery, exposure and CNAME
  inputs.
- `database/migrations/004-asset-inventory.sql` defines
  `workspace_assets.status` as only `active|inactive`.
  `asset-inventory.js` currently changes `active` to `inactive` after one
  comparable, complete discovery scan once `last_seen` is two hours old. It then
  uses that same legacy field to emit `asset_reappeared`.
- `status='inactive'` is also used during workspace archival. It is not proof of
  removal and cannot be redefined.
- CT is an append-only issuance/history source. An old CT name is asset identity
  evidence, not proof of a currently live DNS or HTTP service, and its later
  omission is not proof of removal.

### Design Decision

#### Nine independent signal states

`attack-surface-signal-completeness-v1` owns exactly these keys:

1. `subdomain_discovery`
2. `dns_resolution`
3. `http_https_service`
4. `technology`
5. `exposure_admin_surface`
6. `takeover_candidate`
7. `cve`
8. `kev`
9. `cloud_storage`

Every key resolves independently to exactly one of:

| State | Meaning |
| --- | --- |
| `observed` | The module completed sufficiently to observe the signal. A positive observation remains visible even if another source or sibling is degraded. |
| `not_observed` | The relevant module completed successfully but did not observe the signal in this scan. This is the normal negative observation and is not removal. |
| `absent` | Complete evidence positively establishes scoped absence. P1 permits this only for authoritative DNS absence. |
| `unavailable` | The module could not obtain the evidence required for its signal contract. |
| `incomplete` | Some evidence was obtained, but it is insufficient for the signal contract. |
| `not_assessed` | The signal was intentionally not evaluated or had no eligible target. |

There is deliberately no aggregate healthy/pass state. A consumer must retain
all nine records. An incomplete signal cannot overwrite an observed sibling and
cannot support healthy wording.

#### Confirmed-removal policy

`asset-removal-confirmation-v1` is deterministic:

- eligible hostname assets are rechecked directly; the root-domain inventory row
  is never removal-eligible;
- a qualifying negative observation requires both active sources to complete:
  targeted `dns_resolution` must be `absent`, and targeted
  `http_https_service` must be `not_observed` or `absent`;
- `crt_sh`, `certspotter` and aggregate Certificate Transparency discovery are
  passive historical sources and never advance confirmed removal;
- one qualifying scan sets the lifecycle projection to `not_observed`;
- exactly three qualifying observations are required;
- qualifying observations must be from distinct scan IDs, at least 24 hours
  apart, with at least 48 hours between the first and third;
- elapsed time alone never advances the counter;
- an `observed` active source resets the qualifying sequence, preserves the
  asset identity and produces `reappeared` only when the durable lifecycle was
  `confirmed_removed`;
- `observation_unavailable`, `observation_incomplete` and `not_assessed` neither
  advance nor reset the qualifying observations;
- historical observation rows are append-only.

The constants and both-source requirement are mutation-pinned in P1.

#### Migration 102 proposal

The current schema cannot represent `not_observed`, `confirmed_removed` and
`observation_unavailable` without ambiguity. P2 therefore requires additive
`102-attack-surface-observation-lifecycle.sql` before the production writer.

Migration 102 does:

1. add explicit projection columns to `workspace_assets`:
   - `lifecycle_state`:
     `not_assessed|observed|not_observed|confirmed_removed`;
   - `last_observation_state`:
     `not_assessed|observed|not_observed|observation_unavailable|observation_incomplete`;
   - `lifecycle_policy_version`;
   - `confirmed_removed_at`;
   - `last_observation_scan_id`;
2. leave legacy `status` and every historical value unchanged;
3. create append-only `attack_surface_signal_observations`, one
   workspace/domain/scan/signal row with the canonical state in a real column;
4. create append-only `asset_lifecycle_observations`, one
   workspace/domain/asset/scan row with observation state, qualification flag,
   policy version and observed time in real columns;
5. use JSON only for bounded supporting provenance/source detail, never as a
   second lifecycle truth;
6. add workspace/time, scan and asset/time indexes, workspace FKs and uniqueness
   guards;
7. update the canonical workspace purge inventory/order and tenant-resource
   inventory;
8. backfill every existing asset to `not_assessed`, never infer new lifecycle
   meaning from `active` or `inactive`.

The migration rollback is application-code rollback. Additive rows/columns remain
readable and historical observations remain preserved.

#### Scoped alert-quality review

Verdict: `false_positive`.

Read-only production evidence:

- `scan_f70fa932-10db-46ad-ae77-bb27e007a647` (14 July) emitted
  `asset_no_longer_seen` while both CT providers failed:
  `crt.sh = fetch failed`, `CertSpotter = parse error`; the subdomain set was
  empty because evidence was unavailable, not because absence was established.
- `scan_c36f8a98-0c10-4676-9678-6fab08624d7e` (15 July) re-observed the hostname
  through crt.sh while CertSpotter still failed. It emitted
  `asset_reappeared` and sent a medium alert.
- The later HTTP evidence for the hostname was Cloudflare 530 with no reachable
  origin, no CNAME takeover candidate and no confirmed admin surface.

The alert's core reappearance claim was therefore unsupported. The alert pipeline
stays enabled. P2 makes reappearance depend on the new confirmed-removal
lifecycle instead of legacy `inactive`; it does not suppress an alert class.

The reviewed 14–15 July disappearance/reappearance record predates the ct_error
disappearance guard added on 19 July 2026 in commit `7b35330` / PR #182. That
specific mechanism is already closed and must not be treated as a currently-live
defect. The remaining live gap is that one otherwise-complete scan can still map
not-observed to legacy inactive / asset_no_longer_seen before confirmed-removal
evidence exists.

### Scope Boundaries

- P1 delivered this note, the pure signal resolver, the pure removal policy,
  deterministic fixtures and load-bearing mutations.
- P2 attaches the contract to production reports, adds the additive migration
  and lifecycle writer, preserves provider truth and rechecks known assets
  through the existing active DNS/SSRF-safe HTTP paths.
- P2 does not add case close/reopen depth, implement the alert-quality verdict,
  add customer-surface parity or perform live acceptance.
- No alert disablement, entitlement change, score change or renderer change.
- No new scanner breadth.
- No production write, deployment, DNS/HTTP fixture change or live acceptance.
- Item 14 owns founder-controlled live acceptance; Item 10 engineering proof does
  not claim it.

### Risks and Compatibility

- P2 must change CVE provider provenance before a queried zero can become
  `not_observed`.
- Known-host DNS/HTTP rechecks consume subrequests. P2 must batch/bound them
  inside the current Cloudflare budget and expose unassessed overflow rather than
  fake negatives.
- Existing APIs, report JSON and snapshots are contracts. New blocks are additive;
  old readers ignore them and old reports resolve to `not_assessed`.
- One hostname can be linked to more than one workspace/domain history. Every read
  and write remains workspace-scoped, soft-delete guarded and non-enumerating.
- Existing `asset_events` remain append-only. Incorrect historical events are not
  deleted; customer presentation may identify legacy producer versions.
- Root assets and workspace-archive `inactive` rows cannot enter confirmed removal.

## PR Sequence

### P1 — design, pure signal model and removal policy

- This design note.
- `attack-surface-signal-completeness-v1`.
- `asset-removal-confirmation-v1`.
- Deterministic state/threshold fixtures and source mutations.
- No runtime caller, schema, API, renderer or alert mutation.

### P2 — production signal integration, persistence and lifecycle

- Attach the nine-signal block to new scan reports.
- Preserve per-technology CVE provider outcomes.
- Add bounded known-host active DNS/HTTP rechecks.
- Add Migration 102 and append-only signal/lifecycle observations.
- Replace the legacy one-scan inactive/event mutation with the deterministic
  confirmed-removal projection.
- Emit `asset_no_longer_seen` and `asset_reappeared` only through the existing
  `asset_events` lifecycle/alert source at real threshold transitions.
- Prove one incomplete signal does not collapse siblings through a real
  multi-scan `runScanEngine` → persistence → lifecycle-event trace.

### P3 — managed-case close/reopen depth

- Founder-gated. Not started in P2.
- Case close/reopen behaviour must consume supported lifecycle evidence through
  the universal managed-case transition contract.

### P4 — alert-quality implementation

- Founder-gated. Not started in P2.
- The alert pipeline stays enabled; the scoped review verdict remains
  `false_positive`.

### P5 — customer-surface parity

- Founder-gated. Not started in P2.
- Additive API/inventory/snapshot/report/PDF/MSP parity and historical fallbacks.

## After — P2 Implementation Record

### Files Changed

- `attack-surface-lifecycle.js` owns bounded known-host loading and
  workspace-scoped signal/lifecycle persistence.
- `asset-intel.js` records independent targeted DNS and HTTP evidence while
  reusing the shared DNS cache and canonical SSRF-safe probe.
- `scan-engine.js` attaches the P1 nine-signal block, supplies known identities
  to exposure, and invokes lifecycle persistence after inventory persistence.
- `asset-inventory.js` no longer derives inactive/reappeared from one discovery
  scan; ordinary inventory/DNS-change behaviour remains.
- `vuln-intel.js` distinguishes completed zero-result NVD lookups from provider
  unavailability.
- `reserved-scan.js` admits known identities to its existing bounded exposure
  envelope and live subrequest accounting.
- Purge, tenant-resource inventory, CI and dedicated Item 10 P2 validators are
  extended additively.
- The standalone email Worker closure manifest/version stamp is refreshed
  because it bundles the shared `asset-intel.js`; its deployment remains
  `pending_founder_approval`.

### Schema and Migrations

Migration `102-attack-surface-observation-lifecycle.sql` is additive and has not
been applied to production. It adds the five declared projection columns and
the two declared append-only tables. `workspace_assets.status` remains a
separate legacy projection. Existing rows default to `not_assessed`; neither
legacy `active` nor `inactive` is reinterpreted.

Rollback is application-code rollback. The additive columns/tables remain in
place so recorded evidence is not destroyed. Purge order deletes both new
workspace-scoped tables before `workspace_assets`.

### Behavioural Changes

- Every new report carries all nine independent Attack Surface signals.
- Existing non-root hostname identities enter the existing exposure envelope
  before passive/new candidates, subject to its unchanged cap.
- Only active targeted DNS and HTTP outcomes can qualify removal. CT/passive
  discovery never appears in the qualifying-source list.
- The first qualifying negative remains `not_observed`; unavailable,
  incomplete and not-assessed observations are appended without advancing or
  resetting the sequence.
- A positive active observation resets progress. After confirmed removal it
  emits `asset_reappeared` with the same `workspace_assets.id`.
- Legacy inactive and `asset_no_longer_seen` are produced only when the
  deterministic threshold transitions to `confirmed_removed`.

### Tests and Regression

- Deterministic complete, degraded, provider-timeout and deadline fixtures.
- Six required production-source mutations.
- Direct lifecycle/persistence proof for threshold, CT exclusion, unavailable
  neutrality, reset/reappearance, idempotency, soft-delete, tenant isolation,
  purge order and bounded/no-per-asset reads.
- Real five-scan `runScanEngine` → R2 report → D1 inventory → lifecycle event
  trace.
- Existing P1, exposure honesty, reserved subrequest, shared CT,
  disappearance-history, timeline and purge/tenant validators remain required.

### PR and Merge

P2 PR pending. Merge is not authorised by this episode.

### Deployment IDs

None. P2 explicitly forbids deployment.

### Production Proof

None. DNS/TLS/CT fixtures and live acceptance are outside P2 and remain
founder-gated.

### Rollback

Revert the P2 application commit. Do not delete observation history or overload
legacy status during rollback.

### Residual Risks

- Migration 102 must be applied before any deployed P2 writer.
- The bounded 50-host envelope honestly records overflow as not assessed; it
  does not claim complete fleet-wide rechecking above the cap.
- Customer-surface lifecycle parity, case close/reopen depth and the scoped
  alert-quality implementation remain later founder-gated work.

### Confirmation Later Phases Were Not Started

P3 case close/reopen depth, P4 alert-quality implementation, P5
customer-surface parity, Item 11, deployment and Item 14 live acceptance were
not started.
