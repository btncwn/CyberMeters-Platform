# Item 10 — Attack Surface Depth

Date: 27 July 2026

Canonical base: `aa5ed1aea4c601fa9f6f3265b28636352c1c720b`
(`origin/main`, after Item 9 P5 and PR #325)

Status: P1 design and pure contract; no production caller, migration, deploy or live
acceptance

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
`observation_unavailable` without ambiguity. P2/P3 therefore require additive
`102-attack-surface-observation-lifecycle.sql` before the production writer.

Migration 102 will:

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
7. update the canonical workspace purge inventory/order and migration validators;
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
stays enabled. P3 will make reappearance depend on the new confirmed-removal
lifecycle instead of legacy `inactive`; it will not suppress an alert class.

### Scope Boundaries

- P1: this note, the pure signal resolver, the pure removal policy, deterministic
  fixtures and load-bearing mutations.
- No P1 production import or caller.
- No migration 102 file or schema mutation in P1.
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

### P2 — production signal integration and provider truth

- Attach the nine-signal block to new scan reports.
- Preserve per-technology CVE provider outcomes.
- Add bounded known-host active DNS/HTTP rechecks.
- Prove one incomplete signal does not collapse siblings through a real
  `runScanEngine` trace.

### P3 — migration 102 and lifecycle writer

- Apply the proposed additive schema in code only; production application remains
  founder-gated.
- Append observations and update projections transactionally/idempotently.
- Replace one-pass disappearance/reappearance mutations with the declared policy.
- Preserve legacy `status` semantics separately.

### P4 — alert/customer-surface parity

- Gate `asset_reappeared` on `confirmed_removed -> observed`.
- Keep the alert pipeline enabled and improve event copy/identity.
- Add additive API, inventory, immutable snapshot, Executive Report/PDF and MSP
  parity with historical-report fallbacks.

### P5 — engineering closure

- Full validators, tenant isolation, purge coverage, mutation gate, frontend
  coverage/build, Worker syntax, Wrangler dry-run and CI.
- No deploy and no Item 14 live acceptance.
