# CT-R2 PR-2A — Shadow Provider-Overlap Telemetry

Status: **implementation record — policy-independent; no customer-output or completeness-policy change**

Date: 2026-08-02

Implementation basis: `7673bc28760e47aee1b2f1ef68c3f60798b2352d`

## Scope and invariants

This change observes each provider's terminal value on the existing `subdomains`
consumer promise and freezes that observation at consumer release. It does not
alter the provider calls, retry/timeout policy,
provider order, production `PER_CAP`/`MERGE_CAP`, shared `seen`, customer-facing
`items`, `sources.*.count`, `incomplete`, `incomplete_reason`, scan quality,
scores, snapshots, reports, PDFs or frontend output.

The shadow collector has no return path into the production merge. Collector and
persistence exceptions are observational failures and cannot change scan
finalization. No raw hostname is persisted or logged.

## Attempt and comparison states

Provider attempt states are:

- `terminal_success`: the shared CT cache returned `available` with a parsed array,
  including a successful empty array;
- `terminal_failure`: the shared CT cache returned unavailable, rejected or produced
  no valid parsed array;
- `in_flight_at_consumer_release`: the provider call started, but either the
  scan-engine 12-second consumer cap or the subdomains 15-second inner cap released
  its consumer before that provider's terminal value was observed;
- `not_started`: consumer release occurred before that provider was started.

Consumer release is an explicit one-way latch. Providers already observed terminal
remain terminal; started non-terminal providers become
`in_flight_at_consumer_release`; never-started providers become `not_started`. The
normal all-terminal return freezes after both terminal observations and before
returning. Repeated release is idempotent, and late terminal values cannot mutate
the frozen snapshot later read by post-finalization persistence. Freeze is
observational only: it does not cancel provider work or feed the customer result.

The normal, fully settled subdomains path produces only `terminal_success` and
`terminal_failure`. `in_flight_at_consumer_release` is reachable only on the existing
consumer-release path. `not_started` is retained for the future schema vocabulary and
abnormal partial instrumentation; because the normal implementation starts both CT
calls together, it is not claimed as a normal production outcome. If the subdomains
consumer never starts, `snapshot()` returns no measurement and persistence returns
`not_attempted_empty`; no synthetic comparison row is created.

Comparison states are:

- `compared`: both providers succeeded and neither measurement was truncated;
- `compared_truncated`: both succeeded, but at least one retained set or
  normalization input was truncated. All four comparison counts then describe only
  the retained bounded sets;
- `censored_provider_failure`: at least one provider failed;
- `censored_in_flight`: at least one provider was still in flight at consumer release;
- `not_started`: at least one provider was not started.

Every overlap/difference field is `NULL` for a censored or not-started comparison.
A successful-empty provider instead contributes real zero counts.

## Count dictionary

The following fields exist independently for crt.sh and CertSpotter:

| Field | Meaning |
| --- | --- |
| `raw_record_count` | Length of the provider's parsed response array. It is not a hostname count. |
| `expanded_candidate_count` | Count of non-blank candidate occurrences after expanding crt.sh `name_value` lines plus `common_name`, or CertSpotter `dns_names`. |
| `normalization_input_count` | Candidate occurrences actually passed to `normalizeDiscoveredHostname` within the measurement bound. |
| `normalization_dropped_candidate_count` | `expanded_candidate_count - normalization_input_count`; candidates censored before normalization. |
| `normalization_truncated` | Whether `normalization_dropped_candidate_count > 0`. |
| `normalized_candidate_count` | Valid, in-domain candidate occurrences in the measured normalization prefix. Duplicates still count. |
| `unique_hostname_count` | Size of that provider's deduplicated shadow set before retained-set truncation, within the measured normalization prefix. |
| `retained_hostname_count` | Number of deduplicated hostnames admitted to bounded comparison. |
| `dropped_hostname_count` | `unique_hostname_count - retained_hostname_count`. |
| `truncated` | Whether `dropped_hostname_count > 0`. |

`intersection_count`, `crt_sh_only_count`, `certspotter_only_count` and
`union_count` are calculated only from the retained bounded sets. The schema enforces
their set arithmetic and forbids zero-filled comparisons when measurement is censored.

## Bounding and measurement language

- **MEASURED:** provider array length, expanded candidate occurrences, the first at
  most 4,096 normalization inputs, resulting occurrence/unique counts, the first at
  most 256 lexically retained unique hostnames per provider, and retained-set overlap.
- **MODELLED:** `CT_PROVIDER_OVERLAP_NORMALIZATION_LIMIT = 4096` and
  `CT_PROVIDER_OVERLAP_RETAINED_LIMIT = 256` are engineering safety bounds. They are
  not production discovery caps, provider limits, measured optima or policy
  thresholds. Their purpose is to bound new normalization work and comparison-set
  memory independently of production `PER_CAP`/`MERGE_CAP`.
- **INFERRED:** the uniqueness constraint implies at most one durable row per
  `(scan_id, module, source_set_version)`. This is a schema property, not an observed
  write-volume measurement.
- **UNKNOWN:** actual production cardinality, retention volume, D1 write rate and
  runtime/CPU overhead have not been measured by PR-2A. No forecast is asserted.

The row remains until its canonical parent scan is purged. PR-2A introduces no
independent retention policy or historical backfill.

## Persistence, tenancy and failure meaning

`ct_provider_overlap_telemetry` is append-only and attributed through its canonical
`scan_id` foreign key. It deliberately does not duplicate `workspace_id` as a second
tenant authority. An atomic D1 batch performs `INSERT OR IGNORE` and verifies the
single durable row, so at-least-once finalization remains idempotent.

The structured persistence outcomes are:

- `not_attempted_empty` when the module produced no measurement;
- `persisted` with `count: 1` when exactly one row is durable;
- `persistence_failed` with an `error_class` and `durability: unknown` otherwise.

Persistence reads only the frozen consumer-release snapshot; it never derives state
from mutable provider settlement at scan-finalization time. When D1 is unavailable,
a second D1 failure marker cannot be made durable. The honest
durability is therefore **UNKNOWN**, not a claimed persisted failure. The write occurs
only after terminal scan finalization and cannot affect terminal status or report
readiness.

The table is registered in scan-child purge ordering and the tenant resource/isolation
inventory. Foreign and nonexistent workspaces are indistinguishable at the canonical
scan join: both return no row. No customer API is added.

## Migration and rollback

Migration `104-ct-provider-overlap-telemetry.sql` is additive and is not applied by
this PR. Code rollback is the commit revert. If the migration is applied in a later,
separately approved release, the unused append-only table may safely remain; dropping
it would be a separate destructive migration and is not part of this change.
