# CT-R1 — Certificate Transparency Provider Telemetry

## Goal

Measure the untreated crt.sh and CertSpotter provider-attempt baseline that will
calibrate CT-R2 and CT-R3. CT-R1 changes what CyberMeters knows, not what scans do.

## Exact Pre-Change Map

- `ct-provider-cache.js` owns the existing per-scan shared provider promises and
  the existing maximum of two physical attempts per provider.
- `ssl-scan.js` and `subdomains-scan.js` consume those promises. No provider is
  added, removed, reordered, retried differently, or given a different deadline.
- `subdomains-scan.js` owns the existing `ct_source_degraded` /
  `ct_sources_unavailable` incomplete evidence contract. `buildScanQuality()` is
  the canonical resolver that turns that existing state into partial quality.
- `scan-engine.js` finalizes the R2 report and D1 scan row before it writes
  best-effort `scan_module_telemetry`.
- Migration 078, `SCAN_CHILD_TABLES`, purge completeness, and the tenant resource
  matrix are the existing observability and scan-child governance substrate.

## Design Decision

The shared provider cache records bounded physical-attempt facts in memory. Its
existing callers register whether `ssl`, `subdomains`, or both consumed each
provider promise. After canonical scan quality exists, the cache projects the
attempts to their actual module consumers and marks impact only when the existing
subdomain CT failure caused the existing incomplete contract.

Rows are persisted per-row, best-effort, only after terminal R2+D1 finalization.
There is no awaited D1 write in module execution.

The frozen outcome vocabulary is:

`ok | timeout | http_error | parse_error | rate_limited | network_error`

Unknown failures fail closed to `network_error`; outcome is never null.

The hard bound is eight rows per scan: two providers × two consumers × the
existing two-attempt cap. It is enforced in memory, at persistence, and by a D1
trigger.

`cache_state` is always `miss` and `cache_age_s` is always null in CT-R1. No cache
read or write can affect a result.

## Analysis Surface

`scripts/analyze-ct-provider-telemetry.js` consumes the read-only query printed by:

```bash
node scripts/analyze-ct-provider-telemetry.js --print-sql
```

Pass the query's Wrangler `--json` output by file or stdin:

```bash
node scripts/analyze-ct-provider-telemetry.js --input ct-r1-seven-day.json
```

It computes the rolling seven-day completion rate, distinct completion-loss
attribution by provider and outcome, nearest-rank p50/p90/p99 physical-attempt
latency, and both-provider co-failure rate. Duplicated consumer rows are
deduplicated back to physical attempts for latency and co-failure analysis.

## Scope Boundaries

CT-R1 includes no failover, retry, timeout, provider ordering, result cache,
freshness ceiling, scoring, completeness, finding, evidence, or customer wording
change. CT-R2, CT-R3, Item 11, free scan, P4/P5 ASM, and email workers are not
started.

Migration 103 is designed and committed but must not be applied without a separate
founder gate. This PR authorizes no deployment.

## Risks and Compatibility

- Telemetry persistence failure is swallowed per row and cannot fail a scan.
- Tenancy is inherited through `scan_id`; purge deletes telemetry before scans.
- Existing module objects, report JSON, scan quality, scores, findings, provider
  calls, cache results, and public APIs retain their current semantics.
- A scan cancelled before terminal finalization cannot durably write CT telemetry;
  that preserves the observer-effect boundary and is a known CT-R1 measurement
  limitation.
