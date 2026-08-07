# CT-R2 PR-3 founder decision — structural first-success-wins

Date: **2026-08-07**

Status: **[FOUNDER DECISION] structural implementation authorised; quantitative
and completeness-policy gates remain binding**

Implementation base: `6699f88c396bdc6a5925d2c68f4f939b15091f25`

Canonical historical evidence:
[`CT-PARTIAL-ATTRIBUTION-2026-07-31.md`](./CT-PARTIAL-ATTRIBUTION-2026-07-31.md)

This record does not amend, restate, backfill or rewrite the canonical historical
attribution report. It records the founder's later decision over the newer evidence
window and names the resulting split gate.

## Decision amendment — the gate was split, not passed

**[FOUNDER DECISION]** The historical data gate was not met. The gate is split as
follows:

1. Structural resilience may proceed now without new numeric thresholds.
2. The 14-day gate remains binding for:
   - timeout or retry calibration;
   - overlap-rate claims;
   - provider preference based on measured latency or success;
   - any `partial` to `degraded` or `complete` regrade.

**[OBS] Founder-supplied read-only production measurement at the decision point:**
22 decision-eligible v2 rows, 5 dates, 3 domains, 0 complete scans, 0 crt.sh
successes and 0 measurable overlap. The v2 14-day point is no earlier than
`2026-08-17T13:24:56Z`.

These observations do not support a provider-latency preference, an overlap-rate
claim, a timeout change, a retry change or a scan-quality change. PR-3 therefore
keeps all existing numeric policy and quality semantics byte-stable.

## Structural ruling

**[FOUNDER DECISION]** CT-R2 PR-3 implements structural first-success-wins:

- the first successful provider result may release that consumer;
- a first failure cannot release the consumer while the sibling can still succeed;
- both physical provider requests continue independently within the existing bounds;
- consumer release cannot cancel shared physical work;
- a released customer result is immutable;
- terminal outcomes that arrive after release remain telemetry evidence and are
  explicitly excluded from that released customer result;
- provider degradation remains visible;
- one-provider evidence never represents two-provider completeness;
- when both provider successes are terminal before release, both source-specific
  results are retained.

No scan-quality regrade is authorised by this decision.

## D0 — crt.sh HTTP 404 ruling

**[OBS] Founder-supplied completed read-only production measurement:**

- last 7 days: HTTP 502 = 28 physical attempts, HTTP 404 = 5, timeout = 19,
  parse error = 4, network error = 3, HTTP 429 = 0, success = 0;
- all eight historical founder-cohort HTTP 404 attempts have
  `result_count = NULL`;
- the exact live request shape returned HTTP 502 for all three founder domains;
- the historical evidence therefore cannot establish HTTP 404 as a successful
  empty result.

**[FOUNDER DECISION]** HTTP 404 remains `unavailable`. It must not be converted to
successful empty `[]` merely to improve success metrics. A later change requires a
primary/provider contract or a controlled, reproducible response proving that the
exact request shape defines HTTP 404 as a successful empty measurement.

Successful HTTP 200 JSON `[]` remains a measured zero and is not unavailable.

## Scope boundary

Authorised in PR-3: CT orchestration, source-scoped customer evidence, terminal
telemetry linkage, tests, mutations and local validation.

Not authorised in PR-3: migrations, historical rewrites, production writes or
scans, threshold changes, retry changes, timeout changes, provider preference,
scan-quality regrading, Item 10, Item 11 or unrelated work.
