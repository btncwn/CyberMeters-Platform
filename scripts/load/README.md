# Load & stress scripts

Manual / nightly performance probes — **not run in CI** (they need a live target
or are long-running). Dependency-free (native `fetch` + node:perf), so no k6/
autocannon install required. Run them against a **staging** target, or `/health`
(safe) against production; never point a write/scan load run at production
without intent.

## Scripts

### `dmarc-xml-stress.js` — RUA aggregate-XML parse cost
Standalone (no server). Generates aggregate reports of growing size and times
`parseDmarcAggregateXml`.

```bash
node scripts/load/dmarc-xml-stress.js
```

**Observed (2026-07-12, local Node 24):**

| records | xml KB | parse ms | parsed rows |
|--------:|-------:|---------:|-------------|
| 10      | 4      | ~2       | 10          |
| 100     | 39     | ~2       | 100         |
| 1000    | 390    | ~10      | 1000        |
| 5000    | 1954   | ~45      | 5000        |
| 10000   | 3910   | ~1       | guarded     |

Findings: parsing is linear and cheap up to ~5000 records (~45 ms, well inside a
Worker's budget). Beyond that the parser **short-circuits on an input-size guard**
(the 10000-record case returns near-instantly without a full record array) — a
deliberate DoS guard against an oversized report. No action needed; re-check if
the guard threshold or parse cost shifts materially.

### `concurrent-requests.js` — concurrent HTTP load
Fires N concurrent workers at a target for a duration; reports throughput,
latency percentiles, and 429 (rate-limit) / error rates.

```bash
# read path (safe): confirm /health throughput + latency
TARGET=https://cybermeters-platform.ttrnn47.workers.dev/health \
  CONCURRENCY=50 DURATION_S=15 node scripts/load/concurrent-requests.js

# confirm the global rate limiter bites on an app path (expect 429s)
TARGET=https://<staging>/api/workspaces CONCURRENCY=50 DURATION_S=20 \
  node scripts/load/concurrent-requests.js
```

A 401 counts as "reached the app" (auth enforced) — useful for hitting a
protected path without a token to measure edge throughput. To drive an
authenticated or POST path, set `METHOD`, `PATH_BODY`, and `TOKEN`.

## What to watch
- **Scan burst:** the hourly per-workspace scan limit + global per-IP write limit
  (60/5min) should produce 429s under a scan-start flood — confirm they fire.
- **Slow DNS / provider timeouts:** scans call external DNS/HTTP with bounded
  timeouts; a load run of scan-starts against staging surfaces whether one slow
  target starves the Worker's subrequest budget.
- Record any new bottleneck or a shifted limit here so the next run has a baseline.
