# MSP scale ceilings (measured 21 Oct 2026)

What limits how fast CyberMeters assesses and re-checks a portfolio, measured
from configuration, code and production (read-only), and what one MSP with
50 domains in one workspace should expect. Numbers are re-measured, not copied,
when a limit changes.

## Limits

| Stage | Limit | Source |
|---|---|---|
| Core scan | 2 scans at once, platform-wide; one scan per queue invocation | `wrangler.toml` scan-dispatch consumer `max_concurrency = 2` |
| Core scan duration | created → finished p50 162 s, p95 629 s (16 completed scans, last 14 days) | D1 `scans` |
| Exposure and TLS checks | one job holds the slot per workspace at a time (other domains' jobs wait) | `exposure-jobs.js` claim: `NOT EXISTS` another job's live lease in the workspace |
| Exposure job cost | avg 276 s, max 598 s, avg 674 requests (cap 1,024 per job); 14 complete, 1 budget-exhausted, last 14 days | D1 `external_exposure_jobs` |
| Exposure hourly window | 4,096 requests per verified domain, growing to 25 domains (102,400 requests per hour per workspace) | `EXPOSURE_JOB_LIMITS` |
| TLS probe | 2 fixed container slots, platform-wide | `network-probe/wrangler.toml` |
| Lookalike DNS sweep | **40** candidates per workspace × **10** workspaces per hourly tick = 400/hour (was 10 × 5 = 50/hour); one DNS query and one row update per candidate | `brand-dns-enrichment.js` |
| Lookalike candidates | up to 44 per domain | `MAX_BRAND_CANDIDATES` |
| Lookalike live-website check | 8 candidates × 3 workspaces, once a day (04:00 UTC) = 24/day platform-wide | `brand-http-enrichment.js` |
| Worker | 10,000 subrequests per invocation | `scan-api/wrangler.toml` `[limits]` |

## One MSP, 50 domains, one workspace

| | First full assessment | Weekly re-check |
|---|---|---|
| Core scans | ~70 min (25 waves of 2 × ~162 s), if no other tenant is scanning | same |
| Exposure + TLS | ~4 h (50 × ~276 s, serial per workspace); the hourly window is not the limit (~34,000 of 102,400 requests) | same, fits easily in a week |
| Lookalike DNS (2,200 candidates) | ~55 h at 40/hour (was ~220 h at 10/hour, longer than the weekly window) | ~55 h, inside the 7-day window |
| Lookalike live-website | ceiling: 8 candidates per workspace per day; with ~10% of candidates live (~220) a full pass takes weeks | stated in the product copy, not raised here |

The platform-wide lookalike DNS capacity is about 67,000 checks a week, enough
for a weekly re-check of ~1,500 brand-monitored domains.

## Why the live-website check was not raised

It fetches third-party lookalike sites (8 s timeout, 64 KiB) inside one daily
cron invocation. Moving it to hourly changes outbound traffic to domains we do
not own and the founder acceptance step tied to the 04:00 tick
(`docs/FOUNDER-ACCEPTANCE-PACKAGE.md`), so it is a separate decision. Until
then the portfolio page states the ceiling plainly.

## Related fix

Before 21 Oct 2026 the hourly DNS sweep never re-checked a workspace whose
candidates had all been checked once (#778); every production candidate had
last been checked in July.
