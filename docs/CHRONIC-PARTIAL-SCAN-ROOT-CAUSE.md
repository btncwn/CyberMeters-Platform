# Chronic Partial Scan — Root Cause, Blast Radius and Fix

Investigation date: 21 July 2026. Read-only production evidence + source analysis.
No deploy, DNS, Stripe, legal, Brand IDN or production-data mutation occurred.

## 0. Verified release facts

- Current main SHA: `4f2ecfa` (clean working tree; one untracked docs backlog file, irrelevant to runtime).
- Deployed production Worker: `d1ad62b8-3d46-40f3-896a-a2d510176d25` = commit `532f391` = tag `v2026.07.21-4`.
- Runtime delta since deploy: **none** (only docs PRs #259/#260 landed after `532f391`).
- Latest applied migration: `098-related-changes.sql`. No migration in scope.
- Canonical anchor (re-verified live): **Turhan Workspace** `workspace_2aaf14fb-cf28-49d4-bde0-5eb645eda1a8` → domain_id `dom_db28b2e8-29c3-4e1b-b630-676fd347a7f0` (not deleted).
- Duplicate note: `blackbullbarbers.co.uk` has 5 domain rows across 5 workspaces (Turhan / Berbero's / Black Bull Barbers / BBB / deneme[deleted]) — all founder-controlled. Attribution is unambiguous per (workspace_id, domain_id); every evidence read here is filtered to the exact pair.

## 1. Verified scan timeline (dom_db28b2e8)

| Time (UTC) | scan_quality | score/rating | scan id |
|---|---|---|---|
| 2026-07-18 11:19 | **complete** | 87 / good | scan_ccc13a02 |
| 2026-07-18 17:00 | partial | 95 / excellent | scan_8900ef4e |
| 2026-07-19 18:00 | partial | 87 / good | scan_cfa91de7 |
| 2026-07-20 18:00 | partial | 95 / excellent | scan_0dae1945 |
| 2026-07-21 19:00 | partial | 95 / excellent | scan_ff98eb61 |

The last `complete` scan is genuinely 2026-07-18 11:19; the daily scheduled scans (≈18:00–19:00) have been `partial` since. Historically the domain has 26 complete scans, so completeness is achievable — the condition is intermittent, not permanent. Fleet aggregate (last 7 days): 22 complete / 19 partial; latest-per-domain (3 days): 1 complete, 2 partial — all **founder** domains (blackbullbarbers.co.uk + cybermeters.com). **No real customer domain is affected** (pre-public-beta).

## 2. The exact incomplete modules (per-module telemetry)

From `scan_module_telemetry` for `scan_ff98eb61` (representative partial):

| Module | outcome | duration | note |
|---|---|---|---|
| ssl | ok | **28 423 ms** | completed but slow (see §3) |
| subdomains | ok | **12 000 ms** | hits its 12 s crt.sh timeout **every scan** |
| headers | incomplete | 20 001 ms | hit a 20 s cap |
| technology_detection | error | 10 000 ms | hit a 10 s cap |
| subdomain_takeover | deadline_exceeded | — | never ran |
| asset_exposure | deadline_exceeded | — | never ran |
| cve_intelligence | deadline_exceeded | — | never ran |
| known_exploited_vulnerabilities | deadline_exceeded | — | never ran |
| email_security_intelligence | deadline_exceeded | — | never ran |
| cloud_storage_discovery | deadline_exceeded | — | never ran |
| dns / dns_bruteforce / email_security / whois_intelligence | ok | fast | — |

The **same seven** modules are `deadline_exceeded` when the earlier phase is slow; on the last **complete** scan (scan_ccc13a02) `ssl` took only **3 061 ms** and every module ran. So the set is stable and driven by one variable: **ssl latency**.

## 3. Root cause (per module)

- **Wall-clock budget (design):** `createScanDeadline` sets a **21 s** network budget (`scan-budget.js`, ~9 s reserved under Cloudflare's ~30 s cliff). Phase-1 modules (`dns`, `ssl`, `headers`, `email_security`, `subdomains`, `technology_detection`, `whois`, bruteforce) run in parallel via `Promise.allSettled` (waits for **all**); later modules are deadline-gated via `deadline.canRun(Nms)`.
- **The driver — `ssl`:** `runSslModule` (ssl-scan.js) ran its HTTPS **reachability probes** (2× ~10 s `safeFetch`) and its **Certificate-Transparency cert lookup** (`crt.sh` 8 s + `certspotter` 8 s fallback) **sequentially**. The module's wall-time was therefore the **sum** of both chains — up to ~16 s of CT lookups on top of reachability. On a slow-`crt.sh` day this reached the observed 28 s, exceeding the entire 21 s budget. Because Phase-1 waits for the slowest module, the whole phase was dragged to `ssl`'s duration, so every deadline-gated later module was skipped → `deadline_exceeded`.
- **The constant tax — `subdomains`:** queries `crt.sh` wildcard `%.<domain>` with a 12 s timeout. For a domain with a large certificate history (blackbullbarbers) it **maxes 12 s every scan** — 57 % of the budget, deterministically.
- **Common external factor:** both `ssl` and `subdomains` depend on **crt.sh** (Certificate Transparency), a notoriously slow/flaky external service. crt.sh latency is the environmental trigger.
- **The seven skipped modules:** REAL — they genuinely did not run. Marking the scan `partial` is **honest**, not a misclassification.

Classification (Phase C):
- `ssl` sequential CT lookup → **ORCHESTRATION/CODE DEFECT** (independent I/O serialised; a single module can exceed 100 % of the wall-clock budget). Deterministically reproducible.
- `subdomains` 12 s crt.sh → **ENVIRONMENTAL** (crt.sh slow for a large-history domain) with a design contribution (generous timeout on a non-core module).
- 6 `deadline_exceeded` modules → **REAL FAILURE** (no trustworthy result; correctly `partial`).

## 4. Customer-honesty assessment — no P0

The `scans` row carries a score (partials show 95/excellent), but the **customer-facing** authoritative posture is gated correctly: `getCurrentPosturePresentation` (current-posture.js) uses the latest `scan_quality='complete'` scan as authoritative, shows a partial only as `latest_provisional`, and returns `not_established` when no complete scan exists. So a customer **never** sees a partial "excellent" as their posture. **No false-healthy customer surface; no P0 customer-monitoring-integrity issue.**

## 5. Blast radius — what the complete-to-complete gate suppresses (code-proven)

Consumers of `loadTimelineComparisonContext` / the `scan_quality='complete'` floor that **early-return / do not run** on a partial current (or partial previous) scan:

- **SUPPRESSED (cross-scan change events):**
  - `posture-events.js` → `email_spf_changed`, **`email_spf_authorization_changed`**, `email_dmarc_policy_changed`, `email_dkim_changed`, `exposed_service_detected`, `exposed_service_resolved` (early-return at `!comparison.comparable`).
  - `cert-events.js` → certificate-lifecycle change events (sensitive-host, cert change) computed against the previous **comparable** scan.
  - `asset-inventory.js` → asset-timeline events (new/removed/reappeared, DNS changes).
  - `related-changes.js` → M6 B1 correlation (explicit `scan_quality='complete'` floor for both current and previous).
  - Downstream: the managed alerts that consume those `asset_events` occurrences.
- **STILL RUNS on partial scans:** the scan itself (`status='completed'`); every module that executed and its evidence; managed ASM case creation from current findings; certificate current-state observation; and current-state scoring (gated to show last-complete / `not_established`, i.e. honest, not suppressed).

This is the mechanism that blocked the SPF root-change and include-aware acceptance: the SPF snapshot itself is complete (the `email_security` module runs in ~180 ms and never depends on crt.sh), yet its cross-scan diff is suppressed because **unrelated** modules (asset_exposure, cve, kev, …) were starved of budget.

## 6. Fix decision

Two layers, per the now-canonical **Detection Depth Law** (CLAUDE.md, 21 Jul 2026): *"one incomplete module never silently kills a reliable signal's diff, and incomplete evidence never produces a false alert."*

### 6a. Shipped now — smallest defensible code fix (this PR)

`ssl-scan.js`: the Certificate-Transparency lookup is extracted into `resolveCertificateTransparency(domain)` and launched **concurrently** with the reachability probes (started at the top, awaited before the return). The reachability code is **byte-identical**; every `cert_*` field is preserved; failures stay best-effort (null). The module's wall-time becomes **max(reachability, CT)** instead of their sum, removing up to ~16 s of serial CT latency and reclaiming budget for the deadline-gated modules.

- Tests: `validate-ssl-concurrent-ct.js` (12 assertions) — proves the two chains overlap, wall-time is bounded by the slower chain (not the sum), every `cert_*` field is preserved, the certspotter fallback still fires only when crt.sh is empty, and CT failure never throws. **Mutation-verified:** reverting to a sequential CT lookup reddens the max-not-sum assertion.
- **Honesty:** this **improves reliability; it does not guarantee** complete scans. crt.sh can still be slow enough (and `subdomains` still spends a constant 12 s on crt.sh) that a scan goes partial. This PR does **not** claim "complete scanning restored."

### 6b. Canonical direction — per-signal evidence completeness (Detection Depth Law)

The definitive remedy for the SPF blocker (and every reliable signal) is **per-signal evidence completeness**: a change detector may compare when **its own** previous/current evidence is complete, even if unrelated modules are partial — with explicit per-signal completeness metadata, fail-honest customer wording, dedupe safety and regression proof. This is now a **canonical architectural rule**, not an open question. It is a bounded design program (not a single edit) and should be delivered as a focused follow-up PR, starting with the SPF signal (whose `email_security` evidence is already complete-independent of the slow modules). It must **not** weaken the global gate for signals whose own evidence is incomplete, and must never allow a comparison from untrustworthy evidence.

Options **2** (re-classify optional modules) is **not applicable** — the seven skipped modules are genuine security checks that did not run, so `partial` is correct.

## 7. Other affected domains (aggregate, redacted)

Last 3 days, latest-per-domain: 2 partial, 1 complete — all founder domains (blackbullbarbers.co.uk, cybermeters.com). No real-customer domain is chronically partial. There is **no customer-facing monitoring-degraded warning today**; a `monitoring_degraded` signal on N consecutive partial scans is a reasonable future addition but is **not implemented here** (no existing path covers it; it needs its own threshold + wording design and is out of this episode's scope).

## 8. SPF acceptance status

- SPF include-aware is **DEPLOYED** (`d1ad62b8` / v2026.07.21-4).
- Live acceptance (root-change + include-aware) **remains blocked** until either (a) the anchor domain reliably produces complete scans (this PR improves the odds but does not guarantee it), or (b) the per-signal SPF completeness path (§6b) ships. Recommended: pursue §6b for a deterministic unblock independent of crt.sh.

## 9. Deploy plan + rollback (for the shipped §6a fix)

- No deploy in this episode. When the founder authorises: deploy current main to the Worker; rollback = the prior live version (`d1ad62b8`). The change is additive and evidence-preserving; smoke = `/health` + a founder-domain scan confirming `ssl` duration dropped and cert fields are still populated.

## 9b. Deploy + live exit-gate (21 July 2026)

**Deploy facts:** current main `506f364` deployed to the Worker. New live Worker
`ecd03d0a-bbcd-42d9-95ad-bcf01e632028`; rollback `d1ad62b8` (v2026.07.21-4);
tag `v2026.07.21-5`; migration **none**. Runtime delta vs the deployed commit was
**exactly** PR #263 (`ssl-scan.js` only) — #259–#265 are otherwise docs-only.
Post-deploy `/health` = `ecd03d0a` (5/5 cache-busted after propagation); smoke:
`billing/subscription` 401, `workspaces` 401, `auth/login` 400, `billing/plans`
200 — no regression.

**Live external-call latency (read-only, measured post-deploy):** for
blackbullbarbers.co.uk — reachability probes ~0.09–0.25 s each (fast);
**crt.sh cert query TIMED OUT at ~8 s (HTTP 000 — crt.sh is currently down)**;
**crt.sh wildcard (subdomains) TIMED OUT at ~12 s (HTTP 000)**; certspotter fast
(~0.39 s, HTTP 200).

**Before/after SSL wall-time (from live latencies):**
- Before (sequential): reachability (~0.5 s) + crt.sh (8 s timeout) + certspotter
  (~0.4 s) → and on a bad day the observed **28 s**.
- After (concurrent): max(reachability ~0.5 s, CT chain [crt.sh 8 s → certspotter
  0.4 s] ≈ 8.4 s) ≈ **8.4 s**. SSL is no longer the multi-tens-of-seconds
  bottleneck — a material drop.

**Residual blockers (independent of SSL):**
1. **`subdomains` — constant ~12 s** on the crt.sh wildcard query (crt.sh is
   currently down, so it maxes its 12 s timeout). This is now the Phase-1 floor
   (57 % of the 21 s budget).
2. **`headers` — variable up to ~20 s** (multi-host `safeFetch`, 10 s each). When
   slow it independently blows the budget.

With the SSL fix, when only `subdomains` is the Phase-1 floor (12 s), ~9 s remain —
enough for the deadline-gated Phase-5 modules (which gate at 4 s / 6 s / 8 s), so
the scan **can** complete; but if `headers` is slow (up to 20 s) or crt.sh stays
down, the scan can still go `partial`. **Complete scanning is improved, not
guaranteed.**

**Live scan confirmation — PENDING.** The workspace scan runs **daily**
(next `2026-07-22T19:00`); it cannot be triggered autonomously without founder
authentication or mutating `scheduled_scans.next_run_at` (production data — not
done). The actual `complete`/`partial` outcome of a post-fix scan must be read
from either the next scheduled cron or a founder-triggered manual scan.

**Exit-gate answers (evidence-based):** (1) SSL wall-time materially dropped
(28 s → ~8.4 s, sum→max). (2)/(3)/(4) the six starved modules / headers /
`complete` result — **not yet observed** (no post-fix scan exists; pending).
(5) if still partial, the residual modules are `subdomains` (crt.sh wildcard) and
`headers` (latency). (6) **crt.sh latency is still sufficient to cause partial**
(it is down right now; `subdomains` still spends 12 s on it). (7) authoritative
posture stayed on the last complete scan (`current-posture.js`, unchanged).
(8) complete-to-complete event paths become eligible only on a `complete` scan —
still gated. (9) **SPF live acceptance is NOT yet unblocked.** (10) **per-signal
evidence completeness is still required** — it is the only path that unblocks the
SPF diff regardless of the unrelated `subdomains`/`headers`/crt.sh latency.

## 10. Hard-stop checks

No cross-tenant ambiguity (anchor filtered to one pair), no exploitation/corruption signal, no destructive migration, no comparison-from-incomplete-evidence introduced, deterministic reproduction exists for the shipped fix, current main carries no unrelated unreviewed runtime delta, and no scan was falsely marked healthy.
