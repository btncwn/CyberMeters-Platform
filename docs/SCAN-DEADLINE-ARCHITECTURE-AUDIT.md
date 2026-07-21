# Scan Deadline — Origin & Architecture Audit

Read-only audit (Phase 0 deepening). No runtime change, no deploy. P1 detection-availability. Verdict at the end.

## Founder four-part gate
1. **Real customer harm:** since the 21s budget landed (14 Jul), **~47% of scans are `partial`** (24 complete / 21 partial / 1 null). Partial scans suppress complete-to-complete change events (SPF/DMARC/cert/etc.) and the deadline silently **starves high-value modules**: `known_exploited_vulnerabilities` skipped **7×**, `subdomain_takeover` **4×** (per `scan_module_telemetry`), plus **37 `deadline_exceeded`** module outcomes. The customer's most security-relevant checks are the ones dropped.
2. **Does CyberMeters catch it today:** for ~half of scans, downstream detection is silently unavailable and change events don't fire.
3. **Exact pipeline break:** `engines/scan-budget.js:108` — a **global WALL-CLOCK budget of 21_000 ms** with the comment *"~9s reserved under the ~30s cliff"*. `ssl` (avg 7.7s, **max 28.4s**) + `subdomains` (avg 8.1s) consume the budget → deadline-gated modules (KEV, takeover) are skipped → `partial` → the complete-only gate suppresses cross-scan change events.
4. **Smallest PR sequence** (§Phase G).

## Phase A — Git-forensic origin
- `SCAN_DEADLINE_DEFAULTS` object: commit `fd8c13d` "fix(scan): global wall-clock deadline + latched partial finalization" — **Turhan (founder), 2026-07-14 01:56**.
- `budgetMs: 21_000` value: commit `990df1b` "fix(scan): durable tri-state finalize + hard-bounded network phases" — **Turhan, 2026-07-14 02:26**.
- **Rationale, verbatim in code (scan-budget.js:108):** `// network phases stop here — ~9s reserved under the ~30s cliff`. So the 21s wall-clock cap was derived to stay **~9s under an assumed ~30-second cliff**, reserving time for persistence/finalisation.
- Lineage: `ffa385e` (capacity config) → `b533601` (reserved-mode 50-class budget, gated) → `fd8c13d` (global wall-clock deadline) → `990df1b` (21s + tri-state finalize) → `73f23d5` (per-module telemetry) → `#263 e9e169a` (concurrent CT in ssl — merged, **NOT deployed**).
- **The "~30s cliff" is a WALL-CLOCK assumption.** The audit's core question is whether that assumption holds.

## Phase B — Current Cloudflare reality (verified)
**Official docs (verified via WebSearch, Mar-2025 platform change):** on **Workers Paid**, **there is NO wall-clock duration limit** — waiting on `fetch()`/DB/subrequests does **not** count toward CPU time. **CPU time** default is **30 s**, configurable up to **5 minutes (300,000 ms)** on Paid. Sources: [5-min CPU changelog](https://developers.cloudflare.com/changelog/post/2025-03-25-higher-cpu-limits/), [Workers limits](https://developers.cloudflare.com/workers/platform/limits/).

**This Worker (`wrangler.toml`, verified):**
- Invoked by **both HTTP** (`api.cybermeters.com` custom domain) **and CRON** (`crons = ["0 * * * *"]`, hourly) — the daily scheduled scans are cron-triggered (no client connection).
- **No `[limits]` / `cpu_ms` block** → uses the default (30 s CPU). `compatibility_date = "2026-06-18"`.
- The 21s budget is **WALL-CLOCK** (`now() - startedAtMs`), NOT CPU.

**The seven concerns kept separate:**
| Constraint | Reality for this Worker |
|-----------|--------------------------|
| Wall-clock duration | **No limit (Paid)** — the 21s cap is self-imposed, not platform-required |
| CPU time | 30 s default (configurable → 300 s); scan is **I/O-bound**, uses little CPU |
| Subrequests | Paid = 1000/invocation (generous) |
| Simultaneous outbound connections | **6** — the real concurrency ceiling for parallelisation |
| Per-fetch timeout | must remain bounded per module (the real protection) |
| Invocation lifetime | cron + HTTP; no client-timeout issue for cron |
| Cron limits | generous CPU; wall-clock is not the cron constraint |

**⚠️ Plan confirmation:** the "no wall-clock limit" holds for **Paid**. All evidence (custom domain, hourly cron, D1/R2 at production scale, CPU-configurability context) strongly indicates Paid, but the founder should confirm the plan in the Cloudflare dashboard before removal ships. If Free, the analysis changes (Free has stricter limits).

## Phase C — Quantified damage (telemetry, read-only)
- Scan quality since 14 Jul: **24 complete / 21 partial / 1 null (~47% partial)**.
- `scan_module_telemetry` outcomes since 18 Jul: `ok`=397, **`deadline_exceeded`=37**, `incomplete`=12, `error`=2.
- The starved modules are **high-value security checks**, not cosmetic ones.

## Phase E — Module time-entitlement matrix (32 runs each, since 18 Jul)
| Module | avg ms | max ms | not-ok | Class | Note |
|--------|-------:|-------:|-------:|-------|------|
| **ssl** | 7716 | **28423** | 0 | critical | tent-pole; #263 (concurrent CT, not yet deployed) should cut the max sharply |
| subdomains | 8151 | 12000 | 0 | critical | second-slowest; parallelisable |
| headers | 2147 | 20001 | 2 | important | occasional 20s hang → per-fetch timeout needed |
| technology_detection | 789 | 10000 | 2 | optional | |
| whois_intelligence | 579 | 3434 | 0 | optional | |
| dns_bruteforce | 300 | 2195 | 0 | important | |
| email_security | 136 | 1001 | 0 | **critical** | fast + reliable — its SPF/DMARC diff must NEVER be poisoned by a slow ssl |
| dns | 140 | 791 | 0 | critical | fast |
| **subdomain_takeover** | — | — | **4 starved** | critical | never runs when budget exhausted |
| **known_exploited_vulnerabilities** | — | — | **7 starved** | critical | most-starved; highest-value miss |

Goal: *give every module the time it legitimately needs without letting one broken provider hold the whole scan hostage.*

## Phase D/F — Architecture options & recommendation
- **Option 1 (remove global wall-clock deadline):** viable — the platform does not require it (Paid, no wall-clock limit; scan is I/O-bound so CPU 30s default is nowhere near hit). **Requires** bounded per-module/per-fetch timeouts (mostly present) + the 6-connection concurrency respected + reliable finalisation.
- **Option 2 (raise the number):** rejected as a standalone — changing `21_000` to `60_000` is still an arbitrary wall-clock cap guarding a non-existent cliff.
- **Option 3 (per-module budgets):** yes — each module gets a justified timeout from its p95 (ssl/subdomains generous; optional modules tighter).
- **Option 4 (Queue/Workflow/DO fan-out):** **not needed before public beta** — over-engineering; the scan fits one invocation comfortably once the false wall-clock cap is removed.
- **Option 5 (hybrid) — RECOMMENDED:** generous invocation ceiling (no artificial 21s wall-clock cap) + **strict per-module timeouts** + **concurrency** (respect 6 connections; #263 pattern) + **cached/reused external intelligence** (share CT results across ssl/subdomains) + **per-signal evidence completeness** (a reliable email/SPF signal's diff is never suppressed by a slow KEV) + **final aggregation with reserved finalisation time** + **monitoring-degraded alert** for chronic partial.

## Phase G — Fix policy (audit-first; NO deploy this episode)
Smallest safe PR sequence (each: timing fixtures + timeout mutations + full regression + cost/abuse analysis; **no deploy without explicit authorisation**):
- **PR1 — retire the false global wall-clock cap.** After confirming Paid: remove (or raise far above any real scan, e.g. treat as a safety net not a budget) the 21s wall-clock budget; rely on bounded **per-module** timeouts + a small **reserved finalisation** window. Keep the `deadline_exceeded` telemetry.
- **PR2 — per-signal evidence completeness.** A module's incompleteness poisons only its own signal, not the whole scan's `scan_quality`, and never the diff of a signal that DID complete (unblocks SPF/DMARC/email change events even if KEV was slow). This is the true chronic-partial remedy.
- **PR3 — concurrency + shared CT + per-fetch timeouts.** Extend #263: parallelise independent I/O within the 6-connection limit; share CT lookups across ssl/subdomains; a hard per-fetch timeout on headers (the 20s hang).
- **Cost/abuse safeguards:** per-module timeouts + subrequest ceiling (1000) + the 6-connection limit already bound worst-case; a denial-of-wallet cap belongs at the per-module/per-fetch level, not a global wall-clock budget.

If removal turned out to need a broader orchestration redesign → **STOP, architecture-decision-required.** It does **not** — one invocation suffices.

## Required adversarial fixtures (for the fix PRs)
one provider hangs · crt.sh times out · headers never responds · all fast modules complete · a slow optional module does NOT suppress an unrelated complete signal · two modules compete for connection slots · subrequest limit approached · client disconnect (HTTP) · cron invocation · persistence near invocation end · module throws after partial evidence · fallback source succeeds · all providers fail honestly · scan at 30/60/90/120s · no runaway invocation or duplicate persistence.

## Hard questions — answered
1. **21s under Free/legacy?** Introduced 14 Jul by the founder against an assumed **~30s wall-clock cliff** (code comment), not a plan-specific fact.
2. **Does Cloudflare require it?** **No** — Paid has no wall-clock limit; scan is I/O-bound.
3. **Real upper limits today?** No wall-clock limit (Paid); CPU 30s default→300s configurable; 1000 subrequests; 6 simultaneous connections. (Confirm Paid.)
4. **Detection suppressed?** ~47% partial; KEV starved 7×, takeover 4×; 37 deadline_exceeded.
5. **Safely removable now?** **Yes**, contingent on (a) confirming Paid and (b) bounded per-module timeouts + reserved finalisation.
6. **If not removed?** Per-module budgets (Option 3) + per-signal completeness.
7. **One invocation?** Yes — sufficient; no Queue/Workflow needed pre-beta.
8. **Which modules need more time?** ssl, subdomains (and #263 cuts ssl).
9. **Which must never block others?** email_security/dns/SPF (fast, critical) must never be poisoned by ssl/KEV.
10. **Smallest permanent fix?** PR1 (retire cap) + PR2 (per-signal completeness) + PR3 (concurrency/shared-CT/per-fetch timeout).

## Stale-doc note
The `scan-budget.js:108` comment ("~30s cliff") and any doc implying a universal 30-second Worker wall-clock limit are **incorrect for Workers Paid** and should be corrected when PR1 lands. Public marketing copy unchanged.

---
`21-SECOND DEADLINE OBSOLETE / SAFE REMOVAL DESIGN READY` — contingent on founder confirming the Cloudflare plan is **Paid** (invocation type and platform limits independently verified; plan strongly indicated but not dashboard-confirmed here).
