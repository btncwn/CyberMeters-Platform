# CT-PARTIAL-ATTRIBUTION — read-only production investigation — **v2 (rescoped) — CANONICAL CT-R2 EVIDENCE BASE**

**Adoption (2026-07-31, founder decision):** this v2 report is the canonical
evidence base for CT-R2 design. It was reviewed in two rounds: v1's Part 2
exceeded the authorised tenant intersection (caught in review; deviation
recorded below and quarantined), and v2 was independently re-verified by the
reviewer against the exact scoped intersection with pre-registered predictions
(82 consumer rows by outcome, 41 physical groups, 0 non-pair groups — exact
match, `rows_written = 0`). Committed verbatim from the investigation output;
only this adoption block and the title status were added. This is a
**point-in-time measurement** (window 2026-06-21 → 2026-07-31); it makes no
claim about later windows. No CT-R2 policy or threshold is decided in this
document.

Date: 2026-07-31 · Read-only owner: Claude · Repo untouched (no branch/commit/PR/deploy); source read only via `git show origin/main:` at **exact remote main SHA `6e4cbab17116c46596499fc37ed8b6838495e853`**. Codex's A2+A3 worktree untouched. Production access SELECT-only; **every query's meta returned `rows_written = 0`** (per-query meta in Appendix).

---

## Scope-deviation record (v1 → v2 corrective)

The authorised cohort is the **exact intersection**:

```sql
s.workspace_id = 'workspace_2aaf14fb-cf28-49d4-bde0-5eb645eda1a8'
AND s.domain IN ('cybermeters.com','sheshire.co.uk','blackbullbarbers.co.uk')
```

Deviations in the v1 pass — all read-only, which lowers risk but does **not** make their outputs usable as authorised-cohort results:

1. **`scan_0b2c419b…` (workspace_df864b4f…)** entered the v1 Part 2 cohort through domain-only filters (v1 Q8/Q12/Q14) and one dotted-row pull. Declared in v1 itself; **excluded from the final cohort here**.
2. **v1 Q7** joined the whole `ct_provider_telemetry` table without the workspace predicate (in the returned data every row happened to belong to a founder domain, but the query was not scoped — quarantined).
3. **v1 Q13** counted orphans/totals **globally** across all tenants — quarantined.
4. The initial cohort-scoping query grouped scan counts of the three founder domains **across all workspaces** (used only to select the cohort; its per-other-workspace aggregates are quarantined).
5. Non-tenant reads (sqlite_master schema, `wrangler deployments list`) — account/metadata level, listed for completeness.

Quarantined results are retained below only as *out-of-authorised-cohort observations* and are excluded from every cohort number. All Part 2 numbers were **re-derived from newly executed, exactly-scoped queries (P2-Q1…P2-Q8)**. Part 1 was already exactly cohort-scoped in v1 and is **not re-derived**.

---

## 0. Source contract (origin/main 6e4cbab) — unchanged after rescope

| Fact | Where |
|---|---|
| ONE `ctCache` per scan, passed to both `runSslModule` and `runSubdomainsModule` (Phase-1 `Promise.allSettled`) | `workers/scan-api/src/engines/scan-engine.js` |
| One in-flight promise per `domain\0provider`; a second consumer awaits the same promise | `ct-provider-cache.js` `get()` |
| Policies: crt.sh 6 000 ms × 2 attempts + 150 ms backoff; CertSpotter 4 000 ms × 2 + 100 ms | `CT_PROVIDER_POLICIES` |
| `ssl` consumes crt.sh first, sequentially; CertSpotter only as fallback | `ssl-scan.js resolveCertificateTransparency` |
| `subdomains` launches `ct_wait_crt_sh` + `ct_wait_certspotter` in parallel at module start | `subdomains-scan.js` |
| Module caps: ssl 9 000 ms, subdomains 12 000 ms, headers 1 200 ms; executable budget 19 000 ms | `scan-budget.js` |
| Sub-op rows: dotted pseudo-rows in `scan_module_telemetry`, bounded batch, non-fatal, **no failure marker** | `persistSubOperationTelemetry` |
| `ct_provider_telemetry` (mig 103, applied): terminal-only atomic batch; **each physical attempt fanned out once per consuming module** | `persistCtProviderTelemetry`, `telemetrySnapshot()` |
| `cache_state` bound as constant `'miss'` | `persistCtProviderTelemetry` |

Telemetry release: PRs #353/#354/#355 deployed **2026-07-31T02:06:42Z** (Worker version `9789f36d`, exact main `0b2a0737d6b9…`).

---

## Part 1 — historical partial attribution — **UNCHANGED (was correctly scoped in v1; not re-run)**

Cohort: 108 scans, 2026-06-21 → 2026-07-31.

| Month | complete | partial | failed | Denominator |
|---|---|---|---|---|
| 2026-06 | 7 | 3 | 0 | 10 |
| 2026-07 | 38 | 55 | 5 | 98 |
| Total | 45 | 58 | 5 | 108 |

- Partial share of terminal completed scans **58/103 = 56.3 %** (July 59 %).
- Module telemetry covers 77/108 scans (earliest covered scan 2026-07-14); **48/58 partials measured**, 10 partials' attribution **not obtainable**.
- Non-ok module ranking among the 48 (scans containing each): cve_intelligence 27 · email_security_intelligence 27 · known_exploited_vulnerabilities 27 · subdomains 24 (22 incomplete + 2 deadline) · asset_exposure 21 · cloud_storage_discovery 16 · ssl 15 (12 deadline + 3 incomplete) · dmarc_external_rua skipped 12 · subdomain_takeover 9 · headers 8 · technology_detection 3.
- CT pair: ssl-only 3 · subdomains-only 12 · **both 12** · neither 21. P(both | ssl non-ok) = 12/15 = 80 %; P(both | subdomains non-ok) = 12/24 = 50 %.
- Of the 21 "neither": 17 are phase-5-trio deadline scans whose Phase-1 wall was ≥ 9 000 ms in 17/17 (≥ 12 000 in 14/17; completes' median 8 100 ms); 4 show no ssl/subdomains involvement.
- 12/29 measured completes also had Phase-1 wall ≥ 9 s — slow Phase-1 is associated with, not sufficient for, partial.
- The 5 failed scans (22–23 Jul, blackbullbarbers) are the known unattributed failed-scan class; outside the CT window.

**Corrected involvement statement (per corrective §6):**

> CT-linked ssl/subdomains non-ok **evidence appeared in 27/48** measured partial scans. This is an **INVOLVEMENT ceiling, not a claim that CT-R2 would make all 27 complete** — other deficits co-occur in the same scans (the phase-5 trio appears in 10 of the 27). The ~92 % figure survives only as a **labelled hypothetical upper bound** (27 involved + 17 budget-starvation scans *if* their Phase-1 slowness is CT-caused, which the historical data cannot prove). At least 4/48 (8 %) are provably beyond any CT fix.

---

## Part 2 — provider-level attribution — **RE-DERIVED, exact authorised intersection only**

### 2.1 Instrumented counts (P2-Q1, P2-Q3)

| Metric | v2 (scoped) | v1 | Note |
|---|---|---|---|
| Scans with CT provider telemetry | **15** | 16 | scan_0b2c419b excluded (second workspace) |
| Consumer rows | **82** | 88 | |
| Physical attempts | **41** | 44 | grouping in §2.2 |
| Window | 2026-07-28T05:00:11Z → 2026-07-31T04:33:09Z | same | unchanged after rescope |
| Domains | 3 (bbb 30 rows · sheshire 28 · cybermeters 24) | | |
| Scan quality | **15/15 partial; zero `complete` cohort scans since 28 Jul** | 16/16 | conclusion unchanged after rescope |
| `completeness_impact=1` rows | **26** (all `subdomain_discovery`) | 28 | |
| Sub-op (dotted) instrumented scans | **4** (9 rows each, 36 total) | 5 | post-deploy cohort scans = 4; coverage **4/4** |

**No generalisation from these counts**: 15 scans / 4 days / 3 domains / few cron hours / one D1 region — a reproduced pattern, not independent samples.

### 2.2 Consumer-row → physical-attempt mapping (reproducible; P2-Q2)

- **Grouping key (exact):** `(scan_id, provider, started_at, completed_at, latency_ms, outcome, COALESCE(http_status,-1))`.
- **Merge condition:** two consumer rows count as ONE physical attempt **iff** all seven key fields are identical **and** the group's module set is exactly `{ssl, subdomains}` (each module once). Groups with 1 row, > 2 rows, or a repeated module are **left separate / reported unknown — never merged**.
- **Result:** 41 groups; `consumer_rows = 2` in **41/41**; module set `{ssl, subdomains}` in **41/41**; **ambiguous groups: 0**.
- Collapse risk (two genuinely distinct attempts identical in all seven fields) is structurally excluded here: a retry starts only after the prior attempt completes plus backoff, so `started_at` differs.

The executed SQL is Appendix P2-Q2; the check that classified groups is exactly: `consumer_rows != 2 OR sorted(modules) != ['ssl','subdomains'] → ambiguous`.

### 2.3 Provider outcomes — physical attempts, censored vs measured separated

| Provider | outcome | n | latency | censored? |
|---|---|---|---|---|
| certspotter | ok | **15/15** | **195–708 ms measured** | no |
| crt_sh | timeout | 8 | all exactly 6 000 ms | **censored** (policy cap) |
| crt_sh | network_error | 7 | 2 850 ×5, 3 126, 3 850 | **censored** (attempt-2 abort when the composite hit 9 000 ms) |
| crt_sh | http_error | 10 | 130–4 768 ms measured (404 ×3, 502 ×7) | no |
| crt_sh | parse_error | 1 | 938 ms measured (HTTP 200, non-JSON) | no |

**crt.sh: 0 successes in 26 physical attempts** (v1: 0/28; conclusion unchanged after rescope). Only defensible latency sentence: *failed crt.sh waits held the scan budget for at least the cap duration; no measured crt.sh success latency exists in this window.* No "N× slower" claim is possible.

9 000 ms anatomy — unchanged after rescope: 6 000 (attempt 1 timeout, censored) + 150 (backoff) + 2 850 (attempt 2 aborted when the ssl module's 9 000 ms race cap fired) = 9 000. A **cap fingerprint, not a provider latency**.

Start order: crt.sh and CertSpotter physical attempts begin the same millisecond (subdomains launches both in parallel at Phase-1 t0; ssl consumes crt.sh sequentially). Fallback: CertSpotter attempted and succeeded in **15/15** scans — as a parallel launch, not a triggered failover. Both unchanged after rescope.

### 2.4 Shared-wait hypothesis — SYSTEMATIC (code + scoped data)

- Code (§0): one cache promise per `domain\0provider`, both consumers await it.
- Scoped data: **41/41** physical attempts carry both module labels (P2-Q2); in **4/4** sub-op-instrumented cohort scans `ssl.ct_lookup` and `subdomains.ct_wait_crt_sh` have **identical start AND end stamps — overlap 100 %** (P2-Q4):

| scan | domain | dur (ms) | ssl.ct_lookup | subdomains.ct_wait_crt_sh | ssl module | subdomains module |
|---|---|---|---|---|---|---|
| 3a97a5f8 | sheshire | 9 000 | aborted | unavailable | deadline_exceeded | incomplete |
| 7bd83d64 | blackbull | 564 | ok | unavailable | ok | incomplete |
| 4f100e6d | cybermeters | 9 000 | aborted | unavailable | deadline_exceeded | incomplete |
| 7ba66331 | blackbull | 6 291 | ok | unavailable | ok | incomplete |

The brief's 02:42:17.484Z → 02:42:26.484Z identity (scan 4f100e6d) is **systematic**: two consumers observing ONE shared physical CT wait. They are one provider event, never two. (The fifth v1 row, scan_0b2c419b, showed the same pattern but is outside the authorised cohort and is not counted.)

### 2.5 Why failover alone is insufficient — two mechanisms, corrected wording

**Mechanism 1 — budget coupling (clean, scoped evidence).** ssl waits on crt.sh first, sequentially, up to its whole 9 s cap while CertSpotter's answer sat in the shared cache from ~0.4 s. In 2/4 instrumented cohort scans (3a97a5f8, 4f100e6d) this aborted the ssl module (`deadline_exceeded` → partial); the failed crt.sh sequence can hold up to 9 s of the 19 s executable budget (47 %).

**Mechanism 2 — completeness policy (two vocabularies, stated separately).** In `scan_7bd83d64`:

> Every tracked module **RAN to completion or was explicitly gate-skipped** (execution vocabulary: no deadline_exceeded, no error, no timeout — P2-Q5). The subdomains module's **EVIDENCE** was nevertheless marked **incomplete** (evidence vocabulary: CT source degraded — this scan's two `completeness_impact=1` rows name `subdomain_discovery`) because one CT source (crt.sh, HTTP 404 in 564 ms) failed while CertSpotter succeeded. The scan stayed **partial BY POLICY, not by execution failure.**

Honesty limit on this scan: `dmarc_external_rua` was `skipped` by an explicit launch gate whose reason is **not obtainable from D1** (`error_class` NULL — P2-Q7; reasons live only in R2 diagnostics), and no cohort `complete` scan carries any `dmarc_external_rua` row to test against (P2-Q8). So 7bd83d64 **proves the CT completeness loss is real and policy-graded** (the impact rows bind it), but it is **not a single-cause proof** that CT alone set the partial grade. Scan 3a97a5f8 (dmarc_external_rua `ok`, partial via ssl deadline + subdomains incomplete) carries mechanism 1 without that confound.

Either way the design conclusion stands: **a provider failover that leaves (a) the sequential ssl consumption order and (b) the one-source-failed→incomplete policy untouched cannot restore `complete`** — CertSpotter succeeded in 15/15 scans and all 15 are partial.

### 2.6 Persistence silence, phantoms, coverage — scoped (P2-Q3/Q4)

- Coverage: **15/15** cohort scans since 28 Jul have module rows (17 each incl. `scan_finalisation`) and CT rows (4–6, within the 8 bound); **4/4** post-deploy cohort scans have dotted rows → all classified **persisted(9)**; all pre-deploy cohort scans **not_attempted_empty**. **No `possible_persistence_failure` case observed** — the mechanism stays marker-less, so a future zero-row scan remains indistinguishable from not-attempted: **SUBOP-TELEMETRY-PERSISTENCE-OUTCOME** (observability debt, not a bug claim).
- Phantom dotted rows begun after a module cap: **0** of 36 scoped rows (all begin at Phase-1 t0-region; `ssl.http_redirect_hop_2` never appears).
- **Orphan metric: not obtainable within the authorised cohort** — an orphan row has, by definition, no parent scan and therefore no workspace attribution; scoping it is impossible. The v1 global counts (0 orphans in 1 522 module rows / 88 CT rows) are retained **only as a quarantined out-of-cohort observation**, not a cohort result.
- Completion→report-ready (4 scans): `assessed_at` → snapshot `completed_at` = **49.2 / 49.5 / 52.9 / 67.7 s** (P2-Q6) — context only.

---

## A. Proven facts (rescoped)

1. ssl and subdomains share ONE physical CT wait per provider per scan — code + 41/41 fan-out + 4/4 identical intervals. Unchanged after rescope.
2. crt.sh produced **zero successful responses in 26 physical attempts** (28–31 Jul, cohort); CertSpotter succeeded **15/15** in ≤ 708 ms.
3. The 9 000 ms observations are censored cap observations, not provider latencies. Unchanged after rescope.
4. The one-source-failed→`incomplete` policy grades scans partial even when execution completes and CertSpotter delivers (7bd83d64's impact rows bind the loss to `subdomain_discovery`); with the RUA-skip confound declared, this is a policy-mechanism proof, **not** a single-cause proof.
5. Historically (48 measured partials): CT-linked ssl/subdomains non-ok evidence in **27/48** — an involvement ceiling, not a fix guarantee; ≥ 4/48 provably CT-independent. Unchanged (Part 1 not re-run).
6. Every cohort scan since 28 Jul is partial (15/15); cohort partial rate 56 % overall. Unchanged after rescope.

## B. Supported but unproven hypotheses — unchanged after rescope

1. The 17 phase-5-starved historical partials were driven by slow CT waits (Phase-1 wall ≥ 9 s in 17/17; no historical sub-op split to prove causation).
2. crt.sh's failure pattern is provider-side instability; same-time/same-colo confounding cannot be excluded on 4 days of data.
3. Historical Phase-1 module durations are group-coupled; per-module historical attribution is approximate.

## C. Claims the data does not support — unchanged after rescope, plus one

1. "crt.sh explains the historical 56 % partial rate" — pre-28-Jul provider attribution does not exist.
2. Any crt.sh latency multiplier — censored.
3. Counting the two consumer rows/sub-ops as two provider events.
4. Thresholds derived from n=4 sub-op scans / n=15 CT scans.
5. Attribution for the 10 unmeasured partials and 5 failed scans.
6. **(new)** That CT alone set `scan_7bd83d64`'s partial grade — the skipped external-RUA phase's contribution is not determinable from D1.

## CT-R2 option assessment — unchanged after rescope (no decisions taken)

Provider ordering/failover: necessary, **insufficient alone** (15/15 partial despite 15/15 CertSpotter success). Per-consumer timeout isolation: strongly supported (shared crt.sh wait consumed ssl's whole 9 s cap). Shared-cache first-success-wins fast answer: supported. Preserving successful scoped CT evidence: required (CertSpotter data existed in 15/15). Explicit provider-degradation display: supported. No full/two-source coverage claim: required (Evidence-Grade law). Not consuming the remaining scan budget: supported (failed sequence ≤ 47 % of executable budget). Whether one-source degradation should grade the whole scan partial is a **completeness-policy question — founder-gated**, not decided here.

## Verdict — two-part, unchanged after rescope

- **Structural design: READY FOR DESIGN** — shared single wait, sequential consumption order, cap coupling and the policy interaction are proven by code + scoped data and will not change with more data.
- **Quantitative thresholds / completeness policy: MORE DATA REQUIRED.**

**Data-collection gate (numeric, unchanged after rescope; baseline now n=4):** ≥ 30 sub-op-instrumented **authorised-cohort** scans, ≥ 14 calendar days, ≥ 3 time-of-day bands, all 3 cohort domains, including ≥ 5 `complete` scans and ≥ 5 scans with a successful crt.sh response (for uncensored latency). If crt.sh never succeeds in 14 days, that absence is itself decision-grade.

## Residual telemetry observability debt

1. **SUBOP-TELEMETRY-PERSISTENCE-OUTCOME** — non-fatal, marker-less batch; zero rows indistinguishable from not-attempted.
2. `ct_provider_telemetry` fan-out duplicates each physical attempt per consumer — naive row counts double-count (this report's §2.2 grouping is the required de-duplication).
3. `cache_state` hard-bound to `'miss'`; `fresh_hit`/`stale_available` unobservable.
4. `subdomains` incomplete *reason* not in D1 (R2-only); historical CT attribution rests on the outcome proxy.
5. Historical Phase-1 module durations group-coupled.
6. `scans` has no completion timestamp (reconstructed from snapshot `assessed_at`).
7. **(new)** `dmarc_external_rua` skip **reason** is not persisted to D1 (`error_class` NULL) — gate-refusal attribution (benign no-RUA vs budget) is impossible without R2.

## P0/P1 check — unchanged

No new P0/P1. The all-partial streak is the honest surfacing of a real external CT degradation; the failed scans are the known class. Nothing was fixed; nothing may be described as fixed.

---

## Appendix — exact executable SQL (all run as `npx wrangler d1 execute cybermeters-db --remote --json --command "<SQL>"`)

Every query's returned meta is quoted; **rows_written = 0 in all cases**.

### Part 1 (v1 pass — correctly scoped, not re-run)

Q1 — monthly distribution (rows_read=226, rows_written=0):
```sql
SELECT strftime('%Y-%m', created_at) AS month, status, COALESCE(scan_quality,'(null)') AS scan_quality, COUNT(*) AS n
FROM scans
WHERE workspace_id='workspace_2aaf14fb-cf28-49d4-bde0-5eb645eda1a8'
  AND domain IN ('cybermeters.com','sheshire.co.uk','blackbullbarbers.co.uk')
GROUP BY month, status, scan_quality ORDER BY month, status, scan_quality;
```

Q2 — outcome vocabulary (rows_read=2541, rows_written=0):
```sql
SELECT COALESCE(t.outcome,'(null)') AS outcome, t.timeout, COUNT(*) AS n
FROM scan_module_telemetry t JOIN scans s ON s.id=t.scan_id
WHERE s.workspace_id='workspace_2aaf14fb-cf28-49d4-bde0-5eb645eda1a8'
  AND s.domain IN ('cybermeters.com','sheshire.co.uk','blackbullbarbers.co.uk')
  AND t.module NOT LIKE '%.%'
GROUP BY t.outcome, t.timeout ORDER BY n DESC;
```

Q3 — non-ok modules across partials (rows_read=1139, rows_written=0):
```sql
SELECT t.module, t.outcome, COUNT(DISTINCT t.scan_id) AS partial_scans_with_module_outcome
FROM scan_module_telemetry t JOIN scans s ON s.id=t.scan_id
WHERE s.workspace_id='workspace_2aaf14fb-cf28-49d4-bde0-5eb645eda1a8'
  AND s.domain IN ('cybermeters.com','sheshire.co.uk','blackbullbarbers.co.uk')
  AND s.scan_quality='partial' AND t.module NOT LIKE '%.%' AND t.outcome!='ok'
GROUP BY t.module, t.outcome ORDER BY partial_scans_with_module_outcome DESC;
```

Q4 — per-partial ssl/subdomains co-occurrence by month (rows_read=1316, rows_written=0):
```sql
WITH partials AS (
  SELECT id, strftime('%Y-%m',created_at) AS month FROM scans s
  WHERE s.workspace_id='workspace_2aaf14fb-cf28-49d4-bde0-5eb645eda1a8'
    AND s.domain IN ('cybermeters.com','sheshire.co.uk','blackbullbarbers.co.uk')
    AND s.scan_quality='partial'
), miss AS (
  SELECT t.scan_id,
         MAX(CASE WHEN t.module='ssl' AND t.outcome!='ok' THEN 1 ELSE 0 END) AS ssl_miss,
         MAX(CASE WHEN t.module='subdomains' AND t.outcome!='ok' THEN 1 ELSE 0 END) AS sub_miss,
         COUNT(*) AS telem_rows
  FROM scan_module_telemetry t
  WHERE t.module NOT LIKE '%.%' AND t.scan_id IN (SELECT id FROM partials)
  GROUP BY t.scan_id
)
SELECT p.month, COUNT(*) AS partials,
       SUM(CASE WHEN m.scan_id IS NULL THEN 1 ELSE 0 END) AS no_telemetry,
       SUM(COALESCE(m.ssl_miss,0)) AS ssl_missing,
       SUM(COALESCE(m.sub_miss,0)) AS sub_missing,
       SUM(CASE WHEN m.ssl_miss=1 AND m.sub_miss=1 THEN 1 ELSE 0 END) AS both_missing,
       SUM(CASE WHEN m.scan_id IS NOT NULL AND m.ssl_miss=0 AND m.sub_miss=0 THEN 1 ELSE 0 END) AS neither_missing
FROM partials p LEFT JOIN miss m ON m.scan_id=p.id GROUP BY p.month;
```

Q5 — ssl/subdomains duration distributions (rows_read=763, rows_written=0):
```sql
SELECT s.scan_quality, t.module, t.outcome, COUNT(*) AS n,
       MIN(t.duration_ms) AS min_ms, MAX(t.duration_ms) AS max_ms, ROUND(AVG(t.duration_ms)) AS avg_ms
FROM scan_module_telemetry t JOIN scans s ON s.id=t.scan_id
WHERE s.workspace_id='workspace_2aaf14fb-cf28-49d4-bde0-5eb645eda1a8'
  AND s.domain IN ('cybermeters.com','sheshire.co.uk','blackbullbarbers.co.uk')
  AND t.module IN ('ssl','subdomains') AND s.scan_quality IN ('complete','partial')
GROUP BY s.scan_quality, t.module, t.outcome ORDER BY t.module, s.scan_quality, n DESC;
```

Q6 — full cohort telemetry extract for local analysis (rows_read=2571, rows_written=0):
```sql
SELECT t.scan_id, s.domain, s.created_at, s.status, s.scan_quality,
       t.module, t.outcome, t.timeout, t.duration_ms, t.started_at, t.completed_at
FROM scan_module_telemetry t JOIN scans s ON s.id=t.scan_id
WHERE s.workspace_id='workspace_2aaf14fb-cf28-49d4-bde0-5eb645eda1a8'
  AND s.domain IN ('cybermeters.com','sheshire.co.uk','blackbullbarbers.co.uk')
ORDER BY s.created_at, t.scan_id, t.started_at;
```

Q10 — failed scans (rows_read=113, rows_written=0):
```sql
SELECT id, domain, created_at, current_stage, last_heartbeat_at, completed_modules
FROM scans
WHERE workspace_id='workspace_2aaf14fb-cf28-49d4-bde0-5eb645eda1a8'
  AND domain IN ('cybermeters.com','sheshire.co.uk','blackbullbarbers.co.uk')
  AND status='failed';
```

### Part 2 (v2 rescope — authoritative)

P2-Q1 — CT provider rows, exact cohort (rows_read=291, rows_written=0) → 82 rows, 15 scans, 26 impact rows:
```sql
SELECT c.scan_id, c.module, c.provider, c.outcome, c.http_status, c.latency_ms, c.result_count,
       c.started_at, c.completed_at, c.completeness_impact, c.affected_signal, c.cache_state,
       s.domain, s.created_at AS scan_created, s.status AS scan_status, s.scan_quality
FROM ct_provider_telemetry c JOIN scans s ON s.id = c.scan_id
WHERE s.workspace_id = 'workspace_2aaf14fb-cf28-49d4-bde0-5eb645eda1a8'
  AND s.domain IN ('cybermeters.com','sheshire.co.uk','blackbullbarbers.co.uk')
ORDER BY c.started_at;
```

P2-Q2 — physical-attempt grouping (rows_read=332, rows_written=0) → 41 groups, 41/41 `consumer_rows=2` with module set {ssl,subdomains}, 0 ambiguous:
```sql
SELECT c.scan_id, c.provider, c.started_at, c.completed_at, c.latency_ms, c.outcome,
       COALESCE(c.http_status, -1) AS http_status_key,
       COUNT(*) AS consumer_rows, GROUP_CONCAT(c.module) AS modules
FROM ct_provider_telemetry c JOIN scans s ON s.id = c.scan_id
WHERE s.workspace_id = 'workspace_2aaf14fb-cf28-49d4-bde0-5eb645eda1a8'
  AND s.domain IN ('cybermeters.com','sheshire.co.uk','blackbullbarbers.co.uk')
GROUP BY c.scan_id, c.provider, c.started_at, c.completed_at, c.latency_ms, c.outcome, COALESCE(c.http_status,-1)
ORDER BY c.scan_id, c.started_at;
```
Local classification applied to the result (no merge on violation): `consumer_rows != 2 OR sorted(split(modules,',')) != ['ssl','subdomains'] → ambiguous (left separate / unknown)`.

P2-Q3 — per-scan coverage since 28 Jul, exact cohort (rows_read=724, rows_written=0) → 15 scans, all partial; dotted 9×4 post-deploy:
```sql
SELECT s.id, s.domain, s.created_at, s.status, s.scan_quality,
  (SELECT COUNT(*) FROM ct_provider_telemetry c WHERE c.scan_id = s.id) AS ct_rows,
  (SELECT COUNT(*) FROM scan_module_telemetry t WHERE t.scan_id = s.id AND t.module LIKE '%.%') AS dotted_rows,
  (SELECT COUNT(*) FROM scan_module_telemetry t WHERE t.scan_id = s.id AND t.module NOT LIKE '%.%') AS module_rows
FROM scans s
WHERE s.workspace_id = 'workspace_2aaf14fb-cf28-49d4-bde0-5eb645eda1a8'
  AND s.domain IN ('cybermeters.com','sheshire.co.uk','blackbullbarbers.co.uk')
  AND s.created_at >= '2026-07-28'
ORDER BY s.created_at;
```

P2-Q4 — dotted sub-op rows, exact cohort (rows_read=1416, rows_written=0) → 36 rows, 4 scans, 4/4 identical ct intervals:
```sql
SELECT t.scan_id, s.domain, t.module, t.outcome, t.duration_ms, t.started_at, t.completed_at
FROM scan_module_telemetry t JOIN scans s ON s.id = t.scan_id
WHERE s.workspace_id = 'workspace_2aaf14fb-cf28-49d4-bde0-5eb645eda1a8'
  AND s.domain IN ('cybermeters.com','sheshire.co.uk','blackbullbarbers.co.uk')
  AND t.module LIKE '%.%'
ORDER BY t.scan_id, t.started_at;
```

P2-Q5 — module outcomes, post-deploy cohort scans (rows_read=181, rows_written=0) → 68 rows, 4 scans:
```sql
SELECT t.scan_id, t.module, t.outcome, t.duration_ms, t.timeout
FROM scan_module_telemetry t JOIN scans s ON s.id = t.scan_id
WHERE s.workspace_id = 'workspace_2aaf14fb-cf28-49d4-bde0-5eb645eda1a8'
  AND s.domain IN ('cybermeters.com','sheshire.co.uk','blackbullbarbers.co.uk')
  AND s.created_at >= '2026-07-31 02:30'
  AND t.module NOT LIKE '%.%'
ORDER BY t.scan_id, t.module;
```

P2-Q6 — snapshot readiness, post-deploy cohort scans (rows_read=389, rows_written=0) → 4 rows, 49.2–67.7 s:
```sql
SELECT r.scan_id, r.status, r.scan_quality, r.assessed_at, r.created_at, r.completed_at
FROM scan_report_snapshots r JOIN scans s ON s.id = r.scan_id
WHERE s.workspace_id = 'workspace_2aaf14fb-cf28-49d4-bde0-5eb645eda1a8'
  AND s.domain IN ('cybermeters.com','sheshire.co.uk','blackbullbarbers.co.uk')
  AND s.created_at >= '2026-07-31 02:30'
ORDER BY r.created_at;
```

P2-Q7 — dmarc_external_rua skip reason (rows_read=17, rows_written=0) → error_class NULL in all 4 rows:
```sql
SELECT t.scan_id, t.module, t.outcome, t.error_class
FROM scan_module_telemetry t JOIN scans s ON s.id = t.scan_id
WHERE s.workspace_id = 'workspace_2aaf14fb-cf28-49d4-bde0-5eb645eda1a8'
  AND s.domain IN ('cybermeters.com','sheshire.co.uk','blackbullbarbers.co.uk')
  AND s.created_at >= '2026-07-31 02:30'
  AND t.module = 'dmarc_external_rua'
ORDER BY t.scan_id;
```

P2-Q8 — dmarc_external_rua outcome vs scan_quality, whole cohort (rows_read=164, rows_written=0) → rows exist ONLY for partial scans (5 ok, 12 skipped); no complete-scan rows to test against:
```sql
SELECT s.scan_quality, t.outcome, COUNT(*) AS n
FROM scan_module_telemetry t JOIN scans s ON s.id = t.scan_id
WHERE s.workspace_id = 'workspace_2aaf14fb-cf28-49d4-bde0-5eb645eda1a8'
  AND s.domain IN ('cybermeters.com','sheshire.co.uk','blackbullbarbers.co.uk')
  AND t.module = 'dmarc_external_rua'
GROUP BY s.scan_quality, t.outcome ORDER BY s.scan_quality, t.outcome;
```

### Quarantined v1 queries (out-of-authorised-cohort; retained for audit only; all rows_written=0)

- v1 cohort-scoping aggregate: 3 founder domains grouped across ALL workspaces (rows_read=359).
- v1 Q7: whole-table `SELECT c.*, s.domain, … FROM ct_provider_telemetry c JOIN scans s ON s.id=c.scan_id` with **no workspace predicate** (rows_read=264) → superseded by P2-Q1/P2-Q2.
- v1 Q8: domain-only coverage since 28 Jul, no workspace predicate (rows_read=969) → superseded by P2-Q3.
- v1 Q12: domain-only module outcomes ≥ 2026-07-31 02:30 (rows_read=324) → superseded by P2-Q5.
- v1 Q13: **global** orphan/total counts (rows_read=4830) → orphan metric declared not-obtainable-in-cohort; global result quarantined (0 orphan module rows of 1 522; 0 orphan CT rows of 88).
- v1 Q14: domain-only snapshot readiness (rows_read=284) → superseded by P2-Q6.
- v1 dotted-row pull for scan_0b2c419b (rows_read=41) → excluded from cohort.
- Schema reads on `sqlite_master` (rows_read=404 each) and `wrangler deployments list` — metadata only.
