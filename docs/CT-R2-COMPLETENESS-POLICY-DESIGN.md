# CT-R2 — CT Provider Degradation and Scan-Completeness Policy — DESIGN

Status: **DESIGN FOR FOUNDER DECISION — no policy chosen, no thresholds chosen, no runtime change**
Date: 2026-07-31 · Owner: Claude (policy/design only; reviewers read-only)
Code basis: `origin/main` merge `f865d60` (post PR #363). All file:line references are to that commit.
Evidence base: [`docs/CT-PARTIAL-ATTRIBUTION-2026-07-31.md`](./CT-PARTIAL-ATTRIBUTION-2026-07-31.md) — the canonical, founder-adopted v2 attribution report. This document links to it and never restates or re-derives its numbers.

---

## 0. Goal

Design — on evidence — whether a whole scan must automatically grade `partial` when ONE
Certificate Transparency provider fails while the other provider delivered usable positive
evidence. Produce explicit policy options and their impact on every consumer, for founder
approval. This document decides nothing: it separates **observation** (what the code and the
canonical report prove), **inference** (what they support), and **policy** (what only the
founder may decide).

## 1. Evidence base and its limits

The canonical attribution report proves (its §A, "Proven facts"):

- ssl and subdomains share ONE physical CT wait per provider per scan;
- in the cohort window, crt.sh produced zero successes in 26 physical attempts while
  CertSpotter succeeded 15/15 in ≤ 708 ms;
- the one-source-failed→`incomplete` policy grades scans partial even when execution
  completes and CertSpotter delivers (a policy-mechanism proof, not a single-cause proof);
- a provider failover that leaves the sequential ssl consumption order and the
  one-source-failed policy untouched cannot restore `complete`.

**Binding evidence limits carried into this design** (report §B/§C and adoption block):

1. The 9 000 ms observations are **censored cap observations**, never provider latency.
2. The cohort is narrow: 15 scans / 4 days / 3 founder domains / one D1 region / few cron
   hours. A **reproduced pattern, not an independent statistical sample**. Nothing in this
   design treats it as one.
3. **No numeric failover threshold is approved by this design.** The report's own
   data-collection gate (≥ 30 instrumented cohort scans, ≥ 14 days, ≥ 5 complete scans,
   ≥ 5 crt.sh successes) must be met before any threshold is proposed, and thresholds are a
   separate founder gate.
4. crt.sh degradation is **not** presented as the whole cause of the general partial-rate
   problem: historically CT-linked evidence appears in 27/48 measured partials (an
   involvement **ceiling**), at least 4/48 are provably CT-independent, and 10 partials plus
   5 failed scans have no attribution at all.
5. Marker key used throughout: **[OBS]** observation (code or canonical report),
   **[INF]** inference, **[POL]** policy decision reserved to the founder.

---

## 2. Exact pre-change map (code-counted, `origin/main` `f865d60`)

Counting rule: every claim of "all callers" below was produced by exhaustive grep plus
follow-up of every hit, not by sampling. Raw totals: `scan_quality` appears **601 times**
(workers/ 190 across 46 files; scripts/ 411; shared/ 0; workers/email-ingest 0 — the email
worker carries only a deploy-manifest closure stamp, no scan source). Frontend:
`scan_quality|scanQuality|partial` appears **81 times across 26 files**, of which 27 are
true completeness semantics (the rest are homonyms: DMARC `partial_enforcement`, CE answer
values, "partial owner", platform-status copy).

### 2.1 CT provider cache and all consumers [OBS]

`workers/scan-api/src/engines/ct-provider-cache.js` (464 lines):

- ONE cache per scan; key is the normalized domain + a NUL separator (U+0000) +
  provider, so a hostile domain string cannot forge a key collision; the map stores the
  **promise**, so two consumers of the same (domain, provider) share one outbound request
  chain (`:412-431`). Budget/policy resolve at first insertion only.
- `get()` **never rejects**; every failure resolves to
  `{ status: "unavailable", data: null, error }`; a successful empty response is
  `{ status: "available", data: [] }` — "provider said nothing" stays distinct from
  "provider was down".
- `CT_PROVIDER_POLICIES` (`:22-27`): crt_sh 6 000 ms × 2 attempts + 150 ms backoff;
  certspotter 4 000 ms × 2 + 100 ms; `CT_PROVIDER_HARD_ATTEMPT_CAP = 2` (config cannot
  raise it); physical-attempt limit 4.
- Outcome vocabulary (frozen in CT-R1): `ok | timeout | http_error | parse_error |
  rate_limited | network_error`; unknown coerces to `network_error` (fail closed).
- Production constructors: exactly 4 (`scan-engine.js:407-411` — the only production
  instance under `runScanEngine`; self-construct fallbacks in `ssl-scan.js:24`,
  `subdomains-scan.js:84`, `reserved-scan.js:135`).
- `ctCache.get()` call sites: exactly 4 — `ssl-scan.js:42` (crt_sh), `ssl-scan.js:97`
  (certspotter, conditional), `subdomains-scan.js:173` (crt_sh), `subdomains-scan.js:174`
  (certspotter). `healthSnapshot()` callers: exactly 2 (`scan-engine.js:1455`, `:2181`).
  `telemetrySnapshot()` callers: exactly 1 (`scan-engine.js:435`).

### 2.2 Call order, shared in-flight wait, fan-out [OBS]

- **ssl consumes crt.sh first, sequentially** (`ssl-scan.js:42`); CertSpotter is entered
  only when crt.sh produced **no currently-valid certificate** (`:95`) — not only when it
  errored. ssl's CertSpotter call is usually a warm hit because
  **subdomains launches both providers unconditionally in parallel at Phase-1 t0**
  (`subdomains-scan.js:169-175`, inside one `Promise.allSettled` with the wildcard DNS
  probes).
- CT-R1 telemetry fans each physical attempt out **once per consuming module**
  (`ct-provider-cache.js:446-459`) — naive row counts double-count; the canonical report's
  §2.2 grouping is the required de-duplication.
- The shared wait is systematic, not incidental: 41/41 physical attempts carry both module
  labels; 4/4 sub-op-instrumented scans show identical start AND end stamps for
  `ssl.ct_lookup` and `subdomains.ct_wait_crt_sh` (canonical report §2.4).

### 2.3 Timeout / cap / budget flow per consumer [OBS]

- Executable budget 19 000 ms; ceiling 24 000 ms; finalization reserve 5 000 ms
  (`scan-budget.js:113-121`). Module caps: ssl 9 000, subdomains 12 000, headers 1 200
  (`:131-133`).
- **CT attempt timeouts clamp against the GLOBAL 19 s budget, never the module cap**
  (`ct-provider-cache.js:321` via `scan-engine.js:409`). ssl's worst-case sequential CT
  chain (6 000+150+6 000, then 4 000+100+4 000) ≈ 20.25 s against its own 9 000 ms cap.
  The mitigation is architectural (subdomains' parallel launch warms the CertSpotter
  promise), not arithmetic.
- When a module cap fires, `raceModuleDeadline` **abandons** the promise
  (`scan-budget.js:167-172`); the CT entry stays memoized, so the sibling module with the
  larger cap still consumes it. The 9 000 ms anatomy in production is a **cap fingerprint**
  (6 000 timeout + 150 backoff + 2 850 aborted attempt-2), per the canonical report §2.3.
- A budget-refused attempt (`assertCanIssue` throws before fetch) produces **no telemetry
  row** at all (`ct-provider-cache.js:158,169`) — the refusal is invisible in
  `ct_provider_telemetry`.

### 2.4 CT result propagation beyond ssl/subdomains [OBS]

Every consumer of CT-derived state, counted:

- `modules.ssl.ct_sources` → `certificate-signal-completeness.js:1053-1055` (subdomains
  sources take precedence), `routes/attack-surface.js:1461`.
- `modules.subdomains.sources/ct_error/incomplete_reason` → `cert-intel.js:150-151,166`
  (blackout predicate), `asset-inventory.js:38-41` (discovery-completeness gate — mirrors
  the OR policy), `attack-surface-signal-completeness.js:104,118-138`,
  `ct-provider-cache.js:442` (telemetry attribution).
- CT-derived `cert_*` fields → `cert-intel.js:54-56,291-293`,
  `certificate-signal-completeness.js:1302-1433`, `cert-analysis.js`, `alerts.js`.
- CT-derived `modules.subdomains.items` → `asset-inventory.js:86,103`,
  `cloud-storage-scan.js:292`, `historical-scan.js:90`, `identity-scan.js:210`,
  `scoring.js:835-875` (CT-log-only asset ⇒ confidence 60/weak), `supply-chain.js:14`,
  `takeover-scan.js:248`, `scan-engine.js:698-707` (merge with bruteforce).
- Provider health (`healthSnapshot`) → `signal-monitoring-state.js:265-339`
  (`certificate_transparency` is the ONLY signal with `providers[]`),
  `certificate-signal-completeness.js:1039-1073`, `scan-budget.js:567`
  (R2 execution diagnostics), `cert-intel.js:104`.
- Findings vocabulary: `ct_source_incomplete`, `ct_sources_unavailable`,
  `ct_source_discrepancy` (`cert-trust-l2.js:316-326`, `remediation-registry.js:754`).
- **Brand is CT-independent** (zero references — checked).

### 2.5 scan_quality producers — ALL writers [OBS]

`buildScanQuality` (`scan-engine.js:127-201`) is the **only** computation. Verbatim
decision (`:187-189`):

```js
const status = (coreIncomplete.length > 0 || incompleteModules.length > 0 || coreBudgetSkipped.length > 0)
  ? "partial"
  : (warnings.length > 0 || modulesSkipped.length > 0 ? "degraded" : "complete");
```

It never emits `failed`; a failed scan's row is `scan_quality = NULL` (never fabricated).
All 15 write/latch sites, counted: `scan-engine.js:1450` (compute), `:241` (latch), `:268`
(terminal D1 UPDATE), `:1556` (R2 report), `:1664` (historical_scores), `:1675` (BRS
input), `:2130` (lifecycle email event); `scan-recovery.js:124-131,167,187`;
`scan-dispatch.js:133,153,176`; `index.js:711`; `website-security-lifecycle.js:346`
(per-case denormalisation); plus the read-side trend gate `scan-engine.js:1468-1470`.

### 2.6 The live policy contradiction [OBS]

Two different one-vs-both-provider policies coexist, and a dead invariant sits between
them:

1. `subdomains-scan.js:289` — `ctCoverageDegraded = !!(sources.crt_sh?.error ||
   sources.certspotter?.error)` — **OR**: one failed provider marks
   `incomplete: true, incomplete_reason: "ct_source_degraded"` (`:301-303`) even when the
   other provider succeeded and names were discovered.
2. `cert-intel.js:166` — `ctBlackout = !!(crtShError && certSpotError)` — **AND**: only a
   total blackout marks `certificate_intelligence` incomplete
   (`incomplete_reason: "ct_sources_unavailable"`, `:319`).
3. `scan-engine.js:137-149` and `subdomains-scan.js:263` still assert in comments that
   external CT failure must NOT degrade scan quality, and `:149` excludes `subdomains` from
   the string-match loop — but the **unscoped** `incomplete === true` sweep at
   `scan-engine.js:161-167` re-includes it. The Sprint-10C invariant is dead code.

Net effect [OBS]: one CertSpotter 429 — or, as in the live cohort, a persistent crt.sh
outage — makes the whole scan `partial` and drops it out of **every**
`scan_quality = 'complete'` filter (16 backend query sites, §2.7). The canonical report's
scan `7bd83d64` **proves the one-provider-loss policy mechanism and a fast crt.sh failure
trace** (HTTP 404 in 564 ms; its two `completeness_impact=1` rows bind the completeness
loss to `subdomain_discovery`). It does **not** prove that CT was the sole cause of that
scan's overall partial grade: the same scan carries a `dmarc_external_rua` skip whose
reason is not persisted to D1 — the canonical report's own declared confound (§2.5 there).
For the budget-coupling mechanism, the report's confound-free example is scan `3a97a5f8`
(`dmarc_external_rua` ok; partial via ssl deadline + subdomains incomplete). The two proof
classes are kept separate throughout this document.

Note the asymmetry is itself a designable fact [INF]: for `certificate_intelligence`, CT is
the module's ONLY evidence source, so AND-blackout is the honest floor; for `subdomains`,
CT is one of several discovery paths (CT + wildcard DNS + bruteforce merge at
`scan-engine.js:698-703`) and each CT provider is a partially redundant source of the same
evidence type. The OR policy encodes "any lost source taints the whole module"; the AND
policy encodes "all sources lost taints the module". Neither is derived from a declared
contract — that gap is what §4 fixes.

### 2.7 Complete/partial consumer inventory — ALL consumers, with the change table

Backend readers filtering on `scan_quality = 'complete'` (16 query sites, counted):
`business-risk.js:747`, `cyber-mot-state-history.js:335,392`, `historical-scan.js:51`,
`portfolio-domains.js:185,237`, `portfolio-risk.js:291`, `related-changes.js:62,222`,
`report-queries.js:26,30`, `weekly-digest.js:81`, `routes/executive-dashboard.js:166,210`,
`routes/portfolio.js:181,464,477`, `routes/workspace-analytics.js:407`,
`routes/workspaces-core.js:113`, `cyber-mot-domains.js:197`.

The table below is the required per-consumer statement: what the consumer does **today when
a single-provider CT failure grades the scan `partial`**, and what would change **under the
candidate `complete + structured degradation` semantics (Option B, §8)**. "No change"
always means: behaviour identical to a genuinely complete scan, with the degradation
visible in the new `degradations[]` channel (§3) instead of via the quality grade. Under
**Option D** (§8 — re-grade to the existing `degraded` status + `degradations[]`) the
"today" column applies mechanically unchanged for every consumer keying on
`!== 'complete'`; only consumers keying on the literal `'partial'` (e.g. rows 15/§10b)
need the five-point implementation gate defined in §8 Option D. Per the pinned two-layer rule
(§7), every "complete" in the Option B column means *eligible for complete — subject to
every other mandatory evidence contract passing*.

| # | Consumer (file:line) | Today when partial (CT single-provider) | Under complete + degradation (Option B) |
|---|---|---|---|
| 1 | Canonical snapshot (`report-snapshot.js:518,696,938,1054`) | `scan_quality='partial'` in D1 + snapshot; `trend.comparable_basis=false`; `evidence_completeness` block records skip | D1 scalar `'complete'`; NEW additive, schema-versioned `overall.evidence_completeness.degradations[]` (immutable projection of `report.scan_quality.degradations[]`, contract-versioned); existing `evidence_completeness` fields untouched |
| 2 | Score/display (`assessment-presentation.js:172-186`) | `display_rating=null`, `provisional=true`, score shown with provisional message | Band shown **only if** the band rule (§4.4) passes: CT strengthening-only ⇒ band shown + degradation note; CT score-contributing ⇒ unchanged provisional behaviour |
| 3 | score_band in snapshot (`report-snapshot.js` overall) | `score_band=null` | Band per band rule; never silently green — degradation travels with it |
| 4 | BRS per-scan BRI (`report-snapshot.js` mask) | band `null`, "not authoritative" explanation | Authoritative iff no score-contributing degradation [POL]; explanation cites CT degradation when present |
| 5 | Workspace BRS (PR #344, `business-risk.js:723-771,875`) | **not persisted at all**; projection `latest_incomplete`, all nulls | Persisted (basis contract `complete_scan/v1` would need a versioned successor naming degradations) [POL] |
| 6 | Free-scan surface (PR #332, `routes/billing.js:238-268`) | `score=null`, `risk_level=null`, `preview_state=evidence_incomplete` — false-healthy P1 history; **cannot be skipped** | Score/risk shown per band rule; `preview_state` must carry degradation; absence claims stay closed (§4.3) |
| 7 | Timeline trust (`timeline-trust.js:70,84,94`) | comparison `unavailable`/`not_comparable`; ALL 15 customer change-event types suppressed (incl. 3 certificate events) | Comparable iff both sides complete under the SAME contract version; complete-with-degradations ↔ complete-with-degradations comparability is a [POL] row (§9) |
| 8 | SPF diff exception (`posture-events.js:213-223`) | SPF diffs still emitted (per-signal completeness) | Unchanged — this is the existing per-signal precedent Option B generalises |
| 9 | Historical comparison (`historical-scan.js:51`, `scan-engine.js:1074`, `cyber-mot-state-history.js:144,335,392`) | partial scan invisible as baseline; `score_change=null`; trend `not_comparable` | Degraded-complete scans enter baseline pools only under matching contract version [POL]; never across the version boundary |
| 10 | Related Changes (`related-changes.js:62,222,229`) | no correlation window; `correlation_possible=false` | Window opens; correlation output must surface degradation on affected clusters |
| 11 | Executive PDF (`pdf.js:323,473,501-503`) + `executive-report.js:44,85` | "Provisional Score", no band line, evidence-bounded BRI text | Band per band rule; NEW: degradations rendered in the evidence-completeness section — never silently absent |
| 12 | Scheduled workspace report (`scheduled-reports.js`) | inherits via pdf.js/report-queries | Same inheritance; no independent decision point (verified: zero own quality logic) |
| 13 | Alerts senders (`alerts.js:619`, `asset-alert-delivery.js:184-189`) | **no quality gate today** — alerts fire off partial scans with a wording disclosure only | Unchanged mechanically; degradation wording replaces partial wording; the real gates stay upstream in event producers |
| 14 | Alert event producers (`posture-events`, `timeline-trust`, `asm-cases`) | suppressed via comparability + verification gates | Re-enabled per rows 7/9/15; **absence-based events stay closed under CT degradation** (§4.3) |
| 15 | Managed cases/verification (`asm-cases.js` `moduleCompletionGate`, `scanPartial` at `:477-492`; `website-security-lifecycle.js:251-259`) | `canVerify()=false` for every module when partial; website rows `unknown_reason='scan_partial'` | Gate becomes per-module: modules untouched by the degradation may verify; CT-dependent absence verification stays closed (§4.3) [POL] |
| 16 | Weekly digest (`weekly-digest.js:75-105`) | `coverage='partial_only'`; reassuring wording forbidden | `complete_assessment` **only if** no absence-blocking degradation; quiet wording gate keys on degradations, not just quality [POL] |
| 17 | Notifications/lifecycle email (`assessment-presentation.js:46-60`, `lifecycle-email.js:209,346-353`) | "provisional" disclosure paragraph, preserved through retry sweep | Disclosure paragraph switches to specific degradation wording (same retry-sweep preservation required) |
| 18 | Monitoring/recurrence (`alert-occurrence.js`) | no quality logic (verified) | Unchanged; recurrence honesty continues to ride on lifecycle grading |
| 19 | Report preparation (`report-availability.js:60,141,193`) | `report_preparing` state; quality-agnostic | Unchanged |
| 20 | Posture/current state (`current-posture.js:41-111`) | partial excluded from authoritative posture; "not yet established" | Degraded-complete counts as established per band rule [POL] |
| 21 | Portfolio/MSP (`portfolio-domains.js:185-341`, `portfolio-risk.js:272-291`, `portfolio.js:181,464,477`, `portfolio-customers.js:62`, `workspaces-core.js:113`, `executive-dashboard.js:166,210`, `workspace-analytics.js:407`) | excluded from averages/trends/rankings; `overall_state='provisional'`; coverage_note shown | Included, with degradation surfaced via existing `coverage_note`/state channels; comparability rules as row 9 |
| 22 | Domain maturity ledger (`domain-maturity.js:226`) | `skipped: "not_complete"` — no ledger row | Writes a row iff contract version matches ledger contract expectations [POL] |
| 23 | DMARCbis lifecycle (`dmarcbis-managed-lifecycle.js:197`) | `scan_incomplete` — no advance | Advances (CT degradation is unrelated to DMARC evidence) — per-module gate, row 15 |
| 24 | Cyber MOT domains (`cyber-mot-domains.js:196-203,342-345`) | `provisional=true`; required-module gate blocks `assessed_healthy` off missing evidence | `provisional` keys on domain-relevant degradations; the `moduleAssessed` fail-closed gate is untouched |
| 25 | Frontend ScanDetail (`ScanDetail.jsx:1092-1155`) | amber coverage strip below an unqualified score hero; comparison panel has NO completeness qualifier (gap) | Renders backend `degradations[]`; comparison qualifier comes from backend comparability (row 7). No frontend derivation |
| 26 | Frontend Dashboard (`Dashboard.jsx:50-56,795-815,907-920`) | best-in-app: provisional eyebrow, band suppressed, honest empty state | Authoritative selection keys on backend fields; wording switches from "provisional" to specific degradation note |
| 27 | Frontend IntelligencePage (`IntelligencePage.jsx:1013,1121-1126`) | zero quality awareness (Codex corrective in flight — untouched by this design) | Consumes backend fields only; no independent decision |
| 28 | Frontend free-scan (`freeScanPresentation.js:66-103`, `FreeScanPage.jsx:615-625`) | fail-closed since PR #332: `noIssuesObserved` requires `evidence_coverage.complete === true` AND `preview_state === 'no_issues_observed'`; an unrecognised `preview_state` resolves to `evidenceIncomplete`; the green presentation branch is reachable only after the `evidenceIncomplete`/`issuesObserved` gates | If CT-R2 emits new degradations, backend `evidence_coverage`/`preview_state` must carry the limitation; the frontend continues to derive no second verdict |
| 29 | Frontend Portfolio/Website Security/Related Changes (`PortfolioDomainsPage.jsx`, `WebsiteSecurityPage.jsx:43-86`, `RelatedChangesList.jsx:116-156`) | already render backend completeness states/pills | Same channels carry degradation entries; two known frontend-side derivations (`websiteSecurityDisplay.js:65 isSettled`, `CyberMotDomains.jsx:33`) must migrate to backend fields — pre-existing debt this design records, does not fix |

Also recorded for completeness [OBS]: the scan list (`ScansPage.jsx:145`), Domain History
(`DomainHistory.jsx:56,101`), posture timeline points (`WorkspaceDashboard.jsx:579,585`)
and Exposure Timeline render partial and complete identically today — they are wording/UX
debt independent of which option is chosen, and become MORE important if Option B ships
(a "complete" scan with degradations must never be indistinguishable from a clean one).

---

## 3. Vocabulary / data model

**The current contract, stated exactly [OBS]:**

- `scans.status` is the **lifecycle/terminal** vocabulary. `failed` lives HERE — it is a
  scan lifecycle status, never a `scan_quality` value.
- `scans.scan_quality` is minted by exactly ONE function, `buildScanQuality`, with exactly
  three produced values: **`complete | partial | degraded`** (`scan-engine.js:187-189`).
  A failed or interrupted scan's `scan_quality` is `NULL` — quality was never earned, and
  it is never fabricated (`scan-recovery.js:182-187`, `scan-dispatch.js:153`).
- Readers normalise NULL/unrecognised values to **`unknown`, fail closed — never
  `complete`** (`assessment-presentation.js:21-32`: `SCAN_QUALITY = { COMPLETE, PARTIAL,
  DEGRADED, UNKNOWN }`; its contract comment: "Quality describes EXECUTION + EVIDENCE
  COVERAGE, not security posture … degraded evidence sources are 'degraded'").

**Proposal: `provider_degraded` must NOT become a fourth produced status.** [INF→POL]

Rationale: 16 backend `= 'complete'` filters, the produced three-value vocabulary and the
NULL-means-unearned convention key on this contract. A new produced status would fork
every filter into an extra decision and reintroduce the "two vocabularies through one
slot" defect class recorded in the alerting repair (customer word vs evidence word).
Provider degradation is **evidence metadata**, not a new quality grade — and the existing
`degraded` value already names the closest concept (see Option D, §8).

Retained model, with the canonical storage projection pinned explicitly — the D1 scalar
and the report/snapshot object are DIFFERENT vocabularies and are never conflated:

```
D1  scans.status:              lifecycle/terminal vocabulary (unchanged; `failed` lives here)
D1  scans.scan_quality:        SCALAR TEXT, complete | partial | degraded (produced set
                               unchanged; NULL = never earned). NO nested field is added
                               here and NO D1 migration is required by this design.
reader normalisation:          unknown (fail closed; unchanged)
R2  report.scan_quality:       existing object {status, warnings, modules_skipped,
                               subrequest_budget} + NEW report.scan_quality.degradations[]
                               (structured provider/module limitations, append-only)
Snapshot (scan_report_snapshots R2 body):
                               NEW overall.evidence_completeness.degradations[] — an
                               immutable, additive, schema-versioned projection of
                               report.scan_quality.degradations[] at build time
```

Wherever this document says `degradations[]` without a path, it means: the R2 report field
`report.scan_quality.degradations[]` at production time, and its immutable snapshot
projection `overall.evidence_completeness.degradations[]` at read time. The D1
`scans.scan_quality` column never carries it.

Proposed degradation entry shape (minimum fields, all required):

```jsonc
{
  "module": "subdomains",                  // reporting module
  "dependency": "ct:crt_sh",               // namespaced dependency identifier
  "status": "unavailable",                 // unavailable | degraded | conflicting
  "reason": "http_error",                  // frozen CT-R1 outcome vocabulary where applicable
  "claim_effect": "absence_claims_blocked",// what may no longer be claimed:
                                           // none | strengthening_lost |
                                           // absence_claims_blocked | score_input_lost
  "fallback_evidence": "ct:certspotter",   // dependency that DID deliver, or null
  "fallback_publishable": true,            // may the fallback's POSITIVE evidence publish?
  "observed_at": "2026-07-31T02:42:17Z",
  "contract_version": "ct-completeness/1"  // versioned evidence contract (§4)
}
```

Fail-closed rules [INF]:

- An unrecognised `status`, `claim_effect`, or missing `contract_version` invalidates the
  entry AND forces the legacy path: the scan grades `partial` exactly as today. Unknown
  never resolves to the more permissive branch — consistent with `normalizeQuality`
  (`assessment-presentation.js:29`, unrecognised → `unknown`, never `complete`) and the
  CT-R1 outcome coercion (unknown → `network_error`).
- Readers that do not understand `degradations[]` see an unchanged three-value
  `scan_quality.status` — additive compatibility, no consumer forked.
- Snapshot readers keep their existing fail-closed schema-version gate
  (`report-snapshot.js:341-344`); `degradations[]` rides the snapshot schema version.

Relationship to existing structures [OBS]: the snapshot already carries
`overall.evidence_completeness.monitoring_degraded_signals[]` (`report-snapshot.js:942-948`),
`limitations[]` (`:980-990`), and the versioned signal-monitoring vocabulary
(`signal-monitoring-state.js:8-15`). `degradations[]` is the structured, per-dependency,
contract-versioned generalisation; it must compose with — not duplicate — those fields, and
`SIGNAL_MONITORING_DEFINITIONS.certificate_transparency.providers` (`:24-27`) is the
natural source of the `dependency` namespace.

### 3.1 Terminology consistency table

Pinned meanings for every completeness term used in this document. Any sentence elsewhere
in this document that conflicts with a row here is a defect in that sentence.

| Term | Meaning in this document | Source of truth |
|---|---|---|
| `scans.status` | Scan **lifecycle/terminal** state; `failed` lives HERE and only here | `scans` table; `scan-engine.js:268` |
| `scan_quality` (produced) | `complete` \| `partial` \| `degraded` — minted only by `buildScanQuality` | `scan-engine.js:187-189` |
| `scan_quality = NULL` | Quality never earned (failed / interrupted / queued); not a fourth value; never fabricated | `scan-recovery.js:182-187`, `scan-dispatch.js:153` |
| `unknown` | **Reader-side** normalisation of NULL/unrecognised; fail closed; never produced or persisted | `assessment-presentation.js:29-32` |
| `failed` | A `scans.status` value ONLY; **never** a `scan_quality` value | §3 |
| `degraded` (status) | Existing produced grade: warnings/skips today; Option D would add provider evidence degradation | `scan-engine.js:189`; §8 Option D |
| `degradations[]` | Proposed structured evidence metadata: `report.scan_quality.degradations[]` (R2 report) projected immutably to `overall.evidence_completeness.degradations[]` (snapshot); **never a status value, never a D1 column** | §3 |
| complete-with-degradations | Shorthand for Option B's proposed outcome: D1 scalar `scan_quality='complete'` with non-empty `report.scan_quality.degradations[]` — distinct from the `degraded` status | §8 Option B |
| `partial` | Conservative-but-coarse produced grade: core module error, any module `incomplete`, or core budget-skip | `scan-engine.js:187-188` |
| `incomplete` (module flag) | Module self-report: this module's evidence is ineligible to support absence claims | `subdomains-scan.js:276-303` |
| `ct_source_degraded` / `ct_sources_unavailable` | One-source-lost / both-sources-lost CT incomplete reasons | `subdomains-scan.js:301`, `cert-intel.js:319` |
| provisional | Presentation state: quality ≠ `complete` (reader-derived, backend-owned) | `assessment-presentation.js:172-186`, `cyber-mot-domains.js:203` |

## 4. Mandatory evidence contract

**"Complete = mandatory evidence contracts satisfied" must be a declared, versioned
artefact, not a magic constant.** Today the de-facto contract is scattered and unversioned
[OBS]: `isPublishableModuleEvidence` (`scan-budget.js:219-226`) has no version constant;
the per-domain `required` lists live in `cyber-mot-domains.js:102-123` (versioned
indirectly via `CYBER_MOT_RESOLVER_VERSION`); the subdomains OR policy and cert-intel AND
policy are inline booleans with contradictory comments (§2.6).

Proposed artefact [INF→POL]: a per-module **evidence contract**, following the
Evidence-Grade Law per-signal contract shape (`docs/EVIDENCE-GRADE-LAW.md`, "Per-signal
grade contract"), declaring for each module:

- `required` (grade-bearing) evidence — absence blocks `complete`;
- `strengthening` (corroborating) evidence — absence yields a degradation entry, not
  `partial`;
- `positive_only` evidence — usable for findings, never for absence claims;
- `absence_claims` — the evidence set required before "none found / healthy / removed /
  resolved" may be uttered;
- a `contract_version` bumped under the same discipline as `CYBER_MOT_RESOLVER_VERSION`
  (`cyber-mot-domains.js:25-50`): any change to what `complete` means is a version bump,
  and comparisons never cross the boundary.

### 4.1 Are two CT sources mandatory or strengthening for subdomain assessment?

[OBS] Each provider returns the same evidence type (CT log entries); the Evidence-Grade
Law's corroboration axis classifies a second provider as `independent-source`
corroboration, which **strengthens** grade/corroboration but is explicitly NOT required
for L4 ("L4 does not require an independent second source"). CertSpotter alone discovered
usable names in 15/15 cohort scans while crt.sh returned nothing in 26 attempts.
[INF] Two sources are **corroborating/strengthening for positive discovery**, and jointly
**mandatory for absence claims** (§4.3). [POL] The founder must ratify this
classification — it is the pivotal row of the decision table.

### 4.2 Is a single provider's positive finding publishable?

[OBS] Today it already is: discovered names merge into `items` regardless of the other
provider's error, and downstream (takeover, exposure, identity, scoring) consumes them;
scoring already prices CT-log-only assets at confidence 60/weak (`scoring.js:835-875`).
The canonical report requires preserving successful scoped CT evidence ("CertSpotter data
existed in 15/15"). [INF] Yes — a positive observation from one provider is a real
observation; suppressing it would discard true evidence. Detection Depth Law wording
bounds the claim: "observed", never "complete coverage". No change needed; the contract
should state it explicitly.

### 4.3 May one provider support "no other subdomains", healthy, removed, or resolved?

[INF] **No.** Absence-of-evidence claims are exactly what the `incomplete` flag exists to
block (`subdomains-scan.js:276-279`: ineligible to support a "no subdomains found"
conclusion). One provider's silence plus one provider's absence is not two-source absence:
in the live cohort crt.sh was blind for four days — a single-source "nothing found" would
have been unfalsifiable. This aligns with: Shadow IT honesty (disappearance ≠ removal),
the website-security verifier requiring `last_scan_quality='complete'` before
`no_longer_observed`, and the #105 defect class (a probe that never ran must not produce a
recovery). Under Option B this rule survives the re-grade: `claim_effect:
"absence_claims_blocked"` keeps every absence/healthy/removed/resolved path closed even
while the scan grades complete. [POL] Founder ratifies.

### 4.4 May the final band show when a provider degradation touches score input?

Proposed band rule (from the brief), assessed [INF]:

> Final band shows only when every score-contributing input is publishable. If the
> degradation affects only strengthening evidence — contributing neither to the score nor
> to an absence/healthy conclusion — the band may show alongside the degradation;
> otherwise the presentation stays provisional/not-assessed.

Assessment: consistent with the existing architecture — `display_rating` already nulls on
non-complete (`assessment-presentation.js:181`), Phase-5 masking already nulls score/band
when CVE/KEV/email modules are unpublishable (`phase5-evidence.js:123-196`), and the BRS
basis contract already re-proves its input (`business-risk.js:875`). The rule generalises
those precedents instead of inventing a new one. The hard part is honest classification of
"score-contributing": subdomain count/exposure feeds scoring via merged items
(`scoring.js:835-875`), so CT loss is NOT automatically strengthening-only — for scans
where crt.sh contributed nothing and CertSpotter delivered, the *counterfactual* score
input is unchanged, but proving that per-scan requires the contract to define which inputs
were actually consumed. [POL] Adopt/adapt/reject the band rule; if adopted, the
"score-contributing" classification per module ships inside the versioned contract, not as
inline code.

## 5. Policy-independent engineering (design candidates — no implementation)

These stand on their own merit under ANY policy option, because they change latency and
blast-radius, not completeness semantics. All are design candidates only; each is
[INF] unless marked.

1. **First-success-wins for equivalent evidence.** Launch both providers in parallel for
   every consumer (subdomains already does; ssl does not — `ssl-scan.js:42` waits crt.sh
   sequentially for up to its full cap while CertSpotter's answer sat in the shared cache
   from ~0.4 s in the cohort). A ready fallback answer must never sit behind a 9 s wait
   for the preferred source. Field-extraction differences (crt.sh `name_value` vs
   CertSpotter `dns_names`; `cert_shared_san_count` only derivable from crt.sh) mean
   "equivalent" needs per-field declaration in the evidence contract.
2. **Fast-fail degraded response.** Non-transient outcomes (404, parse_error, non-JSON)
   already skip retry [OBS]; the residual cost is the timeout path. A provider that has
   already failed non-transiently for consumer A should be immediately degraded for
   consumer B (the shared promise already gives this) — the gap is only the sequential
   consumption order.
3. **Per-consumer bounded wait.** CT attempt timeouts clamp to the global budget, not the
   consuming module's cap (§2.3) — so one provider wait can consume up to 47 % of the
   executable budget (canonical report, mechanism 1). A consumer-side bound (wait at most
   min(remaining module cap, provider policy)) keeps one dependency from starving the
   module, without changing provider policy itself. **No numeric values are proposed here**
   — the report's data gate governs.
4. **Consumer cancellation must not poison the shared cache.** Already structurally true
   [OBS]: `raceModuleDeadline` abandons rather than aborts the shared promise, and the
   memoized entry survives for the sibling consumer. Any redesign must preserve this
   property explicitly (a per-consumer AbortSignal must never propagate into the shared
   fetch).
5. **Late provider responses must not write into a finalized scan.** Today protected by
   the terminal-latch ordering [OBS]: CT telemetry persists only after the terminal D1
   status (`scan-engine.js:420-446`), sub-op telemetry after finalization with honest
   `aborted` outcomes, and the abandoned promise's value is discarded. A future cross-scan
   cache (schema already reserves `fresh_hit`/`stale_available`, and `scan-engine.js:369`
   currently hard-binds `'miss'` — a known swallow point) must key results by scan id and
   never back-fill a completed scan's evidence.

## 6. Historical integrity

Binding rules, all [POL]-ratifiable but architecture-forced:

1. **No re-grading of old partial scans.** Existing `scans.scan_quality`,
   `historical_scores`, and `scan_report_snapshots` rows are immutable history; the 15/15
   cohort partials stay partial forever. No backfill, no retroactive "would have been
   complete".
2. **Immutable snapshots stay immutable.** `degradations[]` is written into NEW snapshots
   at build time (Phase 8o), append-only; the checksum/parity contract
   (`report-snapshot.js:1318-1319`) is untouched for existing objects.
3. **New semantics apply only from the versioned contract forward.** The first scan
   assessed under `ct-completeness/1` is the first scan whose `complete` means the new
   thing. Pre-contract scans are honestly absent from the new regime — exactly the M5.c
   precedent (no backfilled snapshots).
4. **Comparisons never cross the contract boundary.** `assessTimelineComparison` already
   refuses producer-version mismatches (`timeline-trust.js:94-107`) and the MSP portfolio
   refuses resolver-version crossings (reads as `insufficient_history`, never
   deterioration). The CT contract version joins that gate: complete-under-v0 vs
   complete-under-v1 is `not_comparable` by default. Whether complete-with-degradations compares
   with clean-complete WITHIN a version is a founder row (§9).

## 7. Acceptance matrix

**Pinned two-layer rule (applies to EVERY row below and to every policy-option table in
§8):** each case is stated as **(i) the CT evidence-contract contribution** and **(ii) the
resulting overall `scan_quality`, which follows only if every OTHER mandatory evidence
contract is also satisfied**. A CT outcome alone never determines the overall grade —
other modules may independently be incomplete/skipped/errored — and the lifecycle
`scans.status` (`completed`/`failed`) is independent of both layers. "Blocked" always
means fail-closed with explicit wording, never silence.

| # | Case | (i) CT contract contribution → (ii) overall outcome |
|---|---|---|
| 1 | crt.sh ok + CertSpotter ok | (i) CT contributes no degradation; two-source absence eligibility earned. (ii) Overall `complete` **only if every other mandatory contract also passes**; band per normal rules |
| 2 | crt.sh unavailable + CertSpotter usable positive evidence | (i) A/today: `ct_source_degraded` incomplete flag — forces overall `partial` regardless of every other module. B: degradation entry `{dependency: ct:crt_sh, claim_effect: absence_claims_blocked, fallback_publishable: true}`; positive findings publish; absence/healthy/removed blocked; band per §4.4. D: same degradation entry, CT contribution re-classified as `degraded`-grade. (ii) B: overall `complete` only if all other mandatory contracts pass. D: overall `degraded` (never better), `partial` if any other contract independently fails |
| 3 | CertSpotter unavailable + crt.sh usable positive evidence | Symmetric to 2 — the contract is provider-agnostic |
| 4 | Both providers unavailable | (i) CT contract blocks authoritative completeness AND all absence claims; `cert-intel` blackout guard fires (`ct_sources_unavailable`); Certificates & Trust cannot read healthy (v2026.07.16-6 guard preserved, mutation-tested). (ii) Overall can never be `complete` under ANY option; lifecycle `scans.status` remains independently `completed` or `failed` |
| 5 | Provider returns unknown/unrecognised result | (i) Outcome coerces to `network_error` (frozen CT-R1 rule); unrecognised degradation fields invalidate the entry. (ii) Legacy path applies — the scan grades as today (`partial` via the incomplete flag); fail closed, never the permissive branch |
| 6 | Provider fails fast (e.g. 404 in 564 ms) | (i) No retry (non-transient); the CT wait consumes only the measured latency of the scan budget (fast-failure trace: cohort scan `7bd83d64`). (ii) No claim is made here about other modules' outcomes or the overall grade — that scan's overall `partial` carries a declared confound (§2.6) |
| 7 | Shared wait, two consumers, same interval | ONE physical attempt, two consumer records (fan-out preserved for attribution); sub-op stamps identical; never counted as two provider events |
| 8 | One consumer caps out while the other completes | ssl deadline fires, promise abandoned NOT aborted; subdomains (12 s cap) still consumes the memoized result; late value never mutates the capped module's published result |
| 9 | Positive finding visible, absence claim closed | A discovered subdomain/takeover/exposure from the surviving provider publishes; "no other subdomains", `no_longer_observed`, `resolved`, quiet-digest wording all blocked while `absence_claims_blocked` is present |
| 10 | Score-contributing evidence missing | No band: `display_rating=null`, BRI band null with evidence-bounded explanation, BRS not persisted (basis contract unmet) — regardless of option |
| 11 | Only strengthening evidence missing | Per approved policy: band may show WITH visible degradation (B), or stays provisional (A); presentation never hides the degradation in either case |
| 12 | Old snapshot / historical rating | Byte-identical; no re-grade, no backfill; historical comparisons refuse the contract boundary |
| 13 | Alert / weekly digest during degradation | No false "resolved/healthy": recovery-class events and `complete_assessment` quiet wording gated on absence-claims eligibility, not on scan_quality alone; alert wording states the degradation |
| 14 | Soft-deleted workspace | No new scans, snapshots, degradation records, telemetry rows, alerts, or digests — existing lifecycle guards apply to every new artefact this design adds |
| 15 | Cross-tenant / non-enumerating contract | `degradations[]` and any new read surface are workspace-scoped, tenant-isolated, non-enumerating (foreign/nonexistent → same safe response); CT telemetry remains internal-only (Evidence-Grade Law scope boundary: operational telemetry is not customer evidence) |

Proof obligations per the Detection Depth Law (four proofs) apply to whichever option
ships: deterministic fixture, mutation proof (including "corrupt completeness guard →
red"), end-to-end pipeline trace, founder-controlled live acceptance. The existing
mutation suites (`validate-probe-evidence-honesty.js` §5, `validate-ct-blackout-evidence-honesty.js`,
`validate-shared-ct-provider-cache.js`) define the bar and must survive unweakened.

## 8. Policy options for founder decision

### Option A — Status quo: any CT provider loss ⇒ `partial`

- **Evidence honesty:** maximally conservative; no claim rides on degraded coverage.
  `scan_quality` legitimately describes **execution AND evidence coverage together**
  (`assessment-presentation.js:25-28` [OBS]), so grading provider evidence degradation
  `partial` is not a vocabulary violation. It is, however, **conservative but coarse**
  [INF]: the produced grade cannot distinguish "checks did not run" from the narrower
  "one corroborating provider was unavailable while execution completed", and it currently
  contradicts the code's own stated CT invariant (§2.6 — a consistency defect regardless
  of which policy is chosen).
- **Score/band:** suppressed (rating null) whenever one external dependency blips.
- **BRS:** not persisted; workspace shows `latest_incomplete` through any provider outage.
- **Comparisons:** all customer change events (including certificate events) suppressed
  for the outage's duration — a multi-week crt.sh outage silences the posture timeline
  entirely [OBS: 15/15 cohort, zero complete scans since 28 Jul].
- **Alerts/digest:** digest can never say "stable"; alert wording says partial.
- **Customer comprehension:** customer copy derived from `partial` **may imply** that
  checks did not run when the narrower true condition was provider evidence degradation
  [INF] — imprecise wording during provider outages the customer cannot influence.
- **Operational cost:** zero (no change). Ongoing cost: chronic partial rate whenever any
  provider degrades; free-scan conversions see null scores.
- **Migration/API compatibility:** none needed. **Rollback:** n/a.

### Option B — Mandatory/strengthening distinction: usable fallback ⇒ eligible for `complete` + structured degradation

(Per the pinned two-layer rule (§7): CT ceasing to block completeness makes the scan
*eligible* for `complete`; the overall grade still requires every other mandatory
evidence contract to pass.)

- **Evidence honesty:** honest in both directions — positive evidence publishes, absence
  claims stay closed (§4.3), the limitation is structured, versioned, and visible in every
  surface that today shows quality. Requires the §4 contract to exist first; without it
  this option is just relabelling.
- **Score/band:** shown per the band rule (§4.4) — never above the achieved evidence.
- **BRS:** persists when the basis contract (a versioned successor of
  `complete_scan/v1`) is satisfied; the basis names its degradations.
- **Comparisons:** timeline recovers during single-provider outages; comparability rules
  within/across contract versions are explicit founder rows (§9).
- **Alerts/digest:** quiet wording gated on absence-eligibility, not raw quality; no false
  resolved/healthy (acceptance rows 9/13).
- **Customer comprehension:** best long-term ("assessment complete; one corroborating
  source was unavailable; findings unaffected; absence claims deferred") but requires
  disciplined wording work across ~17 backend and ~9 frontend surfaces (§2.7 table).
- **Operational cost:** highest — evidence contract artefact, snapshot addition,
  presentation changes, wording, four-proof suite per the Detection Depth Law, live
  acceptance. Multiple focused PRs.
- **Migration/API compatibility:** additive only (new snapshot field, new API fields);
  `scan_quality` values unchanged; no D1 migration strictly required for the policy itself
  (degradations ride the snapshot JSON) — a queryable D1 projection would be a separate
  founder-gated additive migration.
- **Rollback:** contract-version gate makes rollback clean: stop emitting
  `ct-completeness/1`, new scans grade under the old rules, no history rewritten.

### Option C — Module-scoped partial: overall scan vs CT module coverage separated

Keep `scan_quality` as the *execution* grade (complete iff everything ran) and move ALL
evidence limitation — including today's CT-driven `partial` — into per-module/per-signal
coverage read by consumers that care.

- **Evidence honesty:** cleanest conceptual split (execution vocabulary vs evidence
  vocabulary — the exact two-vocabularies lesson), and closest to the existing per-signal
  machinery (`signal-monitoring-state`, per-domain `required` lists, SPF-diff exception).
- **But** [OBS]: 16 backend `scan_quality='complete'` query sites and the entire
  comparability lattice key on the scalar today. Option C re-points every one of them at
  per-module coverage — the largest consumer-migration surface of the three, with the
  highest risk of a missed consumer silently treating "executed" as "evidenced" (the
  precise false-healthy class this platform keeps finding: #105, #344, free-scan, Phase-5).
- **Score/band/BRS/comparisons/alerts:** each must define its own coverage predicate —
  power and risk in equal measure.
- **Operational cost:** highest total; effectively Option B plus a semantic change to
  `complete` itself.
- **Migration/API compatibility:** `scan_quality` stops meaning "evidence complete" — a
  breaking semantic change for API consumers even if the values look identical; requires
  its own contract version and consumer-by-consumer cutover.
- **Rollback:** hard — once consumers read per-module coverage, reverting to the scalar
  is a second migration.

### Option D — Existing `degraded` status + structured degradations[] (lower-risk than B/C)

Re-route the CT single-provider loss from `partial` to the **already-existing** `degraded`
status, and attach the same structured `degradations[]` entries as Option B. No new
vocabulary is produced: `normalizeQuality`'s contract comment already reserves the value
for exactly this class ("degraded evidence sources are 'degraded'",
`assessment-presentation.js:25-28`), `buildScanQuality` already emits it for
warning/skip-only scans, and ScanDetail already has a `status === 'degraded'` banner
branch (`ScanDetail.jsx:1103`).

**D is NOT producer-only and NOT risk-free.** The re-grade changes the value seen by every
consumer that tests the literal `'partial'` instead of `!== 'complete'` — and those
consumers include fail-closed gates: `asm-cases.js` `moduleCompletionGate`
(`scanPartial = scanQuality?.status === "partial"` at `:485`, driving `canVerify()=false`
at `:492`) and the website-security `unknown_reason = 'scan_partial'` selection
(`website-security-lifecycle.js:251-259`) would silently stop matching, LOOSENING a
verification gate on a degraded scan. [OBS: the §2.7 inventory found gates keying on both
patterns.] D is therefore "lower-risk than B/C" — no `= 'complete'` filter changes
meaning — never "near-zero risk".

**Mandatory implementation gate for D** (all five before any re-grade ships):

1. **AST-backed exhaustive literal-status consumer inventory** — every comparison against
   the literal strings `'partial'`/`'degraded'`/`'complete'` across workers/, frontend/
   and scripts/, found by AST matching (the Track A TS-AST guard is the precedent), not by
   grep sampling.
2. **Equivalent fail-closed behaviour** — every gate that treats `partial` conservatively
   must treat `degraded` at least as conservatively, by explicit code change or proven
   pre-existing handling; no gate may become more permissive.
3. **Behavioural fixture per gate** — each inventoried gate gets a fixture proving its
   behaviour on a `degraded` scan equals its behaviour on a `partial` scan.
4. **Mutation proof** — mutants that let `degraded` escape a `partial`-only gate (e.g.
   reverting a `["partial","degraded"].includes(...)` back to `=== "partial"`) must be
   killed by a targeted assertion, per the Detection Depth Law's "corrupt completeness
   guard → red" requirement.
5. **Joint rollback plan** — the producer classification AND every consumer adaptation
   revert together as one unit; reverting only the producer would leave consumers
   accepting a value that no longer occurs (harmless) but reverting only consumers would
   re-open the loosened-gate defect. Rollback is a planned, tested step — not trivial.

- **Evidence honesty:** the overall assessment stays **provisional**; the final band and
  every comparison stay **closed** exactly as today (`display_rating` nulls on any
  non-complete quality; `assessTimelineComparison` gates on `complete`); but the wording
  stops implying that checks did not run and states the true provider-degradation
  condition.
- **Score/band/BRS/comparisons/digest:** every `= 'complete'` filter still excludes the
  scan; workspace BRS still does not persist; the digest still refuses quiet wording; the
  posture timeline is NOT recovered. The grade label, the degradation record, and the
  literal-`'partial'` gate adaptations change.
- **Customer comprehension:** materially more precise wording than A; does not deliver
  B's timeline/BRS/digest recovery during provider outages.
- **Operational cost:** lower than B or C but real — producer classification
  (`ct_source_degraded` ⇒ `degraded` in `buildScanQuality`), `degradations[]` emission,
  wording, PLUS the full five-point implementation gate above (inventory, consumer
  adaptations, fixtures, mutation proofs, joint-rollback rehearsal).
- **Migration/API compatibility:** `degraded` is already a legal produced value with
  existing reader handling; no D1 migration. API consumers that switch behaviour on the
  literal value need the same inventory treatment.
- **Historical:** old partials stay partial; no re-grade of history; comparisons
  unaffected (both grades are non-complete).
- **Relation to B:** D is a strict subset of B's machinery and a natural staging step:
  ship the vocabulary honesty and the degradations[] channel first, collect the canonical
  report's data gate, then decide B's completeness re-grade on real numbers.

### Recommendation (explicitly marked, non-binding) [INF]

**Option D now — gated on its five-point implementation gate — with Option B as the
evaluated destination.** D fixes the one defect provable from current evidence (imprecise
degradation wording riding on a coarse grade) without changing the meaning of any
`= 'complete'` filter; its risk is bounded and enumerable (the literal-`'partial'` gate
inventory), unlike B's consumer-wide semantic change. B — the completeness re-grade that
would recover timeline/BRS/digest behaviour during single-provider outages — stays gated
on the canonical report's data-collection gate and the D5/D6 rulings; deciding it now
would outrun the evidence. C is not recommended: it maximises the missed-consumer
false-healthy risk across 16+ query sites for benefit B already captures; its
execution/evidence separation is better adopted as vocabulary inside the contract. This
is a recommendation only; no part of it is decided.

## 9. Founder decision table

| # | Decision | Options | This design's marked lean |
|---|---|---|---|
| D1 | Completeness policy | A (status quo) / B (complete + degradation) / C (module-scoped) / D (existing `degraded` + degradations[]) | D now, subject to D's five-point implementation gate; B as evaluated destination (§8) |
| D2 | Two CT sources for subdomain discovery: mandatory or strengthening? | mandatory / strengthening-for-positive + jointly-mandatory-for-absence | the latter (§4.1) |
| D3 | Single-provider positive findings publishable? | yes / no | yes (already live; ratify) (§4.2) |
| D4 | Single-provider absence/healthy/removed/resolved claims? | allowed / blocked | blocked (§4.3) |
| D5 | Band rule (§4.4) | adopt / adapt / reject | adopt, with per-module score-input classification inside the versioned contract |
| D6 | Does complete-with-degradations compare with clean-complete WITHIN one contract version? | comparable-with-caveat / not_comparable | undecided — needs the data gate; default fail-closed (`not_comparable`) until ruled |
| D7 | Does workspace BRS persist off a complete-with-degradations basis? | yes (new basis contract version) / no | follows D1+D5; if B, yes with explicit basis degradations |
| D8 | Weekly-digest quiet wording key | `scan_quality='complete'` (today) / absence-eligibility | absence-eligibility (strictly stronger; never quieter than today) |
| D9 | Managed-case verification gate granularity | whole-scan (today) / per-module with CT-absence closed | per-module (§2.7 row 15); CT-dependent absence verification stays closed |
| D10 | D1 projection of degradations (queryable table) | snapshot-JSON only / additive migration | snapshot-only first; migration is a separate founder-gated step |
| D11 | Numeric thresholds (timeouts, failover order, per-consumer bounds) | — | **explicitly NOT decidable now** — blocked behind the canonical report's data-collection gate |

No decision in this table is taken by this document. The engineering candidates in §5 are
policy-independent but still ship only inside founder-approved episodes.

## 10. Residual uncertainties

1. The cohort evidence window is 4 days / 3 founder domains; whether crt.sh's failure
   pattern is provider-side instability or environment-correlated cannot be excluded
   (canonical report §B.2). The data-collection gate governs.
2. `dmarc_external_rua` skip reasons are not persisted to D1, so one cohort scan's partial
   grade has a declared confound (report §2.5); this design's per-module contract would
   make such confounds attributable, but cannot resolve the historical one.
3. Sub-op telemetry persistence remains marker-less
   (SUBOP-TELEMETRY-PERSISTENCE-OUTCOME); a zero-row scan is indistinguishable from
   not-attempted. Observability debt, tracked in the canonical report.
4. The "score-contributing vs strengthening" classification for subdomain-derived score
   inputs (§4.4) needs a per-input audit of `scoring.js` consumption before D5 can be
   implemented honestly; that audit is implementation-phase work.
5. Two pre-existing frontend-side verdict derivations (`websiteSecurityDisplay.js:65`,
   `CyberMotDomains.jsx:33`) and the quality-blind surfaces (scan list, Domain History,
   posture timeline points, Exposure Timeline, `ScanDetail` comparison panel) are recorded
   debt that any option inherits; Option B raises their priority.
6. The `cache_state` hard-bind at `scan-engine.js:369` will silently swallow real cache
   states if a cross-scan cache ever lands (§5.5) — must be fixed in that future change,
   not this one.

---

*This document is design-only. No runtime, frontend, Worker, schema, migration, CI,
deployment configuration, CHANGELOG or tag change accompanies it. Reviewer role is
read-only. Implementation, thresholds, and live acceptance are separate founder-gated
steps under the Detection Depth Law status ladder.*
