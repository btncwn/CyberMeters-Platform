# Pre-Beta Frozen Execution Backlog

**Status:** ACTIVE CANONICAL EXECUTION ORDER — historical item contracts preserved;
current rescue queue updated 30 August 2026.
**Authority:** this document alone ORDERS current and remaining pre-beta work.
Roles and decision rights live only in `docs/AI-EXECUTIVE-OPERATING-MODEL.md`.
Strategic scope and acceptance gates remain in
`docs/ROADMAP-TO-FIRST-PAYING-CUSTOMER.md`; detection engineering policy remains
in `docs/DETECTION-QUALITY-ROADMAP.md`; release facts remain in `CHANGELOG.md`.

Production baseline at freeze: `main @ bfc7c1d` · live Worker `ecd03d0a`
(v2026.07.21-5, deployed 2026-07-21T21:28Z) · rollback `d1ad62b8` · latest migration `098`.

Labels: **[ACC]** acceptance-only (already built/deployed — needs live acceptance, not
re-implementation) · **[IMPL]** implementation work · **[DES]** design-first.

## Current rescue gate and canonical order — 30 August 2026

The 30-August rescue operation is a bounded recovery of customer actionability,
runtime reliability, CI duration and release/audit integrity. It is not a new
feature programme and it does not erase the frozen item contracts below.

**Founder conditional HOLD decision — RECORDED, NOT YET CONSUMED (30 August
2026).** The bounded operating-model §3 pre-authorisation is preserved in the
[append-only decision receipt](governance/2026-08-30-rescue/founder-conditional-hold-preauthorization-2026-08-30.md).
It grants no current release, deploy, pilot or acceptance credit: every existing
technical gate, the exact-candidate nine-condition Governance `ACCEPT`, rollback
proof and the relevant staged live evidence remain mandatory. Production and
customer/pilot `HOLD` remain active until their respective hard stage is green.

Measured state:

- recovery base `integration/audit-recovery-final-20260826 @ a970def2`; rescue
  changes are committed in separate candidate PRs but remain unmerged, unshipped
  and **not Live**;
- production source identity reconciled to `47d9bb39`; the after-the-fact
  `v2026.08.26-2` CHANGELOG record is present with zero acceptance credit, while
  its non-backdated annotated tag remains pending Integration;
- R2 entitlement and read integrity are restored; the controlled write/read/delete
  canary remains open;
- the historical production report/snapshot/PDF trace is authentic and exposed
  customer-actionability, report-ordering and Phase-5 runtime failures;
- historical rescue evidence records that the first runtime Phase-5 candidate
  failed Governance review and corrected A1 v2 also received an independent
  **FAIL** on true whole-invocation enforcement and physical-budget telemetry
  provenance. Subsequent bounded runtime, evidence-admission, DSE and CX
  correctives have focused and independent review evidence in candidate PRs. The
  explicit DSE `finding_type`, severity and canonical-domain admission blocker is
  closed only in candidate bytes; none of this is Live. Integration, required CI,
  production proof and release acceptance remain open;
- the current evidence-admission convergence keeps CAA, HSTS and DNSSEC as
  observations with no action; admits only definitive-absent MTA-STS as a low
  actionable finding; and keeps the observed CSP `style-src 'unsafe-inline'`
  shape low/observation/no-action. These are candidate contracts, not Live facts;
- the prior serial developer-blocking CI path measured a 28.73-minute median and
  30.10-minute p95. PR #451 merged fail-closed sharding to `main` without deleting
  assurance; natural cold/cache-miss proof, the required `main` timing sample set
  and full release acceptance remain open;
- two `scan_completed` rows for one scan exposed an open audit exactly-once and
  scan-owner scoping defect. Existing append-only rows remain untouched.
- the preserved P1 audit measured a bidirectional false-conclusion inventory of
  **43 producers** at its dated evidence boundary. This is a historical measured
  fact, not a claim that the current producer count is still 43; remeasurement
  remains part of the preserved P1 work after the rescue gate.

Execute only this order:

```text
[freeze the exact rescue candidate + keep docs and feature changes disjoint]
→ [bounded evidence-admission / runtime / CX corrective
   + scan-completion audit exactly-once corrective]
|| [risk-based local/PR CI sharding + independent mutation/release assurance]
→ [integration; focused, tenant/security and full sharded gates
   within the measured duration boundaries]
→ [exact-candidate Governance audit-recovery decision]
→ [Executive release preparation, merge/deploy/rollback proof and
   company-controlled production proof only if every required gate is green]
→ [resume the preserved P1 / FD-007 / full FD-008 / Items 12–18
   + Item 19 sequence below]
```

Production/customer state remains `HOLD`. No new scanner breadth, migration,
customer activation, pilot, public claim, broad cleanup, GTR reopening or later
item mutation is authorised by this rescue order. The separate Founder decisions
remain public Assisted/Automated language, any material roadmap timebox change and
the eventual controlled-pilot/customer HOLD boundary.

## Preserved predecessor order — 24 August 2026

This was the immediately preceding queue and remains the preserved source of the
join and later-item order. The dated package under
`docs/governance/2026-08-23-gtr7-competitor-first-successor/` is immutable source
evidence for how this order was reached; it has no current operating authority.

```text
[GTR-4 = terminal technical HOLD at successor-8
 + GTR-6/GTR-7 = PROGRAMME HOLD until after beta
 → no retry, successor-9, install, observer or technical-PASS credit
 → Founder risk acceptance terminates this lane for this pre-beta JOIN only]
||
[AS-B2 STOP/AMEND + corrected isolated preparation/authoring (zero credit)
 + AS-B6 read-only remeasurement
 → Executive R1 dispatch → controlled-live accepted 4/4 operational shame closure]
||
[fresh-clone armour → idle boundary → verified ~/dev cutover
 + independently restored external-disk transport backup]
→ JOIN
→ exact-candidate audit recovery + one Governance decision against the preserved
  cumulative nine-condition gate
→ preserved P1 / FD-007 / full FD-008 / Items 12–18
 + pre-existing Item 19 aggregate source-fidelity law
```

**Governance status correction — 24 August 2026:** GTR-4 did not technically
pass. Under the current Founder scope cut and the terminal Governance
disposition, GTR-4, GTR-6 and GTR-7 are removed from the active pre-beta queue
and held until an explicit after-beta reopening. This is risk acceptance, not
technical acceptance. For this JOIN only, the terminal HOLD satisfies the
lane-termination input; it does not authorise a retry, acquisition, installation,
observer activation, GTR-6/GTR-7 work, release, deployment or customer
activation. Frozen GTR evidence remains unchanged.

Production/customer state is `HOLD`. The former 2026-09-01 recovery-candidate
target is a reforecast checkpoint. Historical `ACTIVE` labels below mean active
at their dated freeze/reconciliation point; they are not current queue authority.
No new governance successor package is required for work already named in this
order. Claude Desktop dispatches it under R0/R1; Governance adjudicates only the
named GTR/audit gate or a material authority conflict.

---

## Corrections captured at freeze (do not re-litigate)

1. **Pricing is LOCKED, not open.** Every earlier pre-lock price ladder (including the
   higher-priced "Talk to us"-MSP variant) is **RETIRED** — never resurrect one or treat
   it as a competing policy (the figures are deliberately not repeated here; the
   commercial-canonicalisation guard enforces this). Canonical ladder per
   `docs/PRICING-POLICY.md`:
   Trial £0 · Starter £9.99 · Professional £19.99 · Business £49.99 · MSP £99.99+.
   Remaining pricing work is **production lockstep only** (policy ↔ backend registry ↔
   PricingPage ↔ Stripe products/prices ↔ checkout ↔ portal ↔ trial/cancellation/VAT/legal
   copy). Report drift only against the locked ladder.
2. **The PDF problem is content depth, not renderer failure.** No evidence exists of
   blank pages, zero-byte PDFs, R2 corruption or renderer crashes. The founder concern is
   that generated PDFs are **too shallow relative to the evidence the platform holds**.
   The former "empty-PDF root-cause audit" is replaced by the
   **Executive PDF Content Depth & Context Completeness Audit** (item 6).
3. **Closed items removed:** the certificate evidence-insufficient and DMARC
   could-not-be-observed punctuation/template defects were closed by PR #218
   (`v2026.07.20-7`, `pdfEsc` transliteration). Reopen only on a NEW failing artefact.
4. **Shadow IT Alert Trust is DEPLOYED** (#211/#213, v2026.07.20-4/-5) —
   remaining work is **controlled live acceptance**, not re-implementation.
5. **No stale deployment facts.** #263 is DEPLOYED (v2026.07.21-5); SSL external latency
   28s → ~8.4s verified live. `d1ad62b8` is the rollback baseline, not live.

---

## Frozen execution order — preserved base under the 23-August overlay

### 1. Post-#263 authenticated workspace scan acceptance — [ACC] · ACTIVE AT FREEZE (HISTORICAL)
The first post-fix scheduled scan of `blackbullbarbers.co.uk` is
**2026-07-22 19:00 UTC** (the 2026-07-21 19:00:08 scan pre-dated the 21:28Z deploy and
ran on the old Worker).

**Pre-fix baseline (scan_ff98eb61, 2026-07-21 19:00:08, old Worker — recorded for the
comparison):**

| module | outcome | duration |
| --- | --- | --- |
| ssl | ok | **28,423 ms** (sequential CT — the driver) |
| headers | incomplete | 20,001 ms |
| subdomains | ok | 12,000 ms |
| technology_detection | error | 10,000 ms |
| whois_intelligence · dns_bruteforce · email_security · dns | ok | ≤1.3 s |
| asset_exposure · cloud_storage_discovery · cve_intelligence · email_security_intelligence · known_exploited_vulnerabilities · subdomain_takeover | **deadline_exceeded** | never ran |

**Acceptance checks:** scan completes; `scan_quality`; the full previously-starved set
above actually runs; ssl/subdomains/headers/technology/takeover/SPF-email module
outcomes; telemetry durations recorded; no deadline starvation; comparison against the
last complete scan; alert/event/case production unbroken; **a fresh Executive PDF is
generated from this scan and handed to item 6**.

**Verdict (one of):** `PASS` · `PASS WITH RESIDUAL DEGRADATION` · `FAIL — DEADLINE` ·
`FAIL — PROVIDER / MODULE`.

### 2. Global 21-second deadline replacement — [IMPL]
Retire the 21s global cap in `scan-budget.js` per the #267 audit. Not unlimited: an
invocation ceiling per real Workers Paid limits; per-fetch timeouts preserved;
per-module timeouts; safe finalize/persist reserve; stuck-promise tests; deadline
telemetry; explicit CPU vs wall-clock model; cron vs HTTP invocation assessed
separately. Acceptance: deterministic deadline fixtures · mutation proof · complete
scan · partial scan · provider timeout · finalisation still persists · no false
healthy · no missing telemetry.

### 3. SPF per-signal evidence completeness — [IMPL]
Change detection per signal, not per scan: previous and current SPF evidence complete →
compare resolved sets; unrelated SSL/CT/subdomain partial never silences the SPF event;
incomplete SPF never produces a change. Rollout order after SPF: DMARC → certificates →
headers → subdomains → asset exposure → takeover → technology → Brand candidate
activity.

### 4. SPF controlled live acceptance — [ACC]
Code is DEPLOYED (v2026.07.21-4). Controlled, reversible root change on
`v=spf1 include:secureserver.net -all`; child-include change with root unchanged;
RUA corroboration (unauthorised source, tier, dedupe, fail-honest wording, no
"malicious" claim); edge cases (cycle, redirect, multiple records, void/10-lookup
limits, TempError/PermError, CIDR v4/v6, `a`/`mx`, nested includes, old-complete vs
new-incomplete suppression).

### 5. Provider isolation + monitoring-degraded customer state — [CLOSED — LIVE]
crt.sh isolation; CertSpotter fallback semantics; shared per-scan CT cache (kill the
duplicate ssl+subdomains lookups); per-provider timeout + health telemetry;
provider unavailable ≠ no findings; provider failure ≠ healthy; bounded
retry/backoff; per-invocation hard timeout + two-attempt ceiling. Canonical beta customer
states: `monitoring healthy · monitoring degraded · signal unavailable · evidence incomplete`
with signal-specific wording ("We could not fully verify certificate transparency data in
this run. Other checks completed normally."). A cross-scan circuit breaker and a cross-run
`recovered` monitoring state are post-beta work, not Item 5 launch blockers; no recovery
claim is made.
**Includes: `cybermeters-email` inbound Worker reliability/security acceptance**
(per-address Email Routing only — never catch-all; DMARC-trust gating; RUA/TLS-RPT
parser safety; header-From trust boundary). Plus the reliability live matrix (fast
healthy · slow TLS · crt.sh down · NXDOMAIN · HTTP timeout · odd DNS · rate-limited
provider · large SPF chain · partial-but-SPF-complete · complete-after-partial ·
no duplicate alert).
**Finding (24 Jul 2026, Gate 5 prep — hosted-DMARC RUA routing drift, monitoring-loss):**
the autopilot manages a customer's DNS RUA token but NOT the matching Email Routing rule, so
DNS can advertise a `cmrua_<hex>@reports.cybermeters.com` mailbox with no route → reports
fall to the disabled catch-all and are silently dropped. cybermeters.com dropped its OWN
DMARC reports this way (published `adfcbad7...`, no rule); contained 24 Jul by adding the
literal rule → `cybermeters-email`. Also an orphan rule `15127b...` matches no live domain.
Product fix owed: autopilot must create/verify the ingest rule on every RUA set/rotation and
reconcile on a schedule (belongs with automation re-enablement — currently Gate-1/2
suspended); clean up the orphan under item 13 after reachability proof. Detail:
[[hosted-dmarc-rua-routing-drift]].

**Founder closure decision (24 Jul 2026): Item 5 launch blockers CLOSED.**

- **Email/DMARC inbound hardening Gates 1–5 — LIVE-ACCEPTED.** Main
  `4f5b2a7c`; scan-api `7e2b91f1`; email `f1308762`, APP_VERSION
  `2026.07.24-gate4.1.8e25b5b44574`; migration 100 applied. Forged inbound evidence
  remains observational/non-authoritative and cannot drive DNS, case verification,
  readiness, business risk or authoritative alerts; the captured genuine Microsoft
  nested-multipart report is accepted.
- **CT-blackout false-healthy P0 — FIXED + LIVE (PR #300).** Main `c296fea7`;
  scan-api `5aea078f` (rollback `7e2b91f1`); email closure rebuild `27e93b06`,
  APP_VERSION `2026.07.24-item5-ct.85f0fefdf9dc` (rollback `f1308762`). A controlled
  total-blackout canary resolves Attack Surface to `evidence_insufficient` /
  `signal_unavailable`, caps the score as provisional and suppresses rating/authoritative
  BRI; the monitoring state reaches the immutable snapshot and Executive PDF path.
- **Founder de-scope:** cross-scan circuit breaker and cross-run `recovered` state move
  post-beta. The per-invocation hard timeout and two-attempt ceiling already bound
  degradation, and CyberMeters makes no recovery claim.
- **Non-blocking follow-up:** direct HTTP 429 and real slow-TLS fixtures; naturally
  observed live CT-blackout evidence with a new production snapshot. Controlled/simulated
  acceptance passed; the natural live event remains pending.

### 6. Executive PDF Content Depth & Context Completeness Audit — [DES→IMPL]
NOT a renderer-failure hunt. Trace: available scan evidence → canonical report
snapshot → selected domain findings → historical changes → Related Changes → managed
cases/remediation → customer narrative → rendered PDF. Assess (founder's 12 questions):
evidence beyond scores; what changed and when; why it matters; affected assets;
confidence/evidence-completeness; unknown/unavailable/not-assessed vs healthy
distinctions; remediation steps; ownership + case status; verification method;
recurrence; meaningful context for **all eight** Cyber MOT domains; MSP/customer
branding without content loss; whether the PDF is merely a poorer summary of the
dashboard. Claude Desktop reviews the fresh post-#263 PDF from item 1. No renderer-corruption
claims without a concrete failing artefact.

### 7. DMARCbis design + runtime remediation — [CLOSED — LIVE-ACCEPTED · PASS WITH BACKLOG]
Founder verdict (26 July 2026): **LIVE-ACCEPTED — PASS WITH BACKLOG**. P1–P6,
migration 101 and both Workers are live. The founder-controlled core run on the
isolated `dmarc-test.blackbullbarbers.co.uk` namespace proved RFC 9989
organisational-policy inheritance (`p=none`), exact-policy precedence (`p=reject`),
legacy `pct=100` preservation without current-policy application, exact-record
removal back to complete/corroborated organisational inheritance, UI/PDF parity and
historical snapshot/PDF integrity. The run did not mutate `cybermeters.com`, the
`blackbullbarbers.co.uk` apex or its production DMARC/email records. It did not prove
receiver enforcement, live RUA ingestion, full RFC 9990 destination authorisation or
every possible DMARCbis scenario.

The following named residuals are explicit backlog. They do not reopen the accepted
Item 7 core unless a future regression affects that accepted behaviour:

#### Backlog 7-A — Full-monitoring DMARC alert acceptance
Prove live automatic DMARC alert creation only when complete monitoring evidence
supports a qualifying actionable regression: strong-to-weaker policy, exact-record
removal that weakens the effective requested policy, invalid/malformed state,
multiple records, deduplication and recurrence after resolution. Incomplete
monitoring evidence must not infer or emit a DMARC change alert and must remain
fail-honest.

#### Backlog 7-B — DMARC managed-case live lifecycle
Prove company-controlled manual case creation from a qualifying DMARC regression;
never auto-open a case. Prove workspace-scoped condition lookup, IDOR protection,
verification only from a later complete scan, recurrence after resolution and
historical case/evidence integrity.

#### Backlog 7-C — RUA destination authorisation
Implement and prove authorised external-RUA validation where applicable. Distinguish
`authorised`, `unauthorised`, `not_assessed` and
`incomplete`/provider-unavailable. Unassessed is never authorised, and a published
`rua` URI never proves report ingestion.

#### Backlog 7-D — Hosted-DMARC routing automation and reconciliation
When separately approved automation is re-enabled, setting or rotating a hosted RUA
address must create and verify the exact corresponding ingest routing rule and
periodic reconciliation must detect drift. Hosted-DMARC remains suspended now.
Orphan routing cleanup remains Item 13 work and must not be silently folded into
this backlog.

#### Backlog 7-E — Child and deep-label RFC 9989 live scenarios
Prove additional company-controlled child and deep-label author domains, inherited
`sp` where applicable, equal-policy inheritance suppression and exact-versus-
organisational precedence across additional label depth. The accepted core run did
not include them because the current Professional workspace had one remaining
domain slot.

#### Backlog 7-F — Second-tenant isolation acceptance
Prove DMARC projection, alerts, cases, verification, snapshots and presentation
under a second workspace/tenant, with no cross-tenant read, write, alert, case access
or evidence leakage.

#### Backlog 7-G — Presentation and minor UX defects
Triage raw or implementation-facing alert vocabulary such as
`boundary_protection` or `secure_configuration` appearing as customer-facing
“Affected Domain”; generic or mismatched alert copy; remaining UI/PDF terminology
inconsistencies; and technical-appendix DMARC data rendered as `[object Object]`.
Any transient or false HTTPS/TLS finding caused by incomplete scan/provider
conditions belongs to the relevant engine and must not be attributed to the accepted
DMARCbis resolver.

#### Backlog 7-H — Full parity and reconciliation expansion
Extend live acceptance beyond founder-reviewed UI/PDF evidence to direct API
projection comparison, D1/R2 evidence reconciliation, alert occurrence rows,
managed-case evidence references, notification occurrence linkage, and repeated-scan
performance/timeout behaviour. Presentation remains backend-owned; renderers must
not independently re-derive DMARC state.

#### Backlog 7-I — Cleanup of isolated acceptance namespace
Do not clean up now. A separately approved task must decide whether to retain or
remove the `dmarc-test.blackbullbarbers.co.uk` Pages custom domain, `dmarc-test`
CNAME, `_cybermeters.dmarc-test` ownership TXT and CyberMeters workspace-domain row.
Preserve acceptance evidence first. Never remove or mutate the
`blackbullbarbers.co.uk` apex, production `_dmarc.blackbullbarbers.co.uk`,
production MX/SPF/DKIM records or `status.cybermeters.com`.

### 8. Brand IDN/homograph — PR-A / PR-B / PR-C — [ACTIVE AT FREEZE · HISTORICAL QUEUE LABEL]
At the 26-July freeze, Item 8 was the next active frozen-backlog item. That is a
historical queue fact, not current authority; this reconciliation starts no Item 8
implementation.

PR-A normalisation + confusable core (NFC, punycode round-trip, mixed-script,
skeleton, allowlists, deterministic fixtures + mutation). PR-B candidate generation +
passive CT/SAN discovery (bounded volume, nested hostnames, dedupe, activity checks,
prioritisation). PR-C lifecycle/customer surface (campaign grouping, first-seen /
reappeared / inactive, DNS/HTTP/TLS + login-surface evidence, case lifecycle, alert
copy, PDF/MSP, fail-honest claims). Live acceptance on controlled fixtures — no
"confirmed phishing" overclaim.

### 9. Certificates & Trust depth + live acceptance
Per-signal completeness (leaf/chain/SAN/issuer/expiry/CT/wildcard/parallel/active
service); renewal lifecycle acceptance (bands, renewed, failed, replaced, issuer/SAN
changed, wildcard, dedupe, case close/reopen, PDF parity); trust-policy depth (CAA,
chain state, hostname mismatch, weak algorithms, expired intermediate, CT-only vs
live-serving); controlled renewal on a company-controlled host.

### 10. Attack Surface depth + live acceptance
Full module reliability with observed/unavailable/incomplete/absent/resolved/reappeared
distinctions; asset lifecycle trust (first seen → confirmed removed → reappeared,
DNS-only vs HTTP-only, no false "resolved"); the deferred
`www.email.blackbullbarbers.co.uk` alert-quality review (true-positive vs
noisy-but-true vs false-positive — **scoped review; the alert pipeline stays on**);
company-controlled live acceptance (new/removed/reappeared asset, admin surface,
takeover candidate, KEV signal).

### Evidence-integrity interlock — Free-Scan False-Healthy P1

Mandatory, unnumbered interlock in the frozen execution order — **it does not renumber
anything**. Sequenced **after Item 10 P3 and before Item 10 P4**:

```text
Item 10 P3
→ Free-Scan False-Healthy P1
→ SPF CIDR Evidence-Fidelity P1
→ Item 10 P4
```

**Why it interrupts Item 10.** The anonymous free scan can render a green health verdict from
probes that never succeeded. This is the platform's most basic law broken on its highest-traffic,
unauthenticated surface — the same defect class as the `#105` unexecuted-probe P1 that was fixed
in the authenticated path, still live in the public one. It is a **runtime correctness defect,
not copy**: rewording it would conceal it. Surfaced by the Item 17 public-claims audit and
escalated out of it by founder ruling.

**Required behaviour**

- The anonymous free scan must **never** derive `healthy` from a failed, unavailable, incomplete
  or unknown probe.
- `total_findings === 0` is **not** sufficient evidence of health — a zero-finding result over
  incomplete evidence is not a clean result.
- `modules_scanned` must be **derived from actual attempted/completed module state**, never a
  fixed list.
- A four-module free scan must **not** claim "all eight domains" (or any equivalent whole-product
  coverage) anywhere in its copy or CTA.
- `attempted` · `completed` · `failed` · `partial` · `incomplete` · `unavailable` must remain
  **distinct** states end to end — collapsing any pair reintroduces the defect.

**Required proof (runtime correction)**

- Deterministic **failed** and **partial** free-scan fixtures.
- **No-false-healthy mutations** — reintroduce each defect (health from a failed probe; health
  from `total_findings === 0` alone; a hard-coded `modules_scanned`; a collapsed state pair) and
  the suite must go red.
- **Customer-copy parity** — the rendered result, the module list and the CTA agree with the
  evidence actually obtained.

**Gate separation (unchanged by this interlock)**

```text
Engineering merged  ≠  deployed  ≠  controlled live acceptance
```

Each remains a separate gate with its own evidence; none inherits from another.

### Evidence-fidelity interlock — SPF CIDR Evidence-Fidelity P1 (recorded, not implemented)

Recorded here for ownership so it is not lost; **no implementation is authorised by this entry.**

The SPF authorisation-change evidence can currently display a **hex-packed IPv4 CIDR** to the
customer — a customer reads `added 1 [ip4:c0000200/24]` where the real value is
`192.0.2.0/24`. Canonicalised authorisation strings are interpolated straight into the customer
description, so the customer-facing evidence is unreadable rather than wrong-but-legible.

This is a **separate, focused customer-evidence P1**. It is sequenced immediately after the
Free-Scan False-Healthy P1 and before Item 10 P4.

**The two runtime fixes must NOT be combined into one PR.** They touch different surfaces
(anonymous free-scan result derivation vs authenticated SPF posture-event rendering), carry
different proof obligations, and merging them would make either one impossible to review or
revert independently.

### Reliability interlock — Scan Completion Rate: CT Provider Resilience
This is the historical 26-July record of a mandatory, unnumbered interlock in the
frozen execution order. At that measurement boundary, R1, R2 and R3 had not
started. Item 11 has since closed independently; this old edge cannot operate
retroactively or invalidate that acceptance. Any still-unproven CT/availability
obligation transfers to exact-candidate audit recovery and Detection Phase 0,
where current-head state must be remeasured rather than assumed.

**PROVEN**

- Read-only production sample, measured 26 July 2026: 46 scans over the preceding
  seven days; 16 complete and 30 partial; the most recent three days contained
  0 complete out of 12 scans.
- Retrieved scan telemetry attributed the observed partial outcomes to `ssl` and/or
  `subdomains`, the CT-dependent module pair in the current pipeline.
- Provider-level attribution was unavailable because current error telemetry was
  insufficient/null.
- Available measurements do not justify increasing the 19-second whole-scan budget
  as the remedy; duration attribution itself is currently coarse and must be improved
  by R1.

**NOT PROVEN / MUST NOT BE CLAIMED**

- Which CT provider is responsible, or in what proportion.
- That crt.sh or CertSpotter is the demonstrated root cause in CyberMeters production.
- That cross-scan caching will raise completion from 35% to 90%+.
- Any specific failover timeout before R1 telemetry supports it.

**HISTORICAL SEQUENCING AT 26 JULY — superseded prospectively by the 23-Aug overlay**

- Mandatory after Item 10 engineering-complete.
- Was specified as mandatory before Item 11 began; Item 11 is now closed and is
  not retroactively reopened by this historical edge.
- Mandatory before Item 14 controlled security acceptance.
- Does not renumber the frozen backlog.
- Must not run in parallel with Item 10 P2–P5 because the verified collision surface
  includes `scan-engine.js`, `scan-budget.js`, `ssl-scan.js`, `subdomains-scan.js`,
  `certificate-signal-completeness.js` and `reserved-scan.js`.

**R1 — TELEMETRY ONLY**

- Provider name and attempt outcome.
- Timeout/upstream HTTP/status/parse/rate-limit error class.
- Provider latency.
- Fresh cache hit, stale cache available and cache miss.
- Cache age and provenance.
- Exact signal/evidence that lowered scan completeness.
- Honest per-module timing attribution.
- No detection or completeness behaviour change.
- Telemetry must not consume or materially perturb the 19-second envelope it measures.

**R2 — MEASURED BOUNDED FAILOVER**

- Primary provider → measured bounded timeout → fallback provider → measured bounded
  timeout → fresh-enough cache → honest unavailable/incomplete.
- Timeout values must be justified by R1 evidence and must not be pre-baked guesses.
- No provider failure may become absent, healthy or complete.

**R3 — FRESHNESS-GOVERNED CROSS-SCAN CT CACHE**

- Store source/provider, `fetched_at`, freshness ceiling/expiry, query identity,
  canonical result identity, completeness, provenance and fresh/stale state.
- CT freshness ceiling must be a declared per-signal contract value following the
  Item 9 grade-contract pattern, not a hidden magic constant.
- Cache presence alone never promotes a signal or scan to complete.
- Stale evidence is surfaced as stale and never represented as fresh.

**ACCEPTANCE GATE**

- Completion rate improves against a documented pre-deploy baseline.
- No stale evidence is represented as fresh.
- No provider failure becomes absent or healthy.
- No duplicate CT lookup is introduced.
- The 19-second envelope remains intact.
- Non-CT sibling signals remain independently publishable.
- Company-controlled-domain pre/post production evidence is recorded after the
  Executive-approved deploy.

### 11. Website / Identity / Shadow IT domain closures
Three **separately-accepted** sub-items — each is LIVE-ACCEPTED independently and on its
own evidence. There is **no lumped "Item 11 PASS"**; a verdict is recorded per sub-item.
The sub-items are **not equal effort**: 11A and 11B are build-plus-accept, while 11C is
verify-only against already-deployed code (lighter).

**11A. Website Security — [IMPL] + live acceptance.**
Header/technology completeness (fetch-failed ≠ missing; 52x/530; CSP/HSTS/
Permissions/Referrer/XCTO/frame; confidence), change intelligence (added/removed/
weakened/strengthened; false-diff suppression), managed lifecycle acceptance.

**11B. Identity Exposure — [IMPL] + live acceptance.**
Evidence source + scope audit (no dark-web/endpoint overclaim; unavailable ≠
low risk), lifecycle acceptance, wording tiers (observed exposure ≠ confirmed
compromise ≠ validity unknown).

**11C. Shadow IT — [ACC]** (live verification only — already deployed; lighter than
11A/11B). The wording/field-mapping fixes are DEPLOYED (v2026.07.20-4/-5); verify against
the live product (approved-but-owner-missing wording, owner status, evidence source,
affected domain, no workspace-UUID leakage, CTA destination, footer, approved ≠
suspicious, WC ≠ action), then the full approved-inventory acceptance and claim
boundaries (external evidence only).

### Preservation boundary before Items 12–13

Items 12 and 13 and all completed design/evidence artifacts remain preserved
without loss of credit. They resume after the current three-lane join and audit-recovery
gate. Before then, only the specifically authorised read-only Item 13A
reachability instrument may support AS-B6 measurement; it grants no Item 13B
mutation, retirement, deletion, `reserved-scan` activation, merge, deploy, or
acceptance authority.

### 12. Related Changes B2/B3 — [IMPL]
B2 correlation quality (stronger cross-domain rules, bounded temporal windows, evidence
compatibility, duplicate grouping, confidence, contradictions, no causality overclaim).
B3 customer actionability (related-not-caused-by language, owner, case linkage,
remediation ordering, report/PDF, MSP surface, alerting rules). Live scenarios
including the negative control: unrelated simultaneous events must NOT correlate.

### 13. Dead-code & reachability audit — [IMPL]
Classify every file (runtime-reachable / route-only / cron-only / email-only /
test-only / docs-only / legacy / retired / orphan). Vendor/Supply retirement per the
queued canonical episode (Option B — fold honest signal into Shadow IT; preserve data +
pipeline). Frontend surfaces (`VendorsPage`, `WorkspaceSupplyChainPage`,
`ThirdPartyPage`, `SaasExposurePage`, duplicate lifecycle pages) — **no deletion before
reachability proof**.
**Named candidate — `reserved-scan.js` (reserved-mode orchestration):** imported by
`scan-engine.js:46` and conditionally dispatched, but `SCAN_CAPACITY_MODE` defaults to
`legacy` (`scan-budget.js:30`) and is unset in wrangler.toml → **not executed in production**
(flag-gated/dormant, NOT an orphan — the anti-orphan guard sees it as wired). The comment
"legacy until BBB live acceptance passes" marks it a staged experiment, not abandoned code.
Adjudicate one of three, do not just delete: (a) activate + live-accept reserved-mode; (b)
**remove — likely superseded**, since PR-B2's deadline/budget architecture (24s ceiling / 19s
budget / 5s reserve + outbound accounting) probably already solves the subrequest-budget
starvation that reserved-mode was built for; or (c) keep + document explicitly as an
intentional flag-gated experiment. NOTE: `reserved-probe.js` is a DIFFERENT file and is LIVE
(SSRF-safe prober used by asset-intel / brand-http-enrichment / managed-verification) — do
NOT remove it.
**Registry-drift target (noted 24 Jul 2026):** a scan module is registered by hand in four
separate places (`TELEMETRY_TRACKED_MODULES`, `OUTBOUND_FULLY_INSTRUMENTED_MODULES`,
`MODULE_SUBREQUEST_COST`, launch-gate/`canRun`). The reachability audit must confirm every live
module appears consistently in all four (a module launched but missing from telemetry/outbound/
budget/snapshot-downstream is a silent-drift defect). Long-term ideal is a single canonical
`registerScanModule(descriptor)` that derives the four sets — noted as DRIFT DEBT only, not
scheduled now.

### 14. Controlled security acceptance — [ACC]
A6 production viewer spot-check · live Microsoft SSO + MFA-with-SSO · password-reset
revocation · invitation flows · deleted-workspace behaviour · API-token lifecycle ·
case ownership/transitions · branded PDF access. Claude Desktop owns execution;
Founder presence is required only for a human-only action or reserved judgement.

### 15. Independent authenticated pentest (narrow, pre-first-sale)
Auth/session/MFA/SSO · tenant isolation · roles · token scopes · invitation abuse ·
password reset · billing/webhooks · SSRF · report/object access · IDOR/BOLA · rate
limits · business-logic abuse. Full pentest + retest scheduled before public beta;
live DAST acceptance (DOM-XSS founder plan, OAuth callback, viewer enforcement) —
no destructive production actions.

### 16. Legal #232 + Stripe production cutover
Close the founder-gated #232 decisions (entity/sole-trader wording, Terms, Privacy,
DPA, subprocessors, retention/deletion, trial/cancellation/refunds, immediate-start
consent, VAT, auto-renewal, AUP, scanning authorisation, liability, beta wording,
SLA, incident notification). Stripe LIVE cutover under sole-trader Turhan Acar:
live products/prices for the LOCKED ladder, webhook verification, portal
(switch-plans + prorate + ToS/Privacy replicated from sandbox), invoice/VAT display,
cancellation live acceptance. **Requires creating a real entitled MSP account so the
MSP portfolio surface can finally be customer-accepted.**
**This item requires its OWN security acceptance — "Stripe test-mode worked" is NOT
enough.** Going to real money and live webhook secrets opens new IDOR/entitlement/authz
surface. Minimum security-acceptance scope: webhook authenticity + replay · entitlement-
transition correctness · cross-tenant billing access · portal ownership · subscription
downgrade/cancel races · MSP-portfolio authorisation · invoice/billing-email data
boundaries · IDOR/BOLA around billing resources. (The item-15 pentest PASS is then
re-validated against this cutover at item 18 — see item 18.)

### 17. Full public-claims truth audit
Map every public claim to the proven rung of the status ladder
(`DISCOVERED → … → DEPLOYED → LIVE-ACCEPTED → CUSTOMER-CLAIM-APPROVED`); public copy
uses the last proven level only. Forbidden overclaims list enforced (no exhaustive
phishing detection, no confirmed-malicious from lookalike alone, no dark-web /
internal / endpoint claims, no "RFC compliant" without fixture+live proof, no
"continuous"/"real time" where hourly/bounded). Copy parity across landing, pricing,
dashboard, alerts, cases, reports, PDFs, lifecycle emails, legal, MSP materials.

### 18. Final public-beta exit review
All blocks simultaneously green: reliability (items 1–5) · detection depth
(6–12) + reachability & dead-code integrity (13) · **module source-fidelity + freshness
(19)** · security (14–15) ·
commercial/legal (16) · operations (monitoring, backup/
restore drill, incident response, rollback, support) · claims (17). This exit review is
also the **Item-19 aggregate reconciliation** (the two are one gate — see item 19), and
its "final regression/reconciliation" re-checks that every prior acceptance is still valid
against the current build. In particular it **must RE-VALIDATE that the Item-15 pentest
still holds AFTER the Item-16 billing cutover** — a pentest PASS at item 15 can be
invalidated by new IDOR/entitlement/authz surface introduced by item 16's Stripe live
cutover. This re-validation closes via **one of**: an independent-pentester delta retest of
item 16 · a pre-agreed billing-cutover retest scope · an explicit pentester
change-impact review — **NOT internal regression alone** (too weak for the
billing/entitlement surface). **Final reflective step before invitations: re-read the
local-only strategic positioning review**
(`local/STRATEGY-THREE-PILLARS-REVIEW.md`, gitignored per the anti-imitability law) and
confirm the product is going to market as the intended system-of-record + channel, not a
thin scanner wrapper — any pillar whose foundation is not LIVE-ACCEPTED, whose public
claims overclaim, or that the first cohort does not exercise with real events is a
pre-invitation blocker. Then the first two controlled invitations — never an open launch.

### 19. [LAW] Live source-fidelity & freshness acceptance — all 14 probe modules — [ACC]
**Permanent founder law (24 Jul 2026): no scan module is trusted to return correct data
by assumption.** Fixtures prove a module's *logic*; they do not prove it reads the *correct
and current* value from the real external source. This is the source-fidelity + freshness
link of the Detection Depth Law made explicit — it does NOT replace items 3–13, it
consolidates them; do not build a second governance system around it.

Scope: the 14 live probe modules — `dns`, `ssl`, `headers`, `email_security`, `subdomains`,
`technology_detection`, `whois_intelligence`, `dns_bruteforce`, `subdomain_takeover`,
`asset_exposure`, `cve_intelligence`, `known_exploited_vulnerabilities`,
`email_security_intelligence`, `cloud_storage_discovery` — plus the derived
`historical_changes` / identity-correlation phases. Per module, on record:
- **Source correctness** — queries the right authoritative source (authoritative resolver /
  live CT / live cert / current CVE+KEV catalog / live WHOIS / real HTTP), not a stale
  cache, mirror, mock, or silently-degraded fallback treated as truth.
- **Freshness** — feed/cache age is bounded and surfaced; a stale or unreachable source
  yields an honest evidence-insufficient / monitoring-degraded state (item 5), never a
  confident wrong answer.
- **Ground-truth cross-check** — output compared against an independent live oracle
  (dig / openssl / whois / NVD+KEV catalog / curl) on a company-controlled domain, matching
  within a documented tolerance. Divergence is a defect, not noise.
- **Live acceptance** — proven on a company-controlled domain with a real observation, per
  the Detection Depth Law's four proofs (fixture · mutation · e2e trace · controlled live
  acceptance). CI-green is NOT this.

**Precedence:** executes after item 5 closes and **closes PER-ITEM alongside each 7–13
acceptance** — the module's source-fidelity/freshness proof and its independent-oracle
cross-check are recorded as that item is worked, so there is no big data-truth surprise
deferred to the end. The **retroactive Evidence-Grade grading audit** (per
`docs/EVIDENCE-GRADE-LAW.md`) **also folds per-item** in the same way: both cross-cutting
gates close item-by-item, not only at the end. The per-item results are then **consolidated
as one aggregate reconciliation**, which **IS** item 18's exit "final
regression/reconciliation" gate — they are a single gate, not two. **Although
listed last, this is a LAUNCH-BLOCKER — a module returning wrong or stale data is a
materially-misleading security result (harm class 3); it must be green BEFORE the two
invitations, never a post-launch activity.**

---

## Standing release invariants (added at freeze)

- **`workers_dev = true` must survive every deploy** — Microsoft SSO's registered
  redirect URI lives on the workers.dev hostname and it is the rollback path; declaring
  a route silently flips the default to false (recorded 96-second outage). Deploy
  checklist: verify the line is present before `wrangler deploy`, verify
  `cybermeters-platform.ttrnn47.workers.dev/health` after.
- **No stale deployment facts in any report:** live/rollback Worker IDs are read from
  `CHANGELOG.md` (or `wrangler deployments list`) at reporting time — never from a
  prior session's summary.
- Sharp override OV-1 (`docs/DEPENDENCY-OVERRIDES.md`): review 2026-10-31; remove when
  wrangler/miniflare ships sharp ≥ 0.35.0; rerun clean install + build + scheduled
  smoke at removal.
- **No module is assumed correct (founder law, 24 Jul 2026):** every scan module's live
  source-fidelity + freshness is proven against an independent oracle before public beta
  (item 19). Fixtures prove logic, not that the live feed is accurate and current. A module
  returning wrong or stale data is a class-3 launch-blocker, not a backlog nicety.
- **Evidence-Grade acceptance bar (founder law v2, 24 Jul 2026 — `docs/EVIDENCE-GRADE-LAW.md`):**
  the remaining detection items (6 Exec PDF, 7 DMARCbis, 8 Brand IDN, 9 Certs, 10 Attack
  Surface, 11 Website/Identity/Shadow IT, 12 Related Changes) are accepted ONLY when every
  customer-facing signal meets its pre-declared **grade contract** (observable_ceiling /
  beta_target / minimum_publishable / degrade_behavior / required_corroboration). Two axes:
  Evidence Grade L0–L5 + Corroboration Status. Externally unobservable internal signals cap at
  L0-attestation (never dressed up). Every verdict carries `source_type` + standard provenance
  and cites its authority (RFC clause / CIS item / CE·NCSC·ISO control), distinguishing a
  standard requirement from `product_policy`. Reframes the bar; does NOT reorder. Defensibility
  = accurate grading + cited provenance + honest limits, NOT universal L5. First pilot: item 6
  (minimal-viable subset), expand as signals demand.

## Today's honest status line

```text
Platform exists: YES        Core product value exists: YES
Security engineering substantial: YES
Reliability exit gate complete: NO      Detection Integrity Gate complete: NO
Independent pentest complete: NO        Legal/commercial closure complete: NO
Public beta ready: NO                   Engineering finished: NO
```
