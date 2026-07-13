# Codex build brief — DMARC impact forecast + post-change impact monitor

> Owner: Codex builds · Claude reviews · Turhan approves deploy. **MEDIUM risk.**
> Scorecard epic **#2** (`docs/DMARC-MATURITY-SCORECARD.md`, report areas #3 + #6).
> Builds directly on epic #1 (auto sender classification, now live): the whole
> point is to separate **legitimate** mail from risky mail when quantifying impact.

**Branch:** `feat/dmarc-impact-forecast` off `main`.

## Goal (one sentence)
Answer two questions the product currently can't: **before** a policy change —
"advancing to `reject pct=X` would affect ~N messages (Y%), including M from
legitimate senders"; and **after** a change — "did legitimate mail delivery get
worse?", feeding an honest rollback recommendation.

## Why this needs epic #1 (classification)
"Affected messages" alone is a raw fail count and is misleading — most failing
mail is exactly the spoofing you WANT to block. The number that matters is
**failing mail from senders classified legitimate**
(`authorised | likely_authorised | forwarder | mailing_list`). Epic #1 put
`auto_classification` (+ `classified_at` manual override) on
`email_sender_sources`; this engine joins it to the aggregate data to compute the
legitimate-impact number.

## Grounded building blocks (reuse)
- **Raw material:** `dmarc_aggregate_records` (per source_ip, per report):
  `source_ip, message_count, disposition, spf_aligned_result, dkim_aligned_result,
  header_from, ...` (keyed by `workspace_id, domain, source_ip`). Its time window
  comes from the parent `dmarc_aggregate_reports.date_range_begin/end` (the actual
  mail period — records carry only `created_at` = ingest time; reports arrive with
  lag, so **window by `date_range_begin`, not `created_at`**, joining records→reports).
- **Classification join:** `email_sender_sources` keyed by
  `(workspace_id, domain, source_ip)` → `auto_classification`, `classified_at`,
  `classification` (manual). Effective classification = manual when `classified_at`
  set, else `auto_classification` (mirror `emailSenderToApi` in `rua-routing.js:144`).
- **Existing pattern to extend:** `getHostedDmarcPassRate(env, ws, domain, {sinceDays})`
  (`engines/hosted-dmarc.js:660`) already windows `dmarc_aggregate_records`.
- **Change markers on `hosted_dns_entries`:** `last_change_at`, `pass_rate_at_change`
  (snapshot at commit, `hosted-dmarc.js:779`). Current rollback trigger:
  `shouldAutoRollback({baseline_pass_rate, current_pass_rate, total_messages})`
  (`:652`) — pass-rate drop only; you'll add an impact-aware assessment alongside it.
- Readiness engines that will surface the forecast: `evaluateRampReadiness`
  (`hosted-dmarc.js`), `buildDmarcEnforcementReadiness` (`rua-routing.js:45`).

## The design — new `engines/dmarc-impact.js`

**Constants (named, config-ready):** `IMPACT_MIN_MESSAGES` (e.g. 50),
`IMPACT_WINDOW_DAYS` (7), `ROLLBACK_LEGIT_FAIL_PP` (e.g. 2), `LEGIT_CLASSES =
{authorised, likely_authorised, forwarder, mailing_list}`.

### 1. `forecastPolicyImpact(env, ws, domain, { targetPolicy, targetPct, windowDays })`
For a proposed `(targetPolicy, targetPct)`, over the window (join records→reports,
window by `date_range_begin`), per source_ip:
- `total_messages`, `failed_messages` (neither SPF- nor DKIM-aligned), effective
  classification.
- **Affected** = messages the policy would act on = `failed_messages × targetPct/100`
  (pct is the % of failing mail DMARC applies the action to; `none` → 0).
- Return:
  - `affected_messages`, `affected_percentage` (of total),
  - `legitimate_affected_messages` (affected, from LEGIT_CLASSES) + a
    `legitimate_affected_senders[]` list `{source_ip, provider, classification,
    affected}` — the "who gets hurt" breakdown,
  - `risky_affected_messages` (affected, from unknown/suspicious/unauthorised — the
    mail you WANT blocked),
  - `window_days`, `total_messages`, `insufficient_data` (true when
    `total_messages < IMPACT_MIN_MESSAGES` — then DO NOT emit a confident number).

### 2. `comparePolicyImpact(env, ws, domain, { changeAt, windowDays })`
Before window `[changeAt - windowDays, changeAt)` vs after `[changeAt, now]`,
each computed over records whose report `date_range_begin` falls in the window:
- per window: `total`, `aligned_rate`, `failed_rate`, `legitimate_failed_rate`
  (failed mail from LEGIT_CLASSES / total).
- `delta`: `legitimate_failed_rate_increase = after.legitimate_failed_rate -
  before.legitimate_failed_rate`, plus aligned/unknown-volume deltas.
- `insufficient_data` when the AFTER window has too few messages yet (report lag) —
  be explicit; never call a regression on thin data.

### 3. `assessImpactRollback({ before, after, delta })` → RollbackAssessment
`{ rollbackRecommended, severity (low|medium|high|critical), triggers[],
rollbackRecord? }`. Primary trigger: `legitimate_failed_rate_increase >
ROLLBACK_LEGIT_FAIL_PP` (the report's ">2% legitimate-failure increase", now
computable via classification). This **recommends** — it does not widen automatic
action (see guardrails).

## Wiring
- **Forecast → readiness/recommendation surface.** Add `projected_impact`
  (from `forecastPolicyImpact` for the NEXT ramp step) to the hosted-DMARC GET
  state and the PUT preflight, so the customer sees impact **before** approving a
  tightening. Surface it inside `buildDmarcEnforcementReadiness` /
  `hostedDnsRecordToApi` output — not a new endpoint unless cleaner.
- **Compare + assess → the sweep.** In `runHostedDnsVerificationSweep`
  (`hosted-dmarc.js`), for a `connected` row with a recent `last_change_at`,
  compute `comparePolicyImpact` + `assessImpactRollback`; surface the assessment
  (state/notification), and let it INFORM `shouldAutoRollback` — do not replace the
  conservative existing trigger with a trigger-happy one.

## Guardrails (must hold)
- **Legitimate vs risky via epic #1** — impact that matters is failing mail from
  effective-legitimate senders; respect the manual override (`classified_at` wins).
- **HONEST or nothing** — `insufficient_data` when the window is thin (especially
  the after-window given report lag); never emit a confident impact/regression
  number without the volume to back it. (Same ethos as #1's confidence.)
- **Never break mail flow / blast-radius safety** — the assessment *recommends*;
  auto-rollback stays behind the existing conservative autopilot gate + threshold.
  Do not make rollback trigger-happy. (This is the founder's standing rule.)
- **Additive only** — compute on-demand from existing tables; **no migration**.
  (If a change-time baseline snapshot proves necessary for report-lag robustness,
  it may be ONE additive nullable column `impact_baseline TEXT` on
  `hosted_dns_entries` — additive ADD COLUMN, never DROP — but prefer on-demand.)
- **Tenant-isolated** — every query scoped by `workspace_id` (+ domain).
- **Read-only + deterministic** — same data → same forecast/assessment.

## Deliverables
1. `engines/dmarc-impact.js`: `forecastPolicyImpact`, `comparePolicyImpact`,
   `assessImpactRollback` + named thresholds.
2. Wire `projected_impact` into the hosted-DMARC readiness/state output
   (`routes/email-protection.js` + `engines/rua-routing.js`/`hosted-dmarc.js`).
3. Wire `comparePolicyImpact` + `assessImpactRollback` into
   `runHostedDnsVerificationSweep`, informing (not replacing) `shouldAutoRollback`.
4. Frontend: show projected impact before a tightening ("advancing to reject would
   affect ~N msgs / Y%, incl. M from legitimate senders: …") and the post-change
   assessment on the managed-DMARC card.
5. **`scripts/validate-dmarc-impact.js`** (CI-wired): forecast math (affected +
   legitimate breakdown + pct scaling); `insufficient_data` on thin windows;
   before/after compare detecting a legitimate-failure increase AND not
   false-positiving when stable; `assessImpactRollback` recommends past threshold
   only; uses `auto_classification`/manual-override to split legit vs risky;
   tenant isolation. *(Also advances scorecard #4 — the managed flow's test-proof —
   by driving ingest→classify→impact.)*

## Validation gate (all green before PR)
```bash
node --input-type=module --check < workers/scan-api/src/index.js
node scripts/validate-dmarc-impact.js
node scripts/validate-sender-classification.js   # #1 untouched
node scripts/validate-pipeline.js                # sweep wiring intact
node scripts/validate-regression-fixtures.js
node scripts/validate-migrations.js
node scripts/validate-tenant-isolation.js
cd frontend && npm run build && cd ..
cd workers/scan-api && npx wrangler deploy --dry-run && cd ../..
```

## PR
Focused, one logical change. Title:
`feat(email): DMARC policy impact forecast + post-change monitor`.
Do not deploy (Claude reviews — focus: legitimate-vs-risky split honoured, honest
insufficient-data, blast-radius safety on the rollback recommendation, additive/
no-migration, tenant isolation; Turhan approves deploy). **Stop and report** if it
needs a destructive migration, if it would make auto-rollback more aggressive
without explicit gating, or if it needs to change the DMARC parser/dedupe/#1
classification columns.
