# DMARC maturity scorecard — where CyberMeters actually stands vs the "Managed DMARC" report

> Compiled 2026-07-13 from a 5-way evidence-based code audit (data pipeline ·
> sender classification · policy/enforcement engine · DNS change/rollback/workflow
> · alerts/analyst-ops/tests). Every verdict is backed by file:line. Honest, not
> cheerleading.

## Direct answer

**We did NOT "pass" the report — but we are not far, and on one axis we are ahead
of it.** Precisely:

- **Level 1 — DMARC Monitoring: ✅ DONE.** Can honestly be sold today.
- **Level 2 — Guided Remediation: ~2/3 there.** The *hardest engineering* (a
  hosted managed-record flow with a real write-ahead saga, policy ramp, autopilot
  and pass-rate-interlocked auto-rollback + live DNS verification) is genuinely
  built and is **ahead of what the report assumes**. But three Level-2 pillars are
  weak/missing: automated **evidence-based sender classification**, **before/after
  impact** forecasting, and operational **DMARC alerts**.
- **Level 3 — Premium Managed: ~1/5 there.** The defining ops layer (analyst
  review queue, change-management state machine, scheduled deployments,
  incident/SLA, a rollback-assessment engine) does **not** exist.
- **Cross-cutting risk: the managed flow is largely UNPROVEN by tests.** Only the
  RUA XML parser has a harness; the ramp/rollback/reconcile loop and sender
  classification have **no runtime test**, and DMARC resources are absent from the
  tenant-isolation matrix.

The report's own closing line is essentially correct: *"DMARC monitoring + sender
intelligence core exists; guided enforcement and managed change workflow still
need completing."* It only **understates** how much of the DNS-mutation engine is
already done.

## Scorecard by level

| Level | Status | What's real | What's missing |
|---|---|---|---|
| **1 — Monitoring** | ✅ ~95% | Inbound RUA ingest (ZIP/GZIP/XML), XXE/bomb-safe parser, per-tenant dedupe (UNIQUE index), aggregate storage, sender inventory, SPF/DKIM/DMARC results, RUA token mapping, full audit log | parser versioning; dead-letter/retry; `recordsRejected`/`processedAt` in the result shape |
| **2 — Guided Remediation** | 🟡 ~65% | Hosted DMARC record generator; policy ramp ladder; readiness gating with human reasons; **write-ahead saga + reconcile**; live DNS propagation verify; autopilot; one-click + auto rollback; manual sender override that **persists across re-ingests** | **automated evidence-based classification**; **projected/before-after impact**; **operational DMARC alerts**; per-tag record diff; configurable thresholds; graduated reject ramp |
| **3 — Premium Managed** | 🔴 ~20% | MSP portfolio (real cross-tenant isolation); audit-grade history; one-click rollback; self-driving autopilot | **analyst review queue**; **change-management state machine**; **scheduled deployments**; **incident/SLA workflow**; **RollbackAssessment engine**; DMARC signal in the MSP view; human-analyst tooling |

## The report's 10 areas, mapped to code

| # | Report area | Verdict | Headline evidence |
|---|---|---|---|
| 1 | Production data pipeline | ✅ mostly | Full chain in `inbound.js`/`dmarc-ingest.js`; dedupe UNIQUE index; XXE/2MB/5000-row caps. Gaps: **no parser version, no dead-letter/retry**. |
| 2 | Auto + explainable sender classification | 🔴 **biggest gap** | It's **manual 5-value triage** (`unknown/trusted/suspicious/threat/ignored`), not an automated 8-value taxonomy. Everything defaults to `unknown`; no classifier, no forwarder/mailing-list/misconfigured detection, no per-classification confidence/reasons. Strong bit: override persists + audited. |
| 3 | DMARC policy journey engine | 🟡 | Ramp ladder exists (`DMARC_RAMP_LADDER`) but **6 steps** — quarantine starts 5% and **jumps straight to reject 100** (no 10/25/50 reject soak). |
| 4 | "Safe to enforce" engine | 🟡 | `evaluateRampReadiness` / `buildDmarcEnforcementReadiness` gate with human reasons — but **no tri-state status, no numeric score, no structured 7-check object** (only ~3 checks), **thresholds hard-coded**, two divergent engines. |
| 5 | DNS change management | 🟡 | Generator ✅ + saga ✅, but **no per-tag before/after diff** — the live record is mirrored/overwritten; no copy-to-clipboard path for DMARC. |
| 6 | Post-change auto verification | 🟡 | Propagation detection ✅ (sweep). **Before/after IMPACT missing** — only a scalar `pass_rate_at_change` vs a rolling 7-day rate; no pre/post cohort of auth-fail/aligned/unknown volume. |
| 7 | Rollback + blast-radius | 🟡 | `previous_value` stored, one-click + auto rollback ✅. **No `RollbackAssessment` engine** and none of the named triggers (>2% legit-fail, authorised-mail-blocked, incident) — only a 5pp pass-rate-drop trigger. |
| 8 | Human approval workflow | 🟡 | Thin: a `confirm` boolean on tightening (bypassed if readiness met); loosening needs none. **No draft→approved→scheduled→… state machine, no `canTransition`.** |
| 9 | Operational alerts | 🔴 | **0 of 9** report alert types exist as monitoring alerts; the 3 real DMARC notifications are health events about *our own* hosted record, not external DMARC monitoring. No structured `DmarcAlert`. |
| 10 | MSP / analyst workflow | 🟡 | MSP **portfolio** with real isolation ✅ — but **no DMARC signal in it**, and **no internal analyst review-queue** endpoints at all. |

## The report's 16-step "Definition of Done", walked

Passes end-to-end **~50–60%**. Breaks at: **step 5** (senders auto-classified — no auto-classifier), **step 12** (post-change impact monitoring — pass-rate only), **step 15** (reach reject 100 — ladder has no graduated reject), **step 16** (continuous new-sender + regression alerts — no DMARC alerts). Steps 1–4, 7–11, 13 largely pass.

## Priority to honestly say "Guided Remediation" then "Managed DMARC" (fastest → competitive)

Ordered by defining-impact. This IS the report's proposed *Managed DMARC Policy
Journey v1* epic, re-sequenced by what's actually missing here:

1. **`sender-classification-engine` (automated + evidence-based).** THE defining
   gap. Turn the manual triage into an automated verdict per sender
   (authorised/likely/forwarder/mailing-list/misconfigured/unknown/suspicious/
   unauthorised) from evidence we already parse (SPF/DKIM alignment per method,
   provider, volume) with confidence + reasons; keep the existing human override
   on top. *Unblocks Level 2's core and DoD step 5.*
2. **`impact-forecast` + `post-change-impact-monitor`.** Add projected-impact
   ("advancing to reject would affect N msgs / X%") and a real before/after
   window (auth-fail/aligned/unknown volume), distinguishing legitimate from
   unknown senders. *Unblocks DoD step 12 + report #3/#6, and makes rollback
   triggers meaningful.*
3. **DMARC operational `alerts`.** New high-volume sender, auth regression, SPF/DKIM
   alignment drop, record/RUA drift, policy weakened, post-reject legit-fail spike.
   Emit through the existing alert pipeline + surface in the MSP portfolio.
4. **Runtime test-proof of the managed flow.** A harness driving
   ingest→pass-rate→`applyHostedDmarcChange`→`evaluateRampReadiness`→
   `shouldAutoRollback`→`reconcileHostedIntent`, plus sender-classification, plus
   DMARC resources in the tenant-isolation matrix. *The DoD explicitly requires
   this proof; today only the XML parser is tested.*
5. **Ramp completeness + `dmarc-record-generator` diff.** Add the graduated reject
   ramp (10/25/50) and a per-tag before/after diff of the customer's existing
   record; make thresholds configurable.
6. **`enforcement-readiness-engine` v2.** Unify the two divergent engines into one
   tri-state (`not_ready/review_required/ready`) + numeric score + structured
   7-check object.
7. **(Level 3) `managed-change-workflow` + `analyst-review-queue`.** The
   change-management state machine with validated transitions, scheduled
   deployments, and the internal analyst/MSP ops queue endpoints. This is what
   lets us truthfully say **"Managed DMARC."**

Items 1–4 move us to a defensible **"Guided DMARC Remediation"**; 5–7 (plus the
Level-3 ops layer) earn **"Managed DMARC."**

## Honest one-liner for positioning (today)

> "DMARC **monitoring + hosted policy automation** with self-driving enforcement
> ramp and one-click rollback." Do **not** yet claim "Managed DMARC" or fully
> automated "sender intelligence" — the classifier is manual triage, there are no
> DMARC alerts, and the managed loop is not yet test-proven.
