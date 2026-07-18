# CyberMeters Architecture Decision Record

## ADR-003 — Canonical DMARC Enforcement State Model

**Status:** Approved in principle (founder, 18 July 2026), subject to the revisions in this document — not yet canonical in the repository. Becomes canonical only after a separate docs-governance PR is reviewed and merged.
**Date:** 18 July 2026 (revised 18 July 2026 — founder revision sets 1 & 2)
**Supersedes:** none (introduces a new canonical derivation boundary)
**Related:** ADR-001 (Intelligence Engine Architecture), `docs/DMARC-MATURITY-SCORECARD.md`, `docs/verification-vocabulary.md`, `docs/EPISODE-PLAN-posture-timeline-trust.md`
**Location (repository ADR convention):** `docs/12-ADR-003-CANONICAL-DMARC-ENFORCEMENT-STATE-MODEL.md` (sequential with `10-ADR-001`, `11-ADR-002`)

> **Evidence legend used throughout this ADR**
> **[Verified]** — confirmed by the read-only DMARC Enforcement Level Consistency audit, cited with `file:line`.
> **[Inference]** — a reasoned deduction from verified facts, not directly observed.
> **[Recommendation]** — a design decision proposed by this ADR for founder approval.
> **[Unknown]** — an open question this ADR does not resolve.

This is a decision record, not an implementation. It contains no code and no pseudo-code beyond decision trees. It is implementation-independent: it governs any future backend or frontend implementation of DMARC enforcement state.

---

# 1. Executive Summary

**Today's problem [Verified].** CyberMeters has exactly one canonical DMARC record parser — `parseDmarcRecord(record, recordCount)` at `workers/scan-api/src/engines/email-analysis.js:100` — and it is genuinely reused, not duplicated (imported by `index.js`, `email-scan.js`, `email-intel.js`, `hosted-dmarc.js`, `routes/email-protection.js`). But at least **seven independent state vocabularies** re-map that one parser's output into a DMARC posture, each with its own names, thresholds and severities:

1. Policy-journey stages — `email-analysis.js:218` (`missing | monitoring | partial_enforcement | full_enforcement`)
2. Uppercase status — `email-intel.js:46` (`FULLY_PROTECTED | PARTIAL_PROTECTED | REPORTING_ONLY | MISSING | ERROR`)
3. BEC policy normalisation — `bec.js:61` (`missing | unknown | none | quarantine | reject`)
4. Readiness stages — `sender-provenance.js:297` / `rua-routing.js:117` (`reject_ready | quarantine_ready | monitoring`)
5. Hosted ramp ladder — `hosted-dmarc.js:641` (`DMARC_RAMP_LADDER`)
6. Cyber MOT states — `cyber-mot-domains.js:53` (`CYBER_MOT_STATES`)
7. Posture-event severity — `posture-events.js:17` (`absent` sentinel + `high|medium|low`)

Plus independent numeric scoring in two more places — `email-intel.js:220` (`_score_dmarc` interpolation bands) and `posture-scoring.js:84` (−30 / −10 deltas).

**Why it matters [Verified + Inference].** The same published DMARC record can be described to the same customer with different words, different severities and different scores depending on which surface renders it (dashboard vs Executive Report vs Business Risk vs timeline). More seriously, the audit confirmed a **correctness defect, not just a wording defect**: a DNS lookup that *fails* is silently converted into "no record published". At `email-scan.js:23`, `dmarcRes.status === "fulfilled" ? (...answer) : []` collapses a rejected DNS promise into an empty answer set, so `dmarc.present = false` and every downstream derivation reads "missing". **A domain we could not observe is reported as a domain with no protection.** [Verified: `email-scan.js:23`, `email-scan.js:78`.]

**Why this is not merely a UI consistency issue [Inference].** Three of the affected consumers change customer-visible risk truth, not presentation:
- **Scoring / Business Risk** penalise "missing DMARC" (`business-risk.js:96`, `posture-scoring.js:84`) — so an unobservable domain is scored as unprotected.
- **Cyber MOT** rolls the finding into `email_protection` domain state (`cyber-mot-domains.js:74`) — so the eight-domain coverage honesty contract is violated (an unknown is shown as an issue).
- **Timeline** (`posture-events.js:77`) can emit `email_dmarc_policy_changed` on the `absent` sentinel — so a transient DNS failure can manufacture a false "policy regression". This is precisely the failure class the Phase A "Posture Timeline Trust" episode exists to prevent.

**Why the parser is already canonical [Verified].** `parseDmarcRecord` is the single source of the DMARC *primitives* (`policy`, `subdomain_policy`, `percentage`/`pct`, `rua`, `ruf`, `adkim`, `aspf`, `valid`, `record_count`, `warnings`). No consumer re-parses raw DNS text. The primitive layer is sound and this ADR does not change it.

**Why the state derivation is not canonical [Verified].** The step *after* parsing — turning primitives into an enforcement posture — is duplicated across ≥9 sites with ≥7 vocabularies and inconsistent thresholds. There is no single `deriveDmarcState()`. Each consumer owns its own business logic, so they can and do disagree.

**Decision.** Introduce one canonical derived **DMARC State Object** and one canonical derivation function (`deriveDmarcState`, name illustrative) that sits immediately downstream of `parseDmarcRecord`. The derived posture is a **fully-split, structurally-meaningful enforcement ladder** (`not_yet_assessed → not_observed → no_record → invalid_record → monitoring → partial_quarantine → quarantine_enforced → partial_reject → reject_enforced`), whose macro-ordering deliberately mirrors the already-tested hosted `DMARC_RAMP_LADDER` (`hosted-dmarc.js:641`). Every consumer consumes that object and reads the state directly — no consumer must read a *second* field to tell quarantine from reject or partial from full. The parser stays the source of primitives; the new function becomes the single source of derived state. The change is code-only, additive, append-only-safe and requires no migration.

---

# 2. Current Architecture

**Current pipeline [Verified].**

```text
DNS (SPF/DKIM/DMARC TXT lookups, email-scan.js)
        │   ← DNS failure collapses to [] here (email-scan.js:23)  ✗
        ▼
parseDmarcRecord()            ← engines/email-analysis.js:100  (CANONICAL, single copy)
        │   primitives: policy, sp, pct, rua/ruf, adkim/aspf, valid, record_count, warnings
        ▼
┌──────────────────────────── multiple INDEPENDENT state derivations ────────────────────────────┐
│ buildDmarcPolicyJourney       email-analysis.js:218   → journey stage                            │
│ enrichDmarc                   email-intel.js:46       → UPPERCASE status + risk_level            │
│ _score_dmarc                  email-intel.js:220      → numeric band                             │
│ buildBecExposure              bec.js:61               → BEC policy normalisation + findings      │
│ buildDmarcBusinessRisk        sender-provenance.js:247→ own policy normalisation                 │
│ buildDmarcSenderIntelligence  sender-provenance.js:297→ readiness_stage                          │
│ buildDmarcEnforcementReadiness rua-routing.js:117     → milestone readiness                      │
│ scoring (email block)         scoring.js:600-660      → findings + expected_value strings        │
│ computeSecurityPosture        posture-scoring.js:84   → −30 / −10 executive deltas               │
│ posture-events policy diff    posture-events.js:17-86 → timeline severity + `absent` sentinel    │
│ business-risk email block     business-risk.js:96-247 → BRI findings + security_posture          │
│ hosted-dmarc ramp mapping     hosted-dmarc.js:641-725 → ramp step index / ladder                 │
│ cyber-mot roll-up             cyber-mot-domains.js:74 → email_protection domain state            │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
        ▼
API responses (routes/email-protection.js, scan detail)
        ▼
Frontend (mirrors backend vocab: JOURNEY_STAGES WorkspaceEmailProtectionPage.jsx:73;
          DMARC_STATUS_STYLE IntelligencePage.jsx:54; raw p= pill ScanDetail.jsx:755)
        ▼
Cyber MOT domain state · Executive Report / PDF · Business Risk Indicator · Scoring · Alerts · Timeline
```

**Where the independent derivations live [Verified].** See the table above and §1. The key structural fact: the divergence begins one layer *below* the API, inside the Worker engines, so it cannot be fixed at the API or frontend alone. The frontend vocabularies (`JOURNEY_STAGES`, `DMARC_STATUS_STYLE`) are *mirrors* of two of the backend vocabularies — they are downstream symptoms, not the cause.

**Notable current-architecture facts [Verified].**
- DMARC posture is **deliberately non-alertable** today (`email-protection-lifecycle.js:20`, `alert-consumers.js:134`: "SPF/DKIM/DMARC/BIMI/MTA-STS posture … NOT PRESENT, and must never be"). Only sender-monitoring transitions alert.
- A separate XML aggregate-report parser exists (`lib/dmarc-ingest.js:52` `parseDmarcAggregateXml`) for RUA ingestion. It is **out of scope** for this ADR — it parses inbound reports, not enforcement state.
- The hosted-DMARC ramp ladder (`hosted-dmarc.js:641`) is a *change-management* model (how to migrate a record forward), not a posture-observation model. This ADR treats it as a consumer of canonical state, not a rival state model (see §7 Consumer Contract).

---

# 3. Problems Identified

## Confirmed [Verified]

1. **Unavailable treated as missing.** DNS lookup failure collapses to `[]` at `email-scan.js:23`, so `dmarc.present=false` (`email-scan.js:78`) and every consumer reads "missing". `enrichDmarc` (`email-intel.js:50`) folds DNS-unavailable into `status:"MISSING"`. There is no "could not observe" signal at the probe layer. **This is a correctness/evidence-honesty defect, not cosmetic.**
2. **Multiple enum systems.** ≥7 distinct state vocabularies derive from one parser (enumerated in §1). No shared canonical enum.
3. **Inconsistent severity.** The same posture maps to different severities across engines — e.g. `bec.js` grades `p=quarantine` as `medium` while `posture-events.js` `dmarcSeverity` grades policy changes on its own `high|medium|low` scale, and `confidence.js:45` assigns its own weights (`email_missing_dmarc:90`, `email_dmarc_policy_none:90`).
4. **Inconsistent scoring.** Two independent numeric models: `_score_dmarc` interpolation bands (`email-intel.js:220`, reject 75–100 / quarantine 37.5–62.5) and `computeSecurityPosture` fixed deltas (`posture-scoring.js:84`, −30 missing / −10 p=none). They are not reconciled.
5. **Quarantine/reject ambiguity.** `buildDmarcPolicyJourney` groups `quarantine||percentage<100` into `partial_enforcement` and treats `reject@100` as `full_enforcement` (`email-analysis.js:218`), whereas `buildBimiReadiness` treats `quarantine@100` as `enforced` (`email-analysis.js:288`). So "quarantine at 100%" is *full enforcement* for BIMI but *partial* for the journey. The distinction between quarantine and reject is applied inconsistently.
6. **pct ambiguity.** `pct` is defaulted to 100 and clamped in the parser, but consumers disagree on whether `pct<100` demotes an enforcing policy (journey: yes; BIMI: yes only if `<100`; BEC emits a separate `dmarc_partial_pct` finding). The behaviour at `pct=0` under an enforcing policy is unspecified across consumers.
7. **sp (subdomain policy) ambiguity.** `subdomain_policy` is parsed (`email-analysis.js`) but no consumer consistently accounts for a subdomain gap (`p=reject; sp=none`). Enforcement posture is derived largely from `p` alone.
8. **Remediation fragmentation.** DMARC remediation strings are emitted independently in `buildEmailRemediationActions` (`email-analysis.js:349`), `bec.js`, `scoring.js:600`, and `business-risk.js:234`, rather than resolved once from the Canonical Remediation Registry.
9. **Duplicated business logic.** The policy→posture decision is re-implemented in every site listed in §1 rather than called once.
10. **Inconsistent customer wording.** Frontend mirrors two different backend vocabularies (`JOURNEY_STAGES` vs `DMARC_STATUS_STYLE`) plus a raw `p=` pill (`ScanDetail.jsx:755`), so the same posture reads differently on different pages.

## Likely [Inference]

- **False timeline regressions from transient DNS failure.** Because `absent` is a real sentinel in `posture-events.js:21` and DNS failure collapses to absent, a flaky resolver can emit `email_dmarc_policy_changed` as if the customer removed their record. Not separately reproduced in the audit, but mechanically implied by problems #1 and the `posture-events` path. [Inference]
- **Cyber MOT understating/overstating email state on unobservable domains.** The roll-up (`cyber-mot-domains.js:74`) consumes the missing finding, so an unobservable domain likely renders `issue_detected` rather than `unavailable`/`evidence_insufficient`. [Inference — exact rendered state not captured in the audit.]

## Open questions [Unknown]

- Whether any *persisted* historical rows (snapshots, `asset_events`) already contain "missing" values that were in truth "unavailable". If so, they are immutable history and must not be rewritten (see §12). Extent unknown.
- Whether `pct=0` under `p=reject` occurs in any live founder-controlled record (needed to validate the edge-case rule in §6). Unknown.
- Whether alignment mode (`adkim`/`aspf` strict vs relaxed) should ever influence enforcement_level. This ADR says no for v1 (§17), but the product question is open. [Unknown]

---

# 4. Design Principles

These are permanent engineering rules for all future DMARC work. They extend, and are subordinate to, the CLAUDE.md permanent architectural rules.

1. **The parser owns primitives; nothing else parses.** `parseDmarcRecord` remains the single source of DMARC primitive evidence. No consumer reads raw DNS text. [Verified this already holds.]
2. **State is derived exactly once.** A single canonical function derives the DMARC State Object from primitives. It is the only place policy→posture logic lives.
3. **State is never manually duplicated.** No engine, route, report, score, alert or component may re-implement enforcement derivation. Adding a parallel derivation is a defect.
4. **Customer wording never derives policy.** Labels, badges and copy are a pure function of the canonical `enforcement_level` (and, where strength matters, `policy`/`pct`). Wording code must not branch on raw primitives to invent a posture.
5. **Evidence honesty overrides convenience.** Where a single coarse state would misrepresent evidence, the object carries the finer primitive so no consumer is forced to lie.
6. **Customer assertion ≠ external verification.** A customer-asserted policy (`policy_source = customer_asserted`) is never rendered as observed enforcement and never scored as verified. (Consistent with `docs/verification-vocabulary.md`.)
7. **`unavailable` ≠ `missing`.** Failure to observe is a first-class state, never silently converted to "no record". This is the primary correctness fix.
8. **`missing` ≠ `invalid`.** An absent record and a malformed/duplicate record are distinct states with distinct remediation.
9. **`monitoring` ≠ `enforcement`.** `p=none` is telemetry only and must never be presented, scored or coloured as protection.
10. **`quarantine` ≠ `reject` — structurally.** The two enforcing policies are separate rungs of `enforcement_level` (`partial_quarantine`/`quarantine_enforced` vs `partial_reject`/`reject_enforced`). A consumer must **never** need to read the `policy` primitive to distinguish them; the state is independently meaningful. The `policy` primitive remains present for provenance, not for the distinction.
11. **`partial` ≠ `full` — structurally.** A partially-applied enforcing policy is its own rung (`partial_quarantine`, `partial_reject`), separate from the full rung of the same policy, because the receiver-side action on the covered fraction differs. `reject_enforced` is the only final "done" rung; `quarantine_enforced` is a valid enforcing state that is **not** equivalent to reject and still carries remediation to progress.
12. **Intent-preserving states, effect-explaining caveats.** Where an intended enforcing policy has no observable effect (e.g. `pct=0`), the state stays in the **intent family** (`partial_reject`/`partial_quarantine` per the published policy) and a mandatory, visible caveat states the *effective* behaviour. The state never silently collapses to `monitoring`/`p=none`; nothing about the intent or the effect is hidden.
13. **Append-only, comparability-gated history.** DMARC state changes recorded to history follow the existing append-only + `not_comparable`/producer-version gate (Phase A). A cross-model-version comparison is `not_comparable`, never a fabricated regression.
14. **Fail closed on unknown values.** An unrecognised policy token or enum value resolves to `invalid`/`evidence_insufficient`, never to a healthy or enforcing state.

---

# 5. Canonical DMARC State Object

The canonical object is the sole contract between DMARC observation and every consumer. All fields are always present; "not applicable" is expressed with an explicit sentinel/`null`, never by omission.

| Field | Type / allowed values | Meaning & why it exists |
|---|---|---|
| `evidence_status` | `observed` \| `unavailable` \| `not_yet_assessed` | **Could CyberMeters observe DMARC at all?** `observed` = the DNS query completed (record may be present or absent). `unavailable` = the lookup failed/timed out/SERVFAIL — we do not know. `not_yet_assessed` = never scanned. **Exists to end the unavailable-as-missing conflation (Problem #1). This is the top gate — read first.** [Recommendation] |
| `record_presence` | `present` \| `absent` \| `unknown` | Given `observed`, was a DMARC record published? `unknown` only when `evidence_status != observed`. Separates "we looked and found none" (`absent`) from "we could not look" (`unknown`). [Recommendation] |
| `record_validity` | `valid` \| `invalid` \| `not_applicable` | Structural validity per RFC 7489 when a record is present: exactly one record, `v=DMARC1`, a known `p` token, well-formed `pct`. `not_applicable` when `record_presence != present`. Carries `invalid_reason` (below). Separates `missing` from `invalid` (Problem #7/§4). [Recommendation; validity primitive already exists as `parseDmarcRecord.valid` — Verified] |
| `invalid_reason` | `null` \| `multiple_records` \| `not_dmarc1` \| `unknown_policy_token` \| `malformed_pct` \| `other` | Always present as a key; `null` unless `record_validity = invalid`. Drives honest remediation and wording. Extensible; unknown maps to `other`. [Recommendation] |
| `policy` | `reject` \| `quarantine` \| `none` \| `null` | The published `p=` primitive (from the parser). `null` when no valid record. Retained for **provenance and traceability** — the quarantine-vs-reject distinction is carried **structurally** by `enforcement_level`, so no consumer needs `policy` to tell them apart. [Verified primitive] |
| `pct` | integer 0–100 \| `null` | The `pct=` primitive; parser defaults to 100 and clamps. `null` when no valid record. Underlies the partial/full split but consumers read the split from `enforcement_level`, not from `pct`. [Verified primitive] |
| `subdomain_policy` | `reject` \| `quarantine` \| `none` \| `inherit` \| `null` | The effective `sp=`. `inherit` when `sp` absent (RFC: subdomains follow `p`). Underlies the `subdomain_gap` caveat. `null` when no valid record. [Verified primitive; `inherit` sentinel is a Recommendation] |
| `policy_source` | `observed_dns` \| `hosted_managed_verified` \| `customer_asserted` | Provenance of the enforcement value. `observed_dns` = read from live DNS. `hosted_managed_verified` = a CyberMeters-hosted record confirmed live via DNS (`verifyDmarcDnsSetup`, `hosted-dmarc.js:96`). `customer_asserted` = the customer stated it, never externally observed → never counts as verified enforcement (Principle 6). Note: a hosted or customer-declared *intent* is not external verification. [Recommendation] |
| `enforcement_level` | `not_yet_assessed` \| `not_observed` \| `no_record` \| `invalid_record` \| `monitoring` \| `partial_quarantine` \| `quarantine_enforced` \| `partial_reject` \| `reject_enforced` | **The single canonical derived posture, fully split.** Replaces all seven legacy vocabularies. A total, severity-ordered ladder (below) whose macro-ordering mirrors the tested hosted `DMARC_RAMP_LADDER`. **Each rung is independently meaningful — a consumer never reads a second field to distinguish quarantine from reject or partial from full.** The one field every consumer keys off. [Recommendation] |
| `caveats` | array of `policy_applies_to_zero_percent` \| `pct_below_100` \| `subdomain_gap` (empty `[]` when none) | **Structured reasons a partial/effect-limited state exists, so no consumer re-derives "why".** `pct_below_100` → covered fraction < 100% (remediation: raise pct to 100). `subdomain_gap` → org policy enforces but `sp` is weaker/none (remediation: set `sp=`). `policy_applies_to_zero_percent` → `pct=0` (see §6 edge case; carries mandatory effective-behaviour wording). A `partial_*` rung always carries at least one caveat; **every applicable caveat is preserved and exposed — none is removed, suppressed, overwritten, or hidden.** The array is emitted in **canonical lead-remediation priority order** (below), so `caveats[0]` is the lead remediation while all others remain present. Extensible; unknown caveats ignored by consumers. [Recommendation] |
| `confidence` | `high` \| `medium` \| `low` | Evidence quality of the derivation. `high` = valid observed/hosted-verified record. `medium` = observed but weak corroboration (e.g. no reporting configured). `low` = `unavailable`, `not_yet_assessed`, or `customer_asserted`. Lets consumers avoid asserting strong claims from weak evidence. [Recommendation] |
| `last_observed` | ISO 8601 timestamp \| `null` | When the observation that produced this state was made. `null` when `not_yet_assessed`. Supports staleness handling and the append-only timeline. [Recommendation] |

**`enforcement_level` ladder (severity order, weakest protection first):**

```text
not_yet_assessed    (never scanned — no claim)
not_observed        (DNS lookup failed — unknown, evidence_status=unavailable)
no_record           (observed, no DMARC published — the true "missing")
invalid_record      (record present but structurally invalid — see invalid_reason)
monitoring          (p=none — intentionally published telemetry-only)
partial_quarantine  (p=quarantine but pct<100 and/or subdomain gap — see caveats)
quarantine_enforced (p=quarantine applied to all in-scope mail — enforcing, but NOT reject)
partial_reject      (p=reject but pct<100 and/or subdomain gap — see caveats)
reject_enforced     (p=reject applied to all in-scope mail — the ONLY final "done" state)
```

**Note on the fully-split ladder [Recommendation].** The founder revision (18 July 2026) replaced the earlier grouped `full_enforcement` with four distinct enforcing rungs so that quarantine-vs-reject and partial-vs-full are **structural**, not something a consumer must reconstruct from `policy`/`pct`:

- `partial_quarantine` and `partial_reject` are **separate** because the receiver-side action on the covered fraction differs (divert vs block) — a partial reject is materially stronger than a partial quarantine and must not share a rung.
- `quarantine_enforced` is a **valid enforcing state but not equivalent to reject**. It gets a distinct near-complete presentation (not the reject green, not amber-alarm) and **retains remediation to progress to reject** (§9).
- `reject_enforced` is the **only** final green/done rung.

**Ladder ordering justification [Recommendation, grounded in Verified code].** The read-side ordering is not arbitrary: it deliberately mirrors the macro-ordering of the already-implemented and already-tested hosted ramp ladder `DMARC_RAMP_LADDER` (`hosted-dmarc.js:641`, exercised by `scripts/validate-dmarc-graduated-ramp.js` [Verified]), which ramps `none → quarantine (5/25/50/100) → reject (10/25/50/100)`. Read-side `monitoring → partial_quarantine → quarantine_enforced → partial_reject → reject_enforced` is the observation-side image of that same progression. Binding the two subsystems to one ordering means the state a customer *reads* and the state the hosted engine *ramps toward* can never disagree about which posture is stronger. A parity validator enforces this (see §16).

**Canonical caveat lead-remediation priority [Founder decision, 18 July 2026].** When more than one caveat applies to a state, remediation is presented in this fixed priority order:

```text
1. policy_applies_to_zero_percent   (raise pct off 0 — the policy currently protects no mail)
2. subdomain_gap                    (set sp= — subdomains are unprotected)
3. pct_below_100                    (raise pct to 100 — coverage is incomplete)
```

This ordering **only** controls which remediation is presented *first* (`caveats[0]`). It must **never** remove, suppress, overwrite, or hide any other applicable caveat: every applicable caveat remains present in the `caveats` array and is surfaced to the customer. A state with two caveats shows two remediations, lead-first; the priority never collapses them to one.

---

# 6. Canonical Derivation Rules

Behaviour of `deriveDmarcState()` (name illustrative). Pure function of parser primitives + evidence-availability signal. Deterministic. No I/O. No random. No wall-clock beyond the passed `last_observed`.

**Priority order (first matching rule wins):**

```text
1. If the domain has never been scanned for DMARC:
      enforcement_level = not_yet_assessed
      evidence_status   = not_yet_assessed
      record_presence   = unknown ; record_validity = not_applicable
      policy = pct = subdomain_policy = null
      confidence = low ; last_observed = null
   → STOP.

2. Else if the DMARC DNS lookup did NOT complete successfully
   (SERVFAIL, timeout, network error, rejected promise):
      evidence_status   = unavailable
      enforcement_level = not_observed
      record_presence   = unknown ; record_validity = not_applicable
      policy = pct = subdomain_policy = null
      confidence = low ; last_observed = <observation time>
   → STOP.   [THIS RULE IS THE FIX FOR PROBLEM #1 — it must precede any presence test.]

3. Else evidence_status = observed. Branch on record set:

   3a. recordCount == 0:
          record_presence = absent ; record_validity = not_applicable
          enforcement_level = no_record
          policy = pct = subdomain_policy = null
          confidence = high (we positively observed the absence)
       → STOP.

   3b. recordCount > 1:
          record_presence = present ; record_validity = invalid
          invalid_reason  = multiple_records
          enforcement_level = invalid_record
          policy/pct/sp = as-parsed-if-any, but NOT used for posture
          confidence = high
       → STOP.   (RFC 7489: multiple records ⇒ no policy applied. We mark invalid,
                  NOT monitoring — honesty: the customer's intent is unenforceable.)

   3c. recordCount == 1 AND parser.valid == false
       (missing v=DMARC1, unknown p token, malformed pct):
          record_presence = present ; record_validity = invalid
          invalid_reason  = <not_dmarc1 | unknown_policy_token | malformed_pct | other>
          enforcement_level = invalid_record
          confidence = high
       → STOP.   (Fail closed — Principle 14.)

   3d. recordCount == 1 AND parser.valid == true:
          record_presence = present ; record_validity = valid
          policy = parser.policy ; pct = parser.pct (default 100)
          subdomain_policy = parser.sp present ? parser.sp : inherit
          caveats = []

          // Collect EVERY applicable caveat (none is ever suppressed), then emit the array
          // in canonical lead-remediation priority order (§5):
          //   1. policy_applies_to_zero_percent  2. subdomain_gap  3. pct_below_100
          enforcing = policy in {quarantine, reject}
          subdomain_gap = enforcing AND subdomain_policy == none   // parent enforced, subdomains open
          IF enforcing AND pct == 0:   caveats += policy_applies_to_zero_percent
          IF subdomain_gap:            caveats += subdomain_gap
          IF enforcing AND 0 < pct < 100: caveats += pct_below_100
          caveats = caveats sorted by canonical priority   // caveats[0] = lead remediation; all retained

          IF policy == none:
                enforcement_level = monitoring
          ELIF policy == quarantine:
                enforcement_level = (caveats is empty) ? quarantine_enforced : partial_quarantine
          ELIF policy == reject:
                enforcement_level = (caveats is empty) ? reject_enforced : partial_reject

          // NOTE 1: pct=0 keeps the INTENT family (partial_quarantine / partial_reject per the
          //   published policy) via the policy_applies_to_zero_percent caveat — it is NEVER
          //   collapsed to monitoring / p=none (Principle 12).
          // NOTE 2: pct==0 and pct_below_100 are mutually exclusive (pct=0 → zero_percent, not
          //   pct_below_100), but subdomain_gap CAN co-occur with either, giving a 2-caveat state
          //   whose remediations are shown lead-first, both retained.

          confidence = has_reporting ? high : medium   // reporting corroborates observation
          last_observed = <observation time>
       → STOP.
```

**Edge cases (all resolved above, restated for clarity):**

- **DNS failure vs no record** — Rule 2 vs 3a. The decisive fix. Rule 2 must run *before* any presence test; the current code does the opposite at `email-scan.js:23`. [Verified defect]
- **Multiple records** — Rule 3b → `invalid_record`, not `no_record` and not `monitoring`. [Recommendation]
- **`pct=0` under an enforcing policy** — Rule 3d → **stays in the intent family** (`partial_reject` for `p=reject`, `partial_quarantine` for `p=quarantine`) with the mandatory `policy_applies_to_zero_percent` caveat and explicit remediation. **Never** silently equated with an intentionally published `p=none`/`monitoring`. Per RFC 7489 residual-policy semantics the caveat states the *effective* behaviour: `p=reject; pct=0` effectively behaves like **quarantine** of failing mail; `p=quarantine; pct=0` effectively like **none/no action**. Wording: *"an enforcing policy is published but currently applies to 0% of messages; failing mail is presently handled as …"*. [Recommendation — resolves Problem #6; live occurrence Unknown.]
- **Subdomain gap (`p=reject; sp=none`)** — Rule 3d → `partial_reject` with the `subdomain_gap` caveat (remediation: set `sp=`). Parent is protected, subdomains are not; a full rung would be dishonest. Likewise `p=quarantine; sp=none` → `partial_quarantine` + `subdomain_gap`. [Recommendation — resolves Problem #7.]
- **`sp` absent** — treated as `inherit`; no gap. [Verified RFC behaviour]
- **`quarantine@100` vs `reject@100`** — **structurally distinct rungs** `quarantine_enforced` vs `reject_enforced`; no consumer reads `policy` to tell them apart (resolves the BIMI-vs-journey contradiction, Problem #5). [Recommendation]
- **`partial_quarantine` vs `partial_reject`** — separate rungs because the receiver-side action on the covered fraction differs (divert vs block); a partial reject is materially stronger. [Recommendation]
- **Unknown/garbage policy token** — Rule 3c → `invalid_record`, fail closed. [Recommendation, Principle 14]
- **Reporting-only presence** — `rua`/`ruf` present does not raise `enforcement_level`; reporting is a separate primitive (`has_reporting`) and at most affects `confidence`. [Recommendation — `monitoring != enforcement`]

**Worked examples [Recommendation]:**

| Input | enforcement_level | caveats | policy | pct | confidence | Note |
|---|---|---|---|---|---|---|
| never scanned | `not_yet_assessed` | — | null | null | low | no claim |
| DNS SERVFAIL | `not_observed` | — | null | null | low | **was "missing" before** |
| no TXT record | `no_record` | — | null | null | high | the true missing |
| two DMARC records | `invalid_record` | — | — | — | high | `multiple_records` |
| `v=DMARC1; p=none; rua=…` | `monitoring` | — | none | 100 | high | telemetry only |
| `p=quarantine; pct=50` | `partial_quarantine` | `pct_below_100` | quarantine | 50 | medium | half of mail diverted |
| `p=quarantine; pct=100` | `quarantine_enforced` | — | quarantine | 100 | high | enforcing, NOT reject — retains remediation to reject |
| `p=reject; pct=50` | `partial_reject` | `pct_below_100` | reject | 50 | medium | half of mail blocked |
| `p=reject; pct=100` | `reject_enforced` | — | reject | 100 | high | only final "done" state |
| `p=reject; pct=0` | `partial_reject` | `policy_applies_to_zero_percent` | reject | 0 | high | intent preserved; failing mail effectively quarantined |
| `p=quarantine; pct=0` | `partial_quarantine` | `policy_applies_to_zero_percent` | quarantine | 0 | high | intent preserved; failing mail effectively no-action |
| `p=reject; sp=none` | `partial_reject` | `subdomain_gap` | reject | 100 | high | org enforced, subdomains open (set `sp=`) |
| `p=reject; pct=0; sp=none` | `partial_reject` | `[policy_applies_to_zero_percent, subdomain_gap]` | reject | 0 | high | **two caveats, both retained**; lead remediation = raise pct off 0, then set `sp=` |
| `p=quarantine; pct=50; sp=none` | `partial_quarantine` | `[subdomain_gap, pct_below_100]` | quarantine | 50 | medium | **two caveats, both retained**; lead = set `sp=`, then raise pct to 100 |

---

# 7. Consumer Contract

**Rule:** every consumer consumes the canonical DMARC State Object. No consumer derives its own enforcement state. Each retires its private derivation and reads canonical fields.

| Consumer | Current independent derivation to retire [Verified] | May consume (canonical fields) | Must NOT do |
|---|---|---|---|
| **Email Protection** (page/engine) | `buildDmarcPolicyJourney` (`email-analysis.js:218`), `enrichDmarc` (`email-intel.js:46`), **inline `DmarcCard` kind derivation (`WorkspaceEmailProtectionPage.jsx`)** | `enforcement_level`, `caveats`, `confidence`, `evidence_status`, `last_observed` (and `policy`/`pct` for display only) | re-map policy→stage; keep parallel vocabularies; derive a card "kind"/colour inline |
| **Cyber MOT** | roll-up in `cyber-mot-domains.js:74` | `enforcement_level` → mapped to `CYBER_MOT_STATES` via one documented table (below) | infer domain state from raw `policy`; render `not_observed` as `issue_detected` |
| **Executive Report** | `computeSecurityPosture` reasons (`posture-scoring.js:66`), `buildDmarcSenderIntelligenceEvidence` (`sender-provenance.js:297`) | `enforcement_level`, `caveats`, `confidence`, `evidence_status` | invent its own reason strings from primitives |
| **PDF** | findings from `scoring.js:600-660` | canonical wording table (§9) keyed by `enforcement_level` (+`caveats`) | branch on raw `p=` or re-read `policy` to tell quarantine from reject |
| **Dashboard / badges** | `DMARC_STATUS_STYLE` (`IntelligencePage.jsx:54`), `JOURNEY_STAGES` (`WorkspaceEmailProtectionPage.jsx:73`), raw pill (`ScanDetail.jsx:755`), **inline `DmarcCard` kind derivation (`WorkspaceEmailProtectionPage.jsx`)** | `enforcement_level` → one badge map (§9) | four different colourings/kinds for one posture |
| **Business Risk** | `business-risk.js:96-247` | `enforcement_level`, `caveats`, `confidence` | its own missing/none normalisation |
| **Scoring** | `_score_dmarc` (`email-intel.js:220`), `posture-scoring.js:84` | `enforcement_level`, `evidence_status` (§11 — monotonic along the ladder) | two unreconciled numeric models; read `policy`/`pct` instead of the ladder rung |
| **Alerts** | `email-protection-lifecycle.js`, `alert-consumers.js:134` | `enforcement_level` transitions + `evidence_status` (§10) | alert on `not_observed`; treat unavailable as regression |
| **Timeline** | `posture-events.js:17-86` (`absent` sentinel) | `enforcement_level` transitions, comparability gate | emit `policy_changed` across an `unavailable` observation |
| **Hosted DMARC** | ramp mapping `hosted-dmarc.js:641-725` | canonical state as the *observed* starting point; ramp ladder stays a change-management model | treat the ramp ladder as a rival posture vocabulary |
| **API** | route shapes in `routes/email-protection.js` | serialise the canonical object verbatim (§8) | expose a second derived shape |
| **Validator** | scattered `validate-*.js` | assert parity against canonical state | assert against a legacy vocabulary as ground truth |

**Cyber MOT mapping table [Recommendation]** (the one documented, deterministic bridge from `enforcement_level` to `CYBER_MOT_STATES` — no `provisional`/severity-ranking ambiguity):

```text
not_yet_assessed    → not_yet_assessed
not_observed        → unavailable        (NOT issue_detected — the honesty fix)
no_record           → issue_detected
invalid_record      → issue_detected
monitoring          → issue_detected     (monitoring != protection)
partial_quarantine  → issue_detected     (observed weakness, NOT provisional/insufficient)
quarantine_enforced → issue_detected     (enforcing but not the final healthy state — see below)
partial_reject      → issue_detected     (observed weakness, NOT provisional/insufficient)
reject_enforced     → assessed_healthy   (the only healthy DMARC state)
```

Rationale: `partial_quarantine`/`partial_reject` are **observed** weaknesses (we saw the record and saw the gap), so they are `issue_detected`, never `provisional` or `evidence_insufficient`, which denote *absence* of observation. Only `reject_enforced` is `assessed_healthy`. [Recommendation — resolves founder revision item 5]

**`quarantine_enforced` → `issue_detected` is intentional and load-bearing [Founder decision, 18 July 2026].** A full quarantine policy is genuinely **enforcing**, but it is **not the final healthy state for CyberMeters** because failed/spoofed mail may still be delivered into quarantine/spam and remain available to the recipient. It is therefore `issue_detected` so the customer is steered toward `reject`. This `issue_detected` classification must **not** be read or worded as `no_record`/missing, `invalid_record`/invalid, `monitoring`/monitoring-only, `partial_*`/partial, or unverified. Customer-facing surfaces must **acknowledge that enforcement is active** while clearly recommending progression to reject (§9). The distinction "enforcing but not yet the healthy end-state" is carried by the rung itself, never by demoting the state's meaning.

**BEC, readiness stages, ramp ladder [Recommendation].** These are *derived views* for specific workflows (BEC exposure, enforcement-readiness milestones, hosted change-management). They may continue to exist **as functions of the canonical object**, but they must take `enforcement_level`/`policy`/`pct` as input rather than re-deriving posture from primitives. They are downstream transforms, not rival sources of truth.

---

# 8. API Contract

**Shape [Recommendation].** The canonical object is exposed as an additive block on every DMARC-bearing response:

```text
dmarc_state: {
  evidence_status, record_presence, record_validity, invalid_reason,
  policy, pct, subdomain_policy, policy_source,
  enforcement_level, caveats, confidence, last_observed,
  state_model_version            // e.g. "2026-07-18"
}
```

- **Required fields:** all twelve state fields above are always present as keys; inapplicable values use explicit sentinels/`null`/`[]` (never omitted). `enforcement_level` is one of the nine ladder rungs (§5). `caveats` is always an array (empty `[]` when none), carrying **every** applicable caveat, serialised in canonical lead-remediation priority order so `caveats[0]` is the lead — the API never omits, dedups away, or reorders out a non-lead caveat. `invalid_reason` is always present but `null` unless `record_validity=invalid`. `state_model_version` is required.
- **No optional/scalar caveat field:** there is no separate scalar `caveat` field — all caveats (including `policy_applies_to_zero_percent`) are carried by the `caveats` array.
- **Future compatibility:** consumers must ignore unknown fields and treat unknown enum values as their fail-closed neighbour (`enforcement_level` unknown → treat as `invalid_record`/insufficient-evidence, never as `reject_enforced`/healthy; unknown `caveats` entries ignored). New `invalid_reason`/`enforcement_level`/`caveats` values may be added additively. **A consumer must key behaviour off `enforcement_level` (and `caveats`), never reconstruct the rung from `policy`/`pct`.**
- **Versioning:** carried by `state_model_version` (a CyberMeters product date-version, ISO `YYYY-MM-DD`, consistent with the CE questionnaire versioning precedent). No `/api/v1/` path scheme — versioning is a field, not a route (CLAUDE.md rule). A version bump is a methodology-version change and is `not_comparable` across older stored states (§12).
- **Backward compatibility:** existing legacy fields (`policy_journey`, `enrichDmarc.status`, raw `p=`, business-risk findings) remain in responses during the transition and are **derived from** the canonical object, not independently. They may be deprecated on a later, separately approved schedule — not in the first implementation.

---

# 9. UI Contract

One label, colour and wording set per `enforcement_level` rung — the rung already encodes quarantine-vs-reject and partial-vs-full, so wording does **not** branch on `policy`/`pct`. Caveats drive the exact remediation. "Explanation first, number second" (CLAUDE.md).

| `enforcement_level` | Badge label | Badge colour intent | Customer wording | Executive wording | Tooltip | Remediation (from Registry) |
|---|---|---|---|---|---|---|
| `not_yet_assessed` | Not yet assessed | neutral/grey | "We haven't assessed DMARC for this domain yet." | "DMARC assessment pending." | "No DMARC observation has been made yet." | none (no claim) |
| `not_observed` | Couldn't check | amber/neutral (NOT red) | "We couldn't reach DNS to check DMARC. This is not a finding about your protection." | "DMARC could not be observed at scan time; evidence insufficient." | "The DNS lookup did not complete. Unknown ≠ missing." | Retry / check DNS resolver; **no penalty** |
| `no_record` | No DMARC | red | "No DMARC record is published for this domain." | "DMARC is not published — inbound spoofing is not mitigated." | "We queried DNS and found no DMARC record." | Publish a DMARC record (monitoring first) |
| `invalid_record` | Invalid DMARC | red | "A DMARC record exists but is invalid ({reason})." | "DMARC record is malformed and provides no protection." | "Record present but fails RFC 7489 validation." | Correct the record ({invalid_reason}) |
| `monitoring` | Monitoring only | amber | "DMARC is in monitoring mode (p=none) — it reports but does not block." | "Monitoring only — no enforcement; spoofed mail is not blocked." | "p=none collects reports but takes no action." | Progress to quarantine, then reject |
| `partial_quarantine` | Partial quarantine | amber | "DMARC quarantines some failing mail{ — see below}." | "Partial quarantine — not all failing mail is diverted." | "Quarantine applied, but coverage is incomplete." | **Caveat-driven:** `pct_below_100`→"raise pct to 100"; `subdomain_gap`→"set sp="; `policy_applies_to_zero_percent`→"applies to 0% of mail; failing mail is presently handled as no-action — raise pct" |
| `quarantine_enforced` | Quarantine enforced | **distinct near-complete (blue/teal — NOT reject-green, NOT amber-alarm)** | "DMARC quarantines all failing mail. Progress to reject for the strongest protection." | "Enforcing at quarantine — divert, not block. One step from full protection." | "Quarantine diverts failing mail; reject blocks it outright." | **Retained:** "Move to p=reject to reach full enforcement." |
| `partial_reject` | Partial reject | amber | "DMARC rejects some failing mail{ — see below}." | "Partial reject — not all failing mail is blocked." | "Reject applied, but coverage is incomplete." | **Caveat-driven:** `pct_below_100`→"raise pct to 100"; `subdomain_gap`→"set sp="; `policy_applies_to_zero_percent`→"applies to 0% of mail; failing mail is presently effectively quarantined — raise pct" |
| `reject_enforced` | Fully enforcing (reject) | green | "DMARC is fully enforcing — failing mail is rejected." | "Full enforcement (reject) — spoofing is actively blocked." | "reject=block; this is the strongest, complete DMARC posture." | Maintain |

**Rules [Recommendation]:**
- **Only `reject_enforced` may be green.** It is the single final "done" state.
- **`quarantine_enforced` gets its own distinct presentation** — a near-complete colour (blue/teal), neither the reject green nor an amber alarm — and always shows remediation to progress to reject. It must never be styled identically to `reject_enforced` and never treated as "done". Wording must **acknowledge that enforcement is active** ("DMARC is enforcing at quarantine") while recommending progression to reject, and must **never** describe it as missing, invalid, monitoring-only, partial, or unverified — even though it maps to `issue_detected` in Cyber MOT (§7). The rung, not the wording, carries "enforcing but not the final healthy state". [Founder decision, 18 July 2026]
- `partial_quarantine` and `partial_reject` are separate visual states; `monitoring` is never green (Principle 9).
- `not_observed` is never red and never worded as a failure of the customer's setup (Principle 7).
- The quarantine-vs-reject and partial-vs-full distinctions come from the **rung**, never re-derived from `policy`/`pct`. Remediation specifics come from `caveats`.
- **Multiple caveats: show all, lead-first.** When a state carries more than one caveat, the surface presents the remediation for `caveats[0]` (the canonical lead — `policy_applies_to_zero_percent` > `subdomain_gap` > `pct_below_100`, §5) **first**, and still surfaces the remaining applicable caveats' remediation. A surface must never drop, hide, or overwrite a non-lead caveat. [Founder decision, 18 July 2026]
- Frontend removes `JOURNEY_STAGES`, `DMARC_STATUS_STYLE`, the raw `p=` pill **and the inline `DmarcCard` kind derivation (`WorkspaceEmailProtectionPage.jsx`)** as independent maps; all four become renders of `enforcement_level` (+`caveats`).

---

# 10. Alert Contract

**Current state [Verified]:** DMARC posture is deliberately non-alertable (`alert-consumers.js:134`, `email-protection-lifecycle.js:20`). This ADR **does not** change that policy — introducing DMARC posture alerts is a separate founder decision (§17). This section defines the honest *contract* that any future alerting MUST obey, and the invariants that already matter because DMARC state flows into the timeline.

**When an alert may fire [Recommendation, if/when enabled]:**
- Only on a transition **between two `observed` states** with the same `state_model_version` (comparable).
- A genuine weakening — a move *down* the ladder (e.g. `reject_enforced → partial_reject`, `reject_enforced → monitoring`, `quarantine_enforced → no_record`). Ladder position (§5) defines direction, so "weakening" is unambiguous and structural.

**When an alert MUST NOT fire [Recommendation — binding now, for timeline too]:**
- On any transition **into or out of `not_observed`** (`evidence_status=unavailable`). Unavailable is never a regression. This is the direct correctness consequence of Problem #1 and the Phase A trust invariant.
- On any transition into `not_yet_assessed`.
- Across a `state_model_version` change — such comparisons are `not_comparable` (Phase A gate), never a fabricated event.
- On a stable state (silent-on-stable — Phase A).

**State transitions, recurrence, reappearance, suppression, append-only [Recommendation]:**
- **Transitions** are computed on `enforcement_level` between the two most recent *comparable observed* states.
- **Recurrence / reappearance** (a weakening returns after recovery) follows the existing managed-case recurrence model; a reappearance is a new append-only event, not an overwrite.
- **Suppression** that contradicts current evidence is an explicit conflict, never silent (consistent with the `two-vocabularies-one-slot` alerting policy).
- **Append-only:** every DMARC state change written to `asset_events`/posture-events is additive; history is never mutated (Principle 13, §12).

---

# 11. Scoring Contract

**The score is a monotonic function of the `enforcement_level` rung [Recommendation].** The single scoring input is the ladder position; a weaker rung scores **≤** a stronger rung. `policy`/`pct` are **not** read directly — the rung already encodes them. This replaces the two unreconciled models (`_score_dmarc` bands + `posture-scoring` deltas).

**Required monotonic ordering (weakest → strongest protection credit):**

```text
no_record  ≤  invalid_record  ≤  monitoring  ≤  partial_quarantine
           ≤  quarantine_enforced  ≤  partial_reject  ≤  reject_enforced
```

- **`reject_enforced` is the only full-credit / no-penalty enforcing state.**
- **`quarantine_enforced` carries a small penalty — not full green.** It is enforcing (scored well above `partial_*`/`monitoring`) but strictly below `reject_enforced`, reflecting that it diverts rather than blocks and still has remediation outstanding.
- `partial_reject` scores above `partial_quarantine` (block > divert on the covered fraction), and both score above `monitoring`.
- The `pct=0` case sits at its intent rung (`partial_reject`/`partial_quarantine`) and is scored as a partial state — never as `monitoring` and never as full credit.

**Carries strictly NO penalty and NO credit (neither debit nor credit) [Recommendation]:**
- `evidence_status = unavailable` (`not_observed`) — **the scoring-side correction for Problem #1**; scored as "no change / no claim", never as `no_record`.
- `not_yet_assessed` — no claim.
These two are excluded from the monotonic ladder entirely: they are score-neutral, not a low rung.

**Does NOT influence the score [Recommendation]:**
- Presence of `rua`/`ruf` reporting — reporting is not protection; it may raise `confidence` but not the posture score.
- `policy_source = customer_asserted` / hosted-declared *intent* — never earns an enforcement score (Principle 6); surfaced but scored as unverified.

**Distinctions the scoring MUST preserve [Recommendation]:** `unavailable` ≠ `missing` (neutral vs full penalty); `invalid` ≠ `monitoring` (different remediation, similar low credit); `partial_*` < `*_enforced`; `quarantine_enforced` < `reject_enforced`; `partial_reject` > `partial_quarantine`. All are enforced by the fixture matrix (§16).

**Methodology versioning [Recommendation]:** any change to these weights bumps the DMARC scoring methodology version (as with `CYBER_MOT_RESOLVER_VERSION` / CMS+BRI stamps), so a weight change can never read as a posture movement across history. Cross-version comparison is `not_comparable`.

---

# 12. Historical Compatibility

**Do not rewrite history** (CLAUDE.md — historical integrity is sacred).

- **Existing snapshots [Verified constraint].** M5.c snapshots are immutable, checksum-bound R2 objects composed from canonical producers. They are **not** recomputed. New scans produce snapshots carrying the new DMARC state and its `state_model_version`; older snapshots keep their original values and stamps.
- **Existing reports.** Already-rendered reports (PDF/Executive) are historical artefacts and remain as issued. Only future renders use the canonical object.
- **Existing findings.** Legacy DMARC findings (`email_missing_dmarc`, `email_dmarc_policy_none`, etc.) remain in history. Going forward they are derived from the canonical object; they are not retro-relabelled.
- **Existing timelines / `asset_events`.** Prior events keep their original vocabulary. Any historical event that recorded "missing" where the truth was "unavailable" is left as-is (immutable), and the comparability gate ensures it is not compared against new `not_observed` states as if continuous. Pre-model history is honestly absent, never backfilled.
- **Methodology versioning.** `state_model_version` stamps every new canonical state (§8). A version change is `not_comparable` across the boundary (Phase A gate), preventing fabricated regressions when the model itself changes.
- **Reconstruction policy.** Consistent with M5.d: historical surfaces are reconstructed from their own stamped snapshot with provenance, and **no current-state injection** — an old report never shows today's DMARC state.

---

# 13. Migration Strategy

**Is a migration required? No. [Recommendation]**

This ADR consolidates *derivation logic*, not storage. The primitives are already parsed and already stored (in scans/snapshots/`asset_events`). The canonical object is computed from existing inputs at read/finalize time. No new table, column, index or purge-order change is needed.

**Why not [Inference].** Nothing here requires persisting a new shape to satisfy the contract: consumers can consume the canonical object computed by the shared function. Persisting a derived state would duplicate what the immutable snapshot already composes (M5.c), and would risk snapshot/derived-state disagreement — the exact class of defect M5.c closed.

**If persistence is later wanted [Recommendation].** Should a future need arise to store the canonical `enforcement_level` for query performance (e.g. MSP portfolio filters), it must be:
- an **additive** migration (new nullable column or a new append-only table), numbered and validated per CLAUDE.md;
- **derived, never authoritative** — recomputable from primitives + `state_model_version`;
- **tenant-scoped** with an isolation test;
- **backfill-free for truth** — historical rows are stamped with the model version under which they were computed and are `not_comparable` across versions; no destructive rewrite.

Any destructive change remains High Risk and founder-gated.

---

# 14. Implementation Plan

Split into minimal, independently reviewable, additive PRs. Every PR is additive and reversible; none introduces a migration.

| PR | Scope | Owner | Notes |
|---|---|---|---|
| **PR-1** | `deriveDmarcState()` + canonical object (nine-rung `enforcement_level` + `caveats` array) + `evidence_status`/`not_observed` DNS-failure signal at the probe (`email-scan.js:23`). Unit + mutation tests for the full decision tree (§6), incl. the `pct=0` intent-family cases. No consumer switched yet. | **Codex (backend)** | Foundational. Must fix the probe so `unavailable` is distinguishable *before* any consumer reads it. |
| **PR-2** | Point scoring + Business Risk (`_score_dmarc`, `posture-scoring.js`, `business-risk.js`) at the canonical object; enforce §11 **monotonic ladder** (weaker rung ≤ stronger; only `reject_enforced` full-credit; `quarantine_enforced` small penalty; `not_observed`/`not_yet_assessed` score-neutral). Monotonicity fixture. | **Codex** | Highest correctness impact — stops scoring unobservable domains as unprotected and stops treating quarantine@100 as full green. |
| **PR-3** | Cyber MOT roll-up + Executive Report/PDF reasons consume canonical state (§7 tables), incl. the **deterministic** bridge (both `partial_*` → `issue_detected`; `quarantine_enforced` → `issue_detected`; only `reject_enforced` → `assessed_healthy`). | **Codex** | Includes the `CYBER_MOT_STATES` bridge table. |
| **PR-4** | Timeline / posture-events consume `enforcement_level` ladder transitions + comparability gate; "weakening" = move down the ladder; guarantee no event across `not_observed` (§10). | **Codex** | Directly reinforces Phase A trust invariants. |
| **PR-5** | API serialisation of `dmarc_state` (§8) with `enforcement_level`, `caveats`, `state_model_version`; legacy fields become derived. | **Codex** | Additive; legacy fields retained. |
| **PR-6** | Frontend: replace `JOURNEY_STAGES`, `DMARC_STATUS_STYLE`, the raw `p=` pill **and the inline `DmarcCard` kind derivation (`WorkspaceEmailProtectionPage.jsx`)** with one `enforcement_level`(+`caveats`)-keyed badge/label/wording map (§9), incl. the **distinct `quarantine_enforced` presentation** (near-complete, not reject-green). | **Claude (frontend)** | Copy, badges, tooltips, caveat-driven remediation; loading/empty/error/`not_observed` states. |
| **PR-7** | Consolidate DMARC remediation strings to resolve from the Canonical Remediation Registry (Problem #8), caveat-driven (`pct_below_100`→raise pct; `subdomain_gap`→set sp; `policy_applies_to_zero_percent`→raise pct with effective-behaviour note). | **Shared** | Removes the last independent remediation source. |
| **PR-8** | Validators: extend `validate-*.js` to assert cross-surface parity + the **monotonic scoring** and the **ramp-ladder-ordering parity** (read-side vs `DMARC_RAMP_LADDER`); add a DMARC state fixture set. | **Codex + Shared** | Acceptance gate (§16). |

**Ownership summary:**
- **Codex** — backend derivation (nine-rung ladder + caveats), probe fix, monotonic scoring, roll-ups, API, validators (incl. ramp-ladder ordering parity), tests, mutation coverage.
- **Claude** — frontend, customer/executive copy, reports UX, badges, tooltips, caveat-driven remediation, the distinct `quarantine_enforced` presentation, all state renders including `not_observed`.
- **Shared** — this ADR's contract approval, remediation-registry consolidation, and production verification on founder-controlled domains.

**Sequencing note [Recommendation].** PR-1 and PR-2 carry the correctness value and should land first. The remaining PRs are consistency/consolidation and can follow. This is an *engineering contract*, not a roadmap authorisation — it does not start the active canonical episode; scheduling remains founder-gated per CLAUDE.md.

---

# 15. Risks

**Technical risks [Recommendation/Inference]:**
- *Nine-rung ladder complexity.* More rungs mean more branches to cover. **Mitigation:** the fully-split ladder removes the need for any consumer to read a second field, so it *reduces* consumer branching; the decision tree (§6) is mutation-tested end-to-end, and the monotonic ordering + ramp-ladder-parity validators (§16) pin the rungs.
- *Two DMARC subsystems drift apart.* The read-side ladder and the hosted `DMARC_RAMP_LADDER` could diverge over time. **Mitigation:** the §16 ramp-ladder-ordering parity validator fails CI if read-side ordering stops mirroring the ramp ladder.
- *Consumer drift re-emerges.* A future engine adds its own derivation. **Mitigation:** a CI guard that fails when policy→posture logic (branching on raw `p=`/`pct`) appears outside the canonical function (grep-based, like existing drift guards).
- *Probe-fix regressions.* Changing `email-scan.js:23` touches the hot scan path. **Mitigation:** mutation-tested decision tree; the change is additive (adds an `unavailable` branch) and reversible.

**Customer risks [Inference]:**
- *Score movement on rollout.* Domains previously penalised as "missing" but truly "unavailable" will stop being penalised — a score can rise. **Mitigation:** this is a correctness fix; document it as methodology-versioned so it is not read as the customer's posture improving.
- *Wording change familiarity.* Labels change on the dashboard. **Mitigation:** wording table (§9) reviewed; no green added anywhere protection isn't real.

**Operational risks [Recommendation]:**
- *Partial rollout inconsistency.* Between PRs, some surfaces read canonical state and some legacy. **Mitigation:** legacy fields are *derived from* canonical from PR-1 onward, so they cannot diverge further; parity validators (PR-8) gate completion.

**Rollback strategy [Recommendation]:** every PR is code-only and additive with no migration, so rollback is a Worker redeploy of the prior version (record live + rollback Worker IDs per CLAUDE.md). No data migration means no data rollback. The `state_model_version` stamp means any state written under the new model remains self-describing after a rollback.

---

# 16. Acceptance Criteria

Objective, verifiable at completion:

1. **Backend parity.** One `deriveDmarcState()` is the only site that maps policy→posture; a CI guard proves no other backend site derives enforcement state (branches on raw `p=`/`pct`). [Verified by code + drift guard]
2. **Frontend parity.** `JOURNEY_STAGES`, `DMARC_STATUS_STYLE`, the raw `p=` pill **and the inline `DmarcCard` kind derivation (`WorkspaceEmailProtectionPage.jsx`)** no longer derive posture/colour; all four render `enforcement_level` (+`caveats`). `quarantine_enforced` renders in its distinct near-complete style, never the `reject_enforced` green. [Verified by frontend tests]
3. **API parity.** Every DMARC-bearing response carries `dmarc_state` with all twelve fields (incl. `enforcement_level` as one of the nine rungs and `caveats` as an array) + `state_model_version`; legacy fields equal the canonical derivation. [Verified by contract test]
4. **Report parity.** Executive Report and PDF wording for a given domain match the dashboard for the same scan, including the quarantine-vs-reject and partial-vs-full distinction. [Verified by fixture]
5. **Alert/timeline parity.** No event fires across a `not_observed` observation or a `state_model_version` boundary; "weakening" is a move down the ladder; silent-on-stable holds. [Verified by `validate-posture-events` extension]
6. **Cross-surface state parity.** A fixture matrix (the §6 examples, at minimum — all nine rungs + every caveat, incl. both `pct=0` intent cases and both `sp=none` cases) yields identical `enforcement_level` and `caveats` across scoring, Cyber MOT, report, API and frontend. [Verified by new validator]
6a. **`quarantine_enforced` classification + wording.** `quarantine_enforced` maps to Cyber MOT `issue_detected` (never `assessed_healthy`), and its customer/executive wording acknowledges active enforcement while recommending progression to reject — and never labels it missing, invalid, monitoring-only, partial, or unverified. [Founder decision item 1 — verified by fixture + frontend copy test]
6b. **Multiple-caveat preservation + lead ordering.** A fixture with co-occurring caveats (e.g. `p=reject; pct=0; sp=none` → `[policy_applies_to_zero_percent, subdomain_gap]`) proves every applicable caveat is preserved in the API and surfaced in the UI, and that the lead remediation follows the canonical priority `policy_applies_to_zero_percent > subdomain_gap > pct_below_100`. No caveat is dropped, suppressed, overwritten, or hidden. [Founder decision item 2 — verified by new validator]
7. **Monotonic scoring parity.** The fixture matrix proves the score is monotonic along the ladder (`no_record ≤ invalid_record ≤ monitoring ≤ partial_quarantine ≤ quarantine_enforced ≤ partial_reject ≤ reject_enforced`), that **only `reject_enforced`** takes full credit, that `quarantine_enforced` carries a strictly-smaller-than-full penalty, and that `not_observed`/`not_yet_assessed` are score-neutral (neither credit nor debit). [New validator — enforces founder revision item 7]
8. **Ramp-ladder ordering parity.** A parity validator asserts the read-side `enforcement_level` ordering mirrors the hosted `DMARC_RAMP_LADDER` macro-ordering (`none → quarantine-ramp → quarantine@100 → reject-ramp → reject@100`), so the read-side and change-management subsystems cannot drift apart. [New validator — enforces founder revision item 2; complements `scripts/validate-dmarc-graduated-ramp.js`]
9. **The unavailable-≠-missing proof.** A simulated DNS failure yields `enforcement_level=not_observed`, **no score penalty**, `unavailable` Cyber MOT state, and **no timeline regression** — reproduced end-to-end. [Primary acceptance gate for Problem #1]
10. **Production verification.** On a founder-controlled domain: authenticated API returns the canonical object; a known enforcing record renders the correct rung (e.g. `reject_enforced`) consistently across surfaces; a deliberately induced resolver failure renders `not_observed`, not `no_record`. (Unauthenticated route existence is not proof — CLAUDE.md.)

---

# 17. Future Work — Explicitly Out of Scope

This ADR does not expand into any of the following. Each is a separate decision.

- **DMARC posture alerting.** Whether to make DMARC posture alertable at all (today it is deliberately not). This ADR only defines the honesty contract such alerts would obey if later approved.
- **Alignment mode (`adkim`/`aspf` strict vs relaxed).** Not part of `enforcement_level` v1; may become a future primitive-driven refinement.
- **Impact forecasting / before-after.** `dmarc-impact.js` forecasting is unchanged and remains a consumer, not part of the state model.
- **Sender classification / RUA aggregate analysis.** `dmarc-ingest.js` XML ingestion and sender intelligence are separate subsystems.
- **Hosted DMARC change-management ladder.** The ramp ladder stays a change-management model; only its *observation* input becomes canonical.
- **MTA-STS / TLS-RPT / BIMI posture.** Related email-trust signals, governed separately (BIMI merely consumes `enforcement_level` per §7).
- **Persisting derived state to D1.** Only if a future performance need arises, under the additive-migration constraints of §13.
- **Behaviour Intelligence / cross-domain correlation.** Out of scope; sensor-dependent and founder-gated per the current roadmap.

---

*End of ADR-003. Documentation only — no code, no migration, no deployment, no tag, no DMARC implementation. Placed under the repository ADR convention (`docs/12-ADR-003-…`) via a documentation-only PR for review.*
