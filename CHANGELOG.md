# Changelog

Internal release notes for CyberMeters. Newest first. `APP_VERSION` in
`workers/scan-api/wrangler.toml` tracks the human version; each production
release is git-tagged `vYYYY.MM.DD-n` and the deployment id is visible at
`GET /health`.

## 2026.07.16-14 (Cyber Essentials readiness honesty — no proxy scoring) — deployed 2026-07-16

- **Live Worker Version ID:** `1ebf34f0-7576-4a1b-9324-fe78750c0904` (main `72b5265`)
- **Rollback Worker Version ID:** `82de6cfa-86cf-4488-8730-43eff9cc35b8` (v2026.07.16-13)
- **Remote D1 migrations applied:** none — no schema change (latest remains `091`).
- **Pages:** auto-deploys from main (CE page changed).
- **PR:** #136

A live grading and reporting defect, reproduced before any edit. Same site — same HTTPS,
HSTS, CSP, zero findings — with ONLY the email records removed: Access Control 100 -> 60,
Phishing & Malware Exposure 100 -> 60, overall CE readiness 100 -> 84.

Both controls declare `external_coverage: none` in the repo's own honesty metadata, yet both
were scored 0-100 from SPF/DKIM/DMARC, given colour bands, flagged `externally_assessed:
true`, and each carried 20% of the indicator. A business with perfect MFA and least
privilege scored 60/100 on "Access Control" for a missing SPF record; one with no MFA at all
scored 100/100 in green, with "SPF is present." offered as the reason.

Email authentication tells you whether someone can spoof your domain. It says nothing about
whether staff use MFA, whether admin rights are separated, or whether leavers are
deprovisioned, and it cannot tell you whether AV is installed on a single device. The proxy
was not weak evidence — it was evidence of a different thing. The malware copy admitted it
was "estimated from available signals only" and printed 100/100 in green anyway; the
admission did not undo the claim.

It also contradicted the platform's OWN case path, which has always treated both controls as
`not_externally_assessable` (`v2026.07.16-13`). The scoring path and the case path now read
one source of truth: `CE_QUESTIONS.external_coverage`.

Both controls stay VISIBLE — hiding them would be its own dishonesty — with `score: null`
(not 0, not 100), `weight: 0`, no band, `externally_assessed: false`, and one reason:
"Not externally assessable — self-attestation only". The indicator is now the mean of the
three assessable areas and states its denominator: "External readiness indicator based on
3 of 5 Cyber Essentials control areas. Access Control and Phishing & Malware Exposure
require customer attestation." That statement rides on the readiness object, the Executive
PDF and the authenticated page.

Deliberate consequences, recorded rather than discovered later:
- CE external readiness no longer moves on email posture at all. That evidence lives in
  Email Protection, and still does (asserted).
- `ce_saas_access_review` was attributed ONLY to access_control and is gone from CE. SaaS
  exposure remains visible in Shadow IT; admin surfaces already drive `boundary_protection`
  (an assessable control) and Attack Surface, so nothing observable is lost.
- `validate-probe-evidence-honesty` asserted the old attribution. Corrected rather than
  weakened: CE must NOT attribute DMARC, AND the gap must still live in Email Protection —
  both asserted, so this change cannot become a silencer.

Also corrected: the Executive PDF printed "No data" for a control it cannot see (wrong
wording) and now prints the honest label with no bar and no colour; the authenticated page's
`score ?? 0` painted "not assessed" RED, and an absent indicator is now neutral.

**Production proof:** `/health` polled to 6 consecutive reads of `1ebf34f0` (it flapped
across PoPs before settling); `/ready` d1+r2 true; the CE readiness route returns a
customer-safe `401` unauthenticated — live and auth-gated, which is NOT proof of the
authenticated workflow. No customer case, alert or email was manufactured.

## 2026.07.16-13 (M5.a PR3 — Cyber Essentials managed cases; M5.a CLOSED) — deployed 2026-07-16

- **Live Worker Version ID:** `82de6cfa-86cf-4488-8730-43eff9cc35b8` (main `dd83daf`)
- **Rollback Worker Version ID:** `6d1aaaa7-f283-4ae8-af3b-c2a3d2b2130f` (v2026.07.16-12)
- **Remote D1 migrations applied:** none — no schema change (latest remains `091`).
- **Pages:** unaffected (no frontend change).
- **PR:** #134

The third and final M5.a vertical. **M5.a is closed**: Email Protection, Website Security
and Cyber Essentials each now have creation, linkage, case-level ownership, honest
verification and recurrence in production.

Migration 090 reserved `cyber_essentials_control_records.linked_case_id` and a `case_linked`
event type and both had been dead since. They now mean something.

**The authority map.** Of the five canonical CE controls the repo's own honesty metadata
declares only THREE externally assessable, and only ever PARTIALLY — `boundary_protection`,
`secure_configuration` and `patch_management_readiness` are `external_coverage: partial`;
`access_control` and `malware_protection` are `none`, scored from email-auth proxies that
measure anti-spoofing, not user access control or endpoint AV. `gradeCeControl` returns
`not_externally_assessable` for those two, which is never actionable, so they carry no
recurrence and can NEVER open a case. That is the honest answer rather than an omission:
there is no external observation to base a case on and no verifier could ever close one.

**The partial ceiling.** The three assessable controls are partial, not full, so a case must
never imply the CONTROL is compliant. The case title, summary and the verification evidence
itself (`verification_scope: externally_observable_evidence_only`, `external_coverage:
partial`) all scope the claim to the externally observable evidence. This is the
`v2026.07.16-6` "fully validated" defect class: a partial check must not be reported as a
complete one.

Both CE recurrences resolve to `ce.readiness.control_review` → `rescan` → automated, so a
customer attestation can never conclude a CE case. That falls out of the registry, not a
special case here.

Verification has four stops, each mutation-proven: CE's own `control_recovered`
(`condition_resolved` is Website Security's vocabulary and concludes nothing here); evidence
completeness, re-checked INSIDE the verifier and defaulting to refuse; the registry per
finding; and the case machine.

The suite drives the REAL evaluator end to end through six passes — baseline, deterioration,
unchanged repeat, dead probe, recovery, re-deterioration — and that end-to-end pass is what
proves the lifecycle actually calls the case layer. It also caught a wrong assumption in the
test itself: removing HSTS+CSP makes TWO controls not-ready, and the engine correctly opens
one case per control record.

Purge is proven rather than assumed: a workspace with linked CE cases purges to nothing
(records, events, cases, case events, questionnaire answers), leaves no `linked_case_id`
orphan, and does not touch the other tenant. Mutations reintroduce both the `#106` defect
(answers dropped from purge) and a broken purge order.

**Production proof:** `/health` polled to 6 consecutive reads of `82de6cfa` (it flapped
across PoPs before settling); `/ready` d1+r2 true; `/api/workspaces/:id/cyber-essentials/
controls`, its detail route and `/managed-cases` each return a customer-safe `401`
unauthenticated — live and auth-gated, which is NOT proof of the authenticated workflow.
No customer case, alert or email was manufactured. Authenticated customer acceptance with
real CE lifecycle events remains a release-gate activity.

## 2026.07.16-12 (M5.a PR2 — Website Security managed cases + verification vocabulary) — deployed 2026-07-16

- **Live Worker Version ID:** `6d1aaaa7-f283-4ae8-af3b-c2a3d2b2130f` (main `54d08e7`)
- **Rollback Worker Version ID:** `33069515-d515-4093-91c2-0aea2331dca5` (v2026.07.16-11)
- **Remote D1 migrations applied:** none — no schema change (latest remains `091`).
- **Pages:** auto-deploys from main (case display + queue changed).
- **PR:** #132

The second of three vertical M5.a domain increments. Website Security ships creation,
linkage, case-level ownership, honest verification and recurrence together. Migration 089
reserved `website_security_conditions.linked_case_id` and a `case_linked` event type and
both had been dead since — the column was always null and the route's linked_case lookup
could never return anything. They now mean something.

Every Website Security recurrence opens a case, unlike Email which had to exclude
`hosted_impact_regression`. All 14 condition keys (2 ssl_* + 6 headers x missing/malformed)
resolve to `https_recheck`, and ONE recovery event — `condition_resolved` — covers every one
of them, so no condition here can be opened but never honestly closed. `control_recovered`
is Cyber Essentials' vocabulary and verifies nothing in this domain.

Verification has three independent stops, each mutation-proven: the detecting module must
provably have run (re-checked INSIDE the verifier rather than trusted from the caller's
branch — the #105 defect class, and "the caller was in the right branch" is not a contract);
the registry decides per finding; and the case machine still governs the path. Incomplete,
partial or never-executed evidence produces a deferred history row, never a verification.

**Two live defects found and fixed.**

**P1 — the managed lifecycle dead-ended at `assigned`.** `approved: [requireActor]` was
registered bare, but guards are invoked `guard(caseRecord, ctx)` and `requireActor` takes the
ctx as its ONLY argument. It received the case row, found no `actor_id`, and refused EVERY
approval — making `approved` unreachable for all six base domains, and with it
`awaiting_verification` and `verified`. The Email cases shipped in `v2026.07.16-11` could
never have been verified in production. `brand-case-machine.js` had always wrapped it
correctly; this line never did. PR #130's suite missed it by jumping straight to
`awaiting_verification` instead of walking the path a customer walks; the new suite walks the
whole path for every base case type.

**Verification vocabulary.** Case phase `verified` rendered "Verified" in green for every
case — including Email's `manual_attestation` cases, where the registry says the product
CANNOT observe the fix. `verification_support` is now exposed on the case API (the backend
owns it; a screen inferring it would be deriving a verification verdict) and the display
splits "Verified by CyberMeters" from "Attested by customer — not externally verifiable",
failing closed to the weaker claim. `docs/verification-vocabulary.md` is the canonical record
and carries the rule into the M5.e parity matrix and the Unified Reporting snapshot.

`resolveRemediation` now REFUSES unknown arguments instead of silently returning an unknown
resolution. Passing `{remediation_id}` yielded `verification_method: null` and would have
made every case in a domain permanently unverifiable — it failed silently, in the
honest-looking direction, on the one path where being wrong is invisible. A repository-wide
audit found no live misuse remains: every call site passes `{finding_type}`. An unknown
finding type still fails honestly rather than throwing.

**Production proof:** `/health` polled to 6 consecutive reads of `6d1aaaa7` (it flapped
across PoPs for the first three reads before settling); `/ready` d1+r2 true. Behavioural
contract proof is CI-side; authenticated customer acceptance with real Website Security
lifecycle events remains a release-gate activity.

## 2026.07.16-11 (M5.a PR1 — Email Protection managed cases) — deployed 2026-07-16

- **Live Worker Version ID:** `33069515-d515-4093-91c2-0aea2331dca5` (main `7344c59`)
- **Rollback Worker Version ID:** `8a34ea0a-b728-48ff-b412-e1b9546d0d73` (v2026.07.16-10)
- **Remote D1 migrations applied:** none — no schema change (latest remains `091`).
- **Pages:** unaffected (no frontend change).
- **PR:** #130

The first of three vertical M5.a domain increments. Email Protection now ships case
creation, linkage, case-level ownership, honest verification and recurrence **together** —
the founder's vertical rule forbids a production state holding cases with no honest
verifier, or a verifier with no customer-visible linkage.

Five of Email's six recurrences open a canonical case via `createManagedCase`;
`hosted_impact_regression` deliberately opens **none**. Its registry method is
`receiver_reports`, so the product genuinely can observe it — but the engine emits the
regression and never an "impact recovered" signal, so no verifier exists. Declaring it
`unsupported` would contradict the registry; opening a case anyway would create one that
can never honestly close. It continues to alert exactly as before, and the missing
impact-recovery verifier is recorded as a gap rather than guessed at.

Verification support comes from `v2026.07.16-10`'s per-finding contract, so it splits
within the domain: `hosted_record_disconnected` (`dns_recheck`) and
`sender_unauthorised_failures_active` (`receiver_reports`) are **automated** — a customer
cannot self-certify what CyberMeters re-observes, and only a real recovery observation
(`hosted_record_reconnected` / `sender_failures_recovered`) verifies them. The three
`manual_attestation` conditions accept a structured attestation as their ceiling.
Attestation-only non-verification is asserted in CI.

No migration was needed: `managed_cases.finding_id` already carries the lifecycle record
id and `createManagedCase` already dedupes on (workspace_id, case_type, finding_id) among
non-terminal cases, so an unchanged pass creates nothing and the reverse lookup is a query.
Ownership uses universal case-level assignment per the founder's M5.a decision; the absence
of business/technical/remediation-owner fields is an intentional parity difference recorded
for M5.e.

`scripts/validate-m5a-email-cases.js` (89 assertions, CI-blocking) covers the six-recurrence
map, creation/linkage/dedupe, tenancy, ownership, the verification boundary, system
verification, attestation-only non-verification, recurrence reopen, and no-parallel-model —
including 9 mutations, each proven to apply and reproduce its defect.

One bug this caught before production: case verification resolved remediation via
`resolveRemediation({remediation_id})`, which resolves by finding_type only and returned an
unknown resolution — `verification_method: undefined` would have made **every** email case
unverifiable. Now `getRemediationById`.

**Production proof:** `/health` polled to 6 consecutive reads of `33069515`, no flapping.
Behavioural contract proof is CI-side; authenticated customer acceptance with real Email
lifecycle events remains a release-gate activity.

## 2026.07.16-10 (Case verification contract — registry-derived, per finding) — deployed 2026-07-16

- **Live Worker Version ID:** `8a34ea0a-b728-48ff-b412-e1b9546d0d73` (main `8001496`)
- **Rollback Worker Version ID:** `3ad513ee-bec5-4634-963f-eb08c57d7a43` (v2026.07.16-9)
- **Remote D1 migrations applied:** none — no schema change.
- **Pages:** unaffected (no frontend change).
- **PR:** #129

The foundation for managed cases on Email Protection / Website Security / Cyber Essentials,
landed FIRST and deliberately: creating those cases under the previous contract would have
shipped cases a CUSTOMER COULD MARK VERIFIED BY ASSERTING.

`verification_support` was a property of the case_type (`baseEntry` → `"manual"`, so a
structured attestation reached `verified`). A case_type is the WRONG GRAIN, and both blanket
answers are wrong for Email, whose case-producing conditions the registry already grades
differently — `hosted_record_disconnected` → `dns_recheck` (observable), while
`hosted_rolled_back_auto` and `sender_unrecognised` → `manual_attestation`. Blanket `manual`
lets a customer self-certify a DNS record CyberMeters re-observes; blanket `automated` makes
three of Email's six conditions unverifiable forever. **The blanket answer was tried first
and the tests caught it.**

The Canonical Remediation Registry had already decided this per finding, and CLAUDE.md makes
it the source of truth for remediation meaning "including ... verification method". Its
vocabulary is explicit: `manual_attestation // customer confirms; product cannot observe it`.
So the model asks it: `manual_attestation` → attestation is the honest ceiling; any
observable method (`dns_recheck` / `https_recheck` / `rescan` / `certificate_recheck` /
`receiver_reports` / `external`) → only CyberMeters' own observation verifies and the
customer cannot conclude it; unresolvable or absent → **fails closed** to unsupported, because
an unknown finding is not an invitation to self-certify.

Not a new product semantic — CLAUDE.md's existing rule read literally: "Verification requires
structured, METHOD-APPROPRIATE evidence", where attestation is method-appropriate exactly, and
only, where observation is impossible. Measured today: Website Security 9/9 observable, CE's
case-producing findings `rescan`/`external`, Email mixed.

Scoped to `email_case` / `website_case` / `cyber_essentials_case`. `certificate_case`,
`identity_case` and `shadow_it_case` are closed increments and keep their per-type answer.

`validate-managed-case-model` used `email_case` as its example of "base manual"; it is no
longer one, so the vehicle moved to `identity_case`, which still is. **The base-manual
contract itself is unchanged and still asserted** — only the case type demonstrating it moved.
92 → 107 assertions.

**INERT IN PRODUCTION:** no Email/Website/CE case exists yet, so this changes no live
behaviour. It defines the rule before the cases arrive. Deployed to keep main and production
aligned rather than to change anything.

**Validation:** 104/104 CI validators · regression 227/227 · wrangler dry-run clean ·
exact-HEAD CI confirmed on `9cc2fbe`.

**Production proof:** `/health` polled to 6 consecutive reads of `8a34ea0a`; `/ready` d1+r2
true; read surfaces still `401` (unchanged, as expected for an inert contract).

**NOT delivered by this increment — the managed-case increment is OPEN:** case creation for
the three domains, `linked_case_id` population, the verifiers that consume the existing
recovery evidence, and ownership/assignment. See the founder report.

## 2026.07.16-9 (M5 read surfaces — mig 088/089/090 were write-only) — deployed 2026-07-16

- **Live Worker Version ID:** `3ad513ee-bec5-4634-963f-eb08c57d7a43` (main `62b7272`)
- **Rollback Worker Version ID:** `db190243-5f44-4f70-ab4f-ecfe0427b8b7` (v2026.07.16-8)
- **Pages deployment:** `5d56ebe7-3502-434f-ad7e-dfca05ca8b27` (Production, from `62b7272`)
- **Remote D1 migrations applied:** none — no schema change.
- **PRs:** #127 (read APIs) · #128 (surfaces + alert deep links)

Mapping confirmed **from the repo**, not the migration names: 088 = Email Protection
(`email_protection_events`, events only — no state table), 089 = Website Security
(`website_security_conditions` + `_events`), 090 = Cyber Essentials
(`cyber_essentials_control_records` + `_events`).

**All three shipped a lifecycle that WRITES records and ALERTS on them, with no way for a
customer to read them.** 089 had zero routes, both engine read helpers at zero callers, no
page, no nav entry and no api.js method. 090's `listCeControlRecords` had zero callers
repo-wide. 088 had no read helper at all, and the four lifecycle columns it added to
`email_sender_sources` are stripped before they leave the API. A record is not
customer-visible merely because it exists in D1.

**The alert symptom, located exactly:** 0 of 6 `emitLifecycleAlert` calls passed a `link`,
so `managed-alerts.js` fell back to `${origin}/notifications` — a customer told their
hosted DMARC record had disconnected, at `high`, landed on a generic list. The in-app card
was worse: `NotificationsPage` derived a destination only from `metadata.scan_id`/
`report_id` and never read `metadata.link`, so lifecycle alerts rendered `cursor-default`
and went nowhere while the same alert's email carried a link.

**Read APIs** (one style, matching `routes/certificates-lifecycle.js` — auth → role →
workspace gate → record; foreign ≡ nonexistent; `scope_note` on every response):
`GET /website-security/conditions[/:id]`, `GET /cyber-essentials/controls[/:id]`,
`GET /email-protection/lifecycle`. Email is shaped differently because mig 088 is — it
created no state table, so the resource is the history itself.

**Reuse meant fixing first.** The zero-caller helpers could not simply be called: `SELECT *`
(would have served `evaluated_at`, documented diagnostic-only), no `LIMIT` (unbounded), and
`ORDER BY last_seen_at DESC` alone (ties on every condition seen in the same scan). Each
now has a serializer deciding once what a customer may see, a bound, and a deterministic
order. Pagination uses the shared `lib/util.js` contract, which util.js documents as "every
list endpoint" and only 2 of 14 routes honoured.

**Alert deep links** are built in ONE place (`lifecycleRecordLink`), not at six call sites,
and every target is asserted to be a route `App.jsx` actually declares. Domains with no
read surface resolve to null — honest, since the notifications list is where the customer
would have gone anyway.

**Honesty is rendered, not asserted.** `unknown` is styled neutral and captioned "This is
not a fix", never green. CE coverage shows on every control because two of the five are
permanently `not_externally_assessable`; no CE control can render "verified" — there is no
such state in the vocabulary. The CE external-evidence section is a separate block with a
separate vocabulary from the self-assessment: merging them is how a self-attested answer
starts looking verified.

**A locked product model the tests defended.** Website Security was first added as a FIFTH
sidebar service; `WorkspaceNav.test.jsx` asserts "exactly the four services" and
`SERVICE_COLORS` has four keys. A fifth service is a founder-level product decision, not
something to slip in behind a read surface. Reverted to a sub-item of Attack Surface,
following the precedent already set for Identity Exposure.

**Three decorative guards of my own, caught by mutation and fixed:** the deep-link guard
checked a hardcoded path rather than the one the link points at (so a link to a nonexistent
route passed); the metadata guard matched the top-level `link:` argument too (so deleting
the metadata field left it green and the card dark); and a soft-delete test asserted 404
when the real behaviour is 403 (`requireWorkspaceRole` gets there first — the route gate
only closes the delete-between-checks window).

**Validation:** 103/103 CI validators · new `validate-m5-read-surfaces.js` (100 assertions,
CI-blocking) drives the REAL Worker over the real schema · frontend 261 tests + build +
playwright · regression 227/227 · tenant isolation green · exact-HEAD CI confirmed on
`324b059` (#127) and `4b3d6a1` (#128).

**Production proof:** propagation flapped across edge PoPs, so the version was polled until
6 consecutive reads served `3ad513ee`. `/ready` d1+r2 true. All three new routes return
`401` (mounted and auth-gated, nothing enumerated). `app.cybermeters.com/ws/website-security`
200. No customer alert was manufactured: every test ran against in-memory SQLite with
`fetch` stubbed, and the smoke is unauthenticated and observation-only.

**Not closed by this increment:** case creation for Email/Website/CE (so `linked_case_id`
is still always null for 089/090 and the API must not imply a case exists), ownership and
verification workflows beyond honest read display, and the maturity ledger.

## 2026.07.16-8 (Occurrence resolver — correct at any lifecycle age) — deployed 2026-07-16

- **Live Worker Version ID:** `db190243-5f44-4f70-ab4f-ecfe0427b8b7` (main `d63f422`)
- **Rollback Worker Version ID:** `029ee0b9-15e3-4761-84e6-9b7e28743842` (v2026.07.16-7)
- **Remote D1 migrations applied:** none — no schema change.
- **Pages:** unaffected (no frontend change).
- **PR:** #126

**What the audit claimed, and what actually happens.** The audit reported that Shadow IT
alerting self-destructs after ~25 passes. Reproduced against the real engine, the mechanism
is exactly right and lands at **pass 26** — but the customer-visible harm did **not**
reproduce, and this entry says so rather than repeating the headline.

`findConditionOccurrence` read `LIMIT 25` `monitoring_changed` rows and filtered
`to_recurrence_type` in JavaScript. That event type is overloaded — it also records
`reappeared`, `no_longer_observed` and case-linkage — and Shadow IT appended one
case-linkage row per evaluation pass while a condition persisted. Measured on one item:
**148 `monitoring_changed` rows, 4 of them real occurrences**; the resolver returned the
occurrence on passes 1-25 and NULL from 26 onward, forever.

But alerts stayed correctly at **1** across 40 passes — the dedupe key IS the occurrence
id, so those passes would have deduped anyway; eviction and dedupe produce identical
silence. And a genuine recurrence still alerted: driven through recovery → re-entry after
**143 intervening events**, the occurrence resolved and the customer was told. The defect
was that **correctness rested on the ordering** — the real transition happened to be
written immediately before the read, so it happened to still be inside the window. An
arbitrary event window is not lifecycle state, and 25 is not a bound; it is a number.

**The fix.** The resolver now asks SQL for the exact row: the `to_recurrence_type` filter
is pushed into the query (guarded by `CASE WHEN json_valid(...)`), ordered
`created_at DESC, rowid DESC`, `LIMIT 1`. `LIMIT 1` is semantic — exactly one row can be
the latest transition into a condition — and it is an ordered index walk that stops at the
first match, measured correct past **25, 50, 100 and 500** intervening events. Not a bigger
magic number, not an unbounded scan, no parallel state machine, no deleted history, no new
state record. It is the SHARED resolver, so the fix lands for all eight domains.
`json_valid()` is load-bearing: a bare `json_extract()` throws on one malformed row and
would take the whole read — and every alert for that record — down with it.

**Root cause, fixed as a class.** The per-pass case-linkage row is not a monitoring change
and is now `case_recurrence_noted` in all three domains that wrote the identical row
(shadow-it, identity, certificates), declared in each domain's own event vocabulary.
Measured: 148 rows → 7. Fixing only the reported domain is how `#105` left the same defect
live elsewhere.

**Behavioural change:** strictly widening and fail-closed. The new read returns the same
row wherever the old one returned anything; it only recovers occurrences the window had
orphaned. Legacy production rows still carry the old event type and behave identically —
the case-linkage row never carried `to_recurrence_type`, so no reader's answer changes.
History now records the same fact under two types (old `monitoring_changed`, new
`case_recurrence_noted`); any future by-type timeline must handle both.

**Four defects an independent review found in this change — all mine, all corrected before
merge:** (1) a **false** claim, shipped in three comments, that the retype shortens the
resolver's index walk — every index is `(fk, created_at)` with no `event_type`, so the walk
is unchanged and the honest rationale is typing, not performance; (2) a **vacuous** tenant
assertion that was true for every possible engine behaviour because the API does not select
`workspace_id`; (3) a planner-dependent ORDER BY mutant, now stated as such and joined by a
planner-independent tie-break mutant; (4) a comment overclaiming which payload shapes are
pinned. Also recorded: `LIMIT 1 → LIMIT 25` with the filter intact is an **equivalent
mutant** — undetectable, so deliberately not guarded rather than faked.

**Validation:** 103/103 CI validators · regression 227/227 · tenant isolation green ·
purge + migration validators green · wrangler dry-run clean · exact-HEAD CI confirmed on
`5d220db`. validate-alert-occurrence 88, validate-alerting-repair-mutations 57,
validate-shadow-it-correlation 66. Reverting the resolver fails 8 assertions.

**Production proof:** the first deploy attempt FAILED (`fetch failed`, transient Cloudflare
API error) and was verified to have shipped nothing — `/health` still served the previous
version — then retried successfully. Propagation flapped across edge PoPs (reads alternated
between old and new), so the version was polled until **6 consecutive reads** served
`db190243` before it was called live. `/ready` d1+r2 true. Shadow IT returns `404`
(non-enumerating); identity and certificates `401` (auth-gated). No real customer alert was
manufactured: every reproduction ran against in-memory SQLite with `fetch` stubbed.

**Outstanding, reported not fixed:** the case-linkage row and its `managed_case_events`
sibling are still written once per pass and still record no new fact — roughly 8,760
rows/item/year at hourly cadence. That is a storage/history concern with its own semantics
(does a still-open case want an hourly heartbeat at all?) and was not decided as a side
effect of an alerting fix.

## 2026.07.16-7 (M5 alerting repair — threat suppression + hosted re-alert) — deployed 2026-07-16

- **Live Worker Version ID:** `029ee0b9-15e3-4761-84e6-9b7e28743842` (main `325e09b`)
- **Rollback Worker Version ID:** `6b310472-702c-4e7a-bafd-92cbc4a1b83d` (v2026.07.16-6)
- **Remote D1 migrations applied:** none — no schema change.
- **Pages:** unaffected (no frontend change).
- **PR:** #125

Both defects were reproduced end-to-end against the real engines and the real schema
before a line was changed, and both were live on Worker `6b310472`.

**1. Marking a sender a THREAT turned its own high alert off.** The product carried TWO
sender vocabularies and pushed both through ONE slot: OBSERVED (`authorised …
unauthorised`, from `classifySender()`) and the customer's DISPOSITION
(`trusted/suspicious/threat/ignored/unknown`). They overlap on only `suspicious` and
`unknown`. `effectiveClassification` returned the customer's word verbatim and handed it
to `senderAlertBand()`, which speaks OBSERVED — so `threat`, `trusted` and `ignored` all
banded **null**. Reproduced: a sender with 80 receiver-reported failures held
`sender_unauthorised_failures_active` at band high with an alert delivered; the customer
marked it THREAT; condition and band both went to null. The customer's strongest signal
of danger deleted the evidence.

The correct mapping already existed as a PRIVATE copy inside `dmarc-impact.js`, while
`email-protection-lifecycle.js` and `rua-routing.js` each carried their own copy WITHOUT
it — three implementations, two wrong, which is why aliasing one function would have
fixed nothing. There is now ONE vocabulary and ONE mapping in the leaf authority
(`sender-classification.js`); the duplicates import it.

**The canonical customer-classification policy** (`resolveSenderPolicy`, beside the bands
and the trigger): the floor is the EVIDENCE and nothing the customer says lowers it; the
customer may ESCALATE (`threat` claims `unauthorised`, so it can only raise);
`trusted`/`ignored` may SUPPRESS but only where the evidence does not contradict; a
suppression meeting contradicting evidence is an explicit CONFLICT, not silence — the
alert stands at the observed band and the disagreement is named in history; anything
unrecognised FAILS CLOSED to medium. `ignored` now claims nothing rather than passing
through as a verdict — "don't tell me" is not "it is safe".

**2. A hosted DMARC record could alert on disconnection exactly ONCE.** Recovery is
appended as `hosted_record_reconnected`; `lastGradedCondition` read only
`monitoring_changed`, so the graded condition stayed `hosted_record_disconnected` across
the recovery, the second disconnect compared equal, and no event, occurrence or alert was
produced — forever. Fixed by correcting the READER, deliberately not by appending a
clearing `monitoring_changed`: `findConditionOccurrence` reads `LIMIT 25` of those rows
and filters in JS, so extra rows narrow the window a real transition can be found in —
the eviction defect the audit found in Shadow IT. Closure is an EXPLICIT, short list:
every non-alertable hosted event carries `to_recurrence_type: null`, so "any event
carrying the key" would let a POLICY CHANGE or MANUAL ROLLBACK close a live disconnection
and re-alert an outage that never went away. Only a genuine return to health is recovery.

**Canonical contract:** a recovered condition that RETURNS is a recurrence/re-entry on the
existing lifecycle — same condition, same canonical remediation, NEW occurrence, NEW
dedupe key — never an unchanged duplicate and never a new incident kind.

**Guards.** `validate-alert-b3-email-protection`'s hosted section had been titled
"disconnect → reconnect → re-disconnect" since it was written and never performed the
re-disconnect — the defect it was named after was live the whole time. It now drives the
full sequence (145 → 187 assertions). New CI-blocking
`validate-alerting-repair-mutations.js` (27 assertions) proves every guard load-bearing
across the seven required mutations. Reverting either fix fails the guards, verified.

**Honest limits, recorded rather than papered over:** mutation 6 (drop `workspace_id` from
the lifecycle lookup) is asserted STRUCTURALLY — a cross-tenant leak could not be
reproduced because the scenario cannot exist (`hosted_dns_entries.id` is the PRIMARY KEY,
so one record id cannot span two tenants and the events never collide). The predicate is
defence in depth, and the suite says so rather than staging an unreachable fixture and
calling it a leak. Two suites asserted the OLD collapsed contract and were corrected, not
weakened: b3 seeded `classification: "authorised"` in the CUSTOMER slot (a state the
classify route has rejected since `27f655f` and migration 074 forbids by design), and
`validate-sender-classification` asserted `effective_classification: "trusted"` — the
customer's word in an evidence-shaped field. `effective_classification` has no other
consumer, frontend or backend, so no shipped surface changed. One audit lead did not
survive checking: `sender_classification_worsened` was never gated on
`classificationRank` — it uses band ranks via `rankOf`, which is now unified onto the one
band ladder.

**Validation:** 103/103 CI validators · regression 227/227 · tenant isolation 86/86 ·
purge + migration validators green · wrangler dry-run clean · exact-HEAD CI confirmed on
`c9ab823`.

**Production proof:** both hosts serve `029ee0b9` (`api.cybermeters.com` and
`workers.dev`; the first read raced propagation and was re-checked until stable across 4
consecutive reads). `/ready` d1+r2 true. The touched surfaces return `401` — live and
auth-gated ahead of body parsing, so the smoke classified no sender and sent no alert. No
real customer alert was manufactured: every reproduction ran against in-memory SQLite
with `fetch` stubbed. Genuine live-event acceptance across all eight domains remains
outstanding and is a release-gate activity.

**Not started (M5 scope):** Shadow IT's 25-pass alerting self-destruct, the read surfaces
for migrations 088/089/090, case creation for Email Protection / Website Security / Cyber
Essentials, and the maturity ledger (corrected LAST). No pricing review, pentest,
controlled acceptance or customer invitations.

## 2026.07.16-6 (Evidence-honesty class fix — four false claims) — deployed 2026-07-16

- **Live Worker Version ID:** `6b310472-702c-4e7a-bafd-92cbc4a1b83d` (main `7119c63`)
- **Rollback Worker Version ID:** `18c075a7-92bf-41f2-a06b-38a17929b687` (v2026.07.16-5)
- **Remote D1 migrations applied:** none — no schema change.
- **Pages:** unaffected (no frontend change).
- **PR:** #123

The M5 pre-change parity audit across all eight domains found the platform asserting four
things the evidence does not support. Each breaches a permanent rule in `CLAUDE.md`. Each
shipped with a **passing** suite — that the suites could not see any of them is the finding.

1. **The Executive PDF told boards "SSL and certificate configuration is fully validated."**
   `sslScore` starts at 100 and only ever deducts for HTTPS availability, HTTP→HTTPS
   redirect and expiry, so `good` meant those three things. Chain validity, root trust,
   OCSP and revocation are never checked — Certificates & Trust already declares them
   `unknown`. The PDF contradicted our own limitation on the artifact customers forward to
   insurers and boards.

2. **Certificates & Trust rendered `assessed_healthy` off a total Certificate Transparency
   blackout.** CT is that module's only evidence source; with both logs down it recorded an
   `info` signal, returned `error: null` and no `incomplete`, so `moduleAssessed()` counted
   a zero-evidence module as materially assessed — and `certificates_trust` has
   `required: ["certificate_intelligence"]`, so that module *is* the verdict. This is the
   **same defect class as #105** (unexecuted probe → healthy), which was fixed in
   `headers-scan`/`ssl-scan` **only** — per module, not per class — so certificate
   intelligence kept the bug. Fixed with the identical canonical `incomplete` flag.

3. **Shadow IT laundered disappearance into "verified" removal** —
   `removal_verified = stillObserved ? "contradicted" : "verified"`. A customer assertion
   plus our failure to observe became "verified" and was served by the API, while the same
   file's header states *"disappearance != verified removal"* and its own event records
   `note: "not_verified_removed"`. Now **unverified**. `verified` is unreachable here by
   design: Shadow IT is external-observation-only and nothing external can prove an internal
   removal. The asymmetry is intended — we can disprove; we cannot confirm.

4. **Identity verification fabricated "Verified by CyberMeters"** — the contract accepted
   `material_change || last_changed_at`, i.e. ANY change ever recorded, so a provider change
   from two years ago verified an assertion made today. The change must now post-date the
   customer's action, anchored to the `customer_action_recorded` event. No migration: the
   append-only log already held the fact. Fails closed when the ordering is unknown.

**Behavioural change:** strictly in the honest direction. A CT blackout now degrades the
scan to `partial` (so other domains read *provisional*, not healthy) instead of reading
clean. This uses the pre-existing `buildScanQuality` contract — any `incomplete` module
degrades the scan, established by `565fccc` — not a new rule.

**Guards — mutation-tested, extended in the suites that own each class:**
`validate-probe-evidence-honesty` 68→81 (§5 CT blackout + its mutation) ·
`validate-cert-trust-l2` 20/20 · `validate-shadow-it-correlation` 48→54 ·
`validate-identity-exposure-lifecycle` 78→94. Each reintroduces its defect and requires the
suite to fail; each asserts **direction**, so a guard cannot pass by refusing to verify
anything. Two pre-existing guards were fake: shadow-it suite 11 only exercised the
CONTRADICTED branch (the `verified` branch shipped untested), and
`validate-alert-b3-email-protection.js:375` is titled "disconnect → reconnect →
re-disconnect" and never performs the re-disconnect (**recorded, not fixed — alerting is a
later M5 increment**).

**Timestamp normalisation:** the identity comparison reads `last_changed_at` (ISO, `Z`)
against `customer_action_at` (SQLite `datetime('now')` — UTC but no zone marker, which
`Date.parse` reads as LOCAL). Workers run UTC so production skew is zero, but under
Europe/London the same instant parses an hour apart and would falsely verify.
`parseInstant()` normalises; its guard **pins a non-UTC zone**, because on CI's UTC machine
the defect does not exist and the test would be decorative (verified by mutation under
`TZ=UTC`; green under UTC, Europe/London, America/Los_Angeles, Asia/Tokyo).

**Validation:** 102/102 CI validators · frontend 261 tests + build · regression fixtures
227/227 · `wrangler deploy --dry-run` clean.

**Production proof:** `GET /health` returns the new deployment id; certificates and
identity-exposure routes return `401` (live and auth-gated), shadow-it `404`
(non-enumerating). The CT-blackout path cannot be forced in production without a genuine
dual-CT outage, so its proof is the mutation-tested contract, not a live occurrence.
Authenticated UI smoke remains a final release-gate action.

**Not started (M5 scope, founder-sequenced):** alerting repair (hosted DMARC can never
re-alert after recovery; marking a sender **"threat" silences its own alert**; Shadow IT
alerting self-destructs after 25 passes), the missing read surfaces for migrations
088/089/090 (`listCeControlRecords` has **zero callers repo-wide**), case creation for
email/website/CE, and the **maturity ledger — wrong in all eight rows**, to be corrected
LAST once it can certify reality rather than aspiration. No pricing review, pentest,
controlled acceptance or customer invitations.

## 2026.07.16-5 (MSP Portfolio Per-Domain State and Trend) — deployed 2026-07-16

- **Live Worker Version ID:** `18c075a7-92bf-41f2-a06b-38a17929b687` (main `d97625b`)
- **Rollback Worker Version ID:** `f06f3c43-5c32-413d-a93e-5eb7e5808c9a` (v2026.07.16-4)
- **Remote D1 migrations applied:** `091-cyber-mot-domain-states.sql` — additive; table + 2 named indexes verified present, 16 columns, 0 rows.
- **Pages:** auto-deployed from `main`; `app.cybermeters.com/portfolio/domains` 200.
- **PRs:** #119 (exec-summary all-clear) · #120 (per-domain state + trend backend, mig 091) · #121 (per-domain UI)

The portfolio could say which **customer** was worst. It could not say which **domain**,
which of the eight Cyber MOT domains inside it, or **what changed**. The per-domain data
was already computed and thrown away — `LATEST_SCAN_CTE` partitions by `domain_id`, then
collapses it with `GROUP BY wd.workspace_id`.

**Why a table, when the resolver's own header says "no new storage".** Compute-on-read
from R2 is right for one workspace and wrong for a portfolio, twice over: R2 has no
multi-get, so 50 customers = 50 R2 reads + ~100 D1 reads + 50 full report parses per page
load; and re-deriving history through today's resolver rewrites what the customer saw
last month. So the canonical resolver's own output is persisted at scan finalize from the
report already in memory, and the portfolio reads D1 only — four queries for the whole
portfolio, independent of domain count. One place still decides what state a domain is
in; this is a record of what it decided.

**`resolver_version` is the first algorithm version stamped on a state a customer sees.**
The repo had none (`PROVIDER_MAP_VERSION` was the only persisted stamp, on one column).
Adding a `required` module or tightening a `match()` regex silently shifted every
historical state, with nothing recording that the ruler moved rather than the thing
measured. The trend now refuses to compare across a version boundary — a change we made
is never rendered as a change the customer caused.

**No blended portfolio score. Deliberately.** A customer at 86 with one critical domain
and nine healthy ones is not "Low risk", and a mean is how that gets said out loud.

Three findings recorded, not actioned (they are M5's, and acting on them here would have
been a different episode):

- `resolveCyberMotDomainStates` has **no staleness gate at all** — a `complete` scan from
  2019 still resolves `assessed_healthy` with full confidence on the Dashboard, Scan
  Detail, Executive Report and PDF. The portfolio adds freshness as its own axis rather
  than changing the resolver under four surfaces. **P1, open.**
- **Six divergent score-band ladders** exist against a module that says every rating
  surface "MUST delegate here" (the audit found six, not the three previously recorded).
  **P2, open.**
- Four of eight domains are unreachable from `WorkspaceNav`; `website_security` has no
  page; three managed pages read a `useParams` id their routes never declare and issue
  `GET /api/workspaces/undefined/...`. **P1, open — M5.**

> **Reachability, stated plainly.** `/api/portfolio/*` is gated on `portfolio_monitoring`
> (business+) and production has **0 business/enterprise subscriptions**, so no account
> can reach this feature. `cyber_mot_domain_states` holds **0 rows** and will stay empty
> until the next scan finalizes — the writer fires only at scan completion, and no scan
> was triggered to populate it (that would manufacture production lifecycle transitions
> and risk minting alerts). Behavioural proof is by harness against the exact deployed
> code path; authenticated customer acceptance is a release-gate action and remains
> outstanding.

> **Rollback is clean.** `f06f3c43` predates the table and never reads it. Migration 091
> is additive and its rollback is code-only: with no writer the table simply stops
> receiving rows and the portfolio degrades to "not yet assessed", which is honest rather
> than wrong.

## 2026.07.16-4 (Portfolio null-score honesty — absent evidence is not a verdict) — deployed 2026-07-16

- **Live Worker Version ID:** `f06f3c43-5c32-413d-a93e-5eb7e5808c9a` (PR #118, squash-merged as `e5b7e00`)
- **Rollback Worker Version ID:** `6dc509c8-226e-4e17-ae66-d7770b865b71` (PR #117, squash-merged as `027fab8`)
- **Remote D1 migrations applied:** none. `git diff ba6cbe4..e5b7e00 -- database/` is empty.
- **Pages:** auto-deployed from `main`; `app.cybermeters.com` 200.
- **PRs:** #117 (null-score honesty contract) · #118 (the all-clear said about nothing)

> **Rollback carries a known defect.** `6dc509c8` is #117 without #118 — it fixes the
> fabricated *score* but still tells an MSP with zero assessments that "No customer
> environments are currently in critical or high risk states." The pre-Gate-1 version
> is `4ad06deb`, which carries the original null→serious defect. Neither prior version
> is clean; prefer forward-fix. No migration means either rollback is schema-safe.

### Fix (a portfolio with no evidence was reported as serious risk)

- **`null` fell through the band ladder to 'serious'** (PR **#117**).
  - `generatePortfolioExecutiveSummary` classified with an inline `>= 75 / >= 55 / >= 35`, else `'serious'`. `null` fails all three, so a portfolio with no completed assessment published: *"Your portfolio of 2 customer environments is showing **serious** overall risk (portfolio score: **null/100**)."* An MSP that had onboarded customers but not yet scanned them was told they were in serious danger, with a `null` shown as the evidence. The inverse of healthy-washing, and the same sin — the alerts post-mortem already recorded that removing fabricated deductions alone would trade *"a fabricated failure for a fabricated pass"*. Absent evidence is neither.
  - **Contract (additive; `portfolio_score` keeps its meaning and value):** `portfolio_score_state` (`no_workspaces` | `evidence_insufficient` | `partial` | `available`), `portfolio_score_reason` (customer-safe prose — every non-available state says why), `portfolio_score_basis` (`{scored_workspaces,total_workspaces}`), `portfolio_score_band` (`healthy|moderate|elevated|serious`, or **null** when unsayable). `resolvePortfolioScoreState()` is the single source of truth; the API publishes it verbatim and the frontend renders a decision it did not make.
  - **Three further findings the work turned up.** `RiskBadge` fell back to `?? 'badge-low'`, so the backend's *honest* `'unknown'` rendered in low-risk blue on **15 surfaces** — a customer we knew nothing about looked identical to one verified fine; unrecognised now renders slate. **`partial` did not exist**: `portfolio_score` is the mean of the *scored* workspaces, so one 90 among five customers published a portfolio score of 90 — missing evidence silently flattering the verdict; the basis is now disclosed in the summary sentence itself. And `PortfolioRiskPage` carried a byte-identical 75/55/35 ladder plus a second copy in `scoreColor()`, both guarding `!= null` — which **NaN passes**, landing in the final else and painting the page red.
  - **Boundaries deliberately unchanged (75/55/35).** They do **not** match `portfolioRiskBand`'s 25/50/75 partition, and a third ladder exists at `portfolio-customers.js:92` (40/60/80). Reconciling them would silently restate real customers' scores — a product decision, not an honesty fix. Recorded, not actioned.

### Fix (the all-clear that was said about nothing)

- **"No customer environments are currently in critical or high risk states"** (PR **#118**).
  - Found by reading #117's own production-proof **output** rather than its assertions. `critical_workspaces`/`high_risk_workspaces` count bands equal to `'critical'`/`'high'`; an unassessed environment's band is `'unknown'`, so it counts toward neither and both read zero — not because the customers are safe but because nobody looked. The unconditional `else` then handed an MSP an all-clear about a portfolio it had no evidence for. **It survived #117 because it prints no number** — those guards hunted for `'serious'` and `null/100`, and this sentence contains neither.
  - The all-clear is now withheld entirely for `evidence_insufficient`/`no_workspaces`, and for `partial` it is scoped to the assessed subset and names its own blind spot. `available` is unchanged.

### Production proof and its limits

Both hosts serve `f06f3c43`; `/ready` d1+r2 true on both; unauthenticated `/api/portfolio/risk` → 401; across live traffic `portfolio_risk_snapshots` held **0 → 0** while `api_rate_limits` advanced **1801 → 1803**. `app.cybermeters.com` 200.

> **Latent, not customer-visible — and unexercisable in production.** `/api/portfolio/risk` is gated on `portfolio_monitoring` (business+) and production has **no business or enterprise subscription**, so no account could reach the defect or can now reach the fix. The entitled 200 path is proven against the **exact deployed code path** instead: all four states return honest output with no `null/100` and no verdict without a score. **This is harness proof, not customer acceptance.** Authenticated UI smoke on a real entitled account remains a release-gate action.

- **Tests:** `validate-portfolio-score-honesty.js` 73 assertions (real `fetch()` handler, real schema; every band boundary and either side, 0, 100, null, undefined, NaN, ±Infinity) · frontend 247/247 across 28 files, up from 170 — `PortfolioRiskPage` had **zero** coverage before. Mutation-proved **19×**; each fails the relevant guard.

## 2026.07.16-3 (Portfolio read purity — a GET no longer writes) — deployed 2026-07-16

- **Live Worker Version ID:** `4ad06deb-efe3-4db1-abc1-7b495c1bae99` (PR #116, squash-merged as `f28d2ac`)
- **Rollback Worker Version ID:** `98cb2131-1817-4a35-a142-5dc952297fb2`
- **Remote D1 migrations applied:** none. `git diff febadd4..f28d2ac -- database/` is empty.
- **Files:** `engines/portfolio-risk.js`, `routes/portfolio.js`, `scripts/validate-portfolio-read-purity.js` (new, CI-blocking), `ci.yml`.

### Fix (a GET mutated production state)

- **Opening the Portfolio Risk page wrote to the database** (PR **#116**).
  - `computePortfolioRisk()` appended a `portfolio_risk_snapshots` row on every call, and its only caller is `GET /api/portfolio/risk`. One row per page load, per refresh, unbounded — no dedupe, no rate limit, no retention — with `catch { /* non-fatal */ }` swallowing anything it broke. Any prefetch, retry, double-click or uptime check wrote a row.
  - **Removed, not moved to a cron**, because writing the proof settled it: **nothing reads the table** — no `SELECT` against `portfolio_risk_snapshots` exists anywhere in the repository, and the 30-day trend the page renders comes from `workspace_brs_score_history`. Migration `036`'s header calls the write *"typically post-scan or on-demand"*; there is no post-scan path and never was, and no cron writes it. The rows were not a record of the portfolio over time — they were a record of **when someone opened a page**. A cron would have preserved a cadence nobody consumes, for a table that cannot express what MSP Portfolio needs anyway (four scalars keyed by `users.id`, no domain dimension).
  - **The table and its rows are kept.** Unevenly sampled observations are still real observations; dropping them would be a destructive migration.
  - `userId` is gone from `computePortfolioRisk()`'s signature — it fed only the write. The tenant boundary is `workspaceIds`, already resolved by `getAccessibleWorkspaceIds()`. `upsertPortfolioRiskSnapshot()` is deleted rather than left unused, and the route comment claiming *"Persists a snapshot"* is corrected — this repository has been bitten before by a comment asserting behaviour nobody wrote.
  - **Legitimate writes preserved and asserted.** `api_rate_limits` and `user_sessions.last_seen_at` fire on every authenticated request before any handler runs; removing them would be a security regression, not a cleanup. The first draft of the suite asserted "no write of any kind" and caught them — it now names and excuses exactly those two, treats anything else as a finding, and separately asserts the rate-limit write still happens.
  - **Proof, not assertion:** `validate-portfolio-read-purity.js` drives the real `fetch()` handler against the real schema and counts rows. Against the unfixed engine: `rows went 0 -> 1 — a GET mutated production state`, and six requests produced six rows. Mutation-proved ×5 — re-introducing the exact write, a write to a *different* table, nulling the returned score, dropping a workspace from the rankings, and removing the entitlement gate each fail the suite.

### Production proof

Both hosts serve `4ad06deb`; `/ready` d1+r2 true on both. `GET /api/portfolio/risk` unauthenticated → 401. Across live traffic against the route, `portfolio_risk_snapshots` held at **0 → 0** while `api_rate_limits` advanced **1795 → 1796** — the read is inert, the rate limiter is not.

> **The defect was real but latent in production.** `portfolio_risk_snapshots` contains **0 rows** and always has: `portfolio_monitoring` is a business+ entitlement and **no business or enterprise subscription exists** (production has only free/starter/professional). So no account could reach the write path. Nothing was cleaned up, because nothing had accumulated.
>
> **The authenticated 200 path therefore cannot be exercised in production** without creating a business subscription — a billing change, out of scope. It is proven instead against the deployed code path with a real session and a business entitlement: status **200**, writes issued were `api_rate_limits` ×2 and `UPDATE user_sessions SET last_seen_at` only, `portfolio_risk_snapshots` **0**, and `last_seen_at` advanced `2020-01-01T00:00:00Z → 2026-07-16 01:29:57`. Authenticated UI smoke on a real entitled account remains a release-gate action.

### Known defect, not fixed here

`portfolio-risk.js:52-54` ladders `>= 75 / >= 55 / >= 35` and falls through to `'serious'`. **`null` fails every comparison**, so a portfolio with no BRS evidence renders as *"showing serious overall risk (portfolio score: null/100)"* — a new MSP with workspaces but no scans is told its portfolio is serious. The inverse of healthy-washing, and the same sin: a verdict fabricated from absent evidence. Corrective queued next.

## 2026.07.16-2 (API host corrective — `api.cybermeters.com` exists now) — deployed 2026-07-16

- **Live Worker Version ID:** `98cb2131-1817-4a35-a142-5dc952297fb2` (PR #114)
- **Rollback Worker Version ID:** `e0ce455f-034b-41e4-aad6-d546170b9ec7` (the pre-episode version)
- **PRs:** #113 (canonical API host + derived-host contract) · #114 (keep workers.dev enabled)
- **Remote D1 migrations applied:** none. **No `src/` changed in either PR** — `git diff b0b4364..HEAD -- workers/scan-api/src frontend/src` is empty. Zero customer, billing, tenant, alert or notification behaviour change.
- **Custom domain:** `api.cybermeters.com` → `cybermeters-platform` (production), id `08217538ba5bbe103d882b7450db1ec0d154ee57`, zone `602ec345a439a5bbb091b1af360d31b0`, cert `97f26548-cb86-4501-b7e5-66b40d1c26a1`. Cloudflare-managed DNS + TLS, proxied, no CNAME chain.

> **Do not roll back to `451c3c33-6a1f-4db1-b852-0687c12b02ad`.** That version was
> deployed with workers.dev disabled (see below) and exists only as the 96-second
> window between the two PRs. Roll back to `e0ce455f` or forward-fix.
>
> **The surgical rollback for this release is not a version rollback at all.** No code
> changed, so reverting a version reverts nothing. To undo, delete the custom domain:
> `DELETE /accounts/{account}/workers/domains/08217538ba5bbe103d882b7450db1ec0d154ee57`.
> workers.dev keeps serving throughout, and the live frontend is still pointed at it,
> so customer impact of that undo is zero.

### Fix (the API host every document named did not exist)

- **`api.cybermeters.com` was NXDOMAIN** (PR **#113**, squash-merged as `e5fb8d0`).
  - `README.md`, `frontend/.env.example`, `OPERATIONS.md` and `docs/openapi.json` all published it as the production API base. There was **no DNS record, no route, no custom domain** — `[[routes]]`/`custom_domain` appear in no `.toml` in this repository's history. Production served only from `cybermeters-platform.ttrnn47.workers.dev`.
  - So a developer copying `.env.example` configured a host that cannot resolve; a customer copying the DMARC curl got the same; and **`OPERATIONS.md` told an operator to health-check production at an address that answers nothing** — during an incident, that reads as an outage. #111/#112 fixed the *path* half of this hint hours earlier and never questioned the host.
  - **Why CI was green, which matters more than the bug.** `validate-frontend-env-contract.js:31`, verbatim: *"This asserts the CONTRACT, not any value."* It proved the base ends in `/api`. Nothing anywhere proved the host existed. Same shape as the alerts audit, and as the purge suite that seeded only the tables already on its own list — confidently green because it was never looking.
  - **The fix is not a corrected string.** Hardcoding `api.cybermeters.com` in a test is the same fiction with a test in front of it. The validator now **derives** the canonical host from the `custom_domain` route — the only thing that actually causes a hostname to serve the Worker — and asserts every surface names the host the deployment binds: `.env.example`, README, API_REFERENCE, `openapi.servers[0]`, the OPERATIONS runbook curls, the frontend's hints and `BASE` fallbacks, and the CSP `connect-src`. Docs cannot drift without the config drifting first, and the config is what makes reality. **Deleting the route — the world as it stood that morning — now fails CI.**
  - **No DNS lookup in CI:** resolution is a network fact and would make every run flaky. A real resolve is proven once per release by the runbook smoke test.
  - Deliberately untouched: `MICROSOFT_REDIRECT_URI` (Azure-registered against workers.dev), the `billing.js` origin fallback (dead code — `FRONTEND_URL` is set), and the Stripe webhook docs (they describe the URL actually registered with Stripe).

### Fix (self-inflicted, 96 seconds — the custom domain disabled workers.dev)

- **Declaring any route flips wrangler's `workers_dev` default to false** (PR **#114**, squash-merged as `de2440c`).
  - #113's deploy silently 404'd `cybermeters-platform.ttrnn47.workers.dev`. Wrangler said so in its output — *"Because your 'workers.dev' route is disabled"* — and the post-deploy smoke test caught it 96 seconds later.
  - **That hostname is not a spare URL.** `MICROSOFT_REDIRECT_URI` is registered against it in Azure AD, so **Microsoft SSO sign-in was broken** for that window. It is also the rollback path, and the only way to tell a hostname fault from a bad deployment — the exact diagnostic #113 had just added to the release checklist. #113's own comment said "workers.dev deliberately stays enabled", and the config it added turned it off.
  - `workers_dev = true` is now explicit. **The default was the trap.** Two CI guards, both mutation-proved: any `[[routes]]` ⇒ `workers_dev = true` explicit; and any wrangler.toml *value* pointing at workers.dev ⇒ workers.dev stays enabled. The second is the real invariant — a config value may not target a hostname the same file disables.

### Production proof

Both hosts serve `98cb2131`. `api.cybermeters.com`: DNS → zone proxy IPs; TLS strict-verified (zone cert SAN `*.cybermeters.com`); `/health` returns the live deployment id; `/ready` d1+r2 true; unauth `/api/scans` 401; `/api/api/scans` 404 (no double-`/api`); bare `/scans` 404; `POST /api/dmarc-ingest` 401 (exists, gated); CORS returns a **static** `https://app.cybermeters.com` and never echoes `evil.example.com` or the lookalike `app.cybermeters.com.evil.com`. Microsoft SSO `/api/auth/microsoft/login` 302s to `login.microsoftonline.com` on **both** hosts with the Azure-registered `redirect_uri` unchanged. Hourly cron trigger intact.

**Not yet done:** the live frontend's `VITE_API_BASE_URL` is a Cloudflare Pages *dashboard* build variable (not in the repo, not in CI) and still points at workers.dev. The app therefore works and is unaffected, but the canonical host has no browser traffic proving it stays healthy. Repointing it is a founder decision, deliberately not taken here.

## 2026.07.16-1 (Alerts corrective phase — 8/8 canonical coverage) — deployed 2026-07-16

- **Live Worker Version ID:** `e0ce455f-034b-41e4-aad6-d546170b9ec7` (PR #108)
- **Rollback Worker Version ID:** `ccfe0cd5-3d75-4acc-9057-32354954533c` (PR #107)
- **Rollback chain:** `40f5e1f6` (#106) → `d1dcba4a` (#105) → `d633118f` (pre-phase, `v2026.07.15-2`)
- **Remote D1 migrations applied:** `089-website-security-lifecycle.sql`, `090-cyber-essentials-lifecycle.sql` — both additive, both applied exactly once, both verified idempotent on re-run (78 → 80 tables).
- **PRs:** #105 (probe evidence honesty, P1) · #106 (CE data integrity, 2× P1) · #107 (Website Security lifecycle) · #108 (Cyber Essentials lifecycle)

> **`v2026.07.15-2` is superseded.** It recorded a six-of-eight closure that was
> premature: it deferred Website Security and Cyber Essentials on reasoning that was
> wrong. The tag is preserved as the historical record; `docs/alerts-eight-domain-coverage.md`
> is now authoritative and explains why the original audit was wrong, because the
> failure mode is more useful than the conclusion.
>
> **All eight canonical domains now alert.** **No genuine live occurrence proof exists
> for any of them** — CI and no-op deployment only. Controlled, founder-led acceptance
> with real events remains a release-gate activity.

### Fix (P1 — a probe that never executed was reported as healthy)

- **Unavailable evidence is unknown: never healthy, never a finding, never a recovery** (PR **#105**, squash-merged as `b72b0ed`, Worker `d1dcba4a`).
  - **Reproduced end-to-end.** `safeFetch` returns null on a 10s timeout, a redirect loop, more than `MAX_REDIRECT_HOPS`, a blocked target, or any throw. `runHeadersModule` returned that as an ordinary success — `accessible:false` with no `error`, no `incomplete`, no `skipped`. So `buildScanQuality` graded the scan **`complete`**, `moduleAssessed` said the module ran, scoring emitted nothing (it gates on `accessible`), and the eight-domain resolver concluded **Website Security = `assessed_healthy`, "Assessed — no material issue observed", coverage `complete`** — for a site nobody could reach. That inverts the platform's first permanent rule, and it is the same defect `probeAsset` already fixed for exposure evidence (`reachable: null` + `probe_status: "not_executed"`) and never applied to headers/ssl.
  - **`ssl-scan` had the mirror defect:** a timed-out HTTPS probe collapsed into `https_available:false`, which scoring turned into a **critical** finding asserting *"TLS handshake failed or connection refused on port 443"* — a claim about the customer's server that an incomplete fetch cannot make. A timeout is not a refusal. The module already drew this distinction one field below (`http_redirect_validated` stays false on a null response); reachability never got the same discipline.
  - **Fixes, all in the direction of less claim:** headers/ssl declare `incomplete` when the probe did not execute (one flag → `scan_quality` partial, `moduleAssessed` false, `canVerify` false — every gate fails closed); `https_available` is **tri-state** (`null` = we did not look); scoring + posture-scoring claim unavailability only on an observed `=== false`; CE's signals are tri-state; CE returns `not_assessed` with no scan; the resolver renders that as `evidence_insufficient`; the Dashboard shows `unknown` rather than reading `missing.length` raw.
  - **The subtle one:** the `not_assessed` guard is mandatory *because of* the tri-state fix. Removing the fabricated deductions alone would have flipped a no-evidence workspace from 72/C/`partially_ready` to **100/A/`likely_ready`** — trading a fabricated failure for a fabricated pass. Absent evidence is neither.
  - **Not a silencer:** an observed absent HSTS still produces its gap, an observed `https_available:false` still emits the critical finding, and a reachable clean site is still `assessed_healthy` / `complete`.
  - **Proof:** `validate-probe-evidence-honesty.js` (68 assertions). The fixtures **are** the real modules' output — global `fetch` is made to time out, refuse and redirect-loop, and `runHeadersModule`/`runSslModule` are executed for real. Mutation-tested: removing the guard reproduces `assessed_healthy` + `canVerify: true`.

### Fix (P1 ×2 — Cyber Essentials data integrity)

- **Purge the answers customers were told were deleted, and grade only their own evidence** (PR **#106**, squash-merged as `724e3eb`, Worker `40f5e1f6`).
  - **`cyber_essentials_answers` survived every workspace purge**, for the entire life of the table. It holds `note` (free customer text) and `answered_by`, and carries **no FK to `workspaces(id)`** so D1 could not block the parent delete either — while the deletion email tells the owner the workspace *"and all of its data have now been permanently removed"*.
  - **Why it was invisible, which matters more:** `validate-purge-completeness` seeded rows by iterating `WORKSPACE_PURGE_TABLES`, so it could only ever prove the list purges the tables **on the list**. A forgotten table was never seeded and never counted — and the suite reported a confident 10/10. `index.js` further claimed the list was *"kept in sync by `purge_covers_all_workspace_fk_tables`"*. **That test did not exist** — the name appears nowhere in the repository, and neither does `purge_covers_all_scan_fk_tables` cited beside it. A comment asserting a guard nobody wrote is worse than no comment: it stops the next person looking. The guard is now **derived from the schema** — all 57 `workspace_id`-bearing tables must be purged or explicitly excepted with a reason.
  - **CE graded one workspace from another's scan.** `workspace_domains` is PK `(workspace_id, domain_id)` — one domain, many workspaces, by design. The `OR wd.workspace_id = ?` arm matched on merely *linking* the domain, so an MSP scanning hourly deterministically supplied its client's readiness baseline. Fixing the readiness query alone was **not enough** and the validator caught it: CE's counts come from `buildScorecardData`, which resolved the newest scan of any linked domain — the same leak through a back door. It gains an explicit `scanScope`; CE passes `"workspace"`. The **default is unchanged**, so the PDF and scorecard route keep today's behaviour (logged P2 — a product call, not made silently).

### Feature (Website Security — the 7th canonical alerting domain)

- **The managed lifecycle that lets this domain alert honestly** (PR **#107**, squash-merged as `5029377`, migration **089**, Worker `ccfe0cd5`).
  - **What was missing was continuity, not evidence.** The D1 `findings` INSERT binds `createId("finding")` and **drops** the canonical slug, so the same condition carried a different id every scan and nothing could answer *"is HSTS still missing, and since when?"*. The evaluator (scan-engine **Phase 8m**) reads the slug from the in-memory findings, as `createManagedAsmCasesForScan` already does.
  - **Identity `(workspace_id, domain_id, condition_key)` — an honesty decision.** No Website Security finding carries a host or path; the per-path evidence that exists is consumed only as a boolean. A per-hostname key would **invent** the attribution, and its obvious source (`evidence.final_url`) is the redirect target — so a customer fixing their canonical redirect would "resolve" one record and "create" another, **alerting twice for an improvement**.
  - **The flood guard is per-DOMAIN, and B3's per-record birth guard does not transfer** — B3's records pre-existed with their own `created_at`, whereas a website condition record is *born* at first evaluation, after the watermark. A `domain_baseline_established` marker is written once per (workspace, domain); its absence defines the seeding pass, and it is written even when that pass finds nothing so a clean first scan still baselines the domain.
  - **Unknown is never recovery.** Absence means "fixed" only when the detecting module provably ran — knowable at all only because #105 shipped first. A downgrade to a non-material grade (a CDN challenge makes scoring emit the same condition at `info`) is recorded as `evidence_uncertain`, not a fix.
  - Only **material (medium+)** conditions are actionable; the info/low grades have no mapping at all, so a new info/low detection rule cannot alert anyone. Severity **inherits** from `scoring.js`; `recurrence_band` carries the grade so worsening escalates (PR-B2 pattern).
  - **Registry fix found by the suite:** only `header_malformed_strict_transport_security` had ever been added — the other five malformed variants resolved `unknown` and would have emitted the *"review required"* fallback, a content-free email.
  - **Proof:** `validate-website-security-lifecycle.js` (127 assertions). Mutations: removing the flood guard alerts a 14-month backlog (4 alerts); removing the completeness gate writes `condition_resolved` from a timed-out probe.

### Feature (Cyber Essentials Readiness — the 8th and last canonical alerting domain)

- **Readiness alerts from external evidence only** (PR **#108**, squash-merged as `3253670`, migration **090**, Worker `e0ce455f`).
  - **The ownership decision.** CE detects nothing of its own (`modules: []`, `match: () => false`), so every control re-interprets evidence another domain already owns **and already alerts**. It therefore never raises a second "we found X" — it owns only **control-theme readiness transitions**, at a **fixed `medium`**. Inheriting the technical grade would re-raise the same urgency under a second name; a customer on `critical_only` hears the technical alert and is not interrupted twice.
  - **Only externally supportable controls alert.** `access_control` and `malware_protection` declare `external_coverage: "none"` in the repo's own metadata — they are scored from email-auth proxies that measure anti-spoofing, not user access control or endpoint AV. They stay **visible** and are persisted as `not_externally_assessable`; they can never contribute an occurrence. Read from `lib/cyber-essentials.js` at runtime rather than restated, so it cannot drift.
  - **The questionnaire is not security truth.** The evaluator calls `buildCyberEssentialsReadiness` **directly** — never `getCyberEssentialsSnapshot`, where answers gate display and through which flipping one answer to `"unknown"` would mint an occurrence from a form edit. Proven behaviourally.
  - **A score moving is not an event.** State comes from the sorted **set of failing canonical remediation ids** — stable against count churn and scoring-weight changes.
  - **A real design flaw the suite caught:** `ready` and `unknown` both carry `recurrence_type: null`, so comparing recurrences alone made `ready`↔`unknown` invisible and a genuine recovery out of an evidence outage was never recorded. The readiness state is now the monitoring dimension.
  - CE also had **no evaluator anywhere** — no cron task, no scan hook — which is why its verdict was compute-on-read only. It now runs as scan-engine **Phase 8n**.
  - **Proof:** `validate-ce-lifecycle.js` (113 assertions). Mutations: removing the coverage gate makes `access_control` an alertable `not_ready` from a DMARC proxy; removing the no-evidence guard turns an unexecuted probe into `control_recovered` — a fabricated recovery.

### Production verification

- **Zero flood, zero drift** across both deploys: `notification_events` 222 → 222, `alert_deliveries` 0 → 0, and all four new tables empty. Newest notification `2026-07-15 17:23:32` — hours older than every deploy. No alert was manufactured.

## 2026.07.15-2 (Alerts episode — SUPERSEDED: premature six-of-eight closure) — deployed 2026-07-15

> **Superseded by `v2026.07.16-1`.** This tag closed the Alerts episode at 6 of 8
> domains, deferring Website Security and Cyber Essentials as "outcome B — lifecycle
> foundation missing". **That conclusion was wrong, and so were its stated reasons:**
> CE's readiness computation never read the questionnaire (it was already 100%
> externally observed), and Website Security's findings were persisted all along —
> immutably in R2 with stable canonical ids. The gap was *continuity*, not
> persistence. Both domains were buildable. The re-audit that corrected it also found
> two live P1s the original audit had missed. Retained as the historical record; see
> `docs/alerts-eight-domain-coverage.md`.

- **Live Worker Version ID:** `d633118f-64f4-4baf-8d5b-cc486b8cf210` (PR #103)
- **Intermediate Worker Version ID:** `d5bdcd8d-10b8-4b6f-b132-b8c39ddf2a11` (PR #102 — rollback target for #103)
- **Rollback Worker Version ID:** `e8a2942e-1e2f-4410-83d6-8f6a389545e6` (pre-episode)
- **Remote D1 migration applied:** none. Neither PR changed the schema; `rowid` already exists on every source table, and B4b only deleted code.
- **Episode PRs:** #97 (PR-A, trust foundation) · #98 (B1, Brand + ASM) · #99 (B4a, suppression) · #100 (B2, certificates) · #101 (B3, Email Protection) · **#102 (occurrence ordering)** · **#103 (B4b, legacy cleanup)**

> **Honest status.** Six of the eight canonical domains alert through the canonical
> pipeline. **Website Security and Cyber Essentials Readiness do not alert at all** —
> both lack a persisted entity identity and an append-only occurrence source, and are
> deferred to their own scoped episode. **No genuine live occurrence proof exists for
> any domain:** alerting is proven by CI and by no-op deployment only. Controlled,
> founder-led acceptance with real events remains a release-gate activity. Full matrix:
> `docs/alerts-eight-domain-coverage.md`.

### Fix (alert foundation — a real alert could be silently swallowed)

- **Same-second occurrences resolve on insertion order, not a random id** (PR **#102**, squash-merged as `43a905f`).
  - **The defect:** `findConditionOccurrence` ordered candidates `created_at DESC, id DESC`. Every lifecycle event is stamped by SQLite `datetime('now')` — **second precision** — so two appends for one record inside one second tie on `created_at` and fall through to the tie-break. Every id is random hex, so the resolver could return the **older** event as the newest occurrence. That older event's `dedupe_key` already exists, so `INSERT OR IGNORE` swallows the newer, real alert as a duplicate. **Fail-silent, and shared by all six wired domains** — it predates PR-B3 and was recorded at `00841d8` as "assess before B4b".
  - **The fix is one clause:** tie-break on `rowid`, the insertion order the table already maintains. Not a new idea — PR-B3 reached the same conclusion for its own `lastGradedCondition` read and has been running it in production; this applies it to the resolver all six domains share.
  - **Why `rowid` and not sub-second timestamps, proven rather than argued:** a rowid tie-break only ever re-selects among rows whose `created_at` are **identical**, so `observed_at` is bit-for-bit unchanged and every `observationIsAfterWatermark` decision (strict `>`) is invariant; where `created_at` differs the tie-break is never consulted. Sub-second precision fails for the opposite reason — it would flip same-second events from "at the watermark" to "after it" and could **release a backlog of pre-existing conditions as if they were news**.
  - **Schema facts verified against the real schema, not assumed,** and re-asserted in CI so a future migration cannot quietly invalidate the contract: all five sources are physical tables (not views), none is `WITHOUT ROWID`, every PK is `TEXT` so rowid is **not** aliased to a customer-supplied key, no `AUTOINCREMENT`, no `VACUUM` in the repo. Rowid reuse after a purge is real and asserted, but cannot invert order — SQLite assigns `max(rowid)+1` over the rows that **remain**, so a new append always sorts above every survivor. Occurrence identity is unchanged: still the persisted event id, no historical ids rewritten.
  - **Proof:** `scripts/validate-alert-occurrence-ordering.js` (65 assertions, CI-blocking) **mutation-tests itself** — it rebuilds the resolver with the old `id DESC` and asserts the defect reproduces, so a green run means the suite can *catch* the regression rather than merely agree with the code. Reverting the fix fails it **16 times across all six domains**.

### Fix (PR-B4b — the legacy alert engine, finished on evidence rather than habit)

- **The last unevidenced outbound claims, the last advisory dedupe, and the last ungated senders** (PR **#103**, squash-merged as `45a327b`). Net **−258/+185** — mostly deletion.
  - **`score_drop` → outbound suppressed** (`evidence_not_attributable`). Both scores are persisted and attributable to scan ids — a weaker case than `new_vendor` — but it fails for the reason `supply_chain_risk_increase` did: **a score is a recomputation, not an observation.** The row records that the score is now 62, never *which evidence moved*. 77 → 62 is equally new findings, a module that returned less evidence this pass, or **a scoring-formula change shipped by us, which would mail every customer at once.** And the email does not hedge — it states the drop *"indicates new critical or high-severity findings"*, a cause the code never checks.
  - **`new_finding` → outbound suppressed** (`evidence_not_attributable`). The closest call, and it turns on the baseline. Its evidence **is** persisted (the previous complete scan's R2 report, diffed on stable canonical finding-*type* ids, not random ids). It is **not reliably attributable**: `runHistoricalModule` selects the baseline `WHERE domain = ?` with **no `workspace_id`**, and `workspace_domains` is keyed `(workspace_id, domain_id)` — so another tenant's scan of the same domain can be the baseline. "New since your last scan" silently means "new since *someone's* last scan", on a clock the customer does not control: an MSP scanning hourly makes its client's weekly alert claim "new" for something seen an hour ago, and the client is never told about the week it was actually introduced. **No cross-tenant data is exposed** — `requireScanReadAccess` scopes every scan read (404, no existence oracle) and both workspaces are verified owners of that domain. **The defect is the claim, not a leak** (logged P2).
  - **The suppression set is now EXHAUSTIVE over the legacy processor,** and CI proves it by extracting the raised types from the source rather than trusting a hand-maintained list. This matters because the gate is **opt-in**: an unlisted type would silently send.
  - **`isAlertDuplicate` → deleted, zero callers.** Read-then-write with no lock (two concurrent scans both read "not a duplicate" and both send), and it **swallowed every error into `false` — failing OPEN into a duplicate send**, the one direction a dedupe must never fail; plus an unbounded, un-`LIMIT`ed scan of the tenant's whole notification history. It was never the real dedupe: every legacy condition is a **delta against persisted state**, so a persisting condition stops being a delta on the next scan and goes quiet on its own (asserted by an unchanged-rescan test). Its per-finding loop was also quietly broken — it deduped each finding but recorded only `nonDupNew[0].id` as the batch's `related_entity`, so findings 2..n had nothing to match against.
  - **`sendTakeoverAlert` + `sendSslExpiryAlert` → deleted.** Dead code, and unsafe if ever revived: both called the **ops-only `sendAlertEmail`, which falls back to `env.ALERT_EMAIL_TO` — the operator's inbox** — when given no recipient. One future caller would have emailed a tenant's takeover risks to the operator with no entitlement, preference, severity, recipient resolution, dedupe or ledger. Having no callers was the only thing making them harmless. Certificate expiry is already owned canonically by `certificates_trust.renewal_overdue`/`.expired` (PR-B2).
  - **Retained deliberately:** `asset_change` (append-only `asset_events` evidence + DB-backed `INSERT OR IGNORE` dedupe) and the in-app `notification_events` row for every suppressed type — **suppression is about the claim leaving the platform, not erasing the observation.**
  - **Proof:** `scripts/validate-alert-b4b-legacy-cleanup.js` (54 assertions, CI-blocking), mutation-tested. It drives the **real** processor against the **real** schema with Slack/Teams/webhook enabled and every sender instrumented, asserts the conditions were *reached* (otherwise "nothing sent" proves nothing), then asserts nothing left on any transport. Emptying the policy set makes the mutant email the customer — so the silence is a proven result, not an artefact.

### Deferred, with the foundation named (not silently skipped)

- **Website Security** and **Cyber Essentials Readiness** were assessed independently against primary code and schema: **outcome B — the lifecycle foundation is missing**, for both. Neither is outcome C: neither has an unevidenced outbound path left to retract. Both already have the *presentation* layer (resolver entry, remediation entries, a registered `case_type`) and the *watermark* layer (`alert_activation` is domain-agnostic) — **what both lack is the entire middle**: persisted entity identity → monitoring/recurrence semantics → append-only `monitoring_changed` evidence. Website Security's engines write **nothing** to D1. Cyber Essentials is blocked more deeply: its verdict is compute-on-read and persisted nowhere, its one durable table is mutable-by-upsert (so it can never be an occurrence source), and **what a CE "recurrence" even means is an unmade product decision**. A registered `case_type` is not readiness: `website_case` and `cyber_essentials_case` have **zero production call sites**. Full detail: `docs/alerts-eight-domain-coverage.md`.

## 2026.07.15 (release tag pending — domain-verification integrity incident: CLOSED) — deployed 2026-07-15

- **Live Worker Version ID:** `a2410eb2-9b12-4217-bc33-d1e99fdf7ff9` (PR #96)
- **Intermediate Worker Version ID:** `7f8083f0-8e35-4822-99dc-e6a39ca3b61c` (PR #95 — rollback target for #96)
- **Rollback Worker Version ID:** `078ef7da-d59b-49e5-b0ed-7c2a2bec9edf` (pre-incident)
- **Remote D1 migration applied:** none — no schema change in either PR. Every column predates both (migration 079); `audit_events` is existing.

### Fix (P0 incident — verification claimed without proof, and the automatic path was dead)

Two defects, one incident: the product could tell a customer it had proven domain ownership when it had not, and the background job meant to complete verification had never run since migration 079. Both are the same class — **a claim made from state that was never proven** — and both are now impossible by construction rather than by care.

- **A verified response must be proven by persisted state** (PR **#95**, squash-merged as `af6181f`).
  - **The defect:** `POST /api/domains/:id/verify` returned `{success:true, verification_status:"verified"}` on the strength of an UPDATE whose result was never inspected. A zero-row UPDATE is a perfectly successful D1 statement, so the route could report proven ownership while the authoritative `workspace_domains` row sat at `pending` with `verified_at` NULL. Separately, the early-return paths emitted no evidence at all — which is why the incident could not be diagnosed: the absence of an audit row was ambiguous between "rejected early" and "never arrived".
  - **`persistVerification()`** is now the only writer of a verified link, gated on two independent checks: `meta.changes === 1` (zero = the link vanished or the scope was wrong; `>1` = `(workspace_id, domain_id)` was not unique and we just wrote `verified` onto rows we never meant to touch — a tenant-integrity event, never a success), **and** a follow-up SELECT on the exact link that must read back `verified` with a non-null `verified_at` **and echo the same two ids**. Reading the ids back is what makes the response's `domain_id`/`workspace_id`/`verified_at` sourced from the persisted row rather than from the request. Fails closed.
  - **Terminal observability:** a frozen `VERIFICATION_OUTCOMES` vocabulary; every branch — including the 401 and the `catch` — emits exactly one, correlated by the existing `X-Request-ID`. Two sinks: `audit_events` (`domain_verification_attempted`, best-effort) and a redacted console line that still fires when the audit write is the thing that failed. **Telemetry can never change an outcome** — persistence proof is mandatory, telemetry is not. The record deliberately does not report whether the audit row landed: `createAuditEvent` swallows its own errors, so such a flag would itself be an unverified claim.
  - **Token safety, two independent controls:** the attempt record is a strict allowlist (an unknown key cannot reach a sink), and the console sink goes through `redactedJson`, whose `[A-Fa-f0-9]{40,}` rule catches the 48-char token even if a future edit smuggles one into an allowlisted field. `dns_record_hash` is SHA-256 of a 192-bit random token — a fingerprint, not reversible.
  - **Contract (additive except one removal):** `+ domain_id`, `method`, `outcome`, `request_id` on every response; `+ verified_at` on success (re-read from the row); `− token` and `checks.dns_txt.expected` on failure (verified unused). `verification_method` retained as the legacy alias. **DNS results are now three-way** (`dns_not_found` / `dns_mismatch` / `dns_lookup_error`) — "not published yet", "published wrong" and "resolver failed" are different customer actions, and a lookup failure is never reported as "not found".
  - **Frontend:** one comment and the type contract only, no logic. PR #94's trust contract rested on a stated structural fact — that the response *cannot* carry `verified_at`. Returning it makes that false, and a comment asserting a vanished guarantee on a trust boundary is an active trap. `isAuthoritativeVerified()` / `verifyResponseClaimsSuccess()` are byte-for-byte unchanged: the UI still rereads authoritative state and never trusts the response.

- **The hourly auto-recheck was dead code — the 48-hour promise restored on the authoritative link** (PR **#96**, squash-merged as `b56c08f`).
  - **The defect, and the incident's true root cause:** the failure response promises *"we re-check automatically every hour for 48 hours."* `retryPendingDomainVerifications` selected on `domains.verification_token` / `domains.verification_initiated_at` — but migration 079 moved initiation to the `workspace_domains` link and left the legacy `domains.verification_*` columns read-only, so **nothing has written those two columns since.** The WHERE clause matched nothing, forever, and the deadness was invisible: a task that finds no candidates looks exactly like a task with no work. **Confirmed in production data** — the live legacy row for `cybermeters.com` had `verification_token` NULL, so the old query could never have selected it.
  - **Had it matched a pre-079 row it would have been worse:** it wrote only the legacy `domains` table — never the authoritative link the scan gate reads — while notifying every linked workspace *"ownership verified"*. The customer would have been told they were verified and still been unable to scan.
  - **This explains the reported symptom end to end:** customer clicks Verify before propagation → `failed` → is told it will re-check hourly → it never does → the row sits with a token-generation audit above it and nothing after.
  - **Candidates now come from `workspace_domains`**, joined to `domains` only for the hostname (never consulted for state, never mutated), excluding soft-deleted workspaces, bounded (10/run) and deterministically ordered. Status covers **`'pending'` AND `'failed'`** (founder-approved): the manual route writes `failed` when proof is not yet available, which is precisely the customer this task exists to rescue — a pending-only filter would preserve the defect.
  - **No second implementation.** `checkDnsTxtProof()` is the one definition of "does this domain publish our token?", now shared by route and cron; the cron's private copy of the lookup and comparison is gone and `dnsQuery` is no longer imported by `index.js`. `persistVerification()` holds the cron to exactly the manual route's gate — a zero-row UPDATE cannot notify or claim success.
  - **Idempotency rests on the status transition**, not a dedup check: `persistVerification` moves the row to `verified`, so the candidate query can never select it again. A repeat run is a no-op.
  - **The promise is now generated from the constants the scheduler obeys** (`VERIFICATION_WINDOW_HOURS` / `_RECHECK_INTERVAL` / `_RECHECK_BATCH`), so the copy cannot drift from the behaviour again — that drift is what made the sentence false for ~5 days. Window expiry emits `recheck_window_expired` **once**, in the hour the row crosses the boundary; an unbounded "older than 48h" would re-log every dead row forever.
  - **Tests (CI-blocking):** `validate-domain-verification-integrity.js` (**74**) and `validate-domain-verification-recheck.js` (**70**) — zero-row/multi-row/unconfirmed-reread/mismatched-identity persistence cannot report success; every terminal branch emits a canonical outcome; failure telemetry leaks no token in audit *or* log; dead telemetry cannot fail a request; legacy rows cannot satisfy the workspace-scoped route; the cron reads the authoritative link, rescues `failed` rows, skips expired ones, batches with overflow picked up next run, and three consecutive runs produce one notification/audit/attempt/DNS query; tenant isolation (ws_a's proof never verifies ws_b); soft-deleted workspaces receive nothing. **Both suites mutation-tested** — removing either persistence gate, the soft-delete exclusion, the `failed` status, or the expiry bound fails them.
  - **Full gate:** **86/86** CI validators, Semgrep SAST (95 rules) 0 findings, worker syntax, `wrangler --dry-run` clean, frontend typecheck + Vitest **170/170** + build. CI green on PR #95, PR #96, and on main at both merge commits.

### Production proof — the incident domain, verified by the path that was supposed to do it

`cybermeters.com` in **Turhan Workspace** had sat `pending` since 10:20:31 with the TXT record published. It was the **only** eligible row (founder-controlled; blast radius of one).

- **First tick (13:00:18):** cron selected the authoritative row, found the record, and persisted — `verification_status='verified'`, `verification_method='dns_txt'`, `verified_at='2026-07-15 13:00:18'`. Attempt outcome `verified_dns_txt`, `request_id='cron:domain_verify_retry'`, **`affected_row_count=1`**, `persisted_status='verified'`, `persisted_verified_at` non-null, `dns_result='found'`. **One** `domain_verified` notification and **one** audit, both scoped to Turhan Workspace.
- **Second tick (14:00) — idempotent:** row still `verified`, **`verified_at` unchanged at 13:00:18** (no second persistence write), still exactly **1** notification, **1** `domain_verified` audit, **1** cron attempt row. No persistence-failure outcomes.
- **Legacy table untouched throughout:** the `domains` row is still `unverified`, no token, `verified_at` NULL — proving the cron neither reads nor writes it.
- **Zero token leakage:** no audit or notification row contains the token, the raw `cybermeters-verification=` value, or an `authorization` key.
- **Honest limitation:** the 14:00 tick's *execution* was not independently confirmed — Analytics Engine (where `runCronTask` records) needs an API token not available here, and no other hourly task writes to D1 unconditionally, so unchanged counts alone are ambiguous between "correctly skipped" and "never ran". Idempotency is instead proven **structurally**, which is stronger: the cron's exact candidate query returns **0 rows** against production, because the row is now `verified` and the query selects only `pending`/`failed`. No future tick can select it regardless.
- No scan was triggered, no DNS changed, no token regenerated as part of this proof.

**Incident status: CLOSED.**

### Known / not included
- **P2 (non-blocking):** cron-generated attempt records carry `actor_type='anonymous'` because `recordVerificationAttempt` derives it from the absence of a `user_id`. A scheduled system task is not an anonymous external caller, and the `domain_verified` audit beside it correctly says `system` — so one tick labels itself two ways. Cosmetic (an operator filtering `actor_type='anonymous'` sees cron work mixed with unauthenticated probes); logged in `docs/P0-PUBLIC-BETA-BLOCKERS.md`.
- **401s on `/api/domains/:id/verify` now write an anonymous `audit_events` row** (founder decision). Bounded by the global per-IP write throttle (60/5min) already guarding every write path; rows carry a null workspace so they cannot pollute a tenant's audit view.
- `POST /api/domains/:id/check-verification` retains its own DNS lookup — a read-only diagnostic that never persists or claims verification, so not a second proof. Worth folding into `checkDnsTxtProof` later.
- **Roadmap:** Alerts Across All Eight Domains **not started** — the next canonical episode. No release tag cut for either PR.

## 2026.07.15 (v2026.07.15-1 — tenant alert recipients: no operator fallback) — deployed 2026-07-15

- **Live Worker Version ID:** `2e92c5fd-455c-416a-aba0-1158b73e644b`
- **Rollback Worker Version ID:** `d032e4ed-5267-44bd-a6cc-5c036de535cf`
- **Remote D1 migration applied:** none — no schema change.

### Fix (latent P0 — found while mapping the Alerts episode, shipped ahead of it)
- **Tenant alerts resolve their own verified recipients and never the operator inbox** (PR **#86**, squash-merged to main as `6bc29e3`).
  - **The defect:** every asset-change alert email was delivered to the **operator's** inbox instead of the customer. `sendAlertEmail` falls back to `[env.ALERT_EMAIL_TO]` (`alerts.js:152`) when given no recipients, `wrangler.toml:42` points that at a personal address, and both asset-alert send sites called it with none. No workspace owner ever received their asset alerts, and every tenant's domains/hostnames/workspace ids aggregated into one mailbox. Only founder-controlled domains exist today, so **nothing reached a third party** — a latent P0 and a pre-invitation blocker, fixed before more domains are wired onto the same sender.
  - **Two further defects in the same path:** recipients were never filtered by `email_verified` (`alerts.js:166-169`), unlike every other sender (`weekly-digest.js:106`, `lifecycle-email.js:253`) — security findings could be emailed to an unverified, attacker-controlled address; and a D1 error returned `[]` (`alerts.js:191`) which was then recorded as `email_delivery={status:"skipped", reason:"no_recipients"}`, storing a transient failure permanently as a fact about the customer.
  - **`resolveWorkspaceAlertRecipients(env, workspaceId)`** is now the ONE place deciding who may receive a workspace's alerts, so every path inherits: tenant-scoped membership only (no global fallback), `u.email_verified` required, and `workspaces.deleted_at IS NULL` (a soft-deleted workspace is nonexistent). Returns `{ok, emails, reason}` so a lookup failure (`recipient_lookup_failed`) stays distinct from a genuine empty audience (`no_verified_recipient`). The workspace owner is folded into the same query rather than a second unguarded lookup, so the rules cannot be bypassed.
  - **`sendTenantAlertEmail(...)`** is the only way an alert reaches a customer by email — it never touches `ALERT_EMAIL_TO` and refuses to send with no audience. Both asset-alert sites use it; **no engine calls `sendAlertEmail`** any more. `sendAlertEmail` is retained and documented **OPS-ONLY** (the fallback is correct for `opsHealthHeartbeat`, `index.js:1078`).
  - **Fail honest, don't retry forever:** `deliveryOutcome()` maps a missing audience to `status='skipped'` (not `'failed'`), recorded with a safe reason and not retried hourly for three days; transient failures and lookup errors stay retryable. No CHECK constraint on the column → **no migration**.
  - `sendAssetChangeAlert` now joins `workspaces ... deleted_at IS NULL`, gating **channels as well as email**; the resolver re-checks independently (defence in depth).
  - **Tests (CI-blocking):** `validate-alert-recipients.js` (**33**, DB-backed) — no cross-tenant recipient leakage, unverified + plain-member users excluded, soft-deleted workspaces receive nothing (zero outbound email), unknown workspaces non-enumerating, no-recipient cases skip with zero outbound email, a D1 error never reported as an empty audience, retry mapping, and a structural guard that no engine may call the operator-fallback sender. Two regression fixtures encoded the OLD contract (they reached the delivery path only because the fallback guaranteed a recipient) and now seed the workspace's own verified recipient; they still test retry enrolment and the bounded sweep.
  - **Full gate:** **80/80** CI validators, regression **227/227**, worker syntax, `wrangler --dry-run` clean, frontend Vitest **106/106** + build. CI green on PR #86 and on main.
  - **Production proof (side-effect-safe):** `GET /health` returns deployment `2e92c5fd…` (confirmed after propagation); `/ready` 200; `/notifications` live and auth-gated (401). No migration to verify. No alert was sent to any address as part of this proof.
  - **Not included:** the Alerts Across All Eight Domains refactor itself — not started; the episode's pre-change map is complete and two founder decisions (plan gating, unsubscribe scope) are outstanding.

## 2026.07.14 (v2026.07.14-20 — ASM Verification closed: honest DNS/header verification) — deployed 2026-07-14

- **Live Worker Version ID:** `d032e4ed-5267-44bd-a6cc-5c036de535cf`
- **Rollback Worker Version ID:** `7e6eb67c-7a6c-4708-b203-a57c1aa1c110`
- **Remote D1 migration applied:** none — no table and no schema change.

### Feat (Complete ASM Verification — part 2; **the canonical episode is now closed**)
- **Honest DNS/header verification for `subdomain_takeover` and `dse_*`** (PR **#84**, squash-merged to main as `34d2c5f`). Continues the preserved groundwork branch, rebased onto `v2026.07.14-19`. No table, no migration, no parallel system, **no widened host-scope/SSRF boundary**.
  - **The central problem: "no risk found" ≠ "not vulnerable".** `runTakeoverModule` reached `risks=[]` for five different reasons — three of them ignorance, not evidence (CNAME lookup failed / body fetch refused by the SSRF guard / body unreadable) and two genuinely conclusive (CNAME no longer dangling or not a takeover-prone provider; body read with the fingerprint gone). Collapsing the first three into "fixed" would have **falsely resolved a live takeover risk**. `dse_*` had the same class of trap: a failed header probe yields `hsts.present=false` / `cookies.found=0`, which a naive predicate reads as remediation.
  - **Detectors now return structured completeness; detector and verifier share ONE canonical predicate.** `takeover-scan.js` records `lookup_failed_hosts`, `unconfirmed[{host,cname,provider,reason}]` and `checked_hosts` instead of skipping silently (additive — existing consumers read only `risks`/`checked`/`potential_risks`/`cname_observations`), and exports `hostHasConfirmedTakeoverRisk` (the same `risks` scoring.js raises the finding from) + `takeoverObservationFor` (separates conclusive absence from ignorance). `headers-scan.js` exports `securityHeaderValuesFrom` + `captureSetCookieRaw`, now used by `runHeadersModule` itself, so the verifier reads HSTS/Set-Cookie with the scan's own parsing. `dse-findings.js` (new, pure) holds `DSE_PRESENCE` — the one predicate set that scan-engine raises findings from and the verifier evaluates; `dns-scan.js` exports the canonical `buildCaaFromAnswers`. Extractions were verbatim: **regression stayed 227/227 at every step**.
  - **Technique dispatch** (`http_asset` | `dns_takeover` | `dns_caa` | `http_headers`), each deferring on anything inconclusive. `subdomain_takeover`: re-runs the real detector for the host through the SSRF-guarded reserved probe — DNS failure → defer; vulnerable CNAME + refused/failed/unreadable body → **defer**; fingerprint present → `still_present`; body read + fingerprint gone, or CNAME no longer dangling → `fixed`. `dse_missing_caa`/`dse_caa_no_issuers`: re-query CAA; lookup failure → defer. `dse_hsts_*`/`dse_cookie_*`: re-observe headers; unreachable/refused → defer; **a response setting no cookies cannot distinguish "flags fixed" from "this request set no cookies" → defer** (HSTS is a plain response header, so a complete response is conclusive either way).
  - **`ASM_VERIFICATION_SUPPORT` — the finding-by-finding support matrix in code.** **14 automated** (`asset_exposure_admin_interface`/`sensitive_tool`/`dev_env`, `admin_surface_critical`/`high`/`medium`, `subdomain_takeover`, `dse_missing_caa`, `dse_caa_no_issuers`, `dse_hsts_short_maxage`, `dse_hsts_not_preload_eligible`, `dse_cookie_no_secure`/`no_httponly`/`no_samesite`); **2 intentionally unsupported** (`cloud_storage_public_listing`, `cloud_storage_takeover_risk` — third-party storage infrastructure outside the customer's DNS scope; founder decision, unchanged); **3 observation-only/not-applicable** (`asset_exposure_interface_observed`, `asset_provider_infrastructure_observed`, `cloud_storage_exposure_observed`). Every non-automated entry states why; unknown types are unsupported by default. **CI asserts the matrix and the dispatch agree exactly**, so the product cannot claim support it does not have.
  - **Legacy prose `asset_ref` healed, never parsed.** When the SAME finding is observed again carrying structured hosts, they are appended to `evidence_json` as a new top-level key (the original finding snapshot stays byte-for-byte intact), `asset_ref` is replaced **only** when what is stored is not a valid in-scope host, and the change is recorded as an append-only case event (`affected_hosts_enriched`). Idempotent on repeat scans. Prose is never read back as data.
  - **Tests (CI-blocking):** `validate-managed-verification` **65 → 107**, `validate-asm-remediation-loop` **32 → 42** — every takeover outcome (including a **genuine SSRF refusal** driven by a reserved-IP target so the real guard does the refusing), every CAA/HSTS/cookie outcome, the no-cookies and DNS-failure traps, matrix/dispatch parity, legacy-case healing with history preserved and no duplicate cases. These tests caught a real bug in development: `observeTakeover` initially failed to pass the DNS implementation through, so every lookup silently failed.
  - **Full gate:** **79/79** CI validators, regression **227/227**, purge **10/10**, managed-case **92/92**, migrations **96/96**, tenant isolation, error contract, worker syntax, `wrangler --dry-run` clean, frontend Vitest **106/106** + build. CI green on PR #84 and on main.
  - **Production proof (side-effect-safe):** `GET /health` returns deployment `d032e4ed…` (confirmed after propagation); `/ready` 200; `POST /managed-cases/:id/verify` and `GET /managed-cases` live and auth-gated (401). No migration to verify. Authenticated founder-workspace UI smoke remains a final release-gate action.
  - **Roadmap:** **Complete ASM Verification is closed.** Alerts / MSP Portfolio / M5 not started.

## 2026.07.14 (v2026.07.14-19 — ASM Verification: affected-host truth + exposure coverage) — deployed 2026-07-14

- **Live Worker Version ID:** `7e6eb67c-7a6c-4708-b203-a57c1aa1c110`
- **Rollback Worker Version ID:** `895e7719-2a40-4163-99ce-20523a6cf6a1`
- **Remote D1 migration applied:** none — this release adds no table and no schema change.

### Fix + Feat (Complete ASM Verification — part 1 of the canonical episode)
- **ASM verification now targets real hosts and covers the exposure findings** (PR **#83**, squash-merged to main as `0d650e8`). ASM already rides the universal managed-case substrate (`managed_cases`, `case_type='asm_exposure'`, `domain_key='attack_surface'`) and already routes every transition through `canTransitionCase` — so this is gap-closure in place: **no new table, no migration, no parallel system, no new network primitive, no widened SSRF/host-scope boundary.**
  - **`asset_ref` held PROSE, not a host — on-demand ASM verification was non-functional in production.** `assetRefForFinding` fell back to the first evidence entry's `value`, which for every ASM finding is the finding's *description*. Proven against the real pipeline: `asset_ref = "1 administrative or login interface is publicly accessible: admin.example.com. Restrict access…"`. `verifyManagedCaseById` derives its probe target from `asset_ref` and guards it with `host === domain || host.endsWith("."+domain)` — a sentence never passes. So `POST /verify` could never resolve a case: `host_scope_mismatch` for the one supported type, `unsupported_finding_type` for the rest. It failed **closed**, so nothing was ever falsely verified — production was honest, just non-working. Every ASM resolution to date came from the weaker rescan-absence path.
  - **Affected-host truth:** ASM findings are *aggregate* (one finding covers N hosts, carries no `hostname`), so the detectors now emit a structured `affected_hosts` from the real asset records (`scoring.js`: takeover/sensitive_tool/admin_interface/dev_env; `scan-engine.js`: `admin_surface_*`; `cloud-storage-scan.js`: the customer-side DNS name). Hosts are validated + scoped through the existing `normalizeDiscoveredHostname` at write time **and again at read time** — a stored host is never trusted as in-scope merely because it was stored. The prose fallback is gone; a host-less finding yields the domain, never free text.
  - **Verifier coverage 1 → 6 types:** `asset_exposure_admin_interface` / `sensitive_tool` / `dev_env`, `admin_surface_critical` / `high` / `medium`. Presence predicates **reuse the real detectors** (`runAdminSurfaceModule` and `assetFingerprintSignals` are both pure), so a verifier cannot drift from the detector that raised the finding and resolve a live exposure. Two scan-wide suppressors (`provider_owned_infrastructure`, `wildcard_dns`) are unavailable to a single-host probe; omitting them can only make the profile see "still present" more readily — never a false "fixed".
  - **Multi-host semantics:** ANY affected host still exposed → `still_present` (short-circuits); ANY host inconclusive with none present → `deferred`. `fixed` requires **every** affected host observed conclusively clear — absence on a subset is not remediation. Over `MAX_VERIFICATION_HOSTS` (10) → defer without probing at all.
  - **Deliberately still unsupported, each failing closed:** `cloud_storage_*` (the object lives on third-party infrastructure outside the customer's DNS scope; probing it would widen the host-scope/SSRF boundary — founder decision, out of scope), `*_observed` info findings (observations, not exposures with a fix), and `subdomain_takeover` / `dse_*` (verifiable, but need DNS/header techniques — part 2).
  - **Rescan-absence is now fail-closed.** `moduleCompletionGate` previously did `if (!modules && !scanQuality) return null` while callers did `if (gate && !gate.canVerify(...))` — so with no telemetry, gating was skipped entirely and a completed scan alone verified the fix, which the verification contract forbids. The gate always returns an object now: no completeness evidence, partial scan, unknown detecting module, or a module that cannot be shown to have run clean → defer, never resolve; each deferral records why (`no_completeness_evidence` / `scan_partial` / `unknown_detecting_module` / `module_incomplete` / `module_did_not_run`). The only production caller already passes `{modules, scanQuality}`, so live behaviour is unchanged for complete scans.
  - **Honesty preserved:** `SYSTEM_ONLY_CASE_STATES` untouched (customer assertion ≠ CyberMeters verification); `createManagedCase`/`canTransitionCase` remain the only paths; Canonical Remediation Registry unchanged; append-only history intact (the raw finding keeps every observed host — scope filtering happens at read time).
  - **Tests (CI-blocking):** `validate-managed-verification` **28 → 65**, `validate-asm-remediation-loop` **22 → 32** — dispatch allowlist + fail-closed for every unsupported type, prototype-key injection, multi-host semantics, host cap (no probing), out-of-scope/metadata hosts never probed, legacy prose `asset_ref` deferring instead of probing the wrong host, `asset_ref` never a description, every fail-closed gate path. Two legacy tests asserted the old dishonest contract (resolving with no module evidence) and now supply real completeness evidence; the fixture domain moved off the reserved `.example` TLD rather than weakening hostname validation.
  - **Full gate:** all **79** CI validators, regression **227/227**, purge **10/10**, managed-case **92/92**, migrations **96/96**, tenant isolation, error contract, worker syntax, `wrangler --dry-run` clean, frontend Vitest **106/106** + build. CI green on PR #83 and on main.
  - **Production proof (side-effect-safe):** `GET /health` returns deployment `7e6eb67c…`; `/ready` 200; `POST /managed-cases/:id/verify` live and auth-gated (401). No migration to verify. Authenticated founder-workspace UI smoke remains a final release-gate action.
  - **Not included:** part 2 (`subdomain_takeover` + `dse_*` verification via DNS/header techniques). Its groundwork is committed, regression-green and unmerged on `feat/asm-verification-dns-headers` — shared `dse-findings.js` conditions, canonical `buildCaaFromAnswers`, and `runTakeoverModule` fetcher injection. Held back because `runTakeoverModule` returns `risks=[]` both when a CNAME is genuinely no longer dangling and when the body fetch was refused/failed; collapsing those to "fixed" would falsely resolve a live takeover risk. Alerts / MSP Portfolio / M5 not started.

## 2026.07.14 (v2026.07.14-18 — Identity Exposure Managed Workflow) — deployed 2026-07-14

- **Live Worker Version ID:** `895e7719-2a40-4163-99ce-20523a6cf6a1`
- **Rollback Worker Version ID:** `62a197de-639f-4123-91d0-b64fbf81ba5b`
- **Remote D1 migration applied:** `086-identity-exposure.sql` (additive; both tables verified present in production).

### Feat (Identity Exposure becomes a managed external identity-exposure workflow)
- **Identity Exposure Managed Workflow** (PR **#82**, squash-merged to main as `b88d17c`). **Additive migration 086.** Extends the existing identity-observation architecture — no second identity scanner, no duplicate asset table.
  - **Source-of-truth split:** `identity_assets` (mig 030) stays the raw externally-observed evidence + history (referenced, never copied); new `identity_exposure` (mig 086) owns classification, ownership, remediation, verification and monitoring; `identity_exposure_events` is append-only. Both added to `WORKSPACE_PURGE_TABLES`.
  - **Deterministic identity** (`identity-policy.js`): explicit provider alias layer (Entra ≠ M365; never fuzzy), closed surface-type set, canonical identity key — a hostname-anchored surface keeps its identity across a provider change (material event with OLD evidence preserved), a provider-level detection anchors on provider+surface. Explainable, non-alarmist risk model (an expected, owned provider login is `ok`; an unexpected public admin surface is `high`).
  - **Lifecycle engine** (`identity-lifecycle.js`): correlation with non-destructive evidence union; three-role ownership (business/technical/identity → known/partial/missing); 15 audited workflow actions (exceptions require reason+expiry); **external-observation-only verification** — a customer-recorded change/removal is NEVER verified until re-observed (removal: absent across a 14-day window → verified, still observed → failed, within window → inconclusive, nothing recorded → pending); ONE deterministic monitoring evaluator with explicit precedence (exception window → exception-expired → removal-contradicted → verification-failed → owner-missing(assign_owner) → public-admin → unexpected → retired-reappeared → investigate → provider-change → stale) that opens/reopens `identity_case` **via `createManagedCase`/`canTransitionCase`** → `identity.*` canonical remediation.
  - **5 new canonical remediation entries:** `identity.review.unexpected_surface`, `identity.review.public_admin_surface`, `identity.assign.owner`, `identity.review.provider_change`, `identity.review.exception_expired` — each states the exposed-surface-only scope; no leaked-credential/dark-web/MFA/Conditional-Access claim anywhere.
  - **APIs:** `/api/workspaces/:id/identity-surfaces[/:id[/action|/verify]]` — workspace-scoped, non-enumerating (foreign/nonexistent → same 404), soft-delete-gated. Distinct path from the preserved `/identity-exposure` verdict + `/identity-assets` inventory. Wired as scan **Phase 8l**.
  - **Frontend:** focused Identity Exposure managed page (`/ws/identity-exposure`, nav sub-item) + `identityExposureDisplay.js` (co-located Vitest) — hard line between **Observed externally / Classified by you / Verified by CyberMeters**; server-provided actions only.
  - **Honesty preserved:** `cyber-mot-domains.js` identity_exposure domain-state unchanged; `unknown_signals` carried on every record and verification.
  - **Tests (CI-blocking):** `validate-identity-exposure-lifecycle.js` (**78**, DB-backed). Full gate re-run at merge: regression, migrations guard, purge **10/10**, managed-case **92/92**, tenant isolation, error-contract, openapi (65 paths/76 ops), remediation registry **62** + parity **12**, worker syntax, `wrangler --dry-run` clean, frontend Vitest **106/106** + build. CI green on PR #82 and on main.
  - **Production proof (side-effect-safe):** `GET /health` returns deployment `895e7719…`; `/ready` 200; `/identity-surfaces` live and auth-gated (401); both tables verified in production D1; 25 active `identity_assets` await first correlation on the next scan (Phase 8l is scan-driven, so `identity_exposure` correctly starts empty). Authenticated founder-workspace UI smoke remains a final release-gate action.

## 2026.07.14 (v2026.07.14-17 — Certificates Managed Lifecycle) — deployed 2026-07-14

- **Live Worker Version ID:** `62a197de-639f-4123-91d0-b64fbf81ba5b`
- **Rollback Worker Version ID:** `3fae558d-1196-4198-ab7d-54d7276d9867`
- **Remote D1 migration applied:** `085-certificate-lifecycle.sql` (additive; `changed_db: true`, both tables verified present).

### Feat (Certificates & Trust becomes a managed certificate lifecycle)
- **Certificates Managed Lifecycle** (PR **#81**, squash-merged to main). **Additive migration 085.** Extends the existing certificate-observation architecture — no second scanner, no duplicate source of truth.
  - **Source-of-truth split:** `certificate_observations` (mig 031) stays the raw externally-observed evidence + history (referenced, never copied; a replacement never overwrites the old certificate's evidence). New `certificate_lifecycle` (mig 085) owns ownership, renewal planning, verification state and monitoring; `certificate_lifecycle_events` is append-only. Both added to `WORKSPACE_PURGE_TABLES`.
  - **Canonical renewal policy** (`certificate-policy.js`): ONE threshold source — bands 90+/60–89/30–59/14–29/1–13/expired → `readiness` + `risk_status`, plus `renewal_start_by = not_after − 30d`. Replaces the four scattered per-engine cut-offs (ssl-scan/cert-intel/cert-trust-l2/alerts). `days_remaining` from observed expiry only; `null` expiry → `unknown` (never assumed safe).
  - **Identity + replacement** (`certificate-lifecycle.js`): deterministic identity via the existing `certificate_key` surrogate; current cert = furthest-future expiry per host; a replacement is a NEW identity → `previous_certificate_observation_id` preserved, `replacement_detected_at` set, old observation never overwritten.
  - **Coverage model:** expected (customer-declared) vs observed SANs kept separate → complete/partial/missing/unexpected/unknown. Wildcard matches a single label only — never auto-covers apex or nested depth, never makes coverage "complete" for undeclared hosts.
  - **Ownership:** three-role (business/technical/renewal) → server-derived `ownership_status` (known/partial/missing), distinct from renewal/verification/monitoring status.
  - **Verification contract (external-observation only):** a customer "recorded renewal" moves to `awaiting_verification` and stays **not verified**. Positive verification requires a genuinely distinct new certificate observed on the expected hostname(s) with acceptable coverage AND a later expiry; incomplete coverage / no-new-cert → `inconclusive`; expiry-not-advanced → `failed`. Structured evidence keeps chain/root/OCSP/revocation/private-key/fingerprint/serial explicitly **unknown** (no live TLS).
  - **Monitoring evaluator:** ONE deterministic pass with explicit precedence (exception window → expired → recorded-not-observed contradiction → verification failed → replacement unverified → renewal-overdue(critical/expired) → coverage regression → unexpected SAN → owner-missing → stale). Opens/reopens `certificate_case` **via `createManagedCase`/`canTransitionCase`** → `cert.*` canonical remediation (never a separate case table, never a bare dedup).
  - **APIs:** `/api/workspaces/:id/certificates/lifecycle[/:id[/action|/verify]]` — workspace-scoped, non-enumerating (foreign/nonexistent → same 404), soft-delete-gated. Wired as scan **Phase 8k**.
  - **Frontend:** focused Certificate Lifecycle page (`/ws/certificates/lifecycle`, nav sub-item) + `certificateLifecycleDisplay.js` (co-located Vitest) — draws a hard line between **customer-recorded** and **externally-verified**; server-provided actions only.
  - **Honesty preserved:** `cyber-mot-domains.js` certificates_trust (M2/recommendations, chain/root/OCSP/revocation unknown) unchanged.
  - **Tests (CI-blocking):** `validate-certificate-lifecycle.js` (**71**, DB-backed). Full gate: migrations **95/95**, purge **10/10**, regression **227/227**, cert-trust-l2 **17/17**, tenant **86/86**, error-contract **116/116**, openapi ok, `wrangler --dry-run` clean, frontend build + Vitest **97/97** (coverage 84.85%).
  - **Not included:** unrelated `AGENTS.md` + `CLAUDE.md` documentation rewrites deliberately kept out of this PR (reviewed, held separate per instruction).

## 2026.07.14 (v2026.07.14-16 — Shadow IT correlation depth) — deployed 2026-07-14

### Feat (completes the Shadow IT approved-inventory foundation — multi-source correlation, ownership, monitoring)
- **Shadow IT correlation depth** (PR **#79**, merge on main). Builds on v2026.07.14-15, unchanged foundation. **Additive migration 084.**
  - **Multi-source correlation:** gathers from `workspace_vendors` + `workspace_assets.cloud_provider` + `identity_assets` + `email_sender_sources` (+ ephemeral `saas_exposure`). Each contribution keeps a structured evidence reference (`source_table, source_record_id, source_type, observed_identifier, first/last_seen_at, confidence`). Evidence is UNIONed **non-destructively** (`unionEvidence` — dedup by source_table+record, refresh last_seen, never drop a prior source). Generic CDN/hosting is categorised honestly (cdn/hosting/cloud_storage), never auto-treated as SaaS.
  - **Alias layer** (`TECHNOLOGY_ALIASES`): M365 variants → `microsoft_365`, G Suite → `google_workspace`, Entra/Azure AD → `microsoft_entra_id` — deterministic; unrelated products of one provider stay separate.
  - **Ownership:** server-derived `ownership_status` (known/partial/missing), separate from the customer classification (now 5: unreviewed/approved/rejected/exception/retired). Owner assignment recomputes + audits; owner-missing surfaces in API/frontend + opens a case when follow-up is due.
  - **Monitoring evaluator** (`evaluateShadowItMonitoring`): ONE deterministic pass over 9 conditions with explicit thresholds (`STALE_EVIDENCE_DAYS=45`, `MATERIAL_CHANGE_WINDOW_DAYS=30`); persists `monitoring_status/reason/evidence_age_days/material_change/recurrence_type/required_case_action/evaluated_at`. Approved disappearance stays a monitoring observation (no case); disappearance is never verified removal.
  - **Removal contradiction:** `removed + still observed` → `removal_verified=contradicted`, assertion preserved, event appended, case opened/reopened. **Linked-case recurrence:** `openOrReopenShadowItCase` reopens a verified/monitoring case **via `canTransitionCase`** (or appends a recurrence event to an active case) — never a bare dedup return, no separate case table.
  - **Migration 084 (additive):** `ownership_status, monitoring_reason, evidence_age_days, material_change, recurrence_type, required_case_action, evaluated_at, removal_verified` on `shadow_it_inventory`.
  - **Frontend:** ownership pill + recurrence hint; api `ownership_status` filter; descriptor updated (5 classifications + ownership).
  - **Tests (CI-blocking):** `validate-shadow-it-correlation.js` (48, DB-backed); existing shadow-it (34) + `shadowItDisplay` Vitest updated. Full gate: **all 77 CI validators**, frontend build + coverage (83%), `wrangler dry-run`, migrations guard.
  - **Deferred (report-only, not safely persistable this increment):** tech-fingerprints, cert-SANs, SPF provider inference.
  - **Deployed Worker Version ID:** `e27fca1a-e527-4243-adbe-53d5ffd01849` (`GET /health` confirms; `/shadow-it/inventory` live; 8 new columns verified in production D1). Pages redeployed.
  - **Rollback Version ID:** `1763d1d4-5110-4517-9739-58a79c1bf809`.
  - **Deferred (NOT started):** Certificates Managed Lifecycle, Identity workflow, all-domain alerts, MSP portfolio, M5.

## 2026.07.14 (v2026.07.14-15 — Shadow IT approved inventory) — deployed 2026-07-14

### Feat (Shadow IT & Unmanaged Technology becomes a managed approved-inventory system — foundation)
- **Shadow IT approved inventory** (PR **#77**, merge on main). Externally-observed scope only; classification is a customer decision separate from observation; nothing is called unauthorised until the customer classifies it. Uses the Universal Managed-Case Model for follow-up.
  - **Migration 083 (additive):** `shadow_it_inventory` (canonical, workspace-scoped, one row per correlated technology — full contract incl. `canonical_technology_key`, provider/category/source, observed identifiers/hostnames, first/last/changed seen, confidence, classification + reason, owners, approve/reject/exception/onboarding/removal/monitoring, source_evidence, linked_case_id) + `shadow_it_inventory_events` (append-only history). Both added to `WORKSPACE_PURGE_TABLES`.
  - **Identity + correlation:** `canonicalTechnologyKey` is a deterministic PRODUCT-level slug (`google_workspace ≠ google_cloud` — never provider-collapsed). `correlateShadowItInventory` **reuses `workspace_vendors`** (source of truth for the raw observation) grouped by that key + ephemeral `saas_exposure` portal URLs; classification/ownership persist across upserts, observation fields refresh; detects material change, disappearance (`no_longer_observed` — never auto verified-removed) and reappearance; soft-deleted workspaces skipped.
  - **Classification/workflow:** 12 audited customer actions (approve/reject/mark_exception/assign owners/set purpose/onboarding/removal/retire/reopen); exception requires reason + expiry; reject is not removal; mark_removed is a customer assertion. `evaluateShadowItRecurrence` opens a `shadow_it_case` (→ `shadow_it.saas.review`) for rejected-still-observed / retired-reappeared / exception-expired via `createManagedCase`.
  - **Wiring/API/frontend:** scan-pipeline correlation phase (after supply-chain, soft-delete gated); `routes/shadow-it.js` workspace-scoped GET inventory (+counts/filters), GET item (+history + linked case), POST action (non-enumerating 404); `ShadowItInventoryPage` (server-provided actions only — cannot invent classification states) + shared `shadowItDisplay` descriptor.
  - **Tests (CI-blocking):** `validate-shadow-it-inventory.js` (34, DB-backed); `shadowItDisplay` Vitest unit test; Shadow IT added to `validate-tenant-isolation.js` (86). Full gate: **all 76 CI validators**, frontend build + coverage, `wrangler dry-run`, migrations guard.
  - **Deliberately unchanged:** `cyber-mot-domains` shadow_it stays observation-only (coverage-state honesty preserved).
  - **Deployed Worker Version ID:** `307ada26-e5f8-41dc-9c9d-9c36cb6b4c81` (`GET /health` confirms; `/shadow-it/inventory` live; both tables verified in production D1). Pages redeployed.
  - **Rollback Version ID:** `7eb57f71-c27a-4f0d-83cb-0983588f8b52`.
  - **Deferred (NOT started):** Certificates Managed Lifecycle, Identity domain workflow, all-domain alerts, MSP portfolio, M5.

## 2026.07.14 (v2026.07.14-14 — universal case invariants enforced) — deployed 2026-07-14

### Feat (completes the Universal Managed-Case Model — transition + creation invariants enforced platform-wide)
- **Universal case invariants** (PR **#75**, merge on main). Builds on v2026.07.14-13, unchanged. **No schema change this increment.**
  - **No bypass:** the ASM and Brand state machines were extracted into neutral leaf modules (`asm-case-machine.js`, `brand-case-machine.js`) to break the import cycle, so `asm-cases.js` (`updateCaseStatus` + the `casCaseStatus` CAS) and `brand-cases.js` (`applyBrandTransition`) validate through `canTransitionCase` before persisting + appending the event. **No raw `applyCaseTransition` status-mutation remains in either engine.** Machines, stored states and side effects unchanged; one additive ASM edge (`verifying→verification_requested`) makes the concurrency release validator-legal instead of a raw-CAS bypass.
  - **Verification contract:** `validateVerificationEvidence` requires structured evidence (`verification_method`, `verification_result`, `evidence_type`, `observed_at`, `observation`/`attestation`/`evidence_reference`). Unsupported / scan-completion-only / note-only / failed / inconclusive / still-present never verify; automated case types (ASM/Brand) verify only by CyberMeters (system actor); manual base domains verify via a structured attestation from an identified actor. ASM/Brand resolve sites pass conforming automated evidence. Precedence: edge → system-only → verified.
  - **`createManagedCase` factory (six base types):** validates domain key + case_type + match, active workspace + linked domain, canonical remediation linkage or explicit null, initial state, deduplication, source linkage, creation timestamp, and an append-only `case_created` event. Wired to `POST /api/workspaces/:id/cases` (base types only).
  - **Event taxonomy:** `CASE_EVENT_TYPES` + `buildCaseEventDetail` define the canonical deterministic `detail_json` shape for every universal write; legacy ASM/Brand actions stay readable.
  - **Frontend:** the AssetsPage `CasesQueue` mount is labelled a temporary integration proof (component is standalone/reusable; not the permanent IA).
  - **Tests (CI-blocking):** `validate-universal-case-factory.js` (21, DB-backed); `validate-managed-case-model.js` grown to 92. ASM/Brand compatibility green. Full gate: **all 75 CI validators**, frontend build, `wrangler dry-run`, migrations guard.
  - **Deployed Worker Version ID:** `554e6ac1-2edd-48b0-8f7b-32877ffe5182` (`GET /health` confirms; GET/POST `/cases` + `/cases/:id/transition` live, auth-gated). Pages redeployed.
  - **Rollback Version ID:** `8d91a9ab-d74f-4d39-b108-277bd082ecf6`.
  - **Deferred (NOT started):** Shadow IT inventory, cert renewal workflow, identity domain workflow, all-domain alerts, MSP portfolio, M5.

## 2026.07.14 (v2026.07.14-13 — universal managed-case model) — deployed 2026-07-14

### Feat (one shared managed-case platform across all eight Cyber MOT domains — platform, not per-domain workflow depth)
- **Universal Managed-Case Model** (PR **#73**, merge **fa2bfd6**). Extends the existing `managed_cases` table + generic `case-workflow` engine **in place** — no parallel case system. **Additive migration (082) only.**
  - `engines/managed-case-model.js` — canonical BASE lifecycle with machine-stable keys: `detected → triaged → assigned → approved → action_in_progress → awaiting_verification → verified → monitoring → reopened` + terminal/exceptional `rejected / accepted_risk / false_positive / closed_no_action / superseded`. `CASE_TYPE_REGISTRY` registers all eight domains — `attack_surface` (asm_exposure) and `brand_protection` (brand_abuse) keep their EXISTING machines (full back-compat); the other six use the base machine. `CANONICAL_PHASE_MAP` folds every case_type's states onto one canonical phase for a cross-domain queue. **`canTransitionCase(...)` is the single validator** — enforces machine edges/guards/terminal-immutability, the system-only rule, and the universal invariants: verified needs a **system actor AND verification evidence** (a completed scan alone never verifies); accepted-risk / false-positive are never the verified phase; reopen preserves prior evidence; canonical timestamps stamped; an append-only history event is returned.
  - **Migration 082 (additive):** `domain_key`, `source_finding_type/scan_id`, `remediation_id`, `title/summary/priority`, `assigned_user_id/business_owner/technical_owner`, and lifecycle phase timestamps on `managed_cases`; back-fills `domain_key` for existing ASM/Brand rows (**4 production asm_exposure cases → attack_surface, verified live**); reuses `managed_case_events` as the append-only history (no duplicate tables).
  - **Compat + linkage:** ASM + Brand case creation attach `domain_key` + canonical `remediation_id` + `source_finding_type`. ASM scan-driven auto-open now **gates soft-deleted workspaces** (`deleted_at IS NULL`) — closes a rule-13 gap.
  - **`routes/managed-cases.js`:** universal cross-domain `GET /cases` + `GET /cases/:id` (canonical_phase + append-only history) + `POST /cases/:id/transition` routed **only** through `canTransitionCase` (no bypass), workspace-scoped, soft-delete gated, same 404 for foreign + nonexistent. ASM/Brand keep their bespoke endpoints.
  - **Frontend:** shared `caseDisplay` descriptor (canonical phase labels — no transition map), `api.getCases/getCase/transitionCase`, minimum cross-domain `CasesQueue` presentation.
  - **Tests (CI-blocking):** `validate-managed-case-model.js` (75 assertions); universal `/cases` added to `validate-tenant-isolation.js` (83). Full gate green: regression 227, **all 74 CI validators**, frontend build, `wrangler dry-run`, migrations guard.
  - **Deferred (NOT started):** Shadow IT inventory, certificate renewal workflow, identity domain workflow, all-domain alerts, MSP portfolio, M5.
  - **Deployed Worker Version ID:** `8403e8c2-0ae6-4fe8-9a44-f0ddbaaaa6a8` (`GET /health` confirms; `/cases` live; migration backfill verified in production D1). Pages redeployed.
  - **Rollback Version ID:** `10f66998-572c-49e2-a064-ce17f17c21d7`.

## 2026.07.14 (v2026.07.14-12 — canonical remediation coverage completion) — deployed 2026-07-14

### Feat (completes the canonical remediation registry — every customer-facing source now resolves canonically)
- **Canonical remediation coverage completion** (PR **#70**, merge **255d366**; CI-blocking parity harness PR **#71**, merge **fa7fcbf**). Builds on v2026.07.14-11 (PR #69 / e554db0), unchanged. **No migration, no schema change.**
  - **Registry (additive):** new `cert.intelligence.review`, `cert.caa.configure`, `ce.backlog.remediate`, `ce.access.saas_review`; extended `asm.exposure.admin` (`admin_surface_critical/high/medium`), `web.header.hsts` (`dse_hsts_not_preload_eligible`), `web.cookie.flags` (`dse_cookie_no_samesite`) — closing emitted-but-unmapped actionable finding types. New `resolveByCustomerTitle()` (reunites persisted canonical titles with their identity) and `findingRemediation()`.
  - **Executive PDF — fabrication removed.** `priority_actions`/`top_recommendations` no longer promote raw posture reasons or fabricate `"Improve {category}"` titles — they consume the canonical remediations posture scoring now exposes; `priority_action_plan` is assembled only from canonical remediations (enriched `top_recommendations` + CE `canonical_remediations`) carrying `remediation_id` + canonical `business_impact`, deduped by identity; generic impact only as an honest fallback. `executive-report.js` threads `remediation_id` + `verification_method` so the Executive Report UI and the PDF carry the **same** remediation identity per title.
  - **Cyber Essentials:** `ce-readiness.js addGap` resolves each control-gap ACTION from the registry (reusing the technical remediations + the new CE entries); the `reason` stays CE risk framing; emits `canonical_remediations`. Certification stays external (IASME) — separate from readiness remediation.
  - **Posture scoring:** each category keeps its risk `reasons` AND exposes canonical `remediations` for any promoted action; surface-expansion-only signals promote nothing (honest, no invented advice).
  - **Frontend is no longer a second source of truth:** `frontend/src/data/remediation.js` drops `LIBRARY`/`METADATA_ONLY`/`PREFIX_ALIASES`/`MODULE_OWNER` (~560 lines); all semantics (title, business impact, action, owner, effort, verification) come from the backend `finding.remediation`; only step-by-step + a CLI verification command remain, keyed strictly by canonical `remediation_id`. `/report` enriches each finding with its canonical remediation (compute-on-read).
  - **Production finding coverage:** `validate-remediation-coverage.js` checks EMITTERS against the registry — every actionable production finding type → exactly one primary canonical remediation; informational → explicit `remediation_not_required`; a static emitter sweep fails CI on any new unclassified finding id. Forward-looking entries with no current producer (`cert.ca_concentration`, `ce.certification.external`, `identity.*`) are reported.
  - **Tests (CI-blocking):** `validate-remediation-coverage.js`, `validate-frontend-remediation-source.js` (frontend cannot override canonical title/action), `validate-remediation-surface-parity.js` (Scan Detail / Exec Report / Scorecard-PDF join / posture→PDF / CE all resolve the SAME `remediation_id` for Email + Web/ASM + CE — proven by running the actual builders), plus cross-surface join-parity in `validate-remediation-registry.js` (62 assertions). Full gate green: regression **227/227**, **all 72 CI validators**, frontend build, `wrangler deploy --dry-run`.
  - **Deployed Worker Version ID:** `41d1608c-909a-4a81-a10b-4365e9f93327` (`GET /health` confirms in production; Pages frontend redeployed).
  - **Rollback Version ID:** `c1dd9175-150a-40c0-8f1c-06d97c84bde8`.

## 2026.07.14 (v2026.07.14-11 — canonical remediation registry) — deployed 2026-07-14

### Feat (one canonical source of truth for customer-facing remediation content across all eight Cyber MOT domains)
- **Canonical remediation registry + resolver** (PR **#69**, merge **e554db0**). **No migration, no schema change, no frontend change.** Code-backed, resolved at read time; historical reports keep resolving via aliases.
  - `engines/remediation-registry.js` — **49 active entries** across the eight domains (domain keys derived from `CYBER_MOT_DOMAINS`, single source of truth). Full contract per entry: `remediation_id` (stable dotted slug, independent of display copy), `version`, `status`, `domain_key`, `finding_types[]`, `customer_title`, `technical_explanation`, `business_impact`, `recommended_action`, `effort`, `owner_type`, `verification_method` + `verification_evidence_requirements`, `supporting_evidence_types[]`, `managed_workflow_compatible`, `case_type`, `applicability`, `limitations[]`, `references[]`, `introduced_at`/`deprecated_at`/`replacement_remediation_id`.
  - `resolveRemediation({finding_type, domain_key, evidence, context, surface})` — pure, deterministic, **surface-invariant**. Known type → primary (+ secondaries); legacy alias → same canonical; **unknown → fails honestly, no generic advice**; deprecated → forwards to replacement, flagged; evidence-dependent applicability (BIMI needs enforced DMARC); unsupported verification (cert chain/OCSP/revocation) stays **explicit**. The finding_type index **throws on a conflicting primary** so the invariant cannot silently break.
  - **Wired the shared backend generation points** to source canonical advice: `scoring.js` (the persisted `remediation_items` path — scan detail, scorecard, executive report and PDF all inherit it), `email-intel.js` + `email-analysis.js` (the email fan-out), and `business-risk.js` IMPACT_MAP. **Real conflicts fixed:** DMARC now consistently **ramps from p=none** (was `p=quarantine` in scoring vs `p=reject` in BRS — previously visible together in one PDF); SPF guidance unified. Concrete DNS records / affected-host lists preserved as surface detail.
  - **Honest scope enforced per domain:** Identity = exposed sign-in surface only (no breach/credential/dark-web); Shadow IT = externally observed only; Cyber Essentials certification stays external (IASME); Brand takedown stays prepare-and-track.
  - **Deliberately deferred (documented follow-up, NOT this PR):** `posture-scoring.js` reason-promotion, `ce-readiness.js` re-wording, `pdf.js` title fabrication, and frontend `data/remediation.js` still hold their own copies. This wires the highest-leverage, conflict-bearing backend points, not every screen.
  - **Tests:** new CI-blocking `validate-remediation-registry.js` (**55 assertions** — stable ids, 8 domain keys, all finding types resolve, aliases → same canonical, deprecated forwards safely, unknown fails honestly, surface invariance + wired-generator parity, historical compat, per-domain honesty wording, determinism, no duplicate/conflicting primaries). Full gate green: worker parses, regression **227/227**, **all 70 CI validators pass**, hosted-DMARC lifecycle contracts unchanged and green, wrangler dry-run clean.
  - **Deployed Worker Version ID:** `a54d51ef-8742-42ed-b85b-b83e0e0a6f02` (`GET /health` confirms in production).
  - **Rollback Version ID:** `e6604068-837f-47cb-b98b-772c368eaaff`.

## 2026.07.14 (v2026.07.14-10 — eight-domain coverage-state parity) — deployed 2026-07-14

### Fix (parity patch to v2026.07.14-9 — three honesty gaps closed before the episode closes)
- **Eight-domain coverage-state parity** (PR **#68**, merge **f3c37c7**). No migration.
  1. **Cyber Essentials cross-surface parity.** New canonical `getCyberEssentialsSnapshot(wsId, env)` is the single CE source; scan `/report`, `/executive-report-v2`, the Executive PDF (`collectPdfData`) and the new `/cyber-mot-domains` endpoint all pass it into the same resolver, so a workspace shows the SAME CE state on every surface. The snapshot gates on questionnaire **completeness** (not `COUNT(*)>0`): no answers **or** a partial answer set → `customer_input_required`; only a COMPLETE questionnaire (all 20 questions answered non-`unknown`, via `isCyberEssentialsQuestionnaireComplete` over the canonical `CE_QUESTIONS`) yields a readiness verdict, and `assessed_healthy` only when complete **and** likely_ready. **Live proof:** BBB shows `customer_input_required` identically on the Dashboard endpoint, `/report` and `/executive-report-v2`.
  2. **Dashboard no-scan + endpoint-failure visibility.** New `GET /api/workspaces/:id/cyber-mot-domains` (workspace:read, no feature gate) server-resolves the eight states from the authoritative scan, the canonical no-scan states when none exists, or the no-scan set on any error — always eight. The Dashboard fetches it and renders unconditionally. New `frontend/src/lib/cyberMotDisplay.js` `resolveDisplayDomains()` guarantees the component never renders fewer than eight: absent/malformed/failed data → the eight canonical domain names in a non-healthy `unavailable` state (no domain disappears, none becomes healthy; no state derived in the frontend).
  3. **Per-domain healthy-eligibility predicates.** `assessed_healthy` now requires a domain's own `required` module(s) to have been assessed on a COMPLETE scan with no material finding — email→[email_security], brand→[brand_monitoring], attack_surface→[subdomains,dns] (closes the CT/subdomain healthy-off-missing hole), certificates_trust→[certificate_intelligence] (chain/root/OCSP/revocation stay **unknown** via limitation — never a positive trust claim), website→[headers,ssl], identity→[identity_discovery]. A required module errored/skipped/incomplete → `evidence_insufficient`; absent → `not_yet_assessed`; provisional scan → `provisional`. **Live proof:** BBB `missing-evidence-healthy: false` — every healthy domain has evidence.
  - **Tests:** `validate-eight-domain-parity.js` (83 — CE parity + real node:sqlite full-vs-partial questionnaire completeness, no-scan, endpoint-failure fallback, per-domain healthy matrix); updated coverage-state (29) + wiring (15). Full regression + report scoping/branding + parity + tenant isolation + entitlement + migrations + lifecycle + frontend build + wrangler dry-run green.
  - **Deployed Worker Version ID:** `ef8860fc-6f1b-44b8-9b85-582ae7282707`.
  - **Rollback Version ID:** `d79da556-84d5-44fa-800d-61cf048d461f`.

## 2026.07.14 (v2026.07.14-9 — eight-domain Cyber MOT coverage-state honesty) — deployed 2026-07-14

### Feat (first before-public-beta episode of the eight-domain managed Cyber MOT roadmap)
- **Canonical eight-domain coverage-state honesty** (PR **#67**, merge **2b684cf**).
  One compute-on-read resolver for the eight customer-facing Cyber MOT domains, wired
  into the four primary surfaces so every domain is always visible with one explicit
  honest state and missing evidence can never render as healthy. **No migration, no new
  storage, no scan-pipeline change.**
  - `engines/cyber-mot-domains.js` `resolveCyberMotDomainStates(report,{cyberEssentials})`
    — always returns the eight domains in fixed canonical order (email_protection,
    brand_protection, attack_surface, certificates_trust, cyber_essentials_readiness,
    website_security, identity_exposure, shadow_it_unmanaged_technology) with stable
    keys, a fixed state enum (assessed_healthy | issue_detected | provisional |
    degraded | unavailable | not_configured | customer_input_required | monitoring_only
    | not_yet_assessed | evidence_insufficient) and honest metadata (coverage, maturity,
    managed_status, evidence/finding counts, highest_severity, limitations, source scan).
    Deterministic precedence: a real finding is never hidden (issue_detected + coverage
    caveat); anything that is not a COMPLETE scan is provisional; missing/insufficient
    evidence is never healthy. Reuses the existing canonical scan-quality + findings
    semantics — no competing quality system.
  - **Honest scopes preserved:** Identity Exposure covers spoofing / impersonation /
    exposed-login surfaces only (no breach/credential/dark-web claim); Shadow IT is
    `monitoring_only` — "observed", never "unauthorised" (approved-inventory comparison
    is a separate later episode).
  - **Wiring (frontend renders server states; no resolver logic duplicated):** scan
    `GET /report` + `/executive-report-v2` responses carry `cyber_mot_domains`;
    `collectPdfData` computes it over the workspace authoritative (latest-complete)
    scan; the Executive PDF gains a compact page-12 "Eight-Domain Cyber MOT Coverage
    Summary" (**v2.2 → v2.3, +1 page, no section removed, white-label preserved**); a
    shared `<CyberMotDomains>` renders on the Main Dashboard, Scan Detail and Executive
    Report UI. The Dashboard's default-to-green health fallbacks were removed.
  - **Explicitly NOT started** (separate later episodes): Shadow IT approved inventory,
    Certificates managed renewal cases, Identity Exposure cases, eight-domain alerts,
    MSP per-domain portfolio trends, remediation registry, universal ASM verification,
    M5 workflows.
  - **Tests:** `validate-eight-domain-coverage-state.js` (27 — matrix 1–20 incl. no-scan,
    partial, degraded, unknown, missing-module, DKIM-uncertainty, brand-watchlist,
    CT-incomplete, HTTPS≠trust, CE-input-required, identity-scope, shadow-monitoring) and
    `validate-eight-domain-wiring.js` (15 — four-surface wiring + PDF renders all eight +
    white-label). Full regression + report scoping/branding + parity + tenant isolation +
    entitlement + migrations + lifecycle + frontend build + wrangler dry-run green.
  - **Production proof (side-effect-safe, founder BBB workspace):** the authoritative
    scan `/report` and `/executive-report-v2` both return exactly **8** domains in stable
    order with the correct source scan; **no missing-evidence domain marked healthy** (CE
    → customer_input_required, Shadow IT → monitoring_only, real findings → issue_detected);
    Identity/Shadow-IT wording scope-honest. No customer report or email generated.
  - **Deployed Worker Version ID:** `d79da556-84d5-44fa-800d-61cf048d461f`.
  - **Rollback Version ID:** `3fae558d-1196-4198-ab7d-54d7276d9867`.

## 2026.07.14 (v2026.07.14-8 — atomic scheduled-report occurrence claim) — deployed 2026-07-14

### Fix (concurrency — close the v2026.07.14-7 overlap gap)
- **Atomic occurrence claim for scheduled report generation** (PR **#66**, merge
  **9f25df0**). v2026.07.14-7 bounded scheduled reports but the overlap-idempotency
  evidence was only two *sequential* invocations. Two genuinely overlapping cron
  invocations could both observe no completed row, both `INSERT` a pending row, both
  build the PDF, and both complete — duplicating the `workspace_reports` row, the
  customer notification, and the monthly usage count (a COUNT of completed rows). The
  claim was a SELECT-then-INSERT with **no atomic constraint**.
  - **Migration 081 (additive):** partial `UNIQUE INDEX
    idx_workspace_reports_active_occurrence (workspace_id, report_type,
    report_period) WHERE deleted_at IS NULL AND status != 'failed' AND report_period
    IS NOT NULL`. Excludes soft-deleted history (regeneration after delete stays
    possible) and failed rows (retryable). D1 partial-index support proven (migration
    076 already uses one). **Pre-checked against production D1 — zero conflicting
    active duplicates — before applying.**
  - **`claimReportOccurrence`** — the pending INSERT is now `INSERT OR IGNORE`, so
    exactly ONE concurrent caller wins (`changes=1`). A loser returns the existing
    row with `claimed:false` and performs **zero** generation side effects (no PDF
    build, R2 write, notification, or usage row). Side effects were already
    post-completion, so only the winner emits them.
  - **Stale-claim recovery:** a pending row older than `STALE_REPORT_CLAIM_MINUTES`
    (30) means the owning invocation died; it is transitioned to `failed` (guarded)
    and the claim retried once, so a crash can never block the occurrence forever. A
    fresh live pending is never stolen.
  - The user-schedule caller (`processScheduledReports`) now notifies/audits only
    when it actually generated (`claimed !== false`) — no duplicate notification. The
    bounded engine counts a claim-loser as `jobs_deduplicated`, not
    `reports_generated`.
  - No report content, product naming, navigation, or scan-execution change. No
    Queue/Durable Object; no in-memory lock.
  - **Tests:** `validate-report-occurrence-claim.js` (23 assertions — true
    interleaving, DB uniqueness enforcement, completed no-regeneration, failed retry,
    stale recovery + fresh-not-stolen, R2-failure retryable, loss-path zero
    side-effects, overlapping retry → one claim, soft-delete history coexistence,
    caller notification guard), wired into CI. Bounded-batching / entitlement /
    fairness / report scoping+branding / lifecycle / migrations guard / dry-run green.
  - **Production proof (side-effect-safe):** against the live index, two
    `INSERT OR IGNORE` claims for a synthetic throwaway occurrence yielded
    `rows_written` 1 then **0** (the second blocked) — exactly one row — then the
    synthetic rows were deleted. No customer report / email / usage created.
  - **Deployed Worker Version ID:** `3fae558d-1196-4198-ab7d-54d7276d9867`.
  - **Rollback Version ID:** `b96353c2-8893-46cd-ad7e-e257daea17e0`
    (migration 081 is additive — rollback is worker-only; the index is harmless to
    the prior worker, which it also protects).

## 2026.07.14 (v2026.07.14-7 — bounded scheduled report generation) — deployed 2026-07-14

### Fix (architecture audit follow-up — the single launch-adjacent finding)
- **Bound scheduled executive-report generation** (PR **#65**, merge **4fa09b0**).
  Source: the Product Capability & Execution Architecture Audit, which flagged
  `generateScheduledReports` as the only launch-adjacent item — it iterated **every**
  workspace in one hourly cron invocation (no batch limit, no `deleted_at` filter, no
  entitlement re-check, status-blind idempotency). **No migration; no Queue/Durable
  Object; no new Worker/DB; no scan-orchestration or report-content change.**
  - New `engines/scheduled-reports.js` makes the cron job **bounded** (
    `SCHEDULED_REPORT_BATCH_LIMIT`, default **25**, env-tunable, clamped [1,100]; the
    deferred remainder drains across the report-day's later hourly invocations),
    **deterministic + fair** (never-attempted jobs first so a persistent failure can't
    starve fresh workspaces, then report_type, then workspace id ascending),
    **idempotent** (a completed `workspace_reports` row for (workspace, type, period)
    is the claim; the R2 key is deterministic per that tuple so an overlapping run
    writes one artifact; dedup is now `status='completed'`-scoped, so a stale
    pending/failed period is retried not blocked — no migration required),
    **entitlement-aware** (re-checks workspace-active + effective plan `pdf_reports` +
    report quota via the canonical helpers; skipped jobs create no report row / R2
    object / email / usage increment — closes a free-plan auto-PDF gap), and
    **observable** (one structured summary per invocation + per-failure reason codes).
  - `index.js` handler is now a thin isolated wrapper; the cron registry, other ~13
    hourly tasks, and PDF/report builders are untouched.
  - **Batch-limit rationale:** each executive report is ~a handful of subrequests +
    one PDF build; 25/invocation is a few hundred subrequests (well within the
    per-invocation budget, leaving room for the other cron tasks) and, drained across
    24 hourly invocations, covers hundreds of workspaces per report-day.
  - **Tests:** `validate-bounded-scheduled-reports.js` (33 assertions — matrix A–L:
    no-due / below-limit / above-limit / next-invocation / deterministic-tie /
    failure-isolation / overlap-idempotency / entitlement-change / deleted-workspace /
    R2-failure / completed-only-dedup / generation-unchanged, plus fairness,
    observability, batch resolution), wired into CI. Full regression + report scoping +
    branding + lifecycle email + weekly digest + tenant isolation + migrations +
    error-contract + wrangler dry-run green.
  - **Production smoke (side-effect-safe):** batch default 25/max 100 (no override); 7
    eligible workspaces (all fit one invocation now — the bound activates past 25 at
    scale); today (Tue) is a confirmed live no-op (due_types `[]`, 0 executive reports
    created in 2h); next Monday deterministically → `weekly_executive 2026-W30`. No
    customer reports created during the smoke.
  - **Deployed Worker Version ID:** `b96353c2-8893-46cd-ad7e-e257daea17e0`.
  - **Rollback Version ID:** `1763d1d4-5110-4517-9739-58a79c1bf809`.
  - **Residual (non-blocking):** stale `pending` rows from a crashed generation are
    left in place (not `completed`, so J-safe and non-blocking); the deeper scan-
    execution queue/DO separation remains post-launch scaling work (not this episode).

## 2026.07.14 (v2026.07.14-6 — security invariant stabilization) — deployed 2026-07-14

### Fix (audit follow-up — close localized invariant gaps before the architecture audit)
- **Security Invariant Stabilization** (PR **#64**, merge **fa7d7f4**). Source: the
  Security Invariant Consolidation audit (no fundamental architectural instability;
  the core architecture is sound). One focused PR, one guarded release, **no
  migration** (reuses the deployed `scan_quality` column).
  - **Ep1 — Scheduled scan eligibility parity.** New canonical
    `evaluateScheduledScanEligibility()` (engines/plan-usage.js) reuses
    `isWorkspaceDomainVerified` / `getEffectivePlan` / `hasFeatureEntitlement` /
    `checkScanLimit` / `consumeApiRateLimit`; `triggerScheduledScan` now gates on it
    at **run time** (verified link → workspace accessible → scheduled-scans feature →
    monthly quota → fail-closed scan-start rate limit) before any scan row, with
    stable reason codes (`domain_verification_required`, `feature_not_entitled`,
    `scan_limit_exceeded`, `workspace_not_accessible`, `rate_limit_unavailable`) and
    **zero side effects** on skip. A downgraded/over-quota account can no longer run
    unlimited scheduled scans.
  - **Ep2 — Email Protection entitlement.** Hosted-DMARC policy gate resolves the
    owner's **current effective plan** via `getEffectivePlan` (subscriptions,
    grace/expiry aware) instead of the stale, never-synced `users.plan` column.
    **Live proof:** BBB owner (professional/trialing) → `policy_management_available:
    true` (previously fail-closed-locked to `false`).
  - **Ep3 — Current-findings de-duplication.** One canonical, exported
    `LATEST_COMPLETED_SCAN_SCOPE` (deterministic `created_at DESC, id DESC` +
    complete-only) reused by Executive Dashboard, Workspace Insights, executive
    report and PDF — replaces a raw 30-day window and tie-prone `MAX(created_at)`
    joins. **Live proof:** BBB workspace had 4 raw critical findings across all
    scans; the dashboard and the canonical scope both report **0** current (latest
    complete scan), no inflation.
  - **Ep4 — 403/404 existence oracle.** Scan report/detail, schedule delete and
    workspace restore authorize **before** revealing existence. **Live proof:** a
    foreign-existing scan id and a nonexistent id return **byte-identical 403** (same
    status + body) on both report and detail endpoints.
  - **Ep5 — Finalization/reconciliation parity.** Scheduled-scan catch is
    downgrade-guarded (`status != 'completed'` + R2 completed-check — never clobbers
    a completed scan); the scan-detail reconciler converges `scan_quality` from the
    canonical R2 report, matching the list reconciler and finalizer.
  - **Ep6 — DMARC ingest rate limit.** Now **fail-closed** (503, before any
    parse/persistence) when the limiter store is unavailable, so its abuse cap
    survives the D1 stress an attack would create; dedup unchanged.
  - **Ep7 — Dead code.** Removed the ungated, zero-caller `sendScoreDropAlert`
    (proven zero references); the canonical comparable-gated alert path is unchanged.
  - **Ep8 — Workspace-access predicates.** No change (documented non-blocking debt):
    `portfolio.js` already delegates to `getAccessibleWorkspaceIds`; the `account.js`
    GDPR data-export predicate is intentionally broader (includes soft-deleted
    workspaces, no token boundary), so consolidating would change export semantics.
  - **Tests (CI-blocking):** new `validate-scheduled-eligibility` (9),
    `validate-email-entitlement` (9), `validate-current-findings-dedup` (9),
    `validate-stabilization-contracts` (18); updated report-findings-scoping
    (complete-quality fixture), canonical-presentation-parity (32),
    domain-verification-gate (34). Full regression + tenant isolation + migrations
    guard + frontend typecheck/build + wrangler dry-run all green.
  - **Production smoke:** /health + /ready = 200 (d1=true, r2=true); secrets intact;
    no `--var`; oracle/findings/entitlement live proofs above; no unnecessary
    production scans (scheduled eligibility proven via the side-effect-free
    behavioural test); all controlled sessions revoked.
  - **Deployed Worker Version ID:** `1763d1d4-5110-4517-9739-58a79c1bf809`.
  - **Rollback Version ID:** `7eb57f71-c27a-4f0d-83cb-0983588f8b52`.
  - **Non-blocking debt (deferred):** Ep8 duplicated predicates; the PDF `info`-count
    is not latest-scan-scoped (non-threat metric); the portfolio-overview bare "Avg
    Score" number (shared finding CTE).

## 2026.07.14 (v2026.07.14-5 — partial-scan score honesty) — deployed 2026-07-14

### Fix (customer trust — a partial assessment could read as a clean "Excellent")
- **Partial-scan score honesty** (PR **#63**, merge
  **896d93fb** — `896d93f`; follow-up honesty fixes on main `1e934b5`, `190e6b8`,
  `2f6dd72`).
  - **Root cause:** a scan's score was computed purely from findings, so a scan
    that skipped risk-producing checks (timeout / subrequest budget / dependency
    degraded) produced *fewer deductions* → a *higher* score, and `scan_quality`
    was never persisted to D1 or fed into score/rating/trend. A partial scan could
    therefore score 95/"Excellent" while a complete scan scored 82/"Good", and a
    workspace whose only scan was partial headlined a clean rating.
  - **Model (strict):** `scan_quality ∈ complete | partial | degraded | unknown`
    (NULL = unknown, never complete). Only a **complete** assessment is
    authoritative, comparable, and may carry an unqualified rating. Partial /
    degraded / unknown are **provisional**: raw score shown as observed (no
    dampening/clamping), **no rating**, with a status caveat. Authoritative current
    posture = latest **complete** scan (tie-break `created_at DESC, id DESC`); a
    newer partial never replaces it. Trend deltas are **complete-vs-complete only**.
  - **Canonical seams:** one presentation resolver
    `resolveAssessmentPresentation({score,scanQuality,status})` and one posture
    selector `getAuthoritativeCurrentPosture` / `getCurrentPosturePresentation`.
    Every customer surface delegates to them — scan-detail + report API, executive
    report, scorecard (API + PDF), executive dashboard, workspace insights,
    portfolio customer rating, scan-report PDF, executive-workspace PDF, workspace
    detail, and the main Dashboard. Score-drop alerts fire only on a comparable
    (complete) delta. Enforced by a static contract test
    (`validate-canonical-presentation-parity.js`, 32 assertions) that fails CI if a
    consumer re-introduces a divergent rating.
  - **Persistence:** migration **080** adds `scan_quality` to `scans` and
    `historical_scores` (additive `ALTER ADD COLUMN`, no DROP). `finalizeScanResult`
    and the stuck-scan reconciler both write it. **Migration 080 result (remote
    D1):** 2 columns added; row counts unchanged (**scans 82 / historical_scores
    81**); all values initially NULL; **zero** defaulted to complete.
  - **Controlled new-scan D1/R2 parity proof (2026-07-14):** one authorised scan on
    the canonical BBB workspace-domain (scan `scan_a10a9af0`) finalized
    **status=completed, score=87**; **D1 `scans.scan_quality`=complete = R2
    `report.scan_quality.status`=complete = `historical_scores.scan_quality`=
    complete**; exactly 1 scan row + 1 historical row (no duplicate scan/report/case
    side-effects).
  - **Backfill reconciliation** (one-time auditable script
    `scripts/backfill-scan-quality.js`, reads canonical R2, never infers complete):
    80 completed scans inspected · 80 R2 reports found · 0 missing · **2 parse
    failures left NULL** (legacy reports predating the `scan_quality` report field —
    the honest "cannot establish" set) · derived 38 complete / 31 partial / 9
    degraded / 0 explicit-unknown · **77 scans + 77 historical_scores updated** (1
    already-set: the controlled scan). **Second dry-run: 0 remaining updates.** Final
    D1: scans 38/31/9 + 2 NULL; historical 38/31/9 + 4 NULL (1 parse-failure
    completed scan + 3 orphan rows whose `scans` row was purged). No scan inferred
    complete without R2 evidence. (Note: the pre-merge estimate of "23 missing" was
    from a stale local run; production R2 actually holds all reports — the real
    leave-NULL count is 2.)
  - **Fixture proofs (live, post-backfill):** `scan_5e51158e` → scan_quality=partial,
    provisional=true, authoritative=false, comparable=false, **no rating**;
    `scan_50cabd4d` → scan_quality=complete, authoritative-eligible, rating=Good.
  - **Authoritative posture proofs (live APIs):** BBB workspace — Executive Dashboard
    + Scorecard both report authoritative **87/Good** from the newest **complete**
    scan; newer partials present but never chosen (Dashboard first-complete selection
    == backend selector, MATCH). SSO-test workspace (only a partial-95 scan) —
    `not_established`, provisional 95, **display_rating null**, "Current posture not
    yet established." Executive-workspace PDF: BBB "Cyber Posture: 87 / 100 — Good";
    SSO "Not yet established" (no "Excellent"). Scan-report PDF: partial → "Provisional
    Score" + caveat, complete → "Good". Workspace-detail API: BBB posture 87/good,
    SSO not-established/null rating.
  - **Alert suppression proof:** **0** score-drop `notification_events` since deploy
    (the only such event, "-25 points" at 2026-07-13 18:48, predates the fix and is
    itself an artifact of the old bug — a 70-partial following a 95-complete).
  - **Divergent-consumer audit (during rollout):** two surfaces initially still
    rendered a partial as a clean rating and were fixed before release — the
    executive-workspace PDF (`190e6b8`) and the workspace-detail Cyber Score
    (`2f6dd72`). Audited-clean: scorecard PDF, portfolio customer rating, and
    workspace-insights are already complete-only; ASM 30-day averages are score-only
    (no rating).
  - **Rollout order (race-safe):** migration 080 applied → **Worker deployed** (so
    the code that writes `scan_quality` was live before any backfill) → controlled
    scan parity proof → backfill dry-run → apply → second dry-run (0 remaining).
  - **D1/R2 consistency model:** R2 is the canonical finalized report artifact; D1
    normally persists the same `scan_quality` during finalization; the two may
    temporarily diverge after a partial persistence failure; a NULL D1 value is
    treated as unknown / non-authoritative / non-comparable (fail-safe); the
    stuck-scan reconciler converges D1 from the canonical R2 report. Divergence is
    possible, not impossible — the failure-path test asserts a NULL D1 stays
    non-authoritative and is restored from R2.
  - **Tests:** `validate-partial-scan-honesty.js` (56, drives real worker.fetch),
    `validate-canonical-presentation-parity.js` (32, static contract),
    `validate-posture-events.js` (17, complete baseline), portfolio 39/39, migrations
    guard 90/90, tenant-isolation, error-contract, regression, frontend
    typecheck/build, `wrangler --dry-run` — all green. Two new suites added to CI.
  - **Deployed Worker Version ID:** `7eb57f71-c27a-4f0d-83cb-0983588f8b52`
    (intermediate release deploys: `10f66998` post-merge, `8d91a9ab` exec-PDF fix).
  - **Rollback Version ID:** `c1dd9175-150a-40c0-8f1c-06d97c84bde8`.
  - **Residual:** the portfolio overview "Avg Score" StatCard (`portfolio.js:262`)
    is a bare number (no rating) computed via the shared latest-scan CTE that also
    feeds critical-finding counts; left as-is to avoid changing finding aggregation —
    tightening it to complete-only is a low-priority consistency follow-up.

## 2026.07.14 (v2026.07.14-4 — workspace-scoped domain verification + scan-start gate) — deployed 2026-07-14

### Fix (security beta-blocker — scans required workspace-level proof of control)
- **Workspace-scoped domain verification + hard scan-start gate** (PR **#62**, merge
  **5554bd5eedc64271f8b4bc244553d3b196145905**).
  - **Root cause:** scan-start had no verification guard; verification was advisory
    and domain-global-per-user, so a workspace could scan a domain it never proved
    control of (found via the external Microsoft SSO onboarding test —
    scan_5e51158e on the unverified domain_3fe1e1a2).
  - **Fix:** migration **079** adds verification columns to `workspace_domains` (per
    workspace-domain link; additive, no DROP). A fail-closed gate on `POST /api/scan`
    and `triggerScheduledScan` rejects/skips unless the exact (workspace_id,
    domain_id) link is verified → `403 {error:"domain_verification_required",
    message:"Verify domain ownership before starting a Cyber MOT."}` with no scan
    row / R2 placeholder / telemetry / case / report. Verification lifecycle is now
    workspace-explicit (token + status on the link); legacy domains.verification_*
    is read-only compat, never a scan gate. Scheduled scans only skip + log (no
    config mutation).
  - **Migration 079 result (remote D1):** 6 columns added; link count unchanged
    (24); backfill promoted exactly **3** verified-domain links (21 unverified;
    0 miss; 0 unrelated). Canonical BBB link (workspace_8f4e7bd1 / domain_2ba2cce0)
    → **verified** (verified_at 2026-06-23 preserved); SSO test link
    (workspace_35e25fc5 / domain_3fe1e1a2) → **unverified**. No row deleted.
  - **Tests:** scripts/validate-domain-verification-gate.js (34 assertions);
    migrations guard 89/89; tenant-isolation + SSO-linking-guard + error-contract +
    regression + frontend typecheck/build green.
  - **Production smoke:** unauth `/api/scan` → 401; SSO test workspace unchanged
    (no new scan); SSO link unverified → gate 403; canonical BBB link verified →
    eligible (side-effect-free); scheduled configs intact (3 total / 2 enabled).
  - **Authenticated production confirmation (2026-07-14):** a real authenticated
    SSO-test-session Scan Now against the unverified workspace-domain
    (workspace_35e25fc5 / domain_3fe1e1a2) returned **HTTP 403
    `domain_verification_required`** with the exact message "Verify domain ownership
    before starting a Cyber MOT." Zero side-effects verified against a locked
    baseline: scans 1→1, telemetry 14→14, managed cases 0→0, workspace reports 0→0;
    no new scan row, R2 placeholder, report, telemetry or case. Verification
    remediation episode CLOSED.
  - **Deployed Worker Version ID:** `c1dd9175-150a-40c0-8f1c-06d97c84bde8`.
  - **Rollback Version ID:** `e6604068-837f-47cb-b98b-772c368eaaff`.

## 2026.07.14 (v2026.07.14-3 — portfolio entitlement consistency + deterministic latest-scan) — deployed 2026-07-14

### Fix (packaging + correctness — MSP Portfolio hardening)
- **Gate all six /api/portfolio/* endpoints on the existing portfolio_monitoring
  entitlement + deterministic latest-scan selection** (PR **#61**, merge
  **cc5119cf141865806928d5fea803c4764f530b40**).
  - **Entitlement consistency:** Portfolio is a Business+/MSP feature, but only
    `/risk` enforced `portfolio_monitoring`; `/overview`, `/workspaces`, `/alerts`,
    `/trends`, `/executive-summary` were reachable by any authenticated Free/Starter/
    Growth user. All six now apply the SAME gate (shared helper reusing
    `getEffectivePlan` + `hasFeatureEntitlement`, identical 403 shape). No new
    entitlement/plan/route/pricing rule. Self-scoping + cross-MSP isolation unchanged.
  - **Deterministic latest-scan tie-break:** shared `LATEST_SCAN_CTE` ranks completed
    scans by `(created_at DESC, id DESC)` and takes `rn=1`, so two completed scans
    sharing an identical `created_at` can no longer both match and double-count a
    domain. Applied to all 5 CTEs across `routes/portfolio.js` + `engines/portfolio-customers.js`.
  - **Sanitized /risk error handling:** replaced the raw `{ error:'Internal server
    error' }` 500 with the shared `serverError("api", err)` path used by the other five.
  - **Tests:** `validate-portfolio.js` **39/39** (was 21) — Free→403 on all six,
    Business/MSP→200 on all six, historical critical from an older scan excluded,
    identical-timestamp scans don't duplicate a domain, cross-MSP isolation passes,
    never-scanned customer honest (null score, not fake 0).
  - **Live verification:** all six endpoints 401 unauthenticated; live BBB data
    (10 completed scans) surfaces only the latest scan `scan_50cabd4d`; 0 identical-
    timestamp collisions in production.
  - **Deployed Worker Version ID:** `41da2a9d-402a-4de1-b2e6-90496ac1b122`.
  - **Rollback Version ID:** `1fe26e1b-2f29-420a-971c-97284fc418b3`.
  - **No migration / schema / DDL change** — code + query + test only.

## 2026.07.14 (v2026.07.14-2 — executive report latest-scan scoping) — deployed 2026-07-14

### Fix (customer trust — executive report no longer piles up historical findings)
- **Scope executive-report findings + recommendations to the latest completed scan**
  (PR **#60**, merge **0918275**).
  - **Root cause:** `GET /api/workspaces/:id/report` (`routes/portfolio.js`) queried
    findings and recommendations with only `WHERE wd.workspace_id = ?` — no
    latest-scan scope — so every historical scan's rows piled up. A real Black Bull
    Barbers PDF rendered one "HTTPS Not Available" finding (from 4 old scans) as
    **CRITICAL (4)** and one "DMARC p=none" (from 9 scans) as nine MEDIUM rows, and
    resurfaced an HTTPS issue already resolved by the latest scan. The parallel
    `collectPdfData` path already scoped correctly (8ccebb2); this route did not.
  - **Fix:** extracted the proven latest-completed-scan-per-domain scope into
    `engines/report-queries.js` (`REPORT_FINDINGS_SQL` / `REPORT_RECOMMENDATIONS_SQL`,
    shared so both PDF paths agree) and used it in `portfolio.js`. Read-only query
    change — **no schema, no migration, no rendering change.**
  - **Regression:** `scripts/validate-report-findings-scoping.js` (16 assertions,
    incl. a negative control reproducing the ×4-HTTPS / ×5-DMARC pile-up).
  - **Live verification** — regenerated BBB report data from the deployed endpoint
    queries, every row sourced from scan
    **`scan_50cabd4d-ee1e-4589-91ee-619935ae346b`**: **0 critical, 3 medium**
    (DMARC p=none ×1, Sensitive Subdomain ×1, Admin Interface ×1), **0 "HTTPS Not
    Available"**, **no duplicate recommendations** (Strengthen DMARC / Review
    Sensitive Subdomains / Restrict Administrative Interfaces). Findings section,
    severity summary and recommendations all derive from the same canonical set.
  - **Deployed Worker Version ID:** `1fe26e1b-2f29-420a-971c-97284fc418b3`.
  - **Rollback Version ID:** `94980ffb-fe4d-4680-bccf-7c6919b65f43`.
  - **No migration applied.**

## 2026.07.14 (v2026.07.14-1 — scan waitUntil-cancellation reliability) — deployed 2026-07-14

### Fix (reliability — orphaned scans from ctx.waitUntil() background cancellation)
- **Global scan deadline + durable finalization + honest partial** (PR **#59**,
  merge **7ff3fbafcd** — commits `fd8c13d`, `19d6e1d`, `73f23d5`, `990df1b`).
  - **Root cause (proven, not CPU):** the scan engine runs inside `ctx.waitUntil()`,
    which Cloudflare cancels ~30s after the response is sent. Invocation record:
    `wallTime 31170ms / cpuTime 40ms / outcome "ok"` + log *"waitUntil() tasks did not
    complete within the allowed time after invocation end and have been cancelled."*
    Silent (no exception → no catch → no failed report) → scan stuck `status='running'`.
  - **Fix (additive/reversible; mode stays legacy, reserved off):**
    - **Deadline** (`createScanDeadline`, default **21000ms**, clamped 5000–24000):
      network phases stop launching before the ~30s cliff, reserving ≥6s for finalization.
    - **Bounded execution** (`raceModuleDeadline`): takeover, asset exposure, the Phase‑5
      trio and cloud-storage are hard-bounded to the remaining budget (canRun only gated
      the *start*); on the bound they defer honestly and the late promise is abandoned
      (no persistence, cannot mutate finalized state).
    - **Durable tri-state finalize** (`open→finalizing→finalized`): terminal only after
      both R2 report + D1 status are durable; individually guarded, never throws,
      re-entrant, downgrade-safe. A completed D1 status is never written over the running
      placeholder; a failed terminal is always written → a scan is never silently running.
      Closes the pre-fix orphan/downgrade hazard.
    - **Honest partial:** deadline-deferred modules `incomplete:true` → `scan_quality:partial`.
    - **KEV cache:** CISA catalogue cached in R2 (24h TTL, honest degrade); CT hard cap 25s→15s.
    - **Diagnosability:** heartbeat (`scans.last_heartbeat_at/current_stage/completed_modules`)
      + `scan_module_telemetry` (migration **078**, additive; purge-covered).
  - **Tests:** `validate-scan-deadline.js` (90, incl. failure-injection),
    `validate-kev-cache.js` (31), `validate-scan-telemetry.js` (36); full suite green.
  - **Migration 078** applied to remote D1 and verified (3 nullable columns + telemetry table + index).
  - **Deployed Worker Version ID:** `94980ffb-fe4d-4680-bccf-7c6919b65f43`.
  - **Rollback Version ID:** `a4f6fc4a-571b-4130-93c2-8424152b1c82` (prior live).

## 2026.07.13 (v2026.07.13-17 — exposure probe honesty: not-checked ≠ clean) — deployed 2026-07-13

### Fix (customer trust — unchecked exposure never presented as a clean result)
- **Report subrequest-starved exposure probes as not-checked, not `reachable:false`**
  (PR **#56**, commit **565fcccac90f510a363ef21c710617a4dc2d9559**).
  - **Root cause:** when a scan exhausts the Worker's per-invocation subrequest
    budget, every remaining `fetch` throws *"Too many subrequests by single Worker
    invocation."* `probeAsset` swallowed this into `reachable:false`.
  - **Customer risk:** an exposure probe that **never actually ran** appeared as a
    **confirmed-unreachable / falsely clean** result, and managed-case verification
    could resolve off a scan that never re-checked the exposure. (Proven long-standing:
    exposure has been budget-starved on every scan since the earliest 2026-07-06 report.)
  - **Fix (trust/semantic only — no capacity, order, estimator, resolver-count or
    architecture change):**
    - `probeAsset` distinguishes budget exhaustion from a genuine failure →
      `reachable:null, probe_status:"not_executed", reason:"subrequest_budget_exhausted"`.
      Genuine failures stay `reachable:false`; successful probes unchanged.
    - `runExposureModule` flags `incomplete:true` (+ reason + `not_executed_count`)
      and a customer-safe `notice` — never raw runtime error text.
    - `buildScanQuality` forces `scan_quality:"partial"` and lists the module in
      `modules_skipped`.
    - `moduleCompletionGate` (managed ASM) treats `incomplete` like `error`, so cases
      are **deferred, never resolved** off an unchecked scan.
  - **Regression test:** `scripts/validate-exposure-honesty.js` (22 assertions,
    negative-control verified) wired into CI. SSRF controls untouched.
  - **No migration / schema change** — pure code.
  - **Live validation** — scan **`scan_28901eca-4c95-4689-8856-d59ef241f9bd`**
    (blackbullbarbers.co.uk): all 5 hosts `reachable:null`,
    `probe_status:"not_executed"`, `reason:"subrequest_budget_exhausted"`;
    `asset_exposure.incomplete:true`; `scan_quality.status:"partial"`
    (`modules_skipped:["asset_exposure"]`); no falsely-clean "0 exposed assets".
  - **Not fixed here (separate queued workstream):** exposure probes are still
    starved — the *capacity* fix (reserve/reorder subrequest budget) is tracked as a
    separate design brief pending review. This release makes the starved state
    honest, not resolved.
- Deployed commit **565fcccac90f510a363ef21c710617a4dc2d9559**. Active version
  **33fe2a3f-f71f-44ed-a91b-b11208607b2a**. Rollback:
  **83dea0c7-80ea-4b04-97bd-70121b8e42b3** (v2026.07.13-16).

## 2026.07.13 (v2026.07.13-16 — headers-scan runtime binding fix) — deployed 2026-07-13

### Fix (scanner reliability — security-headers module restored)
- **Restore the HTTP security-headers scan module** (commits **b6467fb** fix +
  **0692da2** test). **Root cause:** the Phase-1c monolith extraction
  (`dd76969`, 2026-07-09) moved `runHeadersModule` into
  `engines/headers-scan.js` but left its `SECURITY_HEADERS` dependency as a
  private const in `scoring.js`. The extracted module referenced it as a bare
  free identifier — valid syntax (passes `node --check` and
  `wrangler --dry-run`) but a **runtime `ReferenceError: SECURITY_HEADERS is not
  defined`**.
  - **Customer impact:** the headers module **failed on every scan since
    2026-07-09** (all domains) — surfaced as "Headers module failed" and forced
    `scan_quality: partial`. HSTS/CSP/X-Frame-Options and related header findings
    were absent for ~4 days.
  - **Fix:** move `SECURITY_HEADERS` into a shared leaf module
    `engines/security-headers-config.js`, imported by both `scoring.js` and
    `headers-scan.js`. Leaf module (not `scoring.js`) avoids a cycle —
    `scoring.js` already imports `classifyHeaderStrength` from `headers-scan.js`.
    Single source of truth, no duplicate copies. **safeFetch/SSRF untouched.**
  - **Regression test:** `scripts/validate-security-headers-binding.js` executes
    `runHeadersModule` end-to-end (imported as its own ES module, as esbuild
    bundles it) so a missing/renamed cross-module binding throws instead of being
    swallowed. Negative-control verified (reverting the fix fails 10/14). Wired
    into CI.
  - **No migration / no schema change** — pure code.
  - **Live validation:** headers module returned **`accessible:true`,
    `status_code:200`** on scan
    **`scan_2eb60973-0873-449c-9610-dd22d317b4e0`** (blackbullbarbers.co.uk).
- Deployed commit **0692da2165decb46e92e8af4f8c776a84bc5e010**. Active version
  **83dea0c7-80ea-4b04-97bd-70121b8e42b3**. Rollback:
  **45b9cd68-7bc8-4b55-b1b8-bebb0ff802c8** (v2026.07.13-15).

## 2026.07.13 (v2026.07.13-15 — Certificates & Trust L2 guided intelligence) — deployed 2026-07-13

### Product (4-service managed maturity — Certificates & Trust: L1 → L2)
- **Certificates & Trust L2 Guided Trust Remediation** (PR #55, Codex built /
  Claude reviewed+integrated): honesty-first L2 over the existing CT-only
  inventory. New `engines/cert-trust-l2.js` (compute-on-read, **no migration**):
  - **Explainable findings** — typed enum (expiring_soon/expired/self_signed/
    unexpected_issuer/unexpected_san/unexpected_wildcard/parallel_certificate/
    coverage_gap/ct_source_incomplete) with evidence + reasons + confidence.
    **Forbidden fabricated types (weak_key/weak_signature/untrusted_chain/revoked)
    are never emitted** (harness-locked).
  - **Renewal readiness** — status + days + `auto_renew_observed` derived from CT
    reissue history (observational; never claims *configured* auto-renew) + CA
    provider + blockers + actions.
  - **Honest trust-path** — HTTPS/redirect/HSTS/expiry from observable evidence;
    **chain_valid / root_trusted / OCSP stay `"unknown"`** (require a live TLS
    handshake CyberMeters does not perform). Replaces the frontend's misleading
    `valid ?? chain_valid` "Secure/Broken" boolean + the always-0 "Broken HTTPS"
    stat with a truthful posture.
  - **Anomalies** — unexpected issuer/SAN/wildcard/parallel-certificate from the
    `certificate_observations` history + existing cert `asset_events`.
  - Route `GET /api/workspaces/:id/certificates` extended additively; tenant-scoped
    (foreign → 403, harness-locked). `validate-cert-trust-l2.js`.
  - **Out of scope (unchanged):** external TLS prober, managed renewal, deployment
    verification, edge consistency, revocation automation, private-key handling —
    all remain a future L3 epic. Never presents a CT-observed cert as live
    deployment; unsupported TLS fields stay `"unknown"`.
  - **Positioning:** "Guided certificate & trust remediation" (NOT "managed").
- Live version **45b9cd68-7bc8-4b55-b1b8-bebb0ff802c8**. Rollback:
  **b4597747-9ba2-474b-91dd-9efcd003a2b4**.

## 2026.07.13 (v2026.07.13-14 — Managed Brand Protection v1) — deployed 2026-07-13

### Product (4-service managed maturity — Epic 3: Brand becomes managed)
- **Managed Brand Protection v1 — takedown lifecycle** (PR #50, Codex built /
  Claude reviewed×3+integrated): Brand is the shared Managed Case Platform's
  second consumer (`case_type='brand_abuse'` on `managed_cases`, reusing
  `case-workflow.js` — no new engine). A registered, high-risk impersonation
  candidate becomes a governed takedown case: detected → triage → confirmed_abuse
  → customer_approval → evidence_ready → takedown_submitted → provider_followup →
  verification_pending → resolved (+ false_positive/duplicate/provider_no_response/
  escalated/reappeared/closed).
  - **Registration-reality gate:** a case opens only for a *registered/active*
    candidate at risk_level high/critical — never an unregistered permutation
    (watchlist only).
  - **No-self-resolve:** resolved/reappeared/provider_no_response are
    system-only; a customer/analyst cannot self-mark removal.
  - **Immutable evidence bundles:** new `brand_evidence_bundles` table — INSERT-only,
    versioned (`UNIQUE(ws,case,version)`, atomic in-SQL MAX+1 + retry), canonically
    hashed (sorted-key JSON → SHA-256), append-only; `managed_cases.evidence_json`
    holds only the `{latest_evidence_bundle_id, latest_evidence_version}` pointer.
    Submissions bind an exact bundle id+version+hash.
  - **Technical verification only:** the hourly `brand_takedown_followup` sweep
    resolves a case solely when CyberMeters re-observes the abusive domain gone
    (DNS+MX); an incomplete probe **defers**, never false-resolves. Reappearance
    links a `brand_abuse_campaigns` row + system-reopens.
  - Additive migration 077 (`brand_abuse_campaigns` + `brand_evidence_bundles`),
    both added to `WORKSPACE_PURGE_TABLES` before the parent case. Routes
    tenant-scoped + manage/read-gated. `validate-brand-takedown-lifecycle.js` (25,
    incl. append-only + prior-version-preserved + concurrent-capture no-loss).
  - **Positioning:** NOT "Managed Brand Protection" until the live DoD pilot
    passes — until then "Brand abuse detection with guided takedown preparation".
- Live version **b4597747-9ba2-474b-91dd-9efcd003a2b4**. Rollback:
  **4eab3458-1970-4039-9292-c8fde85cde38**.

## 2026.07.13 (v2026.07.13-13 — CI defense-in-depth locks) — deployed 2026-07-13

### Security (public-beta P0 #5 + #4 — regression locks, both surfaces already safe)
- **R2 report ownership lock** (PR #54): `validate-tenant-isolation.js` now
  exercises the scan-report R2 endpoints — a ws1-owned scan's report object
  carries a marker; foreign/non-member/anon are asserted refused on `/report`,
  `/report/pdf`, `/executive-report-v2` (no leak) with an owner positive control.
  Locks `requireScanReadAccess` + workspace-scoped `report_key`. 72/72.
- **Digest escaper unification** (PR #54): `weekly-digest.js` now uses the
  canonical `escapeEmailHtml` (quote-safe) instead of a local `&<>`-only `esc` —
  future-proofs against attribute-context interpolation. Behaviour-equivalent.
  No migration.
- Live version **4eab3458-1970-4039-9292-c8fde85cde38**. Rollback:
  **98ab6f36-f930-4f47-9455-95f07fa545a7**.

## 2026.07.13 (v2026.07.13-12 — SSO nOAuth hardening) — deployed 2026-07-13

### Security (public-beta P0 #6 — from the pre-beta audit)
- **Microsoft SSO email-linking gated to single-tenant** (PR #53): the callback
  auto-linked an incoming Microsoft identity to an existing local account by
  email (and auto-verified it) — safe only when the email claim is trustworthy.
  Extracted `isSingleTenantConfig(tenantId)`; the email-based auto-link + verify
  now runs ONLY under a single-tenant config (org-controlled email + enforced
  tid). Under a multi-tenant alias the link is skipped, closing the nOAuth
  account-takeover footgun before it can ship. **Behaviour-preserving for the
  live single-tenant config** (AZURE_TENANT_ID is a specific GUID → already not
  exploitable; tid was enforced). Founder-approved HIGH-risk auth change. No
  migration. `validate-sso-linking-guard.js` (13). Login-initiation verified live
  (still redirects to the single-tenant authorize URL).
- Live version **98ab6f36-f930-4f47-9455-95f07fa545a7**. Rollback:
  **eea81821-d43c-4a7c-97e3-285869954f88**.

## 2026.07.13 (v2026.07.13-11 — SSRF scan-fetch hardening) — deployed 2026-07-13

### Security (public-beta P0 #3a — from the pre-beta audit)
- **SSRF-hardened scan fetches** (PR #52): the string input-gate only vetted the
  initial user string; two vectors were mitigated only by the Cloudflare egress
  backstop. `safeFetch` is now SSRF-aware at the single choke point every scan
  module routes through — it validates the host on every hop and follows
  redirects **manually**, refusing a mid-chain internal target (redirect-time
  SSRF). New `lib/ssrf.js` classifier + `resolvesToPrivateIp` (A+AAAA,
  fail-open); free-scan resolves the target and refuses private/reserved IPs at
  the door (A-record SSRF). Behaviour-preserving for legit scans. No migration.
  `validate-ssrf-scan-guard.js` (45). **Production-verified:** `example.com`
  scans normally (4 modules, score 95); `localtest.me` (→127.0.0.1) and
  `10-0-0-1.nip.io` (→10.0.0.1) are refused (400).
- Live version **eea81821-d43c-4a7c-97e3-285869954f88**. Rollback:
  **56e0b5f0-0005-415c-8f5e-95bbcfe53295**.

## 2026.07.13 (v2026.07.13-10 — P0 scheduled-scan burst cap + free-scan backstop) — deployed 2026-07-13

### Ops / security (public-beta P0 hardening — from the pre-beta audit)
- **Scheduled-scan subrequest burst cap (#8)** (PR #51): the per-tick `LIMIT`
  capped schedule count, but all due scans ran concurrently in one invocation
  sharing the 1,000-subrequest budget — ~8-15 rich-domain schedules in a tick
  could blow it. Added a bounded worker pool (`SCHEDULED_SCAN_CONCURRENCY=3`) so
  peak fan-out stays well under 1,000, plus a named per-tick cap
  (`SCHEDULED_SCAN_MAX_PER_TICK=12`). Fairness (oldest-due-first) preserved;
  per-item failures isolated. `validate-cron.js` locks peak concurrency ≤ cap +
  isolation (25→31).
- **Free-scan global backstop (#3b)** (PR #51): `/api/free-scan` was throttled
  per-IP only (5/hr); a botnet spreading across IPs had no aggregate ceiling.
  Added a fail-closed global cap (500/hr) independent of source IP. No migration.
- Live version **56e0b5f0-0005-415c-8f5e-95bbcfe53295**. Rollback:
  **03e84d63-8767-4ba3-944b-56feb0297bd3**.

## 2026.07.13 (v2026.07.13-9 — ASM verification completeness guard) — deployed 2026-07-13

### Product (Managed ASM — verification honesty hardening)
- **Scan-completeness guard** (PR #49): closes the known limitation from v...-8.
  Verification treated a finding absent from the latest scan as "resolved", so a
  silently-failed / timed-out / skipped scan module could false-resolve a case
  (absence of a finding it never looked for). `verifyManagedAsmCasesForScan` now
  consumes the scan's `{ modules, scanQuality }`: if the exposure's own module
  errored/timed-out/was-skipped, or the whole scan came back `partial` (a core
  module broke), the case is **deferred** (left awaiting verification with a
  `verification_deferred` timeline event, retried next complete scan) — never
  resolved off incomplete evidence. Only explicitly-signalled incompleteness
  gates, so the happy path never regresses; legacy callers unchanged. No
  migration. `validate-asm-remediation-loop.js` 22/22.
- Live version **03e84d63-8767-4ba3-944b-56feb0297bd3**. Rollback:
  **85486b4a-a104-4337-8254-de300aa3fb42**.

## 2026.07.13 (v2026.07.13-8 — Managed Case Platform v1 + ASM remediation loop) — deployed 2026-07-13

### Product (4-service managed maturity — Epic 1: Attack Surface goes managed)
- **Managed Case Platform v1 + Managed ASM remediation loop** (PR #48, Codex built /
  Claude reviewed+fixed+integrated): the first generic managed-case platform, with Attack
  Surface as its first consumer. A new external exposure becomes a governed case that is
  owned, remediated by the customer, **independently re-verified by CyberMeters against a
  fresh scan**, resolved only when the exposure is actually gone, and **auto-reopened if it
  returns** — full tenant-scoped audit trail.
  - Generic `engines/case-workflow.js` — a pure, domain-agnostic, parameterised state-machine
    runner + reusable guard helpers. Proven against both the ASM graph and (in tests) the DMARC
    graph, without touching the shipped DMARC workflow.
  - `engines/asm-cases.js` — ASM machine (open→triage→owner_assigned→remediation_in_progress→
    verification_requested→verifying→resolved, + risk_accepted-with-expiry / verification_failed /
    reopened / false_positive). Case creation + verification hook rides the existing scan re-probe
    (no parallel prober); anchored on the stable `finding_id`; respects `finding_waivers`.
    Risk-acceptance now carries a mandatory expiry (closes the waiver-no-expiry gap).
  - Migration 076 (additive): `managed_cases` + `managed_case_events` + `audit_events.actor_type`
    column; both new tables added to the workspace-purge list.
  - Routes under `/api/workspaces/:id/managed-cases` (list/detail/assign/transition); Managed
    Cases panel on the Attack Surface page.
  - **Review fix (Claude):** the customer transition route could drive verification-outcome
    states (verifying/resolved/verification_failed/reopened). Locked those to CyberMeters'
    system verification only (`SYSTEM_ONLY_CASE_STATES`) — a customer can no longer self-mark
    an exposure "resolved"/"verified", preserving the independent-verification promise.
  - Validation: `validate-managed-case-workflow.js`, `validate-asm-remediation-loop.js` (18,
    incl. the DoD scenario + self-resolve-blocked assertions), tenant-isolation extended,
    regression 227/227, migrations, pipeline, cron, frontend build, wrangler dry-run all green.
  - **Known limitation / fast-follow:** verification treats a finding absent from the latest
    scan as resolved; a silently-failed scan module could transiently false-resolve, but
    auto-reopen self-corrects on the next complete scan. A scan-completeness guard is the
    follow-up. Positioning "Managed exposure remediation with independent fix verification"
    holds once the DoD scenario is exercised live.
- Live version **85486b4a-a104-4337-8254-de300aa3fb42**. Rollback:
  **ab6c2b64-d56a-4e2d-8503-75225b83bb88**.

## 2026.07.13 (v2026.07.13-7 — managed DMARC change workflow, Level 3) — deployed 2026-07-13

### Product (DMARC managed maturity — scorecard epic #7, final / Level 3)
- **Managed change-workflow state machine + analyst review queue** (PR #47): the
  human-in-the-loop governance layer that turns a proposed managed-policy change
  into a reviewable request an analyst must approve before it executes — the last
  piece for honest "Managed DMARC" positioning. `engines/dmarc-change-workflow.js`
  is a pure, guarded state machine (draft → pending_review → approved → scheduled
  → applying → verifying → completed, plus rejected/rolled_back/cancelled). Guards
  enforce **separation of duties** (approver ≠ requester), a required reason on
  reject/rollback, a required time on schedule, and terminal immutability;
  `buildChangeReviewQueue` surfaces pending items FIFO with an age. Routes
  (GET/POST `/dmarc/change-requests`, POST `.../:id/transition`) are tenant-scoped,
  manage-role gated and audit-logged; the frontend `ChangeReviewQueue` panel lets
  an analyst approve/reject with a reason. **Purely additive** — the autopilot /
  manual policy path is untouched; routing a change through the queue is opt-in.
- **Migration 075** (`dmarc_change_requests`, additive CREATE TABLE) applied to
  remote D1 before deploy; added to the workspace-purge table list.
  `validate-dmarc-change-workflow.js` (31) proves the state machine, guards,
  queue and a tenant-scoped DB round-trip; regression 227/227.
- Live version **ab6c2b64-d56a-4e2d-8503-75225b83bb88**. Rollback:
  **bf91cbf8-9a58-4123-91ed-6e80ec132e75**.

## 2026.07.13 (v2026.07.13-6 — enforcement readiness v2) — deployed 2026-07-13

### Product (DMARC managed maturity — scorecard epic #6)
- **Unified enforcement readiness (v2)** (PR #46): the customer DMARC summary and
  the hosted autopilot each answered "are we ready to tighten DMARC?" with a
  different vocabulary and different thresholds. Now unified behind one
  explainable model — `buildEnforcementReadinessChecks` produces a 7-check
  evidence set (pass-rate, sender alignment, active-threats, reporting window,
  sender classification, volume, soak time) → weighted numeric **score** (0-100)
  → tri-state **status** (ready / approaching / not_ready). A single hard fail
  (alignment failure or active impersonation threat) can never sit inside a
  "ready" verdict. `buildDmarcEnforcementReadiness` merges `{status, score,
  checks}` onto its return **alongside** every legacy milestone key (unchanged —
  no consumer regresses). Frontend readiness card now shows the score/status
  pill + the 7-check green/amber/red breakdown. No migration.
  `validate-enforcement-readiness-v2.js` (28) proves legacy and v2 verdicts
  agree on healthy and unhealthy domains.
- Live version **bf91cbf8-9a58-4123-91ed-6e80ec132e75**. Rollback:
  **2ce0bab7-a4ed-4a11-9506-a42711425b8d**.

## 2026.07.13 (v2026.07.13-5 — DMARC graduated reject ramp) — deployed 2026-07-13

### Product (DMARC managed maturity — scorecard epic #5)
- **Graduated reject ramp + per-tag diff + configurable thresholds** (PR #45):
  the riskiest managed transition — quarantine→reject — no longer jumps to full
  enforcement. `DMARC_RAMP_LADDER` now percentage-ramps reject (10→25→50→100), so
  a misclassified legitimate sender surfaces on a small slice before full reject;
  `dmarcRampStepIndex` snaps off-ladder values **down** (never overstates
  progress). `dmarcTagDiff` renders a policy change as `p: none→reject,
  pct: null→10` (surfaced as `pending_diff`/`next_step_diff`), never a blind
  overwrite. `resolveRampThresholds(env)` makes ramp/rollback gating tunable per
  environment (min messages / pass-rate / soak days / rollback drop pp / rollback
  min messages) with safe fallback to the constants — threaded through the
  autopilot sweep and both route call sites. Frontend ladder track 6→9 steps.
  Both live records sit at `p=none` (index 0) — unaffected. No migration.
  `validate-dmarc-graduated-ramp.js` (27); regression 227/227. Deployed under the
  standing MEDIUM-risk delegation.
- Live version **2ce0bab7-a4ed-4a11-9506-a42711425b8d**. Rollback:
  **5d39290b-2914-48c5-9df1-0cf6df17f91e**.

## 2026.07.13 (v2026.07.13-4 — DMARC operational alerts) — deployed 2026-07-13

### Product (DMARC managed maturity — scorecard epic #3)
- **DMARC operational alerts** (PR #43): a new hourly `dmarc_alerts_sweep` turns
  classified sender data into actionable notifications through the existing
  pipeline (in-app bell + workspace alert channels) — `dmarc_new_sender` (a new,
  high-volume, not-yet-recognised source) and `dmarc_spoofing_spike` (an
  `unauthorised` source failing auth at volume while claiming the domain).
  Read-only, deduped (24h), tenant-scoped; the manual sender override wins
  (a trusted-override suppresses the alert). No migration. `validate-dmarc-alerts.js`
  (10). Complements epic #2's `hosted_dmarc_impact_regression` and the hosted
  lifecycle alerts. First deploy under the standing MEDIUM-risk delegation.
- Live version **5d39290b-2914-48c5-9df1-0cf6df17f91e**. Rollback:
  **0121ecbe-bb3d-4c0c-9f4c-6f612326cca9**.

## 2026.07.13 (v2026.07.13-3 — DMARC impact forecast + post-change monitor) — deployed 2026-07-13

### Product (DMARC managed maturity — scorecard epic #2)
- **DMARC policy impact forecast + post-change monitor** (PR #42): quantifies what
  a policy change would do, using epic #1's classification to separate legitimate
  mail from spoofing. `engines/dmarc-impact.js`:
  - `forecastPolicyImpact` — before a change: affected messages / %, a
    **legitimate-affected** breakdown + a "who gets hurt" sender list, and
    risky-affected (mail you want to block). `insufficient_data` on thin windows.
  - `comparePolicyImpact` — before/after a change (windowed by the report's
    `date_range_begin`, not ingest time): legitimate-failed-rate delta.
  - `assessImpactRollback` — recommends review when the legitimate failed-mail rate
    rises > 2pp. **Recommend-only:** the sweep emits an audit event +
    `hosted_dmarc_impact_regression` notification (the first real DMARC operational
    alert); it never auto-rolls-back and leaves the conservative `shouldAutoRollback`
    untouched (blast-radius safety — never break mail flow).
  - Respects the manual sender override (`classified_at` wins). **No migration**
    (on-demand from existing aggregate + sender tables). Tenant-isolated (joins
    enforce `workspace_id`). `validate-dmarc-impact.js` (15).
- Live version **0121ecbe-bb3d-4c0c-9f4c-6f612326cca9**; hosted-dmarc path verified.
  Rollback: **fbd1e3a3-34dc-4a56-9b79-e79a334fdf0a**.

## 2026.07.13 (v2026.07.13-2 — Automated sender classification) — deployed 2026-07-13

### Product (DMARC managed maturity — scorecard gap #1)
- **Automated evidence-based sender classification** (PR #40): turns the manual
  sender triage into an automated, explainable verdict per DMARC sender from
  evidence we already parse — per-method SPF/DKIM alignment, provider, volume,
  pass-rate. Taxonomy: authorised | likely_authorised | forwarder | mailing_list
  | misconfigured | unknown | suspicious | unauthorised, each with a confidence
  and human-readable reasons.
  - **The manual override stays sacred**: the engine writes only new `auto_*`
    columns; `classification`/`notes` are never touched and the manual decision
    still wins and persists across re-ingests. The API exposes both with a
    `classification_source` (manual|auto) and an effective classification.
  - **Honest confidence**: `mailing_list` requires a recognised list provider (not
    inferred from aggregate data), `forwarder` requires the real DKIM-pass/SPF-fail
    signature, and weak/low-volume evidence returns `unknown` — never a
    high-confidence guess.
  - Migration **074** additive (7 `ADD COLUMN`s incl. per-method alignment counts +
    `provider_map_version`). `validate-sender-classification.js` (30) proves the
    full taxonomy, the manual-override invariant across re-ingest, honest
    low-evidence handling, and tenant isolation of the DMARC sender surface.
- Live version **fbd1e3a3-34dc-4a56-9b79-e79a334fdf0a**; email-senders API path
  verified, hosted-dmarc unaffected. Rollback:
  **a6ff57eb-f8f4-48fb-a760-61d83b9359a5**.

## 2026.07.13 (v2026.07.13-1 — Auth rate-limit hardening) — deployed 2026-07-13

### Security (P0 pre-public-beta hardening — see docs/P0-PUBLIC-BETA-BLOCKERS.md)
- **Per-account login lockout** (PR #38 #1): login was throttled per-IP only, so a
  DISTRIBUTED attack (many IPs, one account) had no per-account ceiling. Added a
  per-account consume (20 / 15 min, keyed on the normalised email, fail-closed)
  before any credential check. Generous threshold so real users never trip it;
  the short window bounds the account-lockout DoS inherent to any per-account
  throttle. `validate-pipeline.js` proves it (22 attempts from unique IPs → 21st
  is 429 while no single IP is over its own limit).
- **Fail-closed `scan_start`** (PR #38 #2): the scan-start burst limiter failed
  OPEN on D1 error, so under the exact D1 stress an attack causes an account could
  start unmetered (expensive, many-subrequest) scans. Now fail-closed — a brief
  503 + retry is safer than an unthrottled burst. (The coarse global read/write
  guard is deliberately left fail-open — defense-in-depth behind the fail-closed
  primary limiters; hard-closing it would 503 the whole API on any D1 blip.)
- No migration. pipeline 42/42, security-contracts, regression, integration green.
- Live version **a6ff57eb-f8f4-48fb-a760-61d83b9359a5** (health reports
  2026.07.13); login path verified (bogus creds → 401, no 5xx). Rollback:
  **c9a46eed-b9e0-46c0-8c5a-50c83d6f7960**.

## 2026.07.12 (v2026.07.12-9 — Guided-hybrid MTA-STS) — deployed 2026-07-12

### Product (Phase C — email wedge, on the hosted DNS v2 foundation)
- **Guided-hybrid MTA-STS** (PR #36): CyberMeters hosts + manages the
  `_mta-sts.<domain>` DNS TXT (policy id) via `record_kind='mtasts'` on
  `hosted_dns_entries`; generates a standards-compliant policy from the domain's
  **live MX**, pinned at creation. Deliberately **guided-hybrid, not full-hosted**
  — the customer/their web provider serves the HTTPS policy file at
  `https://mta-sts.<domain>/.well-known/mta-sts.txt` (full hosting via Cloudflare
  for SaaS custom hostnames is a separate post-beta packet).
  - Two **independent** verified states: DNS TXT (CNAME delegation, existing saga)
    and HTTPS policy (reachable + matches pinned content). UI says "MTA-STS active
    in testing mode" only when **both** are green — never "protected/hosted".
  - Strictly `mode: testing`; never auto-`enforce`. MX drift is surfaced ("review
    and republish"), never silently applied, and the DNS policy id is not bumped
    before the policy verifies. Explicit product boundary shown in the UI.
  - Migration **073** additive (`hosted_dns_entries.policy_content`). DMARC +
    TLS-RPT parity preserved. `validate-hosted-mta-sts.js` (36) covers every
    guardrail; regression 227/227 green.
- Live version **c9a46eed-b9e0-46c0-8c5a-50c83d6f7960**; new route 401 unauth,
  existing hosted-dmarc/tls-rpt routes intact. Rollback:
  **8fa4b19d-c681-4876-892a-e6bbc8873633**.

## 2026.07.12 (v2026.07.12-8 — Hosted DNS v2 + TLS-RPT hosting & ingestion) — deployed 2026-07-12

### Architecture (pre-revenue refactor + Phase C)
- **Hosted DNS v2 bounded context** (PR #34): `hosted_dns_records` was pinned by
  `CHECK (record_type IN ('dmarc'))` — Codex's audit caught it; widening a CHECK
  needs a `DROP TABLE` rebuild the additive-only guard rightly forbids. So the
  layer was redesigned additively as `hosted_dns_entries` — one table for
  DMARC/TLS-RPT/MTA-STS/SPF, **no CHECK** (enums in code → new kinds never need a
  migration). Migration **071** created it + **idempotent 1:1 backfill** of the
  live hosted DMARC row (verified: `_dmarc.cybermeters.com`, connected, mapped
  1:1). Engine + routes repointed via an aliased projection → **DMARC behaviour
  identical** (the 3 hosted-DMARC lifecycle contracts + regression 227/227 green).
  Old table retired-in-place (kept + still purged; no `DROP TABLE`).
- **TLS-RPT hosting** — new `record_kind='tlsrpt'`, no migration: `/hosted-tls-rpt`
  create/verify/delete via CNAME delegation (`_smtp._tls.<domain>`), reusing the
  domain's reporting mailbox. `validate-hosted-tls-rpt.js` (20).
- **TLS-RPT report ingestion** — migration **072** (`tlsrpt_aggregate_reports` +
  `tlsrpt_failure_details`, both purged); a **separate JSON parser**
  (`lib/tlsrpt-ingest.js`) — never the DMARC XML path; the inbound handler now
  **routes by attachment type** (TLS-RPT JSON → new path; DMARC XML unchanged).
  `GET /tls-rpt/reports` + a SMTP-TLS-delivery-health card. `validate-tlsrpt-ingest.js`
  (21, incl. real inbound routing end-to-end + no-regression).
- Migrations 071 + 072 applied to remote D1 (071 first — backfill). Live version
  **8fa4b19d-c681-4876-892a-e6bbc8873633**; health/ready 200, new + repointed
  routes 401 unauth. Rollback: **36f77bb0-3082-4854-9bab-72f3750d2741**.

## 2026.07.12 (v2026.07.12-7 — White-label report branding) — deployed 2026-07-12

### Product (Faz 1 — MSP wedge)
- **White-label report branding** (PR #29): MSPs on Business+ can put their own
  company name, logo, and accent colour on the reports they share with clients —
  the answer to "can I send the report with my own logo?" is now yes, **including
  a real logo image on the PDF**. Branding is account-level (`customer_profiles`,
  keyed by owner_user_id) so it applies to every customer workspace the MSP owns;
  OFF by default → existing reports unchanged.
  - `GET/PUT /api/account/report-branding` — Business `white_label` entitlement
    gate on switch-ON, requires a company profile (409), rejects api-token
    sessions, audited.
  - PDF logo image (`engines/pdf-image.js` + `assemblePdfWithImage`): JPEG via
    `/DCTDecode`; PNG inflated/de-filtered/alpha-flattened over the accent band
    and re-deflated as an 8-bit DeviceRGB XObject; SVG/WebP/CMYK → text-wordmark
    fallback (never throws). Header wordmark → logo/name, accent band, footer
    "Prepared by <MSP> | Powered by CyberMeters". Logo also rides the HTML exec
    report brand bar.
  - CI-blocking `validate-report-branding.js` (42) incl. PNG decode round-trip,
    JPEG passthrough, plan gating, company-profile requirement, cross-account
    isolation. Verified end-to-end with pypdf (valid PDF, `/Im0` Image XObject).
- **Migration 070** (`customer_profiles.brand_logo/brand_accent/report_white_label`,
  additive) applied to remote D1 before deploy; columns verified present.
- Also fixed a pre-existing time-of-day flake in `validate-pipeline.js` (cron
  task-set assertion now mirrors the 08:00-UTC ops-health + Monday weekly-digest
  tasks, not just 02:00 retention).
- Live version **36f77bb0-3082-4854-9bab-72f3750d2741**; report-branding endpoint
  401 unauth (sanitized). Rollback: previous version
  **99acf2bf-ae61-4d16-9947-76b96b60cddb**.

## 2026.07.12 (v2026.07.12-6 — Identity Exposure) — deployed 2026-07-12

### Product (Faz 0 — final bet)
- **Identity Exposure** (`7a1c594`,`104c6da`): consolidates three REAL, free,
  outside-in signals under "how can an attacker impersonate/steal/abuse your
  identity?" — exposed login surfaces (identity_assets), active impersonation
  infrastructure (resolving lookalikes that can send mail / host a login), and
  email spoofing (SPF/DMARC weakness = the #1 BEC threat, from the latest scan
  report). Overall Low/Medium/High level + plain-English summary. New
  GET /api/workspaces/:id/identity-exposure + an explanation-first card on the
  identity page. NO fake HIBP placeholder — HIBP breached-credentials is a
  genuine Faz 1 add. CI-blocking validate-identity-exposure.js (14) incl. tenant
  isolation. No migration.
- Live version **99acf2bf-ae61-4d16-9947-76b96b60cddb**; endpoint 401 unauth,
  /ready healthy, free-scan verified. Rollback: **77bd47ac-facb-46db-9b6c-47ef15e8657e**.

## 2026.07.12 (v2026.07.12-5 — MSP Portfolio: change-counts + exec summary) — deployed 2026-07-12

### Product (Faz 0 — MSP wedge)
- **MSP Portfolio sharpening** (`86067ca`): the "which customer needs attention
  today?" view now shows THIS WEEK'S Exposure-Timeline change counts per customer
  and factors new high/critical changes into the attention ranking (connecting the
  two Faz 0 bets). New `GET /api/portfolio/executive-summary` — portfolio-level
  posture spread + this week's movement + top-3 attention list + plain-English
  narrative the MSP can share. Per-customer logic extracted to a shared,
  unit-tested engine. New CI-blocking `validate-portfolio.js` (21) closes the
  previously-untested CROSS-MSP ISOLATION invariant (MSP A never sees MSP B's
  customers). No migration.
- Live version **77bd47ac-facb-46db-9b6c-47ef15e8657e**; new endpoints 401 unauth.
  Rollback: previous version **22ab9763-9d90-48f2-a7f0-4f87cb0935d6**.

## 2026.07.12 (v2026.07.12-4 — SSRF gate hardening) — deployed 2026-07-12

### Security (internal pentest, code-side)
- **SSRF domain-gate hardening** (`7a64a28`): `isValidDomain` (enforced before
  every scan AND the public free-scan) now also rejects reserved / private-use
  TLDs (internal/local/localhost/corp/lan/…). Closes a finding from the internal
  pentest: `metadata.google.internal` previously passed the alpha-TLD rule.
  Verified live — metadata + IP-literal targets rejected, legitimate domains
  unaffected. Locked by `validate-ssrf-domain-guard.js` (37) +
  `validate-dmarc-xml-safety.js` (18, XXE/DoS), both CI-blocking.
- Live version **22ab9763-9d90-48f2-a7f0-4f87cb0935d6**. Rollback: previous
  version **8e243e0b-5264-42c5-84d2-8e50ec9038d2**.

## 2026.07.12 (v2026.07.12-3 — weekly Exposure Timeline digest) — deployed 2026-07-12

### Product (Faz 0 — retention hook)
- **Weekly digest** (`4377c6e`): a Monday 08:00 UTC "what changed this week" email
  to active workspaces (verified owner + >=1 monitored domain), deduped once per
  ISO week, aggregating the last 7 days of exposure events (severity + category
  breakdown + top 5). Quiet weeks send a short "all quiet — posture stable"
  reassurance; dormant/unverified owners get nothing (protects deliverability).
  Completes the Exposure Timeline (change detection -> feed API -> UI -> digest) —
  the one-time-scan -> subscription hinge. No migration (reuses lifecycle_email_events).
- Live version **8e243e0b-5264-42c5-84d2-8e50ec9038d2**; /health 200, /ready d1+r2
  healthy, free-scan verified. Rollback: previous version **52281cb0-aadf-41ea-80b7-0eb2830b2954**.

## 2026.07.12 (v2026.07.12-2 — Exposure Timeline backend) — deployed 2026-07-12

### Product (Faz 0 — the subscription hinge)
- **Exposure Timeline change detection + feed** (`#26`,`#27`,`#28`): the platform
  now records what changed between scans — turning a one-time scan tool into a
  subscription product. New `asset_events` on top of the existing subdomain/cert
  diffs: DNS changes (IP / CNAME / redirect target, external redirect = high),
  email-auth changes (SPF record, DMARC policy weakened/strengthened, DKIM), and
  new/resolved internet-exposed services. Surfaced by a new enriched, filterable,
  paginated feed API `GET /api/workspaces/:id/exposure/feed` (category + severity
  + hostname + date filters), consumed by the upcoming Timeline UI + weekly digest.
  Fully test-covered (validate-exposure-events / -posture-events / -exposure-feed,
  all CI-blocking) and documented in OpenAPI (ExposureEvent schema). New events
  accrue on future scans, so deploying now starts building change history.
- Live version **52281cb0-aadf-41ea-80b7-0eb2830b2954**; `/health` 200,
  `/exposure/feed` 401 (auth enforced). Rollback: previous version
  **4d9898d4-d0e2-45c0-b77f-59842dff7a29**.

## 2026.07.12 (v2026.07.12-1 — planned maintenance mode) — deployed 2026-07-12

### Operations
- **Planned maintenance mode** (`17dc938`): `MAINTENANCE_MODE` var (off by
  default, fail-safe). When on, every API route returns the uniform
  `503 { code: "maintenance", message }` + `Retry-After: 300` — placed right
  after `/health` and `/ready` so monitoring stays reachable; `/health` reports a
  `maintenance` flag. `MAINTENANCE_BYPASS_TOKEN` + `X-Maintenance-Bypass` header
  lets the founder smoke-test a deploy mid-window. Frontend detects the contract
  and shows a full-screen "back shortly" overlay (covers login too) that polls
  `/health` and auto-reloads when the window lifts. Guarded by
  `validate-maintenance-mode.js` (29 assertions, CI-blocking); enable/verify/lift
  runbook in `docs/07-RELEASE-CHECKLIST.md`. Capability shipped with the flag OFF
  (behaviourally inert until toggled).
- Live version **4d9898d4-d0e2-45c0-b77f-59842dff7a29**; `/health` 200
  (version 2026.07.12, maintenance:false). Rollback: previous stable
  **60d557a2-9467-4e3f-b28a-11b18d4637a8**.

## 2026.07.11 (v2026.07.11-3 — daily ops-health heartbeat) — deployed 2026-07-11

### Operations
- **Daily ops-health heartbeat** (`4850c91`): a cron self-check (08:00 UTC) runs
  read-only signal queries — scans stuck `running` >15min, undelivered
  lifecycle-email backlog, undelivered asset-alert backlog, deletion purges
  overdue >35d — and emails ops (`ALERT_EMAIL_TO`) ONLY when a threshold is
  breached, so a healthy system stays silent (≤1 alert/day). If every query is
  skipped the DB is treated as unreachable and the alert says so. Per-run
  `ops_health` metric for trends. Fully isolated via `runCronTask` (never affects
  existing cron tasks). New `src/lib/ops-health.js` (pure, tunable
  `OPS_THRESHOLDS`) + CI-blocking `validate-ops-health.js` (29 assertions).
  `docs/MONITORING.md` documents all three layers (/health+/ready probes,
  Cloudflare 5xx/log notifications, this heartbeat) + response runbook.
- Live version **16212a24-1b94-4892-87ef-28a04e52ed6d**; `/health` 200, `/ready`
  d1+r2 healthy. Rollback: previous version **60d557a2-9467-4e3f-b28a-11b18d4637a8**.

## 2026.07.11 (v2026.07.11-2 — uniform API error contract) — deployed 2026-07-11

### API / trust
- **Uniform error contract** (`c33aff9`): every error response (HTTP ≥ 400) now
  carries `{ error, code, message }` — a snake_case machine `code` the UI can
  switch on and a customer-safe human `message` a user can read verbatim —
  enforced centrally in `normalizeApiResponseData` (the choke point behind
  `json()`), so all 568+ error sites conform with no route churn. Completed the
  status→code map (405/410/422/502/503) and guaranteed `message` (added only
  when a route didn't set its own). `detail`/`stack` are still stripped.
  Backward-compatible: `error` unchanged (existing machine-code switches keep
  working); `message` is additive. OpenAPI Error schema updated. New CI-blocking
  harness `validate-error-contract.js` (116 assertions). Live 401 now returns a
  clean sentence instead of a bare "Unauthorized".
- Live version **60d557a2-9467-4e3f-b28a-11b18d4637a8**; `/health` 200. Rollback:
  previous version **9e0949d6-123b-4526-b863-a635f7236928**.

## 2026.07.11 (v2026.07.11-1 — secure-SDLC batch: log redaction, Stripe replay guard, purge + migration CI gates) — deployed 2026-07-11

### Security / reliability (every finding paired with an automated regression)
- **P0#7 — central log redaction** (`a168bd4`): new `src/lib/redact.js` (recursive,
  cycle-safe, depth-capped) strips secret-named keys (password/token/secret/
  authorization/cookie/api-key/mfa/totp/session/…) and secret-shaped values
  (JWT, Stripe sk/rk/pk, whsec_, cm_/cmrua_, Bearer, long hex). The `serverError`
  request-error logger now routes through `redactedJson()` — defense-in-depth so
  no log site can ever leak a credential. Test: `validate-log-redaction.js` (17/17).
- **P0#5 — idempotent Stripe webhooks** (`c18defb`): a replayed/retried event
  (same id) could re-run entitlement side effects. Every handled event id is now
  persisted in `stripe_processed_events` (migration 069, additive) and an
  `INSERT OR IGNORE` before the switch short-circuits a replay to
  `{received, deduped}` without reprocessing; signature verification unchanged and
  still first. Test: `validate-pipeline.js` posts the webhook twice and asserts
  the replay is deduped (38/38). Migration 069 applied to remote D1 before deploy.
- **P1#10 — purge-completeness regression** (`adc9e0f`): `validate-purge-completeness.js`
  seeds every purge table + reports + a scan (+children) for two workspaces, runs
  the real `purgeWorkspaceData` to completion, and asserts zero orphaned rows/R2
  objects for the purged workspace with the other fully intact (10/10). Guards the
  forgotten-table orphan class.
- **P1#3 — CI security gates expanded** (`33222a8`): new `validate-migrations.js`
  enforces additive-only migrations (destructive-statement scan) + fresh-apply
  convergence (79/79); worker `npm audit --audit-level=high` (0 vulns) and the
  three new harnesses are now CI-blocking.

### UX
- **New Scan re-click resets the form** (`ea84ff0`): clicking the header New Scan
  button while already on /scans/new now clears + scrolls the form. Feedback
  widget simplified to a single **Contact support** action (bug/feature options
  removed).

- Live version **9e0949d6-123b-4526-b863-a635f7236928**; `/health` 200 (version
  2026.07.11), anon endpoints 401. Rollback: previous version
  **5dc30474-f8df-4e4d-a198-fbe7484a4c50**.

## 2026.07.10 (v2026.07.10-11 — authenticated red-team fixes) — deployed 2026-07-11

### Security (Codex authenticated logic-layer red-team — all findings verified vs HEAD)
- **P1 — Free trial is now once-per-owner** (`5b57af3`): trials were minted per
  workspace with no lifetime check, and workspace usage ignores soft-deleted
  workspaces, so an owner could farm unlimited 14-day Professional trials via
  create → soft-delete → create. Trial creation now skips if the owner already
  has any subscription with a trial_start (survives soft-delete). First workspace
  still trials; recycled ones do not.
- **P1 — Workspace notifications scoped per user** (`68d056b`): notification_events
  has a user_id column (NULL = global) but list/count/mark-read filtered only by
  workspace_id, so any member could see and clear another member's user-specific
  notifications. All four queries now scope by (user_id IS NULL OR user_id =
  caller). Backward-compatible — today all rows are global.
- **P2 — MFA recovery-code endpoint throttle** (`a7ea6e5`): added the fail-closed
  IP limiter the other MFA proof endpoints already had.
- **P2 — Worker lockfiles committed** (`6068eb3`): npm audit now reproducible on
  both workers, 0 vulnerabilities.
- Live version **5dc30474-f8df-4e4d-a198-fbe7484a4c50**; `/health` 200, anon
  endpoints 401. Rollback: previous version `fa3c49d1-c111-4785-bbdf-a2d136d282e0`.

## 2026.07.10 (v2026.07.10-10 — red-team hardening) — deployed 2026-07-11

### Security
- **Signup user-enumeration removed** (`429f2e0`): signup returned a distinct
  409 for a registered email, letting an attacker probe which emails have
  accounts (found in the authorized black-box red-team pass). Signup with an
  existing email now returns the exact same generic 201 as a fresh signup — no
  account is created, and a security-notice email goes to the genuine owner
  instead. The HTTP response is now indistinguishable between registered and
  unregistered emails; signup stays rate-limited (5/hour/IP). Verified live:
  existing vs non-existing email now return identical responses.
- **Dev-dependency CVEs cleared** (`eb2562a`, no deploy needed): wrangler
  bumped v3 → ^4.24.4, clearing 5 advisories (esbuild dev-server SSRF, undici
  ×9, miniflare) — all devDependency-only, never in the production runtime.
  `npm audit` now 0 across frontend + both workers.
- Authorized black-box red-team pass (16 checks) otherwise clean: HSTS/CSP/
  X-Frame/nosniff, auth-required 401s, error sanitisation, login rate-limit
  fires at the 10th attempt, CORS not reflected, body 413 / URL 414, webhook
  400 unsigned, no file leaks, security.txt present, no cookies.
- Live version **fa3c49d1-c111-4785-bbdf-a2d136d282e0**; `/health` 200.
  Rollback: previous version `fd583e3d-525b-4a35-8561-80ab91deda3f`.

## 2026.07.10 (v2026.07.10-9 — pre-beta security hardening)

### Fixed (independent Codex audit at 0bf010e, all verified against HEAD)
- **Cross-tenant domain existence oracle** (`4783ef6`): the domain verification
  init + check routes returned 403 for a domain owned by another tenant but 404
  for a nonexistent id — an authenticated user could distinguish foreign-existing
  from nonexistent domain ids. Both now return an identical 404 (ids are opaque
  UUIDs so enumeration was already impractical; the response oracle is closed).
- **Invitation-send rate limiting now fail-closed** (`4af86f7`): invite_send
  hourly/daily limits fell open on a rate_limit table outage; each invite sends
  an email from our domain, so an outage was an open spam/reputation window. Now
  fail-closed (503) — a brief inability to invite beats unbounded outbound mail.
- **Fail-closed throttles on MFA proof endpoints** (`27d597f`): verify-setup /
  disable (per user, 10/15min) and login challenge (per IP, 20/15min) had no
  endpoint-specific limit — the TOTP/password proofs relied only on the fail-open
  global guard. Defense-in-depth atop the existing per-challenge single-use guard.

### CI
- **Worker bundle dry-run added to CI** (`a762bec`): CI ran all 5 harnesses +
  frontend build but not the Cloudflare bundling step — the exact class that
  produced the v-3 PLAN_LIMITS runtime break would now be caught pre-merge.

### Deploy note
- Live version **7c7c7a05-449e-42cd-9d28-6dbcc362365c** (100% traffic, confirmed
  via `wrangler deployments list` + `/health`). The `wrangler deploy` client
  reported "fetch failed" on its final confirmation fetch due to flaky local
  network, but the Cloudflare-side activation succeeded — verified independently.
  Post-deploy smoke: `/health` 200, `/api/billing/plans` 200, anon `/api/auth/me`
  401. Rollback: previous version `fd583e3d-525b-4a35-8561-80ab91deda3f`.

## 2026.07.10 (v2026.07.10-8 — RUA external report authorization auto-provisioning)

### Added
- **RFC 7489 §7.1 authorization auto-provisioning** (`24ff2a7`): configuring a
  DMARC ingest endpoint's Cloudflare route now also upserts the
  `<domain>._report._dmarc.<rua-domain>` TXT (`v=DMARC1;`) on our zone, so
  cross-org receivers (Google, Microsoft) actually send aggregate reports for
  external customer domains — previously a manual, silently-gating step (the
  first pilot's stall). Same-org domains (apex + sibling subdomains of the
  inbound domain's org) exempt per the RFC; idempotent (adopts existing
  records); a failure never blocks route setup and self-heals on the next
  configure pass. Unit-tested against a mocked CF API (6/6); 5/5 harnesses.
- Post-deploy smoke: `GET /health` → 200,
  `deployment_id fd583e3d-525b-4a35-8561-80ab91deda3f`; plans 200, anon
  auth/me 401. Rollback: previous version
  `f0528ca1-cefa-4123-9b96-4d33e4432730`.
- Same day: **first real external DMARC aggregate ingested** — google.com →
  blackbullbarbers.co.uk (3 records: SPF aligned pass ×3, DKIM aligned fail ×3
  from Microsoft 365 IPs — confirming the known M365-DKIM-disabled gap),
  stored in the correct workspace end-to-end.

## 2026.07.10 (v2026.07.10-7 — router split COMPLETE, PRs #14–#20)

### Changed
- **Router split PRs #14–#20 — Phase 2 COMPLETE** (behaviour-preserving, solo):
  scans (start/report/PDF + scheduled scans), portfolio + workspace list,
  **attack-surface** (assets/alerts/posture/vendors, 1,493 lines — largest
  band), workspace-insights (validation/usage/summary/health), account
  (profile/tokens/sessions/GDPR export + platform QA), global-billing (plans,
  DMARC signed-upload ingest, **Stripe webhook**, checkout/portal) and finally
  **auth** (signup/login/MFA/SSO/password lifecycle, 1,499 lines, zero
  routeCtx changes). **index.js 15,637 → 2,242 lines (−86%) across 20 PRs**;
  every route group now lives in `src/routes/` (16 modules) behind the
  per-request routeCtx dispatcher; engines grew by plan-usage +
  subscription-state. Every PR: byte-equality vs main, index-def leak scan +
  cross-module missing-import scan, all 5 harnesses, CI green.
- Post-deploy smoke: `GET /health` → 200,
  `deployment_id f0528ca1-cefa-4123-9b96-4d33e4432730`; auth paths verified
  live (bad login → 401 not 500, anon `/api/auth/me` → 401,
  `/api/billing/plans` → 200). Rollback: previous version
  `892f8ee6-7d90-43be-91d3-52f72eb855ee`.

## 2026.07.10 (v2026.07.10-6 — router split PRs #11–#13)

### Changed
- **Router split PRs #11–#13** (behaviour-preserving, solo): workspaces-core
  (detail/rename/domain-link CRUD + delete-request/restore; routeCtx gains
  DELETION_PURGE_WINDOW_DAYS), the **subscription/trial-state engine**
  (`engines/subscription-state.js`: TRIAL_PLAN constants, trial/subscription
  state checks, workspace subscription resolution, checkout plan parsing,
  public billing plans), and billing + free-scan routes (last group before the
  404 fallback; routeCtx gains rateLimitScopeId). index.js 9,579 → 8,916
  (running total 15,637 → 8,916 across 13 PRs). Byte-equality + double leak
  scans + all 5 harnesses per PR; CI green throughout.
- Post-deploy smoke: `GET /health` → 200,
  `deployment_id 892f8ee6-7d90-43be-91d3-52f72eb855ee`; `/api/billing/plans`
  → 200. Rollback: previous version `e95c982d-fd2f-4f6a-8f95-11f6394bb01c`.

## 2026.07.10 (v2026.07.10-5 — router split PRs #7–#10)

### Changed
- **Router split PRs #7–#10** (behaviour-preserving, solo): workspace-members
  (invitations + members, routeCtx gains consumeApiRateLimit + ROLE_RANK),
  executive-dashboard (KPI + activity feed), **email-protection** (the whole
  email-wedge route band — DMARC report import/list/summary, sender inventory,
  BEC exposure, hosted DMARC/DNS management, RUA routing, alert channels;
  1,040 lines, 54 symbols from 9 modules), and domains (import + verification
  lifecycle; /domains/import precedence over :domainId preserved; routeCtx
  gains requireDomainRole). index.js 11,928 → 10,037 lines. Every PR:
  byte-equality vs main, index-def leak scan + cross-module missing-import
  scan, all 5 harnesses (incl. validate-pipeline — mandatory since the v-4
  incident), CI green.
- Post-deploy smoke: `GET /health` → 200,
  `deployment_id e95c982d-fd2f-4f6a-8f95-11f6394bb01c`; `/api/billing/plans`
  → 200. Rollback: previous version `414ec706-13f6-4682-8f46-6d322737a1cd`.

## 2026.07.10 (v2026.07.10-4 — hotfix: PLAN_LIMITS import)

### Fixed
- **`/api/billing/plans` 500 introduced by v2026.07.10-3**: PR #4 moved
  `getPlanLimits` into `engines/plan-usage.js` without carrying the
  `PLAN_LIMITS` import (bracket access evaded the call-based dependency scan;
  the symbol was satisfied by index.js's own import — for the old scope).
  Caught by CI `validate-pipeline` (local runs had skipped that harness — all
  5 are now mandatory for every change, no exceptions). A cross-module
  missing-import scan (refs to another module's exports without importing
  them) now runs over every extracted module: all 7 clean. Post-deploy:
  endpoint 200, `deployment_id 414ec706-13f6-4682-8f46-6d322737a1cd`.
  Broken window: ~70 min on a public no-auth metadata endpoint; quota checks
  were unaffected (fail-open by design).

## 2026.07.10 (v2026.07.10-3 — router split, low-risk batch)

### Changed
- **Router split PRs #1–#6** (behaviour-preserving; PRs #21/#22/#23 via Codex +
  3 solo): route groups extracted from the monolithic `fetch()` router into
  `src/routes/` modules dispatched through a per-request `routeCtx` —
  workspace-analytics (scorecard/CE/BRS), workspace-intel (identity/vendor-rel/
  supply-chain), brand (intelligence v1 + monitoring), workspace-reports
  (reports + scheduled-reports), workspace-activity (audit events +
  notifications); plus the 31-function plan-usage/report-lifecycle engine
  (`engines/plan-usage.js`: plan limits, usage metering, retention, quota
  checkers, report cadence, generateWorkspaceExecutiveReport). index.js
  15,637 → 12,558 lines. Every move byte-equality-verified against main with a
  full bare-identifier leak scan; all 4 harnesses green per PR.
- Post-deploy smoke: `GET /health` → 200,
  `deployment_id 42e170a8-21e7-4b8c-a9fc-b4f7373fb7ae`.
  Rollback: previous version `4003937f-100f-41e3-ab2d-b838a14fbe39`.

## 2026.07.10 (v2026.07.10-2 — asset alert trust fixes)

### Fixed
- **Inventory diff survives domain delete/re-add** (`145974e`): existing assets are
  matched by hostname (root or `*.root`) as well as `domain_id`. Previously a re-added
  domain got a new `domain_id`, making rows written under the old id invisible to the
  diff — every later scan re-announced known assets as `new_asset_discovered` while
  `UNIQUE(workspace_id, hostname)` silently blocked the re-insert and froze `last_seen`
  (observed live: `cybermeters.com` + `app.cybermeters.com` stuck at 2026-06-19 while
  alerted as "new" by scan `scan_2d7183d1` on 2026-07-10). Matched rows are re-linked
  to the current `domain_id`, so orphaned inventory self-heals on the next scan.
- **Asset change alert scoped to the scan's own workspace** (`8ccf344`): one scan
  produced three alert emails — HIGH "new assets" to the owning workspace plus two
  identical MEDIUM "reappeared" mails to the other workspaces linked to the same
  domain, each exposing the owning workspace's scan id. Alert email + channel fan-out
  now target only the scan's workspace; asset events remain written for every linked
  workspace (in-app feeds unchanged). Scans without a workspace keep the old fan-out.
- Validation: accuracy 227/227, security-contracts 45/45, integration 18/18,
  email-worker equivalence 9/9, `wrangler deploy --dry-run` clean. Post-deploy smoke:
  `GET /health` → 200, `deployment_id 4003937f-100f-41e3-ab2d-b838a14fbe39`.
  Rollback: previous version `b35a8990-00fd-46f6-968f-11837db07747`.

## 2026.07.10 (v2026.07.10-1 — monolith decomposition Phase 1)

### Changed
- **Worker modularisation** (worker `780d3120`, decomposition commits `61b63a3`…`d95f242`):
  the 36,321-line `workers/scan-api/src/index.js` monolith was split into **66 focused
  modules** (53 `src/engines/` + 13 `src/lib/`); index.js is now ~15,637 lines. Every
  extraction is a **verbatim, behaviour-preserving move** — no logic, scoring, copy,
  pricing, schema, or API change. Extracted: all scan/discovery modules, the scoring
  engine (`computeScore`), the email wedge (analysis/scan/intel/BEC), brand protection,
  the DMARC/hosted/RUA subsystem (incl. the hosted DMARC records engine), PDF generation,
  billing (entitlements + Stripe), alerts, risk-scoring (BRS/vendor/supply-chain/portfolio/
  CE), and the scan pipeline orchestrator (`runScanEngine` → `engines/scan-engine.js`,
  which now composes 56 symbols from 37 modules). Remaining index.js = worker entry/auth
  glue + operational plumbing + the HTTP router.
- **Latent bug fixed in passing:** the dangling-reference audit caught `computeScanBudget`'s
  fallback referencing `BRUTEFORCE_MAX_NAMES` (a `subdomains-scan` module-internal) — a
  `ReferenceError` on the non-numeric branch that the test suites never exercised. Now
  exported + imported. This branch existed pre-decomposition too; the refactor surfaced it.
- Verified at every step and at release: all 5 regression suites green (accuracy 227/227,
  pipeline real-fetch, security-contracts, integration authz, email-worker golden
  equivalence 9/9), `wrangler deploy --dry-run` clean (bundle 1399 KiB, identical to the
  deployed bundle), `git diff --check` clean. Post-deploy smoke: `GET /health` → 200 with
  `deployment_id 780d3120`. Structural refactor done pre-revenue at zero customer stakes.

## 2026.07.09 (v2026.07.09-3 — Cyber MOT welcome-email copy)

### Changed
- **Welcome email wording** (worker `d8a1bd45`, PR #7 `a79e6f3`): the signup
  welcome email now leads with Cyber MOT / Website Security / Certificates & Trust
  instead of "external attack surface" + "run your first scan". Copy-only, part of
  the ChatGPT-led Cyber MOT wording pass (docs/COPY-CLEANUP-BACKLOG.md); the
  matching frontend copy (dashboard, onboarding, pricing hero, scans, workspaces)
  shipped on Pages via the same PR. No logic, pricing, or template-structure change;
  email-worker golden equivalence 9/9.

## 2026.07.09 (v2026.07.09-2 — trust-copy corrections)

### Fixed
- **Mis-selling plan copy** (worker `38a9291b`, commit `0c6518a`): the upgrade
  wall advertised "Up to 25 domains" (Starter, sells 1) and "Up to 250 domains"
  (Professional, sells 5) — now matches the frozen tiers (1 / up to 5 / up to
  20 monitored domains). Billing plan-limits grid is domain-first (internal
  workspace/scan quotas no longer rendered). Free Cyber MOT 429 no longer
  promises "unlimited scanning" (free plan has monthly caps). Source: external
  audit P1s, each verified against source before fixing.
- Also shipped on Pages this cycle: Cyber MOT domain handoff through signup →
  onboarding (+ regression tests via PR #6), CE Preview/Dashboard naming, and
  the in-app entry for the paid CE dashboard (previously an orphan route).

## 2026.07.09 (v2026.07.09-1 — pricing coherence + single-workspace SMB)

### Fixed
- **SMB plans are single-workspace** (worker version `2d17cf49`): Starter and
  Professional allowed multi-workspace (ws=3 / ws=10) while domains are enforced
  per-workspace, so a Professional user could reach 10×5=50 domains vs the
  advertised 5. Set starter/professional `workspaces` to 1 (free already 1);
  Business (50) and Enterprise (unlimited) keep multi-workspace for per-client
  tenant isolation. Enforcement is creation-only — existing workspaces are never
  touched (verified against prod D1: the only >1-workspace account is the
  founder's own and stays intact).
- **Pricing cards are tier-aware** (frontend / Pages, commit `b629fc0`): SMB
  tiers lead with domains (the value metric); MSP tiers show client workspaces +
  domains-per-workspace. Removed internal scans/reports quotas from the cards,
  added a "Most popular" badge on Professional, and persisted the billing-cycle
  choice so it survives the signup/checkout round-trip.
- **Self-serve checkout** (worker deploy `bd43876d`): checkout was disabled by
  three of our own bugs (hardcoded `checkout_enabled:false`, env-var name
  mismatch, yearly→monthly interval collapse) — not the Stripe configuration.
  Verified live: 6/6 checkout sessions created, zero missing-price errors.

## 2026.07.08 (v2026.07.08-6 — Cyber Essentials Readiness)

### Added
- **Cyber Essentials Readiness endpoint** (deployment `22fe448e`): GET/PUT
  `/api/workspaces/:id/cyber-essentials/answers` (auth + professional plan gate +
  server-side key validation + upsert on migration 068). The readiness endpoint
  now additively returns `self_assessment` — measured categories merged with
  self-attestation, with an HONEST per-control evidence label
  (self_attested_only for internal controls — never "verified";
  contradicted_by_scan where an optimistic answer conflicts with observed
  evidence). Partial verification, transparently labelled.
- **CE Readiness free-hook page** (frontend, Codex + Claude review): public
  `/cyber-essentials-readiness` lead-gen questionnaire (local state), distinct
  from the paid in-app `ws/cyber-essentials` service. Not yet wired to data.

## 2026.07.08 (v2026.07.08-5 — asset-alert retry + manual release model)

### Production verification (release closure)
First cron on deployment `2a6e2baa` — the first run with `asset_alert_retry`
in the registry (captured via `wrangler tail`, window 14:58–15:04 UTC):
- **Run time:** 2026-07-08 **15:00:12 UTC** (`"0 * * * *" — Ok`).
- **Errors:** zero `[cron-error]` / exception lines in the window. A mis-wired
  registry entry would have surfaced as an `is not a function` cron error; the
  task-name set is additionally CI-locked (pipeline suite).
- **`[asset-alert-retry]` log lines:** none — expected: the sweep logs only
  when it retries something, and the failed-set is empty (the pre-067 lost
  alert reads `'sent'` by design and is never retro-retried).
- **Metric reference:** AE `cybermeters_metrics` `cron_task` rows at
  2026-07-08T15:00Z include `asset_alert_retry` (query in OPERATIONS.md).

### Changed
- **Release model:** Cloudflare Workers Builds disconnected from the worker
  (probe-verified before and after — a docs push created a version while
  connected, none after). The worker now deploys manually only; Pages keeps
  auto-deploying the frontend. Flow: feature branch → PR/CI → merge → manual
  `wrangler deploy` → tag → CHANGELOG.

### Fixed
- Asset-change alert emails are enrolled in the hourly retry cron
  (`asset_alert_retry`): previously the dedupe row was written before the
  send, so a failed delivery was permanently lost (observed 2026-07-08).
  Migration 067 adds delivery-outcome tracking (safe to re-run, NOT strictly
  idempotent — duplicate-column error = already applied). Delivery semantics
  are documented at-least-once. Deployment `2a6e2baa`.

### Added
- Standalone `cybermeters-email` worker deployed dark (Stage B; 56 KiB bundle;
  Email Routing still points at the main worker until cutover).
- Pipeline suite → 31 assertions: billing lifecycle arc (payment-failed →
  grace holds → cancellation closes the gate → re-subscribe restores) and
  cron assertions upgraded to exact task-name-set + all-ok outcomes.

## 2026.07.08 (v2026.07.08-4 — worker decomposition phase 1)

### Production verification (Sprint 9 closure evidence)
First production cron of the modular worker — captured via `wrangler tail`
(window 10:58–11:04 UTC):
- **Run time:** 2026-07-08 **11:00:28 UTC** (`"0 * * * *" — Ok`).
- **Deployment:** `575d361a-0b91-4f35-bc98-4ac865342ab8` (`v2026.07.08-4`).
- **Tasks:** `triggerScheduledScan` ran visibly — real scheduled scan on
  blackbullbarbers.co.uk (`scan_06b0c7ee`, inventory 2 assets found, change
  detection 14 → +2, two workspaces updated). The six wrapped tasks
  (scheduled_reports, user_scheduled_reports, hosted_dns_sweep,
  deletion_purge, lifecycle_email_retry, domain_verify_retry) completed with
  **zero `[cron-error]` lines** (success is metrics-only by design; per-task
  duration datapoints in AE `cybermeters_metrics`, query in OPERATIONS.md).
  `report_retention` correctly skipped (only 02:00 UTC).
- **Unexpected exceptions:** 0. Handled external-dependency errors inside the
  scan: 1× certspotter CT-log timeout (scan completed past it), 2× alert-email
  `network_error` (pre-existing failure class — the documented motivation for
  the lifecycle-retry cron; follow-up: confirm asset-alert emails have a retry
  path).
- **API plane served traffic throughout** the cron (notification polls Ok at
  11:59–12:04 local, uninterrupted).
- **Reference:** tail capture preserved in session scratchpad; AE `cron_task`
  rows at 2026-07-08T11:00Z.

### Changed
- The worker is now a multi-module ES build (behaviour-identical, single
  deployment): inbound RUA email handling lives in `src/email/inbound.js`,
  cron orchestration in `src/cron/scheduled.js` (task-registry injection),
  and metrics in `src/lib/metrics.js`. Deployment `575d361a`.
- The four validation suites load the worker as a real ES module (vm-free);
  the request-pipeline suite gained a cron-orchestration section and now
  proves login, webhook→entitlement, feature-gate, pagination, rate-limiting
  and cron wiring end to end (24 assertions).
- Frontend: Vitest + Testing Library layer (24 tests) and an incremental
  TypeScript foundation (typed API client, CI type gate) — Sprints 7-8.

## 2026.07.08

### Added
- Release traceability: `GET /health` now returns `version` (APP_VERSION) and
  `deployment_id` (Cloudflare version-metadata binding); `[request-error]` logs
  carry the version.
- `docs/PUBLIC-BETA-SPRINTS.md` — the 10-sprint public-beta ladder.
- `OPERATIONS.md` — production runbook (deploy / rollback / secrets / incident).
- `scripts/validate-security-contracts.js` — 36 auth / MFA / RBAC / billing
  contract tests, wired into CI (blocking).
- CI: dependency-free secret scan + `npm audit --audit-level=high`.
- Reports: four-service Ocean & Ice colour-coding across the scan and executive
  PDFs (data reads in its owning service's colour).

### Changed
- Notifications are clickable again — the UI now reads the parsed `metadata`
  object (the API had stopped returning `metadata_json`), restoring
  click-through to the related scan.
- Domain verification auto-retries the DNS TXT check hourly for 48h so slow
  registrar propagation completes without manual re-clicks; verification audit
  events record the DNS record hash + resolver used.
- Cloudflare API calls retry transient 429/503 with a short bounded backoff.
- Colour-coded, persistent workspace sidebar; wider logo bracket spacing.

### Fixed
- Stale-chunk "reload" screen no longer dead-ends: the auto-reload budget is
  restored after a healthy boot, so an independent later deploy self-heals.
- Inbound DMARC report drops now raise a calm in-app notification instead of
  failing silently.

### Security
- Stopped returning internal R2 object paths (`report_key`) in client report
  responses.
- Masked recipient email local-parts in delivery logs.
- Auth/RBAC/billing crypto now covered by CI contract tests.

### Ops / hygiene
- `.gitignore` fixed (lockfiles no longer ignored; de-duplicated); strategy
  docs + a sample report PDF untracked from the code repo.
