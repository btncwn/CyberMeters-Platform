# Codex Build Brief — Managed Brand Protection v1 (takedown lifecycle on the shared Case Platform)

**Decision owner:** Turhan · **Queued:** 2026-07-13 · **Author of brief:** Claude (Lead Eng / review-integrate)
**Operating model:** Codex builds · Claude reviews + integrates + validates + deploys · Turhan decides
**Risk tier:** MEDIUM (additive migrations + new engine/routes/UI). Additive & reversible only.

**Prerequisite:** the Managed Case Platform (`engines/case-workflow.js` + `managed_cases` /
`managed_case_events`) is already shipped (v2026.07.13-8/9) and is Brand's foundation. **Do NOT
write a new case engine.** Brand is the platform's *second* consumer — proving it generalizes.

---

## 0. One-line goal

Turn a high-risk brand-impersonation candidate into a governed **takedown case**: confirmed,
customer-approved, evidence-bundled, submission-tracked, followed-up, **technically re-verified by
CyberMeters when the abusive domain actually goes away**, and **auto-reopened / campaign-linked if
it returns** — full tenant-scoped audit trail, on the shared case platform.

Positioning after the live proof: **"Managed brand abuse detection and takedown lifecycle."**
Be honest about the external dependency: CyberMeters detects, classifies, prepares, submits,
follows up and **technically verifies removal** — it does not *control* the registrar/host/CA
decision. Never imply guaranteed takedown.

---

## 1. Why Brand is the second managed consumer (context)

DMARC = managed (done). ASM = managed + the platform-extraction vehicle (done, v...-9). Brand is
next because the generic case platform now exists, and Brand's audit shows a **strong Level-2
classification brain already in place** — so this epic is mostly the *lifecycle*, not new
intelligence:
- `scoreBrandCandidateRisk` → `{ score, risk_level, reasons }` (`brand-protection.js:74-131`),
  risk_level `critical` (≥85) / `high` (≥65) / lower.
- **Registration-reality guardrail** (`brand-protection.js:107-123`): unregistered permutation →
  `not_registered_watchlist` (capped low); registered + mail-capable → `registered_with_mail_capability`
  (floored high). This guardrail is load-bearing — see §7.
- Candidates persist in `workspace_brand_assets` (UNIQUE `(workspace_id, domain, candidate_domain)`,
  `brand_profile_id`, migration 009 + 058); triage labels in `BRAND_CLASSIFICATIONS`
  (`brand-protection.js:20`); profile scoping via `buildBrandProfileDomainScope`.

Roadmap: DMARC ✅ → ASM ✅ (+ completeness guard ✅) → **Brand (THIS)** → Cert L2 → external TLS
prober → managed cert deployment verification.

---

## 2. Architecture — reuse the shared platform (do not re-invent)

- Brand cases are `managed_cases` rows with `case_type = 'brand_abuse'`. Reuse the generic
  `engines/case-workflow.js` runner with a **Brand machine definition** (§6).
- **Anchor / dedup:** a case maps 1:1 to a brand candidate — `domain` = `candidate_domain`,
  `finding_id` = a stable candidate key (`brand_profile_id` + `:` + `candidate_domain`), `asset_ref`
  = the protected brand/domain. At most one non-terminal case per `(workspace_id, brand_profile_id,
  candidate_domain)` (partial unique index, as 076 did).
- Brand-specific detail (provider contacts, submission tracking, follow-up schedule, evidence-bundle
  reference, similarity/abuse indicators) lives in `evidence_json` / `managed_case_events.detail_json`
  — mostly no new columns. The ONE genuinely new persistence need is **campaign linking** (§8f):
  add an additive `brand_abuse_campaigns` table.
- Reuse `createAuditEvent` (now has `actor_type`) + `createNotificationEvent`/`alerts.js` exactly as
  `asm-cases.js` does. Follow `engines/asm-cases.js` as the structural template; put Brand logic in
  a new `engines/brand-cases.js`.

---

## 3. Scope

### IN (Managed Brand Protection v1)
1. Brand candidate → managed case (only high-risk, registered candidates — §7).
2. Evidence bundle generator (§8b) — a real, timestamped, exportable artifact.
3. Customer/analyst classification review (confirm abuse / reject).
4. Confirmed-abuse workflow → customer approval gate.
5. Takedown preparation (recipients + evidence bundle assembled).
6. Provider/contact resolution (registrar abuse via RDAP; best-effort hosting/CA — §8d).
7. Submission tracking (record that a submission was made + reference; **human submits**, §3-OUT).
8. Follow-up scheduling (cron sweep re-checks + escalates on no-response).
9. Technical takedown verification (re-probe the candidate; §8e) — system-only, honest.
10. Reappearance → campaign link → auto-reopen (§8f).

### OUT (explicitly deferred — do NOT build in v1)
- **Automated submission** to registrars/hosts/CAs (no auto-emailing abuse desks). v1 PREPARES and
  TRACKS; a human sends. This bounds blast radius and overclaim.
- Screenshot rendering, IF no in-Worker rendering path exists (Workers can't run a headless browser).
  Evidence bundle v1 = DNS/WHOIS(RDAP)/MX/TLS-from-CT/similarity snapshots (all Worker-native). Flag
  screenshots as a follow-up needing an external render service — do NOT fake them.
- Legal-review workflow, SLA breach engine, social-platform impersonation APIs, MSP cross-customer
  analyst queue. (`escalated` state may exist as a label; no escalation engine in v1.)

Keep v1 tight. A giant "full managed brand" task is rejected.

---

## 4. Data model (additive, enums-in-code, NO CHECK)

- **Reuse `managed_cases`** with `case_type='brand_abuse'`. No new columns needed on it.
- **New additive table `brand_abuse_campaigns`** (reappearance/campaign linking):
```
id                TEXT PRIMARY KEY            -- 'bac-'+12hex
workspace_id      TEXT NOT NULL
brand_profile_id  TEXT
linked_domains    TEXT   -- JSON array of candidate domains in this campaign
linked_ips        TEXT   -- JSON array
shared_certs      TEXT   -- JSON array of cert fingerprints/SHA256
shared_favicon_hashes TEXT -- JSON array
first_seen_at     TEXT
last_seen_at      TEXT
created_at/updated_at TEXT NOT NULL DEFAULT (datetime('now'))
FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
```
Index `(workspace_id, brand_profile_id)`. A `managed_cases` brand row references its campaign via
`evidence_json.campaign_id` (no schema change to managed_cases).
- **Add `brand_abuse_campaigns` to `WORKSPACE_PURGE_TABLES`** (`index.js`) — the
  `purge_covers_all_workspace_fk_tables` contract will fail otherwise.

---

## 5. (reuse `engines/case-workflow.js` — no new engine)

Brand supplies a `createCaseMachine({...})` definition (§6) and reusable guard helpers
(`requireReason`, `requireField`, `requireActor`, `requireDifferentActor`). New code lives in
`engines/brand-cases.js` (candidate→case, evidence bundle, provider resolution, verification,
campaign linking) — structured like `asm-cases.js`.

---

## 6. Brand case state machine (`case_type = 'brand_abuse'`)

```
detected
→ triage
→ confirmed_abuse
→ customer_approval
→ evidence_ready
→ takedown_submitted
→ provider_followup
→ verification_pending
→ resolved
```
Alternative / branch states: `false_positive`, `duplicate`, `provider_no_response`, `escalated`,
`reappeared`, `closed`.

Transitions (author precisely; principles):
- `detected → triage` · `triage → confirmed_abuse | false_positive | duplicate`
- `confirmed_abuse → customer_approval` (guard: `requireReason` — the abuse evidence)
- `customer_approval → evidence_ready` (guard: `requireActor` — a customer/authorised approver;
  this is the approval gate before any takedown prep)
- `evidence_ready → takedown_submitted` (guard: `requireField('recipients')` — cannot submit
  without resolved provider contacts + a generated bundle)
- `takedown_submitted → provider_followup → verification_pending`
- `verification_pending → resolved` (SYSTEM ONLY) | `→ provider_no_response` (timeout, system) |
  `→ escalated`
- `resolved → reappeared` (SYSTEM, on re-detection) → `confirmed_abuse` (re-enters lifecycle)
- Terminals: `false_positive`, `duplicate`, `closed`.

**Trust guard (reuse the ASM pattern):** verification-outcome states are CyberMeters-only. A
customer/analyst transition must NEVER reach `resolved` / `reappeared` (and `provider_no_response`
should be system-set). Mirror `asm-cases.js` `SYSTEM_ONLY_CASE_STATES` — a case is `resolved` only
when CyberMeters technically re-observes the abusive domain gone (§8e), never on a human's say-so.

---

## 7. Case-open threshold (respect the registration-reality guardrail)

A case opens **only** for a candidate that is BOTH:
- `risk_level ∈ {critical, high}` from `scoreBrandCandidateRisk`, AND
- actually **registered / live** (resolves, or has a cert/MX) — i.e. NOT `not_registered_watchlist`.

An unregistered permutation is a **watchlist item, never a takedown case** — opening cases for
theoretical permutations would flood the queue with non-threats and break customer trust (this is a
hard CLAUDE.md brand rule). Low/medium candidates stay in the existing monitoring/triage view.
Respect `buildBrandProfileDomainScope` — cases are scoped to the brand profile's protected domains;
never let unrelated workspace domains (Google/Tesla/etc.) open a brand case.

Candidate → case creation hook: run during brand discovery/refresh (wherever candidates are scored),
mirroring how `createManagedAsmCasesForScan` runs in the scan pipeline. Respect any existing
`owned`/`ignored`/`false_positive` classification — never auto-open a case for a candidate the
customer already dismissed.

---

## 8. Integration seams

**a. Candidate → case.** Anchor on `(workspace_id, brand_profile_id, candidate_domain)`. Dedup:
one non-terminal case per anchor. Snapshot the candidate's risk score + reasons + evidence into
`evidence_json`.

**b. Evidence bundle generator.** A timestamped, immutable bundle (store as `evidence_json.bundle`
or an R2 object + reference): candidate domain, protected brand, `evidenceCapturedAt`, DNS snapshot,
WHOIS/RDAP snapshot, MX presence, TLS/cert from CT, similarity evidence (domain + any visual/text
scores already computed), abuse indicators, recommended recipients. Worker-native only — no faked
screenshots (flag as follow-up if no render service). Bundle is generated on
`customer_approval → evidence_ready`.

**c. Classification review.** Analyst/customer confirms abuse (`triage → confirmed_abuse`) or
dismisses (`false_positive`/`duplicate`), with reason. Reconcile with existing `BRAND_CLASSIFICATIONS`
— a case's confirmation should set/read the candidate's classification consistently (don't create a
divergent second source of truth).

**d. Provider/contact resolution.** Registrar abuse contact via RDAP (Worker-native HTTP). Hosting
abuse (IP→ASN→abuse) and CA contact: best-effort; if unavailable, record `unknown` — never invent a
contact. Recipients feed the `takedown_submitted` guard.

**e. Technical takedown verification (system-only, honest).** Re-probe the candidate domain: does it
still resolve? still serve the abusive content / brand keywords? MX removed? cert revoked/expired?
"Removed" = the abuse is no longer technically present. Apply the **same completeness discipline as
ASM's guard** — only conclude "gone" from a successful probe; a failed/timed-out probe DEFERS
(stays `verification_pending`, retried), never a false `resolved`. Runs on a cron follow-up sweep
(§8, register in `cron/scheduled.js` + both cron/pipeline validators).

**f. Reappearance → campaign.** When a `resolved` candidate (or a new candidate sharing IP / cert /
favicon-hash with a known one) is re-detected, link it into a `brand_abuse_campaigns` row (linked
domains/IPs/certs/favicon-hashes) and transition the case `resolved → reappeared → confirmed_abuse`
(increment `reopened_count`, notify) rather than opening an unrelated fresh case.

**g. Audit + notification.** Every transition writes a `managed_case_events` row + an audit event
(`actor_type` customer/analyst/system) + a `notification_events` row for the key milestones
(case opened, approval needed, submitted, resolved, reappeared). Reuse the `asm-cases.js` helpers.

---

## 9. Frontend

A **Brand Takedown Cases** panel in the Brand Protection area (style-match the ASM Managed Cases
panel + DMARC ChangeReviewQueue): case list with candidate domain + risk + status, evidence-bundle
view, confirm/dismiss, the customer-approval action, submission-recording, follow-up status,
reappearance/campaign indicator. Add `api.js` methods (list/detail/transition/approve/record-submission).
Hidden/empty when no cases.

---

## 10. Guardrails (non-negotiable)

- Additive migrations only; enums in code (NO CHECK); `brand_abuse_campaigns` added to
  `WORKSPACE_PURGE_TABLES`.
- **Reuse** the generic case engine + `managed_cases` + `events.js` + `alerts.js`. Do not fork them.
- **Do not break** existing brand monitoring/classification (legacy `/brand-monitoring/*` + v1
  `/brand/*`), the registration-reality guardrail, or brand-profile scoping. Do NOT touch DMARC/ASM
  case code.
- **Registration-reality:** never open a case for an unregistered permutation (§7).
- **Verification honesty + no self-resolve:** customer/analyst can never drive `resolved`/`reappeared`;
  resolve only on a real technical re-observation; failed probe defers.
- **No overclaim:** submission is PREPARED/tracked, not auto-sent; "removed" requires technical proof.
- Customer-safe copy; `serverError` sanitisation; tenant-scoped + bound params everywhere.

---

## 11. Validation (CI-blocking, Node 24+, mirror existing `validate-*.js`)

1. `validate-brand-takedown-lifecycle.js` — the Brand machine on the generic engine (transitions,
   guards, terminal immutability) + a **DB round-trip** of the DoD flow: detected→triage→
   confirmed_abuse→customer_approval→evidence_ready→takedown_submitted→provider_followup→
   verification_pending→resolved; reappearance→campaign link + reopen; **customer-cannot-self-resolve**;
   **unregistered permutation does NOT open a case** (guardrail); evidence bundle generated with a
   timestamp; tenant scoping (two workspaces, no leakage).
2. Full gate green: `validate-managed-case-workflow.js`, `validate-regression-fixtures.js` (incl.
   purge contract), `validate-migrations.js`, `validate-tenant-isolation.js` (add brand-case routes),
   `validate-pipeline.js` + `validate-cron.js` (register the follow-up sweep), frontend build,
   `wrangler deploy --dry-run`.

---

## 12. Definition of Done (live scenario — must pass end-to-end before "Managed Brand")

1. A high-risk, registered impersonation candidate is detected (scoped to the brand profile).
2. A `brand_abuse` case opens (unregistered permutations do NOT).
3. Analyst/customer confirms abuse.
4. Customer approves takedown.
5. Evidence bundle is generated (timestamped, immutable, Worker-native contents).
6. Provider recipients resolved; submission recorded (human-sent).
7. Follow-up sweep re-checks; escalates on no-response.
8. CyberMeters technically verifies the abusive domain is gone → case `resolved` (a customer cannot).
9. The domain returns (diff IP/cert) → linked as a campaign continuation + case `reappeared`.
10. Every transition is tenant-scoped + audited with correct actor_type.

Until this passes live, do NOT say "Managed Brand Protection" — use "Brand abuse detection with
guided takedown preparation".

---

## 13. Handoff

Codex builds on a feature branch, PR with the full validation table. Claude reviews (platform reuse,
guardrails, verification honesty + no-self-resolve, registration-reality, tenant isolation, no
DMARC/ASM regression), integrates, and deploys under the standing MEDIUM-risk delegation (additive
migration to remote D1 before deploy; rollback Version ID recorded; CHANGELOG + tag). Turhan is
informed, not blocked, unless something turns HIGH risk.
