# Codex build brief — Automated evidence-based sender classification engine

> Owner: Codex builds · Claude reviews · Turhan approves deploy. **MEDIUM risk.**
> The #1 gap in `docs/DMARC-MATURITY-SCORECARD.md` (Level-2 defining pillar): today
> sender "classification" is a 5-value MANUAL triage; there is no automated
> classifier. This makes the classifier real — **without breaking the manual
> override, which is the strongest existing behaviour and must be preserved.**

**Branch:** `feat/sender-classification-engine` off `main`.

## Goal (one sentence)
Compute an automated, explainable classification for every DMARC sender from the
evidence we already parse (per-method SPF/DKIM alignment, provider, volume,
pass-rate), with confidence + human-readable reasons — while the customer's manual
decision, when set, always wins and always persists across re-ingests.

## Current state (grounded — reuse, don't rebuild)
- **Manual triage today:** `email_sender_sources.classification` ∈
  `unknown | trusted | suspicious | threat | ignored`, default `unknown`
  (`lib/dmarc-ingest.js:207`, `migrations/054-dmarc-sender-intelligence.sql:97`).
  Override endpoint `POST /api/workspaces/:id/domains/:domain/email-senders/:source_id/classify`
  (`routes/email-protection.js:970`) writes `classification`+`notes`, audits
  `email_sender_classified`. **Critically:** the ingest rollup UPDATE deliberately
  OMITS `classification`/`notes` so a manual decision survives future reports
  (`lib/dmarc-ingest.js:190-199`). **This invariant is sacred — do not change it.**
- **Evidence already parsed but under-used:** per-record `spf_aligned_result`,
  `dkim_aligned_result`, raw `spf_result`/`dkim_result`
  (`lib/dmarc-ingest.js:97-105`, stored in `dmarc_aggregate_records`
  `:346-355`). But the sender rollup COLLAPSES them into one boolean
  `aligned = spf_aligned_result==="pass" || dkim_aligned_result==="pass"`
  (`:166`) → only `aligned_messages`/`failed_messages` survive. We lose the
  SPF-vs-DKIM distinction the classifier needs.
- **Provider guess:** `DMARC_PROVIDER_PATTERNS` (11 substring patterns,
  `lib/dmarc-ingest.js:115-127`) → `provider_guess`, `provider_confidence`
  (low/medium), `provider_reason`. No version stamp.
- **Serializer:** `emailSenderToApi` (`engines/rua-routing.js:126-139`);
  risk level `dmarcSenderRiskLevel` (`:28`).

## The design

### 1. Separate AUTO from MANUAL (the key architectural rule)
Do **not** repurpose the `classification` column — it stays the MANUAL field
(persists, human-owned). Add engine-owned columns via an **additive** migration
(`074-...`, ADD COLUMN only, never DROP):
- `auto_classification TEXT` — the engine's verdict (taxonomy below).
- `auto_confidence REAL` — 0..1.
- `auto_reasons TEXT` — JSON array of human strings.
- `classified_at TEXT` — set ONLY by the manual override endpoint (the "human has
  decided" signal).
- `spf_aligned_messages INTEGER NOT NULL DEFAULT 0`, `dkim_aligned_messages INTEGER
  NOT NULL DEFAULT 0` — per-sender, so SPF-alignment vs DKIM-alignment is
  recoverable.
- `provider_map_version TEXT` — stamps which provider-map version produced the guess.

**Effective classification** (API-derived, not stored): `classified_at IS NOT NULL`
→ the manual `classification` wins; else → `auto_classification`. The engine
recomputes `auto_*` on every ingest; it must **never write `classification`,
`notes`, or `classified_at`.**

### 2. Track per-method alignment in the rollup
In `updateEmailSenderSources` (`lib/dmarc-ingest.js:166`), stop collapsing: count
`spf_aligned_messages` (spf_aligned_result==="pass") and `dkim_aligned_messages`
(dkim_aligned_result==="pass") separately, in addition to the existing
`aligned_messages` (either) / `failed_messages`. Additive UPDATE columns.

### 3. The classifier — pure, deterministic, explainable
New `engines/sender-classification.js`:
`classifySender(evidence) -> { classification, confidence, reasons }`, where
`evidence = { total_messages, spf_aligned_messages, dkim_aligned_messages,
aligned_messages, failed_messages, provider_guess, provider_confidence,
header_from, protected_domain }`.

Taxonomy (exact values — the report's set): `authorised | likely_authorised |
forwarder | mailing_list | misconfigured | unknown | suspicious | unauthorised`.

Rules (ordered; each returns reasons[] interpolating the ACTUAL numbers, and a
confidence reflecting evidence strength — **never high-confidence without
evidence; low-volume/low-evidence → `unknown`**). Thresholds as a named const
object at the top (config-ready):
- **`unknown`** if `total_messages < MIN_VOLUME` (e.g. 5) or no signal — low conf.
- **`authorised`** — both SPF *and* DKIM aligned at high rate (both ≥ ALIGN_HIGH
  e.g. 98%) AND a recognised provider — high conf.
- **`likely_authorised`** — aligned via exactly one method at ≥ ALIGN_HIGH (+
  provider) but not both — medium conf.
- **`forwarder`** — DKIM-aligned but SPF-not-aligned across most messages (classic
  forwarding signature: `dkim_aligned_rate` high, `spf_aligned_rate` low) — medium.
- **`mailing_list`** — recognised ESP/list provider (mailchimp/sendgrid/constant
  contact/google-groups patterns) with the list signature — medium.
- **`misconfigured`** — recognised provider but low alignment at meaningful volume
  (looks legit, failing DMARC alignment) — medium.
- **`unauthorised`** — fails SPF+DKIM alignment, no provider, and `header_from`
  claims the protected domain (spoofing signature) — medium/high.
- **`suspicious`** — fails with no provider + no alignment but not clearly claiming
  the domain — low/medium.

Keep it heuristic and HONEST: confidence is evidence-proportional; the reasons[]
must let a human see exactly why (e.g. "DKIM aligned on 12,190 of 12,481 messages;
SPF alignment failed — consistent with a forwarder.").

### 4. Wire it in
- At the end of ingest (after `updateEmailSenderSources`), recompute `auto_*` for
  the affected senders (or a `classifyWorkspaceDomainSenders(env, workspaceId,
  domain)` pass). Idempotent.
- Stamp `provider_map_version = PROVIDER_MAP_VERSION`.
- Optionally a `POST .../email-senders/reclassify` (manage) to recompute on demand.

### 5. Surface it
`emailSenderToApi` (`rua-routing.js:126`) returns: `auto_classification`,
`auto_confidence`, `auto_reasons`, `spf_aligned` + `dkim_aligned` rates,
`classification_source` (`manual` | `auto`), and the effective classification.
Frontend sender inventory shows the verdict + confidence + reasons + per-method
alignment, with the existing manual-override control on top (unchanged), e.g.:
"Classified as Microsoft 365 · SPF aligned · DKIM aligned · 12,481 msgs (7d) ·
confidence 98%".

## Guardrails (must hold)
- **Never overwrite a manual classification** — engine writes only `auto_*` +
  alignment counts + `provider_map_version`; the human-wins-persists invariant
  (`dmarc-ingest.js:199`) stays intact and is proven by the harness.
- **Additive migration only** (ADD COLUMN, no DROP — the additive-only guard
  blocks DROP TABLE/COLUMN).
- **Honest confidence** — low evidence → `unknown`; never claim `authorised`
  without real per-method alignment evidence.
- **Tenant-isolated** — every read/write scoped by `workspace_id`.
- **Deterministic + explainable** — same evidence → same verdict + reasons.
- No new infra dependency. Do not touch the DMARC XML parser or dedupe.

## Deliverables
1. Additive migration `074-sender-auto-classification.sql`.
2. `engines/sender-classification.js` (pure `classifySender` + a persistence pass).
3. `lib/dmarc-ingest.js`: per-method alignment counts in the rollup + call the
   classifier after `updateEmailSenderSources` (never touching manual columns).
4. `engines/rua-routing.js` `emailSenderToApi`: expose the auto fields + effective
   classification + `classification_source`.
5. Frontend: sender-inventory verdict + confidence + reasons + per-method alignment
   (manual override control unchanged).
6. **`scripts/validate-sender-classification.js`** (CI-wired): pure `classifySender`
   cases for each taxonomy verdict from crafted evidence; auto recomputed on
   re-ingest; **manual override preserved AND wins over auto**; per-method
   alignment counts correct; provider-map version stamped; tenant isolation
   (a sender in ws A never visible/classified into ws B). *(This also closes the
   scorecard's "sender classification has no runtime test" + starts closing
   "DMARC absent from the isolation matrix".)*

## Validation gate (all green before PR)
```bash
node --input-type=module --check < workers/scan-api/src/index.js
node scripts/validate-sender-classification.js
node scripts/validate-dmarc-xml-safety.js      # parser untouched
node scripts/validate-regression-fixtures.js
node scripts/validate-migrations.js
node scripts/validate-tenant-isolation.js
cd frontend && npm run build && cd ..
cd workers/scan-api && npx wrangler deploy --dry-run && cd ../..
```

## PR
Focused, one logical change. Title:
`feat(email): automated evidence-based sender classification (keeps manual override)`.
Do not deploy (Claude reviews — focus: manual-override invariant preserved,
honest confidence, additive migration, tenant isolation; Turhan approves deploy).
**Stop and report** if it would require overwriting the manual `classification`
column, a destructive migration, or any change to the DMARC parser/dedupe.
