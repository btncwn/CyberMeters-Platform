# Hosted DNS v2 — bounded-context redesign (decision + design)

> **Decision (Turhan, 2026-07-12 — "son karar"):** Option 4. Stop the Phase C
> packet work built on `hosted_dns_records`, and instead redesign the Hosted DNS
> layer **now** as one clean bounded context. DMARC, TLS-RPT, MTA-STS and SPF all
> use the same architecture. No CHECK constraint; the record-kind enum lives in
> code. Additive migration only — **no `DROP TABLE`, no guardrail weakening.**
> This supersedes `PHASE-C-PACKET-1/2*` and `PHASE-C-HOSTED-RECORDS-DESIGN.md`
> (kept for their reuse-mapping, marked ON HOLD).

## Why (the audit trail that led here)

- The Packet 1 spec claimed "no migration needed". **Codex's audit correctly
  caught** that `hosted_dns_records` pins `record_type` with
  `CHECK (record_type IN ('dmarc'))` — `record_type='tlsrpt'` cannot be inserted.
  Good catch; the review process worked.
- Widening a CHECK in SQLite requires a full table rebuild (`DROP TABLE`), which
  two deliberate CI guards forbid (`validate-migrations.js` additive-only;
  `validate-regression-fixtures.js` purge-completeness). Weakening those to force
  a rebuild is **rejected** — a guard that stops accidental production table
  drops is worth more than convenience here.
- Root cause: `hosted_dns_records` was optimised too early around DMARC. Hosted
  DNS is now its own bounded context (DMARC → TLS-RPT → MTA-STS → SPF). Cleaning
  it up **now**, at private-beta data volume (a handful of rows), is far cheaper
  than after revenue.

## Target schema — `hosted_dns_entries` (new table, no CHECK)

Generic, record-kind agnostic. The enum is enforced in application code, not a DB
CHECK, so new kinds never need a migration again.

| column | notes |
|---|---|
| `id` | `hd-<12hex>` — DNS-safe label, doubles as the managed host label (unchanged) |
| `workspace_id` | tenant scope (FK → workspaces) |
| `domain` | customer domain (lowercase) — kept as the key the flow + `dmarc_ingest_endpoints` use |
| `record_kind` | `'dmarc' \| 'tlsrpt' \| 'mtasts' \| 'spf'` — **enum in code, no CHECK** |
| `customer_name` | the record the customer CNAMEs to us (`_dmarc.<d>`, `_smtp._tls.<d>`, …) — **stored, not derived** |
| `target_name` | our managed name they point at (`<hd-…>.dmarc.cybermeters.com`) |
| `target_value` | the TXT value we serve |
| `provider` | `'cloudflare'` — abstraction seam for future DNS providers |
| `verification_state` | `pending_dns \| awaiting_cname \| connected \| disconnected \| pending_removal` (enum in code) |
| `published_at`, `verified_at` | lifecycle timestamps |
| `created_by`, `created_at`, `updated_at` | audit |
| **saga (generic, all kinds):** `previous_value`, `pending_value`, `pending_since`, `provider_record_id` (was `cf_record_id`), `failure_count`, `last_error` | write-ahead intent + retry state |
| **dmarc-only (nullable):** `autopilot`, `pass_rate_at_change` | ramp/self-driving state — see decision below |

Indexes: `UNIQUE (workspace_id, domain, record_kind)` (one hosted record per
kind per domain) + `(verification_state)`. Added to `WORKSPACE_PURGE_TABLES`.

### DECIDED: DMARC ramp fields → nullable columns on the unified table
DMARC has ramp/autopilot/pass-rate state the other kinds don't. **v2.0 keeps
`autopilot` + `pass_rate_at_change` as nullable columns on `hosted_dns_entries`**
(ramp position itself lives in `target_value`). Simplest, lowest-risk, direct 1:1
migration. A satellite `hosted_dns_dmarc_policy` table is a later cleanup only if
the DMARC policy engine grows — not now.

## Migration strategy — additive, guard-clean, reversible

1. **New migration `071-hosted-dns-entries.sql`** — `CREATE TABLE
   hosted_dns_entries` + indexes. Additive. No `DROP TABLE`.
2. **Backfill (additive, re-runnable):** copy the existing DMARC rows with
   `INSERT OR IGNORE INTO hosted_dns_entries (...) SELECT (mapped columns) FROM
   hosted_dns_records WHERE record_type='dmarc'` — mapping `record_type→record_kind`,
   `hosted_name→target_name`, `current_value→target_value`,
   `cf_record_id→provider_record_id`, `status→verification_state`,
   `last_verified_at→verified_at`, `customer_name='_dmarc.'||domain`,
   `provider='cloudflare'`, carrying the full saga + ramp state
   (`previous_value`, `pending_value`, `pending_since`, `failure_count`,
   `last_error`, `autopilot`, `pass_rate_at_change`) 1:1. `INSERT OR IGNORE` on
   the `id` PK makes it **idempotent** — safe to re-run after deploy to sweep up
   any stragglers written between backfill and cutover. **Built for 100 customers,
   not "tiny data" assumptions** — the mapping is exhaustive and verified by a
   dedicated harness, not eyeballed.
3. **Engine:** generalise the hosted-dmarc engine to read/write
   `hosted_dns_entries` keyed by `record_kind`; `customer_name` is stored (no
   derive). The saga / `runHostedDnsVerificationSweep` / `verifyHostedRecord` /
   `hostedDnsRecordToApi` all move to the new table. DMARC behaviour identical.
4. **Retire-in-place:** `hosted_dns_records` is no longer written; it stays
   (still in `WORKSPACE_PURGE_TABLES` for its historical rows). A `DROP TABLE`
   cleanup is a **separate, explicitly-approved** future step — never bundled here.
5. **Rollback:** additive migration + old table intact → rollback = redeploy the
   prior worker (reads `hosted_dns_records`). Cutover window is a handful of
   rows in private beta; acceptable. (Dual-write is available if we want zero-gap,
   but is overkill at this volume.)

## Sequencing (each an independent, validated PR)

1. **v2.0 core** — `hosted_dns_entries` + engine generalisation + DMARC migrated
   onto it, **behaviour-identical for hosted DMARC**. This is the risky part
   (live DMARC lifecycle) — full harness parity + the existing hosted-DMARC tests
   must stay green. Ship + verify before anything else.
2. **TLS-RPT hosting** — a new `record_kind='tlsrpt'` (was Packet 1). Trivial once
   v2 exists: `customer_name='_smtp._tls.'||domain`, value
   `v=TLSRPTv1; rua=mailto:…`.
3. **TLS-RPT ingestion** — was Packet 2 (JSON parser, routing, storage, card).
4. **MTA-STS** — DNS TXT + the hosted policy-file Worker route (testing mode).
5. **Dynamic SPF** — gated, manual-review, autopilot off.

## Guardrails (unchanged from the constitution)

- **No `DROP TABLE`, no guardrail edits.** Additive only.
- **No DMARC regression** in v2.0 — the live hosted-DMARC lifecycle must behave
  identically; prove it with the existing + parity harnesses.
- **Enum in code, not DB CHECK** — new record kinds never need a migration.
- Tenant-isolated; deletion-complete (both old + new tables purged);
  customer-safe errors.

## Timing note

This lands in the **pre-revenue refactor window** (do risky structural refactors
now at zero stakes — see the standing directive). It is deliberately done before
public beta, not after. If public-beta-blocking P0 security/quality work is
competing for the same time, that keeps priority — but the Hosted DNS layer is
small and self-contained, so v2.0 is a bounded, low-collateral refactor.

## Status

**GO — building v2.0 core now** (Turhan: build the best-in-market product, no
shortcuts, assume 100 live customers). Order of work: migration + idempotent
backfill (verified by harness) → engine generalisation onto `hosted_dns_entries`
→ routes/frontend repoint (API shape preserved) → DMARC parity harness. Existing
hosted-DMARC behaviour must be identical. MEDIUM risk (additive migration +
live-feature repoint) — implement + validate + commit, **stop before deploy** for
Turhan's approval.
