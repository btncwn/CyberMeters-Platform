# Phase C — Packet 2: TLS-RPT report ingestion (build spec for Codex)

> **Owner:** Codex builds · Claude reviews/integrates · Turhan approves deploy.
> **Risk:** MEDIUM (new inbound-email routing branch + a migration + untrusted
> report parsing). **Do not deploy without approval.**
> **Depends on:** Packet 1 (`docs/PHASE-C-PACKET-1-TLSRPT.md`) — the hosted
> TLS-RPT record must exist and point `rua=mailto:` at the domain's reporting
> address before reports flow.

## Goal (one sentence)

Ingest the **JSON TLS-RPT reports** that arrive by email at
`reports.cybermeters.com`, store them per workspace+domain, and surface a
plain-English "is SMTP TLS delivery to me succeeding?" summary — mirroring the
DMARC RUA ingestion pipeline, with a **separate JSON parser** (never the DMARC
XML path).

## The routing problem this packet solves (read first)

TLS-RPT reports arrive at the **same inbound mailbox** as DMARC RUA
(`<address>@reports.cybermeters.com`, resolved via `dmarc_ingest_endpoints`
→ workspace+domain). The current `handleInboundEmail`
(`workers/scan-api/src/email/inbound.js:394`) assumes every attachment is a
DMARC XML and **drops** anything else. So the core of this packet is: after the
endpoint is resolved, **detect report type from the attachment and route** —
TLS-RPT JSON → the new path; DMARC XML → the existing path unchanged.

Until this packet ships, TLS-RPT reports are dropped as an unrecognised
attachment (acceptable — Packet 1 claims hosting+verification only, not
analytics). Make the pre-existing drop reason neutral, not "DMARC report failed".

## Reuse (do NOT rebuild)

- Inbound plumbing in `email/inbound.js`: `parseInboundRecipient`,
  `extractInboundLocalpart`, endpoint lookup, size caps
  (`RUA_ATTACHMENT_MAX_BYTES`/`RUA_DECOMPRESSED_MAX_BYTES`/
  `RUA_MAX_COMPRESSION_RATIO`), `readStreamCapped`, `parseMimeParts`,
  `gunzipXmlBytes` (:105 — rename to `gunzipBytes`, or add a thin alias; the
  zip-bomb/ratio guards are exactly what TLS-RPT needs too), the `drop()`
  audit+notification helper, and `deriveInboundReportProvenance` (same
  header-From trust model).
- `ingestDmarcReport`'s **contract shape** to mirror:
  `{ ok, duplicate, messages/sessions, records, error }`.
- `dmarc_aggregate_reports`/`_records` **schema shape** to mirror (see below).

## The actual work

### 1. Migration (new tables — additive, idempotent)
`database/migrations/071-tlsrpt-reports.sql`, mirroring
`054-dmarc-sender-intelligence.sql`:

- **`tlsrpt_aggregate_reports`** — one row per report:
  `id` PK, `workspace_id` NOT NULL, `domain` NOT NULL, `org_name`,
  `contact_info`, `external_report_id` NOT NULL, `date_range_begin`/`_end`
  (epoch or ISO), `policy_type` (`sts`|`tlsa`|`no-policy-found`), `policy_domain`,
  `total_successful_sessions` INTEGER, `total_failure_sessions` INTEGER,
  `failure_count` INTEGER, `raw_hash`, `provenance` (`verified`|`unverified`),
  `created_at`. Dedup index on `(workspace_id, domain, external_report_id)`.
- **`tlsrpt_failure_details`** — one row per failure entry:
  `id` PK, `report_id` FK → tlsrpt_aggregate_reports, `workspace_id`, `domain`,
  `result_type` (e.g. `certificate-expired`, `starttls-not-supported`,
  `validation-failure`…), `sending_mta_ip`, `receiving_mx_hostname`,
  `receiving_ip`, `failed_session_count` INTEGER, `additional_info`.

### 2. Parser (`lib/tlsrpt-ingest.js` — NEW, separate from dmarc-ingest.js)
`parseTlsRptReport(jsonString)`:
- `JSON.parse` inside try/catch; **never eval**. TLS-RPT is JSON so there is no
  XXE risk, but treat it as fully untrusted: enforce the **same caps** as DMARC
  (reject > ~2 MB decoded; cap `policies[]` and `failure-details[]` array
  lengths, e.g. 5000). Return `{ ok:false, error }` on malformed/oversized.
- Extract per RFC 8460: `organization-name`, `date-range`
  {`start-datetime`,`end-datetime`}, `contact-info`, `report-id`, and each
  `policies[]` entry's `policy.policy-type`/`policy-domain`,
  `summary.total-successful-session-count`/`total-failure-session-count`, and
  `failure-details[]`.
- `ingestTlsRptReport(env, { workspaceId, domain, jsonString, source,
  ingestEndpointId, domainId, enforceDomainMatch, provenance })`:
  parse → **enforce domain match** (`policy-domain` must equal endpoint.domain
  when `enforceDomainMatch`) → dedup by `(workspace_id, domain,
  external_report_id)` (return `{ duplicate:true }` on repeat, change nothing) →
  insert one report row + N failure-detail rows. Mirror `ingestDmarcReport`'s
  return contract. Forged reports (header-From unverified) are still ingested but
  marked `provenance='unverified'` — auditable and purgeable, never silently
  trusted (same record-not-drop model as DMARC).

### 3. Attachment detection + routing (`email/inbound.js`)
- `selectTlsRptAttachment(parts)` + `extractTlsRptFromAttachment(filename,
  bytes, caps)` mirroring the DMARC helpers: accept MIME
  `application/tlsrpt+gzip`, `application/tlsrpt+json`, or filename `.json` /
  `.json.gz` / `.gz` whose decompressed body is a TLS-RPT JSON object; gunzip via
  the shared `gunzipBytes` under the existing caps.
- In `handleInboundEmail`, after the endpoint is resolved and provenance derived,
  **classify the attachment**: TLS-RPT → `extractTlsRptFromAttachment` +
  `ingestTlsRptReport`; otherwise the existing DMARC path, **unchanged**. On
  success update `dmarc_ingest_endpoints.last_inbound_at` (shared column) and
  audit `tlsrpt_inbound_email_received`; on failure use `drop()` with a
  TLS-RPT-appropriate, customer-safe reason.

### 4. Surface it (read endpoint + card)
- `GET /api/workspaces/:id/domains/:domain/tls-rpt/reports` (role
  `workspace:read`): recent reports + a summary — total sessions, **success
  rate**, failure count, top failing `result_type`s and receiving MX. Tenant-
  scoped; customer-safe.
- A summary card on **Email Protection** (co-located with DMARC/RUA — it's mail
  transport; cross-link from Certificates & Trust). Explanation-first: "SMTP TLS
  delivery health" — is mail to you being delivered over TLS, and where is it
  failing. `api.js`: `getTlsRptReports(wsId, domain)`.

### 5. Deletion completeness (trust — non-negotiable)
Add `tlsrpt_aggregate_reports` and `tlsrpt_failure_details` to
`WORKSPACE_PURGE_TABLES` (`index.js:936`) so workspace deletion purges them.
Verify with the existing deletion/purge harness.

## Scope boundary

**IN (Packet 2):** parse + store + dedup + surface TLS-RPT reports; route them at
ingest; delete-on-purge.

**OUT:** MTA-STS (Packet 3), dynamic SPF (Packet 4). Do **not** fold MTA-STS
policy hosting in here — TLS-RPT and MTA-STS are separate records even though
both relate to SMTP TLS.

## Guardrails (must hold)

- **Never touch the DMARC XML path.** New parser, new tables, new helpers. A
  DMARC report must still ingest byte-for-byte as today (prove it in the harness).
- **Untrusted input, bounded.** Size + array caps; `JSON.parse` in try/catch; no
  eval; never throw out of the email handler (`handleInboundEmail` already
  swallows — keep it that way).
- **Honest state + provenance.** `provenance='unverified'` for reports whose
  header-From we can't trust; success-rate summaries must not imply TLS is fine
  when only failures were reported.
- **Tenant isolation.** Every row scoped by `workspace_id`; read endpoint scoped;
  purge-list updated.
- **Customer-safe drops.** No raw payload, no CF/D1 internals; neutral reasons.

## Deliverables

1. `database/migrations/071-tlsrpt-reports.sql` (2 tables, additive).
2. `lib/tlsrpt-ingest.js` — `parseTlsRptReport`, `ingestTlsRptReport`.
3. `email/inbound.js` — `selectTlsRptAttachment`, `extractTlsRptFromAttachment`,
   `gunzipBytes` (generalised), the routing branch in `handleInboundEmail`.
4. Read route `tls-rpt/reports` + Email Protection card + `api.js` wrapper.
5. `WORKSPACE_PURGE_TABLES` updated.
6. **`scripts/validate-tlsrpt-ingest.js`** (CI-wired), mirroring the DMARC ingest
   tests:
   - Parse a real RFC 8460 sample (success-only, failure-only, mixed policies).
   - Dedup by `external_report_id`; second import changes nothing.
   - `enforceDomainMatch` rejects a report whose `policy-domain` ≠ endpoint.
   - Oversized JSON + oversized arrays rejected; malformed JSON → `{ok:false}`.
   - **Routing:** a TLS-RPT attachment routes to TLS-RPT ingest; a DMARC XML
     still routes to DMARC (no regression) — drive `handleInboundEmail` with a
     stub message for each.
   - `provenance='unverified'` recorded for an untrusted header-From.
   - Tenant isolation on the read endpoint (non-member 403; no cross-ws bleed).
   - Purge: both tables emptied by workspace purge.

## Validation (run before PR)

```bash
node --input-type=module --check < workers/scan-api/src/index.js
node scripts/validate-tlsrpt-ingest.js
node scripts/validate-dmarc-xml-safety.js     # DMARC parser unchanged
node scripts/validate-email-lifecycle.js      # inbound handler regression
node scripts/validate-regression-fixtures.js
node scripts/validate-migrations.js
cd frontend && npm run build && cd ..
cd workers/scan-api && npx wrangler deploy --dry-run && cd ../..
```
Deploy (on approval): apply migration 071 to remote D1 **before** `wrangler
deploy`; the email worker (`cybermeters-email`) also redeploys if the inbound
handler is shared — confirm which worker owns `email()` and deploy both if so.

## Acceptance criteria

- [ ] A hosted-TLS-RPT domain's inbound JSON reports are parsed, stored, deduped,
      and attributed to the right workspace+domain.
- [ ] The Email Protection card shows SMTP TLS delivery health (success rate +
      top failures) in plain English; no report analytics claimed without data.
- [ ] DMARC ingestion is byte-for-byte unchanged (harness proves both routes).
- [ ] Migration 071 additive; both tables in the purge list; tenant-isolated.
- [ ] No raw payloads or internals in customer-facing surfaces or drops.
