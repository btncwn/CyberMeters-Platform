# Codex task brief — Phase C Packet 2: TLS-RPT report ingestion

> Condensed, copy-pasteable handoff. **Full spec (source of truth):**
> [`docs/PHASE-C-PACKET-2-TLSRPT-INGESTION.md`](PHASE-C-PACKET-2-TLSRPT-INGESTION.md)
> — read it first. Owner: Codex builds · Claude reviews · Turhan approves deploy.
> **MEDIUM risk — do not deploy.**
> **Depends on Packet 1** (`feat/hosted-tls-rpt`) being merged: the hosted
> TLS-RPT record must point `rua=mailto:` at the domain's reporting address
> before reports flow. Build this only after Packet 1 lands on `main`.

**Branch:** `feat/tls-rpt-ingestion` off `main`.

**Goal:** Ingest the JSON TLS-RPT reports that arrive by email at
`reports.cybermeters.com`, store them per workspace+domain, and surface a
plain-English "is SMTP TLS delivery to me succeeding?" summary — mirroring the
DMARC RUA pipeline with a **separate JSON parser** (never the DMARC XML path).

## The routing problem this packet solves (read first)

TLS-RPT reports land at the **same inbound mailbox** as DMARC RUA
(`<address>@reports.cybermeters.com`, resolved via `dmarc_ingest_endpoints` →
workspace+domain). Today's `handleInboundEmail`
(`workers/scan-api/src/email/inbound.js:394`) assumes every attachment is DMARC
XML and **drops** the rest. The core of this packet is: after the endpoint is
resolved, **classify the attachment and route** — TLS-RPT JSON → new path; DMARC
XML → existing path, unchanged.

## Reuse — do NOT rebuild

Inbound plumbing in `email/inbound.js`: `parseInboundRecipient`,
`extractInboundLocalpart`, endpoint lookup, the size caps
(`RUA_ATTACHMENT_MAX_BYTES` / `RUA_DECOMPRESSED_MAX_BYTES` /
`RUA_MAX_COMPRESSION_RATIO`), `readStreamCapped`, `parseMimeParts`,
`gunzipXmlBytes` (`:105` — generalise to `gunzipBytes`, the zip-bomb/ratio guards
are exactly right for TLS-RPT), the `drop()` audit+notification helper, and
`deriveInboundReportProvenance`. Mirror `ingestDmarcReport`'s return contract
(`{ ok, duplicate, sessions, error }`) and the `dmarc_aggregate_reports` schema
shape.

## The actual work

1. **Migration `071-tlsrpt-reports.sql`** (additive, idempotent) — two tables
   mirroring `054-dmarc-sender-intelligence.sql`:
   - `tlsrpt_aggregate_reports` (one per report: workspace_id, domain, org_name,
     contact_info, external_report_id, date_range_begin/_end, policy_type
     sts|tlsa|no-policy-found, policy_domain, total_successful_sessions,
     total_failure_sessions, failure_count, raw_hash, provenance
     verified|unverified, created_at; dedup index on
     (workspace_id, domain, external_report_id)).
   - `tlsrpt_failure_details` (one per failure: report_id FK, workspace_id,
     domain, result_type, sending_mta_ip, receiving_mx_hostname, receiving_ip,
     failed_session_count, additional_info).
2. **`lib/tlsrpt-ingest.js`** (NEW, separate from dmarc-ingest.js):
   - `parseTlsRptReport(jsonString)` — `JSON.parse` in try/catch, **never eval**;
     same caps as DMARC (reject > ~2 MB decoded; cap `policies[]` /
     `failure-details[]` array lengths ~5000). Extract per RFC 8460.
   - `ingestTlsRptReport(env, { workspaceId, domain, jsonString, source,
     ingestEndpointId, domainId, enforceDomainMatch, provenance })` — enforce
     `policy-domain === endpoint.domain`, dedup by external_report_id (repeat →
     `{duplicate:true}`, change nothing), insert report + N failure rows. Forged
     header-From → ingested but `provenance='unverified'` (record-not-drop).
3. **Attachment routing (`email/inbound.js`)** — `selectTlsRptAttachment` +
   `extractTlsRptFromAttachment` mirroring the DMARC helpers (MIME
   `application/tlsrpt+gzip`/`application/tlsrpt+json`, or `.json`/`.json.gz` with
   a TLS-RPT JSON body; gunzip via shared `gunzipBytes` under existing caps). In
   `handleInboundEmail`, classify after endpoint resolution: TLS-RPT → new
   extract+ingest; else DMARC path **unchanged**. Update
   `dmarc_ingest_endpoints.last_inbound_at`; audit `tlsrpt_inbound_email_received`;
   TLS-RPT-appropriate customer-safe drop reasons.
4. **Surface** — `GET /api/workspaces/:id/domains/:domain/tls-rpt/reports`
   (`workspace:read`): recent reports + summary (total sessions, **success
   rate**, failure count, top failing result_types + receiving MX). A summary
   card on **Email Protection** (co-located with DMARC/RUA; cross-link from
   Certificates & Trust). `api.js`: `getTlsRptReports(wsId, domain)`.
   Explanation-first; no analytics claimed without data.
5. **Deletion completeness** — add `tlsrpt_aggregate_reports` and
   `tlsrpt_failure_details` to `WORKSPACE_PURGE_TABLES` (`index.js:936`).
6. **`scripts/validate-tlsrpt-ingest.js`** (CI-wired in
   `.github/workflows/ci.yml`): parse RFC 8460 samples (success-only,
   failure-only, mixed); dedup by external_report_id; `enforceDomainMatch`
   rejects a policy-domain mismatch; oversized/malformed JSON rejected;
   **routing proof** — a TLS-RPT attachment routes to TLS-RPT ingest and a DMARC
   XML still routes to DMARC (drive `handleInboundEmail` with a stub message for
   each); `provenance='unverified'` recorded for an untrusted header-From; tenant
   isolation on the read endpoint; purge empties both tables.

## Hard guardrails

- **Never touch the DMARC XML path** (`parseDmarcAggregateXml`, its tables). New
  parser, new tables, new helpers. A DMARC report must still ingest byte-for-byte
  as today — prove it in the harness.
- **Untrusted input, bounded.** Size + array caps; `JSON.parse` in try/catch; no
  eval; never throw out of `handleInboundEmail` (it already swallows — keep it).
- **Honest state + provenance.** `provenance='unverified'` for untrusted
  header-From; success-rate summaries must not imply TLS is fine when only
  failures were reported.
- **Tenant-isolated**, purge-list updated, customer-safe drops (no raw payloads /
  CF / D1 internals).
- **Migration discipline:** additive only, idempotent where SQLite allows.

## Validation gate (all must pass before PR)

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

## PR

Focused, one logical change. Title:
`feat(email): ingest TLS-RPT reports (Phase C Packet 2)`.
Do not deploy (MEDIUM risk — Claude reviews, Turhan approves). Deploy note for
later: migration 071 applies to remote D1 **before** `wrangler deploy`; confirm
which worker owns `email()` and redeploy the email worker too if the inbound
handler is shared. Claude's review focus: **no DMARC regression** (both routes
proven), bounded untrusted parsing, provenance honesty, and deletion
completeness.
