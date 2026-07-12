# Phase C — Packet 1: Hosted TLS-RPT (build spec for Codex)

> **Owner:** Codex builds · Claude reviews/integrates · Turhan approves deploy.
> **Risk:** MEDIUM (hosted DNS management + Cloudflare + a shared verify path the
> live DMARC flow depends on). **Do not deploy without approval.**
> **Parent design:** `docs/PHASE-C-HOSTED-RECORDS-DESIGN.md` (TLS-RPT is step 1,
> "reuse `cfCreateHostedTxt` verbatim").

## Goal (one sentence)

Let a customer **host their TLS-RPT record with us via CNAME delegation** — the
same "publish once, we keep it correct" flow that already exists for hosted
DMARC — so `_smtp._tls.<domain>` reporting is published and continuously
verified. **Report *ingestion*/summaries are explicitly Packet 2** (see Scope).

## Why it's small: what already exists (reuse, do NOT rebuild)

- `hosted_dns_records` table is **already generalised** with a `record_type`
  column (only `'dmarc'` rows exist today). **No migration needed.**
- `cfCreateHostedTxt(env, name, content)` (`engines/hosted-dmarc.js:183`) —
  idempotent list-before-create TXT publisher. **Reuse verbatim** for the
  TLS-RPT TXT.
- Write-ahead saga (Prepare→Execute→Verify→Commit), `reconcileHostedIntent`,
  `nextHostedDnsStatus`, removal grace, per-row isolation, and the hourly
  `runHostedDnsVerificationSweep` (`:298`) are **record-type-agnostic** except
  the single verify call at `:345`.
- `tlsRptRemediation` descriptor **already exists** (`:832`, id `tls_rpt`,
  value `v=TLSRPTv1; rua=mailto:<addr>`, customer name `_smtp._tls.<domain>`).
- Reporting-address provisioning exists for DMARC (`engines/rua-routing.js`:
  `configureDmarcEndpointRoute`, `generateInboundLocalpart`,
  `safelyEnsureCloudflareEmailRoute`, table `dmarc_ingest_endpoints`,
  `RUA_INBOUND_DOMAIN` = `reports.cybermeters.com`).
- `newHostedDnsRecordId()` (`hd-<12hex>`) and `hostedDmarcSubdomain(env)` (the
  managed delegation zone) work for any record type.

## The actual work

### 1. Generalise the two DMARC-hardcoded helpers (surgical)
`engines/hosted-dmarc.js` hardcodes `_dmarc.${domain}` in two places. Introduce a
tiny resolver and thread it through — **without changing DMARC behaviour**:

```js
// Customer-side record name we expect to CNAME to our hosted name.
export function hostedCustomerRecordName(row) {
  return row.record_type === "tlsrpt"
    ? `_smtp._tls.${row.domain}`
    : `_dmarc.${row.domain}`;      // dmarc (default) — unchanged
}
```

- **`verifyHostedDmarcRecord(row)` (`:245`)** — the two-sided logic (hosted TXT
  live **and** customer name CNAMEs to our hosted name) is identical for TLS-RPT;
  only the customer name differs. Rename/generalise to
  `verifyHostedRecord(row, opts)` using `hostedCustomerRecordName(row)`, and keep
  `verifyHostedDmarcRecord` as a thin back-compat wrapper (or update the one call
  site + the DMARC route import). **The DMARC path must behave identically.**
- **Sweep call at `:345`** — already passes `row`; once verify derives the name
  from `record_type`, no change needed beyond calling the generalised function.
- **`hostedDnsRecordToApi(row)` (`:155`)** — `cname_name` is hardcoded
  `_dmarc.${domain}`; derive it from `hostedCustomerRecordName(row)`. The DMARC
  ramp/policy fields (`policy_step`, `next_step`, `autopilot`) must be **null/
  omitted for `tlsrpt`** (TLS-RPT has no policy ramp and no autopilot).

### 2. TLS-RPT value builder
```js
export function buildTlsRptValue(reportingAddress) {
  return `v=TLSRPTv1; rua=mailto:${reportingAddress}`;
}
```

### 3. Routes (`routes/email-protection.js`) — slimmer than DMARC
New path `/(api/workspaces/:id/domains/:domain/hosted-tls-rpt)(/verify)?`,
mirroring the hosted-dmarc route block (`:191`) but with **no PUT/autopilot/ramp**:
- **POST** (role `workspace:manage`): resolve-or-provision the reporting address
  (reuse the DMARC inbound provisioning; if the workspace already has a
  reporting address, reuse it), insert a `hosted_dns_records` row
  (`record_type='tlsrpt'`, `current_value=buildTlsRptValue(addr)`,
  `hosted_name=<hd-…>.<hostedDmarcSubdomain>`, `status='pending_dns'`), then let
  the sweep (or an inline `cfCreateHostedTxt`) publish it. Return
  `hostedDnsRecordToApi(row)` incl. the `cname_name`/`cname_target` the customer
  must publish.
- **GET** (role `workspace:read`): current row + connection status, or
  `{ record: null }`.
- **GET …/verify** (role `workspace:read`): live `verifyHostedRecord` result.
- **DELETE** (role `workspace:manage`): grace-protected removal via the existing
  `pending_removal` machinery (reuse — do not add a new deletion path).
- Audit every mutation (mirror the `hosted_dmarc_*` audit events with
  `hosted_tls_rpt_*`). Customer-safe errors only (no CF/D1 internals).

### 4. Remediation registry wiring
Expose the hosted flow on the existing `tls_rpt` descriptor so the UI offers
"Let us host it" like DMARC: set `managed_via: "hosted"` on `tlsRptRemediation`
and surface the managed capability the same way `dmarcRemediation` does.

### 5. Frontend (minimal, mirror hosted-DMARC card)
On the Email Protection page, add a **Host TLS-RPT** action that mirrors the
existing hosted-DMARC card: create → show the single CNAME to publish
(`_smtp._tls.<domain>` → `<hd-…>`) → live verify → "Hosted & verified" only when
the two-sided check passes. Reuse the DMARC card's states/copy patterns; no new
design system. `api.js` wrappers: `getHostedTlsRpt`, `createHostedTlsRpt`,
`verifyHostedTlsRpt`, `deleteHostedTlsRpt`.

## Scope boundary (keep the packet shippable + the promise honest)

**IN (Packet 1):** host + verify + manage the TLS-RPT record; publish the CNAME
target; "Hosted & verified" gated on the two-sided check.

**OUT (→ Packet 2 — TLS-RPT report intelligence):** ingesting the JSON TLS-RPT
reports that arrive at the mailbox, storing them, and a summary UI. TLS-RPT
reports are **JSON** (not DMARC XML) — a **separate** parser; do **not** touch
the DMARC XML path or `parseDmarcAggregateXml`. Until Packet 2, the product may
say "TLS-RPT record hosted and verified" but must **not** claim report analytics.

**OUT (later packets):** MTA-STS (Packet 3), dynamic SPF (Packet 4).

## Guardrails (must hold)

- **No DMARC regression.** The generalisation is the riskiest part — the live
  hosted-DMARC flow shares `verifyHostedRecord`, the sweep, and
  `hostedDnsRecordToApi`. The existing DMARC behaviour and any hosted-DMARC
  harness must stay byte-for-byte green.
- **Honest state.** "Hosted & verified" requires hosted TXT live **and**
  customer CNAME chains to our hosted name — same bar as DMARC.
- **Never break mail flow.** TLS-RPT is report-only (it can't bounce mail), so
  no ramp needed — but keep autopilot off/absent for this type.
- **Tenant isolation.** All rows scoped by `workspace_id`; managed names stay
  opaque `hd-…`.
- **No migration, no schema drift.** If you think you need a column, stop and
  flag it — Packet 1 should fit the existing table.

## Deliverables

1. `engines/hosted-dmarc.js` (or a new `engines/hosted-records.js` shared module):
   `hostedCustomerRecordName`, generalised `verifyHostedRecord`,
   `buildTlsRptValue`, `hostedDnsRecordToApi` record-type awareness.
2. `routes/email-protection.js`: the `hosted-tls-rpt` route block.
3. `tlsRptRemediation.managed_via = "hosted"` + registry exposure.
4. Frontend: Host TLS-RPT card + `api.js` wrappers.
5. **`scripts/validate-hosted-tls-rpt.js`** (CI-wired in `.github/workflows/ci.yml`),
   mirroring the DMARC hosted tests:
   - `hostedCustomerRecordName` returns `_smtp._tls.<domain>` for tlsrpt,
     `_dmarc.<domain>` for dmarc.
   - Saga: create → `pending_dns` → sweep publishes (stubbed CF) → two-sided
     verify (stub customer CNAME → hosted TXT) → `connected`.
   - `connected` → customer CNAME removed → `disconnected` (loud, not silent).
   - Removal grace honoured; row deleted only after CF delete confirmed.
   - Tenant isolation: non-member `403`; no cross-workspace bleed.
   - **DMARC unaffected:** a dmarc row still verifies against `_dmarc.<domain>`.

## Validation (run before PR)

```bash
node --input-type=module --check < workers/scan-api/src/index.js
node scripts/validate-hosted-tls-rpt.js
node scripts/validate-pipeline.js          # cron/sweep wiring unchanged
node scripts/validate-regression-fixtures.js
cd frontend && npm run build && cd ..
cd workers/scan-api && npx wrangler deploy --dry-run && cd ../..
```

## Acceptance criteria

- [ ] A customer can create a hosted TLS-RPT record, see the CNAME to publish,
      and reach "Hosted & verified" only when both sides resolve.
- [ ] The hourly sweep publishes/verifies/removes TLS-RPT rows alongside DMARC,
      one shared reconciler, no DMARC regression.
- [ ] `validate-hosted-tls-rpt.js` green + all existing harnesses green.
- [ ] No migration; no customer-facing CF/D1 internals; tenant-isolated.
- [ ] Product copy claims hosting+verification only — **not** report analytics
      (that's Packet 2).
