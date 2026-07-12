# Codex task brief — Phase C Packet 1: Hosted TLS-RPT

> Condensed, copy-pasteable handoff. **Full spec (source of truth):**
> [`docs/PHASE-C-PACKET-1-TLSRPT.md`](PHASE-C-PACKET-1-TLSRPT.md) — read it first.
> Owner: Codex builds · Claude reviews · Turhan approves deploy. **MEDIUM risk —
> do not deploy.**

**Branch:** `feat/hosted-tls-rpt` off `main`.

**Goal:** Let a customer host their TLS-RPT record with us via CNAME delegation —
the same "publish once, we keep it correct" flow that already exists for hosted
DMARC. `_smtp._tls.<domain>` gets published and continuously verified. **Report
ingestion is NOT in this packet** (that's Packet 2) — claim hosting +
verification only.

**~80% is reuse — do NOT rebuild:** `cfCreateHostedTxt`
(`engines/hosted-dmarc.js:183`), the write-ahead saga, `reconcileHostedIntent`,
`nextHostedDnsStatus`, removal grace, and the hourly
`runHostedDnsVerificationSweep` (`:298`) are record-type-agnostic except one
verify call at `:345`. The `hosted_dns_records` table already has `record_type`
→ **no migration**. The `tlsRptRemediation` descriptor already exists (`:832`).

## The actual work

1. Add `hostedCustomerRecordName(row)` → `_smtp._tls.${domain}` for `tlsrpt`,
   `_dmarc.${domain}` for `dmarc` (unchanged).
2. Generalise `verifyHostedDmarcRecord` (`:245`) → `verifyHostedRecord(row, opts)`
   using that resolver; keep a back-compat `verifyHostedDmarcRecord` wrapper.
   DMARC behaviour must be identical.
3. Make `hostedDnsRecordToApi` (`:155`) derive `cname_name` from the resolver and
   **null the ramp/policy/autopilot fields for `tlsrpt`**.
4. Add `buildTlsRptValue(addr)` → `v=TLSRPTv1; rua=mailto:${addr}`.
5. Slim routes in `routes/email-protection.js` at
   `/api/workspaces/:id/domains/:domain/hosted-tls-rpt(/verify)?` —
   **create/get/verify/delete only, NO PUT/ramp/autopilot** (mirror the
   hosted-dmarc block at `:191`, reuse the `pending_removal` machinery for
   DELETE). Reuse the domain's existing reporting address; provision via the
   DMARC path if none.
6. Set `tlsRptRemediation.managed_via = "hosted"` and expose the managed flow
   like `dmarcRemediation`.
7. Frontend: a "Host TLS-RPT" card mirroring the hosted-DMARC card + `api.js`
   wrappers (`getHostedTlsRpt`/`createHostedTlsRpt`/`verifyHostedTlsRpt`/
   `deleteHostedTlsRpt`).
8. **`scripts/validate-hosted-tls-rpt.js`**, CI-wired in
   `.github/workflows/ci.yml` (add a `validate` step). Cover: resolver names;
   full saga (create→pending_dns→sweep publishes→two-sided verify→connected);
   connected→CNAME removed→disconnected (loud); removal grace; tenant isolation
   (403 + no bleed); **and a dmarc row still verifying against `_dmarc.` (no
   regression)**.

## Hard guardrails

- **No DMARC regression** — the generalisation touches the shared
  verify/sweep/serialize path the live hosted-DMARC flow depends on. Existing
  DMARC behaviour and any hosted-DMARC harness must stay green.
- **No migration / no schema drift.** If you think you need a column, stop and
  flag it.
- Honest state ("Hosted & verified" only when hosted TXT live **and** customer
  CNAME chains to us), tenant-isolated, customer-safe errors (no CF/D1
  internals), autopilot off/absent for this type.

## Validation gate (all must pass before PR)

```bash
node --input-type=module --check < workers/scan-api/src/index.js
node scripts/validate-hosted-tls-rpt.js
node scripts/validate-pipeline.js
node scripts/validate-regression-fixtures.js
cd frontend && npm run build && cd ..
cd workers/scan-api && npx wrangler deploy --dry-run && cd ../..
```

## PR

Focused, one logical change. Title:
`feat(email): host TLS-RPT records via delegation (Phase C Packet 1)`.
Do not deploy (MEDIUM risk — Claude reviews, Turhan approves). Claude's review
focus: **no DMARC regression** on the shared verify/sweep path, and the harness
genuinely proving the two-sided verify + tenant isolation.
