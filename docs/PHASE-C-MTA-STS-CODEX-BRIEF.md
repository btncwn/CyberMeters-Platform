# Codex task brief — MTA-STS (guided-hybrid) on the Hosted DNS v2 foundation

> Owner: Codex builds · Claude reviews · Turhan approves deploy. **MEDIUM risk.**
> Decision (Turhan): **Option A — guided-hybrid MTA-STS.** No Cloudflare-for-SaaS
> / custom-hostname infra in this packet (that is a separate, post-beta packet).
> Build on the additive `hosted_dns_entries` bounded context; keep DMARC + TLS-RPT
> parity and every existing guardrail intact.

## The founder's directive (authoritative scope — build exactly this)

Proceed with Option A: guided-hybrid MTA-STS. Build it on the new additive
hosted-records bounded context and keep the existing guardrails intact.

1. Host and manage **only** the `_mta-sts.<domain>` TXT record through the
   existing delegation model using `record_kind='mtasts'`.
2. Generate a standards-compliant MTA-STS policy from the domain's **live MX**
   records.
3. Default strictly to `mode: testing`. Do **not** implement automatic or default
   `enforce`.
4. Provide the customer with the exact HTTPS policy-file content and required path:
   `https://mta-sts.<customer-domain>/.well-known/mta-sts.txt`
5. Verify DNS TXT and HTTPS policy **independently** (two separate states).
6. Do **not** show "configured", "protected", "hosted", or equivalent success
   wording unless the relevant state is genuinely verified.
7. Make the product boundary explicit in the UI:
   *"CyberMeters manages the MTA-STS DNS policy ID. Your organisation or web
   provider hosts the HTTPS policy file."*
8. Preserve DMARC and TLS-RPT parity and keep all migrations **additive**.
9. Add tenant-isolation, serialization, verification, lifecycle, and regression tests.
10. Do **not** introduce Cloudflare-for-SaaS / custom-hostname infrastructure.
11. Do **not** begin Dynamic SPF as part of this work.

**Stop and report** if implementation requires a destructive migration, a hidden
infrastructure dependency, or any change that could affect customer email delivery.
Deliver implementation + validation evidence + commit + deployment plan, **but do
not deploy** until all existing DMARC, TLS-RPT, migration, regression, and
frontend-build checks are green.

## Explicit DO-NOTs (founder)
- Do not show state as "hosted"/"protected" before the customer's policy file is published + verified.
- Do not use `mode: enforce` directly (testing only in this packet).
- Do not silently change the policy when MX changes — surface drift, require explicit action.
- Do not bump the TXT `id` before the policy is verified.
- Do not present MTA-STS and TLS-RPT as the same thing.
- Do not jump to Dynamic SPF.

## Codebase anchors (reuse — don't reinvent)

- **Foundation:** `hosted_dns_entries` (record_kind, customer_name, target_name,
  target_value, verification_state, provider_record_id, saga fields). **No CHECK**
  → `record_kind='mtasts'` inserts already work. The DNS-TXT half needs **no
  migration**.
- **DNS TXT hosting:** reuse the whole delegation model in
  `engines/hosted-dmarc.js` — `cfCreateHostedTxt`, the write-ahead saga,
  `runHostedDnsVerificationSweep`, `nextHostedDnsStatus`, `HOSTED_DNS_ENTRY_SELECT`.
  Extend `hostedCustomerRecordName(domain, recordKind)` (already returns
  `_smtp._tls.` for tlsrpt) to return `_mta-sts.<domain>` for `mtasts`. The TXT
  value is `v=STSv1; id=<unix-ts>`.
- **Two-sided DNS verify:** `verifyHostedDmarcRecord(row)` is already kind-aware
  (reads the stored `customer_name`) — it verifies the `_mta-sts` CNAME→hosted TXT
  exactly like DMARC/TLS-RPT. This is verification state #1.
- **Policy generation:** `mtaStsRemediation.generate()` (`hosted-dmarc.js:889`)
  already builds the policy from MX: `version: STSv1 / mode: testing / mx: … /
  max_age: 604800`. Extract this into a reusable `buildMtaStsPolicy(domain, mxHosts)`
  + `buildMtaStsTxtValue(id)`; keep `mode: testing`.
- **Live MX:** `dnsQuery(domain, "MX")` (see `engines/dns-scan.js:30`) → parse the
  `Answer` MX exchanges into `mxHosts`; fall back to `*.<domain>` if none (as the
  descriptor does).
- **HTTPS policy probe (verification state #2):** `fetchMtaSts(domain)`
  (`engines/email-intel.js:110`) fetches `https://mta-sts.<domain>/.well-known/
  mta-sts.txt`. Use it (or an equivalent bounded fetch) to check the policy is
  reachable + a valid `STSv1` policy — **independently** from the TXT check.
- **Routes to mirror:** the `/hosted-tls-rpt` block in
  `routes/email-protection.js` (create/get/verify/delete) — MTA-STS adds the
  policy content + path to the response and a second verification field. No ramp,
  no autopilot.
- **Frontend:** mirror `ManagedTlsRptCard` in
  `pages/ws/WorkspaceEmailProtectionPage.jsx` → `ManagedMtaStsCard`, showing the
  **two independent states**, the policy file to publish + its path, and the
  explicit boundary text from directive #7. `api.js` wrappers.

## Policy storage (additive only)
To honour "don't silently change when MX changes" + "don't bump id before the
policy is verified", the generated policy must be **pinned at creation**, not
regenerated live. Store the generated policy content additively — a nullable
column (e.g. `policy_content`) on `hosted_dns_entries` via an **additive** ALTER
(migration 073, ADD COLUMN only — never DROP), or a small satellite table. Your
choice; additive only. On MX drift, surface "your MX changed — review and
republish" rather than mutating the stored policy or bumping the id automatically.

## Verification model (two independent states — never conflate)
- `dns_txt`: `pending_dns → awaiting_cname → connected` (existing saga/sweep).
- `https_policy`: `not_published → reachable_valid` (from the HTTPS probe;
  `reachable_invalid` if fetched but not a valid STSv1 policy).
- Only when **both** are green may the UI say the MTA-STS setup is complete —
  and even then, label it "MTA-STS active in testing mode", never "enforced".

## Deliverables
1. Engine: `hostedCustomerRecordName` mtasts case; `buildMtaStsPolicy` +
   `buildMtaStsTxtValue`; an MTA-STS HTTPS verify helper.
2. `routes/email-protection.js`: `/hosted-mta-sts` (create/get/verify/delete) +
   the two-state verify. Audited, customer-safe errors.
3. (If needed) additive migration `073` for `policy_content`.
4. Frontend `ManagedMtaStsCard` + `api.js` wrappers.
5. **`scripts/validate-hosted-mta-sts.js`** (CI-wired): TXT hosting lifecycle;
   policy generated in `mode: testing` (never enforce); the two verification
   states are independent; "complete" only when both verified; MX-drift surfaces
   (no silent policy change / no id bump before verify); DMARC + TLS-RPT rows
   coexist on one domain; tenant isolation (403/401); no DMARC/TLS-RPT regression.

## Validation gate (all green before PR)
```bash
node --input-type=module --check < workers/scan-api/src/index.js
node scripts/validate-hosted-mta-sts.js
node scripts/validate-hosted-dns-v2.js
node scripts/validate-hosted-tls-rpt.js
node scripts/validate-tlsrpt-ingest.js
node scripts/validate-regression-fixtures.js
node scripts/validate-migrations.js
cd frontend && npm run build && cd ..
cd workers/scan-api && npx wrangler deploy --dry-run && cd ../..
```

## PR
Focused, one logical change. Title:
`feat(email): guided-hybrid MTA-STS (host TXT + generate policy, on hosted DNS v2)`.
Do not deploy (Claude reviews — focus: two-state honesty, testing-mode default,
additive-only, DMARC/TLS-RPT parity; Turhan approves deploy).
