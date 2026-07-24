# PR-5.5 Gate 5 — production cutover and live acceptance

Status: **PREPARED, NOT EXECUTED**

Gate 4 base merge: `4a1110873c193ac872e21d681f723b25345e59c7`

Production database observed 24 July 2026: migration 099 applied; migration 100 unapplied

Production Workers observed 24 July 2026:

- `cybermeters-platform`: `7d200938-a608-46c0-80b6-3827ee299239`
  (previous `9f0aa21a-1582-466f-83ba-404e2382d2fe`);
- `cybermeters-email`: `a90a59c7-5e13-41dc-90be-728f26fc2ebd`
  (previous uploaded version `ee04bee2-41ef-4319-b2c0-2132da256b76`).

Re-read deployment history at execution time. The observed IDs above are evidence,
not permission to assume that production is unchanged.

## Hard stop conditions

Do not apply migration 100 or deploy either Worker unless all of these are true:

1. The founder has approved one exact Gate 5 main SHA and the worktree contains
   that SHA.
2. CI is green on that SHA.
3. A genuine, original RFC822 (`.eml`) report from each report format actually
   received by the founder domains passes the offline preflight below.
4. The exact per-address Email Routing rules needed for acceptance exist and
   target `cybermeters-email`; no catch-all rule targets the Worker.
5. The pre-migration integrity snapshot has been saved.
6. A rollback Worker Version ID has been recorded immediately before each
   Worker deployment.

If a genuine report returns `AUDITED_REJECT`, stop before production mutation.
Record the exact `parser_reason` and limit from the tool. Tune and revalidate the
envelope in a separate reviewed change; silently losing a legitimate aggregate
report is not an accepted trade.

## Preflight evidence available now

The production inspection was read-only (`rows_written: 0` for every query).
Historical audit metadata predates Gate 5 and stores transfer-decoded attachment
size (`compressed_size`) and decoded XML/JSON size (`decompressed_size`). It does
**not** store raw RFC822 size, base64-encoded length, MIME part count, or nesting.
Those dimensions cannot be reconstructed honestly from D1 report rows.

| Domain / type | Received evidence | Raw RFC822 max | Encoded attachment max | Transfer-decoded attachment max | Decoded body max | Nested multipart | Preflight |
| --- | --- | ---: | ---: | ---: | ---: | --- | --- |
| `blackbullbarbers.co.uk` DMARC | 6 genuine provider receipts, 10–22 July (Google, Microsoft, Yahoo); one additional controlled E2E receipt | Not historically recorded | Not historically recorded | 778 bytes for genuine reports; 1,160 bytes including E2E | 2,157 bytes | Not historically recorded | **BLOCKED pending original `.eml`** |
| `blackbullbarbers.co.uk` TLS-RPT | No stored/received reports | n/a | n/a | n/a | n/a | n/a | No real sample exists |
| `cybermeters.com` DMARC | No stored/received reports | n/a | n/a | n/a | n/a | n/a | **BLOCKED: no delivery path/sample** |
| `cybermeters.com` TLS-RPT | No stored/received reports | n/a | n/a | n/a | n/a | n/a | No real sample exists |

Additional routing finding: the active `cybermeters.com` RUA endpoint is
published by its hosted DMARC record, but D1 says `cloudflare_route_status =
'not_configured'`, it has never received a report, and a read-only Cloudflare
Email Routing listing contains no literal rule for that endpoint. This is an
existing monitoring-loss blocker for the `cybermeters.com` live acceptance.
The active `blackbullbarbers.co.uk` endpoint has a literal per-address Worker
rule. Cloudflare's catch-all rule is disabled and drops rather than invoking the
Worker.

No original report was present in the repository or connected founder mailbox.
Consequently the 4 MiB raw / 3 MiB encoded / 2 MiB decoded limits are promising
against the stored decoded-size evidence, but **not yet proven envelope-fit**.

Gate 5 adds safe size/nesting fields to future successful receipt audits:
`raw_email_size`, `encoded_attachment_size`, `compressed_size`,
`decompressed_size`, `mime_part_count`, and `nested_multipart`. It stores no raw
email or report body.

### Founder-safe offline report preflight

Obtain the provider's original message with “Download original” / “Save as
`.eml`”. Do not use a forwarded or copied message: a mail client may add nested
multipart structure that the provider did not send. If an exact per-address
route must be temporarily forwarded to a founder-controlled mailbox to capture
one report, change only that literal address, never enable catch-all, record the
old action first, and restore/verify it immediately after capture. That routing
change requires separate founder action; this preparation PR performs none.

From the repository root:

```bash
node scripts/preflight-real-aggregate-report.js \
  --file /absolute/path/provider-report.eml \
  --expect-domain blackbullbarbers.co.uk
```

Expected success:

```json
{
  "mode": "offline_read_only",
  "production_mutated": false,
  "outcome": "PASS",
  "nested_multipart": false
}
```

The full output gives raw, encoded, transfer-decoded, and decoded-body bytes
alongside all named limits. `AUDITED_REJECT` means the real inbound handler
would take its required append-only terminal audit path; it does not mean this
offline tool wrote an audit row.

Retain only the numeric output needed for acceptance. Treat the `.eml` as
sensitive evidence and do not commit it.

## Ordered production cutover — founder executes

All commands below assume the repository root unless a `cd` is shown. Migration
100 must precede **both** Worker deployments.

### 0. Freeze the exact release and repeat the blockers

```bash
git fetch origin
git switch main
git pull --ff-only origin main
git rev-parse HEAD
git status --short
gh pr checks <GATE5_PR_NUMBER>
node scripts/preflight-real-aggregate-report.js \
  --file /absolute/path/provider-report.eml \
  --expect-domain blackbullbarbers.co.uk
```

Set the approved SHA without reusing a system variable:

```bash
GATE5_MAIN_SHA="$(git rev-parse HEAD)"
```

Stop if the preflight is not `PASS`, CI is not green on
`$GATE5_MAIN_SHA`, or the worktree contains anything other than the founder's
known local files.

Run the focused release gate:

```bash
node scripts/validate-gate5-cutover-prep.js
node scripts/validate-inbound-email-authority-containment.js
node scripts/validate-email-ingest-reliability.js
node scripts/validate-email-parser-hardening.js
node scripts/validate-email-worker.js
node scripts/validate-email-worker-deploy-traceability.js
node scripts/validate-q7-dmarc-report-trust.js
node scripts/validate-dmarc-xml-safety.js
node scripts/validate-tlsrpt-ingest.js
node scripts/validate-migrations.js
node --check workers/scan-api/src/index.js
node --check workers/email-ingest/src/index.js
git diff --check
```

### 1. Apply migration 100

First capture one scalar pre-state row. Keep the output with the release record:

```bash
cd workers/scan-api
npx wrangler d1 execute cybermeters-db --remote --command="SELECT
  (SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN
    ('idx_scans_one_active_per_workspace_domain',
     'idx_scans_one_active_per_domain_null_ws')) AS migration_099_indexes,
  (SELECT COUNT(*) FROM pragma_table_info('tlsrpt_aggregate_reports')
    WHERE name='source') AS tlsrpt_source_columns,
  (SELECT COUNT(*) FROM sqlite_master WHERE type='table'
    AND name='aggregate_report_ingest_claims') AS claim_tables,
  (SELECT COUNT(*) FROM dmarc_aggregate_reports) AS dmarc_reports,
  (SELECT COALESCE(SUM(length(id)+length(COALESCE(raw_hash,''))+
    record_count+message_count),0) FROM dmarc_aggregate_reports) AS dmarc_signature,
  (SELECT COUNT(*) FROM dmarc_aggregate_records) AS dmarc_records,
  (SELECT COUNT(*) FROM tlsrpt_aggregate_reports) AS tlsrpt_reports,
  (SELECT COALESCE(SUM(length(id)+length(COALESCE(raw_hash,''))+
    failure_count+total_successful_sessions+total_failure_sessions),0)
    FROM tlsrpt_aggregate_reports) AS tlsrpt_signature,
  (SELECT COUNT(*) FROM tlsrpt_failure_details) AS tlsrpt_failures"
```

Required pre-state: `migration_099_indexes=2`,
`tlsrpt_source_columns=0`, `claim_tables=0`.

Apply the exact additive migration:

```bash
npx wrangler d1 execute cybermeters-db \
  --remote \
  --file=../../database/migrations/100-aggregate-report-ingest-state.sql
```

Verify schema, backfill, and 099 integrity:

```bash
npx wrangler d1 execute cybermeters-db --remote --command="SELECT
  (SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN
    ('idx_scans_one_active_per_workspace_domain',
     'idx_scans_one_active_per_domain_null_ws')) AS migration_099_indexes,
  (SELECT COUNT(*) FROM pragma_table_info('tlsrpt_aggregate_reports')
    WHERE name='source' AND [notnull]=1 AND dflt_value='''inbound_email''')
    AS tlsrpt_source_columns,
  (SELECT COUNT(*) FROM sqlite_master WHERE type='table'
    AND name='aggregate_report_ingest_claims') AS claim_tables,
  (SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN
    ('idx_aggregate_report_ingest_identity',
     'idx_aggregate_report_ingest_report',
     'idx_aggregate_report_ingest_repair')) AS claim_indexes,
  (SELECT COUNT(*) FROM dmarc_aggregate_reports) AS dmarc_reports,
  (SELECT COALESCE(SUM(length(id)+length(COALESCE(raw_hash,''))+
    record_count+message_count),0) FROM dmarc_aggregate_reports) AS dmarc_signature,
  (SELECT COUNT(*) FROM dmarc_aggregate_records) AS dmarc_records,
  (SELECT COUNT(*) FROM tlsrpt_aggregate_reports) AS tlsrpt_reports,
  (SELECT COALESCE(SUM(length(id)+length(COALESCE(raw_hash,''))+
    failure_count+total_successful_sessions+total_failure_sessions),0)
    FROM tlsrpt_aggregate_reports) AS tlsrpt_signature,
  (SELECT COUNT(*) FROM tlsrpt_failure_details) AS tlsrpt_failures,
  (SELECT COUNT(*) FROM dmarc_aggregate_reports r LEFT JOIN
    aggregate_report_ingest_claims c ON c.report_type='dmarc'
    AND c.report_id=r.id WHERE c.id IS NULL) AS dmarc_missing_claims,
  (SELECT COUNT(*) FROM tlsrpt_aggregate_reports r LEFT JOIN
    aggregate_report_ingest_claims c ON c.report_type='tlsrpt'
    AND c.report_id=r.id WHERE c.id IS NULL) AS tlsrpt_missing_claims"
```

Required post-state:

- `migration_099_indexes=2`, `tlsrpt_source_columns=1`,
  `claim_tables=1`, `claim_indexes=3`;
- the five report/child counts and both signatures exactly equal pre-state;
- both `*_missing_claims=0`.

Stop on any mismatch; do not deploy. Operational rollback is to leave this
additive, backwards-compatible schema unused while investigating. If physical
rollback is explicitly founder-authorised before either new Worker runs, the
migration's documented inverse is:

```sql
DROP TABLE IF EXISTS aggregate_report_ingest_claims;
ALTER TABLE tlsrpt_aggregate_reports DROP COLUMN source;
```

Do not run that destructive inverse after either new Worker has accepted a
report. Restore Workers first and preserve evidence.

### 2. Deploy `cybermeters-platform` / scan-api

Record the current 100% version as `SCAN_ROLLBACK_VERSION` before deploy:

```bash
npx wrangler deployments list --json
grep -n '^workers_dev = true$' wrangler.toml
npx wrangler deploy --dry-run
```

`workers_dev = true` must be present. Copy the current 100% version ID from the
deployment listing, then:

```bash
SCAN_ROLLBACK_VERSION="<CURRENT_100_PERCENT_VERSION_ID>"
npx wrangler deploy \
  --message "PR-5.5 Gates 1-4 cutover ${GATE5_MAIN_SHA}"
npx wrangler deployments list --json
```

Record `SCAN_LIVE_VERSION` from the new 100% deployment. Verify both hosts:

```bash
curl -sS https://api.cybermeters.com/health | jq -e \
  --arg id "$SCAN_LIVE_VERSION" '.deployment_id==$id'
curl -sS https://cybermeters-platform.ttrnn47.workers.dev/health | jq -e \
  --arg id "$SCAN_LIVE_VERSION" '.deployment_id==$id'
curl -sS https://api.cybermeters.com/ready | jq -e \
  '.status=="ready" and .checks.d1==true and .checks.r2==true'
curl -sS https://cybermeters-platform.ttrnn47.workers.dev/ready | jq -e \
  '.status=="ready" and .checks.d1==true and .checks.r2==true'
curl -sS -o /dev/null -w '%{http_code}\n' \
  https://api.cybermeters.com/api/workspaces
curl -sS -o /dev/null -w '%{http_code}\n' \
  https://cybermeters-platform.ttrnn47.workers.dev/api/workspaces
```

Both protected calls must print `401`. On failure:

```bash
npx wrangler rollback "$SCAN_ROLLBACK_VERSION" \
  --message "Rollback PR-5.5 Gate 5 scan-api acceptance failure" --yes
```

Re-run health/ready and stop. Do not deploy the email Worker.

### 3. Deploy `cybermeters-email`

This is the first code-bundle deployment since 8 July; the observed live version
is the stale `a90a59c7-…` secret deployment. From the repository root:

```bash
node scripts/validate-email-worker.js
node scripts/validate-email-worker-deploy-traceability.js
cd workers/email-ingest
grep -n '^workers_dev = true$' wrangler.toml
grep -n '^APP_VERSION = "2026.07.24-gate4\.' wrangler.toml
npm run dry-run
../scan-api/node_modules/.bin/wrangler deployments list --json \
  --config wrangler.toml
```

The standalone Worker validator must prove the mandatory shared
`consumeApiRateLimit`/`rateLimitScopeId` injection, including its flood and
TLS-RPT paths. The traceability validator must prove the APP_VERSION suffix
matches the effective shared-source import closure. `workers_dev = true` must be
explicit.

Copy the current 100% version, then deploy only this Worker with the pinned local
Wrangler:

```bash
EMAIL_ROLLBACK_VERSION="<CURRENT_100_PERCENT_VERSION_ID>"
../scan-api/node_modules/.bin/wrangler deploy \
  --config wrangler.toml \
  --message "PR-5.5 Gates 3A-4 email cutover ${GATE5_MAIN_SHA}"
../scan-api/node_modules/.bin/wrangler deployments list --json \
  --config wrangler.toml
```

Record `EMAIL_LIVE_VERSION`, then:

```bash
curl -sS https://cybermeters-email.ttrnn47.workers.dev/health | jq -e \
  --arg id "$EMAIL_LIVE_VERSION" \
  '.status=="ok" and .service=="cybermeters-email" and
   .deployment_id==$id and (.version|startswith("2026.07.24-gate4."))'
curl -sS https://cybermeters-email.ttrnn47.workers.dev/ready | jq -e \
  '.status=="ready" and .checks.d1==true'
curl -sS -o /dev/null -w '%{http_code}\n' \
  https://cybermeters-email.ttrnn47.workers.dev/api/workspaces
```

The protected/nonexistent route must be `404`; this Worker deliberately exposes
only `/health` and `/ready`. On failure:

```bash
../scan-api/node_modules/.bin/wrangler rollback "$EMAIL_ROLLBACK_VERSION" \
  --config wrangler.toml \
  --message "Rollback PR-5.5 Gate 5 email acceptance failure" --yes
```

Re-run email health/ready and stop.

## Founder live acceptance A — forged report has no authority

This procedure must use a founder-controlled domain and mailbox. It must not
alter third-party DNS, unrelated customer data, or the authority gate.

`cybermeters.com` is the only current founder domain that has a real hosted-DMARC
record against which a DNS non-change is meaningful. Its exact literal RUA
Email Routing rule is currently absent, so this acceptance is **blocked** until
the founder separately creates/verifies that one per-address Worker rule. Never
use a catch-all. `blackbullbarbers.co.uk` can prove observational ingestion but
cannot prove DNS non-change because it has no hosted-DMARC record.

1. Record a UTC start time, the hosted row, public TXT answers, and authoritative
   event watermark:

```bash
GATE5_ACCEPTANCE_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cd workers/scan-api
npx wrangler d1 execute cybermeters-db --remote --command="SELECT
  id, workspace_id, domain, hosted_name, current_value, previous_value,
  status, autopilot, pass_rate_at_change, pending_value, pending_since,
  last_change_at, updated_at
  FROM hosted_dns_records WHERE domain='cybermeters.com'
  AND record_type='dmarc'"
curl -sS -H 'accept: application/dns-json' \
  'https://cloudflare-dns.com/dns-query?name=_dmarc.cybermeters.com&type=TXT'
```

2. Resolve the active endpoint address from D1; verify the Cloudflare rule is a
   literal `to` match for exactly that address and its sole action is Worker
   `cybermeters-email`.

```bash
npx wrangler d1 execute cybermeters-db --remote --command="SELECT
  address_local || '@reports.cybermeters.com' AS acceptance_address,
  cloudflare_route_status, cloudflare_route_id
  FROM dmarc_ingest_endpoints
  WHERE domain='cybermeters.com' AND status='active'"
```

3. Generate two strict, unique attachments. The script never sends them:

```bash
cd ../..
node scripts/generate-gate5-forged-rua-fixture.js \
  --domain cybermeters.com --scenario fail \
  --output /tmp/gate5-forged-fail.xml
node scripts/generate-gate5-forged-rua-fixture.js \
  --domain cybermeters.com --scenario pass \
  --output /tmp/gate5-forged-pass.xml
```

Record both printed report IDs. From the founder-controlled mailbox, send two
new messages to the exact acceptance address, attaching one XML file per
message. Do not forward an unrelated email and do not send to any other
workspace.

4. Confirm both are observational, complete, and audited. Replace the two
   placeholders:

```bash
cd workers/scan-api
npx wrangler d1 execute cybermeters-db --remote --command="SELECT
  r.external_report_id, r.source, c.source_scope, c.ingest_state,
  c.completed_at, r.record_count, r.message_count
  FROM dmarc_aggregate_reports r
  JOIN aggregate_report_ingest_claims c
    ON c.report_type='dmarc' AND c.report_id=r.id
  WHERE r.domain='cybermeters.com'
    AND r.external_report_id IN ('<FAIL_REPORT_ID>','<PASS_REPORT_ID>')"
npx wrangler d1 execute cybermeters-db --remote --command="SELECT
  event_type, created_at, metadata_json
  FROM audit_events
  WHERE event_type='dmarc_inbound_email_received'
    AND json_extract(metadata_json,'$.domain')='cybermeters.com'
    AND created_at >= '<ACCEPTANCE_START_UTC>'
  ORDER BY created_at"
node --input-type=module -e \
  "import { buildAggregateReportTrustSemantics as b } from './src/lib/dmarc-authority.js'; const r=b({source:'inbound_email',claimedDomain:'cybermeters.com'}); console.log(JSON.stringify(r,null,2)); if(r.authoritative_eligible||r.external_automation_eligible) process.exit(1)"
```

Required: both rows are `source=inbound_email`,
`source_scope=observational`, `ingest_state=complete`; both receipt audits carry
the honest observational transport semantics; the helper prints both authority
booleans `false`.

5. Allow one full hosted-DMARC scheduled sweep (up to 70 minutes), then repeat
   the hosted-row and public-DNS queries from step 1 and inspect authoritative
   events:

```bash
npx wrangler d1 execute cybermeters-db --remote --command="SELECT
  event_type, entity_id, created_at, metadata_json
  FROM audit_events
  WHERE workspace_id=(SELECT workspace_id FROM hosted_dns_records
    WHERE domain='cybermeters.com' AND record_type='dmarc' LIMIT 1)
    AND event_type IN
      ('hosted_dmarc_policy_changed','hosted_dmarc_rolled_back',
       'hosted_dmarc_impact_regression','hosted_dmarc_change_aborted')
    AND created_at >= '<ACCEPTANCE_START_UTC>'
  ORDER BY created_at"
```

PASS requires:

- byte-for-byte unchanged `current_value`, `previous_value`, `pending_value`,
  `last_change_at`, and public `_dmarc`/hosted TXT answer;
- zero new policy-change, rollback, impact-regression, or change-aborted events;
- no auto-rollback and no autopilot advance;
- the two reports remain visible only as observational inbound evidence.

Do not enable autopilot for this test. Gate 2 intentionally makes the external
automation source set empty; changing customer DNS settings to manufacture a
trigger would make this test unsafe.

## Founder live acceptance B — genuine RUA is not false-rejected

Use the next fresh report sent by a real provider to the active literal
`blackbullbarbers.co.uk` endpoint (or `cybermeters.com` after its literal route
blocker is resolved). Do not replay an already-ingested report: it should
correctly dedupe rather than demonstrate a new pending-to-complete claim.

1. Record the UTC start time and latest report/audit IDs.
2. Wait for a new genuine provider report. Do not send or modify a third party's
   report.
3. Query the new report and claim:

```bash
cd workers/scan-api
npx wrangler d1 execute cybermeters-db --remote --command="SELECT
  r.id, r.external_report_id, r.source, r.created_at,
  c.id AS claim_id, c.source_scope, c.ingest_state, c.failure_code,
  c.created_at AS claim_created_at, c.completed_at,
  r.record_count,
  (SELECT COUNT(*) FROM dmarc_aggregate_records x
    WHERE x.report_id=r.id) AS persisted_records
  FROM dmarc_aggregate_reports r
  JOIN aggregate_report_ingest_claims c
    ON c.report_type='dmarc' AND c.report_id=r.id
  WHERE r.domain='<FOUNDER_DOMAIN>'
    AND r.source='inbound_email'
    AND r.created_at >= '<ACCEPTANCE_START_UTC>'
  ORDER BY r.created_at DESC LIMIT 5"
npx wrangler d1 execute cybermeters-db --remote --command="SELECT
  event_type, created_at, metadata_json
  FROM audit_events
  WHERE created_at >= '<ACCEPTANCE_START_UTC>'
    AND json_extract(metadata_json,'$.domain')='<FOUNDER_DOMAIN>'
    AND event_type IN
      ('dmarc_inbound_email_received','dmarc_inbound_email_dropped',
       'aggregate_report_inbound_transient_failure',
       'dmarc_report_ingest_failed')
  ORDER BY created_at"
```

PASS requires one new genuine report with:

- a claim whose final state is `complete`, `failure_code IS NULL`, and
  `completed_at` is set (the code-created claim began `pending` and the atomic
  D1 batch committed report rows plus the complete transition);
- `persisted_records = record_count`;
- one `dmarc_inbound_email_received` audit containing raw, encoded,
  transfer-decoded, and decoded XML sizes under their named limits,
  `nested_multipart=false`, and no terminal drop/failure for that delivery;
- normal observational customer visibility, with no authoritative outcome.

For a genuine TLS-RPT report, use the same procedure with
`tlsrpt_aggregate_reports`, `tlsrpt_failure_details`,
`report_type='tlsrpt'`, and the `tlsrpt_inbound_email_received` /
`dmarc_inbound_email_dropped` events (the shared terminal-drop event description
records the TLS-RPT kind). Neither founder domain has produced a
TLS-RPT sample yet, so TLS-RPT live acceptance remains evidence-pending rather
than falsely marked PASS.

## Rollback record

The founder release record must contain:

- approved Gate 5 main SHA;
- migration pre/post snapshots and confirmation “100 applied”;
- scan-api live and rollback Worker Version IDs;
- email-ingest live and rollback Worker Version IDs;
- `workers_dev=true` proof for both Workers;
- scan-api health/ready results on both hosts;
- email Worker health/ready result and exact APP_VERSION;
- live acceptance A/B report IDs, claim IDs, audit timestamps, and PASS/FAIL;
- any remaining blocker.

Nothing in this runbook re-enables inbound-driven automation. Gate 1/2 authority
containment remains the controlling contract.
