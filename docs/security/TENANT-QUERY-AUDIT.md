# CyberMeters — Static Tenant-Query Audit

> **Generated** by `scripts/security/build-tenant-query-audit-report.js`.
> CI gate: `scripts/validate-tenant-query-audit.js` (blocks on any unsuppressed
> high-signal finding or stale suppression).

The audit extracts every `.prepare()`/`.exec()` SQL statement and every R2 key
expression from the Worker source, then classifies each against the tenant-owned
table set from the isolation matrix. A statement carrying an inline tenant predicate
(`workspace_id` / `owner_user_id` / `owner_id` / `user_id` / `subscription_id`)
is **safe** and not reported. A `workspace_domains` JOIN without such a predicate
is never proof of tenant scope.

## Detectors

| Detector | Severity | Gate |
|---|---|---|
| `workspace_domain_scope_missing` | high | blocking |
| `hostname_only_ownership` | high | blocking |
| `global_latest_fallback` | high | blocking |
| `r2_key_not_workspace_bound` | high | blocking |
| `body_workspace_trust` | medium | blocking |
| `unscoped_tenant_query` | informational | reported (guarded out-of-band) |

## Current results

- **body_workspace_trust:** 10
- **global_latest_fallback:** 3
- **r2_key_not_workspace_bound:** 14
- **unscoped_tenant_query:** 307
- **workspace_domain_scope_missing:** 29

Blocking findings are all covered by 38 documented suppressions
(each a manually-verified out-of-band guard with a security contract) — see
`scripts/security/tenant-query-audit-suppressions.json`. Zero unsuppressed.

## Mutation proof

The anchored source mutant preserves `JOIN workspace_domains` in
`resolveWorkspaceDomain`, removes only `wd.workspace_id = ?` and its bind, and
must fail both `validate-tenant-query-audit.js` and the real-router oracle in
`validate-tenant-isolation.js`. The mutation harness restores the source exactly.

## Informational: `unscoped_tenant_query` by table

These queries touch a tenant-owned table without an inline tenant predicate; their
safety rests on an out-of-band guard (an authenticated, workspace-authorized route —
proven by the entry-point inventory — or an already-scoped scan/subscription context).
They are listed for the record, not as defects.

| Table | Unscoped queries |
|---|---:|
| `workspaces` | 85 |
| `scans` | 34 |
| `hosted_dns_entries` | 23 |
| `dmarc_ingest_endpoints` | 14 |
| `workspace_reports` | 14 |
| `scan_report_snapshots` | 11 |
| `subscriptions` | 11 |
| `mcp_oauth_connections` | 8 |
| `scheduled_scans` | 6 |
| `managed_cases` | 6 |
| `mcp_oauth_browser_sessions` | 6 |
| `aggregate_report_ingest_claims` | 5 |
| `workspace_invitations` | 5 |
| `domains` | 5 |
| `asset_alert_records` | 4 |
| `audit_events` | 4 |
| `user_sessions` | 4 |
| `scheduled_reports` | 4 |
| `asset_events` | 3 |
| `findings` | 3 |
| `cyber_essentials_control_records` | 3 |
| `stripe_subscription_lineages` | 3 |
| `website_security_conditions` | 3 |
| `api_tokens` | 3 |
| `report_schedules` | 3 |
| `deletion_requests` | 3 |
| `mfa_challenges` | 3 |
| `workspace_brand_assets` | 3 |
| `mcp_oauth_refresh_uses` | 3 |
| `workspace_alert_channels` | 2 |
| `email_protection_events` | 2 |
| `external_exposure_jobs` | 2 |
| `alert_deliveries` | 2 |
| `network_scans` | 2 |
| `related_changes` | 2 |
| `lifecycle_email_events` | 2 |
| `report_schedule_runs` | 2 |
| `workspace_assets` | 2 |
| `workspace_vendors` | 2 |
| `workspace_members` | 2 |
| `identity_exposure` | 1 |
| `remediation_items` | 1 |
| `dmarc_aggregate_reports` | 1 |
| `dmarc_aggregate_records` | 1 |
| `operational_events` | 1 |
| `tlsrpt_aggregate_reports` | 1 |
| `tlsrpt_failure_details` | 1 |
| `password_reset_tokens` | 1 |
| `dmarc_change_requests` | 1 |
| `email_sender_sources` | 1 |
| `scan_module_telemetry` | 1 |
| `notification_events` | 1 |
