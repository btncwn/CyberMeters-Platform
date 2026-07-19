# CyberMeters — Static Tenant-Query Audit

> **Generated** by `scripts/security/build-tenant-query-audit-report.js`.
> CI gate: `scripts/validate-tenant-query-audit.js` (blocks on any unsuppressed
> high-signal finding or stale suppression).

The audit extracts every `.prepare()`/`.exec()` SQL statement and every R2 key
expression from the Worker source, then classifies each against the tenant-owned
table set from the isolation matrix. A statement carrying an inline tenant predicate
(`workspace_id` / `owner_user_id` / `owner_id` / `user_id` / `subscription_id`, or a
`workspace_domains` join) is **safe** and not reported.

## Detectors

| Detector | Severity | Gate |
|---|---|---|
| `hostname_only_ownership` | high | blocking |
| `global_latest_fallback` | high | blocking |
| `r2_key_not_workspace_bound` | high | blocking |
| `body_workspace_trust` | medium | blocking |
| `unscoped_tenant_query` | informational | reported (guarded out-of-band) |

## Current results

- **body_workspace_trust:** 8
- **global_latest_fallback:** 2
- **r2_key_not_workspace_bound:** 11
- **unscoped_tenant_query:** 240

Blocking findings are all covered by 19 documented suppressions
(each a manually-verified out-of-band guard with a security contract) — see
`scripts/security/tenant-query-audit-suppressions.json`. Zero unsuppressed.

## Mutation proof

Removing `workspace_id = ? AND` from any `WHERE workspace_id = ? AND domain = ?`
statement turns it into a bare `WHERE domain = ?` on a tenant table, which
`hostname_only_ownership` flags with no suppression → the CI gate fails.

## Informational: `unscoped_tenant_query` by table

These queries touch a tenant-owned table without an inline tenant predicate; their
safety rests on an out-of-band guard (an authenticated, workspace-authorized route —
proven by the entry-point inventory — or an already-scoped scan/subscription context).
They are listed for the record, not as defects.

| Table | Unscoped queries |
|---|---:|
| `workspaces` | 67 |
| `hosted_dns_entries` | 23 |
| `scans` | 21 |
| `dmarc_ingest_endpoints` | 14 |
| `workspace_reports` | 10 |
| `subscriptions` | 10 |
| `scan_report_snapshots` | 7 |
| `workspace_invitations` | 6 |
| `scheduled_scans` | 5 |
| `managed_cases` | 5 |
| `domains` | 5 |
| `lifecycle_email_events` | 5 |
| `asset_alert_records` | 4 |
| `workspace_brand_assets` | 4 |
| `audit_events` | 4 |
| `user_sessions` | 4 |
| `deletion_requests` | 4 |
| `mfa_challenges` | 4 |
| `asset_events` | 3 |
| `findings` | 3 |
| `cyber_essentials_control_records` | 3 |
| `website_security_conditions` | 3 |
| `report_schedules` | 3 |
| `scheduled_reports` | 3 |
| `workspace_alert_channels` | 2 |
| `email_protection_events` | 2 |
| `alert_deliveries` | 2 |
| `api_tokens` | 2 |
| `report_schedule_runs` | 2 |
| `email_sender_sources` | 2 |
| `workspace_vendors` | 2 |
| `password_reset_tokens` | 2 |
| `workspace_members` | 2 |
| `certificate_lifecycle` | 1 |
| `identity_exposure` | 1 |
| `remediation_items` | 1 |
| `shadow_it_inventory` | 1 |
| `dmarc_change_requests` | 1 |
| `notification_events` | 1 |
