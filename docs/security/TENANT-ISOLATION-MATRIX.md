# CyberMeters — Tenant-Isolation Invariant Matrix

> **Generated** by `scripts/security/build-tenant-isolation-matrix.js` from the live
> schema. CI gate: `scripts/validate-tenant-isolation-matrix.js` fails if any D1 table
> is unclassified, if a declared ownership column is absent from the schema, or if a
> class claims dynamic-harness coverage it does not have.

Every tenant-owned resource class is bound to a tenant by one of the ownership models
below. A new table that is not assigned to a class fails the gate — so tenancy for new
data cannot be silently omitted.

## Counts

- **schema tables:** 92
- **classified:** 92
- **tenant owned tables:** 88
- **infra or identity tables:** 4
- **unclassified:** 0
- **resource classes:** 32
- **classes with dynamic coverage:** 17

## The 12 invariants

1. own resource succeeds
2. foreign resource safely fails
3. nonexistent resource behaves equivalently (no existence oracle)
4. deleted workspace fails per policy
5. deleted membership fails
6. soft-deleted resource follows policy
7. guessed ID does not bypass access
8. hostname alone is never ownership
9. resource.workspace_id must equal authorised workspace_id
10. same hostname in two workspaces remains isolated
11. read and write paths separately covered
12. background producers preserve workspace identity

## Resource classes

| Class | Domain | Ownership | Tables | Dynamic harness | Property |
|---|---|---|---|:---:|:---:|
| workspaces | core | account(owner_user_id) | 1 | ✓ | ✓ |
| workspace_memberships | core | direct(workspace_id) | 1 | ✓ | ✓ |
| invitations | core | direct(workspace_id) | 1 | ✓ | ✓ |
| domains | core | user(user_id), direct(workspace_id) | 2 | ✓ | ✓ |
| scans | core | direct(workspace_id), via_scan(scan_id) | 5 | ✓ | ✓ |
| assets | attack_surface | direct(workspace_id), via_scan(scan_id) | 4 | ✓ | ✓ |
| asset_events | attack_surface | direct(workspace_id) | 2 | — | — |
| findings | reporting | via_scan(scan_id) | 3 | ✓ | — |
| reports_snapshots | reporting | via_scan(scan_id), direct(workspace_id) | 4 | ✓ | ✓ |
| scheduled_reports | reporting | direct(workspace_id) | 3 | — | — |
| managed_cases | cases | direct(workspace_id) | 2 | ✓ | ✓ |
| alerts | alerts | direct(workspace_id) | 3 | — | — |
| notifications | alerts | direct(workspace_id) | 2 | ✓ | ✓ |
| remediation_waivers | reporting | direct(workspace_id) | 1 | — | — |
| certificates | certificates | direct(workspace_id) | 3 | ✓ | — |
| identity_exposure | identity | direct(workspace_id) | 3 | ✓ | — |
| brand | brand | direct(workspace_id) | 4 | ✓ | ✓ |
| email_protection | email | direct(workspace_id) | 11 | — | — |
| cyber_essentials | cyber_essentials | direct(workspace_id) | 3 | — | — |
| website_security | website | direct(workspace_id) | 2 | — | — |
| shadow_it | shadow_it | direct(workspace_id) | 7 | ✓ | — |
| posture_state | reporting | direct(workspace_id) | 4 | ✓ | — |
| related_changes | correlation | direct(workspace_id) | 2 | — | — |
| api_tokens | account | direct(workspace_id) | 1 | — | ✓ |
| subscriptions | billing | direct(workspace_id), account(owner_user_id), via_subscription(subscription_id) | 4 | ✓ | — |
| report_branding | reporting | direct(workspace_id), account(owner_user_id) | 2 | — | — |
| msp_portfolio | portfolio | account(owner_id) | 1 | — | — |
| audit_log | core | direct(workspace_id) | 1 | ✓ | — |
| deletion_lifecycle | core | direct(workspace_id) | 3 | — | — |
| auth_sessions | auth | user(user_id) | 3 | — | — |
| infrastructure ⁿᵗ | infra | infra | 3 | — | — |
| identity_root ⁿᵗ | auth | identity_root(id) | 1 | — | — |

_ⁿᵗ = non-tenant (global infrastructure / identity root)._

### Coverage notes

- **asset_events:** written by scan/cron; read via /assets + posture; workspace_id-scoped; isolation proven at the assets read surface + static audit
- **findings:** scan_id-scoped; reachable only through /scans/:id ownership-gated report surfaces
- **scheduled_reports:** background report producer; workspace_id-scoped writes; static-audit + background-writer property covered
- **alerts:** workspace_id-scoped; delivery recipients proven by validate-alert-recipients (no operator fallback / soft-delete)
- **remediation_waivers:** workspace_id-scoped; static audit + matrix ownership-consistency
- **identity_exposure:** foreign/anon denial on /identity-surfaces with owner positive control in validate-tenant-isolation-extended.js; plus the dedicated validate-identity-exposure.js
- **email_protection:** workspace_id-scoped; ingest is endpoint-key gated (key binds workspace); read surfaces harness-covered via /maturity + email-protection routes
- **cyber_essentials:** workspace_id-scoped; read surfaces exist; write is answer-versioned (validate-ce-answer-versioning)
- **website_security:** workspace_id-scoped; static audit + lifecycle validator (validate-website-security-lifecycle)
- **related_changes:** M6 B1 deterministic Related Changes (mig 098); both workspace_id-scoped (evidence carries a denormalised workspace_id); read/feedback/case surface is workspace_id-filtered and role-gated; isolation proven by validate-m6-b1-related-changes + the static tenant-query audit, purge by validate-purge-completeness
- **api_tokens:** workspace_id + user_id scoped; account route ownership-gated
- **report_branding:** workspace_branding is workspace_id-scoped (per-workspace co-brand logo); msp_branding_profiles is owner_user_id-scoped (MSP white-label profile, usable only for the MSP's own portfolio); isolation proven by validate-report-branding-v2 + the static audit; logos stored in R2 under tenant-prefixed, content-addressed keys
- **msp_portfolio:** owner_id (MSP account) scoped; cross-MSP isolation proven by validate-portfolio + validate-msp-portfolio-domains
- **deletion_lifecycle:** workspace/user-scoped lifecycle; purge-completeness proven by validate-purge-completeness
- **auth_sessions:** per-user auth material; token-hash keyed; not a workspace resource — covered by validate-security-contracts
- **infrastructure:** global infrastructure — holds no tenant data
- **identity_root:** identity root — a user owns only their own row; not a workspace resource

## Table → class index

| Table | Ownership model | Class |
|---|---|---|
| `aggregate_report_ingest_claims` | direct(workspace_id) | email_protection |
| `alert_activation` | direct(workspace_id) | alerts |
| `alert_deliveries` | direct(workspace_id) | alerts |
| `api_rate_limits` | infra | infrastructure |
| `api_tokens` | direct(workspace_id) | api_tokens |
| `asset_alert_records` | direct(workspace_id) | asset_events |
| `asset_events` | direct(workspace_id) | asset_events |
| `asset_lifecycle_observations` | direct(workspace_id) | assets |
| `attack_surface_signal_observations` | direct(workspace_id) | assets |
| `audit_events` | direct(workspace_id) | audit_log |
| `brand_abuse_campaigns` | direct(workspace_id) | brand |
| `brand_evidence_bundles` | direct(workspace_id) | brand |
| `certificate_lifecycle` | direct(workspace_id) | certificates |
| `certificate_lifecycle_events` | direct(workspace_id) | certificates |
| `certificate_observations` | direct(workspace_id) | certificates |
| `ct_provider_overlap_telemetry` | via_scan(scan_id) | scans |
| `ct_provider_telemetry` | via_scan(scan_id) | scans |
| `customer_profiles` | account(owner_user_id) | subscriptions |
| `cyber_essentials_answers` | direct(workspace_id) | cyber_essentials |
| `cyber_essentials_control_records` | direct(workspace_id) | cyber_essentials |
| `cyber_essentials_events` | direct(workspace_id) | cyber_essentials |
| `cyber_mot_domain_states` | direct(workspace_id) | posture_state |
| `deletion_requests` | direct(workspace_id) | deletion_lifecycle |
| `dmarc_aggregate_records` | direct(workspace_id) | email_protection |
| `dmarc_aggregate_reports` | direct(workspace_id) | email_protection |
| `dmarc_change_requests` | direct(workspace_id) | email_protection |
| `dmarc_ingest_endpoints` | direct(workspace_id) | email_protection |
| `domain_maturity_ledger` | direct(workspace_id) | posture_state |
| `domains` | user(user_id) | domains |
| `email_protection_events` | direct(workspace_id) | email_protection |
| `email_sender_sources` | direct(workspace_id) | email_protection |
| `finding_waivers` | direct(workspace_id) | remediation_waivers |
| `findings` | via_scan(scan_id) | findings |
| `hidden_assets` | via_scan(scan_id) | assets |
| `historical_scores` | direct(workspace_id) | reports_snapshots |
| `hosted_dns_entries` | direct(workspace_id) | email_protection |
| `hosted_dns_records` | direct(workspace_id) | email_protection |
| `identity_assets` | direct(workspace_id) | identity_exposure |
| `identity_exposure` | direct(workspace_id) | identity_exposure |
| `identity_exposure_events` | direct(workspace_id) | identity_exposure |
| `kev_matches` | via_scan(scan_id) | findings |
| `lifecycle_email_events` | direct(workspace_id) | deletion_lifecycle |
| `managed_case_events` | direct(workspace_id) | managed_cases |
| `managed_cases` | direct(workspace_id) | managed_cases |
| `mfa_challenges` | user(user_id) | auth_sessions |
| `msp_branding_profiles` | account(owner_user_id) | report_branding |
| `notification_events` | direct(workspace_id) | notifications |
| `notification_preferences` | direct(workspace_id) | notifications |
| `oauth_states` | infra | infrastructure |
| `password_reset_tokens` | user(user_id) | auth_sessions |
| `portfolio_risk_snapshots` | account(owner_id) | msp_portfolio |
| `related_change_evidence` | direct(workspace_id) | related_changes |
| `related_changes` | direct(workspace_id) | related_changes |
| `remediation_items` | via_scan(scan_id) | findings |
| `report_schedule_runs` | direct(workspace_id) | scheduled_reports |
| `report_schedules` | direct(workspace_id) | scheduled_reports |
| `reports` | via_scan(scan_id) | reports_snapshots |
| `scan_module_telemetry` | via_scan(scan_id) | scans |
| `scan_report_snapshots` | direct(workspace_id) | reports_snapshots |
| `scans` | direct(workspace_id) | scans |
| `scheduled_reports` | direct(workspace_id) | scheduled_reports |
| `scheduled_scans` | direct(workspace_id) | scans |
| `shadow_it_inventory` | direct(workspace_id) | shadow_it |
| `shadow_it_inventory_events` | direct(workspace_id) | shadow_it |
| `stripe_processed_events` | infra | infrastructure |
| `subscription_accounts` | account(owner_user_id) | subscriptions |
| `subscription_events` | via_subscription(subscription_id) | subscriptions |
| `subscriptions` | direct(workspace_id) | subscriptions |
| `tlsrpt_aggregate_reports` | direct(workspace_id) | email_protection |
| `tlsrpt_failure_details` | direct(workspace_id) | email_protection |
| `user_sessions` | user(user_id) | auth_sessions |
| `users` | identity_root(id) | identity_root |
| `vendor_risk_scores` | direct(workspace_id) | shadow_it |
| `vendor_risk_scores_history` | direct(workspace_id) | shadow_it |
| `website_security_conditions` | direct(workspace_id) | website_security |
| `website_security_events` | direct(workspace_id) | website_security |
| `workspace_alert_channels` | direct(workspace_id) | alerts |
| `workspace_assets` | direct(workspace_id) | assets |
| `workspace_brand_assets` | direct(workspace_id) | brand |
| `workspace_brand_profiles` | direct(workspace_id) | brand |
| `workspace_branding` | direct(workspace_id) | report_branding |
| `workspace_brs_score_history` | direct(workspace_id) | posture_state |
| `workspace_brs_scores` | direct(workspace_id) | posture_state |
| `workspace_domains` | direct(workspace_id) | domains |
| `workspace_invitations` | direct(workspace_id) | invitations |
| `workspace_members` | direct(workspace_id) | workspace_memberships |
| `workspace_reports` | direct(workspace_id) | reports_snapshots |
| `workspace_retention_settings` | direct(workspace_id) | deletion_lifecycle |
| `workspace_supply_chain_history` | direct(workspace_id) | shadow_it |
| `workspace_supply_chain_scores` | direct(workspace_id) | shadow_it |
| `workspace_vendors` | direct(workspace_id) | shadow_it |
| `workspaces` | account(owner_user_id) | workspaces |
