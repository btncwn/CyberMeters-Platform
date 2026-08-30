// ─────────────────────────────────────────────────────────────────────────────
// tenant-resources.js  (shared)
//
// Ground-truth model of every D1 table and how it is bound to a tenant. Parsed
// from database/schema.sql + database/migrations/*.sql so it cannot drift from
// reality. Used by the tenant-isolation invariant matrix builder + validator.
//
// The tenant-ownership graph is not uniform:
//   • direct        — table carries workspace_id
//   • account       — table carries owner_user_id / owner_id (account/MSP root)
//   • user          — table carries user_id and no workspace_id (per-user, pre-workspace)
//   • via_scan      — table carries scan_id, tenancy inherited from scans.workspace_id
//   • via_domain    — table carries domain_id, tenancy via workspace_domains
//   • via_subscription — table carries subscription_id, tenancy via subscriptions
//   • infra         — global infrastructure, holds NO tenant data
//   • identity_root — the users table itself
// ─────────────────────────────────────────────────────────────────────────────
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const REPO_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const DB = path.join(REPO_ROOT, "database");

function tableOperations(sql) {
  const operations = [];
  let match;
  const create = /CREATE TABLE (?:IF NOT EXISTS )?[`"]?(\w+)[`"]?\s*\(([\s\S]*?)\);/gi;
  while ((match = create.exec(sql))) {
    operations.push({
      type: "create",
      index: match.index,
      table: match[1],
      columns: [...match[2].matchAll(/^\s*[`"]?(\w+)[`"]?\s+/gm)].map((entry) => entry[1]),
    });
  }
  const addColumn = /ALTER TABLE [`"]?(\w+)[`"]?\s+ADD COLUMN [`"]?(\w+)[`"]?/gi;
  while ((match = addColumn.exec(sql))) {
    operations.push({ type: "add_column", index: match.index, table: match[1], column: match[2] });
  }
  const rename = /ALTER TABLE [`"]?(\w+)[`"]?\s+RENAME TO [`"]?(\w+)[`"]?/gi;
  while ((match = rename.exec(sql))) {
    operations.push({ type: "rename", index: match.index, table: match[1], target: match[2] });
  }
  const drop = /DROP TABLE (?:IF EXISTS )?[`"]?(\w+)[`"]?/gi;
  while ((match = drop.exec(sql))) {
    operations.push({ type: "drop", index: match.index, table: match[1] });
  }
  return operations.sort((left, right) => left.index - right.index);
}

export function extractSchemaResourcesFromSources(sources) {
  const tables = {};
  const transientMigrationObjects = [];
  for (const source of sources) {
    const createdInSource = new Set();
    for (const operation of tableOperations(source.sql)) {
      if (operation.type === "create") {
        tables[operation.table] = new Set(operation.columns);
        createdInSource.add(operation.table);
        continue;
      }
      if (operation.type === "add_column") {
        if (tables[operation.table]) tables[operation.table].add(operation.column);
        continue;
      }
      if (operation.type === "rename") {
        if (source.migration === true && createdInSource.has(operation.table)) {
          const columns = tables[operation.table];
          transientMigrationObjects.push({
            file: source.file,
            table: operation.table,
            termination: "rename",
            target: operation.target,
          });
          createdInSource.delete(operation.table);
          delete tables[operation.table];
          if (columns) tables[operation.target] = columns;
        }
        continue;
      }
      if (operation.type === "drop") {
        if (source.migration === true && createdInSource.has(operation.table)) {
          transientMigrationObjects.push({
            file: source.file,
            table: operation.table,
            termination: "drop",
            target: null,
          });
          createdInSource.delete(operation.table);
          delete tables[operation.table];
        }
      }
    }
  }
  return {
    tables,
    transientMigrationObjects: transientMigrationObjects.sort((left, right) =>
      left.file.localeCompare(right.file) || left.table.localeCompare(right.table)),
  };
}

export function extractSchemaResources() {
  const files = [
    path.join(DB, "schema.sql"),
    ...fs.readdirSync(path.join(DB, "migrations")).filter((f) => f.endsWith(".sql")).sort().map((f) => path.join(DB, "migrations", f)),
  ];
  return extractSchemaResourcesFromSources(files.map((file) => ({
    file: path.relative(REPO_ROOT, file).split(path.sep).join("/"),
    migration: file !== path.join(DB, "schema.sql"),
    sql: fs.readFileSync(file, "utf8"),
  })));
}

export function extractTables() {
  return extractSchemaResources().tables;
}

// Ownership model derived from the columns actually present on the table.
export function deriveOwnership(table, cols) {
  if (table === "users") return { model: "identity_root", column: "id" };
  if (INFRA_TABLES.has(table)) return { model: "infra", column: null };
  if (cols.has("workspace_id")) return { model: "direct", column: "workspace_id" };
  if (cols.has("owner_user_id")) return { model: "account", column: "owner_user_id" };
  if (cols.has("owner_id")) return { model: "account", column: "owner_id" };
  if (cols.has("subscription_id")) return { model: "via_subscription", column: "subscription_id" };
  if (cols.has("scan_id")) return { model: "via_scan", column: "scan_id" };
  if (cols.has("domain_id")) return { model: "via_domain", column: "domain_id" };
  if (cols.has("user_id")) return { model: "user", column: "user_id" };
  return { model: "UNCLASSIFIED", column: null };
}

// Tables that hold NO tenant data — global infrastructure / cross-account ledgers.
export const INFRA_TABLES = new Set([
  "api_rate_limits",        // rate-limit counters keyed by scope/ip
  "oauth_states",           // OAuth CSRF state token, pre-auth
  "stripe_processed_events",// Stripe webhook idempotency ledger (global)
]);

// The 12 canonical tenant-isolation invariants (mission Phase 2).
export const INVARIANTS = [
  { id: 1,  text: "own resource succeeds" },
  { id: 2,  text: "foreign resource safely fails" },
  { id: 3,  text: "nonexistent resource behaves equivalently (no existence oracle)" },
  { id: 4,  text: "deleted workspace fails per policy" },
  { id: 5,  text: "deleted membership fails" },
  { id: 6,  text: "soft-deleted resource follows policy" },
  { id: 7,  text: "guessed ID does not bypass access" },
  { id: 8,  text: "hostname alone is never ownership" },
  { id: 9,  text: "resource.workspace_id must equal authorised workspace_id" },
  { id: 10, text: "same hostname in two workspaces remains isolated" },
  { id: 11, text: "read and write paths separately covered" },
  { id: 12, text: "background producers preserve workspace identity" },
];

// ── Product resource classes ─────────────────────────────────────────────────
// Every table is assigned to exactly one class. The completeness validator fails
// if a schema table is missing here (forcing a new table to be triaged for
// tenancy) or if a class's declared ownership contradicts the schema.
//
// `harness` = exercised by the dynamic two-tenant harness (validate-tenant-isolation
// / validate-tenant-isolation-extended). `property` = exercised by the property-based
// authz suite. Classes with neither carry a `coverage_note` explaining why.
export const RESOURCE_CLASSES = [
  { class: "workspaces",            domain: "core",     tables: ["workspaces"], harness: true, property: true },
  { class: "workspace_memberships", domain: "core",     tables: ["workspace_members"], harness: true, property: true },
  { class: "invitations",           domain: "core",     tables: ["workspace_invitations"], harness: true, property: true },
  { class: "domains",               domain: "core",     tables: ["domains", "workspace_domains"], harness: true, property: true },
  { class: "scans",                 domain: "core",     tables: ["scans", "scan_module_telemetry", "ct_provider_telemetry", "ct_provider_overlap_telemetry", "scheduled_scans"], harness: true, property: true },
  { class: "assets",                domain: "attack_surface", tables: ["workspace_assets", "hidden_assets", "attack_surface_signal_observations", "asset_lifecycle_observations"], harness: true, property: true },
  { class: "asset_events",          domain: "attack_surface", tables: ["asset_events", "asset_alert_records"], harness: false, property: false, coverage_note: "written by scan/cron; read via /assets + posture; workspace_id-scoped; isolation proven at the assets read surface + static audit" },
  { class: "findings",              domain: "reporting", tables: ["findings", "remediation_items", "kev_matches"], harness: true, property: false, coverage_note: "scan_id-scoped; reachable only through /scans/:id ownership-gated report surfaces" },
  { class: "reports_snapshots",     domain: "reporting", tables: ["reports", "workspace_reports", "scan_report_snapshots", "historical_scores"], harness: true, property: true },
  { class: "scheduled_reports",     domain: "reporting", tables: ["report_schedules", "report_schedule_runs", "scheduled_reports"], harness: false, property: false, coverage_note: "background report producer; workspace_id-scoped writes; static-audit + background-writer property covered" },
  { class: "managed_cases",         domain: "cases",    tables: ["managed_cases", "managed_case_events"], harness: true, property: true },
  { class: "alerts",                domain: "alerts",   tables: ["alert_activation", "alert_deliveries", "workspace_alert_channels"], harness: false, property: false, coverage_note: "workspace_id-scoped; delivery recipients proven by validate-alert-recipients (no operator fallback / soft-delete)" },
  { class: "notifications",         domain: "alerts",   tables: ["notification_events", "notification_preferences"], harness: true, property: true },
  { class: "remediation_waivers",   domain: "reporting", tables: ["finding_waivers"], harness: false, property: false, coverage_note: "workspace_id-scoped; static audit + matrix ownership-consistency" },
  { class: "certificates",          domain: "certificates", tables: ["certificate_lifecycle", "certificate_lifecycle_events", "certificate_observations"], harness: true, property: false },
  { class: "identity_exposure",     domain: "identity", tables: ["identity_exposure", "identity_exposure_events", "identity_assets"], harness: true, property: false, coverage_note: "foreign/anon denial on /identity-surfaces with owner positive control in validate-tenant-isolation-extended.js; plus the dedicated validate-identity-exposure.js" },
  { class: "brand",                 domain: "brand",    tables: ["brand_abuse_campaigns", "brand_evidence_bundles", "workspace_brand_assets", "workspace_brand_profiles"], harness: true, property: true },
  { class: "email_protection",      domain: "email",    tables: ["aggregate_report_ingest_claims", "email_protection_events", "email_sender_sources", "dmarc_aggregate_records", "dmarc_aggregate_reports", "dmarc_change_requests", "dmarc_ingest_endpoints", "hosted_dns_entries", "hosted_dns_records", "tlsrpt_aggregate_reports", "tlsrpt_failure_details"], harness: false, property: false, coverage_note: "workspace_id-scoped; ingest is endpoint-key gated (key binds workspace); read surfaces harness-covered via /maturity + email-protection routes" },
  { class: "cyber_essentials",      domain: "cyber_essentials", tables: ["cyber_essentials_answers", "cyber_essentials_control_records", "cyber_essentials_events"], harness: false, property: false, coverage_note: "workspace_id-scoped; read surfaces exist; write is answer-versioned (validate-ce-answer-versioning)" },
  { class: "website_security",      domain: "website",  tables: ["website_security_conditions", "website_security_events"], harness: false, property: false, coverage_note: "workspace_id-scoped; static audit + lifecycle validator (validate-website-security-lifecycle)" },
  { class: "shadow_it",             domain: "shadow_it", tables: ["shadow_it_inventory", "shadow_it_inventory_events", "workspace_vendors", "vendor_risk_scores", "vendor_risk_scores_history", "workspace_supply_chain_scores", "workspace_supply_chain_history"], harness: true, property: false },
  { class: "posture_state",         domain: "reporting", tables: ["cyber_mot_domain_states", "domain_maturity_ledger", "workspace_brs_scores", "workspace_brs_score_history"], harness: true, property: false },
  { class: "related_changes",       domain: "correlation", tables: ["related_changes", "related_change_evidence"], harness: false, property: false, coverage_note: "M6 B1 deterministic Related Changes (mig 098); both workspace_id-scoped (evidence carries a denormalised workspace_id); read/feedback/case surface is workspace_id-filtered and role-gated; isolation proven by validate-m6-b1-related-changes + the static tenant-query audit, purge by validate-purge-completeness" },
  { class: "api_tokens",            domain: "account",  tables: ["api_tokens"], harness: false, property: true, coverage_note: "workspace_id + user_id scoped; account route ownership-gated" },
  { class: "subscriptions",         domain: "billing",  tables: ["subscriptions", "subscription_accounts", "subscription_events", "customer_profiles"], harness: true, property: false },
  { class: "report_branding",       domain: "reporting", tables: ["workspace_branding", "msp_branding_profiles"], harness: false, property: false, coverage_note: "workspace_branding is workspace_id-scoped (per-workspace co-brand logo); msp_branding_profiles is owner_user_id-scoped (MSP white-label profile, usable only for the MSP's own portfolio); isolation proven by validate-report-branding-v2 + the static audit; logos stored in R2 under tenant-prefixed, content-addressed keys" },
  { class: "msp_portfolio",         domain: "portfolio", tables: ["portfolio_risk_snapshots"], harness: false, property: false, coverage_note: "owner_id (MSP account) scoped; cross-MSP isolation proven by validate-portfolio + validate-msp-portfolio-domains" },
  { class: "audit_log",             domain: "core",     tables: ["audit_events"], harness: true, property: false },
  { class: "operational_observability", domain: "infra", tables: ["operational_events"], harness: false, property: false, coverage_note: "internal-only operational event producer/read contract; safe fields, idempotency, readiness and fail-closed behavior proven by F-027; workspace-owned rows are hard-purged by validate-purge-completeness while platform-level NULL rows remain" },
  { class: "deletion_lifecycle",    domain: "core",     tables: ["deletion_requests", "workspace_retention_settings", "lifecycle_email_events"], harness: false, property: false, coverage_note: "workspace/user-scoped lifecycle; purge-completeness proven by validate-purge-completeness" },
  { class: "auth_sessions",         domain: "auth",     tables: ["user_sessions", "mfa_challenges", "password_reset_tokens"], harness: false, property: false, coverage_note: "per-user auth material; token-hash keyed; not a workspace resource — covered by validate-security-contracts" },
  { class: "infrastructure",        domain: "infra",    tables: ["api_rate_limits", "oauth_states", "stripe_processed_events"], harness: false, property: false, non_tenant: true, coverage_note: "global infrastructure — holds no tenant data" },
  { class: "identity_root",         domain: "auth",     tables: ["users"], harness: false, property: false, non_tenant: true, coverage_note: "identity root — a user owns only their own row; not a workspace resource" },
];

// Every table → its class (built from RESOURCE_CLASSES).
export function tableClassIndex() {
  const idx = new Map();
  for (const rc of RESOURCE_CLASSES) for (const t of rc.tables) {
    if (idx.has(t)) throw new Error(`table ${t} assigned to two classes: ${idx.get(t)} and ${rc.class}`);
    idx.set(t, rc.class);
  }
  return idx;
}
