// ─────────────────────────────────────────────────────────────────────────────
// tenant-query-audit.js  (shared)
//
// A bounded static audit over the Worker's SQL surface for tenant-scope
// regressions. It extracts every .prepare()/.exec() SQL string and classifies
// it against the tenant-owned table set (from the isolation matrix). A query is
// SAFE when it carries an inline tenant predicate (workspace_id / owner_user_id /
// owner_id / user_id / subscription_id); it is
// REPORTED when it touches a tenant-owned table with no inline tenant predicate
// (its safety then rests on an out-of-band guard, which must be justified in the
// suppression file) or matches a high-signal risk pattern.
//
// Detectors:
//   hostname_only_ownership — filters by domain/hostname on a tenant table with
//                             no tenant predicate ("hostname alone is never
//                             ownership")
//   global_latest_fallback  — ORDER BY … LIMIT 1 with no tenant predicate
//   unscoped_tenant_query   — SELECT/UPDATE/DELETE on a tenant table, filtered
//                             but no inline tenant predicate
//   workspace_domain_scope_missing — workspace_domains appears without an
//                             inline tenant predicate; the table/JOIN name alone
//                             is never proof of workspace scope
//   body_workspace_trust    — request body role/plan/workspace_id used in code
//   r2_key_not_workspace_bound — R2 get/put whose key has no workspace/owner/scan
//                             segment
// ─────────────────────────────────────────────────────────────────────────────
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { extractTables, deriveOwnership, INFRA_TABLES } from "./tenant-resources.js";

export const REPO_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const SRC = path.join(REPO_ROOT, "workers", "scan-api", "src");

// Tenant-owned tables (everything except infra + the users identity root).
export function tenantOwnedTables() {
  const tables = extractTables();
  const set = new Set();
  for (const [t, cols] of Object.entries(tables)) {
    const o = deriveOwnership(t, cols);
    if (o.model !== "infra" && o.model !== "identity_root") set.add(t);
  }
  return set;
}

// A tenant column counts as scoping only when used as a PREDICATE (followed by
// =, IN, IS, comparison) — NOT when it merely appears in a SELECT column list.
// `SELECT workspace_id FROM scans WHERE id = ?` is UNSCOPED and must not be
// mistaken for scoped just because the column name appears.
const TENANT_PREDICATE = /\b(workspace_id|owner_user_id|owner_id|subscription_id)\s*(=|<|>|!|\bIN\b|\bIS\b|\bLIKE\b)/i;
const USER_PREDICATE = /\buser_id\s*(=|<|>|!|\bIN\b|\bIS\b|\bLIKE\b)/i;

function listSourceFiles() {
  const out = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith(".js")) out.push(p);
    }
  };
  walk(SRC);
  return out.sort();
}

// Extract SQL strings passed to .prepare()/.exec(). Handles template literals and
// quoted strings, possibly multi-line. Returns {file, line, sql}.
function extractSql(file) {
  const raw = fs.readFileSync(file, "utf8");
  const out = [];
  const re = /\.(prepare|exec)\(\s*(`|"|')/g;
  let m;
  while ((m = re.exec(raw))) {
    const quote = m[2];
    let i = re.lastIndex, sql = "";
    while (i < raw.length) {
      const c = raw[i];
      if (c === "\\") { sql += c + raw[i + 1]; i += 2; continue; }
      if (c === quote) break;
      sql += c; i++;
    }
    if (/\b(select|update|delete|insert)\b/i.test(sql)) {
      const line = raw.slice(0, m.index).split("\n").length;
      out.push({ file: path.relative(REPO_ROOT, file), line, sql: sql.replace(/\s+/g, " ").trim() });
    }
  }
  return out;
}

// Which tenant-owned tables a statement references (FROM/JOIN/INTO/UPDATE).
function referencedTenantTables(sql, tenant) {
  const refs = new Set();
  const re = /\b(?:from|join|into|update)\s+[`"]?(\w+)[`"]?/gi;
  let m;
  while ((m = re.exec(sql))) if (tenant.has(m[1])) refs.add(m[1]);
  return [...refs];
}

export function hasTenantPredicate(sql) {
  return TENANT_PREDICATE.test(sql) || USER_PREDICATE.test(sql);
}

export function auditSql() {
  const tenant = tenantOwnedTables();
  const findings = [];
  for (const file of listSourceFiles()) {
    for (const { file: rel, line, sql } of extractSql(file)) {
      const refs = referencedTenantTables(sql, tenant);
      if (refs.length === 0) continue;                    // non-tenant tables only → safe
      const stmt = (sql.match(/^\s*(select|update|delete|insert)/i) || [])[1]?.toLowerCase();
      if (stmt === "insert") continue;                    // inserts do not disclose across tenants
      const scoped = hasTenantPredicate(sql);
      const fp = crypto.createHash("sha1").update(rel + "|" + sql).digest("hex").slice(0, 12);
      const base = { file: rel, line, tables: refs, sql: sql.slice(0, 240), fingerprint: fp };

      if (scoped) continue;                               // inline tenant predicate → safe

      // No inline tenant predicate — classify by pattern.
      if (refs.includes("workspace_domains")) {
        findings.push({ ...base, detector: "workspace_domain_scope_missing", severity: "high" });
      } else if (/\b(domain|hostname)\s*=\s*\?/i.test(sql) || /\bWHERE\s+domain\b/i.test(sql)) {
        findings.push({ ...base, detector: "hostname_only_ownership", severity: "high" });
      } else if (/order\s+by\b[\s\S]*\blimit\s+1\b/i.test(sql)) {
        findings.push({ ...base, detector: "global_latest_fallback", severity: "high" });
      } else if (/\bwhere\b/i.test(sql)) {
        findings.push({ ...base, detector: "unscoped_tenant_query", severity: "medium" });
      }
    }
  }

  // R2 key-binding detector.
  for (const file of listSourceFiles()) {
    const raw = fs.readFileSync(file, "utf8");
    const re = /cybermeters_reports\.(get|put|head|delete)\(\s*([^,)]+)/g;
    let m;
    while ((m = re.exec(raw))) {
      const keyExpr = m[2].trim();
      const line = raw.slice(0, m.index).split("\n").length;
      const bound = /workspace|owner|scan|tenant|reportKey|r2Key|snapshot|report_key/i.test(keyExpr);
      if (!bound) {
        // Line-independent fingerprint: keyed on the R2 op + key expression, so
        // moving the code does not churn the suppression, but changing the key does.
        const fp = crypto.createHash("sha1").update(path.relative(REPO_ROOT, file) + "|r2|" + m[1] + "|" + keyExpr).digest("hex").slice(0, 12);
        findings.push({ file: path.relative(REPO_ROOT, file), line, detector: "r2_key_not_workspace_bound", severity: "high", sql: `R2.${m[1]}(${keyExpr.slice(0, 80)})`, tables: [], fingerprint: fp });
      }
    }
  }

  // Body-trust detector.
  for (const file of listSourceFiles()) {
    const raw = fs.readFileSync(file, "utf8");
    const lines = raw.split("\n");
    lines.forEach((l, i) => {
      const m = l.match(/\bbody\.(role|plan|workspace_id)\b/);
      if (m) {
        // Line-independent fingerprint: keyed on the trimmed source line.
        const fp = crypto.createHash("sha1").update(path.relative(REPO_ROOT, file) + "|body|" + l.trim()).digest("hex").slice(0, 12);
        findings.push({ file: path.relative(REPO_ROOT, file), line: i + 1, detector: "body_workspace_trust", severity: "medium", sql: l.trim().slice(0, 160), tables: [], fingerprint: fp });
      }
    });
  }

  return findings;
}
