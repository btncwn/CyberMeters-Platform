// Read-only customer discovery projections. Admission, entitlement, rate limit,
// and awaited audit remain the responsibility of the private MCP service.
// These reads repeat the tenant check and never dispatch repair-capable HTTP GETs.
import { visibleFindingSql } from "../engines/finding-identity.js";
import { projectPhase5ScanRowsForCustomer } from "../engines/phase5-evidence.js";
import { boundedReportReads } from "./mcp-projections.js";

const PAGE_SIZE = 10;
const MAX_RESULT_BYTES = 8_192;
const MAX_PORTFOLIO_WORKSPACES = 500;
const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const HOST_RE = /^[A-Za-z0-9.-]{1,253}$/;
const ROLES = new Set(["viewer", "analyst", "admin", "owner"]);
const VERIFICATION = new Set(["verified", "unverified", "pending", "failed"]);
const QUALITY = new Set(["complete", "partial", "degraded", "unknown"]);
const EVIDENCE_READ = new Set(["verified", "unavailable", "bounded_out"]);
const DENIED = "mcp_projection_unavailable";
const encoder = new TextEncoder();

function unavailable() { return new Error(DENIED); }
function validId(value) { return typeof value === "string" && ID_RE.test(value); }
function validHost(value) { return typeof value === "string" && HOST_RE.test(value); }
function safeText(value, max) {
  if (typeof value !== "string" || !value.length || value.length > max ||
      /[\x00-\x1f\x7f\p{Cf}]/u.test(value) || /cm_[a-f0-9]{64}/i.test(value)) {
    throw unavailable();
  }
  return value;
}
function safeDate(value) {
  if (typeof value !== "string" || value.length > 40) throw unavailable();
  const normalized = value.includes("T") ? value : `${value.replace(" ", "T")}Z`;
  const millis = Date.parse(normalized);
  if (!Number.isFinite(millis)) throw unavailable();
  return new Date(millis).toISOString();
}
function result(value) {
  if (encoder.encode(JSON.stringify(value)).byteLength > MAX_RESULT_BYTES) throw unavailable();
  return value;
}
function readInput(input, allowed) {
  if (!input || typeof input !== "object" || Array.isArray(input) ||
      Object.keys(input).some((key) => !allowed.includes(key))) throw unavailable();
}

// Cursors are pagination coordinates, never authorisation grants. They carry a
// scope marker so a cursor from another workspace cannot silently skip records.
function domainCursor(domain, id, workspaceId) {
  return `d1~${workspaceId}~${domain}~${id}`;
}
function parseDomainCursor(cursor, workspaceId) {
  if (cursor == null) return null;
  if (typeof cursor !== "string" || cursor.length > 350) throw unavailable();
  const parts = cursor.split("~");
  if (parts.length !== 4 || parts[0] !== "d1" || parts[1] !== workspaceId ||
      !validHost(parts[2]) || !validId(parts[3])) throw unavailable();
  return { domain: parts[2], id: parts[3] };
}
function findingCursor(scope, workspaceId, severity, createdAt, id) {
  // D1 CURRENT_TIMESTAMP uses a space separator. Encode the raw SQL sort key
  // so it survives the private RPC's strict cursor alphabet unchanged.
  safeDate(createdAt);
  let encoded;
  try { encoded = btoa(createdAt).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""); }
  catch { throw unavailable(); }
  return `f1~${scope}~${workspaceId ?? "portfolio"}~${severity}~${encoded}~${id}`;
}
function cursorDate(encoded) {
  if (!/^[A-Za-z0-9_-]{1,60}$/.test(encoded)) throw unavailable();
  let createdAt;
  try { createdAt = atob(encoded.replace(/-/g, "+").replace(/_/g, "/")); }
  catch { throw unavailable(); }
  if (createdAt.length > 40 || /[^\x20-\x7e]/.test(createdAt)) throw unavailable();
  safeDate(createdAt);
  return createdAt;
}
function parseFindingCursor(cursor, scope, workspaceId) {
  if (cursor == null) return null;
  if (typeof cursor !== "string" || cursor.length > 420) throw unavailable();
  const parts = cursor.split("~");
  if (parts.length !== 6 || parts[0] !== "f1" || parts[1] !== scope ||
      parts[2] !== (workspaceId ?? "portfolio") ||
      !["critical", "high"].includes(parts[3]) ||
      !validId(parts[5])) throw unavailable();
  return { rank: parts[3] === "critical" ? 0 : 1,
    createdAt: cursorDate(parts[4]), id: parts[5] };
}

async function assertCurrentAccess(env, userId, workspaceIds) {
  if (!validId(userId) || !Array.isArray(workspaceIds) ||
      workspaceIds.length > MAX_PORTFOLIO_WORKSPACES ||
      workspaceIds.some((id) => !validId(id)) ||
      new Set(workspaceIds).size !== workspaceIds.length) throw unavailable();
  if (workspaceIds.length === 0) return;
  const placeholders = workspaceIds.map(() => "?").join(",");
  const rows = await env.cybermeters_db.prepare(
    `SELECT w.id, wm.role
       FROM workspaces w
       JOIN workspace_members wm ON wm.workspace_id = w.id AND wm.user_id = ?
       JOIN mcp_beta_workspace_access b ON b.workspace_id = w.id AND b.status = 'enabled'
      WHERE w.id IN (${placeholders}) AND w.deleted_at IS NULL
        AND NOT EXISTS (SELECT 1 FROM deletion_requests d
          WHERE d.request_type = 'workspace' AND d.workspace_id = w.id
            AND d.status NOT IN ('completed','cancelled'))`,
  ).bind(userId, ...workspaceIds).all();
  if (!Array.isArray(rows?.results) || rows.results.length !== workspaceIds.length) throw unavailable();
  for (const row of rows.results) {
    if (!ROLES.has(row.role)) throw unavailable();
  }
}

function projectAssessment(row) {
  if (!row) return { assessment: null, source_report_state: "not_assessed" };
  const sourceState = row.phase5_evidence_read?.state ?? "unavailable";
  if (!EVIDENCE_READ.has(sourceState)) throw unavailable();
  if (sourceState !== "verified") return { assessment: null, source_report_state: "unavailable" };
  const a = row.assessment;
  if (!a || !QUALITY.has(a.quality) || typeof a.authoritative !== "boolean" ||
      typeof a.provisional !== "boolean" || typeof a.comparable !== "boolean") throw unavailable();
  return {
    assessment: {
      quality: a.quality, authoritative: a.authoritative,
      provisional: a.provisional, comparable: a.comparable,
    },
    source_report_state: "verified",
  };
}

async function projectSourceScans(env, rows, mapRow) {
  const reports = boundedReportReads(env);
  const scans = rows.map(mapRow);
  const projected = await projectPhase5ScanRowsForCustomer(reports.env, scans);
  reports.assertWithinBudget();
  if (!Array.isArray(projected) || projected.length !== rows.length) throw unavailable();
  return projected;
}

/** A fixed page of workspace-owned domain links, using the link's verification state. */
export async function projectMcpDomains(env, grant, _facts, input = {}) {
  readInput(input, ["workspaceId", "cursor"]);
  if (!validId(grant?.workspaceId) || input.workspaceId !== grant.workspaceId) throw unavailable();
  await assertCurrentAccess(env, grant.userId, [grant.workspaceId]);
  const cursor = parseDomainCursor(input.cursor, grant.workspaceId);
  const whereCursor = cursor ? "AND (d.domain > ? OR (d.domain = ? AND d.id > ?))" : "";
  const params = cursor
    ? [grant.workspaceId, cursor.domain, cursor.domain, cursor.id, PAGE_SIZE + 1]
    : [grant.workspaceId, PAGE_SIZE + 1];
  const data = await env.cybermeters_db.prepare(
    `SELECT wd.domain_id, d.domain, wd.verification_status, wd.verified_at,
            s.id AS scan_id, s.domain AS scan_domain, s.status AS scan_status,
            s.score, s.rating, s.scan_quality, s.created_at AS scan_created_at
       FROM workspace_domains wd
       JOIN workspaces w ON w.id = wd.workspace_id AND w.deleted_at IS NULL
       JOIN domains d ON d.id = wd.domain_id
       LEFT JOIN scans s ON s.id = (
         SELECT last.id FROM scans last
          WHERE last.workspace_id = wd.workspace_id
            AND last.domain_id = wd.domain_id AND last.status = 'completed'
          ORDER BY last.created_at DESC, last.id DESC LIMIT 1
       )
      WHERE wd.workspace_id = ? ${whereCursor}
      ORDER BY d.domain ASC, d.id ASC LIMIT ?`,
  ).bind(...params).all();
  if (!Array.isArray(data?.results)) throw unavailable();
  const page = data.results.slice(0, PAGE_SIZE);
  const projected = await projectSourceScans(env, page, (row) => row.scan_id
    ? { id: row.scan_id, domain: row.scan_domain, status: row.scan_status,
        score: row.score, rating: row.rating, scan_quality: row.scan_quality }
    : null);
  const domains = page.map((row, index) => {
    if (!validId(row.domain_id) || !validHost(row.domain) ||
        !VERIFICATION.has(row.verification_status)) throw unavailable();
    const hasScan = row.scan_id != null;
    if (hasScan && (!validId(row.scan_id) || row.scan_status !== "completed")) throw unavailable();
    const evidence = projectAssessment(projected[index]);
    return {
      workspace_id: grant.workspaceId,
      domain_id: row.domain_id,
      domain: row.domain,
      verification_status: row.verification_status,
      verified_at: row.verified_at == null ? null : safeDate(row.verified_at),
      last_completed_scan_id: hasScan ? row.scan_id : null,
      last_completed_scan_created_at: hasScan ? safeDate(row.scan_created_at) : null,
      ...evidence,
    };
  });
  const last = page.at(-1);
  return result({
    workspace_id: grant.workspaceId, domains, limit: PAGE_SIZE,
    has_more: data.results.length > PAGE_SIZE,
    next_cursor: data.results.length > PAGE_SIZE && last
      ? domainCursor(last.domain, last.domain_id, grant.workspaceId) : null,
  });
}

function findingKeyset(cursor) {
  if (!cursor) return { sql: "", params: [] };
  const rank = "(CASE f.severity WHEN 'critical' THEN 0 ELSE 1 END)";
  return {
    sql: `AND (${rank} > ? OR (${rank} = ? AND s.created_at < ?)
              OR (${rank} = ? AND s.created_at = ? AND f.id < ?))`,
    params: [cursor.rank, cursor.rank, cursor.createdAt,
      cursor.rank, cursor.createdAt, cursor.id],
  };
}

async function listFindings(env, grant, input, scope) {
  const portfolio = scope === "portfolio";
  readInput(input, portfolio ? ["cursor"] : ["workspaceId", "cursor"]);
  const workspaceIds = portfolio ? grant?.portfolioWorkspaceIds : [grant?.workspaceId];
  if (portfolio) {
    if (grant?.portfolioRead !== true || Object.hasOwn(input, "workspaceId")) throw unavailable();
  } else if (!validId(grant?.workspaceId) || input.workspaceId !== grant.workspaceId) {
    throw unavailable();
  }
  await assertCurrentAccess(env, grant?.userId, workspaceIds);
  const cursor = parseFindingCursor(input.cursor, scope, portfolio ? null : grant.workspaceId);
  if (workspaceIds.length === 0) return result({
    scope, workspace_id: null, findings: [], limit: PAGE_SIZE,
    has_more: false, next_cursor: null,
    coverage_state: "not_proven_complete",
  });
  const placeholders = workspaceIds.map(() => "?").join(",");
  const keyset = findingKeyset(cursor);
  const data = await env.cybermeters_db.prepare(
    `SELECT f.id AS finding_id, f.finding_slug, f.severity, f.title,
            s.id AS scan_id, s.workspace_id, s.domain_id,
            s.status, s.domain AS scan_domain, s.score, s.rating,
            s.scan_quality, s.created_at AS scan_created_at,
            d.domain, wd.verification_status,
            EXISTS (
              SELECT 1 FROM scans newer
               WHERE newer.workspace_id = s.workspace_id AND newer.domain = s.domain
                 AND (newer.created_at > s.created_at
                   OR (newer.created_at = s.created_at AND newer.id > s.id))
            ) AS newer_scan_without_complete_assessment
       FROM findings f
       JOIN scans s ON s.id = f.scan_id
       JOIN domains d ON d.id = s.domain_id
       JOIN workspace_domains wd ON wd.domain_id = s.domain_id
                                 AND wd.workspace_id = s.workspace_id
       JOIN workspaces w ON w.id = s.workspace_id AND w.deleted_at IS NULL
      WHERE s.workspace_id IN (${placeholders})
        AND s.status = 'completed' AND s.scan_quality = 'complete'
        AND wd.verification_status = 'verified'
        AND f.severity IN ('critical', 'high')
        AND ${visibleFindingSql("f", "s")}
        AND s.id = (
          SELECT sy.id FROM scans sy
           WHERE sy.workspace_id = s.workspace_id AND sy.domain = s.domain
             AND sy.status = 'completed' AND sy.scan_quality = 'complete'
           ORDER BY sy.created_at DESC, sy.id DESC LIMIT 1
        )
        ${keyset.sql}
      ORDER BY CASE f.severity WHEN 'critical' THEN 0 ELSE 1 END ASC,
               s.created_at DESC, f.id DESC LIMIT ?`,
  ).bind(...workspaceIds, ...keyset.params, PAGE_SIZE + 1).all();
  if (!Array.isArray(data?.results)) throw unavailable();
  const page = data.results.slice(0, PAGE_SIZE);
  const projected = await projectSourceScans(env, page, (row) => ({
    id: row.scan_id, domain: row.scan_domain, status: row.status,
    score: row.score, rating: row.rating, scan_quality: row.scan_quality,
  }));
  const findings = page.map((row, index) => {
    if (!validId(row.finding_id) || !validId(row.scan_id) ||
        !validId(row.workspace_id) || !validId(row.domain_id) ||
        !validHost(row.domain) || !["critical", "high"].includes(row.severity) ||
        !VERIFICATION.has(row.verification_status) ||
        !workspaceIds.includes(row.workspace_id)) throw unavailable();
    const evidence = projectAssessment(projected[index]);
    return {
      workspace_id: row.workspace_id,
      domain_id: row.domain_id,
      domain: row.domain,
      finding_id: row.finding_id,
      finding_type: row.finding_slug == null ? null : safeText(row.finding_slug, 100),
      title: safeText(row.title, 200),
      severity: row.severity,
      source_scan_id: row.scan_id,
      source_scan_created_at: safeDate(row.scan_created_at),
      source_scan_quality: "complete",
      domain_verification_status: row.verification_status,
      newer_scan_without_complete_assessment:
        row.newer_scan_without_complete_assessment === 1,
      evidence_state: evidence.source_report_state !== "verified" ? "insufficient"
        : evidence.assessment.authoritative ? "authoritative"
        : evidence.assessment.provisional ? "provisional" : "insufficient",
      ...evidence,
    };
  });
  const last = page.at(-1);
  return result({
    scope, workspace_id: portfolio ? null : grant.workspaceId,
    findings, limit: PAGE_SIZE,
    has_more: data.results.length > PAGE_SIZE,
    next_cursor: data.results.length > PAGE_SIZE && last
      ? findingCursor(scope, portfolio ? null : grant.workspaceId,
        last.severity, last.scan_created_at, last.finding_id)
      : null,
    // A zero means no rows in this selected complete-scan scope, not that every
    // tenant/domain was fully assessed or that there is no risk.
    coverage_state: "not_proven_complete",
  });
}

/** Critical/high findings for one currently authorised workspace. */
export const projectMcpFindings = (env, grant, facts, input = {}) =>
  listFindings(env, grant, input, "workspace");

/** The caller must supply an already authorised, server-derived portfolio grant. */
export const projectMcpPortfolioFindings = (env, grant, facts, input = {}) =>
  listFindings(env, grant, input, "portfolio");
