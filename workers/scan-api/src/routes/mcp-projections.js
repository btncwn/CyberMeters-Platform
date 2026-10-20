// Bounded, read-only MCP projections over the platform's canonical decisions.
// These are called only after fresh MCP admission and never dispatch public
// routes: some public GETs intentionally perform report repair on read.
import { getCurrentPosturePresentation } from "../engines/current-posture.js";
import { resolveCyberMotDomainStates } from "../engines/cyber-mot-domains.js";
import { readScanReportSnapshot } from "../engines/report-snapshot.js";
import { projectPhase5ScanRowsForCustomer } from "../engines/phase5-evidence.js";
import {
  CANONICAL_DOMAIN_KEYS, canonicalPhaseFor, caseTypeEntry,
  verificationSupportForCase,
} from "../engines/managed-case-model.js";

const SAFE_NAME_RE = /^[^\x00-\x1f\x7f\p{Cf}]{1,100}$/u;
const SAFE_HOST_RE = /^[A-Za-z0-9.-]{1,253}$/;
const SAFE_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const SAFE_CODE_RE = /^[a-z][a-z0-9_]{0,31}$/;
const SAFE_CURSOR_RE = /^[A-Za-z0-9_~.-]{1,420}$/;
const SCAN_LIMIT = 10;
const CASE_LIMIT = 10;
const PORTFOLIO_LIMIT = 5;
const MAX_REPORT_BYTES = 2_000_000;
const MAX_REPORT_READS = 16;
const MAX_TOTAL_REPORT_BYTES = 8_000_000;
const DOMAIN_KEYS = new Set(CANONICAL_DOMAIN_KEYS);

// A list of scans must not need every full report. Plan the reads from object
// metadata, newest row first: a report is admitted while the running total
// stays inside the budget; the rest are left unread and their rows say so
// ("evidence_read_bound_exceeded") instead of failing the whole call. A key
// with no object is passed through so the reader reports it missing.
export async function planListReportReads(env, keys) {
  const reports = env?.cybermeters_reports;
  if (!reports || typeof reports.head !== "function") return null;
  const admitted = new Set();
  let total = 0;
  for (const key of keys) {
    const meta = await reports.head(key);
    if (!meta) { admitted.add(key); continue; }
    const size = meta.size;
    if (!Number.isSafeInteger(size) || size < 0 || size > MAX_REPORT_BYTES) continue;
    if (total + size > MAX_TOTAL_REPORT_BYTES) continue;
    total += size;
    admitted.add(key);
  }
  return admitted;
}

export const EVIDENCE_READ_BOUND_EXCEEDED = "evidence_read_bound_exceeded";

// Canonical selectors may catch R2 errors and conservatively continue. Track
// budget breaches outside those helpers so the MCP call still fails closed.
// With `admitted`, a key outside the plan is refused as not read (the reader
// marks its row bounded out); it is not a breach.
export function boundedReportReads(env, { maxReads = MAX_REPORT_READS, admitted = null } = {}) {
  if (!Number.isSafeInteger(maxReads) || maxReads < 1 || maxReads > 20) {
    throw new Error("mcp_report_read_budget");
  }
  const reports = env.cybermeters_reports;
  let count = 0;
  let bytes = 0;
  let breached = false;
  if (!reports || typeof reports.get !== "function") {
    return { env, assertWithinBudget() {} };
  }
  const guarded = {
    ...env,
    cybermeters_reports: {
      async get(...args) {
        if (breached) throw new Error("mcp_report_read_budget");
        if (admitted && !admitted.has(args[0])) {
          throw Object.assign(new Error(EVIDENCE_READ_BOUND_EXCEEDED), { code: EVIDENCE_READ_BOUND_EXCEEDED });
        }
        count += 1;
        if (count > maxReads) {
          breached = true;
          throw new Error("mcp_report_read_budget");
        }
        const object = await reports.get(...args);
        if (!object) return null;
        const size = object.size;
        if (!Number.isSafeInteger(size) || size < 0 ||
            size > MAX_REPORT_BYTES || bytes + size > MAX_TOTAL_REPORT_BYTES) {
          breached = true;
          throw new Error("mcp_report_read_budget");
        }
        bytes += size;
        return object;
      },
    },
  };
  return {
    env: guarded,
    assertWithinBudget() {
      if (breached) throw new Error("mcp_report_read_budget");
    },
  };
}

function safeName(value) {
  if (typeof value !== "string" || !SAFE_NAME_RE.test(value)) throw new Error("invalid_projection");
  return value;
}

function safeLimitation(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 500 ||
      /[\x00-\x1f\x7f\p{Cf}]/u.test(value)) throw new Error("invalid_projection");
  return value;
}

export function projectMcpLimitations(values) {
  if (!Array.isArray(values) || values.length > 4) throw new Error("invalid_projection");
  return values.map(safeLimitation);
}

function safeCount(value) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 0) throw new Error("invalid_projection");
  return n;
}

function safeDate(value) {
  if (value == null) return null;
  if (typeof value !== "string" || value.length > 40) throw new Error("invalid_projection");
  const time = Date.parse(value.includes("T") ? value : `${value.replace(" ", "T")}Z`);
  if (!Number.isFinite(time)) throw new Error("invalid_projection");
  return new Date(time).toISOString();
}

function listCursor(kind, workspaceId, row) {
  const time = row.created_at;
  safeDate(time);
  if (!SAFE_ID_RE.test(row.id) || typeof time !== "string" ||
      !/^[\x20-\x7e]{1,40}$/.test(time)) throw new Error("invalid_projection");
  const encoded = btoa(time).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  return `${kind}1~${workspaceId}~${encoded}~${row.id}`;
}

function parseListCursor(value, kind, workspaceId) {
  if (value == null) return null;
  if (typeof value !== "string" || !SAFE_CURSOR_RE.test(value)) throw new Error("invalid_projection");
  const parts = value.split("~");
  if (parts.length !== 4 || parts[0] !== `${kind}1` ||
      parts[1] !== workspaceId || !SAFE_ID_RE.test(parts[3]) ||
      !/^[A-Za-z0-9_-]{1,56}$/.test(parts[2])) throw new Error("invalid_projection");
  let createdAt;
  try {
    createdAt = atob(parts[2].replace(/-/g, "+").replace(/_/g, "/"));
    if (listCursor(kind, workspaceId, { created_at: createdAt, id: parts[3] }) !== value) {
      throw new Error("invalid_projection");
    }
  } catch { throw new Error("invalid_projection"); }
  return { createdAt, id: parts[3] };
}

function safeScore(value) {
  if (value == null) return null;
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0 || n > 100) throw new Error("invalid_projection");
  return n;
}

function safeDomain(value) {
  if (typeof value !== "string" || !SAFE_HOST_RE.test(value)) throw new Error("invalid_projection");
  return value;
}

function safeCode(value) {
  if (typeof value !== "string" || !SAFE_CODE_RE.test(value)) throw new Error("invalid_projection");
  return value;
}

function scoreState(posture) {
  if (posture?.latest_provisional) return "latest_incomplete";
  return posture?.state === "established" ? "assessed" : "not_assessed";
}

async function verifiedPostureSnapshot(env, workspaceId, scanId, readSnapshot = readScanReportSnapshot) {
  if (!SAFE_ID_RE.test(scanId)) throw new Error("invalid_projection");
  let read;
  try {
    read = await readSnapshot(env, scanId, {
      repair: false, allowReconstruction: false, includeSuccessor: false,
    });
  } catch {
    return null;
  }
  const meta = read?.customerSnapshot?.snapshot;
  const domains = read?.customerSnapshot?.domains;
  if (read?.status !== "ok" || read.integrity?.verified !== true ||
      read.row?.scan_id !== scanId || read.row?.workspace_id !== workspaceId ||
      meta?.scan_id !== scanId || meta?.workspace_id !== workspaceId ||
      meta?.domain_id !== read.row?.domain_id ||
      !Array.isArray(domains) || domains.length !== 8 ||
      new Set(domains.map((row) => row?.domain_key)).size !== 8 ||
      domains.some((row) => !DOMAIN_KEYS.has(row?.domain_key) ||
        row.state === "assessed_healthy" &&
          (!row.evidence_grade?.grade || row.evidence_grade.grade === "L0"))) {
    return null;
  }
  return read.customerSnapshot;
}

function authoritativeSnapshotScore(snapshot, posture) {
  if (scoreState(posture) !== "assessed") return null;
  const assessment = snapshot?.overall?.assessment;
  const snapshotScore = safeScore(snapshot?.overall?.cyber_metrics_score);
  if (assessment?.quality !== "complete" || assessment.authoritative !== true ||
      assessment.provisional === true || assessment.comparable !== true ||
      snapshotScore === null ||
      snapshotScore !== safeScore(posture?.authoritative?.display_score)) return null;
  return snapshotScore;
}

function projectScan(row) {
  if (!row || !SAFE_ID_RE.test(row.id)) throw new Error("invalid_projection");
  const assessment = row.assessment;
  const quality = assessment?.quality ?? "unknown";
  const authoritative = assessment?.authoritative === true;
  const provisional = assessment?.provisional === true;
  const comparable = assessment?.comparable === true;
  return {
    scan_id: row.id,
    domain: safeDomain(row.domain),
    status: safeCode(row.status),
    scan_quality: row.scan_quality == null ? null : safeCode(row.scan_quality),
    assessment: { quality: safeCode(quality), authoritative, provisional, comparable },
    quality: safeCode(quality),
    authoritative,
    provisional,
    comparable,
    score_available: assessment?.display_score != null && safeScore(assessment.display_score) != null,
    measured_at: safeDate(row.created_at),
    // Whether this row's stored evidence was read for this answer. "not_read"
    // means the list's report budget was spent on newer rows.
    ...(row.status === "completed" ? { evidence_read: evidenceRead(row.phase5_evidence_read?.state) } : {}),
  };
}

function evidenceRead(state) {
  if (state === "verified") return "read";
  if (state === "bounded_out") return "not_read";
  return "unavailable";
}

export async function projectMcpWorkspaces(_env, grant, facts) {
  return {
    workspaces: [{
      workspace_id: grant.workspaceId,
      display_name: safeName(facts.workspace?.name),
      role: grant.role,
    }],
    count: 1,
  };
}

export async function projectMcpSummary(env, grant, facts) {
  const db = env.cybermeters_db;
  const workspaceId = grant.workspaceId;
  const reports = boundedReportReads(env);
  const [domains, cases, latest, posture] = await Promise.all([
    db.prepare("SELECT COUNT(*) AS n FROM workspace_domains WHERE workspace_id = ?")
      .bind(workspaceId).first(),
    db.prepare("SELECT COUNT(*) AS n FROM managed_cases WHERE workspace_id = ? AND status NOT IN ('closed','false_positive','risk_accepted')")
      .bind(workspaceId).first(),
    db.prepare("SELECT created_at FROM scans WHERE workspace_id = ? AND status = 'completed' ORDER BY created_at DESC, id DESC LIMIT 1")
      .bind(workspaceId).first(),
    getCurrentPosturePresentation(reports.env, { workspaceId }),
  ]);
  reports.assertWithinBudget();
  if (!domains || !cases) throw new Error("invalid_projection");
  const state = scoreState(posture);
  const snapshot = state === "assessed" && posture?.authoritative_scan_id
    ? await verifiedPostureSnapshot(reports.env, workspaceId, posture.authoritative_scan_id)
    : null;
  reports.assertWithinBudget();
  const score = authoritativeSnapshotScore(snapshot, posture);
  const established = score !== null;
  const latestAt = safeDate(latest?.created_at);
  if (established && latestAt === null) throw new Error("invalid_projection");
  const presentedState = established ? "assessed" :
    state === "latest_incomplete" ? "latest_incomplete" :
    latestAt !== null ? "current_not_assessed" : "not_assessed";
  return {
    workspace_id: workspaceId,
    display_name: safeName(facts.workspace?.name),
    domain_count: safeCount(domains.n),
    open_case_count: safeCount(cases.n),
    score_state: presentedState,
    score_value: established ? Math.round(score) : null,
    latest_measurement_at: latestAt,
    evidence_state: established ? "authoritative" : state === "latest_incomplete" ? "provisional" : "insufficient",
    coverage_state: established ? "complete" : state === "latest_incomplete" ? "partial" : latestAt ? "unavailable" : "not_assessed",
    limitations: established ? [] : ["No verified complete assessment currently establishes this workspace's score."],
  };
}

/** Summaries are computed only for the exact workspace set selected at consent. */
export async function projectMcpPortfolioSummary(env, grant, facts, input = {}) {
  const selected = grant?.portfolioWorkspaceIds;
  const workspaces = facts?.portfolio;
  if (grant?.portfolioRead !== true || !Array.isArray(selected) ||
      !Array.isArray(workspaces) || selected.length > 500 ||
      workspaces.length !== selected.length ||
      new Set(selected).size !== selected.length ||
      new Set(workspaces.map((row) => row?.id)).size !== selected.length ||
      selected.some((id) => typeof id !== "string" || !SAFE_ID_RE.test(id)) ||
      workspaces.some((row) => !row || !selected.includes(row.id))) {
    throw new Error("invalid_projection");
  }
  const ordered = [...workspaces].sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  const cursor = input.cursor;
  if (cursor !== undefined && (!SAFE_ID_RE.test(cursor) || !selected.includes(cursor))) {
    throw new Error("invalid_projection");
  }
  const remaining = cursor ? ordered.filter((row) => row.id > cursor) : ordered;
  const page = remaining.slice(0, PORTFOLIO_LIMIT);
  // A single R2 budget spans the whole portfolio page, including selectors that
  // intentionally catch R2 errors. The page fails closed if that budget is hit.
  const reports = boundedReportReads(env);
  const summaries = [];
  for (const row of page) {
    summaries.push(await projectMcpSummary(reports.env,
      { ...grant, workspaceId: row.id }, { workspace: row }));
    reports.assertWithinBudget();
  }
  const value = {
    scope: "portfolio", selected_workspace_count: selected.length,
    workspaces: summaries, limit: PORTFOLIO_LIMIT,
    has_more: remaining.length > PORTFOLIO_LIMIT,
    next_cursor: remaining.length > PORTFOLIO_LIMIT ? page.at(-1).id : null,
    coverage_state: "not_proven_complete",
  };
  if (new TextEncoder().encode(JSON.stringify(value)).byteLength > 20_000) {
    throw new Error("invalid_projection");
  }
  return value;
}

export async function projectMcpPosture(env, grant, {
  getPosture = getCurrentPosturePresentation,
  readSnapshot = readScanReportSnapshot,
} = {}) {
  const workspaceId = grant.workspaceId;
  const reports = boundedReportReads(env);
  const posture = await getPosture(reports.env, { workspaceId });
  reports.assertWithinBudget();
  const sourceScanId = posture?.latest_provisional_scan_id ?? posture?.authoritative_scan_id ?? null;
  // The snapshot freezes resolver decisions, including the Cyber Essentials
  // context from scan finalisation. Never re-resolve from mutable raw R2 JSON.
  const snapshot = sourceScanId
    ? await verifiedPostureSnapshot(reports.env, workspaceId, sourceScanId, readSnapshot)
    : null;
  reports.assertWithinBudget();
  const resolved = snapshot?.domains ?? resolveCyberMotDomainStates(null, { scanId: null });
  if (!Array.isArray(resolved) || resolved.length !== 8) throw new Error("invalid_projection");
  const state = scoreState(posture);
  const established = authoritativeSnapshotScore(snapshot, posture) !== null;
  return {
    workspace_id: workspaceId,
    source_scan_id: snapshot ? sourceScanId : null,
    score_state: !snapshot ? "not_assessed" : established ? "assessed" :
      state === "latest_incomplete" ? "latest_incomplete" : "current_not_assessed",
    domains: resolved.map((domain) => {
      if (!DOMAIN_KEYS.has(domain.domain_key)) throw new Error("invalid_projection");
      return {
        domain_key: domain.domain_key,
        display_name: safeName(domain.display_name),
        state: domain.state,
        coverage: domain.coverage ?? null,
        evidence_strength: domain.confidence ?? null,
        evidence_count: safeCount(domain.evidence_count),
        finding_count: safeCount(domain.finding_count),
        highest_severity: domain.highest_severity ?? null,
        last_assessed_at: safeDate(domain.last_assessed_at),
        // Preserve every canonical caveat. An oversized response is unavailable
        // rather than silently dropping material evidence limitations.
        limitations: projectMcpLimitations(domain.limitations),
      };
    }),
  };
}

export async function projectMcpRecentScans(env, grant, _facts, input = {}) {
  const cursor = parseListCursor(input.cursor, "s", grant.workspaceId);
  const result = await env.cybermeters_db.prepare(
    `SELECT id, domain, status, score, rating, scan_quality, created_at
       FROM scans WHERE workspace_id = ?
        ${cursor ? "AND (created_at < ? OR (created_at = ? AND id < ?))" : ""}
      ORDER BY created_at DESC, id DESC LIMIT ?`,
  ).bind(...(cursor
    ? [grant.workspaceId, cursor.createdAt, cursor.createdAt, cursor.id, SCAN_LIMIT + 1]
    : [grant.workspaceId, SCAN_LIMIT + 1])).all();
  if (!Array.isArray(result?.results)) throw new Error("invalid_projection");
  const page = result.results.slice(0, SCAN_LIMIT);
  const admitted = await planListReportReads(env, page
    .filter((row) => row?.status === "completed" && SAFE_ID_RE.test(row.id ?? ""))
    .map((row) => `reports/${row.id}.json`));
  const reports = boundedReportReads(env, { admitted });
  const projected = await projectPhase5ScanRowsForCustomer(reports.env, page);
  reports.assertWithinBudget();
  return {
    workspace_id: grant.workspaceId,
    scans: projected.map(projectScan),
    limit: SCAN_LIMIT,
    has_more: result.results.length > SCAN_LIMIT,
    next_cursor: result.results.length > SCAN_LIMIT
      ? listCursor("s", grant.workspaceId, result.results[SCAN_LIMIT - 1]) : null,
  };
}

export async function projectMcpScanStatus(env, grant, _facts, input) {
  const row = await env.cybermeters_db.prepare(
    `SELECT id, domain, status, score, rating, scan_quality, created_at
       FROM scans WHERE id = ? AND workspace_id = ? LIMIT 1`,
  ).bind(input.scanId, grant.workspaceId).first();
  if (!row) throw new Error("invalid_projection");
  const reports = boundedReportReads(env);
  const [projected] = await projectPhase5ScanRowsForCustomer(reports.env, [row]);
  reports.assertWithinBudget();
  return { workspace_id: grant.workspaceId, ...projectScan(projected) };
}

export async function projectMcpManagedCases(env, grant, _facts, input = {}) {
  const cursor = parseListCursor(input.cursor, "c", grant.workspaceId);
  const result = await env.cybermeters_db.prepare(
    `SELECT id, case_type, domain_key, status, severity, remediation_id,
            created_at, updated_at, verified_at
       FROM managed_cases
      WHERE workspace_id = ? AND status NOT IN ('closed','false_positive','risk_accepted')
        ${cursor ? "AND (created_at < ? OR (created_at = ? AND id < ?))" : ""}
      ORDER BY created_at DESC, id DESC LIMIT ?`,
  ).bind(...(cursor
    ? [grant.workspaceId, cursor.createdAt, cursor.createdAt, cursor.id, CASE_LIMIT + 1]
    : [grant.workspaceId, CASE_LIMIT + 1])).all();
  if (!Array.isArray(result?.results)) throw new Error("invalid_projection");
  return {
    workspace_id: grant.workspaceId,
    cases: result.results.slice(0, CASE_LIMIT).map(projectManagedCaseRow),
    limit: CASE_LIMIT,
    has_more: result.results.length > CASE_LIMIT,
    next_cursor: result.results.length > CASE_LIMIT
      ? listCursor("c", grant.workspaceId, result.results[CASE_LIMIT - 1]) : null,
  };
}

function projectManagedCaseRow(row) {
  if (!row || !SAFE_ID_RE.test(row.id)) throw new Error("invalid_projection");
  const key = row.domain_key || caseTypeEntry(row.case_type)?.domain_key;
  if (!DOMAIN_KEYS.has(key)) throw new Error("invalid_projection");
  return {
    case_id: row.id,
    domain_key: key,
    canonical_phase: canonicalPhaseFor(row.case_type, row.status),
    status: safeCode(row.status),
    severity: safeCode(row.severity),
    verification_support: verificationSupportForCase(row),
    created_at: safeDate(row.created_at),
    updated_at: safeDate(row.updated_at),
    verified_at: safeDate(row.verified_at),
  };
}

/** Resolve one case only inside the freshly admitted workspace. */
export async function projectMcpManagedCase(env, grant, _facts, input) {
  if (!SAFE_ID_RE.test(input?.caseId)) throw new Error("invalid_projection");
  const row = await env.cybermeters_db.prepare(
    `SELECT id, case_type, domain_key, status, severity, remediation_id,
            created_at, updated_at, verified_at
       FROM managed_cases WHERE workspace_id = ? AND id = ?
         AND status NOT IN ('closed','false_positive','risk_accepted') LIMIT 1`,
  ).bind(grant.workspaceId, input.caseId).first();
  if (!row) throw new Error("invalid_projection");
  return { workspace_id: grant.workspaceId, ...projectManagedCaseRow(row) };
}
