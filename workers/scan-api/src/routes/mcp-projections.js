// Bounded, read-only MCP projections over the platform's canonical decisions.
// These are called only after fresh MCP admission and never dispatch public
// routes: some public GETs intentionally perform report repair on read.
import { getCurrentPosturePresentation } from "../engines/current-posture.js";
import { resolveCyberMotDomainStates } from "../engines/cyber-mot-domains.js";
import { getCyberEssentialsSnapshot } from "../engines/ce-readiness.js";
import { projectPhase5ScanRowsForCustomer } from "../engines/phase5-evidence.js";
import {
  CANONICAL_DOMAIN_KEYS, canonicalPhaseFor, caseTypeEntry,
  verificationSupportForCase,
} from "../engines/managed-case-model.js";

const SAFE_NAME_RE = /^[^\x00-\x1f\x7f\p{Cf}]{1,100}$/u;
const SAFE_HOST_RE = /^[A-Za-z0-9.-]{1,253}$/;
const SAFE_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const SAFE_CODE_RE = /^[a-z][a-z0-9_]{0,31}$/;
const SCAN_LIMIT = 10;
const CASE_LIMIT = 10;
const MAX_REPORT_BYTES = 2_000_000;
const MAX_REPORT_READS = 16;
const MAX_TOTAL_REPORT_BYTES = 8_000_000;
const DOMAIN_KEYS = new Set(CANONICAL_DOMAIN_KEYS);

// Canonical selectors may catch R2 errors and conservatively continue. Track
// budget breaches outside those helpers so the MCP call still fails closed.
function boundedReportReads(env) {
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
        count += 1;
        if (count > MAX_REPORT_READS) {
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
  };
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
  const established = state === "assessed";
  const authoritative = posture?.authoritative;
  const latestAt = safeDate(latest?.created_at);
  if (established && latestAt === null) throw new Error("invalid_projection");
  const score = established ? safeScore(authoritative?.display_score) : null;
  if (established && score === null) throw new Error("invalid_projection");
  return {
    workspace_id: workspaceId,
    display_name: safeName(facts.workspace?.name),
    domain_count: safeCount(domains.n),
    open_case_count: safeCount(cases.n),
    score_state: state === "not_assessed" && latestAt !== null ? "current_not_assessed" : state,
    score_value: established ? Math.round(score) : null,
    latest_measurement_at: latestAt,
    evidence_state: established ? "authoritative" : state === "latest_incomplete" ? "provisional" : "insufficient",
    coverage_state: established ? "complete" : state === "latest_incomplete" ? "partial" : latestAt ? "unavailable" : "not_assessed",
    limitations: established ? [] : ["No verified complete assessment currently establishes this workspace's score."],
  };
}

export async function projectMcpPosture(env, grant) {
  const workspaceId = grant.workspaceId;
  const reports = boundedReportReads(env);
  const posture = await getCurrentPosturePresentation(reports.env, { workspaceId });
  reports.assertWithinBudget();
  const sourceScanId = posture?.latest_provisional_scan_id ?? posture?.authoritative_scan_id ?? null;
  const latest = await env.cybermeters_db.prepare(
    "SELECT id FROM scans WHERE workspace_id = ? AND status = 'completed' ORDER BY created_at DESC, id DESC LIMIT 1",
  ).bind(workspaceId).first();
  if (latest && !sourceScanId) throw new Error("invalid_projection");
  let report = null;
  if (sourceScanId) {
    if (!SAFE_ID_RE.test(sourceScanId)) throw new Error("invalid_projection");
    const object = await reports.env.cybermeters_reports?.get(`reports/${sourceScanId}.json`);
    reports.assertWithinBudget();
    if (!object || !Number.isSafeInteger(object.size) || object.size > MAX_REPORT_BYTES) {
      throw new Error("invalid_projection");
    }
    report = await object.json();
    if (!report || typeof report !== "object" || Array.isArray(report)) {
      throw new Error("invalid_projection");
    }
    if ((report.scan_id && report.scan_id !== sourceScanId) ||
        (report.workspace_id && report.workspace_id !== workspaceId)) {
      throw new Error("invalid_projection");
    }
  }
  // The canonical resolver supplies the eight domain states. Never derive them
  // from the scorecard or from a scan's numeric score.
  const ce = await getCyberEssentialsSnapshot(workspaceId, reports.env);
  reports.assertWithinBudget();
  const resolved = resolveCyberMotDomainStates(report, { scanId: sourceScanId, cyberEssentials: ce });
  if (!Array.isArray(resolved) || resolved.length !== 8) throw new Error("invalid_projection");
  return {
    workspace_id: workspaceId,
    source_scan_id: sourceScanId,
    score_state: scoreState(posture),
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

export async function projectMcpRecentScans(env, grant) {
  const result = await env.cybermeters_db.prepare(
    `SELECT id, domain, status, score, rating, scan_quality, created_at
       FROM scans WHERE workspace_id = ?
      ORDER BY created_at DESC, id DESC LIMIT ?`,
  ).bind(grant.workspaceId, SCAN_LIMIT + 1).all();
  if (!Array.isArray(result?.results)) throw new Error("invalid_projection");
  const reports = boundedReportReads(env);
  const projected = await projectPhase5ScanRowsForCustomer(reports.env, result.results.slice(0, SCAN_LIMIT));
  reports.assertWithinBudget();
  return {
    workspace_id: grant.workspaceId,
    scans: projected.map(projectScan),
    limit: SCAN_LIMIT,
    has_more: result.results.length > SCAN_LIMIT,
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

export async function projectMcpManagedCases(env, grant) {
  const result = await env.cybermeters_db.prepare(
    `SELECT id, case_type, domain_key, status, severity, remediation_id,
            created_at, updated_at, verified_at
       FROM managed_cases
      WHERE workspace_id = ? AND status NOT IN ('closed','false_positive','risk_accepted')
      ORDER BY created_at DESC, id DESC LIMIT ?`,
  ).bind(grant.workspaceId, CASE_LIMIT + 1).all();
  if (!Array.isArray(result?.results)) throw new Error("invalid_projection");
  return {
    workspace_id: grant.workspaceId,
    cases: result.results.slice(0, CASE_LIMIT).map((row) => {
      if (!SAFE_ID_RE.test(row.id)) throw new Error("invalid_projection");
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
    }),
    limit: CASE_LIMIT,
    has_more: result.results.length > CASE_LIMIT,
  };
}
