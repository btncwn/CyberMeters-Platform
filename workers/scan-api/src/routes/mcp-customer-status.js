// Bounded, read-only customer MCP status views. The private service owns OAuth,
// entitlement, rate limiting and awaited audit; these projections repeat the
// live workspace and verified-domain checks before touching customer evidence.
import { visibleFindingSql } from "../engines/finding-identity.js";
import { readScanReportSnapshot } from "../engines/report-snapshot.js";
import { resolveRemediation } from "../engines/remediation-registry.js";
import { buildCertificateLifecycleAssurance } from "../engines/certificate-customer-presentation.js";
import { boundedReportReads } from "./mcp-projections.js";

const PAGE_SIZE = 10;
const MAX_RESULT_BYTES = 20_000;
const MAX_OBSERVATION_BYTES = 32_000;
const ID = /^[A-Za-z0-9_-]{1,64}$/;
const HOST = /^[A-Za-z0-9.-]{1,253}$/;
const TYPE = /^[A-Za-z0-9_.-]{1,120}$/;
const ROLES = new Set(["viewer", "analyst", "admin", "owner"]);
const QUALITY = new Set(["complete", "partial", "degraded", "unknown"]);
const GRADES = new Set(["L0", "L1", "L2", "L3", "L4", "L5"]);
const SIGNAL_STATES = new Set(["observed", "not_observed", "unknown", "unavailable", "incomplete"]);
const CHECK_OUTCOMES = new Set(["passed", "failed", "not_checked"]);
const DOMAIN_STATES = new Set([
  "assessed_healthy", "issue_detected", "provisional", "degraded", "unavailable",
  "not_configured", "customer_input_required", "monitoring_only",
  "not_yet_assessed", "evidence_insufficient",
]);
// Version of this canonical-domain-to-Field-Guide route mapping, not a claim
// about the article's editorial revision.
const GUIDE_VERSION = "area-link-v1";
const GUIDE_SLUG = Object.freeze({
  email_protection: "email-protection", attack_surface: "attack-surface",
  website_security: "website-security", identity_exposure: "identity-exposure",
  shadow_it_unmanaged_technology: "shadow-it", certificates_trust: "certificates-trust",
  brand_protection: "brand-protection", cyber_essentials_readiness: "cyber-essentials",
});
const encoder = new TextEncoder();

function deny() { return new Error("mcp_projection_unavailable"); }
function id(value) { return typeof value === "string" && ID.test(value); }
function host(value) { return typeof value === "string" && HOST.test(value); }
function text(value, max, optional = false) {
  if (optional && value == null) return null;
  if (typeof value !== "string" || !value.length || value.length > max ||
      /[\x00-\x1f\x7f\p{Cf}]/u.test(value) || /cm_[a-f0-9]{64}/i.test(value)) throw deny();
  return value;
}
function date(value, optional = false) {
  if (optional && value == null) return null;
  if (typeof value !== "string" || value.length > 40) throw deny();
  const parsed = Date.parse(value.includes("T") ? value : `${value.replace(" ", "T")}Z`);
  if (!Number.isFinite(parsed)) throw deny();
  return new Date(parsed).toISOString();
}
function listed(value, choices, fallback = "unknown") {
  if (value == null) return fallback;
  if (!choices.has(value)) throw deny();
  return value;
}
function output(value) {
  if (encoder.encode(JSON.stringify(value)).byteLength > MAX_RESULT_BYTES) throw deny();
  return value;
}
function inputObject(input, allowed) {
  if (!input || typeof input !== "object" || Array.isArray(input) ||
      Object.keys(input).some((key) => !allowed.includes(key))) throw deny();
}
function cursorOf(kind, workspaceId, first, second = null) {
  return second == null ? `${kind}1~${workspaceId}~${first}` : `${kind}1~${workspaceId}~${first}~${second}`;
}
function parseCursor(cursor, kind, workspaceId) {
  if (cursor == null) return null;
  if (typeof cursor !== "string" || cursor.length > 350) throw deny();
  const parts = cursor.split("~");
  if (parts[0] !== `${kind}1` || parts[1] !== workspaceId ||
      (kind === "t" && (parts.length !== 3 || !id(parts[2]))) ||
      (kind === "e" && (parts.length !== 4 || !host(parts[2]) || !id(parts[3])))) throw deny();
  return parts;
}

async function assertWorkspace(env, grant, input, allowed) {
  inputObject(input, allowed);
  if (!id(grant?.userId) || !id(grant?.workspaceId) ||
      input.workspaceId !== grant.workspaceId) throw deny();
  const row = await env.cybermeters_db.prepare(
    `SELECT w.id, wm.role
       FROM workspaces w
       JOIN workspace_members wm ON wm.workspace_id = w.id AND wm.user_id = ?
       JOIN mcp_beta_workspace_access b ON b.workspace_id = w.id AND b.status = 'enabled'
      WHERE w.id = ? AND w.deleted_at IS NULL
        AND NOT EXISTS (SELECT 1 FROM deletion_requests d
          WHERE d.request_type = 'workspace' AND d.workspace_id = w.id
            AND d.status NOT IN ('completed','cancelled')) LIMIT 1`,
  ).bind(grant.userId, grant.workspaceId).first();
  if (!row || !ROLES.has(row.role)) throw deny();
  return grant.workspaceId;
}

async function snapshotFor(env, scan, readSnapshot = readScanReportSnapshot, budget = {}) {
  const reports = boundedReportReads(env, budget);
  let read;
  try {
    read = await readSnapshot(reports.env, scan.scan_id, {
      repair: false, allowReconstruction: false, includeSuccessor: false,
    });
  } finally {
    reports.assertWithinBudget();
  }
  if (!read || typeof read !== "object") throw deny();
  if (read.row && (read.row.scan_id !== scan.scan_id ||
      read.row.workspace_id !== scan.workspace_id || read.row.domain_id !== scan.domain_id)) throw deny();
  if (read.status !== "ok") return null;
  const meta = read.customerSnapshot?.snapshot;
  if (!read.row || read.integrity?.verified !== true ||
      !meta || meta.scan_id !== scan.scan_id ||
      meta.workspace_id !== scan.workspace_id || meta.domain_id !== scan.domain_id) throw deny();
  return read;
}

function findingGrade(item) {
  return listed(item?.evidence_grade?.grade, GRADES, "L0");
}
function safeRemediation(slug, item) {
  if (!TYPE.test(slug)) throw deny();
  const resolution = resolveRemediation({ finding_type: slug });
  if (resolution.status !== "resolved") return { status: "unknown" };
  // A frozen snapshot may name a different remediation version. Do not silently
  // replace its meaning with current registry copy.
  if (item?.remediation_id != null && item.remediation_id !== resolution.remediation_id) {
    return { status: "version_mismatch" };
  }
  const limits = Array.isArray(resolution.limitations) ? resolution.limitations : [];
  if (limits.length > 4) throw deny();
  return {
    status: "resolved", remediation_id: text(resolution.remediation_id, 120),
    version: text(String(resolution.version), 80), domain_key: text(resolution.domain_key, 80),
    title: text(resolution.customer_title, 200),
    technical_explanation: text(resolution.technical_explanation, 800),
    business_impact: text(resolution.business_impact, 800),
    recommended_action: text(resolution.recommended_action, 1_000),
    verification_method: text(resolution.verification_method, 80),
    limitations: limits.map((value) => text(value, 300)),
  };
}

/** One D1 opaque finding ID, resolved only inside its verified workspace link. */
export async function projectMcpFindingExplanation(env, grant, _facts, input = {}, overrides = {}) {
  const workspaceId = await assertWorkspace(env, grant, input, ["workspaceId", "findingId"]);
  if (!id(input.findingId)) throw deny();
  const row = await env.cybermeters_db.prepare(
    `SELECT f.id AS finding_id, f.finding_slug, f.title, f.severity,
            s.id AS scan_id, s.workspace_id, s.domain_id, s.created_at AS scan_created_at,
            d.domain
       FROM findings f JOIN scans s ON s.id = f.scan_id
       JOIN domains d ON d.id = s.domain_id
       JOIN workspace_domains wd ON wd.workspace_id = s.workspace_id
                                AND wd.domain_id = s.domain_id
       JOIN workspaces w ON w.id = s.workspace_id AND w.deleted_at IS NULL
      WHERE f.id = ? AND s.workspace_id = ? AND s.status = 'completed'
        AND s.scan_quality = 'complete' AND wd.verification_status = 'verified'
        AND ${visibleFindingSql("f", "s")}
        AND s.id = (
          SELECT latest.id FROM scans latest
           WHERE latest.workspace_id = s.workspace_id AND latest.domain = s.domain
             AND latest.status = 'completed' AND latest.scan_quality = 'complete'
           ORDER BY latest.created_at DESC, latest.id DESC LIMIT 1
        ) LIMIT 1`,
  ).bind(input.findingId, workspaceId).first();
  if (!row || !id(row.scan_id) || !id(row.domain_id) || !host(row.domain) ||
      row.workspace_id !== workspaceId || !["critical", "high", "medium", "low", "info"].includes(row.severity)) {
    throw deny();
  }
  const base = {
    workspace_id: workspaceId, finding_id: row.finding_id,
    domain_id: row.domain_id, domain: row.domain,
    source_scan_id: row.scan_id, source_scan_created_at: date(row.scan_created_at),
  };
  const read = await snapshotFor(env, row, overrides.readSnapshot);
  if (!read) return output({ ...base, status: "snapshot_unavailable", finding: null,
    remediation: null, field_guide: null });
  const slug = row.finding_slug;
  if (typeof slug !== "string" || !TYPE.test(slug)) {
    return output({ ...base, status: "finding_not_in_snapshot", finding: null,
      remediation: null, field_guide: null });
  }
  const candidates = read.customerSnapshot.observed_findings;
  if (!Array.isArray(candidates) || candidates.length > 2_000) throw deny();
  const matched = candidates.filter((item) => item?.finding_id === slug &&
    item?.title === row.title && item?.severity === row.severity);
  if (matched.length !== 1) return output({ ...base, status: "finding_not_in_snapshot",
    finding: null, remediation: null, field_guide: null });
  const item = matched[0];
  const grade = findingGrade(item);
  const remediation = safeRemediation(slug, item);
  const guideSlug = GUIDE_SLUG[remediation.domain_key];
  return output({
    ...base, status: "available",
    finding: {
      type: slug, title: text(row.title, 200), severity: row.severity,
      evidence_grade: grade,
      evidence_state: grade === "L0" ? "insufficient"
        : read.customerSnapshot.overall?.assessment?.authoritative === true
          ? "authoritative" : "provisional",
      evidence_count: Number.isSafeInteger(item.evidence_ref?.count) && item.evidence_ref.count >= 0
        ? Math.min(item.evidence_ref.count, 1_000) : null,
      source_report_state: "integrity_verified_snapshot",
    },
    remediation,
    field_guide: guideSlug ? {
      version: GUIDE_VERSION, path: `/guide/${guideSlug}`,
      url: `https://app.cybermeters.com/guide/${guideSlug}`,
    } : null,
  });
}

/** Current managed certificate lifecycle; a D1 failure is never an empty list. */
export async function projectMcpTlsPosture(env, grant, _facts, input = {}) {
  const workspaceId = await assertWorkspace(env, grant, input, ["workspaceId", "cursor"]);
  const cursor = parseCursor(input.cursor, "t", workspaceId);
  const data = await env.cybermeters_db.prepare(
    `SELECT cl.id, cl.workspace_id, cl.domain_id, cl.primary_hostname,
            cl.not_after, cl.days_remaining, cl.renewal_readiness,
            cl.coverage_status, cl.verification_status, cl.last_seen_at,
            co.evidence_json AS current_observation_evidence_json
       FROM certificate_lifecycle cl
       JOIN workspace_domains wd ON wd.workspace_id = cl.workspace_id
                                AND wd.domain_id = cl.domain_id
       JOIN workspaces w ON w.id = cl.workspace_id AND w.deleted_at IS NULL
       LEFT JOIN certificate_observations co
         ON co.id = cl.current_certificate_observation_id
        AND co.workspace_id = cl.workspace_id AND co.domain_id = cl.domain_id
      WHERE cl.workspace_id = ? AND wd.verification_status = 'verified'
        ${cursor ? "AND cl.id > ?" : ""}
      ORDER BY cl.id ASC LIMIT ?`,
  ).bind(...(cursor ? [workspaceId, cursor[2], PAGE_SIZE + 1] : [workspaceId, PAGE_SIZE + 1])).all();
  if (!Array.isArray(data?.results)) throw deny();
  const page = data.results.slice(0, PAGE_SIZE);
  const certificates = page.map((row) => {
    if (!id(row.id) || !id(row.domain_id) || !host(row.primary_hostname) ||
        row.workspace_id !== workspaceId ||
        (row.current_observation_evidence_json != null &&
          (typeof row.current_observation_evidence_json !== "string" ||
            row.current_observation_evidence_json.length > MAX_OBSERVATION_BYTES))) throw deny();
    const assurance = buildCertificateLifecycleAssurance(row);
    if (row.days_remaining != null && !Number.isSafeInteger(row.days_remaining)) throw deny();
    const signals = {};
    for (const key of ["leaf", "expiry", "hostname_match", "trust_store_validation", "revocation_assurance"]) {
      const signal = assurance.signals?.[key];
      signals[key] = {
        state: listed(signal?.state, SIGNAL_STATES),
        check_outcome: listed(signal?.check?.outcome, CHECK_OUTCOMES, "not_checked"),
      };
    }
    return {
      workspace_id: workspaceId, certificate_lifecycle_id: row.id,
      domain_id: row.domain_id, primary_hostname: row.primary_hostname,
      not_after: date(row.not_after, true),
      days_remaining: row.days_remaining ?? null,
      renewal_readiness: text(row.renewal_readiness, 40),
      coverage_status: text(row.coverage_status, 40),
      verification_status: text(row.verification_status, 40),
      last_seen_at: date(row.last_seen_at),
      assurance_status: assurance.status === "current" ? "current" : "not_recorded",
      signals,
    };
  });
  const more = data.results.length > PAGE_SIZE;
  return output({ workspace_id: workspaceId,
    status: certificates.length ? "available" : "not_observed",
    certificates, limit: PAGE_SIZE, has_more: more,
    next_cursor: more ? cursorOf("t", workspaceId, page.at(-1).id) : null,
    coverage_state: "not_proven_complete",
  });
}

/** Latest completed snapshot for each verified domain, with DNS policy unknowns explicit. */
export async function projectMcpEmailPosture(env, grant, _facts, input = {}, overrides = {}) {
  const workspaceId = await assertWorkspace(env, grant, input, ["workspaceId", "cursor"]);
  const cursor = parseCursor(input.cursor, "e", workspaceId);
  const data = await env.cybermeters_db.prepare(
    `SELECT wd.domain_id, d.domain, s.id AS scan_id, s.workspace_id,
            s.status AS scan_status, s.scan_quality, s.created_at AS scan_created_at
       FROM workspace_domains wd
       JOIN workspaces w ON w.id = wd.workspace_id AND w.deleted_at IS NULL
       JOIN domains d ON d.id = wd.domain_id
       LEFT JOIN scans s ON s.id = (
         SELECT latest.id FROM scans latest
          WHERE latest.workspace_id = wd.workspace_id AND latest.domain_id = wd.domain_id
            AND latest.status = 'completed'
          ORDER BY latest.created_at DESC, latest.id DESC LIMIT 1
       )
      WHERE wd.workspace_id = ? AND wd.verification_status = 'verified'
        ${cursor ? "AND (d.domain > ? OR (d.domain = ? AND d.id > ?))" : ""}
      ORDER BY d.domain ASC, d.id ASC LIMIT ?`,
  ).bind(...(cursor
    ? [workspaceId, cursor[2], cursor[2], cursor[3], PAGE_SIZE + 1]
    : [workspaceId, PAGE_SIZE + 1])).all();
  if (!Array.isArray(data?.results)) throw deny();
  const reports = boundedReportReads(env, { maxReads: 20 });
  const domains = [];
  for (const row of data.results.slice(0, PAGE_SIZE)) {
    if (!id(row.domain_id) || !host(row.domain)) throw deny();
    const base = { workspace_id: workspaceId, domain_id: row.domain_id,
      domain: row.domain, source_scan_id: null, source_scan_created_at: null };
    if (!row.scan_id) {
      domains.push({ ...base, status: "not_assessed", email_domain_state: "not_yet_assessed",
        evidence_grade: "L0", dmarc: null, spf: null, dkim: null });
      continue;
    }
    if (!id(row.scan_id) || row.workspace_id !== workspaceId || row.scan_status !== "completed") throw deny();
    base.source_scan_id = row.scan_id;
    base.source_scan_created_at = date(row.scan_created_at);
    const read = await (overrides.readSnapshot ?? readScanReportSnapshot)(reports.env, row.scan_id, {
      repair: false, allowReconstruction: false, includeSuccessor: false,
    });
    reports.assertWithinBudget();
    if (!read || typeof read !== "object" ||
        (read.row && (read.row.scan_id !== row.scan_id ||
          read.row.workspace_id !== workspaceId || read.row.domain_id !== row.domain_id))) throw deny();
    if (read.status !== "ok") {
      domains.push({ ...base, status: "snapshot_unavailable", email_domain_state: "unavailable",
        evidence_grade: "L0", dmarc: null, spf: null, dkim: null });
      continue;
    }
    if (!read.row || read.integrity?.verified !== true ||
        read.customerSnapshot?.snapshot?.workspace_id !== workspaceId ||
        read.customerSnapshot.snapshot.domain_id !== row.domain_id ||
        read.customerSnapshot.snapshot.scan_id !== row.scan_id) throw deny();
    const entries = read.customerSnapshot.domains;
    if (!Array.isArray(entries) || entries.length > 16) throw deny();
    const email = entries.find((entry) => entry?.domain_key === "email_protection");
    const domainState = listed(email?.state, DOMAIN_STATES, "unavailable");
    const grade = listed(email?.evidence_grade?.grade, GRADES, "L0");
    const policy = read.dmarcPolicy?.status === "current" ? read.dmarcPolicy.evidence : null;
    const spfModule = read.customerModules?.email_security;
    const usableSpf = spfModule && spfModule.executed !== false &&
      spfModule.incomplete !== true && spfModule.outcome !== "deadline_exceeded";
    const spf = usableSpf ? spfModule.spf : null;
    const dkim = usableSpf ? spfModule.dkim : null;
    const spfResolution = ["complete", "partial", "permerror", "temperror"].includes(spf?.resolution_status)
      ? spf.resolution_status : "unknown";
    domains.push({
      ...base, status: "available", email_domain_state: domainState, evidence_grade: grade,
      dmarc: {
        evidence_status: read.dmarcPolicy?.status === "current" ? "current" : "unavailable",
        observation_state: policy?.observation_state ?? "unavailable",
        record_validity: policy?.record_validity ?? "indeterminate",
        effective_requested_policy: policy?.effective_requested_policy ?? null,
        policy_completeness: policy?.policy_completeness ?? "unavailable",
      },
      spf: {
        observation_state: spfResolution === "complete" && spf?.present === true ? "observed"
          : spfResolution === "complete" && spf?.present === false ? "not_observed" : "unknown",
        present: spfResolution === "complete" && typeof spf?.present === "boolean" ? spf.present : null,
        resolution_status: spfResolution,
      },
      dkim: { observation_state: dkim?.present === true ? "selector_observed" : "unknown" },
    });
  }
  reports.assertWithinBudget();
  const more = data.results.length > PAGE_SIZE;
  const last = data.results[Math.min(PAGE_SIZE, data.results.length) - 1];
  return output({ workspace_id: workspaceId,
    status: domains.some((row) => row.status === "available") ? "available"
      : domains.some((row) => row.status === "snapshot_unavailable") ? "snapshot_unavailable" : "not_assessed",
    domains, limit: PAGE_SIZE, has_more: more,
    next_cursor: more && last ? cursorOf("e", workspaceId, last.domain, last.domain_id) : null,
    coverage_state: "not_proven_complete",
  });
}

/** A single latest verified-domain scan summary, never a portfolio report. */
export async function projectMcpReportSummary(env, grant, _facts, input = {}, overrides = {}) {
  const workspaceId = await assertWorkspace(env, grant, input, ["workspaceId"]);
  const row = await env.cybermeters_db.prepare(
    `SELECT s.id AS scan_id, s.workspace_id, s.domain_id, s.domain,
            s.created_at AS scan_created_at, s.scan_quality
       FROM scans s JOIN workspace_domains wd
         ON wd.workspace_id = s.workspace_id AND wd.domain_id = s.domain_id
       JOIN workspaces w ON w.id = s.workspace_id AND w.deleted_at IS NULL
      WHERE s.workspace_id = ? AND s.status = 'completed'
        AND wd.verification_status = 'verified'
      ORDER BY s.created_at DESC, s.id DESC LIMIT 1`,
  ).bind(workspaceId).first();
  const base = { workspace_id: workspaceId, report_scope: "single_scan",
    source_scan_id: null, domain_id: null, domain: null, assessed_at: null,
    scan_quality: null, score: null, summary: null, observed_findings_count: null,
    priority_actions: [], coverage_state: "not_proven_complete" };
  if (!row) return output({ ...base, status: "not_assessed" });
  if (!id(row.scan_id) || !id(row.domain_id) || !host(row.domain) || row.workspace_id !== workspaceId) throw deny();
  base.source_scan_id = row.scan_id;
  base.domain_id = row.domain_id;
  base.domain = row.domain;
  base.scan_quality = listed(row.scan_quality, QUALITY);
  const read = await snapshotFor(env, row, overrides.readSnapshot);
  if (!read) return output({ ...base, status: "snapshot_unavailable" });
  const overall = read.customerSnapshot.overall;
  if (!overall || typeof overall !== "object") throw deny();
  const assessment = overall.assessment;
  const quality = listed(assessment?.quality, QUALITY);
  const authoritative = assessment?.authoritative === true;
  const scoreValue = overall.cyber_metrics_score;
  const value = authoritative && Number.isFinite(scoreValue) && scoreValue >= 0 && scoreValue <= 100
    ? Math.round(scoreValue) : null;
  if (authoritative && value === null) throw deny();
  const findings = read.customerSnapshot.observed_findings;
  const actions = read.customerSnapshot.remediation_actions;
  if (!Array.isArray(findings) || findings.length > 2_000 ||
      !Array.isArray(actions) || actions.length > 2_000) throw deny();
  return output({
    ...base, status: "available", assessed_at: date(read.customerSnapshot.snapshot.as_of),
    score: { value, rating: value == null ? null : text(overall.score_band, 40),
      quality, authoritative, provisional: assessment?.provisional === true,
      comparable: assessment?.comparable === true },
    summary: overall.summary == null ? null : text(overall.summary, 600),
    observed_findings_count: findings.length,
    priority_actions: actions.slice(0, 5).map((action) => ({
      remediation_id: text(action.remediation_id, 120),
      priority: text(action.priority, 20), title: text(action.title, 200),
      action: text(action.action, 800),
    })),
  });
}
