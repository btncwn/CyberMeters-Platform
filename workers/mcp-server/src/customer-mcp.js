import { McpServer } from '@modelcontextprotocol/server';
import { createMcpHandler } from 'agents/mcp/server';
import { z } from 'zod';
import {
  projectWorkspaceSummary, projectWorkspacePosture, projectRecentScans,
  projectScanStatus, projectManagedCases, projectManagedCase,
} from './local-mcp.js';

export const CUSTOMER_RESOURCE = 'https://mcp.cybermeters.com/mcp';
export const CUSTOMER_ISSUER = 'https://api.cybermeters.com';
export const CUSTOMER_RPC_METHODS = Object.freeze([
  'listWorkspaces', 'getWorkspaceSummary', 'getWorkspacePosture',
  'listRecentScans', 'getScanStatus', 'listManagedCases', 'getManagedCase',
  'listDomains', 'listFindings', 'explainFinding',
  'getTlsPosture', 'getEmailPosture', 'getReportSummary',
  'getPortfolioSummary',
]);

const MAX_REQUEST_BYTES = 16_384;
const MAX_RESPONSE_BYTES = 32_768;
const MAX_TOOL_BYTES = 24_576;
const BACKEND_TIMEOUT_MS = 4_000;
const READ_TIMEOUT_MS = 10_000;
const ALLOWED_METHODS = new Set([
  'initialize', 'notifications/initialized', 'ping', 'server/discover',
  'tools/list', 'tools/call',
]);
const encoder = new TextEncoder();
const id = z.string().min(1).max(64).regex(/^[A-Za-z0-9][A-Za-z0-9_-]*$/);
const cursor = z.string().min(1).max(420).regex(/^[A-Za-z0-9_~.:-]+$/);
const text = (max) => z.string().min(1).max(max).refine((value) =>
  !/[\x00-\x1f\x7f\p{Cf}]/u.test(value) &&
  !/cm_[a-f0-9]{64}/i.test(value) &&
  !/\bBearer\s+\S{12,}/i.test(value));
const datetime = z.iso.datetime({ offset: true });
const maybeDatetime = datetime.nullable();
const workspaceInput = z.strictObject({ workspace_id: id.optional() });
const cursorInput = z.strictObject({ cursor: cursor.optional() });
const workspaceCursorInput = z.strictObject({ workspace_id: id.optional(), cursor: cursor.optional() });
const scanInput = z.strictObject({ workspace_id: id.optional(), scan_id: id });
const caseInput = z.strictObject({ workspace_id: id.optional(), case_id: id });
const findingInput = z.strictObject({ workspace_id: id.optional(), finding_id: id });
const findingListInput = z.strictObject({
  scope: z.enum(['workspace', 'portfolio']).optional(),
  workspace_id: id.optional(),
  cursor: cursor.optional(),
}).refine((value) => value.scope !== 'portfolio' || value.workspace_id === undefined);
const assessment = z.object({
  quality: z.enum(['complete', 'partial', 'degraded', 'unknown']),
  authoritative: z.boolean(), provisional: z.boolean(), comparable: z.boolean(),
}).passthrough();
const evidenceGrade = z.enum(['L0', 'L1', 'L2', 'L3', 'L4', 'L5']);
const domainState = z.enum([
  'assessed_healthy', 'issue_detected', 'provisional', 'degraded', 'unavailable',
  'not_configured', 'customer_input_required', 'monitoring_only',
  'not_yet_assessed', 'evidence_insufficient',
]);

class ProjectionError extends Error {
  constructor(code = 'invalid_backend_projection') {
    super(code);
    this.name = 'ProjectionError';
  }
}

function serialize(value) {
  const result = JSON.stringify(value);
  if (encoder.encode(result).byteLength > MAX_TOOL_BYTES) throw new ProjectionError('result_too_large');
  return result;
}

function parse(schema, raw, workspaceId) {
  const result = schema.safeParse(raw);
  if (!result.success || (workspaceId && result.data.workspace_id !== workspaceId)) {
    throw new ProjectionError();
  }
  return result.data;
}

function page(value) {
  if (value.has_more && !value.next_cursor) throw new ProjectionError('missing_cursor');
  if (!value.has_more && value.next_cursor) throw new ProjectionError('unexpected_cursor');
  return { limit: 10, has_more: value.has_more, next_cursor: value.next_cursor };
}

function tag(untrustedFields) {
  return { data_classification: 'untrusted_customer_data', untrusted_fields: untrustedFields,
    evidence_notice: {
      unobserved: 'Unknown, unavailable, and unobserved states are not assessed healthy.',
      customer_attestation: 'Customer statements are not CyberMeters verification.',
    },
  };
}

export function projectCustomerWorkspaces(raw) {
  const value = parse(z.object({
    workspaces: z.array(z.object({
      workspace_id: id, display_name: text(100), role: z.enum(['viewer', 'analyst', 'admin', 'owner']),
    }).passthrough()).max(10),
    limit: z.literal(10), has_more: z.boolean(), next_cursor: cursor.nullable(),
  }).passthrough(), raw);
  return serialize({ ...tag(['workspaces[].display_name']), ...page(value),
    workspaces: value.workspaces.map(({ workspace_id, display_name, role }) =>
      ({ workspace_id, display_name, role })),
  });
}

export function projectCustomerPortfolioSummary(raw) {
  const value = parse(z.object({
    scope: z.literal('portfolio'),
    selected_workspace_count: z.number().int().min(0).max(500),
    workspaces: z.array(z.object({ workspace_id: id }).passthrough()).max(5),
    limit: z.literal(5), has_more: z.boolean(), next_cursor: id.nullable(),
    coverage_state: z.literal('not_proven_complete'),
  }).passthrough(), raw);
  if (value.has_more !== Boolean(value.next_cursor) ||
      value.workspaces.length > value.selected_workspace_count ||
      new Set(value.workspaces.map((item) => item.workspace_id)).size !== value.workspaces.length ||
      (value.has_more && value.workspaces.length !== 5) ||
      (value.next_cursor && value.next_cursor !== value.workspaces.at(-1)?.workspace_id)) {
    throw new ProjectionError();
  }
  const workspaces = value.workspaces.map((item) => {
    const summary = JSON.parse(projectWorkspaceSummary(item, item.workspace_id));
    return {
      workspace_id: summary.workspace_id, display_name: summary.display_name,
      domain_count: summary.domain_count, open_case_count: summary.open_case_count,
      score_state: summary.score_state, score_value: summary.score_value,
      latest_measurement_at: summary.latest_measurement_at,
      evidence_state: summary.evidence_state, coverage_state: summary.coverage_state,
      limitations: summary.limitations,
    };
  });
  return serialize({ ...tag(['workspaces[].display_name', 'workspaces[].limitations']),
    scope: value.scope, selected_workspace_count: value.selected_workspace_count,
    workspaces, limit: value.limit, has_more: value.has_more,
    next_cursor: value.next_cursor, coverage_state: value.coverage_state,
  });
}

export function projectCustomerDomains(raw, workspaceId) {
  const value = parse(z.object({
    workspace_id: id,
    domains: z.array(z.object({
      workspace_id: id, domain_id: id, domain: text(253),
      verification_status: text(48), verified_at: maybeDatetime,
      last_completed_scan_id: id.nullable(), last_completed_scan_created_at: maybeDatetime,
      assessment: assessment.nullable(),
      source_report_state: z.enum(['not_assessed', 'verified', 'unavailable']),
    }).passthrough()).max(10),
    limit: z.literal(10), has_more: z.boolean(), next_cursor: cursor.nullable(),
  }).passthrough(), raw, workspaceId);
  if (value.domains.some((item) => item.workspace_id !== value.workspace_id)) throw new ProjectionError();
  return serialize({ ...tag(['domains[].domain']), workspace_id: value.workspace_id,
    ...page(value), domains: value.domains.map((item) => ({
      workspace_id: item.workspace_id, domain_id: item.domain_id, domain: item.domain,
      verification_status: item.verification_status, verified_at: item.verified_at,
      last_completed_scan_id: item.last_completed_scan_id,
      last_completed_scan_created_at: item.last_completed_scan_created_at,
      assessment: item.assessment && {
        quality: item.assessment.quality, authoritative: item.assessment.authoritative,
        provisional: item.assessment.provisional, comparable: item.assessment.comparable,
      }, source_report_state: item.source_report_state,
    })),
  });
}

export function projectCustomerFindings(raw, workspaceId, portfolio = false) {
  const value = parse(z.object({
    scope: z.enum(['workspace', 'portfolio']), workspace_id: id.nullable(),
    findings: z.array(z.object({
      workspace_id: id, domain_id: id, domain: text(253), finding_id: id,
      finding_type: text(100).nullable(), title: text(180),
      severity: z.enum(['critical', 'high']), source_scan_id: id,
      source_scan_created_at: datetime, source_scan_quality: z.literal('complete'),
      domain_verification_status: text(48),
      newer_scan_without_complete_assessment: z.boolean(),
      evidence_state: z.enum(['authoritative', 'provisional', 'insufficient']),
      assessment: assessment.nullable(),
      source_report_state: z.enum(['verified', 'unavailable']),
    }).passthrough()).max(10),
    limit: z.literal(10), has_more: z.boolean(), next_cursor: cursor.nullable(),
    coverage_state: z.literal('not_proven_complete'),
  }).passthrough(), raw, workspaceId);
  if ((portfolio && (value.scope !== 'portfolio' || value.workspace_id !== null)) ||
      (!portfolio && (value.scope !== 'workspace' || value.workspace_id === null)) ||
      (!portfolio && value.findings.some((item) => item.workspace_id !== value.workspace_id))) {
    throw new ProjectionError();
  }
  return serialize({ ...tag(['findings[].domain', 'findings[].title']),
    scope: value.scope, workspace_id: value.workspace_id, ...page(value),
    coverage_state: value.coverage_state,
    findings: value.findings.map((item) => ({
      workspace_id: item.workspace_id, domain_id: item.domain_id, domain: item.domain,
      finding_id: item.finding_id, finding_type: item.finding_type, title: item.title,
      severity: item.severity, source_scan_id: item.source_scan_id,
      source_scan_created_at: item.source_scan_created_at,
      source_scan_quality: item.source_scan_quality,
      domain_verification_status: item.domain_verification_status,
      newer_scan_without_complete_assessment: item.newer_scan_without_complete_assessment,
      evidence_state: item.evidence_state,
      assessment: item.assessment && {
        quality: item.assessment.quality, authoritative: item.assessment.authoritative,
        provisional: item.assessment.provisional, comparable: item.assessment.comparable,
      }, source_report_state: item.source_report_state,
    })),
  });
}

export function projectCustomerFindingExplanation(raw, workspaceId, findingId) {
  const value = parse(z.object({
    workspace_id: id, finding_id: id, domain_id: id, domain: text(253),
    source_scan_id: id, source_scan_created_at: datetime,
    status: z.enum(['available', 'snapshot_unavailable', 'finding_not_in_snapshot']),
    finding: z.object({
      type: text(120), title: text(200),
      severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
      evidence_grade: evidenceGrade,
      evidence_state: z.enum(['authoritative', 'provisional', 'insufficient']),
      evidence_count: z.number().int().min(0).max(1000).nullable(),
      verification_support: z.enum(['automated', 'manual', 'external', 'unsupported']),
      verification_ceiling: text(120),
      source_report_state: z.literal('integrity_verified_snapshot'),
    }).passthrough().nullable(),
    remediation: z.union([
      z.object({ status: z.enum(['unknown', 'version_mismatch']) }).passthrough(),
      z.object({ status: z.literal('resolved'), remediation_id: text(120),
        version: text(80), domain_key: text(80), title: text(200),
        technical_explanation: text(800), business_impact: text(800),
        recommended_action: text(1000), verification_method: text(80),
        limitations: z.array(text(300)).max(4) }).passthrough(),
    ]).nullable(),
    field_guide: z.object({ version: text(80),
      path: z.string().regex(/^\/guide\/[a-z0-9-]{1,80}$/),
      url: z.string().regex(/^https:\/\/app\.cybermeters\.com\/guide\/[a-z0-9-]{1,80}$/),
    }).passthrough().nullable(),
  }).passthrough(), raw, workspaceId);
  if (value.finding_id !== findingId ||
      (value.status === 'available') !== (value.finding !== null) ||
      (value.status !== 'available' && (value.remediation !== null || value.field_guide !== null)) ||
      (value.field_guide && new URL(value.field_guide.url).pathname !== value.field_guide.path)) {
    throw new ProjectionError();
  }
  return serialize({ ...tag(['domain', 'finding.title', 'remediation.title',
    'remediation.technical_explanation', 'remediation.business_impact',
    'remediation.recommended_action', 'remediation.limitations']),
  workspace_id: value.workspace_id, finding_id: value.finding_id,
  domain_id: value.domain_id, domain: value.domain,
  source_scan_id: value.source_scan_id, source_scan_created_at: value.source_scan_created_at,
  status: value.status, finding: value.finding && {
    type: value.finding.type, title: value.finding.title,
    severity: value.finding.severity, evidence_grade: value.finding.evidence_grade,
    evidence_state: value.finding.evidence_state, evidence_count: value.finding.evidence_count,
    verification_support: value.finding.verification_support,
    verification_ceiling: value.finding.verification_ceiling,
    source_report_state: value.finding.source_report_state,
  }, remediation: value.remediation && (value.remediation.status === 'resolved' ? {
    status: value.remediation.status, remediation_id: value.remediation.remediation_id,
    version: value.remediation.version, domain_key: value.remediation.domain_key,
    title: value.remediation.title,
    technical_explanation: value.remediation.technical_explanation,
    business_impact: value.remediation.business_impact,
    recommended_action: value.remediation.recommended_action,
    verification_method: value.remediation.verification_method,
    limitations: value.remediation.limitations,
  } : { status: value.remediation.status }),
  field_guide: value.field_guide && { version: value.field_guide.version,
    path: value.field_guide.path, url: value.field_guide.url },
  });
}

export function projectCustomerTlsPosture(raw, workspaceId) {
  const signal = z.object({
    state: z.enum(['observed', 'not_observed', 'unknown', 'unavailable', 'incomplete']),
    check_outcome: z.enum(['passed', 'failed', 'not_checked']),
  }).passthrough();
  const value = parse(z.object({
    workspace_id: id, status: z.enum(['available', 'not_observed']),
    certificates: z.array(z.object({
      workspace_id: id, certificate_lifecycle_id: id, domain_id: id,
      primary_hostname: text(253), not_after: maybeDatetime,
      days_remaining: z.number().int().safe().nullable(),
      renewal_readiness: text(40), coverage_status: text(40),
      verification_status: text(40), last_seen_at: datetime,
      assurance_status: z.enum(['current', 'not_recorded']),
      certificate_evidence_reason: z.enum([
        'invalid_recorded_evidence', 'signal_evidence_over_limit',
        'signal_evidence_not_recorded',
      ]).nullable(),
      tls_assessment: z.object({
        source_scan_id: id.nullable(),
        state: z.enum(['complete', 'incomplete', 'not_recorded']),
        reason: z.enum([
          'budget_exhausted', 'authority_lost', 'checks_not_finished',
          'tls_progress_unavailable', 'tls_assessment_not_recorded',
        ]).nullable(),
        completed_checks: z.number().int().min(0).max(2048).nullable(),
        planned_checks: z.number().int().min(0).max(2048).nullable(),
      }).passthrough(),
      signals: z.object({
        leaf: signal, expiry: signal, hostname_match: signal,
        trust_store_validation: signal, revocation_assurance: signal,
      }).passthrough(),
    }).passthrough()).max(10), limit: z.literal(10),
    has_more: z.boolean(), next_cursor: cursor.nullable(),
    coverage_state: z.literal('not_proven_complete'),
  }).passthrough(), raw, workspaceId);
  if (value.certificates.some((item) => item.workspace_id !== value.workspace_id) ||
      (value.status === 'not_observed') !== (value.certificates.length === 0)) throw new ProjectionError();
  return serialize({ ...tag(['certificates[].primary_hostname']),
    workspace_id: value.workspace_id, status: value.status,
    ...page(value), coverage_state: value.coverage_state,
    certificates: value.certificates.map((item) => ({
      workspace_id: item.workspace_id,
      certificate_lifecycle_id: item.certificate_lifecycle_id,
      domain_id: item.domain_id, primary_hostname: item.primary_hostname,
      not_after: item.not_after, days_remaining: item.days_remaining,
      renewal_readiness: item.renewal_readiness, coverage_status: item.coverage_status,
      verification_status: item.verification_status, last_seen_at: item.last_seen_at,
      assurance_status: item.assurance_status,
      certificate_evidence_reason: item.certificate_evidence_reason,
      tls_assessment: {
        source_scan_id: item.tls_assessment.source_scan_id,
        state: item.tls_assessment.state, reason: item.tls_assessment.reason,
        completed_checks: item.tls_assessment.completed_checks,
        planned_checks: item.tls_assessment.planned_checks,
      },
      signals: Object.fromEntries([
        'leaf', 'expiry', 'hostname_match', 'trust_store_validation', 'revocation_assurance',
      ].map((key) => [key, {
        state: item.signals[key].state, check_outcome: item.signals[key].check_outcome,
      }])),
    })),
  });
}

export function projectCustomerEmailPosture(raw, workspaceId) {
  const value = parse(z.object({
    workspace_id: id,
    status: z.enum(['available', 'snapshot_unavailable', 'not_assessed']),
    domains: z.array(z.object({
      workspace_id: id, domain_id: id, domain: text(253),
      source_scan_id: id.nullable(), source_scan_created_at: maybeDatetime,
      status: z.enum(['available', 'snapshot_unavailable', 'not_assessed']),
      email_domain_state: domainState, evidence_grade: evidenceGrade,
      dmarc: z.object({
        evidence_status: text(40), observation_state: text(60),
        record_validity: text(60), effective_requested_policy: text(80).nullable(),
        policy_completeness: text(60),
      }).passthrough().nullable(),
      spf: z.object({ observation_state: text(60), present: z.boolean().nullable(),
        resolution_status: text(60) }).passthrough().nullable(),
      dkim: z.object({ observation_state: text(60) }).passthrough().nullable(),
    }).passthrough()).max(10), limit: z.literal(10),
    has_more: z.boolean(), next_cursor: cursor.nullable(),
    coverage_state: z.literal('not_proven_complete'),
  }).passthrough(), raw, workspaceId);
  if (value.domains.some((item) => item.workspace_id !== value.workspace_id)) throw new ProjectionError();
  return serialize({ ...tag(['domains[].domain']), workspace_id: value.workspace_id,
    status: value.status, ...page(value), coverage_state: value.coverage_state,
    domains: value.domains.map((item) => ({
      workspace_id: item.workspace_id, domain_id: item.domain_id, domain: item.domain,
      source_scan_id: item.source_scan_id, source_scan_created_at: item.source_scan_created_at,
      status: item.status, email_domain_state: item.email_domain_state,
      evidence_grade: item.evidence_grade,
      dmarc: item.dmarc && {
        evidence_status: item.dmarc.evidence_status,
        observation_state: item.dmarc.observation_state,
        record_validity: item.dmarc.record_validity,
        effective_requested_policy: item.dmarc.effective_requested_policy,
        policy_completeness: item.dmarc.policy_completeness,
      }, spf: item.spf && {
        observation_state: item.spf.observation_state, present: item.spf.present,
        resolution_status: item.spf.resolution_status,
      }, dkim: item.dkim && { observation_state: item.dkim.observation_state },
    })),
  });
}

export function projectCustomerReportSummary(raw, workspaceId) {
  const value = parse(z.object({
    workspace_id: id, status: z.enum(['available', 'not_assessed', 'snapshot_unavailable']),
    report_scope: z.literal('single_scan'),
    source_scan_id: id.nullable(), domain_id: id.nullable(), domain: text(253).nullable(),
    assessed_at: maybeDatetime,
    scan_quality: z.enum(['complete', 'partial', 'degraded', 'unknown']).nullable(),
    score: z.object({
      value: z.number().int().min(0).max(100).nullable(), rating: text(40).nullable(),
      quality: z.enum(['complete', 'partial', 'degraded', 'unknown']),
      authoritative: z.boolean(), provisional: z.boolean(), comparable: z.boolean(),
    }).passthrough().nullable(),
    summary: text(600).nullable(),
    observed_findings_count: z.number().int().min(0).max(2000).nullable(),
    priority_actions: z.array(z.object({
      remediation_id: text(120), priority: text(20), title: text(200), action: text(800),
      verification_support: z.enum(['automated', 'manual', 'external', 'unsupported']),
      verification_ceiling: text(120),
    }).passthrough()).max(5),
    coverage_state: z.literal('not_proven_complete'),
  }).passthrough(), raw, workspaceId);
  if (value.status === 'available' && (!value.source_scan_id || !value.domain_id || !value.domain ||
      !value.assessed_at || !value.score)) throw new ProjectionError();
  if (value.status !== 'available' && (value.score || value.summary || value.priority_actions.length)) {
    throw new ProjectionError();
  }
  return serialize({ ...tag(['domain', 'summary', 'priority_actions[].title',
    'priority_actions[].action']),
  workspace_id: value.workspace_id, status: value.status,
  report_scope: value.report_scope, source_scan_id: value.source_scan_id,
  domain_id: value.domain_id, domain: value.domain, assessed_at: value.assessed_at,
  scan_quality: value.scan_quality,
  score: value.score && {
    value: value.score.value, rating: value.score.rating, quality: value.score.quality,
    authoritative: value.score.authoritative, provisional: value.score.provisional,
    comparable: value.score.comparable,
  }, summary: value.summary, observed_findings_count: value.observed_findings_count,
  coverage_state: value.coverage_state,
  priority_actions: value.priority_actions.map((item) => ({
      remediation_id: item.remediation_id, priority: item.priority,
      title: item.title, action: item.action,
      verification_support: item.verification_support,
      verification_ceiling: item.verification_ceiling,
  })),
  });
}

function safeError(status, error) {
  return Response.json({ error }, { status, headers: { 'cache-control': 'no-store' } });
}

function emit(onEvent, kind) {
  try { onEvent?.(kind); } catch { /* Metrics cannot affect the boundary. */ }
}

async function readCapped(stream, maxBytes, timeoutMs) {
  if (!stream) return '';
  const reader = stream.getReader();
  const parts = [];
  let bytes = 0;
  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => {
      void reader.cancel().catch(() => {});
      reject(new Error('read_timeout'));
    }, timeoutMs);
  });
  try {
    while (true) {
      const { done, value } = await Promise.race([reader.read(), deadline]);
      if (done) break;
      bytes += value.byteLength;
      if (bytes > maxBytes) {
        void reader.cancel().catch(() => {});
        return null;
      }
      parts.push(value);
    }
  } finally {
    clearTimeout(timer);
    reader.releaseLock();
  }
  const result = new Uint8Array(bytes);
  let at = 0;
  for (const part of parts) { result.set(part, at); at += part.byteLength; }
  return new TextDecoder('utf-8', { fatal: true }).decode(result);
}

function requestAllowed(request, resource, allowedOrigins) {
  try {
    const url = new URL(request.url);
    const target = new URL(resource);
    if (url.origin !== target.origin || url.username || url.password ||
        request.headers.get('host')?.toLowerCase() !== target.host.toLowerCase()) return false;
    const origin = request.headers.get('origin');
    if (origin !== null && !allowedOrigins.includes(origin)) return false;
    return true;
  } catch {
    return false;
  }
}

function backendArgs(name, input, bearer) {
  const args = { bearer };
  if (input.workspace_id !== undefined) args.workspaceId = input.workspace_id;
  if (input.cursor !== undefined) args.cursor = input.cursor;
  if (input.scan_id !== undefined) args.scanId = input.scan_id;
  if (input.case_id !== undefined) args.caseId = input.case_id;
  if (input.finding_id !== undefined) args.findingId = input.finding_id;
  if (name === 'cybermeters_list_findings' && input.scope === 'portfolio') args.portfolio = true;
  return args;
}

function projectResult(name, raw, input, boundWorkspaceId) {
  const expectedWorkspaceId = input.workspace_id ?? boundWorkspaceId;
  switch (name) {
    case 'cybermeters_list_workspaces': return projectCustomerWorkspaces(raw);
    case 'cybermeters_get_workspace_summary': return projectWorkspaceSummary(raw, expectedWorkspaceId);
    case 'cybermeters_get_workspace_posture': return projectWorkspacePosture(raw, expectedWorkspaceId);
    case 'cybermeters_list_recent_scans': return projectRecentScans(raw, expectedWorkspaceId,
      { requireCursor: true });
    case 'cybermeters_get_scan_status': return projectScanStatus(raw, expectedWorkspaceId, input.scan_id);
    case 'cybermeters_list_managed_cases': return projectManagedCases(raw, expectedWorkspaceId,
      { requireCursor: true });
    case 'cybermeters_get_managed_case': return projectManagedCase(raw, expectedWorkspaceId, input.case_id);
    case 'cybermeters_list_domains': return projectCustomerDomains(raw, expectedWorkspaceId);
    case 'cybermeters_list_findings': return projectCustomerFindings(raw, expectedWorkspaceId, input.scope === 'portfolio');
    case 'cybermeters_explain_finding': return projectCustomerFindingExplanation(raw, expectedWorkspaceId, input.finding_id);
    case 'cybermeters_get_tls_posture': return projectCustomerTlsPosture(raw, expectedWorkspaceId);
    case 'cybermeters_get_email_posture': return projectCustomerEmailPosture(raw, expectedWorkspaceId);
    case 'cybermeters_get_report_summary': return projectCustomerReportSummary(raw, expectedWorkspaceId);
    case 'cybermeters_get_portfolio_summary': return projectCustomerPortfolioSummary(raw);
    default: throw new ProjectionError('projection_not_configured');
  }
}

const tools = Object.freeze([
  ['cybermeters_list_workspaces', 'listWorkspaces', cursorInput, 'List your currently authorised workspaces in bounded pages.'],
  ['cybermeters_get_workspace_summary', 'getWorkspaceSummary', workspaceInput, 'Summarise one authorised workspace and its evidence quality.'],
  ['cybermeters_get_workspace_posture', 'getWorkspacePosture', workspaceInput, 'Read the eight security domain states and limitations.'],
  ['cybermeters_list_recent_scans', 'listRecentScans', workspaceCursorInput, 'List a bounded page of recent scan states.'],
  ['cybermeters_get_scan_status', 'getScanStatus', scanInput, 'Read one scan lifecycle and assessment state.'],
  ['cybermeters_list_managed_cases', 'listManagedCases', workspaceCursorInput, 'List a bounded page of managed case phases.'],
  ['cybermeters_get_managed_case', 'getManagedCase', caseInput, 'Read one authorised managed case state.'],
  ['cybermeters_list_domains', 'listDomains', workspaceCursorInput, 'List verified and managed domains with evidence freshness.'],
  ['cybermeters_list_findings', 'listFindings', findingListInput, 'List high and critical findings; portfolio requires separate consent.'],
  ['cybermeters_explain_finding', 'explainFinding', findingInput, 'Explain measured evidence, limitations, and guidance for one finding.'],
  ['cybermeters_get_tls_posture', 'getTlsPosture', workspaceCursorInput, 'Read measured certificate and TLS posture.'],
  ['cybermeters_get_email_posture', 'getEmailPosture', workspaceCursorInput, 'Read measured DMARC, SPF, and email posture.'],
  ['cybermeters_get_report_summary', 'getReportSummary', workspaceInput, 'Summarise an existing verified report.'],
  ['cybermeters_get_portfolio_summary', 'getPortfolioSummary', cursorInput, 'Summarise only the workspaces selected for this portfolio connection.'],
]);

async function callBackend(backend, method, args, timeoutMs) {
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(() => backend[method](args)),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('backend_timeout')), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function protocolHandler({ bearer, boundWorkspaceId, backend, resource,
  allowedOrigins, onEvent, backendTimeoutMs }) {
  return createMcpHandler(() => {
    const server = new McpServer({ name: 'cybermeters-mcp', version: '0.1.0' });
    for (const [name, method, inputSchema, description] of tools) {
      server.registerTool(name, {
        description, inputSchema,
        annotations: { readOnlyHint: true, destructiveHint: false,
          idempotentHint: true, openWorldHint: false },
      }, async (input) => {
        try {
          const raw = await callBackend(backend, method, backendArgs(name, input, bearer), backendTimeoutMs);
          const result = projectResult(name, raw, input, boundWorkspaceId);
          emit(onEvent, 'tool_success');
          return { content: [{ type: 'text', text: result }] };
        } catch (error) {
          emit(onEvent, error instanceof ProjectionError ? 'projection_rejected'
            : error?.message === 'backend_timeout' ? 'backend_timeout' : 'backend_failure');
          return { isError: true, content: [{ type: 'text', text: 'mcp_read_unavailable' }] };
        }
      });
    }
    return server;
  }, {
    route: '/mcp', responseMode: 'json', legacy: 'stateless', corsOptions: false,
    allowedHostnames: [new URL(resource).hostname],
    allowedOriginHostnames: allowedOrigins.map((origin) => new URL(origin).hostname),
    onerror: () => emit(onEvent, 'protocol_error'),
  });
}

export function createCustomerMcpWorker({ auth, backend, onEvent,
  resource = CUSTOMER_RESOURCE, issuer = CUSTOMER_ISSUER,
  allowedOrigins = [new URL(resource).origin],
  backendTimeoutMs = BACKEND_TIMEOUT_MS,
  oauthRuntime, auditDenial } = {}) {
  const target = new URL(resource);
  if ((target.protocol !== 'https:' && !(target.protocol === 'http:' &&
       ['localhost', '127.0.0.1'].includes(target.hostname))) ||
      target.username || target.password || target.search || target.hash ||
      target.pathname !== '/mcp' || !Array.isArray(allowedOrigins) ||
      allowedOrigins.some((origin) => {
        try { return new URL(origin).origin !== origin; } catch { return true; }
      }) ||
      !Number.isInteger(backendTimeoutMs) || backendTimeoutMs < 1 || backendTimeoutMs > 10_000) {
    throw new TypeError('Invalid customer MCP configuration');
  }
  if (!auth || typeof auth.validateToken !== 'function' || !backend ||
      CUSTOMER_RPC_METHODS.some((method) => typeof backend[method] !== 'function')) {
    throw new TypeError('Customer MCP bindings are incomplete');
  }
  if (auditDenial !== undefined && typeof auditDenial !== 'function') {
    throw new TypeError('Invalid customer MCP audit binding');
  }
  async function audited(response, fixedReason, authenticated = false) {
    if (response.status < 400) return response;
    const challenge = response.headers.get('www-authenticate') || '';
    const reason = fixedReason || (response.status === 401 ? 'invalid_bearer'
      : response.status === 403 && challenge.includes('insufficient_scope') ? 'insufficient_scope'
        : response.status === 403 ? 'workspace_denied'
          : response.status === 503 ? 'backend_unavailable'
            : response.status >= 500 ? 'protocol_error' : 'invalid_request');
    try {
      if (await auditDenial?.({ reason, authenticated }) !== true) throw new Error('audit_unavailable');
    } catch {
      emit(onEvent, 'audit_unavailable');
      return safeError(503, 'mcp_not_configured');
    }
    return response;
  }
  const makeOAuth = ({ OAuthResourceServer, insufficientScope }, onAuthenticated) => new OAuthResourceServer({
    resourceMetadata: { resource, authorization_servers: [issuer] },
    requiredScopes: ['mcp:read'],
    validateToken: () => async (audience, token) => {
      if (/^cm_[a-f0-9]{64}$/i.test(token)) return null;
      const grant = await auth.validateToken(audience, token);
      if (grant?.audience === resource &&
          (grant.expiresAt == null || grant.expiresAt > Date.now() / 1000)) {
        onAuthenticated();
      }
      return grant;
    },
    handler: {
      async fetch(request, _env, ctx) {
        const props = ctx.props;
        if (!props || typeof props.userId !== 'string' || !props.userId ||
            typeof props.connectionId !== 'string' || !props.connectionId ||
            (props.workspaceId !== null && !id.safeParse(props.workspaceId).success) ||
            typeof props.portfolioRead !== 'boolean') {
          emit(onEvent, 'invalid_grant_context');
          return safeError(403, 'access_denied');
        }
        if (!ctx.auth.scope.includes('mcp:read')) {
          emit(onEvent, 'insufficient_scope');
          return insufficientScope(ctx.auth, ['mcp:read']);
        }
        if (request.method !== 'POST') return safeError(405, 'method_not_allowed');
        if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers.get('content-type') || '')) {
          return safeError(415, 'unsupported_media_type');
        }
        const length = Number(request.headers.get('content-length'));
        if (Number.isFinite(length) && length > MAX_REQUEST_BYTES) return safeError(413, 'request_too_large');
        let body;
        try { body = await readCapped(request.body, MAX_REQUEST_BYTES, READ_TIMEOUT_MS); }
        catch { return safeError(400, 'invalid_json'); }
        if (body === null) return safeError(413, 'request_too_large');
        let parsed;
        try {
          parsed = JSON.parse(body);
          if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error();
        } catch { return safeError(400, 'invalid_json'); }
        if (!ALLOWED_METHODS.has(parsed.method)) return safeError(400, 'unsupported_method');
        if (parsed.method === 'tools/call' && typeof parsed.params?.name === 'string') {
          const tool = parsed.params.name;
          const args = parsed.params.arguments;
          const contract = tools.find(([name]) => name === tool);
          if (!contract || !contract[2].safeParse(args).success) return safeError(400, 'invalid_tool_call');
          const needsWorkspace = !['cybermeters_list_workspaces', 'cybermeters_list_findings',
            'cybermeters_get_portfolio_summary'].includes(tool) ||
            tool === 'cybermeters_list_findings' && args?.scope !== 'portfolio';
          if (args?.workspace_id !== undefined && props.workspaceId !== null &&
              args.workspace_id !== props.workspaceId) {
            emit(onEvent, 'workspace_denied');
            return safeError(403, 'access_denied');
          }
          if (needsWorkspace && props.workspaceId === null && args?.workspace_id === undefined) {
            emit(onEvent, 'workspace_required');
            return safeError(400, 'workspace_required');
          }
        }
        if (parsed.method === 'tools/call' &&
            ((parsed.params?.name === 'cybermeters_list_findings' &&
              parsed.params?.arguments?.scope === 'portfolio') ||
             parsed.params?.name === 'cybermeters_get_portfolio_summary') &&
            (!ctx.auth.scope.includes('portfolio:read') || !props.portfolioRead)) {
          emit(onEvent, 'insufficient_scope');
          return insufficientScope(ctx.auth, ['mcp:read', 'portfolio:read']);
        }
        const headers = new Headers(request.headers);
        headers.delete('authorization');
        headers.delete('content-length');
        const protocolRequest = new Request(request.url, { method: 'POST', headers, body });
        const handler = protocolHandler({ bearer: ctx.auth.token,
          boundWorkspaceId: props.workspaceId, backend, resource,
          allowedOrigins, onEvent, backendTimeoutMs });
        try {
          const response = await handler.fetch(protocolRequest, { parsedBody: parsed });
          const nullBody = [204, 205, 304].includes(response.status);
          const result = nullBody ? '' : await readCapped(response.body, MAX_RESPONSE_BYTES, READ_TIMEOUT_MS);
          if (result === null) return safeError(502, 'mcp_response_too_large');
          const responseHeaders = new Headers(response.headers);
          responseHeaders.delete('content-length');
          responseHeaders.set('cache-control', 'no-store');
          return new Response(nullBody ? null : result, { status: response.status, headers: responseHeaders });
        } catch {
          emit(onEvent, 'protocol_error');
          return safeError(500, 'mcp_protocol_error');
        }
      },
    },
  });
  let oauthPromise;
  const loadOAuthRuntime = () => (oauthPromise ??= Promise.resolve(
    oauthRuntime ?? import('@cloudflare/workers-oauth-provider')));

  return {
    async fetch(request, executionContext) {
      if (!requestAllowed(request, resource, allowedOrigins)) {
        emit(onEvent, 'request_denied');
        return audited(safeError(403, 'request_denied'), 'request_denied');
      }
      const url = new URL(request.url);
      const metadataPath = `/.well-known/oauth-protected-resource${target.pathname}`;
      if ((url.pathname !== target.pathname && url.pathname !== metadataPath) || url.search || url.hash) {
        return audited(safeError(404, 'not_found'), 'invalid_request');
      }
      if (url.pathname === metadataPath && request.method !== 'GET') {
        return audited(safeError(405, 'method_not_allowed'), 'invalid_request');
      }
      try {
        let authenticated = false;
        const oauth = makeOAuth(await loadOAuthRuntime(), () => { authenticated = true; });
        const response = await oauth.fetch(request, { MCP_AUTH: auth }, executionContext);
        return audited(response, undefined, authenticated);
      } catch {
        emit(onEvent, 'oauth_unavailable');
        return audited(safeError(503, 'mcp_not_configured'), 'backend_unavailable');
      }
    },
  };
}
