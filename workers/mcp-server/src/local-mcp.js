import { McpServer } from '@modelcontextprotocol/server';
import { createMcpHandler } from 'agents/mcp/server';
import { z } from 'zod';

const TOOL_RPC = Object.freeze({
  cybermeters_list_workspaces: 'listWorkspaces',
  cybermeters_get_workspace_summary: 'getWorkspaceSummary',
  cybermeters_get_workspace_posture: 'getWorkspacePosture',
  cybermeters_list_recent_scans: 'listRecentScans',
  cybermeters_get_scan_status: 'getScanStatus',
  cybermeters_list_managed_cases: 'listManagedCases',
});
export const REQUIRED_RPC_METHODS = Object.freeze(Object.values(TOOL_RPC));
const MAX_REQUEST_BYTES = 4096;
const MAX_RESPONSE_BYTES = 8192;
const MAX_TOOL_TEXT_BYTES = 6144;
const MAX_STREAM_READ_MS = 2000;
const DEFAULT_BACKEND_TIMEOUT_MS = 2000;
const ALLOWED_PROTOCOL_METHODS = new Set(['server/discover', 'tools/list', 'tools/call']);
const encoder = new TextEncoder();
const workspaceId = z.string().min(1).max(64).regex(/^[A-Za-z0-9][A-Za-z0-9_-]*$/);
const scanId = workspaceId;
const emptyInput = z.strictObject({});
const workspaceInput = z.strictObject({ workspace_id: workspaceId });
const scanInput = z.strictObject({ workspace_id: workspaceId, scan_id: scanId });
const scoreStates = ['assessed', 'latest_incomplete', 'current_not_assessed', 'not_assessed', 'basis_unproven'];
const coverageStates = ['complete', 'partial', 'unavailable', 'not_assessed'];
const evidenceStates = ['authoritative', 'provisional', 'insufficient'];
const safeText = (max) => z.string().min(1).max(max).refine((value) =>
  !/[\x00-\x1f\x7f\p{Cf}]/u.test(value) && !/cm_[a-f0-9]{64}/i.test(value));
const timestamp = z.iso.datetime({ offset: true }).nullable();
const domainKeys = [
  'email_protection', 'brand_protection', 'attack_surface', 'certificates_trust',
  'cyber_essentials_readiness', 'website_security', 'identity_exposure', 'shadow_it_unmanaged_technology',
];
const domainStates = [
  'assessed_healthy', 'issue_detected', 'provisional', 'degraded', 'unavailable',
  'not_configured', 'customer_input_required', 'monitoring_only',
  'not_yet_assessed', 'evidence_insufficient',
];
const assessmentQuality = z.enum(['complete', 'partial', 'degraded', 'unknown']);
const assessment = z.object({
  quality: assessmentQuality,
  authoritative: z.boolean(), provisional: z.boolean(), comparable: z.boolean(),
}).passthrough();
const scan = z.object({
  scan_id: scanId,
  domain: z.string().min(1).max(253).regex(/^[A-Za-z0-9.-]+$/),
  status: z.enum(['pending', 'queued', 'running', 'completed', 'failed', 'cancelled']),
  scan_quality: assessmentQuality.nullable(),
  assessment,
  measured_at: timestamp,
  score_available: z.boolean(),
}).passthrough();
const caseItem = z.object({
  case_id: workspaceId,
  domain_key: z.enum(domainKeys),
  canonical_phase: z.enum([
    'detected', 'triaged', 'assigned', 'approved', 'action_in_progress',
    'awaiting_verification', 'verified', 'monitoring', 'reopened',
    'accepted_risk', 'rejected', 'false_positive', 'closed_no_action', 'superseded',
  ]),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).nullable(),
  verification_support: z.enum(['automated', 'manual', 'external', 'unsupported']),
  created_at: timestamp, updated_at: timestamp, verified_at: timestamp,
}).passthrough();

class ProjectionError extends Error {
  constructor(code) {
    super(code);
    this.name = 'ProjectionError';
    this.code = code;
  }
}

// Only named fields can cross the protocol boundary. Unknown backend keys are
// accepted as input solely so the projection can prove that it drops them.
const backendSummary = z.object({
  workspace_id: workspaceId,
  display_name: safeText(100),
  domain_count: z.number().int().min(0).max(1000),
  open_case_count: z.number().int().min(0).max(1_000_000),
  score_state: z.enum(scoreStates),
  score_value: z.number().int().min(0).max(100).nullable(),
  latest_measurement_at: z.iso.datetime({ offset: true }).nullable(),
  evidence_state: z.enum(evidenceStates),
  coverage_state: z.enum(coverageStates),
  limitations: z.array(safeText(180)).max(4),
}).passthrough();

function emit(onEvent, kind) {
  try { onEvent?.(kind); } catch { /* Metrics must not alter access or disclose content. */ }
}

function serializeProjection(value, maxBytes = MAX_TOOL_TEXT_BYTES) {
  const text = JSON.stringify(value);
  if (encoder.encode(text).byteLength > maxBytes) throw new ProjectionError('tool_result_too_large');
  return text;
}

function parsedOrThrow(schema, raw, code, requestedId) {
  const result = schema.safeParse(raw);
  if (!result.success || (requestedId && result.data.workspace_id !== requestedId)) {
    throw new ProjectionError(code);
  }
  return result.data;
}

const metadata = (untrustedFields) => ({
  data_classification: 'untrusted_customer_data', untrusted_fields: untrustedFields,
});

export function projectWorkspaces(raw) {
  const value = parsedOrThrow(z.object({ workspaces: z.array(z.object({
    workspace_id: workspaceId, display_name: safeText(100),
    role: z.enum(['viewer', 'analyst', 'admin', 'owner']),
  }).passthrough()).length(1), count: z.literal(1) }).passthrough(), raw, 'invalid_backend_workspaces');
  const one = value.workspaces[0];
  return serializeProjection({ ...metadata(['workspaces[].display_name']),
    count: 1, workspaces: [{ workspace_id: one.workspace_id, display_name: one.display_name, role: one.role }],
  }, 2048);
}

export function projectWorkspacePosture(raw, requestedId) {
  const value = parsedOrThrow(z.object({
    workspace_id: workspaceId,
    source_scan_id: scanId.nullable(),
    domains: z.array(z.object({
      domain_key: z.enum(domainKeys), display_name: safeText(100), state: z.enum(domainStates),
      evidence_strength: z.enum(evidenceStates).nullable(), coverage: assessmentQuality.nullable(),
      last_assessed_at: timestamp,
      limitations: z.array(safeText(500)).max(4),
    }).passthrough()).length(8),
  }).passthrough(), raw, 'invalid_backend_posture', requestedId);
  if (value.domains.some((domain, i) => domain.domain_key !== domainKeys[i])) {
    throw new ProjectionError('invalid_backend_posture');
  }
  const domains = value.domains.map((domain) => ({
    domain_key: domain.domain_key, display_name: domain.display_name, state: domain.state,
    evidence_strength: domain.evidence_strength, coverage: domain.coverage,
    last_assessed_at: domain.last_assessed_at,
    limitations: domain.limitations,
  }));
  return serializeProjection({ ...metadata(['domains[].limitations']),
    workspace_id: value.workspace_id, source_scan_id: value.source_scan_id,
    domains,
    ui_path: `/workspaces/${encodeURIComponent(value.workspace_id)}`,
  });
}

function projectScan(value) {
  if (value.status !== 'completed' && value.score_available) {
    throw new ProjectionError('invalid_scan_assessment');
  }
  if (value.assessment.authoritative &&
      (value.assessment.quality !== 'complete' || !value.assessment.comparable ||
       value.assessment.provisional || !value.score_available)) {
    throw new ProjectionError('invalid_scan_assessment');
  }
  if (value.status !== 'completed' && (value.assessment.authoritative || value.assessment.comparable)) {
    throw new ProjectionError('invalid_scan_assessment');
  }
  return {
    scan_id: value.scan_id, domain: value.domain, status: value.status,
    scan_quality: value.scan_quality,
    assessment: {
      quality: value.assessment.quality, authoritative: value.assessment.authoritative,
      provisional: value.assessment.provisional, comparable: value.assessment.comparable,
    },
    measurement_at: value.measured_at, score_available: value.score_available,
    ui_path: `/scans/${encodeURIComponent(value.scan_id)}`,
  };
}

export function projectRecentScans(raw, requestedId) {
  const value = parsedOrThrow(z.object({
    workspace_id: workspaceId, scans: z.array(scan).max(10), limit: z.literal(10),
    has_more: z.boolean(),
  }).passthrough(), raw, 'invalid_backend_scans', requestedId);
  return serializeProjection({ ...metadata([]), workspace_id: value.workspace_id,
    limit: 10, has_more: value.has_more,
    scans: value.scans.map((item) => projectScan(item)),
  });
}

export function projectScanStatus(raw, requestedId, requestedScanId) {
  const value = parsedOrThrow(z.object({
    workspace_id: workspaceId,
    ...scan.shape,
  }).passthrough(), raw, 'invalid_backend_scan', requestedId);
  if (value.scan_id !== requestedScanId) throw new ProjectionError('invalid_backend_scan');
  return serializeProjection({ ...metadata([]), workspace_id: value.workspace_id,
    scan: projectScan(value),
  }, 2048);
}

export function projectManagedCases(raw, requestedId) {
  const value = parsedOrThrow(z.object({
    workspace_id: workspaceId, cases: z.array(caseItem).max(10), limit: z.literal(10),
    has_more: z.boolean(),
  }).passthrough(), raw, 'invalid_backend_cases', requestedId);
  return serializeProjection({ ...metadata([]), workspace_id: value.workspace_id,
    limit: 10, has_more: value.has_more,
    cases: value.cases.map((item) => ({
      case_id: item.case_id, domain_key: item.domain_key,
      canonical_phase: item.canonical_phase, severity: item.severity,
      verification_support: item.verification_support, created_at: item.created_at,
      updated_at: item.updated_at, verified_at: item.verified_at,
      ui_path: `/ws/cases/${encodeURIComponent(item.case_id)}`,
    })),
  });
}

function safeError(status, error) {
  return new Response(JSON.stringify({ error }), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}

function localRequestAllowed(request) {
  try {
    const url = new URL(request.url);
    const host = request.headers.get('host');
    // Wrangler also sets request.cf for local workerd requests. The deploy
    // boundary is the absent enablement variable and route, not that property.
    if (url.protocol !== 'http:' ||
        !['localhost', '127.0.0.1'].includes(url.hostname) ||
        host?.toLowerCase() !== url.host.toLowerCase() ||
        url.username || url.password) return false;
    const originValue = request.headers.get('origin');
    if (originValue !== null) {
      const origin = new URL(originValue);
      if (origin.origin !== url.origin || originValue !== origin.origin) return false;
    }
    return true;
  } catch {
    return false;
  }
}

async function readCapped(stream, limit) {
  if (!stream) return '';
  const reader = stream.getReader();
  const chunks = [];
  let length = 0;
  let timer;
  let timedOut = false;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => {
      timedOut = true;
      reject(new Error('stream_read_timeout'));
      void reader.cancel().catch(() => {});
    }, MAX_STREAM_READ_MS);
  });
  try {
    while (true) {
      const { done, value } = await Promise.race([reader.read(), deadline]);
      if (timedOut) throw new Error('stream_read_timeout');
      if (done) break;
      length += value.byteLength;
      if (length > limit) {
        // A producer-controlled cancel hook may never settle. Rejection must
        // not wait for it, or the size cap becomes an unbounded request.
        void reader.cancel().catch(() => {});
        return null;
      }
      chunks.push(value);
    }
  } catch (error) {
    if (timedOut) throw new Error('stream_read_timeout');
    throw error;
  } finally {
    clearTimeout(timer);
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

export function projectWorkspaceSummary(raw, requestedId) {
  const parsed = backendSummary.safeParse(raw);
  if (!parsed.success || parsed.data.workspace_id !== requestedId) throw new ProjectionError('invalid_backend_summary');
  const value = parsed.data;
  if ((value.score_state === 'assessed') !== (value.score_value !== null) ||
      (value.score_state === 'assessed' && value.latest_measurement_at === null)) {
    throw new ProjectionError('invalid_score_basis');
  }
  if (value.score_state === 'assessed' &&
      (value.evidence_state !== 'authoritative' || value.coverage_state !== 'complete')) {
    throw new ProjectionError('invalid_evidence_basis');
  }
  const projection = {
    data_classification: 'untrusted_customer_data',
    untrusted_fields: ['display_name', 'limitations'],
    workspace_id: value.workspace_id,
    display_name: value.display_name,
    domain_count: value.domain_count,
    open_case_count: value.open_case_count,
    score_state: value.score_state,
    score_value: value.score_value,
    latest_measurement_at: value.latest_measurement_at,
    evidence_state: value.evidence_state,
    coverage_state: value.coverage_state,
    limitations: value.limitations,
    ui_path: `/workspaces/${encodeURIComponent(value.workspace_id)}`,
  };
  return serializeProjection(projection, 2048);
}

async function loadBackend(backend, method, args, timeoutMs) {
  const controller = new AbortController();
  let timeoutId;
  const timeout = new Promise((_, reject) => {
    timeoutId = setTimeout(() => {
      controller.abort();
      reject(new Error('backend_timeout'));
    }, timeoutMs);
  });
  try {
    return await Promise.race([
      backend[method]({ ...args, signal: controller.signal }),
      timeout,
    ]);
  } finally {
    clearTimeout(timeoutId);
  }
}

export function createLocalMcpWorker({ backend, onEvent, backendTimeoutMs = DEFAULT_BACKEND_TIMEOUT_MS }) {
  if (!backend || REQUIRED_RPC_METHODS.some((method) => typeof backend[method] !== 'function')) {
    throw new TypeError('Six named read RPC methods are required');
  }
  if (!Number.isInteger(backendTimeoutMs) || backendTimeoutMs < 1 || backendTimeoutMs > 10_000) {
    throw new TypeError('Invalid backend timeout');
  }
  const handler = createMcpHandler(() => {
    const server = new McpServer({ name: 'cybermeters-local-mcp', version: '0.0.0-local' });
    const definitions = [
      ['cybermeters_list_workspaces', emptyInput, 'List the single workspace bound to this internal trial credential.', projectWorkspaces],
      ['cybermeters_get_workspace_summary', workspaceInput, 'Return a bounded assessment summary for one workspace.', projectWorkspaceSummary],
      ['cybermeters_get_workspace_posture', workspaceInput, 'Return all eight canonical Cyber MOT domain states and limitations.', projectWorkspacePosture],
      ['cybermeters_list_recent_scans', workspaceInput, 'List a fixed small page of recent scan assessment states.', projectRecentScans],
      ['cybermeters_get_scan_status', scanInput, 'Return a scan lifecycle and separate assessment state.', projectScanStatus],
      ['cybermeters_list_managed_cases', workspaceInput, 'List a fixed small page of managed case phases.', projectManagedCases],
    ];
    for (const [name, inputSchema, description, project] of definitions) {
      server.registerTool(name, {
        description, inputSchema,
        annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
      }, async (input) => {
        try {
          const args = name === 'cybermeters_list_workspaces' ? {}
            : name === 'cybermeters_get_scan_status'
              ? { workspaceId: input.workspace_id, scanId: input.scan_id }
              : { workspaceId: input.workspace_id };
          const raw = await loadBackend(backend, TOOL_RPC[name], args, backendTimeoutMs);
          const text = project(raw, input.workspace_id, input.scan_id);
          emit(onEvent, 'tool_success');
          return { content: [{ type: 'text', text }] };
        } catch (error) {
          emit(onEvent, error instanceof ProjectionError
            ? (error.code === 'tool_result_too_large' ? 'response_capped' : 'projection_rejected')
            : (error?.message === 'backend_timeout' ? 'backend_timeout' : 'backend_failure'));
          return { isError: true, content: [{ type: 'text', text: 'mcp_read_unavailable' }] };
        }
      });
    }
    return server;
  }, {
    route: '/mcp',
    responseMode: 'json',
    legacy: 'reject',
    corsOptions: false,
    allowedHostnames: ['localhost', '127.0.0.1'],
    allowedOriginHostnames: ['localhost', '127.0.0.1'],
    onerror: () => emit(onEvent, 'protocol_error'),
  });

  return {
    async fetch(request) {
      if (!localRequestAllowed(request)) {
        emit(onEvent, 'request_denied');
        return safeError(403, 'local_request_required');
      }
      const url = new URL(request.url);
      if (url.pathname !== '/mcp' || url.search || url.hash) {
        emit(onEvent, 'request_denied');
        return safeError(404, 'not_found');
      }
      if (request.method !== 'POST') {
        emit(onEvent, 'request_denied');
        return safeError(405, 'method_not_allowed');
      }
      if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers.get('content-type') || '')) {
        emit(onEvent, 'request_denied');
        return safeError(415, 'unsupported_media_type');
      }
      const declaredLength = Number(request.headers.get('content-length'));
      if (Number.isFinite(declaredLength) && declaredLength > MAX_REQUEST_BYTES) {
        emit(onEvent, 'request_denied');
        return safeError(413, 'request_too_large');
      }
      let body;
      try { body = await readCapped(request.body, MAX_REQUEST_BYTES); }
      catch (error) {
        emit(onEvent, 'protocol_error');
        return error?.message === 'stream_read_timeout'
          ? safeError(408, 'request_timeout') : safeError(400, 'invalid_json');
      }
      if (body === null) {
        emit(onEvent, 'request_denied');
        return safeError(413, 'request_too_large');
      }
      let parsedBody;
      try {
        parsedBody = JSON.parse(body);
        if (!parsedBody || typeof parsedBody !== 'object' || Array.isArray(parsedBody)) throw new Error();
        const pending = [[parsedBody, 0]];
        let visited = 0;
        while (pending.length) {
          const [value, depth] = pending.pop();
          if (++visited > 256 || depth > 16) throw new Error();
          if (value && typeof value === 'object') {
            for (const child of Object.values(value)) pending.push([child, depth + 1]);
          }
        }
      } catch {
        emit(onEvent, 'protocol_error');
        return safeError(400, 'invalid_json');
      }
      if (!ALLOWED_PROTOCOL_METHODS.has(parsedBody.method) ||
          request.headers.get('mcp-method') !== parsedBody.method) {
        emit(onEvent, 'request_denied');
        return safeError(400, 'unsupported_method');
      }
      try {
        // The SDK sees only protocol headers and the capped body. In particular,
        // the request-scoped bearer is never handed to its handler or tools.
        const protocolHeaders = new Headers(request.headers);
        protocolHeaders.delete('authorization');
        const protocolRequest = new Request(request.url, {
          method: 'POST', headers: protocolHeaders, body,
        });
        const response = await handler.fetch(protocolRequest, { parsedBody });
        const nullBodyStatus = [204, 205, 304].includes(response.status);
        const responseText = nullBodyStatus ? '' : await readCapped(response.body, MAX_RESPONSE_BYTES);
        if (responseText === null) {
          emit(onEvent, 'response_capped');
          return safeError(502, 'mcp_response_too_large');
        }
        const headers = new Headers(response.headers);
        headers.delete('content-length');
        headers.set('cache-control', 'no-store');
        return new Response(nullBodyStatus ? null : responseText, { status: response.status, headers });
      } catch {
        emit(onEvent, 'protocol_error');
        return safeError(500, 'mcp_protocol_error');
      }
    },
  };
}
