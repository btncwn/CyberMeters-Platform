import { McpServer } from '@modelcontextprotocol/server';
import { createMcpHandler } from 'agents/mcp/server';
import { z } from 'zod';

const TOOL_NAME = 'cybermeters_get_workspace_summary';
const MAX_REQUEST_BYTES = 4096;
const MAX_RESPONSE_BYTES = 8192;
const MAX_TOOL_TEXT_BYTES = 2048;
const DEFAULT_BACKEND_TIMEOUT_MS = 2000;
const encoder = new TextEncoder();
const workspaceId = z.string().min(1).max(64).regex(/^[A-Za-z0-9][A-Za-z0-9_-]*$/);
const inputSchema = z.strictObject({ workspace_id: workspaceId });
const scoreStates = ['assessed', 'latest_incomplete', 'current_not_assessed', 'not_assessed', 'basis_unproven'];
const coverageStates = ['complete', 'partial', 'unavailable', 'not_assessed'];
const evidenceStates = ['authoritative', 'provisional', 'insufficient'];
const safeText = (max) => z.string().min(1).max(max).refine((value) =>
  !/[\x00-\x1f\x7f\p{Cf}]/u.test(value) && !/cm_[a-f0-9]{64}/i.test(value));

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
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > limit) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } finally {
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
    score_state: value.score_state,
    score_value: value.score_value,
    latest_measurement_at: value.latest_measurement_at,
    evidence_state: value.evidence_state,
    coverage_state: value.coverage_state,
    limitations: value.limitations,
    ui_path: `/workspaces/${encodeURIComponent(value.workspace_id)}`,
  };
  const text = JSON.stringify(projection);
  if (encoder.encode(text).byteLength > MAX_TOOL_TEXT_BYTES) throw new ProjectionError('tool_result_too_large');
  return text;
}

async function loadWorkspaceSummary(backend, workspaceIdValue, timeoutMs) {
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
      backend.getWorkspaceSummary({ workspaceId: workspaceIdValue, signal: controller.signal }),
      timeout,
    ]);
  } finally {
    clearTimeout(timeoutId);
  }
}

export function createLocalMcpWorker({ backend, onEvent, backendTimeoutMs = DEFAULT_BACKEND_TIMEOUT_MS }) {
  if (!Number.isInteger(backendTimeoutMs) || backendTimeoutMs < 1 || backendTimeoutMs > 10_000) {
    throw new TypeError('Invalid backend timeout');
  }
  const handler = createMcpHandler(() => {
    const server = new McpServer({ name: 'cybermeters-local-mcp', version: '0.0.0-local' });
    server.registerTool(TOOL_NAME, {
      description: 'Return a bounded, read-only summary for one explicitly identified workspace.',
      inputSchema,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    }, async ({ workspace_id }) => {
      try {
        const raw = await loadWorkspaceSummary(backend, workspace_id, backendTimeoutMs);
        const text = projectWorkspaceSummary(raw, workspace_id);
        emit(onEvent, 'tool_success');
        return { content: [{ type: 'text', text }] };
      } catch (error) {
        emit(onEvent, error instanceof ProjectionError
          ? (error.code === 'tool_result_too_large' ? 'response_capped' : 'projection_rejected')
          : (error?.message === 'backend_timeout' ? 'backend_timeout' : 'backend_failure'));
        return { isError: true, content: [{ type: 'text', text: 'workspace_summary_unavailable' }] };
      }
    });
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
      catch { emit(onEvent, 'protocol_error'); return safeError(400, 'invalid_json'); }
      if (body === null) {
        emit(onEvent, 'request_denied');
        return safeError(413, 'request_too_large');
      }
      let parsedBody;
      try {
        parsedBody = JSON.parse(body);
        if (!parsedBody || typeof parsedBody !== 'object' || Array.isArray(parsedBody)) throw new Error();
      } catch {
        emit(onEvent, 'protocol_error');
        return safeError(400, 'invalid_json');
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
