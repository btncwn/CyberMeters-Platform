import { getWorkspaceRetentionSettings } from './plan-usage.js';

export const BREACH_CONSENT_VERSION = '2026-10-09';
export const BREACH_SCOPE_NOTE = 'Checks only the address you submit against LeakCheck Public sources. This is not domain-wide, dark-web or password monitoring. A match does not prove current account compromise; no match does not prove the address is safe.';
export const LEAKCHECK_TIMEOUT_MS = 8000;
export const LEAKCHECK_RESPONSE_BYTES = 131072;
export const breachFailure = (reason, status = 'unavailable') => ({ status, reason, found_count: null, fields: [], sources: [] });

export async function boundedJson(request, maxBytes) {
  const length = request.headers.get('content-length');
  if (length && (!/^\d+$/.test(length) || Number(length) > maxBytes)) throw new Error('body_too_large');
  if (!request.body) throw new Error('invalid_json');
  const reader = request.body.getReader();
  const chunks = []; let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) { await reader.cancel(); throw new Error('body_too_large'); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
}

// Fixed public API contract; extra provider fields (including any values) are
// discarded. An incomplete response can never become a negative observation.
export function parseLeakCheckResult(body) {
  // The Public API also uses this exact legacy envelope for an absent result.
  // Extra fields or any other error stay unknown; HTTP errors are rejected by
  // queryLeakCheck before this parser is called.
  if (body && !Array.isArray(body) && body.success === false && body.error === 'Not found'
      && Object.keys(body).sort().join(',') === 'error,success') {
    return { status: 'no_matches', reason: null, found_count: 0, fields: [], sources: [] };
  }
  const text = (s, max) => typeof s === 'string' && s.length > 0 && s.length <= max && !/[\u0000-\u001f\u007f]/.test(s);
  if (!body || body.success !== true || !Number.isSafeInteger(body.found) || body.found < 0
      || !Array.isArray(body.fields) || body.fields.length > 100 || !body.fields.every(s => text(s, 80))
      || !Array.isArray(body.sources) || body.sources.length > 1000
      || !body.sources.every(s => s && text(s.name, 200) && (s.date === null || text(s.date, 40)))
      || (body.found === 0 && (body.sources.length > 0 || body.fields.length > 0))
      || (body.found > 0 && body.sources.length === 0)) return breachFailure('invalid_provider_response');
  return {
    status: body.found > 0 ? 'sources_found' : 'no_matches', reason: null,
    found_count: body.found, fields: [...new Set(body.fields)],
    sources: body.sources.map(s => ({ name: s.name, date: s.date })),
  };
}

export async function queryLeakCheck(hash, fetcher = fetch) {
  if (typeof hash !== 'string' || !/^[a-f0-9]{24}$/.test(hash)) return breachFailure('invalid_subject');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), LEAKCHECK_TIMEOUT_MS);
  try {
    const response = await fetcher(`https://leakcheck.io/api/public?check=${hash}`, {
      // Workers supports manual/follow, not redirect:error. Never follow a
      // redirect; the non-2xx branch below rejects it without another request.
      method: 'GET', redirect: 'manual', signal: controller.signal,
      headers: { Accept: 'application/json' },
    });
    if (response.status === 429) { await response.body?.cancel(); return breachFailure('provider_rate_limited', 'rate_limited'); }
    if (!response.ok) { await response.body?.cancel(); return breachFailure('provider_unavailable'); }
    return parseLeakCheckResult(await boundedJson(response, LEAKCHECK_RESPONSE_BYTES));
  } catch { return breachFailure(controller.signal.aborted ? 'provider_timeout' : 'provider_unavailable'); }
  finally { clearTimeout(timer); }
}

export async function subjectHashes(workspaceId, email) {
  const sha = async text => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))), b => b.toString(16).padStart(2, '0')).join('');
  return { providerHash: (await sha(email)).slice(0, 24), subjectHash: await sha(`${workspaceId}\0${email}`) };
}

export function normalizeBreachInput(body, domain) {
  if (!body || typeof body !== 'object' || Array.isArray(body)
      || Object.keys(body).some(k => !['domain_id','email','consent','consent_version','request_id'].includes(k))
      || body.consent !== true || body.consent_version !== BREACH_CONSENT_VERSION
      || typeof body.request_id !== 'string' || !/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(body.request_id)
      || typeof body.email !== 'string' || body.email.length > 254) throw new Error('invalid_request');
  const email = body.email.trim().toLowerCase();
  const [local, host, extra] = email.split('@');
  if (extra !== undefined || !local || local.length > 64 || !/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+$/.test(local)
      || local.startsWith('.') || local.endsWith('.') || local.includes('..') || !host
      || host !== String(domain).toLowerCase()) throw new Error('address_domain_mismatch');
  return email;
}

export function breachItem(row, retention) {
  const stale = row.status === 'pending' && Date.now() - Date.parse(row.checked_at) > 30000;
  return { id: row.id, domain_id: row.domain_id, masked_address: row.masked_address,
    status: stale ? 'unavailable' : row.status, reason: stale ? 'check_interrupted' : row.reason,
    found_count: row.found_count, fields: JSON.parse(row.fields_json), sources: JSON.parse(row.sources_json),
    checked_at: row.checked_at, expires_at: retention ? breachExpiry(retention, row.checked_at) : row.expires_at };
}

export function breachExpiry(retention, checkedAt) {
  return retention.auto_cleanup && Number.isFinite(retention.retention_days) && retention.retention_days > 0
    ? new Date(Date.parse(checkedAt) + retention.retention_days * 86400000).toISOString() : null;
}

export async function breachExpiresAt(env, workspaceId, checkedAt) {
  return breachExpiry(await getWorkspaceRetentionSettings(workspaceId, env), checkedAt);
}

// Re-evaluate the current workspace policy, as report retention does. No raw
// provider response is retained in D1 or R2. Bounded batches avoid cron starvation.
export async function cleanupIdentityBreachChecks(nowIso, env) {
  const state = await env.cybermeters_db.prepare('SELECT workspace_cursor FROM identity_breach_cleanup_state WHERE id=1').first();
  if (!state) throw new Error('breach_cleanup_cursor_missing');
  const rows = await env.cybermeters_db.prepare('SELECT DISTINCT workspace_id FROM identity_breach_checks WHERE workspace_id > ? ORDER BY workspace_id LIMIT 100').bind(state.workspace_cursor).all();
  let deleted = 0;
  for (const { workspace_id } of rows.results || []) {
    const retention = await getWorkspaceRetentionSettings(workspace_id, env);
    if (retention.auto_cleanup && Number.isFinite(retention.retention_days) && retention.retention_days > 0) {
      const cutoff = new Date(Date.parse(nowIso) - retention.retention_days * 86400000).toISOString();
      const result = await env.cybermeters_db.prepare('DELETE FROM identity_breach_checks WHERE id IN (SELECT id FROM identity_breach_checks WHERE workspace_id = ? AND checked_at < ? LIMIT 500)').bind(workspace_id, cutoff).run();
      deleted += result.meta?.changes || 0;
    }
    await env.cybermeters_db.prepare('UPDATE identity_breach_cleanup_state SET workspace_cursor=? WHERE id=1').bind(workspace_id).run();
  }
  if ((rows.results || []).length < 100) await env.cybermeters_db.prepare("UPDATE identity_breach_cleanup_state SET workspace_cursor='' WHERE id=1").run();
  return { deleted };
}
