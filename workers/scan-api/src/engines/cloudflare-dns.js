// Fixed provider origin, bounded bodies/deadlines, no redirect or arbitrary URL.
export const DNS_PROVIDER_ORIGIN = 'https://api.cloudflare.com/client/v4';
export class DnsActionError extends Error {
  constructor(code, status = 409, message = 'The DNS action could not be completed.', uncertain = false) {
    super(message); Object.assign(this, { code, status, uncertain });
  }
}
export function canonicalDomain(value, { underscore = false } = {}) {
  if (typeof value !== 'string' || value.length > 253 || value !== value.trim()) throw new DnsActionError('unsupported_input', 422);
  const name = value.toLowerCase().replace(/\.$/, '');
  const label = underscore ? /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/ : /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  if (!name.includes('.') || name.split('.').some(part => !label.test(part))) throw new DnsActionError('unsupported_input', 422);
  return name;
}
export const inZone = (domain, zone) => domain === zone || domain.endsWith('.' + zone);
export function stableJson(value) {
  if (Array.isArray(value)) return '[' + value.map(stableJson).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + stableJson(value[key])).join(',') + '}';
  return JSON.stringify(value);
}
export async function boundedDnsJson(response, limit = 524288) {
  const length = Number(response.headers.get('content-length'));
  if (Number.isFinite(length) && length > limit) { await response.body?.cancel(); throw new DnsActionError('invalid_response', 502); }
  const reader = response.body?.getReader();
  if (!reader) throw new DnsActionError('invalid_response', 502);
  const chunks = []; let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read(); if (done) break;
      size += value.byteLength;
      if (size > limit) { await reader.cancel(); throw new DnsActionError('invalid_response', 502); }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch { throw new DnsActionError('invalid_response', 502); }
  finally { reader.releaseLock(); }
}
const providerId = value => typeof value === 'string' && /^[a-f0-9]{32}$/.test(value);
export function recordSnapshot(record, expectedName) {
  if (!record || !providerId(record.id) || typeof record.type !== 'string' || !/^[A-Z0-9]{1,16}$/.test(record.type) ||
      canonicalDomain(record.name, { underscore: true }) !== expectedName || typeof record.content !== 'string' || record.content.length > 16384 ||
      !Number.isInteger(record.ttl) || record.ttl < 1 || record.ttl > 86400 || typeof record.proxied !== 'boolean') throw new DnsActionError('invalid_response', 502);
  const copy = { id: record.id, name: expectedName, type: record.type, content: record.content, ttl: record.ttl, proxied: record.proxied };
  for (const key of ['comment', 'tags', 'settings', 'priority', 'data', 'modified_on', 'comment_modified_on', 'tags_modified_on']) {
    if (record[key] !== undefined) copy[key] = record[key];
  }
  if (stableJson(copy).length > 32768 || (copy.comment != null && typeof copy.comment !== 'string')) throw new DnsActionError('invalid_response', 502);
  return copy;
}
export function createCloudflareDns(token, { fetchImpl = fetch, timeoutMs = 6000 } = {}) {
  if (!/^[a-zA-Z0-9_-]{20,256}$/.test(token)) throw new DnsActionError('invalid_token', 400);
  async function request(path, { method = 'GET', body } = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const writing = method !== 'GET';
    try {
      const response = await fetchImpl(DNS_PROVIDER_ORIGIN + path, {
        method, redirect: 'manual', signal: controller.signal,
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      if (!response.ok) {
        await response.body?.cancel();
        throw new DnsActionError(response.status === 401 || response.status === 403 ? 'provider_access_denied' : 'provider_unavailable', 503, 'Cloudflare could not confirm this request.', writing && (response.status >= 500 || response.status >= 300 && response.status < 400));
      }
      const value = await boundedDnsJson(response);
      if (!value || value.success !== true || !Object.hasOwn(value, 'result')) throw new DnsActionError('invalid_response', 502, undefined, writing);
      return value;
    } catch (error) {
      if (error instanceof DnsActionError) { if (writing && error.code === 'invalid_response') error.uncertain = true; throw error; }
      throw new DnsActionError('provider_unavailable', 503, 'Cloudflare could not confirm this request.', writing);
    } finally { clearTimeout(timer); }
  }
  const zonePath = zone => { if (!providerId(zone)) throw new DnsActionError('invalid_zone', 400); return `/zones/${zone}`; };
  return {
    async verifyZone(zoneId, domain) {
      const verified = await request('/user/tokens/verify');
      if (verified.result?.status !== 'active') throw new DnsActionError('provider_access_denied', 403);
      const zone = (await request(zonePath(zoneId))).result;
      if (zone?.id !== zoneId || zone.status !== 'active' || !inZone(domain, canonicalDomain(zone.name))) throw new DnsActionError('zone_mismatch', 422);
      return { id: zoneId, name: canonicalDomain(zone.name) };
    },
    async list(zoneId, name) {
      const result = await request(`${zonePath(zoneId)}/dns_records?${new URLSearchParams({ 'name.exact': name, per_page: '1000', page: '1' })}`);
      if (!Array.isArray(result.result) || result.result.length > 1000 || !result.result_info ||
          result.result_info.total_count !== result.result.length || result.result_info.page !== 1 || ![0,1].includes(result.result_info.total_pages)) throw new DnsActionError('incomplete_record_set', 502);
      const records = result.result.map(record => recordSnapshot(record, name));
      if (new Set(records.map(record => record.id)).size !== records.length) throw new DnsActionError('invalid_response', 502);
      return records.sort((left, right) => left.id.localeCompare(right.id));
    },
    async create(zoneId, record) { return request(`${zonePath(zoneId)}/dns_records`, { method: 'POST', body: record }); },
    async update(zoneId, id, record) {
      if (!providerId(id)) throw new DnsActionError('invalid_record', 422);
      return request(`${zonePath(zoneId)}/dns_records/${id}`, { method: 'PATCH', body: record });
    },
    async remove(zoneId, id) {
      if (!providerId(id)) throw new DnsActionError('invalid_record', 422);
      return request(`${zonePath(zoneId)}/dns_records/${id}`, { method: 'DELETE' });
    },
  };
}
