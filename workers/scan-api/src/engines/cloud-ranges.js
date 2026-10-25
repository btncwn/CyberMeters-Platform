// Cloud-provider public address ranges, from each provider's own free list
// (dangling-DNS check, 24 Oct 2026). Refreshed daily by cron into the report
// bucket; scans read the cache, never the feeds. A stale or missing cache means
// the check is not assessed - never a guess. Azure publishes no stable free URL
// (its weekly Service Tags file name changes), so Azure is not covered.
import { readBoundedJson } from '../../../network-probe/src/contract.js';
import { SCANNER_USER_AGENT } from '../lib/http.js';

export const CLOUD_RANGES_KEY = 'public-feeds/cloud-ranges-v1.json';
export const CLOUD_RANGES_MAX_AGE_MS = 7 * 86400000;
const PROVIDER_NAMES = Object.freeze({ gcp: 'Google Cloud', aws: 'Amazon Web Services', oracle: 'Oracle Cloud', digitalocean: 'DigitalOcean' });
export const cloudProviderName = (id) => PROVIDER_NAMES[id] || null;

const V4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/;
function v4Range(cidr) {
  const m = V4.exec(cidr); if (!m) return null;
  const octets = m.slice(1, 5).map(Number), bits = Number(m[5]);
  if (octets.some((o) => o > 255) || bits > 32) return null;
  const base = octets.reduce((n, o) => n * 256 + o, 0), size = 2 ** (32 - bits);
  const start = base - (base % size);
  return [start, start + size - 1];
}
function v6ToBig(address) {
  if (!/^[0-9a-f:]+$/i.test(address) || address.split('::').length > 2) return null;
  const [head, tail = ''] = address.split('::');
  const h = head ? head.split(':') : [], t = tail ? tail.split(':') : [];
  const groups = address.includes('::') ? [...h, ...Array(8 - h.length - t.length).fill('0'), ...t] : h;
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/i.test(g))) return null;
  return groups.reduce((n, g) => (n << 16n) + BigInt(parseInt(g, 16)), 0n);
}
function v6Range(cidr) {
  const [address, bitsText] = String(cidr).split('/'); const bits = Number(bitsText);
  if (!Number.isInteger(bits) || bits < 0 || bits > 128) return null;
  const n = v6ToBig(address); if (n === null) return null;
  const size = 1n << BigInt(128 - bits); const start = n - (n % size);
  return [start, start + size - 1n];
}
const v4Of = (address) => { const r = v4Range(`${address}/32`); return r ? r[0] : null; };

// Feed parsers: each returns CIDR strings (IPv4 and IPv6) or throws on a bad shape.
const SOURCES = Object.freeze([
  { id: 'gcp', url: 'https://www.gstatic.com/ipranges/cloud.json', kind: 'json',
    parse: (b) => { if (!Array.isArray(b?.prefixes)) throw new Error('shape'); return b.prefixes.map((p) => p.ipv4Prefix || p.ipv6Prefix).filter(Boolean); } },
  // EC2 only: CloudFront and other edge services are CDN, never a customer host.
  { id: 'aws', url: 'https://ip-ranges.amazonaws.com/ip-ranges.json', kind: 'json',
    parse: (b) => { if (!Array.isArray(b?.prefixes) || !Array.isArray(b?.ipv6_prefixes)) throw new Error('shape');
      return [...b.prefixes.filter((p) => p.service === 'EC2').map((p) => p.ip_prefix), ...b.ipv6_prefixes.filter((p) => p.service === 'EC2').map((p) => p.ipv6_prefix)]; } },
  { id: 'oracle', url: 'https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json', kind: 'json',
    parse: (b) => { if (!Array.isArray(b?.regions)) throw new Error('shape'); return b.regions.flatMap((r) => (r.cidrs || []).map((c) => c.cidr)).filter(Boolean); } },
  { id: 'digitalocean', url: 'https://www.digitalocean.com/geo/google.csv', kind: 'csv',
    parse: (text) => String(text).split('\n').map((line) => line.split(',')[0].trim()).filter((c) => c.includes('/')) },
]);
export const CLOUD_RANGE_SOURCES = SOURCES.map(({ id, url }) => Object.freeze({ id, url }));

async function readBoundedText(body, limit) {
  const reader = body.getReader(); const chunks = []; let size = 0;
  for (;;) { const { done, value } = await reader.read(); if (done) break; size += value.byteLength;
    if (size > limit) { await reader.cancel(); throw new Error('too_large'); } chunks.push(value); }
  return new TextDecoder().decode(chunks.reduce((a, c) => { const n = new Uint8Array(a.length + c.length); n.set(a); n.set(c, a.length); return n; }, new Uint8Array()));
}

export async function refreshCloudRanges(env, { fetchImpl = fetch, now = Date.now() } = {}) {
  if (!env.cybermeters_reports?.put) return { status: 'unavailable' };
  const providers = {}, sources = {};
  for (const source of SOURCES) {
    try {
      const response = await fetchImpl(source.url, { method: 'GET', redirect: 'error',
        headers: { 'User-Agent': SCANNER_USER_AGENT }, signal: AbortSignal.timeout(10000) });
      if (!response.ok) { await response.body?.cancel(); sources[source.id] = 'unavailable'; continue; }
      const parsed = source.parse(source.kind === 'json' ? await readBoundedJson(response.body, 8 * 1024 * 1024)
        : await readBoundedText(response.body, 4 * 1024 * 1024));
      const cidrs = [...new Set(parsed.filter((c) => typeof c === 'string' && (c.includes(':') ? v6Range(c) : v4Range(c))))];
      if (cidrs.length < 1 || cidrs.length > 50000) { sources[source.id] = 'invalid'; continue; }
      providers[source.id] = cidrs; sources[source.id] = 'ok';
    } catch { sources[source.id] = 'invalid'; }
  }
  if (!Object.keys(providers).length) throw new Error('cloud_ranges_refresh_failed');
  const cache = { schema: 'cloud-ranges-v1', fetched_at: new Date(now).toISOString(), sources, providers };
  await env.cybermeters_reports.put(CLOUD_RANGES_KEY, JSON.stringify(cache), { httpMetadata: { contentType: 'application/json' } });
  return { status: 'updated', providers: Object.keys(providers) };
}

// An index for lookups; null when the cache is missing, malformed or stale.
export function cloudRangeIndex(cache, now = Date.now()) {
  const fetched = Date.parse(cache?.fetched_at || '');
  if (cache?.schema !== 'cloud-ranges-v1' || !Number.isFinite(fetched) || fetched > now + 60000 || now - fetched > CLOUD_RANGES_MAX_AGE_MS
      || !cache.providers || typeof cache.providers !== 'object') return null;
  const v4 = [], v6 = [];
  for (const [provider, cidrs] of Object.entries(cache.providers)) {
    if (!PROVIDER_NAMES[provider] || !Array.isArray(cidrs)) continue;
    for (const cidr of cidrs) {
      if (String(cidr).includes(':')) { const r = v6Range(cidr); if (r) v6.push([r[0], r[1], provider]); }
      else { const r = v4Range(cidr); if (r) v4.push([r[0], r[1], provider]); }
    }
  }
  v4.sort((a, b) => a[0] - b[0]); v6.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  return { fetched_at: cache.fetched_at, v4, v6 };
}
function search(list, value) {
  let lo = 0, hi = list.length - 1, found = null;
  while (lo <= hi) { const mid = (lo + hi) >> 1; if (list[mid][0] <= value) { found = mid; lo = mid + 1; } else hi = mid - 1; }
  if (found === null) return null;
  // Ranges can nest; walk back while starts could still cover the value.
  for (let i = found; i >= 0 && i > found - 64; i--) if (list[i][0] <= value && value <= list[i][1]) return list[i][2];
  return null;
}
export function cloudProviderForAddress(index, address) {
  if (!index) return null;
  const value = String(address).includes(':') ? v6ToBig(address) : v4Of(address);
  if (value === null) return null;
  return search(String(address).includes(':') ? index.v6 : index.v4, value);
}
export async function readCloudRanges(env) {
  try {
    const object = await env.cybermeters_reports?.get?.(CLOUD_RANGES_KEY);
    if (!object || object.size > 6 * 1024 * 1024) return null;
    return await readBoundedJson(object.body, 6 * 1024 * 1024);
  } catch { return null; }
}
