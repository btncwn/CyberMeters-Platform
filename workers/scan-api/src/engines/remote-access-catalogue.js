// Public catalogue refresh only. Scans read the existing bucket, never the feed.
import { readBoundedJson } from '../../../network-probe/src/contract.js';
import { SCANNER_USER_AGENT } from '../lib/http.js';
export const REMOTE_ACCESS_CATALOGUE_KEY = 'public-feeds/remote-access-kev-v1.json';
export const REMOTE_ACCESS_FEED_URLS = Object.freeze([
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  // Official agency-owned mirror, for regions where the canonical feed refuses GET.
  'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json',
]);
export async function refreshRemoteAccessCatalogue(env, { fetchImpl = fetch, now = Date.now() } = {}) {
  if (!env.cybermeters_reports?.put) return { status: 'unavailable' };
  for (const url of REMOTE_ACCESS_FEED_URLS) {
    try {
      const response = await fetchImpl(url, { method: 'GET', redirect: 'error',
        headers: { Accept: 'application/json', 'User-Agent': SCANNER_USER_AGENT }, signal: AbortSignal.timeout(10000) });
      if (!response.ok) { await response.body?.cancel(); continue; }
      const body = await readBoundedJson(response.body, 4 * 1024 * 1024);
      const released = Date.parse(body.dateReleased || '');
      if (!Number.isFinite(released) || released > now + 60000 || now - released > 14 * 86400000 ||
          typeof body.catalogVersion !== 'string' || !/^\d{4}\.\d{2}\.\d{2}$/.test(body.catalogVersion) ||
          !Array.isArray(body.vulnerabilities) || body.vulnerabilities.length < 1 || body.vulnerabilities.length > 20000 ||
          body.count !== body.vulnerabilities.length || body.vulnerabilities.some(v => !/^CVE-\d{4}-\d{4,19}$/.test(v?.cveID))) continue;
      const cache = { schema: 'remote-access-kev-v1', source: url, fetched_at: new Date(now).toISOString(),
        catalogue_version: body.catalogVersion, released_at: body.dateReleased,
        cves: [...new Set(body.vulnerabilities.map(v => v.cveID))] };
      await env.cybermeters_reports.put(REMOTE_ACCESS_CATALOGUE_KEY, JSON.stringify(cache), { httpMetadata: { contentType: 'application/json' } });
      return { status: 'updated', count: cache.cves.length };
    } catch { /* keep the last validated cache; its seven-day expiry still applies */ }
  }
  throw new Error('remote_access_catalogue_refresh_failed');
}
export async function readRemoteAccessCatalogue(env) {
  try {
    const object = await env.cybermeters_reports.get(REMOTE_ACCESS_CATALOGUE_KEY);
    if (!object || object.size > 1024 * 1024) return null;
    const cache = await readBoundedJson(object.body, 1024 * 1024);
    if (cache.schema !== 'remote-access-kev-v1' || !REMOTE_ACCESS_FEED_URLS.includes(cache.source) ||
        typeof cache.catalogue_version !== 'string' || !Array.isArray(cache.cves) || cache.cves.length > 20000 ||
        cache.cves.some(v => !/^CVE-\d{4}-\d{4,19}$/.test(v))) return null;
    return cache;
  } catch { return null; }
}
