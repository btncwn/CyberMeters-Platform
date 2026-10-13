import { EXPOSURE_CATALOG_VERSION, EXPOSURE_RULES, RULES_BY_ID } from './catalog.js';
import { isSafeExposurePath, isRulePathAllowed, sha256Text } from './redaction.js';

// Paths here are candidates. Host references never create authorization or trigger a fetch.
export function discoverExposureReferences({origin, paths = [], urls = [], body = '', headers = {}} = {}) {
  let base; try { base = new URL(origin); } catch { return {paths: [], discoveredHosts: []}; }
  const candidates = [...paths, ...urls];
  const text = typeof body === 'string' ? body.slice(0,32768) : '';
  for (const match of text.matchAll(/(?:href|src)\s*=\s*["']([^"'<>\s]+)["']|sourceMappingURL\s*=\s*([^\s*]+)|<loc>\s*([^<\s]+)\s*<\/loc>|^(?:Allow|Disallow|Sitemap):\s*(\S+)/gmi)) candidates.push(match[1] || match[2] || match[3] || match[4] || match[5]);
  for (const key of ['sourcemap', 'x-sourcemap', 'SourceMap', 'X-SourceMap']) if (headers[key]) candidates.push(headers[key]);
  try {
    const doc = JSON.parse(text);
    if (doc?.version === 3 && Array.isArray(doc.sources)) {
      const root = typeof doc.sourceRoot === 'string' ? doc.sourceRoot : '';
      for (const source of doc.sources.slice(0,512)) {
        if (typeof source !== 'string') continue;
        try { candidates.push(new URL(source, new URL(root || '.', base)).href); } catch { /* webpack/file identifiers are not HTTP targets. */ }
      }
    }
    if (doc && (doc.openapi || doc.swagger) && doc.paths && typeof doc.paths === 'object') {
      // Only documented GET operations, and still only finite catalog-compatible paths.
      for (const [path, operations] of Object.entries(doc.paths)) if (operations?.get) candidates.push(path);
      for (const server of (Array.isArray(doc.servers) ? doc.servers : [])) if (server?.url) candidates.push(server.url);
    }
  } catch { /* Not a JSON reference document. */ }
  const accepted = new Set(), hosts = new Set();
  for (const candidate of candidates.slice(0, 1024)) {
    if (typeof candidate !== 'string' || candidate.length > 2048) continue;
    try {
      const url = new URL(candidate, base);
      if (!['http:','https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) continue;
      if (url.origin !== base.origin) {
        // DNS ownership/verification must be rechecked by the established discovery pipeline.
        if (/^[a-z0-9.-]{1,253}$/i.test(url.hostname) && !url.hostname.includes('..')) hosts.add(url.hostname.toLowerCase());
        continue;
      }
      if (isSafeExposurePath(url.pathname)) accepted.add(url.pathname);
    } catch { /* A reference is untrusted input. */ }
  }
  return {paths: [...accepted].slice(0, 512), discoveredHosts: [...hosts].slice(0, 128)};
}

export function planExposureChecks({origin, observations = {}, previousFindings = []} = {}) {
  let base; try { base = new URL(origin); } catch { return {catalogVersion: EXPOSURE_CATALOG_VERSION, checks: [], discoveredHosts: []}; }
  if (!['http:','https:'].includes(base.protocol) || base.username || base.password || base.search || base.hash) return {catalogVersion: EXPOSURE_CATALOG_VERSION, checks: [], discoveredHosts: []};
  const refs = discoverExposureReferences({origin: base.origin, ...observations});
  const checks = new Map();
  const technologies = (Array.isArray(observations.technologies) ? observations.technologies : []).filter(v=>typeof v === 'string').join(' ').toLowerCase();
  const add = (rule, path, source, priority) => {
    if (!isRulePathAllowed(rule, path)) return;
    const key = rule.id + '\n' + path;
    if (!checks.has(key) || checks.get(key).priority < priority) checks.set(key, {ruleId: rule.id, url: base.origin + path, source, priority, maxCost: rule.maxCost});
  };
  for (const f of previousFindings.slice(0, 256)) {
    const rule = RULES_BY_ID[f?.ruleId || f?.rule_id];
    try { const u = new URL(f.url, base); if (u.origin === base.origin && !u.search && !u.hash && !u.username && !u.password) add(rule, u.pathname, 'previous_finding', 100); } catch { /* No reconstructable retest endpoint. */ }
  }
  for (const rule of EXPOSURE_RULES) {
    const techBoost = technologies && /(?:git|svn|php|spring|jenkins|grafana|elasticsearch|couchdb|prometheus|ignition)/.test(technologies) && technologies.split(/[^a-z]+/).some(t=>t.length > 2 && rule.id.includes(t)) ? 3 : 0;
    rule.paths.forEach((path,index)=>add(rule, path, 'catalog', 20 + techBoost - Math.min(index, 15)));
  }
  for (const path of refs.paths) {
    for (const rule of EXPOSURE_RULES) if (isRulePathAllowed(rule, path)) add(rule, path, 'observed_reference', 60);
    if (/\.(?:m?js|css)$/i.test(path)) add(RULES_BY_ID['source-map'], path + '.map', 'observed_filename_variant', 55);
    if (/\.(?:php|aspx|jsp|config|py|rb)$/i.test(path)) {
      for (const suffix of ['.bak', '.old', '~']) add(RULES_BY_ID['backup-source'], path + suffix, 'observed_filename_variant', 50);
    }
    if (/(?:\.env|\.(?:json|ya?ml|conf|config|properties))$/i.test(path)) {
      for (const suffix of ['.bak','.old']) {
        add(RULES_BY_ID['env-config'], path + suffix, 'observed_filename_variant', 50);
        add(RULES_BY_ID['application-config'], path + suffix, 'observed_filename_variant', 50);
      }
    }
    // Observed application directory names yield backup archive candidates; never execute the path itself.
    const directory = path.endsWith('/') ? path.slice(0,-1) : path.slice(0,path.lastIndexOf('/'));
    if (directory && /\/[a-z][a-z0-9_-]{1,40}$/i.test(directory)) for (const suffix of ['.zip','.tar.gz']) add(RULES_BY_ID['backup-archive'], directory + suffix, 'observed_directory_variant', 45);
  }
  // Stable salted ordering within priority avoids giving alphabetical paths permanent precedence.
  const seed = String(observations.rotationKey || base.hostname);
  const ordered = [...checks.values()].sort((a,b)=>b.priority-a.priority || sha256Text(seed+a.ruleId+a.url).localeCompare(sha256Text(seed+b.ruleId+b.url)));
  return {catalogVersion: EXPOSURE_CATALOG_VERSION, checks: ordered, discoveredHosts: refs.discoveredHosts};
}
