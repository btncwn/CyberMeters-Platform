import { normalizeHostname, classifyHostname } from './hostname-candidates.js';

// Locally authored service, environment and region patterns; no downloaded list.
// These are guesses for later DNS validation, never observations or open services.
const SERVICES = Object.freeze([
  'accounts', 'admin', 'analytics', 'api', 'app', 'apps', 'assets', 'auth',
  'autodiscover', 'backup', 'billing', 'blog', 'build', 'cache', 'calendar',
  'cdn', 'chat', 'ci', 'desktops', 'cloud', 'cms', 'console', 'control', 'crm',
  'dashboard', 'data', 'db', 'deploy', 'developer', 'devops', 'direct', 'discovery',
  'dns', 'containers', 'docs', 'download', 'downloads', 'edge', 'index', 'indexer',
  'erp', 'events', 'mailbox', 'extranet', 'files', 'ftp', 'gateway', 'git',
  'repositories', 'charts', 'graphql', 'help', 'helpdesk', 'hr', 'hub', 'id', 'identity',
  'images', 'img', 'imap', 'intranet', 'builds', 'issues', 'jobs', 'eventbus', 'kb',
  'realms', 'logsearch', 'clusters', 'ldap', 'login', 'logs', 'm', 'mail',
  'management', 'media', 'metrics', 'mobile', 'monitor', 'monitoring', 'mq',
  'mta', 'relational', 'news', 'webserver', 'notify', 'ns', 'ntp', 'oauth', 'collaboration',
  'ops', 'origin', 'webaccess', 'panel', 'partners', 'pay', 'payments', 'portal',
  'database', 'timeseries', 'proxy', 'queues', 'radius', 'memory', 'registry',
  'relay', 'remote', 'repo', 'reports', 'router', 'objects', 'sales', 'search',
  'secure', 'security', 'errors', 'service', 'services', 'sftp', 'documents',
  'shop', 'smtp', 'sql', 'sso', 'static', 'stats', 'status', 'storage', 'store',
  'stream', 'support', 'sync', 'team', 'telemetry', 'tickets', 'uploads', 'vault',
  'video', 'vpn', 'web', 'webhooks', 'webmail', 'wiki', 'www', 'xmpp',
]);

const ENVIRONMENTS = Object.freeze([
  'dev', 'staging', 'test', 'uat', 'qa', 'prod', 'old', 'new', 'v2',
]);
const REGIONS = Object.freeze([
  'apac', 'au', 'ca', 'de', 'eu', 'eu-central', 'eu-west', 'fr', 'jp',
  'sg', 'uk', 'us', 'us-east', 'us-west', 'us-east-1', 'us-west-2',
]);
const REGION_SERVICES = Object.freeze([
  'api', 'app', 'assets', 'auth', 'backup', 'cdn', 'cloud', 'console', 'data',
  'db', 'edge', 'files', 'gateway', 'git', 'images', 'login', 'logs', 'mail',
  'metrics', 'mobile', 'monitor', 'portal', 'proxy', 'registry', 'remote',
  'reports', 'objects', 'search', 'smtp', 'sso', 'static', 'status', 'storage',
  'stream', 'support', 'uploads', 'video', 'vpn', 'web', 'www',
]);

function buildWordlist() {
  const labels = new Set([
    ...SERVICES, ...ENVIRONMENTS, ...REGIONS,
    'beta', 'demo', 'development', 'internal', 'local', 'preprod', 'preview',
    'production', 'sandbox', 'stage', 'testing', 'training', 'acceptance',
  ]);
  for (const service of SERVICES) {
    for (const environment of ENVIRONMENTS) labels.add(`${service}-${environment}`);
    labels.add(`dev-${service}`);
    labels.add(`staging-${service}`);
  }
  for (const service of REGION_SERVICES) {
    for (const region of REGIONS) labels.add(`${service}-${region}`);
  }
  for (const service of ['app', 'api', 'db', 'dns', 'mail', 'mx', 'ns', 'smtp', 'vpn', 'web', 'www']) {
    for (const number of [1, 2, 3]) labels.add(`${service}${number}`);
  }
  return Object.freeze([...labels].sort());
}

export const DISCOVERY_WORDLIST = buildWordlist();
export const DISCOVERY_WORDLIST_LIMITS = Object.freeze({
  defaultSliceSize: 50,
  defaultVariants: 100,
  maxVariants: 1000,
  maxInputNames: 1000,
});

/**
 * A slice stops at the list end instead of duplicating labels across a wrap.
 * wrapped means that this call reached the end; next_cursor is then zero.
 * Invalid cursors restart at zero. Invalid sizes default to 50; zero is a no-op.
 * Oversized slices return at most one cycle, with a caller-owned labels array.
 */
export function wordlistSlice(options = {}) {
  const { cursor, size } = options ?? {};
  const length = DISCOVERY_WORDLIST.length;
  const start = Number.isInteger(cursor) && cursor >= 0 && cursor < length ? cursor : 0;
  const count = Number.isSafeInteger(size) && size >= 0
    ? Math.min(size, length)
    : DISCOVERY_WORDLIST_LIMITS.defaultSliceSize;
  const end = Math.min(start + count, length);
  return {
    labels: DISCOVERY_WORDLIST.slice(start, end),
    next_cursor: end === length ? 0 : end,
    wrapped: end === length,
  };
}

function variantLimit(value) {
  return Number.isSafeInteger(value) && value >= 0
    ? Math.min(value, DISCOVERY_WORDLIST_LIMITS.maxVariants)
    : DISCOVERY_WORDLIST_LIMITS.defaultVariants;
}

/**
 * Returns guesses only: no DNS, service or ownership claim is made here.
 * Input inspection is limited to its first 1000 entries; max is capped at 1000.
 * For the inspected names, results and lexical parent choice are order independent.
 * Replaces only labels below the supplied root, preserving nested hostname paths.
 */
export function deriveNameVariants(hostnames, options = {}) {
  const { domain, max } = options ?? {};
  const root = normalizeHostname(domain);
  const limit = variantLimit(max);
  if (!root || !limit || !Array.isArray(hostnames)) return [];

  const observed = new Set();
  for (const value of hostnames.slice(0, DISCOVERY_WORDLIST_LIMITS.maxInputNames)) {
    const result = classifyHostname(value, root);
    if (result.kind === 'candidate') observed.add(result.hostname);
  }
  const derived = new Map();
  function add(relativeLabels, parent) {
    const candidate = `${relativeLabels.join('.')}.${root}`;
    const result = classifyHostname(candidate, root);
    if (result.kind !== 'candidate' || observed.has(result.hostname)) return;
    const previous = derived.get(result.hostname);
    if (!previous || parent < previous) derived.set(result.hostname, parent);
  }

  for (const parent of [...observed].sort()) {
    const labels = parent.slice(0, -(root.length + 1)).split('.');
    const first = labels[0];
    for (const environment of ENVIRONMENTS) add([`${first}-${environment}`, ...labels.slice(1)], parent);
    for (const environment of ['dev', 'staging']) add([`${environment}-${first}`, ...labels.slice(1)], parent);

    // Keep a numeric suffix's width (app01 -> app02/app03), avoiding imprecise integers.
    const numeric = first.match(/^(.*?)(\d+)$/);
    if (numeric && numeric[1] && numeric[2].length <= 12) {
      const current = Number(numeric[2]);
      for (const increment of [1, 2]) {
        const number = String(current + increment).padStart(numeric[2].length, '0');
        add([`${numeric[1]}${number}`, ...labels.slice(1)], parent);
      }
    }

    // Prefer the longest match so api-us-east-1 is one region rather than "us".
    for (let index = 0; index < labels.length; index++) {
      const label = labels[index];
      const matched = [...REGIONS].sort((a, b) => b.length - a.length || (a < b ? -1 : a > b ? 1 : 0))
        .find(region => label === region || label.endsWith(`-${region}`) || label.startsWith(`${region}-`));
      if (!matched) continue;
      for (const region of REGIONS) {
        if (region === matched) continue;
        let replacement;
        if (label === matched) replacement = region;
        else if (label.endsWith(`-${matched}`)) replacement = `${label.slice(0, -(matched.length + 1))}-${region}`;
        else replacement = `${region}-${label.slice(matched.length + 1)}`;
        const next = labels.slice();
        next[index] = replacement;
        add(next, parent);
      }
    }
  }
  return [...derived.keys()].sort().slice(0, limit)
    .map(hostname => ({ hostname, derived_from: derived.get(hostname) }));
}
