// Passive reported-version advice, never proof of exploitability. Reuses the
// technology response; no request, live database or exploit payload is involved.
import { sha256Text } from '../../../../shared/exposure/redaction.js';

export const PHP_RUNTIME_TABLE_VERSION = '2026-10-24.1';
const ADVISORY = 'https://www.php.net/archive/2026.php#2026-10-21-5';
export const PHP_UPSTREAM_FIXES = Object.freeze([
  ...[['8.5', '8.5.12'], ['8.4', '8.4.27'], ['8.3', '8.3.36'], ['8.2', '8.2.35']].map(([branch, fixed]) => Object.freeze({ branch, fixed, advisory: ADVISORY })),
  Object.freeze({ branch: '<=8.1', fixed: null, advisory: ADVISORY }),
]);
export const PHP_RUNTIME_TITLE = 'Review the reported PHP release';
const KEY = /^tech_php2shell_outdated__[a-f0-9]{64}$/;
export const isPhpRuntimeConditionKey = (key) => KEY.test(String(key || ''));

// PHP 8.1 and older have no fixed upstream release. Distribution backports may
// retain the same number: retain their suffix and describe only the report.
export function classifyPhpRuntime({ poweredBy = null, server = null } = {}) {
  const tokens = [];
  for (const header of [poweredBy, server]) {
    if (header == null) continue;
    if (typeof header !== 'string' || header.length > 2048 || /[^\x20-\x7e]/.test(header)) return { state: 'unreadable' };
    let recognized = false;
    for (const match of header.matchAll(/(?:^|[\s,;(])(PHP(?:[-_]FPM|-CGI)?|mod_php)(?=$|[\/\s,;)])([^,;]*)/gi)) {
      recognized = true;
      const rest = match[2].trim();
      if (!rest || /^\)+$/.test(rest) || /^\([^\d]*\)$/.test(rest)) { tokens.push(null); continue; }
      if (match[1].toLowerCase() !== 'php') return { state: 'unreadable' };
      if (/(?:^|[\s;(])PHP(?=$|[\/\s;)])/i.test(rest)) return { state: 'unreadable' };
      // A client/pre-release/malformed number is not a stable server release.
      const version = /^\/([1-9]\d?\.(?:0|[1-9]\d?)\.(?:0|[1-9]\d{0,3})(?:[-+][0-9A-Za-z][0-9A-Za-z.+~_-]{0,63})?)(?:\s|\)|$)/.exec(rest)?.[1];
      if (!version || /(?:alpha|beta|rc|dev|snapshot|preview|pre-)/i.test(version)) return { state: 'unreadable' };
      tokens.push(version);
    }
    // A runtime alias or unfamiliar version spelling is not absence of PHP.
    if (!recognized && /\b(?:PHP|mod_php)/i.test(header)) return { state: 'unreadable' };
  }
  if (!tokens.length) return { state: 'absent' };
  const versions = [...new Set(tokens.filter(Boolean))];
  if (!versions.length) return { state: 'hidden' };
  if (versions.length !== 1) return { state: 'unreadable' };
  const version = versions[0];
  const [major, minor, patch] = version.split(/[.+-]/).slice(0, 3).map(Number);
  if (major < 1 || major > 8 || major === 8 && minor > 5) return { state: 'unreadable' };
  const fixed = PHP_UPSTREAM_FIXES.find(row => row.branch === `${major}.${minor}`)?.fixed || null;
  const oldBranch = major < 8 || major === 8 && minor <= 1;
  if (!fixed && !oldBranch) return { state: 'unreadable' };
  return { state: oldBranch || patch < Number(fixed.split('.')[2]) ? 'outdated' : 'fixed', reported_version: version, upstream_fixed: fixed };
}

function observedUrl(raw) {
  try {
    const url = new URL(raw);
    if (url.protocol !== 'https:' || url.username || url.password || url.href.length > 2048) return null;
    url.search = ''; url.hash = '';
    return url.href;
  } catch { return null; }
}

export function phpRuntimeObservation({ poweredBy, server, url } = {}) {
  const affected_url = observedUrl(url);
  if (!affected_url) return { state: 'unreadable', table_version: PHP_RUNTIME_TABLE_VERSION };
  return { ...classifyPhpRuntime({ poweredBy, server }), affected_url,
    condition_key: `tech_php2shell_outdated__${sha256Text(affected_url)}`, table_version: PHP_RUNTIME_TABLE_VERSION };
}

export function phpRuntimeFindings(observation) {
  if (!observation?.affected_url) return [];
  const common = { score_impact: 0, affected_hosts: [new URL(observation.affected_url).hostname],
    php_runtime: observation, finding_type: 'finding' };
  if (observation.state === 'outdated') return [{ ...common, id: observation.condition_key,
    title: PHP_RUNTIME_TITLE, severity: 'high',
    description: phpRuntimeSentence(observation) }];
  if (observation.state === 'hidden') return [{ ...common, id: 'tech_php2shell_version_hidden',
    title: 'Confirm the PHP update with your hosting provider', severity: 'info', finding_type: 'observation',
    description: phpRuntimeSentence(observation) }];
  return [];
}

export function phpRuntimeSentence(observation) {
  if (observation?.state === 'outdated' && typeof observation.reported_version === 'string'
      && /^[0-9][0-9A-Za-z.+~_-]{0,79}$/.test(observation.reported_version)) {
    return `Your website reports PHP version ${observation.reported_version}, which is older than the release that fixes the critical PHP2Shell vulnerabilities (CVE-2026-109618, CVE-2026-109619). Update PHP, or confirm with your hosting provider that their patched build is installed.`;
  }
  if (observation?.state === 'hidden') return 'Your website appears to run on PHP. Its version is not visible from outside, so confirm with your hosting provider that PHP has been updated for the PHP2Shell vulnerabilities.';
  return null;
}

// A new URL, hidden version, access restriction or unsupported version cannot
// verify a prior case. Only the exact host/path observed serviceably can clear.
export function evaluatePhpRuntimeCondition(key, tech) {
  const observation = tech?.php_runtime;
  if (!isPhpRuntimeConditionKey(key) || !observation || tech.incomplete || tech.error
      || tech.serviceability_contract?.serviceable !== true || key !== observation.condition_key) return { state: 'deferred', reason: 'runtime_retest_not_comparable' };
  if (observation.state === 'outdated') return { state: 'present', reason: 'reported_release_below_upstream_fix' };
  if (['fixed', 'absent'].includes(observation.state)) return { state: 'clear', reason: 'exact_runtime_response_retested_clear' };
  return { state: 'deferred', reason: 'runtime_version_inconclusive' };
}
