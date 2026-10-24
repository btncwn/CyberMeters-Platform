// Versioned, deliberately narrow signatures and advisory-derived ranges.
// Product names stay in fingerprint/table code; no inference from client versions,
// URL cache keys, certificates, hostnames, or the KEV product-name strings.
export const REMOTE_ACCESS_TABLE_VERSION = '2026-10-24.1';
// Login path: primary release-note PAN-183981 (10.1.9 addressed issues).
// A disabled browser page returns404 without disabling agent access:
// https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClbpCAC
export const REMOTE_ACCESS_PATHS = Object.freeze(['/', '/global-protect/login.esp']);
export const REMOTE_ACCESS_SIGNATURES = Object.freeze([{
  id: 'panos_globalprotect',
  // Factory title documented in the primary response-page template.
  // https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClErCAK
  title: '^\\s*(?:Palo Alto Networks\\s*-\\s*)?GlobalProtect(?:\\s+(?:Portal|Gateway))?\\s*$',
  loginPath: '/global-protect/login.esp',
  versionLabel: '\\bPAN-OS\\s+(?:[Vv]ersion\\s*[:=]?\\s*)?([^\\s<>;,]{1,48})',
}]);
export const REMOTE_ACCESS_ADVISORIES = Object.freeze([
  // Vendor table: each maintenance release has its own backported hotfix.
  // Unlisted maintenance releases are UNKNOWN, never a guessed fixed version.
  ...[[0, 3], [1, 1], [2, 3]].map(([patch, fixedHotfix]) => Object.freeze({
    product_id: 'panos_globalprotect', cve: 'CVE-2024-3400',
    branch: `11.1.${patch}`, affectedFrom: `11.1.${patch}`, fixed: `11.1.${patch}-h${fixedHotfix}`,
    advisory: 'https://security.paloaltonetworks.com/CVE-2024-3400',
    reviewed_at: '2026-10-24',
  })),
]);
export const REMOTE_ACCESS_SENTENCES = Object.freeze({
  listed: 'Your remote-access portal is exposed to the internet and its version is on the list of actively exploited vulnerabilities.',
  hidden: 'Your remote-access portal is exposed to the internet; its version is not visible from outside.',
});

export function remoteAccessFingerprint(body, value) {
  if (typeof body !== 'string' || body.length > 32768) return null;
  let url; try { url = new URL(value); } catch { return null; }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) return null;
  const html = body.replace(/<!--[\s\S]*?-->/g, '').replace(/<(?:script|style)\b[^>]*>[\s\S]*?<\/(?:script|style)>/gi, '');
  const title = html.match(/<title\b[^>]*>([^<]*)<\/title>/i)?.[1];
  if (!title || /<(?:pre|code|article)\b/i.test(html) || /portal does not exist|portal (?:is )?not configured/i.test(html)) return null;
  for (const signature of REMOTE_ACCESS_SIGNATURES) {
    if (!new RegExp(signature.title, 'i').test(title) || !['/', signature.loginPath].includes(url.pathname)) continue;
    const forms = [...html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)];
    const login = forms.some(([, attrs, fields]) => {
      const action = attrs.match(/\baction\s*=\s*["']([^"']+)["']/i)?.[1];
      if (!action || !/<input\b[^>]*\btype\s*=\s*["']password["']/i.test(fields) ||
          !/<input\b[^>]*\bname\s*=\s*["'](?:user|username)["']/i.test(fields)) return false;
      let target; try { target = new URL(action, url); } catch { return false; }
      return target.origin === url.origin && target.pathname === signature.loginPath && !target.search && !target.hash;
    });
    if (!login) continue;
    // Only an explicit server-product label in page text; client downloads and
    // JavaScript/configuration values never establish the server version.
    const visible = html.replace(/<[^>]*>/g, '\n').replace(/&(?:nbsp|#160);/g, ' ');
    const labels = [...visible.matchAll(new RegExp(signature.versionLabel, 'gi'))].map(m => m[1]);
    const versions = [...new Set(labels)];
    // Require a standalone product/version field, not prose about a supported,
    // recommended or required release. Ambiguous mentions remain unreadable.
    const field = visible.split('\n').some(line => new RegExp(`^\\s*${signature.versionLabel}\\s*$`, 'i').test(line));
    const explicit = field && versions.length === 1 && /^\d{1,3}\.\d{1,3}\.\d{1,3}(?:-h\d{1,3})?$/.test(versions[0]);
    return { product_id: signature.id, version: explicit ? versions[0] : null,
      version_state: explicit ? 'explicit' : labels.length ? 'unreadable' : 'absent' };
  }
  return null;
}

export function validRemoteAccessEvidence(portal) {
  return portal && Object.keys(portal).length === 3 &&
    Object.keys(portal).every(k => ['product_id', 'version', 'version_state'].includes(k)) &&
    REMOTE_ACCESS_SIGNATURES.some(s => s.id === portal.product_id) &&
    ['explicit', 'absent', 'unreadable'].includes(portal.version_state) &&
    (portal.version_state === 'explicit'
      ? typeof portal.version === 'string' && /^\d{1,3}\.\d{1,3}\.\d{1,3}(?:-h\d{1,3})?$/.test(portal.version)
      : portal.version === null);
}

export function assessRemoteAccess(portal, catalogue, now = Date.now()) {
  if (!validRemoteAccessEvidence(portal)) return { state: 'deferred', reason: 'portal_evidence_invalid' };
  if (portal.version_state === 'absent') return { state: 'present', reason: 'version_not_visible', sentence: REMOTE_ACCESS_SENTENCES.hidden, severity: 'medium' };
  if (portal.version_state !== 'explicit') return { state: 'deferred', reason: 'version_not_interpretable' };
  const fetched = Date.parse(catalogue?.fetched_at || '');
  if (!Number.isFinite(fetched) || fetched > now + 60000 || now - fetched > 7 * 86400000 || !Array.isArray(catalogue?.cves))
    return { state: 'deferred', reason: 'catalogue_unavailable_or_stale' };
  const [branch, hotfix = '0'] = portal.version.split('-h');
  const rows = REMOTE_ACCESS_ADVISORIES.filter(r => r.product_id === portal.product_id && r.branch === branch);
  if (!rows.length) return { state: 'deferred', reason: 'version_outside_curated_table' };
  const match = rows.find(r => Number(hotfix) < Number(r.fixed.split('-h')[1]) && catalogue.cves.includes(r.cve));
  if (match) return { state: 'present', reason: 'stated_version_listed', sentence: REMOTE_ACCESS_SENTENCES.listed,
    severity: 'high', cve: match.cve, advisory: match.advisory, table_version: REMOTE_ACCESS_TABLE_VERSION,
    catalogue_version: catalogue.catalogue_version, catalogue_checked_at: catalogue.fetched_at };
  // Being absent from KEV is not proof that an affected version is fixed.
  if (rows.some(r => Number(hotfix) < Number(r.fixed.split('-h')[1]))) return { state: 'deferred', reason: 'affected_version_not_in_current_catalogue' };
  return { state: 'clear', reason: 'stated_version_in_fixed_range', table_version: REMOTE_ACCESS_TABLE_VERSION };
}

export function remoteAccessProgramSource() {
  return `const REMOTE_ACCESS_SIGNATURES=${JSON.stringify(REMOTE_ACCESS_SIGNATURES)};\n${remoteAccessFingerprint.toString()}\n`;
}
