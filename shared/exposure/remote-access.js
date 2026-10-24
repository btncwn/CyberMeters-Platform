// Versioned, deliberately narrow signatures and advisory-derived ranges.
// Product names stay in fingerprint/table code; no inference from client versions,
// URL cache keys, certificates, hostnames, or the KEV product-name strings.
export const REMOTE_ACCESS_TABLE_VERSION = '2026-10-24.2';
// Login path: primary release-note PAN-183981 (10.1.9 addressed issues).
// A disabled browser page returns404 without disabling agent access:
// https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClbpCAC
export const REMOTE_ACCESS_PATHS = Object.freeze(['/', '/global-protect/login.esp', '/remote/login',
  '/vpn/index.html', '/dana-na/auth/url_default/welcome.cgi']);
const number = '(?:0|[1-9]\\d{0,2})';
export const REMOTE_ACCESS_SIGNATURES = Object.freeze([{
  id: 'panos_globalprotect',
  // Factory title documented in the primary response-page template.
  // https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClErCAK
  title: '^\\s*(?:Palo Alto Networks\\s*-\\s*)?GlobalProtect(?:\\s+(?:Portal|Gateway))?\\s*$',
  loginPath: '/global-protect/login.esp', versionContext: '\\bPAN-OS\\b',
  paths: ['/', '/global-protect/login.esp'], userField: 'user|username', format: 'panos',
  versionPattern: `^${number}\\.${number}\\.(?:0|[1-9]\\d?)(?:-h${number})?$`,
  versionLabel: '\\bPAN-OS\\s+(?:[Vv]ersion\\s*[:=]?\\s*)?([^\\s<>;,]{1,48})',
}, ...['fortios_sslvpn', 'fortiproxy_sslvpn'].map(id => ({
  id, title: '^\\s*(?:SSL[ -]?VPN Service|FortiGate(?: SSL[ -]?VPN)?|FortiProxy(?: SSL[ -]?VPN)?)\\s*$',
  productMarker: id === 'fortios_sslvpn' ? '\\b(?:FortiGate|FortiOS)\\b' : '\\bFortiProxy\\b',
  versionContext: id === 'fortios_sslvpn' ? '\\b(?:FortiGate|FortiOS)\\b' : '\\bFortiProxy\\b',
  // Primary SSL-VPN request paths: vendor KB technical tip163518.
  // https://community.fortinet.com/fortigate-3/troubleshooting-tip-ssl-vpn-user-not-able-to-connect-web-blocklist-check-error-163518
  paths: ['/', '/remote/login'], loginPath: '/remote/logincheck', userField: 'username', format: 'semver',
  versionPattern: `^${number}\\.${number}\\.${number}$`,
  versionLabel: `\\b${id === 'fortios_sslvpn' ? 'FortiOS' : 'FortiProxy'}\\s+(?:[Vv]ersion\\s*[:=]?\\s*|[vV](?=\\d))([^\\s<>;,]{1,48})`,
})), {
  id: 'netscaler_gateway', versionContext: '\\b(?:Citrix|NetScaler)(?: ADC| Gateway)?\\b', title: '^\\s*(?:Citrix|NetScaler) Gateway\\s*$',
  // Primary Gateway documentation: /vpn/index.html is the login front door.
  // https://docs.netscaler.com/en-us/netscaler-gateway/current-release/authentication-authorization/nfactor-for-gateway-authentication.html
  paths: ['/', '/vpn/index.html'], loginPath: '/cgi/login', userField: 'login|username', format: 'netscaler',
  // Three-digit suffixes and explicitly labelled FIPS/NDcPP builds are outside
  // this standard-build profile, not silently compared against another edition.
  versionPattern: `^${number}\\.${number}-${number}\\.(?:0|[1-9]\\d?)$`,
  unsupportedMarker: '\\b(?:FIPS|NDcPP)\\b',
  versionLabel: '\\b(?:Citrix|NetScaler)(?: ADC| Gateway)?\\s+[Vv]ersion\\s*[:=]?\\s*([^\\s<>;,]{1,48})',
}, {
  id: 'ivanti_connect_secure', versionContext: '\\b(?:Ivanti Connect Secure|Pulse(?: Connect)? Secure)\\b', title: '^\\s*(?:Ivanti Connect Secure|Pulse(?: Connect)? Secure)(?: - Sign In)?\\s*$',
  paths: ['/', '/dana-na/auth/url_default/welcome.cgi'], loginPath: '/dana-na/auth/url_default/login.cgi',
  userField: 'username', format: 'ivanti', versionPattern: `^${number}\\.${number}R${number}(?:\\.${number})?$`,
  versionLabel: '\\b(?:Ivanti Connect Secure|Pulse(?: Connect)? Secure)\\s+[Vv]ersion\\s*[:=]?\\s*([^\\s<>;,]{1,48})',
}]);
const advisoryRow = (product_id, cve, branch, affectedFrom, fixed, advisory, extra = {}) => Object.freeze({
  product_id, cve, branch, affectedFrom, fixed, advisory, reviewed_at: '2026-10-24', ...extra,
});
export const REMOTE_ACCESS_ADVISORIES = Object.freeze([
  // Vendor table: each maintenance release has its own backported hotfix.
  // Backports apply to their own maintenance release. The advisory explicitly
  // fixes later maintenance releases after the final listed fix in each train.
  ...[['10.2', [3,2,5,13,16,6,3,8,3,1]], ['11.0', [3,4,4,10,1]], ['11.1', [3,1,3]]]
    .flatMap(([train, fixes]) => fixes.map((hotfix, patch) => advisoryRow('panos_globalprotect', 'CVE-2024-3400',
      `${train}.${patch}`, `${train}.${patch}`, `${train}.${patch}-h${hotfix}`,
      'https://security.paloaltonetworks.com/CVE-2024-3400', {later_maintenance: patch === fixes.length-1}))),
  ...[
    ['fortios_sslvpn', 'CVE-2024-21762', [['7.4',3],['7.2',7],['7.0',14],['6.4',15],['6.2',16]], 'FG-IR-24-015'],
    ['fortiproxy_sslvpn', 'CVE-2024-21762', [['7.4',3],['7.2',9],['7.0',15],['2.0',14]], 'FG-IR-24-015'],
    ['fortios_sslvpn', 'CVE-2023-27997', [['7.2',5],['7.0',12],['6.4',13],['6.2',14],['6.0',17]], 'FG-IR-23-097'],
    ['fortiproxy_sslvpn', 'CVE-2023-27997', [['7.2',4],['7.0',10],['2.0',13]], 'FG-IR-23-097'],
  ].flatMap(([product,cve,trains,bulletin]) => trains.map(([train,patch]) => advisoryRow(product,cve,train,
    `${train}.0`,`${train}.${patch}`,`https://www.fortiguard.com/psirt/${bulletin}`))),
  // The vendor CNA marks this EOL train through6.0.18 affected, with no in-train
  // fixed release. An unlisted later spelling is unknown, never guessed fixed.
  advisoryRow('fortios_sslvpn','CVE-2024-21762','6.0','6.0.0',null,
    'https://www.fortiguard.com/psirt/FG-IR-24-015',{affectedThrough:'6.0.18'}),
  // Explicit unaffected reviewed train; do not infer future product branches.
  ...['fortios_sslvpn','fortiproxy_sslvpn'].map(product => advisoryRow(product,'CVE-2023-27997','7.4',null,'7.4.0',
    'https://www.fortiguard.com/psirt/FG-IR-23-097')),
  ...[
    ['CVE-2023-3519', 'CTX561482', [['13.0','91.13'],['13.1','49.13']]],
    ['CVE-2023-4966', 'CTX579459', [['13.0','92.19'],['13.1','49.15'],['14.1','8.50']]],
    ['CVE-2023-6549', 'CTX584986', [['13.0','92.21'],['13.1','51.15'],['14.1','12.35']]],
    ['CVE-2025-5777', 'CTX693420', [['13.1','58.32'],['14.1','43.56']]],
    ['CVE-2025-6543', 'CTX694788', [['13.1','59.19'],['14.1','47.46']]],
    ['CVE-2025-7775', 'CTX694938', [['13.1','59.22'],['14.1','47.48']]],
    ['CVE-2026-8452', 'CTX696604', [['13.1','63.18'],['14.1','72.61']]],
    ['CVE-2026-88771', 'CTX697096', [['13.1','64.23'],['14.1','73.37']]],
  ].flatMap(([cve,bulletin,trains]) => trains.map(([train,build]) => advisoryRow('netscaler_gateway',cve,train,
    `${train}-0.0`,`${train}-${build}`,`https://support.citrix.com/support-home/kbsearch/article?articleNumber=${bulletin}`))),
  // 14.1 was not an affected train in the vendor's2023-3519 record.
  advisoryRow('netscaler_gateway','CVE-2023-3519','14.1',null,'14.1-0.0',
    'https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX561482'),
  advisoryRow('ivanti_connect_secure','CVE-2025-0282','22.7R2','22.7R2','22.7R2.5',
    'https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Connect-Secure-Policy-Secure-ZTA-Gateways-CVE-2025-0282-CVE-2025-0283'),
  advisoryRow('ivanti_connect_secure','CVE-2025-22457','22.7R2','22.7R2','22.7R2.6',
    'https://forums.ivanti.com/s/article/April-Security-Advisory-Ivanti-Connect-Secure-Policy-Secure-ZTA-Gateways-CVE-2025-22457'),
  advisoryRow('ivanti_connect_secure','CVE-2025-22457','9.1',null,null,
    'https://www.ivanti.com/blog/security-update-pulse-connect-secure-ivanti-connect-secure-policy-secure-and-neurons-for-zta-gateways'),
]);
// Exact ranges are recorded, but their additional settings cannot be established
// by an anonymous login-page GET. These rows never independently emit a claim or
// permit verification. They are explicit excluded coverage, not guessed defaults.
export const REMOTE_ACCESS_CONDITIONAL_ADVISORIES = Object.freeze([
  ...[['13.1','64.23'],['14.1','73.37']].map(([train,build]) => advisoryRow('netscaler_gateway','CVE-2026-88772',train,
    `${train}-0.0`,`${train}-${build}`,'https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697096', {requires:'dtls_enabled'})),
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
  const candidates = REMOTE_ACCESS_SIGNATURES.filter(signature =>
    new RegExp(signature.title, 'i').test(title) && signature.paths.includes(url.pathname) &&
    (!signature.productMarker || new RegExp(signature.productMarker, 'i').test(html.replace(/<[^>]*>/g, '\n'))));
  if (candidates.length !== 1) return null;
  for (const signature of candidates) {
    const forms = [...html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)];
    const login = forms.some(([, attrs, fields]) => {
      const action = attrs.match(/\baction\s*=\s*["']([^"']+)["']/i)?.[1];
      if (!action || !/<input\b[^>]*\btype\s*=\s*["']password["']/i.test(fields) ||
          !new RegExp(`<input\\b[^>]*\\bname\\s*=\\s*["'](?:${signature.userField})["']`, 'i').test(fields)) return false;
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
    const lines = visible.split('\n');
    const field = lines.some(line => new RegExp(`^\\s*${signature.versionLabel}\\s*$`, 'i').test(line));
    const unsupported = signature.unsupportedMarker && new RegExp(signature.unsupportedMarker, 'i').test(visible);
    const explicit = !unsupported && field && versions.length === 1 && new RegExp(signature.versionPattern).test(versions[0]);
    // An unattributed visible version is not proof the server version is hidden.
    // Only a clearly named client/app/agent version may be excluded as client data.
    const unattributed = !labels.length && lines.some(line => /(?:^|[^\w.])v?\d{1,3}\.\d{1,3}(?:[.Rr-]\d{1,3})*(?:-h\d{1,3})?/.test(line) &&
      !/^\s*(?:client|app|agent)\s+(?:version|release)\s*[:=]?\s*v?\d{1,3}\.\d{1,3}(?:[.Rr-]\d{1,3})*(?:-h\d{1,3})?\s*$/i.test(line));
    const unparsedField = !labels.length && lines.some(line => {
      const value = line.match(/^\s*(?:(?:server|software|firmware)\s+)?(?:version|release)\s*[:=]?\s*([^\s]{1,48})/i)?.[1];
      return value && /\d/.test(value);
    });
    const unparsedProductVersion = !labels.length && lines.some(line => /\d/.test(line) &&
      new RegExp(signature.versionContext, 'i').test(line) &&
      !/\b(?:client|app|agent)\s+(?:version|release)\b/i.test(line));
    return { product_id: signature.id, version: explicit ? versions[0] : null,
      version_state: explicit ? 'explicit' : unsupported || labels.length || unattributed || unparsedField || unparsedProductVersion ? 'unreadable' : 'absent' };
  }
  return null;
}

export function validRemoteAccessEvidence(portal) {
  return portal && Object.keys(portal).length === 3 &&
    Object.keys(portal).every(k => ['product_id', 'version', 'version_state'].includes(k)) &&
    REMOTE_ACCESS_SIGNATURES.some(s => s.id === portal.product_id) &&
    ['explicit', 'absent', 'unreadable'].includes(portal.version_state) &&
    (portal.version_state === 'explicit'
      ? typeof portal.version === 'string' && new RegExp(REMOTE_ACCESS_SIGNATURES.find(s => s.id === portal.product_id).versionPattern).test(portal.version)
      : portal.version === null);
}

function compareRemoteVersion(a, b) {
  const parts = value => value.split(/[^\d]+/).map(Number);
  const left = parts(a), right = parts(b);
  for (let i = 0; i < 4; i++) {
    const difference = (left[i] || 0) - (right[i] || 0);
    if (difference) return Math.sign(difference);
  }
  return 0;
}

function remoteRowApplies(row, portal) {
  const signature = REMOTE_ACCESS_SIGNATURES.find(s => s.id === portal.product_id);
  if (signature.format === 'panos') {
    const version = portal.version.split('-h')[0].split('.').map(Number), branch = row.branch.split('.').map(Number);
    return version[0] === branch[0] && version[1] === branch[1] &&
      (version[2] === branch[2] || row.later_maintenance === true && version[2] > branch[2]);
  }
  if (signature.format === 'ivanti') return portal.version.startsWith(`${row.branch}R`) ||
    portal.version === row.branch || portal.version.startsWith(`${row.branch}.`);
  return portal.version.startsWith(row.branch + (signature.format === 'netscaler' ? '-' : '.'));
}

export function assessRemoteAccess(portal, catalogue, now = Date.now()) {
  if (!validRemoteAccessEvidence(portal)) return { state: 'deferred', reason: 'portal_evidence_invalid' };
  if (portal.version_state === 'absent') return { state: 'present', reason: 'version_not_visible', sentence: REMOTE_ACCESS_SENTENCES.hidden, severity: 'medium' };
  if (portal.version_state !== 'explicit') return { state: 'deferred', reason: 'version_not_interpretable' };
  const fetched = Date.parse(catalogue?.fetched_at || '');
  const released = Date.parse(catalogue?.released_at || '');
  if (!Number.isFinite(fetched) || fetched > now + 60000 || now - fetched > 7 * 86400000 ||
      !Number.isFinite(released) || released > now + 60000 || now - released > 14 * 86400000 || !Array.isArray(catalogue?.cves))
    return { state: 'deferred', reason: 'catalogue_unavailable_or_stale' };
  const productRows = REMOTE_ACCESS_ADVISORIES.filter(r => r.product_id === portal.product_id);
  const rows = productRows.filter(r => remoteRowApplies(r, portal));
  if (!rows.length) return { state: 'deferred', reason: 'version_outside_curated_table' };
  const affected = row => (row.affectedFrom === null && row.fixed === null ||
    row.affectedFrom !== null && compareRemoteVersion(portal.version, row.affectedFrom) >= 0) &&
    (row.fixed === null || compareRemoteVersion(portal.version, row.fixed) < 0) &&
    (!row.affectedThrough || compareRemoteVersion(portal.version, row.affectedThrough) <= 0);
  const match = rows.find(r => affected(r) && catalogue.cves.includes(r.cve));
  if (match) return { state: 'present', reason: 'stated_version_listed', sentence: REMOTE_ACCESS_SENTENCES.listed,
    severity: 'high', cve: match.cve, advisory: match.advisory, table_version: REMOTE_ACCESS_TABLE_VERSION,
    catalogue_version: catalogue.catalogue_version, catalogue_checked_at: catalogue.fetched_at };
  // Being absent from KEV is not proof that an affected version is fixed.
  if (rows.some(affected)) return { state: 'deferred', reason: 'affected_version_not_in_current_catalogue' };
  // Every curated CVE for this product must have a conclusive comparison. A
  // fixed release for one CVE never clears another affected/unknown branch.
  const covered = new Set(rows.filter(r => r.fixed !== null && compareRemoteVersion(portal.version,r.fixed) >= 0).map(r => r.cve));
  if (productRows.some(r => !covered.has(r.cve))) return {state:'deferred',reason:'version_outside_curated_table'};
  return { state: 'clear', reason: 'stated_version_in_fixed_range', table_version: REMOTE_ACCESS_TABLE_VERSION };
}

export function remoteAccessProgramSource() {
  return `const REMOTE_ACCESS_SIGNATURES=${JSON.stringify(REMOTE_ACCESS_SIGNATURES)};\n${remoteAccessFingerprint.toString()}\n`;
}
