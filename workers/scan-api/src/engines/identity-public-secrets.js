// Only customer-verified public web sources. No credentials are tested, returned
// or stored. Evidence is a one-way fingerprint, a mask and source location.
import { makeSsrfSafeProbeFetch } from './reserved-probe.js';
import { dnsQuery } from './dns.js';
import { urlIsBlockedTarget } from '../lib/ssrf.js';

export const SECRET_CHECK_SCOPE = 'One public page and up to three directly linked same-origin JavaScript files. Key validity, use and account compromise are not tested. No match does not establish the absence of secrets.';
export const SECRET_CHECK_LIMITS = Object.freeze({ files: 4, bytesPerFile: 524288, candidates: 20, timeoutMs: 15000 });
const RULES = [
  { id: 'stripe_secret', label: 'Stripe live secret or restricted key', pattern: /\b(?:sk|rk)_live_[A-Za-z0-9]{24,200}\b/g },
  { id: 'github_token', label: 'GitHub access token', pattern: /\bgh[pousr]_[A-Za-z0-9]{36}\b/g },
  { id: 'github_fine_grained', label: 'GitHub fine-grained access token', pattern: /\bgithub_pat_[A-Za-z0-9_]{82}\b/g },
  { id: 'slack_token', label: 'Slack access token', pattern: /\bxox[baprs]-[0-9]{8,15}-[0-9]{8,15}-[A-Za-z0-9]{16,64}\b/g },
  { id: 'private_key', label: 'Private key material', pattern: /-----BEGIN ((?:RSA |EC |OPENSSH )?PRIVATE KEY)-----[\s\S]{128,16384}?-----END \1-----/g },
];
export const SECRET_CHECK_TYPES = RULES.map(({ id, label }) => ({ id, label }));
const error = code => Object.assign(new Error('Public source check unavailable.'), { code });
const hex = buffer => [...new Uint8Array(buffer)].map(n => n.toString(16).padStart(2, '0')).join('');
async function digest(text) { return hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))); }
function plausible(value) {
  if (/example|placeholder|your[_-]|changeme|dummy|synthetic/i.test(value)) return false;
  const body = value.replace(/^[^_]*_[^_]*_/, '');
  const counts = new Map(); for (const c of body) counts.set(c, (counts.get(c) || 0) + 1);
  let entropy = 0; for (const n of counts.values()) { const p = n / body.length; entropy -= p * Math.log2(p); }
  return entropy >= 3.3;
}
export function secretSourceUrl(value) {
  const url = new URL(value); url.search = ''; url.hash = ''; url.username = ''; url.password = '';
  // Paths may themselves contain credentials. Keep ordinary asset filenames,
  // but hide long opaque segments and every recognized token family.
  url.pathname = url.pathname.split('/').map(part => {
    let decoded; try { decoded = decodeURIComponent(part); } catch { decoded = part; }
    return decoded.length > 120 || /(?:sk_live_|rk_live_|gh[pousr]_|github_pat_|xox[baprs]-)/i.test(decoded) ? '[redacted]' : part;
  }).join('/');
  return url.href;
}
export function validateSecretCheckUrl(value, verifiedDomain) {
  if (typeof value !== 'string' || value.length > 2048) throw error('invalid_source_url');
  let url; try { url = new URL(value); } catch { throw error('invalid_source_url'); }
  const domain = String(verifiedDomain || '').toLowerCase();
  if (!domain || !/^https?:$/.test(url.protocol) || url.username || url.password || url.port || url.search || url.hash ||
      !(url.hostname === domain || url.hostname.endsWith('.' + domain)) || urlIsBlockedTarget(url.href)) throw error('invalid_source_url');
  return url.href;
}
export async function inspectPublicSecrets(text, sourceUrl, { observedAt = new Date().toISOString() } = {}) {
  const findings = [], seen = new Set();
  const bounded = String(text).slice(0, SECRET_CHECK_LIMITS.bytesPerFile);
  for (const rule of RULES) {
    // Use a fresh RegExp; concurrent requests cannot share lastIndex state.
    for (const match of bounded.matchAll(new RegExp(rule.pattern.source, 'g'))) {
      const value = match[0];
      if (!plausible(value)) continue;
      const fingerprint = await digest(value);
      if (seen.has(fingerprint)) continue;
      seen.add(fingerprint);
      findings.push({ rule_id: rule.id, label: rule.label, fingerprint,
        masked_evidence: rule.id === 'private_key' ? '[private key material redacted]' : value.slice(0, 4) + '…' + value.slice(-4),
        source_url: secretSourceUrl(sourceUrl), line: bounded.slice(0, match.index).split('\n').length,
        observed_at: observedAt, status: 'candidate', validity: 'not_tested', compromise: 'not_assessed',
        recommendation: 'Confirm ownership and whether this is a real secret. If real, revoke or rotate it with its provider and remove it from public files and build history.' });
      if (findings.length >= SECRET_CHECK_LIMITS.candidates) return { findings, capped: true };
    }
  }
  return { findings, capped: false };
}
export function linkedSameOriginScripts(html, pageUrl) {
  const urls = [], seen = new Set(); const origin = new URL(pageUrl).origin;
  // Only direct script src attributes, never URLs from strings/comments or a
  // third-party base element. External hosts are intentionally not fetched.
  const markup = html.replace(/<!--[\s\S]*?(?:-->|$)/g, '').replace(/<(textarea|template|noscript|xmp)\b[^>]*>[\s\S]*?(?:<\/\1\s*>|$)/gi, '');
  const pattern = /<script\b((?:"[^"]*"|'[^']*'|[^'">])*)>[\s\S]*?(?:<\/script\s*>|$)/gi;
  for (const tag of markup.matchAll(pattern)) {
    const attrs = new Map();
    for (const attr of tag[1].matchAll(/([^\s=/>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g)) {
      const name = attr[1].toLowerCase(); if (!attrs.has(name)) attrs.set(name, attr[2] ?? attr[3] ?? attr[4] ?? '');
    }
    const src = attrs.get('src'); if (!src || src.length > 2048) continue;
    let url; try { url = new URL(src.replace(/&amp;/g, '&'), pageUrl); } catch { continue; }
    if (url.origin !== origin || url.username || url.password || url.hash || urlIsBlockedTarget(url.href) || seen.has(url.href)) continue;
    seen.add(url.href); urls.push(url.href);
    if (urls.length === 4) break; // one extra detects truncation
  }
  return urls;
}
async function readBoundedText(response) {
  const reader = response.body?.getReader(); if (!reader) throw error('source_unavailable');
  const chunks = []; let size = 0, truncated = false, timer;
  const deadline = new Promise((_, reject) => { timer = setTimeout(() => reject(error('source_timeout')), 2000); });
  try {
    while (true) {
      const { value, done } = await Promise.race([reader.read(), deadline]); if (done) break;
      const remaining = SECRET_CHECK_LIMITS.bytesPerFile - size;
      chunks.push(value.subarray(0, remaining)); size += Math.min(value.byteLength, remaining);
      if (value.byteLength >= remaining) { truncated = true; break; }
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    return { text: new TextDecoder().decode(bytes), truncated };
  } finally { clearTimeout(timer); void reader.cancel().catch(() => {}); reader.releaseLock(); }
}
export async function checkPublicSecretSources(sourceUrl, verifiedDomain, { fetcher = makeSsrfSafeProbeFetch({ resolver: dnsQuery, maxHops: 0, timeoutMs: 4000 }), signal } = {}) {
  const target = validateSecretCheckUrl(sourceUrl, verifiedDomain), origin = new URL(target).origin;
  const observedAt = new Date().toISOString(), controller = new AbortController();
  let timer;
  const deadline = new Promise((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(error('check_timeout')); }, SECRET_CHECK_LIMITS.timeoutMs); });
  const combined = signal ? AbortSignal.any([signal, controller.signal]) : controller.signal;
  const sources = [], findings = []; let truncated = false;
  async function source(url, page) {
    if (combined.aborted) throw error('check_timeout');
    // maxHops=0 means an external redirect is never followed. A caller can
    // explicitly check the final same-domain URL in a subsequent request.
    const response = await fetcher(url, { signal: combined });
    const type = (response?.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
    if (!response || response.status < 200 || response.status >= 300 ||
        (response.url && new URL(response.url).origin !== origin) ||
        !(page ? ['text/html', 'application/javascript', 'text/javascript', 'application/x-javascript', 'text/plain'] : ['application/javascript', 'text/javascript', 'application/x-javascript', 'text/plain']).includes(type)) {
      void response?.body?.cancel().catch(() => {});
      sources.push({ source_url: secretSourceUrl(url), status: 'unavailable', http_status: response?.status ?? null }); return null;
    }
    try {
      const body = await readBoundedText(response);
      const detected = await inspectPublicSecrets(body.text, url, { observedAt });
      findings.push(...detected.findings); truncated ||= body.truncated || detected.capped;
      sources.push({ source_url: secretSourceUrl(url), status: body.truncated ? 'partial' : 'checked', http_status: response.status });
      return { ...body, type };
    } catch {
      sources.push({ source_url: secretSourceUrl(url), status: 'unavailable', http_status: response.status }); return null;
    }
  }
  const operation = (async () => {
    const page = await source(target, true);
    if (page?.type === 'text/html') {
      const scripts = linkedSameOriginScripts(page.text, target); truncated ||= scripts.length > 3;
      for (const url of scripts.slice(0, 3)) await source(url, false);
    }
  })();
  try { await Promise.race([operation, deadline]); }
  catch { truncated = true; }
  finally { clearTimeout(timer); controller.abort(); }
  // Do not return the mutable arrays while a timed-out operation unwinds.
  const evidence = findings.slice(0, SECRET_CHECK_LIMITS.candidates);
  truncated ||= findings.length > evidence.length || sources.some(s => s.status !== 'checked');
  return { schema_version: 'identity_public_secrets.v1', checked_at: observedAt, scope_note: SECRET_CHECK_SCOPE,
    state: evidence.length ? 'candidates_observed' : sources.some(s => s.status === 'checked') ? 'no_candidates_observed' : 'unavailable',
    coverage: truncated ? 'partial' : 'bounded', source_url: secretSourceUrl(target),
    checked_sources: sources.map(s => ({ ...s })), findings: evidence, key_validity: 'not_tested', account_compromise: 'not_assessed' };
}
