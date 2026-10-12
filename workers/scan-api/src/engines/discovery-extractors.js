import { normalizeHostname, classifyHostname, createCandidateCollector, HOSTNAME_CANDIDATE_SOURCES } from './hostname-candidates.js';
import { NSEC_WALK_SOURCE } from './nsec-walk.js';

// These parsers only inspect supplied evidence. Their output never grants permission
// to connect to a host or proves that a service is reachable.
export const DISCOVERY_EXTRACTOR_SOURCES = Object.freeze(Object.fromEntries([
  'robots_txt', 'sitemap', 'javascript', 'link_header', 'cors_header', 'mta_sts',
  'bimi', 'dmarc', 'redirect_chain', 'security_txt', 'ptr',
].map(key => [key, key])));
export const DISCOVERY_EXTRACTOR_LIMITS = Object.freeze({
  maxInputBytes: 262144, maxCandidates: 200, maxUrls: 5, maxListItems: 500,
});
const SOURCES = new Set([...Object.values(DISCOVERY_EXTRACTOR_SOURCES), ...Object.values(HOSTNAME_CANDIDATE_SOURCES), NSEC_WALK_SOURCE]);
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const OPTIONS = value => value && typeof value === 'object' ? value : {};

function context(options) {
  const { domain, observedAt = null } = OPTIONS(options);
  const collector = createCandidateCollector({ domain, observedAt,
    maxCandidates: DISCOVERY_EXTRACTOR_LIMITS.maxCandidates,
    maxInputBytes: DISCOVERY_EXTRACTOR_LIMITS.maxInputBytes,
    maxListItems: DISCOVERY_EXTRACTOR_LIMITS.maxListItems });
  return { domain, collector };
}

function boundedText(value, collector, retainPrefix = false) {
  if (typeof value !== 'string') { collector.reject(); return ''; }
  const cap = DISCOVERY_EXTRACTOR_LIMITS.maxInputBytes;
  // A UTF-16 prefix of cap code units is enough to determine the UTF-8 bound,
  // without encoding an unbounded caller-owned string.
  const bytes = encoder.encode(value.slice(0, cap));
  if (value.length > cap || bytes.length > cap) {
    collector.truncate();
    // A truncated token can turn an external hostname into an in-scope one.
    // Reject the whole oversized document; XML alone inspects the prefix only
    // for prohibited declarations and never extracts evidence from it.
    if (!retainPrefix) return '';
  }
  return decoder.decode(bytes.subarray(0, cap));
}

function urlValue(raw, baseUrl, relative = false) {
  if (typeof raw !== 'string') return null;
  const value = raw.trim();
  if (!value || /[\s\u0000-\u001f\u007f\\]/u.test(value)) return null;
  if (!relative && !/^(?:https?|wss?):\/\//i.test(value)) return null;
  try {
    const url = relative ? new URL(value, baseUrl) : new URL(value);
    if (!['http:', 'https:', 'ws:', 'wss:'].includes(url.protocol) || url.username || url.password) return null;
    if (!normalizeHostname(url.hostname)) return null;
    url.hash = '';
    return url;
  } catch { return null; }
}

function addUrl(raw, source, ctx, baseUrl, relative = false) {
  const url = urlValue(raw, baseUrl, relative);
  if (!url) { ctx.collector.reject(); return null; }
  ctx.collector.add(url.hostname, source);
  return url;
}

function addListedUrl(url, list, ctx) {
  if (!url || !['http:', 'https:'].includes(url.protocol)) return;
  const classification = classifyHostname(url.hostname, ctx.domain);
  if (!['root', 'candidate'].includes(classification.kind) || list.includes(url.href)) return;
  if (list.length >= DISCOVERY_EXTRACTOR_LIMITS.maxUrls) { ctx.collector.truncate(); return; }
  list.push(url.href);
}

function xmlText(value) {
  return value.replace(/&(?:amp|quot|apos|lt|gt);|&#(?:\d{1,7}|x[\da-f]{1,6});/gi, token => {
    const basic = { '&amp;': '&', '&quot;': '"', '&apos;': "'", '&lt;': '<', '&gt;': '>' };
    if (basic[token]) return basic[token];
    const hex = /^&#x/i.test(token);
    const code = Number.parseInt(token.slice(hex ? 3 : 2, -1), hex ? 16 : 10);
    return code > 0 && code <= 0x10ffff && !(code >= 0xd800 && code <= 0xdfff) ? String.fromCodePoint(code) : '';
  });
}

function attributes(tag) {
  const attrs = new Map();
  const pattern = /(?:^|\s)([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g;
  for (const match of tag.matchAll(pattern)) {
    const name = match[1].toLowerCase();
    if (!attrs.has(name)) attrs.set(name, xmlText(match[2] ?? match[3] ?? match[4]));
  }
  return attrs;
}

export function extractFromRobotsTxt(text, options = {}) {
  const ctx = context(options), sitemap_urls = [];
  for (const line of boundedText(text, ctx.collector).split(/\r?\n/)) {
    const match = /^\s*(sitemap|allow|disallow)\s*:\s*(\S+)/i.exec(line);
    if (!match || !/^https?:\/\//i.test(match[2])) continue;
    const url = addUrl(match[2], 'robots_txt', ctx);
    if (match[1].toLowerCase() === 'sitemap') addListedUrl(url, sitemap_urls, ctx);
  }
  return { ...ctx.collector.result(), sitemap_urls };
}

export function extractFromSitemapXml(text, options = {}) {
  const ctx = context(options), sitemap_urls = [];
  let xml = boundedText(text, ctx.collector, true);
  if (/<!\s*(?:DOCTYPE|ENTITY)\b/i.test(xml)) {
    ctx.collector.reject();
    return { ...ctx.collector.result(), sitemap_urls, rejected_reason: 'xml_doctype' };
  }
  // Do not interpret a partial XML document: a declaration may be beyond the
  // input bound, and an incomplete prefix cannot prove its absence.
  if (ctx.collector.result().truncated) return { ...ctx.collector.result(), sitemap_urls };
  xml = xml.replace(/<!--[\s\S]*?(?:-->|$)/g, '');
  const index = /<(?:[\w-]+:)?sitemapindex\b/i.test(xml);
  for (const match of xml.matchAll(/<(?:[\w-]+:)?loc\b[^>]*>([^<]*)<\/(?:[\w-]+:)?loc\s*>/gi)) {
    const url = addUrl(xmlText(match[1].trim()), 'sitemap', ctx);
    if (index) addListedUrl(url, sitemap_urls, ctx);
  }
  for (const match of xml.matchAll(/<xhtml:link\b[^>]*>/gi)) {
    const href = attributes(match[0]).get('href');
    if (href !== undefined) addUrl(href, 'sitemap', ctx);
  }
  return { ...ctx.collector.result(), sitemap_urls };
}

function readQuoted(text, start) {
  const quote = text[start];
  let value = '', valid = true, i = start + 1;
  for (; i < text.length; i++) {
    const char = text[i];
    if (char === quote) return { value, end: i + 1, valid };
    if (char === '\n' || char === '\r') return { value: '', end: i + 1, valid: false };
    if (char !== '\\') { value += char; continue; }
    const next = text[++i];
    if (next === undefined) break;
    if (next === '\n') continue;
    if (next === '\r') { if (text[i + 1] === '\n') i++; continue; }
    if (next === 'x' || next === 'u') {
      const length = next === 'x' ? 2 : 4;
      const hex = text.slice(i + 1, i + length + 1);
      if (hex.length !== length || !/^[\da-f]+$/i.test(hex)) { valid = false; continue; }
      value += String.fromCharCode(Number.parseInt(hex, 16)); i += length;
    } else {
      const escapes = { n: '\n', r: '\r', t: '\t', b: '\b', f: '\f', v: '\v', '0': '\0' };
      value += escapes[next] ?? next;
    }
  }
  return { value: '', end: i, valid: false };
}

function skipTemplate(text, start) {
  const stack = [{ kind: 'template' }];
  let i = start + 1;
  while (i < text.length && stack.length) {
    const frame = stack[stack.length - 1], c = text[i], n = text[i + 1];
    if (frame.kind === 'template') {
      if (c === '\\') { i += 2; continue; }
      if (c === '`') { stack.pop(); i++; continue; }
      if (c === '$' && n === '{') { stack.push({ kind: 'expression', depth: 1, expressionStart: true }); i += 2; continue; }
      i++; continue;
    }
    if (/\s/.test(c)) { i++; continue; }
    if (c === '/' && n === '/') { const end = text.indexOf('\n', i + 2); i = end < 0 ? text.length : end + 1; continue; }
    if (c === '/' && n === '*') { const end = text.indexOf('*/', i + 2); i = end < 0 ? text.length : end + 2; continue; }
    if (c === '"' || c === "'") { i = readQuoted(text, i).end; frame.expressionStart = false; continue; }
    if (c === '`') { stack.push({ kind: 'template' }); frame.expressionStart = false; i++; continue; }
    if (c === '/' && frame.expressionStart) {
      let inClass = false; i++;
      while (i < text.length) {
        if (text[i] === '\\') { i += 2; continue; }
        if (text[i] === '\n' || text[i] === '\r') break;
        if (text[i] === '[') inClass = true;
        if (text[i] === ']') inClass = false;
        if (text[i++] === '/' && !inClass) break;
      }
      frame.expressionStart = false; continue;
    }
    if (c === '{') frame.depth++;
    if (c === '}' && --frame.depth === 0) { stack.pop(); i++; continue; }
    // The decrement applies only to a closing brace; other characters do not
    // change interpolation depth. No expression in a template is a literal.
    frame.expressionStart = /[=([{,:;!?&|+*%^~<>-]/.test(c);
    i++;
  }
  return i;
}

// This small lexer extracts string literals and skips comments, templates and
// regular-expression bodies. It intentionally does not interpret expressions.
function *quotedValues(text) {
  let i = 0, expressionStart = true, lastWord = '';
  const parentheses = [];
  while (i < text.length) {
    const c = text[i], n = text[i + 1];
    if (/\s/.test(c)) { i++; continue; }
    if (n === '/' && c === '/') { const end = text.indexOf('\n', i + 2); i = end < 0 ? text.length : end + 1; continue; }
    if (c === '/' && n === '*') { const end = text.indexOf('*/', i + 2); i = end < 0 ? text.length : end + 2; continue; }
    if (c === '"' || c === "'") {
      const literal = readQuoted(text, i); i = literal.end;
      if (literal.valid) yield literal.value;
      expressionStart = false; continue;
    }
    if (c === '`') {
      i = skipTemplate(text, i);
      expressionStart = false; continue;
    }
    if (c === '/' && expressionStart) {
      let inClass = false; i++;
      while (i < text.length) {
        if (text[i] === '\\') { i += 2; continue; }
        if (text[i] === '\n' || text[i] === '\r') break;
        if (text[i] === '[') inClass = true;
        if (text[i] === ']') inClass = false;
        if (text[i++] === '/' && !inClass) break;
      }
      while (/[a-z]/i.test(text[i] ?? '') && i < text.length) i++;
      expressionStart = false; continue;
    }
    if (/[\w$]/.test(c)) {
      const start = i++;
      while (i < text.length && /[\w$]/.test(text[i])) i++;
      lastWord = text.slice(start, i);
      expressionStart = /^(?:return|throw|case|delete|void|typeof|yield|await|new|in|of|else|do)$/.test(lastWord);
      continue;
    }
    if (c === '(') { parentheses.push(/^(?:if|while|for|with|switch|catch)$/.test(lastWord)); expressionStart = true; }
    else if (c === ')') expressionStart = parentheses.pop() === true;
    else expressionStart = /[=\[{},:;!?&|+*%^~<>-]/.test(c);
    lastWord = ''; i++;
  }
}

export function extractFromJavaScript(text, options = {}) {
  const ctx = context(options);
  for (const value of quotedValues(boundedText(text, ctx.collector))) {
    if (/^(?:https?|wss?):\/\//i.test(value)) addUrl(value, 'javascript', ctx);
    else if (value.includes('.') && !/[\s/:@]/.test(value)) ctx.collector.add(value, 'javascript');
  }
  return ctx.collector.result();
}

export function scriptSrcs(html, baseUrl, domain) {
  const ctx = context({ domain }), script_urls = [];
  const text = boundedText(html, ctx.collector);
  // Walk complete tags while respecting outer attribute quotes; script-looking
  // text inside an attribute, comment or raw-text element is not markup.
  let cursor = 0;
  const opening = /<([a-z][a-z0-9:-]*)\b/igy;
  while (cursor < text.length) {
    const start = text.indexOf('<', cursor);
    if (start < 0) break;
    if (text.startsWith('<!--', start)) { const end = text.indexOf('-->', start + 4); cursor = end < 0 ? text.length : end + 3; continue; }
    opening.lastIndex = start;
    const match = opening.exec(text);
    let end = start + 1, quote = '';
    for (; end < text.length; end++) {
      if (quote) { if (text[end] === quote) quote = ''; }
      else if (text[end] === '"' || text[end] === "'") quote = text[end];
      else if (text[end] === '>') break;
    }
    if (end === text.length) break;
    cursor = end + 1;
    if (!match) continue;
    const tagName = match[1].toLowerCase();
    if (['script', 'style', 'textarea', 'title'].includes(tagName)) {
      const closing = new RegExp(`<\\/${tagName}\\s*>`, 'ig');
      closing.lastIndex = cursor;
      const close = closing.exec(text);
      cursor = close ? closing.lastIndex : text.length;
    }
    if (tagName !== 'script') continue;
    const src = attributes(text.slice(opening.lastIndex, end)).get('src');
    if (src === undefined) continue;
    const url = addUrl(src, 'javascript', ctx, baseUrl, true);
    addListedUrl(url, script_urls, ctx);
  }
  return { ...ctx.collector.result(), script_urls };
}

export function extractFromLinkHeader(value, options = {}) {
  const ctx = context(options), { baseUrl } = OPTIONS(options);
  const text = boundedText(value, ctx.collector);
  // Quoted parameter values may contain angle brackets; only a link-value target
  // beginning the field or following an unquoted comma is a reference.
  let quoted = false, escaped = false, expecting = true;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (escaped) { escaped = false; continue; }
    if (quoted && c === '\\') { escaped = true; continue; }
    if (c === '"') { quoted = !quoted; continue; }
    if (quoted) continue;
    if (c === ',') { expecting = true; continue; }
    if (expecting && /\s/.test(c)) continue;
    if (expecting && c === '<') {
      const end = text.indexOf('>', i + 1);
      if (end < 0) { ctx.collector.reject(); break; }
      addUrl(text.slice(i + 1, end), 'link_header', ctx, baseUrl, true); i = end;
    }
    expecting = false;
  }
  return ctx.collector.result();
}

export function extractFromCorsHeader(value, options = {}) {
  const ctx = context(options), text = boundedText(value, ctx.collector).trim();
  if (!text || text === '*' || text === 'null') return ctx.collector.result();
  const url = urlValue(text);
  if (!url || !['http:', 'https:'].includes(url.protocol) || url.origin !== text) ctx.collector.reject();
  else ctx.collector.add(url.hostname, 'cors_header');
  return ctx.collector.result();
}

export function extractFromMtaStsPolicy(text, options = {}) {
  const ctx = context(options);
  for (const line of boundedText(text, ctx.collector).split(/\r?\n/)) {
    const match = /^\s*mx\s*:\s*(.*?)\s*$/i.exec(line);
    if (match) ctx.collector.add(match[1], 'mta_sts');
  }
  return ctx.collector.result();
}

function tags(text) {
  return text.split(';').map(part => /^\s*([a-z]+)\s*=\s*(.*?)\s*$/i.exec(part)).filter(Boolean);
}

export function extractFromBimiRecord(txt, options = {}) {
  const ctx = context(options);
  for (const match of tags(boundedText(txt, ctx.collector))) {
    if (/^(?:l|a)$/i.test(match[1]) && match[2]) addUrl(match[2], 'bimi', ctx);
  }
  return ctx.collector.result();
}

function addMailOrUrl(raw, source, ctx) {
  if (/^mailto:/i.test(raw)) {
    const mailbox = raw.slice(7).split('?')[0];
    const match = /^[^\s@,<>]+@([^\s@,<>]+)$/.exec(mailbox);
    if (match) ctx.collector.add(match[1], source); else ctx.collector.reject();
  } else addUrl(raw, source, ctx);
}

export function extractFromDmarcRecord(txt, options = {}) {
  const ctx = context(options);
  for (const match of tags(boundedText(txt, ctx.collector))) {
    if (!/^(?:rua|ruf)$/i.test(match[1])) continue;
    for (const raw of match[2].split(',')) addMailOrUrl(raw.trim().replace(/!\d+[kmgt]?$/i, ''), 'dmarc', ctx);
  }
  return ctx.collector.result();
}

export function extractFromRedirectChain(chain, options = {}) {
  const ctx = context(options);
  if (!Array.isArray(chain)) { ctx.collector.reject(); return ctx.collector.result(); }
  const cap = DISCOVERY_EXTRACTOR_LIMITS.maxListItems;
  if (chain.length > cap) ctx.collector.truncate(chain.length - cap);
  let bytesLeft = DISCOVERY_EXTRACTOR_LIMITS.maxInputBytes;
  for (const entry of chain.slice(0, cap)) {
    if (!entry || typeof entry !== 'object') { ctx.collector.reject(); continue; }
    for (const key of ['from', 'to']) {
      const value = entry[key];
      if (typeof value !== 'string') { ctx.collector.reject(); continue; }
      const bytes = encoder.encode(value.slice(0, bytesLeft + 1)).length;
      if (value.length > bytesLeft || bytes > bytesLeft) { ctx.collector.truncate(); bytesLeft = 0; break; }
      bytesLeft -= bytes; addUrl(value, 'redirect_chain', ctx);
    }
    if (bytesLeft <= 0) break;
  }
  return ctx.collector.result();
}

export function extractFromSecurityTxt(text, options = {}) {
  const ctx = context(options);
  for (const line of boundedText(text, ctx.collector).split(/\r?\n/)) {
    const match = /^\s*(?:Contact|Policy|Hiring|Canonical|Encryption)\s*:\s*(\S+)/i.exec(line);
    if (match) addMailOrUrl(match[1], 'security_txt', ctx);
  }
  return ctx.collector.result();
}

export function extractFromPtrNames(names, options = {}) {
  const ctx = context(options);
  if (!Array.isArray(names)) { ctx.collector.reject(); return ctx.collector.result(); }
  const cap = DISCOVERY_EXTRACTOR_LIMITS.maxListItems;
  if (names.length > cap) ctx.collector.truncate(names.length - cap);
  let bytesLeft = DISCOVERY_EXTRACTOR_LIMITS.maxInputBytes;
  for (const name of names.slice(0, cap)) {
    if (typeof name !== 'string') { ctx.collector.reject(); continue; }
    const bytes = encoder.encode(name.slice(0, bytesLeft + 1)).length;
    if (name.length > bytesLeft || bytes > bytesLeft) { ctx.collector.truncate(); break; }
    bytesLeft -= bytes; ctx.collector.add(name, 'ptr');
  }
  return ctx.collector.result();
}

export function mergeCandidateSets(...sets) {
  // Inputs are candidate sets already scoped by their extractors. This merger
  // is not an authorization boundary; it does not grant a new scanning scope.
  const merged = new Map(), wildcards = new Set();
  let rejected_count = 0, out_of_scope_count = 0, truncated_count = 0, truncated = false;
  const count = value => Number.isSafeInteger(value) && value >= 0 ? value : 0;
  const cap = DISCOVERY_EXTRACTOR_LIMITS.maxListItems;
  let bytesLeft = DISCOVERY_EXTRACTOR_LIMITS.maxInputBytes;
  const consume = value => {
    if (typeof value !== 'string') return true;
    const bytes = encoder.encode(value.slice(0, bytesLeft + 1)).length;
    if (value.length > bytesLeft || bytes > bytesLeft) { truncated = true; truncated_count++; return false; }
    bytesLeft -= bytes;
    return true;
  };
  if (sets.length > cap) { truncated = true; truncated_count += sets.length - cap; }
  for (const set of sets.slice(0, cap)) {
    if (!set || typeof set !== 'object') { rejected_count++; continue; }
    rejected_count += count(set.rejected_count); out_of_scope_count += count(set.out_of_scope_count);
    truncated_count += count(set.truncated_count); truncated ||= set.truncated === true;
    const candidates = Array.isArray(set.candidates) ? set.candidates : [];
    if (candidates.length > cap) { truncated = true; truncated_count += candidates.length - cap; }
    for (const candidate of candidates.slice(0, cap)) {
      if (!consume(candidate?.hostname)) continue;
      const hostname = normalizeHostname(candidate?.hostname);
      if (!hostname) { rejected_count++; continue; }
      const sources = Array.isArray(candidate.sources) ? candidate.sources.slice(0, cap).filter(source => consume(source) && SOURCES.has(source)) : [];
      if (!sources.length) { rejected_count++; continue; }
      if (!merged.has(hostname)) {
        if (merged.size >= DISCOVERY_EXTRACTOR_LIMITS.maxCandidates) { truncated = true; truncated_count++; continue; }
        merged.set(hostname, new Set());
      }
      for (const source of sources) merged.get(hostname).add(source);
    }
    const scopes = Array.isArray(set.wildcard_scopes) ? set.wildcard_scopes : [];
    if (scopes.length > cap) { truncated = true; truncated_count += scopes.length - cap; }
    for (const raw of scopes.slice(0, cap)) {
      if (!consume(raw)) continue;
      const scope = normalizeHostname(typeof raw === 'string' ? raw.replace(/^\*\./, '') : raw);
      if (!scope) { rejected_count++; continue; }
      if (wildcards.size < DISCOVERY_EXTRACTOR_LIMITS.maxCandidates || wildcards.has(scope)) wildcards.add(scope);
      else { truncated = true; truncated_count++; }
    }
  }
  return {
    candidates: [...merged].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([hostname, sources]) => ({ hostname, sources: [...sources].sort() })),
    wildcard_scopes: [...wildcards].sort(), out_of_scope_count, rejected_count,
    truncated: truncated || truncated_count > 0, truncated_count,
  };
}
