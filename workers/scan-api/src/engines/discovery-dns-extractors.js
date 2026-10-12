import { normalizeHostname, classifyHostname, createCandidateCollector } from './hostname-candidates.js';

// Supplied DNS evidence only: these helpers do not resolve names, expand SPF
// macros, evaluate SPF policy, or assert that a candidate is a live service.
export const DISCOVERY_DNS_SOURCES = Object.freeze({ spf: 'spf', cname: 'cname', txt: 'txt' });
export const DISCOVERY_DNS_LIMITS = Object.freeze({
  maxInputBytes: 262144, maxRecords: 500, maxCandidates: 200,
});
const encoder = new TextEncoder();
const inScope = item => item.kind === 'root' || item.kind === 'candidate';

function context(options) {
  const opts = options && typeof options === 'object' ? options : {};
  const collector = createCandidateCollector({ domain: opts.domain, observedAt: opts.observedAt,
    maxInputBytes: DISCOVERY_DNS_LIMITS.maxInputBytes, maxCandidates: DISCOVERY_DNS_LIMITS.maxCandidates });
  return { collector, domain: opts.domain, remaining: DISCOVERY_DNS_LIMITS.maxInputBytes };
}

function list(records, ctx, strings = true) {
  if (strings && typeof records === 'string') return [records];
  if (!Array.isArray(records)) { ctx.collector.reject(); return []; }
  const cap = DISCOVERY_DNS_LIMITS.maxRecords;
  if (records.length > cap) ctx.collector.truncate(records.length - cap);
  return records.slice(0, cap);
}

// Each record is atomic. On a byte overflow, omit it and all later records;
// truncating a hostname prefix could turn an external name into an in-scope one.
// Only parsed string fields count toward the shared UTF-8 input budget.
function consume(values, ctx) {
  let size = 0;
  for (const value of values) {
    const remaining = ctx.remaining - size;
    if (value.length > remaining) return false;
    const bytes = encoder.encode(value).length;
    if (bytes > remaining) return false;
    size += bytes;
  }
  ctx.remaining -= size;
  return true;
}

function hostnameOperand(value, ctx, source) {
  // Shared normalization is intentionally host-only: service labels containing
  // underscores, wildcards, IP literals, URLs and macro syntax are not hosts.
  const hostname = normalizeHostname(value);
  if (!hostname) { ctx.collector.reject(); return; }
  ctx.collector.add(hostname, source);
}

function spfOperand(token) {
  // RFC 7208 sections 5/6/12. The modifier redirect has no qualifier; mechanisms
  // may have one. This is a conservative operand reader, not an SPF validator.
  if (token.includes('%')) return null;
  const redirect = /^redirect=(.+)$/i.exec(token);
  if (redirect) return redirect[1];
  const mechanism = /^[+?~-]?(include|a|mx):(.+)$/i.exec(token);
  if (!mechanism) return null;
  const value = mechanism[2];
  if (mechanism[1].toLowerCase() === 'include') return value;
  const slash = value.indexOf('/');
  if (slash < 0) return value;
  const suffix = value.slice(slash);
  const cidrs = /^(?:\/(0|[1-9][0-9]?))?(?:\/\/(0|[1-9][0-9]{0,2}))?$/.exec(suffix);
  if (!cidrs || (cidrs[1] !== undefined && Number(cidrs[1]) > 32)
    || (cidrs[2] !== undefined && Number(cidrs[2]) > 128)) return null;
  return value.slice(0, slash);
}

// A string is one already-assembled TXT record; an array is separate records,
// not chunks to concatenate. Callers must assemble DNS character-strings first.
export function extractFromSpfRecords(records, options = {}) {
  const ctx = context(options), rows = list(records, ctx);
  for (let i = 0; i < rows.length; i++) {
    const record = rows[i];
    if (typeof record !== 'string') { ctx.collector.reject(); continue; }
    if (!consume([record], ctx)) { ctx.collector.truncate(rows.length - i); break; }
    const text = record.trim();
    if (!/^v=spf1(?: |$)/i.test(text)) continue;
    // SPF terms are separated by ASCII SP; controls are not DNS presentation
    // escapes and cannot be used to split an otherwise invalid operand.
    if (/[\u0000-\u001f\u007f]/u.test(text)) { ctx.collector.reject(); continue; }
    for (const token of text.split(/ +/).slice(1)) {
      const operand = spfOperand(token);
      if (operand !== null) hostnameOperand(operand, ctx, DISCOVERY_DNS_SOURCES.spf);
    }
  }
  return ctx.collector.result();
}

// Count cyclic strongly connected components (including self-loops) of the
// supplied in-scope graph. The record cap bounds nodes and DFS depth to <= 1000.
// A nonzero count describes these observations, not the current DNS state.
function countLoops(graph) {
  const index = new Map(), low = new Map(), stack = [], active = new Set();
  let serial = 0, loops = 0;
  function visit(node) {
    index.set(node, serial); low.set(node, serial++); stack.push(node); active.add(node);
    for (const next of graph.get(node) || []) {
      if (!index.has(next)) { visit(next); low.set(node, Math.min(low.get(node), low.get(next))); }
      else if (active.has(next)) low.set(node, Math.min(low.get(node), index.get(next)));
    }
    if (low.get(node) !== index.get(node)) return;
    let size = 0, member;
    do { member = stack.pop(); active.delete(member); size++; } while (member !== node);
    if (size > 1 || graph.get(node)?.has(node)) loops++;
  }
  for (const node of graph.keys()) if (!index.has(node)) visit(node);
  return loops;
}

// Accepted rows: { name, value } or { name, target }, using bare DNS names.
// An out-of-scope owner never licenses its in-scope target as evidence. Owners
// and targets in valid observed chains are retained; no chain is followed online.
export function extractFromCnameRecords(records, options = {}) {
  const ctx = context(options), rows = list(records, ctx, false), graph = new Map();
  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    if (!row || typeof row !== 'object' || Array.isArray(row)) { ctx.collector.reject(); continue; }
    const values = [row.name];
    if (row.value !== undefined) values.push(row.value);
    if (row.target !== undefined) values.push(row.target);
    if (values.length < 2 || values.some(value => typeof value !== 'string')) { ctx.collector.reject(); continue; }
    if (!consume(values, ctx)) { ctx.collector.truncate(rows.length - i); break; }
    const owner = classifyHostname(row.name, ctx.domain);
    if (!inScope(owner)) {
      if (owner.kind === 'out_of_scope') ctx.collector.add(row.name, DISCOVERY_DNS_SOURCES.cname);
      else ctx.collector.reject();
      continue;
    }
    const target = normalizeHostname(row.value ?? row.target);
    if (!target || (row.value !== undefined && row.target !== undefined && normalizeHostname(row.target) !== target)) {
      ctx.collector.reject(); continue;
    }
    ctx.collector.add(owner.hostname, DISCOVERY_DNS_SOURCES.cname);
    ctx.collector.add(target, DISCOVERY_DNS_SOURCES.cname);
    if (!inScope(classifyHostname(target, ctx.domain))) continue;
    if (!graph.has(owner.hostname)) graph.set(owner.hostname, new Set());
    graph.get(owner.hostname).add(target);
  }
  const cname_loop_count = countLoops(graph);
  return { ...ctx.collector.result(), cname_loop_count };
}

function addTxtUrl(value, ctx) {
  // Require an explicit unrepaired authority. Do not accept userinfo, escapes,
  // wildcard hosts, protocol-relative URLs or whitespace/control repair by URL.
  const match = /^(?:https?|wss?):\/\/([^/?#]+)(?:[/?#].*)?$/i.exec(value);
  if (!match || /[\s\u0000-\u001f\u007f\\]/u.test(value)) { ctx.collector.reject(); return; }
  const authority = /^([^:@%*]+)(?::[0-9]{1,5})?$/.exec(match[1]);
  if (!authority || !normalizeHostname(authority[1])) { ctx.collector.reject(); return; }
  try {
    const url = new URL(value);
    if (url.username || url.password) { ctx.collector.reject(); return; }
    ctx.collector.add(url.hostname, DISCOVERY_DNS_SOURCES.txt);
  } catch { ctx.collector.reject(); }
}

function txtFields(record) {
  const fields = [];
  let start = 0, quote = null;
  for (let i = 0; i < record.length; i++) {
    const char = record[i];
    if (quote) {
      if (char === '\\') i++;
      else if (char === quote) quote = null;
    } else if (char === '"' || char === "'") quote = char;
    else if (char === ';' || char === '\r' || char === '\n') { fields.push(record.slice(start, i)); start = i + 1; }
  }
  if (!quote) fields.push(record.slice(start));
  return fields;
}

// Conservative TXT grammar, applied to semicolon/newline fields outside quotes:
//   absolute http(s)/ws(s) URL as the entire field; OR
//   domain=<bare hostname>, hostname=<bare hostname>; OR
//   url=<absolute URL>, uri=<absolute URL>.
// Keys are case-insensitive. A whole value may be single/double quoted. We do
// not search prose, JSON, arbitrary key values, token strings or bare hostnames.
// Thus site-verification=api.example.com is never hostname evidence.
export function extractFromTxtRecords(records, options = {}) {
  const ctx = context(options), rows = list(records, ctx);
  for (let i = 0; i < rows.length; i++) {
    const record = rows[i];
    if (typeof record !== 'string') { ctx.collector.reject(); continue; }
    if (!consume([record], ctx)) { ctx.collector.truncate(rows.length - i); break; }
    for (const field of txtFields(record)) {
      const text = field.trim();
      const pair = /^(domain|hostname|url|uri)\s*=\s*(.*)$/i.exec(text);
      let value = pair ? pair[2] : text;
      if (value.length >= 2 && ((value[0] === '"' && value.at(-1) === '"') || (value[0] === "'" && value.at(-1) === "'"))) value = value.slice(1, -1);
      if (pair && /^(?:domain|hostname)$/i.test(pair[1])) hostnameOperand(value, ctx, DISCOVERY_DNS_SOURCES.txt);
      else if (pair || /^(?:https?|wss?):\/\//i.test(value)) addTxtUrl(value, ctx);
    }
  }
  return ctx.collector.result();
}
