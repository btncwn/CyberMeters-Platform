import { normalizeHostname } from './hostname-candidates.js';

// Supplied DoH JSON only. This module does not issue queries or infer ownership,
// service reachability, DNSSEC deployment, or health from a DNS observation.
export const DISCOVERY_DNS_LIMITS = Object.freeze({
  maxObservations: 256,
  maxRecords: 256,
  maxStringBytes: 4_096,
  maxInputBytes: 65_536,
  maxObservedAtBytes: 128,
  maxCnameHops: 16,
});
export const DISCOVERY_DNS_RECORD_TYPES = Object.freeze({ A: 1, CNAME: 5, MX: 15, TXT: 16, AAAA: 28 });
export const DISCOVERY_DNS_OUTCOMES = Object.freeze([
  'answer', 'nxdomain', 'nodata', 'servfail', 'refused', 'timeout',
  'transport_error', 'invalid_response', 'cname_only', 'referral', 'truncated', 'dns_error',
]);
const VERSION = 'discovery-dns-observation-v1';
const encoder = new TextEncoder();
const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);

// Only own data fields are evidence. Getters and inherited fields cannot forge
// resolver data or execute while normalising ordinary caller-owned objects.
function field(value, key) {
  if (value == null) return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor && !Object.hasOwn(descriptor, 'value')) throw new Error('accessor');
  return descriptor?.value;
}

function typeCode(value) {
  if (typeof value === 'string') {
    if (value.length > 16) return null;
    const upper = value.toUpperCase();
    const known = Object.hasOwn(DISCOVERY_DNS_RECORD_TYPES, upper)
      ? DISCOVERY_DNS_RECORD_TYPES[upper] : ({ NS: 2, SOA: 6, RRSIG: 46 })[upper];
    if (typeof known === 'number') return known;
    if (!/^\d{1,5}$/.test(value)) return null;
    value = Number(value);
  }
  return Number.isInteger(value) && value > 0 && value <= 65_535 ? value : null;
}
const typeName = code => Object.keys(DISCOVERY_DNS_RECORD_TYPES).find(key => DISCOVERY_DNS_RECORD_TYPES[key] === code) ?? null;

function byteLength(value, limit) {
  return value.length > limit ? limit + 1 : encoder.encode(value).length;
}
function inputText(value, state, cap = DISCOVERY_DNS_LIMITS.maxStringBytes) {
  if (typeof value !== 'string') throw new Error('invalid_string');
  const size = byteLength(value, cap);
  if (size > cap) { state.truncation_reasons.add('string_bytes'); return null; }
  state.bytes += size;
  if (state.bytes > DISCOVERY_DNS_LIMITS.maxInputBytes) {
    state.truncation_reasons.add('input_bytes'); return null;
  }
  return value;
}

function address(data, type) {
  if (type === 'A') {
    return /^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(data)
      && data.split('.').every(part => Number(part) <= 255) ? data : null;
  }
  if (!data.includes(':') || !/^[\da-f:.]+$/i.test(data)) return null;
  try { return new URL(`http://[${data}]/`).hostname.slice(1, -1); } catch { return null; }
}

function record(value, state) {
  if (!object(value)) throw new Error('invalid_record');
  const rawName = inputText(field(value, 'name'), state);
  const rawData = inputText(field(value, 'data'), state);
  if (rawName === null || rawData === null) return null;
  const name = rawName === '.' ? '.' : normalizeHostname(rawName);
  const code = typeCode(field(value, 'type'));
  const ttl = field(value, 'TTL');
  if (!name || !code || (ttl !== undefined && (!Number.isInteger(ttl) || ttl < 0 || ttl > 0xffff_ffff))) {
    throw new Error('invalid_record');
  }
  const type = typeName(code);
  let data = rawData;
  if (type === 'A' || type === 'AAAA') data = address(rawData, type);
  if (type === 'CNAME') data = normalizeHostname(rawData);
  if (type === 'MX') {
    const match = /^(\d{1,5})\s+(\S+)$/.exec(rawData.trim());
    const target = match && (match[2] === '.' ? '.' : normalizeHostname(match[2]));
    data = match && Number(match[1]) <= 65_535 && target && (target !== '.' || Number(match[1]) === 0)
      ? `${Number(match[1])} ${target}` : null;
  }
  // TXT remains the resolver's presentation string, not a parsed SPF/DMARC claim.
  if (type === 'TXT' && /[\u0000\r\n]/.test(rawData)) data = null;
  if (data === null || data === false) throw new Error('invalid_record_data');
  return { name, type: type ?? code, data, ttl: ttl ?? null };
}

function section(value, state) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new Error('invalid_section');
  const available = Math.max(0, DISCOVERY_DNS_LIMITS.maxRecords - state.records);
  if (value.length > available) state.truncation_reasons.add('record_count');
  const records = [];
  for (let i = 0; i < Math.min(value.length, available); i++) {
    state.records++;
    const parsed = record(field(value, String(i)), state);
    if (parsed) records.push(parsed);
  }
  return records;
}

function errorOutcome(error) {
  let name = object(error) ? field(error, 'name') : null;
  // AbortSignal.timeout supplies a DOMException with a native inherited getter.
  if (typeof DOMException !== 'undefined' && error instanceof DOMException) {
    name = Object.getOwnPropertyDescriptor(DOMException.prototype, 'name').get.call(error);
  }
  const code = object(error) ? field(error, 'code') : null;
  const outcome = object(error) ? field(error, 'outcome') : error;
  return name === 'TimeoutError' || code === 'ETIMEDOUT' || code === 'UND_ERR_CONNECT_TIMEOUT' || outcome === 'timeout'
    ? 'timeout' : 'transport_error';
}

/**
 * Accept {hostname, recordType, response, error, observedAt}. recordType is one
 * of A/AAAA/CNAME/MX/TXT, a numeric code, or its decimal string. observedAt is
 * caller-supplied; null means not supplied. Missing DoH Answer means empty, as
 * permitted by the JSON API. TC, local bounds, malformed records and unresolved
 * aliases cannot become negative address evidence. AD describes only the
 * resolver's authentication bit; absent AD is unknown, never DNSSEC disabled.
 */
export function classifyDiscoveryDnsResponse(input = {}) {
  const result = {
    version: VERSION, hostname: null, record_type: null, observed_at: null,
    outcome: 'invalid_response', reason: 'invalid_input', rcode: null,
    records: [], cname_chain: [], dns_address_resolved: null,
    dnssec_authenticated: null, complete: false, truncated: false, truncation_reasons: [],
  };
  const state = { bytes: 0, records: 0, truncation_reasons: new Set() };
  const finish = (outcome, reason = null) => {
    result.truncation_reasons = [...state.truncation_reasons].sort(compare);
    result.truncated = result.truncation_reasons.length > 0;
    result.outcome = result.truncated && outcome !== 'invalid_response' ? 'truncated' : outcome;
    result.reason = reason;
    result.complete = !result.truncated && ['answer', 'nxdomain', 'nodata', 'servfail', 'refused', 'dns_error'].includes(result.outcome);
    if (result.record_type === 'A' || result.record_type === 'AAAA') {
      result.dns_address_resolved = result.outcome === 'answer' ? true
        : ['nxdomain', 'nodata'].includes(result.outcome) ? false : null;
    }
    return result;
  };
  try {
    if (!object(input)) return finish('invalid_response', 'invalid_input');
    const rawHostname = inputText(field(input, 'hostname'), state);
    result.hostname = normalizeHostname(rawHostname);
    result.record_type = typeName(typeCode(field(input, 'recordType')));
    const timestamp = field(input, 'observedAt');
    if (timestamp !== undefined && timestamp !== null) result.observed_at = inputText(timestamp, state, DISCOVERY_DNS_LIMITS.maxObservedAtBytes);
    if (state.truncation_reasons.size) return finish('truncated', 'input_limit');
    if (!result.hostname || !result.record_type) return finish('invalid_response', 'invalid_question');
    const error = field(input, 'error');
    if (error !== undefined && error !== null) return finish(errorOutcome(error));
    const response = field(input, 'response');
    if (!object(response)) return finish('invalid_response', 'missing_response');
    const rcode = field(response, 'Status');
    if (!Number.isInteger(rcode) || rcode < 0 || rcode > 4_095) return finish('invalid_response', 'invalid_status');
    result.rcode = rcode;
    for (const flag of ['TC', 'AD']) {
      const value = field(response, flag);
      if (value !== undefined && typeof value !== 'boolean') return finish('invalid_response', 'invalid_flag');
      if (flag === 'AD') result.dnssec_authenticated = value ?? null;
      if (flag === 'TC' && value === true) state.truncation_reasons.add('dns_tc');
    }
    const questions = field(response, 'Question');
    if (questions !== undefined) {
      if (!Array.isArray(questions) || questions.length !== 1) return finish('invalid_response', 'question_mismatch');
      const question = field(questions, '0');
      if (!object(question) || normalizeHostname(inputText(field(question, 'name'), state)) !== result.hostname
          || typeCode(field(question, 'type')) !== DISCOVERY_DNS_RECORD_TYPES[result.record_type]) {
        return finish('invalid_response', 'question_mismatch');
      }
    }
    const answers = section(field(response, 'Answer'), state);
    const authority = section(field(response, 'Authority'), state);
    // Additional is deliberately not consulted: glue is not an answer to this
    // question and cannot establish resolution for the queried hostname.
    if (state.truncation_reasons.size) return finish('truncated', 'incomplete_response');
    const byOwner = new Map();
    for (const item of answers) {
      if (!byOwner.has(item.name)) byOwner.set(item.name, []);
      byOwner.get(item.name).push(item);
    }
    let owner = result.hostname;
    const visited = new Set();
    for (;;) {
      if (visited.has(owner)) return finish('invalid_response', 'cname_loop');
      visited.add(owner);
      const records = byOwner.get(owner) ?? [];
      const aliases = records.filter(item => item.type === 'CNAME');
      const targets = [...new Set(aliases.map(item => item.data))];
      if (targets.length > 1 || (aliases.length && records.some(item => ['A', 'AAAA', 'MX', 'TXT'].includes(item.type)))) {
        return finish('invalid_response', 'conflicting_cname');
      }
      result.records.push(...records.filter(item => item.type === result.record_type || item.type === 'CNAME'));
      if (!targets.length) break;
      if (result.cname_chain.length >= DISCOVERY_DNS_LIMITS.maxCnameHops) {
        state.truncation_reasons.add('cname_hops'); return finish('truncated', 'incomplete_cname_chain');
      }
      result.cname_chain.push({ name: owner, target: targets[0] });
      owner = targets[0];
    }
    const unique = new Map(result.records.map(item => [JSON.stringify(item), item]));
    result.records = [...unique.values()].sort((a, b) => compare(JSON.stringify(a), JSON.stringify(b)));
    const matched = result.records.some(item => item.type === result.record_type);
    if (rcode === 3) {
      if (matched && result.record_type !== 'CNAME') return finish('invalid_response', 'answer_with_nxdomain');
      return finish('nxdomain');
    }
    if (rcode !== 0) {
      result.records = []; result.cname_chain = [];
      return finish(rcode === 2 ? 'servfail' : rcode === 5 ? 'refused' : 'dns_error');
    }
    if (matched) return finish('answer');
    if (result.cname_chain.length) return finish('cname_only', 'terminal_answer_missing');
    // RFC 2308 §2.2: an NS referral without SOA is not NODATA.
    if (authority.some(item => item.type === 2) && !authority.some(item => item.type === 6)) return finish('referral');
    return finish('nodata');
  } catch { return finish('invalid_response', 'malformed_input_or_response'); }
}

/** Merge classifier outputs by hostname; no cross-host address/absence inference.
 * Positive/negative address summaries are restricted to this supplied batch,
 * not a current-state claim across independent resolver observations or times.
 */
export function mergeDiscoveryDnsObservations(observations) {
  const result = { version: 'discovery-dns-summary-v1', hosts: [], observation_count: 0,
    rejected_count: 0, truncated: false, truncation_reasons: [] };
  const truncated = new Set(), hosts = new Map();
  if (!Array.isArray(observations)) { result.rejected_count = 1; return result; }
  if (observations.length > DISCOVERY_DNS_LIMITS.maxObservations) truncated.add('observation_count');
  for (let i = 0; i < Math.min(observations.length, DISCOVERY_DNS_LIMITS.maxObservations); i++) {
    try {
      const item = field(observations, String(i));
      if (!object(item) || field(item, 'version') !== VERSION) throw new Error('invalid_observation');
      const rawHostname = field(item, 'hostname');
      if (typeof rawHostname !== 'string' || byteLength(rawHostname, DISCOVERY_DNS_LIMITS.maxStringBytes) > DISCOVERY_DNS_LIMITS.maxStringBytes) throw new Error('invalid_hostname');
      const hostname = normalizeHostname(rawHostname);
      const type = field(item, 'record_type'), outcome = field(item, 'outcome');
      const timestamp = field(item, 'observed_at');
      if (!hostname || hostname !== rawHostname || typeof type !== 'string' || !Object.hasOwn(DISCOVERY_DNS_RECORD_TYPES, type)
          || !DISCOVERY_DNS_OUTCOMES.includes(outcome)
          || (timestamp !== null && (typeof timestamp !== 'string' || byteLength(timestamp, DISCOVERY_DNS_LIMITS.maxObservedAtBytes) > DISCOVERY_DNS_LIMITS.maxObservedAtBytes))) {
        throw new Error('invalid_observation');
      }
      // Recheck conclusive results from the retained owner-bound records rather
      // than trusting caller-supplied dns_address_resolved booleans.
      let verified = null;
      if (['answer', 'nodata', 'nxdomain'].includes(outcome)) {
        const records = field(item, 'records');
        if (!Array.isArray(records) || records.length > DISCOVERY_DNS_LIMITS.maxRecords) throw new Error('invalid_records');
        const answers = [];
        for (let index = 0; index < records.length; index++) {
          const value = field(records, String(index));
          answers.push({
            name: field(value, 'name'), type: field(value, 'type'), data: field(value, 'data'),
            ...(field(value, 'ttl') === null ? {} : { TTL: field(value, 'ttl') }),
          });
        }
        verified = classifyDiscoveryDnsResponse({ hostname, recordType: type, response: {
          Status: field(item, 'rcode'), Answer: answers,
        } });
        if (verified.outcome !== outcome || field(item, 'truncated') !== false || field(item, 'complete') !== true) throw new Error('inconsistent_observation');
      }
      if (!hosts.has(hostname)) hosts.set(hostname, { hostname, observation_count: 0, outcomes: new Map(),
        types: new Set(), times: new Set(), addresses: { A: new Set(), AAAA: new Set() }, negative: new Set(), nodata: new Set(), unknown: new Set() });
      const host = hosts.get(hostname);
      result.observation_count++; host.observation_count++;
      host.outcomes.set(outcome, (host.outcomes.get(outcome) ?? 0) + 1);
      host.types.add(type);
      if (timestamp !== null) host.times.add(timestamp);
      if (field(item, 'truncated') === true || outcome === 'truncated') truncated.add('observation_truncated');
      if (type !== 'A' && type !== 'AAAA') continue;
      if (verified?.dns_address_resolved === true) {
        for (const record of verified.records.filter(record => record.type === type)) {
          if (host.addresses.A.size + host.addresses.AAAA.size >= DISCOVERY_DNS_LIMITS.maxRecords && !host.addresses[type].has(record.data)) {
            truncated.add('summary_records'); continue;
          }
          host.addresses[type].add(record.data);
        }
      } else if (verified?.dns_address_resolved === false) {
        host.negative.add(type);
        if (outcome === 'nodata') host.nodata.add(type);
      }
      else host.unknown.add(type);
    } catch { result.rejected_count++; }
  }
  // Omitted or rejected input may contain a contradicting positive observation.
  // Retain witnessed positives, but do not infer absence from a partial batch.
  const batchComplete = truncated.size === 0 && result.rejected_count === 0;
  result.hosts = [...hosts.values()].sort((a, b) => compare(a.hostname, b.hostname)).map(host => {
    const ipv4 = [...host.addresses.A].sort(compare), ipv6 = [...host.addresses.AAAA].sort(compare);
    const conflict = (ipv4.length > 0 && host.negative.has('A')) || (ipv6.length > 0 && host.negative.has('AAAA'))
      || ((ipv4.length > 0 || ipv6.length > 0) && host.outcomes.has('nxdomain'));
    const negativePair = batchComplete && host.negative.has('A') && host.negative.has('AAAA') && host.unknown.size === 0;
    return { hostname: host.hostname, observation_count: host.observation_count,
      record_types: [...host.types].sort(compare), observed_at: [...host.times].sort(compare),
      outcome_counts: Object.fromEntries([...host.outcomes].sort(([a], [b]) => compare(a, b))),
      ipv4_addresses: ipv4, ipv6_addresses: ipv6,
      dns_address_resolved: ipv4.length || ipv6.length ? true : negativePair ? false : null,
      address_observations_conflict: conflict,
      // A timeout or a missing A query cannot prove IPv6-only resolution.
      ipv6_only_observed: batchComplete && ipv6.length > 0 && ipv4.length === 0 && host.nodata.has('A') && !host.unknown.has('A') && !conflict,
    };
  });
  result.truncation_reasons = [...truncated].sort(compare);
  result.truncated = result.truncation_reasons.length > 0;
  return result;
}
