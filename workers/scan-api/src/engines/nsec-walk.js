import { normalizeHostname, classifyHostname } from './hostname-candidates.js';

export const NSEC_WALK_SOURCE = 'nsec';
export const NSEC_WALK_LIMITS = Object.freeze({ defaultMaxQueries: 64, maxRecords: 500, maxRecordLength: 16384 });

// Pure planner: caller performs an authorized parent-zone NSEC (type 47, DO=1)
// query for nextNsecQuery(state), then applies that one response. No resolver,
// clock or DNSSEC signature verification lives here. "complete" means this
// supplied NSEC chain closed; it is NOT an inventory or DNSSEC-validation claim.
// Serialize the whole state, not only resume_after (the next pending name).
// Resume explicitly resets queriesUsed; it preserves start, visited, evidence
// and delegation boundaries. no_dnssec means no DNSSEC data was observed in a
// successful initial response, not cryptographic proof the zone is unsigned.
export function createNsecWalkState({ domain, maxQueries = NSEC_WALK_LIMITS.defaultMaxQueries } = {}) {
  const root = normalizeHostname(domain);
  if (!root) throw new TypeError('A valid root domain is required');
  if (!Number.isSafeInteger(maxQueries) || maxQueries < 0) throw new TypeError('maxQueries must be a nonnegative integer');
  return {
    version: 1, domain: root, root, start: root, query: root,
    visited: [], chain: [], delegated_zones: [], candidates: [], wildcard_scopes: [],
    queriesUsed: 0, totalQueries: 0, maxQueries, minimal_steps: 0,
    outcome: maxQueries === 0 ? 'budget_exhausted' : 'walking',
    resume_after: maxQueries === 0 ? root : null,
  };
}

function validState(state) {
  if (!state || state.version !== 1 || !state.root || normalizeHostname(state.root) !== state.root ||
      state.domain !== state.root || state.start !== state.root ||
      !Array.isArray(state.visited) || !Array.isArray(state.chain) ||
      !Array.isArray(state.candidates) || !Array.isArray(state.wildcard_scopes) ||
      !Array.isArray(state.delegated_zones) || !Number.isSafeInteger(state.queriesUsed) ||
      !Number.isSafeInteger(state.maxQueries) || !Number.isSafeInteger(state.totalQueries) ||
      state.queriesUsed < 0 || state.maxQueries < 0 || state.totalQueries < state.queriesUsed ||
      state.chain.length !== state.visited.length || new Set(state.visited).size !== state.visited.length) return false;
  let expected = state.start;
  for (let i = 0; i < state.chain.length; i++) {
    const edge = state.chain[i];
    if (!edge || edge.owner !== expected || edge.owner !== state.visited[i] ||
        ownerName(edge.owner) !== edge.owner || !within(edge.owner, state.root) ||
        ownerName(edge.next) !== edge.next || !within(edge.next, state.root) ||
        (edge.next !== state.start && compareDnsNames(edge.owner, edge.next) >= 0) ||
        (edge.next === state.start && i !== state.chain.length - 1)) return false;
    expected = edge.next;
  }
  if (state.chain.length > 0 && state.totalQueries === 0) return false;
  if (state.outcome === 'complete') {
    if (!state.chain.length || expected !== state.start || state.query !== null) return false;
  } else if (state.query !== expected || ownerName(state.query) !== state.query ||
      !within(state.query, state.root) || state.visited.includes(state.query)) return false;
  if (state.outcome === 'budget_exhausted' &&
      (state.resume_after !== state.query || state.queriesUsed < state.maxQueries)) return false;
  if (state.outcome !== 'budget_exhausted' && state.resume_after !== null) return false;
  return state.candidates.every(item => item && state.visited.includes(item.hostname) &&
    classifyHostname(item.hostname, state.root).kind === 'candidate' &&
    Array.isArray(item.sources) && item.sources.length === 1 && item.sources[0] === NSEC_WALK_SOURCE) &&
    state.wildcard_scopes.every(scope => classifyHostname(`*.${scope}`, state.root).kind === 'wildcard') &&
    state.delegated_zones.every(zone => ownerName(zone) === zone && under(zone, state.root));
}

function copyState(state) {
  if (!validState(state)) throw new TypeError('Use a complete, coherent NSEC walk state');
  return { ...state, visited: [...state.visited], chain: state.chain.map(edge => ({ ...edge })),
    delegated_zones: [...state.delegated_zones], wildcard_scopes: [...state.wildcard_scopes],
    candidates: state.candidates.map(item => ({ ...item, sources: [...item.sources] })) };
}

export function resumeNsecWalk(state, { maxQueries = state?.maxQueries } = {}) {
  const next = copyState(state);
  if (state.outcome !== 'budget_exhausted') throw new TypeError('Only a budget-exhausted walk can resume');
  if (!Number.isSafeInteger(maxQueries) || maxQueries < 1) throw new TypeError('Resume requires a positive query budget');
  return { ...next, queriesUsed: 0, maxQueries, query: state.resume_after, outcome: 'walking', resume_after: null };
}

export function nextNsecQuery(state) {
  if (!validState(state) || state.outcome !== 'walking' || state.queriesUsed >= state.maxQueries) return null;
  return state.query;
}

const typeIs = (value, number, label) => value === number || value === String(number) || value === label;
const isNsec = record => typeIs(record?.type, 47, 'NSEC');
const isNsec3 = record => typeIs(record?.type, 50, 'NSEC3') || typeIs(record?.type, 51, 'NSEC3PARAM');
const within = (name, root) => name === root || name.endsWith(`.${root}`);
const under = (name, root) => name !== root && name.endsWith(`.${root}`);

// DNS owner names can contain service underscores and wildcard labels even
// though those are not hostnames. Keep them walkable, but admit candidates ONLY
// through the shared hostname classifier below. Arbitrary escaped wire labels
// are unsupported; stopping is more honest than silently skipping chain links.
function ownerName(value) {
  const hostname = normalizeHostname(value);
  if (hostname) return hostname;
  if (typeof value !== 'string') return null;
  const name = value.toLowerCase().replace(/\.$/, '');
  if (name.length > 253 || !name.length) return null;
  return name.split('.').every(label => label.length > 0 && label.length <= 63 &&
    (/^[a-z0-9_-]+$/.test(label) || label === '*')) ? name : null;
}

// RFC 4034 canonical order: compare labels from the root toward the leaf,
// using octet ordering (locale-aware string sorting is inappropriate).
function compareDnsNames(left, right) {
  const a = left.split('.').reverse();
  const b = right.split('.').reverse();
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return a.length - b.length;
}

function stop(state, outcome) {
  return { ...state, outcome, resume_after: outcome === 'budget_exhausted' ? state.query : null };
}

function addCandidate(state, name) {
  const item = classifyHostname(name, state.domain);
  if (item.kind === 'candidate' && !state.candidates.some(candidate => candidate.hostname === item.hostname)) {
    state.candidates.push({ hostname: item.hostname, sources: [NSEC_WALK_SOURCE] });
  } else if (item.kind === 'wildcard' && !state.wildcard_scopes.includes(item.scope)) {
    state.wildcard_scopes.push(item.scope);
  }
}

function parseRecord(record) {
  if (typeof record?.name !== 'string' || typeof record.data !== 'string' ||
      record.data.length > NSEC_WALK_LIMITS.maxRecordLength || record.name.length > 1024) return null;
  const fields = record.data.trim().replace(/[()]/g, ' ').split(/\s+/);
  const rawNext = fields.shift();
  const bitmap = fields.map(type => type.toUpperCase());
  // RFC 4470 null-label successors and compact-denial TYPE65281 are not
  // instantiated names. NSEC/RRSIG-only generated denial records are likewise
  // not used as an enumeration source. This conservative stop may limit yield.
  const synthetic = /\\000|\u0000|\\255/.test(rawNext || '') ||
    /\\000|\u0000|\\255/.test(record.name) || bitmap.includes('TYPE65281') ||
    (bitmap.length > 0 && bitmap.every(type => type === 'NSEC' || type === 'RRSIG' || type === 'TYPE47' || type === 'TYPE46'));
  return { owner: ownerName(record.name), next: ownerName(rawNext), bitmap, synthetic };
}

export function applyNsecAnswer(state, dohJson) {
  const next = copyState(state);
  if (nextNsecQuery(state) === null) return next;
  next.queriesUsed++;
  next.totalQueries++;
  if (!dohJson || typeof dohJson !== 'object' || !Number.isInteger(dohJson.Status)) return stop(next, 'invalid_response');
  if (dohJson.Status !== 0 && dohJson.Status !== 3) return stop(next, 'dns_error');
  if (dohJson.TC === true) return stop(next, 'truncated_response');
  if (dohJson.Question !== undefined && (!Array.isArray(dohJson.Question) || dohJson.Question.length !== 1 ||
      ownerName(dohJson.Question[0]?.name) !== state.query || !typeIs(dohJson.Question[0]?.type, 47, 'NSEC'))) {
    return stop(next, 'invalid_response');
  }
  if ((dohJson.Answer !== undefined && !Array.isArray(dohJson.Answer)) ||
      (dohJson.Authority !== undefined && !Array.isArray(dohJson.Authority))) return stop(next, 'invalid_response');
  if ((dohJson.Answer?.length || 0) + (dohJson.Authority?.length || 0) > NSEC_WALK_LIMITS.maxRecords) return stop(next, 'truncated_response');
  const records = [...(dohJson.Answer || []), ...(dohJson.Authority || [])];
  const zoneRecords = records.filter(record => {
    const owner = ownerName(record?.name);
    return owner && within(owner, next.root);
  });
  if (zoneRecords.some(isNsec3)) return stop(next, 'nsec3_not_walkable');
  // A child SOA is a different zone. Never follow its names as the parent chain.
  if (zoneRecords.some(record => typeIs(record?.type, 6, 'SOA') && ownerName(record.name) !== next.root)) {
    return stop(next, 'delegation_boundary');
  }
  const nsecs = records.filter(isNsec);
  if (nsecs.length === 0) {
    const dnssecPresent = dohJson.AD === true || zoneRecords.some(record => [43, 46, 48].includes(Number(record.type)) ||
      ['DS', 'RRSIG', 'DNSKEY'].includes(record.type));
    return stop(next, dnssecPresent || next.visited.length > 0 ? 'nsec_unavailable' : 'no_dnssec');
  }
  const parsed = [];
  for (const record of nsecs) {
    const item = parseRecord(record);
    if (!item) return stop(next, 'invalid_response');
    if (item.synthetic) return stop(next, 'synthetic_nsec_not_walkable');
    if (!item.owner || !item.next || item.bitmap.length === 0) return stop(next, 'invalid_response');
    if (!within(item.owner, next.root) || !within(item.next, next.root)) return stop(next, 'out_of_zone');
    parsed.push(item);
  }
  // An exact-owner NSEC query cannot both assert an instantiated owner and
  // return NXDOMAIN. Do not promote contradictory or generated denial data.
  if (dohJson.Status === 3) return stop(next, 'incoherent_chain');
  // A valid answer can carry several linked records (including a parent's
  // delegation NSEC). Consume those without issuing a child-zone query.
  while (true) {
    const matches = parsed.filter(record => record.owner === next.query);
    if (matches.length === 0) return stop(next, 'incoherent_chain');
    const record = matches[0];
    if (matches.some(item => item.next !== record.next || item.bitmap.join(' ') !== record.bitmap.join(' '))) {
      return stop(next, 'incoherent_chain');
    }
    if (next.visited.includes(record.owner)) return stop(next, 'incoherent_chain');
    const soa = record.bitmap.includes('SOA') || record.bitmap.includes('TYPE6');
    const ns = record.bitmap.includes('NS') || record.bitmap.includes('TYPE2');
    if (record.owner === next.root && !soa) return stop(next, 'incoherent_chain');
    if (record.owner !== next.root && soa) return stop(next, 'delegation_boundary');
    if (next.delegated_zones.some(zone => under(record.owner, zone))) return stop(next, 'delegation_boundary');
    if (record.next !== next.start && compareDnsNames(record.owner, record.next) >= 0) return stop(next, 'incoherent_chain');
    // Repeated one-label epsilon successors are another conservative compact-
    // denial signal. A legitimate deeply nested chain can stop here too; never
    // claim completeness merely because the server can generate more labels.
    const prefix = record.next.endsWith(`.${record.owner}`)
      ? record.next.slice(0, -(record.owner.length + 1)) : null;
    next.minimal_steps = prefix !== null && prefix.length === 1 ? next.minimal_steps + 1 : 0;
    if (next.minimal_steps >= 2) return stop(next, 'synthetic_nsec_not_walkable');
    if (ns && !soa && !next.delegated_zones.includes(record.owner)) next.delegated_zones.push(record.owner);
    if (next.delegated_zones.some(zone => under(record.next, zone))) return stop(next, 'delegation_boundary');
    next.visited.push(record.owner);
    next.chain.push({ owner: record.owner, next: record.next });
    addCandidate(next, record.owner);
    // Only actual owner records are candidate evidence. A next-name pointer
    // may be synthetic even when its text looks normal; verify its owner RR
    // in a later answer before admitting it as a discovered name.
    if (record.next === next.start) {
      next.query = null;
      return stop(next, 'complete');
    }
    next.query = record.next;
    if (next.visited.includes(next.query)) return stop(next, 'incoherent_chain');
    if (!parsed.some(item => item.owner === next.query)) break;
  }
  if (next.queriesUsed >= next.maxQueries) return stop(next, 'budget_exhausted');
  return next;
}
