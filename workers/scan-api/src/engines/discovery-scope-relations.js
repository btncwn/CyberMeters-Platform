import { normalizeHostname } from './hostname-candidates.js';

// Pure routing of supplied evidence, with no network, storage, or ambient time.
// verifiedDomains MUST come from the caller's tenant-scoped ownership checks.
// This function cannot prove authentication, authorization, ownership, or that
// these domains belong to tenantId. Never pass a client-supplied scope list here.
// Neither a source label nor any result grants permission to scan a destination,
// or proves an active host, a service, ownership, or a confirmed dependency.
export const DISCOVERY_SCOPE_RELATION_LIMITS = Object.freeze({
  maxCandidates: 200,
  maxExternalRelationships: 100,
  maxWithinScopeRelationships: 200,
  maxWildcardScopes: 200,
  maxObservations: 500,
  maxVerifiedDomains: 10_000,
  maxScopeBytes: 262_144,
  maxEntryBytes: 16_384,
});

// These are relationship *evidence types*, not trusted sources. In particular,
// certificate co-occurrence (including live_tls_san) never establishes a link.
const RELATIONSHIPS = new Map([
  ['dns_cname', 'dns_cname'], ['cname', 'dns_cname'],
  ['dns_mx', 'mx'], ['mx', 'mx'], ['dns_ns', 'ns'], ['ns', 'ns'],
  ['dns_spf', 'spf'], ['spf', 'spf'],
  ['redirect_chain', 'redirect'], ['http_redirect', 'redirect'],
  ['javascript', 'javascript_reference'], ['csp', 'csp_reference'],
]);
const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;
const fields = ['hostname', 'source', 'from_hostname', 'evidence_ref', 'observed_at'];
const encoder = new TextEncoder();

// Read only own data properties: inherited scope/evidence and accessors do not
// supply authority or evidence. Extra fields are ignored, never traversed.
function readRecord(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return null;
  const record = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor && !Object.hasOwn(descriptor, 'value')) return null;
    record[key] = descriptor?.value;
  }
  return record;
}

function ownArrayValue(array, index) {
  const descriptor = Object.getOwnPropertyDescriptor(array, String(index));
  return descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
}

function timestamp(value) {
  if (value == null) return null;
  return typeof value === 'string' && value.length > 0 && value.length <= 128 &&
    !/[\u0000-\u001f\u007f]/u.test(value) ? value : undefined;
}

function matchingRoot(hostname, roots) {
  // Canonical suffixes are tested from longest to shortest. This preserves
  // label boundaries and most-specific routing without scanning every domain.
  let suffix = hostname;
  while (suffix) {
    if (roots.has(suffix)) return suffix;
    const dot = suffix.indexOf('.');
    if (dot < 0) break;
    suffix = suffix.slice(dot + 1);
  }
  return null;
}

function addEvidence(map, key, properties, provenance) {
  if (!map.has(key)) map.set(key, { ...properties, sources: new Set(), provenance: new Map() });
  const item = map.get(key);
  item.sources.add(provenance.source);
  item.provenance.set(JSON.stringify(provenance), provenance);
}

function finishEvidence(item) {
  return { ...item, sources: [...item.sources].sort(compare),
    provenance: [...item.provenance].sort(([a], [b]) => compare(a, b)).map(([, value]) => ({ ...value })) };
}

export function routeDiscoveryEvidence(input) {
  const result = {
    version: 'discovery-scope-relations-v1', tenantId: null, observed_at: null,
    candidates: [], wildcard_scopes: [], relationships: [],
    counters: {
      input_observations: 0, processed_observations: 0, rejected_observations: 0,
      in_scope_observations: 0, root_observations: 0, out_of_scope_observations: 0,
      foreign_san_observations: 0, unlinked_external_observations: 0,
      candidate_count: 0, wildcard_scope_count: 0,
      external_relationship_count: 0, within_scope_relationship_count: 0,
    },
    truncated: false, truncated_count: 0, truncation_reasons: [], rejected_reasons: [],
  };
  const truncationReasons = new Set(), rejectedReasons = new Set();
  const truncate = (reason, count) => {
    if (count <= 0) return;
    result.truncated = true; result.truncated_count += count; truncationReasons.add(reason);
  };
  const finish = () => {
    result.truncation_reasons = [...truncationReasons].sort(compare);
    result.rejected_reasons = [...rejectedReasons].sort(compare);
    return result;
  };
  const invalid = reason => { rejectedReasons.add(reason); return finish(); };
  const rejectObservation = reason => { result.counters.rejected_observations++; rejectedReasons.add(reason); };
  try {
    const options = readRecord(input, ['tenantId', 'verifiedDomains', 'observations', 'observedAt']);
    if (!options) return invalid('invalid_input');
    if (typeof options.tenantId !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$/.test(options.tenantId)) return invalid('invalid_tenant_id');
    result.tenantId = options.tenantId;
    const observedAt = timestamp(options.observedAt);
    if (observedAt === undefined) return invalid('invalid_observed_at');
    result.observed_at = observedAt;
    const { verifiedDomains, observations } = options;
    if (!Array.isArray(verifiedDomains)) return invalid('invalid_verified_domains');
    const scopeCount = Object.getOwnPropertyDescriptor(verifiedDomains, 'length')?.value;
    if (!Number.isSafeInteger(scopeCount) || scopeCount <= 0) return invalid('invalid_verified_domains');
    if (scopeCount > DISCOVERY_SCOPE_RELATION_LIMITS.maxVerifiedDomains) {
      // Partial scope could route an overlapping child to the wrong parent.
      truncate('verified_domains_limit', scopeCount - DISCOVERY_SCOPE_RELATION_LIMITS.maxVerifiedDomains);
      return invalid('invalid_verified_domains');
    }
    const roots = new Set();
    let scopeBytes = 0;
    for (let i = 0; i < scopeCount; i++) {
      const value = ownArrayValue(verifiedDomains, i);
      if (typeof value !== 'string') return invalid('invalid_verified_domains');
      const remaining = DISCOVERY_SCOPE_RELATION_LIMITS.maxScopeBytes - scopeBytes;
      if (value.length > remaining || (scopeBytes += encoder.encode(value).length) > DISCOVERY_SCOPE_RELATION_LIMITS.maxScopeBytes) {
        // Count the full supplied scope as omitted; no partial scope is used.
        truncate('verified_domains_bytes_limit', scopeCount);
        return invalid('invalid_verified_domains');
      }
      const root = normalizeHostname(value);
      if (!root || !root.includes('.')) return invalid('invalid_verified_domains');
      roots.add(root);
    }
    if (!Array.isArray(observations)) return invalid('invalid_observations');
    const observationCount = Object.getOwnPropertyDescriptor(observations, 'length')?.value;
    if (!Number.isSafeInteger(observationCount) || observationCount < 0) return invalid('invalid_observations');
    result.counters.input_observations = observationCount;
    const count = Math.min(observationCount, DISCOVERY_SCOPE_RELATION_LIMITS.maxObservations);
    truncate('observations_limit', observationCount - count);
    const candidates = new Map(), wildcards = new Map(), external = new Map(), internal = new Map();
    for (let i = 0; i < count; i++) {
      result.counters.processed_observations++;
      let entry;
      try { entry = readRecord(ownArrayValue(observations, i), fields); }
      catch { entry = null; }
      if (!entry) { rejectObservation('invalid_observation'); continue; }
      // Bound the total UTF-8 bytes of consumed scalar fields, including refs.
      // No JSON serialization, custom toJSON, getter, or unknown subtree runs.
      let bytes = 0;
      for (const field of fields) {
        const value = entry[field];
        if (typeof value !== 'string') continue;
        if (value.length > DISCOVERY_SCOPE_RELATION_LIMITS.maxEntryBytes) { bytes = Infinity; break; }
        bytes += encoder.encode(value).length;
      }
      if (bytes > DISCOVERY_SCOPE_RELATION_LIMITS.maxEntryBytes) { truncate('entry_bytes_limit', 1); continue; }
      if (typeof entry.source !== 'string' || !/^[a-z][a-z0-9_]{0,63}$/.test(entry.source)) { rejectObservation('invalid_source'); continue; }
      const raw = typeof entry.hostname === 'string' ? entry.hostname.trim() : '';
      const wildcard = raw.startsWith('*.');
      const hostname = normalizeHostname(wildcard ? raw.slice(2) : raw);
      if (!hostname) { rejectObservation('invalid_hostname'); continue; }
      const from = entry.from_hostname == null ? null : normalizeHostname(entry.from_hostname);
      if (entry.from_hostname != null && !from) { rejectObservation('invalid_from_hostname'); continue; }
      const ref = entry.evidence_ref == null ? null : entry.evidence_ref;
      if (ref !== null && (typeof ref !== 'string' || !ref.trim() || /[\u0000-\u001f\u007f]/u.test(ref))) { rejectObservation('invalid_evidence_ref'); continue; }
      const time = entry.observed_at == null ? observedAt : timestamp(entry.observed_at);
      if (time === undefined) { rejectObservation('invalid_observed_at'); continue; }
      const root = matchingRoot(hostname, roots);
      const fromRoot = from === null ? null : matchingRoot(from, roots);
      // Unverified origins are never copied into a tenant's candidate provenance.
      const provenance = { source: entry.source, from_hostname: fromRoot ? from : null,
        evidence_ref: ref, observed_at: time };
      if (root) {
        result.counters.in_scope_observations++;
        if (wildcard) {
          addEvidence(wildcards, `${root}\n${hostname}`, { root, scope: hostname }, provenance);
          continue;
        }
        if (hostname === root) result.counters.root_observations++;
        else addEvidence(candidates, `${root}\n${hostname}`, { root, hostname }, provenance);
      } else {
        result.counters.out_of_scope_observations++;
        if (entry.source === 'live_tls_san') result.counters.foreign_san_observations++;
      }
      const relationship = RELATIONSHIPS.get(entry.source);
      if (!wildcard && fromRoot && ref !== null && relationship && from !== hostname) {
        const properties = { kind: root ? 'within_scope' : 'external',
          from_root: fromRoot, from_hostname: from, to_root: root, to_hostname: hostname, relationship };
        const key = `${fromRoot}\n${from}\n${root ?? ''}\n${hostname}\n${relationship}`;
        addEvidence(root ? internal : external, key, properties, provenance);
      } else if (!root) result.counters.unlinked_external_observations++;
    }
    const bounded = (map, limit, reason) => {
      const entries = [...map].sort(([a], [b]) => compare(a, b));
      truncate(reason, Math.max(0, entries.length - limit));
      return entries.slice(0, limit).map(([, item]) => finishEvidence(item));
    };
    result.candidates = bounded(candidates, DISCOVERY_SCOPE_RELATION_LIMITS.maxCandidates, 'candidates_limit');
    result.wildcard_scopes = bounded(wildcards, DISCOVERY_SCOPE_RELATION_LIMITS.maxWildcardScopes, 'wildcard_scopes_limit');
    const externalRelations = bounded(external, DISCOVERY_SCOPE_RELATION_LIMITS.maxExternalRelationships, 'external_relationships_limit');
    const internalRelations = bounded(internal, DISCOVERY_SCOPE_RELATION_LIMITS.maxWithinScopeRelationships, 'within_scope_relationships_limit');
    result.relationships = [...internalRelations, ...externalRelations];
    result.counters.candidate_count = result.candidates.length;
    result.counters.wildcard_scope_count = result.wildcard_scopes.length;
    result.counters.external_relationship_count = externalRelations.length;
    result.counters.within_scope_relationship_count = internalRelations.length;
    return finish();
  } catch {
    // Invalid outer objects (including exceptional proxy traps) fail closed.
    result.candidates = []; result.wildcard_scopes = []; result.relationships = [];
    return invalid('invalid_input');
  }
}
