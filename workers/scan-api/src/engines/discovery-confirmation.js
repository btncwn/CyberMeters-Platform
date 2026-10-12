// ── Discovery confirmation ───────────────────────────────────────────────────
// The one rule every discovery source uses to turn a candidate hostname into a
// discovered one: a DNS A question, answered. Shared by referenced names, the
// rotating word list, name variants, the NSEC walk and customer-listed names,
// so no source can admit on weaker evidence than another.
import { classifyDiscoveryDnsResponse } from "./discovery-dns-observation.js";

const compare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

export function wildcardAddressSet(addresses = []) {
  return new Set((Array.isArray(addresses) ? addresses : [])
    .filter((address) => typeof address === "string")
    .map((address) => address.toLowerCase()));
}

/**
 * Ask names in batches. No new batch starts once `clock()` reaches
 * `deadlineAt`; names never asked are counted in `unasked`. A lookup that
 * throws is classified as a transport failure, never as absence.
 */
export async function lookupNames(names, lookup, { clock = Date.now, deadlineAt = Infinity, batchSize = 25 } = {}) {
  const observations = [];
  let unasked = 0;
  const size = Number.isSafeInteger(batchSize) && batchSize > 0 ? batchSize : 25;
  for (let start = 0; start < names.length; start += size) {
    if (clock() >= deadlineAt) { unasked = names.length - start; break; }
    observations.push(...await Promise.all(names.slice(start, start + size).map(async (hostname) => {
      let response = null, error = null;
      try { response = await lookup(hostname, "A"); } catch (err) { error = err ?? new Error("lookup_failed"); }
      return classifyDiscoveryDnsResponse({ hostname, recordType: "A", ...(error ? { error } : { response }) });
    })));
  }
  return { observations, unasked };
}

/**
 * What one A observation says about its name:
 *   confirmed         — an address, or an alias chain with no address at its end;
 *   wildcard_filtered — a guess answered exactly by the zone's wildcard answer
 *                       (only when `filterWildcard`: a guess is not evidence);
 *   not_found         — NXDOMAIN;
 *   no_address        — the name exists but has no IPv4 address;
 *   lookup_failed     — anything else (SERVFAIL, timeout, malformed answer).
 */
export function confirmationOf(observation, { wildcardSet = new Set(), filterWildcard = false } = {}) {
  const outcome = observation?.outcome;
  if (outcome === "answer" || outcome === "cname_only") {
    const addresses = (observation.records || [])
      .filter((record) => record.type === "A")
      .map((record) => String(record.data).toLowerCase())
      .sort(compare);
    const wildcardMatch = wildcardSet.size > 0 && addresses.length === wildcardSet.size &&
      addresses.every((address) => wildcardSet.has(address));
    if (wildcardMatch && filterWildcard) return { status: "wildcard_filtered" };
    return {
      status: "confirmed",
      addresses,
      alias_only: outcome === "cname_only",
      wildcard_match: wildcardMatch,
    };
  }
  if (outcome === "nxdomain") return { status: "not_found" };
  if (outcome === "nodata") return { status: "no_address" };
  return { status: "lookup_failed" };
}

// A confirmed discovery row, with flags only when they are true.
export function confirmedHost(hostname, confirmation, extra = {}) {
  return {
    hostname,
    ...extra,
    ip_addresses: confirmation.addresses,
    ...(confirmation.alias_only ? { alias_only: true } : {}),
    ...(confirmation.wildcard_match ? { wildcard_match: true } : {}),
  };
}
