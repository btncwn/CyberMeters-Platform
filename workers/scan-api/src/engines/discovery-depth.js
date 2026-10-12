// ── Discovery depth ──────────────────────────────────────────────────────────
// Bounded DNS discovery beyond the fixed word list, for durable invocations:
//   • a rotating slice of the authored discovery word list — each completed
//     scan of the domain checks the next slice, so repeated scans cover the
//     whole list instead of the same names every time;
//   • name variants of hosts already found (app → app-dev, api01 → api02…);
//   • a bounded DNSSEC NSEC walk, which reads the names a signed zone lists.
// Every guess is one DNS question. A name joins discovery only when DNS
// answers for it; a guessed name whose answer is exactly the zone's wildcard
// answer is not evidence that the name exists, so it is not admitted.
import { dnsQuery, dnsQueryDnssec } from "./dns.js";
import { DISCOVERY_WORDLIST, deriveNameVariants, wordlistSlice } from "./discovery-wordlist.js";
import { applyNsecAnswer, createNsecWalkState, nextNsecQuery } from "./nsec-walk.js";
import { confirmationOf, confirmedHost, lookupNames, wildcardAddressSet } from "./discovery-confirmation.js";
import { normalizeHostname } from "./hostname-candidates.js";

export const DISCOVERY_DEPTH_VERSION = "discovery-depth-v1";

// Per-scan bounds. Lookups run in batches; no new batch starts after
// softBudgetMs, and each DoH question carries its own 6s timeout, so the step
// always finishes inside budgetMs with nothing left in flight.
export const DISCOVERY_DEPTH_LIMITS = Object.freeze({
  wordlistSlice: 200,
  variants: 100,
  nsecQueries: 64,
  nsecConfirmations: 64,
  batchSize: 25,
  softBudgetMs: 18_000,
  budgetMs: 25_000,
});

export const DISCOVERY_DEPTH_ASSET_SOURCES = Object.freeze({
  wordlist: "dns_wordlist",
  variant: "dns_name_variant",
  nsec: "dnssec_nsec",
});

const compare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const strings = (value) => (Array.isArray(value) ? value.filter((item) => typeof item === "string") : []);

// The slice a scan checks: completed scans of the domain advance the cursor by
// one slice, wrapping at the end of the list.
export function wordlistRotation(rotationIndex, size = DISCOVERY_DEPTH_LIMITS.wordlistSlice) {
  const index = Number.isSafeInteger(rotationIndex) && rotationIndex >= 0 ? rotationIndex : 0;
  const cursor = (index * size) % DISCOVERY_WORDLIST.length;
  return { cursor, ...wordlistSlice({ cursor, size }) };
}

// One bounded read: completed scans of this domain in this workspace. A failed
// read rotates from the start and says so.
export async function loadDiscoveryRotationIndex(env, { domainId, workspaceId = null } = {}) {
  if (!env?.cybermeters_db || typeof domainId !== "string" || !domainId) return { index: 0, source: "unavailable" };
  try {
    const row = workspaceId
      ? await env.cybermeters_db
        .prepare("SELECT COUNT(*) AS n FROM scans WHERE domain_id = ? AND workspace_id = ? AND status = 'completed'")
        .bind(domainId, workspaceId).first()
      : await env.cybermeters_db
        .prepare("SELECT COUNT(*) AS n FROM scans WHERE domain_id = ? AND status = 'completed'")
        .bind(domainId).first();
    const n = Number(row?.n);
    return Number.isSafeInteger(n) && n >= 0 ? { index: n, source: "completed_scans" } : { index: 0, source: "unavailable" };
  } catch {
    return { index: 0, source: "unavailable" };
  }
}

function now() {
  return Date.now();
}

// `listed` names appear in the zone's own NSEC chain: they keep the NSEC
// source and are never wildcard-filtered, even when a guess also asked them.
function tally(observations, source, { wildcardSet, filterWildcard, listed = new Set() }) {
  const confirmed = [];
  const counts = { found: 0, not_found: 0, no_address: 0, lookup_failed: 0, wildcard_filtered: 0 };
  for (const observation of observations) {
    const isListed = listed.has(observation?.hostname);
    const confirmation = confirmationOf(observation, { wildcardSet, filterWildcard: filterWildcard && !isListed });
    if (confirmation.status === "confirmed") {
      counts.found++;
      confirmed.push(confirmedHost(observation.hostname, confirmation, {
        source: isListed ? DISCOVERY_DEPTH_ASSET_SOURCES.nsec : source,
      }));
    } else counts[confirmation.status]++;
  }
  return { confirmed, counts };
}

// Walk the zone's NSEC chain, one question at a time, within the query bound
// and the soft time budget. Owner names are names the zone itself lists.
async function walkNsec(domain, nsecLookup, { clock, deadlineAt, maxQueries }) {
  let state;
  try { state = createNsecWalkState({ domain, maxQueries }); } catch { return { outcome: "invalid_domain", queries: 0, owners: [] }; }
  let outcome = null;
  for (let name = nextNsecQuery(state); name !== null; name = nextNsecQuery(state)) {
    if (clock() >= deadlineAt) { outcome = "time_budget_reached"; break; }
    let response = null;
    try { response = await nsecLookup(name, "NSEC"); } catch { outcome = "lookup_failed"; break; }
    state = applyNsecAnswer(state, response);
  }
  return {
    outcome: outcome ?? state.outcome,
    queries: state.totalQueries,
    owners: state.candidates.map((item) => item.hostname).sort(compare),
  };
}

export function discoveryDepthNotExecuted(reason) {
  return {
    version: DISCOVERY_DEPTH_VERSION,
    executed: false,
    reason,
    confirmed: [],
    incomplete: true,
    incomplete_reason: reason,
  };
}

/**
 * Run the three bounded sources. `knownHosts` are names discovery already
 * holds or the inventory already knows; they are never asked about again.
 */
export async function runDiscoveryDepth(domain, {
  knownHosts = [],
  discoveredHosts = [],
  wildcardAddresses = [],
  rotationIndex = 0,
  accounting = null,
  cache = null,
  signal = null,
  clock = now,
  lookup = (name, type) => dnsQuery(name, type, { accounting, cache, signal }),
  nsecLookup = (name, type) => dnsQueryDnssec(name, type, { accounting, cache, signal }),
} = {}) {
  const root = normalizeHostname(domain);
  if (!root) return discoveryDepthNotExecuted("invalid_domain");
  const limits = DISCOVERY_DEPTH_LIMITS;
  const deadlineAt = clock() + limits.softBudgetMs;
  const wildcardSet = wildcardAddressSet(wildcardAddresses);
  const asked = new Set([root, ...strings(knownHosts).map((host) => normalizeHostname(host)).filter(Boolean)]);
  const fresh = (names) => {
    const out = [];
    for (const name of names) {
      if (!name || asked.has(name)) continue;
      asked.add(name);
      out.push(name);
    }
    return out;
  };

  // Word-list slice and NSEC walk run side by side; variants need the slice's
  // answers first.
  const rotation = wordlistRotation(rotationIndex);
  const sliceNames = fresh(rotation.labels.map((label) => normalizeHostname(`${label}.${root}`)));
  const [sliceRun, walk] = await Promise.all([
    lookupNames(sliceNames, lookup, { clock, deadlineAt, batchSize: limits.batchSize }),
    walkNsec(root, nsecLookup, { clock, deadlineAt, maxQueries: limits.nsecQueries }),
  ]);
  const listed = new Set(walk.owners);
  const wordlist = tally(sliceRun.observations, DISCOVERY_DEPTH_ASSET_SOURCES.wordlist, { wildcardSet, filterWildcard: true, listed });

  // A name the zone lists keeps the NSEC source and is never wildcard-
  // filtered, whichever lookup asked it (`listed`).
  const nsecFresh = fresh(walk.owners);
  const nsecNames = nsecFresh.slice(0, limits.nsecConfirmations);
  const nsecNotChecked = nsecFresh.length - nsecNames.length;
  const variantInputs = [...strings(discoveredHosts), ...wordlist.confirmed.map((item) => item.hostname)];
  const derived = deriveNameVariants(variantInputs, { domain: root, max: limits.variants }).map((item) => item.hostname);
  const variantNames = fresh(derived);
  const [variantRun, nsecRun] = await Promise.all([
    lookupNames(variantNames, lookup, { clock, deadlineAt, batchSize: limits.batchSize }),
    lookupNames(nsecNames, lookup, { clock, deadlineAt, batchSize: limits.batchSize }),
  ]);
  const variants = tally(variantRun.observations, DISCOVERY_DEPTH_ASSET_SOURCES.variant, { wildcardSet, filterWildcard: true, listed });
  // Names the zone lists are not guesses: a wildcard-shaped answer is flagged,
  // not filtered.
  const nsec = tally(nsecRun.observations, DISCOVERY_DEPTH_ASSET_SOURCES.nsec, { wildcardSet, filterWildcard: false });

  const unasked = sliceRun.unasked + variantRun.unasked + nsecRun.unasked;
  const lookupFailed = wordlist.counts.lookup_failed + variants.counts.lookup_failed + nsec.counts.lookup_failed;
  const reasons = [];
  if (unasked > 0) reasons.push("time_budget_reached");
  if (lookupFailed > 0) reasons.push("lookup_failed");
  if (nsecNotChecked > 0) reasons.push("nsec_confirmation_cap_reached");
  if (["budget_exhausted", "lookup_failed", "dns_error", "invalid_response", "truncated_response", "time_budget_reached"].includes(walk.outcome)) {
    reasons.push(`nsec_${walk.outcome}`);
  }
  return {
    version: DISCOVERY_DEPTH_VERSION,
    executed: true,
    reason: null,
    wordlist: {
      rotation_index: Number.isSafeInteger(rotationIndex) && rotationIndex >= 0 ? rotationIndex : 0,
      cursor: rotation.cursor,
      next_cursor: rotation.next_cursor,
      list_size: DISCOVERY_WORDLIST.length,
      checked: sliceRun.observations.length,
      ...wordlist.counts,
    },
    variants: { derived: derived.length, checked: variantRun.observations.length, ...variants.counts },
    nsec: {
      outcome: walk.outcome,
      queries: walk.queries,
      owners: walk.owners.length,
      checked: nsecRun.observations.length,
      not_checked: nsecNotChecked,
      ...nsec.counts,
    },
    confirmed: [...wordlist.confirmed, ...variants.confirmed, ...nsec.confirmed],
    not_asked: unasked,
    incomplete: reasons.length > 0,
    incomplete_reason: reasons[0] ?? null,
    ...(reasons.length > 1 ? { incomplete_reasons: reasons } : {}),
  };
}
