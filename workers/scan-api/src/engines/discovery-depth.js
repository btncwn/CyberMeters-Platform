// ── Discovery depth ──────────────────────────────────────────────────────────
// Bounded DNS discovery beyond the fixed word list, for durable invocations:
//   • a rotating slice of the authored discovery word list — each completed
//     scan of the domain checks the next slice, so repeated scans cover the
//     whole list instead of the same names every time;
//   • name variants of hosts already found (app → app-dev, api01 → api02…);
//   • a bounded DNSSEC NSEC walk, which reads the names a signed zone lists.
// Every guess asks A, and AAAA when A did not prove the name does not exist; all
// questions, the NSEC walk's included, spend the scan's shared discovery
// budget. A name joins discovery only when DNS answers for it; a guessed name
// whose answer is exactly a wildcard's answer — the zone's, or a wildcard
// below it that a guess's parent answers for — is not evidence that the name
// exists, so it is not admitted.
import { dnsQuery, dnsQueryDnssec } from "./dns.js";
import { DISCOVERY_WORDLIST, deriveNameVariants, wordlistSlice } from "./discovery-wordlist.js";
import { applyNsecAnswer, createNsecWalkState, nextNsecQuery } from "./nsec-walk.js";
import { confirmationOf, confirmedHost, lookupNames, tallyConfirmation, wildcardAddressSet } from "./discovery-confirmation.js";
import { normalizeHostname } from "./hostname-candidates.js";

export const DISCOVERY_DEPTH_VERSION = "discovery-depth-v1";

// Per-scan bounds. Lookups run in batches; no new batch starts after
// softBudgetMs, each DoH question carries its own 6s timeout, and an AAAA
// question is only started when it still ends before budgetMs, so the step
// always finishes inside budgetMs with nothing left in flight.
export const DISCOVERY_DEPTH_LIMITS = Object.freeze({
  wordlistSlice: 200,
  variants: 100,
  nsecQueries: 64,
  nsecConfirmations: 64,
  // Distinct parents below the domain whose own wildcard is checked before
  // their derived variants count (two questions each).
  subzoneWildcardChecks: 8,
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
// `wildcardFor(hostname)` gives the wildcard answer that applies to a guess.
function tally(observations, source, { wildcardFor, filterWildcard, listed = new Set() }) {
  const confirmed = [];
  const counts = { found: 0, not_found: 0, no_address: 0, lookup_failed: 0, wildcard_filtered: 0 };
  for (const observation of observations) {
    const isListed = listed.has(observation?.hostname);
    const confirmation = confirmationOf(observation, {
      wildcardSet: wildcardFor(observation?.hostname),
      filterWildcard: filterWildcard && !isListed,
    });
    tallyConfirmation(counts, confirmation);
    if (confirmation.status === "confirmed") {
      confirmed.push(confirmedHost(observation.hostname, confirmation, {
        source: isListed ? DISCOVERY_DEPTH_ASSET_SOURCES.nsec : source,
      }));
    }
  }
  return { confirmed, counts };
}

// Walk the zone's NSEC chain, one question at a time, within the query bound,
// the shared question budget and the soft time budget. Owner names are names
// the zone itself lists.
async function walkNsec(domain, nsecLookup, { clock, deadlineAt, maxQueries, budget }) {
  let state;
  try { state = createNsecWalkState({ domain, maxQueries }); } catch { return { outcome: "invalid_domain", queries: 0, owners: [] }; }
  let outcome = null;
  for (let name = nextNsecQuery(state); name !== null; name = nextNsecQuery(state)) {
    if (clock() >= deadlineAt) { outcome = "time_budget_reached"; break; }
    if (budget && !budget.take("discovery_depth", 1)) { outcome = "question_budget_reached"; break; }
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

// The parent a guess was derived under, when that is not the scanned domain.
function guessParent(hostname, root) {
  const parent = hostname.slice(hostname.indexOf(".") + 1);
  return parent !== root && parent.endsWith(`.${root}`) ? parent : null;
}

// Does a parent below the domain answer for any name? One random label, both
// families. Only a positive answer counts as a wildcard; anything else leaves
// the parent unfiltered and says so.
async function probeSubzoneWildcards(parents, lookup, { budget, random }) {
  const results = new Map();
  const outcomes = [];
  for (const parent of parents) {
    if (budget && !budget.take("discovery_depth", 2)) { outcomes.push({ parent, outcome: "not_asked" }); continue; }
    const label = `cybermeters-wildcard-check-${random().toString(36).slice(2, 10)}`;
    const { observations } = await lookupNames([`${label}.${parent}`], lookup, { batchSize: 1, mode: "parallel" });
    const confirmation = confirmationOf(observations[0]);
    if (confirmation.status === "confirmed" && confirmation.addresses.length > 0) {
      results.set(parent, wildcardAddressSet(confirmation.dns.A.addresses, confirmation.dns.AAAA.addresses));
      outcomes.push({ parent, outcome: "wildcard" });
    } else {
      outcomes.push({ parent, outcome: confirmation.status === "not_found" || confirmation.status === "no_address" ? "no_wildcard" : "unknown" });
    }
  }
  return { results, outcomes };
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
  wildcardIpv6Addresses = [],
  rotationIndex = 0,
  budget = null,
  accounting = null,
  cache = null,
  signal = null,
  clock = now,
  random = Math.random,
  lookup = (name, type) => dnsQuery(name, type, { accounting, cache, signal }),
  nsecLookup = (name, type) => dnsQueryDnssec(name, type, { accounting, cache, signal }),
} = {}) {
  const root = normalizeHostname(domain);
  if (!root) return discoveryDepthNotExecuted("invalid_domain");
  const limits = DISCOVERY_DEPTH_LIMITS;
  const startedAt = clock();
  const deadlineAt = startedAt + limits.softBudgetMs;
  const hardDeadlineAt = startedAt + limits.budgetMs - 500;
  const apexWildcard = wildcardAddressSet(wildcardAddresses, wildcardIpv6Addresses);
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
  // A word-list or variant guess answered exactly by the zone's wildcard A
  // answer is filtered whatever its AAAA says: AAAA is not asked for it.
  const apexA = apexWildcard.A;
  const wildcardShapedA = (observation) => {
    if (apexA.size === 0 || observation?.outcome !== "answer") return false;
    const addresses = (observation.records || []).filter((record) => record.type === "A").map((record) => String(record.data).toLowerCase());
    return addresses.length === apexA.size && addresses.every((address) => apexA.has(address));
  };
  const guessOptions = { clock, deadlineAt, hardDeadlineAt, batchSize: limits.batchSize, budget, source: "discovery_depth", mode: "sequential", wildcardShapedA };

  // Word-list slice and NSEC walk run side by side; variants need the slice's
  // answers first.
  const rotation = wordlistRotation(rotationIndex);
  const sliceNames = fresh(rotation.labels.map((label) => normalizeHostname(`${label}.${root}`)));
  const [sliceRun, walk] = await Promise.all([
    lookupNames(sliceNames, lookup, guessOptions),
    walkNsec(root, nsecLookup, { clock, deadlineAt, maxQueries: limits.nsecQueries, budget }),
  ]);
  const listed = new Set(walk.owners);
  const wordlist = tally(sliceRun.observations, DISCOVERY_DEPTH_ASSET_SOURCES.wordlist, { wildcardFor: () => apexWildcard, filterWildcard: true, listed });

  // A name the zone lists keeps the NSEC source and is never wildcard-
  // filtered, whichever lookup asked it (`listed`).
  const nsecFresh = fresh(walk.owners);
  const nsecNames = nsecFresh.slice(0, limits.nsecConfirmations);
  const nsecNotChecked = nsecFresh.length - nsecNames.length;
  const variantInputs = [...strings(discoveredHosts), ...wordlist.confirmed.map((item) => item.hostname)];
  const derived = deriveNameVariants(variantInputs, { domain: root, max: limits.variants }).map((item) => item.hostname);
  const variantNames = fresh(derived);
  // Variants below a sub-zone are only evidence when that sub-zone does not
  // answer every name itself.
  const parentCounts = new Map();
  for (const name of variantNames) {
    const parent = guessParent(name, root);
    if (parent) parentCounts.set(parent, (parentCounts.get(parent) || 0) + 1);
  }
  const parents = [...parentCounts].sort((a, b) => b[1] - a[1] || compare(a[0], b[0])).map(([parent]) => parent);
  const checkedParents = parents.slice(0, limits.subzoneWildcardChecks);
  const subzones = await probeSubzoneWildcards(checkedParents, lookup, { budget, random });
  // A variant whose parent's wildcard could not be settled is not asked: its
  // answer could not be told apart from that wildcard's.
  const settled = new Set(subzones.outcomes
    .filter((item) => item.outcome === "wildcard" || item.outcome === "no_wildcard")
    .map((item) => item.parent));
  const askable = variantNames.filter((name) => {
    const parent = guessParent(name, root);
    return !parent || settled.has(parent);
  });
  const variantsUnchecked = variantNames.length - askable.length;
  const [variantRun, nsecRun] = await Promise.all([
    lookupNames(askable, lookup, guessOptions),
    // Names the zone lists are not guesses: both families are always asked.
    lookupNames(nsecNames, lookup, { ...guessOptions, wildcardShapedA: null }),
  ]);
  const wildcardForVariant = (hostname) => {
    const parent = hostname ? guessParent(hostname, root) : null;
    return (parent && subzones.results.get(parent)) || apexWildcard;
  };
  const variants = tally(variantRun.observations, DISCOVERY_DEPTH_ASSET_SOURCES.variant, { wildcardFor: wildcardForVariant, filterWildcard: true, listed });
  // Names the zone lists are not guesses: a wildcard-shaped answer is flagged,
  // not filtered.
  const nsec = tally(nsecRun.observations, DISCOVERY_DEPTH_ASSET_SOURCES.nsec, { wildcardFor: () => apexWildcard, filterWildcard: false });

  const notAskedTime = sliceRun.unasked_time + variantRun.unasked_time + nsecRun.unasked_time;
  const notAskedBudget = sliceRun.unasked_budget + variantRun.unasked_budget + nsecRun.unasked_budget;
  const lookupFailed = wordlist.counts.lookup_failed + variants.counts.lookup_failed + nsec.counts.lookup_failed;
  const reasons = [];
  if (notAskedTime > 0) reasons.push("time_budget_reached");
  if (notAskedBudget > 0) reasons.push("question_budget_reached");
  if (variantsUnchecked > 0) reasons.push("subzone_wildcard_unsettled");
  if (lookupFailed > 0) reasons.push("lookup_failed");
  if (nsecNotChecked > 0) reasons.push("nsec_confirmation_cap_reached");
  if (["budget_exhausted", "lookup_failed", "dns_error", "invalid_response", "truncated_response", "time_budget_reached", "question_budget_reached"].includes(walk.outcome)) {
    reasons.push(`nsec_${walk.outcome}`);
  }
  const counted = (counts) => {
    const { families, family_uncertain: _uncertain, found, ...rest } = counts;
    return { found, ...rest };
  };
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
      ...counted(wordlist.counts),
    },
    variants: {
      derived: derived.length,
      checked: variantRun.observations.length,
      ...counted(variants.counts),
      not_asked_unsettled_parent: variantsUnchecked,
      subzone_wildcards: subzones.outcomes,
    },
    nsec: {
      outcome: walk.outcome,
      queries: walk.queries,
      owners: walk.owners.length,
      checked: nsecRun.observations.length,
      not_checked: nsecNotChecked,
      ...counted(nsec.counts),
    },
    confirmed: [...wordlist.confirmed, ...variants.confirmed, ...nsec.confirmed],
    not_asked: notAskedTime + notAskedBudget + variantsUnchecked,
    incomplete: reasons.length > 0,
    incomplete_reason: reasons[0] ?? null,
    ...(reasons.length > 1 ? { incomplete_reasons: reasons } : {}),
  };
}
