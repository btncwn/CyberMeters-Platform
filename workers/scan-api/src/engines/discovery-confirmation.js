// ── Discovery confirmation ───────────────────────────────────────────────────
// The one rule every discovery source uses to turn a candidate hostname into a
// discovered one: DNS answers for the name. Shared by the fixed name check,
// SRV targets, home-page links, configuration references, customer lists, the
// rotating word list, name variants, the NSEC walk and page references, so no
// source can admit on weaker evidence than another.
//
// Each name is asked for both address families. What each family said is kept
// apart — an answer, an alias, NXDOMAIN, NODATA, SERVFAIL, REFUSED, a timeout,
// a transport failure, a malformed answer, or not asked (budget or time) — so
// an IPv6-only name is found, a dual-stack name keeps both address sets, and
// one family failing never erases what the other proved.
//
// A name is discovered when either family returns an address, when it is an
// alias whose target has no address, or when it is an alias whose target does
// not exist (a dangling alias: the name exists and is the classic takeover
// candidate). A discovered name is never evidence of ownership or of a service:
// an alias target outside the scanned domain stays a third party's name.
import { classifyDiscoveryDnsResponse } from "./discovery-dns-observation.js";

const compare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

// ── One question budget for all of discovery ────────────────────────────────
// The total is the sum of the per-source question caps discovery already had
// (wildcard check 2, fixed name check 56, references 50, customer list 200,
// word list / variants / NSEC walk and its confirmations 428, page references
// 50). Asking AAAA as well spends from the same total: every question — an
// address question, an alias chain the resolver follows inside one question,
// an NSEC step, a derived variant — is charged here, and a source that finds
// the budget spent reports its names as not asked, never as absent.
export const DISCOVERY_DNS_QUESTION_BUDGET = 786;

export function createDiscoveryQuestionBudget({ total = DISCOVERY_DNS_QUESTION_BUDGET } = {}) {
  const limit = Number.isSafeInteger(total) && total >= 0 ? total : DISCOVERY_DNS_QUESTION_BUDGET;
  let spent = 0;
  const bySource = {};
  const refused = {};
  const reserved = new Map();
  const heldFor = (source) => {
    let held = 0;
    for (const [owner, questions] of reserved) if (owner !== source) held += questions;
    return held;
  };
  const budget = {
    total: limit,
    available(source) {
      return Math.max(0, limit - spent - heldFor(source));
    },
    // Charge `questions` to `source`, all or nothing.
    take(source, questions = 1) {
      if (budget.available(source) < questions) {
        refused[source] = (refused[source] || 0) + questions;
        return false;
      }
      spent += questions;
      bySource[source] = (bySource[source] || 0) + questions;
      if (reserved.has(source)) reserved.set(source, Math.max(0, reserved.get(source) - questions));
      return true;
    },
    // Hold questions back for a source that runs later in the scan.
    reserve(source, questions) {
      const amount = Number.isSafeInteger(questions) && questions > 0 ? questions : 0;
      reserved.set(source, Math.min(amount, Math.max(0, limit - spent - heldFor(source))));
    },
    release(source) {
      reserved.delete(source);
    },
    snapshot() {
      return {
        version: "discovery-question-budget-v1",
        total: limit,
        spent,
        remaining: Math.max(0, limit - spent),
        by_source: { ...bySource },
        refused: { ...refused },
      };
    },
  };
  return budget;
}

// ── Wildcard answers ────────────────────────────────────────────────────────
// The zone's answer for a random name, per family. An empty family set means
// that family had no wildcard answer.
export function wildcardAddressSet(addresses = [], ipv6Addresses = null) {
  const set = (values) => new Set((Array.isArray(values) ? values : [])
    .filter((address) => typeof address === "string")
    .map((address) => address.toLowerCase()));
  const a = set(addresses);
  // Called with one list (older callers): A answers only.
  if (ipv6Addresses === null) return a;
  return { A: a, AAAA: set(ipv6Addresses), families: true };
}

function wildcardFamilies(value) {
  if (value?.families === true) return value;
  return { A: value instanceof Set ? value : new Set(), AAAA: new Set(), families: true };
}

// ── Asking ──────────────────────────────────────────────────────────────────
// A DoH question carries its own six-second timeout; asking AAAA after A is
// only started when one more question still fits before the hard deadline.
export const DISCOVERY_QUESTION_TIMEOUT_MS = 6_000;

async function ask(lookup, hostname, type) {
  let response = null, error = null;
  try { response = await lookup(hostname, type); } catch (err) { error = err ?? new Error("lookup_failed"); }
  return classifyDiscoveryDnsResponse({ hostname, recordType: type, ...(error ? { error } : { response }) });
}

/**
 * Ask each name for A and AAAA, in batches. No new batch starts once `clock()`
 * reaches `deadlineAt`. With a budget, every question is charged to `source`.
 *
 *   mode "parallel"   — A and AAAA together (one round trip; for names a
 *                       source states exist: references, lists, the fixed
 *                       name check).
 *   mode "sequential" — A first; AAAA only when A did not prove the name does
 *                       not exist (for guesses, where most names do not
 *                       exist), and only when it still fits before
 *                       `hardDeadlineAt`.
 *
 * Returns one observation per asked name: { hostname, A, AAAA, aaaa_skipped }
 * where A/AAAA are classified DNS observations or null, and counts of names
 * never asked because of time or budget.
 */
export async function lookupNames(names, lookup, {
  clock = Date.now,
  deadlineAt = Infinity,
  hardDeadlineAt = Infinity,
  batchSize = 25,
  budget = null,
  source = "discovery",
  mode = "parallel",
  // Sequential mode only: a guess whose A answer is exactly the zone's
  // wildcard answer is filtered whatever AAAA says, so AAAA is not asked.
  wildcardShapedA = null,
} = {}) {
  const observations = [];
  let unaskedTime = 0, unaskedBudget = 0;
  const size = Number.isSafeInteger(batchSize) && batchSize > 0 ? batchSize : 25;
  const list = Array.isArray(names) ? names : [];
  for (let start = 0; start < list.length; start += size) {
    if (clock() >= deadlineAt) { unaskedTime += list.length - start; break; }
    const batch = await Promise.all(list.slice(start, start + size).map(async (hostname) => {
      if (mode === "parallel") {
        const both = !budget || budget.take(source, 2);
        if (!both && !budget.take(source, 1)) return { hostname, A: null, AAAA: null, not_asked: "budget" };
        const [A, AAAA] = await Promise.all([
          ask(lookup, hostname, "A"),
          both ? ask(lookup, hostname, "AAAA") : Promise.resolve(null),
        ]);
        return { hostname, A, AAAA, aaaa_skipped: both ? null : "budget" };
      }
      if (budget && !budget.take(source, 1)) return { hostname, A: null, AAAA: null, not_asked: "budget" };
      const A = await ask(lookup, hostname, "A");
      if (A.outcome === "nxdomain") return { hostname, A, AAAA: null, aaaa_skipped: "name_does_not_exist" };
      if (typeof wildcardShapedA === "function" && wildcardShapedA(A)) return { hostname, A, AAAA: null, aaaa_skipped: "wildcard_shaped" };
      if (clock() + DISCOVERY_QUESTION_TIMEOUT_MS > hardDeadlineAt) return { hostname, A, AAAA: null, aaaa_skipped: "time" };
      if (budget && !budget.take(source, 1)) return { hostname, A, AAAA: null, aaaa_skipped: "budget" };
      return { hostname, A, AAAA: await ask(lookup, hostname, "AAAA"), aaaa_skipped: null };
    }));
    for (const observation of batch) {
      if (observation.not_asked === "budget") unaskedBudget++;
      else observations.push(observation);
    }
  }
  return { observations, unasked: unaskedTime + unaskedBudget, unasked_time: unaskedTime, unasked_budget: unaskedBudget };
}

// ── What a family said ──────────────────────────────────────────────────────
const UNCERTAIN = new Set(["servfail", "refused", "timeout", "transport_error", "invalid", "not_asked"]);

function familyOutcome(observation, type, skipped = null) {
  if (!observation) return { outcome: "not_asked", reason: skipped ?? "not_asked", addresses: [] };
  const addresses = (observation.records || [])
    .filter((record) => record.type === type)
    .map((record) => String(record.data).toLowerCase())
    .sort(compare);
  switch (observation.outcome) {
    case "answer": return { outcome: "answer", addresses };
    case "cname_only": return { outcome: "alias", addresses: [] };
    case "nxdomain":
      return observation.cname_chain?.length
        ? { outcome: "dangling_alias", addresses: [] }
        : { outcome: "nxdomain", addresses: [] };
    case "nodata": return { outcome: "nodata", addresses: [] };
    case "servfail": return { outcome: "servfail", addresses: [] };
    case "refused": return { outcome: "refused", addresses: [] };
    case "timeout": return { outcome: "timeout", addresses: [] };
    case "transport_error": return { outcome: "transport_error", addresses: [] };
    default: return { outcome: "invalid", reason: observation.reason ?? observation.outcome ?? null, addresses: [] };
  }
}

function sameSet(addresses, set) {
  return addresses.length === set.size && addresses.every((address) => set.has(address));
}

/**
 * What one name's observations say:
 *   confirmed         — an address in either family, an alias with no address
 *                       at its end, or a dangling alias;
 *   wildcard_filtered — a guess answered exactly by the zone's wildcard answer
 *                       (only when `filterWildcard`: a guess is not evidence);
 *   not_found         — NXDOMAIN;
 *   no_address        — the name exists and has no address in either family;
 *   lookup_failed     — no positive answer, and at least one family failed or
 *                       the families disagree (uncertain, never absent);
 *   not_asked         — the budget ran out before the name was asked.
 *
 * Accepts the pair observations lookupNames returns, or a single classified A
 * observation (older callers; AAAA then reads as not asked).
 */
export function confirmationOf(observation, { wildcardSet = new Set(), filterWildcard = false } = {}) {
  const pair = observation && ("A" in observation || "AAAA" in observation || observation.not_asked)
    ? observation
    : { hostname: observation?.hostname, A: observation ?? null, AAAA: null, aaaa_skipped: "not_asked" };
  if (pair.not_asked === "budget") return { status: "not_asked", reason: "budget" };
  const A = familyOutcome(pair.A, "A");
  const AAAA = familyOutcome(pair.AAAA, "AAAA", pair.aaaa_skipped);
  const families = [A, AAAA];
  const cnameChain = (pair.A?.cname_chain?.length ? pair.A.cname_chain : pair.AAAA?.cname_chain) || [];
  const dns = {
    A: { outcome: A.outcome, addresses: A.addresses, ...(A.reason ? { reason: A.reason } : {}) },
    AAAA: { outcome: AAAA.outcome, addresses: AAAA.addresses, ...(AAAA.reason ? { reason: AAAA.reason } : {}) },
    ...(cnameChain.length ? { cname_chain: cnameChain.map((hop) => ({ name: hop.name, target: hop.target })) } : {}),
  };

  const positive = families.some((family) => family.outcome === "answer");
  const alias = families.some((family) => family.outcome === "alias");
  const dangling = families.some((family) => family.outcome === "dangling_alias");
  if (positive || alias || dangling) {
    // One family positive while the other says the name does not exist is a
    // disagreement, kept as uncertainty beside the address that was found.
    const uncertain = ["A", "AAAA"].filter((type) => {
      const family = type === "A" ? A : AAAA;
      return UNCERTAIN.has(family.outcome) || (positive && family.outcome === "nxdomain");
    });
    const addresses = [...A.addresses, ...AAAA.addresses];
    const wildcard = wildcardFamilies(wildcardSet);
    const wildcardKnown = wildcard.A.size > 0 || wildcard.AAAA.size > 0;
    const wildcardMatch = positive && wildcardKnown &&
      sameSet(A.addresses, wildcard.A) &&
      (pair.AAAA ? sameSet(AAAA.addresses, wildcard.AAAA) : true);
    if (wildcardMatch && filterWildcard) return { status: "wildcard_filtered", dns };
    return {
      status: "confirmed",
      addresses,
      alias_only: !positive,
      ...(dangling && !positive && !alias ? { dangling_alias: true } : {}),
      wildcard_match: wildcardMatch,
      dns: { ...dns, ...(uncertain.length ? { uncertain } : {}) },
    };
  }
  if (A.outcome === "nxdomain" && (AAAA.outcome === "nxdomain" || AAAA.outcome === "not_asked")) {
    return { status: "not_found", dns };
  }
  if (A.outcome === "nodata" && AAAA.outcome === "nodata") return { status: "no_address", dns };
  // A single A observation from an older caller: NODATA keeps its old meaning.
  if (A.outcome === "nodata" && AAAA.outcome === "not_asked" && pair.aaaa_skipped === "not_asked") {
    return { status: "no_address", dns };
  }
  return { status: "lookup_failed", dns };
}

// A confirmed discovery row, with flags only when they are true.
export function confirmedHost(hostname, confirmation, extra = {}) {
  return {
    hostname,
    ...extra,
    ip_addresses: confirmation.addresses,
    ...(confirmation.alias_only ? { alias_only: true } : {}),
    ...(confirmation.dangling_alias ? { dangling_alias: true } : {}),
    ...(confirmation.wildcard_match ? { wildcard_match: true } : {}),
    ...(confirmation.dns ? { dns: confirmation.dns } : {}),
  };
}

// Count a confirmation outcome into a result's tallies.
export function tallyConfirmation(counts, confirmation) {
  const key = confirmation.status === "confirmed" ? "found" : confirmation.status;
  counts[key] = (counts[key] || 0) + 1;
  if (confirmation.status === "confirmed") {
    const a = confirmation.dns?.A?.addresses?.length > 0, aaaa = confirmation.dns?.AAAA?.addresses?.length > 0;
    const family = a && aaaa ? "dual_stack" : aaaa ? "ipv6_only" : a ? "ipv4_only" : "alias_only";
    counts.families = counts.families || { ipv4_only: 0, ipv6_only: 0, dual_stack: 0, alias_only: 0 };
    counts.families[family]++;
    if (confirmation.dns?.uncertain?.length) counts.family_uncertain = (counts.family_uncertain || 0) + 1;
  }
  return counts;
}
