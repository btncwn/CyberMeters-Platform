// ── Page references ──────────────────────────────────────────────────────────
// Hostnames under the scanned domain that the site's own robots.txt, sitemaps
// and first-party scripts name, as read by page discovery. They arrive after
// this scan's takeover and exposure checks, so a confirmed name joins the
// inventory now and gets those checks from the next scan's inventory re-check.
// Each is asked for A and AAAA through the shared confirmation rule; a name
// joins only when DNS answers for it.
import { dnsQuery } from "./dns.js";
import { normalizeHostname } from "./hostname-candidates.js";
import { confirmationOf, confirmedHost, lookupNames, tallyConfirmation, wildcardAddressSet } from "./discovery-confirmation.js";

export const PAGE_REFERENCES_VERSION = "page-references-v1";

export const PAGE_REFERENCE_LIMITS = Object.freeze({
  maxChecks: 50,
  budgetMs: 7_000,
});

// Evidence source → asset source. Key order is precedence.
export const PAGE_REFERENCE_ASSET_SOURCES = Object.freeze({
  robots_txt: "robots_reference",
  sitemap:    "sitemap_reference",
  javascript: "script_reference",
});
const RANK = new Map(Object.keys(PAGE_REFERENCE_ASSET_SOURCES).map((source, index) => [source, index]));
const compare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const bestRank = (sources) => Math.min(...sources.map((source) => RANK.get(source) ?? RANK.size));

export function pageReferencesNotExecuted(reason, candidates = 0) {
  const gap = !["no_references"].includes(reason);
  return {
    version: PAGE_REFERENCES_VERSION,
    executed: false,
    reason,
    candidates_found: candidates,
    confirmed: [],
    incomplete: gap,
    incomplete_reason: gap ? reason : null,
  };
}

// The page-discovery candidates not already known, best source first.
export function pendingPageReferences(domain, references, known = []) {
  const root = normalizeHostname(domain);
  const seen = new Set((Array.isArray(known) ? known : []).map((host) => normalizeHostname(host)).filter(Boolean));
  const pending = [];
  for (const candidate of Array.isArray(references?.candidates) ? references.candidates : []) {
    const hostname = normalizeHostname(candidate?.hostname);
    if (!root || !hostname || hostname === root || !hostname.endsWith(`.${root}`) || seen.has(hostname)) continue;
    const sources = (Array.isArray(candidate.sources) ? candidate.sources : []).filter((source) => RANK.has(source));
    if (!sources.length) continue;
    seen.add(hostname);
    pending.push({ hostname, sources: [...sources].sort(compare) });
  }
  return pending.sort((a, b) => (bestRank(a.sources) - bestRank(b.sources)) || compare(a.hostname, b.hostname));
}

/**
 * Confirm at most maxChecks pending names. Names a site's own files name are
 * not guesses: a wildcard-shaped answer is flagged, not filtered.
 */
export async function confirmPageReferences(pending, {
  wildcardAddresses = [],
  wildcardIpv6Addresses = [],
  budget = null,
  accounting = null,
  cache = null,
  signal = null,
  lookup = (name, type) => dnsQuery(name, type, { accounting, cache, signal }),
} = {}) {
  const list = Array.isArray(pending) ? pending : [];
  const checks = list.slice(0, PAGE_REFERENCE_LIMITS.maxChecks);
  const { observations, unasked_budget: notAsked } = await lookupNames(checks.map((item) => item.hostname), lookup, {
    batchSize: PAGE_REFERENCE_LIMITS.maxChecks,
    budget,
    source: "page_references",
    mode: "parallel",
  });
  const wildcardSet = wildcardAddressSet(wildcardAddresses, wildcardIpv6Addresses);
  const byHost = new Map(observations.map((observation) => [observation.hostname, observation]));
  const confirmed = [];
  const counts = {};
  for (const item of checks) {
    const observation = byHost.get(item.hostname);
    if (!observation) continue;
    const confirmation = confirmationOf(observation, { wildcardSet, filterWildcard: false });
    tallyConfirmation(counts, confirmation);
    if (confirmation.status === "confirmed") {
      const best = item.sources.reduce((a, b) => (RANK.get(a) <= RANK.get(b) ? a : b));
      confirmed.push(confirmedHost(item.hostname, confirmation, {
        sources: item.sources,
        asset_source: PAGE_REFERENCE_ASSET_SOURCES[best],
      }));
    }
  }
  const notChecked = list.length - checks.length;
  const reasons = [];
  if (notChecked > 0) reasons.push("check_cap_reached");
  if (notAsked > 0) reasons.push("question_budget_reached");
  if ((counts.lookup_failed || 0) > 0) reasons.push("lookup_failed");
  return {
    version: PAGE_REFERENCES_VERSION,
    executed: true,
    reason: null,
    candidates_found: list.length,
    checked: observations.length,
    not_checked: notChecked + notAsked,
    confirmed,
    not_found: counts.not_found || 0,
    no_address: counts.no_address || 0,
    lookup_failed: counts.lookup_failed || 0,
    not_asked: notAsked,
    families: counts.families || { ipv4_only: 0, ipv6_only: 0, dual_stack: 0, alias_only: 0 },
    incomplete: reasons.length > 0,
    incomplete_reason: reasons[0] ?? null,
    ...(reasons.length > 1 ? { incomplete_reasons: reasons } : {}),
  };
}
