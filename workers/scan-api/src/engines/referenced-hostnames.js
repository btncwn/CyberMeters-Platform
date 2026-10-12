// ── Referenced hostnames ─────────────────────────────────────────────────────
// Hostnames under the scanned domain that the customer's own published
// configuration names: the live certificate, the website's security and link
// headers, its redirects, and the domain's mail, name-server, SPF, DMARC and
// BIMI records. They are read from evidence this scan already holds — nothing extra
// is fetched to find them — and each is confirmed with one bounded DNS lookup
// before it joins discovery. A name only counts as discovered when DNS answers
// for it; a reference alone never does.
import { dnsQuery } from "./dns.js";
import { extractHostnameCandidates, normalizeHostname } from "./hostname-candidates.js";
import {
  extractFromBimiRecord,
  extractFromCorsHeader,
  extractFromDmarcRecord,
  extractFromLinkHeader,
  extractFromRedirectChain,
} from "./discovery-extractors.js";
import { extractFromSpfRecords } from "./discovery-dns-extractors.js";
import { confirmationOf, confirmedHost, lookupNames, wildcardAddressSet } from "./discovery-confirmation.js";

export const REFERENCED_HOSTNAMES_VERSION = "referenced-hostnames-v1";

// At most maxChecks names are looked up per scan; the rest are counted, never
// silently dropped. The lookups run in parallel and each DoH request carries
// its own 6s timeout, so budgetMs (the step's hard bound) always outlasts them
// and no lookup is left in flight when the step returns.
export const REFERENCED_HOSTNAME_LIMITS = Object.freeze({
  maxChecks: 50,
  budgetMs: 7_000,
});

// Evidence source → the asset source recorded for a confirmed name. Key order
// is precedence: a name named in several places keeps the first source listed.
export const REFERENCED_HOSTNAME_ASSET_SOURCES = Object.freeze({
  live_tls_san:   "tls_certificate_name",
  mx:             "mx_target",
  ns:             "ns_target",
  spf:            "spf_reference",
  dmarc:          "dmarc_reference",
  bimi:           "bimi_reference",
  redirect_chain: "redirect_reference",
  csp:            "csp_reference",
  link_header:    "link_header_reference",
  cors_header:    "cors_reference",
});

const SOURCE_RANK = new Map(Object.keys(REFERENCED_HOSTNAME_ASSET_SOURCES).map((source, index) => [source, index]));
const compare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

const text = (value) => (typeof value === "string" && value.trim() ? value : null);
const strings = (value) => (Array.isArray(value) ? value.filter((item) => typeof item === "string") : []);

function bestSourceRank(sources) {
  return Math.min(...sources.map((source) => SOURCE_RANK.get(source) ?? SOURCE_RANK.size));
}

export function assetSourceForReferencedSources(sources = []) {
  const known = sources.filter((source) => SOURCE_RANK.has(source));
  if (known.length === 0) return null;
  const best = known.reduce((a, b) => (SOURCE_RANK.get(a) <= SOURCE_RANK.get(b) ? a : b));
  return REFERENCED_HOSTNAME_ASSET_SOURCES[best];
}

// Consecutive request URLs of a redirect chain as {from, to} pairs.
function redirectPairs(ssl, headers) {
  const pairs = [];
  const chain = ssl?.http_redirect_chain;
  const hops = Array.isArray(chain?.hop_observations) ? chain.hop_observations : [];
  const urls = hops.map((hop) => text(hop?.url)).filter(Boolean);
  const finalUrl = text(chain?.final_url);
  if (finalUrl && urls[urls.length - 1] !== finalUrl) urls.push(finalUrl);
  for (let i = 0; i + 1 < urls.length; i++) pairs.push({ from: urls[i], to: urls[i + 1] });
  for (const pair of Array.isArray(headers?.raw_capture?.redirect_chain) ? headers.raw_capture.redirect_chain : []) {
    if (text(pair?.from) && text(pair?.to)) pairs.push({ from: pair.from, to: pair.to });
  }
  return pairs;
}

/**
 * Read in-scope hostname candidates from evidence the scan already holds.
 * Pure: no network, storage or clock. Names outside the scanned domain, the
 * domain itself, wildcard names and malformed values are never candidates.
 */
export function collectReferencedHostnames(domain, { ssl = null, headers = null, dns = null, spfRecord = null, dmarcRecord = null, bimiRecord = null, observedAt = null } = {}) {
  const root = normalizeHostname(domain);
  const evidence = [];
  const sets = [];
  if (!root) return { candidates: [], evidence_inputs: [], truncated: false };
  const options = { domain: root, observedAt };

  const live = ssl?.live_certificate?.collection_complete === true ? ssl.live_certificate : null;
  const liveNames = strings(live?.dns_names);
  const mxValues = strings((Array.isArray(dns?.mx_records) ? dns.mx_records : []).map((record) => record?.value));
  const nameservers = strings(dns?.nameservers);
  const snapshot = headers?.raw_capture?.headers_snapshot && typeof headers.raw_capture.headers_snapshot === "object"
    ? headers.raw_capture.headers_snapshot
    : {};
  const csp = [text(snapshot["content-security-policy"]), text(snapshot["content-security-policy-report-only"])]
    .filter(Boolean).join(", ") || null;

  const core = {};
  if (liveNames.length) { core.liveTlsDnsNames = liveNames; evidence.push("live_tls_san"); }
  if (mxValues.length) { core.mxValues = mxValues; evidence.push("mx"); }
  if (nameservers.length) { core.nameservers = nameservers; evidence.push("ns"); }
  if (csp) { core.csp = csp; evidence.push("csp"); }
  if (Object.keys(core).length) sets.push(extractHostnameCandidates({ domain: root, observedAt, sources: core }));

  const link = text(snapshot.link);
  if (link) {
    evidence.push("link_header");
    sets.push(extractFromLinkHeader(link, { ...options, baseUrl: text(headers?.response_url) || `https://${root}/` }));
  }
  const cors = text(snapshot["access-control-allow-origin"]);
  if (cors) { evidence.push("cors_header"); sets.push(extractFromCorsHeader(cors, options)); }
  const redirects = redirectPairs(ssl, headers);
  if (redirects.length) { evidence.push("redirect_chain"); sets.push(extractFromRedirectChain(redirects, options)); }
  const spf = text(spfRecord);
  if (spf) { evidence.push("spf"); sets.push(extractFromSpfRecords(spf, options)); }
  const dmarc = text(dmarcRecord);
  if (dmarc) { evidence.push("dmarc"); sets.push(extractFromDmarcRecord(dmarc, options)); }
  const bimi = text(bimiRecord);
  if (bimi) { evidence.push("bimi"); sets.push(extractFromBimiRecord(bimi, options)); }

  const merged = new Map();
  let truncated = false;
  for (const set of sets) {
    truncated ||= set?.truncated === true;
    for (const candidate of Array.isArray(set?.candidates) ? set.candidates : []) {
      const hostname = normalizeHostname(candidate?.hostname);
      if (!hostname || hostname === root || !hostname.endsWith(`.${root}`)) continue;
      const sources = strings(candidate.sources).filter((source) => SOURCE_RANK.has(source));
      if (!sources.length) continue;
      if (!merged.has(hostname)) merged.set(hostname, new Set());
      for (const source of sources) merged.get(hostname).add(source);
    }
  }
  const candidates = [...merged]
    .map(([hostname, sources]) => ({ hostname, sources: [...sources].sort(compare) }))
    .sort((a, b) => (bestSourceRank(a.sources) - bestSourceRank(b.sources)) || compare(a.hostname, b.hostname));
  return { candidates, evidence_inputs: [...new Set(evidence)].sort(compare), truncated };
}

// The step did not run: the reason says why, and nothing is claimed.
export function referencedHostnamesNotExecuted(reason, collected = null) {
  return {
    version: REFERENCED_HOSTNAMES_VERSION,
    executed: false,
    reason,
    evidence_inputs: collected?.evidence_inputs ?? [],
    candidates_found: collected ? collected.candidates.length : 0,
    checked: 0,
    not_checked: collected ? collected.candidates.length : 0,
    confirmed: [],
    not_found: 0,
    no_address: 0,
    lookup_failed: 0,
    incomplete: true,
    incomplete_reason: reason,
  };
}

/**
 * Confirm candidates with one DNS A lookup each. A name that answers with an
 * address, or with an alias chain whose end has no address, joins discovery;
 * a name DNS says does not exist, or has no IPv4 address, does not. Names
 * already discovered (`exclude`) are not looked up again.
 */
export async function confirmReferencedHostnames(domain, collected, {
  exclude = [],
  wildcardAddresses = [],
  accounting = null,
  cache = null,
  signal = null,
  lookup = (name, type) => dnsQuery(name, type, { accounting, cache, signal }),
} = {}) {
  const root = normalizeHostname(domain);
  const known = new Set(strings(exclude).map((host) => normalizeHostname(host)).filter(Boolean));
  const pending = (collected?.candidates || []).filter((candidate) => !known.has(candidate.hostname) && candidate.hostname !== root);
  const checks = pending.slice(0, REFERENCED_HOSTNAME_LIMITS.maxChecks);
  const notChecked = pending.length - checks.length;
  const wildcardSet = wildcardAddressSet(wildcardAddresses);

  // One batch: every check runs in parallel and each DoH question carries its
  // own timeout, so nothing is left in flight when the step returns.
  const { observations } = await lookupNames(checks.map((candidate) => candidate.hostname), lookup, {
    batchSize: REFERENCED_HOSTNAME_LIMITS.maxChecks,
  });

  const confirmed = [];
  let notFound = 0, noAddress = 0, lookupFailed = 0;
  checks.forEach((candidate, index) => {
    // A referenced name is not a guess: a wildcard-shaped answer is flagged.
    const confirmation = confirmationOf(observations[index], { wildcardSet, filterWildcard: false });
    if (confirmation.status === "confirmed") {
      confirmed.push(confirmedHost(candidate.hostname, confirmation, {
        sources: candidate.sources,
        asset_source: assetSourceForReferencedSources(candidate.sources),
      }));
    } else if (confirmation.status === "not_found") notFound++;
    else if (confirmation.status === "no_address") noAddress++;
    else lookupFailed++;
  });

  const reasons = [];
  if (notChecked > 0) reasons.push("check_cap_reached");
  if (lookupFailed > 0) reasons.push("lookup_failed");
  return {
    version: REFERENCED_HOSTNAMES_VERSION,
    executed: true,
    reason: null,
    evidence_inputs: collected?.evidence_inputs ?? [],
    candidates_found: pending.length,
    checked: checks.length,
    not_checked: notChecked,
    confirmed,
    not_found: notFound,
    no_address: noAddress,
    lookup_failed: lookupFailed,
    incomplete: reasons.length > 0,
    incomplete_reason: reasons[0] ?? null,
    ...(reasons.length > 1 ? { incomplete_reasons: reasons } : {}),
  };
}

// Confirmed names, appended after the names discovery already holds.
export function withConfirmedReferences(discovered = [], referenced = null) {
  const base = Array.isArray(discovered) ? discovered : [];
  const seen = new Set(base);
  const added = [];
  for (const item of Array.isArray(referenced?.confirmed) ? referenced.confirmed : []) {
    if (typeof item?.hostname !== "string" || seen.has(item.hostname)) continue;
    seen.add(item.hostname);
    added.push(item.hostname);
  }
  return [...base, ...added];
}
