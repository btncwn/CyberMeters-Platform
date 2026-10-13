// ── DNS answers per address family, as evidence ─────────────────────────────
// The shared discovery confirmation (A and AAAA kept apart: an answer, an
// alias, NXDOMAIN, NODATA, a failure, or not asked) compacted for storage with
// an asset's evidence: at most eight addresses per family and five alias hops,
// no TTLs and no raw answers. Used by discovery evidence and by the web check's
// own re-check questions (runExposureModule), so both read the same way.
import { normalizeHostname } from "./hostnames.js";
import { classifyDiscoveryDnsResponse } from "./discovery-dns-observation.js";
import { confirmationOf } from "./discovery-confirmation.js";

export const DNS_EVIDENCE_LIMITS = Object.freeze({
  addressesPerFamily: 8,
  aliasHops: 5,
});

const compare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

export function compactFamily(family) {
  if (!family || typeof family !== "object") return { outcome: "not_asked", addresses: [] };
  const addresses = (Array.isArray(family.addresses) ? family.addresses : [])
    .filter((address) => typeof address === "string").map((address) => address.toLowerCase()).sort(compare);
  return {
    outcome: typeof family.outcome === "string" ? family.outcome : "invalid",
    addresses: addresses.slice(0, DNS_EVIDENCE_LIMITS.addressesPerFamily),
    ...(addresses.length > DNS_EVIDENCE_LIMITS.addressesPerFamily ? { more_addresses: addresses.length - DNS_EVIDENCE_LIMITS.addressesPerFamily } : {}),
    ...(typeof family.reason === "string" && family.outcome === "not_asked" ? { reason: family.reason } : {}),
  };
}

// A discovery confirmation's `dns` block, compacted.
export function compactConfirmationDns(dns, source) {
  if (!dns || typeof dns !== "object") return null;
  if (dns.MX && !dns.A && !dns.AAAA) {
    const exchanges = (Array.isArray(dns.MX.exchanges) ? dns.MX.exchanges : []).filter((value) => typeof value === "string");
    return { source, MX: { outcome: dns.MX.outcome === "answer" ? "answer" : "invalid", exchanges: exchanges.slice(0, DNS_EVIDENCE_LIMITS.addressesPerFamily) } };
  }
  const chain = (Array.isArray(dns.cname_chain) ? dns.cname_chain : [])
    .map((hop) => normalizeHostname(hop?.target)).filter(Boolean).slice(0, DNS_EVIDENCE_LIMITS.aliasHops);
  const uncertain = (Array.isArray(dns.uncertain) ? dns.uncertain : []).filter((type) => type === "A" || type === "AAAA");
  return {
    source,
    A: compactFamily(dns.A),
    AAAA: compactFamily(dns.AAAA),
    ...(chain.length ? { alias_chain: chain } : {}),
    ...(uncertain.length ? { uncertain } : {}),
  };
}

/**
 * What the web check's own A and AAAA questions said about a host, in the
 * shared discovery vocabulary. `a` and `aaaa` are settled promises of DoH
 * answers. Kept beside the removal signal, which stays unchanged.
 */
export function exposureDnsEvidence(host, a, aaaa) {
  const hostname = normalizeHostname(host);
  if (!hostname) return null;
  const classify = (settled, recordType) => (settled?.status === "fulfilled"
    ? classifyDiscoveryDnsResponse({ hostname, recordType, response: settled.value })
    : classifyDiscoveryDnsResponse({ hostname, recordType, error: settled?.reason ?? new Error("lookup_failed") }));
  const confirmation = confirmationOf({ hostname, A: classify(a, "A"), AAAA: classify(aaaa, "AAAA"), aaaa_skipped: null });
  return confirmation.dns ? compactConfirmationDns(confirmation.dns, "web_check") : null;
}
