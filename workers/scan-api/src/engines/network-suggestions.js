// ── Network target suggestions from Attack Surface discovery ──────────────────
//
// Turns hosts already discovered under the workspace's verified domains into
// suggested Network Assets targets, grouped by public IP address.
//
// Authorization boundary (unchanged): a suggestion never creates a target and
// never starts a scan. Network targets are still created only by the existing
// POST with an explicit literal address and the customer's authorization
// declaration (network-targets.js: "DNS evidence, domains and provider/CDN
// associations never create network authorization"). This module only reads
// stored discovery evidence and, for hosts with no stored address, resolves the
// customer's own hostnames over DoH. It never connects to the hosts.
//
// Shared infrastructure is identified so it is not offered for testing: an
// address in a CDN's published edge ranges, or one reached through a CNAME to a
// known hosting provider, belongs to that provider — a service check there
// would test the provider's shared edge, not a server the customer controls.

import { isPublicProbeAddress } from "../../../network-probe/src/contract.js";
import { providerMetadataForHostname } from "./asset-intel.js";
import { dnsQuery } from "./dns.js";
import { HIGH_VALUE_EXPOSURE_LABELS } from "./subdomains-scan.js";

export const NETWORK_SUGGESTION_VERSION = "network-suggestions-v1";
export const NETWORK_SUGGESTION_LIMITS = Object.freeze({
  assets: 500,          // stored discovery rows read per request
  resolve_hosts: 20,    // hosts without a stored address resolved per request
  addresses_per_host: 8,
  hostnames_per_suggestion: 10,
  suggestions: 50,
});

// Cloudflare's published edge ranges (https://www.cloudflare.com/ips-v4 and
// /ips-v6, retrieved 10 October 2026). Customer origins behind Cloudflare are
// not reachable at these addresses.
const CLOUDFLARE_EDGE_RANGES = Object.freeze([
  "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
  "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
  "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
  "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
  "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
  "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]);

const HIGH_VALUE = new Set(HIGH_VALUE_EXPOSURE_LABELS);

// Canonical text form, matching network-targets.js addressText(): dotted IPv4
// as given, IPv6 through the URL parser's compression.
export function canonicalAddress(raw) {
  const value = String(raw ?? "").trim().toLowerCase();
  if (/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(value)) {
    return value.split(".").every((part) => Number(part) <= 255) ? value : null;
  }
  if (!/^[0-9a-f:]+$/.test(value) || !value.includes(":")) return null;
  try { return new URL(`http://[${value}]/`).hostname.slice(1, -1); } catch { return null; }
}

function addressBits(address) {
  if (address.includes(".")) {
    return { bits: 32, value: address.split(".").reduce((n, b) => (n << 8n) | BigInt(b), 0n) };
  }
  const [left, right] = address.split("::");
  const l = left ? left.split(":") : [];
  const r = right !== undefined && right ? right.split(":") : [];
  const words = address.includes("::") ? [...l, ...Array(8 - l.length - r.length).fill("0"), ...r] : l;
  if (words.length !== 8) return null;
  return { bits: 128, value: words.reduce((n, w) => (n << 16n) | BigInt(`0x${w}`), 0n) };
}

const PARSED_EDGE_RANGES = CLOUDFLARE_EDGE_RANGES.map((cidr) => {
  const [base, prefix] = cidr.split("/");
  const parsed = addressBits(canonicalAddress(base));
  return { ...parsed, prefix: Number(prefix) };
});

export function publishedEdgeProvider(address) {
  const canonical = canonicalAddress(address);
  const parsed = canonical && addressBits(canonical);
  if (!parsed) return null;
  for (const range of PARSED_EDGE_RANGES) {
    if (range.bits !== parsed.bits) continue;
    const shift = BigInt(range.bits - range.prefix);
    if ((parsed.value >> shift) === (range.value >> shift)) return "Cloudflare";
  }
  return null;
}

function hostUnder(host, root) {
  return host === root || host.endsWith(`.${root}`);
}

function firstLabel(host, root) {
  if (host === root) return null;
  return host.slice(0, -(root.length + 1)).split(".")[0] || null;
}

function storedAddresses(value) {
  if (value == null) return null;
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function eligible(asset) {
  return asset
    && asset.status === "active"
    && asset.lifecycle_state !== "confirmed_removed"
    && !Number(asset.wildcard_dns)
    && typeof asset.hostname === "string"
    && typeof asset.domain === "string";
}

// Hosts that need a live lookup: eligible, no stored addresses. High-value
// names first so the bounded resolution budget is spent where risk is.
export function hostsNeedingResolution(assets = [], max = NETWORK_SUGGESTION_LIMITS.resolve_hosts) {
  const rows = assets.filter(eligible).filter((asset) => {
    const stored = storedAddresses(asset.ip_addresses);
    return !stored || stored.length === 0;
  });
  const ranked = rows
    .map((asset) => {
      const host = asset.hostname.toLowerCase();
      const root = asset.domain.toLowerCase();
      return { host, high: hostUnder(host, root) && HIGH_VALUE.has(firstLabel(host, root)) };
    })
    .filter((row, index, all) => all.findIndex((other) => other.host === row.host) === index)
    .sort((a, b) => Number(b.high) - Number(a.high));
  return ranked.slice(0, max).map((row) => row.host);
}

// A + AAAA over DoH for the customer's own hostnames. A failed lookup is simply
// "no address known" for this request — it never fabricates one.
export async function resolveHostAddresses(hosts = [], { dnsQueryImpl = dnsQuery } = {}) {
  const resolved = new Map();
  await Promise.all(hosts.map(async (host) => {
    const answers = await Promise.allSettled([dnsQueryImpl(host, "A"), dnsQueryImpl(host, "AAAA")]);
    const addresses = [];
    for (const answer of answers) {
      if (answer.status !== "fulfilled") continue;
      for (const record of answer.value?.Answer || []) {
        if (record?.type === 1 || record?.type === 28) addresses.push(record.data);
      }
    }
    resolved.set(host, addresses);
  }));
  return resolved;
}

// Pure. assets: workspace_assets rows joined with their verified domain.
// registeredAddresses: every address already covered by a network target.
// resolved: Map(host -> addresses) from resolveHostAddresses.
export function buildNetworkSuggestions({ assets = [], registeredAddresses = [], resolved = new Map() } = {}) {
  const registered = new Set(registeredAddresses.map(canonicalAddress).filter(Boolean));
  const groups = new Map();

  for (const asset of assets) {
    if (!eligible(asset)) continue;
    const host = asset.hostname.toLowerCase();
    const root = asset.domain.toLowerCase();
    if (!hostUnder(host, root)) continue;
    const stored = storedAddresses(asset.ip_addresses);
    const raw = stored && stored.length ? stored : (resolved.get(host) || []);
    const viaProvider = providerMetadataForHostname(asset.cname)?.provider || null;
    const label = firstLabel(host, root);

    for (const value of raw.slice(0, NETWORK_SUGGESTION_LIMITS.addresses_per_host)) {
      const address = canonicalAddress(value);
      if (!address || !isPublicProbeAddress(address)) continue;
      const group = groups.get(address) || { address, hostnames: new Set(), labels: new Set(), cnameProviders: new Set() };
      group.hostnames.add(host);
      if (label && HIGH_VALUE.has(label)) group.labels.add(label);
      if (viaProvider) group.cnameProviders.add(viaProvider);
      groups.set(address, group);
    }
  }

  const rank = { candidate: 0, covered: 1, provider_infrastructure: 2 };
  const all = [...groups.values()].map((group) => {
    const edge = publishedEdgeProvider(group.address);
    const cnameProvider = [...group.cnameProviders].sort()[0] || null;
    const provider = edge || cnameProvider;
    const covered = registered.has(group.address);
    const hostnames = [...group.hostnames].sort();
    return {
      address: group.address,
      hostnames: hostnames.slice(0, NETWORK_SUGGESTION_LIMITS.hostnames_per_suggestion),
      hostname_count: hostnames.length,
      high_value_labels: [...group.labels].sort(),
      priority: group.labels.size ? "high" : "normal",
      recommendation: covered ? "covered" : provider ? "provider_infrastructure" : "candidate",
      provider,
      provider_evidence: edge ? "published_edge_range" : cnameProvider ? "dns_cname" : null,
    };
  }).sort((a, b) =>
    rank[a.recommendation] - rank[b.recommendation]
    || (a.priority === b.priority ? 0 : a.priority === "high" ? -1 : 1)
    || b.hostname_count - a.hostname_count
    || a.address.localeCompare(b.address));

  const ownServers = all.filter((row) => row.recommendation !== "provider_infrastructure");
  return {
    version: NETWORK_SUGGESTION_VERSION,
    suggestions: all.slice(0, NETWORK_SUGGESTION_LIMITS.suggestions),
    truncated: all.length > NETWORK_SUGGESTION_LIMITS.suggestions,
    coverage: {
      likely_own_servers: ownServers.length,
      covered: ownServers.filter((row) => row.recommendation === "covered").length,
      shared_infrastructure: all.length - ownServers.length,
    },
  };
}
