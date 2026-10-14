// Which provider network an observed IP address belongs to.
//
// Cloud and edge providers publish the address ranges they operate. A copy of
// those lists ships with the Worker (cloud-networks-data.js, built by
// scripts/build-cloud-networks.js); nothing is fetched at run time and no
// address leaves the server.
//
// What a match means, and what it does not: the address is inside a range the
// provider publishes for its network. It does not say whose account runs the
// server — a SaaS product the customer uses can sit in the same ranges as the
// customer's own servers. Customer wording says exactly that.
//
// The list is verified (entry count and SHA-256) the first time it is used in
// an isolate. A damaged list attributes nothing: every address reads as
// "unavailable", never as a wrong provider.
import { CLOUD_NETWORK_LIST } from "./cloud-networks-data.js";

import {
  canonicalCidr, maskFor, networkKind, NETWORK_PROVIDERS, parseCidr, parseIpAddress,
} from "./cloud-network-ranges.js";

export { canonicalCidr, networkKind, NETWORK_PROVIDERS, parseCidr, parseIpAddress };

export const HOSTING_LIMITATIONS = Object.freeze({
  cloud: "The address is in a range the provider publishes for its cloud. It does not show whose account runs the server.",
  edge: "The address belongs to an edge network in front of the site. The server behind it is not visible from outside.",
});

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// One map per (family, prefix length); a lookup tries the longest prefix first.
function buildIndex(lines) {
  const tables = { 4: new Map(), 6: new Map() };
  for (const line of lines) {
    const [cidr, provider, region = "", service = ""] = line.split("\t");
    const parsed = parseCidr(cidr);
    if (!parsed || !NETWORK_PROVIDERS[provider]) return null;
    const byBits = tables[parsed.version];
    if (!byBits.has(parsed.bits)) byBits.set(parsed.bits, new Map());
    // The build keeps one row per network; a duplicate here is a damaged list.
    if (byBits.get(parsed.bits).has(parsed.network)) return null;
    byBits.get(parsed.bits).set(parsed.network, Object.freeze({ cidr, provider, region, service }));
  }
  return {
    4: { tables: tables[4], order: [...tables[4].keys()].sort((a, b) => b - a) },
    6: { tables: tables[6], order: [...tables[6].keys()].sort((a, b) => b - a) },
  };
}

/**
 * Build a lookup for one list. The returned async function resolves an address
 * to its most specific published range ({ cidr, provider, region, service }),
 * to null when no range matches, to "invalid" when the address does not parse,
 * or to "unavailable" when the list does not verify.
 */
export function createNetworkLookup(list) {
  let loaded = null;
  const load = async () => {
    try {
      const text = typeof list?.entries === "string" ? list.entries : "";
      const lines = text ? text.split("\n") : [];
      if (!lines.length || lines.length !== list.count) return null;
      if ((await sha256Hex(text)) !== list.sha256) return null;
      return buildIndex(lines);
    } catch {
      return null;
    }
  };
  const lookup = async (address) => {
    loaded ??= load();
    const index = await loaded;
    if (!index) return "unavailable";
    const ip = parseIpAddress(address);
    if (!ip) return "invalid";
    const family = index[ip.version];
    for (const bits of family.order) {
      const hit = family.tables.get(bits).get(ip.value & maskFor(ip.version, bits));
      if (hit) return hit;
    }
    return null;
  };
  lookup.version = list?.version ?? null;
  return lookup;
}

const bundledLookup = createNetworkLookup(CLOUD_NETWORK_LIST);

/** Addresses from a workspace_assets.ip_addresses value (JSON array or legacy comma list). */
export function addressesFromStored(value) {
  if (Array.isArray(value)) return [...new Set(value.map((v) => String(v ?? "").trim()).filter(Boolean))];
  const raw = String(value ?? "").trim();
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return addressesFromStored(parsed);
  } catch { /* legacy comma-separated value */ }
  return addressesFromStored(raw.split(","));
}

const MAX_ADDRESSES = 16;

/**
 * Describe the provider networks behind a set of observed addresses.
 *   status: "no_address" | "unavailable" | "attributed" | "unattributed"
 * "unattributed" means every address was checked and none is in a published
 * provider range — it is not a claim about where the server is.
 */
export async function describeHostingNetwork(addresses, { lookup = bundledLookup } = {}) {
  const list = addressesFromStored(addresses).filter((a) => parseIpAddress(a)).slice(0, MAX_ADDRESSES);
  const base = { list_version: lookup.version ?? null, networks: [], providers: [], limitations: [] };
  if (!list.length) return { status: "no_address", ...base };
  const networks = [];
  for (const address of list) {
    const hit = await lookup(address);
    if (hit === "unavailable") return { status: "unavailable", ...base };
    if (!hit || hit === "invalid") continue;
    const meta = NETWORK_PROVIDERS[hit.provider];
    networks.push({
      address,
      provider: hit.provider,
      provider_label: meta.label,
      kind: networkKind(hit.provider, hit.service),
      region: hit.region || null,
      service: hit.service || null,
      range: hit.cidr,
    });
  }
  if (!networks.length) return { status: "unattributed", ...base };
  const providers = [...new Set(networks.map((n) => n.provider))];
  // An address can be both (e.g. a provider's edge in front of its own cloud);
  // each kind present carries its own limitation.
  const kinds = [...new Set(networks.map((n) => n.kind))];
  return {
    status: "attributed",
    ...base,
    networks,
    providers,
    limitations: kinds.map((k) => HOSTING_LIMITATIONS[k]),
  };
}

/** Count assets by provider network for a list of describeHostingNetwork results. */
export function summariseHostingNetworks(descriptions) {
  const by_provider = {};
  let unattributed = 0, no_address = 0, unavailable = 0;
  for (const d of descriptions) {
    if (d?.status === "attributed") for (const p of d.providers) by_provider[p] = (by_provider[p] || 0) + 1;
    else if (d?.status === "unattributed") unattributed++;
    else if (d?.status === "no_address") no_address++;
    else unavailable++;
  }
  return {
    assets: descriptions.length,
    by_provider: Object.entries(by_provider)
      .map(([provider, count]) => ({ provider, provider_label: NETWORK_PROVIDERS[provider].label, kind: NETWORK_PROVIDERS[provider].kind, count }))
      .sort((a, b) => b.count - a.count || a.provider.localeCompare(b.provider)),
    other_networks: unattributed,
    no_address,
    unavailable,
    list_version: descriptions[0]?.list_version ?? null,
  };
}
