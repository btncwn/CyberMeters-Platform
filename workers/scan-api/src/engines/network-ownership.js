// ── Network target ownership: only addresses observed in verified-domain DNS ─
//
// Founder decision (21 Oct 2026): a network target may be scanned only when
// every address in it is observed in the DNS of a domain this workspace has
// verified: the A/AAAA of the verified domain itself, of the hosts discovered
// under it (workspace_assets), and of its MX hosts that are under a verified
// domain of the same workspace. A customer's attestation alone no longer
// authorises an address. The attestation stays required as well.
//
// Excluded even when observed, because the address belongs to someone else:
//   • shared provider infrastructure (a CDN's published edge range, or a host
//     reached through a CNAME to a known hosting provider), the same verdict as
//     network-suggestions.js; a service check there tests the provider;
//   • MX hosts outside the workspace's verified domains (a mail provider's
//     servers): the domain points at them, it does not own them.
//
// The evidence is the workspace's own: every read is scoped by workspace_id
// and verification_status = 'verified', so another workspace's verified
// domain can never authorise an address here. A failed lookup only means "not
// observed" (fail closed); a later check can bring the address back in scope.
import { dnsQuery } from "./dns.js";
import {
  canonicalAddress, groupObservedAddresses, hostsNeedingResolution, NETWORK_SUGGESTION_LIMITS, resolveHostAddresses,
} from "./network-suggestions.js";

export const NETWORK_SCOPE_VERSION = "network-scope-v1";
export const NETWORK_SCOPE_LIMITS = Object.freeze({
  verified_domains: 10,   // roots whose own A/AAAA/MX are looked up per check
  resolve_hosts: NETWORK_SUGGESTION_LIMITS.resolve_hosts,
  // A stored decision older than this is checked again before a scan.
  max_age_ms: 60 * 60 * 1000,
});

export const NETWORK_SCOPE_REASONS = Object.freeze({
  observed: "all_addresses_observed_in_verified_dns",
  not_observed: "address_not_observed_in_verified_dns",
  shared: "address_is_shared_provider_infrastructure",
  no_domain: "no_verified_domain",
});

const MESSAGES = Object.freeze({
  [NETWORK_SCOPE_REASONS.observed]: "Every address is observed in the DNS of a domain you verified.",
  [NETWORK_SCOPE_REASONS.not_observed]: "Not scanned: an address is not observed in the DNS (A, AAAA or MX) of a domain you verified, or of a host discovered under it. Point a record of your verified domain at it, then check again.",
  [NETWORK_SCOPE_REASONS.shared]: "Not scanned: an address belongs to a provider's shared infrastructure (for example a CDN edge), not to a server you control.",
  [NETWORK_SCOPE_REASONS.no_domain]: "Not scanned: verify a domain first. Only addresses observed in its DNS can be scanned.",
});

function hostUnder(host, root) {
  return host === root || host.endsWith(`.${root}`);
}

/**
 * Every public address observed for this workspace's verified domains:
 * { roots, owned: Map(address -> hostnames), shared: Map(address -> provider), lookups_failed }.
 */
export async function observedNetworkAddresses(env, workspaceId, { dnsQueryImpl = dnsQuery, limits = NETWORK_SCOPE_LIMITS } = {}) {
  const db = env.cybermeters_db;
  const roots = ((await db.prepare(
    `SELECT DISTINCT lower(d.domain) AS domain
       FROM workspace_domains wd
       JOIN domains d ON d.id = wd.domain_id
       JOIN workspaces w ON w.id = wd.workspace_id AND w.deleted_at IS NULL
      WHERE wd.workspace_id = ? AND wd.verification_status = 'verified'
      ORDER BY d.domain LIMIT ?`,
  ).bind(workspaceId, limits.verified_domains).all()).results || []).map((row) => row.domain);
  if (!roots.length) return { roots, owned: new Map(), shared: new Map(), lookups_failed: 0 };

  const assets = (await db.prepare(
    `SELECT a.hostname, a.ip_addresses, a.cname, a.status, a.lifecycle_state, a.wildcard_dns, d.domain
       FROM workspace_assets a
       JOIN workspace_domains wd ON wd.workspace_id = a.workspace_id AND wd.domain_id = a.domain_id
       JOIN domains d ON d.id = a.domain_id
      WHERE a.workspace_id = ? AND wd.verification_status = 'verified' AND a.status = 'active'
      ORDER BY a.last_seen DESC, a.hostname LIMIT ?`,
  ).bind(workspaceId, NETWORK_SUGGESTION_LIMITS.assets).all()).results || [];

  // MX hosts under a verified root of this workspace; a provider's MX is not ours.
  let lookupsFailed = 0;
  const mxHosts = [];
  for (const root of roots) {
    try {
      const answer = await dnsQueryImpl(root, "MX");
      for (const record of answer?.Answer || []) {
        if (record?.type !== 15) continue;
        const host = String(record.data || "").trim().split(/\s+/).pop()?.replace(/\.$/, "").toLowerCase();
        const owner = host && roots.find((r) => hostUnder(host, r));
        if (owner) mxHosts.push({ host, root: owner });
      }
    } catch { lookupsFailed += 1; }
  }

  // The verified roots and their MX hosts are looked up first: the root's own
  // asset row stores no address.
  const synthetic = [
    ...roots.map((root) => ({ hostname: root, domain: root, ip_addresses: null, cname: null, status: "active", lifecycle_state: "observed", wildcard_dns: 0 })),
    ...mxHosts.map(({ host, root }) => ({ hostname: host, domain: root, ip_addresses: null, cname: null, status: "active", lifecycle_state: "observed", wildcard_dns: 0 })),
  ];
  const first = [...new Set(synthetic.map((row) => row.hostname))];
  const rest = hostsNeedingResolution(assets, limits.resolve_hosts).filter((host) => !first.includes(host));
  const toResolve = [...first, ...rest].slice(0, limits.resolve_hosts);
  const resolved = await resolveHostAddresses(toResolve, {
    dnsQueryImpl: async (name, type) => {
      try { return await dnsQueryImpl(name, type); } catch (error) { lookupsFailed += 1; throw error; }
    },
  });

  const groups = groupObservedAddresses({ assets: [...assets, ...synthetic], registeredAddresses: [], resolved });
  const owned = new Map(), shared = new Map();
  for (const group of groups) {
    if (group.recommendation === "provider_infrastructure") shared.set(group.address, group.provider);
    else owned.set(group.address, group.hostnames);
  }
  return { roots, owned, shared, lookups_failed: lookupsFailed };
}

/** Pure: the scope decision for one target's addresses. */
export function evaluateTargetScope(addresses = [], observed) {
  const list = addresses.map(canonicalAddress);
  const evidence = {};
  if (!observed?.roots?.length) {
    return { state: "out_of_scope", reason: NETWORK_SCOPE_REASONS.no_domain, unobserved: list, shared: [], evidence };
  }
  const shared = list.filter((address) => address && observed.shared.has(address));
  const unobserved = list.filter((address) => !address || (!observed.owned.has(address) && !observed.shared.has(address)));
  for (const address of list) if (address && observed.owned.has(address)) evidence[address] = observed.owned.get(address);
  const state = list.length > 0 && !shared.length && !unobserved.length ? "in_scope" : "out_of_scope";
  const reason = state === "in_scope" ? NETWORK_SCOPE_REASONS.observed
    : unobserved.length ? NETWORK_SCOPE_REASONS.not_observed : NETWORK_SCOPE_REASONS.shared;
  return { state, reason, unobserved, shared, evidence };
}

export function scopeMessage(reason) {
  return MESSAGES[reason] || null;
}

/** Customer projection of a target's stored scope. */
export function networkScopeProjection(row) {
  if (!row?.scope_state) {
    return { state: "not_checked", reason: null, checked_at: null, message: "Not checked yet against your verified domains. It is checked before any scan.", unobserved: [], shared: [] };
  }
  let detail = {};
  try { detail = JSON.parse(row.scope_evidence_json || "{}") || {}; } catch { detail = {}; }
  return {
    state: row.scope_state,
    reason: row.scope_reason,
    checked_at: row.scope_checked_at,
    message: scopeMessage(row.scope_reason),
    unobserved: Array.isArray(detail.unobserved) ? detail.unobserved.slice(0, 32) : [],
    shared: Array.isArray(detail.shared) ? detail.shared.slice(0, 32) : [],
  };
}

/**
 * Check targets against the workspace's observed addresses and store the
 * decision. Returns Map(target id -> decision). One observation per call.
 */
export async function checkNetworkTargetScope(env, workspaceId, targets, deps = {}) {
  const observed = deps.observed || await observedNetworkAddresses(env, workspaceId, deps);
  const now = (deps.now ? new Date(deps.now()) : new Date()).toISOString();
  const decisions = new Map();
  const statements = [];
  for (const target of targets) {
    let addresses = [];
    try { addresses = JSON.parse(target.addresses_json); } catch { addresses = []; }
    const decision = evaluateTargetScope(Array.isArray(addresses) ? addresses : [], observed);
    decisions.set(target.id, { ...decision, checked_at: now });
    statements.push(env.cybermeters_db.prepare(
      `UPDATE network_targets SET scope_state = ?, scope_reason = ?, scope_checked_at = ?, scope_evidence_json = ?
        WHERE id = ? AND workspace_id = ?`,
    ).bind(decision.state, decision.reason, now, JSON.stringify({
      version: NETWORK_SCOPE_VERSION, unobserved: decision.unobserved, shared: decision.shared,
      evidence: decision.evidence, roots: observed.roots, lookups_failed: observed.lookups_failed,
    }), target.id, workspaceId));
  }
  if (statements.length === 1) await statements[0].run();
  else if (statements.length) await env.cybermeters_db.batch(statements);
  return decisions;
}
