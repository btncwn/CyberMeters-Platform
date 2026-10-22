// Remote-administration exposure (S3-0, 22 Oct 2026, founder order): every
// scan of a verified domain checks a fixed set of remote-administration and
// data-service ports on the addresses that domain's own DNS points at, so an
// MSP hears about an exposed RDP/SMB/database port before an attacker does.
//
// Lawful default scope (#765): only addresses observed in the workspace's
// verified-domain DNS (network-ownership.js); provider/CDN/MX infrastructure
// is excluded there. One network-probe call, profile network_services: TCP
// connect plus whatever banner the service sends unprompted. No login, no
// payload, no exploit; nothing is sent to the service.
//
// Completeness is strict because a managed case closes only on a complete
// re-check (asm-cases.js moduleCompletionGate): more owned addresses than the
// cap, any pair the deadline cut off, any failed DNS lookup or an unavailable
// probe leaves the module incomplete, with its reason. The scan states that as
// a limit rather than turning partial (scan-engine.js buildScanQuality).
import { dnsQuery } from "./dns.js";
import { observedNetworkAddresses } from "./network-ownership.js";
import { collectNetworkProbe, isPublicProbeAddress } from "./network-probe.js";
import { createId } from "../lib/util.js";

export const REMOTE_ADMIN_EXPOSURE_VERSION = "remote-admin-exposure-v1";

// Port -> what it is commonly used for, and how serious an answer from the
// internet is. "Commonly" because the port alone does not prove the service.
export const REMOTE_ADMIN_PORTS = Object.freeze({
  21:    { service: "FTP", tier: "medium" },
  22:    { service: "SSH", tier: "observation" },
  23:    { service: "Telnet", tier: "high" },
  445:   { service: "SMB (Windows file sharing)", tier: "high" },
  1433:  { service: "Microsoft SQL Server", tier: "high" },
  2375:  { service: "Docker API (unencrypted)", tier: "high" },
  3306:  { service: "MySQL", tier: "high" },
  3389:  { service: "Remote Desktop (RDP)", tier: "high" },
  5432:  { service: "PostgreSQL", tier: "high" },
  5900:  { service: "VNC remote desktop", tier: "high" },
  5985:  { service: "WinRM (Windows remote management, HTTP)", tier: "high" },
  5986:  { service: "WinRM (Windows remote management, HTTPS)", tier: "high" },
  6379:  { service: "Redis", tier: "high" },
  9200:  { service: "Elasticsearch", tier: "high" },
  11211: { service: "Memcached", tier: "high" },
  27017: { service: "MongoDB", tier: "high" },
});
export const REMOTE_ADMIN_PORT_LIST = Object.freeze(Object.keys(REMOTE_ADMIN_PORTS).map(Number).sort((a, b) => a - b));

// 8 addresses x 16 ports = 128 pairs: inside the probe's 256-pair cap and, at
// the collector's 8 workers x <=1.95 s per pair, inside the deadline below.
export const REMOTE_ADMIN_LIMITS = Object.freeze({ max_addresses: 8, deadline_ms: 28_000 });

// The banner names the service only for protocols that announce themselves.
const BANNER_NAMES = Object.freeze({ ssh: "SSH", telnet: "Telnet", ftp: "FTP", smtp: "SMTP", imap: "IMAP", pop3: "POP3" });

const hostUnder = (host, root) => host === root || host.endsWith(`.${root}`);

/** Pure: one observed open port -> the customer-facing exposure row. */
export function exposureFromObservation(row, hostnames = []) {
  const known = REMOTE_ADMIN_PORTS[row.port];
  if (!known || row.state !== "open") return null;
  const bannerName = row.service?.basis === "unsolicited_tcp_banner" ? BANNER_NAMES[row.service.name] || null : null;
  const banner = typeof row.service?.banner_sample === "string" ? row.service.banner_sample.slice(0, 120) : null;
  return {
    address: row.address,
    port: row.port,
    hostnames,
    tier: known.tier,
    service: known.service,
    // Named from the banner only when the service said what it is.
    service_basis: bannerName ? "banner" : "port_answered",
    banner_service: bannerName,
    banner_excerpt: bannerName ? banner : null,
  };
}

export async function runRemoteAdminExposureModule(env, scan, {
  signal = null, accounting = null,
  observe = (environment, workspaceId) => observedNetworkAddresses(environment, workspaceId, {
    dnsQueryImpl: (name, type) => dnsQuery(name, type, { accounting }),
  }),
  collect = collectNetworkProbe, now = Date.now, requestId = () => createId("netadm"),
} = {}) {
  const observedAt = () => new Date(now()).toISOString();
  const result = (fields) => ({
    source: "remote_admin_exposure", version: REMOTE_ADMIN_EXPOSURE_VERSION,
    ports: REMOTE_ADMIN_PORT_LIST, exposures: [], addresses_checked: [],
    coverage: { owned_addresses: 0, checked_addresses: 0, planned_pairs: 0, completed_pairs: 0 },
    incomplete: false, incomplete_reason: null, error: null, observed_at: observedAt(), ...fields,
  });
  // A free/anonymous scan has no workspace identity and never reaches the
  // probe. Ownership is checked again at this network boundary.
  if (!scan?.workspace_id || !scan.domain_id || !scan.id || !scan.domain) {
    return result({ state: "not_assessed", reason: "verified_workspace_required" });
  }
  const verified = await env.cybermeters_db.prepare(`SELECT 1 AS allowed FROM workspace_domains wd
    JOIN domains d ON d.id=wd.domain_id JOIN workspaces w ON w.id=wd.workspace_id
    WHERE wd.workspace_id=? AND wd.domain_id=? AND d.domain=?
      AND wd.verification_status='verified' AND w.deleted_at IS NULL`)
    .bind(scan.workspace_id, scan.domain_id, scan.domain).first();
  if (!verified) return result({ state: "not_assessed", reason: "verified_workspace_required" });

  let observed;
  try { observed = await observe(env, scan.workspace_id); }
  catch { return result({ state: "not_assessed", reason: "address_scope_unavailable", incomplete: true, incomplete_reason: "address_scope_unavailable", error: "address_scope_unavailable" }); }

  // Only addresses this scan's own domain points at; another verified domain
  // of the workspace is assessed by its own scan.
  const root = String(scan.domain).toLowerCase();
  const owned = [...(observed?.owned || new Map()).entries()]
    .map(([address, hostnames]) => [address, (hostnames || []).map((h) => String(h).toLowerCase()).filter((h) => hostUnder(h, root)).sort()])
    .filter(([address, hostnames]) => hostnames.length > 0 && isPublicProbeAddress(address))
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  const lookupsFailed = Number(observed?.lookups_failed || 0);
  if (!owned.length) {
    // Nothing owned to check. A failed lookup means we may have missed one.
    return result(lookupsFailed > 0
      ? { state: "not_assessed", reason: "address_lookup_failed", incomplete: true, incomplete_reason: "address_lookup_failed" }
      : { state: "not_assessed", reason: "no_owned_address_observed" });
  }
  // Stable selection: the same addresses every scan, so a case is re-checked
  // on the address it was opened for. Any beyond the cap are stated.
  const selected = owned.slice(0, REMOTE_ADMIN_LIMITS.max_addresses);
  const hostnamesByAddress = new Map(selected);
  const request = {
    schema_version: "network-probe-request-v1", request_id: requestId(),
    workspace_id: scan.workspace_id, scan_id: scan.id, profile: "network_services",
    deadline_at: new Date(now() + REMOTE_ADMIN_LIMITS.deadline_ms).toISOString(),
    targets: selected.map(([address]) => ({ address, hostname: null })), ports: [...REMOTE_ADMIN_PORT_LIST],
  };
  const coverageBase = { owned_addresses: owned.length, checked_addresses: selected.length, planned_pairs: selected.length * REMOTE_ADMIN_PORT_LIST.length };
  let receipt;
  try {
    accounting?.assertCanIssue?.();
    accounting?.recordAttempt?.();
    receipt = await collect(env, request, { signal });
  } catch {
    return result({ state: "not_assessed", reason: "probe_unavailable", incomplete: true, incomplete_reason: "probe_unavailable",
      error: "probe_unavailable", coverage: { ...coverageBase, completed_pairs: 0 } });
  }
  const rows = Array.isArray(receipt?.observations) ? receipt.observations : [];
  // A port that did not answer (timeout at connect) is a conclusive "no
  // answer": checked. Only error / not_run leave a pair unchecked.
  const completedPairs = rows.filter((row) => row?.state === "open" || row?.state === "closed" || row?.state === "timeout").length;
  const exposures = rows.map((row) => exposureFromObservation(row, hostnamesByAddress.get(row?.address) || [])).filter(Boolean);
  const reasons = [];
  if (owned.length > selected.length) reasons.push("address_cap");
  if (completedPairs < coverageBase.planned_pairs) reasons.push("ports_not_all_checked");
  if (lookupsFailed > 0) reasons.push("address_lookup_failed");
  return result({
    state: "observed", reason: null, exposures,
    addresses_checked: selected.map(([address, hostnames]) => ({ address, hostnames })),
    coverage: { ...coverageBase, completed_pairs: completedPairs },
    incomplete: reasons.length > 0, incomplete_reason: reasons[0] || null, incomplete_reasons: reasons,
  });
}
