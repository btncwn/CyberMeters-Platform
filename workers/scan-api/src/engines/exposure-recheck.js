// ── Re-checking an exposure case on its own hosts ────────────────────────────
// A case about a reachable sign-in or management page is closed by a scan only
// when that scan re-tested the old problem on every affected host and saw it
// gone. Two observations do that:
//
//   answered_without_tool  the same host gave an origin answer the
//                          serviceability contract can conclude from (2xx, 3xx,
//                          or a 4xx other than 401/403/429) and the tool is no
//                          longer identified on it — by the same presence
//                          predicate the single-case re-check uses;
//   confirmed_removed      the name no longer resolves and the canonical removal
//                          policy (three qualifying observations at least a day
//                          apart over at least 48 hours) has confirmed it.
//
// Nothing else re-tests the problem, so nothing else closes the case: a timeout,
// a refused or dropped connection, 401/403/429 (often a filter that answers only
// scanners that way), an origin or edge 5xx, a name that stopped resolving but is
// not yet confirmed removed, or a host this scan did not probe. Those leave the
// case waiting for a re-check, with the reason recorded. Pure; no I/O.
import { ACCESS_RESTRICTED_STATUSES } from "../lib/serviceability.js";
import { normalizeHostname } from "./hostnames.js";
import { httpAssetStillPresent, isHttpAssetVerification } from "./managed-verification.js";

export const EXPOSURE_RECHECK_VERSION = "exposure-recheck-v1";

export const EXPOSURE_RECHECK_OUTCOMES = Object.freeze([
  "answered_without_tool",
  "confirmed_removed",
  "still_present",
  "not_rechecked",
  "timed_out",
  "no_answer",
  "access_restricted",
  "no_origin",
  "server_error",
  "name_not_resolving",
]);

const CLOSING = new Set(["answered_without_tool", "confirmed_removed"]);

// When a case stays open, the first of these that applies names why.
const WAITING_ORDER = Object.freeze([
  "not_rechecked",
  "timed_out",
  "no_answer",
  "access_restricted",
  "no_origin",
  "server_error",
  "name_not_resolving",
]);

export { isHttpAssetVerification as isHttpAssetRecheck };

// Which protocol and port answered, and — when the answer came after a redirect
// to another place — where it finally came from (protocol, host and port only).
function answeredAttempt(asset) {
  const attempt = (Array.isArray(asset?.attempts) ? asset.attempts : [])
    .find((item) => item?.outcome === "responded");
  if (!attempt?.protocol) return {};
  const ended = attempt.ended_at && typeof attempt.ended_at === "object" && attempt.ended_at.host
    ? {
      ended_at: {
        protocol: String(attempt.ended_at.protocol || ""),
        host: normalizeHostname(attempt.ended_at.host),
        port: Number.isInteger(attempt.ended_at.port) ? attempt.ended_at.port : null,
      },
    }
    : {};
  return {
    protocol: String(attempt.protocol),
    port: Number.isInteger(attempt.port) ? attempt.port : null,
    ...ended,
  };
}

function failedAttempts(asset) {
  return (Array.isArray(asset?.attempts) ? asset.attempts : [])
    .filter((item) => item?.protocol && item?.outcome && item.outcome !== "responded")
    .map((item) => ({ protocol: String(item.protocol), port: Number.isInteger(item.port) ? item.port : null, outcome: String(item.outcome) }))
    .slice(0, 2);
}

/**
 * What this scan's probe record says about one affected host. `asset` is the
 * host's entry in modules.asset_exposure.assets (or undefined when the scan did
 * not probe it).
 */
export function classifyExposureHost(findingType, asset) {
  if (!asset) return { outcome: "not_rechecked" };
  switch (asset.probe_status) {
    case "not_applicable": return { outcome: "name_not_resolving" };
    case "not_executed": return { outcome: "not_rechecked" };
    case "timed_out": return { outcome: "timed_out" };
    case "origin_unreachable": return { outcome: "no_origin", status: Number.isInteger(asset.status) ? asset.status : null };
    case "server_error": return { outcome: "server_error", status: Number.isInteger(asset.status) ? asset.status : null };
    default: break;
  }
  const status = asset.status;
  if (!Number.isInteger(status)) {
    return asset.reachable === false
      ? { outcome: "no_answer", attempts: failedAttempts(asset) }
      : { outcome: "not_rechecked" };
  }
  if (status >= 500) return { outcome: "server_error", status };
  if (ACCESS_RESTRICTED_STATUSES.includes(status)) return { outcome: "access_restricted", status, ...answeredAttempt(asset) };
  if (status < 200) return { outcome: "not_rechecked", status };
  const present = httpAssetStillPresent(findingType, asset);
  if (present === null) return { outcome: "not_rechecked", status };
  return { outcome: present ? "still_present" : "answered_without_tool", status, ...answeredAttempt(asset) };
}

/**
 * The scan's re-check of one case.
 *   hosts       the case's affected hosts (already validated against its domain)
 *   assets      modules.asset_exposure.assets of this scan
 *   removalFor  host → { verified, reason, observation } from the removal policy;
 *               consulted only for a host whose name no longer resolves
 * Returns { version, decision: "verified" | "still_present" | "deferred", reason, hosts }.
 */
function finalHostOf(asset) {
  try { return normalizeHostname(new URL(String(asset?.url || "")).hostname); } catch { return null; }
}

// A host the scan probed that redirected to another of the customer's names is
// folded into that name's record as an alias (deduplicateExposureAssets): the
// answer it got is that record's final answer. Its own record wins if it has one.
function recordsByHost(assets) {
  const byHost = new Map();
  const list = Array.isArray(assets) ? assets : [];
  for (const asset of list) {
    const host = normalizeHostname(asset?.host);
    if (host && !byHost.has(host)) byHost.set(host, { asset });
  }
  for (const asset of list) {
    const representative = normalizeHostname(asset?.host);
    for (const alias of Array.isArray(asset?.aliases) ? asset.aliases : []) {
      const host = normalizeHostname(alias);
      if (host && !byHost.has(host)) byHost.set(host, { asset, groupedWith: representative });
    }
  }
  return byHost;
}

function classifyRecord(findingType, host, record) {
  if (!record) return classifyExposureHost(findingType, undefined);
  if (!record.groupedWith) return classifyExposureHost(findingType, record.asset);
  // Judge the final page as the answer to this host's own name; the protocol
  // and port of its own request were not kept, only where the answer came from.
  const result = classifyExposureHost(findingType, { ...record.asset, host, attempts: [] });
  const finalHost = finalHostOf(record.asset);
  return {
    ...result,
    grouped_with: record.groupedWith,
    ...(finalHost && finalHost !== host ? { ended_at: { host: finalHost } } : {}),
  };
}

export function assessExposureRecheck({ findingType, hosts = [], assets = [], removalFor = () => null } = {}) {
  const byHost = recordsByHost(assets);
  const results = (Array.isArray(hosts) ? hosts : []).map((hostname) => {
    const host = normalizeHostname(hostname);
    let result = classifyRecord(findingType, host, byHost.get(host));
    // A name that no longer resolves — or one this scan holds no probe record
    // for but whose lifecycle it re-observed — closes only through the removal
    // policy.
    if (result.outcome === "name_not_resolving" || result.outcome === "not_rechecked") {
      const removal = removalFor(host) || null;
      if (removal?.verified) {
        result = { outcome: "confirmed_removed", ...(removal.observation ? { removal: removal.observation } : {}) };
      } else if (result.outcome === "name_not_resolving") {
        result = { outcome: "name_not_resolving", removal_reason: removal?.reason || "no_lifecycle_record" };
      }
    }
    return { hostname: host, ...result };
  });
  const base = { version: EXPOSURE_RECHECK_VERSION, hosts: results };
  if (results.length === 0) return { ...base, decision: "deferred", reason: "affected_hosts_unknown" };
  if (results.some((result) => result.outcome === "still_present")) return { ...base, decision: "still_present", reason: null };
  if (results.every((result) => CLOSING.has(result.outcome))) return { ...base, decision: "verified", reason: null };
  const waiting = WAITING_ORDER.find((outcome) => results.some((result) => result.outcome === outcome)) || "not_rechecked";
  return { ...base, decision: "deferred", reason: `affected_host_${waiting}` };
}
