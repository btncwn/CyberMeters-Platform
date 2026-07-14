// ── Managed-verification scan profile (scan_profile = "managed_verification") ──
// A separate, lean verification that re-checks ONE managed case's affected host(s) — it
// does NOT invoke the standard or reserved full-scan orchestration. It resolves +
// SSRF-safe-probes only the affected hostnames, derives the asset record, and evaluates
// the original finding condition. Expected cost ≈ 2 external calls per affected host.
//
// Finding-type dispatch is an allowlisted server-side mapping — a case/customer value
// can never select an arbitrary module/function. Unsupported types fail closed
// (deferred, never resolved). Completeness is conservative: any incomplete / SSRF-
// refused / budget / DNS-indeterminate / ambiguous result DEFERS (never resolves).
//
// ── Why the presence predicates reuse the real detectors ──────────────────────
// A verifier that re-implemented a detector's condition could drift from it and then
// resolve a case whose exposure is still live. So each predicate below evaluates the
// SAME code the scan used to raise the finding:
//   • admin_surface_*  → runAdminSurfaceModule (a PURE function over asset records)
//   • asset_exposure_* → assetFingerprintSignals (the same signal source scoring.js uses)
// Two scan-wide inputs are deliberately unavailable to a single-host probe
// (`provider_owned_infrastructure`, `wildcard_dns`, both of which the scan uses only to
// SUPPRESS a finding). Omitting them can only make this profile see "still present" more
// readily than the scan did — it can never manufacture a false "fixed". That asymmetry is
// the point: an over-cautious verifier leaves a case open, an over-eager one lies.
import { assetFingerprintSignals, runAdminSurfaceModule } from "./asset-intel.js";
import { makeReservedProbeFetch } from "./reserved-probe.js";

export const MANAGED_VERIFICATION_PROFILE = "managed_verification";

// Bound on how many affected hosts one verification may probe. A finding covering more
// hosts than this defers (fail-closed) rather than concluding "fixed" from a subset —
// partial coverage is not evidence that every affected host was remediated.
export const MAX_VERIFICATION_HOSTS = 10;

// ── Presence predicates — pure, evaluated against a probed asset record ───────
// Each returns true iff the original finding's condition still holds for this host.

// asset_exposure_admin_interface (scoring.js): a reachable generic admin/login interface.
function presentAdminInterface(asset) {
  const s = assetFingerprintSignals(asset);
  return asset.status === 200 && s.admin_hostname && s.admin_title && !s.generic_default_page;
}

// asset_exposure_sensitive_tool (scoring.js): a directly fingerprinted management tool.
function presentSensitiveTool(asset) {
  const s = assetFingerprintSignals(asset);
  return asset.status === 200 && s.sensitive_service && !s.generic_default_page;
}

// asset_exposure_dev_env (scoring.js): a reachable development/staging environment.
function presentDevEnv(asset) {
  const s = assetFingerprintSignals(asset);
  return asset.status === 200 && s.dev_hostname && s.dev_title && !s.generic_default_page;
}

// admin_surface_<level> (scan-engine.js): the admin-surface module still fingerprints an
// actionable service at this risk level on this host. Mirrors the scan's own condition
// (`detected && total > 0` gate, then a risk_level match across services) by running the
// real module over a single-asset module snapshot.
function presentAdminSurface(level) {
  return (asset) => {
    const mod = runAdminSurfaceModule({ asset_exposure: { assets: [asset] } });
    return Boolean(mod?.detected) && Number(mod?.total || 0) > 0
      && (mod.services || []).some((s) => s.risk_level === level);
  };
}

// Allowlisted finding-type → presence predicate. Server-side only; not client-selectable.
//
// Deliberately absent (each fails closed → deferred, never verified):
//   • cloud_storage_*  — the affected object lives on third-party storage infrastructure
//     outside the customer's DNS scope. Probing it would widen the host-scope/SSRF
//     boundary, which is a founder decision and out of scope for this profile.
//   • *_observed info findings (asset_exposure_interface_observed,
//     asset_provider_infrastructure_observed, cloud_storage_exposure_observed) — these are
//     observations, not exposures with a fix. "Verified fixed" is not a meaningful outcome.
//   • subdomain_takeover, dse_* — externally verifiable, but via DNS/header techniques
//     this HTTP-only profile does not yet implement.
const VERIFICATION_DISPATCH = Object.freeze({
  asset_exposure_admin_interface: presentAdminInterface,
  asset_exposure_sensitive_tool:  presentSensitiveTool,
  asset_exposure_dev_env:         presentDevEnv,
  admin_surface_critical:         presentAdminSurface("critical"),
  admin_surface_high:             presentAdminSurface("high"),
  admin_surface_medium:           presentAdminSurface("medium"),
});

// Resolve the finding type from the stored finding (never from client input).
export function findingTypeOf(finding = {}) {
  return String(finding?.id || "").trim();
}

export function isSupportedVerification(finding = {}) {
  return Object.prototype.hasOwnProperty.call(VERIFICATION_DISPATCH, findingTypeOf(finding));
}

// The finding types this profile can verify — exported so tests and the API can state
// support honestly rather than re-deriving the list.
export function supportedVerificationTypes() {
  return Object.keys(VERIFICATION_DISPATCH).sort();
}

function isSubrequestBudgetError(err) {
  return /too many subrequests/i.test(err?.message || "");
}

// Build the minimal asset record the presence predicates need, from one probe
// response. Reads at most 8 KB of the body for the <title>. No sensitive body is
// persisted — only the extracted title (and it is length-bounded).
async function assetFromResponse(host, res) {
  const status = res.status;
  const server = res.headers.get("server") || null;
  const rawCT = res.headers.get("content-type") || null;
  let title = null;
  if (rawCT && /text\/html/i.test(rawCT)) {
    try {
      const body = await res.text();
      const m = body.slice(0, 8_192).match(/<title[^>]*>([^<]{1,200})<\/title>/i);
      title = m ? m[1].trim() : null;
    } catch { title = null; }
  }
  return { host, url: res.url || `https://${host}`, status, reachable: status < 500, title, server, tech: [] };
}

// Probe ONE host over https then http. Returns { completeness, asset } — any outcome
// other than "complete" must defer, never resolve.
async function probeHost(host, fetcher) {
  let response = null, ssrfRefused = false, budgetExhausted = false;
  for (const proto of ["https", "http"]) {
    let r;
    try {
      r = await fetcher(`${proto}://${host}`);
    } catch (err) {
      if (isSubrequestBudgetError(err)) { budgetExhausted = true; break; }
      continue; // genuine network/DNS/timeout error — try the next protocol
    }
    if (r === null) { ssrfRefused = true; continue; } // reserved SSRF guard refused this target
    response = r; break;
  }

  if (budgetExhausted) return { completeness: "incomplete", reason: "subrequest_budget", asset: null };
  if (ssrfRefused && !response) return { completeness: "ssrf_refused", asset: null };
  if (!response) return { completeness: "indeterminate", reason: "unreachable", asset: null }; // conservative: defer

  return { completeness: "complete", asset: await assetFromResponse(host, response) };
}

// Run the verification profile for a finding + its affected host(s). Returns a decision:
//   { decision: "still_present" | "fixed" | "deferred", completeness, evidence }.
//
// Multi-host semantics (an ASM finding commonly covers several hosts):
//   • ANY affected host still exhibiting the condition → still_present (short-circuits;
//     one live exposure is enough, and it saves subrequests).
//   • ANY host inconclusive, with none present      → deferred. "Fixed" requires a
//     complete, conclusive observation of EVERY affected host.
//   • All hosts observed conclusively and clear      → fixed.
// onOutbound is invoked per real outbound call so callers can meter cost.
export async function runManagedVerificationProbe(finding, hostOrHosts, { onOutbound } = {}) {
  const isPresent = VERIFICATION_DISPATCH[findingTypeOf(finding)];
  if (!isPresent) return { decision: "deferred", completeness: "unsupported_finding_type", reason: "fail_closed" };

  const hosts = [...new Set(
    (Array.isArray(hostOrHosts) ? hostOrHosts : [hostOrHosts])
      .map((h) => String(h || "").trim().toLowerCase())
      .filter(Boolean)
  )];
  if (hosts.length === 0) return { decision: "deferred", completeness: "no_affected_host" };
  if (hosts.length > MAX_VERIFICATION_HOSTS) {
    return { decision: "deferred", completeness: "too_many_affected_hosts", reason: "fail_closed", hosts_total: hosts.length };
  }

  const cache = new Map();
  const fetcher = makeReservedProbeFetch({ cache, onOutbound });
  const observations = [];
  let firstIncomplete = null;

  for (const host of hosts) {
    const probe = await probeHost(host, fetcher);
    if (probe.completeness !== "complete") {
      firstIncomplete = firstIncomplete || probe;
      observations.push({ host, completeness: probe.completeness, reason: probe.reason || null });
      continue;
    }
    const asset = probe.asset;
    const present = Boolean(isPresent(asset));
    const signals = assetFingerprintSignals(asset);
    observations.push({
      host, status: asset.status, title: asset.title, present,
      admin_hostname: signals.admin_hostname, admin_title: signals.admin_title,
      sensitive_service: signals.sensitive_service, generic_default_page: signals.generic_default_page,
    });
    if (present) {
      return {
        decision: "still_present",
        completeness: "complete",
        evidence: { hosts_total: hosts.length, hosts_checked: observations.length, observations },
      };
    }
  }

  if (firstIncomplete) {
    return {
      decision: "deferred",
      completeness: firstIncomplete.completeness,
      reason: firstIncomplete.reason || null,
      evidence: { hosts_total: hosts.length, hosts_checked: observations.length, observations },
    };
  }

  return {
    decision: "fixed",
    completeness: "complete",
    evidence: { hosts_total: hosts.length, hosts_checked: observations.length, observations },
  };
}
