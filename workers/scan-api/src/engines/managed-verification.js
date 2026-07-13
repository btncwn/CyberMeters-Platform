// ── Managed-verification scan profile (scan_profile = "managed_verification") ──
// A separate, lean verification that re-checks ONE managed case's affected host — it
// does NOT invoke the standard or reserved full-scan orchestration. It resolves +
// SSRF-safe-probes only the affected hostname, derives admin_surface evidence, and
// evaluates the original finding condition. Expected cost ≈ 3–5 external calls.
//
// Finding-type dispatch is an allowlisted server-side mapping — a case/customer value
// can never select an arbitrary module/function. Unsupported types fail closed
// (deferred, never resolved). Completeness is conservative: any incomplete / SSRF-
// refused / budget / DNS-indeterminate / ambiguous result DEFERS (never resolves).
import { assetFingerprintSignals } from "./asset-intel.js";
import { makeReservedProbeFetch } from "./reserved-probe.js";

export const MANAGED_VERIFICATION_PROFILE = "managed_verification";

// Allowlisted finding-type → verifier. Server-side only; not client-selectable.
const VERIFICATION_DISPATCH = Object.freeze({
  asset_exposure_admin_interface: verifyAssetExposureAdminInterface,
});

// Resolve the finding type from the stored finding (never from client input).
export function findingTypeOf(finding = {}) {
  return String(finding?.id || "").trim();
}

export function isSupportedVerification(finding = {}) {
  return Object.prototype.hasOwnProperty.call(VERIFICATION_DISPATCH, findingTypeOf(finding));
}

function isSubrequestBudgetError(err) {
  return /too many subrequests/i.test(err?.message || "");
}

// Build the minimal asset record the admin-interface condition needs, from one probe
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

// Verifier for asset_exposure_admin_interface: is a reachable admin/login interface
// still publicly served on the affected host?  Present iff HTTP 200 + admin hostname +
// admin title + not a generic default page.  Policy: for THIS finding a conclusive
// probe that no longer meets that condition (e.g. now 403/404, or a non-admin page) is
// sufficient evidence of remediation; a non-conclusive probe defers.
async function verifyAssetExposureAdminInterface(host, { onOutbound } = {}) {
  const cache = new Map();
  const fetcher = makeReservedProbeFetch({ cache, onOutbound });
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

  if (budgetExhausted) return { completeness: "incomplete", reason: "subrequest_budget", present: null };
  if (ssrfRefused && !response) return { completeness: "ssrf_refused", present: null };
  if (!response) return { completeness: "indeterminate", reason: "unreachable", present: null }; // conservative: defer

  const asset = await assetFromResponse(host, response);
  const signals = assetFingerprintSignals(asset);
  const present = asset.status === 200
    && signals.admin_hostname
    && signals.admin_title
    && !signals.generic_default_page;
  return {
    completeness: "complete",
    present,
    evidence: { host, status: asset.status, title: asset.title, admin_hostname: signals.admin_hostname, admin_title: signals.admin_title },
  };
}

// Run the verification profile for a finding + affected host. Returns a decision:
//   { decision: "still_present" | "fixed" | "deferred", completeness, evidence }.
// onOutbound is invoked per real outbound call so callers can meter cost.
export async function runManagedVerificationProbe(finding, host, { onOutbound } = {}) {
  const verifier = VERIFICATION_DISPATCH[findingTypeOf(finding)];
  if (!verifier) return { decision: "deferred", completeness: "unsupported_finding_type", reason: "fail_closed" };
  const cleanHost = String(host || "").trim().toLowerCase();
  if (!cleanHost) return { decision: "deferred", completeness: "no_affected_host" };

  const result = await verifier(cleanHost, { onOutbound });
  if (result.completeness !== "complete") {
    return { decision: "deferred", completeness: result.completeness, reason: result.reason || null };
  }
  return {
    decision: result.present ? "still_present" : "fixed",
    completeness: "complete",
    evidence: result.evidence || null,
  };
}
