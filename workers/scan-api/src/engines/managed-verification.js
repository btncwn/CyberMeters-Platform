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
import { dnsQuery } from "./dns.js";
import { buildCaaFromAnswers } from "./dns-scan.js";
import { runDomainSecurityEnrichmentModule } from "./domain-enrichment.js";
import { DSE_EVIDENCE_SOURCE, DSE_PRESENCE, dsePresenceEvidenceUsable } from "./dse-findings.js";
import { captureSetCookieRaw, securityHeaderValuesFrom } from "./headers-scan.js";
import { makeReservedProbeFetch } from "./reserved-probe.js";
import { hostHasConfirmedTakeoverRisk, runTakeoverModule, takeoverObservationFor } from "./takeover-scan.js";

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

// Allowlisted finding-type → { technique, present }. Server-side only; not
// client-selectable. `technique` decides what is re-observed; `present` (http_asset
// only) is the pure predicate over the probed asset. DNS/header techniques delegate
// their predicate to the detector's own module (see the header comment).
const VERIFICATION_DISPATCH = Object.freeze({
  // Re-probe the affected host over HTTP and re-evaluate the exposure condition.
  asset_exposure_admin_interface: { technique: "http_asset", present: presentAdminInterface },
  asset_exposure_sensitive_tool:  { technique: "http_asset", present: presentSensitiveTool },
  asset_exposure_dev_env:         { technique: "http_asset", present: presentDevEnv },
  admin_surface_critical:         { technique: "http_asset", present: presentAdminSurface("critical") },
  admin_surface_high:             { technique: "http_asset", present: presentAdminSurface("high") },
  admin_surface_medium:           { technique: "http_asset", present: presentAdminSurface("medium") },
  // Re-run the takeover detector for this host: CNAME + provider fingerprint + body.
  subdomain_takeover:             { technique: "dns_takeover" },
  // Re-query CAA and re-evaluate the canonical dse_* predicate.
  dse_missing_caa:                { technique: "dns_caa" },
  dse_caa_no_issuers:             { technique: "dns_caa" },
  // Re-observe response headers and re-evaluate the canonical dse_* predicate.
  dse_hsts_short_maxage:          { technique: "http_headers" },
  dse_hsts_not_preload_eligible:  { technique: "http_headers" },
  dse_cookie_no_secure:           { technique: "http_headers" },
  dse_cookie_no_httponly:         { technique: "http_headers" },
  dse_cookie_no_samesite:         { technique: "http_headers" },
});

// ── Support matrix (the honest, code-backed statement of what we can verify) ──
// Every ASM finding type that can open a managed case appears here exactly once, in
// one of three states. CI asserts this matrix and VERIFICATION_DISPATCH agree, so the
// product can never claim verification support it does not have.
//
//   automated        — CyberMeters re-observes externally and decides.
//   unsupported      — a real exposure, but we will not verify it (scope boundary).
//   not_applicable   — an observation, not an exposure with a fix; "verified fixed"
//                      is not a meaningful outcome for it.
export const ASM_VERIFICATION_SUPPORT = Object.freeze({
  asset_exposure_admin_interface:  { support: "automated", technique: "http_asset" },
  asset_exposure_sensitive_tool:   { support: "automated", technique: "http_asset" },
  asset_exposure_dev_env:          { support: "automated", technique: "http_asset" },
  admin_surface_critical:          { support: "automated", technique: "http_asset" },
  admin_surface_high:              { support: "automated", technique: "http_asset" },
  admin_surface_medium:            { support: "automated", technique: "http_asset" },
  subdomain_takeover:              { support: "automated", technique: "dns_takeover" },
  dse_missing_caa:                 { support: "automated", technique: "dns_caa" },
  dse_caa_no_issuers:              { support: "automated", technique: "dns_caa" },
  dse_hsts_short_maxage:           { support: "automated", technique: "http_headers" },
  dse_hsts_not_preload_eligible:   { support: "automated", technique: "http_headers" },
  dse_cookie_no_secure:            { support: "automated", technique: "http_headers" },
  dse_cookie_no_httponly:          { support: "automated", technique: "http_headers" },
  dse_cookie_no_samesite:          { support: "automated", technique: "http_headers" },

  cloud_storage_public_listing:    { support: "unsupported", technique: null,
    reason: "The affected object is served from third-party storage infrastructure outside the customer's DNS scope. Verifying it would require probing beyond the host-scope/SSRF boundary." },
  cloud_storage_takeover_risk:     { support: "unsupported", technique: null,
    reason: "The referenced storage resource is third-party infrastructure outside the customer's DNS scope; only the customer-side DNS reference is observed." },

  asset_exposure_interface_observed:      { support: "not_applicable", technique: null,
    reason: "Observation only — a weak hostname/title heuristic with no confirmed exposure to remediate." },
  asset_provider_infrastructure_observed: { support: "not_applicable", technique: null,
    reason: "Observation only — provider-hosted naming does not itself confirm a customer exposure." },
  cloud_storage_exposure_observed:        { support: "not_applicable", technique: null,
    reason: "Observation only — an intentionally public storage endpoint is not itself a defect." },
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

// Why a finding type is not verifiable — an explicit, customer-safe statement rather
// than silence. Unknown types are treated as unsupported (fail closed).
export function verificationSupportFor(findingId) {
  return ASM_VERIFICATION_SUPPORT[String(findingId || "")]
    || { support: "unsupported", technique: null, reason: "This finding type has no external verification method." };
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

// Probe ONE host over https then http. Returns { completeness, res } — any outcome
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

  if (budgetExhausted) return { completeness: "incomplete", reason: "subrequest_budget", res: null };
  if (ssrfRefused && !response) return { completeness: "ssrf_refused", res: null };
  if (!response) return { completeness: "indeterminate", reason: "unreachable", res: null }; // conservative: defer

  return { completeness: "complete", res: response };
}

// ── Per-technique observation ────────────────────────────────────────────────
// Each returns { completeness, present, evidence }. `present` is only meaningful when
// completeness === "complete"; every other value MUST defer. No technique may infer
// remediation from a check that did not conclusively happen.

async function observeHttpAsset(entry, host, fetcher) {
  const probe = await probeHost(host, fetcher);
  if (probe.completeness !== "complete") return { completeness: probe.completeness, reason: probe.reason || null };
  const asset = await assetFromResponse(host, probe.res);
  const signals = assetFingerprintSignals(asset);
  return {
    completeness: "complete",
    present: Boolean(entry.present(asset)),
    evidence: {
      status: asset.status, title: asset.title,
      admin_hostname: signals.admin_hostname, admin_title: signals.admin_title,
      sensitive_service: signals.sensitive_service, generic_default_page: signals.generic_default_page,
    },
  };
}

// subdomain_takeover: re-run the REAL detector for this host, then read its structured
// completeness. risks=[] alone is never remediation — a failed CNAME lookup or an
// unread body is ignorance (see takeoverObservationFor).
async function observeTakeover(host, fetcher, dnsImpl) {
  let mod;
  try {
    mod = await runTakeoverModule(host, [host], { fetcher, dnsQueryImpl: dnsImpl });
  } catch (err) {
    if (isSubrequestBudgetError(err)) return { completeness: "incomplete", reason: "subrequest_budget" };
    return { completeness: "indeterminate", reason: "takeover_module_failed" };
  }
  const obs = takeoverObservationFor(mod, host);
  if (!obs.complete) return { completeness: "indeterminate", reason: obs.reason || obs.status };
  const present = hostHasConfirmedTakeoverRisk(mod, host);
  const risk = (mod.risks || []).find((r) => String(r.host || "").toLowerCase() === host);
  return {
    completeness: "complete",
    present,
    evidence: {
      observation: obs.status,
      cname: risk?.cname ?? (mod.cname_observations || []).find((c) => c.host === host)?.cname ?? null,
      provider: risk?.provider ?? null,
      potential_risks: mod.potential_risks ?? 0,
      limitations: "External CNAME + provider-fingerprint observation only — it cannot confirm who controls the target service account.",
    },
  };
}

// dse_missing_caa / dse_caa_no_issuers: re-query CAA and re-evaluate the canonical
// predicate. A DNS failure is inconclusive, never "fixed".
async function observeDseCaa(findingId, host, dnsImpl) {
  let answers;
  try {
    const r = await dnsImpl(host, "CAA");
    answers = r?.Answer || [];
  } catch (err) {
    if (isSubrequestBudgetError(err)) return { completeness: "incomplete", reason: "subrequest_budget" };
    return { completeness: "indeterminate", reason: "caa_lookup_failed" };
  }
  const enrich = { caa: buildCaaFromAnswers(answers) };
  if (!dsePresenceEvidenceUsable(findingId, enrich)) {
    return { completeness: "indeterminate", reason: "caa_evidence_unusable" };
  }
  return {
    completeness: "complete",
    present: Boolean(DSE_PRESENCE[findingId](enrich)),
    evidence: {
      caa_present: enrich.caa.present,
      caa_records: enrich.caa.records.length,
      caa_issuers: enrich.caa.issuers,
      limitations: "External DNS observation only — it cannot confirm CA-side issuance policy.",
    },
  };
}

// dse_hsts_* / dse_cookie_*: re-observe the response headers with the scan's own capture
// helpers, rebuild the enrichment through the real (pure) module, then re-evaluate the
// canonical predicate.
async function observeDseHeaders(findingId, host, fetcher) {
  const probe = await probeHost(host, fetcher);
  if (probe.completeness !== "complete") return { completeness: probe.completeness, reason: probe.reason || null };

  const headers = {
    values: securityHeaderValuesFrom(probe.res.headers),
    set_cookie_raw: captureSetCookieRaw(probe.res.headers),
  };
  const enrich = runDomainSecurityEnrichmentModule(host, { headers });
  if (!dsePresenceEvidenceUsable(findingId, enrich)) {
    return { completeness: "indeterminate", reason: "header_evidence_unusable" };
  }

  // Cookie findings need cookies to reason about. A response that sets none does NOT
  // distinguish "the cookie flags were fixed" from "this particular request simply set
  // no cookies", so it is inconclusive rather than a fix. (HSTS is a plain response
  // header, so a complete response IS conclusive for it either way.)
  if (DSE_EVIDENCE_SOURCE[findingId] === "cookies" && (enrich.cookies?.found || 0) === 0) {
    return { completeness: "indeterminate", reason: "no_cookies_observed" };
  }

  return {
    completeness: "complete",
    present: Boolean(DSE_PRESENCE[findingId](enrich)),
    evidence: {
      status: probe.res.status,
      hsts_present: enrich.hsts?.present ?? null,
      hsts_max_age: enrich.hsts?.max_age ?? null,
      cookies_found: enrich.cookies?.found ?? 0,
      cookies_insecure: enrich.cookies?.insecure_count ?? 0,
      cookies_no_httponly: enrich.cookies?.no_httponly ?? 0,
      cookies_no_samesite: enrich.cookies?.no_samesite ?? 0,
      limitations: "External observation of one response only — it cannot enumerate every cookie the application may set on other paths or states.",
    },
  };
}

async function observeHost(entry, findingId, host, { fetcher, dnsImpl }) {
  switch (entry.technique) {
    case "http_asset":   return observeHttpAsset(entry, host, fetcher);
    case "dns_takeover": return observeTakeover(host, fetcher, dnsImpl);
    case "dns_caa":      return observeDseCaa(findingId, host, dnsImpl);
    case "http_headers": return observeDseHeaders(findingId, host, fetcher);
    default:             return { completeness: "unsupported_finding_type", reason: "fail_closed" };
  }
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
export async function runManagedVerificationProbe(finding, hostOrHosts, { onOutbound, dnsQueryImpl } = {}) {
  const findingId = findingTypeOf(finding);
  const entry = VERIFICATION_DISPATCH[findingId];
  if (!entry) {
    const support = verificationSupportFor(findingId);
    return {
      decision: "deferred", completeness: "unsupported_finding_type", reason: "fail_closed",
      support: support.support, support_reason: support.reason || null,
    };
  }

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
  // DNS goes through the same metering so a verification's true cost stays visible.
  const dnsImpl = dnsQueryImpl || (async (name, type) => {
    if (typeof onOutbound === "function") onOutbound();
    return dnsQuery(name, type);
  });
  const observations = [];
  let firstIncomplete = null;

  for (const host of hosts) {
    const obs = await observeHost(entry, findingId, host, { fetcher, dnsImpl });
    if (obs.completeness !== "complete") {
      firstIncomplete = firstIncomplete || obs;
      observations.push({ host, technique: entry.technique, completeness: obs.completeness, reason: obs.reason || null });
      continue;
    }
    observations.push({ host, technique: entry.technique, present: obs.present, ...(obs.evidence || {}) });
    if (obs.present) {
      return {
        decision: "still_present",
        completeness: "complete",
        technique: entry.technique,
        evidence: { hosts_total: hosts.length, hosts_checked: observations.length, observations },
      };
    }
  }

  if (firstIncomplete) {
    return {
      decision: "deferred",
      completeness: firstIncomplete.completeness,
      reason: firstIncomplete.reason || null,
      technique: entry.technique,
      evidence: { hosts_total: hosts.length, hosts_checked: observations.length, observations },
    };
  }

  return {
    decision: "fixed",
    completeness: "complete",
    technique: entry.technique,
    evidence: { hosts_total: hosts.length, hosts_checked: observations.length, observations },
  };
}
