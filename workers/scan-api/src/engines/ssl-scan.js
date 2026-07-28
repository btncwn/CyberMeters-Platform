// ── SSL / TLS scan module ──
// External-scan HTTPS/TLS phase: HTTPS reachability, certificate expiry via Certificate
// Transparency (crt.sh + certspotter fallback), SAN discovery. Extracted verbatim from
// index.js (monolith decomposition, Phase 1c) — no logic change.
import { safeFetch } from "../lib/http.js";
import { customerSafeFailure } from "../lib/errors.js";
import { aggregateFetchObservations, classifyFetchObservation } from "../lib/fetch-observation.js";
import { createCertificateTransparencyCache } from "./ct-provider-cache.js";
import { normalizeCertificateSanNames, normalizeDiscoveredHostname, parseCertificateSanNames } from "./hostnames.js";

// ── Module 2: SSL Detection ───────────────────────────────────────────────────

// Certificate Transparency lookup (crt.sh + certspotter fallback). The certificate
// field logic remains the extracted behavior; provider I/O now comes from the shared
// per-scan cache. It runs CONCURRENTLY with HTTPS probes because certificate data
// comes from CT logs, not from reaching the origin, and running them
// sequentially made the SSL module's wall-time the SUM of both chains — up to ~16s
// of CT lookups on top of reachability, which on a slow-crt.sh day pushed the whole
// scan past its ~21s deadline and starved the later deadline-gated modules
// (docs/CHRONIC-PARTIAL-SCAN-ROOT-CAUSE.md). Returns the 11 cert_* fields; on any
// failure they stay null/0 exactly as before (best-effort — the scan still completes).
export async function resolveCertificateTransparency(domain, opts = {}) {
  const accounting = opts.accounting || null;
  const ctCache = opts.ctCache || createCertificateTransparencyCache({ signal: opts.signal });
  const rootDomain = String(domain || "").trim().toLowerCase().replace(/\.$/, "");
  const coversRootDomain = (names) => parseCertificateSanNames(names).some((name) =>
    name.replace(/^\*\./, "") === rootDomain
  );
  let cert_expiry_days = null;
  let cert_age_days    = null;
  let cert_not_before  = null;
  let cert_not_after   = null;
  let cert_issuer      = null;
  let cert_subject     = null;
  let cert_san_count   = 0;
  let cert_raw_san_count = 0;
  let cert_wildcard_san_count = 0;
  let cert_shared_san_count = 0;
  let cert_san_names   = [];
  const ct_sources = { crt_sh: null, certspotter: null };
  try {
    const crtResult = await ctCache.get(domain, "crt_sh", { accounting, module: "ssl" });
    ct_sources.crt_sh = {
      count: crtResult.status === "available" ? crtResult.data.length : 0,
      error: crtResult.status === "unavailable" ? crtResult.error : null,
    };
    if (crtResult.status === "available") {
      const certs = crtResult.data.filter((certificate) =>
        coversRootDomain(certificate.name_value || certificate.common_name || domain)
      );
      const now = Date.now();
      // Keep only certs that are currently valid (not yet expired).
      // Sort by not_after descending so the longest-lived cert comes first —
      // that is the one most likely still active on the server.
      const valid = certs
        .filter(c => c.not_after && new Date(c.not_after).getTime() > now)
        .sort((a, b) => new Date(b.not_after).getTime() - new Date(a.not_after).getTime());
      if (valid.length > 0) {
        const selected = valid[0];
        const rawSanNames = parseCertificateSanNames(selected.name_value || selected.common_name || domain);
        cert_not_before  = selected.not_before || null;
        cert_not_after   = valid[0].not_after;
        cert_expiry_days = Math.floor(
          (new Date(cert_not_after).getTime() - now) / 86_400_000
        );
        const notBeforeMs = cert_not_before ? new Date(cert_not_before).getTime() : NaN;
        cert_age_days = Number.isFinite(notBeforeMs)
          ? Math.max(0, Math.floor((now - notBeforeMs) / 86_400_000))
          : null;
        cert_issuer    = selected.issuer_name || null;
        cert_subject   = selected.common_name || domain;
        cert_san_names = normalizeCertificateSanNames(
          selected.name_value || selected.common_name || domain,
          domain
        );
        cert_san_count = cert_san_names.length;
        cert_raw_san_count = rawSanNames.length;
        cert_wildcard_san_count = rawSanNames.filter((name) => name.includes("*")).length;
        cert_shared_san_count = rawSanNames.filter((name) =>
          !normalizeDiscoveredHostname(name.replace(/^\*\./, ""), domain)
        ).length;
      }
    }
  } catch (err) {
    ct_sources.crt_sh = {
      count: 0,
      error: customerSafeFailure("scan/ct/crt-sh-consume", err, "parse error"),
    };
  }

  // Fallback: crt.sh is frequently slow/flaky, so if it yielded no usable
  // certificate, try certspotter (a second CT source). This prevents a single
  // source's timeout from leaving the inventory showing "Unknown" issuer/expiry
  // for a host that plainly serves a valid certificate.
  if (cert_not_after == null) {
    try {
      const certSpotterResult = await ctCache.get(domain, "certspotter", { accounting, module: "ssl" });
      ct_sources.certspotter = {
        count: certSpotterResult.status === "available" ? certSpotterResult.data.length : 0,
        error: certSpotterResult.status === "unavailable" ? certSpotterResult.error : null,
      };
      if (certSpotterResult.status === "available") {
        const issuances = certSpotterResult.data.filter((issuance) =>
          coversRootDomain(
            (Array.isArray(issuance.dns_names) ? issuance.dns_names : []).join(" ")
          )
        );
        const now = Date.now();
        const valid = issuances
          .filter((c) => c.not_after && new Date(c.not_after).getTime() > now)
          .sort((a, b) => new Date(b.not_after).getTime() - new Date(a.not_after).getTime());
        if (valid.length > 0) {
          const selected = valid[0];
          const dnsNames = Array.isArray(selected.dns_names) ? selected.dns_names : [];
          cert_not_before  = selected.not_before || null;
          cert_not_after   = selected.not_after;
          cert_expiry_days = Math.floor((new Date(cert_not_after).getTime() - now) / 86_400_000);
          const notBeforeMs = cert_not_before ? new Date(cert_not_before).getTime() : NaN;
          cert_age_days = Number.isFinite(notBeforeMs)
            ? Math.max(0, Math.floor((now - notBeforeMs) / 86_400_000))
            : null;
          cert_issuer    = (selected.issuer && selected.issuer.name) || null;
          cert_subject   = domain;
          cert_san_names = normalizeCertificateSanNames(dnsNames.join(" "), domain);
          cert_san_count = cert_san_names.length;
          cert_raw_san_count = dnsNames.length;
          cert_wildcard_san_count = dnsNames.filter((n) => n.includes("*")).length;
        }
      }
    } catch (err) {
      ct_sources.certspotter = {
        count: 0,
        error: customerSafeFailure("scan/ct/certspotter-consume", err, "parse error"),
      };
    }
  }

  return {
    cert_expiry_days, cert_age_days, cert_not_before, cert_not_after,
    cert_issuer, cert_subject, cert_san_count, cert_raw_san_count,
    cert_wildcard_san_count, cert_shared_san_count, cert_san_names, ct_sources,
  };
}

export async function runSslModule(domain, opts = {}) {
  const accounting = opts.accounting || null;
  const observedAt = typeof opts.now === "function"
    ? new Date(opts.now()).toISOString()
    : new Date().toISOString();
  // Launch the Certificate Transparency lookup CONCURRENTLY with the reachability
  // probes below. The two are independent, so awaiting the promise at the end makes
  // the module's wall-time max(reachability, CT) instead of their sum.
  const certPromise = resolveCertificateTransparency(domain, {
    accounting,
    signal: opts.signal,
    ctCache: opts.ctCache,
  });

  // Try HTTPS on the bare domain
  const httpsRes = await safeFetch(`https://${domain}`, {
    method: "HEAD",
    redirect: "manual",
    accounting,
  });
  // ONE shared classifier decides what this fetch observed (lib/fetch-observation.js).
  // Any origin status — 2xx/3xx/4xx AND 5xx — proves HTTPS transport: to answer at
  // all over https:// the handshake completed and a certificate was accepted. A
  // Cloudflare-synthesised 52x/530 is NOT an origin answer and proves nothing either
  // way. The old `status < 500` rule got both wrong.
  const bareObservation = classifyFetchObservation({ response: httpsRes });
  const httpsOk = bareObservation.transport_observed === true;

  // Try www. fallback if the bare domain did not PROVE transport. An edge error or a
  // timeout on the bare name is inconclusive, not a negative, so the fallback still
  // runs — it may yet observe a genuine origin.
  let wwwHttpsOk = false;
  let wwwRes = null;
  let wwwObservation = null;
  if (!httpsOk && !domain.startsWith("www.")) {
    wwwRes = await safeFetch(`https://www.${domain}`, {
      method: "HEAD",
      redirect: "manual",
      accounting,
    });
    wwwObservation = classifyFetchObservation({ response: wwwRes });
    wwwHttpsOk = wwwObservation.transport_observed === true;
  }

  // ── What did we actually OBSERVE? ───────────────────────────────────────────
  // Three facts used to collapse into one boolean, and two of them were lies:
  //
  //   • a genuine origin response          → transport PROVEN
  //   • a Cloudflare-synthesised 52x/530   → a real Response, but NO origin answered
  //   • a timeout / refusal / block / null → nothing observed about port 443
  //
  // Reading the middle two as `false` is how a domain serving valid TLS produced a
  // CRITICAL "HTTPS Not Available" finding — "TLS handshake failed or connection
  // refused on port 443" — and an email telling its owner to install a certificate.
  // A Workers fetch cannot make that claim: it can PROVE transport, never disprove it.
  //
  // https_available keeps its TRI-STATE contract, so every consumer testing
  // `=== true` / `=== false` is untouched:
  //   true  — an origin answered over HTTPS (any status, including 5xx)
  //   false — RESERVED for positive TLS/certificate evidence of absence, which a
  //           Workers fetch cannot produce. This probe therefore never emits false;
  //           the certificate signal family owns that verdict.
  //   null  — not observed. Never a security claim.
  //
  // The `false` case is retained in the contract rather than removed because
  // scoring.js / posture-scoring.js / ce-readiness.js / cert-intel.js all branch on
  // `=== false`, and a TLS-evidence producer may legitimately set it later.
  //
  // The bare null is no longer the whole story: the additive fields below say WHICH
  // of the non-observations happened, so "edge error" and "we never looked" stay
  // distinguishable downstream.
  // Aggregate by canonical precedence, keeping BOTH endpoints' provenance. The old
  // "www if it proved transport, else bare" rule silently discarded the sibling's
  // reason: bare timeout + www edge error reported transport_unavailable and lost
  // the edge attribution entirely.
  const httpsObservation = aggregateFetchObservations([
    { endpoint: domain, observation: bareObservation },
    ...(wwwObservation ? [{ endpoint: `www.${domain}`, observation: wwwObservation }] : []),
  ]);
  // UNCHANGED CONTRACT. `https_probe_executed` means "the probe came back with a
  // response we could look at", not "we attempted a request". buildScanQuality,
  // moduleAssessed() and canVerify('ssl') all depend on that reading: a timed-out
  // probe must keep this FALSE so the scan degrades to `partial` and can never
  // verify or resolve an SSL condition. A Cloudflare edge error DOES set it true —
  // a Response object came back and the edge was genuinely observed — which is
  // exactly the founder contract ("probe was executed", observation incomplete).
  const httpsProbeExecuted = httpsRes !== null || wwwRes !== null;
  const httpsAvailable = (httpsOk || wwwHttpsOk) ? true : null;

  // Check whether plain HTTP redirects to HTTPS.
  // Follow up to 2 hops to handle intermediate http→http→https chains
  // (e.g. http://google.com → 301 → http://www.google.com → 301 → https://www.google.com).
  const httpOrigUrl = `http://${domain}`;
  const httpRes = await safeFetch(httpOrigUrl, { method: "HEAD", redirect: "manual", accounting });
  let httpRedirectsToHttps = false;

  // PR-A2 — the redirect chain is classified by the SAME shared observation
  // classifier as the HTTPS probe (lib/fetch-observation.js), on the initial hop
  // AND on every follow-on hop.
  //
  // `http_redirect_validated` used to be set true whenever safeFetch returned a
  // non-null Response. A Cloudflare-synthesised 520–527/530 IS a non-null Response,
  // so the chain was marked *validated* on evidence that never reached the
  // customer's origin, and scoring.js then took its DEFINITIVE branch:
  // "HTTP Does Not Redirect to HTTPS", medium, score_impact -5 — a verdict about a
  // server nobody ever spoke to. This is the same root class as PR-A1, one field
  // over: probe execution read as evidence completion.
  //
  // Validation now requires a GENUINE ORIGIN response. Anything else — edge error,
  // timeout, refusal, block — is honestly "not observed", exactly as a null
  // response already was.
  const httpObservation = classifyFetchObservation({ response: httpRes });
  const redirectHops = [{
    hop:           1,
    url:           httpOrigUrl,
    state:         httpObservation.state,
    reason:        httpObservation.reason,
    origin_status: httpObservation.origin_status,
  }];
  // SEQUENTIAL contract, deliberately NOT the bare/www aggregate rule.
  //
  // Those two endpoints are INDEPENDENT — a genuine origin response from either one
  // is decisive, so precedence lets it win. The redirect chain is a DEPENDENCY: hop 1
  // answering tells us nothing about hop 2, and hop 2 is REQUIRED whenever hop 1
  // redirects to another HTTP URL. An earlier origin response can never override an
  // inconclusive later hop.
  //
  // `chainObservation` therefore tracks the FIRST inconclusive REQUIRED hop, and
  // `redirectEvidenceObserved` means "the entire required redirect decision was
  // observed" — not merely "hop 1 answered". Previously both came from hop 1 alone,
  // so a genuine 301 into a Cloudflare-signed 522 published the definitive
  // "HTTP Does Not Redirect to HTTPS" (medium, -5) with the required hop unobserved.
  let chainObservation = httpObservation;
  let redirectEvidenceObserved = httpObservation.transport_observed === true;

  let http_redirect_chain = {
    original_url:            httpOrigUrl,
    final_url:               null,
    redirect_count:          0,
    http_redirect_validated: redirectEvidenceObserved,
  };

  if (redirectEvidenceObserved) {
    const status1 = httpObservation.origin_status;
    const rawLoc1 = httpRes.headers.get("location") || "";
    if ([301, 302, 307, 308].includes(status1) && rawLoc1) {
      let loc1;
      try { loc1 = new URL(rawLoc1, httpOrigUrl).href; } catch { loc1 = rawLoc1; }

      if (loc1.startsWith("https://")) {
        // Direct http→https — best case
        httpRedirectsToHttps = true;
        http_redirect_chain = { original_url: httpOrigUrl, final_url: loc1, redirect_count: 1, http_redirect_validated: true };
      } else {
        // First hop stayed on HTTP — follow one more hop to catch http→http→https.
        // The second hop is classified too: a chain that ends in a Cloudflare edge
        // error has not been observed to reach HTTPS, and must not be read as one
        // that has.
        const hop2 = await safeFetch(loc1, { method: "HEAD", redirect: "manual", accounting });
        const hop2Observation = classifyFetchObservation({ response: hop2 });
        redirectHops.push({
          hop:           2,
          url:           loc1,
          state:         hop2Observation.state,
          reason:        hop2Observation.reason,
          origin_status: hop2Observation.origin_status,
        });
        if (hop2Observation.transport_observed === true) {
          const rawLoc2 = hop2.headers.get("location") || "";
          let loc2;
          try { loc2 = new URL(rawLoc2, loc1).href; } catch { loc2 = rawLoc2; }
          if ([301, 302, 307, 308].includes(hop2Observation.origin_status) && loc2.startsWith("https://")) {
            httpRedirectsToHttps = true;
            http_redirect_chain = { original_url: httpOrigUrl, final_url: loc2, redirect_count: 2, http_redirect_validated: true };
          }
        } else {
          // The REQUIRED second hop was not observed (edge error, timeout, refusal,
          // block). The redirect decision is therefore unobserved as a whole: hop 1's
          // origin response does not rescue it. Chain-level state comes from THIS hop,
          // not from hop 1, so downstream sees the real reason.
          redirectEvidenceObserved = false;
          chainObservation = hop2Observation;
          http_redirect_chain.http_redirect_validated = false;
        }
      }
    }
  }
  // Additive observation metadata + bounded per-hop provenance (≤ 2 hops, matching
  // the chain depth this module follows). Nothing below reads these yet; they exist
  // so a consumer never has to infer WHY a redirect verdict was withheld.
  // CHAIN-level state — the first inconclusive REQUIRED hop, not hop 1. Publishing
  // hop 1's `origin_response` while a required later hop was an edge error is what
  // made an unobserved chain look decisive.
  http_redirect_chain.observation_state  = chainObservation.state;
  http_redirect_chain.observation_reason = chainObservation.reason;
  http_redirect_chain.observation_completeness = chainObservation.completeness;
  http_redirect_chain.hop_observations   = redirectHops;

  // ── SSL Certificate Expiry (via Certificate Transparency) ───────────────────
  // Resolved concurrently with the reachability probes above (launched at the top
  // of this function). Best-effort — failure leaves cert_expiry_days as null.
  const {
    cert_expiry_days, cert_age_days, cert_not_before, cert_not_after,
    cert_issuer, cert_subject, cert_san_count, cert_raw_san_count,
    cert_wildcard_san_count, cert_shared_san_count, cert_san_names, ct_sources,
  } = await certPromise;

  return {
    https_available:          httpsAvailable,
    https_probe_executed:     httpsProbeExecuted,
    // Additive observation metadata — the explicit WHY behind a null, so no consumer
    // has to guess whether an absent boolean means "edge error", "timed out" or "we
    // never looked". Purely additive: nothing below reads these yet, and every
    // existing `=== true` / `=== false` consumer is untouched.
    //   observed | incomplete | unavailable | not_assessed
    https_observation_state:  httpsObservation.state,
    https_observation_reason: httpsObservation.reason,
    https_observation_completeness: httpsObservation.completeness,
    // Present ONLY for a genuine origin answer. A 5xx here means the origin served
    // an error over a working TLS channel — an application-health fact, never
    // certificate absence and never "traffic is transmitted unencrypted".
    https_origin_status:      httpsObservation.origin_status,
    // The module did not truly run its reachability check. buildScanQuality reads
    // this into scan_quality `partial`, moduleAssessed() into evidence_insufficient
    // and moduleCompletionGate into "cannot verify" — so an unexecuted probe can
    // never present as healthy and can never resolve an existing condition.
    //
    // Scoped to the HTTPS probe deliberately: Certificate Transparency data below
    // comes from crt.sh/certspotter and is independent of reaching the origin, so
    // it stays valid and is not discarded. What is unknown is whether the site
    // serves HTTPS — which is exactly what `required: ["headers","ssl"]` on the
    // Website Security domain is asking.
    // PR-A1 — the gate is EVIDENCE, not EXECUTION.
    //
    // This was `httpsProbeExecuted ? {} : {incomplete}`, so a Cloudflare-signed
    // 522/530 — which DOES return a Response, hence executed:true — never marked the
    // module incomplete. The scan then finalized `complete` and the Cyber MOT
    // resolver published website_security and certificates_trust as
    // "Assessed — no material issue observed" having observed no TLS at all. That is
    // the false-healthy half of the same defect: swapping a false alarm for a false
    // all-clear is not a fix.
    //
    //     executed  !=  evidence complete
    //
    // `https_probe_executed` stays TRUTHFUL above (true for an edge Response). What
    // changes is that incompleteness is now derived from whether a genuine ORIGIN
    // response was observed. Reasons are a bounded canonical set:
    //   https_probe_not_executed    — nothing came back at all (pre-existing value,
    //                                 preserved so existing consumers are unchanged)
    //   https_origin_not_observed   — a Cloudflare edge Response, no origin answer
    //   https_transport_unavailable — the probe ran and observed no transport
    //
    // PR-A2 adds the REDIRECT signal to the same canonical channel. If the HTTP
    // probe never reached the origin, the redirect verdict is withheld — and a
    // withheld verdict must not read as a FIXED redirect. Without this, the
    // definitive finding simply stops being produced, and on an otherwise complete
    // scan moduleCompletionGate.canVerify('ssl') would let the lifecycle RESOLVE an
    // open redirect condition: disappearance read as removal.
    //
    // Reason precedence: the HTTPS transport gap is the more fundamental one and
    // wins when both are unobserved.
    ...((httpsAvailable === true && redirectEvidenceObserved) ? {} : {
      incomplete: true,
      incomplete_reason: httpsAvailable !== true
        ? (!httpsProbeExecuted
          ? "https_probe_not_executed"
          : httpsObservation.state === "cloudflare_edge_error"
            ? "https_origin_not_observed"
            : "https_transport_unavailable")
        : "http_redirect_not_observed",
    }),
    // Per-endpoint provenance (bounded: bare + www only). A sibling's more
    // informative reason survives the aggregate rather than being discarded.
    https_endpoint_observations: httpsObservation.endpoints || [],
    http_redirects_to_https:  httpRedirectsToHttps,
    http_redirect_chain,
    www_fallback_used:        !httpsOk && wwwHttpsOk,
    cert_expiry_days,
    cert_age_days,
    cert_not_before,
    cert_not_after,
    cert_issuer,
    cert_subject,
    cert_san_count,
    cert_raw_san_count,
    cert_wildcard_san_count,
    cert_shared_san_count,
    cert_san_names,
    ct_sources,
    // Item 9 P2: explicit collection scope for the per-signal certificate model.
    // This is metadata over evidence already collected above: it performs no probe
    // and intentionally refuses to present CT issuance as a live TLS certificate.
    certificate_evidence: {
      schema_version: "external-certificate-observation-v2",
      observed_at: observedAt,
      live_tls: {
        // Legacy booleans remain for historical readers. The structured fields
        // below are the P4 trust-policy contract and are deliberately absent until
        // a compatible peer-certificate collector supplies real handshake evidence.
        leaf_collected: false,
        chain_collected: false,
        trust_store_context: null,
        leaf_certificate: {
          collection_performed: false,
          collection_complete: false,
          certificate_identity: null,
        },
        presented_chain: {
          collection_performed: false,
          collection_complete: false,
          presentation_state: "unknown",
          intermediates: [],
        },
        hostname_match: {
          assessment_performed: false,
          result: "unknown",
          reference_hostname: domain,
        },
        trust_store_validation: {
          validation_performed: false,
          validation_result: "unknown",
          certificate_identity: null,
          trust_store_context: null,
        },
        revocation_assurance: {
          assessment_performed: false,
          stapled_ocsp: null,
          response_validated: false,
          status: "unknown",
          certificate_identity: null,
        },
        reason: "worker_http_fetch_does_not_expose_peer_certificate",
      },
      ct_projection: {
        source: "shared_ct_provider_cache",
        selected_certificate_observed: Boolean(
          cert_not_after || cert_issuer || cert_subject
        ),
      },
      parallel_certificate_set: {
        collection_performed: false,
        observation_scope: "live_tls_endpoint_set",
        reason: "simultaneous_endpoint_certificate_set_not_collected",
      },
      active_service: {
        probe_executed: httpsProbeExecuted,
        https_available: httpsAvailable,
        // Same additive observation metadata as the module root, so the per-signal
        // certificate model can tell an edge error from a probe that never ran
        // without re-deriving it from a bare null.
        observation_state: httpsObservation.state,
        observation_reason: httpsObservation.reason,
        observation_completeness: httpsObservation.completeness,
        origin_status: httpsObservation.origin_status,
        endpoint_context: wwwHttpsOk ? `www.${domain}` : domain,
      },
    },
  };
}
