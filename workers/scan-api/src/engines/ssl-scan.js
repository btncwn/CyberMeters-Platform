// ── SSL / TLS scan module ──
// External-scan HTTPS/TLS phase: HTTPS reachability, certificate expiry via Certificate
// Transparency (crt.sh + certspotter fallback), SAN discovery. Extracted verbatim from
// index.js (monolith decomposition, Phase 1c) — no logic change.
import { safeFetch } from "../lib/http.js";
import { normalizeCertificateSanNames, normalizeDiscoveredHostname, parseCertificateSanNames } from "./hostnames.js";

// ── Module 2: SSL Detection ───────────────────────────────────────────────────

// Certificate Transparency lookup (crt.sh + certspotter fallback). Extracted from
// runSslModule VERBATIM (same calls, same field logic, same timeouts) so it can run
// CONCURRENTLY with the HTTPS reachability probes: the two are independent (cert
// data comes from CT logs, not from reaching the origin), and running them
// sequentially made the SSL module's wall-time the SUM of both chains — up to ~16s
// of CT lookups on top of reachability, which on a slow-crt.sh day pushed the whole
// scan past its ~21s deadline and starved the later deadline-gated modules
// (docs/CHRONIC-PARTIAL-SCAN-ROOT-CAUSE.md). Returns the 11 cert_* fields; on any
// failure they stay null/0 exactly as before (best-effort — the scan still completes).
function recordFetchError(accounting, err) {
  accounting?.recordError?.(err);
  throw err;
}

async function countedFetch(url, init, accounting = null) {
  accounting?.recordAttempt?.();
  try {
    const res = await fetch(url, init);
    accounting?.recordCompleted?.();
    return res;
  } catch (err) {
    recordFetchError(accounting, err);
  }
}

export async function resolveCertificateTransparency(domain, opts = {}) {
  const accounting = opts.accounting || null;
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
  try {
    const crtRes = await countedFetch(
      `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`,
      {
        headers: { Accept: "application/json", "User-Agent": "CyberMeters/1.0" },
        signal:  AbortSignal.timeout(8_000),
      },
      accounting
    );
    if (crtRes.ok) {
      const ct = crtRes.headers.get("content-type") || "";
      if (ct.includes("json")) {
        const certs = await crtRes.json();
        if (Array.isArray(certs)) {
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
      }
    }
  } catch {
    // crt.sh unavailable — cert expiry data omitted, scan still completes
  }

  // Fallback: crt.sh is frequently slow/flaky, so if it yielded no usable
  // certificate, try certspotter (a second CT source). This prevents a single
  // source's timeout from leaving the inventory showing "Unknown" issuer/expiry
  // for a host that plainly serves a valid certificate.
  if (cert_not_after == null) {
    try {
      const csRes = await countedFetch(
        `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=false&expand=dns_names&expand=issuer`,
        {
          headers: { Accept: "application/json", "User-Agent": "CyberMeters/1.0" },
          signal:  AbortSignal.timeout(8_000),
        },
        accounting
      );
      if (csRes.ok && (csRes.headers.get("content-type") || "").includes("json")) {
        const issuances = await csRes.json();
        if (Array.isArray(issuances)) {
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
      }
    } catch {
      // certspotter unavailable too — cert data stays null; page reads "unknown"
    }
  }

  return {
    cert_expiry_days, cert_age_days, cert_not_before, cert_not_after,
    cert_issuer, cert_subject, cert_san_count, cert_raw_san_count,
    cert_wildcard_san_count, cert_shared_san_count, cert_san_names,
  };
}

export async function runSslModule(domain, opts = {}) {
  const accounting = opts.accounting || null;
  // Launch the Certificate Transparency lookup CONCURRENTLY with the reachability
  // probes below. The two are independent, so awaiting the promise at the end makes
  // the module's wall-time max(reachability, CT) instead of their sum.
  const certPromise = resolveCertificateTransparency(domain, { accounting });

  // Try HTTPS on the bare domain
  const httpsRes = await safeFetch(`https://${domain}`, {
    method: "HEAD",
    redirect: "manual",
    accounting,
  });
  const httpsOk = httpsRes !== null && httpsRes.status < 500;

  // Try www. fallback if bare domain HTTPS fails
  let wwwHttpsOk = false;
  let wwwRes = null;
  if (!httpsOk && !domain.startsWith("www.")) {
    wwwRes = await safeFetch(`https://www.${domain}`, {
      method: "HEAD",
      redirect: "manual",
      accounting,
    });
    wwwHttpsOk = wwwRes !== null && wwwRes.status < 500;
  }

  // ── Did we actually LOOK? ───────────────────────────────────────────────────
  // safeFetch returns null for a 10s timeout, a redirect loop, a blocked target or
  // any thrown error. None of those observed anything about port 443.
  //
  // This distinction already existed one field below — `http_redirect_validated`
  // stays false on a null response precisely so the scoring engine will not claim
  // a redirect verdict it never saw. The same discipline was never applied to
  // reachability, so a timed-out probe collapsed into `https_available: false`,
  // and scoring turned that into a CRITICAL finding asserting "TLS handshake
  // failed or connection refused on port 443" — a claim about the customer's
  // server that safeFetch cannot make, because a timeout is not a refusal.
  //
  // https_available is therefore TRI-STATE, matching the platform's existing
  // unknown vocabulary (probeAsset's `reachable: null`):
  //   true  — a response was observed over HTTPS
  //   false — a response was observed and HTTPS is genuinely not serving (>=500)
  //   null  — WE DID NOT LOOK. Never a security claim.
  // Consumers that already test `=== true` / `=== false` are unaffected by null;
  // the two that tested truthiness (`!ssl.https_available`) are corrected in this
  // same change, because to them null previously meant "not available".
  const httpsProbeExecuted = httpsRes !== null || wwwRes !== null;
  const httpsAvailable = httpsProbeExecuted ? (httpsOk || wwwHttpsOk) : null;

  // Check whether plain HTTP redirects to HTTPS.
  // Follow up to 2 hops to handle intermediate http→http→https chains
  // (e.g. http://google.com → 301 → http://www.google.com → 301 → https://www.google.com).
  const httpOrigUrl = `http://${domain}`;
  const httpRes = await safeFetch(httpOrigUrl, { method: "HEAD", redirect: "manual", accounting });
  let httpRedirectsToHttps = false;
  // http_redirect_validated starts false — only set true when safeFetch returns a
  // response (not null).  A null response means the fetch was blocked or timed out
  // (geo-routing, bot protection, firewall) and we cannot draw conclusions about
  // redirect behaviour.  The scoring engine skips ssl_no_http_redirect when this
  // stays false to avoid false positives on enterprise edge deployments.
  let http_redirect_chain = {
    original_url:            httpOrigUrl,
    final_url:               null,
    redirect_count:          0,
    http_redirect_validated: false,
  };

  if (httpRes) {
    // We got a response — the chain is at least partially observable.
    http_redirect_chain.http_redirect_validated = true;

    const status1 = httpRes.status;
    const rawLoc1 = httpRes.headers.get("location") || "";
    if ([301, 302, 307, 308].includes(status1) && rawLoc1) {
      let loc1;
      try { loc1 = new URL(rawLoc1, httpOrigUrl).href; } catch { loc1 = rawLoc1; }

      if (loc1.startsWith("https://")) {
        // Direct http→https — best case
        httpRedirectsToHttps = true;
        http_redirect_chain = { original_url: httpOrigUrl, final_url: loc1, redirect_count: 1, http_redirect_validated: true };
      } else {
        // First hop stayed on HTTP — follow one more hop to catch http→http→https
        const hop2 = await safeFetch(loc1, { method: "HEAD", redirect: "manual", accounting });
        if (hop2) {
          const rawLoc2 = hop2.headers.get("location") || "";
          let loc2;
          try { loc2 = new URL(rawLoc2, loc1).href; } catch { loc2 = rawLoc2; }
          if ([301, 302, 307, 308].includes(hop2.status) && loc2.startsWith("https://")) {
            httpRedirectsToHttps = true;
            http_redirect_chain = { original_url: httpOrigUrl, final_url: loc2, redirect_count: 2, http_redirect_validated: true };
          }
        }
      }
    }
  }

  // ── SSL Certificate Expiry (via Certificate Transparency) ───────────────────
  // Resolved concurrently with the reachability probes above (launched at the top
  // of this function). Best-effort — failure leaves cert_expiry_days as null.
  const {
    cert_expiry_days, cert_age_days, cert_not_before, cert_not_after,
    cert_issuer, cert_subject, cert_san_count, cert_raw_san_count,
    cert_wildcard_san_count, cert_shared_san_count, cert_san_names,
  } = await certPromise;

  return {
    https_available:          httpsAvailable,
    https_probe_executed:     httpsProbeExecuted,
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
    ...(httpsProbeExecuted ? {} : {
      incomplete: true,
      incomplete_reason: "https_probe_not_executed",
    }),
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
  };
}
