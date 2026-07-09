// ── Certificate intelligence module ──
// Sensitive-host classification, certificate ownership assessment, and the certificate
// intelligence scan roll-up (expiry, CA concentration, self-signed, lifecycle). Extracted
// verbatim from index.js (monolith decomposition, Phase 1c). CERT_SENSITIVE_LABELS is
// module-internal.
import {
  buildCaConcentrationAnalytics,
  buildCertificateLifecycleIntelligence,
  detectSelfSignedCertificate,
  extractCertificateCryptoMetadata,
  mapCertificateAuthorityOwner,
  normalizeCertificateIssuer,
} from "./cert-analysis.js";
import { normalizeHostname } from "./hostnames.js";

// ── Certificate Intelligence ─────────────────────────────────────────────────
// Correlates SSL certificate data with CT-discovered hostname inventory to
// produce a certificate-level intelligence view.
//
// Data sources (already in modules — zero new network calls):
//   modules.ssl          → cert_expiry_days, cert_not_after, https_available
//   modules.subdomains   → CT-sourced hostname list, sensitive[], wildcard_dns,
//                          sources (crt_sh + certspotter counts)
//   modules.dns_bruteforce → brute-forced hostnames
//   domain               → apex for sensitive-label checks
//
// Suspicious signals emitted:
//   certificate_expiring_soon    (< 30 days)
//   certificate_expiring_critical(< 14 days)
//   wildcard_dns_detected        (informational DNS behavior observation)
//   sensitive_hosts_in_ct        (admin/vpn/portal/sso/login/mail/dev/staging etc.)
//   high_subdomain_growth        (CT count > 50 — large attack surface)
//   ct_source_discrepancy        (one source >> the other — may indicate stale CT log)
//   no_https                     (HTTPS unavailable)

/** Hostnames whose labels indicate certificate-relevant sensitivity */
const CERT_SENSITIVE_LABELS = new Set([
  "admin", "vpn", "portal", "login", "sso", "mail", "webmail",
  "dev", "staging", "stage", "test", "qa", "sandbox",
  "remote", "auth", "oauth", "api", "app", "dashboard",
]);

export function isCertSensitiveHost(hostname, domain) {
  const sub = hostname.endsWith("." + domain)
    ? hostname.slice(0, -(domain.length + 1))
    : hostname;
  return sub.split(".").some((label) => CERT_SENSITIVE_LABELS.has(label.toLowerCase()));
}

export function buildCertificateOwnershipAssessment(ssl, domain) {
  const root = normalizeHostname(domain);
  const subject = String(ssl?.cert_subject || "").toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
  const customerSans = Array.isArray(ssl?.cert_san_names) ? ssl.cert_san_names : [];
  const sharedSanCount = Number(ssl?.cert_shared_san_count || 0);
  const wildcardSanCount = Number(ssl?.cert_wildcard_san_count || 0);
  const subjectMatches = Boolean(root && (subject === root || subject.endsWith(`.${root}`)));

  if (sharedSanCount > 0) {
    return {
      status: "shared_certificate",
      confidence: 50,
      customer_owned: false,
      shared_san_count: sharedSanCount,
      wildcard_san_count: wildcardSanCount,
      evidence_signals: ["customer_san", "unrelated_san"],
    };
  }
  if (subjectMatches || customerSans.length > 0) {
    return {
      status: wildcardSanCount > 0 ? "customer_domain_wildcard" : "customer_domain_certificate",
      confidence: wildcardSanCount > 0 ? 70 : 90,
      customer_owned: true,
      shared_san_count: 0,
      wildcard_san_count: wildcardSanCount,
      evidence_signals: [subjectMatches ? "subject_match" : "customer_san"],
    };
  }
  return {
    status: "ownership_uncertain",
    confidence: 60,
    customer_owned: false,
    shared_san_count: sharedSanCount,
    wildcard_san_count: wildcardSanCount,
    evidence_signals: [],
  };
}

/**
 * runCertificateIntelligenceModule(modules, domain) — pure computation, zero I/O.
 *
 * Returns:
 *   { total_certificates_seen, certificate_status, issuer, subject, san_count,
 *     expires_at, days_until_expiry, issued_for_sensitive_hosts,
 *     newly_observed_hosts, suspicious_certificate_signals,
 *     certificate_risk_level, source: "ssl_ct_correlation", error: null }
 */
export function runCertificateIntelligenceModule(modules, domain) {
  try {
    const ssl      = modules?.ssl       || {};
    const subMod   = modules?.subdomains || {};
    const brute    = modules?.dns_bruteforce || {};

    // ── Certificate expiry data ───────────────────────────────────────────
    const days_until_expiry = ssl.cert_expiry_days ?? null;
    const expires_at        = ssl.cert_not_after   ?? null;
    const https_available   = ssl.https_available  ?? false;
    const certificate_ownership = buildCertificateOwnershipAssessment(ssl, domain);

    // ── CT hostname inventory ─────────────────────────────────────────────
    const ctHosts    = Array.isArray(subMod.items)    ? subMod.items    : [];
    const bruteHosts = Array.isArray(brute.items)
      ? brute.items.filter((item) => item?.wildcard_match !== true).map((i) => i.hostname || i).filter(Boolean)
      : [];
    const allHosts   = [...new Set([...ctHosts, ...bruteHosts])];

    const total_certificates_seen = allHosts.length;

    // ── Sensitive hosts in CT ─────────────────────────────────────────────
    const issued_for_sensitive_hosts = allHosts
      .filter((h) => isCertSensitiveHost(h, domain))
      .sort();

    // Also capture the pre-classified sensitive list from subdomains module
    const subSensitive = Array.isArray(subMod.sensitive) ? subMod.sensitive : [];
    const allSensitive = [...new Set([...issued_for_sensitive_hosts, ...subSensitive])].sort();

    // ── CT source health ──────────────────────────────────────────────────
    const crtShCount    = subMod.sources?.crt_sh?.count     ?? 0;
    const certSpotCount = subMod.sources?.certspotter?.count ?? 0;
    const crtShError    = subMod.sources?.crt_sh?.error     ?? null;
    const certSpotError = subMod.sources?.certspotter?.error ?? null;

    // ── Suspicious signal detection ───────────────────────────────────────
    const suspicious_certificate_signals = [];

    if (!https_available) {
      suspicious_certificate_signals.push({
        signal:      "no_https",
        severity:    "high",
        description: "HTTPS is not available on this domain. Certificate may be missing or misconfigured.",
      });
    }

    if (days_until_expiry !== null && days_until_expiry < 14) {
      suspicious_certificate_signals.push({
        signal:      "certificate_expiring_critical",
        severity:    "critical",
        description: `Certificate expires in ${days_until_expiry} day${days_until_expiry === 1 ? "" : "s"} (${expires_at}). Immediate renewal required to avoid service outage.`,
      });
    } else if (days_until_expiry !== null && days_until_expiry < 30) {
      suspicious_certificate_signals.push({
        signal:      "certificate_expiring_soon",
        severity:    "medium",
        description: `Certificate expires in ${days_until_expiry} day${days_until_expiry === 1 ? "" : "s"} (${expires_at}). Renewal recommended within the next week.`,
      });
    }

    if (subMod.wildcard_dns) {
      suspicious_certificate_signals.push({
        signal:      "wildcard_dns_detected",
        severity:    "info",
        description: "Wildcard DNS behavior was observed. This does not confirm that a wildcard certificate is in use or that generated hostnames are customer assets.",
      });
    }

    if (certificate_ownership.status === "shared_certificate") {
      suspicious_certificate_signals.push({
        signal:      "shared_certificate_observed",
        severity:    "info",
        description: "The observed certificate contains names outside the customer domain. It is treated as shared or provider-managed evidence and does not establish asset ownership by itself.",
      });
    }

    if (allSensitive.length > 0) {
      suspicious_certificate_signals.push({
        signal:      "sensitive_hosts_in_ct",
        severity:    "info",
        description: `${allSensitive.length} hostname${allSensitive.length > 1 ? "s" : ""} with sensitive-looking labels were observed in Certificate Transparency data: ${allSensitive.slice(0, 10).join(", ")}${allSensitive.length > 10 ? ` (+${allSensitive.length - 10} more)` : ""}. Reachability and exposure are not confirmed by this evidence alone.`,
        hostnames:   allSensitive,
      });
    }

    if (total_certificates_seen > 50) {
      suspicious_certificate_signals.push({
        signal:      "high_subdomain_growth",
        severity:    "info",
        description: `${total_certificates_seen} unique hostnames were observed in Certificate Transparency data. This is an inventory observation and does not indicate exposure by itself.`,
      });
    }

    // CT discrepancy: one source returning 2× or more than the other
    if (crtShCount > 0 && certSpotCount > 0) {
      const ratio = Math.max(crtShCount, certSpotCount) / Math.min(crtShCount, certSpotCount);
      if (ratio >= 2) {
        suspicious_certificate_signals.push({
          signal:      "ct_source_discrepancy",
          severity:    "info",
          description: `CT sources returned different hostname counts — crt.sh: ${crtShCount}, CertSpotter: ${certSpotCount}. Some hostnames may only appear in one log.`,
        });
      }
    } else if (crtShError && certSpotError) {
      suspicious_certificate_signals.push({
        signal:      "ct_sources_unavailable",
        severity:    "info",
        description: "Both Certificate Transparency sources were unavailable during this scan. CT hostname inventory may be incomplete.",
      });
    }

    // ── Certificate risk level ────────────────────────────────────────────
    let certificate_risk_level = "low";
    const hasCritical = suspicious_certificate_signals.some((s) => s.severity === "critical");
    const hasHigh     = suspicious_certificate_signals.some((s) => s.severity === "high");
    const hasMedium   = suspicious_certificate_signals.some((s) => s.severity === "medium");
    // Did we actually retrieve certificate details? Absence of data must read as
    // "unknown", never "low" — a security product must not imply health it has
    // not verified. (In the real flow issuer/not_after/expiry_days are set
    // together, so any one being present means we have data.)
    const hasCertificateDetail = ssl.cert_issuer != null
      || ssl.cert_not_after != null || ssl.cert_expiry_days != null;

    if (hasCritical || !https_available) certificate_risk_level = "critical";
    else if (hasHigh)                    certificate_risk_level = "high";
    else if (hasMedium)                  certificate_risk_level = "medium";
    else if (!hasCertificateDetail)      certificate_risk_level = "unknown";

	    // ── Newly observed hosts (all CT hosts are "newly observed" relative to
	    //    baseline — true delta tracking requires historical DB rows which are
	    //    captured in asset_events via upsertAssetInventory) ─────────────────
	    const newly_observed_hosts = allSensitive;   // surface the sensitive subset
	    const issuer = ssl.cert_issuer ?? null;
	    const subject = ssl.cert_subject ?? domain;
	    const issuer_normalized = normalizeCertificateIssuer(issuer);
	    const ca_owner = mapCertificateAuthorityOwner(issuer_normalized);
	    const crypto_metadata = extractCertificateCryptoMetadata(ssl);
	    const self_signed = detectSelfSignedCertificate(issuer, subject);
	    const lifecycle = buildCertificateLifecycleIntelligence({
	      days_until_expiry,
	      expires_at,
	    });
	    const ca_concentration = buildCaConcentrationAnalytics(issuer ? [issuer] : []);

	    return {
	      total_certificates_seen,
	      certificate_status:    https_available ? "valid" : "unavailable",
	      issuer,
	      issuer_normalized,
	      ca_owner,
	      subject,
	      san_count:             ssl.cert_san_count ?? 0,
	      raw_san_count:         ssl.cert_raw_san_count ?? ssl.cert_san_count ?? 0,
	      wildcard_san_count:    ssl.cert_wildcard_san_count ?? 0,
	      shared_san_count:      ssl.cert_shared_san_count ?? 0,
	      san_hostnames:         ssl.cert_san_names ?? [],
	      ownership:             certificate_ownership,
	      reuse_status:          "not_assessed",
	      evidence_source:       "certificate_transparency",
	      live_certificate_verified: false,
	      issued_at:             ssl.cert_not_before ?? null,
	      certificate_age_days:  ssl.cert_age_days ?? null,
	      expires_at,
	      days_until_expiry,
	      lifecycle,
	      key_algorithm:         crypto_metadata.key_algorithm,
	      key_size_bits:         crypto_metadata.key_size_bits,
	      signature_algorithm:   crypto_metadata.signature_algorithm,
	      crypto_metadata,
	      self_signed,
	      ca_concentration,
	      issued_for_sensitive_hosts: allSensitive,
	      newly_observed_hosts,
	      ct_sources:            { crt_sh: crtShCount, certspotter: certSpotCount },
	      wildcard_dns:          subMod.wildcard_dns ?? false,
      wildcard_warning:      subMod.wildcard_warning ?? null,
      suspicious_certificate_signals,
      certificate_risk_level,
      source:                "ssl_ct_correlation",
      error:                 null,
    };
  } catch (err) {
    return {
	      total_certificates_seen:    0,
	      certificate_status:         "unknown",
	      issuer:                     null,
	      issuer_normalized:          normalizeCertificateIssuer(null),
	      ca_owner:                   mapCertificateAuthorityOwner(null),
	      subject:                    domain,
	      san_count:                  0,
	      raw_san_count:              0,
	      wildcard_san_count:         0,
	      shared_san_count:           0,
	      san_hostnames:              [],
	      ownership:                  buildCertificateOwnershipAssessment({}, domain),
	      reuse_status:               "not_assessed",
	      evidence_source:            "certificate_transparency",
	      live_certificate_verified:  false,
	      issued_at:                  null,
	      certificate_age_days:       null,
	      expires_at:                 null,
	      days_until_expiry:          null,
	      lifecycle:                  buildCertificateLifecycleIntelligence({}),
	      key_algorithm:              "unknown",
	      key_size_bits:              "unknown",
	      signature_algorithm:        "unknown",
	      crypto_metadata:            {
	        key_algorithm: "unknown",
	        key_size_bits: "unknown",
	        signature_algorithm: "unknown",
	      },
	      self_signed:                "unknown",
	      ca_concentration:           buildCaConcentrationAnalytics([]),
	      issued_for_sensitive_hosts: [],
      newly_observed_hosts:       [],
      ct_sources:                 { crt_sh: 0, certspotter: 0 },
      wildcard_dns:               false,
      wildcard_warning:           null,
      suspicious_certificate_signals: [],
      certificate_risk_level:     "unknown",
      source:                     "ssl_ct_correlation",
      error:                      err?.message ?? "Certificate intelligence failed",
    };
  }
}
