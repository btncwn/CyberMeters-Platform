import { liveCertificateFindings } from './network-probe.js';
// ── Certificate intelligence module ──
// Sensitive-host classification, certificate ownership assessment, and the certificate
// intelligence scan roll-up (expiry, CA concentration, self-signed, lifecycle). Extracted
// verbatim from index.js (monolith decomposition, Phase 1c). CERT_SENSITIVE_LABELS is
// module-internal.
import {
  buildCaConcentrationAnalytics,
  buildCertificateLifecycleIntelligence,
  detectSelfSignedCertificate,
  mapCertificateAuthorityOwner,
  normalizeCertificateIssuer,
} from "./cert-analysis.js";
import { deriveCertificateSignalCompletenessFromModules } from "./certificate-signal-completeness.js";
import { normalizeCertificateSanNames, normalizeDiscoveredHostname, normalizeHostname } from "./hostnames.js";
import { resolveTlsRuntimeState, TLS_RUNTIME_STATES } from "./tls-evidence.js";

// ── Certificate Intelligence ─────────────────────────────────────────────────
// A certificate-level view built from the certificate the live site actually
// served, captured by the live TLS collector and attached to modules.ssl.
// Zero new network calls. When no live certificate was captured, the
// certificate is unknown — never inferred from any other source.
//
// Suspicious signals emitted:
//   certificate_expired / certificate_expiring_critical / certificate_expiring_soon
//   certificate_hostname_mismatch / certificate_untrusted   (live TLS findings)
//   wildcard_dns_detected        (informational DNS behavior observation)
//   shared_certificate_observed  (names outside the customer domain on the leaf)
//   no_https                     (HTTPS positively unavailable)

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

// The live TLS leaf, when the collector captured it completely.
function liveLeaf(ssl) {
  const live = ssl?.live_certificate;
  return live && live.collection_complete === true ? live : null;
}

// "CN=example.com\nO=…" → "example.com".
function subjectCommonName(subject) {
  const match = String(subject || "").match(/(?:^|[\n,/]\s*)CN=([^\n,/]+)/);
  return match ? match[1].trim() : "";
}

// Whether a shared-SAN count is a measurement. A live leaf always measures it
// from its own SAN list. A stored record from an earlier scan measured it only
// when a source answered with a SAN-bearing result and recorded a non-negative
// integer count (sentinel precedence: an error or missing measurement dominates
// any compatibility number, so an eager zero still fails closed).
export function sharedSanMeasured(ssl) {
  if (liveLeaf(ssl)) return true;
  const rawSharedSanCount = ssl?.cert_shared_san_count;
  if (!Number.isInteger(rawSharedSanCount) || rawSharedSanCount < 0) return false;
  const sources = ssl?.ct_sources;
  if (!sources || typeof sources !== "object") return false;
  return Object.values(sources).some((source) => Boolean(
    source && source.error == null && Number.isInteger(source.count) && source.count > 0,
  ));
}

// The certificate facts ownership is assessed from: the live leaf, or the SAN
// fields a stored record from an earlier scan carries.
function ownershipFacts(ssl, root) {
  const live = liveLeaf(ssl);
  if (live) {
    const rawSans = (Array.isArray(live.dns_names) ? live.dns_names : [])
      .map((name) => String(name || "").trim().toLowerCase().replace(/\.$/, ""))
      .filter(Boolean);
    return {
      subject: subjectCommonName(live.subject),
      customerSans: normalizeCertificateSanNames(rawSans.join(" "), root),
      sharedSanCount: rawSans.filter((name) =>
        !normalizeDiscoveredHostname(name.replace(/^\*\./, ""), root)).length,
      wildcardSanCount: rawSans.filter((name) => name.includes("*")).length,
    };
  }
  return {
    subject: ssl?.cert_subject,
    customerSans: Array.isArray(ssl?.cert_san_names) ? ssl.cert_san_names : [],
    sharedSanCount: ssl?.cert_shared_san_count,
    wildcardSanCount: Number(ssl?.cert_wildcard_san_count || 0),
  };
}

export function buildCertificateOwnershipAssessment(ssl, domain) {
  const root = normalizeHostname(domain);
  const facts = ownershipFacts(ssl, root);
  const subject = String(facts.subject || "").toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
  const customerSans = facts.customerSans;
  const measured = sharedSanMeasured(ssl);
  const sharedSanCount = measured ? facts.sharedSanCount : null;
  const wildcardSanCount = facts.wildcardSanCount;
  // Only an observed certificate subject is evidence; ownership otherwise rests
  // on the certificate's own DNS names.
  const subjectMatches = Boolean(root && subject && (subject === root || subject.endsWith(`.${root}`)));

  if (!measured) {
    return {
      status: "unknown",
      assessment_state: "not_assessed",
      assessment_reason: "shared_san_not_measured",
      confidence: null,
      customer_owned: null,
      shared_san_count: null,
      wildcard_san_count: wildcardSanCount,
      evidence_signals: [],
      customer_message:
        "Certificate ownership was not assessed because shared certificate hostnames were not measured.",
    };
  }

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
      shared_san_count: sharedSanCount,
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
 * Returns the certificate the live site served (issuer, subject, SANs, expiry,
 * live findings) and the signal-completeness model. With no live certificate
 * captured, the certificate is unknown and the module is incomplete.
 */
function attachSignalCompleteness(result, modules, opts) {
  return {
    ...result,
    signal_completeness: deriveCertificateSignalCompletenessFromModules({
      modules: { ...modules, certificate_intelligence: result },
      observedAt:
        opts.observedAt ??
        modules?.ssl?.certificate_evidence?.observed_at ??
        modules?.ssl?.tls_positive_absence_evidence?.observed_at ??
        null,
      engineVersion: opts.engineVersion ?? null,
    }),
  };
}

export function runCertificateIntelligenceModule(modules, domain, opts = {}) {
  try {
    const ssl      = modules?.ssl       || {};
    const subMod   = modules?.subdomains || {};

    // ── Live certificate ──────────────────────────────────────────────────
    const live = ssl.network_probe?.profile === 'live_tls' && ssl.live_certificate?.collection_complete === true ? ssl.live_certificate : null;
    const liveIncomplete = ssl.certificate_evidence?.schema_version === 'external-certificate-observation-v4' && ssl.certificate_evidence.live_tls?.all_planned_endpoints_observed !== true;
    const liveObservedMs = Date.parse(ssl.network_probe?.finished_at);
    const days_until_expiry = live ? Math.floor((Date.parse(live.not_after)-liveObservedMs)/86_400_000) : null;
    const expires_at = live?.not_after ?? null;
    const tls = resolveTlsRuntimeState(ssl);
    const https_available = tls.state === TLS_RUNTIME_STATES.OBSERVED_PRESENT
      ? true
      : tls.state === TLS_RUNTIME_STATES.POSITIVELY_ABSENT
        ? false
        : null;
    const certificate_ownership = tls.state === TLS_RUNTIME_STATES.UNAVAILABLE
      ? buildCertificateOwnershipAssessment({}, domain)
      : buildCertificateOwnershipAssessment(ssl, domain);
    // HTTPS is served (or could not be ruled out) but no certificate was
    // captured: the certificate is unknown, so this module cannot support a
    // healthy Certificates conclusion and must defer it.
    const certificateNotObserved = !live && https_available !== false;

    // ── Suspicious signal detection ───────────────────────────────────────
    const suspicious_certificate_signals = [];

    if (https_available === false) {
      suspicious_certificate_signals.push({
        signal:      "no_https",
        severity:    "high",
        description: "HTTPS is not available on this domain. Certificate may be missing or misconfigured.",
      });
    }

    suspicious_certificate_signals.push(...liveCertificateFindings(ssl, domain));

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

    // ── Certificate risk level ────────────────────────────────────────────
    let certificate_risk_level = "low";
    const hasCritical = suspicious_certificate_signals.some((s) => s.severity === "critical");
    const hasHigh     = suspicious_certificate_signals.some((s) => s.severity === "high");
    const hasMedium   = suspicious_certificate_signals.some((s) => s.severity === "medium");
    // Absence of certificate data reads as "unknown", never "low" — a security
    // product must not imply health it has not verified.
    if (hasCritical || https_available === false) certificate_risk_level = "critical";
    else if (hasHigh)                    certificate_risk_level = "high";
    else if (hasMedium)                  certificate_risk_level = "medium";
    else if (!live || liveIncomplete)    certificate_risk_level = "unknown";

    const issuer = live?.issuer ?? null;
    const subject = live?.subject ?? domain;
    const issuer_normalized = normalizeCertificateIssuer(issuer);
    const ca_owner = mapCertificateAuthorityOwner(issuer_normalized);
    const crypto_metadata = live
      ? {key_algorithm:live.public_key_algorithm || 'unknown',key_size_bits:live.public_key_size_bits ?? 'unknown',signature_algorithm:live.signature_algorithm || 'unknown',source:'live_tls'}
      : {key_algorithm:'unknown',key_size_bits:'unknown',signature_algorithm:'unknown'};
    const self_signed = live ? detectSelfSignedCertificate(issuer, subject) : "unknown";
    const lifecycle = buildCertificateLifecycleIntelligence({
      days_until_expiry,
      expires_at,
    });
    const ca_concentration = buildCaConcentrationAnalytics(issuer ? [issuer] : []);
    const liveSans = live && Array.isArray(live.dns_names) ? live.dns_names : [];

    return attachSignalCompleteness({
      tls_state: tls.state,
      certificate_status:
        live ? (live.hostname_match === "matched" && live.trust_validation === "valid" ? (liveIncomplete ? "unknown" : "valid") : "invalid")
          : https_available === false ? "unavailable" : "unknown",
      issuer,
      issuer_normalized,
      ca_owner,
      subject,
      san_count:             liveSans.length,
      raw_san_count:         liveSans.length,
      wildcard_san_count:    liveSans.filter((name) => String(name).startsWith("*.")).length,
      shared_san_count:      certificate_ownership.shared_san_count,
      san_hostnames:         liveSans,
      ownership:             certificate_ownership,
      reuse_status:          "not_assessed",
      evidence_source:       live ? "live_tls" : "not_observed",
      live_certificate_verified: !!live,
      live_tls: ssl.certificate_evidence?.live_tls ?? null,
      expiry_evidence:       live ? "usable" : "not_usable",
      issued_at:             live?.not_before ?? null,
      certificate_age_days:  live ? Math.floor((liveObservedMs-Date.parse(live.not_before))/86_400_000) : null,
      expires_at,
      days_until_expiry,
      lifecycle,
      key_algorithm:         crypto_metadata.key_algorithm,
      key_size_bits:         crypto_metadata.key_size_bits,
      signature_algorithm:   crypto_metadata.signature_algorithm,
      crypto_metadata,
      self_signed,
      ca_concentration,
      wildcard_dns:          subMod.wildcard_dns ?? false,
      wildcard_warning:      subMod.wildcard_warning ?? null,
      suspicious_certificate_signals,
      certificate_risk_level,
      source:                "live_tls",
      ...(certificateNotObserved ? { incomplete: true, incomplete_reason: "certificate_not_observed" } : {}),
      ...(liveIncomplete ? { incomplete: true, incomplete_reason: "live_tls_not_fully_observed" } : {}),
      error:                 null,
    }, modules, opts);
  } catch (err) {
    return attachSignalCompleteness({
      tls_state:                   TLS_RUNTIME_STATES.UNAVAILABLE,
      certificate_status:         "unknown",
      issuer:                     null,
      issuer_normalized:          normalizeCertificateIssuer(null),
      ca_owner:                   mapCertificateAuthorityOwner(null),
      subject:                    domain,
      san_count:                  0,
      raw_san_count:              0,
      wildcard_san_count:         0,
      shared_san_count:           null,
      san_hostnames:              [],
      ownership:                  buildCertificateOwnershipAssessment({}, domain),
      reuse_status:               "not_assessed",
      evidence_source:            "not_observed",
      live_certificate_verified:  false,
      expiry_evidence:            "not_usable",
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
      wildcard_dns:               false,
      wildcard_warning:           null,
      suspicious_certificate_signals: [],
      certificate_risk_level:     "unknown",
      source:                     "live_tls",
      error:                      err?.message ?? "Certificate intelligence failed",
    }, modules, opts);
  }
}
