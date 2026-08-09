// ── Domain-security-enrichment findings (canonical conditions) ────────────────
// The ONE source of truth for what each dse_* finding means. Pure: no I/O, no state.
//
// Two consumers must agree exactly, or the platform lies:
//   • scan-engine.js raises these findings during a scan (buildDseFindings).
//   • managed-verification.js decides whether a managed case's exposure is STILL
//     present when a customer asks CyberMeters to verify their fix (DSE_PRESENCE).
// A verifier that re-implemented these conditions could drift from the detector and
// resolve a case whose issue is still live, so both read the same predicates here.
// Extracted verbatim from scan-engine.js — the emitted findings are byte-identical.
//
// Every predicate takes the `domain_security_enrichment` module output (itself pure —
// see runDomainSecurityEnrichmentModule) and answers one question: does this exact
// finding's condition hold right now?

import {
  cookieEvidenceUsable,
  cookieFindingPresent,
} from "./cookie-observation.js";

export const HSTS_MIN_MAX_AGE = 31_536_000; // 365 days — the preload-list minimum.

// ── Presence predicates ──────────────────────────────────────────────────────
// Keyed by finding id. Each returns true iff the condition still holds. A predicate
// returns false when its own evidence is missing/errored — callers must treat
// "evidence unavailable" as inconclusive rather than as remediation (see
// dsePresenceEvidenceUsable below); false here means only "condition not observed".

function caaUsable(enrich) {
  return Boolean(enrich?.caa && !enrich.caa.error);
}
function hstsUsable(enrich) {
  return Boolean(enrich?.hsts && !enrich.hsts.error);
}

// Which sub-signal each finding depends on. Used to decide whether a verification
// observation is conclusive for THIS finding, rather than assuming absence = fixed.
export const DSE_EVIDENCE_SOURCE = Object.freeze({
  dse_missing_caa:               "caa",
  dse_caa_no_issuers:            "caa",
  dse_hsts_short_maxage:         "hsts",
  dse_hsts_not_preload_eligible: "hsts",
  dse_cookie_no_secure:          "cookies",
  dse_cookie_no_httponly:        "cookies",
  dse_cookie_no_samesite:        "cookies",
});

export function dsePresenceEvidenceUsable(findingId, enrich) {
  switch (DSE_EVIDENCE_SOURCE[findingId]) {
    case "caa":     return caaUsable(enrich);
    case "hsts":    return hstsUsable(enrich);
    case "cookies": return cookieEvidenceUsable(enrich);
    default:        return false;
  }
}

// Missing preload requirements, in the scan's original order. Shared by the finding
// copy and the preload-eligibility predicate.
export function hstsPreloadGaps(hsts) {
  const missing = [];
  if (!hsts.include_subdomains) missing.push("includeSubDomains");
  if (!hsts.preload_directive) missing.push("preload directive");
  if (hsts.max_age === null || hsts.max_age < HSTS_MIN_MAX_AGE) missing.push("max-age ≥ 31536000");
  return missing;
}

export const DSE_PRESENCE = Object.freeze({
  dse_missing_caa: (enrich) => caaUsable(enrich) && !enrich.caa.present,

  dse_caa_no_issuers: (enrich) =>
    caaUsable(enrich) && enrich.caa.present
    && enrich.caa.issuers.length === 0 && enrich.caa.records.length > 0,

  dse_hsts_short_maxage: (enrich) =>
    hstsUsable(enrich) && enrich.hsts.present
    && enrich.hsts.max_age !== null && enrich.hsts.max_age < HSTS_MIN_MAX_AGE,

  dse_hsts_not_preload_eligible: (enrich) =>
    hstsUsable(enrich) && enrich.hsts.present
    && !enrich.hsts.preload_eligible && hstsPreloadGaps(enrich.hsts).length > 0,

  dse_cookie_no_secure: (enrich) => cookieFindingPresent("dse_cookie_no_secure", enrich),

  dse_cookie_no_httponly: (enrich) => cookieFindingPresent("dse_cookie_no_httponly", enrich),

  dse_cookie_no_samesite: (enrich) => cookieFindingPresent("dse_cookie_no_samesite", enrich),
});

export function isDseFindingType(findingId) {
  return Object.prototype.hasOwnProperty.call(DSE_PRESENCE, String(findingId || ""));
}

// ── Finding construction ─────────────────────────────────────────────────────
// Builds the dse_* findings for a scan. Copy is unchanged from the original inline
// block in scan-engine.js; the conditions are now the shared predicates above.
//
// `affected_hosts` is the domain itself: every dse_* signal is observed on the
// domain's own DNS/HTTP response. Managed cases derive their verification target
// from this — never from the prose description.
export function buildDseFindings(enrich, domain) {
  if (!enrich || enrich.error) return [];
  const findings = [];
  const host = [domain].filter(Boolean);

  if (DSE_PRESENCE.dse_missing_caa(enrich)) {
    findings.push({
      id:             "dse_missing_caa",
      module:         "domain_security_enrichment",
      severity:       "medium",
      score_impact:   0,
      affected_hosts: host,
      title:          "No CAA DNS Record",
      description:    "This domain has no CAA (Certification Authority Authorization) record. Without CAA, any publicly trusted CA can issue TLS certificates for this domain, increasing the risk of mis-issuance.",
      recommendation: `Add a DNS CAA record to restrict which CAs may issue certificates. Example: \`0 issue "letsencrypt.org"\`, \`0 issue "pki.goog"\`. Add \`0 iodef "mailto:security@${domain}"\` to receive mis-issuance reports.`,
    });
  } else if (DSE_PRESENCE.dse_caa_no_issuers(enrich)) {
    findings.push({
      id:             "dse_caa_no_issuers",
      module:         "domain_security_enrichment",
      severity:       "low",
      score_impact:   0,
      affected_hosts: host,
      title:          "CAA Record Present But No Issuers Listed",
      description:    `A CAA record exists but contains no \`issue\` or \`issuewild\` tags, which effectively blocks all certificate issuance for this domain.`,
      recommendation: `Add at least one \`0 issue "<ca>"\` tag to allow your CA to issue certificates.`,
    });
  }

  if (DSE_PRESENCE.dse_hsts_short_maxage(enrich)) {
    const h = enrich.hsts;
    findings.push({
      id:             "dse_hsts_short_maxage",
      module:         "domain_security_enrichment",
      severity:       "low",
      score_impact:   0,
      affected_hosts: host,
      title:          "HSTS max-age Below Recommended Minimum",
      description:    `The HSTS header specifies max-age=${h.max_age} seconds (${Math.round(h.max_age / 86400)} days). The recommended minimum is 31,536,000 (365 days) to qualify for the HSTS preload list and ensure robust protection.`,
      recommendation: "Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    });
  }
  if (DSE_PRESENCE.dse_hsts_not_preload_eligible(enrich)) {
    findings.push({
      id:             "dse_hsts_not_preload_eligible",
      module:         "domain_security_enrichment",
      severity:       "low",
      score_impact:   0,
      affected_hosts: host,
      title:          "HSTS Not Eligible for Preload List",
      description:    `This domain's HSTS configuration is missing the following preload requirements: ${hstsPreloadGaps(enrich.hsts).join(", ")}. Preloaded HSTS protects users on their very first visit before any HSTS header is seen.`,
      recommendation: "Update to: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload — then submit to https://hstspreload.org",
    });
  }

  if (DSE_PRESENCE.dse_cookie_no_secure(enrich)) {
    const c = enrich.cookies;
    findings.push({
      id:             "dse_cookie_no_secure",
      module:         "domain_security_enrichment",
      severity:       "high",
      score_impact:   0,
      affected_hosts: host,
      title:          `${c.insecure_count} Cookie${c.insecure_count > 1 ? "s" : ""} Missing Secure Flag`,
      description:    `${c.insecure_count} of ${c.found} cookie${c.found > 1 ? "s" : ""} set by ${domain} lack the Secure flag. These cookies may be transmitted over unencrypted HTTP connections, exposing session tokens to network interception.`,
      recommendation: "Add the Secure attribute to all session and authentication cookies: Set-Cookie: name=value; Secure; HttpOnly; SameSite=Strict",
    });
  }
  if (DSE_PRESENCE.dse_cookie_no_httponly(enrich)) {
    const c = enrich.cookies;
    findings.push({
      id:             "dse_cookie_no_httponly",
      module:         "domain_security_enrichment",
      severity:       "medium",
      score_impact:   0,
      affected_hosts: host,
      title:          `${c.no_httponly} Cookie${c.no_httponly > 1 ? "s" : ""} Missing HttpOnly Flag`,
      description:    `${c.no_httponly} cookie${c.no_httponly > 1 ? "s are" : " is"} accessible via JavaScript. If an XSS vulnerability exists, these cookies can be exfiltrated by injected scripts.`,
      recommendation: "Add HttpOnly to all cookies that do not need to be accessed by JavaScript (session tokens, auth cookies).",
    });
  }
  if (DSE_PRESENCE.dse_cookie_no_samesite(enrich)) {
    const c = enrich.cookies;
    findings.push({
      id:             "dse_cookie_no_samesite",
      module:         "domain_security_enrichment",
      severity:       "low",
      score_impact:   0,
      affected_hosts: host,
      title:          `${c.no_samesite} Cookie${c.no_samesite > 1 ? "s" : ""} Missing SameSite Attribute`,
      description:    `${c.no_samesite} cookie${c.no_samesite > 1 ? "s do" : " does"} not specify a SameSite attribute. Without SameSite, browsers may send these cookies in cross-site requests, enabling CSRF attacks.`,
      recommendation: "Set SameSite=Strict or SameSite=Lax on all cookies. Use SameSite=None; Secure only for cookies that must be sent in cross-site contexts.",
    });
  }

  return findings;
}
