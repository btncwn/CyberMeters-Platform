// ── Canonical eight-domain Cyber MOT coverage-state resolver ──────────────────
// ONE source of truth for "what state is each of the eight customer-facing Cyber MOT
// domains in?" — consumed by the Main Dashboard, Scan Detail, Executive Report UI and
// the Executive PDF so every domain is ALWAYS visible with one explicit honest state
// and missing evidence can NEVER render as healthy.
//
// This is compute-on-read from the canonical R2 scan report (modules + findings +
// scan_quality). No new storage, no migration. It does NOT re-score, re-scan, or
// re-implement scan-quality — it consumes the existing canonical semantics
// (complete=authoritative, partial/degraded=provisional, unknown=legacy).
//
// Honest scope is preserved per domain — Identity Exposure covers spoofing /
// impersonation / exposed authentication surfaces (NOT breach/credential/dark-web),
// and Shadow IT is externally-observed unmanaged-technology monitoring only (it can
// say "observed / unknown", never "unauthorised", because no approved inventory
// exists yet — a separate later episode).

// Fixed canonical enum — the resolver contract layer. UI maps these to friendly
// labels; the source state stays stable.
export const CYBER_MOT_STATES = Object.freeze({
  ASSESSED_HEALTHY:        "assessed_healthy",
  ISSUE_DETECTED:          "issue_detected",
  PROVISIONAL:             "provisional",
  DEGRADED:                "degraded",
  UNAVAILABLE:             "unavailable",
  NOT_CONFIGURED:          "not_configured",
  CUSTOMER_INPUT_REQUIRED: "customer_input_required",
  MONITORING_ONLY:         "monitoring_only",
  NOT_YET_ASSESSED:        "not_yet_assessed",
  EVIDENCE_INSUFFICIENT:   "evidence_insufficient",
});

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const materialSeverity = (s) => (SEV_RANK[String(s || "").toLowerCase()] ?? 0) >= 2; // medium+

// Fixed domain order + honest metadata. `modules` = report.modules keys that
// materially assess this domain. `match(finding)` attributes an authoritative
// finding to exactly one primary domain.
export const CYBER_MOT_DOMAINS = Object.freeze([
  {
    domain_key: "email_protection",
    display_name: "Email Protection",
    description: "SPF, DKIM, DMARC, MX and transport-security posture, plus who is sending email as you.",
    modules: ["email_security", "email_security_intelligence"],
    match: (f) => /^(email_|dmarc_|spf_|dkim_|mta_|bimi_|tlsrpt_)/.test(f.id || "") || f.module === "email_security",
    maturity: "M5", managed_status: "verification_monitoring",
    limitations: ["DKIM is checked against common selectors only; a non-match is informational, not proof DKIM is absent."],
  },
  {
    domain_key: "brand_protection",
    display_name: "Brand Protection",
    description: "Lookalike and typosquat domains that could impersonate your brand.",
    modules: ["brand_monitoring"],
    match: (f) => /^brand_/.test(f.id || "") || f.module === "brand_monitoring",
    maturity: "M3", managed_status: "managed_case",
    limitations: ["Unregistered permutations are watchlist-only, not active abuse. CyberMeters prepares and tracks takedowns; it does not perform them."],
  },
  {
    domain_key: "attack_surface",
    display_name: "Attack Surface",
    description: "Internet-facing subdomains, exposed admin surfaces, takeover risk and cloud exposure.",
    modules: ["subdomains", "admin_surface_detection", "cloud_storage_discovery", "dns"],
    match: (f) => /^(asset_|subdomain_|admin_|takeover_|exposure_|dse_|cve_|kev_|cloud_|dns_)/.test(f.id || ""),
    maturity: "M3", managed_status: "managed_case",
    limitations: ["External observation only — no internal-network discovery. Subdomain coverage depends on public Certificate Transparency logs."],
  },
  {
    domain_key: "certificates_trust",
    display_name: "Certificates & Trust",
    description: "Certificate expiry, issuer, hostname coverage and anomalies from Certificate Transparency logs.",
    modules: ["certificate_intelligence"],
    match: (f) => /^(cert_|certificate_)/.test(f.id || "") || f.module === "certificate_intelligence",
    maturity: "M2", managed_status: "recommendations",
    limitations: ["Analysis is based on Certificate Transparency logs. Chain validity, root trust, OCSP and revocation status are not checked and remain unknown."],
  },
  {
    domain_key: "cyber_essentials_readiness",
    display_name: "Cyber Essentials Readiness",
    description: "An indicative estimate of your likely Cyber Essentials readiness — not a certification.",
    modules: [], // derived from external signals + the questionnaire, not a scan module
    match: () => false,
    maturity: "M2", managed_status: "recommendations",
    limitations: ["Indicative readiness estimate, not certification. CyberMeters does not certify Cyber Essentials."],
  },
  {
    domain_key: "website_security",
    display_name: "Website Security",
    description: "Passive external website health — HTTPS, redirects, security headers and DNS availability.",
    modules: ["headers", "ssl", "dns"],
    match: (f) => /^(header_|https_|redirect_|canonical_|ssl_|tech_)/.test(f.id || ""),
    maturity: "M2", managed_status: "recommendations",
    limitations: ["Passive external check only — no active, authenticated or intrusive testing."],
  },
  {
    domain_key: "identity_exposure",
    display_name: "Identity Exposure",
    description: "Externally observable spoofing, impersonation and exposed authentication-surface risks.",
    modules: ["identity_discovery"],
    match: (f) => /^identity_/.test(f.id || "") || f.module === "identity_discovery",
    maturity: "M1", managed_status: "monitoring",
    limitations: ["Covers spoofing, impersonation and exposed login/identity-provider surfaces. It does not include leaked-credential, breached-password or dark-web monitoring."],
  },
  {
    domain_key: "shadow_it_unmanaged_technology",
    display_name: "Shadow IT & Unmanaged Technology",
    description: "Externally visible SaaS, cloud services, email senders and internet-facing technologies that may sit outside the known technology inventory.",
    modules: ["saas_exposure", "third_party_discovery", "technology_detection", "cloud_storage_discovery", "vendor_relationships"],
    match: () => false, // observation-only; not attributed authoritative findings this episode
    maturity: "M0", managed_status: "monitoring",
    limitations: ["Externally observed technology only. Approved-inventory comparison is not yet configured, so items are shown as observed, not authorised or unauthorised. No internal-network, endpoint, CASB or EDR visibility."],
  },
]);

// A module "materially assessed" its domain iff it is present, has no error, and was
// not skipped/incomplete for this scan.
function moduleAssessed(report, name, skippedSet) {
  const m = report?.modules?.[name];
  if (m == null) return false;
  if (m.error) return false;
  if (m.skipped === true || m.incomplete === true) return false;
  if (skippedSet.has(name)) return false;
  return true;
}
function moduleAttempted(report, name, skippedSet) {
  // Attempted-but-insufficient: present but errored/skipped/incomplete.
  const m = report?.modules?.[name];
  if (m == null) return skippedSet.has(name);
  return !!(m.error || m.skipped === true || m.incomplete === true || skippedSet.has(name));
}

/**
 * resolveCyberMotDomainStates — the canonical eight-domain resolver.
 * @param {object} report  the R2 scan report (modules + findings + scan_quality). May be null.
 * @param {object} [opts.cyberEssentials]  optional CE readiness output ({grade,status,top_gaps,limitations}).
 * @param {string} [opts.scanId]
 * @returns {Array} exactly 8 entries in fixed order.
 */
export function resolveCyberMotDomainStates(report, opts = {}) {
  const { cyberEssentials = null, scanId = null } = opts;
  const quality = report?.scan_quality?.status ?? (report ? "unknown" : null); // null = no scan at all
  const skippedSet = new Set(report?.scan_quality?.modules_skipped || []);
  const findings = Array.isArray(report?.findings) ? report.findings : [];
  const lastAssessedAt = report?.completed_at || report?.created_at || null;
  const sourceScanId = scanId || report?.scan_id || null;
  // Anything that is not an authoritative "complete" scan is provisional — this
  // includes legacy "unknown" coverage, which must never render as healthy.
  const provisional = quality != null && quality !== "complete";

  return CYBER_MOT_DOMAINS.map((d) => {
    const base = {
      domain_key: d.domain_key,
      display_name: d.display_name,
      summary: "",
      description: d.description,
      state: CYBER_MOT_STATES.NOT_YET_ASSESSED,
      coverage: quality,                 // domain-relevant quality (refined below)
      maturity: d.maturity,
      managed_status: d.managed_status,
      evidence_count: 0,
      finding_count: 0,
      highest_severity: null,
      recommendation_count: 0,
      confidence: null,                  // never fabricated
      freshness: lastAssessedAt,
      last_assessed_at: lastAssessedAt,
      limitations: [...d.limitations],
      source_scan_id: sourceScanId,
    };

    // No scan at all → honest not-yet-assessed for every domain.
    if (!report) {
      base.coverage = null;
      base.summary = "Not yet assessed — run a scan to establish this domain.";
      return base;
    }

    // ── Cyber Essentials (5) — always needs customer input; separate surface ──
    if (d.domain_key === "cyber_essentials_readiness") {
      if (cyberEssentials && cyberEssentials.status) {
        const ready = cyberEssentials.status === "likely_ready";
        base.finding_count = (cyberEssentials.top_gaps || []).length;
        base.recommendation_count = base.finding_count;
        base.state = ready ? CYBER_MOT_STATES.ASSESSED_HEALTHY : CYBER_MOT_STATES.ISSUE_DETECTED;
        base.coverage = provisional ? quality : "complete";
        base.summary = ready
          ? "Indicative readiness looks on track (estimate, not certification)."
          : `Indicative readiness gaps identified (${base.finding_count}).`;
      } else {
        base.state = CYBER_MOT_STATES.CUSTOMER_INPUT_REQUIRED;
        base.summary = "Complete the Cyber Essentials questionnaire to assess readiness.";
      }
      return base;
    }

    // ── Shadow IT (8) — externally-observed monitoring only, no inventory yet ──
    if (d.domain_key === "shadow_it_unmanaged_technology") {
      const observed = d.modules.reduce((n, name) => {
        const m = report.modules?.[name];
        if (!m || m.error) return n;
        const c = m.count ?? m.total ?? (Array.isArray(m.items) ? m.items.length : (Array.isArray(m.assets) ? m.assets.length : 0));
        return n + (Number.isFinite(c) ? c : 0);
      }, 0);
      base.evidence_count = observed;
      base.state = CYBER_MOT_STATES.MONITORING_ONLY;
      base.coverage = provisional ? quality : "complete";
      base.summary = observed > 0
        ? `${observed} externally observed technologies/services (approved-inventory comparison not yet configured).`
        : "Externally observed technology monitoring active (approved-inventory comparison not yet configured).";
      return base;
    }

    // ── Scan-evidenced domains (1,2,3,4,6,7) ──────────────────────────────────
    const relevant = d.modules;
    const assessed = relevant.filter((n) => moduleAssessed(report, n, skippedSet));
    const attemptedInsufficient = relevant.filter((n) => moduleAttempted(report, n, skippedSet));
    const domainFindings = findings.filter((f) => materialSeverity(f.severity) && d.match(f));
    base.finding_count = domainFindings.length;
    base.evidence_count = assessed.length;
    if (domainFindings.length) {
      base.highest_severity = domainFindings
        .map((f) => String(f.severity || "").toLowerCase())
        .sort((a, b) => (SEV_RANK[b] ?? 0) - (SEV_RANK[a] ?? 0))[0];
      base.recommendation_count = domainFindings.filter((f) => f.recommendation).length;
    }

    // Domain-relevant coverage: if a required module was attempted-but-insufficient
    // it lowers THIS domain's coverage even when the overall scan is complete
    // (honest for the CT/subdomain hole in Attack Surface).
    const domainDegraded = attemptedInsufficient.length > 0 && assessed.length === 0;
    const domainPartial = attemptedInsufficient.length > 0 && assessed.length > 0;

    // ── Precedence (findings are never hidden; coverage carries the caveat) ──
    if (domainFindings.length > 0) {
      // A real finding always surfaces as issue_detected; coverage metadata tells the
      // UI whether the evidence is provisional.
      base.state = CYBER_MOT_STATES.ISSUE_DETECTED;
      base.coverage = domainPartial || provisional ? "partial" : (quality || "complete");
      base.summary = `${domainFindings.length} issue${domainFindings.length === 1 ? "" : "s"} detected${(domainPartial || provisional) ? " (provisional evidence)" : ""}.`;
      return base;
    }
    if (relevant.length === 0) {
      base.state = CYBER_MOT_STATES.NOT_YET_ASSESSED;
      base.summary = "Not yet assessed.";
      return base;
    }
    if (domainDegraded) {
      // Every required module errored/was skipped → evidence attempted but insufficient.
      base.state = CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT;
      base.coverage = "degraded";
      base.summary = "Evidence could not be collected this scan — not enough to assess.";
      return base;
    }
    if (assessed.length === 0) {
      // Modules simply absent (never ran) → not assessed, never healthy.
      base.state = CYBER_MOT_STATES.NOT_YET_ASSESSED;
      base.summary = "Not yet assessed for this domain.";
      return base;
    }
    if (provisional || domainPartial) {
      // Assessed, no material finding, but the scan/domain evidence is provisional →
      // do NOT assert healthy off incomplete evidence.
      base.state = CYBER_MOT_STATES.PROVISIONAL;
      base.coverage = domainPartial ? "partial" : quality;
      base.summary = "No material issue observed, but coverage this scan was provisional.";
      return base;
    }
    // Assessed on complete evidence with no material finding → genuinely healthy.
    base.state = CYBER_MOT_STATES.ASSESSED_HEALTHY;
    base.coverage = "complete";
    base.summary = "Assessed — no material issue observed.";
    return base;
  });
}
