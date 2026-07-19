import { DMARC_MOT_CONTRIBUTION } from "./dmarc-canonical-consumers.js";
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

// ── Resolver version — bump this whenever a state could change for UNCHANGED input ──
// The states below are a pure function of the R2 report, so every consumer that only
// computes on read silently rewrites the past when this file changes: the same
// historical report re-resolves to a different state today than it did yesterday, with
// nothing recording that the ruler moved and not the thing being measured.
//
// That is tolerable while every consumer is "what is true right now" (Dashboard, Scan
// Detail, Executive Report, PDF). It is NOT tolerable for a trend, which subtracts two
// states and calls the difference the customer's doing. MSP Portfolio persists each
// resolved state with this version stamp and REFUSES to compare across a version
// boundary — a resolver change reads as `insufficient_history`, never as deterioration
// the customer caused.
//
// Bump on any change to: CYBER_MOT_STATES, a domain's `modules` or `required` list, a
// `match()` regex, the severity gate, or the precedence ladder in the resolver. Do NOT
// bump for display copy (`description`, `summary` prose, `limitations`) — those do not
// change which state is resolved.
//
// Precedent: PROVIDER_MAP_VERSION (engines/sender-classification.js), the only other
// algorithm version stamped onto a persisted row.
//
// ── ALSO bump when an INPUT the resolver reads changes what it resolves ──
// `.2` (16 July 2026): the Cyber Essentials domain state is derived from
// `cyberEssentials.status`, which comes from the readiness GRADE, which comes from the
// readiness SCORE. That score's denominator changed from 3 of 5 control areas to 2 of 5 when
// `patch_management_readiness` was reclassified as not externally assessable (readiness
// methodology revision 2). Nothing in THIS file changed — but the state it resolves for a
// workspace can now differ with no change in the customer's security posture, and the trend
// gate below compares resolver_version to decide whether two assessments describe the same
// measurement. Without this bump, the portfolio would tell customers their Cyber Essentials
// posture improved or deteriorated on the day we deployed a definition change.
export const CYBER_MOT_RESOLVER_VERSION = "2026-07-16.2";

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
    required: ["email_security"],
    match: (f) => /^(email_|dmarc_|spf_|dkim_|mta_|bimi_|tlsrpt_)/.test(f.id || "") || f.module === "email_security",
    maturity: "M5", managed_status: "verification_monitoring",
    limitations: ["DKIM is checked against common selectors only; a non-match is informational, not proof DKIM is absent."],
  },
  {
    domain_key: "brand_protection",
    display_name: "Brand Protection",
    description: "Lookalike and typosquat domains that could impersonate your brand.",
    modules: ["brand_monitoring"],
    required: ["brand_monitoring"],
    match: (f) => /^brand_/.test(f.id || "") || f.module === "brand_monitoring",
    maturity: "M3", managed_status: "managed_case",
    limitations: ["Unregistered permutations are watchlist-only, not active abuse. CyberMeters prepares and tracks takedowns; it does not perform them."],
  },
  {
    domain_key: "attack_surface",
    display_name: "Attack Surface",
    description: "Internet-facing subdomains, exposed admin surfaces, takeover risk and cloud exposure.",
    modules: ["subdomains", "admin_surface_detection", "cloud_storage_discovery", "dns"],
    required: ["subdomains", "dns"],
    match: (f) => /^(asset_|subdomain_|admin_|takeover_|exposure_|dse_|cve_|kev_|cloud_|dns_)/.test(f.id || ""),
    maturity: "M3", managed_status: "managed_case",
    limitations: ["External observation only; no internal-network discovery. Subdomain coverage depends on public Certificate Transparency logs."],
  },
  {
    domain_key: "certificates_trust",
    display_name: "Certificates & Trust",
    description: "Certificate expiry, issuer, hostname coverage and anomalies from Certificate Transparency logs.",
    modules: ["certificate_intelligence"],
    required: ["certificate_intelligence"],
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
    required: ["headers", "ssl"],
    match: (f) => /^(header_|https_|redirect_|canonical_|ssl_|tech_)/.test(f.id || ""),
    maturity: "M2", managed_status: "recommendations",
    limitations: ["Passive external check only; no active, authenticated or intrusive testing."],
  },
  {
    domain_key: "identity_exposure",
    display_name: "Identity Exposure",
    description: "Externally observable spoofing, impersonation and exposed authentication-surface risks.",
    modules: ["identity_discovery"],
    required: ["identity_discovery"],
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
      // The SET of canonical finding ids behind this state, sorted and de-duplicated.
      // Additive and presentation-neutral — no existing surface reads it, and it never
      // participates in resolving `state`.
      //
      // It exists so a trend can say WHICH evidence changed rather than that a number
      // moved. Migration 090 established the rule: "A readiness percentage moving is not
      // an event: the score is a recomputation, and 72→68 says nothing about which
      // evidence changed." A set difference does say it, and — unlike a score — it is
      // stable against scoring-weight churn.
      finding_ids: [],
    };

    // No scan at all → honest not-yet-assessed for every domain.
    if (!report) {
      base.coverage = null;
      base.summary = "Not yet assessed — run a scan to establish this domain.";
      return base;
    }

    // ── Cyber Essentials (5) — readiness needs a COMPLETE questionnaire ───────
    // A readiness verdict (and therefore assessed_healthy) requires the customer to
    // have COMPLETED the questionnaire (snapshot.complete). No answers OR a partial
    // answer set → customer_input_required. External signals alone are indicative,
    // never a readiness verdict, so they never produce a healthy CE. Every surface
    // passes the same snapshot, so the state is identical everywhere.
    if (d.domain_key === "cyber_essentials_readiness") {
      // No external evidence => not assessed, and NOT an issue. ce-readiness.js
      // returns status 'not_assessed' when there is no completed scan report to
      // grade (no scan, missing R2 object, or a failed read). Without this branch
      // that status falls through to `ready === false` and renders ISSUE_DETECTED —
      // announcing readiness gaps the platform never observed. Evidence we do not
      // have is evidence_insufficient, in either direction.
      if (cyberEssentials && cyberEssentials.status === "not_assessed") {
        base.state = CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT;
        base.coverage = quality;
        base.summary = "Readiness could not be assessed — no completed external scan evidence is available yet.";
        return base;
      }
      if (cyberEssentials && cyberEssentials.has_answers === true && cyberEssentials.complete === true) {
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
        base.summary = (cyberEssentials && cyberEssentials.has_answers === true)
          ? "Cyber Essentials questionnaire is in progress — complete it to assess readiness."
          : "Complete the Cyber Essentials questionnaire to assess readiness.";
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
    // `required` = the module(s) that MUST have been assessed for a healthy verdict.
    // A globally-complete scan with no mapped finding is NOT enough — the domain's own
    // required evidence has to have actually been collected (this closes the CT/
    // subdomain "healthy off missing evidence" hole for Attack Surface, and stops
    // Website/Identity/Certs/Brand from reading healthy when their evidence is absent).
    const relevant = d.modules;
    const required = Array.isArray(d.required) && d.required.length ? d.required : relevant;
    const assessed = relevant.filter((n) => moduleAssessed(report, n, skippedSet));
    const requiredAssessedAll = required.length > 0 && required.every((n) => moduleAssessed(report, n, skippedSet));
    const requiredInsufficient = required.filter((n) => moduleAttempted(report, n, skippedSet));
    const anyRequiredInsufficient = requiredInsufficient.length > 0;

    const domainFindings = findings.filter((f) => materialSeverity(f.severity) && d.match(f));
    base.finding_count = domainFindings.length;
    base.evidence_count = assessed.length;
    base.finding_ids = [...new Set(domainFindings.map((f) => f.id).filter(Boolean))].sort();
    if (domainFindings.length) {
      base.highest_severity = domainFindings
        .map((f) => String(f.severity || "").toLowerCase())
        .sort((a, b) => (SEV_RANK[b] ?? 0) - (SEV_RANK[a] ?? 0))[0];
      base.recommendation_count = domainFindings.filter((f) => f.recommendation).length;
    }

    // ── Precedence (findings are never hidden; coverage carries the caveat) ──
    if (domainFindings.length > 0) {
      // A real finding always surfaces as issue_detected; coverage metadata tells the
      // UI whether the evidence behind it was provisional.
      const caveat = anyRequiredInsufficient || provisional;
      base.state = CYBER_MOT_STATES.ISSUE_DETECTED;
      base.coverage = caveat ? "partial" : (quality || "complete");
      base.summary = `${domainFindings.length} issue${domainFindings.length === 1 ? "" : "s"} detected${caveat ? " (provisional evidence)" : ""}.`;
      return base;
    }
    // ── Email Protection: canonical DMARC contribution (ADR-003 §7) ──────────
    // DMARC's enforcement verdict comes from the canonical dmarc_state produced by
    // deriveDmarcState(), read DIRECTLY from the live email module result. That
    // property is NON-ENUMERABLE, so it only resolves at snapshot-build time (the
    // in-memory report); an R2-rehydrated report drops it and this domain falls back
    // to the module-presence logic below (historical scans are never rewritten).
    // Runs only when NO material finding surfaced above, so a real finding is never
    // hidden — this exists to stop a healthy verdict for observed-but-weak DMARC
    // (partial/quarantine/invalid → issue_detected) or unobserved DMARC
    // (not_observed → evidence_insufficient). reject_enforced and not_yet_assessed
    // fall through to the normal healthy / not-assessed logic. no_record and
    // monitoring already surfaced as findings above and never reach here.
    if (d.domain_key === "email_protection") {
      const dmarcLevel = report?.modules?.email_security?.dmarc_state?.enforcement_level ?? null;
      const contribution = dmarcLevel ? DMARC_MOT_CONTRIBUTION[dmarcLevel] : null;
      if (contribution === "issue_detected") {
        const caveat = anyRequiredInsufficient || provisional;
        base.state = CYBER_MOT_STATES.ISSUE_DETECTED;
        base.coverage = caveat ? "partial" : (quality || "complete");
        base.highest_severity = base.highest_severity || "medium";
        base.summary = `DMARC enforcement is incomplete (${dmarcLevel})${caveat ? " (provisional evidence)" : ""}.`;
        return base;
      }
      if (contribution === "evidence_insufficient") {
        base.state = CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT;
        base.coverage = "degraded";
        base.summary = "DMARC could not be observed this scan (the DNS lookup did not complete) — not enough to assess.";
        return base;
      }
    }
    if (relevant.length === 0) {
      base.state = CYBER_MOT_STATES.NOT_YET_ASSESSED;
      base.summary = "Not yet assessed.";
      return base;
    }
    if (anyRequiredInsufficient) {
      // A REQUIRED module errored / was skipped / reported incomplete → the evidence
      // needed to assess this domain was attempted but not obtained. Never healthy.
      base.state = CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT;
      base.coverage = "degraded";
      base.summary = `Required evidence (${requiredInsufficient.join(", ")}) could not be collected this scan — not enough to assess.`;
      return base;
    }
    if (!requiredAssessedAll) {
      // A required module simply never ran (absent) → not assessed, never healthy.
      base.state = CYBER_MOT_STATES.NOT_YET_ASSESSED;
      base.summary = "Not yet assessed for this domain — required checks did not run.";
      return base;
    }
    if (provisional) {
      // All required evidence assessed, no material finding, BUT the overall scan is
      // provisional (partial/degraded/unknown) → do not assert an authoritative healthy.
      base.state = CYBER_MOT_STATES.PROVISIONAL;
      base.coverage = quality;
      base.summary = "No material issue observed, but this scan's coverage was provisional.";
      return base;
    }
    // All required evidence assessed on a COMPLETE scan with no material finding →
    // genuinely healthy (domain-specific limitations, e.g. unknown certificate trust,
    // remain attached and are never turned into a positive trust claim).
    base.state = CYBER_MOT_STATES.ASSESSED_HEALTHY;
    base.coverage = "complete";
    base.summary = "Assessed — no material issue observed.";
    return base;
  });
}
