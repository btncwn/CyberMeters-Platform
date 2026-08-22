import { DMARC_MOT_CONTRIBUTION } from "./dmarc-canonical-consumers.js";
import { resolveSignalMonitoringCoverage } from "./signal-monitoring-state.js";
import { isCookieFindingType } from "./cookie-observation.js";
import { hasIdentityReachabilityProducer } from "./identity-evidence-contract.js";
import {
  projectTlsFindingsForCustomer,
  resolveTlsRuntimeState,
  TLS_RUNTIME_STATES,
} from "./tls-evidence.js";
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
// `.3` (24 July 2026): domain conclusions now consume their declared signal
// monitoring dependencies. Missing/degraded CT provenance cannot support a
// healthy negative conclusion, while positive findings remain visible.
// `.4` (24 July 2026): Evidence-Grade Law pilot. A favourable 2-of-5 external
// Cyber Essentials indicator can no longer promote the full five-control
// domain to assessed_healthy; three controls remain customer-attestation-only.
// `2026-08-09.1`: RWS.5 atomically transfers the three cookie-attribute finding
// identities from Attack Surface to Website Security. Persisted earlier rows keep
// their original bytes; the existing version gate makes the boundary not_comparable.
// `2026-08-09.2`: combined SSL corrective — Website conclusions consume the canonical
// active-TLS tri-state (legacy/unproven false is evidence-insufficient, never a
// material issue) and D1 canonical finding identity adds a bounded read-time
// projection for exact historical null-identity TLS-only Website rows.
// `2026-08-11.1`: Identity provider/candidate evidence no longer stands in for
// endpoint reachability. With no registered producer, a finding-free Identity
// assessment is evidence-insufficient and cross-version trend is incomparable.
// `2026-08-12.1`: a valid canonical DMARC policy conclusion outranks stale
// lookup/core degradation markers from the same frozen evidence. The version
// boundary prevents that definition correction reading as customer change.
export const CYBER_MOT_RESOLVER_VERSION = "2026-08-22.1";

// THE HONESTY BOUNDARY IS A FIXED FLOOR, NOT A MOVING ONE.
//
// `CYBER_MOT_RESOLVER_VERSION` moves on every methodology mint. Comparing a stored
// snapshot against it asks "was this produced by the CURRENT resolver?" — and the
// answer goes false for every historical row the moment we mint, including rows that
// were entirely honest when written. A projection keyed on that question therefore
// masks honest history: a snapshot stamped 2026-08-12.1 with an `assessed_healthy`
// identity conclusion would be rewritten to `evidence_insufficient` and told the
// customer "Identity reachability was not evaluated by a supported producer" — a
// sentence that is false about that snapshot.
//
// The question the projection actually needs is "was this produced at or after the
// version where the semantics became honest?", which is a FIXED point in history.
// Honest predecessor versions stay honest forever. This floor moves only by explicit
// future ruling — never as a side effect of a mint.
export const FIRST_HONEST_RESOLVER_VERSION = "2026-08-12.1";

export function isResolverVersionAtLeast(version, minimum = CYBER_MOT_RESOLVER_VERSION) {
  const parse = (value) => {
    const match = /^(\d{4})-(\d{2})-(\d{2})\.(\d+)$/.exec(String(value || ""));
    return match ? match.slice(1).map(Number) : null;
  };
  const actual = parse(version);
  const floor = parse(minimum);
  if (!actual || !floor) return false;
  for (let i = 0; i < actual.length; i += 1) {
    if (actual[i] !== floor[i]) return actual[i] > floor[i];
  }
  return true;
}

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
    monitoring_signals: ["certificate_transparency"],
    monitoring_degradation_message: "Attack-surface and subdomain discovery coverage was incomplete this run.",
    match: (f) => !isCookieFindingType(f?.id)
      && /^(asset_|subdomain_|admin_|takeover_|exposure_|dse_|cve_|kev_|cloud_|dns_)/.test(f?.id || ""),
    maturity: "M3", managed_status: "managed_case",
    limitations: ["External observation only; no internal-network discovery. Subdomain coverage depends on public Certificate Transparency logs."],
  },
  {
    domain_key: "certificates_trust",
    display_name: "Certificates & Trust",
    description: "Certificate expiry, issuer, hostname coverage and anomalies from Certificate Transparency logs.",
    modules: ["certificate_intelligence"],
    required: ["certificate_intelligence"],
    monitoring_signals: ["certificate_transparency"],
    match: (f) => /^(cert_|certificate_)/.test(f.id || "") || f.module === "certificate_intelligence",
    maturity: "M2", managed_status: "recommendations",
    limitations: ["Analysis is based on Certificate Transparency logs. Chain validity, root trust, OCSP and revocation status are not checked and remain unknown."],
  },
  {
    domain_key: "cyber_essentials_readiness",
    display_name: "Cyber Essentials Readiness",
    description: "An indicative estimate of your likely Cyber Essentials readiness — not a certification.",
    modules: [], // derived from external signals + the questionnaire, not a scan module
    monitoring_signals: ["certificate_transparency"],
    monitoring_degradation_message: "External-control indicator coverage was incomplete this run.",
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
    match: (f) => isCookieFindingType(f?.id)
      || /^(header_|https_|redirect_|canonical_|ssl_|tech_)/.test(f?.id || ""),
    maturity: "M2", managed_status: "recommendations",
    limitations: ["Passive external check only; no active, authenticated or intrusive testing."],
  },
  {
    domain_key: "identity_exposure",
    display_name: "Identity Exposure",
    description: "Externally observable provider relationships and possible identity-facing hostnames, with reachability reported only when measured.",
    modules: ["identity_discovery"],
    required: ["identity_discovery"],
    monitoring_signals: ["certificate_transparency"],
    monitoring_degradation_message: "Identity-surface enumeration was incomplete this run.",
    match: (f) => /^identity_/.test(f.id || "") || f.module === "identity_discovery",
    maturity: "M1", managed_status: "monitoring",
    limitations: ["Current Identity discovery identifies provider relationships and possible identity-facing hostnames; it does not measure endpoint reachability or include leaked-credential, breached-password or dark-web monitoring."],
  },
  {
    domain_key: "shadow_it_unmanaged_technology",
    display_name: "Shadow IT & Unmanaged Technology",
    description: "Externally visible SaaS, cloud services, email senders and internet-facing technologies that may sit outside the known technology inventory.",
    modules: ["saas_exposure", "third_party_discovery", "technology_detection", "cloud_storage_discovery", "vendor_relationships"],
    monitoring_signals: ["certificate_transparency"],
    monitoring_degradation_message: "Technology observation coverage was incomplete this run.",
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
  if (name === "ssl" && resolveTlsRuntimeState(m).state === TLS_RUNTIME_STATES.UNAVAILABLE) return false;
  if (m.error) return false;
  if (m.skipped === true || m.incomplete === true) return false;
  if (skippedSet.has(name)) return false;
  return true;
}
function moduleAttempted(report, name, skippedSet) {
  // Attempted-but-insufficient: present but errored/skipped/incomplete.
  const m = report?.modules?.[name];
  if (m == null) return skippedSet.has(name);
  if (name === "ssl" && resolveTlsRuntimeState(m).state === TLS_RUNTIME_STATES.UNAVAILABLE) return true;
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
  const findings = projectTlsFindingsForCustomer(report?.findings, report?.modules);
  const lastAssessedAt = report?.completed_at || report?.created_at || null;
  const sourceScanId = scanId || report?.scan_id || null;
  // Anything that is not an authoritative "complete" scan is provisional — this
  // includes legacy "unknown" coverage, which must never render as healthy.
  const provisional = quality != null && quality !== "complete";

  return CYBER_MOT_DOMAINS.map((d) => {
    const monitoringCoverage = resolveSignalMonitoringCoverage(
      report?.monitoring_states,
      d.monitoring_signals
    );
    const signalCoverageLimited = !monitoringCoverage.complete;
    // The signal/provider message remains canonical monitoring provenance, but a
    // domain conclusion must explain the effect in that domain's own language.
    // Certificates deliberately keeps the CT-specific wording because CT is the
    // evidence being assessed there; Identity/Shadow/CE/ASM describe the coverage
    // consequence instead of exposing a nonsensical provider sentence.
    const signalCoverageMessage = signalCoverageLimited
      ? (d.monitoring_degradation_message || monitoringCoverage.messages.join(" "))
      : "";
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
      // Additive evidence-coverage provenance. This is not a posture verdict:
      // it records whether this domain's declared monitoring inputs completed.
      monitoring_state: monitoringCoverage.state,
      monitoring_signals: monitoringCoverage.signals,
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
        base.summary = cyberEssentials.containment_reason && typeof cyberEssentials.summary === "string"
          ? cyberEssentials.summary
          : "Readiness could not be assessed — no completed external scan evidence is available yet.";
        return base;
      }
      if (cyberEssentials && cyberEssentials.has_answers === true && cyberEssentials.complete === true) {
        const ready = cyberEssentials.status === "likely_ready";
        base.finding_count = (cyberEssentials.top_gaps || []).length;
        base.recommendation_count = base.finding_count;
        if (!ready) {
          base.state = CYBER_MOT_STATES.ISSUE_DETECTED;
          base.coverage = (provisional || signalCoverageLimited) ? "partial" : "complete";
          base.summary = `Indicative readiness gaps identified (${base.finding_count})` +
            `${signalCoverageLimited ? " (some external evidence was unavailable)." : "."}`;
        } else if (signalCoverageLimited) {
          base.state = CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT;
          base.coverage = "degraded";
          base.summary = `${signalCoverageMessage} Indicative readiness cannot be confirmed from incomplete external evidence.`;
        } else {
          // Evidence-Grade Law: the named external indicator covers only 2 of 5
          // controls. Access Control, Malware Protection and Security Update
          // Management remain L0 customer attestation, so the FULL domain can
          // never be labelled healthy even when the external indicator is
          // favourable and every questionnaire answer is complete.
          base.state = CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT;
          base.coverage = provisional ? quality : "partial";
          base.summary =
            "External indicator found no material issue in 2 of 5 control areas; " +
            "the full Cyber Essentials conclusion remains evidence-insufficient because 3 controls are attestation-only.";
        }
      } else {
        base.state = CYBER_MOT_STATES.CUSTOMER_INPUT_REQUIRED;
        if (signalCoverageLimited) base.coverage = "degraded";
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
      base.coverage = signalCoverageLimited ? "degraded" : (provisional ? quality : "complete");
      base.summary = observed > 0
        ? `${observed} externally observed ${observed === 1 ? "technology/service" : "technologies/services"} (approved-inventory comparison not yet configured).`
        : "Externally observed technology monitoring active (approved-inventory comparison not yet configured).";
      if (signalCoverageLimited) {
        base.summary += ` ${signalCoverageMessage}`;
      }
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
      const caveat = anyRequiredInsufficient || provisional || signalCoverageLimited;
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
      const dmarcState = report?.modules?.email_security?.dmarc_state ?? null;
      const dmarcLevel = dmarcState?.enforcement_level ?? null;
      const contribution = dmarcLevel ? DMARC_MOT_CONTRIBUTION[dmarcLevel] : null;
      if (contribution === "issue_detected") {
        const caveat = anyRequiredInsufficient || provisional;
        base.state = CYBER_MOT_STATES.ISSUE_DETECTED;
        base.coverage = caveat ? "partial" : (quality || "complete");
        base.highest_severity = base.highest_severity || "medium";
        base.summary = (dmarcState.canonical_summary ||
          `DMARC enforcement is incomplete (${dmarcLevel}).`) +
          (caveat ? " Other Email Protection evidence was provisional." : "");
        return base;
      }
      if (contribution === "evidence_insufficient") {
        base.state = CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT;
        base.coverage = "degraded";
        base.summary = dmarcState.canonical_summary ||
          "DMARC could not be observed this scan (the DNS lookup did not complete) — not enough to assess.";
        return base;
      }
    }
    if (d.domain_key === "identity_exposure" && !hasIdentityReachabilityProducer()) {
      base.state = CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT;
      base.coverage = requiredAssessedAll ? "partial" : quality;
      base.summary = "Identity reachability was not evaluated — no supported reachability producer is implemented. Provider relationships and possible hostnames remain visible for review.";
      return base;
    }
    if (relevant.length === 0) {
      base.state = CYBER_MOT_STATES.NOT_YET_ASSESSED;
      base.summary = "Not yet assessed.";
      return base;
    }
    // A domain may have all of its module objects present while a decisive
    // provider-backed signal inside those modules was unavailable. This generic
    // dependency gate prevents that shape from becoming assessed_healthy. It is
    // intentionally after positive findings (which must remain visible) and
    // before every negative/healthy conclusion.
    if (signalCoverageLimited) {
      base.state = CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT;
      base.coverage = "degraded";
      base.summary = `${signalCoverageMessage} Not enough evidence was available to make a healthy conclusion.`;
      return base;
    }
    if (anyRequiredInsufficient) {
      // A REQUIRED module errored / was skipped / reported incomplete → the evidence
      // needed to assess this domain was attempted but not obtained. Never healthy.
      // The module's own `incomplete_reason` is carried into the customer sentence.
      // Without it this read "could not be collected", which is wrong for a module that
      // DID collect a response and found it unusable — an all-5xx origin under F-48 is
      // observed, not unreachable — and it hid the exact marker
      // (origin_error_no_serviceable_response / origin_not_observed) the remediation
      // exists to produce. The reason is read from the stored per-module record, so the
      // card cannot claim anything the evidence does not itself say.
      base.state = CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT;
      base.coverage = "degraded";
      // Two DIFFERENT propositions share `incomplete: true`, and they must not be
      // worded alike:
      //   reason present — the module ran and what it observed could not support a
      //                    conclusion (e.g. origin_error_no_serviceable_response);
      //   reason absent  — the module did NOT complete within the scan budget, so
      //                    nothing was observed at all. Calling that "not usable"
      //                    would assert an observation that never happened.
      // Neither wording carries a favourable or unfavourable inference.
      const withReason = requiredInsufficient.filter((n) => report?.modules?.[n]?.incomplete_reason);
      const withoutReason = requiredInsufficient.filter((n) => !report?.modules?.[n]?.incomplete_reason);
      const clauses = [];
      if (withReason.length > 0) {
        const detail = withReason.map((name) =>
          `${name}: ${String(report.modules[name].incomplete_reason).replace(/_/g, " ")}`);
        clauses.push(`Required evidence (${detail.join(", ")}) was not usable this scan`);
      }
      if (withoutReason.length > 0) {
        clauses.push(`Required checks (${withoutReason.join(", ")}) did not complete within the scan budget — not assessed`);
      }
      base.summary = `${clauses.join(". ")} — not enough to assess.`;
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
