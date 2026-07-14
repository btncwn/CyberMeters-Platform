// ── Executive report + intelligence-engine registry ──
// Canonical scan-score resolution, the intelligence-engine registry + attribution helpers,
// and the executive report v2 builder (findings → remediation-grouped executive summary).
// Extracted verbatim from index.js (monolith decomposition, Phase 1c).
// findRegisteredIntelligenceEngine + buildExecutiveReportV2Remediation are module-internal.
import { resolveAssessmentPresentation } from "./assessment-presentation.js";
import { applyEvidenceQuality, isActionableFinding, normalizeFindingSchema } from "./findings.js";

export function resolveCanonicalScanScore(storedScore, reportScore) {
  const storedValue = storedScore == null || storedScore === "" ? NaN : Number(storedScore);
  if (Number.isFinite(storedValue)) return storedValue;

  const reportValue = reportScore == null || reportScore === "" ? NaN : Number(reportScore);
  return Number.isFinite(reportValue) ? reportValue : 0;
}

export const INTELLIGENCE_ENGINE_REGISTRY = {
  attack_surface: {
    label: "Attack Surface Intelligence",
    modules: new Set([
      "dns", "ssl", "headers", "subdomains", "subdomain_takeover", "asset_exposure",
      "technology_detection", "whois_intelligence", "dns_bruteforce", "cve_intelligence",
      "known_exploited_vulnerabilities", "cloud_storage_discovery", "admin_surface_detection",
      "canonical_url_profile", "domain_security_enrichment", "certificate_intelligence",
      "saas_exposure", "third_party_assets", "vendor_relationships",
    ]),
    idPrefixes: [],
    recommendationIdPrefixes: [],
  },
  business_email: {
    label: "Business Email Intelligence",
    modules: new Set(["email_security", "email_security_intelligence"]),
    idPrefixes: ["email_"],
    recommendationIdPrefixes: [],
  },
  identity: {
    label: "Identity Intelligence",
    modules: new Set(["identity_discovery"]),
    idPrefixes: ["identity_"],
    recommendationIdPrefixes: [],
  },
  brand: {
    label: "Brand Intelligence",
    modules: new Set(["brand_monitoring"]),
    idPrefixes: ["brand_"],
    recommendationIdPrefixes: ["brand_"],
  },
  executive: {
    label: "Executive Intelligence",
    modules: new Set(),
    idPrefixes: [],
    recommendationIdPrefixes: [],
  },
};

function findRegisteredIntelligenceEngine(item, prefixField = "idPrefixes") {
  const moduleName = String(item?.module || "");
  const itemId = String(item?.id || "");
  for (const [engine, definition] of Object.entries(INTELLIGENCE_ENGINE_REGISTRY)) {
    const prefixes = definition[prefixField] || [];
    if (definition.modules.has(moduleName) || prefixes.some((prefix) => itemId.startsWith(prefix))) {
      return engine;
    }
  }
  return null;
}

export function resolveIntelligenceEngine(item) {
  return findRegisteredIntelligenceEngine(item) || "attack_surface";
}

function buildExecutiveReportV2Remediation(findings, recommendations, remediationPlan) {
  const actionableTitles = new Set(findings.map((finding) => finding.title).filter(Boolean));
  const actionableModules = new Set(findings.map((finding) => finding.module).filter(Boolean));
  const output = [];
  const seen = new Set();
  const add = (item, priority) => {
    const title = item?.title;
    if (!title || seen.has(title)) return;
    seen.add(title);
    output.push({
      priority,
      title,
      action: item.action || item.description || null,
      reason: item.reason || null,
      source: item.source || item.module || null,
      due_date: item.due_date || null,
    });
  };

  const roadmap = [
    ["P1", remediationPlan?.p1_immediate || []],
    ["P2", remediationPlan?.p2_high || []],
    ["P3", remediationPlan?.p3_medium_low || []],
  ];
  for (const [priority, items] of roadmap) {
    for (const item of items) {
      if (actionableTitles.has(item?.title) || item?.source === "cisa_kev" || item?.source === "subdomain_takeover") {
        add(item, priority);
      }
    }
  }
  for (const recommendation of recommendations) {
    if (actionableTitles.has(recommendation?.title) || actionableModules.has(recommendation?.module)) {
      add(recommendation, `P${Math.max(1, Math.min(3, Number(recommendation?.priority) || 3))}`);
    }
  }
  return output;
}

export function buildExecutiveReportV2({ scan, rawReport, workspace = null, generatedAt = new Date().toISOString() }) {
  const raw = rawReport || {};
  const evidence = raw.modules || {};
  const allFindings = applyEvidenceQuality(
    (Array.isArray(raw.findings) ? raw.findings : []).map(normalizeFindingSchema)
  );
  const verifiedFindings = allFindings.filter(isActionableFinding);
  const observations = allFindings.filter((finding) => !isActionableFinding(finding));
  const recommendations = Array.isArray(raw.recommendations) ? raw.recommendations : [];
  const canonicalScore = resolveCanonicalScanScore(scan?.score, raw.cyber_metrics_score);
  // Canonical completeness-aware presentation — a final rating shows ONLY for a
  // complete assessment; partial/degraded/unknown are provisional (no rating).
  const assessment = resolveAssessmentPresentation({
    score: canonicalScore,
    scanQuality: raw.scan_quality?.status,
    status: scan?.status || raw.status,
    coverage: raw.scan_quality?.modules_skipped ?? null,
  });
  const rating = assessment.display_rating;
  const historical = evidence.historical_changes || {};
  // Only a complete current assessment against a complete baseline is comparable.
  const trendComparable = assessment.comparable && historical.comparable !== false;
  const severityRank = { critical: 5, high: 4, medium: 3, low: 2, info: 1, informational: 1 };
  const topRisks = [...verifiedFindings]
    .sort((a, b) => (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0)
      || Math.abs(Number(b.score_impact) || 0) - Math.abs(Number(a.score_impact) || 0))
    .slice(0, 5);
  const prioritizedRemediation = buildExecutiveReportV2Remediation(
    verifiedFindings,
    recommendations,
    evidence.remediation_plan,
  );
  // A provisional (partial/degraded/unknown) assessment must never emit reassuring
  // clean-state language — surface the status caveat instead.
  const riskNarrative = !assessment.authoritative
    ? assessment.message
    : (evidence.risk_intelligence?.narrative || (
        canonicalScore >= 90
          ? "External exposure controls are strong. Continue monitoring for material changes."
          : canonicalScore >= 75
            ? "External exposure is generally well controlled, with focused improvements recommended."
            : canonicalScore >= 50
              ? "Several external exposure issues require planned remediation and continued monitoring."
              : "Material external exposure issues require prioritized remediation."
      ));
  // Trend deltas/direction appear ONLY for comparable (complete-vs-complete)
  // assessments — a partial/degraded scan never renders improved/declined/+N.
  const trendSummary = {
    status: (trendComparable && historical.has_previous) ? "available" : "not_available",
    comparable: trendComparable,
    previous_scan_id: trendComparable ? (historical.previous_scan_id || null) : null,
    previous_score: trendComparable ? (historical.previous_score ?? null) : null,
    current_score: canonicalScore,
    score_change: (trendComparable && historical.previous_score != null) ? canonicalScore - historical.previous_score : null,
    direction: (trendComparable && historical.previous_score != null)
      ? (canonicalScore > historical.previous_score ? "improved"
        : canonicalScore < historical.previous_score ? "declined" : "unchanged")
      : "not_available",
    new_findings_count: Array.isArray(historical.new_findings) ? historical.new_findings.length : 0,
    resolved_findings_count: Array.isArray(historical.resolved_findings) ? historical.resolved_findings.length : 0,
  };

  const engineItems = (engine, items) => items.filter((item) => resolveIntelligenceEngine(item) === engine);
  const attackFindings = engineItems("attack_surface", verifiedFindings);
  const attackObservations = engineItems("attack_surface", observations);
  const emailFindings = engineItems("business_email", verifiedFindings);
  const emailObservations = engineItems("business_email", observations);
  const identityFindings = engineItems("identity", verifiedFindings);
  const identityObservations = engineItems("identity", observations);
  const brandFindings = engineItems("brand", verifiedFindings);
  const brandObservations = engineItems("brand", observations);
  const actionableModules = new Set(verifiedFindings.map((finding) => finding.module).filter(Boolean));
  const recommendationsFor = (engine) => recommendations.filter((item) =>
    actionableModules.has(item?.module)
      && findRegisteredIntelligenceEngine(item, "recommendationIdPrefixes") === engine
  );

  const identityEvidence = evidence.identity_discovery;
  const identityAvailable = Boolean(identityEvidence?.detected || identityFindings.length || identityObservations.length);
  const brandEvidenceAvailable = Boolean(
    evidence.brand_monitoring || evidence.certificate_intelligence || brandFindings.length || brandObservations.length
  );

  return {
    version: "2.0",
    report_type: "executive",
    workspace: {
      id: workspace?.id || null,
      name: workspace?.name || null,
    },
    domain: {
      id: scan?.domain_id || raw.domain_id || null,
      name: scan?.domain || raw.domain || null,
      scan_id: scan?.id || raw.scan_id || null,
      scan_status: scan?.status || raw.status || null,
      scanned_at: scan?.created_at || raw.started_at || null,
      completed_at: raw.completed_at || null,
    },
    generated_at: generatedAt,
    cyber_metrics_score: {
      value: assessment.display_score,
      rating,                       // null for a provisional (non-complete) assessment
      provisional: assessment.provisional,
      authoritative: assessment.authoritative,
      comparable: assessment.comparable,
      quality: assessment.quality,
      message: assessment.message,  // status caveat, null when complete
      minimum: 0,
      maximum: 100,
      source: scan?.score == null ? "legacy_report_fallback" : "scan_record",
    },
    executive_summary: {
      risk_narrative: riskNarrative,
      verified_findings_count: verifiedFindings.length,
      observations_count: observations.length,
      top_risks: topRisks,
      trend: trendSummary,
      priority_actions: prioritizedRemediation.slice(0, 5),
    },
    intelligence_engines: {
      attack_surface: {
        status: Object.keys(evidence).length ? "available" : "not_available",
        summary: `${attackFindings.length} actionable finding(s) and ${attackObservations.length} observation(s) from external attack surface evidence.`,
        evidence: {
          dns: evidence.dns || null,
          ssl_tls: evidence.ssl || null,
          https: evidence.canonical_url_profile || null,
          security_headers: evidence.headers || null,
          certificates: evidence.certificate_intelligence || null,
          subdomains: evidence.subdomains || null,
          takeover: evidence.subdomain_takeover || null,
          assets: evidence.asset_exposure || null,
          cloud_exposure: evidence.cloud_storage_discovery || null,
          admin_surfaces: evidence.admin_surface_detection || null,
          saas_exposure: evidence.saas_exposure || null,
          third_party_exposed_assets: evidence.third_party_assets || null,
          third_party_relationships: evidence.vendor_relationships || null,
        },
        findings: attackFindings,
        observations: attackObservations,
        recommendations: recommendationsFor("attack_surface"),
      },
      business_email: {
        status: evidence.email_security || evidence.email_security_intelligence ? "available" : "not_available",
        summary: `${emailFindings.length} actionable finding(s) and ${emailObservations.length} observation(s) from business email evidence.`,
        evidence: {
          spf: evidence.email_security_intelligence?.spf || evidence.email_security?.spf || null,
          dkim: evidence.email_security_intelligence?.dkim || evidence.email_security?.dkim || null,
          dmarc: evidence.email_security_intelligence?.dmarc || evidence.email_security?.dmarc || null,
          mta_sts: evidence.email_security_intelligence?.mta_sts || null,
          tls_rpt: evidence.email_security_intelligence?.tls_rpt || null,
          mx_intelligence: {
            has_mx: evidence.dns?.has_mx ?? null,
            records: evidence.dns?.mx || evidence.dns?.mx_records || [],
          },
          provider_detection: evidence.email_security?.dkim?.provider || null,
          email_security_score: evidence.email_security_intelligence?.email_security_score ?? null,
          rating: evidence.email_security_intelligence?.rating || null,
          remediation: evidence.email_security ? {
            spf_detail: evidence.email_security.spf_detail || null,
            dmarc_detail: evidence.email_security.dmarc_detail || null,
            dkim_detail: evidence.email_security.dkim_detail || null,
            bimi_readiness: evidence.email_security.bimi_readiness || null,
            mta_sts_detail: evidence.email_security.mta_sts_detail || null,
            tls_rpt_detail: evidence.email_security.tls_rpt_detail || null,
            policy_journey: evidence.email_security.policy_journey || null,
            actions: evidence.email_security.remediation_actions || [],
          } : null,
        },
        findings: emailFindings,
        observations: emailObservations,
        recommendations: recommendationsFor("business_email"),
      },
      identity: identityAvailable ? {
        status: "partial",
        summary: "Externally observable identity providers or login surfaces were detected. Connected identity posture assessment is not enabled.",
        evidence: identityEvidence,
        findings: identityFindings,
        observations: identityObservations,
        recommendations: recommendationsFor("identity"),
      } : {
        status: "not_available",
        summary: "Identity Intelligence is not enabled for this workspace yet.",
        findings: [],
        observations: [],
        recommendations: [],
      },
      brand: {
        status: brandEvidenceAvailable ? "partial" : "not_available",
        summary: brandEvidenceAvailable
          ? "Brand intelligence is based on currently available lookalike-domain and certificate evidence."
          : "Brand Intelligence evidence is not available for this scan.",
        evidence: {
          brand_monitoring: evidence.brand_monitoring || null,
          certificate_signals: evidence.certificate_intelligence?.suspicious_certificate_signals || [],
        },
        findings: brandFindings,
        observations: brandObservations,
        recommendations: recommendationsFor("brand"),
      },
      executive: {
        status: "available",
        cyber_metrics_score: canonicalScore,
        rating,
        risk_narrative: riskNarrative,
        top_risks: topRisks,
        trend_summary: trendSummary,
        prioritized_recommendations: prioritizedRemediation,
      },
    },
    verified_findings: verifiedFindings,
    observations,
    historical_trends: trendSummary,
    prioritized_remediation: prioritizedRemediation,
    supporting_evidence: {
      scan_quality: raw.scan_quality || null,
      technology_detection: evidence.technology_detection || null,
      whois_intelligence: evidence.whois_intelligence || null,
      known_exploited_vulnerabilities: evidence.known_exploited_vulnerabilities || null,
      legacy_vendor_context: evidence.vendor_risk || null,
    },
  };
}
