// ── Business Risk Score (BRS) v1 ──
// Executive-facing business-risk composite (separate from the ASM technical score): risk
// bands, finding-id expansion, scan-report BRS derivation, latest-scan BRS lookup, and the
// core BRS computation. Extracted verbatim from index.js (monolith decomposition, Phase 1c).
import { applyEvidenceQuality, isActionableFinding, normalizeFindingSchema } from "./findings.js";
import { resolveRemediation } from "./remediation-registry.js";
import { computeWorkspaceVendorRisk } from "./vendor-risk.js";
import { createId } from "../lib/util.js";

// ── Business Risk Score (BRS) v1 ─────────────────────────────────────────────
//
// An executive-facing risk composite separate from the ASM technical score.
// Uses only existing scan findings + workspace intelligence data.
// Never makes new network probes.
//
// Five weighted categories:
//   1. Email Risk       25% — SPF / DMARC / DKIM
//   2. Service Health   20% — DNS resolution + SSL validity
//   3. Customer Trust   20% — HTTPS / HSTS / header hygiene
//   4. Brand Exposure   20% — active typosquat domains (DNS-confirmed)
//   5. Supply Chain     15% — vendor count and risk level distribution
//
// Returns { brs, grade, grade_label, narrative, categories, top_concerns, generated_at }

// First methodology stamp for the scan-path Business Risk derivation (M5.c). Dates
// the CURRENT category weights + band cutoffs of deriveScanBusinessRisk; bump on any
// change so a persisted snapshot can refuse cross-methodology comparison. Customer
// presentation of this value is "Business Risk Indicator" — a band plus explanation,
// never a second competing score (founder package, 2026-07-16).
export const BUSINESS_RISK_METHODOLOGY_VERSION = "2026-07-16.1";

function getBusinessRiskBand(score) {
  if (score <= 30) return "critical";
  if (score <= 50) return "high";
  if (score <= 75) return "medium";
  return "low";
}

function computeWorkspaceBusinessRiskScore(workspace) {
  const vendor = workspace?.vendor_risk || {};
  const asm = workspace?.asm_security || {};
  const assets = workspace?.asset_exposure || {};

  let score = 100;
  const drivers = {
    vendor_risk: 0,
    security_findings: 0,
    asset_exposure: 0,
  };
  const primary_risks = [];
  const recommendations = [];

  const concentration = vendor.concentration_risk?.level || "low";
  const concentrationDeduction = concentration === "high" ? -25 : concentration === "medium" ? -15 : -5;
  drivers.vendor_risk += concentrationDeduction;
  if (concentration === "high") {
    primary_risks.push(`High dependency on external ${vendor.concentration_risk?.dominant_category || "vendor"} provider`);
    recommendations.push("Reduce dependency on a single critical third-party provider.");
  } else if (concentration === "medium") {
    primary_risks.push("Moderate concentration across third-party vendors");
    recommendations.push("Review vendor concentration and maintain fallback options for critical services.");
  }

  const topVendorScores = Array.isArray(vendor.top_vendors)
    ? vendor.top_vendors.map((v) => Number(v.score)).filter((n) => Number.isFinite(n))
    : [];
  const avgTopVendorScore = topVendorScores.length
    ? topVendorScores.reduce((sum, n) => sum + n, 0) / topVendorScores.length
    : null;
  if (avgTopVendorScore !== null) {
    // Vendor Risk Engine scores are exposure scores: higher values mean higher vendor risk.
    const vendorScoreDeduction =
      avgTopVendorScore > 80 ? -25 :
      avgTopVendorScore > 60 ? -15 :
      avgTopVendorScore > 40 ? -5 : 0;
    drivers.vendor_risk += vendorScoreDeduction;
    if (vendorScoreDeduction <= -15) {
      primary_risks.push("High-risk third-party vendor dependencies are present");
      recommendations.push("Review the highest-risk vendors and document compensating controls.");
    }
  }

  const criticalFindings = Number(asm.critical_findings || 0);
  if (criticalFindings > 5) {
    drivers.security_findings -= 20;
    primary_risks.push("Multiple unresolved critical findings");
    recommendations.push("Prioritize remediation of critical findings before expanding the attack surface.");
  }
  if (asm.missing_https) {
    drivers.security_findings -= 10;
    primary_risks.push("Public services do not consistently enforce HTTPS");
    recommendations.push("Fix critical SSL and HTTPS enforcement issues.");
  }
  if (asm.weak_email_security) {
    drivers.security_findings -= 10;
    primary_risks.push("Weak email security posture");
    recommendations.push("Enable SPF, DKIM, and DMARC enforcement for business email domains.");
  }
  if (asm.header_misconfig) {
    drivers.security_findings -= 5;
    primary_risks.push("Security header misconfiguration increases web risk");
    recommendations.push("Fix missing or weak security headers such as HSTS and CSP.");
  }

  const assetCount = Number(assets.asset_count || 0);
  const highOrCriticalFindings = criticalFindings > 0 || Number(asm.high_findings || 0) > 0;
  if (assetCount > 500 && highOrCriticalFindings) {
    drivers.asset_exposure -= 20;
    primary_risks.push("Large exposed asset footprint");
    recommendations.push("Reduce unmanaged external assets and prioritize ownership validation.");
  } else if (assetCount > 100 && highOrCriticalFindings) {
    drivers.asset_exposure -= 10;
    primary_risks.push("Expanded external asset footprint");
    recommendations.push("Review internet-facing assets and retire unused services.");
  } else if (assetCount > 500) {
    drivers.asset_exposure -= 5;
    primary_risks.push("Large external asset footprint with limited severe findings");
    recommendations.push("Continue asset ownership review and monitor for high-risk findings.");
  }

  score += drivers.vendor_risk + drivers.security_findings + drivers.asset_exposure;
  score = Math.max(0, Math.min(100, Math.round(score)));
  const risk_band = getBusinessRiskBand(score);

  const vendor_dependency_risk = concentration;
  const security_posture =
    criticalFindings > 5 || asm.missing_https ? "high" :
    asm.weak_email_security || asm.header_misconfig ? "medium" : "low";
  const asset_exposure =
    assetCount > 500 && highOrCriticalFindings ? "high" :
    (assetCount > 100 && highOrCriticalFindings) || assetCount > 500 ? "medium" : "low";

  const uniqueRisks = [...new Set(primary_risks.filter(Boolean))].slice(0, 6);
  const uniqueRecommendations = [...new Set(recommendations.filter(Boolean))].slice(0, 6);

  return {
    workspace_id: workspace.workspace_id,
    business_risk_score: score,
    risk_band,
    summary: {
      primary_risks: uniqueRisks,
      vendor_dependency_risk,
      security_posture,
      asset_exposure,
    },
    drivers,
    recommendations: uniqueRecommendations,
    vendor_risk: {
      workspace_vendor_risk_score: vendor.workspace_vendor_risk_score ?? null,
      avg_top_vendor_score: avgTopVendorScore === null ? null : Math.round(avgTopVendorScore),
      concentration_risk: vendor.concentration_risk ?? null,
      top_vendors: Array.isArray(vendor.top_vendors) ? vendor.top_vendors.slice(0, 10) : [],
    },
    calculated_at: new Date().toISOString(),
  };
}

// expandFindingIds: builds a finding ID Set that includes _consolidated_ids
// from any consolidated observations (e.g. security_headers_not_observed).
// This allows BRS and other ID-based checks to remain backward compatible
// without changes to the functions that receive the Set.
export function expandFindingIds(findings) {
  const ids = new Set(findings.map((f) => f.id).filter(Boolean));
  for (const f of findings) {
    if (Array.isArray(f._consolidated_ids)) {
      for (const id of f._consolidated_ids) ids.add(id);
    }
  }
  return ids;
}

/**
 * deriveScanBusinessRisk(report) — single source of truth for a scan's Business
 * Risk Score. Used by BOTH GET /scans/:id/report (UI) and the scan PDF route so
 * the two can never disagree. Takes a raw stored report; normalises findings and
 * reads module signals defensively (identical to the report endpoint's inline
 * derivation). Returns { score, band, summary, categories, top_business_risks }.
 */
export function deriveScanBusinessRisk(report) {
  const findings = applyEvidenceQuality(
    (Array.isArray(report?.findings) ? report.findings : []).map(normalizeFindingSchema)
  );
  const findingIds = expandFindingIds(findings.filter(isActionableFinding));
  const mods = report?.modules || {};
  const brsModuleData = {
    subdomainTakeoverCount: (mods.subdomain_takeover?.risks ?? []).length,
    assetExposureCount:     (mods.asset_exposure?.assets ?? []).filter(a => a.reachable).length,
    brandHighRisk: 0, brandMedRisk: 0, brandLowRisk: 0,
    vendorHigh: 0, vendorMedium: 0, vendorTotal: 0,
    identityHighRiskCount: (mods.identity_discovery?.high_risk_count ?? 0),
    vendorRelHighConf:     (mods.vendor_relationships?.high_confidence ?? 0),
  };
  const r = computeBusinessRiskScore(findingIds, brsModuleData);
  return {
    score:              r.score,
    band:               r.band,
    summary:            r.summary,
    categories:         r.categories,
    top_business_risks: r.top_business_risks,
  };
}


export function computeBusinessRiskScore(findingIds, workspaceData = {}) {
  if (findingIds && typeof findingIds === "object" && !(findingIds instanceof Set)) {
    return computeWorkspaceBusinessRiskScore(findingIds);
  }
  // findingIds: Set<string> of finding IDs from the scan/report
  // workspaceData: {
  //   brandHighRisk, brandMedRisk, brandLowRisk,
  //   vendorHigh, vendorMedium, vendorTotal,
  //   subdomainTakeoverCount, assetExposureCount
  // }

  // ── Category label helper ──────────────────────────────────────────────────
  function categoryLabel(s) {
    if (s >= 90) return "Excellent";
    if (s >= 75) return "Good";
    if (s >= 60) return "Moderate";
    if (s >= 40) return "Needs Attention";
    return "Critical";
  }

  // ── Business impact registry ───────────────────────────────────────────────
  // Maps finding IDs to executive business language.
  const IMPACT_MAP = [
    {
      id: "email_missing_spf",
      title: "No email sender protection (SPF)",
      impact: "Attackers can send emails that appear to come from your domain, enabling phishing attacks on your customers and partners.",
      recommendation: "Publish an SPF record in DNS specifying which mail servers are authorised to send email on your behalf.",
      severity: "high",
    },
    {
      id: "email_missing_dmarc",
      title: "No email anti-fraud policy (DMARC)",
      impact: "Attackers may impersonate your business email domain to phish customers or conduct brand fraud without any enforcement in place.",
      recommendation: "Publish a DMARC record at p=reject to block unauthorised use of your domain in email.",
      severity: "high",
    },
    {
      id: "email_dmarc_policy_none",
      title: "Email fraud protection is not enforced",
      impact: "Your DMARC record exists but is set to p=none, allowing fraudulent emails to be delivered to recipients.",
      recommendation: "Upgrade your DMARC policy from p=none to p=quarantine or p=reject.",
      severity: "medium",
    },
    {
      id: "email_dkim_not_detected",
      title: "DKIM selector could not be verified",
      impact: "Common-selector checks did not confirm a DKIM key. A custom selector may be in use, so DKIM absence is not confirmed.",
      recommendation: "Confirm the active selector with the email provider and verify that DNS record directly.",
      severity: "info",
    },
    {
      id: "ssl_certificate_expired",
      title: "SSL certificate has expired",
      impact: "Customers are blocked from accessing your website by browser security warnings, causing revenue loss and reputational damage.",
      recommendation: "Renew your SSL certificate immediately and configure automated renewal to prevent future lapses.",
      severity: "critical",
    },
    {
      id: "ssl_certificate_expiring_soon",
      title: "SSL certificate expiring soon",
      impact: "If not renewed promptly, your website will display security warnings and block customer access.",
      recommendation: "Renew your SSL certificate before the expiry date to prevent service disruption.",
      severity: "medium",
    },
    {
      id: "ssl_no_certificate",
      title: "No SSL/TLS certificate",
      impact: "Your website is unencrypted. Customer data and business transactions are exposed to interception.",
      recommendation: "Install an SSL certificate and configure HTTPS enforcement on your web server immediately.",
      severity: "critical",
    },
    {
      id: "no_https_redirect",
      title: "Website does not enforce HTTPS",
      impact: "Visitors connecting over HTTP may have their data intercepted. Modern browsers may warn users before loading your site.",
      recommendation: "Configure a permanent 301 redirect from HTTP to HTTPS on your web server.",
      severity: "high",
    },
    {
      id: "header_missing_strict_transport_security",
      title: "HSTS not configured",
      impact: "Users may be exposed to protocol downgrade attacks that bypass HTTPS encryption.",
      recommendation: "Set the Strict-Transport-Security response header with a max-age of at least 31536000 seconds.",
      severity: "medium",
    },
    {
      id: "header_weak_hsts",
      title: "HSTS configuration is weak",
      impact: "A short HSTS max-age creates brief windows after the first visit where users could be intercepted.",
      recommendation: "Increase HSTS max-age to at least 31536000 seconds and add the includeSubDomains directive.",
      severity: "low",
    },
    {
      id: "header_missing_content_security_policy",
      title: "No Content Security Policy (CSP)",
      impact: "Your website has no protection against cross-site scripting (XSS) attacks, which can compromise customer accounts and data.",
      recommendation: "Implement a Content Security Policy header to restrict which scripts and resources can load on your pages.",
      severity: "medium",
    },
    {
      id: "csp_weak_policy",
      title: "Content Security Policy is too permissive",
      impact: "Your CSP allows unsafe script sources, reducing its effectiveness against XSS and script injection attacks.",
      recommendation: "Tighten your CSP by removing unsafe-inline, unsafe-eval, and wildcard source directives.",
      severity: "low",
    },
    {
      id: "dns_no_resolution",
      title: "Domain is unreachable",
      impact: "Your website and online services are offline, causing customer loss, revenue disruption, and reputational damage.",
      recommendation: "Restore DNS configuration for your domain immediately and contact your DNS registrar.",
      severity: "critical",
    },
  ];

  const topRisks = [];
  for (const risk of IMPACT_MAP) {
    if (findingIds.has(risk.id)) {
      // The executive title/impact framing is BRS-specific, but the recommended
      // ACTION resolves through the canonical registry so it never conflicts with
      // the same advice shown elsewhere (e.g. DMARC ramp guidance, SPF -all).
      const canonical = resolveRemediation({ finding_type: risk.id });
      const recommendation = canonical.status === "resolved"
        ? canonical.recommended_action : risk.recommendation;
      topRisks.push({ title: risk.title, impact: risk.impact, recommendation, severity: risk.severity });
    }
  }
  // Sort: critical > high > medium > low
  const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
  topRisks.sort((a, b) => (SEV_ORDER[a.severity] ?? 4) - (SEV_ORDER[b.severity] ?? 4));

  // ── Category 1: Email Trust (25%) ──────────────────────────────────────────
  let emailDed = 0;
  if (findingIds.has("email_missing_spf"))       emailDed += 30;
  if (findingIds.has("email_missing_dmarc"))      emailDed += 30;
  else if (findingIds.has("email_dmarc_policy_none")) emailDed += 15;
  // Common-selector probing cannot confirm DKIM absence, so it does not affect BRS.
  const emailScore = Math.max(0, 100 - emailDed);

  // ── Category 2: Website Trust (20%) ────────────────────────────────────────
  let webDed = 0;
  if (findingIds.has("no_https_redirect") || findingIds.has("ssl_no_certificate")) webDed += 35;
  if (findingIds.has("header_missing_strict_transport_security")) webDed += 20;
  else if (findingIds.has("header_weak_hsts")) webDed += 8;
  if (findingIds.has("header_missing_content_security_policy")) webDed += 15;
  else if (findingIds.has("csp_weak_policy")) webDed += 5;
  if (findingIds.has("header_missing_x_frame_options") && findingIds.has("header_missing_x_content_type_options")) webDed += 8;
  const websiteScore = Math.max(0, 100 - webDed);

  // ── Category 3: Operational Continuity (20%) ───────────────────────────────
  let opsDed = 0;
  if (findingIds.has("dns_no_resolution"))            opsDed += 50;
  if (findingIds.has("ssl_certificate_expired"))      opsDed += 35;
  else if (findingIds.has("ssl_certificate_expiring_soon")) opsDed += 15;
  if (findingIds.has("ssl_no_certificate"))           opsDed += 25;
  const opsScore = Math.max(0, 100 - opsDed);

  // ── Category 4: Attack Surface Exposure (20%) ──────────────────────────────
  const {
    subdomainTakeoverCount  = 0,
    assetExposureCount      = 0,
    vendorHigh              = 0,
    vendorMedium            = 0,
    vendorTotal             = 0,
    identityHighRiskCount   = 0,
    vendorRelHighConf       = 0,  // high-confidence CSP-derived vendor relationships (supply chain signal)
  } = workspaceData;
  let attackDed = 0;
  attackDed += Math.min(30, subdomainTakeoverCount * 15);
  attackDed += Math.min(15, assetExposureCount * 5);
  if (vendorTotal > 0) {
    attackDed += Math.min(30, vendorHigh * 12 + vendorMedium * 5);
  } else {
    attackDed += 10; // No vendor visibility signal
  }
  // Identity surface deduction: internet-facing SSO/VPN/IdP portals are high-value targets
  attackDed += Math.min(20, identityHighRiskCount * 7);
  // Supply chain signal: confirmed payment/identity vendors detected via CSP increase
  // exposure risk (each confirmed relationship is a potential breach vector).
  // Cap at 10 — vendor_risk high count already carries the heavier penalty above.
  if (vendorRelHighConf >= 3) attackDed += Math.min(10, (vendorRelHighConf - 2) * 2);
  const attackScore = Math.max(0, 100 - attackDed);

  // ── Category 5: Brand / Reputation Risk (15%) ──────────────────────────────
  const { brandHighRisk = 0, brandMedRisk = 0, brandLowRisk = 0 } = workspaceData;
  const brandDed = Math.min(70, brandHighRisk * 20 + brandMedRisk * 10 + brandLowRisk * 4);
  const brandScore = Math.max(0, 100 - brandDed);

  // ── Composite score ────────────────────────────────────────────────────────
  const score = Math.round(
    emailScore   * 0.25
    + websiteScore * 0.20
    + opsScore     * 0.20
    + attackScore  * 0.20
    + brandScore   * 0.15
  );

  // ── Risk band ──────────────────────────────────────────────────────────────
  let band;
  if      (score >= 90) band = "Low Business Risk";
  else if (score >= 70) band = "Moderate Business Risk";
  else if (score >= 40) band = "High Business Risk";
  else                  band = "Critical Business Risk";

  // ── Backward-compat grade (used by historical score persistence) ───────────
  let grade, grade_label;
  if      (score >= 80) { grade = "A"; grade_label = "Low Risk";      }
  else if (score >= 60) { grade = "B"; grade_label = "Moderate Risk"; }
  else if (score >= 40) { grade = "C"; grade_label = "Elevated Risk"; }
  else if (score >= 20) { grade = "D"; grade_label = "High Risk";     }
  else                  { grade = "F"; grade_label = "Critical Risk";  }

  // ── Executive summary ──────────────────────────────────────────────────────
  const weakAreas = [];
  if (emailScore   < 70) weakAreas.push("email security");
  if (websiteScore < 70) weakAreas.push("website trust");
  if (opsScore     < 70) weakAreas.push("operational continuity");
  if (attackScore  < 70) weakAreas.push("attack surface exposure");
  if (brandScore   < 70) weakAreas.push("brand protection");

  let summary;
  if (weakAreas.length === 0) {
    summary = `Business risk posture is ${grade_label.toLowerCase()}. No major gaps detected across email security, website trust, operational continuity, attack surface, or brand protection.`;
  } else {
    const focus = weakAreas.slice(0, 2).join(" and ");
    summary = `Business risk posture is ${grade_label.toLowerCase()}. Primary concerns are in ${focus}. Addressing these areas will have the greatest impact on reducing commercial and reputational exposure.`;
  }

  const categories = {
    email_trust:              { score: emailScore,   label: categoryLabel(emailScore),   weight: 0.25 },
    website_trust:            { score: websiteScore, label: categoryLabel(websiteScore), weight: 0.20 },
    operational_continuity:   { score: opsScore,     label: categoryLabel(opsScore),     weight: 0.20 },
    attack_surface_exposure:  { score: attackScore,  label: categoryLabel(attackScore),  weight: 0.20 },
    brand_reputation_risk:    { score: brandScore,   label: categoryLabel(brandScore),   weight: 0.15 },
  };

  return {
    // ── v2 format (sprint-specified) ──
    score,
    band,
    summary,
    categories,
    top_business_risks: topRisks.slice(0, 5),
    generated_at: new Date().toISOString(),
    // ── Backward-compat aliases (workspace page + historical_scores persistence) ──
    brs:          score,
    grade,
    grade_label,
    narrative:    summary,
    top_concerns: topRisks.slice(0, 5).map(r => ({ category: r.title, issue: r.impact, score })),
  };
}

// ── Canonical workspace Business Risk: compute + persist (M5.e) ──────────────
// The founder contract: the workspace-model BRS is calculated and persisted at
// SCAN FINALIZE; GET /business-risk reads the persisted result and never
// recalculates or writes. This function is the ONE producer — it assembles the
// workspace model (vendors, latest-scan findings, assets), computes, derives
// the customer payload (narrative, grade, top concerns), and persists
// workspace_brs_scores (+ one history row per finalized scan — history cadence
// is scan cadence, never page-view cadence).

// Workspace-BRS letter grade — a WORKSPACE Business Risk semantic, not a Cyber
// Metrics Score band (relocated verbatim from the route so exactly one ladder
// exists, here, documented).
export function workspaceBrsGrade(score) {
  return score >= 76 ? "A" : score >= 51 ? "B" : score >= 31 ? "C" : "F";
}

export async function computeAndPersistWorkspaceBrs(env, workspaceId) {
  const [latestScanRow, assetRow] = await Promise.all([
    env.cybermeters_db
      .prepare(`SELECT s.id AS scan_id, s.score, s.rating, s.created_at
                FROM scans s WHERE s.workspace_id = ? AND s.status = 'completed'
                ORDER BY s.created_at DESC LIMIT 1`)
      .bind(workspaceId).first(),
    env.cybermeters_db
      .prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND status = 'active'`)
      .bind(workspaceId).first(),
  ]);

  let vendorRows = [];
  try {
    const r = await env.cybermeters_db
      .prepare(`SELECT wv.id, wv.workspace_id, wv.vendor_name, wv.category,
                       wv.source, wv.evidence, wv.confidence, wv.risk_level,
                       wv.status, wv.first_seen, wv.last_seen,
                       vrs.score AS persisted_score, vrs.category_multiplier, vrs.concentration_penalty
                FROM workspace_vendors wv
                LEFT JOIN vendor_risk_scores vrs
                  ON vrs.vendor_id = wv.id AND vrs.workspace_id = wv.workspace_id
                WHERE wv.workspace_id = ? AND wv.status = 'active' AND wv.source_module = 'vendor_risk'`)
      .bind(workspaceId).all();
    vendorRows = r.results || [];
  } catch {
    const r = await env.cybermeters_db
      .prepare(`SELECT id, workspace_id, vendor_name, category, source, evidence,
                       confidence, risk_level, status, first_seen, last_seen
                FROM workspace_vendors
                WHERE workspace_id = ? AND status = 'active' AND source_module = 'vendor_risk'`)
      .bind(workspaceId).all();
    vendorRows = r.results || [];
  }

  const vendorAggregate = computeWorkspaceVendorRisk(vendorRows);
  const topVendors = vendorAggregate.top_vendors.map((v) => ({
    id: v.id, name: v.vendor_name, vendor_name: v.vendor_name,
    category: v.normalized_category, score: v.persisted_score ?? v.score, risk_level: v.risk_level,
  }));

  let findingIds = new Set();
  let criticalFindings = 0;
  let highFindings = 0;
  if (latestScanRow?.scan_id) {
    try {
      const obj = await env.cybermeters_reports.get(`reports/${latestScanRow.scan_id}.json`);
      if (obj) {
        const report = await obj.json();
        const findings = Array.isArray(report.findings) ? report.findings : [];
        findingIds = expandFindingIds(findings.filter(isActionableFinding));
        criticalFindings = findings.filter((f) => f.severity === "critical").length;
        highFindings = findings.filter((f) => f.severity === "high").length;
      }
    } catch { /* tolerate missing report */ }
    if (criticalFindings === 0 && highFindings === 0) {
      try {
        const severityRows = await env.cybermeters_db
          .prepare(`SELECT severity, COUNT(*) AS n FROM findings WHERE scan_id = ? GROUP BY severity`)
          .bind(latestScanRow.scan_id).all();
        const severityMap = Object.fromEntries((severityRows.results || []).map((r) => [r.severity, r.n]));
        criticalFindings = severityMap.critical || 0;
        highFindings = severityMap.high || 0;
      } catch { /* non-fatal */ }
    }
  }

  const workspaceModel = {
    workspace_id: workspaceId,
    vendor_risk: {
      workspace_vendor_risk_score: vendorAggregate.workspace_vendor_risk_score,
      top_vendors: topVendors,
      concentration_risk: vendorAggregate.concentration_risk,
    },
    asm_security: {
      critical_findings: criticalFindings,
      high_findings: highFindings,
      missing_https: findingIds.has("ssl_no_certificate") || findingIds.has("no_https_redirect"),
      weak_email_security:
        findingIds.has("email_missing_spf") || findingIds.has("email_missing_dmarc") ||
        findingIds.has("email_dmarc_policy_none"),
      header_misconfig:
        findingIds.has("header_missing_strict_transport_security") || findingIds.has("header_weak_hsts") ||
        findingIds.has("header_missing_content_security_policy") || findingIds.has("csp_weak_policy"),
    },
    asset_exposure: { asset_count: assetRow?.n || 0 },
  };

  const brs = computeBusinessRiskScore(workspaceModel);
  const narrative = brs.summary.primary_risks.length > 0
    ? `Business risk is ${brs.risk_band}. Primary concerns: ${brs.summary.primary_risks.slice(0, 2).join("; ")}.`
    : `Business risk is ${brs.risk_band}. No major business-risk drivers were detected from current ASM and vendor data.`;
  const grade = workspaceBrsGrade(brs.business_risk_score);

  const payload = {
    ...brs,
    score: brs.business_risk_score,
    brs: brs.business_risk_score,
    band: brs.risk_band,
    grade,
    grade_label: brs.risk_band,
    narrative,
    top_concerns: brs.summary.primary_risks.map((risk) => ({
      title: risk, impact: risk,
      recommendation: brs.recommendations[0] || "Review this risk with the responsible business owner.",
      severity: brs.risk_band === "critical" ? "critical" : brs.risk_band === "high" ? "high" : "medium",
    })),
    latest_scan: latestScanRow ? {
      scan_id: latestScanRow.scan_id, asm_score: latestScanRow.score,
      asm_rating: latestScanRow.rating, scanned_at: latestScanRow.created_at,
    } : null,
    workspace_context: {
      vendor_total: vendorAggregate.scored_vendors.length,
      asset_count: workspaceModel.asset_exposure.asset_count,
      critical_findings: criticalFindings,
      high_findings: highFindings,
    },
  };

  await env.cybermeters_db
    .prepare(`INSERT OR REPLACE INTO workspace_brs_scores
                (workspace_id, score, risk_band, calculated_at, payload_json)
              VALUES (?, ?, ?, ?, ?)`)
    .bind(workspaceId, brs.business_risk_score, brs.risk_band, brs.calculated_at, JSON.stringify(payload))
    .run();
  await env.cybermeters_db
    .prepare(`INSERT INTO workspace_brs_score_history
                (id, workspace_id, score, risk_band, calculated_at)
              VALUES (?, ?, ?, ?, ?)`)
    .bind(createId("brshist"), workspaceId, brs.business_risk_score, brs.risk_band, brs.calculated_at)
    .run();
  return payload;
}
