// ── Cyber Essentials readiness (v1 estimate) ──
// Lightweight UK Cyber Essentials readiness estimate from existing scan data (grades +
// per-category gaps/recommendations across the five CE controls). Extracted verbatim from
// index.js (monolith decomposition, Phase 1c). Only buildCyberEssentialsReadiness is public.
import { clamp } from "./posture-scoring.js";
import { buildScorecardData } from "./scorecard.js";

// ── Cyber Essentials Readiness v1 ────────────────────────────────────────────
//
// Lightweight UK Cyber Essentials readiness estimate using only existing
// CyberMeters scan and workspace intelligence signals. This is not certification
// logic and does not add new probes, evidence uploads, or compliance tables.

function cyberEssentialsGrade(score) {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 55) return 'C';
  if (score >= 35) return 'D';
  return 'F';
}

function cyberEssentialsStatus(grade) {
  if (grade === 'A' || grade === 'B') return 'likely_ready';
  if (grade === 'C') return 'partially_ready';
  return 'not_ready';
}

function cyberEssentialsCategory(key, label, score, reasons, gaps, recommendations) {
  return {
    key,
    label,
    score: clamp(Math.round(score)),
    weight: 20,
    reasons: reasons.length ? reasons : ['No major readiness gaps detected from available signals.'],
    gaps,
    recommendations,
  };
}

function headerValue(headers, name) {
  if (!headers || typeof headers !== 'object') return null;
  const exact = headers[name] ?? headers[name.toLowerCase()] ?? headers[name.toUpperCase()];
  if (exact !== undefined) return exact;
  const found = Object.entries(headers).find(([k]) => k.toLowerCase() === name.toLowerCase());
  return found ? found[1] : null;
}

function hstsPresent(modules) {
  const hsts = modules?.domain_security_enrichment?.hsts;
  if (hsts && hsts.present !== undefined) return !!hsts.present;
  return !!headerValue(modules?.headers?.headers_observed ?? modules?.headers?.values, 'strict-transport-security');
}

function cspPresent(modules) {
  const value = headerValue(modules?.headers?.headers_observed ?? modules?.headers?.values, 'content-security-policy');
  return !!value;
}

function emailSignals(modules) {
  const email = modules?.email_security ?? {};
  return {
    spf:   !!email.spf?.present,
    dmarc: !!email.dmarc?.present,
    dmarcPolicy: email.dmarc?.policy ?? null,
    dkim:  !!email.dkim?.present,
  };
}

async function getLatestWorkspaceScanReport(wsId, env) {
  try {
    const scan = await env.cybermeters_db
      .prepare(
        `SELECT s.id
         FROM scans s
         LEFT JOIN workspace_domains wd ON wd.domain_id = s.domain_id
         WHERE s.status = 'completed'
           AND (s.workspace_id = ? OR wd.workspace_id = ?)
         ORDER BY s.created_at DESC LIMIT 1`
      )
      .bind(wsId, wsId)
      .first();
    if (!scan?.id) return null;

    const obj = await env.cybermeters_reports.get(`reports/${scan.id}.json`);
    if (!obj) return null;
    return await obj.json();
  } catch {
    return null;
  }
}

export async function buildCyberEssentialsReadiness(wsId, env) {
  const [scorecard, report] = await Promise.all([
    buildScorecardData(wsId, env),
    getLatestWorkspaceScanReport(wsId, env),
  ]);
  if (!scorecard) return null;

  const modules = report?.modules ?? {};
  const ssl = modules.ssl ?? {};
  const email = emailSignals(modules);
  const certRisk = scorecard.certificate_risks ?? {};
  const certRiskLevel = certRisk.risk_level ?? null;
  const certDaysLeft = certRisk.days_until_expiry;
  const adminTotal = scorecard.admin_surfaces ?? 0;
  const saasTotal = scorecard.saas_exposures ?? 0;
  const criticalFindings = scorecard.critical_findings ?? 0;
  const highFindings = scorecard.high_findings ?? 0;
  const takeoverRisks = modules.subdomain_takeover?.risks ?? modules.subdomain_takeover?.findings ?? [];
  const takeoverCount = Array.isArray(takeoverRisks) ? takeoverRisks.length : 0;
  const hsts = hstsPresent(modules);
  const csp = cspPresent(modules);

  const categories = [];
  const allGaps = [];
  const allRecommendations = [];

  function addGap(state, amount, reason, recommendation) {
    state.score -= amount;
    state.reasons.push(reason);
    state.gaps.push(reason);
    state.recommendations.push(recommendation ?? reason);
    allGaps.push({ reason, impact: amount });
    allRecommendations.push(recommendation ?? reason);
  }

  function addReason(state, reason) {
    state.reasons.push(reason);
  }

  // Boundary Protection: HTTPS, headers, exposed critical assets, takeover risk.
  {
    const state = { score: 100, reasons: [], gaps: [], recommendations: [] };
    if (ssl.https_available === false) {
      addGap(state, 30, 'HTTPS is not confirmed for the latest scanned domain.', 'Enable HTTPS on all public web services.');
    } else if (ssl.https_available === true) {
      addReason(state, 'HTTPS is available on the latest scanned domain.');
    }
    if (!hsts && !csp) {
      addGap(state, 15, 'Core browser boundary headers are missing or not confirmed.', 'Configure HSTS and Content Security Policy where applicable.');
    }
    if (criticalFindings > 0) {
      addGap(state, 20, `${criticalFindings} critical finding${criticalFindings !== 1 ? 's' : ''} remain in the latest scan.`, 'Remediate critical external findings before assessment.');
    }
    if (adminTotal > 0) {
      addGap(state, 20, `${adminTotal} exposed admin or management surface${adminTotal !== 1 ? 's' : ''} detected.`, 'Restrict admin and management interfaces from public internet access.');
    }
    if (takeoverCount > 0) {
      addGap(state, 25, `${takeoverCount} potential subdomain takeover risk${takeoverCount !== 1 ? 's' : ''} detected.`, 'Remove dangling DNS records or reclaim the referenced services.');
    }
    categories.push(cyberEssentialsCategory('boundary_protection', 'Boundary Protection', state.score, state.reasons, state.gaps, state.recommendations));
  }

  // Secure Configuration: HSTS, CSP, TLS posture, certificate health.
  {
    const state = { score: 100, reasons: [], gaps: [], recommendations: [] };
    if (!hsts) {
      addGap(state, 25, 'HSTS is not present or could not be confirmed.', 'Enable HSTS after validating HTTPS coverage.');
    } else {
      addReason(state, 'HSTS is present.');
    }
    if (!csp) {
      addGap(state, 20, 'Content Security Policy is not present or could not be confirmed.', 'Add a Content Security Policy suitable for the application.');
    } else {
      addReason(state, 'Content Security Policy is present.');
    }
    if (ssl.http_redirects_to_https === false) {
      addGap(state, 15, 'HTTP to HTTPS redirect is not confirmed.', 'Redirect all HTTP traffic to HTTPS.');
    }
    if (ssl.https_available === false) {
      addGap(state, 25, 'TLS is not available on the latest scanned domain.', 'Deploy valid TLS certificates for public services.');
    }
    if (certRiskLevel === 'critical' || certRiskLevel === 'high') {
      addGap(state, certRiskLevel === 'critical' ? 25 : 15, `Certificate intelligence risk is ${certRiskLevel}.`, 'Review certificate expiry, issuer, and suspicious certificate signals.');
    }
    categories.push(cyberEssentialsCategory('secure_configuration', 'Secure Configuration', state.score, state.reasons, state.gaps, state.recommendations));
  }

  // Access Control: email authentication plus externally visible admin/SaaS portals.
  {
    const state = { score: 100, reasons: [], gaps: [], recommendations: [] };
    if (!email.spf) addGap(state, 15, 'SPF is missing or not confirmed.', 'Publish an SPF record for approved sending services.');
    else addReason(state, 'SPF is present.');
    if (!email.dmarc) {
      addGap(state, 25, 'DMARC is missing or not confirmed.', 'Publish a DMARC policy for the domain.');
    } else if (email.dmarcPolicy === 'none') {
      addGap(state, 10, 'DMARC is monitor-only (p=none).', 'Move DMARC toward quarantine or reject after monitoring.');
    } else {
      addReason(state, 'DMARC is present.');
    }
    if (!email.dkim) addReason(state, 'DKIM could not be verified using common selectors; a custom selector may be in use.');
    else addReason(state, 'DKIM is detected.');
    if (adminTotal > 0) addGap(state, 25, 'Public admin surfaces increase access-control exposure.', 'Place admin portals behind VPN, SSO, or IP allowlists.');
    if (saasTotal > 0) addGap(state, 10, `${saasTotal} externally reachable SaaS portal${saasTotal !== 1 ? 's' : ''} detected.`, 'Review SSO and MFA coverage for externally reachable SaaS portals.');
    categories.push(cyberEssentialsCategory('access_control', 'Access Control', state.score, state.reasons, state.gaps, state.recommendations));
  }

  // Phishing & Malware Exposure: estimate only, based on proxy domain/email posture.
  {
    const state = { score: 100, reasons: [], gaps: [], recommendations: [] };
    addReason(state, 'Phishing and malware exposure is estimated from available domain, email, and external exposure signals only.');
    if (!email.dmarc || email.dmarcPolicy === 'none') {
      addGap(state, 25, 'Email anti-spoofing enforcement is weak.', 'Strengthen DMARC enforcement to reduce spoofing and phishing exposure.');
    }
    if (!email.spf) addGap(state, 15, 'SPF is missing or not confirmed.', 'Limit authorized mail senders with SPF.');
    if (!email.dkim) addReason(state, 'DKIM could not be verified using common selectors; a custom selector may be in use.');
    if (criticalFindings + highFindings > 0) {
      addGap(state, 15, 'High-impact external findings may increase malware delivery risk.', 'Prioritize remediation of critical and high findings.');
    }
    categories.push(cyberEssentialsCategory('malware_protection', 'Phishing & Malware Exposure', state.score, state.reasons, state.gaps, state.recommendations));
  }

  // Patch Management Readiness: certificate expiry, trend, remediation backlog.
  {
    const state = { score: 100, reasons: [], gaps: [], recommendations: [] };
    if (typeof certDaysLeft === 'number') {
      if (certDaysLeft < 0) {
        addGap(state, 30, 'A certificate is expired.', 'Renew expired certificates immediately.');
      } else if (certDaysLeft < 30) {
        addGap(state, 15, `A certificate expires in ${certDaysLeft} day${certDaysLeft !== 1 ? 's' : ''}.`, 'Renew certificates before the 30-day window.');
      } else {
        addReason(state, 'Certificate expiry health is acceptable.');
      }
    }
    if (certRiskLevel === 'critical' || certRiskLevel === 'high') {
      addGap(state, 15, `Certificate risk level is ${certRiskLevel}.`, 'Investigate certificate intelligence findings.');
    }
    if (criticalFindings > 0 || highFindings > 0) {
      addGap(state, 25, `${criticalFindings + highFindings} critical/high finding${criticalFindings + highFindings !== 1 ? 's' : ''} remain open in the latest scan.`, 'Close critical and high findings as evidence of remediation responsiveness.');
    } else {
      addReason(state, 'No critical or high findings in the latest scan.');
    }
    if ((scorecard.asset_events_30d ?? 0) > 0) {
      addReason(state, `${scorecard.asset_events_30d} asset change event${scorecard.asset_events_30d !== 1 ? 's' : ''} recorded in the last 30 days.`);
    }
    categories.push(cyberEssentialsCategory('patch_management_readiness', 'Patch Management Readiness', state.score, state.reasons, state.gaps, state.recommendations));
  }

  const score = Math.round(categories.reduce((sum, c) => sum + c.score * (c.weight / 100), 0));
  const grade = cyberEssentialsGrade(score);
  const topGaps = [...new Map(
    allGaps
      .sort((a, b) => b.impact - a.impact)
      .map(g => [g.reason, g.reason])
  ).values()].slice(0, 5);
  const recommendations = [...new Set(allRecommendations)].slice(0, 6);

  return {
    workspace_id: wsId,
    workspace_name: scorecard.workspace_name,
    score,
    grade,
    status: cyberEssentialsStatus(grade),
    categories,
    top_gaps: topGaps,
    recommendations,
    summary: topGaps.length
      ? `Cyber Essentials readiness is ${cyberEssentialsStatus(grade).replace(/_/g, ' ')}. Two areas to address first: ${topGaps.slice(0, 2).map(g => String(g).trim().replace(/\.+$/, '')).join('; ')}.`
      : 'Cyber Essentials readiness looks strong from currently available CyberMeters signals.',
    generated_at: new Date().toISOString(),
    latest_scan: {
      domain: scorecard.last_scanned_domain,
      scanned_at: scorecard.last_scan_at,
      security_score: scorecard.security_score,
      risk_rating: scorecard.risk_rating,
    },
    limitations: [
      'CyberMeters does not certify Cyber Essentials.',
      'This readiness estimate uses externally observable CyberMeters signals only.',
      'Endpoint protection, internal device configuration, and user access policies cannot be fully assessed from external ASM data.',
    ],
  };
}
