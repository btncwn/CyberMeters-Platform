// ── Cyber Essentials readiness (v1 estimate) ──
// Lightweight UK Cyber Essentials readiness estimate from existing scan data (grades +
// per-category gaps/recommendations across the five CE controls). Extracted verbatim from
// index.js (monolith decomposition, Phase 1c). Only buildCyberEssentialsReadiness is public.
import { clamp } from "./posture-scoring.js";
import { buildScorecardData } from "./scorecard.js";
import { resolveRemediation } from "./remediation-registry.js";
import { CE_QUESTIONS } from "../lib/cyber-essentials.js";

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

function cyberEssentialsCategory(key, label, score, reasons, gaps, recommendations, remediations, unknown) {
  const unknownSignals = unknown ?? [];
  return {
    key,
    label,
    score: clamp(Math.round(score)),
    weight: 20,
    // "No major readiness gaps detected" is a CLAIM. It may only be made when
    // something was actually observed — otherwise the honest line is that the
    // control could not be assessed, which is what `unknown` records.
    reasons: reasons.length
      ? reasons
      : (unknownSignals.length
          ? ['This control area could not be assessed from the available external evidence.']
          : ['No major readiness gaps detected from available signals.']),
    gaps,
    // The signals CyberMeters did NOT observe for this control area. Empty means
    // every signal this control reads was actually assessed.
    unknown: unknownSignals,
    // True only when at least one signal was observed AND none is unknown.
    externally_assessed: unknownSignals.length === 0,
    recommendations,
    // Canonical remediation identities for each gap in this control area, so the
    // CE surface, Executive Report and PDF resolve the SAME remediation as the
    // scan surfaces. Readiness framing is separate from external certification.
    remediations: remediations ?? [],
  };
}

function headerValue(headers, name) {
  if (!headers || typeof headers !== 'object') return null;
  const exact = headers[name] ?? headers[name.toLowerCase()] ?? headers[name.toUpperCase()];
  if (exact !== undefined) return exact;
  const found = Object.entries(headers).find(([k]) => k.toLowerCase() === name.toLowerCase());
  return found ? found[1] : null;
}

// ── Did the module that carries this evidence actually assess it? ────────────
// CE reads other modules' output. If a module errored, was skipped by the
// subrequest budget, or self-reported `incomplete` (a probe that never executed —
// see headers-scan.js / ssl-scan.js), then CE observed NOTHING about the controls
// that module feeds.
//
// This mattered because every signal below was a loose falsy test. With no scan at
// all — or one failed R2 read, since getLatestWorkspaceScanReport returns null for
// "no scan", "object missing" and "any error" alike — `modules` is `{}`, so `!hsts`,
// `!csp`, `!email.spf` and `!email.dmarc` were all true and CE reported
// score 72 / grade C / `partially_ready`, listing gaps like "DMARC is missing or
// not confirmed". Absent evidence was graded identically to confirmed failure.
//
// The asymmetry proved it was an oversight rather than a decision: `https_available`
// was already tested with a strict `=== false` (someone deliberately separated
// "absent" from "false" for that one signal) while the other four were not.
//
// Tri-state from here on: true / false / null, where NULL MEANS UNKNOWN AND NEVER
// SCORES. addGap refuses null (below), so an unassessed control can neither deduct
// nor produce a gap. `unknown` is the honest state; a fabricated gap is not.
function moduleAssessedForCe(modules, name) {
  const m = modules?.[name];
  if (m == null) return false;
  if (m.error) return false;
  if (m.skipped === true || m.incomplete === true) return false;
  return true;
}

function hstsPresent(modules) {
  const hsts = modules?.domain_security_enrichment?.hsts;
  if (hsts && hsts.present !== undefined) return !!hsts.present;
  if (!moduleAssessedForCe(modules, 'headers')) return null;   // we did not look
  return !!headerValue(modules?.headers?.headers_observed ?? modules?.headers?.values, 'strict-transport-security');
}

function cspPresent(modules) {
  if (!moduleAssessedForCe(modules, 'headers')) return null;   // we did not look
  const value = headerValue(modules?.headers?.headers_observed ?? modules?.headers?.values, 'content-security-policy');
  return !!value;
}

function emailSignals(modules) {
  if (!moduleAssessedForCe(modules, 'email_security')) {
    return { spf: null, dmarc: null, dmarcPolicy: null, dkim: null };
  }
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

  // ── No external evidence at all => NOT ASSESSED. Never a grade. ─────────────
  // getLatestWorkspaceScanReport returns null for three different situations that
  // must not be conflated: no completed scan, the R2 object missing, and any thrown
  // error. In all three CyberMeters has observed nothing externally, so it has
  // nothing to say about external readiness.
  //
  // This guard is mandatory BECAUSE of the tri-state fix above, not despite it.
  // Previously `modules = {}` made every loose `!signal` true, and CE reported
  // score 72 / grade C / `partially_ready` — fabricating gaps ("DMARC is missing")
  // from evidence it never collected. Making those signals honest (null) removes
  // the deductions, which alone would have flipped a no-evidence workspace to
  // score 100 / grade A / `likely_ready` — trading a fabricated failure for a
  // fabricated pass, which is far worse. Absent evidence is neither. It is unknown.
  //
  // The questionnaire is NOT consulted here and must never be: this function is the
  // answer-free external verdict. `getCyberEssentialsSnapshot` gates on the
  // questionnaire for DISPLAY; that is a separate concern, downstream of this.
  if (!report) {
    return {
      workspace_id: wsId,
      workspace_name: scorecard.workspace_name,
      assessable: false,
      score: null,
      grade: null,
      status: 'not_assessed',
      categories: [],
      top_gaps: [],
      recommendations: [],
      canonical_remediations: [],
      summary: 'Cyber Essentials readiness has not been assessed — no completed external scan evidence is available for this workspace yet.',
      generated_at: new Date().toISOString(),
      latest_scan: null,
      limitations: [
        'CyberMeters does not certify Cyber Essentials.',
        'No completed external scan evidence was available, so no readiness estimate has been made.',
      ],
    };
  }

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
  const allRemediations = [];

  // addGap now takes a canonical remediation reference (a registry finding_type)
  // instead of a hard-coded recommendation string. The recommended ACTION and its
  // identity resolve from the canonical registry, so CE readiness advice can never
  // drift from the same advice shown on the scan surfaces. The `reason` remains the
  // CE-specific RISK interpretation (readiness owns that). Falls back to the reason
  // text only if the ref does not resolve (should not happen — CI asserts coverage).
  function addGap(state, amount, reason, remediationRef) {
    state.score -= amount;
    state.reasons.push(reason);
    state.gaps.push(reason);
    const r = remediationRef ? resolveRemediation({ finding_type: remediationRef }) : null;
    const resolved = r && r.status === "resolved";
    const recommendation = resolved ? r.recommended_action : reason;
    state.recommendations.push(recommendation);
    if (resolved) {
      const rem = {
        remediation_id: r.remediation_id,
        customer_title: r.customer_title,
        recommended_action: r.recommended_action,
        business_impact: r.business_impact,
        verification_method: r.verification_method,
        domain_key: r.domain_key,
      };
      state.remediations.push(rem);
      allRemediations.push(rem);
    }
    allGaps.push({ reason, impact: amount });
    allRecommendations.push(recommendation);
  }

  function addReason(state, reason) {
    state.reasons.push(reason);
  }

  // A signal we did not observe is recorded, not scored. The customer is told the
  // control could not be assessed rather than being shown a gap the platform never
  // saw — and `unknown` is carried on the category so a consumer (and the CE
  // lifecycle) can tell "externally evidenced ready" apart from "we did not look".
  function addUnknown(state, signal, reason) {
    state.unknown.push({ signal, reason });
    state.reasons.push(reason);
  }

  // Boundary Protection: HTTPS, headers, exposed critical assets, takeover risk.
  {
    const state = { score: 100, reasons: [], gaps: [], recommendations: [], remediations: [], unknown: [] };
    if (ssl.https_available === false) {
      addGap(state, 30, 'HTTPS is not confirmed for the latest scanned domain.', 'ssl_not_available');
    } else if (ssl.https_available === true) {
      addReason(state, 'HTTPS is available on the latest scanned domain.');
    } else {
      addUnknown(state, 'https_available', 'HTTPS could not be assessed — the probe did not complete.');
    }
    // Strict `=== false` on BOTH: null means the headers module never assessed, and
    // "core browser boundary headers are missing" is then a claim about the
    // customer's site made from a probe that never ran.
    if (hsts === false && csp === false) {
      addGap(state, 15, 'Core browser boundary headers are missing or not confirmed.', 'header_missing_strict_transport_security');
    } else if (hsts === null && csp === null) {
      addUnknown(state, 'browser_headers', 'Browser security headers could not be assessed — the probe did not complete.');
    }
    if (criticalFindings > 0) {
      addGap(state, 20, `${criticalFindings} critical finding${criticalFindings !== 1 ? 's' : ''} remain in the latest scan.`, 'ce_open_findings_backlog');
    }
    if (adminTotal > 0) {
      addGap(state, 20, `${adminTotal} exposed admin or management surface${adminTotal !== 1 ? 's' : ''} detected.`, 'asset_exposure_admin_interface');
    }
    if (takeoverCount > 0) {
      addGap(state, 25, `${takeoverCount} potential subdomain takeover risk${takeoverCount !== 1 ? 's' : ''} detected.`, 'subdomain_takeover');
    }
    categories.push(cyberEssentialsCategory('boundary_protection', 'Boundary Protection', state.score, state.reasons, state.gaps, state.recommendations, state.remediations, state.unknown));
  }

  // Secure Configuration: HSTS, CSP, TLS posture, certificate health.
  {
    const state = { score: 100, reasons: [], gaps: [], recommendations: [], remediations: [], unknown: [] };
    if (hsts === false) {
      addGap(state, 25, 'HSTS is not present or could not be confirmed.', 'header_missing_strict_transport_security');
    } else if (hsts === true) {
      addReason(state, 'HSTS is present.');
    } else {
      addUnknown(state, 'hsts', 'HSTS could not be assessed — the header probe did not complete.');
    }
    if (csp === false) {
      addGap(state, 20, 'Content Security Policy is not present or could not be confirmed.', 'header_missing_content_security_policy');
    } else if (csp === true) {
      addReason(state, 'Content Security Policy is present.');
    } else {
      addUnknown(state, 'csp', 'Content Security Policy could not be assessed — the header probe did not complete.');
    }
    if (ssl.http_redirects_to_https === false) {
      addGap(state, 15, 'HTTP to HTTPS redirect is not confirmed.', 'ssl_no_http_redirect');
    }
    if (ssl.https_available === false) {
      addGap(state, 25, 'TLS is not available on the latest scanned domain.', 'ssl_not_available');
    }
    if (certRiskLevel === 'critical' || certRiskLevel === 'high') {
      addGap(state, certRiskLevel === 'critical' ? 25 : 15, `Certificate intelligence risk is ${certRiskLevel}.`, 'ce_cert_review');
    }
    categories.push(cyberEssentialsCategory('secure_configuration', 'Secure Configuration', state.score, state.reasons, state.gaps, state.recommendations, state.remediations, state.unknown));
  }

  // Access Control: email authentication plus externally visible admin/SaaS portals.
  {
    const state = { score: 100, reasons: [], gaps: [], recommendations: [], remediations: [], unknown: [] };
    if (email.spf === false) addGap(state, 15, 'SPF is missing or not confirmed.', 'email_missing_spf');
    else if (email.spf === true) addReason(state, 'SPF is present.');
    else addUnknown(state, 'spf', 'SPF could not be assessed — email evidence was not collected.');
    if (email.dmarc === false) {
      addGap(state, 25, 'DMARC is missing or not confirmed.', 'email_missing_dmarc');
    } else if (email.dmarc === true && email.dmarcPolicy === 'none') {
      addGap(state, 10, 'DMARC is monitor-only (p=none).', 'email_dmarc_policy_none');
    } else if (email.dmarc === true) {
      addReason(state, 'DMARC is present.');
    } else {
      addUnknown(state, 'dmarc', 'DMARC could not be assessed — email evidence was not collected.');
    }
    if (email.dkim === true) addReason(state, 'DKIM is detected.');
    else if (email.dkim === false) addReason(state, 'DKIM could not be verified using common selectors; a custom selector may be in use.');
    else addUnknown(state, 'dkim', 'DKIM could not be assessed — email evidence was not collected.');
    if (adminTotal > 0) addGap(state, 25, 'Public admin surfaces increase access-control exposure.', 'asset_exposure_admin_interface');
    if (saasTotal > 0) addGap(state, 10, `${saasTotal} externally reachable SaaS portal${saasTotal !== 1 ? 's' : ''} detected.`, 'ce_saas_access_review');
    categories.push(cyberEssentialsCategory('access_control', 'Access Control', state.score, state.reasons, state.gaps, state.recommendations, state.remediations, state.unknown));
  }

  // Phishing & Malware Exposure: estimate only, based on proxy domain/email posture.
  {
    const state = { score: 100, reasons: [], gaps: [], recommendations: [], remediations: [], unknown: [] };
    addReason(state, 'Phishing and malware exposure is estimated from available domain, email, and external exposure signals only.');
    if (email.dmarc === false || (email.dmarc === true && email.dmarcPolicy === 'none')) {
      addGap(state, 25, 'Email anti-spoofing enforcement is weak.', 'email_dmarc_policy_none');
    } else if (email.dmarc === null) {
      addUnknown(state, 'dmarc', 'Email anti-spoofing enforcement could not be assessed — email evidence was not collected.');
    }
    if (email.spf === false) addGap(state, 15, 'SPF is missing or not confirmed.', 'email_missing_spf');
    else if (email.spf === null) addUnknown(state, 'spf', 'SPF could not be assessed — email evidence was not collected.');
    if (email.dkim === false) addReason(state, 'DKIM could not be verified using common selectors; a custom selector may be in use.');
    if (criticalFindings + highFindings > 0) {
      addGap(state, 15, 'High-impact external findings may increase malware delivery risk.', 'ce_open_findings_backlog');
    }
    categories.push(cyberEssentialsCategory('malware_protection', 'Phishing & Malware Exposure', state.score, state.reasons, state.gaps, state.recommendations, state.remediations, state.unknown));
  }

  // Patch Management Readiness: certificate expiry, trend, remediation backlog.
  {
    const state = { score: 100, reasons: [], gaps: [], recommendations: [], remediations: [], unknown: [] };
    if (typeof certDaysLeft === 'number') {
      if (certDaysLeft < 0) {
        addGap(state, 30, 'A certificate is expired.', 'ssl_certificate_expired');
      } else if (certDaysLeft < 30) {
        addGap(state, 15, `A certificate expires in ${certDaysLeft} day${certDaysLeft !== 1 ? 's' : ''}.`, 'ssl_certificate_expiring_soon');
      } else {
        addReason(state, 'Certificate expiry health is acceptable.');
      }
    }
    if (certRiskLevel === 'critical' || certRiskLevel === 'high') {
      addGap(state, 15, `Certificate risk level is ${certRiskLevel}.`, 'ce_cert_review');
    }
    if (criticalFindings > 0 || highFindings > 0) {
      addGap(state, 25, `${criticalFindings + highFindings} critical/high finding${criticalFindings + highFindings !== 1 ? 's' : ''} remain open in the latest scan.`, 'ce_open_findings_backlog');
    } else {
      addReason(state, 'No critical or high findings in the latest scan.');
    }
    if ((scorecard.asset_events_30d ?? 0) > 0) {
      addReason(state, `${scorecard.asset_events_30d} asset change event${scorecard.asset_events_30d !== 1 ? 's' : ''} recorded in the last 30 days.`);
    }
    categories.push(cyberEssentialsCategory('patch_management_readiness', 'Patch Management Readiness', state.score, state.reasons, state.gaps, state.recommendations, state.remediations, state.unknown));
  }

  const score = Math.round(categories.reduce((sum, c) => sum + c.score * (c.weight / 100), 0));
  const grade = cyberEssentialsGrade(score);
  const topGaps = [...new Map(
    allGaps
      .sort((a, b) => b.impact - a.impact)
      .map(g => [g.reason, g.reason])
  ).values()].slice(0, 5);
  const recommendations = [...new Set(allRecommendations)].slice(0, 6);
  // Deduplicated canonical remediation identities across all control areas, so a
  // consumer (Executive Report, PDF, tests) can join CE readiness to the SAME
  // remediation shown on scan surfaces. Certification remains external (below).
  const canonicalRemediations = [...new Map(
    allRemediations.map((r) => [r.remediation_id, r])
  ).values()];

  return {
    workspace_id: wsId,
    workspace_name: scorecard.workspace_name,
    // External scan evidence existed and was graded. The `not_assessed` early
    // return above is the only path that reports otherwise.
    assessable: true,
    score,
    grade,
    status: cyberEssentialsStatus(grade),
    categories,
    top_gaps: topGaps,
    recommendations,
    canonical_remediations: canonicalRemediations,
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

// isCyberEssentialsQuestionnaireComplete — the canonical completeness contract:
// every question of every control has a non-"unknown" answer (mirrors mergeReadiness'
// `answered` predicate in lib/cyber-essentials.js). A single or partial answer set is
// NOT complete, so it can never permit an authoritative readiness verdict.
export function isCyberEssentialsQuestionnaireComplete(answersMap = {}) {
  return CE_QUESTIONS.every((ctrl) => {
    const ans = answersMap[ctrl.control_key] || {};
    const answered = ctrl.questions.filter((q) => ans[q.key] && ans[q.key] !== "unknown");
    return answered.length === ctrl.questions.length;
  });
}

// getCyberEssentialsSnapshot — the ONE canonical Cyber Essentials snapshot used by
// every surface's eight-domain resolver, so a workspace shows the SAME CE state on
// the Dashboard, Scan Detail, Executive Report UI and Executive PDF.
//
// Cyber Essentials readiness is only meaningful once the customer has COMPLETED the
// self-attestation questionnaire — external signals alone (and a partial answer set)
// are indicative, not a readiness verdict. So the snapshot carries both flags:
//   • no answers            → { has_answers:false, complete:false } → customer_input_required;
//   • partial answers       → { has_answers:true,  complete:false } → customer_input_required;
//   • complete questionnaire → { has_answers:true,  complete:true, status } → readiness verdict.
// The readiness (heavier) computation only runs once the questionnaire is complete.
export async function getCyberEssentialsSnapshot(wsId, env) {
  let rows = [];
  try {
    const r = await env.cybermeters_db
      .prepare('SELECT control_key, question_key, answer FROM cyber_essentials_answers WHERE workspace_id = ?')
      .bind(wsId).all();
    rows = r?.results || [];
  } catch { rows = []; }

  const has_answers = rows.length > 0;
  if (!has_answers) return { has_answers: false, complete: false, status: null, top_gaps: [] };

  const answersMap = {};
  for (const r of rows) {
    if (!answersMap[r.control_key]) answersMap[r.control_key] = {};
    answersMap[r.control_key][r.question_key] = r.answer;
  }
  const complete = isCyberEssentialsQuestionnaireComplete(answersMap);

  let readiness = null;
  if (complete) {
    try { readiness = await buildCyberEssentialsReadiness(wsId, env); } catch { readiness = null; }
  }
  return {
    has_answers: true,
    complete,
    status: readiness?.status ?? null,
    top_gaps: Array.isArray(readiness?.top_gaps) ? readiness.top_gaps : [],
  };
}
