// ── Security posture scoring / executive scorecard ──
// Score→status mapping, value clamping, and computeSecurityPosture (executive scorecard
// posture roll-up vs the enterprise benchmark). Extracted verbatim from index.js (monolith
// decomposition, Phase 1c). scoreStatus is module-internal.
import { ENTERPRISE_DOMAINS } from "./scoring-config.js";
import { resolveRemediation } from "./remediation-registry.js";

// Posture scoring OWNS risk interpretation (the `reasons`). Any customer ACTION
// promoted from a posture category (e.g. into the Executive PDF) must resolve
// from the canonical remediation registry rather than be re-worded or fabricated.
// pushRem resolves a finding type to its canonical remediation identity and adds
// it (deduped by remediation_id) to a category's remediations list. Unknown types
// add nothing — an informational reason honestly yields no promoted action.
function pushRem(arr, findingType) {
  if (!findingType) return;
  const r = resolveRemediation({ finding_type: findingType });
  if (r.status !== "resolved") return;
  if (arr.some((x) => x.remediation_id === r.remediation_id)) return;
  arr.push({
    remediation_id: r.remediation_id,
    customer_title: r.customer_title,
    recommended_action: r.recommended_action,
    business_impact: r.business_impact,
    verification_method: r.verification_method,
    domain_key: r.domain_key,
  });
}

// ── Executive Security Scorecard ─────────────────────────────────────────────
//
// Aggregates data from D1 (structured tables) + R2 (latest scan report modules)
// into a business-friendly security scorecard.  Shared by:
//   GET /api/workspaces/:id/scorecard
//   GET /api/workspaces/:id/scorecard/report

// ── Security Posture Scoring ──────────────────────────────────────────────────
//
// Computes five category scores (0-100) from existing scorecard + R2 report data.
// No new queries — pure function over already-loaded data.
//
// Weights (must sum to 1.0):
//   Email Security:    20%
//   SSL & Certs:       20%
//   Attack Surface:    25%
//   Third-Party Risk:  15%
//   Admin Exposure:    20%

function scoreStatus(s) {
  if (s === null)  return 'unknown';
  if (s >= 90)     return 'good';
  if (s >= 70)     return 'fair';
  if (s >= 50)     return 'warning';
  return 'critical';
}

export function clamp(n, lo = 0, hi = 100) { return Math.max(lo, Math.min(hi, n)); }

/**
 * computeSecurityPosture(sc, report)
 *
 * @param {object} sc     — the scorecard object (all D1-derived fields)
 * @param {object|null} report — the R2 JSON report (may be null if no scan yet)
 * @returns {{ email_security, ssl_certificates, attack_surface,
 *             third_party_risk, admin_exposure, overall_score }}
 */
export function computeSecurityPosture(sc, report) {
  const em   = report?.modules?.email_security   ?? null;
  const ssl  = report?.modules?.ssl              ?? null;
  const adm  = report?.modules?.admin_surface_detection ?? null;

  // ── 1. Email Security ────────────────────────────────────────────────────────
  let emailScore   = 100;
  const emailReasons = [];
  const emailRem = [];

  if (em === null) {
    emailScore = null;
  } else {
    if (!em.spf?.present) {
      emailScore -= 25;
      emailReasons.push('Missing SPF record — any server can send mail as this domain');
      pushRem(emailRem, 'email_missing_spf');
    }
    if (!em.dmarc?.present) {
      emailScore -= 30;
      emailReasons.push('Missing DMARC policy — email spoofing is not prevented');
      pushRem(emailRem, 'email_missing_dmarc');
    } else if (em.dmarc.policy === 'none') {
      emailScore -= 10;
      emailReasons.push('DMARC policy is p=none (monitor-only) — spoofed mail is not rejected');
      pushRem(emailRem, 'email_dmarc_policy_none');
    }
    if (!em.dkim?.present) {
      emailReasons.push('DKIM could not be verified using common selectors; a custom selector may be in use');
    }
    emailScore = clamp(emailScore);
  }

  // ── 2. SSL & Certificates ────────────────────────────────────────────────────
  let sslScore   = 100;
  const sslReasons = [];
  const sslRem = [];

  if (ssl === null && sc.certificate_risks.risk_level === null) {
    sslScore = null;
  } else {
    if (ssl !== null) {
      if (!ssl.https_available) {
        sslScore -= 40;
        sslReasons.push('HTTPS is not available — all traffic is unencrypted');
        pushRem(sslRem, 'ssl_not_available');
      }
      // Only deduct for missing redirect when the chain was confirmed observable
      // and there is no enterprise edge contradiction (same guard as scoring engine)
      const redirectValidated = ssl.http_redirect_chain?.http_redirect_validated !== false;
      const enterpriseContradiction = ENTERPRISE_DOMAINS.has(sc.last_scanned_domain ?? '')
        && redirectValidated
        && !ssl.http_redirects_to_https
        && (report?.modules?.headers?.final_https !== false);
      if (!ssl.http_redirects_to_https && redirectValidated && !enterpriseContradiction) {
        sslScore -= 15;
        sslReasons.push('HTTP does not redirect to HTTPS — unencrypted access is possible');
        pushRem(sslRem, 'ssl_no_http_redirect');
      }
    }
    // Certificate expiry
    const daysLeft = sc.certificate_risks.days_until_expiry;
    if (daysLeft !== null) {
      if (daysLeft < 0) {
        sslScore -= 35;
        sslReasons.push('Certificate has expired');
        pushRem(sslRem, 'ssl_certificate_expired');
      } else if (daysLeft < 7) {
        sslScore -= 25;
        sslReasons.push(`Certificate expires in ${daysLeft} day${daysLeft !== 1 ? 's' : ''} — renewal is critical`);
        pushRem(sslRem, 'ssl_certificate_expiring_soon');
      } else if (daysLeft < 30) {
        sslScore -= 15;
        sslReasons.push(`Certificate expires in ${daysLeft} days — renew soon`);
        pushRem(sslRem, 'ssl_certificate_expiring_soon');
      }
    }
    // Certificate intelligence signals
    const certRisk = sc.certificate_risks.risk_level;
    if (certRisk === 'critical') {
      sslScore -= 20;
      sslReasons.push('Certificate intelligence: critical-risk signal detected');
      pushRem(sslRem, 'certificate_intelligence_review');
    } else if (certRisk === 'high') {
      sslScore -= 10;
      sslReasons.push('Certificate intelligence: high-risk signal detected');
      pushRem(sslRem, 'certificate_intelligence_review');
    }
    sslScore = clamp(sslScore);
  }

  // ── 3. Attack Surface ────────────────────────────────────────────────────────
  let asScore   = 100;
  const asReasons = [];
  const asRem = [];

  const brandHigh = sc.brand_risks.high   ?? 0;
  const brandMed  = sc.brand_risks.medium ?? 0;
  const newA30    = sc.new_assets_30d     ?? 0;
  const cloudN    = Array.isArray(report?.modules?.cloud_storage_discovery?.assets)
    ? report.modules.cloud_storage_discovery.assets.length : 0;

  if (brandHigh > 0) {
    const cut = clamp(brandHigh * 12, 0, 35);
    asScore -= cut;
    asReasons.push(`${brandHigh} high-risk brand impersonation domain${brandHigh !== 1 ? 's' : ''} actively resolving`);
    pushRem(asRem, 'brand_lookalike_detected');
  }
  if (brandMed > 0) {
    const cut = clamp(brandMed * 5, 0, 15);
    asScore -= cut;
    asReasons.push(`${brandMed} medium-risk typosquat domain${brandMed !== 1 ? 's' : ''} detected`);
    pushRem(asRem, 'brand_typosquat_detected');
  }
  if (newA30 > 0) {
    const cut = clamp(newA30 * 4, 0, 20);
    asScore -= cut;
    asReasons.push(`${newA30} new asset${newA30 !== 1 ? 's' : ''} discovered in the last 30 days — surface is expanding`);
    // Surface expansion is an observation, not a specific remediation — no
    // promoted action (fails honestly rather than inventing generic advice).
  }
  if (cloudN > 0) {
    asScore -= 10;
    asReasons.push(`${cloudN} cloud storage asset${cloudN !== 1 ? 's' : ''} exposed`);
    pushRem(asRem, 'cloud_storage_exposure_observed');
  }
  asScore = clamp(asScore);

  // ── 4. Third-Party Risk ──────────────────────────────────────────────────────
  let tpScore   = 100;
  const tpReasons = [];
  const tpRem = [];

  const vHigh = sc.vendor_risk.high   ?? 0;
  const vMed  = sc.vendor_risk.medium ?? 0;
  const tpa   = sc.third_party_assets ?? 0;
  const saas  = sc.saas_exposures     ?? 0;

  if (vHigh > 0) {
    const cut = clamp(vHigh * 15, 0, 40);
    tpScore -= cut;
    tpReasons.push(`${vHigh} high-risk vendor${vHigh !== 1 ? 's' : ''} in the supply chain`);
    pushRem(tpRem, 'vendor_risk_detected');
  }
  if (vMed > 0) {
    const cut = clamp(vMed * 5, 0, 20);
    tpScore -= cut;
    tpReasons.push(`${vMed} medium-risk vendor${vMed !== 1 ? 's' : ''} detected`);
    pushRem(tpRem, 'vendor_risk_detected');
  }
  if (tpa > 0) {
    const cut = clamp(tpa * 3, 0, 15);
    tpScore -= cut;
    tpReasons.push(`${tpa} third-party service${tpa !== 1 ? 's' : ''} with external data access`);
    pushRem(tpRem, 'third_party_js_detected');
  }
  if (saas > 0) {
    const cut = clamp(saas * 3, 0, 15);
    tpScore -= cut;
    tpReasons.push(`${saas} externally reachable SaaS portal${saas !== 1 ? 's' : ''}`);
    pushRem(tpRem, 'saas_exposure');
  }
  tpScore = clamp(tpScore);

  // ── 5. Admin Exposure ────────────────────────────────────────────────────────
  let admScore   = 100;
  const admReasons = [];
  const admRem = [];

  // adm.critical / adm.high come from admin_surface_detection module
  const admCritical = adm?.critical ?? 0;
  const admHigh     = adm?.high     ?? 0;
  const admOther    = (adm?.total ?? sc.admin_surfaces) - admCritical - admHigh;

  if (admCritical > 0) {
    const cut = clamp(admCritical * 20, 0, 60);
    admScore -= cut;
    admReasons.push(`${admCritical} critical admin surface${admCritical !== 1 ? 's' : ''} publicly exposed`);
    pushRem(admRem, 'admin_surface_critical');
  }
  if (admHigh > 0) {
    const cut = clamp(admHigh * 12, 0, 30);
    admScore -= cut;
    admReasons.push(`${admHigh} high-risk admin surface${admHigh !== 1 ? 's' : ''} publicly exposed`);
    pushRem(admRem, 'admin_surface_high');
  }
  if (admOther > 0) {
    const cut = clamp(admOther * 6, 0, 20);
    admScore -= cut;
    admReasons.push(`${admOther} other management interface${admOther !== 1 ? 's' : ''} exposed`);
    pushRem(admRem, 'asset_exposure_admin_interface');
  }
  admScore = clamp(admScore);

  // ── Weighted overall ─────────────────────────────────────────────────────────
  // If any category is null (no scan data) it is excluded from the weighted average.
  const categories = [
    { key: 'email_security',    label: 'Email Security',     score: emailScore, weight: 0.20 },
    { key: 'ssl_certificates',  label: 'SSL & Certificates', score: sslScore,   weight: 0.20 },
    { key: 'attack_surface',    label: 'Attack Surface',     score: asScore,    weight: 0.25 },
    { key: 'third_party_risk',  label: 'Third-Party Risk',   score: tpScore,    weight: 0.15 },
    { key: 'admin_exposure',    label: 'Admin Exposure',     score: admScore,   weight: 0.20 },
  ];

  const known = categories.filter(c => c.score !== null);
  const weightSum = known.reduce((s, c) => s + c.weight, 0);
  const overall = weightSum > 0
    ? Math.round(known.reduce((s, c) => s + c.score * (c.weight / weightSum), 0))
    : null;

  // Build per-category objects
  const result = { overall_score: overall };
  const reasonsMap = {
    email_security:   emailReasons,
    ssl_certificates: sslReasons,
    attack_surface:   asReasons,
    third_party_risk: tpReasons,
    admin_exposure:   admReasons,
  };
  const remMap = {
    email_security:   emailRem,
    ssl_certificates: sslRem,
    attack_surface:   asRem,
    third_party_risk: tpRem,
    admin_exposure:   admRem,
  };
  for (const { key, score } of categories) {
    const reasons = reasonsMap[key];
    result[key] = {
      score,
      status:  scoreStatus(score),
      reasons: reasons.length > 0 ? reasons : (score === null ? [] : ['No issues detected']),
      // Canonical remediation identities promoted from this category's risk
      // signals. Consumers (e.g. the Executive PDF) render these instead of
      // re-labelling a reason string or fabricating an "Improve X" action.
      remediations: remMap[key] ?? [],
    };
  }
  return result;
}
