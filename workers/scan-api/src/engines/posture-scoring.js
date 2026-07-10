// ── Security posture scoring / executive scorecard ──
// Score→status mapping, value clamping, and computeSecurityPosture (executive scorecard
// posture roll-up vs the enterprise benchmark). Extracted verbatim from index.js (monolith
// decomposition, Phase 1c). scoreStatus is module-internal.
import { ENTERPRISE_DOMAINS } from "./scoring-config.js";

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

  if (em === null) {
    emailScore = null;
  } else {
    if (!em.spf?.present) {
      emailScore -= 25;
      emailReasons.push('Missing SPF record — any server can send mail as this domain');
    }
    if (!em.dmarc?.present) {
      emailScore -= 30;
      emailReasons.push('Missing DMARC policy — email spoofing is not prevented');
    } else if (em.dmarc.policy === 'none') {
      emailScore -= 10;
      emailReasons.push('DMARC policy is p=none (monitor-only) — spoofed mail is not rejected');
    }
    if (!em.dkim?.present) {
      emailReasons.push('DKIM could not be verified using common selectors; a custom selector may be in use');
    }
    emailScore = clamp(emailScore);
  }

  // ── 2. SSL & Certificates ────────────────────────────────────────────────────
  let sslScore   = 100;
  const sslReasons = [];

  if (ssl === null && sc.certificate_risks.risk_level === null) {
    sslScore = null;
  } else {
    if (ssl !== null) {
      if (!ssl.https_available) {
        sslScore -= 40;
        sslReasons.push('HTTPS is not available — all traffic is unencrypted');
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
      }
    }
    // Certificate expiry
    const daysLeft = sc.certificate_risks.days_until_expiry;
    if (daysLeft !== null) {
      if (daysLeft < 0) {
        sslScore -= 35;
        sslReasons.push('Certificate has expired');
      } else if (daysLeft < 7) {
        sslScore -= 25;
        sslReasons.push(`Certificate expires in ${daysLeft} day${daysLeft !== 1 ? 's' : ''} — renewal is critical`);
      } else if (daysLeft < 30) {
        sslScore -= 15;
        sslReasons.push(`Certificate expires in ${daysLeft} days — renew soon`);
      }
    }
    // Certificate intelligence signals
    const certRisk = sc.certificate_risks.risk_level;
    if (certRisk === 'critical') {
      sslScore -= 20;
      sslReasons.push('Certificate intelligence: critical-risk signal detected');
    } else if (certRisk === 'high') {
      sslScore -= 10;
      sslReasons.push('Certificate intelligence: high-risk signal detected');
    }
    sslScore = clamp(sslScore);
  }

  // ── 3. Attack Surface ────────────────────────────────────────────────────────
  let asScore   = 100;
  const asReasons = [];

  const brandHigh = sc.brand_risks.high   ?? 0;
  const brandMed  = sc.brand_risks.medium ?? 0;
  const newA30    = sc.new_assets_30d     ?? 0;
  const cloudN    = Array.isArray(report?.modules?.cloud_storage_discovery?.assets)
    ? report.modules.cloud_storage_discovery.assets.length : 0;

  if (brandHigh > 0) {
    const cut = clamp(brandHigh * 12, 0, 35);
    asScore -= cut;
    asReasons.push(`${brandHigh} high-risk brand impersonation domain${brandHigh !== 1 ? 's' : ''} actively resolving`);
  }
  if (brandMed > 0) {
    const cut = clamp(brandMed * 5, 0, 15);
    asScore -= cut;
    asReasons.push(`${brandMed} medium-risk typosquat domain${brandMed !== 1 ? 's' : ''} detected`);
  }
  if (newA30 > 0) {
    const cut = clamp(newA30 * 4, 0, 20);
    asScore -= cut;
    asReasons.push(`${newA30} new asset${newA30 !== 1 ? 's' : ''} discovered in the last 30 days — surface is expanding`);
  }
  if (cloudN > 0) {
    asScore -= 10;
    asReasons.push(`${cloudN} cloud storage asset${cloudN !== 1 ? 's' : ''} exposed`);
  }
  asScore = clamp(asScore);

  // ── 4. Third-Party Risk ──────────────────────────────────────────────────────
  let tpScore   = 100;
  const tpReasons = [];

  const vHigh = sc.vendor_risk.high   ?? 0;
  const vMed  = sc.vendor_risk.medium ?? 0;
  const tpa   = sc.third_party_assets ?? 0;
  const saas  = sc.saas_exposures     ?? 0;

  if (vHigh > 0) {
    const cut = clamp(vHigh * 15, 0, 40);
    tpScore -= cut;
    tpReasons.push(`${vHigh} high-risk vendor${vHigh !== 1 ? 's' : ''} in the supply chain`);
  }
  if (vMed > 0) {
    const cut = clamp(vMed * 5, 0, 20);
    tpScore -= cut;
    tpReasons.push(`${vMed} medium-risk vendor${vMed !== 1 ? 's' : ''} detected`);
  }
  if (tpa > 0) {
    const cut = clamp(tpa * 3, 0, 15);
    tpScore -= cut;
    tpReasons.push(`${tpa} third-party service${tpa !== 1 ? 's' : ''} with external data access`);
  }
  if (saas > 0) {
    const cut = clamp(saas * 3, 0, 15);
    tpScore -= cut;
    tpReasons.push(`${saas} externally reachable SaaS portal${saas !== 1 ? 's' : ''}`);
  }
  tpScore = clamp(tpScore);

  // ── 5. Admin Exposure ────────────────────────────────────────────────────────
  let admScore   = 100;
  const admReasons = [];

  // adm.critical / adm.high come from admin_surface_detection module
  const admCritical = adm?.critical ?? 0;
  const admHigh     = adm?.high     ?? 0;
  const admOther    = (adm?.total ?? sc.admin_surfaces) - admCritical - admHigh;

  if (admCritical > 0) {
    const cut = clamp(admCritical * 20, 0, 60);
    admScore -= cut;
    admReasons.push(`${admCritical} critical admin surface${admCritical !== 1 ? 's' : ''} publicly exposed`);
  }
  if (admHigh > 0) {
    const cut = clamp(admHigh * 12, 0, 30);
    admScore -= cut;
    admReasons.push(`${admHigh} high-risk admin surface${admHigh !== 1 ? 's' : ''} publicly exposed`);
  }
  if (admOther > 0) {
    const cut = clamp(admOther * 6, 0, 20);
    admScore -= cut;
    admReasons.push(`${admOther} other management interface${admOther !== 1 ? 's' : ''} exposed`);
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
  for (const { key, score } of categories) {
    const reasons = reasonsMap[key];
    result[key] = {
      score,
      status:  scoreStatus(score),
      reasons: reasons.length > 0 ? reasons : (score === null ? [] : ['No issues detected']),
    };
  }
  return result;
}
