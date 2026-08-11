// ── Executive security scorecard data ──
// Assembles the workspace executive scorecard from the latest scan report + module-level
// R2 data (posture, exposure, certs, third-party, supply-chain). Extracted verbatim from
// index.js (monolith decomposition, Phase 1c).
import { computeSecurityPosture } from "./posture-scoring.js";
import { getCurrentPosturePresentation } from "./current-posture.js";
import { resolveCyberMotDomainStates } from "./cyber-mot-domains.js";
import { canSayHealthy, domainState, neutralSummary, scorecardBehaviour, sectionStatus } from "./scorecard-domain-state.js";
import { resolvePhase5HistoricalCustomerProjection } from "./phase5-evidence.js";
import { suppressedLegacyTlsRemediationSql, visibleFindingSql } from "./finding-identity.js";
import {
  projectTlsRecommendationsForCustomer,
  projectTlsReportForCustomer,
} from "./tls-evidence.js";
import {
  loadAssetLifecycleEventSupport,
  summariseLifecycleClaimProjection,
} from "./asset-lifecycle-event-support.js";

const CERTIFICATE_RISK_SEVERITIES = new Set(["critical", "high", "medium"]);

export function isCertificateRiskSignal(signal) {
  return Boolean(signal && typeof signal === "object" &&
    CERTIFICATE_RISK_SEVERITIES.has(signal.severity));
}

function isCertificateInformationalObservation(signal) {
  return Boolean(signal && typeof signal === "object" && signal.severity === "info");
}

export function buildCertificateRiskFields(signals, riskLevel, daysUntilExpiry) {
  const allSignals = Array.isArray(signals) ? signals : [];
  const riskSignals = allSignals.filter(isCertificateRiskSignal);
  const informationalObservations = allSignals.filter(isCertificateInformationalObservation);
  return {
    risk_level: riskLevel,
    signals: allSignals.length,
    days_until_expiry: daysUntilExpiry,
    risk_signal_count: riskSignals.length,
    risk_signals: riskSignals,
    informational_observation_count: informationalObservations.length,
    informational_observations: informationalObservations,
  };
}

function certificateSignalPreview(signals) {
  return signals
    .slice(0, 2)
    .map((signal) => signal.description || signal.signal || "certificate signal")
    .join(", ");
}

function certificateInformationSummary(observations, { includePreview = false } = {}) {
  const count = observations.length;
  const preview = includePreview ? certificateSignalPreview(observations) : "";
  return `Certificate intelligence recorded ${count} neutral informational observation${count !== 1 ? "s" : ""}` +
    (preview ? `: ${preview}.` : ".");
}

/**
 * buildScorecardData(wsId, env)
 *
 * Returns the full scorecard object for the workspace, or null on DB error.
 * Uses:
 *   - D1 batch 1  — workspace meta, asset / vendor / brand counts
 *   - D1 batch 2  — findings severity + top remediation (needs scan_id)
 *   - R2 (1 get)  — module-level data (saas_exposure, admin_surface_detection,
 *                    certificate_intelligence, third_party_assets, cloud assets)
 */
// ── scanScope — WHOSE scan may supply this workspace's evidence ─────────────
// "linked_domains" (default, unchanged): the newest completed scan of any domain
//   this workspace links, whoever ran it. workspace_domains is PK (workspace_id,
//   domain_id), so one domain may be linked by several workspaces — an MSP and its
//   client both owning acme.com is a supported configuration. For a computed
//   posture VIEW of a domain both parties verifiably own, sharing the newest scan
//   is defensible: it is external observation of their own domain.
//
// "workspace": only scans this workspace itself ran (scans.workspace_id). Required
//   wherever evidence becomes an ATTRIBUTED CLAIM rather than a view — persisted
//   lifecycle state, or anything that emails a customer. Cyber Essentials passes
//   this, because "your readiness fell" must be graded from evidence the customer
//   actually owns, on a clock they control; an MSP scanning hourly must not decide
//   what its client is told about itself.
//
//   Legacy scans predating migration 021 carry workspace_id NULL. Under this scope
//   they belong to nobody and are excluded — the honest result, since they cannot
//   be attributed to a tenant at all. Callers must treat "no evidence" as unknown,
//   never as a pass (see buildCyberEssentialsReadiness' not_assessed return).
export async function buildScorecardData(wsId, env, { scanScope = "linked_domains" } = {}) {
  const scanScopePredicate = scanScope === "workspace"
    ? "AND s.workspace_id = ?"
    : "";
  const now30dAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();

  // ── D1 Batch 1 ─────────────────────────────────────────────────────────────
  let b1;
  try {
    b1 = await env.cybermeters_db.batch([
      // 0. Latest completed scan
      env.cybermeters_db.prepare(
        `SELECT s.id, s.score, s.rating, s.scan_quality, s.domain, s.created_at
         FROM workspace_domains wd
         JOIN domains d ON d.id = wd.domain_id
         JOIN scans   s ON s.domain_id = d.id
         WHERE wd.workspace_id = ? AND s.status = 'completed'
         ${scanScopePredicate}
         ORDER BY s.created_at DESC LIMIT 1`
      ).bind(...(scanScope === "workspace" ? [wsId, wsId] : [wsId])),

      // 1. Workspace name
      env.cybermeters_db.prepare(
        `SELECT name FROM workspaces WHERE id = ?`
      ).bind(wsId),

      // 2. Active asset count
      env.cybermeters_db.prepare(
        `SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND status = 'active'`
      ).bind(wsId),

      // 3. Asset type breakdown (admin_panel, cloud_storage, etc.)
      env.cybermeters_db.prepare(
        `SELECT asset_type, COUNT(*) AS n FROM workspace_assets
         WHERE workspace_id = ? AND status = 'active' GROUP BY asset_type`
      ).bind(wsId),

      // 4. Active vendor count
      env.cybermeters_db.prepare(
        `SELECT COUNT(*) AS n FROM workspace_vendors WHERE workspace_id = ? AND status = 'active'`
      ).bind(wsId),

      // 5. Vendor risk breakdown
      env.cybermeters_db.prepare(
        `SELECT risk_level, COUNT(*) AS n FROM workspace_vendors
         WHERE workspace_id = ? AND status = 'active'
           AND risk_level IS NOT NULL
           AND COALESCE(source_module, '') != 'identity_discovery'
         GROUP BY risk_level`
      ).bind(wsId),

      // 6. Active brand risks (DNS-confirmed typosquats, status='active')
      env.cybermeters_db.prepare(
        `SELECT risk_level, COUNT(*) AS n FROM workspace_brand_assets
         WHERE workspace_id = ? AND status = 'active' GROUP BY risk_level`
      ).bind(wsId),

      // 7. Total brand candidates (any status)
      env.cybermeters_db.prepare(
        `SELECT COUNT(*) AS n FROM workspace_brand_assets WHERE workspace_id = ?`
      ).bind(wsId),

      // 8. Asset events in last 30 days
      env.cybermeters_db.prepare(
        `SELECT COUNT(*) AS n FROM asset_events WHERE workspace_id = ? AND created_at >= ?`
      ).bind(wsId, now30dAgo),

      // 9. New assets discovered in last 30 days (first_seen)
      env.cybermeters_db.prepare(
        `SELECT COUNT(*) AS n FROM workspace_assets
         WHERE workspace_id = ? AND first_seen >= ?`
      ).bind(wsId, now30dAgo),

      // 10. Total domains in workspace
      env.cybermeters_db.prepare(
        `SELECT COUNT(*) AS n FROM workspace_domains WHERE workspace_id = ?`
      ).bind(wsId),

      // 11. Bounded event universe for the additive P4 read projection.
      env.cybermeters_db.prepare(
        `SELECT id, workspace_id, domain_id, asset_id, scan_id, event_type,
                hostname, severity, description, created_at
         FROM asset_events
         WHERE workspace_id = ? AND created_at >= ?
         ORDER BY created_at DESC, id DESC LIMIT 2001`
      ).bind(wsId, now30dAgo),
    ]);
  } catch {
    return null;
  }

  const latestScan     = b1[0].results?.[0]  ?? null;
  // Canonical current posture — authoritative score/rating come ONLY from the latest
  // COMPLETE scan; a provisional latest never establishes the rating.
  const posture        = await getCurrentPosturePresentation(env, { workspaceId: wsId });
  const wsName         = b1[1].results?.[0]?.name ?? 'Unknown';
  const activeAssets   = b1[2].results?.[0]?.n    ?? 0;
  const assetTypeRows  = b1[3].results ?? [];
  const vendorsActive  = b1[4].results?.[0]?.n ?? 0;
  const vendorRiskRows = b1[5].results ?? [];
  const brandRiskRows  = b1[6].results ?? [];
  const brandTotal     = b1[7].results?.[0]?.n ?? 0;
  const events30d      = b1[8].results?.[0]?.n ?? 0;
  const newAssets30d   = b1[9].results?.[0]?.n ?? 0;
  const totalDomains   = b1[10].results?.[0]?.n ?? 0;
  const eventProjectionRows = b1[11].results ?? [];
  const eventProjection = await loadAssetLifecycleEventSupport(env, {
    workspaceId: wsId,
    events: eventProjectionRows,
    collectionLimit: 2000,
    scope: "scorecard_asset_events_30d",
  });
  const eventProjectionSummary = summariseLifecycleClaimProjection(
    eventProjectionRows,
    eventProjection,
  );
  const customerEvents30d = eventProjectionSummary.coverage === "complete"
    ? eventProjectionSummary.customer_change_count
    : null;

  // ── D1 Batch 2: scan-specific data ────────────────────────────────────────
  const scanId = latestScan?.id ?? null;
  let criticalFindings = 0, highFindings = 0, mediumFindings = 0, lowFindings = 0;
  let topRemediation   = [];

  if (scanId) {
    try {
      const b2 = await env.cybermeters_db.batch([
        env.cybermeters_db.prepare(
          `SELECT f.severity, COUNT(*) AS n
           FROM findings f JOIN scans s ON s.id = f.scan_id
           WHERE f.scan_id = ? AND ${visibleFindingSql("f", "s")}
           GROUP BY f.severity`
        ).bind(scanId),
        env.cybermeters_db.prepare(
          `SELECT title, priority, action FROM remediation_items
           WHERE scan_id = ? AND NOT ${suppressedLegacyTlsRemediationSql("remediation_items")}
           ORDER BY priority ASC LIMIT 5`
        ).bind(scanId),
      ]);
      const sevMap = Object.fromEntries((b2[0].results ?? []).map(r => [r.severity, r.n]));
      criticalFindings = sevMap.critical ?? 0;
      highFindings     = sevMap.high     ?? 0;
      mediumFindings   = sevMap.medium   ?? 0;
      lowFindings      = sevMap.low      ?? 0;
      topRemediation   = (b2[1].results ?? []).map(r => ({
        title:       r.title,
        priority:    Number(r.priority),
        description: r.action,
      }));
    } catch { /* non-fatal — findings unavailable */ }
  }
  // ── R2: latest scan report for module-level data (1 subrequest) ───────────
  let report = null;
  if (scanId) {
    try {
      const obj = await env.cybermeters_reports.get(`reports/${scanId}.json`);
      if (obj) report = projectTlsReportForCustomer(await obj.json());
    } catch { /* tolerate missing report */ }
  }
  topRemediation = projectTlsRecommendationsForCustomer(
    topRemediation,
    report?.modules ?? {},
  );

  // Derived values from R2 modules
  const saasTotal      = report?.modules?.saas_exposure?.total ?? 0;
  const adminTotal     = report?.modules?.admin_surface_detection?.total ?? 0;
  const certRiskLevel  = report?.modules?.certificate_intelligence?.certificate_risk_level ?? null;
  const certSignals    = Array.isArray(report?.modules?.certificate_intelligence?.suspicious_certificate_signals)
    ? report.modules.certificate_intelligence.suspicious_certificate_signals
    : [];
  const certDaysLeft   = report?.modules?.certificate_intelligence?.days_until_expiry ?? null;
  const certificateRiskFields = buildCertificateRiskFields(
    certSignals,
    certRiskLevel,
    certDaysLeft,
  );
  const riskSignals = certificateRiskFields.risk_signals;
  const informationalObservations = certificateRiskFields.informational_observations;
  const ctSourcesUnavailable = informationalObservations.some(
    (signal) => signal.signal === "ct_sources_unavailable",
  );
  const tpaTotal       = report?.modules?.third_party_assets?.total ?? 0;
  const cloudAssetList = report?.modules?.cloud_storage_discovery?.assets ?? [];
  const phase5Assessment = resolvePhase5HistoricalCustomerProjection({
    score: latestScan?.score,
    riskLevel: latestScan?.rating,
    scanQuality: latestScan?.scan_quality,
    modules: report?.modules ?? {},
  });

  // Computed helpers
  const assetTypeMap  = Object.fromEntries(assetTypeRows.map(r => [r.asset_type, r.n]));
  const vendorRiskMap = Object.fromEntries(vendorRiskRows.map(r => [r.risk_level, r.n]));
  const brandRiskMap  = Object.fromEntries(brandRiskRows.map(r => [r.risk_level, r.n]));
  const brandHighRisk = brandRiskMap.high   ?? 0;
  const brandMedRisk  = brandRiskMap.medium ?? 0;
  const activeBrands  = brandHighRisk + brandMedRisk + (brandRiskMap.low ?? 0);

  // ── Executive Summary ──────────────────────────────────────────────────────
  const good              = [];
  const attentionRequired = [];
  const urgent            = [];

  // B canonicalisation: reassuring "healthy / none detected / looks normal" wording
  // is now gated on the canonical Cyber MOT domain state (already resolved from the
  // report) and the A3 admin evidence_status — an empty raw count / null / failed
  // query can never by itself produce a positive verdict.
  const cyberMotStates = Array.isArray(report?.cyber_mot_domains)
    ? report.cyber_mot_domains
    : resolveCyberMotDomainStates(report);
  const adminEvidence = report?.modules?.admin_surface_detection?.evidence_status ?? null;
  const brandStateB = domainState(cyberMotStates, "brand_protection");
  const certStateB  = domainState(cyberMotStates, "certificates_trust");
  const asStateB    = domainState(cyberMotStates, "attack_surface");
  const shadowStateB = domainState(cyberMotStates, "shadow_it_unmanaged_technology");
  // A non-healthy, non-issue domain gets a neutral "could not assess / not yet
  // assessed" line (never a reassuring one, never silent healthy).
  const noteNeutral = (behaviour, subject) => {
    if (behaviour === "unavailable" || behaviour === "not_assessed") {
      attentionRequired.push(neutralSummary(behaviour === "unavailable" ? "unavailable" : "not_yet_assessed", subject));
    }
  };

  // ── Good signals ──────────────────────────────────────────────────────────
  if (activeAssets > 0) {
    good.push(
      `Asset inventory is active — ${activeAssets} asset${activeAssets !== 1 ? 's' : ''} monitored across ${totalDomains} domain${totalDomains !== 1 ? 's' : ''}.`
    );
  }
  if (!cloudAssetList.length && !assetTypeMap['cloud_storage']) {
    if (canSayHealthy(asStateB)) good.push('No cloud storage exposure was detected.');
    else noteNeutral(scorecardBehaviour(asStateB), 'Cloud storage exposure');
  }
  if (vendorsActive > 0) {
    good.push(
      `Vendor dependencies are visible — ${vendorsActive} third-party vendor${vendorsActive !== 1 ? 's' : ''} detected.`
    );
  }
  if (criticalFindings === 0 && highFindings === 0) {
    if (phase5Assessment.evidence.complete) {
      good.push('No critical or high-severity findings in the latest scan.');
    } else {
      attentionRequired.push(phase5Assessment.assessment?.message);
    }
  }
  if (brandHighRisk === 0 && activeBrands === 0) {
    if (canSayHealthy(brandStateB)) good.push('No active brand impersonation domains detected.');
    else noteNeutral(scorecardBehaviour(brandStateB), 'Brand impersonation');
  }
  if (adminTotal === 0) {
    if (adminEvidence === 'assessed_healthy') good.push('No exposed admin or management surfaces detected.');
    else noteNeutral(adminEvidence, 'Admin surface exposure');   // unavailable/not_assessed → neutral; null (legacy) → silent, never "none detected"
  }
  if (canSayHealthy(certStateB) && !ctSourcesUnavailable &&
      riskSignals.length === 0 && informationalObservations.length === 0) {
    good.push('Certificate health looks normal — no suspicious signals detected.');
  } else if (!canSayHealthy(certStateB) || ctSourcesUnavailable) {
    noteNeutral(scorecardBehaviour(certStateB), 'Certificate health');   // null/unavailable/not_assessed → neutral, never "looks normal"; issue handled by the urgent line
  }

  // ── Attention Required ────────────────────────────────────────────────────
  if (customerEvents30d > 0) {
    attentionRequired.push(
      `Attack surface changed in the last 30 days — ${customerEvents30d} supported lifecycle or other asset event${customerEvents30d !== 1 ? 's' : ''} recorded.`
    );
  } else if (customerEvents30d === null) {
    attentionRequired.push('Support for historical attack-surface lifecycle records was not evaluated completely.');
  }
  if (newAssets30d > 0) {
    attentionRequired.push(
      `${newAssets30d} new asset${newAssets30d !== 1 ? 's' : ''} discovered in the last 30 days.`
    );
  }
  if (tpaTotal > 0) {
    attentionRequired.push(
      `${tpaTotal} third-party service${tpaTotal !== 1 ? 's' : ''} in use — email, support, or marketing tools with external data access.`
    );
  }
  if (riskSignals.length > 0 && certRiskLevel !== 'critical') {
    const sigPreview = certificateSignalPreview(riskSignals);
    attentionRequired.push(
      `Certificate intelligence flagged ${riskSignals.length} suspicious signal${riskSignals.length !== 1 ? 's' : ''}: ${sigPreview}.`
    );
  }
  if (informationalObservations.length > 0) {
    attentionRequired.push(certificateInformationSummary(
      informationalObservations,
      { includePreview: true },
    ));
  }
  if (saasTotal > 0) {
    attentionRequired.push(
      `${saasTotal} SaaS portal${saasTotal !== 1 ? 's' : ''} exposed — login or admin access may be reachable externally.`
    );
  }
  if ((vendorRiskMap.medium ?? 0) > 0) {
    attentionRequired.push(
      `${vendorRiskMap.medium} medium-risk vendor${(vendorRiskMap.medium ?? 0) !== 1 ? 's' : ''} detected in the supply chain.`
    );
  }
  if (brandMedRisk > 0 && brandHighRisk === 0) {
    attentionRequired.push(
      `${brandMedRisk} medium-risk typosquat domain${brandMedRisk !== 1 ? 's' : ''} found actively resolving.`
    );
  }

  // ── Urgent ────────────────────────────────────────────────────────────────
  if (criticalFindings > 0) {
    urgent.push(
      `${criticalFindings} critical finding${criticalFindings !== 1 ? 's' : ''} require immediate remediation.`
    );
  }
  if (highFindings > 0) {
    urgent.push(
      `${highFindings} high-severity finding${highFindings !== 1 ? 's' : ''} should be addressed soon.`
    );
  }
  if (brandHighRisk > 0) {
    urgent.push(
      `${brandHighRisk} high-risk brand impersonation domain${brandHighRisk !== 1 ? 's' : ''} ${brandHighRisk === 1 ? 'is' : 'are'} actively resolving — phishing risk.`
    );
  }
  if (adminTotal > 0) {
    urgent.push(
      `${adminTotal} admin surface${adminTotal !== 1 ? 's' : ''} exposed to the internet — management interfaces should not be publicly accessible.`
    );
  }
  if ((vendorRiskMap.high ?? 0) > 0) {
    urgent.push(
      `${vendorRiskMap.high} high-risk vendor${(vendorRiskMap.high ?? 0) !== 1 ? 's' : ''} detected — supply chain exposure requires review.`
    );
  }
  if (certRiskLevel === 'critical') {
    const certDetail = certDaysLeft !== null
      ? `expires in ${certDaysLeft} day${certDaysLeft !== 1 ? 's' : ''}`
      : 'suspicious signals detected';
    urgent.push(`Certificate is at critical risk — ${certDetail}.`);
  }

  // ── Security Posture Breakdown ────────────────────────────────────────────
  const security_posture = computeSecurityPosture(
    // Pass a partial scorecard-like object — only the fields computeSecurityPosture reads
    {
      last_scanned_domain: latestScan?.domain ?? null,
      new_assets_30d:      newAssets30d,
      vendor_risk:         { high: vendorRiskMap.high ?? 0, medium: vendorRiskMap.medium ?? 0, low: vendorRiskMap.low ?? 0 },
      third_party_assets:  tpaTotal,
      saas_exposures:      saasTotal,
      admin_surfaces:      adminTotal,
      brand_risks:         { high: brandHighRisk, medium: brandMedRisk, low: brandRiskMap.low ?? 0 },
      certificate_risks:   certificateRiskFields,
    },
    report
  );
  const cyber_mot_domains = cyberMotStates;   // resolved once above (B), reused here

  // ── Final scorecard object ─────────────────────────────────────────────────
  return {
    workspace_id:        wsId,
    workspace_name:      wsName,
    security_score:      posture.authoritative?.display_score  ?? null,
    risk_rating:         posture.authoritative?.display_rating ?? 'unknown',
    current_posture:     posture,
    last_scan_at:        latestScan?.created_at ?? null,
    last_scanned_domain: latestScan?.domain     ?? null,
    attack_surface_size: activeAssets,
    active_assets:       activeAssets,
    new_assets_30d:      newAssets30d,
    vendors_detected:    vendorsActive,
    vendor_risk: {
      high:   vendorRiskMap.high   ?? 0,
      medium: vendorRiskMap.medium ?? 0,
      low:    vendorRiskMap.low    ?? 0,
    },
    third_party_assets: tpaTotal,
    saas_exposures:     saasTotal,
    admin_surfaces:     adminTotal,
    admin_surface_evidence_status: adminEvidence,   // B: additive — canonical A3 admin state for wording
    brand_risks: {
      total:  brandTotal,
      active: activeBrands,
      high:   brandHighRisk,
      medium: brandMedRisk,
      low:    brandRiskMap.low ?? 0,
    },
    certificate_risks: certificateRiskFields,
    critical_findings: criticalFindings,
    high_findings:     highFindings,
    medium_findings:   mediumFindings,
    low_findings:      lowFindings,
    asset_events_30d:  events30d,
    customer_asset_events_30d: customerEvents30d,
    lifecycle_claim_projection_30d: eventProjectionSummary,
    executive_summary: {
      good,
      attention_required: attentionRequired,
      urgent,
    },
    top_recommendations: topRemediation,
    security_posture,
    cyber_mot_domains,
  };
}

// ── B: /scorecard/report sections, built from the scorecard payload ──────────
// Moved out of the route so the sections and the executive_summary share ONE state
// mapping and the route never re-derives health from raw counts. Brand /
// Certificates / Shadow-IT / Admin wording is gated on canonical Cyber MOT state
// (+ the A3 admin evidence_status) — an empty count / null / failed query can never
// by itself produce a healthy "none detected" / "looks normal".
export function buildScorecardSections(scorecard) {
  const cmd = scorecard.cyber_mot_domains;
  const brandState  = domainState(cmd, "brand_protection");
  const certState   = domainState(cmd, "certificates_trust");
  const shadowState = domainState(cmd, "shadow_it_unmanaged_technology");
  const adminEv     = scorecard.admin_surface_evidence_status ?? null;
  const hasCertificateRisksObject = Boolean(
    scorecard.certificate_risks &&
    typeof scorecard.certificate_risks === "object" &&
    !Array.isArray(scorecard.certificate_risks),
  );
  const cr = scorecard.certificate_risks || {};
  const riskSignalsValid = Array.isArray(cr.risk_signals) &&
    cr.risk_signals.every(isCertificateRiskSignal);
  const informationalObservationsValid = Array.isArray(cr.informational_observations) &&
    cr.informational_observations.every(isCertificateInformationalObservation);
  const riskSigs = riskSignalsValid
    ? cr.risk_signals
    : [];
  const infoObs = informationalObservationsValid
    ? cr.informational_observations
    : [];
  const riskCount = riskSigs.length;
  const infoCount = infoObs.length;
  const classificationsRecorded = riskSignalsValid && informationalObservationsValid;
  const classificationsMalformed =
    (Object.hasOwn(cr, "risk_signals") && !riskSignalsValid) ||
    (Object.hasOwn(cr, "informational_observations") && !informationalObservationsValid);
  const ctSourcesUnavailable = infoObs.some(
    (signal) => signal.signal === "ct_sources_unavailable",
  );
  const certificateFallbackStatus = ctSourcesUnavailable || classificationsMalformed ||
      !hasCertificateRisksObject
    ? "unknown"
    : sectionStatus(certState, 'warning');
  const certificateFallbackSummary = ctSourcesUnavailable || classificationsMalformed ||
      !hasCertificateRisksObject
    ? neutralSummary("unavailable", "Certificate health")
    : !classificationsRecorded && canSayHealthy(certState)
      ? "Certificate signal classification was not recorded for this historical scorecard."
    : neutralSummary(
        scorecardBehaviour(certState) === 'unavailable' ? 'unavailable' : 'not_yet_assessed',
        'Certificate health',
      );

  return [
    {
      title:   'Asset Inventory',
      status:  scorecard.active_assets === 0 ? 'unknown'
             : scorecard.new_assets_30d > 0  ? 'warning' : 'ok',
      summary: scorecard.active_assets > 0
        ? `${scorecard.active_assets} active assets monitored.` +
          (scorecard.new_assets_30d > 0 ? ` ${scorecard.new_assets_30d} new in the last 30 days.` : ' No new assets in the last 30 days.')
        : 'No assets have been inventoried yet. Run a scan to begin discovery.',
      data: { active_assets: scorecard.active_assets, new_assets_30d: scorecard.new_assets_30d, asset_events_30d: scorecard.asset_events_30d },
    },
    {
      title:   'Vendor Risk',
      status:  scorecard.vendor_risk.high > 0 ? 'critical' : scorecard.vendor_risk.medium > 0 ? 'warning' : 'ok',
      summary: scorecard.vendors_detected > 0
        ? `${scorecard.vendors_detected} vendor${scorecard.vendors_detected !== 1 ? 's' : ''} detected.` +
          (scorecard.vendor_risk.high > 0 ? ` ${scorecard.vendor_risk.high} high-risk.` : ' No high-risk vendors.')
        : 'No third-party vendors detected in this scan.',
      data: { total: scorecard.vendors_detected, ...scorecard.vendor_risk },
    },
    {
      title:   'Third-Party Assets',
      status:  scorecard.third_party_assets > 0 ? 'warning' : sectionStatus(shadowState, 'warning'),
      summary: scorecard.third_party_assets > 0
        ? `${scorecard.third_party_assets} third-party SaaS service${scorecard.third_party_assets !== 1 ? 's' : ''} in use (email, CRM, support, marketing).`
        : canSayHealthy(shadowState) ? 'No third-party SaaS dependencies detected.'
          : neutralSummary(scorecardBehaviour(shadowState) === 'unavailable' ? 'unavailable' : 'not_yet_assessed', 'Unmanaged / shadow-IT technology'),
      data: { count: scorecard.third_party_assets },
    },
    {
      title:   'SaaS Exposure',
      status:  scorecard.saas_exposures > 0 ? 'warning' : sectionStatus(shadowState, 'warning'),
      summary: scorecard.saas_exposures > 0
        ? `${scorecard.saas_exposures} exposed SaaS portal${scorecard.saas_exposures !== 1 ? 's' : ''} or login surface${scorecard.saas_exposures !== 1 ? 's' : ''} detected.`
        : canSayHealthy(shadowState) ? 'No externally exposed SaaS portals detected.'
          : neutralSummary(scorecardBehaviour(shadowState) === 'unavailable' ? 'unavailable' : 'not_yet_assessed', 'Externally exposed SaaS'),
      data: { count: scorecard.saas_exposures },
    },
    {
      title:   'Admin Surfaces',
      status:  scorecard.admin_surfaces > 0 ? 'critical' : sectionStatus(adminEv, 'critical'),
      summary: scorecard.admin_surfaces > 0
        ? `${scorecard.admin_surfaces} admin or management interface${scorecard.admin_surfaces !== 1 ? 's' : ''} publicly exposed.`
        : adminEv === 'assessed_healthy' ? 'No exposed admin surfaces detected.'
          : adminEv === 'unavailable' ? 'Admin surface exposure could not be assessed in the latest scan — evidence was unavailable.'
          : 'Admin surface exposure has not been assessed yet.',
      data: { count: scorecard.admin_surfaces, evidence_status: adminEv },
    },
    {
      title:   'Brand Monitoring',
      status:  scorecard.brand_risks.high > 0 ? 'critical'
             : scorecard.brand_risks.active > 0 ? 'warning' : sectionStatus(brandState, 'warning'),
      summary: scorecard.brand_risks.active > 0
        ? `${scorecard.brand_risks.active} active typosquat domain${scorecard.brand_risks.active !== 1 ? 's' : ''} detected.` +
          (scorecard.brand_risks.high > 0 ? ` ${scorecard.brand_risks.high} high-risk.` : '')
        : canSayHealthy(brandState) ? `${scorecard.brand_risks.total} candidate domain${scorecard.brand_risks.total !== 1 ? 's' : ''} generated — none currently resolving.`
          : neutralSummary(scorecardBehaviour(brandState) === 'unavailable' ? 'unavailable' : 'not_yet_assessed', 'Brand impersonation'),
      data: scorecard.brand_risks,
    },
    {
      title:   'Certificate Intelligence',
      status:  cr.risk_level === 'critical' ? 'critical'
             : cr.risk_level === 'high' ? 'warning'
             : riskCount > 0 ? 'warning'
             : certificateFallbackStatus,
      summary: riskCount > 0 || cr.risk_level === 'critical' || cr.risk_level === 'high'
        ? `Certificate risk is ${cr.risk_level || 'elevated'}.` +
          (riskCount > 0 ? ` ${riskCount} suspicious signal${riskCount !== 1 ? 's' : ''} detected.` : '')
        : infoCount > 0 && canSayHealthy(certState) && !ctSourcesUnavailable
          ? certificateInformationSummary(infoObs)
        : classificationsRecorded && canSayHealthy(certState) && !ctSourcesUnavailable
          ? 'Certificate health looks normal — no suspicious signals detected.'
        : certificateFallbackSummary,
      data: scorecard.certificate_risks,
    },
    {
      title:   'Security Findings',
      status:  scorecard.critical_findings > 0 ? 'critical' : scorecard.high_findings > 0 ? 'warning' : 'ok',
      summary: (scorecard.critical_findings + scorecard.high_findings) === 0
        ? `No critical or high findings.` +
          (scorecard.medium_findings + scorecard.low_findings > 0 ? ` ${scorecard.medium_findings + scorecard.low_findings} lower-severity finding${(scorecard.medium_findings + scorecard.low_findings) !== 1 ? 's' : ''} noted.` : ' Clean scan.')
        : `${scorecard.critical_findings} critical, ${scorecard.high_findings} high, ${scorecard.medium_findings} medium, ${scorecard.low_findings} low findings.`,
      data: { critical: scorecard.critical_findings, high: scorecard.high_findings, medium: scorecard.medium_findings, low: scorecard.low_findings },
    },
  ];
}
