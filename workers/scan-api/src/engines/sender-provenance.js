// ── Inbound RUA sender provenance ──
// Forged-report hardening + DMARC sender intelligence: DMARC report remediation actions,
// business-risk from sender stats, CyberMeters-RUA-present detection, and the BEC exposure +
// sender-intelligence evidence loaders (email modules + brand candidates). Extracted verbatim
// from index.js (monolith decomposition, Phase 1c). loadLatestDomainEmailModules +
// loadBecBrandEvidence are module-internal.
import { RUA_INBOUND_DOMAIN_DEFAULT } from "../lib/dmarc-ingest.js";
import {
  DMARC_AUTHORITY_EVIDENCE_SCOPE,
  dmarcAuthoritySourceSql,
} from "../lib/dmarc-authority.js";
import { brandCandidateToApi, loadWorkspaceBrandProfile } from "./brand-protection.js";
import { remediationAction } from "./email-analysis.js";
import { buildDmarcEnforcementReadiness, summarizeEmailSenders } from "./rua-routing.js";

// ── Inbound RUA sender provenance (forged-report hardening) ───────────────────
//
// The inbound aggregate-report handler enforces enforceDomainMatch (the XML's
// policy_published.domain must equal the endpoint's domain). Because the opaque
// RUA address lives in the customer's PUBLIC DMARC record, an attacker can email
// a forged-but-well-formed report whose XML sets the domain to match. Cloudflare
// Email Routing already rejects inbound mail that fails the sender's DMARC policy,
// so a legitimate reporter cannot be spoofed — but an attacker CAN send a
// well-formed report from a domain they themselves control. We therefore record
// who really sent each report and classify a trust verdict, WITHOUT ever dropping
// a report (many legitimate smaller reporters exist; dropping real reports would
// regress coverage). See migration 066-dmarc-inbound-provenance.sql.


export function buildDmarcReportRemediationActions(senders, readiness) {
  const actions = [];
  const unknowns = senders.filter((s) => (s.classification || "unknown") === "unknown");
  const highVolFailed = senders.filter((s) => (s.total_messages || 0) >= 50 && (typeof s.pass_rate === "number" ? s.pass_rate : 100) < 90);
  if (unknowns.length > 0) {
    actions.push(remediationAction("unknown_sender_detected", "DMARC", "medium",
      "Unknown email sender detected in DMARC reports",
      `${unknowns.length} source IP(s) sent mail using this domain but have not been classified.`,
      "Unknown senders may represent legitimate services, forwarding, or attempted impersonation.",
      "Review each sender, confirm ownership, and classify it as trusted, suspicious, threat, ignored, or unknown."));
    actions.push(remediationAction("sender_needs_classification", "DMARC", "low",
      "Classify observed email senders",
      `${unknowns.length} sender(s) are awaiting classification.`,
      "Until senders are classified, DMARC enforcement readiness cannot be confirmed.",
      "Open Email Protection and classify each observed sender."));
  }
  if (highVolFailed.length > 0) {
    actions.push(remediationAction("high_volume_alignment_failure", "DMARC", "high",
      "High-volume sender failing DMARC alignment",
      `${highVolFailed.length} sender(s) send significant volume but frequently fail SPF/DKIM alignment.`,
      "Legitimate mail may be lost at enforcement, or an unauthorised sender may be active.",
      "Confirm whether the sender is legitimate; if so, correct its SPF/DKIM alignment before enforcement.",
      { caution: "Do not move to enforcement until high-volume senders are aligned or confirmed unauthorised." }));
  }
  if (readiness?.ready_for_quarantine) {
    actions.push(remediationAction("ready_for_quarantine_review", "DMARC", "low",
      "Review readiness to move to quarantine",
      "Observed traffic appears mostly aligned over the reporting window.",
      "Moving to quarantine increases protection against impersonation once senders are confirmed.",
      readiness.next_step,
      { caution: "Confirm all legitimate senders before changing policy." }));
  } else {
    actions.push(remediationAction("not_ready_for_reject", "DMARC", "info",
      "Not yet ready for reject enforcement",
      readiness?.explanation || "Enforcement readiness has not been met.",
      "Premature enforcement can cause legitimate mail to be rejected.",
      readiness?.next_step || "Classify senders and improve alignment before enforcement."));
  }
  return actions;
}

/**
 * buildDmarcBusinessRisk(stats) — derive the dmarc-summary business_risk { level, summary }
 * from CURRENT sender classifications and alignment, so the copy always reflects the
 * real mix (e.g. a suspicious sender is not described as "unknown senders").
 */
export function buildDmarcBusinessRisk(stats = {}) {
  const threat     = stats.threat_senders || 0;
  const suspicious = stats.suspicious_senders || 0;
  const unknown    = stats.unknown_senders || 0;
  const failed     = stats.failed_messages || 0;
  const pass       = typeof stats.pass_rate === "number" ? stats.pass_rate : 0;

  if (threat > 0) {
    return { level: "high",
      summary: "Threat-classified senders and failed alignment may increase impersonation and invoice-fraud risk." };
  }
  if (suspicious > 0 && failed > 0) {
    return { level: "high",
      summary: "Suspicious sender activity and failed DMARC alignment may increase impersonation and invoice-fraud risk." };
  }
  if (unknown > 0 && failed > 0) {
    return { level: pass < 80 ? "high" : "medium",
      summary: "Unknown email senders and failed alignment may increase impersonation and invoice-fraud risk." };
  }
  if (unknown > 0) {
    return { level: "medium",
      summary: "Unknown email senders should be classified before tightening DMARC enforcement." };
  }
  if (failed > 0) {
    return { level: "medium",
      summary: "Failed DMARC alignment remains a risk even after sender classification. Review failing sources before enforcement." };
  }
  if (pass >= 98 && unknown === 0 && suspicious === 0 && threat === 0) {
    return { level: "low",
      summary: "Sender alignment looks strong. Continue monitoring before tightening enforcement." };
  }
  return { level: "low",
    summary: "Continue monitoring sender alignment and classification before changing DMARC enforcement." };
}

async function loadLatestDomainEmailModules(env, workspaceId, domain) {
  try {
    if (!env.cybermeters_reports) return null;
    const scan = await env.cybermeters_db
      .prepare(`SELECT s.id
                FROM scans s
                LEFT JOIN workspace_domains wd ON wd.domain_id = s.domain_id
                WHERE s.status = 'completed'
                  AND s.domain = ?
                  AND (s.workspace_id = ? OR wd.workspace_id = ?)
                ORDER BY s.created_at DESC LIMIT 1`)
      .bind(domain, workspaceId, workspaceId).first();
    if (!scan?.id) return null;
    const obj = await env.cybermeters_reports.get(`reports/${scan.id}.json`);
    if (!obj) return null;
    const report = await obj.json();
    return report?.modules || null;
  } catch {
    return null;
  }
}

export function cybermetersRuaPresentInDmarcRecord(record, endpoint) {
  const local = String(endpoint?.address_local || "").trim().toLowerCase();
  if (!local || !record) return false;
  const inboundDomain = String(endpoint?.inbound_domain || RUA_INBOUND_DOMAIN_DEFAULT).trim().toLowerCase();
  return String(record).toLowerCase().includes(`${local}@${inboundDomain}`);
}

async function loadBecBrandEvidence(env, workspaceId, domain) {
  try {
    const profile = await loadWorkspaceBrandProfile(env, workspaceId);
    const rows = await env.cybermeters_db
      .prepare(`SELECT id, domain, candidate_domain, variant_type, similarity_score,
                       risk_level, risk_reasons, dns_resolves, https_available,
                       status, classification, first_seen, last_seen, last_checked_at,
                       mx_present, registrar_or_whois_summary, evidence_json,
                       created_at, updated_at
                FROM workspace_brand_assets
                WHERE workspace_id = ? AND domain = ?
                LIMIT 250`)
      .bind(workspaceId, domain).all();
    const candidates = (rows.results || []).map((row) => brandCandidateToApi(row, profile));
    let highRiskActiveDns = 0;
    let highRiskMx = 0;
    let suspiciousOrConfirmed = 0;
    let ignoredOrOwned = 0;
    for (const candidate of candidates) {
      if (["owned", "ignored", "false_positive"].includes(candidate.classification)) {
        ignoredOrOwned++;
        continue;
      }
      const highRisk = ["critical", "high"].includes(candidate.risk_level);
      if (highRisk && candidate.dns_active === true) highRiskActiveDns++;
      if (highRisk && candidate.mx_present === true) highRiskMx++;
      if (["suspicious", "confirmed_abuse"].includes(candidate.classification) &&
          (candidate.dns_active === true || candidate.mx_present === true)) suspiciousOrConfirmed++;
    }
    return {
      available: true,
      total: candidates.length,
      high_risk_active_dns: highRiskActiveDns,
      high_risk_mx: highRiskMx,
      suspicious_or_confirmed: suspiciousOrConfirmed,
      owned_ignored_or_false_positive: ignoredOrOwned,
    };
  } catch {
    return { available: false };
  }
}

// Authority-only sender view for readiness, BEC risk and executive evidence.
// The cumulative email_sender_sources rows deliberately remain observational:
// inbound reports still appear in the customer sender/report surfaces. Counts
// used for authority are rebuilt from parent reports whose explicit source is
// eligible; inbound, NULL and unknown sources are excluded by construction.
async function loadAuthorityEligibleDmarcSenders(env, workspaceId, domain) {
  const rows = await env.cybermeters_db
    .prepare(`SELECT r.source_ip,
                     COALESCE(s.classification, 'unknown') AS classification,
                     SUM(r.message_count) AS total_messages,
                     SUM(CASE WHEN r.spf_aligned_result = 'pass' OR r.dkim_aligned_result = 'pass'
                              THEN r.message_count ELSE 0 END) AS aligned_messages,
                     SUM(CASE WHEN r.spf_aligned_result = 'pass' OR r.dkim_aligned_result = 'pass'
                              THEN 0 ELSE r.message_count END) AS failed_messages
              FROM dmarc_aggregate_records r
              JOIN dmarc_aggregate_reports rep
                ON rep.id = r.report_id
               AND rep.workspace_id = r.workspace_id
               AND rep.domain = r.domain
              LEFT JOIN email_sender_sources s
                ON s.workspace_id = r.workspace_id
               AND s.domain = r.domain
               AND s.source_ip = r.source_ip
              WHERE r.workspace_id = ? AND r.domain = ?
                AND ${dmarcAuthoritySourceSql("rep")}
              GROUP BY r.source_ip, s.classification
              ORDER BY total_messages DESC`)
    .bind(workspaceId, domain).all();
  return (rows.results || []).map((row) => {
    const total = Number(row.total_messages || 0);
    const aligned = Number(row.aligned_messages || 0);
    return {
      ...row,
      total_messages: total,
      aligned_messages: aligned,
      failed_messages: Number(row.failed_messages || 0),
      pass_rate: total > 0 ? Math.round((aligned / total) * 1000) / 10 : 0,
    };
  });
}

export async function loadBecExposureEvidence(env, workspaceId, domain) {
  const [domainRow, senders, reportWindow, latestEndpoint, modules, brand] = await Promise.all([
    env.cybermeters_db
      .prepare(`SELECT d.id, d.domain, d.verification_status
                FROM domains d
                JOIN workspace_domains wd ON wd.domain_id = d.id
                WHERE wd.workspace_id = ? AND d.domain = ? LIMIT 1`)
      .bind(workspaceId, domain).first(),
    loadAuthorityEligibleDmarcSenders(env, workspaceId, domain).catch(() => []),
    env.cybermeters_db
      .prepare(`SELECT COUNT(*) AS imported_reports,
                       SUM(message_count) AS report_messages,
                       MIN(date_range_begin) AS first_report_epoch,
                       MAX(date_range_end) AS last_report_epoch,
                       (SELECT policy_p FROM dmarc_aggregate_reports
                        WHERE workspace_id = ? AND domain = ?
                          AND ${dmarcAuthoritySourceSql("dmarc_aggregate_reports")}
                        ORDER BY created_at DESC LIMIT 1) AS latest_policy_p,
                       (SELECT policy_pct FROM dmarc_aggregate_reports
                        WHERE workspace_id = ? AND domain = ?
                          AND ${dmarcAuthoritySourceSql("dmarc_aggregate_reports")}
                        ORDER BY created_at DESC LIMIT 1) AS latest_policy_pct
                FROM dmarc_aggregate_reports rep
                WHERE workspace_id = ? AND domain = ?
                  AND ${dmarcAuthoritySourceSql("rep")}`)
      .bind(workspaceId, domain, workspaceId, domain, workspaceId, domain).first().catch(() => null),
    env.cybermeters_db
      .prepare(`SELECT domain, address_local, status, last_used_at, last_inbound_at,
                       last_signed_upload_at, cloudflare_route_status
                FROM dmarc_ingest_endpoints
                WHERE workspace_id = ? AND domain = ?
                ORDER BY created_at DESC LIMIT 1`)
      .bind(workspaceId, domain).first().catch(() => null),
    loadLatestDomainEmailModules(env, workspaceId, domain),
    loadBecBrandEvidence(env, workspaceId, domain),
  ]);

  const sSummary = summarizeEmailSenders(senders);
  const totalMessages = Number(sSummary.total_messages || 0);
  const alignedMessages = Number(sSummary.aligned_messages || 0);
  const failedMessages = Math.max(0, totalMessages - alignedMessages) || sSummary.failed_messages || 0;
  const passRate = totalMessages > 0 ? Math.round((alignedMessages / totalMessages) * 1000) / 10 : sSummary.overall_pass_rate;
  const highVolFailed = senders.filter((s) => (s.total_messages || 0) >= 50 &&
    (typeof s.pass_rate === "number" ? s.pass_rate : 100) < 90).length;

  const email = modules?.email_security || {};
  const dmarcDetail = email.dmarc_detail || {};
  const dmarc = email.dmarc || {};
  const spf = email.spf || {};
  const dkim = email.dkim || {};
  const endpointWithDomain = latestEndpoint
    ? { ...latestEndpoint, inbound_domain: env.RUA_INBOUND_DOMAIN || RUA_INBOUND_DOMAIN_DEFAULT }
    : null;
  const cybermetersRuaVerified = cybermetersRuaPresentInDmarcRecord(dmarc.record, endpointWithDomain);
  const daysWithData = (reportWindow?.first_report_epoch && reportWindow?.last_report_epoch)
    ? Math.max(1, Math.round((Number(reportWindow.last_report_epoch || 0) -
      Number(reportWindow.first_report_epoch || 0)) / 86400)) : 0;
  const readiness = buildDmarcEnforcementReadiness({
    days_with_data: daysWithData,
    total_messages: totalMessages,
    pass_rate: passRate,
    unknown_senders: sSummary.unknown_senders,
    high_volume_failed_senders: highVolFailed,
  });

  return {
    domain,
    dmarc_present: dmarc.present === true || dmarcDetail.raw != null || Boolean(dmarc.record) || Boolean(reportWindow?.latest_policy_p),
    dmarc_policy: dmarcDetail.policy || dmarc.policy || reportWindow?.latest_policy_p || (dmarc.present === false ? "missing" : "unknown"),
    dmarc_pct: dmarcDetail.percentage ?? dmarc.pct ?? reportWindow?.latest_policy_pct ?? null,
    spf_present: spf.present,
    spf_status: spf.present === false ? "missing" : (spf.status || (spf.present === true ? "valid" : "unknown")),
    dkim_present: dkim.present,
    dkim_status: dkim.present === false ? "missing" : (dkim.status || (dkim.present === true ? "valid" : "unknown")),
    pass_rate: passRate,
    total_messages: totalMessages,
    aligned_messages: alignedMessages,
    failed_messages: failedMessages,
    known_senders: sSummary.total_senders,
    total_senders: sSummary.total_senders,
    unknown_senders: sSummary.unknown_senders,
    suspicious_senders: sSummary.suspicious_senders,
    threat_senders: sSummary.threat_senders,
    high_volume_failing_senders: highVolFailed,
    reports_received: Number(reportWindow?.imported_reports || 0) > 0 || totalMessages > 0,
    imported_reports: Number(reportWindow?.imported_reports || 0),
    last_report_received_at: reportWindow?.last_report_epoch ? new Date(Number(reportWindow.last_report_epoch) * 1000).toISOString()
      : (latestEndpoint?.last_inbound_at || latestEndpoint?.last_used_at || null),
    cybermeters_rua_verified: cybermetersRuaVerified,
    domain_verification_status: domainRow?.verification_status || null,
    dns_status_known: Boolean(modules?.email_security || domainRow?.verification_status),
    enforcement_readiness_blockers: readiness.blockers || [],
    evidence_scope: DMARC_AUTHORITY_EVIDENCE_SCOPE,
    inbound_reports_authoritative: false,
    brand,
  };
}

// Additive Executive-Report evidence: a compact sender-intelligence summary.
export async function buildDmarcSenderIntelligenceEvidence(env, workspaceId, domain) {
  if (!workspaceId || !domain) return null;
  try {
    const senders = await loadAuthorityEligibleDmarcSenders(env, workspaceId, domain);
    const window = await env.cybermeters_db
      .prepare(`SELECT COUNT(*) AS c, MIN(date_range_begin) AS minb, MAX(date_range_end) AS maxe
                FROM dmarc_aggregate_reports rep
                WHERE workspace_id = ? AND domain = ?
                  AND ${dmarcAuthoritySourceSql("rep")}`)
      .bind(workspaceId, domain).first();
    const imported = window?.c || 0;
    if (imported === 0 && senders.length === 0) return null;
    const summary = summarizeEmailSenders(senders);
    const daysWithData = (window?.minb && window?.maxe) ? Math.max(1, Math.round((window.maxe - window.minb) / 86400)) : 0;
    const highVolFailed = senders.filter((s) => (s.total_messages || 0) >= 50 && (typeof s.pass_rate === "number" ? s.pass_rate : 100) < 90).length;
    const readiness = buildDmarcEnforcementReadiness({
      days_with_data: daysWithData, total_messages: summary.total_messages,
      pass_rate: summary.overall_pass_rate, unknown_senders: summary.unknown_senders,
      high_volume_failed_senders: highVolFailed,
    });
    return {
      imported_reports: imported,
      observed_senders: summary.total_senders,
      unknown_senders: summary.unknown_senders,
      total_messages: summary.total_messages,
      failed_messages: summary.failed_messages,
      pass_rate: summary.overall_pass_rate,
      readiness_stage: readiness.ready_for_reject ? "reject_ready" : readiness.ready_for_quarantine ? "quarantine_ready" : "monitoring",
      evidence_scope: DMARC_AUTHORITY_EVIDENCE_SCOPE,
      inbound_reports_authoritative: false,
    };
  } catch { return null; }
}
