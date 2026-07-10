// ── BEC exposure score ──
// Business Email Compromise exposure scoring: translates email-auth evidence (SPF/DMARC/DKIM/
// RUA) into a business-risk exposure level + reasons + recommended actions + summary. Higher
// = more exposed (per CLAUDE.md BEC rules). Extracted verbatim from index.js (monolith
// decomposition, Phase 1c). The bec* helpers + normalizeEmailAuthStatus are module-internal.

function becExposureLevel(score) {
  if (score >= 90) return "critical";
  if (score >= 71) return "high";
  if (score >= 46) return "medium";
  if (score >= 21) return "low";
  return "minimal";
}

function becReason(code, severity, label, detail) {
  return { code, severity, label, detail };
}

function becAction(code, priority, label, detail) {
  return { code, priority, label, detail };
}

function normalizeEmailAuthStatus(value, present) {
  const v = String(value || "").toLowerCase();
  if (["pass", "valid", "configured", "present", "ok"].includes(v)) return "valid";
  if (["fail", "invalid", "error", "missing"].includes(v)) return v === "missing" ? "missing" : "invalid";
  if (present === true) return "valid";
  if (present === false) return "missing";
  return "unknown";
}

function buildBecExposureSummary(level, evidence = {}, reasons = []) {
  if (level === "critical") {
    return "This domain is critically exposed to business email compromise and impersonation because multiple email authentication and sender-risk controls are unresolved.";
  }
  if (level === "high") {
    const parts = [];
    if (["missing", "none"].includes(evidence.dmarc_policy)) parts.push("DMARC is not enforcing");
    if ((evidence.failed_messages || 0) > 0) parts.push("failed alignment is material");
    if ((evidence.suspicious_senders || 0) > 0 ||
        (evidence.high_volume_failing_senders || 0) > 0) parts.push("risky sender evidence is present");
    return `This domain has high BEC exposure${parts.length ? ` because ${parts.join(", ")}.` : "."}`;
  }
  if (level === "medium") {
    return "This domain has measurable impersonation exposure. Continue sender classification, reporting coverage, and DMARC enforcement work before treating the risk as low.";
  }
  if (level === "low") {
    return "This domain has limited observed BEC exposure, but continued DMARC reporting and sender review are still recommended.";
  }
  return reasons.length === 0
    ? "This domain has minimal observed BEC exposure based on the available email authentication and sender evidence."
    : "This domain has minimal BEC exposure, with only minor evidence gaps observed.";
}

export function computeBecExposureScore(input = {}, options = {}) {
  const nowMs = options.now ? new Date(options.now).getTime() : Date.now();
  const reasons = [];
  const recommendedActions = [];
  let score = 0;

  const dmarcPresent = input.dmarc_present !== false && input.dmarc_policy !== "missing";
  const dmarcPolicy = !dmarcPresent ? "missing" : String(input.dmarc_policy || "unknown").toLowerCase();
  const dmarcPct = Number.isFinite(Number(input.dmarc_pct)) ? Math.max(0, Math.min(100, Number(input.dmarc_pct))) : null;
  const spfStatus = normalizeEmailAuthStatus(input.spf_status, input.spf_present);
  const dkimStatus = normalizeEmailAuthStatus(input.dkim_status, input.dkim_present);
  const totalMessages = Math.max(0, Number(input.total_messages || 0));
  const alignedMessages = Math.max(0, Number(input.aligned_messages || 0));
  const failedMessages = Math.max(0, Number(input.failed_messages || Math.max(0, totalMessages - alignedMessages) || 0));
  const passRate = Number.isFinite(Number(input.pass_rate))
    ? Math.max(0, Math.min(100, Number(input.pass_rate)))
    : (totalMessages > 0 ? Math.round((alignedMessages / totalMessages) * 1000) / 10 : null);
  const reportsReceived = input.reports_received === true || Number(input.imported_reports || 0) > 0 || totalMessages > 0;
  const senderDataExists = Number(input.known_senders || input.total_senders || 0) > 0;
  const cybermetersRuaVerified = input.cybermeters_rua_verified === true;
  const unknownSenders = Math.max(0, Number(input.unknown_senders || 0));
  const suspiciousSenders = Math.max(0, Number(input.suspicious_senders || 0) + Number(input.threat_senders || 0));
  const highVolumeFailingSenders = Math.max(0, Number(input.high_volume_failing_senders || input.high_volume_failed_senders || 0));

  if (dmarcPolicy === "missing" || dmarcPolicy === "unknown") {
    score += 30;
    reasons.push(becReason("dmarc_missing", "critical", "DMARC is missing",
      "Receivers have no domain-owner policy for handling messages that fail alignment."));
    recommendedActions.push(becAction("publish_dmarc", "critical", "Publish a DMARC record",
      "Start with monitored aggregate reporting, then move toward quarantine and reject after legitimate senders are aligned."));
  } else if (dmarcPolicy === "none") {
    score += 16;
    reasons.push(becReason("dmarc_policy_none", "high", "DMARC is monitoring only",
      "Receivers are not instructed to quarantine or reject messages that fail alignment."));
    recommendedActions.push(becAction("move_dmarc_to_enforcement", "high", "Move DMARC toward enforcement",
      "Classify legitimate senders, resolve alignment failures, then progress from p=none to quarantine and reject."));
  } else if (dmarcPolicy === "quarantine") {
    score += 6;
    reasons.push(becReason("dmarc_policy_quarantine", "medium", "DMARC is partially enforcing",
      "Quarantine reduces impersonation risk but does not provide the strongest reject instruction."));
    recommendedActions.push(becAction("progress_to_reject", "medium", "Progress DMARC to reject",
      "After sender alignment is stable, move from quarantine to reject with full coverage."));
  }

  if (dmarcPct != null && dmarcPct < 100 && ["quarantine", "reject"].includes(dmarcPolicy)) {
    score += 5;
    reasons.push(becReason("dmarc_partial_pct", "medium", "DMARC enforcement is partial",
      `The DMARC pct tag applies enforcement to ${dmarcPct}% of messages.`));
    recommendedActions.push(becAction("increase_dmarc_pct", "medium", "Increase DMARC policy coverage",
      "Raise pct to 100 after confirming legitimate senders are aligned."));
  }

  if (!cybermetersRuaVerified) {
    score += 7;
    reasons.push(becReason("cybermeters_rua_not_verified", "high", "CyberMeters RUA is not verified",
      "Automated DMARC report ingestion is not confirmed for this domain."));
    recommendedActions.push(becAction("add_cybermeters_rua", "high", "Add CyberMeters RUA to DMARC",
      "This improves reporting coverage and confirms automated ingestion."));
  }

  if (!reportsReceived) {
    score += 18;
    reasons.push(becReason("no_dmarc_reports", "medium", "No DMARC reports have been received",
      "Without aggregate report evidence, sender alignment and abuse patterns cannot be measured reliably."));
    recommendedActions.push(becAction("enable_dmarc_reporting", "high", "Enable DMARC aggregate reporting",
      "Add an aggregate reporting address and confirm reports are arriving."));
  } else if (input.last_report_received_at) {
    const lastMs = new Date(input.last_report_received_at).getTime();
    if (Number.isFinite(lastMs) && Number.isFinite(nowMs) && nowMs - lastMs > 14 * 86400000) {
      score += 6;
      reasons.push(becReason("dmarc_reports_stale", "medium", "DMARC reports are stale",
        "The most recent DMARC report is older than 14 days."));
      recommendedActions.push(becAction("restore_rua_flow", "medium", "Restore DMARC report flow",
        "Check the DMARC rua destination and confirm mailbox providers are still sending aggregate reports."));
    }
  }

  if (passRate != null && totalMessages > 0) {
    if (passRate < 80) {
      score += 16;
      reasons.push(becReason("dmarc_pass_rate_low", "high", "DMARC pass rate is below 80%",
        `${passRate}% of observed mail passed alignment.`));
      recommendedActions.push(becAction("fix_sender_alignment", "high", "Fix sender alignment",
        "Review failing sources and align SPF or DKIM for legitimate senders."));
    } else if (passRate < 95) {
      score += 8;
      reasons.push(becReason("dmarc_pass_rate_moderate", "medium", "DMARC pass rate is below 95%",
        `${passRate}% of observed mail passed alignment.`));
      recommendedActions.push(becAction("improve_sender_alignment", "medium", "Improve sender alignment",
        "Resolve remaining legitimate sender alignment failures before stronger enforcement."));
    }
  }

  if (failedMessages > 0) {
    const failedShare = totalMessages > 0 ? failedMessages / totalMessages : 0;
    const failedPoints = failedShare >= 0.2 || failedMessages >= 100 ? 8
      : failedShare >= 0.05 || failedMessages >= 25 ? 5 : 3;
    score += failedPoints;
    reasons.push(becReason("failed_alignment_present", failedPoints >= 15 ? "high" : "medium",
      "Failed DMARC alignment is present",
      `${failedMessages} observed message${failedMessages === 1 ? "" : "s"} failed alignment.`));
  }

  if (suspiciousSenders > 0) {
    score += 14;
    reasons.push(becReason("suspicious_sender_present", "high", "Suspicious sender activity is present",
      `${suspiciousSenders} sender${suspiciousSenders === 1 ? "" : "s"} are classified as suspicious or threat.`));
    recommendedActions.push(becAction("investigate_suspicious_senders", "high", "Investigate suspicious senders",
      "Confirm whether suspicious sources are legitimate suppliers or unauthorized impersonation attempts."));
  }

  if (unknownSenders > 0) {
    score += 6;
    reasons.push(becReason("unknown_sender_present", "medium", "Unknown senders remain unclassified",
      `${unknownSenders} sender${unknownSenders === 1 ? "" : "s"} must be classified before enforcement decisions.`));
    recommendedActions.push(becAction("classify_unknown_senders", "medium", "Classify unknown senders",
      "Mark legitimate senders as trusted and investigate unexpected sources."));
  }

  if (highVolumeFailingSenders > 0) {
    score += 14;
    reasons.push(becReason("high_volume_failing_sender", "high", "High-volume failing sender detected",
      `${highVolumeFailingSenders} high-volume sender${highVolumeFailingSenders === 1 ? "" : "s"} are failing alignment.`));
    recommendedActions.push(becAction("resolve_high_volume_failures", "high", "Resolve high-volume alignment failures",
      "Prioritize high-volume failing senders before moving to stricter DMARC enforcement."));
  }

  if (["missing", "invalid", "fail"].includes(spfStatus)) {
    score += 10;
    reasons.push(becReason("spf_missing_or_invalid", "medium", "SPF is missing or invalid",
      "Receivers may not be able to validate authorized sending infrastructure."));
    recommendedActions.push(becAction("fix_spf", "medium", "Fix SPF authorization",
      "Publish or correct SPF for legitimate mail services and avoid permissive mechanisms."));
  }

  if (["missing", "invalid", "fail", "unknown"].includes(dkimStatus)) {
    score += 6;
    reasons.push(becReason("dkim_missing_or_uncertain", "medium", "DKIM is missing or uncertain",
      "Receivers may not have a reliable cryptographic signal for message authenticity."));
    recommendedActions.push(becAction("fix_dkim", "medium", "Configure DKIM for legitimate senders",
      "Enable DKIM signing across business email and third-party sending services."));
  }

  const brand = input.brand || {};
  const brandMxHighRisk = Math.max(0, Number(brand.high_risk_mx || 0));
  const brandActiveHighRisk = Math.max(0, Number(brand.high_risk_active_dns || 0));
  const brandSuspicious = Math.max(0, Number(brand.suspicious_or_confirmed || 0));
  let brandPoints = 0;
  if (brandSuspicious > 0) brandPoints = 12;
  else if (brandMxHighRisk > 0) brandPoints = 8;
  else if (brandActiveHighRisk > 0) brandPoints = 5;
  if (brandPoints > 0) {
    score += brandPoints;
    reasons.push(becReason("brand_impersonation_candidates", brandPoints >= 10 ? "high" : "medium",
      "Brand impersonation candidates may enable email fraud",
      "Active or MX-enabled lookalike domains increase supplier impersonation and invoice-fraud exposure."));
    recommendedActions.push(becAction("review_brand_candidates", brandPoints >= 10 ? "high" : "medium",
      "Review high-risk brand candidates",
      "Investigate active or MX-enabled lookalikes and classify owned, ignored, suspicious, or confirmed abuse cases."));
  }

  const exposureScore = Math.max(0, Math.min(100, Math.round(score)));
  const exposureLevel = becExposureLevel(exposureScore);
  const dnsStatusKnown = input.dns_status_known === true || dmarcPolicy !== "unknown" ||
    typeof input.domain_verification_status === "string";
  let confidence = "low";
  if (reportsReceived && senderDataExists && dnsStatusKnown) confidence = "high";
  else if (dnsStatusKnown || dmarcPolicy !== "unknown") confidence = "medium";
  if (!reportsReceived && confidence === "high") confidence = "medium";

  const evidence = {
    dmarc_policy: dmarcPolicy,
    dmarc_pct: dmarcPct,
    pass_rate: passRate,
    total_messages: totalMessages,
    aligned_messages: alignedMessages,
    failed_messages: failedMessages,
    known_senders: Math.max(0, Number(input.known_senders || input.total_senders || 0)),
    unknown_senders: unknownSenders,
    suspicious_senders: suspiciousSenders,
    high_volume_failing_senders: highVolumeFailingSenders,
    reports_received: reportsReceived,
    cybermeters_rua_verified: cybermetersRuaVerified,
    last_report_received_at: input.last_report_received_at || null,
    spf_status: spfStatus,
    dkim_status: dkimStatus,
    domain_verification_status: input.domain_verification_status || null,
    enforcement_readiness_blockers: Array.isArray(input.enforcement_readiness_blockers)
      ? input.enforcement_readiness_blockers.slice(0, 10) : [],
    brand_candidates_available: Boolean(brand.available),
    brand_high_risk_active_dns: brandActiveHighRisk,
    brand_high_risk_mx: brandMxHighRisk,
    brand_suspicious_or_confirmed: brandSuspicious,
  };

  return {
    domain: input.domain || null,
    exposure_score: exposureScore,
    exposure_level: exposureLevel,
    confidence,
    summary: buildBecExposureSummary(exposureLevel, evidence, reasons),
    reasons,
    recommended_actions: recommendedActions.filter((action, idx, arr) =>
      arr.findIndex((candidate) => candidate.code === action.code) === idx),
    evidence,
  };
}
