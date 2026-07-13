// ── Certificates & Trust L2 intelligence ──
// Compute-on-read certificate findings, renewal readiness, trust-path posture and
// historical anomalies from existing CT/report evidence. This layer is deliberately
// honest about current evidence limits: no live TLS handshake, no chain validation,
// no OCSP/revocation result and no private-key inspection.
import {
  detectSelfSignedCertificate,
  mapCertificateAuthorityOwner,
  normalizeCertificateIssuer,
} from "./cert-analysis.js";

const FINDING_TYPES = new Set([
  "expiring_soon",
  "expired",
  "self_signed",
  "unexpected_issuer",
  "unexpected_san",
  "unexpected_wildcard",
  "parallel_certificate",
  "coverage_gap",
  "ct_source_incomplete",
  "unknown",
]);

const UNKNOWN_LIVE_TLS_REASON = "Unknown — requires live TLS inspection (not performed).";

function normaliseString(value) {
  return typeof value === "string" ? value.trim() : "";
}

function parseEvidenceJson(value) {
  try {
    return value ? JSON.parse(value) : {};
  } catch {
    return {};
  }
}

function uniqueSorted(values) {
  return [...new Set((Array.isArray(values) ? values : [])
    .map((value) => normaliseString(value).toLowerCase())
    .filter(Boolean))]
    .sort();
}

function daysUntil(expiresAt, fallback) {
  if (Number.isFinite(fallback)) return Number(fallback);
  const raw = normaliseString(expiresAt);
  if (!raw) return null;
  const expires = Date.parse(raw);
  if (!Number.isFinite(expires)) return null;
  return Math.ceil((expires - Date.now()) / 86_400_000);
}

function addFinding(findings, finding) {
  if (!finding || !FINDING_TYPES.has(finding.type)) return;
  findings.push({
    confidence: "medium",
    reasons: [],
    evidence: [],
    remediation: [],
    observed_via: "ct",
    ...finding,
  });
}

function certEvidence(cert, extra = {}) {
  return {
    source: "certificate_intelligence",
    issuer: cert.issuer || null,
    subject: cert.subject || null,
    expires_at: cert.expires_at || null,
    observed_via: "ct",
    ...extra,
  };
}

function historyRows(rows) {
  return (Array.isArray(rows) ? rows : []).map((row) => {
    const evidence = parseEvidenceJson(row.evidence_json);
    return {
      ...row,
      evidence,
      issuer: row.issuer || evidence.issuer || null,
      subject: row.subject || evidence.subject || null,
      expires_at: row.expires_at || evidence.expires_at || null,
      san_hostnames: uniqueSorted(evidence.san_hostnames || []),
    };
  });
}

function previousRowsForCurrent(cert, rows) {
  const currentIssuer = normaliseString(cert.issuer);
  const currentSubject = normaliseString(cert.subject);
  const currentExpiry = normaliseString(cert.expires_at);
  return rows.filter((row) => {
    if (currentIssuer && currentIssuer === normaliseString(row.issuer)
      && currentSubject && currentSubject === normaliseString(row.subject)
      && currentExpiry && currentExpiry === normaliseString(row.expires_at)) {
      return false;
    }
    return true;
  });
}

function buildTrustPath(cert) {
  const httpsReachable = typeof cert.https_reachable === "boolean"
    ? cert.https_reachable
    : typeof cert.https_available === "boolean"
      ? cert.https_available
      : cert.certificate_status === "valid"
        ? true
        : cert.certificate_status === "unavailable"
          ? false
          : "unknown";
  const redirectToHttps = typeof cert.redirect_to_https === "boolean" ? cert.redirect_to_https : "unknown";
  const hstsPresent = typeof cert.hsts_present === "boolean" ? cert.hsts_present : "unknown";
  const days = daysUntil(cert.expires_at, cert.days_until_expiry);
  const expiryOk = days === null ? "unknown" : days >= 0;

  const reasons = [];
  if (httpsReachable === "unknown") reasons.push("HTTPS reachability was not confirmed by a live TLS inspection.");
  if (redirectToHttps === "unknown") reasons.push("HTTP to HTTPS redirect posture was not available in certificate evidence.");
  if (hstsPresent === "unknown") reasons.push("HSTS posture was not available in certificate evidence.");
  reasons.push("Certificate chain validity, trusted root and OCSP status require live TLS inspection and are not assessed here.");

  return {
    https_reachable: httpsReachable,
    redirect_to_https: redirectToHttps,
    hsts_present: hstsPresent,
    expiry_ok: expiryOk,
    chain_valid: "unknown",
    root_trusted: "unknown",
    ocsp: "unknown",
    reasons,
  };
}

function buildRenewalReadiness(cert, rows) {
  const days = daysUntil(cert.expires_at, cert.days_until_expiry);
  const issuer = cert.issuer || null;
  const ca = mapCertificateAuthorityOwner(normalizeCertificateIssuer(issuer));
  const prior = previousRowsForCurrent(cert, rows);
  const currentExpiry = Date.parse(cert.expires_at || "");
  const priorExpiries = prior
    .map((row) => Date.parse(row.expires_at || ""))
    .filter(Number.isFinite)
    .sort((a, b) => b - a);
  const recentReissueObserved = Number.isFinite(currentExpiry)
    && priorExpiries.some((expiry) => currentExpiry > expiry);

  let status = "unknown";
  if (days !== null) {
    if (days < 0 || days <= 14) status = "critical";
    else if (days <= 30) status = "warning";
    else status = "healthy";
  }

  const blockers = [];
  const recommended_actions = [];
  if (days === null) {
    blockers.push("Certificate expiry was not available in the latest evidence.");
    recommended_actions.push("Confirm certificate expiry with your hosting provider or certificate authority.");
  } else if (days < 0) {
    blockers.push("The observed certificate has expired.");
    recommended_actions.push("Renew and deploy the certificate immediately, then run a fresh Cyber MOT.");
  } else if (days <= 30) {
    blockers.push(`The observed certificate expires in ${days} day${days === 1 ? "" : "s"}.`);
    recommended_actions.push("Schedule renewal before the certificate enters the final renewal window.");
  } else {
    recommended_actions.push("Keep renewal ownership and calendar reminders current.");
  }
  if (!recentReissueObserved && rows.length > 1 && days !== null && days <= 30) {
    recommended_actions.push("Check whether automatic renewal is working; no newer replacement certificate was observed in history.");
  }

  return {
    status,
    days_remaining: days,
    auto_renew_observed: recentReissueObserved ? true : (rows.length > 1 ? false : null),
    ca_provider: ca.ca_family !== "unknown" ? ca.ca_family : ca.owner,
    recent_reissue_observed: recentReissueObserved,
    blockers,
    recommended_actions,
  };
}

function buildAnomalies(cert, rows) {
  const prior = previousRowsForCurrent(cert, rows);
  const currentIssuer = normaliseString(cert.issuer);
  const currentSans = uniqueSorted(cert.san_hostnames);
  const priorIssuers = new Set(prior.map((row) => normaliseString(row.issuer)).filter(Boolean));
  const priorSans = new Set(prior.flatMap((row) => row.san_hostnames));
  const anomalies = [];

  if (currentIssuer && priorIssuers.size > 0 && !priorIssuers.has(currentIssuer)) {
    anomalies.push({
      type: "unexpected_issuer",
      severity: "medium",
      confidence: "medium",
      title: "New certificate issuer observed",
      reasons: ["The latest certificate issuer differs from previously observed certificate history."],
      evidence: [certEvidence(cert, { prior_issuers: [...priorIssuers].sort() })],
      first_seen: rows.find((row) => normaliseString(row.issuer) === currentIssuer)?.first_seen || null,
      prior: [...priorIssuers].sort(),
    });
  }

  const newSans = currentSans.filter((san) => !priorSans.has(san));
  if (newSans.length > 0 && priorSans.size > 0) {
    anomalies.push({
      type: "unexpected_san",
      severity: newSans.some((san) => san.includes("admin") || san.includes("vpn") || san.includes("sso")) ? "high" : "medium",
      confidence: "medium",
      title: "New certificate SAN observed",
      reasons: [`${newSans.length} SAN hostname${newSans.length === 1 ? "" : "s"} were not present in prior certificate history.`],
      evidence: [certEvidence(cert, { new_sans: newSans.slice(0, 20) })],
      first_seen: null,
      prior: [...priorSans].sort().slice(0, 20),
    });
  }

  const newWildcards = newSans.filter((san) => san.startsWith("*."));
  if (newWildcards.length > 0) {
    anomalies.push({
      type: "unexpected_wildcard",
      severity: "medium",
      confidence: "medium",
      title: "New wildcard certificate name observed",
      reasons: ["A wildcard SAN appears in current CT evidence but was not present in prior certificate history."],
      evidence: [certEvidence(cert, { wildcard_sans: newWildcards })],
      first_seen: null,
      prior: [...priorSans].filter((san) => san.startsWith("*.")).sort(),
    });
  }

  const now = Date.now();
  const currentAsRow = {
    issuer: currentIssuer,
    subject: cert.subject || null,
    expires_at: cert.expires_at || null,
    first_seen: null,
  };
  const activeRows = [currentAsRow, ...rows].filter((row) => {
    const expiry = Date.parse(row.expires_at || "");
    return Number.isFinite(expiry) && expiry >= now;
  });
  const activeIssuers = new Set(activeRows.map((row) => normaliseString(row.issuer)).filter(Boolean));
  if (activeRows.length >= 2 && activeIssuers.size >= 2) {
    anomalies.push({
      type: "parallel_certificate",
      severity: "low",
      confidence: "medium",
      title: "Parallel valid certificates observed",
      reasons: ["Certificate history contains multiple currently unexpired certificates for this domain from different issuers."],
      evidence: activeRows.slice(0, 10).map((row) => ({
        source: "certificate_observations",
        issuer: row.issuer,
        subject: row.subject,
        expires_at: row.expires_at,
        observed_via: "history",
      })),
      first_seen: activeRows.map((row) => row.first_seen).filter(Boolean).sort()[0] || null,
      prior: [...activeIssuers].sort(),
    });
  }

  return anomalies;
}

export function buildCertificateTrustL2(cert, options = {}) {
  const current = cert || {};
  const rows = historyRows(options.history);
  const findings = [];
  const days = daysUntil(current.expires_at, current.days_until_expiry);
  const selfSigned = current.self_signed ?? detectSelfSignedCertificate(current.issuer, current.subject);

  if (days !== null && days < 0) {
    addFinding(findings, {
      type: "expired",
      severity: "critical",
      confidence: "high",
      title: "Certificate expired",
      reasons: [`The observed certificate expired ${Math.abs(days)} day${Math.abs(days) === 1 ? "" : "s"} ago.`],
      evidence: [certEvidence(current, { days_until_expiry: days })],
      remediation: ["Renew and deploy the certificate, then run a fresh Cyber MOT to confirm the new evidence."],
    });
  } else if (days !== null && days <= 30) {
    addFinding(findings, {
      type: "expiring_soon",
      severity: days <= 14 ? "high" : "medium",
      confidence: "high",
      title: "Certificate expiring soon",
      reasons: [`The observed certificate expires in ${days} day${days === 1 ? "" : "s"}.`],
      evidence: [certEvidence(current, { days_until_expiry: days })],
      remediation: ["Schedule renewal and confirm the replacement certificate is visible after deployment."],
    });
  }

  if (selfSigned === true) {
    addFinding(findings, {
      type: "self_signed",
      severity: "high",
      confidence: "medium",
      title: "Self-signed certificate evidence",
      reasons: ["The certificate issuer and subject appear to match."],
      evidence: [certEvidence(current, { self_signed: true })],
      remediation: ["Use a publicly trusted certificate authority for public business services."],
    });
  }

  if (current.ct_sources?.crt_sh === 0 && current.ct_sources?.certspotter === 0) {
    addFinding(findings, {
      type: "ct_source_incomplete",
      severity: "low",
      confidence: "medium",
      title: "Certificate Transparency source incomplete",
      reasons: ["No CT source returned certificate hostnames for this scan."],
      evidence: [certEvidence(current, { ct_sources: current.ct_sources })],
      remediation: ["Review again after the next scan; CT source availability can vary."],
    });
  }

  if (!current.issuer && !current.expires_at && !current.subject) {
    addFinding(findings, {
      type: "coverage_gap",
      severity: "info",
      confidence: "high",
      title: "Certificate detail unavailable",
      reasons: ["The latest evidence did not include issuer, subject or expiry details."],
      evidence: [{ source: "certificate_intelligence", observed_via: "ct" }],
      remediation: ["Run a fresh Cyber MOT and confirm the domain serves HTTPS where expected."],
    });
  }

  const anomalies = buildAnomalies(current, rows);
  for (const anomaly of anomalies) {
    addFinding(findings, {
      ...anomaly,
      observed_via: anomaly.type === "parallel_certificate" ? "history" : "ct",
      remediation: anomaly.type === "unexpected_issuer"
        ? ["Confirm the issuer change was expected and tied to a planned renewal or hosting change."]
        : anomaly.type === "unexpected_wildcard"
          ? ["Confirm wildcard coverage is intentional and documented."]
          : anomaly.type === "unexpected_san"
            ? ["Review newly observed SAN names and remove unintended certificate coverage."]
            : ["Review parallel certificates and retire any certificates that are no longer required."],
    });
  }

  if (findings.length === 0) {
    addFinding(findings, {
      type: "unknown",
      severity: "info",
      confidence: "low",
      title: "No certificate L2 gaps found from available evidence",
      reasons: ["Available CT and historical evidence did not show a specific certificate gap."],
      evidence: [certEvidence(current, { trust_path_limit: UNKNOWN_LIVE_TLS_REASON })],
      remediation: ["Use live TLS inspection if you need chain, root trust, OCSP or served-certificate verification."],
    });
  }

  return {
    findings,
    renewal_readiness: buildRenewalReadiness(current, rows),
    trust_path: buildTrustPath(current),
    anomalies,
  };
}
