// ── Identity Exposure — "how can an attacker impersonate, steal, or abuse your
// identity?" ─────────────────────────────────────────────────────────────────
// Consolidates three REAL, free, outside-in signals we already produce — no HIBP,
// no fake placeholder:
//   1. Exposed login / credential surfaces (identity_assets: OWA/VPN/RDP/SSO/…)
//   2. Active impersonation infrastructure (lookalike domains that resolve and can
//      send mail / host a login page — brand_assets)
//   3. Email spoofing exposure (SPF/DMARC weakness → attackers can send email as
//      you — the #1 SMB / BEC threat), read from the latest scan report.
// Read-only; never throws. Breached-credential monitoring (HIBP Pro) is a genuine
// future signal, not represented here until it's real.

import {
  IDENTITY_CANONICAL_EXPOSURE_QUERY,
  buildIdentityEvidenceProjection,
  summarizeIdentityClaims,
} from "./identity-evidence-contract.js";

const MAX_DOMAINS_FOR_EMAIL = 20;

export async function computeIdentityExposure(env, workspaceId) {
  const db = env.cybermeters_db;

  // A2: a FAILED evidence query/read must never look like "observed, zero exposure".
  // Each source tracks its own availability so deriveLevel can return an honest
  // Unavailable / Not Assessed state instead of a false Low/clean conclusion.
  let loginUnavailable = false, brandUnavailable = false, scansUnavailable = false;

  // ── 1. Exposed login / credential surfaces ─────────────────────────────────
  const loginRows = (await db
    .prepare(IDENTITY_CANONICAL_EXPOSURE_QUERY)
    .bind(workspaceId).all().catch(() => { loginUnavailable = true; return { results: [] }; })).results ?? [];
  const projectedLoginRows = loginRows.map((row) => ({ ...row, ...buildIdentityEvidenceProjection(row) }));
  const byType = {};
  for (const r of projectedLoginRows) byType[r.identity_type] = (byType[r.identity_type] || 0) + 1;
  const claimCounts = summarizeIdentityClaims(projectedLoginRows);
  const login = {
    count: projectedLoginRows.length,
    // Deprecated primitive alias: authoritative counts are the four separated
    // siblings below. It now reflects typed reachable measurements only.
    internet_facing: claimCounts.reachable_surface_count,
    ...claimCounts,
    by_type: byType,
    top: projectedLoginRows.slice(0, 5).map((r) => ({
      hostname: r.hostname, type: r.identity_type, provider: r.provider,
      internet_exposed: r.identity_claim?.reachability?.status === "reachable",
      evidence_status: r.evidence_status,
      confidence_detail: r.confidence_detail,
      identity_claim: r.identity_claim,
      name_resolution: r.name_resolution,
    })),
  };

  // ── 2. Active impersonation infrastructure ─────────────────────────────────
  const brandRows = (await db
    .prepare(`SELECT candidate_domain, classification, risk_level, dns_resolves, mx_present, https_available
              FROM workspace_brand_assets WHERE workspace_id = ? AND status = 'active'
              ORDER BY (COALESCE(dns_resolves,0)+COALESCE(mx_present,0)+COALESCE(https_available,0)) DESC LIMIT 200`)
    .bind(workspaceId).all().catch(() => { brandUnavailable = true; return { results: [] }; })).results ?? [];
  const active = brandRows.filter((r) => r.dns_resolves);
  const impersonation = {
    total: brandRows.length,
    active: active.length,                                   // resolving lookalikes
    can_send_mail: active.filter((r) => r.mx_present).length,     // MX → can spoof/receive as you
    can_host_login: active.filter((r) => r.https_available).length, // HTTPS → can host a phishing login
    top: active.slice(0, 5).map((r) => ({ domain: r.candidate_domain, mx: !!r.mx_present, https: !!r.https_available, classification: r.classification })),
  };

  // ── 3. Email spoofing exposure (from the latest scan report per domain) ────
  const scanRows = (await db
    .prepare(`WITH lpd AS (SELECT domain_id, MAX(created_at) mx FROM scans WHERE status='completed' GROUP BY domain_id)
              SELECT s.id AS scan_id, s.domain
              FROM scans s JOIN lpd ON s.domain_id = lpd.domain_id AND s.created_at = lpd.mx
              JOIN workspace_domains wd ON s.domain_id = wd.domain_id
              WHERE wd.workspace_id = ? LIMIT ${MAX_DOMAINS_FOR_EMAIL}`)
    .bind(workspaceId).all().catch(() => { scansUnavailable = true; return { results: [] }; })).results ?? [];
  const emailDetails = [];
  for (const row of scanRows) {
    try {
      const obj = await env.cybermeters_reports.get(`reports/${row.scan_id}.json`);
      if (!obj) continue;                                    // fail-open: no report → skip
      const rep = await obj.json();
      const es = rep?.modules?.email_security;
      if (!es || es.error) continue;
      const spf = !!es.spf?.present;
      const dmarcPresent = !!es.dmarc?.present;
      const dmarcPolicy = (es.dmarc?.policy || "").toLowerCase() || null;
      // Spoofable if there is no SPF, or no DMARC, or DMARC is monitor-only (p=none).
      const spoofable = !spf || !dmarcPresent || dmarcPolicy === "none" || dmarcPolicy === null;
      emailDetails.push({ domain: row.domain, spf, dmarc: dmarcPresent, dmarc_policy: dmarcPolicy, spoofable });
    } catch { /* fail-open per domain */ }
  }
  const email = {
    checked_domains: emailDetails.length,
    spoofable_domains: emailDetails.filter((d) => d.spoofable).length,
    details: emailDetails,
  };

  // A2 evidence status. Unavailable = a source query failed, OR we had completed
  // scans to read but could read NONE of their reports (total R2 failure). A
  // partial R2 read (some reports readable) proceeds on the observed evidence.
  const emailUnavailable = scansUnavailable || (scanRows.length > 0 && emailDetails.length === 0);
  const evidence = {
    unavailable: loginUnavailable || brandUnavailable || emailUnavailable,
    // "assessed" = we actually observed some evidence to evaluate (not just empty tables).
    assessed: login.count > 0 || impersonation.total > 0 || email.checked_domains > 0,
  };

  return { signals: { exposed_login_surfaces: login, impersonation_infrastructure: impersonation, email_spoofing: email }, ...deriveLevel(login, impersonation, email, evidence) };
}

// Pure: overall level + plain-English summary from the three signals.
// A2: `evidence` distinguishes "we observed and saw nothing" from "we could not
// observe" / "nothing to assess". unavailable / not-assessed must NEVER read as a
// clean Low. Real exposure always surfaces first and is never hidden by a gap.
export function deriveLevel(login, impersonation, email, evidence = {}) {
  const highSignals = [
    email.spoofable_domains > 0,                             // attackers can send email as you (BEC)
    impersonation.can_send_mail > 0,                         // a lookalike can spoof mail as you
    impersonation.can_host_login > 0,                        // a lookalike can host a phishing login
  ].filter(Boolean).length;
  const mediumSignals = [
    login.reachable_surface_count > 0,                     // measured reachable identity surfaces
    impersonation.active > 0,                               // resolving lookalikes (even without mail/login)
  ].filter(Boolean).length;

  const parts = [];
  if (email.spoofable_domains > 0) parts.push(`${email.spoofable_domains} of your ${email.checked_domains} domain${email.checked_domains === 1 ? "" : "s"} can be spoofed in email (weak or missing DMARC)`);
  if (impersonation.active > 0) parts.push(`${impersonation.active} active lookalike domain${impersonation.active === 1 ? "" : "s"}${impersonation.can_send_mail ? ` (${impersonation.can_send_mail} able to send mail as you)` : ""}`);
  if (login.reachable_surface_count > 0) parts.push(`${login.reachable_surface_count} identity surface${login.reachable_surface_count === 1 ? "" : "s"} measured reachable`);

  // Real exposure ALWAYS surfaces first — an evidence gap never hides a finding.
  if (highSignals >= 1 || mediumSignals >= 1) {
    const level = highSignals >= 1 ? "High" : "Medium";
    return { identity_exposure_level: level, summary: `Identity exposure is ${level}: ${parts.join("; ")}.` };
  }

  // No exposure observed. Unavailable / not-assessed can NEVER become clean Low.
  const unavailable = evidence.unavailable === true;
  const assessed = evidence.assessed !== undefined
    ? evidence.assessed === true
    : ((login?.count > 0) || (impersonation?.total > 0) || (email?.checked_domains > 0));

  if (unavailable) {
    return {
      identity_exposure_level: "Unavailable",
      summary: "Identity exposure could not be fully assessed this check — some evidence (login-surface, lookalike-domain, or email records) was unavailable. This is not a clean result.",
    };
  }
  if (!assessed) {
    return {
      identity_exposure_level: "Not Assessed",
      summary: "Identity exposure has not been assessed yet — no identity assets, lookalike domains, or completed scans were available to evaluate.",
    };
  }
  if (!(Number(login?.reachability_evaluated_count) > 0)) {
    return {
      identity_exposure_level: "Not Assessed",
      summary: "Identity surface reachability was not evaluated — provider relationships and possible identity-facing hostnames are review evidence, not measured public endpoints.",
    };
  }
  return {
    identity_exposure_level: "Low",
    summary: "No material identity-exposure signal was observed within the evidence that was actually evaluated.",
  };
}
