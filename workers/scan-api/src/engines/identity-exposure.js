// ── Identity Exposure — "how can an attacker impersonate, steal, or abuse your
// identity?" ─────────────────────────────────────────────────────────────────
// Consolidates three REAL, free, outside-in signals we already produce — no HIBP,
// no fake placeholder:
//   1. Exposed login / credential surfaces (identity_assets: OWA/VPN/RDP/SSO/…)
//   2. Unresolved lookalike observations, respecting customer classification.
//   3. Observed DMARC policy gaps, not a demonstration of successful spoofing.
// Read-only; never throws. Breached-credential monitoring (HIBP Pro) is a genuine
// future signal, not represented here until it's real.

import {
  IDENTITY_CANONICAL_EXPOSURE_QUERY,
  buildIdentityEvidenceProjection,
  summarizeIdentityClaims,
} from "./identity-evidence-contract.js";

const MAX_DOMAINS_FOR_EMAIL = 20;
const CLOSED_BRAND_CLASSES = new Set(["owned", "ignored", "benign", "false_positive", "dismissed"]);

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
                AND COALESCE(classification, 'unreviewed') NOT IN ('owned', 'ignored', 'benign', 'false_positive', 'dismissed')
              ORDER BY (COALESCE(dns_resolves,0)+COALESCE(mx_present,0)+COALESCE(https_available,0)) DESC LIMIT 200`)
    .bind(workspaceId).all().catch(() => { brandUnavailable = true; return { results: [] }; })).results ?? [];
  const unresolved = brandRows.filter((r) => !CLOSED_BRAND_CLASSES.has(r.classification));
  const active = unresolved.filter((r) => r.dns_resolves);
  const impersonation = {
    total: unresolved.length,
    active: active.length,                                   // resolving lookalikes
    mail_receiving_domains: active.filter((r) => r.mx_present).length,
    https_responding_domains: active.filter((r) => r.https_available).length,
    confirmed_abuse_domains: active.filter((r) => r.classification === "confirmed_abuse").length,
    // Retained API aliases describe observations only; neither proves abuse.
    can_send_mail: active.filter((r) => r.mx_present).length,
    can_host_login: active.filter((r) => r.https_available).length,
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
      if (!obj) { scansUnavailable = true; continue; }
      const rep = await obj.json();
      const es = rep?.modules?.email_security;
      if (!es || es.error || es.incomplete || es.executed === false || typeof es.dmarc?.present !== "boolean") { scansUnavailable = true; continue; }
      const spf = !!es.spf?.present;
      const dmarcPresent = !!es.dmarc?.present;
      const dmarcPolicy = (es.dmarc?.policy || "").toLowerCase() || null;
      // DMARC may pass via aligned DKIM even without SPF. Missing/unparsed
      // policy is unknown; a published policy does not prove mail alignment.
      const policyGap = !dmarcPresent || dmarcPolicy === "none";
      const usableRecord = es.dmarc_detail?.valid !== false && !(es.dmarc?.record_count > 1);
      const policyKnown = !dmarcPresent || (usableRecord && ["none", "quarantine", "reject"].includes(dmarcPolicy));
      if (!policyKnown) scansUnavailable = true;
      emailDetails.push({ domain: row.domain, spf, dmarc: dmarcPresent, dmarc_policy: dmarcPolicy,
        policy_gap: policyKnown ? policyGap : null, spoofable: policyKnown ? policyGap : null });
    } catch { scansUnavailable = true; }
  }
  const email = {
    checked_domains: emailDetails.length,
    spoofable_domains: emailDetails.filter((d) => d.spoofable).length,
    policy_gap_domains: emailDetails.filter((d) => d.policy_gap === true).length,
    policy_observed_domains: emailDetails.filter((d) => d.policy_gap === false).length,
    details: emailDetails,
  };

  // A2 evidence status. Unavailable = a source query failed, OR we had completed
  // scans whose reports could not be evaluated. Partial evidence stays partial.
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
    email.spoofable_domains > 0,
    impersonation.confirmed_abuse_domains > 0,
  ].filter(Boolean).length;
  const mediumSignals = [
    impersonation.active > 0,                               // resolving lookalikes (even without mail/login)
  ].filter(Boolean).length;

  const parts = [];
  if (email.spoofable_domains > 0) parts.push(`${email.spoofable_domains} of ${email.checked_domains} domain${email.checked_domains === 1 ? "" : "s"} have no enforcing DMARC policy observed; successful impersonation is not established`);
  if (impersonation.active > 0) parts.push(`${impersonation.active} unresolved, resolving lookalike domain${impersonation.active === 1 ? "" : "s"}${impersonation.mail_receiving_domains ? ` (${impersonation.mail_receiving_domains} with mail-receiving MX records)` : ""}${impersonation.confirmed_abuse_domains ? `; ${impersonation.confirmed_abuse_domains} classified as confirmed abuse` : ""}`);
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
