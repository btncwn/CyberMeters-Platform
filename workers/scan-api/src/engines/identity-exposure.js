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

const MAX_DOMAINS_FOR_EMAIL = 20;

export async function computeIdentityExposure(env, workspaceId) {
  const db = env.cybermeters_db;

  // ── 1. Exposed login / credential surfaces ─────────────────────────────────
  const loginRows = (await db
    .prepare(`SELECT hostname, identity_type, provider, internet_exposed, risk_score
              FROM identity_assets WHERE workspace_id = ? AND status = 'active'
              ORDER BY risk_score DESC, internet_exposed DESC LIMIT 100`)
    .bind(workspaceId).all().catch(() => ({ results: [] }))).results ?? [];
  const byType = {};
  for (const r of loginRows) byType[r.identity_type] = (byType[r.identity_type] || 0) + 1;
  const login = {
    count: loginRows.length,
    internet_facing: loginRows.filter((r) => r.internet_exposed).length,
    by_type: byType,
    top: loginRows.slice(0, 5).map((r) => ({ hostname: r.hostname, type: r.identity_type, provider: r.provider, internet_exposed: !!r.internet_exposed })),
  };

  // ── 2. Active impersonation infrastructure ─────────────────────────────────
  const brandRows = (await db
    .prepare(`SELECT candidate_domain, classification, risk_level, dns_resolves, mx_present, https_available
              FROM workspace_brand_assets WHERE workspace_id = ? AND status = 'active'
              ORDER BY (COALESCE(dns_resolves,0)+COALESCE(mx_present,0)+COALESCE(https_available,0)) DESC LIMIT 200`)
    .bind(workspaceId).all().catch(() => ({ results: [] }))).results ?? [];
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
    .bind(workspaceId).all().catch(() => ({ results: [] }))).results ?? [];
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

  return { signals: { exposed_login_surfaces: login, impersonation_infrastructure: impersonation, email_spoofing: email }, ...deriveLevel(login, impersonation, email) };
}

// Pure: overall level + plain-English summary from the three signals.
export function deriveLevel(login, impersonation, email) {
  const highSignals = [
    email.spoofable_domains > 0,                             // attackers can send email as you (BEC)
    impersonation.can_send_mail > 0,                         // a lookalike can spoof mail as you
    impersonation.can_host_login > 0,                        // a lookalike can host a phishing login
  ].filter(Boolean).length;
  const mediumSignals = [
    login.internet_facing > 0,                              // exposed login/credential surfaces
    impersonation.active > 0,                               // resolving lookalikes (even without mail/login)
  ].filter(Boolean).length;

  let level = "Low";
  if (highSignals >= 1) level = "High";
  else if (mediumSignals >= 1) level = "Medium";

  const parts = [];
  if (email.spoofable_domains > 0) parts.push(`${email.spoofable_domains} of your ${email.checked_domains} domain${email.checked_domains === 1 ? "" : "s"} can be spoofed in email (weak or missing DMARC)`);
  if (impersonation.active > 0) parts.push(`${impersonation.active} active lookalike domain${impersonation.active === 1 ? "" : "s"}${impersonation.can_send_mail ? ` (${impersonation.can_send_mail} able to send mail as you)` : ""}`);
  if (login.internet_facing > 0) parts.push(`${login.internet_facing} internet-facing login surface${login.internet_facing === 1 ? "" : "s"} where credentials are attacked`);
  const summary = parts.length
    ? `Identity exposure is ${level}: ${parts.join("; ")}.`
    : "No significant identity-exposure signals detected — email authentication, lookalike domains, and exposed login surfaces all look clean.";

  return { identity_exposure_level: level, summary };
}
