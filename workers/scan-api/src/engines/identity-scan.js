// ── Identity provider discovery module ──
// Detects identity/SSO providers (hostname patterns + provider signatures) from collected
// scan data and vendor detection. Extracted verbatim from index.js (monolith decomposition,
// Phase 1c). The signature/pattern tables + collectIdentitySignals are module-internal.
import { detectVendorsFromModules } from "./vendor-signatures.js";

const IDENTITY_PROVIDER_SIGS = [
  // ── Microsoft ────────────────────────────────────────────────────────────
  {
    name:          "Microsoft Entra ID",
    identity_type: "idp",
    risk_score:    20,
    signals: [
      { source: "cname",  test: (v) => /login\.microsoftonline\.com|sts\.windows\.net/.test(v) },
      { source: "csp",    test: (v) => /login\.microsoftonline\.com|login\.live\.com/.test(v) },
      { source: "spf",    test: (v) => /spf\.protection\.outlook\.com/.test(v) },
      { source: "mx",     test: (v) => /\.protection\.outlook\.com/.test(v) },
    ],
  },
  // ── Okta ─────────────────────────────────────────────────────────────────
  {
    name:          "Okta",
    identity_type: "sso",
    risk_score:    20,
    signals: [
      { source: "cname",  test: (v) => /\.okta\.com|\.oktapreview\.com|\.okta-emea\.com/.test(v) },
      { source: "csp",    test: (v) => /okta\.com/.test(v) },
      { source: "server", test: (v) => /okta/i.test(v) },
    ],
  },
  // ── Auth0 ─────────────────────────────────────────────────────────────────
  {
    name:          "Auth0",
    identity_type: "sso",
    risk_score:    20,
    signals: [
      { source: "cname",  test: (v) => /\.auth0\.com|\.us\.auth0\.com|\.eu\.auth0\.com/.test(v) },
      { source: "csp",    test: (v) => /auth0\.com/.test(v) },
    ],
  },
  // ── Ping Identity ─────────────────────────────────────────────────────────
  {
    name:          "Ping Identity",
    identity_type: "sso",
    risk_score:    20,
    signals: [
      { source: "cname",  test: (v) => /\.pingone\.com|\.pingidentity\.com|\.ping\.cloud/.test(v) },
      { source: "csp",    test: (v) => /pingone\.com|pingidentity\.com/.test(v) },
    ],
  },
  // ── OneLogin ──────────────────────────────────────────────────────────────
  {
    name:          "OneLogin",
    identity_type: "sso",
    risk_score:    20,
    signals: [
      { source: "cname",  test: (v) => /\.onelogin\.com/.test(v) },
      { source: "csp",    test: (v) => /onelogin\.com/.test(v) },
      { source: "spf",    test: (v) => /onelogin\.com/.test(v) },
    ],
  },
  // ── Duo Security ──────────────────────────────────────────────────────────
  {
    name:          "Duo",
    identity_type: "sso",
    risk_score:    15,
    signals: [
      { source: "cname",  test: (v) => /\.duosecurity\.com|\.duofed\.com/.test(v) },
      { source: "csp",    test: (v) => /duosecurity\.com|api\.duosecurity\.com/.test(v) },
      { source: "spf",    test: (v) => /duosecurity\.com/.test(v) },
    ],
  },
  // ── JumpCloud ─────────────────────────────────────────────────────────────
  {
    name:          "JumpCloud",
    identity_type: "idp",
    risk_score:    20,
    signals: [
      { source: "cname",  test: (v) => /\.jumpcloud\.com/.test(v) },
      { source: "csp",    test: (v) => /jumpcloud\.com/.test(v) },
      { source: "spf",    test: (v) => /jumpcloud\.com/.test(v) },
      { source: "mx",     test: (v) => /jumpcloud\.com/.test(v) },
    ],
  },
  // ── Google Workspace Identity ─────────────────────────────────────────────
  {
    name:          "Google Workspace Identity",
    identity_type: "idp",
    risk_score:    15,
    signals: [
      { source: "spf",  test: (v) => /_spf\.google\.com/.test(v) },
      { source: "mx",   test: (v) => /aspmx\.l\.google\.com|smtp\.google\.com/.test(v) },
      { source: "cname", test: (v) => /accounts\.google\.com/.test(v) },
    ],
  },
  // ── Keycloak ─────────────────────────────────────────────────────────────
  {
    name:          "Keycloak",
    identity_type: "idp",
    risk_score:    15,
    signals: [
      { source: "server", test: (v) => /keycloak/i.test(v) },
      { source: "cname",  test: (v) => /keycloak/.test(v) },
      { source: "csp",    test: (v) => /keycloak/.test(v) },
    ],
  },
  // ── ADFS (Microsoft on-prem) ──────────────────────────────────────────────
  {
    name:          "Microsoft ADFS",
    identity_type: "saml",
    risk_score:    20,
    signals: [
      { source: "cname",  test: (v) => /adfs\.|sts\./.test(v) },
      { source: "csp",    test: (v) => /\/adfs\//.test(v) },
    ],
  },
  // ── CrowdStrike Falcon Identity ───────────────────────────────────────────
  {
    name:          "CrowdStrike Falcon Identity",
    identity_type: "idp",
    risk_score:    10,
    signals: [
      { source: "cname",  test: (v) => /\.crowdstrike\.com/.test(v) },
      { source: "csp",    test: (v) => /crowdstrike\.com/.test(v) },
    ],
  },
];

// Hostname prefixes that indicate an identity / authentication surface.
// Matched against the leftmost label of each discovered subdomain.
const IDENTITY_HOSTNAME_PATTERNS = [
  { prefix: /^(sso|saml|adfs|federation|fed)\./i,    identity_type: "sso",          risk_score: 20 },
  { prefix: /^(vpn|remote|ra|ssl-vpn|vpn\d)\./i,     identity_type: "vpn",          risk_score: 15 },
  { prefix: /^(idp|identity|iam|sts|auth0?)\./i,      identity_type: "idp",          risk_score: 20 },
  { prefix: /^(login|signin|sign-in|logon)\./i,       identity_type: "login_portal", risk_score: 10 },
  { prefix: /^(oauth|oauth2|openid|oidc)\./i,         identity_type: "oauth",        risk_score: 15 },
  { prefix: /^(mfa|2fa|otp|duo)\./i,                  identity_type: "sso",          risk_score: 15 },
  { prefix: /^(portal|access|myaccess|myid)\./i,      identity_type: "login_portal", risk_score: 10 },
  { prefix: /^(admin|adminpanel|cpanel|wp-admin)\./i, identity_type: "admin_login",  risk_score: 10 },
  { prefix: /^(okta|ping|jumpcloud)\./i,              identity_type: "idp",          risk_score: 20 },
];

/**
 * Extracts signal values from scan modules for IdP matching.
 * Mirrors the logic used in detectVendorsFromModules.
 */
function collectIdentitySignals(modules) {
  const signals = { cname: [], spf: [], mx: [], csp: [], server: [], dkim: [] };

  // CNAME targets from subdomain takeover / asset exposure / DNS brute-force
  for (const risk  of (modules?.subdomain_takeover?.risks   ?? [])) if (risk?.cname)  signals.cname.push(risk.cname);
  for (const asset of (modules?.asset_exposure?.assets       ?? [])) if (asset?.cname) signals.cname.push(asset.cname);
  for (const item  of (modules?.dns_bruteforce?.items        ?? [])) if (item?.cname)  signals.cname.push(item.cname);

  // SPF includes
  for (const inc of (modules?.email_security?.spf?.includes ?? [])) signals.spf.push(inc);

  // MX records
  for (const mx of (modules?.dns?.mx_records ?? [])) signals.mx.push(mx.hostname ?? mx.exchange ?? String(mx));

  // CSP header
  const cspVal = modules?.headers?.security_headers?.content_security_policy?.value ?? "";
  if (cspVal) signals.csp.push(cspVal);

  // Server header
  const serverVal = modules?.headers?.response_headers?.server ?? "";
  if (serverVal) signals.server.push(serverVal);

  return signals;
}

/**
 * runIdentityDiscoveryModule(modules, domain)
 * Phase 7j — pure computation, zero network I/O.
 */
export function runIdentityDiscoveryModule(modules, domain) {
  try {
    const signals  = collectIdentitySignals(modules);
    const providers = [];
    const portals   = [];

    // ── 1. Provider detection ─────────────────────────────────────────────
    for (const sig of IDENTITY_PROVIDER_SIGS) {
      const matched = [];
      for (const s of sig.signals) {
        const vals = signals[s.source] ?? [];
        for (const v of vals) {
          if (s.test(v)) { matched.push({ source: s.source, value: v }); break; }
        }
      }
      if (matched.length === 0) continue;

      providers.push({
        asset_type:         "provider",
        identity_type:      sig.identity_type,
        provider:           sig.name,
        internet_exposed:   true,
        risk_score:         sig.risk_score,
        source:             "identity_discovery",
        evidence:           matched,
        // Sprint 9D: known IdP fingerprint verified via CNAME/SPF/MX/CSP signals
        confidence:         90,
        validation_quality: "excellent",
      });
    }

    // ── 2. Hostname classification ────────────────────────────────────────
    // Collect all discovered hostnames from CT + DNS brute-force.
    const allHostnames = new Set();
    for (const h of (modules?.subdomains?.items ?? []))             allHostnames.add(h);
    for (const item of (modules?.dns_bruteforce?.items ?? []))      allHostnames.add(item.hostname ?? "");

    for (const hostname of allHostnames) {
      if (!hostname) continue;
      for (const pat of IDENTITY_HOSTNAME_PATTERNS) {
        if (pat.prefix.test(hostname)) {
          portals.push({
            asset_type:         "portal",
            identity_type:      pat.identity_type,
            provider:           null,
            hostname,
            internet_exposed:   true,
            risk_score:         pat.risk_score,
            source:             "hostname_pattern",
            evidence:           [{ source: "subdomain_hostname", value: hostname }],
            // Sprint 9D: hostname prefix pattern only — heuristic, no DNS/HTTP confirmation
            confidence:         60,
            validation_quality: "partial",
          });
          break; // one classification per hostname
        }
      }
    }

    const all = [...providers, ...portals];
    const highRisk = all.filter(a => a.risk_score >= 15).length;

    return {
      detected:         all.length > 0,
      total:            all.length,
      provider_count:   providers.length,
      portal_count:     portals.length,
      high_risk_count:  highRisk,
      providers,
      portals,
      source:           "identity_discovery",
      error:            null,
    };
  } catch (err) {
    return {
      detected:        false,
      total:           0,
      provider_count:  0,
      portal_count:    0,
      high_risk_count: 0,
      providers:       [],
      portals:         [],
      source:          "identity_discovery",
      error:           err?.message ?? "Identity discovery failed",
    };
  }
}
