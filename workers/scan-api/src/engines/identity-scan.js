// ── Identity provider discovery module ──
// Detects identity/SSO providers (hostname patterns + provider signatures) from collected
// scan data and vendor detection. Extracted verbatim from index.js (monolith decomposition,
// Phase 1c). The signature/pattern tables + collectIdentitySignals are module-internal.
import { detectVendorsFromModules } from "./vendor-signatures.js";
import {
  aggregateIdentityNameResolution,
  createIdentityEvidenceDatum,
  identityConfidenceForPrecision,
  normalizeIdentityObservedAt,
  strongestIdentityConfidence,
} from "./identity-evidence-contract.js";

export function canonicalSignalHostname(value) {
  return String(value ?? "").trim().toLowerCase().replace(/\.$/, "");
}

export function matchesAdfsCname(value) {
  const hostname = canonicalSignalHostname(value);
  return hostname.split(".").at(-1) !== "" && /(^|\.)(adfs|sts)\./.test(hostname)
    && !/(^|\.)(windows\.net|microsoftonline\.com)$/.test(hostname);
}

const DISCLOSED_WEAK_TOKEN_PRECISION = "token_substring";

const IDENTITY_PROVIDER_SIGS = [
  // ── Microsoft ────────────────────────────────────────────────────────────
  {
    name:          "Microsoft Entra ID",
    identity_type: "idp",
    risk_score:    20,
    signals: [
      { source: "cname", match_precision: "host_substring", test: (v) => /login\.microsoftonline\.com|sts\.windows\.net/.test(v) },
      { source: "csp", match_precision: "token_substring", test: (v) => /login\.microsoftonline\.com|login\.live\.com/.test(v) },
      { source: "spf", match_precision: "host_substring", test: (v) => /spf\.protection\.outlook\.com/.test(v) },
      { source: "mx", match_precision: "host_substring", test: (v) => /\.protection\.outlook\.com/.test(v) },
    ],
  },
  // ── Okta ─────────────────────────────────────────────────────────────────
  {
    name:          "Okta",
    identity_type: "sso",
    risk_score:    20,
    signals: [
      { source: "cname", match_precision: "host_substring", test: (v) => /\.okta\.com|\.oktapreview\.com|\.okta-emea\.com/.test(v) },
      { source: "csp", match_precision: "token_substring", test: (v) => /okta\.com/.test(v) },
      { source: "server", match_precision: DISCLOSED_WEAK_TOKEN_PRECISION, test: (v) => /okta/i.test(v) },
    ],
  },
  // ── Auth0 ─────────────────────────────────────────────────────────────────
  {
    name:          "Auth0",
    identity_type: "sso",
    risk_score:    20,
    signals: [
      { source: "cname", match_precision: "host_substring", test: (v) => /\.auth0\.com|\.us\.auth0\.com|\.eu\.auth0\.com/.test(v) },
      { source: "csp", match_precision: "token_substring", test: (v) => /auth0\.com/.test(v) },
    ],
  },
  // ── Ping Identity ─────────────────────────────────────────────────────────
  {
    name:          "Ping Identity",
    identity_type: "sso",
    risk_score:    20,
    signals: [
      { source: "cname", match_precision: "host_substring", test: (v) => /\.pingone\.com|\.pingidentity\.com|\.ping\.cloud/.test(v) },
      { source: "csp", match_precision: "token_substring", test: (v) => /pingone\.com|pingidentity\.com/.test(v) },
    ],
  },
  // ── OneLogin ──────────────────────────────────────────────────────────────
  {
    name:          "OneLogin",
    identity_type: "sso",
    risk_score:    20,
    signals: [
      { source: "cname", match_precision: "host_substring", test: (v) => /\.onelogin\.com/.test(v) },
      { source: "csp", match_precision: "token_substring", test: (v) => /onelogin\.com/.test(v) },
      { source: "spf", match_precision: "host_substring", test: (v) => /onelogin\.com/.test(v) },
    ],
  },
  // ── Duo Security ──────────────────────────────────────────────────────────
  {
    name:          "Duo",
    identity_type: "sso",
    risk_score:    15,
    signals: [
      { source: "cname", match_precision: "host_substring", test: (v) => /\.duosecurity\.com|\.duofed\.com/.test(v) },
      { source: "csp", match_precision: "token_substring", test: (v) => /duosecurity\.com|api\.duosecurity\.com/.test(v) },
      { source: "spf", match_precision: "host_substring", test: (v) => /duosecurity\.com/.test(v) },
    ],
  },
  // ── JumpCloud ─────────────────────────────────────────────────────────────
  {
    name:          "JumpCloud",
    identity_type: "idp",
    risk_score:    20,
    signals: [
      { source: "cname", match_precision: "host_substring", test: (v) => /\.jumpcloud\.com/.test(v) },
      { source: "csp", match_precision: "token_substring", test: (v) => /jumpcloud\.com/.test(v) },
      { source: "spf", match_precision: "host_substring", test: (v) => /jumpcloud\.com/.test(v) },
      { source: "mx", match_precision: "host_substring", test: (v) => /jumpcloud\.com/.test(v) },
    ],
  },
  // ── Google Workspace Identity ─────────────────────────────────────────────
  {
    name:          "Google Workspace Identity",
    identity_type: "idp",
    risk_score:    15,
    signals: [
      { source: "spf", match_precision: "host_substring", test: (v) => /_spf\.google\.com/.test(v) },
      { source: "mx", match_precision: "host_substring", test: (v) => /aspmx\.l\.google\.com|smtp\.google\.com/.test(v) },
      { source: "cname", match_precision: "host_substring", test: (v) => /accounts\.google\.com/.test(v) },
    ],
  },
  // ── Keycloak ─────────────────────────────────────────────────────────────
  {
    name:          "Keycloak",
    identity_type: "idp",
    risk_score:    15,
    signals: [
      { source: "server", match_precision: "token_substring", test: (v) => /keycloak/i.test(v) },
      { source: "cname", match_precision: "token_substring", test: (v) => /keycloak/.test(v) },
      { source: "csp", match_precision: DISCLOSED_WEAK_TOKEN_PRECISION, test: (v) => /keycloak/.test(v) },
    ],
  },
  // ── ADFS (Microsoft on-prem) ──────────────────────────────────────────────
  {
    name:          "Microsoft ADFS",
    identity_type: "saml",
    risk_score:    20,
    signals: [
      { source: "cname", match_precision: "label_boundary", test: matchesAdfsCname },
      { source: "csp", match_precision: "token_substring", test: (v) => /\/adfs\//.test(v) },
    ],
  },
  // ── CrowdStrike Falcon Identity ───────────────────────────────────────────
  {
    name:          "CrowdStrike Falcon Identity",
    identity_type: "idp",
    risk_score:    10,
    signals: [
      { source: "cname", match_precision: "host_substring", test: (v) => /\.crowdstrike\.com/.test(v) },
      { source: "csp", match_precision: "token_substring", test: (v) => /crowdstrike\.com/.test(v) },
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
export function collectIdentitySignals(modules) {
  const signals = { cname: [], spf: [], mx: [], csp: [], server: [], dkim: [] };

  const add = (source, value, module, path) => {
    if (value == null || String(value).trim() === "") return;
    signals[source].push({
      source,
      value,
      provenance: { producer: "identity_discovery", module, path },
    });
  };

  // CNAME targets from subdomain takeover / asset exposure / DNS brute-force
  for (const risk of (modules?.subdomain_takeover?.risks ?? [])) add("cname", risk?.cname, "subdomain_takeover", "risks[].cname");
  for (const asset of (modules?.asset_exposure?.assets ?? [])) add("cname", asset?.cname, "asset_exposure", "assets[].cname");
  for (const item of (modules?.dns_bruteforce?.items ?? [])) add("cname", item?.cname, "dns_bruteforce", "items[].cname");

  // SPF includes
  for (const inc of (modules?.email_security?.spf?.includes ?? [])) add("spf", inc, "email_security", "spf.includes[]");

  // MX records. dns-scan.js emits {value, ttl}; legacy strings/keys stay readable.
  for (const mx of (modules?.dns?.mx_records ?? [])) {
    const value = typeof mx === "string" ? mx : mx?.value ?? mx?.hostname ?? mx?.exchange;
    const key = typeof mx === "string" ? null : mx?.value != null ? "value" : mx?.hostname != null ? "hostname" : mx?.exchange != null ? "exchange" : null;
    if (value != null) add("mx", value, "dns", key ? `mx_records[].${key}` : "mx_records[]");
  }

  // CSP header
  const cspVal = modules?.headers?.security_headers?.content_security_policy?.value ?? "";
  add("csp", cspVal, "headers", "security_headers.content_security_policy.value");

  // Server header
  const serverVal = modules?.headers?.response_headers?.server ?? "";
  add("server", serverVal, "headers", "response_headers.server");

  return signals;
}

function dnsBruteforceEvidenceIsPublishable(moduleResult) {
  return Boolean(moduleResult) && !moduleResult.error && moduleResult.outcome !== "deadline_exceeded" &&
    moduleResult.executed !== false && moduleResult.incomplete !== true;
}

function addHostEvidence(hostSources, hostnameValue, evidence) {
  const canonicalHostname = canonicalSignalHostname(hostnameValue);
  if (!canonicalHostname) return;
  const current = hostSources.get(canonicalHostname) ?? {
    display_hostname: String(hostnameValue).trim().replace(/\.$/, ""),
    evidence: [],
  };
  const dedupeKey = [
    evidence.source,
    evidence.provenance.module,
    evidence.provenance.path,
    String(evidence.value ?? ""),
    evidence.nameResolution,
  ].join("\u0000");
  if (!current.evidence.some((item) => item.dedupeKey === dedupeKey)) {
    current.evidence.push({ ...evidence, dedupeKey });
  }
  hostSources.set(canonicalHostname, current);
}

/**
 * runIdentityDiscoveryModule(modules, domain)
 * Phase 7j — pure computation, zero network I/O.
 */
export function runIdentityDiscoveryModule(modules, domain, { observedAt = null } = {}) {
  try {
    const evidenceObservedAt = normalizeIdentityObservedAt(observedAt);
    const signals  = collectIdentitySignals(modules);
    const providers = [];
    const portals   = [];

    // ── 1. Provider detection ─────────────────────────────────────────────
    for (const sig of IDENTITY_PROVIDER_SIGS) {
      const matched = [];
      for (const s of sig.signals) {
        const vals = signals[s.source] ?? [];
        for (const datum of vals) {
          if (s.test(canonicalSignalHostname(datum.value))) {
            matched.push(createIdentityEvidenceDatum({
              source: s.source,
              value: datum.value,
              provenance: datum.provenance,
              matchPrecision: s.match_precision,
              nameResolution: "not_evaluated",
              validationState: "observed",
              confidenceSubject: "provider_identification",
              observedAt: evidenceObservedAt,
            }));
            break;
          }
        }
      }
      if (matched.length === 0) continue;

      const confidenceDetail = strongestIdentityConfidence(matched, "provider_identification");

      providers.push({
        asset_type:         "provider",
        identity_type:      sig.identity_type,
        provider:           sig.name,
        internet_exposed:   true,
        risk_score:         sig.risk_score,
        source:             "identity_discovery",
        evidence:           matched,
        confidence:         90,
        confidence_detail:  confidenceDetail,
        validation_quality: "excellent",
        validation_state:   "observed",
        name_resolution:    aggregateIdentityNameResolution(matched, "valid_v2"),
      });
    }

    // ── 2. Hostname classification ────────────────────────────────────────
    // Preserve every real CT/DNS provenance item for the same hostname.
    const hostSources = new Map();
    for (const item of (modules?.subdomains?.items ?? [])) {
      const hostname = typeof item === "string" ? item : item?.hostname;
      addHostEvidence(hostSources, hostname, {
        source: "certificate_transparency",
        value: hostname,
        provenance: { producer: "identity_discovery", module: "subdomains", path: "items[]" },
        nameResolution: "not_evaluated",
        validationState: "observed",
      });
    }

    const dnsEvidencePublishable = dnsBruteforceEvidenceIsPublishable(modules?.dns_bruteforce);
    if (dnsEvidencePublishable) {
      for (const item of (modules?.dns_bruteforce?.items ?? [])) {
        const hostname = item?.hostname;
        const addresses = Array.isArray(item?.ip_addresses)
          ? item.ip_addresses.map((value) => String(value).trim()).filter(Boolean)
          : [];
        const mailOnly = item?.source === "dns_mx" || item?.mail_only === true;
        addHostEvidence(hostSources, hostname, {
          source: mailOnly ? "dns_mx" : "dns_bruteforce",
          value: hostname,
          provenance: { producer: "identity_discovery", module: "dns_bruteforce", path: "items[]" },
          nameResolution: mailOnly ? "mx_only" : addresses.length > 0 ? "resolved" : "not_evaluated",
          validationState: mailOnly || addresses.length > 0 ? "observed" : "source_incomplete",
          ipAddresses: addresses,
        });
      }
    }

    for (const { display_hostname: hostname, evidence: sourceEvidence } of hostSources.values()) {
      for (const pat of IDENTITY_HOSTNAME_PATTERNS) {
        if (pat.prefix.test(hostname)) {
          const evidence = sourceEvidence.map(({ dedupeKey: _dedupeKey, ...item }) => createIdentityEvidenceDatum({
            source: item.source,
            value: item.value,
            provenance: item.provenance,
            matchPrecision: "hostname_prefix",
            nameResolution: item.nameResolution,
            validationState: item.validationState,
            confidenceSubject: "hostname_classification",
            observedAt: evidenceObservedAt,
            ipAddresses: item.ipAddresses,
          }));
          portals.push({
            asset_type:         "portal",
            identity_type:      pat.identity_type,
            provider:           null,
            hostname,
            internet_exposed:   true,
            risk_score:         pat.risk_score,
            source:             "hostname_pattern",
            evidence,
            confidence:         60,
            confidence_detail:  identityConfidenceForPrecision("hostname_prefix", "hostname_classification"),
            validation_quality: "partial",
            validation_state:   evidence.some((item) => item.validation_state === "source_incomplete") ? "source_incomplete" : "observed",
            name_resolution:    aggregateIdentityNameResolution(evidence, "valid_v2"),
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
