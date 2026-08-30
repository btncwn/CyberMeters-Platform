#!/usr/bin/env node
// RWS.5 semantic mutation gate. Node 24+.
//
// Every mutant is an exact source anchor/replacement applied in a fresh sandbox.
// A kill is valid only when the focused semantic child completes normally, proves
// the exact mutated module URL + SHA it loaded, and returns the exact registered
// failure set. Parse/import/runtime/setup errors are rejected as invalid kills.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const validatorRelative = "scripts/validate-rws5-cookie-ownership.js";
const b2dValidatorRelative = "scripts/validate-email-deadline-evidence.js";
const discover = process.argv.includes("--discover");

const MUTATIONS = Object.freeze([
  {
    id: "b3-m1-material-severity-admission",
    file: "workers/scan-api/src/engines/cyber-mot-domains.js",
    anchor: "    const domainFindings = findings.filter((f) => isActionableFinding(f) && d.match(f));",
    replacement: "    const domainFindings = findings.filter((f) => (SEV_RANK[String(f?.severity || \"\").toLowerCase()] ?? 0) >= 2 && d.match(f));",
    expectedFailures: [
      "B3 actionable HSTS finding stays positive-first under required-evidence failure",
      "B3 low HSTS finding owns Website issue state",
      "B3 low HSTS finding retains count",
      "B3 low HSTS finding retains identity",
      "B3 low HSTS finding retains presentation severity",
      "B3 low SameSite finding owns Website issue state",
      "B3 low SameSite finding retains count and identity",
      "B3 synthetic critical observation owns no domain issue/count/identity",
    ],
  },
  {
    id: "b3-m2-domain-match-only-admission",
    file: "workers/scan-api/src/engines/cyber-mot-domains.js",
    anchor: "    const domainFindings = findings.filter((f) => isActionableFinding(f) && d.match(f));",
    replacement: "    const domainFindings = findings.filter((f) => d.match(f));",
    expectedFailures: [
      "B3 CAA observation owns no domain issue/count/identity",
      "B3 HSTS preload observation owns no domain issue/count/identity",
      "B3 synthetic critical observation owns no domain issue/count/identity",
    ],
  },
  {
    id: "b3-m3-score-impact-as-authority",
    file: "workers/scan-api/src/engines/cyber-mot-domains.js",
    anchor: "    const domainFindings = findings.filter((f) => isActionableFinding(f) && d.match(f));",
    replacement: "    const domainFindings = findings.filter((f) => Number(f?.score_impact) < 0 && d.match(f));",
    expectedFailures: [
      "B3 actionable HSTS finding stays positive-first under required-evidence failure",
      "B3 low HSTS finding owns Website issue state",
      "B3 low HSTS finding retains count",
      "B3 low HSTS finding retains identity",
      "B3 low HSTS finding retains presentation severity",
      "B3 low SameSite finding owns Website issue state",
      "B3 low SameSite finding retains count and identity",
      "B3 synthetic critical observation owns no domain issue/count/identity",
      "cookie appears once in Website Security count",
      "cookie is counted exactly once across all eight domains",
    ],
  },
  {
    id: "b3-m4-observation-severity-promotion",
    file: "workers/scan-api/src/engines/cyber-mot-domains.js",
    anchor: "    const domainFindings = findings.filter((f) => isActionableFinding(f) && d.match(f));",
    replacement: "    const domainFindings = findings.filter((f) => (isActionableFinding(f) || [\"critical\", \"high\"].includes(String(f?.severity || \"\").toLowerCase())) && d.match(f));",
    expectedFailures: ["B3 synthetic critical observation owns no domain issue/count/identity"],
  },
  {
    id: "b3-m5-coverage-before-positive",
    file: "workers/scan-api/src/engines/cyber-mot-domains.js",
    anchor: "    if (domainFindings.length > 0) {",
    replacement: "    if (domainFindings.length > 0 && !anyRequiredInsufficient && !provisional && !signalCoverageLimited) {",
    expectedFailures: ["B3 actionable HSTS finding stays positive-first under required-evidence failure"],
  },
  {
    id: "b3-m6-positive-identity-dropped",
    file: "workers/scan-api/src/engines/cyber-mot-domains.js",
    anchor: "    base.finding_count = domainFindings.length;\n    base.evidence_count = assessed.length;\n    base.finding_ids = [...new Set(domainFindings.map((f) => f.id).filter(Boolean))].sort();",
    replacement: "    base.finding_count = 0;\n    base.evidence_count = assessed.length;\n    base.finding_ids = [];",
    expectedFailures: [
      "B3 actionable HSTS finding stays positive-first under required-evidence failure",
      "B3 low HSTS finding retains count",
      "B3 low HSTS finding retains identity",
      "B3 low SameSite finding retains count and identity",
      "cookie appears once in Website Security count",
      "cookie is counted exactly once across all eight domains",
    ],
  },
  {
    id: "b3-m7-resolver-version-reused",
    file: "workers/scan-api/src/engines/cyber-mot-domains.js",
    anchor: 'export const CYBER_MOT_RESOLVER_VERSION = "2026-08-30.2";',
    replacement: 'export const CYBER_MOT_RESOLVER_VERSION = "2026-08-30.1";',
    expectedFailures: ["B3 resolver version is the explicit evidence-admission mint"],
  },
  {
    id: "b1-explicit-type-removed",
    file: "workers/scan-api/src/engines/dse-findings.js",
    anchor: '      id:             "dse_missing_caa",\n      finding_type:   "observation",',
    replacement: '      id:             "dse_missing_caa",',
    expectedFailures: ["dse_missing_caa: producer emits explicit finding_type"],
  },
  {
    id: "b1-severity-admission-proxy",
    file: "workers/scan-api/src/engines/findings.js",
    anchor: `export function isActionableFinding(finding) {
  return finding?.finding_type === "finding"
    || (finding?.finding_type == null && Number(finding?.score_impact) < 0);
}`,
    replacement: `export function isActionableFinding(finding) {
  return ["critical", "high", "medium"].includes(String(finding?.severity || "").toLowerCase())
    || (finding?.finding_type == null && Number(finding?.score_impact) < 0);
}`,
    expectedFailures: [
      "B3 actionable HSTS finding stays positive-first under required-evidence failure",
      "B3 low HSTS finding owns Website issue state",
      "B3 low HSTS finding retains count",
      "B3 low HSTS finding retains identity",
      "B3 low HSTS finding retains presentation severity",
      "B3 low SameSite finding owns Website issue state",
      "B3 low SameSite finding retains count and identity",
      "B3 synthetic critical observation owns no domain issue/count/identity",
      "TLS-RPT absence observation cannot become actionable from severity",
      "dse_cookie_no_samesite: actionability follows explicit type",
      "dse_hsts_short_maxage: actionability follows explicit type",
      "severity cannot promote an explicit observation",
    ],
  },
  {
    id: "b1-csp-style-promoted",
    file: "workers/scan-api/src/engines/scoring.js",
    anchor: '            finding_type: actionable ? "finding" : "observation",',
    replacement: '            finding_type: "finding",',
    expectedFailures: ["CSP style-only producer is a low observation"],
  },
  {
    id: "b1-csp-quality-bypassed",
    file: "workers/scan-api/src/engines/scoring.js",
    anchor: "    if (responseQualityOk) {",
    replacement: "    if (true) {",
    expectedFailures: [
      "CSP non-200 response admits no weak-policy result",
      "CSP uncertain response admits no weak-policy result",
    ],
  },
  {
    id: "b1-csp-header-wide-substring",
    file: "workers/scan-api/src/engines/headers-scan.js",
    anchor: `  const scriptDanger = ["script-src", "default-src"]
    .map((directive) => ({ directive, tokens: dangerousTokens(directive) }))
    .filter((entry) => entry.tokens.length > 0);`,
    replacement: `  const scriptDanger = raw.toLowerCase().includes("'unsafe-inline'")
    ? [{ directive: "header-wide", tokens: ["'unsafe-inline'"] }]
    : ["script-src", "default-src"]
      .map((directive) => ({ directive, tokens: dangerousTokens(directive) }))
      .filter((entry) => entry.tokens.length > 0);`,
    expectedFailures: [
      "CSP style-only producer is a low observation",
      "CSP style-only producer severity is low",
      "shared CSP classifier identifies style-only weakness",
    ],
  },
  {
    id: "b1-caa-observation-promoted",
    file: "workers/scan-api/src/engines/dse-findings.js",
    anchor: '      id:             "dse_missing_caa",\n      finding_type:   "observation",',
    replacement: '      id:             "dse_missing_caa",\n      finding_type:   "finding",',
    expectedFailures: [
      "B3 CAA observation owns no domain issue/count/identity",
      "dse_missing_caa: actionability follows explicit type",
      "dse_missing_caa: producer emits explicit finding_type",
    ],
  },
  {
    id: "b1-hsts-short-demoted",
    file: "workers/scan-api/src/engines/dse-findings.js",
    anchor: '      id:             "dse_hsts_short_maxage",\n      finding_type:   "finding",',
    replacement: '      id:             "dse_hsts_short_maxage",\n      finding_type:   "observation",',
    expectedFailures: [
      "B3 actionable HSTS finding stays positive-first under required-evidence failure",
      "B3 low HSTS finding owns Website issue state",
      "B3 low HSTS finding retains count",
      "B3 low HSTS finding retains identity",
      "B3 low HSTS finding retains presentation severity",
      "dse_hsts_short_maxage: actionability follows explicit type",
      "dse_hsts_short_maxage: producer emits explicit finding_type",
    ],
  },
  {
    id: "b1-cookie-error-accepted",
    file: "workers/scan-api/src/engines/cookie-observation.js",
    anchor: "  return Boolean(cookies && !cookies.error)",
    replacement: "  return Boolean(cookies)",
    expectedFailures: [
      "DSE errored cookie evidence emits no cookie findings",
      "dse_cookie_no_httponly: unusable cookies are deferred",
      "dse_cookie_no_samesite: unusable cookies are deferred",
      "dse_cookie_no_secure: unusable cookies are deferred",
    ],
  },
  {
    id: "b1-samesite-checks-secure",
    file: "workers/scan-api/src/engines/cookie-observation.js",
    anchor: '  dse_cookie_no_samesite: "no_samesite",',
    replacement: '  dse_cookie_no_samesite: "insecure_count",',
    expectedFailures: [
      "B3 low SameSite finding owns Website issue state",
      "B3 low SameSite finding retains count and identity",
      "dse_cookie_no_samesite: actionability follows explicit type",
      "dse_cookie_no_samesite: found>0 defective is present",
      "dse_cookie_no_samesite: producer emits exact severity",
      "dse_cookie_no_samesite: producer emits explicit finding_type",
      "dse_cookie_no_samesite: producer keeps zero score impact",
      "exactly one managed case opens",
      "found>0 defective remains observed",
      "low-severity SameSite condition is retained by managed lifecycle",
      "new cookie alert is Website Security",
      "new cookie case domain is Website Security",
      "new cookie case keeps the one remediation",
      "new cookie case type is website_case",
      "unchanged defect creates no second case",
    ],
  },
  {
    id: "b1-critical-cert-unmapped-from-expiring",
    file: "workers/scan-api/src/engines/remediation-registry.js",
    anchor: '    finding_types: ["ssl_certificate_expiring_soon", "certificate_expiring_soon", "certificate_expiring_critical"],',
    replacement: '    finding_types: ["ssl_certificate_expiring_soon", "certificate_expiring_soon"],',
    expectedFailures: ["certificate critical maps to expiring action"],
  },
  {
    id: "b1c-m1-critical-severity-restored",
    file: "workers/scan-api/src/engines/cert-intel.js",
    anchor: `        signal:      "certificate_expiring_critical",
        finding_type: "finding",
        severity:    "high",`,
    replacement: `        signal:      "certificate_expiring_critical",
        finding_type: "finding",
        severity:    "critical",`,
    expectedFailures: [
      "certificate expiry 13-day boundary emits high critical-window finding",
      "reachable certificate critical signal is high",
    ],
  },
  {
    id: "b1c-m2-fourteen-enters-critical-window",
    file: "workers/scan-api/src/engines/cert-intel.js",
    anchor: "    if (expiryEvidenceUsable && days_until_expiry < 14) {",
    replacement: "    if (expiryEvidenceUsable && days_until_expiry <= 14) {",
    expectedFailures: [
      "certificate expiry 14-day boundary emits medium soon finding",
      "certificate expiry descriptions stay within returned CT evidence scope",
      "certificate expiry soon description is CT-honest",
      "certificate expiry soon title is producer-owned",
    ],
  },
  {
    id: "b1c-m3-expiry-evidence-guard-dropped",
    file: "workers/scan-api/src/engines/cert-intel.js",
    anchor: `    const expiryEvidenceUsable = Number.isFinite(days_until_expiry) &&
      Number.isInteger(days_until_expiry) && days_until_expiry >= 0 &&
      expiryDateMatchesDayCount;`,
    replacement: `    const expiryEvidenceUsable = days_until_expiry !== null &&
      expiryDateMatchesDayCount;`,
    expectedFailures: ["invalid certificate expiry evidence emits no signal and stays not usable"],
  },
  {
    id: "b1c-m4-negative-emits-scan-time-expired",
    file: "workers/scan-api/src/engines/cert-intel.js",
    anchor: "    if (expiryEvidenceUsable && days_until_expiry < 14) {",
    replacement: `    if (Number.isFinite(days_until_expiry) && days_until_expiry < 0) {
      suspicious_certificate_signals.push({
        signal: "certificate_expired",
        finding_type: "finding",
        severity: "high",
        score_impact: 0,
      });
    } else if (expiryEvidenceUsable && days_until_expiry < 14) {`,
    expectedFailures: [
      "certificate intelligence never emits scan-time expired identity",
      "invalid certificate expiry evidence emits no signal and stays not usable",
    ],
  },
  {
    id: "b1c-m5-ct-evidence-fields-dropped",
    file: "workers/scan-api/src/engines/cert-intel.js",
    anchor: `        evidence_source: "certificate_transparency",
        live_certificate_verified: false,
        evidence_basis: "latest_expiring_logged_certificate",
        title:        "Logged certificate validity ends within 14 days",`,
    replacement: `        title:        "Logged certificate validity ends within 14 days",`,
    expectedFailures: ["certificate expiry evidence is CT-only and not live-verified"],
  },
  {
    id: "b1c-m6-critical-identity-changed",
    file: "workers/scan-api/src/engines/cert-intel.js",
    anchor: '        signal:      "certificate_expiring_critical",',
    replacement: '        signal:      "certificate_expiring_unknown",',
    expectedFailures: [
      "certificate critical maps to expiring action",
      "certificate expiry 13-day boundary emits high critical-window finding",
      "certificate expiry critical description is CT-honest",
      "certificate expiry critical score impact stays zero",
      "certificate expiry critical title is producer-owned",
      "certificate expiry descriptions stay within returned CT evidence scope",
      "certificate expiry evidence is CT-only and not live-verified",
      "reachable certificate critical signal is explicit finding",
      "reachable certificate critical signal is high",
    ],
  },
  {
    id: "b1c-m7-expiry-signal-deducts-score",
    file: "workers/scan-api/src/engines/scoring.js",
    anchor: "  let score = 100;",
    replacement: `  let score = 100;
  if (modules?.certificate_intelligence?.suspicious_certificate_signals
    ?.some((signal) => String(signal?.signal || "").startsWith("certificate_expiring_"))) score -= 5;`,
    expectedFailures: ["certificate expiry signals remain score-neutral"],
  },
  {
    id: "b1c-title-drop",
    file: "workers/scan-api/src/engines/cert-intel.js",
    anchor: '        title:        "Logged certificate validity ends within 14 days",',
    replacement: "",
    expectedFailures: ["certificate expiry critical title is producer-owned"],
  },
  {
    id: "b1c-m8-expiry-date-pair-guard-dropped",
    file: "workers/scan-api/src/engines/cert-intel.js",
    anchor: `    const expiryEvidenceUsable = Number.isFinite(days_until_expiry) &&
      Number.isInteger(days_until_expiry) && days_until_expiry >= 0 &&
      expiryDateMatchesDayCount;`,
    replacement: `    const expiryEvidenceUsable = Number.isFinite(days_until_expiry) &&
      Number.isInteger(days_until_expiry) && days_until_expiry >= 0;`,
    expectedFailures: ["incoherent certificate expiry pairs emit no signal and stay not usable"],
  },
  {
    id: "b1c-m9-universal-ct-claim-restored",
    file: "workers/scan-api/src/engines/cert-intel.js",
    anchor: "The latest-expiring currently valid certificate record returned by the available Certificate Transparency source for ${domain} ends on ${expires_at}",
    replacement: "No currently valid publicly logged certificate covering ${domain} expires later than ${expires_at}",
    expectedFailures: [
      "certificate expiry critical description is CT-honest",
      "certificate expiry descriptions stay within returned CT evidence scope",
      "certificate expiry soon description is CT-honest",
    ],
  },
  {
    id: "b3-m8-score-methodology-moved",
    file: "workers/scan-api/src/engines/scoring.js",
    anchor: 'export const CYBER_METRICS_SCORE_METHODOLOGY_VERSION = "2026-08-26.1";',
    replacement: 'export const CYBER_METRICS_SCORE_METHODOLOGY_VERSION = "2026-08-30.1";',
    expectedFailures: ["score methodology version remains frozen"],
  },
  {
    id: "b1-score-bearing-module-dropped",
    file: "workers/scan-api/src/engines/scoring.js",
    anchor: '  "subdomains",\n  "subdomain_takeover",',
    replacement: '  "subdomains",',
    expectedFailures: ["score-bearing module order remains frozen"],
  },
  {
    id: "b1-legacy-fallback-removed",
    file: "workers/scan-api/src/engines/findings.js",
    anchor: '    || (finding?.finding_type == null && Number(finding?.score_impact) < 0);',
    replacement: "    || false;",
    expectedFailures: ["legacy negative score fallback remains actionable"],
  },
  {
    id: "b1-mta-raw-state-admitted",
    file: "workers/scan-api/src/engines/email-analysis.js",
    anchor: '  const coherent = rawState === "present"',
    replacement: '  const coherent = rawState === "definitive_absent" ? true : rawState === "present"',
    expectedFailures: ["raw MTA-STS absence token alone admits no finding"],
  },
  {
    id: "broad-dse-removal",
    file: "workers/scan-api/src/engines/cookie-observation.js",
    anchor: 'return COOKIE_FINDING_SET.has(String(findingId || ""));',
    replacement: 'return String(findingId || "").startsWith("dse_");',
    expectedFailures: [
      "dse_caa_no_issuers: not dual-owned by Website Security",
      "dse_missing_caa: not dual-owned by Website Security",
    ],
  },
  {
    id: "dual-ownership",
    file: "workers/scan-api/src/engines/cyber-mot-domains.js",
    anchor: `match: (f) => /^(asset_|subdomain_|admin_|takeover_|exposure_|cve_|kev_|cloud_|dns_|dnssec_)/.test(f?.id || ""),`,
    replacement: `match: (f) => /^(asset_|subdomain_|admin_|takeover_|exposure_|dse_|cve_|kev_|cloud_|dns_|dnssec_)/.test(f?.id || ""),`,
    expectedFailures: [
      "cookie is absent from Attack Surface count",
      "cookie is counted exactly once across all eight domains",
      "dse_caa_no_issuers: Attack Surface no longer owns",
      "dse_cookie_no_httponly: Attack Surface no longer owns",
      "dse_cookie_no_samesite: Attack Surface no longer owns",
      "dse_cookie_no_secure: Attack Surface no longer owns",
      "dse_hsts_not_preload_eligible: Attack Surface no longer owns",
      "dse_hsts_short_maxage: Attack Surface no longer owns",
      "dse_missing_caa: Attack Surface no longer owns",
    ],
  },
  {
    id: "zero-cookies-false-resolution",
    file: "workers/scan-api/src/engines/cookie-observation.js",
    anchor: "if (enrich.cookies.found === 0) {",
    replacement: "if (enrich.cookies.found < 0) {",
    expectedFailures: [
      "dse_cookie_no_httponly: found===0 is deferred",
      "dse_cookie_no_httponly: found===0 reason is exact",
      "dse_cookie_no_samesite: found===0 is deferred",
      "dse_cookie_no_samesite: found===0 reason is exact",
      "dse_cookie_no_secure: found===0 is deferred",
      "dse_cookie_no_secure: found===0 reason is exact",
      "found===0 writes no condition_resolved event",
      "historical full-scan cookie case remains awaiting verification",
      "historical full-scan cookie verification defers zero cookies",
      "historical full-scan deferral keeps no_cookies_observed reason",
      "no-cookies: case state",
      "no-cookies: condition state",
      "no-cookies: unknown reason",
    ],
  },
  {
    id: "cookies-usable-only-gate",
    file: "workers/scan-api/src/engines/cookie-observation.js",
    anchor: "const present = enrich.cookies[COOKIE_COUNTER[id]] > 0;",
    replacement: "const present = true;",
    expectedFailures: [
      "dse_cookie_no_httponly: found>0 compliant is clear",
      "dse_cookie_no_samesite: found>0 compliant is clear",
      "dse_cookie_no_secure: found>0 compliant is clear",
    ],
  },
  {
    id: "duplicate-case-creation",
    file: "workers/scan-api/src/engines/website-security-cases.js",
    anchor: "if (historicalAsm) {",
    replacement: "if (false && historicalAsm) {",
    expectedFailures: [
      "Website condition presents the historical case link",
      "historical ASM cookie case suppresses a Website duplicate",
    ],
  },
  {
    id: "wrong-alert-domain",
    file: "workers/scan-api/src/engines/website-security-lifecycle.js",
    anchor: "domain_key: WEBSITE_SECURITY_DOMAIN_KEY",
    replacement: 'domain_key: "attack_surface"',
    replaceAll: true,
    expectedAnchorCount: 2,
    expectedFailures: [
      "both Website lifecycle alert calls use the canonical Website domain constant",
      "new cookie alert is Website Security",
    ],
  },
  {
    id: "historical-case-rewrite",
    file: "workers/scan-api/src/engines/website-security-cases.js",
    anchor: `if (historicalAsm) {\n      await linkConditionToCase(env, workspace_id, record_id, historicalAsm.id);`,
    replacement: `if (historicalAsm) {\n      await env.cybermeters_db.prepare("UPDATE managed_cases SET domain_key = 'website_security' WHERE id = ? AND workspace_id = ?").bind(historicalAsm.id, workspace_id).run();\n      await linkConditionToCase(env, workspace_id, record_id, historicalAsm.id);`,
    expectedFailures: ["historical ASM case row remains byte-equivalent"],
  },
  {
    id: "comparable-historical-transition",
    file: "workers/scan-api/src/engines/cyber-mot-domains.js",
    anchor: 'export const CYBER_MOT_RESOLVER_VERSION = "2026-08-30.2";',
    replacement: 'export const CYBER_MOT_RESOLVER_VERSION = "2026-07-24.4";',
    expectedFailures: [
      "B3 resolver version is the explicit evidence-admission mint",
      "historical/new ownership boundary is not_comparable",
      "resolver version is mechanically bumped from 2026-07-24.4",
    ],
  },
  {
    id: "b2d-d1-tls-admission-removed",
    file: "workers/scan-api/src/engines/scan-engine.js",
    anchor: "      modules.ssl?.tls_state === TLS_RUNTIME_STATES.OBSERVED_PRESENT &&",
    replacement: "      true &&",
    b2dProbe: "tls_unavailable",
  },
  {
    id: "b2d-d2-other-signal-admitted",
    file: "workers/scan-api/src/engines/scan-engine.js",
    anchor: `    const certificateExpiryIds = [
      "certificate_expiring_critical",
      "certificate_expiring_soon",
    ];`,
    replacement: `    const certificateExpiryIds = [
      "certificate_expiring_critical",
      "certificate_expiring_soon",
      "no_https",
    ];`,
    b2dProbe: "contract_exact_ids",
  },
  {
    id: "b2d-d3-live-leaf-claim-restored",
    file: "workers/scan-api/src/engines/scan-engine.js",
    anchor: `            live_certificate_verified: false,
            providers: certificateEvidenceProviders,`,
    replacement: `            live_certificate_verified: true,
            providers: certificateEvidenceProviders,`,
    b2dProbe: "evidence_integrity",
  },
  {
    id: "b2d-d4-numeric-bound-dropped",
    file: "workers/scan-api/src/engines/scan-engine.js",
    anchor: "          !Number.isFinite(days) || !Number.isInteger(days) || !exactBand ||",
    replacement: "          !exactBand ||",
    b2dProbe: "numeric_band",
  },
  {
    id: "b2d-d5-dedupe-removed",
    file: "workers/scan-api/src/engines/scan-engine.js",
    anchor: "        if (sourceRows.length !== 1 || findings.some((finding) => finding?.id === findingId)) continue;",
    replacement: "        if (sourceRows.length < 1) continue;",
    b2dProbe: "source_and_dedupe",
  },
  {
    id: "b2d-d6-score-impact-restored",
    file: "workers/scan-api/src/engines/scan-engine.js",
    anchor: `          severity: source.severity,
          score_impact: 0,
          title: source.title,`,
    replacement: `          severity: source.severity,
          score_impact: -10,
          title: source.title,`,
    b2dProbe: "score_neutral",
  },
  {
    id: "b2d-d7-late-reconcile-disabled",
    file: "workers/scan-api/src/engines/scan-engine.js",
    anchor: "    if (modules.historical_changes) {",
    replacement: "    if (false && modules.historical_changes) {",
    b2dProbe: "late_history",
  },
  {
    id: "b2d-d8-expired-identity-admitted",
    file: "workers/scan-api/src/engines/scan-engine.js",
    anchor: `    const certificateExpiryIds = [
      "certificate_expiring_critical",
      "certificate_expiring_soon",
    ];`,
    replacement: `    const certificateExpiryIds = [
      "certificate_expiring_critical",
      "certificate_expiring_soon",
      "certificate_expired",
    ];`,
    b2dProbe: "contract_exact_ids",
  },
  {
    id: "M-S4CX-1-pdf-finding-title-dropped",
    file: "workers/scan-api/src/engines/pdf.js",
    anchor: [
      'function findingHeading(item, fallbackTitle = "Finding") {',
      '  const severity = typeof item?.severity === "string" ? item.severity.trim() : "";',
      '  return `${severity ? `[${severity.toUpperCase()}] ` : ""}${item?.title || fallbackTitle}`;',
      '}',
    ].join("\n"),
    replacement: [
      'function findingHeading(item, fallbackTitle = "Finding") {',
      '  const severity = typeof item?.severity === "string" ? item.severity.trim() : "";',
      '  return `${severity ? `[${severity.toUpperCase()}] ` : ""}${fallbackTitle}`;',
      '}',
    ].join("\n"),
    s4cxProbe: "pdf_title",
  },
  {
    id: "M-S4CX-2-registry-title-leak",
    file: "workers/scan-api/src/engines/report-snapshot.js",
    anchor: "      title: f.title ?? null,",
    replacement: "      title: rem?.customer_title ?? f.title ?? null,",
    s4cxProbe: "snapshot_title",
  },
  {
    id: "M-S4CX-3-certificate-explanation-lost",
    file: "workers/scan-api/src/engines/report-snapshot.js",
    anchor: "      explanation: f.description ?? f.recommendation ?? null,",
    replacement: '      explanation: String(f?.id || "").startsWith("certificate_") ? null : (f.description ?? f.recommendation ?? null),',
    s4cxProbe: "snapshot_explanation",
  },
  {
    id: "M-S4CX-4-executive-severity-promotion",
    file: "workers/scan-api/src/engines/executive-report.js",
    anchor: "    observed_findings: observed,",
    replacement: `    observed_findings: observed.map((item) =>
      item?.domain_keys?.includes("certificates_trust") && item?.severity === "high"
        ? { ...item, severity: "critical" }
        : item),`,
    s4cxProbe: "executive_severity",
  },
  {
    id: "M-S4CX-5-executive-action-duplicated",
    file: "workers/scan-api/src/engines/executive-report.js",
    anchor: "    remediation_actions: actions,",
    replacement: `    remediation_actions: [
      ...actions,
      ...actions.filter((action) => action?.remediation_id === "cert.expiry.expiring"),
    ],`,
    s4cxProbe: "executive_action",
  },
  {
    id: "M-S4CX-6-frontend-certificate-derivation",
    file: "frontend/src/components/ExecutiveReportV2.jsx",
    anchor: '        <ItemList items={report.observed_findings} emptyLabel="No material findings were observed in this assessment." />',
    replacement: `        <ItemList
          items={report.modules?.certificate_intelligence?.producer_signals?.length
            ? [...(report.observed_findings || []), {
                finding_id: "frontend_synthetic_certificate",
                title: "Logged certificate validity ends within 14 days",
                explanation: "Synthetic frontend certificate projection.",
                severity: "high",
              }]
            : report.observed_findings}
          emptyLabel="No material findings were observed in this assessment."
        />`,
    s4cxFrontendProbe: true,
  },
  {
    id: "second-cookie-verifier",
    file: "workers/scan-api/src/engines/managed-verification.js",
    anchor: "const cookie = evaluateCookieObservation(findingId, enrich, { moduleComplete: true });",
    replacement: 'const cookie = { state: enrich.cookies?.found > 0 && enrich.cookies?.insecure_count > 0 ? "present" : "clear", reason: "duplicate_verifier" };',
    expectedFailures: ["canonical cookie counters are defined only in the shared contract"],
  },
]);

let pass = 0;
let fail = 0;
const ok = (name, condition, detail = "") => {
  if (condition) {
    pass += 1;
    console.log(`PASS ${name}`);
  } else {
    fail += 1;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
};

const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const countOccurrences = (source, anchor) => source.split(anchor).length - 1;
const candidateFingerprints = new Map(
  [...new Set(MUTATIONS.map((mutation) => mutation.file))].map((relative) => [
    relative,
    sha(fs.readFileSync(path.join(root, relative))),
  ]),
);

function makeSandbox(mutation) {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), `rws5-${mutation.id}-`));
  for (const relative of ["database", "shared", "workers/scan-api/src"]) {
    fs.cpSync(path.join(root, relative), path.join(sandbox, relative), { recursive: true });
  }
  fs.mkdirSync(path.join(sandbox, "scripts"), { recursive: true });
  fs.copyFileSync(path.join(root, validatorRelative), path.join(sandbox, validatorRelative));
  fs.copyFileSync(path.join(root, b2dValidatorRelative), path.join(sandbox, b2dValidatorRelative));
  const installed = fs.realpathSync(path.join(root, "workers/scan-api/node_modules"));
  fs.symlinkSync(installed, path.join(sandbox, "workers/scan-api/node_modules"));
  if (mutation.s4cxFrontendProbe) {
    fs.cpSync(path.join(root, "frontend/src"), path.join(sandbox, "frontend/src"), {
      recursive: true,
    });
    for (const file of ["package.json", "vitest.config.js", "vite.config.js"]) {
      fs.copyFileSync(path.join(root, "frontend", file), path.join(sandbox, "frontend", file));
    }
    const frontendInstalled = fs.realpathSync(path.join(root, "frontend/node_modules"));
    fs.symlinkSync(frontendInstalled, path.join(sandbox, "frontend/node_modules"));
  }
  return sandbox;
}

function mutate(sandbox, mutation) {
  const target = path.join(sandbox, mutation.file);
  const original = fs.readFileSync(target, "utf8");
  const count = countOccurrences(original, mutation.anchor);
  const expectedCount = mutation.expectedAnchorCount ?? 1;
  if (count !== expectedCount) throw new Error(`anchor count ${count}, expected ${expectedCount}`);
  const changed = mutation.replaceAll
    ? original.split(mutation.anchor).join(mutation.replacement)
    : original.replace(mutation.anchor, mutation.replacement);
  if (changed === original) throw new Error("replacement made no change");
  fs.writeFileSync(target, changed);
  return { target, digest: sha(fs.readFileSync(target)) };
}

function failuresFrom(output) {
  return [...output.matchAll(/^FAIL ([^\n—]+?)(?: —.*)?$/gm)]
    .map((match) => match[1].trim())
    .sort();
}

function runB2dProbe(sandbox, mutation, mutated) {
  const childMode = ["tls_unavailable"].includes(mutation.b2dProbe)
    ? "b2d-tls-unavailable"
    : ["evidence_integrity", "score_neutral", "late_history"].includes(mutation.b2dProbe)
      ? "b2d-cert13"
      : "b2d-contract";
  const loadedUrl = `${pathToFileURL(fs.realpathSync(mutated.target)).href}?b2d-mutant=${mutation.id}`;
  const child = spawnSync(process.execPath, [path.join(sandbox, b2dValidatorRelative), `--child=${childMode}`], {
    cwd: sandbox,
    encoding: "utf8",
    env: {
      ...process.env,
      EMAIL_DEADLINE_SCAN_ENGINE_MODULE_URL: loadedUrl,
    },
    maxBuffer: 16 * 1024 * 1024,
  });
  let projection = null;
  try { projection = JSON.parse(String(child.stdout || "")); } catch { /* invalid probe below */ }
  const completed = child.status === 0 && !child.signal && projection != null;
  const finding = projection?.findings?.find((row) => row.id === "certificate_expiring_critical");
  const defect = {
    tls_unavailable: () => (projection?.findings || []).length > 0,
    contract_exact_ids: () => projection?.exact_ids === false,
    evidence_integrity: () => finding?.live_certificate_verified !== false ||
      finding?.evidence?.[0]?.live_certificate_verified !== false,
    numeric_band: () => projection?.numeric_band === false,
    source_and_dedupe: () => projection?.exact_source_and_dedupe === false,
    score_neutral: () => finding?.score_impact !== 0,
    late_history: () => !projection?.historical?.new_findings?.some((row) =>
      row.id === "certificate_expiring_critical"),
  }[mutation.b2dProbe];
  return {
    child,
    projection,
    completed,
    exactLoad: projection?.loaded_module_url === loadedUrl &&
      projection?.loaded_module_sha256 === mutated.digest,
    defectDetected: completed && typeof defect === "function" && defect(),
  };
}

function runS4cxProbe(sandbox, mutation, mutated) {
  const child = spawnSync(process.execPath, [
    path.join(sandbox, b2dValidatorRelative),
    "--child=b2d-cx",
  ], {
    cwd: sandbox,
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
  });
  let projection = null;
  try { projection = JSON.parse(String(child.stdout || "")); } catch { /* invalid probe below */ }
  const completed = child.status === 0 && !child.signal && projection != null;
  const candidate = projection?.cert13;
  const snapshotItem = candidate?.snapshot_cert_findings?.find((item) =>
    item.finding_id === "certificate_expiring_critical");
  const producer = candidate?.producer_signals?.find((signal) =>
    signal.signal === "certificate_expiring_critical");
  const executiveItem = candidate?.executive?.observed_findings?.find((item) =>
    item.finding_id === "certificate_expiring_critical");
  const executiveActions = candidate?.executive?.remediation_actions?.filter((action) =>
    action.remediation_id === "cert.expiry.expiring") || [];
  const moduleKey = {
    pdf_title: "pdf",
    snapshot_title: "report_snapshot",
    snapshot_explanation: "report_snapshot",
    executive_severity: "executive_report",
    executive_action: "executive_report",
  }[mutation.s4cxProbe];
  const loaded = candidate?.loaded_modules?.[moduleKey];
  const expectedUrl = pathToFileURL(fs.realpathSync(mutated.target)).href;
  const defect = {
    pdf_title: () => !candidate?.pdf_text?.includes(
      "[HIGH] Logged certificate validity ends within 14 days",
    ) && candidate?.pdf_text?.includes("[HIGH] Finding"),
    snapshot_title: () => snapshotItem?.title !== producer?.title &&
      snapshotItem?.title === "Renew the certificate before expiry",
    snapshot_explanation: () => snapshotItem?.explanation == null &&
      typeof producer?.description === "string",
    executive_severity: () => snapshotItem?.severity === "high" &&
      executiveItem?.severity === "critical",
    executive_action: () => candidate?.cert_actions?.length === 1 &&
      executiveActions.length === 2,
  }[mutation.s4cxProbe];
  return {
    child,
    completed,
    exactLoad: loaded?.url === expectedUrl && loaded?.sha256 === mutated.digest,
    defectDetected: completed && typeof defect === "function" && defect(),
  };
}

function runS4cxFrontendProbe(sandbox, mutation, mutated) {
  const child = spawnSync(path.join(sandbox, "frontend/node_modules/.bin/vitest"), [
    "run",
    "src/components/__tests__/ExecutiveReportV2.report-first.test.jsx",
    "-t",
    "renders the real S4 certificate finding and never derives it from raw module diagnostics",
  ], {
    cwd: path.join(sandbox, "frontend"),
    encoding: "utf8",
    env: {
      ...process.env,
      B2B_PROOF_REPO_ROOT: sandbox,
    },
    maxBuffer: 32 * 1024 * 1024,
  });
  const rawOutput = `${child.stdout || ""}${child.stderr || ""}`;
  const output = rawOutput.replace(/\u001B(?:\[[0-?]*[ -/]*[@-~]|[@-_])/g, "");
  const expectedFailure =
    "renders the real S4 certificate finding and never derives it from raw module diagnostics";
  const invalidKill = /(?:SyntaxError|TypeError|ReferenceError|ERR_MODULE_NOT_FOUND|failed to (?:load|resolve)|cannot find (?:module|package)|no test files found|setup(?: file)? (?:failed|error))/i.test(output);
  const completed = child.status === 1 && !child.signal &&
    output.includes(expectedFailure) &&
    !invalidKill;
  return {
    child,
    completed,
    exactLoad: pathToFileURL(fs.realpathSync(mutated.target)).href.endsWith(
      "/frontend/src/components/ExecutiveReportV2.jsx",
    ) && sha(fs.readFileSync(mutated.target)) === mutated.digest,
    defectDetected: completed &&
      /Logged certificate validity ends within 14 days/.test(output),
  };
}

ok("mutation registry is exact, ordered and unique",
  MUTATIONS.length === 54 && new Set(MUTATIONS.map((mutation) => mutation.id)).size === MUTATIONS.length);

for (const mutation of MUTATIONS) {
  let sandbox = null;
  try {
    sandbox = makeSandbox(mutation);
    const mutated = mutate(sandbox, mutation);
    ok(`${mutation.id}: exact anchor/replacement preflight`, true);

    if (mutation.b2dProbe) {
      const probe = runB2dProbe(sandbox, mutation, mutated);
      ok(`${mutation.id}: focused B2d child completed without invalid kill`,
        probe.completed,
        `${probe.child.stdout || ""}${probe.child.stderr || ""}`.slice(-1200));
      ok(`${mutation.id}: exact loaded-module URL and SHA proof`, probe.exactLoad);
      ok(`${mutation.id}: isolated B2d contract regression detected`,
        probe.defectDetected,
        JSON.stringify(probe.projection));
      continue;
    }

    if (mutation.s4cxProbe) {
      const probe = runS4cxProbe(sandbox, mutation, mutated);
      ok(`${mutation.id}: focused S4 CX child completed without invalid kill`,
        probe.completed,
        `${probe.child.stdout || ""}${probe.child.stderr || ""}`.slice(-1200));
      ok(`${mutation.id}: exact loaded-module URL and SHA proof`, probe.exactLoad);
      ok(`${mutation.id}: isolated S4 customer-output regression detected`,
        probe.defectDetected);
      continue;
    }

    if (mutation.s4cxFrontendProbe) {
      const probe = runS4cxFrontendProbe(sandbox, mutation, mutated);
      ok(`${mutation.id}: focused S4 frontend child completed without invalid kill`,
        probe.completed,
        `${probe.child.stdout || ""}${probe.child.stderr || ""}`.slice(-1200));
      ok(`${mutation.id}: exact loaded-module URL and SHA proof`, probe.exactLoad);
      ok(`${mutation.id}: isolated frontend derivation regression detected`,
        probe.defectDetected);
      continue;
    }

    const child = spawnSync(process.execPath, [path.join(sandbox, validatorRelative)], {
      cwd: sandbox,
      encoding: "utf8",
      env: {
        ...process.env,
        RWS5_EXPECT_MUTATED_FILE: mutation.file,
        RWS5_EXPECT_MUTATED_SHA256: mutated.digest,
      },
      maxBuffer: 16 * 1024 * 1024,
    });
    const output = `${child.stdout || ""}${child.stderr || ""}`;
    const completedSemantically = child.status === 1
      && !child.signal
      && /RWS\.5 cookie ownership: \d+\/\d+ passed/.test(output)
      && /RWS\.5 cookie ownership validation FAILED/.test(output)
      && !/(?:SyntaxError|TypeError|ReferenceError|ERR_MODULE_NOT_FOUND|mutation setup mismatch)/.test(output);
    ok(`${mutation.id}: semantic child completed without invalid kill`, completedSemantically,
      completedSemantically ? "" : output.slice(-1200));

    const expectedUrl = `LOADED_MUTATED_MODULE_URL=${pathToFileURL(fs.realpathSync(mutated.target)).href}`;
    const expectedSha = `LOADED_MUTATED_MODULE_SHA256=${mutated.digest}`;
    ok(`${mutation.id}: exact loaded-module URL and SHA proof`,
      output.includes(expectedUrl) && output.includes(expectedSha));

    const actualFailures = failuresFrom(output);
    if (discover) {
      console.log(`DISCOVER ${mutation.id} ${JSON.stringify(actualFailures)}`);
      ok(`${mutation.id}: discover produced a semantic failure set`, actualFailures.length > 0);
    } else {
      ok(`${mutation.id}: exact expected failure set`,
        JSON.stringify(actualFailures) === JSON.stringify([...mutation.expectedFailures].sort()),
        `got ${JSON.stringify(actualFailures)} want ${JSON.stringify([...mutation.expectedFailures].sort())}`);
    }
  } catch (error) {
    ok(`${mutation.id}: mutation setup`, false, error?.stack || error?.message);
  } finally {
    if (sandbox && sandbox.startsWith(os.tmpdir() + path.sep) && path.basename(sandbox).startsWith("rws5-")) {
      fs.rmSync(sandbox, { recursive: true, force: true });
    }
  }
}

for (const [relative, before] of candidateFingerprints) {
  ok(`${relative}: candidate source fingerprint preserved`, sha(fs.readFileSync(path.join(root, relative))) === before);
}

console.log(`\nRWS.5 cookie ownership mutations: ${pass}/${pass + fail} assertions passed; ${MUTATIONS.length} registry-derived mutants`);
if (fail > 0) {
  console.error("RWS.5 cookie ownership mutation validation FAILED");
  process.exit(1);
}
console.log("RWS.5 cookie ownership mutation validation passed");
