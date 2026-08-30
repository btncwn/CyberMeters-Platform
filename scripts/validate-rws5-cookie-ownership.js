#!/usr/bin/env node
// RWS.5 — Option A + H-A focused contract. Node 24+.
//
// This gate drives the real resolver, Website lifecycle/case factory, remediation
// registry and history comparator. It deliberately uses the repository schema in an
// in-memory D1-compatible harness so tenant, soft-delete and immutable-legacy-case
// behaviour are executable claims rather than source-string assertions.

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = (...parts) => path.join(root, "workers", "scan-api", "src", ...parts);
const eng = (name) => pathToFileURL(src("engines", name)).href;

if (process.env.RWS5_EXPECT_MUTATED_FILE || process.env.RWS5_EXPECT_MUTATED_SHA256) {
  const relative = process.env.RWS5_EXPECT_MUTATED_FILE || "";
  const target = path.join(root, ...relative.split("/"));
  const bytes = fs.readFileSync(target);
  const digest = crypto.createHash("sha256").update(bytes).digest("hex");
  if (digest !== process.env.RWS5_EXPECT_MUTATED_SHA256) {
    throw new Error(`RWS5 mutation setup mismatch for ${relative}`);
  }
  await import(`${pathToFileURL(target).href}?mutation_sha=${digest}`);
  console.log(`LOADED_MUTATED_MODULE_URL=${pathToFileURL(target).href}`);
  console.log(`LOADED_MUTATED_MODULE_SHA256=${digest}`);
}

let pass = 0;
let fail = 0;
const ok = (name, condition, detail = "") => {
  if (condition) pass += 1;
  else {
    fail += 1;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
};
const eq = (name, got, want) => ok(name, JSON.stringify(got) === JSON.stringify(want), `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);

const COOKIE_IDS = Object.freeze([
  "dse_cookie_no_secure",
  "dse_cookie_no_httponly",
  "dse_cookie_no_samesite",
]);
const CAA_IDS = Object.freeze([
  "dse_missing_caa",
  "dse_caa_no_issuers",
]);
const HSTS_IDS = Object.freeze([
  "dse_hsts_short_maxage",
  "dse_hsts_not_preload_eligible",
]);

let cookieContract = null;
try { cookieContract = await import(eng("cookie-observation.js")); } catch { /* fail-first */ }
const domains = await import(eng("cyber-mot-domains.js"));
const history = await import(eng("cyber-mot-state-history.js"));
const lifecycle = await import(eng("website-security-lifecycle.js"));
const websiteCases = await import(eng("website-security-cases.js"));
const remediation = await import(eng("remediation-registry.js"));
const asmCases = await import(eng("asm-cases.js"));
const managedVerification = await import(eng("managed-verification.js"));
const dseFindings = await import(eng("dse-findings.js"));
const findingsContract = await import(eng("findings.js"));
const scoring = await import(eng("scoring.js"));
const headersContract = await import(eng("headers-scan.js"));
const certIntel = await import(eng("cert-intel.js"));
const emailAnalysis = await import(eng("email-analysis.js"));

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (filename) => {
    try { db.exec(fs.readFileSync(filename, "utf8")); } catch { /* schema already includes additive migrations */ }
  };
  apply(path.join(root, "database", "schema.sql"));
  for (const file of fs.readdirSync(path.join(root, "database", "migrations")).filter((name) => name.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", file));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}

function makeD1(db) {
  const wrap = (sql, args) => ({
    first: async (column) => {
      const row = db.prepare(sql).get(...args) ?? null;
      return column && row ? row[column] : row;
    },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => {
      const result = db.prepare(sql).run(...args);
      return { success: true, meta: { changes: result.changes } };
    },
  });
  return {
    prepare(sql) {
      const direct = wrap(sql, []);
      direct.bind = (...args) => wrap(sql, args);
      return direct;
    },
  };
}

function seed(db) {
  db.prepare("INSERT INTO users (id,email,name,plan,created_at) VALUES ('u1','one@example.test','One','business',datetime('now'))").run();
  db.prepare("INSERT INTO users (id,email,name,plan,created_at) VALUES ('u2','two@example.test','Two','business',datetime('now'))").run();
  for (const [workspace, owner] of [["ws1", "u1"], ["ws2", "u2"]]) {
    db.prepare("INSERT INTO workspaces (id,owner_user_id,name) VALUES (?,?,?)").run(workspace, owner, workspace);
    db.prepare(`INSERT OR IGNORE INTO alert_activation
      (id,workspace_id,domain_key,activated_at,baseline_count,created_at)
      VALUES (?,?,'website_security','2020-01-01T00:00:00Z',0,datetime('now'))`).run(`act_${workspace}`, workspace);
  }
  db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('d1','u1','shared.example.test')").run();
  db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('d2','u2','shared.example.test')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES ('ws1','d1')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES ('ws2','d2')").run();
}

function cookieEvidence({ found = 1, insecure = 0, noHttpOnly = 0, noSameSite = 0, error = null } = {}) {
  return {
    caa: { present: true, records: [], issuers: ["example"], error: null },
    hsts: { present: true, max_age: 31_536_000, preload_eligible: true, error: null },
    cookies: {
      found,
      cookies: Array.from({ length: found }, (_, i) => ({ name: `c${i}` })),
      insecure_count: insecure,
      no_httponly: noHttpOnly,
      no_samesite: noSameSite,
      error,
    },
    source: "dns_headers_analysis",
    error: null,
  };
}

function context(enrich, { quality = "complete", moduleError = null } = {}) {
  const value = moduleError ? { ...enrich, error: moduleError } : enrich;
  return {
    modules: { domain_security_enrichment: value, headers: { values: {} }, ssl: { available: true } },
    scanQuality: { status: quality, modules_skipped: quality === "partial" ? ["domain_security_enrichment"] : [] },
  };
}

const finding = (id) => ({
  id,
  finding_type: "finding",
  module: "domain_security_enrichment",
  severity: id === "dse_cookie_no_secure" ? "high" : id === "dse_cookie_no_httponly" ? "medium" : "low",
  title: id,
  description: id,
  recommendation: "Set the canonical cookie attributes.",
  affected_hosts: ["shared.example.test"],
});

async function baseline(env, workspace = "ws1", domainId = "d1") {
  return lifecycle.evaluateWebsiteSecurityForScan(env, {
    workspace_id: workspace,
    domain_id: domainId,
    domain: "shared.example.test",
    scan_id: `${workspace}-baseline`,
    findings: [],
    ...context(cookieEvidence({ found: 0 })),
  });
}

async function evaluate(env, {
  workspace = "ws1", domainId = "d1", scanId = "scan-1", findings = [],
  enrich = cookieEvidence(), quality = "complete", moduleError = null,
} = {}) {
  return lifecycle.evaluateWebsiteSecurityForScan(env, {
    workspace_id: workspace,
    domain_id: domainId,
    domain: "shared.example.test",
    scan_id: scanId,
    findings,
    ...context(enrich, { quality, moduleError }),
  });
}

function condition(db, workspace, id) {
  return db.prepare("SELECT * FROM website_security_conditions WHERE workspace_id=? AND condition_key=?").get(workspace, id) || null;
}

function cases(db, workspace) {
  return db.prepare("SELECT * FROM managed_cases WHERE workspace_id=? ORDER BY rowid").all(workspace);
}

// 1. One neutral canonical observation contract.
ok("shared cookie observation module loads", Boolean(cookieContract));
eq("cookie registry is exact", cookieContract?.COOKIE_FINDING_TYPES, COOKIE_IDS);
if (cookieContract) {
  for (const id of COOKIE_IDS) {
    const defect = id === "dse_cookie_no_secure" ? { insecure: 1 }
      : id === "dse_cookie_no_httponly" ? { noHttpOnly: 1 }
      : { noSameSite: 1 };
    eq(`${id}: found>0 defective is present`, cookieContract.evaluateCookieObservation(id, cookieEvidence(defect), { moduleComplete: true })?.state, "present");
    eq(`${id}: found>0 compliant is clear`, cookieContract.evaluateCookieObservation(id, cookieEvidence(), { moduleComplete: true })?.state, "clear");
    const none = cookieContract.evaluateCookieObservation(id, cookieEvidence({ found: 0 }), { moduleComplete: true });
    eq(`${id}: found===0 is deferred`, none?.state, "deferred");
    eq(`${id}: found===0 reason is exact`, none?.reason, "no_cookies_observed");
    eq(`${id}: incomplete module is deferred`, cookieContract.evaluateCookieObservation(id, cookieEvidence(defect), { moduleComplete: false })?.state, "deferred");
    eq(`${id}: unusable cookies are deferred`, cookieContract.evaluateCookieObservation(id, cookieEvidence({ ...defect, error: "failed" }), { moduleComplete: true })?.state, "deferred");
  }
}

// Producer-owned evidence admission: type is explicit and severity never promotes
// an observation. Invalid/absent evidence produces no DSE card.
const dseCases = [
  {
    id: "dse_missing_caa", type: "observation", severity: "low",
    enrich: { ...cookieEvidence(), caa: { present: false, records: [], issuers: [], error: null } },
  },
  {
    id: "dse_caa_no_issuers", type: "observation", severity: "low",
    enrich: { ...cookieEvidence(), caa: { present: true, records: ['0 iodef "mailto:security@example.test"'], issuers: [], error: null } },
  },
  {
    id: "dse_hsts_short_maxage", type: "finding", severity: "low",
    enrich: { ...cookieEvidence(), hsts: { present: true, max_age: 86_400, include_subdomains: true, preload_directive: true, preload_eligible: false, error: null } },
  },
  {
    id: "dse_hsts_not_preload_eligible", type: "observation", severity: "low",
    enrich: { ...cookieEvidence(), hsts: { present: true, max_age: 31_536_000, include_subdomains: false, preload_directive: false, preload_eligible: false, error: null } },
  },
  {
    id: "dse_cookie_no_secure", type: "finding", severity: "high",
    enrich: cookieEvidence({ insecure: 1 }),
  },
  {
    id: "dse_cookie_no_httponly", type: "finding", severity: "medium",
    enrich: cookieEvidence({ noHttpOnly: 1 }),
  },
  {
    id: "dse_cookie_no_samesite", type: "finding", severity: "low",
    enrich: cookieEvidence({ noSameSite: 1 }),
  },
];
for (const sample of dseCases) {
  const emitted = dseFindings.buildDseFindings(sample.enrich, "shared.example.test")
    .find((entry) => entry.id === sample.id);
  eq(`${sample.id}: producer emits explicit finding_type`, emitted?.finding_type, sample.type);
  eq(`${sample.id}: producer emits exact severity`, emitted?.severity, sample.severity);
  eq(`${sample.id}: producer keeps zero score impact`, emitted?.score_impact, 0);
  eq(`${sample.id}: actionability follows explicit type`, findingsContract.isActionableFinding(emitted), sample.type === "finding");
}
eq("DSE error emits no findings", dseFindings.buildDseFindings({ error: "unavailable" }, "shared.example.test"), []);
eq("DSE NaN cookie counters emit no cookie findings",
  dseFindings.buildDseFindings(cookieEvidence({ insecure: Number.NaN }), "shared.example.test").filter((entry) => COOKIE_IDS.includes(entry.id)), []);
eq("DSE errored cookie evidence emits no cookie findings",
  dseFindings.buildDseFindings(cookieEvidence({ insecure: 1, error: "unavailable" }), "shared.example.test").filter((entry) => COOKIE_IDS.includes(entry.id)), []);
ok("severity cannot promote an explicit observation",
  !findingsContract.isActionableFinding({ id: "synthetic_observation", finding_type: "observation", severity: "critical", score_impact: 0 }));
ok("legacy negative score fallback remains actionable",
  findingsContract.isActionableFinding({ id: "legacy", score_impact: -1 }));
ok("legacy zero score without explicit type remains an observation",
  !findingsContract.isActionableFinding({ id: "legacy_zero", score_impact: 0 }));

const cspModules = (policy, { uncertain = false, status = 200 } = {}) => ({
  dns: { resolves: true },
  ssl: { https_available: true, http_redirects_to_https: true },
  headers: {
    accessible: true, final_https: true, validation_uncertain: uncertain, status_code: status,
    values: {
      "strict-transport-security": "max-age=31536000; includeSubDomains",
      "content-security-policy": policy,
      "x-frame-options": "DENY", "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer", "permissions-policy": "geolocation=()",
    },
  },
  email_security: { spf: { present: true }, dmarc: { present: true, policy: "reject" }, dkim: { present: true } },
});
const cspFinding = (policy, opts) => scoring.computeScore(cspModules(policy, opts), "shared.example.test")
  .findings.find((entry) => entry.id === "csp_weak_policy");
eq("CSP style-only producer is a low observation", cspFinding("default-src 'self'; script-src 'self'; style-src 'unsafe-inline'")?.finding_type, "observation");
eq("CSP style-only producer severity is low", cspFinding("default-src 'self'; script-src 'self'; style-src 'unsafe-inline'")?.severity, "low");
eq("CSP script weakness producer is an explicit finding", cspFinding("default-src 'self'; script-src 'unsafe-inline'")?.finding_type, "finding");
eq("CSP script weakness producer severity is medium", cspFinding("default-src 'self'; script-src 'unsafe-inline'")?.severity, "medium");
eq("CSP font/img wildcard is not header-wide promoted", cspFinding("default-src 'self'; script-src 'self'; img-src *"), undefined);
eq("CSP uncertain response admits no weak-policy result", cspFinding("script-src 'unsafe-inline'", { uncertain: true }), undefined);
eq("CSP non-200 response admits no weak-policy result", cspFinding("script-src 'unsafe-inline'", { status: 503 }), undefined);
eq("shared CSP classifier identifies style-only weakness",
  headersContract.classifyCspPolicy("script-src 'self'; style-src 'unsafe-inline'")?.classification, "weak_style_only");

eq("score methodology version remains frozen", scoring.CYBER_METRICS_SCORE_METHODOLOGY_VERSION, "2026-08-26.1");
eq("score-bearing module order remains frozen", scoring.SCORE_BEARING_MODULES,
  ["dns", "ssl", "headers", "email_security", "asset_exposure", "subdomains", "subdomain_takeover"]);

const CERTIFICATE_EXPIRY_NOW_MS = Date.UTC(2026, 7, 30, 12, 0, 0);
const expiryNotAfterForDays = (days, skewDays = 0) => new Date(
  CERTIFICATE_EXPIRY_NOW_MS +
    ((Number.isFinite(days) && days >= 0 ? days : 10) + 0.5 + skewDays) * 86_400_000,
).toISOString();
const certificateExpiryIntel = (days, notAfter = expiryNotAfterForDays(days)) =>
  certIntel.runCertificateIntelligenceModule({
    ssl: { cert_expiry_days: days, cert_not_after: notAfter },
    subdomains: { items: [], sources: {} },
  }, "shared.example.test", { nowMs: CERTIFICATE_EXPIRY_NOW_MS });
const certificateExpirySignals = (days, notAfter) =>
  certificateExpiryIntel(days, notAfter).suspicious_certificate_signals || [];
const criticalExpiryDate = expiryNotAfterForDays(10);
const certResult = certificateExpiryIntel(10, criticalExpiryDate);
const certSignals = certResult.suspicious_certificate_signals || [];
const criticalCert = certSignals.find((entry) => entry.signal === "certificate_expiring_critical");
eq("reachable certificate critical signal is high", criticalCert?.severity, "high");
eq("reachable certificate critical signal is explicit finding", criticalCert?.finding_type, "finding");
eq("certificate expiry critical score impact stays zero", criticalCert?.score_impact, 0);
eq("certificate expiry critical title is producer-owned", criticalCert?.title,
  "Logged certificate validity ends within 14 days");
eq("certificate expiry critical description is CT-honest", criticalCert?.description,
  `The latest-expiring currently valid certificate record returned by the available Certificate Transparency source for shared.example.test ends on ${criticalExpiryDate} (10 days). This is Certificate Transparency evidence; the certificate served by the live site was not inspected. Renew and deploy a replacement before that date, or confirm that a newer certificate is already in service.`);
ok("certificate expiry evidence is CT-only and not live-verified",
  criticalCert?.evidence_source === "certificate_transparency" &&
    criticalCert?.live_certificate_verified === false &&
    criticalCert?.evidence_basis === "latest_expiring_logged_certificate" &&
    certResult.expiry_evidence === "usable");
eq("certificate expiry pair accepts at most one day of independent-clock skew",
  certificateExpiryIntel(10, expiryNotAfterForDays(10, 1)).expiry_evidence, "usable");
eq("certificate expiry 13-day boundary emits high critical-window finding",
  certificateExpirySignals(13).find((entry) => entry.signal === "certificate_expiring_critical")?.severity, "high");
eq("certificate expiry 14-day boundary emits medium soon finding",
  certificateExpirySignals(14).find((entry) => entry.signal === "certificate_expiring_soon")?.severity, "medium");
eq("certificate expiry 29-day boundary emits medium soon finding",
  certificateExpirySignals(29).find((entry) => entry.signal === "certificate_expiring_soon")?.severity, "medium");
eq("certificate expiry 30-day boundary emits no expiry finding",
  certificateExpirySignals(30).filter((entry) => entry.signal.startsWith("certificate_expir")), []);
const soonExpiryDate = expiryNotAfterForDays(14);
const soonCert = certificateExpirySignals(14, soonExpiryDate)
  .find((entry) => entry.signal === "certificate_expiring_soon");
eq("certificate expiry soon title is producer-owned", soonCert?.title,
  "Logged certificate validity ends within 30 days");
ok("certificate expiry soon description is CT-honest",
  soonCert?.description ===
    `The latest-expiring currently valid certificate record returned by the available Certificate Transparency source for shared.example.test ends on ${soonExpiryDate} (14 days). This is Certificate Transparency evidence; the certificate served by the live site was not inspected. Plan renewal now so the replacement is deployed before that date.` &&
    !soonCert.description.includes("service outage"));
ok("certificate expiry descriptions stay within returned CT evidence scope",
  [criticalCert, soonCert].every((entry) =>
    entry?.description.includes("returned by the available Certificate Transparency source") &&
    !entry.description.includes("No currently valid publicly logged certificate")));
const invalidExpiryValues = [-1, Number.NaN, Number.POSITIVE_INFINITY, 0.5, null, "13"];
ok("invalid certificate expiry evidence emits no signal and stays not usable",
  invalidExpiryValues.every((days) => {
    const result = certificateExpiryIntel(days);
    return result.expiry_evidence === "not_usable" &&
      !result.suspicious_certificate_signals?.some((entry) => entry.signal.startsWith("certificate_expir"));
  }));
const incoherentExpiryPairs = [
  { days: 10, notAfter: null },
  { days: 10, notAfter: "" },
  { days: 10, notAfter: "   " },
  { days: 10, notAfter: "not-a-date" },
  { days: 10, notAfter: expiryNotAfterForDays(10, 2) },
  { days: 10, notAfter: "2100-01-01T00:00:00Z" },
  { days: 0, notAfter: "2026-08-29T12:00:00.000Z" },
];
ok("incoherent certificate expiry pairs emit no signal and stay not usable",
  incoherentExpiryPairs.every(({ days, notAfter }) => {
    const result = certificateExpiryIntel(days, notAfter);
    return result.expiry_evidence === "not_usable" &&
      !result.suspicious_certificate_signals?.some((entry) => entry.signal.startsWith("certificate_expir"));
  }));
ok("certificate intelligence never emits scan-time expired identity",
  [...invalidExpiryValues, 0, 13, 14, 29, 30].every((days) =>
    !certificateExpirySignals(days).some((entry) => entry.signal === "certificate_expired")));
const scoreWithoutCertificateExpiry = scoring.computeScore(cspModules(
  "default-src 'self'; script-src 'self'; style-src 'self'",
), "shared.example.test").score;
const scoreWithCertificateExpiry = scoring.computeScore({
  ...cspModules("default-src 'self'; script-src 'self'; style-src 'self'"),
  certificate_intelligence: certResult,
}, "shared.example.test").score;
eq("certificate expiry signals remain score-neutral", scoreWithCertificateExpiry, scoreWithoutCertificateExpiry);
eq("certificate critical maps to expiring action",
  remediation.resolveRemediation({ finding_type: criticalCert?.signal })?.remediation_id, "cert.expiry.expiring");

ok("raw MTA-STS absence token alone admits no finding",
  emailAnalysis.mtaStsAdmission({ observation_state: "definitive_absent" }).missing_finding === false);
ok("TLS-RPT absence observation cannot become actionable from severity",
  !findingsContract.isActionableFinding({ id: "email_intel_tls_rpt_missing", finding_type: "observation", severity: "high", score_impact: 0 }));

// 2. Projection has one owner and preserves every unrelated dse_* mapping.
const attack = domains.CYBER_MOT_DOMAINS.find((entry) => entry.domain_key === "attack_surface");
const website = domains.CYBER_MOT_DOMAINS.find((entry) => entry.domain_key === "website_security");
const certificates = domains.CYBER_MOT_DOMAINS.find((entry) => entry.domain_key === "certificates_trust");
for (const id of COOKIE_IDS) {
  eq(`${id}: Attack Surface no longer owns`, attack?.match({ id }), false);
  eq(`${id}: Website Security owns`, website?.match({ id }), true);
  eq(`${id}: generic ASM creation excludes`, asmCases.isAsmManagedFinding(finding(id)), false);
  eq(`${id}: managed verification ownership is Website Security`, managedVerification.managedVerificationDomainKey(id), "website_security");
}
for (const id of CAA_IDS) {
  eq(`${id}: Attack Surface no longer owns`, attack?.match({ id }), false);
  eq(`${id}: Certificates & Trust owns`, certificates?.match({ id }), true);
  eq(`${id}: not dual-owned by Website Security`, website?.match({ id }), false);
  eq(`${id}: managed verification ownership is Certificates & Trust`, managedVerification.managedVerificationDomainKey(id), "certificates_trust");
}
for (const id of HSTS_IDS) {
  eq(`${id}: Attack Surface no longer owns`, attack?.match({ id }), false);
  eq(`${id}: Website Security owns`, website?.match({ id }), true);
  eq(`${id}: not dual-owned by Certificates & Trust`, certificates?.match({ id }), false);
  eq(`${id}: managed verification ownership is Website Security`, managedVerification.managedVerificationDomainKey(id), "website_security");
}
eq("dnssec finding remains Attack Surface-owned", attack?.match({ id: "dnssec_not_enabled" }), true);
eq("csp_weak_policy is Website Security-owned", website?.match({ id: "csp_weak_policy" }), true);
eq("csp_weak_policy is not Attack Surface-owned", attack?.match({ id: "csp_weak_policy" }), false);

const report = {
  scan_id: "scan-projection",
  completed_at: "2026-08-09T12:00:00Z",
  scan_quality: { status: "complete", modules_skipped: [] },
  modules: {
    subdomains: { subdomains: [] }, dns: { records: [] }, headers: { values: {} },
    ssl: { available: true }, domain_security_enrichment: cookieEvidence({ insecure: 1 }),
  },
  findings: [finding("dse_cookie_no_secure")],
};
const projected = domains.resolveCyberMotDomainStates(report);
const projectedAttack = projected.find((entry) => entry.domain_key === "attack_surface");
const projectedWebsite = projected.find((entry) => entry.domain_key === "website_security");
eq("cookie is absent from Attack Surface count", projectedAttack?.finding_count, 0);
eq("cookie appears once in Website Security count", projectedWebsite?.finding_count, 1);
eq("cookie is counted exactly once across all eight domains", projected.reduce((sum, entry) => sum + entry.finding_count, 0), 1);

// B3 resolver admission: real producer rows retain their explicit authority
// independently from severity and score impact.
const producerRow = (id, enrich) => dseFindings.buildDseFindings(enrich, "shared.example.test")
  .find((entry) => entry.id === id);
const hstsShort = producerRow("dse_hsts_short_maxage",
  { ...cookieEvidence(), hsts: { present: true, max_age: 86_400, include_subdomains: true, preload_directive: true, preload_eligible: false, error: null } });
const sameSite = producerRow("dse_cookie_no_samesite", cookieEvidence({ noSameSite: 1 }));
const caaAbsent = producerRow("dse_missing_caa",
  { ...cookieEvidence(), caa: { present: false, records: [], issuers: [], error: null } });
const hstsPreload = producerRow("dse_hsts_not_preload_eligible",
  { ...cookieEvidence(), hsts: { present: true, max_age: 31_536_000, include_subdomains: false, preload_directive: false, preload_eligible: false, error: null } });
const resolveRow = (row, mutate = null) => {
  const candidate = {
    ...report,
    modules: { ...report.modules, headers: { values: {} }, ssl: { https_available: true, https_probe_executed: true } },
    findings: row ? [row] : [],
  };
  if (mutate) mutate(candidate);
  return domains.resolveCyberMotDomainStates(candidate);
};

const hstsDomain = resolveRow(hstsShort).find((entry) => entry.domain_key === "website_security");
eq("B3 low HSTS finding owns Website issue state", hstsDomain?.state, "issue_detected");
eq("B3 low HSTS finding retains count", hstsDomain?.finding_count, 1);
eq("B3 low HSTS finding retains identity", hstsDomain?.finding_ids, ["dse_hsts_short_maxage"]);
eq("B3 low HSTS finding retains presentation severity", hstsDomain?.highest_severity, "low");

const sameSiteDomain = resolveRow(sameSite).find((entry) => entry.domain_key === "website_security");
eq("B3 low SameSite finding owns Website issue state", sameSiteDomain?.state, "issue_detected");
eq("B3 low SameSite finding retains count and identity",
  [sameSiteDomain?.finding_count, sameSiteDomain?.finding_ids], [1, ["dse_cookie_no_samesite"]]);

const caveatedHsts = resolveRow(hstsShort, (candidate) => {
  candidate.modules.headers = { incomplete: true, incomplete_reason: "origin_error_no_serviceable_response" };
}).find((entry) => entry.domain_key === "website_security");
eq("B3 actionable HSTS finding stays positive-first under required-evidence failure",
  [caveatedHsts?.state, caveatedHsts?.coverage, caveatedHsts?.finding_count, caveatedHsts?.finding_ids],
  ["issue_detected", "partial", 1, ["dse_hsts_short_maxage"]]);

for (const [label, row, domainKey] of [
  ["CAA", caaAbsent, "certificates_trust"],
  ["HSTS preload", hstsPreload, "website_security"],
  ["synthetic critical", { id: "csp_weak_policy", finding_type: "observation", severity: "critical", score_impact: -100, module: "headers" }, "website_security"],
]) {
  const state = resolveRow(row).find((entry) => entry.domain_key === domainKey);
  ok(`B3 ${label} observation owns no domain issue/count/identity`,
    state?.state !== "issue_detected" && state?.finding_count === 0 && JSON.stringify(state?.finding_ids) === "[]");
}
eq("B3 resolver version is the explicit evidence-admission mint", domains.CYBER_MOT_RESOLVER_VERSION, "2026-08-30.2");

// 3. One canonical remediation identity, already Website-owned.
const cookieEntries = remediation.REMEDIATION_REGISTRY.filter((entry) =>
  entry.finding_types?.some((id) => COOKIE_IDS.includes(id)));
eq("one remediation entry covers cookies", cookieEntries.length, 1);
eq("cookie remediation identity remains web.cookie.flags", cookieEntries[0]?.remediation_id, "web.cookie.flags");
eq("cookie remediation remains Website-owned", cookieEntries[0]?.domain_key, "website_security");
eq("one entry covers exactly all three cookie ids", [...(cookieEntries[0]?.finding_types || [])].sort(), [...COOKIE_IDS].sort());

// 4. Lifecycle spec/case ownership/alert domain and low SameSite preservation.
for (const id of COOKIE_IDS) {
  const spec = lifecycle.websiteConditionSpec(id);
  ok(`${id}: Website lifecycle spec exists`, Boolean(spec));
  eq(`${id}: detecting module is domain_security_enrichment`, spec?.module, "domain_security_enrichment");
  eq(`${id}: recurrence reuses the canonical Website case path`, websiteCases.WEBSITE_CASE_RECURRENCES.has(spec?.recurrence), true);
}

{
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db), RESEND_API_KEY: "" };
  await baseline(env);
  await evaluate(env, {
    findings: [finding("dse_cookie_no_samesite")],
    enrich: cookieEvidence({ noSameSite: 1 }),
  });
  const row = condition(db, "ws1", "dse_cookie_no_samesite");
  const allCases = cases(db, "ws1");
  ok("low-severity SameSite condition is retained by managed lifecycle", Boolean(row));
  eq("exactly one managed case opens", allCases.length, 1);
  eq("new cookie case type is website_case", allCases[0]?.case_type, "website_case");
  eq("new cookie case domain is Website Security", allCases[0]?.domain_key, "website_security");
  eq("new cookie case keeps the one remediation", allCases[0]?.remediation_id, "web.cookie.flags");
  eq("condition links to its single case", row?.linked_case_id, allCases[0]?.id);
  const alertDomains = db.prepare("SELECT domain_key FROM notification_events WHERE workspace_id='ws1'").all().map((entry) => entry.domain_key);
  ok("new cookie alert is Website Security", alertDomains.includes("website_security"), JSON.stringify(alertDomains));
  ok("no Attack Surface cookie alert is emitted", !alertDomains.includes("attack_surface"), JSON.stringify(alertDomains));

  await evaluate(env, {
    scanId: "scan-defect-repeat",
    findings: [finding("dse_cookie_no_samesite")],
    enrich: cookieEvidence({ noSameSite: 1 }),
  });
  eq("found>0 defective remains observed", condition(db, "ws1", "dse_cookie_no_samesite")?.monitoring_status, "observed");
  eq("unchanged defect creates no second case", cases(db, "ws1").length, 1);
}

// 5. Conclusive clear can verify; zero cookies and incomplete/error evidence cannot.
async function verificationScenario({ name, enrich, quality = "complete", moduleError = null, wantStatus, wantUnknown, wantCase }) {
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db), RESEND_API_KEY: "" };
  await baseline(env);
  await evaluate(env, { findings: [finding("dse_cookie_no_secure")], enrich: cookieEvidence({ insecure: 1 }) });
  const row = condition(db, "ws1", "dse_cookie_no_secure");
  if (!row?.linked_case_id) {
    ok(`${name}: prerequisite cookie condition exists`, false);
    eq(`${name}: condition state`, row?.monitoring_status, wantStatus);
    eq(`${name}: unknown reason`, row?.unknown_reason ?? null, wantUnknown ?? null);
    eq(`${name}: case state`, null, wantCase);
    return { db, next: row, kase: null };
  }
  db.prepare("UPDATE managed_cases SET status='awaiting_verification' WHERE id=?").run(row?.linked_case_id);
  await evaluate(env, { scanId: `scan-${name}`, findings: [], enrich, quality, moduleError });
  const next = condition(db, "ws1", "dse_cookie_no_secure");
  const kase = db.prepare("SELECT * FROM managed_cases WHERE id=?").get(row?.linked_case_id);
  eq(`${name}: condition state`, next?.monitoring_status, wantStatus);
  eq(`${name}: unknown reason`, next?.unknown_reason ?? null, wantUnknown ?? null);
  eq(`${name}: case state`, kase?.status, wantCase);
  return { db, next, kase };
}

await verificationScenario({
  name: "compliant", enrich: cookieEvidence(),
  wantStatus: "no_longer_observed", wantUnknown: null, wantCase: "verified",
});
const none = await verificationScenario({
  name: "no-cookies", enrich: cookieEvidence({ found: 0 }),
  wantStatus: "unknown", wantUnknown: "no_cookies_observed", wantCase: "awaiting_verification",
});
eq("found===0 writes no condition_resolved event",
  none.next
    ? none.db.prepare("SELECT COUNT(*) AS n FROM website_security_events WHERE record_id=? AND event_type='condition_resolved'").get(none.next.id).n
    : null,
  0);
await verificationScenario({
  name: "partial", enrich: cookieEvidence(), quality: "partial",
  wantStatus: "unknown", wantUnknown: "scan_partial", wantCase: "awaiting_verification",
});
await verificationScenario({
  name: "module-error", enrich: cookieEvidence(), moduleError: "enrichment failed",
  wantStatus: "unknown", wantUnknown: "module_not_assessed", wantCase: "awaiting_verification",
});

// The historical full-scan ASM verifier must not translate the ownership exclusion
// into finding absence. It consumes the same contract before deciding.
{
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db), RESEND_API_KEY: "" };
  db.prepare(`INSERT INTO managed_cases
    (id,workspace_id,case_type,domain_key,domain,finding_id,source_finding_type,asset_ref,severity,status,evidence_json,created_at,updated_at)
    VALUES ('legacy-awaiting','ws1','asm_exposure','attack_surface','shared.example.test','dse_cookie_no_secure',
      'dse_cookie_no_secure','shared.example.test','high','verification_requested',?,datetime('now'),datetime('now'))`)
    .run(JSON.stringify({ finding: finding("dse_cookie_no_secure") }));
  const result = await asmCases.verifyManagedAsmCasesForScan(
    "scan-legacy-none", "d1", "shared.example.test", [], env,
    { ...context(cookieEvidence({ found: 0 })), scanPublished: true },
  );
  eq("historical full-scan cookie verification defers zero cookies", result.deferred, 1);
  eq("historical full-scan cookie case remains awaiting verification",
    db.prepare("SELECT status FROM managed_cases WHERE id='legacy-awaiting'").get()?.status,
    "verification_requested");
  const deferred = db.prepare("SELECT detail_json FROM managed_case_events WHERE case_id='legacy-awaiting' AND action='verification_deferred' ORDER BY rowid DESC LIMIT 1").get();
  eq("historical full-scan deferral keeps no_cookies_observed reason",
    deferred ? JSON.parse(deferred.detail_json).reason : null,
    "no_cookies_observed");
}

// 6. Historical H-A compatibility: exact legacy case suppresses a new case without mutation.
{
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db), RESEND_API_KEY: "" };
  await baseline(env);
  db.prepare(`INSERT INTO managed_cases
    (id,workspace_id,case_type,domain_key,domain,finding_id,source_finding_type,asset_ref,severity,status,evidence_json,created_at,updated_at)
    VALUES ('legacy-cookie','ws1','asm_exposure','attack_surface','shared.example.test','dse_cookie_no_secure',
      'dse_cookie_no_secure','shared.example.test','high','open','{"legacy":true}','2026-07-01 00:00:00','2026-07-01 00:00:00')`).run();
  db.prepare(`INSERT INTO managed_case_events
    (id,case_id,workspace_id,actor_type,action,detail_json,created_at)
    VALUES ('legacy-event','legacy-cookie','ws1','system','case_created','{"legacy":true}','2026-07-01 00:00:00')`).run();
  const caseBefore = JSON.stringify(db.prepare("SELECT * FROM managed_cases WHERE id='legacy-cookie'").get());
  const eventBefore = JSON.stringify(db.prepare("SELECT * FROM managed_case_events WHERE id='legacy-event'").get());
  await evaluate(env, {
    findings: [finding("dse_cookie_no_secure")],
    enrich: cookieEvidence({ insecure: 1 }),
  });
  const allCases = cases(db, "ws1");
  eq("historical ASM cookie case suppresses a Website duplicate", allCases.length, 1);
  eq("historical ASM case row remains byte-equivalent", JSON.stringify(db.prepare("SELECT * FROM managed_cases WHERE id='legacy-cookie'").get()), caseBefore);
  eq("historical ASM event remains byte-equivalent", JSON.stringify(db.prepare("SELECT * FROM managed_case_events WHERE id='legacy-event'").get()), eventBefore);
  eq("Website condition presents the historical case link", condition(db, "ws1", "dse_cookie_no_secure")?.linked_case_id, "legacy-cookie");
}

// 7. Resolver boundary is mechanically versioned and therefore never recovery/new risk.
ok("resolver version is mechanically bumped from 2026-07-24.4", domains.CYBER_MOT_RESOLVER_VERSION !== "2026-07-24.4");
const oldState = {
  domain_key: "attack_surface", state: "issue_detected", coverage: "complete",
  highest_severity: "high", finding_count: 1, finding_ids_json: '["dse_cookie_no_secure"]',
  scan_quality: "complete", resolver_version: "2026-07-24.4", assessed_at: "2026-08-08T00:00:00Z",
};
const newState = {
  ...oldState, state: "assessed_healthy", highest_severity: null, finding_count: 0,
  finding_ids_json: "[]", resolver_version: domains.CYBER_MOT_RESOLVER_VERSION,
  assessed_at: "2026-08-09T00:00:00Z",
};
eq("historical/new ownership boundary is not_comparable",
  history.resolveDomainTrend(newState, oldState).trend, "not_comparable");

// 8. Tenant and soft-delete boundaries through the real Website writer.
{
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db), RESEND_API_KEY: "" };
  await baseline(env, "ws1", "d1");
  await baseline(env, "ws2", "d2");
  await evaluate(env, { workspace: "ws1", domainId: "d1", findings: [finding("dse_cookie_no_secure")], enrich: cookieEvidence({ insecure: 1 }) });
  eq("same hostname in foreign tenant receives no condition", condition(db, "ws2", "dse_cookie_no_secure"), null);
  eq("same hostname in foreign tenant receives no case", cases(db, "ws2").length, 0);

  db.prepare("UPDATE workspaces SET deleted_at=datetime('now') WHERE id='ws2'").run();
  const eventCount = db.prepare("SELECT COUNT(*) AS n FROM website_security_events WHERE workspace_id='ws2'").get().n;
  await evaluate(env, { workspace: "ws2", domainId: "d2", findings: [finding("dse_cookie_no_secure")], enrich: cookieEvidence({ insecure: 1 }) });
  eq("soft-deleted workspace receives no condition", condition(db, "ws2", "dse_cookie_no_secure"), null);
  eq("soft-deleted workspace receives no case", cases(db, "ws2").length, 0);
  eq("soft-deleted workspace receives no event write", db.prepare("SELECT COUNT(*) AS n FROM website_security_events WHERE workspace_id='ws2'").get().n, eventCount);
}

// 9. No second remediation, cookie detector or verifier is introduced.
const contractSource = cookieContract ? fs.readFileSync(src("engines", "cookie-observation.js"), "utf8") : "";
const dseSource = fs.readFileSync(src("engines", "dse-findings.js"), "utf8");
const verificationSource = fs.readFileSync(src("engines", "managed-verification.js"), "utf8");
const lifecycleSource = fs.readFileSync(src("engines", "website-security-lifecycle.js"), "utf8");
eq("both Website lifecycle alert calls use the canonical Website domain constant",
  (lifecycleSource.match(/domain_key: WEBSITE_SECURITY_DOMAIN_KEY/g) || []).length, 2);
ok("canonical cookie counters are defined only in the shared contract",
  cookieContract && [dseSource, verificationSource, lifecycleSource].every((sourceText) =>
    !/insecure_count\s*>\s*0|no_httponly\s*>\s*0|no_samesite\s*>\s*0/.test(sourceText)) &&
    /insecure_count/.test(contractSource) && /no_httponly/.test(contractSource) && /no_samesite/.test(contractSource));
ok("detection imports the shared cookie contract", /from "\.\/cookie-observation\.js"/.test(dseSource));
ok("Website lifecycle imports the shared cookie contract", /from "\.\/cookie-observation\.js"/.test(lifecycleSource));
ok("managed verification imports the shared cookie contract", /from "\.\/cookie-observation\.js"/.test(verificationSource));

console.log(`\nRWS.5 cookie ownership: ${pass}/${pass + fail} passed`);
if (fail > 0) {
  console.error("RWS.5 cookie ownership validation FAILED");
  process.exit(1);
}
console.log("RWS.5 cookie ownership validation passed");
