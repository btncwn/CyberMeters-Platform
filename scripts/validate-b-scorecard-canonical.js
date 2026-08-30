#!/usr/bin/env node
//
// B — Workspace Scorecard Canonicalisation validator.
//
// Proves the live scorecard's per-domain wording (Brand, Certificates, Shadow-IT,
// Attack-Surface admin) derives from canonical Cyber MOT state / A3 admin
// evidence_status — never from raw counts / null-defaults — so unavailable /
// not_assessed evidence can never render "none detected" / "looks normal" / healthy.
// Uses the REAL buildScorecardSections and the REAL scorecard-domain-state helper.
//
// Pure-function harness: no live D1/R2. Node 24+.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const ENG = path.join(ROOT, "workers", "scan-api", "src", "engines");
const absU = (f) => pathToFileURL(path.join(ENG, f)).href;
const SCORECARD = path.join(ENG, "scorecard.js");
const HELPER = path.join(ENG, "scorecard-domain-state.js");
const REPORT_SNAPSHOT = process.env.SAN_B_REPORT_SNAPSHOT_PATH ||
  path.join(ENG, "report-snapshot.js");
const ATTACK_SURFACE = process.env.SAN_B_ATTACK_SURFACE_PATH ||
  path.join(ROOT, "workers", "scan-api", "src", "routes", "attack-surface.js");
const MANIFEST = process.env.SAN_B_MANIFEST_PATH ||
  path.join(ROOT, "workers", "email-ingest", "deploy-manifest.json");
const EMAIL_CONFIG = process.env.SAN_B_EMAIL_WRANGLER_PATH ||
  path.join(ROOT, "workers", "email-ingest", "wrangler.toml");
const SCAN_API_CONFIG = process.env.SAN_B_SCAN_API_WRANGLER_PATH ||
  path.join(ROOT, "workers", "scan-api", "wrangler.toml");
let scorecardModuleUrl = process.env.SAN_B_SCORECARD_MODULE_URL ||
  pathToFileURL(SCORECARD).href;
const certIntelModuleUrl = process.env.SAN_B_CERT_INTEL_MODULE_URL ||
  absU("cert-intel.js");
let sourceRevisionDirectory = null;
if (process.env.SAN_B_SCORECARD_SOURCE_REV) {
  const shown = spawnSync("git", [
    "show",
    `${process.env.SAN_B_SCORECARD_SOURCE_REV}:workers/scan-api/src/engines/scorecard.js`,
  ], { cwd: ROOT, encoding: "utf8" });
  if (shown.status !== 0) throw new Error(`cannot read scorecard revision: ${shown.stderr}`);
  sourceRevisionDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "san-b-base-"));
  const source = shown.stdout.replace(/from "\.\/([^"]+)"/g, (_match, file) =>
    `from ${JSON.stringify(absU(file))}`);
  const file = path.join(sourceRevisionDirectory, "scorecard.mjs");
  fs.writeFileSync(file, source);
  scorecardModuleUrl = pathToFileURL(file).href;
}

const scorecardModule = await import(scorecardModuleUrl);
const {
  buildScorecardData,
  buildScorecardSections,
} = scorecardModule;
const buildCertificateRiskFields = scorecardModule.buildCertificateRiskFields ||
  ((signals, riskLevel, daysUntilExpiry) => ({
    risk_level: riskLevel,
    signals: Array.isArray(signals) ? signals.length : 0,
    days_until_expiry: daysUntilExpiry,
  }));
if (sourceRevisionDirectory) fs.rmSync(sourceRevisionDirectory, { recursive: true, force: true });
const { runCertificateIntelligenceModule } = await import(certIntelModuleUrl);
const { scorecardBehaviour, canSayHealthy } = await import(pathToFileURL(HELPER).href);

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  cond ? pass++ : fail++;
  console.log(`${cond ? "ok  " : "FAIL"} - ${name}${!cond && detail ? ` -- ${detail}` : ""}`);
};
const REASSURING = /none|no exposed|no third-party|no external|looks normal|no active|not resolving|none currently|none detected|no exposed login/i;

// ── 0. Shared helper mapping (real) ──────────────────────────────────────────
ok("helper: assessed_healthy → healthy", scorecardBehaviour("assessed_healthy") === "healthy");
ok("helper: issue_detected → issue", scorecardBehaviour("issue_detected") === "issue");
ok("helper: evidence_insufficient → unavailable", scorecardBehaviour("evidence_insufficient") === "unavailable");
ok("helper: not_yet_assessed → not_assessed", scorecardBehaviour("not_yet_assessed") === "not_assessed");
ok("helper: monitoring_only → not_assessed", scorecardBehaviour("monitoring_only") === "not_assessed");
ok("helper: null/unknown → not_assessed", scorecardBehaviour(null) === "not_assessed");
ok("helper: canSayHealthy only for assessed_healthy",
  canSayHealthy("assessed_healthy") && !canSayHealthy("evidence_insufficient") && !canSayHealthy(null) && !canSayHealthy("monitoring_only"));

// ── scorecard payload builder + section lookup ───────────────────────────────
function scorecardWith(o = {}) {
  return {
    cyber_mot_domains: o.cmd || [],
    admin_surface_evidence_status: o.adminEv ?? null,
    admin_surfaces: o.admin_surfaces ?? 0,
    brand_risks: o.brand ?? { total: 5, active: 0, high: 0, medium: 0, low: 0 },
    certificate_risks: o.cert ?? {
      risk_level: null,
      signals: 0,
      days_until_expiry: null,
      risk_signal_count: 0,
      risk_signals: [],
      informational_observation_count: 0,
      informational_observations: [],
    },
    third_party_assets: o.tpa ?? 0,
    saas_exposures: o.saas ?? 0,
    active_assets: 3, new_assets_30d: 0, asset_events_30d: 0,
    vendors_detected: 0, vendor_risk: { high: 0, medium: 0, low: 0 },
    critical_findings: 0, high_findings: 0, medium_findings: 0, low_findings: 0,
  };
}
const cmd = (key, state) => [{ domain_key: key, state }];
const sec = (payload, title, mod = buildScorecardSections) => mod(payload).find((s) => s.title === title);

// ── 1. BRAND — gated on brand_protection ─────────────────────────────────────
{
  const healthy = sec(scorecardWith({ cmd: cmd("brand_protection", "assessed_healthy") }), "Brand Monitoring");
  ok("brand: assessed_healthy + zero active → positive summary + ok", healthy.status === "ok" && /none currently resolving/i.test(healthy.summary));
  const unavail = sec(scorecardWith({ cmd: cmd("brand_protection", "evidence_insufficient") }), "Brand Monitoring");
  ok("brand: unavailable + zero active → NEUTRAL (no 'none resolving'), status unknown",
    unavail.status === "unknown" && !REASSURING.test(unavail.summary) && /could not be assessed/i.test(unavail.summary));
  const notAssessed = sec(scorecardWith({ cmd: cmd("brand_protection", "not_yet_assessed") }), "Brand Monitoring");
  ok("brand: not_assessed → NEUTRAL 'not been assessed', status unknown", notAssessed.status === "unknown" && /not been assessed yet/i.test(notAssessed.summary));
  const issue = sec(scorecardWith({ cmd: cmd("brand_protection", "issue_detected"), brand: { total: 3, active: 2, high: 1, medium: 0, low: 0 } }), "Brand Monitoring");
  ok("brand: active>0 → issue surfaces (critical/warning), never softened", issue.status === "critical" || issue.status === "warning");
  // canonical issue with ZERO raw active count still surfaces (finding never hidden by count).
  const issueZeroCount = sec(scorecardWith({ cmd: cmd("brand_protection", "issue_detected") }), "Brand Monitoring");
  ok("brand: issue_detected with zero raw count still NOT healthy (issue not hidden by count)", issueZeroCount.status !== "ok");
}

// ── 2. CERTIFICATES — gated on certificates_trust ────────────────────────────
{
  const healthy = sec(scorecardWith({ cmd: cmd("certificates_trust", "assessed_healthy") }), "Certificate Intelligence");
  ok("cert: assessed_healthy → 'looks normal' + ok", healthy.status === "ok" && /looks normal/i.test(healthy.summary));
  const nullState = sec(scorecardWith({ cmd: [] /* no certificates_trust state */, cert: { risk_level: null, signals: 0 } }), "Certificate Intelligence");
  ok("cert: null state + null risk → NEUTRAL, NOT 'looks normal'", nullState.status === "unknown" && !/looks normal/i.test(nullState.summary));
  const unavail = sec(scorecardWith({ cmd: cmd("certificates_trust", "evidence_insufficient") }), "Certificate Intelligence");
  ok("cert: unavailable → 'could not be assessed', not 'looks normal'", /could not be assessed/i.test(unavail.summary) && !/looks normal/i.test(unavail.summary));
  const issue = sec(scorecardWith({ cert: { risk_level: "critical", signals: 2 } }), "Certificate Intelligence");
  ok("cert: real risk signals → issue surfaces", issue.status === "critical" || issue.status === "warning");
}

// ── 3. SHADOW IT — Third-Party / SaaS gated on shadow_it_unmanaged_technology ─
{
  const healthy = sec(scorecardWith({ cmd: cmd("shadow_it_unmanaged_technology", "assessed_healthy") }), "Third-Party Assets");
  ok("shadow: assessed_healthy + zero → 'none detected' + ok", healthy.status === "ok" && /no third-party/i.test(healthy.summary));
  const monitoring = sec(scorecardWith({ cmd: cmd("shadow_it_unmanaged_technology", "monitoring_only") }), "Third-Party Assets");
  ok("shadow: monitoring_only + zero → NEUTRAL, NOT 'none detected'", monitoring.status === "unknown" && !REASSURING.test(monitoring.summary));
  const saasHealthy = sec(scorecardWith({ cmd: cmd("shadow_it_unmanaged_technology", "assessed_healthy") }), "SaaS Exposure");
  ok("shadow SaaS: assessed_healthy + zero → 'none detected' + ok", saasHealthy.status === "ok" && /no externally exposed/i.test(saasHealthy.summary));
  const saasMon = sec(scorecardWith({ cmd: cmd("shadow_it_unmanaged_technology", "not_yet_assessed") }), "SaaS Exposure");
  ok("shadow SaaS: not_assessed + zero → NEUTRAL", saasMon.status === "unknown" && !REASSURING.test(saasMon.summary));
  const tpaIssue = sec(scorecardWith({ tpa: 4 }), "Third-Party Assets");
  ok("shadow: real count>0 → issue surfaces", tpaIssue.status === "warning");
}

// ── 4. ATTACK SURFACE admin — gated on A3 evidence_status ────────────────────
{
  const healthy = sec(scorecardWith({ adminEv: "assessed_healthy" }), "Admin Surfaces");
  ok("admin: assessed_healthy + total0 → 'No exposed admin surfaces detected' + ok (A3 earned positive)",
    healthy.status === "ok" && /no exposed admin surfaces detected/i.test(healthy.summary));
  const unavail = sec(scorecardWith({ adminEv: "unavailable" }), "Admin Surfaces");
  ok("admin: unavailable + total0 → NEUTRAL 'could not be assessed', status unknown (never clean)",
    unavail.status === "unknown" && /could not be assessed/i.test(unavail.summary) && !/no exposed admin/i.test(unavail.summary));
  const notAssessed = sec(scorecardWith({ adminEv: "not_assessed" }), "Admin Surfaces");
  ok("admin: not_assessed + total0 → NEUTRAL 'not been assessed', unknown", notAssessed.status === "unknown" && /not been assessed yet/i.test(notAssessed.summary));
  const issue = sec(scorecardWith({ adminEv: "issue_detected", admin_surfaces: 2 }), "Admin Surfaces");
  ok("admin: total>0 → critical, issue surfaces", issue.status === "critical");
  const legacyNull = sec(scorecardWith({ adminEv: null, admin_surfaces: 0 }), "Admin Surfaces");
  ok("admin: legacy null evidence + total0 → NEUTRAL (never 'none detected')", legacyNull.status === "unknown" && !/no exposed admin surfaces detected/i.test(legacyNull.summary));
}

// ── 5. Legacy / empty payload does not crash ─────────────────────────────────
ok("legacy: empty cyber_mot_domains + null admin → sections build without crash, no false healthy",
  (() => {
    const secs = buildScorecardSections(scorecardWith({}));
    const brand = secs.find((s) => s.title === "Brand Monitoring");
    const admin = secs.find((s) => s.title === "Admin Surfaces");
    return Array.isArray(secs) && brand.status !== "ok" && admin.status !== "ok";
  })());

// ── 6. Candidate B V2 — informational observations are neutral ──────────────
const INFO_NAMES = [
  "wildcard_dns_detected",
  "shared_certificate_observed",
  "sensitive_hosts_in_ct",
  "high_subdomain_growth",
  "ct_source_discrepancy",
];
const SYNTHETIC_INFO_NAMES = [...INFO_NAMES, "ct_sources_unavailable"];
const infoSignal = (signal) => ({ signal, severity: "info", description: `${signal} observed` });
const riskSignal = (signal, severity = "medium") => ({ signal, severity, description: `${signal} detected` });
const certFields = (signals, riskLevel = "low", days = 84) =>
  buildCertificateRiskFields(signals, riskLevel, days);
const certSection = (signals, state = "assessed_healthy", riskLevel = "low") =>
  sec(scorecardWith({ cmd: cmd("certificates_trust", state), cert: certFields(signals, riskLevel) }), "Certificate Intelligence");
const REASSURING_CERT = /Certificate health looks normal\s*[—-]\s*no suspicious signals detected\.|(?:^|\s)No suspicious signals\./i;
const RISK_FRAMED_CERT = /Certificate intelligence flagged \d+ suspicious signal/i;

function scorecardEnv(signals, state = "assessed_healthy", riskLevel = "low", { noScan = false } = {}) {
  const scan = {
    id: "san-b-scan", scan_id: "san-b-scan", score: 100, rating: "excellent",
    scan_quality: "complete", domain: "example.com", created_at: "2026-08-09T12:00:00.000Z",
  };
  const report = {
    domain: "example.com",
    modules: {
      certificate_intelligence: {
        certificate_risk_level: riskLevel,
        suspicious_certificate_signals: signals,
        days_until_expiry: 84,
      },
      ssl: { https_available: true, http_redirects_to_https: true, cert_expiry_days: 84 },
      admin_surface_detection: { total: 0, evidence_status: "assessed_healthy" },
      saas_exposure: { total: 0 },
      third_party_assets: { total: 0 },
      cloud_storage_discovery: { assets: [] },
    },
    cyber_mot_domains: [{ domain_key: "certificates_trust", state }],
    monitoring_states: [],
  };
  const statement = (sql = "") => ({
    bind() { return this; },
    async all() { return { results: !noScan && sql.includes("scan_quality='complete'") ? [scan] : [] }; },
    async first() {
      if (!noScan && sql.includes("FROM scans")) return scan;
      return null;
    },
  });
  return {
    cybermeters_db: {
      prepare(sql) { return statement(sql); },
      async batch(items) {
        if (items.length === 12) return [
          { results: noScan ? [] : [scan] }, { results: [{ name: "SAN B" }] },
          { results: [{ n: 3 }] }, { results: [] }, { results: [{ n: 0 }] },
          { results: [] }, { results: [] }, { results: [{ n: 0 }] },
          { results: [{ n: 0 }] }, { results: [{ n: 0 }] },
          { results: [{ n: 1 }] }, { results: [] },
        ];
        return [{ results: [] }, { results: [] }];
      },
    },
    cybermeters_reports: {
      async get() { return noScan ? null : { async json() { return structuredClone(report); } }; },
    },
  };
}

const oneInfo = [infoSignal(INFO_NAMES[0])];
const oneInfoFields = certFields(oneInfo);
const oneInfoSection = certSection(oneInfo);
const fullOneInfo = await buildScorecardData("san-b-workspace", scorecardEnv(oneInfo));
const fullStrings = (payload, section) => [
  ...(payload?.executive_summary?.good || []),
  ...(payload?.executive_summary?.attention_required || []),
  ...(payload?.executive_summary?.urgent || []),
  section?.summary || "",
].join("\n");

ok("SAN_B_F01", oneInfoSection.status === "ok" &&
  !/suspicious/i.test(oneInfoSection.summary) && !/\b1\s+signal/i.test(oneInfoSection.summary));
ok("SAN_B_F02a", !fullOneInfo.executive_summary.good.some((line) => REASSURING_CERT.test(line)) &&
  !REASSURING_CERT.test(oneInfoSection.summary));
{
  const payloads = [oneInfo, [riskSignal("mixed", "high")], [riskSignal("mixed", "high"), ...oneInfo]];
  ok("SAN_B_F02b", payloads.every((signals) => {
    const fields = certFields(signals, signals.some((s) => s.severity === "high") ? "high" : "low");
    const section = certSection(signals, "assessed_healthy", fields.risk_level);
    return !REASSURING_CERT.test(fullStrings({ executive_summary: { good: [], attention_required: [], urgent: [] } }, section));
  }) && !REASSURING_CERT.test(fullStrings(fullOneInfo, oneInfoSection)));
}
ok("SAN_B_F03", !fullOneInfo.executive_summary.attention_required.some((line) => RISK_FRAMED_CERT.test(line)) &&
  fullOneInfo.executive_summary.attention_required.filter((line) => /neutral informational observation/i.test(line)).length === 1);
{
  const medium = certSection([riskSignal("certificate_expiring_soon")], "assessed_healthy", "medium");
  ok("SAN_B_F04", medium.status === "warning" && /suspicious/i.test(medium.summary));
}
{
  const fields = certFields([riskSignal("certificate_expiring_critical", "high"), infoSignal("wildcard_dns_detected")], "high");
  const section = sec(scorecardWith({ cmd: cmd("certificates_trust", "issue_detected"), cert: fields }), "Certificate Intelligence");
  ok("SAN_B_F05", section.status === "warning" && Array.isArray(fields.risk_signals) &&
    fields.risk_signals.length === 1 && Array.isArray(fields.informational_observations) &&
    fields.informational_observations.length === 1 && fields.risk_signals.every((s) => s.severity !== "info") &&
    /1 suspicious signal/i.test(section.summary));
}
{
  const fields = certFields([riskSignal("historical_critical_signal", "critical")], "critical");
  const section = sec(scorecardWith({ cmd: cmd("certificates_trust", "issue_detected"), cert: fields }), "Certificate Intelligence");
  ok("SAN_B_F24", section.status === "critical" && fields.risk_signals?.length === 1 &&
    fields.risk_signals[0]?.severity === "critical" && /1 suspicious signal/i.test(section.summary));
}
ok("SAN_B_F06", [[], oneInfo, [riskSignal("medium"), ...oneInfo]].every((signals) =>
  certFields(signals).signals === signals.length));
ok("SAN_B_F07", Object.hasOwn(oneInfoFields, "risk_signals") &&
  Object.hasOwn(oneInfoFields, "informational_observations") &&
  oneInfoFields.risk_level === "low" && oneInfoFields.days_until_expiry === 84);
{
  const section = certSection([], "evidence_insufficient", null);
  ok("SAN_B_F08", section.status === "unknown" && !REASSURING_CERT.test(section.summary));
}
{
  const section = certSection([], "assessed_healthy", "low");
  ok("SAN_B_F09", section.status === "ok" && /looks normal/i.test(section.summary));
}
{
  const section = certSection(SYNTHETIC_INFO_NAMES.map(infoSignal));
  ok("SAN_B_F10a", section.status !== "warning" && !/suspicious/i.test(section.summary) &&
    Array.isArray(section.data.informational_observations) &&
    section.data.informational_observations.length === 6 &&
    Array.isArray(section.data.risk_signals) && section.data.risk_signals.length === 0);
}
{
  const section = certSection(INFO_NAMES.map(infoSignal));
  ok("SAN_B_F10b", section.status === "ok" && !/suspicious/i.test(section.summary) &&
    Array.isArray(section.data.informational_observations) &&
    section.data.informational_observations.length === 5 &&
    Array.isArray(section.data.risk_signals) && section.data.risk_signals.length === 0);
}
ok("SAN_B_F11", ["risk_signal_count", "risk_signals", "informational_observation_count", "informational_observations"]
  .every((key) => Object.hasOwn(fullOneInfo.certificate_risks, key) && Object.hasOwn(oneInfoFields, key)) &&
  JSON.stringify(Object.keys(fullOneInfo.certificate_risks).sort()) ===
    JSON.stringify(Object.keys(oneInfoFields).sort()));

const emptyScorecard = await buildScorecardData(
  "san-b-empty-workspace",
  scorecardEnv([], "not_yet_assessed", null, { noScan: true }),
);
const benignProducer = runCertificateIntelligenceModule({
  ssl: { https_available: true, cert_expiry_days: 84, cert_issuer: "Fixture CA" },
  subdomains: {
    wildcard_dns: true,
    items: ["admin.example.com"],
    sensitive: ["admin.example.com"],
    sources: { crt_sh: { count: 60 }, certspotter: { count: 60 } },
  },
  dns_bruteforce: { items: [] },
}, "example.com");
ok("SAN_B_F12", benignProducer.certificate_risk_level === "low" &&
  emptyScorecard?.certificate_risks != null);
ok("SAN_B_F13", benignProducer.certificate_risk_level === "low");
ok("SAN_B_F14", benignProducer.certificate_risk_level === "low");

const SCORECARD_EXPIRY_NOW_MS = Date.UTC(2026, 7, 30, 12, 0, 0);
const scorecardExpiryNotAfter = (days, skewDays = 0) => new Date(
  SCORECARD_EXPIRY_NOW_MS +
    ((Number.isFinite(days) && days >= 0 ? days : 10) + 0.5 + skewDays) * 86_400_000,
).toISOString();
const expiryProducer = (days, notAfter = scorecardExpiryNotAfter(days)) => runCertificateIntelligenceModule({
  ssl: {
    https_available: true,
    cert_expiry_days: days,
    cert_not_after: notAfter,
    cert_issuer: "Fixture CA",
  },
  subdomains: { items: [], sources: {} },
}, "example.com", { nowMs: SCORECARD_EXPIRY_NOW_MS });
const expirySignals = (days) => expiryProducer(days).suspicious_certificate_signals
  .filter((signal) => signal.signal.startsWith("certificate_expir"));
ok("certificate scorecard producer uses exact 13/14/29/30 boundaries",
  expirySignals(13)[0]?.signal === "certificate_expiring_critical" &&
    expirySignals(13)[0]?.severity === "high" &&
    expirySignals(14)[0]?.signal === "certificate_expiring_soon" &&
    expirySignals(14)[0]?.severity === "medium" &&
    expirySignals(29)[0]?.signal === "certificate_expiring_soon" &&
    expirySignals(30).length === 0);
ok("certificate scorecard producer rejects unusable expiry values",
  [-1, Number.NaN, null].every((days) => {
    const result = expiryProducer(days);
    return result.expiry_evidence === "not_usable" && expirySignals(days).length === 0;
  }));
ok("certificate scorecard producer rejects incoherent expiry pairs",
  [
    null,
    "",
    "not-a-date",
    scorecardExpiryNotAfter(10, 2),
    "2100-01-01T00:00:00Z",
    "2026-08-29T12:00:00.000Z",
  ].every((notAfter) => {
    const result = expiryProducer(10, notAfter);
    return result.expiry_evidence === "not_usable" &&
      result.suspicious_certificate_signals.every((signal) =>
        !signal.signal.startsWith("certificate_expir"));
  }));
ok("certificate scorecard producer carries exact CT-honest titles",
  expirySignals(13)[0]?.title === "Logged certificate validity ends within 14 days" &&
    expirySignals(14)[0]?.title === "Logged certificate validity ends within 30 days" &&
    [expirySignals(13)[0], expirySignals(14)[0]].every((signal) =>
      signal?.description?.includes("Certificate Transparency") &&
      signal.description.includes("returned by the available Certificate Transparency source") &&
      !signal.description.includes("No currently valid publicly logged certificate") &&
      signal.description.includes("not inspected") &&
      !signal.description.includes("service outage")));

const snapshotSource = fs.readFileSync(REPORT_SNAPSHOT, "utf8");
ok("SAN_B_F15", !/\b(?:risk_signals|informational_observations)\b/.test(snapshotSource));
const scanRouteSource = fs.readFileSync(path.join(ROOT, "workers", "scan-api", "src", "routes", "scans.js"), "utf8");
ok("SAN_B_F16", /modules:\s*\{\s*\.\.\.normalisedModules,/s.test(scanRouteSource));
const attackSurfaceSource = fs.readFileSync(ATTACK_SURFACE, "utf8");
ok("SAN_B_F17", /suspicious_certificate_signals:\s*ci\.suspicious_certificate_signals\s*\|\|\s*\[\]/.test(attackSurfaceSource));
ok("SAN_B_F18", /requireWorkspaceRole\(user, wsId, "workspace:read", env\)/.test(attackSurfaceSource) &&
  /deleted_at IS NULL/.test(attackSurfaceSource));
ok("SAN_B_F19", emptyScorecard !== null && emptyScorecard.certificate_risks != null);

{
  const skipClosure = process.argv.includes("--skip-closure");
  let condition = true;
  if (!skipClosure) {
    const trace = spawnSync(process.execPath, [path.join(ROOT, "scripts", "validate-email-worker-deploy-traceability.js"), "--print"], {
      cwd: ROOT, encoding: "utf8",
    });
    try {
      const computed = JSON.parse(trace.stdout);
      const manifest = JSON.parse(fs.readFileSync(MANIFEST, "utf8"));
      const versionMatch = fs.readFileSync(EMAIL_CONFIG, "utf8").match(/^APP_VERSION\s*=\s*"([^"]+)"\s*$/m);
      const version = versionMatch?.[1] || "";
      const scanVersionMatch = fs.readFileSync(SCAN_API_CONFIG, "utf8").match(/^APP_VERSION\s*=\s*"([^"]+)"\s*$/m);
      const scanVersion = scanVersionMatch?.[1] || "";
      condition = trace.status === 0 &&
        computed.closure_sha256 !== "58c26ff6c9e4a9352a0aa2f52931541e297ca0b069f5510d5663de4bc3095875" &&
        manifest.closure_sha256 === computed.closure_sha256 &&
        manifest.closure_file_count === computed.closure_file_count &&
        manifest.scan_api_file_count === computed.scan_api_file_count &&
        JSON.stringify(manifest.files) === JSON.stringify(computed.files) &&
        manifest.app_version === version &&
        scanVersion === version &&
        version.endsWith(`.${computed.closure_sha256.slice(0, 12)}`);
    } catch { condition = false; }
  }
  ok("SAN_B_F20", condition);
}

const frontendCertificateSources = [
  "frontend/src/pages/Dashboard.jsx",
  "frontend/src/pages/ws/WorkspaceDashboard.jsx",
].map((relative) => fs.readFileSync(path.join(ROOT, relative), "utf8")).join("\n");
ok("SAN_B_F21", !/\b(?:risk_signals|informational_observations)\b/.test(frontendCertificateSources));
{
  const legacy = sec(scorecardWith({ cmd: cmd("certificates_trust", "evidence_insufficient"), cert: { risk_level: null, signals: 0 } }), "Certificate Intelligence");
  ok("SAN_B_F22a", legacy && !/suspicious|looks normal/i.test(legacy.summary));
}
{
  const legacy = sec(scorecardWith({ cmd: cmd("certificates_trust", "assessed_healthy"), cert: { risk_level: null, days_until_expiry: null } }), "Certificate Intelligence");
  ok("SAN_B_F22b", Boolean(legacy));
}
{
  const payload = scorecardWith({ cmd: cmd("certificates_trust", "evidence_insufficient") });
  delete payload.certificate_risks;
  const legacy = sec(payload, "Certificate Intelligence");
  ok("SAN_B_F22c", Boolean(legacy) && !REASSURING_CERT.test(legacy.summary));
}
{
  const malformed = [null, 3, "x", [{ severity: "info" }, null]];
  ok("SAN_B_F22d", malformed.every((value) => {
    const section = sec(scorecardWith({
      cmd: cmd("certificates_trust", "evidence_insufficient"),
      cert: { risk_level: null, signals: 0, risk_signals: value, informational_observations: value },
    }), "Certificate Intelligence");
    return section && section.status !== "warning" && !REASSURING_CERT.test(section.summary) && !/suspicious/i.test(section.summary);
  }));
}
{
  const section = certSection(oneInfo, "evidence_insufficient", null);
  ok("SAN_B_F23", section.status === "unknown" && !REASSURING_CERT.test(section.summary));
}

// ── 7. MUTATION HARNESS — helper gates are load-bearing ──────────────────────
// Inject a mutant helper into the REAL buildScorecardSections (rewrite scorecard.js
// imports to absolute; point scorecard-domain-state at the mutant).
if (!process.argv.includes("--candidate-b-child")) {
const helperSrc = fs.readFileSync(HELPER, "utf8");
const scorecardSrc = fs.readFileSync(SCORECARD, "utf8");
async function mutantSections(mutateHelper) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "b-"));
  const hFile = path.join(dir, "helper.mjs");
  fs.writeFileSync(hFile, mutateHelper(helperSrc));
  const scSrc = scorecardSrc.replace(/from "\.\/([^"]+)"/g, (_m, f) =>
    f === "scorecard-domain-state.js" ? `from ${JSON.stringify(pathToFileURL(hFile).href)}` : `from ${JSON.stringify(absU(f))}`);
  const scFile = path.join(dir, "scorecard.mjs");
  fs.writeFileSync(scFile, scSrc);
  const mod = await import(`${pathToFileURL(scFile).href}?t=${Date.now()}-${Math.random()}`);
  fs.rmSync(dir, { recursive: true, force: true });
  return mod.buildScorecardSections;
}

// M1: unavailable → healthy.
{
  const m = helperSrc.includes('case "provisional":          return "unavailable";');
  const fn = m ? await mutantSections((s) => s.replace('case "provisional":          return "unavailable";', 'case "provisional":          return "healthy";')) : null;
  const cert = m ? sec(scorecardWith({ cmd: cmd("certificates_trust", "evidence_insufficient") }), "Certificate Intelligence", fn) : null;
  ok("mutation M1 (unavailable→healthy) is CAUGHT", m && (cert.status === "ok" || /looks normal/i.test(cert.summary)));
}
// M2: not_assessed → healthy (default case).
{
  const m = helperSrc.includes('return "not_assessed"; // not_yet_assessed');
  const fn = m ? await mutantSections((s) => s.replace('return "not_assessed"; // not_yet_assessed', 'return "healthy"; // not_yet_assessed')) : null;
  const sh = m ? sec(scorecardWith({ cmd: cmd("shadow_it_unmanaged_technology", "monitoring_only") }), "Third-Party Assets", fn) : null;
  ok("mutation M2 (not_assessed→healthy) is CAUGHT", m && (sh.status === "ok" || /no third-party/i.test(sh.summary)));
}
// M3: canSayHealthy always true (raw count zero bypasses canonical state).
{
  const m = helperSrc.includes('return scorecardBehaviour(state) === "healthy";');
  const fn = m ? await mutantSections((s) => s.replace('return scorecardBehaviour(state) === "healthy";', 'return true;')) : null;
  const brand = m ? sec(scorecardWith({ cmd: cmd("brand_protection", "evidence_insufficient") }), "Brand Monitoring", fn) : null;
  ok("mutation M3 (canSayHealthy always true → count bypasses state) is CAUGHT", m && /none currently resolving/i.test(brand.summary));
}
// M4: sectionStatus issue → ok (canonical issue suppressed by zero count).
{
  const m = helperSrc.includes('if (b === "issue")   return issueStatus;');
  const fn = m ? await mutantSections((s) => s.replace('if (b === "issue")   return issueStatus;', 'if (b === "issue")   return "ok";')) : null;
  const brand = m ? sec(scorecardWith({ cmd: cmd("brand_protection", "issue_detected") }), "Brand Monitoring", fn) : null;
  ok("mutation M4 (issue suppressed by zero count) is CAUGHT", m && brand.status === "ok");
}

// Candidate B's 13 scorecard/consumer/closure mutants. M10 is intentionally
// owned by validate-cert-shared-san-honesty-mutations.js because it mutates the
// certificate-intelligence producer in place and must also run the regression
// fixture in fresh processes.
const candidateBMutants = [
  {
    id: "SAN_B_M01",
    expected: ["SAN_B_F01", "SAN_B_F10a", "SAN_B_F10b"],
    mutateScorecard: (source) => replaceOne(source,
      ": riskCount > 0 ? 'warning'\n             : certificateFallbackStatus,",
      ": riskCount > 0 ? 'warning'\n             : infoCount > 0 && canSayHealthy(certState) ? 'warning'\n             : certificateFallbackStatus,", "SAN_B_M01"),
  },
  {
    id: "SAN_B_M02",
    expected: ["SAN_B_F02a", "SAN_B_F02b"],
    mutateScorecard: (source) => replaceOne(source,
      "if (canSayHealthy(certStateB) && !ctSourcesUnavailable &&\n      riskSignals.length === 0 && informationalObservations.length === 0) {",
      "if (canSayHealthy(certStateB)) {", "SAN_B_M02"),
  },
  {
    id: "SAN_B_M03",
    expected: ["SAN_B_F03"],
    mutateScorecard: (source) => replaceOne(source,
      "if (riskSignals.length > 0 && certRiskLevel !== 'critical') {",
      "if (certSignals.length > 0 && certRiskLevel !== 'critical') {", "SAN_B_M03"),
  },
  {
    id: "SAN_B_M04",
    expected: ["SAN_B_F04", "SAN_B_F24"],
    mutateScorecard: (source) => replaceOne(
      replaceOne(source,
        'const CERTIFICATE_RISK_SEVERITIES = new Set(["critical", "high", "medium"]);',
        'const CERTIFICATE_RISK_SEVERITIES = new Set(["high"]);', "SAN_B_M04-risk"),
      'signal.severity === "info"',
      '["info", "medium", "critical"].includes(signal.severity)', "SAN_B_M04-info"),
  },
  {
    id: "SAN_B_M05",
    expected: ["SAN_B_F06"],
    mutateScorecard: (source) => replaceOne(source,
      "signals: allSignals.length,", "signals: riskSignals.length,", "SAN_B_M05"),
  },
  {
    id: "SAN_B_M06",
    expected: ["SAN_B_F23"],
    mutateScorecard: (source) => replaceOne(source,
      ": riskCount > 0 ? 'warning'\n             : certificateFallbackStatus,",
      ": riskCount > 0 ? 'warning'\n             : infoCount > 0 ? 'ok'\n             : certificateFallbackStatus,", "SAN_B_M06"),
  },
  {
    id: "SAN_B_M07",
    expected: ["SAN_B_F11"],
    mutateScorecard: (source) => replaceNth(source,
      "certificate_risks: certificateRiskFields,",
      "certificate_risks: { risk_level: certRiskLevel, signals: certSignals.length, days_until_expiry: certDaysLeft },",
      1, "SAN_B_M07"),
  },
  {
    id: "SAN_B_M08",
    expected: ["SAN_B_F12", "SAN_B_F19"],
    mutateScorecard: (source) => replaceNth(source,
      "certificate_risks: certificateRiskFields,",
      "certificate_risks: report ? certificateRiskFields : undefined,",
      1, "SAN_B_M08"),
  },
  {
    id: "SAN_B_M09",
    expected: ["SAN_B_F24"],
    mutateScorecard: (source) => replaceOne(source,
      "const riskSignalsValid = Array.isArray(cr.risk_signals) &&\n    cr.risk_signals.every(isCertificateRiskSignal);",
      "const riskSignalsValid = Array.isArray(cr.risk_signals) &&\n    cr.risk_signals.every((signal) => ['high', 'medium'].includes(signal?.severity));", "SAN_B_M09"),
  },
  { id: "SAN_B_M11", expected: ["SAN_B_F15"], kind: "snapshot" },
  { id: "SAN_B_M12", expected: ["SAN_B_F17"], kind: "attack" },
  { id: "SAN_B_M13", expected: ["SAN_B_F20"], kind: "manifest" },
  { id: "SAN_B_M14", expected: ["SAN_B_F20"], kind: "config" },
];

function replaceOne(source, from, to, label) {
  const count = source.split(from).length - 1;
  if (count !== 1) throw new Error(`${label}: anchor count ${count}, expected 1`);
  return source.replace(from, to);
}
function replaceNth(source, from, to, nth, label) {
  const parts = source.split(from);
  if (parts.length - 1 < nth) throw new Error(`${label}: anchor count ${parts.length - 1}, expected at least ${nth}`);
  return parts.slice(0, nth).join(from) + to + parts.slice(nth).join(from);
}
function candidateFailureIds(output) {
  return String(output).split(/\r?\n/)
    .filter((line) => line.startsWith("FAIL - SAN_B_F"))
    .map((line) => line.slice("FAIL - ".length));
}
function runCandidateChild(env, { skipClosure = true } = {}) {
  const args = [fileURLToPath(import.meta.url), "--candidate-b-child"];
  if (skipClosure) args.push("--skip-closure");
  const child = spawnSync(process.execPath, args, {
    cwd: ROOT, encoding: "utf8", timeout: 120_000,
    env: { ...process.env, ...env },
  });
  const output = `${child.stdout || ""}\n${child.stderr || ""}`;
  const failures = candidateFailureIds(output);
  const summary = String(child.stdout || "").match(/B scorecard canonical: (\d+)\/(\d+) passed/);
  const normal = child.error == null && child.signal == null && child.status === 1 && summary &&
    Number(summary[2]) - Number(summary[1]) === failures.length;
  return { child, output, failures, normal };
}
function writeMutantFile(directory, name, source) {
  const file = path.join(directory, name);
  fs.writeFileSync(file, source);
  return file;
}
function absoluteScorecardSource(source) {
  return source.replace(/from "\.\/([^"]+)"/g, (_match, file) =>
    `from ${JSON.stringify(absU(file))}`);
}

let candidateMutantsKilled = 0;
let candidateInvalidKillsRejected = 0;
for (const mutant of candidateBMutants) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), `san-b-${mutant.id.toLowerCase()}-`));
  try {
    const env = {};
    let skipClosure = true;
    if (mutant.mutateScorecard) {
      const mutated = absoluteScorecardSource(mutant.mutateScorecard(scorecardSrc));
      env.SAN_B_SCORECARD_MODULE_URL = pathToFileURL(
        writeMutantFile(directory, "scorecard.mjs", mutated),
      ).href;
    } else if (mutant.kind === "snapshot") {
      const source = fs.readFileSync(REPORT_SNAPSHOT, "utf8") +
        "\n// mutant consumer: scorecard.certificate_risks.risk_signals\n";
      env.SAN_B_REPORT_SNAPSHOT_PATH = writeMutantFile(directory, "report-snapshot.js", source);
    } else if (mutant.kind === "attack") {
      const source = replaceOne(fs.readFileSync(ATTACK_SURFACE, "utf8"),
        "suspicious_certificate_signals: ci.suspicious_certificate_signals || [],",
        "suspicious_certificate_signals: (ci.suspicious_certificate_signals || []).filter((signal) => signal.severity !== 'info'),",
        mutant.id);
      env.SAN_B_ATTACK_SURFACE_PATH = writeMutantFile(directory, "attack-surface.js", source);
    } else if (mutant.kind === "manifest") {
      const shown = spawnSync("git", ["show", "9b4745706786cfed7dbc0fb61f9d01c5b818935c:workers/email-ingest/deploy-manifest.json"], {
        cwd: ROOT, encoding: "utf8",
      });
      if (shown.status !== 0) throw new Error(shown.stderr);
      env.SAN_B_MANIFEST_PATH = writeMutantFile(directory, "deploy-manifest.json", shown.stdout);
      skipClosure = false;
    } else if (mutant.kind === "config") {
      const source = fs.readFileSync(EMAIL_CONFIG, "utf8").replace(
        /^APP_VERSION\s*=\s*"[^"]+"\s*$/m,
        'APP_VERSION = "candidate-b.invalid-digest"',
      );
      env.SAN_B_EMAIL_WRANGLER_PATH = writeMutantFile(directory, "wrangler.toml", source);
      skipClosure = false;
    }
    const result = runCandidateChild(env, { skipClosure });
    if (result.normal && JSON.stringify(result.failures) === JSON.stringify(mutant.expected)) {
      candidateMutantsKilled += 1;
      console.log(`ok   - ${mutant.id} exact FAIL set ${JSON.stringify(result.failures)}`);
    } else {
      ok(`${mutant.id} exact right-reason kill`, false,
        `expected ${JSON.stringify(mutant.expected)}, got ${JSON.stringify(result.failures)}; status ${result.child.status}; ${result.output.slice(-600)}`);
    }
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

// Invalid-kill controls: syntax/load failures and a real but wrong assertion
// set must never satisfy a pinned semantic mutant.
for (const control of [
  { id: "SAN_B_SYNTAX_FAILURE_REJECTED", source: `${scorecardSrc}\nthis is invalid JavaScript !`, expectNormal: false },
  { id: "SAN_B_LOAD_FAILURE_REJECTED", source: scorecardSrc.replace('from "./posture-scoring.js";', 'from "./missing-san-b-module.js";'), expectNormal: false },
  { id: "SAN_B_NOOP_MUTATION_REJECTED", source: scorecardSrc, expectNormal: false },
  { id: "SAN_B_WRONG_REASON_REJECTED", source: replaceOne(scorecardSrc,
      'const CERTIFICATE_RISK_SEVERITIES = new Set(["critical", "high", "medium"]);',
      'const CERTIFICATE_RISK_SEVERITIES = new Set(["critical", "high"]);', "SAN_B_WRONG_REASON_REJECTED"), expectNormal: true },
]) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "san-b-control-"));
  try {
    const file = writeMutantFile(directory, "scorecard.mjs", absoluteScorecardSource(control.source));
    const result = runCandidateChild({ SAN_B_SCORECARD_MODULE_URL: pathToFileURL(file).href });
    const rejected = control.expectNormal
      ? result.normal && JSON.stringify(result.failures) !== JSON.stringify(candidateBMutants[0].expected)
      : !result.normal && result.failures.length === 0;
    if (rejected) {
      candidateInvalidKillsRejected += 1;
      console.log(`ok   - ${control.id}`);
    } else ok(control.id, false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}
ok("Candidate B scorecard mutants complete",
  candidateMutantsKilled === candidateBMutants.length && candidateInvalidKillsRejected === 4,
  `${candidateMutantsKilled}/${candidateBMutants.length} killed, ${candidateInvalidKillsRejected}/4 controls`);
}

console.log(`\nB scorecard canonical: ${pass}/${pass + fail} passed`);
if (fail) { console.error("b-scorecard-canonical validation FAILED"); process.exit(1); }
console.log("b-scorecard-canonical validation passed");
