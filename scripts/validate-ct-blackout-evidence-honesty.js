#!/usr/bin/env node
//
// Item 5 P0 — CT-provider blackout evidence honesty.
//
// Reproduces the original false-healthy shape (complete scan, present/empty
// subdomains module, no top-level error) and proves that canonical monitoring
// provenance, rather than scan failure, prevents unsupported healthy conclusions.
// Also drives the real subdomain module through a deterministic two-provider
// blackout, freezes the state in a canonical snapshot, and verifies the PDF path
// renders the limitation. Node 24+. CI-blocking and mutation-backed.

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const root = path.join(path.dirname(scriptPath), "..");
const engines = path.join(root, "workers", "scan-api", "src", "engines");
const eng = (file) => pathToFileURL(path.join(engines, file)).href;
const mutationArg = process.argv.find((arg) => arg.startsWith("--mutation="));
const mutation = mutationArg?.slice("--mutation=".length) || null;

async function loadDomainResolver() {
  const sourcePath = path.join(engines, "cyber-mot-domains.js");
  if (!mutation) return import(pathToFileURL(sourcePath).href);

  const source = fs.readFileSync(sourcePath, "utf8")
    .replace(
      'from "./dmarc-canonical-consumers.js";',
      `from "${eng("dmarc-canonical-consumers.js")}";`
    )
    .replace(
      'from "./signal-monitoring-state.js";',
      `from "${eng("signal-monitoring-state.js")}";`
    )
    .replace(
      'from "./cookie-observation.js";',
      `from "${eng("cookie-observation.js")}";`
    )
    .replace(
      'from "./tls-evidence.js";',
      `from "${eng("tls-evidence.js")}";`
    )
    .replace(
      'from "./identity-evidence-contract.js";',
      `from "${eng("identity-evidence-contract.js")}";`
    );
  let target;
  let replacement;
  if (mutation === "drop-domain-signal-gate") {
    target =
      "    if (signalCoverageLimited) {\n" +
      "      base.state = CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT;";
    replacement =
      "    if (false) {\n" +
      "      base.state = CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT;";
  } else if (mutation === "generic-domain-wording") {
    target =
      "    const signalCoverageMessage = signalCoverageLimited\n" +
      "      ? (d.monitoring_degradation_message || monitoringCoverage.messages.join(\" \"))\n" +
      "      : \"\";";
    replacement =
      "    const signalCoverageMessage = monitoringCoverage.messages.join(\" \");";
  } else {
    throw new Error(`unknown mutation: ${mutation}`);
  }
  const mutated = source.replace(target, replacement);
  if (mutated === source) throw new Error(`mutation target missing: ${mutation}`);
  return import(
    `data:text/javascript;base64,${Buffer.from(mutated).toString("base64")}#ct-blackout`
  );
}

const {
  resolveCyberMotDomainStates,
  CYBER_MOT_STATES,
} = await loadDomainResolver();
const {
  deriveSignalMonitoringStates,
  resolveSignalMonitoringCoverage,
} = await import(eng("signal-monitoring-state.js"));
const { runSubdomainsModule } = await import(eng("subdomains-scan.js"));
const { composeSnapshot } = await import(eng("report-snapshot.js"));
const { buildExecutiveReportV2 } = await import(eng("executive-report.js"));
const { buildScanReportPdf } = await import(eng("pdf.js"));
const { getCurrentPosturePresentation } = await import(eng("current-posture.js"));

let pass = 0;
let fail = 0;
const ok = (name, condition, detail = "") => {
  condition ? pass++ : fail++;
  if (!condition) console.log(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
};
const eq = (name, got, want) =>
  ok(name, got === want, `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);
const byKey = (domains, key) => domains.find((domain) => domain.domain_key === key);

const modules = {
  dns: {},
  subdomains: { count: 0, items: [], error: null },
  ssl: { https_available: true, https_probe_executed: true },
  headers: {},
  email_security: {},
  email_security_intelligence: {},
  dns_bruteforce: {},
  subdomain_takeover: {},
  asset_exposure: {},
  admin_surface_detection: {},
  cloud_storage_discovery: {},
  certificate_intelligence: {},
  identity_discovery: {},
  brand_monitoring: {},
  technology_detection: {},
  saas_exposure: {},
  third_party_discovery: {},
  vendor_relationships: {},
  cve_intelligence: {},
  known_exploited_vulnerabilities: {},
  whois_intelligence: {},
};
const providerHealth = {
  crt_sh: { outcome: "unavailable", attempts: 2, final_error: "fixture timeout" },
  certspotter: { outcome: "unavailable", attempts: 2, final_error: "fixture 503" },
};
const monitoringStates = deriveSignalMonitoringStates({
  modules,
  scanQuality: { status: "complete", modules_skipped: [] },
  providerHealth,
});
const report = {
  scan_id: "scan_ct_blackout",
  domain_id: "domain_founder",
  domain: "founder.example",
  status: "completed",
  completed_at: "2026-07-24T12:00:00.000Z",
  cyber_metrics_score: 96,
  risk_level: "excellent",
  scan_quality: { status: "complete", modules_skipped: [], warnings: [] },
  monitoring_states: monitoringStates,
  modules,
  findings: [],
};
const ceReady = {
  has_answers: true,
  complete: true,
  status: "likely_ready",
  top_gaps: [],
};

// ── Real producer: outage is bounded/non-fatal but explicitly incomplete ────
const realFetch = globalThis.fetch;
globalThis.fetch = async (url) => {
  if (String(url).includes("/dns-query?")) {
    return new Response(JSON.stringify({ Status: 0, Answer: [] }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }
  throw new Error(`unexpected network call: ${url}`);
};
const unavailableCache = {
  get: async (_domain, provider) => ({
    status: "unavailable",
    provider,
    data: null,
    error: `${provider} unavailable (fixture)`,
  }),
};
const actualBlackout = await runSubdomainsModule("founder.example", {
  ctCache: unavailableCache,
});
globalThis.fetch = realFetch;

eq("real subdomain module keeps a total CT outage non-fatal", actualBlackout.error, null);
eq("real subdomain module marks total-CT evidence incomplete", actualBlackout.incomplete, true);
eq("real subdomain module records the explicit outage reason",
  actualBlackout.incomplete_reason, "ct_sources_unavailable");
ok("real subdomain module preserves both provider errors",
  !!actualBlackout.sources?.crt_sh?.error &&
  !!actualBlackout.sources?.certspotter?.error);

// ── Canonical monitoring + domain resolution ───────────────────────────────
eq("both providers unavailable → canonical CT signal_unavailable",
  monitoringStates.signals.certificate_transparency.state, "signal_unavailable");
const ctCoverage = resolveSignalMonitoringCoverage(
  monitoringStates,
  ["certificate_transparency"]
);
eq("CT dependency coverage is not complete", ctCoverage.complete, false);
eq("CT dependency preserves signal_unavailable", ctCoverage.state, "signal_unavailable");

const domains = resolveCyberMotDomainStates(report, {
  scanId: report.scan_id,
  cyberEssentials: ceReady,
});
const attack = byKey(domains, "attack_surface");
ok("resolver propagation: invisible blackout can never produce healthy Attack Surface",
  attack.state === CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT &&
  attack.state !== CYBER_MOT_STATES.ASSESSED_HEALTHY);
eq("Attack Surface coverage is degraded, never complete", attack.coverage, "degraded");
eq("Attack Surface carries the canonical provider state",
  attack.monitoring_state, "signal_unavailable");
for (const key of [
  "certificates_trust",
  "identity_exposure",
  "cyber_essentials_readiness",
]) {
  eq(`${key} cannot claim healthy over unavailable CT evidence`,
    byKey(domains, key).state, CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT);
}
eq("Shadow IT keeps its bounded monitoring-only posture",
  byKey(domains, "shadow_it_unmanaged_technology").state,
  CYBER_MOT_STATES.MONITORING_ONLY);
eq("Shadow IT records degraded CT-dependent coverage",
  byKey(domains, "shadow_it_unmanaged_technology").coverage, "degraded");
ok("Identity explains absent reachability measurement without leaking CT-provider wording",
  /Identity reachability was not evaluated.*no supported reachability producer/i.test(
    byKey(domains, "identity_exposure").summary
  ) &&
  !/certificate transparency/i.test(byKey(domains, "identity_exposure").summary));
ok("Shadow IT explains incomplete technology coverage without leaking CT-provider wording",
  /Technology observation coverage was incomplete this run/.test(
    byKey(domains, "shadow_it_unmanaged_technology").summary
  ) &&
  !/certificate transparency/i.test(
    byKey(domains, "shadow_it_unmanaged_technology").summary
  ));
ok("Certificates keeps the CT-specific degradation wording where it is accurate",
  /certificate transparency data was unavailable/i.test(
    byKey(domains, "certificates_trust").summary
  ));
eq("unrelated Website Security remains independently assessed",
  byKey(domains, "website_security").state, CYBER_MOT_STATES.ASSESSED_HEALTHY);
eq("unrelated Email Protection remains independently assessed",
  byKey(domains, "email_protection").state, CYBER_MOT_STATES.ASSESSED_HEALTHY);

const missingProvenance = resolveCyberMotDomainStates(
  { ...report, monitoring_states: undefined },
  { cyberEssentials: ceReady }
);
eq("missing provider provenance fails toward evidence-insufficient",
  byKey(missingProvenance, "attack_surface").state,
  CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT);
const malformedProvenance = resolveSignalMonitoringCoverage({
  signals: {
    certificate_transparency: {
      state: "future_unknown_state",
      message: "Certificate transparency checks completed normally in this run.",
    },
  },
}, ["certificate_transparency"]);
eq("unrecognised provider state fails toward evidence_incomplete",
  malformedProvenance.state, "evidence_incomplete");
ok("unrecognised state cannot retain optimistic healthy wording",
  !/completed normally/i.test(malformedProvenance.messages.join(" ")));

const partialCt = deriveSignalMonitoringStates({
  modules,
  scanQuality: report.scan_quality,
  providerHealth: {
    crt_sh: providerHealth.crt_sh,
    certspotter: { outcome: "available", attempts: 1, final_error: null },
  },
});
eq("crt.sh down with CertSpotter available → monitoring_degraded",
  partialCt.signals.certificate_transparency.state, "monitoring_degraded");
eq("partial CT degradation still cannot support a healthy negative conclusion",
  byKey(
    resolveCyberMotDomainStates(
      { ...report, monitoring_states: partialCt },
      { cyberEssentials: ceReady }
    ),
    "attack_surface"
  ).state,
  CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT);

// ── Immutable snapshot + assessment/BRI/PDF consumer contract ──────────────
const snapshot = composeSnapshot({
  snapshotId: "snapshot_ct_blackout",
  workspaceId: "workspace_founder",
  domainId: report.domain_id,
  scanId: report.scan_id,
  domain: report.domain,
  report,
  cyberEssentials: ceReady,
  ceReadiness: null,
  caseRows: [],
  questionSetVersions: [],
  supersedesSnapshotId: null,
  builtAt: "2026-07-24T12:00:01.000Z",
});
eq("snapshot persists canonical CT signal_unavailable",
  snapshot.monitoring_states.signals.certificate_transparency.state,
  "signal_unavailable");
eq("snapshot freezes Attack Surface evidence_insufficient",
  byKey(snapshot.domains, "attack_surface").state,
  CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT);
eq("CT blackout lowers Attack Surface Evidence Grade to L0",
  byKey(snapshot.domains, "attack_surface").evidence_grade?.grade,
  "L0");
eq("snapshot assessment completeness is coverage-capped",
  snapshot.overall.assessment.quality, "degraded");
ok("snapshot assessment message states degraded evidence",
  /evidence sources were degraded/i.test(snapshot.overall.assessment.message));
ok("score is explicitly provisional/non-authoritative/non-comparable",
  snapshot.overall.assessment.provisional === true &&
  snapshot.overall.assessment.authoritative === false &&
  snapshot.overall.assessment.comparable === false);
eq("healthy/high rating is suppressed", snapshot.overall.score_band, null);
eq("Business Risk Indicator band is suppressed", snapshot.overall.business_risk_indicator.band, null);
eq("Business Risk Indicator is marked provisional",
  snapshot.overall.business_risk_indicator.provisional, true);
ok("overall completeness names the degraded CT signal",
  snapshot.overall.evidence_completeness.monitoring_degraded_signals.some(
    (entry) =>
      entry.signal === "certificate_transparency" &&
      entry.state === "signal_unavailable"
  ));
ok("overall summary cannot hide the low-coverage domain",
  snapshot.overall.not_fully_assessed.some(
    (entry) =>
      entry.domain_key === "attack_surface" &&
      entry.state === "evidence_insufficient"
  ));
eq("overall eight-domain Evidence Grade is capped by the CT-insufficient domain",
  snapshot.overall.evidence_grade?.grade, "L0");

const read = {
  status: "ok",
  snapshot,
  row: { id: "snapshot_ct_blackout" },
  integrity: { verified: true },
};
const executive = buildExecutiveReportV2({
  scan: { id: report.scan_id, domain: report.domain, status: "completed" },
  read,
});
eq("frontend Executive Report path receives persisted monitoring state",
  executive.monitoring_states.signals.certificate_transparency.state,
  "signal_unavailable");
eq("frontend Executive Report receives no authoritative rating",
  executive.cyber_metrics_score.rating, null);
eq("frontend Executive Report receives no authoritative BRI band",
  executive.business_risk_indicator.band, null);

const postureRow = {
  scan_id: report.scan_id,
  score: report.cyber_metrics_score,
  rating: report.risk_level,
  scan_quality: "complete",
  created_at: report.completed_at,
};
const posture = await getCurrentPosturePresentation({
  cybermeters_db: {
    prepare: () => ({
      bind: () => ({ first: async () => postureRow }),
    }),
  },
  cybermeters_reports: {
    get: async (key) => key === `reports/${report.scan_id}.json`
      ? { json: async () => report }
      : null,
  },
}, { domainId: report.domain_id });
eq("current-posture KPI does not establish authority from a CT-degraded complete row",
  posture.state, "not_established");
eq("current-posture KPI suppresses the authoritative score/rating",
  posture.authoritative, null);
ok("current-posture exposes the scan separately as provisional",
  posture.latest_provisional?.provisional === true &&
  posture.latest_provisional_scan_id === report.scan_id);

const pdf = buildScanReportPdf(
  { id: report.scan_id, domain: report.domain },
  read
);
const pdfText = new TextDecoder().decode(pdf);
ok("PDF path renders the canonical CT coverage limitation",
  pdfText.includes("Monitoring coverage: Certificate transparency data was unavailable in this run."));
ok("PDF labels the score provisional and BRI non-authoritative",
  pdfText.includes("Provisional Score") &&
  pdfText.includes("Business Risk Indicator: NOT AUTHORITATIVE"));
ok("PDF renders the canonical Limited-strength basis before the provisional number",
  pdfText.indexOf("Evidence strength: Limited") >= 0 &&
  pdfText.indexOf("Score basis:") > pdfText.indexOf("Evidence strength: Limited") &&
  pdfText.indexOf("Score basis:") < pdfText.indexOf("96 / 100") &&
  !pdfText.includes("Evidence confidence: Low"));
ok("PDF never renders a healthy/high CyberMeters assessment band",
  !pdfText.includes("CyberMeters assessment band: excellent") &&
  !pdfText.includes("CyberMeters assessment band: Excellent") &&
  !/Security rating:/i.test(pdfText));

// The mutation deletes the one generic domain signal gate. The original false-
// healthy fixture then returns immediately, so this validator must turn RED.
if (!mutation) {
  const mutatedGate = spawnSync(
    process.execPath,
    [scriptPath, "--mutation=drop-domain-signal-gate"],
    { cwd: root, encoding: "utf8" }
  );
  ok("mutation dropping CT coverage propagation turns validation RED",
    mutatedGate.status !== 0 &&
    mutatedGate.stdout.includes(
      "FAIL resolver propagation: invisible blackout can never produce healthy Attack Surface"
    ),
    `status=${mutatedGate.status} stdout=${JSON.stringify(mutatedGate.stdout.slice(0, 500))}`);
  const mutatedWording = spawnSync(
    process.execPath,
    [scriptPath, "--mutation=generic-domain-wording"],
    { cwd: root, encoding: "utf8" }
  );
  ok("mutation restoring generic CT wording on every domain turns validation RED",
    mutatedWording.status !== 0 &&
    mutatedWording.stdout.includes(
      "FAIL Shadow IT explains incomplete technology coverage without leaking CT-provider wording"
    ),
    `status=${mutatedWording.status} stdout=${JSON.stringify(mutatedWording.stdout.slice(0, 500))}`);
}

console.log(`\nct-blackout-evidence-honesty: ${pass} passed, ${fail} failed`);
if (fail > 0) {
  console.error("ct-blackout-evidence-honesty validation FAILED");
  process.exit(1);
}
console.log("ct-blackout-evidence-honesty validation passed");
process.exit(0);
