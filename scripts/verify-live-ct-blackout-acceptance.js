#!/usr/bin/env node
//
// Read-only verifier for founder-captured production artefacts. It does not call
// production, start scans, write D1/R2, or simulate provider health. Capture the
// immutable report + snapshot exactly as documented, then run this offline.

import fs from "node:fs";
import { createHash } from "node:crypto";

function arg(name) {
  const prefix = `--${name}=`;
  return process.argv.find((value) => value.startsWith(prefix))?.slice(prefix.length) ?? null;
}
function readJson(file, label) {
  if (!file) throw new Error(`--${label}=<path> is required`);
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

const scenario = arg("scenario");
if (!["crt-sh-down", "both-ct-down"].includes(scenario)) {
  throw new Error("--scenario must be crt-sh-down or both-ct-down");
}
const reportFile = arg("report");
const snapshotFile = arg("snapshot");
const expectedChecksum = String(arg("expected-checksum") || "").trim().toLowerCase();
if (!/^[a-f0-9]{64}$/.test(expectedChecksum)) {
  throw new Error("--expected-checksum=<64-character D1 checksum_sha256> is required");
}
const report = readJson(reportFile, "report");
const snapshot = readJson(snapshotFile, "snapshot");
const actualChecksum = createHash("sha256")
  .update(fs.readFileSync(snapshotFile))
  .digest("hex");
const providerHealth = report?.execution_diagnostics?.provider_health ?? {};
const reportCt = report?.monitoring_states?.signals?.certificate_transparency ?? null;
const snapshotCt = snapshot?.monitoring_states?.signals?.certificate_transparency ?? null;
const attack = (snapshot?.domains ?? []).find((entry) => entry.domain_key === "attack_surface");
const expectedState = scenario === "both-ct-down"
  ? "signal_unavailable"
  : "monitoring_degraded";

const checks = [
  ["report is a completed scan", report?.status === "completed"],
  ["report scan quality records completed core execution",
    report?.scan_quality?.status === "complete"],
  ["snapshot belongs to the captured scan",
    snapshot?.snapshot?.scan_id === report?.scan_id],
  ["snapshot bytes match the completed D1 checksum",
    actualChecksum === expectedChecksum],
  ["crt.sh is explicitly unavailable",
    providerHealth?.crt_sh?.outcome === "unavailable"],
  ["CertSpotter outcome matches the scenario",
    providerHealth?.certspotter?.outcome ===
      (scenario === "both-ct-down" ? "unavailable" : "available")],
  ["report CT monitoring state is canonical",
    reportCt?.state === expectedState],
  ["snapshot preserves the identical CT monitoring state",
    snapshotCt?.state === expectedState],
  ["subdomain evidence is explicitly incomplete",
    report?.modules?.subdomains?.incomplete === true],
  ["Attack Surface is evidence_insufficient",
    attack?.state === "evidence_insufficient"],
  ["Attack Surface coverage is not complete",
    attack?.coverage !== "complete"],
  ["snapshot score is provisional/non-authoritative",
    snapshot?.overall?.assessment?.provisional === true &&
      snapshot?.overall?.assessment?.authoritative === false],
  ["snapshot rating is suppressed",
    snapshot?.overall?.score_band == null],
  ["snapshot Business Risk Indicator band is suppressed",
    snapshot?.overall?.business_risk_indicator?.band == null],
  ["snapshot completeness names certificate transparency",
    (snapshot?.overall?.evidence_completeness?.monitoring_degraded_signals ?? [])
      .some((entry) =>
        entry?.signal === "certificate_transparency" &&
        entry?.state === expectedState
      )],
];

let failed = 0;
for (const [name, passed] of checks) {
  console.log(`${passed ? "PASS" : "FAIL"} ${name}`);
  if (!passed) failed += 1;
}
console.log(JSON.stringify({
  outcome: failed === 0 ? "PASS" : "FAIL",
  scenario,
  scan_id: report?.scan_id ?? null,
  snapshot_id: snapshot?.snapshot?.snapshot_id ?? null,
  checksum_sha256: actualChecksum,
  ct_monitoring_state: snapshotCt?.state ?? null,
  attack_surface_state: attack?.state ?? null,
  assessment_quality: snapshot?.overall?.assessment?.quality ?? null,
  rating: snapshot?.overall?.score_band ?? null,
  business_risk_band: snapshot?.overall?.business_risk_indicator?.band ?? null,
  failures: failed,
}, null, 2));
process.exit(failed === 0 ? 0 : 1);
