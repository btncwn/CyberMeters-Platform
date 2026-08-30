#!/usr/bin/env node

// A2 mutation assurance. Every mutant runs in an isolated temporary copy, so
// the shared worktree is never rewritten and concurrent seats remain safe.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const VALIDATOR = "validate-dmarc-historical-consistency.js";

function replaceOnce(file, before, after) {
  const source = fs.readFileSync(file, "utf8");
  const first = source.indexOf(before);
  const second = first < 0 ? -1 : source.indexOf(before, first + before.length);
  if (first < 0 || second >= 0) {
    throw new Error(`mutation anchor count was not exactly one in ${file}`);
  }
  fs.writeFileSync(file, source.slice(0, first) + after + source.slice(first + before.length));
}

function engine(root, name) {
  return path.join(root, "workers", "scan-api", "src", "engines", name);
}

function route(root, name) {
  return path.join(root, "workers", "scan-api", "src", "routes", name);
}

const createdCopies = [];

function prepareCopy() {
  const copy = fs.mkdtempSync(path.join(os.tmpdir(), "cybermeters-a2-mutant-"));
  createdCopies.push(copy);
  fs.mkdirSync(path.join(copy, "workers", "scan-api"), { recursive: true });
  fs.cpSync(
    path.join(ROOT, "workers", "scan-api", "src"),
    path.join(copy, "workers", "scan-api", "src"),
    { recursive: true },
  );
  const workerNodeModules = path.join(ROOT, "workers", "scan-api", "node_modules");
  if (fs.existsSync(workerNodeModules)) {
    fs.symlinkSync(
      workerNodeModules,
      path.join(copy, "workers", "scan-api", "node_modules"),
      "dir",
    );
  }
  fs.symlinkSync(path.join(ROOT, "shared"), path.join(copy, "shared"), "dir");
  fs.cpSync(path.join(ROOT, "database"), path.join(copy, "database"), { recursive: true });
  fs.mkdirSync(path.join(copy, "scripts", "fixtures"), { recursive: true });
  fs.mkdirSync(path.join(copy, "scripts", "lib"), { recursive: true });
  fs.copyFileSync(
    path.join(ROOT, "scripts", VALIDATOR),
    path.join(copy, "scripts", VALIDATOR),
  );
  fs.copyFileSync(
    path.join(ROOT, "scripts", "fixtures", "dmarc-production-shape.json"),
    path.join(copy, "scripts", "fixtures", "dmarc-production-shape.json"),
  );
  fs.copyFileSync(
    path.join(ROOT, "scripts", "lib", "migration-apply-tolerated.js"),
    path.join(copy, "scripts", "lib", "migration-apply-tolerated.js"),
  );
  return copy;
}

function execute(mutant) {
  const copy = prepareCopy();
  try {
    if (mutant?.apply) mutant.apply(copy);
    return spawnSync(process.execPath, [path.join(copy, "scripts", VALIDATOR)], {
      cwd: copy,
      encoding: "utf8",
      timeout: 30_000,
    });
  } finally {
    fs.rmSync(copy, { recursive: true, force: true });
  }
}

const baseline = execute(null);
if (baseline.status !== 0) {
  process.stderr.write(baseline.stdout || "");
  process.stderr.write(baseline.stderr || "");
  throw new Error(`A2 mutation baseline failed with status ${baseline.status}`);
}
console.log("ok   - baseline passes in isolated copy");

const mutants = [
  {
    id: "M1",
    name: "remove production .value retention",
    apply(copy) {
      replaceOnce(
        engine(copy, "dmarc-state.js"),
        "    evidence?.source_record?.raw,\n    evidence?.source_record?.value,",
        "    evidence?.source_record?.raw,",
      );
      replaceOnce(
        engine(copy, "dmarc-state.js"),
        ".flatMap((record) => [record?.raw, record?.value])",
        ".flatMap((record) => [record?.raw])",
      );
    },
  },
  {
    id: "M2",
    name: "remove historical producer re-observation gate",
    apply(copy) {
      replaceOnce(
        engine(copy, "historical-scan.js"),
        ".filter((id) => currentProducerWasReobserved(prevFindingMap[id], currentModules))",
        ".filter(() => true)",
      );
      replaceOnce(
        engine(copy, "historical-scan.js"),
        ".filter((id) => !currentProducerWasReobserved(prevFindingMap[id], currentModules))",
        ".filter(() => false)",
      );
    },
  },
  {
    id: "M3",
    name: "remove API comparable gate",
    apply(copy) {
      replaceOnce(
        path.join(copy, "workers", "scan-api", "src", "routes", "scans.js"),
        "  if (comparable !== true) {",
        "  if (false && comparable !== true) {",
      );
    },
  },
  {
    id: "M4",
    name: "force hosted RUA refusal incomplete",
    apply(copy) {
      replaceOnce(
        engine(copy, "dmarcbis-production.js"),
        ": allDestinationsNotRequired ? \"complete\" : \"incomplete\",",
        ": \"incomplete\",",
      );
    },
  },
  {
    id: "M5",
    name: "let parsed DMARC detail bypass canonical action gate",
    apply(copy) {
      replaceOnce(
        engine(copy, "email-analysis.js"),
        "  if (dmarcConclusionObserved) {",
        "  if (true) {",
      );
    },
  },
  {
    id: "M6",
    name: "drift fixture raw field back to string",
    apply(copy) {
      const file = path.join(copy, "scripts", "fixtures", "dmarc-production-shape.json");
      const value = JSON.parse(fs.readFileSync(file, "utf8"));
      value.source_record.raw = value.source_record.value;
      value.raw_records[0].raw = value.raw_records[0].value;
      fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
    },
  },
  {
    id: "M7",
    name: "remove engine comparability cleanup assignment",
    apply(copy) {
      replaceOnce(
        engine(copy, "scan-engine.js"),
        `      modules.historical_changes = applyScanComparability(
        modules.historical_changes,
        scanQuality.status === "complete",
        scanQuality.status,
      );`,
        `      modules.historical_changes = {
        ...modules.historical_changes,
        comparable: scanQuality.status === "complete",
        score_change: scanQuality.status === "complete"
          ? modules.historical_changes.score_change
          : null,
      };`,
      );
    },
  },
  {
    id: "M8",
    name: "retain non-comparable new and resolved lists",
    apply(copy) {
      replaceOnce(
        engine(copy, "historical-scan.js"),
        `    new_findings: [],
    resolved_findings: [],`,
        `    new_findings: preserved.new_findings || [],
    resolved_findings: preserved.resolved_findings || [],`,
      );
    },
  },
  {
    id: "M9",
    name: "remove comparability suppression reason stamp",
    apply(copy) {
      replaceOnce(
        engine(copy, "historical-scan.js"),
        `    comparison_suppressed_reason: "scan_not_comparable",
    comparison_scan_quality: quality,`,
        `    comparison_scan_quality: quality,`,
      );
    },
  },
  {
    id: "M10",
    name: "bypass failed-report historical projection",
    apply(copy) {
      replaceOnce(
        route(copy, "scans.js"),
        `            historical_changes: projectHistoricalChangesForCustomer(
              normalisedModules.historical_changes,
              { comparable: false, currentModules: normalisedModules },
            ),`,
        `            historical_changes: normalisedModules.historical_changes,`,
      );
    },
  },
  {
    id: "M11",
    name: "remove catch fallback not-reobserved shape",
    apply(copy) {
      replaceOnce(
        engine(copy, "scan-engine.js"),
        `        resolved_findings:  [],
        not_reobserved_findings: [],
        new_takeover_risks: [],`,
        `        resolved_findings:  [],
        new_takeover_risks: [],`,
      );
    },
  },
  {
    id: "H1",
    name: "remove the late reconciliation call",
    apply(copy) {
      replaceOnce(
        engine(copy, "scan-engine.js"),
        `      modules.historical_changes = reconcileLateFindings(
        modules.historical_changes,
        findings,
        modules,
      );`,
        "      modules.historical_changes = modules.historical_changes;",
      );
    },
  },
  {
    id: "H2",
    name: "run late reconciliation twice",
    apply(copy) {
      replaceOnce(
        engine(copy, "scan-engine.js"),
        `      modules.historical_changes = reconcileLateFindings(
        modules.historical_changes,
        findings,
        modules,
      );`,
        `      modules.historical_changes = reconcileLateFindings(
        modules.historical_changes,
        findings,
        modules,
      );
      modules.historical_changes = reconcileLateFindings(
        modules.historical_changes,
        findings,
        modules,
      );`,
      );
    },
  },
  {
    id: "H3",
    name: "reconcile only after comparability",
    apply(copy) {
      replaceOnce(
        engine(copy, "scan-engine.js"),
        `      modules.historical_changes = reconcileLateFindings(
        modules.historical_changes,
        findings,
        modules,
      );
      modules.historical_changes = applyScanComparability(
        modules.historical_changes,
        scanQuality.status === "complete",
        scanQuality.status,
      );`,
        `      modules.historical_changes = applyScanComparability(
        modules.historical_changes,
        scanQuality.status === "complete",
        scanQuality.status,
      );
      modules.historical_changes = reconcileLateFindings(
        modules.historical_changes,
        findings,
        modules,
      );`,
      );
    },
  },
  {
    id: "H4",
    name: "resolve missing rows without producer re-observation",
    apply(copy) {
      replaceOnce(
        engine(copy, "historical-scan.js"),
        ".filter((finding) =>\n    currentProducerWasReobserved(finding, currentModules));",
        ".filter(() => true);",
      );
      replaceOnce(
        engine(copy, "historical-scan.js"),
        ".filter((finding) =>\n    !currentProducerWasReobserved(finding, currentModules));",
        ".filter(() => false);",
      );
    },
  },
  {
    id: "H5",
    name: "serialize private previous finding rows",
    apply(copy) {
      replaceOnce(
        engine(copy, "historical-scan.js"),
        "    enumerable: false,\n    configurable: false,",
        "    enumerable: true,\n    configurable: false,",
      );
    },
  },
  {
    id: "H6",
    name: "mutate the caller current-finding array during reconciliation",
    apply(copy) {
      replaceOnce(
        engine(copy, "historical-scan.js"),
        "  const currentRows = compactFindingRows(currentFindings);",
        `  const currentRows = compactFindingRows(currentFindings);
  if (Array.isArray(currentFindings)) currentFindings.length = 0;`,
      );
    },
  },
  {
    id: "H7",
    name: "break only cloud history while preserving MTA and KEV",
    apply(copy) {
      replaceOnce(
        engine(copy, "historical-scan.js"),
        `  const module = currentModules?.[finding?.module];
  if (!module || typeof module !== "object") return false;`,
        `  const module = currentModules?.[finding?.module];
  if (finding?.module === "cloud_storage_discovery") return false;
  if (!module || typeof module !== "object") return false;`,
      );
    },
  },
  {
    id: "H8",
    name: "bypass canonical DMARC re-observation rule",
    apply(copy) {
      replaceOnce(
        engine(copy, "historical-scan.js"),
        "  if (isDmarcFindingId(finding?.id)) {",
        "  if (false && isDmarcFindingId(finding?.id)) {",
      );
    },
  },
  {
    id: "H9",
    name: "perform a second historical D1 and R2 comparison read",
    apply(copy) {
      replaceOnce(
        engine(copy, "scan-engine.js"),
        `      modules.historical_changes = await runHistoricalModule(
        scanId, domain, score, findings, modules, env, workspaceId
      );`,
        `      modules.historical_changes = await runHistoricalModule(
        scanId, domain, score, findings, modules, env, workspaceId
      );
      modules.historical_changes = await runHistoricalModule(
        scanId, domain, score, findings, modules, env, workspaceId
      );`,
      );
    },
  },
  {
    id: "H10",
    name: "retain derived lists on a non-comparable terminal",
    apply(copy) {
      replaceOnce(
        engine(copy, "historical-scan.js"),
        `    new_findings: [],
    resolved_findings: [],`,
        `    new_findings: preserved.new_findings || [],
    resolved_findings: preserved.resolved_findings || [],`,
      );
    },
  },
  {
    id: "H11",
    name: "break only KEV history while preserving MTA and cloud",
    apply(copy) {
      replaceOnce(
        engine(copy, "historical-scan.js"),
        `  const module = currentModules?.[finding?.module];
  if (!module || typeof module !== "object") return false;`,
        `  const module = currentModules?.[finding?.module];
  if (finding?.module === "known_exploited_vulnerabilities") return false;
  if (!module || typeof module !== "object") return false;`,
      );
    },
  },
  {
    id: "M-S3b-1",
    name: "drop both canonical TLS re-observation gates",
    apply(copy) {
      replaceOnce(
        engine(copy, "historical-scan.js"),
        `    if (currentModules?.ssl?.tls_state !== TLS_RUNTIME_STATES.OBSERVED_PRESENT ||
        !module || typeof module !== "object" || module.executed === false ||`,
        `    if (!module || typeof module !== "object" || module.executed === false ||`,
      );
      replaceOnce(
        engine(copy, "historical-scan.js"),
        `        module.tls_state !== TLS_RUNTIME_STATES.OBSERVED_PRESENT ||
        module.evidence_source !== "certificate_transparency" ||`,
        `        module.evidence_source !== "certificate_transparency" ||`,
      );
    },
  },
  {
    id: "M-S3b-2",
    name: "ignore expiry-pair and positive-provider coherence",
    apply(copy) {
      replaceOnce(
        engine(copy, "historical-scan.js"),
        `    return Number.isFinite(observedAtMs) && Number.isFinite(expiresAtMs) &&
      expiresAtMs > observedAtMs && Number.isFinite(days) && Number.isInteger(days) && days >= 0 &&
      Math.abs(Math.floor((expiresAtMs - observedAtMs) / 86_400_000) - days) <= 1 &&
      (Number(module.ct_sources?.crt_sh) > 0 || Number(module.ct_sources?.certspotter) > 0);`,
        "    return true;",
      );
    },
  },
  {
    id: "M-S3b-3",
    name: "ignore unusable expiry-evidence state",
    apply(copy) {
      replaceOnce(
        engine(copy, "historical-scan.js"),
        `        module.live_certificate_verified !== false || module.expiry_evidence !== "usable") {`,
        `        module.live_certificate_verified !== false) {`,
      );
    },
  },
  {
    id: "M-S3b-4",
    name: "suppress legitimate coherent certificate resolution",
    apply(copy) {
      replaceOnce(
        engine(copy, "historical-scan.js"),
        `  if (finding?.id === "certificate_expiring_critical" ||
      finding?.id === "certificate_expiring_soon") {
    const module = currentModules?.certificate_intelligence;`,
        `  if (finding?.id === "certificate_expiring_critical" ||
      finding?.id === "certificate_expiring_soon") {
    return false;
    const module = currentModules?.certificate_intelligence;`,
      );
    },
  },
  {
    id: "M-S3b-5",
    name: "apply the certificate gate to every finding identity",
    apply(copy) {
      replaceOnce(
        engine(copy, "historical-scan.js"),
        `  if (finding?.id === "certificate_expiring_critical" ||
      finding?.id === "certificate_expiring_soon") {`,
        "  if (true) {",
      );
    },
  },
];

const expectedFailure = {
  M1: /FAIL - production shape derives observed_policy/,
  M2: /FAIL - historical incomplete producer does not resolve prior DMARC finding|FAIL - historical incomplete producer records prior DMARC as not re-observed/,
  M3: /FAIL - API projection suppresses new and resolved lists when not comparable/,
  M4: /FAIL - hosted RUA refusal preserves complete\/not-required result/,
  M5: /FAIL - parsed p=none detail cannot outrun an incomplete canonical conclusion|FAIL - direct action rebuild also rejects unavailable canonical state/,
  M6: /FAIL - fixture source_record.raw is a DoH-shaped object/,
  M7: /FAIL - raw terminal R2 suppresses derived new and resolved lists/,
  M8: /FAIL - non-comparable helper suppresses only derived new\/resolved claims/,
  M9: /FAIL - non-comparable helper stamps exact reason and actual quality/,
  M10: /FAIL - failed legacy report route suppresses stored new and resolved claims/,
  M11: /FAIL - engine historical catch fallback carries not-reobserved shape parity/,
  H1: /FAIL - engine reconciles once after Phase 7h and before comparability/,
  H2: /FAIL - engine reconciles once after Phase 7h and before comparability/,
  H3: /FAIL - engine reconciles once after Phase 7h and before comparability/,
  H4: /FAIL - late reconcile keeps unavailable MTA evidence not re-observed|FAIL - late reconcile keeps a deferred cloud producer not re-observed/,
  H5: /FAIL - private previous findings never enter enumerable or JSON report shape/,
  H6: /FAIL - late reconcile does not mutate inputs and keeps private rows non-enumerable/,
  H7: /FAIL - late cloud_storage_discovery completed producer resolved transition is exact/,
  H8: /FAIL - historical incomplete producer does not resolve prior DMARC finding|FAIL - historical incomplete producer records prior DMARC as not re-observed/,
  H9: /FAIL - engine performs exactly one historical D1\/R2 comparison read/,
  H10: /FAIL - non-comparable helper suppresses only derived new\/resolved claims/,
  H11: /FAIL - late known_exploited_vulnerabilities completed producer resolved transition is exact/,
  "M-S3b-1": /FAIL - certificate history keeps TLS unavailable not re-observed/,
  "M-S3b-2": /FAIL - certificate history keeps (?:blank expiry date|past expiry date|incoherent expiry pair|zero CT providers) not re-observed/,
  "M-S3b-3": /FAIL - certificate history keeps expiry evidence not usable not re-observed/,
  "M-S3b-4": /FAIL - certificate history resolves a prior id only after coherent 30-day re-observation/,
  "M-S3b-5": /FAIL - certificate-specific history gate never captures a non-certificate identity/,
};

const guardedSourcePaths = [
  engine(ROOT, "historical-scan.js"),
  engine(ROOT, "scan-engine.js"),
  route(ROOT, "scans.js"),
  path.join(ROOT, "scripts", VALIDATOR),
  fileURLToPath(import.meta.url),
];
const sha256 = (file) => createHash("sha256").update(fs.readFileSync(file)).digest("hex");
const sourceHashesBefore = Object.fromEntries(guardedSourcePaths.map((file) => [file, sha256(file)]));

let killed = 0;
for (const mutant of mutants) {
  const result = execute(mutant);
  const output = `${result.stdout || ""}\n${result.stderr || ""}`;
  const didFail = result.status !== 0 &&
    expectedFailure[mutant.id].test(output) &&
    !/SyntaxError|ERR_MODULE_NOT_FOUND/.test(output);
  if (didFail) {
    killed += 1;
    console.log(`ok   - ${mutant.id} killed: ${mutant.name}`);
  } else {
    console.error(`FAIL - ${mutant.id} survived: ${mutant.name}`);
    if (output.trim()) console.error(output.trim());
  }
}

const sourceHashesAfter = Object.fromEntries(guardedSourcePaths.map((file) => [file, sha256(file)]));
const sourceUnchanged = JSON.stringify(sourceHashesAfter) === JSON.stringify(sourceHashesBefore);
const residueFree = createdCopies.every((copy) => !fs.existsSync(copy));
console.log(`${sourceUnchanged ? "ok  " : "FAIL"} - shared source hashes unchanged`);
console.log(`${residueFree ? "ok  " : "FAIL"} - zero owned temporary mutant residue`);

console.log(`\nA2 mutations: ${killed}/${mutants.length} killed`);
if (killed !== mutants.length || !sourceUnchanged || !residueFree) process.exit(1);
