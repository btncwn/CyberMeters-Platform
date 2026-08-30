#!/usr/bin/env node
//
// PR-5.1: scan-completion customer copy must disclose partial/degraded/unknown
// coverage and must not publish an unqualified risk band. Complete-quality copy
// is pinned to its pre-change bytes. The validator also executes an in-memory
// source mutation that removes the shared scan_quality gate; that run must fail.
// CI-blocking.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const root = path.join(path.dirname(scriptPath), "..");
const worker = path.join(root, "workers", "scan-api", "src");
const mutationMode = process.argv.includes("--mutate-scan-quality-gate");

async function loadPresentationModule() {
  const sourcePath = path.join(worker, "engines", "assessment-presentation.js");
  if (!mutationMode) return import(pathToFileURL(sourcePath).href);

  // data: modules cannot resolve relative specifiers, so BOTH real relative
  // imports are rewritten to absolute file URLs (the REAL scoring bindings —
  // CYBER_METRICS_SCORE_METHODOLOGY_VERSION + riskLevelForScore — stay intact);
  // each rewrite is a must-fail anchor: a silent no-op replace previously
  // crashed the child at load before the gate mutation could run.
  const gate = "const complete = quality === SCAN_QUALITY.COMPLETE;";
  const scoringAbs = `import {\n  CYBER_METRICS_SCORE_METHODOLOGY_VERSION,\n  riskLevelForScore,\n} from "${pathToFileURL(path.join(worker, "engines", "scoring.js")).href}";`;
  const raw = fs.readFileSync(sourcePath, "utf8");
  const withScoring = raw.replace('import {\n  CYBER_METRICS_SCORE_METHODOLOGY_VERSION,\n  riskLevelForScore,\n} from "./scoring.js";', scoringAbs);
  if (withScoring === raw) throw new Error("scan-completion scoring import anchor missing");
  const source = withScoring.replace('from "./signal-monitoring-state.js";', `from "${pathToFileURL(path.join(worker, "engines", "signal-monitoring-state.js")).href}";`);
  if (source === withScoring || !source.includes(gate)) throw new Error("scan-completion monitoring anchor or quality gate target missing");
  const mutated = source.replace(gate, "const complete = true;");
  return import(`data:text/javascript;base64,${Buffer.from(mutated).toString("base64")}`);
}

const presentation = await loadPresentationModule();
const { buildScanCompletionPresentation, scanCompletionQualityDisclosure } = presentation;
const { buildAssetAlertEmail } = await import(pathToFileURL(path.join(worker, "engines", "asset-alerts.js")).href);
const { buildLifecycleEmail } = await import(pathToFileURL(path.join(worker, "lib", "lifecycle-email.js")).href);
const { createNotificationsForDomain, scanCompletionAuditStatement } = await import(pathToFileURL(path.join(worker, "lib", "events.js")).href);

let pass = 0;
let fail = 0;
const ok = (name, condition, detail = "") => {
  condition ? pass++ : fail++;
  if (!condition) console.log(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
};
const eq = (name, got, want) => ok(name, got === want, `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);
const sha256 = (value) => crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");

function assertNonCompleteCopy(label, copy, expectedLead) {
  ok(`${label}: disclosure names incomplete coverage`, copy.disclosure?.startsWith(expectedLead), copy.disclosure);
  ok(`${label}: disclosure says results may be incomplete`, copy.disclosure?.includes("results may be incomplete"), copy.disclosure);
  ok(`${label}: score is explicitly provisional`, copy.message?.includes("Score: 95 (provisional)"), copy.message);
  ok(`${label}: description is explicitly provisional`, copy.description?.includes("score 95 (provisional)"), copy.description);
  ok(`${label}: unqualified risk band is suppressed`, !/excellent risk|risk excellent/i.test(`${copy.message} ${copy.description}`));
}

function captureScanCompletionAudit(scanQuality) {
  let captured = null;
  const env = {
    cybermeters_db: {
      prepare(sql) {
        return {
          bind(...args) {
            captured = { sql, args };
            return captured;
          },
        };
      },
    },
  };
  scanCompletionAuditStatement(env, {
    workspace_id: "workspace_1",
    scan_id: "scan_1",
    domain: "example.com",
    domain_id: "domain_1",
    score: 95,
    risk_level: "excellent",
    scan_quality: scanQuality,
  });
  return captured;
}

// ── Canonical completion copy ───────────────────────────────────────────────
{
  const complete = buildScanCompletionPresentation({
    domain: "example.com", score: 95, riskLevel: "excellent", scanQuality: "complete",
  });
  eq("complete audit description is byte-unchanged",
    complete.description,
    "Scan completed for example.com — score 95, risk excellent");
  eq("complete notification message is byte-unchanged",
    complete.message,
    "Score: 95 · excellent risk");
  eq("complete quality has no caveat", complete.disclosure, null);

  assertNonCompleteCopy("partial", buildScanCompletionPresentation({
    domain: "example.com", score: 95, riskLevel: "excellent", scanQuality: "partial",
  }), "Partial scan");
  assertNonCompleteCopy("degraded", buildScanCompletionPresentation({
    domain: "example.com", score: 95, riskLevel: "excellent", scanQuality: "degraded",
  }), "Degraded scan");
  assertNonCompleteCopy("unknown/fail-closed", buildScanCompletionPresentation({
    domain: "example.com", score: 95, riskLevel: "excellent", scanQuality: null,
  }), "Scan coverage was not confirmed");
}

// ── Real in-app notification writer ─────────────────────────────────────────
async function captureScanNotification(scanQuality) {
  const inserted = [];
  const env = {
    cybermeters_db: {
      prepare(sql) {
        return {
          bind(...args) {
            return {
              all: async () => /SELECT workspace_id FROM workspace_domains/.test(sql)
                ? { results: [{ workspace_id: "workspace_1" }] }
                : { results: [] },
              run: async () => {
                if (/INSERT INTO notification_events/.test(sql)) {
                  inserted.push({
                    type: args[3],
                    title: args[5],
                    message: args[6],
                  });
                }
                return { meta: { changes: 1 } };
              },
            };
          },
        };
      },
    },
  };
  await createNotificationsForDomain(
    "domain_1",
    "example.com",
    "scan_1",
    95,
    "excellent",
    [{ severity: "critical" }, { severity: "high" }],
    env,
    scanQuality,
  );
  return inserted.find((row) => row.type === "scan_completed");
}

{
  const complete = await captureScanNotification("complete");
  eq("complete in-app notification title is unchanged", complete?.title, "Scan completed for example.com");
  eq("complete in-app notification message is byte-unchanged",
    complete?.message,
    "Score: 95 · excellent risk · 1 critical finding · 1 high finding");

  const partial = await captureScanNotification("partial");
  ok("partial in-app notification discloses incomplete coverage", partial?.message.includes("Partial scan"));
  ok("partial in-app notification retains real finding counts",
    partial?.message.endsWith("· 1 critical finding · 1 high finding"));
  ok("partial in-app notification suppresses the band", !partial?.message.includes("excellent"));
}

// ── Asset-alert email ────────────────────────────────────────────────────────
const assetArgs = [
  "example.com",
  "workspace_1",
  "scan_1",
  { new_asset_discovered: 1 },
  ["<admin>.example.com"],
  "high",
  "https://app.cybermeters.com/assets",
];

{
  const complete = buildAssetAlertEmail(...assetArgs, "complete");
  eq("complete asset-alert email is byte-unchanged",
    sha256(complete),
    "bd35f9e4dc33e49178c09a7db273ff29f05524b9bcb5d930a5109e9dca995642");
  ok("complete asset-alert email has no quality caveat",
    !complete.text.includes("results may be incomplete") && !complete.html.includes("results may be incomplete"));

  for (const quality of ["partial", "degraded"]) {
    const rendered = buildAssetAlertEmail(...assetArgs, quality);
    ok(`${quality} asset-alert text discloses scan quality`,
      rendered.text.includes("Scan quality:") && rendered.text.includes("results may be incomplete"));
    ok(`${quality} asset-alert HTML discloses scan quality`,
      rendered.html.includes("results may be incomplete"));
    ok(`${quality} asset-alert qualifies its real alert severity`,
      rendered.html.includes("Event severity:"));
  }
}

// ── First-scan lifecycle email ───────────────────────────────────────────────
const lifecycleArgs = {
  origin: "https://app.cybermeters.com",
  wsName: "Acme",
  domain: "example.com",
};

{
  const complete = buildLifecycleEmail("lifecycle_first_scan_completed", {
    ...lifecycleArgs, scanQuality: "complete",
  });
  eq("complete first-scan lifecycle email is byte-unchanged",
    sha256(complete),
    "3314af5929c23814a8bedeabc312a20bedffc6b80d289d30c0b8ddce4c9db301");

  const partial = buildLifecycleEmail("lifecycle_first_scan_completed", {
    ...lifecycleArgs, scanQuality: "partial",
  });
  ok("partial first-scan lifecycle text discloses incomplete results",
    partial.text.includes("Partial scan") && partial.text.includes("results may be incomplete"));
  ok("partial first-scan lifecycle HTML discloses incomplete results",
    partial.html.includes("Partial scan") && partial.html.includes("results may be incomplete"));
}

// ── Production wiring and retry preservation ────────────────────────────────
{
  const scanEngine = fs.readFileSync(path.join(worker, "engines", "scan-engine.js"), "utf8");
  const assetDelivery = fs.readFileSync(path.join(worker, "engines", "asset-alert-delivery.js"), "utf8");
  const lifecycle = fs.readFileSync(path.join(worker, "lib", "lifecycle-email.js"), "utf8");
  const partialAudit = captureScanCompletionAudit("partial");
  const expectedPartialAudit = buildScanCompletionPresentation({
    domain: "example.com", score: 95, riskLevel: "excellent", scanQuality: "partial",
  });

  ok("scan engine passes quality to asset email delivery",
    /sendAssetChangeAlert\([^)]*scanQuality\?\.status\)/.test(scanEngine));
  ok("scan engine passes quality to in-app notification delivery",
    /createNotificationsForDomain\([\s\S]{0,260}scanQuality\?\.status,\s*monitoringStates,\s*\)/.test(scanEngine));
  ok("atomic scan-completed audit writer uses canonical completion copy",
    /scanCompletionAuditStatement\(env,\s*latch\.completion\)/.test(scanEngine) &&
      /INSERT INTO audit_events/.test(partialAudit?.sql || "") &&
      partialAudit?.args?.[3] === expectedPartialAudit.description);
  ok("first-scan lifecycle email receives the current scan quality",
    /lifecycle_first_scan_completed[\s\S]{0,120}scan_quality:\s*scanQuality\?\.status/.test(scanEngine));
  ok("asset initial and retry delivery read persisted scan quality",
    /SELECT workspace_id, scan_quality FROM scans/.test(assetDelivery) &&
      /LEFT JOIN scans s ON s\.id = aar\.scan_id/.test(assetDelivery));
  ok("lifecycle retry recovers first-scan quality without a schema change",
    /CASE WHEN le\.type = 'lifecycle_first_scan_completed'[\s\S]{0,500}SELECT s\.scan_quality/.test(lifecycle));
  ok("unknown quality fails closed",
    scanCompletionQualityDisclosure(null).complete === false);
}

// Execute the validator against a real source mutation. Replacing the shared
// quality check with `true` must make the nested run red.
if (!mutationMode) {
  const mutation = spawnSync(process.execPath, [scriptPath, "--mutate-scan-quality-gate"], {
    cwd: root,
    encoding: "utf8",
  });
  ok("mutation: removing the scan_quality gate makes this validator RED",
    mutation.status !== 0 && mutation.stdout.includes("FAIL partial:"));
}

console.log(`\nscan-completion-quality-copy: ${pass} passed, ${fail} failed`);
if (fail) {
  console.error("scan-completion-quality-copy validation FAILED");
  process.exit(1);
}
console.log("scan-completion-quality-copy validation passed");
