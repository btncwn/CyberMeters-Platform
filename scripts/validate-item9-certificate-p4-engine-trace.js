#!/usr/bin/env node
// Item 9 P4 — faithful production runScanEngine proof.
//
// Reuses the P2 in-memory D1/R2 harness because that harness already exercises
// the real production caller, shared CT cache, provider isolation, budget
// telemetry, persistence fan-out, tenant isolation, soft-delete and purge order.
// P4 extends that harness with trust-signal assertions; this wrapper makes the
// P4 proof an explicit CI capability without duplicating a second scan harness.
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const trace = path.join(
  root,
  "scripts",
  "validate-item9-certificate-p2-engine-trace.js",
);
const result = spawnSync(process.execPath, [trace], {
  cwd: root,
  encoding: "utf8",
});

if (result.stdout) process.stdout.write(result.stdout);
if (result.stderr) process.stderr.write(result.stderr);
if (result.status !== 0) {
  console.error("Item 9 P4 faithful runScanEngine trace FAILED");
  process.exit(1);
}

console.log(
  "Item 9 P4 faithful runScanEngine trace passed " +
  "(real caller, v2 trust signals, budget, shared CT and tenant persistence)",
);
