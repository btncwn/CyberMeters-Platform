#!/usr/bin/env node
// Item 9 P5 — faithful production-integrated trace wrapper.
//
// Reuses the established real runScanEngine + in-memory D1/R2 harness and asks
// it to continue through immutable snapshot, API, Executive Report and PDF.
// No stub scan engine and no network acceptance action.
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const result = spawnSync(
  process.execPath,
  [
    path.join(root, "scripts", "validate-item9-certificate-p2-engine-trace.js"),
    "--p5",
  ],
  {
    cwd: root,
    encoding: "utf8",
    stdio: "inherit",
  },
);
process.exit(result.status ?? 1);
