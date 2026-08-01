#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  classifyChange,
  decisionDetails,
  loadManifest,
  markdownSummary,
  outputLines,
  unknownFailClosed,
} from "./ci-safe-docs-only-lib.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

function arg(name, fallback = null) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : fallback;
}

const eventName = arg("--event-name", process.env.GITHUB_EVENT_NAME || "");
const eventPath = arg("--event-file", process.env.GITHUB_EVENT_PATH || "");
const outputPath = arg("--output", process.env.GITHUB_OUTPUT || "");
const summaryPath = arg("--summary", process.env.GITHUB_STEP_SUMMARY || "");
const manifestPath = arg("--manifest", ".github/ci-safe-docs-only-v1.json");

let manifest = null;
let classification = null;
try {
  manifest = loadManifest(root, manifestPath);
  if (!eventPath) throw new Error("event payload path is missing");
  const event = JSON.parse(fs.readFileSync(eventPath, "utf8"));
  classification = classifyChange({ repoRoot: root, eventName, event, manifest });
} catch (error) {
  classification = unknownFailClosed(`classifier bootstrap error: ${error.message}`);
}

if (!manifest) {
  // A broken/missing manifest must never make a skip possible. Keep a minimal
  // summary/output shape so workflow conditions still resolve to RUN-ALL.
  const fallback = {
    ...classification,
    heavy_steps: [],
    expected_gross_savings_seconds: 0,
    expected_fast_path_overhead_seconds: 0,
    expected_net_savings_seconds: 0,
  };
  if (outputPath) fs.appendFileSync(outputPath, `${outputLines(fallback).join("\n")}\n`);
  if (summaryPath) {
    fs.appendFileSync(summaryPath,
      `## CI scope classification\n\n- Decision: **UNKNOWN_FAIL_CLOSED**\n` +
      `- Effective mode: **RUN_ALL**\n- Content class: **unresolved**\n` +
      `- Reason: ${classification.reason}\n- Expected wall-time saving: **0s**\n\n` +
      `### Changed paths\n\n- _(none resolved)_\n\n` +
      `### Heavy-step policy\n\nManifest unavailable; every heavy step remains RUN.\n`);
  }
  console.log(JSON.stringify(fallback));
  process.exit(0);
}

const details = decisionDetails(classification, manifest);
if (summaryPath) fs.appendFileSync(summaryPath, markdownSummary(details));
console.log(JSON.stringify(details));
// Write narrowing outputs last. If summary/logging fails first, the workflow's
// prewritten RUN-ALL defaults remain authoritative; if a later process failure
// ever occurs, the shell reasserts those defaults again.
if (outputPath) fs.appendFileSync(outputPath, `${outputLines(details).join("\n")}\n`);
