#!/usr/bin/env node
//
// F-041 Worker egress configuration oracle.
//
// Application-layer DoH approval and the subsequent global fetch are not
// atomically DNS-pinned. Every Worker executing an authorized sink must bind
// the documented Cloudflare public-route backstop explicitly.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const REQUIRED_FLAG = "global_fetch_strictly_public";
const CONFLICTING_FLAG = "global_fetch_private_origin";

let passed = 0;
let failed = 0;
function ok(id, condition, detail = "") {
  if (condition) {
    passed += 1;
    console.log(`PASS ${id}`);
  } else {
    failed += 1;
    console.log(`FAIL ${id}${detail ? ` — ${detail}` : ""}`);
  }
}

export function workerEgressConfigState(source) {
  const match = String(source || "").match(/^\s*compatibility_flags\s*=\s*\[([\s\S]*?)\]/m);
  const flags = match
    ? [...match[1].matchAll(/["']([^"']+)["']/g)].map((item) => item[1])
    : [];
  if (!flags.includes(REQUIRED_FLAG)) {
    return { ok: false, reason: "global_fetch_strictly_public_missing", flags };
  }
  if (flags.includes(CONFLICTING_FLAG)) {
    return { ok: false, reason: "global_fetch_private_origin_conflict", flags };
  }
  return { ok: true, reason: null, flags };
}

const configs = [
  ["SCAN_API", "workers/scan-api/wrangler.toml"],
  ["EMAIL_INGEST", "workers/email-ingest/wrangler.toml"],
];
for (const [id, relative] of configs) {
  const state = workerEgressConfigState(fs.readFileSync(path.join(root, relative), "utf8"));
  ok(`F041_CONFIG_${id}_STRICT_PUBLIC`, state.ok,
    `reason=${state.reason}, flags=${JSON.stringify(state.flags)}`);
}

const rightReasonFixture = [
  'compatibility_date = "2026-06-18"',
  'compatibility_flags = ["global_fetch_strictly_public"]',
].join("\n");
const missingState = workerEgressConfigState(
  rightReasonFixture.replace('"global_fetch_strictly_public"', '"nodejs_compat"'),
);
ok("F041_CONFIG_NEGATIVE_MISSING_FLAG_RIGHT_REASON",
  missingState.ok === false
    && missingState.reason === "global_fetch_strictly_public_missing");

const conflictState = workerEgressConfigState(
  rightReasonFixture.replace("]", ', "global_fetch_private_origin"]'),
);
ok("F041_CONFIG_NEGATIVE_CONFLICT_RIGHT_REASON",
  conflictState.ok === false
    && conflictState.reason === "global_fetch_private_origin_conflict");

console.log(`\nF-041 outbound config: ${passed} passed, ${failed} failed`);
if (failed) {
  console.error("F-041 outbound config validation FAILED");
  process.exit(1);
}
console.log("F-041 outbound config validation passed");
