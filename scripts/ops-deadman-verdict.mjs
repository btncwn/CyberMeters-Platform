#!/usr/bin/env node
//
// F-027 deadman verdict entrypoint (R1-01). The ops-deadman workflow calls THIS to
// decide healthy/reason, so the shipped decision IS the strict evaluateDeadman the
// focused validator exercises — NOT a shell/jq re-implementation. Inline jq is
// unsafe here: `.x // "missing"` turns a boolean `false` into the default (so the
// correct healthy payload reads unhealthy and the recovery branch is unreachable),
// and `jq -r` renders the string "false" identically to the boolean (so string
// impostors are accepted). Structural JSON-boolean parsing avoids both.
//
// Emits EXACTLY two GITHUB_OUTPUT lines to stdout (healthy=, reason=) and nothing
// customer-derived — reason is a fixed safe-token vocabulary. Always exits 0: the
// verdict is the output, not an error, so a false verdict must still redirect cleanly.
import { readFileSync } from "node:fs";
import { evaluateDeadman } from "../workers/scan-api/src/lib/ops-health.js";

const [, , code, readyPath] = process.argv;

function emit(healthy, reason) {
  process.stdout.write(`healthy=${healthy === true ? "true" : "false"}\nreason=${reason}\n`);
  process.exit(0);
}

// A non-200 probe is never healthy, regardless of any body served.
if (String(code) !== "200") emit(false, `http_${code || "000"}`);

let parsed;
try {
  parsed = JSON.parse(readFileSync(readyPath, "utf8"));
} catch {
  emit(false, "invalid_json");
}

const verdict = evaluateDeadman(true, parsed);
emit(verdict.healthy === true, verdict.reason);
