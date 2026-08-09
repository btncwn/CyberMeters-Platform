#!/usr/bin/env node
// AS-C3 — bounded guard for exactly two source declarations.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const rel = (file) => path.join(root, file);
const subdomainsRelative = "workers/scan-api/src/engines/subdomains-scan.js";
const signalRelative = "workers/scan-api/src/engines/attack-surface-signal-completeness.js";
const subdomains = fs.readFileSync(rel(subdomainsRelative), "utf8");
const signal = fs.readFileSync(rel(signalRelative), "utf8");

let passed = 0;
let failed = 0;
const check = (id, condition, detail = "") => {
  if (condition) { passed += 1; console.log(`PASS ${id}`); }
  else { failed += 1; console.log(`FAIL ${id}${detail ? ` — ${detail}` : ""}`); }
};

check(
  "AS_C3_SUBDOMAIN_DECLARATION_NAMES_CT_PROVIDERS_NOT_RDAP",
  /^\/\/ ── Subdomain discovery \+ brute-force scan module ──\n\/\/ Multi-source Certificate Transparency \(crt\.sh \+ CertSpotter\) subdomain discovery,/m.test(subdomains) &&
    !/^\/\/[^\n]*RDAP/m.test(subdomains),
);
check(
  "AS_C3_SIGNAL_DECLARATION_ACKNOWLEDGES_PRODUCTION_IMPORTERS",
  /^\/\/ P1 is a pure resolver with production importers: no D1\/R2\/network I\/O\./m.test(signal) &&
    !/^\/\/[^\n]*no production caller/m.test(signal),
);

const srcRoot = rel("workers/scan-api/src");
const jsFiles = [];
const walk = (dir) => {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full);
    else if (entry.isFile() && entry.name.endsWith(".js")) jsFiles.push(full);
  }
};
walk(srcRoot);
const importPattern = /from\s+["'][^"']*attack-surface-signal-completeness\.js["']/;
const importers = jsFiles
  .filter((file) => file !== rel(signalRelative) && importPattern.test(fs.readFileSync(file, "utf8")))
  .map((file) => path.relative(root, file).replaceAll(path.sep, "/"))
  .sort();
const expected = [
  "workers/scan-api/src/engines/asset-lifecycle-event-support.js",
  "workers/scan-api/src/engines/attack-surface-customer-presentation.js",
  "workers/scan-api/src/engines/attack-surface-lifecycle.js",
  "workers/scan-api/src/engines/scan-engine.js",
  "workers/scan-api/src/engines/scoring.js",
];
check(
  "AS_C3_SIGNAL_IMPORTER_INVENTORY_IS_EXACT",
  JSON.stringify(importers) === JSON.stringify(expected),
  JSON.stringify(importers),
);

console.log(`\nAS-C3 source declarations: ${passed}/${passed + failed} passed`);
if (failed) process.exit(1);
console.log("AS-C3 source declaration validation passed");
