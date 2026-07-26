#!/usr/bin/env node
//
// Load-bearing Item 8 PR-B mutation:
// removing customer-owned IDN exclusion must make the canonical FP fixture fail.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engines = path.join(root, "workers", "scan-api", "src", "engines");
const sourcePath = path.join(engines, "brand-passive-discovery.js");
const source = fs.readFileSync(sourcePath, "utf8");
const from = "if (own.has(reg)) continue;";
let pass = 0, fail = 0;
const ok = (name, condition, detail = "") => {
  if (condition) pass++;
  else { fail++; console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
};

ok("customer-IDN exclusion mutation site exists", source.includes(from));
if (source.includes(from)) {
  const mutantPath = path.join(engines, `.brand-idn-discovery-mutant-${process.pid}.js`);
  try {
    fs.writeFileSync(mutantPath, source.replace(from, "if (false) continue;"));
    const runner = [
      `import { buildLookalikeBaseSet, filterDiscoveredHosts } from ${JSON.stringify(pathToFileURL(mutantPath).href)};`,
      `const bases = buildLookalikeBaseSet("apple", "com");`,
      `const kept = filterDiscoveredHosts(["xn--pple-43d.com"], { brand: "apple", tld: "com", ownRegistrables: new Set(["\u0430pple.com"]), lookalikeBases: bases });`,
      `process.exit(kept.length === 0 ? 0 : 9);`,
    ].join("\n");
    const result = spawnSync(process.execPath, ["--input-type=module", "-e", runner], {
      cwd: root,
      encoding: "utf8",
    });
    ok("removing customer-IDN exclusion is killed", result.status === 9,
      `status=${result.status}; stdout=${result.stdout}; stderr=${result.stderr}`);
  } finally {
    fs.rmSync(mutantPath, { force: true });
  }
}

console.log(`\nBrand IDN discovery mutations: ${pass}/${pass + fail} passed`);
if (fail) process.exit(1);
console.log("Brand IDN discovery mutation validation passed");
