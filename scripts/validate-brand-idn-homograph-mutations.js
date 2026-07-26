#!/usr/bin/env node
//
// Load-bearing mutations for Item 8 PR-A:
//   M1 remove punycode decoding -> canonical xn-- fixture must be missed.
//   M2 remove skeleton mapping   -> Unicode confusable fixture must be missed.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const sourcePath = path.join(root, "workers", "scan-api", "src", "engines", "idn-homograph.js");
const source = fs.readFileSync(sourcePath, "utf8");
let pass = 0, fail = 0;
const ok = (name, condition, detail = "") => {
  if (condition) pass++;
  else { fail++; console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
};

function runMutant(name, from, to, candidate) {
  ok(`${name}: mutation site exists`, source.includes(from));
  if (!source.includes(from)) return;
  const dir = fs.mkdtempSync(path.join(path.dirname(sourcePath), ".brand-idn-mutant-"));
  try {
    const file = path.join(dir, "idn-homograph.js");
    fs.writeFileSync(file, source.replace(from, to));
    const runner = [
      `import { analyzeIdnHomograph } from ${JSON.stringify(pathToFileURL(file).href)};`,
      `const result = analyzeIdnHomograph(${JSON.stringify(candidate)}, "apple");`,
      `process.exit(result.is_homograph ? 0 : 9);`,
    ].join("\n");
    const result = spawnSync(process.execPath, ["--input-type=module", "-e", runner], {
      cwd: root,
      encoding: "utf8",
    });
    ok(`${name}: canonical homograph test kills mutant`, result.status === 9,
      `status=${result.status}; stdout=${result.stdout}; stderr=${result.stderr}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

runMutant(
  "M1 remove punycode decode",
  "const converted = tr46.toUnicode(submitted, TR46_OPTIONS);",
  "const converted = { domain: submitted, error: false };",
  "xn--pple-43d.com",
);

runMutant(
  "M2 remove confusable skeleton map",
  "const mapped = CONFUSABLE_MAP.get(char);",
  "const mapped = undefined;",
  "\u0430pple.com",
);

console.log(`\nBrand IDN/homograph mutations: ${pass}/${pass + fail} passed`);
if (fail) process.exit(1);
console.log("Brand IDN/homograph mutation validation passed");
