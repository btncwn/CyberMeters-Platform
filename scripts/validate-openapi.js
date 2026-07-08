#!/usr/bin/env node
//
// Zero-dependency structural validator for docs/openapi.json. Not a full OpenAPI
// schema validator — it catches the mistakes that actually break a spec in
// practice: malformed JSON, missing required top-level fields, an operation with
// no responses, and (most common) a dangling $ref. Runs in CI with no external
// download. Exits non-zero on any problem.
//
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const specPath = path.join(__dirname, "..", "docs", "openapi.json");

let doc;
try {
  doc = JSON.parse(fs.readFileSync(specPath, "utf8"));
} catch (e) {
  console.error("openapi.json is not valid JSON:", e.message);
  process.exit(1);
}

const problems = [];
if (!/^3\./.test(String(doc.openapi))) problems.push(`openapi must be 3.x, got ${doc.openapi}`);
if (!doc.info?.title) problems.push("info.title missing");
if (!doc.info?.version) problems.push("info.version missing");
if (!doc.paths || Object.keys(doc.paths).length === 0) problems.push("paths is empty");

// Every operation must declare at least one response.
const METHODS = ["get", "post", "put", "patch", "delete", "options", "head"];
let opCount = 0;
for (const [p, item] of Object.entries(doc.paths || {})) {
  for (const m of METHODS) {
    if (!item[m]) continue;
    opCount++;
    if (!item[m].responses || Object.keys(item[m].responses).length === 0) {
      problems.push(`${m.toUpperCase()} ${p} has no responses`);
    }
  }
}

// Every $ref must resolve within the document.
function resolveRef(ref) {
  if (!ref.startsWith("#/")) return true; // external refs not used here
  let node = doc;
  for (const seg of ref.slice(2).split("/")) {
    const key = seg.replace(/~1/g, "/").replace(/~0/g, "~");
    if (node && typeof node === "object" && key in node) node = node[key];
    else return false;
  }
  return true;
}
let refCount = 0;
(function walk(node) {
  if (!node || typeof node !== "object") return;
  if (typeof node.$ref === "string") { refCount++; if (!resolveRef(node.$ref)) problems.push(`dangling $ref: ${node.$ref}`); }
  for (const v of Object.values(node)) walk(v);
})(doc);

if (problems.length) {
  console.error("OpenAPI validation FAILED:");
  for (const p of problems) console.error("  - " + p);
  process.exit(1);
}
console.log(`OpenAPI valid: ${Object.keys(doc.paths).length} paths, ${opCount} operations, ${refCount} $refs all resolve`);
