#!/usr/bin/env node
//
// Dependency license policy gate. Reads the CycloneDX SBOMs (sbom/*.cdx.json)
// and fails if any component ships under a license that isn't on the permissive
// allowlist and isn't an explicitly documented exception. Keeps a copyleft
// (GPL/AGPL/LGPL/SSPL/BUSL) or unknown-licensed dependency from silently entering
// a commercial SaaS. In CI this runs right after SBOM generation (fresh trees);
// locally it reads the committed snapshots. CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

// ── Policy: SPDX IDs safe to ship in a commercial product without obligation ──
// beyond attribution. Permissive + public-domain-equivalent only.
const ALLOW = new Set([
  "MIT", "MIT-0", "ISC", "0BSD", "BSD-2-Clause", "BSD-3-Clause",
  "Apache-2.0", "CC0-1.0", "Unlicense", "BlueOak-1.0.0", "Python-2.0",
  "WTFPL", "Zlib", "MPL-2.0", // MPL-2.0 is file-level copyleft — safe as an unmodified dep
]);

// ── Exceptions: components with a non-allowlisted license that are nonetheless
// safe, each with a documented reason. Keyed by package name (any version).
const EXCEPTIONS = {
  // LGPL native image library, pulled in only as an OPTIONAL, platform-specific
  // binary of `sharp` (build tooling). LGPL permits use of an unmodified,
  // dynamically-loaded library without copyleft reaching our code; it is never
  // bundled into the Cloudflare Worker (which can't run native binaries).
  "sharp-libvips-darwin-arm64": "LGPL-3.0-or-later — optional native lib, dynamically used, unmodified, not distributed in product",
  "sharp-libvips-darwin-x64": "LGPL-3.0-or-later — same as above (x64 build)",
  "sharp-libvips-linux-x64": "LGPL-3.0-or-later — same as above (CI/linux build)",
  "sharp-libvips-linux-arm64": "LGPL-3.0-or-later — same as above (linux arm64 build)",
  // CC-BY-4.0 browser-compatibility DATA used by browserslist/autoprefixer at
  // BUILD time only; the dataset is not redistributed in our app bundle.
  "caniuse-lite": "CC-BY-4.0 — build-time browser data, not redistributed",
};

function licenseTokens(comp) {
  const raw = [];
  for (const l of comp.licenses || []) {
    if (l.expression) raw.push(l.expression);
    else if (l.license) raw.push(l.license.id || l.license.name || "");
  }
  return raw.filter(Boolean);
}

// An SPDX expression is allowed if: it contains OR and ANY operand is allowed,
// or it's AND/single and EVERY operand is allowed. Conservative on AND.
function expressionAllowed(expr) {
  const tokens = expr.replace(/[()]/g, " ").split(/\s+(?:AND|OR|WITH)\s+/i)
    .map((t) => t.trim().replace(/\+$/, "")).filter(Boolean);
  if (!tokens.length) return false;
  const hasOr = /\sOR\s/i.test(expr);
  return hasOr ? tokens.some((t) => ALLOW.has(t)) : tokens.every((t) => ALLOW.has(t));
}

let pass = 0, fail = 0;
const violations = [];
const sbomFiles = ["sbom/scan-api.cdx.json", "sbom/frontend.cdx.json"];

for (const rel of sbomFiles) {
  const p = path.join(root, rel);
  if (!fs.existsSync(p)) { console.error(`FAIL missing SBOM: ${rel} (run the SBOM step first)`); fail++; continue; }
  const doc = JSON.parse(fs.readFileSync(p, "utf8"));
  for (const comp of doc.components || []) {
    const name = comp.name;
    const exprs = licenseTokens(comp);
    const excepted = Object.prototype.hasOwnProperty.call(EXCEPTIONS, name);

    if (excepted) { pass++; continue; }
    if (!exprs.length) { violations.push({ rel, name, version: comp.version, lic: "<none>" }); fail++; continue; }
    const okAll = exprs.every(expressionAllowed);
    if (okAll) pass++;
    else { violations.push({ rel, name, version: comp.version, lic: exprs.join(", ") }); fail++; }
  }
}

if (violations.length) {
  console.log("Disallowed / unknown licenses (add a documented EXCEPTION only if genuinely safe):");
  for (const v of violations) console.log(`  ✗ [${v.rel.split("/").pop()}] ${v.name}@${v.version} → ${v.lic}`);
}

console.log(`\nLicense policy: ${pass} allowed, ${fail} flagged`);
if (fail) { console.error("license-policy validation FAILED"); process.exit(1); }
console.log("license-policy validation passed");
