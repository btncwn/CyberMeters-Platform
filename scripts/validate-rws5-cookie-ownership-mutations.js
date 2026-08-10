#!/usr/bin/env node
// RWS.5 semantic mutation gate. Node 24+.
//
// Every mutant is an exact source anchor/replacement applied in a fresh sandbox.
// A kill is valid only when the focused semantic child completes normally, proves
// the exact mutated module URL + SHA it loaded, and returns the exact registered
// failure set. Parse/import/runtime/setup errors are rejected as invalid kills.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const validatorRelative = "scripts/validate-rws5-cookie-ownership.js";
const discover = process.argv.includes("--discover");

const MUTATIONS = Object.freeze([
  {
    id: "broad-dse-removal",
    file: "workers/scan-api/src/engines/cookie-observation.js",
    anchor: 'return COOKIE_FINDING_SET.has(String(findingId || ""));',
    replacement: 'return String(findingId || "").startsWith("dse_");',
    expectedFailures: [
      "dse_caa_no_issuers: Attack Surface ownership preserved",
      "dse_caa_no_issuers: generic ASM creation remains enabled",
      "dse_caa_no_issuers: not dual-owned by Website Security",
      "dse_hsts_not_preload_eligible: Attack Surface ownership preserved",
      "dse_hsts_not_preload_eligible: generic ASM creation remains enabled",
      "dse_hsts_not_preload_eligible: not dual-owned by Website Security",
      "dse_hsts_short_maxage: Attack Surface ownership preserved",
      "dse_hsts_short_maxage: generic ASM creation remains enabled",
      "dse_hsts_short_maxage: not dual-owned by Website Security",
      "dse_missing_caa: Attack Surface ownership preserved",
      "dse_missing_caa: generic ASM creation remains enabled",
      "dse_missing_caa: not dual-owned by Website Security",
    ],
  },
  {
    id: "dual-ownership",
    file: "workers/scan-api/src/engines/cyber-mot-domains.js",
    anchor: `match: (f) => !isCookieFindingType(f?.id)\n      && /^(asset_|subdomain_|admin_|takeover_|exposure_|dse_|cve_|kev_|cloud_|dns_)/.test(f?.id || ""),`,
    replacement: `match: (f) => /^(asset_|subdomain_|admin_|takeover_|exposure_|dse_|cve_|kev_|cloud_|dns_)/.test(f?.id || ""),`,
    expectedFailures: [
      "cookie is absent from Attack Surface count",
      "cookie is counted exactly once across all eight domains",
      "dse_cookie_no_httponly: Attack Surface no longer owns",
      "dse_cookie_no_samesite: Attack Surface no longer owns",
      "dse_cookie_no_secure: Attack Surface no longer owns",
    ],
  },
  {
    id: "zero-cookies-false-resolution",
    file: "workers/scan-api/src/engines/cookie-observation.js",
    anchor: "if (enrich.cookies.found === 0) {",
    replacement: "if (enrich.cookies.found < 0) {",
    expectedFailures: [
      "dse_cookie_no_httponly: found===0 is deferred",
      "dse_cookie_no_httponly: found===0 reason is exact",
      "dse_cookie_no_samesite: found===0 is deferred",
      "dse_cookie_no_samesite: found===0 reason is exact",
      "dse_cookie_no_secure: found===0 is deferred",
      "dse_cookie_no_secure: found===0 reason is exact",
      "found===0 writes no condition_resolved event",
      "historical full-scan cookie case remains awaiting verification",
      "historical full-scan cookie verification defers zero cookies",
      "historical full-scan deferral keeps no_cookies_observed reason",
      "no-cookies: case state",
      "no-cookies: condition state",
      "no-cookies: unknown reason",
    ],
  },
  {
    id: "cookies-usable-only-gate",
    file: "workers/scan-api/src/engines/cookie-observation.js",
    anchor: "const present = enrich.cookies[COOKIE_COUNTER[id]] > 0;",
    replacement: "const present = true;",
    expectedFailures: [
      "dse_cookie_no_httponly: found>0 compliant is clear",
      "dse_cookie_no_samesite: found>0 compliant is clear",
      "dse_cookie_no_secure: found>0 compliant is clear",
    ],
  },
  {
    id: "duplicate-case-creation",
    file: "workers/scan-api/src/engines/website-security-cases.js",
    anchor: "if (historicalAsm) {",
    replacement: "if (false && historicalAsm) {",
    expectedFailures: [
      "Website condition presents the historical case link",
      "historical ASM cookie case suppresses a Website duplicate",
    ],
  },
  {
    id: "wrong-alert-domain",
    file: "workers/scan-api/src/engines/website-security-lifecycle.js",
    anchor: "domain_key: WEBSITE_SECURITY_DOMAIN_KEY",
    replacement: 'domain_key: "attack_surface"',
    replaceAll: true,
    expectedAnchorCount: 2,
    expectedFailures: [
      "both Website lifecycle alert calls use the canonical Website domain constant",
      "new cookie alert is Website Security",
    ],
  },
  {
    id: "historical-case-rewrite",
    file: "workers/scan-api/src/engines/website-security-cases.js",
    anchor: `if (historicalAsm) {\n      await linkConditionToCase(env, workspace_id, record_id, historicalAsm.id);`,
    replacement: `if (historicalAsm) {\n      await env.cybermeters_db.prepare("UPDATE managed_cases SET domain_key = 'website_security' WHERE id = ? AND workspace_id = ?").bind(historicalAsm.id, workspace_id).run();\n      await linkConditionToCase(env, workspace_id, record_id, historicalAsm.id);`,
    expectedFailures: ["historical ASM case row remains byte-equivalent"],
  },
  {
    id: "comparable-historical-transition",
    file: "workers/scan-api/src/engines/cyber-mot-domains.js",
    anchor: 'export const CYBER_MOT_RESOLVER_VERSION = "2026-08-09.2";',
    replacement: 'export const CYBER_MOT_RESOLVER_VERSION = "2026-07-24.4";',
    expectedFailures: [
      "historical/new ownership boundary is not_comparable",
      "resolver version is mechanically bumped from 2026-07-24.4",
    ],
  },
  {
    id: "second-cookie-verifier",
    file: "workers/scan-api/src/engines/managed-verification.js",
    anchor: "const cookie = evaluateCookieObservation(findingId, enrich, { moduleComplete: true });",
    replacement: 'const cookie = { state: enrich.cookies?.found > 0 && enrich.cookies?.insecure_count > 0 ? "present" : "clear", reason: "duplicate_verifier" };',
    expectedFailures: ["canonical cookie counters are defined only in the shared contract"],
  },
]);

let pass = 0;
let fail = 0;
const ok = (name, condition, detail = "") => {
  if (condition) {
    pass += 1;
    console.log(`PASS ${name}`);
  } else {
    fail += 1;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
};

const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const countOccurrences = (source, anchor) => source.split(anchor).length - 1;
const candidateFingerprints = new Map(
  [...new Set(MUTATIONS.map((mutation) => mutation.file))].map((relative) => [
    relative,
    sha(fs.readFileSync(path.join(root, relative))),
  ]),
);

function makeSandbox(mutation) {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), `rws5-${mutation.id}-`));
  for (const relative of ["database", "shared", "workers/scan-api/src"]) {
    fs.cpSync(path.join(root, relative), path.join(sandbox, relative), { recursive: true });
  }
  fs.mkdirSync(path.join(sandbox, "scripts"), { recursive: true });
  fs.copyFileSync(path.join(root, validatorRelative), path.join(sandbox, validatorRelative));
  const installed = fs.realpathSync(path.join(root, "workers/scan-api/node_modules"));
  fs.symlinkSync(installed, path.join(sandbox, "workers/scan-api/node_modules"));
  return sandbox;
}

function mutate(sandbox, mutation) {
  const target = path.join(sandbox, mutation.file);
  const original = fs.readFileSync(target, "utf8");
  const count = countOccurrences(original, mutation.anchor);
  const expectedCount = mutation.expectedAnchorCount ?? 1;
  if (count !== expectedCount) throw new Error(`anchor count ${count}, expected ${expectedCount}`);
  const changed = mutation.replaceAll
    ? original.split(mutation.anchor).join(mutation.replacement)
    : original.replace(mutation.anchor, mutation.replacement);
  if (changed === original) throw new Error("replacement made no change");
  fs.writeFileSync(target, changed);
  return { target, digest: sha(fs.readFileSync(target)) };
}

function failuresFrom(output) {
  return [...output.matchAll(/^FAIL ([^\n—]+?)(?: —.*)?$/gm)]
    .map((match) => match[1].trim())
    .sort();
}

ok("mutation registry is exact, ordered and unique",
  MUTATIONS.length === 9 && new Set(MUTATIONS.map((mutation) => mutation.id)).size === MUTATIONS.length);

for (const mutation of MUTATIONS) {
  let sandbox = null;
  try {
    sandbox = makeSandbox(mutation);
    const mutated = mutate(sandbox, mutation);
    ok(`${mutation.id}: exact anchor/replacement preflight`, true);

    const child = spawnSync(process.execPath, [path.join(sandbox, validatorRelative)], {
      cwd: sandbox,
      encoding: "utf8",
      env: {
        ...process.env,
        RWS5_EXPECT_MUTATED_FILE: mutation.file,
        RWS5_EXPECT_MUTATED_SHA256: mutated.digest,
      },
      maxBuffer: 16 * 1024 * 1024,
    });
    const output = `${child.stdout || ""}${child.stderr || ""}`;
    const completedSemantically = child.status === 1
      && !child.signal
      && /RWS\.5 cookie ownership: \d+\/\d+ passed/.test(output)
      && /RWS\.5 cookie ownership validation FAILED/.test(output)
      && !/(?:SyntaxError|TypeError|ReferenceError|ERR_MODULE_NOT_FOUND|mutation setup mismatch)/.test(output);
    ok(`${mutation.id}: semantic child completed without invalid kill`, completedSemantically,
      completedSemantically ? "" : output.slice(-1200));

    const expectedUrl = `LOADED_MUTATED_MODULE_URL=${pathToFileURL(fs.realpathSync(mutated.target)).href}`;
    const expectedSha = `LOADED_MUTATED_MODULE_SHA256=${mutated.digest}`;
    ok(`${mutation.id}: exact loaded-module URL and SHA proof`,
      output.includes(expectedUrl) && output.includes(expectedSha));

    const actualFailures = failuresFrom(output);
    if (discover) {
      console.log(`DISCOVER ${mutation.id} ${JSON.stringify(actualFailures)}`);
      ok(`${mutation.id}: discover produced a semantic failure set`, actualFailures.length > 0);
    } else {
      ok(`${mutation.id}: exact expected failure set`,
        JSON.stringify(actualFailures) === JSON.stringify([...mutation.expectedFailures].sort()),
        `got ${JSON.stringify(actualFailures)} want ${JSON.stringify([...mutation.expectedFailures].sort())}`);
    }
  } catch (error) {
    ok(`${mutation.id}: mutation setup`, false, error?.stack || error?.message);
  } finally {
    if (sandbox && sandbox.startsWith(os.tmpdir() + path.sep) && path.basename(sandbox).startsWith("rws5-")) {
      fs.rmSync(sandbox, { recursive: true, force: true });
    }
  }
}

for (const [relative, before] of candidateFingerprints) {
  ok(`${relative}: candidate source fingerprint preserved`, sha(fs.readFileSync(path.join(root, relative))) === before);
}

console.log(`\nRWS.5 cookie ownership mutations: ${pass}/${pass + fail} assertions passed; ${MUTATIONS.length} registry-derived mutants`);
if (fail > 0) {
  console.error("RWS.5 cookie ownership mutation validation FAILED");
  process.exit(1);
}
console.log("RWS.5 cookie ownership mutation validation passed");
