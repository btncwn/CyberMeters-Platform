#!/usr/bin/env node
//
// PR-5.5 Gate 3A — standalone email Worker deployment traceability.
//
// The email Worker bundles shared scan-api modules. A scan-api change can
// therefore change the routed cybermeters-email Worker even when no file below
// workers/email-ingest/ changed. This validator recursively fingerprints the
// entry point's effective relative-import closure and requires:
//   • a committed manifest matching that exact closure;
//   • an APP_VERSION suffix derived from the closure hash;
//   • the exact lockfile-pinned Wrangler binary for email deploy/dry-run; and
//   • CI coverage for the trace validator and standalone Worker dry-run.
//
// A shared-source change cannot pass CI until the email deployment stamp is
// deliberately updated. Deployment itself remains founder-gated.
//
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const entryRelative = "workers/email-ingest/src/index.js";
const manifestRelative = "workers/email-ingest/deploy-manifest.json";

function repoPath(relative) {
  return path.join(root, ...relative.split("/"));
}

function relativeImports(source) {
  const imports = [];
  const lines = source.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const trimmed = lines[index].trimStart();
    if (!trimmed.startsWith("import ") && !trimmed.startsWith("export ")) continue;
    let statement = lines[index];
    while (!statement.includes(";") && index + 1 < lines.length) {
      index += 1;
      statement += `\n${lines[index]}`;
    }
    const match = statement.match(
      /(?:\bfrom\s+|^\s*import\s+)["']([^"']+)["']/m,
    );
    if (match?.[1]?.startsWith(".")) imports.push(match[1]);
  }

  for (const match of source.matchAll(/\bimport\s*\(\s*["']([^"']+)["']\s*\)/g)) {
    if (match[1].startsWith(".")) imports.push(match[1]);
  }
  return [...new Set(imports)];
}

function resolveImport(importerRelative, specifier) {
  const importerDirectory = path.dirname(repoPath(importerRelative));
  let resolved = path.resolve(importerDirectory, specifier);
  if (!path.extname(resolved)) resolved += ".js";
  const relative = path.relative(root, resolved).split(path.sep).join("/");
  if (relative.startsWith("../") || path.isAbsolute(relative)) {
    throw new Error(`import escapes repository: ${importerRelative} -> ${specifier}`);
  }
  if (!fs.existsSync(resolved) || !fs.statSync(resolved).isFile()) {
    throw new Error(`unresolved relative import: ${importerRelative} -> ${specifier}`);
  }
  return relative;
}

function collectClosure(entry) {
  const pending = [entry];
  const visited = new Set();
  while (pending.length) {
    const relative = pending.pop();
    if (visited.has(relative)) continue;
    visited.add(relative);
    const source = fs.readFileSync(repoPath(relative), "utf8");
    for (const specifier of relativeImports(source)) {
      pending.push(resolveImport(relative, specifier));
    }
  }
  return [...visited].sort();
}

function closureDigest(files) {
  const hash = crypto.createHash("sha256");
  for (const relative of files) {
    hash.update(relative);
    hash.update("\0");
    hash.update(fs.readFileSync(repoPath(relative)));
    hash.update("\0");
  }
  return hash.digest("hex");
}

function readJson(relative) {
  return JSON.parse(fs.readFileSync(repoPath(relative), "utf8"));
}

function readEmailAppVersion() {
  const config = fs.readFileSync(repoPath("workers/email-ingest/wrangler.toml"), "utf8");
  const match = config.match(/^APP_VERSION\s*=\s*"([^"]+)"\s*$/m);
  if (!match) throw new Error("email APP_VERSION is missing");
  return match[1];
}

const closure = collectClosure(entryRelative);
const digest = closureDigest(closure);
const scanApiFiles = closure.filter((relative) =>
  relative.startsWith("workers/scan-api/"));
const computed = {
  schema: "cybermeters.email-worker-deploy-manifest/v1",
  entrypoint: entryRelative,
  app_version: readEmailAppVersion(),
  closure_sha256: digest,
  closure_file_count: closure.length,
  scan_api_file_count: scanApiFiles.length,
  files: closure,
  deployment_required: true,
  deployment_status: "pending_founder_approval",
};

if (process.argv.includes("--print")) {
  process.stdout.write(`${JSON.stringify(computed, null, 2)}\n`);
  process.exit(0);
}

let pass = 0;
let fail = 0;
function ok(name, condition) {
  if (condition) pass += 1;
  else {
    fail += 1;
    console.error(`FAIL ${name}`);
  }
}

const manifest = readJson(manifestRelative);
ok("manifest schema and entrypoint are canonical",
  manifest.schema === computed.schema &&
  manifest.entrypoint === computed.entrypoint);
ok("effective relative-import closure file list is pinned",
  JSON.stringify(manifest.files) === JSON.stringify(computed.files) &&
  manifest.closure_file_count === computed.closure_file_count &&
  manifest.scan_api_file_count === computed.scan_api_file_count);
ok("effective relative-import closure content hash is pinned",
  manifest.closure_sha256 === computed.closure_sha256);
ok("email APP_VERSION matches the manifest",
  manifest.app_version === computed.app_version);
ok("email APP_VERSION is closure-derived",
  computed.app_version.endsWith(`.${computed.closure_sha256.slice(0, 12)}`));
ok("manifest records the founder-gated email deployment requirement",
  manifest.deployment_required === true &&
  manifest.deployment_status === "pending_founder_approval");

const scanPackage = readJson("workers/scan-api/package.json");
const scanLock = readJson("workers/scan-api/package-lock.json");
const emailPackage = readJson("workers/email-ingest/package.json");
const pinnedWrangler = scanPackage.devDependencies?.wrangler;
ok("Wrangler dependency is exact, not a range",
  typeof pinnedWrangler === "string" &&
  /^\d+\.\d+\.\d+$/.test(pinnedWrangler));
ok("Wrangler package and lockfile pins agree",
  scanLock.packages?.[""]?.devDependencies?.wrangler === pinnedWrangler &&
  scanLock.packages?.["node_modules/wrangler"]?.version === pinnedWrangler);
ok("email deploy and dry-run use only the pinned local Wrangler binary",
  emailPackage.scripts?.deploy ===
    "../scan-api/node_modules/.bin/wrangler deploy --config wrangler.toml" &&
  emailPackage.scripts?.["dry-run"] ===
    "../scan-api/node_modules/.bin/wrangler deploy --dry-run --config wrangler.toml" &&
  !JSON.stringify(emailPackage.scripts).includes("npx"));

const apiEntry = fs.readFileSync(repoPath("workers/scan-api/src/index.js"), "utf8");
const emailEntry = fs.readFileSync(repoPath(entryRelative), "utf8");
ok("both Worker entries import the same canonical limiter module",
  /from "\.\/lib\/rate-limit\.js"/.test(apiEntry) &&
  /from "\.\.\/\.\.\/scan-api\/src\/lib\/rate-limit\.js"/.test(emailEntry));
ok("standalone email entry injects both mandatory limiter functions",
  /handleInboundEmail\(message, env, ctx, \{ consumeApiRateLimit, rateLimitScopeId \}\)/.test(
    emailEntry,
  ));

const workflow = fs.readFileSync(repoPath(".github/workflows/ci.yml"), "utf8");
ok("CI validates deployment traceability",
  workflow.includes("node scripts/validate-email-worker-deploy-traceability.js"));
ok("CI runs the standalone email Worker dry-run",
  /working-directory: workers\/email-ingest[\s\S]{0,120}run: npm run dry-run/.test(workflow));

console.log(`\nEmail-worker deploy traceability: ${pass}/${pass + fail} passed`);
if (fail) {
  console.error("email-worker deploy traceability validation FAILED");
  console.error("Expected current closure manifest:");
  console.error(JSON.stringify(computed, null, 2));
  process.exit(1);
}
console.log("email-worker deploy traceability validation passed");
