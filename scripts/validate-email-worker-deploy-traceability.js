#!/usr/bin/env node
//
// PR-5.5 Gate 3A — standalone email Worker deployment traceability.
//
// The email Worker bundles shared scan-api modules. A scan-api change can
// therefore change the routed cybermeters-email Worker even when no file below
// workers/email-ingest/ changed. Both Workers report a release stamp at /health
// (APP_VERSION = YYYY.MM.DD-<commit 12>.<email closure 12>). The stamp is a
// deploy-time value (scripts/lib/release-stamp.mjs), never committed — a
// committed stamp made every pair of parallel PRs conflict. This validator
// requires:
//   • the stamp names the commit and the SHA-256 of the email Worker's effective
//     relative-import closure measured from that commit's own blobs, and moves
//     when any closure byte moves;
//   • no committed APP_VERSION or closure manifest that could go stale;
//   • both deploy scripts pass exactly that stamp via --var (the email one also
//     generates the closure manifest just before deploying) and refuse a dirty
//     tree, so the deployed stamp is true of the commit;
//   • the exact lockfile-pinned Wrangler binary for email deploy/dry-run; and
//   • CI coverage for the trace validator and standalone Worker dry-run.
// scripts/check-live-versions.mjs compares the live stamp with the live commit.
//
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const stampModule = path.join(root, "scripts", "lib", "release-stamp.mjs");
const {
  EMAIL_ENTRY, MANIFEST_SCHEMA, emailClosure, workingTreeReader, commitReader,
  commitIdentity, releaseStamp, parseReleaseStamp, deployManifest, expectedStampForCommit,
} = await import(pathToFileURL(stampModule).href);
const entryRelative = EMAIL_ENTRY;
const manifestRelative = "workers/email-ingest/deploy-manifest.json";

function repoPath(relative) {
  return path.join(root, ...relative.split("/"));
}

function readJson(relative) {
  return JSON.parse(fs.readFileSync(repoPath(relative), "utf8"));
}

const git = (args) => execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
const identity = commitIdentity(root);
const workingClosure = emailClosure(workingTreeReader(root));
// --print keeps its shape for the validators that read the closure from it.
const computed = deployManifest({ ...identity, closure: workingClosure });

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
const throws = (fn) => { try { fn(); return false; } catch { return true; } };

// ── 1. The stamp names the commit and its closure ───────────────────────────
const headClosure = emailClosure(commitReader(root, identity.commit));
const closureDirty = git(["status", "--porcelain", "--", ...new Set(workingClosure.files.map((f) => f.split("/").slice(0, -1).join("/")))]) !== "";
ok("closure measured from the commit's blobs equals the checked-out closure (clean tree)",
  closureDirty || JSON.stringify(headClosure) === JSON.stringify(workingClosure));
ok("closure is the email entry plus shared scan-api modules",
  workingClosure.files.includes(entryRelative) && workingClosure.scan_api_file_count > 0 &&
  workingClosure.closure_file_count === workingClosure.files.length);
const stamp = expectedStampForCommit(root, identity.commit);
const parsed = parseReleaseStamp(stamp);
ok("stamp is <commit date>-<commit 12>.<closure 12> and parses back",
  parsed !== null && parsed.date === identity.commitDate &&
  parsed.commit12 === identity.commit.slice(0, 12) &&
  parsed.closure12 === headClosure.closure_sha256.slice(0, 12));
ok("stamp suffix is the closure digest, not a Git identity",
  parsed !== null && parsed.closure12 !== parsed.commit12);
{
  const read = workingTreeReader(root);
  const target = workingClosure.files.find((f) => f.startsWith("workers/scan-api/"));
  const mutated = emailClosure((relative) => relative === target ? Buffer.concat([read(relative), Buffer.from(" ")]) : read(relative));
  const base = releaseStamp({ ...identity, closureSha256: workingClosure.closure_sha256 });
  const moved = releaseStamp({ ...identity, closureSha256: mutated.closure_sha256 });
  ok("one changed byte in a shared scan-api closure file changes the stamp", moved !== base && moved.slice(0, -12) === base.slice(0, -12));
}
ok("stamp refuses a short commit, a bad date or a bad closure digest",
  throws(() => releaseStamp({ commit: identity.commit.slice(0, 12), commitDate: identity.commitDate, closureSha256: headClosure.closure_sha256 })) &&
  throws(() => releaseStamp({ commit: identity.commit, commitDate: "18 Oct 2026", closureSha256: headClosure.closure_sha256 })) &&
  throws(() => releaseStamp({ commit: identity.commit, commitDate: identity.commitDate, closureSha256: "abc" })) &&
  parseReleaseStamp("2026.10.18-role-aware-scan.226f19315149") === null);
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "release-stamp-"));
  try {
    const out = path.join(dir, "deploy-manifest.json");
    const cli = spawnSync(process.execPath, [stampModule, "--field", "app_version", "--manifest-out", out], { cwd: os.tmpdir(), encoding: "utf8" });
    const manifest = fs.existsSync(out) ? JSON.parse(fs.readFileSync(out, "utf8")) : null;
    ok("deploy-time CLI prints the commit's stamp from any directory", cli.status === 0 && cli.stdout.trim() === stamp);
    ok("deploy-time manifest records schema, commit, stamp and the exact closure",
      manifest?.schema === MANIFEST_SCHEMA && manifest.commit === identity.commit &&
      manifest.app_version === stamp && manifest.closure_sha256 === headClosure.closure_sha256 &&
      JSON.stringify(manifest.files) === JSON.stringify(headClosure.files));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

// ── 2. Nothing committed can go stale ───────────────────────────────────────
const emailConfig = fs.readFileSync(repoPath("workers/email-ingest/wrangler.toml"), "utf8");
const scanConfig = fs.readFileSync(repoPath("workers/scan-api/wrangler.toml"), "utf8");
ok("neither wrangler.toml commits an APP_VERSION (set at deploy time only)",
  !/^\s*APP_VERSION\s*=/m.test(emailConfig) && !/^\s*APP_VERSION\s*=/m.test(scanConfig));
ok("the closure manifest is generated at deploy time, not committed",
  git(["ls-files", "--", manifestRelative]) === "" &&
  fs.readFileSync(repoPath(".gitignore"), "utf8").split(/\r?\n/).includes(manifestRelative));

// ── 3. The deploy scripts carry exactly that stamp ──────────────────────────
const scanDeploy = fs.readFileSync(repoPath("scripts/deploy-scan-api.sh"), "utf8");
const emailDeploy = fs.readFileSync(repoPath("scripts/deploy-email-ingest.sh"), "utf8");
ok("scan-api deploy passes the computed stamp next to the commit",
  /^stamp=\$\(node "\$root\/scripts\/lib\/release-stamp\.mjs" --field app_version\)$/m.test(scanDeploy) &&
  /wrangler deploy --var "GIT_COMMIT:\$commit" --var "APP_VERSION:\$stamp"/.test(scanDeploy));
ok("email deploy refuses uncommitted closure sources",
  /^set -eu$/m.test(emailDeploy) &&
  /status --porcelain -- workers\/email-ingest\/src workers\/email-ingest\/wrangler\.toml workers\/scan-api\/src shared\)" \]; then[\s\S]*?exit 1/.test(emailDeploy));
ok("email deploy generates the manifest just before deploying and passes the stamp",
  /^stamp=\$\(node "\$root\/scripts\/lib\/release-stamp\.mjs" --field app_version --manifest-out "\$root\/workers\/email-ingest\/deploy-manifest\.json"\)$/m.test(emailDeploy) &&
  /^exec \.\.\/scan-api\/node_modules\/\.bin\/wrangler deploy --config wrangler\.toml --var "APP_VERSION:\$stamp" --tag "\$short" --message "\$message" "\$@"$/m.test(emailDeploy));
const apiEntry = fs.readFileSync(repoPath("workers/scan-api/src/index.js"), "utf8");
const emailEntry = fs.readFileSync(repoPath(entryRelative), "utf8");
ok("both Workers report the deploy-time stamp at /health",
  /version:\s+env\.APP_VERSION \|\| "dev"/.test(apiEntry) && /version: env\.APP_VERSION \|\| "dev"/.test(emailEntry));
ok("email Worker has no public workers.dev host",
  /^workers_dev\s*=\s*false\s*$/m.test(emailConfig));

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
ok("email deploy runs the stamping script; deploy and dry-run use only the pinned local Wrangler binary",
  emailPackage.scripts?.deploy === "sh ../../scripts/deploy-email-ingest.sh" &&
  emailPackage.scripts?.["dry-run"] ===
    "../scan-api/node_modules/.bin/wrangler deploy --dry-run --config wrangler.toml" &&
  !JSON.stringify(emailPackage.scripts).includes("npx"));

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
  console.error("Current deploy-time manifest:");
  console.error(JSON.stringify(computed, null, 2));
  process.exit(1);
}
console.log("email-worker deploy traceability validation passed");
