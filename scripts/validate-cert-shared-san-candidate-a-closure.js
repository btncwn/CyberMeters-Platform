#!/usr/bin/env node
// Candidate A F12 — self-relative email-Worker closure invariance.
//
// The candidate parent is derived from git state, never from a frozen digest:
//   * uncommitted candidate: HEAD is the parent;
//   * committed candidate: the parent of the projector's introduction commit.
// The effective email import graph, content digest, and both Worker APP_VERSIONs
// must be byte-identical. Candidate A is blocked for redesign on any drift.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const entry = "workers/email-ingest/src/index.js";
const projector = "workers/scan-api/src/routes/certificate-shared-san-projection.js";

function git(args, options = {}) {
  return execFileSync("git", args, {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    ...options,
  }).trim();
}

function gitFile(commit, relative) {
  try {
    return execFileSync("git", ["show", `${commit}:${relative}`], {
      cwd: root,
      encoding: null,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch {
    return null;
  }
}

function currentFile(relative) {
  const absolute = path.join(root, ...relative.split("/"));
  return fs.existsSync(absolute) ? fs.readFileSync(absolute) : null;
}

function parentCommit() {
  if (process.env.CERT_SHARED_SAN_CANDIDATE_PARENT) {
    return git(["rev-parse", process.env.CERT_SHARED_SAN_CANDIDATE_PARENT]);
  }
  const head = git(["rev-parse", "HEAD"]);
  const workingProjector = currentFile(projector)?.toString("utf8") || "";
  const headProjector = gitFile(head, projector)?.toString("utf8") || "";
  const marker = "legacy_ambiguous_zero";
  if (workingProjector.includes(marker) && !headProjector.includes(marker)) return head;
  if (headProjector.includes(marker)) {
    const introduction = git([
      "log", "-1", "--format=%H", "--diff-filter=A", "--", projector,
    ]);
    if (!introduction) throw new Error("projector introduction commit missing");
    return git(["rev-parse", `${introduction}^`]);
  }
  return head;
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
    const match = statement.match(/(?:\bfrom\s+|^\s*import\s+)["']([^"']+)["']/m);
    if (match?.[1]?.startsWith(".")) imports.push(match[1]);
  }
  for (const match of source.matchAll(/\bimport\s*\(\s*["']([^"']+)["']\s*\)/g)) {
    if (match[1].startsWith(".")) imports.push(match[1]);
  }
  return [...new Set(imports)];
}

function resolveImport(importer, specifier, read) {
  let resolved = path.posix.normalize(path.posix.join(path.posix.dirname(importer), specifier));
  if (!path.posix.extname(resolved)) resolved += ".js";
  if (resolved.startsWith("../") || resolved.startsWith("/")) {
    throw new Error(`import escapes repository: ${importer} -> ${specifier}`);
  }
  if (read(resolved) == null) {
    throw new Error(`unresolved relative import: ${importer} -> ${specifier}`);
  }
  return resolved;
}

function measure(read) {
  const pending = [entry];
  const visited = new Set();
  while (pending.length) {
    const relative = pending.pop();
    if (visited.has(relative)) continue;
    const bytes = read(relative);
    if (bytes == null) throw new Error(`missing closure file: ${relative}`);
    visited.add(relative);
    for (const specifier of relativeImports(bytes.toString("utf8"))) {
      pending.push(resolveImport(relative, specifier, read));
    }
  }
  const files = [...visited].sort();
  const hash = crypto.createHash("sha256");
  for (const relative of files) {
    hash.update(relative);
    hash.update("\0");
    hash.update(read(relative));
    hash.update("\0");
  }
  return {
    files,
    closure_file_count: files.length,
    scan_api_file_count: files.filter((file) => file.startsWith("workers/scan-api/")).length,
    closure_sha256: hash.digest("hex"),
  };
}

function appVersion(bytes, label) {
  const match = bytes?.toString("utf8").match(/^APP_VERSION\s*=\s*"([^"]+)"\s*$/m);
  if (!match) throw new Error(`${label} APP_VERSION missing`);
  return match[1];
}

let failed = false;
try {
  const parent = parentCommit();
  const parentRead = (relative) => gitFile(parent, relative);
  const currentRead = (relative) => currentFile(relative);
  const pre = measure(parentRead);
  const post = measure(currentRead);
  const preApps = {
    scan_api: appVersion(parentRead("workers/scan-api/wrangler.toml"), "scan-api parent"),
    email_ingest: appVersion(parentRead("workers/email-ingest/wrangler.toml"), "email parent"),
  };
  const postApps = {
    scan_api: appVersion(currentRead("workers/scan-api/wrangler.toml"), "scan-api current"),
    email_ingest: appVersion(currentRead("workers/email-ingest/wrangler.toml"), "email current"),
  };
  const equal = JSON.stringify(pre) === JSON.stringify(post) &&
    JSON.stringify(preApps) === JSON.stringify(postApps);
  const evidence = { parent, pre: { ...pre, app_versions: preApps }, post: { ...post, app_versions: postApps } };
  if (process.argv.includes("--print")) {
    process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
  }
  if (!equal) {
    failed = true;
    console.error("FAIL SAN_A_F12 — Candidate-A-caused email closure or APP_VERSION drift; BLOCKED_FOR_REDESIGN");
    console.error(JSON.stringify(evidence, null, 2));
  } else {
    console.log("PASS SAN_A_F12 — parent/current closure list, counts, digest and APP_VERSIONs are byte-identical");
  }
} catch (error) {
  failed = true;
  console.error(`FAIL SAN_A_F12 — ${error?.message || error}`);
}

console.log(`Candidate A closure invariance: ${failed ? 0 : 1}/1 passed`);
if (failed) process.exit(1);
