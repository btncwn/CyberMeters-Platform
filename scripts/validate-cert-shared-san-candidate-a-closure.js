#!/usr/bin/env node
// Candidate A F12 — email-Worker closure invariance, in two modes.
//
// Uncommitted candidate (projector not in HEAD): the parent is derived from git
// state, never from a frozen digest, and the effective email import graph,
// content digest, and both Worker APP_VERSIONs must be byte-identical to it.
//
// Committed (durable) mode: the working-tree-vs-introduction-parent comparison
// would permanently pin the closure to Candidate A's parent and block every
// later legitimate, manifest-coordinated closure release. Instead this mode
// asserts Candidate A's actual invariants: the introduction commit itself moved
// nothing (historical, from git blobs), the projector and routes/scans.js stay
// OUT of the derived closure (constraint C1), and the current tree passes the
// canonical deploy-traceability governance (digest vs manifest/APP_VERSION).
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
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

// Durable post-merge semantics. While the projector is an uncommitted candidate,
// the original PRE/POST parent comparison applies verbatim. Once the projector is
// committed, comparing the working tree against the introduction parent forever
// would block every later legitimate, manifest-coordinated closure release — so
// the committed mode asserts exactly Candidate A's own three invariants instead:
//   (1) HISTORICAL — the projector's introduction commit changed neither the
//       closure (list, counts, digest) nor either APP_VERSION, measured from
//       immutable git blobs, so "Candidate A caused no drift" stays executable;
//   (2) PLACEMENT — the projector and routes/scans.js are OUT of the closure
//       derived from the current tree (constraint C1; catches any relocation);
//   (3) GOVERNANCE — the current tree passes the canonical email-worker deploy
//       traceability validator, so any un-coordinated closure byte change
//       (digest vs manifest/APP_VERSION) still fails here.
let failed = false;
try {
  const head = git(["rev-parse", "HEAD"]);
  const currentRead = (relative) => currentFile(relative);
  const marker = "legacy_ambiguous_zero";
  const projectorCommitted =
    (gitFile(head, projector)?.toString("utf8") || "").includes(marker);

  if (!projectorCommitted) {
    const parent = parentCommit();
    const parentRead = (relative) => gitFile(parent, relative);
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
    const evidence = { mode: "uncommitted_candidate", parent, pre: { ...pre, app_versions: preApps }, post: { ...post, app_versions: postApps } };
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
  } else {
    const introduction = git(["log", "-1", "--format=%H", "--diff-filter=A", "--", projector]);
    if (!introduction) throw new Error("projector introduction commit missing");
    const introductionParent = git(["rev-parse", `${introduction}^`]);
    const introRead = (relative) => gitFile(introduction, relative);
    const introParentRead = (relative) => gitFile(introductionParent, relative);
    const intro = measure(introRead);
    const introParent = measure(introParentRead);
    const introApps = {
      scan_api: appVersion(introRead("workers/scan-api/wrangler.toml"), "scan-api introduction"),
      email_ingest: appVersion(introRead("workers/email-ingest/wrangler.toml"), "email introduction"),
    };
    const introParentApps = {
      scan_api: appVersion(introParentRead("workers/scan-api/wrangler.toml"), "scan-api introduction parent"),
      email_ingest: appVersion(introParentRead("workers/email-ingest/wrangler.toml"), "email introduction parent"),
    };
    const historical = JSON.stringify(intro) === JSON.stringify(introParent) &&
      JSON.stringify(introApps) === JSON.stringify(introParentApps);

    const current = measure(currentRead);
    const placement = !current.files.includes(projector) &&
      !current.files.includes("workers/scan-api/src/routes/scans.js");

    const trace = spawnSync(process.execPath, [
      path.join(root, "scripts", "validate-email-worker-deploy-traceability.js"),
    ], { cwd: root, encoding: "utf8", timeout: 120_000 });
    const governed = trace.status === 0 && trace.error == null && trace.signal == null;

    const evidence = {
      mode: "committed_durable",
      introduction,
      introduction_parent: introductionParent,
      historical_invariant: historical,
      introduction_closure: { ...intro, app_versions: introApps },
      introduction_parent_closure: { ...introParent, app_versions: introParentApps },
      current_closure: current,
      placement_clean: placement,
      deploy_traceability_exit: trace.status,
    };
    if (process.argv.includes("--print")) {
      process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
    }
    if (!historical || !placement || !governed) {
      failed = true;
      console.error("FAIL SAN_A_F12 — Candidate-A closure invariant violated " +
        `(historical=${historical}, placement=${placement}, deploy-traceability=${governed})`);
      console.error(JSON.stringify(evidence, null, 2));
    } else {
      console.log("PASS SAN_A_F12 — introduction caused no closure/APP_VERSION drift; projector and scans.js remain outside the governed closure");
    }
  }
} catch (error) {
  failed = true;
  console.error(`FAIL SAN_A_F12 — ${error?.message || error}`);
}

console.log(`Candidate A closure invariance: ${failed ? 0 : 1}/1 passed`);
if (failed) process.exit(1);
