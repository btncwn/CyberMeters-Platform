#!/usr/bin/env node
//
// The release stamp both Workers report at /health as APP_VERSION.
//
// It is computed at deploy time from the checked-out commit, never committed:
// a committed stamp made every pair of parallel PRs conflict after the first
// merged. Format:
//
//   YYYY.MM.DD-<commit 12 hex>.<email closure 12 hex>
//
// The date is the commit's committer date, the middle names the commit, and
// the suffix is the first 12 hex of the SHA-256 over the email Worker's
// effective relative-import closure (it bundles shared scan-api modules, so a
// scan-api change can change the routed email Worker without touching
// workers/email-ingest/). The closure is read from the commit's blobs, so two
// checkouts of the same commit always give the same stamp.
//
//   node scripts/lib/release-stamp.mjs                       # JSON for HEAD
//   node scripts/lib/release-stamp.mjs --field app_version   # the stamp only
//   node scripts/lib/release-stamp.mjs --manifest-out <file> # also write the deploy manifest
//
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const EMAIL_ENTRY = "workers/email-ingest/src/index.js";
export const MANIFEST_SCHEMA = "cybermeters.email-worker-deploy-manifest/v2";
const STAMP = /^(\d{4})\.(\d{2})\.(\d{2})-([0-9a-f]{12})\.([0-9a-f]{12})$/;

export function relativeImports(source) {
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

function resolveImport(read, importerRelative, specifier) {
  let resolved = path.posix.normalize(path.posix.join(path.posix.dirname(importerRelative), specifier));
  if (!path.posix.extname(resolved)) resolved += ".js";
  if (resolved.startsWith("../") || path.posix.isAbsolute(resolved)) {
    throw new Error(`import escapes repository: ${importerRelative} -> ${specifier}`);
  }
  if (read(resolved) == null) throw new Error(`unresolved relative import: ${importerRelative} -> ${specifier}`);
  return resolved;
}

/** Files are read through `read(relative) → Buffer | null`, so a closure can be
 *  measured from the working tree or from any commit's blobs. */
export function workingTreeReader(root) {
  return (relative) => {
    const absolute = path.join(root, ...relative.split("/"));
    return fs.existsSync(absolute) && fs.statSync(absolute).isFile() ? fs.readFileSync(absolute) : null;
  };
}

// Where the email closure lives today; read in one `git cat-file --batch` call.
// A file outside these trees still resolves, one `git show` at a time.
const CLOSURE_TREES = ["workers/email-ingest/src", "workers/scan-api/src", "shared"];

export function commitReader(root, commit) {
  const blobs = new Map();
  const listing = execFileSync("git", ["ls-tree", "-r", commit, "--", ...CLOSURE_TREES], { cwd: root, encoding: "utf8", maxBuffer: 64 << 20 });
  const entries = listing.split("\n").filter(Boolean).map((line) => {
    const [meta, name] = line.split("\t");
    const [, type, oid] = meta.split(" ");
    return type === "blob" ? { name, oid } : null;
  }).filter(Boolean);
  if (entries.length) {
    const out = execFileSync("git", ["cat-file", "--batch"], { cwd: root, input: entries.map((e) => e.oid).join("\n") + "\n", maxBuffer: 256 << 20 });
    let at = 0;
    for (const { name } of entries) {
      const newline = out.indexOf(0x0a, at);
      const size = Number(out.subarray(at, newline).toString("utf8").split(" ")[2]);
      blobs.set(name, out.subarray(newline + 1, newline + 1 + size));
      at = newline + 1 + size + 1;
    }
  }
  return (relative) => {
    if (blobs.has(relative)) return blobs.get(relative);
    if (CLOSURE_TREES.some((tree) => relative.startsWith(`${tree}/`))) return null;
    try {
      return execFileSync("git", ["show", `${commit}:${relative}`], { cwd: root, stdio: ["ignore", "pipe", "ignore"] });
    } catch { return null; }
  };
}

export function emailClosure(read, entry = EMAIL_ENTRY) {
  const pending = [entry];
  const visited = new Map();
  while (pending.length) {
    const relative = pending.pop();
    if (visited.has(relative)) continue;
    const bytes = read(relative);
    if (bytes == null) throw new Error(`closure file missing: ${relative}`);
    visited.set(relative, bytes);
    for (const specifier of relativeImports(bytes.toString("utf8"))) pending.push(resolveImport(read, relative, specifier));
  }
  const files = [...visited.keys()].sort();
  const hash = crypto.createHash("sha256");
  for (const relative of files) {
    hash.update(relative); hash.update("\0");
    hash.update(visited.get(relative)); hash.update("\0");
  }
  return {
    entrypoint: entry,
    closure_sha256: hash.digest("hex"),
    closure_file_count: files.length,
    scan_api_file_count: files.filter((f) => f.startsWith("workers/scan-api/")).length,
    files,
  };
}

export function releaseStamp({ commit, commitDate, closureSha256 }) {
  if (!/^[0-9a-f]{40}$/.test(String(commit))) throw new Error("release stamp needs a full commit SHA");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(commitDate))) throw new Error("release stamp needs the commit date as YYYY-MM-DD");
  if (!/^[0-9a-f]{64}$/.test(String(closureSha256))) throw new Error("release stamp needs the closure SHA-256");
  return `${commitDate.replaceAll("-", ".")}-${commit.slice(0, 12)}.${closureSha256.slice(0, 12)}`;
}

export function parseReleaseStamp(stamp) {
  const m = STAMP.exec(String(stamp ?? ""));
  return m ? { date: `${m[1]}-${m[2]}-${m[3]}`, commit12: m[4], closure12: m[5] } : null;
}

export function commitIdentity(root, ref = "HEAD") {
  const git = (args) => execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  return { commit: git(["rev-parse", `${ref}^{commit}`]), commitDate: git(["log", "-1", "--format=%cs", ref]) };
}

/** The stamp a commit must carry when deployed, measured from its own blobs. */
export function expectedStampForCommit(root, commit) {
  const { commitDate } = commitIdentity(root, commit);
  return releaseStamp({ commit, commitDate, closureSha256: emailClosure(commitReader(root, commit)).closure_sha256 });
}

export function deployManifest({ commit, commitDate, closure }) {
  return {
    schema: MANIFEST_SCHEMA,
    app_version: releaseStamp({ commit, commitDate, closureSha256: closure.closure_sha256 }),
    commit,
    commit_date: commitDate,
    ...closure,
  };
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
  const arg = (name) => { const i = process.argv.indexOf(`--${name}`); return i > -1 ? process.argv[i + 1] : undefined; };
  // Measured from the commit's own blobs, so the stamp names the commit even if
  // the working tree differs; the deploy scripts refuse a dirty tree anyway.
  const identity = commitIdentity(root);
  const manifest = deployManifest({ ...identity, closure: emailClosure(commitReader(root, identity.commit)) });
  const out = arg("manifest-out");
  if (out) fs.writeFileSync(out, `${JSON.stringify(manifest, null, 2)}\n`);
  const field = arg("field");
  process.stdout.write(field ? `${manifest[field]}\n` : `${JSON.stringify(manifest, null, 2)}\n`);
}
