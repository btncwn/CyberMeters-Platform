#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  LOCAL_GATE_DECISIONS,
  LOCAL_GATE_MODES,
  LOCAL_GATE_SCHEMA_VERSION,
  MAX_GATE_MS,
  classifyFocusedChanges,
  normalizeRepoPath,
} from "./local-focused-gate-policy.js";
import { classifyChange, loadManifest } from "./ci-safe-docs-only-lib.js";

const scriptRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const SHA_RE = /^[0-9a-f]{40}$/;
const SOURCE_PREFIXES = Object.freeze([
  ".github/",
  "database/",
  "frontend/src/",
  "scripts/",
  "workers/",
]);
const SOURCE_ROOT_FILES = new Set([
  ".gitignore",
  "package.json",
  "package-lock.json",
  "wrangler.toml",
  "vite.config.js",
  "vitest.config.js",
]);

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const textDecoder = new TextDecoder("utf-8", { fatal: true });

function git(repoRoot, args, { encoding = null, timeout = 30_000, allowFailure = false } = {}) {
  const child = spawnSync("git", args, {
    cwd: repoRoot,
    encoding,
    timeout,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (!allowFailure && (child.error || child.signal !== null || child.status !== 0)) {
    const stderr = Buffer.isBuffer(child.stderr)
      ? child.stderr.toString("utf8")
      : String(child.stderr || "");
    throw new Error(`git ${args[0]} failed (${child.signal || child.status || child.error?.message}): ${stderr.trim()}`);
  }
  return child;
}

function gitBuffer(repoRoot, args) {
  return git(repoRoot, args).stdout;
}

function gitText(repoRoot, args) {
  return String(git(repoRoot, args, { encoding: "utf8" }).stdout || "");
}

export function parseInputArguments(argv) {
  if (argv.length === 3 && argv[0] === "--range") {
    const baseSha = argv[1];
    const headSha = argv[2];
    if (!SHA_RE.test(baseSha || "") || !SHA_RE.test(headSha || "") || baseSha === headSha) {
      throw new Error("--range requires distinct exact lowercase 40-hex BASE_SHA and HEAD_SHA values");
    }
    return { mode: "range", baseSha, headSha, lanePathsFile: null };
  }
  if (argv.length === 1 && argv[0] === "--worktree") {
    return { mode: "worktree", baseSha: null, headSha: null, lanePathsFile: null };
  }
  if (argv.length === 3 && argv[0] === "--worktree" && argv[1] === "--lane-paths-file") {
    if (!argv[2]) throw new Error("--lane-paths-file requires a path");
    return { mode: "lane", baseSha: null, headSha: null, lanePathsFile: argv[2] };
  }
  throw new Error(
    "exactly one input mode is required: --range BASE_SHA HEAD_SHA, --worktree, or --worktree --lane-paths-file NUL_FILE",
  );
}

export function parseNameStatusBuffer(buffer) {
  let source;
  try {
    source = textDecoder.decode(buffer);
  } catch {
    throw new Error("Git name-status output is not valid UTF-8");
  }
  const fields = source.split("\0");
  if (fields.at(-1) === "") fields.pop();
  const records = [];
  for (let index = 0; index < fields.length;) {
    const status = fields[index++];
    if (!status) throw new Error("empty Git name-status field");
    const code = status[0];
    if (code === "R" || code === "C") {
      if (index + 1 >= fields.length) throw new Error(`truncated ${status} Git name-status record`);
      records.push({ status, code, old_path: fields[index++], path: fields[index++] });
    } else {
      if (index >= fields.length) throw new Error(`truncated ${status} Git name-status record`);
      records.push({ status, code, path: fields[index++] });
    }
  }
  return records;
}

export function parseLanePathsBuffer(buffer) {
  let source;
  try {
    source = textDecoder.decode(buffer);
  } catch {
    throw new Error("lane path file is not valid UTF-8");
  }
  const fields = source.split("\0");
  if (fields.at(-1) === "") fields.pop();
  if (!fields.length) throw new Error("lane path file is empty");
  const paths = [];
  const seen = new Set();
  for (const field of fields) {
    const normalized = normalizeRepoPath(field);
    if (!normalized) throw new Error(`invalid lane path ${JSON.stringify(field)}`);
    if (seen.has(normalized)) throw new Error(`duplicate lane path ${normalized}`);
    seen.add(normalized);
    paths.push(normalized);
  }
  return paths;
}

function requireNonShallow(repoRoot) {
  const shallow = gitText(repoRoot, ["rev-parse", "--is-shallow-repository"]).trim();
  if (shallow !== "false") throw new Error(`repository is shallow (${JSON.stringify(shallow)})`);
}

function commitExists(repoRoot, sha) {
  git(repoRoot, ["cat-file", "-e", `${sha}^{commit}`]);
}

function rangeIdentity(repoRoot, baseSha, headSha) {
  requireNonShallow(repoRoot);
  commitExists(repoRoot, baseSha);
  commitExists(repoRoot, headSha);
  const mergeBase = gitText(repoRoot, ["merge-base", baseSha, headSha]).trim();
  if (!SHA_RE.test(mergeBase)) throw new Error(`merge-base is malformed: ${JSON.stringify(mergeBase)}`);
  git(repoRoot, ["merge-base", "--is-ancestor", baseSha, headSha]);
  if (mergeBase !== baseSha) throw new Error(`merge-base ${mergeBase} does not equal supplied base ${baseSha}`);
  return mergeBase;
}

function rangeTreeEntry(repoRoot, headSha, relative) {
  const records = gitBuffer(repoRoot, ["ls-tree", "-z", headSha, "--", relative])
    .toString("utf8").split("\0").filter(Boolean);
  if (records.length !== 1) throw new Error(`expected one tree entry for ${relative}, got ${records.length}`);
  const match = records[0].match(/^(\d{6}) ([^ ]+) ([0-9a-f]{40})\t([\s\S]+)$/);
  if (!match || match[4] !== relative) throw new Error(`unparseable tree entry for ${relative}`);
  return { mode: match[1], type: match[2] };
}

function rangeBytes(repoRoot, headSha, relative) {
  return gitBuffer(repoRoot, ["show", `${headSha}:${relative}`]);
}

function rangeBinary(repoRoot, baseSha, headSha, relative) {
  const output = gitText(repoRoot, ["diff", "--numstat", `${baseSha}...${headSha}`, "--", relative]);
  const lines = output.split("\n").filter(Boolean);
  if (lines.length !== 1) throw new Error(`expected one numstat record for ${relative}, got ${lines.length}`);
  const fields = lines[0].split("\t");
  if (fields.length < 3) throw new Error(`unparseable numstat record for ${relative}`);
  return fields[0] === "-" || fields[1] === "-";
}

function utf8Valid(bytes) {
  try {
    textDecoder.decode(bytes);
    return true;
  } catch {
    return false;
  }
}

function enrichRangeRecord(repoRoot, baseSha, headSha, record) {
  const relative = normalizeRepoPath(record.path);
  if (!relative) return { ...record, mode: null, type: null, binary: false, valid_utf8: false };
  if (!new Set(["A", "M"]).has(record.code)) {
    return { ...record, path: relative, mode: null, type: null, binary: false, valid_utf8: true };
  }
  const entry = rangeTreeEntry(repoRoot, headSha, relative);
  const binary = rangeBinary(repoRoot, baseSha, headSha, relative);
  const bytes = rangeBytes(repoRoot, headSha, relative);
  return { ...record, path: relative, ...entry, binary, valid_utf8: binary ? true : utf8Valid(bytes) };
}

function trackedIndexEntry(repoRoot, relative) {
  const source = gitBuffer(repoRoot, ["ls-files", "-s", "-z", "--", relative]).toString("utf8");
  const records = source.split("\0").filter(Boolean);
  if (records.length !== 1) return null;
  const match = records[0].match(/^(\d{6}) ([0-9a-f]{40}) (\d)\t([\s\S]+)$/);
  if (!match || match[4] !== relative || match[3] !== "0") return null;
  return { mode: match[1], type: match[1] === "160000" ? "commit" : "blob" };
}

function worktreeFileEntry(repoRoot, relative) {
  const absolute = path.join(repoRoot, relative);
  const stat = fs.lstatSync(absolute);
  if (stat.isSymbolicLink()) return { mode: "120000", type: "blob" };
  if (!stat.isFile()) return { mode: "000000", type: "unknown" };
  return { mode: stat.mode & 0o111 ? "100755" : "100644", type: "blob" };
}

function worktreeBinary(repoRoot, relative, tracked) {
  if (tracked) {
    const output = gitText(repoRoot, ["diff", "--numstat", "HEAD", "--", relative]);
    const lines = output.split("\n").filter(Boolean);
    if (lines.length === 1) {
      const fields = lines[0].split("\t");
      if (fields.length >= 3) return fields[0] === "-" || fields[1] === "-";
    }
  }
  return fs.readFileSync(path.join(repoRoot, relative)).includes(0);
}

function enrichWorktreeRecord(repoRoot, record, untracked = false) {
  const relative = normalizeRepoPath(record.path);
  if (!relative) return { ...record, mode: null, type: null, binary: false, valid_utf8: false };
  if (!new Set(["A", "M"]).has(record.code)) {
    return { ...record, path: relative, mode: null, type: null, binary: false, valid_utf8: true };
  }
  const indexEntry = untracked ? null : trackedIndexEntry(repoRoot, relative);
  const fileEntry = worktreeFileEntry(repoRoot, relative);
  const entry = indexEntry?.mode === "160000" ? indexEntry : fileEntry;
  if (entry.type !== "blob" || !new Set(["100644", "100755"]).has(entry.mode)) {
    return { ...record, path: relative, ...entry, binary: false, valid_utf8: true };
  }
  const binary = worktreeBinary(repoRoot, relative, !untracked);
  const bytes = fs.readFileSync(path.join(repoRoot, relative));
  return { ...record, path: relative, ...entry, binary, valid_utf8: binary ? true : utf8Valid(bytes) };
}

function worktreeInventory(repoRoot) {
  const tracked = parseNameStatusBuffer(gitBuffer(repoRoot, [
    "diff", "--name-status", "-z", "--find-renames=50%", "--find-copies=50%",
    "--find-copies-harder", "HEAD", "--",
  ])).map((record) => enrichWorktreeRecord(repoRoot, record, false));

  const untrackedFields = gitBuffer(repoRoot, ["ls-files", "--others", "--exclude-standard", "-z"])
    .toString("utf8").split("\0").filter(Boolean);
  const untracked = untrackedFields.map((relative) =>
    enrichWorktreeRecord(repoRoot, { status: "A", code: "A", path: relative }, true));
  const records = [...tracked, ...untracked];
  const paths = records.map((record) => record.path);
  if (new Set(paths).size !== paths.length) throw new Error("worktree inventory contains duplicate paths");
  return records.sort((left, right) => left.path.localeCompare(right.path));
}

export function resolveGateInput(input, repoRoot) {
  if (input.mode === "range") {
    const mergeBase = rangeIdentity(repoRoot, input.baseSha, input.headSha);
    const raw = gitBuffer(repoRoot, [
      "diff", "--name-status", "-z", "--find-renames=50%", "--find-copies=50%",
      "--find-copies-harder", `${input.baseSha}...${input.headSha}`, "--",
    ]);
    const records = parseNameStatusBuffer(raw)
      .map((record) => enrichRangeRecord(repoRoot, input.baseSha, input.headSha, record))
      .sort((left, right) => left.path.localeCompare(right.path));
    return {
      mode: "range",
      records,
      omitted: [],
      scopeComplete: true,
      partialLane: false,
      baseSha: input.baseSha,
      headSha: input.headSha,
      mergeBase,
    };
  }

  const allRecords = worktreeInventory(repoRoot);
  if (input.mode === "worktree") {
    return {
      mode: "worktree",
      records: allRecords,
      omitted: [],
      scopeComplete: true,
      partialLane: false,
      baseSha: null,
      headSha: gitText(repoRoot, ["rev-parse", "HEAD"]).trim() || null,
      mergeBase: null,
    };
  }

  const laneBytes = fs.readFileSync(path.resolve(repoRoot, input.lanePathsFile));
  const lanePaths = parseLanePathsBuffer(laneBytes);
  const byPath = new Map(allRecords.map((record) => [record.path, record]));
  const missing = lanePaths.filter((relative) => !byPath.has(relative));
  if (missing.length) throw new Error(`lane path is not changed in the worktree: ${missing.join(", ")}`);
  const selected = lanePaths.map((relative) => byPath.get(relative));
  const selectedSet = new Set(lanePaths);
  return {
    mode: "lane",
    records: selected,
    omitted: allRecords.map((record) => record.path).filter((relative) => !selectedSet.has(relative)),
    scopeComplete: false,
    partialLane: true,
    baseSha: null,
    headSha: gitText(repoRoot, ["rev-parse", "HEAD"]).trim() || null,
    mergeBase: null,
  };
}

function sourcePath(relative) {
  return SOURCE_ROOT_FILES.has(relative) || SOURCE_PREFIXES.some((prefix) => relative.startsWith(prefix));
}

function inventorySourcePaths(repoRoot) {
  const tracked = gitBuffer(repoRoot, ["ls-files", "-z"]).toString("utf8").split("\0").filter(Boolean);
  const untracked = gitBuffer(repoRoot, ["ls-files", "--others", "--exclude-standard", "-z"])
    .toString("utf8").split("\0").filter(Boolean);
  return [...new Set([...tracked, ...untracked].filter(sourcePath))].sort();
}

export function wholeSourceFingerprint(repoRoot) {
  const records = [];
  for (const relative of inventorySourcePaths(repoRoot)) {
    const absolute = path.join(repoRoot, relative);
    let stat;
    try {
      stat = fs.lstatSync(absolute);
    } catch (error) {
      if (error.code === "ENOENT") {
        records.push(`${relative}\0missing`);
        continue;
      }
      throw error;
    }
    if (stat.isSymbolicLink()) {
      records.push(`${relative}\0symlink\0${sha256(fs.readlinkSync(absolute))}`);
    } else if (stat.isFile()) {
      records.push(`${relative}\0${stat.mode & 0o111 ? "100755" : "100644"}\0${sha256(fs.readFileSync(absolute))}`);
    } else {
      records.push(`${relative}\0unexpected-${stat.mode}`);
    }
  }
  return sha256(records.join("\n"));
}

function walkFiles(directory, visit) {
  const stat = fs.lstatSync(directory, { throwIfNoEntry: false });
  if (!stat?.isDirectory()) return;
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })
    .sort((left, right) => left.name.localeCompare(right.name))) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory() && !entry.isSymbolicLink()) walkFiles(absolute, visit);
    else visit(absolute, entry.name);
  }
}

function repoRelative(repoRoot, absolute) {
  return path.relative(repoRoot, absolute).split(path.sep).join("/");
}

function isInside(parent, candidate) {
  const relative = path.relative(parent, candidate);
  return relative !== "" && relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function scanTaskOwnedWorktreeMetadata(repoRoot, hits) {
  const commonDirText = gitText(repoRoot, ["rev-parse", "--git-common-dir"]).trim();
  if (!commonDirText) throw new Error("git common directory is empty");
  const commonDir = path.resolve(repoRoot, commonDirText);
  const metadataRoot = path.join(commonDir, "worktrees");
  const metadataStat = fs.lstatSync(metadataRoot, { throwIfNoEntry: false });
  if (!metadataStat?.isDirectory()) return;

  const f004Root = path.join(repoRoot, ".f004-mutation-worktrees");
  for (const entry of fs.readdirSync(metadataRoot, { withFileTypes: true })
    .sort((left, right) => left.name.localeCompare(right.name))) {
    if (!entry.isDirectory()) continue;
    const metadataPath = path.join(metadataRoot, entry.name);
    const gitdirPath = path.join(metadataPath, "gitdir");
    let pointer;
    try {
      pointer = fs.readFileSync(gitdirPath, "utf8").trim();
    } catch {
      // Existing worktree metadata is not residue merely because it is not
      // inspectable. Only an exact pointer into the task-owned F004 root is.
      continue;
    }
    if (!pointer) continue;
    const worktreeGitDir = path.isAbsolute(pointer) ? path.normalize(pointer) : path.resolve(metadataPath, pointer);
    const worktreeRoot = path.dirname(worktreeGitDir);
    if (!isInside(f004Root, worktreeRoot)) continue;
    const relative = repoRelative(repoRoot, metadataPath);
    hits.add(relative.startsWith("../") ? metadataPath : relative);
  }
}

export function scanMutationResidue(repoRoot) {
  const hits = new Set();
  const add = (absolute) => hits.add(repoRelative(repoRoot, absolute));

  walkFiles(path.join(repoRoot, "workers", "scan-api", "src"), (absolute, name) => {
    const dotSibling = name.startsWith(".") && name.endsWith(".js") &&
      (name.includes(".mutant.") || name.includes("-mutant"));
    const doubleUnderscoreModule = name.endsWith("__.mjs") && name.includes(".__mutant_");
    const suboperationControl = name.startsWith(".subop-child-control") && name.endsWith(".mjs");
    if (dotSibling || doubleUnderscoreModule || suboperationControl) add(absolute);
  });

  walkFiles(path.join(repoRoot, "frontend", "src"), (absolute, name) => {
    const hiddenA1 = name.startsWith(".") && name.includes(".a1-mutant.") && name.endsWith(".js");
    const a1Test = name.includes(".a1-mutant.") && name.includes(".test.");
    if (hiddenA1 || a1Test) add(absolute);
  });

  const scriptsDir = path.join(repoRoot, "scripts");
  const scriptsStat = fs.lstatSync(scriptsDir, { throwIfNoEntry: false });
  if (scriptsStat?.isDirectory()) {
    for (const entry of fs.readdirSync(scriptsDir, { withFileTypes: true })) {
      if (entry.isDirectory()) continue;
      if (entry.name.startsWith(".") &&
          ((entry.name.includes("-mutant") && entry.name.endsWith(".js")) ||
           entry.name.includes(".ct2a1-mutant."))) {
        add(path.join(scriptsDir, entry.name));
      }
    }
  }

  const migrationsDir = path.join(repoRoot, "database", "migrations");
  const migrationsStat = fs.lstatSync(migrationsDir, { throwIfNoEntry: false });
  if (migrationsStat?.isDirectory()) {
    for (const entry of fs.readdirSync(migrationsDir, { withFileTypes: true })) {
      if (!entry.isDirectory() && entry.name.startsWith(".") && entry.name.includes("mutant")) {
        add(path.join(migrationsDir, entry.name));
      }
    }
  }

  for (const entry of fs.readdirSync(repoRoot, { withFileTypes: true })) {
    if (!entry.isDirectory() && entry.name.startsWith(".d1-rollback-probe-") && entry.name.endsWith(".mjs")) {
      add(path.join(repoRoot, entry.name));
    }
  }

  const f004Root = path.join(repoRoot, ".f004-mutation-worktrees");
  if (fs.lstatSync(f004Root, { throwIfNoEntry: false })) hits.add(".f004-mutation-worktrees");
  scanTaskOwnedWorktreeMetadata(repoRoot, hits);

  return [...hits].sort((left, right) => left.localeCompare(right));
}

function pidIsLive(pid) {
  if (!Number.isInteger(pid) || pid < 1) return null;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error.code === "ESRCH") return false;
    return true;
  }
}

export function repositoryLockPath(repoRoot, lockRoot = os.tmpdir()) {
  const identity = sha256(fs.realpathSync(repoRoot));
  return path.join(lockRoot, `cybermeters-local-focused-gate-${identity}.lock`);
}

function readLockOwner(directory) {
  try {
    return JSON.parse(fs.readFileSync(path.join(directory, "owner.json"), "utf8"));
  } catch {
    throw new Error(`repository gate lock exists with unverifiable ownership: ${directory}`);
  }
}

function sameLockOwner(left, right) {
  return left?.pid === right?.pid && left?.token === right?.token && left?.repo === right?.repo;
}

export function acquireRepositoryLock(repoRoot, lockRoot = os.tmpdir()) {
  const lockPath = repositoryLockPath(repoRoot, lockRoot);
  const token = crypto.randomUUID();
  const repoIdentity = fs.realpathSync(repoRoot);
  const newOwner = { pid: process.pid, token, repo: repoIdentity };
  const create = () => {
    fs.mkdirSync(lockPath, { mode: 0o700 });
    fs.writeFileSync(path.join(lockPath, "owner.json"), `${JSON.stringify(newOwner)}\n`, {
      mode: 0o600,
    });
  };
  try {
    create();
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
    const observedOwner = readLockOwner(lockPath);
    if (pidIsLive(observedOwner.pid) !== false) {
      throw new Error(`repository gate lock is held by PID ${observedOwner.pid}: ${lockPath}`);
    }

    // One stale-takeover claimant is elected with O_EXCL before the directory is
    // moved. Without this claim, a second process could rename a freshly-created
    // replacement lock after both had observed the same dead PID.
    const takeoverClaim = { pid: process.pid, token, observed_owner: observedOwner };
    const claimPath = path.join(lockPath, ".stale-takeover.json");
    let claimFd;
    try {
      claimFd = fs.openSync(claimPath, "wx", 0o600);
      fs.writeFileSync(claimFd, `${JSON.stringify(takeoverClaim)}\n`);
    } catch (claimError) {
      if (claimError.code === "EEXIST" || claimError.code === "ENOENT") {
        throw new Error(`repository gate stale-lock takeover is already in progress: ${lockPath}`);
      }
      throw claimError;
    } finally {
      if (claimFd !== undefined) fs.closeSync(claimFd);
    }

    const claimedOwner = readLockOwner(lockPath);
    if (!sameLockOwner(claimedOwner, observedOwner) || pidIsLive(claimedOwner.pid) !== false) {
      throw new Error(`repository gate stale-lock owner changed before takeover: ${lockPath}`);
    }

    const takeoverPath = `${lockPath}.stale-${process.pid}-${token}`;
    try {
      fs.renameSync(lockPath, takeoverPath);
    } catch (renameError) {
      throw new Error(`repository gate stale-lock takeover lost the atomic rename: ${renameError.code || renameError.message}`);
    }

    let takeoverVerified = false;
    try {
      const movedOwner = readLockOwner(takeoverPath);
      const movedClaim = JSON.parse(fs.readFileSync(path.join(takeoverPath, ".stale-takeover.json"), "utf8"));
      if (!sameLockOwner(movedOwner, observedOwner) || movedClaim?.token !== token ||
          movedClaim?.pid !== process.pid || pidIsLive(movedOwner.pid) !== false) {
        throw new Error(`repository gate stale-lock ownership changed during takeover: ${takeoverPath}`);
      }
      takeoverVerified = true;
      try {
        create();
      } catch (createError) {
        if (createError.code === "EEXIST") {
          throw new Error(`repository gate lock was acquired by another process during stale takeover: ${lockPath}`);
        }
        throw createError;
      }
    } finally {
      if (takeoverVerified) {
        try { fs.rmSync(takeoverPath, { recursive: true, force: false }); } catch { /* isolated dead lock quarantine */ }
      }
    }
  }
  let released = false;
  return {
    path: lockPath,
    release() {
      if (released) return;
      const owner = JSON.parse(fs.readFileSync(path.join(lockPath, "owner.json"), "utf8"));
      if (owner.pid !== process.pid || owner.token !== token) {
        throw new Error("refusing to release a repository gate lock owned by another process");
      }
      fs.rmSync(lockPath, { recursive: true, force: false });
      released = true;
    },
  };
}

export function installRepositoryLockSignalHandlers(lock, exit = (code) => process.exit(code)) {
  const handlers = [];
  for (const [signal, code] of [["SIGINT", 130], ["SIGTERM", 143]]) {
    const handler = () => {
      try { lock?.release(); } catch { /* preserve signal exit */ }
      exit(code);
    };
    handlers.push([signal, handler]);
    process.once(signal, handler);
  }
  return () => handlers.forEach(([signal, handler]) => process.off(signal, handler));
}

function dependenciesReady(repoRoot) {
  return fs.statSync(path.join(repoRoot, "workers/scan-api/node_modules"), { throwIfNoEntry: false })?.isDirectory() &&
    fs.statSync(path.join(repoRoot, "frontend/node_modules"), { throwIfNoEntry: false })?.isDirectory();
}

function defaultExecuteCommand(commandDefinition, repoRoot, timeoutMs) {
  const cwd = path.join(repoRoot, commandDefinition.working_directory);
  const input = commandDefinition.stdin_path
    ? fs.readFileSync(path.join(repoRoot, commandDefinition.stdin_path))
    : undefined;
  const child = spawnSync(commandDefinition.argv[0], commandDefinition.argv.slice(1), {
    cwd,
    input,
    encoding: "utf8",
    timeout: timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...process.env,
      CI: "1",
      NO_UPDATE_NOTIFIER: "1",
      npm_config_audit: "false",
      npm_config_offline: "true",
      npm_config_update_notifier: "false",
    },
  });
  return {
    status: child.status,
    signal: child.signal,
    error: child.error || null,
    stdout: child.stdout || "",
    stderr: child.stderr || "",
  };
}

function commonCommands(records) {
  const commands = [{
    id: "common-diff-check",
    argv: ["git", "diff", "--check"],
    working_directory: ".",
    timeout_ms: 30_000,
    mutation_bearing: false,
    stdin_path: null,
    display: "git diff --check",
  }];
  if (records.some((record) => record.path.startsWith("workers/"))) {
    commands.push({
      id: "common-worker-entry-syntax",
      argv: ["node", "--input-type=module", "--check"],
      working_directory: ".",
      timeout_ms: 30_000,
      mutation_bearing: false,
      stdin_path: "workers/scan-api/src/index.js",
      display: "node --input-type=module --check < workers/scan-api/src/index.js",
    });
  }
  return commands;
}

function emptyResult(startedAt, now) {
  return {
    schema_version: LOCAL_GATE_SCHEMA_VERSION,
    decision: LOCAL_GATE_DECISIONS.UNKNOWN_FAIL_CLOSED,
    effective_mode: LOCAL_GATE_MODES.RUN_ALL,
    scope_complete: false,
    partial_lane: false,
    merge_gate_eligible: false,
    base_sha: null,
    head_sha: null,
    merge_base: null,
    changed_paths: [],
    omitted_worktree_paths: [],
    selected_packs: [],
    commands: [],
    command_results: [],
    elapsed_ms: now() - startedAt,
    source_fingerprint_before: null,
    source_fingerprint_after: null,
    residue_paths_before: [],
    residue_paths_after: [],
    residue_checks: [],
    timing_sample_valid: false,
    reason: "input has not been resolved",
  };
}

function exitCodeFor(decision) {
  if (decision === LOCAL_GATE_DECISIONS.FOCUSED) return 0;
  if (decision === LOCAL_GATE_DECISIONS.FAILED) return 1;
  return 2;
}

function docsClassificationFor(resolved, repoRoot) {
  const docsLike = resolved.mode === "range" && resolved.records.length > 0 &&
    resolved.records.every((record) => record.path === "CHANGELOG.md" || record.path.startsWith("docs/"));
  if (!docsLike) return null;
  try {
    const manifest = loadManifest(repoRoot);
    return classifyChange({
      repoRoot,
      eventName: "pull_request",
      event: { pull_request: { base: { sha: resolved.baseSha }, head: { sha: resolved.headSha } } },
      manifest,
    });
  } catch (error) {
    return { decision: "UNKNOWN_FAIL_CLOSED", reason: `safe-docs bootstrap error: ${error.message}` };
  }
}

export function runLocalFocusedGate({ argv, repoRoot = scriptRoot, hooks = {} }) {
  const now = hooks.now || Date.now;
  const startedAt = now();
  const result = emptyResult(startedAt, now);
  const fingerprint = hooks.fingerprintSource || wholeSourceFingerprint;
  const scanResidue = hooks.scanResidue || scanMutationResidue;
  const executeCommand = hooks.executeCommand || defaultExecuteCommand;
  const dependencyProbe = hooks.dependenciesReady || dependenciesReady;
  const nodeVersion = hooks.nodeVersion || process.versions.node;
  const lockRoot = hooks.lockRoot || os.tmpdir();
  const log = hooks.log || ((message) => process.stderr.write(`${message}\n`));
  let lock = null;
  let removeSignalHandlers = () => {};

  const residueCheck = (phase) => {
    const paths = scanResidue(repoRoot);
    result.residue_checks.push({ phase, paths });
    return paths;
  };
  const recordResidueAfter = (paths) => {
    result.residue_paths_after = [...new Set([...result.residue_paths_after, ...paths])]
      .sort((left, right) => left.localeCompare(right));
  };
  const failForResidue = (phase, paths) => {
    result.decision = LOCAL_GATE_DECISIONS.FAILED;
    result.effective_mode = LOCAL_GATE_MODES.FOCUSED;
    result.timing_sample_valid = false;
    result.reason = `mutation residue detected ${phase}: ${JSON.stringify(paths)}; timing sample INVALID; no files were deleted or moved`;
  };

  try {
    const input = parseInputArguments(argv);
    const preflightResidue = residueCheck("preflight");
    result.residue_paths_before = preflightResidue;
    if (preflightResidue.length) {
      failForResidue("before gate input resolution", preflightResidue);
      result.elapsed_ms = now() - startedAt;
      return { result, exitCode: 1 };
    }
    const resolved = resolveGateInput(input, repoRoot);
    result.scope_complete = resolved.scopeComplete;
    result.partial_lane = resolved.partialLane;
    result.base_sha = resolved.baseSha;
    result.head_sha = resolved.headSha;
    result.merge_base = resolved.mergeBase;
    result.changed_paths = resolved.records.map((record) => record.path);
    result.omitted_worktree_paths = resolved.omitted;

    const classification = classifyFocusedChanges({
      records: resolved.records,
      inputMode: resolved.mode,
      docsClassification: docsClassificationFor(resolved, repoRoot),
    });
    result.decision = classification.decision;
    result.effective_mode = classification.effective_mode;
    result.selected_packs = classification.selected_packs;
    result.commands = classification.commands.map((item) => item.display);
    result.reason = classification.reason;
    if (classification.ownership_warning) result.ownership_warning = true;
    if (classification.decision !== LOCAL_GATE_DECISIONS.FOCUSED) {
      result.elapsed_ms = now() - startedAt;
      return { result, exitCode: exitCodeFor(result.decision) };
    }

    const commands = [...classification.commands, ...commonCommands(resolved.records)];
    result.commands = commands.map((item) => item.display);
    if (Number.parseInt(String(nodeVersion).split(".")[0], 10) !== 24) {
      result.decision = LOCAL_GATE_DECISIONS.FAILED;
      result.reason = `Node.js major 24 is required; found ${nodeVersion}`;
      result.elapsed_ms = now() - startedAt;
      return { result, exitCode: 1 };
    }
    if (!dependencyProbe(repoRoot)) {
      result.decision = LOCAL_GATE_DECISIONS.FAILED;
      result.reason = "dependency roots are missing; no install was attempted. Run: node scripts/install-governed-dependencies.js --root workers/scan-api ; node scripts/install-governed-dependencies.js --root frontend";
      result.elapsed_ms = now() - startedAt;
      return { result, exitCode: 1 };
    }

    lock = acquireRepositoryLock(repoRoot, lockRoot);
    if (hooks.installSignalHandlers) {
      removeSignalHandlers = installRepositoryLockSignalHandlers(lock);
    }

    const beforeResidue = residueCheck("before-commands");
    result.residue_paths_before = beforeResidue;
    if (beforeResidue.length) {
      failForResidue("before command execution", beforeResidue);
    } else {
      result.source_fingerprint_before = fingerprint(repoRoot);
      result.source_fingerprint_after = result.source_fingerprint_before;
      for (const item of commands) {
        const elapsed = now() - startedAt;
        const remaining = MAX_GATE_MS - elapsed;
        if (remaining <= 0) {
          result.decision = LOCAL_GATE_DECISIONS.FAILED;
          result.reason = `focused gate exceeded ${MAX_GATE_MS}ms before ${item.id}`;
          break;
        }
        const timeoutMs = Math.max(1, Math.min(item.timeout_ms, remaining));
        log(`LOCAL-FOCUSED ${item.id}: ${item.display}`);
        const commandStarted = now();
        const execution = executeCommand(item, repoRoot, timeoutMs);
        const commandElapsed = now() - commandStarted;
        if (execution.stdout) log(execution.stdout.trimEnd());
        if (execution.stderr) log(execution.stderr.trimEnd());
        const commandResult = {
          id: item.id,
          exit_code: execution.status,
          signal: execution.signal,
          elapsed_ms: commandElapsed,
          residue_paths_after: [],
        };
        result.command_results.push(commandResult);
        const commandResidue = residueCheck(`after-command:${item.id}`);
        commandResult.residue_paths_after = commandResidue;
        recordResidueAfter(commandResidue);
        result.source_fingerprint_after = fingerprint(repoRoot);
        if (commandResidue.length) {
          failForResidue(`after command ${item.id}`, commandResidue);
          break;
        }
        if (result.source_fingerprint_after !== result.source_fingerprint_before) {
          result.decision = LOCAL_GATE_DECISIONS.FAILED;
          result.reason = `whole-source fingerprint changed while ${item.id} ran; no automatic restore was attempted`;
          break;
        }
        if (execution.error || execution.signal !== null || execution.status !== 0) {
          result.decision = LOCAL_GATE_DECISIONS.FAILED;
          result.reason = execution.error?.code === "ETIMEDOUT"
            ? `command timed out: ${item.id}`
            : `command failed: ${item.id} (${execution.signal || execution.status || execution.error?.message})`;
          break;
        }
      }

      if (result.decision === LOCAL_GATE_DECISIONS.FOCUSED) {
        result.source_fingerprint_after = fingerprint(repoRoot);
        if (result.source_fingerprint_after !== result.source_fingerprint_before) {
          result.decision = LOCAL_GATE_DECISIONS.FAILED;
          result.reason = "whole-source fingerprint changed before terminal exit; no automatic restore was attempted";
        } else {
          result.reason = result.partial_lane
            ? "focused commands passed for a partial lane; omitted worktree paths remain outside this non-merge proof"
            : "focused commands passed; full PR CI remains authoritative and this local result is not merge evidence";
        }
      }
    }
  } catch (error) {
    result.decision = result.selected_packs.length
      ? LOCAL_GATE_DECISIONS.FAILED
      : LOCAL_GATE_DECISIONS.UNKNOWN_FAIL_CLOSED;
    result.effective_mode = result.decision === LOCAL_GATE_DECISIONS.FAILED
      ? LOCAL_GATE_MODES.FOCUSED
      : LOCAL_GATE_MODES.RUN_ALL;
    result.reason = `local gate error: ${error.message}`;
  } finally {
    removeSignalHandlers();
    if (lock) {
      try {
        const terminalResidue = residueCheck("terminal");
        recordResidueAfter(terminalResidue);
        if (terminalResidue.length && !/mutation residue detected/.test(result.reason)) {
          failForResidue("at terminal exit", terminalResidue);
        }
      } catch (error) {
        result.decision = LOCAL_GATE_DECISIONS.FAILED;
        result.effective_mode = LOCAL_GATE_MODES.FOCUSED;
        result.reason = `terminal mutation residue scan failed closed: ${error.message}`;
      }
      try {
        lock.release();
      } catch (error) {
        result.decision = LOCAL_GATE_DECISIONS.FAILED;
        result.effective_mode = LOCAL_GATE_MODES.FOCUSED;
        result.reason = `repository lock release failed: ${error.message}`;
      }
    }
    result.timing_sample_valid = result.decision === LOCAL_GATE_DECISIONS.FOCUSED &&
      result.residue_paths_before.length === 0 && result.residue_paths_after.length === 0 &&
      result.source_fingerprint_before !== null &&
      result.source_fingerprint_before === result.source_fingerprint_after;
    result.merge_gate_eligible = false;
    result.elapsed_ms = now() - startedAt;
  }
  return { result, exitCode: exitCodeFor(result.decision) };
}

function isCliEntry() {
  return process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url));
}

if (isCliEntry()) {
  const { result, exitCode } = runLocalFocusedGate({
    argv: process.argv.slice(2),
    repoRoot: scriptRoot,
    hooks: { installSignalHandlers: true },
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
  process.exit(exitCode);
}
