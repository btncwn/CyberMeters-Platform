import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const activeSandboxes = new Set();
let signalCleanupInstalled = false;

function assertSafeTempRoot(tempRoot) {
  const resolved = path.resolve(tempRoot || "");
  const tempBoundary = `${path.resolve(os.tmpdir())}${path.sep}`;
  if (!tempRoot || !resolved.startsWith(tempBoundary) || resolved === path.resolve(os.tmpdir())) {
    throw new Error(`unsafe mutation temp root: ${String(tempRoot)}`);
  }
  return resolved;
}

function removeSandbox(tempRoot) {
  if (!tempRoot) return;
  const resolved = assertSafeTempRoot(tempRoot);
  fs.rmSync(resolved, { recursive: true, force: true });
  activeSandboxes.delete(tempRoot);
}

export function installMutationSignalCleanup() {
  if (signalCleanupInstalled) return;
  signalCleanupInstalled = true;
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
    process.once(signal, () => {
      for (const tempRoot of [...activeSandboxes]) {
        try { removeSandbox(tempRoot); } catch { /* preserve interruption */ }
      }
      console.error(`FAIL Item 10 P5 mutation harness interrupted by ${signal}`);
      process.exit(2);
    });
  }
}

export function createMutationSandbox(root, label = "item10-p5-mutant-") {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), label));
  activeSandboxes.add(tempRoot);
  const workerRoot = path.join(tempRoot, "workers/scan-api");
  const workerSource = path.join(workerRoot, "src");
  try {
    fs.mkdirSync(workerRoot, { recursive: true });
    fs.cpSync(path.join(root, "workers/scan-api/src"), workerSource, {
      recursive: true,
    });
    fs.copyFileSync(
      path.join(root, "workers/scan-api/package.json"),
      path.join(workerRoot, "package.json"),
    );
    fs.symlinkSync(
      path.join(root, "workers/scan-api/node_modules"),
      path.join(workerRoot, "node_modules"),
      "dir",
    );
    const sharedRoot = path.join(root, "shared");
    if (fs.existsSync(sharedRoot)) {
      fs.cpSync(sharedRoot, path.join(tempRoot, "shared"), { recursive: true });
    }
  } catch (error) {
    removeSandbox(tempRoot);
    throw error;
  }
  return Object.freeze({
    tempRoot,
    workerRoot,
    workerSource,
    cleanup: () => removeSandbox(tempRoot),
  });
}

export function replaceExactly(source, from, to, label) {
  if (typeof from !== "string" || from.length === 0) {
    throw new Error(`${label}: mutation anchor must be a non-empty string`);
  }
  let count = 0;
  let cursor = 0;
  while (true) {
    const index = source.indexOf(from, cursor);
    if (index < 0) break;
    count += 1;
    cursor = index + from.length;
  }
  if (count !== 1) {
    throw new Error(`${label}: mutation anchor count ${count}, expected 1`);
  }
  return source.replace(from, to);
}

export function analyseOrderedRegistry({
  registeredIds,
  expectedIds,
  expectedCount,
  expectedFailureIds,
}) {
  const duplicates = registeredIds.filter(
    (id, index) => registeredIds.indexOf(id) !== index,
  );
  const missing = expectedIds.filter((id) => !registeredIds.includes(id));
  const unexpected = registeredIds.filter((id) => !expectedIds.includes(id));
  const exactOrder = JSON.stringify(registeredIds) === JSON.stringify(expectedIds);
  const countExact = registeredIds.length === expectedCount &&
    expectedIds.length === expectedCount;
  const failureRegistryExact = expectedFailureIds == null ||
    JSON.stringify(expectedFailureIds) === JSON.stringify(expectedIds);
  return Object.freeze({
    valid: countExact && exactOrder && duplicates.length === 0 &&
      missing.length === 0 && unexpected.length === 0 && failureRegistryExact,
    countExact,
    exactOrder,
    duplicates,
    missing,
    unexpected,
    failureRegistryExact,
  });
}

const FATAL_DIAGNOSTIC = /(?:\b(?:SyntaxError|ReferenceError|TypeError|RangeError|EvalError|URIError|AggregateError)\b|\bERR_[A-Z0-9_]+\b|UnhandledPromiseRejection|uncaughtException|ITEM10_MUTATION_(?:IMPORT|MODULE|RUNTIME|SPAWN)_FAILURE)/;

export function classifySemanticMutation({
  child,
  output,
  actualFailures,
  expectedFailures,
  summaries,
  expectedAssertions,
  preflight,
}) {
  const summary = summaries.length === 1 ? summaries[0] : null;
  const completedSemantically =
    child?.error == null && child?.status === 1 && child?.signal == null &&
    preflight?.ok === true && summaries.length === 1 &&
    Number(summary?.passed) + actualFailures.length === expectedAssertions &&
    Number(summary?.total) === expectedAssertions &&
    Array.isArray(expectedFailures) && expectedFailures.length > 0 &&
    !FATAL_DIAGNOSTIC.test(String(output || ""));
  return Object.freeze({
    completedSemantically,
    killed: completedSemantically &&
      JSON.stringify(actualFailures) === JSON.stringify(expectedFailures),
  });
}

export function preflightMutationTargets({ moduleUrls = [], sourceFiles = [] }) {
  const failures = [];
  for (const moduleUrl of moduleUrls) {
    const child = spawnSync(process.execPath, [
      "--input-type=module",
      "--eval",
      `await import(process.argv[1]); process.stdout.write("ITEM10_MUTATION_PREFLIGHT_OK\\n");`,
      moduleUrl,
    ], { encoding: "utf8" });
    if (
      child.error != null || child.status !== 0 || child.signal != null ||
      child.stdout !== "ITEM10_MUTATION_PREFLIGHT_OK\n"
    ) {
      failures.push({
        kind: "module",
        target: moduleUrl,
        status: child.status,
        signal: child.signal,
        error: child.error?.message || null,
        output: `${child.stdout || ""}\n${child.stderr || ""}`,
      });
    }
  }
  for (const sourceFile of sourceFiles) {
    const child = spawnSync(process.execPath, ["--check", sourceFile], {
      encoding: "utf8",
    });
    if (child.error != null || child.status !== 0 || child.signal != null) {
      failures.push({
        kind: "syntax",
        target: sourceFile,
        status: child.status,
        signal: child.signal,
        error: child.error?.message || null,
        output: `${child.stdout || ""}\n${child.stderr || ""}`,
      });
    }
  }
  return Object.freeze({ ok: failures.length === 0, failures });
}

export function filesUnder(directory) {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...filesUnder(target));
    else if (entry.isFile()) files.push(target);
  }
  return files;
}

export function fingerprintFiles(files) {
  const currentFiles = typeof files === "function" ? files() : files;
  const digest = crypto.createHash("sha256");
  for (const file of [...currentFiles].sort()) {
    digest.update(file);
    digest.update("\0");
    digest.update(fs.readFileSync(file));
    digest.update("\0");
  }
  return digest.digest("hex");
}

export function forcedInterruptionLeavesFingerprint({ files }) {
  const before = fingerprintFiles(files);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "item10-p5-interrupt-"));
  const sentinel = path.join(tempRoot, "mutant-sentinel.js");
  try {
    const child = spawnSync(process.execPath, [
      "--input-type=module",
      "--eval",
      `import fs from "node:fs";
       fs.writeFileSync(process.argv[1], "mutant bytes");
       process.kill(process.pid, "SIGKILL");`,
      sentinel,
    ], { encoding: "utf8" });
    return child.signal === "SIGKILL" && fs.existsSync(sentinel) &&
      fingerprintFiles(files) === before;
  } finally {
    fs.rmSync(assertSafeTempRoot(tempRoot), { recursive: true, force: true });
  }
}

export function handledSignalCleansSandbox({ root, files }) {
  const before = fingerprintFiles(files);
  const recordRoot = fs.mkdtempSync(path.join(os.tmpdir(), "item10-p5-signal-"));
  const recordFile = path.join(recordRoot, "sandbox-path.txt");
  try {
    const child = spawnSync(process.execPath, [
      "--input-type=module",
      "--eval",
      `import fs from "node:fs";
       const harness = await import(process.argv[1]);
       harness.installMutationSignalCleanup();
       const sandbox = harness.createMutationSandbox(process.argv[2], "item10-p5-signal-child-");
       fs.writeFileSync(process.argv[3], sandbox.tempRoot);
       process.kill(process.pid, "SIGTERM");
       await new Promise((resolve) => setTimeout(resolve, 5000));`,
      import.meta.url,
      root,
      recordFile,
    ], { encoding: "utf8" });
    const sandboxPath = fs.existsSync(recordFile)
      ? fs.readFileSync(recordFile, "utf8")
      : null;
    return Object.freeze({
      ok: child.status === 2 && child.signal == null && Boolean(sandboxPath) &&
        !fs.existsSync(sandboxPath) && fingerprintFiles(files) === before,
      status: child.status,
      signal: child.signal,
      error: child.error?.message || null,
      sandboxPath,
      sandboxExists: Boolean(sandboxPath && fs.existsSync(sandboxPath)),
      output: `${child.stdout || ""}\n${child.stderr || ""}`,
    });
  } finally {
    fs.rmSync(assertSafeTempRoot(recordRoot), { recursive: true, force: true });
  }
}
