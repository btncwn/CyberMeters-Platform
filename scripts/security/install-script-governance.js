#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export const REPO_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
export const POLICY_PATH = path.join(REPO_ROOT, "scripts", "security", "install-script-policy.json");
export const INSTALL_EVENTS = Object.freeze(["preinstall", "install", "postinstall"]);
const EXPECTED_NPMRC = "ignore-scripts=true\n";
const SKIP_DIRECTORIES = new Set([".git", ".wrangler", "coverage", "dist", "node_modules", "test-results"]);
const SHA256_RE = /^[0-9a-f]{64}$/;

export const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const readJson = (filename) => JSON.parse(fs.readFileSync(filename, "utf8"));
const hasOwn = (value, key) => value != null && Object.prototype.hasOwnProperty.call(value, key);
const canonical = (value) => {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
};
const stableJson = (value) => JSON.stringify(canonical(value));

function normalizedRelative(value) {
  if (typeof value !== "string" || !value || value.includes("\\") || value.includes("\0")) return null;
  if (path.posix.isAbsolute(value)) return null;
  const normalized = path.posix.normalize(value);
  if (normalized !== value || normalized === ".." || normalized.startsWith("../")) return null;
  return normalized;
}

function withinRepo(repoRoot, relative) {
  const normalized = normalizedRelative(relative);
  if (!normalized) throw new Error("invalid repository-relative path: " + JSON.stringify(relative));
  const absolute = path.resolve(repoRoot, normalized);
  const repoPrefix = path.resolve(repoRoot) + path.sep;
  if (!absolute.startsWith(repoPrefix)) throw new Error("path escapes repository: " + relative);
  return absolute;
}

export function loadInstallScriptPolicy(repoRoot = REPO_ROOT) {
  return readJson(withinRepo(repoRoot, "scripts/security/install-script-policy.json"));
}

function packageNameFromLockPath(packagePath) {
  const marker = "node_modules/";
  const offset = packagePath.lastIndexOf(marker);
  return offset < 0 ? null : packagePath.slice(offset + marker.length);
}

function installLifecycle(scripts) {
  return Object.fromEntries(INSTALL_EVENTS
    .filter((event) => typeof scripts?.[event] === "string")
    .map((event) => [event, scripts[event]]));
}

function discoverFiles(root, predicate) {
  const found = [];
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (entry.isDirectory() && SKIP_DIRECTORIES.has(entry.name)) continue;
      const absolute = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) visit(absolute);
      else if (entry.isFile() && predicate(absolute)) found.push(absolute);
    }
  };
  visit(root);
  return found;
}

export function discoverPackageRoots(repoRoot = REPO_ROOT) {
  return discoverFiles(repoRoot, (filename) => path.basename(filename) === "package.json")
    .map((filename) => path.relative(repoRoot, path.dirname(filename)).split(path.sep).join("/"))
    .sort();
}

function lockMarkerIdentity(packagePath, meta) {
  return {
    package_path: packagePath,
    package_name: packageNameFromLockPath(packagePath),
    version: meta.version,
    resolved: meta.resolved,
    integrity: meta.integrity,
  };
}

export function validateRootLock(rootPolicy, packageBytes, lockBytes) {
  const errors = [];
  let manifest;
  let lock;
  try { manifest = JSON.parse(packageBytes); } catch (error) { return ["package.json parse failed: " + error.message]; }
  try { lock = JSON.parse(lockBytes); } catch (error) { return ["package-lock.json parse failed: " + error.message]; }

  if (sha256(packageBytes) !== rootPolicy.package_json_sha256) errors.push("package.json SHA-256 drift");
  if (sha256(lockBytes) !== rootPolicy.lockfile_sha256) errors.push("package-lock.json SHA-256 drift");
  if (manifest.name !== rootPolicy.package_name || manifest.version !== rootPolicy.package_version) {
    errors.push("package root name/version drift");
  }
  if (Object.keys(installLifecycle(manifest.scripts)).length) errors.push("package root declares an install lifecycle script");
  if (lock.lockfileVersion !== rootPolicy.lockfile_version) errors.push("lockfileVersion drift");
  if (lock.packages?.[""]?.name !== rootPolicy.package_name || lock.packages?.[""]?.version !== rootPolicy.package_version) {
    errors.push("lockfile root identity drift");
  }

  const actual = Object.entries(lock.packages || {})
    .filter(([, meta]) => meta.hasInstallScript === true)
    .map(([packagePath, meta]) => lockMarkerIdentity(packagePath, meta))
    .sort((a, b) => a.package_path.localeCompare(b.package_path));
  const expected = (rootPolicy.install_script_markers || [])
    .map(({ package_path, package_name, version, resolved, integrity }) => ({
      package_path, package_name, version, resolved, integrity,
    }))
    .sort((a, b) => a.package_path.localeCompare(b.package_path));
  if (stableJson(actual) !== stableJson(expected)) errors.push("lock install-script marker identity drift");
  return errors;
}

function parseWorkflowSteps(source, relativeFile) {
  const lines = source.split("\n");
  const steps = [];
  for (let index = 0; index < lines.length; index += 1) {
    const nameMatch = lines[index].match(/^(\s*)- name: (.+)$/);
    if (!nameMatch) continue;
    const indent = nameMatch[1].length;
    let run = null;
    let cursor = index + 1;
    for (; cursor < lines.length; cursor += 1) {
      const nextStep = lines[cursor].match(/^(\s*)- name: /);
      if (nextStep && nextStep[1].length === indent) break;
      const runMatch = lines[cursor].match(/^\s*run:\s*(.+)$/);
      if (runMatch && runMatch[1] !== "|" && runMatch[1] !== ">") run = runMatch[1].trim();
    }
    if (run) steps.push({ file: relativeFile, step_name: nameMatch[2].trim(), command: run });
    index = cursor - 1;
  }
  return steps;
}

function workflowInstallInvocations(repoRoot) {
  const workflowsRoot = path.join(repoRoot, ".github", "workflows");
  const files = discoverFiles(workflowsRoot, (filename) => /\.ya?ml$/.test(filename));
  const governed = [];
  const raw = [];
  for (const filename of files) {
    const relative = path.relative(repoRoot, filename).split(path.sep).join("/");
    const source = fs.readFileSync(filename, "utf8");
    for (const step of parseWorkflowSteps(source, relative)) {
      if (/^node scripts\/install-governed-dependencies\.js --root [A-Za-z0-9._/-]+$/.test(step.command)) {
        governed.push({ ...step, root: step.command.slice(step.command.lastIndexOf(" ") + 1) });
      }
      if (/^npm\s+(?:ci|install)(?:\s|$)/.test(step.command)) raw.push(step);
    }
    for (const line of source.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed.startsWith("#") && /^npm\s+(?:ci|install)(?:\s|$)/.test(trimmed)) {
        raw.push({ file: relative, step_name: "multiline shell", command: trimmed });
      }
    }
  }
  return { governed, raw };
}

function scriptNpmInstallCalls(repoRoot) {
  const scriptsRoot = path.join(repoRoot, "scripts");
  const files = discoverFiles(scriptsRoot, (filename) => /\.(?:c?js|mjs|sh)$/.test(filename));
  const found = [];
  const call = /\b(?:spawn|spawnSync|execFile|execFileSync)\s*\(\s*["']npm["']\s*,\s*(?:policy\.installer\.npm_args|\[\s*["'](?:ci|install)["'])/g;
  for (const filename of files) {
    const source = fs.readFileSync(filename, "utf8");
    const matches = [...source.matchAll(call)];
    for (const match of matches) {
      found.push({
        file: path.relative(repoRoot, filename).split(path.sep).join("/"),
        offset: match.index,
      });
    }
  }
  return found;
}

function validatePolicyShape(policy) {
  const errors = [];
  if (policy?.schema_version !== 1) errors.push("schema_version must be 1");
  if (policy?.policy_id !== "H-04-INSTALL-SCRIPT-GOVERNANCE-v1") errors.push("policy_id drift");
  if (policy?.default_action !== "deny") errors.push("default_action must be deny");
  if (!Array.isArray(policy?.package_roots) || !Array.isArray(policy?.npmrc_paths)) errors.push("policy arrays missing");
  for (const rootPolicy of policy?.package_roots || []) {
    if (normalizedRelative(rootPolicy.root) !== rootPolicy.root) errors.push("invalid package root: " + rootPolicy.root);
    if (!SHA256_RE.test(rootPolicy.package_json_sha256 || "")) errors.push("invalid package hash: " + rootPolicy.root);
    if (!SHA256_RE.test(rootPolicy.lockfile_sha256 || "")) errors.push("invalid lock hash: " + rootPolicy.root);
    for (const marker of rootPolicy.install_script_markers || []) {
      if (!["approved", "deny_no_install_lifecycle"].includes(marker.disposition)) {
        errors.push("invalid disposition: " + rootPolicy.root + "/" + marker.package_path);
      }
      if (!SHA256_RE.test(marker.package_json_sha256 || "")) errors.push("invalid package manifest hash: " + marker.package_path);
      if (marker.disposition === "approved") {
        if (marker.lifecycle_event !== "postinstall" || marker.lifecycle_command !== "node " + marker.script_path) {
          errors.push("approved command is not one exact node postinstall: " + marker.package_path);
        }
        if (!SHA256_RE.test(marker.script_sha256 || "")) errors.push("invalid approved script hash: " + marker.package_path);
      } else if (hasOwn(marker, "lifecycle_event") || hasOwn(marker, "lifecycle_command") || hasOwn(marker, "script_path")) {
        errors.push("denied marker carries executable fields: " + marker.package_path);
      }
    }
  }
  return errors;
}

export function validateRepositoryPolicy(policy, repoRoot = REPO_ROOT) {
  const errors = validatePolicyShape(policy);
  const roots = (policy.package_roots || []).map((entry) => entry.root).sort();
  if (roots.length !== policy.expected_package_root_count || new Set(roots).size !== roots.length) {
    errors.push("package root count/uniqueness drift");
  }
  const discovered = discoverPackageRoots(repoRoot);
  if (stableJson(roots) !== stableJson(discovered)) errors.push("package root inventory drift: " + discovered.join(", "));

  const npmrcPaths = [...(policy.npmrc_paths || [])].sort();
  const expectedNpmrc = [".npmrc", ...roots.map((root) => root + "/.npmrc")].sort();
  if (stableJson(npmrcPaths) !== stableJson(expectedNpmrc)) errors.push(".npmrc root coverage drift");
  for (const relative of npmrcPaths) {
    try {
      if (fs.readFileSync(withinRepo(repoRoot, relative), "utf8") !== EXPECTED_NPMRC) {
        errors.push(relative + " is not the exact deny default");
      }
    } catch (error) { errors.push(relative + ": " + error.message); }
  }

  let markerCount = 0;
  let approvedCount = 0;
  for (const rootPolicy of policy.package_roots || []) {
    markerCount += (rootPolicy.install_script_markers || []).length;
    approvedCount += (rootPolicy.install_script_markers || []).filter((marker) => marker.disposition === "approved").length;
    try {
      const rootAbs = withinRepo(repoRoot, rootPolicy.root);
      const rootErrors = validateRootLock(
        rootPolicy,
        fs.readFileSync(path.join(rootAbs, "package.json")),
        fs.readFileSync(path.join(rootAbs, "package-lock.json")),
      );
      errors.push(...rootErrors.map((error) => rootPolicy.root + ": " + error));
    } catch (error) { errors.push(rootPolicy.root + ": " + error.message); }
  }
  if (markerCount !== policy.expected_lock_install_marker_count) errors.push("lock install-script marker count drift");
  if (approvedCount !== policy.expected_approved_script_count) errors.push("approved lifecycle-script count drift");

  const workflow = workflowInstallInvocations(repoRoot);
  const actualWorkflow = workflow.governed.sort((a, b) => stableJson(a).localeCompare(stableJson(b)));
  const expectedWorkflow = [...(policy.workflow_install_invocations || [])]
    .map(({ file, step_name, root, command }) => ({ file, step_name, command, root }))
    .sort((a, b) => stableJson(a).localeCompare(stableJson(b)));
  if (stableJson(actualWorkflow) !== stableJson(expectedWorkflow)) errors.push("workflow install invocation map drift");
  if (workflow.raw.length) {
    errors.push("raw npm install invocation found: " + workflow.raw
      .map((item) => item.file + ":" + item.command).join(" | "));
  }

  const installer = policy.installer || {};
  try {
    const entrypointBytes = fs.readFileSync(withinRepo(repoRoot, installer.entrypoint_file));
    if (sha256(entrypointBytes) !== installer.entrypoint_sha256) {
      errors.push("governed installer entrypoint SHA-256 drift");
    }
    const implementationBytes = fs.readFileSync(withinRepo(repoRoot, installer.implementation_file));
    if (sha256(implementationBytes) !== installer.implementation_sha256) {
      errors.push("governed installer implementation SHA-256 drift");
    }
    const implementationSource = implementationBytes.toString("utf8");
    const validationAnchor = "assertRepositoryPolicy" + "(policy, repoRoot);";
    const firstValidation = implementationSource.indexOf(validationAnchor);
    const npmSpawnAnchor = "spawnSync(" + '\"npm\", policy.installer.npm_args';
    const npmInstall = implementationSource.indexOf(npmSpawnAnchor);
    const secondValidation = implementationSource.indexOf(
      validationAnchor,
      firstValidation + 1,
    );
    const approvedAnchor = "runApprovedLifecycleScripts" + "(rootAbs, rootPolicy);";
    const approvedExecution = implementationSource.indexOf(approvedAnchor);
    if (!(firstValidation >= 0 && npmInstall > firstValidation &&
          secondValidation > npmInstall && approvedExecution > secondValidation)) {
      errors.push("governed installer validation/execution order drift");
    }
  } catch (error) { errors.push("governed installer: " + error.message); }
  if (stableJson(installer.npm_args) !== stableJson(["ci", "--ignore-scripts", "--no-audit", "--no-fund"])) {
    errors.push("governed npm argument drift");
  }
  const scriptCalls = scriptNpmInstallCalls(repoRoot);
  if (scriptCalls.length !== 1 || scriptCalls[0].file !== installer.implementation_file) {
    errors.push("script npm install invocation map drift");
  }
  return errors;
}

export function assertRepositoryPolicy(policy, repoRoot = REPO_ROOT) {
  const errors = validateRepositoryPolicy(policy, repoRoot);
  if (errors.length) throw new Error("install-script policy invalid: " + errors.join("; "));
}

export function resolveRootPolicy(policy, selectedRoot) {
  const normalized = normalizedRelative(selectedRoot);
  const match = policy.package_roots?.filter((entry) => entry.root === normalized) || [];
  if (match.length !== 1) throw new Error("package root is not governed: " + JSON.stringify(selectedRoot));
  return match[0];
}

function constraintMatches(values, current) {
  if (!Array.isArray(values) || values.length === 0) return true;
  if (values.includes("!" + current)) return false;
  const positive = values.filter((entry) => !entry.startsWith("!"));
  return positive.length === 0 || positive.includes(current);
}

function preflightPlatformBinary(rootAbs, lock, marker, packageManifest) {
  const dependencies = Object.entries(packageManifest.optionalDependencies || {});
  const candidates = dependencies.filter(([name]) => {
    const meta = lock.packages?.["node_modules/" + name];
    return meta && constraintMatches(meta.os, process.platform) && constraintMatches(meta.cpu, process.arch);
  });
  if (candidates.length !== 1) {
    throw new Error(marker.package_name + ": expected one platform package, found " + candidates.length);
  }
  const [platformName, platformVersion] = candidates[0];
  const platformPath = "node_modules/" + platformName;
  const platformMeta = lock.packages[platformPath];
  const platformRoot = path.join(rootAbs, platformPath);
  const platformManifest = readJson(path.join(platformRoot, "package.json"));
  if (platformManifest.name !== platformName ||
      platformManifest.version !== platformVersion ||
      platformMeta.version !== platformVersion) {
    throw new Error(marker.package_name + ": platform package identity drift");
  }
  const binary = path.join(platformRoot, marker.platform_binary_subpath);
  if (!fs.statSync(binary).isFile()) throw new Error(marker.package_name + ": platform binary is missing");
}

export function validateInstalledRoot(rootAbs, rootPolicy) {
  const errors = [];
  const lock = readJson(path.join(rootAbs, "package-lock.json"));
  const approvals = new Map((rootPolicy.install_script_markers || [])
    .filter((marker) => marker.disposition === "approved")
    .map((marker) => [marker.package_path, marker]));
  const installedLifecycle = [];
  for (const packagePath of Object.keys(lock.packages || {})) {
    const manifestPath = packagePath
      ? path.join(rootAbs, packagePath, "package.json")
      : path.join(rootAbs, "package.json");
    if (!fs.existsSync(manifestPath)) continue;
    const manifestBytes = fs.readFileSync(manifestPath);
    const manifest = JSON.parse(manifestBytes);
    const lifecycle = installLifecycle(manifest.scripts);
    if (Object.keys(lifecycle).length) installedLifecycle.push({ packagePath, manifest, manifestBytes, lifecycle });

    const marker = (rootPolicy.install_script_markers || []).find((entry) => entry.package_path === packagePath);
    if (marker && sha256(manifestBytes) !== marker.package_json_sha256) {
      errors.push(packagePath + ": installed package.json SHA-256 drift");
    }
    if (marker?.disposition === "deny_no_install_lifecycle" && Object.keys(lifecycle).length) {
      errors.push(packagePath + ": denied package exposes an install lifecycle script");
    }
  }
  for (const item of installedLifecycle) {
    const approval = approvals.get(item.packagePath);
    if (!approval) {
      errors.push((item.packagePath || "<package-root>") + ": unapproved install lifecycle script");
      continue;
    }
    if (stableJson(item.lifecycle) !== stableJson({ [approval.lifecycle_event]: approval.lifecycle_command })) {
      errors.push(item.packagePath + ": approved lifecycle command drift");
    }
    const script = path.join(rootAbs, item.packagePath, approval.script_path);
    if (!fs.existsSync(script) || sha256(fs.readFileSync(script)) !== approval.script_sha256) {
      errors.push(item.packagePath + ": approved lifecycle script bytes drift");
    }
  }
  for (const packagePath of approvals.keys()) {
    if (!installedLifecycle.some((item) => item.packagePath === packagePath)) {
      errors.push(packagePath + ": approved lifecycle script is absent");
    }
  }
  return errors;
}

export function runApprovedLifecycleScripts(rootAbs, rootPolicy) {
  const installedErrors = validateInstalledRoot(rootAbs, rootPolicy);
  if (installedErrors.length) throw new Error("installed graph rejected: " + installedErrors.join("; "));
  const lock = readJson(path.join(rootAbs, "package-lock.json"));
  const approved = (rootPolicy.install_script_markers || [])
    .filter((marker) => marker.disposition === "approved");
  for (const marker of approved) {
    const packageRoot = path.join(rootAbs, marker.package_path);
    const manifest = readJson(path.join(packageRoot, "package.json"));
    preflightPlatformBinary(rootAbs, lock, marker, manifest);
    const script = path.join(packageRoot, marker.script_path);
    const lifecycleEnvironment = {
      ...process.env,
      npm_config_ignore_scripts: "true",
      npm_lifecycle_event: marker.lifecycle_event,
      npm_lifecycle_script: marker.lifecycle_command,
      npm_package_name: marker.package_name,
      npm_package_version: marker.version,
    };
    for (const key of Object.keys(lifecycleEnvironment)) {
      if (key.toLowerCase() === "path") delete lifecycleEnvironment[key];
    }
    lifecycleEnvironment.PATH = "";
    const child = spawnSync(process.execPath, [script], {
      cwd: packageRoot,
      env: lifecycleEnvironment,
      encoding: "utf8",
      timeout: 120_000,
      maxBuffer: 16 * 1024 * 1024,
    });
    if (child.error || child.signal !== null || child.status !== 0) {
      throw new Error(marker.package_name + ": controlled postinstall failed: " +
        (child.error?.message || child.signal || child.stderr || child.status));
    }
    const probe = spawnSync(path.join(packageRoot, marker.probe_path), marker.probe_args, {
      cwd: packageRoot,
      encoding: "utf8",
      timeout: 30_000,
      maxBuffer: 1024 * 1024,
    });
    if (probe.error || probe.signal !== null || probe.status !== 0 ||
        probe.stdout.trim() !== marker.probe_stdout) {
      throw new Error(marker.package_name + ": postinstall probe failed or drifted");
    }
    console.log("approved lifecycle script: " + rootPolicy.root + "/" +
      marker.package_name + "@" + marker.version + " " + marker.lifecycle_event);
  }
  const postErrors = validateInstalledRoot(rootAbs, rootPolicy);
  if (postErrors.length) throw new Error("post-execution graph rejected: " + postErrors.join("; "));
}

export function installGovernedRoot(policy, selectedRoot, repoRoot = REPO_ROOT) {
  assertRepositoryPolicy(policy, repoRoot);
  const rootPolicy = resolveRootPolicy(policy, selectedRoot);
  const rootAbs = withinRepo(repoRoot, rootPolicy.root);
  const child = spawnSync("npm", policy.installer.npm_args, {
    cwd: rootAbs,
    env: { ...process.env, npm_config_ignore_scripts: "true" },
    stdio: "inherit",
    timeout: 300_000,
  });
  if (child.error || child.signal !== null || child.status !== 0) {
    throw new Error("script-disabled npm ci failed for " + rootPolicy.root + ": " +
      (child.error?.message || child.signal || child.status));
  }
  assertRepositoryPolicy(policy, repoRoot);
  runApprovedLifecycleScripts(rootAbs, rootPolicy);
  console.log("governed install complete: " + rootPolicy.root);
}
