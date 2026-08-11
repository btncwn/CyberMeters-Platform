#!/usr/bin/env node

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  assertRepositoryPolicy,
  loadInstallScriptPolicy,
  REPO_ROOT,
  resolveRootPolicy,
  runApprovedLifecycleScripts,
  sha256,
  validateInstalledRoot,
  validateRepositoryPolicy,
  validateRootLock,
} from "./security/install-script-governance.js";

let passed = 0;
let failed = 0;
const ok = (name, condition, detail = "") => {
  if (condition) passed += 1;
  else {
    failed += 1;
    console.log("FAIL " + name + (detail ? " — " + detail : ""));
  }
};
const rejects = (name, operation) => {
  let rejected = false;
  try { operation(); } catch { rejected = true; }
  ok(name, rejected);
};

const policy = loadInstallScriptPolicy();
const baselineErrors = validateRepositoryPolicy(policy);
ok(
  "repository policy, roots, locks, npm defaults and install invocations are exact",
  baselineErrors.length === 0,
  baselineErrors.join(" | "),
);
ok("package-root count is pinned", policy.package_roots.length === 3);
const markers = policy.package_roots.flatMap((root) =>
  root.install_script_markers.map((marker) => ({ root: root.root, ...marker })));
ok("lock install-script marker count is pinned", markers.length === 6);
ok(
  "approved lifecycle-script count is pinned",
  markers.filter((marker) => marker.disposition === "approved").length === 3,
);
ok(
  "denied lock-only markers carry no executable fields",
  markers.filter((marker) => marker.disposition !== "approved")
    .every((marker) => !marker.lifecycle_event && !marker.lifecycle_command && !marker.script_path),
);

for (const [name, mutate] of [
  ["must fail: unapproved package/root drift", (candidate) => { candidate.package_roots[0].root = "frontend-other"; }],
  ["must fail: approved version drift", (candidate) => { candidate.package_roots[0].install_script_markers[0].version = "0.25.13"; }],
  ["must fail: approved integrity drift", (candidate) => { candidate.package_roots[0].install_script_markers[0].integrity = "sha512-unapproved"; }],
  ["must fail: package lock identity drift", (candidate) => { candidate.package_roots[0].lockfile_sha256 = "0".repeat(64); }],
  ["must fail: lifecycle command drift", (candidate) => { candidate.package_roots[0].install_script_markers[0].lifecycle_command = "node changed.js"; }],
  ["must fail: workflow install mapping drift", (candidate) => { candidate.workflow_install_invocations[0].root = "frontend"; }],
]) {
  const candidate = structuredClone(policy);
  mutate(candidate);
  ok(name, validateRepositoryPolicy(candidate).length > 0);
}

const frontendPolicy = policy.package_roots.find((root) => root.root === "frontend");
const frontendRoot = path.join(REPO_ROOT, "frontend");
const mutatedLock = JSON.parse(fs.readFileSync(path.join(frontendRoot, "package-lock.json"), "utf8"));
mutatedLock.packages["node_modules/unapproved"] = {
  version: "1.0.0",
  resolved: "https://registry.invalid/unapproved.tgz",
  integrity: "sha512-unapproved",
  hasInstallScript: true,
};
ok(
  "must fail: a new lock install-script marker is denied",
  validateRootLock(
    frontendPolicy,
    fs.readFileSync(path.join(frontendRoot, "package.json")),
    Buffer.from(JSON.stringify(mutatedLock) + "\n"),
  ).some((error) => error.includes("install-script marker identity drift")),
);

rejects(
  "must fail: an ungoverned install root is rejected before npm",
  () => resolveRootPolicy(policy, "workers/unknown"),
);

const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "install-script-denial-"));
try {
  const packageRoot = path.join(fixture, "node_modules", "unapproved");
  fs.mkdirSync(packageRoot, { recursive: true });
  const markerPath = path.join(fixture, "UNAPPROVED_SCRIPT_EXECUTED");
  const script = "require('node:fs').writeFileSync(" + JSON.stringify(markerPath) + ", 'executed')\n";
  fs.writeFileSync(path.join(packageRoot, "marker.js"), script);
  const manifest = {
    name: "unapproved",
    version: "1.0.0",
    scripts: { postinstall: "node marker.js" },
  };
  const manifestBytes = Buffer.from(JSON.stringify(manifest) + "\n");
  fs.writeFileSync(path.join(packageRoot, "package.json"), manifestBytes);
  fs.writeFileSync(path.join(fixture, "package-lock.json"), JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "node_modules/unapproved": {
        version: "1.0.0",
        resolved: "https://registry.invalid/unapproved.tgz",
        integrity: "sha512-unapproved",
        hasInstallScript: true,
      },
    },
  }) + "\n");
  const deniedMarker = {
    package_path: "node_modules/unapproved",
    package_name: "unapproved",
    version: "1.0.0",
    resolved: "https://registry.invalid/unapproved.tgz",
    integrity: "sha512-unapproved",
    disposition: "deny_no_install_lifecycle",
    package_json_sha256: sha256(manifestBytes),
  };
  const fixturePolicy = { root: "fixture", install_script_markers: [deniedMarker] };
  rejects(
    "must fail: an unapproved installed lifecycle script is rejected",
    () => runApprovedLifecycleScripts(fixture, fixturePolicy),
  );
  ok("must fail control: the unapproved lifecycle script did not execute", !fs.existsSync(markerPath));

  const approvedMarker = {
    ...deniedMarker,
    disposition: "approved",
    lifecycle_event: "postinstall",
    lifecycle_command: "node marker.js",
    script_path: "marker.js",
    script_sha256: sha256(Buffer.from(script)),
  };
  const wrongCommand = structuredClone(approvedMarker);
  wrongCommand.lifecycle_command = "node other.js";
  ok(
    "must fail: installed lifecycle command drift is rejected before execution",
    validateInstalledRoot(fixture, { root: "fixture", install_script_markers: [wrongCommand] })
      .some((error) => error.includes("approved lifecycle command drift")),
  );
  const wrongBytes = structuredClone(approvedMarker);
  wrongBytes.script_sha256 = "0".repeat(64);
  ok(
    "must fail: installed lifecycle script-byte drift is rejected before execution",
    validateInstalledRoot(fixture, { root: "fixture", install_script_markers: [wrongBytes] })
      .some((error) => error.includes("approved lifecycle script bytes drift")),
  );
} finally {
  fs.rmSync(fixture, { recursive: true, force: true });
}

let finalPolicyError = null;
try { assertRepositoryPolicy(policy); } catch (error) { finalPolicyError = error; }
ok("final policy assertion", finalPolicyError === null, finalPolicyError?.message || "");

console.log("\ninstall-script governance: " + passed + " passed, " + failed + " failed");
if (failed) process.exit(1);
