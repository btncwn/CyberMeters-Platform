#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  classifyChange,
  evidenceScopeFingerprint,
  loadManifest,
  manifestSemanticFingerprint,
  validateManifest,
  verifyEvidenceScopes,
} from "./ci-safe-docs-only-lib.js";
import { evaluateWorkflowPolicy } from "./ci-workflow-policy.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const self = fileURLToPath(import.meta.url);
const workflowPath = path.join(root, ".github", "workflows", "ci.yml");
const manifestPath = path.join(root, ".github", "ci-safe-docs-only-v1.json");
const libraryPath = path.join(root, "scripts", "ci-safe-docs-only-lib.js");
const MUTATION_TARGET_FILES = Object.freeze([workflowPath, manifestPath, libraryPath]);
// This validator must remain runnable before commit because founder review is
// performed against frozen uncommitted candidates. The only permitted target
// drift is the exact reviewed workflow byte set that wires this candidate's
// two validators; after commit the ordinary HEAD equality path applies again.
const REVIEWED_UNCOMMITTED_TARGET_SHA256 = Object.freeze(new Map([
  [workflowPath, "c59ec04906aea003c9fce7330edf60c5eb0b6324e6d0e5e0fbd704a0e4945416"],
  [manifestPath, "a356e9682737d764a10a272612777c63f8ff631ab8098301336671c5abb62068"],
]));
const EXPECTED_FIXTURES = 31;
const EXPECTED_MUTANTS = 26;
const EXPECTED_POLICY_ASSERTIONS = 13;
const EXPECTED_ASSERTIONS = 85;
const EXPECTED_MANIFEST_SEMANTIC_FINGERPRINT = "17827a4dd6e05d8e555a632d0b7282014a2cc0f5932e3452d44f7769ef23abca";

const fixtureChild = process.argv.includes("--fixture-child");
const policyChild = process.argv.includes("--policy-child");
const manifestChild = process.argv.includes("--manifest-child");
const interruptRestoreArg = process.argv.find((arg) => arg.startsWith("--interrupt-restore-child="));
const selectedFixturesArg = process.argv.find((arg) => arg.startsWith("--fixtures="));

const FIXTURES = Object.freeze([
  { name: "changelog_only", safe: true, contentClass: "CHANGELOG_ONLY" },
  { name: "ordinary_docs", safe: true, contentClass: "DOCS_ONLY" },
  { name: "ordinary_docs_addition", safe: true, contentClass: "DOCS_ONLY" },
  { name: "docs_runtime", safe: false },
  { name: "docs_scripts", safe: false },
  { name: "docs_workflow", safe: false },
  { name: "docs_changelog_mixed", safe: false },
  { name: "rename", safe: false },
  { name: "copy", safe: false },
  { name: "deletion", safe: false },
  { name: "symlink", safe: false },
  { name: "submodule", safe: false },
  { name: "binary", safe: false },
  { name: "root_governance", safe: false },
  { name: "security_inventory", safe: false },
  { name: "security_case_variant", safe: false },
  { name: "governance_name_variant", safe: false },
  { name: "allow_deny_conflict", safe: false },
  { name: "workflow_only", safe: false },
  { name: "scripts_only", safe: false },
  { name: "classifier_change", safe: false },
  { name: "manifest_change", safe: false },
  { name: "over_300_files", safe: false },
  { name: "malformed_base", safe: false },
  { name: "missing_base_object", safe: false },
  { name: "stale_evidence", safe: false, decision: "UNKNOWN_FAIL_CLOSED" },
  { name: "shallow_checkout", safe: false },
  { name: "unresolved_merge_base", safe: false },
  { name: "wrong_base", safe: false },
  { name: "empty_diff", safe: false },
  { name: "unexpected_event_and_push_main", safe: false },
]);

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

function git(repo, args, options = {}) {
  const child = spawnSync("git", args, {
    cwd: repo,
    encoding: "utf8",
    timeout: 30_000,
    maxBuffer: 16 * 1024 * 1024,
    ...options,
  });
  if (child.error || child.signal !== null || child.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${child.error?.message || child.signal || child.stderr || child.status}`);
  }
  return child.stdout.trim();
}

function write(repo, relative, contents) {
  const target = path.join(repo, relative);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, contents);
}

function commit(repo, message) {
  git(repo, ["add", "-A"]);
  git(repo, ["commit", "-m", message]);
  return git(repo, ["rev-parse", "HEAD"]);
}

function baseFixtureRepo() {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "ci-safe-docs-fixture-"));
  git(repo, ["init", "-b", "main"]);
  git(repo, ["config", "user.email", "ci-fixture@example.invalid"]);
  git(repo, ["config", "user.name", "CI Fixture"]);
  write(repo, "CHANGELOG.md", "# Changelog\n\nBaseline.\n");
  write(repo, "AGENTS.md", "# Governance\n");
  write(repo, "proof.txt", "evidence scope\n");
  write(repo, "docs/ordinary.md", "# Ordinary\n");
  write(repo, "docs/security/ENTRY-POINT-INVENTORY.md", "# Security inventory\n");
  write(repo, "workers/scan-api/src/index.js", "export default {};\n");
  write(repo, "scripts/classify-ci-change.js", "export {};\n");
  write(repo, ".github/workflows/ci.yml", "name: fixture\n");
  write(repo, ".github/ci-safe-docs-only-v1.json", "{}\n");
  const base = commit(repo, "base");
  return { repo, base };
}

function fixtureManifest(repo) {
  const manifest = structuredClone(loadManifest(root));
  const proof = evidenceScopeFingerprint(repo, ["proof.txt"]);
  for (const step of manifest.skipped_heavy_steps) {
    step.evidence.scope_paths = ["proof.txt"];
    step.evidence.scope_sha256 = proof.sha256;
    step.evidence.scope_file_count = proof.file_count;
  }
  return manifest;
}

function prEvent(base, head) {
  return { pull_request: { base: { sha: base }, head: { sha: head } } };
}

function buildFixture(name) {
  const state = baseFixtureRepo();
  const { repo, base } = state;
  let eventName = "pull_request";
  let event = null;
  let head = null;

  const append = (relative, text = "change\n") => fs.appendFileSync(path.join(repo, relative), text);
  switch (name) {
    case "changelog_only": append("CHANGELOG.md"); break;
    case "ordinary_docs": append("docs/ordinary.md"); break;
    case "ordinary_docs_addition":
      write(repo, "docs/new-ordinary-note.md", "# New ordinary note\n\nA distinct documentation-only addition.\n");
      break;
    case "docs_runtime": append("docs/ordinary.md"); append("workers/scan-api/src/index.js"); break;
    case "docs_scripts": append("docs/ordinary.md"); append("scripts/classify-ci-change.js"); break;
    case "docs_workflow": append("docs/ordinary.md"); append(".github/workflows/ci.yml"); break;
    case "docs_changelog_mixed": append("docs/ordinary.md"); append("CHANGELOG.md"); break;
    case "rename": fs.renameSync(path.join(repo, "docs/ordinary.md"), path.join(repo, "docs/renamed.md")); break;
    case "copy": fs.copyFileSync(path.join(repo, "docs/ordinary.md"), path.join(repo, "docs/copied.md")); break;
    case "deletion": fs.unlinkSync(path.join(repo, "docs/ordinary.md")); break;
    case "symlink": fs.symlinkSync("ordinary.md", path.join(repo, "docs/link.md")); break;
    case "submodule":
      git(repo, ["update-index", "--add", "--cacheinfo", `160000,${base},docs/gitlink.md`]);
      break;
    case "binary": write(repo, "docs/binary.md", Buffer.from([0, 1, 2, 3, 0, 255])); break;
    case "root_governance": append("AGENTS.md"); break;
    case "security_inventory": append("docs/security/ENTRY-POINT-INVENTORY.md"); break;
    case "security_case_variant":
      write(repo, "docs/Security/entry-point-inventory.md", "# Security inventory variant\n");
      break;
    case "governance_name_variant":
      write(repo, "docs/governance-notes/ci.md", "# Governance notes\n");
      break;
    case "allow_deny_conflict": append("docs/security/ENTRY-POINT-INVENTORY.md"); break;
    case "workflow_only": append(".github/workflows/ci.yml"); break;
    case "scripts_only": write(repo, "scripts/validate-new.js", "export {};\n"); break;
    case "classifier_change": append("scripts/classify-ci-change.js"); break;
    case "manifest_change": append(".github/ci-safe-docs-only-v1.json"); break;
    case "over_300_files":
      for (let index = 0; index < 301; index += 1) {
        write(repo, `docs/generated/file-${String(index).padStart(3, "0")}.md`, `# ${index}\n`);
      }
      break;
    case "malformed_base": append("docs/ordinary.md"); break;
    case "missing_base_object": append("docs/ordinary.md"); break;
    case "stale_evidence": append("docs/ordinary.md"); break;
    case "shallow_checkout":
      append("proof.txt", "intermediate\n");
      state.actualBase = commit(repo, "intermediate base");
      append("docs/ordinary.md");
      break;
    case "unresolved_merge_base": append("docs/ordinary.md"); break;
    case "wrong_base": append("docs/ordinary.md"); break;
    case "empty_diff": break;
    case "unexpected_event_and_push_main": append("docs/ordinary.md"); break;
    default: throw new Error(`unknown fixture ${name}`);
  }

  if (name === "empty_diff") {
    git(repo, ["commit", "--allow-empty", "-m", `fixture ${name}`]);
    head = git(repo, ["rev-parse", "HEAD"]);
  } else if (name === "submodule") {
    git(repo, ["commit", "-m", `fixture ${name}`]);
    head = git(repo, ["rev-parse", "HEAD"]);
  } else {
    head = commit(repo, `fixture ${name}`);
  }
  event = prEvent(state.actualBase || base, head);

  if (name === "malformed_base") event.pull_request.base.sha = "not-a-sha";
  if (name === "missing_base_object") event.pull_request.base.sha = "f".repeat(40);
  if (name === "unresolved_merge_base") {
    const tree = git(repo, ["rev-parse", `${head}^{tree}`]);
    const orphan = git(repo, ["commit-tree", tree, "-m", "unrelated base"], {
      env: {
        ...process.env,
        GIT_AUTHOR_NAME: "CI Fixture",
        GIT_AUTHOR_EMAIL: "ci-fixture@example.invalid",
        GIT_COMMITTER_NAME: "CI Fixture",
        GIT_COMMITTER_EMAIL: "ci-fixture@example.invalid",
      },
    });
    event.pull_request.base.sha = orphan;
  }
  if (name === "wrong_base") {
    const tree = git(repo, ["rev-parse", `${base}^{tree}`]);
    const siblingBase = git(repo, ["commit-tree", tree, "-p", base, "-m", "wrong event base"], {
      env: {
        ...process.env,
        GIT_AUTHOR_NAME: "CI Fixture",
        GIT_AUTHOR_EMAIL: "ci-fixture@example.invalid",
        GIT_COMMITTER_NAME: "CI Fixture",
        GIT_COMMITTER_EMAIL: "ci-fixture@example.invalid",
      },
    });
    event.pull_request.base.sha = siblingBase;
  }
  if (name === "unexpected_event_and_push_main") eventName = "schedule";

  if (name === "shallow_checkout") {
    const shallow = fs.mkdtempSync(path.join(os.tmpdir(), "ci-safe-docs-shallow-"));
    fs.rmdirSync(shallow);
    git(os.tmpdir(), ["clone", "--depth", "2", `file://${repo}`, shallow]);
    return { ...state, repo: shallow, sourceRepo: repo, base, head, eventName, event };
  }
  return { ...state, base, head, eventName, event };
}

function runFixture(definition) {
  const state = buildFixture(definition.name);
  try {
    const manifest = fixtureManifest(state.repo);
    if (definition.name === "allow_deny_conflict") {
      manifest.safe_docs.allowed_exact_files.push("docs/security/ENTRY-POINT-INVENTORY.md");
    }
    if (definition.name === "stale_evidence") {
      manifest.skipped_heavy_steps[0].evidence.scope_sha256 = "0".repeat(64);
    }
    const classification = classifyChange({
      repoRoot: state.repo,
      eventName: state.eventName,
      event: state.event,
      manifest,
    });
    const problems = [];
    if (definition.safe) {
      if (!classification.safe_docs_only || classification.effective_mode !== "SAFE_DOCS_ONLY") {
        problems.push(`got ${classification.decision}/${classification.effective_mode}: ${classification.reason}`);
      }
      if (classification.content_class !== definition.contentClass) {
        problems.push(`content class ${classification.content_class}, want ${definition.contentClass}`);
      }
    } else if (classification.safe_docs_only || classification.effective_mode !== "RUN_ALL") {
      problems.push(`unsafe fixture narrowed to ${classification.decision}/${classification.effective_mode}`);
    }
    if (definition.decision && classification.decision !== definition.decision) {
      problems.push(`decision ${classification.decision}, want ${definition.decision}`);
    }

    if (definition.name === "unexpected_event_and_push_main") {
      const push = classifyChange({
        repoRoot: state.repo,
        eventName: "push",
        event: { ref: "refs/heads/main", before: state.base, after: state.head },
        manifest,
      });
      if (push.safe_docs_only || push.effective_mode !== "RUN_ALL") {
        problems.push(`push:main narrowed to ${push.decision}/${push.effective_mode}`);
      }
    }
    return problems;
  } finally {
    fs.rmSync(state.repo, { recursive: true, force: true });
    if (state.sourceRepo) fs.rmSync(state.sourceRepo, { recursive: true, force: true });
  }
}

function failNames(output) {
  return output.split("\n")
    .filter((line) => line.startsWith("FAIL "))
    .map((line) => line.slice(5).split(" — ")[0].trim())
    .sort();
}

if (fixtureChild) {
  const selected = new Set((selectedFixturesArg?.slice("--fixtures=".length) || "").split(",").filter(Boolean));
  const definitions = selected.size ? FIXTURES.filter((fixture) => selected.has(fixture.name)) : FIXTURES;
  let failures = 0;
  for (const definition of definitions) {
    const problems = runFixture(definition);
    if (problems.length) {
      failures += 1;
      console.log(`FAIL fixture ${definition.name} remains ${definition.safe ? definition.contentClass : "RUN_ALL"} — ${problems.join("; ")}`);
    } else {
      console.log(`PASS fixture ${definition.name} remains ${definition.safe ? definition.contentClass : "RUN_ALL"}`);
    }
  }
  console.log(`fixture child: ${definitions.length - failures}/${definitions.length} passed`);
  process.exit(failures ? 1 : 0);
}

if (policyChild) {
  const manifest = loadManifest(root);
  const workflowSource = fs.readFileSync(workflowPath, "utf8");
  const checks = evaluateWorkflowPolicy({ workflowSource, manifest });
  const failures = checks.filter((check) => !check.passed);
  for (const check of checks) {
    console.log(`${check.passed ? "PASS" : "FAIL"} ${check.name}${check.detail ? ` — ${check.detail}` : ""}`);
  }
  console.log(`policy child: ${checks.length - failures.length}/${checks.length} passed`);
  process.exit(failures.length ? 1 : 0);
}

if (manifestChild) {
  const manifest = loadManifest(root);
  const checks = [
    {
      name: "manifest classifier/mapping/evidence semantic fingerprint is exact and pinned",
      passed: manifestSemanticFingerprint(manifest) === EXPECTED_MANIFEST_SEMANTIC_FINGERPRINT,
    },
  ];
  for (const check of checks) console.log(`${check.passed ? "PASS" : "FAIL"} ${check.name}`);
  process.exit(checks.some((check) => !check.passed) ? 1 : 0);
}

const worktreeFingerprint = () => {
  const status = git(root, ["status", "--porcelain=v1", "--untracked-files=all"]);
  const diff = git(root, ["diff", "--binary", "--no-ext-diff", "HEAD", "--", "."]);
  const untrackedRaw = spawnSync("git", ["ls-files", "--others", "--exclude-standard", "-z"], {
    cwd: root, encoding: null, timeout: 30_000,
  });
  if (untrackedRaw.error || untrackedRaw.signal !== null || untrackedRaw.status !== 0) {
    throw new Error("cannot inventory untracked files");
  }
  const untracked = untrackedRaw.stdout.toString("utf8").split("\0").filter(Boolean).sort()
    .map((relative) => `${relative}\0${sha256(fs.readFileSync(path.join(root, relative)))}`).join("\n");
  return sha256(`${status}\0${diff}\0${untracked}`);
};

function headBytes(filename) {
  const relative = path.relative(root, filename).split(path.sep).join("/");
  const child = spawnSync("git", ["show", `HEAD:${relative}`], {
    cwd: root, encoding: null, timeout: 30_000, maxBuffer: 16 * 1024 * 1024,
  });
  if (child.error || child.signal !== null || child.status !== 0) {
    throw new Error(`cannot read HEAD bytes for ${relative}`);
  }
  return child.stdout;
}

function mutationTargetHeadProblems() {
  const problems = [];
  for (const filename of MUTATION_TARGET_FILES) {
    const relative = path.relative(root, filename).split(path.sep).join("/");
    try {
      const bytes = fs.readFileSync(filename);
      const equalsHead = bytes.equals(headBytes(filename));
      const reviewedUncommitted = REVIEWED_UNCOMMITTED_TARGET_SHA256.get(filename) === sha256(bytes);
      if (!equalsHead && !reviewedUncommitted) problems.push(`${relative}: differs from HEAD and reviewed candidate bytes`);
    } catch (error) {
      problems.push(`${relative}: ${error.message}`);
    }
  }
  return problems;
}

function restoreTargets(targetOriginals) {
  for (const [filename, bytes] of targetOriginals) fs.writeFileSync(filename, bytes);
}

function targetsEqual(targetOriginals) {
  return [...targetOriginals].every(([filename, bytes]) => fs.readFileSync(filename).equals(bytes));
}

function installSynchronousRestoreHandlers(targetOriginals, beforeTree) {
  const handlers = new Map();
  for (const [signal, exitCode] of [["SIGINT", 130], ["SIGTERM", 143]]) {
    const handler = () => {
      let restored = false;
      try {
        restoreTargets(targetOriginals);
        restored = targetsEqual(targetOriginals) && worktreeFingerprint() === beforeTree;
      } catch (error) {
        process.stderr.write(`FAIL interrupted restore ${signal}: ${error.message}\n`);
      }
      process.stdout.write(`${restored ? "PASS" : "FAIL"} interrupted restore ${signal}\n`);
      process.exit(restored ? exitCode : 2);
    };
    handlers.set(signal, handler);
    process.on(signal, handler);
  }
  return () => {
    for (const [signal, handler] of handlers) process.off(signal, handler);
  };
}

if (interruptRestoreArg) {
  const signal = interruptRestoreArg.slice("--interrupt-restore-child=".length);
  if (!new Set(["SIGINT", "SIGTERM"]).has(signal)) process.exit(2);
  const preflight = mutationTargetHeadProblems();
  if (preflight.length) {
    console.error(`FAIL interrupt child preflight — ${preflight.join(" | ")}`);
    process.exit(2);
  }
  const originals = new Map(MUTATION_TARGET_FILES.map((filename) => [filename, fs.readFileSync(filename)]));
  const before = worktreeFingerprint();
  installSynchronousRestoreHandlers(originals, before);
  fs.appendFileSync(libraryPath, `\n// CONTROLLED_${signal}_MUTANT\n`);
  process.kill(process.pid, signal);
  setTimeout(() => {
    restoreTargets(originals);
    console.error(`FAIL ${signal} handler was not delivered`);
    process.exit(3);
  }, 1_000);
  await new Promise(() => {});
}

const MUTANTS = [
  {
    name: "push:main is narrowed",
    file: libraryPath,
    replacements: [{
      from: `return runAll(\`push event (\${ref}) always runs the complete CI gate\`, [], {
        base_sha: event?.before || null,
        head_sha: event?.after || null,
        merge_base: null,
      });`,
      to: "return safeDocsOnly(`MUTANT narrowed push (${ref})`, []);",
    }],
    childArgs: ["--fixture-child", "--fixtures=unexpected_event_and_push_main"],
    expectedFailures: ["fixture unexpected_event_and_push_main remains RUN_ALL"],
  },
  {
    name: "mixed diff is accepted as docs-only",
    file: libraryPath,
    replacements: [{
      from: `return runAll(
        "allowlisted content classes are mixed; V1 requires CHANGELOG-only or docs-only",
        safePaths,
        gitDetails,
      );`,
      to: "return safeDocsOnly(\"MUTANT mixed accepted\", safePaths, { content_class: \"DOCS_ONLY\" });",
    }],
    childArgs: ["--fixture-child", "--fixtures=docs_changelog_mixed"],
    expectedFailures: ["fixture docs_changelog_mixed remains RUN_ALL"],
  },
  {
    name: "mandatory step receives if false",
    file: workflowPath,
    replacements: [{
      from: "      - name: Validate CI governance (trigger / reachability / anti-orphan)\n        run: node scripts/validate-ci-governance.js",
      to: "      - name: Validate CI governance (trigger / reachability / anti-orphan)\n        if: false\n        run: node scripts/validate-ci-governance.js",
    }],
    childArgs: ["--policy-child"],
    expectedFailures: ["always-run: mandatory steps are present exactly once and unconditional"],
  },
  {
    name: "mandatory step receives an empty if key",
    file: workflowPath,
    replacements: [{
      from: "      - name: Validate CI governance (trigger / reachability / anti-orphan)\n        run: node scripts/validate-ci-governance.js",
      to: "      - name: Validate CI governance (trigger / reachability / anti-orphan)\n        if:\n        run: node scripts/validate-ci-governance.js",
    }],
    childArgs: ["--policy-child"],
    expectedFailures: ["always-run: mandatory steps are present exactly once and unconditional"],
  },
  {
    name: "mandatory step becomes non-blocking",
    file: workflowPath,
    replacements: [{
      from: "      - name: Validate CI governance (trigger / reachability / anti-orphan)\n        run: node scripts/validate-ci-governance.js",
      to: "      - name: Validate CI governance (trigger / reachability / anti-orphan)\n        continue-on-error: true\n        run: node scripts/validate-ci-governance.js",
    }],
    childArgs: ["--policy-child"],
    expectedFailures: ["reachability: validate/sast jobs and every step remain blocking"],
  },
  {
    name: "a conditional third job is introduced",
    file: workflowPath,
    replacements: [{
      from: "\n  sast:\n    runs-on: ubuntu-latest",
      to: "\n  orphaned-validators:\n    if: false\n    runs-on: ubuntu-latest\n    steps:\n      - name: Mutant orphan carrier\n        run: node scripts/validate-regression-fixtures.js\n\n  sast:\n    runs-on: ubuntu-latest",
    }],
    childArgs: ["--policy-child"],
    expectedFailures: ["jobs: validate and sast jobs are unconditional"],
  },
  {
    name: "always-run step enters skip-list",
    file: manifestPath,
    replacements: [{
      from: "\"name\": \"Validate scan-quality vocabulary inventory (AST + SQL taxonomy)\"",
      to: "\"name\": \"Secret scan (tracked files)\"",
    }],
    childArgs: ["--policy-child"],
    expectedFailures: ["manifest: always-run steps cannot enter the skip-list"],
  },
  {
    name: "classifier error is accepted as safe",
    file: libraryPath,
    replacements: [{
      from: "return unknownFailClosed(`classifier error: ${error.message}`);",
      to: "return safeDocsOnly(`MUTANT error accepted: ${error.message}`, []);",
    }],
    childArgs: ["--fixture-child", "--fixtures=missing_base_object"],
    expectedFailures: ["fixture missing_base_object remains RUN_ALL"],
  },
  {
    name: "late classifier failure does not reassert RUN-ALL outputs",
    file: workflowPath,
    replacements: [{
      from: `            echo "::warning::CI scope classifier failed unexpectedly; RUN-ALL defaults remain active"
            # Reassert after any late process failure. The classifier writes its
            # safe outputs last, but this second default also closes stdout,
            # summary or future post-output failure paths.
            {
              echo "decision=UNKNOWN_FAIL_CLOSED"
              echo "effective_mode=RUN_ALL"
              echo "safe_docs_only=false"
              echo "expected_net_savings_seconds=0"
            } >> "$GITHUB_OUTPUT"`,
      to: `            echo "::warning::CI scope classifier failed unexpectedly; MUTANT leaves late outputs active"`,
    }],
    childArgs: ["--policy-child"],
    expectedFailures: ["classifier wiring: complete step is exact and fail-closed"],
  },
  {
    name: ">300 files are truncated",
    file: libraryPath,
    replacements: [{
      from: "const changes = parseNameStatus(diff);",
      to: "const changes = parseNameStatus(diff).slice(0, manifest.safe_docs.max_files);",
    }],
    childArgs: ["--fixture-child", "--fixtures=over_300_files"],
    expectedFailures: ["fixture over_300_files remains RUN_ALL"],
  },
  {
    name: "shallow and merge-base errors are treated as a safe empty diff",
    file: libraryPath,
    replacements: [{
      from: "return unknownFailClosed(`classifier error: ${error.message}`);",
      to: "if (/shallow|merge-base/.test(error.message)) return safeDocsOnly(\"MUTANT empty diff accepted\", []);\n    return unknownFailClosed(`classifier error: ${error.message}`);",
    }],
    childArgs: ["--fixture-child", "--fixtures=shallow_checkout,unresolved_merge_base"],
    expectedFailures: [
      "fixture shallow_checkout remains RUN_ALL",
      "fixture unresolved_merge_base remains RUN_ALL",
    ],
  },
  {
    name: "stale evidence is accepted as current",
    file: libraryPath,
    replacements: [{
      from: "if (evidenceMismatches.length > 0) {",
      to: "if (false && evidenceMismatches.length > 0) {",
    }],
    childArgs: ["--fixture-child", "--fixtures=stale_evidence"],
    expectedFailures: ["fixture stale_evidence remains RUN_ALL"],
  },
  {
    name: "classifier and manifest paths are accepted",
    file: libraryPath,
    replacements: [
      {
        from: "function eligibleDocsPath(relativePath, manifest) {",
        to: "function eligibleDocsPath(relativePath, manifest) {\n  if (relativePath === \"scripts/classify-ci-change.js\" || relativePath === \".github/ci-safe-docs-only-v1.json\") return true;",
      },
      {
        from: `      : safePaths.every((item) => item.startsWith("docs/"))
        ? "DOCS_ONLY"
        : null;`,
        to: `      : safePaths.every((item) => item.startsWith("docs/"))
        ? "DOCS_ONLY"
        : safePaths.every((item) => item === "scripts/classify-ci-change.js" || item === ".github/ci-safe-docs-only-v1.json") ? "DOCS_ONLY" : null;`,
      },
    ],
    childArgs: ["--fixture-child", "--fixtures=classifier_change,manifest_change"],
    expectedFailures: [
      "fixture classifier_change remains RUN_ALL",
      "fixture manifest_change remains RUN_ALL",
    ],
  },
  {
    name: "evidence scope is narrowed while its live digest is refreshed",
    file: manifestPath,
    mutate: (source) => {
      const mutatedManifest = JSON.parse(source);
      const proof = evidenceScopeFingerprint(root, ["frontend/package.json"]);
      const target = mutatedManifest.skipped_heavy_steps.find((step) => step.id === "frontend-test-coverage");
      target.evidence.scope_paths = ["frontend/package.json"];
      target.evidence.scope_sha256 = proof.sha256;
      target.evidence.scope_file_count = proof.file_count;
      return `${JSON.stringify(mutatedManifest, null, 2)}\n`;
    },
    childArgs: ["--manifest-child"],
    expectedFailures: ["manifest classifier/mapping/evidence semantic fingerprint is exact and pinned"],
  },
  {
    name: "classifier output is overridden to safe after invocation",
    file: workflowPath,
    replacements: [{
      from: "          fi\n\n      - name: Show Node version",
      to: "          fi\n          echo \"decision=SAFE_DOCS_ONLY\" >> \"$GITHUB_OUTPUT\"\n\n      - name: Show Node version",
    }],
    childArgs: ["--policy-child"],
    expectedFailures: ["classifier wiring: complete step is exact and fail-closed"],
  },
  {
    name: "ordinary non-manifest step becomes conditional",
    file: workflowPath,
    replacements: [{
      from: "      - name: Validate tenant-isolation matrix (cross-tenant read/write/delete/oracle)\n        run: node scripts/validate-tenant-isolation.js",
      to: "      - name: Validate tenant-isolation matrix (cross-tenant read/write/delete/oracle)\n        if: false\n        run: node scripts/validate-tenant-isolation.js",
    }],
    childArgs: ["--policy-child"],
    expectedFailures: ["conditions: only versioned skip-list steps may be conditional"],
  },
  {
    name: "skip-list command drifts",
    file: workflowPath,
    replacements: [{
      from: "        run: node scripts/validate-scan-quality-vocabulary-inventory.js",
      to: "        run: /usr/bin/env node scripts/validate-scan-quality-vocabulary-inventory.js",
    }],
    childArgs: ["--policy-child"],
    expectedFailures: ["wiring: every skip-list step has one exact name/command/working-directory mapping"],
  },
  {
    name: "skip-list working directory drifts",
    file: workflowPath,
    replacements: [{
      from: "      - name: Validate scan-quality vocabulary inventory (AST + SQL taxonomy)\n        if: ${{ steps.ci_scope.outputs.decision != 'SAFE_DOCS_ONLY' }}\n        run: node scripts/validate-scan-quality-vocabulary-inventory.js",
      to: "      - name: Validate scan-quality vocabulary inventory (AST + SQL taxonomy)\n        if: ${{ steps.ci_scope.outputs.decision != 'SAFE_DOCS_ONLY' }}\n        working-directory: scripts\n        run: node scripts/validate-scan-quality-vocabulary-inventory.js",
    }],
    childArgs: ["--policy-child"],
    expectedFailures: ["wiring: every skip-list step has one exact name/command/working-directory mapping"],
  },
  {
    name: "SAST step becomes conditional",
    file: workflowPath,
    replacements: [{
      from: "      - name: Set up Python\n        uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
      to: "      - name: Set up Python\n        if: false\n        uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
    }],
    childArgs: ["--policy-child"],
    expectedFailures: ["SAST: every step remains unconditional"],
  },
  {
    name: "skip-list identity drifts",
    file: manifestPath,
    replacements: [{
      from: "\"id\": \"scan-quality-vocabulary-inventory\"",
      to: "\"id\": \"scan-quality-vocabulary-inventory-mutant\"",
    }],
    childArgs: ["--policy-child"],
    expectedFailures: ["manifest: skip-list identities are exact and pinned"],
  },
  {
    name: "always-run identity drifts",
    file: manifestPath,
    replacements: [{
      from: "\"Validate CAPABILITIES.md drift\"",
      to: "\"Validate CAPABILITIES.md drift MUTANT\"",
    }],
    childArgs: ["--policy-child"],
    expectedFailures: ["manifest: always-run identities are exact and pinned"],
  },
  {
    name: "workflow contains a duplicate YAML key",
    file: workflowPath,
    replacements: [{
      from: "  validate:\n    runs-on: ubuntu-latest",
      to: "  validate:\n    runs-on: ubuntu-latest\n    runs-on: ubuntu-latest",
    }],
    childArgs: ["--policy-child"],
    expectedFailures: ["YAML AST: workflow parses uniquely with validate and sast step sequences"],
  },
  {
    name: "validator command survives only in a comment",
    file: workflowPath,
    replacements: [{
      from: "      - name: Validate scanner regression fixtures\n        run: node scripts/validate-regression-fixtures.js",
      to: "      - name: Validate scanner regression fixtures\n        run: |\n          echo validator-disabled\n          # node scripts/validate-regression-fixtures.js",
    }],
    childArgs: ["--policy-child"],
    expectedFailures: ["anti-orphan: every validator is an exact executable AST run mapping"],
  },
  {
    name: "allowed exact path overrides a denied prefix",
    file: libraryPath,
    replacements: [{
      from: `  if (deniedFiles.includes(normalized)) return false;
  if (deniedPrefixes.some((prefix) => normalized.startsWith(prefix))) return false;
  if ((manifest.safe_docs.allowed_exact_files || []).includes(normalized)) return true;`,
      to: `  if ((manifest.safe_docs.allowed_exact_files || []).includes(normalized)) return true;
  if (deniedFiles.includes(normalized)) return false;
  if (deniedPrefixes.some((prefix) => normalized.startsWith(prefix))) return false;`,
    }],
    childArgs: ["--fixture-child", "--fixtures=allow_deny_conflict"],
    expectedFailures: ["fixture allow_deny_conflict remains RUN_ALL"],
  },
  {
    name: "measurement source identity drifts",
    file: manifestPath,
    replacements: [{
      from: "\"governance_proof_source_run_id\": 30713452775",
      to: "\"governance_proof_source_run_id\": 30713452776",
    }],
    childArgs: ["--manifest-child"],
    expectedFailures: ["manifest classifier/mapping/evidence semantic fingerprint is exact and pinned"],
  },
  {
    name: "canonical skip condition drifts",
    file: workflowPath,
    replacements: [{
      from: "      - name: Validate scan-quality vocabulary inventory (AST + SQL taxonomy)\n        if: ${{ steps.ci_scope.outputs.decision != 'SAFE_DOCS_ONLY' }}",
      to: "      - name: Validate scan-quality vocabulary inventory (AST + SQL taxonomy)\n        if: false",
    }],
    childArgs: ["--policy-child"],
    expectedFailures: ["conditions: every skip-list step uses the exact canonical fail-closed expression"],
  },
];

let passed = 0;
let failed = 0;
const ok = (name, condition, detail = "") => {
  if (condition) {
    passed += 1;
    console.log(`PASS ${name}`);
  } else {
    failed += 1;
    console.log(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
};

const preflightProblems = mutationTargetHeadProblems();
ok(
  "preflight mutation targets equal HEAD bytes with no prior mutant residue",
  preflightProblems.length === 0,
  preflightProblems.join(" | "),
);
if (preflightProblems.length) {
  console.error("mutation preflight failed before any target write");
  process.exit(1);
}
const beforeTree = worktreeFingerprint();
const targetOriginals = new Map(MUTATION_TARGET_FILES
  .map((filename) => [filename, fs.readFileSync(filename)]));
const removeRestoreHandlers = installSynchronousRestoreHandlers(targetOriginals, beforeTree);

const manifest = loadManifest(root);
ok("manifest structure is valid", validateManifest(manifest).length === 0);
ok(
  "manifest classifier/mapping/evidence semantic fingerprint is exact and pinned",
  manifestSemanticFingerprint(manifest) === EXPECTED_MANIFEST_SEMANTIC_FINGERPRINT,
  manifestSemanticFingerprint(manifest),
);
const invalidManifestCases = [
  {
    name: "manifest rejects an unnormalised allowed path",
    mutate: (candidate) => candidate.safe_docs.allowed_exact_files.push("docs/../CHANGELOG.md"),
  },
  {
    name: "manifest rejects allowed/denied exact overlap",
    mutate: (candidate) => candidate.safe_docs.allowed_exact_files.push("docs/CAPABILITIES.md"),
  },
  {
    name: "manifest rejects an allowed path below a denied prefix",
    mutate: (candidate) => candidate.safe_docs.allowed_exact_files.push("docs/security/new.md"),
  },
  {
    name: "manifest rejects case-normalisation deny bypass",
    mutate: (candidate) => candidate.safe_docs.allowed_exact_files.push("docs/Security/new.md"),
  },
];
for (const definition of invalidManifestCases) {
  const candidate = structuredClone(manifest);
  definition.mutate(candidate);
  ok(definition.name, validateManifest(candidate).length > 0);
}
const evidenceMismatches = verifyEvidenceScopes(root, manifest);
console.log(evidenceMismatches.length === 0
  ? "INFO manifest evidence-scope fingerprints are current"
  : `WARN manifest evidence drift disables SAFE_DOCS_ONLY until re-proven: ${JSON.stringify(evidenceMismatches)}`);

const policyChecks = evaluateWorkflowPolicy({
  workflowSource: fs.readFileSync(workflowPath, "utf8"),
  manifest,
});
for (const check of policyChecks) ok(check.name, check.passed, check.detail);
ok("policy assertion count is pinned", policyChecks.length === EXPECTED_POLICY_ASSERTIONS, `got ${policyChecks.length}`);

for (const [signal, exitCode] of [["SIGINT", 130], ["SIGTERM", 143]]) {
  let child;
  try {
    child = spawnSync(process.execPath, [self, `--interrupt-restore-child=${signal}`], {
      cwd: root, encoding: "utf8", timeout: 30_000, maxBuffer: 16 * 1024 * 1024,
    });
  } finally {
    if (!targetsEqual(targetOriginals)) restoreTargets(targetOriginals);
  }
  const output = `${child?.stdout || ""}\n${child?.stderr || ""}`;
  ok(
    `interrupted child ${signal} restores target bytes and full worktree fingerprint`,
    !child?.error && child?.signal === null && child?.status === exitCode &&
      output.includes(`PASS interrupted restore ${signal}`) &&
      !output.includes("FAIL ") && targetsEqual(targetOriginals) &&
      worktreeFingerprint() === beforeTree,
    output.trim(),
  );
}

ok("fixture table count is pinned", FIXTURES.length === EXPECTED_FIXTURES, `got ${FIXTURES.length}`);
for (const definition of FIXTURES) {
  const child = spawnSync(process.execPath, [self, "--fixture-child", `--fixtures=${definition.name}`], {
    cwd: root, encoding: "utf8", timeout: 120_000, maxBuffer: 16 * 1024 * 1024,
  });
  const output = `${child.stdout || ""}\n${child.stderr || ""}`;
  ok(
    `fixture ${definition.name} fresh-process contract`,
    !child.error && child.signal === null && child.status === 0 && !/^(FAIL|Error|SyntaxError)/m.test(output),
    output.trim(),
  );
}

ok("mutant table count is pinned", MUTANTS.length === EXPECTED_MUTANTS, `got ${MUTANTS.length}`);
try {
  for (const mutant of MUTANTS) {
    const original = targetOriginals.get(mutant.file);
    let mutated = original.toString("utf8");
    const setupProblems = [];
    if (!targetsEqual(targetOriginals)) setupProblems.push("target bytes are not at the centralized original baseline");
    if (mutant.mutate) {
      try {
        mutated = mutant.mutate(mutated);
      } catch (error) {
        setupProblems.push(`dynamic mutation failed: ${error.message}`);
      }
    } else {
      for (const replacement of mutant.replacements) {
        const first = mutated.indexOf(replacement.from);
        if (first < 0 || mutated.indexOf(replacement.from, first + replacement.from.length) >= 0) {
          setupProblems.push("anchor missing or non-unique");
          continue;
        }
        mutated = mutated.slice(0, first) + replacement.to + mutated.slice(first + replacement.from.length);
      }
    }
    let exactKill = false;
    let detail = setupProblems.join("; ");
    try {
      if (!setupProblems.length && mutated !== original.toString("utf8")) {
        fs.writeFileSync(mutant.file, mutated);
        const child = spawnSync(process.execPath, [self, ...mutant.childArgs], {
          cwd: root, encoding: "utf8", timeout: 120_000, maxBuffer: 16 * 1024 * 1024,
        });
        const output = `${child.stdout || ""}\n${child.stderr || ""}`;
        const got = failNames(output);
        const want = [...mutant.expectedFailures].sort();
        const problems = [];
        if (child.error) problems.push(`spawn ${child.error.message}`);
        if (child.signal !== null) problems.push(`signal ${child.signal}`);
        if (child.status !== 1) problems.push(`exit ${child.status}, want 1`);
        if (/SyntaxError|ERR_MODULE_NOT_FOUND|Cannot find module|YAMLParseError/.test(output)) problems.push("syntax/load failure is not a kill");
        if (JSON.stringify(got) !== JSON.stringify(want)) problems.push(`FAIL set ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
        exactKill = problems.length === 0;
        detail = problems.length ? `${problems.join("; ")}\n${output.trim()}` : want.join(" | ");
      }
    } finally {
      restoreTargets(targetOriginals);
    }
    ok(`mutant ${mutant.name} killed only by exact target assertion`, exactKill, detail);
  }
} finally {
  restoreTargets(targetOriginals);
}

ok("all mutant target bytes are restored", [...targetOriginals].every(([filename, bytes]) => fs.readFileSync(filename).equals(bytes)));
ok("complete worktree fingerprint is restored", worktreeFingerprint() === beforeTree);
ok("assertion count is exact and pinned", passed + failed + 1 === EXPECTED_ASSERTIONS, `got ${passed + failed + 1}, want ${EXPECTED_ASSERTIONS}`);
removeRestoreHandlers();

console.log(`\nCI safe docs-only governance: ${passed}/${passed + failed} assertions passed; ${FIXTURES.length} fixtures; ${MUTANTS.length} mutants`);
if (failed > 0 || passed + failed !== EXPECTED_ASSERTIONS) process.exit(1);
