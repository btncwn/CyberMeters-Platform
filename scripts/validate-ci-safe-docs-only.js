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
const EXPECTED_FIXTURES = 27;
const EXPECTED_MUTANTS = 12;
const EXPECTED_POLICY_ASSERTIONS = 11;
const EXPECTED_ASSERTIONS = 59;
const EXPECTED_MANIFEST_SEMANTIC_FINGERPRINT = "1765b841e2c14e9e86612108c6bff5443aa01ab1619c6b08b509f54194afd24b";

const fixtureChild = process.argv.includes("--fixture-child");
const policyChild = process.argv.includes("--policy-child");
const manifestChild = process.argv.includes("--manifest-child");
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
  { name: "workflow_only", safe: false },
  { name: "scripts_only", safe: false },
  { name: "classifier_change", safe: false },
  { name: "manifest_change", safe: false },
  { name: "over_300_files", safe: false },
  { name: "malformed_base", safe: false },
  { name: "missing_base_object", safe: false },
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
    head = base;
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
    {
      name: "manifest evidence-scope fingerprints are current",
      passed: verifyEvidenceScopes(root, manifest).length === 0,
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
    expectedFailures: ["classifier wiring: id/output defaults/process invocation are fail-closed"],
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
    replacements: [{
      from: `        "scope_paths": [
          "frontend"
        ],
        "scope_sha256": "1659841f45a0289082dfcd29aac995a5f56a5cb1d9a7e04b1a3ef52e97a5857e",
        "scope_file_count": 228,`,
      to: `        "scope_paths": [
          "frontend/package.json"
        ],
        "scope_sha256": "ff494662369ed2a6d22b0b493b0ba53ba0137478b200c807c5b71f27bafe6044",
        "scope_file_count": 1,`,
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

const manifest = loadManifest(root);
ok("manifest structure is valid", validateManifest(manifest).length === 0);
ok(
  "manifest classifier/mapping/evidence semantic fingerprint is exact and pinned",
  manifestSemanticFingerprint(manifest) === EXPECTED_MANIFEST_SEMANTIC_FINGERPRINT,
  manifestSemanticFingerprint(manifest),
);
const evidenceMismatches = verifyEvidenceScopes(root, manifest);
ok("manifest evidence-scope fingerprints are current", evidenceMismatches.length === 0, JSON.stringify(evidenceMismatches));

const policyChecks = evaluateWorkflowPolicy({
  workflowSource: fs.readFileSync(workflowPath, "utf8"),
  manifest,
});
for (const check of policyChecks) ok(check.name, check.passed, check.detail);
ok("policy assertion count is pinned", policyChecks.length === EXPECTED_POLICY_ASSERTIONS, `got ${policyChecks.length}`);

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
const beforeTree = worktreeFingerprint();
const targetOriginals = new Map([...new Set(MUTANTS.map((mutant) => mutant.file))]
  .map((filename) => [filename, fs.readFileSync(filename)]));

for (const mutant of MUTANTS) {
  const original = targetOriginals.get(mutant.file);
  let mutated = original.toString("utf8");
  const setupProblems = [];
  for (const replacement of mutant.replacements) {
    const first = mutated.indexOf(replacement.from);
    if (first < 0 || mutated.indexOf(replacement.from, first + replacement.from.length) >= 0) {
      setupProblems.push("anchor missing or non-unique");
      continue;
    }
    mutated = mutated.slice(0, first) + replacement.to + mutated.slice(first + replacement.from.length);
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
    fs.writeFileSync(mutant.file, original);
  }
  ok(`mutant ${mutant.name} killed only by exact target assertion`, exactKill, detail);
}

ok("all mutant target bytes are restored", [...targetOriginals].every(([filename, bytes]) => fs.readFileSync(filename).equals(bytes)));
ok("complete worktree fingerprint is restored", worktreeFingerprint() === beforeTree);
ok("assertion count is exact and pinned", passed + failed + 1 === EXPECTED_ASSERTIONS, `got ${passed + failed + 1}, want ${EXPECTED_ASSERTIONS}`);

console.log(`\nCI safe docs-only governance: ${passed}/${passed + failed} assertions passed; ${FIXTURES.length} fixtures; ${MUTANTS.length} mutants`);
if (failed > 0 || passed + failed !== EXPECTED_ASSERTIONS) process.exit(1);
