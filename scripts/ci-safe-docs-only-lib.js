#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

export const DECISIONS = Object.freeze({
  RUN_ALL: "RUN_ALL",
  SAFE_DOCS_ONLY: "SAFE_DOCS_ONLY",
  UNKNOWN_FAIL_CLOSED: "UNKNOWN_FAIL_CLOSED",
});

const SHA_RE = /^[0-9a-f]{40}$/;
const SAFE_DOC_RE = /^docs\/[A-Za-z0-9][A-Za-z0-9._/-]*\.md$/;
const ALLOWED_STATUSES = new Set(["A", "M"]);
const ALLOWED_MODE = "100644";
const ALLOWED_TYPE = "blob";

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const canonicalJsonValue = (value) => {
  if (Array.isArray(value)) return value.map(canonicalJsonValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalJsonValue(value[key])]));
  }
  return value;
};
const stableJson = (value) => JSON.stringify(canonicalJsonValue(value));

function result(decision, reason, changedPaths = [], details = {}) {
  return {
    decision,
    effective_mode: decision === DECISIONS.SAFE_DOCS_ONLY
      ? DECISIONS.SAFE_DOCS_ONLY
      : DECISIONS.RUN_ALL,
    safe_docs_only: decision === DECISIONS.SAFE_DOCS_ONLY,
    reason,
    changed_paths: [...changedPaths].sort(),
    ...details,
  };
}

export const runAll = (reason, changedPaths = [], details = {}) =>
  result(DECISIONS.RUN_ALL, reason, changedPaths, details);
export const safeDocsOnly = (reason, changedPaths, details = {}) =>
  result(DECISIONS.SAFE_DOCS_ONLY, reason, changedPaths, details);
export const unknownFailClosed = (reason, changedPaths = [], details = {}) =>
  result(DECISIONS.UNKNOWN_FAIL_CLOSED, reason, changedPaths, details);

function runGit(repoRoot, args, encoding = "buffer") {
  const child = spawnSync("git", args, {
    cwd: repoRoot,
    encoding: encoding === "buffer" ? null : encoding,
    timeout: 30_000,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (child.error || child.signal !== null || child.status !== 0) {
    const stderr = Buffer.isBuffer(child.stderr)
      ? child.stderr.toString("utf8")
      : String(child.stderr || "");
    throw new Error(
      `git ${args[0]} failed (${child.signal || child.status || child.error?.message}): ${stderr.trim()}`,
    );
  }
  return child.stdout;
}

function commitExists(repoRoot, sha) {
  runGit(repoRoot, ["cat-file", "-e", `${sha}^{commit}`]);
}

function requireCompleteHistory(repoRoot, baseSha, headSha) {
  const shallow = runGit(repoRoot, ["rev-parse", "--is-shallow-repository"], "utf8").trim();
  if (shallow !== "false") throw new Error(`repository is shallow (${JSON.stringify(shallow)})`);
  const mergeBase = runGit(repoRoot, ["merge-base", baseSha, headSha], "utf8").trim();
  if (!SHA_RE.test(mergeBase)) throw new Error(`merge-base is malformed: ${JSON.stringify(mergeBase)}`);
  runGit(repoRoot, ["merge-base", "--is-ancestor", mergeBase, baseSha]);
  runGit(repoRoot, ["merge-base", "--is-ancestor", mergeBase, headSha]);
  // V1 is deliberately narrower than GitHub's general three-dot semantics: a
  // docs fast path is available only when the PR head contains the exact base
  // SHA from the event. A behind-main docs branch runs the complete gate.
  if (mergeBase !== baseSha) {
    throw new Error(`merge-base ${mergeBase} does not equal event base ${baseSha}`);
  }
  return mergeBase;
}

function parseNameStatus(buffer) {
  const fields = buffer.toString("utf8").split("\0");
  if (fields.at(-1) === "") fields.pop();
  const changes = [];
  for (let index = 0; index < fields.length;) {
    const status = fields[index++];
    if (!status) throw new Error("empty git name-status field");
    const code = status[0];
    if (code === "R" || code === "C") {
      if (index + 1 >= fields.length) throw new Error(`truncated ${status} name-status record`);
      changes.push({ status, code, old_path: fields[index++], path: fields[index++] });
    } else {
      if (index >= fields.length) throw new Error(`truncated ${status} name-status record`);
      changes.push({ status, code, path: fields[index++] });
    }
  }
  return changes;
}

function treeEntry(repoRoot, headSha, relativePath) {
  const raw = runGit(repoRoot, ["ls-tree", "-z", headSha, "--", relativePath]);
  const records = raw.toString("utf8").split("\0").filter(Boolean);
  if (records.length !== 1) throw new Error(`expected one tree entry for ${relativePath}, got ${records.length}`);
  const match = records[0].match(/^(\d{6}) ([^ ]+) ([0-9a-f]{40})\t([\s\S]+)$/);
  if (!match || match[4] !== relativePath) throw new Error(`unparseable tree entry for ${relativePath}`);
  return { mode: match[1], type: match[2], sha: match[3] };
}

function isBinaryDiff(repoRoot, baseSha, headSha, relativePath) {
  const output = runGit(
    repoRoot,
    ["diff", "--numstat", `${baseSha}...${headSha}`, "--", relativePath],
    "utf8",
  );
  const lines = output.split("\n").filter(Boolean);
  if (lines.length !== 1) throw new Error(`expected one numstat record for ${relativePath}, got ${lines.length}`);
  const fields = lines[0].split("\t");
  if (fields.length < 3) throw new Error(`unparseable numstat record for ${relativePath}`);
  return fields[0] === "-" || fields[1] === "-";
}

function normalizedRepoPath(relativePath) {
  if (typeof relativePath !== "string" || relativePath.length === 0) return null;
  if (relativePath.includes("\0") || relativePath.includes("\\")) return null;
  if (path.posix.isAbsolute(relativePath)) return null;
  const normalized = path.posix.normalize(relativePath);
  if (normalized !== relativePath || normalized === ".." || normalized.startsWith("../")) return null;
  return normalized;
}

function eligibleDocsPath(relativePath, manifest) {
  if ((manifest.safe_docs.allowed_exact_files || []).includes(relativePath)) return true;
  if (!normalizedRepoPath(relativePath) || !SAFE_DOC_RE.test(relativePath)) return false;
  if ((manifest.safe_docs.denied_files || []).includes(relativePath)) return false;
  if ((manifest.safe_docs.denied_prefixes || []).some((prefix) => relativePath.startsWith(prefix))) return false;
  return true;
}

function recursiveFiles(repoRoot, relative) {
  const normalized = normalizedRepoPath(relative);
  if (!normalized) throw new Error(`invalid evidence path: ${relative}`);
  const absolute = path.join(repoRoot, normalized);
  const stat = fs.lstatSync(absolute);
  if (stat.isSymbolicLink()) throw new Error(`evidence path is a symlink: ${relative}`);
  if (stat.isFile()) return [normalized];
  if (!stat.isDirectory()) throw new Error(`evidence path is not a regular file/directory: ${relative}`);
  const files = [];
  const visit = (directory, relDir) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const childRel = path.posix.join(relDir, entry.name);
      const childAbs = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new Error(`evidence scope contains a symlink: ${childRel}`);
      if (entry.isDirectory()) {
        if (["node_modules", "coverage", "dist", ".wrangler", "test-results"].includes(entry.name)) continue;
        visit(childAbs, childRel);
      } else if (entry.isFile()) {
        files.push(childRel);
      } else {
        throw new Error(`evidence scope contains an unexpected file type: ${childRel}`);
      }
    }
  };
  visit(absolute, normalized);
  return files;
}

export function evidenceScopeFingerprint(repoRoot, scopePaths) {
  const files = [...new Set(scopePaths.flatMap((entry) => recursiveFiles(repoRoot, entry)))].sort();
  const records = files.map((relative) => {
    const bytes = fs.readFileSync(path.join(repoRoot, relative));
    return `${relative}\0${bytes.length}\0${sha256(bytes)}`;
  });
  return {
    file_count: files.length,
    sha256: sha256(records.join("\n")),
  };
}

export function validateManifest(manifest) {
  const errors = [];
  if (!manifest || typeof manifest !== "object") return ["manifest is not an object"];
  if (manifest.schema_version !== 1) errors.push("schema_version must be 1");
  if (manifest.policy_id !== "CI-VALIDATE-DURATION-OPTIMIZATION-v1") errors.push("unexpected policy_id");
  if (!Number.isInteger(manifest.safe_docs?.max_files) || manifest.safe_docs.max_files < 1 || manifest.safe_docs.max_files > 300) {
    errors.push("safe_docs.max_files must be an integer from 1 to 300");
  }
  if (!Array.isArray(manifest.safe_docs?.allowed_exact_files) ||
      !Array.isArray(manifest.safe_docs?.denied_files) ||
      !Array.isArray(manifest.safe_docs?.denied_prefixes)) {
    errors.push("safe_docs allow/deny lists must be arrays");
  }
  if (!Array.isArray(manifest.skipped_heavy_steps) || manifest.skipped_heavy_steps.length === 0) {
    errors.push("skipped_heavy_steps must be a non-empty array");
    return errors;
  }
  const ids = new Set();
  const names = new Set();
  for (const step of manifest.skipped_heavy_steps) {
    if (!/^[a-z0-9-]+$/.test(step.id || "") || ids.has(step.id)) errors.push(`invalid/duplicate step id: ${step.id}`);
    if (typeof step.name !== "string" || !step.name || names.has(step.name)) errors.push(`invalid/duplicate step name: ${step.name}`);
    if (typeof step.command !== "string" || !step.command) errors.push(`step ${step.id} has no command`);
    if (typeof step.working_directory !== "string") errors.push(`step ${step.id} has no working_directory`);
    if (!Number.isInteger(step.measured_seconds) || step.measured_seconds < 1) errors.push(`step ${step.id} has invalid measured_seconds`);
    if (!Array.isArray(step.evidence?.scope_paths) || step.evidence.scope_paths.length === 0) errors.push(`step ${step.id} has no evidence scope`);
    if (!/^[0-9a-f]{64}$/.test(step.evidence?.scope_sha256 || "")) errors.push(`step ${step.id} has invalid evidence fingerprint`);
    if (!Number.isInteger(step.evidence?.scope_file_count) || step.evidence.scope_file_count < 1) errors.push(`step ${step.id} has invalid evidence file count`);
    if (!step.evidence?.source_graph_review || !step.evidence?.negative_without_docs || !step.evidence?.positive_workflow_baseline) {
      errors.push(`step ${step.id} is missing required evidence records`);
    }
    ids.add(step.id);
    names.add(step.name);
  }
  return errors;
}

export function verifyEvidenceScopes(repoRoot, manifest) {
  const mismatches = [];
  for (const step of manifest.skipped_heavy_steps) {
    try {
      const current = evidenceScopeFingerprint(repoRoot, step.evidence.scope_paths);
      if (current.sha256 !== step.evidence.scope_sha256 || current.file_count !== step.evidence.scope_file_count) {
        mismatches.push({ id: step.id, expected: {
          sha256: step.evidence.scope_sha256,
          file_count: step.evidence.scope_file_count,
        }, current });
      }
    } catch (error) {
      mismatches.push({ id: step.id, error: error.message });
    }
  }
  return mismatches;
}

export function loadManifest(repoRoot, manifestPath = ".github/ci-safe-docs-only-v1.json") {
  const normalized = normalizedRepoPath(manifestPath);
  if (!normalized) throw new Error(`invalid manifest path: ${manifestPath}`);
  const manifest = JSON.parse(fs.readFileSync(path.join(repoRoot, normalized), "utf8"));
  const errors = validateManifest(manifest);
  if (errors.length) throw new Error(`invalid manifest: ${errors.join("; ")}`);
  return manifest;
}

export function classifyChange({ repoRoot, eventName, event, manifest }) {
  try {
    if (eventName === "push") {
      const ref = event?.ref || "unknown ref";
      return runAll(`push event (${ref}) always runs the complete CI gate`, [], {
        base_sha: event?.before || null,
        head_sha: event?.after || null,
        merge_base: null,
      });
    }
    if (eventName !== "pull_request") {
      return runAll(`unsupported event ${JSON.stringify(eventName)}; policy is RUN-ALL`);
    }

    const baseSha = event?.pull_request?.base?.sha;
    const headSha = event?.pull_request?.head?.sha;
    if (!SHA_RE.test(baseSha || "") || !SHA_RE.test(headSha || "") || baseSha === headSha) {
      return unknownFailClosed("pull request base/head SHA is missing, malformed, or identical");
    }
    commitExists(repoRoot, baseSha);
    commitExists(repoRoot, headSha);
    const mergeBase = requireCompleteHistory(repoRoot, baseSha, headSha);
    const gitDetails = { base_sha: baseSha, head_sha: headSha, merge_base: mergeBase };

    const diff = runGit(repoRoot, [
      "diff", "--name-status", "-z", "--find-renames=1%", "--find-copies=1%",
      "--find-copies-harder",
      `${baseSha}...${headSha}`, "--",
    ]);
    const changes = parseNameStatus(diff);
    const paths = changes.flatMap((change) => change.old_path ? [change.old_path, change.path] : [change.path]);
    if (changes.length === 0) return unknownFailClosed("pull request diff is empty or could not be resolved uniquely");
    if (changes.length > manifest.safe_docs.max_files) {
      return runAll(
        `changed-file count ${changes.length} exceeds safe docs limit ${manifest.safe_docs.max_files}`,
        paths,
        gitDetails,
      );
    }

    const unsafeReasons = [];
    const safePaths = [];
    for (const change of changes) {
      if (!ALLOWED_STATUSES.has(change.code)) {
        unsafeReasons.push(`${change.status} ${change.old_path ? `${change.old_path} -> ` : ""}${change.path}`);
        continue;
      }
      if (!eligibleDocsPath(change.path, manifest)) {
        unsafeReasons.push(`non-allowlisted path ${change.path}`);
        continue;
      }
      const entry = treeEntry(repoRoot, headSha, change.path);
      if (entry.mode !== ALLOWED_MODE || entry.type !== ALLOWED_TYPE) {
        unsafeReasons.push(`unexpected git object ${entry.mode} ${entry.type} at ${change.path}`);
        continue;
      }
      if (isBinaryDiff(repoRoot, baseSha, headSha, change.path)) {
        unsafeReasons.push(`binary diff at ${change.path}`);
        continue;
      }
      safePaths.push(change.path);
    }

    if (unsafeReasons.length > 0) {
      return runAll(`diff is not the narrow safe docs class: ${unsafeReasons.join("; ")}`, paths, gitDetails);
    }
    if (safePaths.length !== changes.length) {
      return unknownFailClosed("classifier accounting mismatch", paths, gitDetails);
    }

    const contentClass = safePaths.length === 1 && safePaths[0] === "CHANGELOG.md"
      ? "CHANGELOG_ONLY"
      : safePaths.every((item) => item.startsWith("docs/"))
        ? "DOCS_ONLY"
        : null;
    if (!contentClass) {
      return runAll(
        "allowlisted content classes are mixed; V1 requires CHANGELOG-only or docs-only",
        safePaths,
        gitDetails,
      );
    }

    const evidenceMismatches = verifyEvidenceScopes(repoRoot, manifest);
    if (evidenceMismatches.length > 0) {
      return unknownFailClosed(
        `skip evidence is stale or unreadable for: ${evidenceMismatches.map((item) => item.id).join(", ")}`,
        safePaths,
        { ...gitDetails, evidence_mismatches: evidenceMismatches },
      );
    }
    return safeDocsOnly(
      contentClass === "CHANGELOG_ONLY"
        ? "the sole change is regular textual CHANGELOG.md with A/M status and current skip evidence"
        : `all ${safePaths.length} changed file(s) are regular, textual, allowlisted docs Markdown with A/M status and current skip evidence`,
      safePaths,
      { content_class: contentClass, ...gitDetails },
    );
  } catch (error) {
    return unknownFailClosed(`classifier error: ${error.message}`);
  }
}

export function decisionDetails(classification, manifest) {
  const steps = manifest.skipped_heavy_steps.map((step) => ({
    id: step.id,
    name: step.name,
    command: step.command,
    measured_seconds: step.measured_seconds,
    action: classification.safe_docs_only ? "SKIP" : "RUN",
  }));
  const grossSeconds = classification.safe_docs_only
    ? steps.reduce((total, step) => total + step.measured_seconds, 0)
    : 0;
  return {
    ...classification,
    heavy_steps: steps,
    expected_gross_savings_seconds: grossSeconds,
    expected_classifier_overhead_seconds: classification.safe_docs_only
      ? manifest.measurement.expected_classifier_overhead_seconds
      : 0,
    expected_net_savings_seconds: classification.safe_docs_only
      ? Math.max(0, grossSeconds - manifest.measurement.expected_classifier_overhead_seconds)
      : 0,
  };
}

export function markdownSummary(details) {
  const paths = details.changed_paths.length
    ? details.changed_paths.map((item) => `- \`${item}\``).join("\n")
    : "- _(none resolved)_";
  const steps = details.heavy_steps
    .map((step) => `| ${step.action} | ${step.name} | ${step.measured_seconds}s |`)
    .join("\n");
  return `## CI scope classification\n\n` +
    `- Decision: **${details.decision}**\n` +
    `- Effective mode: **${details.effective_mode}**\n` +
    `- Content class: **${details.content_class || "not safe / unresolved"}**\n` +
    `- Reason: ${details.reason}\n` +
    `- Base / head / merge-base: \`${details.base_sha || "unresolved"}\` / ` +
      `\`${details.head_sha || "unresolved"}\` / \`${details.merge_base || "unresolved"}\`\n` +
    `- Expected gross saving: **${details.expected_gross_savings_seconds}s**\n` +
    `- Expected classifier overhead: **${details.expected_classifier_overhead_seconds}s**\n` +
    `- Expected net saving: **${details.expected_net_savings_seconds}s**\n\n` +
    `### Changed paths\n\n${paths}\n\n` +
    `### Versioned heavy-step policy\n\n` +
    `| Action | Heavy step | Measured wall time |\n| --- | --- | ---: |\n${steps}\n\n` +
    `All non-manifest Validate steps remain RUN, including secret scan, CI governance, ` +
    `docs/security inventory readers, dependency audits, bundle checks and build gates. ` +
    `SAST remains an independent full job.\n`;
}

export function outputLines(details) {
  return [
    `decision=${details.decision}`,
    `effective_mode=${details.effective_mode}`,
    `safe_docs_only=${details.safe_docs_only}`,
    `content_class=${details.content_class || ""}`,
    `base_sha=${details.base_sha || ""}`,
    `head_sha=${details.head_sha || ""}`,
    `merge_base=${details.merge_base || ""}`,
    `expected_net_savings_seconds=${details.expected_net_savings_seconds}`,
    `changed_paths_json=${JSON.stringify(details.changed_paths)}`,
    `heavy_steps_json=${JSON.stringify(details.heavy_steps)}`,
    `reason_sha256=${sha256(details.reason)}`,
  ];
}

export function manifestSemanticFingerprint(manifest) {
  return sha256(stableJson({
    schema_version: manifest.schema_version,
    policy_id: manifest.policy_id,
    safe_docs: manifest.safe_docs,
    skipped_heavy_steps: manifest.skipped_heavy_steps.map((step) => ({
      id: step.id,
      name: step.name,
      command: step.command,
      working_directory: step.working_directory,
      measured_seconds: step.measured_seconds,
    })),
  }));
}
