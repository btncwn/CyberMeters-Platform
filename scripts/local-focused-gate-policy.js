#!/usr/bin/env node

import crypto from "node:crypto";
import path from "node:path";

export const LOCAL_GATE_SCHEMA_VERSION = 1;
export const MAX_FOCUSED_PATHS = 40;
export const MAX_FOCUSED_PACKS = 3;
export const MAX_GATE_MS = 300_000;

export const LOCAL_GATE_DECISIONS = Object.freeze({
  FOCUSED: "FOCUSED",
  RUN_ALL_REQUIRED: "RUN_ALL_REQUIRED",
  UNKNOWN_FAIL_CLOSED: "UNKNOWN_FAIL_CLOSED",
  FAILED: "FAILED",
});

export const LOCAL_GATE_MODES = Object.freeze({
  FOCUSED: "FOCUSED",
  RUN_ALL: "RUN_ALL",
});

const command = (id, argv, options = {}) => Object.freeze({
  id,
  argv: Object.freeze([...argv]),
  working_directory: options.workingDirectory || ".",
  timeout_ms: options.timeoutMs || 180_000,
  mutation_bearing: Boolean(options.mutationBearing),
  stdin_path: options.stdinPath || null,
  display: options.display || argv.join(" "),
});

const RUNTIME_COMMANDS = Object.freeze([
  command("runtime-scan-budget-syntax", ["node", "--check", "workers/scan-api/src/engines/scan-budget.js"]),
  command("runtime-scan-engine-syntax", ["node", "--check", "workers/scan-api/src/engines/scan-engine.js"]),
  command("runtime-scan-deadline", ["node", "scripts/validate-scan-deadline.js"]),
  command("runtime-email-deadline", ["node", "scripts/validate-email-deadline-evidence.js"], { mutationBearing: true }),
  command("runtime-phase5-evidence", ["node", "scripts/validate-phase5-evidence-honesty.js"], { mutationBearing: true }),
  command("runtime-partial-scan", ["node", "scripts/validate-partial-scan-honesty.js"]),
  command("runtime-scan-telemetry", ["node", "scripts/validate-scan-telemetry.js"]),
  command("runtime-cookie-ownership", ["node", "scripts/validate-rws5-cookie-ownership.js"]),
  command("runtime-dmarcbis-p2", ["node", "scripts/validate-dmarcbis-p2.js"]),
]);

const REPORT_CX_COMMANDS = Object.freeze([
  command("report-pdf-syntax", ["node", "--check", "workers/scan-api/src/engines/pdf.js"]),
  command(
    "report-frontend-focused-test",
    ["npm", "run", "test", "--", "src/components/__tests__/ExecutiveReportV2.report-first.test.jsx"],
    { workingDirectory: "frontend" },
  ),
  command("report-m5d-renderer", ["node", "scripts/validate-m5d-renderer-migration.js"], { mutationBearing: true }),
  command("report-eight-domain-wiring", ["node", "scripts/validate-eight-domain-wiring.js"]),
  command("report-eight-domain-parity", ["node", "scripts/validate-eight-domain-parity.js"]),
  command("report-frontend-build", ["npm", "run", "build"], { workingDirectory: "frontend", timeoutMs: 240_000 }),
]);

const CI_POLICY_COMMANDS = Object.freeze([
  command("ci-classifier-syntax", ["node", "--check", "scripts/classify-ci-change.js"]),
  command("ci-safe-docs-library-syntax", ["node", "--check", "scripts/ci-safe-docs-only-lib.js"]),
  command("ci-workflow-policy-syntax", ["node", "--check", "scripts/ci-workflow-policy.js"]),
  command("ci-install-governance", ["node", "scripts/validate-install-script-governance.js"]),
  command("ci-safe-docs-governance", ["node", "scripts/validate-ci-safe-docs-only.js"], { mutationBearing: true }),
  command("ci-governance", ["node", "scripts/validate-ci-governance.js"]),
  command("ci-local-focused-gate", ["node", "scripts/validate-local-focused-gate.js"]),
]);

const DOCS_ONLY_COMMANDS = Object.freeze([
  command("docs-safe-classifier-governance", ["node", "scripts/validate-ci-safe-docs-only.js"], { mutationBearing: true }),
]);

export const PACK_ORDER = Object.freeze([
  "runtime_evidence",
  "report_cx",
  "ci_policy",
  "docs_only",
]);

export const PACKS = Object.freeze({
  runtime_evidence: Object.freeze({ id: "runtime_evidence", commands: RUNTIME_COMMANDS }),
  report_cx: Object.freeze({ id: "report_cx", commands: REPORT_CX_COMMANDS }),
  ci_policy: Object.freeze({ id: "ci_policy", commands: CI_POLICY_COMMANDS }),
  docs_only: Object.freeze({ id: "docs_only", commands: DOCS_ONLY_COMMANDS }),
});

const PATH_PACKS = new Map([
  ["workers/scan-api/src/engines/scan-budget.js", ["runtime_evidence"]],
  ["workers/scan-api/src/engines/scan-engine.js", ["runtime_evidence"]],
  ["scripts/validate-scan-deadline.js", ["runtime_evidence"]],
  ["scripts/validate-email-deadline-evidence.js", ["runtime_evidence"]],
  ["scripts/validate-phase5-evidence-honesty.js", ["runtime_evidence"]],

  ["workers/scan-api/src/engines/pdf.js", ["report_cx"]],
  ["frontend/src/components/ExecutiveReportV2.jsx", ["report_cx"]],
  ["frontend/src/components/__tests__/ExecutiveReportV2.report-first.test.jsx", ["report_cx"]],

  [".github/workflows/ci.yml", ["ci_policy"]],
  [".github/ci-safe-docs-only-v1.json", ["ci_policy"]],
  ["scripts/classify-ci-change.js", ["ci_policy"]],
  ["scripts/ci-safe-docs-only-lib.js", ["ci_policy"]],
  ["scripts/ci-workflow-policy.js", ["ci_policy"]],
  ["scripts/validate-ci-safe-docs-only.js", ["ci_policy"]],
  ["scripts/validate-ci-governance.js", ["ci_policy"]],
  ["scripts/security/install-script-policy.json", ["ci_policy"]],
  ["scripts/validate-install-script-governance.js", ["ci_policy"]],
  ["scripts/run-local-focused-gate.js", ["ci_policy"]],
  ["scripts/local-focused-gate-policy.js", ["ci_policy"]],
  ["scripts/validate-local-focused-gate.js", ["ci_policy"]],
]);

const GOVERNANCE_PATHS = new Set([
  "AGENTS.md",
  "CLAUDE.md",
  "OPERATIONS.md",
  "docs/AI-EXECUTIVE-OPERATING-MODEL.md",
  "docs/07-RELEASE-CHECKLIST.md",
  "docs/PRE-BETA-EXECUTION-BACKLOG.md",
  "docs/ROADMAP-TO-FIRST-PAYING-CUSTOMER.md",
  "docs/CLAUDE-DESKTOP-ADVERSARIAL-REVIEW-CONTRACT.md",
]);

const PUBLIC_CLAIM_PATHS = new Set([
  "docs/CAPABILITIES.md",
  "docs/PRICING-POLICY.md",
]);

const SENSITIVE_PATH_RE = /(?:^|\/)(?:auth(?:entication)?|rbac|tenant(?:-isolation)?|billing|entitlement|stripe|secret|credential|scor(?:e|ing)|posture|business-risk|business_risk|remediation(?:-registry)?|finding-canonical|purge|retention)(?:[./_-]|$)/i;
const RELEASE_PATH_RE = /(?:^|\/)(?:deploy|release|production)(?:[./_-]|$)/i;

export function normalizeRepoPath(value) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0") || value.includes("\\")) return null;
  if (/[\u0000-\u001f\u007f]/.test(value) || path.posix.isAbsolute(value)) return null;
  const normalized = path.posix.normalize(value);
  if (normalized !== value || normalized === ".." || normalized.startsWith("../")) return null;
  return normalized;
}

export const isGovernancePath = (relative) =>
  GOVERNANCE_PATHS.has(relative) ||
  /^docs\/(?:.*\/)?[^/]*governance[^/]*(?:\/|\.md$)/i.test(relative);

export const isPublicClaimPath = (relative) =>
  PUBLIC_CLAIM_PATHS.has(relative) || /(?:^|\/)(?:pricing|capabilities)(?:[._/-]|$)/i.test(relative);

function unmappedPathReason(relative) {
  if (relative.startsWith("database/") || SENSITIVE_PATH_RE.test(relative) ||
      (relative.startsWith("scripts/ops/") && RELEASE_PATH_RE.test(relative))) {
    return `full-assurance-only sensitive path: ${relative}`;
  }
  if (relative.startsWith(".github/") || relative.startsWith("workers/") ||
      relative.startsWith("frontend/") || relative.startsWith("scripts/")) {
    return `unknown source/config path: ${relative}`;
  }
  return `unmapped path: ${relative}`;
}

function baseDecision(decision, reason, details = {}) {
  return {
    decision,
    effective_mode: decision === LOCAL_GATE_DECISIONS.FOCUSED
      ? LOCAL_GATE_MODES.FOCUSED
      : LOCAL_GATE_MODES.RUN_ALL,
    reason,
    selected_packs: [],
    commands: [],
    ownership_warning: false,
    ...details,
  };
}

function orderedCommands(packIds, paths) {
  const commands = [];
  const seen = new Set();
  for (const packId of PACK_ORDER) {
    if (!packIds.includes(packId)) continue;
    for (const item of PACKS[packId].commands) {
      if (!seen.has(item.id)) {
        seen.add(item.id);
        commands.push(item);
      }
    }
  }
  return commands;
}

export function classifyFocusedChanges({ records, inputMode, docsClassification = null }) {
  if (!Array.isArray(records) || records.length === 0) {
    return baseDecision(LOCAL_GATE_DECISIONS.UNKNOWN_FAIL_CLOSED, "changed-file inventory is empty");
  }
  if (records.length > MAX_FOCUSED_PATHS) {
    return baseDecision(
      LOCAL_GATE_DECISIONS.RUN_ALL_REQUIRED,
      `changed-file count ${records.length} exceeds focused limit ${MAX_FOCUSED_PATHS}`,
    );
  }

  const normalizedRecords = [];
  const seenPaths = new Set();
  for (const record of records) {
    const relative = normalizeRepoPath(record?.path);
    if (!relative) {
      return baseDecision(LOCAL_GATE_DECISIONS.UNKNOWN_FAIL_CLOSED, `invalid changed path ${JSON.stringify(record?.path)}`);
    }
    if (seenPaths.has(relative)) {
      return baseDecision(LOCAL_GATE_DECISIONS.UNKNOWN_FAIL_CLOSED, `duplicate changed path ${relative}`);
    }
    seenPaths.add(relative);
    normalizedRecords.push({ ...record, path: relative });
  }

  const ineligible = normalizedRecords.filter((record) =>
    !new Set(["A", "M"]).has(record.code) ||
    !new Set(["100644", "100755"]).has(record.mode) ||
    record.type !== "blob" || record.binary === true);
  if (ineligible.length) {
    const record = ineligible[0];
    return baseDecision(
      LOCAL_GATE_DECISIONS.RUN_ALL_REQUIRED,
      `ineligible Git record ${record.status || record.code} ${record.mode || "unknown-mode"} ${record.type || "unknown-type"} ${record.path}`,
    );
  }
  const invalidUtf8 = normalizedRecords.find((record) => record.valid_utf8 === false);
  if (invalidUtf8) {
    return baseDecision(LOCAL_GATE_DECISIONS.UNKNOWN_FAIL_CLOSED, `invalid UTF-8 at ${invalidUtf8.path}`);
  }

  const paths = normalizedRecords.map((record) => record.path);
  const governance = paths.find(isGovernancePath);
  if (governance) {
    return baseDecision(
      LOCAL_GATE_DECISIONS.RUN_ALL_REQUIRED,
      `canonical governance/order path requires full assurance and Governance authority: ${governance}`,
      { ownership_warning: true },
    );
  }
  const publicClaim = paths.find(isPublicClaimPath);
  if (publicClaim) {
    return baseDecision(
      LOCAL_GATE_DECISIONS.RUN_ALL_REQUIRED,
      `public capability/pricing claim requires full assurance: ${publicClaim}`,
    );
  }

  const docsLike = paths.every((relative) => relative === "CHANGELOG.md" || relative.startsWith("docs/"));
  if (docsLike) {
    if (inputMode !== "range") {
      return baseDecision(
        LOCAL_GATE_DECISIONS.RUN_ALL_REQUIRED,
        "worktree docs changes cannot synthesize the committed safe-docs evidence contract",
      );
    }
    if (docsClassification?.decision === "SAFE_DOCS_ONLY") {
      return baseDecision(
        LOCAL_GATE_DECISIONS.FOCUSED,
        "existing CI classifier proved the exact committed safe-docs class",
        { selected_packs: ["docs_only"], commands: orderedCommands(["docs_only"], paths) },
      );
    }
    if (docsClassification?.decision === "UNKNOWN_FAIL_CLOSED") {
      return baseDecision(
        LOCAL_GATE_DECISIONS.UNKNOWN_FAIL_CLOSED,
        `safe-docs classifier uncertainty: ${docsClassification.reason}`,
      );
    }
    return baseDecision(
      LOCAL_GATE_DECISIONS.RUN_ALL_REQUIRED,
      `committed docs range is outside the exact safe-docs class: ${docsClassification?.reason || "unresolved"}`,
    );
  }

  const packSet = new Set();
  for (const relative of paths) {
    const mapped = PATH_PACKS.get(relative);
    if (!mapped) {
      return baseDecision(LOCAL_GATE_DECISIONS.RUN_ALL_REQUIRED, unmappedPathReason(relative));
    }
    for (const packId of mapped) packSet.add(packId);
  }

  const selectedPacks = PACK_ORDER.filter((packId) => packSet.has(packId));
  if (selectedPacks.length > MAX_FOCUSED_PACKS) {
    return baseDecision(
      LOCAL_GATE_DECISIONS.RUN_ALL_REQUIRED,
      `selected pack count ${selectedPacks.length} exceeds focused limit ${MAX_FOCUSED_PACKS}`,
    );
  }
  const commands = orderedCommands(selectedPacks, paths);
  return baseDecision(
    LOCAL_GATE_DECISIONS.FOCUSED,
    `all ${paths.length} changed path(s) map to ${selectedPacks.length} focused pack(s)`,
    { selected_packs: selectedPacks, commands },
  );
}

const canonicalJson = (value) => {
  if (Array.isArray(value)) return value.map(canonicalJson);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalJson(value[key])]));
  }
  return value;
};

export function localFocusedGatePolicyFingerprint() {
  const semantic = {
    schema_version: LOCAL_GATE_SCHEMA_VERSION,
    max_paths: MAX_FOCUSED_PATHS,
    max_packs: MAX_FOCUSED_PACKS,
    max_gate_ms: MAX_GATE_MS,
    pack_order: PACK_ORDER,
    packs: PACKS,
    path_packs: [...PATH_PACKS].sort(([left], [right]) => left.localeCompare(right)),
    governance_paths: [...GOVERNANCE_PATHS].sort(),
    public_claim_paths: [...PUBLIC_CLAIM_PATHS].sort(),
  };
  return crypto.createHash("sha256").update(JSON.stringify(canonicalJson(semantic))).digest("hex");
}
