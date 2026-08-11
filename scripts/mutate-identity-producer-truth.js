#!/usr/bin/env node
// U2 semantic mutation harness. Each mutant changes exact production bytes,
// launches the 28-fixture validator in a fresh process, requires the exact FAIL
// set, rejects invalid kills, and restores the candidate worktree fingerprint.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const VALIDATOR = path.join(ROOT, "scripts", "validate-identity-producer-truth.js");
const TARGETS = {
  scan: path.join(ROOT, "workers/scan-api/src/engines/identity-scan.js"),
  contract: path.join(ROOT, "workers/scan-api/src/engines/identity-evidence-contract.js"),
  persistence: path.join(ROOT, "workers/scan-api/src/engines/asset-persistence.js"),
};
const digest = (value) => crypto.createHash("sha256").update(value).digest("hex");

function git(args) {
  return execFileSync("git", args, { cwd: ROOT, encoding: "utf8" });
}

function worktreeFingerprint() {
  const status = git(["status", "--porcelain=v1", "-z"]);
  const paths = status.split("\0").filter(Boolean).map((entry) => entry.slice(3)).sort();
  const hash = crypto.createHash("sha256").update(status);
  for (const relative of paths) {
    const absolute = path.join(ROOT, relative);
    hash.update(relative).update("\0");
    if (fs.existsSync(absolute) && fs.statSync(absolute).isFile()) hash.update(fs.readFileSync(absolute));
    hash.update("\0");
  }
  return hash.digest("hex");
}

function replaceExactly(source, from, to, label) {
  const count = source.split(from).length - 1;
  if (count !== 1) throw new Error(`${label}: anchor count ${count}, expected 1`);
  return source.replace(from, to);
}

function applyReplacements(source, replacements, label) {
  return replacements.reduce((value, replacement, index) =>
    replaceExactly(value, replacement.from, replacement.to, `${label}.${index + 1}`), source);
}

function failureIds(output) {
  return String(output).split(/\r?\n/)
    .filter((line) => line.startsWith("FAIL U2-"))
    .map((line) => line.split(" — ")[0].slice("FAIL ".length));
}

function runValidator(timeout = 120_000) {
  const child = spawnSync(process.execPath, [VALIDATOR], {
    cwd: ROOT,
    encoding: "utf8",
    timeout,
  });
  const output = `${child.stdout || ""}\n${child.stderr || ""}`;
  const failures = failureIds(output);
  const summary = String(child.stdout || "").match(/U2 producer truth: (\d+)\/(\d+) fixtures passed/);
  const controls = String(child.stdout || "").match(/U2 controls: (\d+)\/(\d+) passed/);
  const loaded = String(child.stdout || "").includes("LOADED identity-scan.js asset-persistence.js contract=true");
  const normal = child.error == null && child.signal == null && child.status === 1 && loaded &&
    summary != null && Number(summary[2]) === 28 && Number(summary[1]) + failures.length === 28 &&
    controls != null && Number(controls[1]) === Number(controls[2]) && Number(controls[2]) === 2;
  return { child, output, failures, normal };
}

const LEGACY_SET_HELPER = `function addHostEvidence(hostSources, hostnameValue, evidence) {
  const canonicalHostname = canonicalSignalHostname(hostnameValue);
  if (!canonicalHostname) return;
  if (![...hostSources].some((item) => item.display_hostname === canonicalHostname)) {
    hostSources.add({
      display_hostname: canonicalHostname,
      evidence: [{
        source: "unknown",
        value: canonicalHostname,
        provenance: { producer: "identity_discovery", module: "unknown", path: null },
        nameResolution: "not_evaluated",
        validationState: "observed",
        dedupeKey: canonicalHostname,
      }],
    });
  }
}`;

const MUTANTS = [
  {
    id: "U2-M01", target: "scan", expected: ["U2-B2-N01"], controls: ["U2-B2-P01", "U2-POS-01"], fresh_process: true,
    replacements: [{ from: "/(^|\\.)(adfs|sts)\\./", to: "/adfs\\.|sts\\./" }],
  },
  {
    id: "U2-M02", target: "scan", expected: ["U2-B2-N02"], controls: ["U2-B2-P01"], fresh_process: true,
    replacements: [{
      from: "    && !/(^|\\.)(windows\\.net|microsoftonline\\.com)$/.test(hostname);",
      to: ";",
    }],
  },
  {
    id: "U2-M03", target: "scan", expected: ["U2-B2-P01"], controls: ["U2-B2-N01"], fresh_process: true,
    replacements: [{
      from: '  return String(value ?? "").trim().toLowerCase().replace(/\\.$/, "");',
      to: '  return String(value ?? "").trim().replace(/\\.$/, "");',
    }],
  },
  {
    id: "U2-M04", target: "scan", expected: ["U2-B2-P01"], controls: ["U2-B2-N01"], fresh_process: true,
    replacements: [{
      from: '  return String(value ?? "").trim().toLowerCase().replace(/\\.$/, "");',
      to: '  return String(value ?? "").trim().toLowerCase();',
    }],
  },
  {
    id: "U2-M05", target: "scan", expected: ["U2-E01", "U2-E02", "U2-B2-MX01"], controls: ["U2-B2-MX02"], fresh_process: true,
    replacements: [{
      from: "mx?.value ?? mx?.hostname ?? mx?.exchange",
      to: "mx?.hostname ?? mx?.exchange",
    }],
  },
  {
    id: "U2-M06", target: "scan", expected: ["U2-E01", "U2-B2-P01", "U2-B2-W01", "U2-B2-W02"], controls: ["U2-POS-01", "U2-POS-02"], fresh_process: true,
    replacements: [{ from: "matchPrecision: s.match_precision,", to: 'matchPrecision: "unknown",' }],
  },
  {
    id: "U2-M07", target: "scan", expected: ["U2-B2-W01", "U2-B2-W02"], controls: ["U2-B2-P01"], fresh_process: true,
    replacements: [{
      from: 'const DISCLOSED_WEAK_TOKEN_PRECISION = "token_substring";',
      to: 'const DISCLOSED_WEAK_TOKEN_PRECISION = "label_boundary";',
    }],
  },
  {
    id: "U2-M08", target: "scan", expected: ["U2-E01"], controls: ["U2-B2-P01", "U2-B2-W01"], fresh_process: true,
    replacements: [{
      from: "matchPrecision: s.match_precision,",
      to: 'matchPrecision: matched.length === 0 ? s.match_precision : "unknown",',
    }],
  },
  {
    id: "U2-M09", target: "scan", expected: [
      "U2-B3-CT01", "U2-B3-DNS01", "U2-B3-BOTH01", "U2-B3-MX01",
      "U2-B3-EMPTY01", "U2-B3-FAIL01", "U2-B3-DEAD01", "U2-B3-NOREACH01",
    ], controls: ["U2-POS-02"], fresh_process: true,
    replacements: [
      { from: "const hostSources = new Map();", to: "const hostSources = new Set();" },
      {
        from: `function addHostEvidence(hostSources, hostnameValue, evidence) {
  const canonicalHostname = canonicalSignalHostname(hostnameValue);
  if (!canonicalHostname) return;
  const current = hostSources.get(canonicalHostname) ?? {
    display_hostname: String(hostnameValue).trim().replace(/\\.$/, ""),
    evidence: [],
  };
  const dedupeKey = [
    evidence.source,
    evidence.provenance.module,
    evidence.provenance.path,
    String(evidence.value ?? ""),
    evidence.nameResolution,
  ].join("\\u0000");
  if (!current.evidence.some((item) => item.dedupeKey === dedupeKey)) {
    current.evidence.push({ ...evidence, dedupeKey });
  }
  hostSources.set(canonicalHostname, current);
}`,
        to: LEGACY_SET_HELPER,
      },
    ],
  },
  {
    id: "U2-M10", target: "scan", expected: ["U2-B3-EMPTY01"], controls: ["U2-B3-CT01", "U2-B3-DNS01"], fresh_process: true,
    replacements: [{
      from: 'source: mailOnly ? "dns_mx" : "dns_bruteforce",',
      to: 'source: mailOnly ? "dns_mx" : addresses.length > 0 ? "dns_bruteforce" : "certificate_transparency",',
    }],
  },
  {
    id: "U2-M11", target: "scan", expected: ["U2-B3-FAIL01", "U2-B3-DEAD01"], controls: ["U2-B3-DNS01"], fresh_process: true,
    replacements: [{
      from: "const dnsEvidencePublishable = dnsBruteforceEvidenceIsPublishable(modules?.dns_bruteforce);",
      to: "const dnsEvidencePublishable = true;",
    }],
  },
  {
    id: "U2-M12", target: "contract", expected: ["U2-B3-CT01", "U2-B3-FAIL01", "U2-B3-ABS01"], controls: ["U2-B3-DNS01", "U2-B3-MX01"], fresh_process: true,
    replacements: [{ from: '  let status = "not_evaluated";', to: '  let status = ["not", "resolved"].join("_");' }],
  },
  {
    id: "U2-M13", target: "scan", expected: ["U2-B3-TIME01", "U2-B3-TIME02"], controls: ["U2-POS-01"], fresh_process: true,
    replacements: [{
      from: "const evidenceObservedAt = normalizeIdentityObservedAt(observedAt);",
      to: "const evidenceObservedAt = new Date().toISOString();",
    }],
  },
  {
    id: "U2-M14", target: "contract", expected: ["U2-B3-CT01", "U2-B3-TIME01"], controls: ["U2-B3-DNS01", "U2-B3-MX01"], fresh_process: true,
    replacements: [{
      from: `    measured_at: status === "resolved" || status === "mx_only"
      ? supporting.map((item) => normalizeIdentityObservedAt(item.observed_at)).find(Boolean) ?? null
      : null,`,
      to: `    measured_at: status === "resolved" || status === "mx_only"
      ? supporting.map((item) => normalizeIdentityObservedAt(item.observed_at)).find(Boolean) ?? null
      : valid.map((item) => normalizeIdentityObservedAt(item.observed_at)).find(Boolean) ?? null,`,
    }],
  },
  {
    id: "U2-M15", target: "persistence", expected: ["U2-E02", "U2-E08"], controls: ["U2-POS-01"], fresh_process: true,
    replacements: [{
      from: "serializeIdentityEvidence(asset.evidence)",
      to: "JSON.stringify(asset.evidence ?? [])",
    }],
  },
  {
    id: "U2-M16", target: "contract", expected: ["U2-E04", "U2-E05"], controls: ["U2-E06"], fresh_process: true,
    replacements: [
      {
        from: '        status: "malformed", items: [], valid_v2_count: 0, legacy_count: 0, malformed_count: 1,',
        to: '        status: "empty", items: [], valid_v2_count: 0, legacy_count: 0, malformed_count: 0,',
      },
      {
        from: "  const status = populatedKinds > 1",
        to: '  const status = malformedCount > 0 ? "empty" : populatedKinds > 1',
      },
    ],
  },
  {
    id: "U2-M17", target: "scan", expected: ["U2-E07"], controls: ["U2-POS-01"], fresh_process: true,
    replacements: [{ from: "confidence:         90,", to: "confidence:         confidenceDetail," }],
  },
  {
    id: "U2-M18", target: "contract", expected: ["U2-B3-DNS01", "U2-B3-NOREACH01"], controls: ["U2-B3-CT01"], fresh_process: true,
    replacements: [{
      from: '      status: "not_evaluated",',
      to: '      status: resolution.status === "resolved" ? "reachable" : "not_evaluated",',
    }],
  },
];

let failures = 0;
let killed = 0;
const initialFingerprint = worktreeFingerprint();
for (const mutant of MUTANTS) {
  const target = TARGETS[mutant.target];
  const original = fs.readFileSync(target);
  const originalHash = digest(original);
  try {
    const mutated = applyReplacements(original.toString("utf8"), mutant.replacements, mutant.id);
    if (mutated === original.toString("utf8")) throw new Error("mutation changed no bytes");
    fs.writeFileSync(target, mutated);
    const result = runValidator();
    const exact = JSON.stringify(result.failures) === JSON.stringify(mutant.expected);
    if (result.normal && exact) {
      killed += 1;
      console.log(`PASS ${mutant.id} exact FAIL set ${JSON.stringify(result.failures)} controls=${JSON.stringify(mutant.controls)} fresh=${mutant.fresh_process}`);
    } else {
      failures += 1;
      console.error(`FAIL ${mutant.id} expected=${JSON.stringify(mutant.expected)} actual=${JSON.stringify(result.failures)} normal=${result.normal} status=${result.child.status} signal=${result.child.signal} error=${result.child.error?.message || "none"}\n${result.output}`);
    }
  } catch (error) {
    failures += 1;
    console.error(`FAIL ${mutant.id} — ${error?.message ?? error}`);
  } finally {
    fs.writeFileSync(target, original);
    if (digest(fs.readFileSync(target)) !== originalHash) {
      failures += 1;
      console.error(`FAIL ${mutant.id} target bytes not restored`);
    }
    if (worktreeFingerprint() !== initialFingerprint) {
      failures += 1;
      console.error(`FAIL ${mutant.id} worktree fingerprint not restored`);
    }
  }
}

let invalidKillControls = 0;
function control(name, condition) {
  if (condition) {
    invalidKillControls += 1;
    console.log(`PASS ${name}`);
  } else {
    failures += 1;
    console.error(`FAIL ${name}`);
  }
}

{
  const target = TARGETS.scan;
  const original = fs.readFileSync(target);
  try {
    fs.writeFileSync(target, `${original.toString("utf8")}\nthis is invalid syntax !\n`);
    const result = runValidator();
    control("SYNTAX_FAILURE_REJECTED", !result.normal && result.failures.length === 0);
  } finally { fs.writeFileSync(target, original); }
}

{
  const target = TARGETS.scan;
  const original = fs.readFileSync(target);
  try {
    fs.writeFileSync(target, replaceExactly(original.toString("utf8"),
      'from "./identity-evidence-contract.js";', 'from "./missing-identity-evidence-contract.js";', "load control"));
    const result = runValidator();
    control("LOAD_FAILURE_REJECTED", !result.normal && result.failures.length === 0);
  } finally { fs.writeFileSync(target, original); }
}

{
  const result = runValidator(1);
  control("TIMEOUT_REJECTED", !result.normal && result.child.error?.code === "ETIMEDOUT");
}

{
  const target = TARGETS.scan;
  const original = fs.readFileSync(target);
  try {
    fs.writeFileSync(target, replaceExactly(original.toString("utf8"),
      "confidence:         60,", "confidence:         61,", "wrong-reason control"));
    const result = runValidator();
    control("WRONG_REASON_REJECTED", result.normal && result.failures.length > 0 &&
      JSON.stringify(result.failures) !== JSON.stringify(MUTANTS[0].expected));
  } finally { fs.writeFileSync(target, original); }
}

control("WRONG_ORDER_REJECTED",
  JSON.stringify([...MUTANTS[4].expected].reverse()) !== JSON.stringify(MUTANTS[4].expected));

if (worktreeFingerprint() !== initialFingerprint) {
  failures += 1;
  console.error("FAIL final worktree fingerprint drift");
}
console.log(`U2 mutations: ${killed}/${MUTANTS.length} semantic mutants killed; ${invalidKillControls}/5 invalid-kill controls rejected`);
if (failures || killed !== MUTANTS.length || invalidKillControls !== 5) process.exit(1);
