#!/usr/bin/env node
//
// F-026 mutation proof. Each named mutant reintroduces one half of the two
// defects; the plain validator must fail with a NAMED assertion. Mutations run
// in a disposable sandbox copy. The worktree fingerprint is checked so a killed
// mutant can never write into another owner's product path or leak edits.
// Node 24+.

import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";

const sourceRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const sandboxRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cm-f026-mutations-"));
const f = (rel) => path.join(sandboxRoot, rel);
function git(args) { return execFileSync("git", args, { cwd: sourceRoot, encoding: "utf8" }); }
function worktreeFingerprint() {
  const status = git(["status", "--porcelain=v1", "-z"]);
  return crypto.createHash("sha256").update(status).digest("hex");
}
function replaceExactly(src, from, to, id) {
  const n = src.split(from).length - 1;
  if (n !== 1) throw new Error(`${id}: anchor count ${n}, expected 1`);
  return src.replace(from, to);
}

const LANE = "scripts/validate-f026-capacity-completeness-truth.js";

function prepareSandbox() {
  fs.mkdirSync(path.join(sandboxRoot, "scripts"), { recursive: true });
  fs.mkdirSync(path.join(sandboxRoot, "workers", "scan-api"), { recursive: true });
  const workerPackage = path.join(sourceRoot, "workers", "scan-api", "package.json");
  fs.copyFileSync(workerPackage, path.join(sandboxRoot, "package.json"));
  fs.copyFileSync(workerPackage, f("workers/scan-api/package.json"));
  fs.copyFileSync(path.join(sourceRoot, LANE), f(LANE));
  fs.copyFileSync(
    path.join(sourceRoot, "workers", "scan-api", "wrangler.toml"),
    f("workers/scan-api/wrangler.toml"),
  );
  fs.cpSync(
    path.join(sourceRoot, "workers", "scan-api", "src"),
    f("workers/scan-api/src"),
    { recursive: true },
  );
  fs.cpSync(path.join(sourceRoot, "shared"), f("shared"), { recursive: true });
  const dependencies = path.join(sourceRoot, "workers", "scan-api", "node_modules");
  if (fs.existsSync(dependencies)) {
    fs.symlinkSync(dependencies, f("workers/scan-api/node_modules"), "dir");
  }
}

const mutants = [
  {
    id: "TAKEOVER_CAP_OMITS_INCOMPLETE",
    file: "workers/scan-api/src/engines/takeover-scan.js",
    from: "    if (omittedHostCount > 0) reasons.push(\"host_cap_truncation\");",
    to:   "    if (false) reasons.push(\"host_cap_truncation\");",
    mustContain: "FAIL (a) a truncated run is flagged incomplete",
  },
  {
    id: "TAKEOVER_REPORTS_ALL_CHECKED",
    file: "workers/scan-api/src/engines/takeover-scan.js",
    from: "        omitted: omittedHostCount,",
    to:   "        omitted: 0,",
    mustContain: "FAIL (a) truncation is EXPLICIT",
  },
  {
    id: "TAKEOVER_LOOKUP_FAILURE_DROPPED",
    file: "workers/scan-api/src/engines/takeover-scan.js",
    from: "    if (lookupFailedCount > 0) reasons.push(\"host_lookup_failure\");",
    to:   "    if (false) reasons.push(\"host_lookup_failure\");",
    mustContain: "FAIL (a2-all-fail) total lookup failure is incomplete",
  },
  {
    id: "TAKEOVER_TRUNCATION_ONLY_PREDICATE",
    file: "workers/scan-api/src/engines/takeover-scan.js",
    from: "      incomplete: reasons.length > 0,",
    to:   "      incomplete: omittedHostCount > 0,",
    mustContain: "FAIL (a2-all-fail) total lookup failure is incomplete",
  },
  {
    id: "TAKEOVER_REASON_OVERWRITE",
    file: "workers/scan-api/src/engines/takeover-scan.js",
    from: "    if (lookupFailedCount > 0) reasons.push(\"host_lookup_failure\");",
    to:   "    if (lookupFailedCount > 0) reasons.splice(0, reasons.length, \"host_lookup_failure\");",
    mustContain: "FAIL (a2-cap+fail) truncation AND lookup failure both appear",
  },
  {
    id: "TAKEOVER_UNCONFIRMED_DROPPED",
    file: "workers/scan-api/src/engines/takeover-scan.js",
    from: "    if (unconfirmedHostCount > 0) reasons.push(\"host_probe_unconfirmed\");",
    to:   "    if (false) reasons.push(\"host_probe_unconfirmed\");",
    mustContain: "FAIL (a3-fetch-failed) a failed probe leaves the host unmeasured",
  },
  {
    id: "TAKEOVER_UNCONFIRMED_OVERCORRECTED",
    file: "workers/scan-api/src/engines/takeover-scan.js",
    from: "    if (unconfirmedHostCount > 0) reasons.push(\"host_probe_unconfirmed\");",
    to:   "    if (unconfirmedHostCount >= 0) reasons.push(\"host_probe_unconfirmed\");",
    mustContain: "FAIL (a3-all-success) confirmed-claimed candidates leave the run COMPLETE",
  },
  {
    // R1 #2: restoring the per-CANDIDATE denominator (unconfirmed.length instead
    // of the distinct-host count) must break the two-hop / duplicate-answer
    // controls and the coverage invariant.
    id: "TAKEOVER_CANDIDATE_COUNTING_RESTORED",
    file: "workers/scan-api/src/engines/takeover-scan.js",
    from: "    ...resolveCoverage(lookup_failed_hosts.length, unconfirmed_hosts.length),",
    to:   "    ...resolveCoverage(lookup_failed_hosts.length, unconfirmed.length),",
    mustContain: "FAIL (a4-two-hop) totals.unconfirmed counts the DISTINCT host",
  },
  {
    // One host may yield many matching CNAME rows. Restoring per-candidate HTTP
    // probes must be killed by the adversarial 100 x 100 fan-out fixture.
    id: "TAKEOVER_PER_CANDIDATE_FETCH_RESTORED",
    file: "workers/scan-api/src/engines/takeover-scan.js",
    from: "  const probeHosts = [...candidatesByHost.keys()];",
    to:   "  const probeHosts = candidates.map(({ host }) => host);",
    mustContain: "FAIL (a6-boundary) exactly 100 candidates share one host probe and remain complete",
  },
  {
    id: "TAKEOVER_CANDIDATE_CAP_REMOVED",
    file: "workers/scan-api/src/engines/takeover-scan.js",
    from: "  const CANDIDATE_CAP = HOST_CAP;",
    to:   "  const CANDIDATE_CAP = Number.MAX_SAFE_INTEGER;",
    mustContain: "FAIL (a6-boundary) candidate 101 is omitted explicitly and makes coverage partial",
  },
  {
    id: "TAKEOVER_CANDIDATE_CAP_OFF_BY_ONE",
    file: "workers/scan-api/src/engines/takeover-scan.js",
    from: "          if (candidateAdmittedCount < CANDIDATE_CAP) {",
    to:   "          if (candidateAdmittedCount <= CANDIDATE_CAP) {",
    mustContain: "FAIL (a6-boundary) candidate 101 is omitted explicitly and makes coverage partial",
  },
  {
    id: "TAKEOVER_CANDIDATE_OMITTED_COUNT_ZEROED",
    file: "workers/scan-api/src/engines/takeover-scan.js",
    from: "            candidateOmittedCount += 1;",
    to:   "            candidateOmittedCount += 0;",
    mustContain: "FAIL (a6-boundary) candidate 101 is omitted explicitly and makes coverage partial",
  },
  {
    id: "TAKEOVER_CANDIDATE_TRUNCATION_REASON_SUPPRESSED",
    file: "workers/scan-api/src/engines/takeover-scan.js",
    from: "    if (candidateOmittedCount > 0) reasons.push(\"candidate_cap_truncation\");",
    to:   "    if (false) reasons.push(\"candidate_cap_truncation\");",
    mustContain: "FAIL (a6-boundary) candidate 101 is omitted explicitly and makes coverage partial",
  },
  {
    id: "TAKEOVER_TRUNCATED_HOST_OBSERVATION_BYPASSED",
    file: "workers/scan-api/src/engines/takeover-scan.js",
    from: "  if ((mod?.candidate_truncated_hosts || []).some((x) => String(x).toLowerCase() === h)) {",
    to:   "  if (false) {",
    mustContain: "FAIL (a6-observation) a truncated candidate host cannot become no-takeover-surface",
  },
  {
    // R1 #2 delta: omitting the canonical dedupe at the producer boundary (counting
    // raw input rows for requested/checked/lookup_failed) must break the canonical
    // host-identity controls — a spelling variant then inflates the denominator and
    // can evict a distinct host from the cap.
    id: "TAKEOVER_RAW_ROW_COUNTING_RESTORED",
    file: "workers/scan-api/src/engines/takeover-scan.js",
    from: "  const requestedHosts = [...new Set(subdomains.map(canonicalHost).filter(Boolean))];",
    to:   "  const requestedHosts = subdomains;",
    mustContain: "FAIL (a5-case-dot) case+trailing-dot spellings collapse to ONE canonical host",
  },
  {
    id: "TAKEOVER_ZERO_FAIL_OVERCORRECTED",
    file: "workers/scan-api/src/engines/takeover-scan.js",
    from: "    if (lookupFailedCount > 0) reasons.push(\"host_lookup_failure\");",
    to:   "    if (lookupFailedCount >= 0) reasons.push(\"host_lookup_failure\");",
    mustContain: "FAIL (a2-zero-fail) a fully-measured within-cap run stays COMPLETE",
  },
  {
    id: "QUALITY_CONFUSES_PROVIDER_WITH_EFFECTIVE",
    file: "workers/scan-api/src/engines/scan-engine.js",
    from: "  const effectiveLimit = Number.isFinite(capacity?.limit) ? capacity.limit : null;",
    to:   "  const effectiveLimit = PLATFORM_SUBREQUEST_CEILING;",
    mustContain: "FAIL (b) candidate resolves explicit legacy admission/report effective_limit 200",
  },
  {
    id: "QUALITY_GUESSES_LEGACY_EFFECTIVE_LIMIT",
    file: "workers/scan-api/src/engines/scan-engine.js",
    from: "  const effectiveLimit = Number.isFinite(capacity?.limit) ? capacity.limit : null;",
    to:   "  const effectiveLimit = 50;",
    mustContain: "FAIL (b) a different resolved capacity (120) flows through",
  },
  {
    id: "QUALITY_RESTORES_STALE_PROVIDER_1000",
    file: "workers/scan-api/src/engines/scan-engine.js",
    from: "  const PLATFORM_SUBREQUEST_CEILING = 10_000;",
    to:   "  const PLATFORM_SUBREQUEST_CEILING = 1_000;",
    mustContain: "FAIL (b) provider ceiling is reported as 10000",
  },
  {
    id: "LEGACY_ACTIVATES_RESERVED_PHYSICAL_COUNTER",
    file: "workers/scan-api/src/engines/scan-engine.js",
    from: "    const reservedMode = capacity.mode === \"reserved\";",
    to:   "    const reservedMode = capacity.mode === \"legacy\";",
    mustContain: "FAIL (b) legacy 200 is not configured as a provider-enforced physical hard cap",
  },
  {
    id: "WRANGLER_TURNS_200_INTO_PROVIDER_HARD_CAP",
    file: "workers/scan-api/wrangler.toml",
    from: "SCAN_SUBREQUEST_LIMIT = 200\n",
    to:   "SCAN_SUBREQUEST_LIMIT = 200\n\n[limits]\nsubrequests = 200\n",
    mustContain: "FAIL (b) legacy 200 is not configured as a provider-enforced physical hard cap",
  },
  {
    id: "VARIABLE_BRUTEFORCE_CAP_ESCAPES_PROVIDER",
    file: "workers/scan-api/src/engines/subdomains-scan.js",
    from: "export const BRUTEFORCE_MAX_NAMES  = 15;",
    to:   "export const BRUTEFORCE_MAX_NAMES  = 9_000;",
    mustContain: "FAIL (c) discovered and historical candidates are source-bounded before variable probes",
  },
  {
    id: "VARIABLE_EXPOSURE_CAP_ESCAPES_PROVIDER",
    file: "workers/scan-api/src/engines/asset-intel.js",
    from: "  const targets = candidates.slice(0, 50);",
    to:   "  const targets = candidates.slice(0, 500);",
    mustContain: "FAIL (c) discovered and historical candidates are source-bounded before variable probes",
  },
  {
    id: "VARIABLE_TAKEOVER_CAP_ESCAPES_PROVIDER",
    file: "workers/scan-api/src/engines/takeover-scan.js",
    from: "  const HOST_CAP = 100;",
    to:   "  const HOST_CAP = 2_000;",
    mustContain: "FAIL (c) discovered and historical candidates are source-bounded before variable probes",
  },
  {
    id: "VARIABLE_EXPOSURE_REDIRECTS_ESCAPE_PROVIDER",
    file: "workers/scan-api/src/engines/reserved-probe.js",
    from: "export const RESERVED_MAX_REDIRECT_HOPS = 3;",
    to:   "export const RESERVED_MAX_REDIRECT_HOPS = 100;",
    mustContain: "FAIL (c) exposure redirect/DNS fan-out is source-bounded",
  },
  {
    id: "VARIABLE_TAKEOVER_REDIRECTS_ESCAPE_PROVIDER",
    file: "workers/scan-api/src/lib/http.js",
    from: "const MAX_REDIRECT_HOPS = 4;",
    to:   "const MAX_REDIRECT_HOPS = 100;",
    mustContain: "FAIL (c) takeover valid-CNAME path is source-bounded",
  },
  {
    id: "ADMIN_SURFACE_REINTRODUCES_NETWORK_IO",
    file: "workers/scan-api/src/engines/asset-intel.js",
    from: "export function runAdminSurfaceModule(modules) {\n",
    to:   "export function runAdminSurfaceModule(modules) {\n  fetch(\"https://example.invalid\");\n",
    mustContain: "FAIL (c) admin_surface is derived from completed exposure evidence with zero new network I/O",
  },
];

let killed = 0; const failures = [];
const initial = worktreeFingerprint();
try {
  prepareSandbox();
  const baseline = spawnSync(process.execPath, [f(LANE)], {
    cwd: sandboxRoot,
    encoding: "utf8",
    timeout: 120000,
  });
  if (baseline.status !== 0) {
    failures.push("sandbox-baseline-red");
    console.error(`FAIL sandbox baseline red (status ${baseline.status})`);
    console.error(`${baseline.stdout || ""}${baseline.stderr || ""}`);
  }
  for (const m of mutants) {
    const abs = f(m.file);
    const original = fs.readFileSync(abs);
    try {
      fs.writeFileSync(abs, replaceExactly(original.toString("utf8"), m.from, m.to, m.id));
      const child = spawnSync(process.execPath, [f(LANE)], { cwd: sandboxRoot, encoding: "utf8", timeout: 120000 });
      const out = `${child.stdout || ""}\n${child.stderr || ""}`;
      const diedRightReason = child.status !== 0 && out.includes(m.mustContain);
      if (diedRightReason) { killed++; console.log(`PASS ${m.id}: killed by "${m.mustContain}"`); }
      else { failures.push(m.id); console.error(`FAIL ${m.id}: not killed for the named reason (status ${child.status})`); }
    } finally {
      fs.writeFileSync(abs, original);
    }
  }
} finally {
  fs.rmSync(sandboxRoot, { recursive: true, force: true });
}
if (worktreeFingerprint() !== initial) { failures.push("worktree-not-restored"); console.error("FAIL worktree fingerprint changed"); }

console.log(`\nF-026 mutations: ${killed}/${mutants.length} killed`);
if (failures.length) process.exit(1);
