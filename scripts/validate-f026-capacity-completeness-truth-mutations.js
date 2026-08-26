#!/usr/bin/env node
//
// F-026 mutation proof. Each named mutant reintroduces one half of the two
// defects; the plain validator must fail with a NAMED assertion. Mutations run
// in-process against a temporary copy of the source, restored in finally. The
// worktree fingerprint is checked so a killed mutant can never leak edits.
// Node 24+.

import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const f = (rel) => path.join(root, rel);
function git(args) { return execFileSync("git", args, { cwd: root, encoding: "utf8" }); }
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
    id: "QUALITY_KEEPS_1000_LITERAL",
    file: "workers/scan-api/src/engines/scan-engine.js",
    from: "  const effectiveLimit = Number.isFinite(capacity?.limit) ? capacity.limit : null;",
    to:   "  const effectiveLimit = PLATFORM_SUBREQUEST_CEILING;",
    mustContain: "FAIL (b) the reported effective limit equals the resolved capacity",
  },
  {
    id: "QUALITY_GUESSES_LEGACY_EFFECTIVE_LIMIT",
    file: "workers/scan-api/src/engines/scan-engine.js",
    from: "  const effectiveLimit = Number.isFinite(capacity?.limit) ? capacity.limit : null;",
    to:   "  const effectiveLimit = 50;",
    mustContain: "FAIL (b) a different resolved capacity (120) flows through",
  },
];

let killed = 0; const failures = [];
const initial = worktreeFingerprint();
for (const m of mutants) {
  const abs = f(m.file);
  const original = fs.readFileSync(abs);
  try {
    fs.writeFileSync(abs, replaceExactly(original.toString("utf8"), m.from, m.to, m.id));
    const child = spawnSync(process.execPath, [f(LANE)], { cwd: root, encoding: "utf8", timeout: 120000 });
    const out = `${child.stdout || ""}\n${child.stderr || ""}`;
    const diedRightReason = child.status !== 0 && out.includes(m.mustContain);
    if (diedRightReason) { killed++; console.log(`PASS ${m.id}: killed by "${m.mustContain}"`); }
    else { failures.push(m.id); console.error(`FAIL ${m.id}: not killed for the named reason (status ${child.status})`); }
  } finally {
    fs.writeFileSync(abs, original);
  }
}
if (worktreeFingerprint() !== initial) { failures.push("worktree-not-restored"); console.error("FAIL worktree fingerprint changed"); }

console.log(`\nF-026 mutations: ${killed}/${mutants.length} killed`);
if (failures.length) process.exit(1);
