#!/usr/bin/env node
// Offline negative contracts and real-source guard mutants. A mutant is killed
// only by an assertion FAIL in a fresh process, never by an import/tool error.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { evaluateAuditExceptions, collectAuditInputs } from "./validate-audit-exceptions.js";

const self = fileURLToPath(import.meta.url);
const root = path.resolve(path.dirname(self), "..");
const validator = path.join(root, "scripts/validate-audit-exceptions.js");
const NOW = "2026-10-04T12:00:00Z";
const clone = (x) => structuredClone(x);
const OWNER = "CyberMeters engineering (founder-owned)";
const ID = "GHSA-vfj7-8cjw-p6xm";
const OTHER = "GHSA-aaaa-bbbb-cccc";

const advisory = (name, id = ID, range = "<=3.0.3", severity = "high") =>
  ({ name, dependency: name, url: `https://github.com/advisories/${id}`, range, severity });
const finding = (name, via, severity = "high") =>
  ({ name, severity, nodes: [`node_modules/${name}`], via });
const tool = (doc, status = 1) => ({ status, signal: null, error: null, stdout: JSON.stringify(doc) });
function auditTool(vulnerabilities) {
  const counts = Object.fromEntries(["info", "low", "moderate", "high", "critical"].map((s) =>
    [s, Object.values(vulnerabilities).filter((v) => v.severity === s).length]));
  counts.total = Object.keys(vulnerabilities).length;
  return tool({ auditReportVersion: 2, vulnerabilities, metadata: { vulnerabilities: counts } }, counts.total ? 1 : 0);
}
function baseline() {
  return {
    workspace: "frontend", now: NOW, owners: [OWNER],
    auditResult: auditTool({ braces: finding("braces", [advisory("braces")]),
      tailwindcss: finding("tailwindcss", ["braces"]),
      vitest: finding("vitest", [advisory("vitest", OTHER, "<4", "moderate")], "moderate") }),
    register: { schema: "cybermeters.audit-exception-register/v1", reviewed_on: "2026-10-03", exceptions: [{
      id: "E-1", workspace: "frontend", package: "braces",
      advisories: [{ id: ID, range: "<=3.0.3" }], lock_paths: ["node_modules/braces"],
      reachability: "dev_only", production_closure_evidence: "npm ls --omit=dev braces",
      reason: "Time-limited acceptance for the development toolchain; no patched braces release.",
      removal_criterion: "Install a fixed braces version or migrate Tailwind and remove this record.",
      owner: OWNER, introduced_on: "2026-10-03", reviewed_on: "2026-10-03", review_by: "2027-01-01",
      record: "docs/AUDIT-EXCEPTIONS.md#e-1",
    }] },
    lock: { lockfileVersion: 3, packages: {
      "": { name: "cybermeters-frontend", version: "1.0.0" },
      "node_modules/braces": { version: "3.0.3", dev: true },
      "node_modules/tailwindcss": { version: "3.4.4", dev: true },
      "node_modules/vitest": { version: "3.2.7", dev: true },
    } },
    productionResults: { braces: tool({ name: "cybermeters-frontend", version: "1.0.0" }) },
  };
}
const entry = (x) => x.register.exceptions[0];
function editAudit(x, fn) {
  const doc = JSON.parse(x.auditResult.stdout);
  fn(doc.vulnerabilities);
  x.auditResult = auditTool(doc.vulnerabilities);
}
function addUnaccepted(x, severity) {
  x.lock.packages["node_modules/new-risk"] = { version: "1.0.0", dev: true };
  editAudit(x, (v) => { v["new-risk"] = finding("new-risk", [advisory("new-risk", OTHER, "<2", severity)], severity); });
}

const CASES = [];
function test(name, guard, change = () => {}) {
  const input = baseline(); change(input);
  CASES.push({ name, expected: guard ? [guard] : [], input });
}
test("accepted direct and transitive high plus unrelated moderate", null);
test("UTC deadline remains valid through the last second", null, (x) => { x.now = "2027-01-01T23:59:59Z"; });
test("no records needed for moderate-only audit", null, (x) => {
  x.register.exceptions = []; editAudit(x, (v) => { delete v.braces; delete v.tailwindcss; });
});
test("clean audit with empty register", null, (x) => { x.register.exceptions = []; x.auditResult = auditTool({}); });
test("moderate advisory URL need not be a registered GHSA", null, (x) => {
  editAudit(x, (v) => { v.vitest.via[0].url = "https://example.invalid/advisory"; });
});
test("tool-status", "audit-tool", (x) => { x.auditResult.status = 2; });
test("tool-spawn-error", "audit-tool", (x) => { x.auditResult.error = "ENOENT"; });
test("tool-signal", "audit-tool", (x) => { x.auditResult.signal = "SIGTERM"; });
test("invalid-json", "audit-schema", (x) => { x.auditResult.stdout = "not JSON"; });
test("audit-version", "audit-schema", (x) => {
  const d = JSON.parse(x.auditResult.stdout); d.auditReportVersion = 1; x.auditResult = tool(d);
});
test("npm-error-object", "audit-schema", (x) => {
  const d = JSON.parse(x.auditResult.stdout); d.error = { code: "ENETUNREACH" }; x.auditResult = tool(d);
});
test("counts-drift", "audit-counts", (x) => {
  const d = JSON.parse(x.auditResult.stdout); d.metadata.vulnerabilities.total++; x.auditResult = tool(d);
});
test("empty-report-nonzero-exit", "audit-counts", (x) => { x.auditResult = auditTool({}); x.auditResult.status = 1; });
test("lock-version", "lock-schema", (x) => { x.lock.lockfileVersion = 2; });
test("finding-name", "audit-findings", (x) => { editAudit(x, (v) => { v.braces.name = "wrong"; }); });
test("missing-locked-audit-node", "audit-findings", (x) => { delete x.lock.packages["node_modules/tailwindcss"]; });
test("empty-via", "audit-findings", (x) => { editAudit(x, (v) => { v.tailwindcss.via = []; }); });
test("unknown-via-reference", "audit-findings", (x) => { editAudit(x, (v) => { v.tailwindcss.via.push("missing"); }); });
test("advisory-package-alias", "audit-findings", (x) => { editAudit(x, (v) => { v.braces.via[0].dependency = "other"; }); });
test("advisory-severity-underreported", "audit-findings", (x) => { editAudit(x, (v) => { v.braces.severity = "moderate"; }); });
test("register-version", "register-schema", (x) => { x.register.schema = "unknown/v1"; });
test("record-unknown-field", "record-shape", (x) => { entry(x).ignore = true; });
test("record-missing-field", "record-shape", (x) => { delete entry(x).review_by; });
test("duplicate-record", "record-identity", (x) => { x.register.exceptions.push(clone(entry(x))); });
test("duplicate-advisory", "record-identity", (x) => { entry(x).advisories.push(clone(entry(x).advisories[0])); });
test("wrong-workspace", "workspace", (x) => { entry(x).workspace = "workers/scan-api"; });
test("wrong-invocation-workspace", "workspace", (x) => { x.workspace = "workers/scan-api"; });
test("off-vocabulary-owner", "owner", (x) => { entry(x).owner = "unapproved"; });
test("expired", "dates", (x) => { x.now = "2027-01-02T00:00:00Z"; });
test("invalid-calendar-date", "dates", (x) => { entry(x).review_by = "2026-11-31"; });
test("review-window-too-long", "dates", (x) => { entry(x).review_by = "2027-01-02"; });
test("future-review", "dates", (x) => { entry(x).reviewed_on = "2026-10-05"; });
test("missing-reason", "record-purpose", (x) => { entry(x).reason = ""; });
test("false-reachability", "record-purpose", (x) => { entry(x).reachability = "production_runtime"; });
test("false-evidence-command", "record-purpose", (x) => { entry(x).production_closure_evidence = "not measured"; });
test("wrong-doc-anchor", "record-purpose", (x) => { entry(x).record = "docs/AUDIT-EXCEPTIONS.md#e-2"; });
test("production-lock-flag", "lock-binding", (x) => { x.lock.packages["node_modules/braces"].dev = false; });
test("omitted-nested-path", "lock-binding", (x) => { x.lock.packages["node_modules/tool/node_modules/braces"] = { version: "3.0.3", dev: true }; });
test("production-package-present", "production-closure", (x) => {
  x.productionResults.braces = tool({ name: "cybermeters-frontend", version: "1.0.0", dependencies: { braces: { version: "3.0.3" } } }, 0);
});
test("closure-tool-error", "production-closure", (x) => { x.productionResults.braces.error = "spawn failure"; });
test("closure-invalid-json", "production-closure", (x) => { x.productionResults.braces.stdout = "not JSON"; });
test("closure-problems", "production-closure", (x) => {
  x.productionResults.braces = tool({ name: "cybermeters-frontend", version: "1.0.0", problems: ["invalid dependency"] });
});
test("closure-wrong-root", "production-closure", (x) => { x.productionResults.braces = tool({ name: "wrong", version: "1.0.0" }); });
test("stale-record", "no-stale-record", (x) => { editAudit(x, (v) => { delete v.braces; delete v.tailwindcss; }); });
test("GHSA-drift", "no-stale-record", (x) => { editAudit(x, (v) => { v.braces.via[0].url = `https://github.com/advisories/${OTHER}`; }); });
test("range-drift", "no-stale-record", (x) => { editAudit(x, (v) => { v.braces.via[0].range = "<=3.0.4"; }); });
test("exception-package-drift", "no-stale-record", (x) => {
  entry(x).package = "other"; entry(x).lock_paths = ["node_modules/other"];
  entry(x).production_closure_evidence = "npm ls --omit=dev other";
  x.lock.packages["node_modules/other"] = { version: "1.0.0", dev: true };
  x.productionResults.other = clone(x.productionResults.braces);
});
test("additional-high", "high-critical-coverage", (x) => { addUnaccepted(x, "high"); });
test("additional-critical", "high-critical-coverage", (x) => { addUnaccepted(x, "critical"); });
test("mixed-via", "high-critical-coverage", (x) => { editAudit(x, (v) => { v.tailwindcss.via.push("vitest"); }); });
test("cycle-via", "high-critical-coverage", (x) => { editAudit(x, (v) => { v.tailwindcss.via.push("tailwindcss"); }); });

function assertCase(evaluator, c) {
  const actual = evaluator(c.input).filter((r) => !r.passed).map((r) => r.name);
  if (JSON.stringify(actual) !== JSON.stringify(c.expected)) {
    console.error(`FAIL ASSERTION ${c.name}: expected ${JSON.stringify(c.expected)}, got ${JSON.stringify(actual)}`);
    return false;
  }
  return true;
}
function assertCommandContract(collector) {
  const calls = [];
  collector(root, (command, args, options) => { calls.push({ command, args, cwd: options.cwd }); return tool({}); });
  const expected = [
    { command: "npm", args: ["audit", "--json", "--include=dev", "--include=optional", "--include=peer"], cwd: path.join(root, "frontend") },
    { command: "npm", args: ["ls", "--omit=dev", "--json", "braces"], cwd: path.join(root, "frontend") },
  ];
  if (JSON.stringify(calls) !== JSON.stringify(expected)) {
    console.error(`FAIL ASSERTION command-contract: expected ${JSON.stringify(expected)}, got ${JSON.stringify(calls)}`);
    return false;
  }
  return true;
}

if (process.argv[2] === "--assert-case") {
  try {
    const mod = await import(pathToFileURL(process.argv[3]).href);
    const name = process.argv[4];
    const passed = name === "command-contract" ? assertCommandContract(mod.collectAuditInputs)
      : assertCase(mod.evaluateAuditExceptions, CASES.find((c) => c.name === name));
    process.exitCode = passed ? 0 : 1;
  } catch (error) { console.error(`ERROR INSTRUMENT ${error.stack}`); process.exitCode = 2; }
} else {
  let passed = 0, failed = 0;
  const ok = (name, condition) => {
    console.log(`${condition ? "PASS" : "FAIL"} ${name}`);
    condition ? passed++ : failed++;
  };
  for (const c of CASES) ok(`fixture ${c.name}`, assertCase(evaluateAuditExceptions, c));
  ok("full-graph command contract", assertCommandContract(collectAuditInputs));

  const source = fs.readFileSync(validator, "utf8");
  const pairs = {
    "audit-tool": "tool-status", "audit-schema": "audit-version", "audit-counts": "counts-drift",
    "lock-schema": "lock-version", "audit-findings": "finding-name", "register-schema": "register-version",
    "record-shape": "record-unknown-field", "record-identity": "duplicate-record", workspace: "wrong-workspace",
    owner: "off-vocabulary-owner", dates: "expired", "record-purpose": "missing-reason",
    "lock-binding": "production-lock-flag", "production-closure": "production-package-present",
    "no-stale-record": "stale-record", "high-critical-coverage": "additional-high",
  };
  const guards = [...source.matchAll(/\bcheck\("([a-z-]+)",/g)].map((m) => m[1]);
  ok("every real guard has exactly one declared paired mutant",
    guards.length === new Set(guards).size && JSON.stringify([...guards].sort()) === JSON.stringify(Object.keys(pairs).sort()));
  const mutants = Object.entries(pairs).map(([guard, fixture]) => ({
    name: `guard:${guard}`, fixture, from: `check("${guard}",`, to: `check("${guard}", true ||`,
  }));
  mutants.push(
    { name: "identity:GHSA", fixture: "GHSA-drift", from: "advisory.id === advisoryId(via)", to: "true" },
    { name: "identity:range", fixture: "range-drift", from: "advisory.range === via.range", to: "true" },
    { name: "identity:package", fixture: "exception-package-drift", from: "entry.package === name", to: "true" },
    { name: "via:all-branches", fixture: "mixed-via", from: "return v.via.every(", to: "return v.via.some(" },
    { name: "via:cycle", fixture: "cycle-via", from: "if (visiting.has(name)) return false;", to: "if (visiting.has(name)) return true;" },
    { name: "severity:critical", fixture: "additional-critical", from: '["high", "critical"].includes(v.severity)', to: '["high"].includes(v.severity)' },
    { name: "severity:high", fixture: "additional-high", from: '["high", "critical"].includes(v.severity)', to: '["critical"].includes(v.severity)' },
    { name: "command:full-graph", fixture: "command-contract", from: '"audit", "--json", "--include=dev",', to: '"audit", "--json",' },
  );

  // Temporary mutated source lives only under this task's worktree; no shared
  // source is overwritten. The directory is removed even when a proof fails.
  const output = path.join(root, "output"); fs.mkdirSync(output, { recursive: true });
  const scratch = fs.mkdtempSync(path.join(output, "audit-exception-mutants-"));
  const run = (file, fixture) => spawnSync(process.execPath, [self, "--assert-case", file, fixture],
    { encoding: "utf8", timeout: 30_000, maxBuffer: 1024 * 1024 });
  try {
    for (let i = 0; i < mutants.length; i++) {
      const m = mutants[i];
      if (source.split(m.from).length !== 2) { ok(`unique source anchor ${m.name}`, false); continue; }
      const file = path.join(scratch, `${i}.mjs`);
      fs.writeFileSync(file, source.replace(m.from, m.to));
      const child = run(file, m.fixture);
      const killed = child.status === 1 && !child.error && child.signal === null &&
        /^FAIL ASSERTION /m.test(child.stderr) && !/ERROR INSTRUMENT/.test(child.stderr);
      ok(`mutant ${m.name} killed by ${m.fixture}`, killed);
      console.log(JSON.stringify({ mutant: m.name, fixture: m.fixture, status: child.status,
        signal: child.signal, assertion: child.stderr.trim(), killed }));
    }
    const noop = path.join(scratch, "noop.mjs"); fs.writeFileSync(noop, source + "\n// no-op control\n");
    const wrong = path.join(scratch, "wrong.mjs"); fs.writeFileSync(wrong,
      source.replace('check("dates",', 'check("dates", true ||'));
    ok("no-op control preserves the expected rejection", run(noop, "additional-high").status === 0);
    ok("wrong-guard control preserves the expected rejection", run(wrong, "additional-high").status === 0);
  } finally { fs.rmSync(scratch, { recursive: true, force: true }); }
  console.log(`audit-exception mutations: ${passed} passed, ${failed} failed; ${mutants.length} real-source mutants`);
  if (failed) process.exitCode = 1;
}
