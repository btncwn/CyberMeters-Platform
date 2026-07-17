#!/usr/bin/env node
//
// M5.g — Final CI closure for the M5 eight-domain episode. CI-blocking.
//
// M5 shipped as ten focused validators (read-surfaces, m5a×3, m5b×2, m5c, m5d, m5e, m5f),
// each proving its own slice. Nothing, however, guaranteed the SUITE stays wired: only the
// m5e and m5f validators re-assert a handful of siblings, so deleting a `validate-m5a-*`,
// `validate-m5b-*` or `validate-m5-read-surfaces` step from ci.yml would silently drop that
// coverage while CI still went green — the exact "looked checked, wasn't" failure mode that
// `validate-ci-governance.js` was written for at the trigger level. This closure asserts, at
// the gate level, that no M5 coverage can silently rot:
//   1. every M5 validator that exists is wired in ci.yml as an uncommented run step (and the
//      canonical ten all exist) — deletion OR commenting-out is caught;
//   2. ci-governance (the trigger-shape guard) is wired; and, reciprocally,
//      validate-ci-governance.js asserts THIS closure is wired — the two mutually guard each
//      other, so dropping either step is caught by the other (a self-guard cannot catch the
//      deletion of its own step alone, which is why the guard is reciprocal);
//   3. the M5 append-only IDEMPOTENCY invariants hold — the three per-scan tables
//      (091 states, 093 snapshot, 095 maturity) keep their natural/partial UNIQUE and are
//      written only with INSERT OR IGNORE, never a history-overwriting REPLACE, and the 093
//      claim machine's UPDATEs are all guarded to still-building rows (a completed row is
//      immutable).
//
// It is a static, deterministic gate. It changes no runtime behaviour and requires no deploy.
//
// SCOPE NOTE (deliberately NOT closed here): the "cost" residual — Phase 8o's snapshot build
// re-runs buildCyberEssentialsReadiness that Phase 8n already ran (scan-engine.js ~1234) — is
// a scan-finalize/ce-lifecycle contract change that only takes effect once DEPLOYED. Per the
// founder's boundary it is tracked as a separately-approved deploy increment, not smuggled
// into this no-deploy CI closure. Proof-of-production is per-increment: M5.f is production-
// accepted (v2026.07.17-5); a–e authenticated acceptance is the public-beta gate.
//
// Node 24+.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const scriptsDir = path.join(root, "scripts");
const read = (rel) => fs.readFileSync(path.join(root, rel), "utf8");

// In-memory source map so the mutation suite can prove each guard is load-bearing.
const sourceFiles = new Map();
const getSource = (rel) => sourceFiles.get(rel) ?? read(rel);
const setSource = (rel, src) => sourceFiles.set(rel, src);

let pass = 0, fail = 0;
const failures = [];
function ok(name, condition, detail = "") {
  if (condition) pass++;
  else { fail++; const m = `FAIL ${name}${detail ? " — " + detail : ""}`; failures.push(m); console.log(m); }
}

// The canonical M5 validator suite. Each MUST exist and MUST be wired.
const CANONICAL_M5_VALIDATORS = Object.freeze([
  "validate-m5-read-surfaces.js",
  "validate-m5a-email-cases.js",
  "validate-m5a-website-cases.js",
  "validate-m5a-ce-cases.js",
  "validate-m5b-certificate-verification.js",
  "validate-m5b-remaining-reconciliation.js",
  "validate-m5c-reporting-snapshot.js",
  "validate-m5d-renderer-migration.js",
  "validate-m5e-closure.js",
  "validate-m5f-maturity-ledger.js",
]);

// The three per-scan append-only tables and the invariants that make a re-finalize or a
// reconciler re-run an idempotent no-op that can never rewrite history.
const IDEMPOTENCY = Object.freeze([
  {
    label: "091 cyber_mot_domain_states",
    migration: "database/migrations/091-cyber-mot-domain-states.sql",
    unique: /UNIQUE \(workspace_id, domain_id, scan_id, domain_key\)/,
    engine: "workers/scan-api/src/engines/cyber-mot-state-history.js",
    insert: /INSERT OR IGNORE INTO cyber_mot_domain_states/,
    table: "cyber_mot_domain_states",
  },
  {
    label: "093 scan_report_snapshots",
    migration: "database/migrations/093-scan-report-snapshots.sql",
    unique: /CREATE UNIQUE INDEX[^\n]*idx_scan_report_snapshots_active[\s\S]*?\(scan_id\) WHERE status != 'failed'/,
    engine: "workers/scan-api/src/engines/report-snapshot.js",
    insert: /INSERT OR IGNORE INTO scan_report_snapshots/,
    table: "scan_report_snapshots",
    // The 081 claim machine: a row transitions building → completed|failed, then a COMPLETED
    // row is immutable. So (unlike the pure append-only 091/095) it legitimately UPDATEs — but
    // every UPDATE must be guarded to building rows so a completed snapshot is never rewritten.
    claimMachine: true,
  },
  {
    label: "095 domain_maturity_ledger",
    migration: "database/migrations/095-domain-maturity-ledger.sql",
    unique: /UNIQUE \(workspace_id, domain_id, scan_id, domain_key\)/,
    engine: "workers/scan-api/src/engines/domain-maturity.js",
    insert: /INSERT OR IGNORE INTO domain_maturity_ledger/,
    table: "domain_maturity_ledger",
  },
]);

function m5ValidatorFiles() {
  return fs.readdirSync(scriptsDir)
    .filter((f) => /^validate-m5.*\.js$/.test(f) && f !== "validate-m5-closure.js")
    .sort();
}

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
// A validator is "wired" only as an UNCOMMENTED `run:` step — a commented-out
// `# run: node scripts/x.js` line must NOT count (that would silently drop coverage while
// still satisfying a naive substring match).
const isWired = (ci, file) => new RegExp(`^\\s*run:\\s*node scripts/${escapeRe(file)}\\s*$`, "m").test(ci);

function checkGateWiring() {
  const ci = getSource(".github/workflows/ci.yml");

  // 1. The canonical ten all EXIST (none silently deleted).
  for (const v of CANONICAL_M5_VALIDATORS) {
    ok(`M5 validator file exists: ${v}`, fs.existsSync(path.join(scriptsDir, v)));
  }

  // 2. EVERY validate-m5*.js on disk is wired as a real run step (auto-covers future ones).
  for (const f of m5ValidatorFiles()) {
    ok(`M5 validator is wired in ci.yml: ${f}`, isWired(ci, f), "not an uncommented run step in ci.yml");
  }

  // 3. The trigger-shape guard and THIS closure are themselves wired (cannot be dropped).
  ok("ci-governance guard is wired", isWired(ci, "validate-ci-governance.js"));
  ok("M5 closure guard is itself wired", isWired(ci, "validate-m5-closure.js"));

  // 4. No canonical validator missing from the on-disk set (belt and braces vs. rename drift).
  const onDisk = new Set(m5ValidatorFiles());
  for (const v of CANONICAL_M5_VALIDATORS) {
    ok(`canonical M5 validator present on disk: ${v}`, onDisk.has(v));
  }
}

// Every `UPDATE <table> SET ...` statement must be filtered to building rows: the
// `status = 'building'` guard has to appear in the statement's WHERE clause (not merely
// somewhere in the SET), so a completed/immutable row can never be rewritten. Captures the
// whole statement body up to the SQL-template terminator (backtick or `;`) — no fixed window,
// and a statement with no WHERE at all fails closed.
function everyUpdateGuardedToBuilding(engine, table) {
  const re = new RegExp("UPDATE\\s+" + table + "\\s+SET([^;`]*)", "gi");
  let m;
  while ((m = re.exec(engine)) !== null) {
    const body = m[1];
    const whereIdx = body.search(/\bWHERE\b/i);
    if (whereIdx === -1) return false;                                  // no filter → could hit any row
    if (!/status\s*=\s*'building'/i.test(body.slice(whereIdx))) return false; // building not in the WHERE
  }
  return true;
}

function checkIdempotencyInvariants() {
  for (const inv of IDEMPOTENCY) {
    const mig = getSource(inv.migration);
    ok(`${inv.label}: migration keeps its idempotency UNIQUE`, inv.unique.test(mig));
    const eng = getSource(inv.engine);
    ok(`${inv.label}: engine writes with INSERT OR IGNORE (append-once)`, inv.insert.test(eng));
    // Historical immutability. A REPLACE would clobber a prior row on either kind of table.
    const replace = new RegExp(`INSERT OR REPLACE INTO ${inv.table}\\b|\\bREPLACE INTO ${inv.table}\\b`, "i");
    ok(`${inv.label}: no history-overwriting REPLACE`, !replace.test(eng),
      "an append-only per-scan table must never be REPLACEd");
    if (inv.claimMachine) {
      // Claim machine: UPDATEs are allowed only to flip a still-building row; a completed row
      // is immutable, so every UPDATE must carry the status='building' guard.
      ok(`${inv.label}: every UPDATE is guarded to building rows (completed row is immutable)`,
        everyUpdateGuardedToBuilding(eng, inv.table),
        "an UPDATE without a status='building' guard could rewrite a completed snapshot");
    } else {
      // Pure append-only: never updated in place at all.
      const update = new RegExp(`UPDATE\\s+${inv.table}\\s+SET`, "i");
      ok(`${inv.label}: no in-place UPDATE (pure append-only)`, !update.test(eng),
        "a pure append-only per-scan table must never be UPDATEd in place");
    }
  }
}

// ── Mutation suite — each reintroduces a defect the guards must catch ──────────
const MUTATIONS = [
  {
    name: "drop an M5 validator step from ci.yml",
    file: ".github/workflows/ci.yml",
    mutate: (s) => s.replace(/\n\s*- name:[^\n]*\n\s*run: node scripts\/validate-m5f-maturity-ledger\.js/, ""),
    expect: () => isWired(getSource(".github/workflows/ci.yml"), "validate-m5f-maturity-ledger.js") ? null : "m5f validator step dropped from ci.yml",
  },
  {
    name: "comment out an M5 validator step (must NOT count as wired)",
    file: ".github/workflows/ci.yml",
    mutate: (s) => s.replace("run: node scripts/validate-m5e-closure.js", "# run: node scripts/validate-m5e-closure.js"),
    expect: () => isWired(getSource(".github/workflows/ci.yml"), "validate-m5e-closure.js") ? null : "commented-out m5e step no longer counts as wired",
  },
  {
    name: "drop the ci-governance guard",
    file: ".github/workflows/ci.yml",
    mutate: (s) => s.replace("node scripts/validate-ci-governance.js", "node scripts/validate-ci-governance.DISABLED.js"),
    expect: () => isWired(getSource(".github/workflows/ci.yml"), "validate-ci-governance.js") ? null : "ci-governance guard unwired",
  },
  {
    name: "unwire the M5 closure guard itself",
    file: ".github/workflows/ci.yml",
    mutate: (s) => s.replace("node scripts/validate-m5-closure.js", "node scripts/validate-m5-closure.DISABLED.js"),
    expect: () => isWired(getSource(".github/workflows/ci.yml"), "validate-m5-closure.js") ? null : "M5 closure guard unwired",
  },
  {
    name: "drop the 095 maturity-ledger idempotency UNIQUE",
    file: "database/migrations/095-domain-maturity-ledger.sql",
    mutate: (s) => s.replace("UNIQUE (workspace_id, domain_id, scan_id, domain_key),", ""),
    expect: () => IDEMPOTENCY[2].unique.test(getSource("database/migrations/095-domain-maturity-ledger.sql")) ? null : "095 idempotency UNIQUE dropped",
  },
  {
    name: "overwrite maturity history (INSERT OR IGNORE → INSERT OR REPLACE)",
    file: "workers/scan-api/src/engines/domain-maturity.js",
    mutate: (s) => s.replace("INSERT OR IGNORE INTO domain_maturity_ledger", "INSERT OR REPLACE INTO domain_maturity_ledger"),
    expect: () => IDEMPOTENCY[2].insert.test(getSource("workers/scan-api/src/engines/domain-maturity.js")) ? null : "maturity writer no longer append-once (INSERT OR IGNORE)",
  },
  {
    name: "add an UNGUARDED UPDATE that could rewrite a completed snapshot",
    file: "workers/scan-api/src/engines/report-snapshot.js",
    mutate: (s) => `${s}\nasync function __evil(env){ return env.cybermeters_db.prepare("UPDATE scan_report_snapshots SET status='x' WHERE id=?").bind('x').run(); }\n`,
    expect: () => everyUpdateGuardedToBuilding(getSource("workers/scan-api/src/engines/report-snapshot.js"), "scan_report_snapshots") ? null : "an unguarded UPDATE could rewrite a completed snapshot",
  },
];

function runMutations() {
  const touched = new Set(MUTATIONS.map((m) => m.file));
  const original = new Map();
  for (const f of touched) original.set(f, read(f));
  let mutationPass = 0, mutationFail = 0;
  for (const m of MUTATIONS) {
    sourceFiles.clear();
    for (const [k, v] of original) sourceFiles.set(k, v);
    setSource(m.file, m.mutate(getSource(m.file)));
    const reason = m.expect();
    if (reason) mutationPass++;
    else { mutationFail++; console.log(`FAIL mutation '${m.name}' did not break its invariant`); }
  }
  sourceFiles.clear();
  ok(`mutations: ${MUTATIONS.length} required regressions each break an invariant`, mutationFail === 0, `${mutationPass} caught, ${mutationFail} escaped`);
}

function main() {
  checkGateWiring();
  checkIdempotencyInvariants();
  runMutations();

  console.log(`\nm5-closure: ${pass} passed, ${fail} failed`);
  if (fail) { console.error("m5-closure validation FAILED"); process.exit(1); }
  console.log("m5-closure validation passed");
}
main();
