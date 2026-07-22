#!/usr/bin/env node
// validate-scan-admission-guard.js
//
// PR-2 (22 Jul 2026 scan-lifecycle sequence): proves the ATOMIC active-scan
// admission guard — migration 099's partial unique indexes make the database
// the final admission authority: at most ONE active scan ('queued' | 'running'
// | 'retrying') per (workspace_id, domain), with a defensive per-domain guard
// for NULL-workspace rows (SQLite UNIQUE treats NULLs as distinct).
//
// Layers:
//   A. REAL database semantics — node:sqlite with schema.sql + every migration
//      applied (same tolerant convergence as validate-migrations.js), then
//      behavioural fixtures against the actual index.
//   B. Guard library — isUniqueConstraintError proven against a REAL SQLite
//      constraint rejection AND the D1-prefixed wording; findActiveScan
//      behaviour incl. fail-degraded (never fail-different-decision).
//   C. Drift guard — SCAN_ACTIVE_STATUSES must equal the status set in BOTH
//      index WHERE clauses of migration 099.
//   D. Source contracts — both creation paths route the constraint rejection
//      to the honest outcome (manual → 409 body, scheduled → skip + return),
//      and no creation path exists outside them.
//
// Mutation directions (reverting the guard reddens the named assertion):
//   - drop WHERE from the primary index      → "terminal statuses free the slot"
//     fails (completed rows would collide)
//   - index on domain_id instead of domain   → "same domain under a different
//     domain_id is still blocked" fails
//   - drop the NULL-workspace index          → "NULL-workspace duplicate active
//     is blocked" fails
//   - remove 'queued'/'retrying' from index  → layer C drift check fails
//   - remove the route catch / 409           → layer D contract fails
//   - widen isUniqueConstraintError to all errors → B3 (non-constraint error
//     must NOT read as admission conflict) fails
//
// Node 24+ (node:sqlite). No network.

import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const libPath = path.join(root, "workers", "scan-api", "src", "lib", "scan-admission.js");
const { SCAN_ACTIVE_STATUSES, ACTIVE_SCAN_CONFLICT_MESSAGE, isUniqueConstraintError, findActiveScan } =
  await import(pathToFileURL(libPath).href);

let passed = 0, failed = 0;
function ok(name, cond, detail = "") {
  if (cond) { passed++; console.log(`PASS ${name}`); }
  else      { failed++; console.log(`FAIL ${name}${detail ? " — " + detail : ""}`); }
}

// ── Layer A: real database semantics ─────────────────────────────────────────
// Converge schema.sql + all migrations exactly like validate-migrations.js so
// the index under test is the one production will get, not a hand-built copy.
const db = new DatabaseSync(":memory:", { enableForeignKeyConstraints: false });
const migDir = path.join(root, "database", "migrations");
const migFiles = fs.readdirSync(migDir).filter((f) => f.endsWith(".sql")).sort();
const apply = (p) => {
  try { db.exec(fs.readFileSync(p, "utf8")); }
  catch (e) { if (!/duplicate|already exists|no such (table|column)/i.test(e.message)) throw e; }
};
apply(path.join(root, "database", "schema.sql"));
for (const f of migFiles) apply(path.join(migDir, f));

ok("migration 099 exists and applied",
  migFiles.includes("099-active-scan-admission-guard.sql") &&
  db.prepare("SELECT COUNT(*) c FROM sqlite_master WHERE type='index' AND name IN ('idx_scans_one_active_per_workspace_domain','idx_scans_one_active_per_domain_null_ws')").get().c === 2);

let seq = 0;
const insertScan = ({ ws, domainId, domain, status }) => db
  .prepare("INSERT INTO scans (id, domain_id, workspace_id, domain, status) VALUES (?, ?, ?, ?, ?)")
  .run(`scan_t${++seq}`, domainId, ws, domain, status);
const throwsUnique = (fn) => {
  try { fn(); return { threw: false, unique: false }; }
  catch (e) { return { threw: true, unique: /UNIQUE constraint failed/i.test(e.message), err: e }; }
};

// A1 — baseline admission succeeds.
insertScan({ ws: "ws1", domainId: "dom_a", domain: "example.com", status: "running" });
ok("A1 first active scan admitted", true);

// A2 — duplicate active same (workspace, domain) is rejected by the DB itself.
const a2 = throwsUnique(() => insertScan({ ws: "ws1", domainId: "dom_a", domain: "example.com", status: "running" }));
ok("A2 duplicate active (same ws, same domain) rejected with UNIQUE", a2.threw && a2.unique);

// A3 — THE ALIASING CASE: same canonical domain under a DIFFERENT domain_id
// (domains rows are per-user) must still be blocked. An index on domain_id
// would wrongly admit this.
const a3 = throwsUnique(() => insertScan({ ws: "ws1", domainId: "dom_b_other_user", domain: "example.com", status: "running" }));
ok("A3 same domain under a different domain_id is still blocked", a3.threw && a3.unique);

// A4 — no cross-tenant blocking: another workspace scans the same domain freely.
const a4 = throwsUnique(() => insertScan({ ws: "ws2", domainId: "dom_c", domain: "example.com", status: "running" }));
ok("A4 same domain in a DIFFERENT workspace is admitted (tenant-scoped)", !a4.threw);

// A5 — same workspace, different domain is admitted.
const a5 = throwsUnique(() => insertScan({ ws: "ws1", domainId: "dom_d", domain: "other.example", status: "running" }));
ok("A5 different domain in the same workspace is admitted", !a5.threw);

// A6 — every future active status participates in the guard.
const a6q = throwsUnique(() => insertScan({ ws: "ws1", domainId: "dom_a", domain: "example.com", status: "queued" }));
const a6r = throwsUnique(() => insertScan({ ws: "ws1", domainId: "dom_a", domain: "example.com", status: "retrying" }));
ok("A6 'queued' and 'retrying' are blocked while a scan is active",
  a6q.threw && a6q.unique && a6r.threw && a6r.unique);

// A7 — terminal statuses free the slot (partial WHERE is load-bearing).
db.prepare("UPDATE scans SET status = 'completed' WHERE id = 'scan_t1'").run();
const a7 = throwsUnique(() => insertScan({ ws: "ws1", domainId: "dom_a", domain: "example.com", status: "running" }));
ok("A7 terminal statuses free the slot (new scan admitted after completion)", !a7.threw);

// A8 — 'failed' also frees the slot (PR-1 recovery unblocks admissions).
db.prepare("UPDATE scans SET status = 'failed' WHERE domain = 'example.com' AND workspace_id = 'ws1' AND status = 'running'").run();
const a8 = throwsUnique(() => insertScan({ ws: "ws1", domainId: "dom_a", domain: "example.com", status: "running" }));
ok("A8 'failed' frees the slot (recovery unblocks the next admission)", !a8.threw);
db.prepare("UPDATE scans SET status = 'failed' WHERE domain = 'example.com' AND workspace_id = 'ws1' AND status = 'running'").run();

// A9 — historical reality preserved: many TERMINAL rows for one (ws, domain)
// coexist. A non-partial unique index would make history itself a violation.
const a9a = throwsUnique(() => insertScan({ ws: "ws1", domainId: "dom_a", domain: "example.com", status: "completed" }));
const a9b = throwsUnique(() => insertScan({ ws: "ws1", domainId: "dom_a", domain: "example.com", status: "completed" }));
ok("A9 multiple terminal rows for one (ws, domain) coexist", !a9a.threw && !a9b.threw);

// A10 — NULL-workspace defense: NULLs are distinct in SQLite UNIQUE indexes,
// so without the second index two NULL-ws active scans would both be admitted.
const a10a = throwsUnique(() => insertScan({ ws: null, domainId: "dom_e", domain: "legacy.example", status: "running" }));
const a10b = throwsUnique(() => insertScan({ ws: null, domainId: "dom_e", domain: "legacy.example", status: "running" }));
ok("A10 NULL-workspace duplicate active is blocked (defensive index)",
  !a10a.threw && a10b.threw && a10b.unique);

// A11 — NULL-ws and real-ws scopes are distinct (defensive index never blocks
// a real workspace's admission).
const a11 = throwsUnique(() => insertScan({ ws: "ws3", domainId: "dom_f", domain: "legacy.example", status: "running" }));
ok("A11 NULL-workspace active does not block a real workspace", !a11.threw);

// A12 — read-then-write is NOT sufficient, the INSERT is the decision: both
// racers observe zero active rows for a fresh (ws, domain), then both insert;
// exactly one wins. This is the atomicity claim of PR-2 in miniature.
const seen1 = db.prepare("SELECT COUNT(*) c FROM scans WHERE workspace_id='ws9' AND domain='race.example' AND status IN ('queued','running','retrying')").get().c;
const seen2 = db.prepare("SELECT COUNT(*) c FROM scans WHERE workspace_id='ws9' AND domain='race.example' AND status IN ('queued','running','retrying')").get().c;
const r1 = throwsUnique(() => insertScan({ ws: "ws9", domainId: "dom_g", domain: "race.example", status: "running" }));
const r2 = throwsUnique(() => insertScan({ ws: "ws9", domainId: "dom_h", domain: "race.example", status: "running" }));
ok("A12 race: both pre-reads saw 0 active, exactly one INSERT wins",
  seen1 === 0 && seen2 === 0 && !r1.threw && r2.threw && r2.unique);

// ── Layer B: guard library ───────────────────────────────────────────────────
// B1 — the matcher matches a REAL SQLite constraint rejection (a2 above).
ok("B1 isUniqueConstraintError matches a real SQLite rejection", isUniqueConstraintError(a2.err));
// B2 — and the D1 client wording.
ok("B2 isUniqueConstraintError matches D1 wording",
  isUniqueConstraintError(new Error("D1_ERROR: UNIQUE constraint failed: scans.workspace_id, scans.domain: SQLITE_CONSTRAINT")));
// B3 — anything else is NOT an admission conflict (must propagate to safe 500).
ok("B3 non-constraint errors are not admission conflicts",
  !isUniqueConstraintError(new Error("D1_ERROR: no such table: scans")) &&
  !isUniqueConstraintError(new Error("network timeout")) &&
  !isUniqueConstraintError(undefined) && !isUniqueConstraintError(null));

// B4 — findActiveScan returns the blocking row via a bound, workspace-scoped read.
const stubEnv = (rows, { fail = false } = {}) => ({
  cybermeters_db: {
    prepare(sql) {
      return { bind(...args) { return { async first() {
        if (fail) throw new Error("D1 read failure");
        // Assert tenancy + status binding shape rather than trusting SQL text.
        const [ws, domain, ...statuses] = args;
        const hit = rows.find((r) => r.workspace_id === ws && r.domain === domain && statuses.includes(r.status));
        return hit ?? null;
      } }; } };
    },
  },
});
const found = await findActiveScan(
  stubEnv([{ id: "scan_x", workspace_id: "ws1", domain: "example.com", status: "running", created_at: "2026-07-22 10:00:00" }]),
  "ws1", "example.com");
ok("B4 findActiveScan returns the blocking active scan", found?.id === "scan_x");
const foreign = await findActiveScan(
  stubEnv([{ id: "scan_y", workspace_id: "ws2", domain: "example.com", status: "running" }]),
  "ws1", "example.com");
ok("B5 findActiveScan never crosses the workspace boundary", foreign === null);
const degraded = await findActiveScan(stubEnv([], { fail: true }), "ws1", "example.com");
ok("B6 findActiveScan read failure degrades to null, never throws", degraded === null);

// ── Layer C: constant ↔ migration drift guard ────────────────────────────────
ok("C0 SCAN_ACTIVE_STATUSES is exactly queued/running/retrying",
  JSON.stringify(SCAN_ACTIVE_STATUSES) === JSON.stringify(["queued", "running", "retrying"]));
const migSrc = fs.readFileSync(path.join(migDir, "099-active-scan-admission-guard.sql"), "utf8")
  .replace(/--[^\n]*/g, "");
const whereSets = [...migSrc.matchAll(/WHERE\s+status\s+IN\s*\(([^)]*)\)/gi)]
  .map((m) => m[1].match(/'([^']+)'/g).map((s) => s.slice(1, -1)).sort().join(","));
ok("C1 both index WHERE clauses exist", whereSets.length === 2);
ok("C2 index status sets match SCAN_ACTIVE_STATUSES (no drift)",
  whereSets.every((s) => s === [...SCAN_ACTIVE_STATUSES].sort().join(",")));

// ── Layer D: source contracts on the only two creation paths ─────────────────
const scansSrc = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "routes", "scans.js"), "utf8");
const indexSrc = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "index.js"), "utf8");

ok("D1 manual path imports the admission guard",
  /from ["']\.\.\/lib\/scan-admission\.js["']/.test(scansSrc));
ok("D2 manual path converts the constraint rejection to an honest 409",
  /isUniqueConstraintError\(insertErr\)[\s\S]{0,700}ACTIVE_SCAN_CONFLICT_MESSAGE[\s\S]{0,700}409/.test(scansSrc));
ok("D3 manual 409 names the blocking scan (honest, pollable outcome)",
  /active_scan_id/.test(scansSrc) && /findActiveScan\(env, workspaceId, domain\)/.test(scansSrc));
ok("D4 scheduled path imports the admission guard",
  /from ["']\.\/lib\/scan-admission\.js["']/.test(indexSrc));
const schedGuard = indexSrc.match(/isUniqueConstraintError\(insertErr\)[\s\S]{0,600}/);
ok("D5 scheduled path skips with the stable reason and returns (no side effects)",
  !!schedGuard && /active_scan_exists/.test(schedGuard[0]) && /return;/.test(schedGuard[0]));
// D6 — the two guarded INSERTs are the ONLY scan-row creation paths in the
// Worker. A third path would bypass route-level honesty (the DB still blocks).
const workerInsertCount = (dir) => {
  let n = 0;
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith(".js")) n += (fs.readFileSync(p, "utf8").match(/INSERT INTO scans/g) || []).length;
    }
  };
  walk(dir);
  return n;
};
ok("D6 exactly two scan-creation paths exist in the Worker",
  workerInsertCount(path.join(root, "workers", "scan-api", "src")) === 2);

// ── Summary ──────────────────────────────────────────────────────────────────
console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
