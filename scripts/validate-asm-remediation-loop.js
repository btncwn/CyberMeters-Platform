#!/usr/bin/env node
//
// Managed ASM remediation loop validation: drives the DB-backed case engine
// over real schema+migrations. Covers open -> assign -> fix completed ->
// verify resolved, verify failed, reopen on re-detection, risk expiry
// reassessment, audit/event rows, and tenant scoping.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const asm = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "asm-cases.js")).href);

const {
  assignManagedCaseOwner,
  createManagedAsmCasesForScan,
  getManagedCase,
  listManagedCaseEvents,
  listManagedCases,
  reassessExpiredRiskAcceptedCases,
  transitionManagedCase,
  verifyManagedAsmCasesForScan,
} = asm;

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering/idempotency no-op */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}

function makeD1(db) {
  const wrap = (sql, args) => ({
    __sql: sql, __args: args,
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
  });
  return {
    prepare(sql) { const b = wrap(sql, []); b.bind = (...args) => wrap(sql, args); return b; },
    async batch(stmts) { return Promise.all(stmts.map((s) => (/^\s*select/i.test(s.__sql) ? s.all() : s.run()))); },
  };
}

const db = buildDb();
const env = {
  cybermeters_db: makeD1(db),
  cybermeters_reports: { get: async () => null, put: async () => ({}), delete: async () => ({}) },
  RESEND_API_KEY: "",
};

function seedWorkspace(ws, domainId, domain) {
  db.prepare("INSERT INTO users (id, email, name, plan, created_at) VALUES (?, ?, ?, 'free', datetime('now'))")
    .run(`${ws}_user`, `${ws}@example.com`, ws);
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES (?, ?, ?)").run(ws, `${ws}_user`, ws);
  db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?, ?, ?, 'admin')")
    .run(`${ws}_member`, ws, `${ws}_user`);
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES (?, ?, ?)").run(domainId, `${ws}_user`, domain);
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES (?, ?)").run(ws, domainId);
}

seedWorkspace("ws_case", "dom_case", "case.example");
seedWorkspace("ws_other", "dom_other", "other.example");

const adminFinding = {
  id: "admin_surface_high",
  module: "admin_surface_detection",
  severity: "high",
  title: "High-risk admin interface exposed",
  description: "An admin interface is publicly reachable.",
  evidence: [{ hostname: "admin.case.example" }],
};
const takeoverFinding = {
  id: "takeover_risk_detected",
  module: "subdomain_takeover",
  severity: "critical",
  title: "Subdomain takeover risk",
  description: "A dangling CNAME was observed.",
  evidence: [{ hostname: "old.case.example" }],
};

await createManagedAsmCasesForScan("scan_1", "dom_case", "case.example", [adminFinding], [{ module: "admin_surface_detection", action: "Restrict access" }], env);
let cases = await listManagedCases(env, "ws_case");
ok("new ASM finding opens one managed case", cases.length === 1 && cases[0].status === "open" && cases[0].finding_id === "admin_surface_high");
ok("case evidence snapshot is present", cases[0].evidence?.finding?.title === adminFinding.title);
ok("tenant list is scoped", (await listManagedCases(env, "ws_other")).length === 0);

let row = await getManagedCase(env, "ws_case", cases[0].id);
let triage = await transitionManagedCase(env, row, "triage", { actor_type: "customer", actor_id: "user1" });
ok("customer can move case to triage", triage.ok && triage.case.status === "triage");
let assigned = await assignManagedCaseOwner(env, triage.case, { owner_type: "team", owner_ref: "IT", assigned_by: "customer", actor_id: "user1" });
ok("owner assignment advances triage case", assigned.ok && assigned.case.owner_ref === "IT");
let inProgress = await transitionManagedCase(env, assigned.case, "remediation_in_progress", { actor_type: "customer", actor_id: "user1" });
ok("owner_assigned advances to remediation", inProgress.ok && inProgress.case.status === "remediation_in_progress");
let fixCompleted = await transitionManagedCase(env, inProgress.case, "verification_requested", { actor_type: "customer", actor_id: "user1", action: "fix_completed" });
ok("customer fix completed requests verification", fixCompleted.ok && fixCompleted.case.status === "verification_requested");

const resolved = await verifyManagedAsmCasesForScan("scan_2", "dom_case", "case.example", [], env);
row = await getManagedCase(env, "ws_case", cases[0].id);
ok("fresh scan with finding absent resolves case", resolved.resolved === 1 && row.status === "resolved" && row.resolved_at);

await createManagedAsmCasesForScan("scan_3", "dom_case", "case.example", [adminFinding], [], env);
row = await getManagedCase(env, "ws_case", cases[0].id);
ok("resolved case auto-reopens on re-detection", row.status === "remediation_in_progress" && row.reopened_count === 1);

await createManagedAsmCasesForScan("scan_4", "dom_case", "case.example", [takeoverFinding], [], env);
cases = await listManagedCases(env, "ws_case");
const takeoverCase = cases.find((c) => c.finding_id === "takeover_risk_detected");
row = await getManagedCase(env, "ws_case", takeoverCase.id);
triage = await transitionManagedCase(env, row, "triage", { actor_type: "customer", actor_id: "user1" });
assigned = await assignManagedCaseOwner(env, triage.case, { owner_type: "team", owner_ref: "Network", assigned_by: "customer", actor_id: "user1" });
inProgress = await transitionManagedCase(env, assigned.case, "remediation_in_progress", { actor_type: "customer", actor_id: "user1" });
fixCompleted = await transitionManagedCase(env, inProgress.case, "verification_requested", { actor_type: "customer", actor_id: "user1", action: "fix_completed" });
const failed = await verifyManagedAsmCasesForScan("scan_5", "dom_case", "case.example", [takeoverFinding], env);
row = await getManagedCase(env, "ws_case", takeoverCase.id);
ok("fresh scan with finding present fails verification", failed.failed === 1 && row.status === "verification_failed" && /still observed/i.test(row.reason));

const riskReq = await transitionManagedCase(env, row, "risk_acceptance_requested", { actor_type: "customer", actor_id: "user1", reason: "Accepted during migration" });
const riskAccepted = await transitionManagedCase(env, riskReq.case, "risk_accepted", {
  actor_type: "customer",
  actor_id: "user1",
  reason: "Accepted during migration",
  risk_accepted_until: "2026-07-01T00:00:00Z",
});
ok("risk acceptance requires and stores expiry", riskAccepted.ok && riskAccepted.case.status === "risk_accepted");
const reassessed = await reassessExpiredRiskAcceptedCases(env, "ws_case", "2026-07-13T00:00:00Z");
row = await getManagedCase(env, "ws_case", takeoverCase.id);
ok("expired risk acceptance returns to triage", reassessed.reassessed === 1 && row.status === "triage");

const eventRows = await listManagedCaseEvents(env, "ws_case", cases[0].id);
const auditCount = db.prepare("SELECT COUNT(*) AS n FROM audit_events WHERE workspace_id = 'ws_case' AND actor_type IS NOT NULL").get().n;
ok("case timeline is written", eventRows.length >= 5);
ok("audit events include actor_type", auditCount >= 1);

db.prepare("INSERT INTO finding_waivers (id, workspace_id, domain, finding_id, reason, waived_by, created_at, updated_at) VALUES ('fw1','ws_case','case.example','cloud_storage_detected','accepted','user1',datetime('now'),datetime('now'))").run();
await createManagedAsmCasesForScan("scan_6", "dom_case", "case.example", [{
  id: "cloud_storage_detected", module: "cloud_storage_discovery", severity: "high", title: "Cloud storage exposed",
}], [], env);
const waived = (await listManagedCases(env, "ws_case")).filter((c) => c.finding_id === "cloud_storage_detected");
ok("finding waivers suppress auto-open", waived.length === 0);

console.log(`\nASM remediation loop: ${pass}/${pass + fail} passed`);
if (fail) { console.error("asm-remediation-loop validation FAILED"); process.exit(1); }
console.log("asm-remediation-loop validation passed");
