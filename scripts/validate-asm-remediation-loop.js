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
const eq = (name, got, want) => { const c = got === want; c ? pass++ : fail++; if (!c) console.log(`FAIL ${name} — got ${JSON.stringify(got)} want ${JSON.stringify(want)}`); };

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

seedWorkspace("ws_case", "dom_case", "case-example.com");
seedWorkspace("ws_other", "dom_other", "other.example");

const adminFinding = {
  id: "admin_surface_high",
  module: "admin_surface_detection",
  severity: "high",
  title: "High-risk admin interface exposed",
  description: "An admin interface is publicly reachable.",
  evidence: [{ hostname: "admin.case-example.com" }],
};
const takeoverFinding = {
  id: "takeover_risk_detected",
  module: "subdomain_takeover",
  severity: "critical",
  title: "Subdomain takeover risk",
  description: "A dangling CNAME was observed.",
  evidence: [{ hostname: "old.case-example.com" }],
};

await createManagedAsmCasesForScan("scan_1", "dom_case", "case-example.com", [adminFinding], [{ module: "admin_surface_detection", action: "Restrict access" }], env);
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

// Trust guard: a customer must NOT be able to self-drive the verification
// outcome — that is CyberMeters' independent step. Resolution must come only
// from a real scan observing the exposure absent.
const selfVerify = await transitionManagedCase(env, fixCompleted.case, "verifying", { actor_type: "customer", actor_id: "user1" });
ok("customer cannot self-start verification", !selfVerify.ok && /verified by CyberMeters/i.test(selfVerify.error));
const selfResolve = await transitionManagedCase(env, fixCompleted.case, "resolved", { actor_type: "customer", actor_id: "user1" });
ok("customer cannot self-resolve a case", !selfResolve.ok);
const dbStatusAfterSelf = (await getManagedCase(env, "ws_case", cases[0].id)).status;
ok("case stays awaiting verification after blocked self-resolve", dbStatusAfterSelf === "verification_requested");

// Absence only verifies when the DETECTING module can be shown to have run clean.
const completeAdminScan = { modules: { admin_surface_detection: {} }, scanQuality: { status: "complete", modules_skipped: [] } };
const resolved = await verifyManagedAsmCasesForScan("scan_2", "dom_case", "case-example.com", [], env, completeAdminScan);
row = await getManagedCase(env, "ws_case", cases[0].id);
ok("fresh scan with finding absent resolves case", resolved.resolved === 1 && row.status === "resolved" && row.resolved_at);

await createManagedAsmCasesForScan("scan_3", "dom_case", "case-example.com", [adminFinding], [], env);
row = await getManagedCase(env, "ws_case", cases[0].id);
ok("resolved case auto-reopens on re-detection", row.status === "remediation_in_progress" && row.reopened_count === 1);

await createManagedAsmCasesForScan("scan_4", "dom_case", "case-example.com", [takeoverFinding], [], env);
cases = await listManagedCases(env, "ws_case");
const takeoverCase = cases.find((c) => c.finding_id === "takeover_risk_detected");
row = await getManagedCase(env, "ws_case", takeoverCase.id);
triage = await transitionManagedCase(env, row, "triage", { actor_type: "customer", actor_id: "user1" });
assigned = await assignManagedCaseOwner(env, triage.case, { owner_type: "team", owner_ref: "Network", assigned_by: "customer", actor_id: "user1" });
inProgress = await transitionManagedCase(env, assigned.case, "remediation_in_progress", { actor_type: "customer", actor_id: "user1" });
fixCompleted = await transitionManagedCase(env, inProgress.case, "verification_requested", { actor_type: "customer", actor_id: "user1", action: "fix_completed" });
const failed = await verifyManagedAsmCasesForScan("scan_5", "dom_case", "case-example.com", [takeoverFinding], env, {
  modules: { subdomain_takeover: {} }, scanQuality: { status: "complete", modules_skipped: [] },
});
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

db.prepare("INSERT INTO finding_waivers (id, workspace_id, domain, finding_id, reason, waived_by, created_at, updated_at) VALUES ('fw1','ws_case','case-example.com','cloud_storage_detected','accepted','user1',datetime('now'),datetime('now'))").run();
await createManagedAsmCasesForScan("scan_6", "dom_case", "case-example.com", [{
  id: "cloud_storage_detected", module: "cloud_storage_discovery", severity: "high", title: "Cloud storage exposed",
}], [], env);
const waived = (await listManagedCases(env, "ws_case")).filter((c) => c.finding_id === "cloud_storage_detected");
ok("finding waivers suppress auto-open", waived.length === 0);

// ── Scan-completeness guard: never resolve off an incomplete scan ─────────────
const guardFinding = { id: "admin_surface_critical", module: "admin_surface_detection", severity: "critical", title: "Admin panel exposed", evidence: [{ hostname: "panel.case-example.com" }] };
await createManagedAsmCasesForScan("scan_g1", "dom_case", "case-example.com", [guardFinding], [], env);
let gCase = (await listManagedCases(env, "ws_case")).find((c) => c.finding_id === "admin_surface_critical");
let gRow = await getManagedCase(env, "ws_case", gCase.id);
gRow = (await transitionManagedCase(env, gRow, "triage", { actor_type: "customer", actor_id: "user1" })).case;
gRow = (await assignManagedCaseOwner(env, gRow, { owner_type: "team", owner_ref: "IT", assigned_by: "customer", actor_id: "user1" })).case;
gRow = (await transitionManagedCase(env, gRow, "remediation_in_progress", { actor_type: "customer", actor_id: "user1" })).case;
gRow = (await transitionManagedCase(env, gRow, "verification_requested", { actor_type: "customer", actor_id: "user1", action: "fix_completed" })).case;

// Finding absent BUT its module failed/timed-out this scan → must DEFER, not resolve.
const deferredRun = await verifyManagedAsmCasesForScan("scan_g2", "dom_case", "case-example.com", [], env, {
  modules: { admin_surface_detection: { error: "timed out" } },
  scanQuality: { status: "degraded", modules_skipped: ["admin_surface_detection"] },
});
gRow = await getManagedCase(env, "ws_case", gCase.id);
ok("incomplete module defers verification (no false resolve)",
   deferredRun.deferred === 1 && deferredRun.resolved === 0 && gRow.status === "verification_requested");
const deferEvent = (await listManagedCaseEvents(env, "ws_case", gCase.id)).some((e) => e.action === "verification_deferred");
ok("deferral is recorded on the case timeline", deferEvent);

// A partial scan (a core module broke) also defers, even with the ASM module clean.
const partialRun = await verifyManagedAsmCasesForScan("scan_g3", "dom_case", "case-example.com", [], env, {
  modules: { admin_surface_detection: {} },
  scanQuality: { status: "partial", modules_skipped: [] },
});
ok("partial scan defers verification", partialRun.deferred === 1 && partialRun.resolved === 0);

// Same finding absent, module completed cleanly on a complete scan → resolve.
const cleanRun = await verifyManagedAsmCasesForScan("scan_g4", "dom_case", "case-example.com", [], env, {
  modules: { admin_surface_detection: {} },
  scanQuality: { status: "complete", modules_skipped: [] },
});
gRow = await getManagedCase(env, "ws_case", gCase.id);
ok("complete scan verifies and resolves", cleanRun.resolved === 1 && gRow.status === "resolved");

// ── Fail-closed gate: a completed scan alone is never verification ────────────
// Drive the same case back to awaiting-verification and prove each way the gate
// can fail to demonstrate the detecting module ran leaves the case UNVERIFIED.
async function backToAwaitingVerification(caseId) {
  let r = await getManagedCase(env, "ws_case", caseId);
  r = (await transitionManagedCase(env, r, "reopened", { actor_type: "system" })).case;
  r = (await transitionManagedCase(env, r, "remediation_in_progress", { actor_type: "system" })).case;
  return (await transitionManagedCase(env, r, "verification_requested", { actor_type: "customer", actor_id: "user1", action: "fix_completed" })).case;
}

await backToAwaitingVerification(gCase.id);
const noEvidenceRun = await verifyManagedAsmCasesForScan("scan_g5", "dom_case", "case-example.com", [], env);
gRow = await getManagedCase(env, "ws_case", gCase.id);
ok("no completeness evidence never resolves (fail-closed)",
   noEvidenceRun.resolved === 0 && noEvidenceRun.deferred === 1 && gRow.status === "verification_requested");
ok("no-evidence deferral records why",
   (await listManagedCaseEvents(env, "ws_case", gCase.id)).some((e) => e.detail?.reason === "no_completeness_evidence"));

// The detecting module simply did not run this scan (absent from the module map,
// not explicitly errored). Absence of telemetry is not evidence it was re-checked.
const notRunRun = await verifyManagedAsmCasesForScan("scan_g6", "dom_case", "case-example.com", [], env, {
  modules: { dns: {} }, scanQuality: { status: "complete", modules_skipped: [] },
});
gRow = await getManagedCase(env, "ws_case", gCase.id);
ok("detecting module that did not run never resolves",
   notRunRun.resolved === 0 && notRunRun.deferred === 1 && gRow.status === "verification_requested");
ok("module-did-not-run deferral records why",
   (await listManagedCaseEvents(env, "ws_case", gCase.id)).some((e) => e.detail?.reason === "module_did_not_run"));

// A case whose finding records no module cannot prove anything re-checked it.
await createManagedAsmCasesForScan("scan_g7", "dom_case", "case-example.com", [{
  id: "exposed_service_unknown_module", severity: "high", title: "Exposed service",
}], [], env);
const noModCase = (await listManagedCases(env, "ws_case")).find((c) => c.finding_id === "exposed_service_unknown_module");
let nmRow = await getManagedCase(env, "ws_case", noModCase.id);
nmRow = (await transitionManagedCase(env, nmRow, "triage", { actor_type: "customer", actor_id: "user1" })).case;
nmRow = (await assignManagedCaseOwner(env, nmRow, { owner_type: "team", owner_ref: "IT", assigned_by: "customer", actor_id: "user1" })).case;
nmRow = (await transitionManagedCase(env, nmRow, "remediation_in_progress", { actor_type: "customer", actor_id: "user1" })).case;
await transitionManagedCase(env, nmRow, "verification_requested", { actor_type: "customer", actor_id: "user1", action: "fix_completed" });
const unknownModuleRun = await verifyManagedAsmCasesForScan("scan_g8", "dom_case", "case-example.com", [], env, {
  modules: { admin_surface_detection: {} }, scanQuality: { status: "complete", modules_skipped: [] },
});
nmRow = await getManagedCase(env, "ws_case", noModCase.id);
// (This run also resolves the unrelated admin case whose module DID run clean —
// assert on this case only, not the run-wide counters.)
ok("finding with unknown detecting module never resolves", nmRow.status === "verification_requested");
ok("unknown-module deferral records why",
   (await listManagedCaseEvents(env, "ws_case", noModCase.id)).some((e) => e.detail?.reason === "unknown_detecting_module"));

// ── Affected-host truth: asset_ref is a host, never customer-facing prose ─────
// Regression guard for the defect where asset_ref fell back to the first evidence
// entry's `value` — which for every ASM finding is the finding's description.
await createManagedAsmCasesForScan("scan_h1", "dom_case", "case-example.com", [{
  id: "asset_exposure_admin_interface", module: "asset_exposure", severity: "medium",
  title: "Administrative Interface Publicly Reachable",
  description: "1 administrative or login interface is publicly accessible: panel.case-example.com. Restrict access to authorised IP ranges or enforce MFA.",
  affected_hosts: ["panel.case-example.com", "PORTAL.case-example.com", "attacker.evil.example", "not a hostname"],
}], [], env);
const hostCase = (await listManagedCases(env, "ws_case")).find((c) => c.finding_id === "asset_exposure_admin_interface");
const hostRow = await getManagedCase(env, "ws_case", hostCase.id);
eq("asset_ref is the structured affected host", hostRow.asset_ref, "panel.case-example.com");
ok("asset_ref is never the finding description", !/publicly accessible/i.test(hostRow.asset_ref || ""));
ok("asset_ref passes the verification host-scope guard",
   hostRow.asset_ref === "case-example.com" || hostRow.asset_ref.endsWith(".case-example.com"));

// A finding with no derivable host falls back to the domain — never to free text.
await createManagedAsmCasesForScan("scan_h2", "dom_case", "case-example.com", [{
  id: "dse_missing_caa", module: "domain_security_enrichment", severity: "medium",
  title: "No CAA DNS Record", description: "This domain has no CAA record, so any CA may issue for it.",
}], [], env);
const caaCase = (await listManagedCases(env, "ws_case")).find((c) => c.finding_id === "dse_missing_caa");
eq("host-less finding falls back to the domain", (await getManagedCase(env, "ws_case", caaCase.id)).asset_ref, "case-example.com");

// ── Legacy prose asset_ref is healed by a later observation, never by parsing ──
// Simulate a case opened before affected_hosts existed: prose in asset_ref, no
// structured hosts in the evidence snapshot.
{
  const legacyDesc = "1 administrative or login interface is publicly accessible: legacy.case-example.com. Restrict access.";
  const legacyEvidence = JSON.stringify({
    scan_id: "scan_old", domain_id: "dom_case",
    finding: { id: "asset_exposure_dev_env", module: "asset_exposure", severity: "medium", title: "Dev env exposed", description: legacyDesc },
  });
  db.prepare(`INSERT INTO managed_cases (id, workspace_id, case_type, domain_key, domain, finding_id,
      source_finding_type, source_scan_id, asset_ref, severity, status, evidence_json, created_by, created_at, updated_at)
    VALUES ('case_legacy','ws_case','asm_exposure','attack_surface','case-example.com','asset_exposure_dev_env',
      'asset_exposure_dev_env','scan_old',?, 'medium','open',?, 'system', datetime('now'), datetime('now'))`)
    .run(legacyDesc, legacyEvidence);

  const before = await getManagedCase(env, "ws_case", "case_legacy");
  ok("legacy case starts with prose in asset_ref", /publicly accessible/.test(before.asset_ref));

  // The SAME finding is observed again, this time carrying structured hosts.
  await createManagedAsmCasesForScan("scan_heal", "dom_case", "case-example.com", [{
    id: "asset_exposure_dev_env", module: "asset_exposure", severity: "medium",
    title: "Dev env exposed", description: legacyDesc,
    affected_hosts: ["legacy.case-example.com", "staging.case-example.com"],
  }], [], env);

  const after = await getManagedCase(env, "ws_case", "case_legacy");
  eq("legacy asset_ref healed to a real host on re-observation", after.asset_ref, "legacy.case-example.com");
  const ev = JSON.parse(after.evidence_json);
  eq("enriched hosts appended to evidence", JSON.stringify(ev.affected_hosts), JSON.stringify(["legacy.case-example.com", "staging.case-example.com"]));
  ok("enrichment records the observing scan", ev.affected_hosts_scan_id === "scan_heal" && Boolean(ev.affected_hosts_observed_at));
  eq("original finding snapshot preserved byte-for-byte", ev.finding.description, legacyDesc);
  ok("original finding snapshot gains no invented hosts", ev.finding.affected_hosts === undefined);
  ok("prose is never parsed into a host", !/publicly accessible/.test(after.asset_ref));
  const healEvents = await listManagedCaseEvents(env, "ws_case", "case_legacy");
  ok("enrichment is audited as an append-only event",
     healEvents.some((e) => e.action === "affected_hosts_enriched" && e.detail?.asset_ref_replaced === true
       && e.detail?.reason === "legacy_asset_ref_not_a_host"));
  ok("no duplicate case was opened for the healed finding",
     (await listManagedCases(env, "ws_case")).filter((c) => c.finding_id === "asset_exposure_dev_env").length === 1);

  // Idempotent: re-observing the same hosts again must not append a second event.
  const eventsBefore = (await listManagedCaseEvents(env, "ws_case", "case_legacy")).length;
  await createManagedAsmCasesForScan("scan_heal2", "dom_case", "case-example.com", [{
    id: "asset_exposure_dev_env", module: "asset_exposure", severity: "medium", title: "Dev env exposed",
    affected_hosts: ["legacy.case-example.com", "staging.case-example.com"],
  }], [], env);
  eq("re-observing identical hosts is idempotent (no event churn)",
     (await listManagedCaseEvents(env, "ws_case", "case_legacy")).length, eventsBefore);
}

console.log(`\nASM remediation loop: ${pass}/${pass + fail} passed`);
if (fail) { console.error("asm-remediation-loop validation FAILED"); process.exit(1); }
console.log("asm-remediation-loop validation passed");
