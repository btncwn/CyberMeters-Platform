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
  caseGuidanceForRow,
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

// The scan's probe record for a host that answered: by default a page that is not
// a management tool.
const answered = (host, extra = {}) => ({
  host, url: `https://${host}/`, status: 200, reachable: true, title: "Welcome", server: "nginx", tech: [],
  attempts: [{ protocol: "https", port: 443, outcome: "responded", status: 200 }], ...extra,
});

// Absence only verifies when the DETECTING module can be shown to have run clean,
// and the affected host (here the domain itself: the finding names no host) was
// re-checked and answered without the tool.
const completeAdminScan = {
  modules: { admin_surface_detection: {}, asset_exposure: { assets: [answered("case-example.com")] } },
  scanQuality: { status: "complete", modules_skipped: [] },
};
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

// Same finding absent, module completed cleanly on a complete scan, and the
// affected host answered without the tool → resolve.
const cleanRun = await verifyManagedAsmCasesForScan("scan_g4", "dom_case", "case-example.com", [], env, {
  modules: { admin_surface_detection: {}, asset_exposure: { assets: [answered("case-example.com")] } },
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

// ── The re-check must re-test the old problem on the affected host ───────────
// A management-page case closes only when the same host answers without the
// tool, or its name is confirmed removed. Silence, a refused connection, a
// filter's 401/403/429, an origin or edge 5xx, a name that stopped resolving but
// is not yet confirmed removed, or a host the scan did not probe leave it
// waiting, with the reason recorded — none of them re-tests the problem.
{
  const host = "tools.case-example.com";
  await createManagedAsmCasesForScan("scan_r0", "dom_case", "case-example.com", [{
    id: "admin_surface_medium", module: "admin_surface_detection", severity: "medium",
    title: "Admin page exposed", affected_hosts: [host],
  }], [], env);
  const recheckCase = (await listManagedCases(env, "ws_case")).find((c) => c.finding_id === "admin_surface_medium");
  let r = await getManagedCase(env, "ws_case", recheckCase.id);
  r = (await transitionManagedCase(env, r, "triage", { actor_type: "customer", actor_id: "user1" })).case;
  r = (await assignManagedCaseOwner(env, r, { owner_type: "team", owner_ref: "IT", assigned_by: "customer", actor_id: "user1" })).case;
  r = (await transitionManagedCase(env, r, "remediation_in_progress", { actor_type: "customer", actor_id: "user1" })).case;
  await transitionManagedCase(env, r, "verification_requested", { actor_type: "customer", actor_id: "user1", action: "fix_completed" });
  const complete = { status: "complete", modules_skipped: [] };
  const scanWith = (assets) => ({ modules: { admin_surface_detection: {}, asset_exposure: { assets } }, scanQuality: complete, observedAt: "2026-10-05T10:00:00.000Z" });
  const waiting = [
    ["a timeout", [{ host, status: null, reachable: null, probe_status: "timed_out" }], "affected_host_timed_out", "timed_out"],
    ["a refused connection", [{ host, status: null, reachable: false, attempts: [{ protocol: "https", port: 443, outcome: "refused" }, { protocol: "http", port: 80, outcome: "refused" }] }], "affected_host_no_answer", "no_answer"],
    ["a filter's 403", [answered(host, { status: 403, title: null })], "affected_host_access_restricted", "access_restricted"],
    ["an edge answer with no origin behind it", [{ host, status: 530, reachable: false, probe_status: "origin_unreachable" }], "affected_host_no_origin", "no_origin"],
    ["an origin 5xx", [{ host, status: 503, reachable: false, probe_status: "server_error" }], "affected_host_server_error", "server_error"],
    ["a host this scan did not probe", [], "affected_host_not_rechecked", "not_rechecked"],
    ["a name that stopped resolving, removal not confirmed", [{ host, status: null, reachable: null, probe_status: "not_applicable" }], "affected_host_name_not_resolving", "name_not_resolving"],
  ];
  for (const [label, assets, reason, outcome] of waiting) {
    const scanId = `scan_r_${outcome}`;
    const run = await verifyManagedAsmCasesForScan(scanId, "dom_case", "case-example.com", [], env, scanWith(assets));
    const current = await getManagedCase(env, "ws_case", recheckCase.id);
    const deferral = (await listManagedCaseEvents(env, "ws_case", recheckCase.id))
      .find((e) => e.action === "verification_deferred" && e.detail?.scan_id === scanId);
    ok(`${label} never closes the case`, run.resolved === 0 && current.status === "verification_requested");
    ok(`${label} is recorded as the reason it stays open`,
      deferral?.detail?.reason === reason && deferral?.detail?.recheck?.hosts?.[0]?.outcome === outcome);
  }
  const stillThere = await verifyManagedAsmCasesForScan("scan_r_present", "dom_case", "case-example.com", [], env,
    scanWith([answered(host, { title: "Jira Dashboard" })]));
  r = await getManagedCase(env, "ws_case", recheckCase.id);
  ok("the tool still answering on the host fails verification, with the host's re-check",
    stillThere.failed === 1 && r.status === "verification_failed" &&
      (await listManagedCaseEvents(env, "ws_case", recheckCase.id)).some((e) => e.action === "verification_failed" && e.detail?.recheck?.hosts?.[0]?.outcome === "still_present"));
  r = (await transitionManagedCase(env, r, "remediation_in_progress", { actor_type: "customer", actor_id: "user1" })).case;
  await transitionManagedCase(env, r, "verification_requested", { actor_type: "customer", actor_id: "user1", action: "fix_completed" });
  const fixedRun = await verifyManagedAsmCasesForScan("scan_r_fixed", "dom_case", "case-example.com", [], env,
    scanWith([answered(host, { status: 302, title: null, attempts: [{ protocol: "https", port: 443, outcome: "responded", status: 302 }] }),
      { host: "gone.case-example.com", status: null, reachable: null, probe_status: "not_applicable" }]));
  r = await getManagedCase(env, "ws_case", recheckCase.id);
  ok("the host answering without the tool closes the case, though another name stopped resolving",
    fixedRun.resolved >= 1 && r.status === "resolved");
  const verifiedEvent = (await listManagedCaseEvents(env, "ws_case", recheckCase.id)).find((e) => e.action === "verified_resolved");
  const evidence = verifiedEvent?.detail?.verification_evidence;
  ok("the closure keeps its evidence: method, result, type, the scan's time and each host's re-check",
    evidence?.verification_method === "rescan" && evidence?.verification_result === "fixed" &&
      evidence?.evidence_type === "host_reobservation" && evidence?.observed_at === "2026-10-05T10:00:00.000Z" &&
      JSON.stringify(evidence?.observation?.recheck?.hosts) === JSON.stringify([{ hostname: host, outcome: "answered_without_tool", status: 302, protocol: "https", port: 443 }]));

  // ── What the case page says (engines/case-guidance.js) ─────────────────────
  const rawEvents = db.prepare("SELECT action, detail_json, created_at FROM managed_case_events WHERE case_id = ? ORDER BY rowid").all(recheckCase.id);
  const upTo = (scanId, action) => rawEvents.slice(0, rawEvents.findIndex((e) => e.action === action && JSON.parse(e.detail_json || "{}").scan_id === scanId) + 1);
  const resolvedRow = await getManagedCase(env, "ws_case", recheckCase.id);
  const waitingGuidance = caseGuidanceForRow({ ...resolvedRow, status: "verification_requested" },
    { phase: "awaiting_verification", support: "automated", events: upTo("scan_r_no_answer", "verification_deferred") });
  ok("the case page states the canonical action and how the fix is re-checked, never an invented one",
    waitingGuidance.remediation?.recommended_action === "Limit each admin interface to trusted IP ranges, or place it behind a VPN or MFA-protected gateway." &&
      waitingGuidance.recheck?.method === "rescan" && /never closes the case/.test(waitingGuidance.recheck?.rule || ""));
  ok("a refused connection reads as not confirmed, with the host's answer and why it is not proof",
    waitingGuidance.last_recheck?.outcome === "waiting" && waitingGuidance.last_recheck?.label === "Not confirmed yet" &&
      /A blocked connection is not proof/.test(waitingGuidance.last_recheck?.reason || "") &&
      waitingGuidance.last_recheck?.hosts?.[0]?.label === `${host} refused or dropped the connection.` &&
      waitingGuidance.closure === null);
  const failedGuidance = caseGuidanceForRow({ ...resolvedRow, status: "verification_failed" },
    { phase: "action_in_progress", support: "automated", events: upTo("scan_r_present", "verification_failed") });
  ok("a tool still answering reads as still present on that host",
    failedGuidance.last_recheck?.outcome === "still_present" && /still answers with the tool \(HTTPS port 443, HTTP 200\)/.test(failedGuidance.last_recheck?.hosts?.[0]?.label || ""));
  const verifiedGuidance = caseGuidanceForRow(resolvedRow, { phase: "verified", support: "automated", events: rawEvents });
  ok("a verified case states CyberMeters verified it, at the scan's time, on the host's own answer",
    verifiedGuidance.closure?.kind === "verified" && verifiedGuidance.closure?.at === "2026-10-05T10:00:00.000Z" &&
      verifiedGuidance.last_recheck?.label === "Fixed — verified by CyberMeters" &&
      verifiedGuidance.last_recheck?.hosts?.[0]?.label === `${host} answered without the tool (HTTPS port 443, HTTP 302).`);
  ok("a case your team closed, accepted or attested is never worded as verified by CyberMeters",
    caseGuidanceForRow({ ...resolvedRow, verified_at: null, status: "closed", closed_at: "2026-10-06T09:00:00Z" }, { phase: "closed_no_action", support: "automated", events: [] }).closure?.kind === "closed_by_customer" &&
      caseGuidanceForRow({ ...resolvedRow, status: "risk_accepted", risk_accepted_until: "2026-09-30T00:00:00Z" }, { phase: "accepted_risk", support: "automated", events: [] }).closure?.label === "Risk accepted by your team until 2026-09-30" &&
      caseGuidanceForRow({ ...resolvedRow, case_type: "identity_case" }, { phase: "verified", support: "manual", events: [] }).closure?.kind === "attested");

  // The tool comes back: the scan's own sighting is the latest re-check, so the
  // reopened case never still reads "fixed".
  await createManagedAsmCasesForScan("scan_r_back", "dom_case", "case-example.com", [{
    id: "admin_surface_medium", module: "admin_surface_detection", severity: "medium",
    title: "Admin page exposed", affected_hosts: [host],
  }], [], env);
  const reopenedRow = await getManagedCase(env, "ws_case", recheckCase.id);
  const reopenedGuidance = caseGuidanceForRow(reopenedRow, { phase: "action_in_progress", support: "automated",
    events: db.prepare("SELECT action, actor_type, to_status, detail_json, created_at FROM managed_case_events WHERE case_id = ? ORDER BY rowid").all(recheckCase.id) });
  ok("a case CyberMeters reopened shows the scan that saw it again, never the earlier fix",
    reopenedRow.status === "remediation_in_progress" && Number(reopenedRow.reopened_count) === 1 &&
      reopenedGuidance.last_recheck?.outcome === "still_present" && reopenedGuidance.last_recheck?.scan_id === "scan_r_back" &&
      reopenedGuidance.last_recheck?.label === "Seen again — the case was reopened" && reopenedGuidance.closure === null);
}

// ── Closed outcomes stay distinct, and a finding seen again keeps its history ──
// A finding your team marked as not a real problem is not re-opened as a new
// case while it is seen on the same hosts; seen on new hosts, it opens a case
// that points back. A finding seen again after your team closed its case opens a
// new case linked both ways (closed is terminal; nothing is reopened in place).
{
  const fpHost = "legacy-app.case-example.com";
  const fpFinding = { id: "asset_exposure_dev_env", module: "asset_exposure", severity: "medium", title: "Dev env exposed", affected_hosts: [fpHost] };
  db.prepare("DELETE FROM managed_cases WHERE workspace_id = 'ws_case' AND finding_id = 'asset_exposure_dev_env'").run();
  await createManagedAsmCasesForScan("scan_fp1", "dom_case", "case-example.com", [fpFinding], [], env);
  let fp = (await listManagedCases(env, "ws_case")).find((c) => c.finding_id === "asset_exposure_dev_env");
  let fpRow = await getManagedCase(env, "ws_case", fp.id);
  fpRow = (await transitionManagedCase(env, fpRow, "triage", { actor_type: "customer", actor_id: "user1" })).case;
  const marked = await transitionManagedCase(env, fpRow, "false_positive", { actor_type: "customer", actor_id: "user1", reason: "A test page, not reachable by customers" });
  ok("your team can mark a finding as not a real problem, with a reason", marked.ok && marked.case.status === "false_positive");
  await createManagedAsmCasesForScan("scan_fp2", "dom_case", "case-example.com", [fpFinding], [], env);
  await createManagedAsmCasesForScan("scan_fp3", "dom_case", "case-example.com", [fpFinding], [], env);
  const devCases = () => db.prepare("SELECT * FROM managed_cases WHERE workspace_id = 'ws_case' AND finding_id = 'asset_exposure_dev_env' ORDER BY created_at, id").all();
  ok("a finding marked not a real problem is not opened again on the same hosts", devCases().length === 1);
  const fpEvents = await listManagedCaseEvents(env, "ws_case", fp.id);
  ok("each later sighting is recorded on the marked case, once per scan",
    fpEvents.filter((e) => e.action === "seen_again_marked_not_a_problem").length === 2);
  ok("the case page says it is still seen and stays marked",
    /stays marked as not a real problem/.test(caseGuidanceForRow(await getManagedCase(env, "ws_case", fp.id), { phase: "false_positive", support: "automated", events: db.prepare("SELECT action, detail_json, created_at FROM managed_case_events WHERE case_id = ? ORDER BY rowid").all(fp.id) }).continuity?.still_seen?.label || ""));
  await createManagedAsmCasesForScan("scan_fp4", "dom_case", "case-example.com", [{ ...fpFinding, affected_hosts: [fpHost, "new-dev.case-example.com"] }], [], env);
  const afterNewHost = devCases();
  ok("seen on a new host, it opens a new case that points back to the marked one",
    afterNewHost.length === 2 && JSON.parse(afterNewHost[1].evidence_json).previous_case?.id === fp.id &&
      JSON.parse(afterNewHost[1].evidence_json).previous_case?.status === "false_positive");

  // Closed by your team, then seen again.
  let open = await getManagedCase(env, "ws_case", afterNewHost[1].id);
  open = (await transitionManagedCase(env, open, "triage", { actor_type: "customer", actor_id: "user1" })).case;
  open = (await assignManagedCaseOwner(env, open, { owner_type: "team", owner_ref: "IT", assigned_by: "customer", actor_id: "user1" })).case;
  open = (await transitionManagedCase(env, open, "remediation_in_progress", { actor_type: "customer", actor_id: "user1" })).case;
  const closed = await transitionManagedCase(env, open, "closed", { actor_type: "customer", actor_id: "user1" });
  ok("your team can close a case without a re-check", closed.ok && closed.case.status === "closed");
  // The latest earlier case is now the closed one; the host your team marked
  // stays marked all the same.
  await createManagedAsmCasesForScan("scan_fp4b", "dom_case", "case-example.com", [fpFinding], [], env);
  ok("a host your team marked is not opened again because a later case on other hosts was closed",
    devCases().length === 2 &&
      (await listManagedCaseEvents(env, "ws_case", fp.id)).some((e) => e.action === "seen_again_marked_not_a_problem" && e.detail?.scan_id === "scan_fp4b"));
  await createManagedAsmCasesForScan("scan_fp5", "dom_case", "case-example.com", [{ ...fpFinding, affected_hosts: ["new-dev.case-example.com"] }], [], env);
  const afterClose = devCases();
  const reopenedAs = afterClose[2];
  ok("seen again after a closure, it opens a new case linked to the closed one",
    afterClose.length === 3 && JSON.parse(reopenedAs.evidence_json).previous_case?.id === closed.case.id &&
      JSON.parse(reopenedAs.evidence_json).previous_case?.status === "closed");
  const closedEvents = db.prepare("SELECT action, to_status, detail_json, created_at FROM managed_case_events WHERE case_id = ? ORDER BY rowid").all(closed.case.id);
  ok("the closed case records that it was seen again, and keeps its whole history",
    closedEvents.some((e) => e.action === "seen_again" && JSON.parse(e.detail_json).new_case_id === reopenedAs.id) &&
      closedEvents.some((e) => e.action === "case_created") && closedEvents.some((e) => e.to_status === "closed"));
  const closedGuidance = caseGuidanceForRow(await getManagedCase(env, "ws_case", closed.case.id), { phase: "closed_no_action", support: "automated", events: closedEvents });
  const newGuidance = caseGuidanceForRow(reopenedAs, { phase: "detected", support: "automated", events: [] });
  ok("both cases point at each other on the case page, and the closure reads as your team's, not a verification",
    closedGuidance.closure?.kind === "closed_by_customer" && closedGuidance.continuity?.next_case?.case_id === reopenedAs.id &&
      newGuidance.continuity?.previous_case?.case_id === closed.case.id && /closed/.test(newGuidance.continuity?.previous_case?.label || ""));
}

console.log(`\nASM remediation loop: ${pass}/${pass + fail} passed`);
if (fail) { console.error("asm-remediation-loop validation FAILED"); process.exit(1); }
console.log("asm-remediation-loop validation passed");
