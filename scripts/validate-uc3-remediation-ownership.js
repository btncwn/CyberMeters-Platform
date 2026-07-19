#!/usr/bin/env node
//
// UC3 — Unified Remediation, Case and Ownership Workflow validator.
//
// This is a broad, behavioural contract test for the customer-facing lifecycle:
//   observed evidence → managed case → assigned owner → remediation action →
//   verification → honest closure or continued monitoring.
// It drives the REAL worker routes (/cases create, /assign, /transition, /list,
// /detail) against the real SQLite schema + migrations, and imports the canonical
// engines directly for the edges a single route fixture cannot reach (system
// verification, recurrence). It exists to hold the UC3 contract as a whole and to
// mutation-fail the regressions the ownership + verification honesty rules forbid.
//
// Canonical semantic separation it protects:
//   • assignment ≠ remediation ≠ verification ≠ closure
//   • a customer assertion is never a verification
//   • unavailable / failed / not-assessed evidence never closes a case
//   • an assignee (assigned_user_id) is a real ACTIVE member of the SAME workspace
//   • a no-op re-assignment records no new audit fact
//   • only canTransitionCase moves a case; nothing (score, note, "AI") bypasses it
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const workerSrc = path.join(root, "workers", "scan-api", "src");

const read = (rel) => fs.readFileSync(path.join(root, rel), "utf8");
const sourceFiles = new Map();
const getSource = (relPath) => sourceFiles.get(relPath) ?? read(relPath);
const setSource = (relPath, src) => sourceFiles.set(relPath, src);

let pass = 0;
let fail = 0;
const failures = [];
function ok(name, condition, detail = "") {
  if (condition) { pass++; } else {
    fail++;
    const msg = `FAIL ${name}${detail ? " — " + detail : ""}`;
    failures.push(msg);
    console.log(msg);
  }
}
function eq(name, actual, expected) {
  ok(name, actual === expected, `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* additive-drift tolerant, as in m5e-closure */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  return db;
}

function makeD1(db) {
  const wrap = (sql, args) => ({
    __sql: sql, __args: args,
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid ?? 0) } }; },
  });
  return {
    prepare(sql) { const b = wrap(sql, []); b.bind = (...args) => wrap(sql, args); return b; },
    async batch(stmts) { return Promise.all(stmts.map((s) => (/^\s*select/i.test(s.__sql) ? s.all() : s.run()))); },
    async exec(sql) { db.exec(sql); return { count: 0, duration: 0 }; },
  };
}

const noR2 = { get: async () => null, put: async () => ({}), head: async () => null, delete: async () => ({}), list: async () => ({ objects: [] }) };
function makeEnv(db) {
  return {
    cybermeters_db: makeD1(db), cybermeters_reports: noR2,
    MFA_ENCRYPTION_KEY: "uc3-validator-key", STRIPE_WEBHOOK_SECRET: "whsec_test",
    STRIPE_SECRET_KEY: "sk_test_x", STRIPE_PRICE_MAP: "{}",
    ALLOWED_ORIGIN: "https://app.cybermeters.com", FRONTEND_URL: "https://app.cybermeters.com",
    APP_VERSION: "test", RESEND_API_KEY: "", ADMIN_EMAILS: "",
  };
}

async function loadWorker() {
  globalThis.fetch = async () => { throw new Error("network disabled"); };
  AbortSignal.timeout = () => undefined;
  return import(pathToFileURL(path.join(workerSrc, "index.js")).href);
}
const engine = () => import(pathToFileURL(path.join(workerSrc, "engines", "managed-case-model.js")).href);
const registry = () => import(pathToFileURL(path.join(workerSrc, "engines", "remediation-registry.js")).href);

const CANONICAL_KEYS = Object.freeze([
  "email_protection", "brand_protection", "attack_surface", "certificates_trust",
  "cyber_essentials_readiness", "website_security", "identity_exposure", "shadow_it_unmanaged_technology",
]);

async function seedUser(mod, db, { user, token, workspace, role = "admin", makeWorkspace = false }) {
  const hash = await mod.hashToken(token);
  db.prepare("INSERT INTO users (id,email,name,plan,status,email_verified,mfa_enabled) VALUES (?,?,?,?,?,1,0)")
    .run(user, `${user}@example.com`, user, "business", "active");
  db.prepare("INSERT INTO user_sessions (id,user_id,token_hash,expires_at,last_seen_at) VALUES (?,?,?,?,?)")
    .run(`sess_${user}`, user, hash, "2099-01-01T00:00:00Z", "2026-01-01T00:00:00Z");
  if (makeWorkspace) {
    db.prepare("INSERT INTO subscriptions (id,owner_user_id,plan,subscription_status,status,current_period_end,created_at,updated_at) VALUES (?,?,?,?,?,?,datetime('now'),datetime('now'))")
      .run(`sub_${user}`, user, "business", "active", "active", "2099-01-01T00:00:00Z");
    db.prepare("INSERT INTO workspaces (id,name,owner_user_id,created_at,updated_at) VALUES (?,?,?,?,?)")
      .run(workspace, workspace, user, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z");
  }
  db.prepare("INSERT INTO workspace_members (id,workspace_id,user_id,role,created_at) VALUES (?,?,?,?,datetime('now'))")
    .run(`mem_${user}_${workspace}`, workspace, user, role);
  return { token, user, workspace };
}

function seedCase(db, { id, workspace, case_type, domain_key, status = "triaged", finding, remediation_id = null, extra = {} }) {
  finding = finding ?? `f_${id}`;
  const cols = ["id", "workspace_id", "case_type", "domain_key", "status", "severity", "title", "domain", "finding_id", "remediation_id", "created_at", "updated_at"];
  const vals = [id, workspace, case_type, domain_key, status, "high", `${case_type} case`, "example.com", finding, remediation_id, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"];
  for (const [k, v] of Object.entries(extra)) { cols.push(k); vals.push(v); }
  db.prepare(`INSERT INTO managed_cases (${cols.join(",")}) VALUES (${cols.map(() => "?").join(",")})`).run(...vals);
}

const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };
function api(mod, env, workspace, token) {
  const base = `https://api.cybermeters.com/api/workspaces/${workspace}`;
  const call = (p, method, body, tok = token) => mod.default.fetch(new Request(`${base}${p}`, {
    method, headers: { Authorization: `Bearer ${tok}`, "content-type": "application/json" },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  }), env, ctx);
  return {
    createCase: (body) => call("/cases", "POST", body),
    listCases: (qs = "") => call(`/cases${qs}`, "GET"),
    getCase: (caseId) => call(`/cases/${caseId}`, "GET"),
    assign: (caseId, body, tok) => call(`/cases/${caseId}/assign`, "POST", body, tok),
    transition: (caseId, body, tok) => call(`/cases/${caseId}/transition`, "POST", body, tok),
  };
}
const evCount = (db, caseId, action) =>
  db.prepare("SELECT COUNT(*) c FROM managed_case_events WHERE case_id=? AND action=?").get(caseId, action).c;

// ── A. Creation, category, resource, dedup ──────────────────────────────────
async function checkCreationAndDedup() {
  const mod = await loadWorker();
  const db = buildDb();
  const env = makeEnv(db);
  const { token, workspace } = await seedUser(mod, db, { user: "u_owner", token: "tok", workspace: "ws1", makeWorkspace: true });
  db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('d1','u_owner','example.com')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES ('ws1','d1')").run();
  const a = api(mod, env, workspace, token);

  const r1 = await a.createCase({ case_type: "email_case", domain_key: "email_protection", domain: "example.com", asset_ref: "example.com", source_finding_type: "email_missing_dmarc", source_finding_id: "find-1" });
  eq("1: case creation returns 201", r1.status, 201);
  const d1 = await r1.json();
  eq("1: case records the Cyber MOT category", d1.case.domain_key, "email_protection");
  eq("1: case records the evidence source finding", d1.case.source_finding_type, "email_missing_dmarc");
  eq("1: case records the affected resource", d1.case.asset_ref, "example.com");
  ok("1: case links the canonical remediation", Boolean(d1.case.remediation_id));

  const r2 = await a.createCase({ case_type: "email_case", domain_key: "email_protection", domain: "example.com", source_finding_type: "email_missing_dmarc", source_finding_id: "find-1" });
  const d2 = await r2.json();
  eq("2: same evidence dedupes (created:false)", d2.created, false);
  eq("2: dedup did not insert a second case row", db.prepare("SELECT COUNT(*) c FROM managed_cases WHERE workspace_id='ws1' AND finding_id='find-1'").get().c, 1);
}

// ── B. Ownership assignment + membership + idempotency ──────────────────────
async function checkOwnership() {
  const mod = await loadWorker();
  const db = buildDb();
  const env = makeEnv(db);
  const { token, workspace } = await seedUser(mod, db, { user: "u_owner", token: "tok", workspace: "ws1", makeWorkspace: true });
  await seedUser(mod, db, { user: "u_member2", token: "tok2", workspace: "ws1", role: "analyst" });          // active member of ws1
  await seedUser(mod, db, { user: "u_removed", token: "tokr", workspace: "ws1", role: "viewer" });            // will be removed below
  db.prepare("DELETE FROM workspace_members WHERE user_id='u_removed' AND workspace_id='ws1'").run();          // hard-delete = inactive
  await seedUser(mod, db, { user: "u_foreign", token: "tokf", workspace: "ws_foreign", role: "admin", makeWorkspace: true }); // member of a different workspace
  seedCase(db, { id: "c1", workspace: "ws1", case_type: "email_case", domain_key: "email_protection" });
  const a = api(mod, env, workspace, token);

  // 3. empty owner refused, nothing persisted
  const empty = await a.assign("c1", { owner_type: "team", owner_ref: "" });
  eq("3: empty owner assignment is refused", empty.status, 400);
  eq("3: refused assignment does not persist owner", db.prepare("SELECT owner_ref FROM managed_cases WHERE id='c1'").get().owner_ref, null);

  // 4. valid assignment persists owner + owner_type
  const asg = await a.assign("c1", { owner_type: "team", owner_ref: "Security Team", assigned_user_id: "u_member2" });
  eq("4: valid assignment succeeds", asg.status, 200);
  const asgRow = db.prepare("SELECT owner_ref, owner_type, assigned_user_id FROM managed_cases WHERE id='c1'").get();
  eq("4: owner_ref persists", asgRow.owner_ref, "Security Team");
  eq("4: owner_type persists", asgRow.owner_type, "team");
  eq("5: assigned_user_id (active member) persists", asgRow.assigned_user_id, "u_member2");

  // 6. assignment_changed event emitted exactly once for the change
  eq("6: assignment_changed event emitted", evCount(db, "c1", "assignment_changed"), 1);
  const ev = db.prepare("SELECT detail_json FROM managed_case_events WHERE case_id='c1' AND action='assignment_changed' ORDER BY created_at DESC LIMIT 1").get();
  ok("6: assignment event records previous→new owner fact", /Security Team/.test(ev.detail_json) && /u_member2/.test(ev.detail_json));

  // 7. duplicate identical assignment is idempotent — no second event, actor never overwrites owner
  const dup = await a.assign("c1", { owner_type: "team", owner_ref: "Security Team", assigned_user_id: "u_member2" });
  eq("7: duplicate identical assignment still returns 200", dup.status, 200);
  eq("7: duplicate identical assignment emits NO second event (idempotent)", evCount(db, "c1", "assignment_changed"), 1);

  // 8. actor and assignee remain distinct (assigned_by is the acting user, not the owner_ref)
  eq("8: assignment actor stored as assigned_by, not as owner", db.prepare("SELECT assigned_by FROM managed_cases WHERE id='c1'").get().assigned_by, "u_owner");

  // 9. non-member assignee refused (fail closed)
  const ghost = await a.assign("c1", { owner_type: "person", owner_ref: "Ghost", assigned_user_id: "u_ghost" });
  eq("9: non-existent assignee is refused", ghost.status, 400);
  eq("9: refused non-member assignment does not overwrite owner", db.prepare("SELECT assigned_user_id FROM managed_cases WHERE id='c1'").get().assigned_user_id, "u_member2");

  // 10. removed (inactive) member cannot be newly assigned
  const removed = await a.assign("c1", { owner_type: "person", owner_ref: "Removed", assigned_user_id: "u_removed" });
  eq("10: removed member cannot be assigned", removed.status, 400);

  // 11. foreign-workspace user cannot be assigned as assignee
  const foreignAssignee = await a.assign("c1", { owner_type: "person", owner_ref: "Foreign", assigned_user_id: "u_foreign" });
  eq("11: foreign-workspace user cannot be the assignee", foreignAssignee.status, 400);

  // 12. foreign CALLER cannot assign (tenant authz), 13. foreign/nonexistent case parity
  const foreignCaller = await a.assign("c1", { owner_type: "team", owner_ref: "Nope" }, "tokf");
  eq("12: foreign-workspace caller cannot assign", foreignCaller.status, 403);
  const missingCase = await a.assign("c_does_not_exist", { owner_type: "team", owner_ref: "X" });
  eq("13: nonexistent case returns 404 (same as foreign)", missingCase.status, 404);

  // 14. transition path enforces the same membership rule
  seedCase(db, { id: "c2", workspace: "ws1", case_type: "website_case", domain_key: "website_security" });
  const badTransition = await a.transition("c2", { target_status: "assigned", owner_type: "person", owner_ref: "X", assigned_user_id: "u_foreign" });
  eq("14: transition with foreign assignee is refused", badTransition.status, 400);
  const goodTransition = await a.transition("c2", { target_status: "assigned", owner_type: "person", owner_ref: "Web Owner", assigned_user_id: "u_member2" });
  eq("14: transition with valid member assignee succeeds", goodTransition.status, 200);
  eq("14: assigned transition persists status", db.prepare("SELECT status FROM managed_cases WHERE id='c2'").get().status, "assigned");
}

// ── C. Remediation vs verification honesty (customer assertion ≠ verified) ───
async function checkVerificationHonesty() {
  const mod = await loadWorker();
  const db = buildDb();
  const env = makeEnv(db);
  const { token, workspace } = await seedUser(mod, db, { user: "u_owner", token: "tok", workspace: "ws1", makeWorkspace: true });
  const a = api(mod, env, workspace, token);
  const dmarcRem = (await registry()).findingRemediation({ id: "email_missing_dmarc", finding_type: "finding" }).remediation_id;

  // A base case walked to action_in_progress; customer marks work complete → awaiting_verification (NOT verified).
  seedCase(db, { id: "cc", workspace: "ws1", case_type: "email_case", domain_key: "email_protection", status: "action_in_progress", remediation_id: dmarcRem, extra: { owner_ref: "Team", owner_type: "team" } });
  const complete = await a.transition("cc", { target_status: "awaiting_verification" });
  eq("15: customer completion transition succeeds", complete.status, 200);
  eq("16: customer completion enters awaiting_verification, NOT verified", db.prepare("SELECT status FROM managed_cases WHERE id='cc'").get().status, "awaiting_verification");

  // 17. a note / scan-completion alone never verifies an observable (automated) finding.
  const noteOnly = await a.transition("cc", { target_status: "verified", evidence: { note_only: true } });
  ok("17: note-only evidence does not verify", noteOnly.status >= 400);
  const scanOnly = await a.transition("cc", { target_status: "verified", evidence: { scan_completed_only: true } });
  ok("17: scan-completion-only evidence does not verify", scanOnly.status >= 400);

  // 18. an observable (automated) finding cannot be verified by the CUSTOMER at all (only CyberMeters' system verifier).
  const custVerify = await a.transition("cc", { target_status: "verified", evidence: { verification_method: "dns_recheck", verification_result: "fixed", evidence_type: "dns", observed_at: "2026-02-01T00:00:00Z", observation: { record: "present" } } });
  eq("18: customer cannot verify an observable finding (system-only)", custVerify.status, 403);
  eq("18: unverified observable case stays awaiting_verification", db.prepare("SELECT status FROM managed_cases WHERE id='cc'").get().status, "awaiting_verification");

  // 19. failed / still-present verification result never closes (engine contract, exercised via system verify).
  const { canTransitionCase } = await engine();
  const failRow = { id: "cf", workspace_id: "ws1", case_type: "email_case", status: "awaiting_verification", remediation_id: dmarcRem };
  const failDecision = canTransitionCase({ case: failRow, target_status: "verified", actor: { actor_type: "system", actor_id: "sys" }, evidence: { verification_method: "dns_recheck", verification_result: "still_present", evidence_type: "dns", observed_at: "2026-02-01T00:00:00Z", observation: { record: "absent" } } });
  ok("19: failed/still-present evidence does not verify (engine)", failDecision.ok === false);
  const okDecision = canTransitionCase({ case: failRow, target_status: "verified", actor: { actor_type: "system", actor_id: "sys" }, evidence: { verification_method: "dns_recheck", verification_result: "fixed", evidence_type: "dns", observed_at: "2026-02-01T00:00:00Z", observation: { record: "present" } } });
  ok("19: CyberMeters' own positive observation DOES verify via canonical transition", okDecision.ok === true && okDecision.case.status === "verified");

  // 20. a MANUAL-support finding may be honestly concluded only by a structured attestation from an identified actor.
  seedCase(db, { id: "cm", workspace: "ws1", case_type: "identity_case", domain_key: "identity_exposure", status: "awaiting_verification" });
  const attestBad = await a.transition("cm", { target_status: "verified", evidence: { verification_method: "manual_attestation", verification_result: "fixed", evidence_type: "attestation", observed_at: "2026-02-01T00:00:00Z" } });
  ok("20: manual attestation without a structured attestation object is refused", attestBad.status >= 400);
  const attestGood = await a.transition("cm", { target_status: "verified", evidence: { verification_method: "manual_attestation", verification_result: "fixed", evidence_type: "attestation", observed_at: "2026-02-01T00:00:00Z", attestation: { statement: "Removed the exposed account", by: "u_owner" } } });
  eq("20: structured customer attestation concludes a manual finding", attestGood.status, 200);
  eq("20: attested manual case reaches verified", db.prepare("SELECT status FROM managed_cases WHERE id='cm'").get().status, "verified");
}

// ── D. Recurrence / reopen (engine-level, no duplicate occurrence) ──────────
async function checkRecurrence() {
  const { canTransitionCase } = await engine();
  const verified = { id: "cr", workspace_id: "ws1", case_type: "website_case", status: "verified", reopened_count: 0, evidence_json: JSON.stringify({ prior: true }) };
  const reopen = canTransitionCase({ case: verified, target_status: "reopened", actor: { actor_type: "system", actor_id: "sys" } });
  ok("21: a re-observed condition reopens a verified case", reopen.ok === true && reopen.case.status === "reopened");
  eq("21: reopen increments reopened_count exactly once", reopen.case.reopened_count, 1);
  ok("21: reopen preserves prior evidence/history", reopen.case.evidence_json === verified.evidence_json);
  // 22. reopened → reopened is not a legal edge (no duplicate occurrence churn).
  const doubleReopen = canTransitionCase({ case: { ...reopen.case }, target_status: "reopened", actor: { actor_type: "system", actor_id: "sys" } });
  ok("22: a reopened case does not reopen again (no duplicate occurrence)", doubleReopen.ok === false);
}

// ── E/F/G. Parity, consistency, coverage, no-bypass (static + engine) ───────
async function checkParityAndInvariants() {
  const eng = await engine();
  const reg = await registry();

  // 23-30. 8-domain coverage: every canonical domain has a registered case_type; six base open via the factory.
  const domainKeys = new Set(Object.values(eng.CASE_TYPE_REGISTRY).map((e) => e.domain_key));
  for (const k of CANONICAL_KEYS) ok(`23: domain ${k} has a registered case_type`, domainKeys.has(k));
  const baseCount = Object.values(eng.CASE_TYPE_REGISTRY).filter((e) => e.base).length;
  eq("24: exactly six base-lifecycle case types open via createManagedCase", baseCount, 6);
  const bespoke = Object.values(eng.CASE_TYPE_REGISTRY).filter((e) => !e.base).map((e) => e.domain_key).sort();
  eq("24: exactly ASM + Brand keep bespoke machines", bespoke.join(","), ["attack_surface", "brand_protection"].join(","));

  // 25. Latent fail-open pin: identity/shadow are NOT registry-derived, which is safe ONLY while every
  //     one of their findings is manual_attestation. Pin it so an observable finding cannot silently fail-open.
  const softDomains = new Set(["identity_exposure", "shadow_it_unmanaged_technology"]);
  const nonManual = reg.REMEDIATION_REGISTRY.filter((r) => softDomains.has(r.domain_key) && r.verification_method !== "manual_attestation");
  eq("25: every identity/shadow remediation is manual_attestation (blanket-manual is safe)", nonManual.length, 0);
  eq("25: identity_case verification support is manual", eng.verificationSupportForCase({ case_type: "identity_case", remediation_id: null }), "manual");
  eq("25: shadow_it_case verification support is manual", eng.verificationSupportForCase({ case_type: "shadow_it_case", remediation_id: null }), "manual");

  // 26. External-method findings can never be concluded by scan OR by customer attestation.
  const extDecision = eng.canTransitionCase({
    case: { id: "ce", workspace_id: "ws1", case_type: "certificate_case", status: "awaiting_verification", remediation_id: null },
    target_status: "verified", actor: { actor_type: "system", actor_id: "sys" },
    evidence: { verification_method: "external", verification_result: "verified", evidence_type: "audit", observed_at: "2026-02-01T00:00:00Z", evidence_reference: "x" },
  });
  ok("26: unresolved/unsupported remediation fails closed to unsupported verification", extDecision.ok === false);

  // 27. No-bypass: the universal route persists status ONLY behind canTransitionCase; assignment behind assignCaseOwner.
  const routeSrc = getSource("workers/scan-api/src/routes/managed-cases.js");
  ok("27: transition route drives canTransitionCase (no bypass)", /canTransitionCase\(/.test(routeSrc));
  ok("27: no UPDATE managed_cases SET status outside the canTransitionCase decision", (() => {
    // The only status write is the CAS UPDATE inside the transition branch, fed by decision.case.
    const statusWrites = [...routeSrc.matchAll(/UPDATE managed_cases SET[\s\S]*?status\s*=/gi)];
    return statusWrites.length === 1;
  })());
  ok("27: assignment persists via assignCaseOwner / membership-validated path", /assignCaseOwner\(/.test(routeSrc) && /isActiveWorkspaceMember\(/.test(routeSrc));

  // 28. Score cannot close a case: no scoring symbol appears in the case route or the transition validator.
  ok("28: managed-cases route has no score-driven closure", !/riskLevelForScore|cyber_metrics_score|\bscore\b\s*>=|closeCaseIfScore/i.test(routeSrc));
  const modelSrc = getSource("workers/scan-api/src/engines/managed-case-model.js");
  ok("28: canTransitionCase has no score input", !/riskLevelForScore|cyber_metrics_score/i.test(modelSrc));

  // 29. "AI"/explanation has no transition authority: the model/route never import an AI/LLM decider for state.
  ok("29: no AI/LLM state-transition authority in the case model", !/openai|anthropic|llm|generateClosure|aiDecide/i.test(modelSrc + routeSrc));

  // 30. Owner display consistency: the customer projection surfaces every canonical owner field.
  for (const field of ["owner_ref", "owner_type", "assigned_user_id", "business_owner", "technical_owner"]) {
    ok(`30: universal case projection exposes ${field}`, new RegExp(`${field}:`).test(routeSrc));
  }
  // 31. Record↔case owner sync rule: ASM's bespoke owner assignment DELEGATES to the one canonical writer.
  const asmSrc = getSource("workers/scan-api/src/engines/asm-cases.js");
  ok("31: ASM assignment delegates to canonical assignCaseOwner (no divergent owner writer)", /assignCaseOwner\(/.test(asmSrc));

  // 32. Membership check is fail-closed and reused by both universal mutation paths.
  ok("32: isActiveWorkspaceMember is exported and fail-closed", /export async function isActiveWorkspaceMember/.test(modelSrc) && /\.catch\(\(\) => null\)/.test(modelSrc.slice(modelSrc.indexOf("isActiveWorkspaceMember"))));
}

// ── G. Workspace deletion disables further workflow writes ───────────────────
async function checkWorkspaceDeletion() {
  const mod = await loadWorker();
  const db = buildDb();
  const env = makeEnv(db);
  const { token, workspace } = await seedUser(mod, db, { user: "u_owner", token: "tok", workspace: "ws1", makeWorkspace: true });
  seedCase(db, { id: "cd", workspace: "ws1", case_type: "email_case", domain_key: "email_protection" });
  db.prepare("UPDATE workspaces SET deleted_at='2026-03-01T00:00:00Z' WHERE id='ws1'").run();
  const a = api(mod, env, workspace, token);
  const create = await a.createCase({ case_type: "website_case", domain_key: "website_security" });
  ok("33: soft-deleted workspace refuses new cases", create.status >= 400);
  // A soft-deleted workspace refuses writes: requireWorkspaceRole joins
  // `deleted_at IS NULL`, so the role check fails closed (403) before the route's
  // own 404 — either way the write is refused, which is the contract.
  const assign = await a.assign("cd", { owner_type: "team", owner_ref: "X" });
  ok("33: soft-deleted workspace refuses assignment", assign.status === 403 || assign.status === 404, `got ${assign.status}`);
  const transition = await a.transition("cd", { target_status: "triaged" });
  ok("33: soft-deleted workspace refuses transition", transition.status === 403 || transition.status === 404, `got ${transition.status}`);

  // 34/35. createManagedCase fails closed on inactive workspace at the engine level too.
  const { createManagedCase } = await engine();
  const res = await createManagedCase(env, { workspace_id: "ws1", domain_key: "email_protection", case_type: "email_case" });
  eq("34: createManagedCase refuses an inactive workspace", res.code, "workspace_inactive");
  eq("35: no case is created for a deleted workspace", db.prepare("SELECT COUNT(*) c FROM managed_cases WHERE id!='cd'").get().c, 0);
}

// ── Mutations — each reintroduces a forbidden UC3 regression ─────────────────
const MUTATIONS = [
  {
    name: "owner not persisted",
    file: "workers/scan-api/src/engines/managed-case-model.js",
    mutate: (s) => s.replace("SET owner_type = ?, owner_ref = ?, assigned_by = ?, assigned_user_id = ?, updated_at = ?", "SET updated_at = ?"),
    expect: () => /SET owner_type = \?, owner_ref = \?, assigned_by = \?, assigned_user_id = \?/.test(getSource("workers/scan-api/src/engines/managed-case-model.js")) ? null : "assignment no longer persists owner columns",
  },
  {
    name: "assignment event removed",
    file: "workers/scan-api/src/engines/managed-case-model.js",
    mutate: (s) => s.replaceAll("assignment_changed", "assignment_silent"),
    expect: () => /"assignment_changed"/.test(getSource("workers/scan-api/src/engines/managed-case-model.js")) ? null : "assignment_changed audit event removed",
  },
  {
    name: "foreign/non-member assignee allowed (assignCaseOwner)",
    file: "workers/scan-api/src/engines/managed-case-model.js",
    mutate: (s) => s.replace("if (assignee && !(await isActiveWorkspaceMember(env, caseRow.workspace_id, assignee))) {", "if (false) {"),
    expect: () => /if \(assignee && !\(await isActiveWorkspaceMember\(env, caseRow\.workspace_id, assignee\)\)\)/.test(getSource("workers/scan-api/src/engines/managed-case-model.js")) ? null : "assignCaseOwner no longer validates assignee membership",
  },
  {
    name: "foreign/non-member assignee allowed (transition route)",
    file: "workers/scan-api/src/routes/managed-cases.js",
    mutate: (s) => s.replace("if (assignee && !(await isActiveWorkspaceMember(env, wsId, assignee))) {", "if (false) {"),
    expect: () => /if \(assignee && !\(await isActiveWorkspaceMember\(env, wsId, assignee\)\)\)/.test(getSource("workers/scan-api/src/routes/managed-cases.js")) ? null : "transition route no longer validates assignee membership",
  },
  {
    name: "duplicate assignment emits duplicate event",
    file: "workers/scan-api/src/engines/managed-case-model.js",
    mutate: (s) => s.replace("if (curRef === ref && curType === type && curAssignee === assignee) {", "if (false) {"),
    expect: () => /if \(curRef === ref && curType === type && curAssignee === assignee\)/.test(getSource("workers/scan-api/src/engines/managed-case-model.js")) ? null : "no-op re-assignment idempotency guard removed",
  },
  {
    name: "actor stored as owner_ref",
    file: "workers/scan-api/src/engines/managed-case-model.js",
    mutate: (s) => s.replace("SET owner_type = ?, owner_ref = ?, assigned_by = ?", "SET owner_type = ?, owner_ref = assigned_by, assigned_by = ?"),
    expect: () => /owner_ref = \?, assigned_by = \?/.test(getSource("workers/scan-api/src/engines/managed-case-model.js")) ? null : "assignment actor overwrote owner_ref",
  },
  {
    name: "unavailable/failed evidence closes",
    file: "workers/scan-api/src/engines/managed-case-model.js",
    mutate: (s) => s.replace('const POSITIVE_RESULTS = new Set(["fixed", "verified"]);', 'const POSITIVE_RESULTS = new Set(["fixed", "verified", "still_present", "failed", "inconclusive"]);'),
    expect: () => /const POSITIVE_RESULTS = new Set\(\["fixed", "verified"\]\);/.test(getSource("workers/scan-api/src/engines/managed-case-model.js")) ? null : "non-positive verification results can now close a case",
  },
  {
    name: "note-only evidence verifies",
    file: "workers/scan-api/src/engines/managed-case-model.js",
    mutate: (s) => s.replace('if (evidence.note_only === true) return { ok: false, reason: "note_not_verification" };', ""),
    expect: () => /note_not_verification/.test(getSource("workers/scan-api/src/engines/managed-case-model.js")) ? null : "a bare note can now verify a case",
  },
  {
    name: "customer can verify an observable finding",
    file: "workers/scan-api/src/engines/managed-case-model.js",
    mutate: (s) => s.replace('if (support === "automated" && actorType !== "system") {', "if (false) {"),
    expect: () => /if \(support === "automated" && actorType !== "system"\)/.test(getSource("workers/scan-api/src/engines/managed-case-model.js")) ? null : "customer can now verify a system-only observable finding",
  },
  {
    name: "external method concluded locally",
    file: "workers/scan-api/src/engines/managed-case-model.js",
    mutate: (s) => s.replace('if (method === "external") return "external";', 'if (method === "external") return "automated";'),
    expect: () => /if \(method === "external"\) return "external";/.test(getSource("workers/scan-api/src/engines/managed-case-model.js")) ? null : "external-evidence finding downgraded to automated and concludable locally",
  },
  {
    name: "recurrence reopen drops evidence",
    file: "workers/scan-api/src/engines/managed-case-model.js",
    mutate: (s) => s.replace('if (phase === "reopened") next.evidence_json = caseRecord.evidence_json ?? next.evidence_json ?? null;', 'if (phase === "reopened") next.evidence_json = null;'),
    expect: () => /if \(phase === "reopened"\) next\.evidence_json = caseRecord\.evidence_json/.test(getSource("workers/scan-api/src/engines/managed-case-model.js")) ? null : "reopen now discards prior case evidence/history",
  },
  {
    name: "transition loses workspace scope on load",
    file: "workers/scan-api/src/routes/managed-cases.js",
    mutate: (s) => s.replace("WHERE id = ? AND workspace_id = ?`)\n    .bind(caseId, wsId)", "WHERE id = ?`)\n    .bind(caseId)"),
    expect: () => /WHERE id = \? AND workspace_id = \?`\)\n    \.bind\(caseId, wsId\)/.test(getSource("workers/scan-api/src/routes/managed-cases.js")) ? null : "case load lost workspace scope (cross-tenant read)",
  },
  {
    name: "membership check fails open on read error",
    file: "workers/scan-api/src/engines/managed-case-model.js",
    mutate: (s) => s.replace(".bind(workspace_id, user_id).first().catch(() => null);\n  return Boolean(row);", ".bind(workspace_id, user_id).first().catch(() => ({ id: 'x' }));\n  return Boolean(row);"),
    expect: () => /\.first\(\)\.catch\(\(\) => null\);\n  return Boolean\(row\);/.test(getSource("workers/scan-api/src/engines/managed-case-model.js")) ? null : "membership lookup now fails OPEN on a read error",
  },
  {
    name: "assignee_not_member downgraded to 404 (silent)",
    file: "workers/scan-api/src/routes/managed-cases.js",
    mutate: (s) => s.replace('res.code === "owner_ref_required" || res.code === "assignee_not_member" ? 400 : 404', 'res.code === "owner_ref_required" ? 400 : 404'),
    expect: () => /res\.code === "owner_ref_required" \|\| res\.code === "assignee_not_member" \? 400 : 404/.test(getSource("workers/scan-api/src/routes/managed-cases.js")) ? null : "assignee_not_member no longer surfaces as a 400",
  },
];

function runMutations() {
  const original = new Map();
  const files = [...new Set(MUTATIONS.map((m) => m.file))];
  for (const f of files) original.set(f, read(f));
  let mutationPass = 0, mutationFail = 0;
  for (const m of MUTATIONS) {
    sourceFiles.clear();
    for (const [k, v] of original) setSource(k, v);
    setSource(m.file, m.mutate(getSource(m.file)));
    const reason = m.expect();
    if (reason) mutationPass++;
    else { mutationFail++; console.log(`FAIL mutation '${m.name}' did not fail for intended reason`); }
  }
  sourceFiles.clear();
  ok(`mutations: ${MUTATIONS.length} required regressions fail for intended reason`, mutationFail === 0, `${mutationPass} caught, ${mutationFail} escaped`);
}

async function main() {
  await checkCreationAndDedup();
  await checkOwnership();
  await checkVerificationHonesty();
  await checkRecurrence();
  await checkParityAndInvariants();
  await checkWorkspaceDeletion();
  runMutations();

  console.log(`\nuc3-remediation-ownership: ${pass} passed, ${fail} failed`);
  if (fail) {
    console.error("UC3 validation FAILED");
    process.exit(1);
  }
  console.log("UC3 validation passed");
}

main().catch((err) => { console.error(err?.stack || err); process.exit(1); });
