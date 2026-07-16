#!/usr/bin/env node
//
// M5.a — Email Protection managed cases. DB-backed, drives the REAL engines. CI-blocking.
//
// The vertical this proves: a qualifying condition opens a canonical case, the case is
// reachable from the record, a customer can own and drive it, and ONLY CyberMeters' own
// re-observation can verify it where the registry says the condition is observable.
//
// The assertion boundary this defends, stated once: **a customer's assertion cannot
// conclude verification for anything CyberMeters can see itself.** Every mutation below
// attacks that boundary or the linkage that makes a case usable.
//
// Node 24+.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const srcPath = (...p) => path.join(root, "workers", "scan-api", "src", ...p);
const eng = (f) => pathToFileURL(srcPath("engines", f)).href;

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* additive drift tolerated */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}
function makeD1(db) {
  const wrap = (sql, args) => ({
    __sql: sql,
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
}
const realFetch = globalThis.fetch;
globalThis.fetch = async () => new Response("{}", { status: 200 });
const tick = () => new Promise((r) => setTimeout(r, 1100));

function seed(db) {
  db.prepare("INSERT INTO users (id,email,name,plan,created_at) VALUES ('u1','o@e.com','o','business',datetime('now'))").run();
  db.prepare("INSERT INTO users (id,email,name,plan,created_at) VALUES ('u2','b@e.com','b','business',datetime('now'))").run();
  for (const ws of ["ws1", "ws2"]) {
    db.prepare("INSERT INTO workspaces (id,owner_user_id,name) VALUES (?,?,?)").run(ws, ws === "ws1" ? "u1" : "u2", ws);
    db.prepare(`INSERT OR IGNORE INTO alert_activation (id,workspace_id,domain_key,activated_at,baseline_count,created_at)
                VALUES (?,?,'email_protection','2026-07-01T00:00:00Z',0,datetime('now'))`).run(`act_${ws}`, ws);
  }
  // The SAME domain name in two tenants — a hostname is not a tenant-unique identifier.
  db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('d1','u1','shared.example.com')").run();
  db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('d2','u2','shared.example.com')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES ('ws1','d1')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES ('ws2','d2')").run();
}
const seedHosted = (db, id, ws, domain) =>
  db.prepare(`INSERT INTO hosted_dns_entries (id,workspace_id,domain,record_kind,customer_name,target_name,target_value,verification_state,created_at,updated_at)
              VALUES (?,?,?,'dmarc',?,?, 'v=DMARC1; p=none','connected','2026-07-10 09:00:00','2026-07-10 09:00:00')`)
    .run(id, ws, domain, `_dmarc.${domain}`, `${id}.dmarc.cybermeters.com`);
const hostedRow = (id, ws, domain) => ({ id, workspace_id: ws, domain, created_at: "2026-07-10 09:00:00", status: "connected" });
const casesFor = (db, ws) => db.prepare("SELECT * FROM managed_cases WHERE workspace_id=? AND case_type='email_case'").all(ws);

const lifecycle = await import(eng("email-protection-lifecycle.js"));
const cases = await import(eng("email-protection-cases.js"));
const model = await import(eng("managed-case-model.js"));
const registry = await import(eng("remediation-registry.js"));

// ════ 1. THE SIX RECURRENCES — the map, asserted rather than described ═══════
// Every one is stated: does it open a case, what remediation, what method. A recurrence
// that silently stops opening a case, or whose registry method changes, fails here.
{
  const expected = {
    hosted_record_disconnected:          { opens: true,  method: "dns_recheck",        support: "automated" },
    hosted_impact_regression:            { opens: false, method: "receiver_reports",   support: "automated" },
    hosted_rolled_back_auto:             { opens: true,  method: "manual_attestation", support: "manual" },
    sender_unrecognised:                 { opens: true,  method: "manual_attestation", support: "manual" },
    sender_classification_worsened:      { opens: true,  method: "manual_attestation", support: "manual" },
    sender_unauthorised_failures_active: { opens: true,  method: "receiver_reports",   support: "automated" },
  };
  eq("all SIX recurrences are accounted for", lifecycle.EMAIL_RECURRENCES.length, 6);
  for (const r of lifecycle.EMAIL_RECURRENCES) {
    const e = expected[r];
    ok(`${r}: is mapped in this suite`, Boolean(e));
    if (!e) continue;
    eq(`${r}: opens a case? ${e.opens}`, cases.EMAIL_CASE_RECURRENCES.has(r), e.opens);
    const ft = lifecycle.EMAIL_RECURRENCE_FINDING_TYPE[r];
    const rem = registry.resolveRemediation({ finding_type: ft });
    eq(`${r}: registry method is ${e.method}`, rem?.verification_method, e.method);
    // The support the case model will derive from that remediation.
    eq(`${r}: derives ${e.support}`,
      model.verificationSupportForCase({ case_type: "email_case", remediation_id: rem?.remediation_id }), e.support);
  }
  // The one that does NOT open a case, and why — an observable method with no verifier.
  ok("hosted_impact_regression has an observable method but NO system verifier exists",
    !Object.values(cases.EMAIL_RECOVERY_VERIFIES).includes("hosted_impact_regression"));
  ok("...so it deliberately opens no case it could never honestly close",
    !cases.EMAIL_CASE_RECURRENCES.has("hosted_impact_regression"));
}

// ════ 2. CREATION + LINKAGE + DEDUPE, driven through the REAL engine ════════
const db = buildDb();
seed(db);
const env = { cybermeters_db: makeD1(db), RESEND_API_KEY: "", ALERT_EMAIL_FROM: "a@cybermeters.com" };
seedHosted(db, "hd-1", "ws1", "shared.example.com");
const hd1 = hostedRow("hd-1", "ws1", "shared.example.com");

{
  await lifecycle.recordHostedTransition(env, hd1, { recurrence: "hosted_record_disconnected", from_status: "connected", to_status: "disconnected" });
  const cs = casesFor(db, "ws1");
  eq("a qualifying condition opens exactly ONE canonical case", cs.length, 1);
  eq("the case is the canonical type", cs[0].case_type, "email_case");
  eq("its domain_key is canonical", cs[0].domain_key, "email_protection");
  eq("LINKAGE: finding_id is the lifecycle record id", cs[0].finding_id, "hd-1");
  eq("it carries the canonical remediation", cs[0].remediation_id, "email.hosted_dmarc.reconnect");
  eq("it opens at the canonical initial state", cs[0].status, "detected");

  // The reverse lookup mig 088 has no column for.
  const found = await cases.findEmailCaseForRecord(env, "ws1", "hd-1");
  eq("REVERSE LOOKUP: the record resolves to its case", found?.id, cs[0].id);
  eq("a record with no case resolves to nothing", await cases.findEmailCaseForRecord(env, "ws1", "hd-nope"), null);

  // The linkage event is history, never an occurrence.
  const linkEvents = db.prepare("SELECT * FROM email_protection_events WHERE record_id='hd-1' AND event_type='case_linked'").all();
  eq("a case_linked history row is written", linkEvents.length, 1);
  ok("and it is NOT occurrence-shaped, so it can never become an alert",
    !JSON.parse(linkEvents[0].detail_json || "{}").to_recurrence_type);

  // DEDUPE: the same condition again must not mint a second case.
  await lifecycle.recordHostedTransition(env, hd1, { recurrence: "hosted_record_disconnected", from_status: "connected", to_status: "disconnected" });
  eq("an UNCHANGED condition creates no second case", casesFor(db, "ws1").length, 1);
}

// ════ 3. TENANCY — the same hostname in another tenant is a separate case ════
{
  seedHosted(db, "hd-2", "ws2", "shared.example.com");
  await lifecycle.recordHostedTransition(env, hostedRow("hd-2", "ws2", "shared.example.com"),
    { recurrence: "hosted_record_disconnected", from_status: "connected", to_status: "disconnected" });
  eq("ws2 gets its OWN case for the same hostname", casesFor(db, "ws2").length, 1);
  ok("and ws1 still has exactly one", casesFor(db, "ws1").length === 1);
  ok("every case is stamped with its own workspace",
    casesFor(db, "ws2").every((c) => c.workspace_id === "ws2"));
  eq("a ws2-scoped reverse lookup cannot reach ws1's record",
    await cases.findEmailCaseForRecord(env, "ws2", "hd-1"), null);
}

// ════ 4. OWNERSHIP — universal, case-level, no domain-specific system ═══════
{
  const c = casesFor(db, "ws1")[0];
  // The base machine REQUIRES an owner to reach `assigned` — assignment is not decoration.
  const noOwner = model.canTransitionCase({ case: { ...c, status: "triaged" }, target_status: "assigned", actor: { actor_type: "customer", actor_id: "u1" } });
  ok("assignment without an owner is refused by the canonical guard", noOwner.ok === false);
  // owner_ref is a top-level transition option (canTransitionCase lifts it into ctx, and
  // requireField reads ctx first) — not a `patch` object, which it would ignore.
  const withOwner = model.canTransitionCase({ case: { ...c, status: "triaged" }, target_status: "assigned", actor: { actor_type: "customer", actor_id: "u1" }, owner_ref: "u1" });
  ok("assignment WITH an owner is accepted", withOwner.ok === true);
  // Reassignment is the same universal path — there is no email-specific owner column.
  ok("ownership lives on managed_cases, not on an email-specific table",
    ["owner_type", "owner_ref", "assigned_user_id"].every((col) =>
      db.prepare("PRAGMA table_info(managed_cases)").all().some((x) => x.name === col)));
  ok("no email lifecycle table carries an owner column (M5.a: universal assignment only)",
    !db.prepare("PRAGMA table_info(email_sender_sources)").all().some((x) => /owner/.test(x.name))
    && !db.prepare("PRAGMA table_info(hosted_dns_entries)").all().some((x) => /owner/.test(x.name)));
}

// ════ 5. THE BOUNDARY — who may verify what ════════════════════════════════
{
  const c = casesFor(db, "ws1")[0];   // dns_recheck → observable → automated
  const av = { ...c, status: "awaiting_verification" };
  const attestation = {
    verification_method: "manual_attestation", verification_result: "verified",
    evidence_type: "attestation", observed_at: "2026-07-16T00:00:00Z",
    attestation: { by: "u1", statement: "I reconnected it" },
  };
  const byCustomer = model.canTransitionCase({ case: av, target_status: "verified", actor: { actor_type: "customer", actor_id: "u1" }, evidence: attestation });
  ok("a CUSTOMER cannot verify an observable email condition, even with a structured attestation", byCustomer.ok === false);
  eq("and is told why", byCustomer.code, "verify_requires_system");

  // The attestation-only condition keeps the path the registry endorses.
  const attRem = registry.resolveRemediation({ finding_type: "email_sender_unrecognised" });
  const attCase = { id: "mc-att", workspace_id: "ws1", case_type: "email_case", remediation_id: attRem.remediation_id, status: "awaiting_verification" };
  ok("a customer CAN attest the condition the registry says we cannot observe",
    model.canTransitionCase({ case: attCase, target_status: "verified", actor: { actor_type: "customer", actor_id: "u1" }, evidence: attestation }).ok === true);
  eq("but a bare note still verifies nothing",
    model.canTransitionCase({ case: attCase, target_status: "verified", actor: { actor_type: "customer", actor_id: "u1" }, evidence: { note_only: true } }).code,
    "verify_requires_evidence");
}

// ════ 6. SYSTEM VERIFICATION from the two recovery observations ═════════════
{
  // Drive the case to awaiting_verification the way a customer would.
  const c = casesFor(db, "ws1")[0];
  db.prepare("UPDATE managed_cases SET status='awaiting_verification' WHERE id=?").run(c.id);

  await tick();
  await lifecycle.recordHostedTransition(env, hd1, { event_type: "hosted_record_reconnected", from_status: "disconnected", to_status: "connected" });
  const after = db.prepare("SELECT * FROM managed_cases WHERE id=?").get(c.id);
  eq("RECOVERY OBSERVED: a real DNS re-observation verifies the case", after.status, "verified");
  ok("and stamps when it was verified", Boolean(after.verified_at));
  const ev = db.prepare("SELECT * FROM managed_case_events WHERE case_id=? ORDER BY rowid DESC LIMIT 1").get(c.id);
  const detail = JSON.parse(ev.detail_json || "{}");
  eq("the evidence records the METHOD the registry declared", detail.verification_method, "dns_recheck");
  eq("and the observation that produced it", detail.evidence_type, "hosted_record_reconnected");
  eq("the verifying actor is CyberMeters, never the customer", ev.actor_type, "system");
}

// ════ 7. A recovery for an ATTESTATION-ONLY finding does NOT verify ═════════
// The sharpest edge: seeing "no failures" for a finding the registry says we cannot
// observe is not evidence the customer did anything. It is history, and the case waits.
{
  const db2 = buildDb(); seed(db2);
  const env2 = { cybermeters_db: makeD1(db2), RESEND_API_KEY: "" };
  const attRem = registry.resolveRemediation({ finding_type: "email_sender_unrecognised" });
  db2.prepare(`INSERT INTO managed_cases (id, workspace_id, case_type, domain_key, finding_id, source_finding_type, remediation_id, status, severity, created_at, updated_at)
               VALUES ('mc-x','ws1','email_case','email_protection','snd-x','email_sender_unrecognised',?,'awaiting_verification','medium',datetime('now'),datetime('now'))`)
    .run(attRem.remediation_id);
  const res = await cases.verifyEmailCaseFromRecovery(env2, {
    workspace_id: "ws1", record_id: "snd-x", recovery_event_type: "sender_failures_recovered",
  });
  eq("a recovery observation does NOT verify an attestation-only finding", res.skipped, "verification_not_automated_for_this_finding");
  eq("the case stays where it was", db2.prepare("SELECT status FROM managed_cases WHERE id='mc-x'").get().status, "awaiting_verification");
  ok("and the observation is recorded as history rather than discarded",
    db2.prepare("SELECT * FROM managed_case_events WHERE case_id='mc-x' AND action='recovery_observed_not_verifying'").all().length === 1);
}

// ════ 8. RECURRENCE reopens the canonical case — never a second one ═════════
{
  const c = casesFor(db, "ws1")[0];   // verified by §6
  eq("precondition: the case is verified", db.prepare("SELECT status FROM managed_cases WHERE id=?").get(c.id).status, "verified");
  await tick();
  await lifecycle.recordHostedTransition(env, hd1, { recurrence: "hosted_record_disconnected", from_status: "connected", to_status: "disconnected" });
  const after = db.prepare("SELECT * FROM managed_cases WHERE id=?").get(c.id);
  eq("a returning condition REOPENS the canonical case", after.status, "reopened");
  ok("and counts the reopen", Number(after.reopened_count) >= 1);
  eq("it does NOT create a second case", casesFor(db, "ws1").length, 1);
  ok("the reopen went through the canonical event log",
    db.prepare("SELECT * FROM managed_case_events WHERE case_id=? AND to_status='reopened'").all(c.id).length >= 1);
  ok("and the record's own history records it",
    db.prepare("SELECT * FROM email_protection_events WHERE record_id='hd-1' AND event_type='case_reopened'").all().length >= 1);
}

// ════ 9. No parallel case model, no bypass ══════════════════════════════════
{
  const src = fs.readFileSync(srcPath("engines", "email-protection-cases.js"), "utf8");
  const code = src.replace(/^\s*\/\/.*$/gm, "");
  ok("cases are created through the canonical factory", /createManagedCase\(/.test(code));
  ok("transitions go through the canonical validator", /canTransitionCase\(/.test(code));
  ok("no bespoke email case table is created", !/CREATE TABLE/i.test(code));
  ok("no direct INSERT INTO managed_cases bypasses the factory", !/INSERT INTO managed_cases/i.test(code));
  ok("the module imports nothing from the lifecycle (no cycle)",
    !/^import .* from "\.\/email-protection-lifecycle\.js"/m.test(code));
  // Migration 088's parents are untouched: the linkage is finding_id, not a new column.
  //
  // This used to pin the LATEST migration filename to 091, which asserted something else
  // entirely — "no migration has landed anywhere in the repo since" — and so it broke the
  // moment an unrelated increment (092, CE question-set versioning) added one. The real
  // claim is scoped to THIS increment: Email managed cases needed no schema, because the
  // pointer already existed. Assert that, not the global tip.
  const migSrc = fs.readdirSync(path.join(root, "database", "migrations"))
    .filter((f) => f.endsWith(".sql"))
    .map((f) => fs.readFileSync(path.join(root, "database", "migrations", f), "utf8"))
    .join("\n")
    .replace(/^\s*--.*$/gm, "");   // intent lives in comments; only DDL counts
  for (const parent of ["hosted_dns_entries", "email_sender_sources"]) {
    ok(`no migration adds a case-linkage column to ${parent} (the pointer is managed_cases.finding_id)`,
      !new RegExp(`ALTER TABLE ${parent} ADD COLUMN (linked_case_id|case_id)`, "i").test(migSrc));
  }
  // Table NAMES only. Matching across a whole CREATE TABLE body is meaningless: `[^;]*`
  // happily spans an unrelated table's columns and finds "email" and "case" in different
  // tables, which is how this first "failed" against shadow_it_inventory.
  const tableNames = [...migSrc.matchAll(/CREATE TABLE (?:IF NOT EXISTS )?([a-z_]+)/gi)].map((m) => m[1]);
  ok("no migration creates an email-specific case table",
    !tableNames.some((t) => /email/i.test(t) && /case/i.test(t)), tableNames.filter((t) => /email/i.test(t)).join(", "));
}

// ════ 10. MUTATION PROOF — every guard above must be load-bearing ══════════
// A passing count is not proof. Each mutation reintroduces a specific defect and the
// corresponding claim must break. If a mutation stops reproducing, the guard has stopped
// guarding — that is a failure here, not a pass.
let mutSeq = 0;
async function withMutant(file, mutate, run) {
  const original = fs.readFileSync(srcPath("engines", file), "utf8");
  const mutated = mutate(original);
  ok(`[${file}] the mutation applied (the guard is where this suite thinks it is)`, mutated !== original);
  if (mutated === original) return;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cm-m5a-"));
  const tmp = srcPath("engines", `.${file.replace(/\.js$/, "")}.mutant.${path.basename(dir)}.js`);
  fs.writeFileSync(tmp, mutated);
  try { await run(await import(pathToFileURL(tmp).href)); }
  finally { fs.rmSync(tmp, { force: true }); fs.rmSync(dir, { recursive: true, force: true }); }
}
// A fresh world per mutant: a case created by a previous mutant must never satisfy the next.
function freshCaseWorld() {
  const d = buildDb(); seed(d);
  seedHosted(d, "hd-1", "ws1", "shared.example.com");
  return { db: d, env: { cybermeters_db: makeD1(d), RESEND_API_KEY: "" } };
}
const attestation = {
  verification_method: "manual_attestation", verification_result: "verified",
  evidence_type: "attestation", observed_at: "2026-07-16T00:00:00Z",
  attestation: { by: "u1", statement: "done" },
};

// M1 — customer attestation verifies externally observable remediation.
await withMutant("managed-case-model.js",
  // The support derivation was a single ternary when this was written; it is now an explicit
  // chain (manual / external / automated). The mutant's INTENT is unchanged: force every
  // finding to "manual" so a customer can attest something CyberMeters re-observes.
  (x) => x.replace('if (method === "manual_attestation") return "manual";', 'if (method) return "manual";'),
  async (mut) => {
    const observable = { id: "mc-1", workspace_id: "ws1", case_type: "email_case", remediation_id: "email.hosted_dmarc.reconnect", status: "awaiting_verification" };
    ok("MUTANT-1: a customer's attestation verifies a DNS-observable condition — the defect, reproduced",
      mut.canTransitionCase({ case: observable, target_status: "verified", actor: { actor_type: "customer", actor_id: "u1" }, evidence: attestation }).ok === true);
  });

// M2 — the registry method is ignored.
await withMutant("managed-case-model.js",
  (x) => x.replace("  const rem = caseRecord.remediation_id ? getRemediationById(caseRecord.remediation_id) : null;\n  const method = rem?.verification_method ?? null;",
                   "  const method = \"manual_attestation\";"),
  async (mut) => {
    const observable = { id: "mc-2", workspace_id: "ws1", case_type: "email_case", remediation_id: "email.hosted_dmarc.reconnect", status: "awaiting_verification" };
    eq("MUTANT-2: ignoring the registry makes an observable finding customer-verifiable",
      mut.verificationSupportForCase(observable), "manual");
  });

// M3 — case dedupe removed.
await withMutant("email-protection-cases.js",
  (x) => x.replace(/const existing = await env\.cybermeters_db[\s\S]*?\.first\(\)\.catch\(\(\) => null\);/, "const existing = null;"),
  async (mut) => {
    const { db: d, env: e } = freshCaseWorld();
    for (let i = 0; i < 2; i++) {
      await mut.openOrReopenEmailCase(e, { workspace_id: "ws1", record_id: "hd-1", entity: "shared.example.com", domain: "shared.example.com", recurrence: "hosted_record_disconnected", finding_type: "email_hosted_dmarc_disconnected" });
    }
    // createManagedCase still dedupes internally, so the observable defect is that the
    // module stops SEEING the existing case — reopen/recurrence handling is bypassed.
    ok("MUTANT-3: without its dedupe read the module can no longer find the case it must reopen",
      d.prepare("SELECT COUNT(*) n FROM managed_case_events WHERE action='email_recurrence'").get().n === 0);
  });

// M4 — workspace scope removed from the reverse lookup.
await withMutant("email-protection-cases.js",
  (x) => x.replace(/WHERE workspace_id = \? AND case_type = \? AND finding_id = \?\n         AND status NOT IN/, "WHERE case_type = ? AND finding_id = ?\n         AND status NOT IN")
          .replace(".bind(workspaceId, EMAIL_CASE_TYPE, recordId)", ".bind(EMAIL_CASE_TYPE, recordId)"),
  async (mut) => {
    const { db: d, env: e } = freshCaseWorld();
    d.prepare(`INSERT INTO managed_cases (id, workspace_id, case_type, domain_key, finding_id, remediation_id, status, severity, created_at, updated_at)
               VALUES ('mc-foreign','ws2','email_case','email_protection','hd-1','email.hosted_dmarc.reconnect','detected','high',datetime('now'),datetime('now'))`).run();
    const leaked = await mut.findEmailCaseForRecord(e, "ws1", "hd-1");
    eq("MUTANT-4: without workspace scope, ws2's case leaks into ws1's lookup", leaked?.id, "mc-foreign");
  });

// M5 — linkage omitted (finding_id not set).
await withMutant("email-protection-cases.js",
  (x) => x.replace("      source_finding_id: record_id,   // THE linkage — the reverse lookup reads this", "      source_finding_id: null,"),
  async (mut) => {
    const { db: d, env: e } = freshCaseWorld();
    await mut.openOrReopenEmailCase(e, { workspace_id: "ws1", record_id: "hd-1", entity: "shared.example.com", domain: "shared.example.com", recurrence: "hosted_record_disconnected", finding_type: "email_hosted_dmarc_disconnected" });
    const c = d.prepare("SELECT * FROM managed_cases WHERE workspace_id='ws1'").get();
    ok("MUTANT-5: the case exists but carries no record linkage", c && c.finding_id !== "hd-1");
    eq("MUTANT-5: so the record can no longer find its case",
      await mut.findEmailCaseForRecord(e, "ws1", "hd-1"), null);
  });

// M6 — recovery evidence ignored.
await withMutant("email-protection-cases.js",
  (x) => x.replace("  const recurrence = EMAIL_RECOVERY_VERIFIES[recovery_event_type];\n  if (!recurrence) return { skipped: \"not_a_recovery_observation\" };",
                   "  return { skipped: \"not_a_recovery_observation\" };"),
  async (mut) => {
    const { db: d, env: e } = freshCaseWorld();
    d.prepare(`INSERT INTO managed_cases (id, workspace_id, case_type, domain_key, finding_id, remediation_id, status, severity, created_at, updated_at)
               VALUES ('mc-r','ws1','email_case','email_protection','hd-1','email.hosted_dmarc.reconnect','awaiting_verification','high',datetime('now'),datetime('now'))`).run();
    await mut.verifyEmailCaseFromRecovery(e, { workspace_id: "ws1", record_id: "hd-1", recovery_event_type: "hosted_record_reconnected" });
    eq("MUTANT-6: ignoring the recovery observation leaves the case unverified forever",
      d.prepare("SELECT status FROM managed_cases WHERE id='mc-r'").get().status, "awaiting_verification");
  });

// M7 — incomplete evidence verifies (a bare flag instead of a method).
await withMutant("email-protection-cases.js",
  (x) => x.replace(/const evidence = \{\n    verification_method: rem\?\.verification_method \?\? null,[\s\S]*?\n  \};/, "const evidence = { verified: true };"),
  async (mut) => {
    const { db: d, env: e } = freshCaseWorld();
    d.prepare(`INSERT INTO managed_cases (id, workspace_id, case_type, domain_key, finding_id, remediation_id, status, severity, created_at, updated_at)
               VALUES ('mc-i','ws1','email_case','email_protection','hd-1','email.hosted_dmarc.reconnect','awaiting_verification','high',datetime('now'),datetime('now'))`).run();
    const r = await mut.verifyEmailCaseFromRecovery(e, { workspace_id: "ws1", record_id: "hd-1", recovery_event_type: "hosted_record_reconnected" });
    // The universal evidence contract is the backstop: unstructured evidence is refused
    // even when this module hands it over. That is defence in depth, and it is asserted
    // rather than assumed.
    ok("MUTANT-7: unstructured evidence is refused by the universal contract, not verified",
      d.prepare("SELECT status FROM managed_cases WHERE id='mc-i'").get().status === "awaiting_verification" && r.skipped === "transition_refused");
  });

// M8 — recurrence fails to reopen (verified/monitoring no longer reopens).
await withMutant("email-protection-cases.js",
  (x) => x.replace('if (phase === "verified" || phase === "monitoring") {', "if (false) {"),
  async (mut) => {
    const { db: d, env: e } = freshCaseWorld();
    d.prepare(`INSERT INTO managed_cases (id, workspace_id, case_type, domain_key, finding_id, remediation_id, status, severity, created_at, updated_at)
               VALUES ('mc-v','ws1','email_case','email_protection','hd-1','email.hosted_dmarc.reconnect','verified','high',datetime('now'),datetime('now'))`).run();
    await mut.openOrReopenEmailCase(e, { workspace_id: "ws1", record_id: "hd-1", entity: "shared.example.com", domain: "shared.example.com", recurrence: "hosted_record_disconnected", finding_type: "email_hosted_dmarc_disconnected" });
    eq("MUTANT-8: a returning condition no longer reopens the verified case",
      d.prepare("SELECT status FROM managed_cases WHERE id='mc-v'").get().status, "verified");
  });

// M9 — domain-specific assignment bypassing managed_cases.
{
  const src = fs.readFileSync(srcPath("engines", "email-protection-cases.js"), "utf8");
  const code = src.replace(/^\s*\/\/.*$/gm, "");
  ok("ownership is never written to an email-specific table", !/UPDATE (email_sender_sources|hosted_dns_entries) SET[^;]*owner/i.test(code));
  const bypassed = code + "\nexport async function __assign(env, id, owner) { return env.cybermeters_db.prepare('UPDATE email_sender_sources SET owner_ref = ?').bind(owner).run(); }";
  ok("MUTANT-9: a domain-specific assignment path IS detected — the check is not vacuous",
    /UPDATE (email_sender_sources|hosted_dns_entries) SET[^;]*owner/i.test(bypassed));
}

console.log(`\nm5a-email-cases: ${pass} passed, ${fail} failed`);
globalThis.fetch = realFetch;
if (fail > 0) { console.error("m5a-email-cases validation FAILED"); process.exit(1); }
console.log("m5a-email-cases validation passed");
