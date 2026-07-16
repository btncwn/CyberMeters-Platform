#!/usr/bin/env node
//
// M5.a — Website Security managed cases + the cross-domain verification vocabulary.
// DB-backed, drives the REAL engines through evaluateWebsiteSecurityForScan. CI-blocking.
//
// The vertical this proves: a qualifying condition opens a canonical case, the condition
// links to it, a customer can own and drive it, ONLY CyberMeters' own re-observation can
// verify it, and a recurrence reopens it.
//
// Two boundaries every mutation below attacks:
//   1. absence is evidence of a fix ONLY when the detecting module provably ran (the #105
//      defect class);
//   2. the words "Verified"/"Confirmed" belong to what CyberMeters OBSERVED — never to a
//      customer's attestation.
//
// Node 24+.
import fs from "node:fs";
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
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
}
globalThis.fetch = async () => new Response("{}", { status: 200 });

function seed(db) {
  db.prepare("INSERT INTO users (id,email,name,plan,created_at) VALUES ('u1','o@e.com','o','business',datetime('now'))").run();
  db.prepare("INSERT INTO users (id,email,name,plan,created_at) VALUES ('u2','b@e.com','b','business',datetime('now'))").run();
  for (const ws of ["ws1", "ws2"]) {
    db.prepare("INSERT INTO workspaces (id,owner_user_id,name) VALUES (?,?,?)").run(ws, ws === "ws1" ? "u1" : "u2", ws);
    db.prepare(`INSERT OR IGNORE INTO alert_activation (id,workspace_id,domain_key,activated_at,baseline_count,created_at)
                VALUES (?,?,'website_security','2026-07-01T00:00:00Z',0,datetime('now'))`).run(`act_${ws}`, ws);
  }
  // The SAME hostname in two tenants — a hostname is not a tenant-unique identifier.
  db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('d1','u1','shared.example.com')").run();
  db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('d2','u2','shared.example.com')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES ('ws1','d1')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES ('ws2','d2')").run();
}

const HSTS = { id: "header_missing_strict_transport_security", title: "HSTS missing", severity: "high" };
const finding = (f) => ({ ...f, finding_type: "finding" });
// A scan where the headers module ran to completion: the ONLY shape in which absence means
// "fixed". `modules` must CONTAIN the key — moduleCompletionGate requires it to have run.
const COMPLETE = { modules: { headers: { ok: true }, ssl: { ok: true } }, scanQuality: { status: "complete" } };
const PARTIAL  = { modules: { headers: { ok: true } }, scanQuality: { status: "partial" } };
const NOT_RUN  = { modules: { ssl: { ok: true } }, scanQuality: { status: "complete" } };

const conds = (db, ws) => db.prepare("SELECT * FROM website_security_conditions WHERE workspace_id=?").all(ws);
const casesFor = (db, ws) => db.prepare("SELECT * FROM managed_cases WHERE workspace_id=? AND case_type='website_case'").all(ws);
const caseEvents = (db, id) => db.prepare("SELECT * FROM managed_case_events WHERE case_id=? ORDER BY rowid").all(id);
const wsEvents = (db, ws) => db.prepare("SELECT * FROM website_security_events WHERE workspace_id=? ORDER BY rowid").all(ws);

// The canonical path a customer drives a base-domain case along (BASE_CASE_MACHINE).
const DRIVE = ["triaged", "assigned", "approved", "action_in_progress", "awaiting_verification"];

const lifecycle = await import(eng("website-security-lifecycle.js"));
const cases = await import(eng("website-security-cases.js"));
const model = await import(eng("managed-case-model.js"));
const registry = await import(eng("remediation-registry.js"));
const { SECURITY_HEADERS } = await import(pathToFileURL(srcPath("engines", "security-headers-config.js")).href);

// Baseline the domain, then observe the condition: only a post-baseline appearance is a
// real first occurrence. Returns the evaluator's own result.
async function baselineThen(env, findings, opts = COMPLETE) {
  await lifecycle.evaluateWebsiteSecurityForScan(env, {
    workspace_id: "ws1", domain_id: "d1", domain: "shared.example.com", scan_id: "s0",
    findings: [], ...opts,
  });
  return await lifecycle.evaluateWebsiteSecurityForScan(env, {
    workspace_id: "ws1", domain_id: "d1", domain: "shared.example.com", scan_id: "s1",
    findings, ...opts,
  });
}

// ════ 1. THE RECURRENCE MAP — asserted, not described ════════════════════════
// Every Website Security condition key, its module, its registry method and whether it
// opens a case. A key that silently stops opening a case, or whose registry method drifts
// to something a customer could self-certify, fails HERE.
{
  const slug = (n) => String(n).toLowerCase().replace(/-/g, "_");
  const keys = ["ssl_not_available", "ssl_no_http_redirect"];
  for (const h of SECURITY_HEADERS) keys.push(`header_missing_${slug(h.name)}`, `header_malformed_${slug(h.name)}`);
  eq("all 14 condition keys enumerated (2 ssl + 6 headers × 2)", keys.length, 14);

  for (const k of keys) {
    const spec = lifecycle.websiteConditionSpec(k);
    ok(`${k}: has a lifecycle spec`, Boolean(spec));
    const r = registry.resolveRemediation({ finding_type: k });
    eq(`${k}: resolves to a canonical remediation`, r.status, "resolved");
    // THE domain invariant: every Website Security condition is externally observable, so
    // no customer attestation can ever conclude one. If the registry ever says
    // manual_attestation here, this domain's verification story changes and the vertical
    // must be re-thought — not silently accepted.
    eq(`${k}: registry method is https_recheck (externally observable)`, r.verification_method, "https_recheck");
    eq(`${k}: its recurrence opens a case`, cases.WEBSITE_CASE_RECURRENCES.has(spec.recurrence), true);
    // The support the case model derives, per finding — the PR #129 contract.
    eq(`${k}: verification support is automated`,
      model.verificationSupportForCase({ case_type: "website_case", remediation_id: r.remediation_id }), "automated");
  }
  eq("the recovery event is condition_resolved, NOT control_recovered",
    cases.WEBSITE_RECOVERY_EVENT, "condition_resolved");
  eq("condition_resolved is the lifecycle's own resolved event",
    cases.WEBSITE_RECOVERY_EVENT, lifecycle.WS_EVENT_RESOLVED);
  ok("control_recovered (Cyber Essentials' vocabulary) appears nowhere in the WS case engine",
    !fs.readFileSync(srcPath("engines", "website-security-cases.js"), "utf8").includes("control_recovered")
    || fs.readFileSync(srcPath("engines", "website-security-cases.js"), "utf8").includes("NOT `control_recovered`"));
}

// ════ 1b. THE WHOLE PATH IS WALKABLE — for every base domain ════════════════
// A regression for a LIVE defect this suite found: `approved: [requireActor]` was
// registered bare, but guards are called guard(caseRecord, ctx), so requireActor read the
// case row, found no actor_id and refused EVERY approval. `approved` was unreachable for
// all six base domains, and with it awaiting_verification and verified — the managed
// lifecycle dead-ended at `assigned` and no case could ever be verified.
//
// It survived PR #130 because that suite jumped straight to awaiting_verification instead
// of walking the path a customer actually walks. So this asserts the WHOLE path, for every
// base case type — a shortcut here proves nothing about the product.
{
  for (const ct of ["email_case", "website_case", "cyber_essentials_case", "certificate_case", "identity_case", "shadow_it_case"]) {
    let k = { id: "c1", workspace_id: "ws1", case_type: ct, status: "detected" };
    let reached = "detected";
    for (const t of DRIVE) {
      const d = model.canTransitionCase({ case: k, target_status: t, actor: { actor_type: "customer", actor_id: "u1" }, owner_ref: "u1" });
      if (!d.ok) break;
      k = { ...k, ...d.case }; reached = t;
    }
    eq(`${ct}: a customer can walk the full canonical path to awaiting_verification`, reached, "awaiting_verification");
  }
  // The guard must still BE a guard: approval with no actor is refused.
  ok("approval with no actor is still refused", !model.canTransitionCase({
    case: { id: "c", workspace_id: "w", case_type: "website_case", status: "assigned" },
    target_status: "approved", actor: {},
  }).ok);
}

// ════ 2. CREATION + LINKAGE ══════════════════════════════════════════════════
{
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db) };
  await baselineThen(env, [finding(HSTS)]);

  const c = casesFor(db, "ws1");
  eq("one case opened for the observed condition", c.length, 1);
  eq("case_type is the canonical website_case", c[0]?.case_type, "website_case");
  eq("case domain_key is website_security", c[0]?.domain_key, "website_security");
  eq("case opens in the canonical initial status", c[0]?.status, "detected");

  const rec = conds(db, "ws1").find((r) => r.condition_key === HSTS.id);
  ok("the condition record exists", Boolean(rec));
  // The forward pointer AND the column mig 089 reserved must agree.
  eq("managed_cases.finding_id points at the condition (forward)", c[0]?.finding_id, rec.id);
  eq("website_security_conditions.linked_case_id points at the case (reverse)", rec.linked_case_id, c[0]?.id);
  eq("the case resolved its canonical remediation", c[0]?.remediation_id, "web.header.hsts");
  eq("the case carries the condition key as its finding type", c[0]?.source_finding_type, HSTS.id);

  // The lifecycle's own append-only log records the linkage.
  const linked = wsEvents(db, "ws1").filter((e) => e.event_type === "case_linked");
  eq("exactly one case_linked lifecycle event", linked.length, 1);
  eq("case_linked names the case", JSON.parse(linked[0].detail_json).case_id, c[0].id);
  ok("case_linked is non-alertable by construction",
    lifecycle.WS_NON_ALERTABLE_EVENT_TYPES.includes("case_linked"));

  const found = await cases.findWebsiteCaseForRecord(env, "ws1", rec.id);
  eq("the reverse lookup resolves the case", found?.id, c[0].id);
}

// ════ 3. DEDUPE — an unchanged pass must create NOTHING ══════════════════════
{
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db) };
  await baselineThen(env, [finding(HSTS)]);
  const before = casesFor(db, "ws1")[0];
  const linkedBefore = wsEvents(db, "ws1").filter((e) => e.event_type === "case_linked").length;

  // Three more identical passes. The condition has not moved.
  for (const s of ["s2", "s3", "s4"]) {
    await lifecycle.evaluateWebsiteSecurityForScan(env, {
      workspace_id: "ws1", domain_id: "d1", domain: "shared.example.com", scan_id: s,
      findings: [finding(HSTS)], ...COMPLETE,
    });
  }
  eq("still exactly ONE case after three unchanged passes", casesFor(db, "ws1").length, 1);
  eq("the case id is unchanged", casesFor(db, "ws1")[0].id, before.id);
  // The v2026.07.16-8 lesson: a row written per evaluation that records no new fact is a
  // defect, not history.
  eq("no extra case_linked row per unchanged pass",
    wsEvents(db, "ws1").filter((e) => e.event_type === "case_linked").length, linkedBefore);
}

// ════ 4. TENANT ISOLATION ════════════════════════════════════════════════════
{
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db) };
  await baselineThen(env, [finding(HSTS)]);
  // ws2 has the SAME hostname and the SAME condition.
  for (const s of ["t0", "t1"]) {
    await lifecycle.evaluateWebsiteSecurityForScan(env, {
      workspace_id: "ws2", domain_id: "d2", domain: "shared.example.com", scan_id: s,
      findings: s === "t0" ? [] : [finding(HSTS)], ...COMPLETE,
    });
  }
  eq("ws1 has exactly one case", casesFor(db, "ws1").length, 1);
  eq("ws2 has its own separate case", casesFor(db, "ws2").length, 1);
  ok("the two tenants' cases are distinct", casesFor(db, "ws1")[0].id !== casesFor(db, "ws2")[0].id);

  // A cross-tenant read must find nothing — the record id is real, the tenant is not.
  const ws1rec = conds(db, "ws1")[0];
  const leaked = await cases.findWebsiteCaseForRecord(env, "ws2", ws1rec.id);
  eq("ws2 cannot read ws1's case via ws1's record id", leaked, null);

  // Soft-deleted workspace: nonexistent. No record, no case.
  db.prepare("UPDATE workspaces SET deleted_at=datetime('now') WHERE id='ws2'").run();
  const before = casesFor(db, "ws2").length;
  await lifecycle.evaluateWebsiteSecurityForScan(env, {
    workspace_id: "ws2", domain_id: "d2", domain: "shared.example.com", scan_id: "t2",
    findings: [finding({ ...HSTS, id: "header_missing_content_security_policy" })], ...COMPLETE,
  });
  eq("a soft-deleted workspace opens no new case", casesFor(db, "ws2").length, before);
}

// ════ 5. OWNERSHIP — universal case-level assignment, no domain-specific model ═
{
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db) };
  await baselineThen(env, [finding(HSTS)]);
  const kase = casesFor(db, "ws1")[0];

  const t = model.canTransitionCase({ case: kase, target_status: "triaged", actor: { actor_type: "customer", actor_id: "u1" } });
  ok("a customer may triage the case through the universal validator", t.ok, t.code || "");
  db.prepare("UPDATE managed_cases SET status=? WHERE id=?").run(t.case.status, kase.id);
  const d = model.canTransitionCase({
    case: casesFor(db, "ws1")[0], target_status: "assigned",
    actor: { actor_type: "customer", actor_id: "u1" },
    owner_ref: "u1", owner_type: "customer", reason: "mine",
  });
  ok("a customer may assign the case through the universal validator", d.ok, d.code || "");
  eq("assignment lands on the canonical assigned phase",
    model.canonicalPhaseFor("website_case", d.case?.status), "assigned");
  // owner_ref is REQUIRED by the canonical guard — assignment with no owner is refused.
  ok("assignment with no owner_ref is refused by the canonical guard", !model.canTransitionCase({
    case: casesFor(db, "ws1")[0], target_status: "assigned", actor: { actor_type: "customer", actor_id: "u1" },
  }).ok);
  // The founder's M5.a decision: ownership is the universal case-level fields ONLY. No
  // business/technical/remediation-owner migration for this increment.
  ok("no Website-Security-specific ownership table exists",
    !fs.readdirSync(path.join(root, "database", "migrations"))
      .some((f) => /website.*(owner|assign)/i.test(f)));
}

// ════ 6. VERIFICATION — an OBSERVATION, and only with complete evidence ══════
{
  // 6a. The honest path: customer drives the case up, CyberMeters observes the fix.
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db) };
  await baselineThen(env, [finding(HSTS)]);
  const rec = conds(db, "ws1")[0];
  let kase = casesFor(db, "ws1")[0];

  for (const target of DRIVE) {
    const d = model.canTransitionCase({ case: kase, target_status: target, actor: { actor_type: "customer", actor_id: "u1" }, owner_ref: "u1" });
    ok(`customer drives the case to ${target}`, d.ok, d.code || "");
    if (!d.ok) break;
    db.prepare("UPDATE managed_cases SET status=? WHERE id=?").run(d.case.status, kase.id);
    kase = casesFor(db, "ws1")[0];
  }
  eq("the case is awaiting verification", model.canonicalPhaseFor("website_case", kase.status), "awaiting_verification");

  // The condition disappears AND the headers module provably ran => a real fix.
  await lifecycle.evaluateWebsiteSecurityForScan(env, {
    workspace_id: "ws1", domain_id: "d1", domain: "shared.example.com", scan_id: "s9",
    findings: [], ...COMPLETE,
  });
  const after = casesFor(db, "ws1")[0];
  eq("CyberMeters' own re-observation verified the case", after.status, "verified");
  const vEv = caseEvents(db, after.id).filter((e) => e.to_status === "verified");
  eq("exactly one verification event", vEv.length, 1);
  const ev = JSON.parse(vEv[0].detail_json);
  // The registry's method, carried on the evidence — the resolveRemediation bug made this
  // null and every case unverifiable.
  eq("evidence records the registry's method", ev.verification_method, "https_recheck");
  eq("evidence names the Website Security recovery event", ev.evidence_type, "condition_resolved");
  ok("evidence carries an observation time", Boolean(ev.observed_at));
  eq("the condition itself is recorded as no longer observed",
    conds(db, "ws1")[0].monitoring_status, "no_longer_observed");
  eq("the lifecycle recorded condition_resolved",
    wsEvents(db, "ws1").filter((e) => e.event_type === "condition_resolved").length, 1);
}
{
  // 6b. THE #105 CLASS: the condition is absent but the module NEVER RAN. Absence is not a
  // fix. This must defer, never verify.
  for (const [name, opts] of [["the module did not run", NOT_RUN], ["the scan was partial", PARTIAL]]) {
    const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db) };
    await baselineThen(env, [finding(HSTS)]);
    let kase = casesFor(db, "ws1")[0];
    for (const target of DRIVE) {
      const d = model.canTransitionCase({ case: kase, target_status: target, actor: { actor_type: "customer", actor_id: "u1" }, owner_ref: "u1" });
      if (!d.ok) break;
      db.prepare("UPDATE managed_cases SET status=? WHERE id=?").run(d.case.status, kase.id);
      kase = casesFor(db, "ws1")[0];
    }
    await lifecycle.evaluateWebsiteSecurityForScan(env, {
      workspace_id: "ws1", domain_id: "d1", domain: "shared.example.com", scan_id: "sx",
      findings: [], ...opts,
    });
    const after = casesFor(db, "ws1")[0];
    ok(`${name}: the case is NOT verified`, after.status !== "verified", `status=${after.status}`);
    eq(`${name}: the condition is unknown, not recovered`, conds(db, "ws1")[0].monitoring_status, "unknown");
    eq(`${name}: no condition_resolved event was written`,
      wsEvents(db, "ws1").filter((e) => e.event_type === "condition_resolved").length, 0);
  }
}
{
  // 6c. The verifier refuses on its OWN evidence, not on its caller's branch. Called
  // directly with module_assessed false — the case must not verify, and the refusal must be
  // recorded as deferred rather than silently dropped.
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db) };
  await baselineThen(env, [finding(HSTS)]);
  const rec = conds(db, "ws1")[0];
  let kase = casesFor(db, "ws1")[0];
  for (const target of DRIVE) {
    const d = model.canTransitionCase({ case: kase, target_status: target, actor: { actor_type: "customer", actor_id: "u1" }, owner_ref: "u1" });
    if (!d.ok) break;
    db.prepare("UPDATE managed_cases SET status=? WHERE id=?").run(d.case.status, kase.id);
    kase = casesFor(db, "ws1")[0];
  }
  const r = await cases.verifyWebsiteCaseFromResolution(env, {
    workspace_id: "ws1", record_id: rec.id, module_assessed: false, detecting_module: "headers",
  });
  eq("the verifier defers when the module is not proven complete", r.skipped, "evidence_incomplete_verification_deferred");
  eq("the case is still awaiting verification", casesFor(db, "ws1")[0].status, kase.status);
  const noted = caseEvents(db, kase.id).filter((e) => e.action === "resolution_observed_not_verifying");
  eq("the deferral is recorded on the case", noted.length, 1);
  eq("recorded as deferred, not as a verification", JSON.parse(noted[0].detail_json).verification_state, "deferred");

  // Default is REFUSE: omitting the argument entirely must not verify.
  const r2 = await cases.verifyWebsiteCaseFromResolution(env, { workspace_id: "ws1", record_id: rec.id });
  eq("module_assessed defaults to refusing", r2.skipped, "evidence_incomplete_verification_deferred");

  // Cyber Essentials' recovery event must conclude nothing here.
  const r3 = await cases.verifyWebsiteCaseFromResolution(env, {
    workspace_id: "ws1", record_id: rec.id, recovery_event_type: "control_recovered", module_assessed: true,
  });
  eq("control_recovered verifies nothing in Website Security", r3.skipped, "not_a_recovery_observation");

  // THE REGISTRY IS THE AUTHORITY, not this domain's current answer.
  // Every Website Security condition is https_recheck today, so the registry stop is
  // unreachable through real WS data — which is exactly why it must be proven directly.
  // Here a website_case carries an attestation-only remediation (the shape the row would
  // have if the registry ever graded a web finding manual_attestation). Observing a
  // "recovery" must NOT conclude it: the registry says we cannot see that fix, so seeing
  // the condition gone is not evidence the customer did anything.
  const db2 = buildDb(); seed(db2); const env2 = { cybermeters_db: makeD1(db2) };
  const attRem = registry.resolveRemediation({ finding_type: "email_sender_unrecognised" });
  eq("the attestation-only remediation used here really is manual_attestation",
    attRem.verification_method, "manual_attestation");
  db2.prepare(`INSERT INTO managed_cases (id,workspace_id,case_type,domain_key,finding_id,source_finding_type,remediation_id,status,severity,created_at,updated_at)
               VALUES ('mc-att','ws1','website_case','website_security','wsc-att','x',?,'awaiting_verification','high',datetime('now'),datetime('now'))`)
    .run(attRem.remediation_id);
  const r4 = await cases.verifyWebsiteCaseFromResolution(env2, {
    workspace_id: "ws1", record_id: "wsc-att", module_assessed: true, detecting_module: "headers",
  });
  eq("an attestation-only finding is NOT verified by an observation",
    r4.skipped, "verification_not_automated_for_this_finding");
  eq("and the case did not move", db2.prepare("SELECT status FROM managed_cases WHERE id='mc-att'").get().status, "awaiting_verification");
  const nv = db2.prepare("SELECT * FROM managed_case_events WHERE case_id='mc-att'").all();
  eq("the refusal is recorded as unknown, never as a verification",
    JSON.parse(nv[0].detail_json).verification_state, "unknown");
}
{
  // 6d. A recovery observed on a case NOBODY has acted on is history, not a remediation.
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db) };
  await baselineThen(env, [finding(HSTS)]);
  const kase = casesFor(db, "ws1")[0];
  eq("the case is still at detected", kase.status, "detected");
  await lifecycle.evaluateWebsiteSecurityForScan(env, {
    workspace_id: "ws1", domain_id: "d1", domain: "shared.example.com", scan_id: "s9",
    findings: [], ...COMPLETE,
  });
  const after = casesFor(db, "ws1")[0];
  ok("an untouched case is not verified by a recovery", after.status !== "verified", `status=${after.status}`);
  eq("the observation is recorded as history", caseEvents(db, after.id).filter((e) => e.action === "resolution_observed").length, 1);
}
{
  // 6e. THE BOUNDARY: a customer cannot self-certify an externally observable condition.
  // Every Website Security case is automated, so a structured attestation must be REFUSED.
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db) };
  await baselineThen(env, [finding(HSTS)]);
  let kase = casesFor(db, "ws1")[0];
  for (const target of DRIVE) {
    const d = model.canTransitionCase({ case: kase, target_status: target, actor: { actor_type: "customer", actor_id: "u1" }, owner_ref: "u1" });
    if (!d.ok) break;
    db.prepare("UPDATE managed_cases SET status=? WHERE id=?").run(d.case.status, kase.id);
    kase = casesFor(db, "ws1")[0];
  }
  const attested = model.canTransitionCase({
    case: kase, target_status: "verified",
    actor: { actor_type: "customer", actor_id: "u1" },
    evidence: {
      verification_method: "manual_attestation", verification_result: "fixed",
      evidence_type: "customer_attestation", observed_at: new Date().toISOString(),
      attestation: { statement: "I added the HSTS header, honest.", by: "u1" },
    },
  });
  ok("a customer attestation CANNOT verify an externally observable condition", !attested.ok,
    `unexpectedly allowed: ${JSON.stringify(attested.case?.status)}`);
  // And a bare claim with no evidence at all is refused too.
  ok("a bare customer claim cannot verify", !model.canTransitionCase({
    case: kase, target_status: "verified", actor: { actor_type: "customer", actor_id: "u1" },
  }).ok);
}

// ════ 7. RECURRENCE — reopen the canonical case, never mint a second ═════════
{
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db) };
  await baselineThen(env, [finding(HSTS)]);
  const rec = conds(db, "ws1")[0];
  let kase = casesFor(db, "ws1")[0];
  for (const target of DRIVE) {
    const d = model.canTransitionCase({ case: kase, target_status: target, actor: { actor_type: "customer", actor_id: "u1" }, owner_ref: "u1" });
    if (!d.ok) break;
    db.prepare("UPDATE managed_cases SET status=? WHERE id=?").run(d.case.status, kase.id);
    kase = casesFor(db, "ws1")[0];
  }
  await lifecycle.evaluateWebsiteSecurityForScan(env, {
    workspace_id: "ws1", domain_id: "d1", domain: "shared.example.com", scan_id: "s9", findings: [], ...COMPLETE,
  });
  eq("the case verified", casesFor(db, "ws1")[0].status, "verified");

  // The condition COMES BACK.
  await lifecycle.evaluateWebsiteSecurityForScan(env, {
    workspace_id: "ws1", domain_id: "d1", domain: "shared.example.com", scan_id: "s10",
    findings: [finding(HSTS)], ...COMPLETE,
  });
  eq("still exactly ONE case — a recurrence is not a new identity", casesFor(db, "ws1").length, 1);
  const re = casesFor(db, "ws1")[0];
  eq("the canonical case reopened", re.status, "reopened");
  eq("the reopen count incremented", Number(re.reopened_count), 1);
  eq("the linkage still resolves after reopen", conds(db, "ws1")[0].linked_case_id, re.id);
  eq("a second case_linked event records the reopen",
    wsEvents(db, "ws1").filter((e) => e.event_type === "case_linked").length, 2);
  ok("the reopen went through the canonical validator (a canonical action name)",
    caseEvents(db, re.id).some((e) => e.to_status === "reopened"));
}

// ════ 8. NO PARALLEL MODEL ═══════════════════════════════════════════════════
{
  const src = fs.readFileSync(srcPath("engines", "website-security-cases.js"), "utf8");
  ok("uses the canonical factory", src.includes("createManagedCase("));
  ok("uses the canonical validator", src.includes("canTransitionCase("));
  ok("derives verification support from the canonical contract", src.includes("verificationSupportForCase("));
  ok("reads the remediation by ID, never by finding type", src.includes("getRemediationById(")
    && !/resolveRemediation\(\s*\{\s*remediation_id/.test(src));
  ok("no bespoke status machine: no hand-rolled transition table", !/CASE_MACHINE\s*=/.test(src));
  ok("no direct INSERT INTO managed_cases (the factory owns creation)",
    !/INSERT\s+INTO\s+managed_cases\b/i.test(src));
  ok("website_case is registered in the canonical registry",
    Boolean(model.CASE_TYPE_REGISTRY.website_case));
  eq("website_case belongs to the website_security domain",
    model.CASE_TYPE_REGISTRY.website_case.domain_key, "website_security");
}

// ════ 9. THE RESOLVER GUARD — the misuse cannot silently return null ═════════
{
  let threw = null;
  try { registry.resolveRemediation({ remediation_id: "web.header.hsts" }); } catch (e) { threw = e; }
  ok("resolveRemediation({remediation_id}) THROWS rather than silently resolving unknown", Boolean(threw));
  ok("the error names the correct resolver", /getRemediationById/.test(String(threw?.message)));
  let threw2 = null;
  try { registry.resolveRemediation({ findingType: "ssl_not_available" }); } catch (e) { threw2 = e; }
  ok("a camelCase near-miss also throws rather than answering 'unknown'", Boolean(threw2));
  // Legal args still work, and an unknown FINDING TYPE is still real data → honest unknown.
  eq("a legal call still resolves", registry.resolveRemediation({ finding_type: "ssl_not_available" }).status, "resolved");
  eq("an unknown finding type still fails honestly (not a throw)",
    registry.resolveRemediation({ finding_type: "made_up_xyz" }).status, "unknown");
  eq("every legal argument is accepted",
    registry.resolveRemediation({ finding_type: "ssl_not_available", domain_key: "website_security", evidence: {}, context: {}, surface: "pdf" }).status,
    "resolved");
  // No caller anywhere may use the wrong path.
  const offenders = [];
  const walk = (dir) => {
    for (const f of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, f.name);
      if (f.isDirectory()) { if (f.name !== "node_modules") walk(p); continue; }
      if (!f.name.endsWith(".js") && !f.name.endsWith(".jsx")) continue;
      const s = fs.readFileSync(p, "utf8");
      if (/resolveRemediation\(\s*\{[^}]*\bremediation_id\b/.test(s)) offenders.push(p);
    }
  };
  walk(path.join(root, "workers")); walk(path.join(root, "frontend", "src"));
  eq("no call site passes remediation_id into resolveRemediation", offenders, []);
}

// ════ 10. THE VERIFICATION VOCABULARY — cross-domain ═════════════════════════
{
  const disp = fs.readFileSync(path.join(root, "frontend", "src", "lib", "caseDisplay.js"), "utf8");
  ok("the attested wording is the founder's exact sentence",
    disp.includes("Attested by customer — not externally verifiable"));

  // Drive the real display function.
  const mod = await import(pathToFileURL(path.join(root, "frontend", "src", "lib", "caseDisplay.js")).href);
  const auto = mod.phaseMeta("verified", "automated");
  eq("an OBSERVED verification says CyberMeters verified it", auto.label, "Verified by CyberMeters");
  eq("and reads as settled", auto.tone, "green");

  const manual = mod.phaseMeta("verified", "manual");
  eq("an ATTESTATION uses the reserved-free wording", manual.label, mod.ATTESTED_LABEL);
  ok("an attestation NEVER says 'verified'", !/verified/i.test(manual.label));
  ok("an attestation NEVER says 'confirmed'", !/confirmed/i.test(manual.label));
  ok("an attestation is not green (tone carries meaning too)", manual.tone !== "green");
  ok("phaseClass follows the same split", mod.phaseClass("verified", "manual") !== mod.phaseClass("verified", "automated"));

  // FAIL CLOSED: unknown/absent support is presented as the WEAKER claim.
  for (const s of [null, undefined, "unsupported", "manual", "bogus"]) {
    ok(`support=${JSON.stringify(s)} does not claim CyberMeters verified it`,
      !/verified by cybermeters/i.test(mod.phaseMeta("verified", s).label));
  }
  // Reading the map directly must not yield a bare "Verified" either.
  ok("the phase map's verified entry is not a bare 'Verified'",
    mod.CANONICAL_PHASE_META.verified.label !== "Verified");

  // The API must SAY which it is, or the frontend cannot tell the truth.
  const route = fs.readFileSync(srcPath("routes", "managed-cases.js"), "utf8");
  ok("the case API exposes verification_support", /verification_support:\s*verificationSupportForCase\(/.test(route));
  const queue = fs.readFileSync(path.join(root, "frontend", "src", "components", "CasesQueue.jsx"), "utf8");
  ok("the cases queue passes verification_support into phaseMeta",
    /phaseMeta\(\s*c\.canonical_phase\s*,\s*c\.verification_support\s*\)/.test(queue));
  ok("the cases queue passes it into phaseClass too",
    /phaseClass\(\s*c\.canonical_phase\s*,\s*c\.verification_support\s*\)/.test(queue));

  // The canonical record exists and carries the rule forward.
  const doc = fs.readFileSync(path.join(root, "docs", "verification-vocabulary.md"), "utf8");
  ok("the vocabulary rule is recorded canonically", doc.includes("Attested by customer — not externally verifiable"));
  ok("it is carried into the M5.e parity matrix", /M5\.e/.test(doc));
  ok("it is carried into the Unified Reporting snapshot vocabulary", /Unified Reporting/.test(doc));

  // Email's manual conditions are the live consumers of the attested wording.
  const emailManual = model.verificationSupportForCase({ case_type: "email_case", remediation_id: "email.sender.review_unrecognised" });
  eq("Email's sender review remains manual (the wording has a live consumer)", emailManual, "manual");
}

// ════ 11. MUTATIONS — every guard must be PROVEN to be load-bearing ═════════
// Each mutation reintroduces a specific defect. The suite MUST fail with it applied; a
// mutation that leaves the suite green is a guard that proves nothing.
if (!process.argv.includes("--no-mutate")) {
  const MUTATIONS = [
    { file: srcPath("engines", "website-security-cases.js"),
      name: "verifier accepts incomplete module evidence (the #105 class)",
      from: "if (module_assessed !== true) {", to: "if (false) {" },
    { file: srcPath("engines", "website-security-cases.js"),
      name: "verifier trusts any recovery event (CE's control_recovered would verify)",
      from: "if (recovery_event_type !== WEBSITE_RECOVERY_EVENT) return { skipped: \"not_a_recovery_observation\" };",
      to: "if (false) return { skipped: \"not_a_recovery_observation\" };" },
    { file: srcPath("engines", "website-security-cases.js"),
      name: "verifier ignores the registry's per-finding method",
      from: "if (support !== \"automated\") {", to: "if (false) {" },
    { file: srcPath("engines", "website-security-cases.js"),
      name: "verifier skips the case machine (verifies a case nobody acted on)",
      from: "if (phase !== \"awaiting_verification\") {", to: "if (false) {" },
    { file: srcPath("engines", "website-security-cases.js"),
      name: "wrong resolver: verification_method silently null",
      from: "const rem = kase.remediation_id ? getRemediationById(kase.remediation_id) : null;",
      to: "const rem = kase.remediation_id ? { verification_method: null } : null;" },
    { file: srcPath("engines", "website-security-cases.js"),
      name: "linkage never written (linked_case_id stays null)",
      from: "async function linkConditionToCase(env, workspaceId, recordId, caseId) {\n  if (!caseId) return;",
      to: "async function linkConditionToCase(env, workspaceId, recordId, caseId) {\n  if (caseId) return;" },
    { file: srcPath("engines", "website-security-cases.js"),
      name: "recurrence mints a second case instead of reopening",
      from: "if (phase === \"verified\" || phase === \"monitoring\") {", to: "if (false) {" },
    { file: srcPath("engines", "remediation-registry.js"),
      name: "resolver misuse silently returns unknown again",
      from: "  assertResolverArgs(args);\n", to: "" },
    { file: path.join(root, "frontend", "src", "lib", "caseDisplay.js"),
      name: "an attestation is labelled 'Verified'",
      from: "      : { label: ATTESTED_LABEL, tone: 'blue' };",
      to: "      : { label: 'Verified', tone: 'green' };" },
    { file: path.join(root, "frontend", "src", "lib", "caseDisplay.js"),
      name: "unknown support optimistically claims CyberMeters verified it",
      from: "    return verificationSupport === 'automated'", to: "    return verificationSupport !== 'manual'" },
  ];
  const self = fileURLToPath(import.meta.url);
  const { execFileSync } = await import("node:child_process");
  for (const m of MUTATIONS) {
    const orig = fs.readFileSync(m.file, "utf8");
    ok(`mutation applies: ${m.name}`, orig.includes(m.from), "anchor text not found — the mutation tests nothing");
    if (!orig.includes(m.from)) continue;
    fs.writeFileSync(m.file, orig.replace(m.from, m.to));
    let survived = true;
    try { execFileSync(process.execPath, [self, "--no-mutate"], { stdio: "pipe" }); } catch { survived = false; }
    finally { fs.writeFileSync(m.file, orig); }
    ok(`mutation is CAUGHT: ${m.name}`, !survived, "the suite stayed green — this guard proves nothing");
  }
}

console.log(`\nm5a-website-cases: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
console.log("m5a-website-cases validation passed");
