#!/usr/bin/env node
//
// M5.a — Cyber Essentials Readiness managed cases. The FINAL vertical.
// DB-backed, drives the REAL engines through evaluateCyberEssentialsLifecycle. CI-blocking.
//
// The boundary this defends, stated once: **a CE control CyberMeters cannot externally
// observe must never be presented as externally verified**, and what CyberMeters CAN see is
// only ever a PARTIAL slice — so a case here verifies the externally observable evidence,
// never the control and never the customer's questionnaire answer.
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
    __sql: sql, __args: args,
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
  });
  return {
    prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; },
    // buildScorecardData batches its reads; without this the readiness builder returns
    // nothing and the evaluator skips with readiness_unavailable.
    async batch(stmts) {
      return stmts.map((st) => ({ results: db.prepare(st.__sql).all(...(st.__args || [])), success: true, meta: {} }));
    },
  };
}
globalThis.fetch = async () => new Response("{}", { status: 200 });

function seed(db) {
  db.prepare("INSERT INTO users (id,email,name,plan,created_at) VALUES ('u1','o@e.com','o','professional',datetime('now'))").run();
  db.prepare("INSERT INTO users (id,email,name,plan,created_at) VALUES ('u2','b@e.com','b','professional',datetime('now'))").run();
  db.prepare("UPDATE users SET email_verified = 1").run();
  for (const u of ["u1", "u2"]) {
    db.prepare(`INSERT INTO subscriptions (id, owner_user_id, plan, subscription_status, status, current_period_end, created_at, updated_at)
                VALUES (?,?,'professional','active','active',datetime('now','+30 days'),datetime('now'),datetime('now'))`).run(`s_${u}`, u);
  }
  for (const ws of ["ws1", "ws2"]) {
    const owner = ws === "ws1" ? "u1" : "u2";
    db.prepare("INSERT INTO workspaces (id,owner_user_id,name) VALUES (?,?,?)").run(ws, owner, ws);
    db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?,?,?,'owner')").run(`m_${ws}`, ws, owner);
    db.prepare(`INSERT OR IGNORE INTO alert_activation (id,workspace_id,domain_key,activated_at,baseline_count,created_at)
                VALUES (?,?,'cyber_essentials_readiness','2026-07-01T00:00:00Z',0,datetime('now'))`).run(`act_${ws}`, ws);
  }
}

const recs = (db, ws) => db.prepare("SELECT * FROM cyber_essentials_control_records WHERE workspace_id=?").all(ws);
const casesFor = (db, ws) => db.prepare("SELECT * FROM managed_cases WHERE workspace_id=? AND case_type='cyber_essentials_case'").all(ws);
const caseEvents = (db, id) => db.prepare("SELECT * FROM managed_case_events WHERE case_id=? ORDER BY rowid").all(id);
const ceEvents = (db, ws) => db.prepare("SELECT * FROM cyber_essentials_events WHERE workspace_id=? ORDER BY rowid").all(ws);

// The canonical path a customer drives a base-domain case along (BASE_CASE_MACHINE).
const DRIVE = ["triaged", "assigned", "approved", "action_in_progress", "awaiting_verification"];

const lifecycle = await import(eng("ce-lifecycle.js"));
const cases = await import(eng("cyber-essentials-cases.js"));
const model = await import(eng("managed-case-model.js"));
const registry = await import(eng("remediation-registry.js"));
const { CE_QUESTIONS } = await import(pathToFileURL(srcPath("lib", "cyber-essentials.js")).href);

// Sections 1-12 exercise the grader and the case layer directly. Section 8b drives the REAL
// evaluateCyberEssentialsLifecycle end to end — without it, nothing here would prove the
// lifecycle CALLS the case layer at all, which is the whole wiring this increment adds.

// ════ 1. THE CONTROL-BY-CONTROL AUTHORITY MAP — asserted, not described ══════
// Every CE control: its declared coverage, whether it is externally assessable, and
// therefore whether it can EVER open a case. Derived from the repo's own honesty metadata.
{
  const EXPECTED = {
    boundary_protection:        { coverage: "partial", assessable: true },
    secure_configuration:       { coverage: "partial", assessable: true },
    patch_management_readiness: { coverage: "none",    assessable: false },
    access_control:             { coverage: "none",    assessable: false },
    malware_protection:         { coverage: "none",    assessable: false },
  };
  eq("all five canonical CE controls are accounted for", CE_QUESTIONS.length, 5);
  for (const q of CE_QUESTIONS) {
    const e = EXPECTED[q.control_key];
    ok(`${q.control_key}: is mapped in this suite`, Boolean(e));
    if (!e) continue;
    eq(`${q.control_key}: declared coverage`, q.external_coverage || "none", e.coverage);
    eq(`${q.control_key}: externally assessable?`, lifecycle.ceControlIsExternallyAssessable(q.control_key), e.assessable);

    // A questionnaire-only control cannot even be GRADED into an actionable state — the
    // grader returns not_externally_assessable, which carries no recurrence, so no case can
    // ever be opened for it. That is the honest answer, not an omission.
    if (!e.assessable) {
      const g = lifecycle.gradeCeControl({ key: q.control_key, label: q.label, remediations: [{ remediation_id: "x", customer_title: "x" }], unknown: [] });
      eq(`${q.control_key}: grades as not_externally_assessable even WITH gap evidence`, g.state, "not_externally_assessable");
      eq(`${q.control_key}: and says why`, g.reason, "control_not_externally_observable");
      eq(`${q.control_key}: carries no fingerprint to band a recurrence on`, g.fingerprint, null);
    }
  }

  // Both recurrences, their finding type, registry method and derived support.
  const R = lifecycle.CE_RECURRENCE_FINDING_TYPE;
  eq("exactly two CE recurrences", Object.keys(R).length, 2);
  for (const [rec, ft] of Object.entries(R)) {
    eq(`${rec}: opens a case`, cases.CE_CASE_RECURRENCES.has(rec), true);
    const r = registry.resolveRemediation({ finding_type: ft });
    eq(`${rec}: resolves to a canonical remediation`, r.status, "resolved");
    // rescan = CyberMeters re-observes. So a customer can NEVER self-certify a CE case.
    eq(`${rec}: registry method is rescan (externally observable)`, r.verification_method, "rescan");
    eq(`${rec}: verification support is automated`,
      model.verificationSupportForCase({ case_type: "cyber_essentials_case", remediation_id: r.remediation_id }), "automated");
  }
  eq("the recovery event is control_recovered, NOT condition_resolved",
    cases.CE_RECOVERY_EVENT, "control_recovered");
  eq("and it is the lifecycle's own recovery event", cases.CE_RECOVERY_EVENT, lifecycle.CE_EVENT_RECOVERED);
  ok("case_linked is non-alertable by construction",
    lifecycle.CE_NON_ALERTABLE_EVENT_TYPES.includes("case_linked"));
  ok("control_recovered is non-alertable (recovery needs no customer action)",
    lifecycle.CE_NON_ALERTABLE_EVENT_TYPES.includes("control_recovered"));
}

// ════ 2. THE PARTIAL CEILING — a case never claims the CONTROL is fine ══════
{
  const src = fs.readFileSync(srcPath("engines", "cyber-essentials-cases.js"), "utf8");
  ok("the case title scopes the claim to externally observable evidence",
    /externally observable evidence for/.test(src));
  ok("the summary says explicitly this is not a CE assessment or certification",
    /not a Cyber Essentials assessment/i.test(src) && /certification/i.test(src));
  ok("the verification evidence carries its own scope",
    /verification_scope: "externally_observable_evidence_only"/.test(src));
}

// ════ 3. THE WHOLE PATH IS WALKABLE (the approved-guard P1, regression-locked) ═
{
  for (const ct of ["cyber_essentials_case", "email_case", "website_case", "certificate_case", "identity_case", "shadow_it_case"]) {
    let k = { id: "c1", workspace_id: "ws1", case_type: ct, status: "detected" };
    let reached = "detected";
    for (const t of DRIVE) {
      const d = model.canTransitionCase({ case: k, target_status: t, actor: { actor_type: "customer", actor_id: "u1" }, owner_ref: "u1" });
      if (!d.ok) break;
      k = { ...k, ...d.case }; reached = t;
    }
    eq(`${ct}: a customer can walk the FULL canonical path to awaiting_verification`, reached, "awaiting_verification");
  }
  ok("approval with no actor is still refused", !model.canTransitionCase({
    case: { id: "c", workspace_id: "w", case_type: "cyber_essentials_case", status: "assigned" },
    target_status: "approved", actor: {},
  }).ok);
}

// ── A seeded not-ready CE control record, as the evaluator would have written it ──
// The case layer's contract is (record_id, control_key, recurrence); the evaluator's job of
// producing them is proved in section 8's end-to-end pass.
function seedControl(db, { id = "cec-1", ws = "ws1", key = "boundary_protection", state = "not_ready", monitoring = "observed", fp = "ce.backlog.remediate" } = {}) {
  db.prepare(`INSERT INTO cyber_essentials_control_records
      (id, workspace_id, control_key, control_label, external_coverage, readiness_state,
       readiness_reason, evidence_fingerprint, last_assessed_at, first_seen_at, last_seen_at,
       monitoring_status, recurrence_type, lifecycle_state, created_at, updated_at)
    VALUES (?,?,?,?,'partial',?,'external_evidence_shows_gaps',?,datetime('now'),datetime('now'),
            datetime('now'),?, 'externally_observed_control_not_ready','observed',datetime('now'),datetime('now'))`)
    .run(id, ws, key, key.replace(/_/g, " "), state, fp, monitoring);
  return id;
}

// ════ 4. CASE CREATION + LINKAGE ═════════════════════════════════════════════
{
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db) };
  const id = seedControl(db);
  const res = await cases.openOrReopenCeCase(env, {
    workspace_id: "ws1", record_id: id, control_key: "boundary_protection",
    control_label: "Boundary protection", recurrence: "externally_observed_control_not_ready",
    finding_type: "ce_control_not_ready", severity: "medium",
  });
  ok("a qualifying deterioration opens a case", res.ok && res.created, res.code || "");
  const c = casesFor(db, "ws1");
  eq("exactly one case", c.length, 1);
  eq("canonical case_type", c[0].case_type, "cyber_essentials_case");
  eq("canonical domain_key", c[0].domain_key, "cyber_essentials_readiness");
  eq("opens at the canonical initial status", c[0].status, "detected");
  eq("forward pointer: finding_id = the control record", c[0].finding_id, id);
  eq("reverse pointer: linked_case_id = the case", recs(db, "ws1")[0].linked_case_id, c[0].id);
  eq("canonical remediation resolved", c[0].remediation_id, "ce.readiness.control_review");
  // CE readiness is per WORKSPACE — inventing a domain would be inventing attribution.
  eq("no domain is attributed to a workspace-scoped control", c[0].domain, null);
  eq("asset_ref names the control", c[0].asset_ref, "boundary_protection");
  ok("the title scopes the claim to the OBSERVABLE evidence, not the control",
    /externally observable evidence/i.test(c[0].title));
  eq("the reverse lookup resolves", (await cases.findCeCaseForRecord(env, "ws1", id))?.id, c[0].id);

  // A recurrence that is not a case-opening recurrence must open nothing.
  const bad = await cases.openOrReopenCeCase(env, {
    workspace_id: "ws1", record_id: id, control_key: "x", recurrence: "some_other_thing",
  });
  eq("an unmapped recurrence opens no case", bad.code, "recurrence_does_not_open_a_case");
}

// ════ 5. NO CASE FOR WHAT WE CANNOT SEE, AND NONE AT BASELINE ═══════════════
{
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db) };
  // A questionnaire-only control can never carry a case-opening recurrence, so even the
  // case layer refuses: its recurrence is not in the map.
  for (const key of ["access_control", "malware_protection", "patch_management_readiness"]) {
    const g = lifecycle.gradeCeControl({ key, label: key, remediations: [{ remediation_id: "x", customer_title: "x" }], unknown: [] });
    ok(`${key}: has no recurrence to open a case with`, !cases.CE_CASE_RECURRENCES.has(g.state));
    eq(`${key}: is not actionable`, g.state === "not_ready", false);
  }
  eq("no cases exist for questionnaire-only controls", casesFor(db, "ws1").length, 0);

  // BASELINE: a pre-existing control is recorded and remains visible WITH its remediation,
  // but opens no case (founder rule: no automatic baseline cases in this increment).
  const id = seedControl(db, { id: "cec-b", monitoring: "baseline" });
  eq("the baseline record is visible", recs(db, "ws1").length, 1);
  eq("the baseline record has an explicit no-case state", recs(db, "ws1")[0].linked_case_id, null);
  eq("its remediation is still resolvable for display",
    registry.resolveRemediation({ finding_type: "ce_control_not_ready" }).remediation_id, "ce.readiness.control_review");
  eq("no case was opened at baseline", casesFor(db, "ws1").length, 0);
}

// ════ 6. DEDUPE + OWNERSHIP ══════════════════════════════════════════════════
{
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db) };
  const id = seedControl(db);
  const args = {
    workspace_id: "ws1", record_id: id, control_key: "boundary_protection",
    recurrence: "externally_observed_control_not_ready", finding_type: "ce_control_not_ready",
  };
  await cases.openOrReopenCeCase(env, args);
  const first = casesFor(db, "ws1")[0];
  for (let i = 0; i < 3; i++) await cases.openOrReopenCeCase(env, args);
  eq("three unchanged passes create NO second case", casesFor(db, "ws1").length, 1);
  eq("and the case id is unchanged", casesFor(db, "ws1")[0].id, first.id);

  // Ownership: the universal case-level fields, through the universal validator.
  let k = casesFor(db, "ws1")[0];
  const t = model.canTransitionCase({ case: k, target_status: "triaged", actor: { actor_type: "customer", actor_id: "u1" } });
  ok("customer triages via the universal validator", t.ok, t.code || "");
  db.prepare("UPDATE managed_cases SET status=? WHERE id=?").run(t.case.status, k.id);
  const a = model.canTransitionCase({
    case: casesFor(db, "ws1")[0], target_status: "assigned",
    actor: { actor_type: "customer", actor_id: "u1" }, owner_ref: "u1", owner_type: "customer",
  });
  ok("customer assigns via universal case-level assignment", a.ok, a.code || "");
  ok("assignment with no owner_ref is refused", !model.canTransitionCase({
    case: casesFor(db, "ws1")[0], target_status: "assigned", actor: { actor_type: "customer", actor_id: "u1" },
  }).ok);
  ok("no CE-specific ownership table exists",
    !fs.readdirSync(path.join(root, "database", "migrations")).some((f) => /(^|-)ce.*(owner|assign)/i.test(f)));
}

// Drive a seeded case along the REAL customer path to awaiting_verification.
async function driveToAwaiting(db, env, id) {
  await cases.openOrReopenCeCase(env, {
    workspace_id: "ws1", record_id: id, control_key: "boundary_protection",
    recurrence: "externally_observed_control_not_ready", finding_type: "ce_control_not_ready",
  });
  let k = casesFor(db, "ws1")[0];
  for (const t of DRIVE) {
    const d = model.canTransitionCase({ case: k, target_status: t, actor: { actor_type: "customer", actor_id: "u1" }, owner_ref: "u1" });
    if (!d.ok) return { ok: false, at: t, code: d.code };
    db.prepare("UPDATE managed_cases SET status=? WHERE id=?").run(d.case.status, k.id);
    k = casesFor(db, "ws1")[0];
  }
  return { ok: true, case: k };
}

// ════ 7. THE VERIFICATION BOUNDARY ═══════════════════════════════════════════
{
  // 7a. The honest path: customer acts, CyberMeters re-observes.
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db) };
  const id = seedControl(db);
  const drove = await driveToAwaiting(db, env, id);
  ok("the customer reached awaiting_verification through the real path", drove.ok, JSON.stringify(drove));
  const r = await cases.verifyCeCaseFromRecovery(env, {
    workspace_id: "ws1", record_id: id, evidence_complete: true, control_key: "boundary_protection", scan_id: "s1",
  });
  ok("complete re-observation verifies the case", r.ok && r.verified, JSON.stringify(r));
  const after = casesFor(db, "ws1")[0];
  eq("the case is verified", after.status, "verified");
  const ev = JSON.parse(caseEvents(db, after.id).filter((e) => e.to_status === "verified")[0].detail_json);
  eq("evidence records the registry's method", ev.verification_method, "rescan");
  eq("evidence names CE's own recovery event", ev.evidence_type, "control_recovered");
  // THE PARTIAL CEILING, carried on the evidence itself.
  eq("evidence records that only the observable slice was verified", ev.verification_scope, "externally_observable_evidence_only");
  eq("evidence records the partial coverage", ev.external_coverage, "partial");
  // And the vocabulary: automated support => "Verified by CyberMeters".
  const disp = await import(pathToFileURL(path.join(root, "frontend", "src", "lib", "caseDisplay.js")).href);
  eq("an automated CE verification renders 'Verified by CyberMeters'",
    disp.phaseMeta("verified", model.verificationSupportForCase(after)).label, "Verified by CyberMeters");
}
{
  // 7b. INCOMPLETE EVIDENCE DEFERS — the #105 class. Default is refuse.
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db) };
  const id = seedControl(db);
  await driveToAwaiting(db, env, id);
  const before = casesFor(db, "ws1")[0].status;
  const r = await cases.verifyCeCaseFromRecovery(env, { workspace_id: "ws1", record_id: id, evidence_complete: false });
  eq("incomplete external evidence defers", r.skipped, "evidence_incomplete_verification_deferred");
  eq("the case did not move", casesFor(db, "ws1")[0].status, before);
  const noted = caseEvents(db, casesFor(db, "ws1")[0].id).filter((e) => e.action === "recovery_observed_not_verifying");
  eq("the deferral is recorded", noted.length, 1);
  eq("recorded as deferred, never as a verification", JSON.parse(noted[0].detail_json).verification_state, "deferred");

  const r2 = await cases.verifyCeCaseFromRecovery(env, { workspace_id: "ws1", record_id: id });
  eq("evidence_complete defaults to REFUSING", r2.skipped, "evidence_incomplete_verification_deferred");

  // Website Security's recovery event must conclude nothing here.
  const r3 = await cases.verifyCeCaseFromRecovery(env, {
    workspace_id: "ws1", record_id: id, recovery_event_type: "condition_resolved", evidence_complete: true,
  });
  eq("condition_resolved verifies nothing in Cyber Essentials", r3.skipped, "not_a_recovery_observation");
}
{
  // 7c. A customer assertion is NEVER a verification for an observable finding.
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db) };
  const id = seedControl(db);
  const drove = await driveToAwaiting(db, env, id);
  const attested = model.canTransitionCase({
    case: drove.case, target_status: "verified",
    actor: { actor_type: "customer", actor_id: "u1" },
    evidence: {
      verification_method: "manual_attestation", verification_result: "fixed",
      evidence_type: "customer_attestation", observed_at: new Date().toISOString(),
      attestation: { statement: "We fixed our firewall, honest.", by: "u1" },
    },
  });
  ok("a customer attestation cannot verify an externally observable CE control", !attested.ok,
    `unexpectedly allowed: ${attested.case?.status}`);
  ok("a bare customer claim cannot verify", !model.canTransitionCase({
    case: drove.case, target_status: "verified", actor: { actor_type: "customer", actor_id: "u1" },
  }).ok);
  // A questionnaire answer cannot fake a recovery: answers are not the recovery event.
  const r = await cases.verifyCeCaseFromRecovery(env, {
    workspace_id: "ws1", record_id: id, recovery_event_type: "questionnaire_answered", evidence_complete: true,
  });
  eq("a questionnaire answer is not a recovery observation", r.skipped, "not_a_recovery_observation");
  eq("the case is still awaiting verification", casesFor(db, "ws1")[0].status, "awaiting_verification");
}
{
  // 7d. A recovery on a case nobody acted on is history, not a remediation.
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db) };
  const id = seedControl(db);
  await cases.openOrReopenCeCase(env, {
    workspace_id: "ws1", record_id: id, control_key: "boundary_protection",
    recurrence: "externally_observed_control_not_ready", finding_type: "ce_control_not_ready",
  });
  const r = await cases.verifyCeCaseFromRecovery(env, { workspace_id: "ws1", record_id: id, evidence_complete: true });
  eq("an untouched case is not verified by a recovery", r.skipped, "case_not_awaiting_verification");
  eq("the observation is recorded as history",
    caseEvents(db, casesFor(db, "ws1")[0].id).filter((e) => e.action === "recovery_observed").length, 1);
}
{
  // 7e. THE REGISTRY IS THE AUTHORITY. Every CE finding is `rescan` today, so this stop is
  // unreachable through real CE data — which is exactly why it is proven directly. A CE case
  // carrying an attestation-only remediation must NOT be concluded by an observation.
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db) };
  const attRem = registry.resolveRemediation({ finding_type: "email_sender_unrecognised" });
  eq("the attestation-only remediation used here really is manual_attestation", attRem.verification_method, "manual_attestation");
  db.prepare(`INSERT INTO managed_cases (id,workspace_id,case_type,domain_key,finding_id,source_finding_type,remediation_id,status,severity,created_at,updated_at)
              VALUES ('mc-att','ws1','cyber_essentials_case','cyber_essentials_readiness','cec-att','x',?,'awaiting_verification','high',datetime('now'),datetime('now'))`)
    .run(attRem.remediation_id);
  const r = await cases.verifyCeCaseFromRecovery(env, { workspace_id: "ws1", record_id: "cec-att", evidence_complete: true });
  eq("an attestation-only finding is NOT verified by an observation", r.skipped, "verification_not_automated_for_this_finding");
  eq("the case did not move", db.prepare("SELECT status FROM managed_cases WHERE id='mc-att'").get().status, "awaiting_verification");
  eq("recorded as unknown, never as a verification",
    JSON.parse(db.prepare("SELECT * FROM managed_case_events WHERE case_id='mc-att'").all()[0].detail_json).verification_state, "unknown");
  // And the vocabulary renders the honest ceiling for it.
  const disp = await import(pathToFileURL(path.join(root, "frontend", "src", "lib", "caseDisplay.js")).href);
  const m = disp.phaseMeta("verified", "manual");
  ok("a manual case never renders 'verified'", !/verified/i.test(m.label));
  ok("nor 'confirmed'", !/confirmed/i.test(m.label));
  ok("nor green", m.tone !== "green");
  // FAIL CLOSED. A CE case whose support cannot be resolved must NOT claim CyberMeters
  // verified it — guessing "automated" from silence is the optimistic-healthy default the
  // platform forbids, and CE is where it would hurt most: a control we cannot see.
  for (const sup of [null, undefined, "unsupported", "bogus", ""]) {
    ok(`CE support=${JSON.stringify(sup)} does not claim CyberMeters verified it`,
      !/verified by cybermeters/i.test(disp.phaseMeta("verified", sup).label));
    ok(`CE support=${JSON.stringify(sup)} is not green`, disp.phaseMeta("verified", sup).tone !== "green");
  }
}

// ════ 8. RECURRENCE — the exact sequence, end to end through the REAL engine ═
{
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db) };
  const id = seedControl(db);
  const drove = await driveToAwaiting(db, env, id);
  await cases.verifyCeCaseFromRecovery(env, { workspace_id: "ws1", record_id: id, evidence_complete: true });
  eq("the case verified", casesFor(db, "ws1")[0].status, "verified");
  const linkedBefore = ceEvents(db, "ws1").filter((e) => e.event_type === "case_linked").length;

  // The evidence DETERIORATES again.
  const again = await cases.openOrReopenCeCase(env, {
    workspace_id: "ws1", record_id: id, control_key: "boundary_protection",
    recurrence: "externally_observed_control_worsened", finding_type: "ce_control_worsened",
  });
  ok("deterioration after recovery reopens", again.ok && again.reopened, JSON.stringify(again));
  eq("still exactly ONE case — a recurrence is not a new identity", casesFor(db, "ws1").length, 1);
  const re = casesFor(db, "ws1")[0];
  eq("the canonical case reopened", re.status, "reopened");
  eq("the reopen count incremented", Number(re.reopened_count), 1);
  eq("the linkage still resolves", recs(db, "ws1")[0].linked_case_id, re.id);
  ok("the reopen went through the canonical validator", caseEvents(db, re.id).some((e) => e.to_status === "reopened"));

  // Recurrence must be detectable regardless of event AGE: the case-layer reopen reads
  // lifecycle STATE (the case's own phase), never a bounded recent-event window.
  const src = fs.readFileSync(srcPath("engines", "cyber-essentials-cases.js"), "utf8");
  ok("no bounded event window governs reopen", !/LIMIT\s+\d{1,2}\b/.test(src.replace(/LIMIT 1\b/g, "")));
}

// ════ 8b. END TO END THROUGH THE REAL EVALUATOR ═════════════════════════════
// The wiring, proven rather than asserted: a real scan report with missing security headers
// drives evaluateCyberEssentialsLifecycle, which must itself open the case, write the
// linkage and later verify it. Uses the same seam as validate-ce-lifecycle.js: the R2 report
// the workspace's own latest scan produced.
{
  const db = buildDb(); seed(db); 
  db.prepare("INSERT INTO domains (id,user_id,domain,created_at) VALUES ('d1','u1','acme.example.com',datetime('now'))").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES ('ws1','d1')").run();
  let REPORT = null;
  const env = {
    cybermeters_db: makeD1(db),
    cybermeters_reports: { get: async () => (REPORT ? { json: async () => REPORT } : null) },
  };
  const setScan = (id) => {
    db.prepare("DELETE FROM scans WHERE workspace_id='ws1'").run();
    db.prepare(`INSERT INTO scans (id,domain_id,workspace_id,domain,score,rating,status,scan_quality,created_at)
                VALUES (?,'d1','ws1','acme.example.com',70,'fair','completed','complete',datetime('now'))`).run(id);
  };
  const HEALTHY = () => ({ modules: {
    headers: { accessible: true, headers_assessed: true, values: { "strict-transport-security": "max-age=63072000", "content-security-policy": "default-src 'self'" }, present: [], missing: [] },
    ssl: { https_available: true, https_probe_executed: true, http_redirects_to_https: true },
    email_security: { spf: { present: true }, dmarc: { present: true, policy: "reject" }, dkim: { present: true } },
  } });
  const NO_HEADERS = () => ({ modules: {
    headers: { accessible: true, headers_assessed: true, values: {}, present: [], missing: ["strict-transport-security", "content-security-policy"] },
    ssl: { https_available: true, https_probe_executed: true, http_redirects_to_https: true },
    email_security: { spf: { present: true }, dmarc: { present: true, policy: "reject" }, dkim: { present: true } },
  } });
  const HEADERS_DEAD = () => ({ modules: {
    headers: { accessible: false, incomplete: true, incomplete_reason: "probe_not_executed" },
    ssl: { https_available: true, https_probe_executed: true, http_redirects_to_https: true },
    email_security: { spf: { present: true }, dmarc: { present: true, policy: "reject" }, dkim: { present: true } },
  } });

  // Pass 1 — BASELINE. Everything found now predates our watching.
  REPORT = HEALTHY(); setScan("scan_1");
  await lifecycle.evaluateCyberEssentialsLifecycle(env, "ws1", { scanId: "scan_1" });
  eq("baseline pass opens NO case", casesFor(db, "ws1").length, 0);

  // Pass 2 — the headers disappear. THIS is the event that creates the first case:
  // a post-baseline monitoring_changed carrying to_recurrence_type
  // externally_observed_control_not_ready on an externally assessable control.
  //
  // Removing HSTS+CSP makes TWO controls not-ready — boundary_protection AND
  // secure_configuration both read those headers as evidence — so the engine opens ONE CASE
  // PER CONTROL. That is the correct identity: a case is per control record, and a customer
  // fixes each control, not "the headers".
  REPORT = NO_HEADERS(); setScan("scan_2");
  await lifecycle.evaluateCyberEssentialsLifecycle(env, "ws1", { scanId: "scan_2" });
  const opened = casesFor(db, "ws1");
  const notReady = db.prepare("SELECT control_key FROM cyber_essentials_control_records WHERE workspace_id='ws1' AND readiness_state='not_ready'").all().map((r) => r.control_key);
  ok("the deterioration made at least one externally assessable control not-ready", notReady.length > 0, JSON.stringify(notReady));
  eq("exactly ONE case per not-ready control — no more, no fewer", opened.length, notReady.length);
  eq("every case names an externally assessable control",
    opened.every((c) => ["boundary_protection", "secure_configuration"].includes(c.asset_ref)), true);
  ok("no case for any control declared not externally assessable",
    !opened.some((c) => ["access_control", "malware_protection", "patch_management_readiness"].includes(c.asset_ref)));
  // Every not-ready control's record points at its own case, and vice versa.
  for (const key of notReady) {
    const rec = db.prepare("SELECT * FROM cyber_essentials_control_records WHERE workspace_id='ws1' AND control_key=?").get(key);
    const mine = opened.filter((c) => c.asset_ref === key);
    eq(`${key}: exactly one case`, mine.length, 1);
    eq(`${key}: the real evaluator wrote the linkage`, rec.linked_case_id, mine[0].id);
    eq(`${key}: the case points back at the record`, mine[0].finding_id, rec.id);
  }
  eq("one case_linked event per opened case",
    ceEvents(db, "ws1").filter((e) => e.event_type === "case_linked").length, opened.length);

  // Pass 3 — UNCHANGED. Must stay silent and create nothing.
  REPORT = NO_HEADERS(); setScan("scan_3");
  await lifecycle.evaluateCyberEssentialsLifecycle(env, "ws1", { scanId: "scan_3" });
  eq("an unchanged repeat creates no second case", casesFor(db, "ws1").length, opened.length);
  eq("and writes no second case_linked row",
    ceEvents(db, "ws1").filter((e) => e.event_type === "case_linked").length, opened.length);

  // Drive EVERY opened case to awaiting_verification the way a customer does.
  for (const c0 of opened) {
    let k = db.prepare("SELECT * FROM managed_cases WHERE id=?").get(c0.id);
    for (const t of DRIVE) {
      const d = model.canTransitionCase({ case: k, target_status: t, actor: { actor_type: "customer", actor_id: "u1" }, owner_ref: "u1" });
      ok(`e2e ${c0.asset_ref}: customer drives to ${t}`, d.ok, d.code || "");
      if (!d.ok) break;
      db.prepare("UPDATE managed_cases SET status=? WHERE id=?").run(d.case.status, k.id);
      k = db.prepare("SELECT * FROM managed_cases WHERE id=?").get(c0.id);
    }
    eq(`e2e ${c0.asset_ref}: reached awaiting_verification`, k.status, "awaiting_verification");
  }

  // Pass 4 — THE PROBE DIES. Absence of evidence is NOT a fix: must not verify.
  REPORT = HEADERS_DEAD(); setScan("scan_4");
  await lifecycle.evaluateCyberEssentialsLifecycle(env, "ws1", { scanId: "scan_4" });
  eq("a dead probe verifies NOTHING", casesFor(db, "ws1").filter((c) => c.status === "verified").length, 0);
  for (const key of notReady) {
    eq(`${key}: reads unknown, never recovered`,
      db.prepare("SELECT readiness_state FROM cyber_essentials_control_records WHERE workspace_id='ws1' AND control_key=?").get(key).readiness_state, "unknown");
  }
  eq("no control_recovered was written from a dead probe",
    ceEvents(db, "ws1").filter((e) => e.event_type === "control_recovered").length, 0);

  // Pass 5 — the headers come BACK, observed. The real evaluator verifies.
  REPORT = HEALTHY(); setScan("scan_5");
  await lifecycle.evaluateCyberEssentialsLifecycle(env, "ws1", { scanId: "scan_5" });
  eq("real re-observation verified every case end to end",
    casesFor(db, "ws1").filter((c) => c.status === "verified").length, opened.length);
  eq("control_recovered written once per recovered control",
    ceEvents(db, "ws1").filter((e) => e.event_type === "control_recovered").length, notReady.length);

  // Pass 6 — it DETERIORATES again: the canonical cases reopen, no second identity.
  REPORT = NO_HEADERS(); setScan("scan_6");
  await lifecycle.evaluateCyberEssentialsLifecycle(env, "ws1", { scanId: "scan_6" });
  eq("still exactly the same cases after a full recur cycle", casesFor(db, "ws1").length, opened.length);
  eq("every canonical case reopened", casesFor(db, "ws1").filter((c) => c.status === "reopened").length, opened.length);
  eq("reopen count incremented on each",
    casesFor(db, "ws1").every((c) => Number(c.reopened_count) === 1), true);
  eq("a case_linked event records each reopen",
    ceEvents(db, "ws1").filter((e) => e.event_type === "case_linked").length, opened.length * 2);
}

// ════ 9. TENANT ISOLATION ════════════════════════════════════════════════════
{
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db) };
  // The SAME control key in two tenants.
  const a = seedControl(db, { id: "cec-a", ws: "ws1" });
  const b = seedControl(db, { id: "cec-b", ws: "ws2" });
  const mk = (ws, id) => cases.openOrReopenCeCase(env, {
    workspace_id: ws, record_id: id, control_key: "boundary_protection",
    recurrence: "externally_observed_control_not_ready", finding_type: "ce_control_not_ready",
  });
  await mk("ws1", a); await mk("ws2", b);
  eq("ws1 has its own case", casesFor(db, "ws1").length, 1);
  eq("ws2 has its own case", casesFor(db, "ws2").length, 1);
  ok("the two tenants' cases are distinct", casesFor(db, "ws1")[0].id !== casesFor(db, "ws2")[0].id);
  eq("ws2 cannot read ws1's case via ws1's record id", await cases.findCeCaseForRecord(env, "ws2", a), null);
  // A foreign record id is indistinguishable from a nonexistent one — non-enumerating.
  eq("a foreign record and a nonexistent one are the same answer",
    await cases.findCeCaseForRecord(env, "ws2", a), await cases.findCeCaseForRecord(env, "ws2", "cec-does-not-exist"));
  // Verifying a foreign record must do nothing.
  const v = await cases.verifyCeCaseFromRecovery(env, { workspace_id: "ws2", record_id: a, evidence_complete: true });
  eq("ws2 cannot verify ws1's case", v.skipped, "no_open_case");

  // Soft-deleted workspace: nonexistent.
  db.prepare("UPDATE workspaces SET deleted_at=datetime('now') WHERE id='ws2'").run();
  const c2 = seedControl(db, { id: "cec-c", ws: "ws2", key: "secure_configuration" });
  const r = await mk("ws2", c2);
  ok("a soft-deleted workspace opens no case", !r.ok || r.code === "workspace_inactive", JSON.stringify(r));
  eq("and no second case appeared", casesFor(db, "ws2").length, 1);
}

// ════ 10. PURGE — in safe order, no orphan, no foreign damage ════════════════
// The historical lesson (#106): cyber_essentials_answers survived every purge while the
// deletion email said "permanently removed", because it carried no FK and nobody seeded it
// in the test. linked_case_id is exactly that shape again — a bare TEXT pointer with no FK —
// so this proves the new linkage cannot recreate that class.
{
  const worker = await import(pathToFileURL(srcPath("index.js")).href);
  const T = worker.WORKSPACE_PURGE_TABLES;
  for (const t of ["cyber_essentials_events", "cyber_essentials_control_records", "cyber_essentials_answers", "managed_cases", "managed_case_events"]) {
    ok(`purge covers ${t}`, T.includes(t));
  }
  // Order: children before parents. Events hold no FK to their record table but must go
  // first anyway — history must never outlive the purge of what it describes.
  ok("cyber_essentials_events is purged before cyber_essentials_control_records",
    T.indexOf("cyber_essentials_events") < T.indexOf("cyber_essentials_control_records"));
  ok("managed_case_events is purged before managed_cases",
    T.indexOf("managed_case_events") < T.indexOf("managed_cases"));

  // End-to-end: a workspace with a linked CE case purges to nothing, and the OTHER tenant
  // is untouched.
  const db = buildDb(); seed(db); const env = { cybermeters_db: makeD1(db) };
  const a = seedControl(db, { id: "cec-p1", ws: "ws1" });
  const b = seedControl(db, { id: "cec-p2", ws: "ws2" });
  for (const [ws, id] of [["ws1", a], ["ws2", b]]) {
    await cases.openOrReopenCeCase(env, {
      workspace_id: ws, record_id: id, control_key: "boundary_protection",
      recurrence: "externally_observed_control_not_ready", finding_type: "ce_control_not_ready",
    });
  }
  db.prepare(`INSERT INTO cyber_essentials_answers (id,workspace_id,control_key,question_key,answer,note,answered_by,updated_at)
              VALUES ('a1','ws1','access_control','q1','yes','n','u1',datetime('now'))`).run();
  eq("ws1 has a linked case before purge", recs(db, "ws1")[0].linked_case_id !== null, true);

  // The purge is BATCHED: it returns {done:false} until reports and scans are drained.
  // Driving it to completion is the only honest way to prove it purges.
  const penv = { cybermeters_db: env.cybermeters_db, cybermeters_reports: { delete: async () => {} } };
  let guard = 0, res;
  do { res = await worker.purgeWorkspaceData(penv, "ws1"); } while (res && res.done === false && ++guard < 50);
  eq("the purge ran to completion", res?.done, true);

  eq("ws1 control records purged", recs(db, "ws1").length, 0);
  eq("ws1 CE events purged", ceEvents(db, "ws1").length, 0);
  eq("ws1 cases purged", casesFor(db, "ws1").length, 0);
  eq("ws1 case events purged", db.prepare("SELECT COUNT(*) c FROM managed_case_events WHERE workspace_id='ws1'").get().c, 0);
  eq("ws1 questionnaire answers purged (the #106 lesson)",
    db.prepare("SELECT COUNT(*) c FROM cyber_essentials_answers WHERE workspace_id='ws1'").get().c, 0);
  // No orphan: nothing anywhere still points at a purged case.
  eq("no linked_case_id orphan survives",
    db.prepare(`SELECT COUNT(*) c FROM cyber_essentials_control_records r
                WHERE r.linked_case_id IS NOT NULL
                  AND NOT EXISTS (SELECT 1 FROM managed_cases m WHERE m.id = r.linked_case_id)`).get().c, 0);
  // The other tenant is untouched.
  eq("ws2 control records survive", recs(db, "ws2").length, 1);
  eq("ws2 case survives", casesFor(db, "ws2").length, 1);
  eq("ws2 linkage still resolves", recs(db, "ws2")[0].linked_case_id, casesFor(db, "ws2")[0].id);
}

// ════ 11. READ SURFACE + ALERT LINK ══════════════════════════════════════════
{
  const api = lifecycle.ceControlRecordToApi({
    id: "cec-1", control_key: "boundary_protection", control_label: "Boundary protection",
    readiness_state: "not_ready", external_coverage: "partial", linked_case_id: "mc-1",
    evidence_json: "[]", unknown_json: "[]",
  });
  eq("the read surface exposes the linked case", api.linked_case_id, "mc-1");
  eq("and the partial coverage, so nothing reads as a full assessment", api.external_coverage, "partial");
  eq("a record with no case says so honestly (null, not a fabricated id)",
    lifecycle.ceControlRecordToApi({ id: "x" }).linked_case_id, null);

  const route = fs.readFileSync(srcPath("routes", "cyber-essentials-controls.js"), "utf8");
  ok("the route resolves the linked case only when one exists", /if \(rec\.linked_case_id\)/.test(route));
  ok("the route is tenant-scoped when resolving the case", /WHERE id = \? AND workspace_id = \?/.test(route));
  ok("the route ships an explicit scope note", /scope_note/.test(route));

  // The alert must be able to name the case, and the deep link must resolve.
  const lc = fs.readFileSync(srcPath("engines", "ce-lifecycle.js"), "utf8");
  ok("the CE alert carries the case id it just opened", /case_id: opened\?\.case_id/.test(lc));
  const consumers = await import(eng("alert-consumers.js"));
  const link = consumers.lifecycleRecordLink({ FRONTEND_URL: "https://app.cybermeters.com" }, "cyber_essentials_readiness", "cec-1");
  ok("the CE alert deep link resolves to a real CE read surface", Boolean(link) && /cec-1/.test(link), String(link));

  // The API must SAY the verification support, or the frontend cannot tell the truth.
  const mc = fs.readFileSync(srcPath("routes", "managed-cases.js"), "utf8");
  ok("the case API exposes verification_support", /verification_support:\s*verificationSupportForCase\(/.test(mc));
  const queue = fs.readFileSync(path.join(root, "frontend", "src", "components", "CasesQueue.jsx"), "utf8");
  ok("the frontend CONSUMES it rather than deriving a verdict",
    /phaseMeta\(\s*c\.canonical_phase\s*,\s*c\.verification_support\s*\)/.test(queue));
  const disp = fs.readFileSync(path.join(root, "frontend", "src", "lib", "caseDisplay.js"), "utf8");
  ok("the frontend never re-derives support from a registry of its own",
    !/manual_attestation|remediation_registry|verification_method/.test(disp));
}

// ════ 12. NO PARALLEL MODEL ══════════════════════════════════════════════════
{
  const src = fs.readFileSync(srcPath("engines", "cyber-essentials-cases.js"), "utf8");
  ok("uses the canonical factory", src.includes("createManagedCase("));
  ok("uses the canonical validator", src.includes("canTransitionCase("));
  ok("derives verification support from the canonical contract", src.includes("verificationSupportForCase("));
  ok("reads the remediation by ID, never by finding type",
    src.includes("getRemediationById(") && !/resolveRemediation\(\s*\{\s*remediation_id/.test(src));
  ok("no bespoke status machine", !/CASE_MACHINE\s*=/.test(src));
  ok("no direct INSERT INTO managed_cases", !/INSERT\s+INTO\s+managed_cases\b/i.test(src));
  ok("cyber_essentials_case is registered canonically", Boolean(model.CASE_TYPE_REGISTRY.cyber_essentials_case));
  eq("and belongs to the CE domain", model.CASE_TYPE_REGISTRY.cyber_essentials_case.domain_key, "cyber_essentials_readiness");
  ok("condition_resolved (Website Security's vocabulary) concludes nothing here",
    !/recovery_event_type === "condition_resolved"/.test(src));
}

// ════ 13. MUTATIONS ══════════════════════════════════════════════════════════
if (!process.argv.includes("--no-mutate")) {
  const CE = srcPath("engines", "cyber-essentials-cases.js");
  const DISP = path.join(root, "frontend", "src", "lib", "caseDisplay.js");
  const MUTATIONS = [
    { file: CE, name: "incomplete evidence accepted (the #105 class)",
      from: "if (evidence_complete !== true) {", to: "if (false) {" },
    { file: CE, name: "control_recovered ignored — any event verifies",
      from: "if (recovery_event_type !== CE_RECOVERY_EVENT) return { skipped: \"not_a_recovery_observation\" };",
      to: "if (false) return { skipped: \"not_a_recovery_observation\" };" },
    { file: CE, name: "registry verification method bypassed",
      from: "if (support !== \"automated\") {", to: "if (false) {" },
    { file: CE, name: "case machine bypassed (verifies a case nobody acted on)",
      from: "if (phase !== \"awaiting_verification\") {", to: "if (false) {" },
    { file: CE, name: "linked_case_id write removed",
      from: "async function linkControlToCase(env, workspaceId, recordId, caseId) {\n  if (!caseId) return;",
      to: "async function linkControlToCase(env, workspaceId, recordId, caseId) {\n  if (caseId) return;" },
    // NOT mutation-tested, deliberately: dropping `AND workspace_id = ?` from the linkage
    // write changes NOTHING observable, because a control record id is a globally unique
    // primary key — no two tenants can hold the same one, so the scope can never actually
    // select a foreign row. The clause stays (defence in depth, and the next schema change
    // may make it load-bearing), but a mutation asserting it would be decorative: it would
    // pass whatever the code did. Tenant isolation is proven for real in section 9, where
    // the reads and the verifier are attacked cross-tenant with a real foreign id.
    { file: CE, name: "recurrence reopen removed (mints a second case)",
      from: "if (phase === \"verified\" || phase === \"monitoring\") {", to: "if (false) {" },
    { file: CE, name: "wrong resolver: verification_method silently null",
      from: "const rem = kase.remediation_id ? getRemediationById(kase.remediation_id) : null;",
      to: "const rem = kase.remediation_id ? { verification_method: null } : null;" },
    { file: CE, name: "the partial ceiling dropped from the evidence",
      from: "    verification_scope: \"externally_observable_evidence_only\",", to: "" },
    { file: CE, name: "an unmapped recurrence may open a case",
      from: "if (!CE_CASE_RECURRENCES.has(recurrence)) return { ok: false, code: \"recurrence_does_not_open_a_case\" };",
      to: "if (false) return { ok: false, code: \"recurrence_does_not_open_a_case\" };" },
    { file: DISP, name: "attestation painted green / labelled Verified",
      from: "    return { label: ATTESTED_LABEL, tone: 'blue' };", to: "    return { label: 'Verified', tone: 'green' };" },
    { file: DISP, name: "unknown support optimistically claims CyberMeters verified it",
      from: "    if (verificationSupport === 'automated') return { label: 'Verified by CyberMeters', tone: 'green' };",
      to: "    if (verificationSupport !== 'manual') return { label: 'Verified by CyberMeters', tone: 'green' };" },
    { file: srcPath("routes", "managed-cases.js"), name: "verification_support deleted from the API contract",
      from: "    verification_support: verificationSupportForCase(row),", to: "" },
    { file: srcPath("engines", "managed-case-model.js"), name: "the approved-guard P1 reintroduced",
      from: "    approved:         [(_row, ctx) => requireActor(ctx)],", to: "    approved:         [requireActor]," },
    { file: srcPath("index.js"), name: "purge order broken (events after their parent)",
      from: '"cyber_essentials_events", "cyber_essentials_control_records",',
      to: '"cyber_essentials_control_records", "cyber_essentials_events",' },
    { file: srcPath("index.js"), name: "CE answers dropped from purge (the #106 defect)",
      from: '  "cyber_essentials_answers",', to: "" },
  ];
  const self = fileURLToPath(import.meta.url);
  const { execFileSync } = await import("node:child_process");
  for (const m of MUTATIONS) {
    const orig = fs.readFileSync(m.file, "utf8");
    ok(`mutation applies: ${m.name}`, orig.includes(m.from), "anchor not found — the mutation tests nothing");
    if (!orig.includes(m.from)) continue;
    fs.writeFileSync(m.file, orig.replace(m.from, m.to));
    let survived = true;
    try { execFileSync(process.execPath, [self, "--no-mutate"], { stdio: "pipe" }); } catch { survived = false; }
    finally { fs.writeFileSync(m.file, orig); }
    ok(`mutation is CAUGHT: ${m.name}`, !survived, "the suite stayed green — this guard proves nothing");
  }
}

console.log(`\nm5a-ce-cases: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
console.log("m5a-ce-cases validation passed");
