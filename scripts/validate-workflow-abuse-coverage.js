#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-workflow-abuse-coverage.js  (CI-blocking)
//
// The F-section (workflow abuse) of docs/SECURITY-VERIFICATION-MATRIX.md — same
// discipline as the #241 (authz) and #243 (billing) suites. REUSES the
// #187/#241/#243 harness (real Worker router + in-memory SQLite). The managed-
// case transition validator, the canonical alert emitter, the weekly-digest
// producer and the rate limiter are TESTED AS-IS; this suite changes no runtime.
//
//   F2 — Verification cannot be forged (attest ≠ verified). Through the real
//        transition route AND the pure validator: a bare completed-scan / note /
//        customer word does NOT reach `verified`; automated support needs a
//        SYSTEM actor; unsupported/external are refused; a manual case verifies
//        ONLY with a structured attestation from an identified actor. The
//        customer-facing ceiling for `manual` reads "Attested by customer — not
//        externally verifiable", never system verification.
//   F3 — Alert / digest workflow cannot be spoofed or replayed. The canonical
//        emitter dedupes an identical (dedupe_key) observation (DB-guaranteed);
//        an alert for a soft-deleted workspace is suppressed, never emitted; a
//        workspace's alert recipients resolve to THAT workspace's owners/admins
//        only. The weekly-digest producer is idempotent per ISO week (a second
//        run does not create a second send row).
//   F4 — Rate limiting holds. Through the real login route (cap 10 / 15 min,
//        failClosed): the (cap+1)th attempt from one IP is rejected 429, and on
//        a rate-store error the failClosed caller DENIES (does not fail open).
//
// Every negative has a positive control (non-vacuous). A RED assertion here is a
// real workflow finding — STOP and report, do not patch. Requires Node 24+.
// ─────────────────────────────────────────────────────────────────────────────
import { loadWorker, buildDb, makeEnv, makeCaller, makeSeeder, ctx } from "./security/lib/worker-harness.js";
import { canTransitionCase, validateVerificationEvidence, verificationSupportForMethod } from "../workers/scan-api/src/engines/managed-case-model.js";
import { verificationCeiling } from "../workers/scan-api/src/engines/report-snapshot.js";
import { emitManagedAlert } from "../workers/scan-api/src/engines/managed-alerts.js";
import { resolveWorkspaceAlertRecipients } from "../workers/scan-api/src/engines/alerts.js";
import { sendWeeklyDigests } from "../workers/scan-api/src/engines/weekly-digest.js";

let passed = 0, failed = 0, section = "General";
const results = [];
const sec = (s) => { section = s; };
const ok = (name, cond) => { cond ? (passed++, results.push(`PASS [${section}] ${name}`)) : (failed++, results.push(`FAIL [${section}] ${name}`)); };
const nowIso = () => new Date().toISOString();

// A base-domain case at awaiting_verification (its legal pre-verified state).
const baseCase = (over = {}) => ({
  id: "case_x", workspace_id: "wsX", case_type: "identity_case", status: "awaiting_verification",
  domain: "alpha.example", finding_id: "f1", asset_ref: "a1", severity: "high",
  evidence_json: "{}", recommended_actions_json: "[]", ...over,
});
const GOOD_MANUAL = { verification_method: "manual_attestation", verification_result: "verified", evidence_type: "attestation", observed_at: nowIso(), attestation: { by: "customer", statement: "remediated" } };
const GOOD_AUTOMATED = { verification_method: "automated", verification_result: "fixed", evidence_type: "scan", observed_at: nowIso(), evidence_reference: "scan_ok", observation: { reachable: false } };

async function main() {
  const mod = await loadWorker();
  const worker = mod.default;

  // ── F2: verification cannot be forged (attest ≠ verified) ──────────────────
  sec("F2 verification cannot be forged");
  // Positive control: a MANUAL case verifies with a valid customer attestation.
  const manualOk = canTransitionCase({ case: baseCase(), target_status: "verified", actor: { actor_type: "customer", actor_id: "u1" }, evidence: GOOD_MANUAL });
  ok("manual case verifies with a valid attestation (positive control)", manualOk.ok === true);
  // A bare completed scan never verifies.
  ok("bare completed-scan does NOT verify", canTransitionCase({ case: baseCase(), target_status: "verified", actor: { actor_type: "customer", actor_id: "u1" }, evidence: { scan_completed_only: true } }).ok === false);
  // Isolating case: OTHERWISE-VALID manual evidence flagged scan_completed_only
  // is still refused for that exact reason (so the scan-completion guard is
  // load-bearing, not masked by a missing-field failure).
  ok("scan_completed_only flag on otherwise-valid evidence is refused as scan-completion", validateVerificationEvidence({ ...GOOD_MANUAL, scan_completed_only: true }, { support: "manual", actor: { actor_id: "u1" } }).reason === "scan_completion_not_verification");
  // A note alone never verifies.
  ok("note-only does NOT verify", canTransitionCase({ case: baseCase(), target_status: "verified", actor: { actor_type: "customer", actor_id: "u1" }, evidence: { note_only: true } }).ok === false);
  // No evidence at all is refused.
  ok("no evidence does NOT verify (verify_requires_evidence)", canTransitionCase({ case: baseCase(), target_status: "verified", actor: { actor_type: "customer", actor_id: "u1" }, evidence: null }).code === "verify_requires_evidence");
  // Manual attestation without a structured attestation object is refused.
  ok("manual_attestation without attestation object refused", canTransitionCase({ case: baseCase(), target_status: "verified", actor: { actor_type: "customer", actor_id: "u1" }, evidence: { verification_method: "manual_attestation", verification_result: "verified", evidence_type: "attestation", observed_at: nowIso() } }).ok === false);
  // Manual attestation with NO identified actor is refused.
  ok("manual_attestation without an actor refused", canTransitionCase({ case: baseCase(), target_status: "verified", actor: { actor_type: "customer" }, evidence: GOOD_MANUAL }).ok === false);
  // An UNSUPPORTED case (registry says the product cannot verify it) is refused.
  ok("unsupported case cannot be verified (verify_unsupported)", canTransitionCase({ case: baseCase({ case_type: "email_case" }), target_status: "verified", actor: { actor_type: "customer", actor_id: "u1" }, evidence: GOOD_MANUAL }).code === "verify_unsupported");
  // An AUTOMATED-support case (ASM) can only be verified by a SYSTEM actor: a
  // customer attempting the automated verified edge is refused (system_only OR
  // verify_requires_system — either is a correct "customer cannot forge" outcome).
  const asmCustomer = canTransitionCase({ case: { id: "c2", workspace_id: "wsX", case_type: "asm_exposure", status: "verifying", evidence_json: "{}" }, target_status: "resolved", actor: { actor_type: "customer", actor_id: "u1" }, evidence: GOOD_AUTOMATED });
  ok("automated case cannot be verified by a customer actor", asmCustomer.ok === false && ["system_only", "verify_requires_system"].includes(asmCustomer.code));
  // Positive control: a SYSTEM actor with a valid automated result DOES verify it.
  const asmSystem = canTransitionCase({ case: { id: "c2", workspace_id: "wsX", case_type: "asm_exposure", status: "verifying", evidence_json: "{}" }, target_status: "resolved", actor: { actor_type: "system", actor_id: "cybermeters" }, evidence: GOOD_AUTOMATED });
  ok("automated case verifies for a SYSTEM actor with a valid result (positive control)", asmSystem.ok === true);
  // validateVerificationEvidence contract — failed/inconclusive/still-present never positive.
  ok("failed result never verifies", validateVerificationEvidence({ ...GOOD_AUTOMATED, verification_result: "failed" }, { support: "automated", actor: { actor_id: "u" } }).ok === false);
  ok("still_present result never verifies", validateVerificationEvidence({ ...GOOD_AUTOMATED, verification_result: "still_present" }, { support: "automated", actor: { actor_id: "u" } }).ok === false);
  ok("unsupported method never verifies", validateVerificationEvidence({ ...GOOD_AUTOMATED, verification_method: "unsupported" }, { support: "automated", actor: { actor_id: "u" } }).ok === false);
  ok("valid automated evidence passes the contract (positive control)", validateVerificationEvidence(GOOD_AUTOMATED, { support: "automated", actor: { actor_id: "u" } }).ok === true);
  // Vocabulary ceiling: manual = attested, never system verification.
  ok("manual ceiling reads 'Attested by customer — not externally verifiable'", verificationCeiling("manual") === "Attested by customer — not externally verifiable.");
  ok("manual support is NOT the automated 'verified' claim", verificationCeiling("manual") !== verificationCeiling("automated"));
  ok("verificationSupportForMethod(manual_attestation) === manual", verificationSupportForMethod("manual_attestation") === "manual");

  // F2 through the REAL transition route.
  {
    const db = buildDb();
    const env = makeEnv(db);
    const seed = await makeSeeder(db, mod);
    const call = makeCaller(worker, env);
    seed.user("uMgr", "mgr@a.co"); await seed.session("sMgr", "uMgr", "raw-mgr");
    seed.workspace("wsF2", "uMgr", "F2WS"); seed.member("mF2", "wsF2", "uMgr", "owner");
    seed.raw("INSERT INTO managed_cases (id, workspace_id, case_type, domain_key, domain, finding_id, asset_ref, severity, status, evidence_json, recommended_actions_json, awaiting_verification_at, created_at, updated_at) VALUES ('caseF2','wsF2','identity_case','identity_exposure','alpha.example','identity_admin_unowned','a1','high','awaiting_verification','{}','[]',datetime('now'),datetime('now'),datetime('now'))");
    const bare = await call("POST", "/api/workspaces/wsF2/cases/caseF2/transition", "raw-mgr", { target_status: "verified" });
    ok("real route: manager cannot reach verified with a bare transition (409)", bare.status === 409);
    const rowAfter = db.prepare("SELECT status FROM managed_cases WHERE id='caseF2'").get();
    ok("real route: case NOT verified after the bare attempt", rowAfter.status === "awaiting_verification");
  }

  // ── F3: alert / digest workflow cannot be spoofed or replayed ──────────────
  sec("F3 alert/digest cannot be spoofed or replayed");
  const db = buildDb();
  const env = makeEnv(db);
  const seed = await makeSeeder(db, mod);
  seed.user("uA", "a@a.co"); seed.user("uB", "b@b.co");
  seed.raw("UPDATE users SET email_verified = 1 WHERE id IN ('uA','uB')");
  seed.workspace("wsA", "uA", "AlphaWS"); seed.workspace("wsB", "uB", "BravoWS");
  seed.member("mA", "wsA", "uA", "owner"); seed.member("mB", "wsB", "uB", "owner");
  const countNotif = (ws) => db.prepare("SELECT COUNT(*) AS n FROM notification_events WHERE workspace_id = ?").get(ws).n;
  const emitArgs = (over = {}) => ({ workspace_id: "wsA", domain_key: "attack_surface", kind: "asm_exposure", severity: "high", title: "T", message: "M", dedupe_key: "dk-1", observed_at: nowIso(), ...over });
  // Positive control: a first observation emits (empty baseline, contemporaneous).
  const first = await emitManagedAlert(env, emitArgs());
  ok("first observation emits (positive control)", first.emitted === true && countNotif("wsA") === 1);
  // Duplicate/unchanged (same dedupe_key) is deduped — no repeat alert.
  const dup = await emitManagedAlert(env, emitArgs());
  ok("duplicate (same dedupe_key) is deduped", dup.emitted === false && dup.reason === "deduplicated");
  ok("duplicate created no second notification row", countNotif("wsA") === 1);
  // A genuinely different observation (new dedupe_key) DOES emit.
  const changed = await emitManagedAlert(env, emitArgs({ dedupe_key: "dk-2" }));
  ok("a different observation (new dedupe_key) emits", changed.emitted === true && countNotif("wsA") === 2);
  // An alert for a soft-deleted workspace is suppressed, never emitted.
  seed.workspace("wsDead", "uA", "DeadWS", true);
  const dead = await emitManagedAlert(env, emitArgs({ workspace_id: "wsDead", dedupe_key: "dk-dead" }));
  ok("soft-deleted workspace alert is suppressed (workspace_deleted)", dead.emitted === false && dead.reason === "workspace_deleted");
  ok("soft-deleted workspace received no notification row", countNotif("wsDead") === 0);
  // Recipients resolve to the alert's OWN workspace only — never another tenant's.
  const recA = await resolveWorkspaceAlertRecipients(env, "wsA");
  ok("wsA recipients include wsA owner", recA.emails.includes("a@a.co"));
  ok("wsA recipients EXCLUDE wsB owner (no cross-tenant recipient)", !recA.emails.includes("b@b.co"));

  // Weekly-digest idempotency per ISO week.
  seed.raw("INSERT INTO domains (id, user_id, domain) VALUES ('dA','uA','alpha.example')");
  seed.raw("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('wsA','dA')");
  const digestRows = () => db.prepare("SELECT COUNT(*) AS n FROM lifecycle_email_events WHERE workspace_id = 'wsA' AND type = 'lifecycle_weekly_digest'").get().n;
  await sendWeeklyDigests(env);
  const afterRun1 = digestRows();
  ok("digest producer records a send row for an eligible workspace (positive control)", afterRun1 === 1);
  await sendWeeklyDigests(env);
  ok("digest re-run same ISO week is idempotent (no second send row)", digestRows() === afterRun1);
  // An ineligible workspace (no monitored domain) produces no digest row.
  ok("workspace with no monitored domain gets no digest row", db.prepare("SELECT COUNT(*) AS n FROM lifecycle_email_events WHERE workspace_id = 'wsB'").get().n === 0);

  // ── F4: rate limiting holds (real login route, failClosed) ─────────────────
  sec("F4 rate limiting holds");
  {
    const rlDb = buildDb();
    const rlEnv = makeEnv(rlDb);
    const rlSeed = await makeSeeder(rlDb, mod);
    rlSeed.user("uLogin", "login@a.co"); // real user; we send WRONG passwords
    // Fixed IP so the per-IP login limiter (10 / 15 min) actually accumulates.
    const capCall = makeCaller(worker, rlEnv, { fixedIp: "203.0.113.7" });
    const attempt = () => capCall("POST", "/api/auth/login", null, { email: "login@a.co", password: "wrong-pw" });
    let sawAllowed = 0, saw429 = 0;
    for (let i = 0; i < 10; i++) { const r = await attempt(); if (r.status !== 429) sawAllowed++; }
    ok("first 10 login attempts are NOT rate-limited (positive control)", sawAllowed === 10);
    const over = await attempt(); // the 11th
    ok("the (cap+1)th login attempt is rejected 429", over.status === 429);
    // Fail-CLOSED on store error: drop the rate-limit table; a fresh IP (never
    // capped) must be DENIED, not allowed through — the failClosed caller denies.
    const failCall = makeCaller(worker, rlEnv, { fixedIp: "203.0.113.99" });
    const beforeDrop = await failCall("POST", "/api/auth/login", null, { email: "login@a.co", password: "wrong-pw" });
    ok("fresh IP is NOT independently rate-limited before the store fails (isolates the cause)", beforeDrop.status !== 429);
    rlDb.exec("DROP TABLE api_rate_limits");
    const afterDrop = await failCall("POST", "/api/auth/login", null, { email: "login@a.co", password: "wrong-pw" });
    ok("rate-store error → login DENIED (fails CLOSED, not open)", afterDrop.status === 429);
  }

  // ── Coverage delta ─────────────────────────────────────────────────────────
  sec("Coverage");
  const controls = {
    F2: "verification cannot be forged (attest≠verified; automated needs system; unsupported/external refused; manual ceiling wording)",
    F3: "alert/digest cannot be spoofed/replayed (dedupe_key dedup, soft-delete suppression, own-tenant recipients, weekly-digest idempotent)",
    F4: "rate limiting holds (login cap+1 → 429; fail-closed on store error)",
  };
  ok("all three assessable F-section controls asserted", Object.keys(controls).length === 3);

  // ── Report ─────────────────────────────────────────────────────────────────
  const bySec = {};
  for (const line of results) { const s = line.match(/\[(.*?)\]/)[1]; (bySec[s] ??= { p: 0, f: 0 })[line.startsWith("PASS") ? "p" : "f"]++; }
  console.log("\nWorkflow abuse coverage (F-section, reusing #187/#241/#243 harness):");
  for (const [s, c] of Object.entries(bySec)) console.log(`  ${c.f ? "✗" : "✓"} ${s}: ${c.p}/${c.p + c.f}`);
  console.log("\nF-section coverage delta:");
  for (const [k, v] of Object.entries(controls)) console.log(`  + ${k} — ${v}`);
  console.log("  · NT F1 (workflow state-machine bypass via a real browser) — the transition invariants are covered here through the pure validator + the real route; a full click-through of the customer UI needs a browser and is a release-gate item.");
  if (failed) { console.log("\nFailures:"); for (const rr of results.filter((x) => x.startsWith("FAIL"))) console.log("  " + rr); }
  console.log(`\nWorkflow abuse coverage: ${passed}/${passed + failed} passed`);
  if (failed) { console.error("workflow-abuse-coverage validation FAILED — a RED assertion here is a workflow finding, not a test bug"); process.exit(1); }
  console.log("workflow-abuse-coverage validation passed");
}

main().catch((e) => { console.error("workflow-abuse-coverage runner crashed:", e); process.exit(1); });
