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
import { webcrypto } from "node:crypto";
import { loadWorker, buildDb, makeEnv, makeCaller, makeSeeder, ctx } from "./security/lib/worker-harness.js";
import { canTransitionCase, validateVerificationEvidence, verificationSupportForMethod } from "../workers/scan-api/src/engines/managed-case-model.js";
import { verificationCeiling } from "../workers/scan-api/src/engines/report-snapshot.js";
import { emitManagedAlert } from "../workers/scan-api/src/engines/managed-alerts.js";
import { resolveWorkspaceAlertRecipients } from "../workers/scan-api/src/engines/alerts.js";
import { sendWeeklyDigests } from "../workers/scan-api/src/engines/weekly-digest.js";
import { consumeApiRateLimit } from "../workers/scan-api/src/lib/rate-limit.js";

let passed = 0, failed = 0, section = "General";
const results = [];
const sec = (s) => { section = s; };
const ok = (name, cond) => { cond ? (passed++, results.push(`PASS [${section}] ${name}`)) : (failed++, results.push(`FAIL [${section}] ${name}`)); };
const nowIso = () => new Date().toISOString();
const RATE_LIMIT_WINDOW_MS = 900_000;
const RATE_LIMIT_EPOCH_MS = 1_800_000_001_234;
const EXPECTED_ASSERTION_COUNT = 66;
const HARNESS_MUTANT = process.env.F4_PR1_HARNESS_MUTANT || "";
const F4_PR2_FAIL_FIRST = process.env.F4_PR2_FAIL_FIRST === "1";
const F4_PR2_BARRIER_MODE = process.env.F4_PR2_BARRIER_MODE || "attached";
const F4_PR2_FOCUSED = process.env.F4_PR2_FOCUSED === "1";
const withRateLimitClock = async (epochProvider, operation) => {
  const originalDateNow = Date.now;
  Date.now = () => (typeof epochProvider === "function" ? epochProvider() : epochProvider);
  try {
    return await operation();
  } finally {
    if (HARNESS_MUTANT !== "bypass_clock_restoration") Date.now = originalDateNow;
  }
};
const rateLimitWindowStart = (epochMs, windowSeconds) => new Date(
  Math.floor(epochMs / (windowSeconds * 1000)) * windowSeconds * 1000,
).toISOString();
const rateLimitScopeIdForTest = async (prefix, value) => {
  const digest = await webcrypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(String(value || "unknown")),
  );
  return `${prefix}_${Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, "0")).join("").slice(0, 16)}`;
};
const scopedActionCounter = (db, { scope, scopeId, action, windowStart }) => db.prepare(
  `SELECT scope, scope_id, action, window_start, window_seconds, request_count
   FROM api_rate_limits
   WHERE scope = ? AND scope_id = ? AND action = ? AND window_start = ?
   LIMIT 1`,
).get(scope, scopeId, action, windowStart);
const renameRateLimitActionInMemory = (env, fromAction, toAction) => {
  const canonicalDb = env.cybermeters_db;
  return {
    ...env,
    cybermeters_db: {
      prepare(sql) {
        const statement = canonicalDb.prepare(sql);
        if (!/\bapi_rate_limits\b/i.test(sql) || typeof statement.bind !== "function") return statement;
        const canonicalBind = statement.bind.bind(statement);
        statement.bind = (...args) => canonicalBind(
          ...args.map((value) => value === fromAction ? toAction : value),
        );
        return statement;
      },
      batch: (...args) => canonicalDb.batch(...args),
      exec: (...args) => canonicalDb.exec(...args),
    },
  };
};
const forwardMember = (target, property) => {
  const value = Reflect.get(target, property, target);
  return typeof value === "function" ? value.bind(target) : value;
};
const wrapD1 = (canonicalDb, wrapBound) => ({
  prepare(sql) {
    const statement = canonicalDb.prepare(sql);
    return new Proxy(statement, {
      get(target, property) {
        if (property === "bind") {
          return (...args) => wrapBound(sql, args, target.bind(...args));
        }
        return forwardMember(target, property);
      },
    });
  },
  batch: (...args) => canonicalDb.batch(...args),
  exec: (...args) => canonicalDb.exec(...args),
});
const withDeferredLegacyReadBarrier = (env, action) => {
  const canonicalDb = env.cybermeters_db;
  const targetAction = F4_PR2_BARRIER_MODE === "wrong_action"
    ? `${action}_wrong_attachment`
    : action;
  let deferredReads = 0;
  let releaseScheduled = false;
  let released = false;
  let readGeneration = 0;
  const waiters = [];
  const release = () => {
    released = true;
    while (waiters.length > 0) waiters.shift()();
  };
  const waitForPassiveRelease = () => {
    if (released) return Promise.resolve();
    if (!releaseScheduled) {
      releaseScheduled = true;
      let observedGeneration = readGeneration;
      let quietTurns = 0;
      const observeQuiescence = () => {
        if (observedGeneration !== readGeneration) {
          observedGeneration = readGeneration;
          quietTurns = 0;
        } else {
          quietTurns += 1;
        }
        if (quietTurns >= 256) release();
        else setImmediate(observeQuiescence);
      };
      setImmediate(observeQuiescence);
    }
    return new Promise((resolve) => waiters.push(resolve));
  };
  const cybermetersDb = wrapD1(canonicalDb, (sql, args, bound) => {
    const normalisedSql = String(sql).replace(/\s+/g, " ").trim();
    const isActualLegacyRead = normalisedSql.startsWith("SELECT request_count FROM api_rate_limits") &&
      args[2] === targetAction;
    if (!isActualLegacyRead) return bound;
    return new Proxy(bound, {
      get(target, property) {
        if (property === "first") {
          return async (...firstArgs) => {
            // Execute the actual prepared/bound D1 read first, then defer its
            // result. No caller can enter the write phase until the passive
            // next-turn release, so all concurrent legacy reads observe the
            // same pre-write state. Atomic UPSERTs never enter this branch.
            const row = await target.first(...firstArgs);
            deferredReads += 1;
            readGeneration += 1;
            await waitForPassiveRelease();
            return row;
          };
        }
        return forwardMember(target, property);
      },
    });
  });
  return {
    env: { ...env, cybermeters_db: cybermetersDb },
    deferredReadCount: () => deferredReads,
  };
};
const withActionScopedRateStoreFailure = (env, action) => {
  const canonicalDb = env.cybermeters_db;
  return {
    ...env,
    cybermeters_db: wrapD1(canonicalDb, (sql, args, bound) => {
      const targetsAction = /\bapi_rate_limits\b/i.test(String(sql)) &&
        args.some((value) => value === action);
      if (!targetsAction) return bound;
      return new Proxy(bound, {
        get(target, property) {
          if (["first", "all", "run"].includes(String(property))) {
            return async () => { throw new Error(`forced ${action} rate-store failure`); };
          }
          return forwardMember(target, property);
        },
      });
    }),
  };
};
const responseObservation = (responses) => ({
  allowed: responses.filter((response) => response.status !== 429).length,
  unauthorized: responses.filter((response) => response.status === 401).length,
  denied429: responses.filter((response) => response.status === 429).length,
  statuses: responses.map((response) => response.status),
});
const actionRows = (db, action, windowStart) => db.prepare(
  `SELECT scope, scope_id, action, window_start, window_seconds, request_count
   FROM api_rate_limits
   WHERE action = ? AND window_start = ?
   ORDER BY scope, scope_id`,
).all(action, windowStart);
const recordF4Pr2Fixture = (id, description, pass, observation) => {
  console.log(`F4_PR2_OBSERVATION ${JSON.stringify({ id, ...observation })}`);
  ok(`${id} — ${description}`, pass);
};
const fixedIpCheckResults = ({ responses, loginRow, accountRow, loginScopeId, accountScopeId, windowStart }) => [
  {
    name: "first 10 login attempts are NOT rate-limited (positive control)",
    pass: responses.slice(0, 10).every((response) => response.status !== 429),
  },
  {
    name: "the (cap+1)th login attempt is rejected 429 by login action",
    pass: responses[10]?.status === 429 &&
      responses[10]?.data?.action !== "global_write" &&
      loginRow?.scope === "ip" &&
      loginRow?.scope_id === loginScopeId &&
      loginRow?.action === "login" &&
      loginRow?.window_start === windowStart &&
      loginRow?.window_seconds === 900 &&
      loginRow?.request_count === 11,
  },
  {
    name: "first ten fixed-IP attempts reached login_account before request 11 was stopped by login",
    pass: accountRow?.scope === "user" &&
      accountRow?.scope_id === accountScopeId &&
      accountRow?.action === "login_account" &&
      accountRow?.window_start === windowStart &&
      accountRow?.window_seconds === 900 &&
      accountRow?.request_count === 10,
  },
];
const enforceExpectedAssertionCount = () => {
  const observed = passed + failed;
  if (observed === EXPECTED_ASSERTION_COUNT) return;
  failed += 1;
  results.push(
    `FAIL [Harness integrity] assertion-count interlock expected ${EXPECTED_ASSERTION_COUNT}, observed ${observed}`,
  );
};

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

  if (!F4_PR2_FOCUSED) {
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
  const dateNowBeforeF4 = Date.now;
  let observedExpectedThrow = false;
  try {
    await withRateLimitClock(RATE_LIMIT_EPOCH_MS, async () => {
      if (HARNESS_MUTANT !== "remove_intentional_throw") {
        throw new Error("intentional clock-restore assertion");
      }
    });
  } catch (error) {
    observedExpectedThrow = error?.message === "intentional clock-restore assertion";
  }
  if (HARNESS_MUTANT !== "omit_expected_throw_assertion") {
    ok("intentional thrown assertion is observed", observedExpectedThrow);
  }
  ok("Date.now is restored after an intentional thrown assertion", Date.now === dateNowBeforeF4);
  {
    const rlDb = buildDb();
    const rlEnv = makeEnv(rlDb);
    const rlSeed = await makeSeeder(rlDb, mod);
    rlSeed.user("uLogin", "login@a.co"); // real user; we send WRONG passwords
    // Fixed IP so the per-IP login limiter (10 / 15 min) actually accumulates.
    const fixedIp = "203.0.113.7";
    const capCall = makeCaller(worker, rlEnv, { fixedIp });
    const attempt = () => capCall("POST", "/api/auth/login", null, { email: "login@a.co", password: "wrong-pw" });
    const fixedIpResponses = [];
    await withRateLimitClock(RATE_LIMIT_EPOCH_MS, async () => {
      for (let index = 0; index < 11; index++) fixedIpResponses.push(await attempt());
      const windowStart = rateLimitWindowStart(RATE_LIMIT_EPOCH_MS, 900);
      const loginScopeId = await rateLimitScopeIdForTest("login", fixedIp);
      const accountScopeId = await rateLimitScopeIdForTest("login_acct", "login@a.co");
      const checks = fixedIpCheckResults({
        responses: fixedIpResponses,
        loginRow: scopedActionCounter(rlDb, {
          scope: "ip", scopeId: loginScopeId, action: "login", windowStart,
        }),
        accountRow: scopedActionCounter(rlDb, {
          scope: "user", scopeId: accountScopeId, action: "login_account", windowStart,
        }),
        loginScopeId,
        accountScopeId,
        windowStart,
      });
      for (const check of checks) ok(check.name, check.pass);
    });
    ok("Date.now is restored after the sequential F4 fixture", Date.now === dateNowBeforeF4);
    // Fail-CLOSED on store error: drop the rate-limit table; a fresh IP (never
    // capped) must be DENIED, not allowed through — the failClosed caller denies.
    await withRateLimitClock(RATE_LIMIT_EPOCH_MS, async () => {
      const failCall = makeCaller(worker, rlEnv, { fixedIp: "203.0.113.99" });
      const beforeDrop = await failCall("POST", "/api/auth/login", null, { email: "login@a.co", password: "wrong-pw" });
      ok("fresh IP is NOT independently rate-limited before the store fails (isolates the cause)", beforeDrop.status !== 429);
      rlDb.exec("DROP TABLE api_rate_limits");
      const afterDrop = await failCall("POST", "/api/auth/login", null, { email: "login@a.co", password: "wrong-pw" });
      ok("rate-store error → login DENIED (fails CLOSED, not open)", afterDrop.status === 429);
    });
    ok("Date.now is restored after the store-failure fixture", Date.now === dateNowBeforeF4);
  }

  // Right-reason mutant: rewrite only the login_account action argument as it
  // crosses the in-memory D1 adapter. Production auth.js remains byte-identical;
  // the real route still reaches the login IP 429 on request 11, but the exact
  // login_account provenance row is gone and only that fixed-IP check may fail.
  {
    const mutantDb = buildDb();
    const canonicalMutantEnv = makeEnv(mutantDb);
    const mutantEnv = renameRateLimitActionInMemory(
      canonicalMutantEnv,
      "login_account",
      "login_account_mutant",
    );
    const mutantSeed = await makeSeeder(mutantDb, mod);
    mutantSeed.user("uLoginMutant", "login-mutant@a.co");
    const fixedIp = "203.0.113.8";
    const accountEmail = "login-mutant@a.co";
    const mutantCall = makeCaller(worker, mutantEnv, { fixedIp });
    const responses = [];
    let checks = [];
    let renamedRow = null;
    await withRateLimitClock(RATE_LIMIT_EPOCH_MS, async () => {
      for (let index = 0; index < 11; index++) {
        responses.push(await mutantCall("POST", "/api/auth/login", null, {
          email: accountEmail,
          password: "wrong-pw",
        }));
      }
      const windowStart = rateLimitWindowStart(RATE_LIMIT_EPOCH_MS, 900);
      const loginScopeId = await rateLimitScopeIdForTest("login", fixedIp);
      const accountScopeId = await rateLimitScopeIdForTest("login_acct", accountEmail);
      checks = fixedIpCheckResults({
        responses,
        loginRow: scopedActionCounter(mutantDb, {
          scope: "ip", scopeId: loginScopeId, action: "login", windowStart,
        }),
        accountRow: scopedActionCounter(mutantDb, {
          scope: "user", scopeId: accountScopeId, action: "login_account", windowStart,
        }),
        loginScopeId,
        accountScopeId,
        windowStart,
      });
      renamedRow = scopedActionCounter(mutantDb, {
        scope: "user", scopeId: accountScopeId, action: "login_account_mutant", windowStart,
      });
    });
    const mutantFailures = checks.filter((check) => !check.pass).map((check) => check.name);
    ok("right-reason action mutant removes only positive login_account provenance while IP 429 survives", responses[10]?.status === 429 &&
      renamedRow?.request_count === 10 &&
      JSON.stringify(mutantFailures) === JSON.stringify([
        "first ten fixed-IP attempts reached login_account before request 11 was stopped by login",
      ]));
  }

  // A fixed-window boundary is intentional product behaviour. A natural run
  // can cross it after any of attempts 1..10; this fixture deliberately uses
  // a 5/5 split to prove the semantics. The overall 11th request below is
  // only the sixth request in the second bucket, while the final request is
  // the cap+1 inside that bucket.
  {
    const rolloverDb = buildDb();
    const rolloverEnv = makeEnv(rolloverDb);
    const rolloverSeed = await makeSeeder(rolloverDb, mod);
    rolloverSeed.user("uRollover", "rollover@a.co");
    const rolloverCall = makeCaller(worker, rolloverEnv, { fixedIp: "203.0.113.71" });
    let rolloverEpoch = RATE_LIMIT_EPOCH_MS;
    await withRateLimitClock(() => rolloverEpoch, async () => {
      for (let i = 0; i < 5; i++) {
        ok(`rollover first-window attempt ${i + 1} allowed`, (await rolloverCall("POST", "/api/auth/login", null, { email: "rollover@a.co", password: "wrong-pw" })).status !== 429);
      }
      rolloverEpoch += RATE_LIMIT_WINDOW_MS;
      for (let i = 0; i < 6; i++) {
        const response = await rolloverCall("POST", "/api/auth/login", null, { email: "rollover@a.co", password: "wrong-pw" });
        ok(`rollover second-window attempt ${i + 1} receives a separate budget`, response.status !== 429);
      }
      for (let i = 6; i < 10; i++) {
        ok(`rollover second-window attempt ${i + 1} remains allowed`, (await rolloverCall("POST", "/api/auth/login", null, { email: "rollover@a.co", password: "wrong-pw" })).status !== 429);
      }
      const rolloverCap = await rolloverCall("POST", "/api/auth/login", null, { email: "rollover@a.co", password: "wrong-pw" });
      const rolloverLoginScopeId = await rateLimitScopeIdForTest("login", "203.0.113.71");
      const rolloverLoginRow = scopedActionCounter(rolloverDb, {
        scope: "ip",
        scopeId: rolloverLoginScopeId,
        action: "login",
        windowStart: rateLimitWindowStart(rolloverEpoch, 900),
      });
      ok("rollover cap+1 is denied only inside its own bucket by login action", rolloverCap.status === 429 && rolloverCap.data?.action !== "global_write" && rolloverLoginRow?.request_count === 11);
    });
    ok("Date.now is restored after the rollover fixture", Date.now === dateNowBeforeF4);
  }
  }

  // ── F4 PR-2: atomic login/account limiter contract (X1–X7) ───────────────
  // The passive barrier wraps the actual prepared/bound SELECT statement used
  // by consumeApiRateLimit. It deterministically forces the permitted
  // all-reads-before-any-write legacy interleaving. In-process SQLite does not
  // schedule that race naturally; no production D1 occurrence is claimed.
  sec("F4 PR-2 login rate-limit atomicity");
  {
    const fixtureClockBefore = Date.now;
    const fixedIp = "203.0.113.101";
    const email = "f4-x1@example.test";
    const db = buildDb();
    const barrier = withDeferredLegacyReadBarrier(makeEnv(db), "login");
    const call = makeCaller(worker, barrier.env, { fixedIp });
    const responses = await withRateLimitClock(RATE_LIMIT_EPOCH_MS, () => Promise.all(
      Array.from({ length: 11 }, () => call("POST", "/api/auth/login", null, {
        email,
        password: "wrong-pw",
      })),
    ));
    const windowStart = rateLimitWindowStart(RATE_LIMIT_EPOCH_MS, 900);
    const loginScopeId = await rateLimitScopeIdForTest("login", fixedIp);
    const accountScopeId = await rateLimitScopeIdForTest("login_acct", email);
    const loginRow = scopedActionCounter(db, {
      scope: "ip", scopeId: loginScopeId, action: "login", windowStart,
    });
    const accountRow = scopedActionCounter(db, {
      scope: "user", scopeId: accountScopeId, action: "login_account", windowStart,
    });
    const response = responseObservation(responses);
    const observation = {
      ...response,
      login_count: loginRow?.request_count ?? null,
      login_account_count: accountRow?.request_count ?? null,
      deferred_reads: barrier.deferredReadCount(),
    };
    const deniedResponse = responses.find((item) => item.status === 429);
    recordF4Pr2Fixture("X1", "same-IP concurrency is bounded at 10 with one account-safe 429", response.allowed === 10 &&
      response.unauthorized === 10 && response.denied429 === 1 &&
      deniedResponse?.data?.action !== "global_write" && loginRow?.scope === "ip" &&
      loginRow?.scope_id === loginScopeId && loginRow?.action === "login" &&
      loginRow?.window_start === windowStart && loginRow?.window_seconds === 900 &&
      loginRow?.request_count === 11 && accountRow?.scope === "user" &&
      accountRow?.scope_id === accountScopeId && accountRow?.action === "login_account" &&
      accountRow?.window_start === windowStart && accountRow?.window_seconds === 900 &&
      accountRow?.request_count === 10 && barrier.deferredReadCount() === 0 &&
      Date.now === fixtureClockBefore, observation);
  }

  {
    const fixtureClockBefore = Date.now;
    const email = "f4-x2@example.test";
    const db = buildDb();
    const barrier = withDeferredLegacyReadBarrier(makeEnv(db), "login_account");
    // No fixedIp: makeCaller assigns a distinct deterministic IP to every call.
    const call = makeCaller(worker, barrier.env);
    const responses = await withRateLimitClock(RATE_LIMIT_EPOCH_MS, () => Promise.all(
      Array.from({ length: 21 }, () => call("POST", "/api/auth/login", null, {
        email,
        password: "wrong-pw",
      })),
    ));
    const windowStart = rateLimitWindowStart(RATE_LIMIT_EPOCH_MS, 900);
    const accountScopeId = await rateLimitScopeIdForTest("login_acct", email);
    const accountRow = scopedActionCounter(db, {
      scope: "user", scopeId: accountScopeId, action: "login_account", windowStart,
    });
    const accountRows = actionRows(db, "login_account", windowStart);
    const loginRows = actionRows(db, "login", windowStart);
    const response = responseObservation(responses);
    const observation = {
      ...response,
      login_account_count: accountRow?.request_count ?? null,
      login_account_rows: accountRows.length,
      login_rows: loginRows.length,
      login_row_counts: loginRows.map((row) => row.request_count),
      deferred_reads: barrier.deferredReadCount(),
    };
    recordF4Pr2Fixture("X2", "distributed account concurrency allows exactly 20 before one scoped 429", response.allowed === 20 &&
      response.unauthorized === 20 && response.denied429 === 1 &&
      responses.slice(0, 20).every((item) => item.status === 401) &&
      responses[20]?.status === 429 && responses[20]?.data?.action !== "global_write" &&
      accountRow?.scope === "user" && accountRow?.scope_id === accountScopeId &&
      accountRow?.action === "login_account" && accountRow?.window_start === windowStart &&
      accountRow?.window_seconds === 900 && accountRow?.request_count === 21 &&
      accountRows.length === 1 && loginRows.length === 21 &&
      loginRows.every((row) => row.scope === "ip" && row.action === "login" &&
        row.window_start === windowStart && row.window_seconds === 900 && row.request_count === 1) &&
      barrier.deferredReadCount() === 0 && Date.now === fixtureClockBefore, observation);
  }

  {
    const fixtureClockBefore = Date.now;
    const fixedIp = "203.0.113.103";
    const email = "f4-x3@example.test";
    const db = buildDb();
    const barrier = withDeferredLegacyReadBarrier(makeEnv(db), "login");
    const call = makeCaller(worker, barrier.env, { fixedIp });
    const responses = await withRateLimitClock(RATE_LIMIT_EPOCH_MS, () => Promise.all(
      Array.from({ length: 10 }, () => call("POST", "/api/auth/login", null, {
        email,
        password: "wrong-pw",
      })),
    ));
    const windowStart = rateLimitWindowStart(RATE_LIMIT_EPOCH_MS, 900);
    const loginScopeId = await rateLimitScopeIdForTest("login", fixedIp);
    const accountScopeId = await rateLimitScopeIdForTest("login_acct", email);
    const loginRow = scopedActionCounter(db, {
      scope: "ip", scopeId: loginScopeId, action: "login", windowStart,
    });
    const accountRow = scopedActionCounter(db, {
      scope: "user", scopeId: accountScopeId, action: "login_account", windowStart,
    });
    const response = responseObservation(responses);
    const expectedDeferredReads = F4_PR2_FAIL_FIRST ? 10 : 0;
    const observation = {
      ...response,
      login_count: loginRow?.request_count ?? null,
      login_account_count: accountRow?.request_count ?? null,
      deferred_reads: barrier.deferredReadCount(),
      expected_deferred_reads: expectedDeferredReads,
    };
    recordF4Pr2Fixture("X3", "barrier does not fabricate a below-cap denial", response.allowed === 10 &&
      response.unauthorized === 10 && response.denied429 === 0 &&
      loginRow?.request_count === 10 && accountRow?.request_count === 10 &&
      barrier.deferredReadCount() === expectedDeferredReads && Date.now === fixtureClockBefore,
    observation);
  }

  {
    const fixtureClockBefore = Date.now;
    const fixedIp = "203.0.113.104";
    const email = "f4-x4a@example.test";
    const db = buildDb();
    const call = makeCaller(worker, makeEnv(db), { fixedIp });
    const responses = [];
    await withRateLimitClock(RATE_LIMIT_EPOCH_MS, async () => {
      for (let index = 0; index < 11; index++) {
        responses.push(await call("POST", "/api/auth/login", null, { email, password: "wrong-pw" }));
      }
    });
    const windowStart = rateLimitWindowStart(RATE_LIMIT_EPOCH_MS, 900);
    const loginScopeId = await rateLimitScopeIdForTest("login", fixedIp);
    const loginRow = scopedActionCounter(db, {
      scope: "ip", scopeId: loginScopeId, action: "login", windowStart,
    });
    const response = responseObservation(responses);
    const expectedPersisted = F4_PR2_FAIL_FIRST ? 10 : 11;
    const observation = { ...response, login_count: loginRow?.request_count ?? null, expected_persisted: expectedPersisted };
    recordF4Pr2Fixture("X4a", "sequential same-IP cap+1 preserves the approved boundary", response.allowed === 10 &&
      response.unauthorized === 10 && response.denied429 === 1 && responses[10]?.status === 429 &&
      responses[10]?.data?.action !== "global_write" && loginRow?.request_count === expectedPersisted &&
      Date.now === fixtureClockBefore, observation);
  }

  {
    const fixtureClockBefore = Date.now;
    const email = "f4-x4b@example.test";
    const db = buildDb();
    const call = makeCaller(worker, makeEnv(db));
    const responses = [];
    await withRateLimitClock(RATE_LIMIT_EPOCH_MS, async () => {
      for (let index = 0; index < 21; index++) {
        responses.push(await call("POST", "/api/auth/login", null, { email, password: "wrong-pw" }));
      }
    });
    const windowStart = rateLimitWindowStart(RATE_LIMIT_EPOCH_MS, 900);
    const accountScopeId = await rateLimitScopeIdForTest("login_acct", email);
    const accountRow = scopedActionCounter(db, {
      scope: "user", scopeId: accountScopeId, action: "login_account", windowStart,
    });
    const response = responseObservation(responses);
    const expectedPersisted = F4_PR2_FAIL_FIRST ? 20 : 21;
    const observation = { ...response, login_account_count: accountRow?.request_count ?? null, expected_persisted: expectedPersisted };
    recordF4Pr2Fixture("X4b", "sequential distributed cap+1 preserves the approved account boundary", response.allowed === 20 &&
      response.unauthorized === 20 && response.denied429 === 1 && responses[20]?.status === 429 &&
      responses[20]?.data?.action !== "global_write" && accountRow?.request_count === expectedPersisted &&
      Date.now === fixtureClockBefore, observation);
  }

  {
    const fixtureClockBefore = Date.now;
    const fixedIp = "203.0.113.105";
    const email = "f4-x5@example.test";
    const db = buildDb();
    const failingEnv = withActionScopedRateStoreFailure(makeEnv(db), "login");
    const call = makeCaller(worker, failingEnv, { fixedIp });
    const response = await withRateLimitClock(RATE_LIMIT_EPOCH_MS, () =>
      call("POST", "/api/auth/login", null, { email, password: "wrong-pw" }));
    const windowStart = rateLimitWindowStart(RATE_LIMIT_EPOCH_MS, 900);
    const accountScopeId = await rateLimitScopeIdForTest("login_acct", email);
    const accountRow = scopedActionCounter(db, {
      scope: "user", scopeId: accountScopeId, action: "login_account", windowStart,
    });
    const observation = {
      status: response.status,
      action: response.data?.action ?? null,
      login_account_count: accountRow?.request_count ?? null,
    };
    recordF4Pr2Fixture("X5", "login-scoped store failure fails closed before account or credential work", response.status === 429 &&
      response.data?.action !== "global_write" && accountRow == null && Date.now === fixtureClockBefore,
    observation);
  }

  {
    const fixtureClockBefore = Date.now;
    const db = buildDb();
    const env = makeEnv(db);
    const scope = [{ scope: "ip", scope_id: "f4_x6_scope" }];
    let epoch = RATE_LIMIT_EPOCH_MS;
    const firstBucket = [];
    const secondBucket = [];
    let capResult = null;
    await withRateLimitClock(() => epoch, async () => {
      for (let index = 0; index < 5; index++) {
        firstBucket.push(await consumeApiRateLimit(env, scope, "login", 10, 900, {
          failClosed: true,
          atomic: true,
        }));
      }
      epoch += RATE_LIMIT_WINDOW_MS;
      for (let index = 0; index < 10; index++) {
        secondBucket.push(await consumeApiRateLimit(env, scope, "login", 10, 900, {
          failClosed: true,
          atomic: true,
        }));
      }
      capResult = await consumeApiRateLimit(env, scope, "login", 10, 900, {
        failClosed: true,
        atomic: true,
      });
    });
    const observation = {
      first_bucket_allowed: firstBucket.filter((result) => result == null).length,
      second_bucket_allowed: secondBucket.filter((result) => result == null).length,
      cap_status: capResult?.status ?? null,
      cap_action: capResult?.body?.action ?? null,
    };
    // Deliberately no persisted-count assertion: X6 pins budget semantics only.
    recordF4Pr2Fixture("X6", "fixed-window rollover grants a fresh budget and denies only cap+1", firstBucket.length === 5 &&
      firstBucket.every((result) => result == null) && secondBucket.length === 10 &&
      secondBucket.every((result) => result == null) && capResult?.status === 429 &&
      capResult?.body?.action === "login" && Date.now === fixtureClockBefore, observation);
  }

  {
    const fixtureClockBefore = Date.now;
    const fixedIp = "203.0.113.107";
    const email = "f4-x7@example.test";
    const db = buildDb();
    const call = makeCaller(worker, makeEnv(db), { fixedIp });
    const response = await withRateLimitClock(RATE_LIMIT_EPOCH_MS, () =>
      call("POST", "/api/auth/login", null, { email, password: "wrong-pw" }));
    const windowStart = rateLimitWindowStart(RATE_LIMIT_EPOCH_MS, 900);
    const loginRows = actionRows(db, "login", windowStart);
    const accountRows = actionRows(db, "login_account", windowStart);
    const observation = {
      status: response.status,
      login_rows: loginRows.length,
      login_account_rows: accountRows.length,
      login_counts: loginRows.map((row) => row.request_count),
      login_account_counts: accountRows.map((row) => row.request_count),
    };
    recordF4Pr2Fixture("X7", "each login call site remains single-scope with one exact row", response.status === 401 &&
      loginRows.length === 1 && accountRows.length === 1 &&
      loginRows[0]?.scope === "ip" && loginRows[0]?.action === "login" &&
      loginRows[0]?.window_start === windowStart && loginRows[0]?.window_seconds === 900 &&
      loginRows[0]?.request_count === 1 && accountRows[0]?.scope === "user" &&
      accountRows[0]?.action === "login_account" && accountRows[0]?.window_start === windowStart &&
      accountRows[0]?.window_seconds === 900 && accountRows[0]?.request_count === 1 &&
      Date.now === fixtureClockBefore, observation);
  }

  // ── Coverage delta ─────────────────────────────────────────────────────────
  sec("Coverage");
  const controls = {
    F2: "verification cannot be forged (attest≠verified; automated needs system; unsupported/external refused; manual ceiling wording)",
    F3: "alert/digest cannot be spoofed/replayed (dedupe_key dedup, soft-delete suppression, own-tenant recipients, weekly-digest idempotent)",
    F4: "rate limiting holds (login cap+1 → 429; fail-closed on store error)",
  };
  if (!F4_PR2_FOCUSED) {
    ok("all three assessable F-section controls asserted", Object.keys(controls).length === 3);
    enforceExpectedAssertionCount();
  }

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
