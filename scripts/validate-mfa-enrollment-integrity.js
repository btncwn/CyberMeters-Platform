#!/usr/bin/env node
// Real Worker router + in-memory SQLite. No network, credentials or real users.
// Enrollment must not overwrite an enabled factor or issue recovery codes for
// a stale proof. Hooks schedule a second real request at a D1 await boundary;
// they do not change SQL results or replace the route under test.
import assert from "node:assert/strict";
import { loadWorker, buildDb, makeEnv, makeCaller, makeSeeder } from "./security/lib/worker-harness.js";
import { base32Decode } from "../workers/scan-api/src/lib/base32.js";
import { decryptTotpSecret } from "../workers/scan-api/src/lib/auth-crypto.js";
import { verifyTotp } from "../workers/scan-api/src/lib/totp.js";

let passed = 0;
function check(name, fn) { fn(); passed++; console.log(`PASS ${name}`); }
async function codeFor(secret) {
  const t = Math.floor(Date.now() / 30000);
  const msg = new DataView(new ArrayBuffer(8));
  msg.setUint32(0, Math.floor(t / 0x100000000));
  msg.setUint32(4, t >>> 0);
  const key = await crypto.subtle.importKey("raw", base32Decode(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg.buffer));
  const o = sig[sig.length - 1] & 15;
  return String((((sig[o] & 127) << 24) | ((sig[o + 1] & 255) << 16) | ((sig[o + 2] & 255) << 8) | (sig[o + 3] & 255)) % 1000000).padStart(6, "0");
}
const MFA_COLUMNS = "mfa_enabled, totp_secret, mfa_enabled_at, mfa_last_verified_at, mfa_recovery_codes_hash_json";
const hasEnrollmentMaterial = (r) => "secret_base32" in (r.data || {}) || "otpauth_uri" in (r.data || {}) || "recovery_codes" in (r.data || {});
const mod = await loadWorker();
async function fixture() {
  const db = buildDb(), env = makeEnv(db), seed = await makeSeeder(db, mod);
  seed.user("uEnrollment", "enrollment@example.test");
  await seed.session("sEnrollment", "uEnrollment", "fixture-session");
  const call = makeCaller(mod.default, env);
  return {
    db, env, call,
    setup: () => call("POST", "/api/auth/mfa/setup", "fixture-session", {}),
    verify: async (secret) => call("POST", "/api/auth/mfa/verify-setup", "fixture-session", { code: await codeFor(secret) }),
    state: () => db.prepare(`SELECT ${MFA_COLUMNS} FROM users WHERE id = 'uEnrollment'`).get(),
    events: (type) => db.prepare("SELECT COUNT(*) AS n FROM audit_events WHERE user_id = 'uEnrollment' AND event_type = ?").get(type).n,
  };
}

// Run exactly one second request after a pending-secret read or before a setup
// write. The one-shot switch is cleared before the nested request executes.
function interleaveOnce(env, { sqlIncludes, method, after = false }, action) {
  const d1 = env.cybermeters_db, prepare = d1.prepare;
  let fired = 0;
  d1.prepare = function (sql) {
    function wrap(statement) {
      const wrapped = { ...statement };
      if (statement.bind) wrapped.bind = (...args) => wrap(statement.bind(...args));
      const original = statement[method];
      wrapped[method] = async (...args) => {
        if (fired || !sql.includes(sqlIncludes)) return original(...args);
        fired++;
        if (after) {
          const value = await original(...args);
          await action();
          return value;
        }
        await action();
        return original(...args);
      };
      return wrapped;
    }
    return wrap(prepare.call(d1, sql));
  };
  return { fired: () => fired, restore: () => { d1.prepare = prepare; } };
}

// An existing session alone cannot replace or remove an enrolled factor.
{
  const f = await fixture();
  const anon = await f.call("POST", "/api/auth/mfa/setup", null, {});
  check("anonymous enrollment is rejected", () => assert.equal(anon.status, 401));
  const first = await f.setup();
  check("disabled account can start enrollment", () => assert.equal(first.status, 200));
  const secret = first.data.secret_base32;
  const storedSecret = await decryptTotpSecret(f.state().totp_secret, f.env);
  check("pending secret is encrypted and matches returned secret", () => { assert.equal(storedSecret, secret); assert.notEqual(f.state().totp_secret, secret); });
  let wrong = "000000";
  while (await verifyTotp(secret, wrong)) wrong = String(Number(wrong) + 1).padStart(6, "0");
  const beforeWrong = f.state();
  const bad = await f.call("POST", "/api/auth/mfa/verify-setup", "fixture-session", { code: wrong });
  check("wrong enrollment proof changes no MFA state", () => { assert.equal(bad.status, 400); assert.deepEqual(f.state(), beforeWrong); });
  const enabled = await f.verify(secret);
  check("correct proof enables MFA and returns recovery codes", () => { assert.equal(enabled.status, 200); assert.equal(f.state().mfa_enabled, 1); assert.ok(enabled.data.recovery_codes.length > 0); });
  const protectedState = f.state(), setups = f.events("mfa_setup_started"), enables = f.events("mfa_enabled");
  const replacement = await f.setup();
  check("enabled MFA rejects setup without exposing replacement material", () => { assert.equal(replacement.status, 409); assert.equal(hasEnrollmentMaterial(replacement), false); });
  check("rejected setup preserves all MFA fields and audit count", () => { assert.deepEqual(f.state(), protectedState); assert.equal(f.events("mfa_setup_started"), setups); });
  const duplicate = await f.verify(secret);
  check("enabled MFA rejects duplicate verification without new recovery codes", () => { assert.equal(duplicate.status, 409); assert.equal(hasEnrollmentMaterial(duplicate), false); assert.deepEqual(f.state(), protectedState); assert.equal(f.events("mfa_enabled"), enables); });
  const noProof = await f.call("POST", "/api/auth/mfa/disable", "fixture-session", {});
  check("session alone cannot disable MFA", () => { assert.equal(noProof.status, 400); assert.deepEqual(f.state(), protectedState); });
  const disable = await f.call("POST", "/api/auth/mfa/disable", "fixture-session", { code: await codeFor(secret) });
  check("original factor still disables MFA normally", () => { assert.equal(disable.status, 200); assert.equal(f.state().mfa_enabled, 0); assert.equal(f.state().totp_secret, null); });
  const reenroll = await f.setup();
  check("verified disable permits fresh enrollment", () => assert.equal(reenroll.status, 200));
  f.db.close();
}

// A verifies secret A while B rotates the pending enrollment to secret B.
{
  const f = await fixture(), first = await f.setup();
  let replacement;
  const hook = interleaveOnce(f.env, { sqlIncludes: "SELECT totp_secret, mfa_enabled FROM users", method: "first", after: true }, async () => { replacement = await f.setup(); });
  const stale = await f.verify(first.data.secret_base32);
  hook.restore();
  check("pending rotation exercised two real requests", () => { assert.equal(hook.fired(), 1); assert.equal(replacement.status, 200); });
  check("stale proof is refused without recovery codes or enable event", () => { assert.equal(stale.status, 409); assert.equal(hasEnrollmentMaterial(stale), false); assert.equal(f.state().mfa_enabled, 0); assert.equal(f.state().mfa_recovery_codes_hash_json, null); assert.equal(f.events("mfa_enabled"), 0); });
  const storedSecret = await decryptTotpSecret(f.state().totp_secret, f.env);
  check("pending replacement survives stale verification", () => assert.equal(storedSecret, replacement.data.secret_base32));
  const fresh = await f.verify(replacement.data.secret_base32);
  check("replacement's own proof succeeds", () => { assert.equal(fresh.status, 200); assert.equal(f.events("mfa_enabled"), 1); });
  f.db.close();
}

// Two verifications read the same disabled pending enrollment; only one wins.
{
  const f = await fixture(), first = await f.setup();
  let winner, winnerState;
  const hook = interleaveOnce(f.env, { sqlIncludes: "SELECT totp_secret, mfa_enabled FROM users", method: "first", after: true }, async () => { winner = await f.verify(first.data.secret_base32); winnerState = f.state(); });
  const loser = await f.verify(first.data.secret_base32);
  hook.restore();
  check("concurrent verification has one successful response", () => { assert.equal(hook.fired(), 1); assert.equal(winner.status, 200); assert.equal(loser.status, 409); });
  check("loser cannot replace winner's recovery codes or emit enable event", () => { assert.equal(hasEnrollmentMaterial(loser), false); assert.deepEqual(f.state(), winnerState); assert.equal(f.events("mfa_enabled"), 1); });
  f.db.close();
}

// Setup starts before verification completes, then writes after MFA is enabled.
{
  const f = await fixture(), first = await f.setup();
  let winner, winnerState;
  const hook = interleaveOnce(f.env, { sqlIncludes: "UPDATE users SET totp_secret = ?", method: "run" }, async () => { winner = await f.verify(first.data.secret_base32); winnerState = f.state(); });
  const lateSetup = await f.setup();
  hook.restore();
  check("setup write races a completed verification", () => { assert.equal(hook.fired(), 1); assert.equal(winner.status, 200); assert.equal(lateSetup.status, 409); });
  check("late setup cannot overwrite the enabled factor", () => { assert.equal(hasEnrollmentMaterial(lateSetup), false); assert.deepEqual(f.state(), winnerState); assert.equal(f.events("mfa_setup_started"), 1); });
  f.db.close();
}

// ── Sign-in with a second factor: each challenge and each recovery code is
// spent exactly once, even when requests race. Races run a second real request
// at the D1 boundary of the first, on real SQLite storage.
async function enrolled() {
  const f = await fixture();
  const setup = await f.setup();
  const secret = setup.data.secret_base32;
  const enabled = await f.verify(secret);
  let n = 0;
  const challenge = async ({ expired = false } = {}) => {
    const raw = `cmfa_test_${n++}_${Math.random().toString(36).slice(2)}`;
    const expires = new Date(Date.now() + (expired ? -60_000 : 600_000)).toISOString();
    f.db.prepare("INSERT INTO mfa_challenges (id, user_id, challenge_hash, expires_at) VALUES (?, 'uEnrollment', ?, ?)")
      .run(`mfach_test_${n}`, await mod.hashToken(raw), expires);
    return raw;
  };
  return {
    ...f, secret, codes: enabled.data.recovery_codes, challenge,
    recover: (challenge_token, recovery_code) => f.call("POST", "/api/auth/mfa/recovery-code", null, { challenge_token, recovery_code }),
    totp: async (challenge_token, code) => f.call("POST", "/api/auth/mfa/challenge", null, { challenge_token, code: code ?? await codeFor(secret) }),
    sessions: () => f.db.prepare("SELECT COUNT(*) AS n FROM user_sessions WHERE user_id = 'uEnrollment'").get().n,
    storedCodes: () => JSON.parse(f.state().mfa_recovery_codes_hash_json || "[]").length,
  };
}
const SPEND = "SET mfa_recovery_codes_hash_json = ?, last_login_at";

// One code, two challenges, racing: at most one session.
{
  const f = await enrolled();
  const [c1, c2] = [await f.challenge(), await f.challenge()];
  const code = f.codes[0], before = f.sessions(), stored = f.storedCodes();
  let nested;
  const hook = interleaveOnce(f.env, { sqlIncludes: SPEND, method: "run" }, async () => { nested = await f.recover(c2, code); });
  const outer = await f.recover(c1, code);
  hook.restore();
  check("one recovery code racing on two challenges signs in once", () => {
    assert.equal(hook.fired(), 1);
    assert.deepEqual([outer.status, nested.status].sort(), [200, 401]);
    assert.equal(f.sessions(), before + 1);
    assert.equal(f.storedCodes(), stored - 1);
  });
  f.db.close();
}

// Two codes racing: both sign in and both stay spent.
{
  const f = await enrolled();
  const [c1, c2, c3, c4] = [await f.challenge(), await f.challenge(), await f.challenge(), await f.challenge()];
  const [a, b] = f.codes, stored = f.storedCodes();
  let nested;
  const hook = interleaveOnce(f.env, { sqlIncludes: SPEND, method: "run" }, async () => { nested = await f.recover(c2, b); });
  const outer = await f.recover(c1, a);
  hook.restore();
  check("two codes racing both sign in", () => { assert.equal(hook.fired(), 1); assert.equal(outer.status, 200); assert.equal(nested.status, 200); });
  check("neither racing code is restored by the other's write", () => assert.equal(f.storedCodes(), stored - 2));
  const [againA, againB] = [await f.recover(c3, a), await f.recover(c4, b)];
  check("both spent codes are refused afterwards", () => { assert.equal(againA.status, 401); assert.equal(againB.status, 401); });
  f.db.close();
}

// One challenge cannot be used twice, whatever the second code is.
{
  const f = await enrolled();
  const c1 = await f.challenge();
  const first = await f.recover(c1, f.codes[0]);
  const second = await f.recover(c1, f.codes[1]);
  check("a challenge used with one code refuses another", () => { assert.equal(first.status, 200); assert.equal(second.status, 401); });
  const before = f.sessions();
  const c2 = await f.challenge();
  let nested;
  const hook = interleaveOnce(f.env, { sqlIncludes: "UPDATE mfa_challenges SET used_at", method: "run" }, async () => { nested = await f.totp(c2); });
  const outer = await f.totp(c2);
  hook.restore();
  check("one authenticator challenge submitted twice at once signs in once", () => {
    assert.equal(hook.fired(), 1);
    assert.deepEqual([outer.status, nested.status].sort(), [200, 401]);
    assert.equal(f.sessions(), before + 1);
  });
  f.db.close();
}

// Expired challenge, suspended account and wrong code are refused; a wrong
// code still spends the challenge.
{
  const f = await enrolled();
  const expiredRecovery = await f.recover(await f.challenge({ expired: true }), f.codes[0]);
  const expiredTotp = await f.totp(await f.challenge({ expired: true }));
  check("an expired challenge is refused", () => { assert.equal(expiredRecovery.status, 401); assert.equal(expiredTotp.status, 401); });
  const wrong = await f.challenge();
  const wrongCode = await f.recover(wrong, "AAAA-BBBB-CCCC");
  const retry = await f.recover(wrong, f.codes[0]);
  check("a wrong code is refused and spends the challenge", () => { assert.equal(wrongCode.status, 401); assert.equal(retry.status, 401); });
  f.db.prepare("UPDATE users SET status = 'suspended' WHERE id = 'uEnrollment'").run();
  const stored = f.storedCodes();
  const suspended = await f.recover(await f.challenge(), f.codes[0]);
  check("a suspended account is refused without spending a code", () => { assert.equal(suspended.status, 403); assert.equal(f.storedCodes(), stored); });
  f.db.close();
}

// A failure after the code is spent never makes it valid again, and never
// yields a session.
{
  const f = await enrolled();
  const d1 = f.env.cybermeters_db, prepare = d1.prepare;
  let thrown = 0;
  d1.prepare = function (sql) {
    const statement = prepare.call(d1, sql);
    if (!sql.includes("INSERT INTO user_sessions")) return statement;
    const wrap = (st) => ({ ...st, bind: (...args) => wrap(st.bind(...args)), run: async (...args) => { if (!thrown++) throw new Error("D1 unavailable"); return st.run(...args); } });
    return wrap(statement);
  };
  const before = f.sessions(), stored = f.storedCodes();
  const failed = await f.recover(await f.challenge(), f.codes[0]);
  d1.prepare = prepare;
  check("a storage failure after spending yields no session", () => { assert.equal(thrown, 1); assert.equal(failed.status, 500); assert.equal(f.sessions(), before); });
  const reuse = await f.recover(await f.challenge(), f.codes[0]);
  check("the spent code stays spent", () => { assert.equal(f.storedCodes(), stored - 1); assert.equal(reuse.status, 401); });
  const totp = await f.totp(await f.challenge());
  check("authenticator sign-in still works", () => { assert.equal(totp.status, 200); assert.ok(totp.data.token); });
  const recovered = await f.recover(await f.challenge(), f.codes[1]);
  check("an unspent recovery code still works", () => { assert.equal(recovered.status, 200); assert.ok(recovered.data.token); });
  f.db.close();
}

console.log(`\nMFA enrollment integrity: ${passed}/${passed} passed`);
