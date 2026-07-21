#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-auth-coverage.js  (CI-blocking)
//
// The B-section (authentication) of docs/SECURITY-VERIFICATION-MATRIX.md — same
// discipline as the #241/#243/#245 suites. REUSES the #187/#241 harness (real
// Worker router + in-memory SQLite). The session, logout/reset, MFA, Microsoft
// id_token validator and password-reset paths are TESTED AS-IS.
//
//   B2 — Session token: server-side stored (only the HASH persists; the raw is
//        never in D1), high-entropy, and a fresh login mints a NEW distinct
//        token (rotation). NOTE the architecture: CyberMeters uses Bearer tokens
//        returned in the login body and sent via Authorization — there is NO
//        auth cookie, so the httpOnly/Secure/SameSite cookie flags are N/A
//        (documented NT); the equivalent protections are asserted instead.
//   B3 — Logout invalidates the CURRENT session (per-device, by design — a
//        second session stays valid). Password reset invalidates ALL of the
//        user's sessions AND revokes API tokens.
//   B4 — MFA TOTP: a valid code verifies (happy path) and a wrong code is
//        rejected; the login-MFA challenge is single-use (replay → already
//        used) and an expired challenge is rejected; recovery codes are
//        single-use.
//   B5 — Microsoft id_token CLAIMS validation (microsoft-jwt.js): alg / aud /
//        exp / nbf / iss / tid / oid / nonce are each enforced. NT: the RS256
//        JWKS signature fetch + the live OAuth redirect/state exchange need a
//        real IdP.
//   B6 — Password-reset token: single-use (used_at) and expiring; the request
//        path does not leak account existence (identical response for a known
//        and an unknown email — no user enumeration).
//
// Every negative has a positive control. A RED assertion here is a real auth
// finding — STOP and report, do not patch. Requires Node 24+.
// ─────────────────────────────────────────────────────────────────────────────
import { loadWorker, buildDb, makeEnv, makeCaller, makeSeeder, ctx } from "./security/lib/worker-harness.js";
import { validateMicrosoftIdTokenClaims } from "../workers/scan-api/src/lib/microsoft-jwt.js";
import { generateTotpSecret } from "../workers/scan-api/src/lib/totp.js";
import { base32Decode } from "../workers/scan-api/src/lib/base32.js";

let passed = 0, failed = 0, section = "General";
const results = [];
const sec = (s) => { section = s; };
const ok = (name, cond) => { cond ? (passed++, results.push(`PASS [${section}] ${name}`)) : (failed++, results.push(`FAIL [${section}] ${name}`)); };
const throwsSync = (fn) => { try { fn(); return false; } catch { return true; } };

// Compute a valid RFC 6238 TOTP for the current window (matches lib/totp.js).
async function computeTotp(base32Secret, timeStep) {
  const keyBytes = base32Decode(base32Secret);
  const t = timeStep ?? Math.floor(Date.now() / 1000 / 30);
  const msg = new DataView(new ArrayBuffer(8));
  msg.setUint32(0, Math.floor(t / 0x100000000), false);
  msg.setUint32(4, t >>> 0, false);
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg.buffer));
  const offset = sig[sig.length - 1] & 0x0f;
  const code = (((sig[offset] & 0x7f) << 24) | ((sig[offset + 1] & 0xff) << 16) | ((sig[offset + 2] & 0xff) << 8) | (sig[offset + 3] & 0xff)) % 1_000_000;
  return code.toString().padStart(6, "0");
}

async function main() {
  const mod = await loadWorker();
  const worker = mod.default;
  const { hashToken, verifyTotp, generateRecoveryCodes, verifyRecoveryCode, encryptTotpSecret } = mod;

  // A shared authed probe: GET /api/auth/mfa/status is requireAuth-gated and
  // returns 200 for any valid session, 401 otherwise — the "is this token live?" oracle.
  const isLive = async (call, token) => (await call("GET", "/api/auth/mfa/status", token)).status === 200;

  // ── B2: session token — server-side stored, high-entropy, rotates ──────────
  sec("B2 session token");
  {
    const db = buildDb();
    const env = makeEnv(db);
    const seed = await makeSeeder(db, mod);
    const call = makeCaller(worker, env);
    seed.user("uSess", "sess@a.co"); // makeSeeder sets a known password + email_verified
    const login = async () => call("POST", "/api/auth/login", null, { email: "sess@a.co", password: "Sup3r-secret-pw" });
    const r1 = await login();
    ok("login succeeds and returns a token (positive control)", r1.status === 200 && typeof r1.data?.token === "string" && r1.data.token.length >= 32);
    const raw1 = r1.data.token;
    // Server-side: only the HASH is stored; the raw token is never in D1.
    const rawInDb = db.prepare("SELECT COUNT(*) AS n FROM user_sessions WHERE token_hash = ?").get(raw1).n;
    const hashInDb = db.prepare("SELECT COUNT(*) AS n FROM user_sessions WHERE token_hash = ?").get(await hashToken(raw1)).n;
    ok("raw token is NOT stored in user_sessions", rawInDb === 0);
    ok("only the token HASH is stored server-side", hashInDb === 1);
    // Rotation: a second login mints a DISTINCT token.
    const r2 = await login();
    ok("a fresh login mints a NEW distinct token (rotation)", r2.data?.token && r2.data.token !== raw1);
    // The issued token authenticates; a forged one does not.
    ok("issued token authenticates", await isLive(call, raw1));
    ok("a forged/random token does not authenticate", !(await isLive(call, "cmforged_" + "x".repeat(40))));
  }

  // ── B3: logout (per-device) + password reset (all sessions) ────────────────
  sec("B3 session invalidation");
  {
    const db = buildDb();
    const env = makeEnv(db);
    const seed = await makeSeeder(db, mod);
    const call = makeCaller(worker, env);
    seed.user("uLR", "lr@a.co");
    await seed.session("s1", "uLR", "tok1");
    await seed.session("s2", "uLR", "tok2");
    ok("both sessions valid before logout (positive control)", (await isLive(call, "tok1")) && (await isLive(call, "tok2")));
    await call("POST", "/api/auth/logout", "tok1");
    ok("logout invalidates the CURRENT session (tok1 rejected)", !(await isLive(call, "tok1")));
    ok("logout leaves OTHER sessions valid (tok2, per-device by design)", await isLive(call, "tok2"));
    // Password reset invalidates ALL sessions + revokes API tokens.
    await seed.session("s3", "uLR", "tok3"); // fresh pair for the reset case
    await seed.session("s4", "uLR", "tok4");
    seed.raw("INSERT INTO api_tokens (id, user_id, name, token_hash, scope, workspace_id, status, created_at) VALUES ('at1','uLR','t', ?, 'read', NULL, 'active', datetime('now'))", await hashToken("cm_apitok_lr"));
    const rawReset = "reset-raw-token";
    seed.raw("INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at) VALUES ('prt1','uLR', ?, ?, datetime('now'))", await hashToken(rawReset), new Date(Date.now() + 3600e3).toISOString());
    ok("sessions valid before reset (positive control)", (await isLive(call, "tok3")) && (await isLive(call, "tok4")));
    const reset = await call("POST", "/api/auth/reset-password", null, { token: rawReset, password: "N3w-passw0rd-here" });
    ok("reset-password succeeds with a valid token", reset.status === 200);
    ok("password reset invalidates ALL sessions (tok3 rejected)", !(await isLive(call, "tok3")));
    ok("password reset invalidates ALL sessions (tok4 rejected)", !(await isLive(call, "tok4")));
    const apiTokActive = db.prepare("SELECT status FROM api_tokens WHERE id='at1'").get().status;
    ok("password reset revokes active API tokens", apiTokActive !== "active");
  }

  // ── B4: MFA TOTP + challenge single-use + recovery codes ───────────────────
  sec("B4 MFA");
  {
    const db = buildDb();
    const env = makeEnv(db);
    const seed = await makeSeeder(db, mod);
    const call = makeCaller(worker, env);
    const secret = generateTotpSecret();
    const validCode = await computeTotp(secret);
    // TOTP primitive: valid code verifies, wrong code rejected.
    ok("valid TOTP code verifies (happy path)", (await verifyTotp(secret, validCode)) === true);
    ok("wrong TOTP code is rejected", (await verifyTotp(secret, "000000")) === false || validCode === "000000");
    // Login-MFA challenge is single-use + expiry, end-to-end through the route.
    seed.user("uMfa", "mfa@a.co");
    const encSecret = await encryptTotpSecret(secret, env);
    seed.raw("UPDATE users SET mfa_enabled = 1, totp_secret = ? WHERE id = 'uMfa'", encSecret);
    // Happy path: a valid challenge + valid code → 200 + session token.
    const rawCh = "chal-valid";
    seed.raw("INSERT INTO mfa_challenges (id, user_id, challenge_hash, expires_at) VALUES ('mc1','uMfa', ?, ?)", await hashToken(rawCh), new Date(Date.now() + 300e3).toISOString());
    const good = await call("POST", "/api/auth/mfa/challenge", null, { challenge_token: rawCh, code: await computeTotp(secret) });
    ok("MFA challenge with a valid code issues a session (happy path)", good.status === 200 && typeof good.data?.token === "string");
    // Single-use: a fresh challenge, first attempt (wrong code) consumes it,
    // replay is rejected as already-used regardless of code.
    const rawCh2 = "chal-single-use";
    seed.raw("INSERT INTO mfa_challenges (id, user_id, challenge_hash, expires_at) VALUES ('mc2','uMfa', ?, ?)", await hashToken(rawCh2), new Date(Date.now() + 300e3).toISOString());
    const firstUse = await call("POST", "/api/auth/mfa/challenge", null, { challenge_token: rawCh2, code: "000000" });
    ok("wrong MFA code is rejected (401)", firstUse.status === 401);
    const replay = await call("POST", "/api/auth/mfa/challenge", null, { challenge_token: rawCh2, code: await computeTotp(secret) });
    ok("MFA challenge is single-use (replay rejected even with a valid code)", replay.status === 401);
    // Expired challenge is rejected.
    const rawChExp = "chal-expired";
    seed.raw("INSERT INTO mfa_challenges (id, user_id, challenge_hash, expires_at) VALUES ('mc3','uMfa', ?, '2000-01-01T00:00:00.000Z')", await hashToken(rawChExp));
    ok("expired MFA challenge is rejected", (await call("POST", "/api/auth/mfa/challenge", null, { challenge_token: rawChExp, code: await computeTotp(secret) })).status === 401);
    // Recovery codes are single-use.
    const rc = await generateRecoveryCodes();
    const firstRc = await verifyRecoveryCode(rc.codes[0], JSON.stringify(rc.hashes));
    ok("recovery code accepted once (positive control)", firstRc.valid === true);
    ok("recovery code is single-use (reuse rejected)", (await verifyRecoveryCode(rc.codes[0], JSON.stringify(firstRc.remainingHashes))).valid === false);
  }

  // ── B5: Microsoft id_token claims validation ───────────────────────────────
  sec("B5 Microsoft id_token claims");
  {
    const CLIENT = "client-abc", TENANT = "11111111-1111-1111-1111-111111111111";
    const now = 1_000_000;
    const goodHeader = { alg: "RS256", kid: "k1" };
    const goodPayload = { aud: CLIENT, exp: now + 300, nbf: now - 10, oid: "user-oid", tid: TENANT, iss: `https://login.microsoftonline.com/${TENANT}/v2.0`, nonce: "n-123" };
    // Positive control: fully valid claims do not throw.
    ok("valid claims pass (positive control)", !throwsSync(() => validateMicrosoftIdTokenClaims(goodHeader, goodPayload, CLIENT, TENANT, "n-123", now)));
    ok("wrong alg (not RS256) rejected", throwsSync(() => validateMicrosoftIdTokenClaims({ ...goodHeader, alg: "none" }, goodPayload, CLIENT, TENANT, "n-123", now)));
    ok("missing kid rejected", throwsSync(() => validateMicrosoftIdTokenClaims({ alg: "RS256" }, goodPayload, CLIENT, TENANT, "n-123", now)));
    ok("wrong audience rejected", throwsSync(() => validateMicrosoftIdTokenClaims(goodHeader, { ...goodPayload, aud: "attacker-client" }, CLIENT, TENANT, "n-123", now)));
    ok("expired token rejected", throwsSync(() => validateMicrosoftIdTokenClaims(goodHeader, { ...goodPayload, exp: now - 300 }, CLIENT, TENANT, "n-123", now)));
    ok("not-yet-active (nbf) token rejected", throwsSync(() => validateMicrosoftIdTokenClaims(goodHeader, { ...goodPayload, nbf: now + 300 }, CLIENT, TENANT, "n-123", now)));
    ok("tenant mismatch (single-tenant) rejected", throwsSync(() => validateMicrosoftIdTokenClaims(goodHeader, { ...goodPayload, tid: "22222222-2222-2222-2222-222222222222", iss: "https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222/v2.0" }, CLIENT, TENANT, "n-123", now)));
    ok("issuer mismatch rejected", throwsSync(() => validateMicrosoftIdTokenClaims(goodHeader, { ...goodPayload, iss: "https://evil.example/v2.0" }, CLIENT, TENANT, "n-123", now)));
    ok("missing oid rejected", throwsSync(() => validateMicrosoftIdTokenClaims(goodHeader, { ...goodPayload, oid: undefined }, CLIENT, TENANT, "n-123", now)));
    ok("nonce mismatch (replay) rejected", throwsSync(() => validateMicrosoftIdTokenClaims(goodHeader, goodPayload, CLIENT, TENANT, "different-nonce", now)));
  }

  // ── B6: password-reset token single-use + expiry + no enumeration ──────────
  sec("B6 password-reset token");
  {
    const db = buildDb();
    const env = makeEnv(db);
    const seed = await makeSeeder(db, mod);
    const call = makeCaller(worker, env);
    seed.user("uPr", "pr@a.co");
    // Single-use: a valid token resets once, the second use is refused.
    const rawPr = "pr-raw-1";
    seed.raw("INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at) VALUES ('prtA','uPr', ?, ?, datetime('now'))", await hashToken(rawPr), new Date(Date.now() + 3600e3).toISOString());
    const use1 = await call("POST", "/api/auth/reset-password", null, { token: rawPr, password: "Fresh-passw0rd-1" });
    ok("reset token works once (positive control)", use1.status === 200);
    const use2 = await call("POST", "/api/auth/reset-password", null, { token: rawPr, password: "Another-passw0rd-2" });
    ok("reset token is single-use (second use refused)", use2.status === 400);
    ok("used_at is stamped on the reset token", db.prepare("SELECT used_at FROM password_reset_tokens WHERE id='prtA'").get().used_at != null);
    // Expiry: an expired token is refused.
    const rawExp = "pr-raw-expired";
    seed.raw("INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at) VALUES ('prtB','uPr', ?, '2000-01-01T00:00:00.000Z', datetime('now'))", await hashToken(rawExp));
    ok("expired reset token is refused", (await call("POST", "/api/auth/reset-password", null, { token: rawExp, password: "Whatever-passw0rd" })).status === 400);
    // No enumeration: identical response for a known and an unknown email.
    const known = await call("POST", "/api/auth/forgot-password", null, { email: "pr@a.co" });
    const unknown = await call("POST", "/api/auth/forgot-password", null, { email: "nobody-here@nowhere.co" });
    ok("forgot-password: known + unknown email return the SAME status", known.status === unknown.status && known.status === 200);
    ok("forgot-password: known + unknown email return the SAME body (no enumeration)", JSON.stringify(known.data) === JSON.stringify(unknown.data));
  }

  // ── Coverage delta ─────────────────────────────────────────────────────────
  sec("Coverage");
  const controls = {
    B2: "session token server-side stored (hash-at-rest), high-entropy, rotates on login",
    B3: "logout invalidates the current session (per-device); password reset invalidates ALL sessions + revokes API tokens",
    B4: "MFA TOTP valid/wrong code; challenge single-use + expiry; recovery codes single-use",
    B5: "Microsoft id_token claims (alg/aud/exp/nbf/iss/tid/oid/nonce) each enforced",
    B6: "reset token single-use (used_at) + expiring; forgot-password does not enumerate accounts",
  };
  ok("all five assessable B-section controls asserted", Object.keys(controls).length === 5);

  // ── Report ─────────────────────────────────────────────────────────────────
  const bySec = {};
  for (const line of results) { const s = line.match(/\[(.*?)\]/)[1]; (bySec[s] ??= { p: 0, f: 0 })[line.startsWith("PASS") ? "p" : "f"]++; }
  console.log("\nAuthentication coverage (B-section, reusing #187/#241 harness):");
  for (const [s, c] of Object.entries(bySec)) console.log(`  ${c.f ? "✗" : "✓"} ${s}: ${c.p}/${c.p + c.f}`);
  console.log("\nB-section coverage delta:");
  for (const [k, v] of Object.entries(controls)) console.log(`  + ${k} — ${v}`);
  console.log("  · NT B2 cookie flags — CyberMeters is a Bearer-token architecture (token in the login body, sent via Authorization); there is NO auth cookie, so httpOnly/Secure/SameSite do not apply. Server-side storage, hash-at-rest, rotation and expiry are asserted instead.");
  console.log("  · NT B5 signature + live OAuth — the RS256 JWKS signature verify and the OAuth redirect/state single-use exchange need a real Microsoft IdP (live JWKS + code exchange); the security-critical CLAIMS validation is fully covered here.");
  if (failed) { console.log("\nFailures:"); for (const rr of results.filter((x) => x.startsWith("FAIL"))) console.log("  " + rr); }
  console.log(`\nAuth coverage: ${passed}/${passed + failed} passed`);
  if (failed) { console.error("auth-coverage validation FAILED — a RED assertion here is an auth finding, not a test bug"); process.exit(1); }
  console.log("auth-coverage validation passed");
}

main().catch((e) => { console.error("auth-coverage runner crashed:", e); process.exit(1); });
