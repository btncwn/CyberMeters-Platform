#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-microsoft-login-binding.js  (CI-blocking)
//
// Microsoft sign-in is released only to the browser that started it. Drives the
// REAL Worker router against in-memory SQLite, with a local identity provider:
// an RSA key pair this script generates serves the JWKS, and the token endpoint
// returns id_tokens signed with it. Every issuer, audience, tenant, nonce and
// signature check in the Worker runs unchanged. No live Microsoft call is made;
// the real-provider round trip is a separate live acceptance.
//
// A "browser" here is a verifier the start request bound with its SHA-256
// challenge. Browser B holds a different verifier (or none).
// ─────────────────────────────────────────────────────────────────────────────
import { createHash, randomBytes } from "node:crypto";
import { loadWorker, buildDb, makeEnv, makeSeeder, ctx } from "./security/lib/worker-harness.js";

let passed = 0, failed = 0;
const ok = (name, cond, detail = "") => {
  if (cond) { passed++; console.log(`PASS ${name}`); }
  else { failed++; console.log(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
};

const CLIENT_ID = "client-abc";
const TENANT_ID = "11111111-1111-1111-1111-111111111111";
const API = "https://api.cybermeters.com";
const APP = "https://app.cybermeters.com";

const mod = await loadWorker();
const worker = mod.default;

// ── Local identity provider ──────────────────────────────────────────────────
const keyPair = await crypto.subtle.generateKey(
  { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
  true, ["sign", "verify"],
);
const jwk = { ...(await crypto.subtle.exportKey("jwk", keyPair.publicKey)), kid: "local-key", alg: "RS256", use: "sig" };
const b64url = (value) => Buffer.from(value).toString("base64url");
async function signIdToken(claims) {
  const header = b64url(JSON.stringify({ alg: "RS256", kid: "local-key", typ: "JWT" }));
  const now = Math.floor(Date.now() / 1000);
  const payload = b64url(JSON.stringify({
    aud: CLIENT_ID, tid: TENANT_ID, iss: `https://login.microsoftonline.com/${TENANT_ID}/v2.0`,
    exp: now + 600, nbf: now - 10, ...claims,
  }));
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", keyPair.privateKey, new TextEncoder().encode(`${header}.${payload}`));
  return `${header}.${payload}.${b64url(new Uint8Array(signature))}`;
}
const issuedCodes = new Map();
let tokenRequests = 0;
globalThis.fetch = async (input, init = {}) => {
  const target = String(input?.url ?? input);
  if (target === `https://login.microsoftonline.com/${TENANT_ID}/discovery/v2.0/keys`) {
    return Response.json({ keys: [jwk] });
  }
  if (target === `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token`) {
    tokenRequests++;
    const code = new URLSearchParams(String(init.body || "")).get("code");
    const identity = issuedCodes.get(code);
    issuedCodes.delete(code);
    if (!identity) return Response.json({ error: "invalid_grant" }, { status: 400 });
    return Response.json({ id_token: await signIdToken(identity) });
  }
  throw new Error(`unexpected network call: ${target}`);
};

// ── Harness ──────────────────────────────────────────────────────────────────
let ip = 0;
async function fixture() {
  const db = buildDb();
  const env = makeEnv(db);
  Object.assign(env, { AZURE_CLIENT_ID: CLIENT_ID, AZURE_CLIENT_SECRET: "secret", AZURE_TENANT_ID: TENANT_ID, FRONTEND_URL: APP });
  const seed = await makeSeeder(db, mod);
  const send = async (pathname, { method = "GET", body, token, contentType = "application/json" } = {}) => {
    const headers = { "CF-Connecting-IP": `10.9.${(ip >> 8) & 255}.${ip++ & 255}` };
    if (body) headers["Content-Type"] = contentType;
    if (token) headers.Authorization = `Bearer ${token}`;
    const res = await worker.fetch(new Request(API + pathname, {
      method, headers, body: body ? JSON.stringify(body) : undefined, redirect: "manual",
    }), env, ctx);
    const text = await res.text();
    let data = null; try { data = JSON.parse(text); } catch { /* not JSON */ }
    return { status: res.status, location: res.headers.get("Location"), data };
  };
  const count = (sql, ...args) => db.prepare(sql).get(...args).n;
  return { db, env, seed, send, count };
}

const newBrowser = () => {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
};

// Start sign-in in a browser and complete the provider round trip; returns the
// one-time code the callback redirected to (or the callback response).
async function signIn(f, browser, identity) {
  const start = await f.send("/api/auth/microsoft/start", { method: "POST", body: { binding: browser.challenge } });
  const authorize = new URL(start.data.authorize_url);
  const state = authorize.searchParams.get("state");
  const code = `code-${randomBytes(6).toString("hex")}`;
  issuedCodes.set(code, { ...identity, nonce: identity.nonce ?? authorize.searchParams.get("nonce") });
  const callback = await f.send(`/api/auth/microsoft/callback?code=${code}&state=${state}`);
  const landing = callback.location ? new URL(callback.location) : null;
  return { start, state, callback, otc: landing?.searchParams.get("otc") || null };
}
const exchange = (f, otc, verifiers) => f.send("/api/auth/exchange", { method: "POST", body: { code: otc, verifiers } });
const owner = { oid: "oid-owner", email: "owner@example.test", name: "Owner" };

// ── 1. The starting browser completes its own sign-in ───────────────────────
{
  const f = await fixture();
  const A = newBrowser();
  const { start, callback, otc } = await signIn(f, A, owner);
  const authorizeUrl = start.data?.authorize_url || "";
  ok("start returns the provider URL with state and nonce, never the verifier or challenge",
    start.status === 200 && !start.location && authorizeUrl.startsWith(`https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/authorize`)
      && !authorizeUrl.includes(A.verifier) && !authorizeUrl.includes(A.challenge));
  ok("callback redirects to the app with only a one-time code",
    callback.status === 302 && callback.location.startsWith(`${APP}/auth/microsoft/callback?otc=`) && /^[0-9a-f]{64}$/.test(otc || ""));
  ok("callback creates no session before the browser is proven", f.count("SELECT COUNT(*) AS n FROM user_sessions") === 0);
  const result = await exchange(f, otc, [A.verifier]);
  ok("the starting browser receives a session", result.status === 200 && typeof result.data?.token === "string" && result.data?.email === owner.email, JSON.stringify(result.data));
  ok("the result names the challenge it matched, so the page forgets only that verifier", result.data?.binding === A.challenge);
  const me = await f.send("/api/auth/me", { token: result.data?.token });
  ok("the session works", me.status === 200 && me.data?.email === owner.email, JSON.stringify(me.data));
  ok("a replayed code is refused", (await exchange(f, otc, [A.verifier])).status === 401);
  const logout = await f.send("/api/auth/logout", { method: "POST", token: result.data?.token });
  ok("sign-out ends the session", logout.status === 200 && (await f.send("/api/auth/me", { token: result.data?.token })).status === 401);
}

// ── 2. Another browser cannot finish it ─────────────────────────────────────
{
  const f = await fixture();
  const A = newBrowser(), B = newBrowser();
  f.seed.user("uBob", "bob@example.test");
  await f.seed.session("sBob", "uBob", "bob-session");
  const { otc } = await signIn(f, A, owner);
  const sessionsBefore = f.count("SELECT COUNT(*) AS n FROM user_sessions");
  const other = await exchange(f, otc, [B.verifier]);
  ok("another browser's verifier is refused", other.status === 401 && !other.data?.token);
  ok("no verifier at all is refused", (await exchange(f, otc, [])).status === 401);
  ok("a malformed verifier is refused", (await exchange(f, otc, ["not a verifier"])).status === 401);
  ok("the other browser's existing session is untouched",
    f.count("SELECT COUNT(*) AS n FROM user_sessions") === sessionsBefore
      && (await f.send("/api/auth/me", { token: "bob-session" })).data?.email === "bob@example.test");
  ok("a refused attempt does not burn the code: the starting browser still finishes",
    (await exchange(f, otc, [A.verifier])).status === 200);
}

// ── 3. Concurrent exchanges of one code deliver once ────────────────────────
// A second exchange runs to completion at the D1 boundary right after the first
// exchange's code lookup returns — the window a read-then-delete would leave.
{
  const f = await fixture();
  const A = newBrowser();
  const { otc } = await signIn(f, A, owner);
  const d1 = f.env.cybermeters_db, prepare = d1.prepare.bind(d1);
  let nested = null, fired = false;
  d1.prepare = (sql) => {
    const hook = (statement) => {
      const wrapped = { ...statement, bind: (...args) => hook(statement.bind(...args)) };
      wrapped.first = async (...args) => {
        const value = await statement.first(...args);
        if (!fired && sql.includes("provider = 'ms_exchange'")) {
          fired = true;
          nested = await exchange(f, otc, [A.verifier]);
        }
        return value;
      };
      return wrapped;
    };
    return hook(prepare(sql));
  };
  const first = await exchange(f, otc, [A.verifier]);
  d1.prepare = prepare;
  const statuses = [first.status, nested?.status];
  ok("an exchange racing inside another's lookup produces exactly one session",
    fired && statuses.filter((status) => status === 200).length === 1 && f.count("SELECT COUNT(*) AS n FROM user_sessions") === 1,
    statuses.join(","));
  const parallel = await signIn(f, A, owner);
  const results = await Promise.all([1, 2, 3].map(() => exchange(f, parallel.otc, [A.verifier])));
  ok("parallel exchanges of one code produce exactly one session",
    results.filter((r) => r.status === 200).length === 1, results.map((r) => r.status).join(","));
}

// ── 4. Several tabs in one browser ───────────────────────────────────────────
{
  const f = await fixture();
  const tab1 = newBrowser(), tab2 = newBrowser();
  const first = await signIn(f, tab1, owner);
  const second = await signIn(f, tab2, owner);
  const both = [tab1.verifier, tab2.verifier];
  ok("each tab's sign-in completes with the browser's stored verifiers",
    (await exchange(f, first.otc, both)).status === 200 && (await exchange(f, second.otc, both)).status === 200);
  const many = newBrowser();
  const late = await signIn(f, many, owner);
  const decoys = Array.from({ length: 5 }, () => newBrowser().verifier);
  ok("only the first five presented verifiers are considered", (await exchange(f, late.otc, [...decoys, many.verifier])).status === 401);
}

// ── 5. Who can start a sign-in, and sign-ins started before binding existed ─
// Only the app's own JSON request starts one. A link (GET) or a cross-site form
// (no JSON content type) cannot route a visitor through Microsoft with a
// challenge someone else chose.
{
  const f = await fixture();
  const states = () => f.count("SELECT COUNT(*) AS n FROM oauth_states WHERE provider = 'microsoft'");
  for (const [label, body] of [["missing", {}], ["malformed", { binding: "short" }]]) {
    const r = await f.send("/api/auth/microsoft/start", { method: "POST", body });
    ok(`a ${label} binding starts nothing`, r.status === 400 && !r.location && states() === 0);
  }
  const link = await f.send(`/api/auth/microsoft/login?binding=${newBrowser().challenge}`);
  ok("a link to the old start URL starts nothing and sends the visitor to sign-in",
    link.status === 302 && link.location.startsWith(`${APP}/login?ms_error=`) && states() === 0);
  const form = await f.send("/api/auth/microsoft/start", { method: "POST", body: { binding: newBrowser().challenge }, contentType: "text/plain" });
  ok("a cross-site form post (not JSON) starts nothing", form.status === 415 && !form.location && states() === 0);
  f.db.prepare("INSERT INTO oauth_states (state, provider, redirect_uri, expires_at) VALUES ('legacy-state', 'microsoft', ?, datetime('now', '+10 minutes'))")
    .run(JSON.stringify({ redirect_uri: `${API}/api/auth/microsoft/callback`, nonce: "n-legacy" }));
  const requestsBefore = tokenRequests;
  issuedCodes.set("legacy-code", { ...owner, nonce: "n-legacy" });
  const legacy = await f.send("/api/auth/microsoft/callback?code=legacy-code&state=legacy-state");
  issuedCodes.delete("legacy-code");
  ok("an unbound in-flight sign-in is refused before any token exchange",
    legacy.status === 302 && legacy.location.startsWith(`${APP}/login?ms_error=`) && tokenRequests === requestsBefore
      && f.count("SELECT COUNT(*) AS n FROM oauth_states") === 0);
  const A = newBrowser();
  f.db.prepare("INSERT INTO oauth_states (state, provider, redirect_uri, expires_at) VALUES ('legacy-otc', 'ms_exchange', ?, datetime('now', '+5 minutes'))")
    .run(JSON.stringify({ token: "legacy-token", userId: "u", email: "x@example.test" }));
  ok("a one-time code from before binding existed is refused", (await exchange(f, "legacy-otc", [A.verifier])).status === 401);
}

// ── 6. Expiry, replay of state, and provider-claim checks are unchanged ─────
{
  const f = await fixture();
  const A = newBrowser();
  const { otc, state } = await signIn(f, A, owner);
  ok("a consumed state cannot be replayed", (await f.send(`/api/auth/microsoft/callback?code=x&state=${state}`)).status === 400);
  f.db.prepare("UPDATE oauth_states SET expires_at = '2000-01-01 00:00:00' WHERE state = ?").run(otc);
  ok("an expired code is refused even with the right verifier", (await exchange(f, otc, [A.verifier])).status === 401);
  const wrongNonce = await signIn(f, newBrowser(), { ...owner, nonce: "someone-elses-nonce" });
  ok("a token with another sign-in's nonce is rejected and yields no code",
    wrongNonce.callback.status === 401 && !wrongNonce.otc && f.count("SELECT COUNT(*) AS n FROM oauth_states WHERE provider = 'ms_exchange'") === 0);
  const foreignTenant = await signIn(f, newBrowser(), { ...owner, oid: "oid-foreign", tid: "22222222-2222-2222-2222-222222222222", iss: "https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222/v2.0" });
  ok("a token from another tenant is rejected", foreignTenant.callback.status === 401 && !foreignTenant.otc);
}

// ── 7. MFA accounts receive a challenge, and only at the exchange ───────────
{
  const f = await fixture();
  f.seed.user("uMfa", "mfa@example.test");
  f.db.prepare("UPDATE users SET mfa_enabled = 1, microsoft_oid = 'oid-mfa' WHERE id = 'uMfa'").run();
  const A = newBrowser();
  const { otc } = await signIn(f, A, { oid: "oid-mfa", email: "mfa@example.test", name: "MFA" });
  ok("no MFA challenge exists before the browser is proven", f.count("SELECT COUNT(*) AS n FROM mfa_challenges") === 0);
  ok("another browser gets neither a challenge nor a session",
    (await exchange(f, otc, [newBrowser().verifier])).status === 401 && f.count("SELECT COUNT(*) AS n FROM mfa_challenges") === 0);
  const result = await exchange(f, otc, [A.verifier]);
  ok("the starting browser receives a challenge and no session",
    result.status === 200 && result.data?.mfa_required === true && typeof result.data?.challenge_token === "string" && !result.data?.token
      && f.count("SELECT COUNT(*) AS n FROM user_sessions") === 0 && f.count("SELECT COUNT(*) AS n FROM mfa_challenges") === 1);
}

// ── 8. A suspension between callback and exchange is honoured ───────────────
{
  const f = await fixture();
  const A = newBrowser();
  const { otc } = await signIn(f, A, owner);
  f.db.prepare("UPDATE users SET status = 'suspended' WHERE email = ?").run(owner.email);
  const result = await exchange(f, otc, [A.verifier]);
  ok("a suspended account receives no session", result.status === 403 && f.count("SELECT COUNT(*) AS n FROM user_sessions") === 0);
}

// ── 9. An unverified local signup cannot retain its credentials after SSO ───
{
  const f = await fixture();
  const email = "reserved@example.test";
  f.seed.user("uReserved", email);
  f.db.prepare(`UPDATE users SET email_verified = 0, status = 'pending_verification',
    verification_token = 'pending-token', verification_token_expires_at = datetime('now', '+1 day')
    WHERE id = 'uReserved'`).run();
  await f.seed.session("sReserved", "uReserved", "reserved-session");
  const apiToken = "cm_reserved-token";
  f.db.prepare(`INSERT INTO api_tokens (id, user_id, name, token_hash, status)
    VALUES ('tReserved', 'uReserved', 'reserved', ?, 'active')`).run(await mod.hashToken(apiToken));
  const originalBatch = f.env.cybermeters_db.batch.bind(f.env.cybermeters_db);
  let linkBatch = null;
  f.env.cybermeters_db.batch = async (statements) => {
    const sql = statements.map((statement) => statement.__sql || "");
    if (sql.some((statement) => statement.includes("SET microsoft_oid"))) linkBatch = sql;
    return originalBatch(statements);
  };
  const before = f.db.prepare("SELECT password_hash FROM users WHERE id = 'uReserved'").get();
  ok("the reserved account starts with a password and unverified address",
    Boolean(before.password_hash)
      && (await f.send("/api/auth/login", { method: "POST", body: { email, password: "Sup3r-secret-pw" } })).status === 403);

  const A = newBrowser();
  const { callback, otc } = await signIn(f, A, { oid: "oid-reserved", email, name: "Reserved" });
  const after = f.db.prepare(`SELECT microsoft_oid, password_hash, email_verified, status,
    verification_token, verification_token_expires_at FROM users WHERE id = 'uReserved'`).get();
  ok("credential cleanup and account binding share one D1 batch",
    linkBatch?.length === 3
      && linkBatch.some((statement) => statement.includes("DELETE FROM user_sessions"))
      && linkBatch.some((statement) => statement.includes("UPDATE api_tokens"))
      && linkBatch.some((statement) => statement.includes("UPDATE users")));
  ok("the identity provider binds the existing account",
    callback.status === 302 && Boolean(otc) && after.microsoft_oid === "oid-reserved" && after.email_verified === 1 && after.status === "active");
  ok("the unverified signup's password and verification token are erased",
    after.password_hash === null && after.verification_token === null && after.verification_token_expires_at === null);
  ok("the unverified signup's old session and API token are invalidated",
    f.count("SELECT COUNT(*) AS n FROM user_sessions WHERE user_id = 'uReserved'") === 0
      && f.db.prepare("SELECT status FROM api_tokens WHERE id = 'tReserved'").get()?.status === "revoked"
      && (await f.send("/api/auth/me", { token: "reserved-session" })).status === 401
      && (await f.send("/api/auth/me", { token: apiToken })).status === 401);
  ok("the original password cannot sign in after SSO verified the address",
    (await f.send("/api/auth/login", { method: "POST", body: { email, password: "Sup3r-secret-pw" } })).status === 401);
  ok("the legitimate SSO browser can still finish sign-in",
    (await exchange(f, otc, [A.verifier])).status === 200);
}

// ── 10. A previously verified account retains its local credentials ─────────
{
  const f = await fixture();
  const email = "verified@example.test";
  f.seed.user("uVerified", email);
  await f.seed.session("sVerified", "uVerified", "verified-session");
  const apiToken = "cm_verified-token";
  f.db.prepare(`INSERT INTO api_tokens (id, user_id, name, token_hash, status)
    VALUES ('tVerified', 'uVerified', 'verified', ?, 'active')`).run(await mod.hashToken(apiToken));
  const originalHash = f.db.prepare("SELECT password_hash FROM users WHERE id = 'uVerified'").get().password_hash;
  const { callback } = await signIn(f, newBrowser(), { oid: "oid-verified", email, name: "Verified" });
  const after = f.db.prepare("SELECT password_hash, email_verified FROM users WHERE id = 'uVerified'").get();
  ok("verified account keeps its password and sign-in behavior",
    callback.status === 302 && after.email_verified === 1 && after.password_hash === originalHash
      && (await f.send("/api/auth/login", { method: "POST", body: { email, password: "Sup3r-secret-pw" } })).status === 200);
  ok("verified account keeps its prior session and API token",
    (await f.send("/api/auth/me", { token: "verified-session" })).status === 200
      && f.db.prepare("SELECT status FROM api_tokens WHERE id = 'tVerified'").get()?.status === "active"
      && (await f.send("/api/auth/me", { token: apiToken })).status === 200);
}

console.log(`\nMicrosoft sign-in browser binding: ${passed}/${passed + failed} passed`);
if (failed) { console.error("microsoft-login-binding validation FAILED"); process.exit(1); }
console.log("microsoft-login-binding validation passed");
