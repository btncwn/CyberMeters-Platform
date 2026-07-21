#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-oauth-callback-readiness.js  (CI-blocking)
//
// B5 release-gate: the DETERMINISTIC, locally-testable half of the Microsoft SSO
// path, driven end-to-end through the REAL Worker router (reusing the #187/#241
// harness). These controls all execute BEFORE (or entirely without) the live
// Microsoft token-exchange / JWKS fetch, so no real IdP is needed:
//
//   Callback (GET /api/auth/microsoft/callback):
//     • unconfigured instance (no AZURE_* env)      → 503
//     • missing code or state                        → 400
//     • provider-returned error (?error=…)           → 302 redirect to /login, no session
//     • unknown state (CSRF)                         → 400 (before any token exchange)
//     • expired state (TTL)                          → 400
//     • single-use state: a valid state is CONSUMED (deleted) on first use, so a
//       replay of the same state → 400 and no second session can be minted.
//   Exchange (POST /api/auth/exchange — fully local, no external fetch):
//     • missing code                                 → 400
//     • unknown / expired OTC                        → 401
//     • valid session OTC                            → returns the bearer token ONCE;
//       a replay of the same OTC → 401 (single-use)
//     • MFA-gated OTC                                → returns { mfa_required,
//       challenge_token } and NO session token (the second factor is still owed)
//
// Source-level non-regression: the callback threads the state's stored nonce into
// the id_token validator (the pure nonce/aud/iss/exp checks are proven in
// validate-auth-coverage.js B5; here we prove the wiring is not dropped).
//
// The live token exchange + RS256/JWKS signature verify + a valid id_token need a
// real Microsoft IdP → that is the founder live-OAuth acceptance script, NOT this
// suite. Requires Node 24+.
// ─────────────────────────────────────────────────────────────────────────────
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadWorker, buildDb, makeEnv, makeCaller, makeSeeder, ctx } from "./security/lib/worker-harness.js";

let passed = 0, failed = 0, section = "General";
const results = [];
const sec = (s) => { section = s; };
const ok = (name, cond) => { cond ? (passed++, results.push(`PASS [${section}] ${name}`)) : (failed++, results.push(`FAIL [${section}] ${name}`)); };

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

async function main() {
  const mod = await loadWorker();
  const worker = mod.default;

  // Azure config present for the configured-instance cases.
  const configured = (db) => {
    const e = makeEnv(db);
    e.AZURE_CLIENT_ID = "client-abc";
    e.AZURE_CLIENT_SECRET = "secret-xyz";
    e.AZURE_TENANT_ID = "11111111-1111-1111-1111-111111111111";
    e.FRONTEND_URL = "https://app.cybermeters.com";
    return e;
  };

  // ── Callback: unconfigured instance → 503 ──────────────────────────────────
  sec("Callback config + input gates");
  {
    const db = buildDb();
    const env = makeEnv(db); // no AZURE_* set
    const call = makeCaller(worker, env);
    const r = await call("GET", "/api/auth/microsoft/callback?code=x&state=y", null);
    ok("unconfigured instance → 503 (no login attempted)", r.status === 503);
  }
  {
    const db = buildDb();
    const env = configured(db);
    const call = makeCaller(worker, env);
    ok("missing state → 400", (await call("GET", "/api/auth/microsoft/callback?code=onlycode", null)).status === 400);
    ok("missing code → 400", (await call("GET", "/api/auth/microsoft/callback?state=onlystate", null)).status === 400);
    // Provider-returned error → redirect to /login, never a session.
    const errResp = await worker.fetch(new Request("https://api.cybermeters.com/api/auth/microsoft/callback?error=access_denied", { redirect: "manual" }), env, ctx);
    ok("provider error param → 302 redirect (no session)", errResp.status === 302 && String(errResp.headers.get("Location") || "").includes("/login"));
  }

  // ── Callback: CSRF state validation (unknown / expired / single-use) ───────
  sec("Callback CSRF state");
  {
    const db = buildDb();
    const env = configured(db);
    const call = makeCaller(worker, env);
    // Unknown state.
    ok("unknown state → 400 (before any token exchange)", (await call("GET", "/api/auth/microsoft/callback?code=c&state=unknown-state", null)).status === 400);
    // Expired state.
    db.prepare(`INSERT INTO oauth_states (state, provider, redirect_uri, expires_at) VALUES ('expired-state','microsoft', ?, '2000-01-01 00:00:00')`)
      .run(JSON.stringify({ redirect_uri: "https://app.cybermeters.com/api/auth/microsoft/callback", nonce: "n1" }));
    ok("expired state → 400", (await call("GET", "/api/auth/microsoft/callback?code=c&state=expired-state", null)).status === 400);

    // Single-use: a VALID state is consumed on first use. The token exchange fetch
    // fails (mocked non-2xx), but the state is deleted BEFORE the exchange, so a
    // replay of the same state can never mint a session.
    db.prepare(`INSERT INTO oauth_states (state, provider, redirect_uri, expires_at) VALUES ('live-state','microsoft', ?, datetime('now','+10 minutes'))`)
      .run(JSON.stringify({ redirect_uri: "https://app.cybermeters.com/api/auth/microsoft/callback", nonce: "n2" }));
    const realFetch = globalThis.fetch;
    // Keep the token-exchange fetch mocked across BOTH calls: under correct code the
    // replay is rejected at the state check (before any fetch); if single-use were
    // defeated, the replay would reach this mocked exchange and fail the assertion
    // cleanly (502, not 400) rather than crash on the disabled network.
    globalThis.fetch = async () => ({ ok: false, status: 502, json: async () => ({}), text: async () => "" });
    const first = await call("GET", "/api/auth/microsoft/callback?code=c&state=live-state", null);
    const stateGone = db.prepare("SELECT COUNT(*) AS n FROM oauth_states WHERE state='live-state'").get().n === 0;
    ok("valid state is CONSUMED (deleted) on first callback use", stateGone);
    ok("first use did NOT mint a session (token exchange failed → non-2xx)", first.status >= 400);
    const replay = await call("GET", "/api/auth/microsoft/callback?code=c&state=live-state", null);
    globalThis.fetch = realFetch;
    ok("replay of a consumed state → 400 (single-use CSRF)", replay.status === 400);
    ok("no session row exists after the failed/replayed callback", db.prepare("SELECT COUNT(*) AS n FROM user_sessions").get().n === 0);
  }

  // ── Exchange: OTC single-use + MFA handoff (fully local) ───────────────────
  sec("OTC exchange");
  {
    const db = buildDb();
    const env = configured(db);
    const call = makeCaller(worker, env);
    const seed = await makeSeeder(db, mod);
    seed.user("uSso", "sso@a.co");
    ok("missing code → 400", (await call("POST", "/api/auth/exchange", null, {})).status === 400);
    ok("unknown OTC → 401", (await call("POST", "/api/auth/exchange", null, { code: "no-such-otc" })).status === 401);
    // Expired OTC.
    db.prepare(`INSERT INTO oauth_states (state, provider, redirect_uri, expires_at) VALUES ('otc-expired','ms_exchange', ?, '2000-01-01 00:00:00')`)
      .run(JSON.stringify({ token: "t", userId: "uSso", email: "sso@a.co", name: "SSO", plan: "free" }));
    ok("expired OTC → 401", (await call("POST", "/api/auth/exchange", null, { code: "otc-expired" })).status === 401);
    // Valid session OTC → token once, replay → 401.
    db.prepare(`INSERT INTO oauth_states (state, provider, redirect_uri, expires_at) VALUES ('otc-good','ms_exchange', ?, datetime('now','+5 minutes'))`)
      .run(JSON.stringify({ token: "sess-tok-123", userId: "uSso", email: "sso@a.co", name: "SSO", plan: "free" }));
    const good = await call("POST", "/api/auth/exchange", null, { code: "otc-good" });
    ok("valid session OTC → returns the bearer token", good.status === 200 && good.data?.token === "sess-tok-123");
    ok("OTC is single-use: replay → 401", (await call("POST", "/api/auth/exchange", null, { code: "otc-good" })).status === 401);
    // MFA-gated OTC → challenge, never a session token.
    db.prepare(`INSERT INTO oauth_states (state, provider, redirect_uri, expires_at) VALUES ('otc-mfa','ms_exchange', ?, datetime('now','+5 minutes'))`)
      .run(JSON.stringify({ mfa_required: true, challenge_token: "chal-abc" }));
    const mfa = await call("POST", "/api/auth/exchange", null, { code: "otc-mfa" });
    ok("MFA-gated OTC → { mfa_required, challenge_token } and NO session token", mfa.data?.mfa_required === true && mfa.data?.challenge_token === "chal-abc" && !mfa.data?.token);
  }

  // ── Source non-regression: nonce is threaded from state into the validator ─
  sec("Nonce binding (source)");
  {
    const src = fs.readFileSync(path.join(ROOT, "workers", "scan-api", "src", "routes", "auth.js"), "utf8");
    ok("callback reads the stored nonce from the state payload", /expectedNonce\s*=\s*statePayload\?\.nonce/.test(src));
    ok("callback passes expectedNonce into validateMicrosoftIdToken", /validateMicrosoftIdToken\(idToken,\s*clientId,\s*tenantId,\s*expectedNonce\)/.test(src));
    ok("login route stores a per-request nonce alongside the state", /nonce:\s*nonceRaw/.test(src));
  }

  // ── Report ─────────────────────────────────────────────────────────────────
  const bySec = {};
  for (const line of results) { const s = line.match(/\[(.*?)\]/)[1]; (bySec[s] ??= { p: 0, f: 0 })[line.startsWith("PASS") ? "p" : "f"]++; }
  console.log("\nOAuth callback + exchange readiness (deterministic, no live IdP):");
  for (const [s, c] of Object.entries(bySec)) console.log(`  ${c.f ? "✗" : "✓"} ${s}: ${c.p}/${c.p + c.f}`);
  if (failed) { console.log("\nFailures:"); for (const r of results.filter((r) => r.startsWith("FAIL"))) console.log("  " + r); }
  console.log(`\nOAuth callback readiness: ${passed}/${passed + failed} passed`);
  if (failed) { console.error("oauth-callback-readiness validation FAILED"); process.exit(1); }
  console.log("oauth-callback-readiness validation passed");
}

main().catch((e) => { console.error("oauth-callback-readiness runner crashed:", e); process.exit(1); });
