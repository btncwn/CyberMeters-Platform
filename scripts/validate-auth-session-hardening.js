#!/usr/bin/env node
//
// Security Hardening v2 — auth/session/tenant-lifecycle guards. CI-blocking.
//
// Pins four confirmed P2 fixes so a future refactor cannot silently revert them:
//
//   F-2  Microsoft SSO enforces MFA. The exchange issues an mfa_challenges token
//        (never a session) when the account has MFA enabled, and completes through
//        the same POST /api/auth/mfa/challenge endpoint as password login. Without
//        this, an MFA-enabled account signs in via SSO with the second factor
//        silently ignored.
//   F-1  Password reset revokes active API tokens. Reset deletes sessions but must
//        also revoke `cm_` bearer tokens — otherwise an attacker who minted one
//        keeps access through the exact recovery flow meant to cut them off.
//   Inv-2 Invitation accept refuses a soft-deleted workspace. Accept is the one
//        membership path outside requireWorkspaceRole (which already filters
//        deleted_at), so it must enforce the invariant explicitly via a join.
//   Q4   Lifecycle email skips soft-deleted workspaces. The workspace_id → owner
//        resolver filters deleted_at so a soft-deleted workspace receives no
//        onboarding/first-scan email (including failed-email retries).
//
// Each guard is a predicate over source that MUST hold on the real file AND MUST
// fail on a copy with the defect reintroduced (in-memory mutation). That makes the
// validator self-proving: it demonstrates it would catch the reversion it guards.
//
// Node 24+.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (...p) => fs.readFileSync(path.join(root, ...p), "utf8");

const authSrc    = read("workers", "scan-api", "src", "routes", "auth.js");
const membersSrc = read("workers", "scan-api", "src", "routes", "workspace-members.js");
const lifeSrc    = read("workers", "scan-api", "src", "lib", "lifecycle-email.js");
const mcpSrc     = read("workers", "scan-api", "src", "routes", "mcp-oauth-server.js");

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

// A guard: predicate over source + a mutation that reintroduces the defect. The
// predicate must be true on the real source and false on the mutated source.
function guard(name, src, predicate, mutate) {
  ok(`${name} — holds on current source`, predicate(src) === true);
  const mutated = mutate(src);
  ok(`${name} — mutation changed the source`, mutated !== src);
  ok(`${name} — CAUGHT: predicate fails when the defect is reintroduced`, predicate(mutated) === false);
}

// ── F-2 SSO MFA enforcement ───────────────────────────────────────────────────

// The callback never mints a session or a challenge: it issues a one-time code
// bound to the starting browser. The exchange releases that code and, for an
// MFA account, returns a challenge token (never a session) — the MFA gate sits
// BEFORE session creation in the exchange.
const exchangeBlock = (s) => {
  const start = s.indexOf('url.pathname === "/api/auth/exchange"');
  const end = s.indexOf("// ── POST /api/auth/forgot-password", start);
  return start === -1 || end === -1 ? "" : s.slice(start, end);
};
guard(
  "F-2 SSO exchange issues an MFA challenge instead of a session",
  authSrc,
  (s) => {
    const block = exchangeBlock(s);
    const gate = block.indexOf("if (user.mfa_enabled) {");
    const challenge = block.indexOf("return json({ mfa_required: true, challenge_token: challengeRaw");
    const session = block.indexOf("INSERT INTO user_sessions");
    return gate !== -1 && challenge > gate && session > challenge
      && /if \(user\.mfa_enabled\) \{[\s\S]*?INSERT INTO mfa_challenges[\s\S]*?return json\(\{ mfa_required: true/.test(block);
  },
  // Reversion: drop the exchange's MFA gate.
  (s) => {
    const block = exchangeBlock(s);
    return s.replace(block, block.replace("if (user.mfa_enabled) {", "if (false) {"));
  },
);

// The callback creates neither a session nor a challenge before the browser
// binding is proven at the exchange.
guard(
  "F-2 SSO callback mints no session or challenge",
  authSrc,
  (s) => {
    const start = s.indexOf('url.pathname === "/api/auth/microsoft/callback"');
    const end = s.indexOf('url.pathname === "/api/auth/exchange"');
    const block = start === -1 || end === -1 ? "" : s.slice(start, end);
    return block.includes("'ms_exchange'") && !block.includes("INSERT INTO user_sessions") && !block.includes("INSERT INTO mfa_challenges");
  },
  (s) => s.replace("      // ── 5. Issue a one-time result bound to the starting browser", "      await env.cybermeters_db.prepare(`INSERT INTO user_sessions (id) VALUES ('x')`).run();\n      // ── 5. Issue a one-time result bound to the starting browser"),
);

// The gate can only fire if the account's MFA state is read — pin it on the
// callback's oid lookup and on the exchange's user read.
guard(
  "F-2 callback selects mfa_enabled (oid lookup)",
  authSrc,
  (s) => /SELECT id, email, name, plan, status, mfa_enabled FROM users WHERE microsoft_oid = \?/.test(s),
  (s) => s.replace("status, mfa_enabled FROM users WHERE microsoft_oid", "status FROM users WHERE microsoft_oid"),
);
guard(
  "F-2 exchange reads the account's current MFA state",
  authSrc,
  (s) => /SELECT id, email, name, status, mfa_enabled FROM users WHERE id = \? LIMIT 1/.test(exchangeBlock(s)),
  (s) => s.replace("SELECT id, email, name, status, mfa_enabled FROM users WHERE id = ? LIMIT 1", "SELECT id, email, name, status FROM users WHERE id = ? LIMIT 1"),
);

// ── F-1 Password reset revokes API tokens ─────────────────────────────────────
// SSO binding also invalidates sessions and tokens. Inspect only the password
// reset batch so another route cannot satisfy this guard or its mutation test.
const resetBatch = (s) => {
  const route = s.indexOf('url.pathname === "/api/auth/reset-password"');
  const start = s.indexOf("const resetStatements = [", route);
  const end = s.indexOf("const resetResults = await env.cybermeters_db.batch(resetStatements);", start);
  return route === -1 || start === -1 || end === -1 ? "" : s.slice(start, end);
};
const resetRevoke = "UPDATE api_tokens SET status = 'revoked' WHERE user_id = ? AND status = 'active'";
const resetRevokesApiTokens = (s) => {
  const batch = resetBatch(s);
  const sessions = batch.indexOf("DELETE FROM user_sessions WHERE user_id = ? AND ${eligible}");
  const revoke = batch.indexOf(resetRevoke + " AND ${eligible}");
  const consume = batch.indexOf("UPDATE password_reset_tokens SET used_at = ?");
  const revokeBinding = batch.indexOf(".bind(user.id, ...guard)", revoke);
  return sessions !== -1 && revoke > sessions && consume > revoke
    && revokeBinding > revoke && revokeBinding < consume;
};
guard(
  "F-1 password reset revokes active API tokens in the batch",
  authSrc,
  resetRevokesApiTokens,
  (s) => {
    const batch = resetBatch(s);
    return batch ? s.replace(batch, batch.replace(resetRevoke, "SELECT 1")) : s;
  },
);

// ── Inv-2 Invitation accept refuses soft-deleted workspaces ───────────────────
guard(
  "Inv-2 invitation accept joins workspaces on deleted_at IS NULL",
  membersSrc,
  (s) => /FROM workspace_invitations wi\s+JOIN workspaces w ON w\.id = wi\.workspace_id AND w\.deleted_at IS NULL\s+WHERE wi\.token_hash = \?/.test(s),
  (s) => s.replace("AND w.deleted_at IS NULL", ""),
);

// ── Q4 Lifecycle email skips soft-deleted workspaces ──────────────────────────
guard(
  "Q4 lifecycle email owner lookup filters deleted_at",
  lifeSrc,
  (s) => /JOIN users u ON u\.id = w\.owner_user_id WHERE w\.id = \? AND w\.deleted_at IS NULL/.test(s),
  (s) => s.replace("WHERE w.id = ? AND w.deleted_at IS NULL", "WHERE w.id = ?"),
);

// ── S-1 Secrets stay out of URLs (19 Oct 2026) ────────────────────────────────
// Page analytics and server logs see a URL's path and query. Every emailed or
// redirected link that carries a secret carries it in the fragment, which never
// leaves the browser; the app clears it from the address bar on load
// (frontend/src/lib/urlSecrets.js). Each guard fails if the secret goes back
// into the query.
guard(
  "S-1 password reset link carries its token in the fragment",
  authSrc,
  (s) => s.includes("`${appUrl}/reset-password#t=${encodeURIComponent(resetToken)}`") && !/reset-password\?token=/.test(s),
  (s) => s.replace("`${appUrl}/reset-password#t=${encodeURIComponent(resetToken)}`", "`${appUrl}/reset-password?token=${resetToken}`"),
);
guard(
  "S-1 email verification link opens the app with the token in the fragment",
  authSrc,
  (s) => s.includes("return `${origin}/verify-email#${fragment.toString()}`;") && !/api\/auth\/verify-email\?token=/.test(s),
  (s) => s.replace("return `${origin}/verify-email#${fragment.toString()}`;", "return `${origin}/api/auth/verify-email?${fragment.toString()}`;"),
);
guard(
  "S-1 the app verifies a fragment token by POST, the GET form stays for links already sent",
  authSrc,
  (s) => /request\.method === "POST" && url\.pathname === "\/api\/auth\/verify-email"[\s\S]{0,400}verifyEmailToken\(env, token\)/.test(s) &&
         /request\.method === "GET" && url\.pathname === "\/api\/auth\/verify-email"[\s\S]{0,900}verifyEmailToken\(env, url\.searchParams\.get\("token"\)/.test(s),
  (s) => s.replace('request.method === "POST" && url.pathname === "/api/auth/verify-email"', 'request.method === "PUT" && url.pathname === "/api/auth/verify-email"'),
);
guard(
  "S-1 Microsoft sign-in hands its one-time code back in the fragment",
  authSrc,
  (s) => s.includes("dest.hash = new URLSearchParams({ otc: otcRaw }).toString();") && !s.includes('dest.searchParams.set("otc"'),
  (s) => s.replace("dest.hash = new URLSearchParams({ otc: otcRaw }).toString();", 'dest.searchParams.set("otc", otcRaw);'),
);
guard(
  "S-1 MCP consent intent reaches the app in the fragment",
  mcpSrc,
  (s) => s.includes("`${appOrigin}/mcp/connect#intent=${intent}`") && !s.includes("/mcp/connect?intent="),
  (s) => s.replace("`${appOrigin}/mcp/connect#intent=${intent}`", "`${appOrigin}/mcp/connect?intent=${intent}`"),
);

console.log(`\nauth/session hardening: ${pass}/${pass + fail} passed`);
if (fail) { console.error("auth-session-hardening validation FAILED"); process.exit(1); }
console.log("auth-session-hardening validation passed");
