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
guard(
  "F-1 password reset revokes active API tokens in the batch",
  authSrc,
  (s) => {
    // Revocation statement present AND co-located with the session-invalidation
    // batch (so it runs atomically as part of the reset, not somewhere unrelated).
    const revoke = "UPDATE api_tokens SET status = 'revoked' WHERE user_id = ? AND status = 'active'";
    const sess = "DELETE FROM user_sessions WHERE user_id = ?";
    return s.includes(revoke) && s.includes(sess)
      && Math.abs(s.indexOf(revoke) - s.indexOf(sess)) < 800;
  },
  (s) => s.replace("UPDATE api_tokens SET status = 'revoked' WHERE user_id = ? AND status = 'active'", "SELECT 1"),
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

console.log(`\nauth/session hardening: ${pass}/${pass + fail} passed`);
if (fail) { console.error("auth-session-hardening validation FAILED"); process.exit(1); }
console.log("auth-session-hardening validation passed");
