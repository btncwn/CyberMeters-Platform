#!/usr/bin/env node
//
// Security-contract tests for the money + access paths the scanner regression
// suite does not cover: password + MFA crypto, recovery-code single-use, the
// RBAC permission matrix, Stripe webhook signature verification, and the billing
// grace-period logic. Same isolation approach as validate-regression-fixtures.js
// — the monolith is loaded in a vm sandbox and the pure functions are exercised
// directly (no network, no D1). Exits non-zero on any failure so CI blocks.
//
import fs from "node:fs";
import path from "node:path";
import { webcrypto } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const workerPath = path.join(repoRoot, "workers", "scan-api", "src", "index.js");

// ESM worker loading (vm-free): the worker is a real module since Sprint 9
// split it up — vm.runInContext cannot evaluate `import`. Network stays
// disabled and Workers-global stubs are applied process-wide before import.
async function loadSecurityFns() {
  globalThis.fetch = async () => { throw new Error("network disabled"); };
  AbortSignal.timeout = () => undefined;
  return import(pathToFileURL(workerPath).href);
}

// ── tiny assert harness ──────────────────────────────────────────────────────
let passed = 0, failed = 0;
const results = [];
function ok(name, cond) {
  if (cond) { passed++; results.push(`PASS ${name}`); }
  else { failed++; results.push(`FAIL ${name}`); }
}
async function throws(name, fn) {
  try { await fn(); ok(name, false); }
  catch { ok(name, true); }
}

// Independent HMAC-SHA256 hex — the trusted reference for the Stripe test, so we
// verify the worker's signature check against a standard implementation, not itself.
async function hmacHex(secret, message) {
  const key = await webcrypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await webcrypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function main() {
  const S = await loadSecurityFns();

  // ── 1. Password hashing (PBKDF2) ──
  const stored = await S.hashPassword("Correct horse battery staple");
  ok("password: correct verifies", await S.verifyPassword("Correct horse battery staple", stored));
  ok("password: wrong rejected", !(await S.verifyPassword("wrong", stored)));
  ok("password: malformed hash rejected", !(await S.verifyPassword("x", "not-a-valid-hash")));
  ok("password: hash is salted (two hashes differ)",
    stored !== await S.hashPassword("Correct horse battery staple"));

  // ── 2. Recovery codes — single-use ──
  const rc = await S.generateRecoveryCodes();
  ok("recovery: generates codes + hashes", Array.isArray(rc.codes) && Array.isArray(rc.hashes) && rc.codes.length > 0);
  const firstUse = await S.verifyRecoveryCode(rc.codes[0], JSON.stringify(rc.hashes));
  ok("recovery: valid code accepted", firstUse.valid === true);
  ok("recovery: used code removed from remaining", firstUse.remainingHashes.length === rc.hashes.length - 1);
  const reuse = await S.verifyRecoveryCode(rc.codes[0], JSON.stringify(firstUse.remainingHashes));
  ok("recovery: code is single-use (reuse rejected)", reuse.valid === false);
  ok("recovery: wrong code rejected", (await S.verifyRecoveryCode("0000-0000", JSON.stringify(rc.hashes))).valid === false);

  // ── 3. MFA secret at-rest crypto (AES-GCM) ──
  const env = { MFA_ENCRYPTION_KEY: "unit-test-mfa-key-do-not-use-in-prod" };
  const secret = S.generateTotpSecret();
  const enc = await S.encryptTotpSecret(secret, env);
  ok("mfa: encrypt->decrypt roundtrip", await S.decryptTotpSecret(enc, env) === secret);
  ok("mfa: ciphertext is not plaintext", !String(enc).includes(secret));
  const tampered = (() => { const o = JSON.parse(enc); o.ct = o.ct.slice(0, -2) + (o.ct.endsWith("00") ? "11" : "00"); return JSON.stringify(o); })();
  await throws("mfa: tampered ciphertext fails auth (GCM)", () => S.decryptTotpSecret(tampered, env));
  await throws("mfa: wrong key cannot decrypt", () => S.decryptTotpSecret(enc, { MFA_ENCRYPTION_KEY: "a-different-key" }));

  // ── 4. TOTP verify rejects wrong codes ──
  ok("totp: obviously-wrong code rejected", !(await S.verifyTotp(secret, "000000")));
  ok("totp: empty code rejected", !(await S.verifyTotp(secret, "")));

  // ── 5. RBAC permission matrix ──
  ok("rbac: viewer cannot manage workspace", !S.hasWorkspacePermission("viewer", "workspace:manage"));
  ok("rbac: admin can manage workspace", S.hasWorkspacePermission("admin", "workspace:manage"));
  ok("rbac: owner can manage workspace", S.hasWorkspacePermission("owner", "workspace:manage"));
  ok("rbac: analyst cannot delete reports", !S.hasWorkspacePermission("analyst", "report:delete"));
  ok("rbac: admin can delete reports", S.hasWorkspacePermission("admin", "report:delete"));
  ok("rbac: unknown role denied", !S.hasWorkspacePermission("superhacker", "workspace:manage"));
  ok("rbac: unknown permission denied", !S.hasWorkspacePermission("owner", "workspace:obliterate"));
  // Monotonic: if a lower role holds a permission, every higher role holds it too.
  const ROLES = ["viewer", "analyst", "admin", "owner"];
  const PERMS = ["workspace:manage", "workspace:invite", "domain:verify", "report:delete", "scan:create"];
  let monotonic = true;
  for (const p of PERMS) {
    let seenTrue = false;
    for (const r of ROLES) {
      const has = S.hasWorkspacePermission(r, p);
      if (has) seenTrue = true;
      else if (seenTrue) monotonic = false; // a higher role lost a permission a lower one had
    }
  }
  ok("rbac: permissions are monotonic across the role ladder", monotonic);
  // Token scope: a read-scoped token cannot perform a write permission even as owner.
  ok("rbac: read-scoped token cannot manage (even owner)", !S.hasWorkspacePermission("owner", "workspace:manage", "read"));
  ok("rbac: session (no token scope) owner can manage", S.hasWorkspacePermission("owner", "workspace:manage", undefined));

  // ── 6. Stripe webhook signature ──
  const secretKey = "whsec_unit_test";
  const body = JSON.stringify({ id: "evt_1", type: "invoice.payment_failed" });
  const now = Math.floor(Date.now() / 1000);
  const goodSig = await hmacHex(secretKey, `${now}.${body}`);
  ok("stripe: valid signature accepted",
    (await S.verifyStripeWebhookSignature(body, `t=${now},v1=${goodSig}`, secretKey)).ok === true);
  ok("stripe: tampered body rejected",
    (await S.verifyStripeWebhookSignature(body + " ", `t=${now},v1=${goodSig}`, secretKey)).ok === false);
  ok("stripe: wrong secret rejected",
    (await S.verifyStripeWebhookSignature(body, `t=${now},v1=${goodSig}`, "whsec_wrong")).ok === false);
  const oldTs = now - 3600;
  const oldSig = await hmacHex(secretKey, `${oldTs}.${body}`);
  ok("stripe: stale timestamp rejected (replay)",
    (await S.verifyStripeWebhookSignature(body, `t=${oldTs},v1=${oldSig}`, secretKey)).ok === false);
  ok("stripe: malformed header rejected",
    (await S.verifyStripeWebhookSignature(body, "not-a-signature", secretKey)).ok === false);

  // ── 7. Billing grace period ──
  const iso = (msAgo) => new Date(Date.now() - msAgo).toISOString();
  ok("grace: past_due + recent failure is active",
    S.getPaymentGraceState({ subscription_status: "past_due", payment_failed_at: iso(60_000) }).active === true);
  ok("grace: past_due + old failure is expired",
    S.getPaymentGraceState({ subscription_status: "past_due", payment_failed_at: iso(60 * 24 * 60 * 60 * 1000) }).active === false);
  ok("grace: active subscription is not in grace",
    S.getPaymentGraceState({ subscription_status: "active", payment_failed_at: iso(60_000) }).active === false);
  ok("grace: past_due without a failure timestamp is not active",
    S.getPaymentGraceState({ subscription_status: "past_due" }).active === false);

  // ── 8. Session token integrity ──
  const t1 = await S.generateSessionToken();
  ok("session: token hash matches hashToken(raw)", t1.hash === await S.hashToken(t1.raw));
  const t2 = await S.generateSessionToken();
  ok("session: tokens are unique (entropy)", t1.raw !== t2.raw);

  // ── 9. Pagination contract ──
  const pp = (q, opts) => S.paginationParams(new URL("https://x/api" + q), opts);
  ok("pagination: parses limit + offset", (() => { const p = pp("?limit=10&offset=20"); return p.limit === 10 && p.offset === 20; })());
  ok("pagination: clamps limit to maxLimit", pp("?limit=9999", { maxLimit: 100 }).limit === 100);
  ok("pagination: clamps limit to >=1", pp("?limit=0").limit === 1);
  ok("pagination: default limit when absent", pp("", { defaultLimit: 50 }).limit === 50);
  ok("pagination: negative offset floored to 0", pp("?offset=-5").offset === 0);
  ok("pageMeta: full page implies has_more", (() => { const m = S.pageMeta({ items: [1, 2, 3], limit: 3, offset: 0 }); return m.count === 3 && m.has_more === true; })());
  ok("pageMeta: partial page has no more", S.pageMeta({ items: [1, 2], limit: 5, offset: 0 }).has_more === false);
  ok("pageMeta: with total computes has_more exactly", (() => { const m = S.pageMeta({ items: [1, 2, 3], limit: 10, offset: 0, total: 25 }); return m.total === 25 && m.has_more === true; })());
  ok("pageMeta: last page with total has no more", S.pageMeta({ items: [1, 2], limit: 10, offset: 8, total: 10 }).has_more === false);

  // ── report ──
  for (const line of results) if (line.startsWith("FAIL")) console.error(line);
  console.log(`\nSecurity contracts: ${passed}/${passed + failed} passed`);
  if (failed > 0) { console.error("security contract validation FAILED"); process.exit(1); }
  console.log("security contract validation passed");
}

main().catch((e) => { console.error("security runner crashed:", e); process.exit(1); });
