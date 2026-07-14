#!/usr/bin/env node
//
// Workspace-scoped domain-verification gate (beta blocker). Proof-of-control is
// per (workspace_id, domain_id) on workspace_domains (migration 079), NOT global per
// user/domain. Every scan-start path must reject an unverified workspace-domain, and
// verification in one workspace must never authorize another. Drives the REAL worker
// fetch with seeded sessions + a recording R2 stub. Requires Node 24+ (node:sqlite).
// CI-blocking.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const lib = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib", "domain-verification.js")).href);
const { hashToken } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib", "auth-crypto.js")).href);
const { isWorkspaceDomainVerified, DOMAIN_VERIFICATION_REQUIRED } = lib;

let pass = 0, fail = 0;
const ok = (n, c) => { c ? pass++ : fail++; if (!c) console.log("FAIL " + n); };
const eq = (n, g, w) => ok(n + ` (got ${JSON.stringify(g)})`, g === w);

globalThis.fetch = async () => { throw new Error("network disabled"); };
AbortSignal.timeout = () => undefined;
const worker = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "index.js")).href);

const db = new DatabaseSync(":memory:");
const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering no-ops */ } };
apply(path.join(root, "database", "schema.sql"));
const migDir = path.join(root, "database", "migrations");
const migFiles = fs.readdirSync(migDir).filter((f) => f.endsWith(".sql")).sort();
for (const f of migFiles) apply(path.join(migDir, f));
db.exec("PRAGMA foreign_keys = OFF");

const makeD1 = (d) => {
  const wrap = (sql, args) => ({ first: async () => d.prepare(sql).get(...args) ?? null, all: async () => ({ results: d.prepare(sql).all(...args) }), run: async () => { const r = d.prepare(sql).run(...args); return { meta: { changes: r.changes } }; } });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
};

// ── 1. Migration 079 is additive + the backfill rule is correct ──────────────
{
  const mig = fs.readFileSync(path.join(migDir, "079-workspace-domain-verification.sql"), "utf8");
  ok("079: additive columns on workspace_domains", /ALTER TABLE workspace_domains ADD COLUMN verification_status/.test(mig));
  ok("079: adds all 6 columns", ["verification_status", "verification_method", "verification_token", "verification_initiated_at", "verified_at", "verification_metadata"].every((c) => new RegExp("ADD COLUMN " + c).test(mig)));
  ok("079: no destructive statement", !/\b(DROP\s+TABLE|DROP\s+COLUMN|DELETE\s+FROM|TRUNCATE)\b/i.test(mig.replace(/--[^\n]*/g, "")));

  // Backfill fixture: a verified domain's link → verified; an unverified domain's link → stays unverified.
  db.exec(`INSERT INTO domains (id, user_id, domain, verification_status, verification_method, verified_at) VALUES ('d_ver','u_bf','ver.co.uk','verified','dns_txt','2026-06-01')`);
  db.exec(`INSERT INTO domains (id, user_id, domain, verification_status) VALUES ('d_unv','u_bf','unv.co.uk','unverified')`);
  db.exec(`INSERT INTO workspaces (id, name, owner_user_id) VALUES ('ws_bf_a','A','u_bf'),('ws_bf_b','B','u_bf')`);
  db.exec(`INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws_bf_a','d_ver'),('ws_bf_b','d_unv')`);
  // Run the exact backfill UPDATE from the migration.
  const backfill = mig.split(/UPDATE workspace_domains/)[1];
  db.exec("UPDATE workspace_domains" + backfill);
  const a = db.prepare("SELECT verification_status, verification_method, verified_at FROM workspace_domains WHERE workspace_id='ws_bf_a' AND domain_id='d_ver'").get();
  const b = db.prepare("SELECT verification_status FROM workspace_domains WHERE workspace_id='ws_bf_b' AND domain_id='d_unv'").get();
  eq("backfill: verified-domain link → verified", a.verification_status, "verified");
  eq("backfill: copies method", a.verification_method, "dns_txt");
  eq("backfill: unverified-domain link stays unverified", b.verification_status, "unverified");
}

// ── Seed users / workspaces / sessions for the live-endpoint tests ───────────
const tok = {};
async function seedUser(uid, email) {
  db.prepare("INSERT INTO users (id, email, email_verified) VALUES (?,?,1)").run(uid, email);
  const t = "tok_" + uid; tok[uid] = t;
  db.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES (?,?,?, datetime('now','+1 day'))").run("s_" + uid, uid, await hashToken(t));
}
function seedWs(wsId, owner) {
  db.prepare("INSERT INTO workspaces (id, name, owner_user_id) VALUES (?,?,?)").run(wsId, wsId, owner);
  db.prepare("INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (?,?, 'owner')").run(wsId, owner);
}
function seedDomain(id, uid, domain) { db.prepare("INSERT INTO domains (id, user_id, domain, verification_status) VALUES (?,?,?, 'unverified')").run(id, uid, domain); }
function link(wsId, domId, status) { db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id, verification_status) VALUES (?,?,?)").run(wsId, domId, status); }

await seedUser("u1", "u1@example.co.uk");
await seedUser("u2", "u2@example.co.uk");
// Same root domain (u1's record) linked to TWO of u1's workspaces: one verified, one not.
seedWs("ws_ver", "u1"); seedWs("ws_unv", "u1");
seedDomain("dom_u1", "u1", "shared.co.uk");
link("ws_ver", "dom_u1", "verified");
link("ws_unv", "dom_u1", "unverified");
// A different user's OWN record for the same root domain — independently unverified.
seedWs("ws_u2", "u2");
seedDomain("dom_u2", "u2", "shared.co.uk");
link("ws_u2", "dom_u2", "unverified");

const r2puts = [];
const env = {
  cybermeters_db: makeD1(db),
  cybermeters_reports: { get: async () => null, put: async (k) => { r2puts.push(k); return {}; }, head: async () => null, delete: async () => ({}), list: async () => ({ objects: [] }) },
  ALLOWED_ORIGIN: "https://app.cybermeters.com", APP_VERSION: "test",
};
const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };
const call = async (path, token, method = "GET", body) => {
  const res = await worker.default.fetch(new Request(`https://app.cybermeters.com${path}`, {
    method, headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  }), env, ctx);
  let json = {}; try { json = await res.json(); } catch { /* */ }
  return { status: res.status, body: json };
};
const scanCount = (wsId) => db.prepare("SELECT COUNT(*) n FROM scans WHERE workspace_id=?").get(wsId).n;

// ── 2. Unverified workspace-domain manual scan → 403, NO side effects ────────
{
  const before = { scans: scanCount("ws_unv"), r2: r2puts.length };
  const r = await call("/api/scan", tok.u1, "POST", { domain: "shared.co.uk", workspace_id: "ws_unv" });
  eq("unverified manual scan → 403", r.status, 403);
  eq("unverified → error code", r.body.error, "domain_verification_required");
  eq("unverified → exact customer-safe message", r.body.message, DOMAIN_VERIFICATION_REQUIRED.message);
  eq("no scan row created", scanCount("ws_unv"), before.scans);
  eq("no R2 placeholder created", r2puts.length, before.r2);
  eq("no telemetry row", db.prepare("SELECT COUNT(*) n FROM scan_module_telemetry").get().n, 0);
  eq("no managed case created", db.prepare("SELECT COUNT(*) n FROM managed_cases WHERE workspace_id='ws_unv'").get().n, 0);
}

// ── 3. Verified workspace-domain manual scan → allowed (scan row created) ────
{
  const before = scanCount("ws_ver");
  const r = await call("/api/scan", tok.u1, "POST", { domain: "shared.co.uk", workspace_id: "ws_ver" });
  ok("verified manual scan is NOT 403", r.status !== 403);
  ok("verified manual scan accepted (running/202)", r.status === 202 || r.status === 200);
  eq("verified → scan row created", scanCount("ws_ver"), before + 1);
}

// ── 4. Same root domain: verified workspace A allowed, unverified B blocked ──
{
  // ws_ver verified (allowed above), ws_unv unverified (blocked above) — same domain
  // string, same user. Proves verification in A does not authorize B.
  const r = await call("/api/scan", tok.u1, "POST", { domain: "shared.co.uk", workspace_id: "ws_unv" });
  eq("workspace B (unverified) still blocked while A verified", r.status, 403);
}

// ── 5. Cross-user same root domain → independently unverified (blocked) ──────
{
  const before = scanCount("ws_u2");
  const r = await call("/api/scan", tok.u2, "POST", { domain: "shared.co.uk", workspace_id: "ws_u2" });
  eq("cross-user same domain is independently unverified → 403", r.status, 403);
  eq("cross-user → no scan row", scanCount("ws_u2"), before);
}

// ── 6. Verification INITIATION writes the token to the EXACT link only ───────
{
  const r = await call("/api/domains/dom_u1/verification", tok.u1, "POST", { workspace_id: "ws_unv" });
  eq("init → 200", r.status, 200);
  eq("init → workspace_id echoed", r.body.workspace_id, "ws_unv");
  const target = db.prepare("SELECT verification_status, verification_token FROM workspace_domains WHERE workspace_id='ws_unv' AND domain_id='dom_u1'").get();
  ok("init: token stored on the target link", !!target.verification_token && target.verification_status === "pending");
  const other = db.prepare("SELECT verification_status, verification_token FROM workspace_domains WHERE workspace_id='ws_ver' AND domain_id='dom_u1'").get();
  eq("init: the OTHER workspace link is untouched (still verified)", other.verification_status, "verified");
  ok("init: other link has no pending token from this call", other.verification_token == null || other.verification_status === "verified");
  const legacy = db.prepare("SELECT verification_status FROM domains WHERE id='dom_u1'").get();
  eq("init: legacy domains row NOT mutated (read-only compat)", legacy.verification_status, "unverified");
}

// ── 7. Verify with no token on the link → 400 'No verification token found' ──
{
  const r = await call("/api/domains/dom_u2/verify", tok.u2, "POST", { workspace_id: "ws_u2" });
  eq("verify without a token → 400", r.status, 400);
  ok("verify → advisory message", /No verification token found/.test(r.body.error || ""));
}

// ── 8. isWorkspaceDomainVerified helper is exact + fails closed ──────────────
{
  ok("helper: verified link → true", (await isWorkspaceDomainVerified(env, "ws_ver", "dom_u1")) === true);
  ok("helper: unverified link → false", (await isWorkspaceDomainVerified(env, "ws_unv", "dom_u1")) === false);
  ok("helper: nonexistent link → false (fail closed)", (await isWorkspaceDomainVerified(env, "ws_ver", "nope")) === false);
  ok("helper: missing args → false", (await isWorkspaceDomainVerified(env, null, null)) === false);
}

// ── 9. Scheduled-scan path gates on the same helper (source wiring) ──────────
{
  const src = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "index.js"), "utf8");
  ok("scheduled scan imports the gate helper", /isWorkspaceDomainVerified/.test(src));
  ok("scheduled scan skips unverified before creating a scan row", /isWorkspaceDomainVerified\(env, schedule\.workspace_id, domainId\)/.test(src) && /\[scheduled-scan\] skipped/.test(src));
}

// ── 10. Auth still required before the gate (no oracle regression) ───────────
{
  const r = await call("/api/scan", null, "POST", { domain: "shared.co.uk", workspace_id: "ws_ver" });
  eq("unauthenticated scan → 401 (before gate)", r.status, 401);
}

console.log(`\ndomain-verification-gate: ${pass} passed, ${fail} failed`);
if (fail) { console.error("domain-verification-gate validation FAILED"); process.exit(1); }
console.log("domain-verification-gate validation passed");
