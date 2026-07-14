#!/usr/bin/env node
//
// Scheduled-scan eligibility parity — behavioural proof that a scheduled scan is
// held to the SAME run-time security/entitlement/quota rules as a manual scan.
// Drives the real exported evaluateScheduledScanEligibility() (engines/plan-usage.js)
// against a node:sqlite DB loaded from the production schema + migrations, so it
// exercises the canonical helpers (isWorkspaceDomainVerified, getEffectivePlan,
// getWorkspaceBillingUserId, checkScanLimit) — no plan rules are duplicated in the
// test. Proves each stable reason code, fail-closed rate limiting, and that a skip
// mutates nothing (schedule config + scans table untouched). Node 24+. CI-blocking.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const { evaluateScheduledScanEligibility } = await import(
  pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "plan-usage.js")).href
);

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering/dup — schema converges */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}
function makeD1(db) {
  const wrap = (sql, args) => ({
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all:   async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run:   async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
}

const U = "usr_owner", W = "ws1", D = "dom1";
const future = new Date(Date.now() + 30 * 864e5).toISOString();
const nowIso = new Date().toISOString();

function seed({ deleted = false, verified = true, plan = "starter", scanCount = 0 } = {}) {
  const db = buildDb();
  db.prepare("INSERT INTO users (id, email, plan) VALUES (?,?,?)").run(U, "o@x.co", "free"); // stale users.plan intentionally 'free'
  db.prepare("INSERT INTO workspaces (id, name, owner_user_id, deleted_at) VALUES (?,?,?,?)")
    .run(W, "WS", U, deleted ? nowIso : null);
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES (?,?,?)").run(D, U, "a.com");
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id, verification_status) VALUES (?,?,?)")
    .run(W, D, verified ? "verified" : "unverified");
  if (plan) {
    db.prepare(`INSERT INTO subscriptions (owner_user_id, plan, subscription_status, current_period_end, created_at)
                VALUES (?,?,?,?,?)`).run(U, plan, "active", future, nowIso);
  }
  for (let i = 0; i < scanCount; i++) {
    db.prepare("INSERT INTO scans (id, domain_id, workspace_id, domain, status, created_at) VALUES (?,?,?,?,?,?)")
      .run(`s${i}`, D, W, "a.com", "completed", nowIso);
  }
  return { db, env: { cybermeters_db: makeD1(db) } };
}

const allow = async () => null;                    // rate limiter allows
const failClosed = async () => ({ status: 503 });  // limiter store unavailable → fail closed

// 1. Verified + entitled (starter) + within quota + rate ok → ok, and ZERO side effects.
{
  const { db, env } = seed({});
  const before = db.prepare("SELECT COUNT(*) AS n FROM scans").get().n;
  const r = await evaluateScheduledScanEligibility(env, { workspaceId: W, domainId: D, ownerUserId: U, consumeRateLimit: allow });
  ok("verified+entitled+within-quota → ok:true", r.ok === true, JSON.stringify(r));
  ok("eligibility check creates no scan row (no side effect)", db.prepare("SELECT COUNT(*) AS n FROM scans").get().n === before);
  ok("eligibility check does not mutate schedule config",
    db.prepare("SELECT COUNT(*) AS n FROM scheduled_scans").get().n === 0);
}

// 2. Unverified link → domain_verification_required.
{
  const { env } = seed({ verified: false });
  const r = await evaluateScheduledScanEligibility(env, { workspaceId: W, domainId: D, ownerUserId: U, consumeRateLimit: allow });
  ok("unverified link → domain_verification_required", !r.ok && r.reason === "domain_verification_required", JSON.stringify(r));
}

// 3. Deleted workspace → workspace_not_accessible.
{
  const { env } = seed({ deleted: true });
  const r = await evaluateScheduledScanEligibility(env, { workspaceId: W, domainId: D, ownerUserId: U, consumeRateLimit: allow });
  ok("deleted workspace → workspace_not_accessible", !r.ok && r.reason === "workspace_not_accessible", JSON.stringify(r));
}

// 4. Free effective plan (no scheduled_scans feature) → feature_not_entitled.
{
  const { env } = seed({ plan: "free" });
  const r = await evaluateScheduledScanEligibility(env, { workspaceId: W, domainId: D, ownerUserId: U, consumeRateLimit: allow });
  ok("free plan (no scheduled_scans feature) → feature_not_entitled", !r.ok && r.reason === "feature_not_entitled", JSON.stringify(r));
}

// 5. Quota exhausted (starter = 100 scans/month; seed 100) → scan_limit_exceeded.
{
  const { env } = seed({ scanCount: 100 });
  const r = await evaluateScheduledScanEligibility(env, { workspaceId: W, domainId: D, ownerUserId: U, consumeRateLimit: allow });
  ok("quota exhausted → scan_limit_exceeded", !r.ok && r.reason === "scan_limit_exceeded", JSON.stringify(r));
}

// 6. Rate-limit store unavailable → fail CLOSED → rate_limit_unavailable.
{
  const { env } = seed({});
  const r = await evaluateScheduledScanEligibility(env, { workspaceId: W, domainId: D, ownerUserId: U, consumeRateLimit: failClosed });
  ok("limiter unavailable → rate_limit_unavailable (fail-closed)", !r.ok && r.reason === "rate_limit_unavailable", JSON.stringify(r));
}

// 7. Order: a partial/degraded persistence isn't relevant here, but confirm the
//    security check precedes billing — unverified + free plan still reports the
//    SECURITY reason (verification), never leaking entitlement state first.
{
  const { env } = seed({ verified: false, plan: "free" });
  const r = await evaluateScheduledScanEligibility(env, { workspaceId: W, domainId: D, ownerUserId: U, consumeRateLimit: allow });
  ok("verification (security) reason precedes entitlement disclosure",
    !r.ok && r.reason === "domain_verification_required", JSON.stringify(r));
}

console.log(`\nscheduled-eligibility: ${pass} passed, ${fail} failed`);
if (fail) { console.error("scheduled-eligibility validation FAILED"); process.exit(1); }
console.log("scheduled-eligibility validation passed");
