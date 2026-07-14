#!/usr/bin/env node
//
// Email Protection entitlement — behavioural proof that hosted-DMARC policy
// management is gated by the CANONICAL effective plan (subscriptions table, via
// getEffectivePlan), never the stale never-synced users.plan column. Drives the
// real getEffectivePlan + planAllowsHostedPolicyManagement against a node:sqlite
// DB. A static contract also asserts the route delegates and no longer reads
// users.plan for authorization. Node 24+. CI-blocking.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href);
const { getEffectivePlan } = await eng("entitlements.js");
const { planAllowsHostedPolicyManagement } = await eng("hosted-dmarc.js");

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };

function makeD1(db) {
  const wrap = (sql, args) => ({
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all:   async () => ({ results: db.prepare(sql).all(...args) }),
    run:   async () => { const r = db.prepare(sql).run(...args); return { meta: { changes: r.changes } }; },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
}
function db0() {
  const db = new DatabaseSync(":memory:");
  db.exec(`
    CREATE TABLE users (id TEXT PRIMARY KEY, plan TEXT);
    CREATE TABLE subscriptions (owner_user_id TEXT, plan TEXT, subscription_status TEXT, current_period_end TEXT, payment_failed_at TEXT, created_at TEXT, updated_at TEXT);
  `);
  return db;
}
const future = new Date(Date.now() + 30 * 864e5).toISOString();
const past   = new Date(Date.now() - 30 * 864e5).toISOString();
const now    = new Date().toISOString();

// 1. Paid subscription + STALE users.plan='free' → effective = paid → policy allowed.
{
  const db = db0();
  db.prepare("INSERT INTO users VALUES (?,?)").run("u1", "free");            // stale, permanently 'free'
  db.prepare("INSERT INTO subscriptions (owner_user_id, plan, subscription_status, current_period_end, created_at) VALUES (?,?,?,?,?)")
    .run("u1", "starter", "active", future, now);
  const env = { cybermeters_db: makeD1(db) };
  const plan = await getEffectivePlan("u1", env);
  ok("paid subscription overrides stale users.plan (effective = starter)", plan === "starter", plan);
  ok("paid effective plan → hosted-DMARC policy management ALLOWED", planAllowsHostedPolicyManagement(plan) === true);
  // The stale column must NOT be what gates it.
  ok("stale users.plan='free' cannot deny a genuinely paid owner", planAllowsHostedPolicyManagement("free") === false && planAllowsHostedPolicyManagement(plan) === true);
}

// 2. Genuinely free (no subscription) → effective free → policy denied.
{
  const db = db0();
  db.prepare("INSERT INTO users VALUES (?,?)").run("u2", "free");
  const env = { cybermeters_db: makeD1(db) };
  const plan = await getEffectivePlan("u2", env);
  ok("no subscription → effective free", plan === "free");
  ok("free effective plan → policy management DENIED", planAllowsHostedPolicyManagement(plan) === false);
}

// 3. Cancelled / expired subscription → follows effective state (free), not a stale paid grant.
{
  const db = db0();
  db.prepare("INSERT INTO users VALUES (?,?)").run("u3", "professional");    // stale paid value
  db.prepare("INSERT INTO subscriptions (owner_user_id, plan, subscription_status, current_period_end, created_at) VALUES (?,?,?,?,?)")
    .run("u3", "professional", "canceled", past, now);
  const env = { cybermeters_db: makeD1(db) };
  const plan = await getEffectivePlan("u3", env);
  ok("cancelled subscription → effective free (no stale paid grant)", plan === "free", plan);
  ok("cancelled owner → policy management DENIED", planAllowsHostedPolicyManagement(plan) === false);
}

// 4. Static contract — the route resolves via getEffectivePlan and no longer reads
//    users.plan for the policy gate.
{
  const src = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "routes", "email-protection.js"), "utf8");
  ok("email-protection delegates to getEffectivePlan", /getEffectivePlan\(/.test(src));
  ok("email-protection no longer reads users.plan for the policy gate", !/SELECT u\.plan FROM workspaces/.test(src));
}

console.log(`\nemail-entitlement: ${pass} passed, ${fail} failed`);
if (fail) { console.error("email-entitlement validation FAILED"); process.exit(1); }
console.log("email-entitlement validation passed");
