#!/usr/bin/env node
//
// Tenant alert-recipient safety — DB-backed, CI-blocking.
//
// Guards the invariant that a customer's alert reaches THAT customer's verified
// audience, or nobody. Regression cover for the defect where every tenant's
// asset-change alert email was delivered to the operator inbox (ALERT_EMAIL_TO)
// because sendAlertEmail was called with no recipients and silently fell back.
//
// Proves, against real schema+migrations:
//   1. no cross-tenant recipient leakage
//   2. unverified users are excluded
//   3. soft-deleted workspaces receive nothing
//   4. no-recipient cases skip safely (no send, honest reason, no retry churn)
//   5. the operator/global fallback is NEVER used for a tenant alert
//   6. a lookup failure is never recorded as "this workspace has no recipients"
//
// Node 24+.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href;
const { resolveWorkspaceAlertRecipients, sendTenantAlertEmail, sendAlertEmail } = await import(eng("alerts.js"));
const { deliveryOutcome } = await import(eng("asset-alert-delivery.js"));
// The canonical retry vocabulary — asserted against rather than restated, so this
// file cannot drift from the engine's own definition of what may be retried.
const { RETRYABLE_REASONS } = await import(eng("managed-alerts.js"));

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* additive drift tolerated */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}

function makeD1(db) {
  const wrap = (sql, args) => ({
    __sql: sql, __args: args,
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
}

const db = buildDb();

// ── Seed: two live tenants + one soft-deleted + one with no verified audience ──
// This file tests WHO may receive an alert (tenant scope, verification,
// soft-delete). Entitlement is validate-alert-trust-foundation.js's job — but it
// is now a precondition here, because sendTenantAlertEmail refuses an unentitled
// workspace before it ever resolves recipients.
//
// Every workspace below is therefore entitled via a `subscriptions` row: that is
// what getUserPlan actually reads. `users.plan` is stale compatibility data and is
// deliberately NOT the source of truth (see validate-email-entitlement.js).
//
// Worth recording: this fixture seeded plan 'free' and every assertion still
// passed, because sendTenantAlertEmail had no entitlement check at all. The suite
// was quietly encoding the bypass — a free workspace being emailed was the
// expected result.
function user(id, email, verified) {
  db.prepare("INSERT INTO users (id, email, name, plan, created_at) VALUES (?, ?, ?, 'free', datetime('now'))").run(id, email, id);
  db.prepare("UPDATE users SET email_verified = ? WHERE id = ?").run(verified ? 1 : 0, id);
  // Mirrors what the Stripe webhook writes; getUserPlan reads subscriptions by
  // owner_user_id and treats a missing/non-active row as free.
  db.prepare(`INSERT INTO subscriptions
      (id, owner_user_id, plan, subscription_status, status, current_period_end, created_at, updated_at)
    VALUES (?, ?, 'professional', 'active', 'active', datetime('now', '+30 days'), datetime('now'), datetime('now'))`)
    .run(`sub_${id}`, id);
}
function workspace(ws, ownerId, { deleted = false } = {}) {
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES (?, ?, ?)").run(ws, ownerId, ws);
  if (deleted) db.prepare("UPDATE workspaces SET deleted_at = datetime('now') WHERE id = ?").run(ws);
}
function member(ws, userId, role) {
  db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?, ?, ?, ?)")
    .run(`${ws}_${userId}`, ws, userId, role);
}

user("u_a_owner", "owner-a@example.com", true);
user("u_a_admin", "admin-a@example.com", true);
user("u_a_unver", "unverified-a@example.com", false);   // must never be mailed
user("u_a_member", "member-a@example.com", true);        // 'member' role — not an alert recipient
user("u_b_owner", "owner-b@example.com", true);          // the OTHER tenant
user("u_dead", "owner-dead@example.com", true);
user("u_none", "unverified-only@example.com", false);

workspace("ws_a", "u_a_owner");
member("ws_a", "u_a_owner", "owner");
member("ws_a", "u_a_admin", "admin");
member("ws_a", "u_a_unver", "admin");
member("ws_a", "u_a_member", "member");

workspace("ws_b", "u_b_owner");
member("ws_b", "u_b_owner", "owner");

workspace("ws_dead", "u_dead", { deleted: true });
member("ws_dead", "u_dead", "owner");

workspace("ws_none", "u_none");   // owner exists but is unverified
member("ws_none", "u_none", "owner");

const env = {
  cybermeters_db: makeD1(db),
  ALERT_EMAIL_TO: "operator@cybermeters.example",   // the operator inbox a tenant alert must NEVER reach
  ALERT_EMAIL_FROM: "alerts@cybermeters.com",       // must satisfy resolveEmailSender's allow-list
  RESEND_API_KEY: "",
};

// ── Email capture: record every outbound recipient set ────────────────────────
const realFetch = globalThis.fetch;
function captureEmails() {
  const sent = [];
  globalThis.fetch = async (url, init) => {
    if (String(url).includes("resend.com")) {
      let body = {};
      try { body = JSON.parse(init?.body || "{}"); } catch { /* non-JSON body */ }
      sent.push({ to: body.to || [], subject: body.subject });
      return new Response(JSON.stringify({ id: "email_1" }), { status: 200, headers: { "content-type": "application/json" } });
    }
    return new Response("{}", { status: 200 });
  };
  return sent;
}
const withKey = { ...env, RESEND_API_KEY: "re_test" };

// ── 1. Recipient resolution: tenant scope + verified-only ────────────────────
{
  const a = await resolveWorkspaceAlertRecipients(env, "ws_a");
  ok("ws_a resolves ok", a.ok === true);
  eq("ws_a: only verified owner+admin, sorted", [...a.emails].sort(), ["admin-a@example.com", "owner-a@example.com"]);
  ok("unverified admin is excluded", !a.emails.includes("unverified-a@example.com"));
  ok("plain 'member' role is not an alert recipient", !a.emails.includes("member-a@example.com"));
  ok("no cross-tenant leakage: ws_a never sees ws_b's owner", !a.emails.includes("owner-b@example.com"));

  const b = await resolveWorkspaceAlertRecipients(env, "ws_b");
  eq("ws_b resolves only its own owner", b.emails, ["owner-b@example.com"]);
  ok("no cross-tenant leakage: ws_b never sees ws_a", !b.emails.some((e) => e.endsWith("-a@example.com")));
}

// ── 2. Soft-deleted workspace is nonexistent ─────────────────────────────────
{
  const d = await resolveWorkspaceAlertRecipients(env, "ws_dead");
  ok("soft-deleted workspace resolves ok (not an error)", d.ok === true);
  eq("soft-deleted workspace has no recipients", d.emails, []);
  eq("soft-deleted workspace reason", d.reason, "no_verified_recipient");
}

// ── 3. Unknown workspace fails closed (non-enumerating: same shape as empty) ──
{
  const u = await resolveWorkspaceAlertRecipients(env, "ws_does_not_exist");
  eq("unknown workspace has no recipients", u.emails, []);
  eq("unknown workspace looks identical to an empty one", u.reason, "no_verified_recipient");
}

// ── 4. THE REGRESSION: a tenant alert never reaches the operator inbox ────────
{
  const sent = captureEmails();
  const r = await sendTenantAlertEmail(withKey, "ws_a", { subject: "Asset change", text: "t", html: "<p>t</p>" });
  globalThis.fetch = realFetch;
  ok("tenant alert sent to the workspace's own audience", r.sent === true);
  eq("tenant alert recipients are exactly ws_a's verified owner+admin",
     [...(sent[0]?.to || [])].sort(), ["admin-a@example.com", "owner-a@example.com"]);
  ok("operator inbox is NEVER a tenant recipient",
     !sent.some((m) => (m.to || []).includes("operator@cybermeters.example")));
  ok("no other tenant's address appears", !sent.some((m) => (m.to || []).includes("owner-b@example.com")));
}

// ── 5. No verified audience → skip safely, never redirect ────────────────────
{
  const sent = captureEmails();
  const r = await sendTenantAlertEmail(withKey, "ws_none", { subject: "Asset change", text: "t", html: "<p>t</p>" });
  globalThis.fetch = realFetch;
  ok("no-recipient workspace: nothing sent", r.sent === false);
  eq("no-recipient workspace: honest reason", r.reason, "no_verified_recipient");
  eq("no-recipient workspace: ZERO outbound emails (no operator fallback)", sent.length, 0);
}
{
  const sent = captureEmails();
  const r = await sendTenantAlertEmail(withKey, "ws_dead", { subject: "Asset change", text: "t", html: "<p>t</p>" });
  globalThis.fetch = realFetch;
  ok("soft-deleted workspace: nothing sent", r.sent === false);
  eq("soft-deleted workspace: ZERO outbound emails", sent.length, 0);
}

// ── 6. A lookup failure is not "this workspace has no recipients" ────────────
{
  const brokenEnv = {
    ...withKey,
    cybermeters_db: { prepare() { return { bind() { return this; }, async all() { throw new Error("D1_ERROR: connection lost"); } }; } },
  };
  const resolved = await resolveWorkspaceAlertRecipients(brokenEnv, "ws_a");
  ok("D1 error → ok:false (not an empty audience)", resolved.ok === false);
  eq("D1 error reason is distinct from a real empty audience", resolved.reason, "recipient_lookup_failed");
  ok("D1 error reason is NOT the no-recipient reason", resolved.reason !== "no_verified_recipient");

  const sent = captureEmails();
  const r = await sendTenantAlertEmail(brokenEnv, "ws_a", { subject: "s", text: "t", html: "<p>t</p>" });
  globalThis.fetch = realFetch;
  ok("D1 error: nothing sent", r.sent === false);
  eq("D1 error: no operator fallback", sent.length, 0);
  // The reason is now `entitlement_lookup_failed` rather than
  // `recipient_lookup_failed`: with D1 down, the FIRST thing sendTenantAlertEmail
  // cannot establish is the plan, and it says so precisely instead of blaming the
  // recipient lookup it never reached. The assertion this test exists for is
  // unchanged and is checked explicitly below — the reason must be RETRYABLE and
  // must never be a permanent fact about the customer.
  eq("D1 error: retryable reason surfaced", r.reason, "entitlement_lookup_failed");
  ok("D1 error: the reason is retryable, not terminal", RETRYABLE_REASONS.has(r.reason));
  ok("D1 error: never recorded as a permanent fact about the customer",
     r.reason !== "feature_not_entitled" && r.reason !== "no_verified_recipient");
}

// ── 7. Delivery outcome mapping (retry only for transient failures) ──────────
{
  eq("sent → sent", deliveryOutcome({ sent: true }), { status: "sent", error: null });
  eq("no verified recipient → skipped (never retried forever)",
     deliveryOutcome({ sent: false, reason: "no_verified_recipient" }), { status: "skipped", error: "no_verified_recipient" });
  eq("transient send failure stays retryable",
     deliveryOutcome({ sent: false, reason: "resend_500" }), { status: "failed", error: "resend_500" });
  eq("lookup failure stays retryable",
     deliveryOutcome({ sent: false, reason: "recipient_lookup_failed" }), { status: "failed", error: "recipient_lookup_failed" });
}

// ── 8. Structural guard: no tenant engine may use the operator-fallback sender ─
{
  const enginesDir = path.join(root, "workers", "scan-api", "src", "engines");
  const offenders = [];
  for (const f of fs.readdirSync(enginesDir).filter((f) => f.endsWith(".js"))) {
    const src = fs.readFileSync(path.join(enginesDir, f), "utf8");
    // alerts.js defines it (ops-only); no engine may CALL it.
    const calls = src.split("\n").filter((l) => /\bsendAlertEmail\s*\(/.test(l) && !/^export async function sendAlertEmail/.test(l.trim()));
    if (calls.length > 0) offenders.push(`${f}: ${calls[0].trim().slice(0, 80)}`);
  }
  eq("no engine calls the operator-fallback sender", offenders, []);
  ok("sendAlertEmail is still exported for ops use", typeof sendAlertEmail === "function");
}

console.log(`\nalert-recipients: ${pass} passed, ${fail} failed`);
if (fail > 0) { console.error("alert-recipients validation FAILED"); process.exit(1); }
console.log("alert-recipients validation passed");
