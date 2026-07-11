#!/usr/bin/env node
//
// Lifecycle-email regression: sendLifecycleEmail must record each send in
// lifecycle_email_events, dedupe repeat sends for the same scope, mark failures
// so the hourly cron can retry them, and never send to an unverified address.
// retryFailedLifecycleEmails must re-send failed rows but never touch
// lifecycle_payment_failed. Delivery (Resend fetch) is mocked so success/failure
// is deterministic. Requires Node 24+ (node:sqlite). CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const lib = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib", "lifecycle-email.js")).href);
const { sendLifecycleEmail, retryFailedLifecycleEmails, lifecycleDedupeKey, LIFECYCLE_TYPES, buildLifecycleEmail } = lib;

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

// ── Mock Resend delivery via globalThis.fetch ────────────────────────────────
let deliverOk = true;
globalThis.fetch = async (url) => {
  if (String(url).includes("resend.com")) {
    if (!deliverOk) throw new Error("network down");
    return { ok: true, status: 200, json: async () => ({ id: "re_mock" }) };
  }
  throw new Error("network disabled");
};
AbortSignal.timeout = () => undefined;

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering no-ops */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  db.prepare("INSERT INTO users (id, email, email_verified) VALUES ('usr_ok','owner@example.co.uk',1)").run();
  db.prepare("INSERT INTO users (id, email, email_verified) VALUES ('usr_unv','pending@example.co.uk',0)").run();
  return db;
}
function makeD1(db) {
  const wrap = (sql, args) => ({
    first: async () => db.prepare(sql).get(...args) ?? null,
    all: async () => ({ results: db.prepare(sql).all(...args) }),
    run: async () => { const r = db.prepare(sql).run(...args); return { meta: { changes: r.changes } }; },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
}

const db = buildDb();
const env = {
  cybermeters_db: makeD1(db),
  RESEND_API_KEY: "re_test", HELLO_EMAIL_FROM: "hello@cybermeters.com",
  FRONTEND_URL: "https://app.cybermeters.com", ALLOWED_ORIGIN: "https://app.cybermeters.com",
};
const rowsFor = (type) => db.prepare("SELECT id, status, type FROM lifecycle_email_events WHERE type = ?").all(type);
const statusOf = (id) => db.prepare("SELECT status FROM lifecycle_email_events WHERE id = ?").get(id)?.status;

// ── 1. Every lifecycle type builds a real, non-empty email ───────────────────
for (const type of LIFECYCLE_TYPES) {
  const m = buildLifecycleEmail(type, { origin: env.FRONTEND_URL, wsName: "Acme", domain: "acme.co.uk" });
  ok(`type ${type}: builds subject/text/html`, m && m.subject && m.text && m.html && m.text.length > 10);
}
ok("exactly the 6 documented lifecycle types exist", LIFECYCLE_TYPES.size === 6);

// ── 2. A verified send records a 'sent' row ──────────────────────────────────
deliverOk = true;
const r1 = await sendLifecycleEmail(env, { type: "lifecycle_welcome", user_id: "usr_ok" });
ok("welcome send returns sent", r1.sent === true);
const welcomeRows = rowsFor("lifecycle_welcome");
ok("welcome wrote exactly one row", welcomeRows.length === 1);
ok("welcome row is 'sent'", welcomeRows[0]?.status === "sent");

// ── 3. Dedupe: a repeat for the same scope is skipped, no second row ──────────
const r1b = await sendLifecycleEmail(env, { type: "lifecycle_welcome", user_id: "usr_ok" });
ok("repeat welcome is deduped", r1b.skipped === "duplicate");
ok("no duplicate welcome row written", rowsFor("lifecycle_welcome").length === 1);

// ── 4. A delivery failure records a 'failed' row (retryable) ──────────────────
deliverOk = false;
const r2 = await sendLifecycleEmail(env, { type: "lifecycle_domain_added", workspace_id: null, user_id: "usr_ok", domain: "acme.co.uk" });
ok("failed delivery returns sent:false", r2.sent === false);
const domRows = rowsFor("lifecycle_domain_added");
ok("failed send wrote a row", domRows.length === 1);
ok("failed send row is 'failed'", domRows[0]?.status === "failed");
const failedRowId = domRows[0]?.id;

// ── 5. Unverified recipient is never emailed ─────────────────────────────────
deliverOk = true;
const r3 = await sendLifecycleEmail(env, { type: "lifecycle_welcome", user_id: "usr_unv" });
ok("unverified recipient is skipped", r3.skipped === "no_verified_email");

// ── 6. The cron retry re-sends the failed row (now that delivery recovered) ──
deliverOk = true;
await retryFailedLifecycleEmails(env);
ok("retry flips the failed row to 'sent'", statusOf(failedRowId) === "sent");

// ── 7. Retry must NEVER touch lifecycle_payment_failed ───────────────────────
db.prepare(`INSERT INTO lifecycle_email_events (id, user_id, type, dedupe_key, status, created_at)
            VALUES ('life_pf','usr_ok','lifecycle_payment_failed','lifecycle_payment_failed:inv_1','failed', datetime('now'))`).run();
deliverOk = true;
await retryFailedLifecycleEmails(env);
ok("payment_failed row is excluded from retry (stays 'failed')", statusOf("life_pf") === "failed");

// ── 8. Dedupe keys are scoped as documented (pure) ───────────────────────────
ok("welcome key is per-user", lifecycleDedupeKey({ type: "lifecycle_welcome", user_id: "u1" }) === "lifecycle_welcome:u1");
ok("domain_added key is per-workspace+domain", lifecycleDedupeKey({ type: "lifecycle_domain_added", workspace_id: "w1", domain: "A.CO.UK" }) === "lifecycle_domain_added:w1:a.co.uk");
ok("payment_failed key is per-invoice ref", lifecycleDedupeKey({ type: "lifecycle_payment_failed", ref: "inv_9" }) === "lifecycle_payment_failed:inv_9");

console.log(`\nEmail lifecycle: ${pass}/${pass + fail} passed`);
if (fail) { console.error("email-lifecycle validation FAILED"); process.exit(1); }
console.log("email-lifecycle validation passed");
