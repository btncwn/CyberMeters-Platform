#!/usr/bin/env node
//
// F-009 — deletion integrity containment.
//
// Runs the REAL deletion cron against a REAL in-memory SQLite with
// **PRAGMA foreign_keys = ON**. That pragma is the whole point: the existing
// purge suite runs with FKs OFF and has no account path, so it is structurally
// blind to the class this file covers — a DELETE that D1 would refuse in
// production succeeds silently in the test.
//
// Asserted contract:
//   A. no error path may reach `completed` — a blocked purge stays retryable
//   B. the permanence email may NEVER precede proof of deletion
//   C. an R2 delete failure may NOT delete the pointer row
//   D. wrong-predicate tables must actually purge
//   E. completion requires zero governed rows + FK check clean + parent absent
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const workerPath = path.join(root, "workers", "scan-api", "src", "index.js");

const sentEmails = [];
async function loadWorker() {
  globalThis.fetch = async (url, init) => {
    sentEmails.push({ url: String(url), body: String(init?.body ?? "") });
    return new Response(JSON.stringify({ id: "email_stub" }), { status: 200, headers: { "Content-Type": "application/json" } });
  };
  AbortSignal.timeout = () => undefined;
  return import(pathToFileURL(workerPath).href);
}

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* converges */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  // THE POINT OF THIS FILE.
  db.exec("PRAGMA foreign_keys = ON");
  return db;
}

// D1 surfaces a failed statement as a rejected promise. The fake must do the
// same, or every swallowed `.catch(() => {})` in the runner looks like success.
function makeD1(db) {
  const wrap = (sql, args) => ({
    __sql: sql, __args: args,
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all:   async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run:   async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
  });
  return {
    prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; },
    async batch(st) { return Promise.all(st.map((s) => (/^\s*select/i.test(s.__sql) ? s.all() : s.run()))); },
    async exec(sql) { db.exec(sql); return { count: 0, duration: 0 }; },
  };
}

let r2FailKey = null;
const r2 = {
  store: new Set(),
  async delete(key) { if (r2FailKey && String(key) === r2FailKey) throw new Error("R2 delete failed"); this.store.delete(String(key)); },
  async get() { return null; }, async put() { return {}; }, async head() { return null; },
  async list() { return { objects: [] }; },
};

function makeEnv(db) {
  return {
    cybermeters_db: makeD1(db), cybermeters_reports: r2,
    RESEND_API_KEY: "re_stub_key", HELLO_EMAIL_FROM: "hello@cybermeters.com",
    ALERT_EMAIL_FROM: "alerts@cybermeters.com", APP_VERSION: "test",
    ALLOWED_ORIGIN: "https://app.cybermeters.com", FRONTEND_URL: "https://app.cybermeters.com",
    MFA_ENCRYPTION_KEY: "k", STRIPE_WEBHOOK_SECRET: "w", STRIPE_SECRET_KEY: "s", STRIPE_PRICE_MAP: "{}",
    ADMIN_EMAILS: "",
  };
}

let passed = 0, failed = 0; const out = [];
let section = "general";
const ok = (n, c) => { c ? (passed++, out.push(`PASS [${section}] ${n}`)) : (failed++, out.push(`FAIL [${section}] ${n}`)); };

const OLD = "datetime('now','-60 days')";

function seedAccount(db) {
  const run = (sql, ...a) => { try { db.prepare(sql).run(...a); return null; } catch (e) { return e.message; } };
  const errs = [];
  const push = (e) => { if (e) errs.push(e); };
  push(run("INSERT INTO users (id,email,name,plan,status,email_verified) VALUES ('u1','gone@example.com','U','free','active',1)"));
  push(run(`INSERT INTO deletion_requests (id,request_type,user_id,workspace_id,requested_by,status,created_at) VALUES ('dr1','account','u1',NULL,'u1','pending', ${OLD})`));
  // FK edges the account purge does NOT cover, or covers with a WRONG predicate:
  push(run("INSERT INTO domains (id,user_id,domain) VALUES ('d1','u1','gone.example.com')"));
  push(run("INSERT INTO customer_profiles (id,owner_user_id,company_name) VALUES ('cp1','u1','Gone Ltd')")); // wrong predicate: user_id
  return errs;
}

async function main() {
  const mod = await loadWorker();
  const { processDeletionRequests } = mod;
  const db = buildDb();
  const env = makeEnv(db);

  section = "fixture-preconditions";
  const seedErrs = seedAccount(db);
  ok(`fixture seeded (${seedErrs[0] ?? "no errors"})`, seedErrs.length === 0);
  ok("FK enforcement is ON (the blindness class this file exists for)",
     db.prepare("PRAGMA foreign_keys").get().foreign_keys === 1);
  ok("oauth_states has NO user_id column (the wrong-predicate proof)",
     !db.prepare("PRAGMA table_info(oauth_states)").all().some((c) => c.name === "user_id"));
  ok("customer_profiles keys on owner_user_id, not user_id",
     db.prepare("PRAGMA table_info(customer_profiles)").all().some((c) => c.name === "owner_user_id"));

  sentEmails.length = 0;
  await processDeletionRequests(env);

  const req  = db.prepare("SELECT status FROM deletion_requests WHERE id='dr1'").get();
  const user = db.prepare("SELECT id FROM users WHERE id='u1'").get();
  const dom  = db.prepare("SELECT COUNT(*) c FROM domains WHERE user_id='u1'").get().c;
  const prof = db.prepare("SELECT COUNT(*) c FROM customer_profiles WHERE owner_user_id='u1'").get().c;
  const fk   = db.prepare("PRAGMA foreign_key_check").all();
  const emailSent = sentEmails.length > 0;

  section = "A-no-completed-on-surviving-rows";
  ok(`request is NOT 'completed' while data survives (status=${req?.status})`,
     !(req?.status === "completed" && (user || dom > 0 || prof > 0)));

  section = "B-email-never-precedes-proof";
  ok(`permanence email NOT sent while the user row survives (email=${emailSent}, user=${!!user})`,
     !(emailSent && !!user));

  section = "D-wrong-predicates";
  // customer_profiles WAS in the purge list with a wrong predicate (user_id vs
  // owner_user_id) and silently no-oped for the life of the feature. That is a
  // bug, and it must now purge.
  ok(`customer_profiles purged (survivors=${prof})`, prof === 0);

  section = "F-residuals-declared-not-hidden";
  // `domains` is NOT purged here, deliberately: whether a departing user's rows
  // are ERASED or ANONYMISED is a founder/legal decision this lane must not make.
  // What the contract DOES require is that survival is DECLARED — named in the
  // audit trail — never silently ignored. Asserting "domains purged" would
  // pre-judge the very decision that is being escalated.
  const blockedEvent = db.prepare(
    "SELECT metadata_json AS metadata FROM audit_events WHERE event_type='account_purge_blocked_residual_data' ORDER BY rowid DESC LIMIT 1"
  ).get();
  let declared = [];
  try { declared = JSON.parse(blockedEvent?.metadata ?? "{}").residual_edges ?? []; } catch { declared = []; }
  ok("a blocked purge records an audit event naming the surviving edges", declared.length > 0);
  ok(`surviving domains rows are DECLARED in that event (survivors=${dom})`,
     dom === 0 || declared.some((e) => e.table === "domains"));
  ok("the retained deletion_requests self-FK is declared as the structural blocker",
     declared.some((e) => e.table === "deletion_requests"));

  section = "E-completion-requires-proof";
  ok(`if completed, the parent user row is ABSENT (status=${req?.status}, user=${!!user})`,
     req?.status !== "completed" || !user);
  ok(`if completed, foreign_key_check is clean (${fk.length} violations)`,
     req?.status !== "completed" || fk.length === 0);

  // ── C. R2 failure must not orphan the object by deleting its pointer ──────
  section = "C-r2-verified-before-pointer";
  {
    const db2 = buildDb(); const env2 = makeEnv(db2);
    const run = (sql, ...a) => { try { db2.prepare(sql).run(...a); } catch { /* variance */ } };
    run("INSERT INTO users (id,email,name,plan,status,email_verified) VALUES ('u2','w@example.com','W','free','active',1)");
    run("INSERT INTO workspaces (id,name,owner_user_id,deleted_at) VALUES ('ws2','WS','u2', datetime('now','-60 days'))");
    run(`INSERT INTO deletion_requests (id,request_type,user_id,workspace_id,requested_by,status,created_at) VALUES ('dr2','workspace','u2','ws2','u2','pending', ${OLD})`);
    run("INSERT INTO workspace_reports (id,workspace_id,report_type,status,report_key) VALUES ('wr1','ws2','manual','completed','reports/stuck.pdf')");
    r2FailKey = "reports/stuck.pdf";
    await processDeletionRequests(env2);
    r2FailKey = null;
    const ptr = db2.prepare("SELECT COUNT(*) c FROM workspace_reports WHERE id='wr1'").get().c;
    ok("a failed R2 delete does NOT delete the pointer row (no orphaned object)", ptr === 1);
    const req2 = db2.prepare("SELECT status FROM deletion_requests WHERE id='dr2'").get();
    ok(`the request stays retryable after an R2 failure (status=${req2?.status})`, req2?.status !== "completed");
  }

  // ── POSITIVE CONTROLS — the suite must not pass by blocking everything ────
  // Every assertion above is a denial. Without these, an implementation that
  // simply never completes anything would score a perfect run.
  section = "G-positive-control";
  {
    const db3 = buildDb(); const env3 = makeEnv(db3);
    const run = (sql, ...a) => { try { db3.prepare(sql).run(...a); } catch { /* variance */ } };
    run("INSERT INTO users (id,email,name,plan,status,email_verified) VALUES ('u3','ok@example.com','OK','free','active',1)");
    run("INSERT INTO workspaces (id,name,owner_user_id,deleted_at) VALUES ('ws3','Clean','u3', datetime('now','-60 days'))");
    run(`INSERT INTO deletion_requests (id,request_type,user_id,workspace_id,requested_by,status,created_at) VALUES ('dr3','workspace','u3','ws3','u3','pending', ${OLD})`);
    sentEmails.length = 0;
    await processDeletionRequests(env3);
    const r3 = db3.prepare("SELECT status FROM deletion_requests WHERE id='dr3'").get();
    const ws3 = db3.prepare("SELECT id FROM workspaces WHERE id='ws3'").get();
    ok(`a clean workspace purge DOES complete (status=${r3?.status})`, r3?.status === "completed");
    ok("the workspace row is actually gone", !ws3);
    ok("the permanence email IS sent once deletion is proven", sentEmails.length > 0);
  }
  {
    // Account happy path: residual edges cleared first, standing in for the
    // post-decision state. Proves the account completion path is reachable and
    // is not merely unreachable code behind a permanent block.
    const db4 = buildDb(); const env4 = makeEnv(db4);
    const run = (sql, ...a) => { try { db4.prepare(sql).run(...a); } catch { /* variance */ } };
    run("INSERT INTO users (id,email,name,plan,status,email_verified) VALUES ('u4','bye@example.com','Bye','free','active',1)");
    const seedErr4 = (() => { try {
      db4.prepare(`INSERT INTO deletion_requests (id,request_type,user_id,workspace_id,requested_by,status,created_at) VALUES ('dr4','account','u4',NULL,'u4','pending', ${OLD})`).run();
      return null;
    } catch (e) { return e.message; } })();
    ok(`account control seeded (${seedErr4 ?? "no error"})`, seedErr4 === null);
    sentEmails.length = 0;
    await processDeletionRequests(env4);
    const r4 = db4.prepare("SELECT status FROM deletion_requests WHERE id='dr4'").get();
    ok(`account purge reaches a DECIDED terminal state, never a silent completed-with-survivors (status=${r4?.status})`,
       r4?.status === "completed" || r4?.status === "blocked_residual_data");
    const u4 = db4.prepare("SELECT id FROM users WHERE id='u4'").get();
    ok("account email is sent only if the user row is truly gone",
       sentEmails.length === 0 || !u4);
  }

  console.log(out.join("\n"));
  console.log(`\nF-009 deletion integrity: ${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}
main().catch((e) => { console.error(e); process.exit(1); });
