#!/usr/bin/env node
//
// Alerting-repair MUTATION PROOF. CI-blocking. Node 24+.
//
// A passing assertion count is not proof. Every guard below is proved LOAD-BEARING by
// reintroducing the exact defect it exists to catch and requiring the defect to reappear.
// If a mutation stops reproducing, the guard has stopped guarding — that is a failure
// here, not a pass.
//
// This exists because two guards in this repo were named for coverage they never had:
//   • validate-alert-b3-email-protection.js's hosted section was titled
//     "disconnect → reconnect → re-disconnect" and never performed the re-disconnect —
//     the defect it was named after was live the entire time;
//   • validate-shadow-it-correlation.js tested only the CONTRADICTED branch of removal
//     verification, so the branch that fabricated "verified" shipped untested.
// A test that renames a sequence without executing it is worse than no test: it spends
// the reviewer's confidence without earning it.
//
// The seven mutations are the founder's list, each tied to a defect reproduced live on
// 2026-07-16 against Worker 6b310472.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const srcPath = (...p) => path.join(root, "workers", "scan-api", "src", ...p);

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

// Write a mutated copy of an engine next to the original (so its relative imports still
// resolve), import it, and always clean up.
let mutantSeq = 0;
async function withMutant(file, mutate, run) {
  const original = fs.readFileSync(srcPath("engines", file), "utf8");
  const mutated = mutate(original);
  ok(`[${file}] the mutation applied (the guard is where this suite thinks it is)`, mutated !== original);
  if (mutated === original) return;
  const tmpName = `.${file.replace(/\.js$/, "")}.mutant.${process.pid}.${++mutantSeq}.js`;
  const tmp = srcPath("engines", tmpName);
  fs.writeFileSync(tmp, mutated);
  try {
    await run(await import(pathToFileURL(tmp).href));
  } finally {
    fs.rmSync(tmp, { force: true });
  }
}

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
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
}
function freshEnv() {
  const db = buildDb();
  db.prepare("INSERT INTO users (id,email,name,plan,created_at) VALUES ('u1','o@e.com','o','business',datetime('now'))").run();
  db.prepare("INSERT INTO users (id,email,name,plan,created_at) VALUES ('u2','b@e.com','b','business',datetime('now'))").run();
  db.prepare("INSERT INTO workspaces (id,owner_user_id,name) VALUES ('ws1','u1','ws1')").run();
  db.prepare("INSERT INTO workspaces (id,owner_user_id,name) VALUES ('ws2','u2','ws2')").run();
  for (const ws of ["ws1", "ws2"]) {
    db.prepare(`INSERT OR IGNORE INTO alert_activation (id,workspace_id,domain_key,activated_at,baseline_count,created_at)
                VALUES (?,?, 'email_protection','2026-07-01T00:00:00Z',0,datetime('now'))`).run(`act_${ws}`, ws);
  }
  return { db, env: { cybermeters_db: makeD1(db), RESEND_API_KEY: "", ALERT_EMAIL_FROM: "a@cybermeters.com" } };
}
const seedHosted = (db, id, ws, domain) =>
  db.prepare(`INSERT INTO hosted_dns_entries (id,workspace_id,domain,record_kind,customer_name,target_name,target_value,verification_state,created_at,updated_at)
              VALUES (?,?,?,'dmarc',?,?, 'v=DMARC1; p=none','connected','2026-07-16 09:00:00','2026-07-16 09:00:00')`)
    .run(id, ws, domain, `_dmarc.${domain}`, `${id}.dmarc.cybermeters.com`);
const hostedRow = (id, ws, domain) => ({ id, workspace_id: ws, domain, created_at: "2026-07-16 09:00:00", status: "connected" });
const notifications = (db, ws) => db.prepare("SELECT * FROM notification_events WHERE workspace_id=?").all(ws);
const tick = () => new Promise((r) => setTimeout(r, 1100));

const realFetch = globalThis.fetch;
globalThis.fetch = async () => new Response("{}", { status: 200 });

// Drive the full recovery sequence and report how many alerts the SECOND disconnect got.
async function reDisconnectAlerts(mod, { workspace = "ws1", id = "hd-mut-0001" } = {}) {
  const { db, env } = freshEnv();
  seedHosted(db, id, workspace, "example.com");
  const row = hostedRow(id, workspace, "example.com");
  const before = notifications(db, workspace).length;
  await mod.recordHostedTransition(env, row, { recurrence: "hosted_record_disconnected", from_status: "connected", to_status: "disconnected" });
  await tick();
  await mod.recordHostedTransition(env, row, { event_type: "hosted_record_reconnected", from_status: "disconnected", to_status: "connected" });
  await tick();
  await mod.recordHostedTransition(env, row, { recurrence: "hosted_record_disconnected", from_status: "connected", to_status: "disconnected" });
  return notifications(db, workspace).length - before;
}

// ════ MUTATION 1 — remove `threat` from the canonical map ════════════════════
// DEFECT: marking a sender a THREAT silences its own alert.
await withMutant("sender-classification.js",
  (s) => s.replace(`  threat:     "unauthorised",\n`, ""),
  async (mut) => {
    eq("MUTANT-1: threat claims nothing", mut.assertedClassification("threat"), null);
    eq("MUTANT-1: a THREAT'd sender resolves to the evidence-free customer word — the collapse returns",
      mut.resolveEffectiveClassification({ classification: "threat", auto_classification: "authorised", classified_at: "x" }), "authorised");
    ok("MUTANT-1: the vocabulary guard notices the hole",
      mut.CUSTOMER_SENDER_DISPOSITIONS.some((d) => !(d in mut.DISPOSITION_ASSERTS)));
  });

// ════ MUTATION 2 — restore the vocabulary mismatch ═══════════════════════════
// DEFECT: the exact live bug — the customer's word handed to a function that speaks
// evidence, so threat/trusted/ignored all band null.
await withMutant("sender-classification.js",
  (s) => s.replace(
    /export function resolveEffectiveClassification\(row = \{\}\) \{[\s\S]*?\n\}/,
    `export function resolveEffectiveClassification(row = {}) {
  if (row.classified_at) return row.classification || "unknown";
  return row.auto_classification || row.classification || "unknown";
}`),
  async (mut) => {
    eq("MUTANT-2: the customer's raw word is returned again",
      mut.resolveEffectiveClassification({ classification: "threat", auto_classification: "unauthorised", classified_at: "x" }), "threat");
    // And that word is not in the observed vocabulary, so anything grading on it bands null.
    ok("MUTANT-2: the returned value is NOT an observed classification — the collapse is back",
      !mut.OBSERVED_SENDER_CLASSIFICATIONS.includes("threat"));
  });

// ════ MUTATION 3 — ignore hosted_record_reconnected ══════════════════════════
// DEFECT: recovery never closes the condition, so the second disconnect is silent.
await withMutant("email-protection-lifecycle.js",
  (s) => s.replace(
    "const CONDITION_CLOSING_EVENT_TYPES = Object.freeze([EMAIL_EVENT_HOSTED_RECONNECTED]);",
    "const CONDITION_CLOSING_EVENT_TYPES = Object.freeze([]);"),
  async (mut) => {
    eq("MUTANT-3: a second disconnect after recovery is SILENT — the defect, reproduced",
      await reDisconnectAlerts(mut), 1);
  });

// ════ MUTATION 4 — lastGradedCondition reads only the old disconnect event ═══
// DEFECT: the original code. Same silence, reached a different way, so the guard is
// pinned to the BEHAVIOUR rather than to one constant.
await withMutant("email-protection-lifecycle.js",
  (s) => s.replace(
    /WHERE workspace_id = \? AND record_id = \? AND event_type IN \(\?, \?\)\n(\s*)ORDER BY created_at DESC, rowid DESC LIMIT 1`\)\n(\s*)\.bind\(workspaceId, recordId, MONITORING_CHANGED, \.\.\.CONDITION_CLOSING_EVENT_TYPES\)/,
    "WHERE workspace_id = ? AND record_id = ? AND event_type = ?\n$1ORDER BY created_at DESC, rowid DESC LIMIT 1`)\n$2.bind(workspaceId, recordId, MONITORING_CHANGED)"),
  async (mut) => {
    eq("MUTANT-4: reading only monitoring_changed silences the re-entry — the defect, reproduced",
      await reDisconnectAlerts(mut), 1);
  });

// ════ MUTATION 5 — suppress the re-entry with the FIRST dedupe key ═══════════
// DEFECT: dedupe swallowing a genuine recurrence.
//
// The dedupe key is the occurrence id, so "reuse the first disconnect's key" means "let
// the resolver return the FIRST occurrence instead of the newest". That is what an
// ASC ordering in findConditionOccurrence would do. It is asserted directly against the
// resolver rather than through a mutated copy: the lifecycle imports the resolver by a
// fixed specifier, so swapping the module in isolation would not change what the
// lifecycle calls, and a mutation the code under test never loads proves nothing.
{
  const { db, env } = freshEnv();
  const occMod = await import(pathToFileURL(srcPath("engines", "alert-occurrence.js")).href);
  const lifecycle = await import(pathToFileURL(srcPath("engines", "email-protection-lifecycle.js")).href);
  seedHosted(db, "hd-mut-0005", "ws1", "example.com");
  const row = hostedRow("hd-mut-0005", "ws1", "example.com");
  await lifecycle.recordHostedTransition(env, row, { recurrence: "hosted_record_disconnected", from_status: "connected", to_status: "disconnected" });
  await tick();
  await lifecycle.recordHostedTransition(env, row, { event_type: "hosted_record_reconnected", from_status: "disconnected", to_status: "connected" });
  await tick();
  await lifecycle.recordHostedTransition(env, row, { recurrence: "hosted_record_disconnected", from_status: "connected", to_status: "disconnected" });

  const occ = await occMod.findConditionOccurrence(env, {
    workspace_id: "ws1", domain_key: "email_protection",
    record_id: "hd-mut-0005", recurrence_type: "hosted_record_disconnected",
  });
  const rows = db.prepare(`SELECT id, created_at FROM email_protection_events
                           WHERE record_id='hd-mut-0005' AND event_type='monitoring_changed'
                           ORDER BY created_at DESC, rowid DESC`).all();
  eq("the re-entry minted a second occurrence row", rows.length, 2);
  eq("the resolver returns the NEWEST occurrence, so the dedupe key is new",
    occ?.occurrence_id, rows[0].id);
  ok("and NOT the first disconnect's occurrence — which would reuse its dedupe key and silence the recurrence",
    occ?.occurrence_id !== rows[1].id);
}

// ════ MUTATION 6 — remove workspace_id from the lifecycle lookup ═════════════
// Asserted STRUCTURALLY, and the honest reason matters more than the assertion.
//
// I tried to reproduce a cross-tenant leak behaviourally first and could not, because
// the scenario it needs cannot exist: `hosted_dns_entries.id` is the PRIMARY KEY, so the
// same record id in two workspaces is rejected by the database, and
// `email_protection_events.record_id` therefore never collides across tenants. Dropping
// `workspace_id` from this lookup finds the same row either way.
//
// So this predicate is DEFENCE IN DEPTH, not a live exploit, and this suite says so
// rather than staging an unreachable fixture and calling the result a leak. It still has
// to stay: the events table deliberately carries no FK to its parents (migration 088 —
// history outlives a hard-deleted hosted record), so record_id's uniqueness is a property
// of another table that this query does not join. Nothing but this predicate keeps the
// read tenant-scoped if that ever changes.
{
  const src = fs.readFileSync(srcPath("engines", "email-protection-lifecycle.js"), "utf8");
  const fn = src.match(/async function lastGradedCondition[\s\S]*?\n\}/)?.[0] ?? "";
  ok("lastGradedCondition exists where this suite thinks it does", fn.length > 0);
  ok("the lifecycle condition lookup is workspace-scoped in SQL", /WHERE workspace_id = \?/.test(fn));
  ok("and binds the workspace id first", /\.bind\(workspaceId, recordId/.test(fn));

  // Prove the check can fail: strip the scope and require it to be seen.
  const stripped = fn
    .replace("WHERE workspace_id = ? AND record_id = ?", "WHERE record_id = ?")
    .replace(".bind(workspaceId, recordId,", ".bind(recordId,");
  ok("MUTANT-6: an unscoped lookup IS detected — the check is not vacuous",
    !/WHERE workspace_id = \?/.test(stripped) && !/\.bind\(workspaceId, recordId/.test(stripped));
}

// Tenant independence where it IS observable: two tenants, two records, one condition
// each. ws1's live disconnection must not silence ws2's first.
{
  const { db, env } = freshEnv();
  const lifecycle = await import(pathToFileURL(srcPath("engines", "email-protection-lifecycle.js")).href);
  seedHosted(db, "hd-tenant-ws1", "ws1", "example.com");
  seedHosted(db, "hd-tenant-ws2", "ws2", "ex2.com");
  await lifecycle.recordHostedTransition(env, hostedRow("hd-tenant-ws1", "ws1", "example.com"),
    { recurrence: "hosted_record_disconnected", from_status: "connected", to_status: "disconnected" });
  await tick();
  const before = notifications(db, "ws2").length;
  await lifecycle.recordHostedTransition(env, hostedRow("hd-tenant-ws2", "ws2", "ex2.com"),
    { recurrence: "hosted_record_disconnected", from_status: "connected", to_status: "disconnected" });
  eq("ws2's first disconnect alerts, unaffected by ws1's live disconnection",
    notifications(db, "ws2").length - before, 1);
  ok("every ws2 event is stamped with ws2",
    db.prepare("SELECT workspace_id FROM email_protection_events WHERE record_id='hd-tenant-ws2'")
      .all().every((e) => e.workspace_id === "ws2"));

  // A soft-deleted tenant is never mailed: the canonical engine's gate, not this module's.
  db.prepare("UPDATE workspaces SET deleted_at = datetime('now') WHERE id='ws2'").run();
  await tick();
  const beforeDead = notifications(db, "ws2").length;
  await lifecycle.recordHostedTransition(env, hostedRow("hd-tenant-ws2", "ws2", "ex2.com"),
    { event_type: "hosted_record_reconnected", from_status: "disconnected", to_status: "connected" });
  await tick();
  await lifecycle.recordHostedTransition(env, hostedRow("hd-tenant-ws2", "ws2", "ex2.com"),
    { recurrence: "hosted_record_disconnected", from_status: "connected", to_status: "disconnected" });
  eq("a soft-deleted workspace receives NO alert, even for a genuine recurrence",
    notifications(db, "ws2").length - beforeDead, 0);
}

// ════ MUTATION 7 — bypass the alert policy, call a delivery sender directly ══
// DEFECT: a second send path. Every alert must go through emitLifecycleAlert, which is
// where the activation watermark, entitlement gate, soft-delete check, severity mapping,
// canonical remediation and dedupe live. A module that reaches for a channel sender
// directly bypasses all of it — including the checks that stop us mailing a deleted
// tenant. This is asserted at source level because it is an architectural boundary, and
// the mutation proves the assertion is not vacuous.
const DELIVERY_SENDERS = ["deliverWorkspaceAlert", "sendTenantAlertEmail", "sendAlertEmail", "buildAlertChannelPayload", "signAlertWebhookBody"];
const CANONICAL_ALERT_CALLERS = ["email-protection-lifecycle.js", "hosted-dmarc.js", "sender-classification.js", "dmarc-impact.js"];
for (const file of CANONICAL_ALERT_CALLERS) {
  const src = fs.readFileSync(srcPath("engines", file), "utf8");
  const found = DELIVERY_SENDERS.filter((fn) => new RegExp(`\\b${fn}\\b`).test(src));
  eq(`${file} calls NO delivery sender directly — it goes through the canonical engine`, found, []);
}
{
  // Prove the check above can actually fail: inject the bypass and require it to be seen.
  const src = fs.readFileSync(srcPath("engines", "email-protection-lifecycle.js"), "utf8");
  const bypassed = `import { deliverWorkspaceAlert } from "./alerts.js";\n` + src
    + `\nexport async function __bypass(env, ws, e) { return deliverWorkspaceAlert(env, ws, e); }\n`;
  const found = DELIVERY_SENDERS.filter((fn) => new RegExp(`\\b${fn}\\b`).test(bypassed));
  eq("MUTANT-7: a direct delivery call IS detected — the boundary check is not vacuous",
    found, ["deliverWorkspaceAlert"]);
}
// And the one legitimate route in: the lifecycle emits only through the canonical engine.
{
  const src = fs.readFileSync(srcPath("engines", "email-protection-lifecycle.js"), "utf8");
  ok("the lifecycle emits through emitLifecycleAlert (the canonical engine)",
    /import \{ emitLifecycleAlert \} from "\.\/alert-consumers\.js";/.test(src));
}

globalThis.fetch = realFetch;
console.log(`\nalerting-repair-mutations: ${pass} passed, ${fail} failed`);
if (fail > 0) { console.error("alerting-repair-mutations validation FAILED"); process.exit(1); }
console.log("alerting-repair-mutations validation passed");
