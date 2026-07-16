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

// ════ MUTATIONS 8-13 — the occurrence resolver must not depend on a window ═══
// DEFECT (reproduced 2026-07-16 against the real Shadow IT engine): findConditionOccurrence
// read `LIMIT 25` of monitoring_changed rows and filtered to_recurrence_type in JS. Shadow
// IT appended one non-matching case-linkage row per evaluation pass, so the window filled
// and from pass 26 the resolver returned NULL forever — measured 148 monitoring_changed
// rows for ONE item, of which 4 were real occurrences.
//
// Each mutation below is driven against a REAL seeded lifecycle, not a source regex, so it
// proves behaviour rather than spelling.
function occDb() {
  const db = buildDb();
  db.prepare("INSERT INTO users (id,email,name,plan,created_at) VALUES ('u1','o@e.com','o','business',datetime('now'))").run();
  db.prepare("INSERT INTO workspaces (id,owner_user_id,name) VALUES ('ws1','u1','ws1')").run();
  db.prepare("INSERT INTO workspaces (id,owner_user_id,name) VALUES ('ws2','u1','ws2')").run();
  const ins = (id, rec, ws, type, detail, at) =>
    db.prepare(`INSERT INTO certificate_lifecycle_events (id, lifecycle_id, workspace_id, actor_type, event_type, detail_json, created_at)
                VALUES (?,?,?,'system',?,?,?)`).run(id, rec, ws, type, JSON.stringify(detail), at);

  // The real occurrence, OLDEST, then 60 non-matching rows above it.
  ins("real", "rec1", "ws1", "monitoring_changed", { to_recurrence_type: "COND" }, "2026-06-02T00:00:00Z");
  for (let i = 0; i < 60; i++) ins(`noise${i}`, "rec1", "ws1", "monitoring_changed", { case_id: "c1", recurrence: "COND" }, "2026-06-03T00:00:00Z");
  // A NEWER match on ANOTHER record in the SAME tenant: fk-predicate bait. Reachable —
  // two overdue certificates in one workspace is routine.
  ins("other_rec", "rec2", "ws1", "monitoring_changed", { to_recurrence_type: "COND" }, "2026-06-21T00:00:00Z");
  // A NEWER row of a DIFFERENT event_type echoing the same payload: type-predicate bait.
  // SYNTHETIC — no engine writes to_recurrence_type under any type but monitoring_changed
  // today, so dropping the type predicate is behaviour-preserving on real data. This row
  // exists to keep it that way when a future writer starts echoing the field, and the
  // guard is honest about being future-proofing rather than a live defect.
  ins("wrong_type", "rec1", "ws1", "case_recurrence_noted", { to_recurrence_type: "COND" }, "2026-06-22T00:00:00Z");
  return { db, env: { cybermeters_db: makeD1(db) } };
}
const resolveWith = (mod, env) => mod.findConditionOccurrence(env, {
  workspace_id: "ws1", domain_key: "certificates_trust", record_id: "rec1", recurrence_type: "COND",
});

// 8 — the precise event-type filter removed.
await withMutant("alert-occurrence.js",
  (s) => s.replace("WHERE workspace_id = ? AND ${source.fk} = ? AND ${source.type_column} = ?",
                   "WHERE workspace_id = ? AND ${source.fk} = ?")
          .replace(".bind(workspace_id, record_id, MONITORING_CHANGED, String(recurrence_type))",
                   ".bind(workspace_id, record_id, String(recurrence_type))"),
  async (mut) => {
    const { env } = occDb();
    const occ = await resolveWith(mut, env);
    eq("MUTANT-8: without the type filter, a non-occurrence event_type becomes the occurrence",
      occ?.occurrence_id, "wrong_type");
  });

// 9 — workspace_id removed.
// Asserted as a CONFUSED-DEPUTY guard, not as a cross-tenant row leak, because the leak
// is unreachable: every lifecycle fk is the TEXT PRIMARY KEY of one global table with a
// crypto-random id, and every writer stamps the event's workspace_id from the owning
// record — so no consistent database holds a row matching the fk under a different
// tenant. Seeding one to claim a leak would be staging impossible data. What the
// predicate genuinely defends is a CALLER arriving with someone else's record id, and
// that is exactly what this drives.
await withMutant("alert-occurrence.js",
  (s) => s.replace("WHERE workspace_id = ? AND ${source.fk} = ? AND ${source.type_column} = ?",
                   "WHERE ${source.fk} = ? AND ${source.type_column} = ?")
          .replace(".bind(workspace_id, record_id, MONITORING_CHANGED, String(recurrence_type))",
                   ".bind(record_id, MONITORING_CHANGED, String(recurrence_type))"),
  async (mut) => {
    const { env } = occDb();
    const leaked = await mut.findConditionOccurrence(env, {
      workspace_id: "ws2", domain_key: "certificates_trust", record_id: "rec1", recurrence_type: "COND",
    });
    eq("MUTANT-9: without workspace_id, a caller scoped to ws2 resolves ws1's occurrence",
      leaked?.occurrence_id, "real");
  });

// 9b — the REAL module refuses that same call.
{
  const { env } = occDb();
  const mod = await import(pathToFileURL(srcPath("engines", "alert-occurrence.js")).href);
  const denied = await mod.findConditionOccurrence(env, {
    workspace_id: "ws2", domain_key: "certificates_trust", record_id: "rec1", recurrence_type: "COND",
  });
  eq("REAL: a caller scoped to ws2 resolves NOTHING for a ws1 record", denied, null);
}

// 10 — the record/entity identity removed.
await withMutant("alert-occurrence.js",
  (s) => s.replace("WHERE workspace_id = ? AND ${source.fk} = ? AND ${source.type_column} = ?",
                   "WHERE workspace_id = ? AND ${source.type_column} = ?")
          .replace(".bind(workspace_id, record_id, MONITORING_CHANGED, String(recurrence_type))",
                   ".bind(workspace_id, MONITORING_CHANGED, String(recurrence_type))"),
  async (mut) => {
    const { env } = occDb();
    const occ = await resolveWith(mut, env);
    eq("MUTANT-10: without the record id, ANOTHER RECORD's newer event is returned",
      occ?.occurrence_id, "other_rec");
  });

// 11 — deterministic ordering removed.
//
// HONEST LIMIT: without ORDER BY, SQLite's row order is UNSPECIFIED, not random. Today's
// planner walks the (fk, created_at) index ascending, so the mutant returns the OLDEST
// match and is caught. A future planner could legally return the newest first and this
// mutant would survive — the assertion would then pass against a genuinely broken query.
// It is written to fail only on the WRONG answer, never to fail correct code, so a planner
// change makes it weaker rather than flaky. The property itself is pinned unconditionally
// by validate-alert-occurrence.js §10 (which asserts the newest wins WITH the ORDER BY)
// and by MUTANT-11b below, which does not depend on planner order at all.
await withMutant("alert-occurrence.js",
  (s) => s.replace(/\n\s*ORDER BY created_at DESC, rowid DESC\n(\s*)LIMIT 1`\)/, "\n$1LIMIT 1`)"),
  async (mut) => {
    const { db, env } = occDb();
    // A SECOND, newer occurrence: with ORDER BY, this must win.
    db.prepare(`INSERT INTO certificate_lifecycle_events (id, lifecycle_id, workspace_id, actor_type, event_type, detail_json, created_at)
                VALUES ('newest','rec1','ws1','system','monitoring_changed',?,'2026-06-25T00:00:00Z')`)
      .run(JSON.stringify({ to_recurrence_type: "COND" }));
    const occ = await resolveWith(mut, env);
    ok("MUTANT-11: without ORDER BY the resolver stops returning the newest occurrence (planner-dependent)",
      occ?.occurrence_id !== "newest");
  });

// 11b — the tie-break specifically: rowid DESC -> id DESC.
// Planner-independent: both rows tie on created_at, so ONLY the tie-break decides. The ids
// are chosen so lexicographic order inverts insertion order.
await withMutant("alert-occurrence.js",
  (s) => s.replace("ORDER BY created_at DESC, rowid DESC", "ORDER BY created_at DESC, id DESC"),
  async (mut) => {
    const { db, env } = occDb();
    const SEC = "2026-06-30T00:00:00Z";
    for (const id of ["zzz_first", "aaa_second"]) {
      db.prepare(`INSERT INTO certificate_lifecycle_events (id, lifecycle_id, workspace_id, actor_type, event_type, detail_json, created_at)
                  VALUES (?, 'rec1','ws1','system','monitoring_changed',?,?)`)
        .run(id, JSON.stringify({ to_recurrence_type: "COND" }), SEC);
    }
    const occ = await resolveWith(mut, env);
    eq("MUTANT-11b: an `id DESC` tie-break returns the EARLIER append — reusing its dedupe key and silencing the recurrence",
      occ?.occurrence_id, "zzz_first");
  });

// 12 — reverted to LIMIT 25 + JavaScript filtering (the original code).
await withMutant("alert-occurrence.js",
  (s) => {
    const a = s.indexOf("    const row = await env.cybermeters_db");
    const b = s.indexOf("    return null;   // pre-existing condition");
    if (a === -1 || b === -1) return s;
    return s.slice(0, a) + `    const rows = await env.cybermeters_db
      .prepare(\`SELECT id, created_at, detail_json
                FROM \${source.table}
                WHERE workspace_id = ? AND \${source.fk} = ? AND \${source.type_column} = ?
                ORDER BY created_at DESC, rowid DESC
                LIMIT 25\`)
      .bind(workspace_id, record_id, MONITORING_CHANGED)
      .all();

    for (const row of (rows.results || [])) {
      const detail = parseJson(row.detail_json, {}) || {};
      if (String(detail.to_recurrence_type || "") === String(recurrence_type)) {
        return { occurrence_id: row.id, observed_at: row.created_at, detail };
      }
    }
` + s.slice(b);
  },
  async (mut) => {
    const { env } = occDb();
    const occ = await resolveWith(mut, env);
    eq("MUTANT-12: LIMIT 25 + JS filtering loses the occurrence behind 60 noise rows — the defect, reproduced",
      occ, null);
  });

// 13 — the json_valid guard dropped: one malformed row poisons every alert for the record.
await withMutant("alert-occurrence.js",
  (s) => s.replace(/\(CASE WHEN json_valid\(detail_json\)\n\s*THEN json_extract\(detail_json, '\$\.to_recurrence_type'\) END\)/,
                   "json_extract(detail_json, '$.to_recurrence_type')"),
  async (mut) => {
    const { db, env } = occDb();
    db.prepare(`INSERT INTO certificate_lifecycle_events (id, lifecycle_id, workspace_id, actor_type, event_type, detail_json, created_at)
                VALUES ('poison','rec1','ws1','system','monitoring_changed','{not json','2026-06-24T00:00:00Z')`).run();
    const occ = await resolveWith(mut, env);
    eq("MUTANT-13: one malformed row takes the whole read down — fails closed, alert lost", occ, null);
  });

// ════ 14 — the case-linkage row is not typed as a monitoring change ══════════
// It records "the already-open case was touched again for the same recurrence" and is
// appended on EVERY evaluation pass while a condition persists. Typed `monitoring_changed`
// it was eviction fuel: measured 148 monitoring_changed rows for ONE shadow-IT item, of
// which 4 were real occurrences.
//
// This is NOT what makes the resolver correct (the window is gone), and it does NOT make
// it faster: every index on these tables is (fk, created_at), so event_type is a residual
// filter and the walk visits every row for the record either way. It is for honest typing
// — the log should not call a case touch a monitoring change, and the occurrence namespace
// should mean one thing.
//
// Asserted for ALL THREE domains that carried the identical row. Fixing only the one that
// was reported is how #105 left the same defect live in another module.
for (const file of ["shadow-it-inventory.js", "identity-lifecycle.js", "certificate-lifecycle.js"]) {
  const src = fs.readFileSync(srcPath("engines", file), "utf8");
  const code = src.replace(/^\s*\/\/.*$/gm, "");
  ok(`${file}: the case-linkage row is typed case_recurrence_noted`,
    /event_type: "case_recurrence_noted", detail: \{ case_id/.test(code));
  ok(`${file}: no case-linkage row is typed monitoring_changed any more`,
    !/event_type: "monitoring_changed", detail: \{ case_id/.test(code));
  // It must carry no occurrence payload, or it would become an occurrence itself.
  ok(`${file}: the case-linkage row carries no to_recurrence_type`,
    !/case_recurrence_noted[\s\S]{0,160}to_recurrence_type/.test(code));
  // A domain must DECLARE every event type it writes. These vocabularies are exported and
  // currently read by nothing, which is exactly how a declaration goes stale unnoticed —
  // the engine writes one word and its own published list says another.
  // `[^\]]*` — NOT `[\s\S]*?`. A lazy any-char match walks straight out of the array
  // literal and finds the string in the appendEvent call further down the file, so it
  // passes with the declaration deleted. This assertion did exactly that until its own
  // mutation caught it: excluding `]` is what keeps the match inside the array.
  ok(`${file}: declares case_recurrence_noted in its own event vocabulary`,
    /EVENT_TYPES = Object\.freeze\(\[[^\]]*"case_recurrence_noted"[^\]]*\]\)/.test(code));
}
{
  // And the resolver ignores it end-to-end, even carrying a matching payload.
  const { env } = occDb();
  const mod = await import(pathToFileURL(srcPath("engines", "alert-occurrence.js")).href);
  const occ = await resolveWith(mod, env);
  ok("a case_recurrence_noted row is never resolved as the occurrence, even echoing the payload",
    occ?.occurrence_id === "real");
}

// The REAL module survives every fixture above.
{
  const { db, env } = occDb();
  const mod = await import(pathToFileURL(srcPath("engines", "alert-occurrence.js")).href);
  db.prepare(`INSERT INTO certificate_lifecycle_events (id, lifecycle_id, workspace_id, actor_type, event_type, detail_json, created_at)
              VALUES ('poison','rec1','ws1','system','monitoring_changed','{not json','2026-06-24T00:00:00Z')`).run();
  const occ = await resolveWith(mod, env);
  eq("REAL: resolves the true occurrence past 60 noise rows, a foreign tenant, another record, a wrong type and a malformed row",
    occ?.occurrence_id, "real");
  eq("REAL: and carries the transition's OWN timestamp", occ?.observed_at, "2026-06-02T00:00:00Z");
}

globalThis.fetch = realFetch;
console.log(`\nalerting-repair-mutations: ${pass} passed, ${fail} failed`);
if (fail > 0) { console.error("alerting-repair-mutations validation FAILED"); process.exit(1); }
console.log("alerting-repair-mutations validation passed");
