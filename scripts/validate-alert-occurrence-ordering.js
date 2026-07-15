#!/usr/bin/env node
//
// Alert occurrence ORDERING — DB-backed, mutation-tested, CI-blocking.
//
// findConditionOccurrence resolves "which occurrence of this condition is this?"
// by taking the newest matching `monitoring_changed` event. Every lifecycle event
// is stamped by SQLite `datetime('now')` — SECOND precision — so two appends for
// one record inside one second TIE on created_at and fall through to the
// tie-break. The tie-break used to be `id DESC`, and every id is random hex, so
// the resolver could return the OLDER event as the newest occurrence. The older
// event's dedupe_key already exists, so INSERT OR IGNORE swallows the newer, real
// alert as a duplicate: fail-SILENT. This suite proves the tie-break is now
// insertion order (`rowid DESC`), and — via a mutation run at the end — that this
// suite would actually CATCH a regression to `id DESC` rather than pass anyway.
//
// The ordering contract rests on a schema fact, so it is asserted against the real
// schema (§1) rather than assumed: every source is a physical rowid table.
//
// Watermark safety is the reason this fix is `rowid` and not sub-second
// timestamps: a rowid tie-break only ever re-selects among rows whose created_at
// are IDENTICAL, so observed_at is bit-for-bit unchanged and every
// observationIsAfterWatermark decision is invariant (§6, §7).
//
// Node 24+.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engPath = (f) => path.join(root, "workers", "scan-api", "src", "engines", f);
const eng = (f) => pathToFileURL(engPath(f)).href;
const { findConditionOccurrence, buildMonitoringTransitionDetail, LIFECYCLE_EVENT_SOURCES, MONITORING_CHANGED } =
  await import(eng("alert-occurrence.js"));
const { emitManagedAlert, ensureAlertActivation, buildAlertDedupeKey, observationIsAfterWatermark } =
  await import(eng("managed-alerts.js"));

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
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
}

const db = buildDb();
const realFetch = globalThis.fetch;
globalThis.fetch = async (url) => (String(url).includes("resend.com")
  ? new Response(JSON.stringify({ id: "email_1" }), { status: 200, headers: { "content-type": "application/json" } })
  : new Response("{}", { status: 200 }));

// ── Seed ─────────────────────────────────────────────────────────────────────
db.prepare("INSERT INTO users (id, email, name, plan, created_at) VALUES ('u1','o@example.com','o','professional',datetime('now'))").run();
db.prepare("UPDATE users SET email_verified = 1 WHERE id = 'u1'").run();
db.prepare(`INSERT INTO subscriptions (id, owner_user_id, plan, subscription_status, status, current_period_end, created_at, updated_at)
            VALUES ('s1','u1','professional','active','active',datetime('now','+30 days'),datetime('now'),datetime('now'))`).run();
for (const ws of ["ws1", "ws2"]) {
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES (?,'u1',?)").run(ws, ws);
}
db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES ('m1','ws1','u1','owner')").run();

const env = { cybermeters_db: makeD1(db), ALERT_EMAIL_FROM: "alerts@cybermeters.com", RESEND_API_KEY: "re_test" };
const notifs = (ws) => db.prepare("SELECT * FROM notification_events WHERE workspace_id = ?").all(ws);

// Append a monitoring_changed event exactly as an evaluator would, but with an
// EXPLICIT id and created_at so a same-second tie can be constructed on purpose.
// The per-source column shape differs (managed cases name the vocabulary column
// `action` and carry from/to status; Email Protection carries record_type), so the
// insert is built from the source map rather than hardcoded to one table.
function append(domain_key, ws, recordId, { id, to_recurrence_type, created_at, entity = "www.example.com" }) {
  const src = LIFECYCLE_EVENT_SOURCES[domain_key];
  const detail = JSON.stringify(buildMonitoringTransitionDetail({
    to_monitoring_status: "at_risk", to_recurrence_type, reason: "condition_observed", entity,
  }));
  if (src.table === "managed_case_events") {
    db.prepare(`INSERT INTO managed_case_events (id, case_id, workspace_id, actor_type, actor_id, from_status, to_status, action, detail_json, created_at)
                VALUES (?,?,?,'system',NULL,'open','open',?,?,?)`).run(id, recordId, ws, MONITORING_CHANGED, detail, created_at);
  } else if (src.table === "email_protection_events") {
    db.prepare(`INSERT INTO email_protection_events (id, record_id, record_type, workspace_id, actor_type, actor_id, event_type, detail_json, created_at)
                VALUES (?,?,'hosted_dns_entry',?,'system',NULL,?,?,?)`).run(id, recordId, ws, MONITORING_CHANGED, detail, created_at);
  } else {
    db.prepare(`INSERT INTO ${src.table} (id, ${src.fk}, workspace_id, actor_type, actor_id, event_type, detail_json, created_at)
                VALUES (?,?,?,'system',NULL,?,?,?)`).run(id, recordId, ws, MONITORING_CHANGED, detail, created_at);
  }
  return id;
}

const SAME_SECOND = "2026-07-01 12:00:00";

// ── 1. The schema fact the ordering contract rests on ────────────────────────
// rowid ordering is only legal on a physical rowid table. A view has no rowid; a
// WITHOUT ROWID table has none either. Either would make the resolver's ORDER BY
// raise, hit its catch, and fail closed to null FOREVER — silently unalertable.
{
  for (const [domain_key, src] of Object.entries(LIFECYCLE_EVENT_SOURCES)) {
    const obj = db.prepare("SELECT type, sql FROM sqlite_master WHERE name = ?").get(src.table);
    ok(`${domain_key}: ${src.table} exists`, Boolean(obj));
    eq(`${domain_key}: ${src.table} is a physical table, not a view`, obj?.type, "table");
    ok(`${domain_key}: ${src.table} is NOT declared WITHOUT ROWID`, !/without\s+rowid/i.test(obj?.sql || ""));
    // The load-bearing proof: rowid is actually selectable on this table.
    let rowidWorks = true;
    try { db.prepare(`SELECT rowid FROM ${src.table} LIMIT 1`).all(); } catch { rowidWorks = false; }
    ok(`${domain_key}: rowid is available on ${src.table}`, rowidWorks);
    // An INTEGER PRIMARY KEY would ALIAS rowid, making it customer-supplied rather
    // than insertion order. Every source keys on TEXT, so rowid stays the table's
    // own append counter. (Asserted, not assumed — an aliased rowid would silently
    // reintroduce exactly the defect this suite exists to prevent.)
    const pk = db.prepare(`PRAGMA table_info(${src.table})`).all().find((c) => c.pk === 1);
    eq(`${domain_key}: primary key is TEXT, so rowid is not aliased`, String(pk?.type || "").toUpperCase(), "TEXT");
  }
  // The resolver must not have been "fixed" by reaching for sub-second timestamps.
  const src = fs.readFileSync(engPath("alert-occurrence.js"), "utf8")
    .split("\n").filter((l) => !l.trim().startsWith("//")).join("\n");
  ok("the resolver tie-breaks on rowid", /ORDER BY created_at DESC, rowid DESC/.test(src));
  ok("the resolver does not tie-break on the random id", !/ORDER BY created_at DESC, id DESC/.test(src));
  ok("the resolver does not mint sub-second timestamps", !src.includes("%f"));
}

// ── 2. Same second, same record, same recurrence → the LATEST append wins ────
// The older row is given a lexically HIGHER id on purpose. Under `id DESC` the
// resolver returns the older row; under `rowid DESC` it returns the real newest.
{
  const older = append("certificates_trust", "ws1", "cl_tie", { id: "zzz-older", to_recurrence_type: "renewal_overdue", created_at: SAME_SECOND });
  const newer = append("certificates_trust", "ws1", "cl_tie", { id: "aaa-newer", to_recurrence_type: "renewal_overdue", created_at: SAME_SECOND });
  const occ = await findConditionOccurrence(env, { workspace_id: "ws1", domain_key: "certificates_trust", record_id: "cl_tie", recurrence_type: "renewal_overdue" });
  eq("same-second tie resolves the LATEST append", occ?.occurrence_id, newer);
  ok("same-second tie does not resolve the older append", occ?.occurrence_id !== older);
  // Occurrence identity must remain the PERSISTED event id — not a synthesised one.
  const persisted = db.prepare("SELECT id FROM certificate_lifecycle_events WHERE lifecycle_id='cl_tie' ORDER BY rowid DESC LIMIT 1").get();
  eq("occurrence_id equals the actual selected persisted event id", occ?.occurrence_id, persisted.id);
  eq("observed_at is the persisted event's own created_at", occ?.observed_at, SAME_SECOND);
}

// ── 3. Reversing the lexical id order changes nothing ────────────────────────
// The mirror of §2: now the older row has the LOWER id, so `id DESC` would happen
// to be right. Selection must be identical either way — the resolver must depend
// on insertion order, never on how the random hex happened to sort.
{
  append("certificates_trust", "ws1", "cl_tie2", { id: "aaa-older", to_recurrence_type: "renewal_overdue", created_at: SAME_SECOND });
  const newer = append("certificates_trust", "ws1", "cl_tie2", { id: "zzz-newer", to_recurrence_type: "renewal_overdue", created_at: SAME_SECOND });
  const occ = await findConditionOccurrence(env, { workspace_id: "ws1", domain_key: "certificates_trust", record_id: "cl_tie2", recurrence_type: "renewal_overdue" });
  eq("reversed lexical id order still resolves the LATEST append", occ?.occurrence_id, newer);
}

// ── 4. Records and recurrences cannot cross-resolve ──────────────────────────
{
  append("certificates_trust", "ws1", "cl_other", { id: "zzz-other-record", to_recurrence_type: "renewal_overdue", created_at: SAME_SECOND });
  const occ = await findConditionOccurrence(env, { workspace_id: "ws1", domain_key: "certificates_trust", record_id: "cl_tie", recurrence_type: "renewal_overdue" });
  ok("a different record's same-second event is never borrowed", occ?.occurrence_id === "aaa-newer");

  // Same record, same second, DIFFERENT recurrence types. The band case from PR-B2
  // lives here: both rows are `monitoring_changed` on one record, and only the
  // detail's to_recurrence_type separates them.
  append("certificates_trust", "ws1", "cl_mix", { id: "zzz-cov", to_recurrence_type: "coverage_regression", created_at: SAME_SECOND });
  const mixNewer = append("certificates_trust", "ws1", "cl_mix", { id: "aaa-ren", to_recurrence_type: "renewal_overdue", created_at: SAME_SECOND });
  const cov = await findConditionOccurrence(env, { workspace_id: "ws1", domain_key: "certificates_trust", record_id: "cl_mix", recurrence_type: "coverage_regression" });
  const ren = await findConditionOccurrence(env, { workspace_id: "ws1", domain_key: "certificates_trust", record_id: "cl_mix", recurrence_type: "renewal_overdue" });
  eq("recurrence A resolves its own event, not the newer neighbour", cov?.occurrence_id, "zzz-cov");
  eq("recurrence B resolves its own event", ren?.occurrence_id, mixNewer);
  ok("different recurrence types never cross-resolve", cov?.occurrence_id !== ren?.occurrence_id);
}

// ── 5. Tenant isolation survives the tie-break ───────────────────────────────
{
  append("certificates_trust", "ws2", "cl_tie", { id: "zzz-foreign", to_recurrence_type: "renewal_overdue", created_at: SAME_SECOND });
  const mine = await findConditionOccurrence(env, { workspace_id: "ws1", domain_key: "certificates_trust", record_id: "cl_tie", recurrence_type: "renewal_overdue" });
  const theirs = await findConditionOccurrence(env, { workspace_id: "ws2", domain_key: "certificates_trust", record_id: "cl_tie", recurrence_type: "renewal_overdue" });
  // ws2's row is the newest append for record id 'cl_tie' GLOBALLY. If workspace_id
  // ever left the predicate, ws1 would now resolve ws2's event — the tie-break makes
  // that failure MORE likely to be selected, so it is asserted here explicitly.
  eq("a foreign tenant's newer same-second event is never resolved", mine?.occurrence_id, "aaa-newer");
  eq("each tenant resolves its own occurrence", theirs?.occurrence_id, "zzz-foreign");
}

// ── 6. Watermark safety — the whole reason this fix is rowid, not %f ─────────
{
  // Both candidate rows carry the SAME created_at, so whichever the tie-break picks,
  // observed_at is byte-identical and every watermark decision is invariant. This is
  // the property sub-second timestamps would have destroyed.
  const rows = db.prepare("SELECT id, created_at FROM certificate_lifecycle_events WHERE lifecycle_id='cl_tie' AND workspace_id='ws1'").all();
  eq("both same-second candidates carry an identical created_at", [...new Set(rows.map((r) => r.created_at))], [SAME_SECOND]);
  const AT = "2026-07-01T12:00:00Z";   // the activation watermark, same second
  ok("a same-second event is NOT after the watermark, whichever row is selected",
     rows.every((r) => observationIsAfterWatermark(r.created_at, AT) === false));
  const AFTER = "2026-06-01T00:00:00Z";
  ok("a genuinely later event is after an earlier watermark, whichever row is selected",
     rows.every((r) => observationIsAfterWatermark(r.created_at, AFTER) === true));
  // A historical event stays historical: the tie-break cannot move it forward.
  ok("a pre-watermark historical event remains pre-watermark",
     observationIsAfterWatermark("2026-01-01 00:00:00", AFTER) === false);
}

// ── 7. Baseline establishment does not release a backlog ─────────────────────
{
  // A condition that already existed when alerting was switched on must stay silent
  // forever, and the tie-break must not change that. Two same-second PRE-activation
  // events with adversarial ids: neither may emit.
  append("certificates_trust", "ws1", "cl_backlog", { id: "zzz-old-1", to_recurrence_type: "renewal_overdue", created_at: "2026-01-01 00:00:00", entity: "backlog.example.com" });
  append("certificates_trust", "ws1", "cl_backlog", { id: "aaa-old-2", to_recurrence_type: "renewal_overdue", created_at: "2026-01-01 00:00:00", entity: "backlog.example.com" });
  await ensureAlertActivation(env, "ws1", "certificates_trust", { now: "2026-06-01T00:00:00Z" });
  const before = notifs("ws1").length;
  const occ = await findConditionOccurrence(env, { workspace_id: "ws1", domain_key: "certificates_trust", record_id: "cl_backlog", recurrence_type: "renewal_overdue" });
  const r = await emitManagedAlert(env, {
    workspace_id: "ws1", domain_key: "certificates_trust", kind: "cert_renewal_overdue", severity: "high",
    title: "Certificate renewal overdue", message: "Condition observed.",
    dedupe_key: buildAlertDedupeKey({ domain_key: "certificates_trust", kind: "cert_renewal_overdue", subject: "backlog.example.com", period: occ.occurrence_id }),
    observed_at: occ.observed_at,
  });
  eq("a pre-activation backlog condition does not emit", r.emitted, false);
  eq("a pre-activation backlog condition is baselined", r.reason, "alert_baseline_established");
  eq("baseline establishment creates no notification", notifs("ws1").length, before);
}

// ── 8. Every wired domain resolves its own same-second tie ───────────────────
// The resolver is shared by six domains, so the fix is proven on each source table
// rather than on certificates alone — the two shared-table shapes (managed cases;
// Email Protection's two record families) are exactly where a tie-break regression
// would hide.
{
  for (const domain_key of Object.keys(LIFECYCLE_EVENT_SOURCES)) {
    const rec = `rec_${domain_key}`;
    append(domain_key, "ws1", rec, { id: `zzz-${domain_key}-older`, to_recurrence_type: "cond_x", created_at: SAME_SECOND });
    const newer = append(domain_key, "ws1", rec, { id: `aaa-${domain_key}-newer`, to_recurrence_type: "cond_x", created_at: SAME_SECOND });
    const occ = await findConditionOccurrence(env, { workspace_id: "ws1", domain_key, record_id: rec, recurrence_type: "cond_x" });
    eq(`${domain_key}: same-second tie resolves the latest append`, occ?.occurrence_id, newer);
  }
}

// ── 9. Purge / rowid reuse cannot invert append order ────────────────────────
// SQLite assigns a new rowid as max(rowid)+1 over the rows that REMAIN, so rowid
// values ARE reused after a purge deletes the tail. That is safe for this contract
// and the reason is worth pinning: a reused rowid is still larger than every
// surviving row, so a new append can never sort BELOW an older one.
{
  append("certificates_trust", "ws1", "cl_purge", { id: "keep-1", to_recurrence_type: "cond_p", created_at: "2026-07-02 00:00:00" });
  const tail = append("certificates_trust", "ws1", "cl_purge", { id: "purge-me", to_recurrence_type: "cond_p", created_at: "2026-07-02 00:00:00" });
  const purgedRowid = db.prepare("SELECT rowid AS r FROM certificate_lifecycle_events WHERE id = ?").get(tail).r;
  // Purge the tail, exactly as a workspace purge deletes the highest rowids.
  db.prepare("DELETE FROM certificate_lifecycle_events WHERE id = ?").run(tail);
  const reused = append("certificates_trust", "ws1", "cl_purge", { id: "aaa-after-purge", to_recurrence_type: "cond_p", created_at: "2026-07-02 00:00:00" });
  const newRowid = db.prepare("SELECT rowid AS r FROM certificate_lifecycle_events WHERE id = ?").get(reused).r;
  // Reuse genuinely happens (no AUTOINCREMENT on any source table) — asserted, so
  // that if a future migration adds AUTOINCREMENT this test says so out loud rather
  // than quietly passing on a changed premise.
  eq("the purged tail's rowid IS reused by the next append", newRowid, purgedRowid);
  const survivorRowid = db.prepare("SELECT rowid AS r FROM certificate_lifecycle_events WHERE id='keep-1'").get().r;
  ok("a post-purge append still sorts ABOVE every surviving row", newRowid > survivorRowid);
  const occ = await findConditionOccurrence(env, { workspace_id: "ws1", domain_key: "certificates_trust", record_id: "cl_purge", recurrence_type: "cond_p" });
  eq("a post-purge append resolves as the newest occurrence", occ?.occurrence_id, reused);
  eq("the purged event is gone from history", db.prepare("SELECT COUNT(*) AS c FROM certificate_lifecycle_events WHERE id = ?").get(tail).c, 0);
}

// ── 10. MUTATION — would this suite actually catch a regression? ─────────────
// A passing test proves nothing unless it fails when the fix is removed. Rebuild
// the resolver with the OLD `id DESC` tie-break and re-run §2's assertion against
// it. The mutant MUST return the older event; if it does not, this suite is not
// testing what it claims and the ordering guarantee is unproven.
{
  const original = fs.readFileSync(engPath("alert-occurrence.js"), "utf8");
  const mutated = original.replace("ORDER BY created_at DESC, rowid DESC", "ORDER BY created_at DESC, id DESC");
  ok("the mutation actually applied (the fix is where this suite thinks it is)", mutated !== original);

  const tmp = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "cm-mutant-")), "alert-occurrence.mutant.js");
  fs.writeFileSync(tmp, mutated);
  const mutant = await import(pathToFileURL(tmp).href);

  const occ = await mutant.findConditionOccurrence(env, {
    workspace_id: "ws1", domain_key: "certificates_trust", record_id: "cl_tie", recurrence_type: "renewal_overdue",
  });
  // Under the mutant, 'zzz-older' outranks 'aaa-newer' on id DESC — the real defect,
  // reproduced. This is the assertion that gives §2 its meaning.
  eq("MUTANT (id DESC) resolves the OLDER event — the defect, reproduced", occ?.occurrence_id, "zzz-older");
  ok("MUTANT does not resolve the true latest append", occ?.occurrence_id !== "aaa-newer");

  // And the consequence that makes it fail-SILENT: the older occurrence's dedupe key
  // is what a real caller would build, so the newer alert is swallowed as a duplicate.
  const mutantKey = buildAlertDedupeKey({ domain_key: "certificates_trust", kind: "cert_renewal_overdue", subject: "www.example.com", period: occ.occurrence_id });
  const fixedOcc = await findConditionOccurrence(env, { workspace_id: "ws1", domain_key: "certificates_trust", record_id: "cl_tie", recurrence_type: "renewal_overdue" });
  const fixedKey = buildAlertDedupeKey({ domain_key: "certificates_trust", kind: "cert_renewal_overdue", subject: "www.example.com", period: fixedOcc.occurrence_id });
  ok("the mutant would build a DIFFERENT dedupe key — i.e. a real alert is lost", mutantKey !== fixedKey);

  fs.rmSync(path.dirname(tmp), { recursive: true, force: true });
}

globalThis.fetch = realFetch;
console.log(`\nalert-occurrence-ordering: ${pass} passed, ${fail} failed`);
if (fail > 0) { console.error("alert-occurrence-ordering validation FAILED"); process.exit(1); }
console.log("alert-occurrence-ordering validation passed");
