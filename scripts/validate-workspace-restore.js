#!/usr/bin/env node
//
// Workspace restore — owner-only list of restorable soft-deleted workspaces
// (GET /api/account/deleted-workspaces) and the race-safe restore
// (POST /api/workspaces/:id/restore). DB-backed, CI-blocking, no network.
//
// Proves: tenant isolation (foreign == nonexistent), the purge window, no
// restore once permanent deletion started or finished, fail-closed reads, and
// that a purge claim racing the restore can never leave a restored workspace
// whose data is being purged.
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = (...p) => pathToFileURL(path.join(root, "workers", "scan-api", "src", ...p)).href;
const { workspacesCoreRoutes } = await import(src("routes", "workspaces-core.js"));

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) pass++;
  else { fail++; console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
};
const eq = (name, got, want) => ok(name, JSON.stringify(got) === JSON.stringify(want), `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);

const DAY = 86_400_000;
const ago = (days) => new Date(Date.now() - days * DAY).toISOString();
const WINDOW = 30;

function createDb() {
  const db = new DatabaseSync(":memory:");
  db.exec(`
    CREATE TABLE workspaces (id TEXT PRIMARY KEY, name TEXT, owner_user_id TEXT, deleted_at TEXT, created_at TEXT);
    CREATE TABLE deletion_requests (id TEXT PRIMARY KEY, request_type TEXT, user_id TEXT, workspace_id TEXT,
      requested_by TEXT, status TEXT, created_at TEXT, updated_at TEXT);
    CREATE TABLE audit_events (id TEXT, workspace_id TEXT, user_id TEXT, event_type TEXT, entity_type TEXT,
      entity_id TEXT, description TEXT, metadata TEXT, created_at TEXT);
    CREATE TABLE domains (id TEXT PRIMARY KEY, domain TEXT);
    CREATE TABLE workspace_domains (workspace_id TEXT, domain_id TEXT);
    CREATE TABLE workspace_assets (id TEXT PRIMARY KEY, workspace_id TEXT, domain_id TEXT, hostname TEXT,
      status TEXT, updated_at TEXT);
    CREATE TABLE scheduled_scans (id TEXT PRIMARY KEY, workspace_id TEXT, domain TEXT, enabled INTEGER);
  `);
  return db;
}
const addWs = (db, id, owner, deletedAt, name = id) =>
  db.prepare("INSERT INTO workspaces VALUES (?,?,?,?,?)").run(id, name, owner, deletedAt, ago(90));
const addReq = (db, id, ws, status, createdAt, type = "workspace", user = "u_owner") =>
  db.prepare("INSERT INTO deletion_requests VALUES (?,?,?,?,?,?,?,?)").run(id, type, user, ws, user, status, createdAt, createdAt);

// D1 shim. `hooks` may intercept SQL: { match: RegExp, before?: fn(db), throws?: bool }.
// batch() runs as ONE transaction (as D1 does): any failure rolls back all.
function d1(db, hooks = []) {
  const stmt = (sql) => {
    const hook = hooks.find((h) => h.match.test(sql));
    const st = db.prepare(sql);
    const guard = () => { if (hook?.throws) throw new Error("D1_ERROR: simulated"); hook?.before?.(db); };
    const bound = (...a) => ({
      _run: () => { guard(); const r = st.run(...a); return { meta: { changes: Number(r.changes) } }; },
      all: async () => { guard(); return { results: st.all(...a) }; },
      first: async () => { guard(); return st.get(...a) ?? null; },
      run: async () => { guard(); const r = st.run(...a); return { meta: { changes: Number(r.changes) } }; },
    });
    return { bind: (...a) => bound(...a), all: async () => bound().all(), first: async () => bound().first(), run: async () => bound().run(), _run: () => bound()._run() };
  };
  return {
    prepare: stmt,
    async batch(statements) {
      db.exec("BEGIN");
      try {
        const out = statements.map((s) => s._run());
        db.exec("COMMIT");
        return out;
      } catch (e) { db.exec("ROLLBACK"); throw e; }
    },
  };
}
function ctx(db, method, pathname, { user = { id: "u_owner" }, hooks = [] } = {}) {
  const request = new Request(`https://api.example${pathname}`, { method });
  return {
    request, url: new URL(request.url),
    env: { cybermeters_db: d1(db, hooks) },
    json: (body, status = 200) => Response.json(body, { status }),
    serverError: () => Response.json({ error: "server" }, { status: 500 }),
    requireAuth: async () => user,
    requireWorkspaceRole: async () => null,
    DELETION_PURGE_WINDOW_DAYS: WINDOW,
  };
}
async function call(db, method, p, opts) {
  const r = await workspacesCoreRoutes(ctx(db, method, p, opts));
  return [r?.status, r ? await r.json() : null];
}
const list = (db, opts) => call(db, "GET", "/api/account/deleted-workspaces", opts);
const restore = (db, id, opts) => call(db, "POST", `/api/workspaces/${id}/restore`, opts);
const deletedAt = (db, id) => db.prepare("SELECT deleted_at FROM workspaces WHERE id = ?").get(id)?.deleted_at ?? null;
const reqStatus = (db, id) => db.prepare("SELECT status FROM deletion_requests WHERE id = ?").get(id)?.status;

// ── List ────────────────────────────────────────────────────────────────────
{
  const db = createDb();
  addWs(db, "ws_recent", "u_owner", ago(2), "Recent");
  addWs(db, "ws_older", "u_owner", ago(10), "Older");
  addWs(db, "ws_active", "u_owner", null);
  addWs(db, "ws_expired", "u_owner", ago(WINDOW + 1));
  addWs(db, "ws_purging", "u_owner", ago(5)); addReq(db, "r_purging", "ws_purging", "purging", ago(5));
  addWs(db, "ws_done", "u_owner", ago(6)); addReq(db, "r_done", "ws_done", "completed", ago(6));
  addWs(db, "ws_pending", "u_owner", ago(3)); addReq(db, "r_pending", "ws_pending", "pending", ago(3));
  addWs(db, "ws_foreign", "u_other", ago(1));

  const [st, body] = await list(db);
  eq("list: owner → 200", st, 200);
  eq("list: only restorable own workspaces, newest first", body.workspaces.map((w) => w.id), ["ws_recent", "ws_pending", "ws_older"]);
  eq("list: window days exposed", body.restore_window_days, WINDOW);
  const recent = body.workspaces[0];
  ok("list: restorable_until = deleted_at + window",
    Math.abs(new Date(recent.restorable_until).getTime() - (new Date(recent.deleted_at).getTime() + WINDOW * DAY)) < 1000);
  ok("list: no foreign workspace leaks", !JSON.stringify(body).includes("ws_foreign"));
  eq("list: unauthenticated → 401", (await list(db, { user: null }))[0], 401);
  eq("list: API token → 403", (await list(db, { user: { id: "u_owner", api_token_id: "t" } }))[0], 403);
  const [errSt] = await list(db, { hooks: [{ match: /FROM workspaces w/, throws: true }] });
  eq("list: read failure → 503 (never an empty list)", errSt, 503);
  eq("list: other owner sees only their own", (await list(db, { user: { id: "u_other" } }))[1].workspaces.map((w) => w.id), ["ws_foreign"]);
}

// ── Restore: authorisation and refusals ─────────────────────────────────────
{
  const db = createDb();
  addWs(db, "ws_foreign", "u_other", ago(1));
  addWs(db, "ws_live", "u_owner", null);
  addWs(db, "ws_expired", "u_owner", ago(WINDOW + 1));
  addWs(db, "ws_purging", "u_owner", ago(5)); addReq(db, "r_purging", "ws_purging", "purging", ago(5));
  addWs(db, "ws_done", "u_owner", ago(6)); addReq(db, "r_done", "ws_done", "completed", ago(6));

  eq("restore: unauthenticated → 401", (await restore(db, "ws_foreign", { user: null }))[0], 401);
  eq("restore: API token → 403", (await restore(db, "ws_live", { user: { id: "u_owner", api_token_id: "t" } }))[0], 403);
  const foreign = await restore(db, "ws_foreign");
  const missing = await restore(db, "ws_does_not_exist");
  eq("restore: foreign → 403", foreign[0], 403);
  eq("restore: foreign and nonexistent are indistinguishable", foreign, missing);
  ok("restore: foreign workspace untouched", deletedAt(db, "ws_foreign") !== null);
  eq("restore: not deleted → 400", (await restore(db, "ws_live"))[0], 400);
  eq("restore: window passed → 409", (await restore(db, "ws_expired"))[0], 409);
  ok("restore: expired stays deleted", deletedAt(db, "ws_expired") !== null);
  eq("restore: purge started → 409", (await restore(db, "ws_purging"))[0], 409);
  ok("restore: purging stays deleted", deletedAt(db, "ws_purging") !== null);
  eq("restore: purge completed → 409", (await restore(db, "ws_done"))[0], 409);
}

// ── Restore: success paths ──────────────────────────────────────────────────
{
  const db = createDb();
  addWs(db, "ws_a", "u_owner", ago(4)); addReq(db, "r_a", "ws_a", "pending", ago(4));
  const [st, body] = await restore(db, "ws_a");
  eq("restore: owner inside window → 200", st, 200);
  eq("restore: response says restored", body.restored, true);
  ok("restore: response says monitoring resumes", /resumes/i.test(body.note || ""));
  eq("restore: workspace is live again", deletedAt(db, "ws_a"), null);
  eq("restore: pending purge request cancelled", reqStatus(db, "r_a"), "cancelled");
  eq("restore: second restore → 400 (not deleted)", (await restore(db, "ws_a"))[0], 400);
}
{
  const db = createDb();
  addWs(db, "ws_legacy", "u_owner", ago(4)); // no deletion_requests row at all
  eq("restore: legacy delete without request row → 200", (await restore(db, "ws_legacy"))[0], 200);
  eq("restore: legacy workspace live", deletedAt(db, "ws_legacy"), null);
}

// ── Restore: fail closed and race safety ────────────────────────────────────
{
  const db = createDb();
  addWs(db, "ws_b", "u_owner", ago(4)); addReq(db, "r_b", "ws_b", "pending", ago(4));
  const [st] = await restore(db, "ws_b", { hooks: [{ match: /SELECT id, status, created_at FROM deletion_requests/, throws: true }] });
  eq("restore: deletion-request read failure → 503", st, 503);
  ok("restore: read failure leaves workspace deleted", deletedAt(db, "ws_b") !== null);
  eq("restore: read failure leaves request pending", reqStatus(db, "r_b"), "pending");
}

// ── P1: more than one open request ──────────────────────────────────────────
{
  // Older request already purging + newer pending: both sides must NOT win.
  const db = createDb();
  addWs(db, "ws_two", "u_owner", ago(5));
  addReq(db, "r_old", "ws_two", "purging", ago(31));
  addReq(db, "r_new", "ws_two", "pending", ago(5));
  eq("two rows: any purging row → 409", (await restore(db, "ws_two"))[0], 409);
  ok("two rows: workspace stays deleted", deletedAt(db, "ws_two") !== null);
  eq("two rows: newer pending request untouched", reqStatus(db, "r_new"), "pending");
  eq("two rows: hidden from the list", (await list(db))[1].workspaces.map((w) => w.id), []);
}
{
  // Two pending rows (double submit): restore cancels BOTH so no purge remains.
  const db = createDb();
  addWs(db, "ws_dup", "u_owner", ago(3));
  addReq(db, "r_dup1", "ws_dup", "pending", ago(4));
  addReq(db, "r_dup2", "ws_dup", "pending", ago(3));
  eq("duplicate pending: restore → 200", (await restore(db, "ws_dup"))[0], 200);
  eq("duplicate pending: both requests cancelled", [reqStatus(db, "r_dup1"), reqStatus(db, "r_dup2")], ["cancelled", "cancelled"]);
}
{
  // A re-used old pending request makes the purge due earlier than deleted_at.
  const db = createDb();
  addWs(db, "ws_clock", "u_owner", ago(5));
  addReq(db, "r_clock", "ws_clock", "pending", ago(WINDOW + 1));
  eq("old request clock: hidden from the list", (await list(db))[1].workspaces.map((w) => w.id), []);
  eq("old request clock: restore → 409", (await restore(db, "ws_clock"))[0], 409);
  ok("old request clock: still deleted", deletedAt(db, "ws_clock") !== null);
}
{
  const db = createDb();
  addWs(db, "ws_clock2", "u_owner", ago(5));
  addReq(db, "r_clock2", "ws_clock2", "pending", ago(20));
  const w = (await list(db))[1].workspaces[0];
  ok("deadline uses the older request clock",
    Math.abs(new Date(w.restorable_until).getTime() - (Date.now() - 20 * DAY + WINDOW * DAY)) < 5000, w?.restorable_until);
}
{
  const db = createDb();
  addWs(db, "ws_nan", "u_owner", "not-a-date");
  eq("unparseable deleted_at: restore → 409", (await restore(db, "ws_nan"))[0], 409);
  eq("unparseable deleted_at: not listed", (await list(db))[1].workspaces.length, 0);
}
{
  const db = createDb();
  addWs(db, "ws_acct", "u_owner", ago(2));
  addReq(db, "r_acct", null, "pending", ago(1), "account", "u_owner");
  eq("account deletion pending: list is empty", (await list(db))[1].workspaces.length, 0);
  const [st, body] = await restore(db, "ws_acct");
  eq("account deletion pending: restore → 409", st, 409);
  ok("account deletion pending: says why", /account is scheduled for deletion/.test(body.error));
  ok("account deletion pending: still deleted", deletedAt(db, "ws_acct") !== null);
}

// ── P2: atomicity, true undo, honest outcomes ───────────────────────────────
function seedMonitoring(db, ws) {
  db.prepare("INSERT INTO domains VALUES (?,?)").run("d_linked", "linked.example");
  db.prepare("INSERT INTO domains VALUES (?,?)").run("d_removed", "removed.example");
  db.prepare("INSERT INTO workspace_domains VALUES (?,?)").run(ws, "d_linked");
  const a = db.prepare("INSERT INTO workspace_assets VALUES (?,?,?,?,?,?)");
  a.run("a1", ws, "d_linked", "www.linked.example", "inactive", ago(5));
  a.run("a2", ws, "d_removed", "www.removed.example", "inactive", ago(9));
  a.run("a3", "ws_other", "d_linked", "x.linked.example", "inactive", ago(5));
  const sc = db.prepare("INSERT INTO scheduled_scans VALUES (?,?,?,?)");
  sc.run("s1", ws, "linked.example", 0);
  sc.run("s2", ws, "removed.example", 0);
  sc.run("s3", "ws_other", "linked.example", 0);
}
const assetStatus = (db, id) => db.prepare("SELECT status FROM workspace_assets WHERE id = ?").get(id).status;
const schedEnabled = (db, id) => db.prepare("SELECT enabled FROM scheduled_scans WHERE id = ?").get(id).enabled;
{
  const db = createDb();
  addWs(db, "ws_mon", "u_owner", ago(5)); addReq(db, "r_mon", "ws_mon", "pending", ago(5));
  seedMonitoring(db, "ws_mon");
  const [st, body] = await restore(db, "ws_mon");
  eq("undo: restore → 200", st, 200);
  eq("undo: linked-domain asset active again", assetStatus(db, "a1"), "active");
  eq("undo: removed-domain asset stays inactive", assetStatus(db, "a2"), "inactive");
  eq("undo: other workspace asset untouched", assetStatus(db, "a3"), "inactive");
  eq("undo: linked-domain schedule re-enabled", schedEnabled(db, "s1"), 1);
  eq("undo: removed-domain schedule stays off", schedEnabled(db, "s2"), 0);
  eq("undo: other workspace schedule untouched", schedEnabled(db, "s3"), 0);
  eq("undo: response reports what resumed", [body.reactivated_assets, body.reenabled_schedules], [1, 1]);
}
{
  // A failure inside the batch rolls everything back: no stranded state.
  const db = createDb();
  addWs(db, "ws_mid", "u_owner", ago(5)); addReq(db, "r_mid", "ws_mid", "pending", ago(5));
  seedMonitoring(db, "ws_mid");
  const [st] = await restore(db, "ws_mid", { hooks: [{ match: /UPDATE workspace_assets SET status = 'active'/, throws: true }] });
  eq("mid-batch failure → 500", st, 500);
  ok("mid-batch failure: workspace still deleted", deletedAt(db, "ws_mid") !== null);
  eq("mid-batch failure: request still pending (purge can proceed)", reqStatus(db, "r_mid"), "pending");
  eq("mid-batch failure: schedule still off", schedEnabled(db, "s1"), 0);
}
{
  // Purge claim lands just before the batch: guarded undelete changes nothing.
  const db = createDb();
  addWs(db, "ws_late", "u_owner", ago(5)); addReq(db, "r_late", "ws_late", "pending", ago(5));
  seedMonitoring(db, "ws_late");
  const hooks = [{
    match: /UPDATE workspaces SET deleted_at = NULL/,
    before: (raw) => raw.prepare("UPDATE deletion_requests SET status = 'purging' WHERE id = 'r_late' AND status = 'pending'").run(),
  }];
  const [st] = await restore(db, "ws_late", { hooks });
  eq("late purge claim → 409", st, 409);
  ok("late purge claim: still deleted", deletedAt(db, "ws_late") !== null);
  eq("late purge claim: request stays purging", reqStatus(db, "r_late"), "purging");
  eq("late purge claim: nothing reactivated", [assetStatus(db, "a1"), schedEnabled(db, "s1")], ["inactive", 0]);
}
{
  // Second tab restores first: honest message, no second success.
  const db = createDb();
  addWs(db, "ws_tab", "u_owner", ago(5)); addReq(db, "r_tab", "ws_tab", "pending", ago(5));
  const hooks = [{
    match: /UPDATE workspaces SET deleted_at = NULL/,
    before: (raw) => raw.prepare("UPDATE workspaces SET deleted_at = NULL WHERE id = 'ws_tab'").run(),
  }];
  const [st, body] = await restore(db, "ws_tab", { hooks });
  eq("concurrent restore → 409", st, 409);
  ok("concurrent restore: says already restored", /already been restored/.test(body.error));
}

console.log(`validate-workspace-restore: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
