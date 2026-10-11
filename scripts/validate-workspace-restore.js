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
  `);
  return db;
}
const addWs = (db, id, owner, deletedAt, name = id) =>
  db.prepare("INSERT INTO workspaces VALUES (?,?,?,?,?)").run(id, name, owner, deletedAt, ago(90));
const addReq = (db, id, ws, status, createdAt) =>
  db.prepare("INSERT INTO deletion_requests VALUES (?,?,?,?,?,?,?,?)").run(id, "workspace", "u_owner", ws, "u_owner", status, createdAt, createdAt);

// D1 shim. `hooks` may intercept SQL: { match: RegExp, before?: fn(db), throws?: bool }.
function d1(db, hooks = []) {
  return {
    prepare(sql) {
      const hook = hooks.find((h) => h.match.test(sql));
      const st = db.prepare(sql);
      const guard = () => { if (hook?.throws) throw new Error("D1_ERROR: simulated"); hook?.before?.(db); };
      const bound = (...a) => ({
        all: async () => { guard(); return { results: st.all(...a) }; },
        first: async () => { guard(); return st.get(...a) ?? null; },
        run: async () => { guard(); const r = st.run(...a); return { meta: { changes: Number(r.changes) } }; },
      });
      return { bind: (...a) => bound(...a), all: async () => bound().all(), first: async () => bound().first(), run: async () => bound().run() };
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
  ok("restore: response explains schedules stay paused", /paused/i.test(body.note || ""));
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
{
  // The purge cron claims the request (pending -> purging) after our read but
  // before our cancel. The cancel CAS must lose and nothing may be restored.
  const db = createDb();
  addWs(db, "ws_race", "u_owner", ago(4)); addReq(db, "r_race", "ws_race", "pending", ago(4));
  const hooks = [{
    match: /UPDATE deletion_requests SET status = 'cancelled'/,
    before: (raw) => raw.prepare("UPDATE deletion_requests SET status = 'purging' WHERE id = 'r_race' AND status = 'pending'").run(),
  }];
  const [st] = await restore(db, "ws_race", { hooks });
  eq("race: purge wins → restore 409", st, 409);
  ok("race: workspace stays deleted while purging", deletedAt(db, "ws_race") !== null);
  eq("race: request remains purging", reqStatus(db, "r_race"), "purging");
}

console.log(`validate-workspace-restore: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
