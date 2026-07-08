#!/usr/bin/env node
//
// Integration tests for the access-control flows the pure-function contract
// tests can't reach — they need a database. Uses a REAL in-memory SQLite
// (node:sqlite) wrapped in a D1-compatible adapter, so the worker's actual SQL
// runs against a real engine (high fidelity, not a hand-programmed mock). The
// worker is loaded in the same vm sandbox as the other runners. Proves tenant
// isolation end to end. Exits non-zero on any failure so CI blocks.
//
// Requires Node 24+ (stable node:sqlite). CI pins the version via setup-node.
//
import fs from "node:fs";
import path from "node:path";
import { webcrypto } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const workerPath = path.join(__dirname, "..", "workers", "scan-api", "src", "index.js");

// ESM worker loading (vm-free): the worker is a real module since Sprint 9
// split it up — vm.runInContext cannot evaluate `import`. Network stays
// disabled and Workers-global stubs are applied process-wide before import.
async function loadAuthFns() {
  globalThis.fetch = async () => { throw new Error("network disabled"); };
  AbortSignal.timeout = () => undefined;
  return import(pathToFileURL(workerPath).href);
}

// ── D1-compatible adapter over node:sqlite ────────────────────────────────────
// Mirrors the subset of the D1 API the worker uses: prepare().bind().first()/
// .all()/.run(), plus prepare().first() without bind.
function makeD1(db) {
  const exec = (stmt, args) => ({
    first: async () => stmt.get(...args) ?? null,
    all:   async () => ({ results: stmt.all(...args) }),
    run:   async () => { const r = stmt.run(...args); return { meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid ?? 0) } }; },
  });
  return {
    prepare(sql) {
      const stmt = db.prepare(sql);
      const api = exec(stmt, []);
      api.bind = (...args) => exec(stmt, args);
      return api;
    },
  };
}

function seedDb() {
  const db = new DatabaseSync(":memory:");
  db.exec(`
    CREATE TABLE workspaces (id TEXT PRIMARY KEY, owner_user_id TEXT, name TEXT, deleted_at TEXT);
    CREATE TABLE workspace_members (id TEXT PRIMARY KEY, workspace_id TEXT, user_id TEXT, role TEXT);
  `);
  const ws = db.prepare("INSERT INTO workspaces (id, owner_user_id, name, deleted_at) VALUES (?, ?, ?, ?)");
  ws.run("ws1", "userA", "Alpha", null);           // has members
  ws.run("ws2", "userC", "Bravo", null);           // separate tenant
  ws.run("ws_legacy", "userD", "Legacy", null);    // owner, no members
  ws.run("ws_deleted", "userA", "Gone", "2026-01-01T00:00:00Z"); // soft-deleted
  const m = db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?, ?, ?, ?)");
  m.run("m1", "ws1", "userA", "admin");
  m.run("m2", "ws1", "userB", "viewer");
  m.run("m3", "ws2", "userC", "owner");
  return db;
}

let passed = 0, failed = 0;
const results = [];
async function ok(name, promiseOrBool) {
  const cond = typeof promiseOrBool === "boolean" ? promiseOrBool : await promiseOrBool;
  if (cond) { passed++; results.push(`PASS ${name}`); } else { failed++; results.push(`FAIL ${name}`); }
}

async function main() {
  const S = await loadAuthFns();
  const env = { cybermeters_db: makeD1(seedDb()) };
  const u = (id, extra = {}) => ({ id, ...extra });

  // ── Tenant isolation (the headline invariant) ──
  await ok("member of ws1 gets their role",
    (await S.requireWorkspaceAccess(u("userA"), "ws1", env))?.role === "admin");
  await ok("viewer of ws1 gets viewer role",
    (await S.requireWorkspaceAccess(u("userB"), "ws1", env))?.role === "viewer");
  await ok("CROSS-TENANT: userB (ws1) is DENIED ws2",
    (await S.requireWorkspaceAccess(u("userB"), "ws2", env)) === null);
  await ok("CROSS-TENANT: userA (ws1 owner+member) is DENIED ws2",
    (await S.requireWorkspaceAccess(u("userA"), "ws2", env)) === null);
  await ok("non-member of a foreign workspace is denied",
    (await S.requireWorkspaceAccess(u("userZ"), "ws1", env)) === null);

  // ── Legacy owner fallback (workspace with no member rows) ──
  await ok("legacy owner (no members) granted owner role",
    (await S.requireWorkspaceAccess(u("userD"), "ws_legacy", env))?.role === "owner");
  await ok("non-owner denied a legacy workspace",
    (await S.requireWorkspaceAccess(u("userA"), "ws_legacy", env)) === null);

  // ── Soft-deleted workspace is inaccessible even to the owner ──
  await ok("soft-deleted workspace denied to its owner",
    (await S.requireWorkspaceAccess(u("userA"), "ws_deleted", env)) === null);

  // ── API-token workspace boundary ──
  await ok("workspace-bound token can access its own workspace",
    (await S.requireWorkspaceAccess(u("userA", { token_workspace_id: "ws1" }), "ws1", env))?.role === "admin");
  await ok("workspace-bound token is DENIED a different workspace",
    (await S.requireWorkspaceAccess(u("userA", { token_workspace_id: "ws1" }), "ws2", env)) === null);

  // ── requireWorkspaceRole: access + RBAC permission together ──
  await ok("viewer cannot manage the workspace (role gate)",
    (await S.requireWorkspaceRole(u("userB"), "ws1", "workspace:manage", env)) === null);
  await ok("admin can manage the workspace",
    (await S.requireWorkspaceRole(u("userA"), "ws1", "workspace:manage", env))?.role === "admin");
  await ok("non-member cannot manage regardless of permission",
    (await S.requireWorkspaceRole(u("userB"), "ws2", "workspace:read", env)) === null);

  // ── getAccessibleWorkspaceIds: only what you may see ──
  const aIds = await S.getAccessibleWorkspaceIds(u("userA"), env);
  await ok("accessible list includes own membership (ws1)", aIds.includes("ws1"));
  await ok("accessible list excludes a foreign tenant (ws2)", !aIds.includes("ws2"));
  await ok("accessible list excludes soft-deleted workspaces", !aIds.includes("ws_deleted"));
  const dIds = await S.getAccessibleWorkspaceIds(u("userD"), env);
  await ok("legacy owner sees their legacy workspace", dIds.includes("ws_legacy"));
  const tIds = await S.getAccessibleWorkspaceIds(u("userA", { token_workspace_id: "ws1" }), env);
  await ok("token-bound accessible list is exactly its workspace", tIds.length === 1 && tIds[0] === "ws1");

  for (const line of results) if (line.startsWith("FAIL")) console.error(line);
  console.log(`\nIntegration tests: ${passed}/${passed + failed} passed`);
  if (failed > 0) { console.error("integration validation FAILED"); process.exit(1); }
  console.log("integration validation passed");
}

main().catch((e) => { console.error("integration runner crashed:", e); process.exit(1); });
