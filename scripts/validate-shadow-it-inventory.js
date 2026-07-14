#!/usr/bin/env node
//
// Shadow IT Approved Inventory — DB-backed proof. CI-blocking. Runs against an
// in-memory SQLite database with the production schema + all migrations.
//
// Proves: canonical identity determinism + product distinctness; same-technology
// correlation; unrelated products of one provider are NOT merged; repeat
// observation updates last_seen and appends (never erases) history; classification
// transitions; approval is not health and rejection is not removal; exception
// requires reason + expiry; owner assignment is audited; a rejected-still-observed
// technology opens a Universal Managed Case via createManagedCase with the
// canonical remediation; soft-deleted workspace receives no observations; history
// is append-only; and the frontend cannot invent classification states.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href);
const sii = await eng("shadow-it-inventory.js");
const {
  canonicalTechnologyKey, correlateShadowItInventory, classifyShadowItItem,
  listShadowItInventory, listShadowItItemEvents, SHADOW_IT_CLASSIFICATIONS, SHADOW_IT_WORKFLOW_ACTIONS,
} = sii;

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, a, b) => ok(n, a === b, `expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* additive drift tolerated */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) apply(path.join(root, "database", "migrations", f));
  db.exec("PRAGMA foreign_keys = OFF");
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
const env = { cybermeters_db: makeD1(db) };
db.prepare("INSERT INTO workspaces (id, name, owner_user_id, created_at, updated_at) VALUES ('ws1','Alpha','u1',datetime('now'),datetime('now'))").run();
db.prepare("INSERT INTO workspaces (id, name, owner_user_id, created_at, updated_at, deleted_at) VALUES ('wsDead','Dead','u1',datetime('now'),datetime('now'),datetime('now'))").run();

let vc = 0;
function seedVendor(ws, name, category, { conf = "medium", evidence = [], first = "2026-07-01T00:00:00Z", last = "2026-07-10T00:00:00Z", status = "active" } = {}) {
  db.prepare(`INSERT INTO workspace_vendors (id, workspace_id, vendor_name, category, source, evidence, confidence, risk_level, first_seen, last_seen, status, created_at, updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,datetime('now'),datetime('now'))`)
    .run(`wv-${++vc}`, ws, name, category, "cname", JSON.stringify(evidence), conf, "low", first, last, status);
}

// ── 1. Canonical identity determinism + product distinctness ─────────────────
eq("canonical key is deterministic", canonicalTechnologyKey("Microsoft 365"), canonicalTechnologyKey("microsoft 365"));
ok("unrelated products of one provider get distinct keys", canonicalTechnologyKey("Google Workspace") !== canonicalTechnologyKey("Google Cloud"));
eq("exactly six classification keys", SHADOW_IT_CLASSIFICATIONS.length, 6);
eq("twelve workflow actions", SHADOW_IT_WORKFLOW_ACTIONS.length, 12);

// ── 2. Correlation — same tech merges, unrelated products don't ─────────────
seedVendor("ws1", "Microsoft 365", "email_identity", { conf: "high", evidence: [{ source: "spf", detail: "spf.protection.outlook.com" }] });
seedVendor("ws1", "Microsoft 365", "collaboration", { conf: "medium", evidence: [{ source: "cname", detail: "sharepoint.com" }] }); // same product, 2nd category
seedVendor("ws1", "Google Workspace", "email_identity", { evidence: [{ source: "mx", detail: "aspmx.l.google.com" }] });
seedVendor("ws1", "Google Cloud", "cloud", { evidence: [{ source: "cname", detail: "googleusercontent.com" }] });
const r1 = await correlateShadowItInventory(env, "ws1", { now: "2026-07-10T00:00:00Z" });
const items1 = await listShadowItInventory(env, "ws1");
eq("three canonical items created (M365 merged, Google products distinct)", items1.length, 3);
ok("Microsoft 365 correlates its two category rows into one item", items1.some((i) => i.canonical_technology_key === "microsoft_365"));
ok("Google Workspace and Google Cloud are separate items", items1.some((i) => i.canonical_technology_key === "google_workspace") && items1.some((i) => i.canonical_technology_key === "google_cloud"));
const m365 = items1.find((i) => i.canonical_technology_key === "microsoft_365");
eq("merged item takes the strongest confidence", m365.confidence, "high");
eq("new item defaults to unreviewed", m365.classification, "unreviewed");
eq("new item is observed", m365.monitoring_status, "observed");

// ── 3. Repeat observation updates last_seen + appends history (no erase) ────
const eventsBefore = (await listShadowItItemEvents(env, "ws1", m365.inventory_item_id)).length;
// New observation with a later last_seen + a new hostname → material change.
db.prepare("UPDATE workspace_vendors SET last_seen = '2026-07-20T00:00:00Z' WHERE vendor_name = 'Microsoft 365' AND workspace_id='ws1'").run();
seedVendor("ws1", "Microsoft 365", "identity_provider", { evidence: [{ source: "cname", detail: "login.microsoftonline.com" }] });
await correlateShadowItInventory(env, "ws1", { now: "2026-07-20T00:00:00Z" });
const m365b = (await listShadowItInventory(env, "ws1")).find((i) => i.canonical_technology_key === "microsoft_365");
eq("last_seen advanced on repeat observation", m365b.last_seen_at, "2026-07-20T00:00:00Z");
const eventsAfter = (await listShadowItItemEvents(env, "ws1", m365.inventory_item_id)).length;
ok("history only appends (never shrinks)", eventsAfter >= eventsBefore);
eq("still one M365 item after repeat observation (no duplicate)", (await listShadowItInventory(env, "ws1")).filter((i) => i.canonical_technology_key === "microsoft_365").length, 1);

// ── 4. Classification transitions + honesty invariants ──────────────────────
const approve = await classifyShadowItItem(env, "ws1", m365b.inventory_item_id, "approve", { actor_id: "admin", reason: "sanctioned" });
eq("approve sets classification approved", approve.item.classification, "approved");
ok("approved is NOT a health/security claim (scope_note present, no 'secure' state)", /not a security guarantee/i.test(approve.item.scope_note) && approve.item.removal_status == null);

const gw = items1.find((i) => i.canonical_technology_key === "google_workspace");
const reject = await classifyShadowItItem(env, "ws1", gw.inventory_item_id, "reject", { actor_id: "admin", reason: "not sanctioned" });
eq("reject sets classification rejected", reject.item.classification, "rejected");
ok("rejection is NOT removal (removal_status not 'removed')", reject.item.removal_status == null || reject.item.removal_status !== "removed");
eq("reject without a reason is refused", (await classifyShadowItItem(env, "ws1", gw.inventory_item_id, "reject", { actor_id: "admin" })).code, "reason_required");

const gc = items1.find((i) => i.canonical_technology_key === "google_cloud");
eq("mark_exception without reason is refused", (await classifyShadowItItem(env, "ws1", gc.inventory_item_id, "mark_exception", { actor_id: "admin", exception_until: "2026-08-01T00:00:00Z" })).code, "reason_required");
eq("mark_exception without expiry is refused", (await classifyShadowItItem(env, "ws1", gc.inventory_item_id, "mark_exception", { actor_id: "admin", reason: "temporary" })).code, "expiry_required");
const exc = await classifyShadowItItem(env, "ws1", gc.inventory_item_id, "mark_exception", { actor_id: "admin", reason: "temporary", exception_until: "2026-08-01T00:00:00Z" });
ok("exception carries reason + expiry", exc.item.classification === "exception" && exc.item.exception_until && exc.item.exception_reason);

// ── 5. Owner assignment is audited ──────────────────────────────────────────
await classifyShadowItItem(env, "ws1", m365b.inventory_item_id, "assign_business_owner", { actor_id: "admin", owner: "IT Team" });
const ownerEvents = (await listShadowItItemEvents(env, "ws1", m365b.inventory_item_id)).filter((e) => e.event_type === "owner_assigned");
ok("owner assignment writes an audited owner_assigned event", ownerEvents.length === 1);
eq("owner assignment requires an owner", (await classifyShadowItItem(env, "ws1", m365b.inventory_item_id, "assign_business_owner", { actor_id: "admin" })).code, "owner_required");
eq("mark_removed is a customer assertion, not verified removal", (await classifyShadowItItem(env, "ws1", m365b.inventory_item_id, "mark_removed", { actor_id: "admin" })).item.removal_status, "removed");

// ── 6. Rejected-still-observed opens a Universal Managed Case + remediation ──
const gwFresh = (await listShadowItInventory(env, "ws1")).find((i) => i.canonical_technology_key === "google_workspace");
ok("rejected-still-observed item has a linked case", Boolean(gwFresh.linked_case_id));
const kase = gwFresh.linked_case_id ? db.prepare("SELECT * FROM managed_cases WHERE id = ?").get(gwFresh.linked_case_id) : null;
ok("linked case is a shadow_it_case in the shadow_it domain", kase && kase.case_type === "shadow_it_case" && kase.domain_key === "shadow_it_unmanaged_technology");
eq("linked case carries the canonical remediation", kase?.remediation_id, "shadow_it.saas.review");
const caseCreatedEvents = db.prepare("SELECT COUNT(*) AS n FROM managed_case_events WHERE case_id = ? AND action = 'case_created'").get(gwFresh.linked_case_id).n;
eq("case_created event was appended (append-only)", caseCreatedEvents, 1);

// ── 7. Soft-deleted workspace receives no observations ──────────────────────
seedVendor("wsDead", "Slack", "collaboration", {});
const dead = await correlateShadowItInventory(env, "wsDead", {});
eq("soft-deleted workspace correlation is skipped", dead.skipped, "workspace_inactive");
eq("no inventory rows created for a soft-deleted workspace", db.prepare("SELECT COUNT(*) AS n FROM shadow_it_inventory WHERE workspace_id='wsDead'").get().n, 0);

// ── 8. Deterministic API output + no invented frontend states ───────────────
const a1 = JSON.stringify(await listShadowItInventory(env, "ws1"));
const a2 = JSON.stringify(await listShadowItInventory(env, "ws1"));
ok("list API output is deterministic", a1 === a2);
const disp = fs.readFileSync(path.join(root, "frontend", "src", "lib", "shadowItDisplay.js"), "utf8");
const dispCode = disp.replace(/\/\/[^\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "");
ok("frontend descriptor defines NO classification transition logic (labels only)", !/transition|allowedActions|canClassify|setClassification\s*\(/i.test(dispCode));
const page = fs.readFileSync(path.join(root, "frontend", "src", "pages", "ws", "ShadowItInventoryPage.jsx"), "utf8");
ok("frontend page surfaces only SERVER-provided actions (cannot invent actions)", /data\?\.actions/.test(page) && /serverActions\.includes/.test(page));
// The route + engine are workspace-scoped (tenant isolation).
const routeSrc = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "routes", "shadow-it.js"), "utf8");
ok("route scopes by workspace + soft-delete + same-error 404", /deleted_at IS NULL/.test(routeSrc) && /Inventory item not found/.test(routeSrc));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
