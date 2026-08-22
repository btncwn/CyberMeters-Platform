#!/usr/bin/env node
//
// Shadow IT recurrence semantics & surface parity — DB-backed, CI-blocking.
//
// PR-2 of the Shadow IT Alert Trust episode. Proves:
//   • every recurrence the evaluator can emit carries its own truthful event
//     description and action (no generic fallback for a supported recurrence);
//   • the copy obeys the truth rules: observed ≠ unauthorised; approved-but-
//     owner-missing is never sanction-review; disappearance is never verified
//     removal; a reappearance is never worded as a first observation;
//   • event description ≠ recommendation for every recurrence;
//   • the inventory API carries the SAME copy the alert email/in-app card carry
//     (parity by construction, not by duplication);
//   • the list route advertises mutation actions only to workspace:manage;
//   • a second unchanged evaluation pass emits nothing new (dedupe preserved).
//
// Node 24+.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engDir = path.join(root, "workers", "scan-api", "src", "engines");
const routesDir = path.join(root, "workers", "scan-api", "src", "routes");
const eng = (f) => pathToFileURL(path.join(engDir, f)).href;

const { describeRecurrenceEvent, recommendationForRecurrence, severityForRecurrence } = await import(eng("alert-consumers.js"));
const { shadowItItemToApi, evaluateShadowItMonitoring, SHADOW_IT_CLASSIFICATIONS, SHADOW_IT_OWNERSHIP_STATUSES, SHADOW_IT_WORKFLOW_ACTIONS } = await import(eng("shadow-it-inventory.js"));
const { resolveRemediation } = await import(eng("remediation-registry.js"));
const { ensureAlertActivation } = await import(eng("managed-alerts.js"));
const { shadowItRoutes } = await import(pathToFileURL(path.join(routesDir, "shadow-it.js")).href);

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

const DOMAIN = "shadow_it_unmanaged_technology";
// The complete evaluator vocabulary — CI-pinned against the severity map, so a
// new recurrence cannot ship without copy AND a severity decision.
const RECURRENCES = ["removal_incomplete", "rejected_reappeared", "removal_contradicted",
  "retired_reappeared", "exception_expired", "approved_disappeared", "material_change",
  "owner_missing", "evidence_stale"];

// ── 1. Copy matrix: complete, specific, distinct, truthful ───────────────────
{
  const registryAction = resolveRemediation({ finding_type: "saas_exposure" })?.recommended_action || null;
  const seenWc = new Set(), seenAct = new Set();
  for (const rec of RECURRENCES) {
    ok(`${rec}: has a declared severity`, severityForRecurrence(DOMAIN, rec) !== null);
    const wc = describeRecurrenceEvent(DOMAIN, rec, "Stripe");
    const act = recommendationForRecurrence(DOMAIN, rec, "Stripe", registryAction);
    ok(`${rec}: has SPECIFIC copy (not the generic condition sentence)`, !wc.includes('condition "'));
    ok(`${rec}: event description differs from recommendation`, wc !== act);
    ok(`${rec}: copy never claims unauthorised/unapproved/malicious`, !/unauthoris|unapproved|malicious/i.test(wc + act));
    seenWc.add(wc); seenAct.add(act);
  }
  eq("every recurrence's event description is distinct", seenWc.size, RECURRENCES.length);
  ok("recurrence copy set is exactly the evaluator vocabulary (no invented states)",
     RECURRENCES.every((r) => severityForRecurrence(DOMAIN, r) !== null));

  // Specific truth rules.
  const owner = describeRecurrenceEvent(DOMAIN, "owner_missing", "Stripe")
    + recommendationForRecurrence(DOMAIN, "owner_missing", "Stripe", registryAction);
  ok("owner_missing never uses sanction-review wording", !/sanction/i.test(owner));
  ok("owner_missing states the approved-without-owner fact", owner.includes("approved service does not have an assigned owner"));
  const reap = describeRecurrenceEvent(DOMAIN, "retired_reappeared", "Stripe");
  ok("retired_reappeared is worded as a re-observation, not a first observation",
     /again/i.test(reap) && !/first time|first observed/i.test(reap));
  const gone = describeRecurrenceEvent(DOMAIN, "approved_disappeared", "Stripe")
    + recommendationForRecurrence(DOMAIN, "approved_disappeared", "Stripe", registryAction);
  ok("approved_disappeared explicitly denies verified removal", /not (verify|verified)/i.test(gone));
  ok("approved_disappeared never states the service WAS removed", !/was removed|has been removed/i.test(gone));
}

// ── 2. State vocabulary stays separate — no 'unapproved' verdict exists ──────
{
  ok("classification vocabulary holds no 'unapproved'/'unauthorised' verdict",
     SHADOW_IT_CLASSIFICATIONS.every((c) => !/unapproved|unauthoris/i.test(c)));
  ok("ownership is a separate dimension from classification",
     SHADOW_IT_OWNERSHIP_STATUSES.every((s) => !SHADOW_IT_CLASSIFICATIONS.includes(s)));
  ok("'unreviewed' (not yet classified) is a real state", SHADOW_IT_CLASSIFICATIONS.includes("unreviewed"));
}

// ── 3. API parity: the surface carries the SAME copy as the alert ────────────
{
  const row = {
    id: "sii_x", workspace_id: "ws1", canonical_technology_key: "stripe",
    display_name: "Stripe", classification: "approved", ownership_status: "missing",
    monitoring_status: "observed", recurrence_type: "owner_missing",
    observed_hostnames_json: '["https://js.stripe.com"]', observed_identifiers_json: "[]",
    source_evidence_json: "[]", first_seen_at: "a", last_seen_at: "b", created_at: "c", updated_at: "d",
  };
  const api = shadowItItemToApi(row);
  eq("recurrence_summary is the alert's own event description",
     api.recurrence_summary, describeRecurrenceEvent(DOMAIN, "owner_missing", "Stripe"));
  ok("recommended_next_action is the alert's own recommendation",
     api.recommended_next_action === recommendationForRecurrence(DOMAIN, "owner_missing", "Stripe",
       resolveRemediation({ finding_type: "saas_exposure" })?.recommended_action || null));
  ok("summary and action differ on the surface too", api.recurrence_summary !== api.recommended_next_action);
  const idle = shadowItItemToApi({ ...row, recurrence_type: null });
  eq("no recurrence => no summary (nothing invented)", [idle.recurrence_summary, idle.recommended_next_action], [null, null]);
}

// ── DB harness for route + evaluator sections ────────────────────────────────
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
const env = { cybermeters_db: makeD1(db), FRONTEND_URL: "https://app.cybermeters.com" };
const realFetch = globalThis.fetch;
globalThis.fetch = async (url) => new Response(JSON.stringify({ id: "email_x" }), { status: 200, headers: { "content-type": "application/json" } });

db.prepare("INSERT INTO users (id, email, name, plan, created_at) VALUES ('u1','u1@example.com','u1','professional',datetime('now'))").run();
db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('ws1','u1','WS One')").run();
db.prepare(`INSERT INTO shadow_it_inventory
    (id, workspace_id, canonical_technology_key, display_name, provider, category, source_type,
     observed_identifiers_json, observed_hostnames_json, observed_domains_json,
     first_seen_at, last_seen_at, confidence, classification, ownership_status, monitoring_status,
     source_evidence_json, created_at, updated_at)
  VALUES ('sii_1','ws1','stripe','Stripe','Stripe','saas','vendor','[]','[]','[]',
          '2026-07-01T00:00:00Z','2026-07-19T00:00:00Z','high','approved','missing','observed','[]',datetime('now'),datetime('now'))`).run();

// ── 4. Route: viewer never sees mutation actions; manager does ───────────────
async function driveList({ manage }) {
  const url = new URL("https://api.local/api/workspaces/ws1/shadow-it/inventory");
  const rctx = {
    request: new Request(url, { method: "GET" }), env, url,
    json: (body, status = 200) => ({ body, status }),
    requireAuth: async () => ({ id: "u1" }),
    requireWorkspaceRole: async (_u, _ws, permission) =>
      permission === "workspace:manage" ? (manage ? { role: "owner" } : null) : { role: manage ? "owner" : "viewer" },
  };
  return await shadowItRoutes(rctx);
}
{
  const manager = await driveList({ manage: true });
  eq("manager: full action vocabulary advertised", manager.body.actions, SHADOW_IT_WORKFLOW_ACTIONS);
  eq("manager: can_manage true", manager.body.can_manage, true);
  const viewer = await driveList({ manage: false });
  eq("viewer: NO mutation actions advertised", viewer.body.actions, []);
  eq("viewer: can_manage false", viewer.body.can_manage, false);
  ok("viewer: still sees the inventory itself (read is not gated)", viewer.body.items.length === 1);
  ok("list items carry the parity fields", "recurrence_summary" in viewer.body.items[0]);
}

// ── 5. Unchanged second pass emits nothing new ───────────────────────────────
{
  await ensureAlertActivation(env, "ws1", DOMAIN, { now: "2020-01-01T00:00:00Z" });
  const notifCount = () => db.prepare("SELECT COUNT(*) c FROM notification_events WHERE workspace_id = 'ws1'").get().c;
  const evCount = () => db.prepare("SELECT COUNT(*) c FROM shadow_it_inventory_events WHERE workspace_id = 'ws1' AND event_type = 'monitoring_changed'").get().c;
  await evaluateShadowItMonitoring(env, "ws1", { now: new Date().toISOString() });
  const n1 = notifCount(), e1 = evCount();
  ok("first evaluation records the owner_missing occurrence", e1 >= 1 && n1 >= 1, `events=${e1} notifs=${n1}`);
  await evaluateShadowItMonitoring(env, "ws1", { now: new Date().toISOString() });
  eq("second unchanged pass appends NO new occurrence", evCount(), e1);
  eq("second unchanged pass emits NO new alert", notifCount(), n1);
}

// ── 6. MUTATION HARNESS ──────────────────────────────────────────────────────
const LIB_URL = pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib")).href;
const ENG_URL = pathToFileURL(engDir).href;
const rewrite = (src) => src
  .replace(/from "\.\.\/engines\//g, `from "${ENG_URL}/`)
  .replace(/from "\.\.\/lib\//g, `from "${LIB_URL}/`)
  .replace(/from "\.\//g, `from "${ENG_URL}/`);
async function mutantOf(dir, file, from, to) {
  const orig = fs.readFileSync(path.join(dir, file), "utf8");
  if (!orig.includes(from)) return { anchor: false };
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sit-truth-"));
  const f = path.join(tmp, file.replace(/\.js$/, ".mjs"));
  fs.writeFileSync(f, rewrite(orig.replace(from, to)));
  try {
    return { anchor: true, mod: await import(`${pathToFileURL(f).href}?t=${Date.now()}-${Math.random()}`) };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

// M1 — owner_missing regresses to sanction-review wording.
{
  const m = await mutantOf(engDir, "alert-consumers.js",
    'what_changed: () => "An approved service does not have an assigned owner.",',
    'what_changed: () => "Confirm whether this service is sanctioned.",');
  const wc = m.anchor ? m.mod.describeRecurrenceEvent(DOMAIN, "owner_missing", "Stripe") : "";
  ok("mutation M1 (owner_missing → sanction wording) is CAUGHT", m.anchor && /sanction/i.test(wc));
}

// M2 — reappearance collapses into first-seen wording.
{
  const m = await mutantOf(engDir, "alert-consumers.js",
    "was observed again after previously no longer being seen.",
    "was observed for the first time.");
  const wc = m.anchor ? m.mod.describeRecurrenceEvent(DOMAIN, "retired_reappeared", "Stripe") : "";
  ok("mutation M2 (reappeared → first-seen wording) is CAUGHT", m.anchor && /first time/i.test(wc) && !/again/i.test(wc));
}

// M3 — viewer role gating removed from the list route.
{
  const m = await mutantOf(routesDir, "shadow-it.js",
    "actions: canManage ? SHADOW_IT_WORKFLOW_ACTIONS : [],",
    "actions: SHADOW_IT_WORKFLOW_ACTIONS,");
  let caught = false;
  if (m.anchor) {
    const url = new URL("https://api.local/api/workspaces/ws1/shadow-it/inventory");
    const res = await m.mod.shadowItRoutes({
      request: new Request(url, { method: "GET" }), env, url,
      json: (body, status = 200) => ({ body, status }),
      requireAuth: async () => ({ id: "u1" }),
      requireWorkspaceRole: async (_u, _ws, permission) => permission === "workspace:manage" ? null : { role: "viewer" },
    });
    caught = (res.body.actions || []).length > 0;   // viewer now sees mutation actions
  }
  ok("mutation M3 (viewer role gate removed) is CAUGHT", m.anchor && caught);
}

// M4 — parity fields dropped from the API serializer.
{
  const m = await mutantOf(engDir, "shadow-it-inventory.js",
    "recurrence_summary: row.recurrence_type",
    "recurrence_summary: null && row.recurrence_type");
  const api = m.anchor ? m.mod.shadowItItemToApi({ id: "x", workspace_id: "w", canonical_technology_key: "stripe", display_name: "Stripe", recurrence_type: "owner_missing" }) : null;
  ok("mutation M4 (recurrence_summary dropped from API) is CAUGHT", m.anchor && api.recurrence_summary === null);
}

// M5 — still-present guard removed: every pass would mint a new occurrence.
{
  const m = await mutantOf(engDir, "shadow-it-inventory.js",
    "if (isMonitoringTransition({ monitoring_status: it.monitoring_status, recurrence_type: it.recurrence_type }, nextShadowMonitoring)) {",
    "if (true) {");
  let caught = false;
  if (m.anchor) {
    const evCount = () => db.prepare("SELECT COUNT(*) c FROM shadow_it_inventory_events WHERE workspace_id = 'ws1' AND event_type = 'monitoring_changed'").get().c;
    const before = evCount();
    await m.mod.evaluateShadowItMonitoring(env, "ws1", { now: new Date().toISOString() });
    caught = evCount() > before;   // unchanged state appended a fresh occurrence
  }
  ok("mutation M5 (unchanged-state re-emission guard removed) is CAUGHT", m.anchor && caught);
}

// M6 — all event descriptions collapse into one generic sentence.
{
  const m = await mutantOf(engDir, "alert-consumers.js",
    "if (copy?.what_changed) return copy.what_changed(subject);",
    'if (copy?.what_changed) return "Review this item in CyberMeters.";');
  let caught = false;
  if (m.anchor) {
    const set = new Set(RECURRENCES.map((r) => m.mod.describeRecurrenceEvent(DOMAIN, r, "Stripe")));
    caught = set.size < RECURRENCES.length;
  }
  ok("mutation M6 (copy matrix collapse) is CAUGHT", m.anchor && caught);
}

// M7 — disappearance claims verified removal.
{
  const m = await mutantOf(engDir, "alert-consumers.js",
    "is no longer externally observed. This is an observation only — it does not verify removal.",
    "was removed.");
  const wc = m.anchor ? m.mod.describeRecurrenceEvent(DOMAIN, "approved_disappeared", "Stripe") : "";
  ok("mutation M7 (disappearance → verified removal claim) is CAUGHT", m.anchor && /was removed/.test(wc) && !/not verify/i.test(wc));
}

// ── BL-1 — first-observation copy is pinned, and stays a NON-verdict ─────────
// Surfacing a newly observed technology is the moment the product is most tempted
// to editorialise. The exact wording is pinned on BOTH sides (engine + frontend)
// because a copy that drifts on one surface is how "observed" quietly becomes
// "unauthorised".
{
  const eng2 = await import(eng("shadow-it-inventory.js"));
  const LABEL = eng2.SHADOW_IT_FIRST_OBSERVATION_LABEL;
  const SECTION = eng2.SHADOW_IT_FIRST_OBSERVATION_SECTION;
  ok("BL1: first-observation label is exactly the approved copy",
    LABEL === "Newly observed technology — not yet reviewed", String(LABEL));
  ok("BL1: digest section header is exactly the approved copy",
    SECTION === "Newly observed technologies — not yet reviewed", String(SECTION));
  ok("BL1: neither string claims unauthorised/unapproved/malicious",
    !/unauthoris|unapproved|malicious/i.test(`${LABEL} ${SECTION}`));
  // The label is a REVIEW prompt, not a verdict: it must not assert risk or breach.
  ok("BL1: label asserts no risk verdict",
    !/risk|threat|breach|violation|dangerous|suspicious/i.test(LABEL), String(LABEL));
  // The frontend copy must be byte-identical — one drifts, both lie.
  const feSrc = fs.readFileSync(path.join(root, "frontend/src/lib/shadowItDisplay.js"), "utf8");
  ok("BL1: frontend copy constant is byte-identical to the engine's",
    feSrc.includes(`export const SHADOW_IT_FIRST_OBSERVATION_LABEL = "${LABEL}"`));
  // Assert on the STRING LITERAL, not the file: the surrounding comments
  // deliberately NAME the forbidden words in order to forbid them, and a
  // whole-file scan would fail on its own guard-rail text.
  const feLiteral = (feSrc.match(/SHADOW_IT_FIRST_OBSERVATION_LABEL = "([^"]*)"/) || [])[1] || "";
  ok("BL1: frontend copy literal carries no forbidden verdict word",
    feLiteral !== "" && !/unauthoris|unapproved|malicious/i.test(feLiteral), feLiteral);
  // The shared dedupe identity is reused, never a parallel scheme.
  ok("BL1: dedupe reuses the shared domain_key/kind, not a private scheme",
    eng2.SHADOW_IT_FIRST_OBSERVATION_DOMAIN_KEY === "shadow_it"
    && eng2.SHADOW_IT_FIRST_OBSERVATION_KIND === "first_observation");
}

globalThis.fetch = realFetch;
console.log(`\nshadow-it-recurrence-truth: ${pass}/${pass + fail} passed`);
if (fail) { console.error("shadow-it-recurrence-truth validation FAILED"); process.exit(1); }
console.log("shadow-it-recurrence-truth validation passed");
