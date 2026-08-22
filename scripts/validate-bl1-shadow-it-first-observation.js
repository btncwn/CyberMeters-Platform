#!/usr/bin/env node
//
// BL-1 — Shadow IT first-observation surfacing. Node 24+ (node:sqlite).
//
// THE GAP THIS CLOSES. shadow-it-inventory.js writes an append-only `observed` event
// with `detail.created = 1` on insert and then CONTINUES without touching the alert
// pipeline, so a newly observed technology was genuinely silent: no alert (the
// managed path fires only after customer classification), and the weekly digest
// never read that table at all.
//
// WHAT IS AND IS NOT CLAIMED. Observation is not a verdict. The surfaced copy is a
// REVIEW PROMPT — "not yet reviewed" — never `unauthorised`/`unapproved`/`malicious`.
// Authority: EXECUTIVE-SCOPE-BL1-SHADOW-IT-FIRST-OBSERVATION-001 + FOUNDER-DECISION-007.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href;

const { shadowItFirstObservationsForWindow, buildDigestEmail, isoWeekKey } =
  await import(eng("weekly-digest.js"));
const { listShadowItInventory, SHADOW_IT_FIRST_OBSERVATION_SECTION } =
  await import(eng("shadow-it-inventory.js"));

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; console.log(`${c ? "PASS" : "FAIL"} ${n}${!c && d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering no-ops */ } };
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
    all: async () => ({ results: db.prepare(sql).all(...args) }),
    run: async () => { const r = db.prepare(sql).run(...args); return { meta: { changes: r.changes } }; },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
}

const db = buildDb();
const env = { cybermeters_db: makeD1(db) };
const WS = "ws-acme", FOREIGN = "ws-other";

let seq = 0;
function seedItem(ws, key, name, classification = "unreviewed") {
  const id = `sii-${++seq}`;
  db.prepare(
    `INSERT INTO shadow_it_inventory
       (id, workspace_id, canonical_technology_key, display_name, provider, category,
        source_type, observed_identifiers_json, observed_hostnames_json, observed_domains_json,
        first_seen_at, last_seen_at, confidence, classification, ownership_status,
        monitoring_status, source_evidence_json, created_at, updated_at)
     VALUES (?, ?, ?, ?, 'p', 'saas', 'vendor', '[]', '[]', '[]',
             datetime('now'), datetime('now'), 'high', ?, 'missing', 'observed', '[]',
             datetime('now'), datetime('now'))`
  ).run(id, ws, key, name, classification);
  return id;
}
// `created` mirrors the engine's own detail shape: the INSERT branch alone sets it.
function seedObservedEvent(ws, itemId, { created = true, ageDays = 0 } = {}) {
  db.prepare(
    `INSERT INTO shadow_it_inventory_events
       (id, item_id, workspace_id, actor_type, actor_id, event_type, detail_json, created_at)
     VALUES (?, ?, ?, 'system', NULL, 'observed', ?, datetime('now', ?))`
  ).run(`sie-${++seq}`, itemId, ws, JSON.stringify({ created }), `-${ageDays} days`);
}

const digestFor = async (ws) => {
  const obs = await shadowItFirstObservationsForWindow(env, ws, isoWeekKey());
  const email = buildDigestEmail("Acme", {
    customer_total: 0, customer_bySeverity: {}, customer_top: [], total: 0,
    bySeverity: {}, top: [], assessment: {}, lifecycle_review: { total: 0 },
    shadow_it_first_observations: obs,
  }, "https://app.cybermeters.com", ws);
  return { obs, email };
};

// ── PROOF 1 — deterministic fixture: first observation reaches the digest ────
{
  const slack = seedItem(WS, "slack", "Slack");
  seedObservedEvent(WS, slack, { created: true });
  const { obs, email } = await digestFor(WS);
  eq("BL1_P1_ONE_FIRST_OBSERVATION_COLLECTED", obs.count, 1);
  ok("BL1_P1_DIGEST_RENDERS_THE_SECTION", email.text.includes(SHADOW_IT_FIRST_OBSERVATION_SECTION));
  ok("BL1_P1_DIGEST_NAMES_THE_TECHNOLOGY", /Slack/.test(email.text), email.text.slice(-260));
  ok("BL1_P1_DIGEST_LINKS_TO_SHADOW_IT", /\/ws\/shadow-it/.test(email.text));
  ok("BL1_P1_DIGEST_MAKES_NO_VERDICT_CLAIM",
     !/unauthoris|unapproved|malicious/i.test(`${email.text}${email.html}`));
  // The section must survive the QUIET week, which is the first-scan case.
  ok("BL1_P1_SECTION_SURVIVES_A_ZERO_CHANGE_WEEK", email.text.includes("Newly observed"));
  // Dedupe identity is the SHARED alert shape, not a private scheme.
  ok("BL1_P1_OCCURRENCE_USES_THE_SHARED_DEDUPE_SHAPE",
     obs.items[0].occurrence_id === `shadow_it|first_observation|slack|${isoWeekKey()}`,
     obs.items[0].occurrence_id);
}

// ── PROOF 2 — a second scan of the same technology adds no duplicate ────────
{
  // A re-observation in the real engine carries no `created` flag; seed both that
  // and a pathological duplicate `created` row, so dedupe is proven, not assumed.
  const dupItem = db.prepare(`SELECT id FROM shadow_it_inventory WHERE workspace_id=? AND canonical_technology_key='slack'`).get(WS).id;
  seedObservedEvent(WS, dupItem, { created: false });
  seedObservedEvent(WS, dupItem, { created: true });
  const { obs, email } = await digestFor(WS);
  eq("BL1_P2_SECOND_SCAN_ADDS_NO_DUPLICATE", obs.count, 1);
  eq("BL1_P2_TECHNOLOGY_NAMED_EXACTLY_ONCE",
     (email.text.match(/Slack/g) || []).length, 1);
}

// ── PROOF 3 — NEGATIVE CONTROL: a reviewed technology does not re-surface ───
{
  const okta = seedItem(WS, "okta", "Okta", "approved");
  seedObservedEvent(WS, okta, { created: true });
  const { obs, email } = await digestFor(WS);
  ok("BL1_P3_REVIEWED_TECH_IS_NOT_NEWLY_OBSERVED",
     !obs.items.some((i) => i.technology_key === "okta"), JSON.stringify(obs.items));
  ok("BL1_P3_REVIEWED_TECH_IS_ABSENT_FROM_THE_DIGEST", !/Okta/.test(email.text));
  // POSITIVE CONTROL alongside it: the unreviewed one is still surfaced, so the
  // filter cannot pass by suppressing everything.
  ok("BL1_P3_POSITIVE_UNREVIEWED_TECH_STILL_SURFACED", /Slack/.test(email.text));
  // An observation older than the window is not "this week's" news — AND a long-known
  // technology that is merely SEEN AGAIN this week is not newly observed either.
  // Zoom carries both shapes: a first observation 30 days ago, plus a re-observation
  // inside the window. Only the `created` flag separates them, so this row is what
  // makes that filter load-bearing rather than decorative.
  const stale = seedItem(WS, "zoom", "Zoom");
  seedObservedEvent(WS, stale, { created: true, ageDays: 30 });
  seedObservedEvent(WS, stale, { created: false, ageDays: 1 });
  const later = await digestFor(WS);
  ok("BL1_P3_STALE_OBSERVATION_IS_OUT_OF_WINDOW", !/Zoom/.test(later.email.text),
     later.email.text.slice(-260));
  ok("BL1_P3_REOBSERVED_KNOWN_TECH_IS_NOT_NEWLY_OBSERVED",
     !later.obs.items.some((i) => i.technology_key === "zoom"), JSON.stringify(later.obs.items));
}

// ── PROOF 4 — TENANT ISOLATION ─────────────────────────────────────────────
{
  const foreign = seedItem(FOREIGN, "notion", "Notion");
  seedObservedEvent(FOREIGN, foreign, { created: true });
  const mine = await digestFor(WS);
  ok("BL1_P4_FOREIGN_TECH_ABSENT_FROM_MY_DIGEST", !/Notion/.test(mine.email.text));
  ok("BL1_P4_MY_TECH_STILL_PRESENT", /Slack/.test(mine.email.text));
  const theirs = await digestFor(FOREIGN);
  ok("BL1_P4_FOREIGN_WORKSPACE_SEES_ONLY_ITS_OWN", /Notion/.test(theirs.email.text) && !/Slack/.test(theirs.email.text));
  // The in-app indicator is workspace-scoped through the SAME event and window.
  const mineList = await listShadowItInventory(env, WS, {});
  const theirsList = await listShadowItInventory(env, FOREIGN, {});
  ok("BL1_P4_INDICATOR_IS_WORKSPACE_SCOPED",
     mineList.every((i) => i.workspace_id === WS) && theirsList.every((i) => i.workspace_id === FOREIGN));
  const slackRow = mineList.find((i) => i.canonical_technology_key === "slack");
  const oktaRow = mineList.find((i) => i.canonical_technology_key === "okta");
  ok("BL1_P4_INDICATOR_SET_FOR_NEW_UNREVIEWED", slackRow?.newly_observed === true, JSON.stringify(slackRow?.newly_observed));
  ok("BL1_P4_INDICATOR_CLEAR_FOR_REVIEWED", oktaRow?.newly_observed === false, JSON.stringify(oktaRow?.newly_observed));
  ok("BL1_P4_INDICATOR_AGREES_WITH_THE_DIGEST",
     (mineList.filter((i) => i.newly_observed === true).map((i) => i.canonical_technology_key).sort().join(","))
     === (mine.obs.items.map((i) => i.technology_key).sort().join(",")));
}

// ── Fail-closed: an unreadable window says NOTHING, never an invented zero ──
{
  const broken = { cybermeters_db: { prepare() { throw new Error("d1 down"); } } };
  const obs = await shadowItFirstObservationsForWindow(broken, WS, isoWeekKey());
  eq("BL1_FAILCLOSED_UNREADABLE_WINDOW_IS_NOT_EVALUATED", obs.evaluated, false);
  eq("BL1_FAILCLOSED_COUNT_IS_NULL_NOT_ZERO", obs.count, null);
  const email = buildDigestEmail("Acme", {
    customer_total: 0, customer_bySeverity: {}, customer_top: [], total: 0, bySeverity: {},
    top: [], assessment: {}, lifecycle_review: { total: 0 }, shadow_it_first_observations: obs,
  }, "https://app.cybermeters.com", WS);
  ok("BL1_FAILCLOSED_DIGEST_SAYS_NOTHING", !email.text.includes("Newly observed"));
}

console.log(`\nBL-1 shadow-it first observation: ${pass}/${pass + fail} assertions passed`);
if (fail > 0) { console.error("BL-1 validation FAILED"); process.exit(1); }
console.log("BL-1 validation passed");
