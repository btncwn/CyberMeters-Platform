#!/usr/bin/env node
//
// CE answer re-versioning contract + question-set version format. CI-blocking.
//
// ── THE DEFECT THIS EXISTS TO PREVENT (shipped live in a08285e4, caught in review) ──
// The authenticated page submits the FULL questionnaire on every save, not a delta:
//   saveAnswers() → flattenAnswers(answers) → all 20 answers, untouched ones included.
// The first cut of mig 092's writer did `question_set_version = excluded.question_set_version`
// unconditionally, so ONE edit re-stamped ALL 20 rows with the active version — silently
// relabelling 19 untouched answers as answers to the CURRENT wording, including the patch
// question reworded from "applied quickly" to "within 14 days of release", which those
// customers never saw. A no-op save did the same.
//
// ── THE ONE RULE ──
//   THE ANSWER IS THE ATTESTATION. The version moves only when the answer does.
//   note-only edit → keep the version (a note is context ABOUT an attestation).
//   no-op          → write nothing at all.
//
// It is enforced in SQL, against the REAL route, because a client-side delta would be
// bypassed by any crafted or future client. Every assertion below drives the actual
// workspaceAnalyticsRoutes PUT handler with a real DB.
//
// Node 24+.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const srcPath = (...p) => path.join(root, "workers", "scan-api", "src", ...p);

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

const shared = await import(pathToFileURL(path.join(root, "shared", "cyber-essentials-questions.js")).href);
const { CE_QUESTIONS, CE_QUESTION_SET_VERSION, CE_QUESTION_SET_PROVENANCE, CE_QUESTION_SET_VERSION_FORMAT } = shared;
const { workspaceAnalyticsRoutes } = await import(pathToFileURL(srcPath("routes", "workspace-analytics.js")).href);

const PRIOR_VERSION = "2026-07";   // the version live before this increment

// ════════════════════════════════════════════════════════════════════════════
// PART 1 — THE VERSION FORMAT (founder decision: ISO 8601 YYYY-MM-DD)
// ════════════════════════════════════════════════════════════════════════════
{
  eq("the version is exactly the founder-kept value", CE_QUESTION_SET_VERSION, "2026-07-16");
  ok("the version matches the canonical ISO 8601 YYYY-MM-DD shape",
    CE_QUESTION_SET_VERSION_FORMAT.test(CE_QUESTION_SET_VERSION));

  // It must be a REAL date, not merely date-shaped. "2026-13-45" passes a shape regex.
  const [y, m, d] = CE_QUESTION_SET_VERSION.split("-").map(Number);
  const asDate = new Date(Date.UTC(y, m - 1, d));
  ok("the version is a real calendar date",
    asDate.getUTCFullYear() === y && asDate.getUTCMonth() === m - 1 && asDate.getUTCDate() === d);

  // The rejected forms, tested against the exported regex so every consumer shares one rule.
  const REJECT = {
    "2026-08": "month-only: two revisions in one month become indistinguishable",
    "2026-8": "month-only, unpadded",
    "16-07-2026": "DD-MM-YYYY: ambiguous and unsortable",
    "07-16-2026": "MM-DD-YYYY: ambiguous and unsortable",
    "2026": "year-only",
    "2026-07-16T00:00:00Z": "datetime, not a date",
    "v2026-07-16": "prefixed",
    "2026/07/16": "slash-separated",
    "2026-07-16 ": "trailing whitespace",
    "": "empty",
  };
  for (const [bad, why] of Object.entries(REJECT)) {
    ok(`rejects '${bad}' (${why})`, !CE_QUESTION_SET_VERSION_FORMAT.test(bad));
  }
  ok("accepts a valid ISO date", CE_QUESTION_SET_VERSION_FORMAT.test("2027-01-16"));

  // CYBERMETERS-OWNED, not IASME/NCSC. This is the claim that must never blur.
  eq("the version is declared a CyberMeters product version", CE_QUESTION_SET_PROVENANCE.version_owner, "cybermeters_product");
  eq("it is explicitly NOT an IASME/NCSC release identifier", CE_QUESTION_SET_PROVENANCE.version_is_iasme_or_ncsc_identifier, false);
  eq("the version scheme is recorded", CE_QUESTION_SET_PROVENANCE.version_scheme, "iso_8601_date");
  eq("the set is still declared NOT the official form", CE_QUESTION_SET_PROVENANCE.is_official_application_form, false);
  const sharedSrc = fs.readFileSync(path.join(root, "shared", "cyber-essentials-questions.js"), "utf8");
  ok("the convention is documented where the version lives", /ISO 8601 `YYYY-MM-DD`/.test(sharedSrc));
  ok("the documentation says month-only is rejected and WHY", /NOT month-only/.test(sharedSrc) && /twice in one month/.test(sharedSrc));
  ok("the documentation says this is not an IASME/NCSC identifier",
    /NOT an IASME release identifier/.test(sharedSrc));

  // CONSISTENCY: every other place a CE question-set version appears must use the same
  // format. A second format anywhere is a second convention.
  const provDates = [CE_QUESTION_SET_PROVENANCE.official_set_aligned_on, CE_QUESTION_SET_PROVENANCE.next_review_due];
  for (const dt of provDates) ok(`provenance date '${dt}' uses the same ISO format`, CE_QUESTION_SET_VERSION_FORMAT.test(dt));

  // The migration's backfill value is a question-set version too — it must be ISO, and it
  // must be the PRIOR version, never the active one.
  const mig = fs.readFileSync(path.join(root, "database", "migrations", "092-ce-answer-question-set-version.sql"), "utf8");
  const backfill = mig.match(/SET question_set_version = '([^']+)'/)?.[1];
  eq("the migration backfills the PRIOR version", backfill, PRIOR_VERSION);
  ok("the backfill version is ISO-shaped (year-month is the legacy value, kept verbatim)",
    /^\d{4}-\d{2}$/.test(backfill) || CE_QUESTION_SET_VERSION_FORMAT.test(backfill));
  ok("the migration never backfills the ACTIVE version",
    !new RegExp(`SET question_set_version = '${CE_QUESTION_SET_VERSION}'`).test(mig));

  // Any CE question-set version literal anywhere in code/tests/docs must be ISO or the
  // documented legacy value. This is the drift guard across surfaces.
  // THIS file is deliberately excluded: it is the version-format test, so it necessarily
  // contains invalid examples ("2026-08", "16-07-2026") for the regex to reject. Scanning it
  // would only ever flag its own counter-examples. Every other surface a CE question-set
  // version reaches — the metadata, the API writer/reader, the migration and the other
  // test — is scanned. The counter-examples above are confined to the labelled REJECT map
  // and are all tested through the exported regex, never a re-derived one.
  const scan = [
    path.join(root, "shared", "cyber-essentials-questions.js"),
    srcPath("routes", "workspace-analytics.js"),
    path.join(root, "database", "migrations", "092-ce-answer-question-set-version.sql"),
    path.join(root, "scripts", "validate-ce-question-drift.js"),
  ];
  const ALLOWED = new Set([CE_QUESTION_SET_VERSION, PRIOR_VERSION]);
  for (const f of scan) {
    const src = fs.readFileSync(f, "utf8");
    // Only literals sitting next to a question_set_version / CE_QUESTION_SET_VERSION mention.
    for (const m of src.matchAll(/question_set_version[^\n]*?['"`](\d{4}-\d{1,2}(?:-\d{1,2})?)['"`]/gi)) {
      ok(`${path.basename(f)}: version literal '${m[1]}' is a known CE question-set version`,
        ALLOWED.has(m[1]), `unknown/inconsistent version literal: ${m[1]}`);
    }
  }
}

// ════════════════════════════════════════════════════════════════════════════
// PART 2 — THE RE-VERSIONING CONTRACT, against the REAL route
// ════════════════════════════════════════════════════════════════════════════
function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch {} };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  db.prepare("INSERT INTO users (id,email,name,plan,created_at) VALUES ('u1','o@e.com','o','professional',datetime('now'))").run();
  db.prepare("UPDATE users SET email_verified=1").run();
  db.prepare(`INSERT INTO subscriptions (id,owner_user_id,plan,subscription_status,status,current_period_end,created_at,updated_at)
              VALUES ('s1','u1','professional','active','active',datetime('now','+30 days'),datetime('now'),datetime('now'))`).run();
  db.prepare("INSERT INTO workspaces (id,owner_user_id,name) VALUES ('ws1','u1','ws1')").run();
  db.prepare("INSERT INTO workspace_members (id,workspace_id,user_id,role) VALUES ('m1','ws1','u1','owner')").run();
  return db;
}
function makeD1(db) {
  const wrap = (sql, args) => ({
    __sql: sql, __args: args,
    first: async (c) => { const r = db.prepare(sql).get(...args) ?? null; return c && r ? r[c] : r; },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
  });
  return {
    prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; },
    async batch(st) { return st.map((x) => ({ results: db.prepare(x.__sql).all(...(x.__args || [])), success: true, meta: {} })); },
  };
}

// Drive the REAL route handler. Auth/entitlement are the only things stubbed — everything
// from the JSON body to the SQL is the production path.
function ctxFor(db) {
  const env = { cybermeters_db: makeD1(db), cybermeters_reports: { get: async () => null } };
  return (body) => workspaceAnalyticsRoutes({
    request: new Request("https://api.test/api/workspaces/ws1/cyber-essentials/answers", {
      method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
    }),
    env,
    url: new URL("https://api.test/api/workspaces/ws1/cyber-essentials/answers"),
    json: (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json" } }),
    serverError: () => new Response("err", { status: 500 }),
    requireAuth: async () => ({ id: "u1" }),
    requireWorkspaceRole: async () => true,
    getWorkspaceBillingUserId: async () => "u1",
    corsHeaders: {},
    isActionableFinding: () => true,
  });
}
const rowFor = (db, ck, qk) => db.prepare("SELECT * FROM cyber_essentials_answers WHERE workspace_id='ws1' AND control_key=? AND question_key=?").get(ck, qk);
// The FULL questionnaire, exactly as flattenAnswers() builds it.
const fullPayload = (answerFor) => ({
  answers: CE_QUESTIONS.flatMap((c) => c.questions.map((q) => ({
    control_key: c.control_key, question_key: q.key, answer: answerFor(c.control_key, q.key),
  }))),
});
// Seed a historical answer set, as it exists after mig 092's backfill.
function seedHistorical(db, answer = "yes") {
  for (const c of CE_QUESTIONS) for (const q of c.questions) {
    db.prepare(`INSERT INTO cyber_essentials_answers (id,workspace_id,control_key,question_key,answer,answered_by,question_set_version,updated_at)
                VALUES (?,?,?,?,?,'u1',?, '2026-07-01 09:00:00')`)
      .run(`a-${c.control_key}-${q.key}`, "ws1", c.control_key, q.key, answer, PRIOR_VERSION);
  }
}

// ── 2a. The reproduction: ONE edit must not re-version the other 19 ─────────
{
  const db = buildDb(); seedHistorical(db); const put = ctxFor(db);
  const before = db.prepare("SELECT COUNT(*) c FROM cyber_essentials_answers WHERE question_set_version=?").get(PRIOR_VERSION).c;
  eq("20 historical answers at the prior version", before, 20);

  // The customer changes exactly ONE answer. The page submits ALL 20.
  const res = await put(fullPayload((ck, qk) => (ck === "access_control" && qk === "mfa_enabled") ? "no" : "yes"));
  eq("the route accepted the save", res.status, 200);

  const changed = rowFor(db, "access_control", "mfa_enabled");
  eq("the genuinely re-answered question takes the ACTIVE version", changed.question_set_version, CE_QUESTION_SET_VERSION);
  eq("and its new answer is stored", changed.answer, "no");

  const stillOld = db.prepare("SELECT COUNT(*) c FROM cyber_essentials_answers WHERE question_set_version=?").get(PRIOR_VERSION).c;
  eq("the OTHER 19 untouched answers retain their original version", stillOld, 19);
  const reversioned = db.prepare("SELECT control_key||'.'||question_key k FROM cyber_essentials_answers WHERE question_set_version=?").all(CE_QUESTION_SET_VERSION).map((r) => r.k);
  eq("exactly one row moved version", reversioned, ["access_control.mfa_enabled"]);

  // The reworded question is the one that matters most: a customer who never saw
  // "within 14 days" must not be recorded as having answered it.
  eq("the reworded 14-day patch question still carries the version the customer ACTUALLY answered",
    rowFor(db, "patch_management_readiness", "urgent_patch_process").question_set_version, PRIOR_VERSION);
}

// ── 2b. A no-op save writes NOTHING ────────────────────────────────────────
{
  const db = buildDb(); seedHistorical(db); const put = ctxFor(db);
  const snap = () => db.prepare("SELECT control_key,question_key,answer,note,answered_by,question_set_version,updated_at FROM cyber_essentials_answers WHERE workspace_id='ws1' ORDER BY control_key,question_key").all();
  const before = JSON.stringify(snap());

  await put(fullPayload(() => "yes"));   // identical values — the page loaded and Save pressed
  eq("loading the page and pressing Save changes NOTHING (version, updated_at, answered_by)",
    JSON.stringify(snap()), before);

  // Twice more, for good measure: idempotent by contract, not by luck.
  await put(fullPayload(() => "yes"));
  await put(fullPayload(() => "yes"));
  eq("repeated no-op saves remain byte-identical", JSON.stringify(snap()), before);
}

// ── 2c. A CRAFTED client cannot force re-versioning ────────────────────────
// The client is not trusted: the payload here resubmits every identical value and even tries
// to smuggle a question_set_version field of its own.
{
  const db = buildDb(); seedHistorical(db); const put = ctxFor(db);
  const hostile = { answers: CE_QUESTIONS.flatMap((c) => c.questions.map((q) => ({
    control_key: c.control_key, question_key: q.key, answer: "yes",
    question_set_version: CE_QUESTION_SET_VERSION,   // ignored: the server decides
    updated_at: "2099-01-01",                        // ignored
  }))) };
  await put(hostile);
  eq("a crafted payload resubmitting identical values re-versions nothing",
    db.prepare("SELECT COUNT(*) c FROM cyber_essentials_answers WHERE question_set_version=?").get(PRIOR_VERSION).c, 20);
  eq("and cannot inject its own version",
    db.prepare("SELECT COUNT(*) c FROM cyber_essentials_answers WHERE question_set_version=?").get(CE_QUESTION_SET_VERSION).c, 0);
  eq("nor its own updated_at",
    db.prepare("SELECT COUNT(*) c FROM cyber_essentials_answers WHERE updated_at LIKE '2099%'").get().c, 0);

  // The server ignores client-supplied version fields entirely — it binds its own constant.
  const route = fs.readFileSync(srcPath("routes", "workspace-analytics.js"), "utf8");
  ok("the writer binds the server's own version constant, never the client's",
    /CE_QUESTION_SET_VERSION\)\s*\n?\s*\.run\(\)/.test(route));
  ok("the writer never reads a client-supplied question_set_version",
    !/it\?\.question_set_version|body\?\.question_set_version/.test(route));
}

// ── 2d. THE NOTE RULE — one documented rule ────────────────────────────────
// THE ANSWER IS THE ATTESTATION. A note is context ABOUT it ("yes, via Intune" is the same
// yes), so a note-only edit preserves the version and moves only updated_at.
{
  const db = buildDb(); seedHistorical(db); const put = ctxFor(db);
  const payloadWithNote = { answers: CE_QUESTIONS.flatMap((c) => c.questions.map((q) => ({
    control_key: c.control_key, question_key: q.key, answer: "yes",
    note: (c.control_key === "access_control" && q.key === "mfa_enabled") ? "Enforced via Intune" : undefined,
  }))) };
  const beforeUpdated = rowFor(db, "access_control", "mfa_enabled").updated_at;
  await put(payloadWithNote);
  const r = rowFor(db, "access_control", "mfa_enabled");
  eq("a note-only edit KEEPS the version the answer was given under", r.question_set_version, PRIOR_VERSION);
  eq("the note is stored", r.note, "Enforced via Intune");
  ok("but updated_at moves, because something did change", r.updated_at !== beforeUpdated);
  eq("no other row was touched",
    db.prepare("SELECT COUNT(*) c FROM cyber_essentials_answers WHERE question_set_version=?").get(PRIOR_VERSION).c, 20);
  // The rule is written down where the code is.
  const route = fs.readFileSync(srcPath("routes", "workspace-analytics.js"), "utf8");
  ok("the note rule is documented at the write site", /THE ANSWER IS THE ATTESTATION/.test(route));
  ok("and explains why a note is not a re-attestation", /note is context[\s\S]{0,80}?ABOUT an attestation/.test(route));
}

// ── 2e. Genuine new answers, and a real re-answer, DO take the active version ─
// The guard must not be a silencer: this is the control.
{
  const db = buildDb(); const put = ctxFor(db);   // no history at all
  await put(fullPayload(() => "yes"));
  eq("a first-time answer set takes the ACTIVE version",
    db.prepare("SELECT COUNT(*) c FROM cyber_essentials_answers WHERE question_set_version=?").get(CE_QUESTION_SET_VERSION).c, 20);

  // Now genuinely change three of them.
  const CHANGED = new Set(["mfa_enabled", "auto_updates", "asset_inventory"]);
  db.exec(`UPDATE cyber_essentials_answers SET question_set_version='${PRIOR_VERSION}'`);
  await put(fullPayload((ck, qk) => CHANGED.has(qk) ? "no" : "yes"));
  const moved = db.prepare("SELECT question_key k FROM cyber_essentials_answers WHERE question_set_version=?").all(CE_QUESTION_SET_VERSION).map((r) => r.k).sort();
  eq("exactly the three genuinely re-answered questions moved version", moved, [...CHANGED].sort());
  eq("the other 17 kept theirs",
    db.prepare("SELECT COUNT(*) c FROM cyber_essentials_answers WHERE question_set_version=?").get(PRIOR_VERSION).c, 17);
}

// ── 2f. Null-safety: a pre-092 row with a NULL version ─────────────────────
{
  const db = buildDb(); const put = ctxFor(db);
  db.prepare(`INSERT INTO cyber_essentials_answers (id,workspace_id,control_key,question_key,answer,answered_by,updated_at)
              VALUES ('a-null','ws1','access_control','mfa_enabled','yes','u1','2026-07-01 09:00:00')`).run();
  await put({ answers: [{ control_key: "access_control", question_key: "mfa_enabled", answer: "yes" }] });
  eq("an identical resubmit leaves a NULL version NULL (IS NOT is null-safe)",
    rowFor(db, "access_control", "mfa_enabled").question_set_version, null);
  await put({ answers: [{ control_key: "access_control", question_key: "mfa_enabled", answer: "no" }] });
  eq("a genuine change stamps the active version even from NULL",
    rowFor(db, "access_control", "mfa_enabled").question_set_version, CE_QUESTION_SET_VERSION);
}

// ── 2g. The read surface reports the stored version, never the active one ──
{
  const db = buildDb(); seedHistorical(db);
  const env = { cybermeters_db: makeD1(db), cybermeters_reports: { get: async () => null } };
  const res = await workspaceAnalyticsRoutes({
    request: new Request("https://api.test/api/workspaces/ws1/cyber-essentials/answers", { method: "GET" }),
    env,
    url: new URL("https://api.test/api/workspaces/ws1/cyber-essentials/answers"),
    json: (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json" } }),
    serverError: () => new Response("err", { status: 500 }),
    requireAuth: async () => ({ id: "u1" }),
    requireWorkspaceRole: async () => true,
    getWorkspaceBillingUserId: async () => "u1",
    corsHeaders: {}, isActionableFinding: () => true,
  });
  const body = await res.json();
  eq("the API reports the ACTIVE set version at the top level", body.question_set_version, CE_QUESTION_SET_VERSION);
  eq("but each answer reports the version IT was given under",
    body.answer_versions.access_control.mfa_enabled, PRIOR_VERSION);
  ok("so a consumer can see an answer is stale relative to the current wording",
    body.answer_versions.patch_management_readiness.urgent_patch_process !== body.question_set_version);
}

// ════════════════════════════════════════════════════════════════════════════
// MUTATIONS
// ════════════════════════════════════════════════════════════════════════════
if (!process.argv.includes("--no-mutate")) {
  const ROUTE = srcPath("routes", "workspace-analytics.js");
  const SHARED = path.join(root, "shared", "cyber-essentials-questions.js");
  const MUTATIONS = [
    { file: ROUTE, name: "THE SHIPPED BUG: unconditional re-stamp re-versions every row",
      from: `                          question_set_version = CASE
                            WHEN cyber_essentials_answers.answer IS NOT excluded.answer
                              THEN excluded.question_set_version
                            ELSE cyber_essentials_answers.question_set_version
                          END,`,
      to: "                          question_set_version = excluded.question_set_version," },
    { file: ROUTE, name: "the no-op guard is removed (a bare Save rewrites updated_at)",
      from: `                        WHERE cyber_essentials_answers.answer IS NOT excluded.answer
                           OR cyber_essentials_answers.note IS NOT excluded.note`,
      to: "" },
    { file: ROUTE, name: "a note-only edit is treated as a re-attestation",
      from: "                            WHEN cyber_essentials_answers.answer IS NOT excluded.answer",
      to: "                            WHEN cyber_essentials_answers.answer IS NOT excluded.answer OR cyber_essentials_answers.note IS NOT excluded.note" },
    { file: ROUTE, name: "the server trusts a client-supplied version",
      from: ", user.id, CE_QUESTION_SET_VERSION)", to: ", user.id, it?.question_set_version ?? CE_QUESTION_SET_VERSION)" },
    { file: SHARED, name: "a month-only version is accepted",
      from: 'export const CE_QUESTION_SET_VERSION = "2026-07-16";', to: 'export const CE_QUESTION_SET_VERSION = "2026-08";' },
    { file: SHARED, name: "a DD-MM-YYYY version is accepted",
      from: 'export const CE_QUESTION_SET_VERSION = "2026-07-16";', to: 'export const CE_QUESTION_SET_VERSION = "16-07-2026";' },
    { file: SHARED, name: "the format regex is loosened to allow partial versions",
      from: "export const CE_QUESTION_SET_VERSION_FORMAT = /^\\d{4}-\\d{2}-\\d{2}$/;",
      to: "export const CE_QUESTION_SET_VERSION_FORMAT = /^\\d{4}-\\d{2}(-\\d{2})?$/;" },
    { file: SHARED, name: "the version is claimed as an IASME/NCSC identifier",
      from: "  version_is_iasme_or_ncsc_identifier: false,", to: "  version_is_iasme_or_ncsc_identifier: true," },
    { file: SHARED, name: "the version owner is no longer CyberMeters",
      from: '  version_owner: "cybermeters_product",', to: '  version_owner: "iasme",' },
  ];
  const self = fileURLToPath(import.meta.url);
  const { execFileSync } = await import("node:child_process");
  for (const m of MUTATIONS) {
    const orig = fs.readFileSync(m.file, "utf8");
    ok(`mutation applies: ${m.name}`, orig.includes(m.from), "anchor not found — the mutation tests nothing");
    if (!orig.includes(m.from)) continue;
    fs.writeFileSync(m.file, orig.replace(m.from, m.to));
    let survived = true;
    try { execFileSync(process.execPath, [self, "--no-mutate"], { stdio: "pipe" }); } catch { survived = false; }
    finally { fs.writeFileSync(m.file, orig); }
    ok(`mutation is CAUGHT: ${m.name}`, !survived, "the suite stayed green — this guard proves nothing");
  }
}

console.log(`\nce-answer-versioning: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
console.log("ce-answer-versioning validation passed");
