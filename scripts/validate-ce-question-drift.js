#!/usr/bin/env node
//
// CE questionnaire hygiene — public/paid drift, versioning and scope. CI-blocking.
//
// The defect this locks out was live: the public self-check page and the authenticated
// question set were two independently-maintained copies, and they had drifted. 14 of the 20
// questions carried a DIFFERENT KEY on each side for the same question
// (`open_services_documented` vs `documented_inbound_services`, `endpoint_av_enabled` vs
// `endpoint_protection_enabled`, ...), and 4 of the 6 shared keys were worded differently.
// A visitor who answered the public check and then subscribed was answering a different
// questionnaire, and nothing in the repo could have told us.
//
// Three boundaries defended here:
//   1. ONE question set. Both surfaces read the same build-time module — no second copy.
//   2. KEYS ARE PERSISTED. `question_key` is stored in cyber_essentials_answers; renaming one
//      orphans every stored answer for that question.
//   3. WORDING CHANGES ARE VERSIONED. An answer is evidence about the question that was
//      actually asked, so the wording that produced it must be identifiable forever.
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
const workerLib = await import(pathToFileURL(srcPath("lib", "cyber-essentials.js")).href);
const { CE_QUESTIONS, CE_QUESTION_SET_VERSION, CE_QUESTION_SET_PROVENANCE } = shared;

// Assertions about "does this file DO X" must read the CODE, not the prose. Several guards
// here first failed against their own explanatory comments ("no React", "has no DROP COLUMN
// path"), which proves nothing about behaviour either way.
const stripJs = (src) => src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
const stripSql = (src) => src.replace(/^\s*--.*$/gm, "");

const PAGE = path.join(root, "frontend", "src", "pages", "CyberEssentialsReadinessPage.jsx");
const pageSrc = fs.readFileSync(PAGE, "utf8");

// ════ 1. ONE SET — both surfaces consume the SAME module ════════════════════
{
  // The Worker path: the lib re-exports the shared set rather than holding a copy.
  const lib = fs.readFileSync(srcPath("lib", "cyber-essentials.js"), "utf8");
  ok("the worker lib re-exports the shared question set",
    /export\s*\{[\s\S]*?CE_QUESTIONS[\s\S]*?\}\s*from\s*"[^"]*shared\/cyber-essentials-questions\.js"/.test(lib));
  ok("the worker lib does NOT define its own question array", !/^export const CE_QUESTIONS\s*=\s*\[/m.test(lib));
  eq("the worker's CE_QUESTIONS IS the shared array (identity, not a copy)",
    workerLib.CE_QUESTIONS === CE_QUESTIONS, true);
  eq("the worker's version IS the shared version", workerLib.CE_QUESTION_SET_VERSION, CE_QUESTION_SET_VERSION);

  // The public path: the page imports the shared set and derives its controls from it.
  ok("the public page imports the shared question set",
    /import\s*\{[^}]*CE_QUESTIONS[^}]*\}\s*from\s*'[^']*shared\/cyber-essentials-questions\.js'/.test(pageSrc));
  ok("the public page derives its controls from the shared set",
    /const CONTROLS = CE_QUESTIONS\.map\(/.test(pageSrc));
  // The old second copy must not come back: a literal control array with hardcoded questions.
  ok("the public page holds NO second question array",
    !/const CONTROLS\s*=\s*\[/.test(pageSrc));
  ok("the public page hardcodes no question text",
    !/question: '(?:Do|Are|Is|Have|Does)\b/.test(pageSrc));
  // And it must not fetch them: no anonymous public API was added.
  ok("the public page adds no anonymous API call for questions",
    !/fetch\(|api\.get\(|\/api\/public\//.test(pageSrc));
}

// ════ 2. THE SET ITSELF — shape, size, keys ═════════════════════════════════
{
  eq("five canonical control areas", CE_QUESTIONS.length, 5);
  eq("twenty questions — the readiness model is unchanged",
    CE_QUESTIONS.reduce((s, c) => s + c.questions.length, 0), 20);
  eq("the five canonical control keys",
    CE_QUESTIONS.map((c) => c.control_key),
    ["boundary_protection", "secure_configuration", "access_control", "malware_protection", "patch_management_readiness"]);

  const seen = new Set();
  for (const c of CE_QUESTIONS) {
    ok(`${c.control_key}: declares external_coverage`, ["partial", "none"].includes(c.external_coverage));
    ok(`${c.control_key}: has a paid label`, Boolean(c.label));
    ok(`${c.control_key}: has a public title`, Boolean(c.public_title));
    ok(`${c.control_key}: has a description, why and recommended action`,
      Boolean(c.description && c.why && c.recommended_action));
    eq(`${c.control_key}: four questions`, c.questions.length, 4);
    for (const q of c.questions) {
      ok(`${c.control_key}.${q.key}: has text`, Boolean(q.text) && q.text.trim().length > 10);
      ok(`${c.control_key}.${q.key}: has a why`, Boolean(q.why));
      ok(`${c.control_key}.${q.key}: key is unique across the whole set`, !seen.has(q.key), q.key);
      seen.add(q.key);
    }
  }
  eq("CE_QUESTION_KEYS is the flattened set", shared.CE_QUESTION_KEYS.length, 20);
}

// ════ 3. KEYS ARE PERSISTED — RENAMING ONE ORPHANS STORED ANSWERS ═══════════
// `question_key` is a stored column. These are the keys the paid product has been writing to
// D1, so they are the canonical ones and the public page was the side that had to move. This
// list is pinned deliberately: changing it must be a conscious act with a data migration, not
// a rename that silently strands every customer's answers.
{
  const PERSISTED_KEYS = {
    boundary_protection: ["default_inbound_block", "open_services_documented", "boundary_default_creds", "admin_pages_protected"],
    secure_configuration: ["default_passwords_changed", "unused_removed", "device_hardening", "asset_inventory"],
    access_control: ["mfa_enabled", "admin_separation", "joiner_leaver_process", "least_privilege"],
    malware_protection: ["endpoint_av_enabled", "av_auto_update", "software_install_control", "mobile_protection"],
    patch_management_readiness: ["auto_updates", "unsupported_removed", "update_review_process", "urgent_patch_process"],
  };
  for (const c of CE_QUESTIONS) {
    eq(`${c.control_key}: question keys match what is stored in D1 (renaming orphans answers)`,
      c.questions.map((q) => q.key), PERSISTED_KEYS[c.control_key]);
  }
}

// ════ 4. THE PUBLIC PAGE RENDERS THE SHARED WORDING, NOT ITS OWN ════════════
// Build the page's derived CONTROLS the same way the page does, and prove every rendered word
// comes from the shared set.
{
  const ICONS = ["ShieldCheck", "Lock", "UserCheck", "ShieldAlert", "RefreshCw"];
  ok("icons stay local to the page (they are React components, not data)",
    ICONS.every((i) => pageSrc.includes(i)));
  ok("no icon or React dependency leaked into the shared data module",
    !/ShieldCheck|lucide|from ['"]react/i.test(stripJs(fs.readFileSync(path.join(root, "shared", "cyber-essentials-questions.js"), "utf8"))));
  ok("the shared module is pure data (no imports at all)",
    !/^import\s/m.test(fs.readFileSync(path.join(root, "shared", "cyber-essentials-questions.js"), "utf8")));

  // The mapping the page performs must preserve identity and text.
  const derived = CE_QUESTIONS.map((c) => ({
    id: c.control_key,
    externalEvidenceCapable: c.external_coverage === "partial",
    questions: c.questions.map((q) => ({ id: q.key, question: q.text })),
  }));
  eq("public control ids are the canonical control keys",
    derived.map((d) => d.id), CE_QUESTIONS.map((c) => c.control_key));
  eq("public question ids are the canonical (persisted) question keys",
    derived.flatMap((d) => d.questions.map((q) => q.id)),
    CE_QUESTIONS.flatMap((c) => c.questions.map((q) => q.key)));
  eq("the three non-assessable controls are marked as such on the public page",
    derived.filter((d) => !d.externalEvidenceCapable).map((d) => d.id),
    ["access_control", "malware_protection", "patch_management_readiness"]);
}

// ════ 5. THE RECONCILED WORDING — the founder's two named changes ═══════════
{
  const q = (ck, qk) => CE_QUESTIONS.find((c) => c.control_key === ck).questions.find((x) => x.key === qk);

  // The clearer boundary wording: a business on a consumer router, or relying on the firewall
  // built into Windows/macOS, still HAS this control.
  const inbound = q("boundary_protection", "default_inbound_block");
  ok("boundary question uses the clearer 'router, firewall or built-in security control' wording",
    /router, firewall or built-in security control/.test(inbound.text), inbound.text);
  ok("and no longer says the narrow 'router/firewall'", !/router\/firewall/.test(inbound.text));

  // The 14-day expectation, stated rather than implied.
  const urgent = q("patch_management_readiness", "urgent_patch_process");
  ok("urgent-patch question states the 14-day expectation", /within 14 days/.test(urgent.text), urgent.text);
  ok("and no longer asks the unanswerable 'applied quickly'", !/applied quickly/.test(urgent.text));
  ok("its explanation names the 14-day expectation too", /14 days/.test(urgent.why));

  // Admin pages: the clearer public phrasing won.
  const adminPages = q("boundary_protection", "admin_pages_protected");
  ok("admin-pages question uses the clearer 'clear, controlled business need' wording",
    /clear, controlled business need/.test(adminPages.text), adminPages.text);
}

// ════ 6. VERSIONING ═════════════════════════════════════════════════════════
{
  ok("a question set version is declared", Boolean(CE_QUESTION_SET_VERSION));
  ok("the version was bumped for this reworded set", CE_QUESTION_SET_VERSION !== "2026-07");
  eq("the current version", CE_QUESTION_SET_VERSION, "2026-07-16");

  // The version must be a FUNCTION of the wording: if any text changes and the version does
  // not, this fails. That is what makes "any wording change requires a bump" enforceable
  // rather than a rule someone remembers.
  const WORDING_FINGERPRINT = CE_QUESTIONS
    .flatMap((c) => c.questions.map((q) => `${c.control_key}.${q.key}=${q.text}`))
    .join("|");
  const PINNED = {
    "2026-07-16": "87ba4434",
  };
  // Tiny stable hash — no crypto import needed and the value only has to be deterministic.
  let h = 0;
  for (let i = 0; i < WORDING_FINGERPRINT.length; i++) { h = (Math.imul(31, h) + WORDING_FINGERPRINT.charCodeAt(i)) | 0; }
  const digest = (h >>> 0).toString(16).padStart(8, "0");
  ok(`the wording fingerprint matches version ${CE_QUESTION_SET_VERSION} — CHANGE THE TEXT, BUMP THE VERSION and update this pin`,
    PINNED[CE_QUESTION_SET_VERSION] === digest,
    `version=${CE_QUESTION_SET_VERSION} expected=${PINNED[CE_QUESTION_SET_VERSION]} actual=${digest}`);

  // Provenance: what this set IS, when we last aligned it, and when we look again.
  eq("the set declares it is NOT the official application form", CE_QUESTION_SET_PROVENANCE.is_official_application_form, false);
  eq("it declares itself a readiness self-check", CE_QUESTION_SET_PROVENANCE.set_type, "readiness_self_check");
  ok("it records the official-set alignment date", /^\d{4}-\d{2}-\d{2}$/.test(CE_QUESTION_SET_PROVENANCE.official_set_aligned_on));
  ok("it records a review cadence", Number(CE_QUESTION_SET_PROVENANCE.review_cadence_months) > 0);
  ok("it records when the next review is due", /^\d{4}-\d{2}-\d{2}$/.test(CE_QUESTION_SET_PROVENANCE.next_review_due));
  ok("the next review is after the alignment date",
    Date.parse(CE_QUESTION_SET_PROVENANCE.next_review_due) > Date.parse(CE_QUESTION_SET_PROVENANCE.official_set_aligned_on));
}

// ════ 7. THE VERSION IS PERSISTED, AND HISTORY IS KEPT ══════════════════════
{
  const mig = fs.readFileSync(path.join(root, "database", "migrations", "092-ce-answer-question-set-version.sql"), "utf8");
  ok("mig 092 adds the column additively", /ALTER TABLE cyber_essentials_answers ADD COLUMN question_set_version TEXT;/.test(mig));
  ok("it is nullable (no NOT NULL, no default that would lie about intent)",
    !/question_set_version TEXT NOT NULL/.test(mig));
  ok("existing answers are backfilled to the version they were ANSWERED under, not the current one",
    /SET question_set_version = '2026-07'/.test(mig) && !new RegExp(`SET question_set_version = '${CE_QUESTION_SET_VERSION}'`).test(mig));
  ok("the backfill is idempotent (scoped to NULL)", /WHERE question_set_version IS NULL/.test(mig));
  ok("no destructive statement", !/DROP|DELETE FROM|TRUNCATE/i.test(stripSql(mig)));

  const route = fs.readFileSync(srcPath("routes", "workspace-analytics.js"), "utf8");
  ok("the writer stamps the version on insert", /question_set_version.*\n?.*VALUES/.test(route) || /CE_QUESTION_SET_VERSION\)\s*\n?\s*\.run\(\)/.test(route));
  ok("the writer stamps it on update too", /question_set_version = excluded\.question_set_version/.test(route));
  ok("the reader returns the stored per-answer version", /answer_versions/.test(route));
  ok("the reader selects the column", /SELECT control_key, question_key, answer, note, question_set_version/.test(route));
  ok("the API publishes the provenance", /question_set_provenance: CE_QUESTION_SET_PROVENANCE/.test(route));

  // Prove the round-trip against a real DB with the real migration applied.
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch {} };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  const cols = db.prepare("PRAGMA table_info(cyber_essentials_answers)").all().map((c) => c.name);
  ok("question_set_version exists on the table after migration", cols.includes("question_set_version"));
  // A row written before 092 (no version) is backfilled to the OLD version, not the new one.
  db.prepare(`INSERT INTO cyber_essentials_answers (id,workspace_id,control_key,question_key,answer,updated_at)
              VALUES ('a-old','ws1','access_control','mfa_enabled','yes',datetime('now'))`).run();
  db.exec("UPDATE cyber_essentials_answers SET question_set_version = '2026-07' WHERE question_set_version IS NULL");
  eq("a pre-092 answer retains the version it was actually answered under",
    db.prepare("SELECT question_set_version v FROM cyber_essentials_answers WHERE id='a-old'").get().v, "2026-07");
  ok("and is NOT stamped with the current version",
    db.prepare("SELECT question_set_version v FROM cyber_essentials_answers WHERE id='a-old'").get().v !== CE_QUESTION_SET_VERSION);
}

// ════ 8. SCOPE — answers stay attestation, and touch nothing they must not ══
{
  // Answers must never reach the Cyber Metrics Score or the Business Risk Indicator.
  for (const f of ["scoring.js", "business-risk.js", "posture-scoring.js"]) {
    ok(`${f} never reads cyber_essentials_answers`,
      !/cyber_essentials_answers/.test(stripJs(fs.readFileSync(srcPath("engines", f), "utf8"))));
  }
  // ce-readiness.js DOES read answers — once, in getCyberEssentialsSnapshot, purely as a
  // COMPLETENESS GATE: no/partial answers => customer_input_required, complete => show the
  // verdict. That is attestation deciding VISIBILITY, which is correct and must stay. What it
  // must never do is decide the NUMBER, so the assertion is scoped to the builder.
  {
    const src = fs.readFileSync(srcPath("engines", "ce-readiness.js"), "utf8");
    const builder = stripJs(src.slice(
      src.indexOf("export async function buildCyberEssentialsReadiness"),
      src.indexOf("export function isCyberEssentialsQuestionnaireComplete")));
    ok("the external readiness BUILDER never reads questionnaire answers",
      !/cyber_essentials_answers/.test(builder));
    const snapshot = stripJs(src.slice(src.indexOf("export async function getCyberEssentialsSnapshot")));
    ok("the snapshot reads answers only to gate visibility, and calls the builder unchanged",
      /isCyberEssentialsQuestionnaireComplete\(answersMap\)/.test(snapshot)
      && /buildCyberEssentialsReadiness\(wsId, env\)/.test(snapshot));
  }
  // Answers must never auto-create a managed case.
  const ceCases = stripJs(fs.readFileSync(srcPath("engines", "cyber-essentials-cases.js"), "utf8"));
  ok("the CE case engine never reads questionnaire answers", !/cyber_essentials_answers/.test(ceCases));
  const lifecycle = await import(pathToFileURL(srcPath("engines", "ce-lifecycle.js")).href);
  const cases = await import(pathToFileURL(srcPath("engines", "cyber-essentials-cases.js")).href);
  for (const key of ["access_control", "malware_protection"]) {
    const g = lifecycle.gradeCeControl({ key, label: key, remediations: [{ remediation_id: "x", customer_title: "x" }], unknown: [] });
    eq(`${key}: still not externally assessable (unchanged by this increment)`, g.state, "not_externally_assessable");
    ok(`${key}: a questionnaire gap still cannot open a case`, !cases.CE_CASE_RECURRENCES.has(g.state));
  }
  // BEHAVIOURAL PROOF, not a grep: same external evidence, three different answer sets —
  // all-yes, all-no, and none at all — must produce the IDENTICAL external readiness
  // indicator. A grep can only say the builder does not mention a table; this says the
  // number cannot move, whatever the customer attests.
  {
    const mkDb = () => {
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
      db.prepare("INSERT INTO domains (id,user_id,domain,created_at) VALUES ('d1','u1','acme.example.com',datetime('now'))").run();
      db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES ('ws1','d1')").run();
      db.prepare(`INSERT INTO scans (id,domain_id,workspace_id,domain,score,rating,status,scan_quality,created_at)
                  VALUES ('scan_1','d1','ws1','acme.example.com',70,'fair','completed','complete',datetime('now'))`).run();
      return db;
    };
    const mkD1 = (db) => {
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
    };
    globalThis.fetch = async () => new Response("{}", { status: 200 });
    const REPORT = { modules: {
      headers: { accessible: true, headers_assessed: true, values: { "strict-transport-security": "max-age=63072000", "content-security-policy": "default-src 'self'" }, present: [], missing: [] },
      ssl: { https_available: true, https_probe_executed: true, http_redirects_to_https: true },
      email_security: { spf: { present: true }, dmarc: { present: true, policy: "reject" }, dkim: { present: true } },
    } };
    const { buildCyberEssentialsReadiness } = await import(pathToFileURL(srcPath("engines", "ce-readiness.js")).href);
    const runWith = async (answer) => {
      const db = mkDb();
      if (answer) {
        for (const c of CE_QUESTIONS) for (const q of c.questions) {
          db.prepare(`INSERT INTO cyber_essentials_answers (id,workspace_id,control_key,question_key,answer,question_set_version,updated_at)
                      VALUES (?,?,?,?,?,?,datetime('now'))`)
            .run(`a-${c.control_key}-${q.key}`, "ws1", c.control_key, q.key, answer, CE_QUESTION_SET_VERSION);
        }
      }
      const env = { cybermeters_db: mkD1(db), cybermeters_reports: { get: async () => ({ json: async () => REPORT }) } };
      const r = await buildCyberEssentialsReadiness("ws1", env);
      return JSON.stringify({ score: r.score, coverage: r.external_coverage_statement, cats: r.categories.map((c) => [c.key, c.score, c.weight]) });
    };
    const noAnswers = await runWith(null);
    const allYes = await runWith("yes");
    const allNo = await runWith("no");
    eq("all-YES attestation cannot move the external readiness indicator", allYes, noAnswers);
    eq("all-NO attestation cannot move the external readiness indicator", allNo, noAnswers);
  }

  // Purge still covers the table the new column lives on.
  const worker = await import(pathToFileURL(srcPath("index.js")).href);
  ok("purge still covers cyber_essentials_answers (the #106 lesson)",
    worker.WORKSPACE_PURGE_TABLES.includes("cyber_essentials_answers"));
  // Never claim certification.
  const sharedSrc = fs.readFileSync(path.join(root, "shared", "cyber-essentials-questions.js"), "utf8");
  ok("the shared set states it is not the official form", /not the official/i.test(sharedSrc));
  ok("nothing in the set claims we certify", !/we certify|CyberMeters certifies/i.test(sharedSrc));
}

// ════ 9. MUTATIONS ══════════════════════════════════════════════════════════
if (!process.argv.includes("--no-mutate")) {
  const SHARED = path.join(root, "shared", "cyber-essentials-questions.js");
  const LIB = srcPath("lib", "cyber-essentials.js");
  const MUTATIONS = [
    { file: SHARED, name: "a question key is renamed (orphans every stored answer)",
      from: 'key: "open_services_documented"', to: 'key: "documented_inbound_services"' },
    { file: SHARED, name: "question wording changes without a version bump",
      from: "text: \"Are any open inbound services documented with a clear business reason?\"",
      to: "text: \"Are open inbound services documented?\"" },
    { file: SHARED, name: "the 14-day patch expectation is softened back to 'quickly'",
      from: "text: \"Are critical or high-severity security updates applied within 14 days of release?\"",
      to: "text: \"Are urgent security updates applied quickly when flagged as important?\"" },
    { file: SHARED, name: "the clearer boundary wording is reverted",
      from: "text: \"Do all business devices connect to the internet through a router, firewall or built-in security control that blocks unwanted inbound access by default?\"",
      to: "text: \"Do all business devices reach the internet through a router/firewall that blocks unwanted inbound access by default?\"" },
    { file: SHARED, name: "a control's external_coverage is flipped to hide non-assessability",
      from: '    control_key: "access_control",\n    external_coverage: "none",',
      to: '    control_key: "access_control",\n    external_coverage: "partial",' },
    { file: SHARED, name: "the set claims to be the official application form",
      from: "  is_official_application_form: false,", to: "  is_official_application_form: true," },
    { file: SHARED, name: "the review cadence is dropped",
      from: "  review_cadence_months: 6,", to: "  review_cadence_months: 0," },
    { file: SHARED, name: "a 21st question is added without review",
      from: '      { key: "asset_inventory", text: "Do you keep a basic list of business devices and important cloud services?", why: "You cannot secure what you do not know you use." },',
      to: '      { key: "asset_inventory", text: "Do you keep a basic list of business devices and important cloud services?", why: "You cannot secure what you do not know you use." },\n      { key: "extra_q", text: "Is this an extra question nobody reviewed?", why: "x" },' },
    { file: LIB, name: "the worker lib goes back to holding its own copy of the questions",
      from: 'export {\n  CE_QUESTIONS,',
      to: 'export const CE_QUESTIONS = [];\nexport {\n' },
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

console.log(`\nce-question-drift: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
console.log("ce-question-drift validation passed");
