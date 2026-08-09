#!/usr/bin/env node
//
// Weekly Digest truth — DB-backed, CI-blocking.
//
// The digest-truth episode fixed three P2 presentation defects:
//   1. raw repeated observations inflated the headline count and repeated
//      identical rows — a digest row is now a DISTINCT SEMANTIC CHANGE
//      (event_type | hostname | normalised description) with an honest
//      occurrence count;
//   2. "Your security posture is stable" could be sent to a workspace with no
//      completed comparable assessment in the window — reassurance now REQUIRES
//      at least one status='completed', scan_quality='complete' scan
//      (partial/degraded/unknown/NULL fail closed);
//   3. the CTA /exposure was workspace-ambiguous — it now carries
//      ?ws=<workspace_id> so the email opens ITS OWN workspace.
//
// This suite proves all three plus the preserved behaviour (workspace scoping,
// weekly dedupe, historical asset_events immutability), and mutation-proves the
// load-bearing gates. Node 24+.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engDir = path.join(root, "workers", "scan-api", "src", "engines");
const mod = await import(pathToFileURL(path.join(engDir, "weekly-digest.js")).href);
const { computeWeeklyChanges, buildDigestEmail, sendWeeklyDigests,
        semanticChangeKey, groupSemanticChanges, assessmentEvidenceForWindow } = mod;

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

// Mock Resend and capture email bodies.
const sentEmails = [];
globalThis.fetch = async (url, init) => {
  if (String(url).includes("resend.com")) {
    try { sentEmails.push(JSON.parse(String(init?.body || "{}"))); } catch { sentEmails.push({}); }
    return { ok: true, status: 200, json: async () => ({ id: "re_mock" }) };
  }
  throw new Error("network disabled");
};
AbortSignal.timeout = () => undefined;

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
function makeD1(db, { onAll = () => {}, rejectAll = () => false } = {}) {
  const wrap = (sql, args) => ({
    first: async () => db.prepare(sql).get(...args) ?? null,
    all: async () => {
      onAll(sql, args);
      if (rejectAll(sql, args)) throw new Error("fixture D1 read rejected");
      return { results: db.prepare(sql).all(...args) };
    },
    run: async () => { const r = db.prepare(sql).run(...args); return { meta: { changes: r.changes } }; },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
}
const db = buildDb();
const env = { cybermeters_db: makeD1(db), RESEND_API_KEY: "re_test", HELLO_EMAIL_FROM: "hello@cybermeters.com", FRONTEND_URL: "https://app.cybermeters.com" };

// ── Seed ─────────────────────────────────────────────────────────────────────
db.prepare("INSERT INTO users (id, email, email_verified) VALUES ('u1','one@example.co.uk',1)").run();
db.prepare("INSERT INTO users (id, email, email_verified) VALUES ('u2','two@example.co.uk',1)").run();
db.prepare("INSERT INTO workspaces (id, name, owner_user_id) VALUES ('ws1','Acme','u1')").run();
db.prepare("INSERT INTO workspaces (id, name, owner_user_id) VALUES ('ws2','Beta','u2')").run();
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws1','d1')").run();
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws2','d2')").run();

let seq = 0;
const seedEvent = (ws, type, host, desc, sev = "medium", age = "-1 day") =>
  db.prepare(`INSERT INTO asset_events (id, workspace_id, domain_id, event_type, hostname, severity, description, created_at)
              VALUES (?, ?, 'd1', ?, ?, ?, ?, datetime('now', ?))`)
    .run(`ev_${++seq}`, ws, type, host, sev, desc, age);

// ws1: the same unchanged condition observed by THREE scans in the window…
seedEvent("ws1", "exposed_service_detected", "mail.acme.co.uk", "Port 25 (SMTP) exposed", "high", "-1 day");
seedEvent("ws1", "exposed_service_detected", "mail.acme.co.uk", "Port 25 (SMTP) exposed", "high", "-3 days");
seedEvent("ws1", "exposed_service_detected", "mail.acme.co.uk", "Port 25 (SMTP) exposed", "high", "-5 days");
// …a MEANINGFUL host-count transition that must stay two separate changes…
seedEvent("ws1", "certificate_growth_detected", "www.acme.co.uk", "2 hosts → 3 hosts", "low", "-4 days");
seedEvent("ws1", "certificate_growth_detected", "www.acme.co.uk", "3 hosts → 4 hosts", "low", "-2 days");
// …and two SEPARATE certificates with identical SAN-ish descriptions.
seedEvent("ws1", "certificate_new_san_detected", "shop.acme.co.uk", "SAN added: *.acme.co.uk", "medium", "-2 days");
seedEvent("ws1", "certificate_new_san_detected", "portal.acme.co.uk", "SAN added: *.acme.co.uk", "medium", "-2 days");
// ws2: same hostname vocabulary in ANOTHER workspace — must never leak into ws1.
seedEvent("ws2", "exposed_service_detected", "mail.acme.co.uk", "Port 25 (SMTP) exposed", "high", "-1 day");

const rawRowCount = db.prepare("SELECT COUNT(*) c FROM asset_events").get().c;

// ── 1. Semantic grouping and honest counts ───────────────────────────────────
{
  const changes = await computeWeeklyChanges(env, "ws1");
  eq("7 raw ws1 rows collapse to 5 distinct semantic changes", changes.total, 5);
  eq("honest weekly total is additive and evidence-supported", changes.customer_total, 5);
  const smtp = changes.top.find((e) => e.event_type === "exposed_service_detected");
  eq("the unchanged condition appears ONCE with an honest occurrence count", smtp?.occurrences, 3);
  const growth = changes.top.filter((e) => e.event_type === "certificate_growth_detected");
  eq("2 hosts → 3 hosts and 3 hosts → 4 hosts stay separate changes", growth.length, 2);
  const sans = changes.top.filter((e) => e.event_type === "certificate_new_san_detected");
  eq("separate certificates are NOT collapsed on similar SAN sets", sans.length, 2);
  const sevSum = Object.values(changes.bySeverity).reduce((a, b) => a + b, 0);
  eq("severity totals sum to the distinct-change total", sevSum, changes.total);
  eq("honest severity totals sum to the honest distinct-change total",
    Object.values(changes.customer_bySeverity || {}).reduce((a, b) => a + b, 0),
    changes.customer_total);
  eq("top list has no duplicate semantic keys",
     new Set(changes.top.map(semanticChangeKey)).size, changes.top.length);

  const mail = buildDigestEmail("Acme", changes, env.FRONTEND_URL, "ws1");
  ok("headline states the DISTINCT count (5), not the raw row count (7)",
     /5 changes on Acme/.test(mail.subject) && !/7 changes/.test(mail.subject));
  ok("repeated observation is stated once with its count",
     (mail.text.match(/Port 25 \(SMTP\) exposed/g) || []).length === 1
     && mail.text.includes("(observed 3 times this week)"));

  const honestWins = buildDigestEmail("Acme", {
    total: 7,
    bySeverity: { high: 7 },
    byCategory: { attack_surface: 7 },
    top: changes.top,
    customer_total: 1,
    customer_bySeverity: { high: 1 },
    customer_byCategory: { attack_surface: 1 },
    customer_top: changes.top.slice(0, 1),
    assessment: { coverage: "complete_assessment" },
    lifecycle_claim_projection: { coverage: "complete" },
  }, env.FRONTEND_URL, "ws1");
  ok("weekly email consumes honest fields rather than legacy raw fields",
    /1 change on Acme/.test(honestWins.subject) && !/7 changes/.test(honestWins.subject));
}

// ── 1a. R7: legacy rows remain unbounded; only lifecycle support is bounded ───
{
  const volumeDb = buildDb();
  volumeDb.prepare("INSERT INTO workspaces (id, name) VALUES ('ws-volume','Volume')").run();
  const insertVolume = volumeDb.prepare(`
    INSERT INTO asset_events
      (id, workspace_id, domain_id, event_type, hostname, severity, description, created_at)
    VALUES (?, 'ws-volume', 'd-volume', 'exposed_service_detected', ?, 'info', ?, datetime('now','-1 day'))
  `);
  volumeDb.exec("BEGIN");
  for (let index = 0; index < 2001; index += 1) {
    insertVolume.run(`volume-${index}`, `host-${index}.example.com`, `Distinct event ${index}`);
  }
  volumeDb.exec("COMMIT");
  const volumeSql = [];
  const volumeChanges = await computeWeeklyChanges({
    ...env,
    cybermeters_db: makeD1(volumeDb, { onAll: (sql) => volumeSql.push(sql) }),
  }, "ws-volume");
  eq("legacy weekly collection remains unbounded above 2000 non-lifecycle rows",
    volumeChanges.total, 2001);
  eq("non-lifecycle volume does not truncate lifecycle support coverage",
    volumeChanges.customer_total, 2001);
  ok("weekly digest keeps a separate unbounded legacy event read",
    volumeSql.some((sql) => /FROM\s+asset_events/i.test(sql) &&
      !/event_type\s+IN\s*\(\s*'asset_no_longer_seen'/i.test(sql) &&
      !/LIMIT\s+2001/i.test(sql)));
  const legacySql = volumeSql.find((sql) => /FROM\s+asset_events/i.test(sql) &&
    !/event_type\s+IN\s*\(\s*'asset_no_longer_seen'/i.test(sql));
  ok("legacy weekly read retains its exact pre-projection columns and tie semantics",
    /SELECT\s+id,\s*event_type,\s*hostname,\s*severity,\s*description,\s*created_at\s+FROM\s+asset_events\s+WHERE\s+workspace_id\s*=\s*\?\s+AND\s+created_at\s*>\s*datetime\('now',\s*'-7 days'\)\s+ORDER BY\s+created_at\s+DESC\s*$/i.test(
      legacySql || "",
    ));
  ok("legacy weekly top rows do not expose projection-only identity columns",
    volumeChanges.top.every((event) =>
      !Object.prototype.hasOwnProperty.call(event, "workspace_id") &&
      !Object.prototype.hasOwnProperty.call(event, "domain_id") &&
      !Object.prototype.hasOwnProperty.call(event, "asset_id") &&
      !Object.prototype.hasOwnProperty.call(event, "scan_id")));
  ok("weekly digest uses a lifecycle-only LIMIT 2001 projection read",
    volumeSql.some((sql) => /event_type\s+IN\s*\(\s*'asset_no_longer_seen'\s*,\s*'asset_reappeared'\s*\)/i.test(sql) &&
      /LIMIT\s+2001/i.test(sql)));
  volumeDb.close();
}

{
  const rejectedProjectionEnv = {
    ...env,
    cybermeters_db: makeD1(db, {
      rejectAll: (sql) => /event_type\s+IN\s*\(\s*'asset_no_longer_seen'\s*,\s*'asset_reappeared'\s*\)/i.test(sql),
    }),
  };
  const changes = await computeWeeklyChanges(rejectedProjectionEnv, "ws1");
  eq("projection failure preserves legacy weekly total", changes.total, 5);
  eq("projection failure nulls the honest weekly total", changes.customer_total, null);
  ok("projection failure has explicit unavailable collection coverage",
    changes.lifecycle_claim_projection?.coverage === "unavailable" &&
    changes.lifecycle_claim_projection?.coverage_reason === "event_collection_read_failed");
  const mail = buildDigestEmail("Acme", changes, env.FRONTEND_URL, "ws1");
  ok("projection failure email never turns legacy rows into an exact claim",
    /support not evaluated/i.test(mail.subject) && !/5 changes/i.test(mail.subject));
}

// ── 2. Workspace scoping preserved ───────────────────────────────────────────
{
  const other = await computeWeeklyChanges(env, "ws2");
  eq("ws2 sees only its own event", other.total, 1);
  const one = await computeWeeklyChanges(env, "ws1");
  eq("ws1 total is unchanged by ws2's identical hostname", one.total, 5);
}

// ── 3. Coverage-aware quiet state ────────────────────────────────────────────
{
  // ws2 gets a quiet week by clearing its events; assessment evidence varies.
  db.prepare("DELETE FROM asset_events WHERE workspace_id = 'ws2'").run();

  const noScan = await assessmentEvidenceForWindow(env, "ws2");
  eq("no scan => no_assessment", noScan.coverage, "no_assessment");
  const q1 = buildDigestEmail("Beta", await computeWeeklyChanges(env, "ws2"), env.FRONTEND_URL, "ws2");
  ok("no scan: no-completed-assessment wording, never 'stable'",
     /No completed assessment was available/.test(q1.text) && !/stable/i.test(q1.text) && !/all quiet/i.test(q1.subject));

  db.prepare(`INSERT INTO scans (id, domain_id, domain, status, workspace_id, scan_quality, created_at)
              VALUES ('s_p','d2','beta.example','completed','ws2','partial',datetime('now','-1 day'))`).run();
  const partial = await assessmentEvidenceForWindow(env, "ws2");
  eq("partial-only completed scan => partial_only", partial.coverage, "partial_only");
  const q2 = buildDigestEmail("Beta", await computeWeeklyChanges(env, "ws2"), env.FRONTEND_URL, "ws2");
  ok("partial-only: no-completed-assessment wording, never 'stable'",
     /No completed assessment was available/.test(q2.text) && !/stable/i.test(q2.text));

  db.prepare(`INSERT INTO scans (id, domain_id, domain, status, workspace_id, scan_quality, created_at)
              VALUES ('s_n','d2','beta.example','completed','ws2',NULL,datetime('now','-1 day'))`).run();
  eq("NULL scan_quality never counts as comparable (fail closed)",
     (await assessmentEvidenceForWindow(env, "ws2")).coverage, "partial_only");

  db.prepare(`INSERT INTO scans (id, domain_id, domain, status, workspace_id, scan_quality, created_at)
              VALUES ('s_c','d2','beta.example','completed','ws2','complete',datetime('now','-1 day'))`).run();
  const complete = await assessmentEvidenceForWindow(env, "ws2");
  eq("complete comparable scan => complete_assessment", complete.coverage, "complete_assessment");
  const q3 = buildDigestEmail("Beta", await computeWeeklyChanges(env, "ws2"), env.FRONTEND_URL, "ws2");
  ok("complete quiet week earns the honest reassurance", /all quiet on Beta/i.test(q3.subject) && /stable/i.test(q3.text));

  // Historical unattributed scan rows (workspace_id NULL) still count via the
  // workspace's own monitored domains — and only for THAT workspace.
  db.prepare("DELETE FROM scans WHERE workspace_id = 'ws2'").run();
  db.prepare(`INSERT INTO scans (id, domain_id, domain, status, workspace_id, scan_quality, created_at)
              VALUES ('s_h','d2','beta.example','completed',NULL,'complete',datetime('now','-1 day'))`).run();
  eq("unattributed scan for a monitored domain counts for its workspace",
     (await assessmentEvidenceForWindow(env, "ws2")).coverage, "complete_assessment");
  eq("the same unattributed scan does NOT count for a foreign workspace",
     (await assessmentEvidenceForWindow(env, "ws1")).coverage, "no_assessment");
}

// ── 4. Workspace-scoped CTA ──────────────────────────────────────────────────
{
  const mail = buildDigestEmail("Acme", await computeWeeklyChanges(env, "ws1"), env.FRONTEND_URL, "ws1");
  ok("CTA carries the digest's own workspace", mail.text.includes("/exposure?ws=ws1") && mail.html.includes("/exposure?ws=ws1"));
  const quiet = buildDigestEmail("Beta", { total: 0, bySeverity: {}, byCategory: {}, top: [] }, env.FRONTEND_URL, "ws2");
  ok("quiet/no-assessment email CTA is workspace-scoped too", quiet.text.includes("/exposure?ws=ws2"));
}

// ── 5. End-to-end send: scoped CTA + weekly dedupe + immutability ────────────
{
  sentEmails.length = 0;
  await sendWeeklyDigests(env);
  const forWs1 = sentEmails.find((m) => `${m.text || ""}`.includes("/exposure?ws=ws1"));
  ok("sent digest links to its own workspace", Boolean(forWs1));
  const sendsFirst = sentEmails.length;
  ok("one digest per active workspace", sendsFirst >= 2);
  await sendWeeklyDigests(env);
  eq("same ISO week never re-sends", sentEmails.length, sendsFirst);
  eq("historical asset_events were not mutated or deleted",
     db.prepare("SELECT COUNT(*) c FROM asset_events").get().c, rawRowCount - 1); // minus the ws2 rows we deleted in §3 (1 row)
  eq("no asset_events row was rewritten",
     db.prepare("SELECT COUNT(*) c FROM asset_events WHERE description = 'Port 25 (SMTP) exposed'").get().c, 3);
}

// ── 6. MUTATION HARNESS ──────────────────────────────────────────────────────
const LIB_URL = pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib")).href;
const ENG_URL = pathToFileURL(engDir).href;
const rewrite = (src) => src
  .replace(/from "\.\.\/lib\//g, `from "${LIB_URL}/`)
  .replace(/from "\.\//g, `from "${ENG_URL}/`);
async function mutantOf(from, to) {
  const orig = fs.readFileSync(path.join(engDir, "weekly-digest.js"), "utf8");
  if (!orig.includes(from)) return { anchor: false };
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "digest-truth-"));
  const f = path.join(tmp, "weekly-digest.mjs");
  fs.writeFileSync(f, rewrite(orig.replace(from, to)));
  try {
    return { anchor: true, mod: await import(`${pathToFileURL(f).href}?t=${Date.now()}-${Math.random()}`) };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

// M1 — semantic grouping removed: raw rows would inflate the total again.
{
  const m = await mutantOf("const legacyChanges = groupSemanticChanges(", "const legacyChanges = ((x) => x)(");
  const c = m.anchor ? await m.mod.computeWeeklyChanges(env, "ws1") : null;
  ok("mutation M1 (grouping removed → raw-row total restored) is CAUGHT", m.anchor && c.total === 7);
}

// M2 — description dropped from the identity: meaningful transitions collapse.
{
  const m = await mutantOf('String(e?.description || "").trim().replace(/\\s+/g, " ").slice(0, 300),', '"",');
  const c = m.anchor ? await m.mod.computeWeeklyChanges(env, "ws1") : null;
  const growth = c ? c.top.filter((e) => e.event_type === "certificate_growth_detected") : [];
  ok("mutation M2 (2→3 / 3→4 transition collapsed) is CAUGHT", m.anchor && growth.length < 2);
}

// M3 — hostname dropped from the identity: separate certificates collapse on SAN text.
{
  const m = await mutantOf('String(e?.hostname || "").trim().toLowerCase(),', '"",');
  const c = m.anchor ? await m.mod.computeWeeklyChanges(env, "ws1") : null;
  const sans = c ? c.top.filter((e) => e.event_type === "certificate_new_san_detected") : [];
  ok("mutation M3 (certificates collapsed by SAN list alone) is CAUGHT", m.anchor && sans.length < 2);
}

// M4 — quiet-state completeness gate removed: stability without evidence.
{
  const m = await mutantOf('if (changes.assessment?.coverage !== "complete_assessment") {', "if (false) {");
  const q = m.anchor ? m.mod.buildDigestEmail("Beta", { total: 0, bySeverity: {}, byCategory: {}, top: [] }, env.FRONTEND_URL, "ws2") : null;
  ok("mutation M4 (completeness gate removed → false stability) is CAUGHT", m.anchor && /stable/i.test(q.text));
}

// M5 — CTA workspace context removed.
{
  const m = await mutantOf("const link = workspaceId ? `${base}?ws=${encodeURIComponent(workspaceId)}` : base;", "const link = base;");
  const q = m.anchor ? m.mod.buildDigestEmail("Acme", { total: 0, bySeverity: {}, byCategory: {}, top: [], assessment: { coverage: "complete_assessment" } }, env.FRONTEND_URL, "ws1") : null;
  ok("mutation M5 (workspace CTA context removed) is CAUGHT", m.anchor && !q.text.includes("?ws=ws1"));
}

// M6 — workspace predicate loosened on the event query: foreign events leak.
{
  // Seed a DISTINCT foreign event (different host + description): a leak must
  // surface as an extra semantic group, not merge into an existing ws1 group.
  seedEvent("ws2", "exposed_service_detected", "rdp.beta.example", "Port 3389 (RDP) exposed", "high", "-1 day");
  const m = await mutantOf("WHERE workspace_id = ? AND created_at > datetime('now', '-7 days')",
                           "WHERE (workspace_id = ? OR 1=1) AND created_at > datetime('now', '-7 days')");
  const c = m.anchor ? await m.mod.computeWeeklyChanges(env, "ws1") : null;
  ok("mutation M6 (workspace scoping removed adds foreign events) is CAUGHT",
     m.anchor && c.total > 5,
     `anchor=${m.anchor} total=${c?.total}`);
}

console.log(`\nweekly-digest-truth: ${pass}/${pass + fail} passed`);
if (fail) { console.error("weekly-digest-truth validation FAILED"); process.exit(1); }
console.log("weekly-digest-truth validation passed");
