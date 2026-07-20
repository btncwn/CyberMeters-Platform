#!/usr/bin/env node
//
// Managed-alert truth & field mapping — DB-backed, CI-blocking.
//
// Written for the Shadow IT Alert Trust episode (July 2026), after a production
// owner_missing alert for the approved service Stripe rendered:
//   • the raw workspace UUID where the customer-facing name belongs;
//   • "Affected Domain: stripe" — a SERVICE labelled as a domain;
//   • the same registry sentence as BOTH "What Changed" and "Recommended Next
//     Action" (sanction-review wording for an already-approved service);
//   • no evidence source, a generic /notifications CTA, and an "Attack Surface
//     Management" footer on a Shadow IT alert.
//
// This suite proves the corrected contract end-to-end (real emit pipeline over a
// real seeded schema) and mutation-proves every load-bearing gate. The truth
// rules it pins: observed ≠ unauthorised; approved-but-owner-missing is never
// described as unapproved; a vendor/service is never labelled as a domain;
// missing evidence never becomes a confident statement; recommendation is never
// the event description; foreign/deleted workspaces can never populate or
// receive an alert.
//
// Node 24+.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engDir = path.join(root, "workers", "scan-api", "src", "engines");
const eng = (f) => pathToFileURL(path.join(engDir, f)).href;

const { formatAlertEmail } = await import(eng("alerts.js"));
const {
  emitManagedAlert, buildAlertEmailFields, boundedEvidenceSentence,
  ALERT_ENTITY_TYPE_LABELS, ensureAlertActivation, buildAlertDedupeKey,
} = await import(eng("managed-alerts.js"));
const {
  emitLifecycleAlert, lifecycleRecordLink, describeRecurrenceEvent,
  recommendationForRecurrence,
} = await import(eng("alert-consumers.js"));
const { evaluateShadowItMonitoring, summarizeShadowItEvidence } = await import(eng("shadow-it-inventory.js"));

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

// ── Real schema ──────────────────────────────────────────────────────────────
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
const sentEmails = [];
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init) => {
  if (String(url).includes("resend.com")) {
    try { sentEmails.push(JSON.parse(String(init?.body || "{}"))); } catch { sentEmails.push({}); }
    return new Response(JSON.stringify({ id: `email_${sentEmails.length}` }), { status: 200, headers: { "content-type": "application/json" } });
  }
  return new Response("{}", { status: 200 });
};

// ── Seed ─────────────────────────────────────────────────────────────────────
const WS_A4 = "workspace_a4e2432f-ea82-40a9-b814-38ecc137b035";
const WS_OTHER = "workspace_0ther999-0000-0000-0000-000000000000";
const WS_DEAD = "workspace_dead0000-0000-0000-0000-000000000000";

function user(id, email) {
  db.prepare("INSERT INTO users (id, email, name, plan, created_at) VALUES (?, ?, ?, 'professional', datetime('now'))").run(id, email, id);
  db.prepare("UPDATE users SET email_verified = 1 WHERE id = ?").run(id);
  db.prepare(`INSERT INTO subscriptions (id, owner_user_id, plan, subscription_status, status, current_period_end, created_at, updated_at)
              VALUES (?, ?, 'professional', 'active', 'active', datetime('now', '+30 days'), datetime('now'), datetime('now'))`)
    .run(`sub_${id}`, id);
}
function workspace(ws, owner, name, { deleted = false } = {}) {
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES (?, ?, ?)").run(ws, owner, name);
  db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?, ?, ?, 'owner')").run(`${ws}_m`, ws, owner);
  if (deleted) db.prepare("UPDATE workspaces SET deleted_at = datetime('now') WHERE id = ?").run(ws);
}
user("u_a4", "a4@example.com");
user("u_other", "other@example.com");
user("u_dead", "dead@example.com");
workspace(WS_A4, "u_a4", "A4 Managed Case Test");
workspace(WS_OTHER, "u_other", "Other Tenant Workspace");
workspace(WS_DEAD, "u_dead", "Deleted Workspace", { deleted: true });

// Monitored domain: exactly one for WS_A4 (unambiguous); two for WS_OTHER.
db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('d_cm', 'u_a4', 'cybermeters.com')").run();
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES (?, 'd_cm')").run(WS_A4);
db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('d_o1', 'u_other', 'other-one.example')").run();
db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('d_o2', 'u_other', 'other-two.example')").run();
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES (?, 'd_o1')").run(WS_OTHER);
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES (?, 'd_o2')").run(WS_OTHER);

// The audited Stripe facts: CSP script-src evidence naming js.stripe.com.
db.prepare(`INSERT INTO workspace_vendors (id, workspace_id, vendor_name, category, source, evidence, confidence, first_seen, last_seen, status, created_at, updated_at)
            VALUES ('wv_stripe', ?, 'Stripe', 'saas', 'csp',
                    '[{"source":"csp:script-src","detail":"https://js.stripe.com"}]',
                    'high', '2026-07-01T00:00:00Z', '2026-07-19T00:00:00Z', 'active', datetime('now'), datetime('now'))`).run(WS_A4);

function seedItem(id, ws, key, display, over = {}) {
  db.prepare(`INSERT INTO shadow_it_inventory
      (id, workspace_id, canonical_technology_key, display_name, provider, category, source_type,
       observed_identifiers_json, observed_hostnames_json, observed_domains_json,
       first_seen_at, last_seen_at, confidence, classification, ownership_status, monitoring_status,
       source_evidence_json, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, 'saas', 'vendor', '["Stripe"]', ?, '[]',
            '2026-07-01T00:00:00Z', '2026-07-19T00:00:00Z', 'high', ?, ?, 'observed', ?, datetime('now'), datetime('now'))`)
    .run(id, ws, key, display, display,
      over.hostnames ?? '["https://js.stripe.com"]',
      over.classification ?? "approved",
      over.ownership_status ?? "missing",
      over.evidence ?? '[{"source_table":"workspace_vendors","source_record_id":"wv_stripe","source_type":"vendor","observed_identifier":"Stripe"}]');
}
seedItem("sii_stripe", WS_A4, "stripe", "Stripe");
// A second, independent item reserved for the mutation harness (own occurrence,
// own dedupe key) so mutant runs never collide with the main assertions.
seedItem("sii_slack", WS_A4, "slack", "Slack", { hostnames: '["https://slack.com"]', evidence: "[]" });

function seedOccurrence(id, itemId, ws, recurrence) {
  db.prepare(`INSERT INTO shadow_it_inventory_events (id, item_id, workspace_id, actor_type, event_type, detail_json, created_at)
              VALUES (?, ?, ?, 'system', 'monitoring_changed', ?, datetime('now'))`)
    .run(id, itemId, ws, JSON.stringify({
      from_monitoring_status: "observed", to_monitoring_status: "observed",
      from_recurrence_type: null, to_recurrence_type: recurrence,
      required_case_action: "assign_owner", reason: recurrence, entity: "stripe",
    }));
}
seedOccurrence("sie_stripe_1", "sii_stripe", WS_A4, "owner_missing");
seedOccurrence("sie_slack_1", "sii_slack", WS_A4, "owner_missing");
// Pristine item + occurrence in the OTHER workspace, reserved for the M3 mutant:
// the WS_A4 evaluator runs consume every WS_A4 occurrence's dedupe key first.
seedItem("sii_m3", WS_OTHER, "notion", "Notion", { hostnames: '["https://notion.so"]', evidence: "[]" });
seedOccurrence("sie_m3_1", "sii_m3", WS_OTHER, "owner_missing");

const env = {
  cybermeters_db: makeD1(db),
  ALERT_EMAIL_FROM: "alerts@cybermeters.com",
  RESEND_API_KEY: "re_test",
  FRONTEND_URL: "https://app.cybermeters.com",
};

const WATERMARK = "2020-01-01T00:00:00Z";
await ensureAlertActivation(env, WS_A4, "shadow_it_unmanaged_technology", { now: WATERMARK });
await ensureAlertActivation(env, WS_OTHER, "shadow_it_unmanaged_technology", { now: WATERMARK });
await ensureAlertActivation(env, WS_DEAD, "shadow_it_unmanaged_technology", { now: WATERMARK });
const notifs = (ws) => db.prepare("SELECT * FROM notification_events WHERE workspace_id = ? ORDER BY created_at, rowid").all(ws);

// ── 1. formatAlertEmail — typed entity, evidence, footer ─────────────────────
{
  const typed = formatAlertEmail({
    workspaceName: "A4 Managed Case Test",
    entityLabel: "Affected Service", entityDisplay: "Stripe", monitoredDomain: "cybermeters.com",
    evidenceSource: "Observed via Content-Security-Policy (script-src): https://js.stripe.com (last seen 2026-07-19).",
    moduleName: "Shadow IT & Unmanaged Technology",
    whatChanged: "An approved service does not have an assigned owner.",
    recommendation: "Assign a business or technical owner for Stripe and record the responsible team.",
    link: "https://app.cybermeters.com/ws/shadow-it?item=sii_stripe",
  });
  ok("typed entity renders its own label", typed.text.includes("Affected Service: Stripe") && typed.html.includes("Affected Service"));
  ok("monitored domain is a SEPARATE row", typed.text.includes("Monitored Domain: cybermeters.com"));
  ok("typed email never renders 'Affected Domain'", !typed.text.includes("Affected Domain") && !typed.html.includes("Affected Domain"));
  ok("evidence section renders", typed.text.includes("How this was observed:") && typed.text.includes("js.stripe.com"));
  ok("footer names the module, not ASM", typed.text.includes("CyberMeters — Shadow IT & Unmanaged Technology") && !typed.text.includes("Attack Surface Management"));
  ok("html footer matches", typed.html.includes("Shadow IT &amp; Unmanaged Technology") && !typed.html.includes("Attack Surface Management"));

  const legacy = formatAlertEmail({
    workspaceName: "WS", domain: "example.com",
    whatChanged: "changed", recommendation: "act", link: null,
  });
  ok("legacy domain-only caller keeps 'Affected Domain'", legacy.text.includes("Affected Domain: example.com"));
  ok("legacy caller gets the neutral footer by default", legacy.text.includes("CyberMeters — Security Monitoring"));
  const legacyAsm = formatAlertEmail({ workspaceName: "WS", domain: "example.com", whatChanged: "c", recommendation: "a", link: null, moduleName: "Attack Surface Management" });
  ok("legacy scan path can keep its ASM footer explicitly", legacyAsm.text.includes("CyberMeters — Attack Surface Management"));
  ok("no evidence => no evidence section", !legacy.text.includes("How this was observed"));
}

// ── 2. buildAlertEmailFields — bounded mapping, fail-safe typing ─────────────
{
  const f = buildAlertEmailFields({
    workspaceName: "A4 Managed Case Test", domain_key: "shadow_it_unmanaged_technology",
    message: "An approved service does not have an assigned owner.",
    metadata: {
      entity_type: "service", entity_display: "Stripe", hostname: "stripe",
      monitored_domain: "cybermeters.com",
      evidence_source: { label: "Content-Security-Policy (script-src)", detail: "https://js.stripe.com", last_seen_at: "2026-07-19T00:00:00Z" },
      recommended_action: "Assign a business or technical owner for Stripe and record the responsible team.",
    },
    link: "https://x/ws/shadow-it?item=sii_stripe", origin: "https://x",
  });
  eq("service entity label", f.entityLabel, "Affected Service");
  eq("entity display is the display name, not the slug", f.entityDisplay, "Stripe");
  eq("legacy domain slot is EMPTY when typed", f.domain, null);
  eq("monitored domain carried", f.monitoredDomain, "cybermeters.com");
  eq("module footer from the canonical eight-domain map", f.moduleName, "Shadow IT & Unmanaged Technology");
  ok("evidence sentence built and bounded", f.evidenceSource.includes("Content-Security-Policy") && f.evidenceSource.includes("js.stripe.com") && f.evidenceSource.includes("2026-07-19"));
  ok("what changed differs from recommendation", f.whatChanged !== f.recommendation);

  const unknownType = buildAlertEmailFields({
    workspaceName: "W", domain_key: "certificates_trust", message: "m",
    metadata: { entity_type: "starship", entity_display: "X", hostname: "www.example.com" },
  });
  eq("unknown entity_type falls back to legacy domain labelling", unknownType.entityLabel, null);
  eq("unknown entity_type keeps the hostname in the legacy slot", unknownType.domain, "www.example.com");
  const noType = buildAlertEmailFields({ workspaceName: "W", domain_key: "certificates_trust", message: "m", metadata: { hostname: "www.example.com" } });
  eq("absent entity_type keeps the legacy slot (compatibility rule)", noType.domain, "www.example.com");
  ok("legacy path has no monitored-domain row", noType.monitoredDomain === null);
  ok("empty workspace name gets bounded fallback, never the id", buildAlertEmailFields({ workspaceName: "", domain_key: "x", message: "m" }).workspaceName === "Unknown Workspace");
  ok("bounded entity vocabulary includes only evidence-based types",
     Object.keys(ALERT_ENTITY_TYPE_LABELS).every((k) => ["domain", "hostname", "service", "vendor", "technology", "certificate", "identity_surface", "sender"].includes(k)));
  eq("missing evidence yields NO confident statement", boundedEvidenceSentence(null), null);
  eq("empty evidence object yields NO statement", boundedEvidenceSentence({}), null);
}

// ── 3. What changed ≠ recommended action; owner_missing truth ────────────────
{
  const wc = describeRecurrenceEvent("shadow_it_unmanaged_technology", "owner_missing", "Stripe");
  const act = recommendationForRecurrence("shadow_it_unmanaged_technology", "owner_missing", "Stripe", "Review each observed service against your approved-technology inventory, confirm it is sanctioned, and record data-handling and access arrangements.");
  eq("owner_missing: what changed states the approved-without-owner fact", wc, "An approved service does not have an assigned owner.");
  eq("owner_missing: action instructs owner assignment", act, "Assign a business or technical owner for Stripe and record the responsible team.");
  ok("owner_missing copy never uses sanction-review wording", !/sanction/i.test(wc) && !/sanction/i.test(act));
  ok("owner_missing copy never implies unauthorised/malicious", !/unauthoris|unapproved|malicious/i.test(wc + act));
  const gwc = describeRecurrenceEvent("certificates_trust", "verification_failed", "www.example.com");
  const gact = recommendationForRecurrence("certificates_trust", "verification_failed", "www.example.com", "Renew the certificate.");
  ok("generic recurrence: event description names entity + transition", gwc.includes("www.example.com") && gwc.includes("verification failed"));
  eq("generic recurrence: recommendation stays the registry action", gact, "Renew the certificate.");
  ok("generic recurrence: the two never collapse", gwc !== gact);
}

// ── 4. Tenant-safe Shadow IT CTA ─────────────────────────────────────────────
{
  const link = lifecycleRecordLink(env, "shadow_it_unmanaged_technology", "sii_stripe");
  ok("shadow IT deep link targets the inventory surface with the item", String(link).includes("/ws/shadow-it?item=sii_stripe"));
  ok("shadow IT deep link is not the generic notifications list", !String(link).includes("/notifications"));
  eq("unknown domain still resolves no link (honest fallback)", lifecycleRecordLink(env, "no_such_domain", "x"), null);
}

// ── 5. End-to-end: the audited Stripe case through the REAL pipeline ─────────
{
  sentEmails.length = 0;
  const monitoredDomain = "cybermeters.com";
  const evidence = await summarizeShadowItEvidence(env, db.prepare("SELECT * FROM shadow_it_inventory WHERE id = 'sii_stripe'").get());
  ok("evidence summary resolves the CSP signal", evidence?.label?.includes("Content-Security-Policy") && evidence?.detail === "https://js.stripe.com");
  const r = await emitLifecycleAlert(env, {
    workspace_id: WS_A4, domain_key: "shadow_it_unmanaged_technology",
    record_id: "sii_stripe", entity: "stripe", hostname: null,
    recurrence: "owner_missing", finding_type: "saas_exposure",
    entity_type: "service", entity_display: "Stripe",
    monitored_domain: monitoredDomain, evidence_source: evidence,
  });
  ok("stripe owner_missing alert emitted", r?.emitted === true, JSON.stringify(r));
  eq("exactly one email sent", sentEmails.length, 1);
  const mail = sentEmails[0] || {};
  const body = `${mail.text || ""}\n${mail.html || ""}`;
  ok("email shows the customer-facing workspace name", body.includes("A4 Managed Case Test"));
  ok("email never shows the raw workspace UUID", !body.includes(WS_A4));
  ok("email labels Stripe as a SERVICE", body.includes("Affected Service: Stripe"));
  ok("email never labels the service as a domain", !body.includes("Affected Domain"));
  ok("email shows the monitored domain separately", body.includes("Monitored Domain: cybermeters.com"));
  ok("email states the approved-without-owner fact", body.includes("An approved service does not have an assigned owner."));
  ok("email recommends owner assignment for Stripe", body.includes("Assign a business or technical owner for Stripe"));
  ok("what changed and recommendation are different sentences",
     !body.includes("What Changed:\nAssign a business or technical owner"));
  ok("email carries the CSP evidence source", body.includes("Content-Security-Policy") && body.includes("js.stripe.com"));
  ok("email footer is Shadow IT, not Attack Surface Management", body.includes("Shadow IT") && !body.includes("Attack Surface Management"));
  ok("email never claims unauthorised/unapproved/malicious", !/unauthoris|unapproved|malicious/i.test(body));
  ok("CTA is the workspace-scoped shadow IT item", body.includes("/ws/shadow-it?item=sii_stripe"));

  const row = notifs(WS_A4).at(-1);
  const meta = JSON.parse(row.metadata_json || "{}");
  ok("canonical event message is the event description", row.message === "An approved service does not have an assigned owner.");
  ok("canonical event recommendation differs from message", meta.recommended_action !== row.message);
  ok("in-app card link matches the email CTA (parity)", String(meta.link || "").includes("/ws/shadow-it?item=sii_stripe"));
  eq("metadata entity typing persisted for the in-app surface", [meta.entity_type, meta.entity_display, meta.monitored_domain], ["service", "Stripe", "cybermeters.com"]);
}

// ── 6. Foreign workspace name can never populate the alert ───────────────────
{
  const all = sentEmails.map((m) => `${m.text || ""}${m.html || ""}`).join("\n");
  ok("no foreign workspace name in any sent email", !all.includes("Other Tenant Workspace"));
}

// ── 7. Deleted workspace still receives nothing ──────────────────────────────
{
  const before = sentEmails.length;
  const r = await emitManagedAlert(env, {
    workspace_id: WS_DEAD, domain_key: "shadow_it_unmanaged_technology", kind: "shadow_it_unmanaged_technology.owner_missing",
    severity: "low", title: "t", message: "m", observed_at: "2026-07-19T00:00:00Z",
    dedupe_key: buildAlertDedupeKey({ domain_key: "shadow_it_unmanaged_technology", kind: "x", subject: "dead" }),
  });
  eq("deleted workspace: not emitted", r.emitted, false);
  eq("deleted workspace: reason", r.reason, "workspace_deleted");
  eq("deleted workspace: no email sent", sentEmails.length, before);
}

// ── 8. Evaluator drive: occurrence + dedupe preserved ────────────────────────
{
  const beforeRows = notifs(WS_A4).length;
  await evaluateShadowItMonitoring(env, WS_A4, { now: new Date().toISOString() });
  const afterFirst = notifs(WS_A4).length;
  ok("evaluator transition emits one new canonical event", afterFirst === beforeRows + 2 || afterFirst === beforeRows + 1,
     `before=${beforeRows} after=${afterFirst}`); // stripe + slack items may both transition
  await evaluateShadowItMonitoring(env, WS_A4, { now: new Date().toISOString() });
  eq("second unchanged pass emits nothing new (dedupe/suppression preserved)", notifs(WS_A4).length, afterFirst);
}

// ── 9. MUTATION HARNESS ──────────────────────────────────────────────────────
// Mutants are written to a temp module with relative imports rewritten to the
// real engine files, so each mutant runs against the true dependency graph.
const ENG_URL = pathToFileURL(engDir).href;
const LIB_URL = pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib")).href;
const rewrite = (src) => src
  .replace(/from "\.\.\/lib\//g, `from "${LIB_URL}/`)
  .replace(/from "\.\//g, `from "${ENG_URL}/`);
async function mutantOf(file, from, to) {
  const orig = fs.readFileSync(path.join(engDir, file), "utf8");
  if (!orig.includes(from)) return { anchor: false };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "alert-truth-"));
  const f = path.join(dir, file.replace(/\.js$/, ".mjs"));
  fs.writeFileSync(f, rewrite(orig.replace(from, to)));
  try {
    return { anchor: true, mod: await import(`${pathToFileURL(f).href}?t=${Date.now()}-${Math.random()}`) };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// M1 — workspace name replaced with the raw id: the email must regress to the UUID.
{
  const m = await mutantOf("managed-alerts.js", "workspaceName: wsRow.name,", "workspaceName: workspace_id,");
  let caught = false;
  if (m.anchor) {
    sentEmails.length = 0;
    await m.mod.emitManagedAlert(env, {
      workspace_id: WS_A4, domain_key: "shadow_it_unmanaged_technology", kind: "shadow_it_unmanaged_technology.owner_missing",
      severity: "low", title: "t-m1", message: "m", observed_at: "2026-07-19T12:00:00Z",
      dedupe_key: buildAlertDedupeKey({ domain_key: "shadow_it_unmanaged_technology", kind: "m1", subject: "m1" }),
      metadata: { entity_type: "service", entity_display: "Stripe" },
    });
    const body = sentEmails.map((x) => `${x.text || ""}${x.html || ""}`).join("");
    caught = body.includes(WS_A4);
  }
  ok("mutation M1 (workspace name → raw id) is CAUGHT", m.anchor && caught);
}

// M2 — entity type forced to domain: a service would be labelled a domain again.
{
  const m = await mutantOf("managed-alerts.js",
    'const entityLabel = ALERT_ENTITY_TYPE_LABELS[String(metadata.entity_type || "")] || null;',
    'const entityLabel = "Affected Domain";');
  const f = m.anchor ? m.mod.buildAlertEmailFields({
    workspaceName: "W", domain_key: "shadow_it_unmanaged_technology", message: "m",
    metadata: { entity_type: "service", entity_display: "Stripe" },
  }) : null;
  ok("mutation M2 (service forced to domain label) is CAUGHT", m.anchor && f.entityLabel !== "Affected Service");
}

// M3 — What Changed collapses back into the recommendation.
{
  const m = await mutantOf("alert-consumers.js", "message: whatChanged,", "message: recommendation,");
  let caught = false;
  if (m.anchor) {
    const before = notifs(WS_OTHER).length;
    await m.mod.emitLifecycleAlert(env, {
      workspace_id: WS_OTHER, domain_key: "shadow_it_unmanaged_technology",
      record_id: "sii_m3", entity: "notion", recurrence: "owner_missing",
      finding_type: "saas_exposure", entity_type: "service", entity_display: "Notion",
    });
    const rows = notifs(WS_OTHER);
    const row = rows.length > before ? rows.at(-1) : null;
    const meta = row ? JSON.parse(row.metadata_json || "{}") : {};
    caught = Boolean(row) && row.message === meta.recommended_action;
  }
  ok("mutation M3 (what-changed = recommendation collapse) is CAUGHT", m.anchor && caught);
}

// M4 — evidence source silently dropped.
{
  const m = await mutantOf("managed-alerts.js",
    "export function boundedEvidenceSentence(evidence) {",
    "export function boundedEvidenceSentence(evidence) { return null;");
  const f = m.anchor ? m.mod.buildAlertEmailFields({
    workspaceName: "W", domain_key: "shadow_it_unmanaged_technology", message: "m",
    metadata: { entity_type: "service", entity_display: "Stripe", evidence_source: { label: "Content-Security-Policy", detail: "https://js.stripe.com" } },
  }) : null;
  ok("mutation M4 (evidence source dropped) is CAUGHT", m.anchor && f.evidenceSource === null);
}

// M5 — footer reverts to hard-coded Attack Surface Management.
{
  const m = await mutantOf("alerts.js",
    'const footerModule = String(moduleName || "Security Monitoring").slice(0, 80);',
    'const footerModule = "Attack Surface Management";');
  const out = m.anchor ? m.mod.formatAlertEmail({
    workspaceName: "W", entityLabel: "Affected Service", entityDisplay: "Stripe",
    moduleName: "Shadow IT & Unmanaged Technology", whatChanged: "c", recommendation: "a", link: null,
  }) : null;
  ok("mutation M5 (footer reverts to ASM) is CAUGHT", m.anchor && out.text.includes("Attack Surface Management"));
}

// M6 — deleted-workspace guard / workspace scoping removed from the name lookup.
{
  const m = await mutantOf("managed-alerts.js",
    "SELECT id, name FROM workspaces WHERE id = ? AND deleted_at IS NULL",
    "SELECT id, name FROM workspaces WHERE id = ?");
  let caught = false;
  if (m.anchor) {
    const r = await m.mod.emitManagedAlert(env, {
      workspace_id: WS_DEAD, domain_key: "shadow_it_unmanaged_technology", kind: "shadow_it_unmanaged_technology.owner_missing",
      severity: "low", title: "t-m6", message: "m", observed_at: "2026-07-19T12:00:00Z",
      dedupe_key: buildAlertDedupeKey({ domain_key: "shadow_it_unmanaged_technology", kind: "m6", subject: "m6" }),
    });
    caught = r.reason !== "workspace_deleted";   // the guard no longer refuses
  }
  ok("mutation M6 (deleted-workspace guard removed) is CAUGHT", m.anchor && caught);
}

// M7 — tenant-safe CTA construction removed (back to the generic list).
{
  const m = await mutantOf("alert-consumers.js",
    "`${origin}/ws/shadow-it?item=${encodeURIComponent(recordId)}`",
    "`${origin}/notifications`");
  const link = m.anchor ? m.mod.lifecycleRecordLink(env, "shadow_it_unmanaged_technology", "sii_stripe") : null;
  ok("mutation M7 (shadow IT CTA removed) is CAUGHT", m.anchor && !String(link).includes("/ws/shadow-it"));
}

globalThis.fetch = realFetch;
console.log(`\nalert-truth-mapping: ${pass}/${pass + fail} passed`);
if (fail) { console.error("alert-truth-mapping validation FAILED"); process.exit(1); }
console.log("alert-truth-mapping validation passed");
