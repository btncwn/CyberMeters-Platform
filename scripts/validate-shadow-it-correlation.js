#!/usr/bin/env node
//
// Shadow IT Multi-Source Correlation — DB-backed proof. CI-blocking. Runs
// against an in-memory SQLite database with the production schema + migrations.
//
// Proves the correlation DEPTH of the shadow-IT inventory: the same product
// observed by different sources (vendor signals, identity assets, cloud assets,
// email sender sources) merges into ONE canonical item with a non-destructive
// evidence union; unrelated products of one provider are never merged; alias
// resolution is deterministic; ownership derivation is server-side; the
// monitoring evaluator surfaces owner-missing / stale / disappearance /
// recurrence / removal-contradiction deterministically with the right case
// follow-up (open, reopen via canTransitionCase, or none); soft-deleted
// workspaces receive nothing; and list output is deterministic.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href);
const sii = await eng("shadow-it-inventory.js");
const {
  canonicalTechnologyKey, correlateShadowItInventory, evaluateShadowItMonitoring, classifyShadowItItem,
  listShadowItInventory, getShadowItItem, listShadowItItemEvents, unionEvidence, deriveOwnershipStatus,
  STALE_EVIDENCE_DAYS,
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
const NOW = "2026-07-20T00:00:00Z";

db.prepare("INSERT INTO users (id, email, name) VALUES ('u1','owner@example.com','Owner')").run();
db.prepare("INSERT INTO workspaces (id, name, owner_user_id, created_at, updated_at) VALUES ('ws1','Alpha','u1',datetime('now'),datetime('now'))").run();
db.prepare("INSERT INTO workspaces (id, name, owner_user_id, created_at, updated_at, deleted_at) VALUES ('wsDead','Dead','u1',datetime('now'),datetime('now'),datetime('now'))").run();
db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('d1','u1','example.com')").run();
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws1','d1')").run();

let vc = 0;
function seedVendor(ws, name, category, { conf = "medium", evidence = [], first = "2026-07-01T00:00:00Z", last = "2026-07-10T00:00:00Z", status = "active" } = {}) {
  db.prepare(`INSERT INTO workspace_vendors (id, workspace_id, vendor_name, category, source, evidence, confidence, risk_level, first_seen, last_seen, status, created_at, updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,datetime('now'),datetime('now'))`)
    .run(`wv-${++vc}`, ws, name, category, "cname", JSON.stringify(evidence), conf, "low", first, last, status);
}
let ac = 0;
function seedCloudAsset(ws, hostname, cloudProvider, { first = "2026-07-01T00:00:00Z", last = "2026-07-10T00:00:00Z" } = {}) {
  db.prepare(`INSERT INTO workspace_assets (id, workspace_id, domain_id, hostname, asset_type, source, first_seen, last_seen, status, cloud_provider, created_at, updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,datetime('now'),datetime('now'))`)
    .run(`wa-${++ac}`, ws, "d1", hostname, "cloud_storage", "exposure_probe", first, last, "active", cloudProvider);
}
let ic = 0;
function seedIdentityAsset(ws, hostname, provider, { first = "2026-07-01T00:00:00Z", last = "2026-07-10T00:00:00Z", risk = 0 } = {}) {
  db.prepare(`INSERT INTO identity_assets (id, workspace_id, domain_id, scan_id, hostname, asset_type, identity_type, provider, first_seen, last_seen, status, risk_score, created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'))`)
    .run(`ia-${++ic}`, ws, "d1", "scan1", hostname, "portal", "sso", provider, first, last, "active", risk);
}
let ec = 0;
function seedEmailSender(ws, domain, providerGuess, { first = "2026-07-05T00:00:00Z", last = "2026-07-12T00:00:00Z", conf = "medium" } = {}) {
  db.prepare(`INSERT INTO email_sender_sources (id, workspace_id, domain, source_ip, provider_guess, provider_confidence, first_seen, last_seen, total_messages, classification, created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,datetime('now'))`)
    .run(`ess-${++ec}`, ws, domain, `192.0.2.${ec}`, providerGuess, conf, first, last, 10, "unknown");
}

const evidenceTables = (item) => new Set((item.source_evidence || []).map((e) => e.source_table));

// ── Seed ws1 with distinct products (one product per scenario) ──────────────
seedVendor("ws1", "Okta", "identity", { conf: "high", evidence: [{ source: "cname", detail: "okta.com" }] });
seedIdentityAsset("ws1", "sso.example.com", "Okta");
seedVendor("ws1", "Google Workspace", "email_identity", { evidence: [{ source: "mx", detail: "aspmx.l.google.com" }] });
seedCloudAsset("ws1", "files.example.com", "gcs");
seedVendor("ws1", "Microsoft Office 365", "email_identity", { evidence: [{ source: "spf", detail: "spf.protection.outlook.com" }] });
seedVendor("ws1", "M365", "collaboration", { evidence: [{ source: "cname", detail: "sharepoint.com" }] });
seedVendor("ws1", "Slack", "collaboration", {});   // scenario 6: owner-missing after approval
seedVendor("ws1", "Zoom", "saas", {});             // scenario 8: approved disappearance
seedVendor("ws1", "Notion", "saas", {});           // scenario 9+12: rejected recurrence + case reopen
seedVendor("ws1", "Figma", "saas", {});            // scenario 10a: retired reappearance
seedVendor("ws1", "Miro", "saas", {});             // scenario 10b: exception expiry
seedVendor("ws1", "Dropbox", "saas", {});          // scenario 11: removal contradiction
seedVendor("ws1", "Legacy CRM", "saas", { last: "2026-01-01T00:00:00Z" }); // scenario 7: stale evidence

await correlateShadowItInventory(env, "ws1", { now: NOW });
const items1 = await listShadowItInventory(env, "ws1");
const byKey = (items, k) => items.filter((i) => i.canonical_technology_key === k);

// ── 1. Cross-source same-product correlation (vendor + identity asset) ──────
const oktas = byKey(items1, "okta");
eq("exactly ONE okta item across vendor + identity sources", oktas.length, 1);
const okta1 = oktas[0];
ok("okta item carries >=2 evidence entries", (okta1.source_evidence || []).length >= 2);
ok("okta evidence spans workspace_vendors AND identity_assets",
  evidenceTables(okta1).has("workspace_vendors") && evidenceTables(okta1).has("identity_assets"));
ok("okta source_type contains both 'vendor' and 'identity_provider'",
  okta1.source_type.split(",").includes("vendor") && okta1.source_type.split(",").includes("identity_provider"));

// ── 2. Unrelated provider products stay separate ────────────────────────────
eq("Google Workspace is its own item", byKey(items1, "google_workspace").length, 1);
eq("Google Cloud Storage (gcs cloud asset) is its own item", byKey(items1, "google_cloud_storage").length, 1);
ok("Google Workspace and Google Cloud Storage are NOT merged",
  byKey(items1, "google_workspace")[0].inventory_item_id !== byKey(items1, "google_cloud_storage")[0].inventory_item_id);

// ── 3. Alias determinism ─────────────────────────────────────────────────────
eq("'Microsoft Office 365' + 'M365' alias to ONE microsoft_365 item", byKey(items1, "microsoft_365").length, 1);
eq("canonicalTechnologyKey('G Suite') === canonicalTechnologyKey('Google Workspace')",
  canonicalTechnologyKey("G Suite"), canonicalTechnologyKey("Google Workspace"));
ok("Microsoft Entra ID is NOT aliased into Microsoft 365",
  canonicalTechnologyKey("Microsoft Entra ID") !== canonicalTechnologyKey("Microsoft 365"));

// ── 4. Evidence union is non-destructive ─────────────────────────────────────
const u = unionEvidence(
  [{ source_table: "a", source_record_id: "1", source_type: "vendor", last_seen_at: "2026-07-01" }],
  [{ source_table: "b", source_record_id: "2", source_type: "identity_provider", last_seen_at: "2026-07-05" }]);
eq("unionEvidence preserves both distinct references", u.length, 2);
ok("unionEvidence keeps both source_tables", u.some((e) => e.source_table === "a") && u.some((e) => e.source_table === "b"));
const oktaEvidenceBefore = (okta1.source_evidence || []).length;
const oktaTablesBefore = evidenceTables(okta1);
seedEmailSender("ws1", "example.com", "Okta"); // 3rd source for the SAME product
await correlateShadowItInventory(env, "ws1", { now: NOW });
const okta2 = await getShadowItItem(env, "ws1", okta1.inventory_item_id);
ok("re-correlation only grows evidence (never shrinks)", (okta2.source_evidence || []).length >= oktaEvidenceBefore);
ok("email_sender_sources evidence was appended", evidenceTables(okta2).has("email_sender_sources"));
ok("no previously-present source_table was lost", [...oktaTablesBefore].every((t) => evidenceTables(okta2).has(t)));

// ── 5. Ownership derivation ──────────────────────────────────────────────────
eq("deriveOwnershipStatus both owners → known", deriveOwnershipStatus("a", "b"), "known");
eq("deriveOwnershipStatus one owner → partial", deriveOwnershipStatus("a", ""), "partial");
eq("deriveOwnershipStatus no owners → missing", deriveOwnershipStatus("", ""), "missing");
eq("freshly-correlated item has ownership_status missing", okta2.ownership_status, "missing");
const bizOwner = await classifyShadowItItem(env, "ws1", okta1.inventory_item_id, "assign_business_owner", { actor_id: "admin", owner: "IT" });
eq("business owner alone → partial", bizOwner.item.ownership_status, "partial");
const techOwner = await classifyShadowItItem(env, "ws1", okta1.inventory_item_id, "assign_technical_owner", { actor_id: "admin", owner: "Platform" });
eq("business + technical owner → known", techOwner.item.ownership_status, "known");

// ── 6. Approved-without-owner surfaces owner_missing + a linked case ────────
const slack0 = byKey(items1, "slack")[0];
await classifyShadowItItem(env, "ws1", slack0.inventory_item_id, "approve", { actor_id: "admin", reason: "sanctioned" });
await evaluateShadowItMonitoring(env, "ws1", { now: NOW });
const slack1 = await getShadowItItem(env, "ws1", slack0.inventory_item_id);
eq("approved item with no owner gets recurrence_type owner_missing", slack1.recurrence_type, "owner_missing");
eq("owner-missing item requires assign_owner case action", slack1.required_case_action, "assign_owner");
ok("owner-missing item has a linked case", Boolean(slack1.linked_case_id));
const slackCase = slack1.linked_case_id ? db.prepare("SELECT * FROM managed_cases WHERE id = ?").get(slack1.linked_case_id) : null;
ok("linked case is a shadow_it_case with the canonical remediation",
  slackCase && slackCase.case_type === "shadow_it_case" && slackCase.remediation_id === "shadow_it.saas.review");

// ── 7. Stale evidence surfaces when nothing higher-priority applies ─────────
const crm1 = await getShadowItItem(env, "ws1", byKey(items1, "legacy_crm")[0].inventory_item_id);
ok("stale item evidence_age_days is a number > STALE_EVIDENCE_DAYS",
  typeof crm1.evidence_age_days === "number" && crm1.evidence_age_days > STALE_EVIDENCE_DAYS);
ok("unreviewed still-observed stale item is flagged evidence_stale",
  crm1.recurrence_type === "evidence_stale" || crm1.monitoring_reason === "evidence_stale");

// ── 8. Approved disappearance = monitoring observation, NOT an issue ────────
const zoom0 = byKey(items1, "zoom")[0];
await classifyShadowItItem(env, "ws1", zoom0.inventory_item_id, "approve", { actor_id: "admin", reason: "sanctioned" });
await classifyShadowItItem(env, "ws1", zoom0.inventory_item_id, "assign_business_owner", { actor_id: "admin", owner: "Sales" });
db.prepare("DELETE FROM workspace_vendors WHERE workspace_id = 'ws1' AND vendor_name = 'Zoom'").run();
await correlateShadowItInventory(env, "ws1", { now: NOW });
const zoom1 = await getShadowItItem(env, "ws1", zoom0.inventory_item_id);
eq("disappeared approved item is no_longer_observed", zoom1.monitoring_status, "no_longer_observed");
eq("disappearance of an approved item is approved_disappeared", zoom1.recurrence_type, "approved_disappeared");
eq("approved disappearance requires NO case action", zoom1.required_case_action, "none");
ok("no case is opened for an approved disappearance",
  !zoom1.linked_case_id && db.prepare("SELECT COUNT(*) AS n FROM managed_cases WHERE workspace_id = 'ws1' AND finding_id = 'shadow_it:zoom'").get().n === 0);

// ── 9. Rejected-still-observed opens a case with the canonical remediation ──
const notion0 = byKey(items1, "notion")[0];
const rejected = await classifyShadowItItem(env, "ws1", notion0.inventory_item_id, "reject", { actor_id: "admin", reason: "not sanctioned" });
ok("rejected-still-observed item gets a linked case", Boolean(rejected.item.linked_case_id));
const notionCase = db.prepare("SELECT * FROM managed_cases WHERE id = ?").get(rejected.item.linked_case_id);
ok("rejection case is a shadow_it_case with remediation shadow_it.saas.review",
  notionCase && notionCase.case_type === "shadow_it_case" && notionCase.remediation_id === "shadow_it.saas.review");
eq("a case_created event exists for the rejection case",
  db.prepare("SELECT COUNT(*) AS n FROM managed_case_events WHERE case_id = ? AND action = 'case_created'").get(rejected.item.linked_case_id).n, 1);

// ── 10. Retired reappearance + exception expiry ─────────────────────────────
const figma0 = byKey(items1, "figma")[0];
await classifyShadowItItem(env, "ws1", figma0.inventory_item_id, "retire", { actor_id: "admin", reason: "decommissioned" });
db.prepare("UPDATE shadow_it_inventory SET monitoring_status = 'reappeared' WHERE id = ?").run(figma0.inventory_item_id);
const miro0 = byKey(items1, "miro")[0];
await classifyShadowItItem(env, "ws1", miro0.inventory_item_id, "mark_exception", { actor_id: "admin", reason: "temporary tolerance", exception_until: "2026-07-01T00:00:00Z" });
await evaluateShadowItMonitoring(env, "ws1", { now: NOW });
const figma1 = await getShadowItItem(env, "ws1", figma0.inventory_item_id);
eq("retired item that reappeared demands open_or_reopen", figma1.required_case_action, "open_or_reopen");
eq("retired reappearance recurrence_type", figma1.recurrence_type, "retired_reappeared");
const miro1 = await getShadowItItem(env, "ws1", miro0.inventory_item_id);
eq("exception past its expiry surfaces exception_expired", miro1.recurrence_type, "exception_expired");

// ── 11. Removal contradiction (customer assertion vs observation) ───────────
const dropbox0 = byKey(items1, "dropbox")[0];
const removed = await classifyShadowItItem(env, "ws1", dropbox0.inventory_item_id, "mark_removed", { actor_id: "admin" });
eq("mark_removed records the customer assertion", removed.item.removal_status, "removed");
await evaluateShadowItMonitoring(env, "ws1", { now: NOW });
const dropbox1 = await getShadowItItem(env, "ws1", dropbox0.inventory_item_id);
eq("still-observed removed item is contradicted", dropbox1.removal_verified, "contradicted");
eq("contradiction recurrence_type", dropbox1.recurrence_type, "removal_contradicted");
ok("a removal_contradicted event was appended",
  (await listShadowItItemEvents(env, "ws1", dropbox0.inventory_item_id)).some((e) => e.event_type === "removal_contradicted"));
ok("contradiction opens a linked case", Boolean(dropbox1.linked_case_id));
eq("the customer assertion is preserved (removal_status stays removed)", dropbox1.removal_status, "removed");

// ── 11b. DISAPPEARANCE IS NOT VERIFIED REMOVAL ──────────────────────────────
// The defect this exists to prevent (live until 2026-07-16): the evaluator read
//   removal_verified = stillObserved ? "contradicted" : "verified"
// so a customer's "I removed it" plus our failure to see the thing was laundered into
// "verified" and served by the API — while this same engine's header states
// "disappearance != verified removal", its own disappearance event records
// `note: "not_verified_removed"`, and CLAUDE.md forbids exactly this inference.
// Absence of evidence is not evidence of removal: the technology may have been renamed,
// moved, stopped serving a public signal, or simply not been re-observed this pass.
//
// Suite 11 above only ever exercised the CONTRADICTED branch, so the `verified` branch
// shipped untested. That is why this section seeds the ABSENCE case explicitly.
{
  // Everything EXCEPT dropbox is still observed — otherwise this pass would mark the
  // whole inventory missing and later sections would be asserting against a fiction.
  const dropboxKey = db.prepare("SELECT canonical_technology_key FROM shadow_it_inventory WHERE id = ?")
    .get(dropbox0.inventory_item_id).canonical_technology_key;
  const stillSeen = new Set(
    db.prepare("SELECT canonical_technology_key FROM shadow_it_inventory WHERE workspace_id = 'ws1'")
      .all().map((r) => r.canonical_technology_key).filter((k) => k !== dropboxKey),
  );

  await evaluateShadowItMonitoring(env, "ws1", { now: NOW, seenKeys: stillSeen });
  const gone = await getShadowItItem(env, "ws1", dropbox0.inventory_item_id);

  eq("a removed item that disappeared is no_longer_observed", gone.monitoring_status, "no_longer_observed");
  ok("disappearance NEVER yields verified removal", gone.removal_verified !== "verified");
  eq("it stays UNVERIFIED — a customer assertion we could not confirm", gone.removal_verified, "unverified");
  eq("the customer assertion itself is preserved", gone.removal_status, "removed");
  ok("and the disappearance is recorded as not-verified-removed history",
    (await listShadowItItemEvents(env, "ws1", dropbox0.inventory_item_id))
      .some((e) => e.event_type === "monitoring_changed" && /not_verified_removed/.test(e.detail_json || "")));

  // Direction check: `contradicted` must remain REACHABLE. A guard that returned
  // "unverified" unconditionally would satisfy every assertion above while destroying the
  // one externally-grounded verdict this domain genuinely has.
  db.prepare("UPDATE shadow_it_inventory SET monitoring_status = 'observed' WHERE id = ?").run(dropbox0.inventory_item_id);
  await evaluateShadowItMonitoring(env, "ws1", { now: NOW });
  const backAgain = await getShadowItItem(env, "ws1", dropbox0.inventory_item_id);
  eq("a removed item observed AGAIN is still contradicted (we saw it — that IS evidence)",
    backAgain.removal_verified, "contradicted");
}

// ── 12. Existing case is REOPENED via canTransitionCase, never duplicated ───
db.prepare("UPDATE managed_cases SET status = 'verified' WHERE id = ?").run(rejected.item.linked_case_id);
await evaluateShadowItMonitoring(env, "ws1", { now: NOW }); // Notion still rejected + observed
eq("verified case is reopened on recurrence (base lifecycle verified→reopened)",
  db.prepare("SELECT status FROM managed_cases WHERE id = ?").get(rejected.item.linked_case_id).status, "reopened");
eq("recurrence reuses the SAME case (linked_case_id unchanged)",
  (await getShadowItItem(env, "ws1", notion0.inventory_item_id)).linked_case_id, rejected.item.linked_case_id);

// ── 13. Soft-deleted workspace receives no observations ─────────────────────
seedVendor("wsDead", "Trello", "collaboration", {});
const dead = await correlateShadowItInventory(env, "wsDead", {});
eq("soft-deleted workspace correlation is skipped", dead.skipped, "workspace_inactive");
eq("no inventory rows created for a soft-deleted workspace",
  db.prepare("SELECT COUNT(*) AS n FROM shadow_it_inventory WHERE workspace_id = 'wsDead'").get().n, 0);

// ── 14. Deterministic list output ────────────────────────────────────────────
ok("list API output is deterministic",
  JSON.stringify(await listShadowItInventory(env, "ws1")) === JSON.stringify(await listShadowItInventory(env, "ws1")));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
