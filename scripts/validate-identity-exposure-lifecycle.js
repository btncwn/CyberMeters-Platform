#!/usr/bin/env node
//
// Identity Exposure Managed Workflow — DB-backed proof. CI-blocking. Runs against
// an in-memory SQLite database with the production schema + migrations.
//
// Proves: raw identity_assets correlate into ONE canonical managed record per
// external identity surface; provider aliases resolve deterministically (Entra ≠
// M365); a hostname-anchored surface keeps its identity across a provider change
// (material event, OLD evidence preserved); evidence union is non-destructive
// (first_seen stable, last_seen advances, no duplicates); customer classification
// is separate from observation; three-role ownership derives known/partial/
// missing; the workflow validates fields, exceptions require reason+expiry, and a
// customer-recorded change/removal is NOT verified; external verification is
// method-specific (disappearance across a window → verified; still observed →
// failed; unchanged/within-window → inconclusive; nothing recorded → pending);
// the monitoring evaluator surfaces public-admin / owner-missing / unexpected /
// removal-contradiction / provider-change / exception-expiry / retired-reappear
// deterministically with the right case follow-up (open, assign_owner, reopen via
// canTransitionCase); identity cases use createManagedCase → identity.* canonical
// remediation; leaked-credential/MFA/Conditional-Access stay unknown; soft-
// deleted workspaces get nothing; and list output is deterministic.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href);
const il = await eng("identity-lifecycle.js");
const ip = await eng("identity-policy.js");
const {
  correlateIdentityExposure, evaluateIdentityExposureMonitoring, identityExposureAction,
  listIdentityExposure, getIdentityExposureRecord, listIdentityExposureEvents,
  deriveIdentityOwnershipStatus, unionIdentityEvidence, buildIdentityVerification,
  IDENTITY_UNKNOWN_SIGNALS, IDENTITY_STALE_EVIDENCE_DAYS,
} = il;
const { providerKey, deriveSurfaceType, canonicalIdentityKey, assessIdentityRisk } = ip;

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
for (const [d, host] of [["d1","example.com"],["d2","admin2.com"],["d3","corp3.com"],["d4","corp4.com"],["d5","corp5.com"],["d6","corp6.com"],["d7","corp7.com"],["d8","corp8.com"],["dDead","dead.com"]]) {
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES (?,?,?)").run(d, "u1", host);
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES (?,?)").run(d === "dDead" ? "wsDead" : "ws1", d);
}
let ac = 0;
function seedIdentity(ws, domainId, { hostname = null, asset_type = "portal", identity_type = "login_portal", provider = null, source = "identity_discovery", risk = 10, first = "2026-07-01T00:00:00Z", last = "2026-07-15T00:00:00Z", status = "active" } = {}) {
  db.prepare(`INSERT INTO identity_assets (id, workspace_id, domain_id, scan_id, hostname, asset_type, identity_type, provider, internet_exposed, source, risk_score, evidence, first_seen, last_seen, status, created_at, updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'),datetime('now'))`)
    .run(`idasset-${++ac}`, ws, domainId, "scan1", hostname, asset_type, identity_type, provider, 1, source, risk, JSON.stringify([{ source, value: hostname || provider }]), first, last, status);
  return `idasset-${ac}`;
}
const byHost = (items, h) => items.find((i) => i.primary_hostname === h);

// ── 1. Provider alias layer (pure, deterministic, Entra ≠ M365) ─────────────
eq("azure ad → microsoft_entra_id", providerKey("Azure AD"), "microsoft_entra_id");
eq("entra id → microsoft_entra_id", providerKey("Entra ID"), "microsoft_entra_id");
eq("office 365 → microsoft_365", providerKey("Office 365"), "microsoft_365");
ok("Entra ID and Microsoft 365 do NOT collapse", providerKey("Microsoft Entra ID") !== providerKey("Microsoft 365"));
eq("okta slug stable", providerKey("Okta"), "okta");
eq("unknown provider falls back to slug", providerKey("Weird Vendor"), "weird_vendor");
eq("empty provider → null", providerKey(""), null);

// ── 2. Surface type + canonical identity key (pure) ─────────────────────────
eq("provider+idp → identity_provider", deriveSurfaceType("provider", "idp"), "identity_provider");
eq("portal+admin_login → admin_login", deriveSurfaceType("portal", "admin_login"), "admin_login");
eq("portal+vpn → vpn_portal", deriveSurfaceType("portal", "vpn"), "vpn_portal");
const kHost = canonicalIdentityKey({ provider_key: "microsoft_entra_id", surface_type: "login_portal", hostname: "login.example.com" });
eq("hostname-anchored key ignores provider (stable across provider change)",
  kHost, canonicalIdentityKey({ provider_key: "okta", surface_type: "login_portal", hostname: "login.example.com" }));
ok("provider-level key (no hostname) is provider-anchored",
  canonicalIdentityKey({ provider_key: "okta", surface_type: "identity_provider", hostname: null }) !== canonicalIdentityKey({ provider_key: "ping_identity", surface_type: "identity_provider", hostname: null }));

// ── 3. Risk model (pure, explainable, not alarmist) ─────────────────────────
eq("expected non-admin → ok", assessIdentityRisk({ surface_type: "login_portal", customer_classification: "expected", ownership_status: "known" }).risk_status, "ok");
eq("unexpected admin → high", assessIdentityRisk({ surface_type: "admin_login", customer_classification: "unexpected", ownership_status: "missing" }).risk_status, "high");
eq("unreviewed admin → elevated", assessIdentityRisk({ surface_type: "admin_login", customer_classification: "unreviewed", ownership_status: "missing" }).risk_status, "elevated");
eq("unreviewed non-admin owned → low", assessIdentityRisk({ surface_type: "login_portal", customer_classification: "unreviewed", ownership_status: "known" }).risk_status, "low");
eq("removal_contradicted → high", assessIdentityRisk({ surface_type: "login_portal", customer_classification: "expected", ownership_status: "known", recurrence_type: "removal_contradicted" }).risk_status, "high");

// ── 4. Ownership derivation (pure, three-role) ──────────────────────────────
eq("business+technical → known", deriveIdentityOwnershipStatus("a", "b", null), "known");
eq("identity owner only → partial", deriveIdentityOwnershipStatus("", "", "i"), "partial");
eq("no owners → missing", deriveIdentityOwnershipStatus("", "", ""), "missing");

// ── 5. Correlation — one record per surface; expected+owned is calm ─────────
const d1old = seedIdentity("ws1", "d1", { hostname: "login.example.com", identity_type: "login_portal", provider: "Microsoft Entra ID" });
seedIdentity("ws1", "d1", { hostname: "login.example.com", identity_type: "login_portal", provider: "Microsoft Entra ID", source: "hostname_pattern" }); // 2nd source, same surface
await correlateIdentityExposure(env, "ws1", { now: NOW });
let items = await listIdentityExposure(env, "ws1");
const d1 = byHost(items, "login.example.com");
ok("exactly one record for login.example.com (two sources merged)", items.filter((i) => i.primary_hostname === "login.example.com").length === 1);
eq("provider alias applied on the record", d1.provider_key, "microsoft_entra_id");
eq("surface type derived", d1.surface_type, "login_portal");
ok("two source evidence refs unioned", (d1.source_evidence || []).length >= 2);
eq("fresh record is unreviewed", d1.customer_classification, "unreviewed");
eq("externally_observed is always true", d1.externally_observed, true);
ok("unknown signals carried (no MFA/breach/dark-web claim)",
  ["mfa_enrolment", "conditional_access", "leaked_credentials", "dark_web"].every((s) => d1.unknown_signals.includes(s)));
ok("scope note states public login is not automatically a vulnerability", /not automatically a vulnerability/i.test(d1.scope_note));

// classify expected + assign owners → calm (ok, no recurrence)
await identityExposureAction(env, "ws1", d1.identity_exposure_id, "classify_expected", { actor_id: "admin" });
await identityExposureAction(env, "ws1", d1.identity_exposure_id, "assign_business_owner", { actor_id: "admin", owner: "IT" });
const d1known = await identityExposureAction(env, "ws1", d1.identity_exposure_id, "assign_technical_owner", { actor_id: "admin", owner: "Platform" });
eq("business+technical owner → known", d1known.item.ownership_status, "known");
await evaluateIdentityExposureMonitoring(env, "ws1", { now: NOW });
const d1calm = await getIdentityExposureRecord(env, "ws1", d1.identity_exposure_id);
eq("expected + owned surface has no recurrence", d1calm.recurrence_type, null);
eq("expected + owned surface risk is ok", d1calm.risk_status, "ok");

// ── 6. Idempotent re-correlation; first_seen stable, last_seen advances ─────
db.prepare("UPDATE identity_assets SET last_seen = '2026-07-19T00:00:00Z' WHERE id = ?").run(d1old);
await correlateIdentityExposure(env, "ws1", { now: NOW });
const d1re = await getIdentityExposureRecord(env, "ws1", d1.identity_exposure_id);
eq("no duplicate record after re-correlation", (await listIdentityExposure(env, "ws1")).filter((i) => i.primary_hostname === "login.example.com").length, 1);
eq("first_seen_at stable", d1re.first_seen_at, d1.first_seen_at);
ok("last_seen_at advanced", d1re.last_seen_at >= d1.last_seen_at);
eq("classification persisted across re-correlation", d1re.customer_classification, "expected");

// ── 7. Provider change on same hostname → material event, old preserved ─────
db.prepare("UPDATE identity_assets SET provider = 'Okta' WHERE id = ?").run(d1old);
db.prepare("DELETE FROM identity_assets WHERE workspace_id='ws1' AND domain_id='d1' AND provider='Microsoft Entra ID'").run(); // keep only the changed one
await correlateIdentityExposure(env, "ws1", { now: NOW });
const d1chg = await getIdentityExposureRecord(env, "ws1", d1.identity_exposure_id);
eq("provider changed on the SAME record (hostname-anchored)", d1chg.provider_key, "okta");
ok("last_changed_at set on provider change", Boolean(d1chg.last_changed_at));
const d1events = await listIdentityExposureEvents(env, "ws1", d1.identity_exposure_id);
ok("a provider_change event was appended (old provider preserved)",
  d1events.some((e) => e.event_type === "provider_change" && /microsoft_entra_id/.test(e.detail_json || "")));
eq("provider change surfaces a provider_change recurrence", d1chg.recurrence_type, "provider_change");
ok("provider change opens an identity case", Boolean(d1chg.linked_case_id));
const d1case = db.prepare("SELECT * FROM managed_cases WHERE id = ?").get(d1chg.linked_case_id);
ok("linked case is an identity_case with an identity.* remediation",
  d1case && d1case.case_type === "identity_case" && String(d1case.remediation_id || "").startsWith("identity."));

// ── 8. Public admin surface → case ──────────────────────────────────────────
seedIdentity("ws1", "d2", { hostname: "admin.admin2.com", identity_type: "admin_login" });
await correlateIdentityExposure(env, "ws1", { now: NOW });
const d2 = await getIdentityExposureRecord(env, "ws1", byHost(await listIdentityExposure(env, "ws1"), "admin.admin2.com").identity_exposure_id);
eq("unreviewed public admin surface → public_admin_surface", d2.recurrence_type, "public_admin_surface");
ok("public admin surface opens a case", Boolean(d2.linked_case_id));
eq("flagged public admin surface risk is high", d2.risk_status, "high");

// ── 9. Unexpected + no owner → owner_missing first, then unexpected ─────────
seedIdentity("ws1", "d3", { hostname: "sso.corp3.com", identity_type: "sso", provider: "Ping Identity" });
await correlateIdentityExposure(env, "ws1", { now: NOW });
const d3id = byHost(await listIdentityExposure(env, "ws1"), "sso.corp3.com").identity_exposure_id;
await identityExposureAction(env, "ws1", d3id, "classify_unexpected", { actor_id: "admin", reason: "not ours" });
await evaluateIdentityExposureMonitoring(env, "ws1", { now: NOW });
const d3a = await getIdentityExposureRecord(env, "ws1", d3id);
eq("unexpected + no owner → owner_missing (assign_owner first)", d3a.recurrence_type, "owner_missing");
eq("owner_missing requires assign_owner", d3a.required_case_action, "assign_owner");
eq("reason_required enforced for classify_unexpected", (await identityExposureAction(env, "ws1", d3id, "classify_unexpected", { actor_id: "admin" })).code, "reason_required");
// assign owner → owner-missing clears → unexpected_surface follow-up
await identityExposureAction(env, "ws1", d3id, "assign_business_owner", { actor_id: "admin", owner: "Sec" });
await identityExposureAction(env, "ws1", d3id, "assign_technical_owner", { actor_id: "admin", owner: "Net" });
await evaluateIdentityExposureMonitoring(env, "ws1", { now: NOW });
const d3b = await getIdentityExposureRecord(env, "ws1", d3id);
eq("owner assignment clears owner_missing → unexpected_surface", d3b.recurrence_type, "unexpected_surface");
ok("unexpected surface opens/keeps a case", Boolean(d3b.linked_case_id));

// ── 10. Case reopened via canTransitionCase, never duplicated ───────────────
db.prepare("UPDATE managed_cases SET status = 'verified' WHERE id = ?").run(d3b.linked_case_id);
await evaluateIdentityExposureMonitoring(env, "ws1", { now: NOW });
eq("verified identity case reopened on recurrence", db.prepare("SELECT status FROM managed_cases WHERE id = ?").get(d3b.linked_case_id).status, "reopened");
eq("recurrence reuses the SAME case", (await getIdentityExposureRecord(env, "ws1", d3id)).linked_case_id, d3b.linked_case_id);
eq("no duplicate identity_case for corp3 surface",
  db.prepare("SELECT COUNT(*) AS n FROM managed_cases WHERE workspace_id='ws1' AND case_type='identity_case' AND finding_id = ?").get(`identity:${d3b.canonical_identity_key}`).n, 1);

// ── 11. Customer-recorded removal is an assertion; verification honesty ──────
seedIdentity("ws1", "d4", { hostname: "vpn.corp4.com", identity_type: "vpn", last: "2026-07-01T00:00:00Z" });
await correlateIdentityExposure(env, "ws1", { now: NOW });
const d4id = byHost(await listIdentityExposure(env, "ws1"), "vpn.corp4.com").identity_exposure_id;
const removed = await identityExposureAction(env, "ws1", d4id, "record_surface_removed", { actor_id: "admin" });
eq("record_surface_removed does NOT verify", removed.item.verification_status, "not_verified");
eq("record_surface_removed sets a customer assertion", removed.item.customer_action_status, "surface_removed");
// still observed → verification failed + removal contradiction
const vFail = await identityExposureAction(env, "ws1", d4id, "request_verification", { actor_id: "admin" });
eq("verify while still observed → failed", vFail.item.verification_status, "failed");
await evaluateIdentityExposureMonitoring(env, "ws1", { now: NOW });
const d4contra = await getIdentityExposureRecord(env, "ws1", d4id);
eq("recorded-removed but still observed → removal_contradicted", d4contra.recurrence_type, "removal_contradicted");
ok("contradiction opens a case", Boolean(d4contra.linked_case_id));
ok("customer assertion preserved", d4contra.customer_action_status === "surface_removed");
// now the surface disappears across the window → verified removal
db.prepare("UPDATE identity_assets SET status='inactive' WHERE workspace_id='ws1' AND domain_id='d4'").run();
await correlateIdentityExposure(env, "ws1", { now: NOW });
const d4gone = await getIdentityExposureRecord(env, "ws1", d4id);
eq("disappeared surface is no_longer_observed (never auto-verified)", d4gone.monitoring_status, "no_longer_observed");
const vOk = await identityExposureAction(env, "ws1", d4id, "request_verification", { actor_id: "admin" });
eq("surface_removed absent across window → verified", vOk.item.verification_status, "verified");
eq("verified method is external_observation", vOk.item.verification_method, "external_observation");
ok("verification evidence keeps identity signals unknown",
  vOk.item.verification_detail && IDENTITY_UNKNOWN_SIGNALS.every((s) => vOk.item.verification_detail.unknown_signals.includes(s)));

// verification unit — pending / inconclusive branches
eq("no customer action → pending", buildIdentityVerification({ customer_action_status: null, monitoring_status: "observed" }, { now: NOW }).verification_result, "pending");
eq("config change with no observed change → inconclusive",
  buildIdentityVerification({ customer_action_status: "configuration_changed", monitoring_status: "observed", material_change: 0, last_changed_at: null }, { now: NOW }).verification_result, "inconclusive");
eq("surface_removed absent but within window → inconclusive",
  buildIdentityVerification({ customer_action_status: "surface_removed", monitoring_status: "no_longer_observed", evidence_age_days: 3 }, { now: NOW }).verification_result, "inconclusive");

// ── 12. Exception requires reason + expiry; expiry lapses to exception_expired
seedIdentity("ws1", "d7", { hostname: "ext.corp7.com", identity_type: "login_portal" });
await correlateIdentityExposure(env, "ws1", { now: NOW });
const d7id = byHost(await listIdentityExposure(env, "ws1"), "ext.corp7.com").identity_exposure_id;
eq("record_exception without expiry rejected", (await identityExposureAction(env, "ws1", d7id, "record_exception", { actor_id: "admin", reason: "temp" })).code, "expiry_required");
await identityExposureAction(env, "ws1", d7id, "record_exception", { actor_id: "admin", reason: "temporary tolerance", exception_until: "2026-08-01T00:00:00Z" });
await evaluateIdentityExposureMonitoring(env, "ws1", { now: NOW });
eq("active exception suppresses recurrence", (await getIdentityExposureRecord(env, "ws1", d7id)).recurrence_type, null);
// expiry in the past → exception_expired
db.prepare("UPDATE identity_exposure SET exception_until = '2026-07-01T00:00:00Z' WHERE id = ?").run(d7id);
await evaluateIdentityExposureMonitoring(env, "ws1", { now: NOW });
const d7exp = await getIdentityExposureRecord(env, "ws1", d7id);
eq("expired exception → exception_expired", d7exp.recurrence_type, "exception_expired");
ok("exception expiry opens a case", Boolean(d7exp.linked_case_id));

// ── 13. Retired surface reappearance ────────────────────────────────────────
seedIdentity("ws1", "d8", { hostname: "old.corp8.com", identity_type: "login_portal" });
await correlateIdentityExposure(env, "ws1", { now: NOW });
const d8id = byHost(await listIdentityExposure(env, "ws1"), "old.corp8.com").identity_exposure_id;
await identityExposureAction(env, "ws1", d8id, "retire", { actor_id: "admin", reason: "decommissioned" });
db.prepare("UPDATE identity_exposure SET monitoring_status='reappeared', exposure_status='reappeared' WHERE id = ?").run(d8id);
await evaluateIdentityExposureMonitoring(env, "ws1", { now: NOW });
eq("retired surface that reappeared → retired_reappeared", (await getIdentityExposureRecord(env, "ws1", d8id)).recurrence_type, "retired_reappeared");

// ── 14. Stale evidence when nothing higher-priority applies ─────────────────
seedIdentity("ws1", "d5", { hostname: "portal.corp5.com", identity_type: "login_portal", last: "2026-05-01T00:00:00Z" });
await correlateIdentityExposure(env, "ws1", { now: NOW });
const d5 = await getIdentityExposureRecord(env, "ws1", byHost(await listIdentityExposure(env, "ws1"), "portal.corp5.com").identity_exposure_id);
ok("stale evidence age exceeds threshold", typeof d5.evidence_age_days === "number" && d5.evidence_age_days > IDENTITY_STALE_EVIDENCE_DAYS);
ok("stale unreviewed surface flagged evidence_stale", d5.recurrence_type === "evidence_stale");

// ── 15. Evidence union non-destructive (pure) ───────────────────────────────
const u = unionIdentityEvidence(
  [{ source_table: "identity_assets", source_record_id: "a", last_seen_at: "2026-07-01" }],
  [{ source_table: "identity_assets", source_record_id: "b", last_seen_at: "2026-07-05" }]);
eq("union preserves both distinct references", u.length, 2);

// ── 16. Platform safety — soft-delete, non-enumeration, invalid action ──────
seedIdentity("wsDead", "dDead", { hostname: "sso.dead.com", identity_type: "sso" });
const dead = await correlateIdentityExposure(env, "wsDead", {});
eq("soft-deleted workspace correlation skipped", dead.skipped, "workspace_inactive");
eq("no identity_exposure rows for a soft-deleted workspace", db.prepare("SELECT COUNT(*) AS n FROM identity_exposure WHERE workspace_id='wsDead'").get().n, 0);
eq("foreign/nonexistent record read returns null", await getIdentityExposureRecord(env, "ws1", "ie-doesnotexist"), null);
eq("invalid action rejected", (await identityExposureAction(env, "ws1", d1.identity_exposure_id, "nope", {})).code, "invalid_action");

// ── 17. Deterministic list output ───────────────────────────────────────────
ok("list API output is deterministic",
  JSON.stringify(await listIdentityExposure(env, "ws1")) === JSON.stringify(await listIdentityExposure(env, "ws1")));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
