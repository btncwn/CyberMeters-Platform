#!/usr/bin/env node
//
// Certificates Managed Lifecycle — DB-backed proof. CI-blocking. Runs against an
// in-memory SQLite database with the production schema + migrations.
//
// Proves: raw certificate_observations correlate into ONE canonical managed
// lifecycle record per host; the current certificate is the furthest-future
// expiry; a replacement produces a NEW identity with the OLD observation
// preserved (never overwritten); the canonical renewal policy drives readiness
// bands; the coverage model separates expected vs observed (wildcard matches a
// single label only, never auto-covers); ownership derivation is server-side and
// three-role; the verification contract is external-observation only (a recorded
// renewal is NOT verified until a distinct new certificate is observed with
// acceptable coverage and a later expiry; incomplete coverage / no-new-cert →
// inconclusive; expiry-not-advanced → failed); the monitoring evaluator surfaces
// expired / renewal-overdue / coverage-regression / owner-missing / replacement-
// contradiction deterministically with the right case follow-up (open, reopen
// via canTransitionCase, assign_owner, or none); chain/root/OCSP/revocation/
// fingerprint/serial stay explicitly unknown; soft-deleted workspaces get
// nothing; and list output is deterministic.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href);
const cl = await eng("certificate-lifecycle.js");
const pol = await eng("certificate-policy.js");
const {
  correlateCertificateLifecycle, evaluateCertificateLifecycleMonitoring, certificateLifecycleAction,
  listCertificateLifecycle, getCertificateLifecycle, listCertificateLifecycleEvents,
  computeCoverage, deriveCertOwnershipStatus, buildVerificationEvidence,
} = cl;
const { assessRenewal, daysUntil, renewalRequiresCase, RENEWAL_START_BY_DAYS } = pol;

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
for (const [d, host] of [["d1","example.com"],["d2","expired.com"],["d3","cover.com"],["d4","owner.com"],["d5","critical.com"],["d6","contra.com"],["d7","noverify.com"],["dDead","dead.com"]]) {
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES (?,?,?)").run(d, "u1", host);
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES (?,?)").run(d === "dDead" ? "wsDead" : "ws1", d);
}
let oc = 0;
function seedCert(ws, domainId, key, { issuer = "Let's Encrypt", subject = null, sans = [], expires, first = "2026-06-01T00:00:00Z", last = "2026-07-15T00:00:00Z" }) {
  const ev = JSON.stringify({ issuer, san_hostnames: sans, expires_at: expires });
  db.prepare(`INSERT INTO certificate_observations (id, workspace_id, domain_id, scan_id, certificate_key, subject, issuer, san_count, expires_at, first_seen, last_seen, evidence_json, created_at, updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'),datetime('now'))`)
    .run(`co-${++oc}`, ws, domainId, "scan1", key, subject, issuer, sans.length, expires, first, last, ev);
  return `co-${oc}`;
}

// ── 1. Canonical renewal policy bands (pure) ────────────────────────────────
eq("assessRenewal 134d → monitoring", assessRenewal("2026-12-01T00:00:00Z", NOW).readiness, "monitoring");
eq("assessRenewal 70d → planning", assessRenewal("2026-09-28T00:00:00Z", NOW).readiness, "planning");
eq("assessRenewal 40d → preparation", assessRenewal("2026-08-29T00:00:00Z", NOW).readiness, "preparation");
eq("assessRenewal 20d → high", assessRenewal("2026-08-09T00:00:00Z", NOW).readiness, "high");
eq("assessRenewal 6d → critical", assessRenewal("2026-07-26T00:00:00Z", NOW).readiness, "critical");
eq("assessRenewal expired → expired", assessRenewal("2026-07-10T00:00:00Z", NOW).readiness, "expired");
eq("assessRenewal no expiry → unknown (never assumes safe)", assessRenewal(null, NOW).readiness, "unknown");
eq("daysUntil null on unparseable", daysUntil("not-a-date", NOW), null);
ok("renewalRequiresCase only critical/expired", renewalRequiresCase("critical") && renewalRequiresCase("expired") && !renewalRequiresCase("high") && !renewalRequiresCase("preparation"));
ok("renewal_start_by = not_after − 30d", assessRenewal("2026-09-01T00:00:00Z", NOW).renewal_start_by.startsWith("2026-08-02"));
eq("RENEWAL_START_BY_DAYS is 30", RENEWAL_START_BY_DAYS, 30);

// ── 2. Coverage model (pure) ────────────────────────────────────────────────
eq("no expected declared → unknown", computeCoverage([], ["a.com"]).status, "unknown");
eq("all expected covered → complete", computeCoverage(["a.com","b.com"], ["a.com","b.com"]).status, "complete");
eq("some expected missing → partial", computeCoverage(["a.com","b.com"], ["a.com"]).status, "partial");
eq("all expected missing → missing", computeCoverage(["a.com","b.com"], ["z.com"]).status, "missing");
eq("extra observed SAN → unexpected", computeCoverage(["a.com"], ["a.com","evil.com"]).status, "unexpected");
ok("wildcard covers single-label subdomain", computeCoverage(["x.example.com"], ["*.example.com"]).status === "complete");
ok("wildcard does NOT cover apex (not auto-covering)", computeCoverage(["example.com"], ["*.example.com"]).status === "missing");
ok("wildcard does NOT cover nested depth", computeCoverage(["a.b.example.com"], ["*.example.com"]).status === "missing");

// ── 3. Ownership derivation (pure, three-role) ──────────────────────────────
eq("business+technical → known", deriveCertOwnershipStatus("a","b",null), "known");
eq("renewal owner only → partial", deriveCertOwnershipStatus("","",  "r"), "partial");
eq("no owners → missing", deriveCertOwnershipStatus("","",""), "missing");

// ── 4. Correlation creates one lifecycle per host; current = furthest expiry ─
seedCert("ws1", "d1", "d1-old", { subject: "example.com", sans: ["example.com","www.example.com"], expires: "2026-12-01T00:00:00Z" });
await correlateCertificateLifecycle(env, "ws1", { now: NOW });
let list1 = await listCertificateLifecycle(env, "ws1");
const d1 = list1.find((r) => r.primary_hostname === "example.com");
ok("exactly one lifecycle for example.com", list1.filter((r) => r.primary_hostname === "example.com").length === 1);
eq("current identity = seeded cert", d1.certificate_identity, "d1-old");
eq("renewal readiness monitoring", d1.renewal_readiness, "monitoring");
eq("observed SANs captured", JSON.stringify(d1.observed_sans), JSON.stringify(["example.com","www.example.com"]));
eq("no expected declared yet → coverage unknown", d1.coverage_status, "unknown");
eq("fingerprint stays unknown (no live TLS)", d1.fingerprint_sha256, null);
eq("serial stays unknown", d1.serial_number, null);
ok("scope_note carries the honesty statement", /not the same as fully trusted|no live TLS/i.test(d1.scope_note));

// ── 5. Replacement detection — old observation preserved ────────────────────
seedCert("ws1", "d1", "d1-new", { subject: "example.com", sans: ["example.com","www.example.com"], expires: "2027-06-01T00:00:00Z", first: "2026-07-18T00:00:00Z", last: "2026-07-19T00:00:00Z" });
await correlateCertificateLifecycle(env, "ws1", { now: NOW });
const d1b = await getCertificateLifecycle(env, "ws1", d1.certificate_lifecycle_id);
eq("current identity switched to the new cert", d1b.certificate_identity, "d1-new");
ok("previous observation preserved (points at old cert)", Boolean(d1b.previous_certificate_observation_id));
ok("replacement_detected_at set", Boolean(d1b.replacement_detected_at));
eq("both raw observations still exist (old never overwritten)",
  db.prepare("SELECT COUNT(*) AS n FROM certificate_observations WHERE workspace_id='ws1' AND domain_id='d1'").get().n, 2);
ok("a replacement_detected event was appended",
  (await listCertificateLifecycleEvents(env, "ws1", d1.certificate_lifecycle_id)).some((e) => e.event_type === "replacement_detected"));

// ── 6. Verification contract — external observation only ────────────────────
await certificateLifecycleAction(env, "ws1", d1.certificate_lifecycle_id, "set_expected_hostnames", { actor_id: "admin", expected_hostnames: ["example.com","www.example.com"] });
const recorded = await certificateLifecycleAction(env, "ws1", d1.certificate_lifecycle_id, "record_replacement_completed", { actor_id: "admin" });
eq("recorded replacement → awaiting_verification (NOT verified)", recorded.item.renewal_status, "awaiting_verification");
eq("recorded replacement stays not_verified", recorded.item.verification_status, "not_verified");
const verified = await certificateLifecycleAction(env, "ws1", d1.certificate_lifecycle_id, "request_verification", { actor_id: "admin" });
eq("distinct new cert + coverage + forward expiry → verified_replaced", verified.item.verification_status, "verified_replaced");
eq("verified verification_method is external_observation", verified.item.verification_method, "external_observation");
ok("verification evidence keeps chain/root/OCSP/revocation unknown",
  verified.item.verification_detail && ["chain_valid","root_trusted","ocsp","revocation"].every((s) => verified.item.verification_detail.unknown_signals.includes(s)));

// verify unit contract — failed / inconclusive branches
const recStub = { expected_hostnames_json: '["a.com"]', observed_sans_json: '["a.com"]', issuer: "X", coverage_status: "complete", certificate_identity: "new" };
eq("distinct + acceptable + NOT forward → failed",
  buildVerificationEvidence(recStub, { current: { certificate_key: "new", expires_at: "2026-01-01T00:00:00Z" }, previous: { certificate_key: "old", expires_at: "2027-01-01T00:00:00Z" }, coverage: { status: "complete" }, now: NOW }).verification_result, "failed");
eq("no distinct new cert → inconclusive",
  buildVerificationEvidence(recStub, { current: { certificate_key: "same", expires_at: "2027-01-01T00:00:00Z" }, previous: { certificate_key: "same", expires_at: "2026-01-01T00:00:00Z" }, coverage: { status: "complete" }, now: NOW }).verification_result, "inconclusive");
eq("incomplete coverage → inconclusive (cannot verify)",
  buildVerificationEvidence(recStub, { current: { certificate_key: "new", expires_at: "2027-01-01T00:00:00Z" }, previous: { certificate_key: "old", expires_at: "2026-01-01T00:00:00Z" }, coverage: { status: "missing" }, now: NOW }).verification_result, "inconclusive");

// ── 7. Expired certificate → case with canonical cert remediation ───────────
seedCert("ws1", "d2", "d2-exp", { subject: "expired.com", sans: ["expired.com"], expires: "2026-07-10T00:00:00Z" });
await correlateCertificateLifecycle(env, "ws1", { now: NOW });
const d2 = (await listCertificateLifecycle(env, "ws1")).find((r) => r.primary_hostname === "expired.com");
eq("expired cert readiness expired", d2.renewal_readiness, "expired");
eq("expired cert recurrence", d2.recurrence_type, "expired");
eq("expired cert requires open_or_reopen", d2.required_case_action, "open_or_reopen");
ok("expired cert has a linked certificate_case", Boolean(d2.linked_case_id));
const d2Case = db.prepare("SELECT * FROM managed_cases WHERE id = ?").get(d2.linked_case_id);
ok("linked case is a certificate_case with a cert.* remediation",
  d2Case && d2Case.case_type === "certificate_case" && String(d2Case.remediation_id || "").startsWith("cert."));

// ── 8. Coverage regression → coverage_regression case ───────────────────────
seedCert("ws1", "d3", "d3-c", { subject: "cover.com", sans: ["a.cover.com"], expires: "2026-12-01T00:00:00Z" });
await correlateCertificateLifecycle(env, "ws1", { now: NOW });
const d3 = (await listCertificateLifecycle(env, "ws1")).find((r) => r.primary_hostname === "cover.com");
await certificateLifecycleAction(env, "ws1", d3.certificate_lifecycle_id, "set_expected_hostnames", { actor_id: "admin", expected_hostnames: ["a.cover.com","b.cover.com"] });
await evaluateCertificateLifecycleMonitoring(env, "ws1", { now: NOW });
const d3b = await getCertificateLifecycle(env, "ws1", d3.certificate_lifecycle_id);
eq("missing expected hostname → coverage partial", d3b.coverage_status, "partial");
eq("coverage regression recurrence", d3b.recurrence_type, "coverage_regression");
ok("coverage regression opens a case", Boolean(d3b.linked_case_id));

// ── 9. Owner-missing on an at-risk (non-critical) cert → assign_owner ───────
seedCert("ws1", "d4", "d4-c", { subject: "owner.com", sans: ["owner.com"], expires: "2026-08-08T00:00:00Z" }); // ~19d → high
await correlateCertificateLifecycle(env, "ws1", { now: NOW });
const d4 = (await listCertificateLifecycle(env, "ws1")).find((r) => r.primary_hostname === "owner.com");
eq("at-risk cert readiness high", d4.renewal_readiness, "high");
eq("no owner on at-risk cert → owner_missing", d4.recurrence_type, "owner_missing");
eq("owner_missing requires assign_owner", d4.required_case_action, "assign_owner");
eq("owner_missing lifecycle_state", d4.lifecycle_state, "owner_missing");

// ── 10. Critical renewal window → renewal_overdue case ──────────────────────
seedCert("ws1", "d5", "d5-c", { subject: "critical.com", sans: ["critical.com"], expires: "2026-07-26T00:00:00Z" }); // 6d → critical
await correlateCertificateLifecycle(env, "ws1", { now: NOW });
const d5 = (await listCertificateLifecycle(env, "ws1")).find((r) => r.primary_hostname === "critical.com");
eq("critical window recurrence renewal_overdue", d5.recurrence_type, "renewal_overdue");
eq("renewal_overdue requires open_or_reopen", d5.required_case_action, "open_or_reopen");

// ── 11. Recorded replacement with NO observed new cert → contradiction ──────
seedCert("ws1", "d6", "d6-c", { subject: "contra.com", sans: ["contra.com"], expires: "2026-12-01T00:00:00Z" });
await correlateCertificateLifecycle(env, "ws1", { now: NOW });
const d6 = (await listCertificateLifecycle(env, "ws1")).find((r) => r.primary_hostname === "contra.com");
await certificateLifecycleAction(env, "ws1", d6.certificate_lifecycle_id, "record_replacement_completed", { actor_id: "admin" });
await evaluateCertificateLifecycleMonitoring(env, "ws1", { now: NOW });
const d6b = await getCertificateLifecycle(env, "ws1", d6.certificate_lifecycle_id);
eq("recorded-but-not-observed replacement is contradicted", d6b.recurrence_type, "replacement_contradicted");
ok("contradiction opens a case", Boolean(d6b.linked_case_id));
ok("the customer assertion is preserved (replacement_recorded_at stays set)", Boolean(d6b.replacement_recorded_at));

// ── 12. Existing case REOPENED via canTransitionCase, never duplicated ──────
db.prepare("UPDATE managed_cases SET status = 'verified' WHERE id = ?").run(d2.linked_case_id);
await evaluateCertificateLifecycleMonitoring(env, "ws1", { now: NOW }); // d2 still expired
eq("verified case reopened on recurrence (base verified→reopened)",
  db.prepare("SELECT status FROM managed_cases WHERE id = ?").get(d2.linked_case_id).status, "reopened");
eq("recurrence reuses the SAME case (linked_case_id unchanged)",
  (await getCertificateLifecycle(env, "ws1", d2.certificate_lifecycle_id)).linked_case_id, d2.linked_case_id);
eq("exactly one certificate_case for expired.com (no duplicate)",
  db.prepare("SELECT COUNT(*) AS n FROM managed_cases WHERE workspace_id='ws1' AND case_type='certificate_case' AND finding_id='certificate:expired.com'").get().n, 1);

// ── 13. Exception suppresses follow-up within its window ─────────────────────
await certificateLifecycleAction(env, "ws1", d5.certificate_lifecycle_id, "record_exception", { actor_id: "admin", reason: "vendor change freeze", exception_until: "2026-08-01T00:00:00Z" });
await evaluateCertificateLifecycleMonitoring(env, "ws1", { now: NOW });
const d5b = await getCertificateLifecycle(env, "ws1", d5.certificate_lifecycle_id);
eq("cert under active exception has no recurrence", d5b.recurrence_type, null);
eq("cert under exception lifecycle_state", d5b.lifecycle_state, "exception");
eq("expiry_required rejected when no exception date",
  (await certificateLifecycleAction(env, "ws1", d5.certificate_lifecycle_id, "record_exception", { actor_id: "admin", reason: "x" })).code, "expiry_required");

// ── 14. Soft-deleted workspace receives nothing; non-enumerating ────────────
seedCert("wsDead", "dDead", "dead-c", { subject: "dead.com", sans: ["dead.com"], expires: "2026-12-01T00:00:00Z" });
const dead = await correlateCertificateLifecycle(env, "wsDead", {});
eq("soft-deleted workspace correlation is skipped", dead.skipped, "workspace_inactive");
eq("no lifecycle rows for a soft-deleted workspace",
  db.prepare("SELECT COUNT(*) AS n FROM certificate_lifecycle WHERE workspace_id='wsDead'").get().n, 0);
eq("foreign/nonexistent record read returns null (non-enumerating)", await getCertificateLifecycle(env, "ws1", "cl-doesnotexist"), null);
eq("invalid action is rejected", (await certificateLifecycleAction(env, "ws1", d1.certificate_lifecycle_id, "nope", {})).code, "invalid_action");

// ── 15. Deterministic list output ───────────────────────────────────────────
ok("list API output is deterministic",
  JSON.stringify(await listCertificateLifecycle(env, "ws1")) === JSON.stringify(await listCertificateLifecycle(env, "ws1")));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
