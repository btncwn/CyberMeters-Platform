#!/usr/bin/env node
//
// Managed Brand Protection v1 validation. Drives the real brand case engine
// against an in-memory SQLite database with the production schema+migrations.
// Covers registration-reality gating, shared managed-case workflow transitions,
// system-only verification states, evidence/submission tracking, technical
// resolution, reappearance campaign linking, tenant isolation, and route auth.
// Requires Node 24+ (node:sqlite).
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const brandCases = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "brand-cases.js")).href);
const workerMod = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "index.js")).href);
const worker = workerMod.default;
const { hashPassword, hashToken } = workerMod;

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* additive migration drift handled by validators */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
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

function makeEnv(db) {
  const noR2 = { get: async () => null, put: async () => ({}), head: async () => null, delete: async () => ({}), list: async () => ({ objects: [] }) };
  return {
    cybermeters_db: makeD1(db),
    cybermeters_reports: noR2,
    MFA_ENCRYPTION_KEY: "brand-case-test-mfa-key",
    JWT_SECRET: "test-secret",
    ALLOWED_ORIGIN: "https://app.cybermeters.com",
    FRONTEND_URL: "https://app.cybermeters.com",
    APP_VERSION: "test",
    RESEND_API_KEY: "",
    ADMIN_EMAILS: "",
  };
}

async function seed(db) {
  const pw = await hashPassword("Sup3r-secret-pw");
  db.prepare("INSERT INTO users (id, email, password_hash, name, plan, status, email_verified, mfa_enabled) VALUES ('admin','admin@example.com',?,'Admin','free','active',1,0)").run(pw);
  db.prepare("INSERT INTO users (id, email, password_hash, name, plan, status, email_verified, mfa_enabled) VALUES ('foreign','foreign@example.com',?,'Foreign','free','active',1,0)").run(pw);
  db.prepare("INSERT INTO workspaces (id, name, owner_user_id, created_at, updated_at) VALUES ('ws1','Alpha','admin',datetime('now'),datetime('now'))").run();
  db.prepare("INSERT INTO workspaces (id, name, owner_user_id, created_at, updated_at) VALUES ('ws2','Beta','foreign',datetime('now'),datetime('now'))").run();
  db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role, created_at) VALUES ('wm-admin','ws1','admin','admin',datetime('now'))").run();
  db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role, created_at) VALUES ('wm-foreign','ws2','foreign','owner',datetime('now'))").run();
  db.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at, created_at) VALUES ('s-admin','admin',?,datetime('now','+1 day'),datetime('now'))").run(await hashToken("tok_admin"));
  db.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at, created_at) VALUES ('s-foreign','foreign',?,datetime('now','+1 day'),datetime('now'))").run(await hashToken("tok_foreign"));
  db.prepare(`INSERT INTO workspace_brand_profiles
    (id, workspace_id, brand_name, primary_domain, keywords_json, protected_domains_json, created_at, updated_at)
    VALUES ('bp1','ws1','Example','example.com','["example"]','["example.com"]',datetime('now'),datetime('now'))`).run();
  db.prepare(`INSERT INTO workspace_brand_profiles
    (id, workspace_id, brand_name, primary_domain, keywords_json, protected_domains_json, created_at, updated_at)
    VALUES ('bp2','ws2','Other','other.com','["other"]','["other.com"]',datetime('now'),datetime('now'))`).run();
  db.prepare(`INSERT INTO workspace_brand_assets
    (id, workspace_id, domain, candidate_domain, variant_type, risk_level, risk_reasons,
     dns_resolves, https_available, ip_address, status, first_seen, last_seen, created_at, updated_at,
     brand_profile_id, similarity_score, classification, last_checked_at, mx_present, evidence_json)
    VALUES
    ('bra-live','ws1','example.com','examp1e-login.com','substitution','critical','["registered_with_mail_capability"]',
     1,1,'203.0.113.10','active',datetime('now'),datetime('now'),datetime('now'),datetime('now'),
     'bp1',92,'unreviewed',datetime('now'),1,'[]'),
    ('bra-watch','ws1','example.com','example-watch.test','substitution','high','["not_registered_watchlist"]',
     0,NULL,NULL,'inactive',datetime('now'),datetime('now'),datetime('now'),datetime('now'),
     'bp1',88,'unreviewed',datetime('now'),0,'[]'),
    ('bra-foreign','ws2','other.com','other-login.com','substitution','critical','["registered_with_mail_capability"]',
     1,1,'203.0.113.20','active',datetime('now'),datetime('now'),datetime('now'),datetime('now'),
     'bp2',91,'unreviewed',datetime('now'),1,'[]')`).run();
}

async function call(env, method, pathname, token, body = null) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body) headers["Content-Type"] = "application/json";
  const res = await worker.fetch(new Request("https://api.cybermeters.com" + pathname, {
    method, headers, body: body ? JSON.stringify(body) : undefined,
  }), env, { waitUntil() {} });
  const text = await res.text();
  let data = null;
  try { data = JSON.parse(text); } catch { /* non-json */ }
  return { status: res.status, data, text };
}

const db = buildDb();
await seed(db);
const env = makeEnv(db);

const blocked = await brandCases.createBrandCaseForCandidateId(env, "ws1", "bra-watch");
ok("registration-reality guard blocks unregistered watchlist permutations", blocked.opened === false && ["not_registered_watchlist", "below_threshold"].includes(blocked.reason));
ok("blocked watchlist candidate creates no managed case", db.prepare("SELECT COUNT(*) AS n FROM managed_cases WHERE workspace_id='ws1'").get().n === 0);

const opened = await brandCases.createBrandCaseForCandidateId(env, "ws1", "bra-live", { actor_id: "admin" });
ok("registered high-risk candidate opens a managed brand case", opened.opened && opened.case.status === "detected");
let row = await brandCases.getBrandCase(env, "ws1", opened.case.id);

const customerResolve = await brandCases.transitionBrandCase(env, row, "resolved", { actor_type: "customer", actor_id: "admin" });
// A customer cannot unilaterally mark a brand case resolved. From `detected` the
// universal validator now blocks it at the edge check (detected→resolved is not a
// legal edge); the system-only protection from a legal edge (verification_pending
// →resolved) is proven in validate-managed-case-model.js. Either rejection is a
// valid block.
ok("customer cannot set resolved state", !customerResolve.ok && /(technical verification|verified by cybermeters|cannot be set manually|cannot move a case)/i.test(customerResolve.error));

const triage = await brandCases.transitionBrandCase(env, row, "triage", { actor_type: "customer", actor_id: "admin", action: "triage_started" });
ok("case moves detected -> triage", triage.ok && triage.case.status === "triage");
const confirmed = await brandCases.reviewBrandCase(env, triage.case, {
  classification: "confirmed_abuse",
  reason: "Registered lookalike with mail capability.",
  actor_id: "admin",
});
ok("human-reviewed classification confirms abuse", confirmed.ok && confirmed.case.status === "confirmed_abuse");
ok("candidate manual classification persists", db.prepare("SELECT classification FROM workspace_brand_assets WHERE id='bra-live'").get().classification === "confirmed_abuse");

const evidenceBundle = {
  candidate_domain: "examp1e-login.com",
  protected_brand: "example.com",
  evidence_captured_at: "2026-07-13T10:00:00Z",
  dns_snapshot: { A: ["203.0.113.10"], MX: ["10 mail.examp1e-login.com"] },
  rdap_snapshot: { status: "ok", registrar: "Example Registrar" },
  recipients: [{ type: "registrar", contact: "abuse@example-registrar.test", source: "test" }],
  recommended_actions: [{ title: "Prepare takedown submission", action: "Send evidence to the registrar." }],
};
const approved = await brandCases.approveBrandTakedown(env, confirmed.case, {
  actor_id: "admin",
  reason: "Approved for takedown.",
  bundle: evidenceBundle,
});
ok("customer approval prepares grounded evidence bundle", approved.ok && approved.case.status === "evidence_ready");
let casePointer = JSON.parse(db.prepare("SELECT evidence_json FROM managed_cases WHERE id=?").get(opened.case.id).evidence_json);
let bundleRows = db.prepare("SELECT * FROM brand_evidence_bundles WHERE workspace_id='ws1' AND case_id=? ORDER BY version").all(opened.case.id);
ok("managed case evidence_json stores only the latest bundle pointer", Object.keys(casePointer).sort().join(",") === "latest_evidence_bundle_id,latest_evidence_version");
ok("evidence bundle is stored as immutable version 1", bundleRows.length === 1 && bundleRows[0].version === 1 &&
  JSON.parse(bundleRows[0].bundle_json).dns_snapshot.A[0] === "203.0.113.10");
ok("evidence bundle version has a content hash and current pointer", /^sha256:[a-f0-9]{64}$/.test(bundleRows[0].content_hash || "") &&
  casePointer.latest_evidence_bundle_id === bundleRows[0].id && casePointer.latest_evidence_version === 1);

const firstHash = bundleRows[0].content_hash;
const firstBundleJson = bundleRows[0].bundle_json;
const recaptured = await brandCases.recaptureBrandEvidenceBundle(env, approved.case, {
  actor_id: "admin",
  reason: "Second capture before submission.",
  bundle: { ...evidenceBundle, evidence_captured_at: "2026-07-13T11:00:00Z", dns_snapshot: { A: ["203.0.113.11"], MX: ["10 mail.examp1e-login.com"] } },
});
ok("evidence re-capture appends a new version", recaptured.ok && recaptured.evidence_bundle.version === 2 && recaptured.evidence_bundle.content_hash !== firstHash);
bundleRows = db.prepare("SELECT * FROM brand_evidence_bundles WHERE workspace_id='ws1' AND case_id=? ORDER BY version").all(opened.case.id);
casePointer = JSON.parse(db.prepare("SELECT evidence_json FROM managed_cases WHERE id=?").get(opened.case.id).evidence_json);
ok("prior evidence version is preserved after re-capture", bundleRows.length === 2 &&
  bundleRows[0].content_hash === firstHash &&
  bundleRows[0].bundle_json === firstBundleJson &&
  JSON.parse(bundleRows[0].bundle_json).dns_snapshot.A[0] === "203.0.113.10" &&
  casePointer.latest_evidence_bundle_id === bundleRows[1].id &&
  casePointer.latest_evidence_version === 2);

const [capA, capB] = await Promise.all([
  brandCases.recaptureBrandEvidenceBundle(env, recaptured.case, {
    actor_id: "admin",
    reason: "Parallel capture A.",
    bundle: { ...evidenceBundle, evidence_captured_at: "2026-07-13T11:30:00Z", dns_snapshot: { A: ["203.0.113.12"], MX: ["10 mail.examp1e-login.com"] } },
  }),
  brandCases.recaptureBrandEvidenceBundle(env, recaptured.case, {
    actor_id: "admin",
    reason: "Parallel capture B.",
    bundle: { ...evidenceBundle, evidence_captured_at: "2026-07-13T11:31:00Z", dns_snapshot: { A: ["203.0.113.13"], MX: ["10 mail.examp1e-login.com"] } },
  }),
]);
bundleRows = db.prepare("SELECT * FROM brand_evidence_bundles WHERE workspace_id='ws1' AND case_id=? ORDER BY version").all(opened.case.id);
ok("two concurrent captures create two distinct versions with no lost row", capA.ok && capB.ok &&
  bundleRows.length === 4 && new Set(bundleRows.map((r) => r.version)).size === 4);
const latestCase = await brandCases.getBrandCase(env, "ws1", opened.case.id);

const submitted = await brandCases.recordBrandTakedownSubmission(env, latestCase, {
  actor_id: "admin",
  submission_reference: "REG-12345",
  note: "Submitted to registrar abuse desk.",
});
ok("submission tracking records takedown reference", submitted.ok && submitted.case.status === "takedown_submitted");
const submissionEvent = db.prepare("SELECT detail_json FROM managed_case_events WHERE case_id=? AND action='takedown_submitted' ORDER BY created_at DESC LIMIT 1").get(opened.case.id);
const submissionDetail = JSON.parse(submissionEvent.detail_json);
ok("submission reference is persisted with evidence bundle integrity pointer", submissionDetail.reference === "REG-12345" &&
  submissionDetail.evidence_bundle_version === 4 &&
  submissionDetail.evidence_bundle_hash === bundleRows[3].content_hash);

const sweep = await brandCases.runBrandTakedownFollowupSweep(env, {
  verifier: async () => ({ complete: true, gone: true, observed: { a_records: 0, mx_records: 0 } }),
  now: "2026-07-13T12:00:00Z",
});
row = await brandCases.getBrandCase(env, "ws1", opened.case.id);
ok("system follow-up completes technical verification as resolved", sweep.resolved === 1 && row.status === "resolved" && row.last_verified_at);

const reopened = await brandCases.createBrandCaseForCandidateId(env, "ws1", "bra-live");
row = await brandCases.getBrandCase(env, "ws1", opened.case.id);
ok("reappeared candidate links a campaign and reopens confirmed-abuse workflow", reopened.opened === false && row.status === "confirmed_abuse" && row.reopened_count >= 1);
const campaignCount = db.prepare("SELECT COUNT(*) AS n FROM brand_abuse_campaigns WHERE workspace_id='ws1'").get().n;
ok("reappearance creates campaign linkage", campaignCount === 1);
const reappearanceNotif = db.prepare("SELECT COUNT(*) AS n FROM notification_events WHERE workspace_id='ws1' AND type='brand_case_reappeared'").get().n;
ok("reappearance creates a customer-visible notification", reappearanceNotif === 1);

const cases = await brandCases.listBrandCases(env, "ws1");
ok("case list is tenant scoped to ws1", cases.length === 1 && cases[0].workspace_id === "ws1");
const foreignCases = await brandCases.listBrandCases(env, "ws2");
ok("case list does not bleed into another tenant", foreignCases.length === 0);

const apiList = await call(env, "GET", "/api/workspaces/ws1/brand/cases", "tok_admin");
ok("brand cases API returns admin workspace case", apiList.status === 200 && apiList.data?.cases?.[0]?.domain === "examp1e-login.com");
const apiForeign = await call(env, "GET", "/api/workspaces/ws1/brand/cases", "tok_foreign");
ok("brand cases API rejects foreign tenant read", apiForeign.status === 403);
const apiAnon = await call(env, "GET", "/api/workspaces/ws1/brand/cases", null);
ok("brand cases API rejects anonymous read", apiAnon.status === 401);

console.log(`\nManaged Brand Protection lifecycle: ${pass}/${pass + fail} passed`);
if (fail) { console.error("managed-brand-protection validation FAILED"); process.exit(1); }
console.log("managed-brand-protection validation passed");
