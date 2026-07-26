#!/usr/bin/env node
//
// M5.b — Certificates & Trust verification reconciliation. CI-blocking.
//
// ── THE DEFECT (live until this increment, reproduced before any edit) ──
// Certificates & Trust holds SIX different verification methods across ten remediations —
// the most diverse domain on the platform — yet certificate_case carried a blanket
// `manual`, so:
//
//   • an EXPIRED certificate could be marked `verified` by a customer ATTESTING it, though
//     the registry says `certificate_recheck` and CyberMeters re-observes certificates on
//     every scan;
//   • a Certificate Transparency BLACKOUT could be attested resolved, though the registry
//     says `unsupported` — nothing can verify it. The product accepted an attestation for
//     something it had explicitly declared unverifiable. (`v2026.07.16-6` fixed the CT
//     blackout being READ as healthy; the CASE stayed attestable.)
//
// Worse, the platform already had an HONEST certificate verifier: buildVerificationEvidence
// requires a NEW, distinct, expiry-advanced certificate on the expected hostnames with
// acceptable coverage. It wrote `certificate_lifecycle.verification_status` and never
// touched the case. Two verification stories for one fact — the record said "not verified",
// the case said "verified", and both were live.
//
// ── THE BOUNDARY ──
//   A customer's assertion can never conclude verification for something CyberMeters
//   re-observes itself. And a finding the registry says NOTHING can verify must not be
//   verifiable by anyone.
//
// Node 24+.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const srcPath = (...p) => path.join(root, "workers", "scan-api", "src", ...p);
const eng = (f) => pathToFileURL(srcPath("engines", f)).href;

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

const model = await import(eng("managed-case-model.js"));
const registry = await import(eng("remediation-registry.js"));
const certLifecycle = await import(eng("certificate-lifecycle.js"));

const attestation = (statement) => ({
  verification_method: "manual_attestation", verification_result: "fixed",
  evidence_type: "customer_attestation", observed_at: new Date().toISOString(),
  attestation: { statement, by: "u1" },
});
const caseFor = (remediation_id) => ({
  id: "mc-x", workspace_id: "ws1", case_type: "certificate_case",
  domain_key: "certificates_trust", remediation_id, status: "awaiting_verification",
});

// ════ 1. THE PER-FINDING MAP — asserted, not described ══════════════════════
// Every active Certificates & Trust remediation, its registry method, and the support the
// case model must derive. A method that drifts, or a finding that silently becomes
// self-certifiable, fails HERE.
{
  const EXPECTED = {
    "cert.expiry.expired":      { method: "certificate_recheck", support: "automated" },
    "cert.expiry.expiring":     { method: "certificate_recheck", support: "automated" },
    "cert.tls.install":         { method: "https_recheck",       support: "automated" },
    "cert.self_signed":         { method: "certificate_recheck", support: "automated" },
    "cert.coverage_gap":        { method: "rescan",              support: "automated" },
    "cert.intelligence.review": { method: "rescan",              support: "automated" },
    "cert.caa.configure":       { method: "dns_recheck",         support: "automated" },
    "cert.ca_concentration":    { method: "manual_attestation",  support: "manual" },
    "cert.anomaly.review":      { method: "manual_attestation",  support: "manual" },
    "cert.ct_incomplete":       { method: "unsupported",         support: "unsupported" },
  };
  const active = registry.REMEDIATION_REGISTRY.filter((e) => e.domain_key === "certificates_trust" && e.status === "active");
  eq("every active Certificates & Trust remediation is mapped in this suite",
    active.map((e) => e.remediation_id).sort(), Object.keys(EXPECTED).sort());

  for (const [id, e] of Object.entries(EXPECTED)) {
    const entry = registry.getRemediationById(id);
    ok(`${id}: exists in the registry`, Boolean(entry));
    if (!entry) continue;
    eq(`${id}: registry verification_method`, entry.verification_method, e.method);
    eq(`${id}: derived case support`, model.verificationSupportForCase(caseFor(id)), e.support);
  }
  // The domain really is the diverse one — this is WHY a blanket answer is wrong here.
  const methods = new Set(active.map((e) => e.verification_method));
  ok("Certificates & Trust genuinely holds many verification methods (a blanket is wrong)",
    methods.size >= 5, [...methods].join(", "));
  ok("certificate_case derives support from the registry",
    fs.readFileSync(srcPath("engines", "managed-case-model.js"), "utf8")
      .match(/REGISTRY_DERIVED_VERIFICATION = new Set\(\[[\s\S]*?\]\)/)[0].includes("certificate_case"));
}

// ════ 2. A CUSTOMER CANNOT SELF-CERTIFY WHAT WE RE-OBSERVE ══════════════════
{
  for (const id of ["cert.expiry.expired", "cert.expiry.expiring", "cert.tls.install",
                    "cert.self_signed", "cert.coverage_gap", "cert.intelligence.review", "cert.caa.configure"]) {
    const d = model.canTransitionCase({
      case: caseFor(id), target_status: "verified",
      actor: { actor_type: "customer", actor_id: "u1" },
      evidence: attestation("We fixed it, honest."),
    });
    ok(`${id}: a customer attestation is REFUSED`, !d.ok, `unexpectedly allowed: ${d.case?.status}`);
    eq(`${id}: refused because only CyberMeters verifies it`, d.code, "verify_requires_system");
  }
  // A bare claim with no evidence at all is refused too.
  ok("a bare customer claim cannot verify a certificate case", !model.canTransitionCase({
    case: caseFor("cert.expiry.expired"), target_status: "verified", actor: { actor_type: "customer", actor_id: "u1" },
  }).ok);
}

// ════ 3. WHAT NOTHING CAN VERIFY, NOBODY VERIFIES ═══════════════════════════
// A Certificate Transparency blackout means we cannot see. The registry says `unsupported`,
// so neither a customer NOR the system may conclude it.
{
  const ct = caseFor("cert.ct_incomplete");
  eq("cert.ct_incomplete derives 'unsupported'", model.verificationSupportForCase(ct), "unsupported");
  const byCustomer = model.canTransitionCase({
    case: ct, target_status: "verified",
    actor: { actor_type: "customer", actor_id: "u1" }, evidence: attestation("CT looks fine to me."),
  });
  ok("a customer cannot attest a CT blackout resolved", !byCustomer.ok);
  eq("refused as unsupported", byCustomer.code, "verify_unsupported");

  const bySystem = model.canTransitionCase({
    case: ct, target_status: "verified", actor: { actor_type: "system", actor_id: null },
    evidence: {
      verification_method: "certificate_recheck", verification_result: "verified",
      evidence_type: "certificate_observation", observed_at: new Date().toISOString(),
      observation: { note: "a new certificate appeared" },
    },
  });
  ok("not even CyberMeters can verify a CT blackout", !bySystem.ok);
  eq("also refused as unsupported", bySystem.code, "verify_unsupported");
}

// ════ 4. ATTESTATION-ONLY FINDINGS REMAIN ATTESTABLE (not a silencer) ═══════
{
  for (const id of ["cert.ca_concentration", "cert.anomaly.review"]) {
    const d = model.canTransitionCase({
      case: caseFor(id), target_status: "verified",
      actor: { actor_type: "customer", actor_id: "u1" },
      evidence: attestation("We reviewed our CA concentration and accept it."),
    });
    ok(`${id}: a structured attestation from an identified actor DOES verify`, d.ok, d.code || d.reason || "");
    eq(`${id}: reaches the verified phase`, model.canonicalPhaseFor("certificate_case", d.case?.status), "verified");
  }
  // And the vocabulary renders the honest ceiling for them.
  const disp = await import(pathToFileURL(path.join(root, "frontend", "src", "lib", "caseDisplay.js")).href);
  const m = disp.phaseMeta("verified", model.verificationSupportForCase(caseFor("cert.ca_concentration")));
  ok("an attestation-only cert case never says 'verified'", !/verified/i.test(m.label));
  ok("nor 'confirmed'", !/confirmed/i.test(m.label));
  ok("nor green", m.tone !== "green");
  // While an observable one, once verified, DOES say CyberMeters verified it.
  const auto = disp.phaseMeta("verified", model.verificationSupportForCase(caseFor("cert.expiry.expired")));
  eq("an observed cert verification says CyberMeters verified it", auto.label, "Verified by CyberMeters");
}

// ════ 5. THE SYSTEM VERIFIER — end to end through the REAL action ═══════════
// The honest path must still close, or `automated` would make these cases unverifiable
// forever — the "cases but no honest verifier" state the vertical ship rule forbids.
function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch {} };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  db.prepare("INSERT INTO users (id,email,name,plan,created_at) VALUES ('u1','o@e.com','o','professional',datetime('now'))").run();
  db.prepare("INSERT INTO workspaces (id,owner_user_id,name) VALUES ('ws1','u1','ws1')").run();
  return db;
}
function makeD1(db) {
  const wrap = (sql, args) => ({
    first: async (c) => { const r = db.prepare(sql).get(...args) ?? null; return c && r ? r[c] : r; },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
}
globalThis.fetch = async () => new Response("{}", { status: 200 });

// A lifecycle record awaiting verification, with a linked case, and a genuinely NEW
// certificate observed on the expected hostname.
function seedReplacement(db, { remediation_id = "cert.expiry.expired", distinct = true, coverageOk = true } = {}) {
  const liveEvidence = ({ identity, expiry, sans }) => JSON.stringify({
    san_hostnames: sans,
    expires_at: expiry,
    signal_completeness: {
      signals: {
        leaf: {
          completeness_state: "monitoring_healthy", complete: true,
          observation: "present", value: { certificate_identity: identity },
          observation_scope: "live_tls", achieved_grade: "L3", publishable: true,
          source_type: "normative_protocol", provenance: [{ source: "m5b-live-fixture" }],
        },
        san: {
          completeness_state: "monitoring_healthy", complete: true,
          observation: "present", value: sans,
          observation_scope: "live_tls", achieved_grade: "L3", publishable: true,
          source_type: "normative_protocol", provenance: [{ source: "m5b-live-fixture" }],
        },
        expiry: {
          completeness_state: "monitoring_healthy", complete: true,
          observation: "present", value: expiry,
          observation_scope: "live_tls", achieved_grade: "L3", publishable: true,
          source_type: "normative_protocol", provenance: [{ source: "m5b-live-fixture" }],
        },
      },
    },
  });
  db.prepare(`INSERT INTO certificate_observations
              (id,workspace_id,domain_id,certificate_key,expires_at,first_seen,last_seen,evidence_json)
              VALUES ('obs-old','ws1','d1','KEY-OLD','2026-07-01T00:00:00Z',
                      '2026-01-01T00:00:00Z','2026-06-30T00:00:00Z',?)`)
    .run(liveEvidence({ identity: "KEY-OLD", expiry: "2026-07-01T00:00:00Z", sans: ["acme.example.com"] }));
  // "No new certificate" is not two rows with the same key — the store is unique on
  // certificate_key, so the real shape is: current still points at the SAME observation.
  if (distinct) {
    const newSans = coverageOk ? ["acme.example.com"] : ["other.example.com"];
    db.prepare(`INSERT INTO certificate_observations
                (id,workspace_id,domain_id,certificate_key,expires_at,first_seen,last_seen,evidence_json)
                VALUES ('obs-new','ws1','d1','KEY-NEW','2099-07-01T00:00:00Z',
                        '2026-07-20T00:00:00Z','2026-07-22T00:00:00Z',?)`)
      .run(liveEvidence({ identity: "KEY-NEW", expiry: "2099-07-01T00:00:00Z", sans: newSans }));
  }
  const currentObs = distinct ? "obs-new" : "obs-old";
  const currentKey = distinct ? "KEY-NEW" : "KEY-OLD";
  const currentExpiry = distinct ? "2099-07-01T00:00:00Z" : "2026-07-01T00:00:00Z";
  db.prepare(`INSERT INTO managed_cases (id,workspace_id,case_type,domain_key,finding_id,source_finding_type,remediation_id,status,severity,created_at,updated_at)
              VALUES ('mc-cert','ws1','certificate_case','certificates_trust','certificate:acme.example.com','x',?, 'awaiting_verification','high',datetime('now'),datetime('now'))`)
    .run(remediation_id);
  // The REAL schema: there is no previous_identity/previous_not_after column — the evidence
  // builder reads those from the certificate_observations rows it is handed, which is why the
  // observation ids above are the load-bearing part.
  db.prepare(`INSERT INTO certificate_lifecycle
      (id,workspace_id,domain_id,primary_hostname,certificate_identity,not_after,
       current_certificate_observation_id,previous_certificate_observation_id,
       expected_hostnames_json,observed_sans_json,coverage_status,ownership_status,
       renewal_status,renewal_readiness,verification_status,monitoring_status,material_change,
       lifecycle_state,linked_case_id,replacement_detected_at,first_seen_at,last_seen_at,created_at,updated_at)
     VALUES ('cl-1','ws1','d1','acme.example.com',?,?,
             ?,'obs-old',?,?,?, 'known',
             'awaiting_verification','ok','not_verified','observed',0,
             'awaiting_verification','mc-cert','2026-07-21T00:00:00Z',
             '2026-01-01T00:00:00Z','2026-07-22T00:00:00Z',datetime('now'),datetime('now'))`)
    .run(currentKey, currentExpiry, currentObs,
         JSON.stringify(["acme.example.com"]),
         JSON.stringify(coverageOk ? ["acme.example.com"] : ["other.example.com"]),
         coverageOk ? "complete" : "partial");
  return { cert: () => db.prepare("SELECT * FROM certificate_lifecycle WHERE id='cl-1'").get(),
           kase: () => db.prepare("SELECT * FROM managed_cases WHERE id='mc-cert'").get(),
           events: () => db.prepare("SELECT * FROM managed_case_events WHERE case_id='mc-cert' ORDER BY rowid").all() };
}
{
  // 5a. THE HONEST PATH: a real new certificate verifies BOTH the record and the case.
  const db = buildDb(); const env = { cybermeters_db: makeD1(db) };
  const h = seedReplacement(db);
  const res = await certLifecycle.certificateLifecycleAction(env, "ws1", "cl-1", "request_verification", { actor_id: "u1" });
  ok("the verify action succeeded", res.ok, res.code || "");
  eq("the lifecycle record verified from its own observation", h.cert().verification_status, "verified_replaced");
  eq("and the LINKED CASE verified too — the two stories now agree", h.kase().status, "verified");

  const vEv = h.events().filter((e) => e.to_status === "verified");
  eq("exactly one case verification event", vEv.length, 1);
  eq("written by the SYSTEM, not the customer who asked us to look", vEv[0].actor_type, "system");
  const ev = JSON.parse(vEv[0].detail_json);
  eq("the case evidence is the lifecycle's own external observation", ev.verification_method, "external_observation");
  eq("it names a genuinely distinct certificate", ev.observation.distinct_certificate, true);
  eq("with expiry advanced", ev.observation.expiry_advanced, true);
  ok("and preserves the permanent unknowns (no live TLS)",
    Array.isArray(ev.unknown_signals) && ev.unknown_signals.includes("chain_valid"));
}
{
  // 5b. NO NEW CERTIFICATE => inconclusive. Neither record nor case verifies.
  const db = buildDb(); const env = { cybermeters_db: makeD1(db) };
  const h = seedReplacement(db, { distinct: false });
  await certLifecycle.certificateLifecycleAction(env, "ws1", "cl-1", "request_verification", { actor_id: "u1" });
  eq("the record is inconclusive, not verified", h.cert().verification_status, "inconclusive");
  ok("the case did NOT verify", h.kase().status !== "verified", h.kase().status);
}
{
  // 5c. INCOMPLETE COVERAGE cannot verify — a new cert that misses a declared hostname.
  const db = buildDb(); const env = { cybermeters_db: makeD1(db) };
  const h = seedReplacement(db, { coverageOk: false });
  await certLifecycle.certificateLifecycleAction(env, "ws1", "cl-1", "request_verification", { actor_id: "u1" });
  ok("incomplete coverage does not verify the record", h.cert().verification_status !== "verified_replaced", h.cert().verification_status);
  ok("nor the case", h.kase().status !== "verified", h.kase().status);
}
{
  // 5d. The observation is real, but the FINDING is attestation-only: the system must NOT
  // conclude it. Seeing a new certificate says nothing about CA concentration.
  const db = buildDb(); const env = { cybermeters_db: makeD1(db) };
  const h = seedReplacement(db, { remediation_id: "cert.ca_concentration" });
  await certLifecycle.certificateLifecycleAction(env, "ws1", "cl-1", "request_verification", { actor_id: "u1" });
  eq("the RECORD still verifies from its own observation", h.cert().verification_status, "verified_replaced");
  ok("but the case does NOT — the registry says this finding is not ours to conclude",
    h.kase().status !== "verified", h.kase().status);
  const noted = h.events().filter((e) => e.action === "replacement_observed_not_verifying");
  eq("and the refusal is recorded on the case", noted.length, 1);
  eq("as unknown, never as a verification", JSON.parse(noted[0].detail_json).verification_state, "unknown");
}
{
  // 5e. cert.ct_incomplete: unsupported. The system observing a new cert must not close it.
  const db = buildDb(); const env = { cybermeters_db: makeD1(db) };
  const h = seedReplacement(db, { remediation_id: "cert.ct_incomplete" });
  await certLifecycle.certificateLifecycleAction(env, "ws1", "cl-1", "request_verification", { actor_id: "u1" });
  ok("a CT-blackout case is not verified by observing a new certificate", h.kase().status !== "verified");
  eq("recorded as unsupported", JSON.parse(h.events().filter((e) => e.action === "replacement_observed_not_verifying")[0].detail_json).verification_state, "unsupported");
}
{
  // 5f. A case nobody has acted on is not verified by an observation — it is history.
  const db = buildDb(); const env = { cybermeters_db: makeD1(db) };
  const h = seedReplacement(db);
  db.prepare("UPDATE managed_cases SET status='detected' WHERE id='mc-cert'").run();
  await certLifecycle.certificateLifecycleAction(env, "ws1", "cl-1", "request_verification", { actor_id: "u1" });
  ok("an untouched case is not verified by a replacement observation", h.kase().status !== "verified", h.kase().status);
  eq("the observation is recorded as history", h.events().filter((e) => e.action === "replacement_observed").length, 1);
}
{
  // 5g. No linked case: the record still verifies, and nothing explodes.
  const db = buildDb(); const env = { cybermeters_db: makeD1(db) };
  const h = seedReplacement(db);
  db.prepare("UPDATE certificate_lifecycle SET linked_case_id=NULL WHERE id='cl-1'").run();
  const res = await certLifecycle.certificateLifecycleAction(env, "ws1", "cl-1", "request_verification", { actor_id: "u1" });
  ok("a record with no linked case still verifies", res.ok && h.cert().verification_status === "verified_replaced");
}

// ════ 6. THE OTHER DEFERRED CASE TYPES — checked, not assumed ═══════════════
// identity_case and shadow_it_case are NOT registry-derived. That is correct ONLY while
// every one of their findings is manual_attestation. If either ever gains an observable
// finding, the blanket becomes the certificate defect again — so this fails until it is
// added to REGISTRY_DERIVED_VERIFICATION.
{
  for (const [domain_key, case_type] of [["identity_exposure", "identity_case"],
                                         ["shadow_it_unmanaged_technology", "shadow_it_case"]]) {
    const active = registry.REMEDIATION_REGISTRY.filter((e) => e.domain_key === domain_key && e.status === "active");
    ok(`${domain_key}: has remediations to check`, active.length > 0);
    const nonAttestation = active.filter((e) => e.verification_method !== "manual_attestation");
    eq(`${case_type}: every finding is manual_attestation, so the blanket 'manual' is honest`,
      nonAttestation.map((e) => `${e.remediation_id}=${e.verification_method}`), []);
    eq(`${case_type}: blanket support agrees with the registry`,
      model.CASE_TYPE_REGISTRY[case_type].verification_support, "manual");
  }
}

// ════ 7. NO PARALLEL MODEL ══════════════════════════════════════════════════
{
  const src = fs.readFileSync(srcPath("engines", "certificate-lifecycle.js"), "utf8");
  ok("case verification goes through the canonical validator", /canTransitionCase\(\{[\s\S]{0,200}target_status: "verified"/.test(src));
  ok("the system verifier acts as the system", /actor: \{ actor_type: "system", actor_id: null \}/.test(src));
  ok("it derives support from the canonical contract", /verificationSupportForCase\(/.test(src));
  ok("it never sets a verified status by raw UPDATE without the validator",
    !/UPDATE managed_cases SET status = 'verified'/i.test(src));
  ok("the permanent certificate unknowns are still declared",
    /unknown_signals: \["chain_valid", "root_trusted", "ocsp", "revocation", "private_key_possession"/.test(src));
}

// ════ 8. MUTATIONS ══════════════════════════════════════════════════════════
if (!process.argv.includes("--no-mutate")) {
  const MODEL = srcPath("engines", "managed-case-model.js");
  const CERT = srcPath("engines", "certificate-lifecycle.js");
  const MUTATIONS = [
    { file: MODEL, name: "THE SHIPPED DEFECT: certificate_case reverts to a blanket answer",
      from: '  "email_case", "website_case", "cyber_essentials_case", "certificate_case",',
      to: '  "email_case", "website_case", "cyber_essentials_case",' },
    { file: MODEL, name: "an unsupported finding becomes verifiable",
      from: '  if (method === "unsupported") return "unsupported";', to: "" },
    { file: MODEL, name: "the automated gate stops requiring a system actor",
      from: '    if (support === "automated" && actorType !== "system") {', to: "    if (false) {" },
    { file: CERT, name: "the case verifier ignores the registry (verifies attestation-only findings)",
      from: '  if (support !== "automated") {', to: "  if (false) {" },
    { file: CERT, name: "the case verifier skips the case machine",
      from: '  if (phase !== "awaiting_verification") {', to: "  if (false) {" },
    { file: CERT, name: "the case is verified even when the observation was inconclusive",
      from: '        verifyCaseFromObservation = { evidence };',
      to: "" },
    { file: CERT, name: "the case verifier acts as the customer, not the system",
      from: '    actor: { actor_type: "system", actor_id: null }, evidence: caseEvidence, now,',
      to: '    actor: { actor_type: "customer", actor_id: "u1" }, evidence: caseEvidence, now,' },
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

console.log(`\nm5b-certificate-verification: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
console.log("m5b-certificate-verification validation passed");
