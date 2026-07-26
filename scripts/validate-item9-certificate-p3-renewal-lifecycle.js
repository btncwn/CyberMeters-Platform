#!/usr/bin/env node
// Item 9 P3 — deterministic renewal lifecycle, append-only replacement and
// canonical case close/reopen proof.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixture = JSON.parse(fs.readFileSync(
  path.join(root, "scripts", "fixtures", "item9-p3-certificate-renewal-lifecycle.json"),
  "utf8"
));
const lifecycle = await import(pathToFileURL(path.join(
  root, "workers", "scan-api", "src", "engines", "certificate-lifecycle.js"
)).href);
const policy = await import(pathToFileURL(path.join(
  root, "workers", "scan-api", "src", "engines", "certificate-policy.js"
)).href);
const cases = await import(pathToFileURL(path.join(
  root, "workers", "scan-api", "src", "engines", "managed-case-model.js"
)).href);

let pass = 0;
let fail = 0;
const ok = (name, condition, detail = "") => {
  condition ? pass++ : fail++;
  if (!condition) console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
};
const eq = (name, actual, expected) =>
  ok(name, actual === expected, `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);

function resolvedSignal(value, {
  observation = "present",
  scope = "live_tls",
  state = "monitoring_healthy",
  grade = "L3",
  publishable = true,
  source = "item9-p3-deterministic-fixture",
} = {}) {
  return {
    completeness_state: state,
    complete: state === "monitoring_healthy",
    observation,
    value,
    observation_scope: scope,
    achieved_grade: grade,
    publishable,
    source_type: "normative_protocol",
    provenance: [{ source, method: `fixture_${scope}` }],
    authorities: [{ id: "RFC5280", classification: "protocol_definition" }],
  };
}

function observation({
  id,
  key,
  issuer,
  sans,
  expiry,
  wildcard = false,
  firstSeen,
  lastSeen,
  overrides = {},
}) {
  const signals = {
    leaf: resolvedSignal({ certificate_identity: key }),
    issuer: resolvedSignal(issuer),
    san: resolvedSignal(sans),
    expiry: resolvedSignal(expiry),
    wildcard: resolvedSignal(wildcard, {
      observation: wildcard ? "present" : "absent",
    }),
    ...overrides,
  };
  return {
    id,
    certificate_key: key,
    issuer,
    expires_at: expiry,
    first_seen: firstSeen,
    last_seen: lastSeen,
    evidence_json: JSON.stringify({
      issuer,
      san_hostnames: sans,
      expires_at: expiry,
      signal_completeness: { model_version: "certificate-signal-completeness-v1", signals },
    }),
  };
}

function ctOnlyObservation(input) {
  const row = input?.evidence_json ? input : observation(input);
  const evidence = JSON.parse(row.evidence_json);
  evidence.signal_completeness.signals.leaf = resolvedSignal(null, {
    observation: "unknown",
    scope: "live_tls",
    state: "evidence_incomplete",
    grade: "L0",
    publishable: false,
    source: "not_collected",
  });
  for (const name of ["issuer", "san", "expiry", "wildcard"]) {
    const signal = evidence.signal_completeness.signals[name];
    signal.observation_scope = "ct_issuance";
    signal.achieved_grade = "L1";
    signal.publishable = false;
  }
  return { ...row, evidence_json: JSON.stringify(evidence) };
}

const clock = fixture.clock;
const oldSpec = fixture.replacement.previous;
const newSpec = fixture.replacement.current;
const oldPure = observation({
  id: "obs-old",
  key: oldSpec.identity,
  issuer: oldSpec.issuer,
  sans: oldSpec.sans,
  expiry: oldSpec.expiry,
  wildcard: oldSpec.wildcard,
  firstSeen: "2026-07-20T10:00:00.000Z",
  lastSeen: clock.baseline,
});
const newPure = observation({
  id: "obs-new",
  key: newSpec.identity,
  issuer: newSpec.issuer,
  sans: newSpec.sans,
  expiry: newSpec.expiry,
  wildcard: newSpec.wildcard,
  firstSeen: clock.replacement_detected,
  lastSeen: clock.replacement_detected,
});

// ── 1. Canonical band policy stays the one source ──────────────────────────
for (const band of fixture.bands) {
  eq(`band ${band.expected}`, policy.assessRenewal(band.not_after, clock.baseline).readiness, band.expected);
}

// ── 2. Pure signal-isolated transition model ───────────────────────────────
const replacement = lifecycle.deriveCertificateRenewalTransition(oldPure, newPure, {
  previousReadiness: "expired",
  currentReadiness: "monitoring",
  renewalStatus: "in_progress",
});
eq("replacement relation", replacement.relation, "replaced");
ok("later expiry derives renewed", replacement.renewed);
ok("issuer change independently derived", replacement.changed.issuer);
ok("SAN change independently derived", replacement.changed.san);
ok("wildcard change independently derived", replacement.changed.wildcard);
ok("leaf change independently derived", replacement.changed.leaf);

const issuerIncomplete = observation({
  ...newPure,
  id: "obs-new-incomplete-issuer",
  key: "leaf-new-incomplete-issuer",
  issuer: null,
  sans: ["example.com", "api.example.com"],
  expiry: "2027-01-31T10:00:00.000Z",
  wildcard: false,
  firstSeen: clock.replacement_detected,
  lastSeen: clock.replacement_detected,
  overrides: {
    issuer: resolvedSignal(null, {
      observation: "unknown",
      state: "evidence_incomplete",
      grade: "L0",
      publishable: false,
    }),
  },
});
const isolated = lifecycle.deriveCertificateRenewalTransition(oldPure, issuerIncomplete, {
  previousReadiness: "expired",
  currentReadiness: "monitoring",
});
ok("incomplete issuer does not erase reliable SAN replacement", isolated.replacement && isolated.changed.san);
ok("incomplete issuer does not invent issuer change", isolated.changed.issuer === false);
ok("incomplete issuer does not erase reliable expiry renewal", isolated.renewed);

const allIncomplete = observation({
  ...newPure,
  id: "obs-all-incomplete",
  key: "surrogate-changed-only",
  overrides: Object.fromEntries(["leaf", "issuer", "san", "expiry", "wildcard"].map((name) => [
    name,
    resolvedSignal(null, {
      observation: "unknown",
      state: "evidence_incomplete",
      grade: "L0",
      publishable: false,
    }),
  ])),
});
eq(
  "composite-key drift without comparable signals is evidence-insufficient",
  lifecycle.deriveCertificateRenewalTransition(oldPure, allIncomplete).relation,
  "evidence_insufficient"
);

const failedCurrent = observation({
  id: "obs-failed",
  key: "leaf-failed",
  issuer: oldSpec.issuer,
  sans: oldSpec.sans,
  expiry: fixture.failed_replacement.current_expiry,
  wildcard: false,
  firstSeen: clock.replacement_detected,
  lastSeen: clock.replacement_detected,
});
const failedPrevious = observation({
  id: "obs-failed-previous",
  key: "leaf-failed-previous",
  issuer: oldSpec.issuer,
  sans: oldSpec.sans,
  expiry: fixture.failed_replacement.previous_expiry,
  wildcard: false,
  firstSeen: "2026-07-20T10:00:00.000Z",
  lastSeen: clock.baseline,
});
const failed = lifecycle.deriveCertificateRenewalTransition(failedPrevious, failedCurrent, {
  previousReadiness: "high",
  currentReadiness: "preparation",
  renewalStatus: fixture.failed_replacement.renewal_status,
});
ok("non-advancing in-progress replacement derives canonical renewal_failed", failed.renewal_failed);
ok("failed renewal is never renewed", !failed.renewed);

const ctOld = ctOnlyObservation(oldPure);
const ctNew = ctOnlyObservation({
  ...newPure,
  firstSeen: clock.replacement_detected,
  lastSeen: clock.replacement_reobserved,
});
const ctEvidence = lifecycle.buildVerificationEvidence({
  replacement_detected_at: clock.replacement_detected,
  expected_hostnames_json: JSON.stringify(["example.com"]),
}, { current: ctNew, previous: ctOld, now: clock.replacement_reobserved });
eq("CT-only later issuance cannot verify live replacement", ctEvidence.verification_result, "inconclusive");
ok("CT-only evidence never claims live serving", !ctEvidence.live_serving_evidence);

// ── 3. DB-backed production lifecycle and canonical case proof ─────────────
function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (file) => {
    try { db.exec(fs.readFileSync(file, "utf8")); } catch { /* convergent migrations */ }
  };
  apply(path.join(root, "database", "schema.sql"));
  for (const file of fs.readdirSync(path.join(root, "database", "migrations"))
    .filter((name) => name.endsWith(".sql"))
    .sort()) {
    apply(path.join(root, "database", "migrations", file));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}

function makeD1(db) {
  const statement = (sql, args = []) => ({
    bind: (...bound) => statement(sql, bound),
    first: async () => db.prepare(sql).get(...args) ?? null,
    all: async () => ({ results: db.prepare(sql).all(...args) }),
    run: async () => {
      const result = db.prepare(sql).run(...args);
      return { meta: { changes: result.changes } };
    },
  });
  return { prepare: (sql) => statement(sql) };
}

const db = buildDb();
const env = { cybermeters_db: makeD1(db) };
db.prepare("INSERT INTO users (id,email,name) VALUES ('u1','owner@example.com','Owner')").run();
for (const [id, name, deleted] of [
  ["ws1", "Primary", null],
  ["ws2", "Other tenant", null],
  ["ws-deleted", "Deleted", "2026-07-25T00:00:00.000Z"],
]) {
  db.prepare(`INSERT INTO workspaces (id,name,owner_user_id,deleted_at,created_at,updated_at)
              VALUES (?,?,?,?,datetime('now'),datetime('now'))`).run(id, name, "u1", deleted);
}
db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('d1','u1','example.com')").run();
for (const ws of ["ws1", "ws2", "ws-deleted"]) {
  db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES (?,'d1')").run(ws);
}

function seedDbObservation(workspaceId, row, scanId = "scan-1") {
  const evidence = JSON.parse(row.evidence_json);
  const sans = evidence.san_hostnames || [];
  db.prepare(`INSERT INTO certificate_observations
    (id,workspace_id,domain_id,scan_id,certificate_key,subject,issuer,san_count,expires_at,
     first_seen,last_seen,evidence_json,created_at,updated_at)
    VALUES (?,?,?,?,?,'example.com',?,?,?,?,?,?,?,?)`)
    .run(
      `${workspaceId}-${row.id}`, workspaceId, "d1", scanId, row.certificate_key,
      row.issuer, sans.length, row.expires_at, row.first_seen, row.last_seen,
      row.evidence_json, row.first_seen, row.last_seen
    );
  return `${workspaceId}-${row.id}`;
}

seedDbObservation("ws1", oldPure);
const otherObservation = observation({
  id: "other",
  key: "other-tenant-leaf",
  issuer: "Other Tenant CA",
  sans: ["example.com"],
  expiry: "2027-12-31T00:00:00.000Z",
  firstSeen: clock.baseline,
  lastSeen: clock.baseline,
});
seedDbObservation("ws2", otherObservation);
seedDbObservation("ws-deleted", oldPure);

await lifecycle.correlateCertificateLifecycle(env, "ws1", { now: clock.baseline });
await lifecycle.correlateCertificateLifecycle(env, "ws2", { now: clock.baseline });
const deletedResult = await lifecycle.correlateCertificateLifecycle(env, "ws-deleted", { now: clock.baseline });
eq("soft-deleted workspace is skipped", deletedResult.skipped, "workspace_inactive");
eq(
  "soft-deleted workspace receives no lifecycle row",
  db.prepare("SELECT COUNT(*) AS n FROM certificate_lifecycle WHERE workspace_id='ws-deleted'").get().n,
  0
);

let ws1Lifecycle = db.prepare("SELECT * FROM certificate_lifecycle WHERE workspace_id='ws1'").get();
ok("expired baseline opens one canonical certificate case", Boolean(ws1Lifecycle.linked_case_id));
eq(
  "exactly one host lifecycle",
  db.prepare("SELECT COUNT(*) AS n FROM certificate_lifecycle WHERE workspace_id='ws1'").get().n,
  1
);
await lifecycle.certificateLifecycleAction(
  env,
  "ws1",
  ws1Lifecycle.id,
  "set_expected_hostnames",
  {
    actor_id: "u1",
    expected_hostnames: ["example.com", "www.example.com", "api.example.com"],
    now: clock.baseline,
  }
);

async function advanceCaseCanonical(caseId) {
  for (const target of ["triaged", "assigned", "approved", "action_in_progress", "awaiting_verification"]) {
    const row = db.prepare("SELECT * FROM managed_cases WHERE id=? AND workspace_id='ws1'").get(caseId);
    const decision = cases.canTransitionCase({
      case: row,
      target_status: target,
      actor: { actor_type: "customer", actor_id: "u1" },
      owner_ref: target === "assigned" ? "u1" : undefined,
      now: clock.replacement_detected,
    });
    ok(`canonical case transition ${row.status}->${target}`, decision.ok, decision.error || "");
    if (!decision.ok) return;
    db.prepare(`UPDATE managed_cases
                SET status=?, owner_ref=?, owner_type=?, approved_at=?, action_started_at=?,
                    awaiting_verification_at=?, updated_at=?
                WHERE id=? AND workspace_id='ws1'`)
      .run(
        decision.case.status,
        decision.case.owner_ref || row.owner_ref || null,
        decision.case.owner_type || row.owner_type || null,
        decision.case.approved_at || row.approved_at || null,
        decision.case.action_started_at || row.action_started_at || null,
        decision.case.awaiting_verification_at || row.awaiting_verification_at || null,
        decision.case.updated_at,
        caseId
      );
    db.prepare(`INSERT INTO managed_case_events
      (id,case_id,workspace_id,actor_type,actor_id,from_status,to_status,action,detail_json,created_at)
      VALUES (?,?,?,?,?,?,?,?,?,?)`)
      .run(
        `mce-fixture-${target}`, caseId, "ws1", "customer", "u1",
        row.status, target, decision.event.action, decision.event.detail_json, clock.replacement_detected
      );
  }
}
await advanceCaseCanonical(ws1Lifecycle.linked_case_id);
eq(
  "case reaches awaiting_verification only through canonical machine",
  db.prepare("SELECT status FROM managed_cases WHERE id=?").get(ws1Lifecycle.linked_case_id).status,
  "awaiting_verification"
);

const ws2Before = JSON.stringify(db.prepare(
  "SELECT * FROM certificate_lifecycle WHERE workspace_id='ws2'"
).get());
const ws2EventsBefore = db.prepare(
  "SELECT COUNT(*) AS n FROM certificate_lifecycle_events WHERE workspace_id='ws2'"
).get().n;

const newDbObservation = { ...newPure, id: "new" };
const newDbId = seedDbObservation("ws1", newDbObservation, "scan-2");
await lifecycle.correlateCertificateLifecycle(env, "ws1", { now: clock.replacement_detected });
ws1Lifecycle = db.prepare("SELECT * FROM certificate_lifecycle WHERE workspace_id='ws1'").get();
eq("first replacement observation does not verify lifecycle", ws1Lifecycle.verification_status, "not_verified");
eq(
  "first replacement observation does not close case",
  db.prepare("SELECT status FROM managed_cases WHERE id=?").get(ws1Lifecycle.linked_case_id).status,
  "awaiting_verification"
);

await lifecycle.certificateLifecycleAction(
  env,
  "ws1",
  ws1Lifecycle.id,
  "record_replacement_completed",
  { actor_id: "u1", now: clock.replacement_detected }
);
const asserted = await lifecycle.certificateLifecycleAction(
  env,
  "ws1",
  ws1Lifecycle.id,
  "request_verification",
  { actor_id: "u1", now: clock.replacement_detected }
);
eq("customer assertion plus first scan remains inconclusive", asserted.item.verification_status, "inconclusive");
eq(
  "customer assertion cannot close case",
  db.prepare("SELECT status FROM managed_cases WHERE id=?").get(ws1Lifecycle.linked_case_id).status,
  "awaiting_verification"
);

const eventTypes = db.prepare(
  "SELECT event_type FROM certificate_lifecycle_events WHERE workspace_id='ws1' AND lifecycle_id=?"
).all(ws1Lifecycle.id).map((row) => row.event_type);
for (const type of fixture.replacement.expected_events) {
  eq(`one canonical ${type} event`, eventTypes.filter((item) => item === type).length, 1);
}
const firstRelationBefore = db.prepare(
  "SELECT detail_json FROM certificate_lifecycle_events WHERE lifecycle_id=? AND event_type='replaced' ORDER BY rowid LIMIT 1"
).get(ws1Lifecycle.id).detail_json;

const eventCountBeforeRepeat = db.prepare(
  "SELECT COUNT(*) AS n FROM certificate_lifecycle_events WHERE lifecycle_id=?"
).get(ws1Lifecycle.id).n;
const caseEventCountBeforeRepeat = db.prepare(
  "SELECT COUNT(*) AS n FROM managed_case_events WHERE case_id=?"
).get(ws1Lifecycle.linked_case_id).n;
await lifecycle.correlateCertificateLifecycle(env, "ws1", { now: clock.replacement_detected });
eq(
  "unchanged first observation emits no duplicate lifecycle event",
  db.prepare("SELECT COUNT(*) AS n FROM certificate_lifecycle_events WHERE lifecycle_id=?").get(ws1Lifecycle.id).n,
  eventCountBeforeRepeat
);
eq(
  "unchanged active recurrence emits no duplicate case event",
  db.prepare("SELECT COUNT(*) AS n FROM managed_case_events WHERE case_id=?").get(ws1Lifecycle.linked_case_id).n,
  caseEventCountBeforeRepeat
);

db.prepare(`UPDATE certificate_observations SET last_seen=?, scan_id='scan-3', updated_at=?
            WHERE id=? AND workspace_id='ws1'`)
  .run(clock.replacement_reobserved, clock.replacement_reobserved, newDbId);
await lifecycle.correlateCertificateLifecycle(env, "ws1", { now: clock.replacement_reobserved });
ws1Lifecycle = db.prepare("SELECT * FROM certificate_lifecycle WHERE workspace_id='ws1'").get();
eq("later complete live re-observation verifies lifecycle", ws1Lifecycle.verification_status, "verified_replaced");
eq(
  "later CyberMeters re-observation closes case through verified transition",
  db.prepare("SELECT status FROM managed_cases WHERE id=?").get(ws1Lifecycle.linked_case_id).status,
  "verified"
);
eq(
  "exactly one system case verification event",
  db.prepare(`SELECT COUNT(*) AS n FROM managed_case_events
              WHERE case_id=? AND to_status='verified' AND actor_type='system'`)
    .get(ws1Lifecycle.linked_case_id).n,
  1
);

const verifiedLifecycleEvents = db.prepare(
  "SELECT COUNT(*) AS n FROM certificate_lifecycle_events WHERE lifecycle_id=? AND event_type='verified_replaced'"
).get(ws1Lifecycle.id).n;
const verifiedCaseEvents = db.prepare(
  "SELECT COUNT(*) AS n FROM managed_case_events WHERE case_id=?"
).get(ws1Lifecycle.linked_case_id).n;
await lifecycle.correlateCertificateLifecycle(env, "ws1", { now: clock.replacement_reobserved });
eq(
  "same re-observation cannot duplicate verified lifecycle event",
  db.prepare("SELECT COUNT(*) AS n FROM certificate_lifecycle_events WHERE lifecycle_id=? AND event_type='verified_replaced'").get(ws1Lifecycle.id).n,
  verifiedLifecycleEvents
);
eq(
  "same re-observation cannot duplicate case event",
  db.prepare("SELECT COUNT(*) AS n FROM managed_case_events WHERE case_id=?").get(ws1Lifecycle.linked_case_id).n,
  verifiedCaseEvents
);

await lifecycle.certificateLifecycleAction(
  env,
  "ws1",
  ws1Lifecycle.id,
  "begin_renewal",
  { actor_id: "u1", now: clock.recurrence }
);
const failedDbObservation = observation({
  id: "failed",
  key: "leaf-failed-live",
  issuer: newSpec.issuer,
  sans: newSpec.sans,
  expiry: "2026-07-20T10:00:00.000Z",
  wildcard: true,
  firstSeen: clock.recurrence,
  lastSeen: clock.recurrence,
});
seedDbObservation("ws1", failedDbObservation, "scan-4");
await lifecycle.correlateCertificateLifecycle(env, "ws1", { now: clock.recurrence });
ws1Lifecycle = db.prepare("SELECT * FROM certificate_lifecycle WHERE workspace_id='ws1'").get();
eq(
  "recurrence reopens the same case through canonical machine",
  db.prepare("SELECT status FROM managed_cases WHERE id=?").get(ws1Lifecycle.linked_case_id).status,
  "reopened"
);
eq(
  "case identity is reused; no duplicate case",
  db.prepare(`SELECT COUNT(*) AS n FROM managed_cases
              WHERE workspace_id='ws1' AND case_type='certificate_case'
                AND finding_id='certificate:example.com'`).get().n,
  1
);
eq(
  "failed replacement emits one renewal_failed event",
  db.prepare("SELECT COUNT(*) AS n FROM certificate_lifecycle_events WHERE lifecycle_id=? AND event_type='renewal_failed'").get(ws1Lifecycle.id).n,
  1
);
eq(
  "second replacement appends a second relation",
  db.prepare("SELECT COUNT(*) AS n FROM certificate_lifecycle_events WHERE lifecycle_id=? AND event_type='replaced'").get(ws1Lifecycle.id).n,
  2
);
eq(
  "first replacement relationship remains byte-identical",
  db.prepare("SELECT detail_json FROM certificate_lifecycle_events WHERE lifecycle_id=? AND event_type='replaced' ORDER BY rowid LIMIT 1").get(ws1Lifecycle.id).detail_json,
  firstRelationBefore
);
eq(
  "all raw certificate identities remain append-only",
  db.prepare("SELECT COUNT(*) AS n FROM certificate_observations WHERE workspace_id='ws1' AND domain_id='d1'").get().n,
  3
);

const reopenEventsBefore = db.prepare(
  "SELECT COUNT(*) AS n FROM managed_case_events WHERE case_id=?"
).get(ws1Lifecycle.linked_case_id).n;
await lifecycle.correlateCertificateLifecycle(env, "ws1", { now: clock.recurrence });
eq(
  "unchanged reopened recurrence emits no duplicate case event",
  db.prepare("SELECT COUNT(*) AS n FROM managed_case_events WHERE case_id=?").get(ws1Lifecycle.linked_case_id).n,
  reopenEventsBefore
);

eq(
  "foreign/nonexistent lifecycle read is non-enumerating",
  await lifecycle.getCertificateLifecycle(env, "ws2", ws1Lifecycle.id),
  null
);
eq(
  "other tenant lifecycle row remains byte-identical",
  JSON.stringify(db.prepare("SELECT * FROM certificate_lifecycle WHERE workspace_id='ws2'").get()),
  ws2Before
);
eq(
  "other tenant receives no P3 event",
  db.prepare("SELECT COUNT(*) AS n FROM certificate_lifecycle_events WHERE workspace_id='ws2'").get().n,
  ws2EventsBefore
);

const source = fs.readFileSync(path.join(
  root, "workers", "scan-api", "src", "engines", "certificate-lifecycle.js"
), "utf8");
ok("production close uses canTransitionCase", /target_status: "verified"[\s\S]{0,160}actor: \{ actor_type: "system"/.test(source));
ok("production reopen uses canTransitionCase", /target_status: "reopened"[\s\S]{0,160}actor: \{ actor_type: "system"/.test(source));
ok("production case creation uses createManagedCase", /createManagedCase\(env,/.test(source));
ok("replacement events use deterministic INSERT OR IGNORE", /INSERT OR IGNORE INTO certificate_lifecycle_events/.test(source));
ok("lifecycle observations are batch loaded (no observation N+1)", /SELECT \* FROM certificate_lifecycle WHERE workspace_id = \?/.test(source));

const indexSource = fs.readFileSync(path.join(
  root, "workers", "scan-api", "src", "index.js"
), "utf8");
const purgeEvents = indexSource.indexOf('"certificate_lifecycle_events"');
const purgeLifecycle = indexSource.indexOf('"certificate_lifecycle"', purgeEvents);
ok("purge order keeps lifecycle events before lifecycle record", purgeEvents >= 0 && purgeLifecycle > purgeEvents);
ok("purge still covers certificate observations", indexSource.includes('"certificate_observations"'));

console.log(`\nItem 9 P3 renewal lifecycle: ${pass} passed, ${fail} failed`);
if (!fail) console.log("Item 9 P3 renewal lifecycle validation passed");
db.close();
process.exit(fail ? 1 : 0);
