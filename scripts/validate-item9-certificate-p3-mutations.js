#!/usr/bin/env node
// Item 9 P3 — load-bearing source mutations. Every mutant reintroduces a
// concrete lifecycle/case defect and the corresponding executable contract
// observes that defect. Checked-in production sources are never overwritten.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engines = path.join(root, "workers", "scan-api", "src", "engines");
const sourcePath = path.join(engines, "certificate-lifecycle.js");
let sequence = 0;
let pass = 0;
let fail = 0;
const ok = (name, condition, detail = "") => {
  condition ? pass++ : fail++;
  if (!condition) console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
};

async function withMutant(name, mutate, execute) {
  const source = fs.readFileSync(sourcePath, "utf8");
  const mutated = mutate(source);
  ok(`${name}: mutation applies`, mutated !== source);
  if (mutated === source) return;
  const mutantPath = path.join(
    engines,
    `.certificate-lifecycle.item9-p3-mutant.${process.pid}.${++sequence}.js`
  );
  fs.writeFileSync(mutantPath, mutated);
  try {
    const module = await import(`${pathToFileURL(mutantPath).href}?mutation=${sequence}`);
    await execute(module);
  } finally {
    fs.rmSync(mutantPath, { force: true });
  }
}

function signal(value, {
  observation = "present",
  scope = "live_tls",
  state = "monitoring_healthy",
  publishable = true,
} = {}) {
  return {
    completeness_state: state,
    complete: state === "monitoring_healthy",
    observation,
    value,
    observation_scope: scope,
    achieved_grade: publishable ? "L3" : "L1",
    publishable,
    source_type: "normative_protocol",
    provenance: [{ source: "item9-p3-mutation-fixture" }],
  };
}

function obs({
  id,
  key,
  issuer = "Mutation CA",
  sans = ["example.com"],
  expiry,
  first = "2026-07-26T10:00:00.000Z",
  last = first,
  signalOverrides = {},
}) {
  const signals = {
    leaf: signal({ certificate_identity: key }),
    issuer: signal(issuer),
    san: signal(sans),
    expiry: signal(expiry),
    wildcard: signal(false, { observation: "absent" }),
    ...signalOverrides,
  };
  return {
    id,
    certificate_key: key,
    issuer,
    expires_at: expiry,
    first_seen: first,
    last_seen: last,
    evidence_json: JSON.stringify({
      issuer,
      san_hostnames: sans,
      expires_at: expiry,
      signal_completeness: { signals },
    }),
  };
}

const oldObs = obs({
  id: "old",
  key: "leaf-old",
  issuer: "Old CA",
  sans: ["example.com", "www.example.com"],
  expiry: "2026-08-01T00:00:00.000Z",
});
const newObs = obs({
  id: "new",
  key: "leaf-new",
  issuer: "New CA",
  sans: ["example.com", "api.example.com"],
  expiry: "2027-08-01T00:00:00.000Z",
  first: "2026-07-27T10:00:00.000Z",
  last: "2026-07-27T10:00:00.000Z",
});

await withMutant(
  "collapsed sibling completeness",
  (source) => source.replace(
    "const replacement = surrogateChanged && Object.values(changed).some(Boolean);",
    "const replacement = surrogateChanged && Object.values(changed).every(Boolean);"
  ),
  async (mutant) => {
    const incompleteIssuer = obs({
      ...newObs,
      id: "new-incomplete-issuer",
      key: "leaf-new-incomplete-issuer",
      signalOverrides: {
        issuer: signal(null, {
          observation: "unknown",
          state: "evidence_incomplete",
          publishable: false,
        }),
      },
    });
    const result = mutant.deriveCertificateRenewalTransition(oldObs, incompleteIssuer);
    ok("collapsed sibling completeness: reliable SAN/expiry replacement disappears", !result.replacement);
  }
);

await withMutant(
  "first replacement scan verifies",
  (source) => source.replace(
    '  if (!laterReobservation) verification_result = "inconclusive";',
    '  if (false) verification_result = "inconclusive";'
  ),
  async (mutant) => {
    const result = mutant.buildVerificationEvidence({
      replacement_detected_at: newObs.first_seen,
      expected_hostnames_json: JSON.stringify(["example.com"]),
    }, { current: newObs, previous: oldObs, now: newObs.last_seen });
    ok("first replacement scan verifies: first observation becomes verified", result.verification_result === "verified");
  }
);

await withMutant(
  "CT-only evidence verifies",
  (source) => source.replace(
    `    method_appropriate:
      signal.comparable &&
      signal.publishable &&
      signal.completeness_state === "monitoring_healthy" &&
      signal.observation === "present" &&
      liveTls,`,
    "    method_appropriate: signal.comparable,"
  ),
  async (mutant) => {
    const ct = (row) => {
      const evidence = JSON.parse(row.evidence_json);
      for (const name of ["leaf", "issuer", "san", "expiry", "wildcard"]) {
        evidence.signal_completeness.signals[name].observation_scope = "ct_issuance";
        evidence.signal_completeness.signals[name].publishable = false;
        evidence.signal_completeness.signals[name].achieved_grade = "L1";
      }
      return { ...row, evidence_json: JSON.stringify(evidence) };
    };
    const current = ct({
      ...newObs,
      last_seen: "2026-07-28T10:00:00.000Z",
    });
    const result = mutant.buildVerificationEvidence({
      replacement_detected_at: "2026-07-27T10:00:00.000Z",
      expected_hostnames_json: JSON.stringify(["example.com"]),
    }, { current, previous: ct(oldObs), now: current.last_seen });
    ok("CT-only evidence verifies: issuance is promoted to live closure", result.verification_result === "verified");
  }
);

await withMutant(
  "in-progress failed renewal disappears",
  (source) => source.replace(
    "    RENEWAL_WORKFLOW_STATES.has(renewalStatus) ||",
    "    false ||"
  ),
  async (mutant) => {
    const backwards = obs({
      id: "backwards",
      key: "leaf-backwards",
      expiry: "2026-07-30T00:00:00.000Z",
      first: "2026-07-27T10:00:00.000Z",
    });
    const previous = obs({
      id: "before-backwards",
      key: "leaf-before-backwards",
      expiry: "2027-07-30T00:00:00.000Z",
    });
    const result = mutant.deriveCertificateRenewalTransition(previous, backwards, {
      previousReadiness: "monitoring",
      currentReadiness: "critical",
      renewalStatus: "in_progress",
    });
    ok("in-progress failed renewal disappears: renewal_failed is lost", !result.renewal_failed);
  }
);

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (file) => {
    try { db.exec(fs.readFileSync(file, "utf8")); } catch { /* convergent */ }
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

function seedBase(db) {
  db.prepare("INSERT INTO users (id,email) VALUES ('u1','owner@example.com')").run();
  db.prepare("INSERT INTO workspaces (id,name,owner_user_id) VALUES ('ws','Workspace','u1')").run();
  db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('dom','u1','example.com')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES ('ws','dom')").run();
}

function insertObservation(db, row) {
  const evidence = JSON.parse(row.evidence_json);
  db.prepare(`INSERT INTO certificate_observations
    (id,workspace_id,domain_id,scan_id,certificate_key,subject,issuer,san_count,expires_at,
     first_seen,last_seen,evidence_json,created_at,updated_at)
    VALUES (?,'ws','dom','scan',?,'example.com',?,?,?,?,?,?,?,?)`)
    .run(
      row.id,
      row.certificate_key,
      row.issuer,
      (evidence.san_hostnames || []).length,
      row.expires_at,
      row.first_seen,
      row.last_seen,
      row.evidence_json,
      row.first_seen,
      row.last_seen
    );
}

await withMutant(
  "furthest-expiry row wins over latest observation",
  (source) => source.replace(
    '      String(b.last_seen || "").localeCompare(String(a.last_seen || "")) ||',
    '      String(b.expires_at || "").localeCompare(String(a.expires_at || "")) ||'
  ),
  async (mutant) => {
    const db = buildDb();
    try {
      seedBase(db);
      const farOld = obs({
        id: "far-old",
        key: "far-old",
        expiry: "2030-01-01T00:00:00.000Z",
        first: "2026-07-01T00:00:00.000Z",
        last: "2026-07-20T00:00:00.000Z",
      });
      const latestShorter = obs({
        id: "latest-shorter",
        key: "latest-shorter",
        issuer: "Replacement CA",
        expiry: "2027-01-01T00:00:00.000Z",
        first: "2026-07-27T00:00:00.000Z",
        last: "2026-07-27T00:00:00.000Z",
      });
      insertObservation(db, farOld);
      const env = { cybermeters_db: makeD1(db) };
      await mutant.correlateCertificateLifecycle(env, "ws", { now: "2026-07-26T00:00:00.000Z" });
      insertObservation(db, latestShorter);
      await mutant.correlateCertificateLifecycle(env, "ws", { now: "2026-07-27T00:00:00.000Z" });
      ok(
        "furthest-expiry row wins: latest shorter replacement stays hidden",
        db.prepare("SELECT certificate_identity FROM certificate_lifecycle WHERE workspace_id='ws'").get().certificate_identity === "far-old"
      );
    } finally {
      db.close();
    }
  }
);

await withMutant(
  "unchanged active recurrence appends",
  (source) => source.replace(
    "  if (!conditionChanged) return { ok: true, deduped: true, case: kase };",
    "  if (false) return { ok: true, deduped: true, case: kase };"
  ),
  async (mutant) => {
    const db = buildDb();
    try {
      seedBase(db);
      db.prepare(`INSERT INTO managed_cases
        (id,workspace_id,case_type,domain_key,finding_id,source_finding_type,remediation_id,status,severity,created_at,updated_at)
        VALUES ('mc','ws','certificate_case','certificates_trust','certificate:example.com',
                'certificate_expired','cert.expiry.expired','detected','high',datetime('now'),datetime('now'))`).run();
      db.prepare(`INSERT INTO certificate_lifecycle
        (id,workspace_id,domain_id,primary_hostname,certificate_identity,current_certificate_observation_id,
         expected_hostnames_json,observed_sans_json,coverage_status,ownership_status,renewal_status,
         renewal_readiness,verification_status,monitoring_status,material_change,lifecycle_state,
         linked_case_id,first_seen_at,last_seen_at,created_at,updated_at)
        VALUES ('cl','ws','dom','example.com','leaf','obs','[]','[]','unknown','missing',
                'not_started','expired','not_verified','observed',0,'expired','mc',
                datetime('now'),datetime('now'),datetime('now'),datetime('now'))`).run();
      const env = { cybermeters_db: makeD1(db) };
      await mutant.openOrReopenCertificateCase(env, db.prepare("SELECT * FROM certificate_lifecycle WHERE id='cl'").get(), {
        recurrence: "expired",
        conditionChanged: false,
        now: "2026-07-26T00:00:00.000Z",
      });
      ok(
        "unchanged active recurrence appends: duplicate audit row appears",
        db.prepare("SELECT COUNT(*) AS n FROM managed_case_events WHERE case_id='mc'").get().n === 1
      );
    } finally {
      db.close();
    }
  }
);

await withMutant(
  "case verifier acts as customer",
  (source) => source.replace(
    `  const decision = canTransitionCase({
    case: kase, target_status: "verified",
    actor: { actor_type: "system", actor_id: null }, evidence: caseEvidence, now,
  });`,
    `  const decision = canTransitionCase({
    case: kase, target_status: "verified",
    actor: { actor_type: "customer", actor_id: "u1" }, evidence: caseEvidence, now,
  });`
  ),
  async (mutant) => {
    const db = buildDb();
    try {
      seedBase(db);
      const previous = obs({
        id: "prev",
        key: "prev",
        expiry: "2026-08-01T00:00:00.000Z",
        first: "2026-07-01T00:00:00.000Z",
        last: "2026-07-20T00:00:00.000Z",
      });
      const current = obs({
        id: "cur",
        key: "cur",
        expiry: "2027-08-01T00:00:00.000Z",
        first: "2026-07-27T00:00:00.000Z",
        last: "2026-07-28T00:00:00.000Z",
      });
      insertObservation(db, previous);
      insertObservation(db, current);
      db.prepare(`INSERT INTO managed_cases
        (id,workspace_id,case_type,domain_key,finding_id,source_finding_type,remediation_id,status,severity,created_at,updated_at)
        VALUES ('mc','ws','certificate_case','certificates_trust','certificate:example.com',
                'certificate_expired','cert.expiry.expired','awaiting_verification','high',datetime('now'),datetime('now'))`).run();
      db.prepare(`INSERT INTO certificate_lifecycle
        (id,workspace_id,domain_id,primary_hostname,certificate_identity,current_certificate_observation_id,
         previous_certificate_observation_id,replacement_detected_at,expected_hostnames_json,observed_sans_json,
         coverage_status,ownership_status,renewal_status,renewal_readiness,verification_status,monitoring_status,
         material_change,lifecycle_state,linked_case_id,first_seen_at,last_seen_at,created_at,updated_at)
        VALUES ('cl','ws','dom','example.com','cur','cur','prev','2026-07-27T00:00:00.000Z',
                '[\"example.com\"]','[\"example.com\"]','complete','known','awaiting_verification',
                'monitoring','not_verified','observed',0,'awaiting_verification','mc',
                '2026-07-01T00:00:00.000Z','2026-07-28T00:00:00.000Z',datetime('now'),datetime('now'))`).run();
      const env = { cybermeters_db: makeD1(db) };
      await mutant.certificateLifecycleAction(env, "ws", "cl", "request_verification", {
        actor_id: "u1",
        now: "2026-07-28T00:00:00.000Z",
      });
      ok(
        "case verifier acts as customer: canonical automated gate refuses closure",
        db.prepare("SELECT status FROM managed_cases WHERE id='mc'").get().status !== "verified"
      );
    } finally {
      db.close();
    }
  }
);

await withMutant(
  "reopen targets noncanonical edge",
  (source) => source.replace(
    'target_status: "reopened", actor: { actor_type: "system", actor_id: null }',
    'target_status: "action_in_progress", actor: { actor_type: "system", actor_id: null }'
  ),
  async (mutant) => {
    const db = buildDb();
    try {
      seedBase(db);
      db.prepare(`INSERT INTO managed_cases
        (id,workspace_id,case_type,domain_key,finding_id,source_finding_type,remediation_id,status,severity,created_at,updated_at)
        VALUES ('mc','ws','certificate_case','certificates_trust','certificate:example.com',
                'certificate_expired','cert.expiry.expired','verified','high',datetime('now'),datetime('now'))`).run();
      db.prepare(`INSERT INTO certificate_lifecycle
        (id,workspace_id,domain_id,primary_hostname,certificate_identity,current_certificate_observation_id,
         expected_hostnames_json,observed_sans_json,coverage_status,ownership_status,renewal_status,
         renewal_readiness,verification_status,monitoring_status,material_change,lifecycle_state,
         linked_case_id,first_seen_at,last_seen_at,created_at,updated_at)
        VALUES ('cl','ws','dom','example.com','leaf','obs','[]','[]','unknown','missing',
                'not_started','expired','not_verified','observed',0,'expired','mc',
                datetime('now'),datetime('now'),datetime('now'),datetime('now'))`).run();
      const env = { cybermeters_db: makeD1(db) };
      await mutant.openOrReopenCertificateCase(env, db.prepare("SELECT * FROM certificate_lifecycle WHERE id='cl'").get(), {
        recurrence: "expired",
        conditionChanged: true,
        now: "2026-07-26T00:00:00.000Z",
      });
      ok(
        "reopen targets noncanonical edge: verified case fails to reopen",
        db.prepare("SELECT status FROM managed_cases WHERE id='mc'").get().status === "verified"
      );
    } finally {
      db.close();
    }
  }
);

console.log(`\nItem 9 P3 mutations: ${pass} passed, ${fail} failed`);
if (!fail) console.log("Item 9 P3 mutation proof passed");
process.exit(fail ? 1 : 0);
