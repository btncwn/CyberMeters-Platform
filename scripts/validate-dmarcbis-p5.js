#!/usr/bin/env node
// Item 7 P5 — narrow alerts, manual cases and later-complete-DNS verification.
//
// Exercises the real migration-088 occurrence resolver, canonical alert
// emitter/dedupe, universal case factory/route, immutable snapshot reader and
// transition validator against in-memory D1/R2. No network, migration or
// deployment is performed.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engine = (name) => import(pathToFileURL(path.join(
  root, "workers", "scan-api", "src", "engines", name,
)).href);
const route = (name) => import(pathToFileURL(path.join(
  root, "workers", "scan-api", "src", "routes", name,
)).href);

globalThis.fetch = async () => {
  throw new Error("network disabled in DMARCbis P5 validator");
};

let pass = 0;
let fail = 0;
const ok = (name, condition, detail = "") => {
  condition ? pass += 1 : fail += 1;
  if (!condition) {
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
};
const eq = (name, got, want) =>
  ok(name, got === want,
    `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);

const {
  DMARC_ALERT_RECURRENCES,
  createDmarcPolicyCase,
  emitDmarcPolicyAlerts,
  verifyDmarcPolicyCasesForScan,
} = await engine("dmarcbis-managed-lifecycle.js");
const {
  recordDmarcPolicyLifecycle,
  isDmarcPolicyConditionComplete,
} = await engine("dmarcbis-lifecycle.js");
const {
  establishDmarcPolicyBaseline,
} = await engine("email-protection-lifecycle.js");
const { sealDmarcPolicyEvidence } = await engine("dmarcbis-contract.js");
const { DMARCBIS_PARSER_VERSION } = await engine("dmarcbis-parser.js");
const { DMARCBIS_METHODOLOGY_VERSION } =
  await engine("dmarcbis-resolver.js");
const { DMARCBIS_IDNA_PROFILE } = await engine("dmarcbis-idna.js");
const { buildScanReportSnapshot } = await engine("report-snapshot.js");
const { resolveRemediation } = await engine("remediation-registry.js");
const { managedCasesRoutes } = await route("managed-cases.js");

const T0 = "2026-07-25T09:00:00.000Z";
const T1 = "2026-07-25T10:00:00.000Z";
const T2 = "2026-07-25T11:00:00.000Z";
const T3 = "2026-07-25T12:00:00.000Z";
const T4 = "2026-07-25T13:00:00.000Z";
const T5 = "2026-07-25T14:00:00.000Z";
const T6 = "2026-07-25T15:00:00.000Z";
const T7 = "2026-07-25T16:00:00.000Z";

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
    __sql: sql,
    bind: (...bound) => statement(sql, bound),
    first: async (column) => {
      const row = db.prepare(sql).get(...args) ?? null;
      return column && row ? row[column] : row;
    },
    all: async () => ({
      results: db.prepare(sql).all(...args),
      success: true,
      meta: {},
    }),
    run: async () => {
      const result = db.prepare(sql).run(...args);
      return {
        success: true,
        meta: {
          changes: result.changes,
          last_row_id: Number(result.lastInsertRowid || 0),
        },
      };
    },
  });
  return {
    prepare: (sql) => statement(sql),
    batch: async (statements) =>
      Promise.all(statements.map((entry) =>
        /^\s*select/i.test(entry.__sql) ? entry.all() : entry.run())),
  };
}

function makeR2(store) {
  return {
    get: async (key) => {
      const body = store.get(String(key));
      return body == null ? null : {
        text: async () => body,
        json: async () => JSON.parse(body),
      };
    },
    put: async (key, body) => {
      store.set(String(key), String(body));
      return {};
    },
    delete: async (key) => {
      store.delete(String(key));
      return {};
    },
    head: async () => null,
    list: async () => ({ objects: [] }),
  };
}

function seedTenant(db, {
  ws,
  user,
  domainId,
  domain = "example.test",
  deleted = false,
}) {
  db.prepare("INSERT INTO users (id, email) VALUES (?, ?)")
    .run(user, `${user}@example.test`);
  db.prepare(
    "INSERT INTO workspaces (id, name, deleted_at) VALUES (?, ?, ?)",
  ).run(ws, ws, deleted ? T0 : null);
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES (?, ?, ?)")
    .run(domainId, user, domain);
  db.prepare(
    "INSERT INTO workspace_domains (workspace_id, domain_id) VALUES (?, ?)",
  ).run(ws, domainId);
}

function exactWalk(author, rawState = "single_valid") {
  return [{
    question: {
      name: `_dmarc.${author}`,
      target_domain: author,
      type: "TXT",
      resolver: "primary",
      purpose: "policy_tree_walk",
    },
    outcome: "success",
    definitive: true,
    record_set: { raw_state: rawState },
  }];
}

function evidence(policy = "reject", overrides = {}) {
  const author = overrides.author_domain || "example.test";
  return {
    schema: "dmarc-policy.v2",
    methodology_version: DMARCBIS_METHODOLOGY_VERSION,
    parser_version: DMARCBIS_PARSER_VERSION,
    resolver_profile: "primary-plus-decisive-corroboration-v1",
    idna_profile: DMARCBIS_IDNA_PROFILE,
    author_domain: author,
    submitted_domain: author,
    observed_at: T1,
    observation_state: "present_valid",
    record_validity: "valid",
    raw_records: [],
    parsed_tags: [],
    lookup_path: exactWalk(author),
    tree_walk: { planned_questions: [], stop_reason: "psd_n", complete: true },
    organisational_domain: author,
    organisational_domain_provenance: "psd_n",
    organisational_domain_completeness: "complete",
    policy_source_domain: author,
    policy_source_kind: "exact",
    source_record: null,
    domain_existence: "not_required",
    existence_completeness: "not_applicable",
    declared_policy: policy,
    effective_requested_policy: policy,
    testing_adjustment: "none",
    effective_policy_tag: "p",
    inheritance_reason: "exact_p",
    p: { present: true, raw: policy, normalized: policy, valid: true },
    sp: { present: false, raw: null, normalized: null, valid: true },
    np: { present: false, raw: null, normalized: null, valid: true },
    t: { present: false, raw: null, normalized: null, valid: true },
    psd: { present: false, raw: null, normalized: null, valid: true },
    legacy_pct: {
      observed: false,
      raw: null,
      numeric: null,
      semantics: "rfc7489_legacy",
      applied_to_effective_policy: false,
    },
    rua_destinations: [],
    ruf_destinations: [],
    policy_completeness: "complete",
    corroboration_state: "corroborated",
    rua_authorisation_completeness: "not_applicable",
    external_rua_authorisation: {
      rua_authorisation_completeness: "not_applicable",
      destinations: [],
    },
    monitoring_state: "monitoring_healthy",
    provider_state: "available",
    receiver_enforcement_observed: false,
    core_completeness: "complete",
    outcome: "complete",
    evidence_grade: {
      observable_ceiling: "L5",
      beta_target: "L4",
      minimum_publishable: "L3",
      degrade_behavior: "Withhold when incomplete.",
      required_corroboration: ["decisive resolver"],
      grade: "L3",
      source_type: "normative_protocol",
      basis: "RFC 9989 DNS policy discovery.",
      limits: ["Receiver enforcement is not observed."],
      repeat_confirmed: false,
    },
    limits: {},
    ...overrides,
  };
}

function report(scanId, domainId, at, sealed, scanQuality = "complete") {
  return {
    scan_id: scanId,
    domain_id: domainId,
    domain: "example.test",
    status: "completed",
    cyber_metrics_score: 70,
    risk_level: "medium",
    started_at: at,
    completed_at: at,
    scan_quality: { status: scanQuality, modules_skipped: [] },
    monitoring_states: { signals: {} },
    modules: { dmarc_core: sealed },
    findings: [],
    recommendations: [],
  };
}

const db = buildDb();
const store = new Map();
const env = {
  cybermeters_db: makeD1(db),
  cybermeters_reports: makeR2(store),
  RESEND_API_KEY: "",
};

seedTenant(db, {
  ws: "ws-alert", user: "usr-alert", domainId: "dom-alert",
  domain: "alerts.example.test",
});
seedTenant(db, {
  ws: "ws-case", user: "usr-case", domainId: "dom-case",
});
seedTenant(db, {
  ws: "ws-other", user: "usr-other", domainId: "dom-other",
});
seedTenant(db, {
  ws: "ws-deleted", user: "usr-deleted", domainId: "dom-deleted",
  domain: "deleted.example.test", deleted: true,
});

// ── Five-alert allowlist, exclusion and occurrence dedupe ──────────────────
eq("founder alert allowlist is exact", DMARC_ALERT_RECURRENCES.join(","), [
  "record_removed",
  "record_became_malformed",
  "multiple_records_detected",
  "enforcement_weakened",
  "external_rua_unauthorised",
].join(","));
db.prepare(
  `INSERT INTO alert_activation
    (id, workspace_id, domain_key, activated_at, baseline_count, created_at)
   VALUES ('aa-p5', 'ws-alert', 'email_protection', ?, 0, ?)`,
).run(T0, T0);

const descriptorType = {
  record_removed: "missing",
  record_became_malformed: "malformed",
  multiple_records_detected: "multiple",
  enforcement_weakened: "weak",
  external_rua_unauthorised: "unauthorised_rua",
};
const descriptors = [];
let alertOrdinal = 0;
for (const recurrence of DMARC_ALERT_RECURRENCES) {
  alertOrdinal += 1;
  const recordId =
    `dmarc:dom-alert:${descriptorType[recurrence]}:` +
    `${String(alertOrdinal).padStart(64, "0")}`;
  const eventId = `epe-p5-${alertOrdinal}`;
  db.prepare(
    `INSERT INTO email_protection_events
      (id, record_id, record_type, workspace_id, actor_type, event_type,
       detail_json, created_at)
     VALUES (?, ?, 'dmarc_policy_condition', 'ws-alert', 'system',
             'monitoring_changed', ?, ?)`,
  ).run(eventId, recordId, JSON.stringify({
    domain_id: "dom-alert",
    author_domain: "alerts.example.test",
    to_recurrence_type: recurrence,
  }), T2);
  descriptors.push({
    event_id: eventId,
    record_id: recordId,
    recurrence_type: recurrence,
    condition_type: descriptorType[recurrence],
    entity: "alerts.example.test",
    author_domain: "alerts.example.test",
    transition_completeness: "complete",
  });
}

const alerted = await emitDmarcPolicyAlerts(env, {
  workspace_id: "ws-alert",
  lifecycle_result: { actionable_events: descriptors },
});
eq("all five definitive regressions reach canonical alert emitter",
  alerted.attempted, 5);
eq("five canonical in-app events are written",
  db.prepare(
    `SELECT COUNT(*) AS n FROM notification_events
     WHERE workspace_id = 'ws-alert'`,
  ).get().n, 5);
eq("alert activation never auto-opens a managed case",
  db.prepare(
    `SELECT COUNT(*) AS n FROM managed_cases
     WHERE workspace_id = 'ws-alert'`,
  ).get().n, 0);
await emitDmarcPolicyAlerts(env, {
  workspace_id: "ws-alert",
  lifecycle_result: { actionable_events: descriptors },
});
eq("replay creates no duplicate alert",
  db.prepare(
    `SELECT COUNT(*) AS n FROM notification_events
     WHERE workspace_id = 'ws-alert'`,
  ).get().n, 5);

const excluded = await emitDmarcPolicyAlerts(env, {
  workspace_id: "ws-alert",
  lifecycle_result: {
    actionable_events: [
      {
        event_id: "degraded",
        record_id: descriptors[0].record_id,
        recurrence_type: "monitoring_degraded",
        transition_completeness: "complete",
      },
      {
        event_id: "incomplete",
        record_id: descriptors[0].record_id,
        recurrence_type: "record_removed",
        transition_completeness: "incomplete",
      },
      {
        event_id: "strengthened",
        record_id: descriptors[0].record_id,
        recurrence_type: "enforcement_strengthened",
        transition_completeness: "complete",
      },
    ],
  },
});
eq("availability, incomplete and strengthened outcomes are non-alerting",
  excluded.attempted, 0);

for (const findingType of [
  "dmarc_exact_record_removed",
  "dmarc_invalid_record",
  "dmarc_multiple_records",
  "email_dmarc_policy_none",
  "dmarc_external_rua_unauthorised",
]) {
  const resolved = resolveRemediation({ finding_type: findingType });
  eq(`${findingType} has one canonical remediation`,
    resolved.status, "resolved");
  eq(`${findingType} verification is later DNS recheck`,
    resolved.verification_method, "dns_recheck");
  ok(`${findingType} remediation is suggestion-only`,
    resolved.recommended_action.includes("CyberMeters will not apply"));
  const customerCopy = [
    resolved.technical_explanation,
    resolved.business_impact,
    resolved.recommended_action,
  ].join(" ");
  ok(`${findingType} avoids prohibited DMARCbis claims`,
    !/full DMARC protection|DMARC enforcement is proven|receivers are blocking spoofed email|attackers cannot spoof|fully RFC compliant|malicious activity|external reporting is working|monitoring recovered|RFC Monitoring Mode/i
      .test(customerCopy));
}

// ── Real snapshot-backed condition and manual route ────────────────────────
async function buildObservedScan(
  scanId,
  at,
  policy,
  scanQuality = "complete",
  overrides = {},
) {
  const sealed = await sealDmarcPolicyEvidence({
    ...evidence(policy, overrides),
    observed_at: at,
  });
  db.prepare(
    `INSERT INTO scans
      (id, workspace_id, domain_id, domain, status, scan_quality, created_at)
     VALUES (?, 'ws-case', 'dom-case', 'example.test', 'completed', ?, ?)`,
  ).run(scanId, scanQuality, at);
  const body = report(scanId, "dom-case", at, sealed, scanQuality);
  store.set(`reports/${scanId}.json`, JSON.stringify(body));
  await establishDmarcPolicyBaseline(env, {
    workspace_id: "ws-case",
    domain_id: "dom-case",
    domain: "example.test",
    scan_id: scanId,
    policy_evidence: sealed,
  });
  const built = await buildScanReportSnapshot(env, {
    workspaceId: "ws-case",
    domainId: "dom-case",
    scanId,
    domain: "example.test",
    report: body,
    cyberEssentials: null,
    assessedAt: at,
  });
  return { sealed, built };
}

await buildObservedScan("scan-case-before", T1, "reject");
await buildObservedScan("scan-case-weak", T2, "none");
const lifecycle = await recordDmarcPolicyLifecycle(env, {
  workspace_id: "ws-case",
  domain_id: "dom-case",
  domain: "example.test",
  scan_id: "scan-case-weak",
});
const weakDescriptor = lifecycle.actionable_events.find((item) =>
  item.recurrence_type === "enforcement_weakened");
ok("real immutable pair produces weak-condition descriptor", !!weakDescriptor);
eq("P4 write alone still opens no case",
  db.prepare(
    `SELECT COUNT(*) AS n FROM managed_cases
     WHERE workspace_id = 'ws-case'`,
  ).get().n, 0);

async function postCase(workspaceId, body, userId = "usr-case") {
  return managedCasesRoutes({
    request: {
      method: "POST",
      json: async () => body,
    },
    env,
    url: new URL(`https://fixture.test/api/workspaces/${workspaceId}/cases`),
    json: (payload, status = 200) => ({ payload, status }),
    requireAuth: async () => ({ id: userId }),
    requireWorkspaceRole: async () => ({ role: "owner" }),
  });
}

const opened = await postCase("ws-case", {
  case_type: "email_case",
  domain_key: "email_protection",
  source_finding_type: "email_dmarc_policy_none",
  source_finding_id: weakDescriptor.record_id,
  source_scan_id: "caller-controlled-scan",
  domain: "attacker.example",
  severity: "critical",
  title: "caller-controlled-title",
});
eq("manual DMARC case route creates the eligible case", opened.status, 201);
eq("case source scan is derived from current immutable evidence",
  opened.payload.case.source_scan_id, "scan-case-weak");
eq("caller cannot inflate DMARC case severity",
  opened.payload.case.severity, "medium");
ok("caller cannot replace canonical case title",
  !opened.payload.case.title.includes("caller-controlled"));
eq("manual case carries canonical remediation",
  opened.payload.case.remediation_id, "email.dmarc.enforce");
eq("manual case is suggestion-only",
  db.prepare(
    `SELECT summary FROM managed_cases
     WHERE id = ?`,
  ).get(opened.payload.case.case_id).summary.includes(
    "not applied by CyberMeters",
  ), true);
eq("one append-only manual case link is recorded",
  db.prepare(
    `SELECT COUNT(*) AS n FROM email_protection_events
     WHERE workspace_id = 'ws-case' AND record_id = ?
       AND event_type = 'case_linked'`,
  ).get(weakDescriptor.record_id).n, 1);

db.prepare(
  `UPDATE email_protection_events SET created_at = '2099-01-01T00:00:00Z'
   WHERE workspace_id = 'ws-case' AND record_id = ?
     AND event_type = 'case_linked'`,
).run(weakDescriptor.record_id);
const reopened = await postCase("ws-case", {
  case_type: "email_case",
  source_finding_id: weakDescriptor.record_id,
});
eq("repeat manual request returns the stable existing case", reopened.status, 200);
eq("repeat manual request creates no duplicate case",
  db.prepare(
    `SELECT COUNT(*) AS n FROM managed_cases
     WHERE workspace_id = 'ws-case'`,
  ).get().n, 1);
eq("repeat manual request creates no duplicate case-link event",
  db.prepare(
    `SELECT COUNT(*) AS n FROM email_protection_events
     WHERE workspace_id = 'ws-case' AND record_id = ?
       AND event_type = 'case_linked'`,
  ).get(weakDescriptor.record_id).n, 1);

const foreign = await postCase("ws-other", {
  case_type: "email_case",
  source_finding_id: weakDescriptor.record_id,
}, "usr-other");
eq("same-hostname foreign tenant cannot resolve condition identity",
  foreign.status, 404);
const wrongCaseType = await postCase("ws-case", {
  case_type: "website_case",
  domain_key: "website_security",
  source_finding_id: weakDescriptor.record_id,
});
eq("DMARC identity cannot fall through into another domain's case type",
  wrongCaseType.status, 400);
eq("wrong case type creates no parallel-domain case",
  db.prepare(
    `SELECT COUNT(*) AS n FROM managed_cases
     WHERE workspace_id = 'ws-case' AND case_type = 'website_case'`,
  ).get().n, 0);
const deleted = await postCase("ws-deleted", {
  case_type: "email_case",
  source_finding_id: weakDescriptor.record_id,
}, "usr-deleted");
eq("soft-deleted workspace cannot receive a DMARC case", deleted.status, 404);

db.prepare(
  `UPDATE scan_report_snapshots SET scan_quality = 'partial'
   WHERE scan_id = 'scan-case-weak'`,
).run();
const incompleteCreate = await createDmarcPolicyCase(env, {
  workspace_id: "ws-case",
  record_id: weakDescriptor.record_id,
  actor: { actor_type: "customer", actor_id: "usr-case" },
});
eq("incomplete current scan cannot authorise a case",
  incompleteCreate.code, "current_evidence_incomplete");
db.prepare(
  `UPDATE scan_report_snapshots SET scan_quality = 'complete'
   WHERE scan_id = 'scan-case-weak'`,
).run();

// ── Verification: only later complete integrity-verified DNS evidence ──────
const caseId = opened.payload.case.case_id;
db.prepare(
  `UPDATE managed_cases
   SET status = 'awaiting_verification',
       awaiting_verification_at = ?, updated_at = ?
   WHERE id = ?`,
).run(T2, T2, caseId);

const sameObservation = await verifyDmarcPolicyCasesForScan(env, {
  workspace_id: "ws-case",
  domain_id: "dom-case",
  scan_id: "scan-case-weak",
});
eq("scan completion alone does not verify an active condition",
  sameObservation.verified, 0);
eq("active condition remains awaiting verification",
  db.prepare("SELECT status FROM managed_cases WHERE id = ?")
    .get(caseId).status, "awaiting_verification");

await buildObservedScan("scan-case-fixed", T3, "reject");
db.prepare(
  `UPDATE scan_report_snapshots SET scan_quality = 'partial'
   WHERE scan_id = 'scan-case-fixed'`,
).run();
const incompleteVerify = await verifyDmarcPolicyCasesForScan(env, {
  workspace_id: "ws-case",
  domain_id: "dom-case",
  scan_id: "scan-case-fixed",
});
eq("incomplete later scan is explicit and does not verify",
  incompleteVerify.reason, "scan_incomplete");
eq("incomplete later scan leaves case awaiting",
  db.prepare("SELECT status FROM managed_cases WHERE id = ?")
    .get(caseId).status, "awaiting_verification");
db.prepare(
  `UPDATE scan_report_snapshots SET scan_quality = 'complete'
   WHERE scan_id = 'scan-case-fixed'`,
).run();

const currentKey = db.prepare(
  `SELECT r2_key FROM scan_report_snapshots
   WHERE scan_id = 'scan-case-fixed'`,
).get().r2_key;
const currentBody = store.get(currentKey);
store.set(currentKey, `${currentBody}corrupt`);
const corruptVerify = await verifyDmarcPolicyCasesForScan(env, {
  workspace_id: "ws-case",
  domain_id: "dom-case",
  scan_id: "scan-case-fixed",
});
eq("D1/R2 hash disagreement withholds verification",
  corruptVerify.reason, "snapshot_integrity_unavailable");
eq("hash disagreement leaves case awaiting",
  db.prepare("SELECT status FROM managed_cases WHERE id = ?")
    .get(caseId).status, "awaiting_verification");
store.set(currentKey, currentBody);

const verified = await verifyDmarcPolicyCasesForScan(env, {
  workspace_id: "ws-case",
  domain_id: "dom-case",
  scan_id: "scan-case-fixed",
});
eq("later complete CyberMeters DNS re-observation verifies", verified.verified, 1);
const verifiedCase = db.prepare(
  "SELECT * FROM managed_cases WHERE id = ?",
).get(caseId);
eq("case reaches canonical verified state", verifiedCase.status, "verified");
ok("case receives a verification timestamp", !!verifiedCase.verified_at);
const verificationEvent = db.prepare(
  `SELECT * FROM managed_case_events
   WHERE case_id = ? AND to_status = 'verified'
   ORDER BY rowid DESC LIMIT 1`,
).get(caseId);
const verificationDetail = JSON.parse(
  verificationEvent?.detail_json || "{}",
);
eq("verification actor is CyberMeters", verificationEvent?.actor_type, "system");
eq("verification method is canonical DNS recheck",
  verificationDetail.evidence?.verification_method, "dns_recheck");
eq("verification evidence names complete re-observation",
  verificationDetail.evidence?.evidence_type,
  "dmarc_complete_reobservation");
eq("verification points to the exact later scan",
  verificationDetail.evidence?.evidence_reference?.scan_id,
  "scan-case-fixed");

await verifyDmarcPolicyCasesForScan(env, {
  workspace_id: "ws-case",
  domain_id: "dom-case",
  scan_id: "scan-case-fixed",
});
eq("verification replay creates no duplicate transition event",
  db.prepare(
    `SELECT COUNT(*) AS n FROM managed_case_events
     WHERE case_id = ? AND to_status = 'verified'`,
  ).get(caseId).n, 1);

const implementationSource = fs.readFileSync(path.join(
  root,
  "workers",
  "scan-api",
  "src",
  "engines",
  "dmarcbis-managed-lifecycle.js",
), "utf8");
ok("verifier does not read aggregate-report evidence",
  !implementationSource.includes("dmarc_aggregate_records") &&
  !implementationSource.includes("dmarc_reports"));
ok("verifier contains no customer-note verification path",
  !/note_only|customer_note|attestation/.test(implementationSource));
ok("P5 contains no DNS mutation path",
  !/dns\\.update|dns\\.create|hosted.*autopilot/i.test(
    implementationSource,
  ));

// Component completeness is condition-specific: external authorisation cannot
// verify on core evidence alone, while a weak-policy condition can.
const coreOnly = evidence("none", {
  rua_authorisation_completeness: "incomplete",
});
eq("weak-policy completeness does not depend on optional RUA phase",
  isDmarcPolicyConditionComplete("weak", coreOnly), true);
eq("external-RUA completeness fails closed when optional phase is incomplete",
  isDmarcPolicyConditionComplete("unauthorised_rua", coreOnly), false);

// Exact record loss remains a stable actionable condition even when a weaker
// inherited policy exists. It resolves only when the exact record returns or
// inheritance becomes equal/stronger than the pre-loss requested policy.
const inheritedNone = {
  observation_state: "absent",
  record_validity: "not_applicable",
  lookup_path: [
    ...exactWalk("example.test", "absent"),
    {
      question: {
        name: "_dmarc.test",
        target_domain: "test",
        type: "TXT",
        resolver: "primary",
        purpose: "policy_tree_walk",
      },
      outcome: "success",
      definitive: true,
      record_set: { raw_state: "single_valid" },
    },
  ],
  organisational_domain: "test",
  policy_source_domain: "test",
  policy_source_kind: "organisational",
  domain_existence: "exists",
  existence_completeness: "complete",
  declared_policy: "none",
  effective_requested_policy: "none",
  effective_policy_tag: "p",
  inheritance_reason: "organisational_p",
  p: { present: true, raw: "none", normalized: "none", valid: true },
};
await buildObservedScan(
  "scan-case-inherited-weak",
  T4,
  "none",
  "complete",
  inheritedNone,
);
const removedLifecycle = await recordDmarcPolicyLifecycle(env, {
  workspace_id: "ws-case",
  domain_id: "dom-case",
  domain: "example.test",
  scan_id: "scan-case-inherited-weak",
});
const removedDescriptor = removedLifecycle.actionable_events.find((item) =>
  item.recurrence_type === "record_removed");
ok("exact loss with weaker inheritance is actionable", !!removedDescriptor);
const removedCase = await createDmarcPolicyCase(env, {
  workspace_id: "ws-case",
  record_id: removedDescriptor.record_id,
  actor: { actor_type: "customer", actor_id: "usr-case" },
});
eq("weaker inheritance does not hide manual exact-loss eligibility",
  removedCase.ok, true);
eq("exact-loss case uses preserved publish remediation identity",
  removedCase.case?.remediation_id, "email.dmarc.publish");
ok("exact-loss summary acknowledges inherited policy",
  removedCase.case?.summary.includes("inherited or absent requested policy"));
db.prepare(
  `UPDATE managed_cases
   SET status = 'awaiting_verification',
       awaiting_verification_at = ?, updated_at = ?
   WHERE id = ?`,
).run(T4, T4, removedCase.case.id);
await buildObservedScan(
  "scan-case-still-inherited-weak",
  T5,
  "none",
  "complete",
  inheritedNone,
);
const stillLost = await verifyDmarcPolicyCasesForScan(env, {
  workspace_id: "ws-case",
  domain_id: "dom-case",
  scan_id: "scan-case-still-inherited-weak",
});
eq("later weaker inheritance does not falsely verify exact-record loss",
  stillLost.verified, 0);
eq("exact-loss case remains awaiting while condition is active",
  db.prepare("SELECT status FROM managed_cases WHERE id = ?")
    .get(removedCase.case.id).status, "awaiting_verification");
await buildObservedScan("scan-case-exact-restored", T6, "reject");
const restored = await verifyDmarcPolicyCasesForScan(env, {
  workspace_id: "ws-case",
  domain_id: "dom-case",
  scan_id: "scan-case-exact-restored",
});
eq("later complete exact-record restoration verifies exact-loss case",
  restored.verified, 1);
await buildObservedScan(
  "scan-case-exact-loss-recurred",
  T7,
  "none",
  "complete",
  inheritedNone,
);
const recurrentLifecycle = await recordDmarcPolicyLifecycle(env, {
  workspace_id: "ws-case",
  domain_id: "dom-case",
  domain: "example.test",
  scan_id: "scan-case-exact-loss-recurred",
});
const recurrentRemoved = recurrentLifecycle.actionable_events.find((item) =>
  item.recurrence_type === "record_removed");
eq("recurrence retains stable exact-loss condition identity",
  recurrentRemoved?.record_id, removedDescriptor.record_id);
const manualReopen = await createDmarcPolicyCase(env, {
  workspace_id: "ws-case",
  record_id: recurrentRemoved.record_id,
  actor: { actor_type: "customer", actor_id: "usr-case" },
});
eq("explicit manual action reopens the stable existing case",
  manualReopen.reopened, true);
eq("recurrence does not create a second case",
  db.prepare(
    `SELECT COUNT(*) AS n FROM managed_cases
     WHERE workspace_id = 'ws-case' AND finding_id = ?`,
  ).get(removedDescriptor.record_id).n, 1);
eq("manual recurrence passes through canonical reopened state",
  db.prepare("SELECT status FROM managed_cases WHERE id = ?")
    .get(removedCase.case.id).status, "reopened");
eq("manual recurrence appends one managed-case transition",
  db.prepare(
    `SELECT COUNT(*) AS n FROM managed_case_events
     WHERE case_id = ? AND to_status = 'reopened'`,
  ).get(removedCase.case.id).n, 1);
eq("manual recurrence appends non-occurrence Email history",
  db.prepare(
    `SELECT COUNT(*) AS n FROM email_protection_events
     WHERE workspace_id = 'ws-case' AND record_id = ?
       AND event_type = 'case_reopened'`,
  ).get(removedDescriptor.record_id).n, 1);

console.log(`\nDMARCbis P5 validation: ${pass} passed, ${fail} failed`);
if (!fail) console.log("DMARCbis P5 validation passed");
db.close();
process.exit(fail ? 1 : 0);
