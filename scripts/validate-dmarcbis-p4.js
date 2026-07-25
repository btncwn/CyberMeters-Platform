#!/usr/bin/env node
// Item 7 P4 — immutable lifecycle + Related Changes fixtures.
//
// Drives the pure transition predicates and the real snapshot reader, migration
// 088 writer, timeline reader, occurrence resolver, and Related Changes adapter
// against in-memory SQLite/R2. No network, alerts, cases, or migrations run.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engine = (name) =>
  import(pathToFileURL(path.join(
    root,
    "workers",
    "scan-api",
    "src",
    "engines",
    name,
  )).href);

globalThis.fetch = async () => {
  throw new Error("network disabled in DMARCbis P4 validator");
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
  DMARC_LIFECYCLE_SUBTYPES,
  deriveDmarcPolicyTransitions,
  recordDmarcPolicyLifecycle,
} = await engine("dmarcbis-lifecycle.js");
const {
  DMARC_POLICY_CONDITION_RECORD_TYPE,
  deriveDmarcPolicyConditions,
  dmarcPolicyConditionRecordId,
  establishDmarcPolicyBaseline,
  listEmailProtectionEvents,
  countEmailProtectionEvents,
} = await engine("email-protection-lifecycle.js");
const {
  sealDmarcPolicyEvidence,
} = await engine("dmarcbis-contract.js");
const {
  buildScanReportSnapshot,
} = await engine("report-snapshot.js");
const {
  collectChangeEvents,
  SIGNAL_FAMILY,
} = await engine("related-changes-adapter.js");
const {
  correlateChangeEvents,
} = await engine("related-changes-rules.js");
const {
  correlateRelatedChanges,
  createCaseFromRelatedChange,
  getRelatedChange,
  listRelatedChanges,
  RELATED_CHANGES_CAUSALITY_NOTICE,
} = await engine("related-changes.js");
const {
  findConditionOccurrence,
} = await engine("alert-occurrence.js");
const {
  DMARCBIS_PARSER_VERSION,
} = await engine("dmarcbis-parser.js");
const {
  DMARCBIS_METHODOLOGY_VERSION,
} = await engine("dmarcbis-resolver.js");
const {
  DMARCBIS_IDNA_PROFILE,
} = await engine("dmarcbis-idna.js");

const T0 = "2026-07-25T10:00:00.000Z";
const T1 = "2026-07-25T11:00:00.000Z";
const T2 = "2026-07-25T12:00:00.000Z";
const T3 = "2026-07-25T13:00:00.000Z";
const T4 = "2026-07-25T14:00:00.000Z";
const T5 = "2026-07-25T15:00:00.000Z";
const T6 = "2026-07-25T16:00:00.000Z";

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

function evidence(overrides = {}) {
  const author = overrides.author_domain || "example.test";
  const base = {
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
    organisational_domain: "example.test",
    organisational_domain_provenance: "psd_n",
    organisational_domain_completeness: "complete",
    policy_source_domain: author,
    policy_source_kind: "exact",
    source_record: null,
    domain_existence: "not_required",
    existence_completeness: "not_applicable",
    declared_policy: "reject",
    effective_requested_policy: "reject",
    testing_adjustment: "none",
    effective_policy_tag: "p",
    inheritance_reason: "exact_p",
    p: { present: true, raw: "reject", normalized: "reject", valid: true },
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
  };
  return { ...base, ...overrides };
}

function absent(overrides = {}) {
  return evidence({
    observation_state: "absent",
    record_validity: "not_applicable",
    raw_records: [],
    parsed_tags: [],
    policy_source_domain: null,
    policy_source_kind: "none",
    declared_policy: null,
    effective_requested_policy: null,
    effective_policy_tag: null,
    inheritance_reason: "none",
    p: null,
    sp: null,
    np: null,
    t: null,
    corroboration_state: "not_applicable",
    lookup_path: exactWalk(
      overrides.author_domain || "example.test",
      "absent",
    ),
    ...overrides,
  });
}

function inherited(policy = "reject", overrides = {}) {
  return evidence({
    observation_state: "absent",
    record_validity: "not_applicable",
    policy_source_domain: "example.test",
    policy_source_kind: "organisational",
    domain_existence: "exists",
    existence_completeness: "complete",
    declared_policy: policy,
    effective_requested_policy: policy,
    effective_policy_tag: "p",
    inheritance_reason: "organisational_p",
    p: { present: true, raw: policy, normalized: policy, valid: true },
    ...overrides,
  });
}

function rua(uri, status, overrides = {}) {
  const destination = {
    raw: uri,
    normalized_uri: uri,
    uri,
    scheme: "mailto",
    syntax_valid: true,
    supported_scheme: true,
    destination_host: "reports.vendor.test",
  };
  const authorization = {
    ...destination,
    authorization_query_name:
      "example.test._report._dmarc.reports.vendor.test",
    authorization_status: status,
    same_organisational_domain:
      status === "not_required_same_organisational_domain" ? true : false,
    authorization_record_state:
      status === "unauthorized" ? "absent" : "single_valid",
    lookup_completeness: "complete",
  };
  return evidence({
    rua_destinations: [destination],
    rua_authorisation_completeness: "complete",
    external_rua_authorisation: {
      rua_authorisation_completeness: "complete",
      destinations: [authorization],
    },
    ...overrides,
  });
}

function subtypes(before, after) {
  return deriveDmarcPolicyTransitions(before, after)
    .map((item) => item.subtype);
}

// ── Pure taxonomy predicates ────────────────────────────────────────────────
{
  const fixtures = [
    ["record_created", absent(), evidence()],
    ["record_removed", evidence(), absent()],
    ["record_became_malformed", evidence(), evidence({
      observation_state: "present_invalid",
      record_validity: "invalid",
      lookup_path: exactWalk("example.test", "single_invalid"),
      policy_source_domain: null,
      policy_source_kind: "none",
      declared_policy: null,
      effective_requested_policy: null,
      effective_policy_tag: null,
      inheritance_reason: "none",
    })],
    ["multiple_records_detected", evidence(), evidence({
      observation_state: "multiple",
      record_validity: "invalid",
      lookup_path: exactWalk("example.test", "multiple"),
      policy_source_domain: null,
      policy_source_kind: "none",
      declared_policy: null,
      effective_requested_policy: null,
      effective_policy_tag: null,
      inheritance_reason: "none",
    })],
    ["policy_changed", evidence({
      declared_policy: "reject",
      effective_requested_policy: "quarantine",
      testing_adjustment: "one_level_below",
      t: {
        present: true,
        raw: "y",
        normalized: "y",
        valid: true,
      },
    }), evidence({
      declared_policy: "quarantine",
      effective_requested_policy: "quarantine",
      testing_adjustment: "none",
      p: {
        present: true,
        raw: "quarantine",
        normalized: "quarantine",
        valid: true,
      },
      t: {
        present: true,
        raw: "n",
        normalized: "n",
        valid: true,
      },
    })],
    ["policy_inherited", evidence(), inherited("reject")],
    ["inheritance_source_changed",
      inherited("reject", { policy_source_domain: "a.example.test" }),
      inherited("reject", { policy_source_domain: "b.example.test" })],
    ["organisational_domain_changed",
      inherited("reject", { organisational_domain: "old.example.test" }),
      inherited("reject", { organisational_domain: "example.test" })],
    ["subdomain_policy_changed",
      inherited("none", {
        effective_policy_tag: "sp",
        inheritance_reason: "organisational_sp",
        sp: { present: true, raw: "none", normalized: "none", valid: true },
      }),
      inherited("reject", {
        effective_policy_tag: "sp",
        inheritance_reason: "organisational_sp",
        sp: {
          present: true,
          raw: "reject",
          normalized: "reject",
          valid: true,
        },
      })],
    ["non_existent_subdomain_policy_changed",
      inherited("none", {
        domain_existence: "nonexistent",
        effective_policy_tag: "np",
        inheritance_reason: "organisational_np",
        np: { present: true, raw: "none", normalized: "none", valid: true },
      }),
      inherited("reject", {
        domain_existence: "nonexistent",
        effective_policy_tag: "np",
        inheritance_reason: "organisational_np",
        np: {
          present: true,
          raw: "reject",
          normalized: "reject",
          valid: true,
        },
      })],
    ["enforcement_strengthened",
      evidence({
        declared_policy: "none",
        effective_requested_policy: "none",
      }),
      evidence()],
    ["enforcement_weakened",
      evidence(),
      evidence({
        declared_policy: "none",
        effective_requested_policy: "none",
      })],
    ["legacy_pct_observed",
      evidence(),
      evidence({
        legacy_pct: {
          observed: true,
          raw: "25",
          numeric: 25,
          semantics: "rfc7489_legacy",
          applied_to_effective_policy: false,
        },
      })],
    ["external_rua_added", evidence(), rua(
      "mailto:agg@reports.vendor.test",
      "authorized",
    )],
    ["external_rua_removed", rua(
      "mailto:agg@reports.vendor.test",
      "authorized",
    ), evidence()],
    ["external_rua_authorised",
      rua("mailto:agg@reports.vendor.test", "unauthorized"),
      rua("mailto:agg@reports.vendor.test", "authorized")],
    ["external_rua_unauthorised",
      rua("mailto:agg@reports.vendor.test", "authorized"),
      rua("mailto:agg@reports.vendor.test", "unauthorized")],
    ["external_rua_authorisation_unavailable",
      rua("mailto:agg@reports.vendor.test", "authorized"),
      rua("mailto:agg@reports.vendor.test", "unavailable", {
        rua_authorisation_completeness: "incomplete",
        external_rua_authorisation: {
          rua_authorisation_completeness: "incomplete",
          destinations: [{
            normalized_uri: "mailto:agg@reports.vendor.test",
            authorization_query_name:
              "example.test._report._dmarc.reports.vendor.test",
            authorization_status: "unavailable",
            lookup_completeness: "incomplete",
          }],
        },
        monitoring_state: "monitoring_degraded",
      })],
    ["monitoring_degraded", evidence(), evidence({
      core_completeness: "unavailable",
      policy_completeness: "unavailable",
      organisational_domain_completeness: "unavailable",
      monitoring_state: "monitoring_degraded",
      provider_state: "timeout",
      observation_state: "unavailable",
      record_validity: "indeterminate",
      effective_requested_policy: null,
      declared_policy: null,
      policy_source_domain: null,
      policy_source_kind: "unknown",
      inheritance_reason: "unknown",
    })],
  ];
  for (const [expected, before, after] of fixtures) {
    ok(
      `taxonomy emits ${expected}`,
      subtypes(before, after).includes(expected),
      subtypes(before, after).join(","),
    );
  }
  const strengthened = subtypes(
    evidence({
      declared_policy: "none",
      effective_requested_policy: "none",
    }),
    evidence(),
  );
  ok(
    "strength subtype supersedes generic policy_changed for the same edit",
    strengthened.includes("enforcement_strengthened") &&
      !strengthened.includes("policy_changed"),
  );
  eq(
    "stable taxonomy is complete and excludes monitoring_recovered",
    DMARC_LIFECYCLE_SUBTYPES.length,
    19,
  );
  ok(
    "monitoring_recovered is prohibited",
    !DMARC_LIFECYCLE_SUBTYPES.includes("monitoring_recovered"),
  );
  eq(
    "legacy snapshot without v2 evidence cannot become a P4 transition baseline",
    deriveDmarcPolicyTransitions(null, evidence()).length,
    0,
  );
  const sourceBefore = inherited("reject", {
    author_domain: "mail.example.test",
    lookup_path: [
      ...exactWalk("mail.example.test", "absent"),
      {
        ...exactWalk("example.test", "single_valid")[0],
        question: {
          ...exactWalk("example.test", "single_valid")[0].question,
          name: "_dmarc.example.test",
          target_domain: "example.test",
        },
      },
    ],
  });
  const sourceAfter = inherited("reject", {
    author_domain: "mail.example.test",
    lookup_path: [
      ...exactWalk("mail.example.test", "absent"),
      {
        ...exactWalk("example.test", "single_invalid")[0],
        question: {
          ...exactWalk("example.test", "single_invalid")[0].question,
          name: "_dmarc.example.test",
          target_domain: "example.test",
        },
      },
    ],
    policy_source_domain: null,
    policy_source_kind: "none",
    declared_policy: null,
    effective_requested_policy: null,
    effective_policy_tag: null,
    inheritance_reason: "none",
  });
  const sourceMalformed = deriveDmarcPolicyTransitions(
    sourceBefore,
    sourceAfter,
  ).find((item) => item.subtype === "record_became_malformed");
  eq(
    "inherited-source malformed transition uses source DNS qname",
    sourceMalformed?.subject_key,
    "_dmarc.example.test",
  );
}

// Completeness, contradiction, applicability and honest-language guards.
{
  const incomplete = evidence({
    core_completeness: "unavailable",
    policy_completeness: "unavailable",
    monitoring_state: "monitoring_degraded",
    provider_state: "timeout",
    observation_state: "unavailable",
    record_validity: "indeterminate",
  });
  const current = absent({
    core_completeness: "complete",
    policy_completeness: "complete",
  });
  ok(
    "previous incomplete/current complete emits no false record removal",
    !subtypes(incomplete, current).includes("record_removed"),
  );
  ok(
    "previous incomplete/current complete emits no monitoring_recovered",
    !subtypes(incomplete, current).includes("monitoring_recovered"),
  );
  const degraded = evidence({
    core_completeness: "unavailable",
    policy_completeness: "unavailable",
    monitoring_state: "monitoring_degraded",
    provider_state: "timeout",
    observation_state: "unavailable",
    record_validity: "indeterminate",
  });
  const degradedTypes = subtypes(evidence(), degraded);
  ok(
    "current incomplete suppresses policy regression",
    !degradedTypes.includes("record_removed") &&
      !degradedTypes.includes("enforcement_weakened"),
  );
  ok(
    "current incomplete produces monitoring limitation",
    degradedTypes.includes("monitoring_degraded"),
  );
  const disagreement = evidence({
    corroboration_state: "resolver_disagreement",
    policy_completeness: "unavailable",
    observation_state: "resolver_disagreement",
  });
  ok(
    "decisive resolver disagreement suppresses risk transitions",
    !subtypes(evidence(), disagreement).some((type) =>
      ["record_removed", "enforcement_weakened"].includes(type)),
  );
  const nonApplicableSpBefore = inherited("none", {
    domain_existence: "nonexistent",
    effective_policy_tag: "np",
    inheritance_reason: "organisational_np",
    sp: { present: true, raw: "none", normalized: "none", valid: true },
  });
  const nonApplicableSpAfter = inherited("none", {
    domain_existence: "nonexistent",
    effective_policy_tag: "np",
    inheritance_reason: "organisational_np",
    sp: {
      present: true,
      raw: "reject",
      normalized: "reject",
      valid: true,
    },
  });
  ok(
    "non-applicable sp change emits no subdomain-policy transition",
    !subtypes(nonApplicableSpBefore, nonApplicableSpAfter)
      .includes("subdomain_policy_changed"),
  );
  ok(
    "applicable sp removal remains a subdomain-policy transition",
    subtypes(
      inherited("none", {
        effective_policy_tag: "sp",
        inheritance_reason: "organisational_sp",
        sp: { present: true, raw: "none", normalized: "none", valid: true },
      }),
      inherited("reject", {
        effective_policy_tag: "p",
        inheritance_reason: "organisational_p",
        sp: { present: false, raw: null, normalized: null, valid: true },
      }),
    ).includes("subdomain_policy_changed"),
  );
  const wording = deriveDmarcPolicyTransitions(
    evidence(),
    evidence({
      declared_policy: "none",
      effective_requested_policy: "none",
    }),
  ).find((event) => event.subtype === "enforcement_weakened")
    ?.customer_wording;
  ok(
    "strength wording says requested policy, not receiver enforcement",
    wording === "The requested DMARC policy became less restrictive.",
  );
  ok(
    "same-organisational-domain RUA is not mislabeled external",
    !subtypes(
      evidence(),
      rua(
        "mailto:agg@example.test",
        "not_required_same_organisational_domain",
      ),
    ).includes("external_rua_added"),
  );
  const caseSensitiveUris = deriveDmarcPolicyTransitions(
    rua("mailto:Reports@reports.vendor.test", "authorized"),
    rua("mailto:reports@reports.vendor.test", "authorized"),
  ).filter((event) =>
    ["external_rua_added", "external_rua_removed"].includes(event.subtype));
  eq(
    "normalised RUA identity preserves case-sensitive mailto local-part",
    caseSensitiveUris.length,
    2,
  );
  const unauthorized = deriveDmarcPolicyTransitions(
    rua("mailto:Reports@reports.vendor.test", "authorized"),
    rua("mailto:Reports@reports.vendor.test", "unauthorized"),
  ).find((event) => event.subtype === "external_rua_unauthorised");
  eq(
    "external authorisation event dedupes on normalised URI",
    unauthorized?.subject_key,
    "mailto:Reports@reports.vendor.test",
  );
  eq(
    "unauthorised-RUA stable condition retains RFC 9990 DNS name",
    unauthorized?.actionable_subject,
    "example.test._report._dmarc.reports.vendor.test",
  );
}

// ── Real D1/R2 snapshot and migration-088 lifecycle integration ────────────
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
    __args: args,
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
  ws = "ws1",
  user = "usr1",
  domainId = "dom1",
  domain = "example.test",
  deleted = false,
} = {}) {
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

function report(scanId, domainId, completedAt, sealed) {
  return {
    scan_id: scanId,
    domain_id: domainId,
    domain: "example.test",
    status: "completed",
    cyber_metrics_score: 70,
    risk_level: "medium",
    started_at: completedAt,
    completed_at: completedAt,
    scan_quality: { status: "complete", modules_skipped: [] },
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
};
seedTenant(db);
seedTenant(db, {
  ws: "ws2",
  user: "usr2",
  domainId: "dom2",
  domain: "example.test",
});
seedTenant(db, {
  ws: "ws-deleted",
  user: "usr-deleted",
  domainId: "dom-deleted",
  domain: "deleted.example.test",
  deleted: true,
});

async function buildObservedScan(scanId, completedAt, policyEvidence) {
  const sealed = await sealDmarcPolicyEvidence({
    ...policyEvidence,
    observed_at: completedAt,
  });
  db.prepare(
    `INSERT INTO scans
      (id, workspace_id, domain_id, domain, status, scan_quality, created_at)
     VALUES (?, 'ws1', 'dom1', 'example.test', 'completed', 'complete', ?)`,
  ).run(scanId, completedAt);
  const body = report(scanId, "dom1", completedAt, sealed);
  store.set(`reports/${scanId}.json`, JSON.stringify(body));
  await establishDmarcPolicyBaseline(env, {
    workspace_id: "ws1",
    domain_id: "dom1",
    domain: "example.test",
    scan_id: scanId,
    policy_evidence: sealed,
  });
  const built = await buildScanReportSnapshot(env, {
    workspaceId: "ws1",
    domainId: "dom1",
    scanId,
    domain: "example.test",
    report: body,
    cyberEssentials: null,
    assessedAt: completedAt,
  });
  return { sealed, built };
}

const first = await buildObservedScan("scan-before", T1, evidence());
const second = await buildObservedScan("scan-after", T2, evidence({
  declared_policy: "none",
  effective_requested_policy: "none",
  p: { present: true, raw: "none", normalized: "none", valid: true },
}));
eq("first canonical snapshot completed", first.built.status, "completed");
eq("second canonical snapshot completed", second.built.status, "completed");

const lifecycle = await recordDmarcPolicyLifecycle(env, {
  workspace_id: "ws1",
  domain_id: "dom1",
  domain: "example.test",
  scan_id: "scan-after",
});
ok("real snapshot-pair lifecycle comparison ran", lifecycle.ran);
ok("weakened pair appended deterministic lifecycle rows",
  lifecycle.inserted > 0);

const dmarcRows = db.prepare(
  `SELECT id, record_id, event_type, detail_json, created_at
   FROM email_protection_events
   WHERE workspace_id = 'ws1' AND record_type = ?
   ORDER BY rowid`,
).all(DMARC_POLICY_CONDITION_RECORD_TYPE);
const occurrenceRows = dmarcRows.filter((row) =>
  row.event_type === "monitoring_changed");
eq("one policy regression creates one actionable occurrence", occurrenceRows.length, 1);
eq("occurrence created_at is immutable current assessment time",
  occurrenceRows[0]?.created_at, T2);
ok("occurrence id is the full deterministic sha256 identity",
  /^epe-[a-f0-9]{64}$/.test(occurrenceRows[0]?.id || ""));
const occurrenceDetail = JSON.parse(occurrenceRows[0].detail_json);
eq("occurrence subtype is enforcement_weakened",
  occurrenceDetail.subtype, "enforcement_weakened");
eq("occurrence points to previous scan",
  occurrenceDetail.before_scan_id, "scan-before");
eq("occurrence points to current scan",
  occurrenceDetail.after_scan_id, "scan-after");
ok("occurrence points to immutable snapshots",
  occurrenceDetail.before_snapshot_id && occurrenceDetail.after_snapshot_id);
eq("before fingerprint reconciles exact sealed R2 evidence",
  occurrenceDetail.before_evidence_fingerprint,
  first.sealed.evidence_fingerprint);
eq("after fingerprint reconciles exact sealed R2 evidence",
  occurrenceDetail.after_evidence_fingerprint,
  second.sealed.evidence_fingerprint);
ok("event detail does not duplicate raw DNS RRsets",
  !Object.prototype.hasOwnProperty.call(occurrenceDetail, "raw_records") &&
  !JSON.stringify(occurrenceDetail).includes("v=DMARC1"));

const occurrence = await findConditionOccurrence(env, {
  workspace_id: "ws1",
  domain_key: "email_protection",
  record_id: occurrenceRows[0].record_id,
  recurrence_type: "enforcement_weakened",
});
eq("existing Email Protection occurrence resolver finds P4 row",
  occurrence?.occurrence_id, occurrenceRows[0].id);

const beforeReplay = dmarcRows.length;
const replay = await recordDmarcPolicyLifecycle(env, {
  workspace_id: "ws1",
  domain_id: "dom1",
  domain: "example.test",
  scan_id: "scan-after",
});
eq("replay inserts zero rows", replay.inserted, 0);
eq("replay leaves one occurrence",
  db.prepare(
    `SELECT COUNT(*) AS n FROM email_protection_events
     WHERE workspace_id = 'ws1' AND record_type = ?
       AND event_type = 'monitoring_changed'`,
  ).get(DMARC_POLICY_CONDITION_RECORD_TYPE).n, 1);
eq("replay leaves row count unchanged",
  db.prepare(
    `SELECT COUNT(*) AS n FROM email_protection_events
     WHERE workspace_id = 'ws1' AND record_type = ?`,
  ).get(DMARC_POLICY_CONDITION_RECORD_TYPE).n, beforeReplay);

const timeline = await listEmailProtectionEvents(env, "ws1", {
  record_type: DMARC_POLICY_CONDITION_RECORD_TYPE,
  limit: 100,
});
eq("DMARC timeline is now readable", timeline.length, beforeReplay);
const weakenedApi = timeline.find((item) =>
  item.subtype === "enforcement_weakened");
const baselineApi = timeline.find((item) =>
  item.subtype === "baseline_established");
eq("customer-visible DMARC baseline carries its minimum Evidence Grade",
  baselineApi?.evidence_grade?.minimum_publishable, "L2");
eq("timeline uses requested-policy wording",
  weakenedApi?.summary,
  "The requested DMARC policy became less restrictive.");
ok("timeline exposes immutable pointers, not raw DNS",
  weakenedApi?.evidence?.before_snapshot_id &&
  weakenedApi?.evidence?.after_snapshot_id &&
  !Object.prototype.hasOwnProperty.call(weakenedApi, "raw_records"));
eq("policy-change timeline assertion carries minimum Evidence Grade",
  weakenedApi?.evidence_grade?.minimum_publishable, "L3");
eq("policy-change timeline Evidence Grade states actual grade",
  weakenedApi?.evidence_grade?.grade, "L3");
eq("policy-change timeline Evidence Grade remains non-repeat-confirmed",
  weakenedApi?.evidence_grade?.repeat_confirmed, false);
ok("policy-change grade limits deny receiver-enforcement proof",
  weakenedApi?.evidence_grade?.limits?.some((limit) =>
    limit.includes("does not prove receiver enforcement")));
eq("timeline count matches tenant-scoped list",
  await countEmailProtectionEvents(env, "ws1", {
    record_type: DMARC_POLICY_CONDITION_RECORD_TYPE,
  }), beforeReplay);
eq("same-hostname second tenant sees no lifecycle rows",
  await countEmailProtectionEvents(env, "ws2", {
    record_type: DMARC_POLICY_CONDITION_RECORD_TYPE,
  }), 0);

const deletedAttempt = await recordDmarcPolicyLifecycle(env, {
  workspace_id: "ws-deleted",
  domain_id: "dom-deleted",
  domain: "deleted.example.test",
  scan_id: "scan-never",
});
eq("soft-deleted workspace is rejected",
  deletedAttempt.reason, "workspace_or_domain_inactive");

// Baseline is first-complete only: the weakening condition did not receive a
// new baseline row that would hide its occurrence.
const weakCondition = deriveDmarcPolicyConditions(second.sealed)
  .find((condition) => condition.condition_type === "weak");
const weakRecordId = await dmarcPolicyConditionRecordId({
  domain_id: "dom1",
  condition_type: "weak",
  subject_key: weakCondition.subject_key,
});
eq("later weak condition has no false baseline event",
  db.prepare(
    `SELECT COUNT(*) AS n FROM email_protection_events
     WHERE workspace_id = 'ws1' AND record_id = ?
       AND event_type = 'baseline_established'`,
  ).get(weakRecordId).n, 0);

const third = await buildObservedScan("scan-resolved", T3, evidence());
await recordDmarcPolicyLifecycle(env, {
  workspace_id: "ws1",
  domain_id: "dom1",
  domain: "example.test",
  scan_id: "scan-resolved",
});
eq("resolved condition is non-occurrence history",
  db.prepare(
    `SELECT COUNT(*) AS n FROM email_protection_events
     WHERE workspace_id = 'ws1' AND record_id = ?
       AND event_type = 'condition_no_longer_observed'`,
  ).get(weakRecordId).n, 1);
eq("resolution does not create a second actionable occurrence",
  db.prepare(
    `SELECT COUNT(*) AS n FROM email_protection_events
     WHERE workspace_id = 'ws1' AND record_id = ?
       AND event_type = 'monitoring_changed'`,
  ).get(weakRecordId).n, 1);

const fourth = await buildObservedScan("scan-recurred", T4, evidence({
  declared_policy: "none",
  effective_requested_policy: "none",
  p: { present: true, raw: "none", normalized: "none", valid: true },
}));
await recordDmarcPolicyLifecycle(env, {
  workspace_id: "ws1",
  domain_id: "dom1",
  domain: "example.test",
  scan_id: "scan-recurred",
});
const recurrentRows = db.prepare(
  `SELECT id, record_id FROM email_protection_events
   WHERE workspace_id = 'ws1' AND record_id = ?
     AND event_type = 'monitoring_changed'
   ORDER BY rowid`,
).all(weakRecordId);
eq("resolved condition recurrence appends a new occurrence",
  recurrentRows.length, 2);
eq("recurrence retains stable condition record identity",
  new Set(recurrentRows.map((row) => row.record_id)).size, 1);
eq("recurrence receives a new append-only occurrence identity",
  new Set(recurrentRows.map((row) => row.id)).size, 2);
ok("recurrence snapshot fingerprint differs from first occurrence",
  third.sealed.evidence_fingerprint !==
    fourth.sealed.evidence_fingerprint);

await buildObservedScan("scan-incomplete", T5, evidence({
  observation_state: "unavailable",
  record_validity: "indeterminate",
  raw_records: null,
  parsed_tags: null,
  lookup_path: [],
  tree_walk: {
    planned_questions: [],
    stop_reason: "required_lookup_unavailable",
    complete: false,
  },
  organisational_domain: null,
  organisational_domain_provenance: "unresolved",
  organisational_domain_completeness: "unavailable",
  policy_source_domain: null,
  policy_source_kind: "unknown",
  domain_existence: "unknown",
  existence_completeness: "unavailable",
  declared_policy: null,
  effective_requested_policy: null,
  testing_adjustment: "unknown",
  effective_policy_tag: null,
  inheritance_reason: "unknown",
  p: null,
  sp: null,
  np: null,
  t: null,
  psd: null,
  rua_destinations: null,
  ruf_destinations: null,
  policy_completeness: "unavailable",
  corroboration_state: "unavailable",
  rua_authorisation_completeness: "incomplete",
  external_rua_authorisation: {
    rua_authorisation_completeness: "incomplete",
    destinations: null,
  },
  monitoring_state: "monitoring_degraded",
  provider_state: "timeout",
  core_completeness: "unavailable",
  outcome: "unavailable",
}));
await recordDmarcPolicyLifecycle(env, {
  workspace_id: "ws1",
  domain_id: "dom1",
  domain: "example.test",
  scan_id: "scan-incomplete",
});
eq("complete-to-incomplete appends monitoring limitation history",
  db.prepare(
    `SELECT COUNT(*) AS n FROM email_protection_events
     WHERE workspace_id = 'ws1'
       AND event_type = 'dmarc_monitoring_degraded'`,
  ).get().n, 1);
eq("complete-to-incomplete creates no false policy occurrence",
  db.prepare(
    `SELECT COUNT(*) AS n FROM email_protection_events
     WHERE workspace_id = 'ws1' AND record_id = ?
       AND event_type = 'monitoring_changed'`,
  ).get(weakRecordId).n, 2);

await buildObservedScan("scan-complete-again", T6, evidence({
  declared_policy: "none",
  effective_requested_policy: "none",
  p: { present: true, raw: "none", normalized: "none", valid: true },
}));
await recordDmarcPolicyLifecycle(env, {
  workspace_id: "ws1",
  domain_id: "dom1",
  domain: "example.test",
  scan_id: "scan-complete-again",
});
eq("incomplete-to-complete emits no monitoring_recovered",
  db.prepare(
    `SELECT COUNT(*) AS n FROM email_protection_events
     WHERE detail_json LIKE '%monitoring_recovered%'`,
  ).get().n, 0);
eq("incomplete predecessor cannot prove a new recurrence",
  db.prepare(
    `SELECT COUNT(*) AS n FROM email_protection_events
     WHERE workspace_id = 'ws1' AND record_id = ?
       AND event_type = 'monitoring_changed'`,
  ).get(weakRecordId).n, 2);

// Related Changes: canonical DMARC remains email_config; two DMARC rows alone
// cannot corroborate each other. Add one independent certificate event and the
// existing rule may correlate without changing the registrable-root key.
db.prepare(
  `INSERT INTO asset_events
    (id, workspace_id, domain_id, scan_id, event_type, hostname,
     severity, description, created_at)
   VALUES ('legacy-dmarc-p4', 'ws1', 'dom1', 'scan-after',
     'email_dmarc_policy_changed', 'example.test', 'medium', '', ?)`,
).run(T2);
const collectedBeforeIndependent = await collectChangeEvents(env, {
  workspaceId: "ws1",
  windowStart: T1,
  windowEnd: T2,
});
const dmarcCanonical = collectedBeforeIndependent.filter((item) =>
  item.source_table === "email_protection_events");
ok("eligible complete DMARC subtype enters existing adapter",
  dmarcCanonical.some((item) =>
    item.event_type === "dmarc_enforcement_weakened"));
ok("DMARC event stays in existing email_config family",
  dmarcCanonical.every((item) =>
    item.producer_family === SIGNAL_FAMILY.EMAIL_CONFIG));
ok("canonical event suppresses the bounded legacy coarse duplicate",
  !collectedBeforeIndependent.some((item) =>
    item.source_record_id === "legacy-dmarc-p4"));
eq("DMARC-only family cannot form a Related Changes cluster",
  correlateChangeEvents(dmarcCanonical).length, 0);

db.prepare(
  `INSERT INTO asset_events
    (id, workspace_id, domain_id, scan_id, event_type, hostname,
     severity, description, created_at)
   VALUES ('cert-p4', 'ws1', 'dom1', 'scan-after',
     'certificate_new_detected', 'mail.example.test', 'info', '', ?)`,
).run(T2);
const relatedRun = await correlateRelatedChanges(env, {
  workspaceId: "ws1",
  domainId: "dom1",
  scanId: "scan-after",
  scanQuality: "complete",
  assessedAt: T2,
});
ok("DMARC plus independent certificate family correlates",
  relatedRun.ran && relatedRun.clusters > 0);
const clusters = await listRelatedChanges(env, "ws1", {});
const dmarcCluster = clusters.find((row) =>
  row.rule_id === "email_config_with_host_or_cert");
ok("existing email-config rule produced a cluster", !!dmarcCluster);
eq("RFC organisational domain did not replace registrable-root key",
  dmarcCluster?.registrable_domain, "example.test");
const relatedDetail = await getRelatedChange(env, "ws1", dmarcCluster.id);
ok("Related Changes stores a snapshot pointer, not DNS payload",
  relatedDetail.evidence.some((item) =>
    item.source_table === "email_protection_events" &&
    String(item.evidence_ref).includes("#protocol_evidence.dmarc")));
const noCase = await createCaseFromRelatedChange(
  env,
  "ws1",
  dmarcCluster.id,
  { userId: "usr1" },
);
eq("P4 DMARC Related Change cannot create a managed case",
  noCase.code, "dmarc_case_deferred");
eq("approved Related Changes causality notice is exact",
  RELATED_CHANGES_CAUSALITY_NOTICE,
  "These changes were observed close together and may be related. CyberMeters has not established that one caused the other or that they indicate compromise.");

// No customer alert, case, or migration is activated by this validator.
eq("P4 created no managed case",
  db.prepare("SELECT COUNT(*) AS n FROM managed_cases").get().n, 0);
eq("P4 created no managed alert",
  db.prepare("SELECT COUNT(*) AS n FROM notification_events").get().n, 0);

console.log(`\nDMARCbis P4: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
console.log("DMARCbis P4 validation passed");
