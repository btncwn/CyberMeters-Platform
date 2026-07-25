#!/usr/bin/env node
// Item 7 P3 — immutable snapshot and additive API dual-reader contract.
//
// Exercises the real snapshot writer/reader, scan and Email Protection routes,
// tenant-scoped latest-domain reader, lifecycle fingerprint reconciliation, and
// old/new immutable R2 artifacts. No network is permitted.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = (...parts) =>
  path.join(root, "workers", "scan-api", "src", ...parts);
const importEngine = (name) =>
  import(pathToFileURL(src("engines", name)).href);

globalThis.fetch = async () => {
  throw new Error("network disabled in DMARCbis P3 validator");
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
  ok(name, got === want, `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (file) => {
    try {
      db.exec(fs.readFileSync(file, "utf8"));
    } catch {
      // schema.sql and additive migrations deliberately overlap.
    }
  };
  apply(path.join(root, "database", "schema.sql"));
  for (const file of fs.readdirSync(path.join(root, "database", "migrations"))
    .filter((name) => name.endsWith(".sql"))
    .sort()) {
    apply(path.join(root, "database", "migrations", file));
  }
  return db;
}

function makeD1(db) {
  const statement = (sql, args = []) => ({
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
        /^\s*select/i.test(entry.__sql || "") ? entry.all() : entry.run())),
    exec: async (sql) => {
      db.exec(sql);
      return { count: 0, duration: 0 };
    },
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

const {
  DMARCBIS_HISTORICAL_METHODOLOGY_NOTICE,
  DMARCBIS_POLICY_EVIDENCE_SCHEMA,
  dmarcPolicyApiProjection,
  dmarcPolicyEvidenceFingerprint,
  readDmarcPolicyEvidenceFromSnapshot,
  sealDmarcPolicyEvidence,
} = await importEngine("dmarcbis-contract.js");
const {
  SNAPSHOT_BUILDER_VERSION,
  SNAPSHOT_SCHEMA_VERSION,
  buildScanReportSnapshot,
  readLatestDomainDmarcPolicyEvidence,
  readScanReportSnapshot,
  snapshotSha256Hex,
} = await importEngine("report-snapshot.js");
const { establishDmarcPolicyBaseline } =
  await importEngine("email-protection-lifecycle.js");
const { unavailableDmarcbisCore } =
  await importEngine("dmarcbis-production.js");
const { scanRoutes } =
  await import(pathToFileURL(src("routes", "scans.js")).href);
const { emailProtectionRoutes } =
  await import(pathToFileURL(src("routes", "email-protection.js")).href);
const { DMARCBIS_IDNA_PROFILE } = await importEngine("dmarcbis-idna.js");
const { DMARCBIS_PARSER_VERSION } = await importEngine("dmarcbis-parser.js");
const { DMARCBIS_METHODOLOGY_VERSION } =
  await importEngine("dmarcbis-resolver.js");

function evidence(overrides = {}) {
  return {
    schema: DMARCBIS_POLICY_EVIDENCE_SCHEMA,
    methodology_version: DMARCBIS_METHODOLOGY_VERSION,
    parser_version: DMARCBIS_PARSER_VERSION,
    resolver_profile: "primary-plus-decisive-corroboration-v1",
    idna_profile: DMARCBIS_IDNA_PROFILE,
    author_domain: "shared.example",
    submitted_domain: "shared.example",
    observed_at: "2026-07-25T12:00:00.000Z",
    observation_state: "present_valid",
    record_validity: "valid",
    raw_records: [{ raw: "v=DMARC1; p=reject; t=y; pct=25" }],
    parsed_tags: [
      { name: "p", raw_value: "reject", normalized: "reject" },
      { name: "t", raw_value: "y", normalized: "y" },
      { name: "pct", raw_value: "25", normalized: null },
    ],
    lookup_path: [{
      question: { name: "_dmarc.shared.example", type: "TXT" },
      outcome: "success",
      resolver: "primary",
    }],
    tree_walk: { planned_questions: [], stop_reason: "psd_n", complete: true },
    organisational_domain: "shared.example",
    organisational_domain_provenance: "psd_n",
    organisational_domain_completeness: "complete",
    policy_source_domain: "shared.example",
    policy_source_kind: "exact",
    source_record: { raw: "v=DMARC1; p=reject; t=y; pct=25" },
    domain_existence: "not_required",
    existence_completeness: "not_applicable",
    declared_policy: "reject",
    effective_requested_policy: "quarantine",
    testing_adjustment: "one_level_below",
    effective_policy_tag: "p",
    inheritance_reason: "exact_p",
    p: { present: true, raw: "reject", normalized: "reject", valid: true },
    sp: { present: false, raw: null, normalized: null, valid: true },
    np: { present: false, raw: null, normalized: null, valid: true },
    t: { present: true, raw: "y", normalized: "y", valid: true },
    psd: { present: false, raw: null, normalized: null, valid: true },
    legacy_pct: {
      observed: true,
      raw: "25",
      numeric: 25,
      semantics: "rfc7489_legacy",
      applied_to_effective_policy: false,
    },
    rua_destinations: [{
      raw: "mailto:agg@reports.vendor.test",
      scheme: "mailto",
      destination_host: "reports.vendor.test",
    }],
    ruf_destinations: [],
    policy_completeness: "complete",
    corroboration_state: "corroborated",
    rua_authorisation_completeness: "incomplete",
    external_rua_authorisation: {
      rua_authorisation_completeness: "incomplete",
      assessment_reason: "subrequest_budget",
      destinations: [{
        uri: "mailto:agg@reports.vendor.test",
        authorization_status: "not_assessed_budget",
        lookup_completeness: "incomplete",
      }],
    },
    monitoring_state: "monitoring_degraded",
    provider_state: "available",
    receiver_enforcement_observed: false,
    core_completeness: "complete",
    outcome: "degraded",
    evidence_grade: {
      observable_ceiling: "L5",
      beta_target: "L4",
      minimum_publishable: "L3",
      degrade_behavior: "Incomplete evidence withholds the conclusion.",
      required_corroboration: ["decisive resolver"],
      grade: "L3",
      source_type: "normative_protocol",
      basis: "RFC 9989 DNS policy discovery.",
      limits: ["Receiver enforcement is not observed."],
      repeat_confirmed: false,
    },
    limits: { maximum_logical_questions: 10 },
    ...overrides,
  };
}

function report(scanId, domainId, policyEvidence, legacyDmarc, completedAt) {
  return {
    scan_id: scanId,
    domain_id: domainId,
    domain: "shared.example",
    status: "completed",
    cyber_metrics_score: 75,
    risk_level: "low",
    started_at: "2026-07-25T11:59:00.000Z",
    completed_at: completedAt,
    findings: [],
    recommendations: [],
    scan_quality: { status: "complete", modules_skipped: [], warnings: [] },
    monitoring_states: {
      version: "signal-monitoring-state-v1",
      signals: {},
    },
    modules: {
      dns: { has_mx: true },
      ssl: {},
      headers: {},
      email_security: {
        spf: { present: true },
        dmarc: legacyDmarc,
        dkim: {},
      },
      dmarc_core: policyEvidence,
      subdomains: { count: 0, items: [] },
      certificate_intelligence: { total_certificates: 0 },
      brand_monitoring: { candidates: [] },
      identity_discovery: { high_risk_count: 0 },
      technology_detection: { count: 0 },
      saas_exposure: { count: 0 },
      third_party_assets: { count: 0 },
      vendor_relationships: { high_confidence: 0 },
      whois_intelligence: {},
    },
  };
}

const db = buildDb();
const store = new Map();
const env = {
  cybermeters_db: makeD1(db),
  cybermeters_reports: makeR2(store),
  RESEND_API_KEY: "",
  APP_VERSION: "test",
};

function seedWorkspace(id, domainId, { deleted = false } = {}) {
  const userId = `user-${id}`;
  db.prepare(
    `INSERT INTO users
       (id, email, password_hash, name, plan, status, email_verified, mfa_enabled)
     VALUES (?, ?, 'x', ?, 'free', 'active', 1, 0)`
  ).run(userId, `${id}@example.test`, id);
  db.prepare(
    `INSERT INTO workspaces (id, owner_user_id, name, deleted_at)
     VALUES (?, ?, ?, ?)`
  ).run(id, userId, id, deleted ? "2026-07-25T00:00:00.000Z" : null);
  db.prepare(
    `INSERT INTO domains (id, user_id, domain)
     VALUES (?, ?, 'shared.example')`
  ).run(domainId, userId);
  db.prepare(
    `INSERT INTO workspace_domains (workspace_id, domain_id)
     VALUES (?, ?)`
  ).run(id, domainId);
}

function seedScan(id, workspaceId, domainId, createdAt) {
  db.prepare(
    `INSERT INTO scans
       (id, workspace_id, domain_id, domain, score, rating, status, scan_quality, created_at)
     VALUES (?, ?, ?, 'shared.example', 75, 'low', 'completed', 'complete', ?)`
  ).run(id, workspaceId, domainId, createdAt);
}

seedWorkspace("ws1", "dom1");
seedWorkspace("ws2", "dom2");
seedWorkspace("ws-dead", "dom-dead", { deleted: true });

async function buildFixture({
  scanId,
  workspaceId,
  domainId,
  policyEvidence,
  legacyDmarc,
  completedAt,
}) {
  seedScan(scanId, workspaceId, domainId, completedAt);
  const sealed = await sealDmarcPolicyEvidence(policyEvidence);
  const rawReport = report(
    scanId,
    domainId,
    sealed,
    legacyDmarc,
    completedAt,
  );
  store.set(`reports/${scanId}.json`, JSON.stringify(rawReport));
  const result = await buildScanReportSnapshot(env, {
    workspaceId,
    domainId,
    scanId,
    domain: "shared.example",
    report: rawReport,
    cyberEssentials: null,
    assessedAt: completedAt,
  });
  const row = db.prepare(
    `SELECT * FROM scan_report_snapshots
     WHERE workspace_id = ? AND scan_id = ? AND status = 'completed'`
  ).get(workspaceId, scanId);
  const snapshotRaw = row ? store.get(row.r2_key) : null;
  return {
    result,
    row,
    rawReport,
    snapshotRaw,
    snapshot: snapshotRaw ? JSON.parse(snapshotRaw) : null,
    sealed,
  };
}

const exact = await buildFixture({
  scanId: "scan-exact",
  workspaceId: "ws1",
  domainId: "dom1",
  policyEvidence: evidence(),
  legacyDmarc: {
    present: true,
    valid: true,
    policy: "reject",
    sp: null,
    pct: 25,
    record: "v=DMARC1; p=reject; t=y; pct=25",
  },
  completedAt: "2026-07-25T12:05:00.000Z",
});

eq("new snapshot build completes", exact.result.status, "completed");
eq("outer snapshot schema remains v1",
  exact.snapshot?.snapshot?.snapshot_schema_version, SNAPSHOT_SCHEMA_VERSION);
eq("nested schema is dmarc-policy.v2",
  exact.snapshot?.protocol_evidence?.dmarc?.schema,
  DMARCBIS_POLICY_EVIDENCE_SCHEMA);
eq("methodology is rfc9989-treewalk-v1",
  exact.snapshot?.protocol_evidence?.dmarc?.methodology_version,
  "rfc9989-treewalk-v1");
eq("snapshot builder version is incremented additively",
  exact.snapshot?.methodology?.snapshot_builder_version,
  SNAPSHOT_BUILDER_VERSION);
eq("raw report and snapshot carry one byte-stable protocol object",
  JSON.stringify(exact.rawReport.modules.dmarc_core),
  JSON.stringify(exact.snapshot.protocol_evidence.dmarc));
eq("nested fingerprint verifies",
  await dmarcPolicyEvidenceFingerprint(
    exact.snapshot.protocol_evidence.dmarc,
  ),
  exact.snapshot.protocol_evidence.dmarc.evidence_fingerprint);
eq("D1 checksum reconciles the exact snapshot R2 bytes",
  exact.row?.checksum_sha256,
  await snapshotSha256Hex(exact.snapshotRaw));
eq("legacy pct remains raw",
  exact.snapshot.protocol_evidence.dmarc.legacy_pct.raw, "25");
eq("legacy pct remains non-operative",
  exact.snapshot.protocol_evidence.dmarc
    .legacy_pct.applied_to_effective_policy, false);
eq("external RUA remains explicitly incomplete",
  exact.snapshot.protocol_evidence.dmarc
    .rua_authorisation_completeness, "incomplete");
ok("external RUA incomplete never claims all authorised",
  exact.snapshot.protocol_evidence.dmarc
    .external_rua_authorisation?.destinations?.every(
      (destination) => destination.authorization_status !== "authorized",
    ));

const exactRead = await readScanReportSnapshot(env, "scan-exact", {
  repair: false,
  includeSuccessor: false,
});
eq("new snapshot dual reader selects current v2",
  exactRead.dmarcPolicy?.status, "current");
eq("new reader exposes the sealed block without recomputation",
  JSON.stringify(exactRead.dmarcPolicy?.evidence),
  JSON.stringify(exact.snapshot.protocol_evidence.dmarc));

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

async function callScan(pathname) {
  const request = new Request(`https://api.example.test${pathname}`);
  const response = await scanRoutes({
    request,
    env,
    ctx: { waitUntil() {} },
    url: new URL(request.url),
    json: jsonResponse,
    serverError: (_scope, error) =>
      jsonResponse({ error: String(error?.message || error) }, 500),
    corsHeaders: {},
    requireAuth: async () => ({ id: "user-ws1" }),
    requireWorkspaceRole: async () => true,
    consumeApiRateLimit: async () => null,
    requireScanReadAccess: async () => true,
    getAccessibleWorkspaceIds: async () => ["ws1", "ws2"],
    computeNextRunAt: () => null,
  });
  return {
    status: response.status,
    body: await response.json(),
  };
}

const exactReportApi = await callScan("/api/scans/scan-exact/report");
eq("report API exposes additive dmarc_policy_evidence",
  exactReportApi.body?.dmarc_policy_evidence?.schema,
  DMARCBIS_POLICY_EVIDENCE_SCHEMA);
eq("testing adjustment remains in the new field",
  exactReportApi.body?.dmarc_policy_evidence
    ?.effective_requested_policy, "quarantine");
eq("testing adjustment never contaminates legacy exact policy",
  exactReportApi.body?.modules?.email_security?.dmarc?.policy, "reject");
eq("legacy pct API value remains raw-era numeric evidence",
  exactReportApi.body?.modules?.email_security?.dmarc?.pct, 25);

const inherited = await buildFixture({
  scanId: "scan-inherited",
  workspaceId: "ws2",
  domainId: "dom2",
  policyEvidence: evidence({
    policy_source_domain: "shared.example",
    policy_source_kind: "organisational",
    declared_policy: "reject",
    effective_requested_policy: "reject",
    effective_policy_tag: "sp",
    inheritance_reason: "organisational_sp",
    t: { present: false, raw: null, normalized: "n", valid: true },
    legacy_pct: {
      observed: false,
      raw: null,
      numeric: null,
      semantics: "rfc7489_legacy",
      applied_to_effective_policy: false,
    },
    rua_destinations: [],
    rua_authorisation_completeness: "not_applicable",
    external_rua_authorisation: null,
    monitoring_state: "monitoring_healthy",
    outcome: "available",
  }),
  legacyDmarc: {
    present: false,
    valid: null,
    policy: null,
    sp: null,
    pct: null,
    record: null,
  },
  completedAt: "2026-07-25T12:06:00.000Z",
});
const inheritedReportApi =
  await callScan("/api/scans/scan-inherited/report");
eq("inherited requested policy is available only in the new object",
  inheritedReportApi.body?.dmarc_policy_evidence
    ?.effective_requested_policy, "reject");
eq("inherited policy never populates legacy policy",
  inheritedReportApi.body?.modules?.email_security?.dmarc?.policy, null);
eq("inherited policy never populates legacy sp",
  inheritedReportApi.body?.modules?.email_security?.dmarc?.sp, null);
eq("inherited policy never populates legacy pct",
  inheritedReportApi.body?.modules?.email_security?.dmarc?.pct, null);

// A historical outer-v1 snapshot has no nested block. The reader adds notice
// metadata to the response but never changes its immutable bytes.
seedScan("scan-legacy", "ws1", "dom1", "2026-07-01T10:00:00.000Z");
const legacySnapshot = {
  snapshot: {
    snapshot_id: "snap-legacy",
    snapshot_schema_version: "1",
    workspace_id: "ws1",
    domain_id: "dom1",
    scan_id: "scan-legacy",
  },
  legacy_marker: "bytes-must-not-change",
};
const legacyRaw = JSON.stringify(legacySnapshot, null, 2);
const legacyKey =
  "reports/snapshots/ws1/scan-legacy/snap-legacy.json";
store.set(legacyKey, legacyRaw);
db.prepare(
  `INSERT INTO scan_report_snapshots
     (id, workspace_id, domain_id, scan_id, status, r2_key,
      checksum_sha256, snapshot_schema_version, resolver_version, assessed_at)
   VALUES (?, ?, ?, ?, 'completed', ?, ?, '1', 'legacy', ?)`
).run(
  "snap-legacy",
  "ws1",
  "dom1",
  "scan-legacy",
  legacyKey,
  await snapshotSha256Hex(legacyRaw),
  "2026-07-01T10:00:00.000Z",
);
const legacyBefore = store.get(legacyKey);
const legacyRead = await readScanReportSnapshot(env, "scan-legacy", {
  repair: false,
  includeSuccessor: false,
});
eq("old snapshot remains readable", legacyRead.status, "ok");
eq("missing nested block is an explicit legacy state",
  legacyRead.dmarcPolicy?.status, "legacy_snapshot");
eq("legacy reader returns the approved methodology notice",
  legacyRead.dmarcPolicy?.notice,
  DMARCBIS_HISTORICAL_METHODOLOGY_NOTICE);
eq("old snapshot bytes remain byte-for-byte unchanged",
  store.get(legacyKey), legacyBefore);
const legacyApi = await callScan("/api/scans/scan-legacy/snapshot");
eq("historical API returns the renderer-owned notice",
  legacyApi.body?.dmarc_methodology_notice,
  DMARCBIS_HISTORICAL_METHODOLOGY_NOTICE);
ok("historical API does not invent a v2 evidence object",
  !Object.prototype.hasOwnProperty.call(
    legacyApi.body || {},
    "dmarc_policy_evidence",
  ));
eq("historical API serves the original snapshot object",
  JSON.stringify(legacyApi.body?.snapshot),
  JSON.stringify(legacySnapshot));
eq("historical read performs no R2 rewrite",
  store.get(legacyKey), legacyBefore);

const unavailable = await sealDmarcPolicyEvidence(evidence({
  observation_state: "unavailable",
  record_validity: "indeterminate",
  raw_records: null,
  parsed_tags: null,
  lookup_path: [],
  organisational_domain: null,
  organisational_domain_provenance: "unresolved",
  organisational_domain_completeness: "unavailable",
  policy_source_domain: null,
  policy_source_kind: "unknown",
  declared_policy: null,
  effective_requested_policy: null,
  effective_policy_tag: null,
  inheritance_reason: "unknown",
  domain_existence: "unknown",
  existence_completeness: "unavailable",
  p: null,
  sp: null,
  np: null,
  t: null,
  psd: null,
  rua_destinations: null,
  ruf_destinations: null,
  policy_completeness: "unavailable",
  rua_authorisation_completeness: "incomplete",
  external_rua_authorisation: null,
  core_completeness: "unavailable",
  monitoring_state: "monitoring_degraded",
  provider_state: "provider_timeout",
  outcome: "unavailable",
}));
const unavailableRead = await readDmarcPolicyEvidenceFromSnapshot({
  protocol_evidence: { dmarc: unavailable },
});
eq("structured unavailable block remains current evidence",
  unavailableRead.status, "current");
eq("unavailable block never fabricates policy",
  unavailableRead.evidence?.effective_requested_policy, null);
eq("unavailable block never turns records into an empty-success",
  unavailableRead.evidence?.raw_records, null);
const productionUnavailable = await sealDmarcPolicyEvidence(
  unavailableDmarcbisCore(
    "shared.example",
    "provider_timeout",
    "2026-07-25T12:00:00.000Z",
  ),
);
eq("real P2 unavailable fallback seals without invented policy",
  productionUnavailable.effective_requested_policy, null);
eq("real P2 unavailable fallback receives fixed parser metadata",
  productionUnavailable.parser_version, DMARCBIS_PARSER_VERSION);
ok("real P2 unavailable fallback receives a verifiable fingerprint",
  productionUnavailable.evidence_fingerprint ===
    await dmarcPolicyEvidenceFingerprint(productionUnavailable));

const unknownSchema = await readDmarcPolicyEvidenceFromSnapshot({
  protocol_evidence: { dmarc: { ...exact.sealed, schema: "dmarc-policy.v999" } },
});
eq("unknown nested schema fails closed", unknownSchema.status, "unsupported_schema");
ok("unknown nested schema exposes no policy evidence",
  unknownSchema.evidence == null);
const unknownEnum = await readDmarcPolicyEvidenceFromSnapshot({
  protocol_evidence: {
    dmarc: {
      ...exact.sealed,
      organisational_domain_provenance: "future_guess",
    },
  },
});
eq("unknown nested enum fails closed", unknownEnum.status, "invalid_contract");
ok("unknown nested enum exposes no policy evidence",
  unknownEnum.evidence == null);
const badFingerprint = await readDmarcPolicyEvidenceFromSnapshot({
  protocol_evidence: {
    dmarc: {
      ...exact.sealed,
      effective_requested_policy: "none",
    },
  },
});
eq("fingerprint mismatch fails closed",
  badFingerprint.status, "integrity_error");
ok("fingerprint mismatch exposes no policy evidence",
  badFingerprint.evidence == null);

const latestWs1 =
  await readLatestDomainDmarcPolicyEvidence(env, "ws1", "dom1");
const latestWs2 =
  await readLatestDomainDmarcPolicyEvidence(env, "ws2", "dom2");
eq("tenant-scoped latest reader returns ws1 testing policy",
  latestWs1.evidence?.effective_requested_policy, "quarantine");
eq("same hostname in ws2 returns only ws2 inherited policy",
  latestWs2.evidence?.inheritance_reason, "organisational_sp");
ok("same-hostname tenant fingerprints remain distinct",
  latestWs1.evidence?.evidence_fingerprint !==
    latestWs2.evidence?.evidence_fingerprint);

// Even if a stale completed pointer exists for a soft-deleted workspace, the
// active-workspace join prevents a read.
seedScan(
  "scan-dead",
  "ws-dead",
  "dom-dead",
  "2026-07-25T12:07:00.000Z",
);
const deadKey =
  "reports/snapshots/ws-dead/scan-dead/snap-dead.json";
store.set(deadKey, exact.snapshotRaw);
db.prepare(
  `INSERT INTO scan_report_snapshots
     (id, workspace_id, domain_id, scan_id, status, r2_key,
      checksum_sha256, snapshot_schema_version, resolver_version, assessed_at)
   VALUES ('snap-dead', 'ws-dead', 'dom-dead', 'scan-dead', 'completed',
           ?, ?, '1', 'test', '2026-07-25T12:07:00.000Z')`
).run(deadKey, await snapshotSha256Hex(exact.snapshotRaw));
const deadRead = await readLatestDomainDmarcPolicyEvidence(
  env,
  "ws-dead",
  "dom-dead",
);
eq("soft-deleted workspace receives no latest policy read",
  deadRead.status, "not_available");

async function callEmail(pathname, workspaceAllowed = true) {
  const request = new Request(`https://api.example.test${pathname}`);
  const response = await emailProtectionRoutes({
    request,
    env,
    url: new URL(request.url),
    json: jsonResponse,
    serverError: (_scope, error) =>
      jsonResponse({ error: String(error?.message || error) }, 500),
    requireAuth: async () => ({ id: "user-ws1" }),
    requireWorkspaceRole: async () => workspaceAllowed,
  });
  return {
    status: response.status,
    body: await response.json(),
  };
}

const summaryWs1 = await callEmail(
  "/api/workspaces/ws1/domains/shared.example/dmarc-summary",
);
eq("Email Protection technical response exposes v2 evidence",
  summaryWs1.body?.dmarc_policy_evidence?.schema,
  DMARCBIS_POLICY_EVIDENCE_SCHEMA);
eq("Email Protection response uses its tenant snapshot",
  summaryWs1.body?.dmarc_policy_evidence?.evidence_fingerprint,
  latestWs1.evidence?.evidence_fingerprint);
const summaryWs2 = await callEmail(
  "/api/workspaces/ws2/domains/shared.example/dmarc-summary",
);
eq("Email Protection same-hostname read stays in ws2",
  summaryWs2.body?.dmarc_policy_evidence?.evidence_fingerprint,
  latestWs2.evidence?.evidence_fingerprint);
const deniedSummary = await callEmail(
  "/api/workspaces/ws2/domains/shared.example/dmarc-summary",
  false,
);
eq("Email Protection projection remains role-gated",
  deniedSummary.status, 403);

const hosted = await callEmail(
  "/api/workspaces/ws1/domains/shared.example/hosted-dmarc",
);
eq("Hosted-DMARC compatibility projection is read-only",
  hosted.body?.hosted_dmarc_interpretation?.mode, "read_only");
eq("Hosted-DMARC automation remains suspended",
  hosted.body?.hosted_dmarc_interpretation?.automation_status, "suspended");
eq("Hosted-DMARC remains suggestion-only",
  hosted.body?.hosted_dmarc_interpretation?.suggestion_only, true);
eq("Hosted-DMARC projection does not reinterpret requested policy",
  hosted.body?.hosted_dmarc_interpretation
    ?.effective_requested_policy, "quarantine");
eq("Hosted-DMARC projection never claims receiver enforcement",
  hosted.body?.hosted_dmarc_interpretation
    ?.receiver_enforcement_observed, false);

await establishDmarcPolicyBaseline(env, {
  workspace_id: "ws1",
  domain_id: "dom1",
  domain: "shared.example",
  scan_id: "scan-exact",
  policy_evidence: exact.sealed,
});
const baseline = db.prepare(
  `SELECT detail_json FROM email_protection_events
   WHERE workspace_id = 'ws1'
     AND record_type = 'dmarc_policy_condition'
     AND event_type = 'dmarc_domain_baseline_established'
   LIMIT 1`
).get();
const baselineDetail = baseline?.detail_json
  ? JSON.parse(baseline.detail_json)
  : null;
eq("D1 lifecycle reference reuses the R2/snapshot fingerprint",
  baselineDetail?.evidence_fingerprint,
  exact.sealed.evidence_fingerprint);
ok("no raw DMARC protocol JSON is copied into the lifecycle row",
  !String(baseline?.detail_json || "").includes("lookup_path"));
eq("repository has no DMARC observation table",
  db.prepare(
    `SELECT COUNT(*) AS count FROM sqlite_master
     WHERE type = 'table' AND name = 'dmarc_policy_observations'`
  ).get().count, 0);

const currentProjection = dmarcPolicyApiProjection(exactRead.dmarcPolicy);
eq("current API projection has explicit status",
  currentProjection.dmarc_policy_evidence_status, "current");
ok("current API projection carries no historical notice",
  !Object.prototype.hasOwnProperty.call(
    currentProjection,
    "dmarc_methodology_notice",
  ));

const openapi = JSON.parse(
  fs.readFileSync(path.join(root, "docs", "openapi.json"), "utf8"),
);
eq("OpenAPI pins the additive DMARC evidence schema",
  openapi.components?.schemas?.DmarcPolicyEvidence
    ?.properties?.schema?.const, DMARCBIS_POLICY_EVIDENCE_SCHEMA);
eq("OpenAPI keeps requested policy distinct from receiver enforcement",
  openapi.components?.schemas?.DmarcPolicyEvidence
    ?.properties?.receiver_enforcement_observed?.const, false);
eq("OpenAPI scan report documents the additive projection",
  openapi.paths?.["/api/scans/{scanId}/report"]
    ?.get?.responses?.["200"]?.$ref,
  "#/components/responses/DmarcPolicyEvidenceProjection");
eq("OpenAPI Email summary documents the additive projection",
  openapi.paths?.[
    "/api/workspaces/{workspaceId}/domains/{domain}/dmarc-summary"
  ]?.get?.responses?.["200"]?.$ref,
  "#/components/responses/DmarcPolicyEvidenceProjection");

console.log(`\nDMARCbis P3 fixtures: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
