#!/usr/bin/env node
//
// PR-5.5 Gates 1–2 — inbound authority containment + honest trust semantics.
//
// A well-formed forged RUA report is still stored and visible as observational
// evidence, but gains no authority over hosted DNS, managed cases, canonical
// alerts, readiness/business-risk, executive evidence, or SPF corroboration.
// The paired source mutations prove every consumer gate is load-bearing.
// Node 24+. CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const workerRoot = path.join(root, "workers", "scan-api", "src");
const imp = (rel) => import(pathToFileURL(path.join(workerRoot, rel)).href);
const read = (rel) => fs.readFileSync(path.join(workerRoot, rel), "utf8");

const {
  ingestDmarcReport,
} = await imp("lib/dmarc-ingest.js");
const { ingestTlsRptReport } = await imp("lib/tlsrpt-ingest.js");
const {
  DMARC_AUTHORITY_ELIGIBLE_SOURCES,
  DMARC_AUTHORITY_EVIDENCE_SCOPE,
  DMARC_EXTERNAL_AUTOMATION_EVIDENCE_SCOPE,
  DMARC_OBSERVATIONAL_EVIDENCE_SCOPE,
  buildAggregateReportTrustSemantics,
  dmarcAuthoritySourceSql,
  dmarcExternalAutomationSourceSql,
  dmarcOperationalSignalSourceSql,
  isDmarcAuthorityEligibleSource,
  isDmarcExternalAutomationEligibleSource,
} = await imp("lib/dmarc-authority.js");
const {
  evaluateRampReadiness,
  getHostedDmarcPassRate,
  runHostedDnsVerificationSweep,
  shouldAutoRollback,
} = await imp("engines/hosted-dmarc.js");
const {
  gradeSenderCondition,
  senderRecoveryConfirmed,
} = await imp("engines/email-protection-lifecycle.js");
const {
  buildDmarcSenderIntelligenceEvidence,
  loadBecExposureEvidence,
} = await imp("engines/sender-provenance.js");
const { computeBecExposureScore } = await imp("engines/bec.js");
const {
  evaluateSpfAuthorizationCorroboration,
  recordSpfRuaCorroboration,
} = await imp("engines/spf-corroboration.js");
const { emailProtectionRoutes } = await imp("routes/email-protection.js");

let pass = 0;
let fail = 0;
const failures = [];
function ok(name, condition) {
  if (condition) pass += 1;
  else {
    fail += 1;
    failures.push(name);
    console.log(`FAIL ${name}`);
  }
}

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (filename) => {
    try { db.exec(fs.readFileSync(filename, "utf8")); } catch { /* migrations converge */ }
  };
  apply(path.join(root, "database", "schema.sql"));
  for (const filename of fs.readdirSync(path.join(root, "database", "migrations"))
    .filter((name) => name.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", filename));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}

function makeD1(db) {
  const wrap = (sql, args) => ({
    __sql: sql,
    first: async () => db.prepare(sql).get(...args) ?? null,
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => {
      const result = db.prepare(sql).run(...args);
      return { success: true, meta: { changes: result.changes, last_row_id: result.lastInsertRowid } };
    },
  });
  return {
    prepare(sql) {
      const statement = wrap(sql, []);
      statement.bind = (...args) => wrap(sql, args);
      return statement;
    },
    async batch(statements) {
      return Promise.all(statements.map((statement) =>
        /^\s*select/i.test(statement.__sql) ? statement.all() : statement.run()));
    },
  };
}

const db = buildDb();
const env = {
  cybermeters_db: makeD1(db),
  RESEND_API_KEY: "",
  RUA_INBOUND_DOMAIN: "reports.cybermeters.com",
  CLOUDFLARE_ZONE_ID: "0123456789abcdef0123456789abcdef",
  CLOUDFLARE_API_TOKEN: "test-token-never-used",
};

db.prepare("INSERT INTO users (id, email, email_verified) VALUES ('u1','founder@example.test',1)").run();
db.prepare("INSERT INTO workspaces (id, name, owner_user_id) VALUES ('ws1','Gate 1','u1')").run();
const seedDomain = (id, domain) => {
  db.prepare("INSERT INTO domains (id, user_id, domain, verification_status) VALUES (?, 'u1', ?, 'verified')")
    .run(id, domain);
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws1', ?)")
    .run(id);
};
seedDomain("d-victim", "victim.example");
seedDomain("d-advance", "advance.example");

// Existing lifecycle state: a forged passing report would have verified this
// case before containment, while a forged failing report could mint an alert.
db.prepare(`INSERT INTO email_sender_sources
  (id, workspace_id, domain, source_ip, header_from, first_seen, last_seen,
   total_messages, aligned_messages, failed_messages, pass_rate, classification,
   auto_classification, monitoring_status, recurrence_type, recurrence_band,
   created_at, updated_at)
  VALUES
  ('sender-recover','ws1','victim.example','198.51.100.10','victim.example',
   datetime('now','-20 days'),datetime('now','-20 days'),0,0,0,0,'unknown',
   'unauthorised','observed','sender_unauthorised_failures_active','high',
   datetime('now','-20 days'),datetime('now','-20 days')),
  ('sender-alert','ws1','victim.example','203.0.113.66','victim.example',
   datetime('now','-20 days'),datetime('now','-20 days'),0,0,0,0,'unknown',
   'unauthorised','recovered',NULL,'high',
   datetime('now','-20 days'),datetime('now','-20 days'))`).run();
db.prepare(`INSERT INTO managed_cases
  (id, workspace_id, case_type, domain_key, finding_id, source_finding_type,
   remediation_id, status, severity, created_at, updated_at)
  VALUES ('case-recover','ws1','email_case','email_protection','sender-recover',
          'email_sender_unauthorised_failures',
          'email.sender.unauthorised_failures_active',
          'awaiting_verification','high',datetime('now'),datetime('now'))`).run();

const nowEpoch = Math.floor(Date.now() / 1000);
function dmarcXml(reportId, domain, records, policy = "reject", {
  begin = nowEpoch - 3600,
  end = nowEpoch,
  orgName = "Attacker Chosen Reporter",
} = {}) {
  return `<?xml version="1.0"?><feedback>
    <report_metadata><org_name>${orgName}</org_name>
      <email>attacker@attacker.example</email><report_id>${reportId}</report_id>
      <date_range><begin>${begin}</begin><end>${end}</end></date_range>
    </report_metadata>
    <policy_published><domain>${domain}</domain><p>${policy}</p><pct>100</pct></policy_published>
    ${records.map((record) => `<record>
      <row><source_ip>${record.ip}</source_ip><count>${record.count}</count>
        <policy_evaluated><disposition>none</disposition>
          <dkim>${record.pass ? "pass" : "fail"}</dkim>
          <spf>${record.pass ? "pass" : "fail"}</spf>
        </policy_evaluated>
      </row>
      <identifiers><header_from>${domain}</header_from><envelope_from>${domain}</envelope_from></identifiers>
      <auth_results>
        <dkim><domain>${domain}</domain><selector>attacker</selector><result>${record.pass ? "pass" : "fail"}</result></dkim>
        <spf><domain>${domain}</domain><result>${record.pass ? "pass" : "fail"}</result></spf>
      </auth_results>
    </record>`).join("")}
  </feedback>`;
}

const baselineBecEvidence = await loadBecExposureEvidence(env, "ws1", "victim.example");
const baselineBecScore = computeBecExposureScore(baselineBecEvidence);
const baselineExecutive = await buildDmarcSenderIntelligenceEvidence(env, "ws1", "victim.example");

const forged = await ingestDmarcReport(env, {
  workspaceId: "ws1",
  domain: "victim.example",
  domainId: "d-victim",
  source: "inbound_email",
  enforceDomainMatch: true,
  provenance: {
    auth_verdict: "sender_domain_claimed",
    reporter_domain: "attacker.example",
    envelope_from: "attacker@attacker.example",
  },
  xmlString: dmarcXml("forged-victim-1", "victim.example", [
    { ip: "198.51.100.10", count: 100, pass: true },
    { ip: "203.0.113.66", count: 500, pass: false },
  ]),
});

ok("forged inbound RUA remains ingested", forged.ok === true && forged.imported === true);
ok("forged inbound report row is stored with its source marker",
  db.prepare("SELECT source FROM dmarc_aggregate_reports WHERE external_report_id='forged-victim-1'").get()?.source === "inbound_email");
ok("forged inbound sender rows remain in the observational rollup",
  db.prepare("SELECT SUM(total_messages) AS n FROM email_sender_sources WHERE workspace_id='ws1' AND domain='victim.example'").get()?.n === 600);

// A second forged report supplies the exact opposite outcome: enough reported
// passing volume to advance hosted-DMARC autopilot if the gate is removed.
await ingestDmarcReport(env, {
  workspaceId: "ws1",
  domain: "advance.example",
  domainId: "d-advance",
  source: "inbound_email",
  enforceDomainMatch: true,
  provenance: { auth_verdict: "sender_domain_claimed", reporter_domain: "attacker.example" },
  xmlString: dmarcXml("forged-advance-1", "advance.example",
    [{ ip: "198.51.100.77", count: 500, pass: true }], "none"),
});

// ── Hosted DNS: no rollback, no advance, no Cloudflare TXT PATCH ─────────────
const hostedNow = new Date("2026-07-23T12:00:00.000Z");
function seedHosted(id, domain, currentValue, previousValue, autopilot) {
  db.prepare(`INSERT INTO hosted_dns_entries
    (id, workspace_id, domain, record_kind, customer_name, target_name, target_value,
     provider, provider_record_id, verification_state, previous_value, autopilot,
     pass_rate_at_change, verified_at, last_change_at, created_at, updated_at)
    VALUES (?, 'ws1', ?, 'dmarc', ?, ?, ?, 'cloudflare', ?, 'connected', ?, ?, 99,
            datetime('now','-10 days'), datetime('now','-10 days'),
            datetime('now','-20 days'), datetime('now','-10 days'))`)
    .run(id, domain, `_dmarc.${domain}`, `${id}.dmarc.cybermeters.com`,
      currentValue, `cf-${id}`, previousValue, autopilot);
}
seedHosted("hd-rollback", "victim.example",
  "v=DMARC1; p=quarantine; pct=50", "v=DMARC1; p=none", 0);
seedHosted("hd-advance", "advance.example",
  "v=DMARC1; p=none", null, 1);

const rollbackRate = await getHostedDmarcPassRate(env, "ws1", "victim.example");
const advanceRate = await getHostedDmarcPassRate(env, "ws1", "advance.example");
ok("inbound-only hosted rollback rate fails closed to no authority",
  rollbackRate.total === 0 && rollbackRate.pass_rate === null &&
  rollbackRate.evidence_scope === DMARC_EXTERNAL_AUTOMATION_EVIDENCE_SCOPE &&
  rollbackRate.inbound_automation_suspended === true &&
  rollbackRate.external_automation_suspended === true &&
  rollbackRate.corroboration_required === true);
ok("inbound-only hosted advance rate fails closed to no authority",
  advanceRate.total === 0 && advanceRate.pass_rate === null);

const rawRate = (domain) => {
  const row = db.prepare(`SELECT SUM(message_count) AS total,
      SUM(CASE WHEN dkim_aligned_result='pass' OR spf_aligned_result='pass'
               THEN message_count ELSE 0 END) AS aligned
    FROM dmarc_aggregate_records
    WHERE workspace_id='ws1' AND domain=?`).get(domain);
  const total = Number(row?.total || 0);
  return { total, pass_rate: total ? (Number(row?.aligned || 0) / total) * 100 : null };
};
const mutantRollbackRate = rawRate("victim.example");
const mutantAdvanceRate = rawRate("advance.example");
ok("mutation proof: an ungated read restores forged auto-rollback authority",
  shouldAutoRollback({
    baseline_pass_rate: 99,
    current_pass_rate: mutantRollbackRate.pass_rate,
    total_messages: mutantRollbackRate.total,
  }) === true);
ok("mutation proof: an ungated read restores forged autopilot-advance authority",
  evaluateRampReadiness({
    pass_rate: mutantAdvanceRate.pass_rate,
    total_messages: mutantAdvanceRate.total,
    days_since_change: 10,
  }).ready === true);

const dnsQueryImpl = async (name, type) => {
  const row = db.prepare(`SELECT target_name, customer_name, target_value
                          FROM hosted_dns_entries
                          WHERE target_name=? OR customer_name=? LIMIT 1`).get(name, name);
  if (!row) return { Status: 3, Answer: [] };
  if (type === "CNAME") return { Status: 0, Answer: [{ type: 5, data: row.target_name }] };
  if (name === row.target_name) return { Status: 0, Answer: [{ type: 16, data: `"${row.target_value}"` }] };
  return { Status: 0, Answer: [
    { type: 5, data: row.target_name },
    { type: 16, data: `"${row.target_value}"` },
  ] };
};
const cloudflareWrites = [];
const fetchImpl = async (...args) => {
  cloudflareWrites.push(args);
  return new Response(JSON.stringify({ success: true, result: {} }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
};
await runHostedDnsVerificationSweep(env, { dnsQueryImpl, fetchImpl, now: hostedNow });
ok("forged inbound data causes zero Cloudflare TXT PATCH/create/delete calls",
  cloudflareWrites.length === 0);
ok("forged inbound data causes zero hosted rollback",
  db.prepare("SELECT target_value FROM hosted_dns_entries WHERE id='hd-rollback'").get()?.target_value ===
    "v=DMARC1; p=quarantine; pct=50");
ok("forged inbound data causes zero hosted autopilot advance",
  db.prepare("SELECT target_value FROM hosted_dns_entries WHERE id='hd-advance'").get()?.target_value ===
    "v=DMARC1; p=none");

// ── Cases + lifecycle alerts: ingest cannot enter the authority consumer ──────
ok("forged inbound report does not auto-verify/close/recover the managed case",
  db.prepare("SELECT status FROM managed_cases WHERE id='case-recover'").get()?.status === "awaiting_verification");
ok("forged inbound report creates no lifecycle event",
  db.prepare("SELECT COUNT(*) AS n FROM email_protection_events").get()?.n === 0);
ok("forged inbound report creates no authoritative notification",
  db.prepare("SELECT COUNT(*) AS n FROM notification_events").get()?.n === 0);
ok("forged inbound report leaves the prior sender recovery state untouched",
  db.prepare("SELECT recurrence_type FROM email_sender_sources WHERE id='sender-recover'").get()?.recurrence_type ===
    "sender_unauthorised_failures_active");

const mutantRecovery = gradeSenderCondition({
  observed: "unauthorised",
  window_total: 100,
  window_failed: 0,
  is_new: false,
});
ok("mutation proof: ungated forged pass volume satisfies case recovery",
  senderRecoveryConfirmed({
    prev_recurrence_type: "sender_unauthorised_failures_active",
    graded_recurrence: mutantRecovery.recurrence,
    window_total: 100,
    window_failed: 0,
  }) === true);
const mutantAlert = gradeSenderCondition({
  observed: "unauthorised",
  window_total: 500,
  window_failed: 500,
  is_new: false,
});
ok("mutation proof: ungated forged fail volume satisfies authoritative alert condition",
  mutantAlert.recurrence === "sender_unauthorised_failures_active");

// SPF corroboration is another canonical-alert consumer of the same records.
const spfSnapshot = {
  resolution_status: "complete",
  resolved_pass_authorisations: [{ family: 4, network: "192.0.2.0", prefix: 24 }],
};
const spfModules = { email_security: {
  spf: spfSnapshot,
  spf_detail: { policy_strength: "strong" },
} };
const spfOutcome = await recordSpfRuaCorroboration(
  "scan-forged", "d-victim", "victim.example", spfModules, env,
  { nowIso: hostedNow.toISOString() },
);
ok("forged inbound SPF evidence emits no canonical alert", spfOutcome.emitted === 0);
const mutantSpf = evaluateSpfAuthorizationCorroboration({
  domain: "victim.example",
  sources: [{
    source_ip: "203.0.113.66",
    spf_result: "fail",
    spf_domain: "victim.example",
    header_from: "victim.example",
    message_count: 500,
  }],
  resolvedAuthorization: spfSnapshot,
  spfPolicy: "strong",
  nowIso: hostedNow.toISOString(),
});
ok("mutation proof: ungated forged SPF evidence creates an alertable finding",
  mutantSpf.findings.length === 1);

// ── Readiness, business-risk and Executive evidence do not move ──────────────
const afterBecEvidence = await loadBecExposureEvidence(env, "ws1", "victim.example");
const afterBecScore = computeBecExposureScore(afterBecEvidence);
const afterExecutive = await buildDmarcSenderIntelligenceEvidence(env, "ws1", "victim.example");
ok("forged inbound report does not change authoritative readiness inputs",
  afterBecEvidence.imported_reports === baselineBecEvidence.imported_reports &&
  afterBecEvidence.total_messages === baselineBecEvidence.total_messages &&
  afterBecEvidence.pass_rate === baselineBecEvidence.pass_rate &&
  afterBecEvidence.evidence_scope === DMARC_AUTHORITY_EVIDENCE_SCOPE &&
  afterBecEvidence.inbound_reports_authoritative === false);
ok("forged inbound report does not change authoritative BEC/business-risk score",
  afterBecScore.score === baselineBecScore.score &&
  afterBecScore.level === baselineBecScore.level);
ok("forged inbound report does not create Executive sender evidence",
  baselineExecutive === null && afterExecutive === null);
ok("mutation proof: the ungated forged totals materially differ from authority inputs",
  mutantRollbackRate.total === 600 && afterBecEvidence.total_messages === 0);

// ── Forensic history stays visible; operational signals are provenance-filtered
async function route(pathname) {
  const request = new Request(`https://app.cybermeters.test${pathname}`);
  return emailProtectionRoutes({
    request,
    env,
    url: new URL(request.url),
    json: (body, status = 200) => ({ body, status }),
    serverError: (where, error) => { throw new Error(`${where}: ${error?.message || error}`); },
    requireAuth: async () => ({ id: "u1" }),
    requireWorkspaceRole: async () => ({ role: "owner" }),
  });
}
const forgedOnlySummary = await route("/api/workspaces/ws1/domains/victim.example/dmarc-summary?days=30");
const forgedOnlySenders = await route("/api/workspaces/ws1/domains/victim.example/email-senders");
const forgedOnlyActions = JSON.stringify(forgedOnlySummary.body.report_remediation_actions || []);
ok("forged inbound report contributes zero traffic/disposition/window decision signal",
  forgedOnlySummary.status === 200 &&
  forgedOnlySummary.body.traffic.total_messages === 0 &&
  forgedOnlySummary.body.traffic.aligned_messages === 0 &&
  forgedOnlySummary.body.traffic.failed_messages === 0 &&
  forgedOnlySummary.body.traffic.pass_rate === 0 &&
  forgedOnlySummary.body.disposition.none === 0 &&
  forgedOnlySummary.body.disposition.quarantine === 0 &&
  forgedOnlySummary.body.disposition.reject === 0 &&
  forgedOnlySummary.body.readiness.checks.find((check) => check.id === "reporting_window")?.detail.startsWith("0 day") &&
  forgedOnlySummary.body.evidence_scope === DMARC_OBSERVATIONAL_EVIDENCE_SCOPE &&
  forgedOnlySummary.body.authoritative === false &&
  forgedOnlySummary.body.readiness.authoritative === false &&
  forgedOnlySummary.body.business_risk.authoritative === false);
ok("forged inbound report contributes zero sender/classification decision signal",
  forgedOnlySenders.status === 200 &&
  forgedOnlySenders.body.senders.length === 0 &&
  forgedOnlySenders.body.summary.total_senders === 0 &&
  forgedOnlySenders.body.summary.total_messages === 0 &&
  forgedOnlySenders.body.summary.unknown_senders === 0 &&
  !forgedOnlyActions.includes("unknown_sender_detected") &&
  !forgedOnlyActions.includes("high_volume_alignment_failure"));
const history = await route("/api/workspaces/ws1/domains/victim.example/dmarc-reports");
ok("forged report history is honestly labelled claimed/unverified observational evidence",
  history.status === 200 && history.body.reports.length === 1 &&
  history.body.reports[0].source === "inbound_email" &&
  history.body.reports[0].auth_verdict === "sender_domain_claimed" &&
  history.body.reports[0].transport_authenticated_sender === null &&
  history.body.reports[0].report_producer_authenticated === false &&
  history.body.reports[0].evidence_confidence === "unverified_observational" &&
  history.body.reports[0].claimed_domain === "victim.example" &&
  history.body.reports[0].authoritative_eligible === false &&
  history.body.reports[0].external_automation_eligible === false &&
  history.body.reports[0].authoritative === false &&
  history.body.reports[0].evidence_scope === DMARC_OBSERVATIONAL_EVIDENCE_SCOPE);

// A recognised inbound report is admitted only to the explicitly
// non-authoritative operational view. It deliberately reuses the forged
// report's source IP so cumulative email_sender_sources counters are poisoned;
// the served metrics must still come solely from eligible parent/child rows.
const recognisedBegin = nowEpoch - 7200;
const recognisedEnd = nowEpoch - 3600;
const recognised = await ingestDmarcReport(env, {
  workspaceId: "ws1",
  domain: "victim.example",
  domainId: "d-victim",
  source: "inbound_email",
  enforceDomainMatch: true,
  provenance: {
    auth_verdict: "sender_domain_claimed_recognised",
    reporter_domain: "outlook.com",
    envelope_from: "reports@outlook.com",
  },
  xmlString: dmarcXml("recognised-inbound-1", "victim.example",
    [{ ip: "198.51.100.10", count: 40, pass: true }], "none", {
      begin: recognisedBegin,
      end: recognisedEnd,
      orgName: "Recognised Reporter",
    }),
});
db.prepare(`UPDATE email_sender_sources
            SET classification='trusted', notes='customer assertion', classified_at=datetime('now')
            WHERE id='sender-recover'`).run();
const recognisedSummary = await route("/api/workspaces/ws1/domains/victim.example/dmarc-summary?days=30");
const recognisedSenders = await route("/api/workspaces/ws1/domains/victim.example/email-senders");
const recognisedSender = recognisedSenders.body.senders.find((sender) => sender.source_ip === "198.51.100.10");
ok("recognised inbound evidence remains an observational operational signal",
  recognised.ok === true &&
  recognisedSummary.body.traffic.total_messages === 40 &&
  recognisedSummary.body.traffic.aligned_messages === 40 &&
  recognisedSummary.body.traffic.failed_messages === 0 &&
  recognisedSummary.body.traffic.pass_rate === 100 &&
  recognisedSummary.body.authoritative === false);
ok("same-IP forged counters cannot poison eligible sender metrics or customer assertion",
  recognisedSenders.body.senders.length === 1 &&
  recognisedSender?.total_messages === 40 &&
  recognisedSender?.aligned_messages === 40 &&
  recognisedSender?.failed_messages === 0 &&
  recognisedSender?.pass_rate === 100 &&
  recognisedSender?.first_seen === new Date(recognisedBegin * 1000).toISOString() &&
  recognisedSender?.last_seen === new Date(recognisedEnd * 1000).toISOString() &&
  recognisedSender?.classification === "trusted" &&
  recognisedSender?.classification_source === "manual" &&
  recognisedSender?.notes === "customer assertion");
ok("recognised inbound label remains non-authoritative and never becomes verified",
  recognisedSender?.effective_classification === "authorised" &&
  recognisedSender?.classification === "trusted" &&
  buildAggregateReportTrustSemantics({
    source: "inbound_email",
    storedTransportVerdict: "sender_domain_claimed_recognised",
    reporterDomain: "outlook.com",
  }).authoritative_eligible === false);

// A second tenant with the same domain and source IP must never affect ws1.
db.prepare("INSERT INTO users (id, email, email_verified) VALUES ('u2','other@example.test',1)").run();
db.prepare("INSERT INTO workspaces (id, name, owner_user_id) VALUES ('ws2','Other tenant','u2')").run();
db.prepare("INSERT INTO domains (id, user_id, domain, verification_status) VALUES ('d-victim-ws2','u2','victim.example','verified')").run();
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws2','d-victim-ws2')").run();
await ingestDmarcReport(env, {
  workspaceId: "ws2",
  domain: "victim.example",
  domainId: "d-victim-ws2",
  source: "inbound_email",
  enforceDomainMatch: true,
  provenance: { auth_verdict: "sender_domain_claimed_recognised", reporter_domain: "outlook.com" },
  xmlString: dmarcXml("other-tenant-1", "victim.example",
    [{ ip: "198.51.100.10", count: 700, pass: false }], "none", {
      orgName: "Other Tenant Reporter",
    }),
});
const tenantBoundSummary = await route("/api/workspaces/ws1/domains/victim.example/dmarc-summary?days=30");
const tenantBoundSenders = await route("/api/workspaces/ws1/domains/victim.example/email-senders");
ok("operational signal aggregation remains workspace/domain tenant-bound",
  tenantBoundSummary.body.traffic.total_messages === 40 &&
  tenantBoundSummary.body.traffic.failed_messages === 0 &&
  tenantBoundSenders.body.senders.length === 1 &&
  tenantBoundSenders.body.senders[0].total_messages === 40);

db.prepare(`UPDATE dmarc_aggregate_reports
            SET auth_verdict='verified', reporter_domain='outlook.com'
            WHERE external_report_id='forged-victim-1'`).run();
const legacyHistory = await route("/api/workspaces/ws1/domains/victim.example/dmarc-reports");
const legacySummary = await route("/api/workspaces/ws1/domains/victim.example/dmarc-summary?days=30");
ok("legacy consumer-mailbox verified rows are never exposed as verified or authoritative",
  legacyHistory.body.reports[0].auth_verdict === "sender_domain_claimed_recognised" &&
  legacyHistory.body.reports[0].recognised_reporter_domain === true &&
  legacyHistory.body.reports[0].transport_authenticated_sender === null &&
  legacyHistory.body.reports[0].report_producer_authenticated === false &&
  legacyHistory.body.reports[0].authoritative_eligible === false &&
  legacyHistory.body.reports[0].authoritative === false);
ok("legacy raw verified label is admitted only to the operational observational view",
  legacySummary.body.traffic.total_messages === 640 &&
  legacySummary.body.authoritative === false &&
  legacySummary.body.readiness.authoritative === false);
db.prepare(`UPDATE dmarc_aggregate_reports
            SET auth_verdict='sender_domain_claimed', reporter_domain='attacker.example'
            WHERE external_report_id='forged-victim-1'`).run();
const restoredSummary = await route("/api/workspaces/ws1/domains/victim.example/dmarc-summary?days=30");
ok("restoring forged provenance removes it from every operational signal without deleting history",
  restoredSummary.body.traffic.total_messages === 40 &&
  db.prepare("SELECT COUNT(*) AS n FROM dmarc_aggregate_reports WHERE external_report_id='forged-victim-1'").get()?.n === 1 &&
  db.prepare("SELECT COUNT(*) AS n FROM dmarc_aggregate_records WHERE report_id=?")
    .get(forged.reportId)?.n === 2);

const tlsBody = JSON.stringify({
  "organization-name": "Attacker Reporter",
  "date-range": {
    "start-datetime": "2026-07-22T00:00:00Z",
    "end-datetime": "2026-07-22T23:59:59Z",
  },
  "report-id": "forged-tls-1",
  policies: [{
    policy: { "policy-type": "sts", "policy-domain": "victim.example" },
    summary: {
      "total-successful-session-count": 0,
      "total-failure-session-count": 999999,
    },
    "failure-details": [{
      "result-type": "certificate-expired",
      "failed-session-count": 999999,
    }],
  }],
});
const tlsIngest = await ingestTlsRptReport(env, {
  workspaceId: "ws1",
  domain: "victim.example",
  enforceDomainMatch: true,
  provenance: { auth_verdict: "sender_domain_claimed", reporter_domain: "attacker.example" },
  jsonString: tlsBody,
});
ok("forged TLS-RPT remains ingested", tlsIngest.ok === true && tlsIngest.duplicate === false);
const tlsHistory = await route("/api/workspaces/ws1/domains/victim.example/tls-rpt/reports");
ok("TLS-RPT is visible only as claimed/non-authoritative observational evidence",
  tlsHistory.status === 200 &&
  tlsHistory.body.summary.failed_sessions === 999999 &&
  tlsHistory.body.summary.authoritative === false &&
  tlsHistory.body.summary.evidence_scope === DMARC_OBSERVATIONAL_EVIDENCE_SCOPE &&
  tlsHistory.body.reports[0].provenance === "sender_domain_claimed" &&
  tlsHistory.body.reports[0].transport_authenticated_sender === null &&
  tlsHistory.body.reports[0].report_producer_authenticated === false &&
  tlsHistory.body.reports[0].evidence_confidence === "unverified_observational" &&
  tlsHistory.body.reports[0].claimed_domain === "victim.example" &&
  tlsHistory.body.reports[0].authoritative_eligible === false &&
  tlsHistory.body.reports[0].external_automation_eligible === false &&
  tlsHistory.body.reports[0].authoritative === false);

// ── Explicit non-inbound regression path remains eligible ────────────────────
const manual = await ingestDmarcReport(env, {
  workspaceId: "ws1",
  domain: "victim.example",
  domainId: "d-victim",
  source: "manual_paste",
  enforceDomainMatch: false,
  actorUserId: "u1",
  xmlString: dmarcXml("manual-regression-1", "victim.example",
    [{ ip: "192.0.2.44", count: 20, pass: true }], "reject"),
});
const manualRate = await getHostedDmarcPassRate(env, "ws1", "victim.example");
const manualExecutive = await buildDmarcSenderIntelligenceEvidence(env, "ws1", "victim.example");
ok("explicit manual-paste regression path remains internally authority-eligible",
  manual.ok === true &&
  manualExecutive?.imported_reports === 1 && manualExecutive?.total_messages === 20);
ok("manual-paste aggregate data still cannot drive destructive external automation",
  manualRate.total === 0 && manualRate.pass_rate === null &&
  manualRate.external_automation_suspended === true &&
  isDmarcExternalAutomationEligibleSource("manual_paste") === false);
const signed = await ingestDmarcReport(env, {
  workspaceId: "ws1",
  domain: "victim.example",
  domainId: "d-victim",
  source: "signed_upload",
  enforceDomainMatch: true,
  xmlString: dmarcXml("signed-regression-1", "victim.example",
    [{ ip: "192.0.2.45", count: 30, pass: true }], "reject", {
      orgName: "Signed Upload Reporter",
    }),
});
const eligibleSummary = await route("/api/workspaces/ws1/domains/victim.example/dmarc-summary?days=30");
const eligibleSenders = await route("/api/workspaces/ws1/domains/victim.example/email-senders");
ok("manual, signed and recognised-inbound evidence feed only the operational observational view",
  signed.ok === true &&
  eligibleSummary.body.traffic.total_messages === 90 &&
  eligibleSummary.body.traffic.aligned_messages === 90 &&
  eligibleSummary.body.traffic.failed_messages === 0 &&
  eligibleSummary.body.authoritative === false &&
  eligibleSenders.body.senders.length === 3 &&
  eligibleSenders.body.summary.total_messages === 90);
ok("source allow-list fails closed for inbound, null and unknown markers",
  isDmarcAuthorityEligibleSource("manual_paste") === true &&
  isDmarcAuthorityEligibleSource("signed_upload") === true &&
  isDmarcAuthorityEligibleSource("inbound_email") === false &&
  isDmarcAuthorityEligibleSource(null) === false &&
  isDmarcAuthorityEligibleSource("future_unreviewed_source") === false);
const unmarked = await ingestDmarcReport(env, {
  workspaceId: "ws1",
  domain: "victim.example",
  domainId: "d-victim",
  enforceDomainMatch: true,
  xmlString: dmarcXml("unmarked-fail-closed-1", "victim.example",
    [{ ip: "203.0.113.200", count: 999999, pass: false }], "reject"),
});
ok("omitted source is persisted as unknown rather than default-authoritative",
  unmarked.ok === true &&
  db.prepare(`SELECT source FROM dmarc_aggregate_reports
              WHERE external_report_id='unmarked-fail-closed-1'`).get()?.source === "unknown");
const afterUnmarkedRate = await getHostedDmarcPassRate(env, "ws1", "victim.example");
ok("omitted-source report has zero authority",
  afterUnmarkedRate.total === 0 &&
  afterUnmarkedRate.pass_rate === null);
const afterUnmarkedSummary = await route("/api/workspaces/ws1/domains/victim.example/dmarc-summary?days=30");
const afterUnmarkedSenders = await route("/api/workspaces/ws1/domains/victim.example/email-senders");
ok("unknown/unmarked report contributes zero operational decision signal",
  afterUnmarkedSummary.body.traffic.total_messages === 90 &&
  afterUnmarkedSummary.body.traffic.failed_messages === 0 &&
  afterUnmarkedSenders.body.senders.length === 3 &&
  afterUnmarkedSenders.body.summary.total_messages === 90);

// ── Gate 2 trust semantics: labels never manufacture producer authority ──────
const recognisedHeaderFrom = buildAggregateReportTrustSemantics({
  source: "inbound_email",
  storedTransportVerdict: "verified", // legacy value from a public-mail allow-list match
  reporterDomain: "outlook.com",
  claimedDomain: "victim.example",
});
const unrecognisedHeaderFrom = buildAggregateReportTrustSemantics({
  source: "inbound_email",
  storedTransportVerdict: "sender_domain_claimed",
  reporterDomain: "attacker.example",
  claimedDomain: "victim.example",
});
const manualSubmission = buildAggregateReportTrustSemantics({
  source: "manual_paste",
  claimedDomain: "victim.example",
});
const signedSubmission = buildAggregateReportTrustSemantics({
  source: "signed_upload",
  claimedDomain: "victim.example",
});
ok("legacy consumer-mailbox verified label normalizes to claimed metadata only",
  recognisedHeaderFrom.transport_sender_status === "sender_domain_claimed_recognised" &&
  recognisedHeaderFrom.recognised_reporter_domain === true &&
  recognisedHeaderFrom.transport_authenticated_sender === null &&
  recognisedHeaderFrom.report_producer_authenticated === false);
ok("authority contract is independent of transport/header-From labels",
  recognisedHeaderFrom.authoritative_eligible === false &&
  unrecognisedHeaderFrom.authoritative_eligible === false &&
  recognisedHeaderFrom.external_automation_eligible === false &&
  unrecognisedHeaderFrom.external_automation_eligible === false);
ok("report-body domain remains an explicitly unverified claim",
  recognisedHeaderFrom.report_body_identity.claimed_domain === "victim.example" &&
  recognisedHeaderFrom.report_body_identity.independently_verified === false);
ok("actor authentication is separate from report-producer authentication",
  manualSubmission.actor_authenticated === true &&
  manualSubmission.actor_authentication === "workspace_session" &&
  signedSubmission.actor_authenticated === true &&
  signedSubmission.actor_authentication === "scoped_ingest_token" &&
  manualSubmission.report_producer_authenticated === false &&
  signedSubmission.report_producer_authenticated === false);
ok("customer-submitted content has bounded internal authority but no external authority",
  manualSubmission.evidence_confidence === "customer_submitted_unverified_content" &&
  manualSubmission.authoritative_eligible === true &&
  manualSubmission.external_automation_eligible === false &&
  signedSubmission.authoritative_eligible === true &&
  signedSubmission.external_automation_eligible === false);
ok("authority and external-automation SQL contracts remain byte-semantically unchanged",
  DMARC_AUTHORITY_ELIGIBLE_SOURCES.join(",") === "manual_paste,signed_upload" &&
  dmarcAuthoritySourceSql("rep") === "rep.source IN ('manual_paste', 'signed_upload')" &&
  dmarcExternalAutomationSourceSql("rep") === "0 = 1");
ok("operational-signal predicate is separate, bounded and excludes claimed/unknown inbound",
  dmarcOperationalSignalSourceSql("rep") ===
    "(rep.source IN ('manual_paste', 'signed_upload') OR (rep.source = 'inbound_email' AND rep.auth_verdict IN ('sender_domain_claimed_recognised', 'verified')))" &&
  !dmarcOperationalSignalSourceSql("rep").includes("sender_identity_unavailable") &&
  !dmarcOperationalSignalSourceSql("rep").includes("'sender_domain_claimed',"));
let aliasRejected = false;
try { dmarcOperationalSignalSourceSql("rep; DROP TABLE workspaces"); } catch (error) {
  aliasRejected = error?.message === "invalid_sql_alias";
}
ok("operational-signal predicate rejects unsafe SQL aliases", aliasRejected);

// ── Mutation guards: deleting any consumer gate is CI-red ────────────────────
function guard(name, rel, predicate, mutate) {
  const source = read(rel);
  ok(`${name} — gate holds`, predicate(source));
  const mutant = mutate(source);
  ok(`${name} — mutation changes source`, mutant !== source);
  ok(`${name} — gate removal is RED`, predicate(mutant) === false);
}
function guardEveryOccurrence(name, rel, token, expected) {
  const source = read(rel);
  const positions = [];
  let cursor = 0;
  while ((cursor = source.indexOf(token, cursor)) !== -1) {
    positions.push(cursor);
    cursor += token.length;
  }
  ok(`${name} — all ${expected} gates hold`, positions.length === expected);
  positions.forEach((position, index) => {
    const mutant = source.slice(0, position) + source.slice(position + token.length);
    ok(`${name} — removing gate ${index + 1}/${expected} is RED`,
      (mutant.split(token).length - 1) !== expected);
  });
}
const hasRepGate = (source) => source.includes('dmarcAuthoritySourceSql("rep")');
const removeRepGate = (source) => source.replace(/\s*AND \$\{dmarcAuthoritySourceSql\("rep"\)\}/, "");
const hasExternalRepGate = (source) => source.includes('dmarcExternalAutomationSourceSql("rep")');
const removeExternalRepGate = (source) =>
  source.replace(/\s*AND \$\{dmarcExternalAutomationSourceSql\("rep"\)\}/, "");
guard("hosted-DMARC DNS automation", "engines/hosted-dmarc.js",
  hasExternalRepGate, removeExternalRepGate);
guard("managed-case recovery and sender alerts", "engines/email-protection-lifecycle.js", hasRepGate, removeRepGate);
guard("hosted policy-impact alert", "engines/dmarc-impact.js", hasRepGate, removeRepGate);
guard("SPF corroboration authoritative alert", "engines/spf-corroboration.js", hasRepGate, removeRepGate);
guardEveryOccurrence("authoritative readiness/business-risk/Executive parent-report gates",
  "engines/sender-provenance.js", 'dmarcAuthoritySourceSql("rep")', 3);
guardEveryOccurrence("authoritative readiness latest-policy gates",
  "engines/sender-provenance.js", 'dmarcAuthoritySourceSql("dmarc_aggregate_reports")', 2);
guardEveryOccurrence("inbound ingest classifier/lifecycle dispatch gates",
  "lib/dmarc-ingest.js", "if (authorityEligible)", 2);
guard("authority-only sender classifier aggregation", "engines/sender-classification.js",
  (source) => source.includes("AND rep.source IN (${placeholders})"),
  (source) => source.replace("AND rep.source IN (${placeholders})", ""));
guard("operational predicate excludes unrecognised inbound claims", "lib/dmarc-authority.js",
  (source) => source.includes("auth_verdict IN ('sender_domain_claimed_recognised', 'verified')"),
  (source) => source.replace(
    "auth_verdict IN ('sender_domain_claimed_recognised', 'verified')",
    "auth_verdict IN ('sender_domain_claimed', 'sender_domain_claimed_recognised', 'verified')",
  ));
guardEveryOccurrence("operational sender inventory parent-report gate",
  "engines/rua-routing.js", 'dmarcOperationalSignalSourceSql("rep")', 1);
guardEveryOccurrence("operational DMARC summary parent-report gates",
  "routes/email-protection.js", 'dmarcOperationalSignalSourceSql("rep")', 2);
guardEveryOccurrence("observational report labels",
  "routes/email-protection.js", "DMARC_OBSERVATIONAL_EVIDENCE_SCOPE", 8);

console.log(`\nInbound-email authority containment: ${pass}/${pass + fail} passed`);
if (fail) {
  for (const name of failures) console.log(`  FAIL ${name}`);
  console.error("inbound-email-authority-containment validation FAILED");
  process.exit(1);
}
console.log("inbound-email-authority-containment validation passed");
