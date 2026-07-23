#!/usr/bin/env node
//
// PR-5.5 Gate 1 — inbound-email authority containment.
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
  DMARC_AUTHORITY_EVIDENCE_SCOPE,
  DMARC_OBSERVATIONAL_EVIDENCE_SCOPE,
  isDmarcAuthorityEligibleSource,
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
function dmarcXml(reportId, domain, records, policy = "reject") {
  return `<?xml version="1.0"?><feedback>
    <report_metadata><org_name>Attacker Chosen Reporter</org_name>
      <email>attacker@attacker.example</email><report_id>${reportId}</report_id>
      <date_range><begin>${nowEpoch - 3600}</begin><end>${nowEpoch}</end></date_range>
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
    auth_verdict: "unverified",
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
  provenance: { auth_verdict: "unverified", reporter_domain: "attacker.example" },
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
  rollbackRate.evidence_scope === DMARC_AUTHORITY_EVIDENCE_SCOPE &&
  rollbackRate.inbound_automation_suspended === true);
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

// ── Observational surfaces remain available and explicitly non-authoritative ─
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
const summary = await route("/api/workspaces/ws1/domains/victim.example/dmarc-summary?days=30");
ok("forged inbound report remains visible in the DMARC observational summary",
  summary.status === 200 && summary.body.traffic.total_messages === 600 &&
  summary.body.evidence_scope === DMARC_OBSERVATIONAL_EVIDENCE_SCOPE &&
  summary.body.authoritative === false &&
  summary.body.readiness.authoritative === false &&
  summary.body.business_risk.authoritative === false);
const history = await route("/api/workspaces/ws1/domains/victim.example/dmarc-reports");
ok("forged report history is honestly labelled unverified observational evidence",
  history.status === 200 && history.body.reports.length === 1 &&
  history.body.reports[0].source === "inbound_email" &&
  history.body.reports[0].auth_verdict === "unverified" &&
  history.body.reports[0].authoritative === false &&
  history.body.reports[0].evidence_scope === DMARC_OBSERVATIONAL_EVIDENCE_SCOPE);

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
  provenance: { auth_verdict: "unverified" },
  jsonString: tlsBody,
});
ok("forged TLS-RPT remains ingested", tlsIngest.ok === true && tlsIngest.duplicate === false);
const tlsHistory = await route("/api/workspaces/ws1/domains/victim.example/tls-rpt/reports");
ok("TLS-RPT is visible only as unverified/non-authoritative observational evidence",
  tlsHistory.status === 200 &&
  tlsHistory.body.summary.failed_sessions === 999999 &&
  tlsHistory.body.summary.authoritative === false &&
  tlsHistory.body.summary.evidence_scope === DMARC_OBSERVATIONAL_EVIDENCE_SCOPE &&
  tlsHistory.body.reports[0].provenance === "unverified" &&
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
ok("explicit manual-paste regression path remains authority-eligible",
  manual.ok === true && manualRate.total === 20 && manualRate.pass_rate === 100 &&
  manualExecutive?.imported_reports === 1 && manualExecutive?.total_messages === 20);
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
  afterUnmarkedRate.total === manualRate.total &&
  afterUnmarkedRate.pass_rate === manualRate.pass_rate);

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
guard("hosted-DMARC DNS automation", "engines/hosted-dmarc.js", hasRepGate, removeRepGate);
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
guardEveryOccurrence("observational report labels",
  "routes/email-protection.js", "DMARC_OBSERVATIONAL_EVIDENCE_SCOPE", 8);

console.log(`\nInbound-email authority containment: ${pass}/${pass + fail} passed`);
if (fail) {
  for (const name of failures) console.log(`  FAIL ${name}`);
  console.error("inbound-email-authority-containment validation FAILED");
  process.exit(1);
}
console.log("inbound-email-authority-containment validation passed");
