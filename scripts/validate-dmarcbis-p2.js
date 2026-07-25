#!/usr/bin/env node
// Item 7 P2 deterministic production-integration fixtures.
//
// Covers the shared DNS cache, two-tier deadline/budget contract, production
// adapters, honest degradation, migration-088 lifecycle reuse, migration 101,
// aggregate report compatibility, and the P2/P4/P5 customer-boundary split.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  attachDmarcbisExternalResult,
  createProductionDmarcbisDnsClient,
  DMARCBIS_CORE_BUDGET_MS,
  DMARCBIS_CORROBORATION_DEADLINE_MS,
  DMARCBIS_EXTERNAL_HOST_RESERVATION,
  DMARCBIS_EXTERNAL_RUA_BUDGET_MS,
  DMARCBIS_EXTERNAL_PRIMARY_DEADLINE_MS,
  DMARCBIS_EXTERNAL_CORROBORATION_DEADLINE_MS,
  DMARCBIS_EXTERNAL_AUTHORIZATION_DEADLINE_MS,
  DMARCBIS_PRIMARY_BUDGET_MS,
  budgetRefusedDmarcbisExternal,
  runDmarcbisCore,
  runDmarcbisExternalRuaPhase,
} from "../workers/scan-api/src/engines/dmarcbis-production.js";
import {
  createOutboundAccounting,
  dnsCacheKey,
  makeDnsCache,
  SCAN_DEADLINE_DEFAULTS,
  SCAN_MODULE_BUDGETS,
} from "../workers/scan-api/src/engines/scan-budget.js";
import { dnsQuery } from "../workers/scan-api/src/engines/dns.js";
import {
  applyDmarcbisEmailCompatibilityProjection,
  runEmailModule,
} from "../workers/scan-api/src/engines/email-scan.js";
import { buildScanQuality } from "../workers/scan-api/src/engines/scan-engine.js";
import {
  deriveSignalMonitoringStates,
} from "../workers/scan-api/src/engines/signal-monitoring-state.js";
import {
  deriveDmarcPolicyConditions,
  dmarcPolicyConditionRecordId,
  establishDmarcPolicyBaseline,
} from "../workers/scan-api/src/engines/email-protection-lifecycle.js";
import { parseDmarcbisPolicyRecord } from "../workers/scan-api/src/engines/dmarcbis-parser.js";
import { parseDmarcAggregateXml } from "../workers/scan-api/src/lib/dmarc-ingest.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
let pass = 0;
let fail = 0;
const failures = [];
const ok = (name, condition, detail = "") => {
  if (condition) {
    pass += 1;
    console.log(`ok - ${name}`);
  } else {
    fail += 1;
    const message = `${name}${detail ? `: ${detail}` : ""}`;
    failures.push(message);
    console.error(`not ok - ${message}`);
  }
};
const eq = (name, actual, expected) =>
  ok(
    name,
    JSON.stringify(actual) === JSON.stringify(expected),
    `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
  );

const NODATA = Object.freeze({ Status: 0, Answer: [] });
const TXT = (...values) => ({
  Status: 0,
  Answer: values.map((data) => ({ type: 16, data })),
});

// ── R1 exact time/subrequest allocation and whole-scan envelope ────────────
eq("core hard phase allocation is 750 ms", DMARCBIS_CORE_BUDGET_MS, 750);
eq("primary tree-walk boundary is 500 ms", DMARCBIS_PRIMARY_BUDGET_MS, 500);
eq("corroboration absolute boundary is 650 ms",
  DMARCBIS_CORROBORATION_DEADLINE_MS, 650);
eq("external-RUA optional allocation is 600 ms",
  DMARCBIS_EXTERNAL_RUA_BUDGET_MS, 600);
eq("external destination primary walk ends by 300 ms",
  DMARCBIS_EXTERNAL_PRIMARY_DEADLINE_MS, 300);
eq("external decisive corroboration ends by 400 ms",
  DMARCBIS_EXTERNAL_CORROBORATION_DEADLINE_MS, 400);
eq("external authorization pair ends by 525 ms",
  DMARCBIS_EXTERNAL_AUTHORIZATION_DEADLINE_MS, 525);
eq("one admitted external host reserves 11 questions",
  DMARCBIS_EXTERNAL_HOST_RESERVATION, 11);
eq("global executable budget remains 19 seconds",
  SCAN_DEADLINE_DEFAULTS.budgetMs, 19_000);
eq("global total ceiling remains 24 seconds",
  SCAN_DEADLINE_DEFAULTS.totalCeilingMs, 24_000);
eq("global finalisation reserve remains 5 seconds",
  SCAN_DEADLINE_DEFAULTS.finalizationReserveMs, 5_000);
const serializedEnvelope =
  SCAN_MODULE_BUDGETS.subdomains +
  SCAN_MODULE_BUDGETS.subdomain_takeover +
  SCAN_MODULE_BUDGETS.asset_exposure +
  SCAN_MODULE_BUDGETS.phase5_intelligence +
  SCAN_MODULE_BUDGETS.dmarc_external_rua +
  SCAN_MODULE_BUDGETS.cloud_storage_discovery;
eq("worst serialized network envelope is exactly 17,350 ms",
  serializedEnvelope, 17_350);
ok("serialized network envelope fits executable budget",
  serializedEnvelope < SCAN_DEADLINE_DEFAULTS.budgetMs);

// ── Invocation cache: in-flight dedupe and resolver/profile isolation ───────
{
  const originalFetch = globalThis.fetch;
  let calls = 0;
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  globalThis.fetch = async () => {
    calls += 1;
    await held;
    return new Response(JSON.stringify(NODATA), {
      status: 200,
      headers: { "content-type": "application/dns-json" },
    });
  };
  try {
    const cache = makeDnsCache();
    const accounting = createOutboundAccounting();
    const first = accounting.contextFor("dns");
    const second = accounting.contextFor("dmarc_core");
    const a = dnsQuery("_dmarc.example.test", "TXT", {
      cache,
      accounting: first,
    });
    const b = dnsQuery("_dmarc.example.test.", "txt", {
      cache,
      accounting: second,
    });
    await Promise.resolve();
    eq("concurrent identical DNS consumers launch one provider request", calls, 1);
    release();
    const [av, bv] = await Promise.all([a, b]);
    first.markSettled();
    second.markSettled();
    eq("first cache consumer is the miss", av.cache_disposition, "miss");
    eq("second cache consumer joins the in-flight promise",
      bv.cache_disposition, "in_flight_hit");
    const aggregate = accounting.aggregate({
      required: ["dns", "dmarc_core"],
    });
    eq("shared cache physical accounting counts one attempt",
      aggregate.outbound_attempts_observed, 1);
    eq("shared cache accounting remains complete",
      aggregate.outbound_measurement_complete, true);
  } finally {
    globalThis.fetch = originalFetch;
  }

  ok("Cloudflare and Google keys are disjoint",
    dnsCacheKey("Example.TEST.", "txt", "cloudflare") !==
      dnsCacheKey("example.test", "TXT", "google"));
  ok("ordinary and DNSSEC Cloudflare keys are disjoint",
    dnsCacheKey("example.test", "A", "cloudflare", "default") !==
      dnsCacheKey("example.test", "A", "cloudflare", "do1"));
}

// Lightweight direct callers retain their exact-record compatibility lookup;
// runScanEngine explicitly transfers ownership to the canonical core peer.
{
  const originalFetch = globalThis.fetch;
  const exactQuestions = [];
  globalThis.fetch = async (url) => {
    const parsed = new URL(url);
    const name = parsed.searchParams.get("name");
    const type = parsed.searchParams.get("type");
    if (name === "_dmarc.example.test" && type === "TXT") {
      exactQuestions.push(name);
      return new Response(JSON.stringify(
        TXT("v=DMARC1; p=reject"),
      ), { status: 200, headers: { "content-type": "application/json" } });
    }
    return new Response(JSON.stringify(NODATA), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  try {
    const direct = await runEmailModule("example.test");
    eq("unwired lightweight caller retains legacy exact DMARC policy",
      direct.dmarc.policy, "reject");
    eq("unwired lightweight caller issues one exact DMARC question",
      exactQuestions.length, 1);

    exactQuestions.length = 0;
    await runEmailModule("example.test", {
      cache: makeDnsCache(),
      dmarcOwnedByCore: true,
    });
    eq("canonical scan caller issues no third exact DMARC question",
      exactQuestions.length, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
}

// ── Complete production core and deterministic provider timeout ────────────
{
  const questions = [];
  const provider = async (name, type) => {
    questions.push({ name, type });
    if (name === "_dmarc.example.test") {
      return TXT("v=DMARC1; p=reject; rua=mailto:agg@example.test");
    }
    return NODATA;
  };
  const core = await runDmarcbisCore("example.test", {
    primaryProvider: provider,
    secondaryProvider: provider,
  });
  eq("complete production core publishes complete", core.core_completeness, "complete");
  eq("complete production core derives reject", core.effective_requested_policy, "reject");
  ok("complete production core remains inside ten logical questions",
    core.lookup_path.length <= 10, `issued ${core.lookup_path.length}`);
  eq("core evidence never claims receiver enforcement",
    core.receiver_enforcement_observed, false);
  eq("complete core reaches resolved-state grade",
    core.evidence_grade.grade, "L3");
  eq("core grade preserves repeat-confirmed honesty",
    core.evidence_grade.repeat_confirmed, false);
  eq("core RUA authorization starts incomplete before optional phase",
    core.rua_authorisation_completeness, "incomplete");
  const exactCompatibility = applyDmarcbisEmailCompatibilityProjection(
    "example.test",
    {},
    core,
  );
  eq("production core projects the exact legacy p without inheritance",
    exactCompatibility.dmarc.policy, "reject");
  eq("production core retains the exact legacy raw record",
    exactCompatibility.dmarc.record,
    "v=DMARC1; p=reject; rua=mailto:agg@example.test");
  const transportAction = { id: "tls_rpt_missing" };
  exactCompatibility.remediation_actions = [transportAction];
  applyDmarcbisEmailCompatibilityProjection(
    "example.test",
    exactCompatibility,
    { ...core, rua_authorisation_completeness: "complete" },
  );
  eq("external-phase reprojection preserves Phase-5 transport remediation",
    exactCompatibility.remediation_actions, [transportAction]);

  const timerAllocations = [];
  const never = () => new Promise(() => {});
  const timedOut = await runDmarcbisCore("slow.example.test", {
    primaryProvider: never,
    secondaryProvider: never,
    now: () => 0,
    setTimer: (callback, milliseconds) => {
      timerAllocations.push(milliseconds);
      queueMicrotask(callback);
      return timerAllocations.length;
    },
    clearTimer: () => {},
  });
  eq("provider timeout is unavailable, never absent",
    timedOut.observation_state, "unavailable");
  eq("provider timeout withholds requested policy",
    timedOut.effective_requested_policy, null);
  eq("provider timeout makes core unavailable",
    timedOut.core_completeness, "unavailable");
  ok("deterministic timeout fixture exercised the 500/750 boundaries",
    timerAllocations.includes(500) && timerAllocations.includes(750),
    JSON.stringify(timerAllocations));
}

// ── Legacy projection stays exact-only until the P3/P6 dual-reader rollout ─
{
  const inherited = applyDmarcbisEmailCompatibilityProjection(
    "mail.example.test",
    {},
    {
      core_completeness: "complete",
      observed_at: "2026-07-25T00:00:00.000Z",
      policy_source_kind: "organisational",
      policy_source_domain: "example.test",
      effective_requested_policy: "reject",
      lookup_path: [{
        question: {
          ordinal: 1,
          resolver: "primary",
          purpose: "policy_tree_walk",
        },
        record_set: { candidates: [], selected: null },
      }],
    },
  );
  eq("inherited policy never fills legacy exact policy",
    inherited.dmarc.policy, null);
  eq("inherited policy never silently changes legacy ADR-003 state",
    inherited.dmarc_state.enforcement_level, "no_record");

  const testing = applyDmarcbisEmailCompatibilityProjection(
    "example.test",
    {},
    {
      core_completeness: "complete",
      effective_requested_policy: "quarantine",
      lookup_path: [{
        question: {
          ordinal: 1,
          resolver: "primary",
          purpose: "policy_tree_walk",
        },
        record_set: {
          candidates: [{ value: "v=DMARC1; p=reject; t=y" }],
          selected: { p: { normalized: "reject" } },
        },
      }],
    },
  );
  eq("canonical testing adjustment does not reinterpret legacy exact p",
    testing.dmarc.policy, "reject");
  eq("legacy ADR-003 state remains based on exact parser semantics",
    testing.dmarc_state.enforcement_level, "reject_enforced");
}

// ── External RUA: complete, core-only refusal, and no false healthy ─────────
{
  const parsed = parseDmarcbisPolicyRecord(
    "v=DMARC1; p=reject; rua=mailto:agg@reports.vendor.test",
  );
  const policyEvidence = {
    schema: "dmarc-policy.v2",
    policy_source_domain: "example.test",
    organisational_domain: "example.test",
    rua_destinations: parsed.rua,
  };
  let providerCalls = 0;
  const provider = async (name) => {
    providerCalls += 1;
    if (name === "_dmarc.vendor.test") {
      return TXT("v=DMARC1; p=none; psd=n");
    }
    if (name === "example.test._report._dmarc.reports.vendor.test") {
      return TXT("v=DMARC1");
    }
    return NODATA;
  };
  let reservations = 0;
  const complete = await runDmarcbisExternalRuaPhase(policyEvidence, {
    primaryProvider: provider,
    secondaryProvider: provider,
    reserveHost: ({ questions }) => {
      reservations += 1;
      return questions === 11;
    },
  });
  eq("external host is fully reserved once", reservations, 1);
  ok("external host uses no more than its 11-question reservation",
    providerCalls <= 11, `issued ${providerCalls}`);
  eq("valid RFC 9990 record authorizes destination",
    complete.destinations[0].authorization_status, "authorized");
  eq("complete external assessment publishes complete",
    complete.rua_authorisation_completeness, "complete");
  eq("complete external assessment may say all authorized",
    complete.all_destinations_authorized, true);
  eq("external authorization keeps Item 5 trust gate",
    complete.trusted_ingestion_status, "item5_gate_unchanged");
  eq("complete external authorization reaches resolved-state grade",
    complete.evidence_grade.grade, "L3");
  eq("per-destination authorization carries the unchanged grade contract",
    Object.keys(complete.destinations[0].evidence_grade).sort(),
    [
      "basis",
      "beta_target",
      "degrade_behavior",
      "grade",
      "limits",
      "minimum_publishable",
      "observable_ceiling",
      "observed_at",
      "repeat_confirmed",
      "required_corroboration",
      "source_type",
    ]);

  const callsBeforeRefusal = providerCalls;
  const refused = await budgetRefusedDmarcbisExternal(
    policyEvidence,
    "subrequest_budget",
  );
  eq("budget refusal issues no provider query", providerCalls, callsBeforeRefusal);
  eq("budget refusal is explicitly incomplete",
    refused.rua_authorisation_completeness, "incomplete");
  eq("budget refusal never says all destinations authorized",
    refused.all_destinations_authorized, null);
  eq("budget refusal retains the reason",
    refused.assessment_reason, "subrequest_budget");
  eq("unissued budget-refused authorization stays L0",
    refused.evidence_grade.grade, "L0");
  eq("budget-refused external component degrades canonical monitoring state",
    attachDmarcbisExternalResult({
      core_completeness: "complete",
      monitoring_state: "monitoring_healthy",
    }, refused).monitoring_state,
    "monitoring_degraded");

  const externalTimeout = await runDmarcbisExternalRuaPhase(
    policyEvidence,
    {
      primaryProvider: () => new Promise(() => {}),
      secondaryProvider: () => new Promise(() => {}),
      reserveHost: () => true,
      now: () => 0,
      setTimer: (callback) => {
        queueMicrotask(callback);
        return 1;
      },
      clearTimer: () => {},
    },
  );
  eq("external provider timeout is incomplete",
    externalTimeout.rua_authorisation_completeness, "incomplete");
  eq("external provider timeout never becomes unauthorized",
    externalTimeout.destinations[0].authorization_status, "unavailable");
  eq("external provider timeout never says all authorized",
    externalTimeout.all_destinations_authorized, null);
  eq("external provider timeout retains its degradation reason",
    externalTimeout.assessment_reason, "provider_timeout");

  const coreOnlyModule = {
    core_completeness: "complete",
    outcome: "degraded",
    degraded: true,
  };
  eq("optional external incompleteness does not make scan_quality partial",
    buildScanQuality({
      dns: {},
      ssl: {},
      headers: {},
      email_security: {},
      dmarc_core: coreOnlyModule,
    }).status,
    "complete");
  const monitoring = deriveSignalMonitoringStates({
    modules: {
      email_security: {},
      dmarc_core: coreOnlyModule,
      email_security_intelligence: {},
    },
    scanQuality: { status: "complete", modules_skipped: [] },
  });
  eq("optional external incompleteness degrades Email monitoring honestly",
    monitoring.signals.email_protection.state, "monitoring_degraded");
  eq("unavailable core becomes incomplete Email evidence, never healthy",
    deriveSignalMonitoringStates({
      modules: {
        email_security: {},
        dmarc_core: {
          core_completeness: "unavailable",
          outcome: "unavailable",
          incomplete: true,
        },
        email_security_intelligence: {},
      },
      scanQuality: { status: "partial", modules_skipped: ["dmarc_core"] },
    }).signals.email_protection.state,
    "evidence_incomplete");
}

// ── Migration-088 lifecycle reuse: identity, baseline, tenant, soft delete ──
class LifecycleDb {
  constructor() {
    this.live = new Set(["ws-a|dom-a|example.test", "ws-b|dom-a|example.test"]);
    this.events = [];
    this.batchCalls = 0;
  }
  prepare(sql) {
    const statement = {
      sql,
      values: [],
      bind: (...values) => { statement.values = values; return statement; },
      first: async () => {
        if (!sql.includes("FROM workspace_domains")) return null;
        const [workspace, domainId, domain] = statement.values;
        return this.live.has(`${workspace}|${domainId}|${String(domain).toLowerCase()}`)
          ? { domain_id: domainId }
          : null;
      },
      all: async () => {
        if (!sql.includes("FROM email_protection_events")) return { results: [] };
        const [workspace, recordType, ...recordIds] = statement.values;
        return {
          results: this.events
            .filter((event) =>
              event.workspace_id === workspace &&
              event.record_type === recordType &&
              recordIds.includes(event.record_id))
            .map((event) => ({
              record_id: event.record_id,
              event_type: event.event_type,
            })),
        };
      },
      run: async () => ({ success: true }),
    };
    return statement;
  }
  async batch(statements) {
    this.batchCalls += 1;
    for (const statement of statements) {
      const [
        id,
        record_id,
        record_type,
        workspace_id,
        event_type,
        detail_json,
      ] = statement.values;
      if (this.events.some((event) => event.id === id)) continue;
      this.events.push({
        id,
        record_id,
        record_type,
        workspace_id,
        event_type,
        detail_json,
      });
    }
    return statements.map(() => ({ success: true }));
  }
}

{
  const baseEvidence = {
    schema: "dmarc-policy.v2",
    methodology_version: "rfc9989-treewalk-v1",
    author_domain: "example.test",
    core_completeness: "complete",
    observation_state: "present_valid",
    record_validity: "valid",
    policy_source_domain: "example.test",
    effective_requested_policy: "none",
    effective_policy_tag: "p",
    inheritance_reason: "exact_p",
    rua_authorisation_completeness: "not_applicable",
    external_rua_authorisation: null,
    lookup_path: [],
  };
  const conditions = deriveDmarcPolicyConditions(baseEvidence);
  eq("no-action policy creates one stable weak condition",
    conditions.map((condition) => condition.condition_type), ["weak"]);
  const defectConditions = deriveDmarcPolicyConditions({
    ...baseEvidence,
    observation_state: "multiple",
    record_validity: "invalid",
    policy_source_domain: null,
    effective_requested_policy: null,
    effective_policy_tag: null,
    inheritance_reason: "none",
    lookup_path: [
      {
        question: {
          resolver: "primary",
          purpose: "policy_tree_walk",
          name: "_dmarc.example.test",
        },
        record_set: { raw_state: "multiple_mixed" },
      },
      {
        question: {
          resolver: "primary",
          purpose: "policy_tree_walk",
          name: "_dmarc.test",
        },
        record_set: { raw_state: "single_invalid_duplicate_tag" },
      },
    ],
  });
  eq("complete malformed/multiple evidence never also becomes missing",
    defectConditions.map((condition) => condition.condition_type).sort(),
    ["malformed", "multiple"]);
  const missingConditions = deriveDmarcPolicyConditions({
    ...baseEvidence,
    observation_state: "absent",
    record_validity: "absent",
    policy_source_domain: null,
    effective_requested_policy: null,
    effective_policy_tag: null,
    inheritance_reason: "no_applicable_policy",
  });
  eq("complete no-policy evidence maps to the missing stable family",
    missingConditions.map((condition) => condition.condition_type),
    ["missing"]);
  const ruaCondition = deriveDmarcPolicyConditions({
    ...baseEvidence,
    effective_requested_policy: "reject",
    rua_authorisation_completeness: "complete",
    external_rua_authorisation: {
      destinations: [{
        authorization_status: "unauthorized",
        authorization_query_name:
          "example.test._report._dmarc.reports.vendor.test",
        normalized_uri: "mailto:agg@reports.vendor.test",
      }],
    },
  });
  eq("definitive unauthorized destination maps to its stable family",
    ruaCondition.map((condition) => condition.condition_type),
    ["unauthorised_rua"]);
  eq("incomplete authorization cannot create unauthorized condition",
    deriveDmarcPolicyConditions({
      ...baseEvidence,
      effective_requested_policy: "reject",
      rua_authorisation_completeness: "incomplete",
      external_rua_authorisation: {
        destinations: [{
          authorization_status: "unauthorized",
          authorization_query_name:
            "example.test._report._dmarc.reports.vendor.test",
        }],
      },
    }).length,
    0);
  const firstId = await dmarcPolicyConditionRecordId({
    domain_id: "dom-a",
    condition_type: "weak",
    subject_key: "Example.Test.",
  });
  const secondId = await dmarcPolicyConditionRecordId({
    domain_id: "dom-a",
    condition_type: "weak",
    subject_key: "example.test",
  });
  eq("condition ID is deterministic across canonical-equivalent subjects",
    firstId, secondId);
  ok("condition ID is disjoint from hosted/sender namespaces",
    firstId.startsWith("dmarc:") &&
      !firstId.startsWith("hd-") &&
      !firstId.startsWith("esender_"));

  const db = new LifecycleDb();
  const env = { cybermeters_db: db };
  const seeded = await establishDmarcPolicyBaseline(env, {
    workspace_id: "ws-a",
    domain_id: "dom-a",
    domain: "example.test",
    scan_id: "scan-a",
    policy_evidence: baseEvidence,
  });
  eq("first complete observation creates domain + condition baselines",
    seeded.inserted, 2);
  ok("baseline rows reuse only dmarc_policy_condition record_type",
    db.events.every((event) => event.record_type === "dmarc_policy_condition"));
  ok("baseline rows cannot be alert occurrences",
    db.events.every((event) => event.event_type !== "monitoring_changed"));
  ok("baseline detail contains no raw RRset",
    db.events.every((event) =>
      !/raw_records|lookup_path|record_set/.test(event.detail_json)));

  const retry = await establishDmarcPolicyBaseline(env, {
    workspace_id: "ws-a",
    domain_id: "dom-a",
    domain: "example.test",
    scan_id: "scan-a-retry",
    policy_evidence: baseEvidence,
  });
  eq("retry does not duplicate a baseline", retry.inserted, 0);
  const otherTenant = await establishDmarcPolicyBaseline(env, {
    workspace_id: "ws-b",
    domain_id: "dom-a",
    domain: "example.test",
    scan_id: "scan-b",
    policy_evidence: baseEvidence,
  });
  eq("same domain in another tenant gets its own baseline",
    otherTenant.inserted, 2);
  eq("each tenant owns exactly its two baseline rows",
    db.events.filter((event) => event.workspace_id === "ws-a").length, 2);
  eq("cross-tenant baseline rows are independently scoped",
    db.events.filter((event) => event.workspace_id === "ws-b").length, 2);

  const beforeInactive = db.events.length;
  const inactive = await establishDmarcPolicyBaseline(env, {
    workspace_id: "ws-deleted",
    domain_id: "dom-a",
    domain: "example.test",
    scan_id: "scan-deleted",
    policy_evidence: baseEvidence,
  });
  eq("soft-deleted/unlinked workspace is rejected",
    inactive.skipped, "workspace_or_domain_inactive");
  eq("inactive workspace receives no event", db.events.length, beforeInactive);
  // P4 activates the migration-088 DMARC timeline read surface. P2 continues
  // to prove only that its first-observation rows are non-occurrence baselines;
  // P4's real D1/R2 validator owns visibility, pagination, and wording.
}

// ── RFC 9990 aggregate metadata + RFC 7489 history compatibility ────────────
function aggregateXml({
  namespace = "",
  version = "",
  policyExtra = "",
  pct = "",
} = {}) {
  return `<?xml version="1.0"?>
<feedback${namespace ? ` xmlns="${namespace}"` : ""}>
${version ? `<version>${version}</version>` : ""}
<report_metadata>
  <org_name>Example Reporter</org_name>
  <email>dmarc@example.net</email>
  <report_id>report-1</report_id>
  <date_range><begin>1700000000</begin><end>1700003600</end></date_range>
</report_metadata>
<policy_published>
  <domain>example.test</domain><p>reject</p>${policyExtra}${pct}
</policy_published>
<record>
  <row><source_ip>192.0.2.1</source_ip><count>1</count>
    <policy_evaluated><disposition>reject</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated>
  </row>
  <identifiers><header_from>example.test</header_from></identifiers>
  <auth_results><dkim><domain>example.test</domain><selector>s1</selector><result>pass</result></dkim></auth_results>
</record>
</feedback>`;
}

{
  const modern = parseDmarcAggregateXml(aggregateXml({
    namespace: "urn:ietf:params:xml:ns:dmarc-2.0",
    version: "1.0",
    policyExtra:
      "<sp>quarantine</sp><np>none</np><fo>1:d</fo><testing>y</testing><discovery_method>treewalk</discovery_method>",
  }));
  eq("RFC 9990 parser preserves namespace",
    modern.metadata.xml_namespace, "urn:ietf:params:xml:ns:dmarc-2.0");
  eq("RFC 9990 parser preserves format version",
    modern.metadata.report_format_version, "1.0");
  eq("RFC 9990 parser preserves discovery method",
    modern.policy_published.discovery_method, "treewalk");
  eq("RFC 9990 parser preserves np", modern.policy_published.np, "none");
  eq("RFC 9990 parser preserves testing", modern.policy_published.testing, "y");
  eq("RFC 9990 parser preserves fo", modern.policy_published.fo, "1:d");
  eq("RFC 9990 parser does not overclaim full XSD validation",
    modern.metadata.schema_conformance,
    "rfc9990_profile_accepted_not_full_xsd");
  ok("aggregate parser stamps a stable parser version",
    modern.metadata.parser_version === "dmarc-aggregate-rfc9990-v1");

  const legacy = parseDmarcAggregateXml(aggregateXml({
    pct: "<pct>25</pct>",
  }));
  eq("legacy aggregate pct remains preserved", legacy.policy_published.pct, 25);
  eq("legacy row receives no invented format version",
    legacy.metadata.report_format_version, null);
  eq("legacy row receives no invented namespace",
    legacy.metadata.xml_namespace, null);
  const wrongVersion = parseDmarcAggregateXml(aggregateXml({
    namespace: "urn:ietf:params:xml:ns:dmarc-2.0",
    version: "2.0",
  }));
  eq("RFC 9990 non-1.0 version fails closed",
    wrongVersion.error, "unsupported_version");
  const futureDiscovery = parseDmarcAggregateXml(aggregateXml({
    namespace: "urn:ietf:params:xml:ns:dmarc-2.0",
    version: "1.0",
    policyExtra: "<discovery_method>future-walk</discovery_method>",
  }));
  eq("unknown discovery method raw token is preserved",
    futureDiscovery.policy_published.discovery_method, "future-walk");
  eq("unknown discovery method receives no current semantics",
    futureDiscovery.policy_published.discovery_method_state,
    "unknown_preserved");
}

// ── Static architecture guards: no third observation concept or P4/P5 leak ─
{
  const migration = fs.readFileSync(
    path.join(root, "database/migrations/101-dmarcbis-aggregate-metadata.sql"),
    "utf8",
  );
  for (const column of [
    "report_format_version",
    "xml_namespace",
    "discovery_method",
    "policy_np",
    "policy_testing",
    "policy_fo",
    "schema_conformance",
    "parser_version",
  ]) {
    ok(`migration 101 adds nullable ${column}`,
      migration.includes(`ADD COLUMN ${column} TEXT`));
  }
  ok("migration 101 creates no table", !/CREATE\s+TABLE/i.test(migration));
  ok("migration 101 never removes legacy pct", !/DROP|DELETE|UPDATE/i.test(migration));

  const occurrenceSource = fs.readFileSync(
    path.join(root, "workers/scan-api/src/engines/alert-occurrence.js"),
    "utf8",
  );
  ok("P2 adds no dmarc lifecycle source",
    !/^[ \t]*dmarc\s*:/m.test(occurrenceSource));
  ok("existing Email Protection occurrence source remains canonical",
    /email_protection:\s*\{\s*table: "email_protection_events"/.test(
      occurrenceSource,
    ));

  const allMigrationNames = fs.readdirSync(
    path.join(root, "database/migrations"),
  );
  ok("P2 creates no dmarc policy table migration",
    !allMigrationNames.some((name) => /dmarc_policy_(?:observation|condition)/.test(name)));
  const purgeSource = fs.readFileSync(
    path.join(root, "workers/scan-api/src/index.js"),
    "utf8",
  );
  ok("migration-088 event source remains in workspace purge order",
    purgeSource.includes('"email_protection_events"'));

  const scanEngine = fs.readFileSync(
    path.join(root, "workers/scan-api/src/engines/scan-engine.js"),
    "utf8",
  );
  ok("P2 production caller uses the production adapter",
    scanEngine.includes('from "./dmarcbis-production.js"'));
  ok("P2 has no DMARC alert or managed-case activation",
    !/emitLifecycleAlert\([^)]*dmarc|createManagedCase\([^)]*dmarc/s.test(
      scanEngine,
    ));
}

console.log(`\nDMARCbis P2 fixtures: ${pass} passed, ${fail} failed`);
if (fail) {
  console.error(failures.map((failure) => ` - ${failure}`).join("\n"));
  process.exit(1);
}
