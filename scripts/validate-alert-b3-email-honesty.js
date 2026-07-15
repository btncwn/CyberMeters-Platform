#!/usr/bin/env node
//
// PR-B3 — Email Protection alert HONESTY + legacy replacement. CI-blocking.
//
// The behavioural suite (validate-alert-b3-email-protection.js) proves the engine
// does the right thing. This proves it CANNOT do the wrong things — the ones no
// behavioural test would catch because they are about what is absent:
//
//   • posture must never become an alert (it has no persisted identity);
//   • cumulative counters must never be a threshold (they latch true forever);
//   • no engine may hold a sender;
//   • audit_events must never be an occurrence source;
//   • the customer-facing claim must not exceed the evidence.
//
// Static analysis on purpose: these are structural guarantees, and a structural
// guarantee is worth more than a test that happened to pass today.
//
// Node 24+.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const enginesDir = path.join(root, "workers", "scan-api", "src", "engines");
const eng = (f) => pathToFileURL(path.join(enginesDir, f)).href;

const { LIFECYCLE_EVENT_SOURCES } = await import(eng("alert-occurrence.js"));
const { severityForRecurrence } = await import(eng("alert-consumers.js"));
const { REMEDIATION_REGISTRY, VERIFICATION_METHOD, resolveRemediation } = await import(eng("remediation-registry.js"));
const { EMAIL_RECURRENCES, NON_ALERTABLE_EVENT_TYPES } = await import(eng("email-protection-lifecycle.js"));

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

// Comments are stripped before every source assertion: this file's own prose
// mentions the very identifiers it bans, and so does the engine's. An assertion
// that a banned call is "absent" must look at CODE, not at a comment explaining
// why it is absent.
const readCode = (rel) => fs.readFileSync(path.join(root, rel), "utf8")
  .split("\n").filter((l) => !l.trim().startsWith("//")).join("\n");
const exists = (rel) => fs.existsSync(path.join(root, rel));

const LIFECYCLE = "workers/scan-api/src/engines/email-protection-lifecycle.js";
const HOSTED = "workers/scan-api/src/engines/hosted-dmarc.js";

// ── 1. The legacy sweep is GONE, not merely unwired ──────────────────────────
{
  ok("the legacy dmarc-alerts.js engine is deleted", !exists("workers/scan-api/src/engines/dmarc-alerts.js"));
  ok("its legacy validator is deleted", !exists("scripts/validate-dmarc-alerts.js"));

  const index = readCode("workers/scan-api/src/index.js");
  ok("index.js no longer imports the legacy sweep", !/dmarc-alerts\.js/.test(index));
  ok("index.js no longer registers runDmarcAlertsSweep", !/runDmarcAlertsSweep/.test(index));

  const cron = readCode("workers/scan-api/src/cron/scheduled.js");
  ok("the cron no longer schedules the legacy sweep", !/runDmarcAlertsSweep/.test(cron));
  // The replacement is deliberately NOT a sweep: evaluation is driven by new
  // evidence arriving, so it cannot fire without new evidence.
  ok("no email alert sweep was re-added to the cron", !/dmarc_alerts_sweep/.test(cron));

  const ci = fs.readFileSync(path.join(root, ".github/workflows/ci.yml"), "utf8");
  ok("CI no longer runs the deleted validator", !/validate-dmarc-alerts\.js/.test(ci));
  ok("CI runs the canonical B3 behavioural suite", /validate-alert-b3-email-protection\.js/.test(ci));
  ok("CI runs the canonical B3 honesty suite", /validate-alert-b3-email-honesty\.js/.test(ci));

  // Sender evaluation is bound to ingestion — the only moment the evidence moves.
  const ingest = readCode("workers/scan-api/src/lib/dmarc-ingest.js");
  ok("sender evaluation runs when a new report is ingested", /evaluateEmailSenderMonitoring\(/.test(ingest));
}

// ── 2. No engine holds a sender ─────────────────────────────────────────────
{
  const hosted = readCode(HOSTED);
  ok("hosted-dmarc.js no longer delivers alerts directly", !/deliverWorkspaceAlert\(/.test(hosted),
     "a domain engine that sends bypasses occurrence, baseline, dedupe and the ledger");
  ok("hosted-dmarc.js does not import a sender", !/from "\.\/alerts\.js"/.test(hosted));
  ok("hosted-dmarc.js does not hand-roll notifications", !/createNotificationEvent\(/.test(hosted));
  ok("hosted-dmarc.js does not bypass the watermark", !/emitManagedAlert\(/.test(hosted));
  ok("hosted-dmarc.js alerts only through the canonical lifecycle engine", /recordHostedTransition\(/.test(hosted));

  const lifecycle = readCode(LIFECYCLE);
  ok("the lifecycle engine does not hold a sender", !/deliverWorkspaceAlert\(/.test(lifecycle));
  ok("the lifecycle engine does not hand-roll notifications", !/createNotificationEvent\(/.test(lifecycle));
  ok("the lifecycle engine does not call emitManagedAlert directly", !/emitManagedAlert\(/.test(lifecycle),
     "a direct emit with no occurrence bypasses the activation watermark");
  ok("the lifecycle engine goes through the canonical consumer", /emitLifecycleAlert\(/.test(lifecycle));

  // The email SCAN engines observe posture. They must never alert on it.
  for (const f of ["email-scan.js", "email-analysis.js", "email-intel.js"]) {
    const src = readCode(`workers/scan-api/src/engines/${f}`);
    ok(`${f} raises no alert`, !/emitLifecycleAlert\(|deliverWorkspaceAlert\(|createNotificationEvent\(|emitManagedAlert\(/.test(src));
    ok(`${f} persists nothing`, !/INSERT INTO|UPDATE /.test(src),
       "posture has no persisted identity — that is precisely why it cannot alert");
  }
}

// ── 3. audit_events is audit history, NEVER occurrence identity ─────────────
{
  const sources = Object.values(LIFECYCLE_EVENT_SOURCES).map((s) => s.table);
  ok("no domain resolves occurrences from audit_events", !sources.includes("audit_events"));
  eq("email_protection resolves from its own dedicated table",
     LIFECYCLE_EVENT_SOURCES.email_protection?.table, "email_protection_events");

  const hosted = readCode(HOSTED);
  // The audit write stays — it is the audit trail. What must not return is the
  // audit_events LOOKUP that used to gate the alert, which re-alerted daily.
  ok("hosted-dmarc.js still writes audit history", /createAuditEvent\(/.test(hosted));
  ok("hosted-dmarc.js no longer reads audit_events to gate an alert",
     !/SELECT id FROM audit_events/.test(hosted),
     "audit_events must never be consulted for identity");

  const lifecycle = readCode(LIFECYCLE);
  ok("the lifecycle engine never reads audit_events", !/audit_events/.test(lifecycle));
}

// ── 4. Cumulative counters must never be a threshold ────────────────────────
// email_sender_sources.failed_messages / total_messages are LIFETIME totals that
// never decrease. A threshold on them latches true forever and recovery becomes
// mathematically inexpressible — the exact defect the legacy sweep shipped with.
{
  const lifecycle = readCode(LIFECYCLE);
  ok("the engine never reads the cumulative failure counter",
     !/\bfailed_messages\b/.test(lifecycle),
     "cumulative counters never decrease: a threshold on them can never recover");
  ok("the engine never reads the cumulative total counter",
     !/\btotal_messages\b/.test(lifecycle));
  ok("the engine never reads the cumulative aligned counter",
     !/\baligned_messages\b/.test(lifecycle));

  // Volumes come from the append-only, receiver-reported evidence, windowed.
  ok("volumes come from the append-only aggregate records", /dmarc_aggregate_records/.test(lifecycle));
  ok("the window is bounded by the report's own date range", /date_range_end\s*>=/.test(lifecycle));
  // Alignment must be defined EXACTLY as the ingest defines it, or the alert
  // would contradict the sender inventory the customer is reading.
  const ingest = readCode("workers/scan-api/src/lib/dmarc-ingest.js");
  ok("ingest defines aligned as spf OR dkim pass",
     /spf_aligned_result === "pass" \|\| r\.dkim_aligned_result === "pass"/.test(ingest));
  ok("the engine uses the SAME alignment definition",
     /spf_aligned_result = 'pass' OR r\.dkim_aligned_result = 'pass'/.test(lifecycle));
}

// ── 5. Posture can never become an alert ────────────────────────────────────
{
  // A representative sample of real posture finding types. None may be gradable.
  const POSTURE = [
    "email_missing_dmarc", "email_dmarc_policy_none", "email_missing_spf",
    "email_intel_dmarc_missing", "email_intel_spf_permissive", "email_intel_dkim_not_found",
    "email_intel_mta_sts_missing", "email_intel_tls_rpt_missing", "bimi_not_configured",
    "dmarc_missing", "spf_missing", "dkim_verification_uncertain",
  ];
  for (const ft of POSTURE) {
    ok(`posture '${ft}' is not a gradable recurrence`, severityForRecurrence("email_protection", ft) === null);
    ok(`posture '${ft}' is not an actionable B3 recurrence`, !EMAIL_RECURRENCES.includes(ft));
  }
  // …but it MUST still resolve to remediation: posture is real advice, it simply
  // is not an ALERT. Removing the entries would be the opposite error.
  for (const ft of ["email_missing_dmarc", "email_missing_spf", "bimi_not_configured"]) {
    ok(`posture '${ft}' still resolves to canonical remediation`, resolveRemediation({ finding_type: ft })?.status === "resolved");
  }
}

// ── 6. Confirmations are structurally unable to alert ───────────────────────
{
  for (const t of NON_ALERTABLE_EVENT_TYPES) {
    ok(`'${t}' has no severity, so it cannot be graded`, severityForRecurrence("email_protection", t) === null);
    ok(`'${t}' is not an actionable recurrence`, !EMAIL_RECURRENCES.includes(t));
    // The founder decision: no "no action required" remediation entries.
    ok(`'${t}' has no remediation entry`, resolveRemediation({ finding_type: t })?.status !== "resolved");
  }
  const lifecycle = readCode(LIFECYCLE);
  // A non-alertable event must not be `monitoring_changed`, or the resolver could
  // match it and the whole guarantee collapses.
  ok("baseline events are not monitoring_changed",
     /EMAIL_EVENT_BASELINE\s*=\s*"baseline_established"/.test(lifecycle));
  ok("recovery is not monitoring_changed",
     /EMAIL_EVENT_SENDER_RECOVERED\s*=\s*"sender_failures_recovered"/.test(lifecycle));
  eq("no non-alertable type collides with the occurrence marker",
     NON_ALERTABLE_EVENT_TYPES.filter((t) => t === "monitoring_changed"), []);

  // A customer's own action is never a risk alert.
  ok("a manual rollback is history, not an alert", severityForRecurrence("email_protection", "hosted_rolled_back_manual") === null);
  ok("an automatic rollback IS actionable", severityForRecurrence("email_protection", "hosted_rolled_back_auto") === "high");
}

// ── 7. The customer-facing claim must not exceed the evidence ───────────────
// DMARC aggregate reports prove an absolute count of failures inside a window,
// as reported by receivers. They do NOT prove a spike, an increase, an attack, or
// a successful spoof — we hold no prior-period baseline to compare against.
{
  const emailEntries = REMEDIATION_REGISTRY.filter((e) => e.domain_key === "email_protection");
  const B3_IDS = [
    "email.hosted_dmarc.reconnect", "email.hosted_dmarc.impact_review",
    "email.hosted_dmarc.auto_rollback_review",
    "email.sender.review_unrecognised", "email.sender.unauthorised_failures_active",
  ];
  for (const id of B3_IDS) {
    const e = emailEntries.find((x) => x.remediation_id === id);
    ok(`registry entry ${id} exists`, Boolean(e));
    if (!e) continue;
    ok(`${id} is active`, e.status === "active");
    ok(`${id} declares a known verification method`, VERIFICATION_METHOD.includes(e.verification_method));
    ok(`${id} states its limitations`, Array.isArray(e.limitations) && e.limitations.length > 0,
       "an evidence-led claim without its boundary is an overclaim");
  }

  // The banned vocabulary, checked on the customer-visible prose of every B3 entry.
  const BANNED = /\bspike\b|\bincreas(e|ed|ing)\b|\battack\b|\bspoofed\b|\bhacked\b|\bbreach(ed)?\b/i;
  for (const id of B3_IDS) {
    const e = emailEntries.find((x) => x.remediation_id === id);
    if (!e) continue;
    const prose = [e.customer_title, e.technical_explanation, e.business_impact, e.recommended_action].join(" ");
    ok(`${id} claims no spike / increase / attack`, !BANNED.test(prose),
       "the evidence is an absolute count in a window, not a comparison against a prior period");
  }

  // The dishonest recurrence name must not come back.
  ok("`sender_spoofing_spike` is not a recurrence", !EMAIL_RECURRENCES.includes("sender_spoofing_spike"));
  ok("`sender_spoofing_spike` has no severity", severityForRecurrence("email_protection", "sender_spoofing_spike") === null);
  const lifecycle = readCode(LIFECYCLE);
  ok("the engine does not use the word 'spike' in code", !/spoofing_spike/.test(lifecycle));

  // The honest one states the window and the source.
  const active = emailEntries.find((x) => x.remediation_id === "email.sender.unauthorised_failures_active");
  ok("the failures claim names the rolling window", /7 days|7-day/.test(
     [active?.technical_explanation, ...(active?.limitations || [])].join(" ")));
  ok("the failures claim attributes the evidence to receivers",
     /receiv(ing|ers?)/i.test([active?.technical_explanation, active?.business_impact].join(" ")));
  ok("the failures claim states it is not evidence of a spike",
     (active?.limitations || []).some((l) => /not evidence of a spike|not a spike/i.test(l)));

  // The hosted disconnect must not claim the domain is unprotected.
  const disc = emailEntries.find((x) => x.remediation_id === "email.hosted_dmarc.reconnect");
  ok("the disconnect claim does not assert the domain has no DMARC policy",
     (disc?.limitations || []).some((l) => /does not claim the domain has no DMARC policy/i.test(l)));

  // Customer assertion is not CyberMeters verification.
  const unrec = emailEntries.find((x) => x.remediation_id === "email.sender.review_unrecognised");
  ok("classifying a sender is recorded as a customer decision, not a verification",
     /not a CyberMeters verification/i.test(unrec?.verification_evidence_requirements || ""));
}

// ── 8. Purge + schema integrity ─────────────────────────────────────────────
{
  const index = readCode("workers/scan-api/src/index.js");
  ok("email_protection_events is purged with the workspace", /"email_protection_events"/.test(index));

  // SQL comments stripped: the migration's own prose explains WHY there is no
  // DROP COLUMN path, and a rollback note must not read as destructive DDL.
  const mig = fs.readFileSync(path.join(root, "database/migrations/088-email-protection-lifecycle.sql"), "utf8")
    .split("\n").filter((l) => !l.trim().startsWith("--")).join("\n");
  ok("088 creates the append-only event source", /CREATE TABLE IF NOT EXISTS email_protection_events/.test(mig));
  // The events MUST outlive the record they describe: hosted-dmarc.js hard-deletes
  // its row, so an FK would either block that delete or cascade the history away.
  ok("088 declares no FK to hosted_dns_entries", !/REFERENCES hosted_dns_entries/.test(mig));
  ok("088 declares no FK to email_sender_sources", !/REFERENCES email_sender_sources/.test(mig));
  ok("088 keeps the workspace FK for tenant integrity", /REFERENCES workspaces\(id\)/.test(mig));
  ok("088 is additive on the sender table", /ALTER TABLE email_sender_sources ADD COLUMN/.test(mig));
  ok("088 performs no destructive DDL", !/DROP TABLE|DROP COLUMN|DELETE FROM/.test(mig));

  // The hard delete this table has to survive is real — assert it still exists,
  // so the no-FK rule cannot be quietly "cleaned up" later.
  const hosted = readCode(HOSTED);
  ok("hosted_dns_entries really is hard-deleted (why there is no FK)",
     /DELETE FROM hosted_dns_entries/.test(hosted));
}

console.log(`\nalert-b3-email-honesty: ${pass} passed, ${fail} failed`);
if (fail > 0) { console.error("alert-b3-email-honesty validation FAILED"); process.exit(1); }
console.log("alert-b3-email-honesty validation passed");
