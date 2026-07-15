#!/usr/bin/env node
//
// PR-B2: certificate expiry alerts through the canonical pipeline. CI-blocking.
//
// The legacy cert_expiry trigger (engines/alerts.js) fired at 14 days by
// recomputing ssl.cert_expiry_days every scan. It persisted nothing, so there was
// no "this certificate started expiring at T" record: no occurrence, no
// domain_key, no dedupe_key, no activation watermark, no delivery ledger, and a
// racy read-then-write isAlertDuplicate. It is DELETED.
//
// Certificates & Trust already alerted on the same condition canonically and
// EARLIER — renewal_overdue from 30 days off the persisted certificate_lifecycle
// record. The legacy alert was a strictly worse duplicate arriving later.
//
// The 7-day escalation is preserved as band-driven severity on that SAME
// recurrence (no new alert type, no parallel recurrence):
//   30-8 days => renewal_overdue @ high
//   7-1  days => renewal_overdue @ critical
//   <=0  days => expired @ critical
//
// The mechanic that makes this work: a certificate at 30 days and the same one at
// 7 days are both `renewal_overdue`, so on status+recurrence alone NO transition is
// seen — no event, same occurrence id, same dedupe key, and the customer is never
// told it became urgent. `recurrence_band` is the third, OPTIONAL transition
// dimension. Absent on both sides it is "" !== "", so every other domain is
// untouched — asserted below.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href;

const report = console.log.bind(console);
let pass = 0, fail = 0;
const ok = (n, c) => { c ? pass++ : fail++; if (!c) report("FAIL " + n); };
const eq = (n, g, w) => ok(`${n} (got ${JSON.stringify(g)}, want ${JSON.stringify(w)})`, g === w);

const { renewalAlertBand, RENEWAL_ALERT_CRITICAL_DAYS, RENEWAL_START_BY_DAYS } = await import(eng("certificate-policy.js"));
const { isMonitoringTransition } = await import(eng("alert-occurrence.js"));
const { severityForRecurrence, INHERIT_SEVERITY, isMappedRecurrence } = await import(eng("alert-consumers.js"));

// ── 1. The bands are exactly the founder's ladder ──────────────────────────
{
  eq("31 days → not overdue", renewalAlertBand(31), null);
  eq("30 days → high (the renewal-overdue boundary)", renewalAlertBand(30), "high");
  eq("20 days → high", renewalAlertBand(20), "high");
  eq("8 days → high (last high day)", renewalAlertBand(8), "high");
  eq("7 days → critical (escalation boundary)", renewalAlertBand(7), "critical");
  eq("3 days → critical", renewalAlertBand(3), "critical");
  eq("1 day → critical (last critical day)", renewalAlertBand(1), "critical");
  eq("0 days → null (expired owns it, not renewal_overdue)", renewalAlertBand(0), null);
  eq("-5 days → null", renewalAlertBand(-5), null);
  eq("the escalation boundary is 7", RENEWAL_ALERT_CRITICAL_DAYS, 7);
  eq("the overdue boundary is 30", RENEWAL_START_BY_DAYS, 30);

  // Unknown/ambiguous input must never produce a band — an unbanded inherit
  // recurrence fails closed rather than alerting at an invented grade.
  for (const bad of [null, undefined, "abc", NaN, {}, []]) {
    eq(`band(${JSON.stringify(bad)}) → null`, renewalAlertBand(bad), null);
  }
}

// ── 2. renewal_overdue inherits; expired stays critical ────────────────────
{
  eq("renewal_overdue inherits its grade from the band",
     severityForRecurrence("certificates_trust", "renewal_overdue"), INHERIT_SEVERITY);
  eq("expired remains statically critical",
     severityForRecurrence("certificates_trust", "expired"), "critical");
  ok("no new alert type was added to the vocabulary",
     !isMappedRecurrence("certificates_trust", "cert_expiry")
     && !isMappedRecurrence("certificates_trust", "expiring_soon")
     && !isMappedRecurrence("certificates_trust", "renewal_critical"));
}

// ── 3. Band transitions: emit ONCE, stay silent inside a band ─────────────
// This is the whole point. Modelled exactly as certificate-lifecycle.js calls it.
{
  const state = (days, recurrence = "renewal_overdue") => ({
    monitoring_status: "monitoring",
    recurrence_type: recurrence,
    recurrence_band: renewalAlertBand(days),
  });

  // 30d → 7d: same recurrence_type, DIFFERENT band ⇒ exactly one new occurrence.
  ok("30d → 7d IS a transition (the escalation the customer needs)",
     isMonitoringTransition(state(30), state(7)));

  // Repeated scans inside the critical band ⇒ no new occurrence ⇒ deduped.
  ok("7d → 6d is NOT a transition (same band)", !isMonitoringTransition(state(7), state(6)));
  ok("7d → 1d is NOT a transition (same band)", !isMonitoringTransition(state(7), state(1)));
  ok("7d → 7d is NOT a transition (unchanged re-scan)", !isMonitoringTransition(state(7), state(7)));

  // Repeated scans inside the high band likewise.
  ok("30d → 20d is NOT a transition (same band)", !isMonitoringTransition(state(30), state(20)));
  ok("20d → 8d is NOT a transition (same band)", !isMonitoringTransition(state(20), state(8)));

  // Entering the overdue window at all.
  ok("31d → 30d IS a transition (null → high)", isMonitoringTransition(state(31), state(30)));
  ok("31d → 31d is NOT a transition (both outside the window)", !isMonitoringTransition(state(31), state(31)));

  // 7d → expired: the recurrence itself changes, which was always a transition.
  ok("7d → expired IS a transition",
     isMonitoringTransition(state(7), state(0, "expired")));
  eq("...and expired alerts critical", severityForRecurrence("certificates_trust", "expired"), "critical");

  // The full ladder, once each: 31 → 30 (high) → 7 (critical) → 0 (expired).
  const ladder = [[31, "renewal_overdue"], [30, "renewal_overdue"], [7, "renewal_overdue"], [0, "expired"]];
  let transitions = 0;
  for (let i = 1; i < ladder.length; i++) {
    if (isMonitoringTransition(state(...ladder[i - 1]), state(...ladder[i]))) transitions++;
  }
  eq("the whole ladder mints exactly three occurrences (high, critical, expired)", transitions, 3);
}

// ── 4. Every OTHER domain is untouched (the additive guarantee) ───────────
// recurrence_band is absent for Identity Exposure, Shadow IT and managed cases, so
// the comparison is "" !== "" — false. If this regresses, three live domains start
// minting or suppressing occurrences differently, silently.
{
  const noBand = (status, recurrence) => ({ monitoring_status: status, recurrence_type: recurrence });

  ok("identity: unchanged state is NOT a transition",
     !isMonitoringTransition(noBand("monitoring", "removal_contradicted"), noBand("monitoring", "removal_contradicted")));
  ok("identity: a recurrence change IS still a transition",
     isMonitoringTransition(noBand("monitoring", "unexpected_surface"), noBand("monitoring", "removal_contradicted")));
  ok("shadow IT: a monitoring_status change IS still a transition",
     isMonitoringTransition(noBand("monitoring", "material_change"), noBand("resolved", "material_change")));
  ok("managed cases: null-vs-null recurrence is NOT a transition",
     !isMonitoringTransition(noBand("monitoring", null), noBand("monitoring", null)));
  ok("a domain with no band is unaffected by the new dimension",
     !isMonitoringTransition({ monitoring_status: "m", recurrence_type: "r" }, { monitoring_status: "m", recurrence_type: "r" }));

  // An explicit undefined band must behave exactly like an absent one.
  ok("undefined band === absent band",
     !isMonitoringTransition({ monitoring_status: "m", recurrence_type: "r", recurrence_band: undefined },
                             { monitoring_status: "m", recurrence_type: "r" }));
  ok("null band === absent band",
     !isMonitoringTransition({ monitoring_status: "m", recurrence_type: "r", recurrence_band: null },
                             { monitoring_status: "m", recurrence_type: "r" }));
}

// ── 5. Source contract ────────────────────────────────────────────────────
{
  const alerts = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "alerts.js"), "utf8");
  const stripped = alerts.replace(/\/\/[^\n]*/g, "");
  ok("the legacy cert_expiry trigger is GONE", !/type:\s*"cert_expiry"/.test(stripped));
  ok("the legacy cert_expiry dedupe is gone", !/isAlertDuplicate\([^)]*"cert_expiry"/.test(stripped));
  ok("the legacy path no longer reads ssl.cert_expiry_days", !/ssl\?\.cert_expiry_days|ssl\.cert_expiry_days/.test(stripped));
  // isAlertDuplicate must survive for its OTHER callers — it dies with B4b, not here.
  ok("isAlertDuplicate still serves its remaining callers", /function isAlertDuplicate/.test(alerts));
  ok("...and still has live callers", (stripped.match(/isAlertDuplicate\(/g) || []).length >= 2);

  const lifecycle = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "certificate-lifecycle.js"), "utf8");
  ok("the evaluator derives the previous band from the persisted record",
     /const prevBand = renewalAlertBand\(rec\.days_remaining\)/.test(lifecycle));
  ok("the evaluator derives the next band from the fresh assessment",
     /const nextBand = renewalAlertBand\(renewal\.days_remaining\)/.test(lifecycle));
  ok("the band is passed on BOTH sides of the transition check",
     /recurrence_band: prevBand/.test(lifecycle) && /recurrence_band: nextBand/.test(lifecycle));
  ok("the band is passed to the alert as record_severity", /record_severity: nextBand/.test(lifecycle));

  // The previous value must be read BEFORE the record is updated, or the
  // comparison is next-vs-itself and no band transition is ever seen.
  const evalFn = lifecycle.slice(lifecycle.indexOf("export async function evaluateCertificateLifecycleMonitoring"));
  const prevAt = evalFn.indexOf("const prevBand = renewalAlertBand(rec.days_remaining)");
  const updAt  = evalFn.indexOf("UPDATE certificate_lifecycle SET days_remaining");
  ok("the previous days_remaining is read BEFORE the record UPDATE", prevAt > 0 && updAt > prevAt);
}

report(`\nAlert B2 (certificate expiry bands): ${pass}/${pass + fail} passed`);
if (fail > 0) process.exit(1);
