#!/usr/bin/env node
//
// PR-B4a: suppress the outbound EMAIL for two legacy alert types that assert a
// claim the platform cannot evidence. CI-blocking.
//
// Proven in production on 15 July 2026 by one controlled scan of cybermeters.com:
// the customer received two alert emails, both from the legacy
// processAlertsForWorkspace path — domain_key NULL, dedupe_key NULL,
// alert_activation 0, alert_deliveries 0. Neither had ever reached the canonical
// pipeline.
//
//   new_vendor — "Google Trust Services (certificate_authority)" was reported as a
//     NEW vendor on the customer's attack surface. It is their long-standing
//     certificate authority, newly RECORDED (cert-events.js inserts a vendor row),
//     not newly present — and it is not an attack-surface vendor event at all.
//     "New" means only `workspace_vendors.first_seen >= scan_start`, on a mutable
//     shared table whose identity is a free-text vendor_name, so a rename or a
//     normalisation change mints a fresh row and reads as new.
//
//   supply_chain_risk_increase — "resilience score dropped from 32 to 20" is a
//     delta between two workspace_supply_chain_history rows. The scores are
//     persisted, but a score is a RECOMPUTATION: the row records that the score is
//     20, never which evidence moved. The same delta is produced by a genuine
//     concentration change, by one fewer vendor being observed, and by a scoring
//     formula change.
//
// This suite proves the email stops and NOTHING ELSE does. It is a suppression, not
// a canonicalisation: no occurrence is invented, no domain_key or dedupe_key is
// fabricated, and neither condition is routed through emitManagedAlert.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href;

const report = console.log.bind(console);
let pass = 0, fail = 0;
const ok = (n, c) => { c ? pass++ : fail++; if (!c) report("FAIL " + n); };
const eq = (n, g, w) => ok(`${n} (got ${JSON.stringify(g)}, want ${JSON.stringify(w)})`, g === w);

const { EMAIL_SUPPRESSED_LEGACY_TYPES } = await import(eng("alerts.js"));

// ── 1. The policy set is exactly the two proven-unattributable types ────────
{
  ok("new_vendor email is suppressed", EMAIL_SUPPRESSED_LEGACY_TYPES.has("new_vendor"));
  ok("supply_chain_risk_increase email is suppressed", EMAIL_SUPPRESSED_LEGACY_TYPES.has("supply_chain_risk_increase"));
  eq("exactly two types are suppressed", EMAIL_SUPPRESSED_LEGACY_TYPES.size, 2);
  ok("the set is frozen", Object.isFrozen(EMAIL_SUPPRESSED_LEGACY_TYPES));

  // Unrelated alert types MUST keep emailing. Suppressing these would be a silent
  // loss of real security signal — the opposite failure to the one being fixed.
  for (const t of ["score_drop", "new_finding", "cert_expiry", "domain_verified", "critical_finding"]) {
    ok(`${t} is NOT suppressed (unrelated signal must survive)`, !EMAIL_SUPPRESSED_LEGACY_TYPES.has(t));
  }
}

// ── 2. Source contract: the gate skips the SEND, not the record ────────────
{
  const src = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "alerts.js"), "utf8");
  const fn = src.slice(src.indexOf("export async function processAlertsForWorkspace"));
  const stripped = fn.replace(/\/\/[^\n]*/g, "");

  ok("triggerAlert gates on the suppressed-type policy", /EMAIL_SUPPRESSED_LEGACY_TYPES\.has\(type\)/.test(stripped));

  // The gate must sit ABOVE sendTenantAlertEmail and BELOW nothing else: the
  // notification INSERT and the channel fan-out must remain reachable.
  const gateAt   = stripped.indexOf("EMAIL_SUPPRESSED_LEGACY_TYPES.has(type)");
  const sendAt   = stripped.indexOf("sendTenantAlertEmail(env, workspaceId");
  const insertAt = stripped.indexOf("INSERT INTO notification_events");
  ok("the gate precedes the email send", gateAt > 0 && sendAt > gateAt);
  ok("the notification INSERT is still reached (condition stays observable in-app)",
     insertAt > 0 && insertAt > sendAt);

  // A suppressed type must be recorded as `skipped`, never `failed`: nothing broke,
  // and a `failed` row is what a retry sweep would pick up.
  ok("suppression is recorded as skipped with an honest reason",
     /status: "skipped", reason: EVIDENCE_NOT_ATTRIBUTABLE/.test(stripped));
  ok("the reason names the actual problem", /const EVIDENCE_NOT_ATTRIBUTABLE = "evidence_not_attributable"/.test(src));

  // This is a suppression PR. It must not quietly canonicalise either condition.
  ok("no occurrence is invented for the suppressed types", !/monitoring_changed/.test(fn));
  ok("neither condition is routed through emitManagedAlert", !/emitManagedAlert\(/.test(fn));
  ok("no domain_key is fabricated on the legacy insert", !/domain_key/.test(fn));
  ok("no dedupe_key is fabricated on the legacy insert", !/dedupe_key/.test(fn));
}

// ── 3. The underlying evidence keeps being collected ───────────────────────
// Suppressing the claim must not suppress the observation. The dashboards, the
// history and the scan record are unchanged — only the assertion by email stops.
{
  const engines = path.join(root, "workers", "scan-api", "src", "engines");
  const scanEngine = fs.readFileSync(path.join(engines, "scan-engine.js"), "utf8");
  const supplyChain = fs.readFileSync(path.join(engines, "supply-chain.js"), "utf8");
  const certEvents = fs.readFileSync(path.join(engines, "cert-events.js"), "utf8");

  ok("workspace_vendors is still written by the scan engine", /INTO workspace_vendors/.test(scanEngine));
  ok("workspace_vendors is still written by cert observation", /INTO workspace_vendors/.test(certEvents));
  ok("workspace_supply_chain_history is still written", /INTO workspace_supply_chain_history/.test(supplyChain));

  // Vendor discovery and scoring are untouched by this PR.
  const vendorRisk = fs.readFileSync(path.join(engines, "vendor-risk.js"), "utf8");
  ok("vendor discovery/scoring is untouched", /computeWorkspaceVendorRisk/.test(vendorRisk));
}

// ── 4. The legacy path still honours PR-A's gates for everything else ──────
// Suppression is additive to the trust chain, not a replacement for it.
{
  const src = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "alerts.js"), "utf8");
  ok("the email chokepoint still checks entitlement", /resolveAlertEntitlement\(env, workspaceId\)/.test(src));
  ok("the email chokepoint still checks the per-user preference", /alertEmailFrequencyForUser\(env, workspaceId, r\.user_id\)/.test(src));
  ok("the email chokepoint still checks severity", /severityAllowedByFrequency\(pref\.frequency, severity\)/.test(src));
  ok("non-suppressed legacy alerts still route through the chokepoint",
     /sendTenantAlertEmail\(env, workspaceId, \{/.test(src));
}

report(`\nAlert B4a (unattributable-claim email suppression): ${pass}/${pass + fail} passed`);
if (fail > 0) process.exit(1);
