#!/usr/bin/env node
//
// PR-B4a: suppress EVERY outbound customer channel for two legacy alert types that
// assert a claim the platform cannot evidence. CI-blocking.
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
// Every outbound path stops — email, Slack, Teams, webhook. The evidence standard
// is a property of the CLAIM, not of the transport, and gating only email would
// leave the claim one channel configuration away from returning. Production has
// zero enabled channels today; this is the guard for when one is added.
//
// This suite proves outbound delivery stops and NOTHING ELSE does. It is a
// suppression, not a canonicalisation: no occurrence is invented, no domain_key or
// dedupe_key is fabricated, and neither condition is routed through
// emitManagedAlert.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href;

const report = console.log.bind(console);
let pass = 0, fail = 0;
const ok = (n, c) => { c ? pass++ : fail++; if (!c) report("FAIL " + n); };
const eq = (n, g, w) => ok(`${n} (got ${JSON.stringify(g)}, want ${JSON.stringify(w)})`, g === w);

const { OUTBOUND_SUPPRESSED_LEGACY_TYPES } = await import(eng("alerts.js"));

// ── 1. The policy set ───────────────────────────────────────────────────────
// B4a suppressed the two types whose claims are not attributable at all. B4b then
// assessed the two B4a deliberately left sending — and suppressed them too, for
// reasons of the same class (see OUTBOUND_SUPPRESSED_LEGACY_TYPES in alerts.js).
// The set is therefore now EXHAUSTIVE over the legacy processor; that stronger
// property is asserted against the real source in
// validate-alert-b4b-legacy-cleanup.js, which is where a new type would be caught.
{
  ok("new_vendor outbound delivery is suppressed", OUTBOUND_SUPPRESSED_LEGACY_TYPES.has("new_vendor"));
  ok("supply_chain_risk_increase outbound delivery is suppressed", OUTBOUND_SUPPRESSED_LEGACY_TYPES.has("supply_chain_risk_increase"));
  ok("score_drop outbound delivery is suppressed (PR-B4b)", OUTBOUND_SUPPRESSED_LEGACY_TYPES.has("score_drop"));
  ok("new_finding outbound delivery is suppressed (PR-B4b)", OUTBOUND_SUPPRESSED_LEGACY_TYPES.has("new_finding"));
  eq("exactly four legacy types are suppressed", OUTBOUND_SUPPRESSED_LEGACY_TYPES.size, 4);
  ok("the set is frozen", Object.isFrozen(OUTBOUND_SUPPRESSED_LEGACY_TYPES));

  // The policy must stay scoped to the LEGACY processor. Suppressing a canonical
  // kind here would be a silent loss of real security signal — the opposite failure
  // to the one being fixed — and cert_expiry is now owned by certificates_trust.
  for (const t of ["cert_expiry", "domain_verified", "critical_finding", "asset_change",
                   "certificates_trust.renewal_overdue", "email_protection.hosted_record_disconnected"]) {
    ok(`${t} is NOT suppressed on any channel (canonical/unrelated signal must survive)`,
       !OUTBOUND_SUPPRESSED_LEGACY_TYPES.has(t));
  }
}

// ── 2. Source contract: the gate skips the SEND, not the record ────────────
{
  const src = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "alerts.js"), "utf8");
  const fn = src.slice(src.indexOf("export async function processAlertsForWorkspace"));
  const stripped = fn.replace(/\/\/[^\n]*/g, "");

  ok("triggerAlert gates on the suppressed-type policy", /OUTBOUND_SUPPRESSED_LEGACY_TYPES\.has\(type\)/.test(stripped));

  // The gate must sit ABOVE sendTenantAlertEmail and BELOW nothing else: the
  // notification INSERT and the channel fan-out must remain reachable.
  const gateAt   = stripped.indexOf("OUTBOUND_SUPPRESSED_LEGACY_TYPES.has(type)");
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
  // Comments are stripped: the comment explaining PR-B2's cert_expiry deletion
  // necessarily NAMES domain_key/dedupe_key when saying the legacy path had none.
  // A rule that forbids explaining a decision would delete its own rationale.
  ok("no occurrence is invented for the suppressed types", !/monitoring_changed/.test(stripped));
  ok("neither condition is routed through emitManagedAlert", !/emitManagedAlert\(/.test(stripped));
  ok("no domain_key is fabricated on the legacy insert", !/domain_key/.test(stripped));
  ok("no dedupe_key is fabricated on the legacy insert", !/dedupe_key/.test(stripped));

  // ── EVERY outbound channel, not just email ───────────────────────────────
  // deliverWorkspaceAlert is the single trunk for Slack, Teams AND webhook, so one
  // gate above it covers all three. Gating only email would leave the unevidenced
  // claim one channel configuration away from returning.
  const fanoutAt = stripped.indexOf("deliverWorkspaceAlert(env, workspaceId");
  ok("the channel fan-out is gated by the same policy",
     /if \(!OUTBOUND_SUPPRESSED_LEGACY_TYPES\.has\(type\)\) \{[\s\S]{0,400}?deliverWorkspaceAlert\(env, workspaceId/.test(stripped),
     "Slack/Teams/webhook would still carry the claim");
  ok("the fan-out gate sits AFTER the notification INSERT (the record survives)",
     fanoutAt > insertAt);

  // The gate must be the ONLY thing standing between a suppressed type and every
  // sender: exactly two guarded call sites, one per outbound trunk.
  const guards = (stripped.match(/OUTBOUND_SUPPRESSED_LEGACY_TYPES\.has\(type\)/g) || []).length;
  eq("both outbound trunks (email + channels) are guarded", guards, 2);

  // No retryable delivery may be created for a suppressed type: `skipped` is what
  // keeps it out of every retry sweep. Asserted structurally above; asserted here
  // as the negative — the suppression branch must never reach a sender at all.
  const suppressedBranch = stripped.slice(gateAt, stripped.indexOf("} else {", gateAt));
  ok("the suppression branch calls no sender", !/sendTenantAlertEmail|deliverWorkspaceAlert|deliverEmail/.test(suppressedBranch));
  ok("the suppression branch enqueues no retry", !/retry|asset_alert_records|alert_deliveries/i.test(suppressedBranch));
}

// ── 2b. Every named channel is covered by the one trunk ───────────────────
// Slack, Teams and webhook all go through deliverWorkspaceAlert — there is no
// fourth sender that could bypass the gate.
{
  const src = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "alerts.js"), "utf8");

  // deliverWorkspaceAlert dispatches on ch.channel_type read from
  // workspace_alert_channels, so the channel names live in the canonical
  // declaration rather than in the sender's body. Assert against that — it is what
  // bounds the set of channels a workspace can even configure.
  const declared = /const ALERT_CHANNEL_TYPES = \[([^\]]+)\]/.exec(src)?.[1] || "";
  for (const ch of ["slack", "teams", "webhook"]) {
    ok(`${ch} is a declared channel, therefore covered by the one gated trunk`,
       new RegExp(`"${ch}"`).test(declared));
  }
  eq("there are exactly three outbound channel types (no ungated fourth)",
     declared.split(",").filter((x) => x.trim()).length, 3);
  ok("every declared channel is delivered by deliverWorkspaceAlert (the gated trunk)",
     /SELECT id, channel_type, webhook_url, secret FROM workspace_alert_channels/.test(src));
  // And the legacy processor holds no private sender of its own.
  const fn = src.slice(src.indexOf("export async function processAlertsForWorkspace"));
  const stripped = fn.replace(/\/\/[^\n]*/g, "");
  ok("the legacy processor has no private email sender", !/deliverEmail\(|sendCustomerEmail\(|sendAlertEmail\(/.test(stripped));
  eq("the legacy processor reaches exactly one channel sender", (stripped.match(/deliverWorkspaceAlert\(/g) || []).length, 1);
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

report(`\nAlert B4a (unattributable-claim outbound suppression): ${pass}/${pass + fail} passed`);
if (fail > 0) process.exit(1);
