#!/usr/bin/env node
//
// Full Evidence-Based Disappearance Confirmation validator.
//
// Proves the disappearance/resolution contract across the three producers that
// could confirm a disappearance/removal/recovery from INSUFFICIENT evidence:
//
//   G0  attack-surface-signal-completeness.js  applyAssetRemovalConfirmation(...)
//         — a host is confirmed removed ONLY from repeated, spaced, ACTIVE negative
//           observations (authoritative DNS absence + no HTTP service). Discovery
//           silence is never evidence: the inventory no longer carries a
//           discovery-completeness predicate and no producer writes
//           asset_no_longer_seen. Unavailable / incomplete / not-assessed
//           observations never advance removal.
//   G1  email-protection-lifecycle.js  senderRecoveryConfirmed({...})
//         — an active-failures email case closes ONLY when the window PROVABLY
//           contains receiver reports (window_total > 0) with zero failures. An
//           empty window (RUA outage) is absence, never recovery.
//   G2  brand-cases.js  interpretBrandGoneProbe(a, mx)
//         — a takedown is verified removed ONLY from an AUTHORITATIVE negative DNS
//           answer (NOERROR/NXDOMAIN). SERVFAIL/REFUSED/timeout is a FAILED probe
//           and must defer, never resolve.
//
// Core rule everywhere: unavailable / not_assessed / failed / incomplete / missing /
// stale / partial / raw-zero-alone evidence must PRESERVE uncertainty and never emit
// disappearance / resolution / recovery / case-closure. Comparability, tenant
// isolation and dedupe are owned by upstream gates (loadTimelineComparisonContext,
// workspace-scoped SQL, recentEvtSet) and their own validators
// (validate-posture-events*.js, tenant-isolation suite) — see notes below.
//
// Pure-function harness: no live D1/R2. Node 24+.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const ENG = path.join(ROOT, "workers", "scan-api", "src", "engines");
const ASSET_SRC = path.join(ENG, "asset-inventory.js");
const REMOVAL_SRC = path.join(ENG, "attack-surface-signal-completeness.js");
const EMAIL_SRC = path.join(ENG, "email-protection-lifecycle.js");
const BRAND_SRC = path.join(ENG, "brand-cases.js");

const assetInventory = await import(pathToFileURL(ASSET_SRC).href);
const { applyAssetRemovalConfirmation } = await import(pathToFileURL(REMOVAL_SRC).href);
const INTEL_SRC = path.join(ENG, "asset-intel.js");
const { dnsRemovalSignal } = await import(pathToFileURL(INTEL_SRC).href);
const { senderRecoveryConfirmed } = await import(pathToFileURL(EMAIL_SRC).href);
const { interpretBrandGoneProbe } = await import(pathToFileURL(BRAND_SRC).href);

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  cond ? pass++ : fail++;
  console.log(`${cond ? "ok  " : "FAIL"} - ${name}${!cond && detail ? ` -- ${detail}` : ""}`);
};

// ── Fixtures ─────────────────────────────────────────────────────────────────
// G0 — active removal observations (DNS + HTTP signal states per scan).
const NEGATIVE = { dns_resolution: { state: "absent" }, http_https_service: { state: "not_observed" } };
const POSITIVE = { dns_resolution: { state: "observed" }, http_https_service: { state: "observed" } };
const UNAVAILABLE = { dns_resolution: { state: "unavailable" }, http_https_service: { state: "not_observed" } };
const INCOMPLETE = { dns_resolution: { state: "absent" }, http_https_service: { state: "incomplete" } };
const NOT_ASSESSED = { dns_resolution: { state: "not_assessed" }, http_https_service: { state: "not_assessed" } };
const DAY = 24 * 60 * 60 * 1000;
const T0 = Date.parse("2026-07-01T00:00:00.000Z");
const at = (offsetMs) => new Date(T0 + offsetMs).toISOString();
function observe(confirm, steps) {
  let current = { lifecycle_state: "observed", qualifying_observations: [], confirmed_removed_at: null };
  let result = null;
  steps.forEach(([offsetMs, signalStates], index) => {
    result = confirm(current, { scan_id: `scan_${index}`, observed_at: at(offsetMs), signal_states: signalStates });
    current = result;
  });
  return result;
}

// G2 — DoH JSON responses (Cloudflare shape: { Status, Answer }).
const doh = (status, answers = 0) => ({ Status: status, Answer: Array.from({ length: answers }, (_, i) => ({ data: `x${i}` })) });
const NOERR = 0, SERVFAIL = 2, NXDOMAIN = 3, REFUSED = 5;

// ── G0 — asset removal confirmation (applyAssetRemovalConfirmation) ─────────
ok("G0.1 three spaced active negative observations over 48h → confirmed removed",
  observe(applyAssetRemovalConfirmation, [[0, NEGATIVE], [DAY, NEGATIVE], [2 * DAY, NEGATIVE]]).lifecycle_state === "confirmed_removed");
ok("G0.2 a single negative observation never confirms removal",
  observe(applyAssetRemovalConfirmation, [[0, NEGATIVE]]).lifecycle_state !== "confirmed_removed");
ok("G0.3 unavailable observations never advance removal",
  observe(applyAssetRemovalConfirmation, [[0, UNAVAILABLE], [DAY, UNAVAILABLE], [2 * DAY, UNAVAILABLE]]).qualifying_observations.length === 0);
ok("G0.4 incomplete observations never advance removal",
  observe(applyAssetRemovalConfirmation, [[0, INCOMPLETE], [DAY, INCOMPLETE], [2 * DAY, INCOMPLETE]]).qualifying_observations.length === 0);
ok("G0.5 not-assessed observations (host outside the recheck envelope) never advance removal",
  observe(applyAssetRemovalConfirmation, [[0, NOT_ASSESSED], [DAY, NOT_ASSESSED], [2 * DAY, NOT_ASSESSED]]).qualifying_observations.length === 0);
ok("G0.6 negative observations closer than 24h count once",
  observe(applyAssetRemovalConfirmation, [[0, NEGATIVE], [60 * 60 * 1000, NEGATIVE]]).qualifying_observations.length === 1);
ok("G0.7 a positive observation resets the confirmation count",
  observe(applyAssetRemovalConfirmation, [[0, NEGATIVE], [DAY, NEGATIVE], [2 * DAY, POSITIVE], [3 * DAY, NEGATIVE]]).qualifying_observations.length === 1);
ok("G0.8 discovery silence is not evidence: inventory carries no discovery-completeness predicate",
  !("subdomainDiscoveryComplete" in assetInventory));
ok("G0.9 no inventory producer writes asset_no_longer_seen",
  !fs.readFileSync(ASSET_SRC, "utf8").includes("asset_no_longer_seen"));

// A name that exists in DNS without an address (mail or text records only) is
// externally observed, never absent. Only NXDOMAIN for both address types is
// DNS absence; a split answer is not evidence either way.
const settled = (status) => ({ status: "fulfilled", value: { Status: status, Answer: [] } });
const NAME_ONLY = { dns_resolution: { state: "observed", reason: "dns_name_without_address" }, http_https_service: { state: "not_observed" } };
const ADDRESS = { dns_resolution: { state: "observed", reason: "active_dns_records_observed" }, http_https_service: { state: "not_observed" } };
const NAME_ONLY_HTTP = { dns_resolution: { state: "observed", reason: "dns_name_without_address" }, http_https_service: { state: "observed", reason: "http_response_observed" } };
const CONFIRMED = { lifecycle_state: "confirmed_removed", qualifying_observations: [], confirmed_removed_at: at(0) };
const after = (signalStates) => applyAssetRemovalConfirmation(CONFIRMED, { scan_id: "scan_after", observed_at: at(5 * DAY), signal_states: signalStates });
ok("G0.10 NXDOMAIN for A and AAAA is DNS absence",
  dnsRemovalSignal([settled(NXDOMAIN), settled(NXDOMAIN)]).state === "absent");
{
  const nameOnly = dnsRemovalSignal([settled(NOERR), settled(NOERR)]);
  ok("G0.11 NOERROR without an address is an observed name, not absence",
    nameOnly.state === "observed" && nameOnly.reason === "dns_name_without_address", JSON.stringify(nameOnly));
}
ok("G0.12 a split NXDOMAIN/NOERROR answer is not evidence either way",
  dnsRemovalSignal([settled(NXDOMAIN), settled(NOERR)]).state === "unavailable");
ok("G0.13 a name without an address is never confirmed removed",
  observe(applyAssetRemovalConfirmation, [[0, NAME_ONLY], [DAY, NAME_ONLY], [2 * DAY, NAME_ONLY]]).lifecycle_state === "observed");
{
  const corrected = after(NAME_ONLY);
  ok("G0.14 after a confirmed removal, a name without an address corrects the lifecycle without a reappearance claim",
    corrected.lifecycle_state === "observed" && corrected.transition === "observed", JSON.stringify(corrected));
}
ok("G0.15 after a confirmed removal, an address is a reappearance",
  after(ADDRESS).transition === "reappeared");
ok("G0.16 after a confirmed removal, an HTTP response is a reappearance",
  after(NAME_ONLY_HTTP).transition === "reappeared");

// ── G1 — email sender recovery (senderRecoveryConfirmed) ─────────────────────
// (matrix 1) prior active failures + condition cleared + window HAS reports, zero failed → recovery.
ok("G1.1 prior active + cleared + window_total>0 + 0 failed → recovery confirmed",
  senderRecoveryConfirmed({ prev_recurrence_type: "sender_unauthorised_failures_active", graded_recurrence: null, window_total: 40, window_failed: 0 }) === true);
// (matrix 2/5/15) RUA outage — sender absent from window defaults to {0,0} → NO recovery / no case closure.
ok("G1.2 RUA outage (window_total 0, window_failed 0) → NO recovery (absence != recovery)",
  senderRecoveryConfirmed({ prev_recurrence_type: "sender_unauthorised_failures_active", graded_recurrence: null, window_total: 0, window_failed: 0 }) === false);
// (matrix 8) issue still present (failures in window) → NO recovery.
ok("G1.3 failures still in window (graded still active) → NO recovery",
  senderRecoveryConfirmed({ prev_recurrence_type: "sender_unauthorised_failures_active", graded_recurrence: "sender_unauthorised_failures_active", window_total: 40, window_failed: 12 }) === false);
// (matrix 9) no prior verified issue → no recovery event.
ok("G1.4 no prior active-failures condition → NO recovery",
  senderRecoveryConfirmed({ prev_recurrence_type: null, graded_recurrence: null, window_total: 40, window_failed: 0 }) === false);
// window has reports but some failed and condition somehow cleared → still gated by window_failed===0.
ok("G1.5 window_total>0 but window_failed>0 → NO recovery",
  senderRecoveryConfirmed({ prev_recurrence_type: "sender_unauthorised_failures_active", graded_recurrence: null, window_total: 40, window_failed: 3 }) === false);

// ── G2 — brand takedown (interpretBrandGoneProbe) ────────────────────────────
// (matrix 1) authoritative NOERROR, zero A + zero MX → gone, complete.
{
  const r = interpretBrandGoneProbe(doh(NOERR, 0), doh(NOERR, 0));
  ok("G2.1 NOERROR + zero A + zero MX → complete & gone (genuine takedown)", r.complete === true && r.gone === true);
}
// authoritative NXDOMAIN both → gone.
{
  const r = interpretBrandGoneProbe(doh(NXDOMAIN, 0), doh(NXDOMAIN, 0));
  ok("G2.2 NXDOMAIN both → complete & gone", r.complete === true && r.gone === true);
}
// (matrix 4) A SERVFAIL → failed probe → NOT complete, NOT gone (defer).
{
  const r = interpretBrandGoneProbe(doh(SERVFAIL, 0), doh(NOERR, 0));
  ok("G2.3 A SERVFAIL → NOT complete → defer (failed probe never confirms takedown)", r.complete === false && r.gone === false);
}
// MX SERVFAIL → defer.
{
  const r = interpretBrandGoneProbe(doh(NOERR, 0), doh(SERVFAIL, 0));
  ok("G2.4 MX SERVFAIL → NOT complete → defer", r.complete === false && r.gone === false);
}
// REFUSED → defer.
{
  const r = interpretBrandGoneProbe(doh(REFUSED, 0), doh(NOERR, 0));
  ok("G2.5 REFUSED → NOT complete → defer", r.complete === false && r.gone === false);
}
// (matrix 6) missing Status (malformed) → defer.
{
  const r = interpretBrandGoneProbe({ Answer: [] }, doh(NOERR, 0));
  ok("G2.6 missing DNS Status → NOT complete → defer", r.complete === false && r.gone === false);
}
// (matrix 8) NOERROR but A records present (incl. a lingering CNAME) → complete, NOT gone (still present).
{
  const r = interpretBrandGoneProbe(doh(NOERR, 1), doh(NOERR, 0));
  ok("G2.7 NOERROR with A answers present → complete & NOT gone (issue still present)", r.complete === true && r.gone === false);
}
// NOERROR A empty but MX present → NOT gone.
{
  const r = interpretBrandGoneProbe(doh(NOERR, 0), doh(NOERR, 2));
  ok("G2.8 NOERROR, no A but MX present → complete & NOT gone", r.complete === true && r.gone === false);
}

// ── Upstream-gate notes (owned by existing suites, asserted structurally) ─────
// matrix 6  (stale/non-comparable scan) — loadTimelineComparisonContext gates every
//           asset_events emit on scan_quality complete-vs-complete + same producer;
//           proven by validate-posture-events.js. G0 removal confirmation is an
//           ADDITIONAL in-series gate over active observations only.
// matrix 10 (dedupe) — recentEvtSet 24h window is unchanged; validate-posture-events.js #8.
// matrix 11 (reappearance) — asset_reappeared requires positive current presence
//           (existing.status inactive + host present); its emit stays gated on
//           canEmitTimelineEvents (presence, not discovery-completeness). It is
//           protected because the ONLY writer that sets a row inactive is now the
//           canConfirmDisappearance-gated sweep, so a false inactive can no longer be
//           created to seed a false reappearance.
// matrix 12/13 (cross-workspace/domain, stale) — the predicates consume a SINGLE
//           asset's observation history / a single record's window; no cross-tenant
//           input exists. Workspace scoping is enforced in the SQL (tenant-isolation
//           suite), not in these pure predicates.
ok("note: G0 confirmation takes one asset's observations only (no cross-tenant input)",
  typeof applyAssetRemovalConfirmation === "function" && applyAssetRemovalConfirmation.length <= 2);

// ── Mutation harness — each gate is load-bearing ─────────────────────────────
async function mutant(srcPath, from, to) {
  const src = fs.readFileSync(srcPath, "utf8");
  if (!src.includes(from)) return { anchor: false };
  const srcUrl = pathToFileURL(srcPath);
  const rewritten = src.replace(from, to)
    .replace(/from "(\.\.?\/[^"]+)"/g, (_m, rel) => `from ${JSON.stringify(new URL(rel, srcUrl).href)}`);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dc-"));
  const file = path.join(dir, "m.mjs");
  fs.writeFileSync(file, rewritten);
  let mod = null;
  try {
    mod = await import(`${pathToFileURL(file).href}?t=${Date.now()}-${Math.random()}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  return { anchor: true, mod };
}

// G0 mutations ----------------------------------------------------------------
// M1: let non-negative observations advance removal.
{
  const m = await mutant(REMOVAL_SRC, '  if (observationState !== "not_observed") return base;', '  if (false) return base;');
  ok("mutation M1 (only-negative gate removed) → unavailable evidence advances removal — CAUGHT",
    m.anchor && observe(m.mod.applyAssetRemovalConfirmation, [[0, UNAVAILABLE], [DAY, UNAVAILABLE], [2 * DAY, UNAVAILABLE]]).qualifying_observations.length > 0);
}
// M2: one observation is enough.
{
  const m = await mutant(REMOVAL_SRC,
    '  required_qualifying_observations: 3,\n  minimum_observation_spacing_ms: 24 * 60 * 60 * 1000,\n  minimum_confirmation_window_ms: 48 * 60 * 60 * 1000,',
    '  required_qualifying_observations: 1,\n  minimum_observation_spacing_ms: 24 * 60 * 60 * 1000,\n  minimum_confirmation_window_ms: 0,');
  ok("mutation M2 (single observation confirms) → one negative scan removes the asset — CAUGHT",
    m.anchor && observe(m.mod.applyAssetRemovalConfirmation, [[0, NEGATIVE]]).lifecycle_state === "confirmed_removed");
}
// M3: drop the spacing requirement.
{
  const m = await mutant(REMOVAL_SRC, `  if (last &&
      observedMs - canonicalLifecycleEpoch(last.observed_at) <
        policy.minimum_observation_spacing_ms) {
    return base;
  }`, "");
  ok("mutation M3 (spacing removed) → back-to-back scans count twice — CAUGHT",
    m.anchor && observe(m.mod.applyAssetRemovalConfirmation, [[0, NEGATIVE], [60 * 60 * 1000, NEGATIVE]]).qualifying_observations.length === 2);
}
// M4: a positive observation no longer resets the count.
{
  const m = await mutant(REMOVAL_SRC, `      lifecycle_state: "observed",
      qualifying_observations: [],`, `      lifecycle_state: "observed",
      qualifying_observations: previousRows,`);
  ok("mutation M4 (observed no longer resets) → stale negatives survive reappearance — CAUGHT",
    m.anchor && observe(m.mod.applyAssetRemovalConfirmation, [[0, NEGATIVE], [DAY, NEGATIVE], [2 * DAY, POSITIVE], [3 * DAY, NEGATIVE]]).qualifying_observations.length > 1);
}

// G1 mutations ----------------------------------------------------------------
// M7: remove the window_total > 0 requirement → RUA outage falsely recovers/closes case.
{
  const m = await mutant(EMAIL_SRC, '    && Number(window_total || 0) > 0\n', '');
  ok("mutation M7 (window_total guard removed) → RUA outage falsely recovers + closes case — CAUGHT",
    m.anchor && m.mod.senderRecoveryConfirmed({ prev_recurrence_type: "sender_unauthorised_failures_active", graded_recurrence: null, window_total: 0, window_failed: 0 }) === true);
}
// M8: weaken > 0 to >= 0 → raw zero bypasses the evidence requirement.
{
  const m = await mutant(EMAIL_SRC, '    && Number(window_total || 0) > 0', '    && Number(window_total || 0) >= 0');
  ok("mutation M8 (window_total > 0 → >= 0) → raw zero volume falsely recovers — CAUGHT",
    m.anchor && m.mod.senderRecoveryConfirmed({ prev_recurrence_type: "sender_unauthorised_failures_active", graded_recurrence: null, window_total: 0, window_failed: 0 }) === true);
}

// G2 mutations ----------------------------------------------------------------
// M9: drop the authoritative-rcode gate → SERVFAIL (failed probe) now confirms takedown.
{
  const m = await mutant(BRAND_SRC,
    '  if (aStatus === null || mxStatus === null\n      || !AUTHORITATIVE.has(aStatus) || !AUTHORITATIVE.has(mxStatus)) {\n    return { complete: false, gone: false, observed: null, reason: "dns_inconclusive" };\n  }',
    '  if (false) {\n    return { complete: false, gone: false, observed: null, reason: "dns_inconclusive" };\n  }');
  const r = m.anchor ? m.mod.interpretBrandGoneProbe(doh(SERVFAIL, 0), doh(SERVFAIL, 0)) : null;
  ok("mutation M9 (rcode-authority gate removed) → SERVFAIL falsely confirms takedown — CAUGHT",
    m.anchor && r.complete === true && r.gone === true);
}
// M10: admit SERVFAIL into the authoritative set → failed probe confirms takedown.
{
  const m = await mutant(BRAND_SRC, '  const AUTHORITATIVE = new Set([0, 3]); // 0 = NOERROR, 3 = NXDOMAIN', '  const AUTHORITATIVE = new Set([0, 2, 3]);');
  const r = m.anchor ? m.mod.interpretBrandGoneProbe(doh(SERVFAIL, 0), doh(SERVFAIL, 0)) : null;
  ok("mutation M10 (SERVFAIL admitted as authoritative) → failed probe falsely gone — CAUGHT",
    m.anchor && r.complete === true && r.gone === true);
}

// M11: NOERROR without an address read as absence again → a mail-only name is
// confirmable as removed.
{
  const m = await mutant(INTEL_SRC, "    if (fulfilled.every((answer) => answer.Status === 3)) {", "    if (fulfilled.every((answer) => answer.Status === 3 || answer.Status === 0)) {");
  const r = m.anchor ? m.mod.dnsRemovalSignal([settled(NOERR), settled(NOERR)]) : null;
  ok("mutation M11 (name without an address read as absence) — CAUGHT",
    m.anchor && r.state === "absent");
}
// M12: reappearance claimed from a name merely existing.
{
  const m = await mutant(REMOVAL_SRC, `      transition: previousLifecycle === "confirmed_removed" &&
        hasAddressOrServiceEvidence(observation.signal_states)`, `      transition: previousLifecycle === "confirmed_removed"`);
  const r = m.anchor ? m.mod.applyAssetRemovalConfirmation(CONFIRMED, { scan_id: "scan_after", observed_at: at(5 * DAY), signal_states: NAME_ONLY }) : null;
  ok("mutation M12 (reappearance claimed from a name without an address) — CAUGHT",
    m.anchor && r.transition === "reappeared");
}

console.log(`\ndisappearance-confirmation: ${pass}/${pass + fail} passed`);
if (fail) { console.error("disappearance-confirmation validation FAILED"); process.exit(1); }
console.log("disappearance-confirmation validation passed");
