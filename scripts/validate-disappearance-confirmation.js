#!/usr/bin/env node
//
// Full Evidence-Based Disappearance Confirmation validator.
//
// Proves the disappearance/resolution contract across the three producers that
// could confirm a disappearance/removal/recovery from INSUFFICIENT evidence:
//
//   G0  asset-inventory.js  subdomainDiscoveryComplete(modules)
//         — a host is retired (inactive + asset_no_longer_seen) ONLY when the CT
//           discovery that would have re-found it completed intact. Degraded /
//           partial / failed CT enumeration must never manufacture disappearance.
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
const EMAIL_SRC = path.join(ENG, "email-protection-lifecycle.js");
const BRAND_SRC = path.join(ENG, "brand-cases.js");

const { subdomainDiscoveryComplete } = await import(pathToFileURL(ASSET_SRC).href);
const { senderRecoveryConfirmed } = await import(pathToFileURL(EMAIL_SRC).href);
const { interpretBrandGoneProbe } = await import(pathToFileURL(BRAND_SRC).href);

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  cond ? pass++ : fail++;
  console.log(`${cond ? "ok  " : "FAIL"} - ${name}${!cond && detail ? ` -- ${detail}` : ""}`);
};

// ── Fixtures ─────────────────────────────────────────────────────────────────
// G0 — subdomain discovery module shapes (mirrors subdomains-scan.js return shapes).
const subHealthy = (items = ["a.example.com"]) => ({
  subdomains: { items, sources: { crt_sh: { count: items.length, error: null }, certspotter: { count: 0, error: null } } },
  dns_bruteforce: { items: [], error: null },
});
const subCtBothFailed = () => ({
  // Both CT sources failed → items collapsed, ct_error set, top-level error stays null.
  subdomains: { items: [], sources: { crt_sh: { count: 0, error: "HTTP 429" }, certspotter: { count: 0, error: "HTTP 429" } }, ct_error: "Both CT sources failed" },
});
const subOneSourceFailed = () => ({
  // crt.sh succeeded, certspotter 429 — partial coverage.
  subdomains: { items: ["a.example.com"], sources: { crt_sh: { count: 1, error: null }, certspotter: { count: 0, error: "HTTP 429" } } },
});
const subModuleError = () => ({
  subdomains: { items: [], sources: { crt_sh: { count: 0, error: "module rejected" }, certspotter: { count: 0, error: "module rejected" } }, error: "Subdomain module failed" },
});
const subBruteforceFailed = () => ({
  subdomains: { items: ["a.example.com"], sources: { crt_sh: { count: 1, error: null }, certspotter: { count: 0, error: null } } },
  dns_bruteforce: { items: [], error: "timed out" },
});

// G2 — DoH JSON responses (Cloudflare shape: { Status, Answer }).
const doh = (status, answers = 0) => ({ Status: status, Answer: Array.from({ length: answers }, (_, i) => ({ data: `x${i}` })) });
const NOERR = 0, SERVFAIL = 2, NXDOMAIN = 3, REFUSED = 5;

// ── G0 — asset disappearance (subdomainDiscoveryComplete) ────────────────────
// (matrix 1) complete healthy scan, host genuinely absent → disappearance ALLOWED.
ok("G0.1 healthy CT scan (no errors) → discovery complete → disappearance allowed",
  subdomainDiscoveryComplete(subHealthy()) === true);
// (matrix 7) healthy scan that genuinely found zero subdomains (no errors) → still complete.
ok("G0.1b healthy scan, empty items but NO errors → complete (genuine disappearance allowed)",
  subdomainDiscoveryComplete({ subdomains: { items: [], sources: { crt_sh: { count: 0, error: null }, certspotter: { count: 0, error: null } } } }) === true);
// (matrix 2/4) both CT sources failed (unavailable) → NOT complete → no disappearance.
ok("G0.2 both CT sources failed (ct_error) → NOT complete → no disappearance",
  subdomainDiscoveryComplete(subCtBothFailed()) === false);
// (matrix 14) one failed source among the two → fail neutral, no disappearance.
ok("G0.3 one CT source failed (partial coverage) → NOT complete → no disappearance",
  subdomainDiscoveryComplete(subOneSourceFailed()) === false);
// (matrix 4) module rejected (top-level error) → no disappearance.
ok("G0.4 subdomains module error → NOT complete → no disappearance",
  subdomainDiscoveryComplete(subModuleError()) === false);
// (matrix 5) missing subdomains module entirely → no disappearance.
ok("G0.5 missing subdomains module → NOT complete → no disappearance",
  subdomainDiscoveryComplete({}) === false && subdomainDiscoveryComplete(undefined) === false);
// (matrix 14) brute-force feeder failed → no disappearance.
ok("G0.6 dns_bruteforce feeder failed → NOT complete → no disappearance",
  subdomainDiscoveryComplete(subBruteforceFailed()) === false);
// brute-force module simply absent (optional feeder) → still complete.
ok("G0.7 no dns_bruteforce module (optional) + healthy CT → complete",
  subdomainDiscoveryComplete({ subdomains: { items: ["a"], sources: { crt_sh: { count: 1, error: null }, certspotter: { count: 0, error: null } } } }) === true);

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
//           proven by validate-posture-events.js. The G0 predicate is an ADDITIONAL
//           in-series gate, so a non-comparable scan is already blocked upstream.
// matrix 10 (dedupe) — recentEvtSet 24h window is unchanged; validate-posture-events.js #8.
// matrix 11 (reappearance) — asset_reappeared requires positive current presence
//           (existing.status inactive + host present); its emit stays gated on
//           canEmitTimelineEvents (presence, not discovery-completeness). It is
//           protected because the ONLY writer that sets a row inactive is now the
//           canConfirmDisappearance-gated sweep, so a false inactive can no longer be
//           created to seed a false reappearance.
// matrix 12/13 (cross-workspace/domain, stale) — the predicates consume a SINGLE
//           scan's in-memory modules / a single record's window; no cross-tenant
//           input exists. Workspace scoping is enforced in the SQL (tenant-isolation
//           suite), not in these pure predicates.
ok("note: G0 predicate takes single-scan modules only (no cross-tenant input)",
  typeof subdomainDiscoveryComplete === "function");

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
// M1: remove the both-CT-failed guard → ct_error (unavailable) now reads complete.
{
  const m = await mutant(ASSET_SRC, 'if (sub.ct_error) return false;', 'if (false) return false;');
  // Isolate the ct_error guard: a payload carrying ONLY ct_error (no per-source
  // errors) — the guard is the sole line standing between it and a false "complete".
  ok("mutation M1 (ct_error guard removed) → collapsed CT now falsely 'complete' — CAUGHT",
    m.anchor && m.mod.subdomainDiscoveryComplete({ subdomains: { items: [], ct_error: "Both CT sources failed" } }) === true);
}
// M2: remove the per-source (crt_sh) guard → partial coverage now reads complete.
{
  const m = await mutant(ASSET_SRC, '  if (sources.crt_sh?.error) return false;       // a CT source errored → partial coverage', '  if (false) return false;');
  ok("mutation M2 (crt_sh source guard removed) → partial coverage falsely 'complete' — CAUGHT",
    m.anchor && m.mod.subdomainDiscoveryComplete({ subdomains: { items: [], sources: { crt_sh: { error: "429" }, certspotter: { error: null } } } }) === true);
}
// M3: remove the certspotter source guard.
{
  const m = await mutant(ASSET_SRC, '  if (sources.certspotter?.error) return false;', '  if (false) return false;');
  ok("mutation M3 (certspotter source guard removed) → partial coverage falsely 'complete' — CAUGHT",
    m.anchor && m.mod.subdomainDiscoveryComplete(subOneSourceFailed()) === true);
}
// M4: flip the missing-module default to true → missing evidence reads healthy.
{
  const m = await mutant(ASSET_SRC, '  if (!sub) return false;                        // no discovery module → cannot anchor disappearance', '  if (!sub) return true;');
  ok("mutation M4 (missing module defaults true) → missing evidence falsely 'complete' — CAUGHT",
    m.anchor && m.mod.subdomainDiscoveryComplete({}) === true);
}
// M5: remove the module-error guard.
{
  const m = await mutant(ASSET_SRC, 'if (sub.error) return false;', 'if (false) return false;');
  // Isolate the top-level error guard: a payload carrying ONLY sub.error.
  ok("mutation M5 (module-error guard removed) → failed module falsely 'complete' — CAUGHT",
    m.anchor && m.mod.subdomainDiscoveryComplete({ subdomains: { items: [], error: "Subdomain module failed" } }) === true);
}
// M6: remove the brute-force feeder guard.
{
  const m = await mutant(ASSET_SRC, '  if (bf?.error) return false;                   // brute-force feeder timed out/failed', '  if (false) return false;');
  ok("mutation M6 (bruteforce guard removed) → failed feeder falsely 'complete' — CAUGHT",
    m.anchor && m.mod.subdomainDiscoveryComplete(subBruteforceFailed()) === true);
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

console.log(`\ndisappearance-confirmation: ${pass}/${pass + fail} passed`);
if (fail) { console.error("disappearance-confirmation validation FAILED"); process.exit(1); }
console.log("disappearance-confirmation validation passed");
