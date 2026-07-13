#!/usr/bin/env node
//
// Exposure-probe honesty proof.
//
// Trust regression guard for the subrequest-budget exhaustion defect: when a
// Cloudflare Worker runs out of its per-invocation subrequest budget, every
// remaining fetch throws "Too many subrequests by single Worker invocation." The
// old probeAsset swallowed this into reachable:false, which reads to a customer as
// "confirmed unreachable / no exposed asset" — a falsely-clean result, and it let
// managed-case verification resolve off a scan that never actually re-checked.
//
// This proves the honest semantics end-to-end (probe → module → scan_quality →
// managed-case gate) without a DB: an exhausted probe is not-executed (reachable:null),
// the module flags incomplete, scan_quality is forced partial, and the managed-case
// completeness gate defers. Genuine failures and successes are unchanged. Node 24+.
// CI-blocking.
//
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href);

const { probeAsset, runExposureModule } = await eng("asset-intel.js");
const { buildScanQuality }              = await eng("scan-engine.js");
const { moduleCompletionGate }          = await eng("asm-cases.js");

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

const realFetch = globalThis.fetch;
const setFetch = (fn) => { globalThis.fetch = fn; };
const html200 = () => new Response("<title>Admin</title>", { status: 200, headers: { "content-type": "text/html" } });
const budgetError = () => { throw new Error("Too many subrequests by single Worker invocation. To configure this limit, refer to https://developers.cloudflare.com/…"); };
const networkError = () => { throw new TypeError("network error: connection refused"); };

// ── 1. probeAsset — genuine network failure still produces reachable:false ─────
setFetch(networkError);
let a = await probeAsset("down.example");
ok("genuine failure → reachable:false", a.reachable === false);
ok("genuine failure → NOT flagged not_executed", a.probe_status === undefined && a.reason === undefined);
ok("genuine failure → status null", a.status === null);

// ── 2. probeAsset — subrequest exhaustion → reachable:null / not_executed ──────
setFetch(budgetError);
a = await probeAsset("starved.example");
ok("exhaustion → reachable:null (NOT false)", a.reachable === null);
ok("exhaustion → probe_status not_executed", a.probe_status === "not_executed");
ok("exhaustion → reason subrequest_budget_exhausted", a.reason === "subrequest_budget_exhausted");

// ── 3. probeAsset — ordinary success unchanged (no new fields) ────────────────
setFetch(html200);
a = await probeAsset("up.example");
ok("success → reachable:true", a.reachable === true && a.status === 200);
ok("success → no probe_status/reason leak (shape unchanged)", a.probe_status === undefined && a.reason === undefined);

// ── 4. runExposureModule — all starved → incomplete + notice, reachable 0 ─────
setFetch(budgetError);
let mod = await runExposureModule("example.com", ["a.example.com", "b.example.com"]);
ok("module (all starved) → incomplete:true", mod.incomplete === true);
ok("module → incomplete_reason subrequest_budget_exhausted", mod.incomplete_reason === "subrequest_budget_exhausted");
ok("module → customer-safe notice, no raw error text", typeof mod.notice === "string" && /could not complete/i.test(mod.notice) && !/subrequest/i.test(mod.notice));
ok("module → reachable 0 but NOT a clean verified result (incomplete set)", mod.reachable === 0 && mod.incomplete === true);

// ── 5. runExposureModule — genuine failures → NOT incomplete ──────────────────
setFetch(networkError);
mod = await runExposureModule("example.com", ["a.example.com", "b.example.com"]);
ok("module (genuine fail) → not flagged incomplete", !mod.incomplete);
ok("module (genuine fail) → reachable 0", mod.reachable === 0);

// ── 6. runExposureModule — success unchanged ──────────────────────────────────
setFetch(html200);
mod = await runExposureModule("example.com", ["a.example.com"]);
ok("module (success) → reachable > 0, not incomplete", mod.reachable === 1 && !mod.incomplete);

globalThis.fetch = realFetch;

// ── 7. buildScanQuality — incomplete exposure forces partial + skipped ────────
const qPartial = buildScanQuality({
  dns: { resolves: true }, ssl: {}, headers: { accessible: true }, email_security: {},
  asset_exposure: { checked: 5, reachable: 0, incomplete: true, incomplete_reason: "subrequest_budget_exhausted" },
});
ok("scan_quality → partial when exposure incomplete", qPartial.status === "partial");
ok("scan_quality → asset_exposure listed as skipped", qPartial.modules_skipped.includes("asset_exposure"));

const qComplete = buildScanQuality({
  dns: { resolves: true }, ssl: {}, headers: { accessible: true }, email_security: {},
  asset_exposure: { checked: 5, reachable: 2 },   // genuine, complete
});
ok("scan_quality → NOT partial on a genuine complete exposure", qComplete.status !== "partial");

// ── 8. Managed-case completeness gate — defer when exposure did not run ────────
const modulesIncomplete = { asset_exposure: { checked: 5, reachable: 0, incomplete: true } };
const gateIncomplete = moduleCompletionGate(modulesIncomplete, qPartial);
ok("gate → cannot verify an asset_exposure case on an incomplete scan (deferred)",
   gateIncomplete.canVerify("asset_exposure") === false);
ok("gate → scanPartial true (blocks resolution broadly)", gateIncomplete.scanPartial === true);

// zero exposed assets must NOT read as verified-clean when probes did not run:
ok("gate → absence of finding is NOT resolvable when exposure incomplete",
   gateIncomplete.canVerify("asset_exposure") === false);

const gateComplete = moduleCompletionGate(
  { asset_exposure: { checked: 5, reachable: 2 } },
  qComplete,
);
ok("gate → CAN verify on a genuine complete scan (happy path unchanged)",
   gateComplete.canVerify("asset_exposure") === true);

console.log(`\nexposure-honesty: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
