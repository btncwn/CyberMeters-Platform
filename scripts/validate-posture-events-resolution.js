#!/usr/bin/env node
//
// Posture-events false-resolution guard validator.
//
// Proves exposed_service_resolved is emitted ONLY when the current admin-surface
// assessment actually completed with zero verified surfaces (evidence_status
// "assessed_healthy"). unavailable / not_assessed / missing / legacy / failed /
// incomplete current evidence must NEVER emit a false "resolved" — fail neutral,
// preserve uncertainty. Uses the REAL buildPostureDiffEvents. (Cross-run dedupe /
// idempotency lives in recordPostureEvents and is unchanged — covered by
// validate-posture-events.js #8, still passing.)
//
// Pure-function harness: no live D1/R2. Node 24+.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const SRC = path.join(ROOT, "workers", "scan-api", "src", "engines", "posture-events.js");
const { buildPostureDiffEvents } = await import(pathToFileURL(SRC).href);

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  cond ? pass++ : fail++;
  console.log(`${cond ? "ok  " : "FAIL"} - ${name}${!cond && detail ? ` -- ${detail}` : ""}`);
};

const svc = (hostname, product) => ({ hostname, product, severity: "high", risk_level: "high" });
// A previous verified exposed admin service.
const PREV = { admin_surface_detection: { services: [svc("panel.example.com", "Jenkins")], evidence_status: "issue_detected" } };
const adminMod = (services, evidence_status) => ({ admin_surface_detection: { services, evidence_status } });
const resolvedCount = (prev, current) =>
  buildPostureDiffEvents("example.com", prev, current).filter((e) => e.event_type === "exposed_service_resolved").length;
const detectedCount = (prev, current) =>
  buildPostureDiffEvents("example.com", prev, current).filter((e) => e.event_type === "exposed_service_detected").length;

// ── Required fixtures ────────────────────────────────────────────────────────
// 1. prev verified + current assessed_healthy → exactly one resolved.
ok("1. prev issue + current assessed_healthy → exactly one resolved",
  resolvedCount(PREV, adminMod([], "assessed_healthy")) === 1);
// 2. current unavailable → zero resolved.
ok("2. prev issue + current unavailable → zero resolved",
  resolvedCount(PREV, adminMod([], "unavailable")) === 0);
// 3. current not_assessed → zero resolved.
ok("3. prev issue + current not_assessed → zero resolved",
  resolvedCount(PREV, adminMod([], "not_assessed")) === 0);
// 4. current null / missing evidence_status → zero resolved (fail neutral).
ok("4. prev issue + current null evidence_status → zero resolved",
  resolvedCount(PREV, adminMod([], null)) === 0);
// 5. failed/incomplete probe (unavailable, maybe partial services) → zero resolved.
ok("5. prev issue + current incomplete/failed probe (unavailable) → zero resolved",
  resolvedCount(PREV, adminMod([svc("other.example.com", "Grafana")], "unavailable")) === 0);
// 6. missing admin module entirely → zero resolved.
ok("6. prev issue + current missing admin module → zero resolved",
  resolvedCount(PREV, { /* no admin_surface_detection */ }) === 0);
// 7. raw zero count but no successful assessment (services [], not_assessed) → zero resolved.
ok("7. prev issue + raw zero count without successful assessment → zero resolved",
  resolvedCount(PREV, adminMod([], "not_assessed")) === 0);
// 8. current issue_detected (same service persists) → zero resolved; issue stays visible.
ok("8a. prev issue + current issue_detected, SAME service persists → zero resolved",
  resolvedCount(PREV, adminMod([svc("panel.example.com", "Jenkins")], "issue_detected")) === 0);
ok("8b. persisting service is not re-detected either (still open, not churned)",
  detectedCount(PREV, adminMod([svc("panel.example.com", "Jenkins")], "issue_detected")) === 0);
ok("8c. current issue_detected with a DIFFERENT service → prior NOT resolved, new one detected",
  resolvedCount(PREV, adminMod([svc("x.example.com", "Rundeck")], "issue_detected")) === 0 &&
  detectedCount(PREV, adminMod([svc("x.example.com", "Rundeck")], "issue_detected")) === 1);
// 9. no previous verified issue + current assessed_healthy → zero resolved.
ok("9. no prior service + current assessed_healthy → zero resolved",
  resolvedCount(adminMod([], "assessed_healthy"), adminMod([], "assessed_healthy")) === 0);
// 11. genuine reappearance/recurrence (service appears) still emits detected, unchanged.
ok("11. reappearance: prior clean + current issue_detected service → detected fires",
  detectedCount(adminMod([], "assessed_healthy"), adminMod([svc("panel.example.com", "Jenkins")], "issue_detected")) === 1);
// 12. legacy payload (no evidence_status on either side) does not crash; fails neutral.
ok("12. legacy prev+current without evidence_status → no crash, zero resolved (fail neutral)",
  resolvedCount({ admin_surface_detection: { services: [svc("panel.example.com", "Jenkins")] } }, { admin_surface_detection: { services: [] } }) === 0);
// Genuine resolution emits exactly ONE per disappeared service (idempotent within a diff).
ok("genuine multi-service resolution: two disappeared + current assessed_healthy → exactly two resolved (one each)",
  resolvedCount({ admin_surface_detection: { services: [svc("a.example.com", "Jenkins"), svc("b.example.com", "Kibana")], evidence_status: "issue_detected" } }, adminMod([], "assessed_healthy")) === 2);

// ── Mutation harness — the resolution gate is load-bearing ───────────────────
const src = fs.readFileSync(SRC, "utf8");
// Rewrite the module's relative imports (./ and ../) to absolute file URLs so the
// mutant can be imported from a temp dir.
const srcUrl = pathToFileURL(SRC);
const rewriteImports = (s) => s.replace(/from "(\.\.?\/[^"]+)"/g, (_m, rel) => `from ${JSON.stringify(new URL(rel, srcUrl).href)}`);
async function mutant(from, to) {
  if (!src.includes(from)) return { anchor: false };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pe-"));
  const file = path.join(dir, "m.mjs");
  fs.writeFileSync(file, rewriteImports(src.replace(from, to)));
  const mod = await import(`${pathToFileURL(file).href}?t=${Date.now()}-${Math.random()}`);
  fs.rmSync(dir, { recursive: true, force: true });
  return { anchor: true, mod };
}
const GATE = 'const currentAdminAssessedHealthy =\n    currentModules?.admin_surface_detection?.evidence_status === "assessed_healthy";';

// M1: remove the gate (current always treated as a completed clean assessment).
{
  const m = await mutant(GATE, 'const currentAdminAssessedHealthy = true;');
  const rc = (cur) => m.anchor ? m.mod.buildPostureDiffEvents("example.com", PREV, cur).filter((e) => e.event_type === "exposed_service_resolved").length : -1;
  ok("mutation M1 (gate removed) → unavailable now falsely resolves — CAUGHT", m.anchor && rc(adminMod([], "unavailable")) === 1);
  ok("mutation M1 → not_assessed now falsely resolves — CAUGHT", m.anchor && rc(adminMod([], "not_assessed")) === 1);
  ok("mutation M1 → missing/null evidence now falsely resolves — CAUGHT", m.anchor && rc(adminMod([], null)) === 1);
}
// M2: accept unavailable as the resolution state (evidence_status compared to the wrong value).
{
  const m = await mutant('evidence_status === "assessed_healthy";', 'evidence_status !== "issue_detected";');
  const rc = (cur) => m.anchor ? m.mod.buildPostureDiffEvents("example.com", PREV, cur).filter((e) => e.event_type === "exposed_service_resolved").length : -1;
  ok("mutation M2 (accept non-issue as resolved) → unavailable falsely resolves — CAUGHT", m.anchor && rc(adminMod([], "unavailable")) === 1);
}

console.log(`\nposture-events resolution guard: ${pass}/${pass + fail} passed`);
if (fail) { console.error("posture-events-resolution validation FAILED"); process.exit(1); }
console.log("posture-events-resolution validation passed");
