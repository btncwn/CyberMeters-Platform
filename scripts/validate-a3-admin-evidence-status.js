#!/usr/bin/env node
//
// A3 — Attack Surface admin evidence-status honesty validator.
//
// Proves that unavailable / failed / missing / not-executed admin-surface evidence
// never collapses into a customer-facing zero-admin / clean / healthy / "none
// detected" conclusion, nor an unearned posture score credit. Uses the REAL
// producer runAdminSurfaceModule, the REAL computeSecurityPosture, and the REAL
// /admin-surfaces route handler (auth is injected via rctx, so mockable).
//
// Pure-function harness: no live DNS/D1/R2. Node 24+.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const ENG = path.join(ROOT, "workers", "scan-api", "src", "engines");
const absU = (f) => pathToFileURL(path.join(ENG, f)).href;

const ASSET_INTEL = path.join(ENG, "asset-intel.js");
const POSTURE = path.join(ENG, "posture-scoring.js");
const { runAdminSurfaceModule } = await import(pathToFileURL(ASSET_INTEL).href);
const { computeSecurityPosture } = await import(pathToFileURL(POSTURE).href);
const { attackSurfaceRoutes } = await import(pathToFileURL(path.join(ROOT, "workers/scan-api/src/routes/attack-surface.js")).href);

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  cond ? pass++ : fail++;
  console.log(`${cond ? "ok  " : "FAIL"} - ${name}${!cond && detail ? ` -- ${detail}` : ""}`);
};

// A reachable host that fingerprints as a verified Jenkins admin surface (a finding).
const ADMIN_HOST = { host: "jenkins.example.com", reachable: true, title: "Jenkins Dashboard", server: "Jetty(9.4)", url: "https://jenkins.example.com" };
const BENIGN_HOST = { host: "shop.example.com", reachable: true, title: "Acme Store", server: "cloudflare", url: "https://shop.example.com" };

// ── 1. PRODUCER runAdminSurfaceModule — evidence_status honesty ──────────────
const pNotRun     = runAdminSurfaceModule({});                                                   // asset_exposure absent
const pEmpty      = runAdminSurfaceModule({ asset_exposure: { assets: [], checked: 0, error: null } });
const pIncomplete = runAdminSurfaceModule({ asset_exposure: { assets: [{ host: "x", reachable: null }], incomplete: true } });
const pError      = runAdminSurfaceModule({ asset_exposure: { assets: [BENIGN_HOST], error: "probe crashed" } });
const pHealthy    = runAdminSurfaceModule({ asset_exposure: { assets: [BENIGN_HOST], error: null } });
const pIssue      = runAdminSurfaceModule({ asset_exposure: { assets: [ADMIN_HOST], error: null } });

ok("producer: asset_exposure absent → not_assessed", pNotRun.evidence_status === "not_assessed");
ok("producer: asset_exposure empty (nothing probed) → not_assessed (empty ≠ healthy)", pEmpty.evidence_status === "not_assessed");
ok("producer: asset_exposure incomplete (probes not-executed) → unavailable", pIncomplete.evidence_status === "unavailable");
ok("producer: unavailable is NOT healthy and total stays 0 (incomplete not silently dropped to clean)",
  pIncomplete.evidence_status !== "assessed_healthy" && pIncomplete.total === 0);
ok("producer: asset_exposure error → unavailable", pError.evidence_status === "unavailable");
ok("producer: completed probe, zero verified admin surfaces → assessed_healthy", pHealthy.evidence_status === "assessed_healthy" && pHealthy.total === 0);
ok("producer: verified admin surface → issue_detected", pIssue.evidence_status === "issue_detected" && pIssue.total > 0);
// Real finding is never hidden by an unavailable/incomplete source.
const pIssueDespiteIncomplete = runAdminSurfaceModule({ asset_exposure: { assets: [ADMIN_HOST, { host: "y", reachable: null }], incomplete: true } });
ok("producer: verified admin surface surfaces as issue_detected even when the pass was incomplete",
  pIssueDespiteIncomplete.evidence_status === "issue_detected");

// ── 2. POSTURE SCORING — unavailable/not_assessed → null (excluded), not 100 ──
// Minimal-but-complete scorecard input so the OTHER categories don't crash; admin
// is the category under test.
const SC = {
  admin_surfaces: 0,
  brand_risks: { high: 0, medium: 0 },
  certificate_risks: { days_until_expiry: 365, risk_level: null },
  vendor_risk: { high: 0, medium: 0 },
  last_scanned_domain: "example.com",
  new_assets_count: 0, saas_exposures: 0, third_party_assets: 0,
};
const posture = (adm) => computeSecurityPosture(SC, { modules: adm === undefined ? {} : { admin_surface_detection: adm } });
ok("posture: admin unavailable → admScore null (excluded from denominator, NOT 100)",
  posture({ evidence_status: "unavailable", total: 0, critical: 0, high: 0 }).admin_exposure.score === null);
ok("posture: admin not_assessed → admScore null",
  posture({ evidence_status: "not_assessed", total: 0 }).admin_exposure.score === null);
ok("posture: admin module absent → admScore null (no unearned credit)",
  posture(undefined).admin_exposure.score === null);
ok("posture: genuine assessed_healthy → admScore 100 (earned credit preserved)",
  posture({ evidence_status: "assessed_healthy", total: 0 }).admin_exposure.score === 100);
ok("posture: verified admin surface → penalised (score < 100), finding never hidden",
  posture({ evidence_status: "issue_detected", total: 1, critical: 1, high: 0 }).admin_exposure.score < 100);
// Null admin is genuinely excluded from the weighted denominator (overall from other categories only).
const overallWithUnavailAdmin = posture({ evidence_status: "unavailable", total: 0 }).overall_score;
ok("posture: null admin excluded from overall (no crash, overall from remaining categories)",
  overallWithUnavailAdmin === null || typeof overallWithUnavailAdmin === "number");

// ── 3. ROUTE /admin-surfaces — additive evidence_status; existing keys intact ─
function rctxFor({ domains = [{ domain_id: "d1" }], scans = { d1: { id: "s1" } }, reports = {} } = {}) {
  const url = new URL("https://api.test/api/workspaces/ws1/admin-surfaces");
  const db = {
    prepare(sql) {
      return {
        bind(...args) {
          return {
            all: async () => {
              if (sql.includes("FROM scans s")) {
                return {
                  results: domains
                    .map(({ domain_id }) => scans[domain_id]
                      ? { id: scans[domain_id].id, domain_id }
                      : null)
                    .filter(Boolean),
                };
              }
              return sql.includes("workspace_domains") ? { results: domains } : { results: [] };
            },
            first: async () => (sql.includes("FROM scans") ? (scans[args[0]] ?? null) : null),
          };
        },
      };
    },
  };
  const cybermeters_reports = {
    get: async (key) => {
      if (!(key in reports)) return null;                 // R2 object missing
      const r = reports[key];
      if (r === "R2_REJECT") throw new Error("r2 down");  // rejected promise
      if (r === "R2_THROW") return { json: async () => { throw new Error("bad json"); } };
      return { json: async () => r };
    },
  };
  return {
    request: { method: "GET" }, url,
    env: { cybermeters_db: db, cybermeters_reports },
    json: (body, status = 200) => ({ body, status }),
    requireAuth: async () => ({ id: "u1" }),
    requireWorkspaceRole: async () => true,
  };
}
const route = async (opts) => (await attackSurfaceRoutes(rctxFor(opts))).body;

const rNoDomains = await route({ domains: [] });
ok("route: no domains → evidence_status not_assessed", rNoDomains.evidence_status === "not_assessed");
ok("route: existing response keys preserved (total/critical/high/medium/services)",
  ["total", "critical", "high", "medium", "services"].every((k) => k in rNoDomains));

const rNoScan = await route({ scans: {} });               // domain exists, no completed scan
ok("route: domain with no completed scan → not_assessed", rNoScan.evidence_status === "not_assessed");

const rR2Missing = await route({ reports: {} });          // scan exists, report missing
ok("route: R2 report missing → unavailable (never a clean total:0)", rR2Missing.evidence_status === "unavailable" && rR2Missing.total === 0);

const rR2Throw = await route({ reports: { "reports/s1.json": "R2_THROW" } });
ok("route: R2 malformed → unavailable", rR2Throw.evidence_status === "unavailable");

const rModUnavail = await route({ reports: { "reports/s1.json": { modules: { admin_surface_detection: { evidence_status: "unavailable", services: [] } } } } });
ok("route: admin module unavailable → unavailable", rModUnavail.evidence_status === "unavailable");

const rHealthy = await route({ reports: { "reports/s1.json": { modules: { admin_surface_detection: { evidence_status: "assessed_healthy", services: [] } } } } });
ok("route: admin assessed_healthy, zero services → assessed_healthy", rHealthy.evidence_status === "assessed_healthy" && rHealthy.total === 0);

const rIssue = await route({ reports: { "reports/s1.json": { domain: "example.com", modules: { admin_surface_detection: { evidence_status: "issue_detected", services: [{ hostname: "jenkins.example.com", product: "Jenkins", category: "admin_panel", risk_level: "critical", confidence: "confirmed" }] } } } } });
ok("route: verified admin surface → issue_detected + total>0", rIssue.evidence_status === "issue_detected" && rIssue.total > 0);

// ── 4. MUTATION HARNESS — the honesty gates are load-bearing ─────────────────
// Rewrites BOTH same-directory (`./x.js`) and parent-directory (`../lib/x.js`)
// relative imports to absolute file URLs. The mutant is imported from a temp dir, so
// any relative specifier left untouched fails to resolve — `../lib/...` was missed
// until the shared fetch-observation classifier introduced one.
const rew = (src) => src.replace(/from "(\.\.?\/[^"]+)"/g, (_m, f) => `from ${JSON.stringify(absU(f))}`);
async function mutant(srcPath, from, to) {
  const src = fs.readFileSync(srcPath, "utf8");
  if (!src.includes(from)) return { anchor: false };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "a3-"));
  const file = path.join(dir, "m.mjs");
  fs.writeFileSync(file, rew(src).replace(from, to));
  const mod = await import(`${pathToFileURL(file).href}?t=${Date.now()}-${Math.random()}`);
  fs.rmSync(dir, { recursive: true, force: true });
  return { anchor: true, mod };
}

// M1: producer maps unavailable → healthy.
{
  const m = await mutant(ASSET_INTEL, 'evidence_status = "unavailable";', 'evidence_status = "assessed_healthy";');
  const r = m.anchor ? m.mod.runAdminSurfaceModule({ asset_exposure: { assets: [{ host: "x", reachable: null }], incomplete: true } }) : null;
  ok("mutation M1 (unavailable→healthy) is CAUGHT", m.anchor && r.evidence_status === "assessed_healthy");
}
// M2: producer drops the incomplete detection (collapse unavailable into clean).
{
  const m = await mutant(ASSET_INTEL, "exposure.error || exposure.incomplete === true", "exposure.error || false");
  const r = m.anchor ? m.mod.runAdminSurfaceModule({ asset_exposure: { assets: [{ host: "x", reachable: null }], incomplete: true } }) : null;
  ok("mutation M2 (incomplete no longer unavailable) is CAUGHT", m.anchor && r.evidence_status !== "unavailable");
}
// M3: producer suppresses a verified finding (issue → healthy).
{
  const m = await mutant(ASSET_INTEL, 'evidence_status = "issue_detected";', 'evidence_status = "assessed_healthy";');
  const r = m.anchor ? m.mod.runAdminSurfaceModule({ asset_exposure: { assets: [ADMIN_HOST], error: null } }) : null;
  ok("mutation M3 (suppress verified finding) is CAUGHT", m.anchor && r.evidence_status !== "issue_detected");
}
// M4: posture awards credit without evidence (null → 100).
{
  const m = await mutant(POSTURE, "    admScore = null;", "    admScore = 100;");
  const r = m.anchor ? m.mod.computeSecurityPosture(SC, { modules: { admin_surface_detection: { evidence_status: "unavailable", total: 0 } } }) : null;
  ok("mutation M4 (unavailable → 100 score credit) is CAUGHT", m.anchor && r.admin_exposure.score === 100);
}

console.log(`\nA3 admin evidence-status: ${pass}/${pass + fail} passed`);
if (fail) { console.error("a3-admin-evidence-status validation FAILED"); process.exit(1); }
console.log("a3-admin-evidence-status validation passed");
