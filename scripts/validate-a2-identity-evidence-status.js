#!/usr/bin/env node
//
// A2 — Identity Exposure evidence-status honesty validator.
//
// Proves that missing evidence, failed R2 reads, failed D1 queries, or nothing to
// assess do NOT collapse into a customer-facing Low / clean / no-exposure verdict.
// Uses the REAL producer computeIdentityExposure() driven by a mock env (D1/R2
// boundary only), and the REAL pure deriveLevel(). No documentation-only mock of
// the logic itself.
//
// Pure-function harness: no live DNS/D1/R2. Node 24+.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const SRC = path.join(ROOT, "workers", "scan-api", "src", "engines", "identity-exposure.js");
const { computeIdentityExposure, deriveLevel } = await import(pathToFileURL(SRC).href);

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  cond ? pass++ : fail++;
  console.log(`${cond ? "ok  " : "FAIL"} - ${name}${!cond && detail ? ` -- ${detail}` : ""}`);
};

const CLEAN_REPORT = { modules: { email_security: { spf: { present: true }, dmarc: { present: true, policy: "reject" } } } };
const SPOOFABLE_REPORT = { modules: { email_security: { spf: { present: false }, dmarc: { present: false, policy: null } } } };
// Benign = a reassuring customer conclusion: level Low, or a POSITIVE "all look
// clean" claim. (The honest Unavailable summary says "not a clean result" — that
// must NOT count as benign, so match the positive phrase, not the bare word.)
const isBenign = (r) => r.identity_exposure_level === "Low" || /(all )?look clean/i.test(r.summary || "");

// Mock env: exercises the REAL producer's failure/absence branches. Pass an Error
// as a query value to simulate a rejected D1 promise (the producer's .catch fires).
function mockEnv({ login = { results: [] }, brand = { results: [] }, scans = { results: [] }, reports = {} } = {}) {
  const pick = (sql) => (sql.includes("identity_assets") ? login : sql.includes("workspace_brand_assets") ? brand : scans);
  const db = {
    prepare(sql) {
      const v = pick(sql);
      return { bind() { return { all() { return v instanceof Error ? Promise.reject(v) : Promise.resolve(v); } }; } };
    },
  };
  const cybermeters_reports = {
    get(key) {
      if (!(key in reports)) return Promise.resolve(null);            // R2 object missing
      const r = reports[key];
      if (r === "R2_THROW") return Promise.resolve({ json: () => Promise.reject(new Error("bad json")) });
      return Promise.resolve({ json: () => Promise.resolve(r) });
    },
  };
  return { cybermeters_db: db, cybermeters_reports };
}
const scanRow = { results: [{ scan_id: "s1", domain: "example.com" }] };
const compute = (opts) => computeIdentityExposure(mockEnv(opts), "ws1");

// ── 1/2. Query / read failure → Unavailable (never benign) ───────────────────
const loginFail = await compute({ login: new Error("d1 down") });
ok("D1 login query failure → Unavailable", loginFail.identity_exposure_level === "Unavailable");
ok("D1 login failure is NOT benign (no Low/clean)", !isBenign(loginFail));

const scansFail = await compute({ scans: new Error("d1 down") });
ok("D1 scans query failure → Unavailable", scansFail.identity_exposure_level === "Unavailable" && !isBenign(scansFail));

const brandFail = await compute({ brand: new Error("d1 down") });
ok("D1 brand query failure → Unavailable", brandFail.identity_exposure_level === "Unavailable" && !isBenign(brandFail));

const r2Missing = await compute({ scans: scanRow /* reports: {} → get returns null */ });
ok("R2 report missing (had a completed scan) → Unavailable", r2Missing.identity_exposure_level === "Unavailable" && !isBenign(r2Missing));

const r2Throw = await compute({ scans: scanRow, reports: { "reports/s1.json": "R2_THROW" } });
ok("R2 read/parse failure (malformed) → Unavailable, NOT healthy", r2Throw.identity_exposure_level === "Unavailable" && !isBenign(r2Throw));

// ── 3. Nothing to assess → Not Assessed (never benign) ───────────────────────
const nothing = await compute({});   // all queries succeed, all empty
ok("nothing assessable → Not Assessed", nothing.identity_exposure_level === "Not Assessed");
ok("Not Assessed is NOT benign (no Low/clean)", !isBenign(nothing));

// ── 6. Successful observation, ZERO exposure → genuine Low ───────────────────
const genuineLow = await compute({
  login: { results: [{ hostname: "app.example.com", identity_type: "sso", internet_exposed: 0, risk_score: 0 }] },
  scans: scanRow, reports: { "reports/s1.json": CLEAN_REPORT },
});
ok("observed assets + readable clean report + zero exposure → Low", genuineLow.identity_exposure_level === "Low");
ok("genuine Low carries the reassuring clean summary", /clean/i.test(genuineLow.summary));

// ── 7. Successful observation WITH exposure → High (never hidden) ─────────────
const spoofable = await compute({ scans: scanRow, reports: { "reports/s1.json": SPOOFABLE_REPORT } });
ok("readable spoofable domain → High", spoofable.identity_exposure_level === "High");
// Real exposure must surface even when ANOTHER source is unavailable.
const exposureDespiteFailure = await compute({
  login: new Error("d1 down"),
  scans: scanRow, reports: { "reports/s1.json": SPOOFABLE_REPORT },
});
ok("real exposure surfaces as High even when another source is unavailable",
  exposureDespiteFailure.identity_exposure_level === "High");

// ── 9. Legacy / minimal shapes do not crash ──────────────────────────────────
ok("deriveLevel with legacy 3-arg call does not crash", (() => {
  const r = deriveLevel({ internet_facing: 0 }, { active: 0, can_send_mail: 0, can_host_login: 0 }, { spoofable_domains: 0, checked_domains: 1 });
  return r.identity_exposure_level === "Low";
})());
ok("computeIdentityExposure over a minimal legacy report does not crash",
  (await compute({ scans: scanRow, reports: { "reports/s1.json": { modules: {} } } })).identity_exposure_level === "Unavailable");

// ── 10. MUTATION HARNESS — the honesty gates are load-bearing ────────────────
// identity-exposure.js has no imports → mutant re-imports cleanly.
const src = fs.readFileSync(SRC, "utf8");
async function mutant(from, to) {
  if (!src.includes(from)) return { anchor: false };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "a2-"));
  const file = path.join(dir, "identity-exposure.mjs");
  fs.writeFileSync(file, src.replace(from, to));
  const m = await import(`${pathToFileURL(file).href}?t=${Date.now()}-${Math.random()}`);
  fs.rmSync(dir, { recursive: true, force: true });
  return { anchor: true, mod: m };
}

// M1: map unavailable → (fall through, becomes Low on assessed evidence).
{
  const m = await mutant("  if (unavailable) {", "  if (false) {");
  const r = m.anchor ? m.mod.deriveLevel({ internet_facing: 0 }, { active: 0, can_send_mail: 0, can_host_login: 0 }, { spoofable_domains: 0, checked_domains: 1 }, { unavailable: true, assessed: true }) : null;
  ok("mutation M1 (unavailable→Low) is CAUGHT", m.anchor && r.identity_exposure_level === "Low");
}
// M2: award healthy on missing evidence (not_assessed → Low).
{
  const m = await mutant("  if (!assessed) {", "  if (false) {");
  const r = m.anchor ? m.mod.deriveLevel({ internet_facing: 0 }, { active: 0, can_send_mail: 0, can_host_login: 0 }, { spoofable_domains: 0, checked_domains: 0 }, { unavailable: false, assessed: false }) : null;
  ok("mutation M2 (not_assessed→Low) is CAUGHT", m.anchor && r.identity_exposure_level === "Low");
}
// M3: collapse the unavailable tracking (failed query no longer flagged).
{
  const m = await mutant("catch(() => { loginUnavailable = true; return { results: [] }; })", "catch(() => { loginUnavailable = false; return { results: [] }; })");
  const r = m.anchor ? await m.mod.computeIdentityExposure(mockEnv({ login: new Error("d1 down"), scans: scanRow, reports: { "reports/s1.json": CLEAN_REPORT } }), "ws1") : null;
  ok("mutation M3 (drop unavailable tracking → Low) is CAUGHT", m.anchor && r.identity_exposure_level === "Low");
}
// M4: suppress a real exposure (the High/Medium gate).
{
  const m = await mutant("  if (highSignals >= 1 || mediumSignals >= 1) {", "  if (false) {");
  const r = m.anchor ? m.mod.deriveLevel({ internet_facing: 0 }, { active: 1, can_send_mail: 1, can_host_login: 0 }, { spoofable_domains: 1, checked_domains: 1 }, { unavailable: false, assessed: true }) : null;
  ok("mutation M4 (suppress real exposure) is CAUGHT", m.anchor && r.identity_exposure_level !== "High");
}

console.log(`\nA2 identity evidence-status: ${pass}/${pass + fail} passed`);
if (fail) { console.error("a2-identity-evidence-status validation FAILED"); process.exit(1); }
console.log("a2-identity-evidence-status validation passed");
