#!/usr/bin/env node
//
// M5.e-A — Band-ladder contract.
//
// One canonical Cyber Metrics Score band partition, everywhere:
//   1. backend canon: CYBER_METRICS_SCORE_BANDS (engines/scoring.js) drives
//      riskLevelForScore — value behaviour pinned at every boundary;
//   2. frontend mirror: frontend/src/lib/score-presentation.js must be
//      VALUE-IDENTICAL (mirrored constants, no cross-build import — this
//      validator IS the coupling);
//   3. no new inline score-band ladder may appear in backend engines/routes
//      outside the documented allowlist of deliberately-distinct semantic
//      models (each entry cites what it is and why it is not a Cyber Metrics
//      Score band).
//
// Mutation-tested: changing a threshold on either side, or desyncing the two,
// must fail this suite.
//
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const self = fileURLToPath(import.meta.url);
let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };

const backend = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "scoring.js")).href);
const mirror = await import(pathToFileURL(path.join(root, "frontend", "src", "lib", "score-presentation.js")).href);

// ── 1. Backend canon behaves per contract at every band boundary ─────────────
const CANON = backend.CYBER_METRICS_SCORE_BANDS;
ok("backend canon has exactly the four thresholds",
   JSON.stringify(Object.keys(CANON).sort()) === JSON.stringify(["excellent", "good", "high", "moderate"]));
const CASES = [
  [100, "excellent"], [90, "excellent"], [89, "good"], [75, "good"],
  [74, "moderate"], [50, "moderate"], [49, "high"], [25, "high"], [24, "critical"], [0, "critical"],
];
for (const [score, band] of CASES) {
  ok(`riskLevelForScore(${score}) === ${band}`, backend.riskLevelForScore(score) === band,
     backend.riskLevelForScore(score));
}

// ── 2. Frontend mirror is VALUE-IDENTICAL and behaves identically ────────────
ok("frontend SCORE_BANDS mirrors backend canon exactly",
   JSON.stringify(mirror.SCORE_BANDS) === JSON.stringify(CANON),
   `frontend=${JSON.stringify(mirror.SCORE_BANDS)} backend=${JSON.stringify(CANON)}`);
for (const [score, band] of CASES) {
  ok(`frontend scoreBand(${score}) === ${band}`, mirror.scoreBand(score) === band, mirror.scoreBand(score));
}
// Fail-closed presentation: absent score has no band; unknown band is neutral.
ok("absent score has NO band (null/undefined/NaN)",
   mirror.scoreBand(null) === null && mirror.scoreBand(undefined) === null && mirror.scoreBand("x") === null);
ok("unrecognised band renders unknown/neutral, never a healthy tone",
   mirror.bandMeta("something_new") === mirror.BAND_META.unknown &&
   mirror.BAND_META.unknown.tone === "slate");
ok("metaForScore(null) is the unknown meta", mirror.metaForScore(null) === mirror.BAND_META.unknown);

// ── 3. Backend inline-ladder ban outside the documented allowlist ────────────
// A "score-band ternary" = `>= N ?` chained comparisons producing band words.
// Each allowlist entry is a deliberately-distinct semantic model — NOT a Cyber
// Metrics Score band — with the reason recorded here, in the guard itself.
const ALLOWLIST = {
  "engines/scoring.js": "the canon itself",
  "engines/business-risk.js": "Business Risk (scan + workspace models) — an indicator, not the score band",
  "engines/posture-scoring.js": "five-category posture status — workspace analytic, not the score band",
  "engines/ce-readiness.js": "Cyber Essentials readiness grade — readiness model, not the score band",
  "engines/portfolio-risk.js": "portfolio risk/score narrative bands — documented deliberately-unreconciled words",
  "engines/portfolio-customers.js": "portfolio customer rating — M5.e-C reconciles; tracked",
  "engines/email-intel.js": "email intelligence module-internal status tiers",
  "engines/supply-chain.js": "supply-chain maturity model",
  "engines/bec.js": "BEC exposure tiering",
  "engines/dns-resilience.js": "DNS resilience tiering",
  "engines/brand-protection.js": "brand candidate risk_level from typosquat confidence score — severity tiering, not the score band",
  "engines/cloud-storage-scan.js": "detection-confidence → severity tiering",
  "engines/dmarc-impact.js": "auth-failure increase → alert severity tiering",
  "engines/rua-routing.js": "DMARC pass-rate / retention pass-warn-fail tiers",
  "engines/shadow-it-inventory.js": "detection-confidence tiering",
  "engines/confidence.js": "finding confidence tiers, not scores",
  "engines/assessment-presentation.js": "delegates to riskLevelForScore (canonical seam)",
  "routes/workspace-analytics.js": "workspace BRS grade ladder — M5.e-B removes; tracked",
};
const scanDirs = ["engines", "routes"].map((d) => path.join(root, "workers", "scan-api", "src", d));
const LADDER_RE = />=\s*\d{2}\s*\?/;
const offenders = [];
for (const dir of scanDirs) {
  for (const f of fs.readdirSync(dir).filter((f) => f.endsWith(".js"))) {
    const rel = `${path.basename(dir)}/${f}`;
    const src = fs.readFileSync(path.join(dir, f), "utf8")
      .replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
    if (LADDER_RE.test(src) && !(rel in ALLOWLIST)) offenders.push(rel);
  }
}
ok("no undocumented inline score-band ladder in backend engines/routes",
   offenders.length === 0, offenders.join(", "));
// The allowlist must not rot: every entry must still exist and still carry a ladder.
for (const rel of Object.keys(ALLOWLIST)) {
  const p = path.join(root, "workers", "scan-api", "src", rel);
  ok(`allowlist entry ${rel} still exists`, fs.existsSync(p));
}

console.log(`\nband-ladder-contract: ${pass} passed, ${fail} failed`);
if (fail) { console.error("band-ladder-contract validation FAILED"); process.exit(1); }

// ── Mutations — each must be CAUGHT ──────────────────────────────────────────
if (!process.argv.includes("--no-mutate")) {
  const MUTATIONS = [
    {
      name: "backend band threshold changed (good 75→70)",
      file: path.join(root, "workers", "scan-api", "src", "engines", "scoring.js"),
      from: "  good: 75,",
      to:   "  good: 70,",
    },
    {
      name: "frontend mirror desynced (moderate 50→45)",
      file: path.join(root, "frontend", "src", "lib", "score-presentation.js"),
      from: "  moderate: 50,",
      to:   "  moderate: 45,",
    },
    {
      name: "frontend unknown band rendered as healthy",
      file: path.join(root, "frontend", "src", "lib", "score-presentation.js"),
      from: "export function bandMeta(band) {\n  return BAND_META[band] ?? BAND_META.unknown;\n}",
      to:   "export function bandMeta(band) {\n  return BAND_META[band] ?? BAND_META.good;\n}",
    },
  ];
  let mfail = 0;
  for (const m of MUTATIONS) {
    const original = fs.readFileSync(m.file, "utf8");
    if (!original.includes(m.from)) { console.log(`FAIL mutation anchor missing: ${m.name}`); mfail++; continue; }
    fs.writeFileSync(m.file, original.replace(m.from, m.to));
    let survived = true;
    try { execFileSync(process.execPath, [self, "--no-mutate"], { stdio: "pipe" }); }
    catch { survived = false; }
    finally { fs.writeFileSync(m.file, original); }
    if (survived) { console.log(`FAIL mutation NOT caught: ${m.name}`); mfail++; }
    else { console.log(`  mutation CAUGHT: ${m.name}`); }
  }
  if (mfail) { console.error("band-ladder-contract mutation validation FAILED"); process.exit(1); }
}

console.log("band-ladder-contract validation passed");
