#!/usr/bin/env node
//
// Graduated-reject ramp + per-tag diff + configurable-threshold runtime proof.
// Epic #5 of the Managed DMARC Policy Journey. Pure-function harness (no DB) —
// covers the three things the graduated ramp adds on top of the lifecycle proof
// in validate-hosted-dmarc-lifecycle.js:
//   • DMARC_RAMP_LADDER graduated reject (9 steps) + dmarcRampStepIndex snapping
//   • dmarcTagDiff        — per-tag before→after, never a blind overwrite
//   • resolveRampThresholds + evaluateRampReadiness/shouldAutoRollback overrides
// Node 24+. CI-blocking.
//
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "hosted-dmarc.js")).href);
const {
  DMARC_RAMP_LADDER, dmarcRampStepIndex, dmarcTagDiff,
  resolveRampThresholds, evaluateRampReadiness, shouldAutoRollback,
} = eng;

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

// ── Graduated-reject ladder shape ─────────────────────────────────────────────
ok("ladder has 9 graduated steps", DMARC_RAMP_LADDER.length === 9);
ok("ladder ends at full reject", DMARC_RAMP_LADDER[8].policy === "reject" && DMARC_RAMP_LADDER[8].pct === 100);
ok("reject is percentage-ramped (10/25/50/100), never a jump to 100",
   DMARC_RAMP_LADDER[5].policy === "reject" && DMARC_RAMP_LADDER[5].pct === 10 &&
   DMARC_RAMP_LADDER[6].pct === 25 && DMARC_RAMP_LADDER[7].pct === 50);
ok("quarantine still fully ramped before any reject", DMARC_RAMP_LADDER[4].policy === "quarantine" && DMARC_RAMP_LADDER[4].pct === 100);

// ── dmarcRampStepIndex: exact matches across the graduated ladder ─────────────
const idx = (v) => dmarcRampStepIndex(v);
ok("p=none → step 0", idx("v=DMARC1; p=none; rua=mailto:a@b") === 0);
ok("quarantine pct=5 → step 1", idx("v=DMARC1; p=quarantine; pct=5") === 1);
ok("reject pct=10 → step 5", idx("v=DMARC1; p=reject; pct=10") === 5);
ok("reject pct=25 → step 6", idx("v=DMARC1; p=reject; pct=25") === 6);
ok("reject pct=50 → step 7", idx("v=DMARC1; p=reject; pct=50") === 7);
ok("reject (no pct = 100) → step 8", idx("v=DMARC1; p=reject") === 8);

// ── dmarcRampStepIndex: off-ladder values snap DOWN (never overstate progress) ─
ok("reject pct=60 snaps down to the 50% step (7)", idx("v=DMARC1; p=reject; pct=60") === 7);
ok("reject pct=5 snaps to the first reject step (5), never below", idx("v=DMARC1; p=reject; pct=5") === 5);
ok("quarantine pct=60 snaps down to the 50% quarantine step (3)", idx("v=DMARC1; p=quarantine; pct=60") === 3);

// ── dmarcTagDiff: per-tag before→after ────────────────────────────────────────
const d1 = dmarcTagDiff("v=DMARC1; p=none; rua=mailto:a@b", "v=DMARC1; p=reject; pct=10; rua=mailto:a@b");
const find = (arr, t) => arr.find((c) => c.tag === t);
ok("diff reports p change none→reject", find(d1, "p")?.before === "none" && find(d1, "p")?.after === "reject");
ok("diff reports pct added (null→10)", find(d1, "pct")?.before === null && find(d1, "pct")?.after === "10");
ok("diff leaves unchanged tags (rua) out", !find(d1, "rua"));
ok("identical records → empty diff (no phantom change)", dmarcTagDiff("v=DMARC1; p=none", "v=DMARC1; p=none").length === 0);
const d2 = dmarcTagDiff("v=DMARC1; p=quarantine; pct=50", "v=DMARC1; p=quarantine");
ok("diff reports pct removed (50→null)", find(d2, "pct")?.before === "50" && find(d2, "pct")?.after === null);

// ── resolveRampThresholds: defaults, override, invalid-falls-back ─────────────
const def = resolveRampThresholds({});
ok("defaults match module constants", def.minMessages === 50 && def.minPassRate === 97 && def.minDaysSinceChange === 3 && def.rollbackDropPp === 5 && def.rollbackMinMessages === 20);
ok("env override is honoured", resolveRampThresholds({ HOSTED_DMARC_MIN_PASS_RATE: "90" }).minPassRate === 90);
ok("non-numeric env falls back to the default (no silent break)", resolveRampThresholds({ HOSTED_DMARC_MIN_MESSAGES: "abc" }).minMessages === 50);

// ── evaluateRampReadiness / shouldAutoRollback honour overrides ───────────────
const borderline = { pass_rate: 95, total_messages: 100, days_since_change: 5 };
ok("95% not ready under the default 97% bar", evaluateRampReadiness(borderline).ready === false);
ok("95% ready once the bar is lowered to 90% via override", evaluateRampReadiness(borderline, resolveRampThresholds({ HOSTED_DMARC_MIN_PASS_RATE: "90" })).ready === true);

const smallDrop = { baseline_pass_rate: 99, current_pass_rate: 96, total_messages: 100 };
ok("3pp drop does not roll back under the default 5pp trigger", shouldAutoRollback(smallDrop) === false);
ok("3pp drop rolls back once the trigger is tightened to 2pp", shouldAutoRollback(smallDrop, resolveRampThresholds({ HOSTED_DMARC_ROLLBACK_DROP_PP: "2" })) === true);
const lowVol = { baseline_pass_rate: 99, current_pass_rate: 80, total_messages: 10 };
ok("low volume suppresses rollback under the default 20-message floor", shouldAutoRollback(lowVol) === false);
ok("low-volume rollback fires once the floor is lowered via override", shouldAutoRollback(lowVol, resolveRampThresholds({ HOSTED_DMARC_ROLLBACK_MIN_MESSAGES: "5" })) === true);

console.log(`\nDMARC graduated ramp: ${pass}/${pass + fail} passed`);
if (fail) { console.error("dmarc-graduated-ramp validation FAILED"); process.exit(1); }
console.log("dmarc-graduated-ramp validation passed");
