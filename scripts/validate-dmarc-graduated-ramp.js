#!/usr/bin/env node
//
// Graduated-reject ramp + per-tag diff + configurable-threshold runtime proof.
// Epic #5 of the Managed DMARC Policy Journey. Pure-function harness (no DB) —
// covers the three things the graduated ramp adds on top of the lifecycle proof
// in validate-hosted-dmarc-lifecycle.js:
//   • DMARC_RAMP_LADDER without pct (RFC 9989): t=y testing steps, step mapping,
//     what a rollback restores, and how a PUT names a step
//   • dmarcTagDiff        — per-tag before→after, never a blind overwrite
//   • resolveRampThresholds + evaluateRampReadiness/shouldAutoRollback overrides
// Node 24+. CI-blocking.
//
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "hosted-dmarc.js")).href);
const {
  DMARC_RAMP_LADDER, dmarcRampStepIndex, dmarcTagDiff, buildDmarcPolicyValue, withoutLegacyPct, legacyPctNotice,
  resolveRampThresholds, evaluateRampReadiness, shouldAutoRollback,
} = eng;
const { resolveRequestedRampStep } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "routes", "email-protection.js")).href);

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

// ── RFC 9989 ladder: no pct; each policy is tested (t=y) before it applies ──
// RFC 9989 Appendix A.6 removed pct; section 4.7 defines t=y as "apply one
// level below the published policy".
ok("ladder has five steps", DMARC_RAMP_LADDER.length === 5);
ok("ladder order: none → quarantine t=y → quarantine → reject t=y → reject",
   JSON.stringify(DMARC_RAMP_LADDER.map((s) => s.key)) === JSON.stringify(["none", "quarantine_testing", "quarantine", "reject_testing", "reject"]));
ok("no ladder step carries a pct", DMARC_RAMP_LADDER.every((s) => !("pct" in s)));
ok("no ladder label or description claims a percentage", DMARC_RAMP_LADDER.every((s) => !/%|percent/i.test(`${s.label} ${s.description}`)));

// Every step, built from a record that still carries pct and t, writes no pct.
const legacy = "v=DMARC1; p=reject; pct=50; t=n; rua=mailto:a@b";
for (const step of DMARC_RAMP_LADDER) {
  const built = buildDmarcPolicyValue(legacy, { policy: step.policy, testing: step.testing });
  ok(`${step.key}: built`, built.ok === true);
  ok(`${step.key}: never writes pct`, built.ok && !/pct\s*=/i.test(built.value));
  ok(`${step.key}: t=y exactly when testing`, built.ok && /(^|;)\s*t=y\s*(;|$)/.test(built.value) === step.testing && !/t=n/.test(built.value));
  ok(`${step.key}: other tags kept`, built.ok && built.value.includes("rua=mailto:a@b"));
  ok(`${step.key}: reads back as the same step`, built.ok && DMARC_RAMP_LADDER[dmarcRampStepIndex(built.value)]?.key === step.key);
}
ok("a pct request is refused", buildDmarcPolicyValue("v=DMARC1; p=none", { policy: "quarantine", pct: 50 }).ok === false);

// ── dmarcRampStepIndex: t=y, and legacy pct read as testing (never overstated) ─
const idx = (v) => DMARC_RAMP_LADDER[dmarcRampStepIndex(v)]?.key;
ok("p=none → none", idx("v=DMARC1; p=none; rua=mailto:a@b") === "none");
ok("p=quarantine; t=y → quarantine_testing", idx("v=DMARC1; p=quarantine; t=y") === "quarantine_testing");
ok("p=quarantine → quarantine", idx("v=DMARC1; p=quarantine") === "quarantine");
ok("p=reject; t=y → reject_testing", idx("v=DMARC1; p=reject; t=y") === "reject_testing");
ok("p=reject; t=n → reject", idx("v=DMARC1; p=reject; t=n") === "reject");
ok("legacy reject pct=50 → reject_testing", idx("v=DMARC1; p=reject; pct=50") === "reject_testing");
ok("legacy quarantine pct=0 → quarantine_testing", idx("v=DMARC1; p=quarantine; pct=0") === "quarantine_testing");
ok("legacy pct=100 → as written", idx("v=DMARC1; p=reject; pct=100") === "reject");

// ── withoutLegacyPct: what a rollback restores ───────────────────────────────
ok("pct below 100 becomes t=y, other tags kept",
   withoutLegacyPct("v=DMARC1; p=reject; pct=50; rua=mailto:a@b") === "v=DMARC1; p=reject; t=y; rua=mailto:a@b");
ok("pct=100 is dropped", withoutLegacyPct("v=DMARC1; p=reject; pct=100; rua=mailto:a@b") === "v=DMARC1; p=reject; rua=mailto:a@b");
ok("an existing t is kept, not duplicated", withoutLegacyPct("v=DMARC1; p=reject; t=n; pct=50") === "v=DMARC1; p=reject; t=n");
ok("p=none with pct gets no t", withoutLegacyPct("v=DMARC1; p=none; pct=10") === "v=DMARC1; p=none");
ok("a value with no pct is unchanged", withoutLegacyPct("v=DMARC1; p=quarantine; rua=mailto:a@b") === "v=DMARC1; p=quarantine; rua=mailto:a@b");
ok("notice for a value with pct", /pct=50/.test(legacyPctNotice("v=DMARC1; p=reject; pct=50")?.message || "") && !/% of/.test(legacyPctNotice("v=DMARC1; p=reject; pct=50").message));
ok("no notice without pct", legacyPctNotice("v=DMARC1; p=reject") === null);

// ── Autopilot takes the same steps, testing first ────────────────────────────
const auto = (value) => eng.autopilotNextStep(value);
ok("autopilot from none → quarantine with t=y", JSON.stringify(auto("v=DMARC1; p=none")) === JSON.stringify({ policy: "quarantine", testing: true }));
ok("autopilot from quarantine t=y → quarantine", JSON.stringify(auto("v=DMARC1; p=quarantine; t=y")) === JSON.stringify({ policy: "quarantine", testing: false }));
ok("autopilot from quarantine → reject with t=y", JSON.stringify(auto("v=DMARC1; p=quarantine")) === JSON.stringify({ policy: "reject", testing: true }));
ok("autopilot from a legacy reject pct=50 → reject as written", JSON.stringify(auto("v=DMARC1; p=reject; pct=50")) === JSON.stringify({ policy: "reject", testing: false }));
ok("autopilot stops at reject", auto("v=DMARC1; p=reject") === null);
ok("autopilot's step never writes pct", buildDmarcPolicyValue("v=DMARC1; p=reject; pct=50", auto("v=DMARC1; p=reject; pct=50")).value === "v=DMARC1; p=reject");

// ── The PUT request names a step ─────────────────────────────────────────────
const at = (key) => DMARC_RAMP_LADDER.findIndex((s) => s.key === key);
const want = (body, from, key) => DMARC_RAMP_LADDER[resolveRequestedRampStep(body, at(from))]?.key === key;
ok("{step} is used as given", want({ step: "reject_testing" }, "none", "reject_testing"));
ok("unknown step → refused", resolveRequestedRampStep({ step: "reject_50" }, at("none")) === -1);
ok("{policy, testing:true}", want({ policy: "quarantine", testing: true }, "none", "quarantine_testing"));
ok("bare stricter policy → its testing step first", want({ policy: "quarantine" }, "none", "quarantine_testing"));
ok("bare same policy → as written (testing → full)", want({ policy: "quarantine" }, "quarantine_testing", "quarantine"));
ok("bare looser policy → as written (the step down)", want({ policy: "quarantine" }, "reject", "quarantine"));
ok("bare reject from quarantine → reject_testing", want({ policy: "reject" }, "quarantine", "reject_testing"));
ok("a non-boolean testing is refused", resolveRequestedRampStep({ policy: "reject", testing: "yes" }, at("none")) === -1);

// ── API projection: ladder, step keys, step down, the legacy pct notice ─────
const row = (value) => ({ id: "hd-1", domain: "example.com", record_type: "dmarc", hosted_name: "hd-1.dmarc.cybermeters.com",
  current_value: value, previous_value: null, status: "connected", created_at: "2026-10-01" });
const atReject = eng.hostedDnsRecordToApi(row("v=DMARC1; p=reject; rua=mailto:a@b"));
ok("API: current step is reject, no next step", atReject.policy_step?.key === "reject" && atReject.next_step === null);
ok("API: the step down is reject_testing", atReject.previous_step?.key === "reject_testing" && atReject.previous_step.testing === true);
ok("API: the whole ladder, keyed, with no pct", atReject.ladder?.length === 5 && atReject.ladder.every((s) => s.key && !("pct" in s)));
ok("API: no legacy notice without pct", atReject.legacy_pct === null);
const atNone = eng.hostedDnsRecordToApi(row("v=DMARC1; p=none; rua=mailto:a@b"));
ok("API: from none the next step is quarantine_testing", atNone.next_step?.key === "quarantine_testing" && atNone.previous_step === null);
ok("API: the next-step diff is the real tag change (p and t), never pct",
   JSON.stringify(atNone.next_step_diff) === JSON.stringify([{ tag: "p", before: "none", after: "quarantine" }, { tag: "t", before: null, after: "y" }]));
const legacyRow = eng.hostedDnsRecordToApi(row("v=DMARC1; p=reject; pct=50; rua=mailto:a@b"));
ok("API: a record still carrying pct gets the notice", legacyRow.legacy_pct?.pct === "50");
ok("API: and reads as the testing step (progress not overstated)", legacyRow.policy_step?.key === "reject_testing");
const pctKeys = (value) => { const found = []; JSON.stringify(value, (key, v) => { if (key === "pct") found.push(v); return v; }); return found; };
ok("API: no step or field carries pct; only the legacy notice names it",
   pctKeys([atReject, atNone]).length === 0 && pctKeys({ ...legacyRow, legacy_pct: null }).length === 0);

// ── Customer wording: no "% of mail" claim anywhere in the API, MCP or emails ─
// RFC 9989 has no percentage of mail; a legacy pct is named, never interpreted.
{
  const fs = await import("node:fs");
  const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory() ? walk(path.join(dir, entry.name)) : /\.(m?js)$/.test(entry.name) ? [path.join(dir, entry.name)] : []);
  const roots = ["workers/scan-api/src", "mcp-server/src", "shared"].map((r) => path.join(root, r)).filter((r) => fs.existsSync(r));
  const claims = roots.flatMap(walk).flatMap((file) => fs.readFileSync(file, "utf8").split("\n")
    .map((line, i) => ({ file: path.relative(root, file), line: i + 1, text: line }))
    .filter(({ text }) => /%\s+of\s+(mail|messages|email|failing)|increase pct|raise pct|pct gradually/i.test(text)));
  ok(`no percentage-of-mail claim in backend wording${claims.length ? `: ${claims.map((c) => `${c.file}:${c.line}`).join(", ")}` : ""}`, claims.length === 0);
}

// ── dmarcTagDiff: per-tag before→after ────────────────────────────────────────
const d1 = dmarcTagDiff("v=DMARC1; p=none; rua=mailto:a@b", "v=DMARC1; p=reject; t=y; rua=mailto:a@b");
const find = (arr, t) => arr.find((c) => c.tag === t);
ok("diff reports p change none→reject", find(d1, "p")?.before === "none" && find(d1, "p")?.after === "reject");
ok("diff reports t added (null→y)", find(d1, "t")?.before === null && find(d1, "t")?.after === "y");
ok("diff leaves unchanged tags (rua) out", !find(d1, "rua"));
ok("identical records → empty diff (no phantom change)", dmarcTagDiff("v=DMARC1; p=none", "v=DMARC1; p=none").length === 0);
const d2 = dmarcTagDiff("v=DMARC1; p=quarantine; pct=50", "v=DMARC1; p=quarantine");
ok("diff reports a legacy pct removed (50→null)", find(d2, "pct")?.before === "50" && find(d2, "pct")?.after === null);

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
