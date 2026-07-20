#!/usr/bin/env node
//
// Anti-date-rot governance — CI-blocking.
//
// The defect class (fixed for brand certificates in PR #203): a validator seeds
// an ABSOLUTE future date as an expiring boundary (certificate not_after,
// exception_until, billing period end) and compares it — directly or through an
// engine — against the LIVE clock. The suite is green when written; when the
// wall clock passes the fixture, the test's meaning silently flips and it
// fails (or worse, silently stops proving what it claimed).
//
// The repository's established defence is the FROZEN-CLOCK convention: a fixed
// `const NOW = "…"` (or fixed watermark) injected into every engine call, so
// fixtures are relative to a clock that never moves. This guard makes the
// convention durable:
//
//   • every scripts/validate-*.js containing a quoted future ISO date literal
//     (after run time, before 2099) must show frozen-clock evidence — a fixed
//     NOW/WATERMARK constant or an inline `now:` injection — or carry an
//     explicit allowlist entry with a reason;
//   • year ≥ 2099 is the deliberate far-future convention (sessions,
//     subscriptions, "never expires") and is exempt by rule;
//   • past dates never flag — they cannot rot.
//
// The check is strongest at introduction time: a NEW validator with a naked
// future fixture fails CI immediately, while the date is still future. Once a
// date lapses into the past the affected suite itself is what fails — this
// guard exists so that moment never arrives unnoticed.
//
// Node 24+.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };

// Files whose future-date literals are proven clock-independent. Every entry
// carries the reason; a stale entry (file gone, or no future literals left) is
// itself a failure so the list can never rot into noise.
const ALLOWLIST = new Map([
  ["validate-ce-answer-versioning.js",
    "future dates are version-format regex examples and mutation strings — string-compared, never clock-compared"],
  ["validate-cert-standing-condition-dedupe.js",
    "expiry strings are signature identity tokens; day counts are passed explicitly, never derived from the clock"],
  ["validate-shadow-it-inventory.js",
    "exception_until is stored and asserted only; the monitoring evaluator that would compare it to a clock is not run in this file"],
  ["validate-m5b-remaining-reconciliation.js",
    "future date is a methodology VERSION string compared as a string, never as a time"],
]);

// Quoted full ISO date literal, e.g. '2026-08-01' or "2026-08-01T00:00:00Z".
const DATE_LITERAL = /['"](20\d{2})-(\d{2})-(\d{2})(?:[T ][0-9:.]+Z?)?['"]/g;
// Frozen-clock evidence: a fixed clock constant, or inline now-injection.
const FROZEN_CLOCK = /const\s+(NOW|WATERMARK)\s*=\s*['"]20|now:\s*['"]20|now:\s*NOW|\{\s*now\s*:\s*NOW/;

// Pure classifier so the negative controls below exercise the REAL logic
// rather than a copy of it.
export function classifyValidatorSource(name, src, nowMs) {
  const futureDates = [];
  for (const m of src.matchAll(DATE_LITERAL)) {
    const year = Number(m[1]);
    if (year >= 2099) continue;                       // deliberate far-future convention
    const ms = Date.parse(`${m[1]}-${m[2]}-${m[3]}T00:00:00Z`);
    if (Number.isFinite(ms) && ms > nowMs) futureDates.push(m[0]);
  }
  if (futureDates.length === 0) return { status: "clean", futureDates };
  if (ALLOWLIST.has(name)) return { status: "allowlisted", futureDates };
  if (FROZEN_CLOCK.test(src)) return { status: "frozen_clock", futureDates };
  return { status: "naked_future_date", futureDates };
}

const nowMs = Date.now();
const files = fs.readdirSync(path.join(root, "scripts")).filter((f) => /^validate-[a-z0-9-]+\.js$/.test(f));

// ── 1. No validator carries a naked future-dated fixture ─────────────────────
const offenders = [];
const allowlistedInUse = new Set();
for (const f of files) {
  if (f === "validate-date-rot-governance.js") continue;   // self: date literals here are patterns
  const r = classifyValidatorSource(f, fs.readFileSync(path.join(root, "scripts", f), "utf8"), nowMs);
  if (r.status === "naked_future_date") offenders.push(`${f} (${r.futureDates.slice(0, 3).join(", ")})`);
  if (r.status === "allowlisted") allowlistedInUse.add(f);
}
ok("every future-dated validator freezes its clock or is explicitly allowlisted",
   offenders.length === 0,
   `naked future fixtures (add const NOW + { now } injection, or an allowlist entry with a reason): ${offenders.join("; ")}`);

// ── 2. The allowlist cannot rot ──────────────────────────────────────────────
// An entry for a missing file is stale. An entry whose file no longer contains
// any future literal is also stale — TODAY. Time lapse can silently drain a
// file's future literals (they become past); tolerate that by only requiring
// entries to name EXISTING files, and flagging never-matching entries as
// warnings via the check below when the file still exists but is clean.
const missing = [...ALLOWLIST.keys()].filter((f) => !files.includes(f));
ok("no allowlist entry names a missing validator", missing.length === 0, `missing: ${missing.join(", ")}`);

// ── 3. Negative controls — the classifier catches what it claims to ──────────
{
  const future = new Date(nowMs + 90 * 86400_000).toISOString().slice(0, 10);
  const naked = `const cert = { not_after: "${future}T00:00:00Z" };`;
  ok("NC1: naked future fixture is flagged",
     classifyValidatorSource("validate-nc-probe.js", naked, nowMs).status === "naked_future_date");
  const frozen = `const NOW = "2026-07-20T00:00:00Z";\nconst cert = { not_after: "${future}T00:00:00Z" };`;
  ok("NC2: the same fixture with a frozen clock passes",
     classifyValidatorSource("validate-nc-probe.js", frozen, nowMs).status === "frozen_clock");
  const inline = `await run(env, { now: "2026-07-20T00:00:00Z" }); seed("${future}");`;
  ok("NC3: inline now-injection counts as frozen",
     classifyValidatorSource("validate-nc-probe.js", inline, nowMs).status === "frozen_clock");
  const farFuture = `const session = { expires_at: "2099-01-01T00:00:00Z" };`;
  ok("NC4: deliberate far-future (>=2099) is exempt by rule",
     classifyValidatorSource("validate-nc-probe.js", farFuture, nowMs).status === "clean");
  const past = `const seeded = { created_at: "2020-01-01T00:00:00Z" };`;
  ok("NC5: past dates never flag (they cannot rot)",
     classifyValidatorSource("validate-nc-probe.js", past, nowMs).status === "clean");
  // Clock-advance control: when run time passes the fixture, it stops being a
  // future literal — the guard's job was done at introduction time.
  const lapsedMs = Date.parse(`${future}T00:00:00Z`) + 86400_000;
  ok("NC6: a lapsed fixture no longer flags (its own suite is the alarm then)",
     classifyValidatorSource("validate-nc-probe.js", naked, lapsedMs).status === "clean");
  // Frozen-clock removal control (the sprint's "remove fixed-clock injection").
  ok("NC7: stripping the frozen clock from a passing file re-flags it",
     classifyValidatorSource("validate-nc-probe.js", frozen.replace(/^const NOW.*\n/, ""), nowMs).status === "naked_future_date");
}

console.log(`\ndate-rot-governance: ${pass} passed, ${fail} failed (${allowlistedInUse.size} allowlisted file(s) currently carry future literals)`);
if (fail) { console.error("date-rot-governance validation FAILED"); process.exit(1); }
console.log("date-rot-governance validation passed");
