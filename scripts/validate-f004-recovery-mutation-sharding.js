#!/usr/bin/env node
//
// Focused contract for the F-004 mutation runner's internal sharding surface.
// This validator never executes a mutation. It proves that the list surface is
// deterministic, seven shards aggregate to the exact 53 unique registered
// mutants without overlap, and malformed CLI input fails before worktree setup.

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const RUNNER = path.join(ROOT, "scripts", "validate-f004-recovery-instrumentation-mutations.js");
const EXPECTED_MUTANTS = 53;

let pass = 0;
let fail = 0;
function ok(name, condition, detail = "") {
  if (condition) {
    pass += 1;
    console.log(`PASS ${name}`);
  } else {
    fail += 1;
    console.log(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

function run(args) {
  return spawnSync(process.execPath, [RUNNER, ...args], {
    cwd: ROOT,
    encoding: "utf8",
  });
}

function parseList(stdout) {
  const text = String(stdout || "").trimEnd();
  if (!text) return [];
  return text.split(/\r?\n/).map((line) => {
    const [id, rawIndex, file, ...nameParts] = line.split("\t");
    return { id, index: Number(rawIndex), file, name: nameParts.join("\t"), line };
  });
}

const full = run(["--list"]);
const fullAgain = run(["--list"]);
const all = parseList(full.stdout);
ok("--list exits zero", full.status === 0 && full.signal === null);
ok("--list writes no stderr", String(full.stderr || "") === "");
ok("--list is byte-deterministic", full.stdout === fullAgain.stdout);
ok("registered mutant count is pinned at 53", all.length === EXPECTED_MUTANTS, `got ${all.length}`);
ok("all mutant ids are unique", new Set(all.map(({ id }) => id)).size === EXPECTED_MUTANTS);
ok("all mutant names are unique", new Set(all.map(({ name }) => name)).size === EXPECTED_MUTANTS);
ok("indices are the exact contiguous range 0..52",
  all.every(({ index }, position) => index === position));
ok("ids are stable F004-M001..F004-M053",
  all.every(({ id }, index) => id === `F004-M${String(index + 1).padStart(3, "0")}`));
ok("every list row has a canonical mutation target",
  all.every(({ file }) => [
    "scripts/ops/backup-production-data.sh",
    "scripts/ops/restore-production-backup-to-staging.sh",
    "scripts/ops/f004-provider-adapter.sh",
  ].includes(file)));

const SHARD_TOTAL = 7;
const shardRuns = Array.from({ length: SHARD_TOTAL }, (_, shardIndex) => ({
  shardIndex,
  result: run(["--list", "--shard-index", String(shardIndex), "--shard-total", String(SHARD_TOTAL)]),
}));
const shardEntries = shardRuns.map(({ result }) => parseList(result.stdout));
ok("all seven shard-list calls exit zero without stderr",
  shardRuns.every(({ result }) => result.status === 0 && result.signal === null && result.stderr === ""));
ok("each shard is the deterministic index-modulo partition",
  shardEntries.every((entries, shardIndex) => entries.every(({ index }) => index % SHARD_TOTAL === shardIndex)));
const aggregate = shardEntries.flat();
ok("seven shards aggregate to exactly 53 rows", aggregate.length === EXPECTED_MUTANTS);
ok("seven-shard aggregate has no duplicate mutant id",
  new Set(aggregate.map(({ id }) => id)).size === EXPECTED_MUTANTS);
ok("seven-shard aggregate equals the complete registry",
  [...aggregate].sort((a, b) => a.index - b.index).map(({ line }) => line).join("\n")
    === all.map(({ line }) => line).join("\n"));
const shardSizes = shardEntries.map(({ length }) => length);
ok("partition is balanced to at most one mutant",
  Math.max(...shardSizes) - Math.min(...shardSizes) <= 1,
  JSON.stringify(shardSizes));

const equalsSyntax = run(["--list", "--shard-index=3", "--shard-total=7"]);
ok("equals-form shard arguments are byte-equivalent",
  equalsSyntax.status === 0 && equalsSyntax.stdout === shardRuns[3].result.stdout);
const onePerShard = run(["--list", "--shard-index", "52", "--shard-total", "53"]);
ok("53-way partition selects exactly its one indexed mutant",
  parseList(onePerShard.stdout).map(({ id }) => id).join(",") === "F004-M053");

const invalidCases = [
  ["--shard-index", "0"],
  ["--shard-total", "2"],
  ["--shard-index", "-1", "--shard-total", "2"],
  ["--shard-index", "2", "--shard-total", "2"],
  ["--shard-index", "0", "--shard-total", "0"],
  ["--shard-index", "0.5", "--shard-total", "2"],
  ["--shard-index", "0", "--shard-total", "54"],
  ["--shard-index", "0", "--shard-index", "0", "--shard-total", "2"],
  ["--list", "--list"],
  ["--unknown"],
  ["positional"],
];
const invalidResults = invalidCases.map((args) => run(args));
ok("invalid arguments all fail closed with exit 2",
  invalidResults.every(({ status, signal }) => status === 2 && signal === null));
ok("invalid arguments emit no stdout",
  invalidResults.every(({ stdout }) => stdout === ""));
ok("invalid arguments emit only the bounded argument-error contract",
  invalidResults.every(({ stderr }) => /^f004 mutation runner argument error: [^\n]+\n$/.test(stderr)));

const source = fs.readFileSync(RUNNER, "utf8");
const listExit = source.indexOf("if (cli.list) {");
const destructiveSetup = source.indexOf("fs.rmSync(WT_BASE, { recursive: true, force: true });");
ok("--list exits before any worktree cleanup or creation",
  listExit >= 0 && destructiveSetup > listExit && source.indexOf("process.exit(0);", listExit) < destructiveSetup);
ok("parallel shards use process-distinct Git worktree leaf names",
  source.includes('worktreeSuffix = `-${cli.shardIndex}-of-${cli.shardTotal}-${process.pid}`;')
    && source.includes("`baseline${worktreeSuffix}`")
    && source.includes("`wt-${m.index}${worktreeSuffix}`"));
ok("argless summary text remains the established full-run contract",
  source.includes('? `(${MUTANTS.length} mutants)`')
    && source.includes("F-004 execution-path mutation proof: ${pass}/${pass + fail} passed ${summaryScope}"));

console.log(`\nF-004 mutation sharding: ${pass}/${pass + fail} passed`);
if (fail > 0) {
  console.error("f004 mutation sharding validation FAILED");
  process.exit(1);
}
console.log("f004 mutation sharding validation passed");
