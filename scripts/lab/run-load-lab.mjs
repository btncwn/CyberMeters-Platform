#!/usr/bin/env node
// Run the load lab once and write what it measured.
//
//   node scripts/lab/run-load-lab.mjs [--root <checkout>] [--days 2] [--seed 1]
//        [--stuck] [--no-burst] [--median-s 25] [--out result.json]
//
// --root measures another checkout of the repository (the lab itself always
// comes from this one), so two versions can be run on the same population and
// compared. --stuck adds schedules that can no longer run (verification removed,
// trial ended). Scan durations are modelled; everything else is the product's
// own code. See scripts/lab/load-lab.mjs.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runLoadLab, summarizeLoad } from "./load-lab.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const value = (name, fallback) => { const i = args.indexOf(name); return i >= 0 && args[i + 1] ? args[i + 1] : fallback; };

const root = path.resolve(value("--root", path.join(here, "..", "..")));
const days = Number(value("--days", 2));
const seed = Number(value("--seed", 1));
const out = value("--out", null);
const stuck = flag("--stuck");
const started = Date.now();

const result = await runLoadLab({
  root,
  days,
  seed,
  population: stuck ? { stuckRevoked: 15, stuckExpiredTrial: 5 } : {},
  demand: flag("--no-burst") ? { mspBurstAt: null } : {},
  duration: { medianMs: Number(value("--median-s", 25)) * 1000 },
  progress: (p) => process.stderr.write(`\r${p.at} jobs=${p.jobs} waiting=${p.queued}   `),
});
const summary = summarizeLoad(result);
process.stderr.write("\n");
const report = { root, measured_at: new Date().toISOString(), wall_s: Math.round((Date.now() - started) / 1000), options: { days, seed, stuck, burst: !flag("--no-burst") }, summary };
if (out) fs.writeFileSync(out, JSON.stringify({ ...report, result }, null, 1));
console.log(JSON.stringify(report, null, 2));
