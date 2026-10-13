#!/usr/bin/env node
// Measure discovery against the lab worlds.
//
//   node scripts/lab/run-discovery-lab.mjs [--root DIR] [--world alpha,bravo,charlie]
//        [--egress open|blocked] [--scans N] [--json]
//
// --root points at any checkout of the repository (default: this one), so an
// older version can be measured with the same worlds:
//   git worktree add /tmp/cm-baseline <commit>
//   node scripts/lab/run-discovery-lab.mjs --root /tmp/cm-baseline --json > before.json
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runLabWorld } from "./lab-scan.mjs";
import { WORLDS } from "./worlds.mjs";

const args = process.argv.slice(2);
const option = (name, fallback) => {
  const index = args.indexOf(`--${name}`);
  return index >= 0 && args[index + 1] && !args[index + 1].startsWith("--") ? args[index + 1] : fallback;
};
const root = path.resolve(option("root", path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..")));
const worlds = option("world", "alpha,bravo,charlie").split(",").map((name) => name.trim()).filter(Boolean);
const egress = option("egress", "open");
const scans = Number(option("scans", "2"));
const asJson = args.includes("--json");

const results = [];
for (const name of worlds) {
  const world = WORLDS[name];
  if (!world) throw new Error(`unknown world ${name}`);
  const run = await runLabWorld({ root, world, egress, scans });
  const { db, r2, log, engine_log: _engineLog, ...measurement } = run;
  results.push(measurement);
}

if (asJson) {
  console.log(JSON.stringify({ root, egress, results }, null, 2));
} else {
  for (const result of results) {
    const inv = result.inventory;
    console.log(`\n== ${result.world} (${result.domain}) · egress ${result.egress}`);
    console.log(`   found ${inv.true_positive}/${inv.expected} expected names (recall ${inv.recall}); stored assets ${inv.stored_assets}`);
    console.log(`   missed: ${inv.missed.join(", ") || "none"}`);
    console.log(`   false positives: ${inv.false_positive.join(", ") || "none"}`);
    console.log(`   out of scope admitted: ${inv.out_of_scope_admitted.join(", ") || "none"}`);
    for (const [host, family] of Object.entries(inv.families)) {
      console.log(`   ${host}: A ${family.A.ok ? "ok" : `stored ${JSON.stringify(family.A.stored)} expected ${JSON.stringify(family.A.expected)}`} · AAAA ${family.AAAA.ok ? "ok" : `stored ${JSON.stringify(family.AAAA.stored)} expected ${JSON.stringify(family.AAAA.expected)}`}`);
    }
    for (const scan of result.scans) {
      const req = scan.requests;
      console.log(`   scan ${scan.scan_id}: ${scan.status}/${scan.quality} in ${scan.elapsed_ms} ms · requests ${req.total} (dns ${req.dns_questions}, target ${req.by_kind.target || 0}, outside data ${req.by_kind.outside_data || 0}) · D1 r/w ${scan.storage.d1_reads}/${scan.storage.d1_writes} · findings ${scan.findings}${scan.error ? ` · error ${scan.error}` : ""}`);
      if (scan.incomplete_modules.length) console.log(`     incomplete: ${scan.incomplete_modules.join(", ")}`);
      if (Object.keys(req.outside_data).length) console.log(`     outside data: ${JSON.stringify(req.outside_data)}`);
    }
    if (result.unexpected_hosts.length) console.log(`   unexpected hosts: ${result.unexpected_hosts.join(", ")}`);
  }
}
process.exit(0);
