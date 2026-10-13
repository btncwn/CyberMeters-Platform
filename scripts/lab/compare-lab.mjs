#!/usr/bin/env node
// Compare two lab measurements taken with run-discovery-lab.mjs --json:
//   node scripts/lab/compare-lab.mjs before.json after.json
import fs from "node:fs";

const [beforePath, afterPath] = process.argv.slice(2);
if (!beforePath || !afterPath) {
  console.error("usage: compare-lab.mjs before.json after.json");
  process.exit(2);
}
const read = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const before = read(beforePath), after = read(afterPath);

const sum = (scans, pick) => scans.reduce((total, scan) => total + (pick(scan) || 0), 0);
function metrics(result) {
  const inv = result.inventory;
  const families = Object.values(inv.families || {});
  return {
    "names found / expected": `${inv.true_positive}/${inv.expected}`,
    "recall": inv.recall,
    "false positives": inv.false_positive.length,
    "out of scope admitted": inv.out_of_scope_admitted.length,
    "address families kept": `${families.filter((f) => f.A.ok && f.AAAA.ok).length}/${families.length}`,
    "scan quality": result.scans.map((s) => s.quality).join(" → "),
    "score": result.scans.map((s) => s.score ?? "withheld").join(" → "),
    "requests": sum(result.scans, (s) => s.requests.total),
    "DNS questions": sum(result.scans, (s) => s.requests.dns_questions),
    "requests to the target": sum(result.scans, (s) => s.requests.by_kind.target),
    "outside data requests": sum(result.scans, (s) => s.requests.by_kind.outside_data),
    "D1 reads / writes": `${sum(result.scans, (s) => s.storage.d1_reads)}/${sum(result.scans, (s) => s.storage.d1_writes)}`,
    "R2 reads / writes": `${sum(result.scans, (s) => s.storage.r2_reads)}/${sum(result.scans, (s) => s.storage.r2_writes)}`,
    "engine time (ms)": sum(result.scans, (s) => s.elapsed_ms),
  };
}

for (const result of after.results) {
  const old = before.results.find((r) => r.world === result.world);
  console.log(`\n== ${result.world} (${result.domain}) · egress ${after.egress}`);
  const a = old ? metrics(old) : {}, b = metrics(result);
  const width = Math.max(...Object.keys(b).map((k) => k.length));
  for (const key of Object.keys(b)) {
    const was = old ? String(a[key]) : "—";
    const now = String(b[key]);
    console.log(`  ${key.padEnd(width)}  ${was.padStart(14)}  →  ${now}${was !== now ? "" : ""}`);
  }
  if (old) {
    const fixed = old.inventory.missed.filter((h) => !result.inventory.missed.includes(h));
    const lost = result.inventory.missed.filter((h) => !old.inventory.missed.includes(h));
    const fpGone = old.inventory.false_positive.filter((h) => !result.inventory.false_positive.includes(h));
    const fpNew = result.inventory.false_positive.filter((h) => !old.inventory.false_positive.includes(h));
    if (fixed.length) console.log(`  now found: ${fixed.join(", ")}`);
    if (lost.length) console.log(`  no longer found: ${lost.join(", ")}`);
    if (fpGone.length) console.log(`  false positives removed: ${fpGone.join(", ")}`);
    if (fpNew.length) console.log(`  new false positives: ${fpNew.join(", ")}`);
  }
}
