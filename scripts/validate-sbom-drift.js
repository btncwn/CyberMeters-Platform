#!/usr/bin/env node
//
// Committed SBOM snapshots (sbom/*.cdx.json) must list exactly the components CI
// regenerates from the lockfiles. A stale snapshot turns every advisory match --
// or its absence -- into a statement about dependencies we no longer ship.
// Runs after the "Generate SBOMs" step, which rewrites the working-tree files;
// the committed version is read from HEAD. Exits non-zero on drift.
//
import { execFileSync } from "node:child_process";
import fs from "node:fs";

const purls = (doc) => new Set((doc.components || []).map((c) => c.purl || `${c.name}@${c.version}`));
let drift = 0;
for (const file of ["sbom/scan-api.cdx.json", "sbom/frontend.cdx.json"]) {
  const committed = purls(JSON.parse(execFileSync("git", ["show", `HEAD:${file}`], { encoding: "utf8" })));
  const generated = purls(JSON.parse(fs.readFileSync(file, "utf8")));
  const missing = [...generated].filter((p) => !committed.has(p));
  const extra = [...committed].filter((p) => !generated.has(p));
  if (missing.length || extra.length) {
    drift += 1;
    console.error(`${file}: committed snapshot differs from the regenerated SBOM (${missing.length} shipped but not listed, ${extra.length} listed but not shipped)`);
    for (const p of missing.slice(0, 15)) console.error(`  + ${p}`);
    for (const p of extra.slice(0, 15)) console.error(`  - ${p}`);
  } else {
    console.log(`${file}: snapshot matches the lockfile tree (${generated.size} components)`);
  }
}
if (drift) {
  console.error("Refresh the committed snapshots (sbom/README.md, Regenerating) and commit them with the dependency change.");
  process.exit(1);
}
