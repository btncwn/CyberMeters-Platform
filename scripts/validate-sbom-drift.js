#!/usr/bin/env node
//
// Committed SBOM snapshots (sbom/*.cdx.json) must list exactly the portable
// components CI regenerates from the lockfiles. A stale snapshot turns every
// advisory match -- or its absence -- into a statement about dependencies we no
// longer ship. Runs after the "Generate SBOMs" step, which rewrites the
// working-tree files; the committed version is read from HEAD.
//
// cyclonedx-npm lists what is installed, so packages the lockfile restricts to a
// platform (os/cpu) or marks optional differ between a macOS laptop and the Linux
// runner; those are left out of the comparison on both sides.
//
import { execFileSync } from "node:child_process";
import fs from "node:fs";

const WORKSPACES = { "sbom/scan-api.cdx.json": "workers/scan-api", "sbom/frontend.cdx.json": "frontend" };

function platformRestricted(workspace) {
  const lock = JSON.parse(fs.readFileSync(`${workspace}/package-lock.json`, "utf8"));
  const names = new Set();
  for (const [key, entry] of Object.entries(lock.packages || {})) {
    if (key && (entry.os || entry.cpu || entry.optional)) names.add(key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length));
  }
  return names;
}

function portable(doc, restricted) {
  const out = new Set();
  for (const c of doc.components || []) {
    const name = c.group ? `${c.group}/${c.name}` : c.name;
    if (restricted.has(name)) continue;
    out.add(c.purl || `${name}@${c.version}`);
  }
  return out;
}

let drift = 0;
for (const [file, workspace] of Object.entries(WORKSPACES)) {
  const restricted = platformRestricted(workspace);
  const committed = portable(JSON.parse(execFileSync("git", ["show", `HEAD:${file}`], { encoding: "utf8" })), restricted);
  const generated = portable(JSON.parse(fs.readFileSync(file, "utf8")), restricted);
  const missing = [...generated].filter((p) => !committed.has(p));
  const extra = [...committed].filter((p) => !generated.has(p));
  if (missing.length || extra.length) {
    drift += 1;
    console.error(`${file}: committed snapshot differs from the regenerated SBOM (${missing.length} shipped but not listed, ${extra.length} listed but not shipped)`);
    for (const p of missing.slice(0, 15)) console.error(`  + ${p}`);
    for (const p of extra.slice(0, 15)) console.error(`  - ${p}`);
  } else {
    console.log(`${file}: snapshot matches the lockfile tree (${generated.size} portable components; ${restricted.size} platform/optional packages not compared)`);
  }
}
if (drift) {
  console.error("Refresh the committed snapshots (sbom/README.md, Regenerating) and commit them with the dependency change.");
  process.exit(1);
}
