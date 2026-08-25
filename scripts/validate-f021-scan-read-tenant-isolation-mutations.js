#!/usr/bin/env node
//
// F-021 mutation proof. Each mutant REINTRODUCES one member of the scan-read
// isolation defect class; the isolation suite must FAIL on a NAMED assertion.
// An invalid-kill control (cosmetic edit) must SURVIVE, so the suite cannot pass by being
// merely brittle. Baseline is gated: mutants measured against a red baseline
// prove nothing. Target bytes are restored and hash-verified after every run.
//
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const SUITE = path.join(root, "scripts", "validate-f021-scan-read-tenant-isolation.js");
const GUARD = path.join(root, "workers", "scan-api", "src", "index.js");
const ROUTES = path.join(root, "workers", "scan-api", "src", "routes", "scans.js");
const ATTACK_SURFACE = path.join(root, "workers", "scan-api", "src", "routes", "attack-surface.js");
const sha = (p) => crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");

function runSuite() {
  try { execFileSync(process.execPath, [SUITE], { cwd: root, encoding: "utf8", stdio: ["ignore","pipe","pipe"] }); return { ok: true, out: "" }; }
  catch (e) { return { ok: false, out: `${e.stdout || ""}${e.stderr || ""}` }; }
}
const failedNames = (out) => out.split("\n").filter(l => l.startsWith("FAIL ")).map(l => l.trim());

const MUTANTS = [
  { name: "M1_RESTORE_NULL_DOMAIN_JOIN_FALLBACK", file: GUARD,
    from: `    if (!scan.workspace_id) return null;`,
    to:   `    if (!scan.workspace_id) {
      const rows = await env.cybermeters_db
        .prepare("SELECT DISTINCT wd.workspace_id FROM scans s JOIN workspace_domains wd ON wd.domain_id = s.domain_id WHERE s.id = ?")
        .bind(scanId).all();
      for (const row of (rows.results || [])) {
        const a = await requireWorkspaceRole(user, row.workspace_id, "workspace:read", env);
        if (a) return { ...a, workspace_id: row.workspace_id };
      }
      return null;
    }`,
    expect: ["direct-detail", "direct-report", "direct-pdf", "direct-exec-v2", "direct-snapshot"] },
  { name: "M2A_RESTORE_UNFILTERED_LIST_NULL_FALLBACK", file: ROUTES,
    from: `             WHERE s.workspace_id IN (\${placeholders})`,
    to:   `             WHERE (s.workspace_id IN (\${placeholders}) OR (s.workspace_id IS NULL AND wd.workspace_id IN (\${placeholders})))`,
    also: [[`          .bind(...workspaceIds)`, `          .bind(...workspaceIds, ...workspaceIds)`]],
    expect: "list" },
  { name: "M2B_RESTORE_FILTERED_LIST_NULL_FALLBACK", file: ROUTES,
    from: `             WHERE s.workspace_id = ?
             ORDER BY s.created_at DESC
             LIMIT 20`,
    to:   `             WHERE (s.workspace_id = ? OR (s.workspace_id IS NULL AND wd.workspace_id = ?))
             ORDER BY s.created_at DESC
             LIMIT 20`,
    also: [[`          .bind(wsFilter)`, `          .bind(wsFilter, wsFilter)`]],
    expect: "list" },
  // The fix removed the workspace_domains JOIN outright, so a mutant that only
  // swaps the WHERE column is INVALID SQL — it crashes instead of reproducing
  // the defect. A crash is not a kill. This mutant restores the ORIGINAL clause
  // in full: the JOIN and the wd filter together.
  { name: "M3_RESTORE_HISTORY_DOMAIN_JOIN", file: ROUTES,
    // Anchored on the adjacent F-021 comment: bare "FROM scans s" also occurs
    // inside the list queries at deeper indentation, so it is not unique.
    from: `           FROM scans s
           -- F-021 — the domain link alone NEVER authorises.`,
    to:   `           FROM scans s
           JOIN workspace_domains wd ON wd.domain_id = s.domain_id
           -- F-021 — the domain link alone NEVER authorises.`,
    also: [[`           WHERE s.domain = ? AND s.workspace_id IN (\${placeholders})`,
            `           WHERE s.domain = ? AND wd.workspace_id IN (\${placeholders})`]],
    expect: "history" },
  { name: "M4_RESTORE_AGGREGATE_NULL_FALLBACK", file: ATTACK_SURFACE,
    from: `           AND s.workspace_id = ?`,
    to:   `           AND (s.workspace_id = ? OR s.workspace_id IS NULL)`,
    expect: ["aggregate-certificates", "aggregate-saas", "aggregate-cloud", "aggregate-cloud-summary", "aggregate-admin"] },
  { name: "M5_RESTORE_AGGREGATE_DOMAIN_ONLY_SCOPE", file: ATTACK_SURFACE,
    from: `           AND s.workspace_id = ?`,
    to:   `           AND wd.workspace_id = ?`,
    expect: ["aggregate-certificates", "aggregate-saas", "aggregate-cloud", "aggregate-cloud-summary", "aggregate-admin"] },
];
const CONTROL = { name: "CONTROL_COSMETIC_COMMENT", file: GUARD,
  from: `    // F-021 — a scan is readable ONLY through its own DIRECT workspace`,
  to:   `    // F-021 (cosmetic control edit) scan readable only via direct workspace` };

console.log("=== BASELINE ===");
const base = runSuite();
console.log(base.ok ? "  PASS — baseline green" : `  FAIL — baseline RED, aborting\n${base.out.slice(-800)}`);
if (!base.ok) process.exit(1);

let allKilled = true;
console.log("\n=== MUTANTS ===");
for (const m of MUTANTS) {
  const before = sha(m.file);
  const orig = fs.readFileSync(m.file, "utf8");
  let mutated = orig;
  if (mutated.split(m.from).length - 1 !== 1) { console.log(`  ANCHOR-FAIL ${m.name}`); allKilled = false; continue; }
  mutated = mutated.replace(m.from, m.to);
  let auxiliaryAnchorsValid = true;
  for (const [a, b] of (m.also || [])) {
    if (mutated.split(a).length - 1 !== 1) {
      console.log(`  ANCHOR-FAIL ${m.name} auxiliary replacement`);
      auxiliaryAnchorsValid = false;
      break;
    }
    mutated = mutated.replace(a, b);
  }
  if (!auxiliaryAnchorsValid) { allKilled = false; continue; }
  fs.writeFileSync(m.file, mutated);
  const r = runSuite();
  fs.writeFileSync(m.file, orig);
  const after = sha(m.file);
  // A mutant that CRASHES the suite proves nothing — it may be invalid rather
  // than defective. A kill requires a NAMED assertion failure in the expected
  // section, and the suite must have reached its terminal summary line.
  const reachedEnd = /scan-read tenant isolation: \d+ passed/.test(r.out);
  const expectedSections = Array.isArray(m.expect) ? m.expect : [m.expect];
  const allFailures = failedNames(r.out);
  const named = allFailures.filter((line) =>
    expectedSections.some((expected) => line.includes(`[${expected}]`))
  );
  const coveredSections = expectedSections.filter((expected) =>
    allFailures.some((line) => line.includes(`[${expected}]`))
  );
  const killed = !r.ok && reachedEnd && coveredSections.length === expectedSections.length;
  console.log(`  ${killed ? "KILLED " : "SURVIVED"} ${m.name}`);
  console.log(`      expected sections: ${expectedSections.map((s) => `[${s}]`).join(", ")}`);
  console.log(`      covered sections: ${coveredSections.length}/${expectedSections.length}   named failures: ${named.length}   suite completed: ${reachedEnd}`);
  if (named[0]) console.log(`      e.g. ${named[0]}`);
  console.log(`      bytes restored: ${before === after ? "verified" : "MISMATCH"}`);
  allKilled &&= killed && before === after;
}

console.log("\n=== INVALID-KILL CONTROL ===");
{
  const before = sha(CONTROL.file);
  const orig = fs.readFileSync(CONTROL.file, "utf8");
  if (orig.split(CONTROL.from).length - 1 !== 1) { console.log("  ANCHOR-FAIL control"); allKilled = false; }
  else {
    fs.writeFileSync(CONTROL.file, orig.replace(CONTROL.from, CONTROL.to));
    const r = runSuite();
    fs.writeFileSync(CONTROL.file, orig);
    const ok = r.ok && sha(CONTROL.file) === before;
    console.log(`  ${ok ? "SURVIVED (correct)" : "KILLED (suite is brittle)"} ${CONTROL.name}`);
    allKilled &&= ok;
  }
}
console.log(`\nRESULT: ${allKilled ? "6/6 MUTANTS KILLED BY NAME, CONTROL SURVIVED" : "FAILED"}`);
process.exit(allKilled ? 0 : 1);
