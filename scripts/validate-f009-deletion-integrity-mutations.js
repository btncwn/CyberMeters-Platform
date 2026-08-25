#!/usr/bin/env node
//
// F-009 mutation proof. Each mutant REINTRODUCES one of the three banned
// behaviours from the containment contract; the integrity suite must FAIL on a
// NAMED assertion. A crash is NOT a kill (an invalid mutant proves nothing). An
// invalid-kill control must SURVIVE. Baseline is gated.
//
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const SUITE = path.join(root, "scripts", "validate-f009-deletion-integrity.js");
const SRC = path.join(root, "workers", "scan-api", "src", "index.js");
const sha = (p) => crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");

function runSuite() {
  try { execFileSync(process.execPath, [SUITE], { cwd: root, encoding: "utf8", stdio: ["ignore","pipe","pipe"] }); return { ok: true, out: "" }; }
  catch (e) { return { ok: false, out: `${e.stdout || ""}${e.stderr || ""}` }; }
}
const failed = (out) => out.split("\n").filter((l) => l.startsWith("FAIL ")).map((l) => l.trim());

const MUTANTS = [
  { name: "M1_EMAIL_BEFORE_PROOF_AND_SWALLOWED_DELETES",
    from: `  const recipient = user.email_verified && isValidEmail(String(user.email || "").toLowerCase())
    ? String(user.email).toLowerCase() : null;`,
    to: `  const recipient = null;
  if (user.email_verified && isValidEmail(String(user.email || "").toLowerCase())) {
    await sendCustomerEmail("Your CyberMeters account has been deleted", "removed", "<p>removed</p>", env, "HELLO_EMAIL_FROM", [String(user.email).toLowerCase()]).catch(() => {});
  }`,
    expect: "B-email-never-precedes-proof" },

  { name: "M2_R2_POINTER_DELETED_BEFORE_OBJECT_VERIFIED",
    from: `      await deleteR2ObjectVerified(env, r.report_key);
      await env.cybermeters_db
        .prepare("DELETE FROM workspace_reports WHERE id = ?").bind(r.id).run();`,
    to: `      if (r.report_key) await env.cybermeters_reports.delete(r.report_key).catch(() => {});
      await env.cybermeters_db
        .prepare("DELETE FROM workspace_reports WHERE id = ?").bind(r.id).run().catch(() => {});`,
    expect: "C-r2-verified-before-pointer" },

  // M3 re-anchored after R1: the release + parent delete now run as one batch,
  // so the old two-statement anchors no longer exist. Intent is unchanged —
  // prove the post-delete ABSENCE RE-READ is load-bearing: swallow the batch and
  // drop the verification, and a failed delete must be caught by the retry
  // assertion instead of completing over a surviving row.
  { name: "M3_PARENT_ABSENCE_UNVERIFIED",
    from: `  const wsStill = await env.cybermeters_db
    .prepare("SELECT id FROM workspaces WHERE id = ? LIMIT 1").bind(req.workspace_id).first();
  if (wsStill) throw new Error(\`workspace row survived deletion: \${req.workspace_id}\`);`,
    to: `  // mutant: absence not verified`,
    // anchored on the batch's own tail: a bare "  ]);" is not unique in index.js
    also: [[`      .prepare("DELETE FROM workspaces WHERE id = ?").bind(req.workspace_id),
  ]);`,
            `      .prepare("DELETE FROM workspaces WHERE id = ?").bind(req.workspace_id),
  ]).catch(() => {});`]],
    expect: "R1-01-atomic-release" },
];

// R1 correctives — each mutant reverts one corrective and must die by name.
MUTANTS.push(
  { name: "M4_GATE_REMOVED_FK_CHECK_NOT_WIRED",
    from: `  // R1-03 — the governed FK proof runs HERE, in production, before any claim.
  await assertForeignKeyCheckClean(env);`,
    to: `  // mutant: production FK gate deleted`,
    expect: "R1-03-production-gate-wired" },

  { name: "M5_GATE_REMOVED_ZERO_COUNT_NOT_WIRED",
    from: `  await assertWorkspacePurgeProven(env, req.workspace_id);`,
    to: `  // mutant: production zero-count gate deleted`,
    expect: "R1-03-production-gate-wired" },

  { name: "M6_RELEASE_AND_DELETE_NOT_ATOMIC",
    from: `  await env.cybermeters_db.batch([
    env.cybermeters_db
      .prepare("UPDATE deletion_requests SET workspace_id = NULL WHERE id = ? AND workspace_id = ?")
      .bind(req.id, req.workspace_id),
    env.cybermeters_db
      .prepare("DELETE FROM workspaces WHERE id = ?").bind(req.workspace_id),
  ]);`,
    to: `  await env.cybermeters_db
    .prepare("UPDATE deletion_requests SET workspace_id = NULL WHERE id = ? AND workspace_id = ?")
    .bind(req.id, req.workspace_id).run();
  await env.cybermeters_db
    .prepare("DELETE FROM workspaces WHERE id = ?").bind(req.workspace_id).run();`,
    expect: "R1-01-atomic-release" },

  { name: "M7_ERROR_READS_AS_ABSENCE_AGAIN",
    from: `    .prepare("SELECT id, name, deleted_at, owner_user_id FROM workspaces WHERE id = ? LIMIT 1")
    .bind(req.workspace_id).first();`,
    to: `    .prepare("SELECT id, name, deleted_at, owner_user_id FROM workspaces WHERE id = ? LIMIT 1")
    .bind(req.workspace_id).first().catch(() => null);`,
    expect: "R1-02-error-is-not-absence" },

  { name: "M8_R2_ABSENCE_OPTIONAL_AGAIN",
    from: `  if (typeof env.cybermeters_reports.head !== "function") {
    throw new Error(\`R2 absence unverifiable (no head binding): \${key}\`);
  }
  const still = await env.cybermeters_reports.head(key);
  if (still) throw new Error(\`R2 object still present after delete: \${key}\`);`,
    to: `  if (typeof env.cybermeters_reports.head === "function") {
    const still = await env.cybermeters_reports.head(key);
    if (still) throw new Error(\`R2 object still present after delete: \${key}\`);
  }`,
    expect: "R1-04-r2-absence-positively-verified" },
);

const CONTROL = {
  name: "CONTROL_COSMETIC_COMMENT",
  from: `// F-009 — atomic claim. Returns true only when THIS runner won the row.`,
  to:   `// F-009 (cosmetic control edit) atomic claim helper.`,
};

console.log("=== BASELINE ===");
const base = runSuite();
console.log(base.ok ? "  PASS — baseline green" : `  FAIL — baseline RED, aborting\n${base.out.slice(-900)}`);
if (!base.ok) process.exit(1);

let allOk = true;
console.log("\n=== MUTANTS ===");
for (const m of MUTANTS) {
  const before = sha(SRC);
  const orig = fs.readFileSync(SRC, "utf8");
  if (orig.split(m.from).length - 1 !== 1) { console.log(`  ANCHOR-FAIL ${m.name} (${orig.split(m.from).length - 1})`); allOk = false; continue; }
  let mutated = orig.replace(m.from, m.to);
  let anchorOk = true;
  for (const [a, b] of (m.also || [])) {
    if (mutated.split(a).length - 1 !== 1) { anchorOk = false; break; }
    mutated = mutated.replace(a, b);
  }
  if (!anchorOk) { console.log(`  ANCHOR-FAIL ${m.name} (also)`); allOk = false; continue; }
  fs.writeFileSync(SRC, mutated);
  const r = runSuite();
  fs.writeFileSync(SRC, orig);
  const restored = sha(SRC) === before;
  // A crash is not a kill: the suite must reach its terminal summary line.
  const reachedEnd = /deletion integrity: \d+ passed/.test(r.out);
  const named = failed(r.out).filter((l) => l.includes(`[${m.expect}]`));
  const killed = !r.ok && reachedEnd && named.length > 0;
  console.log(`  ${killed ? "KILLED " : "SURVIVED"} ${m.name}`);
  console.log(`      expected: [${m.expect}]  named failures: ${named.length}  suite completed: ${reachedEnd}`);
  if (named[0]) console.log(`      e.g. ${named[0]}`);
  console.log(`      bytes restored: ${restored ? "verified" : "MISMATCH"}`);
  allOk &&= killed && restored;
}

console.log("\n=== INVALID-KILL CONTROL ===");
{
  const before = sha(SRC);
  const orig = fs.readFileSync(SRC, "utf8");
  if (orig.split(CONTROL.from).length - 1 !== 1) { console.log("  ANCHOR-FAIL control"); allOk = false; }
  else {
    fs.writeFileSync(SRC, orig.replace(CONTROL.from, CONTROL.to));
    const r = runSuite();
    fs.writeFileSync(SRC, orig);
    const ok = r.ok && sha(SRC) === before;
    console.log(`  ${ok ? "SURVIVED (correct)" : "KILLED (suite is brittle)"} ${CONTROL.name}`);
    allOk &&= ok;
  }
}
console.log(`\nRESULT: ${allOk ? `${MUTANTS.length}/${MUTANTS.length} MUTANTS KILLED BY NAME, CONTROL SURVIVED` : "FAILED"}`);
process.exit(allOk ? 0 : 1);
