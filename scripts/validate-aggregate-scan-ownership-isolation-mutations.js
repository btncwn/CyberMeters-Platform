#!/usr/bin/env node
//
// Aggregate scan-ownership mutation proof. CI-blocking. Node 24+.
//
// Each mutant RESTORES the exact pre-fix SQL of one affected query group (the
// domain-link attribution, or the domain-only "latest per domain" ranking). The
// isolation suite must FAIL on a NAMED assertion in that route's section. An
// invalid-kill control (cosmetic comment edit) must SURVIVE, so the suite cannot
// pass by being merely brittle. Baseline is gated: mutants measured against a red
// baseline prove nothing. Target bytes are restored and hash-verified after
// every run, including when the suite crashes.
//
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const SUITE = path.join(root, "scripts", "validate-aggregate-scan-ownership-isolation.js");
const src = (...p) => path.join(root, "workers", "scan-api", "src", ...p);
const EXEC = src("routes", "executive-dashboard.js");
const PORTFOLIO = src("routes", "portfolio.js");
const CUSTOMERS = src("engines", "portfolio-customers.js");
const DOMAINS = src("engines", "portfolio-domains.js");
const ATTACK = src("routes", "attack-surface.js");
const IDENTITY = src("engines", "identity-exposure.js");
const SENDER = src("engines", "sender-provenance.js");
const RELATED = src("engines", "related-changes.js");
const SCORECARD = src("engines", "scorecard.js");
const sha = (p) => crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");

function runSuite() {
  try { execFileSync(process.execPath, [SUITE], { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }); return { ok: true, out: "" }; }
  catch (e) { return { ok: false, out: `${e.stdout || ""}${e.stderr || ""}` }; }
}
const failedNames = (out) => out.split("\n").filter((l) => l.startsWith("FAIL ")).map((l) => l.trim());

const OWN_JOIN = "JOIN workspace_domains wd ON wd.workspace_id = s.workspace_id AND wd.domain_id = s.domain_id";

// edits: [from, to, expectedOccurrences = 1]; all occurrences are replaced.
const MUTANTS = [
  { name: "M1_EXEC_REMEDIATION_DOMAIN_LINK", file: EXEC, expect: ["executive-dashboard"], edits: [[
    `${OWN_JOIN}
               WHERE s.workspace_id = ?
                 AND s.status = 'completed'
                 AND s.created_at >= datetime('now', '-30 days')`,
    `JOIN workspace_domains wd ON s.domain_id = wd.domain_id
               WHERE wd.workspace_id = ?
                 AND s.status = 'completed'
                 AND s.created_at >= datetime('now', '-30 days')`]] },
  { name: "M2_EXEC_LATEST_SCAN_DOMAIN_LINK", file: EXEC, expect: ["executive-dashboard"], edits: [[
    `${OWN_JOIN}
               WHERE s.workspace_id = ? AND s.status = 'completed' AND s.score IS NOT NULL`,
    `JOIN workspace_domains wd ON s.domain_id = wd.domain_id
               WHERE wd.workspace_id = ? AND s.status = 'completed' AND s.score IS NOT NULL`]] },
  { name: "M3_LATEST_SCAN_CTE_GLOBAL_DOMAIN_RANK", file: CUSTOMERS, expect: ["portfolio-overview", "portfolio-workspaces"], edits: [[
    `    SELECT scan_id, workspace_id, domain_id FROM (
      SELECT id AS scan_id, workspace_id, domain_id,
             ROW_NUMBER() OVER (PARTITION BY workspace_id, domain_id ORDER BY created_at DESC, id DESC) AS rn
      FROM scans WHERE status='completed' AND workspace_id IS NOT NULL`,
    `    SELECT scan_id, domain_id FROM (
      SELECT id AS scan_id, domain_id,
             ROW_NUMBER() OVER (PARTITION BY domain_id ORDER BY created_at DESC, id DESC) AS rn
      FROM scans WHERE status='completed'`]] },
  { name: "M4_CUSTOMER_FINDINGS_DOMAIN_LINK", file: CUSTOMERS, expect: ["portfolio-workspaces", "portfolio-executive-summary"], edits: [
    [`       SELECT s.workspace_id, f.severity, COUNT(*) AS cnt`, `       SELECT wd.workspace_id, f.severity, COUNT(*) AS cnt`],
    [`       ${OWN_JOIN}
       WHERE f.severity IN ('critical','high')
         AND \${visibleFindingSql("f", "s")}
         AND s.workspace_id IN (\${wsIn})
       GROUP BY s.workspace_id, f.severity`,
     `       JOIN workspace_domains wd ON s.domain_id = wd.domain_id
       WHERE f.severity IN ('critical','high')
         AND \${visibleFindingSql("f", "s")}
         AND wd.workspace_id IN (\${wsIn})
       GROUP BY wd.workspace_id, f.severity`]] },
  { name: "M5_CUSTOMER_SCORES_GLOBAL_DOMAIN_RANK", file: CUSTOMERS, expect: ["portfolio-workspaces", "portfolio-executive-summary"], edits: [
    [`                  ROW_NUMBER() OVER (PARTITION BY workspace_id, domain_id ORDER BY created_at DESC, id DESC) AS rn
           FROM scans WHERE status='completed' AND scan_quality='complete'
             AND workspace_id IS NOT NULL`,
     `                  ROW_NUMBER() OVER (PARTITION BY domain_id ORDER BY created_at DESC, id DESC) AS rn
           FROM scans WHERE status='completed' AND scan_quality='complete'`],
    [`       SELECT s.workspace_id, s.id AS scan_id, s.score, s.rating,`, `       SELECT wd.workspace_id, s.id AS scan_id, s.score, s.rating,`],
    [`       ${OWN_JOIN}
       WHERE s.score IS NOT NULL AND s.workspace_id IN (\${wsIn})
       ORDER BY s.workspace_id, s.created_at DESC`,
     `       JOIN workspace_domains wd ON s.domain_id = wd.domain_id
       WHERE s.score IS NOT NULL AND wd.workspace_id IN (\${wsIn})
       ORDER BY wd.workspace_id, s.created_at DESC`]] },
  { name: "M6_OVERVIEW_AVERAGE_DOMAIN_LINK", file: PORTFOLIO, expect: ["portfolio-overview"], edits: [[
    `            ${OWN_JOIN}
            WHERE s.score IS NOT NULL
              AND s.scan_quality = 'complete'
              AND s.workspace_id IN (\${wsIn})`,
    `            JOIN workspace_domains wd ON wd.domain_id = s.domain_id
            WHERE s.score IS NOT NULL
              AND s.scan_quality = 'complete'
              AND wd.workspace_id IN (\${wsIn})`]] },
  { name: "M7_OVERVIEW_FINDINGS_DOMAIN_LINK", file: PORTFOLIO, expect: ["portfolio-overview"], edits: [[
    `            ${OWN_JOIN}
            WHERE f.severity IN ('critical','high')
              AND \${visibleFindingSql("f", "s")}
              AND s.workspace_id IN (\${wsIn})`,
    `            JOIN workspace_domains wd ON wd.domain_id = s.domain_id
            WHERE f.severity IN ('critical','high')
              AND \${visibleFindingSql("f", "s")}
              AND wd.workspace_id IN (\${wsIn})`]] },
  { name: "M8_OVERVIEW_HIGHEST_RISK_DOMAIN_LINK", file: PORTFOLIO, expect: ["portfolio-overview"], edits: [
    [`              SELECT s.workspace_id, s.domain_id, COUNT(*) AS cnt`, `              SELECT s.domain_id, COUNT(*) AS cnt`],
    [`              GROUP BY s.workspace_id, s.domain_id`, `              GROUP BY s.domain_id`],
    [`              SELECT c.workspace_id, SUM(c.cnt) AS total_crit
              FROM crit c
              JOIN workspace_domains wd ON wd.workspace_id = c.workspace_id AND wd.domain_id = c.domain_id
              WHERE c.workspace_id IN (\${wsIn})
              GROUP BY c.workspace_id`,
     `              SELECT wd.workspace_id, SUM(c.cnt) AS total_crit
              FROM crit c
              JOIN workspace_domains wd ON c.domain_id = wd.domain_id
              WHERE wd.workspace_id IN (\${wsIn})
              GROUP BY wd.workspace_id`]] },
  { name: "M9_TRENDS_SCORES_DOMAIN_LINK", file: PORTFOLIO, expect: ["portfolio-trends"], edits: [[
    `            ${OWN_JOIN}
            WHERE s.status = 'completed'
              AND s.scan_quality = 'complete'
              AND s.created_at >= datetime('now', '-30 days')
              AND s.score IS NOT NULL
              AND s.workspace_id IN (\${wsIn})`,
    `            JOIN workspace_domains wd ON wd.domain_id = s.domain_id
            WHERE s.status = 'completed'
              AND s.scan_quality = 'complete'
              AND s.created_at >= datetime('now', '-30 days')
              AND s.score IS NOT NULL
              AND wd.workspace_id IN (\${wsIn})`]] },
  { name: "M10_TRENDS_FINDINGS_DOMAIN_LINK", file: PORTFOLIO, expect: ["portfolio-trends"], edits: [[
    `            ${OWN_JOIN}
            WHERE s.status = 'completed'
              AND s.scan_quality = 'complete'
              AND s.created_at >= datetime('now', '-30 days')
              AND f.severity IN ('critical', 'high')
              AND \${visibleFindingSql("f", "s")}
              AND s.workspace_id IN (\${wsIn})`,
    `            JOIN workspace_domains wd ON wd.domain_id = s.domain_id
            WHERE s.status = 'completed'
              AND s.scan_quality = 'complete'
              AND s.created_at >= datetime('now', '-30 days')
              AND f.severity IN ('critical', 'high')
              AND \${visibleFindingSql("f", "s")}
              AND wd.workspace_id IN (\${wsIn})`]] },
  { name: "M11_PORTFOLIO_DOMAINS_DOMAIN_LINK", file: DOMAINS, expect: ["portfolio-domains", "portfolio-domain-detail"], edits: [
    [`         SELECT s.workspace_id, s.domain_id, s.id AS scan_id, s.score, s.rating,`, `         SELECT wd.workspace_id, s.domain_id, s.id AS scan_id, s.score, s.rating,`],
    [`                  PARTITION BY s.workspace_id, s.domain_id`, `                  PARTITION BY wd.workspace_id, s.domain_id`],
    [`         ${OWN_JOIN}
         WHERE s.workspace_id IN (\${wsIn})`,
     `         JOIN workspace_domains wd ON wd.domain_id = s.domain_id
         WHERE wd.workspace_id IN (\${wsIn})`]] },
  { name: "M12_POSTURE_DOMAIN_LINK", file: ATTACK, expect: ["posture", "posture-timeline"], edits: [[
    `                 ${OWN_JOIN}
                 WHERE s.workspace_id = ?`,
    `                 JOIN workspace_domains wd ON s.domain_id = wd.domain_id
                 WHERE wd.workspace_id = ?`, 5]] },
  { name: "M13_IDENTITY_GLOBAL_LATEST_DOMAIN_LINK", file: IDENTITY, expect: ["identity-exposure"], edits: [[
    `    .prepare(\`WITH lpd AS (
                SELECT scan_id FROM (
                  SELECT id AS scan_id,
                         ROW_NUMBER() OVER (PARTITION BY domain_id ORDER BY created_at DESC, id DESC) AS rn
                  FROM scans WHERE status='completed' AND workspace_id = ?
                ) WHERE rn = 1
              )
              SELECT s.id AS scan_id, s.domain
              FROM scans s JOIN lpd ON lpd.scan_id = s.id
              ${OWN_JOIN}
              WHERE s.workspace_id = ? LIMIT \${MAX_DOMAINS_FOR_EMAIL}\`)
    .bind(workspaceId, workspaceId)`,
    `    .prepare(\`WITH lpd AS (SELECT domain_id, MAX(created_at) mx FROM scans WHERE status='completed' GROUP BY domain_id)
              SELECT s.id AS scan_id, s.domain
              FROM scans s JOIN lpd ON s.domain_id = lpd.domain_id AND s.created_at = lpd.mx
              JOIN workspace_domains wd ON s.domain_id = wd.domain_id
              WHERE wd.workspace_id = ? LIMIT \${MAX_DOMAINS_FOR_EMAIL}\`)
    .bind(workspaceId)`]] },
  { name: "M14_SENDER_PROVENANCE_DOMAIN_LINK_OR", file: SENDER, expect: ["bec-exposure"], edits: [[
    `                FROM scans s
                WHERE s.status = 'completed'
                  AND s.domain = ?
                  AND s.workspace_id = ?
                ORDER BY s.created_at DESC LIMIT 1\`)
      .bind(domain, workspaceId).first();`,
    `                FROM scans s
                LEFT JOIN workspace_domains wd ON wd.domain_id = s.domain_id
                WHERE s.status = 'completed'
                  AND s.domain = ?
                  AND (s.workspace_id = ? OR wd.workspace_id = ?)
                ORDER BY s.created_at DESC LIMIT 1\`)
      .bind(domain, workspaceId, workspaceId).first();`]] },
  { name: "M15_RELATED_CHANGES_DOMAIN_LINK", file: RELATED, expect: ["related-changes"], edits: [[
    `         ${OWN_JOIN}
        WHERE s.workspace_id = ? AND s.status = 'completed'`,
    `         JOIN workspace_domains wd ON wd.domain_id = s.domain_id
        WHERE wd.workspace_id = ? AND s.status = 'completed'`, 2]] },
  { name: "M16_SCORECARD_DOMAIN_LINK", file: SCORECARD, expect: ["scorecard-verified-links", "scorecard-unverified-links", "scorecard-no-owned-evidence"], edits: [[
    `         WHERE wd.workspace_id = ? AND s.status = 'completed'
         AND s.workspace_id = ?
         ORDER BY s.created_at DESC LIMIT 1\`\n      ).bind(wsId, wsId),`,
    `         WHERE wd.workspace_id = ? AND s.status = 'completed'
         ORDER BY s.created_at DESC LIMIT 1\`\n      ).bind(wsId),`]] },
];
const CONTROL = { name: "CONTROL_COSMETIC_COMMENT", file: CUSTOMERS,
  from: "// Shared by portfolio.js (overview) and the queries below so both agree.",
  to:   "// Shared by portfolio.js (overview) and the queries below (cosmetic control edit)." };

const count = (s, needle) => s.split(needle).length - 1;

console.log("=== BASELINE ===");
const base = runSuite();
console.log(base.ok ? "  PASS — baseline green" : `  FAIL — baseline RED, aborting\n${base.out.slice(-1200)}`);
if (!base.ok) process.exit(1);

let allKilled = true;
console.log("\n=== MUTANTS ===");
for (const m of MUTANTS) {
  const before = sha(m.file);
  const orig = fs.readFileSync(m.file, "utf8");
  let mutated = orig, anchorsValid = true;
  for (const [from, to, n = 1] of m.edits) {
    if (count(mutated, from) !== n) { console.log(`  ANCHOR-FAIL ${m.name} (expected ${n}, found ${count(mutated, from)})`); anchorsValid = false; break; }
    mutated = mutated.split(from).join(to);
  }
  if (!anchorsValid) { allKilled = false; continue; }
  fs.writeFileSync(m.file, mutated);
  let r;
  try { r = runSuite(); } finally { fs.writeFileSync(m.file, orig); }
  const after = sha(m.file);
  // A mutant that CRASHES the suite proves nothing — it may be invalid rather
  // than defective. A kill requires a NAMED assertion failure in every expected
  // section, and the suite must have reached its terminal summary line.
  const reachedEnd = /Aggregate scan-ownership isolation: \d+ passed/.test(r.out);
  const allFailures = failedNames(r.out);
  const covered = m.expect.filter((sec) => allFailures.some((l) => l.includes(`[${sec}]`)));
  const named = allFailures.filter((l) => m.expect.some((sec) => l.includes(`[${sec}]`)));
  const killed = !r.ok && reachedEnd && covered.length === m.expect.length;
  console.log(`  ${killed ? "KILLED  " : "SURVIVED"} ${m.name}`);
  console.log(`      expected sections: ${m.expect.map((s) => `[${s}]`).join(", ")}   covered: ${covered.length}/${m.expect.length}   named failures: ${named.length}   suite completed: ${reachedEnd}`);
  if (named[0]) console.log(`      e.g. ${named[0].slice(0, 180)}`);
  console.log(`      bytes restored: ${before === after ? "verified" : "MISMATCH"}`);
  allKilled &&= killed && before === after;
}

console.log("\n=== INVALID-KILL CONTROL ===");
{
  const before = sha(CONTROL.file);
  const orig = fs.readFileSync(CONTROL.file, "utf8");
  if (count(orig, CONTROL.from) !== 1) { console.log("  ANCHOR-FAIL control"); allKilled = false; }
  else {
    fs.writeFileSync(CONTROL.file, orig.replace(CONTROL.from, CONTROL.to));
    let r;
    try { r = runSuite(); } finally { fs.writeFileSync(CONTROL.file, orig); }
    const ok = r.ok && sha(CONTROL.file) === before;
    console.log(`  ${ok ? "SURVIVED (correct)" : "KILLED (suite is brittle)"} ${CONTROL.name}`);
    allKilled &&= ok;
  }
}
console.log(`\nRESULT: ${allKilled ? `${MUTANTS.length}/${MUTANTS.length} MUTANTS KILLED BY NAME, CONTROL SURVIVED` : "FAILED"}`);
process.exit(allKilled ? 0 : 1);
