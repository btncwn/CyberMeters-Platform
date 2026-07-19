#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-entry-point-inventory.js  (CI-blocking)
//
// Re-derives the entry-point signature from Worker source and asserts:
//   1. it matches the committed scripts/security/entry-point-inventory.json
//      (drift gate — a new/removed route or a changed guard set fails until the
//      builder is re-run and the inventory reviewed + committed);
//   2. zero sensitive-scope authorization gaps (re-derived, not trusted from the
//      committed file) — every workspace / resource / account / admin / portfolio
//      handler either authenticates or matches a documented public-allowlist reason.
//
// Exits non-zero on any failure so CI blocks.
// ─────────────────────────────────────────────────────────────────────────────
import fs from "node:fs";
import path from "node:path";
import { extractAll, summarise, isPublic, REPO_ROOT } from "./security/lib/extract-entry-points.js";
import { buildSignature } from "./security/build-entry-point-inventory.js";

let failed = 0;
const fail = (msg) => { failed++; console.error("  ✗ " + msg); };

const jsonPath = path.join(REPO_ROOT, "scripts", "security", "entry-point-inventory.json");
if (!fs.existsSync(jsonPath)) {
  console.error(`FAIL: ${jsonPath} missing. Run: node scripts/security/build-entry-point-inventory.js`);
  process.exit(1);
}

const committed = JSON.parse(fs.readFileSync(jsonPath, "utf8"));
const fresh = buildSignature();

// ── 1. Drift gate ────────────────────────────────────────────────────────────
// Multiset comparison over the full entry signature: a route regex + method can
// legitimately repeat (one match, several sub-branches), so we count identical
// signatures rather than key on (method,path,file), which would collapse them.
const label = (e) => `${e.method} ${e.path} @ ${e.file}  authed=${e.authed} guards=[${(e.auth_guards || []).join(",")}] scope=${e.scope}`;
const bag = (arr) => { const m = new Map(); for (const e of arr) { const k = JSON.stringify(e); m.set(k, (m.get(k) || 0) + 1); } return m; };
const cBag = bag(committed.entry_points);
const fBag = bag(fresh.entry_points);
for (const [k, n] of fBag) {
  const c = cBag.get(k) || 0;
  if (n > c) fail(`NOT in committed inventory (added/changed): ${label(JSON.parse(k))}${n - c > 1 ? ` (×${n - c})` : ""}. Re-run the builder.`);
}
for (const [k, n] of cBag) {
  const f = fBag.get(k) || 0;
  if (n > f) fail(`In committed inventory but no longer in source (removed/changed): ${label(JSON.parse(k))}${n - f > 1 ? ` (×${n - f})` : ""}. Re-run the builder.`);
}
if (committed.counts.total !== fresh.counts.total) {
  fail(`Total count drift: committed=${committed.counts.total} current=${fresh.counts.total}`);
}

// ── 2. Coverage gate (re-derived, authoritative) ─────────────────────────────
const all = extractAll();
const s = summarise(all);
const review = all.filter((e) => !e.authed &&
  ["workspace", "resource", "account", "portfolio", "admin"].includes(e.scope) &&
  !isPublic(e.path || "", e.method) && e.scope !== "preflight");
if (s.gaps.length !== 0 || review.length !== 0) {
  for (const g of review) fail(`Sensitive-scope handler has NO auth guard and NO public-allowlist reason: ${g.method} ${g.path} @ ${g.file}:${g.line}`);
}

// ── Report ───────────────────────────────────────────────────────────────────
console.log("Entry-point inventory:");
console.log(`  entry points: ${fresh.counts.total}   auth-guarded: ${fresh.counts.authed}   public: ${fresh.counts.public_unauthed}`);
console.log(`  sensitive-scope gaps: ${s.gaps.length}`);
if (failed) {
  console.error(`\nentry-point inventory validation FAILED (${failed} issue(s)).`);
  console.error("If routes changed intentionally, run: node scripts/security/build-entry-point-inventory.js  and commit the result.");
  process.exit(1);
}
console.log("entry-point inventory validation passed");
