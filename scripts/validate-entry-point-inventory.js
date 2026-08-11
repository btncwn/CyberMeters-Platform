#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-entry-point-inventory.js  (CI-blocking)
//
// Re-derives the entry-point signature from Worker source and asserts:
//   1. it matches the committed scripts/security/entry-point-inventory.json
//      (drift gate — a new/removed route or a changed guard set fails until the
//      builder is re-run and the inventory reviewed + committed);
//   2. the committed Markdown is the exact canonical rendering, including every
//      displayed source line (stale locations fail deterministically);
//   3. zero sensitive-scope authorization gaps (re-derived, not trusted from the
//      committed file) — every workspace / resource / account / admin / portfolio
//      handler either authenticates or matches a documented public-allowlist reason.
//
// Exits non-zero on any failure so CI blocks.
// ─────────────────────────────────────────────────────────────────────────────
import fs from "node:fs";
import path from "node:path";
import { extractAll, summarise, isPublic, REPO_ROOT } from "./security/lib/extract-entry-points.js";
import { buildSignature, renderMarkdown } from "./security/build-entry-point-inventory.js";

let failed = 0;
const fail = (msg) => { failed++; console.error("  ✗ " + msg); };

const jsonPath = path.join(REPO_ROOT, "scripts", "security", "entry-point-inventory.json");
const markdownPath = path.join(REPO_ROOT, "docs", "security", "ENTRY-POINT-INVENTORY.md");
if (!fs.existsSync(jsonPath)) {
  console.error(`FAIL: ${jsonPath} missing. Run: node scripts/security/build-entry-point-inventory.js`);
  process.exit(1);
}
if (!fs.existsSync(markdownPath)) {
  console.error(`FAIL: ${markdownPath} missing. Run: node scripts/security/build-entry-point-inventory.js`);
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
if (JSON.stringify(committed) !== JSON.stringify(fresh)) {
  fail("Committed machine inventory is not the exact canonical generator output. Re-run the builder.");
}

// ── 2. Exact rendered-document gate ──────────────────────────────────────────
// The security signature deliberately excludes source lines so unrelated source
// movement does not alter route identity. The readable inventory nevertheless
// displays those locations, so its complete canonical rendering is checked
// independently. This preserves the semantic gate and closes the stale-line gap.
const all = extractAll();
const expectedMarkdown = renderMarkdown(fresh, all);
const committedMarkdown = fs.readFileSync(markdownPath, "utf8");
const markdownMatches = (candidate) => candidate === expectedMarkdown;
const firstDifference = (candidate) => {
  const expectedLines = expectedMarkdown.split("\n");
  const candidateLines = candidate.split("\n");
  const count = Math.max(expectedLines.length, candidateLines.length);
  for (let index = 0; index < count; index += 1) {
    if (expectedLines[index] !== candidateLines[index]) return index + 1;
  }
  return null;
};

if (!markdownMatches(committedMarkdown)) {
  fail(`Rendered Markdown drift at document line ${firstDifference(committedMarkdown)}. Re-run the builder.`);
}

// Must-fail control: change only the first displayed numeric source location.
// The exact predicate used above must reject it while route membership remains
// untouched, proving location freshness is a load-bearing CI contract.
const staleLineMarkdown = expectedMarkdown.replace(
  /^(\| [^\n|]+ \| `[^\n]*` \| )(\d+)( \|)/m,
  (_row, prefix, line, suffix) => `${prefix}${Number(line) + 1}${suffix}`,
);
if (staleLineMarkdown === expectedMarkdown || markdownMatches(staleLineMarkdown)) {
  fail("Stale displayed-line negative control was not rejected");
}

// ── 3. Coverage gate (re-derived, authoritative) ─────────────────────────────
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
console.log("  generated Markdown: exact (stale-line negative control rejected)");
if (failed) {
  console.error(`\nentry-point inventory validation FAILED (${failed} issue(s)).`);
  console.error("If routes changed intentionally, run: node scripts/security/build-entry-point-inventory.js  and commit the result.");
  process.exit(1);
}
console.log("entry-point inventory validation passed");
