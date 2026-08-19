#!/usr/bin/env node
// F-47 — mutation proof for the Shadow IT customer action surface.
//
// Each mutant reintroduces one exact defect into the REAL production source and
// re-runs the F-47 suites in a fresh process. A mutant counts as KILLED only when
// the suite fails for the RIGHT REASON — the named tests below must be among the
// failures. A transform/collect/spawn error is never a kill, because a file that
// no longer parses proves nothing about the assertions.
//
// Survivor controls exist for the opposite failure: a suite that fails on any
// edit would score 100% here while discriminating nothing. Cosmetic mutations
// MUST leave the suite green.
//
// Source bytes are restored and verified by hash after every mutant.
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const PAGE = "frontend/src/pages/ws/ShadowItInventoryPage.jsx";
const DISPLAY = "frontend/src/lib/shadowItDisplay.js";
const SUITES = [
  "src/pages/ws/__tests__/ShadowItInventoryPage.actions.test.jsx",
  "src/pages/ws/__tests__/ShadowItInventoryPage.workspace.test.jsx",
  "src/lib/__tests__/shadowItDisplay.test.js",
];
// Baseline assertion count. 48 -> 55 in the F-54 successor (legacy-capable
// persisted-domain fixtures the original suite never exercised), then 55 -> 59 in
// successor-2, which added the measured serializer-boundary fixtures: the empty
// string is normalized to null, and each claimed non-empty value is demonstrated
// as passing through.
const EXPECTED_TOTAL = 59;

const sha256 = (b) => crypto.createHash("sha256").update(b).digest("hex");
const abs = (rel) => path.join(root, rel);
const read = (rel) => fs.readFileSync(abs(rel), "utf8");
const write = (rel, v) => fs.writeFileSync(abs(rel), v);

// ── the runner ──────────────────────────────────────────────────────────────
// Returns { ok, failed: [names], total, transformError }.
function runSuites() {
  const out = path.join(os.tmpdir(), `f47-vitest-${crypto.randomUUID()}.json`);
  const r = spawnSync("npx", ["vitest", "run", "--reporter=json", `--outputFile=${out}`, ...SUITES], {
    cwd: abs("frontend"), encoding: "utf8", timeout: 600000,
  });
  if (r.error || r.signal) return { ok: false, failed: [], total: 0, transformError: true };
  let report;
  try { report = JSON.parse(fs.readFileSync(out, "utf8")); }
  catch { return { ok: false, failed: [], total: 0, transformError: true }; }
  finally { fs.rmSync(out, { force: true }); }
  const tests = (report.testResults || []).flatMap((f) => f.assertionResults || []);
  // No tests collected at all = the file did not parse. Never a kill.
  if (tests.length === 0) return { ok: false, failed: [], total: 0, transformError: true };
  const failed = tests.filter((t) => t.status === "failed").map((t) => t.fullName || t.title);
  return { ok: failed.length === 0, failed, total: tests.length, transformError: false };
}

// ── mutants: [label, file, exactFindString, replacement, requiredFailSubstring] ──
const MUTANTS = [
  ["M1-drop-assign-technical-owner", PAGE,
    "      { action: 'assign_technical_owner', label: 'Technical owner', tone: 'slate' },\n", "",
    "ALL 12 server-advertised actions"],
  ["M2-drop-begin-onboarding", PAGE,
    "      { action: 'begin_onboarding', label: 'Start onboarding', tone: 'slate' },\n", "",
    "ALL 12 server-advertised actions"],
  ["M3-drop-mark-onboarded", PAGE,
    "      { action: 'mark_onboarded',   label: 'Mark onboarded',   tone: 'slate' },\n", "",
    "ALL 12 server-advertised actions"],
  ["M4-drop-begin-removal", PAGE,
    "      { action: 'begin_removal', label: 'Start removal', tone: 'slate' },\n", "",
    "ALL 12 server-advertised actions"],
  ["M5-drop-mark-removed", PAGE,
    "      { action: 'mark_removed',  label: 'Mark removed',  tone: 'slate' },\n", "",
    "ALL 12 server-advertised actions"],
  ["M6-drop-reopen-review", PAGE,
    "      { action: 'reopen_review',  label: 'Reopen review', tone: 'slate' },\n", "",
    "ALL 12 server-advertised actions"],
  // The frontend invents permissions the server never advertised.
  ["M7-ignore-server-action-list", PAGE,
    "const can = (a) => serverActions.includes(a)", "const can = () => true",
    "renders NO action control for a viewer"],
  // The pre-F-47 defect: one failed action erases the whole inventory.
  ["M8-action-error-shares-load-slot", PAGE,
    "      setActionError(`“${ACTION_LABEL[action] || action}” did not complete",
    "      setError(`“${ACTION_LABEL[action] || action}” did not complete",
    "does NOT erase the inventory"],
  // A customer assertion published without asking the customer.
  ["M9-mark-removed-skips-confirmation", PAGE,
    "      if (!confirmed) return", "      if (false) return",
    "does nothing when the customer declines"],
  ["M10-reopen-review-ignores-cancel", PAGE,
    "      if (reason == null) return", "      if (false) return",
    "aborts when the customer cancels"],
  // Duplicate submission is no longer suppressed while in flight.
  ["M11-no-busy-suppression", PAGE,
    "                                  disabled={busy === it.inventory_item_id}\n", "",
    "suppresses duplicate submission"],
  // THE EVIDENCE-HONESTY MUTANT: a customer assertion rendered as verification.
  ["M12-removal-claims-verification", DISPLAY,
    "    return { label: `${base.label} — your assertion, not verified by CyberMeters`, tone: 'amber' }",
    "    return { label: `${base.label} — verified removal`, tone: 'green' }",
    "never presents a customer-asserted removal as verified"],
  // A contradiction silently downgraded to the ordinary unverified case.
  ["M13-contradiction-silenced", DISPLAY,
    "  if (verified === 'contradicted') {", "  if (false) {",
    "escalates a contradicted removal"],
  // ── F-54 — THE DISCRIMINATING LEGACY-VALUE MUTANT ─────────────────────────
  // The persisted column is unconstrained and migration 084 declares `verified`,
  // so a legacy row can carry it. This mutant is the realistic mistake: someone
  // "helpfully" honours that stored grade and promotes it to confirmation.
  //
  // It is deliberately INVISIBLE to every assertion that existed before F-54 —
  // no earlier test ever passed `verified` as an input — and visible ONLY to the
  // new legacy-domain fixtures. That is what makes it discriminating rather than
  // decorative: it proves the added fixture is load-bearing, not merely present.
  ["M14-legacy-verified-promoted-to-confirmation", DISPLAY,
    "  if (verified === 'contradicted') {",
    "  if (verified === 'verified') {\n    return { label: `${base.label} — verified removal`, tone: 'green' }\n  }\n  if (verified === 'contradicted') {",
    "renders a REAL legacy `verified` row as the customer assertion"],
];

// ── survivor controls: cosmetic edits that MUST NOT fail the suite ──────────
const SURVIVORS = [
  ["S1-approve-button-colour", PAGE,
    "{ action: 'approve',        label: 'Approve',       tone: 'green' },",
    "{ action: 'approve',        label: 'Approve',       tone: 'slate' },"],
  ["S2-action-column-width", PAGE,
    'className="space-y-1.5 min-w-[12rem]"', 'className="space-y-1.5 min-w-[14rem]"'],
];

function applyExact(rel, find, replace, label) {
  const src = read(rel);
  const n = src.split(find).length - 1;
  if (n !== 1) throw new Error(`${label}: anchor must appear exactly once in ${rel}, found ${n}`);
  write(rel, src.replace(find, replace));
}

// ── F-54 successor-2 — EXECUTED SERIALIZER-BOUNDARY PROOF ───────────────────
// Bar 1 is about evidence fidelity, so the display module's boundary claim is
// not trusted as prose: it is executed against the REAL serializer.
//
// `shadowItItemToApi` (shadow-it-inventory.js:1018) is the single serializer
// behind every read path — list (:1078), single item (:1082), action result
// (:1005). Its removal_verified expression at :1043 is `row.removal_verified ||
// null`, which is falsy-normalizing, NOT a pass-through.
//
// This check stores each declared value on a real row, runs the real serializer,
// and requires:
//   * every value in REMOVAL_VERIFIED_NORMALIZED_TO_NULL  -> null;
//   * every value in REMOVAL_VERIFIED_PASSES_THROUGH      -> byte-identical.
// A claim that disagrees with the measured behaviour fails here, in either
// direction — too narrow (v1) or too wide (v2).
async function serializerBoundaryProof() {
  const engine = await import(new URL("../workers/scan-api/src/engines/shadow-it-inventory.js", import.meta.url));
  const display = await import(new URL("../frontend/src/lib/shadowItDisplay.js", import.meta.url));
  const row = (v) => ({
    id: "sii_boundary", workspace_id: "ws_boundary", display_name: "Boundary Fixture",
    classification: "unreviewed", monitoring_status: "observed",
    created_at: "2026-08-17T00:00:00Z", updated_at: "2026-08-17T00:00:00Z",
    removal_status: "removed", removal_verified: v,
  });
  const serialize = (v) => engine.shadowItItemToApi(row(v)).removal_verified;
  const problems = [];

  for (const v of display.REMOVAL_VERIFIED_NORMALIZED_TO_NULL) {
    const got = serialize(v);
    console.log(`  stored ${JSON.stringify(v).padEnd(24)} -> ${JSON.stringify(got)}   (claimed: normalized to null)`);
    if (got !== null) problems.push(`${JSON.stringify(v)} was claimed normalized to null but serialized to ${JSON.stringify(got)}`);
  }
  for (const v of display.REMOVAL_VERIFIED_PASSES_THROUGH) {
    const got = serialize(v);
    console.log(`  stored ${JSON.stringify(v).padEnd(24)} -> ${JSON.stringify(got)}   (claimed: passes through)`);
    if (got !== v) problems.push(`${JSON.stringify(v)} was claimed to pass through but serialized to ${JSON.stringify(got)}`);
  }
  // The two sides must stay disjoint and the pass-through side non-falsy: a
  // falsy value can never pass through `|| null`, so claiming one would be the
  // exact too-wide error this proof exists to prevent.
  for (const v of display.REMOVAL_VERIFIED_PASSES_THROUGH) {
    if (!v) problems.push(`falsy value ${JSON.stringify(v)} cannot pass through \`|| null\``);
    if (display.REMOVAL_VERIFIED_NORMALIZED_TO_NULL.includes(v)) problems.push(`${JSON.stringify(v)} is claimed on both sides`);
  }
  // And the legacy value the whole finding is about must be demonstrated.
  if (!display.REMOVAL_VERIFIED_PASSES_THROUGH.includes("verified")) {
    problems.push("legacy 'verified' is not among the demonstrated pass-through values");
  }
  return problems;
}

// ── Boundary mutants: the claim itself must be falsifiable ──────────────────
// The proof above only earns its keep if a WRONG claim fails it. Each mutant
// below edits the display module's boundary lists and must be rejected by the
// executed serializer for its named reason. Both directions are covered,
// because this line has now been wrong in both: too narrow (v1) and too wide
// (v2). Each runs in a FRESH process — ESM caches modules, so an in-process
// re-import would silently re-use the unmutated bytes and prove nothing.
const BOUNDARY_MUTANTS = [
  ["B1-empty-string-claimed-to-pass-through", DISPLAY,
    "export const REMOVAL_VERIFIED_PASSES_THROUGH = Object.freeze([\n  'verified',",
    "export const REMOVAL_VERIFIED_PASSES_THROUGH = Object.freeze([\n  '', 'verified',",
    "was claimed to pass through but serialized to null"],
  ["B2-nonempty-value-claimed-normalized", DISPLAY,
    "export const REMOVAL_VERIFIED_NORMALIZED_TO_NULL = Object.freeze([''])",
    "export const REMOVAL_VERIFIED_NORMALIZED_TO_NULL = Object.freeze(['', 'verified'])",
    "was claimed normalized to null but serialized to"],
  ["B3-legacy-verified-erased-from-demonstration", DISPLAY,
    "  'verified', 'unverified', 'contradicted', 'CONFIRMED', 'verification_grade_a', 'true',",
    "  'unverified', 'contradicted', 'CONFIRMED', 'verification_grade_a', 'true',",
    "legacy 'verified' is not among the demonstrated pass-through values"],
];

function runBoundaryOnly() {
  const r = spawnSync(process.execPath, [fileURLToPath(import.meta.url)], {
    cwd: root, encoding: "utf8", timeout: 300000,
    env: { ...process.env, F47_BOUNDARY_ONLY: "1" },
  });
  return { code: r.status, out: `${r.stdout || ""}${r.stderr || ""}` };
}

async function main() {
  // Sub-process mode used by the boundary mutants above.
  if (process.env.F47_BOUNDARY_ONLY === "1") {
    const problems = await serializerBoundaryProof();
    problems.forEach((p) => console.error(p));
    return problems.length ? 1 : 0;
  }

  const originals = new Map([PAGE, DISPLAY].map((f) => [f, read(f)]));
  const originalHashes = new Map([...originals].map(([f, v]) => [f, sha256(v)]));
  const restore = () => { for (const [f, v] of originals) write(f, v); };

  console.log("F-47 serializer-boundary proof (executed against the real serializer)\n");
  const boundaryProblems = await serializerBoundaryProof();
  if (boundaryProblems.length) {
    console.error("\nFAIL serializer-boundary claim disagrees with the measured expression:");
    boundaryProblems.forEach((p) => console.error(`   ${p}`));
    return 1;
  }
  console.log("PASS serializer boundary — every claimed value matches the executed serializer\n");

  console.log("F-47 mutation proof — baseline first\n");
  const base = runSuites();
  if (!base.ok) {
    console.error(`FAIL baseline is not green (${base.failed.length} failing). Mutation proof is meaningless from a red baseline.`);
    base.failed.slice(0, 5).forEach((f) => console.error(`   ${f}`));
    return 1;
  }
  if (base.total !== EXPECTED_TOTAL) {
    console.error(`FAIL baseline assertion count drifted: expected ${EXPECTED_TOTAL}, measured ${base.total}`);
    return 1;
  }
  console.log(`PASS baseline green — ${base.total} tests\n`);

  let killed = 0, survived = 0, wrongReason = 0, parseOnly = 0;
  for (const [label, file, find, replace, needle] of MUTANTS) {
    try {
      applyExact(file, find, replace, label);
      const r = runSuites();
      if (r.transformError) { console.log(`SKIP ${label} — source no longer parses; not counted as a kill`); parseOnly++; }
      else if (r.ok) { console.log(`SURVIVED ${label} — the suite did not notice the defect`); survived++; }
      else if (r.failed.some((f) => f.includes(needle))) {
        console.log(`KILLED ${label} — right reason ("${needle}")`); killed++;
      } else {
        console.log(`WRONG-REASON ${label} — failed, but not on "${needle}"`);
        r.failed.slice(0, 3).forEach((f) => console.log(`         actual: ${f}`));
        wrongReason++;
      }
    } finally { restore(); }
  }

  console.log("");
  let boundaryKilled = 0;
  for (const [label, file, find, replace, needle] of BOUNDARY_MUTANTS) {
    try {
      applyExact(file, find, replace, label);
      const r = runBoundaryOnly();
      if (r.code === 0) console.log(`SURVIVED ${label} — a false boundary claim was accepted`);
      else if (r.out.includes(needle)) { console.log(`KILLED ${label} — right reason ("${needle}")`); boundaryKilled++; }
      else console.log(`WRONG-REASON ${label} — failed, but not on "${needle}"`);
    } finally { restore(); }
  }

  console.log("");
  let survivorOk = 0;
  for (const [label, file, find, replace] of SURVIVORS) {
    try {
      applyExact(file, find, replace, label);
      const r = runSuites();
      if (r.ok) { console.log(`CONTROL-OK ${label} — cosmetic change survives, as required`); survivorOk++; }
      else console.log(`CONTROL-FAILED ${label} — suite is hypersensitive; it fails on a cosmetic edit`);
    } finally { restore(); }
  }

  for (const [f, want] of originalHashes) {
    const got = sha256(read(f));
    if (got !== want) { console.error(`FAIL source not restored: ${f}`); return 1; }
  }
  console.log("\nSource bytes restored and hash-verified.");
  console.log(`F-47 mutations: ${killed}/${MUTANTS.length} killed (right reason), ${survived} survived, ${wrongReason} wrong-reason, ${parseOnly} unparseable; controls ${survivorOk}/${SURVIVORS.length} survived`);

  console.log(`F-47 boundary mutants: ${boundaryKilled}/${BOUNDARY_MUTANTS.length} killed (right reason)`);
  const ok = killed === MUTANTS.length && survivorOk === SURVIVORS.length
    && boundaryKilled === BOUNDARY_MUTANTS.length;
  console.log(ok ? "F-47 mutation proof PASSED" : "F-47 mutation proof FAILED");
  return ok ? 0 : 1;
}

process.exit(await main());
