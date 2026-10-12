#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

const moduleUrl = new URL("../workers/scan-api/src/engines/asset-recheck-rotation.js", import.meta.url);
const helperUrl = new URL("../workers/scan-api/src/engines/hostname-candidates.js", import.meta.url);
const source = fs.readFileSync(fileURLToPath(moduleUrl), "utf8");

function fixtures(api) {
  let checks = 0;
  const eq = (got, want, label) => { assert.deepEqual(got, want, label); checks++; };
  const ok = (value, label) => { assert.ok(value, label); checks++; };
  const now = "2026-10-12T00:00:00.000Z";
  const run = (input) => api.selectRecheckHosts({ now, ...input });
  const host = (i) => `host${String(i).padStart(3, "0")}.example.com`;
  const known = Array.from({ length: 151 }, (_, i) => ({ hostname: host(i), last_rechecked_at: null }));
  const newNames = Array.from({ length: 12 }, (_, i) => ({ hostname: `new${i}.example.com`, sources: ["csp"] }));
  const touched = new Set();
  for (let turn = 0; turn < 4; turn++) {
    const timestamp = `2026-10-${12 + turn}T00:00:00.000Z`;
    const result = run({ knownAssets: known, candidates: newNames, now: timestamp });
    const selectedKnown = result.selected.filter((r) => r.reason !== "new_candidate");
    eq(selectedKnown.length, 40, "reserved known share");
    eq(result.selected.length, 50, "combined cap");
    for (const row of selectedKnown) {
      touched.add(row.hostname);
      known.find((asset) => asset.hostname === row.hostname).last_rechecked_at = timestamp;
    }
  }
  eq(touched.size, 151, "all 151 known names visited in four runs");
  const unavailable = [{ hostname: "offline.example.com", last_rechecked_at: "2026-10-10T00:00:00Z", consecutive_unavailable: 5 }];
  const blocked = run({ knownAssets: unavailable });
  eq(blocked.selected, [], "four day backoff enforced");
  eq(blocked.backoff_skipped_count, 1, "backoff count");
  eq(blocked.deferred_known_count, 1, "deferred includes backoff subset");
  eq(run({ knownAssets: unavailable, now: "2026-10-14T00:00:00Z" }).selected[0]?.hostname, "offline.example.com", "name returns at exact backoff boundary");
  const cappedBackoff = [{ ...unavailable[0], consecutive_unavailable: Number.MAX_SAFE_INTEGER }];
  eq(run({ knownAssets: cappedBackoff, now: "2026-10-16T00:00:00Z" }).selected.length, 0, "long retry history backs off seven days");
  eq(run({ knownAssets: cappedBackoff, now: "2026-10-17T00:00:00Z" }).selected.length, 1, "seven day cap never drops name");
  eq(run({ knownAssets: known, candidates: [] }).selected.length, 50, "empty candidate group transfers places");
  const lots = Array.from({ length: 70 }, (_, i) => ({ hostname: `new${i}.example.com`, sources: ["csp"] }));
  eq(run({ knownAssets: [], candidates: lots }).selected.length, 50, "empty known group transfers places");
  eq(run({ knownAssets: known.slice(0, 2), candidates: lots }).selected.length, 50, "partially filled known share transfers places");
  eq(run({ knownAssets: known, candidates: lots.slice(0, 2) }).selected.filter((r) => r.reason !== "new_candidate").length, 48, "partially filled candidate share transfers places");
  const ordered = run({ knownAssets: [
    { hostname: "z.example.com", last_rechecked_at: "2026-10-01T00:00:00Z" },
    { hostname: "a.example.com", last_rechecked_at: "2026-10-02T00:00:00Z" },
    { hostname: "never.example.com", last_rechecked_at: null },
    { hostname: "invalid.example.com", last_rechecked_at: "2026-02-30T00:00:00Z" },
    { hostname: "future.example.com", last_rechecked_at: "2099-01-01T00:00:00Z", consecutive_unavailable: 9 },
  ] });
  eq(ordered.selected.map((r) => r.hostname), ["future.example.com", "invalid.example.com", "never.example.com", "z.example.com", "a.example.com"], "null/invalid/future first then oldest");
  eq(ordered.backoff_skipped_count, 0, "future timestamp cannot poison backoff");
  const candidateRank = run({ knownAssets: [], candidates: [
    { hostname: "a.example.com", sources: ["csp", "csp", "csp"] },
    { hostname: "z.example.com", sources: ["csp", "live_tls_san"] },
    { hostname: "z.example.com", sources: ["mx"] },
    { hostname: "B.EXAMPLE.COM.", sources: ["csp"] },
  ] });
  eq(candidateRank.selected.map((r) => r.hostname), ["z.example.com", "a.example.com", "b.example.com"], "unique merged source count ranks candidates");
  const overlap = run({ knownAssets: [{ hostname: "a.example.com", last_rechecked_at: null }], candidates: [{ hostname: "A.EXAMPLE.COM.", sources: ["csp"] }] });
  eq(overlap.selected.length, 1, "known/candidate overlap deduped");
  eq(overlap.selected[0].reason, "known_never_checked", "known role retained");
  const backoffOverlap = run({ knownAssets: unavailable, candidates: [{ hostname: "offline.example.com", sources: ["csp"] }] });
  eq(backoffOverlap.selected, [], "candidate cannot bypass known backoff");
  const dupKnown = run({ knownAssets: [
    { hostname: "a.example.com", last_rechecked_at: "2026-10-11T00:00:00Z", consecutive_unavailable: 5 },
    { hostname: "A.EXAMPLE.COM.", last_rechecked_at: null },
  ] });
  eq(dupKnown.selected.length, 1, "known duplicates use one slot");
  eq(dupKnown.selected[0].reason, "known_never_checked", "duplicate chooses oldest/null evidence");
  for (const cap of [0, 1, 7, 49, 50, 80]) {
    const result = run({ knownAssets: known, candidates: lots, cap });
    ok(result.selected.length <= cap, "cap never exceeded");
    eq(new Set(result.selected.map((r) => r.hostname)).size, result.selected.length, "no duplicate selected slots");
    eq(result.deferred_known_count + result.selected.filter((r) => r.reason !== "new_candidate").length, known.length, "known count reconciles");
    eq(result.deferred_candidate_count + result.selected.filter((r) => r.reason === "new_candidate").length, lots.length, "candidate count reconciles");
  }
  for (const badCap of [-1, 1.5, NaN, Infinity, "20", null]) {
    eq(run({ knownAssets: known, candidates: lots, cap: badCap }).selected.length, 50, "invalid cap defaults safely");
  }
  for (const badShare of [-1, 1.5, NaN, Infinity, "20", null]) {
    eq(run({ knownAssets: known, candidates: lots, knownShare: badShare }).selected.filter((r) => r.reason !== "new_candidate").length, 40, "invalid share defaults safely");
  }
  for (const failures of [-1, 3.5, NaN, Infinity, "5"]) {
    eq(run({ knownAssets: [{ ...unavailable[0], consecutive_unavailable: failures }] }).backoff_skipped_count, 0, "invalid unavailable count cannot poison rotation");
  }
  for (const timestamp of ["bogus", 0, {}, "2026-10-12", "2026-99-10T00:00:00Z", "2026-10-12T24:00:00Z"]) {
    eq(run({ knownAssets: [{ ...unavailable[0], last_rechecked_at: timestamp }] }).selected[0]?.reason, "known_never_checked", "invalid date behaves as null");
  }
  for (const bad of [undefined, null, [], 3, "x", { knownAssets: "x", candidates: {} }]) {
    eq(api.selectRecheckHosts(bad).selected, [], "invalid outer input safe");
  }
  const input = { knownAssets: known, candidates: lots, now };
  const before = JSON.stringify(input);
  eq(run(input), run(input), "deterministic selection");
  eq(JSON.stringify(input), before, "input not modified");
  eq(run({ ...input, knownAssets: [...known].reverse(), candidates: [...lots].reverse() }), run(input), "input order does not change selection");
  eq(Object.keys(run(input)).sort(), ["version", "selected", "deferred_known_count", "deferred_candidate_count", "backoff_skipped_count"].sort(), "exact result contract");
  return checks;
}

try {
  const api = await import(moduleUrl.href);
  let checks = fixtures(api);
  assert.ok(!/\b(?:fetch|connect)\s*\(|from\s*["'](?:node:)?(?:net|tls|https?|dns|dgram)["']/.test(source), "production module has no network I/O"); checks++;
  assert.ok(!/Date\.now\s*\(|Math\.random\s*\(/.test(source), "no ambient time/randomness"); checks++;
  const mutations = [
    ["return a.checked - b.checked;", "return b.checked - a.checked;", "oldest ordering reversed"],
    ["item.failures >= 3 ?", "false ?", "backoff disabled"],
    ["Math.min(2 ** (item.failures - 3), 7)", "100", "backoff cap removed"],
    ["if (!hostname || known.has(hostname)) continue;", "if (!hostname) continue;", "known candidates admitted twice"],
    ["Math.min(spare, eligible.length - knownCount)", "0", "known spare places discarded"],
    ["b.count - a.count || compare(a.hostname, b.hostname)", "a.count - b.count || compare(a.hostname, b.hostname)", "source priority reversed"],
  ];
  for (const [before, after, label] of mutations) {
    assert.equal(source.split(before).length, 2, `unique mutation anchor: ${label}`);
    const code = source.replace(before, after).replace('"./hostname-candidates.js"', JSON.stringify(helperUrl.href));
    const mutant = await import(`data:text/javascript;base64,${Buffer.from(code).toString("base64")}`);
    assert.throws(() => fixtures(mutant), assert.AssertionError, `fixture suite must reject ${label}`);
    checks++;
  }
  console.log(`${checks} checks passed (asset recheck rotation; ${mutations.length} in-memory mutants killed)`);
} catch (error) {
  console.error("FAIL asset recheck rotation:", error);
  process.exitCode = 1;
}
