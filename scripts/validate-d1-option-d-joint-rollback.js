#!/usr/bin/env node
// D1 Option D — JOINT ROLLBACK proof (Bar 5 of the five-point gate).
//
// Authority: work order seq 51 §2.5 — "Define and test one rollback unit covering
// the producer re-grade, structured carrier and every consumer adaptation.
// Reverting only the producer or only consumers is forbidden."
//
// This harness does not merely describe a rollback; it EXECUTES three variants
// against the real source and measures what each leaves behind:
//
//   FULL          revert all five paths -> a coherent pre-D1 world. Single-provider
//                 loss is `partial` again and the old I11A-C3 behaviour returns.
//                 Coherent, and therefore the ONLY acceptable rollback.
//   CONSUMER-ONLY revert the verification gate but KEEP the producer -> `degraded`
//                 scans are still produced AND can verify again. This is strictly
//                 WORSE than either end state: it re-opens the I11A-C3 defect on a
//                 status the producer now emits deliberately. MUST be rejected.
//   PRODUCER-ONLY revert the producer/carrier but KEEP the consumer fix -> the
//                 structured carrier disappears while consumers still expect it.
//                 Incoherent. MUST be rejected.
//
// Every variant restores exact bytes afterwards, verified by hash.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const abs = (r) => path.join(root, r);
const sha256 = (b) => crypto.createHash("sha256").update(b).digest("hex");

const PRODUCER = [
  "workers/scan-api/src/engines/subdomains-scan.js",
  "workers/scan-api/src/engines/scan-engine.js",
  "workers/scan-api/src/engines/report-snapshot.js",
];
const CARRIER = "workers/scan-api/src/engines/scan-degradation-contract.js";
const CONSUMER = ["workers/scan-api/src/engines/asm-cases.js"];
const ALL = [...PRODUCER, CARRIER, ...CONSUMER];

// Pre-D1 bytes come from the EXACT BASE COMMIT, not from HEAD.
//
// SUCCESSOR-3 CORRECTION: this previously read `HEAD:${rel}`, which was only
// correct while the D1 changes sat uncommitted in the working tree. Once they are
// committed — as they must be to open a PR — HEAD CONTAINS D1, so "revert to HEAD"
// restored D1 to itself and the rollback proved nothing. The base is pinned
// explicitly so the harness cannot silently degrade again depending on whether the
// author had committed yet.
const PRE_D1_BASE = "7094222c6745816bba08c26daac139d3e8cc474d";
function preD1(rel) {
  const r = spawnSync("git", ["--no-optional-locks", "show", `${PRE_D1_BASE}:${rel}`], { cwd: root, encoding: "utf8" });
  return r.status === 0 ? r.stdout : null;
}

// Probe the live tree in a FRESH process; module caching would otherwise hide the
// rollback entirely.
const PROBE = `
import { pathToFileURL } from "node:url";
const E = (f) => pathToFileURL(process.argv[2] + "/workers/scan-api/src/engines/" + f).href;
const out = { produced: null, degradedVerifies: null, carrier: null, error: null };
try {
  const { buildScanQuality } = await import(E("scan-engine.js"));
  const { moduleCompletionGate } = await import(E("asm-cases.js"));
  let deg = null;
  try {
    await import(E("scan-degradation-contract.js"));
    // Deterministic module FACTS — the engine stamps observed_at centrally.
    deg = { module:"subdomains", dependency:"ct_provider:crt_sh", reason:"x",
      fallback_source:"ct_provider:certspotter", fallback_count:2 };
    out.carrier = true;
  } catch { out.carrier = false; }
  // LV-01: supply the persisted observation anchor explicitly; the contract now
  // fails closed without one instead of substituting wall-clock time.
  const q = buildScanQuality({ dns:{}, headers:{}, subdomains: deg ? { degradations:[deg] } : { incomplete:true, incomplete_reason:"ct_source_degraded" } }, "2026-08-18T01:00:00Z");
  out.produced = q.status;
  out.degradedVerifies = moduleCompletionGate({ headers:{} }, { status:"degraded", modules_skipped:[] }).canVerify("headers");
} catch (e) { out.error = String(e && e.message || e); }
console.log(JSON.stringify(out));
`;

function probe() {
  const f = path.join(root, `.d1-rollback-probe-${crypto.randomUUID()}.mjs`);
  fs.writeFileSync(f, PROBE);
  try {
    const r = spawnSync(process.execPath, [f, root], { cwd: root, encoding: "utf8", timeout: 300000 });
    const line = `${r.stdout || ""}`.trim().split("\n").pop() || "{}";
    try { return JSON.parse(line); } catch { return { error: `unparseable: ${line.slice(0, 120)}` }; }
  } finally { fs.rmSync(f, { force: true }); }
}

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; console.log(`${c ? "PASS" : "FAIL"} ${n}${!c && d ? " — " + d : ""}`); };

const originals = new Map(ALL.map((r) => [r, fs.existsSync(abs(r)) ? fs.readFileSync(abs(r), "utf8") : null]));
const originalHashes = new Map([...originals].map(([r, v]) => [r, v === null ? "ABSENT" : sha256(v)]));
const restoreAll = () => {
  for (const [r, v] of originals) {
    if (v === null) fs.rmSync(abs(r), { force: true });
    else fs.writeFileSync(abs(r), v);
  }
};
const revert = (paths) => {
  for (const r of paths) {
    const pre = preD1(r);
    if (pre === null) fs.rmSync(abs(r), { force: true }); // new file -> absence
    else fs.writeFileSync(abs(r), pre);
  }
};

// ── Current (post-D1) state ────────────────────────────────────────────────
{
  const s = probe();
  ok("JR_CURRENT_PRODUCES_DEGRADED", s.produced === "degraded", `got ${s.produced}`);
  ok("JR_CURRENT_DEGRADED_CANNOT_VERIFY", s.degradedVerifies === false, `got ${s.degradedVerifies}`);
  ok("JR_CURRENT_CARRIER_PRESENT", s.carrier === true);
}

// ── FULL rollback — the only acceptable unit ───────────────────────────────
try {
  revert(ALL);
  const s = probe();
  ok("JR_FULL_ROLLBACK_RESTORES_PARTIAL", s.produced === "partial", `got ${s.produced}`);
  ok("JR_FULL_ROLLBACK_REMOVES_THE_CARRIER", s.carrier === false);
  // The pre-D1 world verifies a degraded scan — that IS the old I11A-C3 defect,
  // restored honestly. A rollback returns you to the prior contract, defect and
  // all; it must not silently keep half of the fix.
  ok("JR_FULL_ROLLBACK_RESTORES_PRE_D1_VERIFICATION_BEHAVIOUR", s.degradedVerifies === true, `got ${s.degradedVerifies}`);
  ok("JR_FULL_ROLLBACK_IS_COHERENT", s.error === null, String(s.error));
} finally { restoreAll(); }

// ── CONSUMER-ONLY rollback — must be REJECTED ──────────────────────────────
try {
  revert(CONSUMER);
  const s = probe();
  const unsafe = s.produced === "degraded" && s.degradedVerifies === true;
  ok("JR_CONSUMER_ONLY_ROLLBACK_IS_UNSAFE_AND_REJECTED", unsafe,
    `expected producer still degraded + verification re-opened; got produced=${s.produced} degradedVerifies=${s.degradedVerifies}`);
  console.log("     ^ rejected: re-opens the I11A-C3 defect on a status the producer still emits");
} finally { restoreAll(); }

// ── PRODUCER-ONLY rollback — must be REJECTED ──────────────────────────────
try {
  revert([...PRODUCER, CARRIER]);
  const s = probe();
  // MEASURED: this is stronger than "incoherent state". Reverting the producer
  // and carrier while keeping the consumer deletes a module `asm-cases.js` still
  // imports, so the consumer cannot even LOAD. The rejection is a hard module
  // resolution failure, not a subtle semantic drift — which is the most decisive
  // possible proof that the unit cannot be split.
  const hardFailure = typeof s.error === "string" && /Cannot find module|ERR_MODULE_NOT_FOUND/.test(s.error);
  ok("JR_PRODUCER_ONLY_ROLLBACK_IS_REJECTED_AS_A_HARD_LOAD_FAILURE", hardFailure,
    `expected the consumer to fail loading without the carrier; got error=${s.error} carrier=${s.carrier} produced=${s.produced}`);
  console.log("     ^ rejected: consumer imports the carrier the producer-only rollback deletes");
} finally { restoreAll(); }

// ── Exact restoration ──────────────────────────────────────────────────────
{
  let restored = true;
  for (const [r, want] of originalHashes) {
    const now = fs.existsSync(abs(r)) ? sha256(fs.readFileSync(abs(r), "utf8")) : "ABSENT";
    if (now !== want) { restored = false; console.log(`     not restored: ${r}`); }
  }
  ok("JR_ALL_BYTES_RESTORED_AFTER_EVERY_VARIANT", restored);
}

console.log(`\nD1 joint rollback: ${pass}/${pass + fail} assertions passed`);
if (fail > 0) { console.error("D1 joint rollback validation FAILED"); process.exit(1); }
console.log("D1 joint rollback validation passed — only the FULL unit is acceptable");
