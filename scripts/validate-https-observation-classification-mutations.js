#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-https-observation-classification-mutations.js  (CI-blocking)
//
// Mutation proof for PR-A. Each assertion in
// validate-https-observation-classification.js is only worth what it FAILS on, so
// each guard here is deliberately reintroduced as a defect and must be caught.
//
// C6 discipline (three separate protections, because a mutation harness that
// silently stops mutating is worse than none):
//   1. every mutation asserts `mutated !== original` — a no-op anchor is a FAILURE,
//      not a skip, so a behaviour-preserving refactor of the product source
//      reddens CI instead of quietly voiding the proof;
//   2. EXPECTED_MUTANTS is PINNED — a dropped or skipped mutant hard-fails even if
//      every remaining one passes;
//   3. mutants are written BESIDE their originals (so relative imports resolve)
//      and removed in a `finally`, never left behind.
//
// The mutated copy of a DEPENDENCY is paired with a rewritten copy of its importer,
// because mutating lib/fetch-observation.js into a temp file would otherwise leave
// ssl-scan.js importing the pristine original — the mutation would no-op silently.
// Node 24+.
// ─────────────────────────────────────────────────────────────────────────────
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const SRC = path.join(ROOT, "workers", "scan-api", "src");
const ENG = path.join(SRC, "engines");
const LIB = path.join(SRC, "lib");
const FETCHOBS = path.join(LIB, "fetch-observation.js");
const SSL = path.join(ENG, "ssl-scan.js");
const ASSET = path.join(ENG, "asset-intel.js");

// PINNED. Adding a mutation without raising this, or losing one, hard-fails.
const EXPECTED_MUTANTS = 9;

let pass = 0, fail = 0, killed = 0;
const ok = (name, cond, detail = "") => {
  cond ? pass++ : fail++;
  console.log(`${cond ? "ok  " : "FAIL"} - ${name}${!cond && detail ? ` -- ${detail}` : ""}`);
};

const realFetch = globalThis.fetch;
const originResponse = (status) =>
  new Response("body", { status, headers: { "content-type": "text/html", server: "nginx" } });
const edgeResponse = (status) =>
  new Response("error page", { status, headers: { "content-type": "text/html", server: "cloudflare" } });
const noCt = { get: async () => null, set: async () => {} };

let seq = 0;
/**
 * Write a mutated copy of `targetPath` beside the original. When the target is a
 * dependency, also write a copy of `entryPath` whose import points at the mutant,
 * and import THAT. Returns { applied, mod } — `applied:false` means the anchor did
 * not match, which every caller treats as a failure.
 */
async function withMutant({ target, entry = null, from, to }, run) {
  const original = fs.readFileSync(target, "utf8");
  const mutated = original.replace(from, to);
  if (mutated === original) return { applied: false, mod: null };
  const n = `${process.pid}.${++seq}`;
  const mutantName = `.${path.basename(target, ".js")}.mutant.${n}.js`;
  const mutantFile = path.join(path.dirname(target), mutantName);
  const written = [mutantFile];
  fs.writeFileSync(mutantFile, mutated);
  let importTarget = mutantFile;
  try {
    if (entry) {
      const entrySrc = fs.readFileSync(entry, "utf8");
      const relOriginal = `../${path.basename(path.dirname(target))}/${path.basename(target)}`;
      const relMutant = `../${path.basename(path.dirname(target))}/${mutantName}`;
      if (!entrySrc.includes(relOriginal)) return { applied: false, mod: null };
      const entryName = `.${path.basename(entry, ".js")}.mutant.${n}.js`;
      const entryFile = path.join(path.dirname(entry), entryName);
      fs.writeFileSync(entryFile, entrySrc.split(relOriginal).join(relMutant));
      written.push(entryFile);
      importTarget = entryFile;
    }
    const mod = await import(`${pathToFileURL(importTarget).href}?t=${Date.now()}-${Math.random()}`);
    return { applied: true, mod, run: await run(mod) };
  } finally {
    for (const f of written) fs.rmSync(f, { force: true });
  }
}

// CT lookups share the mocked fetch and log their own (internally caught, non-fatal)
// parse failures to stderr. Suppress that benign noise so CI output stays readable —
// CT is independent of reachability and is not what these suites assert.
async function sslWith(mod, fetchImpl) {
  globalThis.fetch = fetchImpl;
  const err = console.error; console.error = () => {};
  try { return await mod.runSslModule("example.com", { ctCache: noCt }); }
  finally { globalThis.fetch = realFetch; console.error = err; }
}

// Each mutant: reintroduce the defect, then assert the harmful OUTPUT reappears.
// `applied` is asserted separately so a stale anchor can never masquerade as a kill.
const MUTATIONS = [
  {
    // Restored at the single point that now governs BOTH the bare-domain and the
    // www fallback. Mutating only the bare-domain rule is NOT a faithful
    // reintroduction: the www fallback would still consult the correct classifier
    // and silently mask the defect (this mutant survived until that was fixed).
    name: "M1 the old `status < 500` rule is restored → origin 500 falsely not-available",
    target: FETCHOBS, entry: SSL,
    from: "    transport_observed: true,\n    origin_status:      status,",
    to:   "    transport_observed: status < 500 ? true : null,\n    origin_status:      status,",
    // With the old rule a genuine origin 500 stops proving transport.
    check: async (mod) => (await sslWith(mod, async () => originResponse(500))).https_available !== true,
  },
  {
    name: "M2 a genuine origin 500 is classified transport_unavailable",
    target: FETCHOBS, entry: SSL,
    from: "  // Rule A: any origin status proves transport, including 5xx.\n  return {\n    state:              FETCH_OBSERVATION_STATES.ORIGIN_RESPONSE,",
    to:   "  // Rule A: any origin status proves transport, including 5xx.\n  if (status >= 500) return { state: FETCH_OBSERVATION_STATES.TRANSPORT_UNAVAILABLE, reason: \"mutant\", completeness: \"unavailable\", probe_executed: true, transport_observed: null, origin_status: null };\n  return {\n    state:              FETCH_OBSERVATION_STATES.ORIGIN_RESPONSE,",
    check: async (mod) => (await sslWith(mod, async () => originResponse(500))).https_available !== true,
  },
  {
    name: "M3 a Cloudflare-signed 522 is treated as a genuine origin response",
    target: FETCHOBS, entry: SSL,
    from: "  if (isCloudflareEdgeSynthesised(status, headerOf(response, \"server\"))) {",
    to:   "  if (false) {",
    // The edge error would then PROVE transport — attributing the edge to the origin.
    check: async (mod) => (await sslWith(mod, async () => edgeResponse(522))).https_available === true,
  },
  {
    name: "M4 executed-but-inconclusive collapses into not_assessed (Rule B broken)",
    target: FETCHOBS, entry: SSL,
    from: "      state:              FETCH_OBSERVATION_STATES.TRANSPORT_UNAVAILABLE,",
    to:   "      state:              FETCH_OBSERVATION_STATES.NOT_ASSESSED,",
    check: async (mod) => {
      const m = await sslWith(mod, async () => { throw new TypeError("refused"); });
      return m.https_observation_state === "not_assessed";
    },
  },
  {
    name: "M5 ssl-scan bypasses the SHARED classifier (proves the class fix, not one caller)",
    target: SSL,
    from: "  const bareObservation = classifyFetchObservation({ response: httpsRes });",
    to:   "  const bareObservation = { state: httpsRes ? \"origin_response\" : \"transport_unavailable\", reason: \"local\", completeness: \"observed\", probe_executed: true, transport_observed: httpsRes && httpsRes.status < 500 ? true : null, origin_status: httpsRes ? httpsRes.status : null };",
    // A local re-implementation reintroduces the edge/5xx confusion the shared
    // classifier exists to prevent.
    check: async (mod) => {
      const edge = await sslWith(mod, async () => edgeResponse(522));
      const five = await sslWith(mod, async () => originResponse(500));
      return edge.https_observation_state === "origin_response" || five.https_available !== true;
    },
  },
  {
    name: "M6 the edge signature requirement is dropped → unsigned 530 falsely excused",
    target: FETCHOBS, entry: SSL,
    from: "    String(server || \"\").trim().toLowerCase() === \"cloudflare\";",
    to:   "    true;",
    check: async (mod) => {
      const m = await sslWith(mod, async () =>
        new Response("x", { status: 530, headers: { server: "some-origin" } }));
      // Without the signature check an ORIGIN's own 530 stops proving transport.
      return m.https_available !== true;
    },
  },
  {
    // PR-A1 P1 — the false-healthy half. Gating incompleteness on EXECUTION rather
    // than EVIDENCE is what let a Cloudflare edge error finalize `complete` and
    // publish "Assessed — no material issue observed".
    name: "M7 module incompleteness is gated on probe EXECUTION again, not on evidence",
    target: SSL,
    // PR-A2 re-point: the gate now also requires observed redirect evidence
    // (`httpsAvailable === true && redirectEvidenceObserved`). Re-gating it on mere
    // probe EXECUTION must still be caught.
    from: "    ...((httpsAvailable === true && redirectEvidenceObserved) ? {} : {",
    to:   "    ...((httpsProbeExecuted) ? {} : {",
    check: async (mod) => {
      const m = await sslWith(mod, async () => edgeResponse(522));
      return m.incomplete !== true;   // edge error would stop marking the module incomplete
    },
  },
  {
    name: "M8 the inclusive 520–530 Cloudflare range is restored (528/529 wrongly excused)",
    target: FETCHOBS, entry: SSL,
    from: "  const inEdgeSet = (code >= CF_EDGE_STATUS_MIN && code <= CF_EDGE_STATUS_MAX) ||\n    code === CF_EDGE_STATUS_EXTRA;",
    to:   "  const inEdgeSet = code >= CF_EDGE_STATUS_MIN && code <= 530;",
    check: async (mod) => {
      const m = await sslWith(mod, async () => edgeResponse(528));
      // A signed 528 is a genuine origin answer; under the inclusive range it is
      // excused as an edge error and stops proving transport.
      return m.https_available !== true;
    },
  },
  {
    name: "M9 aggregate discards the sibling endpoint's more informative reason",
    target: FETCHOBS, entry: SSL,
    from: "  for (const state of AGGREGATE_PRECEDENCE) {",
    to:   "  for (const state of []) {",
    check: async (mod) => {
      // bare timeout + www edge error: precedence must surface the edge reason.
      let call = 0;
      const m = await sslWith(mod, async () => {
        call += 1;
        if (call === 1) throw new TypeError("bare timeout");
        return edgeResponse(522);
      });
      return m.https_observation_state !== "cloudflare_edge_error";
    },
  },
];

console.log("── PR-A mutation proof ──");
for (const m of MUTATIONS) {
  const r = await withMutant(m, (mod) => m.check(mod));
  ok(`${m.name} :: mutation APPLIED (anchor still matches the product source)`, r.applied,
    "anchor not found — the mutation tests NOTHING; re-point it at the current source");
  if (!r.applied) continue;
  const caught = r.run === true;
  if (caught) killed++;
  ok(`${m.name} :: defect REAPPEARS when mutated (the guard is load-bearing)`, caught);
}

// Pinned-count gate — a dropped or skipped mutant fails even if every other passes.
ok(`mutants killed: ${killed}/${EXPECTED_MUTANTS} (pinned)`, killed === EXPECTED_MUTANTS,
  `expected exactly ${EXPECTED_MUTANTS}, killed ${killed}`);
ok(`mutation table length is pinned at ${EXPECTED_MUTANTS}`, MUTATIONS.length === EXPECTED_MUTANTS,
  `table has ${MUTATIONS.length}`);

// No mutant may survive into the working tree.
const strays = [
  ...fs.readdirSync(ENG).filter((f) => f.includes(".mutant.")),
  ...fs.readdirSync(LIB).filter((f) => f.includes(".mutant.")),
];
ok("no mutant file left behind in the source tree", strays.length === 0, strays.join(", "));

console.log(`\nhttps-observation-classification-mutations: ${pass}/${pass + fail} passed; ${killed}/${EXPECTED_MUTANTS} mutants killed`);
if (fail) { console.error("https-observation-classification-mutations validation FAILED"); process.exit(1); }
console.log("https-observation-classification-mutations validation passed");
