#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-authz-properties.js  (CI-blocking)
//
// Property-based authorization testing against the REAL Worker router. No heavy
// framework — a deterministic Mulberry32 PRNG generates combinations across
// {actor, membership status, workspace deleted-state, route, operation, target
// (own / foreign-real / nonexistent / guessed), same/different hostname}. Every
// generated actor LACKS current access to the target workspace, so the oracle is
// uniform and unambiguous:
//
//   CANONICAL PROPERTY — for every user U and tenant-owned resource R, if U lacks
//   current authorised access to R.workspace_id, no operation may disclose,
//   mutate, resolve, remove, score, report, alert on, or otherwise influence R.
//
// Each case asserts: (a) the response is denied (401/403/404, or a 2xx that
// carries no private marker); (b) foreign-real and nonexistent are the same status
// class (no existence oracle); (c) after the full run, no tenant-owned resource in
// the protected workspace was mutated (write attempts changed nothing).
//
// The CI seed is fixed and printed; a failing case prints its seed + tuple for
// deterministic reproduction. Runs PROP_CASES (default 500) cases.
// ─────────────────────────────────────────────────────────────────────────────
import { loadWorker, buildDb, makeEnv, makeCaller, makeSeeder, leaks } from "./security/lib/worker-harness.js";
import { createHash } from "node:crypto";

function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const SEED = process.env.PROP_SEED ? Number(process.env.PROP_SEED) : 0x0C1A55E5;
const CASES = process.env.PROP_CASES ? Number(process.env.PROP_CASES) : 500;

// Read route templates. :ws → target workspace, :rid → target resource.
// mode "marker" — the owner leaks a private marker; a foreign 2xx carrying it is a
//                 real disclosure (non-vacuous). Owner positive control asserts leak.
// mode "status" — the route does not echo a marker; a foreign response must be a
//                 strict 4xx (owner positive control asserts 200).
const READ_ROUTES = [
  { m: "GET", t: "/api/workspaces/:ws", marker: "MainWS-SECRET", mode: "marker" },
  { m: "GET", t: "/api/workspaces/:ws/assets", marker: "asset-SECRET", mode: "marker" },
  { m: "GET", t: "/api/workspaces/:ws/managed-cases", marker: "CASE-SECRET", mode: "marker" },
  { m: "GET", t: "/api/workspaces/:ws/cases", marker: "CASE-SECRET", mode: "marker" },
  { m: "GET", t: "/api/workspaces/:ws/notifications", marker: "notif-SECRET", mode: "marker" },
  { m: "GET", t: "/api/workspaces/:ws/members", marker: "main@a.co", mode: "marker" },
  { m: "GET", t: "/api/scans/:rid/report", marker: "R2-MARKER", mode: "marker", resource: true, ridOwn: "servedScan" },
  { m: "GET", t: "/api/workspaces/:ws/scorecard", mode: "status" },
  { m: "GET", t: "/api/workspaces/:ws/certificates", mode: "status" },
  { m: "GET", t: "/api/workspaces/:ws/identity-surfaces", mode: "status" },
  { m: "GET", t: "/api/workspaces/:ws/report-snapshots", mode: "status" },
];
const WRITE_ROUTES = [
  { m: "PATCH", t: "/api/workspaces/:ws", body: { name: "HIJACKED" } },
  { m: "POST", t: "/api/workspaces/:ws/domains", body: { domain: "evil.example" } },
  { m: "POST", t: "/api/workspaces/:ws/delete-request", body: {} },
  { m: "POST", t: "/api/workspaces/:ws/managed-cases/:rid/assign", body: { owner_ref: "x", owner_type: "team" }, resource: true },
  { m: "POST", t: "/api/workspaces/:ws/members", body: { email: "x@x.co", role: "admin" } },
];

let passed = 0, failed = 0;
const failures = [];

async function main() {
  const rnd = mulberry32(SEED);
  const pick = (arr) => arr[Math.floor(rnd() * arr.length)];
  const mod = await loadWorker();
  const worker = mod.default;
  const db = buildDb();
  const env = makeEnv(db);
  const seed = await makeSeeder(db, mod);
  const call = makeCaller(worker, env, { debug: !!process.env.PROP_DEBUG });

  // ── Universe ──────────────────────────────────────────────────────────────
  for (const [id, email] of [["uMain", "main@a.co"], ["uForeign", "f@b.co"], ["uNobody", "n@c.co"], ["uRemoved", "r@a.co"], ["uDeadOwner", "d@a.co"]]) seed.user(id, email);
  const TOK = { uMain: "t-main", uForeign: "t-foreign", uNobody: "t-nobody", uRemoved: "t-removed", uDeadOwner: "t-dead" };
  for (const [uid, raw] of Object.entries(TOK)) await seed.session("s-" + uid, uid, raw);
  seed.workspace("wsMain", "uMain", "MainWS-SECRET");
  seed.workspace("wsForeign", "uForeign", "ForeignWS");
  seed.workspace("wsDead", "uDeadOwner", "DeadWS-SECRET", true);
  seed.member("m1", "wsMain", "uMain", "owner");
  seed.member("m2", "wsForeign", "uForeign", "owner");
  seed.member("m3", "wsDead", "uDeadOwner", "owner");
  seed.member("m4", "wsMain", "uRemoved", "viewer");
  seed.removeMember("wsMain", "uRemoved"); // uRemoved: was a member, now removed

  // Protected resources in wsMain (all carry a private marker).
  seed.raw("INSERT INTO domains (id, user_id, domain) VALUES ('dMain','uMain','shared.example')");
  seed.raw("INSERT INTO domains (id, user_id, domain) VALUES ('dForeign','uForeign','shared.example')"); // same hostname, other tenant
  seed.raw("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('wsMain','dMain')");
  seed.raw("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('wsForeign','dForeign')");
  seed.raw("INSERT INTO workspace_assets (id, workspace_id, domain_id, hostname, asset_type, source, first_seen, last_seen, status, created_at, updated_at) VALUES ('aMain','wsMain','dMain','asset-SECRET.example','subdomain','ct',datetime('now'),datetime('now'),'active',datetime('now'),datetime('now'))");
  seed.raw("INSERT INTO managed_cases (id, workspace_id, case_type, domain, finding_id, asset_ref, severity, status, evidence_json, recommended_actions_json, created_at, updated_at) VALUES ('cMain','wsMain','asm_exposure','shared.example','admin_surface_high','CASE-SECRET.example','high','open','{}','[]',datetime('now'),datetime('now'))");
  seed.raw("INSERT INTO notification_events (id, workspace_id, user_id, type, severity, title, message, status) VALUES ('nMain','wsMain',NULL,'scan','info','notif-SECRET','m','unread')");
  // Scan id contains "served" so the harness R2 stub serves reports/servedScan.json.
  seed.raw("INSERT INTO scans (id, workspace_id, domain_id, domain, score, rating, status, created_at) VALUES ('servedScan','wsMain','dMain','shared.example',80,'good','completed',datetime('now'))");
  // A completed lifecycle row is not report readiness. Seed the canonical
  // checksum-gated snapshot so the owner positive control remains non-vacuous
  // under the A1 availability contract.
  const snapshotBody = JSON.stringify({
    snapshot: { snapshot_schema_version: "1" },
    marker: "R2-MARKER",
  });
  const snapshotChecksum = createHash("sha256").update(snapshotBody).digest("hex");
  seed.raw(
    `INSERT INTO scan_report_snapshots
       (id,workspace_id,domain_id,scan_id,status,r2_key,checksum_sha256,
        snapshot_schema_version,resolver_version,assessed_at,completed_at)
     VALUES ('servedSnapshot','wsMain','dMain','servedScan','completed',
             'reports/snapshots/wsMain/servedScan/served.json',?,'1','test',
             datetime('now'),datetime('now'))`,
    snapshotChecksum,
  );

  // ── Positive controls (anti-tautology) ─────────────────────────────────────
  // Every marker route must LEAK its marker for the owner (else "no leak" is
  // vacuous); every status route must return 200 for the owner (else "foreign 4xx"
  // is vacuous). A failed control fails the suite.
  const okc = (n, c) => { c ? passed++ : (failed++, failures.push(`CONTROL ${n}`)); };
  for (const r of READ_ROUTES) {
    const rid = r.ridOwn || "servedScan";
    const p = r.t.replace(":ws", "wsMain").replace(":rid", rid);
    const resp = await call(r.m, p, TOK.uMain);
    if (r.mode === "marker") okc(`owner leaks ${r.marker} on ${r.t}`, leaks(resp, r.marker));
    else okc(`owner gets 200 on ${r.t}`, resp.status === 200);
  }

  // ── Property generation ─────────────────────────────────────────────────────
  const ACTORS = [
    { name: "foreign", tok: TOK.uForeign }, { name: "nobody", tok: TOK.uNobody },
    { name: "removed", tok: TOK.uRemoved }, { name: "deadOwner", tok: TOK.uDeadOwner },
    { name: "anon", tok: null },
  ];
  // Every actor lacks access to the target ws (deadOwner only owns a DELETED ws).
  const WS_TARGETS = ["wsMain", "wsDead", "ws_nonexistent_"];
  const RID_TARGETS = ["servedScan", "cMain", "rid_nonexistent"];
  const guessId = () => "gid_" + Math.floor(rnd() * 1e6).toString(36);

  for (let i = 0; i < CASES; i++) {
    const isWrite = rnd() < 0.4;
    const route = isWrite ? pick(WRITE_ROUTES) : pick(READ_ROUTES);
    const actor = pick(ACTORS);
    let ws = pick([...WS_TARGETS, guessId()]);
    if (ws === "ws_nonexistent_") ws = "ws_none_" + guessId();
    let rid = pick([...RID_TARGETS, guessId()]);
    let pathname = route.t.replace(":ws", ws).replace(":rid", rid);
    const resp = await call(route.m, pathname, actor.tok, route.body);

    // Property: an unauthorized actor must be DENIED. For marker routes, denial =
    // a 4xx OR a 2xx that does not carry the private marker. For status/write
    // routes (no reflected marker), denial must be a strict 4xx — a 2xx would be a
    // real unauthorized success.
    let isDenied;
    if (route.mode === "marker") {
      isDenied = [400, 401, 403, 404, 429].includes(resp.status) || !leaks(resp, route.marker);
    } else {
      isDenied = [400, 401, 403, 404, 429].includes(resp.status);
    }
    if (isDenied) passed++;
    else { failed++; failures.push(`seed=${SEED} case#${i} ${actor.name} ${route.m} ${pathname} → ${resp.status} UNAUTHORIZED SUCCESS`); }

    // Existence-oracle: foreign real-ws vs nonexistent-ws same status class (reads).
    if (!isWrite && route.t.includes(":ws") && actor.tok) {
      const real = await call(route.m, route.t.replace(":ws", "wsMain").replace(":rid", rid), actor.tok);
      const fake = await call(route.m, route.t.replace(":ws", "ws_none_" + guessId()).replace(":rid", rid), actor.tok);
      const sameClass = Math.floor(real.status / 100) === Math.floor(fake.status / 100) || (real.status >= 400 && fake.status >= 400);
      if (sameClass) passed++;
      else { failed++; failures.push(`seed=${SEED} case#${i} existence-oracle ${actor.name} ${route.t}: real=${real.status} fake=${fake.status}`); }
    }
  }

  // ── Post-run: no protected resource was mutated by any write attempt ─────────
  const wsRow = db.prepare("SELECT name FROM workspaces WHERE id='wsMain'").get();
  okc("wsMain name unchanged after all foreign write attempts", wsRow && wsRow.name === "MainWS-SECRET");
  const caseRow = db.prepare("SELECT status FROM managed_cases WHERE id='cMain'").get();
  okc("wsMain managed_case status unchanged", caseRow && caseRow.status === "open");
  const domCount = db.prepare("SELECT COUNT(*) AS n FROM workspace_domains WHERE workspace_id='wsMain'").get();
  okc("wsMain domain count unchanged (no foreign domain add)", domCount && domCount.n === 1);
  const memberCount = db.prepare("SELECT COUNT(*) AS n FROM workspace_members WHERE workspace_id='wsMain'").get();
  okc("wsMain member count unchanged (no foreign member add)", memberCount && memberCount.n === 1); // only uMain (uRemoved deleted)

  // ── Report ───────────────────────────────────────────────────────────────
  console.log("Property-based authorization suite:");
  console.log(`  seed: 0x${SEED.toString(16)}   cases: ${CASES}`);
  console.log(`  assertions: ${passed + failed}   passed: ${passed}   failed: ${failed}`);
  if (failed) {
    console.log("\nFailing properties (first 20):");
    for (const f of failures.slice(0, 20)) console.log("  ✗ " + f);
    console.error(`\nauthz property validation FAILED — reproduce with PROP_SEED=${SEED}`);
    process.exit(1);
  }
  console.log("authz property validation passed");
}

main().catch((e) => { console.error("authz property runner crashed:", e); process.exit(1); });
