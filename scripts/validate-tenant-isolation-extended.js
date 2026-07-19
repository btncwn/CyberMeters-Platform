#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-tenant-isolation-extended.js  (CI-blocking)
//
// Extends the base tenant-isolation matrix (validate-tenant-isolation.js) with
// three invariants it does not cover, driving the REAL Worker router against a
// REAL in-memory SQLite:
//
//   • Invariant 10 — SAME hostname in two workspaces remains isolated. The exact
//     same hostname (shared.example, and asset sub.shared.example) is seeded in
//     BOTH tenants; the tenant-B owner is denied on tenant-A's resources even
//     though they legitimately own the identical hostname in their own workspace,
//     and each owner sees only their own row (no cross-tenant merge).
//   • Invariant 5 (dynamic) — a REMOVED member (hard-deleted workspace_members
//     row) can read the workspace before removal and is denied after.
//   • Identity Exposure — foreign/anon denial on /identity-surfaces with an owner
//     positive control (flips the isolation matrix's identity_exposure coverage).
//
// Exits non-zero on any failure.
// ─────────────────────────────────────────────────────────────────────────────
import { loadWorker, buildDb, makeEnv, makeCaller, makeSeeder, leaks, denied } from "./security/lib/worker-harness.js";

let passed = 0, failed = 0, section = "General";
const results = [];
const sec = (s) => { section = s; };
const ok = (name, cond) => { cond ? (passed++, results.push(`PASS [${section}] ${name}`)) : (failed++, results.push(`FAIL [${section}] ${name}`)); };

async function main() {
  const mod = await loadWorker();
  const worker = mod.default;
  const db = buildDb();
  const env = makeEnv(db);
  const seed = await makeSeeder(db, mod);
  const call = makeCaller(worker, env, { debug: !!process.env.TENANT_DEBUG });

  // ── Two tenants, distinct owners ─────────────────────────────────────────
  seed.user("uA", "a@a.co", "OwnerA");
  seed.user("uB", "b@b.co", "OwnerB");
  seed.user("uGone", "gone@a.co", "RemovedMember");
  const T = { A: "raw-A", B: "raw-B", gone: "raw-gone" };
  await seed.session("sA", "uA", T.A);
  await seed.session("sB", "uB", T.B);
  await seed.session("sGone", "uGone", T.gone);
  seed.workspace("wsA", "uA", "AlphaWS-SECRET");
  seed.workspace("wsB", "uB", "BravoWS-SECRET");
  seed.member("mA", "wsA", "uA", "owner");
  seed.member("mB", "wsB", "uB", "owner");
  seed.member("mGone", "wsA", "uGone", "viewer"); // member of wsA, to be removed later

  // ── SAME hostname in BOTH workspaces ─────────────────────────────────────
  // Identical registrable domain + identical asset hostname seeded in each tenant.
  seed.raw("INSERT INTO domains (id, user_id, domain) VALUES ('dA','uA','shared.example')");
  seed.raw("INSERT INTO domains (id, user_id, domain) VALUES ('dB','uB','shared.example')");
  seed.raw("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('wsA','dA')");
  seed.raw("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('wsB','dB')");
  // Asset with the EXACT same hostname in both, distinct marker in asset_ref/case.
  const asset = (id, ws, dom) => seed.raw(`INSERT INTO workspace_assets (id, workspace_id, domain_id, hostname, asset_type, source, first_seen, last_seen, status, created_at, updated_at) VALUES ('${id}','${ws}','${dom}','sub.shared.example','subdomain','ct', datetime('now'), datetime('now'), 'active', datetime('now'), datetime('now'))`);
  asset("asA", "wsA", "dA");
  asset("asB", "wsB", "dB");
  // Managed case on the SAME domain in both, marker in asset_ref.
  const kase = (id, ws, ref) => seed.raw(`INSERT INTO managed_cases (id, workspace_id, case_type, domain, finding_id, asset_ref, severity, status, evidence_json, recommended_actions_json, created_at, updated_at) VALUES ('${id}','${ws}','asm_exposure','shared.example','admin_surface_high','${ref}','high','open','{}','[]',datetime('now'),datetime('now'))`);
  kase("caseA", "wsA", "REF-WSA-SECRET");
  kase("caseB", "wsB", "REF-WSB-SECRET");

  sec("Invariant 10 — same hostname, isolated tenants");
  // The tenant-B owner OWNS the identical hostname in wsB, yet must be denied on wsA.
  ok("B-owner denied wsA assets despite owning identical hostname in wsB",
     denied(await call("GET", "/api/workspaces/wsA/assets", T.B), "REF-WSA-SECRET") &&
     (await call("GET", "/api/workspaces/wsA/assets", T.B)).status >= 400);
  ok("B-owner denied wsA managed-cases (no REF-WSA leak)",
     denied(await call("GET", "/api/workspaces/wsA/managed-cases", T.B), "REF-WSA-SECRET"));
  ok("A-owner denied wsB managed-cases (no REF-WSB leak)",
     denied(await call("GET", "/api/workspaces/wsB/managed-cases", T.A), "REF-WSB-SECRET"));
  // Positive controls: each owner sees only their OWN same-hostname resources —
  // proving the two identical-hostname rows coexist and did not merge.
  const aCases = await call("GET", "/api/workspaces/wsA/managed-cases", T.A);
  const bCases = await call("GET", "/api/workspaces/wsB/managed-cases", T.B);
  ok("A-owner sees wsA's own case (REF-WSA present)", leaks(aCases, "REF-WSA-SECRET"));
  ok("A-owner does NOT see wsB's case (REF-WSB absent) though same hostname", !JSON.stringify(aCases.data ?? "").includes("REF-WSB-SECRET"));
  ok("B-owner sees wsB's own case (REF-WSB present)", leaks(bCases, "REF-WSB-SECRET"));
  ok("B-owner does NOT see wsA's case (REF-WSA absent) though same hostname", !JSON.stringify(bCases.data ?? "").includes("REF-WSA-SECRET"));

  sec("Invariant 5 — removed membership revokes access");
  // Before removal, uGone (viewer of wsA) can read wsA.
  ok("member can read wsA before removal", leaks(await call("GET", "/api/workspaces/wsA", T.gone), "AlphaWS-SECRET"));
  seed.removeMember("wsA", "uGone");
  // After removal, the SAME session token must no longer authorize.
  ok("removed member cannot read wsA after removal", denied(await call("GET", "/api/workspaces/wsA", T.gone), "AlphaWS-SECRET"));
  ok("removed member cannot read wsA assets after removal", denied(await call("GET", "/api/workspaces/wsA/assets", T.gone), "REF-WSA-SECRET"));
  ok("removed member cannot write to wsA after removal",
     [401, 403, 404].includes((await call("POST", "/api/workspaces/wsA/domains", T.gone, { domain: "evil.example" })).status));
  // Existence oracle preserved: removed-member vs nonexistent workspace look alike.
  ok("removed member: real-ws and fake-ws return same status class",
     (await call("GET", "/api/workspaces/wsA", T.gone)).status === (await call("GET", "/api/workspaces/ws_nope", T.gone)).status);

  sec("Identity Exposure — foreign/anon denial with owner positive control");
  ok("owner CAN read own identity-surfaces (200)", (await call("GET", "/api/workspaces/wsA/identity-surfaces", T.A)).status === 200);
  ok("foreign cannot read wsA identity-surfaces", [401, 403, 404].includes((await call("GET", "/api/workspaces/wsA/identity-surfaces", T.B)).status));
  ok("anon cannot read wsA identity-surfaces", [401, 403, 404].includes((await call("GET", "/api/workspaces/wsA/identity-surfaces", null)).status));

  // ── Report ───────────────────────────────────────────────────────────────
  const bySec = {};
  for (const line of results) { const s = line.match(/\[(.*?)\]/)[1]; (bySec[s] ??= { p: 0, f: 0 })[line.startsWith("PASS") ? "p" : "f"]++; }
  console.log("\nExtended tenant-isolation matrix:");
  for (const [s, c] of Object.entries(bySec)) console.log(`  ${c.f ? "✗" : "✓"} ${s}: ${c.p}/${c.p + c.f}`);
  if (failed) { console.log("\nFailures:"); for (const r of results.filter((r) => r.startsWith("FAIL"))) console.log("  " + r); }
  console.log(`\nExtended tenant isolation: ${passed}/${passed + failed} passed`);
  if (failed) { console.error("extended tenant-isolation validation FAILED"); process.exit(1); }
  console.log("extended tenant-isolation validation passed");
}

main().catch((e) => { console.error("extended tenant-isolation runner crashed:", e); process.exit(1); });
