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
//   • Scan authority — POST /api/scan refuses a foreign workspace named in the
//     body, a viewer, a member downgraded or removed THROUGH THE ROUTE (same live
//     session), and an unverified domain; none of them leaves a scan row or links
//     a domain into the victim workspace.
//   • Membership, report download, session revocation and related-change linking
//     across tenants — a foreign id is refused exactly like a nonexistent one, a
//     cross-tenant report id never reaches storage, and a revoked device's token
//     stops working on its next request.
//
// Every denial has a positive control beside it, so no refusal can be vacuous.
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

  // ── Router-level authority: who may start a scan, and for which workspace ──
  // Every check below goes through the real router with a real session token.
  // A positive control sits beside each denial so a 403 can never be vacuous
  // (e.g. every caller refused for an unrelated reason).
  seed.user("uView", "view@a.co", "ViewerA");
  seed.user("uAna", "ana@a.co", "AnalystA");
  seed.user("uDown", "down@a.co", "DowngradedA");
  seed.user("uKick", "kick@a.co", "RouteRemovedA");
  Object.assign(T, { view: "raw-view", ana: "raw-ana", down: "raw-down", kick: "raw-kick", A2: "raw-A2" });
  await seed.session("sView", "uView", T.view);
  await seed.session("sAna", "uAna", T.ana);
  await seed.session("sDown", "uDown", T.down);
  await seed.session("sKick", "uKick", T.kick);
  await seed.session("sA2", "uA", T.A2); // owner A's second device
  seed.member("mView", "wsA", "uView", "viewer");
  seed.member("mAna", "wsA", "uAna", "analyst");
  seed.member("mDown", "wsA", "uDown", "analyst");
  seed.member("mKick", "wsA", "uKick", "analyst");
  // wsA's billing owner holds an active plan, so a permitted caller is stopped by
  // the domain-ownership gate — not by billing — and the positive control is real.
  db.prepare(`INSERT INTO subscriptions (id, owner_user_id, plan, subscription_status, status, current_period_end, created_at, updated_at)
              VALUES ('subA','uA','professional','active','active',datetime('now','+30 days'),datetime('now'),datetime('now'))`).run();

  const count = (sql, ...a) => db.prepare(sql).get(...a).n;
  const scanRows = () => count("SELECT COUNT(*) AS n FROM scans");
  const wsALinks = () => count("SELECT COUNT(*) AS n FROM workspace_domains WHERE workspace_id = 'wsA'");
  const ROLE_DENIED = "Forbidden — analyst role required to create scans";
  // A syntactically valid public name: reserved TLDs (.example) are refused as
  // "Invalid domain" BEFORE any authority check, which would make every denial
  // below vacuous. Nothing is ever fetched — no request here reaches the engine.
  const SCAN_DOMAIN = "cybermeters-tenant-test.com";
  const scanInA = (token) => call("POST", "/api/scan", token, { domain: SCAN_DOMAIN, workspace_id: "wsA" });
  // Past the role gate means the request reached the LATER domain-ownership gate
  // — and stopped there, because nothing in wsA is verified.
  const pastRoleGate = (r) => r.status === 403 && r.data?.error === "domain_verification_required";

  sec("Scan authority — tenant and role gates on POST /api/scan");
  const scans0 = scanRows(), links0 = wsALinks();
  const foreignScan = await scanInA(T.B);
  ok("foreign owner naming wsA in the body → 403", foreignScan.status === 403 && foreignScan.data?.error === ROLE_DENIED);
  ok("foreign attempt created no scan row", scanRows() === scans0);
  ok("foreign attempt linked no domain into wsA", wsALinks() === links0);
  ok("foreign attempt leaks nothing about wsA", !foreignScan.text.includes("AlphaWS-SECRET"));
  const nopeScan = await call("POST", "/api/scan", T.B, { domain: SCAN_DOMAIN, workspace_id: "ws_nope" });
  ok("foreign wsA and nonexistent workspace refuse identically", nopeScan.status === foreignScan.status && nopeScan.text === foreignScan.text);

  const viewerScan = await scanInA(T.view);
  ok("viewer naming wsA → 403 role refusal", viewerScan.status === 403 && viewerScan.data?.error === ROLE_DENIED);
  const viewerAuto = await call("POST", "/api/scan", T.view, { domain: SCAN_DOMAIN });
  ok("viewer with no workspace named → 403 (no workspace silently chosen)", viewerAuto.status === 403);
  ok("viewer attempts created no scan row", scanRows() === scans0);

  const analystScan = await scanInA(T.ana);
  ok("positive control: analyst passes the role gate", pastRoleGate(analystScan));
  ok("unverified domain: analyst's request still created no scan row", scanRows() === scans0);

  sec("Role downgrade and route removal take effect on the same session");
  ok("before downgrade: analyst passes the role gate", pastRoleGate(await scanInA(T.down)));
  const downgrade = await call("PATCH", "/api/workspaces/wsA/members/mDown", T.A, { role: "viewer" });
  ok("owner downgrades analyst → viewer (200)", downgrade.status === 200 && downgrade.data?.role === "viewer");
  const afterDown = await scanInA(T.down);
  ok("downgraded member's existing session → 403 role refusal", afterDown.status === 403 && afterDown.data?.error === ROLE_DENIED);
  ok("downgraded member can still read wsA (viewer)", leaks(await call("GET", "/api/workspaces/wsA", T.down), "AlphaWS-SECRET"));

  ok("before removal: member reads wsA", leaks(await call("GET", "/api/workspaces/wsA", T.kick), "AlphaWS-SECRET"));
  const removal = await call("DELETE", "/api/workspaces/wsA/members/mKick", T.A);
  ok("owner removes member through the route (200)", removal.status === 200);
  ok("removed member's existing session cannot read wsA", denied(await call("GET", "/api/workspaces/wsA", T.kick), "AlphaWS-SECRET"));
  ok("removed member's existing session cannot start a scan in wsA", (await scanInA(T.kick)).status === 403);
  ok("removed member: wsA and nonexistent workspace look alike",
     (await call("GET", "/api/workspaces/wsA", T.kick)).status === (await call("GET", "/api/workspaces/ws_nope", T.kick)).status);
  ok("still no scan row after all role/tenant refusals", scanRows() === scans0);

  sec("Membership changes — foreign owner cannot act on wsA members");
  const memberRow = (id) => db.prepare("SELECT role FROM workspace_members WHERE id = ?").get(id);
  ok("foreign owner DELETE on wsA member → 403", (await call("DELETE", "/api/workspaces/wsA/members/mView", T.B)).status === 403);
  ok("foreign owner PATCH on wsA member → 403", (await call("PATCH", "/api/workspaces/wsA/members/mView", T.B, { role: "admin" })).status === 403);
  ok("foreign owner using own workspace path with wsA member id → 404",
     (await call("DELETE", "/api/workspaces/wsB/members/mView", T.B)).status === 404 &&
     (await call("PATCH", "/api/workspaces/wsB/members/mView", T.B, { role: "admin" })).status === 404);
  ok("wsA member untouched by every foreign attempt", memberRow("mView")?.role === "viewer");
  ok("viewer cannot change roles in own workspace (403)", (await call("PATCH", "/api/workspaces/wsA/members/mAna", T.view, { role: "viewer" })).status === 403 && memberRow("mAna")?.role === "analyst");

  sec("Report download — cross-tenant id never reaches storage");
  db.prepare("INSERT INTO workspace_reports (id, workspace_id, report_type, report_period, report_key, status, generated_at) VALUES ('rptA','wsA','manual','manual-A','reports/served-wsA.pdf','completed',datetime('now'))").run();
  const r2Get = env.cybermeters_reports.get;
  const r2Keys = [];
  env.cybermeters_reports.get = async (key, ...rest) => { r2Keys.push(String(key)); return r2Get(key, ...rest); };
  const ownDl = await call("GET", "/api/workspaces/wsA/reports/rptA/download", T.A);
  ok("positive control: owner downloads own report (200, served from storage)", ownDl.status === 200 && ownDl.text.includes("R2-MARKER"));
  r2Keys.length = 0;
  const crossDl = await call("GET", "/api/workspaces/wsB/reports/rptA/download", T.B);
  const fakeDl = await call("GET", "/api/workspaces/wsB/reports/rpt_nope/download", T.B);
  ok("foreign owner, own workspace path + wsA report id → 404", crossDl.status === 404);
  ok("cross-tenant report id and nonexistent id answer identically", crossDl.status === fakeDl.status && crossDl.text === fakeDl.text);
  const directDl = await call("GET", "/api/workspaces/wsA/reports/rptA/download", T.B);
  ok("foreign owner on wsA path → 403, no file", directDl.status === 403 && !directDl.text.includes("R2-MARKER"));
  ok("foreign wsA path and nonexistent workspace answer identically",
     directDl.status === (await call("GET", "/api/workspaces/ws_nope/reports/rptA/download", T.B)).status);
  ok("no foreign request read storage at all", r2Keys.length === 0);
  ok("foreign owner cannot read wsA report metadata through wsB", (await call("GET", "/api/workspaces/wsB/reports/rptA", T.B)).status === 404);
  env.cybermeters_reports.get = r2Get;

  sec("Session revocation — a revoked device loses access at once");
  ok("second device works before revocation", (await call("GET", "/api/auth/me", T.A2)).status === 200);
  ok("another user cannot revoke owner A's session (404)", (await call("POST", "/api/account/sessions/sA2/revoke", T.B)).status === 404);
  ok("second device still works after the foreign attempt", (await call("GET", "/api/auth/me", T.A2)).status === 200);
  ok("owner revokes the second device (200)", (await call("POST", "/api/account/sessions/sA2/revoke", T.A)).status === 200);
  ok("revoked device token → 401 on the next request", (await call("GET", "/api/auth/me", T.A2)).status === 401);
  ok("revoked device token cannot read wsA", denied(await call("GET", "/api/workspaces/wsA", T.A2), "AlphaWS-SECRET"));
  ok("the revoking device keeps working", (await call("GET", "/api/auth/me", T.A)).status === 200);

  sec("Related change — cannot link to another tenant's case");
  db.prepare(`INSERT INTO related_changes (id, workspace_id, cluster_key, registrable_domain, rule_id, direction,
              signal_family_count, independent_producer_count, completeness, first_seen, last_seen)
              VALUES ('rcA','wsA','ck-A','shared.example','rule-test','changed',2,2,'complete',datetime('now'),datetime('now'))`).run();
  const linked = () => db.prepare("SELECT linked_case_id AS c FROM related_changes WHERE id = 'rcA'").get().c;
  const foreignCase = await call("POST", "/api/workspaces/wsA/related-changes/rcA/link-case", T.A, { case_id: "caseB" });
  ok("owner A linking wsA change to wsB's case → 404", foreignCase.status === 404);
  ok("link refused: nothing written", linked() === null);
  const viaB = await call("POST", "/api/workspaces/wsB/related-changes/rcA/link-case", T.B, { case_id: "caseB" });
  ok("foreign owner linking wsA change via wsB path → 404", viaB.status === 404 && linked() === null);
  ok("foreign owner on wsA path → 403", (await call("POST", "/api/workspaces/wsA/related-changes/rcA/link-case", T.B, { case_id: "caseB" })).status === 403 && linked() === null);
  ok("positive control: owner links own case (200)", (await call("POST", "/api/workspaces/wsA/related-changes/rcA/link-case", T.A, { case_id: "caseA" })).status === 200 && linked() === "caseA");

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
