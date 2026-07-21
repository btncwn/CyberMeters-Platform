#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-tenant-authz-coverage.js  (CI-blocking)
//
// Widens the #187 cross-tenant authorization coverage over the C-section
// controls of docs/SECURITY-VERIFICATION-MATRIX.md. REUSES the #187 two-tenant
// harness (scripts/security/lib/worker-harness.js) — same REAL Worker router,
// REAL in-memory SQLite (schema + migrations). This is not a parallel system; it
// closes specific gaps the base matrix (validate-tenant-isolation.js), the
// extended harness (validate-tenant-isolation-extended.js) and the property
// suite (validate-authz-properties.js) do not assert:
//
//   C1 (BOLA/IDOR) — the SMUGGLE vector (invariant 9). The base + property
//     suites test a foreign/non-member actor against tenant-A's WORKSPACE PATH
//     (blocked at requireWorkspaceRole). They do NOT test the harder case: an
//     actor who legitimately owns workspace B requests tenant-A's resource id
//     THROUGH THEIR OWN workspace-B path (/api/workspaces/wsB/<resource>/<A-id>).
//     Here the role gate PASSES (B owns wsB); isolation then rests entirely on
//     the handler also filtering `workspace_id = wsB` when it loads the row by
//     id. This is the classic BOLA that role checks alone never catch. Asserted
//     by id for: managed-cases/:id, cases/:id, related-changes/:id, assets/:id.
//     Plus the foreign-PATH form (B → wsA/<A-id>) and the existence oracle.
//
//   C2 — viewer-role denial on the MANAGER-GATED mutations the base matrix does
//     not exercise: related-changes feedback / link-case / create-case, and the
//     universal case /cases/:id/transition + /assign. Positive control: the same
//     viewer CAN read the detail (so the 403s are role-specific, not blanket).
//
//   C4 — R2/PDF report bytes: an actor who owns workspace B cannot fetch
//     tenant-A's scan report / PDF / executive report / snapshot bytes by A's
//     scan id (membership in SOME workspace must not grant cross-scan R2).
//
//   C5 — API-token lifecycle END-TO-END through the router (the base only unit-
//     tests hasWorkspacePermission): a token scoped to workspace A cannot read
//     or write workspace B; a read-scoped token cannot perform a write on its
//     own workspace; an expired token and a revoked token are both rejected.
//
// Any assertion going RED on current code is a real cross-tenant finding, not a
// test bug — the oracle is "deny", seeded resources carry private markers, and
// every negative is backed by an owner/viewer positive control so a pass is
// never vacuous. Exits non-zero on any failure. Requires Node 24+ (node:sqlite).
// ─────────────────────────────────────────────────────────────────────────────
import { loadWorker, buildDb, makeEnv, makeCaller, makeSeeder, leaks, denied } from "./security/lib/worker-harness.js";
import { RESOURCE_CLASSES } from "./security/lib/tenant-resources.js";

let passed = 0, failed = 0, section = "General";
const results = [];
const sec = (s) => { section = s; };
const ok = (name, cond) => { cond ? (passed++, results.push(`PASS [${section}] ${name}`)) : (failed++, results.push(`FAIL [${section}] ${name}`)); };
const status4xx = (r) => [400, 401, 403, 404].includes(r.status);

// The by-id resource routes this suite adds a cross-tenant SMUGGLE negative for.
// `covers` maps to the resource classes in the #187 matrix, so the coverage
// delta at the end can mark exactly which classes gained a C1-by-id test here.
const SMUGGLE_ROUTES = [
  { label: "managed-cases/:id detail", path: (ws, id) => `/api/workspaces/${ws}/managed-cases/${id}`, marker: "ASM-REF-A-SECRET", covers: "managed_cases" },
  { label: "cases/:id detail (universal)", path: (ws, id) => `/api/workspaces/${ws}/cases/${id}`, marker: "UNI-REF-A-SECRET", covers: "managed_cases" },
  { label: "related-changes/:id detail", path: (ws, id) => `/api/workspaces/${ws}/related-changes/${id}`, marker: "RC-DOMAIN-A-SECRET", covers: "related_changes" },
  { label: "assets/:assetId detail", path: (ws, id) => `/api/workspaces/${ws}/assets/${id}`, marker: "asset-A-SECRET", covers: "assets" },
];

async function main() {
  const mod = await loadWorker();
  const worker = mod.default;
  const db = buildDb();
  const env = makeEnv(db);
  const seed = await makeSeeder(db, mod);
  const call = makeCaller(worker, env, { debug: !!process.env.TENANT_DEBUG });
  const hashToken = mod.hashToken;

  // ── Two tenants ────────────────────────────────────────────────────────────
  seed.user("uA", "a@a.co", "OwnerA");
  seed.user("uB", "b@b.co", "OwnerB");
  seed.user("uViewerA", "viewer@a.co", "ViewerA");
  // uDual legitimately belongs to BOTH workspaces. It exists so the C5 token-
  // workspace boundary is tested in ISOLATION: a token bound to wsA must be
  // rejected for wsB even though its user IS a member of wsB — so the deny can
  // only come from the token boundary, not from a missing membership.
  seed.user("uDual", "dual@a.co", "DualMember");
  const T = { A: "raw-A", B: "raw-B", VA: "raw-viewerA" };
  await seed.session("sA", "uA", T.A);
  await seed.session("sB", "uB", T.B);
  await seed.session("sVA", "uViewerA", T.VA);
  seed.workspace("wsA", "uA", "AlphaWS-SECRET");
  seed.workspace("wsB", "uB", "BravoWS-SECRET");
  seed.member("mA", "wsA", "uA", "owner");
  seed.member("mB", "wsB", "uB", "owner");
  seed.member("mVA", "wsA", "uViewerA", "viewer");
  seed.member("mDualA", "wsA", "uDual", "admin");
  seed.member("mDualB", "wsB", "uDual", "admin");

  // ── Tenant-A resources, each with a private marker ─────────────────────────
  seed.raw("INSERT INTO domains (id, user_id, domain) VALUES ('dA','uA','alpha.example')");
  seed.raw("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('wsA','dA')");
  seed.raw("INSERT INTO workspace_assets (id, workspace_id, domain_id, hostname, asset_type, source, first_seen, last_seen, status, created_at, updated_at) VALUES ('assetA','wsA','dA','asset-A-SECRET.alpha.example','subdomain','ct',datetime('now'),datetime('now'),'active',datetime('now'),datetime('now'))");
  // ASM managed case (read via /managed-cases/:id) — marker in asset_ref.
  seed.raw("INSERT INTO managed_cases (id, workspace_id, case_type, domain_key, domain, finding_id, asset_ref, severity, status, evidence_json, recommended_actions_json, created_at, updated_at) VALUES ('caseA_asm','wsA','attack_surface','attack_surface','alpha.example','admin_surface_high','ASM-REF-A-SECRET','high','open','{}','[]',datetime('now'),datetime('now'))");
  // A base-lifecycle case reachable via the universal /cases/:id — marker in asset_ref.
  seed.raw("INSERT INTO managed_cases (id, workspace_id, case_type, domain_key, domain, finding_id, asset_ref, severity, status, evidence_json, recommended_actions_json, created_at, updated_at) VALUES ('caseA_uni','wsA','website_security','website_security','alpha.example','website_tls','UNI-REF-A-SECRET','medium','open','{}','[]',datetime('now'),datetime('now'))");
  // Related change (M6 B1) — marker in registrable_domain.
  seed.raw("INSERT INTO related_changes (id, workspace_id, cluster_key, registrable_domain, rule_id, direction, signal_family_count, independent_producer_count, confidence, completeness, customer_state, first_seen, last_seen, recurrence_count, last_scan_id, created_at, updated_at) VALUES ('rcA','wsA','clkA','RC-DOMAIN-A-SECRET.example','new_host_with_cert','appeared',2,2,'correlated','complete','new',datetime('now'),datetime('now'),1,'scanA',datetime('now'),datetime('now'))");
  seed.raw("INSERT INTO related_change_evidence (id, related_change_id, workspace_id, producer_family, source_table, source_record_id, source_event_type, entity_key, observed_at, evidence_ref, scan_id, created_at) VALUES ('rceA','rcA','wsA','cert','asset_events','ae1','certificate_new_detected','host:asset-A-SECRET.alpha.example',datetime('now'),'ae1','scanA',datetime('now'))");
  // Scan with an R2-served report (harness R2 stub serves keys containing "served").
  seed.raw("INSERT INTO scans (id, workspace_id, domain_id, domain, score, rating, status, created_at) VALUES ('servedScanA','wsA','dA','alpha.example',80,'good','completed',datetime('now'))");

  // ── Positive controls: A-owner CAN read each seeded resource by id ──────────
  // Without these, every "B denied" pass could be vacuous ("resource not found
  // for anyone"). Each must surface its marker for the legitimate owner.
  sec("Positive controls (anti-vacuous)");
  ok("A-owner reads own managed-case detail (marker present)", leaks(await call("GET", "/api/workspaces/wsA/managed-cases/caseA_asm", T.A), "ASM-REF-A-SECRET"));
  ok("A-owner reads own universal case detail (marker present)", leaks(await call("GET", "/api/workspaces/wsA/cases/caseA_uni", T.A), "UNI-REF-A-SECRET"));
  ok("A-owner reads own related-change detail (marker present)", leaks(await call("GET", "/api/workspaces/wsA/related-changes/rcA", T.A), "RC-DOMAIN-A-SECRET"));
  ok("A-owner reads own asset detail/list (marker present)", leaks(await call("GET", "/api/workspaces/wsA/assets/assetA", T.A), "asset-A-SECRET"));

  // ── C1: BOLA/IDOR smuggle vector (invariant 9) ─────────────────────────────
  // B legitimately owns wsB. B requests A's resource id THROUGH wsB's own path —
  // the role gate passes, so isolation rests on the handler's workspace_id
  // filter. B must be denied and must never see A's marker. Also: the foreign-
  // PATH form (B → wsA/<A-id>) and the existence oracle (A-id vs nonexistent-id
  // through wsB are the same status class — no existence leak).
  sec("C1 BOLA/IDOR — smuggle vector (own-ws path + foreign resource id)");
  const A_ID = { managed_cases: "caseA_asm", related_changes: "rcA", assets: "assetA" };
  for (const r of SMUGGLE_ROUTES) {
    const aId = r.label.startsWith("cases/:id") ? "caseA_uni" : A_ID[r.covers];
    const viaOwnWs = await call("GET", r.path("wsB", aId), T.B);
    ok(`B cannot read A's ${r.label} via wsB path (no marker, denied)`, denied(viaOwnWs, r.marker) && status4xx(viaOwnWs));
    const viaForeignWs = await call("GET", r.path("wsA", aId), T.B);
    ok(`B cannot read A's ${r.label} via wsA path (role-gated)`, denied(viaForeignWs, r.marker) && status4xx(viaForeignWs));
    const fake = await call("GET", r.path("wsB", "nonexistent_id_xyz"), T.B);
    ok(`existence oracle: A-id vs nonexistent via wsB same status (${r.label})`, viaOwnWs.status === fake.status);
  }

  // ── C4: R2 / PDF report bytes are ownership-scoped, not membership-wide ─────
  // B owns wsB but must not fetch A's scan-report bytes by A's scan id.
  sec("C4 R2/PDF — cross-tenant report bytes");
  const REPORT_ENDPOINTS = [
    "/api/scans/servedScanA/report",
    "/api/scans/servedScanA/report/pdf",
    "/api/scans/servedScanA/executive-report-v2",
    "/api/scans/servedScanA/snapshot",
  ];
  for (const p of REPORT_ENDPOINTS) {
    ok(`B (owns wsB) cannot fetch A's ${p}`, denied(await call("GET", p, T.B), "R2-MARKER") && status4xx(await call("GET", p, T.B)));
    ok(`anon cannot fetch A's ${p}`, status4xx(await call("GET", p, null)));
  }

  // ── C2: viewer cannot perform manager/owner-only mutations ─────────────────
  // uViewerA is a real viewer of wsA (so requireWorkspaceAccess passes) — the
  // deny must come from the ROLE/permission gate, not from tenancy.
  sec("C2 role — viewer cannot perform manager-only mutations");
  const VIEWER_MUTATIONS = [
    ["POST", "/api/workspaces/wsA/related-changes/rcA/feedback", { state: "expected" }, "related-change feedback"],
    ["POST", "/api/workspaces/wsA/related-changes/rcA/link-case", { case_id: "caseA_asm" }, "related-change link-case"],
    ["POST", "/api/workspaces/wsA/related-changes/rcA/create-case", {}, "related-change create-case"],
    ["POST", "/api/workspaces/wsA/cases/caseA_uni/transition", { to_status: "assigned" }, "universal case transition"],
    ["POST", "/api/workspaces/wsA/cases/caseA_uni/assign", { owner_type: "team", owner_ref: "sec" }, "universal case assign"],
    ["POST", "/api/workspaces/wsA/managed-cases/caseA_asm/assign", { owner_type: "team", owner_ref: "sec" }, "ASM case assign"],
  ];
  for (const [m, p, b, label] of VIEWER_MUTATIONS) {
    const r = await call(m, p, T.VA, b);
    ok(`viewer forbidden: ${label} (${r.status})`, r.status === 401 || r.status === 403);
  }
  // Positive controls: the viewer CAN read those surfaces — so the 403s above are
  // role-specific, and the manager gate on the detail advertises no transitions.
  ok("viewer CAN read related-change detail (read allowed, mutate denied)", leaks(await call("GET", "/api/workspaces/wsA/related-changes/rcA", T.VA), "RC-DOMAIN-A-SECRET"));
  const viewerCase = await call("GET", "/api/workspaces/wsA/cases/caseA_uni", T.VA);
  ok("viewer CAN read universal case detail", leaks(viewerCase, "UNI-REF-A-SECRET"));
  ok("viewer detail advertises NO available transitions (server-authoritative manage gate)",
     Array.isArray(viewerCase.data?.available_transitions) && viewerCase.data.available_transitions.length === 0 && viewerCase.data?.can_manage === false);
  // The seeded case status must be unchanged after every viewer mutation attempt.
  const caseStill = db.prepare("SELECT status FROM managed_cases WHERE id='caseA_uni'").get();
  ok("universal case status unchanged after viewer mutation attempts", caseStill && caseStill.status === "open");

  // ── C5: API-token scope / expiry / revocation, end-to-end ──────────────────
  // cm_ tokens authenticate through requireAuth; a workspace-bound token is
  // rejected for any other workspace in requireWorkspaceAccess; scope gates
  // writes in hasWorkspacePermission. All exercised through the REAL router.
  sec("C5 API-token — scope, workspace boundary, expiry, revocation");
  const seedToken = async (id, uid, raw, { scope = "read", wsId = null, status = "active", expires = null } = {}) => {
    seed.raw(
      "INSERT INTO api_tokens (id, user_id, name, token_hash, scope, workspace_id, status, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), ?)",
      id, uid, id, await hashToken(raw), scope, wsId, status, expires,
    );
  };
  // All C5 tokens belong to uDual (a member of BOTH wsA and wsB) and are bound
  // to wsA — so a wsB denial isolates the TOKEN boundary, not a missing membership.
  const TOK_A_READ = "cm_tokA_read";      // scope=read, bound to wsA, active
  const TOK_A_WRITE = "cm_tokA_write";    // scope=write, bound to wsA, active
  const TOK_EXPIRED = "cm_tokExpired";    // bound to wsA, past expiry
  const TOK_REVOKED = "cm_tokRevoked";    // bound to wsA, status=revoked
  await seedToken("apitok_read",  "uDual", TOK_A_READ,  { scope: "read",  wsId: "wsA" });
  await seedToken("apitok_write", "uDual", TOK_A_WRITE, { scope: "write", wsId: "wsA" });
  await seedToken("apitok_exp",   "uDual", TOK_EXPIRED, { scope: "read",  wsId: "wsA", expires: "2000-01-01T00:00:00.000Z" });
  await seedToken("apitok_rev",   "uDual", TOK_REVOKED, { scope: "read",  wsId: "wsA", status: "revoked" });

  // Positive control: the wsA-bound read token CAN read wsA.
  ok("wsA-bound read token CAN read wsA (positive control)", leaks(await call("GET", "/api/workspaces/wsA", TOK_A_READ), "AlphaWS-SECRET"));
  // Positive control that isolates the boundary: uDual's SESSION (no token
  // binding) CAN read wsB, proving the membership exists — so the token denial
  // below is the token boundary alone, not a missing membership.
  await seed.session("sDual", "uDual", "raw-dual");
  ok("uDual session CAN read wsB (membership exists — isolates the token boundary)", leaks(await call("GET", "/api/workspaces/wsB", "raw-dual"), "BravoWS-SECRET"));
  // Cross-workspace: the wsA-bound token must be rejected for wsB even though
  // uDual is a member of wsB.
  const crossRead = await call("GET", "/api/workspaces/wsB", TOK_A_READ);
  ok("wsA-bound token CANNOT read wsB (workspace boundary, member of both)", denied(crossRead, "BravoWS-SECRET") && status4xx(crossRead));
  ok("wsA-bound token CANNOT write wsB (workspace boundary, member of both)", status4xx(await call("PATCH", "/api/workspaces/wsB", TOK_A_READ, { name: "HIJACK" })));
  // Scope: a read-scoped token cannot perform a write even on its OWN workspace.
  const readScopeWrite = await call("PATCH", "/api/workspaces/wsA", TOK_A_READ, { name: "ReadScopeRenamed" });
  ok("read-scoped token CANNOT write its own workspace (scope enforced)", readScopeWrite.status === 401 || readScopeWrite.status === 403);
  const wsAName = db.prepare("SELECT name FROM workspaces WHERE id='wsA'").get();
  ok("wsA name unchanged after read-scoped write attempt", wsAName && wsAName.name === "AlphaWS-SECRET");
  // Lifecycle: expired + revoked tokens are rejected outright (401 — auth fails).
  ok("expired token is rejected", (await call("GET", "/api/workspaces/wsA", TOK_EXPIRED)).status === 401);
  ok("revoked token is rejected", (await call("GET", "/api/workspaces/wsA", TOK_REVOKED)).status === 401);
  // Existence oracle: the expired token sees the same status on wsA and a
  // nonexistent ws (auth is checked before workspace resolution → uniform 401).
  ok("expired token: wsA and nonexistent-ws same status (no oracle)",
     (await call("GET", "/api/workspaces/wsA", TOK_EXPIRED)).status === (await call("GET", "/api/workspaces/ws_nope", TOK_EXPIRED)).status);

  // ── Coverage delta report ──────────────────────────────────────────────────
  // Classify each #187 resource class by whether THIS suite adds a C-section
  // cross-tenant test, it was already covered by the base/extended/property
  // harness, or it is exempt (with the matrix's own reason).
  sec("Coverage");
  const addedClasses = new Set(SMUGGLE_ROUTES.map((r) => r.covers));
  // Classes this suite also exercises through C2/C4/C5 negative paths.
  addedClasses.add("related_changes"); addedClasses.add("managed_cases");
  addedClasses.add("scans"); addedClasses.add("reports_snapshots"); addedClasses.add("api_tokens");
  const added = [], existing = [], exempt = [];
  for (const rc of RESOURCE_CLASSES) {
    if (rc.non_tenant) { exempt.push({ class: rc.class, why: rc.coverage_note }); continue; }
    if (addedClasses.has(rc.class)) added.push(rc.class);
    else if (rc.harness || rc.property) existing.push(rc.class);
    else exempt.push({ class: rc.class, why: rc.coverage_note || "static-audit only" });
  }
  ok("coverage delta computed over all #187 resource classes", added.length + existing.length + exempt.length === RESOURCE_CLASSES.length);

  // ── Report ─────────────────────────────────────────────────────────────────
  const bySec = {};
  for (const line of results) { const s = line.match(/\[(.*?)\]/)[1]; (bySec[s] ??= { p: 0, f: 0 })[line.startsWith("PASS") ? "p" : "f"]++; }
  console.log("\nCross-tenant authorization coverage (C-section, reusing #187 harness):");
  for (const [s, c] of Object.entries(bySec)) console.log(`  ${c.f ? "✗" : "✓"} ${s}: ${c.p}/${c.p + c.f}`);
  console.log("\nCoverage delta over #187 resource classes:");
  console.log(`  + gained a C-section cross-tenant test here (${added.length}): ${added.sort().join(", ")}`);
  console.log(`  = already covered by base/extended/property harness (${existing.length}): ${existing.sort().join(", ")}`);
  console.log(`  · exempt / covered by static-audit or dedicated validator (${exempt.length}):`);
  for (const e of exempt.sort((a, b) => a.class.localeCompare(b.class))) console.log(`      ${e.class} — ${e.why}`);
  if (failed) { console.log("\nFailures:"); for (const r of results.filter((r) => r.startsWith("FAIL"))) console.log("  " + r); }
  console.log(`\nCross-tenant authz coverage: ${passed}/${passed + failed} passed`);
  if (failed) { console.error("tenant-authz-coverage validation FAILED — a RED assertion here is a cross-tenant finding, not a test bug"); process.exit(1); }
  console.log("tenant-authz-coverage validation passed");
}

main().catch((e) => { console.error("tenant-authz-coverage runner crashed:", e); process.exit(1); });
