#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-a6-viewer-enforcement.js  (CI-blocking)
//
// A6 release-gate: viewer-role enforcement on the Related Changes surface, proven
// through the REAL Worker router (reusing the #187/#241 harness) — NOT by hidden
// buttons. The frontend hides manager-only controls, but the SECURITY property is
// that the BACKEND refuses every mutation for a viewer regardless of the UI, and
// that it returns the honest `can_manage` signal the UI renders from.
//
// Asserted for a genuine viewer member of the workspace:
//   • may READ the related-change detail AND its evidence pointers;
//   • the detail carries can_manage=false (the signal the UI hides controls on);
//   • cannot submit feedback in ANY state (expected / unrelated / unexpected);
//   • cannot link an existing case;
//   • cannot create a case;
//   • none of the above mutated the cluster's customer_state.
// Positive controls (so the 403s are role-specific, never a blanket deny):
//   • an owner READS the same detail with can_manage=true;
//   • an owner CAN submit feedback (the mutation path works for a manager).
//
// The load-bearing guard is the route's per-method permission
// (GET → workspace:read, else workspace:manage). A mutation that weakens it to
// allow a viewer through must redden this suite. Requires Node 24+.
// ─────────────────────────────────────────────────────────────────────────────
import { loadWorker, buildDb, makeEnv, makeCaller, makeSeeder, leaks } from "./security/lib/worker-harness.js";

let passed = 0, failed = 0, section = "General";
const results = [];
const sec = (s) => { section = s; };
const ok = (name, cond) => { cond ? (passed++, results.push(`PASS [${section}] ${name}`)) : (failed++, results.push(`FAIL [${section}] ${name}`)); };
const forbidden = (r) => r.status === 401 || r.status === 403;

async function main() {
  const mod = await loadWorker();
  const worker = mod.default;
  const db = buildDb();
  const env = makeEnv(db);
  const seed = await makeSeeder(db, mod);
  const call = makeCaller(worker, env);

  seed.user("uOwner", "owner@a.co");
  seed.user("uViewer", "viewer@a.co");
  await seed.session("sOwner", "uOwner", "tok-owner");
  await seed.session("sViewer", "uViewer", "tok-viewer");
  seed.workspace("wsA", "uOwner", "AlphaWS");
  seed.member("mOwner", "wsA", "uOwner", "owner");
  seed.member("mViewer", "wsA", "uViewer", "viewer"); // a genuine member, low privilege
  seed.raw("INSERT INTO related_changes (id, workspace_id, cluster_key, registrable_domain, rule_id, direction, signal_family_count, independent_producer_count, confidence, completeness, customer_state, first_seen, last_seen, recurrence_count, last_scan_id, created_at, updated_at) VALUES ('rcA','wsA','ck','RC-DOMAIN-SECRET.example','new_host_with_cert','appeared',2,2,'correlated','complete','new',datetime('now'),datetime('now'),1,'sc',datetime('now'),datetime('now'))");
  seed.raw("INSERT INTO related_change_evidence (id, related_change_id, workspace_id, producer_family, source_table, source_record_id, source_event_type, entity_key, observed_at, evidence_ref, scan_id, created_at) VALUES ('reA','rcA','wsA','cert','asset_events','ae1','certificate_new_detected','host:api.example','2026-07-21T00:00:00Z','ae1','sc','2026-07-21T00:00:00Z')");

  const detailPath = "/api/workspaces/wsA/related-changes/rcA";

  // ── Read is allowed; the honest can_manage signal is returned ──────────────
  sec("Viewer read + honest signal");
  const vGet = await call("GET", detailPath, "tok-viewer");
  ok("viewer CAN read the related-change detail (200)", vGet.status === 200 && leaks(vGet, "RC-DOMAIN-SECRET"));
  ok("viewer detail includes the evidence pointers", Array.isArray(vGet.data?.evidence) && vGet.data.evidence.length === 1);
  ok("viewer detail carries can_manage=false (the UI hides controls on this)", vGet.data?.can_manage === false);
  const oGet = await call("GET", detailPath, "tok-owner");
  ok("owner reads the same detail with can_manage=true (positive control)", oGet.status === 200 && oGet.data?.can_manage === true);

  // ── Every mutation is refused for the viewer ───────────────────────────────
  sec("Viewer mutations refused");
  for (const state of ["expected", "unrelated", "unexpected_confirmed"]) {
    ok(`viewer cannot mark '${state}' (feedback forbidden)`, forbidden(await call("POST", `${detailPath}/feedback`, "tok-viewer", { state })));
  }
  ok("viewer cannot link an existing case", forbidden(await call("POST", `${detailPath}/link-case`, "tok-viewer", { case_id: "case-x" })));
  ok("viewer cannot create a case", forbidden(await call("POST", `${detailPath}/create-case`, "tok-viewer", {})));

  // ── State was not mutated by any viewer attempt ────────────────────────────
  const midState = db.prepare("SELECT customer_state FROM related_changes WHERE id='rcA'").get();
  ok("cluster customer_state unchanged after all viewer mutation attempts", midState.customer_state === "new");

  // ── Positive control: the mutation path DOES work for a manager ────────────
  sec("Manager positive control");
  const oFeedback = await call("POST", `${detailPath}/feedback`, "tok-owner", { state: "expected" });
  ok("owner CAN submit feedback (403s above are role-specific, not blanket)", oFeedback.status === 200);
  const afterOwner = db.prepare("SELECT customer_state FROM related_changes WHERE id='rcA'").get();
  ok("owner feedback DID persist (proves the write path is live)", afterOwner.customer_state === "expected");

  // ── Report ─────────────────────────────────────────────────────────────────
  const bySec = {};
  for (const line of results) { const s = line.match(/\[(.*?)\]/)[1]; (bySec[s] ??= { p: 0, f: 0 })[line.startsWith("PASS") ? "p" : "f"]++; }
  console.log("\nA6 viewer-role enforcement (Related Changes, real router):");
  for (const [s, c] of Object.entries(bySec)) console.log(`  ${c.f ? "✗" : "✓"} ${s}: ${c.p}/${c.p + c.f}`);
  if (failed) { console.log("\nFailures:"); for (const r of results.filter((r) => r.startsWith("FAIL"))) console.log("  " + r); }
  console.log(`\nA6 viewer enforcement: ${passed}/${passed + failed} passed`);
  if (failed) { console.error("a6-viewer-enforcement validation FAILED"); process.exit(1); }
  console.log("a6-viewer-enforcement validation passed");
}

main().catch((e) => { console.error("a6-viewer-enforcement runner crashed:", e); process.exit(1); });
