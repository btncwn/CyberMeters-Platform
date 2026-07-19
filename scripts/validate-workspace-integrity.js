#!/usr/bin/env node
//
// Workspace data-integrity + tenant-isolation guard for the workspace-detail screen and
// the owner-only Delete Workspace flow. CI-blocking.
//
// Written after the "Deneme" investigation (2026-07-19): a workspace with zero currently
// monitored domains showed 12 scans / 238 assets / a Latest Scan. The potential P0
// (cross-tenant exposure) was DISPROVEN — every displayed row carried workspace_id = the
// viewed workspace. The real defects were:
//   1. total_scans UNDER-counted: it INNER-JOINed workspace_domains, so a workspace's OWN
//      scans vanished once their domain was removed (showed 12 instead of the true 22).
//   2. retained history read as CURRENT posture on an empty workspace (frontend; guarded by
//      WorkspaceDetailPage.integrity.test.jsx).
//
// This suite pins the tenant-safe SHAPE of the fix so it cannot regress into either a leak
// (hostname-only / global fallback / dropping workspace_id) or the under-count.
//
// Node 24+.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const read = (p) => fs.readFileSync(path.join(root, p), "utf8");
const norm = (s) => s.replace(/\s+/g, " ");

const core = read("workers/scan-api/src/routes/workspaces-core.js");
const insights = read("workers/scan-api/src/routes/workspace-insights.js");

// ── 1. total_scans is the workspace's OWN retained total, tenant-safe ────────
// Extract the total_scans query block (from its comment to its .bind).
const scansBlock = norm((core.match(/SELECT COUNT\(DISTINCT s\.id\) AS n[\s\S]{0,600}?\.bind\(workspaceId, workspaceId\)/) || [""])[0]);
ok("total_scans query block is present", scansBlock.length > 0);
ok("total_scans counts scans directly attributed to this workspace (ownership branch)",
   /s\.workspace_id = \?/.test(scansBlock));
ok("total_scans includes historical NULL-workspace scans only for CURRENT domains of this workspace",
   /s\.workspace_id IS NULL/.test(scansBlock) &&
   /domain_id IN \(\s*SELECT domain_id FROM workspace_domains WHERE workspace_id = \?/.test(scansBlock));
ok("total_scans no longer INNER-JOINs workspace_domains (the under-count cause is gone)",
   !/JOIN workspace_domains/.test(scansBlock));
ok("total_scans never uses hostname-only ownership",
   !/s\.domain\s*=/.test(scansBlock) && !/JOIN domains/.test(scansBlock));

// ── 2. latest_scan / cyber_score stay workspace-scoped (no leak, no global fallback) ─
const latestBlock = norm((core.match(/latest_scan[\s\S]{0,700}?\.bind\(workspaceId, workspaceId\)/) || [""])[0]);
ok("latest_scan remains workspace-scoped (own or NULL-for-current-domain)",
   /s\.workspace_id = \?/.test(latestBlock) && /wd\.workspace_id = \?/.test(latestBlock));
ok("latest_scan never selects a scan by hostname alone", !/s\.domain\s*=\s*\?/.test(latestBlock));
// No unscoped global-latest fallback anywhere in the detail stats.
ok("the detail stats never fall back to a global latest scan",
   !/ORDER BY\s+created_at\s+DESC\s+LIMIT\s+1\s*`\s*\)\s*\.first\(\)\s*,?\s*\n(?![\s\S]*workspace_id)/.test(core));

// ── 3. asset aggregate is workspace-scoped ───────────────────────────────────
ok("active-asset counts are workspace-scoped",
   /FROM workspace_assets\s+WHERE workspace_id = \? AND status = 'active'/.test(norm(insights)));

// ── 4. detail response exposes the caller's role for owner-gating ────────────
ok("GET /api/workspaces/:id exposes the caller's role (owner-gate for the Danger Zone)",
   /role:\s*wsAccess\?\.role/.test(core));

// ── 5. Delete Workspace: owner-only, soft-delete, audited, never a hard delete ─
const delBlock = norm((core.match(/workspaceDeleteRequestMatch && request\.method === "POST"[\s\S]{0,3200}?workspace_deleted/) || [""])[0]);
ok("delete-request route is present", delBlock.length > 0);
ok("delete-request requires the owner role (workspace:delete)",
   /requireWorkspaceRole\(user, workspaceId, "workspace:delete", env\)/.test(delBlock));
ok("delete-request rejects a session-less / api-token caller",
   /api_token_id\)\s*return json\(\{ error: "Session authentication required" \}/.test(delBlock));
ok("delete-request SOFT-deletes (sets deleted_at), never hard-deletes the workspace",
   /UPDATE workspaces SET deleted_at = \? WHERE id = \?/.test(delBlock) &&
   !/DELETE FROM workspaces\b/.test(core));
ok("delete-request disables scheduled scans (monitoring stops)",
   /UPDATE scheduled_scans SET enabled = 0 WHERE workspace_id = \?/.test(delBlock));
ok("delete-request preserves history (archives assets, never deletes them)",
   /UPDATE workspace_assets SET status = 'inactive'/.test(delBlock) && !/DELETE FROM workspace_assets/.test(core));
ok("delete-request emits an audit event",
   /event_type:\s*"workspace_deleted/.test(delBlock));

// ── 6. Count-logic simulation: own retained scans in, foreign out ────────────
// Re-implement the fixed total_scans semantics and prove the invariants on data that
// mirrors the live "Deneme" situation (0 current domains; 22 own scans; a foreign
// workspace scanning the SAME hostname must never be counted).
function countTotalScans(workspaceId, scans, workspaceDomains) {
  const currentDomainIds = new Set(
    workspaceDomains.filter((wd) => wd.workspace_id === workspaceId).map((wd) => wd.domain_id),
  );
  const ids = new Set();
  for (const s of scans) {
    if (s.workspace_id === workspaceId) ids.add(s.id);                              // own attribution
    else if (s.workspace_id == null && currentDomainIds.has(s.domain_id)) ids.add(s.id); // historical for current domain
  }
  return ids.size;
}
const DENEME = "workspace_deneme";
const OTHER = "workspace_other";
const scans = [
  ...Array.from({ length: 12 }, (_, i) => ({ id: `d${i}`, workspace_id: DENEME, domain_id: "dom_bbb_deneme", domain: "blackbullbarbers.co.uk" })),
  ...Array.from({ length: 10 }, (_, i) => ({ id: `x${i}`, workspace_id: DENEME, domain_id: `dom_test_${i}`, domain: "example.com" })),
  ...Array.from({ length: 34 }, (_, i) => ({ id: `o${i}`, workspace_id: OTHER, domain_id: "dom_bbb_other", domain: "blackbullbarbers.co.uk" })),
  { id: "nullcur", workspace_id: null, domain_id: "dom_current", domain: "acme.co.uk" },
  { id: "nullforeign", workspace_id: null, domain_id: "dom_not_deneme", domain: "acme.co.uk" },
];
// Deneme has 0 current domains (its blackbullbarbers domain was removed).
const wsDomainsEmpty = [{ workspace_id: OTHER, domain_id: "dom_bbb_other" }];
ok("simulation: own retained scans are counted even with 0 current domains (22, not 12)",
   countTotalScans(DENEME, scans, wsDomainsEmpty) === 22, `got ${countTotalScans(DENEME, scans, wsDomainsEmpty)}`);
ok("simulation: a foreign workspace's scans of the same hostname are never counted",
   countTotalScans(OTHER, scans, wsDomainsEmpty) === 34, `got ${countTotalScans(OTHER, scans, wsDomainsEmpty)}`);
// Now give Deneme a current domain that owns the NULL-workspace historical scan.
const wsDomainsWithCurrent = [{ workspace_id: DENEME, domain_id: "dom_current" }];
ok("simulation: a NULL-workspace historical scan counts only for the workspace currently owning its domain",
   countTotalScans(DENEME, scans, wsDomainsWithCurrent) === 23 &&
   countTotalScans(OTHER, scans, wsDomainsWithCurrent) === 34,
   `deneme ${countTotalScans(DENEME, scans, wsDomainsWithCurrent)} / other ${countTotalScans(OTHER, scans, wsDomainsWithCurrent)}`);
ok("simulation: hostname alone never confers ownership",
   countTotalScans("workspace_nobody", scans, []) === 0);

console.log(`\nworkspace-integrity: ${pass} passed, ${fail} failed`);
if (fail > 0) { console.error("workspace-integrity validation FAILED"); process.exit(1); }
console.log("workspace-integrity validation passed");
