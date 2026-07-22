#!/usr/bin/env node
// repair-interrupted-r2-quality-2026-07-22.js
//
// ONE-TIME, FOUNDER-APPROVED, BOUNDED canonical repair (PR-1b, 22 Jul 2026).
//
// Scope: EXACTLY the three scans interrupted in the 22 Jul manual-scan incident,
// whose R2 failed reports inherited scan_quality.status="complete" from the old
// running placeholder (the PR-1 live-acceptance gate-fail). The recovery engine
// is idempotent and will never re-touch these terminal rows, so this guarded
// script is the canonical repair vehicle for the three historical objects.
//
// Guards (ALL must hold per object, or the object is skipped with a reason):
//   D1: status='failed' AND scan_quality IS NULL
//   R2: status='failed' AND reason='interrupted_before_finalisation'
//       AND scan_quality is currently NON-null (the inherited defect present)
// Change: scan_quality -> null. NOTHING else. Every other byte preserved.
// Proof: sha256 before/after per object. Idempotent: second run = no change.
// Refuses any scan id outside the pinned three. Creates no alert/case/finding/
// score/audit — this is a pure honesty correction of three JSON documents.
//
// Run from repo root:  node scripts/repair-interrupted-r2-quality-2026-07-22.js
// (requires wrangler auth to the production account; read-only until every
//  guard passes; writes at most the three pinned objects)

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const PINNED_SCAN_IDS = [
  "scan_eb0aba0c-662b-40f9-90d3-57fab9aae951",
  "scan_32945fab-d2ed-49e5-b576-4ea9edd62231",
  "scan_deb2244f-dff7-4be7-8c8d-0ec540af9ea4",
];
const EXPECTED_REASON = "interrupted_before_finalisation";
const WRANGLER_CWD = path.join(process.cwd(), "workers", "scan-api");

const sha256 = (s) => createHash("sha256").update(s).digest("hex");
const wrangler = (args, input = null) =>
  execFileSync("npx", ["wrangler", ...args], {
    cwd: WRANGLER_CWD, encoding: "utf8", input: input ?? undefined,
    stdio: ["pipe", "pipe", "pipe"],
  });

function d1Row(scanId) {
  const out = wrangler([
    "d1", "execute", "cybermeters-db", "--remote", "--json", "--command",
    `SELECT id, status, scan_quality, workspace_id, domain FROM scans WHERE id = '${scanId}'`,
  ]);
  const parsed = JSON.parse(out.slice(out.indexOf("[")));
  return parsed[0]?.results?.[0] ?? null;
}

function r2Get(key) {
  try {
    return wrangler(["r2", "object", "get", `cybermeters-reports/${key}`, "--remote", "--pipe"]);
  } catch { return null; }
}

let repaired = 0, unchanged = 0, refused = 0;

for (const scanId of PINNED_SCAN_IDS) {
  const label = scanId.slice(0, 18) + "…";
  const key = `reports/${scanId}.json`;

  // ── Guard 1-2: authoritative D1 state ─────────────────────────────────────
  const row = d1Row(scanId);
  if (!row) { console.log(`REFUSE ${label}: no D1 row`); refused++; continue; }
  if (row.status !== "failed" || row.scan_quality !== null) {
    console.log(`REFUSE ${label}: D1 not (failed, quality NULL) — status=${row.status} quality=${row.scan_quality}`);
    refused++; continue;
  }

  // ── Guard 3-5: R2 state ───────────────────────────────────────────────────
  const beforeRaw = r2Get(key);
  if (!beforeRaw) { console.log(`REFUSE ${label}: R2 object absent`); refused++; continue; }
  let doc;
  try { doc = JSON.parse(beforeRaw); }
  catch { console.log(`REFUSE ${label}: R2 object unparseable`); refused++; continue; }
  if (doc.status !== "failed" || doc.reason !== EXPECTED_REASON) {
    console.log(`REFUSE ${label}: R2 not (failed, ${EXPECTED_REASON}) — status=${doc.status} reason=${doc.reason}`);
    refused++; continue;
  }
  if (doc.scan_quality === null || doc.scan_quality === undefined) {
    console.log(`NO-CHANGE ${label}: scan_quality already null (idempotent)`);
    unchanged++; continue;
  }

  // ── The single permitted change ───────────────────────────────────────────
  const beforeHash = sha256(beforeRaw);
  const repairedDoc = { ...doc, scan_quality: null };
  const afterBody = JSON.stringify(repairedDoc, null, 2);
  const afterHash = sha256(afterBody);

  // Deterministic diff proof: parse-level equality on every key except the one.
  const changedKeys = Object.keys({ ...doc, ...repairedDoc })
    .filter((k) => JSON.stringify(doc[k]) !== JSON.stringify(repairedDoc[k]));
  if (changedKeys.length !== 1 || changedKeys[0] !== "scan_quality") {
    console.log(`REFUSE ${label}: computed change set is not exactly [scan_quality]: ${changedKeys.join(",")}`);
    refused++; continue;
  }

  const tmp = path.join(os.tmpdir(), `${scanId}.repair.json`);
  fs.writeFileSync(tmp, afterBody);
  wrangler(["r2", "object", "put", `cybermeters-reports/${key}`, "--remote",
            "--file", tmp, "--content-type", "application/json"]);
  fs.unlinkSync(tmp);

  // Post-write verification
  const verifyRaw = r2Get(key);
  const verify = JSON.parse(verifyRaw);
  const okAfter = verify.scan_quality === null && verify.status === "failed" &&
                  verify.reason === EXPECTED_REASON &&
                  (verify.findings || []).length === (doc.findings || []).length;
  console.log(`REPAIRED ${label}`);
  console.log(`  before sha256=${beforeHash}`);
  console.log(`  after  sha256=${afterHash} verified=${okAfter}`);
  console.log(`  quality ${JSON.stringify(doc.scan_quality)} -> null · every other field preserved`);
  if (!okAfter) { console.log(`  !! POST-WRITE VERIFY FAILED for ${label}`); process.exitCode = 1; }
  repaired++;
}

console.log(`\nrepair summary: repaired=${repaired} unchanged=${unchanged} refused=${refused} (pinned=${PINNED_SCAN_IDS.length})`);
if (refused > 0) process.exitCode = 1;
