#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// build-entry-point-inventory.js
//
// Regenerates the canonical entry-point inventory from Worker source:
//   • scripts/security/entry-point-inventory.json  (machine-readable signature)
//   • docs/security/ENTRY-POINT-INVENTORY.md        (readable report)
//
// Run this whenever a route is added, removed, or its guards change, then commit
// both files. `scripts/validate-entry-point-inventory.js` re-derives the same
// signature in CI and fails on any drift, so a new route cannot silently escape
// the inventory.
// ─────────────────────────────────────────────────────────────────────────────
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { extractAll, summarise, isPublic, PUBLIC_ALLOWLIST, ENTRY_POINT_FILES, REPO_ROOT } from "./lib/extract-entry-points.js";

// The drift signature deliberately EXCLUDES `line` (churns on unrelated edits and
// would make the gate noisy) but INCLUDES everything that matters for security:
// method, path, file, scope, the guard set, and whether the handler authenticates.
export function signatureEntry(e) {
  return {
    method: e.method,
    path: e.path,
    path_kind: e.path_kind,
    file: e.file,
    scope: e.scope,
    auth_guards: e.auth_guards,
    scope_helpers: e.scope_helpers,
    authed: e.authed,
    public_reason: e.authed ? null : ((isPublic(e.path || "", e.method) || {}).reason ?? null),
  };
}

export function buildSignature() {
  const all = extractAll();
  const entries = all.map(signatureEntry)
    .sort((a, b) => (a.file.localeCompare(b.file)) ||
                    (String(a.path).localeCompare(String(b.path))) ||
                    (a.method.localeCompare(b.method)));
  const s = summarise(all);
  return {
    schema: "cybermeters.entry-point-inventory/v1",
    generated_by: "scripts/security/build-entry-point-inventory.js",
    doc: "docs/security/ENTRY-POINT-INVENTORY.md",
    source_files: ENTRY_POINT_FILES.map((f) => `workers/scan-api/src/${f}`),
    counts: {
      total: s.total,
      authed: all.filter((e) => e.authed).length,
      public_unauthed: all.filter((e) => !e.authed).length,
      sensitive_scope_gaps: s.gaps.length,
      by_scope: s.byScope,
    },
    public_allowlist: PUBLIC_ALLOWLIST.map((a) => ({ pattern: String(a.match), reason: a.reason })),
    entry_points: entries,
  };
}

function renderMarkdown(sig, all) {
  const L = [];
  L.push("# CyberMeters — Canonical Entry-Point Inventory");
  L.push("");
  L.push("> **Generated** by `scripts/security/build-entry-point-inventory.js` from Worker source.");
  L.push("> Do not edit by hand — run the builder and commit. CI gate:");
  L.push("> `scripts/validate-entry-point-inventory.js` fails on any drift or unverified gap.");
  L.push("");
  L.push("This inventory is a **structural** enumeration of every security-relevant");
  L.push("entry point (HTTP handler sites, the scheduled/cron handler, the inbound-email");
  L.push("handler) and the authorization guards that lexically govern each one. It is not a");
  L.push("semantic proof; its two guarantees are (1) a new route cannot silently escape the");
  L.push("inventory, and (2) no workspace/ownership/account/admin-scoped handler lacks an auth");
  L.push("guard without an explicit, documented public-allowlist reason.");
  L.push("");
  L.push("## Coverage summary");
  L.push("");
  L.push(`- **Total entry points:** ${sig.counts.total}`);
  L.push(`- **Auth-guarded:** ${sig.counts.authed}`);
  L.push(`- **Unauthenticated (public by design):** ${sig.counts.public_unauthed}`);
  L.push(`- **Sensitive-scope gaps (unauthed workspace/resource/account/admin/portfolio, non-public):** ${sig.counts.sensitive_scope_gaps}`);
  L.push("");
  L.push("| Scope | Handlers | Auth-guarded |");
  L.push("|---|---:|---:|");
  for (const [scope, c] of Object.entries(sig.counts.by_scope).sort()) L.push(`| ${scope} | ${c.total} | ${c.authed} |`);
  L.push("");
  L.push("## Public allowlist (unauthenticated by design)");
  L.push("");
  L.push("Each unauthenticated entry point matches one of these documented reasons. Any");
  L.push("unauthenticated sensitive-scope handler NOT covered here fails the CI gate.");
  L.push("");
  L.push("| Pattern | Reason |");
  L.push("|---|---|");
  for (const a of sig.public_allowlist) L.push(`| \`${a.pattern.replace(/\|/g, "\\|")}\` | ${a.reason} |`);
  L.push("");
  L.push("## Entry points by file");
  L.push("");
  const byFile = {};
  for (const e of all) (byFile[e.file] ??= []).push(e);
  for (const file of Object.keys(byFile).sort()) {
    L.push(`### \`${file}\``);
    L.push("");
    L.push("| Method | Path | Line | Scope | Auth | Guards |");
    L.push("|---|---|---:|---|---|---|");
    for (const e of byFile[file].sort((a, b) => a.line - b.line)) {
      const guards = [...(e.auth_guards || []), ...(e.scope_helpers || []).map((g) => g + "*")].join(", ") || "—";
      const authMark = e.authed ? "✓" : (e.scope === "preflight" || isPublic(e.path || "", e.method) ? "public" : "**GAP**");
      const p = String(e.path ?? "(none)").replace(/\|/g, "\\|");
      L.push(`| ${e.method} | \`${p.slice(0, 60)}\` | ${e.line} | ${e.scope} | ${authMark} | ${guards} |`);
    }
    L.push("");
  }
  L.push("_`*` = workspace-scoping helper (getAccessibleWorkspaceIds / getWorkspaceBillingUserId)._");
  L.push("");
  return L.join("\n");
}

function main() {
  const sig = buildSignature();
  const all = extractAll();
  const jsonPath = path.join(REPO_ROOT, "scripts", "security", "entry-point-inventory.json");
  const mdPath = path.join(REPO_ROOT, "docs", "security", "ENTRY-POINT-INVENTORY.md");
  fs.writeFileSync(jsonPath, JSON.stringify(sig, null, 2) + "\n");
  fs.writeFileSync(mdPath, renderMarkdown(sig, all));
  console.log(`Wrote ${jsonPath} (${sig.counts.total} entry points, ${sig.counts.sensitive_scope_gaps} gaps)`);
  console.log(`Wrote ${mdPath}`);
}

// Only write files when run directly — importing buildSignature (e.g. from the
// validator) must have no side effects.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
