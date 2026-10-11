#!/usr/bin/env node
// Is what is on GitHub actually live?
//
//   git fetch origin && node scripts/check-live-versions.mjs
//
// Compares, per component, the commit that is LIVE with origin/main:
//   • app  (Cloudflare Pages, auto-deploys on merge) — https://app.cybermeters.com/version.json
//   • api  (scan-api Worker, deployed by hand)        — https://api.cybermeters.com/health
// and lists the commits on main that touch that component but are not live.
// Requests carry a cache-buster so no CDN or browser copy is read.
//
// Exit code 0: every component is live at main (or nothing it ships changed
// since). 1: something on main is not live yet, or a component cannot say
// which commit it runs (e.g. a Worker deployed without scripts/deploy-scan-api.sh).
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";

export const COMPONENTS = Object.freeze([
  { id: "app", label: "Website (Cloudflare Pages)", url: (o) => `${o.app}/version.json`, read: (b) => b?.commit, paths: ["frontend", "shared"] },
  { id: "api", label: "API Worker (scan-api)", url: (o) => `${o.api}/health`, read: (b) => b?.commit, paths: ["workers/scan-api", "shared", "database/migrations"] },
]);

const SHA = /^[0-9a-f]{40}$/;

/** Pure: decide one component's status. */
export function assessComponent({ liveCommit, mainCommit, pending, reachable }) {
  if (!reachable) return { status: "unreachable", ok: false };
  if (!SHA.test(String(liveCommit || ""))) return { status: "unknown_commit", ok: false };
  if (liveCommit === mainCommit) return { status: "live_at_main", ok: true };
  if (pending === null) return { status: "live_commit_not_on_main", ok: false };
  return pending.length ? { status: "behind_main", ok: false } : { status: "live_no_pending_changes", ok: true };
}

const STATUS_TEXT = {
  live_at_main: "live = main",
  live_no_pending_changes: "live (later main commits do not touch it)",
  behind_main: "NOT live — commits on main are waiting to be deployed",
  live_commit_not_on_main: "live commit is not on main (deployed from another branch?)",
  unknown_commit: "cannot tell — it does not report its commit (deploy with `sh scripts/deploy-scan-api.sh`)",
  unreachable: "unreachable",
};

export async function checkLiveVersions({ fetchImpl = fetch, git, app = "https://app.cybermeters.com", api = "https://api.cybermeters.com", ref = "origin/main", now = Date.now } = {}) {
  const mainCommit = git(["rev-parse", ref]).trim();
  const results = [];
  for (const c of COMPONENTS) {
    let body = null, reachable = false;
    try {
      const res = await fetchImpl(`${c.url({ app, api })}?nocache=${now()}`, { headers: { "cache-control": "no-cache" } });
      reachable = res.ok;
      body = res.ok ? await res.json() : null;
    } catch { reachable = false; }
    const liveCommit = c.read(body) ?? null;
    let pending = null;
    if (SHA.test(String(liveCommit || ""))) {
      try {
        git(["merge-base", "--is-ancestor", liveCommit, mainCommit]);
        const out = git(["log", "--format=%h %s", `${liveCommit}..${mainCommit}`, "--", ...c.paths]).trim();
        pending = out ? out.split("\n") : [];
      } catch { pending = null; }
    }
    results.push({ id: c.id, label: c.label, live_commit: liveCommit, main_commit: mainCommit, pending: pending || [], ...assessComponent({ liveCommit, mainCommit, pending, reachable }), version: body?.version ?? null });
  }
  return { main_commit: mainCommit, ok: results.every((r) => r.ok), components: results };
}

export function formatReport(report) {
  const lines = [`main: ${report.main_commit.slice(0, 12)}`];
  for (const r of report.components) {
    lines.push(`${r.ok ? "✔" : "✘"} ${r.label}: ${STATUS_TEXT[r.status]}${r.live_commit ? ` (live ${r.live_commit.slice(0, 12)}${r.version ? `, ${r.version}` : ""})` : ""}`);
    for (const p of r.pending.slice(0, 20)) lines.push(`    waiting: ${p}`);
    if (r.pending.length > 20) lines.push(`    … and ${r.pending.length - 20} more`);
  }
  return lines.join("\n");
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  const arg = (name) => { const i = process.argv.indexOf(`--${name}`); return i > -1 ? process.argv[i + 1] : undefined; };
  const git = (args) => execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  const report = await checkLiveVersions({ git, app: arg("app"), api: arg("api"), ref: arg("ref") });
  console.log(process.argv.includes("--json") ? JSON.stringify(report, null, 2) : formatReport(report));
  process.exit(report.ok ? 0 : 1);
}
