#!/usr/bin/env node
//
// "Is what is on GitHub live?" — the commit stamps and the live check.
// Proves: the Pages build emits /version.json with a real commit (or null,
// never a guess); the Worker reports the commit it was deployed from only
// when it is a full SHA; and scripts/check-live-versions.mjs tells "live",
// "behind main (these commits are waiting)", "cannot tell" and "unreachable"
// apart, with a cache-buster on every request. No network.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const { buildVersionManifest } = await import(pathToFileURL(path.join(root, "frontend", "version-manifest.js")).href);
const { checkLiveVersions, assessComponent, formatReport } = await import(pathToFileURL(path.join(root, "scripts", "check-live-versions.mjs")).href);

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => { if (cond) pass++; else { fail++; console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); } };
const eq = (name, got, want) => ok(name, JSON.stringify(got) === JSON.stringify(want), `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);

const A = "a".repeat(40), B = "b".repeat(40), C = "c".repeat(40);

// ── 1. Build stamp ──────────────────────────────────────────────────────────
eq("pages: CF_PAGES_COMMIT_SHA used", buildVersionManifest({ CF_PAGES_COMMIT_SHA: A, CF_PAGES_BRANCH: "main" }, () => B).commit, A);
eq("pages: branch recorded", buildVersionManifest({ CF_PAGES_COMMIT_SHA: A, CF_PAGES_BRANCH: "main" }).branch, "main");
eq("pages: falls back to GITHUB_SHA, then git", [buildVersionManifest({ GITHUB_SHA: B }, () => C).commit, buildVersionManifest({}, () => C).commit], [B, C]);
eq("pages: never a guess — invalid or missing commit is null", [buildVersionManifest({ CF_PAGES_COMMIT_SHA: "main" }).commit, buildVersionManifest({}, () => { throw new Error("no git"); }).commit], [null, null]);
const vite = fs.readFileSync(path.join(root, "frontend", "vite.config.js"), "utf8");
ok("pages: manifest plugin is part of the production build", /versionManifest\(\)/.test(vite) && /from '\.\/version-manifest\.js'/.test(vite));
const headers = fs.readFileSync(path.join(root, "frontend", "public", "_headers"), "utf8");
ok("pages: /version.json is never cached (inherits the no-store rule)", /^\/\*\n[\s\S]*?Cache-Control: no-cache, no-store, must-revalidate/m.test(headers) && !/^\/version\.json/m.test(headers));

// ── 2. Worker stamp ─────────────────────────────────────────────────────────
const index = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "index.js"), "utf8");
ok("worker: /health reports a full-SHA commit or null", /commit:\s+\/\^\[0-9a-f\]\{40\}\$\/\.test\(String\(env\.GIT_COMMIT \|\| ""\)\) \? env\.GIT_COMMIT : null/.test(index));
const deploy = fs.readFileSync(path.join(root, "scripts", "deploy-scan-api.sh"), "utf8");
ok("worker: deploy script stamps the commit it is built from", /commit=\$\(git -C "\$root" rev-parse HEAD\)/.test(deploy) && /wrangler deploy --var "GIT_COMMIT:\$commit"/.test(deploy));
ok("worker: deploy script tags the Cloudflare version with the same commit", /short=\$\(printf '%s' "\$commit" \| cut -c1-12\)/.test(deploy) && /--tag "\$short" --message "\$message"/.test(deploy));
ok("worker: deploy script refuses uncommitted Worker sources (the stamp must be true)", /status --porcelain -- workers\/scan-api shared\)" \]; then[\s\S]*?exit 1/.test(deploy) && /^set -eu$/m.test(deploy));
// workers/scan-api/package.json is SHA-pinned by the install-script policy — the stamp lives in the script instead.
const pkg = JSON.parse(fs.readFileSync(path.join(root, "workers", "scan-api", "package.json"), "utf8"));
ok("worker: package.json deploy script untouched (install-script policy pin)", pkg.scripts.deploy === "wrangler deploy");

// ── 3. Assessment ───────────────────────────────────────────────────────────
eq("assess: live = main", assessComponent({ liveCommit: A, mainCommit: A, pending: [], reachable: true }), { status: "live_at_main", ok: true });
eq("assess: behind main", assessComponent({ liveCommit: A, mainCommit: B, pending: ["x"], reachable: true }), { status: "behind_main", ok: false });
eq("assess: later commits don't touch it", assessComponent({ liveCommit: A, mainCommit: B, pending: [], reachable: true }), { status: "live_no_pending_changes", ok: true });
eq("assess: no commit reported", assessComponent({ liveCommit: null, mainCommit: B, pending: null, reachable: true }), { status: "unknown_commit", ok: false });
eq("assess: not on main", assessComponent({ liveCommit: C, mainCommit: B, pending: null, reachable: true }), { status: "live_commit_not_on_main", ok: false });
eq("assess: unreachable", assessComponent({ liveCommit: null, mainCommit: B, pending: null, reachable: false }), { status: "unreachable", ok: false });

// ── 4. End to end with fakes ────────────────────────────────────────────────
function fakeGit({ main = B, ancestors = [A, B], logs = {} } = {}) {
  const calls = [];
  const git = (args) => {
    calls.push(args.join(" "));
    if (args[0] === "rev-parse") return `${main}\n`;
    if (args[0] === "merge-base") { if (!ancestors.includes(args[2])) throw new Error("not ancestor"); return ""; }
    if (args[0] === "log") return logs[args[args.indexOf("--") + 1]] ?? "";
    throw new Error(`unexpected git ${args.join(" ")}`);
  };
  return { git, calls };
}
const fakeFetch = (bodies, seen = []) => async (url) => {
  seen.push(url);
  const key = Object.keys(bodies).find((k) => url.startsWith(k));
  if (!key || bodies[key] === "down") throw new Error("down");
  return new Response(JSON.stringify(bodies[key]), { status: 200, headers: { "content-type": "application/json" } });
};
{
  const seen = [];
  const { git } = fakeGit({ logs: { frontend: "", "workers/scan-api": "1234567 feat(website): signed-in scanning\n89abcde fix(api): x" } });
  const r = await checkLiveVersions({ git, now: () => 42, fetchImpl: fakeFetch({ "https://app.cybermeters.com/version.json": { commit: B }, "https://api.cybermeters.com/health": { commit: A, version: "2026.10.11-x" } }, seen) });
  eq("e2e: app live at main, api behind", r.components.map((c) => [c.id, c.status]), [["app", "live_at_main"], ["api", "behind_main"]]);
  eq("e2e: pending Worker commits listed", r.components[1].pending, ["1234567 feat(website): signed-in scanning", "89abcde fix(api): x"]);
  ok("e2e: overall not ok while something waits", r.ok === false);
  ok("e2e: every request carries a cache-buster", seen.every((u) => /\?nocache=42$/.test(u)), JSON.stringify(seen));
  const text = formatReport(r);
  ok("report: says what is waiting", /NOT live/.test(text) && /waiting: 1234567 feat\(website\): signed-in scanning/.test(text), text);
}
{
  const { git } = fakeGit();
  const r = await checkLiveVersions({ git, fetchImpl: fakeFetch({ "https://app.cybermeters.com/version.json": { commit: B }, "https://api.cybermeters.com/health": { status: "ok", version: "v", commit: null } }) });
  eq("e2e: Worker without a commit stamp → cannot tell (not ok)", [r.components[1].status, r.ok], ["unknown_commit", false]);
  const r2 = await checkLiveVersions({ git, fetchImpl: fakeFetch({ "https://app.cybermeters.com/version.json": "down", "https://api.cybermeters.com/health": { commit: B } }) });
  eq("e2e: unreachable app", [r2.components[0].status, r2.components[1].status, r2.ok], ["unreachable", "live_at_main", false]);
  const r3 = await checkLiveVersions({ git: fakeGit({ ancestors: [B] }).git, fetchImpl: fakeFetch({ "https://app.cybermeters.com/version.json": { commit: C }, "https://api.cybermeters.com/health": { commit: B } }) });
  eq("e2e: live commit not on main", r3.components[0].status, "live_commit_not_on_main");
  const r4 = await checkLiveVersions({ git: fakeGit({ logs: {} }).git, fetchImpl: fakeFetch({ "https://app.cybermeters.com/version.json": { commit: A }, "https://api.cybermeters.com/health": { commit: A } }) });
  eq("e2e: later main commits that touch neither component → ok", [r4.components.map((c) => c.status), r4.ok], [["live_no_pending_changes", "live_no_pending_changes"], true]);
}

console.log(`validate-live-version-check: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
