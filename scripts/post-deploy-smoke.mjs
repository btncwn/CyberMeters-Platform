#!/usr/bin/env node
// Post-deploy smoke test for the scan-api Worker.
//
//   node scripts/post-deploy-smoke.mjs --expect-commit <sha> [--api https://api.cybermeters.com]
//
// Run by scripts/deploy-scan-api.sh right after `wrangler deploy`. It answers one
// question in a few seconds: is the code we just deployed answering, healthy and
// still gated? Checks, retried while the new version propagates:
//   1. GET /health        → 200 and reports the commit we just deployed
//   2. GET /ready         → 200, status "ready" (D1 and R2 reachable)
//   3. GET /api/workspaces without credentials → 401 (routing and the auth gate
//      work; a 5xx or a 200 here is a broken deploy)
// Exit 0 when all pass. Exit 1 with a plain warning and the rollback command
// otherwise. It never changes anything.
import { fileURLToPath } from "node:url";

export const DEFAULT_API = "https://api.cybermeters.com";
const SHA = /^[0-9a-f]{40}$/;

const bust = (url) => `${url}${url.includes("?") ? "&" : "?"}smoke=${Date.now()}`;

async function readJson(fetchImpl, url) {
  try {
    const res = await fetchImpl(bust(url), { headers: { "cache-control": "no-cache" } });
    let body = null;
    try { body = await res.json(); } catch { body = null; }
    return { status: res.status, body };
  } catch (error) {
    return { status: 0, body: null, error: String(error?.message || error) };
  }
}

/** One pass over the three checks. Pure apart from fetchImpl. */
export async function smokeOnce({ fetchImpl, api = DEFAULT_API, expectCommit }) {
  const health = await readJson(fetchImpl, `${api}/health`);
  const ready = await readJson(fetchImpl, `${api}/ready`);
  const gated = await readJson(fetchImpl, `${api}/api/workspaces`);
  const checks = [
    {
      name: "health",
      ok: health.status === 200 && health.body?.status === "ok" && (!expectCommit || health.body?.commit === expectCommit),
      detail: health.status === 200
        ? `commit ${health.body?.commit ?? "not reported"}${expectCommit ? ` (expected ${expectCommit})` : ""}`
        : `HTTP ${health.status}${health.error ? ` ${health.error}` : ""}`,
    },
    {
      name: "ready",
      ok: ready.status === 200 && ready.body?.status === "ready",
      detail: `HTTP ${ready.status} ${ready.body?.status ?? ""}`.trim(),
    },
    {
      name: "auth gate",
      ok: gated.status === 401,
      detail: `GET /api/workspaces without credentials → HTTP ${gated.status} (expected 401)`,
    },
  ];
  return { ok: checks.every((c) => c.ok), checks };
}

/** Retries while the new version propagates; gives up after `attempts`. */
export async function runSmoke({ fetchImpl = fetch, api = DEFAULT_API, expectCommit, attempts = 9, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), delayMs = 10_000 } = {}) {
  if (expectCommit && !SHA.test(expectCommit)) throw new Error("expectCommit must be a full 40-character commit SHA");
  let last = null;
  for (let i = 1; i <= attempts; i++) {
    last = await smokeOnce({ fetchImpl, api, expectCommit });
    if (last.ok) return { ...last, attempt: i };
    if (i < attempts) await sleep(delayMs);
  }
  return { ...last, attempt: attempts };
}

export function formatSmoke(result) {
  const lines = result.checks.map((c) => `  ${c.ok ? "ok  " : "FAIL"} ${c.name}: ${c.detail}`);
  if (result.ok) return [`post-deploy smoke: passed (attempt ${result.attempt})`, ...lines].join("\n");
  return [
    "post-deploy smoke: FAILED — the new scan-api version is not healthy.",
    ...lines,
    "",
    "Roll back now, then investigate:",
    "  (cd workers/scan-api && npx wrangler rollback)",
    "Wrangler rolls back to the previous deployment; confirm the prompt.",
  ].join("\n");
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const args = process.argv.slice(2);
  const value = (flag) => { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : undefined; };
  const result = await runSmoke({ api: value("--api") || DEFAULT_API, expectCommit: value("--expect-commit") });
  console.log(formatSmoke(result));
  process.exit(result.ok ? 0 : 1);
}
