#!/usr/bin/env node
//
// GET /api/validation/benchmark is a QA diagnostic that runs live DNS, TLS,
// header and email modules against an arbitrary, unverified domain. It must be
// reachable by a platform admin session only. Every refused request must be
// refused before any scan module runs (no fetch, no rate-limit consumption).
// CI-blocking; no network.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = (...p) => pathToFileURL(path.join(root, "workers", "scan-api", "src", ...p)).href;
const { workspaceInsightRoutes } = await import(src("routes", "workspace-insights.js"));

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) pass++;
  else { fail++; console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
};

const ADMIN = { id: "u_admin", email: "admin@cybermeters.test" };
const MEMBER = { id: "u_member", email: "member@customer.test" };
const ADMIN_TOKEN = { ...ADMIN, api_token_id: "tok_1" };

function ctx({ user, isPlatformAdmin, query = "?domain=victim.example", counters }) {
  const request = new Request(`https://api.example/api/validation/benchmark${query}`);
  return {
    request,
    url: new URL(request.url),
    env: { ADMIN_EMAILS: ADMIN.email },
    json: (body, status = 200) => Response.json(body, { status }),
    serverError: () => Response.json({ error: "server" }, { status: 500 }),
    requireAuth: async () => user,
    requireWorkspaceRole: async () => null,
    consumeApiRateLimit: async () => { counters.rateLimit++; return null; },
    isPlatformAdmin,
  };
}

// Mirrors index.js isPlatformAdmin (ADMIN_EMAILS allowlist).
const realAdmin = async (user, env) => {
  const list = String(env.ADMIN_EMAILS || "").split(",").map((e) => e.trim().toLowerCase()).filter(Boolean);
  return !!user?.email && list.includes(user.email.toLowerCase());
};

async function run(label, opts) {
  const counters = { fetch: 0, rateLimit: 0 };
  const original = globalThis.fetch;
  globalThis.fetch = async () => { counters.fetch++; return new Response("{}", { status: 200 }); };
  let res;
  try { res = await workspaceInsightRoutes(ctx({ ...opts, counters })); }
  finally { globalThis.fetch = original; }
  return { status: res?.status, counters, label };
}

const refused = [
  ["unauthenticated", { user: null, isPlatformAdmin: realAdmin }, 401],
  ["ordinary signed-in account", { user: MEMBER, isPlatformAdmin: realAdmin }, 403],
  ["admin email via API token", { user: ADMIN_TOKEN, isPlatformAdmin: realAdmin }, 403],
  ["admin helper missing (fail closed)", { user: ADMIN, isPlatformAdmin: undefined }, 403],
  ["admin helper throws (fail closed)", { user: ADMIN, isPlatformAdmin: async () => { throw new Error("x"); } }, 403],
  ["admin helper returns truthy non-true", { user: MEMBER, isPlatformAdmin: async () => "yes" }, 403],
  ["ordinary account listing domains", { user: MEMBER, isPlatformAdmin: realAdmin, query: "?all=1" }, 403],
];
for (const [label, opts, want] of refused) {
  const r = await run(label, opts);
  ok(`${label} → ${want}`, r.status === want, `got ${r.status}`);
  ok(`${label}: no scan module ran`, r.counters.fetch === 0, `fetches=${r.counters.fetch}`);
  ok(`${label}: no rate-limit budget consumed`, r.counters.rateLimit === 0, `rl=${r.counters.rateLimit}`);
}

{
  const r = await run("admin list", { user: ADMIN, isPlatformAdmin: realAdmin, query: "?all=1" });
  ok("admin session reaches the diagnostic (?all=1 → 200)", r.status === 200, `got ${r.status}`);
  ok("admin request is rate limited", r.counters.rateLimit === 1);
}
{
  const r = await run("admin scan", { user: ADMIN, isPlatformAdmin: realAdmin });
  ok("admin session runs the benchmark modules", r.counters.fetch > 0, `fetches=${r.counters.fetch}`);
  ok("admin scan returns a response", typeof r.status === "number" && r.status !== 401 && r.status !== 403, `got ${r.status}`);
}

console.log(`validate-benchmark-admin-only: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
