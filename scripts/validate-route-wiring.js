#!/usr/bin/env node
//
// Do backend features reach a screen? Every Worker route that no frontend
// call reaches must be classified in scripts/security/route-wiring.json
// (admin, auth_flow, webhook, internal, external_api, customer_pending,
// deprecated) with a reason. Fails when:
//   • a new route has no screen and no classification;
//   • a classified route is now called by a screen, or no longer exists
//     (the registry must stay true);
//   • a frontend call matches no route at all (it would 404).
// The customer_pending list printed at the end is the honest answer to
// "is backend work waiting to reach customers?".
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  loadTypescript, extractBackendPatterns, extractFrontendCalls, wiringReport, patternMatches,
} from "./security/lib/route-wiring.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const ts = loadTypescript(root);
let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => { if (cond) pass++; else { fail++; console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); } };
const eq = (name, got, want) => ok(name, JSON.stringify(got) === JSON.stringify(want), `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);

/** Registry rules as a pure function (also used by the fixtures below). */
export function registryErrors(patterns, calls, registry) {
  const errors = [];
  const classes = new Set(Object.keys(registry.classes || {}));
  const { unwired, unserved } = wiringReport(patterns, calls);
  const unwiredKeys = new Set(unwired.map((p) => p.key));
  const allKeys = new Set(patterns.map((p) => p.key));
  for (const p of unwired) {
    const e = registry.unwired?.[p.key];
    if (!e) errors.push(`new route with no screen and no classification: ${p.key} (${p.at[0]}) — add it to scripts/security/route-wiring.json`);
    else if (!classes.has(e.class) || typeof e.reason !== "string" || e.reason.trim().length < 10) errors.push(`bad classification for ${p.key}`);
  }
  for (const key of Object.keys(registry.unwired || {})) {
    if (!allKeys.has(key)) errors.push(`stale: ${key} no longer exists — remove it from the registry`);
    else if (!unwiredKeys.has(key)) errors.push(`stale: ${key} is now called by a screen — remove it from the registry`);
  }
  for (const c of unserved) {
    if (!registry.unserved_frontend?.[c.path]) errors.push(`frontend call matches no route (would 404): ${c.path} (${c.at})`);
  }
  for (const p of Object.keys(registry.unserved_frontend || {})) {
    if (!unserved.some((c) => c.path === p)) errors.push(`stale unserved_frontend entry: ${p}`);
  }
  return errors;
}

// ── 1. Fixtures for the extractor and the rules ─────────────────────────────
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "route-wiring-"));
  const be = path.join(dir, "routes.js"), fe = path.join(dir, "api.js"), page = path.join(dir, "Page.jsx");
  fs.writeFileSync(be, `
    const m = url.pathname.match(/^\\/api\\/workspaces\\/([^/]+)\\/things$/);
    if (url.pathname === "/api/account/me") {}
    if (url.pathname.startsWith("/api/public/")) {}
    if (url.pathname === "/api/unused/feature") {}
    const note = "not a route";
  `);
  fs.writeFileSync(fe, `
    export const api = {
      a: (id) => request(\`/workspaces/\${id}/things\`),
      b: (id, q) => request(\`/workspaces/\${id}/things\${q ? \`?\${q}\` : ''}\`),
      c: () => request('/account/me?x=1'),
      d: () => requestBlob(\`/public/\${'x'}/file\`),
      e: (p) => request(p),
      f: () => fetch(\`\${BASE}/missing/route\`),
      g: () => fetch(\`\${BASE.replace(/\\/api$/, '')}/health\`),
    }
  `);
  fs.writeFileSync(page, `export default () => <a href={\`\${BASE || ''}/account/me\`}>x</a>`);
  const pats = extractBackendPatterns(dir, ts, [be]);
  eq("extract: regex, exact and prefix patterns", pats.map((p) => p.key).sort(),
    ["exact:/api/account/me", "exact:/api/unused/feature", "prefix:/api/public/", "re:^\\/api\\/workspaces\\/([^/]+)\\/things$"]);
  const calls = extractFrontendCalls(dir, ts, [fe, page]);
  eq("extract: segment placeholders kept, query suffix and helper(path) dropped, BASE.replace ignored",
    calls.map((c) => c.path), ["/api/workspaces/x1/things", "/api/workspaces/x1/things", "/api/account/me", "/api/public/x1/file", "/api/missing/route", "/api/account/me"]);
  const report = wiringReport(pats, calls);
  eq("report: unwired route found", report.unwired.map((p) => p.key), ["exact:/api/unused/feature"]);
  eq("report: call with no route found", report.unserved.map((c) => c.path), ["/api/missing/route"]);
  const reg = { classes: { customer_pending: "x" }, unwired: {}, unserved_frontend: {} };
  const errs = registryErrors(pats, calls, reg);
  ok("rules: unclassified unwired route fails", errs.some((e) => /new route with no screen.*unused\/feature/.test(e)), errs.join(" | "));
  ok("rules: unserved call fails", errs.some((e) => /would 404.*missing\/route/.test(e)));
  const reg2 = { classes: { customer_pending: "x" }, unwired: { "exact:/api/unused/feature": { class: "customer_pending", reason: "Planned screen, not built yet." }, "exact:/api/account/me": { class: "customer_pending", reason: "Stale entry for a wired route." }, "exact:/api/gone": { class: "customer_pending", reason: "A route that no longer exists." } }, unserved_frontend: { "/api/missing/route": "Known broken call, fixed next PR." } };
  const errs2 = registryErrors(pats, calls, reg2);
  eq("rules: classified OK, stale entries caught", errs2.map((e) => e.split(":")[0]).sort(), ["stale", "stale"]);
  ok("rules: bad class rejected", registryErrors(pats, calls, { ...reg2, unwired: { ...reg2.unwired, "exact:/api/unused/feature": { class: "whatever", reason: "long enough reason" } } }).some((e) => /bad classification/.test(e)));
  ok("match: regex anchors respected", !patternMatches(pats.find((p) => p.kind === "regex"), "/api/workspaces/x1/things/extra"));
  fs.rmSync(dir, { recursive: true, force: true });
}

// ── 2. The real tree ────────────────────────────────────────────────────────
const registry = JSON.parse(fs.readFileSync(path.join(root, "scripts", "security", "route-wiring.json"), "utf8"));
const patterns = extractBackendPatterns(root, ts);
const calls = extractFrontendCalls(root, ts);
ok("tree: routes and calls found", patterns.length > 100 && calls.length > 100, `${patterns.length} routes, ${calls.length} calls`);
const errors = registryErrors(patterns, calls, registry);
ok("tree: every route reaches a screen or is classified; every call has a route", errors.length === 0, `\n  ${errors.join("\n  ")}`);

const byClass = {};
for (const [key, e] of Object.entries(registry.unwired)) (byClass[e.class] ||= []).push(key);
console.log(`Route wiring: ${patterns.length} route patterns, ${calls.length} frontend calls, ${Object.keys(registry.unwired).length} routes without a screen`);
for (const [cls, keys] of Object.entries(byClass).sort()) console.log(`  ${cls}: ${keys.length}`);
console.log("  Built for customers but not on a screen yet (customer_pending):");
for (const key of byClass.customer_pending || []) console.log(`    ${key.replace(/^(re|exact|prefix):/, "")} — ${registry.unwired[key].reason}`);
console.log(`validate-route-wiring: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
