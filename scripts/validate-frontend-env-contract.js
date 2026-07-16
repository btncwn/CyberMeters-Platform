#!/usr/bin/env node
//
// Frontend environment contract — the template matches what the code reads. CI-blocking.
//
// Written because `frontend/.env.example` did not exist. Not "was removed" — it had
// never existed in the repository's history, while `src/api.js` and SettingsPage both
// told developers to "add it to your .env file" and gave them nothing to copy. The
// only guidance was README.md, and README.md was WRONG: it documented
// `VITE_API_BASE_URL=https://api.cybermeters.com`, omitting the trailing `/api`.
//
// That omission is not cosmetic. Requests are built as `${BASE}${path}` with a bare
// path, and the API serves `/api/...` (openapi.json: server `https://api.cybermeters.com`,
// path `/api/auth/login`; only /health and /ready sit outside /api). A developer
// following the README got a 404 on every call. The inverse mistake — adding `/api` to
// the paths as well — is the double-/api bug that silently broke the free-scan lead
// magnet and the GDPR export, and is guarded by `frontend/src/__tests__/api-base.test.js`.
// This suite guards the other half.
//
// The template fix alone was not enough, because the SOURCE carried the same wrong
// value in two more places (fixed together with this suite's §4b):
//   • api.js printed `e.g. VITE_API_BASE_URL=https://api.cybermeters.com` on the
//     failure path — the console told a developer to configure the value that 404s.
//   • WorkspaceEmailProtectionPage built a curl command the CUSTOMER copies from a
//     `BASE || 'https://api.cybermeters.com'` fallback, resolving to /dmarc-ingest
//     when the real route is /api/dmarc-ingest.
// A hint is documentation that happens to live in a .js file, and it drifts the same
// way. StatusPage.jsx corroborates the contract independently: it does
// `(BASE || '').replace(/\/api\/?$/, '')` to recover the origin for /health + /ready —
// which is only meaningful if BASE ends in /api.
//
// The template is documentation, so nothing enforces it at runtime — which is exactly
// why it needs a test. This asserts the CONTRACT, not any value.
//
// Node 24+.
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const examplePath = path.join(root, "frontend", ".env.example");
const srcRoot = path.join(root, "frontend", "src");

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };

// ── 1. The template exists and is committable ────────────────────────────────
ok("frontend/.env.example exists", fs.existsSync(examplePath));
if (!fs.existsSync(examplePath)) {
  console.error("frontend-env-contract validation FAILED");
  process.exit(1);
}
const example = fs.readFileSync(examplePath, "utf8");

// `.gitignore` ignores `.env`, which does NOT match `.env.example` — but a future
// broadening to `.env*` would silently un-commit the template and this suite would
// be testing a file nobody else can see.
let ignored = false;
try {
  execFileSync("git", ["check-ignore", "-q", "frontend/.env.example"], { cwd: root });
  ignored = true;                       // exit 0 => the path IS ignored
} catch { ignored = false; }            // exit 1 => not ignored, which is what we want
ok("frontend/.env.example is not gitignored", !ignored,
   "a .gitignore rule now matches the template — it would never reach another developer");

// ── 2. Parse the template ────────────────────────────────────────────────────
const declared = new Map();
for (const line of example.split("\n")) {
  const t = line.trim();
  if (!t || t.startsWith("#")) continue;
  const m = t.match(/^([A-Z0-9_]+)\s*=\s*(.*)$/);
  if (m) declared.set(m[1], m[2]);
}
ok("the template declares at least one variable", declared.size > 0);

// ── 3. Every variable the code reads is documented, and vice versa ───────────
const consumed = new Set();
const walk = (dir) => {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) { walk(p); continue; }
    if (!/\.(jsx?|tsx?)$/.test(entry.name)) continue;
    const src = fs.readFileSync(p, "utf8");
    for (const m of src.matchAll(/import\.meta\.env\.([A-Z0-9_]+)/g)) {
      if (m[1].startsWith("VITE_")) consumed.add(m[1]);   // MODE/DEV/PROD are Vite built-ins
    }
  }
};
walk(srcRoot);

const undocumented = [...consumed].filter((v) => !declared.has(v));
ok("every VITE_* variable read by the frontend is in .env.example",
   undocumented.length === 0,
   `read but undocumented: ${undocumented.join(", ")}`);

const unused = [...declared.keys()].filter((v) => !consumed.has(v));
ok("every variable in .env.example is actually read by the frontend",
   unused.length === 0,
   `documented but unused (delete it, or it becomes folklore): ${unused.join(", ")}`);

// ── 4. The one variable's shape — the README got this wrong ──────────────────
ok("VITE_API_BASE_URL is documented", declared.has("VITE_API_BASE_URL"));
const base = declared.get("VITE_API_BASE_URL") || "";
ok("the VITE_API_BASE_URL example ends in /api (the API serves /api/*; requests append a bare path)",
   /\/api$/.test(base), `example value was: ${JSON.stringify(base)}`);
ok("the VITE_API_BASE_URL example is an https URL", /^https:\/\//.test(base), base);
ok("the VITE_API_BASE_URL example has no trailing slash (BASE+path would double it)",
   !/\/$/.test(base), base);

// README is the prose half of the same contract; it must not drift back.
const readme = fs.readFileSync(path.join(root, "README.md"), "utf8");
ok("README documents VITE_API_BASE_URL with the /api segment",
   /VITE_API_BASE_URL=https:\/\/[a-z0-9.-]+\/api\b/.test(readme),
   "README shows a base URL without /api — following it 404s every call");
ok("README points at the committed template", /frontend\/\.env\.example/.test(readme));

// ── 4b. The same contract, in the SOURCE a developer actually reads ──────────
// The template and README were only ever half the story: api.js printed its own
// `e.g. VITE_API_BASE_URL=...` hint on the failure path, and it omitted /api — so the
// console told a developer to configure the exact value that 404s. A hint is
// documentation that happens to live in a .js file, and it drifts the same way.
const jsFiles = [];
const collect = (dir) => {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) { collect(p); continue; }
    if (/\.(jsx?|tsx?)$/.test(entry.name)) jsFiles.push(p);
  }
};
collect(srcRoot);

// Every `VITE_API_BASE_URL=<url>` example anywhere in the frontend source.
const srcExamples = [];
for (const f of jsFiles) {
  const src = fs.readFileSync(f, "utf8");
  for (const m of src.matchAll(/VITE_API_BASE_URL=(https?:\/\/[^\s'"`]+)/g)) {
    srcExamples.push({ file: path.relative(root, f), url: m[1] });
  }
}
const badSrcExamples = srcExamples.filter((e) => !/\/api$/.test(e.url));
ok("every VITE_API_BASE_URL example in frontend source ends in /api",
   badSrcExamples.length === 0,
   badSrcExamples.map((e) => `${e.file}: ${e.url}`).join(" | "));

// A `BASE || '<url>'` fallback stands in for BASE, so it must have BASE's shape.
// WorkspaceEmailProtectionPage builds a curl command the CUSTOMER copies from this
// fallback; an /api-less origin there hands them a request that 404s.
const fallbacks = [];
for (const f of jsFiles) {
  const src = fs.readFileSync(f, "utf8");
  for (const m of src.matchAll(/\b(?:BASE|apiBase)\s*\|\|\s*['"`]([^'"`]*)['"`]/g)) {
    fallbacks.push({ file: path.relative(root, f), url: m[1] });
  }
}
// An empty-string fallback ('') is a deliberate "no base" sentinel, not a base URL.
const badFallbacks = fallbacks.filter((f) => f.url !== "" && !/\/api$/.test(f.url));
ok("every BASE fallback URL in frontend source carries BASE's trailing /api",
   badFallbacks.length === 0,
   badFallbacks.map((f) => `${f.file}: ${JSON.stringify(f.url)}`).join(" | "));

// Anchor the contract to the ROUTES, not to a belief about them. If the API ever
// stopped serving under /api, every assertion above would be wrong together — this
// makes that contradiction fail loudly here rather than silently mislead.
const openapi = JSON.parse(fs.readFileSync(path.join(root, "docs", "openapi.json"), "utf8"));
const apiPaths = Object.keys(openapi.paths || {});
const underApi = apiPaths.filter((p) => p.startsWith("/api/"));
ok("openapi still serves the API under /api (the reason BASE ends in /api)",
   underApi.length > 0 && underApi.length >= apiPaths.length - 2,
   `only ${underApi.length}/${apiPaths.length} paths under /api — if the API moved, this contract changed`);
ok("openapi's server has no /api suffix (the segment comes from VITE_API_BASE_URL)",
   (openapi.servers || []).every((s) => !/\/api\/?$/.test(s.url)),
   "a server ending in /api would double the prefix");

// ── 5. No secret may enter the template ──────────────────────────────────────
// Every VITE_* value is inlined into the public client bundle, so a secret here is
// a published secret. Cheap check, catastrophic miss.
ok("the template contains no live Stripe secret", !/sk_live_[0-9a-zA-Z]{24}/.test(example));
ok("the template contains no Stripe test secret", !/sk_test_[0-9a-zA-Z]{24}/.test(example));
ok("the template contains no webhook signing secret", !/whsec_[0-9a-zA-Z]{16}/.test(example));
ok("the template contains no AWS key id", !/AKIA[0-9A-Z]{16}/.test(example));
ok("the template contains no private key block", !/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(example));
ok("the template warns against putting secrets in VITE_* values", /NEVER put a secret/i.test(example));

// A value that looks like a credential rather than a URL.
for (const [k, v] of declared) {
  ok(`${k}: the example value is a placeholder URL, not a credential`,
     v === "" || /^https?:\/\//.test(v),
     `value was: ${JSON.stringify(v)}`);
}

// ── 6. The real .env must never be committed ─────────────────────────────────
let tracked = "";
try {
  tracked = execFileSync("git", ["ls-files", "frontend/.env"], { cwd: root, encoding: "utf8" }).trim();
} catch { tracked = ""; }
ok("the real frontend/.env is not tracked by git", tracked === "", `tracked: ${tracked}`);

console.log(`\nfrontend-env-contract: ${pass} passed, ${fail} failed`);
if (fail > 0) { console.error("frontend-env-contract validation FAILED"); process.exit(1); }
console.log("frontend-env-contract validation passed");
