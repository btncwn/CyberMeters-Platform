// ─────────────────────────────────────────────────────────────────────────────
// Entry-point extractor (shared)
//
// A deterministic, dependency-free static extractor over the Worker source that
// enumerates every security-relevant *entry point* — HTTP handler sites, the
// scheduled/cron handler, and the inbound-email handler — and records the
// authorization guards that lexically govern each one.
//
// It is NOT a semantic proof: it is a *structural* inventory whose value is that
// (a) it is regenerated from source on every run, so a new route cannot silently
// escape the inventory (drift gate), and (b) it flags any workspace/ownership
// scoped handler that has no auth guard in its lexical ancestry (coverage gate).
//
// Scope association uses indentation depth rather than brace counting: the Worker
// source is uniformly 2-space indented, and indentation is immune to the brace
// characters that appear inside regex and template literals (which a naive
// brace counter miscounts). The rule `noDedent(a,b,ind)` — "no code line strictly
// between a and b is shallower than `ind`" — captures both the combined idiom
// (`if (method && path) { requireAuth(); ... }`, guard is INSIDE the block) and
// the nested idiom (`if (match) { requireAuth(); if (method) {...} }`, guard is
// in an ANCESTOR block).
// ─────────────────────────────────────────────────────────────────────────────
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const REPO_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const WORKER_SRC = path.join(REPO_ROOT, "workers", "scan-api", "src");

// Files that contain security-relevant entry points.
export const ENTRY_POINT_FILES = [
  "index.js",
  ...fs.readdirSync(path.join(WORKER_SRC, "routes")).filter((f) => f.endsWith(".js")).sort().map((f) => path.join("routes", f)),
  "cron/scheduled.js",
  "email/inbound.js",
];

// Guards that constitute an authentication/authorization check.
const AUTH_GUARDS = [
  "requireAuth", "requireWorkspaceRole", "requireWorkspaceAccess",
  "requireScanReadAccess", "requireDomainRole", "isPlatformAdmin",
];
// Helpers that scope a query to the caller's accessible workspaces (imply auth
// already ran; recorded but not sufficient alone to mark a handler authed).
const SCOPE_HELPERS = ["getAccessibleWorkspaceIds", "getWorkspaceBillingUserId"];

// Signature-verified / token-gated / intentionally-public entry points. These
// are NOT auth-guarded in the requireAuth sense and must not be flagged as gaps.
// Each carries a short reason so the allowlist is auditable, not a silent bypass.
export const PUBLIC_ALLOWLIST = [
  { match: /^\/health$/, reason: "liveness probe — no tenant data" },
  { match: /^\/ready$/, reason: "readiness probe — no tenant data" },
  { match: /^\/$/, reason: "root banner — no tenant data" },
  { match: /^\/\.well-known\//, reason: "security.txt / well-known — public by spec" },
  { match: /^\/api\/health$/, reason: "health alias — no tenant data" },
  { match: /^\/api\/version$/, reason: "version banner — no tenant data" },
  { match: /^\/api\/plans$/, reason: "public pricing catalogue — no tenant data" },
  { match: /signup|register/, reason: "account creation — pre-auth by definition" },
  { match: /login|\/session$/, reason: "authentication endpoint — pre-auth by definition" },
  { match: /verify-email|verify\/|resend/, reason: "email verification — token-gated, pre-auth" },
  { match: /password|reset|forgot/, reason: "password reset — token-gated, pre-auth" },
  { match: /\/auth\/(microsoft|sso|oauth|callback)/, reason: "SSO/OAuth — provider-token gated" },
  { match: /\/auth\/exchange/, reason: "one-time-code → session exchange — pre-auth by definition" },
  { match: /\/auth\/logout/, reason: "logout — Bearer-token gated (deletes that session); unauthed is a no-op" },
  { match: /\/auth\/mfa\//, reason: "login MFA challenge/recovery — challenge-token gated, fail-closed IP throttle, pre-full-auth" },
  { match: /webhook/, reason: "Stripe webhook — HMAC signature verified before parse" },
  { match: /\/billing\/plans/, reason: "public billing catalogue — no Stripe price IDs, no tenant data" },
  { match: /\/free-scan/, reason: "public lead-gen scan — SSRF-guarded, gated preview, rate-limited" },
  { match: /\/api\/invitations\//, reason: "invitation token flow — opaque-token gated, pre-membership" },
  { match: /dmarc-ingest|\/ingest\/|\/rua|\/tlsrpt|\/inbound/, reason: "report ingestion — endpoint-key / DMARC-trust gated (key binds the workspace)" },
  { match: /^OPTIONS$/, reason: "CORS preflight — no body, no tenant data" },
];

function isPublic(routePath, method) {
  if (method === "OPTIONS") return { reason: "CORS preflight — no body, no tenant data" };
  // Paths may be regex sources with escaped slashes (`\/api\/invitations\/…`);
  // unescape so a literal allowlist pattern matches both literal and regex forms.
  const p = String(routePath ?? "").replace(/\\/g, "");
  return PUBLIC_ALLOWLIST.find((a) => a.match.test(p)) || null;
}

// ── Brace-block model ────────────────────────────────────────────────────────
// Indentation is unreliable here (several route files mix leading tabs on the
// `if` line with leading spaces in the body, from the original index.js split),
// so scope is derived from matched `{ }` blocks via a string/comment/regex/
// template-aware tokenizer. Returns block ranges [openLine, closeLine] (1-based)
// for every structural brace pair, plus innermostBlockContaining(line).
function computeBlocks(src) {
  const blocks = [];
  const stack = [];            // open structural-brace line numbers
  const modes = ["code"];      // code | line | block | sq | dq | tmpl | regex
  const tmplDepth = [];        // brace depth at which each ${…} started
  let line = 1, prev = "";     // prev = last significant non-space code char
  for (let i = 0; i < src.length; i++) {
    const c = src[i], n = src[i + 1];
    const mode = modes[modes.length - 1];
    if (c === "\n") { line++; if (mode === "line") modes.pop(); continue; }
    if (mode === "line") continue;
    if (mode === "block") { if (c === "*" && n === "/") { modes.pop(); i++; } continue; }
    if (mode === "sq") { if (c === "\\") i++; else if (c === "'") modes.pop(); continue; }
    if (mode === "dq") { if (c === "\\") i++; else if (c === '"') modes.pop(); continue; }
    if (mode === "regex") { if (c === "\\") i++; else if (c === "/") modes.pop(); continue; }
    if (mode === "tmpl") {
      if (c === "\\") { i++; continue; }
      if (c === "`") { modes.pop(); continue; }
      if (c === "$" && n === "{") { modes.push("code"); tmplDepth.push(stack.length); i++; continue; }
      continue;
    }
    // mode === code
    if (c === "/" && n === "/") { modes.push("line"); i++; continue; }
    if (c === "/" && n === "*") { modes.push("block"); i++; continue; }
    if (c === "'") { modes.push("sq"); continue; }
    if (c === '"') { modes.push("dq"); continue; }
    if (c === "`") { modes.push("tmpl"); continue; }
    if (c === "/" && /[=(,:[!&|?{;\n]|return|=>/.test(prev || "(")) { modes.push("regex"); continue; }
    if (c === "{") { stack.push(line); }
    else if (c === "}") {
      // Closing the current ${…} template expression?
      if (tmplDepth.length && stack.length === tmplDepth[tmplDepth.length - 1]) {
        tmplDepth.pop(); modes.pop(); continue;
      }
      const open = stack.pop();
      if (open != null) blocks.push({ open, close: line });
    }
    if (!/\s/.test(c)) prev = c;
  }
  blocks.sort((a, b) => a.open - b.open || b.close - a.close);
  const innermost = (ln) => {
    let best = null;
    for (const b of blocks) if (b.open <= ln && b.close >= ln) { if (!best || (b.open >= best.open && b.close <= best.close)) best = b; }
    return best;
  };
  return { blocks, innermost };
}

// ── Line model ───────────────────────────────────────────────────────────────
function indentOf(line) {
  const m = line.match(/^(\s*)/);
  return m ? m[1].replace(/\t/g, "  ").length : 0;
}
function stripComment(line) {
  // Remove a trailing // line comment that is not inside a string/regex. Cheap
  // heuristic: cut at the first `//` that is not preceded by `:` (URL) and not
  // inside an obvious quote. Good enough for indentation/keyword detection.
  const idx = line.indexOf("//");
  if (idx === -1) return line;
  const before = line.slice(0, idx);
  const quotes = (before.match(/["'`]/g) || []).length;
  if (quotes % 2 === 1) return line; // // is inside a string
  if (line[idx - 1] === ":") return line; // e.g. https://
  return before;
}

// ── Path expression extraction ───────────────────────────────────────────────
function extractInlinePath(code, matchVars) {
  // url.pathname === "literal"
  let m = code.match(/url\.pathname\s*===\s*["'`]([^"'`]+)["'`]/);
  if (m) return { kind: "exact", path: m[1] };
  // url.pathname.startsWith("literal") / endsWith
  m = code.match(/url\.pathname\.(startsWith|endsWith)\(\s*["'`]([^"'`]+)["'`]/);
  if (m) return { kind: m[1], path: m[2] };
  // url.pathname.match(/regex/flags)  (inline)
  m = code.match(/url\.pathname\.match\(\s*\/((?:\\.|[^/\\])+)\//);
  if (m) return { kind: "regex", path: "/" + m[1] + "/" };
  // reference to a previously-defined match variable inside the condition
  for (const [name, regex] of matchVars) {
    if (new RegExp(`\\b${name}\\b`).test(code)) return { kind: "regex", path: regex, via: name };
  }
  return null;
}
function extractMethods(code) {
  const methods = [];
  const re = /(?:request|req)\.method\s*===\s*["'`]([A-Z]+)["'`]/g;
  let m;
  while ((m = re.exec(code))) methods.push(m[1]);
  // `["POST","PUT"].includes(request.method)` style
  const inc = code.match(/\[([^\]]+)\]\.includes\(\s*(?:request|req)\.method\s*\)/);
  if (inc) for (const q of inc[1].match(/["'`]([A-Z]+)["'`]/g) || []) methods.push(q.replace(/["'`]/g, ""));
  return [...new Set(methods)];
}

function classifyScope(routePath) {
  if (!routePath) return "unknown";
  if (/\/workspaces\/[^/]+/.test(routePath) || /workspaces\\\//.test(routePath)) return "workspace";
  if (/\/(scans|scan)\//.test(routePath) || /\/reports?\//.test(routePath)) return "resource";
  if (/\/(account|user|me|tokens|sessions|profile)\b/.test(routePath)) return "account";
  if (/\/portfolio/.test(routePath)) return "portfolio";
  if (/\/(admin|platform)\b/.test(routePath)) return "admin";
  if (/webhook|ingest|rua|tlsrpt|inbound/.test(routePath)) return "webhook";
  return "public-or-global";
}

// ── Core: extract handlers from one file ─────────────────────────────────────
export function extractFile(relPath) {
  const abs = path.join(WORKER_SRC, relPath);
  const raw = fs.readFileSync(abs, "utf8");
  const lines = raw.split("\n");

  // Pre-scan: match-variable definitions `const NAME = url.pathname.match(/re/)`
  const matchVars = new Map();
  for (const line of lines) {
    const m = stripComment(line).match(/(?:const|let|var)\s+(\w+)\s*=\s*url\.pathname\.match\(\s*\/((?:\\.|[^/\\])+)\//);
    if (m) matchVars.set(m[1], "/" + m[2] + "/");
    const m2 = stripComment(line).match(/(?:const|let|var)\s+(\w+)\s*=\s*url\.pathname\s*===\s*["'`]([^"'`]+)["'`]/);
    if (m2) matchVars.set(m2[1], m2[2]);
  }

  const { innermost } = computeBlocks(raw);

  const model = lines.map((line, i) => {
    const code = stripComment(line);
    return {
      n: i + 1,
      code,
      blank: code.trim() === "",
      methods: extractMethods(code),
      inlinePath: extractInlinePath(code, matchVars),
      guards: AUTH_GUARDS.filter((g) => new RegExp(`\\b${g}\\(`).test(code)),
      scopeHelpers: SCOPE_HELPERS.filter((g) => new RegExp(`\\b${g}\\(`).test(code)),
      block: innermost(i + 1),  // innermost brace-block containing this line
    };
  });

  // Governing path for a handler H = the path expression on H's own line, else the
  // path condition on the `if (...) {` line that opened any block CONTAINING H
  // (walk enclosing blocks outward, nearest first).
  function governingPath(h) {
    if (h.inlinePath) return h.inlinePath;
    // Collect blocks that contain h.n, then take the nearest opener's inlinePath.
    const containing = [];
    for (const l of model) {
      if (l.block && l.block.open <= h.n && l.block.close >= h.n) containing.push(l.block);
    }
    const uniq = [...new Map(containing.map((b) => [b.open + ":" + b.close, b])).values()]
      .sort((a, b) => b.open - a.open); // nearest opener first
    for (const b of uniq) {
      const opener = model[b.open - 1];
      if (opener && opener.inlinePath) return opener.inlinePath;
    }
    return null;
  }

  const handlers = [];
  for (const h of model) {
    if (h.methods.length === 0) continue;
    // Skip method-checks that are not route dispatch — variable assignments /
    // return-expressions such as the global rate-limit tiering line
    // `const isReadRequest = request.method === "GET" || …`, which is middleware,
    // not a handler. Real routes always dispatch through `if (…) {`.
    if (/^\s*(const|let|var|return)\b/.test(h.code) && !/\bif\s*\(/.test(h.code)) continue;
    const gp = governingPath(h);
    const routePath = gp ? gp.path : null;
    // A guard governs handler H iff it is lexically INSIDE H's own block (Bh —
    // including a nested try/if, as in email-protection.js), OR inside a block
    // that strictly ENCLOSES H and appears before H (guard at the top of an outer
    // `if (match) { requireAuth(); if (method){…} }`). A guard in a sibling route
    // block is neither, so it is not associated. Bh = innermost block containing
    // the handler's `if (…) {` line, i.e. the block it opens.
    const Bh = h.block;
    const isAncestor = (x, y) => x && y && x.open <= y.open && x.close >= y.close && (x.open !== y.open || x.close !== y.close);
    const authGuards = new Set();
    const scopeHelpers = new Set();
    for (const l of model) {
      if (l.blank || (l.guards.length === 0 && l.scopeHelpers.length === 0)) continue;
      const insideHandler = Bh && Bh.open <= l.n && l.n <= Bh.close;
      const enclosingBefore = isAncestor(l.block, Bh) && l.n < h.n;
      if (!insideHandler && !enclosingBefore) continue;
      l.guards.forEach((g) => authGuards.add(g));
      l.scopeHelpers.forEach((g) => scopeHelpers.add(g));
    }
    for (const method of h.methods) {
      handlers.push({
        method,
        path: routePath,
        path_kind: gp ? gp.kind : null,
        file: `workers/scan-api/src/${relPath}`,
        line: h.n,
        scope: method === "OPTIONS" ? "preflight" : classifyScope(routePath),
        auth_guards: [...authGuards].sort(),
        scope_helpers: [...scopeHelpers].sort(),
        authed: authGuards.size > 0,
      });
    }
  }
  return handlers;
}

// ── Non-HTTP entry points (event handlers) — recorded explicitly ─────────────
export function extractEventHandlers() {
  const out = [];
  const scheduled = fs.readFileSync(path.join(WORKER_SRC, "index.js"), "utf8");
  if (/async\s+scheduled\s*\(/.test(scheduled)) {
    out.push({
      method: "CRON", path: "scheduled()", path_kind: "event",
      file: "workers/scan-api/src/index.js",
      line: scheduled.split("\n").findIndex((l) => /async\s+scheduled\s*\(/.test(l)) + 1,
      scope: "cron", auth_guards: ["platform-cron-trigger"], scope_helpers: [], authed: true,
      note: "Cloudflare Cron trigger — no external caller; each worker-item write is workspace-scoped by the query, not by a request session.",
    });
  }
  const inbound = path.join(WORKER_SRC, "email", "inbound.js");
  if (fs.existsSync(inbound)) {
    out.push({
      method: "EMAIL", path: "email()", path_kind: "event",
      file: "workers/scan-api/src/email/inbound.js", line: 1,
      scope: "email", auth_guards: ["cloudflare-email-routing", "dmarc-trust"], scope_helpers: [], authed: true,
      note: "Cloudflare Email Routing inbound — sender trust is header-From + DMARC record-not-drop; recipient domain resolves the target workspace.",
    });
  }
  return out;
}

export function extractAll() {
  const http = ENTRY_POINT_FILES.flatMap(extractFile);
  const events = extractEventHandlers();
  const all = [...http, ...events];
  // Deterministic order for stable drift diffs.
  all.sort((a, b) => (a.file + a.line + a.method).localeCompare(b.file + b.line + b.method) ||
                     a.line - b.line);
  return all;
}

export function summarise(entries) {
  const byScope = {};
  for (const e of entries) (byScope[e.scope] ??= { total: 0, authed: 0 }).total++, (e.authed && byScope[e.scope].authed++);
  const gaps = entries.filter((e) => !e.authed && ["workspace", "resource", "account", "portfolio", "admin"].includes(e.scope) && !isPublic(e.path || "", e.method));
  return { total: entries.length, byScope, gaps };
}

export { isPublic };
