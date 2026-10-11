// ── Route wiring: which backend routes does a screen actually call? ─────────
//
// Backend patterns: every regex literal starting ^\/api\/ and every "/api/…"
// string in the Worker's router (index.js + routes/**). Frontend calls: every
// path passed to request()/requestBlob()/signInCall() and every `${BASE}/…` template in
// frontend/src (tests excluded). A template placeholder after "/" stands for
// a path segment; any other placeholder (a query string or optional suffix)
// is dropped, as is everything after "?".
//
// Path-level only: the HTTP method is not compared. A broad router regex
// (e.g. ^\/api\/workspaces\/([^/]+)) can serve many paths; the check proves
// that a call has SOME matching route, not which handler answers it.
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

export function loadTypescript(root) {
  return createRequire(path.join(root, "frontend", "package.json"))("typescript");
}

function walk(dir, out = []) {
  for (const f of fs.readdirSync(dir)) {
    const p = path.join(dir, f);
    const st = fs.statSync(p);
    if (st.isDirectory()) { if (!/^(node_modules|__tests__|test)$/.test(f)) walk(p, out); }
    else if (/\.(js|jsx|mjs)$/.test(f) && !/\.test\.(js|jsx)$/.test(f)) out.push(p);
  }
  return out;
}

export function patternKey(p) { return p.kind === "regex" ? `re:${p.src}` : `${p.kind}:${p.text}`; }

export function extractBackendPatterns(root, ts, files = null) {
  const list = files || [path.join(root, "workers/scan-api/src/index.js"), ...walk(path.join(root, "workers/scan-api/src/routes"))];
  const byKey = new Map();
  for (const file of list) {
    const sf = ts.createSourceFile(file, fs.readFileSync(file, "utf8"), ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
    const add = (p, node) => {
      const key = patternKey(p);
      const at = `${path.relative(root, file)}:${sf.getLineAndCharacterOfPosition(node.getStart()).line + 1}`;
      if (byKey.has(key)) byKey.get(key).at.push(at);
      else byKey.set(key, { ...p, key, at: [at] });
    };
    const visit = (n) => {
      if (n.kind === ts.SyntaxKind.RegularExpressionLiteral) {
        const t = n.text, last = t.lastIndexOf("/");
        const src = t.slice(1, last), flags = t.slice(last + 1);
        if (src.startsWith("^\\/api\\/")) add({ kind: "regex", src, flags }, n);
      } else if ((ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) && /^\/api\/[A-Za-z0-9_\-/.:]*$/.test(n.text)) {
        const parent = n.parent;
        const isPrefix = parent && ts.isCallExpression(parent) && ts.isPropertyAccessExpression(parent.expression) && parent.expression.name.text === "startsWith";
        add({ kind: isPrefix ? "prefix" : "exact", text: n.text }, n);
      }
      ts.forEachChild(n, visit);
    };
    visit(sf);
  }
  return [...byKey.values()];
}

// `${BASE}` or `${BASE || ''}` is the API root; anything else (e.g.
// BASE.replace(/\/api$/, '') for /health) is not an /api call.
const IS_BASE = /^BASE(?:\s*\|\|\s*(?:''|""))?$/;

function sampleOf(ts, node) {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  if (!ts.isTemplateExpression(node)) return null;
  let s = node.head.text;
  for (const span of node.templateSpans) {
    const expr = span.expression.getText();
    if (IS_BASE.test(expr) && s === "") s = "{BASE}";
    else if (s.endsWith("/")) s += "x1";
    s += span.literal.text;
  }
  return s;
}

// API helpers in frontend/src/api.js and the argument index that holds the path.
const PATH_HELPERS = new Map([["request", 0], ["requestBlob", 0], ["signInCall", 1]]);

export function extractFrontendCalls(root, ts, files = null) {
  const list = files || walk(path.join(root, "frontend/src"));
  const calls = [];
  for (const file of list) {
    const kind = file.endsWith(".jsx") ? ts.ScriptKind.JSX : ts.ScriptKind.JS;
    const sf = ts.createSourceFile(file, fs.readFileSync(file, "utf8"), ts.ScriptTarget.Latest, true, kind);
    const add = (raw, node) => {
      const p = `/api${raw.split("?")[0].split("#")[0]}`;
      if (p === "/api" || p === "/api/") return; // the generic request(path) helper itself
      calls.push({ path: p, at: `${path.relative(root, file)}:${sf.getLineAndCharacterOfPosition(node.getStart()).line + 1}` });
    };
    const visit = (n) => {
      if (ts.isCallExpression(n) && ts.isIdentifier(n.expression) && PATH_HELPERS.has(n.expression.text) && n.arguments[PATH_HELPERS.get(n.expression.text)]) {
        const s = sampleOf(ts, n.arguments[PATH_HELPERS.get(n.expression.text)]);
        if (s && s.startsWith("/")) add(s, n);
      } else if (ts.isTemplateExpression(n) && n.head.text === "" && IS_BASE.test(n.templateSpans[0]?.expression.getText() || "")) {
        const s = sampleOf(ts, n);
        if (s && s.startsWith("{BASE}")) add(s.slice("{BASE}".length), n);
      }
      ts.forEachChild(n, visit);
    };
    visit(sf);
  }
  return calls;
}

export function patternMatches(p, urlPath) {
  if (p.kind === "regex") { try { return new RegExp(p.src, p.flags).test(urlPath); } catch { return false; } }
  if (p.kind === "prefix") return urlPath.startsWith(p.text);
  return urlPath === p.text;
}

/** Wiring report: which patterns no screen calls; which calls no route serves. */
export function wiringReport(patterns, calls) {
  return {
    unwired: patterns.filter((p) => !calls.some((c) => patternMatches(p, c.path))),
    unserved: calls.filter((c) => !patterns.some((p) => patternMatches(p, c.path))),
  };
}
