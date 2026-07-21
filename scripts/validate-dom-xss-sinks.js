#!/usr/bin/env node
//
// DOM-XSS sink source-guard (Workstream C readiness). The CyberMeters frontend is
// React, which auto-escapes every rendered text node, so stored/reflected data
// rendered as {value} is inherently safe. This guard LOCKS that property: it fails
// if a dangerous DOM sink is introduced anywhere in frontend/src without an
// explicit, reviewed allowlist entry. It also asserts the load-bearing navigation
// sanitiser (NotificationBell.appPath) is still present and origin-locked, since
// alert deep-links are the one place attacker-influenced data reaches navigation.
//
// This is a STATIC guard, not a DAST run — no browser, no payloads. CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const SRC = path.join(ROOT, "frontend", "src");

let pass = 0, fail = 0;
const results = [];
const ok = (name, cond) => { cond ? (pass++, results.push(`PASS ${name}`)) : (fail++, results.push(`FAIL ${name}`)); };

// Dangerous DOM-XSS sinks. Any occurrence in non-test frontend source must be
// explicitly allowlisted below with a reviewed reason — there are currently NONE.
const SINK_PATTERNS = [
  { id: "dangerouslySetInnerHTML", re: /dangerouslySetInnerHTML/ },
  { id: "innerHTML", re: /\.innerHTML\s*=/ },
  { id: "outerHTML", re: /\.outerHTML\s*=/ },
  { id: "insertAdjacentHTML", re: /insertAdjacentHTML\s*\(/ },
  { id: "document.write", re: /document\.write\s*\(/ },
  // eval NOT preceded by a word char, '.', or '-' — excludes CSP keywords like
  // `unsafe-eval` in educational content and identifiers such as `retrieval`.
  { id: "eval", re: /(?<![\w.\-])eval\s*\(/ },
  { id: "new Function", re: /new\s+Function\s*\(/ },
];

// Reviewed exceptions: { file (relative to frontend/src), sink id, reason }.
// EMPTY today — the frontend genuinely uses no raw-HTML sink. A future addition
// must be added here with a security rationale, which is the review checkpoint.
const ALLOWLIST = [];

function walk(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "__tests__" || entry.name === "node_modules") continue;
      out.push(...walk(p));
    } else if (/\.(jsx?|tsx?)$/.test(entry.name) && !/\.test\.|\.spec\./.test(entry.name)) {
      out.push(p);
    }
  }
  return out;
}

const files = walk(SRC);
ok("frontend source tree is scannable (files found)", files.length > 0);

const violations = [];
for (const file of files) {
  const rel = path.relative(SRC, file);
  const text = fs.readFileSync(file, "utf8");
  for (const sink of SINK_PATTERNS) {
    if (!sink.re.test(text)) continue;
    const allowed = ALLOWLIST.some((a) => a.file === rel && a.sink === sink.id);
    if (!allowed) violations.push({ rel, sink: sink.id });
  }
}
ok("no un-allowlisted dangerous DOM sink in frontend/src", violations.length === 0);
if (violations.length) for (const v of violations) results.push(`FAIL   dangerous sink '${v.sink}' in ${v.rel} (add a reviewed allowlist entry or remove the sink)`);

// The one navigation sanitiser that matters: NotificationBell.appPath must
// reject anything that is not a same-origin path (rejecting javascript:, data:,
// and cross-origin absolute URLs — the alert-deep-link XSS/open-redirect vector).
const bellPath = path.join(SRC, "components", "NotificationBell.jsx");
ok("NotificationBell exists", fs.existsSync(bellPath));
if (fs.existsSync(bellPath)) {
  const bell = fs.readFileSync(bellPath, "utf8");
  ok("appPath link sanitiser is present", /function appPath\s*\(/.test(bell));
  ok("appPath rejects protocol-relative URLs (//evil)", /!raw\.startsWith\('\/\/'\)/.test(bell) || /startsWith\("\/\/"\)/.test(bell));
  ok("appPath enforces same-origin on absolute URLs", /u\.origin === window\.location\.origin/.test(bell));
}

// Report.
console.log(`\nDOM-XSS sink source-guard: ${pass}/${pass + fail} passed (scanned ${files.length} files)`);
for (const line of results.filter((r) => r.startsWith("FAIL"))) console.log("  " + line);
if (fail) { console.error("dom-xss-sinks validation FAILED"); process.exit(1); }
console.log("dom-xss-sinks validation passed");
