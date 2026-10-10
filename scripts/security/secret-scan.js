#!/usr/bin/env node
// CI "Secret scan (tracked files)".
//
// The pattern and pathspec are unchanged from the previous inline `git grep`
// step. The one addition is an exact-line exception list for harmless code
// lines that contain a private-key header as a parser pattern or as a test
// template around a runtime-generated key. Each exception is pinned by
// path + SHA-256 of the full line text and permits exactly one occurrence:
//   - any other matching line in the same file (e.g. a real key) still fails;
//   - the pinned line appearing a second time still fails;
//   - the pinned line copied into any other file still fails;
//   - an exception that no longer matches anything fails (no stale entries).
// Editing a pinned line changes its hash, so the scan fails until it is
// re-pinned here deliberately.
//
// Before scanning the repository, must-fail controls run in a throwaway git
// repository: real keys generated at runtime are added to the excepted files
// and the scan must fail. If any control passes, the step fails.
//
// Findings are reported as path:line + pattern family only — the matched text
// is never echoed, so a real secret does not end up in the public CI log.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export const REPO_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
export const SECRET_PATTERN = "(-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{24})";
export const PATHSPEC = Object.freeze([".", ":!.github/**", ":!*.md"]);

export const EXACT_LINE_EXCEPTIONS = Object.freeze([
  Object.freeze({
    path: "workers/scan-api/src/lib/domain-connect.js",
    line_sha256: "637cc5ed812ec28f29d4ca508ae9b3996e3951fc9160d9db7119d264ff22e3c5",
    why: "pemToDer(): regex literal that strips the PKCS#8 header from the configured Worker secret; no key material.",
  }),
  Object.freeze({
    path: "scripts/validate-domain-verification-integrity.js",
    line_sha256: "9c9b52da6ffa0e2a23b6624e0f8072fc388b0f0af5c44e2f86e1365ae96c74c7",
    why: "Domain Connect test: PEM template around a key generated in memory by crypto.subtle at test time; no key material.",
  }),
]);

const sha256 = (text) => crypto.createHash("sha256").update(text, "utf8").digest("hex");

function family(text) {
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(text)) return "private-key header";
  if (/AKIA[0-9A-Z]{16}/.test(text)) return "AWS access key id";
  if (/sk_live_[0-9a-zA-Z]{24}/.test(text)) return "Stripe live secret key";
  return "secret pattern";
}

// Returns { ok, records } or { ok:false, error } — a git failure is never "clean".
export function grepTrackedFiles(root) {
  const res = spawnSync("git", ["grep", "-nIzE", "-e", SECRET_PATTERN, "--", ...PATHSPEC], {
    cwd: root, encoding: "utf8", maxBuffer: 64 * 1024 * 1024,
  });
  if (res.status === 1 && !res.stderr) return { ok: true, records: [] };
  if (res.status !== 0) return { ok: false, error: `git grep exited ${res.status}: ${String(res.stderr || res.error || "").trim()}` };
  const records = res.stdout.split("\n").filter(Boolean).map((rec) => {
    const [file, line, ...rest] = rec.split("\0");
    return { path: file, line: Number(line), text: rest.join("\0") };
  });
  return { ok: true, records };
}

export function evaluate(records, exceptions = EXACT_LINE_EXCEPTIONS) {
  const used = new Map();
  const violations = [];
  for (const record of records) {
    const hash = sha256(record.text);
    const index = exceptions.findIndex((e) => e.path === record.path && e.line_sha256 === hash);
    if (index === -1) { violations.push(record); continue; }
    const count = (used.get(index) || 0) + 1;
    used.set(index, count);
    if (count > 1) violations.push(record);
  }
  const stale = exceptions.filter((_, index) => !used.has(index));
  return { violations, stale };
}

export function scan(root, exceptions = EXACT_LINE_EXCEPTIONS) {
  const grep = grepTrackedFiles(root);
  if (!grep.ok) return { ok: false, error: grep.error, violations: [], stale: [] };
  const { violations, stale } = evaluate(grep.records, exceptions);
  return { ok: violations.length === 0 && stale.length === 0, violations, stale };
}

function git(cwd, args) {
  const res = spawnSync("git", args, { cwd, encoding: "utf8" });
  if (res.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${res.stderr}`);
}

function realKeys() {
  const pkcs8 = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  }).privateKey;
  const pkcs1 = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "pkcs1", format: "pem" },
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
  }).privateKey;
  return { pkcs8, pkcs1 };
}

// Each control mutates a fresh copy of the excepted files and must FAIL on the
// named file. `expect` is the path whose violation (or stale entry) proves it.
export function mustFailControls(root = REPO_ROOT) {
  const [dc, val] = EXACT_LINE_EXCEPTIONS.map((e) => e.path);
  // The fixtures carry only the pinned lines, so the self-test is independent of
  // whatever else the real files contain — a real secret elsewhere in them is
  // reported by the repository scan below with its path:line.
  const pinned = new Map();
  for (const exception of EXACT_LINE_EXCEPTIONS) {
    let text = "";
    try { text = fs.readFileSync(path.join(root, exception.path), "utf8"); } catch { text = ""; }
    const line = text.split("\n").find((l) => sha256(l) === exception.line_sha256);
    if (line === undefined) {
      return [{ name: `pinned line present in ${exception.path}`, ok: false,
        detail: "not found — the line changed or was removed; re-pin or delete this exception deliberately" }];
    }
    pinned.set(exception.path, line);
  }
  const pinnedLine = (file) => pinned.get(file);
  const keys = realKeys();
  const upper = (n) => Array.from(crypto.randomBytes(n), (b) => "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[b % 32]).join("");
  const append = (extra) => (src) => `${src}\n${extra}\n`;

  const controls = [
    { name: "real PKCS#8 key appended to domain-connect.js", file: dc, mutate: append(keys.pkcs8), expect: dc },
    { name: "real PKCS#8 key appended to the Domain Connect test", file: val, mutate: append(keys.pkcs8), expect: val },
    { name: "real PKCS#1 key appended to domain-connect.js", file: dc, mutate: append(keys.pkcs1), expect: dc },
    { name: "real key placed on the same line as the pinned expression", file: dc,
      mutate: (src) => src.replace(pinnedLine(dc), `${pinnedLine(dc)} // ${keys.pkcs8.split("\n")[0]}`), expect: dc },
    { name: "pinned line duplicated in the same file", file: val,
      mutate: (src) => src.replace(pinnedLine(val), `${pinnedLine(val)}\n${pinnedLine(val)}`), expect: val },
    { name: "pinned line copied into a different file", file: "workers/scan-api/src/lib/copied.js",
      mutate: () => `${pinnedLine(dc)}\n`, expect: "workers/scan-api/src/lib/copied.js" },
    { name: "pinned line removed (stale exception)", file: dc,
      mutate: (src) => src.replace(pinnedLine(dc), "    .replace(/x/, \"\")"), expect: dc },
    { name: "AWS key id in an excepted file", file: dc, mutate: append(`// AKIA${upper(16)}`), expect: dc },
    { name: "Stripe live key in an excepted file", file: val,
      mutate: append(`// sk_live_${crypto.randomBytes(12).toString("hex")}`), expect: val },
  ];

  const results = [];
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "secret-scan-"));
  try {
    // Baseline: the pinned expressions on their own must scan clean.
    const seed = (dir) => {
      fs.mkdirSync(dir, { recursive: true });
      git(dir, ["init", "-q"]);
      for (const file of [dc, val]) {
        fs.mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
        fs.writeFileSync(path.join(dir, file), `// fixture\n${pinnedLine(file)}\n// fixture\n`);
      }
    };
    const baseDir = path.join(tmp, "baseline");
    seed(baseDir);
    git(baseDir, ["add", "-A"]);
    const base = scan(baseDir);
    results.push({ name: "baseline: pinned expressions alone scan clean", ok: base.ok,
      detail: base.error || [...base.violations.map((v) => v.path), ...base.stale.map((s) => `stale ${s.path}`)].join(", ") });

    controls.forEach((control, i) => {
      const dir = path.join(tmp, `control-${i}`);
      seed(dir);
      const target = path.join(dir, control.file);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      const before = fs.existsSync(target) ? fs.readFileSync(target, "utf8") : "";
      fs.writeFileSync(target, control.mutate(before));
      git(dir, ["add", "-A"]);
      const r = scan(dir);
      const caught = !r.error && !r.ok &&
        (r.violations.some((v) => v.path === control.expect) || r.stale.some((s) => s.path === control.expect));
      results.push({ name: `must fail: ${control.name}`, ok: caught,
        detail: r.error || (caught ? "" : "scan passed — exception is too broad") });
    });
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
  return results;
}

function main() {
  let failed = false;
  for (const r of mustFailControls()) {
    console.log(`${r.ok ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
    if (!r.ok) failed = true;
  }
  if (failed) {
    console.log("::error::Secret-scan self-test failed — an exact-line exception is stale or too broad");
    process.exit(1);
  }

  const result = scan(REPO_ROOT);
  if (result.error) {
    console.log(`::error::Secret scan could not run: ${result.error}`);
    process.exit(1);
  }
  for (const v of result.violations) console.log(`${v.path}:${v.line}: ${family(v.text)}`);
  for (const s of result.stale) console.log(`stale exception: ${s.path} (${s.line_sha256.slice(0, 12)}…) no longer matches any line`);
  if (!result.ok) {
    console.log("::error::Potential secret found in tracked files — remove it and rotate the credential");
    process.exit(1);
  }
  console.log(`No obvious secrets in tracked files (${EXACT_LINE_EXCEPTIONS.length} exact-line exceptions verified).`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
