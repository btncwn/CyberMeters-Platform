#!/usr/bin/env node
//
// F-004 — recovery instrumentation validator (successor #3).
// Proves the backup/restore ops scripts enforce their contract ON THE REAL `run`
// control flow (main). Two categories are kept visibly separate:
//   * MEASURED — node:crypto AES-256-GCM: a real encrypt→decrypt→hash round-trip and
//     an authenticate-before-release fail-closed proof, run through the scripts' own
//     `--crypto` boundary with ZERO provider access; plus a real materialising
//     backup→restore cycle through a separate-process provider that models BOTH an
//     off-provider store AND a disposable target estate.
//   * NOT MEASURED (runtime) — the wrangler/S3 command envelopes; validated offline
//     only for supported subcommands/flags (no invented commands), never executed.
//     FIFO acceptance and real provider/Wrangler runtime remain NOT MEASURED.
// The fixture provider is a DETERMINISTIC FAKE SECOND PROVIDER: it reports an
// independent provider/account/endpoint/bucket identity, materialises D1 and R2 bytes
// into a target directory, and writes a per-operation ENVIRONMENT CANARY so the
// secret-free provider boundary is proven for EVERY op rather than asserted in prose.
// Author stage: no real backup/restore. CI-blocking. Resolves the tree under F004_ROOT.
//
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = process.env.F004_ROOT ? path.resolve(process.env.F004_ROOT) : path.join(HERE, "..");
const BACKUP = path.join(ROOT, "scripts", "ops", "backup-production-data.sh");
const RESTORE = path.join(ROOT, "scripts", "ops", "restore-production-backup-to-staging.sh");
const DOCS = ["docs/BACKUP-RESTORE-DRILL.md", "docs/07-RELEASE-CHECKLIST.md", "docs/INCIDENT-RESPONSE-PLAN.md", "docs/SECURITY-SDLC-ROADMAP.md"].map((d) => path.join(ROOT, d));
const KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"; // fixed 64-hex test key

// The repository's REAL R2 keyspace is path-shaped. `d1` and `v1/d1/database` are
// deliberate alias probes: under a raw/unencoded scheme they would collide with the
// D1 or manifest slot, which is exactly the successor-2 false-success (finding R1-03).
const REAL_KEYS = ["reports/scan_1.json", "reports/snapshots/ws_9/scan_1/snap_1.json", "d1", "v1/d1/database"];
const DEST_ID = (k) => "v1/r2/" + [...Buffer.from(k, "utf8")].map((b) => {
  const c = String.fromCharCode(b);
  return /[A-Za-z0-9._-]/.test(c) ? c : "%" + b.toString(16).toUpperCase().padStart(2, "0");
}).join("");
const D1_DEST = "v1/d1/database";
const MAN_DEST = "v1/manifest/backup";

// Independent recovery domain reported by the fake second provider.
const DOM = { DP: "s3-compatible-offsite", DA: "acct-recovery-9", DE: "https://s3.us-west-002.example-offsite.com", DB: "f004-offsite" };

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; console.log((cond ? "PASS " : "FAIL ") + name); };
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "f004v-"));
process.on("exit", () => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* best effort */ } });

// ── Deterministic fake SECOND provider (separate process), kept in its own
//    hash-bindable fixture file rather than inlined here. It models an off-provider
//    store shared by backup+restore AND a disposable target estate that really
//    receives replayed D1 bytes and restored R2 objects, reports an independent
//    recovery-domain identity, and writes a per-operation ENVIRONMENT CANARY.
const fakePath = path.join(ROOT, "scripts", "fixtures", "f004-fake-provider.sh");

// Every knob the fake reads is named EXPLICITLY in the provider environment allowlist.
// F004_ENC_KEY / evidence / metadata / expectation names are deliberately absent.
const FAKE_VARS = ["FAKE_STORE", "FAKE_NOW", "FAKE_NOW2", "FAKE_BACKUP_EPOCH", "FAKE_VERIFY", "FAKE_KEYS", "FAKE_MOVING",
  "FAKE_CORRUPT_KEY", "FAKE_SWAP_R2", "FAKE_SWAP_TO", "FAKE_LATE_SWAP", "FAKE_LATE_SWAP_TO", "FAKE_EARLY_SWAP", "FAKE_EARLY_SWAP_TO", "FAKE_DEST_DELETE",
  "FAKE_DP", "FAKE_DA", "FAKE_DE", "FAKE_DB", "FAKE_CREATED_AS", "FAKE_SKIP_REPLAY", "FAKE_SKIP_R2",
  "FAKE_EXTRA_TARGET_KEY", "FAKE_TAMPER_TARGET_D1", "FAKE_TAMPER_TARGET_R2", "FAKE_EVENT_FAIL", "FAKE_EVENT_ACK", "FAKE_SRC_ACCOUNT", "FAKE_INTEGRITY", "FAKE_FK", "FAKE_TABLES", "FAKE_R2"];
const ENV_ALLOW = FAKE_VARS.join(" ");
const DOMAIN_ENV = { F004_DEST_PROVIDER: DOM.DP, F004_DEST_ACCOUNT: DOM.DA, F004_DEST_ENDPOINT: DOM.DE, F004_DEST_BUCKET: DOM.DB };
// Successor #4: the SOURCE account is mandatory and must differ from the destination
// account, and the adapter's bytes must hash to a repository-pinned identity.
const SRC_ACCOUNT = "acct-prod-1";
const ACCOUNT_ENV = { F004_SRC_ACCOUNT: SRC_ACCOUNT };
const ADAPTER = path.join(ROOT, "scripts", "ops", "f004-provider-adapter.sh");
const IDENTITIES = path.join(ROOT, "scripts", "ops", "f004-adapter-identities.txt");

let n = 0;
function run(script, args, env, input) {
  let code = 0, stdout = "";
  try { stdout = execFileSync("bash", [script, ...args], { input: input ?? undefined, env: { ...process.env, ...env }, encoding: input === undefined ? "utf8" : "buffer" }).toString("utf8"); }
  catch (e) { code = typeof e.status === "number" ? e.status : 1; stdout = (e.stdout ? e.stdout.toString() : ""); }
  return { code, stdout };
}
const field = (txt, k) => (txt.match(new RegExp(k + "=(.+)")) || [])[1];
function backup(faults = {}) {
  const store = fs.mkdtempSync(path.join(TMP, `st-${n++}-`));
  const ev = path.join(TMP, `bev-${n}`);
  const r = run(BACKUP, ["run"], { FAKE_STORE: store, F004_PROVIDER_CMD: fakePath, F004_PROVIDER_ENV_ALLOW: ENV_ALLOW, F004_ENC_KEY: KEY, F004_CONFIRM_REAL_RUN: "yes", F004_BACKUP_DEST: "s3+sse://f004-offsite", F004_MAX_AGE: "5000", F004_EVIDENCE_OUT: ev, ...DOMAIN_ENV, ...ACCOUNT_ENV, ...faults });
  const txt = fs.existsSync(ev) ? fs.readFileSync(ev, "utf8") : "";
  const success = /=success/.test(txt);
  return { ...r, success, store, evidence: txt, d1sha: success ? field(txt, "d1_sha256") : null, mansha: success ? field(txt, "manifest_sha256") : null };
}
function restore(store, expectSha, manSha, args = [], faults = {}) {
  const ev = path.join(TMP, `rev-${n++}`);
  const r = run(RESTORE, ["run", ...args], { FAKE_STORE: store, F004_PROVIDER_CMD: fakePath, F004_PROVIDER_ENV_ALLOW: ENV_ALLOW, F004_ENC_KEY: KEY, F004_CONFIRM_REAL_RUN: "yes", F004_RESTORE_TARGET: "drill-x", F004_EXPECT_D1_SHA: expectSha, F004_EXPECT_MANIFEST_SHA: manSha, F004_EVIDENCE_OUT: ev, ...DOMAIN_ENV, ...ACCOUNT_ENV, ...faults });
  const txt = fs.existsSync(ev) ? fs.readFileSync(ev, "utf8") : "";
  const success = /=success/.test(txt);
  return { ...r, success, evidence: txt, restoredSha: success ? field(txt, "restored_d1_sha256") : null };
}
// Every environment a provider process actually received, one entry per invocation.
function canaryEnvs(store) {
  const d = path.join(store, "env");
  if (!fs.existsSync(d)) return [];
  return fs.readdirSync(d).map((f) => ({ op: f.split(".")[0], text: fs.readFileSync(path.join(d, f), "utf8") }));
}

// ── 1. Structural + provider-boundary safety ──
for (const [label, s] of [["backup", BACKUP], ["restore", RESTORE]]) {
  const src = fs.existsSync(s) ? fs.readFileSync(s, "utf8") : "";
  ok(`${label} exists and is executable`, fs.existsSync(s) && (fs.statSync(s).mode & 0o111) !== 0);
  ok(`${label} sets strict bash mode`, /set -euo pipefail/.test(src));
  ok(`${label} uses a separate-process provider protocol, NOT a sourced hook`, /F004_PROVIDER_CMD/.test(src) && !/F004_PROVIDER_HOOK/.test(src) && !/^\s*(\.|source)\s+["']?\$\{?F004_PROVIDER/m.test(src));
  ok(`${label} gates a real run behind F004_CONFIRM_REAL_RUN`, /F004_CONFIRM_REAL_RUN/.test(src));
  ok(`${label} main is not a stub`, !/not implemented here/.test(src));
  ok(`${label} uses node:crypto AES-256-GCM (no external crypto binary)`, /aes-256-gcm/i.test(src) && /createCipheriv|createDecipheriv/.test(src) && !/^[^#\n]*\b(openssl|gpg|age)\s/m.test(src));
  ok(`${label} never exports the encryption key into the ambient environment`, !/^\s*export\s+F004_ENC_KEY/m.test(src) && !/^\s*export\s+F004_PT_(META|HASH)_OUT/m.test(src));
  const invocations = src.match(/"\$F004_PROVIDER_CMD" "\$op"/g) || [];
  const confined = src.match(/"\$\{F004_ENVARGV\[@\]\}" "\$F004_PROVIDER_CMD" "\$op"/g) || [];
  ok(`${label} invokes every provider op through an env -i allowlist`,
    /F004_ENVARGV=\(env -i\)/.test(src) && invocations.length >= 3 && confined.length === invocations.length);
  ok(`${label} delivers the key to the crypto process on fd 3 only`, /3< <\(printf '%s' "\$\{F004_ENC_KEY:-\}"\)/.test(src) && /readFileSync\(3\)/.test(src) && !/F004_ENC_KEY \|\| ""/.test(src));
}
const refuses = (s) => run(s, ["run"], { F004_CONFIRM_REAL_RUN: "no" }).code === 2;
ok("backup refuses a real run without confirmation", refuses(BACKUP));
ok("restore refuses a real run without confirmation", refuses(RESTORE));

// ── 2. node:crypto — MEASURED (through the scripts' own --crypto boundary) ──
const plain = Buffer.from("D1 dump; a semicolon and \x00 a null byte\nrow2\n", "utf8");
const encOnce = () => { try { return execFileSync("bash", [BACKUP, "--crypto", "encrypt"], { input: plain, env: { ...process.env, F004_ENC_KEY: KEY } }); } catch { return Buffer.alloc(0); } };
const encBuf = encOnce();
const encBuf2 = encOnce();
const dec = (() => { try { return execFileSync("bash", [BACKUP, "--crypto", "decrypt"], { input: encBuf, env: { ...process.env, F004_ENC_KEY: KEY } }); } catch { return Buffer.alloc(0); } })();
ok("MEASURED crypto: encrypt→decrypt round-trips to the exact plaintext", Buffer.compare(dec, plain) === 0);
ok("MEASURED crypto: ciphertext differs from plaintext and carries iv+tag overhead", encBuf.length === plain.length + 28);
ok("MEASURED crypto: a fresh 12-byte nonce per encryption (distinct iv, distinct ciphertext)",
  encBuf.length === encBuf2.length && Buffer.compare(encBuf.subarray(0, 12), encBuf2.subarray(0, 12)) !== 0 && Buffer.compare(encBuf, encBuf2) !== 0);
const wrongKey = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const decWrong = run(BACKUP, ["--crypto", "decrypt"], { F004_ENC_KEY: wrongKey }, encBuf);
ok("MEASURED crypto: wrong key fails closed (nonzero, no plaintext released)", decWrong.code !== 0 && decWrong.stdout.length === 0);
const tampered = Buffer.from(encBuf); tampered[20] ^= 1;
const failClosed = (buf) => { let out = Buffer.alloc(0), code = 0; try { out = execFileSync("bash", [BACKUP, "--crypto", "decrypt"], { input: buf, env: { ...process.env, F004_ENC_KEY: KEY } }); } catch (e) { code = e.status; out = e.stdout || Buffer.alloc(0); } return { code, out }; };
const decTamper = failClosed(tampered);
ok("MEASURED crypto: a flipped byte fails closed at tag check with NO plaintext released", decTamper.code !== 0 && decTamper.out.length === 0);
const trunc = failClosed(encBuf.subarray(0, encBuf.length - 1));
ok("MEASURED crypto: a one-byte truncation fails closed with NO plaintext released", trunc.code !== 0 && trunc.out.length === 0);
const shortFrame = failClosed(Buffer.alloc(20, 7));
ok("MEASURED crypto: a sub-28-byte frame fails closed with NO plaintext released", shortFrame.code !== 0 && shortFrame.out.length === 0);
ok("MEASURED crypto: restore --crypto decrypt also round-trips", Buffer.compare((() => { try { return execFileSync("bash", [RESTORE, "--crypto", "decrypt"], { input: encBuf, env: { ...process.env, F004_ENC_KEY: KEY } }); } catch { return Buffer.alloc(0); } })(), plain) === 0);
ok("MEASURED crypto: absent/short key is a terminal STOP", run(BACKUP, ["--crypto", "encrypt"], { F004_ENC_KEY: "short" }, plain).code !== 0);
ok("MEASURED crypto: a non-hex key is a terminal STOP", run(BACKUP, ["--crypto", "encrypt"], { F004_ENC_KEY: "z".repeat(64) }, plain).code !== 0);

// ── 3. Reversible, collision-free destination identity (finding R1-03) ──
{
  const codec = (mode, k) => run(BACKUP, ["--keycodec", mode, k]).stdout.replace(/\n$/, "");
  for (const k of [...REAL_KEYS, "reports/executive/ws_1/monthly/2026-08/executive-report.pdf", "a~b=c+d%e"]) {
    ok(`R2 identity round-trips for the real key shape "${k}"`, codec("decode", codec("encode", k)) === k);
  }
  ok("R2 destination ids are namespaced and slash-free within the namespace",
    REAL_KEYS.every((k) => { const d = codec("dest", k); return d === DEST_ID(k) && d.startsWith("v1/r2/") && !d.slice(6).includes("/"); }));
  ok("an object named `d1` cannot reach the D1 slot", codec("dest", "d1") !== D1_DEST && codec("dest", "d1") === "v1/r2/d1");
  ok("an object named `v1/d1/database` cannot reach the D1 slot", codec("dest", "v1/d1/database") !== D1_DEST);
  const guard = (fn, ...a) => run(BACKUP, ["--selftest", fn, ...a]).code === 0;
  ok("assert_safe_key ACCEPTS the repository's real slash-bearing keyspace",
    guard("assert_safe_key", "reports/scan_1.json") && guard("assert_safe_key", "reports/snapshots/ws/sc/sn.json") && guard("assert_safe_key", "safe/key-1"));
  ok("assert_safe_key still rejects traversal / absolute / empty keys",
    !guard("assert_safe_key", "../evil") && !guard("assert_safe_key", "a/../evil") && !guard("assert_safe_key", "/absolute") && !guard("assert_safe_key", "") && !guard("assert_safe_key", "a//b"));
  ok("assert_dest_identity_free rejects a reserved D1/manifest identity",
    !guard("assert_dest_identity_free", D1_DEST, "|") && !guard("assert_dest_identity_free", MAN_DEST, "|"));
  ok("assert_dest_identity_free rejects a duplicate identity", !guard("assert_dest_identity_free", "v1/r2/x", "|v1/r2/x|") && guard("assert_dest_identity_free", "v1/r2/y", "|v1/r2/x|"));
}

// ── 4. Independent recovery domain (finding R1-04) ──
{
  const dom = (...a) => run(BACKUP, ["--selftest", "assert_recovery_domain", ...a]).code === 0;
  ok("recovery domain ACCEPTS an independent second provider", dom(DOM.DP, DOM.DA, DOM.DE, DOM.DB));
  ok("recovery domain REJECTS the Cloudflare/source provider", !dom("cloudflare", DOM.DA, DOM.DE, DOM.DB) && !dom("r2", DOM.DA, DOM.DE, DOM.DB) && !dom("CloudFlare", DOM.DA, DOM.DE, DOM.DB));
  ok("recovery domain REJECTS an R2/Cloudflare endpoint alias", !dom(DOM.DP, DOM.DA, "https://abc.r2.cloudflarestorage.com", DOM.DB) && !dom(DOM.DP, DOM.DA, "r2+sse://cybermeters-reports", DOM.DB));
  ok("recovery domain REJECTS the source bucket / a production name", !dom(DOM.DP, DOM.DA, DOM.DE, "cybermeters-reports") && !dom(DOM.DP, DOM.DA, DOM.DE, "cybermeters-db"));
  ok("recovery domain REJECTS an incomplete identity", !dom(DOM.DP, "", DOM.DE, DOM.DB) && !dom("", DOM.DA, DOM.DE, DOM.DB));
  ok("a destination LABEL alone is not accepted as recovery-domain proof",
    backup({ F004_BACKUP_DEST: "r2+sse://cybermeters-reports", F004_DEST_PROVIDER: "cloudflare", FAKE_DP: "cloudflare" }).success === false);
  ok("backup REJECTS the source bucket as its declared destination", !backup({ F004_DEST_BUCKET: "cybermeters-reports", FAKE_DB: "cybermeters-reports" }).success);
  ok("backup REJECTS a provider that MEASURES an identity other than the declared one", !backup({ FAKE_DA: "acct-somewhere-else" }).success);
}

// ── 5. Backup execution-path (real main, materialising fake second provider) ──
let happyStore = null;
{
  const happy = backup();
  happyStore = happy;
  ok("BACKUP happy path → exit 0 and a success/freshness record", happy.code === 0 && happy.success);
  ok("BACKUP records the MEASURED destination identity in its evidence",
    happy.success && field(happy.evidence, "dest_provider") === DOM.DP && field(happy.evidence, "dest_account") === DOM.DA
    && field(happy.evidence, "dest_endpoint") === DOM.DE && field(happy.evidence, "dest_bucket") === DOM.DB);
  ok("BACKUP persists a hash-bound manifest at its own namespace",
    happy.success && field(happy.evidence, "manifest_dest") === MAN_DEST && /^[0-9a-f]{64}$/.test(happy.mansha || ""));
  const put = fs.existsSync(path.join(happy.store, ".putkeys")) ? fs.readFileSync(path.join(happy.store, ".putkeys"), "utf8").split("\n").filter(Boolean) : [];
  ok("BACKUP writes every member into a DISJOINT versioned namespace",
    put.includes(D1_DEST) && put.includes(MAN_DEST) && REAL_KEYS.every((k) => put.includes(DEST_ID(k)))
    && new Set(put).size === put.length && put.length === REAL_KEYS.length + 2);
  const faults = [
    ["stored object corrupted", { FAKE_CORRUPT_KEY: DEST_ID(REAL_KEYS[0]) }],
    ["stored object swapped (valid but wrong content)", { FAKE_SWAP_R2: DEST_ID(REAL_KEYS[0]), FAKE_SWAP_TO: DEST_ID(REAL_KEYS[1]) }],
    ["stored manifest swapped (valid but wrong content)", { FAKE_SWAP_R2: MAN_DEST, FAKE_SWAP_TO: D1_DEST }],
    ["moving R2 inventory", { FAKE_MOVING: "1" }],
    ["verification not PASS", { FAKE_VERIFY: "FAIL" }],
    ["unencrypted destination (local path)", { F004_BACKUP_DEST: "/tmp/x.sql" }],
    ["unencrypted destination (remote scheme)", { F004_BACKUP_DEST: "ftp://host/x" }],
    ["stale freshness window", { FAKE_NOW: "1000", FAKE_NOW2: "999999" }],
    ["encryption key absent (STOP)", { F004_ENC_KEY: "" }],
    ["provider missing (STOP)", { F004_PROVIDER_CMD: "/nonexistent-f004" }],
    ["duplicate source key → duplicate destination identity", { FAKE_KEYS: "reports/a.json reports/a.json" }],
    ["destination member vanished after all writes", { FAKE_DEST_DELETE: DEST_ID(REAL_KEYS[1]) }],
    ["destination member replaced after all writes", { FAKE_LATE_SWAP: DEST_ID(REAL_KEYS[0]), FAKE_LATE_SWAP_TO: DEST_ID(REAL_KEYS[1]) }],
    ["destination returned wrong content during the copy only", { FAKE_EARLY_SWAP: DEST_ID(REAL_KEYS[1]), FAKE_EARLY_SWAP_TO: DEST_ID(REAL_KEYS[0]) }],
    ["provider env allowlist names the encryption key", { F004_PROVIDER_ENV_ALLOW: ENV_ALLOW + " F004_ENC_KEY" }],
  ];
  for (const [name, f] of faults) { const r = backup(f); ok(`BACKUP fault "${name}" → non-zero exit and NO success record`, r.code !== 0 && !r.success); }
  const trav = backup({ FAKE_KEYS: "reports/ok.json ../evil" });
  const putLog = fs.existsSync(path.join(trav.store, ".putkeys")) ? fs.readFileSync(path.join(trav.store, ".putkeys"), "utf8") : "";
  ok("BACKUP unsafe R2 key is confined (rejected before it reaches the store)", trav.code !== 0 && !trav.success && !/(^|\n)\.\.\/evil(\n|$)/.test(putLog));
  const bk = backup({ F004_ENC_KEY: "" });
  ok("BACKUP key gate STOPs before any provider action (provider never invoked)", bk.code !== 0 && !fs.existsSync(path.join(bk.store, ".called")));
}

// ── 6. Provider ENVIRONMENT CANARY — secret-free boundary for EVERY op (finding R1-02) ──
{
  const forbidden = [["F004_ENC_KEY", KEY], ["F004_PT_META_OUT", null], ["F004_PT_HASH_OUT", null], ["F004_EVIDENCE_OUT", null], ["F004_EXPECT_D1_SHA", null], ["F004_EXPECT_MANIFEST_SHA", null], ["F004_PROVIDER_CMD", null]];
  const b = backup();
  const r = restore(b.store, b.d1sha, b.mansha);
  ok("canary precondition: the backup and restore both completed through the provider", b.success && r.success);
  const envs = canaryEnvs(b.store);
  ok("canary observed at least one environment per provider operation", envs.length >= 12 && new Set(envs.map((e) => e.op)).size >= 10);
  const leaks = [];
  for (const e of envs) for (const [name, value] of forbidden) {
    if (new RegExp("^" + name + "=", "m").test(e.text)) leaks.push(`${e.op}:${name}`);
    if (value && e.text.includes(value)) leaks.push(`${e.op}:${name}-value`);
  }
  ok("PROVIDER CANARY: no provider operation received the key, hash/evidence paths or expectations", leaks.length === 0);
  if (leaks.length && process.env.F004_DEBUG) console.log("  leaks: " + leaks.join(", "));
  ok("PROVIDER CANARY: every operation ran under a confined environment (allowlist only)",
    envs.every((e) => e.text.split("\n").filter(Boolean).map((l) => l.split("=")[0])
      .every((k) => ["PATH", "LC_ALL", "PWD", "SHLVL", "_"].includes(k) || FAKE_VARS.includes(k))));
  ok("PROVIDER CANARY: the ops that handle plaintext (d1_export/store_put) are covered",
    ["d1_export", "store_put", "store_get", "r2_object", "dest_list", "dest_identity"].every((op) => envs.some((e) => e.op === op)));
}

// ── 7. Restore materialisation, manifest consumption and target binding (R1-01) ──
{
  const b = backup();
  const happy = restore(b.store, b.d1sha, b.mansha);
  ok("RESTORE happy path (reads the backup's own store) → exit 0 and a success record", happy.code === 0 && happy.success);
  ok("byte contract: restored D1 sha equals the backup's recorded sha", happy.success && !!b.d1sha && happy.restoredSha === b.d1sha);
  // MATERIALISATION: the target really holds the exact D1 replay bytes and every object.
  const created = field(happy.evidence, "target");
  ok("RESTORE binds success to the PROVIDER-CREATED target identity", created === "drill-x");
  const tdir = path.join(b.store, "target", created || "drill-x");
  const d1Bytes = fs.existsSync(path.join(tdir, "d1")) ? fs.readFileSync(path.join(tdir, "d1")) : Buffer.alloc(0);
  ok("MATERIALISED: the exact D1 replay bytes reached the target",
    d1Bytes.toString("utf8") === "CREATE TABLE t(a);\nINSERT INTO t VALUES(1);\n" && crypto.createHash("sha256").update(d1Bytes).digest("hex") === b.d1sha);
  const landed = fs.existsSync(path.join(tdir, "r2")) ? fs.readdirSync(path.join(tdir, "r2")).map((f) => f.replace(/~/g, "/")) : [];
  ok("MATERIALISED: every manifest-listed R2 object reached the target with exact bytes",
    landed.length === REAL_KEYS.length && REAL_KEYS.every((k) => landed.includes(k))
    && REAL_KEYS.every((k) => fs.readFileSync(path.join(tdir, "r2", k.replace(/\//g, "~")), "utf8") === `object-bytes-for-${k}`));
  ok("RESTORE reports the number of objects it materially restored", field(happy.evidence, "r2_objects_restored") === String(REAL_KEYS.length));
  ok("RESTORE independently re-read D1 FROM the target", field(happy.evidence, "materialised_d1_sha256") === b.d1sha);
  ok("RESTORE records the measured backup-store identity", field(happy.evidence, "source_bucket") === DOM.DB && field(happy.evidence, "source_provider") === DOM.DP);
  const faults = [
    ["byte-contract break (wrong recorded D1 hash)", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", b.mansha, [], {}],
    ["manifest contract break (wrong recorded manifest hash)", b.d1sha, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", [], {}],
    ["manifest absent from the store", b.d1sha, b.mansha, [], { FAKE_SWAP_R2: MAN_DEST, FAKE_SWAP_TO: D1_DEST }],
    ["production target", b.d1sha, b.mansha, [], { F004_RESTORE_TARGET: "cybermeters-db" }],
    ["unmarked non-production target", b.d1sha, b.mansha, [], { F004_RESTORE_TARGET: "plain-restore" }],
    ["explicit production id (in-place)", b.d1sha, b.mansha, [], { F004_RESTORE_TARGET: "sample-prod", F004_PRODUCTION_IDS: "sample-prod" }],
    ["provider created a DIFFERENT target than requested", b.d1sha, b.mansha, [], { FAKE_CREATED_AS: "drill-other" }],
    ["provider silently skipped the D1 replay", b.d1sha, b.mansha, [], { FAKE_SKIP_REPLAY: "1" }],
    ["provider silently skipped one R2 object", b.d1sha, b.mansha, [], { FAKE_SKIP_R2: REAL_KEYS[1] }],
    ["target holds an object the manifest never listed", b.d1sha, b.mansha, [], { FAKE_EXTRA_TARGET_KEY: "reports/not-in-manifest.json" }],
    ["target received DIFFERENT D1 bytes than were streamed", b.d1sha, b.mansha, [], { FAKE_TAMPER_TARGET_D1: "1" }],
    ["target received DIFFERENT bytes for one R2 object", b.d1sha, b.mansha, [], { FAKE_TAMPER_TARGET_R2: REAL_KEYS[0] }],
    ["D1 Time Travel arg", b.d1sha, b.mansha, ["--timestamp", "2026-01-01"], {}],
    ["restore integrity failed", b.d1sha, b.mansha, [], { FAKE_INTEGRITY: "bad" }],
    ["restore R2 set mismatch", b.d1sha, b.mansha, [], { FAKE_R2: "neq" }],
    ["RPO over budget", b.d1sha, b.mansha, [], { FAKE_BACKUP_EPOCH: "0", FAKE_NOW: "1000", FAKE_NOW2: "1000000" }],
    ["encryption key absent (STOP)", b.d1sha, b.mansha, [], { F004_ENC_KEY: "" }],
    ["provider env allowlist names the encryption key", b.d1sha, b.mansha, [], { F004_PROVIDER_ENV_ALLOW: ENV_ALLOW + " F004_ENC_KEY" }],
    ["backup store is the source recovery domain", b.d1sha, b.mansha, [], { F004_DEST_PROVIDER: "cloudflare", FAKE_DP: "cloudflare" }],
  ];
  let fi = 0;
  for (const [name, exp, man, args, f] of faults) {
    // A FRESH target per fault — otherwise an earlier successful drill's materialised
    // estate would satisfy verify_d1/verify_r2 and mask a skipped replay or object.
    const iso = { F004_RESTORE_TARGET: `drill-f${fi++}`, ...f };
    const rr = restore(b.store, exp, man, args, iso);
    ok(`RESTORE fault "${name}" → non-zero exit and NO success record`, rr.code !== 0 && !rr.success);
  }
  const b2 = backup();
  fs.writeFileSync(path.join(b2.store, "dest", D1_DEST.replace(/\//g, "~")), Buffer.from("tampered-ciphertext"));
  const tam = restore(b2.store, b2.d1sha, b2.mansha);
  ok("byte contract: a tampered stored D1 artefact → restore fails closed", tam.code !== 0 && !tam.success);
  const b3 = backup();
  fs.writeFileSync(path.join(b3.store, "dest", MAN_DEST.replace(/\//g, "~")), Buffer.from("tampered-manifest"));
  const tam2 = restore(b3.store, b3.d1sha, b3.mansha);
  ok("manifest binding: a tampered stored manifest → restore fails closed", tam2.code !== 0 && !tam2.success);
  // CROSS-NAMESPACE ALIAS: forge the stored manifest so the object whose SOURCE key is
  // `v1/d1/database` claims the RAW D1 destination id and the D1 plaintext hash. Every
  // other check then passes — the key still reverses to its source key, the ciphertext
  // still decrypts to the recorded hash, and it would still materialise and verify. Only
  // the namespace guard stands between this and a restore that silently pulls the D1
  // artefact into the R2 object set.
  const b4 = backup();
  const manPath = path.join(b4.store, "dest", MAN_DEST.replace(/\//g, "~"));
  const manPlain = execFileSync("bash", [BACKUP, "--crypto", "decrypt"], { input: fs.readFileSync(manPath), env: { ...process.env, F004_ENC_KEY: KEY } }).toString("utf8");
  const d1line = (manPlain.split("\n").find((l) => l.startsWith("d1\t")) || "").split("\t");
  const forged = manPlain.split("\n").map((l) => {
    const f = l.split("\t");
    if (f.length === 5 && f[0] === "r2" && f[1] === D1_DEST) { f[2] = d1line[1]; f[4] = d1line[3]; }
    return f.join("\t");
  }).join("\n");
  const metaOut = path.join(TMP, `fm-${n++}`);
  fs.writeFileSync(manPath, execFileSync("bash", [BACKUP, "--crypto", "encrypt", metaOut], { input: Buffer.from(forged, "utf8"), env: { ...process.env, F004_ENC_KEY: KEY } }));
  const forgedSha = fs.readFileSync(metaOut, "utf8").split("\t")[0];
  ok("forge precondition: the aliased manifest differs from the original and is re-bound", forged !== manPlain && /^[0-9a-f]{64}$/.test(forgedSha));
  const ns = restore(b4.store, b4.d1sha, forgedSha, [], { F004_RESTORE_TARGET: "drill-ns" });
  ok("RESTORE rejects a manifest destination id outside the r2 namespace (cross-namespace alias)", ns.code !== 0 && !ns.success);
  const freshStore = fs.mkdtempSync(path.join(TMP, "rk-"));
  const rk = restore(freshStore, b2.d1sha, b2.mansha, [], { F004_ENC_KEY: "" });
  ok("RESTORE key gate STOPs before any provider action (provider never invoked)", rk.code !== 0 && !fs.existsSync(path.join(freshStore, ".called")));
}

// ── 8. Envelope validation — offline: supported forms only, no invented commands ──
const banned = /--output\s+-(\s|$)|--file\s+-(\s|$)|r2 object list|openssl|-aes-256-gcm/;
const envOps = { [BACKUP]: ["d1_export /tmp/f", "r2_list", "r2_get K", "store_put N", "store_get N"], [RESTORE]: ["create_d1 drill-x", "replay_d1 drill-x /tmp/f", "check_d1 drill-x PRAGMA", "store_get N", "put_r2 b k"] };
for (const [script, ops] of Object.entries(envOps)) {
  for (const spec of ops) {
    const parts = spec.split(" ");
    const out = run(script, ["--envelope", ...parts]).stdout.trim();
    const label = path.basename(script).split("-")[0] + " envelope " + parts[0];
    ok(`${label} uses only a supported command with no banned/invented form`, out.length > 0 && !banned.test(out) && /^(wrangler|aws) /.test(out));
  }
}
ok("backup d1_export envelope streams to a path (FIFO), never --output -", /wrangler d1 export .* --remote --output /.test(run(BACKUP, ["--envelope", "d1_export", "/tmp/fifo"]).stdout) && !/--output -/.test(run(BACKUP, ["--envelope", "d1_export", "/tmp/fifo"]).stdout));
ok("backup r2_get envelope uses --pipe, never --file -", /--pipe/.test(run(BACKUP, ["--envelope", "r2_get", "K"]).stdout));
ok("dispatchers stay allowlisted (arbitrary selftest/envelope/codec names rejected)",
  run(BACKUP, ["--selftest", "printf"]).code === 3 && run(BACKUP, ["--envelope", "rm"]).code === 3 && run(BACKUP, ["--keycodec", "exec", "x"]).code === 3 && run(RESTORE, ["--selftest", "printf"]).code === 3);

// ── 9. Documentation honesty ──
const VERSIONING = /versioning/i, R2CTX = /\b(r2|bucket|object)\b/i, NEGATION = /\b(no|not|never|without|lacks?|lacking|disabled?|does\s+not|doesn't|has\s+no)\b/i;
const claim = [];
for (const d of DOCS) { const t = fs.existsSync(d) ? fs.readFileSync(d, "utf8") : ""; t.split(/\r?\n/).forEach((l, i) => { if (VERSIONING.test(l) && R2CTX.test(l) && !NEGATION.test(l)) claim.push(`${path.relative(ROOT, d)}:${i + 1}`); }); }
ok("no doc asserts R2 object/bucket versioning (contract item 5)", claim.length === 0);
if (claim.length && process.env.F004_DEBUG) console.log("  " + claim.join(", "));
const drill = fs.existsSync(DOCS[0]) ? fs.readFileSync(DOCS[0], "utf8") : "";
ok("drill doc states R2 has no object versioning", /no object versioning/i.test(drill));
ok("drill doc references both ops scripts", /backup-production-data\.sh/.test(drill) && /restore-production-backup-to-staging\.sh/.test(drill));
ok("drill doc states real backup/restore is Integration/founder territory (no overstated closure)", /integration\s*\/\s*founder/i.test(drill) && /not (broad )?f-004 closure|author-stage/i.test(drill));
ok("drill doc does NOT claim every guard independently fires (honest guard accounting)", /defence-in-depth|defense-in-depth|redundant|not (independently )?reachable|unreachable/i.test(drill));
ok("drill doc documents the manifest, the key channel and the recovery-domain boundary", /manifest/i.test(drill) && /fd 3|file descriptor 3/i.test(drill) && /recovery domain/i.test(drill));
ok("drill doc keeps provider/Wrangler runtime honestly NOT MEASURED", /not measured/i.test(drill));
ok("drill doc states the source account identity is MANDATORY", /source account identity is \*\*MANDATORY\*\*|mandatory/i.test(drill) && /before any provider action/i.test(drill));
ok("drill doc states the adapter is hash-bound to a repository-owned identity", /hash-bound/i.test(drill) && /f004-adapter-identities\.txt/.test(drill));
ok("drill doc states the adapter contacts no provider in the author stage", /contacts no provider in the author stage/i.test(drill) && /F004_ADAPTER_REAL_EXEC/.test(drill));
ok("drill doc documents the F-027 backup_completed producer and its fail-closed ordering",
  /backup_completed/.test(drill) && /only after every verification/i.test(drill) && /INSERT OR IGNORE/.test(drill));
ok("drill doc does not claim the deadman transition itself is proven",
  /must still exercise the real deadman transition/i.test(drill));

// ── 10. Mandatory source-account binding (successor #4, verdict finding R1-04) ──
// Successor-3 defaulted F004_SRC_ACCOUNT to empty and made the same-account rejection
// conditional on it, so an omitted source account produced GUARD_ALLOW and a 129/129
// happy path. Both are now STOPs, bound before any provider action.
{
  const acctGuard = (script, v) => run(script, ["--selftest", "assert_source_account"], v === null ? { F004_SRC_ACCOUNT: "" } : { F004_SRC_ACCOUNT: v }).code === 0;
  for (const [label, s2] of [["backup", BACKUP], ["restore", RESTORE]]) {
    ok(`${label} assert_source_account REJECTS an absent source account`, !acctGuard(s2, null));
    ok(`${label} assert_source_account REJECTS a malformed source account`, !acctGuard(s2, "bad acct!") && !acctGuard(s2, "a/b"));
    ok(`${label} assert_source_account ACCEPTS a well-formed source account`, acctGuard(s2, SRC_ACCOUNT));
    // The same-account rejection must no longer be conditional on the account being supplied.
    const src = fs.readFileSync(s2, "utf8");
    ok(`${label} same-account rejection is UNCONDITIONAL`, /if \[ "\$acct" = "\$F004_SRC_ACCOUNT" \]; then/.test(src) && !/\[ -n "\$F004_SRC_ACCOUNT" \] && \[ "\$acct" = /.test(src));
  }
  // Run-path negatives, on main, with zero provider actions for the absent case.
  const bAbsent = backup({ F004_SRC_ACCOUNT: "" });
  ok("BACKUP run path STOPs when the source account is absent", bAbsent.code !== 0 && !bAbsent.success);
  ok("BACKUP source-account STOP issues ZERO provider actions", !fs.existsSync(path.join(bAbsent.store, ".called")));
  ok("BACKUP run path STOPs when source and destination accounts are identical", !backup({ F004_SRC_ACCOUNT: DOM.DA }).success);
  ok("BACKUP run path PROCEEDS when the accounts are distinct", backup().success);
  const b = backup();
  ok("BACKUP records the bound source account in its evidence", field(b.evidence, "src_account") === SRC_ACCOUNT);
  const rAbsentOpsBefore = canaryEnvs(b.store).map(({ op }) => op).sort();
  const rAbsent = restore(b.store, b.d1sha, b.mansha, [], { F004_SRC_ACCOUNT: "", F004_RESTORE_TARGET: "drill-a1" });
  const rAbsentOpsAfter = canaryEnvs(b.store).map(({ op }) => op).sort();
  ok("RESTORE run path STOPs when the source account is absent", rAbsent.code !== 0 && !rAbsent.success);
  ok("RESTORE source-account STOP issues ZERO provider actions",
    JSON.stringify(rAbsentOpsAfter) === JSON.stringify(rAbsentOpsBefore));
  ok("RESTORE run path STOPs when source and destination accounts are identical",
    !restore(b.store, b.d1sha, b.mansha, [], { F004_SRC_ACCOUNT: DOM.DA, F004_RESTORE_TARGET: "drill-a2" }).success);
  const rOk = restore(b.store, b.d1sha, b.mansha, [], { F004_RESTORE_TARGET: "drill-a3" });
  ok("RESTORE run path PROCEEDS when the accounts are distinct", rOk.success);
  ok("RESTORE records the bound source account in its evidence", field(rOk.evidence, "src_account") === SRC_ACCOUNT);
}

// ── 11. Hash-bound repository-owned provider adapter (finding F004-S3-R1-01) ──
{
  ok("a repository-owned real provider adapter exists and is executable", fs.existsSync(ADAPTER) && (fs.statSync(ADAPTER).mode & 0o111) !== 0);
  ok("a repository-owned adapter identity contract exists", fs.existsSync(IDENTITIES));
  // The contract must describe the files it names, byte for byte.
  const idLines = fs.readFileSync(IDENTITIES, "utf8").split("\n").filter((l) => l.trim() && !l.startsWith("#"));
  const pinned = idLines.map((l) => l.trim().split(/\s+/)).map(([sha, role, rel]) => ({ sha, role, rel }));
  ok("identity contract pins exactly the real adapter and the deterministic fixture",
    pinned.length === 2 && pinned.some((e) => e.role === "real" && e.rel.endsWith("f004-provider-adapter.sh"))
    && pinned.some((e) => e.role === "fixture" && e.rel.endsWith("f004-fake-provider.sh")));
  ok("every pinned identity matches the bytes of the file it names",
    pinned.every((e) => crypto.createHash("sha256").update(fs.readFileSync(path.join(ROOT, e.rel))).digest("hex") === e.sha));
  // A byte-modified adapter must STOP for the identity reason with zero provider actions.
  const modified = path.join(TMP, `mod-adapter-${n++}.sh`);
  fs.writeFileSync(modified, fs.readFileSync(fakePath, "utf8") + "\n# byte-modification\n", { mode: 0o755 });
  ok("the modified adapter really differs from the pinned fixture",
    crypto.createHash("sha256").update(fs.readFileSync(modified)).digest("hex")
      !== crypto.createHash("sha256").update(fs.readFileSync(fakePath)).digest("hex"));
  const bMod = backup({ F004_PROVIDER_CMD: modified });
  ok("BACKUP STOPs on a byte-modified adapter", bMod.code !== 0 && !bMod.success);
  ok("BACKUP adapter-identity STOP issues ZERO provider actions", !fs.existsSync(path.join(bMod.store, ".called")));
  const bPin = backup({ F004_ADAPTER_SHA256: "deadbeef".repeat(8) });
  ok("BACKUP STOPs when an explicit operator pin does not match the adapter bytes", bPin.code !== 0 && !bPin.success);
  const bRole = backup({ F004_REQUIRE_ADAPTER_ROLE: "real" });
  ok("BACKUP STOPs when role `real` is required but a fixture adapter is supplied", bRole.code !== 0 && !bRole.success);
  const bMissingContract = backup({ F004_ADAPTER_IDENTITIES: "/nonexistent-f004-identities" });
  ok("BACKUP STOPs when the identity contract itself is absent", bMissingContract.code !== 0 && !bMissingContract.success);
  const bGood = backup();
  ok("BACKUP records the measured adapter identity and role in its evidence",
    /^[0-9a-f]{64}$/.test(field(bGood.evidence, "adapter_sha256") || "") && field(bGood.evidence, "adapter_role") === "fixture");
  const rMod = restore(bGood.store, bGood.d1sha, bGood.mansha, [], { F004_PROVIDER_CMD: modified, F004_RESTORE_TARGET: "drill-m1" });
  ok("RESTORE STOPs on a byte-modified adapter", rMod.code !== 0 && !rMod.success);
  const rGood = restore(bGood.store, bGood.d1sha, bGood.mansha, [], { F004_RESTORE_TARGET: "drill-m2" });
  ok("RESTORE records the measured adapter identity and role in its evidence",
    /^[0-9a-f]{64}$/.test(field(rGood.evidence, "adapter_sha256") || "") && field(rGood.evidence, "adapter_role") === "fixture");
}

// ── 12. Complete operation → argv / stdin / stdout / exit contract (finding F004-S3-R1-01) ──
// The prior verdict required the adapter's COMPLETE contract to be validated against the
// pinned Wrangler / S3-compatible toolchain without contacting a provider. The adapter
// generates its contract from the same `f004_argv` the real execution path execs, so the
// published contract cannot drift from what a real run would issue.
{
  // Pinned surface. Wrangler flags below were measured from a local `--help` probe and are
  // a conservative superset for the pinned line; AWS forms are the documented streaming
  // shapes. Anything outside this surface fails the contract.
  const WRANGLER_GLOBAL = ["--config", "--cwd", "--env", "--env-file", "--help", "--install-skills", "--version"];
  const SURFACE = {
    wrangler: {
      "d1 export": ["--local", "--remote", "--output", "--no-data", "--no-schema", "--table", "--skip-confirmation"],
      "d1 execute": ["--command", "--file", "--json", "--local", "--persist-to", "--preview", "--remote", "--yes"],
      "d1 create": ["--binding", "--jurisdiction", "--location", "--update-config", "--use-remote"],
      "r2 object get": ["--local", "--persist-to", "--remote", "--jurisdiction", "--file", "--pipe"],
      "whoami": ["--account", "--json"],
      "r2 object put": ["--local", "--persist-to", "--remote", "--jurisdiction", "--file", "--pipe", "--storage-class",
                        "--cache-control", "--content-disposition", "--content-encoding", "--content-language", "--content-type", "--expires", "--force"],
    },
    aws: {
      "s3api list-objects-v2": ["--bucket", "--endpoint-url", "--output", "--query", "--prefix", "--max-items", "--continuation-token"],
      "s3 cp": ["--endpoint-url", "--quiet", "--no-progress", "--expected-size"],
      "sts get-caller-identity": ["--endpoint-url", "--output", "--query"],
    },
    local: { date: ["-u"], cat: [], printf: [] },
  };
  const BANNED = /--output\s+-(\s|$)|--file\s+-(\s|$)|r2 object list|openssl|-aes-256-gcm/;

  const contract = run(ADAPTER, ["--contract"]).stdout.trim().split("\n").filter(Boolean)
    .map((l) => { const [op, kind, stdin, stdout, exit, transform, ...rest] = l.split("\t"); return { op, kind, stdin, stdout, exit, transform, argv: rest.join("\t") }; });
  ok("adapter --contract emits a parseable row per operation",
    contract.length >= 20 && contract.every((c) => c.op && c.kind && c.stdin && c.stdout && c.exit && c.transform && c.argv));
  const TRANSFORMS = new Set(["none", "fifo-stream", "sha256-digest", "confirm-json", "account-id"]);
  ok("every contract entry declares a known runtime transformation", contract.every((c) => TRANSFORMS.has(c.transform)));
  ok("every operation whose protocol answer is NOT the raw command output declares a transform",
    contract.filter((c) => ["record_backup_completed", "verify_d1", "verify_r2", "d1_export", "replay_d1", "src_identity"].includes(c.op))
      .every((c) => c.transform !== "none"));

  // Coverage: every protocol operation either script can issue must have exactly one entry.
  const protocolOps = new Set();
  for (const sc of [BACKUP, RESTORE]) {
    const m = fs.readFileSync(sc, "utf8").match(/^PROVIDER_OPS="([^"]+)"/m);
    if (m) m[1].split(/\s+/).filter(Boolean).forEach((o) => protocolOps.add(o));
  }
  const covered = new Set(contract.map((c) => c.op));
  const uncovered = [...protocolOps].filter((o) => !covered.has(o));
  const extra = [...covered].filter((o) => !protocolOps.has(o));
  ok("adapter contract covers EVERY protocol operation with no extras", protocolOps.size > 0 && uncovered.length === 0 && extra.length === 0);
  if ((uncovered.length || extra.length) && process.env.F004_DEBUG) console.log("  uncovered:", uncovered, "extra:", extra);
  ok("adapter contract has exactly one entry per operation", covered.size === contract.length);

  // stdin/stdout expectations DERIVED from how the ops scripts actually call each op.
  const usage = {};
  for (const sc of [BACKUP, RESTORE]) {
    const src = fs.readFileSync(sc, "utf8");
    for (const m of src.matchAll(/provider_stream\s+([a-z0-9_]+)/g)) (usage[m[1]] ||= {}).stdout = "bytes";
    for (const m of src.matchAll(/provider_sink\s+([a-z0-9_]+)/g)) (usage[m[1]] ||= {}).stdin = "bytes";
    for (const m of src.matchAll(/(^|[^_a-z])provider\s+([a-z0-9_]+)/g)) (usage[m[2]] ||= {}).stdout ||= "text";
  }
  const ioMismatch = contract.filter((c) => {
    const u = usage[c.op]; if (!u) return false;
    if (u.stdout && c.stdout !== u.stdout) return true;
    if (u.stdin && c.stdin !== u.stdin) return true;
    if (!u.stdin && c.stdin === "bytes") return true;
    return false;
  }).map((c) => c.op);
  ok("every contract stdin/stdout matches how the ops scripts actually drive that operation", ioMismatch.length === 0);
  if (ioMismatch.length && process.env.F004_DEBUG) console.log("  io mismatch:", ioMismatch);
  ok("every contract entry declares zero-on-success exit semantics", contract.every((c) => c.exit === "zero-on-success"));

  // argv validated token by token against the pinned surface.
  const argvProblems = [];
  for (const c of contract) {
    const toks = c.argv.split(/\s+/).filter(Boolean);
    const bin = toks[0];
    if (c.kind === "local") {
      if (!Object.prototype.hasOwnProperty.call(SURFACE.local, bin)) { argvProblems.push(`${c.op}: local binary ${bin} not allowlisted`); continue; }
      continue;
    }
    if (bin !== c.kind) { argvProblems.push(`${c.op}: binary ${bin} != declared kind ${c.kind}`); continue; }
    const table = SURFACE[c.kind];
    const sub = Object.keys(table).filter((k) => c.argv.startsWith(`${bin} ${k} `) || c.argv === `${bin} ${k}`)
      .sort((a, b) => b.length - a.length)[0];
    if (!sub) { argvProblems.push(`${c.op}: no pinned subcommand matches "${c.argv}"`); continue; }
    const allowed = new Set([...table[sub], ...(c.kind === "wrangler" ? WRANGLER_GLOBAL : [])]);
    for (const t of toks) if (t.startsWith("--") && !allowed.has(t)) argvProblems.push(`${c.op}: flag ${t} not in pinned surface for "${sub}"`);
    if (BANNED.test(c.argv)) argvProblems.push(`${c.op}: banned/invented form in "${c.argv}"`);
  }
  ok("every contract argv uses only pinned subcommands and flags, with no banned form", argvProblems.length === 0);
  if (argvProblems.length && process.env.F004_DEBUG) console.log("  " + argvProblems.join("\n  "));

  // The FIFO discipline the pinned forms exist for.
  const byOp = Object.fromEntries(contract.map((c) => [c.op, c]));
  ok("d1_export streams bytes while the pinned CLI writes a PATH (never --output -)",
    byOp.d1_export && byOp.d1_export.stdout === "bytes" && /--remote --output /.test(byOp.d1_export.argv) && !/--output -(\s|$)/.test(byOp.d1_export.argv));
  ok("replay_d1 consumes bytes while the pinned CLI reads a PATH (never --file -)",
    byOp.replay_d1 && byOp.replay_d1.stdin === "bytes" && /--remote --file /.test(byOp.replay_d1.argv) && !/--file -(\s|$)/.test(byOp.replay_d1.argv));
  ok("R2 object streaming uses --pipe on both directions",
    /--pipe/.test(byOp.r2_object.argv) && /--pipe/.test(byOp.restore_r2.argv) && /--pipe/.test(byOp.verify_r2.argv));
  ok("object listing uses the S3-compatible adapter (Wrangler has no `r2 object list`)",
    byOp.r2_list.kind === "aws" && byOp.dest_list.kind === "aws" && byOp.target_r2_list.kind === "aws");

  // Pinned toolchain version is bound to the repository's own pin, not restated.
  const declared = run(ADAPTER, ["--pinned-version"]).stdout.trim();
  const pkg = path.join(ROOT, "workers", "scan-api", "package.json");
  const repoPin = fs.existsSync(pkg) ? (JSON.parse(fs.readFileSync(pkg, "utf8")).devDependencies || {}).wrangler
    || (JSON.parse(fs.readFileSync(pkg, "utf8")).dependencies || {}).wrangler : null;
  ok("adapter's declared pinned Wrangler version equals the repository's own pin", !!declared && declared === repoPin);

  // The adapter must never contact a provider in the author stage.
  const realOp = run(ADAPTER, ["now"]);
  ok("adapter REFUSES a real provider operation in the author stage", realOp.code === 4 && realOp.stdout.trim() === "");
  ok("adapter rejects an operation outside its contract", run(ADAPTER, ["not_an_op"]).code === 3);
  ok("adapter --contract and --pinned-version execute no provider command",
    !/exec /.test(run(ADAPTER, ["--contract"]).stdout) && run(ADAPTER, ["--contract"]).code === 0);

  // Optional live probe. Opt-in, and it is only credited as pinned-toolchain proof when the
  // probed binary IS the pinned version. Otherwise the pinned probe stays NOT MEASURED.
  if (process.env.F004_PROBE_CLI === "1") {
    let probed = "";
    try { probed = execFileSync("sh", ["-c", "command -v wrangler >/dev/null 2>&1 && wrangler --version 2>/dev/null | tail -1 || true"], { encoding: "utf8", env: { ...process.env, WRANGLER_SEND_METRICS: "false", CI: "1" } }).trim(); } catch { probed = ""; }
    console.log(`  [probe] local wrangler version: ${probed || "absent"} ; pinned: ${declared} ; ${probed === declared ? "PINNED MATCH" : "NOT the pinned version — advisory only"}`);
  }
}

// ── 13. F-027 bridge: the backup_completed producer (governance amendment) ──
// Accepted F-027 reads operational_events(event_type='backup_completed') for its deadman
// verdict and its own constant comments "F-004 emits the event", but no producer existed
// in product code: /ready returned 200 while the deadman could never leave backup_stale.
// The producer must fire ONLY after full verification, and a backup that cannot durably
// record its event is not a successful backup.
{
  const ledgerOf = (store) => {
    const f = path.join(store, "operational_events.tsv");
    if (!fs.existsSync(f)) return [];
    return fs.readFileSync(f, "utf8").split("\n").filter(Boolean)
      .map((l) => { const [id, ws, type, corr, status, attempts, createdAt] = l.split("\t"); return { id, ws, type, corr, status, attempts, createdAt }; });
  };
  // Accepted derivation, recomputed here independently of the shell implementation.
  const derivedId = (type, corr) => "opev_" + crypto.createHash("sha256").update(`${type} ${corr}`).digest("hex").slice(0, 32);
  const SAFE_TOKEN = /^[\w:.\-]{1,200}$/;   // byte-for-byte the accepted writer's guard

  const good = backup();
  const rows = ledgerOf(good.store);
  ok("F027 happy path records EXACTLY ONE backup_completed event", good.success && rows.length === 1);
  const row = rows[0] || {};
  ok("F027 event carries the migration-108 shape (NULL workspace, ok, attempts 1, DB-defaulted created_at)",
    row.type === "backup_completed" && row.ws === "" && row.status === "ok" && row.attempts === "1" && /^\d{4}-\d{2}-\d{2}T/.test(row.createdAt || ""));
  ok("F027 correlation id is backup:<run-start-epoch>:<manifest-sha256>",
    !!row.corr && new RegExp(`^backup:\\d+:${good.mansha}$`).test(row.corr));
  ok("F027 correlation id satisfies the ACCEPTED writer's safe-token guard", SAFE_TOKEN.test(row.corr || ""));
  ok("F027 event id equals the ACCEPTED deterministic derivation", row.id === derivedId("backup_completed", row.corr));
  ok("F027 evidence reports the recorded event identity", field(good.evidence, "backup_event_id") === row.id
    && field(good.evidence, "backup_event_correlation") === row.corr && field(good.evidence, "backup_event_ack") === "recorded");

  // Nothing may be recorded before full verification passes.
  for (const [label, faults] of [
    ["final verification not PASS", { FAKE_VERIFY: "FAIL" }],
    ["freshness window failed", { FAKE_NOW: "1000", FAKE_NOW2: "999999" }],
    ["R2 set/hash mismatch", { FAKE_SWAP_R2: DEST_ID(REAL_KEYS[0]), FAKE_SWAP_TO: DEST_ID(REAL_KEYS[1]) }],
    ["post-write destination member vanished", { FAKE_DEST_DELETE: DEST_ID(REAL_KEYS[1]) }],
  ]) {
    const r = backup(faults);
    ok(`F027 "${label}" → no success AND zero backup_completed events`, r.code !== 0 && !r.success && ledgerOf(r.store).length === 0);
  }

  // Persistence and confirmation are fail-closed.
  const persistFail = backup({ FAKE_EVENT_FAIL: "1" });
  ok("F027 ledger persistence failure → non-zero exit, NO success record, zero events",
    persistFail.code !== 0 && !persistFail.success && ledgerOf(persistFail.store).length === 0);
  const badAck = backup({ FAKE_EVENT_ACK: "ok" });
  ok("F027 malformed confirmation → non-zero exit and NO success record", badAck.code !== 0 && !badAck.success);
  const wrongRow = backup({ FAKE_EVENT_ACK: `recorded ${derivedId("backup_completed", "backup:0:not-this-run")}` });
  ok("F027 confirmation naming a DIFFERENT row → non-zero exit and NO success record", wrongRow.code !== 0 && !wrongRow.success);

  // The verified backup artefacts survive a ledger failure, so a retry is possible.
  ok("F027 a ledger failure leaves the verified destination artefacts in place for retry",
    fs.existsSync(path.join(persistFail.store, "dest", MAN_DEST.replace(/\//g, "~")))
    && fs.existsSync(path.join(persistFail.store, "dest", D1_DEST.replace(/\//g, "~"))));

  // Retry is idempotent: UNIQUE(event_type, correlation_id) → one logical backup, one row.
  const first = backup();
  const retryEv = path.join(TMP, `retry-${n++}`);
  const retry = run(BACKUP, ["run"], { FAKE_STORE: first.store, F004_PROVIDER_CMD: fakePath, F004_PROVIDER_ENV_ALLOW: ENV_ALLOW,
    F004_ENC_KEY: KEY, F004_CONFIRM_REAL_RUN: "yes", F004_BACKUP_DEST: "s3+sse://f004-offsite", F004_MAX_AGE: "5000",
    F004_EVIDENCE_OUT: retryEv, ...DOMAIN_ENV, ...ACCOUNT_ENV });
  const retryTxt = fs.existsSync(retryEv) ? fs.readFileSync(retryEv, "utf8") : "";
  ok("F027 retry succeeds, is reported as a duplicate, and adds no second row",
    retry.code === 0 && /=success/.test(retryTxt) && field(retryTxt, "backup_event_ack") === "duplicate"
    && ledgerOf(first.store).length === 1);

  // Source binding: the ledger row is SOURCE state, never the recovery destination's.
  const bind = (...a) => run(BACKUP, ["--selftest", "assert_event_source_binding", ...a]).code === 0;
  ok("F027 source binding ACCEPTS a distinct source D1 + source account", bind("cybermeters-db", SRC_ACCOUNT, DOM.DA));
  ok("F027 source binding REJECTS an absent D1 or account", !bind("", SRC_ACCOUNT, DOM.DA) && !bind("cybermeters-db", "", DOM.DA));
  ok("F027 source binding REJECTS attribution to the destination account", !bind("cybermeters-db", DOM.DA, DOM.DA));
  const corrGuard = (c) => run(BACKUP, ["--selftest", "assert_event_correlation", c]).code === 0;
  ok("F027 correlation guard mirrors the accepted safe-token charset",
    corrGuard("backup:1:abc") && !corrGuard("backup 1") && !corrGuard("") && !corrGuard("a/b"));

  // The adapter contract must cover the new operation against the SOURCE database.
  const cRow = run(ADAPTER, ["--contract"]).stdout.trim().split("\n").map((l) => l.split("\t")).find((c) => c[0] === "record_backup_completed");
  ok("adapter contract covers record_backup_completed as a wrangler text op with a confirm-json transform",
    !!cRow && cRow[1] === "wrangler" && cRow[2] === "none" && cRow[3] === "text" && cRow[4] === "zero-on-success" && cRow[5] === "confirm-json");
  ok("adapter writes the ledger to the SOURCE D1, never the recovery destination",
    !!cRow && /wrangler d1 execute <src-d1> --remote --json --command INSERT OR IGNORE INTO operational_events/.test(cRow[6])
    && /'backup_completed'/.test(cRow[6]) && !/<dest-bucket>|<dest-endpoint>|<target-bucket>/.test(cRow[6]));
  ok("adapter ledger INSERT is idempotent and DB-defaults created_at",
    !!cRow && /INSERT OR IGNORE/.test(cRow[6]) && !/created_at/.test(cRow[6]));
  ok("adapter batches the write with an exact confirming SELECT in ONE command",
    !!cRow && /INSERT OR IGNORE[^;]*;\s*SELECT id, workspace_id, event_type, correlation_id, status, attempts FROM operational_events WHERE event_type = 'backup_completed' AND correlation_id =/.test(cRow[6]));
}

// ── 14. Adapter runtime transform: real Wrangler JSON → exact acknowledgement ──
// The adapter previously built the ledger command and let the generic exec hand Wrangler's
// RAW JSON to the caller, while the backup requires exactly `recorded <id>` / `duplicate
// <id>`. The fake provider produced that acknowledgement itself, so the protocol looked
// healthy while the REAL adapter could never satisfy it: a controlled-live run would have
// written the row and then failed its own success gate. These fixtures drive the adapter's
// own parser with representative real Wrangler `d1 execute --json` shapes. NO provider.
{
  const ID = "opev_a44edcc370a96043c797a1e405b03b29";
  const CORR = "backup:1000:58b6391a197f33d074bc0742f5d2c18882466b8f9dcf38265b2ee778f85e4d05";
  const row = (o = {}) => ({ id: ID, workspace_id: null, event_type: "backup_completed", correlation_id: CORR, status: "ok", attempts: 1, ...o });
  const meta = (changes) => ({ served_by: "v3-prod", duration: 0.2143, changes, last_row_id: 0, changed_db: true, rows_read: 1, rows_written: changes });
  const batch = (changes, rows) => JSON.stringify([
    { results: [], success: true, meta: meta(changes) },
    { results: rows, success: true, meta: { served_by: "v3-prod", duration: 0.11, changes: 0, rows_read: 1, rows_written: 0 } },
  ]);
  const confirm = (json) => {
    let out = "", code = 0;
    try { out = execFileSync("bash", [ADAPTER, "--confirm-json", ID, CORR], { input: json, encoding: "utf8" }); }
    catch (e) { code = typeof e.status === "number" ? e.status : 1; out = (e.stdout || "").toString(); }
    return { code, out: out.trim() };
  };
  const okAck = (json, want) => { const r = confirm(json); return r.code === 0 && r.out === `${want} ${ID}`; };
  const failsClosed = (json) => { const r = confirm(json); return r.code !== 0 && r.out === ""; };

  ok("adapter transform: a newly inserted row (changes=1) → `recorded <id>`", okAck(batch(1, [row()]), "recorded"));
  ok("adapter transform: an exact pre-existing row (changes=0) → `duplicate <id>`", okAck(batch(0, [row()]), "duplicate"));
  ok("adapter transform: malformed JSON fails closed", failsClosed("not json at all"));
  ok("adapter transform: empty command output fails closed", failsClosed(""));
  ok("adapter transform: a missing confirming SELECT fails closed",
    failsClosed(JSON.stringify([{ results: [], success: true, meta: meta(1) }])));
  ok("adapter transform: a write reporting failure fails closed",
    failsClosed(JSON.stringify([{ results: [], success: false, meta: meta(1) }, { results: [row()], success: true }])));
  ok("adapter transform: a select reporting failure fails closed",
    failsClosed(JSON.stringify([{ results: [], success: true, meta: meta(1) }, { results: [row()], success: false }])));
  ok("adapter transform: no durable row fails closed", failsClosed(batch(1, [])));
  ok("adapter transform: an ambiguous multi-row result fails closed", failsClosed(batch(1, [row(), row()])));
  ok("adapter transform: a wrong row id fails closed", failsClosed(batch(1, [row({ id: "opev_" + "0".repeat(32) })])));
  ok("adapter transform: a wrong correlation id fails closed", failsClosed(batch(1, [row({ correlation_id: "backup:9:other" })])));
  ok("adapter transform: a non-NULL workspace_id fails closed", failsClosed(batch(1, [row({ workspace_id: "ws_1" })])));
  ok("adapter transform: a wrong event_type fails closed", failsClosed(batch(1, [row({ event_type: "cron_tick" })])));
  ok("adapter transform: a wrong status fails closed", failsClosed(batch(1, [row({ status: "failed" })])));
  ok("adapter transform: wrong attempts fails closed", failsClosed(batch(1, [row({ attempts: 3 })])));
  ok("adapter transform: no inserted-vs-existing signal fails closed",
    failsClosed(JSON.stringify([{ results: [], success: true, meta: {} }, { results: [row()], success: true, meta: {} }])));
  ok("adapter transform: a malformed requested id is refused before any parsing",
    (() => { let c = 0; try { execFileSync("bash", [ADAPTER, "--confirm-json", "not-an-id", CORR], { input: batch(1, [row()]), encoding: "utf8" }); } catch (e) { c = e.status; } return c !== 0; })());

  // The acknowledgement the transform emits is exactly what the backup's gate accepts.
  for (const want of ["recorded", "duplicate"]) {
    const ack = confirm(batch(want === "recorded" ? 1 : 0, [row()])).out;
    ok(`adapter transform: \`${want}\` acknowledgement satisfies the backup's own ack gate`,
      run(BACKUP, ["--selftest", "assert_event_recorded", ack, ID]).code === 0);
  }
  // Raw Wrangler JSON must NEVER satisfy that gate — the defect this closes.
  ok("raw Wrangler JSON does NOT satisfy the backup's ack gate (regression guard)",
    run(BACKUP, ["--selftest", "assert_event_recorded", batch(1, [row()]), ID]).code !== 0);

  // REAL EXEC PATH, provider-free. A `wrangler` STUB is placed first on PATH and the adapter
  // is run with real-exec enabled: it execs the stub, receives representative Wrangler JSON,
  // and must transform+confirm it. No provider, no credential, no network — the control
  // asserts `wrangler` resolves to the stub before running, so a real CLI cannot be reached.
  {
    const stubDir = fs.mkdtempSync(path.join(TMP, "wstub-"));
    const write = (changes, rows) => fs.writeFileSync(path.join(stubDir, "result.json"), batch(changes, rows));
    fs.writeFileSync(path.join(stubDir, "wrangler"),
      `#!/bin/sh\nprintf '%s' "$(cat "$(dirname "$0")/result.json")"\n`, { mode: 0o755 });
    // node must be reachable for the adapter's own transform; the stub dir stays FIRST so
    // `wrangler` still resolves to the stub even though node's dir may also hold a real CLI.
    const stubPath = `${stubDir}:${path.dirname(process.execPath)}:/usr/bin:/bin`;
    const realExec = (changes, rows) => {
      write(changes, rows);
      let out = "", code = 0;
      try {
        out = execFileSync("env", ["-i", `PATH=${stubPath}`, "LC_ALL=C", `F004_ADAPTER_REAL_EXEC=yes`,
          `F004_D1_NAME=cybermeters-db`, "bash", ADAPTER, "record_backup_completed", CORR, ID], { encoding: "utf8", cwd: stubDir });
      } catch (e) { code = typeof e.status === "number" ? e.status : 1; out = (e.stdout || "").toString(); }
      return { code, out: out.trim() };
    };
    const resolved = execFileSync("env", ["-i", `PATH=${stubPath}`, "sh", "-c", "command -v wrangler"], { encoding: "utf8" }).trim();
    ok("real-exec control resolves `wrangler` to the local stub, never a real CLI", resolved === path.join(stubDir, "wrangler"));
    const rec = realExec(1, [row()]);
    ok("adapter REAL exec path transforms stub Wrangler JSON into `recorded <id>`", rec.code === 0 && rec.out === `recorded ${ID}`);
    const dup = realExec(0, [row()]);
    ok("adapter REAL exec path transforms an existing row into `duplicate <id>`", dup.code === 0 && dup.out === `duplicate ${ID}`);
    const wrong = realExec(1, [row({ correlation_id: "backup:9:other" })]);
    ok("adapter REAL exec path fails closed on a wrong durable row", wrong.code !== 0 && wrong.out === "");
    // F-027 END-TO-END: the acknowledgement the REAL path emits satisfies the backup gate,
    // so a verified backup yields the exact source-D1 row ops-health.js consumes.
    ok("F027 healthy path: the REAL adapter acknowledgement satisfies the backup success gate",
      run(BACKUP, ["--selftest", "assert_event_recorded", rec.out, ID]).code === 0
      && run(BACKUP, ["--selftest", "assert_event_recorded", dup.out, ID]).code === 0);
    ok("F027 fail-closed path: an unconfirmed persistence yields NO acknowledgement at all", wrong.out === "");
  }

  // The real path is not a bare exec, and it still contacts no provider in the author stage.
  const adapterSrc = fs.readFileSync(ADAPTER, "utf8");
  ok("adapter does not hand raw command output to the caller for record_backup_completed",
    /if \[ "\$op" = "record_backup_completed" \]; then/.test(adapterSrc)
    && /f004_confirm_json "\$\{2:-\}" "\$\{1:-\}"/.test(adapterSrc));
  ok("adapter still refuses a real record_backup_completed in the author stage",
    run(ADAPTER, ["record_backup_completed", CORR, ID]).code === 4);
}

// ── 15. Successor #5: the four declared transforms, implemented; and the source account
//        bound to the measured credential context (findings F004-S4-R1-01 / -02) ──
// R1 measured that the adapter DECLARED fifo-stream / sha256-digest transforms it did not
// implement (every op but record_backup_completed fell through to a bare exec), and that
// F004_SRC_ACCOUNT was a self-declared label no provider operation was bound to. These
// controls drive the adapter's REAL exec path against a stub that is provably the only
// `wrangler` reachable, and drive both callers through the fixture protocol.
{
  // ── provider-free harness: stub + its own node shim; PATH holds nothing else ──
  const stub = fs.mkdtempSync(path.join(TMP, "wstub5-"));
  fs.symlinkSync(process.execPath, path.join(stub, "node"));
  fs.writeFileSync(path.join(stub, "wrangler"), [
    "#!/bin/sh",
    'mode=""; out=""; file=""; prev=""',
    'for a in "$@"; do',
    '  case "$prev" in --output) out="$a";; --file) file="$a";; esac',
    '  case "$a" in whoami) mode=whoami;; export) mode=export;; execute) mode=execute;; get) mode=get;; esac',
    '  prev="$a"',
    "done",
    'b="$(dirname "$0")"',
    '[ -f "$b/fail" ] && exit 7',
    'case "$mode" in',
    '  whoami)  cat "$b/whoami.json" ;;',
    '  export)  [ -n "$out" ] && cat "$b/export.sql" > "$out" ;;',
    '  execute) [ -n "$file" ] && cat "$file" > "$b/replayed.bin" ;;',
    '  get)     cat "$b/object.bin" ;;',
    '  *) exit 9 ;;',
    "esac",
  ].join("\n") + "\n", { mode: 0o755 });
  const EXPORT_SQL = "CREATE TABLE t(a);\nINSERT INTO t VALUES(1);\n";
  const OBJECT = "OBJECT-BYTES-XYZ";
  fs.writeFileSync(path.join(stub, "export.sql"), EXPORT_SQL);
  fs.writeFileSync(path.join(stub, "object.bin"), OBJECT);
  const whoami = (o) => fs.writeFileSync(path.join(stub, "whoami.json"), JSON.stringify(o));
  whoami({ authType: "api-token", accounts: [{ name: "prod", id: "acct-prod-1" }] });
  const stubPath = `${stub}:/usr/bin:/bin`;
  const sha = (x) => crypto.createHash("sha256").update(x).digest("hex");

  // CONTAINMENT GATE — fail closed before any adapter execution.
  const resolved = execFileSync("env", ["-i", `PATH=${stubPath}`, "sh", "-c", "command -v wrangler"], { encoding: "utf8" }).trim();
  ok("S5 harness: `wrangler` resolves ONLY to the local stub", resolved === path.join(stub, "wrangler"));
  ok("S5 harness: PATH carries no real-CLI directory", !/homebrew|\/usr\/local\/bin/.test(stubPath));
  ok("S5 harness: fails closed when the stub is absent",
    execFileSync("env", ["-i", "PATH=/nonexistent-stub:/usr/bin:/bin", "sh", "-c", "command -v wrangler || echo NONE"], { encoding: "utf8" }).trim() === "NONE");

  const adapter = (args, input) => {
    let out = "", code = 0;
    try {
      out = execFileSync("env", ["-i", `PATH=${stubPath}`, "LC_ALL=C", "WRANGLER_SEND_METRICS=false",
        "F004_ADAPTER_REAL_EXEC=yes", "F004_D1_NAME=cybermeters-db", "F004_R2_BUCKET=cybermeters-reports",
        "F004_TARGET_BUCKET=drill-bucket", "bash", ADAPTER, ...args],
        { encoding: "utf8", input: input ?? "", timeout: 30000, cwd: stub });
    } catch (e) { code = typeof e.status === "number" ? e.status : 1; out = (e.stdout || "").toString(); }
    return { code, out };
  };

  // ── fifo-stream, export direction ──
  const exp = adapter(["d1_export"]);
  ok("S5 d1_export: provider export bytes are emitted on STDOUT", exp.code === 0 && exp.out === EXPORT_SQL);

  // ── fifo-stream, replay direction — and no stale file reuse ──
  fs.writeFileSync(path.join(stub, "replayed.bin"), "OLD_FILE_BYTES");
  const rep = adapter(["replay_d1", "drill-x"], "NEW_STDIN_BYTES");
  ok("S5 replay_d1: OUR stdin reaches the provider's --file path", rep.code === 0
    && fs.readFileSync(path.join(stub, "replayed.bin"), "utf8") === "NEW_STDIN_BYTES");
  ok("S5 replay_d1: stale prior file content is never replayed",
    fs.readFileSync(path.join(stub, "replayed.bin"), "utf8") !== "OLD_FILE_BYTES");

  // ── sha256-digest transforms ──
  const vd = adapter(["verify_d1", "drill-x"]);
  ok("S5 verify_d1: emits exactly one lowercase sha-256 of the RE-EXPORTED state",
    vd.code === 0 && vd.out.trim() === sha(EXPORT_SQL) && /^[0-9a-f]{64}\n?$/.test(vd.out));
  ok("S5 verify_d1: measures restored state, never `SELECT 1` liveness",
    !/SELECT 1/.test(fs.readFileSync(ADAPTER, "utf8").split("verify_d1)")[1].split(";;")[0]));
  const vr = adapter(["verify_r2", "drill-x", "reports/a.json"]);
  ok("S5 verify_r2: emits exactly one lowercase sha-256 of the object",
    vr.code === 0 && vr.out.trim() === sha(OBJECT) && /^[0-9a-f]{64}\n?$/.test(vr.out));
  ok("S5 digests are never the raw provider output",
    vd.out.trim() !== EXPORT_SQL.trim() && vr.out.trim() !== OBJECT);

  // ── account-id transform: measured, ambiguity fails closed ──
  ok("S5 src_identity: measures the account the credential context selects",
    adapter(["src_identity"]).out.trim() === "acct-prod-1");
  whoami({ accounts: [{ id: "a-1" }, { id: "a-2" }] });
  const amb = adapter(["src_identity"]);
  ok("S5 src_identity: an AMBIGUOUS multi-account context fails closed", amb.code !== 0 && amb.out.trim() === "");
  whoami({ accounts: [] });
  ok("S5 src_identity: an empty account set fails closed", adapter(["src_identity"]).code !== 0);
  fs.writeFileSync(path.join(stub, "whoami.json"), "not json");
  ok("S5 src_identity: malformed identity JSON fails closed", adapter(["src_identity"]).code !== 0);
  whoami({ authType: "api-token", accounts: [{ name: "prod", id: "acct-prod-1" }] });

  // ── command failure fails closed on every transform ──
  fs.writeFileSync(path.join(stub, "fail"), "");
  for (const [label, args] of [["d1_export", ["d1_export"]], ["replay_d1", ["replay_d1", "drill-x"]],
    ["verify_d1", ["verify_d1", "drill-x"]], ["verify_r2", ["verify_r2", "drill-x", "k"]], ["src_identity", ["src_identity"]]]) {
    const r = adapter(args, "x");
    ok(`S5 ${label}: a provider command failure fails closed with no success output`, r.code !== 0 && r.out.trim() === "");
  }
  fs.rmSync(path.join(stub, "fail"));

  // ── FIFO hygiene ──
  const adapterSrc = fs.readFileSync(ADAPTER, "utf8");
  ok("S5 fifo: created uniquely with mkfifo (an existing path is refused, so no stale reuse)",
    /mkfifo -m 600 "\$F004_ADAPTER_FIFO"/.test(adapterSrc));
  ok("S5 fifo: private 0700 directory, removed on EXIT and on HUP/INT/TERM",
    /chmod 700 "\$F004_FIFO_DIR"/.test(adapterSrc) && /trap 'f004_fifo_cleanup' EXIT/.test(adapterSrc)
    && /trap 'f004_fifo_cleanup; exit 130' HUP INT TERM/.test(adapterSrc));
  ok("S5 fifo: no adapter stream directory survives a completed run",
    fs.readdirSync("/tmp").filter((f) => f.startsWith("f004-adapter.")).length === 0);
  ok("S5 fifo: plaintext is never staged as a regular file (a fifo is not a file)",
    !/> *"\$F004_FIFO_DIR\/(export|replay|plain)/.test(adapterSrc));

  // ── CALLER BINDING (finding F004-S4-R1-02) — through the real backup/restore run path ──
  const bind = (...a) => run(BACKUP, ["--selftest", "assert_source_account_bound", ...a]).code === 0;
  ok("S5 binding guard ACCEPTS an exact match", bind(SRC_ACCOUNT, SRC_ACCOUNT));
  ok("S5 binding guard REJECTS a mismatch, absent, or malformed measurement",
    !bind(SRC_ACCOUNT, "other-account") && !bind(SRC_ACCOUNT, "") && !bind("", SRC_ACCOUNT) && !bind(SRC_ACCOUNT, "bad acct"));

  const bGood = backup();
  ok("S5 BACKUP proceeds when the declared account equals the measured account", bGood.success);
  ok("S5 BACKUP records the MEASURED source account in evidence",
    field(bGood.evidence, "src_account_measured") === SRC_ACCOUNT);
  // A syntactically valid but FALSE label must be rejected before any other provider action.
  const bFalse = backup({ FAKE_SRC_ACCOUNT: "acct-someone-else" });
  ok("S5 BACKUP STOPs on a syntactically valid but FALSE source-account label",
    bFalse.code !== 0 && !bFalse.success);
  const opsIssued = fs.existsSync(path.join(bFalse.store, "env"))
    ? [...new Set(fs.readdirSync(path.join(bFalse.store, "env")).map((f) => f.split(".")[0]))] : [];
  ok("S5 BACKUP false-label STOP happens BEFORE any other provider action",
    opsIssued.length === 1 && opsIssued[0] === "src_identity");
  const b2 = backup();
  const rGood = restore(b2.store, b2.d1sha, b2.mansha, [], { F004_RESTORE_TARGET: "drill-s5a" });
  ok("S5 RESTORE proceeds when the declared account equals the measured account", rGood.success);
  ok("S5 RESTORE records the MEASURED source account in evidence",
    field(rGood.evidence, "src_account_measured") === SRC_ACCOUNT);
  const rFalse = restore(b2.store, b2.d1sha, b2.mansha, [], { FAKE_SRC_ACCOUNT: "acct-someone-else", F004_RESTORE_TARGET: "drill-s5b" });
  ok("S5 RESTORE STOPs on a syntactically valid but FALSE source-account label",
    rFalse.code !== 0 && !rFalse.success);
}

console.log(`\nF-004 recovery instrumentation: ${pass}/${pass + fail} passed`);
if (fail > 0) { console.error("f004 recovery validation FAILED"); process.exit(1); }
console.log("f004 recovery validation passed");
