#!/usr/bin/env node
//
// F-004 — execution-path mutation proof (successor #3).
// Each mutant reintroduces a defect — main is a stub, main bypasses a load-bearing
// guard, the adapter hands raw command output back instead of parsing and confirming it,
// the GCM decrypt releases plaintext before the tag is authenticated, a
// materialisation step is removed, the provider regains ambient environment
// inheritance, or the destination namespace collapses back to raw keys — in a
// DEDICATED THROWAWAY git worktree (never the root checkout). Every worktree is
// verified GREEN first, then the mutation is proven to make
// `validate-f004-recovery-instrumentation.js` FALL. Anchors are unique. CI-blocking.
//
// HONEST GUARD ACCOUNTING — the following run-path guards are deliberately given NO
// kill-mutant because a different guard covers their distinguishing case, so removing
// them alone cannot change an exit code. They are retained as defence-in-depth and are
// unit-covered; the suite does NOT claim every guard independently fires:
//   * assert_not_plaintext_local (backup) / assert_not_in_place (restore) — a stronger
//     preceding guard rejects their inputs first on the run path.
//   * assert_d1_hash_match — belt-and-suspenders over GCM authentication; a store
//     returning a DIFFERENT validly-encrypted D1 object is caught by the post-write
//     destination re-read instead.
//   * assert_manifest_binding (backup) — the post-write COMPLETE destination re-read
//     covers the manifest slot too, so it fails first-or-equally in every case.
//   * assert_dest_identity_free's DUPLICATE branch — the post-write destination
//     completeness check also catches a duplicated identity. Its RESERVED branch IS
//     load-bearing and is killed by the raw/reserved-collision mutant below.
//   * assert_object_contract (restore) — it runs before any plaintext is released to
//     the target (the safer order), but assert_materialised catches wrong content
//     afterwards by re-reading the target.
//   * assert_key_roundtrip — reversibility is proven positively per key on the run
//     path and by the round-trip controls; no injectable non-reversible encoding
//     exists in the author-stage fixture.
//   * assert_adapter_identity's OPERATOR-PIN and ROLE branches — both have run-path
//     negatives (F004_ADAPTER_SHA256 mismatch, F004_REQUIRE_ADAPTER_ROLE=real against a
//     fixture), but they sit inside the same guard the adapter-identity mutant removes,
//     so they get no separate kill-mutant of their own.
//   * assert_source_account's CHARSET branch — covered by a run-path negative, but it
//     shares the guard the missing-account mutant removes.
//   * assert_event_source_binding and assert_event_correlation — both have run-path
//     selftest negatives, but on the happy path they are satisfied by construction, so a
//     mutant removing either cannot change an exit code. The event WRITER, its
//     CONFIRMATION check and its ORDERING relative to verification are the three
//     load-bearing sites and each has its own named mutant below.
//
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, "..");
const VALIDATOR = path.join(ROOT, "scripts", "validate-f004-recovery-instrumentation.js");
const WT_PARENT = path.join(ROOT, ".f004-mutation-worktrees");

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; console.log((cond ? "PASS " : "FAIL ") + name); };
const git = (args) => execFileSync("git", args, { cwd: ROOT, encoding: "utf8" }).trim();
const validatorExit = (rootDir) => { try { execFileSync("node", [VALIDATOR], { stdio: "pipe", env: { ...process.env, F004_ROOT: rootDir } }); return 0; } catch (e) { return typeof e.status === "number" ? e.status : 1; } };

const B = "scripts/ops/backup-production-data.sh";
const R = "scripts/ops/restore-production-backup-to-staging.sh";
const A = "scripts/ops/f004-provider-adapter.sh";
const BIND_B = '  assert_source_account_bound "${F004_SRC_ACCOUNT:-}" "$measured_src" \\\n    || die "declared source account is not the account the source credential context measures"';
const T = "  true";
const T4 = "    true";
const CRYPTO_BEFORE = `  let pt;
  try { pt = Buffer.concat([d.update(b), d.final()]); }   // final() authenticates; throws on a bad/truncated tag
  catch { process.stderr.write("decrypt auth failed\\n"); process.exit(7); }   // fail closed, nothing released
  process.stdout.write(pt);   // reached ONLY when the tag authenticated`;
const CRYPTO_AFTER = `  process.stdout.write(d.update(b));   // MUTANT: release before authentication
  try { d.final(); } catch { process.stderr.write("decrypt auth failed\\n"); process.exit(7); }`;
const ADAPTER_ANCHOR = '  assert_adapter_identity "${F004_PROVIDER_CMD:-}" "$F004_ADAPTER_IDENTITIES" \\\n    || die "provider adapter identity is not repository-pinned — STOP before any provider action"';
const DOMAIN_ANCHOR = `  assert_recovery_domain "\${F004_DEST_PROVIDER:-}" "\${F004_DEST_ACCOUNT:-}" "\${F004_DEST_ENDPOINT:-}" "\${F004_DEST_BUCKET:-}" \\
    || die "declared destination is not an independent recovery domain"`;

const MUTANTS = [
  // ── successor #1/#2 controls, re-run unchanged ──
  { name: "backup main is a stub (exits before work)", file: B, find: '  last="$(provider now)"', repl: "  exit 2" },
  { name: "backup skips encrypted-destination guard", file: B, find: '  assert_encrypted_destination "$dest" || die "destination is not encrypted"', repl: T },
  { name: "backup skips source-stable guard", file: B, find: '  assert_source_stable "$inv1" "$inv2" || die "R2 source inventory moved during the copy"', repl: T },
  { name: "backup skips R2 set/hash-equality guard", file: B, find: '  assert_r2_manifests_equal "$inv1" "$destman" || die "R2 destination set/round-trip-hash does not equal the source"', repl: T },
  { name: "backup skips verify-before-success guard", file: B, find: '  may_emit_success "$status" || die "final verification did not PASS — no success record"', repl: T },
  { name: "backup skips freshness guard", file: B, find: '  backup_is_fresh "$last" "$now" "$F004_MAX_AGE" || die "backup freshness window failed"', repl: T },
  { name: "backup skips key-confinement guard", file: B, find: '    assert_safe_key "$key" || die "unsafe R2 manifest key: $key"', repl: T4 },
  { name: "backup skips key gate (provider hit before STOP)", file: B, find: '  assert_encryption_key || die "encryption key absent/invalid — STOP before any provider action"', repl: T },
  { name: "backup GCM releases plaintext before tag authentication", file: B, find: CRYPTO_BEFORE, repl: CRYPTO_AFTER },
  { name: "restore main is a stub (exits before work)", file: R, find: '  t0="$(provider now)"', repl: "  exit 2" },
  { name: "restore skips disposable-target guard", file: R, find: '  assert_restore_target "$target" || die "target is not a disposable staging target"', repl: T },
  { name: "restore skips no-time-travel guard", file: R, find: '  assert_no_time_travel "$@"       || die "D1 Time Travel is not a drill mechanism"', repl: T },
  { name: "restore skips backup→restore byte-contract guard", file: R, find: '  assert_backup_contract "${F004_EXPECT_D1_SHA:-}" "$restored_d1" || die "restored D1 does not match the backup record (byte contract)"', repl: T },
  { name: "restore skips restore-verified guard", file: R, find: '  restore_verified "$integrity" "$fk" "$schema" "$tables" "$rows" "$r2" || die "a restore verification check did not pass"', repl: T },
  { name: "restore skips RPO/RTO guard", file: R, find: '  rpo_rto_within_target "$rpo" "$rto" "$F004_RPO_MAX" "$F004_RTO_MAX" || die "RPO/RTO outside target"', repl: T },
  { name: "restore skips key gate (provider hit before STOP)", file: R, find: '  assert_encryption_key || die "encryption key absent/invalid — STOP before any provider action"', repl: T },

  // ── successor #3 — the four blocking findings, by name ──
  // F004-S2-R1-01 — restore materialisation and manifest binding
  { name: "R1-01 remove D1 replay into the target", file: R, find: '  provider_stream store_get "$d1_dest" | f004_decrypt | provider_sink replay_d1 "$created"', repl: T },
  { name: "R1-01 remove manifest consumption", file: R, find: '  assert_manifest_contract "${F004_EXPECT_MANIFEST_SHA:-}" "$man_sha" || die "stored manifest does not match the backup\'s recorded manifest hash"', repl: T },
  { name: "R1-01 omit one R2 object restore", file: R, find: '    provider_stream store_get "$dstid" | f004_decrypt | provider_sink restore_r2 "$created" "$srckey"', repl: T4 },
  { name: "R1-01 accept a wrong provider-returned target identity", file: R, find: '  assert_created_target "$created" "$target" || die "provider-created target identity is absent or is not the requested target"', repl: T },
  { name: "R1-01 skip the D1 materialisation proof", file: R, find: '  assert_materialised "$d1_sha_man" "$materialised_d1" || die "D1 was not materially replayed into $created"', repl: T },
  { name: "R1-01 skip the R2 materialisation proof", file: R, find: '    assert_materialised "$osha" "$landed" || die "R2 object was not materially restored into $created: $srckey"', repl: T4 },
  { name: "R1-01 skip restored-object-set completeness", file: R, find: '  assert_restored_set_complete "$want_keys" "$have_keys" || die "restored R2 object set in $created does not equal the manifest set"', repl: T },
  // F004-S2-R1-02 — secret-free provider boundary
  { name: "R1-02 restore ambient environment inheritance (backup provider)", file: B, find: "  F004_ENVARGV=(env -i)", repl: "  F004_ENVARGV=(env)" },
  { name: "R1-02 restore ambient environment inheritance (restore provider)", file: R, find: "  F004_ENVARGV=(env -i)", repl: "  F004_ENVARGV=(env)" },
  { name: "R1-02 skip the provider environment allowlist guard", file: B, find: '  assert_env_allowlist "${F004_PROVIDER_ENV_ALLOW:-}" || die "provider environment allowlist names a secret or is malformed"', repl: T },
  // F004-S2-R1-03 — reversible, collision-free R2 identity
  { name: "R1-03 allow a raw/reserved destination identity (namespace collapse)", file: B, find: '    dk="$(f004_ns_r2 "$enc")"', repl: '    dk="$key"' },
  { name: "R1-03 accept a manifest destination id outside the r2 namespace", file: R, find: '    [ "$(f004_ns_r2 "$enc")" = "$dstid" ] || die "manifest destination id is outside the r2 namespace: $dstid"', repl: T4 },
  { name: "R1-03 skip the post-write destination completeness re-read", file: B, find: '  assert_destination_complete "$exp_ids" "$obs_ids" || die "final destination listing does not equal the recorded identity set"', repl: T },
  { name: "R1-03 skip the post-write per-member re-read", file: B, find: '    assert_final_readback "$want" "$got" || die "post-write destination re-read mismatch at $did"', repl: T4 },
  // F004-S2-R1-04 — enforced independent recovery domain
  { name: "R1-04 accept the same provider/account/bucket as the source", file: B, find: DOMAIN_ANCHOR, repl: T },
  { name: "R1-04 skip destination-identity binding through the provider", file: B, find: '  assert_destination_identity "$declared" "$measured" || die "provider destination identity does not match the declared recovery domain"', repl: T },

  // ── successor #4 — the two blocking findings of the successor-3 verdict ──
  // F004-SUCCESSOR3-DELTA-R1 R1-04 — mandatory source-account binding
  { name: "S4-R1-04 backup skips the mandatory source-account gate", file: B, find: '  assert_source_account || die "source account identity is absent or malformed — STOP before any provider action"', repl: T },
  { name: "S4-R1-04 restore skips the mandatory source-account gate", file: R, find: '  assert_source_account || die "source account identity is absent or malformed — STOP before any provider action"', repl: T },
  { name: "S4-R1-04 backup accepts an identical source/destination account", file: B, find: '  if [ "$acct" = "$F004_SRC_ACCOUNT" ]; then', repl: "  if false; then" },
  { name: "S4-R1-04 restore accepts an identical source/destination account", file: R, find: '  if [ "$acct" = "$F004_SRC_ACCOUNT" ]; then', repl: "  if false; then" },
  // F004-S3-R1-01 — hash-bound repository-owned provider adapter
  { name: "S4-R1-01 backup skips the adapter identity gate", file: B, find: ADAPTER_ANCHOR, repl: T },
  { name: "S4-R1-01 restore skips the adapter identity gate", file: R, find: ADAPTER_ANCHOR, repl: T },

  // ── governance amendment — the F-027 backup_completed producer bridge ──
  { name: "S4-F027 backup never records the backup_completed event", file: B, find: '  record_backup_completed_event "$ma" "$last" "$man_sha"', repl: T },
  { name: "S4-F027 backup swallows a failed event confirmation", file: B, find: '  assert_event_recorded "$ack" "$eid" || die "backup_completed event was not durably recorded — no success record"', repl: T },
  { name: "S4-F027 backup records the event BEFORE final verification", file: B, find: '  status="$(provider verify_summary)"', repl: '  record_backup_completed_event "$ma" "$last" "$man_sha"\n  status="$(provider verify_summary)"' },

  // ── adapter runtime transform: raw Wrangler JSON is never the protocol answer ──
  { name: "S4-ADPT adapter returns RAW Wrangler output instead of confirming", file: A, find: '  printf \'%s\' "$out" | f004_confirm_json "${2:-}" "${1:-}"', repl: '  printf \'%s\' "$out"' },
  { name: "S4-ADPT adapter skips the durable row-id confirmation", file: A, find: '  if (r.id !== wantId) fail("durable row id is not the requested event id");', repl: "  ;" },
  { name: "S4-ADPT adapter skips the correlation-id confirmation", file: A, find: '  if (r.correlation_id !== wantCorr) fail("durable row correlation_id is not the requested token");', repl: "  ;" },
  { name: "S4-ADPT adapter skips the inserted-vs-existing signal", file: A, find: '  if (changes !== 0 && changes !== 1) fail("no deterministic inserted-vs-existing signal");', repl: "  ;" },
  { name: "S4-ADPT adapter skips exact-row-count confirmation", file: A, find: '  if (rows.length !== 1) fail("confirming select did not return exactly one row");', repl: "  ;" },

  // ── successor #5 — the four declared transforms, and the measured source-account binding ──
  { name: "S5-XFORM adapter d1_export bare-execs instead of streaming the fifo to stdout", file: A, find: '    f004_make_fifo; f004_argv "$op" "$@"; f004_stream_out; exit 0 ;;', repl: '    f004_argv "$op" "$@"; exec "${F004_ARGV[@]}" ;;' },
  { name: "S5-XFORM adapter replay_d1 bare-execs instead of supplying stdin through the fifo", file: A, find: '    f004_make_fifo; f004_argv "$op" "$@"; f004_stream_in; exit 0 ;;', repl: '    f004_argv "$op" "$@"; exec "${F004_ARGV[@]}" ;;' },
  { name: "S5-XFORM adapter verify_d1 emits raw provider output instead of a digest", file: A, find: '    f004_make_fifo; f004_argv "$op" "$@"; f004_digest_fifo; exit 0 ;;', repl: '    f004_argv "$op" "$@"; exec "${F004_ARGV[@]}" ;;' },
  { name: "S5-XFORM adapter verify_r2 emits raw provider output instead of a digest", file: A, find: '    f004_argv "$op" "$@"; f004_digest_pipe; exit 0 ;;', repl: '    f004_argv "$op" "$@"; exec "${F004_ARGV[@]}" ;;' },
  { name: "S5-ACCT adapter accepts an ambiguous multi-account credential context", file: A, find: '  if (accounts.length > 1) fail("credential context is ambiguous: " + accounts.length + " accounts; scope the token to one");', repl: "  ;" },
  { name: "S5-BIND backup skips the measured source-account binding", file: B, find: BIND_B, repl: T },
  { name: "S5-BIND restore skips the measured source-account binding", file: R, find: BIND_B, repl: T },
];

const mutationId = (index) => `F004-M${String(index + 1).padStart(3, "0")}`;

function argumentError(message) {
  console.error(`f004 mutation runner argument error: ${message}`);
  process.exit(2);
}

function parseNonNegativeInteger(raw, option) {
  if (!/^(0|[1-9][0-9]*)$/.test(String(raw ?? ""))) {
    argumentError(`${option} must be a canonical non-negative integer`);
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value)) argumentError(`${option} exceeds the safe integer range`);
  return value;
}

function parseArguments(argv) {
  let list = false;
  let shardIndex = null;
  let shardTotal = null;
  const seen = new Set();

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--list") {
      if (seen.has("--list")) argumentError("--list may be specified only once");
      seen.add("--list");
      list = true;
      continue;
    }

    const match = arg.match(/^(--shard-index|--shard-total)(?:=(.*))?$/);
    if (!match) argumentError(`unknown argument: ${arg}`);
    const option = match[1];
    if (seen.has(option)) argumentError(`${option} may be specified only once`);
    seen.add(option);
    const raw = match[2] !== undefined ? match[2] : argv[++i];
    const value = parseNonNegativeInteger(raw, option);
    if (option === "--shard-index") shardIndex = value;
    else shardTotal = value;
  }

  if ((shardIndex === null) !== (shardTotal === null)) {
    argumentError("--shard-index and --shard-total must be provided together");
  }
  if (shardTotal !== null) {
    if (shardTotal < 1) argumentError("--shard-total must be at least 1");
    if (shardTotal > MUTANTS.length) {
      argumentError(`--shard-total cannot exceed the ${MUTANTS.length} registered mutants`);
    }
    if (shardIndex >= shardTotal) argumentError("--shard-index must be less than --shard-total");
  }

  return { list, shardIndex, shardTotal };
}

const cli = parseArguments(process.argv.slice(2));
const registeredMutants = MUTANTS.map((mutant, index) => ({
  ...mutant,
  id: mutationId(index),
  index,
}));
const selectedMutants = cli.shardTotal === null
  ? registeredMutants
  : registeredMutants.filter(({ index }) => index % cli.shardTotal === cli.shardIndex);

if (cli.list) {
  for (const mutant of selectedMutants) {
    console.log(`${mutant.id}\t${mutant.index}\t${mutant.file}\t${mutant.name}`);
  }
  process.exit(0);
}

let WT_BASE = WT_PARENT;
let worktreeSuffix = "";
if (cli.shardTotal !== null) {
  fs.mkdirSync(WT_PARENT, { recursive: true });
  WT_BASE = fs.mkdtempSync(path.join(
    WT_PARENT,
    `shard-${cli.shardIndex}-of-${cli.shardTotal}-`,
  ));
  // Git derives its administrative worktree key from the checkout's leaf name.
  // A distinct parent is therefore insufficient: parallel shards must also use
  // distinct baseline/mutant leaf names.
  worktreeSuffix = `-${cli.shardIndex}-of-${cli.shardTotal}-${process.pid}`;
}

fs.rmSync(WT_BASE, { recursive: true, force: true });
try { git(["worktree", "prune"]); } catch { /* best effort */ }
fs.mkdirSync(WT_BASE, { recursive: true });
// Baseline: one throwaway worktree off HEAD must be GREEN before any mutation. All
// mutant worktrees are identical HEAD checkouts, so a single baseline attributes every
// later red to its mutation.
const base = path.join(WT_BASE, `baseline${worktreeSuffix}`);
git(["worktree", "add", "--detach", "--quiet", base, "HEAD"]);
const baselineGreen = validatorExit(base) === 0;
git(["worktree", "remove", "--force", base]);
ok("baseline worktree is GREEN before any mutation (attribution)", baselineGreen);
for (const m of selectedMutants) {
  const wt = path.join(WT_BASE, `wt-${m.index}${worktreeSuffix}`);
  let applied = false, killed = false;
  try {
    git(["worktree", "add", "--detach", "--quiet", wt, "HEAD"]);
    const fp = path.join(wt, m.file);
    const txt = fs.readFileSync(fp, "utf8");
    const n = txt.split(m.find).length - 1;
    if (n === 1) { fs.writeFileSync(fp, txt.replace(m.find, m.repl)); applied = true; }
    else console.log(`  (anchor for "${m.name}" occurred ${n}×, expected 1)`);
    killed = applied && validatorExit(wt) !== 0;
  } finally { try { git(["worktree", "remove", "--force", wt]); } catch { /* best effort */ } }
  ok(`${m.name}: mutation applied at a unique anchor`, applied);
  ok(`${m.name}: KILLED (validator falls)`, baselineGreen && applied && killed);
}
fs.rmSync(WT_BASE, { recursive: true, force: true });
if (cli.shardTotal !== null) {
  try { fs.rmdirSync(WT_PARENT); } catch { /* another shard may still own it */ }
}
try { git(["worktree", "prune"]); } catch { /* best effort */ }

const summaryScope = cli.shardTotal === null
  ? `(${MUTANTS.length} mutants)`
  : `(${selectedMutants.length} mutants; shard ${cli.shardIndex}/${cli.shardTotal})`;
console.log(`\nF-004 execution-path mutation proof: ${pass}/${pass + fail} passed ${summaryScope}`);
if (fail > 0) { console.error("f004 mutation proof FAILED"); process.exit(1); }
console.log("f004 mutation proof passed");
