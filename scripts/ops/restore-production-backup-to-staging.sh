#!/usr/bin/env bash
#
# F-004 — restore-production-backup-to-staging.sh
# Restore a CLIENT-ENCRYPTED backup into a SEPARATELY CREATED, DISPOSABLE staging
# D1/R2 target and verify it on the REAL `run` control flow (main). A drill NEVER
# touches a production name/ID/bucket, NEVER uses D1 Time Travel, and NEVER restores
# in place.
#
# MATERIALISATION (successor #3, finding R1-01): the drill CONSUMES the backup's
# persisted, encrypted, hash-bound MANIFEST, then for the D1 artefact and for EVERY
# manifest-listed R2 object it decrypts the stored ciphertext, proves the byte
# contract against the manifest record, and STREAMS THE AUTHENTICATED PLAINTEXT INTO
# THE TARGET through `replay_d1` / `restore_r2` byte sinks. It then INDEPENDENTLY
# re-reads what actually landed in the target (`verify_d1`, `verify_r2`,
# `target_r2_list`). A restore may report success only after D1 and every
# manifest-listed object are materially present and independently verified.
#
# TARGET IDENTITY: the disposable target is CREATED by the provider, which RETURNS the
# identity it created. Every replay, object restore, integrity/FK/schema/table/row/R2
# check and the success record are bound to THAT returned identity — never to the
# requested string alone.
#
# KEY CHANNEL (finding R1-02): the key reaches the local crypto process ONLY over
# inherited fd 3 and is removed from that process's environment. Every provider
# operation runs under `env -i` with an EXPLICIT ALLOWLIST, so no provider child ever
# sees F004_ENC_KEY, an evidence path, or any other secret.
#
# RECOVERY DOMAIN (finding R1-04): the store the drill reads FROM is reconciled through
# the provider protocol against a declared provider/account/endpoint/bucket identity;
# the source provider/account/bucket is rejected. A label is never accepted as proof.
#
# PROVIDER BOUNDARY / ENVELOPES / SCOPE: identical discipline to
# backup-production-data.sh — a test-only allowlisted provider protocol over a
# separate process, fail-closed on missing/invalid; real command envelopes (pinned
# Wrangler 4.120.0) are NEVER executed in the author stage. Guard-and-protocol
# evidence is NOT broad F-004 closure; the controlled-live drill is a later,
# separately authorised residual.
#
set -euo pipefail
export LC_ALL=C

PRODUCTION_NAMES="cybermeters-db cybermeters-reports cybermeters-platform cybermeters-email"
F004_RPO_MAX="${F004_RPO_MAX:-86400}"
F004_RTO_MAX="${F004_RTO_MAX:-14400}"

F004_SRC_PROVIDER="${F004_SRC_PROVIDER:-cloudflare}"
F004_SRC_ACCOUNT="${F004_SRC_ACCOUNT:-}"
F004_SRC_BUCKET="${F004_SRC_BUCKET:-cybermeters-reports}"

F004_SECRET_NAMES="F004_ENC_KEY F004_PT_META_OUT F004_PT_HASH_OUT F004_EVIDENCE_OUT F004_EXPECT_D1_SHA F004_EXPECT_MANIFEST_SHA F004_PROVIDER_ENV_ALLOW F004_PROVIDER_CMD"
F004_PROVIDER_BASE_ENV="PATH LC_ALL"
# Repository-owned adapter identity contract (successor #4, finding F004-S3-R1-01).
F004_ADAPTER_IDENTITIES="${F004_ADAPTER_IDENTITIES:-$(dirname "$0")/f004-adapter-identities.txt}"
F004_NS_VER="v1"

die() { echo "restore FAILED: $*" >&2; exit 1; }
F004_WORK=""
trap '[ -n "${F004_WORK:-}" ] && rm -rf "$F004_WORK"' EXIT

# ── node:crypto (inline; pinned Node 24 stdlib). Decrypt authenticates BEFORE
#    releasing any plaintext (GCM tag at end): a truncated/tampered artefact fails
#    closed at exit 7 with empty stdout — so a target byte sink can only ever receive
#    authenticated plaintext. Key read from FD 3 ONLY (64 hex); absent → exit 9. ──
F004_CRYPTO_JS='
import crypto from "node:crypto";
import fs from "node:fs";
const mode = process.argv[1];
// BOUNDED SECRET CHANNEL: the key arrives only on inherited fd 3, never on argv and
// never in this process environment.
let hex = "";
try { hex = fs.readFileSync(3).toString("utf8").trim(); } catch { hex = ""; }
if (!/^[0-9a-f]{64}$/i.test(hex)) { process.stderr.write("F004 encryption key absent/invalid on fd 3 (need 64 hex)\n"); process.exit(9); }
const key = Buffer.from(hex, "hex");
const chunks = []; for await (const c of process.stdin) chunks.push(c);
const input = Buffer.concat(chunks);
if (mode === "decrypt") {
  if (input.length < 28) { process.stderr.write("ciphertext too short\n"); process.exit(8); }
  const iv = input.subarray(0,12), tag = input.subarray(input.length-16), b = input.subarray(12, input.length-16);
  const d = crypto.createDecipheriv("aes-256-gcm", key, iv); d.setAuthTag(tag);
  let pt;
  try { pt = Buffer.concat([d.update(b), d.final()]); }
  catch { process.stderr.write("decrypt auth failed\n"); process.exit(7); }
  process.stdout.write(pt);
} else { process.stderr.write("restore only decrypts\n"); process.exit(3); }
'
f004_decrypt() {
  env -u F004_ENC_KEY -u F004_PT_META_OUT -u F004_PT_HASH_OUT \
    node --input-type=module -e "$F004_CRYPTO_JS" decrypt 3< <(printf '%s' "${F004_ENC_KEY:-}")
}
f004_sha()   { node -e 'const h=require("node:crypto").createHash("sha256");process.stdin.on("data",c=>h.update(c));process.stdin.on("end",()=>process.stdout.write(h.digest("hex")))'; }
f004_lower() { printf '%s' "${1:-}" | tr 'A-Z' 'a-z'; }

# ── Destination-identity namespaces + the reversible decoder (mirror of the backup). ──
f004_ns_manifest() { printf '%s/manifest/backup' "$F004_NS_VER"; }
f004_ns_r2()       { printf '%s/r2/%s' "$F004_NS_VER" "${1:?encoded key}"; }
f004_key_decode() {
  local s="${1-}" out="" i=0 n hex byte
  n=${#s}
  while [ "$i" -lt "$n" ]; do
    case "${s:$i:1}" in
      %) hex="${s:$((i+1)):2}"
         case "$hex" in [0-9A-F][0-9A-F]) : ;; *) return 1 ;; esac
         byte="$(printf "\\x$hex")"
         case "$byte" in ""|[!!-~]) return 1 ;; esac
         out="$out$byte"; i=$((i+3)) ;;
      *) out="$out${s:$i:1}"; i=$((i+1)) ;;
    esac
  done
  printf '%s' "$out"
}

# ── Guards (pure). SAFE returns 0; each unsafe path tagged for the mutation suite. ──
is_production_identifier() {
  local id="${1:-}" p
  for p in $PRODUCTION_NAMES ${F004_PRODUCTION_IDS:-}; do [ "$id" = "$p" ] && return 0; done
  case "$id" in cybermeters-*) return 0 ;; esac
  return 1
}
is_disposable_staging_target() {
  local id="${1:-}"
  case "$id" in
    drill-*|restore-scratch-*|staging-drill-*) : ;;
    *) return 1 ;;  # REJECT:NOMARKER
  esac
  if is_production_identifier "$id"; then return 1; fi  # REJECT:PRODNAME
  return 0
}
assert_restore_target() { if is_disposable_staging_target "${1:-}"; then return 0; fi; return 1; }  # REJECT:TARGET
assert_not_in_place() { if is_production_identifier "${1:-}"; then return 1; fi; return 0; }         # REJECT:INPLACE
assert_no_time_travel() {
  if printf '%s ' "$@" | grep -qiE 'time.?travel|--timestamp|--bookmark'; then return 1; fi  # REJECT:TIMETRAVEL
  return 0
}
assert_encryption_key() {
  case "${F004_ENC_KEY:-}" in ?*) : ;; *) return 1 ;; esac  # REJECT:KEYABSENT
  case "${F004_ENC_KEY}" in *[!0-9A-Fa-f]*) return 1 ;; esac # REJECT:KEYCHARS
  [ "${#F004_ENC_KEY}" -eq 64 ] || return 1                 # REJECT:KEYLEN
  return 0
}
assert_backup_contract() {   # backup→restore byte contract: decrypted artefact hash == backup's recorded hash
  local expected="${1:-}" restored="${2:-}"
  if [ -n "$expected" ] && [ "$expected" = "$restored" ]; then return 0; fi
  return 1  # REJECT:CONTRACT  (restored artefact does not match the backup record)
}
restore_verified() {
  local integrity="${1:-}" fk="${2:-}" schema="${3:-}" tables="${4:-}" rows="${5:-}" r2="${6:-}"
  if [ "$integrity" = "ok" ] && [ "$fk" = "ok" ] && [ "$schema" = "ok" ] \
     && [ "$tables" = "eq" ] && [ "$rows" = "eq" ] && [ "$r2" = "eq" ]; then return 0; fi
  return 1  # REJECT:VERIFY
}
rpo_rto_within_target() {
  local rpo_s="${1:-}" rto_s="${2:-}" rpo_max="${3:-}" rto_max="${4:-}"
  case "$rpo_s$rto_s$rpo_max$rto_max" in *[!0-9]*|"") return 1 ;; esac  # REJECT:RPORTO_INPUT
  if [ "$rpo_s" -le "$rpo_max" ] && [ "$rto_s" -le "$rto_max" ]; then return 0; fi
  return 1  # REJECT:RPORTO
}

# G-ENVCONFINE (finding R1-02).
assert_env_allowlist() {
  local names="${1-}" n
  for n in $names; do
    case "$n" in
      ""|*[!A-Za-z0-9_]*|[0-9]*) return 1 ;;   # REJECT:ENVNAME
    esac
    case " $F004_SECRET_NAMES " in
      *" $n "*) return 1 ;;                    # REJECT:ENVSECRET
    esac
  done
  return 0
}

# G-MANIFESTCONTRACT (finding R1-01): the manifest the drill consumes must be exactly
# the manifest the backup recorded. Without it, nothing may be materialised.
assert_manifest_contract() {
  local expected="${1:-}" actual="${2:-}"
  if [ -n "$expected" ] && [ "$expected" = "$actual" ]; then return 0; fi
  return 1  # REJECT:MANIFESTCONTRACT
}

# G-MANIFESTSCHEMA: a consumable manifest is versioned, carries exactly one D1 entry,
# and every R2 entry carries source key, destination id, size and a sha256.
assert_manifest_schema() {
  local body="${1-}" head d1count
  head="$(printf '%s\n' "$body" | sed -n '1p')"
  [ "$head" = "f004-manifest-$F004_NS_VER" ] || return 1   # REJECT:MANIFESTVERSION
  d1count="$(printf '%s\n' "$body" | awk -F'\t' '$1=="d1" && NF==4' | grep -c . || true)"
  [ "$d1count" -eq 1 ] || return 1                         # REJECT:MANIFESTD1
  if printf '%s\n' "$body" | awk -F'\t' 'NR>1 && $1!="d1" && $1!="r2" && NF>0 {f=1} END{exit !f}'; then
    return 1                                               # REJECT:MANIFESTKIND
  fi
  if printf '%s\n' "$body" | awk -F'\t' '$1=="r2" && (NF!=5 || $5 !~ /^[0-9a-f]{64}$/) {f=1} END{exit !f}'; then
    return 1                                               # REJECT:MANIFESTR2
  fi
  return 0
}

# G-TARGETIDENTITY (finding R1-01): bind to the identity the PROVIDER created/returned.
# Disposability is NOT re-checked here — the requested target already passed
# assert_restore_target and the created identity must equal it exactly, so a second
# disposability test would be unreachable and would mask that guard's own mutant.
assert_created_target() {
  local created="${1:-}" requested="${2:-}"
  if [ -z "$created" ]; then return 1; fi                  # REJECT:TARGETABSENT
  if [ "$created" != "$requested" ]; then return 1; fi     # REJECT:TARGETIDENTITY
  return 0
}

# G-OBJCONTRACT (finding R1-01): every stored member must decrypt to its manifest hash.
assert_object_contract() {
  local expected="${1:-}" actual="${2:-}"
  if [ -n "$expected" ] && [ "$expected" = "$actual" ]; then return 0; fi
  return 1  # REJECT:OBJCONTRACT
}

# G-MATERIALISED (finding R1-01): what the TARGET now holds, read back FROM the target,
# must equal the manifest record. This is the only proof that a restore actually happened.
assert_materialised() {
  local expected="${1:-}" observed="${2:-}"
  if [ -n "$expected" ] && [ "$expected" = "$observed" ]; then return 0; fi
  return 1  # REJECT:NOTMATERIALISED
}

# G-RESTORESET (finding R1-01): the target must hold EXACTLY the manifest object set.
assert_restored_set_complete() {
  local expected="${1:-}" observed="${2:-}"
  if [ -n "$expected" ] && [ "$expected" = "$observed" ]; then return 0; fi
  return 1  # REJECT:RESTORESET
}

# G-KEYRT (finding R1-03): each manifest destination id must reverse to its source key.
assert_key_roundtrip() {
  local original="${1-}" decoded="${2-}"
  if [ -n "$original" ] && [ "$original" = "$decoded" ]; then return 0; fi
  return 1  # REJECT:KEYRT
}

# ── successor #4 guards (verdict F004-SUCCESSOR3-DELTA-R1) ──────────────────────────
# G-SRCBIND (successor #5, finding F004-S4-R1-02): the source account must be MEASURED under
# the same credential context that will perform the source operations, and must equal the
# declared label EXACTLY. A syntactically valid label is a claim, not evidence, so a false
# but well-formed F004_SRC_ACCOUNT is rejected before any other provider action.
assert_source_account_bound() {
  local claimed="${1:-}" measured="${2:-}"
  if [ -z "$claimed" ] || [ -z "$measured" ]; then return 1; fi   # REJECT:SRCBINDABSENT
  case "$measured" in *[!A-Za-z0-9._-]*) return 1 ;; esac          # REJECT:SRCBINDCHARS
  if [ "$claimed" != "$measured" ]; then return 1; fi              # REJECT:SRCBINDMISMATCH
  return 0
}

# G-SRCACCOUNT (finding R1-04): the SOURCE account identity is MANDATORY and is bound
# BEFORE any provider action. Successor-3 defaulted it to empty and made the same-account
# rejection conditional on it, so omitting it silently allowed a run that could not prove
# provider/account separation at all. Absent or malformed is now a STOP, not a pass.
assert_source_account() {
  local acct="${F004_SRC_ACCOUNT:-}"
  case "$acct" in
    "") return 1 ;;                  # REJECT:SRCACCOUNTABSENT
    *[!A-Za-z0-9._-]*) return 1 ;;   # REJECT:SRCACCOUNTCHARS
  esac
  return 0
}

# G-ADAPTERID (finding F004-S3-R1-01): the provider adapter's BYTES must hash to an
# identity pinned in the repository-owned contract, checked BEFORE any provider action.
# Successor-3 checked only that the caller-supplied path was a file and executable, so an
# independently byte-modified adapter was accepted and produced a success record.
f004_file_sha() {
  node -e 'const c=require("node:crypto"),f=require("node:fs");process.stdout.write(c.createHash("sha256").update(f.readFileSync(process.argv[1])).digest("hex"))' "$1"
}
assert_adapter_identity() {
  local cmd="${1:-}" idfile="${2:-}" measured role want
  [ -n "$cmd" ] || return 1                                   # REJECT:ADAPTERABSENT
  { [ -f "$cmd" ] && [ -r "$cmd" ]; } || return 1             # REJECT:ADAPTERUNREADABLE
  { [ -f "$idfile" ] && [ -r "$idfile" ]; } || return 1       # REJECT:ADAPTERCONTRACTMISSING
  measured="$(f004_file_sha "$cmd")" || return 1
  case "$measured" in ""|*[!0-9a-f]*) return 1 ;; esac         # REJECT:ADAPTERHASH
  [ "${#measured}" -eq 64 ] || return 1                        # REJECT:ADAPTERHASHLEN
  grep -qE "^${measured}[[:space:]]" "$idfile" || return 1      # REJECT:ADAPTERIDENTITY
  want="${F004_ADAPTER_SHA256:-}"
  if [ -n "$want" ] && [ "$want" != "$measured" ]; then
    return 1                                                   # REJECT:ADAPTERPIN
  fi
  want="${F004_REQUIRE_ADAPTER_ROLE:-}"
  if [ -n "$want" ]; then
    role="$(awk -v h="$measured" '$1==h{print $2; exit}' "$idfile")"
    [ "$role" = "$want" ] || return 1                          # REJECT:ADAPTERROLE
  fi
  return 0
}

# G-DOMAIN / G-DESTIDENTITY (finding R1-04).
assert_recovery_domain() {
  local prov="${1:-}" acct="${2:-}" endp="${3:-}" bkt="${4:-}" p
  if [ -z "$prov" ] || [ -z "$acct" ] || [ -z "$endp" ] || [ -z "$bkt" ]; then
    return 1                                              # REJECT:DOMAININCOMPLETE
  fi
  case "$(f004_lower "$prov")" in
    cloudflare|cloudflare-r2|r2|cf|*.cloudflare.com) return 1 ;;   # REJECT:DOMAINPROVIDER
  esac
  if [ "$(f004_lower "$prov")" = "$(f004_lower "$F004_SRC_PROVIDER")" ]; then
    return 1                                              # REJECT:DOMAINPROVIDER
  fi
  case "$(f004_lower "$endp")" in
    *cloudflarestorage.com*|*cloudflare.com*|r2:*|r2+*) return 1 ;;  # REJECT:DOMAINENDPOINT
  esac
  if [ "$acct" = "$F004_SRC_ACCOUNT" ]; then
    return 1                                              # REJECT:DOMAINACCOUNT
  fi
  for p in $PRODUCTION_NAMES $F004_SRC_BUCKET; do
    if [ "$bkt" = "$p" ]; then return 1; fi               # REJECT:DOMAINBUCKET
  done
  return 0
}
assert_destination_identity() {
  local declared="${1:-}" measured="${2:-}"
  if [ -z "$declared" ] || [ -z "$measured" ]; then return 1; fi   # REJECT:DESTIDABSENT
  if [ "$declared" = "$measured" ]; then return 0; fi
  return 1  # REJECT:DESTIDENTITY
}

# ── Real command envelopes (pinned Wrangler 4.120.0; NEVER run in the author stage;
#    verified offline). Disposable REMOTE staging D1, replay via --remote --file, and
#    real checks via --remote --command. Not `--local`, never Time Travel, never prod. ──
env_create_d1()  { printf 'wrangler d1 create %s\n' "${1:?target}"; }
env_replay_d1()  { printf 'wrangler d1 execute %s --remote --file %s\n' "${1:?target}" "${2:?sql path}"; }
env_check_d1()   { printf 'wrangler d1 execute %s --remote --command %s\n' "${1:?target}" "${2:?sql}"; }
env_store_get()  { printf 'aws s3api get-object --bucket %s --key %s --endpoint-url %s\n' "${F004_DEST_BUCKET:-<off-store>}" "${1:?name}" "${F004_DEST_ENDPOINT:-<off-endpoint>}"; }
env_put_r2()     { printf 'wrangler r2 object put %s/%s --pipe --remote\n' "${1:?staging bucket}" "${2:?key}"; }

# ── Test-only provider protocol (separate process; allowlisted; schema-checked;
#    invoked under an EXPLICIT ALLOWLISTED ENVIRONMENT; fail-closed). ──
PROVIDER_OPS="now backup_epoch src_identity dest_identity create_staging store_get replay_d1 restore_r2 verify_d1 verify_r2 target_r2_list check_integrity check_fk check_schema check_tables check_rows check_r2"
provider_schema_ok() {
  local op="$1" out="$2" tab=$'\t'
  case "$op" in
    now|backup_epoch)          printf '%s' "$out" | grep -qxE '[0-9]+' ;;
    check_integrity|check_fk|check_schema) case "$out" in ok|bad) return 0 ;; *) return 1 ;; esac ;;
    check_tables|check_rows|check_r2)      case "$out" in eq|neq) return 0 ;; *) return 1 ;; esac ;;
    create_staging)            printf '%s' "$out" | grep -qxE '[A-Za-z0-9._-]+' ;;
    verify_d1|verify_r2)       printf '%s' "$out" | grep -qxE '[0-9a-f]{64}' ;;
    target_r2_list)            [ -z "$out" ] || ! printf '%s\n' "$out" | grep -qvE '^[A-Za-z0-9._~=+%/-]+$' ;;
    src_identity)   printf '%s' "$out" | grep -qxE '[A-Za-z0-9._-]+' ;;
    dest_identity)             printf '%s' "$out" | grep -qxE "[A-Za-z0-9._+-]+${tab}[A-Za-z0-9._-]+${tab}[A-Za-z0-9._:/+-]+${tab}[A-Za-z0-9._-]+" ;;
    *) return 0 ;;
  esac
}
provider_env_argv() {
  local n v
  F004_ENVARGV=(env -i)
  for n in $F004_PROVIDER_BASE_ENV; do
    eval "v=\${$n-}"
    F004_ENVARGV[${#F004_ENVARGV[@]}]="$n=$v"
  done
  for n in ${F004_PROVIDER_ENV_ALLOW:-}; do
    eval "v=\${$n-}"
    F004_ENVARGV[${#F004_ENVARGV[@]}]="$n=$v"
  done
}
provider_guard() {
  local op="$1"
  case " $PROVIDER_OPS " in *" $op "*) : ;; *) die "provider op not allowlisted: $op" ;; esac
  [ -n "${F004_PROVIDER_CMD:-}" ] || die "no provider protocol available in the author stage (op: $op) — a live run is Integration/founder territory"
  { [ -f "$F004_PROVIDER_CMD" ] && [ -x "$F004_PROVIDER_CMD" ]; } || die "test provider supplied but missing/not executable — STOP before any provider action"
  assert_env_allowlist "${F004_PROVIDER_ENV_ALLOW:-}" || die "provider environment allowlist names a secret or is malformed"
  provider_env_argv
}
provider() { local op="${1:?op}"; shift; provider_guard "$op"; local out; out="$("${F004_ENVARGV[@]}" "$F004_PROVIDER_CMD" "$op" "$@")" || die "provider op failed: $op"; provider_schema_ok "$op" "$out" || die "provider output failed schema for op: $op"; printf '%s' "$out"; }
provider_stream() { local op="${1:?op}"; shift; provider_guard "$op"; "${F004_ENVARGV[@]}" "$F004_PROVIDER_CMD" "$op" "$@"; }
provider_sink()   { local op="${1:?op}"; shift; provider_guard "$op"; "${F004_ENVARGV[@]}" "$F004_PROVIDER_CMD" "$op" "$@"; }

# ── Dispatchers (strictly allowlisted). ──
if [ "${1:-}" = "--crypto" ]; then
  shift; m="${1:?crypto mode}"; shift || true
  set +e; case "$m" in decrypt) f004_decrypt ;; *) echo "restore only decrypts: $m" >&2; exit 3 ;; esac; exit $?
fi
if [ "${1:-}" = "--envelope" ]; then
  shift; op="${1:?envelope op}"; shift || true
  case "$op" in
    create_d1) env_create_d1 "$@" ;; replay_d1) env_replay_d1 "$@" ;; check_d1) env_check_d1 "$@" ;;
    store_get) env_store_get "$@" ;; put_r2) env_put_r2 "$@" ;;
    *) echo "unknown envelope op: $op" >&2; exit 3 ;;
  esac
  exit 0
fi
if [ "${1:-}" = "--selftest" ]; then
  shift; fn="${1:?guard name}"; shift || true
  case "$fn" in
    assert_restore_target|assert_not_in_place|assert_no_time_travel|assert_encryption_key|assert_backup_contract|restore_verified|rpo_rto_within_target|is_production_identifier|is_disposable_staging_target|assert_env_allowlist|assert_manifest_contract|assert_manifest_schema|assert_created_target|assert_object_contract|assert_materialised|assert_restored_set_complete|assert_key_roundtrip|assert_recovery_domain|assert_destination_identity|assert_source_account|assert_adapter_identity|assert_source_account_bound) : ;;
    *) echo "selftest name not allowlisted: $fn" >&2; exit 3 ;;
  esac
  set +e; "$fn" "$@"; rc=$?; set -e
  [ "$rc" -eq 0 ] && echo "GUARD_ALLOW" || echo "GUARD_REJECT"
  exit "$rc"
fi

# ── Real run: full disposable-staging restore; every guard on this path; providers via
#    the protocol under a confined environment; node:crypto decrypt with an fd-3 key
#    channel; manifest consumed; D1 AND every listed R2 object materially replayed into
#    the provider-created target and INDEPENDENTLY re-read from it before any success. ──
main() {
  if [ "${F004_CONFIRM_REAL_RUN:-no}" != "yes" ]; then
    echo "refusing: set F004_CONFIRM_REAL_RUN=yes to run a real restore drill (author stage does not)." >&2
    exit 2
  fi
  assert_encryption_key || die "encryption key absent/invalid — STOP before any provider action"
  local target="${F004_RESTORE_TARGET:-}"
  assert_restore_target "$target" || die "target is not a disposable staging target"
  assert_not_in_place   "$target" || die "refusing in-place restore over a production id"
  assert_no_time_travel "$@"       || die "D1 Time Travel is not a drill mechanism"
  # MANDATORY source account (finding R1-04) — bound before any provider action.
  assert_source_account || die "source account identity is absent or malformed — STOP before any provider action"

  local declared
  declared="${F004_DEST_PROVIDER:-}"$'\t'"${F004_DEST_ACCOUNT:-}"$'\t'"${F004_DEST_ENDPOINT:-}"$'\t'"${F004_DEST_BUCKET:-}"
  assert_recovery_domain "${F004_DEST_PROVIDER:-}" "${F004_DEST_ACCOUNT:-}" "${F004_DEST_ENDPOINT:-}" "${F004_DEST_BUCKET:-}" \
    || die "declared backup store is not an independent recovery domain"

  # ADAPTER IDENTITY (finding F004-S3-R1-01): hash-bind the adapter's BYTES to the
  # repository-owned identity contract BEFORE any provider action. A byte-modified
  # adapter stops here and issues zero provider operations and no success record.
  local adapter_sha adapter_role
  assert_adapter_identity "${F004_PROVIDER_CMD:-}" "$F004_ADAPTER_IDENTITIES" \
    || die "provider adapter identity is not repository-pinned — STOP before any provider action"
  adapter_sha="$(f004_file_sha "${F004_PROVIDER_CMD}")"
  adapter_role="$(awk -v h="$adapter_sha" '$1==h{print $2; exit}' "$F004_ADAPTER_IDENTITIES")"

# SOURCE ACCOUNT BINDING (finding F004-S4-R1-02) — the FIRST provider action. The account is
  # measured by the adapter under the same credential context that will run every source
  # operation, and must equal the declared label exactly. Missing, malformed, ambiguous,
  # command-failure and mismatch all STOP here, before any other provider action.
  local measured_src
  measured_src="$(provider src_identity)"
  assert_source_account_bound "${F004_SRC_ACCOUNT:-}" "$measured_src" \
    || die "declared source account is not the account the source credential context measures"

  local t0 t1 restored_d1 integrity fk schema tables rows r2 rpo rto
  t0="$(provider now)"

  local measured mp ma me mb
  measured="$(provider dest_identity)"
  assert_destination_identity "$declared" "$measured" || die "provider store identity does not match the declared recovery domain"
  IFS=$'\t' read -r mp ma me mb <<EOF
$measured
EOF

  # CREATE the disposable target and BIND everything that follows to the identity the
  # provider actually returned — never to the requested string alone.
  local created
  created="$(provider create_staging "$target")"
  assert_created_target "$created" "$target" || die "provider-created target identity is absent or is not the requested target"

  # MANIFEST CONSUMPTION: decrypt (authenticate first), bind to the backup's recorded
  # manifest hash, and schema-check it. Nothing may be materialised without it.
  local man_dest man_plain man_sha
  man_dest="$(f004_ns_manifest)"
  man_plain="$(provider_stream store_get "$man_dest" | f004_decrypt)"
  man_sha="$(printf '%s' "$man_plain" | f004_sha)"
  assert_manifest_contract "${F004_EXPECT_MANIFEST_SHA:-}" "$man_sha" || die "stored manifest does not match the backup's recorded manifest hash"
  assert_manifest_schema "$man_plain" || die "manifest is not a consumable f004-manifest-$F004_NS_VER record"

  # D1 REPLAY: prove the byte contract, then STREAM the authenticated plaintext into the
  # created target's replay sink, then INDEPENDENTLY re-read what landed there.
  local d1_dest d1_sha_man materialised_d1
  d1_dest="$(printf '%s\n' "$man_plain" | awk -F'\t' '$1=="d1"{print $2; exit}')"
  d1_sha_man="$(printf '%s\n' "$man_plain" | awk -F'\t' '$1=="d1"{print $4; exit}')"
  restored_d1="$(provider_stream store_get "$d1_dest" | f004_decrypt | f004_sha)"
  assert_backup_contract "${F004_EXPECT_D1_SHA:-}" "$restored_d1" || die "restored D1 does not match the backup record (byte contract)"
  assert_object_contract "$d1_sha_man" "$restored_d1" || die "stored D1 artefact does not match the manifest record"
  provider_stream store_get "$d1_dest" | f004_decrypt | provider_sink replay_d1 "$created"
  materialised_d1="$(provider verify_d1 "$created")"
  assert_materialised "$d1_sha_man" "$materialised_d1" || die "D1 was not materially replayed into $created"

  # R2 MATERIALISATION: EVERY manifest-listed object — decrypt, contract-check, stream
  # into the created target, then independently re-read that object FROM the target.
  local kind srckey dstid osize osha got landed enc dec objects=0
  while IFS=$'\t' read -r kind srckey dstid osize osha; do
    [ "$kind" = "r2" ] || continue
    # The manifest's destination id must live in the r2 namespace and must reverse to
    # the source key it claims — a raw or cross-namespace id is rejected, not stripped.
    enc="${dstid#"$F004_NS_VER"/r2/}"
    [ "$(f004_ns_r2 "$enc")" = "$dstid" ] || die "manifest destination id is outside the r2 namespace: $dstid"
    dec="$(f004_key_decode "$enc")" || die "manifest destination id is not decodable: $dstid"
    assert_key_roundtrip "$srckey" "$dec" || die "manifest destination id does not reverse to its source key: $srckey"
    got="$(provider_stream store_get "$dstid" | f004_decrypt | f004_sha)"
    assert_object_contract "$osha" "$got" || die "stored object does not match the manifest record: $srckey"
    provider_stream store_get "$dstid" | f004_decrypt | provider_sink restore_r2 "$created" "$srckey"
    landed="$(provider verify_r2 "$created" "$srckey")"
    assert_materialised "$osha" "$landed" || die "R2 object was not materially restored into $created: $srckey"
    objects=$((objects+1))
  done <<EOF
$man_plain
EOF

  # The target must hold EXACTLY the manifest object set — nothing missing, nothing extra.
  local want_keys have_keys
  want_keys="$(printf '%s\n' "$man_plain" | awk -F'\t' '$1=="r2"{print $2}' | sort)"
  have_keys="$(provider target_r2_list "$created" | sort)"
  assert_restored_set_complete "$want_keys" "$have_keys" || die "restored R2 object set in $created does not equal the manifest set"

  # Real verification of the restored staging estate, bound to the CREATED identity.
  integrity="$(provider check_integrity "$created")"
  fk="$(provider check_fk "$created")"
  schema="$(provider check_schema "$created")"
  tables="$(provider check_tables "$created")"
  rows="$(provider check_rows "$created")"
  r2="$(provider check_r2 "$created")"
  restore_verified "$integrity" "$fk" "$schema" "$tables" "$rows" "$r2" || die "a restore verification check did not pass"

  t1="$(provider now)"
  rpo="$(( t1 - $(provider backup_epoch) ))"
  rto="$(( t1 - t0 ))"
  rpo_rto_within_target "$rpo" "$rto" "$F004_RPO_MAX" "$F004_RTO_MAX" || die "RPO/RTO outside target"

  {
    printf 'restore=success\n'
    printf 'target=%s\n' "$created"
    printf 'restored_d1_sha256=%s\n' "$restored_d1"
    printf 'materialised_d1_sha256=%s\n' "$materialised_d1"
    printf 'manifest_sha256=%s\n' "$man_sha"
    printf 'r2_objects_restored=%s\n' "$objects"
    printf 'source_provider=%s\n' "$mp"
    printf 'source_account=%s\n' "$ma"
    printf 'source_endpoint=%s\n' "$me"
    printf 'source_bucket=%s\n' "$mb"
    printf 'src_account=%s\n' "$F004_SRC_ACCOUNT"
    printf 'src_account_measured=%s\n' "$measured_src"
    printf 'adapter_sha256=%s\n' "$adapter_sha"
    printf 'adapter_role=%s\n' "$adapter_role"
    printf 'rpo_seconds=%s\n' "$rpo"
    printf 'rto_seconds=%s\n' "$rto"
  } > "${F004_EVIDENCE_OUT:-/dev/stdout}"
  echo "restore drill verified into disposable staging" >&2
}

case "${1:-}" in
  run) shift; main "$@" ;;
  *) echo "usage: $0 [run | --crypto decrypt | --envelope <op> | --selftest <guard> <args...>]" >&2; exit 2 ;;
esac
