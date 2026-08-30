#!/usr/bin/env bash
#
# F-004 — backup-production-data.sh
# Point-in-time backup of the production D1 database AND every R2 report object
# into a VERIFIED, CLIENT-ENCRYPTED, INDEPENDENT-RECOVERY-DOMAIN destination. Every
# verification and the success/freshness record run on the REAL `run` control flow
# (main): a partial or unverified copy is never recorded as a backup.
#
# ENCRYPTION: client-side AES-256-GCM via node:crypto (Node 24 is the pinned CI
# runtime; node:crypto is a standard-library module, no external binary). WE hold
# the key — it is never held by the destination store and never written to disk in
# plaintext. Plaintext streams through the cipher and is never staged on the local
# disk; only ciphertext and hashes are stored. (A destination that also provides
# at-rest SSE gets that as incidental defence-in-depth — never as the encryption
# boundary, never counted as evidence.)
#
# KEY CHANNEL (successor #3, finding R1-02): the key reaches the local crypto
# process ONLY over inherited file descriptor 3 — a bounded, per-process pipe. It is
# never on the crypto process's argv and is explicitly REMOVED from that process's
# environment. Every provider operation runs under `env -i` with an EXPLICIT
# ALLOWLIST, so the provider inherits neither F004_ENC_KEY nor any evidence/metadata
# path nor any unrelated secret. A provider canary proves this for every op.
#
# HONEST RECOVERY MODEL (contract item 5): Cloudflare R2 has NO object versioning.
# Recovery is a SEPARATELY COPIED object set plus a PERSISTED, ENCRYPTED, HASH-BOUND
# MANIFEST (namespaced destination id + size + sha256 per member), verified against
# the source before the copy and re-read from the COMPLETE FINAL DESTINATION after
# every write, before any success record.
#
# DESTINATION IDENTITY (successor #3, finding R1-03/R1-04): destination ids live in
# VERSIONED, DISJOINT namespaces (`v1/d1/...`, `v1/r2/...`, `v1/manifest/...`) built
# from a REVERSIBLE percent encoding, so the repository's real slash-bearing keys
# (`reports/<scan>.json`, `reports/snapshots/<ws>/<scan>/<snap>.json`) round-trip and
# no object can ever collide with the D1 or manifest slot. The recovery domain is a
# MEASURED provider/account/endpoint/bucket tuple reconciled through the provider
# protocol — a destination LABEL such as `r2+sse://...` is never accepted as proof.
#
# PROVIDER BOUNDARY (test-only protocol): provider actions go through `provider
# <op> [args]`. Op names are ALLOWLISTED and metadata outputs are SCHEMA-checked.
# In a test, a provider EXECUTABLE is supplied via F004_PROVIDER_CMD and invoked as
# a SEPARATE PROCESS — it cannot redefine main or the guards, cannot read this
# shell's state, and does not receive the encryption key. A supplied-but-missing/
# invalid provider is a TERMINAL STOP before any provider action (never a silent
# live fallback). There is NO sourced hook. Real command envelopes (pinned Wrangler
# 4.120.0; see `--envelope`) are NEVER executed in the author stage — a real run is
# gated on F004_CONFIRM_REAL_RUN=yes and is Integration/founder territory.
# Guard-and-protocol evidence is NOT broad F-004 closure.
#
set -euo pipefail
export LC_ALL=C   # deterministic character classes for the reversible key encoding

PRODUCTION_NAMES="cybermeters-db cybermeters-reports cybermeters-platform cybermeters-email"
F004_D1_NAME="${F004_D1_NAME:-cybermeters-db}"
F004_R2_BUCKET="${F004_R2_BUCKET:-cybermeters-reports}"
F004_MAX_AGE="${F004_MAX_AGE:-86400}"

# Source (production) recovery-domain identity — what the backup must NOT land in.
F004_SRC_PROVIDER="${F004_SRC_PROVIDER:-cloudflare}"
F004_SRC_ACCOUNT="${F004_SRC_ACCOUNT:-}"
F004_SRC_BUCKET="${F004_SRC_BUCKET:-$F004_R2_BUCKET}"

# Values that must NEVER cross the provider boundary (finding R1-02).
F004_SECRET_NAMES="F004_ENC_KEY F004_PT_META_OUT F004_PT_HASH_OUT F004_EVIDENCE_OUT F004_EXPECT_D1_SHA F004_EXPECT_MANIFEST_SHA F004_PROVIDER_ENV_ALLOW F004_PROVIDER_CMD"
# The only ambient names an allowlisted provider environment carries by default.
F004_PROVIDER_BASE_ENV="PATH LC_ALL"
# Repository-owned adapter identity contract (successor #4, finding F004-S3-R1-01).
F004_ADAPTER_IDENTITIES="${F004_ADAPTER_IDENTITIES:-$(dirname "$0")/f004-adapter-identities.txt}"

die() { echo "backup FAILED: $*" >&2; exit 1; }
F004_WORK=""
trap '[ -n "${F004_WORK:-}" ] && rm -rf "$F004_WORK"' EXIT

# ── node:crypto helpers (inline; the pinned Node 24 stdlib — no external binary). ──
# f004_crypto encrypt <meta-out>: stdin plaintext → stdout (iv||ciphertext||tag); also
#   writes "<sha256>\t<bytes>" of the PLAINTEXT to <meta-out> (a hash + a length, never
#   plaintext). No disk plaintext.
# f004_crypto decrypt: stdin (iv||ciphertext||tag) → stdout plaintext.
# Key: read from FD 3 ONLY (64 hex = AES-256). Absent/invalid/wrong-length → exit 9 (STOP).
# NONCE: a fresh random 12-byte IV per encryption (never reused with a key), carried
#   as the artefact prefix; the 16-byte GCM tag is the suffix.
# GCM AUTHENTICATE-BEFORE-RELEASE: decrypt buffers, computes the plaintext, then runs
#   final() (the tag check) and assigns the plaintext ONLY if it succeeds — no
#   unauthenticated or partial plaintext is ever written. A truncated/tampered
#   ciphertext fails closed at exit 7 with an empty stdout.
F004_CRYPTO_JS='
import crypto from "node:crypto";
import fs from "node:fs";
const mode = process.argv[1];
const metaOut = process.argv[2] || "";
// BOUNDED SECRET CHANNEL: the key arrives only on inherited fd 3. It is absent from
// this process environment and from argv, so nothing this process spawns can see it.
let hex = "";
try { hex = fs.readFileSync(3).toString("utf8").trim(); } catch { hex = ""; }
if (!/^[0-9a-f]{64}$/i.test(hex)) { process.stderr.write("F004 encryption key absent/invalid on fd 3 (need 64 hex)\n"); process.exit(9); }
const key = Buffer.from(hex, "hex");
const chunks = []; for await (const c of process.stdin) chunks.push(c);
const input = Buffer.concat(chunks);
if (mode === "encrypt") {
  const iv = crypto.randomBytes(12);
  const cph = crypto.createCipheriv("aes-256-gcm", key, iv);
  const body = Buffer.concat([cph.update(input), cph.final()]);
  if (metaOut) fs.writeFileSync(metaOut, crypto.createHash("sha256").update(input).digest("hex") + "\t" + input.length);
  process.stdout.write(Buffer.concat([iv, body, cph.getAuthTag()]));
} else if (mode === "decrypt") {
  if (input.length < 28) { process.stderr.write("ciphertext too short\n"); process.exit(8); }
  const iv = input.subarray(0,12), tag = input.subarray(input.length-16), b = input.subarray(12, input.length-16);
  const d = crypto.createDecipheriv("aes-256-gcm", key, iv); d.setAuthTag(tag);
  let pt;
  try { pt = Buffer.concat([d.update(b), d.final()]); }   // final() authenticates; throws on a bad/truncated tag
  catch { process.stderr.write("decrypt auth failed\n"); process.exit(7); }   // fail closed, nothing released
  process.stdout.write(pt);   // reached ONLY when the tag authenticated
} else { process.stderr.write("bad crypto mode\n"); process.exit(3); }
'
# The crypto child runs with the key STRIPPED from its environment and delivered on fd 3.
f004_crypto_run() {
  local mode="$1" meta="${2:-}"
  env -u F004_ENC_KEY -u F004_PT_META_OUT -u F004_PT_HASH_OUT \
    node --input-type=module -e "$F004_CRYPTO_JS" "$mode" "$meta" 3< <(printf '%s' "${F004_ENC_KEY:-}")
}
f004_encrypt() { f004_crypto_run encrypt "${1:-}"; }
f004_decrypt() { f004_crypto_run decrypt ""; }
f004_sha()     { node -e 'const h=require("node:crypto").createHash("sha256");process.stdin.on("data",c=>h.update(c));process.stdin.on("end",()=>process.stdout.write(h.digest("hex")))'; }
f004_lower()   { printf '%s' "${1:-}" | tr 'A-Z' 'a-z'; }

# ── Reversible, versioned destination-identity encoding (finding R1-03). ──
# The repository's real R2 keys are path-shaped (`reports/<scan>.json`,
# `reports/snapshots/<ws>/<scan>/<snap>.json`). They are percent-encoded into a single
# opaque segment — reversible byte-for-byte, and structurally incapable of containing
# `/`, so an encoded object can never escape or alias another namespace.
F004_NS_VER="v1"
f004_ns_d1()       { printf '%s/d1/database' "$F004_NS_VER"; }
f004_ns_manifest() { printf '%s/manifest/backup' "$F004_NS_VER"; }
f004_ns_r2()       { printf '%s/r2/%s' "$F004_NS_VER" "${1:?encoded key}"; }

f004_key_encode() {
  local s="${1-}" out="" i=0 n c
  n=${#s}
  while [ "$i" -lt "$n" ]; do
    c="${s:$i:1}"
    case "$c" in
      [A-Za-z0-9._-]) out="$out$c" ;;
      *) out="$out$(printf '%%%02X' "'$c")" ;;
    esac
    i=$((i+1))
  done
  printf '%s' "$out"
}
f004_key_decode() {
  local s="${1-}" out="" i=0 n hex byte
  n=${#s}
  while [ "$i" -lt "$n" ]; do
    case "${s:$i:1}" in
      %) hex="${s:$((i+1)):2}"
         case "$hex" in [0-9A-F][0-9A-F]) : ;; *) return 1 ;; esac
         byte="$(printf "\\x$hex")"
         case "$byte" in ""|[!!-~]) return 1 ;; esac   # only printable ASCII is representable
         out="$out$byte"; i=$((i+3)) ;;
      *) out="$out${s:$i:1}"; i=$((i+1)) ;;
    esac
  done
  printf '%s' "$out"
}

# ── Guards (pure; no side effects). SAFE returns 0; each unsafe path returns
#    non-zero on a uniquely tagged line for the mutation suite. ──

assert_encrypted_destination() {
  local dest="${1:-}"
  case "$dest" in
    age:*|gpg:*|r2+sse://*|s3+sse://*) return 0 ;;
  esac
  return 1  # REJECT:ENC  (plaintext / local / unknown destination scheme)
}

# Defence-in-depth (redundant with assert_encrypted_destination on the run path,
# which rejects every local path first; retained + unit-covered, NOT independently
# reachable on the run path — see the report's honest guard accounting).
assert_not_plaintext_local() {
  local dest="${1:-}"
  case "$dest" in
    /*|./*|../*|~*|file:*) return 1 ;;  # REJECT:PLAINTEXT  (local disk path)
  esac
  return 0
}

# G-KEY: the encryption key must be present and exactly 64 hex (32 bytes) BEFORE any
# provider action; WE hold it, it never reaches the provider. Absent/invalid = STOP.
assert_encryption_key() {
  case "${F004_ENC_KEY:-}" in
    ?*) : ;;
    *) return 1 ;;               # REJECT:KEYABSENT
  esac
  case "${F004_ENC_KEY}" in
    *[!0-9A-Fa-f]*) return 1 ;;  # REJECT:KEYCHARS
  esac
  [ "${#F004_ENC_KEY}" -eq 64 ] || return 1  # REJECT:KEYLEN
  return 0
}

# G-ENVCONFINE (finding R1-02): the provider environment is an explicit allowlist and
# may never name a secret, an evidence path, or a non-identifier.
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

assert_d1_hash_match() {
  local expected="${1:-}" actual="${2:-}"
  if [ -n "$expected" ] && [ "$expected" = "$actual" ]; then return 0; fi
  return 1  # REJECT:D1HASH  (D1 backup round-trip hash mismatch / empty)
}

assert_source_stable() {
  local before="${1:-}" after="${2:-}"
  if [ "$before" = "$after" ]; then return 0; fi
  return 1  # REJECT:MOVING  (source inventory drifted during copy)
}

assert_r2_manifests_equal() {
  local src="${1:-}" dst="${2:-}"
  if [ -n "$src" ] && [ "$src" = "$dst" ]; then return 0; fi
  return 1  # REJECT:R2SET  (missing / extra key or round-trip hash mismatch)
}

may_emit_success() {
  if [ "${1:-}" = "PASS" ]; then return 0; fi
  return 1  # REJECT:VERIFY  (verification did not pass — no success record)
}

backup_is_fresh() {
  local last_epoch="${1:-}" now_epoch="${2:-}" max_age_s="${3:-}"
  case "$last_epoch$now_epoch$max_age_s" in *[!0-9]*|"") return 1 ;; esac  # REJECT:STALE_INPUT
  if [ "$last_epoch" -le 0 ]; then return 1; fi   # REJECT:STALE_ABSENT
  local age=$(( now_epoch - last_epoch ))
  if [ "$age" -ge 0 ] && [ "$age" -le "$max_age_s" ]; then return 0; fi
  return 1  # REJECT:STALE  (last successful run older than max_age)
}

# G-KEYCONFINE: a SOURCE R2 key must be traversal-free and drawn from the unambiguous
# object charset. Slash IS permitted — the production keyspace is path-shaped and the
# reversible encoding, not this guard, is what confines it to one destination segment.
assert_safe_key() {
  local key="${1:-}"
  case "$key" in
    ""|/*|../*|*/../*|*/..|*//*) return 1 ;;    # REJECT:KEYTRAVERSAL
  esac
  case "$key" in *[!A-Za-z0-9._~=+%/-]*) return 1 ;; esac   # REJECT:KEYCHARS2
  return 0
}

# G-KEYRT (finding R1-03): the encoding must be provably reversible for the exact key
# being stored, on the run path — not merely asserted in a unit test.
assert_key_roundtrip() {
  local original="${1-}" decoded="${2-}"
  if [ -n "$original" ] && [ "$original" = "$decoded" ]; then return 0; fi
  return 1  # REJECT:KEYRT  (destination identity is not reversible to the source key)
}

# G-DESTID (finding R1-03): a destination identity must be unique and must never be a
# reserved slot. `d1` as an OBJECT key encodes to v1/r2/d1 and cannot reach v1/d1/database.
assert_dest_identity_free() {
  local id="${1:-}" taken="${2:-}"
  case "$id" in "") return 1 ;; esac                      # REJECT:DESTEMPTY
  if [ "$id" = "$(f004_ns_d1)" ] || [ "$id" = "$(f004_ns_manifest)" ]; then
    return 1                                             # REJECT:DESTRESERVED
  fi
  case "$taken" in *"|$id|"*) return 1 ;; esac            # REJECT:DESTDUP
  return 0
}

# G-MANIFEST (finding R1-01): the stored manifest must be hash-bound — the artefact
# read back from the destination must equal the manifest we encrypted.
assert_manifest_binding() {
  local expected="${1:-}" actual="${2:-}"
  if [ -n "$expected" ] && [ "$expected" = "$actual" ]; then return 0; fi
  return 1  # REJECT:MANIFESTBIND  (stored manifest does not round-trip)
}

# G-DESTSET (finding R1-03): after EVERY write, the COMPLETE final destination listing
# must equal the expected identity set exactly — no missing, extra, or overwritten slot.
assert_destination_complete() {
  local expected="${1:-}" observed="${2:-}"
  if [ -n "$expected" ] && [ "$expected" = "$observed" ]; then return 0; fi
  return 1  # REJECT:DESTSET  (final destination listing differs from the recorded set)
}

assert_final_readback() {
  local expected="${1:-}" actual="${2:-}"
  if [ -n "$expected" ] && [ "$expected" = "$actual" ]; then return 0; fi
  return 1  # REJECT:DESTREREAD  (post-write re-read does not match the manifest record)
}

# G-DOMAIN (finding R1-04): an INDEPENDENT recovery domain. A label is not proof; this
# takes a measured provider/account/endpoint/bucket tuple and rejects the source domain.
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

# ── F-027 bridge guards (governance amendment, 26 Aug 2026) ─────────────────────────
# The accepted F-027 deadman reads operational_events(event_type='backup_completed')
# (ops-health.js `latestOperationalEvent`), and its own comment says "F-004 emits the
# event" — but no producer existed anywhere in product code. /ready still returned 200
# while the external deadman could never leave backup_stale. These guards make the
# producer fail-closed: nothing is recorded before full verification, and a backup that
# cannot durably record its event is not a successful backup.
F004_EVENT_TYPE="backup_completed"

# Deterministic primary key, byte-identical to the accepted derivation in
# operational-events.js: opev_ + first 32 hex of sha256("<event_type> <correlation_id>").
f004_event_id() {
  node -e 'const c=require("node:crypto");process.stdout.write("opev_"+c.createHash("sha256").update(process.argv[1]+" "+process.argv[2]).digest("hex").slice(0,32))' "${1:?event type}" "${2:?correlation id}"
}

# G-EVENTSRC: the ledger row is SOURCE state. It must bind the source D1/account identity
# and must never be attributed to the recovery destination account.
assert_event_source_binding() {
  local d1="${1:-}" acct="${2:-}" dest_acct="${3:-}"
  if [ -z "$d1" ] || [ -z "$acct" ]; then return 1; fi   # REJECT:EVENTSRCABSENT
  if [ "$acct" = "$dest_acct" ]; then return 1; fi       # REJECT:EVENTSRCISDEST
  return 0
}

# G-EVENTCORR: mirrors the accepted SAFE_TOKEN /^[\w:.\-]{1,200}$/ so a correlation id
# this producer emits can never be rejected by the accepted writer boundary.
assert_event_correlation() {
  local c="${1:-}"
  case "$c" in
    ""|*[!A-Za-z0-9_:.-]*) return 1 ;;   # REJECT:EVENTCORR
  esac
  [ "${#c}" -le 200 ] || return 1        # REJECT:EVENTCORRLEN
  return 0
}

# G-EVENTACK: the confirmation must name the EXACT row this run derived. `recorded` and
# `duplicate` are both durable success — UNIQUE(event_type, correlation_id) makes one
# logical backup one row — but anything else, including a different id, fails closed.
assert_event_recorded() {
  local ack="${1:-}" expect="${2:-}"
  [ -n "$expect" ] || return 1                          # REJECT:EVENTIDABSENT
  case "$ack" in
    "recorded $expect"|"duplicate $expect") return 0 ;;
  esac
  return 1  # REJECT:EVENTACK  (absent, malformed, or a different row than we derived)
}

# The producer itself. Called ONCE, only after every verification and the freshness check
# have passed, and before any local success record exists.
record_backup_completed_event() {
  local dest_acct="${1:-}" run_epoch="${2:-}" manifest_sha="${3:-}" corr eid ack
  assert_event_source_binding "$F004_D1_NAME" "${F004_SRC_ACCOUNT:-}" "$dest_acct" \
    || die "backup_completed event is not bound to the source D1/account identity"
  corr="backup:${run_epoch}:${manifest_sha}"
  assert_event_correlation "$corr" || die "backup_completed correlation id is not a safe token"
  eid="$(f004_event_id "$F004_EVENT_TYPE" "$corr")"
  ack="$(provider record_backup_completed "$corr" "$eid")"
  assert_event_recorded "$ack" "$eid" || die "backup_completed event was not durably recorded — no success record"
  F004_EVENT_ID="$eid"; F004_EVENT_CORRELATION="$corr"; F004_EVENT_ACK="${ack%% *}"
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

# G-DESTIDENTITY (finding R1-04): the identity the provider MEASURES must equal the
# identity the run DECLARED. Ambient provider selection is never accepted.
assert_destination_identity() {
  local declared="${1:-}" measured="${2:-}"
  if [ -z "$declared" ] || [ -z "$measured" ]; then return 1; fi   # REJECT:DESTIDABSENT
  if [ "$declared" = "$measured" ]; then return 0; fi
  return 1  # REJECT:DESTIDENTITY  (provider is not the declared recovery domain)
}

# ── Real command envelopes (pinned Wrangler 4.120.0 supported forms — verified
#    offline; NEVER executed in the author stage). Each echoes the argv it would
#    exec. Deliberately the SUPPORTED forms: d1 export to a FIFO path (never
#    `--output -`); r2 object get/put `--pipe` (never `--file -`); an S3-compatible
#    list adapter (Wrangler 4.120.0 has no `r2 object list`); node:crypto for
#    encryption (never `openssl enc -aes-256-gcm`, which OpenSSL 3.x rejects as AEAD).
#    FIFO acceptance and S3 listing behaviour are RUNTIME → NOT MEASURED (fail-closed). ──
env_d1_export()  { printf 'wrangler d1 export %s --remote --output %s\n' "$F004_D1_NAME" "${1:?fifo path}"; }
env_r2_list()    { printf 'aws s3api list-objects-v2 --bucket %s --endpoint-url %s\n' "$F004_R2_BUCKET" "${F004_S3_ENDPOINT:-<endpoint>}"; }
env_r2_get()     { printf 'wrangler r2 object get %s/%s --pipe --remote\n' "$F004_R2_BUCKET" "${1:?key}"; }
env_store_put()  { printf 'aws s3api put-object --bucket %s --key %s --endpoint-url %s\n' "${F004_DEST_BUCKET:-<off-store>}" "${1:?name}" "${F004_DEST_ENDPOINT:-<off-endpoint>}"; }
env_store_get()  { printf 'aws s3api get-object --bucket %s --key %s --endpoint-url %s\n' "${F004_DEST_BUCKET:-<off-store>}" "${1:?name}" "${F004_DEST_ENDPOINT:-<off-endpoint>}"; }

# ── Test-only provider protocol: allowlisted op names, metadata schema-checked,
#    invoked as a SEPARATE PROCESS under an EXPLICIT ALLOWLISTED ENVIRONMENT
#    (`env -i` + F004_PROVIDER_BASE_ENV + F004_PROVIDER_ENV_ALLOW). No sourcing;
#    fail-closed on a missing/invalid provider. Byte-stream ops carry bytes over the
#    pipe; metadata ops carry text. The provider NEVER receives the encryption key,
#    the plaintext-metadata path, the evidence path, or any other secret. ──
PROVIDER_OPS="now r2_list verify_summary d1_export r2_object store_put store_get src_identity dest_identity dest_list record_backup_completed"
provider_schema_ok() {   # metadata ops only; byte-stream ops validated by downstream crypto/hash
  local op="$1" out="$2" tab=$'\t'
  case "$op" in
    now)            printf '%s' "$out" | grep -qxE '[0-9]+' ;;
    verify_summary) case "$out" in PASS|FAIL) return 0 ;; *) return 1 ;; esac ;;
    r2_list)        [ -z "$out" ] || ! printf '%s\n' "$out" | grep -qvE "^[A-Za-z0-9._~=+%/-]+${tab}[0-9]+${tab}[0-9a-f]{64}$" ;;
    dest_list)      [ -z "$out" ] || ! printf '%s\n' "$out" | grep -qvE "^[A-Za-z0-9._~=+%/-]+${tab}[0-9]+${tab}[0-9a-f]{64}$" ;;
    src_identity)   printf '%s' "$out" | grep -qxE '[A-Za-z0-9._-]+' ;;
    dest_identity)  printf '%s' "$out" | grep -qxE "[A-Za-z0-9._+-]+${tab}[A-Za-z0-9._-]+${tab}[A-Za-z0-9._:/+-]+${tab}[A-Za-z0-9._-]+" ;;
    record_backup_completed) printf '%s' "$out" | grep -qxE '(recorded|duplicate) opev_[0-9a-f]{32}' ;;
    *) return 0 ;;
  esac
}
# Build the EXACT environment the provider is allowed to see. Nothing else crosses.
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
provider_guard() {   # shared allowlist + fail-closed availability + env confinement
  local op="$1"
  case " $PROVIDER_OPS " in *" $op "*) : ;; *) die "provider op not allowlisted: $op" ;; esac
  [ -n "${F004_PROVIDER_CMD:-}" ] || die "no provider protocol available in the author stage (op: $op) — a live run is Integration/founder territory"
  { [ -f "$F004_PROVIDER_CMD" ] && [ -x "$F004_PROVIDER_CMD" ]; } || die "test provider supplied but missing/not executable — STOP before any provider action"
  assert_env_allowlist "${F004_PROVIDER_ENV_ALLOW:-}" || die "provider environment allowlist names a secret or is malformed"
  provider_env_argv
}
provider() {         # metadata op: capture stdout, schema-check
  local op="${1:?provider op}"; shift
  provider_guard "$op"
  local out; out="$("${F004_ENVARGV[@]}" "$F004_PROVIDER_CMD" "$op" "$@")" || die "provider op failed: $op"
  provider_schema_ok "$op" "$out" || die "provider output failed schema for op: $op"
  printf '%s' "$out"
}
provider_stream() {  # byte-stream op: pass provider stdout straight through (to a pipe)
  local op="${1:?provider op}"; shift
  provider_guard "$op"
  "${F004_ENVARGV[@]}" "$F004_PROVIDER_CMD" "$op" "$@"
}
provider_sink() {    # byte-stream op: pass our stdin to the provider (e.g. store_put)
  local op="${1:?provider op}"; shift
  provider_guard "$op"
  "${F004_ENVARGV[@]}" "$F004_PROVIDER_CMD" "$op" "$@"
}

# ── Dispatchers (strictly allowlisted; execute nothing but a fixed envelope/guard). ──
if [ "${1:-}" = "--crypto" ]; then
  shift; m="${1:?crypto mode}"; shift || true
  set +e
  case "$m" in encrypt) f004_encrypt "${1:-}" ;; decrypt) f004_decrypt ;; *) echo "bad crypto mode: $m" >&2; exit 3 ;; esac
  exit $?
fi
if [ "${1:-}" = "--keycodec" ]; then
  shift; m="${1:?codec mode}"; shift || true
  set +e
  case "$m" in
    encode) f004_key_encode "${1-}" ;;
    decode) f004_key_decode "${1-}" ;;
    dest)   f004_ns_r2 "$(f004_key_encode "${1-}")" ;;
    *) echo "bad keycodec mode: $m" >&2; exit 3 ;;
  esac
  rc=$?; echo; exit "$rc"
fi
if [ "${1:-}" = "--envelope" ]; then
  shift; op="${1:?envelope op}"; shift || true
  case "$op" in
    d1_export) env_d1_export "$@" ;; r2_list) env_r2_list "$@" ;; r2_get) env_r2_get "$@" ;;
    store_put) env_store_put "$@" ;; store_get) env_store_get "$@" ;;
    *) echo "unknown envelope op: $op" >&2; exit 3 ;;
  esac
  exit 0
fi
if [ "${1:-}" = "--selftest" ]; then
  shift; fn="${1:?guard name}"; shift || true
  case "$fn" in
    assert_encrypted_destination|assert_not_plaintext_local|assert_encryption_key|assert_d1_hash_match|assert_source_stable|assert_r2_manifests_equal|may_emit_success|backup_is_fresh|assert_safe_key|assert_env_allowlist|assert_key_roundtrip|assert_dest_identity_free|assert_manifest_binding|assert_destination_complete|assert_final_readback|assert_recovery_domain|assert_destination_identity|assert_source_account|assert_adapter_identity|assert_event_source_binding|assert_event_correlation|assert_event_recorded|assert_source_account_bound) : ;;
    *) echo "selftest name not allowlisted: $fn" >&2; exit 3 ;;
  esac
  set +e; "$fn" "$@"; rc=$?; set -e
  [ "$rc" -eq 0 ] && echo "GUARD_ALLOW" || echo "GUARD_REJECT"
  exit "$rc"
fi

# ── Real run: full backup, every guard on this path; providers via the protocol under
#    a confined environment; node:crypto client-side with an fd-3 key channel; a real
#    encrypt→store→readback→decrypt→hash round-trip; a persisted hash-bound manifest;
#    and a COMPLETE post-write destination re-read before any success record. ──
main() {
  if [ "${F004_CONFIRM_REAL_RUN:-no}" != "yes" ]; then
    echo "refusing: set F004_CONFIRM_REAL_RUN=yes to run a real backup (author stage does not)." >&2
    exit 2
  fi
  assert_encryption_key || die "encryption key absent/invalid — STOP before any provider action"
  local dest="${F004_BACKUP_DEST:-}"
  assert_encrypted_destination "$dest" || die "destination is not encrypted"
  assert_not_plaintext_local  "$dest" || die "destination is a plaintext local path"
  # MANDATORY source account (finding R1-04) — bound before any provider action.
  assert_source_account || die "source account identity is absent or malformed — STOP before any provider action"

  # DECLARED recovery domain — an independent provider/account/endpoint/bucket.
  local declared
  declared="${F004_DEST_PROVIDER:-}"$'\t'"${F004_DEST_ACCOUNT:-}"$'\t'"${F004_DEST_ENDPOINT:-}"$'\t'"${F004_DEST_BUCKET:-}"
  assert_recovery_domain "${F004_DEST_PROVIDER:-}" "${F004_DEST_ACCOUNT:-}" "${F004_DEST_ENDPOINT:-}" "${F004_DEST_BUCKET:-}" \
    || die "declared destination is not an independent recovery domain"

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

  F004_WORK="$(mktemp -d)"; local work="$F004_WORK"
  local last d1_src d1_back inv1 inv2 destman status now key size hash
  last="$(provider now)"

  # MEASURED recovery domain — reconciled THROUGH the provider protocol. The label in
  # F004_BACKUP_DEST is never accepted as proof of an independent disaster domain.
  local measured mp ma me mb
  measured="$(provider dest_identity)"
  assert_destination_identity "$declared" "$measured" || die "provider destination identity does not match the declared recovery domain"
  IFS=$'\t' read -r mp ma me mb <<EOF
$measured
EOF

  # D1: stream plaintext → hash-while-encrypt → store ciphertext under the D1 namespace;
  # read back → decrypt → hash. The plaintext metadata path is an ARGUMENT to the local
  # crypto process, never an exported variable, so no provider child can observe it.
  local d1_dest d1_bytes
  d1_dest="$(f004_ns_d1)"
  provider_stream d1_export | f004_encrypt "$work/d1.meta" | provider_sink store_put "$d1_dest"
  [ -s "$work/d1.meta" ] || die "D1 plaintext metadata was not produced by the crypto stage"
  d1_src="$(cut -f1 "$work/d1.meta")"
  d1_bytes="$(cut -f2 "$work/d1.meta")"
  d1_back="$(provider_stream store_get "$d1_dest" | f004_decrypt | f004_sha)"
  assert_d1_hash_match "$d1_src" "$d1_back" || die "D1 stored artifact does not round-trip to the export"

  # R2: source inventory, confine every key, encode it REVERSIBLY into a disjoint
  # namespace, reject any duplicate/reserved destination identity, per-object
  # encrypt→store→readback→decrypt→hash, then source inventory again for stability.
  inv1="$(provider r2_list)"
  destman=""
  local manifest_r2="" taken="|" expect_tbl=""
  while IFS=$'\t' read -r key size hash; do
    [ -n "$key" ] || continue
    assert_safe_key "$key" || die "unsafe R2 manifest key: $key"
    local enc dec dk back
    enc="$(f004_key_encode "$key")"
    dec="$(f004_key_decode "$enc")" || die "destination identity is not decodable for key: $key"
    assert_key_roundtrip "$key" "$dec" || die "destination identity does not reverse to the source key: $key"
    dk="$(f004_ns_r2 "$enc")"
    assert_dest_identity_free "$dk" "$taken" || die "duplicate or reserved destination identity: $dk"
    taken="${taken}${dk}|"
    provider_stream r2_object "$key" | f004_encrypt "$work/obj.meta" | provider_sink store_put "$dk"
    back="$(provider_stream store_get "$dk" | f004_decrypt | f004_sha)"
    # destman carries the ROUND-TRIP hash (what the destination gave back) and is compared
    # against the source inventory below. The MANIFEST and the post-write expectation table
    # carry the SOURCE hash — a recovery record must state what the source held, or a store
    # that silently returns different valid ciphertext would be recorded as correct.
    destman="${destman}${key}"$'\t'"${size}"$'\t'"${back}"$'\n'
    manifest_r2="${manifest_r2}r2"$'\t'"${key}"$'\t'"${dk}"$'\t'"${size}"$'\t'"${hash}"$'\n'
    expect_tbl="${expect_tbl}${dk}"$'\t'"${hash}"$'\n'
  done <<EOF
$inv1
EOF
  destman="$(printf '%s' "$destman" | sed '/^$/d')"
  inv2="$(provider r2_list)"
  assert_source_stable "$inv1" "$inv2" || die "R2 source inventory moved during the copy"
  assert_r2_manifests_equal "$inv1" "$destman" || die "R2 destination set/round-trip-hash does not equal the source"

  # MANIFEST (finding R1-01): a versioned, ENCRYPTED, HASH-BOUND record of the complete
  # recovery set. The restore cannot materialise anything without consuming it.
  local man_dest man_body man_sha man_back
  man_dest="$(f004_ns_manifest)"
  man_body="f004-manifest-${F004_NS_VER}"$'\n'"d1"$'\t'"${d1_dest}"$'\t'"${d1_bytes}"$'\t'"${d1_src}"$'\n'"${manifest_r2}"
  man_body="$(printf '%s' "$man_body")"   # exact bytes; no trailing newline, so the restore hash matches
  printf '%s' "$man_body" | f004_encrypt "$work/man.meta" | provider_sink store_put "$man_dest"
  [ -s "$work/man.meta" ] || die "manifest plaintext metadata was not produced by the crypto stage"
  man_sha="$(cut -f1 "$work/man.meta")"
  man_back="$(provider_stream store_get "$man_dest" | f004_decrypt | f004_sha)"
  assert_manifest_binding "$man_sha" "$man_back" || die "stored manifest does not round-trip to the recorded manifest hash"

  # POST-WRITE COMPLETE DESTINATION RE-READ (finding R1-03): after EVERY write, the whole
  # destination must still hold exactly the recorded identity set, and every member must
  # still decrypt to its recorded plaintext hash. An object that overwrote an
  # earlier-verified slot is caught HERE — after the write that caused it.
  expect_tbl="${expect_tbl}${d1_dest}"$'\t'"${d1_src}"$'\n'"${man_dest}"$'\t'"${man_sha}"$'\n'
  local final_list exp_ids obs_ids did dsize dcsha want got
  final_list="$(provider dest_list)"
  exp_ids="$(printf '%s' "$expect_tbl" | awk -F'\t' 'NF{print $1}' | sort)"
  obs_ids="$(printf '%s' "$final_list" | awk -F'\t' 'NF{print $1}' | sort)"
  assert_destination_complete "$exp_ids" "$obs_ids" || die "final destination listing does not equal the recorded identity set"
  while IFS=$'\t' read -r did dsize dcsha; do
    [ -n "$did" ] || continue
    want="$(printf '%s' "$expect_tbl" | awk -F'\t' -v k="$did" 'NF && $1==k {print $2}')"
    got="$(provider_stream store_get "$did" | f004_decrypt | f004_sha)"
    assert_final_readback "$want" "$got" || die "post-write destination re-read mismatch at $did"
  done <<EOF
$final_list
EOF

  status="$(provider verify_summary)"
  may_emit_success "$status" || die "final verification did not PASS — no success record"

  now="$(provider now)"
  backup_is_fresh "$last" "$now" "$F004_MAX_AGE" || die "backup freshness window failed"

  # F-027 BRIDGE — everything above has passed; only now may the deadman be told. A failure
  # here exits nonzero with NO success record, and the verified artefacts remain for retry.
  record_backup_completed_event "$ma" "$last" "$man_sha"

  {
    printf 'backup=success\n'
    printf 'd1_sha256=%s\n' "$d1_back"
    printf 'r2_objects=%s\n' "$(printf '%s\n' "$inv1" | grep -c .)"
    printf 'manifest_dest=%s\n' "$man_dest"
    printf 'manifest_sha256=%s\n' "$man_sha"
    printf 'dest_provider=%s\n' "$mp"
    printf 'dest_account=%s\n' "$ma"
    printf 'dest_endpoint=%s\n' "$me"
    printf 'dest_bucket=%s\n' "$mb"
    printf 'src_account=%s\n' "$F004_SRC_ACCOUNT"
    printf 'src_account_measured=%s\n' "$measured_src"
    printf 'adapter_sha256=%s\n' "$adapter_sha"
    printf 'adapter_role=%s\n' "$adapter_role"
    printf 'backup_event_id=%s\n' "$F004_EVENT_ID"
    printf 'backup_event_correlation=%s\n' "$F004_EVENT_CORRELATION"
    printf 'backup_event_ack=%s\n' "$F004_EVENT_ACK"
    printf 'at=%s\n' "$now"
  } > "${F004_EVIDENCE_OUT:-/dev/stdout}"
  echo "backup verified and recorded" >&2
}

case "${1:-}" in
  run) shift; main "$@" ;;
  *) echo "usage: $0 [run | --crypto <mode> | --keycodec <mode> <key> | --envelope <op> | --selftest <guard> <args...>]" >&2; exit 2 ;;
esac
