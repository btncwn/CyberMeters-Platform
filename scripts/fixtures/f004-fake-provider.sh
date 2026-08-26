#!/usr/bin/env bash
#
# F-004 — deterministic FAKE SECOND PROVIDER (author-stage test fixture only).
#
# It is NEVER a live provider and never touches Cloudflare, D1, R2 or any network.
# It models exactly three things the successor-2 fixture could not, and which
# findings F004-S2-R1-01..04 require to be executable rather than prose:
#
#   1. an OFF-PROVIDER STORE ($FAKE_STORE/dest) that really holds ciphertext under the
#      backup's versioned destination identities, and can be listed (`dest_list`);
#   2. a DISPOSABLE TARGET ESTATE ($FAKE_STORE/target/<id>) that really RECEIVES
#      replayed D1 bytes and restored R2 objects, and can be independently re-read
#      (`verify_d1`, `verify_r2`, `target_r2_list`);
#   3. an INDEPENDENT RECOVERY-DOMAIN IDENTITY it reports over the protocol
#      (`dest_identity`) — a second provider/account/endpoint/bucket, not Cloudflare.
#
# Every invocation writes an ENVIRONMENT CANARY to $FAKE_STORE/env/<op>.<pid>, which is
# how the validator proves for EVERY operation that the provider never received
# F004_ENC_KEY, a plaintext-metadata path, an evidence path or an expectation value.
#
# Fault injection is entirely by allowlisted FAKE_* environment variables so the
# validator can drive negative cases without editing this file.
#
set -euo pipefail
op="${1:-}"; shift || true
S="${FAKE_STORE:-}"
[ -n "$S" ] || { echo "fake: FAKE_STORE unset" >&2; exit 1; }
mkdir -p "$S/dest" "$S/target" "$S/env"
touch "$S/.called"
/usr/bin/env > "$S/env/$op.$$"

sha(){ node -e 'const h=require("node:crypto").createHash("sha256");process.stdin.on("data",c=>h.update(c));process.stdin.on("end",()=>process.stdout.write(h.digest("hex")))'; }
flat(){ printf '%s' "$1" | tr '/' '~'; }
unflat(){ printf '%s' "$1" | tr '~' '/'; }
obj(){ printf 'object-bytes-for-%s' "$1"; }

# The repository's real R2 keyspace is path-shaped. `d1` and `v1/d1/database` are
# deliberate ALIAS PROBES: under the successor-2 raw scheme they collided with the D1
# slot and produced a false-success backup (finding R1-03).
KEYS="${FAKE_KEYS:-reports/scan_1.json reports/snapshots/ws_9/scan_1/snap_1.json d1 v1/d1/database}"

case "$op" in
  now)
    if [ -n "${FAKE_NOW2:-}" ] && [ -f "$S/.n" ]; then echo "${FAKE_NOW2}"; else :>"$S/.n"; echo "${FAKE_NOW:-1000}"; fi ;;
  backup_epoch) echo "${FAKE_BACKUP_EPOCH:-999}" ;;
  verify_summary) echo "${FAKE_VERIFY:-PASS}" ;;

  # ── Source account, MEASURED under the source credential context (successor #5) ──
  src_identity) printf '%s\n' "${FAKE_SRC_ACCOUNT:-acct-prod-1}" ;;

  # ── Independent recovery-domain identity, measured over the protocol ──
  dest_identity)
    printf '%s\t%s\t%s\t%s\n' \
      "${FAKE_DP:-s3-compatible-offsite}" "${FAKE_DA:-acct-recovery-9}" \
      "${FAKE_DE:-https://s3.us-west-002.example-offsite.com}" "${FAKE_DB:-f004-offsite}" ;;

  # ── Source (production) side ──
  r2_list)
    keys="$KEYS"
    if [ "${FAKE_MOVING:-0}" = "1" ] && [ -f "$S/.inv" ]; then keys="$(printf '%s\n' $KEYS | head -1)"; fi
    :>"$S/.inv"
    for k in $keys; do p="$(obj "$k")"; printf '%s\t%s\t%s\n' "$k" "${#p}" "$(printf '%s' "$p"|sha)"; done ;;
  d1_export) printf 'CREATE TABLE t(a);\nINSERT INTO t VALUES(1);\n' ;;
  r2_object) obj "$1" ;;

  # ── Off-provider store ──
  store_put) printf '%s\n' "$1" >> "$S/.putkeys"; cat > "$S/dest/$(flat "$1")" ;;
  store_get)
    f="$(flat "$1")"
    if [ "$1" = "${FAKE_CORRUPT_KEY:-}" ]; then
      head -c 5 "$S/dest/$f"
    elif [ -n "${FAKE_SWAP_R2:-}" ] && [ "$1" = "${FAKE_SWAP_R2}" ]; then
      cat "$S/dest/$(flat "${FAKE_SWAP_TO:-}")"
    elif [ -n "${FAKE_EARLY_SWAP:-}" ] && [ "$1" = "${FAKE_EARLY_SWAP}" ] && [ ! -f "$S/dest/$(flat v1/manifest/backup)" ]; then
      # only BEFORE the manifest (the final write) exists — isolates the source-vs-round-trip
      # comparison, the only guard that sees a swap the manifest would otherwise bake in
      cat "$S/dest/$(flat "${FAKE_EARLY_SWAP_TO:-}")"
    elif [ -n "${FAKE_LATE_SWAP:-}" ] && [ "$1" = "${FAKE_LATE_SWAP}" ] && [ -f "$S/dest/$(flat v1/manifest/backup)" ]; then
      # only AFTER the manifest (the final write) exists — proves the post-write re-read
      cat "$S/dest/$(flat "${FAKE_LATE_SWAP_TO:-}")"
    else
      cat "$S/dest/$f"
    fi ;;
  dest_list)
    for p in "$S"/dest/*; do
      [ -e "$p" ] || continue
      id="$(unflat "$(basename "$p")")"
      if [ "$id" = "${FAKE_DEST_DELETE:-}" ]; then continue; fi
      printf '%s\t%s\t%s\n' "$id" "$(wc -c <"$p" | tr -d ' ')" "$(sha <"$p")"
    done ;;

  # ── F-027 operational_events ledger (mig 108 shape), with UNIQUE(event_type,
  #    correlation_id) modelled so a retry is an idempotent duplicate, not a second row. ──
  record_backup_completed)
    corr="$1"; id="$2"; led="$S/operational_events.tsv"; touch "$led"
    if [ "${FAKE_EVENT_FAIL:-0}" = "1" ]; then echo "fake: ledger write failed" >&2; exit 1; fi
    if [ -n "${FAKE_EVENT_ACK:-}" ]; then printf '%s\n' "${FAKE_EVENT_ACK}"; exit 0; fi
    if awk -F'\t' -v c="$corr" '$3=="backup_completed" && $4==c {f=1} END{exit !f}' "$led" 2>/dev/null; then
      printf 'duplicate %s\n' "$id"
    else
      # id, workspace_id(NULL), event_type, correlation_id, status, attempts, created_at
      printf '%s\t\t%s\t%s\t%s\t%s\t%s\n' "$id" "backup_completed" "$corr" "ok" "1" "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)" >> "$led"
      printf 'recorded %s\n' "$id"
    fi ;;

  # ── Disposable target estate ──
  create_staging) c="${FAKE_CREATED_AS:-$1}"; mkdir -p "$S/target/$c/r2"; printf '%s\n' "$c" ;;
  replay_d1)
    mkdir -p "$S/target/$1"
    if [ "${FAKE_SKIP_REPLAY:-0}" = "1" ]; then cat >/dev/null
    elif [ "${FAKE_TAMPER_TARGET_D1:-0}" = "1" ]; then cat >/dev/null; printf 'not-the-replayed-bytes' > "$S/target/$1/d1"
    else cat > "$S/target/$1/d1"; fi ;;
  restore_r2)
    mkdir -p "$S/target/$1/r2"
    if [ "${FAKE_SKIP_R2:-}" = "$2" ]; then cat >/dev/null
    elif [ "${FAKE_TAMPER_TARGET_R2:-}" = "$2" ]; then cat >/dev/null; printf 'not-the-restored-bytes' > "$S/target/$1/r2/$(flat "$2")"
    else cat > "$S/target/$1/r2/$(flat "$2")"; fi ;;
  verify_d1)
    if [ -f "$S/target/$1/d1" ]; then sha < "$S/target/$1/d1"; else printf '%064d' 0; fi ;;
  verify_r2)
    p="$S/target/$1/r2/$(flat "$2")"
    if [ -f "$p" ]; then sha < "$p"; else printf '%064d' 0; fi ;;
  target_r2_list)
    d="$S/target/$1/r2"
    if [ -n "${FAKE_EXTRA_TARGET_KEY:-}" ]; then printf '%s\n' "${FAKE_EXTRA_TARGET_KEY}"; fi
    if [ -d "$d" ]; then for p in "$d"/*; do [ -e "$p" ] || continue; unflat "$(basename "$p")"; echo; done; fi ;;

  # ── Verification of the restored estate ──
  check_integrity) echo "${FAKE_INTEGRITY:-ok}" ;;
  check_fk) echo "${FAKE_FK:-ok}" ;;
  check_schema) echo "ok" ;;
  check_tables) echo "${FAKE_TABLES:-eq}" ;;
  check_rows) echo "eq" ;;
  check_r2) echo "${FAKE_R2:-eq}" ;;

  *) echo "fake: unknown op $op" >&2; exit 1 ;;
esac
