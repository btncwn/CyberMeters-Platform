# Backup & Restore Drill — CyberMeters (D1 + R2)

> **Status: PROVEN.** A full point-in-time backup of the production D1 database
> was exported, restored into a fresh database, and verified for schema, data
> fidelity, and referential integrity. This document is the standing runbook —
> re-run it on the cadence below and before any risky migration/deploy.

## Objectives (RPO / RTO)

| Metric | Target | Last measured |
|---|---|---|
| **RPO** (max data loss) | ≤ 24h for routine; on-demand snapshot before every migration/risky deploy | On-demand snapshot (point-in-time) |
| **RTO** (time to restore) | ≤ 15 min | **1.57 s** to restore 2.7 MB / 59 tables into a fresh DB (D1 import from the same SQL is minutes-scale; see note) |

The RTO measured here is the local SQL replay. A real production restore
(`wrangler d1 execute --file`) into a new D1 database is network-bound and
takes minutes for this dataset — still well within the 15-min target.

## Instrumentation (F-004)

Two guarded ops scripts encode this runbook so a backup or drill cannot silently
do the wrong thing:

* `scripts/ops/backup-production-data.sh` — exports D1 and copies every R2 object
  into a **client-encrypted, independent-recovery-domain** destination, then
  **persists a versioned, encrypted, hash-bound manifest** of the complete recovery
  set. It emits a success/freshness record **only after** the full verification (a
  per-artefact encrypt→store→read-back→decrypt→hash round-trip, R2 set/hash
  equality, manifest binding, and a **complete post-write re-read of the whole
  destination**) passes. Plaintext streams through the cipher and is never staged on
  the local disk.
* `scripts/ops/restore-production-backup-to-staging.sh` — restores into a
  **separately created, disposable staging** target only. It rejects every
  production name/ID/bucket, never uses D1 Time Travel, never restores in place, and
  **consumes the backup's manifest** before touching anything. For the D1 artefact
  and for **every manifest-listed R2 object** it decrypts the stored ciphertext,
  proves the byte contract, and **streams the authenticated plaintext into the target
  through `replay_d1` / `restore_r2` byte sinks** — then **independently re-reads what
  actually landed there** (`verify_d1`, `verify_r2`, `target_r2_list`) before running
  integrity + FK + schema + table/row + R2-set checks and reporting RPO/RTO. A
  restore cannot report success without material D1 replay and every listed object.

**Encryption is client-side AES-256-GCM via `node:crypto`** (the pinned Node 24
standard library — no external binary). *We* hold the key; it is never held by the
destination store and never written to disk in plaintext. A destination that also
provides at-rest SSE gets that as incidental defence-in-depth only — never as the
encryption boundary, never counted as evidence.

**Secret-free provider boundary.** The key reaches the local crypto process **only
over inherited file descriptor 3** — a bounded, per-process pipe. It is never on that
process's argv and is explicitly removed from its environment. Every provider
operation is executed under `env -i` with an **explicit allowlist** (`PATH`, `LC_ALL`
plus whatever `F004_PROVIDER_ENV_ALLOW` names), and the allowlist itself is rejected
if it names `F004_ENC_KEY`, a plaintext-metadata path, an evidence path or an
expectation value. The validator proves this with a **per-operation environment
canary** rather than in prose: it inspects the exact environment every provider
invocation received and fails if any secret, or the key's value, appears anywhere.

**Reversible, collision-free destination identity.** The repository's real R2 keys
are path-shaped (`reports/<scan>.json`,
`reports/snapshots/<workspace>/<scan>/<snapshot>.json`,
`reports/executive/<workspace>/<type>/<period>/executive-report.pdf`). Each source
key is **percent-encoded into a single opaque segment** and placed in a versioned,
disjoint namespace — `v1/d1/database`, `v1/r2/<encoded-key>`, `v1/manifest/backup`.
The encoding is proven reversible **for the exact key being stored, on the run
path**; duplicate and reserved destination identities are rejected. Because an
encoded object can never contain `/`, an object named `d1` or even
`v1/d1/database` lands at `v1/r2/d1` / `v1/r2/v1%2Fd1%2Fdatabase` and can never
overwrite the D1 or manifest slot.

**Enforced independent recovery domain.** A destination *label* such as
`r2+sse://…` is **never** accepted as proof of a separate disaster domain. The run
declares an explicit provider/account/endpoint/bucket identity, that identity is
**measured back through the provider protocol** and must match exactly, and the
declared tuple is rejected if it names Cloudflare/R2, the source provider, the
source account, or a production/source bucket. The **measured** identity is recorded
in the success evidence.

**The source account identity is MANDATORY.** Successor-3 defaulted `F004_SRC_ACCOUNT`
to empty and made the same-account rejection *conditional* on it being supplied, so a run
that omitted it passed while proving no account separation at all. Both scripts now bind
the source account **before any provider action**: absent or malformed is a STOP, an
account identical to the destination account is a STOP, and only a distinct account
proceeds. The bound account is recorded in the success evidence.

**The provider adapter is hash-bound to a repository-owned identity.** Successor-3
checked only that the caller-supplied `F004_PROVIDER_CMD` was a file and was executable,
so an independently byte-modified adapter was accepted and produced `backup=success`.
Both scripts now hash the adapter's **bytes** and refuse to take any provider action
unless that hash appears in `scripts/ops/f004-adapter-identities.txt`, which pins exactly
two identities: the repository-owned real adapter
(`scripts/ops/f004-provider-adapter.sh`, role `real`) and the deterministic author-stage
fake (`scripts/fixtures/f004-fake-provider.sh`, role `fixture`). An optional
`F004_ADAPTER_SHA256` operator pin must also match the measured bytes, and
`F004_REQUIRE_ADAPTER_ROLE=real` refuses a fixture outright. A byte-modified adapter stops
before the first provider operation and leaves no success record. The measured adapter
hash and role are recorded in the success evidence.

**The backup announces itself to the F-027 deadman.** Accepted F-027 computes its
operational verdict from `operational_events` where `event_type='backup_completed'`, and its
own staleness constant is annotated *"F-004 emits the event"* — but no producer existed
anywhere in product code. `/ready` kept returning 200 while the external deadman could never
leave `backup_stale`, so a silently dead backup was indistinguishable from a healthy one.

The backup now records exactly one such event, through the **same hash-pinned adapter**, as
its final act:

* it fires **only after every verification and the freshness check have passed** — never
  before, so a failed or partial backup announces nothing;
* the row matches migration 108 exactly: `workspace_id` NULL (platform-level, never returned
  to a tenant read), `event_type` `backup_completed`, `correlation_id`
  `backup:<run-start-epoch>:<manifest-sha256>`, `status` `ok`, `attempts` 1, `created_at`
  left to the database default;
* the primary key is the **accepted deterministic derivation** — `opev_` followed by the
  first 32 hex of `sha256("backup_completed <correlation_id>")` — so the same logical backup
  maps to the same row as it would from any other accepted writer;
* the write is `INSERT OR IGNORE` under `UNIQUE(event_type, correlation_id)`, so a **retry is
  an idempotent duplicate and still durable success**, not a second row;
* it is bound to the **source** D1 and source account. The ledger is production state, not
  recovery-destination state, and no destination credential or bucket is involved, so
  source/destination isolation is unchanged;
* **if the event cannot be durably recorded, or the confirmation is absent, malformed, or
  names a different row, the run exits non-zero and emits NO local success record.** The
  verified backup artefacts stay in place, so the operator retries rather than re-copies.

The controlled-live phase must still exercise the real deadman transition; this bridge makes
the event exist, it does not prove the monitor flips.

**The adapter publishes its complete operation contract.** `f004-provider-adapter.sh
--contract` emits, for every protocol operation, the exact argv plus its stdin/stdout/exit
discipline — generated by the *same* `f004_argv` function the real execution path would
exec, so the published contract cannot drift from what a real run issues. The validator
checks that contract covers every protocol operation with no extras, that every argv uses
only pinned Wrangler / S3-compatible subcommands and flags with no banned form, that the
declared pinned Wrangler version equals the repository's own pin in
`workers/scan-api/package.json`, and that each operation's stdin/stdout matches how the
ops scripts actually drive it. **The adapter contacts no provider in the author stage**: a
real operation exits 4 unless `F004_ADAPTER_REAL_EXEC=yes`, which is controlled-live
territory.

Two indirections are deliberate and declared. `d1_export` and `replay_d1` present a byte
stream to the protocol while the pinned CLI reads or writes a **path** — that is precisely
why the supported forms are `--output <path>` / `--file <path>` and never `--output -` /
`--file -`, and the adapter owns the FIFO on both sides. `verify_d1` and `verify_r2`
present **text** (a sha256 of what the target actually holds) while the CLI underneath
streams object bytes or query rows: the adapter hashes, the protocol compares.

**Two evidence categories, kept visibly separate:**
* **MEASURED** — the `node:crypto` round-trip: `validate-f004-recovery-instrumentation.js`
  drives the scripts' own `--crypto` boundary with zero provider access and proves
  encrypt→decrypt→hash equality, iv+tag framing, and — critically —
  authenticate-before-release: a flipped/truncated ciphertext fails closed at the
  GCM tag check with **no** plaintext emitted.
* **NOT MEASURED** — the provider command envelopes (`wrangler d1 export --remote
  --output <fifo>`, `wrangler r2 object get/put --pipe`, `wrangler d1 create` /
  `execute --remote --command|--file`, and an S3-compatible list adapter because
  Wrangler 4.120.0 has no `r2 object list`). Their **flags** are verified offline
  against the pinned CLI (`--envelope`), but FIFO acceptance and S3 listing are
  runtime behaviours **NOT MEASURED** here; they are never executed in the author
  stage. The byte-contract proof depends on neither.

**Every guard runs on the real `run` control flow** (`main`), driven end-to-end
through a **test-only provider protocol** — a *separate process* named by
`F004_PROVIDER_CMD`, with allowlisted op names and schema-checked output, that
cannot redefine `main` or the guards, cannot read the script's state, and does not
receive the key. There is **no sourced hook**. A supplied-but-missing/invalid
provider is a terminal STOP before any provider action. The fake models a real
store, so backup writes real ciphertext and restore reads *that* artefact back — a
genuine round-trip, not orchestration over canned returns. A `--selftest`
dispatcher (allowlisted to the guard names) is kept as unit convenience but is not
the path any guard is proven by.

**Honest guard accounting.** Of the run-path guards, **the load-bearing ones each
fire on `main`**; the following are **redundant defence-in-depth** and are retained
and unit-covered, but the suite does **not** claim every guard independently fires:

* `assert_not_plaintext_local` (backup) and `assert_not_in_place` (restore) — the
  stronger preceding guards (`assert_encrypted_destination`, `assert_restore_target`)
  reject those same inputs first, so their reject branches are **not independently
  reachable on the run path**.
* `assert_dest_identity_free`'s **duplicate** branch — it fires first on the run
  path, but the post-write destination-completeness check would also catch a
  duplicate. Its **reserved** branch *is* load-bearing and is mutation-killed.
* `assert_object_contract` (restore) — it deliberately runs *before* any plaintext is
  released to the target, but a wrong-content object would also be caught afterwards
  by `assert_materialised` re-reading the target. It is kept because failing before
  mutating the target is the safer order, not because it changes the exit code.
* The recovery domain is checked **once** on the declared tuple, and the provider's
  measured tuple is bound to it by exact equality — a second domain check on the
  measured tuple would be unreachable, so none is claimed.

**Scope boundary — this is author-stage proof only.** No real backup or restore is
performed here. A controlled real encrypted production backup and a restore into
separately created disposable D1/R2 staging — proving full set/hash equality,
RPO/RTO, freshness consumption and zero production mutation — is **Integration /
founder territory** and is NOT claimed by this document. Guard-and-protocol
evidence is not broad F-004 closure.

## Backup procedure (D1)

```bash
cd workers/scan-api
# Point-in-time export of the whole database to a single SQL file.
# NOTE: the export briefly makes D1 unavailable to serve queries while the
# snapshot is created — run it during low traffic (or accept the brief pause).
npx wrangler d1 export cybermeters-db --remote \
  --output=backups/cybermeters-$(date +%Y%m%d-%H%M).sql
```

* Store the `.sql` off Cloudflare (encrypted bucket / password manager vault).
* Cadence: **daily** automated (see follow-up) + **on-demand before every
  migration or medium/high-risk deploy** (this is the cheap insurance).
* R2 (reports bucket) is content-addressed and regenerable from D1 scan rows;
  the authoritative state to protect is **D1**. Report objects that matter for
  audit are also referenced by `workspace_reports.report_key`.
* **Cloudflare R2 has no object versioning.** There is no per-object "previous
  version" to roll back to, so recovery of the reports bucket is a **separately
  copied object set plus a manifest** (source key + destination identity + `size` +
  `sha256`), captured alongside the D1 export, **persisted encrypted and hash-bound**
  to the destination, and verified against the source before the copy and against the
  **complete final destination** after every write. A restored D1 plus that copied
  object set reconstructs the full picture, and the restore drill consumes exactly
  that manifest — it cannot materialise anything without it.

## Restore procedure

**Option A — new D1 database (safe, non-destructive; preferred for drills and
for recovering to a parallel instance):**

```bash
# 1. Create a fresh, DISPOSABLE staging db — its name must carry a drill marker
#    (drill-* / restore-scratch-*) and must NOT be a cybermeters-* production name.
#    The restore script rejects every production name/ID/bucket.
npx wrangler d1 create drill-restore-$(date +%Y%m%d-%H%M)
# 2. Replay the backup into it (never D1 Time Travel; never the production binding).
npx wrangler d1 execute drill-restore-YYYYMMDD-HHMM --remote \
  --file=backups/cybermeters-YYYYMMDD-HHMM.sql
# 3. Re-materialise the R2 object set from the copied manifest into a disposable
#    staging bucket (R2 has no object versioning), then verify the set + hashes.
# 4. Point a staging worker at it (wrangler.toml database_id) and smoke test
#    /health + a login before promoting.
```

**Option B — in place (DESTRUCTIVE — real disaster only, with approval):**
restore into the existing binding only after confirming the current data is
already lost/corrupt. Never run against a healthy production DB.

**Local verification (what this drill ran):**

```bash
sqlite3 restored.db < cybermeters-backup.sql       # replay
sqlite3 restored.db "PRAGMA integrity_check;"       # -> ok
sqlite3 restored.db "PRAGMA foreign_key_check;"     # -> (empty)
sqlite3 restored.db "SELECT COUNT(*) FROM sqlite_master WHERE type='table';"
```

## Drill evidence (2026-07-11)

* Export: 2.7 MB SQL, whole prod DB.
* Restore into a fresh SQLite DB: **1.57 s**, **59 tables**.
* `PRAGMA integrity_check` → **ok**. `PRAGMA foreign_key_check` → **no violations**.
* Data fidelity spot-check (real rows present after restore):
  * `users` row `usr_5f099621…` → `ttrnn47@gmail.com` ✓
  * `workspaces` row `workspace_01334c51…` → `Trn Acr's Workspace` ✓
* Restored row counts (sane, non-empty): users 8 · workspaces 7 ·
  workspace_members 7 · scans 65 · workspace_domains 23 · subscriptions 6 ·
  audit_events 511 · user_sessions 21 · stripe_processed_events 0 (new table,
  no webhooks processed yet — expected).

## Follow-ups (tracked)

* [ ] **Automate daily D1 export** to an encrypted off-Cloudflare store (cron
      worker or scheduled CI job) with 30-day retention. *(Turhan: pick the
      store + provide credentials; Claude: wire the job.)*
* [ ] Automate the **R2 manifest copy** (`key`+`size`+`sha256` set copied to the
      same encrypted store) — R2 has no object versioning, so the copied set plus
      manifest *is* the recovery point. *(Claude: wire; Turhan: store credentials.)*
* [ ] Add a **quarterly restore-drill reminder** and record each run's RTO here.
* [ ] Wire an **on-demand backup step into the release checklist** before any
      migration deploy.
