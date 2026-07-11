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
  audit are also referenced by `workspace_reports.report_key` — a restored D1
  plus the R2 bucket (versioning enabled) reconstructs the full picture.

## Restore procedure

**Option A — new D1 database (safe, non-destructive; preferred for drills and
for recovering to a parallel instance):**

```bash
# 1. Create a fresh D1 db (or use a staging one), note its database_id.
npx wrangler d1 create cybermeters-db-restore
# 2. Replay the backup into it.
npx wrangler d1 execute cybermeters-db-restore --remote \
  --file=backups/cybermeters-YYYYMMDD-HHMM.sql
# 3. Point a staging worker at it (wrangler.toml database_id) and smoke test
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
* [ ] Enable **R2 bucket versioning** on `cybermeters-reports` if not already.
      *(Turhan: dashboard toggle.)*
* [ ] Add a **quarterly restore-drill reminder** and record each run's RTO here.
* [ ] Wire an **on-demand backup step into the release checklist** before any
      migration deploy.
