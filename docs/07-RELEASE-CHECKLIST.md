# CyberMeters Release Checklist v2.0 — Operational Runbook

> The executable gate for every worker release. v1.0 was a values checklist; this
> is the step-by-step runbook, matched to the real manual-deploy model (Workers
> Builds is disconnected — pushing to `main` does **not** deploy the worker;
> deploy is a deliberate act). Frontend (Pages) auto-deploys on push to `main`.
> Cross-links: [MONITORING](MONITORING.md) · [INCIDENT-RESPONSE-PLAN](INCIDENT-RESPONSE-PLAN.md) · [BACKUP-RESTORE-DRILL](BACKUP-RESTORE-DRILL.md).

## Release flow (canonical)

```
feature branch → PR → CI green (validate + sast) → merge main
   → [if DB change] apply migration to remote D1 → verify
   → wrangler deploy → RECORD Version ID → smoke test → tag vYYYY.MM.DD-n → CHANGELOG
   → confirm CI green on main
```

## Risk gate — who may deploy

Authority comes only from `docs/AI-EXECUTIVE-OPERATING-MODEL.md`.

| Tier | Examples | Required path |
|---|---|---|
| **R0** | frontend UI/copy, error handling, non-destructive response shaping, tests/tooling/docs | Owner proof + CI + integration smoke → Executive may merge/deploy |
| **R1** | auth/tenant/billing changed path, additive migration, scoring truth, scheduled/cron, retention code, release controls | Dangerous-path proof + one non-author targeted review + CI + rollback → Executive may merge/deploy |
| **R2** | destructive data action, foundational auth/session/RBAC/billing/tenant redesign, irreversible production change | Governance scopes; Founder decides the exact reserved consequence |

Classify actual consequence, not the filename. Do not ask the Founder for a
routine reversible R0/R1 deploy.

---

## 1. Pre-flight (before touching the deploy)

- [ ] Change is on a branch / PR; **CI green** (`validate` + `sast`) on the PR or main.
- [ ] Reviewed the diff (`git diff --check` clean; no stray debug/secrets).
- [ ] Risk tier identified; required R0/R1 proof or R2 decision obtained.

## 2. Local validation gate (must all pass)

```bash
# Worker
node --check workers/scan-api/src/index.js
for s in regression-fixtures security-contracts integration tenant-isolation \
         pipeline email-worker log-redaction purge-completeness migrations \
         error-contract ops-health openapi; do
  node scripts/validate-$s.js || echo "❌ $s FAILED"
done
( cd workers/scan-api && npm audit --audit-level=high && npx wrangler deploy --dry-run )

# Frontend (if touched)
( cd frontend && npm run typecheck && npm test && npm run build )

git diff --check && git status --short
```

- [ ] Every harness passes; dry-run packages cleanly; frontend build/typecheck/tests green.

## 3. Database migration (only if the change adds one)

Migrations are at least **R1**. Additive-only is enforced by
`validate-migrations.js`; destructive consequence is R2. Apply to remote D1
**before** deploying the code that reads the new schema.

```bash
cd workers/scan-api
# Snapshot first (cheap insurance — see BACKUP-RESTORE-DRILL.md)
npx wrangler d1 export cybermeters-db --remote --output=../../backups/pre-$(git rev-parse --short HEAD).sql
# Apply
npx wrangler d1 execute cybermeters-db --remote --file=../../database/migrations/<NNN>-*.sql
# Verify the new object exists
npx wrangler d1 execute cybermeters-db --remote --command="SELECT name FROM sqlite_master WHERE name='<new_table>';"
```

- [ ] Snapshot taken · migration applied · new object verified present.

## 4. Deploy

```bash
cd workers/scan-api
# Bump APP_VERSION in wrangler.toml if the date rolled over
npx wrangler deploy
```

- [ ] **RECORD the printed `Current Version ID`** (rollback needs it): `________________`
- [ ] Note the **previous** Version ID for rollback (from CHANGELOG's last entry): `________________`

> The `cybermeters-email` Worker requires a separately recorded Executive deploy
> whenever `workers/email-ingest/deploy-manifest.json` changes:
> `npm run deploy --prefix workers/email-ingest`

## 5. Post-deploy smoke test (live)

```bash
BASE=https://api.cybermeters.com
curl -s $BASE/health        # version + deployment_id == what you just deployed
curl -s $BASE/ready         # {"status":"ready","checks":{"d1":true,"r2":true}}
curl -s -o /dev/null -w "%{http_code}\n" $BASE/api/workspaces   # 401 (auth enforced)
```

- [ ] `/health` shows the new deployment_id (poll ~30s for propagation).
- [ ] `/ready` is `ready` (d1 + r2 true).
- [ ] Anonymous protected endpoint returns 401 (auth still enforced).
- [ ] If frontend changed: load `app.cybermeters.com`, confirm it renders + a login works (CSP didn't break anything).

> **If `api.cybermeters.com` itself is the suspect** — DNS, the custom domain
> binding or the zone cert — the same Worker answers directly on
> `https://cybermeters-platform.ttrnn47.workers.dev`. A healthy workers.dev and an
> unhealthy `api.` isolates the fault to the hostname rather than the deployment.

## 6. Record the release

```bash
# CHANGELOG entry: version, what shipped, live Version ID, rollback (previous) ID
git commit -m "release(worker): vYYYY.MM.DD-n — <summary>"
git tag -a vYYYY.MM.DD-n -m "vYYYY.MM.DD-n — <summary>. Live <version-id>."
git push origin main && git push origin vYYYY.MM.DD-n
```

- [ ] CHANGELOG updated with live Version ID **and** rollback target.
- [ ] Release tagged `vYYYY.MM.DD-n` and pushed.
- [ ] CI green on the main push.

## 7. Rollback (if smoke test fails or an alert fires)

Fast path — no rebuild needed (full detail in [INCIDENT-RESPONSE-PLAN §4](INCIDENT-RESPONSE-PLAN.md)):

```bash
cd workers/scan-api
npx wrangler deployments list                    # confirm the last good Version ID
npx wrangler rollback --version-id <PREVIOUS_ID>  # or: wrangler versions deploy <ID>
curl -s https://api.cybermeters.com/health   # confirm reverted on the host customers hit
```

- If the release included a migration, additive migrations are safe to leave in
  place on rollback (older code ignores the new column/table). **Never** pair a
  rollback with a destructive down-migration without a fresh snapshot and the
  R2 decision required by the operating constitution.
- Secret/key rotation, DB break-glass, and per-incident playbooks all live in
  [INCIDENT-RESPONSE-PLAN.md](INCIDENT-RESPONSE-PLAN.md) — don't duplicate here.

---

## Maintenance mode (planned windows)

For a risky migration or a window where the API must be quiet, put the platform
into maintenance instead of letting customers hit half-broken behaviour.

**Enable:**
```bash
# set MAINTENANCE_MODE = "on" in workers/scan-api/wrangler.toml [vars], then:
cd workers/scan-api && npx wrangler deploy
```
Every API route now returns a clean `503 { code: "maintenance", message }` with
`Retry-After: 300`. `/health` and `/ready` stay up (monitoring keeps working);
`/health` reports `maintenance: true`. The frontend shows a full-screen
"back shortly" overlay that auto-refreshes when the window lifts.

**Verify the deploy while still in maintenance (bypass):**
```bash
# one-time: wrangler secret put MAINTENANCE_BYPASS_TOKEN
curl -H "X-Maintenance-Bypass: <token>" https://<api-host>/api/workspaces   # 401, not 503
```

**Lift:** set `MAINTENANCE_MODE = "off"` and `wrangler deploy` again. Confirm
`curl https://<api-host>/health` shows `"maintenance": false`.

Fail-safe: an unset/garbled `MAINTENANCE_MODE` reads as OFF. Guarded by
`scripts/validate-maintenance-mode.js` (29 assertions).

---

# Final Rule

Never deploy code you would not confidently demonstrate to a paying customer —
and never deploy without a recorded Version ID you can roll back to.
