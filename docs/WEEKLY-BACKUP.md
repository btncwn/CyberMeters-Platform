# Weekly off-site recovery copy

D1 Time Travel is the point-in-time layer: the free plan retains seven days.
The C-2 manual recovery copy additionally proved a remote scratch restore of
122 application tables and 157 R2 objects on 21 October 2026. A manual copy is
not a recurring backup.

`weekly-backup.yml` adds a Sunday 03:43 UTC export. It captures D1 SQL and a
stable R2 inventory (object keys, sizes, ETags, metadata returned by listing and
the observed object-response headers), compresses and encrypts the
package with AES-256-GCM, and uploads only ciphertext to this private repository's
workflow artifacts. This is outside the Cloudflare account and provider. The
same job downloads the artifact, checks the local ciphertext digest, decrypts it,
checks captured SQL integrity and foreign keys, and only then appends and reads
back `weekly_backup_completed`. No production restore, DNS or schema write occurs.

The R2 inventory is **not an off-site copy of object bytes**, and an ETag is not
claimed to be a content SHA-256. Recovering report bytes still needs the source
R2 bucket or a separate full recovery copy such as C-2. D1/R2 capture is sequential,
not one atomic snapshot. The weekly export has a seven-day recovery-point target;
Time Travel covers the intervening D1 points while available. A disappearing
Cloudflare account can lose more recent R2 objects despite an intact inventory.
Observed HTTP/custom metadata is retained inside the encrypted manifest now;
mapping those fields back onto restored R2 objects is a follow-up. Metadata not
exposed by the API cannot be claimed captured. Object-response bodies are
cancelled after the headers are captured, rather than stored in this export.

The weekly signal becomes stale after eight days (one day of schedule grace).
With `WEEKLY_BACKUP_MONITORING=on`, `/ready` measures this specific off-site event,
returns its real `backup_last_success_at` and `backup_cadence: weekly`, and requires
it even while the older independent-monitor exemption is off. A manual copy
cannot reset it. Missing, failed, unreadable or future-dated proof is stale.
The existing hourly external dead-man sees the stale verdict. The existing daily
operator health email also names the stale backup, independently of customer
notifications. Its current configured recipient is `ttrnn47@gmail.com`; delivery
errors remain in the existing operational-event path. No synthetic alert email
is sent during local tests, and inbox receipt is not claimed from a unit test.

## Founder setup needed before activation

No durable backup token or encryption key exists in repository secrets today.
The workflow is deliberately gated by `WEEKLY_BACKUP_ENABLED=true`. Do not deploy
the weekly monitoring setting until a real off-site run has succeeded.

1. In the Cloudflare dashboard, open **Profile → API Tokens → Create Token →
   Create Custom Token**. Give the backup job **Account / D1 / Edit** (export and
   the success-event insert/readback) and **Account / Workers R2 Storage / Read**
   for only the CyberMeters account. Do not grant DNS, Worker deployment, account
   management or R2 write permissions. Account-level D1 Edit can write production
   data; this is a sensitive operator credential. Keep it out of chats and logs.
2. In this repository, **Settings → Secrets and variables → Actions → Secrets →
   New repository secret**, add it as `CLOUDFLARE_BACKUP_TOKEN`. Add a separate
   random 32-byte encryption key, encoded as base64, as `CM_WEEKLY_BACKUP_KEY`.
   Keep a separately protected recovery copy of the key outside the repository
   and its Actions secrets. Losing the key loses the export; anyone with the key
   and artifact can read the database. Do not publish the key in a comment.
3. Confirm unused **included** Actions minutes and artifact storage before
   enabling. This job uses a standard runner, at most ten minutes per weekly
   attempt, no caches, and at most 10 MiB per artifact for 21 days (normally three
   weekly copies; allow four at a retention boundary). GitHub Free includes
   2,000 minutes/month and 500 MB artifact storage, shared with other workloads.
   The repository's existing CI may consume that allocation. These bounds do
   **not** prove spare account quota or make overage free. If no included quota
   remains, leave disabled and choose a genuinely free execution location; do not
   buy a plan or raise a spending limit for this job.
4. **Settings → Secrets and variables → Actions → Variables → New repository
   variable**: `WEEKLY_BACKUP_ENABLED` = `true`. Then **Actions → weekly-backup →
   Run workflow → main → Run workflow** once for the operational proof. Check all
   capture/upload/download/record steps and retain the run/artifact ID. A skipped
   job, successful export without durable upload, or green unrelated CI is not
   backup success.
5. The source can be deployed with the weekly switch absent; existing readiness
   behavior remains in place. Check the PR release comment for the actual
   deployed Version. After the successful job, in **Cloudflare →
   Compute → Workers & Pages → cybermeters-platform → Settings → Variables and
   Secrets → Add**, add a **Secret** named `WEEKLY_BACKUP_MONITORING` with value
   `on` and deploy that configuration. It is an activation switch, not a
   credential; keeping it out of wrangler.toml prevents another seat's routine
   deployment from enabling an unconfigured backup monitor. Verify `/ready` reports weekly cadence and the
   actual successful job's time, then record Version/rollback IDs in the PR.
   Until this point, the new weekly monitor is not claimed live.

This setup changes credentials/settings and therefore remains a founder action.
No account setting, secret, paid plan, spending limit or workflow dispatch was
changed automatically for this implementation.

## Recover a retained export

Download the encrypted artifact from the successful workflow run into a private
local directory. Keep plaintext off shared disks and logs. With the protected
key, use the same `open`/gzip format as `scripts/ops/weekly-backup.mjs` to decode
the JSON package in memory. `sql` is the D1 export; `objects` is the R2 inventory.
Restore SQL only into a newly created scratch database, verify schema, every row
and foreign keys against the captured SQL, then compare the inventory against
available R2 objects. The C-2 runbook documents the full scratch restore method.
Never restore over production as a routine verification step. This weekly
off-site workflow has synthetic encryption/readback/SQL-integrity tests; its first
real upload/download and scratch restore remain activation evidence to collect.

Rollback: disable the repository variable, revert the source and redeploy the
previous scan-api Version if the weekly monitor has been deployed. Do not erase
existing backup artifacts or recovery evidence. Artifacts expire automatically
after 21 days; this is a short rolling recovery window, not long-term retention.

References: [D1 limits](https://developers.cloudflare.com/d1/platform/limits/),
[Actions included usage](https://docs.github.com/en/billing/concepts/product-billing/github-actions),
[artifact retention](https://docs.github.com/en/actions/tutorials/store-and-share-data).
