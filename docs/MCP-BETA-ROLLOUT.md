# CyberMeters MCP rollout

**State (21 October 2026):** customer MCP is **live in production** and open to trial and paid customers since #720. The gateway `cybermeters-mcp-server` serves `https://mcp.cybermeters.com/mcp` (`MCP_CUSTOMER_ENABLED = "true"`); the API `cybermeters-platform` is the OAuth issuer at `https://api.cybermeters.com` with `MCP_CUSTOMER_OAUTH_ENABLED`, `MCP_CUSTOMER_READ_ENABLED`, `MCP_OAUTH_DCR_ENABLED` and `MCP_OAUTH_DCR_LOOPBACK_ENABLED` all `"true"`, CIMD off, and `MCP_CUSTOMER_ACCESS = "customers"`. All of these live in the two checked-in `wrangler.toml` files, so a plain deploy keeps the live state. Proven clients: Claude.ai hosted connector, Claude Code and Codex CLI ([compatibility](MCP-CLIENT-COMPATIBILITY.md)). ChatGPT web and Gemini CLI still need production read/revoke/reconnect proof; protocol checks alone do not establish client acceptance. Customer connections are read-only and use OAuth; revoke them at [Account → MCP connections](https://app.cybermeters.com/account/mcp) with **Remove access**.

## Who may connect, checked on every read

- **Plan:** a current Trial, Starter, Professional, Business or MSP entitlement (`trial`, `paid` or `grace` plan state). The MSP tier uses the platform's `enterprise` entitlement key. An expired trial or a lapsed plan stops the next read.
- **Identity and membership:** an active, email-verified user with a live `workspace_members` row (viewer, analyst, admin or owner) in a workspace that is not deleted or being deleted; no pending account deletion.
- **Connection:** an active `mcp_oauth_connections` row bound to the same user, client and resource, with the granted scopes. D1 is the revocation fence on every token validation; KV grant removal follows.
- **Workspace switch:** `mcp_beta_workspace_access` is now a per-workspace off switch. No row or `enabled` is open; `paused` closes that workspace. (Before 20 Oct 2026 an `enabled` row was required and only the founder could connect.)
- **Portfolio read:** Business or MSP, with workspaces chosen explicitly at consent; losing the entitlement revokes the portfolio connection.
- **Rate limits:** 10 reads/minute per connection on trial, 30 on paid or grace; OAuth emergency ceilings `2/min` per IP and `8/min` global for authorize and token, `2/hour` per IP and `12/hour` global for DCR; edge limits on the gateway.
- **Audit:** every read and denial writes a durable audit event; an audit-store failure denies the read.

## Production record

- **19 Oct 2026, 18:48:** Claude Code (loopback DCR) read live TLS posture after #669.
- **19 Oct 2026:** #701 put the live MCP flags in config so a plain deploy keeps them.
- **20 Oct 2026:** #715 applied RFC 7591 defaults and a PII-free `mcp_dcr_rejected` log line per refusal. Its first production line showed the Claude hosted connector registering with `client_secret_post`; #718 allowed that method for allow-listed hosted callbacks only. **02:17:** the Claude hosted connector connected and returned real data.
- **20 Oct 2026:** the founder fence was lifted by #720 (`MCP_CUSTOMER_ACCESS = "customers"`).

## Immediate rollback

- **Back to founder only:** set `MCP_CUSTOMER_ACCESS` to anything but `"customers"` in `workers/scan-api/wrangler.toml` and deploy the API. Existing customer tokens stop at their next validation; the founder's keep working.
- **One workspace:** insert or update its `mcp_beta_workspace_access` row to `paused`.
- **All customer reads:** set `MCP_CUSTOMER_READ_ENABLED = "false"` on the API, or `MCP_CUSTOMER_ENABLED = "false"` on the gateway; the rest of CyberMeters keeps serving.
- **Affected connections:** revoke the connection rows; D1 revocation is immediate, KV grant cleanup follows through the hourly queue. Preserve audit and connection records per the retention policy; never drop the migrations as a rollback shortcut.

## Still open

- **Revoking from the app:** done (21 Oct 2026). `/account/mcp` no longer reads `VITE_MCP_BETA_ENABLED`; it always lists the caller's connections from `GET /mcp/oauth/connections` and offers Remove access, with the Connect guidance shown only when the API reports the account eligible. `version.json`'s `mcp_beta_enabled` still records the Pages variable for the canary rollback receipt and gates nothing.
- **ChatGPT web:** #794 added the exact official `https://chatgpt.com/connector_platform_oauth_redirect` callback. Production DCR returned 201 for that URI and 400 for a trailing-slash variant on 21 Oct, without a grant or consent. The founder must still prove a real client read, revoke via `/account/mcp`, fresh-call refusal, and reconnect/read. Do not advertise live client acceptance yet.
- **Gemini CLI:** production client read/revoke/reconnect is pending; see the compatibility page for account and region limits.
- **Customer notice:** keep the third-party AI data-handling text in the Privacy Policy/DPA aligned with the live state.
- **Operations:** a bounded load check and an observed D1 `rows_read`/`rows_written` profile under customer traffic before raising any limit.

## History: isolated staging (October 2026)

The staging record and setup procedure below are the evidence that preceded production. Staging still uses synthetic identities and requires `enabled` rows.

### Staging deployment record (2026-10-15)

- `cybermeters-platform-staging` serves `api-staging.cybermeters.com` with `MAINTENANCE_MODE=on` and all customer MCP flags false. `/health` returned `200` with `maintenance=true`; public signup and free scan returned `503`.
- `cybermeters-mcp-server-staging` serves `mcp-staging.cybermeters.com/mcp` with `MCP_CUSTOMER_ENABLED=false`. The live route returned `503 mcp_not_configured`.
- The staging API uses only `cybermeters-db-staging`, `cybermeters-mcp-oauth-staging`, and `cybermeters-reports-staging`. Its D1 was bootstrapped through migration 121 and then received migrations 122 and 123 for audit and MCP rate-counter retention. Readback confirmed both indexes, both synthetic workspace-access rows `paused`, zero active OAuth connections and sessions, and `PRAGMA quick_check=ok`. It has two **synthetic** users in separate workspaces and no real customer content. The staging gateway has no direct D1/KV/R2 binding.
- A locally built frontend with the staging API URL and a staging-only CSP is deployed to the separate Direct Upload Pages project `cybermeters-dashboard-staging`. The proxied `app-staging.cybermeters.com` CNAME points to that project. Cloudflare Pages now reports both DNS verification and HTTP validation `active`; the custom-domain `/mcp/connect` route returned `200` with CSP `connect-src` pointed at `api-staging.cybermeters.com`.
- A short synthetic hosted test enabled only the two `example.invalid` workspaces while the staging API stayed in maintenance mode. `scripts/mcp-hosted-staging-probe.js` passed live DCR, PKCE consent, discovery of twelve read-only tools, each tenant's own read, cross-tenant `403`, grant revocation followed by `401`, and session logout. The local test process temporarily pinned only `app-staging.cybermeters.com` to a publicly resolved Cloudflare IP because macOS system lookup still returned `ENOTFOUND` after authoritative DNS was live; TLS hostname validation remained active. Recheck normal client DNS before advertising the custom domain. The test client registration expires from KV after its configured TTL; the granted connections and sessions were revoked. This is protocol and isolation evidence, not a Claude.ai, ChatGPT, Gemini, or real-customer content pass.
- After the hosted proof, the staging gateway was redeployed with `MCP_CUSTOMER_ENABLED=false`, the staging API with OAuth/read/DCR/test-login flags false and `MAINTENANCE_MODE=on`, and both synthetic workspace-access rows were paused. Live health showed the disabled API version, the OAuth metadata route returned `503`, and `/mcp` again returned `503 mcp_not_configured`.
- The first repeat after the OAuth guard and migration 123 changes reached consent, token issue and tool discovery, but its first `cybermeters_list_workspaces` call failed. A subsequent guarded repeat with the same code **passed** the two-tenant read, denial, revocation and logout sequence; the gateway tail recorded successful tool calls. The isolated test was restored to disabled state after each run. Treat the first read failure as an unresolved transient until a later repeat and a bounded load check confirm reliability.
- Two later guarded repetitions again passed the CyberMeters two-tenant proof. Their optional Gemini Interactions probe returned Google HTTP `400` before any MCP call reached the gateway. A request-shape mismatch in the local helper was corrected against Google's published `allowed_tools` example; offline tests pass, but a new live Gemini probe is required before claiming Gemini API compatibility.
- After the OAuth saturation change (global starts `2/min`, token exchanges `2/min`, DCR `1/hour`) and the gateway compatibility flag, another short synthetic hosted run issued two OAuth grants but failed at the first `tools/list` response. The guarded cleanup revoked both grants and logged out both accounts. The two workspace-access rows were paused, both staging Workers were redeployed disabled, `/mcp` and OAuth metadata returned `503`, and D1 readback showed zero enabled rows, active connections, or sessions. Audit rows showed the two expected post-revocation `invalid_bearer` denials and no read audit. **This historical run failed; the later strict reliability check below passed before production customer access opened.**
- A later guarded run reused an existing, exact synthetic public DCR client and passed PKCE consent, twelve-tool discovery, two isolated workspace lists and summaries, cross-tenant `403`, revocation `401`, and logout. Durable read, denial, grant, and revocation audit events were confirmed. The two workspace-access rows were paused, both staging Workers were redeployed disabled, `/mcp` and OAuth metadata returned `503`, and D1 readback showed zero enabled rows, active connections, or sessions. **This single pass did not explain the intermittent discovery/read failure; the subsequent bounded reliability check is recorded below.**
- A subsequent strict reliability check ran in three separate minute windows, each with two new synthetic PKCE grants and five sequential `tools/list` plus own-workspace reads per grant. All three runs passed, for six fresh grants and 30 durable workspace-read audit events; six revocations were recorded. The safe gateway tail showed successful 2xx calls and expected 4xx cross-tenant/revoked denials. The test fails at the first unsuccessful read without retrying into a pass. Both staging Workers are again disabled, both workspace-access rows are paused, `/mcp` and OAuth metadata return `503`, and D1 shows zero enabled rows, active connections, or sessions. The earlier intermittent failure did not recur; its root cause remains unknown, so customer monitoring and rollback remain required.
- The optional live Gemini retry was blocked by the automatic approval review because it would send a CyberMeters staging OAuth access token to Google's API without specific user authorization for that token transfer. No Google call occurred in that run. Do not route the token indirectly to Google; obtain explicit authorization for that exact integration test before repeating it.
- Post-test staging D1 readback found durable MCP read and denial audit rows, zero enabled workspace-access rows, zero active OAuth connections, and zero sessions. Test grants were revoked. Repeat these state checks after every hosted run rather than relying on historical counts.
- No production Worker, production D1/KV/R2 binding, existing production DNS record, or customer workspace was changed by this staging setup. This historical staging record is not the current production state; customer production access subsequently opened in #720.

### Staging configuration preparation

Put the actual dedicated staging D1 UUID, OAuth KV namespace ID, and two distinct staging rate namespace IDs in an ignored `local/mcp-staging-resources.json` file. Run `node scripts/generate-mcp-staging-config.js local/mcp-staging-resources.json`, then review the two generated `workers/{scan-api,mcp-server}/.wrangler/mcp-staging/wrangler.jsonc` files and run `node scripts/validate-mcp-staging-config.js`. Dry-run both generated configurations and check their effective bindings. The generator never deploys, enables customer flags, or accepts the production D1/rate IDs.

Provision the dedicated `cybermeters-reports-staging` R2 bucket and staging hostnames separately. Prepare the staging frontend and identity login; Microsoft SSO also needs the exact staging redirect registered in Entra. Verify the resource identities in Cloudflare before any hosted test: static IDs and local dry-runs cannot prove account ownership or actual resource isolation. The staging API intentionally has no Queue or cron binding. Its scan dispatch is fail-closed, and the test validator proves a scan request cannot execute without the Queue.

### Staging frontend artifact

Build the Vite app locally with the staging API URL, then prepare the ignored Pages output before reviewing or uploading it:

```sh
VITE_API_BASE_URL=https://api-staging.cybermeters.com/api \
  VITE_MCP_BETA_ENABLED=true npm --prefix frontend run build
node scripts/prepare-mcp-staging-frontend.js
```

The preparation command requires `frontend/dist/_headers` to be an exact copy of tracked `frontend/public/_headers` and the built entry bundle to contain the exact staging API URL. It replaces only the production API origin in the output CSP `connect-src`; any mismatch fails without changing a file. It does not edit tracked production headers, upload to Pages, change DNS, or enable MCP. Rebuild before running it again. Inspect `frontend/dist/_headers` and the entry bundle before a deliberate staging-only Pages upload. The staging app needs `ALLOWED_ORIGIN=https://app-staging.cybermeters.com` and `FRONTEND_URL=https://app-staging.cybermeters.com` on the staging API; a production Pages preview build compiled with the production API URL is unsuitable for hosted OAuth tests.

### Empty staging D1 bootstrap

The platform's `schema.sql` is a historical baseline. The effective schema is that baseline plus the migration chain; applying the raw files wholesale to a fresh D1 fails at known, exact historical overlaps. The generator uses the existing migration validator and its statement-level tolerance list to build one **empty final-schema** SQL file. It copies no production data and writes only to ignored `local/`:

```sh
node scripts/generate-mcp-staging-schema.js
```

Before any remote import, inspect the generated API Wrangler config and confirm its D1 UUID matches the dedicated `cybermeters-db-staging` database in Cloudflare. The read-only inventory of the newly created remote D1 returned exactly one non-`sqlite_%` object: Cloudflare's internal table `_cf_KV`; it contained no application tables. Repeat the query below immediately before import. Proceed only if its sole row is `type=table, name=_cf_KV`; stop on an application table or any other unexpected object. From the repository root, use the project-pinned Wrangler and the generated staging config; `--remote` is intentional and must never be changed to a production database name or config:

```sh
workers/scan-api/node_modules/.bin/wrangler d1 execute cybermeters-db-staging --remote \
  --config workers/scan-api/.wrangler/mcp-staging/wrangler.jsonc \
  --command "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name"
workers/scan-api/node_modules/.bin/wrangler d1 execute cybermeters-db-staging --remote \
  --config workers/scan-api/.wrangler/mcp-staging/wrangler.jsonc \
  --file local/mcp-staging-schema.sql
```

After import, read back `users`, `workspaces`, and `mcp_beta_workspace_access` counts (all must be zero), confirm `mcp_oauth_connections` exists, and run `PRAGMA quick_check` and `PRAGMA foreign_key_check`. Stop on any import or integrity error. Keep the generated SQL private in `local/`; it is an installation artifact for a **new empty staging D1**, not a routine migration or a production rollback method. See [Cloudflare's D1 execute command](https://developers.cloudflare.com/d1/wrangler-commands/#d1-execute) for `--file`, `--local`, and `--remote` behavior.

### Synthetic two-workspace fixture

After the complete schema is installed and the staging D1's `users`, `workspaces`, and `mcp_beta_workspace_access` tables are confirmed empty, generate and validate two synthetic test identities locally:

```sh
node scripts/generate-mcp-staging-fixture.js --generate-local-test-credentials
node scripts/mcp-staging-fixture-local-check.js
node scripts/mcp-staging-fixture-import-local-check.js
node scripts/import-mcp-staging-fixture.js
```

The generator refuses to replace existing artifacts. It writes the SQL and separate generated test credentials into ignored `local/` files with mode `0600`, without printing the passwords. The SQL inserts only two `example.invalid` users, two workspaces, their memberships, and **paused** workspace-access rows; it creates no scans, domains, or login sessions. The guarded importer checks the dedicated staging UUID and name in the manifest, generated Worker config, and live Cloudflare inventory; verifies the exact generated SQL against the private test credentials; compares the remote schema with the locally generated schema; and refuses unless every application table is empty and integrity checks pass. It uses the fixed staging name and config for the one remote import, then reads back exactly two users, two workspaces, two memberships, two paused workspace-access rows, zero enabled rows, zero domains, and zero sessions. It refuses on a populated staging database, including the currently seeded one. Never run a manual Wrangler import of the fixture or use a production config. Keep workspace-access rows paused until the hosted gateway, app origin, audit, and tenant checks are ready.
