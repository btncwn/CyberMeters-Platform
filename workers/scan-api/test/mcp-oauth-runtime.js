#!/usr/bin/env node
// Disposable local workerd proof for real OAuth code, refresh and revocation.
// It creates only local D1/KV fixtures and never deploys a Worker.
import assert from "node:assert/strict";
import { createHash, randomInt } from "node:crypto";
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const exec = promisify(execFile);
const scanApi = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repo = resolve(scanApi, "../..");
const wrangler = join(scanApi, "node_modules/.bin/wrangler");
const tokenHash = (token) => createHash("sha256").update(token).digest("hex");
const pkce = (verifier) => createHash("sha256").update(verifier).digest("base64url");

async function main() {
  const temp = await mkdtemp(join(tmpdir(), "cybermeters-oauth-workerd-"));
  const port = randomInt(20_000, 45_000);
  const origin = `http://127.0.0.1:${port}`;
  const resource = "https://mcp-staging.cybermeters.com/mcp";
  const callback = `http://127.0.0.1:${port + 1}/callback`;
  const reviewedCimd = "https://reviewed-client.example/oauth/client.json";
  const unreviewedCimd = "https://unreviewed-client.example/oauth/client.json";
  const configPath = join(temp, "worker.json");
  const fixturePath = join(temp, "fixture.js");
  const seedPath = join(temp, "seed.sql");
  const state = join(temp, "state");
  const commandEnv = {
    ...process.env, WRANGLER_SEND_METRICS: "false",
    WRANGLER_LOG_PATH: join(temp, "wrangler.log"),
  };
  let worker;
  try {
    const route = join(scanApi, "src/routes/mcp-oauth-server.js");
    const browserRoute = join(scanApi, "src/routes/mcp-oauth-browser.js");
    const customerReadModule = join(scanApi, "src/routes/mcp-customer-service.js");
    await writeFile(fixturePath, `import { handleMcpOAuthRequest, validateMcpOAuthToken } from ${JSON.stringify(route)};
import { readBoundedMcpOAuthBody } from ${JSON.stringify(browserRoute)};
import { callMcpCustomerRead } from ${JSON.stringify(customerReadModule)};
const reviewedCimd = ${JSON.stringify(reviewedCimd)};
const outboundUrls = [];
globalThis.fetch = async (input) => {
  const url = input instanceof Request ? input.url : String(input);
  outboundUrls.push(url);
  if (url === reviewedCimd) return Response.json({ client_id: reviewedCimd,
    client_name: "Reviewed local CIMD fixture", redirect_uris: [${JSON.stringify(callback)}],
    grant_types: ["authorization_code"], response_types: ["code"],
    token_endpoint_auth_method: "none" });
  return new Response("outbound blocked by local fixture", { status: 502 });
};
const opts = (env) => ({ issuer: env.TEST_ISSUER, resource: env.TEST_RESOURCE,
  appOrigin: env.TEST_APP_ORIGIN, testClientIp: "127.0.0.1" });
export default { async fetch(request, env, ctx) {
  if (new URL(request.url).pathname === "/__outbound_urls") {
    return Response.json(outboundUrls);
  }
  if (new URL(request.url).pathname === "/__reset_mcp_rate") {
    await env.cybermeters_db.prepare("DELETE FROM api_rate_limits WHERE action GLOB 'mcp_*'").run();
    return new Response(null, { status: 204 });
  }
  if (new URL(request.url).pathname === "/__stalled_body") {
    const stalled = new Request("https://example.test", { method: "POST", duplex: "half",
      body: new ReadableStream({ start(controller) {
        controller.enqueue(new TextEncoder().encode("partial="));
      } }),
    });
    return Response.json({ rejected: await readBoundedMcpOAuthBody(stalled, 4096, 25) === null });
  }
  if (new URL(request.url).pathname === "/__read") {
    const bearer = request.headers.get("Authorization")?.replace(/^Bearer /, "") ?? "";
    try {
      const result = await callMcpCustomerRead(env, "listWorkspaces", { bearer }, {
        validateToken: (e, r, t) => validateMcpOAuthToken(e, r, t, opts(e)),
      });
      return Response.json(result);
    } catch { return Response.json({ error: "denied" }, { status: 403 }); }
  }
  if (new URL(request.url).pathname === "/__validate") {
    const bearer = request.headers.get("Authorization")?.replace(/^Bearer /, "") ?? "";
    const value = await validateMcpOAuthToken(env, env.TEST_RESOURCE, bearer, opts(env));
    return Response.json({ ok: !!value, workspace: value?.props?.workspaceId ?? null,
      user: value?.userId ?? null });
  }
  return await handleMcpOAuthRequest(request, env, ctx, opts(env)) ?? new Response("Not found", { status: 404 });
} };\n`);
    await writeFile(configPath, JSON.stringify({
      name: "cybermeters-mcp-oauth-local", main: fixturePath,
      compatibility_date: "2026-06-18",
      compatibility_flags: ["global_fetch_strictly_public"],
      workers_dev: false,
      d1_databases: [{ binding: "cybermeters_db", database_name: "mcp-oauth-disposable-local",
        database_id: "00000000-0000-4000-8000-000000000121" }],
      kv_namespaces: [{ binding: "OAUTH_KV", id: "00000000000000000000000000000121" }],
      vars: { MCP_CUSTOMER_OAUTH_ENABLED: "true", MCP_CUSTOMER_READ_ENABLED: "true",
        MCP_DEPLOYMENT_TIER: "staging", MCP_OAUTH_DCR_ENABLED: "true",
        MCP_OAUTH_CIMD_ALLOWED_CLIENT_IDS: JSON.stringify([reviewedCimd]),
        TEST_ISSUER: origin, TEST_RESOURCE: resource, TEST_APP_ORIGIN: origin },
    }));
    const migration = await readFile(join(repo, "database/migrations/121-mcp-oauth.sql"), "utf8");
    const rate = await readFile(join(repo, "database/migrations/026-api-rate-limits.sql"), "utf8");
    const auditRetentionIndex = await readFile(join(repo,
      "database/migrations/122-audit-retention-index.sql"), "utf8");
    const mcpRateRetentionIndex = await readFile(join(repo,
      "database/migrations/123-mcp-rate-retention-index.sql"), "utf8");
    const selectedWorkspacesMigration = await readFile(join(repo,
      "database/migrations/124-mcp-oauth-selected-workspaces.sql"), "utf8");
    const sessionA = "a".repeat(64);
    const sessionB = "b".repeat(64);
    await writeFile(seedPath, `
      CREATE TABLE users(id TEXT PRIMARY KEY, status TEXT, email_verified INTEGER);
      CREATE TABLE workspaces(id TEXT PRIMARY KEY, name TEXT, deleted_at TEXT, owner_user_id TEXT);
      CREATE TABLE workspace_members(id TEXT PRIMARY KEY, workspace_id TEXT, user_id TEXT, role TEXT);
      CREATE TABLE user_sessions(id TEXT PRIMARY KEY, user_id TEXT, token_hash TEXT, expires_at TEXT);
      CREATE TABLE subscriptions(id TEXT PRIMARY KEY, owner_user_id TEXT, workspace_id TEXT,
        plan TEXT, status TEXT, subscription_status TEXT, trial_end TEXT, expires_at TEXT,
        current_period_end TEXT, payment_failed_at TEXT, stripe_subscription_id TEXT,
        created_at TEXT, updated_at TEXT);
      CREATE TABLE deletion_requests(id TEXT PRIMARY KEY, request_type TEXT, user_id TEXT,
        workspace_id TEXT, status TEXT);
      CREATE TABLE audit_events(id TEXT PRIMARY KEY, workspace_id TEXT, user_id TEXT,
        actor_type TEXT, event_type TEXT, entity_type TEXT, entity_id TEXT,
        description TEXT, metadata_json TEXT, created_at TEXT);
      ${rate}\n${migration}\n${auditRetentionIndex}\n${mcpRateRetentionIndex}\n${selectedWorkspacesMigration}
      INSERT INTO users VALUES ('u1','active',1),('u2','active',1);
      INSERT INTO workspaces VALUES ('w1','One',NULL,'u1'),('w2','Two',NULL,'u2'),('w3','Three',NULL,'u1');
      INSERT INTO workspace_members VALUES ('wm1','w1','u1','viewer'),('wm2','w2','u2','viewer'),
        ('wm3','w3','u1','viewer');
      INSERT INTO subscriptions(id,owner_user_id,workspace_id,plan,status,
        subscription_status,current_period_end,created_at,updated_at)
        VALUES ('sub1','u1','w1','business','active','active','2099-01-01',
          '2026-01-01','2026-01-01');
      INSERT INTO subscriptions(id,owner_user_id,workspace_id,plan,status,
        subscription_status,trial_end,created_at,updated_at)
        VALUES ('trial_u2','u2','w2','professional','trialing','trialing','2099-01-01',
          '2026-01-01','2026-01-01');
      INSERT INTO user_sessions VALUES ('s1','u1','${tokenHash(sessionA)}','2099-01-01'),
        ('s2','u2','${tokenHash(sessionB)}','2099-01-01');
      INSERT INTO mcp_beta_workspace_access(workspace_id,status)
        VALUES ('w1','enabled'),('w2','enabled'),('w3','enabled');
    `);
    async function d1(sqlOrFile, isFile = false) {
      const args = ["d1", "execute", "mcp-oauth-disposable-local", "--config", configPath,
        "--local", "--persist-to", state, isFile ? "--file" : "--command", sqlOrFile,
        "--yes", "--json"];
      let stdout;
      try {
        ({ stdout } = await exec(wrangler, args, { cwd: scanApi, env: commandEnv,
          timeout: 30_000, maxBuffer: 1024 * 1024 }));
      } catch (error) {
        throw new Error(`Local D1 fixture failed: ${error.stderr || error.stdout || error.message}`);
      }
      const result = JSON.parse(stdout);
      assert.equal(result[0]?.success, true, JSON.stringify(result));
      return result[0].results;
    }
    await d1(seedPath, true);
    worker = spawn(wrangler, ["dev", "-c", configPath, "--local", "--ip", "127.0.0.1",
      "--port", String(port), "--inspector-port", "0", "--persist-to", state],
    { cwd: scanApi, env: commandEnv, stdio: ["ignore", "pipe", "pipe"] });
    let log = "";
    for (const stream of [worker.stdout, worker.stderr]) {
      stream.on("data", (data) => { log = (log + data.toString()).slice(-10_000); });
    }
    let ready = false;
    for (let attempt = 0; attempt < 100; attempt++) {
      if (worker.exitCode !== null) throw new Error(`Workerd exited ${worker.exitCode}: ${log}`);
      try {
        const response = await fetch(`${origin}/.well-known/oauth-authorization-server`);
        if (response.status === 200) { ready = true; break; }
      } catch { /* Workerd is starting. */ }
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 200));
    }
    if (!ready) throw new Error(`Workerd startup timed out: ${log}`);
    const metadata = await (await fetch(`${origin}/.well-known/oauth-authorization-server`)).json();
    assert.equal(metadata.issuer, origin);
    assert.equal(metadata.client_id_metadata_document_supported, true);
    assert.equal(metadata.registration_endpoint, `${origin}/oauth/register`);
    assert.equal(metadata.revocation_endpoint, `${origin}/oauth/token`);

    const cimdAuthorize = (clientId) => {
      const url = new URL(`${origin}/authorize`);
      for (const [key, value] of Object.entries({ response_type: "code", client_id: clientId,
        redirect_uri: callback, scope: "mcp:read", state: "cimd-state",
        code_challenge: pkce("c".repeat(43)), code_challenge_method: "S256", resource })) {
        url.searchParams.set(key, value);
      }
      return url;
    };
    const disallowed = await fetch(cimdAuthorize(unreviewedCimd), { redirect: "manual" });
    assert.equal(disallowed.status, 400);
    const resetBudget = async () => {
      assert.equal((await fetch(`${origin}/__reset_mcp_rate`)).status, 204);
    };
    const tokenRequest = async (body, headers = {}) => {
      await resetBudget();
      return fetch(`${origin}/oauth/token`, {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers }, body,
      });
    };
    assert.equal((await tokenRequest(new URLSearchParams({ grant_type: "refresh_token",
      client_id: unreviewedCimd, refresh_token: "dummy" }))).status, 401);
    const basic = Buffer.from(`${encodeURIComponent(unreviewedCimd)}:secret`).toString("base64");
    assert.equal((await tokenRequest("grant_type=authorization_code",
      { Authorization: `Basic ${basic}` })).status, 401);
    assert.equal((await tokenRequest("grant_type=authorization_code",
      { Authorization: `Basic ${basic} ` })).status, 401);
    const assertion = [Buffer.from('{"alg":"RS256"}').toString("base64url"),
      Buffer.from(JSON.stringify({ iss: unreviewedCimd })).toString("base64url"),
      "signature"].join(".");
    assert.equal((await tokenRequest(new URLSearchParams({ grant_type: "authorization_code",
      client_assertion: assertion,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }))).status, 401);
    // The SDK's non-fatal UTF-8 decoder can still parse this JSON and derive
    // the unreviewed issuer. The gate must reject it before any CIMD fetch.
    const badUtf8Claims = Buffer.concat([
      Buffer.from(`{"iss":"${unreviewedCimd}","note":"`), Buffer.from([0xff]),
      Buffer.from('"}'),
    ]).toString("base64url");
    const malformedAssertion = [Buffer.from('{"alg":"RS256"}').toString("base64url"),
      badUtf8Claims, "signature"].join(".");
    assert.equal((await tokenRequest(new URLSearchParams({ grant_type: "authorization_code",
      client_assertion: malformedAssertion,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }))).status, 401);
    assert.equal((await tokenRequest("grant_type=authorization_code")).status, 401);
    assert.equal((await tokenRequest(new URLSearchParams({ grant_type: "authorization_code",
      client_id: reviewedCimd, client_assertion: assertion,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }))).status, 401);
    assert.deepEqual(await (await fetch(`${origin}/__outbound_urls`)).json(), [],
      "blocked CIMD clients must cause zero metadata fetches");
    const allowed = await fetch(cimdAuthorize(reviewedCimd), { redirect: "manual" });
    assert.equal(allowed.status, 302, await allowed.clone().text());
    const approvedFetches = await (await fetch(`${origin}/__outbound_urls`)).json();
    assert.ok(approvedFetches.length >= 1 && approvedFetches.every((url) => url === reviewedCimd));
    const changedCimdRedirect = cimdAuthorize(reviewedCimd);
    changedCimdRedirect.searchParams.set("redirect_uri", `http://127.0.0.1:${port + 2}/callback`);
    assert.equal((await fetch(changedCimdRedirect, { redirect: "manual" })).status, 400,
      "SDK loopback port relaxation must be fenced by exact registered URI");

    const clientMetadata = { client_name: "Local MCP test", redirect_uris: [callback],
      grant_types: ["authorization_code", "refresh_token"], response_types: ["code"],
      token_endpoint_auth_method: "none" };
    for (const invalid of [
      { ...clientMetadata, token_endpoint_auth_method: "client_secret_basic" },
      { ...clientMetadata, token_endpoint_auth_method: undefined },
    ]) {
      await resetBudget();
      const denied = await fetch(`${origin}/oauth/register`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(invalid),
      });
      assert.equal(denied.status, 400, await denied.clone().text());
    }
    await resetBudget();
    const registration = await fetch(`${origin}/oauth/register`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(clientMetadata),
    });
    assert.equal(registration.status, 201, await registration.clone().text());
    const { client_id: clientId } = await registration.json();
    assert.ok(clientId);
    const changedDcrRedirect = new URL(`${origin}/authorize`);
    await resetBudget();
    for (const [key, value] of Object.entries({ response_type: "code", client_id: clientId,
      redirect_uri: `http://127.0.0.1:${port + 2}/callback`, scope: "mcp:read",
      state: "port-mismatch", code_challenge: pkce("m".repeat(43)),
      code_challenge_method: "S256", resource })) changedDcrRedirect.searchParams.set(key, value);
    assert.equal((await fetch(changedDcrRedirect, { redirect: "manual" })).status, 400);

    const beforeInvalid = await d1("SELECT COALESCE(SUM(request_count),0) AS n FROM api_rate_limits WHERE scope='mcp_oauth_global' AND action='mcp_token_exchange'");
    for (let attempt = 0; attempt < 20; attempt++) {
      const malformed = await fetch(`${origin}/oauth/token`, { method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded",
          "CF-Connecting-IP": "203.0.113.11" }, body: "grant_type=invalid" });
      assert.ok([400, 401].includes(malformed.status));
    }
    const afterInvalid = await d1("SELECT COALESCE(SUM(request_count),0) AS n FROM api_rate_limits WHERE scope='mcp_oauth_global' AND action='mcp_token_exchange'");
    assert.deepEqual(afterInvalid, beforeInvalid,
      "malformed traffic from another IP must not spend shared token capacity");

    async function connect(userId, workspaceId, session, index,
      requestedScope = "mcp:read offline_access", deny = false, selectedWorkspaceIds = []) {
      const verifier = `${index}`.repeat(43);
      const authorize = new URL(`${origin}/authorize`);
      for (const [key, value] of Object.entries({ response_type: "code", client_id: clientId,
        redirect_uri: callback, scope: requestedScope, state: `state-${index}`,
        code_challenge: pkce(verifier), code_challenge_method: "S256", resource })) {
        authorize.searchParams.set(key, value);
      }
      const started = await fetch(authorize, { redirect: "manual" });
      assert.equal(started.status, 302, await started.clone().text());
      const intent = new URL(started.headers.get("Location")).searchParams.get("intent");
      assert.ok(intent);
      const bridged = await fetch(`${origin}/api/mcp/oauth/browser-session`, {
        method: "POST", headers: { Origin: origin, Authorization: `Bearer ${session}`,
          "Content-Type": "application/json" }, body: JSON.stringify({ intent }),
      });
      assert.equal(bridged.status, 200, await bridged.clone().text());
      const bridgeCookie = bridged.headers.get("Set-Cookie").split(";")[0];
      const { continue_url: continueUrl } = await bridged.json();
      const consent = await fetch(continueUrl, { headers: { Cookie: bridgeCookie } });
      assert.equal(consent.status, 200, await consent.clone().text());
      const html = await consent.text();
      assert.match(html, /formnovalidate>Deny/);
      assert.match(html, /value="" selected disabled/);
      assert.match(html, /provider may retain data it receives under its own terms and settings/);
      assert.match(html, /Revoking this connection stops future CyberMeters reads, but cannot delete data already sent/);
      if (userId === "u1" && requestedScope.includes("portfolio:read")) {
        assert.match(html, /Selected workspaces \(portfolio read\)/);
        assert.match(html, /None are selected by default/);
        assert.doesNotMatch(html, /name="selected_workspace_id"[^>]*checked/);
      } else {
        assert.doesNotMatch(html, /Selected workspaces \(portfolio read\)/);
      }
      const handle = /name="handle" value="([^"]+)"/.exec(html)?.[1];
      assert.ok(handle);
      const consentCookie = consent.headers.get("Set-Cookie")?.split(";")[0];
      assert.ok(consentCookie);
      const approvalForm = new URLSearchParams(deny
        ? { handle, decision: "deny" }
        : { handle, decision: "approve", context: workspaceId });
      for (const selectedWorkspaceId of selectedWorkspaceIds) {
        approvalForm.append("selected_workspace_id", selectedWorkspaceId);
      }
      const approved = await fetch(continueUrl, {
        method: "POST", redirect: "manual",
        headers: { Origin: origin, Cookie: `${bridgeCookie}; ${consentCookie}`,
          "Content-Type": "application/x-www-form-urlencoded" },
        body: approvalForm,
      });
      assert.equal(approved.status, 302, await approved.clone().text());
      const callbackUrl = new URL(approved.headers.get("Location"));
      assert.equal(callbackUrl.searchParams.get("state"), `state-${index}`);
      assert.equal(callbackUrl.searchParams.get("iss"), origin);
      if (deny) {
        assert.equal(callbackUrl.searchParams.get("error"), "access_denied");
        assert.equal(callbackUrl.searchParams.has("code"), false);
        return { denied: true };
      }
      const code = callbackUrl.searchParams.get("code");
      assert.ok(code);
      if (index === "R") {
        const wrongRedirect = await fetch(`${origin}/oauth/token`, {
          method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ grant_type: "authorization_code", code,
            client_id: clientId, redirect_uri: `http://127.0.0.1:${port + 2}/callback`,
            code_verifier: verifier, resource }),
        });
        assert.equal(wrongRedirect.status, 400);
      }
      const exchanged = await fetch(`${origin}/oauth/token`, {
        method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "authorization_code", code, client_id: clientId,
          redirect_uri: callback, code_verifier: verifier, resource }),
      });
      assert.equal(exchanged.status, 200, await exchanged.clone().text());
      const issued = await exchanged.json();
      assert.ok(issued.access_token);
      assert.ok(issued.refresh_token);
      return { issued, userId, workspaceId, session };
    }
    async function validate(accessToken) {
      const response = await fetch(`${origin}/__validate`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      assert.equal(response.status, 200);
      return response.json();
    }
    async function customerRead(accessToken) {
      const response = await fetch(`${origin}/__read`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      return { status: response.status, body: await response.json() };
    }
    await resetBudget();
    assert.deepEqual(await connect("u1", "w1", sessionA, "D",
      "mcp:read offline_access", true), { denied: true });
    await resetBudget();
    // Client asks for portfolio, but this user approves one workspace.
    // The grant must narrow the scope without changing the request bound to consent.
    const a = await connect("u1", "w1", sessionA, "A", "mcp:read portfolio:read offline_access");
    await resetBudget();
    const b = await connect("u2", "w2", sessionB, "B");
    assert.equal(a.issued.scope.includes("portfolio:read"), false);
    assert.deepEqual(await validate(a.issued.access_token), { ok: true, workspace: "w1", user: "u1" });
    assert.deepEqual(await validate(b.issued.access_token), { ok: true, workspace: "w2", user: "u2" });
    assert.deepEqual((await customerRead(a.issued.access_token)).body.workspaces
      .map((row) => row.workspace_id), ["w1"]);
    assert.deepEqual((await customerRead(b.issued.access_token)).body.workspaces
      .map((row) => row.workspace_id), ["w2"]);
    await resetBudget();
    const refreshed = await fetch(`${origin}/oauth/token`, {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: a.issued.refresh_token,
        client_id: clientId, resource }),
    });
    assert.equal(refreshed.status, 200, await refreshed.clone().text());
    const rotated = await refreshed.json();
    assert.ok(rotated.refresh_token && rotated.refresh_token !== a.issued.refresh_token);
    assert.deepEqual(await validate(rotated.access_token), { ok: true, workspace: "w1", user: "u1" });

    const ownedConnections = await fetch(`${origin}/api/mcp/oauth/connections`, {
      headers: { Origin: origin, Authorization: `Bearer ${sessionA}` },
    });
    assert.equal(ownedConnections.status, 200);
    const connections = await ownedConnections.json();
    assert.equal(connections.connections.length, 1);
    assert.equal(connections.connections[0].workspace_name, "One");
    assert.ok(connections.connections[0].last_used_at,
      "Connections page must expose the last successful MCP use");
    assert.equal(connections.eligible, true);
    const connectionId = connections.connections[0].id;
    await d1(`CREATE TRIGGER block_mcp_revoke_audit BEFORE INSERT ON audit_events
      WHEN NEW.event_type = 'mcp_oauth_grant_revoked'
      BEGIN SELECT RAISE(ABORT, 'audit write unavailable'); END`);
    const failedRevoke = await fetch(`${origin}/api/mcp/oauth/connections/${connectionId}`, {
      method: "DELETE", headers: { Origin: origin, Authorization: `Bearer ${sessionA}` },
    });
    assert.equal(failedRevoke.status, 503, await failedRevoke.clone().text());
    assert.deepEqual(await d1(`SELECT status FROM mcp_oauth_connections WHERE id = '${connectionId}'`),
      [{ status: "active" }], "failed audit must roll back the D1 revocation");
    assert.equal((await validate(rotated.access_token)).ok, true);
    await d1("DROP TRIGGER block_mcp_revoke_audit");
    const revoked = await fetch(`${origin}/api/mcp/oauth/connections/${connectionId}`, {
      method: "DELETE", headers: { Origin: origin, Authorization: `Bearer ${sessionA}` },
    });
    assert.equal(revoked.status, 200, await revoked.clone().text());
    const retried = await fetch(`${origin}/api/mcp/oauth/connections/${connectionId}`, {
      method: "DELETE", headers: { Origin: origin, Authorization: `Bearer ${sessionA}` },
    });
    assert.equal(retried.status, 200, await retried.clone().text());
    assert.equal((await validate(rotated.access_token)).ok, false);
    assert.equal((await customerRead(rotated.access_token)).status, 403);
    assert.deepEqual(await validate(b.issued.access_token), { ok: true, workspace: "w2", user: "u2" });
    assert.deepEqual((await customerRead(b.issued.access_token)).body.workspaces
      .map((row) => row.workspace_id), ["w2"]);
    await resetBudget();
    const refreshDenied = await fetch(`${origin}/oauth/token`, {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: rotated.refresh_token,
        client_id: clientId, resource }),
    });
    assert.equal(refreshDenied.status, 400);
    const clientRevoked = await fetch(metadata.revocation_endpoint, {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: b.issued.refresh_token,
        token_type_hint: "refresh_token", client_id: clientId }),
    });
    assert.equal(clientRevoked.status, 200, await clientRevoked.clone().text());
    assert.equal((await validate(b.issued.access_token)).ok, false);

    await resetBudget();
    const portfolio = await connect("u1", "portfolio", sessionA, "R",
      "mcp:read portfolio:read offline_access", false, ["w1"]);
    assert.deepEqual((await customerRead(portfolio.issued.access_token)).body.workspaces
      .map((row) => row.workspace_id), ["w1"], "unselected w3 must not enter a grant");
    const portfolioConnections = await (await fetch(`${origin}/api/mcp/oauth/connections`, {
      headers: { Origin: origin, Authorization: `Bearer ${sessionA}` },
    })).json();
    const chosen = portfolioConnections.connections.find((row) => row.portfolio_read === true);
    assert.deepEqual(chosen.selected_workspaces.map((row) => row.workspace_id), ["w1"]);
    assert.ok(chosen.last_used_at);
    const refresh = async (credential) => {
      await resetBudget();
      return fetch(`${origin}/oauth/token`, {
        method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: credential,
          client_id: clientId, resource }),
      });
    };
    const unknownRefresh = portfolio.issued.refresh_token.slice(0, -1) +
      (portfolio.issued.refresh_token.endsWith("z") ? "y" : "z");
    assert.equal((await refresh(unknownRefresh)).status, 400);
    assert.equal((await validate(portfolio.issued.access_token)).ok, true,
      "an unknown token must not revoke a connection");
    const firstRotationResponse = await refresh(portfolio.issued.refresh_token);
    assert.equal(firstRotationResponse.status, 200, await firstRotationResponse.clone().text());
    const firstRotation = await firstRotationResponse.json();
    const secondRotationResponse = await refresh(firstRotation.refresh_token);
    assert.equal(secondRotationResponse.status, 200, await secondRotationResponse.clone().text());
    const secondRotation = await secondRotationResponse.json();
    const oldReplay = await refresh(portfolio.issued.refresh_token);
    assert.equal(oldReplay.status, 400);
    assert.equal((await validate(secondRotation.access_token)).ok, false,
      "known rotated-token replay must revoke the whole connection");
    assert.deepEqual(await d1(`SELECT status FROM mcp_oauth_connections WHERE id = '${chosen.id}'`),
      [{ status: "revoked" }]);

    await resetBudget();
    const oversized = await fetch(`${origin}/oauth/token`, {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      duplex: "half", body: new ReadableStream({ start(controller) {
        controller.enqueue(new TextEncoder().encode("grant_type=refresh_token&token="));
        controller.enqueue(new TextEncoder().encode("x".repeat(5000)));
        controller.close();
      } }),
    });
    assert.equal(oversized.status, 400);
    const stalled = await fetch(`${origin}/__stalled_body`);
    assert.equal(stalled.status, 200);
    assert.deepEqual(await stalled.json(), { rejected: true });
    let throttled = false;
    for (let i = 0; i < 65; i++) {
      const response = await fetch(`${origin}/oauth/token`, {
        method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "authorization_code", client_id: clientId,
          code: "invalid", redirect_uri: callback, code_verifier: "v".repeat(43), resource }),
      });
      if (response.status === 429) { throttled = true; break; }
      assert.ok([400, 401].includes(response.status));
    }
    assert.equal(throttled, true, "token requests must hit the fail-closed global budget");
    const events = await d1("SELECT event_type, user_id, workspace_id FROM audit_events ORDER BY created_at");
    assert.equal(events.filter((row) => row.event_type === "mcp_oauth_grant_issued").length, 3);
    assert.equal(events.filter((row) => row.event_type === "mcp_oauth_grant_revoked").length, 1);
    assert.equal(events.filter((row) => row.event_type === "mcp_oauth_refresh_reused").length, 1);
    const reads = await d1(`SELECT user_id, workspace_id, metadata_json, created_at
      FROM audit_events WHERE event_type = 'mcp_customer_workspaces_read' ORDER BY created_at`);
    assert.ok(reads.length >= 3);
    for (const event of reads) {
      const metadata = JSON.parse(event.metadata_json);
      assert.ok(["u1", "u2"].includes(event.user_id));
      assert.ok(event.created_at);
      assert.equal(metadata.tool, "listWorkspaces");
      assert.equal(typeof metadata.client_id_hash, "string");
      assert.equal(typeof metadata.connection_id, "string");
      assert.ok(event.workspace_id || Array.isArray(metadata.selected_workspace_ids));
    }
    process.stdout.write("PASS: local workerd OAuth issuance, backend read, refresh, two-tenant isolation, revoke, bounded token input, rate and audit\n");
  } finally {
    if (worker && worker.exitCode === null && worker.signalCode === null) {
      worker.kill("SIGINT");
      await Promise.race([
        new Promise((resolveExit) => worker.once("exit", resolveExit)),
        new Promise((resolveDelay) => setTimeout(resolveDelay, 3000)),
      ]);
      if (worker.exitCode === null) worker.kill("SIGKILL");
    }
    await rm(temp, { recursive: true, force: true });
  }
}

main().catch((error) => {
  process.stderr.write(`FAIL: ${error.stack ?? error}\n`);
  process.exitCode = 1;
});
