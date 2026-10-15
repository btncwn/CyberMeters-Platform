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
const opts = (env) => ({ issuer: env.TEST_ISSUER, resource: env.TEST_RESOURCE,
  appOrigin: env.TEST_APP_ORIGIN, testClientIp: "127.0.0.1" });
export default { async fetch(request, env, ctx) {
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
        TEST_ISSUER: origin, TEST_RESOURCE: resource, TEST_APP_ORIGIN: origin },
    }));
    const migration = await readFile(join(repo, "database/migrations/121-mcp-oauth.sql"), "utf8");
    const rate = await readFile(join(repo, "database/migrations/026-api-rate-limits.sql"), "utf8");
    const sessionA = "a".repeat(64);
    const sessionB = "b".repeat(64);
    await writeFile(seedPath, `
      CREATE TABLE users(id TEXT PRIMARY KEY, status TEXT, email_verified INTEGER);
      CREATE TABLE workspaces(id TEXT PRIMARY KEY, name TEXT, deleted_at TEXT);
      CREATE TABLE workspace_members(id TEXT PRIMARY KEY, workspace_id TEXT, user_id TEXT, role TEXT);
      CREATE TABLE user_sessions(id TEXT PRIMARY KEY, user_id TEXT, token_hash TEXT, expires_at TEXT);
      CREATE TABLE deletion_requests(id TEXT PRIMARY KEY, request_type TEXT, user_id TEXT,
        workspace_id TEXT, status TEXT);
      CREATE TABLE audit_events(id TEXT PRIMARY KEY, workspace_id TEXT, user_id TEXT,
        actor_type TEXT, event_type TEXT, entity_type TEXT, entity_id TEXT,
        description TEXT, metadata_json TEXT, created_at TEXT);
      ${rate}\n${migration}
      INSERT INTO users VALUES ('u1','active',1),('u2','active',1);
      INSERT INTO workspaces VALUES ('w1','One',NULL),('w2','Two',NULL);
      INSERT INTO workspace_members VALUES ('wm1','w1','u1','viewer'),('wm2','w2','u2','viewer');
      INSERT INTO user_sessions VALUES ('s1','u1','${tokenHash(sessionA)}','2099-01-01'),
        ('s2','u2','${tokenHash(sessionB)}','2099-01-01');
      INSERT INTO mcp_beta_workspace_access(workspace_id,status)
        VALUES ('w1','enabled'),('w2','enabled');
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

    const registration = await fetch(`${origin}/oauth/register`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ client_name: "Local MCP test", redirect_uris: [callback],
        grant_types: ["authorization_code", "refresh_token"], response_types: ["code"],
        token_endpoint_auth_method: "none" }),
    });
    assert.equal(registration.status, 201, await registration.clone().text());
    const { client_id: clientId } = await registration.json();
    assert.ok(clientId);

    async function connect(userId, workspaceId, session, index,
      requestedScope = "mcp:read offline_access", deny = false) {
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
      const handle = /name="handle" value="([^"]+)"/.exec(html)?.[1];
      assert.ok(handle);
      const consentCookie = consent.headers.get("Set-Cookie")?.split(";")[0];
      assert.ok(consentCookie);
      const approved = await fetch(continueUrl, {
        method: "POST", redirect: "manual",
        headers: { Origin: origin, Cookie: `${bridgeCookie}; ${consentCookie}`,
          "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(deny
          ? { handle, decision: "deny" }
          : { handle, decision: "approve", context: workspaceId }),
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
    assert.deepEqual(await connect("u1", "w1", sessionA, "D",
      "mcp:read offline_access", true), { denied: true });
    // Client asks for portfolio, but this free-plan user approves one workspace.
    // The grant must narrow the scope without changing the request bound to consent.
    const a = await connect("u1", "w1", sessionA, "A", "mcp:read portfolio:read offline_access");
    const b = await connect("u2", "w2", sessionB, "B");
    assert.equal(a.issued.scope.includes("portfolio:read"), false);
    assert.deepEqual(await validate(a.issued.access_token), { ok: true, workspace: "w1", user: "u1" });
    assert.deepEqual(await validate(b.issued.access_token), { ok: true, workspace: "w2", user: "u2" });
    assert.deepEqual((await customerRead(a.issued.access_token)).body.workspaces
      .map((row) => row.workspace_id), ["w1"]);
    assert.deepEqual((await customerRead(b.issued.access_token)).body.workspaces
      .map((row) => row.workspace_id), ["w2"]);
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
        body: "grant_type=invalid",
      });
      if (response.status === 429) { throttled = true; break; }
      assert.ok([400, 401].includes(response.status));
    }
    assert.equal(throttled, true, "token requests must hit the fail-closed IP budget");
    const events = await d1("SELECT event_type, user_id, workspace_id FROM audit_events ORDER BY created_at");
    assert.equal(events.filter((row) => row.event_type === "mcp_oauth_grant_issued").length, 2);
    assert.equal(events.filter((row) => row.event_type === "mcp_oauth_grant_revoked").length, 1);
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
