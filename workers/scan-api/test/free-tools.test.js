import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { cleanupExpiredPublicApiRateLimits } from "../src/cron/scheduled.js";
import { buildDmarcToolResult, runDmarcCheck } from "../src/engines/free-tools/dmarc-check.js";
import { buildSpfToolResult, runSpfCheck } from "../src/engines/free-tools/spf-check.js";
import { FREE_TOOL_POLICY, domainCapKey, normaliseToolDomain } from "../src/lib/free-tool-gate.js";
import { signShareToken, verifyShareToken } from "../src/lib/free-tool-share.js";
import { consumeApiRateLimit, rateLimitScopeId } from "../src/lib/rate-limit.js";
import { freeToolsRoutes, processFreeToolDeferredChecks } from "../src/routes/free-tools.js";

const SHARE_KEY = "k".repeat(40);

function fixture({ failRateLimits = false } = {}) {
  const sqlite = new DatabaseSync(":memory:");
  for (const file of ["026-api-rate-limits.sql", "129-free-tool-deferred-checks.sql"]) {
    sqlite.exec(readFileSync(fileURLToPath(new URL(`../../../database/migrations/${file}`, import.meta.url)), "utf8"));
  }
  sqlite.exec(`
    CREATE TABLE workspaces(id TEXT PRIMARY KEY, deleted_at TEXT);
    CREATE TABLE workspace_members(id TEXT PRIMARY KEY, workspace_id TEXT, user_id TEXT);
    INSERT INTO workspaces VALUES ('w1', NULL);
    INSERT INTO workspace_members VALUES ('m1', 'w1', 'u1');
  `);
  const db = {
    prepare(sql) {
      if (failRateLimits && /api_rate_limits/.test(sql)) throw new Error("D1 unavailable");
      const statement = sqlite.prepare(sql);
      return { bind(...args) { return {
        first: async () => statement.get(...args) ?? null,
        all: async () => ({ results: statement.all(...args) }),
        run: async () => ({ meta: { changes: Number(statement.run(...args).changes) } }),
      }; } };
    },
  };
  const env = {
    cybermeters_db: db,
    TURNSTILE_SECRET_KEY: "secret",
    TURNSTILE_SITE_KEY: "site-key",
    FREE_TOOLS_SHARE_KEY: SHARE_KEY,
    FRONTEND_URL: "https://app.cybermeters.com",
  };
  return { sqlite, env };
}

function memoryCache() {
  const store = new Map();
  return {
    store,
    async match(request) { const body = store.get(request.url); return body ? new Response(body) : undefined; },
    async put(request, response) { store.set(request.url, await response.text()); },
  };
}

function goodResult(tool, domain) {
  return { schema: `free-tool-${tool}.v1`, tool, domain, checked_at: "2026-10-19T12:00:00.000Z",
    verdict: { level: "good", headline: "ok", summary: "ok" }, next_step: { title: "No change needed", explanation: "", record: null } };
}

// One harness per test: counts lookups, Turnstile calls and founder alerts.
function harness(env, overrides = {}) {
  const calls = { lookups: 0, turnstile: 0, alerts: [], waits: [] };
  const turnstileFetch = overrides.turnstileFetch || (async (_url, init) => {
    calls.turnstile += 1;
    const token = init.body.get("response");
    return new Response(JSON.stringify(token === "good-dmarc" ? { success: true, action: "tool_dmarc" }
      : token === "good-spf" ? { success: true, action: "tool_spf" }
        : token === "good-dmarc-defer" ? { success: true, action: "tool_dmarc_defer" }
          : { success: false, "error-codes": ["invalid-input-response"] }));
  });
  const cache = overrides.cache === undefined ? memoryCache() : overrides.cache;
  const call = (method, path, body, { ip = "198.51.100.1", auth = null } = {}) => {
    const headers = { "Content-Type": "application/json", "CF-Connecting-IP": ip };
    if (auth) headers.Authorization = `Bearer ${auth}`;
    const request = new Request(`https://api.cybermeters.com${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    return freeToolsRoutes({
      request, env, url: new URL(request.url),
      ctx: { waitUntil: (promise) => calls.waits.push(promise) },
      json: (data, status = 200) => Response.json(data, { status }),
      requireAuth: async (req) => (req.headers.get("Authorization") === "Bearer member" ? { id: "u1" } : req.headers.get("Authorization") === "Bearer loner" ? { id: "u2" } : null),
      consumeApiRateLimit, rateLimitScopeId,
      turnstileFetch,
      freeToolCache: cache,
      freeToolAlert: async (subject) => { calls.alerts.push(subject); return { sent: true }; },
      freeToolRunners: {
        dmarc: async (domain) => { calls.lookups += 1; return goodResult("dmarc", domain); },
        spf: async (domain) => { calls.lookups += 1; return goodResult("spf", domain); },
      },
    });
  };
  return { calls, cache, call, check: (tool, domain, token, opts) => call("POST", `/api/tools/${tool}/check`, { domain, turnstile_token: token }, opts) };
}

const rows = (sqlite, sql = "SELECT * FROM api_rate_limits") => sqlite.prepare(sql).all();
const globalWindowId = () => {
  const start = new Date(Math.floor(Date.now() / 86_400_000) * 86_400_000).toISOString();
  return `rl_global:free_tool_global:free_tool_global:${start}`.replace(/[^a-zA-Z0-9_-]+/g, "_");
};

test("domain input: public names only, never an IP, port, path or internal name", () => {
  assert.deepEqual(normaliseToolDomain("Example.COM"), { ok: true, domain: "example.com" });
  assert.deepEqual(normaliseToolDomain("https://www.example.co.uk/"), { ok: true, domain: "example.co.uk" });
  assert.deepEqual(normaliseToolDomain("mail.example.com."), { ok: true, domain: "mail.example.com" });
  for (const bad of ["127.0.0.1", "169.254.169.254", "[::1]", "::1", "10.0.0.1", "localhost", "intranet",
    "metadata.google.internal", "printer.local", "example.com:8080", "example.com/admin", "user@example.com",
    "example.com?x=1", "1.0.0.127.in-addr.arpa", "router.home", "foo.test", "", "   ", "a".repeat(400), 42, null]) {
    assert.equal(normaliseToolDomain(bad).ok, false, `refused: ${bad}`);
  }
  assert.equal(domainCapKey("mail.shop.example.co.uk"), "example.co.uk");
  assert.equal(domainCapKey("a.b.example.com"), "example.com");
});

test("SSRF-style and invalid targets are refused before Turnstile, D1 or any lookup", async () => {
  const { sqlite, env } = fixture();
  const h = harness(env);
  for (const target of ["127.0.0.1", "metadata.google.internal", "example.com:22", "http://10.0.0.1/"]) {
    const res = await h.check("dmarc", target, "good-dmarc");
    assert.equal(res.status, 400, target);
    assert.equal((await res.json()).status, "invalid_input");
  }
  assert.equal(h.calls.turnstile, 0);
  assert.equal(h.calls.lookups, 0);
  assert.equal(rows(sqlite).length, 0);
});

test("a missing, failed or wrong-tool Turnstile token refuses; a missing secret refuses", async () => {
  const { sqlite, env } = fixture();
  const h = harness(env);
  const missing = await h.check("dmarc", "example.com", undefined);
  assert.equal(missing.status, 400);
  assert.equal((await missing.json()).status, "verification_required");
  assert.equal((await h.check("dmarc", "example.com", "bad")).status, 403);
  // A token made for the SPF tool cannot run the DMARC tool.
  assert.equal((await h.check("dmarc", "example.com", "good-spf")).status, 403);
  const noSecret = harness({ ...env, TURNSTILE_SECRET_KEY: "" });
  const unconfigured = await noSecret.check("dmarc", "example.com", "good-dmarc");
  assert.equal(unconfigured.status, 503);
  assert.equal(noSecret.calls.turnstile, 0);
  const down = harness(env, { turnstileFetch: async () => { throw new Error("timeout"); } });
  assert.equal((await down.check("dmarc", "example.com", "good-dmarc")).status, 503);
  assert.equal(h.calls.lookups + noSecret.calls.lookups + down.calls.lookups, 0);
  assert.equal(rows(sqlite).length, 0);
});

test("each IP runs each tool at most twice per rolling 24 hours, with a reset time", async () => {
  const { sqlite, env } = fixture();
  const h = harness(env);
  assert.equal((await h.check("dmarc", "one.example.com", "good-dmarc")).status, 200);
  assert.equal((await h.check("dmarc", "two.example.com", "good-dmarc")).status, 200);
  const third = await h.check("dmarc", "three.example.com", "good-dmarc");
  assert.equal(third.status, 429);
  const body = await third.json();
  assert.equal(body.status, "limit_reached");
  assert.equal(body.scope, "ip");
  assert.ok(Date.parse(body.reset_at) > Date.now() + 23 * 3600 * 1000);
  assert.match(body.trial_url, /\/signup$/);
  assert.equal(h.calls.lookups, 2);
  // The other tool has its own allowance.
  assert.equal((await h.check("spf", "three.example.com", "good-spf")).status, 200);
  // A claim leaves the window 24 hours after it was made, not at a calendar boundary.
  sqlite.exec(`UPDATE api_rate_limits SET window_start = '${new Date(Date.now() - 25 * 3600 * 1000).toISOString()}'
               WHERE action = 'free_tool_ip_dmarc' AND id LIKE '%slot0'`);
  assert.equal((await h.check("dmarc", "three.example.com", "good-dmarc")).status, 200);
  assert.equal((await h.check("dmarc", "four.example.com", "good-dmarc")).status, 429);
});

test("rolling slots cannot be double-claimed and a refused request writes nothing new", async () => {
  const { sqlite, env } = fixture();
  const scope = [{ scope: "ip", scope_id: "x" }];
  const claims = await Promise.all(Array.from({ length: 5 }, () =>
    consumeApiRateLimit(env, scope, "free_tool_ip_test", 2, 86400, { failClosed: true, rolling: true })));
  assert.equal(claims.filter((c) => c === null).length, 2);
  assert.equal(claims.filter((c) => c?.status === 429).length, 3);
  const before = rows(sqlite);
  assert.equal((await consumeApiRateLimit(env, scope, "free_tool_ip_test", 2, 86400, { failClosed: true, rolling: true, peek: true }))?.status, 429);
  assert.deepEqual(rows(sqlite), before);
});

test("the per-domain cap trips across IPs", async () => {
  const { env } = fixture();
  const h = harness(env, { cache: null });
  for (let i = 0; i < FREE_TOOL_POLICY.domainRuns; i += 1) {
    assert.equal((await h.check("spf", `x${i}.target.example.com`, "good-spf", { ip: `203.0.113.${i + 1}` })).status, 200);
  }
  const capped = await h.check("spf", "target.example.com", "good-spf", { ip: "203.0.113.200" });
  assert.equal(capped.status, 429);
  assert.equal((await capped.json()).scope, "domain");
  assert.equal(h.calls.lookups, FREE_TOOL_POLICY.domainRuns);
});

test("a cache hit for the same domain consumes no IP, domain or global budget", async () => {
  const { sqlite, env } = fixture();
  const h = harness(env);
  assert.equal((await h.check("dmarc", "cached.example.com", "good-dmarc", { ip: "192.0.2.1" })).status, 200);
  const after = rows(sqlite, "SELECT id, request_count, window_start FROM api_rate_limits ORDER BY id");
  for (const ip of ["192.0.2.2", "192.0.2.3", "192.0.2.3", "192.0.2.3"]) {
    const res = await h.check("dmarc", "www.cached.example.com", "good-dmarc", { ip });
    assert.equal(res.status, 200);
    assert.equal((await res.json()).cached, true);
  }
  assert.deepEqual(rows(sqlite, "SELECT id, request_count, window_start FROM api_rate_limits ORDER BY id"), after);
  assert.equal(h.calls.lookups, 1);
  // The cache key is a hash: the domain itself is not in it.
  assert.ok([...h.cache.store.keys()].every((key) => !key.includes("cached")));
});

test("a limiter outage refuses instead of running unlimited", async () => {
  const { env } = fixture({ failRateLimits: true });
  const h = harness(env);
  const res = await h.check("dmarc", "example.com", "good-dmarc");
  assert.equal(res.status, 503);
  assert.equal((await res.json()).status, "unavailable");
  assert.equal(h.calls.lookups, 0);
});

test("signed-in workspace users skip Turnstile and the IP limit; others do not", async () => {
  const { sqlite, env } = fixture();
  const h = harness(env, { cache: null });
  for (let i = 0; i < 4; i += 1) {
    assert.equal((await h.check("dmarc", `m${i}.example.com`, undefined, { auth: "member" })).status, 200);
  }
  assert.equal(h.calls.turnstile, 0);
  assert.equal(rows(sqlite, "SELECT * FROM api_rate_limits WHERE action = 'free_tool_ip_dmarc'").length, 0);
  assert.equal(rows(sqlite, "SELECT request_count FROM api_rate_limits WHERE action = 'free_tool_user_dmarc'")[0].request_count, 4);
  // Signed in but without a workspace: an anonymous visitor.
  assert.equal((await h.check("dmarc", "loner.example.com", undefined, { auth: "loner" })).status, 400);
});

test("the daily breaker never sends the visitor away, and alerts the founder at 50% and 80%", async () => {
  const { sqlite, env } = fixture();
  const h = harness(env, { cache: null });
  const id = globalWindowId();
  const half = Math.ceil(FREE_TOOL_POLICY.dailyBudget * 0.5);
  sqlite.prepare(`INSERT INTO api_rate_limits (id, scope, scope_id, action, window_start, window_seconds, request_count)
    VALUES (?, 'global', 'free_tool_global', 'free_tool_global', ?, 86400, ?)`)
    .run(id, new Date(Math.floor(Date.now() / 86_400_000) * 86_400_000).toISOString(), half - 1);
  assert.equal((await h.check("dmarc", "a.example.com", "good-dmarc", { ip: "192.0.2.10" })).status, 200);
  assert.equal((await h.check("dmarc", "b.example.com", "good-dmarc", { ip: "192.0.2.11" })).status, 200);
  await Promise.all(h.calls.waits);
  assert.deepEqual(h.calls.alerts, ["[CyberMeters] Free tools budget at 50%"]);
  sqlite.prepare("UPDATE api_rate_limits SET request_count = ? WHERE id = ?").run(Math.ceil(FREE_TOOL_POLICY.dailyBudget * 0.8) - 1, id);
  assert.equal((await h.check("dmarc", "c.example.com", "good-dmarc", { ip: "192.0.2.12" })).status, 200);
  await Promise.all(h.calls.waits);
  assert.equal(h.calls.alerts.at(-1), "[CyberMeters] Free tools budget at 80%");

  sqlite.prepare("UPDATE api_rate_limits SET request_count = ? WHERE id = ?").run(FREE_TOOL_POLICY.dailyBudget, id);
  const paused = await h.check("dmarc", "d.example.com", "good-dmarc", { ip: "192.0.2.13" });
  assert.equal(paused.status, 429);
  const body = await paused.json();
  assert.equal(body.status, "capacity_paused");
  assert.equal(body.can_defer, true);
  const lookupsBefore = h.calls.lookups;

  // The visitor leaves an email (with consent) and gets the result later.
  const noConsent = await h.call("POST", "/api/tools/dmarc/defer", { domain: "d.example.com", email: "owner@d.example", turnstile_token: "good-dmarc-defer" });
  assert.equal(noConsent.status, 400);
  const queued = await h.call("POST", "/api/tools/dmarc/defer", { domain: "d.example.com", email: "Owner@d.example", consent: true, turnstile_token: "good-dmarc-defer" }, { ip: "192.0.2.13" });
  assert.equal(queued.status, 200, JSON.stringify(await queued.clone().json()));
  assert.equal((await queued.json()).status, "queued");
  assert.equal(rows(sqlite, "SELECT * FROM free_tool_deferred_checks").length, 1);

  const sent = [];
  const deps = {
    consumeApiRateLimit,
    freeToolRunners: { dmarc: async (domain) => goodResult("dmarc", domain) },
    sendEmail: async (subject, _text, _html, _env, from, to) => { sent.push({ subject, from, to }); return { sent: true }; },
  };
  assert.equal((await processFreeToolDeferredChecks(env, deps)).status, "paused");
  assert.equal(sent.length, 0);
  sqlite.prepare("UPDATE api_rate_limits SET request_count = 0 WHERE id = ?").run(id);
  assert.deepEqual(await processFreeToolDeferredChecks(env, deps), { status: "ok", sent: 1 });
  assert.deepEqual(sent, [{ subject: "Your DMARC result for d.example.com", from: "HELLO_EMAIL_FROM", to: ["owner@d.example"] }]);
  assert.equal(rows(sqlite, "SELECT * FROM free_tool_deferred_checks").length, 0, "the address is deleted once sent");
  assert.equal(h.calls.lookups, lookupsBefore);
});

test("deferred rows expire after 72 hours unsent", async () => {
  const { sqlite, env } = fixture();
  sqlite.prepare(`INSERT INTO free_tool_deferred_checks (id, tool, domain, email, consent_at, created_at)
    VALUES ('old', 'spf', 'old.example', 'a@old.example', ?, ?)`).run("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z");
  await processFreeToolDeferredChecks(env, { consumeApiRateLimit, sendEmail: async () => ({ sent: true }), freeToolRunners: {} });
  assert.equal(rows(sqlite, "SELECT * FROM free_tool_deferred_checks").length, 0);
});

test("a shared link verifies, expires, and cannot be edited", async () => {
  const { env } = fixture();
  const h = harness(env);
  const res = await h.check("spf", "share.example.com", "good-spf");
  const { share } = await res.json();
  assert.match(share.url, /^https:\/\/cybermeters\.com\/tools\/spf-checker#share=v1\./);
  const ok = await h.call("POST", "/api/tools/share", { token: share.token });
  assert.equal(ok.status, 200);
  assert.equal((await ok.json()).result.domain, "share.example.com");
  const [v, body, sig] = share.token.split(".");
  const flipped = body[10] === "A" ? "B" : "A";
  const edited = `${v}.${body.slice(0, 10)}${flipped}${body.slice(11)}.${sig}`;
  assert.equal((await (await h.call("POST", "/api/tools/share", { token: edited })).json()).status, "invalid_link");
  const old = await signShareToken(env, goodResult("spf", "x.example.com"), { now: Date.now() - 8 * 24 * 3600 * 1000 });
  assert.equal((await verifyShareToken(env, old.token)).code, "expired_link");
  assert.equal(await signShareToken({ ...env, FREE_TOOLS_SHARE_KEY: "" }, goodResult("spf", "x.example.com")), null);
});

test("expired free-tool limiter rows are swept", async () => {
  const { sqlite, env } = fixture();
  sqlite.exec(`INSERT INTO api_rate_limits (id, scope, scope_id, action, window_start, window_seconds, request_count)
    VALUES ('old', 'ip', 'x', 'free_tool_ip_dmarc', '2026-01-01T00:00:00.000Z', 86400, 1),
           ('new', 'ip', 'y', 'free_tool_ip_dmarc', '${new Date().toISOString()}', 86400, 1)`);
  await cleanupExpiredPublicApiRateLimits(env, new Date().toISOString());
  assert.deepEqual(rows(sqlite, "SELECT id FROM api_rate_limits").map((r) => r.id), ["new"]);
});

// ── Engines ─────────────────────────────────────────────────────────────────

function spfDns(zone) {
  return async (name, type) => {
    const key = `${name}|${type}`;
    if (zone.temperror?.includes(key)) throw new Error("timeout");
    const values = zone[key];
    if (!values) return { Status: 3, Answer: [] };
    return { Status: 0, Answer: values.map((data) => ({ data })) };
  };
}

test("SPF: include tree, lookup count and a clean record", async () => {
  const result = await runSpfCheck("example.com", { dnsQuery: spfDns({
    "example.com|TXT": ['"v=spf1 include:_spf.mail.example ip4:192.0.2.0/24 -all"'],
    "_spf.mail.example|TXT": ['"v=spf1 include:a.mail.example ~all"'],
    "a.mail.example|TXT": ['"v=spf1 ip4:198.51.100.0/24 ~all"'],
  }) });
  assert.equal(result.verdict.level, "good");
  assert.equal(result.lookups.used, 2);
  assert.equal(result.tree.children[0].domain, "_spf.mail.example");
  assert.equal(result.tree.children[0].lookups, 2);
  assert.equal(result.tree.children[0].children[0].domain, "a.mail.example");
  assert.equal(result.next_step.record, null);
});

test("SPF: a dangling include is a permanent error with a corrected record", async () => {
  const result = await runSpfCheck("example.com", { dnsQuery: spfDns({
    "example.com|TXT": ['"v=spf1 include:gone.example include:ok.example ~all"'],
    "ok.example|TXT": ['"v=spf1 ip4:192.0.2.1 -all"'],
  }) });
  assert.equal(result.verdict.level, "risk");
  assert.ok(result.issues.some((i) => i.code === "dangling_include"));
  assert.equal(result.tree.children[0].stopped, "included_domain_no_spf");
  assert.equal(result.next_step.record.value, "v=spf1 include:ok.example ~all");
});

test("SPF: over ten lookups stops at the limit and names the heaviest includes", async () => {
  const zone = { "example.com|TXT": [`"v=spf1 ${Array.from({ length: 11 }, (_, i) => `include:s${i}.example`).join(" ")} -all"`] };
  for (let i = 0; i < 11; i += 1) zone[`s${i}.example|TXT`] = ['"v=spf1 ip4:192.0.2.1 -all"'];
  const result = await runSpfCheck("example.com", { dnsQuery: spfDns(zone) });
  assert.equal(result.verdict.level, "risk");
  assert.equal(result.lookups.stopped_at_limit, true);
  assert.equal(result.next_step.record, null);
  assert.match(result.next_step.explanation, /include:s0\.example/);
});

test("SPF: +all, ?all, missing all, ptr and duplicate records are each corrected", () => {
  const resolution = (extra = {}) => ({ resolution_status: "complete", lookup_count: 0, void_lookup_count: 0, unresolved_mechanisms: [], include_tree: { domain: "example.com", via: "root", record: null, status: "evaluated", lookups: 0, void_lookups: 0, stopped: null, children: [] }, ...extra });
  const run = (records, res = resolution()) => buildSpfToolResult({ domain: "example.com", checkedAt: "t", rootLookup: "ok", records, resolution: res, mxPresent: true });
  const plus = run(["v=spf1 ip4:192.0.2.1 +all"]);
  assert.equal(plus.verdict.level, "risk");
  assert.equal(plus.next_step.record.value, "v=spf1 ip4:192.0.2.1 ~all");
  assert.equal(run(["v=spf1 ip4:192.0.2.1 ?all"]).next_step.record.value, "v=spf1 ip4:192.0.2.1 ~all");
  assert.equal(run(["v=spf1 ip4:192.0.2.1"]).next_step.record.value, "v=spf1 ip4:192.0.2.1 ~all");
  assert.equal(run(["v=spf1 ptr ip4:192.0.2.1 -all"]).next_step.record.value, "v=spf1 ip4:192.0.2.1 -all");
  const dup = run(["v=spf1 ip4:192.0.2.1 -all", "v=spf1 include:mail.example ip4:192.0.2.1 ~all"], { resolution_status: "permerror", lookup_count: 0, void_lookup_count: 0, include_tree: null });
  assert.equal(dup.verdict.level, "risk");
  assert.equal(dup.next_step.record.value, "v=spf1 ip4:192.0.2.1 include:mail.example -all");
  assert.equal(run(["v=spf1 include:x.example -all"]).verdict.level, "good");
});

test("SPF: no record offers both records; a failed lookup is never 'missing'", async () => {
  const none = await runSpfCheck("example.com", { dnsQuery: spfDns({ "example.com|MX": ["10 mx.example.com."] }) });
  assert.equal(none.verdict.level, "risk");
  assert.deepEqual(none.next_step.options.map((o) => o.record.value)[0], "v=spf1 -all");
  const failed = await runSpfCheck("example.com", { dnsQuery: spfDns({ temperror: ["example.com|TXT"] }) });
  assert.equal(failed.verdict.level, "unknown");
  assert.equal(failed.next_step.record, null);
});

const TXT = (...values) => ({ Status: 0, Answer: values.map((data) => ({ type: 16, data })) });
const NODATA = Object.freeze({ Status: 0, Answer: [] });
const dmarcProviders = (zone) => {
  const provider = async (name) => (zone[name] ? TXT(zone[name]) : NODATA);
  return { primaryProvider: provider, secondaryProvider: provider };
};

test("DMARC: p=none climbs the ladder; pct and t are removed; reports are added", async () => {
  const result = await runDmarcCheck("example.com", { providers: dmarcProviders({
    "_dmarc.example.com": "v=DMARC1; p=none; pct=50; t=y; adkim=s",
  }) });
  assert.equal(result.verdict.level, "attention");
  assert.equal(result.ladder.current, "none");
  assert.equal(result.next_step.record.name, "_dmarc.example.com");
  assert.equal(result.next_step.record.value, "v=DMARC1; p=quarantine; adkim=s; rua=mailto:dmarc-reports@example.com");
  assert.ok(result.tags.some((t) => t.tag === "pct"));
  assert.ok(result.checked.some((c) => c.label === "Aggregate reports (rua)" && c.state === "warn"));
  assert.ok(result.not_checked.some((n) => /receivers apply/.test(n.label)));
});

test("DMARC: an unauthorised third-party report destination gets the exact record it needs", async () => {
  const result = await runDmarcCheck("example.com", { providers: dmarcProviders({
    "_dmarc.example.com": "v=DMARC1; p=reject; rua=mailto:agg@reports.vendor.example",
  }) });
  assert.equal(result.verdict.level, "attention");
  const destination = result.reporting.rua[0];
  assert.equal(destination.status, "unauthorized");
  assert.ok(result.next_step.cautions.some((c) => c.includes("example.com._report._dmarc.reports.vendor.example")));
  const authorised = await runDmarcCheck("example.com", { providers: dmarcProviders({
    "_dmarc.example.com": "v=DMARC1; p=reject; rua=mailto:agg@reports.vendor.example",
    "example.com._report._dmarc.reports.vendor.example": "v=DMARC1",
  }) });
  assert.equal(authorised.verdict.level, "good");
  assert.equal(authorised.next_step.title, "No change needed");
});

test("DMARC: no record suggests monitoring first; a failed lookup is never 'missing'", async () => {
  const none = await runDmarcCheck("example.com", { providers: dmarcProviders({}) });
  assert.equal(none.verdict.level, "risk");
  assert.equal(none.next_step.record.value, "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com");
  const failing = async () => ({ outcome: "timeout" });
  const unknown = await runDmarcCheck("example.com", { providers: { primaryProvider: failing, secondaryProvider: failing } });
  assert.equal(unknown.verdict.level, "unknown");
  assert.equal(unknown.next_step.record, null);
  assert.equal(buildDmarcToolResult(null, { domain: "x.example", checkedAt: "t" }).verdict.level, "unknown");
});

test("DMARC: p=reject with a weaker sp adds np=reject (RFC 9989)", async () => {
  const result = await runDmarcCheck("example.com", { providers: dmarcProviders({
    "_dmarc.example.com": "v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com",
  }) });
  assert.ok(result.checked.some((c) => c.label === "Subdomain policy" && c.state === "warn"));
  assert.equal(result.next_step.record.value, "v=DMARC1; p=reject; sp=none; np=reject; rua=mailto:d@example.com");
});
