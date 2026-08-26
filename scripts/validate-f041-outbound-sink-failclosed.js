#!/usr/bin/env node
//
// F-041 outbound-sink fail-closed oracle.
//
// The test is intentionally transport-local: every DoH and HTTP response is
// supplied by the harness. It proves strict A+AAAA policy, per-hop revalidation,
// alert delivery-time trust, HTML-verification honesty, and cloud-storage's
// physical accounting/cache contract without making an external provider call.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const moduleUrl = (...parts) => pathToFileURL(path.join(root, ...parts)).href;

const ssrf = await import(moduleUrl("workers", "scan-api", "src", "lib", "ssrf.js"));
const http = await import(moduleUrl("workers", "scan-api", "src", "lib", "http.js"));
const alerts = await import(moduleUrl("workers", "scan-api", "src", "engines", "alerts.js"));
const domains = await import(moduleUrl("workers", "scan-api", "src", "routes", "domains.js"));
const cloud = await import(moduleUrl("workers", "scan-api", "src", "engines", "cloud-storage-scan.js"));
const budget = await import(moduleUrl("workers", "scan-api", "src", "engines", "scan-budget.js"));

const realFetch = globalThis.fetch;
const realTimeout = AbortSignal.timeout;
AbortSignal.timeout = () => undefined;

let passed = 0;
let failed = 0;
function ok(id, condition, detail = "") {
  if (condition) {
    passed += 1;
    console.log(`PASS ${id}`);
  } else {
    failed += 1;
    console.log(`FAIL ${id}${detail ? ` — ${detail}` : ""}`);
  }
}
function eq(id, got, want) {
  ok(id, got === want, `got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
}

const PUBLIC_A = "93.184.216.34";
const PUBLIC_AAAA = "2606:2800:220:1:248:1893:25c8:1946";
const PRIVATE_A = "10.0.0.5";
const PRIVATE_AAAA = "fd00::5";

function dnsPacket(type, values, { status = 0 } = {}) {
  const rrType = type === "AAAA" ? 28 : 1;
  return {
    Status: status,
    Answer: values.map((data) => ({ name: "public.example.", type: rrType, TTL: 60, data })),
  };
}

function publicResolver(name, type) {
  return Promise.resolve(dnsPacket(type, [type === "AAAA" ? PUBLIC_AAAA : PUBLIC_A]));
}

async function withFetch(fetcher, thunk) {
  globalThis.fetch = fetcher;
  try { return await thunk(); }
  finally { globalThis.fetch = realFetch; }
}

function response(status = 200, headers = {}, body = "ok") {
  return new Response(body, { status, headers });
}

async function callStrict(host, resolver) {
  if (typeof ssrf.resolvePublicDnsTarget !== "function") return null;
  try { return await ssrf.resolvePublicDnsTarget(host, resolver); }
  catch (error) { return { threw: error }; }
}

// ── 1. Strict tri-state resolver ────────────────────────────────────────────
ok("F041_STRICT_HELPER_EXPORTED", typeof ssrf.resolvePublicDnsTarget === "function");
if (typeof ssrf.resolvePublicDnsTarget === "function") {
  const publicState = await callStrict("public.example", publicResolver);
  eq("F041_PUBLIC_A_AAAA_STATE", publicState?.state, "public");

  // IANA's special-purpose registry makes 2001::/23 default non-global, with
  // only explicit narrower globally-reachable allocations. Keep those positive
  // exceptions load-bearing while refusing every unlisted address in the parent.
  const globallyReachableV6 = [
    "64:ff9b::5db8:d822", // RFC 6052 well-known prefix carrying PUBLIC_A
    "2001:1::1",
    "2001:1::2",
    "2001:1::3",
    "2001:3::1",
    "2001:4:112::1",
    "2001:20::1",
    "2001:30::1",
    "2620:4f:8000::1",
  ];
  const exceptionStates = await Promise.all(globallyReachableV6.map((address) =>
    callStrict("public.example", (name, type) => Promise.resolve(
      dnsPacket(type, [type === "AAAA" ? address : PUBLIC_A]),
    ))));
  ok("F041_IPV6_REGISTRY_GLOBAL_EXCEPTIONS_PUBLIC",
    exceptionStates.every((result) => result?.state === "public"),
    JSON.stringify(exceptionStates.map((result, index) => ({
      address: globallyReachableV6[index], state: result?.state, reason: result?.reason,
    }))));

  const broadParent = await callStrict("public.example", (name, type) => Promise.resolve(
    dnsPacket(type, [type === "AAAA" ? "2001:100::1" : "8.8.8.8"]),
  ));
  ok("F041_IPV6_2001_100_MIXED_BLOCKS",
    broadParent?.state === "blocked"
      && broadParent?.reason === "private_or_reserved_address"
      && broadParent?.addresses?.includes("2001:100::1"),
    JSON.stringify(broadParent));

  const nat64Private = await callStrict("public.example", (name, type) => Promise.resolve(
    dnsPacket(type, [type === "AAAA" ? "64:ff9b::a00:5" : PUBLIC_A]),
  ));
  eq("F041_IPV6_NAT64_PRIVATE_EMBED_BLOCKS", nat64Private?.state, "blocked");

  const mixedA = await callStrict("public.example", (name, type) => Promise.resolve(
    dnsPacket(type, [type === "AAAA" ? PRIVATE_AAAA : PUBLIC_A]),
  ));
  eq("F041_MIXED_PUBLIC_A_PRIVATE_AAAA_BLOCKS", mixedA?.state, "blocked");

  const mixedAAAA = await callStrict("public.example", (name, type) => Promise.resolve(
    dnsPacket(type, [type === "AAAA" ? PUBLIC_AAAA : PRIVATE_A]),
  ));
  eq("F041_MIXED_PRIVATE_A_PUBLIC_AAAA_BLOCKS", mixedAAAA?.state, "blocked");

  const mixedSameFamily = await callStrict("public.example", (name, type) => Promise.resolve(
    dnsPacket(type, type === "AAAA" ? [PUBLIC_AAAA] : [PUBLIC_A, PRIVATE_A]),
  ));
  eq("F041_MIXED_WITHIN_A_ANSWER_BLOCKS", mixedSameFamily?.state, "blocked");

  const knownPrivateAndEmpty = await callStrict("public.example", (name, type) => Promise.resolve(
    dnsPacket(type, type === "AAAA" ? [] : [PRIVATE_A]),
  ));
  eq("F041_KNOWN_PRIVATE_DOMINATES_INCOMPLETE", knownPrivateAndEmpty?.state, "blocked");

  const privateAAndError = await callStrict("public.example", (name, type) => type === "AAAA"
    ? Promise.reject(new TypeError("resolver offline"))
    : Promise.resolve(dnsPacket(type, [PRIVATE_A])));
  ok("F041_PRIVATE_A_DOMINATES_AAAA_ERROR_BLOCKS",
    privateAAndError?.state === "blocked"
      && privateAAndError?.reason === "private_or_reserved_address"
      && privateAAndError?.addresses?.includes(PRIVATE_A),
    JSON.stringify(privateAAndError));

  const privateAaaaAndError = await callStrict("public.example", (name, type) => type === "A"
    ? Promise.reject(new TypeError("resolver offline"))
    : Promise.resolve(dnsPacket(type, [PRIVATE_AAAA])));
  ok("F041_PRIVATE_AAAA_DOMINATES_A_ERROR_BLOCKS",
    privateAaaaAndError?.state === "blocked"
      && privateAaaaAndError?.reason === "private_or_reserved_address"
      && privateAaaaAndError?.addresses?.includes(PRIVATE_AAAA),
    JSON.stringify(privateAaaaAndError));

  const typedResolverError = new DOMException("module cancelled", "AbortError");
  const privateAndTyped = await callStrict("public.example", (name, type) => type === "AAAA"
    ? Promise.reject(typedResolverError)
    : Promise.resolve(dnsPacket(type, [PRIVATE_A])));
  ok("F041_TYPED_RESOLVER_CONTROL_ERROR_STILL_DOMINATES_PRIVATE",
    privateAndTyped?.threw === typedResolverError);

  const oneError = await callStrict("public.example", (name, type) => type === "AAAA"
    ? Promise.reject(new TypeError("resolver offline"))
    : Promise.resolve(dnsPacket(type, [PUBLIC_A])));
  eq("F041_RESOLVER_ERROR_WITH_PUBLIC_BLOCKS", oneError?.state, "unavailable");

  const empty = await callStrict("public.example", (name, type) => Promise.resolve(dnsPacket(type, [])));
  eq("F041_EMPTY_TERMINAL_BLOCKS", empty?.state, "unavailable");

  const truncated = await callStrict("public.example", (name, type) => Promise.resolve({
    ...dnsPacket(type, [type === "AAAA" ? PUBLIC_AAAA : PUBLIC_A]),
    TC: true,
  }));
  eq("F041_TRUNCATED_ANSWER_BLOCKS", truncated?.state, "unavailable");

  const malformed = await callStrict("public.example", (name, type) => Promise.resolve({
    Status: 0,
    Answer: [{ name: "public.example.", type: type === "AAAA" ? 28 : 1, TTL: 60, data: "not-an-ip" }],
  }));
  eq("F041_MALFORMED_TERMINAL_BLOCKS", malformed?.state, "unavailable");
}

// ── 2. safeFetch — zero-I/O refusals, every-hop DNS, hook hygiene ───────────
{
  let dnsCalls = 0;
  let calls = 0;
  const value = await withFetch(async () => { calls += 1; return response(); }, () =>
    http.safeFetch("http://127.0.0.1/private", {
      dnsResolver: async (...args) => { dnsCalls += 1; return publicResolver(...args); },
    }));
  ok("F041_LITERAL_PRIVATE_ZERO_DNS_ZERO_HTTP", value === null && dnsCalls === 0 && calls === 0,
    `dns=${dnsCalls}, http=${calls}`);
}

{
  let dnsCalls = 0;
  let httpCalls = 0;
  const value = await withFetch(async () => { httpCalls += 1; return response(); }, () =>
    http.safeFetch("https://999.999.999.999/", {
      dnsResolver: async (...args) => { dnsCalls += 1; return publicResolver(...args); },
    }));
  ok("F041_LITERAL_MALFORMED_ZERO_DNS_ZERO_HTTP",
    value === null && dnsCalls === 0 && httpCalls === 0,
    `dns=${dnsCalls}, http=${httpCalls}`);
}

{
  let dnsCalls = 0;
  let httpCalls = 0;
  let leaked = null;
  const resolver = async (name, type) => {
    dnsCalls += 1;
    return dnsPacket(type, [type === "AAAA" ? PUBLIC_AAAA : PUBLIC_A]);
  };
  const fetcher = async (url, init = {}) => {
    httpCalls += 1;
    leaked = ["accounting", "dnsResolver", "dnsCache", "fetchImpl"].filter((key) =>
      Object.prototype.hasOwnProperty.call(init, key));
    return response();
  };
  const value = await withFetch(fetcher, () => http.safeFetch("https://public.example/start", {
    dnsResolver: resolver,
    dnsCache: new Map(),
    fetchImpl: fetcher,
  }));
  ok("F041_POSITIVE_PUBLIC_A_AAAA_2XX", value?.status === 200 && dnsCalls === 2 && httpCalls === 1,
    `dns=${dnsCalls}, http=${httpCalls}`);
  ok("F041_INTERNAL_HOOKS_NOT_TRANSPORT_OPTIONS", Array.isArray(leaked) && leaked.length === 0,
    JSON.stringify(leaked));
}

for (const [id, resolver] of [
  ["F041_SAFE_FETCH_MIXED_BLOCKS_HTTP", (name, type) => Promise.resolve(dnsPacket(type, [type === "AAAA" ? PRIVATE_AAAA : PUBLIC_A]))],
  ["F041_SAFE_FETCH_RESOLVER_ERROR_BLOCKS_HTTP", (name, type) => type === "AAAA" ? Promise.reject(new TypeError("offline")) : Promise.resolve(dnsPacket(type, [PUBLIC_A]))],
  ["F041_SAFE_FETCH_EMPTY_BLOCKS_HTTP", (name, type) => Promise.resolve(dnsPacket(type, []))],
]) {
  let httpCalls = 0;
  const fetcher = async () => { httpCalls += 1; return response(); };
  const value = await withFetch(fetcher, () => http.safeFetch("https://public.example/", {
    dnsResolver: resolver,
    fetchImpl: fetcher,
  }));
  ok(id, value === null && httpCalls === 0, `value=${value?.status ?? value}, http=${httpCalls}`);
}

{
  let httpCalls = 0;
  const fetcher = async () => { httpCalls += 1; return response(); };
  const value = await withFetch(fetcher, () => http.safeFetch("https://public.example/", {
    dnsResolver: async (name, type) => dnsPacket(type, [
      type === "AAAA" ? "2001:100::1" : "8.8.8.8",
    ]),
    fetchImpl: fetcher,
  }));
  ok("F041_SAFE_FETCH_IPV6_2001_100_ZERO_HTTP",
    value === null && httpCalls === 0,
    `value=${value?.status ?? value}, http=${httpCalls}`);
}

{
  const calls = [];
  const counter = new budget.PhysicalSubrequestCounter({ limit: 10, safetyMargin: 0 });
  const fetcher = async (url) => {
    calls.push(String(url));
    if (calls.length === 1) return response(302, { location: "http://169.254.169.254/latest/meta-data" }, "");
    return response();
  };
  const value = await withFetch(fetcher, () => http.safeFetch("https://public.example/start", {
    dnsResolver: publicResolver,
    fetchImpl: fetcher,
    accounting: counter.contextFor("literal-redirect"),
  }));
  ok("F041_REDIRECT_LITERAL_PRIVATE_NO_SECOND_HTTP",
    value === null && calls.length === 1 && counter.issued === 1,
    `calls=${JSON.stringify(calls)}, issued=${counter.issued}`);
}

{
  const calls = [];
  const counter = new budget.PhysicalSubrequestCounter({ limit: 10, safetyMargin: 0 });
  const resolver = async (name, type) => dnsPacket(type, [
    name === "rebound.example"
      ? (type === "AAAA" ? PRIVATE_AAAA : PRIVATE_A)
      : (type === "AAAA" ? PUBLIC_AAAA : PUBLIC_A),
  ]);
  const fetcher = async (url) => {
    calls.push(String(url));
    if (calls.length === 1) return response(302, { location: "https://rebound.example/secret" }, "");
    return response();
  };
  const value = await withFetch(fetcher, () => http.safeFetch("https://public.example/start", {
    dnsResolver: resolver,
    fetchImpl: fetcher,
    accounting: counter.contextFor("dns-redirect"),
  }));
  ok("F041_REDIRECT_DNS_PRIVATE_NO_SECOND_HTTP",
    value === null && calls.length === 1 && counter.issued === 1,
    `calls=${JSON.stringify(calls)}, issued=${counter.issued}`);
}

{
  const typed = new budget.SubrequestBudgetExhaustedError({ limit: 0, issued: 0, category: "f041" });
  const accounting = { assertCanIssue() { throw typed; }, recordAttempt() { throw new Error("must not charge"); } };
  let observed = null;
  try {
    await withFetch(async () => response(), () => http.safeFetch("https://public.example/", {
      dnsResolver: publicResolver,
      accounting,
    }));
  } catch (error) { observed = error; }
  ok("F041_TYPED_BUDGET_ERROR_OBSERVABLE", observed === typed && observed?.code === budget.SUBREQUEST_BUDGET_EXHAUSTED_CODE);
}

// ── 3. Alert delivery — delivery-time checks, allowlists, HMAC, no POST follow ─
function alertEnv(channel) {
  const updates = [];
  const env = {
    cybermeters_db: {
      prepare(sql) {
        return {
          bind(...args) {
            return {
              async first() {
                if (/SELECT owner_user_id FROM workspaces/.test(sql)) return { owner_user_id: "user_1" };
                if (/FROM notification_preferences/.test(sql)) return null;
                return null;
              },
              async all() {
                if (/FROM subscriptions/.test(sql)) {
                  return { results: [{
                    id: "sub_1", workspace_id: "ws_1", plan: "professional", status: "active",
                    subscription_status: "active", current_period_end: "2099-01-01T00:00:00.000Z",
                    created_at: "2026-08-26T00:00:00.000Z", updated_at: "2026-08-26T00:00:00.000Z",
                  }] };
                }
                if (/FROM workspace_alert_channels/.test(sql)) return { results: [channel] };
                return { results: [] };
              },
              async run() { updates.push({ sql, args }); return { meta: { changes: 1 } }; },
            };
          },
        };
      },
    },
  };
  return { env, updates };
}

const alertEvent = {
  kind: "f041_test", severity: "high", title: "F-041 test", summary: "Delivery guard test",
  domain: "example.com", workspace_name: "Example", link: "https://app.cybermeters.com/findings/1",
};

ok("F041_ALERT_SLACK_ALLOWLIST_POSITIVE",
  alerts.validateAlertChannelInput("slack", "https://hooks.slack.com/services/T/B/X").ok === true);
ok("F041_ALERT_TEAMS_ALLOWLIST_POSITIVE",
  alerts.validateAlertChannelInput("teams", "https://tenant.webhook.office.com/workflows/abc").ok === true);
ok("F041_ALERT_ALLOWLIST_NEGATIVE",
  alerts.validateAlertChannelInput("slack", "https://attacker.example/hook").ok === false);

{
  const { env, updates } = alertEnv({
    id: "ch_private", channel_type: "webhook", webhook_url: "https://notify.example/hook", secret: "secret",
  });
  let httpCalls = 0;
  const result = await alerts.deliverWorkspaceAlert(env, "ws_1", alertEvent, {
    fetchImpl: async () => { httpCalls += 1; return response(); },
    dnsQueryImpl: async (name, type) => dnsPacket(type, [type === "AAAA" ? PRIVATE_AAAA : PRIVATE_A]),
  });
  ok("F041_ALERT_CREATE_PUBLIC_DELIVERY_PRIVATE_BLOCKS",
    result.delivered === 0 && httpCalls === 0 && updates.length === 1,
    `result=${JSON.stringify(result)}, http=${httpCalls}, updates=${updates.length}`);
}

{
  const { env } = alertEnv({
    id: "ch_stale_slack", channel_type: "slack", webhook_url: "https://attacker.example/hook", secret: null,
  });
  let httpCalls = 0;
  const result = await alerts.deliverWorkspaceAlert(env, "ws_1", alertEvent, {
    fetchImpl: async () => { httpCalls += 1; return response(); },
    dnsQueryImpl: publicResolver,
  });
  ok("F041_ALERT_DELIVERY_RECHECKS_ALLOWLIST", result.delivered === 0 && httpCalls === 0,
    `result=${JSON.stringify(result)}, http=${httpCalls}`);
}

{
  const { env } = alertEnv({
    id: "ch_hmac", channel_type: "webhook", webhook_url: "https://notify.example/hook", secret: "hmac-secret",
  });
  const calls = [];
  const result = await alerts.deliverWorkspaceAlert(env, "ws_1", alertEvent, {
    fetchImpl: async (url, init = {}) => { calls.push({ url: String(url), init }); return response(); },
    dnsQueryImpl: publicResolver,
  });
  const expected = calls[0]
    ? `sha256=${await alerts.signAlertWebhookBody("hmac-secret", calls[0].init.body)}`
    : null;
  ok("F041_ALERT_GENERIC_HMAC_LOAD_BEARING",
    result.delivered === 1 && calls.length === 1
      && calls[0].init.headers?.["X-CyberMeters-Signature"] === expected,
    `result=${JSON.stringify(result)}, calls=${calls.length}`);
}

{
  const { env, updates } = alertEnv({
    id: "ch_redirect", channel_type: "webhook", webhook_url: "https://notify.example/hook", secret: "redirect-secret",
  });
  const calls = [];
  const fetcher = async (url, init = {}) => {
    calls.push({ url: String(url), body: init.body ?? null, signature: init.headers?.["X-CyberMeters-Signature"] ?? null, redirect: init.redirect });
    if (String(url) === "https://notify.example/hook") {
      if (init.redirect !== "manual") {
        calls.push({ url: "https://redirect.example/collect", body: init.body ?? null,
          signature: init.headers?.["X-CyberMeters-Signature"] ?? null, redirect: "implicit-follow" });
        return response();
      }
      return response(302, { location: "https://redirect.example/collect" }, "");
    }
    return response();
  };
  const result = await alerts.deliverWorkspaceAlert(env, "ws_1", alertEvent, {
    fetchImpl: fetcher,
    dnsQueryImpl: publicResolver,
  });
  const updateStatus = updates[0]?.args?.[1] ?? null;
  ok("F041_ALERT_3XX_BODY_NOT_FORWARDED",
    result.delivered === 0 && calls.length === 1 && calls[0]?.redirect === "manual"
      && updateStatus === "failed:http_302",
    `result=${JSON.stringify(result)}, calls=${JSON.stringify(calls)}, status=${updateStatus}`);
}

// ── 4. Domain HTML proof — bounded public redirects and strict success ──────
const domainSource = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "routes", "domains.js"), "utf8");
ok("F041_DOMAIN_HTML_ROUTES_THROUGH_SAFE_FETCH",
  /safeFetch\(htmlUrl,/.test(domainSource) && !/const htmlRes\s*=\s*await fetch\(htmlUrl,/.test(domainSource));
ok("F041_DOMAIN_PROOF_HELPERS_EXPORTED",
  typeof domains.checkDomainHtmlProof === "function" && typeof domains.domainHtmlProofVerified === "function");

if (typeof domains.checkDomainHtmlProof === "function" && typeof domains.domainHtmlProofVerified === "function") {
  let privateHttp = 0;
  const blocked = await domains.checkDomainHtmlProof(
    "https://proof.example/cybermeters-verification-token.html",
    "token",
    {
      dnsResolver: async (name, type) => dnsPacket(type, [type === "AAAA" ? PRIVATE_AAAA : PRIVATE_A]),
      fetchImpl: async () => { privateHttp += 1; return response(200, {}, "token"); },
    },
  );
  ok("F041_DOMAIN_BLOCK_NEVER_VERIFIES",
    domains.domainHtmlProofVerified(blocked) === false && privateHttp === 0,
    `proof=${JSON.stringify(blocked)}, http=${privateHttp}`);
  ok("F041_DOMAIN_NULL_NOT_VERIFIED",
    domains.domainHtmlProofVerified({ state: "unavailable", verified: null }) === false);

  const positive = await domains.checkDomainHtmlProof(
    "https://proof.example/cybermeters-verification-token.html",
    "token",
    { dnsResolver: publicResolver, fetchImpl: async () => response(200, {}, "token") },
  );
  ok("F041_DOMAIN_PUBLIC_2XX_EXACT_TOKEN_VERIFIES",
    domains.domainHtmlProofVerified(positive) === true);

  const calls = [];
  const redirectBlocked = await domains.checkDomainHtmlProof(
    "https://proof.example/cybermeters-verification-token.html",
    "token",
    {
      dnsResolver: publicResolver,
      fetchImpl: async (url) => {
        calls.push(String(url));
        return calls.length === 1
          ? response(302, { location: "http://127.0.0.1/token" }, "")
          : response(200, {}, "token");
      },
    },
  );
  ok("F041_DOMAIN_PRIVATE_REDIRECT_NO_SECOND_HTTP",
    domains.domainHtmlProofVerified(redirectBlocked) === false && calls.length === 1,
    JSON.stringify(calls));
}

ok("F041_DOMAIN_PERSISTENCE_REQUIRES_STRICT_PROOF",
  /domainHtmlProofVerified\(htmlProof\)/.test(domainSource) && /if \(htmlVerified\) \{[\s\S]{0,800}persistVerification/.test(domainSource));

// ── 5. Cloud-storage — shared cache and exact physical accounting ──────────
function cloudModules(hosts) {
  return {
    subdomains: { items: hosts },
    subdomain_takeover: { cname_observations: [], risks: [] },
    asset_exposure: { assets: [] },
  };
}

function makeCloudTransport({ privateDns = false } = {}) {
  const calls = [];
  const fetcher = async (value, init = {}) => {
    const url = String(value);
    const kind = /cloudflare-dns\.com\/dns-query/.test(url) ? "dns" : "http";
    calls.push({ kind, url, method: init.method || "GET" });
    if (kind === "dns") {
      const parsed = new URL(url);
      const type = parsed.searchParams.get("type") || "A";
      const data = privateDns
        ? (type === "AAAA" ? PRIVATE_AAAA : PRIVATE_A)
        : (type === "AAAA" ? PUBLIC_AAAA : PUBLIC_A);
      return new Response(JSON.stringify(dnsPacket(type, [data])), {
        status: 200, headers: { "content-type": "application/dns-json" },
      });
    }
    if ((init.method || "GET") === "HEAD") {
      return new Response(null, { status: 200, headers: { "x-amz-request-id": "req" } });
    }
    return response(200, { "x-amz-request-id": "req" }, "<ListBucketResult></ListBucketResult>");
  };
  return { calls, fetcher };
}

ok("F041_CLOUD_VALIDATOR_EXPORTED", typeof cloud.validateCloudStorageCandidate === "function");
if (typeof cloud.validateCloudStorageCandidate === "function") {
  const literalCounter = new budget.PhysicalSubrequestCounter({ limit: 50, safetyMargin: 0 });
  const literalTransport = makeCloudTransport();
  const literalValidation = await withFetch(literalTransport.fetcher, () => cloud.validateCloudStorageCandidate({
    provider: "AWS S3", bucket_or_container: "literal", source_hostname: "127.0.0.1",
  }, {
    accounting: literalCounter.contextFor("cloud-literal"), cache: budget.makeDnsCache(), fetchImpl: literalTransport.fetcher,
  }));
  ok("F041_CLOUD_LITERAL_ZERO_DNS_ZERO_HTTP",
    literalCounter.issued === 0 && literalTransport.calls.length === 0
      && literalValidation?.resource_exists === "unknown" && literalValidation?.incomplete === true,
    `issued=${literalCounter.issued}, calls=${JSON.stringify(literalTransport.calls)}, validation=${JSON.stringify(literalValidation)}`);
}

{
  const host = "public-bucket.s3.amazonaws.com";
  const counter = new budget.PhysicalSubrequestCounter({ limit: 50, safetyMargin: 0 });
  const transport = makeCloudTransport({ privateDns: true });
  const result = await withFetch(transport.fetcher, () => cloud.runCloudStorageModule(
    "example.com", cloudModules([host]), {
      accounting: counter.contextFor("cloud-private"), cache: budget.makeDnsCache(), fetchImpl: transport.fetcher,
    },
  ));
  const dnsCalls = transport.calls.filter((call) => call.kind === "dns").length;
  const httpCalls = transport.calls.filter((call) => call.kind === "http").length;
  const validation = result?.candidates?.[0]?.validation;
  ok("F041_CLOUD_PRIVATE_DNS_TWO_DNS_ZERO_HTTP_UNKNOWN_INCOMPLETE",
    dnsCalls === 2 && httpCalls === 0 && counter.issued === 2
      && result?.incomplete === true && validation?.resource_exists === "unknown",
    `dns=${dnsCalls}, http=${httpCalls}, issued=${counter.issued}, result=${JSON.stringify(result)}`);
}

{
  const host = "public-bucket.s3.amazonaws.com";
  const counter = new budget.PhysicalSubrequestCounter({ limit: 50, safetyMargin: 0 });
  const transport = makeCloudTransport();
  const result = await withFetch(transport.fetcher, () => cloud.runCloudStorageModule(
    "example.com", cloudModules([host]), {
      accounting: counter.contextFor("cloud-public"), cache: budget.makeDnsCache(), fetchImpl: transport.fetcher,
    },
  ));
  const dnsCalls = transport.calls.filter((call) => call.kind === "dns").length;
  const httpCalls = transport.calls.filter((call) => call.kind === "http").length;
  ok("F041_CLOUD_PUBLIC_HEAD_GET_SHARED_CACHE_EXACT",
    dnsCalls === 2 && httpCalls === 2 && counter.issued === 4
      && result?.candidates?.[0]?.validation?.resource_exists === true,
    `dns=${dnsCalls}, http=${httpCalls}, issued=${counter.issued}, result=${JSON.stringify(result)}`);
  ok("F041_CLOUD_NO_DOUBLE_CHARGE", counter.issued === transport.calls.length,
    `issued=${counter.issued}, physical=${transport.calls.length}`);
}

{
  const hosts = Array.from({ length: 5 }, (_, index) => `public-bucket-${index + 1}.s3.amazonaws.com`);
  const counter = new budget.PhysicalSubrequestCounter({ limit: 50, safetyMargin: 0 });
  const transport = makeCloudTransport();
  const result = await withFetch(transport.fetcher, () => cloud.runCloudStorageModule(
    "example.com", cloudModules(hosts), {
      accounting: counter.contextFor("cloud-worst"), cache: budget.makeDnsCache(), fetchImpl: transport.fetcher,
    },
  ));
  const dnsCalls = transport.calls.filter((call) => call.kind === "dns").length;
  const httpCalls = transport.calls.filter((call) => call.kind === "http").length;
  ok("F041_CLOUD_WORST_CASE_DERIVED_20",
    cloud.CLOUD_STORAGE_MAX_PHYSICAL_ATTEMPTS === 20
      && dnsCalls === 10 && httpCalls === 10 && counter.issued === 20
      && result?.candidates?.length === 5,
    `constant=${cloud.CLOUD_STORAGE_MAX_PHYSICAL_ATTEMPTS}, dns=${dnsCalls}, http=${httpCalls}, issued=${counter.issued}`);
}

{
  const host = "budget-bucket.s3.amazonaws.com";
  const counter = new budget.PhysicalSubrequestCounter({ limit: 2, safetyMargin: 0 });
  const transport = makeCloudTransport();
  let observed = null;
  try {
    await withFetch(transport.fetcher, () => cloud.runCloudStorageModule(
      "example.com", cloudModules([host]), {
        accounting: counter.contextFor("cloud-limit"), cache: budget.makeDnsCache(), fetchImpl: transport.fetcher,
      },
    ));
  } catch (error) { observed = error; }
  const dnsCalls = transport.calls.filter((call) => call.kind === "dns").length;
  const httpCalls = transport.calls.filter((call) => call.kind === "http").length;
  ok("F041_LIMIT_PLUS_ONE_DENIED_PRE_TRANSPORT_TYPED",
    budget.isSubrequestBudgetExhaustedError(observed)
      && counter.issued === 2 && counter.denied === 1 && dnsCalls === 2 && httpCalls === 0,
    `error=${observed?.code ?? null}, issued=${counter.issued}, denied=${counter.denied}, dns=${dnsCalls}, http=${httpCalls}`);
}

const scanEngineSource = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "scan-engine.js"), "utf8");
ok("F041_SCAN_ENGINE_PASSES_SHARED_DNS_CACHE",
  /runCloudStorageModule\(domain, modules, \{ accounting, signal, cache: dnsCache \}\)/.test(scanEngineSource));
ok("F041_SCAN_ENGINE_USES_DERIVED_CLOUD_ENVELOPE",
  /CLOUD_STORAGE_MAX_PHYSICAL_ATTEMPTS/.test(scanEngineSource)
    && !/MODULE_SUBREQUEST_COST\.cloud_storage\)/.test(scanEngineSource));

globalThis.fetch = realFetch;
AbortSignal.timeout = realTimeout;

console.log(`\nF-041 outbound fail-closed: ${passed} passed, ${failed} failed`);
if (failed) {
  console.error("F-041 outbound fail-closed validation FAILED");
  process.exit(1);
}
console.log("F-041 outbound fail-closed validation passed");
