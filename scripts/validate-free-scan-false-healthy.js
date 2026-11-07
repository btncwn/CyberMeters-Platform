#!/usr/bin/env node
// Free-Scan False-Healthy P1 — deterministic contract + real route-to-UI trace.
//
// Drives the production billing route with deterministic module runners, passes
// its actual JSON response into the production UI presentation adapter, and
// proves failed/partial evidence cannot become a clean score, grade, module
// completion, or healthy copy.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixtureDir = path.join(root, "scripts", "fixtures");
const workerSrc = path.join(root, "workers", "scan-api", "src");
const frontendSrc = path.join(root, "frontend", "src");

const { billingRoutes } = await import(
  pathToFileURL(path.join(workerSrc, "routes", "billing.js")).href
);
const {
  buildFreeScanEvidence,
  FREE_SCAN_MODULE_STATES,
  resolveFreeScanPreviewState,
} = await import(
  pathToFileURL(path.join(workerSrc, "engines", "free-scan-evidence.js")).href
);
const { deriveFreeScanPresentation } = await import(
  pathToFileURL(path.join(frontendSrc, "lib", "freeScanPresentation.js")).href
);

let pass = 0;
let fail = 0;
const ok = (name, condition, detail = "") => {
  condition ? pass += 1 : fail += 1;
  if (!condition) console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
};
const eq = (name, actual, expected) =>
  ok(name, actual === expected, `got ${JSON.stringify(actual)} expected ${JSON.stringify(expected)}`);

function readFixture(name) {
  return JSON.parse(
    fs.readFileSync(path.join(fixtureDir, `free-scan-${name}.json`), "utf8"),
  );
}

function fixtureRunners(fixture) {
  return Object.fromEntries(
    Object.entries(fixture.module_outcomes).map(([module, outcome]) => [
      module,
      async () => {
        if (outcome.kind === "rejected") throw new Error(outcome.reason);
        return structuredClone(outcome.value);
      },
    ]),
  );
}

async function runRouteFixture(fixture, runners = fixtureRunners(fixture)) {
  const request = new Request("https://app.cybermeters.com/api/free-scan", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "CF-Connecting-IP": "203.0.113.10",
    },
    body: JSON.stringify({ domain: fixture.domain }),
  });
  const response = await billingRoutes({
    request,
    url: new URL(request.url),
    env: {},
    json: (body, status = 200) => Response.json(body, { status }),
    serverError: (_area, error) => Response.json(
      { error: error?.message || "server error" },
      { status: 500 },
    ),
    consumeApiRateLimit: async () => null,
    rateLimitScopeId: async () => "fixture-scope",
    requireAuth: async () => null,
    requireWorkspaceRole: async () => null,
    freeScanModuleRunners: runners,
  });
  return {
    status: response.status,
    body: await response.json(),
  };
}

// The route's pre-probe SSRF resolution remains live. Only its deterministic DoH
// transport is replaced; the free-scan module runners above are separately
// injected at the route's established internal dependency boundary.
const originalFetch = globalThis.fetch;
globalThis.fetch = async (input) => {
  const url = String(input);
  if (!url.startsWith("https://cloudflare-dns.com/dns-query")) {
    throw new Error(`unexpected network request in fixture: ${url}`);
  }
  const type = new URL(url).searchParams.get("type");
  return Response.json({
    Status: 0,
    Answer: type === "A"
      ? [{ name: "example.com", type: 1, data: "93.184.216.34" }]
      : [{ name: "example.com", type: 28, data: "2606:2800:220:1:248:1893:25c8:1946" }],
  });
};

try {
  // www is the website, not the business domain: the route checks the apex.
  const wwwFixture = { ...readFixture("partial"), domain: "https://WWW.Example.com/home" };
  const probedTargets = new Set();
  const wwwRunners = Object.fromEntries(
    Object.entries(fixtureRunners(wwwFixture)).map(([module, run]) => [
      module,
      async (target, ...rest) => { probedTargets.add(target); return run(target, ...rest); },
    ]),
  );
  const www = await runRouteFixture(wwwFixture, wwwRunners);
  eq("WWW input: real route returns 200", www.status, 200);
  eq("WWW input: result is for the apex", www.body.domain, "example.com");
  eq("WWW input: every probe targets the apex", [...probedTargets].join(","), "example.com");

  const failed = await runRouteFixture(readFixture("failed"));
  eq("FAILED fixture: real route returns 200", failed.status, 200);
  eq("FAILED fixture: rejected TLS remains failed", failed.body.module_evidence
    .find((entry) => entry.module === "ssl")?.state, "failed");
  ok("FAILED fixture: TLS is not listed as scanned",
    !failed.body.modules_scanned.includes("ssl"));
  eq("FAILED fixture: score is suppressed", failed.body.score, null);
  eq("FAILED fixture: risk grade is suppressed", failed.body.risk_level, null);
  eq("FAILED fixture: zero findings is not a clean conclusion",
    failed.body.preview_state, "evidence_incomplete");
  eq("FAILED fixture: canonical signal coverage is incomplete",
    failed.body.evidence_coverage.state, "evidence_incomplete");

  const failedUi = deriveFreeScanPresentation(failed.body);
  eq("FAILED route→UI: customer headline is evidence-incomplete",
    failedUi.headline, "Evidence incomplete");
  ok("FAILED route→UI: UI suppresses score", !failedUi.showScore);
  ok("FAILED route→UI: UI does not produce no-issues verdict",
    !failedUi.noIssuesObserved);

  const partial = await runRouteFixture(readFixture("partial"));
  eq("PARTIAL fixture: real route returns 200", partial.status, 200);
  eq("PARTIAL fixture: uncertain headers remain partial", partial.body.module_evidence
    .find((entry) => entry.module === "headers")?.state, "partial");
  ok("PARTIAL fixture: partial is not collapsed into modules_scanned",
    !partial.body.modules_scanned.includes("headers"));
  eq("PARTIAL fixture: canonical coverage remains degraded",
    partial.body.evidence_coverage.state, "monitoring_degraded");
  eq("PARTIAL fixture: zero findings is not a clean conclusion",
    partial.body.preview_state, "evidence_incomplete");

  const partialUi = deriveFreeScanPresentation(partial.body);
  eq("PARTIAL route→UI: customer headline is evidence-incomplete",
    partialUi.headline, "Evidence incomplete");
  eq("PARTIAL route→UI: exact module state reaches presentation",
    partialUi.moduleEvidence.find((entry) => entry.module === "headers")?.state,
    "partial");

  const allProbesFailed = await runRouteFixture(readFixture("all-probes-failed"));
  eq("ALL-PROBES-FAILED fixture: real route returns 200",
    allProbesFailed.status, 200);
  eq("ALL-PROBES-FAILED fixture: all six modules remain non-complete",
    allProbesFailed.body.module_evidence.every(
      (entry) => ["failed", "unavailable", "incomplete"].includes(entry.state),
    ), true);
  eq("ALL-PROBES-FAILED fixture: no module is listed as scanned",
    allProbesFailed.body.modules_scanned.length, 0);
  eq("ALL-PROBES-FAILED fixture: score is null",
    allProbesFailed.body.score, null);
  eq("ALL-PROBES-FAILED fixture: risk level is null",
    allProbesFailed.body.risk_level, null);
  eq("ALL-PROBES-FAILED fixture: preview remains evidence-incomplete",
    allProbesFailed.body.preview_state, "evidence_incomplete");

  const allProbesFailedUi = deriveFreeScanPresentation(allProbesFailed.body);
  eq("ALL-PROBES-FAILED route→UI: customer headline is evidence-incomplete",
    allProbesFailedUi.headline, "Evidence incomplete");
  eq("ALL-PROBES-FAILED route→UI: score is not displayable",
    allProbesFailedUi.showScore, false);
  eq("ALL-PROBES-FAILED route→UI: healthy/no-issues verdict is false",
    allProbesFailedUi.noIssuesObserved, false);
  ok("ALL-PROBES-FAILED route→UI: no healthy, Excellent, score, or no-issues copy",
    !/healthy|excellent|no issues|no-issues|out of 100/i.test([
      allProbesFailedUi.headline,
      allProbesFailedUi.summary,
      allProbesFailedUi.showScore ? String(allProbesFailed.body.score) : "",
    ].join(" ")));

  const completeFixture = readFixture("failed");
  completeFixture.name = "complete";
  completeFixture.module_outcomes.ssl = {
    kind: "fulfilled",
    value: {
      https_available: true,
      https_probe_executed: true,
      http_redirects_to_https: true,
      http_redirect_chain: { http_redirect_validated: true },
    },
  };
  const completeRoute = await runRouteFixture(completeFixture);
  eq("COMPLETE control: all five bounded modules are scanned",
    completeRoute.body.modules_scanned.length, 5);
  eq("COMPLETE control: explicit coverage is complete",
    completeRoute.body.evidence_coverage.complete, true);
  eq("COMPLETE control: deep opt-outs keep the whole-check conclusion incomplete",
    completeRoute.body.preview_state, "evidence_incomplete");
  const completeUi = deriveFreeScanPresentation(completeRoute.body);
  eq("COMPLETE route→UI: wording remains evidence-incomplete",
    completeUi.headline, "Evidence incomplete");
  ok("COMPLETE route→UI: UI suppresses a whole-check score",
    !completeUi.showScore);
  eq("COMPLETE route: exactly eight canonical cards are projected",
    completeRoute.body.cyber_mot_domains.length, 8);
  ok("COMPLETE route: deep cards never fabricate counts",
    completeRoute.body.cyber_mot_domains
      .filter((entry) => ["brand_protection", "cyber_essentials_readiness"].includes(entry.domain_key))
      .every((entry) => entry.headline_count === null));
  ok("COMPLETE route: non-finding deep domains are input_required in the API contract",
    completeRoute.body.cyber_mot_domains
      .filter((entry) => entry.unlock_required && entry.state !== "issue_detected")
      .every((entry) =>
        entry.state === "customer_input_required" && entry.display_state === "input_required"
      ));
  ok("COMPLETE route: anonymous response omits raw module payloads",
    !Object.hasOwn(completeRoute.body, "modules"));
  ok("COMPLETE route: anonymous response omits the full findings collection",
    !Object.hasOwn(completeRoute.body, "findings"));
  ok("COMPLETE route: global highlighted findings stay bounded to two",
    completeRoute.body.shown_findings.length <= 2);
  const exposedFindingIds = new Set([
    ...completeRoute.body.shown_findings.map((finding) => finding.id),
    ...completeRoute.body.cyber_mot_domains.flatMap((domainEntry) =>
      domainEntry.samples
        .filter((sample) => sample.kind === "finding")
        .map((sample) => sample.id)
    ),
  ]);
  eq("COMPLETE route: exposed finding count is derived from actual public detail",
    completeRoute.body.exposed_finding_count, exposedFindingIds.size);
  eq("COMPLETE route: locked_count equals actual total minus exposed",
    completeRoute.body.locked_count,
    completeRoute.body.total_findings - completeRoute.body.exposed_finding_count);
  ok("COMPLETE route: per-domain locked counts are exact",
    completeRoute.body.cyber_mot_domains.every((entry) =>
      !Number.isFinite(entry.headline_count) ||
      entry.locked_count === Math.max(0, entry.headline_count - entry.samples.length)
    ));

  const websiteCard = partial.body.cyber_mot_domains.find(
    (entry) => entry.domain_key === "website_security",
  );
  ok("WAF/edge-uncertain headers never become Website assessed_healthy",
    websiteCard?.state !== "assessed_healthy" &&
    websiteCard?.display_state !== "assessed_healthy");

  const skippedEmailFixture = structuredClone(completeFixture);
  skippedEmailFixture.module_outcomes.email_security = {
    kind: "fulfilled",
    value: { skipped: true, incomplete: true, reason: "preview_provider_unavailable" },
  };
  const skippedEmail = await runRouteFixture(skippedEmailFixture);
  eq("SKIPPED-EMAIL fixture: Email remains incomplete",
    skippedEmail.body.module_evidence.find(
      (entry) => entry.module === "email_security",
    )?.state, "incomplete");
  const skippedEmailFindingIds = [
    ...skippedEmail.body.shown_findings.map((finding) => finding.id),
    ...skippedEmail.body.cyber_mot_domains.flatMap((domainEntry) =>
      domainEntry.samples
        .filter((sample) => sample.kind === "finding")
        .map((sample) => sample.id)
    ),
  ];
  ok("SKIPPED-EMAIL fixture: no SPF/DKIM finding is fabricated",
    skippedEmailFindingIds.every((id) => !/(spf|dkim)/i.test(String(id))));

  const distinct = buildFreeScanEvidence({
    dns: { status: "pending" },
    ssl: { status: "fulfilled", value: { unavailable: true } },
    headers: { status: "fulfilled", value: { incomplete: true } },
    email_security: {
      status: "fulfilled",
      value: {
        spf_evidence_status: "observed",
        dkim_evidence_status: "observed",
        dmarc_state: { evidence_status: "observed" },
      },
    },
    technology_detection: { status: "fulfilled", value: { technologies: [] } },
  });
  eq("attempted remains distinct", distinct.module_evidence[0].state,
    FREE_SCAN_MODULE_STATES.ATTEMPTED);
  eq("unavailable remains distinct", distinct.module_evidence[1].state,
    FREE_SCAN_MODULE_STATES.UNAVAILABLE);
  eq("incomplete remains distinct", distinct.module_evidence[2].state,
    FREE_SCAN_MODULE_STATES.INCOMPLETE);
  eq("completed remains distinct", distinct.module_evidence[3].state,
    FREE_SCAN_MODULE_STATES.COMPLETED);
  eq("zero findings plus incomplete evidence stays incomplete",
    resolveFreeScanPreviewState({
      findingsCount: 0,
      coverage: distinct.evidence_coverage,
      moduleEvidence: distinct.module_evidence,
    }),
    "evidence_incomplete");

  const emailUnavailable = buildFreeScanEvidence({
    dns: { status: "fulfilled", value: {} },
    ssl: { status: "fulfilled", value: {} },
    headers: { status: "fulfilled", value: {} },
    email_security: {
      status: "fulfilled",
      value: {
        spf_evidence_status: "unavailable",
        dkim_evidence_status: "unavailable",
        dmarc_state: { evidence_status: "unavailable" },
      },
    },
    technology_detection: { status: "fulfilled", value: { technologies: [] } },
  });
  eq("fulfilled email wrapper does not hide total probe unavailability",
    emailUnavailable.module_evidence[3].state, "unavailable");
  eq("email probe unavailability reaches canonical signal coverage",
    emailUnavailable.monitoring_states.signals.email_protection.state,
    "signal_unavailable");

  const mixedEmailValue = {};
  Object.defineProperties(mixedEmailValue, {
    spf_evidence_status: { value: "unavailable", enumerable: false },
    dkim_evidence_status: { value: "observed", enumerable: false },
    dmarc_state: {
      value: { evidence_status: "observed" },
      enumerable: false,
    },
  });
  const emailPartial = buildFreeScanEvidence({
    dns: { status: "fulfilled", value: {} },
    ssl: { status: "fulfilled", value: {} },
    headers: { status: "fulfilled", value: {} },
    email_security: { status: "fulfilled", value: mixedEmailValue },
    technology_detection: { status: "fulfilled", value: { technologies: [] } },
  });
  eq("mixed email probe outcomes remain partial",
    emailPartial.module_evidence[3].state, "partial");
  eq("partial projection preserves non-enumerable email evidence",
    emailPartial.modules.email_security.spf_evidence_status, "unavailable");

  const complete = buildFreeScanEvidence({
    dns: { status: "fulfilled", value: {} },
    ssl: { status: "fulfilled", value: {} },
    headers: { status: "fulfilled", value: {} },
    email_security: {
      status: "fulfilled",
      value: {
        spf_evidence_status: "observed",
        dkim_evidence_status: "observed",
        dmarc_state: { evidence_status: "observed" },
      },
    },
    technology_detection: { status: "fulfilled", value: { technologies: [] } },
  });
  eq("zero findings becomes no-issues only when all six bounded modules completed",
    resolveFreeScanPreviewState({
      findingsCount: 0,
      coverage: complete.evidence_coverage,
      moduleEvidence: complete.module_evidence,
    }),
    "no_issues_observed");

  console.log("\nReal route-to-UI traces:");
  console.log(JSON.stringify({
    failed: {
      module_evidence: failed.body.module_evidence,
      modules_scanned: failed.body.modules_scanned,
      coverage: failed.body.evidence_coverage,
      preview_state: failed.body.preview_state,
      ui_headline: failedUi.headline,
    },
    partial: {
      module_evidence: partial.body.module_evidence,
      modules_scanned: partial.body.modules_scanned,
      coverage: partial.body.evidence_coverage,
      preview_state: partial.body.preview_state,
      ui_headline: partialUi.headline,
    },
    all_probes_failed: {
      module_evidence: allProbesFailed.body.module_evidence,
      modules_scanned: allProbesFailed.body.modules_scanned,
      score: allProbesFailed.body.score,
      risk_level: allProbesFailed.body.risk_level,
      preview_state: allProbesFailed.body.preview_state,
      ui_headline: allProbesFailedUi.headline,
      ui_show_score: allProbesFailedUi.showScore,
      ui_no_issues_observed: allProbesFailedUi.noIssuesObserved,
    },
  }, null, 2));
} finally {
  globalThis.fetch = originalFetch;
}

// ── Real module-to-route flow (no injected module runners) ──────────────────
// The fixtures above inject finished module outputs. These cases inject none:
// billingRoutes runs its own default runners (the production DNS, HTTPS,
// headers, email and technology modules), its own evidence classification and
// its own preview rendering. Only the transport underneath is replaced — DoH
// answers and the target's HTTP/HTTPS responses — so a regression anywhere from
// a module's failure handling to the response is visible here. Any request
// outside the fixture's DoH providers or the fixture host fails the case.
{
  const HOST = "route-fixture.example.com";
  const ADDRESS = "93.184.216.34";
  const DOH = new Map([
    ["cloudflare-dns.com", "/dns-query"],
    ["dns.google", "/resolve"],
    ["dns.quad9.net", "/dns-query"],
  ]);
  const TYPE_CODES = { A: 1, AAAA: 28 };
  const soa = [{ name: "example.com", type: 6, TTL: 300, data: "ns.example.com. hostmaster.example.com. 1 7200 3600 1209600 300" }];

  function dohAnswer(url) {
    const name = String(url.searchParams.get("name") || "").replace(/\.$/, "").toLowerCase();
    const type = String(url.searchParams.get("type") || "").toUpperCase();
    const question = [{ name, type: TYPE_CODES[type] ?? 0 }];
    if (name === HOST && type === "A") {
      return { Status: 0, TC: false, Question: question, Answer: [{ name: HOST, type: 1, TTL: 60, data: ADDRESS }] };
    }
    // The host exists but publishes nothing else (NODATA); every other name,
    // www.<host> included, is NXDOMAIN, so no sibling host is ever contacted.
    return { Status: name === HOST ? 0 : 3, TC: false, Question: question, Answer: [], Authority: soa };
  }

  const refused = () => { throw new TypeError("Network connection lost."); };
  const page = (status, headers = {}) => new Response(
    status >= 500 ? "<html><body>Service Unavailable</body></html>" : "<html><head><title>fixture</title></head><body>ok</body></html>",
    { status, headers: { "content-type": "text/html; charset=utf-8", server: "nginx", ...headers } },
  );
  const SECURE_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
  };

  // origin(protocol, method) answers one request to the fixture host.
  const ORIGINS = {
    refused: () => refused(),
    origin503: () => page(503),
    httpsRefusedHttp200: (protocol) => (protocol === "https:" ? refused() : page(200)),
    observed: (protocol) => (protocol === "http:"
      ? new Response(null, { status: 301, headers: { location: `https://${HOST}/`, server: "nginx" } })
      : page(200, SECURE_HEADERS)),
  };

  async function runRealRoute(originName) {
    const origin = ORIGINS[originName];
    const unexpected = [];
    const targetRequests = [];
    const savedFetch = globalThis.fetch;
    globalThis.fetch = async (input, init = {}) => {
      const raw = typeof input === "string" ? input : (input?.url ?? String(input));
      const url = new URL(raw);
      const method = String(init.method || (typeof input === "object" && input?.method) || "GET").toUpperCase();
      if (DOH.has(url.hostname)) {
        if (url.protocol !== "https:" || url.pathname !== DOH.get(url.hostname) || method !== "GET") {
          unexpected.push(`${method} ${raw}`);
          throw new Error(`unexpected DoH request in real-route fixture: ${method} ${raw}`);
        }
        return Response.json(dohAnswer(url));
      }
      if (url.hostname === HOST && ["http:", "https:"].includes(url.protocol) && ["GET", "HEAD"].includes(method)) {
        targetRequests.push(`${method} ${url.protocol}//${url.host}${url.pathname}`);
        return origin(url.protocol, method);
      }
      unexpected.push(`${method} ${raw}`);
      throw new Error(`unexpected network request in real-route fixture: ${method} ${raw}`);
    };
    try {
      const request = new Request("https://app.cybermeters.com/api/free-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json", "CF-Connecting-IP": "203.0.113.10" },
        body: JSON.stringify({ domain: HOST }),
      });
      const rateCalls = [];
      const response = await billingRoutes({
        request,
        url: new URL(request.url),
        env: {},
        json: (body, status = 200) => Response.json(body, { status }),
        serverError: (_area, error) => Response.json({ error: error?.message || "server error" }, { status: 500 }),
        consumeApiRateLimit: async (_env, scopes, operation, limit, windowSeconds, options) => {
          rateCalls.push({ scope: scopes?.[0]?.scope, operation, limit, windowSeconds, failClosed: options?.failClosed === true });
          return null;
        },
        rateLimitScopeId: async (kind, value) => `${kind}:${value}`,
        requireAuth: async () => null,
        requireWorkspaceRole: async () => null,
        // Deliberately NO freeScanModuleRunners and NO freeScanDnsQuery.
      });
      const body = await response.json();
      return { status: response.status, body, unexpected, targetRequests, rateCalls };
    } finally {
      globalThis.fetch = savedFetch;
    }
  }

  const evidenceOf = (body, module) => body.module_evidence?.find((entry) => entry.module === module);
  const cardOf = (body, key) => body.security_domains?.find((entry) => entry.domain_key === key);
  const exposedIds = (body) => [
    ...(body.shown_findings || []).map((finding) => finding.id),
    ...(body.security_domains || []).flatMap((entry) =>
      (entry.samples || []).filter((sample) => sample.kind === "finding").map((sample) => sample.id)),
  ].map(String);
  const HEADER_FINDING = /^(header_|csp_|security_headers_|dse_hsts)/;
  const HTTPS_FINDING = /(https|ssl|tls|certificate|redirect)/i;
  const TECH_FINDING = /(technolog|tech_|server_|powered_by|version)/i;
  const HTTP_MODULES = ["ssl", "headers", "technology_detection"];

  function commonRouteContract(label, run) {
    eq(`REAL ${label}: route admits the public target (200)`, run.status, 200);
    eq(`REAL ${label}: no request escapes the fixture`, run.unexpected.join(" | "), "");
    ok(`REAL ${label}: the real HTTP modules actually probed the target`,
      run.targetRequests.some((entry) => entry.includes(`https://${HOST}/`))
        && run.targetRequests.some((entry) => entry.includes(`http://${HOST}/`)),
      run.targetRequests.join(" | "));
    eq(`REAL ${label}: all five bounded modules attempted`,
      [...(run.body.modules_attempted || [])].sort().join(","),
      "dns,email_security,headers,ssl,technology_detection");
    eq(`REAL ${label}: admission ran the three fail-closed limiters in order`,
      run.rateCalls.map((call) => `${call.scope}:${call.operation}:${call.limit}:${call.failClosed}`).join(","),
      "ip:free_scan:5:true,domain:free_scan_domain:3:true,global:free_scan_global:500:true");
    eq(`REAL ${label}: score is null`, run.body.score, null);
    eq(`REAL ${label}: risk level is null`, run.body.risk_level, null);
    eq(`REAL ${label}: nothing is persisted`, run.body.persistence, "none");
    ok(`REAL ${label}: preview never reports no_issues_observed`,
      run.body.preview_state !== "no_issues_observed", run.body.preview_state);
    ok(`REAL ${label}: every non-completed module carries a closed-set reason`,
      run.body.module_evidence.every((entry) =>
        entry.state === "completed" ? !entry.reason : typeof entry.reason === "string" && entry.reason.length > 0),
      JSON.stringify(run.body.module_evidence.map((entry) => [entry.module, entry.state, entry.reason])));
    eq(`REAL ${label}: modules_scanned is exactly the completed modules`,
      [...run.body.modules_scanned].sort().join(","),
      run.body.module_evidence.filter((entry) => entry.state === "completed").map((entry) => entry.module).sort().join(","));
    const ui = deriveFreeScanPresentation(run.body);
    ok(`REAL ${label} route→UI: no score and no no-issues verdict`, !ui.showScore && !ui.noIssuesObserved);
    return ui;
  }

  function websiteNotHealthy(label, body) {
    for (const key of ["website_security", "certificates_trust"]) {
      const card = cardOf(body, key);
      eq(`REAL ${label}: ${key} is evidence_insufficient`, card?.state, "evidence_insufficient");
      ok(`REAL ${label}: ${key} never displays assessed_healthy`,
        card?.display_state !== "assessed_healthy", card?.display_state);
    }
    eq(`REAL ${label}: website signal is evidence_incomplete`,
      body.monitoring_states?.signals?.website_security?.state, "evidence_incomplete");
  }

  // 1. Admitted target; every HTTP and HTTPS connection is refused.
  const refusedRun = await runRealRoute("refused");
  const refusedUi = commonRouteContract("REFUSED", refusedRun);
  eq("REAL REFUSED: HTTPS module incomplete because no probe came back",
    `${evidenceOf(refusedRun.body, "ssl")?.state}/${evidenceOf(refusedRun.body, "ssl")?.reason}`,
    "incomplete/https_probe_not_executed");
  eq("REAL REFUSED: headers module incomplete because no probe came back",
    `${evidenceOf(refusedRun.body, "headers")?.state}/${evidenceOf(refusedRun.body, "headers")?.reason}`,
    "incomplete/probe_not_executed");
  eq("REAL REFUSED: technology module incomplete because no origin was observed",
    `${evidenceOf(refusedRun.body, "technology_detection")?.state}/${evidenceOf(refusedRun.body, "technology_detection")?.reason}`,
    "incomplete/origin_not_observed");
  ok("REAL REFUSED: DNS and email still complete (independent evidence kept)",
    evidenceOf(refusedRun.body, "dns")?.state === "completed"
      && evidenceOf(refusedRun.body, "email_security")?.state === "completed");
  ok("REAL REFUSED: no HTTP module is listed as scanned",
    HTTP_MODULES.every((module) => !refusedRun.body.modules_scanned.includes(module)),
    refusedRun.body.modules_scanned.join(","));
  websiteNotHealthy("REFUSED", refusedRun.body);
  ok("REAL REFUSED: no header, HTTPS or technology finding is fabricated",
    exposedIds(refusedRun.body).every((id) => !HEADER_FINDING.test(id) && !HTTPS_FINDING.test(id) && !TECH_FINDING.test(id)),
    exposedIds(refusedRun.body).join(","));
  const refusedCopy = `${refusedUi.headline} ${refusedUi.summary}`;
  ok("REAL REFUSED route→UI: copy never calls the result healthy or issue-free",
    !/no issues|excellent|out of 100/i.test(refusedCopy) && !/(?<!not a )healthy/i.test(refusedCopy),
    refusedCopy);

  // 2. Origin answers 503 on every protocol: TLS transport is observed, content is not.
  const errorRun = await runRealRoute("origin503");
  commonRouteContract("ORIGIN-5XX", errorRun);
  // ssl-scan.js only reaches http_redirect_* when https_available === true, i.e.
  // an origin answered over TLS. A failed-TLS reading would be one of the
  // https_* transport reasons instead.
  eq("REAL ORIGIN-5XX: HTTPS transport observed; only the redirect decision is withheld",
    `${evidenceOf(errorRun.body, "ssl")?.state}/${evidenceOf(errorRun.body, "ssl")?.reason}`,
    "incomplete/http_redirect_not_observed");
  ok("REAL ORIGIN-5XX: TLS is not labelled failed, unavailable or not executed",
    !/^https_/.test(String(evidenceOf(errorRun.body, "ssl")?.reason)), evidenceOf(errorRun.body, "ssl")?.reason);
  eq("REAL ORIGIN-5XX: headers state the origin served no usable page",
    `${evidenceOf(errorRun.body, "headers")?.state}/${evidenceOf(errorRun.body, "headers")?.reason}`,
    "incomplete/origin_error_no_serviceable_response");
  eq("REAL ORIGIN-5XX: technology states the origin served no usable page",
    `${evidenceOf(errorRun.body, "technology_detection")?.state}/${evidenceOf(errorRun.body, "technology_detection")?.reason}`,
    "incomplete/origin_error_no_serviceable_response");
  websiteNotHealthy("ORIGIN-5XX", errorRun.body);
  ok("REAL ORIGIN-5XX: no header, HTTPS or technology finding read off an error page",
    exposedIds(errorRun.body).every((id) => !HEADER_FINDING.test(id) && !HTTPS_FINDING.test(id) && !TECH_FINDING.test(id)),
    exposedIds(errorRun.body).join(","));

  // 3. HTTPS refused, plain HTTP serves the page.
  const httpOnlyRun = await runRealRoute("httpsRefusedHttp200");
  commonRouteContract("HTTPS-REFUSED/HTTP-200", httpOnlyRun);
  eq("REAL HTTPS-REFUSED/HTTP-200: HTTPS remains unobserved, not failed",
    `${evidenceOf(httpOnlyRun.body, "ssl")?.state}/${evidenceOf(httpOnlyRun.body, "ssl")?.reason}`,
    "incomplete/https_probe_not_executed");
  eq("REAL HTTPS-REFUSED/HTTP-200: headers observed over HTTP stay completed",
    evidenceOf(httpOnlyRun.body, "headers")?.state, "completed");
  ok("REAL HTTPS-REFUSED/HTTP-200: the observed headers module is listed as scanned, HTTPS is not",
    httpOnlyRun.body.modules_scanned.includes("headers") && !httpOnlyRun.body.modules_scanned.includes("ssl"),
    httpOnlyRun.body.modules_scanned.join(","));
  ok("REAL HTTPS-REFUSED/HTTP-200: a real header finding from the observed page survives",
    exposedIds(httpOnlyRun.body).some((id) => HEADER_FINDING.test(id)),
    exposedIds(httpOnlyRun.body).join(","));
  ok("REAL HTTPS-REFUSED/HTTP-200: no HTTPS/TLS/HSTS finding is manufactured from an unobserved channel",
    exposedIds(httpOnlyRun.body).every((id) => !HTTPS_FINDING.test(id) && !/hsts|strict_transport/i.test(id)),
    exposedIds(httpOnlyRun.body).join(","));
  websiteNotHealthy("HTTPS-REFUSED/HTTP-200", httpOnlyRun.body);

  // 4. Positive control: a well-behaved origin is observed, not forced incomplete.
  const observedRun = await runRealRoute("observed");
  commonRouteContract("OBSERVED control", observedRun);
  for (const module of HTTP_MODULES) {
    eq(`REAL OBSERVED control: ${module} completes on a real origin response`,
      evidenceOf(observedRun.body, module)?.state, "completed");
  }
  eq("REAL OBSERVED control: every bounded module is scanned",
    [...observedRun.body.modules_scanned].sort().join(","),
    "dns,email_security,headers,ssl,technology_detection");
  eq("REAL OBSERVED control: website signal is monitored, not incomplete",
    observedRun.body.monitoring_states?.signals?.website_security?.state, "monitoring_healthy");
  ok("REAL OBSERVED control: website card is assessed rather than evidence_insufficient",
    cardOf(observedRun.body, "website_security")?.state !== "evidence_insufficient",
    cardOf(observedRun.body, "website_security")?.state);
  ok("REAL OBSERVED control: no missing-header finding for headers the origin sent",
    exposedIds(observedRun.body).every((id) => !/^header_missing_/.test(id)),
    exposedIds(observedRun.body).join(","));

  console.log("\nReal module-to-route traces:");
  console.log(JSON.stringify(Object.fromEntries([
    ["refused", refusedRun], ["origin_5xx", errorRun], ["https_refused_http_200", httpOnlyRun], ["observed", observedRun],
  ].map(([name, run]) => [name, {
    status: run.status,
    module_evidence: run.body.module_evidence.map(({ module, state, reason }) => ({ module, state, ...(reason ? { reason } : {}) })),
    modules_scanned: run.body.modules_scanned,
    website_security: cardOf(run.body, "website_security")?.state,
    certificates_trust: cardOf(run.body, "certificates_trust")?.state,
    exposed_finding_ids: exposedIds(run.body),
    target_requests: run.targetRequests,
  }])), null, 2));
}

// The public free tools (/tools/*) share this lane: same anonymous audience,
// same honesty rule. Their gate and engine tests run here.
{
  const { spawnSync } = await import("node:child_process");
  const tools = spawnSync(process.execPath, ["--test", "workers/scan-api/test/free-tools.test.js"],
    { cwd: root, stdio: "inherit", timeout: 180000 });
  ok("free tools: gate, limits, cache, deferral, share and engine tests", tools.status === 0, `exit ${tools.status}`);
}

// ── Every incomplete module states why (S3-8, 21 Oct 2026) ──────────────────
// module_evidence carries a closed-set reason code for every module that did not
// complete, the customer copy table words every code, and a module's own error
// text never reaches the response.
{
  const evidenceModule = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "free-scan-evidence.js")).href);
  const { CUSTOMER_CODE_COPY } = await import(pathToFileURL(path.join(root, "frontend", "src", "lib", "customerReasonText.js")).href);
  const { buildFreeScanEvidence: build, FREE_SCAN_MODULE_REASONS } = evidenceModule;
  const unmapped = FREE_SCAN_MODULE_REASONS.filter((code) => !Object.hasOwn(CUSTOMER_CODE_COPY, code));
  ok("every free-scan reason code has customer copy", unmapped.length === 0, unmapped.join(","));
  const fulfilled = (value) => ({ status: "fulfilled", value });
  const evidence = build({
    dns: fulfilled({ records: {} }),
    ssl: fulfilled({ incomplete: true, incomplete_reason: "https_origin_timeout" }),
    headers: fulfilled({ accessible: true, validation_uncertain: true, present: [], missing: [] }),
    email_security: { status: "rejected", reason: Object.assign(new Error("secret internal detail at /var/x"), { code: "SOMETHING_INTERNAL" }) },
    technology_detection: fulfilled({ incomplete: true, incomplete_reason: "origin_access_restricted", error: "raw upstream text" }),
  });
  const byModule = Object.fromEntries(evidence.module_evidence.map((e) => [e.module, e]));
  eq("timed-out HTTPS states https_origin_timeout", byModule.ssl.reason, "https_origin_timeout");
  eq("bot-protected headers state validation_uncertain", byModule.headers.reason, "validation_uncertain");
  eq("restricted technology states origin_access_restricted", byModule.technology_detection.reason, "origin_access_restricted");
  eq("a thrown module states check_failed, never its error text", byModule.email_security.reason, "check_failed");
  ok("a completed module carries no reason", !("reason" in byModule.dns), JSON.stringify(byModule.dns));
  ok("every non-completed module carries a closed-set reason",
    evidence.module_evidence.every((e) => e.state === "completed" ? !e.reason : FREE_SCAN_MODULE_REASONS.includes(e.reason)),
    JSON.stringify(evidence.module_evidence.map((e) => [e.module, e.state, e.reason])));
  ok("no module error text reaches module_evidence", !/secret internal|raw upstream|SOMETHING_INTERNAL/.test(JSON.stringify(evidence.module_evidence)));
  eq("an unfinished module at the deadline states the deadline",
    evidenceModule.freeScanModuleReason("incomplete", { status: "rejected", reason: { code: "free_scan_deadline_exhausted" } }), "free_scan_deadline_exhausted");
}

console.log(`\nFree-scan false-healthy: ${pass}/${pass + fail} passed`);
if (fail) process.exit(1);
console.log("Free-scan false-healthy validation passed");
