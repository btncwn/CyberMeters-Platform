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

async function runRouteFixture(fixture) {
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
    freeScanModuleRunners: fixtureRunners(fixture),
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
      : [],
  });
};

try {
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
  eq("ALL-PROBES-FAILED fixture: all four modules remain non-complete",
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
  eq("COMPLETE control: all four modules are scanned",
    completeRoute.body.modules_scanned.length, 4);
  eq("COMPLETE control: explicit coverage is complete",
    completeRoute.body.evidence_coverage.complete, true);
  eq("COMPLETE control: zero findings gets the bounded no-issues state",
    completeRoute.body.preview_state, "no_issues_observed");
  const completeUi = deriveFreeScanPresentation(completeRoute.body);
  eq("COMPLETE route→UI: wording remains limited to completed preview checks",
    completeUi.headline, "No issues observed in the completed preview checks");
  ok("COMPLETE route→UI: UI identifies the bounded score as displayable",
    completeUi.showScore);

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
  });
  eq("zero findings becomes no-issues only when all four modules completed",
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

console.log(`\nFree-scan false-healthy: ${pass}/${pass + fail} passed`);
if (fail) process.exit(1);
console.log("Free-scan false-healthy validation passed");
