#!/usr/bin/env node
//
// Website Security — is a website actually served on this domain?
// A conclusive home-page 404/410 that stayed on the domain becomes a
// score-neutral observation with a canonical next step. Anything that is not a
// conclusive answer (bot challenge, 401/403/429, 5xx, unassessed module, a 2xx
// on any checked home-page path, a redirect to another site) raises nothing.
//
// Drives the REAL emitter, registry, eight-domain attribution, snapshot and
// PDF renderer, and kills two guard mutations in-process. Node 24+.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const enginePath = (f) => path.join(root, "workers", "scan-api", "src", "engines", f);
const eng = (f) => pathToFileURL(enginePath(f)).href;
const W = await import(eng("website-availability.js"));
const { resolveRemediation } = await import(eng("remediation-registry.js"));
const { CYBER_MOT_DOMAINS } = await import(eng("cyber-mot-domains.js"));
const { composeSnapshot } = await import(eng("report-snapshot.js"));
const { buildScanReportPdf } = await import(eng("pdf.js"));

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

// ── Fixtures: headers module results (the shape headers-scan.js returns) ─────
const DOMAIN = "shop.example";
const path404 = (label, status = 404, finalUrl = `https://${DOMAIN}/`, method = "GET") =>
  ({ label, requested_url: finalUrl, method, status: "ok", final_url: finalUrl, status_code: status, redirect_chain: [], headers_observed: {} });
const headers = (over = {}) => ({
  accessible: true,
  headers_assessed: true,
  status_code: 404,
  original_url: `https://${DOMAIN}`,
  response_url: `https://${DOMAIN}/`,
  redirect_count: 1,
  final_https: true,
  validation_uncertain: false,
  bot_protection_signals: [],
  raw_capture: { status: 404, final_url: `https://${DOMAIN}/`, headers_snapshot: { "powered-by": "Shopify", server: "cloudflare" } },
  checked_paths: [
    path404("/"),
    path404("final_canonical_url"),
    path404("www_variant", 404, `https://www.${DOMAIN}/`, "HEAD"),
  ],
  ...over,
});
const run = (h, domain = DOMAIN) => W.homePageAvailabilityFindings({ headers: h }, { domain, checkedAt: "2026-10-11T15:00:00.000Z" });

// ── 1. Emitter: conclusive "not found" ──────────────────────────────────────
{
  const [finding, ...rest] = run(headers());
  ok("Shopify 404 on every home-page path raises exactly one observation", Boolean(finding) && rest.length === 0);
  eq("observation id is the exported canonical id", finding?.id, W.HOME_PAGE_NOT_FOUND_ID);
  ok("observation is score-neutral", finding?.finding_type === "observation" && finding?.score_impact === 0);
  ok("provider is attributed from the response's own headers", finding?.evidence?.hosting_provider === "Shopify"
    && /Shopify/.test(finding.title) && /Shopify/.test(finding.description));
  ok("wording states what was observed — no takeover or attack claim",
    !/takeover|hijack|attack|malicious|compromis|phish/i.test(`${finding?.title} ${finding?.description}`));
  eq("evidence keeps the checked home-page paths and their answers",
    finding?.evidence?.checked_paths?.map((p) => [p.label, p.status_code]),
    [["/", 404], ["final_canonical_url", 404], ["www_variant", 404]]);
  ok("evidence records the observed answer and time", finding?.evidence?.observed_value === "HTTP 404"
    && finding?.evidence?.checked_at === "2026-10-11T15:00:00.000Z");

  const gone = run(headers({
    status_code: 410,
    raw_capture: { headers_snapshot: { server: "nginx" } },
    checked_paths: [path404("/", 410)],
  }));
  ok("410 (gone) raises the observation without inventing a provider",
    gone.length === 1 && gone[0].evidence.hosting_provider === null && /410 \(gone\)/.test(gone[0].description)
    && !/Shopify/.test(`${gone[0].title} ${gone[0].description}`));
  ok("www host counts as the same site",
    run(headers({ response_url: `https://www.${DOMAIN}/`, checked_paths: [path404("/", 404, `https://www.${DOMAIN}/`)] })).length === 1);
}

// ── 2. Never raised on inconclusive or contradicting evidence ───────────────
{
  const none = (name, h, domain) => eq(name, run(h, domain), []);
  none("a served home page (200) raises nothing", headers({ status_code: 200, checked_paths: [path404("/", 200)] }));
  none("any 2xx on a checked home-page path means a website exists",
    headers({ checked_paths: [path404("/"), path404("www_variant", 200, `https://www.${DOMAIN}/`, "HEAD")] }));
  none("access-restricted 403 is not a conclusive answer", headers({ status_code: 403, checked_paths: [path404("/", 403)] }));
  none("429 is not a conclusive answer", headers({ status_code: 429, checked_paths: [path404("/", 429)] }));
  {
    const fiveXx = run(headers({ accessible: false, headers_assessed: false, status_code: 503, checked_paths: [{ ...path404("/", 503), label: "origin_error_response", status: "origin_error" }] }));
    ok("an origin 5xx is never read as 'not found'", !fiveXx.some((f) => f.id === W.HOME_PAGE_NOT_FOUND_ID));
  }
  none("a bot challenge never raises it", headers({ validation_uncertain: true, bot_protection_signals: ["cf-mitigated"] }));
  none("an unassessed headers module never raises it", headers({ headers_assessed: false }));
  none("a redirect to another site is never blamed on this domain",
    headers({ response_url: "https://elsewhere.example/", checked_paths: [path404("/", 404, "https://elsewhere.example/")] }));
  none("a checked path that ended on another site blocks the conclusion",
    headers({ checked_paths: [path404("/"), path404("final_canonical_url", 404, "https://other.example/")] }));
  none("no checked home-page path means no conclusion", headers({ checked_paths: [] }));
  none("a missing headers module raises nothing", undefined);
  none("a missing domain raises nothing", headers(), "");
}

// ── 2b. Website DOWN: every home-page answer was an edge error or origin 5xx ─
{
  const edge = (proto, code) => ({ label: "origin_not_observed", requested_url: `${proto}://${DOMAIN}`, method: "GET",
    status: "cloudflare_edge_error", final_url: `${proto}://${DOMAIN}`, status_code: code, redirect_chain: [], headers_observed: {} });
  const originError = (proto, code) => ({ label: "origin_error_response", requested_url: `${proto}://${DOMAIN}`, method: "GET",
    status: "origin_error", final_url: `${proto}://${DOMAIN}`, status_code: code, redirect_chain: [], headers_observed: {} });
  const down = (paths, over = {}) => run(headers({ accessible: false, headers_assessed: false, status_code: paths[0]?.status_code ?? null,
    validation_uncertain: false, bot_protection_signals: [], checked_paths: paths, ...over }));

  const [finding, ...rest] = down([edge("https", 525), edge("http", 525)]);
  ok("HTTPS and HTTP both answered by Cloudflare 525 raises one 'website returned an error' observation",
    finding?.id === W.HOME_PAGE_UNAVAILABLE_ID && rest.length === 0);
  ok("unavailable observation is score-neutral", finding?.finding_type === "observation" && finding?.score_impact === 0);
  ok("the edge code is explained in plain words",
    /HTTP 525: the secure \(SSL\) connection between Cloudflare and the website's server failed/.test(finding?.description || ""));
  ok("wording reports this scan, never a permanent conclusion",
    /In this scan/.test(finding?.description || "") && /short outage/.test(finding?.description || "")
      && !/takeover|hijack|attack|malicious|compromis|phish|removed|gone/i.test(`${finding?.title} ${finding?.description}`));
  ok("evidence keeps every checked request and its answer",
    JSON.stringify(finding?.evidence?.checked_paths?.map((p) => [p.requested_url, p.status_code]))
      === JSON.stringify([[`https://${DOMAIN}`, 525], [`http://${DOMAIN}`, 525]]));
  ok("an origin 5xx on every request is also reported",
    down([originError("https", 503), originError("http", 503)])[0]?.id === W.HOME_PAGE_UNAVAILABLE_ID);

  const none = (name, result) => eq(name, result, []);
  none("one served answer means the site is not down",
    down([edge("https", 525), { ...path404("/", 200, `http://${DOMAIN}/`), requested_url: `http://${DOMAIN}` }]));
  none("a probe that never produced an answer raises nothing", down([]));
  none("HTTP-only failures without an HTTPS answer raise nothing", down([edge("http", 521)]));
  none("an answer from another site is never blamed on this domain",
    down([{ ...edge("https", 525), requested_url: "https://elsewhere.example" }]));
  none("a 4xx edge answer is not 'down'", down([{ ...edge("https", 403), status_code: 403 }]));
  none("an assessed origin is never 'down'", down([edge("https", 525)], { accessible: true, headers_assessed: true }));
}

// ── 3. Canonical remediation and eight-domain attribution ───────────────────
{
  const r = resolveRemediation({ finding_type: W.HOME_PAGE_NOT_FOUND_ID });
  ok("resolves to exactly the canonical home-page remediation",
    r.status === "resolved" && r.remediation_id === "web.homepage.not_served" && r.domain_key === "website_security");
  ok("remediation is verifiable by CyberMeters re-observation", r.verification_method === "https_recheck");
  ok("remediation offers both outcomes: restore the site or retire its records",
    /reconnect it to your hosting provider/.test(r.recommended_action) && /remove the root and www records/.test(r.recommended_action));
  const down = resolveRemediation({ finding_type: W.HOME_PAGE_UNAVAILABLE_ID });
  ok("the down observation resolves to its own canonical remediation",
    down.status === "resolved" && down.remediation_id === "web.homepage.unavailable" && down.domain_key === "website_security"
      && down.verification_method === "https_recheck");
  const website = CYBER_MOT_DOMAINS.find((d) => d.domain_key === "website_security");
  ok("observation belongs to the Website Security domain", website.match({ id: W.HOME_PAGE_NOT_FOUND_ID }) === true);
}

// ── 4. Engine wiring (pushed after computeScore, never fatal) ───────────────
{
  const src = fs.readFileSync(enginePath("scan-engine.js"), "utf8");
  const signIn = src.indexOf("signInPageFindings(modules.page_discovery");
  const homePage = src.indexOf("homePageAvailabilityFindings(modules, { domain");
  const compute = src.indexOf("computeScore(");
  ok("scan engine emits the observation after the score is computed",
    compute > -1 && signIn > compute && homePage > signIn);
  ok("emission is wrapped so an observation can never break a scan",
    /try \{\s*for \(const f of homePageAvailabilityFindings\(modules, \{ domain, checkedAt: new Date\(now\(\)\)\.toISOString\(\) \}\)\) findings\.push\(f\);\s*\} catch/.test(src));
}

// ── 5. Snapshot and PDF carry the customer step, not a placeholder ──────────
{
  const [finding] = run(headers());
  const report = {
    scan_id: "scan-home", domain_id: "dom-home", domain: DOMAIN, status: "completed",
    completed_at: "2026-10-11T15:00:05.000Z", cyber_metrics_score: 80, risk_level: "medium",
    findings: [finding], recommendations: [],
    modules: { headers: headers() },
    scan_quality: { status: "complete", modules_skipped: [], warnings: [] },
  };
  const snapshot = composeSnapshot({
    snapshotId: "snap-home", workspaceId: "ws-home", domainId: "dom-home", scanId: "scan-home", domain: DOMAIN,
    report, cyberEssentials: null, ceReadiness: null, caseRows: [], questionSetVersions: [],
    certificateLifecycleRecords: [], attackSurfaceLifecycleRecords: [], supersedesSnapshotId: null,
    builtAt: "2026-10-11T15:00:05.000Z",
  });
  const item = snapshot.observations.find((o) => o.finding_id === W.HOME_PAGE_NOT_FOUND_ID);
  ok("snapshot keeps it an observation with the canonical remediation", Boolean(item)
    && item.remediation_id === "web.homepage.not_served"
    && item.remediation_title === "Restore the website or retire its DNS records");
  ok("snapshot never lists it as a scored finding",
    !snapshot.observed_findings.some((f) => f.finding_id === W.HOME_PAGE_NOT_FOUND_ID));
  const pdf = new TextDecoder("latin1").decode(buildScanReportPdf(
    { id: "scan-home", domain: DOMAIN },
    { snapshot, row: { id: "snap-home" }, integrity: { verified: true } },
  ));
  ok("PDF shows the customer step", pdf.includes("Restore the website or retire its DNS records"));
  ok("PDF has no placeholder action text", !pdf.includes("No linked action text"));
}

// ── 6. Guard mutations are killed (in-process, isolated module copies) ──────
{
  const source = fs.readFileSync(enginePath("website-availability.js"), "utf8");
  const mutate = async (before, after) => {
    if (source.split(before).length !== 2) throw new Error(`mutation anchor not unique: ${before}`);
    return import(`data:text/javascript;base64,${Buffer.from(source.replace(before, after)).toString("base64")}`);
  };
  const twoXx = await mutate(
    "NOT_FOUND_STATUSES.has(Number(path.status_code)) &&",
    "true &&",
  );
  ok("MUTANT any-2xx guard removed is killed",
    twoXx.homePageAvailabilityFindings({ headers: headers({ checked_paths: [path404("/"), path404("www_variant", 200, `https://www.${DOMAIN}/`, "HEAD")] }) }, { domain: DOMAIN }).length === 1);
  const accessRestricted = await mutate(
    "const NOT_FOUND_STATUSES = new Set([404, 410]);",
    "const NOT_FOUND_STATUSES = new Set([404, 410, 403]);",
  );
  ok("MUTANT 403 admitted as not-found is killed",
    accessRestricted.homePageAvailabilityFindings({ headers: headers({ status_code: 403, checked_paths: [path404("/", 403)] }) }, { domain: DOMAIN }).length === 1);
  const offSite = await mutate("if (!sameSite(finalUrl, root)) return [];", "");
  const mixed = await mutate(
    "const failing = paths.every((path) =>",
    "const failing = paths.some((path) =>",
  );
  ok("MUTANT one-error-is-enough is killed",
    mixed.homePageAvailabilityFindings({ headers: headers({ accessible: false, headers_assessed: false, checked_paths: [
      { label: "origin_not_observed", requested_url: `https://${DOMAIN}`, status: "cloudflare_edge_error", status_code: 525 },
      { label: "/", requested_url: `http://${DOMAIN}`, status: "ok", status_code: 200 },
    ] }) }, { domain: DOMAIN }).length === 1);
  ok("MUTANT off-site redirect guard removed is killed",
    offSite.homePageAvailabilityFindings({ headers: headers({ response_url: "https://elsewhere.example/", checked_paths: [path404("/", 404)] }) }, { domain: DOMAIN }).length === 1);
}

console.log(`\nWebsite home-page availability: ${pass}/${pass + fail} passed`);
if (fail) { console.error("website home-page availability validation FAILED"); process.exit(1); }
console.log("website home-page availability validation passed");
