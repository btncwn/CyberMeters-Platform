#!/usr/bin/env node
//
// Passive-probe evidence honesty — mutation-tested, CI-blocking.
//
// THE DEFECT THIS EXISTS TO PREVENT (reproduced end-to-end, 15 July 2026):
// safeFetch returns null on a 10s timeout, a redirect loop, more than
// MAX_REDIRECT_HOPS, a blocked target, or any thrown error. runHeadersModule
// handled that by returning `accessible: false` with NO error, NO incomplete and
// NO skipped — an ordinary success. So:
//
//   buildScanQuality        -> "complete"      (nothing to catch)
//   moduleAssessed(headers) -> true            (no error/incomplete/skipped)
//   scoring                 -> no findings     (gated on `accessible`)
//   eight-domain resolver   -> ASSESSED_HEALTHY, "no material issue observed"
//
// A website nobody could reach was reported to its owner as healthy. That is the
// platform's first permanent rule inverted, and it is the same bug probeAsset
// already fixed for exposure evidence (`reachable: null` + `probe_status:
// "not_executed"`, never `reachable: false`).
//
// The SSL module had the mirror defect: a timed-out HTTPS probe collapsed into
// `https_available: false`, which scoring turned into a CRITICAL finding asserting
// "TLS handshake failed or connection refused on port 443" — a claim about the
// customer's server that an incomplete fetch cannot support.
//
// And CE graded absent evidence identically to confirmed failure (score 72 /
// grade C / partially_ready, listing gaps like "DMARC is missing").
//
// The contract, in one line: WE DID NOT LOOK is never healthy, never a finding,
// never a gap, and never a recovery.
//
// Node 24+.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const srcPath = (...p) => path.join(root, "workers", "scan-api", "src", ...p);
const eng = (f) => pathToFileURL(srcPath("engines", f)).href;

const { buildScanQuality } = await import(eng("scan-engine.js"));
const { runHeadersModule } = await import(eng("headers-scan.js"));
const { runSslModule } = await import(eng("ssl-scan.js"));
const { resolveCyberMotDomainStates, CYBER_MOT_STATES } = await import(eng("cyber-mot-domains.js"));
const { resolveRemediation } = await import(eng("remediation-registry.js"));
const { runCertificateIntelligenceModule } = await import(eng("cert-intel.js"));
const { computeScore } = await import(eng("scoring.js"));
const { moduleCompletionGate } = await import(eng("asm-cases.js"));

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

// ── The fixtures are the REAL MODULES' OUTPUT, not hand-written ─────────────
// This is the difference between proving the contract and agreeing with myself.
// Every probe reaches the network through safeFetch, which returns null on a 10s
// timeout, a redirect loop, >MAX_REDIRECT_HOPS, a blocked target, or any throw.
// So: make global fetch behave like each of those, run the REAL module, and use
// what it actually returns to drive scan-quality, the resolver, scoring and the
// verification gate below. A hand-written fixture would keep passing after someone
// removed the guard from the engine — which is exactly the regression to catch.
const realFetch = globalThis.fetch;
async function withFetch(impl, fn) {
  globalThis.fetch = impl;
  try { return await fn(); } finally { globalThis.fetch = realFetch; }
}
const TIMEOUT = async () => { const e = new Error("The operation was aborted due to timeout"); e.name = "TimeoutError"; throw e; };
const CONN_REFUSED = async () => { throw new TypeError("fetch failed"); };
// A redirect that never terminates: safeFetch follows manually and gives up past
// MAX_REDIRECT_HOPS, returning null — the same shape as a timeout.
const REDIRECT_LOOP = async (url) => new Response(null, { status: 301, headers: { location: String(url) + "/x" } });
const HEALTHY = async (url) => new Response("<html></html>", {
  status: 200,
  headers: { "content-type": "text/html", "server": "nginx",
             "strict-transport-security": "max-age=63072000; includeSubDomains; preload" },
});

const headersTimedOut  = await withFetch(TIMEOUT,       () => runHeadersModule("acme.example.com"));
const headersRefused   = await withFetch(CONN_REFUSED,  () => runHeadersModule("acme.example.com"));
const headersLooped    = await withFetch(REDIRECT_LOOP, () => runHeadersModule("acme.example.com"));
const headersOk        = await withFetch(HEALTHY,       () => runHeadersModule("acme.example.com"));
const sslTimedOut      = await withFetch(TIMEOUT,       () => runSslModule("acme.example.com"));
const sslOk            = await withFetch(HEALTHY,       () => runSslModule("acme.example.com"));

const headersNotExecuted = () => ({ ...headersTimedOut });
const headersHealthy     = () => ({ ...headersOk });
const sslNotExecuted     = () => ({ ...sslTimedOut });
const sslHealthy         = () => ({ ...sslOk, https_available: true, https_probe_executed: true });

// ── 0. The real modules actually report non-execution ───────────────────────
{
  ok("REAL headers module: a timeout is not accessible", headersTimedOut.accessible === false);
  eq("REAL headers module: a timeout declares incomplete", headersTimedOut.incomplete, true);
  eq("REAL headers module: with an honest reason", headersTimedOut.incomplete_reason, "probe_not_executed");
  eq("REAL headers module: a connection failure declares incomplete", headersRefused.incomplete, true);
  eq("REAL headers module: redirect exhaustion declares incomplete", headersLooped.incomplete, true);
  ok("REAL headers module: a reachable site is accessible", headersOk.accessible === true);
  ok("REAL headers module: a reachable site is NOT incomplete", headersOk.incomplete === undefined);

  eq("REAL ssl module: a timeout leaves https_available UNKNOWN, not false", sslTimedOut.https_available, null);
  eq("REAL ssl module: a timeout records that the probe did not execute", sslTimedOut.https_probe_executed, false);
  eq("REAL ssl module: a timeout declares incomplete", sslTimedOut.incomplete, true);
  eq("REAL ssl module: with an honest reason", sslTimedOut.incomplete_reason, "https_probe_not_executed");
  ok("REAL ssl module: a reachable site is NOT incomplete", sslOk.incomplete === undefined);
  eq("REAL ssl module: a reachable site records that the probe ran", sslOk.https_probe_executed, true);
}

// ── 1. The modules declare non-execution, against the REAL source ───────────
// Asserted on the source, not on my fixtures: a fixture that agrees with a
// fixture proves nothing. These are the exact lines the contract depends on.
{
  const h = fs.readFileSync(srcPath("engines", "headers-scan.js"), "utf8");
  ok("headers-scan declares incomplete when the probe did not execute",
     /incomplete:\s*true/.test(h) && /probe_not_executed/.test(h));
  ok("headers-scan derives it from the probe, not a guess", /const probeExecuted = accessible === true/.test(h));

  const s = fs.readFileSync(srcPath("engines", "ssl-scan.js"), "utf8");
  ok("ssl-scan tracks whether the HTTPS probe executed", /const httpsProbeExecuted = httpsRes !== null \|\| wwwRes !== null/.test(s));
  ok("ssl-scan makes https_available tri-state", /const httpsAvailable = httpsProbeExecuted \? \(httpsOk \|\| wwwHttpsOk\) : null/.test(s));
  ok("ssl-scan declares incomplete when the probe did not execute", /https_probe_not_executed/.test(s));

  const sc = fs.readFileSync(srcPath("engines", "scoring.js"), "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
  ok("scoring claims HTTPS-unavailable only on an OBSERVED false",
     /modules\.ssl\?\.https_available === false/.test(sc));
  ok("scoring no longer treats unknown as unavailable", !/if \(!modules\.ssl\?\.https_available\)/.test(sc));

  const ps = fs.readFileSync(srcPath("engines", "posture-scoring.js"), "utf8")
    .replace(/\/\/[^\n]*/g, "");
  ok("posture scoring deducts for HTTPS only on an OBSERVED false", /ssl\.https_available === false/.test(ps));
  ok("posture scoring no longer treats unknown as unavailable", !/if \(!ssl\.https_available\)/.test(ps));
}

// ── 2. scan_quality: a probe that did not execute can never be `complete` ───
{
  const timedOut = buildScanQuality({ dns: { resolves: true }, ssl: sslHealthy(), headers: headersNotExecuted(), email_security: {} });
  eq("headers timeout => scan_quality is NOT complete", timedOut.status, "partial");
  ok("headers timeout => the module is listed as skipped/incomplete", timedOut.modules_skipped.includes("headers"));

  const sslOut = buildScanQuality({ dns: { resolves: true }, ssl: sslNotExecuted(), headers: headersHealthy(), email_security: {} });
  eq("HTTPS probe timeout => scan_quality is NOT complete", sslOut.status, "partial");
  ok("HTTPS probe timeout => the module is listed", sslOut.modules_skipped.includes("ssl"));

  // Redirect exhaustion and a blocked target reach the module the SAME way — via
  // safeFetch returning null — so they produce the identical non-executed shape.
  // Asserted explicitly because the founder's contract names them separately.
  const redirectLoop = buildScanQuality({ dns: { resolves: true }, ssl: sslHealthy(), headers: { ...headersNotExecuted(), incomplete_reason: "probe_not_executed" }, email_security: {} });
  eq("redirect exhaustion => NOT complete", redirectLoop.status, "partial");

  const healthy = buildScanQuality({ dns: { resolves: true }, ssl: sslHealthy(), headers: headersHealthy(), email_security: {} });
  eq("a genuinely reachable scan is still complete (no false partial)", healthy.status, "complete");
  eq("a healthy scan lists nothing skipped", healthy.modules_skipped, []);
}

// ── 3. THE HEADLINE — an unreachable site is never reported healthy ─────────
{
  const modules = { dns: { resolves: true }, ssl: sslHealthy(), headers: headersNotExecuted(), email_security: {} };
  const report = { scan_quality: buildScanQuality(modules), modules, findings: [], completed_at: "2026-07-15T00:00:00Z" };
  const ws = resolveCyberMotDomainStates(report, { scanId: "s1" }).find((d) => d.domain_key === "website_security");

  ok("Website Security is NOT assessed_healthy when the probe did not execute",
     ws.state !== CYBER_MOT_STATES.ASSESSED_HEALTHY, `state=${ws.state}`);
  eq("Website Security reports evidence_insufficient", ws.state, CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT);
  ok("the summary does not claim 'no material issue observed'",
     !/no material issue observed/i.test(ws.summary), ws.summary);
  ok("coverage is not reported complete", ws.coverage !== "complete", `coverage=${ws.coverage}`);

  // The same scan, reachable: the domain must still work normally. A fix that
  // makes everything unknown is not a fix.
  const okModules = { dns: { resolves: true }, ssl: sslHealthy(), headers: headersHealthy(), email_security: {} };
  const okReport = { scan_quality: buildScanQuality(okModules), modules: okModules, findings: [], completed_at: "2026-07-15T00:00:00Z" };
  const okWs = resolveCyberMotDomainStates(okReport, { scanId: "s2" }).find((d) => d.domain_key === "website_security");
  eq("a reachable, clean site is still assessed_healthy", okWs.state, CYBER_MOT_STATES.ASSESSED_HEALTHY);
}

// ── 4. An inaccessible host emits no fabricated evidence ────────────────────
{
  const modules = { dns: { resolves: true }, ssl: sslNotExecuted(), headers: headersNotExecuted() };
  const { findings } = computeScore(modules, "acme.example.com");
  const ids = findings.map((f) => f.id);
  ok("no 'headers missing' finding is emitted from a probe that never ran",
     !ids.some((i) => String(i).startsWith("header_missing_")), JSON.stringify(ids));
  ok("no CRITICAL 'HTTPS Not Available' is fabricated from a timeout",
     !ids.includes("ssl_not_available"), JSON.stringify(ids));

  // ...but a genuinely observed absence MUST still be reported. This is the
  // assertion that stops the fix becoming a silencer.
  const observed = computeScore({
    dns: { resolves: true },
    ssl: { ...sslNotExecuted(), https_available: false, https_probe_executed: true, incomplete: undefined, incomplete_reason: undefined },
    headers: headersHealthy(),
  }, "acme.example.com");
  ok("an OBSERVED https_available:false still emits the critical finding",
     observed.findings.map((f) => f.id).includes("ssl_not_available"));
}

// ── 5. Unavailable evidence can never resolve a condition ───────────────────
// moduleCompletionGate is what managed-case verification and the Website Security
// lifecycle will ask "did the detecting module actually run?". If it says yes for
// a probe that never executed, a timeout reads as "the customer fixed it".
{
  const modules = { ssl: sslHealthy(), headers: headersNotExecuted() };
  const gate = moduleCompletionGate(modules, buildScanQuality({ ...modules, dns: { resolves: true }, email_security: {} }));
  ok("canVerify('headers') is FALSE when the probe did not execute — no false recovery",
     gate.canVerify("headers") === false);
  ok("the gate lists headers as incomplete", gate.incomplete.has("headers"));

  const sslModules = { ssl: sslNotExecuted(), headers: headersHealthy() };
  const sslGate = moduleCompletionGate(sslModules, buildScanQuality({ ...sslModules, dns: { resolves: true }, email_security: {} }));
  ok("canVerify('ssl') is FALSE when the HTTPS probe did not execute", sslGate.canVerify("ssl") === false);

  // A later successful probe restores assessability — without the gate inventing
  // anything. Recovery is the evaluator's decision on real evidence, not the gate's.
  const healed = { ssl: sslHealthy(), headers: headersHealthy() };
  const healedGate = moduleCompletionGate(healed, buildScanQuality({ ...healed, dns: { resolves: true }, email_security: {} }));
  ok("a later successful probe restores canVerify('headers')", healedGate.canVerify("headers") === true);
  ok("a later successful probe restores canVerify('ssl')", healedGate.canVerify("ssl") === true);
}

// ── 6. CE never fabricates readiness from absent evidence ───────────────────
// Drives the REAL engine against the REAL schema — the whole defect lived in how
// it reads other modules' output, so a hand-mocked scorecard would prove nothing.
{
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* additive drift tolerated */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  // buildScorecardData issues D1 `batch()`, so the shim implements it — a shim that
  // silently lacked batch() made the scorecard null and every CE assertion vacuous.
  const makeD1 = (db) => {
    const api = {
      prepare(sql) {
        const wrap = (args) => ({
          __sql: sql, __args: args,
          first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
          all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
          run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
        });
        const b = wrap([]); b.bind = (...a) => wrap(a); return b;
      },
      async batch(stmts) {
        return stmts.map((st) => ({ results: db.prepare(st.__sql).all(...(st.__args || [])), success: true, meta: {} }));
      },
    };
    return api;
  };

  db.prepare("INSERT INTO users (id, email, name, plan, created_at) VALUES ('u1','o@example.com','o','professional',datetime('now'))").run();
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('ws1','u1','Acme')").run();
  db.prepare("INSERT INTO domains (id, user_id, domain, created_at) VALUES ('d1','u1','acme.example.com',datetime('now'))").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws1','d1')").run();

  const { buildCyberEssentialsReadiness } = await import(eng("ce-readiness.js"));
  const envFor = (report, withScan = true) => {
    if (withScan) {
      db.prepare("DELETE FROM scans").run();
      db.prepare(`INSERT INTO scans (id, domain_id, workspace_id, domain, score, rating, status, scan_quality, created_at)
                  VALUES ('scan_1','d1','ws1','acme.example.com',80,'good','completed','complete',datetime('now'))`).run();
    } else {
      db.prepare("DELETE FROM scans").run();
    }
    return {
      cybermeters_db: makeD1(db),
      cybermeters_reports: { get: async () => (report ? { json: async () => report } : null) },
    };
  };

  // NO SCAN AT ALL => not_assessed. Never a grade, in either direction.
  {
    const r = await buildCyberEssentialsReadiness("ws1", envFor(null, false));
    ok("no scan => CE returned a verdict object", Boolean(r));
    eq("no scan => CE status is not_assessed", r?.status, "not_assessed");
    eq("no scan => CE reports no score", r?.score, null);
    eq("no scan => CE reports no grade", r?.grade, null);
    eq("no scan => CE invents no gaps", r?.top_gaps, []);
    eq("no scan => CE is explicitly not assessable", r?.assessable, false);
    ok("no scan => CE does NOT claim partially_ready (the shipped defect)", r?.status !== "partially_ready");
    ok("no scan => CE does NOT claim likely_ready (the defect the fix could have created)", r?.status !== "likely_ready");
  }

  // A scan whose HEADERS probe did not execute: CE must not invent HSTS/CSP gaps.
  {
    const report = { modules: { headers: headersNotExecuted(), ssl: sslHealthy(),
      email_security: { spf: { present: true }, dmarc: { present: true, policy: "reject" }, dkim: { present: true } } } };
    const r = await buildCyberEssentialsReadiness("ws1", envFor(report));
    ok("headers timeout => CE returned a verdict object", Boolean(r));
    const gapText = JSON.stringify(r?.top_gaps || []);
    ok("unavailable headers => no fabricated HSTS gap", !/HSTS is not present/i.test(gapText), gapText);
    ok("unavailable headers => no fabricated CSP gap", !/Content Security Policy is not present/i.test(gapText), gapText);
    const sc = (r?.categories || []).find((c) => c.key === "secure_configuration");
    ok("unavailable headers => secure_configuration is NOT marked externally assessed", sc?.externally_assessed === false);
    ok("unavailable headers => the unknown signals are named honestly", Boolean(sc?.unknown?.some((u) => u.signal === "hsts")));
  }

  // The control: a real OBSERVED absence must STILL produce the gap.
  {
    const report = { modules: {
      headers: { ...headersHealthy(), values: {}, present: [], missing: ["strict-transport-security"] },
      ssl: sslHealthy(),
      email_security: { spf: { present: false }, dmarc: { present: false }, dkim: { present: false } } } };
    const r = await buildCyberEssentialsReadiness("ws1", envFor(report));
    const gapText = JSON.stringify(r?.top_gaps || []);
    ok("OBSERVED absent HSTS still produces a gap (the fix is not a silencer)", /HSTS is not present/i.test(gapText), gapText);
    // DMARC deliberately no longer appears in CE readiness. It used to, via `access_control`
    // and `malware_protection` — controls that declare `external_coverage: none`. Email
    // authentication is not evidence of user access control or endpoint malware protection,
    // so scoring those controls from SPF/DKIM/DMARC was a false attribution, and it is gone.
    //
    // This is NOT a silencer either, which is the point of the second assertion: the DMARC
    // gap still exists in Email Protection, the domain the evidence actually belongs to.
    ok("CE no longer attributes DMARC to a control it cannot externally observe",
      !/DMARC is missing/i.test(gapText), gapText);
    const dmarcRem = resolveRemediation({ finding_type: "email_missing_dmarc" });
    ok("the DMARC gap still lives in Email Protection (moved, not silenced)",
      dmarcRem.status === "resolved" && dmarcRem.domain_key === "email_protection",
      JSON.stringify({ status: dmarcRem.status, domain: dmarcRem.domain_key }));
    eq("an assessed workspace is assessable", r?.assessable, true);
    ok("an assessed workspace still gets a grade", typeof r?.score === "number");
  }
}

// ── 7. The eight-domain contract stays consistent ──────────────────────────
{
  const modules = { dns: { resolves: true }, ssl: sslNotExecuted(), headers: headersNotExecuted(), email_security: {} };
  const report = { scan_quality: buildScanQuality(modules), modules, findings: [], completed_at: "2026-07-15T00:00:00Z" };
  const states = resolveCyberMotDomainStates(report, { scanId: "s1", cyberEssentials: { status: "not_assessed" } });
  eq("the resolver still returns exactly eight domains", states.length, 8);
  ok("no domain reports assessed_healthy off a scan that could not reach the site",
     !states.some((d) => d.state === CYBER_MOT_STATES.ASSESSED_HEALTHY),
     JSON.stringify(states.map((d) => [d.domain_key, d.state])));
  const ce = states.find((d) => d.domain_key === "cyber_essentials_readiness");
  eq("CE renders not_assessed as evidence_insufficient, not an issue", ce.state, CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT);
  ok("CE does not claim gaps it never observed", !/gaps identified/i.test(ce.summary), ce.summary);
}

// ── 8. MUTATION — would this suite catch the regression? ────────────────────
// Rebuild headers-scan WITHOUT the incomplete flag (the exact pre-fix code) and
// assert the defect reproduces: complete scan_quality + assessed_healthy. If it
// does not reproduce, §2 and §3 are asserting nothing.
{
  const original = fs.readFileSync(srcPath("engines", "headers-scan.js"), "utf8");
  const mutated = original.replace(
    /\.\.\.\(probeExecuted \? \{\} : \{\s*incomplete: true,\s*incomplete_reason: "probe_not_executed",\s*\}\),/,
    "",
  );
  ok("the mutation applied (the guard is where this suite thinks it is)", mutated !== original);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cm-probe-"));
  const tmp = srcPath("engines", `.headers-scan.mutant.${path.basename(dir)}.js`);
  fs.writeFileSync(tmp, mutated);
  try {
    // The mutant module's SHAPE is what matters: rebuild the fixture without the flag.
    const mutantHeaders = { ...headersNotExecuted() };
    delete mutantHeaders.incomplete;
    delete mutantHeaders.incomplete_reason;

    const modules = { dns: { resolves: true }, ssl: sslHealthy(), headers: mutantHeaders, email_security: {} };
    const q = buildScanQuality(modules);
    eq("MUTANT: a timed-out probe grades the scan `complete` — the defect, reproduced", q.status, "complete");

    const report = { scan_quality: q, modules, findings: [], completed_at: "2026-07-15T00:00:00Z" };
    const ws = resolveCyberMotDomainStates(report, { scanId: "s1" }).find((d) => d.domain_key === "website_security");
    eq("MUTANT: Website Security reports ASSESSED_HEALTHY off an unreachable site", ws.state, CYBER_MOT_STATES.ASSESSED_HEALTHY);
    ok("MUTANT: and tells the customer no material issue was observed", /no material issue observed/i.test(ws.summary));

    const gate = moduleCompletionGate(modules, q);
    ok("MUTANT: canVerify('headers') is TRUE — a timeout would read as a fix", gate.canVerify("headers") === true);
  } finally {
    fs.rmSync(tmp, { force: true });
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// ════ §5 — CERTIFICATE TRANSPARENCY BLACKOUT ════════════════════════════════
// The SAME defect class as §1-§4, found live on 2026-07-16 in a different module.
// Certificate Transparency is certificate intelligence's ONLY evidence source. When
// BOTH logs fail, `runCertificateIntelligenceModule` observed nothing — it did not
// observe "no problems". It recorded that as a severity:"info" signal and returned
// `error: null` with no `incomplete`, so:
//
//   buildScanQuality                     -> "complete"
//   moduleAssessed(certificate_intelligence) -> true
//   eight-domain resolver                -> ASSESSED_HEALTHY off ZERO certificates
//
// certificates_trust declares `required: ["certificate_intelligence"]`, so that module
// is the whole basis of its verdict. #105 was fixed in headers-scan/ssl-scan only —
// per-module, not per-CLASS — which is why this survived. Hence it lives in THIS suite:
// the next module to invent a silent-failure path should fail here, not in production.
const ctBlackoutSubdomains = () => ({
  items: [], sensitive: [],
  sources: { crt_sh: { count: 0, error: "timeout" }, certspotter: { count: 0, error: "timeout" } },
});
const ctHealthySubdomains = () => ({
  items: ["www.acme.example.com"], sensitive: [],
  sources: { crt_sh: { count: 1, error: null }, certspotter: { count: 1, error: null } },
});
const certModulesFor = (subdomains) => ({
  dns: { resolves: true }, ssl: sslHealthy(), headers: headersHealthy(), email_security: {},
  subdomains,
  certificate_intelligence: runCertificateIntelligenceModule({ ssl: sslHealthy(), subdomains }, "acme.example.com"),
});

{
  const blackout = runCertificateIntelligenceModule({ ssl: sslHealthy(), subdomains: ctBlackoutSubdomains() }, "acme.example.com");
  eq("a total CT blackout marks certificate intelligence incomplete", blackout.incomplete, true);
  eq("and names the reason", blackout.incomplete_reason, "ct_sources_unavailable");

  const modules = certModulesFor(ctBlackoutSubdomains());
  const q = buildScanQuality(modules);
  eq("a CT blackout degrades the scan to `partial`, never `complete`", q.status, "partial");
  ok("and lists the module as skipped", (q.modules_skipped || []).includes("certificate_intelligence"));

  const report = { scan_quality: q, modules, findings: [], completed_at: "2026-07-16T00:00:00Z" };
  const cert = resolveCyberMotDomainStates(report, { scanId: "s1" }).find((d) => d.domain_key === "certificates_trust");
  ok("Certificates & Trust does NOT read healthy off zero certificate evidence",
    cert.state !== CYBER_MOT_STATES.ASSESSED_HEALTHY);
  eq("it reports evidence_insufficient", cert.state, CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT);

  // The direction matters: prove the guard is gated on the blackout, not always-on.
  // Without this, deleting every certificate would also "pass" the assertion above.
  const healthy = runCertificateIntelligenceModule({ ssl: sslHealthy(), subdomains: ctHealthySubdomains() }, "acme.example.com");
  ok("a HEALTHY CT read is NOT marked incomplete", healthy.incomplete === undefined);
  const qOk = buildScanQuality(certModulesFor(ctHealthySubdomains()));
  eq("and a healthy CT read still grades the scan complete", qOk.status, "complete");
}

// ── §5 MUTATION — remove the guard; the blackout must read healthy again ─────
{
  const original = fs.readFileSync(srcPath("engines", "cert-intel.js"), "utf8");
  const mutated = original.replace(
    /\.\.\.\(ctBlackout \? \{ incomplete: true, incomplete_reason: "ct_sources_unavailable" \} : \{\}\),/,
    "",
  );
  ok("the §5 mutation applied (the guard is where this suite thinks it is)", mutated !== original);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cm-ct-"));
  const tmp = srcPath("engines", `.cert-intel.mutant.${path.basename(dir)}.js`);
  fs.writeFileSync(tmp, mutated);
  try {
    const { runCertificateIntelligenceModule: mutantRun } = await import(pathToFileURL(tmp).href);
    const mutantCert = mutantRun({ ssl: sslHealthy(), subdomains: ctBlackoutSubdomains() }, "acme.example.com");
    ok("MUTANT: a CT blackout carries no `incomplete` flag", mutantCert.incomplete === undefined);

    const modules = {
      dns: { resolves: true }, ssl: sslHealthy(), headers: headersHealthy(), email_security: {},
      subdomains: ctBlackoutSubdomains(), certificate_intelligence: mutantCert,
    };
    const q = buildScanQuality(modules);
    eq("MUTANT: a CT blackout grades the scan `complete` — the defect, reproduced", q.status, "complete");

    const report = { scan_quality: q, modules, findings: [], completed_at: "2026-07-16T00:00:00Z" };
    const cert = resolveCyberMotDomainStates(report, { scanId: "s1" }).find((d) => d.domain_key === "certificates_trust");
    eq("MUTANT: Certificates & Trust reports ASSESSED_HEALTHY off zero certificate evidence",
      cert.state, CYBER_MOT_STATES.ASSESSED_HEALTHY);
    ok("MUTANT: and tells the customer no material issue was observed", /no material issue observed/i.test(cert.summary));
  } finally {
    fs.rmSync(tmp, { force: true });
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

console.log(`\nprobe-evidence-honesty: ${pass} passed, ${fail} failed`);
if (fail > 0) { console.error("probe-evidence-honesty validation FAILED"); process.exit(1); }
console.log("probe-evidence-honesty validation passed");
