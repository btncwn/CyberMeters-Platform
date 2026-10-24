// Label every customer-visible claim of a full-scan corpus run
// (scripts/lab/full-scan-corpus.mjs) against independent observations made
// now: dig against two public resolvers and two curl runs of the home page.
//
//   tp            the independent check agrees with the claim
//   fp            the independent check contradicts it (a false claim)
//   unverifiable  the independent check could not settle it
//   stated_limit  the claim is the product saying it could not tell
//                 ("Validation Uncertain"); it asserts nothing to check
//   not_measured  the claim rests on a request the passive fence refused, or
//                 on a capability the lab does not provide
//
// Claims are every finding, every domain the snapshot calls assessed_healthy,
// and a score published for a domain that does not exist.
//
//   node scripts/lab/full-scan-claims.mjs --in dir [--json out.json]
import fs from "node:fs";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { curl, dig, stableHeader, txtOnly, verifyClaim } from "./accuracy-ground-truth.mjs";
import { SCANNER_USER_AGENT } from "../../workers/scan-api/src/lib/http.js";

const run = promisify(execFile);
const arg = (name, fallback = null) => {
  const index = process.argv.indexOf(`--${name}`);
  return index > 0 ? process.argv[index + 1] : fallback;
};
const verdict = (label, evidence) => ({ label, evidence });
const yesNo = (ok, evidence) => verdict(ok ? "tp" : "fp", evidence);
const HSTS_MIN_MAX_AGE = 31_536_000; // dse-findings.js

const parseJson = (value) => { try { return JSON.parse(value); } catch { return null; } };
const hstsParts = (value) => ({
  maxAge: Number(value.match(/max-age="?(\d+)/i)?.[1] ?? NaN),
  includeSubDomains: /includesubdomains/i.test(value),
  preload: /(?:^|;)\s*preload\b/i.test(value),
});

async function exists(name) {
  const a = await dig(name, "A"), aaaa = await dig(name, "AAAA"), cname = await dig(name, "CNAME");
  if (a == null && aaaa == null && cname == null) return null;
  return (a?.length || 0) + (aaaa?.length || 0) + (cname?.length || 0) > 0;
}

async function homeBody(url) {
  try {
    const { stdout } = await run("curl", ["-s", "-L", "--max-redirs", "5", "--max-time", "15", "-A", SCANNER_USER_AGENT, url],
      { timeout: 20_000, maxBuffer: 8 << 20 });
    return stdout;
  } catch { return null; }
}

// Set-Cookie values from both curl runs (all hops); null when the runs differ in count.
function cookies(pair) {
  const list = (r) => (r?.hops || []).flatMap((hop) => String(hop.headers["set-cookie"] || "")
    .split(/,\s*(?=[^;,=\s]+=)/).map((c) => c.trim()).filter(Boolean));
  const [a, b] = [list(pair.first), list(pair.second)];
  return a.length === b.length ? a : null;
}

async function checkFinding(domain, finding, ctx) {
  const slug = finding.finding_slug;
  const title = finding.title || "";
  const evidence = parseJson(finding.evidence_json) || {};
  if (/Validation Uncertain/i.test(title)) return verdict("stated_limit", title);
  const target = evidence.probe_target || evidence.host || null;
  if (target && ctx.refusedHosts.has(String(target).toLowerCase()) && !ctx.homeHosts.has(String(target).toLowerCase())) {
    return verdict("not_measured", `rests on ${target}, refused by the passive fence`);
  }
  const header = (name) => stableHeader(ctx.https, name);
  if (slug === "dns_no_resolution") {
    const found = await exists(domain);
    if (found == null) return verdict("unverifiable", "no resolver answer");
    return yesNo(!found, found ? "resolves" : "no A/AAAA/CNAME");
  }
  if (slug === "dse_missing_caa") {
    // RFC 8659: the relevant CAA set is the closest one climbing towards the TLD.
    const labels = domain.split(".");
    for (let i = 0; i < labels.length - 1; i++) {
      const name = labels.slice(i).join(".");
      const caa = await dig(name, "CAA");
      if (caa == null) return verdict("unverifiable", `CAA unsettled at ${name}`);
      if (caa.length) return verdict("fp", `CAA at ${name}: ${caa[0]}`);
    }
    return verdict("tp", "no CAA on the tree");
  }
  if (["dse_hsts_not_preload_eligible", "dse_hsts_short_maxage", "header_weak_hsts"].includes(slug)) {
    // Judged on the apex's own HTTPS answer (hop 0), RFC 6797 host scope (B2).
    const apexHsts = (r) => (r?.hops?.[0] ? (r.hops[0].headers["strict-transport-security"] || "") : undefined);
    const pair = [apexHsts(ctx.https.first), apexHsts(ctx.https.second)];
    const v = pair.some((x) => x === undefined) ? undefined : (pair[0] === pair[1] ? pair[0] : null);
    if (v == null) return verdict("unverifiable", v === null ? "edge varies" : "no response");
    if (!v) return verdict("fp", "no HSTS header (a different finding)");
    const h = hstsParts(v);
    if (slug === "dse_hsts_short_maxage") return yesNo(h.maxAge < HSTS_MIN_MAX_AGE, v);
    if (slug === "dse_hsts_not_preload_eligible") return yesNo(!(h.maxAge >= HSTS_MIN_MAX_AGE && h.includeSubDomains && h.preload), v);
    return yesNo(h.maxAge < HSTS_MIN_MAX_AGE || !h.includeSubDomains, v);
  }
  if (slug === "header_missing_strict_transport_security") {
    // B2: missing for the domain = the apex's own HTTPS answer carries none.
    const apex = [ctx.https.first, ctx.https.second].map((r) => (r?.hops?.[0] ? (r.hops[0].headers["strict-transport-security"] || "") : undefined));
    if (apex.some((v) => v === undefined)) return verdict("unverifiable", "no apex HTTPS answer");
    if (apex[0] !== apex[1]) return verdict("unverifiable", "edge varies");
    return yesNo(!apex[0], apex[0] ? `apex sends ${apex[0]}` : "apex sends no HSTS");
  }
  if (slug === "header_hsts_redirect_host_uncovered") {
    const run = ctx.https.first;
    const apexValue = run?.hops?.[0]?.headers["strict-transport-security"] || "";
    const finalValue = run?.final?.headers["strict-transport-security"] || "";
    if (!run?.hops?.length) return verdict("unverifiable", "no response");
    return yesNo(Boolean(apexValue) && !/includesubdomains/i.test(apexValue) && !finalValue, `apex ${apexValue || "none"}; final ${finalValue || "none"}`);
  }
  if (slug === "dse_cookie_no_httponly") {
    const list = cookies(ctx.https);
    if (list == null) return verdict("unverifiable", "cookie count varies between runs");
    if (list.length === 0) return verdict("unverifiable", "no cookies received by curl (the site varies by client)");
    const missing = list.filter((c) => !/;\s*httponly\b/i.test(c)).length;
    return yesNo(missing >= 1, `${missing}/${list.length} without HttpOnly`);
  }
  if (slug.startsWith("subdomain_sensitive_")) {
    const host = target || evidence.hostname || null;
    if (!host) return verdict("unverifiable", "no host in evidence");
    const found = await exists(host);
    if (found == null) return verdict("unverifiable", `${host} unsettled`);
    return yesNo(found, `${host} ${found ? "exists" : "does not exist"}`);
  }
  if (slug === "subdomain_takeover_unconfirmed") {
    if (!target) return verdict("unverifiable", "no host in evidence");
    const cname = await dig(target, "CNAME");
    if (cname == null) return verdict("unverifiable", `${target} CNAME unsettled`);
    return yesNo(cname.length > 0, `${target} CNAME ${cname[0] || "none"}`);
  }
  if (slug === "shadow_it_dns_registration") {
    const txt = await dig(domain, "TXT");
    if (txt == null) return verdict("unverifiable", "TXT unsettled");
    const tokens = txtOnly(txt).filter((r) => /verification|verify|^ms=|_domainkey|domain-verification|site-verification/i.test(r));
    return yesNo(tokens.length > 0, `${tokens.length} registration TXT records`);
  }
  if (slug === "tech_script_integrity_observation") {
    // The claim: script elements with a src and no nonempty integrity
    // attribute, same-origin included, on the page the scan fetched.
    const page = ctx.httpsHost;
    const html = ctx.body ?? (ctx.body = await homeBody(`https://${page}/`));
    if (html == null) return verdict("unverifiable", `${page} not fetched`);
    const bare = [...html.matchAll(/<script\b[^>]*\bsrc\s*=[^>]*>/gi)]
      .filter((m) => !/\bintegrity\s*=\s*["']?[^"'\s>]/i.test(m[0]));
    return yesNo(bare.length > 0, `${bare.length} script src elements without integrity on ${page}`);
  }
  if (slug === "email_dkim_not_detected") {
    // The claim: no DKIM key at the selectors the scan lists as checked.
    const listed = String(evidence.observed_value || "").match(/selectors?:\s*(.+)$/i)?.[1]?.split(/,\s*/).map((x) => x.trim()).filter(Boolean) || [];
    if (!listed.length) return verdict("unverifiable", "no selector list in evidence");
    const hits = [];
    for (const selector of listed) {
      const r = await dig(`${selector}._domainkey.${domain}`, "TXT");
      if (r == null) return verdict("unverifiable", `${selector} unsettled`);
      if (txtOnly(r).some((v) => /(?:^|;)\s*p\s*=\s*[A-Za-z0-9+/]/.test(v))) hits.push(selector);
    }
    return yesNo(hits.length === 0, `${listed.length} selectors; keys at ${hits.join(",") || "none"}`);
  }
  if (slug === "csp_weak_policy" && /does not restrict/.test(finding.recommendation || "")) {
    const csp = header("content-security-policy");
    if (!csp) return verdict("unverifiable", "no stable CSP in curl's response");
    const names = new Set(csp.split(";").map((d) => d.trim().split(/\s+/)[0]?.toLowerCase()).filter(Boolean));
    const attrOpen = !["script-src-attr", "script-src", "default-src"].some((n) => names.has(n));
    const evalOpen = !["script-src", "default-src"].some((n) => names.has(n));
    return yesNo(attrOpen || evalOpen, `attr ${attrOpen ? "open" : "governed"}, eval ${evalOpen ? "open" : "governed"}`);
  }
  if (slug === "csp_weak_policy") {
    const csp = header("content-security-policy");
    if (!csp) return verdict("unverifiable", csp === "" ? "no CSP in curl's response (the product saw one elsewhere in the chain)" : "edge varies or no response");
    const script = (csp.split(";").map((d) => d.trim().split(/\s+/)).find((p) => p[0]?.toLowerCase() === "script-src")
      || csp.split(";").map((d) => d.trim().split(/\s+/)).find((p) => p[0]?.toLowerCase() === "default-src") || []).slice(1);
    // CSP3: 'unsafe-inline' is ignored when a nonce or hash is present.
    if (/'unsafe-inline' in script-src/.test(finding.recommendation || "") && script.some((x) => /^'(nonce-|sha(256|384|512)-)/i.test(x))) {
      return verdict("fp", `script-src ${script.join(" ").slice(0, 90)} — 'unsafe-inline' is ignored next to a nonce/hash`);
    }
  }
  return verifyClaim(domain, { id: `F:${slug}`, text: finding.recommendation || title }, ctx);
}

async function checkHealthy(domain, key, ctx, findings = []) {
  if (key === "email_protection") {
    const records = await dig(`_dmarc.${domain}`, "TXT");
    if (records == null) return verdict("unverifiable", "_dmarc unsettled");
    const dmarc = txtOnly(records).filter((r) => /^v=DMARC1/i.test(r));
    const policy = dmarc[0]?.match(/(?:^|;)\s*p\s*=\s*(\w+)/i)?.[1]?.toLowerCase();
    const spf = txtOnly((await dig(domain, "TXT")) || []).filter((r) => /^v=spf1/i.test(r));
    return yesNo(dmarc.length === 1 && ["quarantine", "reject"].includes(policy) && spf.length === 1, `DMARC p=${policy || "none"}; SPF ${spf.length}`);
  }
  if (key === "website_security") {
    // Healthy while the product's own header checks say they could not validate.
    const uncertain = findings.filter((f) => /^header_/.test(f.finding_slug) && /Validation Uncertain/i.test(f.title || ""));
    if (uncertain.length) return verdict("fp", `healthy asserted while ${uncertain.length} of its own header checks read "Validation Uncertain"`);
    const v = stableHeader(ctx.https, "strict-transport-security");
    if (v == null) return verdict("unverifiable", "edge varies or no response");
    return yesNo(Boolean(v), v ? `HSTS ${v}` : "no HSTS");
  }
  if (key === "attack_surface") {
    const found = await exists(domain);
    if (found == null) return verdict("unverifiable", "no resolver answer");
    return yesNo(found, found ? "apex resolves" : "apex does not resolve");
  }
  return verdict("not_measured", `no independent check for a healthy ${key}`);
}

export async function labelRun(result) {
  const domain = result.domain;
  const refusedHosts = new Set(Object.keys(result.fence?.refused || {}).map((k) => k.replace(/^refused /, "").split("/")[0]));
  const homeHosts = new Set([domain, `www.${domain}`]);
  const ctx = { httpsHost: domain, refusedHosts, homeHosts };
  ctx.https = await curl(`https://${domain}/`);
  ctx.http = await curl(`http://${domain}/`);
  const claims = [];
  for (const finding of result.findings || []) {
    claims.push({ kind: "finding", id: finding.finding_slug, severity: finding.severity, title: finding.title,
      ...(await checkFinding(domain, finding, ctx)) });
  }
  for (const entry of result.snapshot?.domains || []) {
    if (entry.state !== "assessed_healthy") continue;
    claims.push({ kind: "healthy", id: entry.domain_key, ...(await checkHealthy(domain, entry.domain_key, ctx, result.findings || [])) });
  }
  const score = result.snapshot?.overall?.cyber_metrics_score;
  if (score != null) {
    const found = await exists(domain);
    if (found === false) claims.push({ kind: "score", id: "score_on_nonexistent_domain", label: "fp", evidence: `score ${score} for a domain with no A/AAAA/CNAME` });
  }
  return { domain, quality: result.quality, score: result.score, claims };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const dir = arg("in");
  if (!dir) { console.error("usage: node scripts/lab/full-scan-claims.mjs --in dir [--json out.json]"); process.exit(2); }
  const rows = [];
  for (const file of fs.readdirSync(dir).filter((f) => f.endsWith(".json")).sort()) {
    rows.push(await labelRun(JSON.parse(fs.readFileSync(path.join(dir, file), "utf8"))));
  }
  const tally = {};
  for (const row of rows) for (const c of row.claims) {
    const key = `${c.kind}:${c.id.replace(/^subdomain_sensitive_.*/, "subdomain_sensitive_*")}`;
    tally[key] ??= { tp: 0, fp: 0, unverifiable: 0, stated_limit: 0, not_measured: 0 };
    tally[key][c.label] += 1;
  }
  console.log("| claim | TP | FP | unverifiable | stated limit | not measured |\n|---|---|---|---|---|---|");
  for (const [key, t] of Object.entries(tally).sort()) console.log(`| ${key} | ${t.tp} | ${t.fp} | ${t.unverifiable} | ${t.stated_limit} | ${t.not_measured} |`);
  console.log("\nFalse and unverifiable claims:");
  for (const row of rows) for (const c of row.claims) if (c.label === "fp" || c.label === "unverifiable") console.log(`- ${c.label.toUpperCase()} ${row.domain} ${c.kind}:${c.id}: ${c.evidence}`);
  if (arg("json")) fs.writeFileSync(arg("json"), JSON.stringify(rows, null, 2));
}
