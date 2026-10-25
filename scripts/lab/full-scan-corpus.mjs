// Run the real full-scan engine (runScanEngine: every module, the scoring and
// the report builders) against public corpus domains, locally, behind a
// PASSIVE network fence, to measure what the full scan claims.
//
// The production route refuses a full scan of a domain whose ownership is not
// verified, and a domain we do not own is never port-scanned or probed. So the
// fence lets through only passive public requests:
//   - public DNS-over-HTTPS resolvers, RDAP, Certificate Transparency and the
//     public vulnerability/identity directories (requests about the domain,
//     never to it);
//   - the home page of the apex and www (GET/HEAD of "/") and the redirects it
//     sends, the way one browser visit would. The fence follows redirects
//     itself (each hop fetched with redirect: "manual" and admitted on its
//     own), so a "follow" request cannot reach a hop the fence never saw;
//   - the published MTA-STS policy file.
// Every other request is refused (as a network failure) and recorded, so a
// module that needed it is "not measured on corpus", never TP or FP.
// No network probe, no deep TLS container, no email: those bindings are absent.
//
// Storage is the lab's in-memory full schema; nothing touches production.
//
//   node scripts/lab/full-scan-corpus.mjs --only a.com,b.com --out dir
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildLabDb, labD1, labR2, seedTenant } from "./lab-scan.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..", "..");
const arg = (name, fallback = null) => {
  const index = process.argv.indexOf(`--${name}`);
  return index > 0 ? process.argv[index + 1] : fallback;
};

const DATA_HOSTS = [
  "cloudflare-dns.com", "dns.google", "dns.quad9.net", "crt.sh",
  "www.cisa.gov", "services.nvd.nist.gov", "raw.githubusercontent.com", "api.first.org",
  "login.microsoftonline.com",
];
const isDataHost = (host) => DATA_HOSTS.includes(host) || host === "rdap.org" || /^rdap\./.test(host);
const MAX_REDIRECTS = 5;
// A redirect from a public site must not reach the operator's own network:
// loopback, private, link-local, CGNAT and unique-local literal addresses and
// local-only names are refused. (A public NAME that resolves to a private
// address is not caught here; the lab runs on a machine, not inside a VPC.)
const LOCAL_NAME = /(^|\.)(localhost|local|internal|home\.arpa)$/;
const PRIVATE_V4 = /^(0|10|127)\.|^169\.254\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\.|^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./;
const PRIVATE_V6 = /^(::1?|f[cd][0-9a-f]{0,2}:|fe[89ab][0-9a-f]?:|::ffff:)/;
export const isPrivateTarget = (host) => {
  const bare = host.replace(/^\[|\]$/g, "");
  return LOCAL_NAME.test(bare) || (/^[\d.]+$/.test(bare) && PRIVATE_V4.test(bare)) || (bare.includes(":") && PRIVATE_V6.test(bare));
};

/** A fetch that lets only passive public requests about `domain` through. */
export function passiveFence(domain, realFetch) {
  const apex = domain.toLowerCase();
  const homeHosts = new Set([apex, `www.${apex}`]);
  const redirectTargets = new Map();
  const allowed = [], refused = [];
  const admit = (url, method) => {
    const host = url.hostname.toLowerCase();
    const hops = redirectTargets.get(`${host}${url.pathname}${url.search}`);
    let why = null;
    if (isDataHost(host)) why = "data_source";
    else if (homeHosts.has(host) && url.pathname === "/" && !url.search && (method === "GET" || method === "HEAD")) why = "home_page";
    else if (host === `mta-sts.${apex}` && url.pathname === "/.well-known/mta-sts.txt" && method === "GET") why = "mta_sts_policy";
    else if (hops !== undefined && !isPrivateTarget(host) && (method === "GET" || method === "HEAD")) why = "redirect_of_home_page";
    if (!why) {
      refused.push({ host, path: url.pathname, method });
      throw new TypeError("fetch failed (corpus passive fence)");
    }
    allowed.push({ host, path: url.pathname, method, why });
    return { why, hops: hops || 0 };
  };
  const fence = async (input, init = {}) => {
    const request = typeof input === "object" && !(input instanceof URL) ? input : null;
    let url = new URL(request ? request.url : String(input));
    let method = String(init.method || request?.method || "GET").toUpperCase();
    const mode = init.redirect || request?.redirect || "follow";
    const hopInit = { headers: init.headers ?? request?.headers, signal: init.signal ?? request?.signal };
    for (let followed = 0; ; followed++) {
      const { why, hops } = admit(url, method);
      // Never let the runtime follow a redirect on its own: every hop comes back here.
      const response = followed === 0
        ? await realFetch(input, { ...init, redirect: "manual" })
        : await realFetch(url.href, { ...hopInit, method, redirect: "manual" });
      const location = response.headers.get("location");
      if (!(response.status >= 300 && response.status < 400 && location)) return response;
      let next;
      try { next = new URL(location, url); } catch { return response; } // an unusable Location is the engine's to report
      if (why !== "data_source" && hops < MAX_REDIRECTS) {
        redirectTargets.set(`${next.hostname.toLowerCase()}${next.pathname}${next.search}`, hops + 1);
      }
      if (mode === "manual") return response;
      if (mode === "error" || followed + 1 > MAX_REDIRECTS) throw new TypeError("fetch failed (corpus passive fence: redirect)");
      try { await response.body?.cancel(); } catch { /* nothing to release */ }
      // Fetch spec: 303, and 301/302 after a non-GET, continue as GET (HEAD stays HEAD).
      if (method !== "HEAD" && (response.status === 303 || ((response.status === 301 || response.status === 302) && method !== "GET"))) method = "GET";
      url = next;
    }
  };
  return { fence, allowed, refused };
}

const summarize = (rows) => rows.reduce((acc, row) => {
  const key = `${row.why || "refused"} ${row.host}${row.why === "data_source" ? "" : row.path}`;
  acc[key] = (acc[key] || 0) + 1;
  return acc;
}, {});

export async function runCorpusFullScan(domain, { quiet = true } = {}) {
  const db = await buildLabDb(root);
  const r2 = labR2();
  const ids = { userId: "usr_corpus", workspaceId: "ws_corpus", domainId: "dom_corpus" };
  const at = new Date().toISOString();
  seedTenant(db, { ...ids, domain, createdAt: at });
  const env = {
    cybermeters_db: labD1(db),
    cybermeters_reports: r2,
    SCAN_CAPACITY_MODE: "legacy",
    SCAN_SUBREQUEST_LIMIT: "200",
    APP_VERSION: "corpus-full-scan",
    RESEND_API_KEY: "",
    FRONTEND_URL: "https://app.cybermeters.com",
  };
  const { runScanEngine } = await import(pathToFileURL(path.join(root, "workers/scan-api/src/engines/scan-engine.js")).href);
  const realFetch = globalThis.fetch;
  const { fence, allowed, refused } = passiveFence(domain, realFetch);
  const realConsole = { log: console.log, info: console.info, warn: console.warn, error: console.error };
  const engineLog = [];
  globalThis.fetch = fence;
  if (quiet) for (const level of Object.keys(realConsole)) console[level] = (...parts) => engineLog.push(`${level} ${parts.map(String).join(" ").slice(0, 300)}`);
  const scanId = "scan_corpus_1";
  db.prepare("INSERT INTO scans (id, workspace_id, domain_id, domain, status, created_at) VALUES (?, ?, ?, ?, 'queued', ?)")
    .run(scanId, ids.workspaceId, ids.domainId, domain, at);
  const started = Date.now();
  let error = null;
  try {
    await runScanEngine(scanId, ids.domainId, ids.workspaceId, domain, env, { executionContext: "queue", trigger: "manual" });
  } catch (caught) { error = caught?.name || "Error"; }
  finally {
    globalThis.fetch = realFetch;
    Object.assign(console, realConsole);
  }
  const scan = db.prepare("SELECT status, scan_quality, score FROM scans WHERE id = ?").get(scanId) || {};
  const findings = db.prepare("SELECT * FROM findings WHERE scan_id = ?").all(scanId).map((row) => ({ ...row }));
  const report = JSON.parse(r2.store.get(`reports/${scanId}.json`) || "null");
  const snapshotKey = [...r2.store.keys()].find((key) => key.includes("snapshot"));
  const snapshot = snapshotKey ? JSON.parse(r2.store.get(snapshotKey)) : null;
  return {
    domain,
    observed_at: at,
    elapsed_ms: Date.now() - started,
    error,
    status: scan.status ?? null,
    quality: scan.scan_quality ?? null,
    score: scan.score ?? null,
    scan_quality_detail: report?.scan_quality ?? null,
    findings,
    report,
    snapshot,
    fence: { allowed: summarize(allowed), refused: summarize(refused), allowed_total: allowed.length, refused_total: refused.length },
    engine_log_tail: engineLog.slice(-40),
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const only = String(arg("only", "")).split(",").map((d) => d.trim()).filter(Boolean);
  const out = arg("out");
  if (!only.length || !out) {
    console.error("usage: node scripts/lab/full-scan-corpus.mjs --only a.com,b.com --out dir");
    process.exit(2);
  }
  fs.mkdirSync(out, { recursive: true });
  for (const domain of only) {
    const result = await runCorpusFullScan(domain);
    fs.writeFileSync(path.join(out, `${domain}.json`), JSON.stringify(result));
    console.log(`${domain}: ${result.status}/${result.quality} score ${result.score} findings ${result.findings.length} ` +
      `${Math.round(result.elapsed_ms / 1000)}s allowed ${result.fence.allowed_total} refused ${result.fence.refused_total}${result.error ? ` error ${result.error}` : ""}`);
  }
}
