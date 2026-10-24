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
//     sends, the way one browser visit would;
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

/** A fetch that lets only passive public requests about `domain` through. */
export function passiveFence(domain, realFetch) {
  const apex = domain.toLowerCase();
  const homeHosts = new Set([apex, `www.${apex}`]);
  const redirectTargets = new Map();
  const allowed = [], refused = [];
  const fence = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.url);
    const method = String(init.method || (typeof input === "object" && input.method) || "GET").toUpperCase();
    const host = url.hostname.toLowerCase();
    const key = `${host}${url.pathname}${url.search}`;
    const hops = redirectTargets.get(key);
    let why = null;
    if (isDataHost(host)) why = "data_source";
    else if (homeHosts.has(host) && url.pathname === "/" && !url.search && (method === "GET" || method === "HEAD")) why = "home_page";
    else if (host === `mta-sts.${apex}` && url.pathname === "/.well-known/mta-sts.txt" && method === "GET") why = "mta_sts_policy";
    else if (hops !== undefined && (method === "GET" || method === "HEAD")) why = "redirect_of_home_page";
    if (!why) {
      refused.push({ host, path: url.pathname, method });
      throw new TypeError("fetch failed (corpus passive fence)");
    }
    allowed.push({ host, path: url.pathname, method, why });
    const response = await realFetch(input, init);
    const location = response.headers.get("location");
    if (why !== "data_source" && location && response.status >= 300 && response.status < 400 && (hops || 0) < MAX_REDIRECTS) {
      try {
        const next = new URL(location, url);
        redirectTargets.set(`${next.hostname.toLowerCase()}${next.pathname}${next.search}`, (hops || 0) + 1);
      } catch { /* an unusable Location is the engine's to report */ }
    }
    return response;
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
