// Run the free-scan target check and its five module runners against a corpus
// of real domains, locally, so refusals and incomplete modules show up by
// family instead of one customer report at a time.
//
// Real DNS (cloudflare-dns.com, as the Worker uses) and real HTTP/TLS from this
// machine. Never calls the CyberMeters API and writes nothing: no D1, no R2, no
// rate-limit rows. Mirrors POST /api/free-scan in routes/billing.js — the same
// runners, options, physical subrequest limit and wall-clock deadline — except
// that the modules also run when the target check refuses, so a refusal still
// shows what each module could see. The production route stops at the refusal.
//
//   node scripts/lab/free-scan-corpus.mjs [--domains file] [--only a.com,b.com]
//        [--concurrency 4] [--json out.json]
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { dnsQuery } from "../../workers/scan-api/src/engines/dns.js";
import { runDnsModule } from "../../workers/scan-api/src/engines/dns-scan.js";
import { runEmailModule } from "../../workers/scan-api/src/engines/email-scan.js";
import { runHeadersModule } from "../../workers/scan-api/src/engines/headers-scan.js";
import { runSslModule } from "../../workers/scan-api/src/engines/ssl-scan.js";
import { runTechModule } from "../../workers/scan-api/src/engines/tech-scan.js";
import { buildFreeScanEvidence } from "../../workers/scan-api/src/engines/free-scan-evidence.js";
import { FREE_SCAN_DEADLINE_MS, FREE_SCAN_SUBREQUEST_LIMIT } from "../../workers/scan-api/src/engines/free-scan-preview.js";
import { makeDnsCache, PhysicalSubrequestCounter } from "../../workers/scan-api/src/engines/scan-budget.js";
import { resolvePublicDnsTargetWithRetry, STRICT_DNS_STATES } from "../../workers/scan-api/src/lib/ssrf.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const arg = (name, fallback = null) => {
  const index = process.argv.indexOf(`--${name}`);
  return index > 0 ? process.argv[index + 1] : fallback;
};
const MODULES = ["dns", "ssl", "headers", "email_security", "technology_detection"];
const SHORT = { dns: "dns", ssl: "ssl", headers: "headers", email_security: "email", technology_detection: "tech" };

// Same as routes/billing.js: HTTP safety answers are never reused once settled.
class InFlightOnlyDnsCache extends Map {
  get(key) {
    const existing = super.get(key);
    if (existing?.settled === false) return existing;
    if (existing !== undefined) super.delete(key);
    return undefined;
  }
}

export function loadCorpus(file) {
  return fs.readFileSync(file, "utf8").split("\n")
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
    .map((line) => {
      const [domain, ...tags] = line.split(/\s+/);
      return { domain: domain.toLowerCase(), tags: tags.join(" ") };
    });
}

// The first concrete reason a module gives for not completing.
function moduleReason(entry, settlement) {
  if (entry.state === "completed") return "";
  if (settlement?.status === "rejected") {
    const error = settlement.reason;
    return `threw:${typeof error?.code === "string" ? error.code : error?.name || "error"}`;
  }
  const value = settlement?.value || {};
  if (entry.module === "email_security") {
    const statuses = { spf: value.spf_evidence_status, dkim: value.dkim_evidence_status,
      dmarc: value.dmarc_state?.evidence_status };
    const weak = Object.entries(statuses).filter(([, status]) => status == null
      || ["unavailable", "not_yet_assessed"].includes(status));
    if (weak.length) return weak.map(([key, status]) => `${key}:${status ?? "missing"}`).join(",");
  }
  const error = typeof value.error === "string" ? value.error : value.error?.code;
  return value.incomplete_reason || value.unavailable_reason || value.reason || error
    || (value.outcome && value.outcome !== "complete" ? `outcome:${value.outcome}` : "")
    || (value.validation_uncertain ? "validation_uncertain" : "")
    || (value.executed === false ? "not_executed" : "")
    || (value.skipped ? "skipped" : "") || "unspecified";
}

export async function runFreeScanCorpusDomain(domain) {
  const startedAt = Date.now();
  const physicalCounter = new PhysicalSubrequestCounter({ limit: FREE_SCAN_SUBREQUEST_LIMIT, safetyMargin: 0 });
  const remainingMs = () => Math.max(0, FREE_SCAN_DEADLINE_MS - (Date.now() - startedAt));
  const deadline = new AbortController();
  const timer = setTimeout(() => deadline.abort("free_scan_deadline_exhausted"), FREE_SCAN_DEADLINE_MS);
  const dnsCache = makeDnsCache();
  const safetyDnsCache = new InFlightOnlyDnsCache();
  const accountingFor = (module) => physicalCounter.contextFor(`free_preview_${module}`, { signal: deadline.signal });
  let target;
  try {
    const resolution = await resolvePublicDnsTargetWithRetry(domain, dnsQuery, {
      cache: safetyDnsCache, accounting: accountingFor("ssrf"), signal: deadline.signal,
    });
    target = { state: resolution.state, reason: resolution.reason || "",
      addresses: resolution.addresses || [], retried_after: resolution.first_reason || null };
  } catch (error) {
    target = { state: "threw", reason: typeof error?.code === "string" ? error.code : error?.name || "error", addresses: [] };
  }
  let settlements;
  try {
    const [dnsR, sslR, headersR, emailR, technologyR] = await Promise.allSettled([
      runDnsModule(domain, { accounting: accountingFor("dns"), signal: deadline.signal, cache: dnsCache }),
      runSslModule(domain, { accounting: accountingFor("ssl"), signal: deadline.signal,
        dnsResolver: dnsQuery, dnsCache: safetyDnsCache }),
      runHeadersModule(domain, { accounting: accountingFor("headers"), signal: deadline.signal,
        remainingMs, dnsResolver: dnsQuery, dnsCache: safetyDnsCache }),
      runEmailModule(domain, { accounting: accountingFor("email"), signal: deadline.signal, cache: dnsCache }),
      runTechModule(domain, { accounting: accountingFor("technology"), signal: deadline.signal,
        dnsResolver: dnsQuery, dnsCache: safetyDnsCache }),
    ]);
    settlements = { dns: dnsR, ssl: sslR, headers: headersR, email_security: emailR, technology_detection: technologyR };
  } finally {
    clearTimeout(timer);
  }
  const evidence = buildFreeScanEvidence(settlements);
  const modules = Object.fromEntries(evidence.module_evidence.map((entry) =>
    [entry.module, { state: entry.state, reason: moduleReason(entry, settlements[entry.module]) }]));
  const snapshot = physicalCounter.snapshot();
  return { domain, target, modules, coverage: evidence.evidence_coverage.state,
    subrequests: { issued: snapshot.issued, denied: snapshot.denied }, ms: Date.now() - startedAt };
}

async function pool(items, size, work) {
  const results = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(size, items.length) }, async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await work(items[index], index);
    }
  }));
  return results;
}

const cell = (value) => String(value ?? "").replace(/\|/g, "\\|");
const moduleCell = (module) => module.state === "completed" ? "ok" : `${module.state}: ${module.reason}`;

export function renderTable(rows) {
  const lines = [
    `| domain | tags | target | ${MODULES.map((m) => SHORT[m]).join(" | ")} | subreq | ms |`,
    `|---|---|---|${MODULES.map(() => "---").join("|")}|---|---|`,
  ];
  for (const row of rows) {
    const target = row.target.state === STRICT_DNS_STATES.PUBLIC ? "public"
      : `${row.target.state}: ${row.target.reason}`;
    lines.push(`| ${cell(row.domain)} | ${cell(row.tags)} | ${cell(target)} | `
      + `${MODULES.map((m) => cell(moduleCell(row.modules[m]))).join(" | ")} | `
      + `${row.subrequests.issued}${row.subrequests.denied ? ` (${row.subrequests.denied} denied)` : ""} | ${row.ms} |`);
  }
  return lines.join("\n");
}

// Failure families: one line per distinct (surface, state, reason).
export function renderFamilies(rows) {
  const families = new Map();
  const add = (key, domain) => {
    if (!families.has(key)) families.set(key, []);
    families.get(key).push(domain);
  };
  for (const row of rows) {
    if (row.target.state !== STRICT_DNS_STATES.PUBLIC) add(`target ${row.target.state}: ${row.target.reason}`, row.domain);
    for (const module of MODULES) {
      const entry = row.modules[module];
      if (entry.state !== "completed") add(`${SHORT[module]} ${entry.state}: ${entry.reason}`, row.domain);
    }
  }
  const sorted = [...families.entries()].sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));
  const clean = rows.filter((row) => row.target.state === STRICT_DNS_STATES.PUBLIC
    && MODULES.every((m) => row.modules[m].state === "completed")).length;
  return [`${clean}/${rows.length} domains: target public and all five modules completed.`, "",
    "| family | count | domains |", "|---|---|---|",
    ...sorted.map(([key, domains]) => `| ${cell(key)} | ${domains.length} | ${cell(domains.join(", "))} |`)].join("\n");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  let corpus = loadCorpus(arg("domains", path.join(here, "free-scan-corpus.txt")));
  const only = arg("only");
  if (only) corpus = only.split(",").map((domain) => corpus.find((c) => c.domain === domain) || { domain, tags: "" });
  const concurrency = Math.max(1, Number(arg("concurrency", "4")) || 4);
  const rows = await pool(corpus, concurrency, async ({ domain, tags }, index) => {
    const row = { ...(await runFreeScanCorpusDomain(domain)), tags };
    process.stderr.write(`[${index + 1}/${corpus.length}] ${domain} ${row.target.state} ${row.ms}ms\n`);
    return row;
  });
  const out = arg("json");
  if (out) fs.writeFileSync(out, `${JSON.stringify(rows, null, 2)}\n`);
  console.log(`# Free-scan corpus — ${new Date().toISOString()}\n`);
  console.log(`## Failure families\n\n${renderFamilies(rows)}\n`);
  console.log(`## Per domain\n\n${renderTable(rows)}`);
}
