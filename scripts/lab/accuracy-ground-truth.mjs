// Ground-truth accuracy check for the free scan's customer-facing claims.
//
// Builds the real anonymous preview (the same runners and buildFreeScanPreview
// the route uses) for each domain, then re-checks every claim it makes with
// independent tools — dig against two public resolvers, openssl s_client and
// curl — and labels each one:
//   tp           the independent check agrees with the claim
//   fp           the independent check contradicts it (a false claim)
//   unverifiable the independent check could not settle it (no answer, or two
//                curl runs disagreed because the edge varies its response)
// Claims are every finding the preview counts (shown or locked) plus every
// "observed" statement printed under a domain card.
//
// Passive public checks only: DNS lookups, one TLS handshake to 443 and HTTP(S)
// GETs of the home page — the same requests the free scan itself makes. No
// port scan and no service probe, so it is safe to run against public domains
// we do not own. Measures only; it changes nothing.
//
//   node scripts/lab/accuracy-ground-truth.mjs --only a.com,b.com [--json out.json]
import fs from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { runFreeScanSettlements } from "./free-scan-corpus.mjs";
import { buildFreeScanEvidence } from "../../workers/scan-api/src/engines/free-scan-evidence.js";
import { buildFreeScanPreview } from "../../workers/scan-api/src/engines/free-scan-preview.js";
import { DKIM_SELECTORS } from "../../workers/scan-api/src/engines/email-analysis.js";
import { SCANNER_USER_AGENT } from "../../workers/scan-api/src/lib/http.js";

const run = promisify(execFile);
const arg = (name, fallback = null) => {
  const index = process.argv.indexOf(`--${name}`);
  return index > 0 ? process.argv[index + 1] : fallback;
};
const RESOLVERS = ["1.1.1.1", "8.8.8.8"];

export async function dig(name, type) {
  const answers = [];
  for (const resolver of RESOLVERS) {
    try {
      const { stdout } = await run("dig", [`@${resolver}`, "+short", "+time=4", "+tries=2", name, type], { timeout: 15_000 });
      answers.push(stdout.split("\n").map((line) => line.trim()).filter(Boolean)
        .filter((line) => !line.startsWith(";;")));
    } catch { answers.push(null); }
  }
  const settled = answers.filter(Boolean);
  if (!settled.length) return null;
  // Two resolvers that disagree on emptiness leave the record unsettled.
  if (settled.some((a) => a.length === 0) && settled.some((a) => a.length > 0)) return null;
  return settled.find((a) => a.length) || [];
}
const txt = (records) => records.map((r) => r.replace(/^"|"$/g, "").replace(/"\s+"/g, ""));
// dig +short TXT follows CNAMEs and prints the target name first; keep TXT only.
export const txtOnly = (records) => txt(records.filter((r) => r.startsWith('"')));

async function curlOnce(url) {
  try {
    const { stdout } = await run("curl", ["-s", "-L", "--max-redirs", "5", "--max-time", "15",
      "-A", SCANNER_USER_AGENT, "-D", "-", "-o", "/dev/null", "-w", "\n__EFFECTIVE__ %{url_effective} %{http_code}", url],
    { timeout: 20_000, maxBuffer: 4 << 20 });
    const [raw, tail] = stdout.split("\n__EFFECTIVE__ ");
    const blocks = raw.split(/\r?\n\r?\n/).filter((b) => /^HTTP\//.test(b.trim()));
    const parse = (block) => {
      const lines = block.trim().split(/\r?\n/);
      const headers = {};
      for (const line of lines.slice(1)) {
        const at = line.indexOf(":");
        if (at > 0) {
          const key = line.slice(0, at).trim().toLowerCase();
          headers[key] = headers[key] ? `${headers[key]}, ${line.slice(at + 1).trim()}` : line.slice(at + 1).trim();
        }
      }
      return { status: Number(lines[0].split(" ")[1]), headers };
    };
    const hops = blocks.map(parse);
    const [effective, code] = (tail || "").trim().split(" ");
    return { hops, final: hops.at(-1) || null, effective, code: Number(code) };
  } catch { return null; }
}
export async function curl(url) {
  const first = await curlOnce(url);
  const second = await curlOnce(url);
  return { first, second };
}

async function tlsHandshake(host) {
  try {
    const child = execFile("openssl", ["s_client", "-connect", `${host}:443`, "-servername", host, "-brief"],
      { timeout: 15_000 });
    child.stdin.end();
    let out = "";
    child.stdout.on("data", (d) => { out += d; });
    child.stderr.on("data", (d) => { out += d; });
    await new Promise((resolve) => child.on("close", resolve));
    const protocol = out.match(/Protocol version:\s*(\S+)/)?.[1] || null;
    return { completed: Boolean(protocol), protocol };
  } catch { return null; }
}

// Header value from both curl runs; null when they disagree (edge variance).
export function stableHeader(pair, name) {
  const values = [pair.first, pair.second].map((r) => (r?.final ? r.final.headers[name] ?? "" : undefined));
  if (values.some((v) => v === undefined)) return undefined;
  // A CSP nonce is fresh on every response; it is not variance in the policy.
  const policy = (v) => v.replace(/'nonce-[^']*'/g, "'nonce'");
  return policy(values[0]) === policy(values[1]) ? values[0] : null;
}
const cspDirective = (csp, name) => {
  const map = Object.fromEntries(csp.split(";").map((d) => d.trim().split(/\s+/)).filter((p) => p[0])
    .map(([k, ...v]) => [k.toLowerCase(), v]));
  return map[name] ?? map["default-src"] ?? null;
};
// Unsafe = an unsafe keyword, a bare * or a scheme-only source. A host
// wildcard such as *.example.com is an allow-list entry, not an unsafe source.
const unsafe = (sources) => sources?.some((s) => ["'unsafe-inline'", "'unsafe-eval'", "*"].includes(s)
  || /^(?:https?|data|blob):$/i.test(s)) ?? false;

const verdict = (label, evidence) => ({ label, evidence });

export async function verifyClaim(domain, claim, ctx) {
  const yesNo = (ok, evidence) => verdict(ok ? "tp" : "fp", evidence);
  const header = (name) => stableHeader(ctx.https, name);
  switch (claim.id) {
    case "dns_resolves": {
      const a = await dig(domain, "A"), aaaa = await dig(domain, "AAAA");
      if (a == null && aaaa == null) return verdict("unverifiable", "no resolver answer");
      return yesNo((a?.length || 0) + (aaaa?.length || 0) > 0, `A=${a?.length ?? "?"} AAAA=${aaaa?.length ?? "?"}`);
    }
    case "mx_published": {
      const mx = await dig(domain, "MX");
      if (mx == null) return verdict("unverifiable", "MX unsettled");
      return yesNo(mx.some((r) => !/^0 \.$/.test(r)), mx.join(" ; ").slice(0, 120));
    }
    case "spf_single_record": {
      const records = (await dig(domain, "TXT"));
      if (records == null) return verdict("unverifiable", "TXT unsettled");
      const spf = txtOnly(records).filter((r) => /^v=spf1(\s|$)/i.test(r));
      const ending = claim.text.match(/ending in (\S+)/)?.[1];
      const ok = spf.length === 1 && (!ending || spf[0].trim().split(/\s+/).at(-1).toLowerCase() === ending.toLowerCase());
      return yesNo(ok, `${spf.length} spf; ${spf[0]?.slice(-40) || ""}`);
    }
    case "dmarc_enforcing_policy":
    case "dmarc_aggregate_reporting":
    case "F:email_dmarc_policy_none": {
      const records = await dig(`_dmarc.${domain}`, "TXT");
      if (records == null) return verdict("unverifiable", "_dmarc unsettled");
      const dmarc = txtOnly(records).filter((r) => /^v=DMARC1/i.test(r));
      if (dmarc.length !== 1) return verdict("fp", `${dmarc.length} DMARC records`);
      const policy = dmarc[0].match(/(?:^|;)\s*p\s*=\s*(\w+)/i)?.[1]?.toLowerCase();
      if (claim.id === "dmarc_aggregate_reporting") return yesNo(/(?:^|;)\s*rua\s*=/i.test(dmarc[0]), dmarc[0].slice(0, 120));
      if (claim.id === "F:email_dmarc_policy_none") return yesNo(policy === "none", `p=${policy}`);
      return yesNo(policy === claim.text.match(/p=(\w+)/)?.[1], `p=${policy}`);
    }
    case "F:email_missing_dmarc": {
      const records = await dig(`_dmarc.${domain}`, "TXT");
      if (records == null) return verdict("unverifiable", "_dmarc unsettled");
      const dmarc = txtOnly(records).filter((r) => /^v=DMARC1/i.test(r));
      return yesNo(dmarc.length === 0, `${dmarc.length} DMARC records`);
    }
    case "dkim_key_observed": {
      const selectors = [...claim.text.matchAll(/"([^"]+)"/g)].map((m) => m[1]);
      const results = [];
      for (const s of selectors) {
        const r = await dig(`${s}._domainkey.${domain}`, "TXT");
        results.push(r == null ? null : txtOnly(r).some((v) => /(?:^|;)\s*p\s*=\s*[A-Za-z0-9+/]/.test(v)));
      }
      if (results.includes(false)) return verdict("fp", `selectors ${selectors.join(",")} → ${results.join(",")}`);
      if (results.includes(null)) return verdict("unverifiable", "selector unsettled");
      return verdict("tp", `selectors ${selectors.join(",")}`);
    }
    case "F:email_dkim_not_detected": {
      const hits = [];
      for (const s of DKIM_SELECTORS) {
        const r = await dig(`${s}._domainkey.${domain}`, "TXT");
        if (r && txtOnly(r).some((v) => /(?:^|;)\s*p\s*=\s*[A-Za-z0-9+/]/.test(v))) hits.push(s);
      }
      const provider = claim.text.match(/^The SPF record points to (.+?) as a sender/)?.[1] ?? claim.text.match(/^(.+?) was inferred/)?.[1];
      let providerSeen = true;
      if (provider) {
        const all = [...((await dig(domain, "TXT")) || []), ...((await dig(domain, "MX")) || [])].join(" ").toLowerCase();
        const hints = { Mailchimp: ["mcsv.net", "mailchimp", "mandrillapp"] }[provider] || [provider.toLowerCase()];
        providerSeen = hints.some((h) => all.includes(h));
      }
      return yesNo(hits.length === 0 && providerSeen, `keys at checked selectors: ${hits.join(",") || "none"}; provider record ${providerSeen ? "seen" : "NOT seen"}`);
    }
    case "F:email_not_applicable": {
      const mx = await dig(domain, "MX");
      if (mx == null) return verdict("unverifiable", "MX unsettled");
      return yesNo(!mx.some((r) => !/^0 \.$/.test(r)), `MX ${mx.join(" ; ") || "none"}`);
    }
    case "dnssec_signed":
    case "F:dnssec_not_enabled": {
      const ds = await dig(domain, "DS"), key = await dig(domain, "DNSKEY");
      if (ds == null || key == null) return verdict("unverifiable", "DS/DNSKEY unsettled");
      const signed = ds.length > 0 && key.length > 0;
      if (claim.id === "dnssec_signed") return yesNo(signed, `DS=${ds.length} DNSKEY=${key.length}`);
      return yesNo(ds.length === 0 && key.length === 0, `DS=${ds.length} DNSKEY=${key.length}`);
    }
    case "tls_handshake_completed": {
      const t = ctx.tls ?? (ctx.tls = await tlsHandshake(ctx.httpsHost));
      if (t == null) return verdict("unverifiable", "openssl did not run");
      return yesNo(t.completed, `${ctx.httpsHost} ${t.protocol || "no handshake"}`);
    }
    case "https_answered": {
      const codes = [ctx.https.first?.code, ctx.https.second?.code];
      if (codes.every((c) => !c)) return verdict("fp", "no HTTPS response in two curl runs");
      return verdict("tp", `HTTP ${codes.join("/")}`);
    }
    case "http_redirects_to_https": {
      const runs = [ctx.http.first, ctx.http.second].filter(Boolean);
      if (!runs.length) return verdict("unverifiable", "no HTTP response");
      const ok = runs.map((r) => r.hops[0] && r.hops[0].status >= 300 && r.hops[0].status < 400
        && /^https:/i.test(r.effective || ""));
      if (ok[0] !== ok.at(-1)) return verdict("unverifiable", "curl runs disagree");
      return yesNo(ok[0], `first ${runs[0].hops[0]?.status} → ${runs[0].effective}`);
    }
    case "hsts_set": {
      const v = header("strict-transport-security");
      if (v == null) return verdict("unverifiable", v === null ? "edge varies" : "no response");
      const want = claim.text.match(/max-age=(\d+)/)?.[1];
      return yesNo(Boolean(v) && (!want || new RegExp(`max-age="?${want}\\b`, "i").test(v)), v || "absent");
    }
    case "F:header_missing_strict_transport_security": {
      const v = header("strict-transport-security");
      if (v == null) return verdict("unverifiable", v === null ? "edge varies" : "no response");
      return yesNo(!v, v || "absent");
    }
    case "nosniff_set": {
      const v = header("x-content-type-options");
      if (v == null) return verdict("unverifiable", "edge varies or no response");
      return yesNo(/nosniff/i.test(v), v || "absent");
    }
    case "referrer_policy_set": {
      const v = header("referrer-policy");
      if (v == null) return verdict("unverifiable", "edge varies or no response");
      const want = claim.text.match(/\(([^)]+)\)/)?.[1];
      return yesNo(Boolean(v) && (!want || v.toLowerCase().includes(want.toLowerCase())), v || "absent");
    }
    case "framing_restricted": {
      const xfo = header("x-frame-options"), csp = header("content-security-policy");
      if (xfo == null || csp == null) return verdict("unverifiable", "edge varies or no response");
      return yesNo(/deny|sameorigin/i.test(xfo) || /frame-ancestors/i.test(csp), `XFO=${xfo || "-"} fa=${/frame-ancestors/i.test(csp)}`);
    }
    case "csp_no_unsafe_script":
    case "F:csp_weak_policy": {
      const csp = header("content-security-policy");
      if (csp == null) return verdict("unverifiable", "edge varies or no response");
      if (!csp) return verdict("fp", "no CSP header");
      const script = cspDirective(csp, "script-src"), style = cspDirective(csp, "style-src");
      if (claim.id === "csp_no_unsafe_script") return yesNo(!unsafe(script), `script-src ${script?.join(" ").slice(0, 80)}`);
      if (/no script-src or default-src/.test(claim.text)) return yesNo(script == null, `script-src/default-src ${script == null ? "absent" : "present"}`);
      const scope = /style-src only/.test(claim.text) ? "style" : "script";
      const ok = scope === "style" ? unsafe(style) && !unsafe(script) : unsafe(script);
      return yesNo(ok, `${scope}: script ${unsafe(script)} style ${unsafe(style)}`);
    }
    case "F:security_headers_not_observed": {
      const names = { "Content Security Policy (CSP)": "content-security-policy", "X-Frame-Options": "x-frame-options",
        "X-Content-Type-Options": "x-content-type-options", "Referrer-Policy": "referrer-policy",
        "Permissions-Policy": "permissions-policy", "Strict-Transport-Security": "strict-transport-security" };
      const listed = Object.entries(names).filter(([label]) => claim.text.includes(label)).map(([, h]) => h);
      const values = listed.map((h) => header(h));
      if (values.some((v) => v == null)) return verdict("unverifiable", "edge varies or no response");
      const present = listed.filter((h, i) => values[i]);
      return yesNo(present.length === 0, present.length ? `present: ${present.join(",")}` : `${listed.length} absent`);
    }
    default:
      return verdict("unverifiable", "no independent verifier for this claim");
  }
}

// Every claim the preview makes: counted findings plus domain-card statements.
export function previewClaims(preview) {
  const claims = preview.preview_findings.map((f) => ({ id: `F:${f.id}`, module: "finding", text: f.description || f.title }));
  const domains = Array.isArray(preview.security_domains) ? preview.security_domains : preview.cyber_mot_domains;
  for (const d of domains) for (const o of d.observed || []) claims.push({ id: o.id, module: o.module, text: o.text, domain_key: d.domain_key });
  for (const d of domains) if (d.state === "assessed_healthy") claims.push({ id: `healthy:${d.domain_key}`, module: "domain", text: d.summary });
  return claims;
}

export async function measureDomain(domain) {
  const { settlements, execution } = await runFreeScanSettlements(domain);
  const preview = buildFreeScanPreview({ domain, scannedAt: new Date().toISOString(),
    freeScanEvidence: buildFreeScanEvidence(settlements), execution });
  const ssl = settlements.ssl.status === "fulfilled" ? settlements.ssl.value : {};
  const httpsHost = ssl.www_fallback_used ? `www.${domain}` : domain;
  const ctx = { httpsHost, https: await curl(`https://${httpsHost}/`), http: await curl(`http://${domain}/`) };
  const claims = [];
  for (const claim of previewClaims(preview)) claims.push({ ...claim, ...(await verifyClaim(domain, claim, ctx)) });
  return { domain, claims };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const domains = (arg("only") || "").split(",").map((d) => d.trim()).filter(Boolean);
  const rows = [];
  for (const domain of domains) {
    rows.push(await measureDomain(domain));
    process.stderr.write(`${domain} `);
  }
  process.stderr.write("\n");
  const byClaim = new Map();
  for (const row of rows) for (const c of row.claims) {
    const key = c.id.startsWith("F:") ? c.id : `${c.module}:${c.id}`;
    const tally = byClaim.get(key) || { tp: 0, fp: 0, unverifiable: 0 };
    tally[c.label] += 1; byClaim.set(key, tally);
  }
  const total = { tp: 0, fp: 0, unverifiable: 0 };
  console.log("| claim | TP | FP | unverifiable | precision |\n|---|---|---|---|---|");
  for (const [key, t] of [...byClaim].sort()) {
    for (const k of Object.keys(total)) total[k] += t[k];
    const p = t.tp + t.fp ? `${((100 * t.tp) / (t.tp + t.fp)).toFixed(0)}%` : "n/a";
    console.log(`| ${key} | ${t.tp} | ${t.fp} | ${t.unverifiable} | ${p} |`);
  }
  console.log(`| **all** | ${total.tp} | ${total.fp} | ${total.unverifiable} | ${total.tp + total.fp ? ((100 * total.tp) / (total.tp + total.fp)).toFixed(1) : "n/a"}% |`);
  console.log("\nFalse positives and unverifiable claims:");
  for (const row of rows) for (const c of row.claims) if (c.label !== "tp") console.log(`- ${c.label.toUpperCase()} ${row.domain} ${c.id}: ${c.evidence}`);
  if (arg("json")) fs.writeFileSync(arg("json"), JSON.stringify(rows, null, 2));
}
