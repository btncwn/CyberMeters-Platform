#!/usr/bin/env node
// Builds workers/scan-api/src/lib/cloud-networks-data.js from the address-range
// lists that cloud and edge providers publish for public use.
//
//   node scripts/build-cloud-networks.js <YYYY-MM-DD.N>
//   node scripts/build-cloud-networks.js <YYYY-MM-DD.N> --from <dir>
//
// Without --from it downloads each list from the provider's own published
// address (SOURCES below). With --from it reads the same files from a folder
// (names in SOURCES[].file), so a build can be repeated byte for byte. The
// output records each input's address, retrieval date and SHA-256, the entry
// count and the SHA-256 of the entries.
//
// Updating: re-run with a new version, review the count change, update the
// pinned values in scripts/validate-cloud-networks.js, and commit both. The
// running product never fetches a list.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalCidr, parseCidr, NETWORK_PROVIDERS } from "../workers/scan-api/src/lib/cloud-network-ranges.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUTPUT = path.join(root, "workers", "scan-api", "src", "lib", "cloud-networks-data.js");

// The regional list of one provider is published on a download page whose file
// name changes weekly; the page is read to find the current file.
const WEEKLY_LIST_PAGE = "https://www.microsoft.com/en-us/download/details.aspx?id=56519";
const WEEKLY_LIST_FILE = /https:\/\/download\.microsoft\.com\/download\/[^"'\s]+\/ServiceTags_Public_\d{8}\.json/;

export const SOURCES = Object.freeze([
  { provider: "aws", file: "aws.json", url: "https://ip-ranges.amazonaws.com/ip-ranges.json", parse: "aws" },
  { provider: "gcp", file: "gcp.json", url: "https://www.gstatic.com/ipranges/cloud.json", parse: "gcp" },
  { provider: "azure", file: "azure.json", url: null, page: WEEKLY_LIST_PAGE, parse: "azure" },
  { provider: "cloudflare", file: "cloudflare-v4.txt", url: "https://www.cloudflare.com/ips-v4", parse: "list" },
  { provider: "cloudflare", file: "cloudflare-v6.txt", url: "https://www.cloudflare.com/ips-v6", parse: "list" },
]);

const clean = (v) => String(v ?? "").trim().replace(/[\t\n\r]/g, " ");

// Each parser returns rows { cidr, region, service } exactly as published.
export const PARSERS = Object.freeze({
  aws(text) {
    const data = JSON.parse(text);
    const rows = [];
    for (const p of data.prefixes || []) rows.push({ cidr: p.ip_prefix, region: p.region, service: p.service });
    for (const p of data.ipv6_prefixes || []) rows.push({ cidr: p.ipv6_prefix, region: p.region, service: p.service });
    return rows.map((r) => ({ ...r, region: r.region === "GLOBAL" ? "" : r.region }));
  },
  gcp(text) {
    const data = JSON.parse(text);
    return (data.prefixes || []).map((p) => ({ cidr: p.ipv4Prefix || p.ipv6Prefix, region: p.scope === "global" ? "" : p.scope, service: "" }));
  },
  azure(text) {
    const data = JSON.parse(text);
    const rows = [];
    // Only the per-region cloud tags: every published cloud address, with its region.
    for (const tag of data.values || []) {
      if (!/^AzureCloud\.[a-z0-9]+$/i.test(tag?.name || "")) continue;
      for (const cidr of tag.properties?.addressPrefixes || []) rows.push({ cidr, region: tag.properties?.region || "", service: "" });
    }
    return rows;
  },
  list(text) {
    return String(text).split(/\r?\n/).map((l) => l.trim()).filter(Boolean).map((cidr) => ({ cidr, region: "", service: "" }));
  },
});

// One row per (provider, network). Within a provider the more specific service
// wins over the provider-wide one (e.g. a compute range over the umbrella row).
const GENERIC_SERVICES = new Set(["", "AMAZON"]);

export function buildEntries(inputs) {
  const byKey = new Map();
  for (const { provider, rows } of inputs) {
    if (!NETWORK_PROVIDERS[provider]) throw new Error(`unknown provider ${provider}`);
    for (const row of rows) {
      const cidr = canonicalCidr(row.cidr);
      if (!cidr) throw new Error(`${provider}: not a network: ${JSON.stringify(row.cidr)}`);
      const region = clean(row.region).toLowerCase();
      const service = clean(row.service).toUpperCase();
      const key = `${provider}\t${cidr}`;
      const prev = byKey.get(key);
      if (!prev || (GENERIC_SERVICES.has(prev.service) && !GENERIC_SERVICES.has(service))) {
        byKey.set(key, { provider, cidr, region: region || prev?.region || "", service: GENERIC_SERVICES.has(service) ? "" : service });
      }
    }
  }
  const seen = new Map();
  for (const row of byKey.values()) {
    const p = parseCidr(row.cidr);
    const net = `${p.version}/${p.bits}/${p.network}`;
    if (seen.has(net) && seen.get(net) !== row.provider) {
      throw new Error(`${row.cidr} is published by both ${seen.get(net)} and ${row.provider}`);
    }
    seen.set(net, row.provider);
  }
  return [...byKey.values()]
    .map((r) => [r.cidr, r.provider, r.region, r.service].join("\t"))
    .sort();
}

export function digest(lines) {
  return crypto.createHash("sha256").update(lines.join("\n"), "utf8").digest("hex");
}

async function download(url) {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

async function resolveSource(source, fromDir) {
  if (fromDir) {
    const file = path.join(fromDir, source.file);
    return { url: source.url ?? `${source.page} (current weekly file)`, bytes: fs.readFileSync(file) };
  }
  let url = source.url;
  if (!url) {
    const page = (await download(source.page)).toString("utf8");
    url = page.match(WEEKLY_LIST_FILE)?.[0];
    if (!url) throw new Error(`${source.page}: current list file not found`);
  }
  return { url, bytes: await download(url) };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [version, flag, fromDir] = process.argv.slice(2);
  if (!/^\d{4}-\d{2}-\d{2}\.\d+$/.test(version || "") || (flag && flag !== "--from") || (flag && !fromDir)) {
    console.error("usage: node scripts/build-cloud-networks.js <YYYY-MM-DD.N> [--from <dir>]");
    process.exit(2);
  }
  const retrieved = new Date().toISOString().slice(0, 10);
  const inputs = [], sources = [];
  for (const source of SOURCES) {
    const { url, bytes } = await resolveSource(source, fromDir);
    const rows = PARSERS[source.parse](bytes.toString("utf8"));
    if (!rows.length) throw new Error(`${url}: no ranges`);
    inputs.push({ provider: source.provider, rows });
    sources.push({ provider: source.provider, url, retrieved, sha256: crypto.createHash("sha256").update(bytes).digest("hex"), rows: rows.length });
  }
  const entries = buildEntries(inputs);
  const header = `// GENERATED by scripts/build-cloud-networks.js — do not edit by hand.
//
// Address ranges that cloud and edge providers publish for public use, one row
// per network: "network/bits<TAB>provider<TAB>region<TAB>service". Used only to
// say which provider network an observed address belongs to; it does not show
// whose account runs a server. Sources, retrieval dates and input hashes are
// recorded below.
`;
  const body = `export const CLOUD_NETWORK_LIST = Object.freeze({
  version: ${JSON.stringify(version)},
  sources: ${JSON.stringify(sources, null, 2).replace(/\n/g, "\n  ")},
  count: ${entries.length},
  sha256: ${JSON.stringify(digest(entries))},
  entries: ${JSON.stringify(entries.join("\n"))},
});
`;
  fs.writeFileSync(OUTPUT, `${header}${body}`);
  console.log(`Wrote ${path.relative(root, OUTPUT)}: ${entries.length} ranges, version ${version}, sha256 ${digest(entries)}`);
  for (const s of sources) console.log(`  ${s.provider}: ${s.rows} rows from ${s.url} (sha256 ${s.sha256})`);
}
