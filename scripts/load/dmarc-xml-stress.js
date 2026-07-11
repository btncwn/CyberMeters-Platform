#!/usr/bin/env node
//
// DMARC aggregate-XML parse stress. RUA reports from large senders (Google,
// Microsoft) can contain thousands of <record> rows. This generates aggregate
// reports of increasing size and measures parseDmarcAggregateXml's time +
// resulting record count, so we know where parsing cost becomes a concern before
// a real tenant hits it. Standalone (no server needed): node scripts/load/dmarc-xml-stress.js
//
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const { parseDmarcAggregateXml } = await import(
  pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib", "dmarc-ingest.js")).href
);

function buildAggregate(recordCount) {
  const rows = [];
  for (let i = 0; i < recordCount; i++) {
    const ip = `203.0.${(i >> 8) & 255}.${i & 255}`;
    rows.push(
      `<record><row><source_ip>${ip}</source_ip><count>${1 + (i % 5)}</count>` +
      `<policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>` +
      `<identifiers><header_from>example.co.uk</header_from></identifiers>` +
      `<auth_results><dkim><domain>example.co.uk</domain><result>pass</result></dkim>` +
      `<spf><domain>example.co.uk</domain><result>pass</result></spf></auth_results></record>`
    );
  }
  return `<?xml version="1.0"?><feedback><report_metadata><org_name>stress</org_name>` +
    `<report_id>stress-${recordCount}</report_id></report_metadata>` +
    `<policy_published><domain>example.co.uk</domain><p>none</p></policy_published>` +
    rows.join("") + `</feedback>`;
}

const sizes = [10, 100, 1000, 5000, 10000];
console.log("records |  xml KB | parse ms | parsed rows");
console.log("--------|---------|----------|------------");
for (const n of sizes) {
  const xml = buildAggregate(n);
  const start = performance.now();
  let parsed;
  try { parsed = parseDmarcAggregateXml(xml); } catch (e) { console.log(`${n} → parse ERROR: ${e.message}`); continue; }
  const ms = performance.now() - start;
  const rows = Array.isArray(parsed?.records) ? parsed.records.length : (Array.isArray(parsed) ? parsed.length : "?");
  console.log(`${String(n).padStart(7)} | ${String(Math.round(xml.length / 1024)).padStart(7)} | ${ms.toFixed(1).padStart(8)} | ${rows}`);
}
console.log("\nRecord the numbers above in scripts/load/README.md when they shift materially.");
