#!/usr/bin/env node
//
// Subdomain sensitivity by NAME. A reachable match is scored (-5) and told it
// "suggests development, staging, or administrative use", so only names that
// point away from a normal production service may match. Everyday production
// names (app, api, mail, portal, login...) must never be called a sensitive
// exposure: every business publishes them. Drives the real classifier and the
// real scoring path. Node 24+.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href;
const { isSensitiveSubdomain } = await import(eng("subdomains-scan.js"));
const { computeScore } = await import(eng("scoring.js"));

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const DOMAIN = "example.co.uk";

const PRODUCTION = ["app", "api", "mobile", "mail", "webmail", "smtp", "mx", "portal", "dashboard",
  "auth", "login", "sso", "oauth", "www", "shop", "blog", "status", "help", "docs", "cdn"];
for (const label of PRODUCTION) {
  ok(`production name is not sensitive: ${label}.${DOMAIN}`, !isSensitiveSubdomain(`${label}.${DOMAIN}`, DOMAIN));
}

const SENSITIVE = ["dev", "staging", "stg", "test", "qa", "uat", "sandbox", "preprod", "admin", "cpanel",
  "webmin", "db", "mysql", "redis", "backup", "grafana", "kibana", "jenkins", "gitlab", "internal",
  "intranet", "legacy", "vpn", "rdp", "ftp", "ssh", "jira", "dev2", "stage-eu", "api-dev", "dmarc-test"];
for (const label of SENSITIVE) {
  ok(`non-production or admin name stays sensitive: ${label}.${DOMAIN}`, isSensitiveSubdomain(`${label}.${DOMAIN}`, DOMAIN));
}
ok("a sensitive label deeper in the name still counts", isSensitiveSubdomain(`app.staging.${DOMAIN}`, DOMAIN));
ok("the root domain itself is never sensitive", !isSensitiveSubdomain(DOMAIN, DOMAIN));

// The scored path: reachable app/api produce no sensitive finding and no score
// impact; a reachable staging host still does.
{
  const modules = (names) => ({
    subdomains: { items: names, sensitive: names.filter((h) => isSensitiveSubdomain(h, DOMAIN)), wildcard_dns: false },
    asset_exposure: { assets: names.map((host) => ({ host, reachable: true, status: 200 })) },
  });
  const ids = (result) => (result.findings || []).map((f) => f.id);
  const prod = computeScore(modules([`app.${DOMAIN}`, `api.${DOMAIN}`]), DOMAIN);
  ok("reachable app/api hosts raise no sensitive-subdomain finding",
    !ids(prod).some((id) => String(id).startsWith("subdomain_sensitive_")), ids(prod).join(", "));
  const staging = computeScore(modules([`staging.${DOMAIN}`]), DOMAIN);
  const finding = (staging.findings || []).find((f) => String(f.id).startsWith("subdomain_sensitive_"));
  ok("a reachable staging host is still a scored sensitive finding",
    finding?.severity === "medium" && finding?.score_impact === -5, JSON.stringify(finding));
}

console.log(`\nSubdomain sensitive names: ${pass}/${pass + fail} passed`);
if (fail) { console.error("subdomain sensitive-name validation FAILED"); process.exit(1); }
console.log("subdomain sensitive-name validation passed");
