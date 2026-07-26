#!/usr/bin/env node
//
// Item 8 PR-B — deterministic IDN generation + passive CT discovery.
// Pins bounded volume, A-label dedupe, customer-owned IDN exclusion,
// corroboration-tier risk, additive API evidence, and fail-honest wording data.
import path from "node:path";
import fs from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (file) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", file)).href;
let pass = 0, fail = 0;
const ok = (name, condition, detail = "") => {
  if (condition) pass++;
  else { fail++; console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
};
const eq = (name, got, want) => ok(
  name,
  JSON.stringify(got) === JSON.stringify(want),
  `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`,
);

const {
  generateIdnHomographCandidates,
  BRAND_IDN_GENERATION_LIMIT,
} = await import(eng("idn-homograph.js"));
const { generateTyposquatCandidates } = await import(eng("brand-typosquat.js"));
const {
  brandCandidateToApi,
  normalizeBrandVariantType,
  scoreBrandCandidateRisk,
} = await import(eng("brand-protection.js"));
const {
  BRAND_CT_QUERY_CAP,
  brandCtQueryUrls,
  buildDiscoveredCandidateRisk,
  buildLookalikeBaseSet,
  canonicalBrandHostname,
  discoverBrandCandidatesForWorkspace,
  filterDiscoveredHosts,
  parseCtResponseHostnames,
} = await import(eng("brand-passive-discovery.js"));

// ── 1. Bounded, deterministic generation ────────────────────────────────────
const generated = generateIdnHomographCandidates("apple", "com");
ok("canonical Cyrillic-a IDN is generated",
  generated.some((item) => item.candidate_domain === "xn--pple-43d.com"));
eq("canonical IDN variant", generated.find((item) =>
  item.candidate_domain === "xn--pple-43d.com")?.variant_type, "homoglyph_idn");
eq("canonical Unicode display form", generated.find((item) =>
  item.candidate_domain === "xn--pple-43d.com")?.unicode_domain, "\u0430pple.com");
ok("generation is bounded", generated.length > 0 && generated.length <= BRAND_IDN_GENERATION_LIMIT);
eq("generation is deterministic", generateIdnHomographCandidates("apple", "com"), generated);
eq("short brand refused", generateIdnHomographCandidates("ab", "com"), []);
eq("non-ASCII brand is not expanded speculatively", generateIdnHomographCandidates("\u0430pple", "com"), []);

const allCandidates = generateTyposquatCandidates("apple", "com");
ok("canonical generator includes an IDN family",
  allCandidates.some((item) => item.variant_type === "homoglyph_idn"));
ok("additive global population remains bounded", allCandidates.length <= 44);
ok("generated IDNs never invent live evidence", allCandidates
  .filter((item) => item.variant_type === "homoglyph_idn")
  .every((item) => item.risk_level === "medium" &&
    !("dns_active" in item) && !("https_active" in item) && !("mx_present" in item)));
eq("homoglyph_idn is canonical vocabulary",
  normalizeBrandVariantType("homoglyph_idn"), "homoglyph_idn");

// ── 2. CT query expansion + A-label canonicalisation ─────────────────────────
const urls = brandCtQueryUrls("apple", "com");
ok("literal brand query is preserved", urls.some((url) => decodeURIComponent(url).includes("%apple%")));
ok("punycode query closes literal-token blind spot",
  urls.some((url) => decodeURIComponent(url).includes("xn--pple-43d.com")));
ok("CT query plan is bounded", urls.length >= 2 && urls.length <= BRAND_CT_QUERY_CAP);
eq("Unicode hostname canonicalises to A-label",
  canonicalBrandHostname("\u0430pple.com"), "xn--pple-43d.com");
eq("A-label remains canonical",
  canonicalBrandHostname("XN--PPLE-43D.COM"), "xn--pple-43d.com");
eq("invalid hostname fails closed", canonicalBrandHostname("not a host"), null);

const parsed = parseCtResponseHostnames([
  { name_value: "\u0430pple.com\nxn--pple-43d.com\nlogin.xn--pple-43d.com" },
]);
eq("Unicode + A-label CT forms dedupe",
  parsed.filter((host) => host === "xn--pple-43d.com").length, 1);
ok("nested IDN SAN is retained canonically", parsed.includes("login.xn--pple-43d.com"));

// ── 3. Skeleton-aware membership + customer-owned IDN exclusion ──────────────
const bases = buildLookalikeBaseSet("apple", "com");
ok("generated IDN is an allowed lookalike base", bases.has("xn--pple-43d.com"));
const discovered = filterDiscoveredHosts([
  "xn--pple-43d.com",
  "login.xn--pple-43d.com",
  "xn--e1afmkfd.xn--p1ai",
], {
  brand: "apple",
  tld: "com",
  ownRegistrables: new Set(["apple.com"]),
  lookalikeBases: bases,
});
eq("bare IDN is typed as homoglyph_idn",
  discovered.find((item) => item.candidate_domain === "xn--pple-43d.com")?.variant_type,
  "homoglyph_idn");
eq("nested IDN host preserves nested_host type",
  discovered.find((item) => item.candidate_domain === "login.xn--pple-43d.com")?.variant_type,
  "nested_host");
ok("unrelated punycode is not admitted",
  !discovered.some((item) => item.candidate_domain === "xn--e1afmkfd.xn--p1ai"));

const owned = filterDiscoveredHosts([
  "xn--pple-43d.com",
  "login.xn--pple-43d.com",
], {
  brand: "apple",
  tld: "com",
  // Unicode customer input must exclude the equivalent A-label and its hosts.
  ownRegistrables: new Set(["\u0430pple.com"]),
  lookalikeBases: bases,
});
eq("customer-owned Unicode IDN and nested hosts are excluded", owned, []);

// ── 4. Corroboration tiers + API evidence ────────────────────────────────────
const bareHost = discovered.find((item) => item.candidate_domain === "xn--pple-43d.com");
const ctOnly = buildDiscoveredCandidateRisk(bareHost, "apple");
eq("bare CT IDN remains low until activity is observed", ctOnly.risk.risk_level, "low");
ok("bare CT risk records the activity boundary",
  ctOnly.risk.reasons.includes("idn_candidate_not_yet_live"));
ok("CT evidence contains visual-confusable fact",
  ctOnly.evidence.some((item) => item.signal === "idn_visual_confusable" && item.value === true));

const dnsOnly = scoreBrandCandidateRisk({
  variant_type: "homoglyph_idn",
  similarity_score: 100,
  idn_visual_confusable: true,
  mixed_script: true,
  ct_observed: true,
  dns_active: true,
  classification: "unreviewed",
});
eq("DNS-active IDN is prioritised but not critical without service evidence",
  dnsOnly.risk_level, "high");
ok("DNS-only critical ceiling is explicit",
  dnsOnly.reasons.includes("idn_dns_only_not_critical"));

const serving = scoreBrandCandidateRisk({
  variant_type: "homoglyph_idn",
  similarity_score: 100,
  idn_visual_confusable: true,
  mixed_script: true,
  ct_observed: true,
  dns_active: true,
  https_active: true,
  classification: "unreviewed",
});
eq("DNS + HTTPS corroboration may reach critical", serving.risk_level, "critical");

const api = brandCandidateToApi({
  id: "bra_idn",
  domain: "apple.com",
  candidate_domain: "xn--pple-43d.com",
  variant_type: "homoglyph_idn",
  similarity_score: 100,
  classification: "unreviewed",
  dns_resolves: null,
  https_available: null,
  evidence_json: JSON.stringify([{ signal: "ct_observed", value: true }]),
}, { brand_name: "apple", primary_domain: "apple.com" });
eq("API exposes safe Unicode display form", api.unicode_domain, "\u0430pple.com");
ok("API exposes structured IDN facts", api.idn_homograph?.visually_confusable === true &&
  api.idn_homograph?.mixed_script === true);
ok("API does not call a CT-only candidate malicious",
  !JSON.stringify(api).toLowerCase().includes("malicious"));
const brandPage = fs.readFileSync(
  path.join(root, "frontend", "src", "pages", "ws", "BrandMonitoringPage.jsx"),
  "utf8",
);
ok("customer surface labels the exact IDN evidence",
  brandPage.includes("Visually confusable IDN"));
ok("customer surface states the non-verdict boundary",
  brandPage.includes("lookalike signal, not proof of abuse"));
ok("customer surface never claims confirmed phishing",
  !brandPage.toLowerCase().includes("confirmed phishing"));

// ── 5. End-to-end: only the A-label query returns the CT observation ──────────
{
  const db = new DatabaseSync(":memory:");
  db.exec(`
    CREATE TABLE workspace_domains (workspace_id TEXT, domain_id TEXT);
    CREATE TABLE domains (id TEXT PRIMARY KEY, domain TEXT, created_at TEXT);
    CREATE TABLE workspace_brand_assets (
      id TEXT PRIMARY KEY, workspace_id TEXT, domain TEXT, candidate_domain TEXT,
      variant_type TEXT, similarity_score INTEGER, risk_level TEXT,
      risk_reasons TEXT, evidence_json TEXT, dns_resolves INTEGER,
      https_available INTEGER, ip_address TEXT, status TEXT, classification TEXT,
      first_seen TEXT, last_seen TEXT, last_checked_at TEXT, created_at TEXT,
      updated_at TEXT, UNIQUE (workspace_id, domain, candidate_domain)
    );
  `);
  db.prepare("INSERT INTO domains VALUES (?,?,?)").run("d1", "apple.com", "2026-01-01T00:00:00Z");
  db.prepare("INSERT INTO workspace_domains VALUES (?,?)").run("ws1", "d1");
  const env = { cybermeters_db: {
    prepare(sql) {
      const statement = db.prepare(sql);
      return {
        bind: (...args) => ({
          all: async () => ({ results: statement.all(...args) }),
          run: async () => statement.run(...args),
          first: async () => statement.get(...args) ?? null,
        }),
      };
    },
  } };
  const requested = [];
  const fetchImpl = async (url) => {
    requested.push(decodeURIComponent(url));
    const body = decodeURIComponent(url).includes("xn--pple-43d.com")
      ? [{ name_value: "login.xn--pple-43d.com", common_name: "xn--pple-43d.com" }]
      : [];
    return {
      ok: true,
      headers: { get: () => "application/json" },
      json: async () => body,
    };
  };
  const stats = await discoverBrandCandidatesForWorkspace(env, "ws1", { fetchImpl });
  ok("end-to-end query fan-out is bounded",
    stats.queries_attempted === requested.length && requested.length <= BRAND_CT_QUERY_CAP);
  ok("A-label-only CT observation is discovered", stats.discovered >= 2, `got ${stats.discovered}`);
  const row = db.prepare(
    "SELECT * FROM workspace_brand_assets WHERE workspace_id = ? AND candidate_domain = ?",
  ).get("ws1", "xn--pple-43d.com");
  eq("bare discovered row keeps canonical variant", row?.variant_type, "homoglyph_idn");
  eq("bare CT-only row persists low risk", row?.risk_level, "low");
  eq("activity remains unknown until the existing enrichment sweep runs", row?.dns_resolves, null);
  ok("durable evidence contains exact visual-confusable signal",
    JSON.parse(row?.evidence_json || "[]")
      .some((item) => item.signal === "idn_visual_confusable" && item.value === true));
}

console.log(`\nBrand IDN discovery PR-B: ${pass}/${pass + fail} passed`);
if (fail) process.exit(1);
console.log("Brand IDN discovery PR-B validation passed");
