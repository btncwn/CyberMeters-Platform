#!/usr/bin/env node
//
// Item 8 PR-B — deterministic IDN generation and generated-scan persistence.
// Pins bounded volume, canonical A-label generation, corroboration-tier risk,
// additive API evidence, fail-honest customer wording, and the generated-scan
// persistence path for IDN candidates.
//
// The passive Certificate Transparency keyword discovery that PR-B originally
// added was removed together with crt.sh. Candidates it stored earlier keep
// their `ct_observed` evidence; this file proves a generated scan re-observing
// such a row keeps that evidence, its history and the customer's decision.
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
const { generateTyposquatCandidates, runTyposquatModule } = await import(eng("brand-typosquat.js"));
const {
  brandCandidateToApi,
  normalizeBrandVariantType,
  scoreBrandCandidateRisk,
} = await import(eng("brand-protection.js"));
const { upsertBrandAssets } = await import(eng("asset-persistence.js"));

// ── 1. Bounded, deterministic generation ────────────────────────────────────
const generated = generateIdnHomographCandidates("apple", "com");
ok("canonical Cyrillic-a IDN is generated",
  generated.some((item) => item.candidate_domain === "xn--pple-43d.com"));
eq("canonical IDN variant", generated.find((item) =>
  item.candidate_domain === "xn--pple-43d.com")?.variant_type, "homoglyph_idn");
eq("canonical Unicode display form", generated.find((item) =>
  item.candidate_domain === "xn--pple-43d.com")?.unicode_domain, "аpple.com");
ok("generation is bounded", generated.length > 0 && generated.length <= BRAND_IDN_GENERATION_LIMIT);
eq("generation is deterministic", generateIdnHomographCandidates("apple", "com"), generated);
eq("short brand refused", generateIdnHomographCandidates("ab", "com"), []);
eq("non-ASCII brand is not expanded speculatively", generateIdnHomographCandidates("аpple", "com"), []);

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

// ── 2. Corroboration tiers + API evidence ────────────────────────────────────
// A stored candidate whose evidence says a certificate naming it was logged
// (ct_observed) is still scored by the canonical risk scorer.
const ctOnly = scoreBrandCandidateRisk({
  variant_type: "homoglyph_idn",
  similarity_score: 100,
  idn_visual_confusable: true,
  mixed_script: true,
  ct_observed: true,
  classification: "unreviewed",
});
eq("bare CT IDN remains low until activity is observed", ctOnly.risk_level, "low");
ok("bare CT risk records the activity boundary",
  ctOnly.reasons.includes("idn_candidate_not_yet_live"));

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
eq("API exposes safe Unicode display form", api.unicode_domain, "аpple.com");
ok("API exposes structured IDN facts", api.idn_homograph?.visually_confusable === true &&
  api.idn_homograph?.mixed_script === true);
ok("API does not call a CT-only candidate malicious",
  !JSON.stringify(api).toLowerCase().includes("malicious"));
const brandPage = fs.readFileSync(
  path.join(root, "frontend", "src", "pages", "ws", "BrandMonitoringPage.jsx"),
  "utf8",
);
const frontendApi = fs.readFileSync(path.join(root, "frontend", "src", "api.js"), "utf8");
ok("customer surface labels the exact IDN evidence",
  brandPage.includes("Visually confusable IDN"));
ok("customer surface states the non-verdict boundary",
  brandPage.includes("lookalike signal, not proof of abuse"));
ok("customer surface never claims confirmed phishing",
  !brandPage.toLowerCase().includes("confirmed phishing"));
ok("stored certificate-log evidence keeps its customer label",
  brandPage.includes("Seen in certificate log"));
ok("customer surface calls no removed Brand discovery route",
  !/runBrandDiscovery|\/brand\/discovery/.test(`${brandPage}\n${frontendApi}`));

// ── 3. End-to-end: generated scan persistence through the canonical writer ───
{
  const NOW = "2026-01-01T00:00:00Z";
  const db = new DatabaseSync(":memory:");
  db.exec(`
    CREATE TABLE workspaces (id TEXT PRIMARY KEY, deleted_at TEXT);
    CREATE TABLE domains (id TEXT PRIMARY KEY, domain TEXT, created_at TEXT);
    CREATE TABLE workspace_domains (workspace_id TEXT, domain_id TEXT);
    CREATE TABLE workspace_brand_profiles (
      id TEXT PRIMARY KEY, workspace_id TEXT UNIQUE, brand_name TEXT,
      primary_domain TEXT, created_at TEXT, updated_at TEXT
    );
    CREATE TABLE workspace_brand_assets (
      id TEXT PRIMARY KEY, workspace_id TEXT, domain TEXT, candidate_domain TEXT,
      variant_type TEXT, similarity_score INTEGER, risk_level TEXT,
      risk_reasons TEXT, evidence_json TEXT, dns_resolves INTEGER,
      https_available INTEGER, mx_present INTEGER, ip_address TEXT, status TEXT,
      classification TEXT, brand_profile_id TEXT, first_seen TEXT, last_seen TEXT,
      last_checked_at TEXT, managed_case_ref TEXT, history_marker TEXT,
      created_at TEXT, updated_at TEXT,
      UNIQUE (workspace_id, domain, candidate_domain)
    );
  `);
  db.prepare("INSERT INTO workspaces VALUES (?,NULL)").run("ws1");
  db.prepare("INSERT INTO domains VALUES (?,?,?)").run("d1", "apple.com", NOW);
  db.prepare("INSERT INTO workspace_domains VALUES (?,?)").run("ws1", "d1");
  db.prepare("INSERT INTO workspace_brand_profiles VALUES (?,?,?,?,?,?)")
    .run("profile_ws1", "ws1", "apple", "apple.com", NOW, NOW);
  const seed = db.prepare(`
    INSERT INTO workspace_brand_assets
      (id, workspace_id, domain, candidate_domain, variant_type, similarity_score,
       risk_level, risk_reasons, evidence_json, dns_resolves, https_available,
       mx_present, status, classification, brand_profile_id, first_seen, last_seen,
       managed_case_ref, history_marker, created_at, updated_at)
    VALUES (?, 'ws1', 'apple.com', ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, 'unverified',
            ?, 'profile_ws1', ?, ?, 'case_keep', 'history_keep', ?, ?)
  `);
  // A historical candidate stored by the retired passive CT producer.
  seed.run("bra_ct_stored", "xn--pple-43d.com", "homoglyph_idn", 100, "low",
    JSON.stringify(["certificate_observed_not_yet_live", "unrelated_customer_context"]),
    JSON.stringify([
      { signal: "ct_observed", value: true },
      { signal: "ct_observation", value: { source: "crt.sh", entry_id: "501", serial_number: "AA501" } },
      { signal: "unrelated_historical_evidence", value: "retain" },
    ]),
    "unreviewed", NOW, "2026-01-02T00:00:00Z", NOW, NOW);
  // A generated lookalike the customer has already declared as their own.
  seed.run("bra_owned", "apple.co", "tld_variation", 100, "info",
    JSON.stringify(["customer_owned_reason"]), JSON.stringify([]),
    "owned", NOW, "2026-01-02T00:00:00Z", NOW, NOW);

  const brandMod = runTyposquatModule("apple.com");
  ok("generated population contains the stored lookalikes",
    ["xn--pple-43d.com", "apple.co"].every((name) =>
      brandMod.domains.some((item) => item.candidate_domain === name)));
  const fresh = brandMod.domains.find((item) =>
    item.variant_type === "homoglyph_idn" && item.candidate_domain !== "xn--pple-43d.com");
  ok("generated population contains a second, unstored IDN", Boolean(fresh));

  await upsertBrandAssets("d1", brandMod, { cybermeters_db: {
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
  } });

  const row = db.prepare(
    "SELECT * FROM workspace_brand_assets WHERE workspace_id = ? AND candidate_domain = ?",
  ).get("ws1", fresh?.candidate_domain ?? "");
  const freshEvidence = JSON.parse(row?.evidence_json || "[]");
  eq("generated IDN persists with canonical variant", row?.variant_type, "homoglyph_idn");
  eq("generated-only IDN persists as a low watchlist item", row?.risk_level, "low");
  ok("generated-only IDN records the registration boundary",
    JSON.parse(row?.risk_reasons || "[]").includes("not_registered_watchlist"));
  eq("activity remains unknown until the existing enrichment sweep runs",
    [row?.dns_resolves, row?.https_available], [null, null]);
  ok("durable evidence contains exact visual-confusable signal",
    freshEvidence.some((item) => item.signal === "idn_visual_confusable" && item.value === true));
  ok("generated persistence never invents certificate-log evidence",
    !freshEvidence.some((item) => item.signal === "ct_observed"));

  const stored = db.prepare("SELECT * FROM workspace_brand_assets WHERE id = 'bra_ct_stored'").get();
  const storedEvidence = JSON.parse(stored?.evidence_json || "[]");
  eq("generated scan reuses the stored CT-observed row",
    db.prepare("SELECT COUNT(*) n FROM workspace_brand_assets WHERE candidate_domain = 'xn--pple-43d.com'").get().n, 1);
  ok("generated scan cannot erase stored CT evidence",
    storedEvidence.some((item) => item.signal === "ct_observed" && item.value === true) &&
    storedEvidence.some((item) => item.signal === "ct_observation" && item.value?.entry_id === "501"));
  ok("generated scan preserves unrelated stored history",
    storedEvidence.some((item) => item.signal === "unrelated_historical_evidence") &&
    JSON.parse(stored?.risk_reasons || "[]").includes("unrelated_customer_context") &&
    stored?.first_seen === NOW &&
    stored?.managed_case_ref === "case_keep" && stored?.history_marker === "history_keep");
  ok("stored CT evidence keeps the CT-only IDN tier",
    stored?.risk_level === "low" &&
    JSON.parse(stored?.risk_reasons || "[]").includes("idn_candidate_not_yet_live"));

  const owned = db.prepare("SELECT * FROM workspace_brand_assets WHERE id = 'bra_owned'").get();
  eq("customer classification outranks generated re-observation",
    [owned?.classification, owned?.risk_level, owned?.risk_reasons],
    ["owned", "info", JSON.stringify(["customer_owned_reason"])]);
}

console.log(`\nBrand IDN discovery PR-B: ${pass}/${pass + fail} passed`);
if (fail) process.exit(1);
console.log("Brand IDN discovery PR-B validation passed");
