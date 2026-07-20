#!/usr/bin/env node
//
// Brand typosquat generator — TLD substitution, credential keywords, family
// quotas, speculative-risk honesty. CI-blocking.
//
// Proves the PR-A fix for the lookalike-coverage blocker (brand audit,
// 2026-07-20): the generator was TLD-locked (acme.com could never produce
// acme.co) and its keyword sets missed the credential-phishing vocabulary
// (password / office365 / m365 / microsoft / otp / mfa). Also guards the two
// regressions the fix could introduce:
//   1. speculative-risk honesty — computeScore turns high/critical generated
//      candidates into scored findings (−3/−5); an UNREGISTERED permutation
//      must never be born high, or every customer's Brand score would drop on
//      speculation. Persistence-side risk stays owned by scoreBrandCandidateRisk
//      (registration-reality gate: unregistered → capped 'low').
//   2. family crowd-out — without per-family floors inside MAX_BRAND_CANDIDATES,
//      the enlarged keyword set + TLD swaps out-score and eject the
//      homoglyph/typo variants for longer brands.
//
// Honest limits asserted (NOT bugs — later sprint stages):
//   - nested hosts (office365password.acme.co) are NOT generated (PR-B: passive/CT);
//   - multi-keyword forms (secure-acme-login.com) are NOT generated;
//   - no HTTP/TLS/live-surface signal is set at generation time (PR-C).
//
// Node 24+.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href;

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

const {
  extractBrandParts, generateTyposquatCandidates, runTyposquatModule,
  HIGH_RISK_BRAND_KEYWORDS, CONFUSABLE_TLD_SWAPS,
} = await import(eng("brand-typosquat.js"));
const { normalizeBrandVariantType, scoreBrandCandidateRisk } = await import(eng("brand-protection.js"));

const acme = generateTyposquatCandidates("acme", "com");
const acmeDomains = new Set(acme.map((c) => c.candidate_domain));
const has = (d) => acmeDomains.has(d);
const variantOf = (d) => acme.find((c) => c.candidate_domain === d)?.variant_type;

// ── 1. Founder regression matrix — TLD substitution (acme.com) ───────────────
ok("acme.co generated", has("acme.co"));
eq("acme.co variant_type", variantOf("acme.co"), "tld_variation");
ok("acme.net generated", has("acme.net"));
ok("acme.org generated", has("acme.org"));
ok("acme.io generated", has("acme.io"));
ok("acme.app generated", has("acme.app"));
ok("acme.uk generated", has("acme.uk"));
ok("acme.co.uk generated", has("acme.co.uk"));
ok("own domain acme.com NEVER a candidate", !has("acme.com"));
{
  const swaps = acme.filter((c) => c.variant_type === "tld_variation");
  eq("one swap per confusable TLD except own", swaps.length, CONFUSABLE_TLD_SWAPS.length - 1);
  ok("every swap keeps the exact brand label",
    swaps.every((c) => c.candidate_domain.split(".")[0] === "acme"));
}

// ── 2. Founder regression matrix — credential keyword expansion ──────────────
ok("a password keyword candidate is generated",
  acme.some((c) => c.candidate_domain.includes("password")));
ok("an office365 keyword candidate is generated",
  acme.some((c) => c.candidate_domain.includes("office365")));
ok("acme-password.com generated", has("acme-password.com"));
ok("acme-office365.com generated", has("acme-office365.com"));
ok("acme-m365.com generated", has("acme-m365.com"));
ok("pre-existing keyword coverage preserved (acme-login.com)", has("acme-login.com"));
ok("credential keywords are in the HIGH set",
  ["password", "office365", "o365", "m365", "microsoft", "otp", "mfa"]
    .every((kw) => HIGH_RISK_BRAND_KEYWORDS.includes(kw)));

// ── 3. Honest limits — later sprint stages must NOT be faked here ────────────
ok("nested host office365password.acme.co NOT generated (PR-B scope)", !has("office365password.acme.co"));
ok("nested host login.acme.co NOT generated (PR-B scope)", !has("login.acme.co"));
ok("nested host secure-login.acme.co NOT generated (PR-B scope)", !has("secure-login.acme.co"));
ok("multi-keyword secure-acme-login.com NOT generated (out of PR-A scope)", !has("secure-acme-login.com"));
ok("true negative: unrelated-example.co NOT generated", !has("unrelated-example.co"));
ok("no live-surface flags invented at generation time",
  acme.every((c) => !("https_active" in c) && !("mx_present" in c) && !("looks_like_login" in c)));

// ── 4. Speculative-risk honesty (scan-score protection) ──────────────────────
// computeScore emits scored findings only for high/critical candidates. Nothing
// the generator invents (unregistered permutations) may be born high/critical.
{
  const mod = runTyposquatModule("acme.com");
  eq("no 'high' candidates at generation", mod.risk_summary.high, 0);
  eq("no 'critical' candidates at generation", mod.risk_summary.critical, 0);
  ok("every tld_variation candidate is born 'medium'",
    acme.filter((c) => c.variant_type === "tld_variation").every((c) => c.risk_level === "medium"));
  eq("module still marks candidates unvalidated", mod.candidates_validated, false);
  eq("module candidate count matches domains", mod.total_candidates_generated, mod.domains.length);
}

// ── 5. Canonical vocabulary + persistence-side risk contract ─────────────────
eq("tld_variation is canonical", normalizeBrandVariantType("tld_variation"), "tld_variation");
{
  // Unregistered swap: registration-reality gate must cap at 'low' (watchlist).
  const unregistered = scoreBrandCandidateRisk({
    variant_type: "tld_variation", similarity_score: 100,
    contains_brand_keyword: true, classification: "unreviewed",
  });
  eq("unregistered TLD swap capped at low", unregistered.risk_level, "low");
  ok("cap reason recorded", unregistered.reasons.includes("not_registered_watchlist"));
  // Registered with mail capability: must surface at least high.
  const live = scoreBrandCandidateRisk({
    variant_type: "tld_variation", similarity_score: 100,
    contains_brand_keyword: true, dns_active: true, mx_present: true,
    classification: "unreviewed",
  });
  ok("DNS+MX-confirmed TLD swap is at least high", ["high", "critical"].includes(live.risk_level));
}

// ── 6. Family quotas — no variant family silently crowded out ────────────────
{
  // Long brand: total candidate space far exceeds the cap. Without quotas the
  // keyword + TLD variants (scores 3–4) eject nearly every character variant
  // (score ≤2): the pre-quota outcome was 1 character variant in the top 40.
  const long = generateTyposquatCandidates("cybermeters", "com");
  const fam = (v) => v === "tld_variation" ? "tld"
    : (v === "hyphen_keyword" || v === "prefix_keyword") ? "keyword" : "character";
  const counts = { tld: 0, keyword: 0, character: 0 };
  for (const c of long) counts[fam(c.variant_type)]++;
  ok("cap respected", long.length <= 40, `got ${long.length}`);
  ok("character variants keep a floor (≥8)", counts.character >= 8, `got ${counts.character}`);
  ok("keyword variants keep a floor (≥8)", counts.keyword >= 8, `got ${counts.keyword}`);
  ok("tld swaps keep a floor (≥5)", counts.tld >= 5, `got ${counts.tld}`);
}

// ── 7. Determinism, dedupe, contract fields ──────────────────────────────────
{
  const again = generateTyposquatCandidates("acme", "com");
  eq("deterministic output", again, acme);
  eq("no duplicate candidates", acmeDomains.size, acme.length);
  ok("cap respected for acme", acme.length <= 40);
  ok("scan-time contract fields preserved",
    acme.every((c) => c.confidence === 40 && c.validation_quality === "weak"));
  ok("internal _score never leaks", acme.every((c) => !("_score" in c)));
  ok("every variant_type normalizes canonically (never 'unknown')",
    acme.every((c) => normalizeBrandVariantType(c.variant_type) !== "unknown"));
}

// ── 8. Multi-label TLD (co.uk brand) + short-brand guards ────────────────────
{
  const bbb = generateTyposquatCandidates("blackbullbarbers", "co.uk");
  ok("co.uk brand: own domain never a candidate",
    !bbb.some((c) => c.candidate_domain === "blackbullbarbers.co.uk"));
  ok("co.uk brand: .com swap generated",
    bbb.some((c) => c.candidate_domain === "blackbullbarbers.com" && c.variant_type === "tld_variation"));
  ok("co.uk brand: .uk swap generated",
    bbb.some((c) => c.candidate_domain === "blackbullbarbers.uk" && c.variant_type === "tld_variation"));
  eq("extractBrandParts multi-label tld", extractBrandParts("blackbullbarbers.co.uk"), { brand: "blackbullbarbers", tld: "co.uk" });
  eq("short brand still returns nothing", generateTyposquatCandidates("ab", "com"), []);
  eq("empty brand still returns nothing", generateTyposquatCandidates("", "com"), []);
}

// ── 9. Own-domain guard under identity-preserving mutations ──────────────────
// Transposing two IDENTICAL adjacent letters regenerates the brand itself
// ('aabrand' → 'aabrand'), so a double-letter brand can reproduce its own
// domain as a "candidate" unless the own-domain guard blocks it. 'aa…' sorts
// first among character variants, so without the guard it deterministically
// lands inside the selected set — a customer would see their own registered
// domain listed as a lookalike.
{
  const dbl = generateTyposquatCandidates("aabrand", "com");
  ok("double-letter brand: own domain never a candidate",
    !dbl.some((c) => c.candidate_domain === "aabrand.com"));
  ok("double-letter brand still yields real candidates", dbl.length > 0);
}

console.log(`\nvalidate-brand-typosquat: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
