#!/usr/bin/env node
//
// Canonical remediation registry — contract + behavioural proof. CI-blocking.
//
// Proves the single source of truth for customer-facing remediation content:
//   • stable dotted IDs that are NOT derived from mutable display copy
//   • exactly the eight canonical Cyber MOT domain keys
//   • every registered finding type resolves; aliases resolve to the same
//     canonical remediation; deprecated entries forward safely
//   • unknown finding types FAIL HONESTLY (no unrelated generic advice)
//   • no surface changes the business meaning (resolver is surface-invariant, and
//     the wired backend generators emit the SAME canonical action)
//   • historical reports keep resolving (legacy ids via aliases)
//   • honest scope wording per domain (Identity, Shadow IT, certificates, CE)
//   • deterministic output; no duplicate active ids; no conflicting primary
// Node 24+.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const enginesDir = path.join(root, "workers", "scan-api", "src", "engines");
const imp = (f) => import(pathToFileURL(path.join(enginesDir, f)).href);

const reg = await imp("remediation-registry.js");
const {
  REMEDIATION_REGISTRY, CANONICAL_DOMAIN_KEYS, FINDING_TYPE_ALIASES,
  resolveRemediation, listRegisteredFindingTypes, getRemediationById,
  canonicalRecommendedAction,
} = reg;

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, a, b) => ok(n, a === b, `expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);

// ── 1. Stable IDs, not derived from mutable display copy ─────────────────────
const idPattern = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;
ok("all remediation_ids are stable dotted slugs",
  REMEDIATION_REGISTRY.every((e) => idPattern.test(e.remediation_id)),
  REMEDIATION_REGISTRY.filter((e) => !idPattern.test(e.remediation_id)).map((e) => e.remediation_id).join(","));
// An id must not be a slugified customer_title — identity is independent of copy.
const slug = (s) => String(s).toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "");
ok("ids are NOT slugified titles (identity independent of copy)",
  REMEDIATION_REGISTRY.every((e) => e.remediation_id !== slug(e.customer_title)));

// ── 2. Exactly eight canonical domain keys ───────────────────────────────────
eq("exactly 8 canonical domain keys", CANONICAL_DOMAIN_KEYS.length, 8);
const DOMAIN_SET = new Set(CANONICAL_DOMAIN_KEYS);
ok("every entry uses a canonical domain key",
  REMEDIATION_REGISTRY.every((e) => DOMAIN_SET.has(e.domain_key)),
  REMEDIATION_REGISTRY.filter((e) => !DOMAIN_SET.has(e.domain_key)).map((e) => e.remediation_id).join(","));
ok("no unexpected domain keys",
  [...DOMAIN_SET].every((k) => [
    "email_protection","brand_protection","attack_surface","certificates_trust",
    "cyber_essentials_readiness","website_security","identity_exposure","shadow_it_unmanaged_technology",
  ].includes(k)));

// ── 3. Every registered finding type resolves ────────────────────────────────
const registered = listRegisteredFindingTypes();
ok("registered finding types are non-empty", registered.length > 0);
const unresolved = registered.filter((ft) => resolveRemediation({ finding_type: ft }).status !== "resolved");
ok("every registered finding type resolves", unresolved.length === 0, `unresolved: ${unresolved.join(",")}`);

// ── 4. Aliases resolve to the same canonical remediation ─────────────────────
let aliasMismatch = [];
for (const [legacy, canonical] of Object.entries(FINDING_TYPE_ALIASES)) {
  const a = resolveRemediation({ finding_type: legacy });
  const b = resolveRemediation({ finding_type: canonical });
  if (a.status !== "resolved" || a.remediation_id !== b.remediation_id) aliasMismatch.push(legacy);
}
ok("every alias resolves to the same canonical remediation", aliasMismatch.length === 0, aliasMismatch.join(","));
eq("alias resolution is flagged matched_via=alias",
  resolveRemediation({ finding_type: "email_no_spf" }).matched_via, "alias");

// ── 5. Deprecated entries resolve safely (forward to replacement) ────────────
const dep = resolveRemediation({ finding_type: "email_dmarc_reject_now" });
eq("deprecated finding type resolves", dep.status, "resolved");
eq("deprecated forwards to replacement", dep.remediation_id, "email.dmarc.enforce");
eq("deprecated resolution is flagged", dep.matched_via, "deprecated");
ok("deprecated resolution records the source id", dep.deprecated_from === "email.dmarc.reject_immediately");
ok("deprecated entry is retrievable by id and marked deprecated",
  getRemediationById("email.dmarc.reject_immediately")?.status === "deprecated");
// A deprecated entry must NEVER own a finding type an active entry claims.
const activeFts = new Set(REMEDIATION_REGISTRY.filter((e) => e.status === "active").flatMap((e) => e.finding_types));
ok("deprecated entries never claim an active finding type",
  REMEDIATION_REGISTRY.filter((e) => e.status === "deprecated").every((e) => e.finding_types.every((ft) => !activeFts.has(ft))));

// ── 6. Unknown finding types fail honestly (NO generic advice) ───────────────
const unknown = resolveRemediation({ finding_type: "totally_made_up_finding_xyz" });
eq("unknown finding type → status unknown", unknown.status, "unknown");
eq("unknown → no remediation_id", unknown.remediation_id, null);
eq("unknown → no recommended_action (no generic advice)", unknown.recommended_action, null);
eq("unknown → no customer_title", unknown.customer_title, null);
eq("empty finding type → unknown", resolveRemediation({ finding_type: "" }).status, "unknown");
eq("missing finding type → unknown", resolveRemediation({}).status, "unknown");
eq("canonicalRecommendedAction(unknown) is null", canonicalRecommendedAction("totally_made_up_finding_xyz"), null);

// ── 7. No surface changes the business meaning ───────────────────────────────
for (const ft of ["email_missing_spf", "asset_exposure_admin_interface", "ssl_certificate_expired"]) {
  const surfaces = ["scan_detail", "scorecard", "executive_report", "pdf", "managed_case"].map(
    (s) => resolveRemediation({ finding_type: ft, surface: s }));
  const ids = new Set(surfaces.map((r) => r.remediation_id));
  const actions = new Set(surfaces.map((r) => r.recommended_action));
  ok(`surface-invariant remediation_id for ${ft}`, ids.size === 1);
  ok(`surface-invariant recommended_action for ${ft}`, actions.size === 1);
}

// ── 7b. Wired backend generators emit the SAME canonical meaning ─────────────
const { computeScore } = await imp("scoring.js");
const { buildEmailRemediationActions } = await imp("email-analysis.js");
const { computeBusinessRiskScore } = await imp("business-risk.js");

const scoreRes = computeScore({
  dns: { resolves: true },
  ssl: { https_accessible: false, http_redirects_to_https: false },
  email_security: { applicable: true, dmarc: { present: false }, spf: { present: false }, dkim: { present: true } },
}, "example.com");
const dmarcCanonical = resolveRemediation({ finding_type: "email_missing_dmarc" }).recommended_action;
const scoreDmarcRec = scoreRes.recommendations.find((r) => r.title === resolveRemediation({ finding_type: "email_missing_dmarc" }).customer_title);
ok("scoring.js DMARC recommendation carries the canonical action",
  Boolean(scoreDmarcRec) && scoreDmarcRec.description.startsWith(dmarcCanonical),
  scoreDmarcRec ? scoreDmarcRec.description.slice(0, 60) : "no dmarc rec");
// The honesty fix: DMARC advice ramps from p=none, never jumps to p=reject.
ok("canonical DMARC advice ramps (mentions p=none, not reject-first)",
  /p=none/.test(dmarcCanonical) && !/^[^.]*p=reject/.test(dmarcCanonical));

const emailActions = buildEmailRemediationActions("example.com",
  { spf_detail: { mechanisms: [], all_qualifier: null }, dmarc_detail: { raw: null }, dkim_detail: { selectors_checked: [] }, bimi_readiness: {} },
  { mta_sts: true, tls_rpt: true });
const emailDmarc = emailActions.find((a) => a.id === "dmarc_missing");
eq("email-analysis DMARC card uses the canonical action",
  emailDmarc?.recommended_action, resolveRemediation({ finding_type: "dmarc_missing" }).recommended_action);
ok("email-analysis DMARC card preserves its concrete DNS record",
  Boolean(emailDmarc?.suggested_dns_record));

const brs = computeBusinessRiskScore(new Set(["email_missing_dmarc"]), {});
const brsDmarc = (brs.top_business_risks || brs.top_concerns || []).find((r) => /DMARC/i.test(r.title));
ok("business-risk DMARC recommendation is the canonical action (no p=reject conflict)",
  Boolean(brsDmarc) && brsDmarc.recommendation === dmarcCanonical,
  brsDmarc ? brsDmarc.recommendation.slice(0, 60) : "no brs dmarc risk");

// ── 8. Historical compatibility (legacy ids via aliases) ─────────────────────
for (const [legacy, canonical] of [
  ["email_no_dmarc", "email.dmarc.publish"],
  ["email_no_spf", "email.spf.publish"],
  ["header_missing_strict-transport-security", "web.header.hsts"],
  ["expired", "cert.expiry.expired"],
]) {
  eq(`legacy id "${legacy}" still resolves to ${canonical}`,
    resolveRemediation({ finding_type: legacy }).remediation_id, canonical);
}
// Per-host suffix finding types normalise to their canonical prefix.
eq("subdomain_sensitive_<host> normalises",
  resolveRemediation({ finding_type: "subdomain_sensitive_dev.example.com" }).remediation_id, "asm.subdomain.sensitive");

// ── 9. Identity scope wording (NO credential-breach / dark-web claim) ────────
const identityEntries = REMEDIATION_REGISTRY.filter((e) => e.domain_key === "identity_exposure");
ok("identity entries exist", identityEntries.length > 0);
const identityText = (e) => `${e.customer_title} ${e.technical_explanation} ${e.business_impact} ${e.recommended_action}`.toLowerCase();
// Flag AFFIRMATIVE capability claims (we detect/monitor breaches), not honest
// disclaimers ("not any credential or breach data") which legitimately use the word.
const affirmsBreach = /(detect|monitor|scan|find|check)[^.]{0,40}(breach|leaked|dark[- ]?web)|breached[- ]password|leaked[- ]credential|dark[- ]?web monitoring/;
ok("identity entries make NO affirmative breach/credential/dark-web claim",
  identityEntries.every((e) => !affirmsBreach.test(identityText(e))),
  identityEntries.filter((e) => affirmsBreach.test(identityText(e))).map((e) => e.remediation_id).join(","));
ok("identity entries state the exposed-surface-only scope limitation",
  identityEntries.every((e) => e.limitations.some((l) => /leaked-credential|breached-password|dark-web|exposed sign-in/i.test(l))));

// ── 10. Shadow IT external-scope wording (observed, not unauthorised) ────────
const shadow = REMEDIATION_REGISTRY.filter((e) => e.domain_key === "shadow_it_unmanaged_technology");
ok("shadow IT entries exist", shadow.length > 0);
ok("shadow IT entries scope to externally OBSERVED usage",
  shadow.every((e) => /external/i.test(`${e.technical_explanation} ${e.applicability}`)));
ok("shadow IT entries do not assert services are unauthorised or internally seen",
  shadow.every((e) => e.limitations.some((l) => /externally observed|does not see inside|not.*unauthorised/i.test(l))));

// ── 11. Certificate unknown semantics stay explicit ──────────────────────────
const certUnknown = resolveRemediation({ finding_type: "ct_sources_unavailable" });
eq("certificate CT-incomplete verification is 'unsupported'", certUnknown.verification_method, "unsupported");
ok("certificate unknown entry names chain/OCSP/revocation as unknown",
  certUnknown.limitations.some((l) => /chain|ocsp|revocation/i.test(l)));

// ── 12. Cyber Essentials external-certification wording ──────────────────────
const ce = REMEDIATION_REGISTRY.filter((e) => e.domain_key === "cyber_essentials_readiness");
ok("CE entries exist", ce.length > 0);
ok("CE entries keep certification external (IASME / not issued by us)",
  ce.every((e) => /iasme|external/i.test(`${e.recommended_action} ${e.verification_evidence_requirements}`)));
ok("CE entries never claim to issue certification",
  ce.every((e) => e.limitations.some((l) => /not a cyber essentials certification|does not.*certification/i.test(l))));

// ── 13. Deterministic output ─────────────────────────────────────────────────
const r1 = resolveRemediation({ finding_type: "email_missing_spf", surface: "pdf" });
const r2 = resolveRemediation({ finding_type: "email_missing_spf", surface: "pdf" });
ok("resolver output is deterministic", JSON.stringify(r1) === JSON.stringify(r2));

// ── 14. No duplicate active remediation ids ──────────────────────────────────
const activeIds = REMEDIATION_REGISTRY.filter((e) => e.status === "active").map((e) => e.remediation_id);
eq("no duplicate active remediation ids", activeIds.length, new Set(activeIds).size);

// ── 15. No conflicting primary remediation for a finding type ────────────────
// buildFindingTypeIndex throws at import time on a conflict, so a successful
// import already proves this; assert explicitly that each active finding type is
// owned by exactly one active entry.
const ownerCount = new Map();
for (const e of REMEDIATION_REGISTRY.filter((x) => x.status === "active")) {
  for (const ft of e.finding_types) ownerCount.set(ft, (ownerCount.get(ft) || 0) + 1);
}
const conflicting = [...ownerCount.entries()].filter(([, n]) => n > 1).map(([ft]) => ft);
ok("no finding type has two active primary owners", conflicting.length === 0, conflicting.join(","));

// ── Evidence-dependent applicability (contract behaviour) ────────────────────
const bimiNo = resolveRemediation({ finding_type: "bimi_not_configured", evidence: { dmarc_enforced: false } });
const bimiYes = resolveRemediation({ finding_type: "bimi_not_configured", evidence: { dmarc_enforced: true } });
eq("BIMI not applicable when DMARC not enforced", bimiNo.applicable, false);
eq("BIMI applicable when DMARC enforced", bimiYes.applicable, true);
eq("BIMI still resolves regardless of applicability", bimiNo.status, "resolved");

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
