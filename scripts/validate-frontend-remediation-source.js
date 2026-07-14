#!/usr/bin/env node
//
// Frontend-is-not-a-remediation-source contract. CI-blocking.
//
// Proves frontend/src/data/remediation.js no longer independently DEFINES
// customer-facing remediation meaning: buildRemediationIntelligence takes the
// backend-supplied canonical `finding.remediation` for every semantic field
// (title, business impact, recommended action, owner, effort, verification), and
// only supplies presentation detail (step-by-step + a CLI command) keyed strictly
// by canonical remediation_id. A resolved remediation's title/action CANNOT be
// overridden by the frontend.
// Node 24+.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const file = path.join(root, "frontend", "src", "data", "remediation.js");
const mod = await import(pathToFileURL(file).href);
const { buildRemediationIntelligence, REMEDIATION_STEPS } = mod;

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, a, b) => ok(n, a === b, `expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);

// A server-canonical remediation with SENTINEL semantic values. If the frontend
// echoes these, it is not overriding them with its own copy.
const serverRem = {
  remediation_id: "email.spf.publish",
  customer_title: "SENTINEL_TITLE",
  business_impact: "SENTINEL_IMPACT",
  recommended_action: "SENTINEL_ACTION",
  effort: "low",
  owner_type: "customer_it",
  verification_method: "dns_recheck",
  verification_evidence_requirements: "SENTINEL_EVIDENCE",
};
const out = buildRemediationIntelligence({ id: "email_missing_spf", severity: "high", remediation: serverRem });

ok("returns an object for a finding with a server remediation", Boolean(out));
eq("title comes from the server (not overridden)", out.title, "SENTINEL_TITLE");
eq("business_impact comes from the server", out.business_impact, "SENTINEL_IMPACT");
eq("recommended_action comes from the server", out.recommended_action, "SENTINEL_ACTION");
eq("verification_method comes from the server", out.verification_method, "dns_recheck");
eq("verification_evidence comes from the server", out.verification_evidence, "SENTINEL_EVIDENCE");
eq("remediation_id is the canonical id", out.remediation_id, "email.spf.publish");
// owner/effort are presentation labels DERIVED from server enums, not authored.
ok("owner is derived from server owner_type", typeof out.owner === "string" && out.owner.length > 0);
ok("effort is derived from server effort enum", typeof out.effort === "string" && out.effort.length > 0);
// priority is a presentation mapping of finding.severity, not a remediation semantic.
eq("priority derives from severity (high→P2)", out.priority, "P2");

// Honest failure: no server remediation → no frontend-invented remediation.
eq("null when finding has no server remediation", buildRemediationIntelligence({ id: "email_missing_spf", severity: "high" }), null);
eq("null when finding.remediation is explicitly null", buildRemediationIntelligence({ id: "x", remediation: null }), null);
eq("null for falsy finding", buildRemediationIntelligence(null), null);

// Steps/verification are presentation ONLY, keyed by canonical remediation_id,
// and contain no semantic fields that could drift from the registry.
ok("REMEDIATION_STEPS is keyed by dotted canonical remediation_ids",
  Object.keys(REMEDIATION_STEPS).every((k) => /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/.test(k)),
  Object.keys(REMEDIATION_STEPS).filter((k) => !/\./.test(k)).join(", "));
ok("REMEDIATION_STEPS entries contain ONLY steps + verification (no semantics)",
  Object.values(REMEDIATION_STEPS).every((v) => Object.keys(v).every((f) => f === "steps" || f === "verification")),
  "an entry carries a semantic field (business_impact/owner/effort/title)");
// Steps for a finding are looked up by the SERVER's remediation_id, not by the
// finding id — so they cannot attach to the wrong remediation.
ok("steps resolve by the server remediation_id",
  Array.isArray(out.steps) && out.steps.length === (REMEDIATION_STEPS["email.spf.publish"]?.steps?.length ?? 0));
// An unknown remediation_id yields no steps rather than a wrong/borrowed set.
const unknownIdOut = buildRemediationIntelligence({ id: "x", severity: "low", remediation: { remediation_id: "not.a.real.id", customer_title: "T", recommended_action: "A", business_impact: "B", effort: "medium", owner_type: "customer" } });
eq("unknown remediation_id → empty steps (no borrowed procedure)", unknownIdOut.steps.length, 0);

// Static guard: the source must not re-introduce a finding-type-keyed semantic
// library (the old drift source).
const src = fs.readFileSync(file, "utf8");
ok("source does not define a finding-type-keyed LIBRARY/METADATA semantic map",
  !/\bconst\s+LIBRARY\b/.test(src) && !/\bMETADATA_ONLY\b/.test(src));
ok("source does not author business_impact string literals (pass-through of rem.* is fine)",
  !/business_impact\s*:\s*['"`]/.test(src));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
