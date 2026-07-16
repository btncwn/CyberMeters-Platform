#!/usr/bin/env node
//
// Universal Managed-Case Model — contract + behavioural proof. CI-blocking.
//
// Proves the shared 8-domain case platform:
//   • exactly eight domain keys; valid base states; permitted/forbidden edges;
//   • verified requires system + verification evidence (a scan alone cannot verify);
//   • accepted-risk / false-positive are never the verified phase;
//   • reopen preserves prior evidence/history; canonical remediation linkage +
//     honest unknown; ASM & Brand backward compatibility (their machines are
//     registered and still drive transitions); deterministic output;
//   • the append-only history event is emitted; the universal route routes every
//     mutation through canTransitionCase (no bypass) and is workspace-scoped +
//     soft-delete gated; the frontend defines NO transition map (cannot invent
//     transitions); migration 082 adds the universal columns additively.
// Node 24+.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const enginesDir = path.join(root, "workers", "scan-api", "src", "engines");
const imp = (f) => import(pathToFileURL(path.join(enginesDir, f)).href);

const mcm = await imp("managed-case-model.js");
const {
  CANONICAL_DOMAIN_KEYS, CANONICAL_CASE_STATES, CANONICAL_TERMINAL_STATES,
  CASE_TYPE_REGISTRY, DEFAULT_CASE_TYPE_BY_DOMAIN, canTransitionCase,
  canonicalPhaseFor, caseRemediationId, isValidDomainKey,
} = mcm;

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, a, b) => ok(n, a === b, `expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);

const mkCase = (over = {}) => ({ id: "mc-test", workspace_id: "ws1", case_type: "email_case", status: "detected", ...over });

// ── 1. Exactly eight domain keys ─────────────────────────────────────────────
eq("exactly 8 canonical domain keys", CANONICAL_DOMAIN_KEYS.length, 8);
const DOMAINS = ["email_protection","brand_protection","attack_surface","certificates_trust","cyber_essentials_readiness","website_security","identity_exposure","shadow_it_unmanaged_technology"];
ok("domain keys match the canonical Cyber MOT set", DOMAINS.every((d) => CANONICAL_DOMAIN_KEYS.includes(d)) && CANONICAL_DOMAIN_KEYS.every((d) => DOMAINS.includes(d)));
ok("every domain key has a default case_type", DOMAINS.every((d) => DEFAULT_CASE_TYPE_BY_DOMAIN[d]));
ok("every registered case_type maps to a valid domain key", Object.values(CASE_TYPE_REGISTRY).every((e) => isValidDomainKey(e.domain_key)));
eq("all eight domains are represented by a case_type", new Set(Object.values(CASE_TYPE_REGISTRY).map((e) => e.domain_key)).size, 8);

// ── 2. Valid base states ─────────────────────────────────────────────────────
const EXPECT_BASE = ["detected","triaged","assigned","approved","action_in_progress","awaiting_verification","verified","monitoring","reopened"];
ok("canonical base states are exactly the nine lifecycle keys", EXPECT_BASE.every((s) => CANONICAL_CASE_STATES.includes(s)) && CANONICAL_CASE_STATES.length === 9);
const EXPECT_TERM = ["rejected","accepted_risk","false_positive","closed_no_action","superseded"];
ok("canonical terminal/exceptional states are the five outcomes", EXPECT_TERM.every((s) => CANONICAL_TERMINAL_STATES.includes(s)) && CANONICAL_TERMINAL_STATES.length === 5);
ok("state keys are machine-stable snake_case", [...CANONICAL_CASE_STATES, ...CANONICAL_TERMINAL_STATES].every((s) => /^[a-z][a-z0-9_]*$/.test(s)));

// ── 3. Permitted transitions ─────────────────────────────────────────────────
ok("detected → triaged permitted", canTransitionCase({ case: mkCase(), target_status: "triaged", actor: { actor_type: "customer", actor_id: "u1" } }).ok);
ok("triaged → assigned permitted (with owner)", canTransitionCase({ case: mkCase({ status: "triaged" }), target_status: "assigned", actor: { actor_type: "customer", actor_id: "u1" }, owner_ref: "team-a" }).ok);
ok("action_in_progress → awaiting_verification permitted", canTransitionCase({ case: mkCase({ status: "action_in_progress" }), target_status: "awaiting_verification", actor: { actor_type: "customer", actor_id: "u1" } }).ok);

// ── 4. Forbidden transitions ─────────────────────────────────────────────────
eq("detected → verified forbidden (skips lifecycle)", canTransitionCase({ case: mkCase(), target_status: "verified", actor: { actor_type: "system" }, evidence: { verified: true } }).code, "invalid_transition");
eq("triaged → monitoring forbidden", canTransitionCase({ case: mkCase({ status: "triaged" }), target_status: "monitoring", actor: { actor_type: "customer" } }).code, "invalid_transition");
eq("terminal false_positive cannot transition", canTransitionCase({ case: mkCase({ status: "false_positive" }), target_status: "triaged", actor: { actor_type: "customer" } }).ok, false);
eq("assigned requires an owner (guard)", canTransitionCase({ case: mkCase({ status: "triaged" }), target_status: "assigned", actor: { actor_type: "customer" } }).code, "invalid_transition");

// ── 5/6. Verified requires STRUCTURED evidence; scan/note alone cannot verify ─
// Base (manual) domains verify via a structured attestation from an identified
// actor. A bare flag / scan / note never verifies.
//
// The vehicle is `identity_case`, not `email_case`. email/website/cyber_essentials now
// derive their verification support from each case's own canonical remediation (see
// verificationSupportForCase), so they are no longer examples of "base manual" — their
// answer depends on what the registry says about the finding. identity_case still is one:
// nothing external can confirm an identity fix, so attestation remains its honest ceiling.
// The contract below is unchanged; only the case type that demonstrates it moved.
const av = mkCase({ status: "awaiting_verification", case_type: "identity_case" });
const attn = { verification_method: "manual_attestation", verification_result: "verified", evidence_type: "attestation", observed_at: "2026-07-14T00:00:00Z", attestation: { by: "u1", statement: "fixed" } };
eq("verified with NO evidence is refused", canTransitionCase({ case: av, target_status: "verified", actor: { actor_type: "customer", actor_id: "u1" } }).code, "verify_requires_evidence");
eq("verified from a bare scan completion is refused", canTransitionCase({ case: av, target_status: "verified", actor: { actor_type: "customer", actor_id: "u1" }, evidence: { scan_completed_only: true } }).code, "verify_requires_evidence");
eq("verified from a customer note alone is refused", canTransitionCase({ case: av, target_status: "verified", actor: { actor_type: "customer", actor_id: "u1" }, evidence: { note_only: true } }).code, "verify_requires_evidence");
eq("verified with a bare {verified:true} flag is refused (not structured)", canTransitionCase({ case: av, target_status: "verified", actor: { actor_type: "customer", actor_id: "u1" }, evidence: { verified: true } }).code, "verify_requires_evidence");
eq("manual attestation without an actor is refused", canTransitionCase({ case: av, target_status: "verified", actor: { actor_type: "customer" }, evidence: attn }).reason, "attestation_actor_required");
ok("base manual attestation with structured evidence + actor succeeds", canTransitionCase({ case: av, target_status: "verified", actor: { actor_type: "customer", actor_id: "u1" }, evidence: attn }).ok);
// Automated (ASM) verified state is CyberMeters-only.
const asmVfy = mkCase({ status: "verifying", case_type: "asm_exposure" });
eq("ASM resolved by a customer is refused (system-only)", canTransitionCase({ case: asmVfy, target_status: "resolved", actor: { actor_type: "customer", actor_id: "u1" }, evidence: { verification_method: "automated_probe", verification_result: "fixed", evidence_type: "http_probe", observed_at: "2026-07-14T00:00:00Z", observation: { status: 404 } } }).code, "system_only");
eq("ASM resolved with a failed result is refused", canTransitionCase({ case: asmVfy, target_status: "resolved", actor: { actor_type: "system" }, evidence: { verification_method: "automated_probe", verification_result: "still_present", evidence_type: "http_probe", observed_at: "2026-07-14T00:00:00Z", observation: { status: 200 } } }).reason, "verification_not_positive");
eq("ASM resolved with unsupported method is refused", canTransitionCase({ case: asmVfy, target_status: "resolved", actor: { actor_type: "system" }, evidence: { verification_method: "unsupported", verification_result: "fixed", evidence_type: "x", observed_at: "2026-07-14T00:00:00Z", observation: {} } }).reason, "verification_unsupported");
ok("ASM resolved with a complete positive probe result succeeds", canTransitionCase({ case: asmVfy, target_status: "resolved", actor: { actor_type: "system" }, evidence: { verification_method: "automated_probe", verification_result: "fixed", evidence_type: "http_probe", observed_at: "2026-07-14T00:00:00Z", observation: { status: 404 } } }).ok);

// ── 7/8. Accepted-risk and false-positive are NEVER the verified phase ───────
ok("accepted_risk phase ≠ verified (base)", canonicalPhaseFor("email_case", "accepted_risk") === "accepted_risk");
ok("false_positive phase ≠ verified (base)", canonicalPhaseFor("email_case", "false_positive") === "false_positive");
ok("ASM risk_accepted folds to accepted_risk, not verified", canonicalPhaseFor("asm_exposure", "risk_accepted") === "accepted_risk");
ok("ASM false_positive folds to false_positive, not verified", canonicalPhaseFor("asm_exposure", "false_positive") === "false_positive");
// No non-verified state anywhere folds onto the verified phase.
for (const [ct, entry] of Object.entries(CASE_TYPE_REGISTRY)) {
  const verifiedStates = new Set(entry.verified_states);
  const wrong = Object.entries(entry.phase).filter(([s, p]) => p === "verified" && !verifiedStates.has(s)).map(([s]) => s);
  ok(`${ct}: only its verified state folds to the verified phase`, wrong.length === 0, wrong.join(","));
}

// ── 9. Reopen preserves prior evidence/history ───────────────────────────────
const verifiedCase = mkCase({ status: "verified", evidence_json: JSON.stringify({ finding: "orig", captured: "yes" }) });
const reopened = canTransitionCase({ case: verifiedCase, target_status: "reopened", actor: { actor_type: "system" } });
ok("verified → reopened permitted (system)", reopened.ok);
eq("reopen keeps the prior evidence_json intact", reopened.case.evidence_json, verifiedCase.evidence_json);
ok("reopen stamps reopened_at", Boolean(reopened.ok && reopened.case.reopened_at));

// ── 10/11. Canonical remediation linkage + honest unknown ────────────────────
eq("case remediation resolves the canonical id from source_finding_type", caseRemediationId({ source_finding_type: "email_missing_spf" }), "email.spf.publish");
eq("case remediation resolves via finding_id fallback", caseRemediationId({ finding_id: "asset_exposure_admin_interface" }), "asm.exposure.admin");
eq("unknown finding → null remediation (honest, no invented link)", caseRemediationId({ source_finding_type: "totally_unknown_xyz" }), null);
eq("no finding → null remediation", caseRemediationId({}), null);

// ── 12/13. ASM & Brand backward compatibility (their machines still drive) ───
// ASM open → triage using its own machine, via the universal validator.
const asmCase = { id: "mc-asm", workspace_id: "ws1", case_type: "asm_exposure", status: "open" };
ok("ASM open → triage still works via canTransitionCase", canTransitionCase({ case: asmCase, target_status: "triage", actor: { actor_type: "customer", actor_id: "u1" } }).ok);
eq("ASM forbidden edge still rejected", canTransitionCase({ case: asmCase, target_status: "resolved", actor: { actor_type: "system" }, evidence: { decision: "fixed", completeness: "complete" } }).code, "invalid_transition");
// Brand detected → triage.
const brandCase = { id: "mc-brand", workspace_id: "ws1", case_type: "brand_abuse", status: "detected" };
ok("Brand detected → triage still works via canTransitionCase", canTransitionCase({ case: brandCase, target_status: "triage", actor: { actor_type: "customer", actor_id: "u1" } }).ok);
// Brand system-only 'resolved' cannot be customer-set.
eq("Brand resolved is system-only", canTransitionCase({ case: { ...brandCase, status: "verification_pending" }, target_status: "resolved", actor: { actor_type: "customer" }, evidence: { verified: true } }).code, "system_only");

// ── 16. Deterministic output ─────────────────────────────────────────────────
const d1 = canTransitionCase({ case: mkCase({ status: "triaged" }), target_status: "assigned", actor: { actor_type: "customer", actor_id: "u1" }, owner_ref: "t", now: "2026-07-14T00:00:00Z" });
const d2 = canTransitionCase({ case: mkCase({ status: "triaged" }), target_status: "assigned", actor: { actor_type: "customer", actor_id: "u1" }, owner_ref: "t", now: "2026-07-14T00:00:00Z" });
ok("transition output is deterministic for fixed inputs", JSON.stringify(d1) === JSON.stringify(d2));

// ── 17. Append-only history event emitted (never mutates prior) ──────────────
const withEvent = canTransitionCase({ case: mkCase(), target_status: "triaged", actor: { actor_type: "customer", actor_id: "u1" } });
ok("a transition returns an append-only event descriptor", Boolean(withEvent.event && withEvent.event.from_status === "detected" && withEvent.event.to_status === "triaged"));
ok("event carries case + workspace + actor for audit", withEvent.event.case_id === "mc-test" && withEvent.event.workspace_id === "ws1" && withEvent.event.actor_type === "customer");
// Unknown case_type is rejected (no silent write).
eq("unknown case_type is rejected", canTransitionCase({ case: mkCase({ case_type: "nope" }), target_status: "triaged", actor: { actor_type: "customer" } }).code, "unknown_case_type");

// ── 18. Static guards — no bypass, isolation, frontend cannot invent ─────────
const stripComments = (s) => s.replace(/\/\/[^\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "");
const routeSrc = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "routes", "managed-cases.js"), "utf8");
const routeCode = stripComments(routeSrc);
ok("universal route imports the transition validator", /import\s*\{[^}]*canTransitionCase[^}]*\}\s*from\s*["']\.\.\/engines\/managed-case-model\.js["']/.test(routeCode));
// No bypass: the persisted status is the VALIDATOR's output (next.status from
// canTransitionCase), never a raw client-supplied status.
ok("universal route mutates ONLY through canTransitionCase (persists validator output)",
  /const\s+decision\s*=\s*canTransitionCase\(/.test(routeCode) && /const\s+next\s*=\s*decision\.case/.test(routeCode) && /\.bind\(\s*\n?\s*next\.status/.test(routeCode));
ok("universal route scopes every case query by workspace_id", /WHERE id = \? AND workspace_id = \?/.test(routeCode));
ok("universal route gates on soft-delete (deleted_at IS NULL)", /deleted_at IS NULL/.test(routeCode));
ok("universal route returns the SAME 'Case not found' for foreign + nonexistent", /Case not found/.test(routeCode));

// No status mutation bypasses the validator: ASM + Brand engines route through
// canTransitionCase and NO raw applyCaseTransition status-mutation remains in them.
const asmEngine = stripComments(fs.readFileSync(path.join(enginesDir, "asm-cases.js"), "utf8"));
const brandEngine = stripComments(fs.readFileSync(path.join(enginesDir, "brand-cases.js"), "utf8"));
ok("ASM engine imports + uses canTransitionCase", /canTransitionCase\(/.test(asmEngine) && /from\s*["']\.\/managed-case-model\.js["']/.test(asmEngine));
ok("Brand engine imports + uses canTransitionCase", /canTransitionCase\(/.test(brandEngine) && /from\s*["']\.\/managed-case-model\.js["']/.test(brandEngine));
ok("ASM engine has NO raw applyCaseTransition status-mutation (no bypass)", !/applyCaseTransition\s*\(/.test(asmEngine));
ok("Brand engine has NO raw applyCaseTransition status-mutation (no bypass)", !/applyCaseTransition\s*\(/.test(brandEngine));
ok("ASM updateCaseStatus routes through canTransitionCase", /async function updateCaseStatus[\s\S]{0,400}canTransitionCase\(/.test(asmEngine));
ok("ASM casCaseStatus validates via canTransitionCase before the CAS write", /async function casCaseStatus[\s\S]{0,500}canTransitionCase\([\s\S]{0,400}UPDATE managed_cases SET status/.test(asmEngine));
ok("Brand applyBrandTransition routes through canTransitionCase", /async function applyBrandTransition[\s\S]{0,400}canTransitionCase\(/.test(brandEngine));
// The neutral machine modules exist (cycle-break) and the model imports them.
ok("ASM machine extracted to a neutral leaf module", fs.existsSync(path.join(enginesDir, "asm-case-machine.js")));
ok("Brand machine extracted to a neutral leaf module", fs.existsSync(path.join(enginesDir, "brand-case-machine.js")));
const modelSrc = stripComments(fs.readFileSync(path.join(enginesDir, "managed-case-model.js"), "utf8"));
ok("model imports machines from neutral modules (no cycle)",
  /from\s*["']\.\/asm-case-machine\.js["']/.test(modelSrc) && /from\s*["']\.\/brand-case-machine\.js["']/.test(modelSrc)
  && !/from\s*["']\.\/asm-cases\.js["']/.test(modelSrc) && !/from\s*["']\.\/brand-cases\.js["']/.test(modelSrc));
// The universal create route uses the common factory.
ok("universal route creates via the common factory createManagedCase", /createManagedCase\(/.test(routeCode));

const asmSrc = stripComments(fs.readFileSync(path.join(enginesDir, "asm-cases.js"), "utf8"));
ok("ASM auto-open gates soft-deleted workspaces", /deleted_at IS NULL/.test(asmSrc));
ok("ASM case creation sets domain_key + remediation_id", /domain_key/.test(asmSrc) && /remediation_id/.test(asmSrc));

const caseDisplayCode = stripComments(fs.readFileSync(path.join(root, "frontend", "src", "lib", "caseDisplay.js"), "utf8"));
ok("frontend caseDisplay defines NO transition map (cannot invent transitions)",
  !/transitions?\s*[:=]/i.test(caseDisplayCode) && !/canTransition/i.test(caseDisplayCode));
const queueCode = stripComments(fs.readFileSync(path.join(root, "frontend", "src", "components", "CasesQueue.jsx"), "utf8"));
ok("frontend CasesQueue does not hardcode allowed target states",
  !/target_status\s*:\s*['"]/.test(queueCode));

// ── 19. Migration 082 adds the universal columns additively ──────────────────
const migSrc = fs.readFileSync(path.join(root, "database", "migrations", "082-universal-managed-cases.sql"), "utf8");
for (const col of ["domain_key","source_finding_type","source_scan_id","remediation_id","title","summary","priority","assigned_user_id","business_owner","technical_owner","approved_at","action_started_at","awaiting_verification_at","verified_at","monitoring_started_at","reopened_at","accepted_at","closed_at"]) {
  ok(`migration adds column ${col}`, new RegExp(`ADD COLUMN ${col}\\b`).test(migSrc));
}
ok("migration is additive (no destructive statement)", !/\b(DROP\s+TABLE|DROP\s+COLUMN|DELETE\s+FROM|TRUNCATE)\b/i.test(migSrc.replace(/--[^\n]*/g, "")));
ok("migration back-fills domain_key for existing ASM + Brand rows",
  /UPDATE managed_cases SET domain_key = 'attack_surface'/.test(migSrc) && /UPDATE managed_cases SET domain_key = 'brand_protection'/.test(migSrc));

// ── 13. Verification support is derived from the REGISTRY, per case ──────────
// THE DEFECT THIS EXISTS TO PREVENT: verification support used to be a property of the
// case_type, and a case_type is the wrong grain. Email Protection holds BOTH a hosted DMARC
// record CyberMeters re-observes by DNS and a sender review the registry says the product
// cannot observe at all. Under a per-type answer, one of those is always wrong:
//   • blanket `manual`    → a customer's assertion concludes verification for a DNS record
//                           we check ourselves (the rule this increment must preserve);
//   • blanket `automated` → the attestation-only findings become unverifiable FOREVER,
//                           because no system verifier can exist for them.
// The Canonical Remediation Registry already decided this per finding, and CLAUDE.md makes
// it the source of truth for verification method. So the model asks it.
{
  const { verificationSupportForCase } = mcm;
  const c = (case_type, remediation_id, over = {}) =>
    ({ id: "mc-v", workspace_id: "ws1", case_type, remediation_id, status: "awaiting_verification", ...over });

  // Observable findings → only CyberMeters verifies.
  eq("website https_recheck → automated", verificationSupportForCase(c("website_case", "web.https.redirect")), "automated");
  eq("email dns_recheck → automated", verificationSupportForCase(c("email_case", "email.dmarc.publish")), "automated");
  eq("CE rescan → automated", verificationSupportForCase(c("cyber_essentials_case", "ce.readiness.control_review")), "automated");

  // The registry says the product cannot observe these → attestation is the honest ceiling.
  eq("email manual_attestation → manual", verificationSupportForCase(c("email_case", "email.dkim.verify")), "manual");
  eq("CE manual_attestation → manual", verificationSupportForCase(c("cyber_essentials_case", "ce.access.saas_review")), "manual");

  // Fail closed: an unresolvable or absent remediation is not an invitation to self-certify.
  eq("a case with NO remediation is unsupported, not manual", verificationSupportForCase(c("website_case", null)), "unsupported");
  eq("a case with an unknown remediation is unsupported", verificationSupportForCase(c("website_case", "web.does.not.exist")), "unsupported");

  // Closed increments keep their own per-type answer — this derivation is opt-in.
  eq("identity_case still answers from its case_type", verificationSupportForCase(c("identity_case", "web.https.redirect")), "manual");
  eq("shadow_it_case still answers from its case_type", verificationSupportForCase(c("shadow_it_case", "web.https.redirect")), "manual");
  eq("asm keeps automated", verificationSupportForCase(c("asm_exposure", null)), "automated");

  // ── The rule this increment exists to preserve, end to end ────────────────
  const obs = c("website_case", "web.https.redirect");
  const attestation = {
    verification_method: "manual_attestation", verification_result: "verified",
    evidence_type: "attestation", observed_at: "2026-07-16T00:00:00Z",
    attestation: { by: "u1", statement: "I fixed it" },
  };
  const byCustomer = canTransitionCase({ case: obs, target_status: "verified", actor: { actor_type: "customer", actor_id: "u1" }, evidence: attestation });
  ok("a CUSTOMER cannot verify an observable website condition, even with a structured attestation",
    byCustomer.ok === false);
  eq("and is told why", byCustomer.code, "verify_requires_system");

  const bySystem = canTransitionCase({
    case: obs, target_status: "verified", actor: { actor_type: "system" },
    evidence: { verification_method: "https_recheck", verification_result: "fixed", evidence_type: "http_probe", observed_at: "2026-07-16T00:00:00Z", observation: { status: 200 } },
  });
  ok("CyberMeters' own re-observation DOES verify it", bySystem.ok === true);

  // …while the attestation-only finding keeps the path the registry endorses.
  const att = c("email_case", "email.dkim.verify");
  ok("a customer CAN attest the finding the product genuinely cannot observe",
    canTransitionCase({ case: att, target_status: "verified", actor: { actor_type: "customer", actor_id: "u1" }, evidence: attestation }).ok === true);
  // But never on a bare note — the evidence contract still applies.
  eq("and a bare note still does not verify it",
    canTransitionCase({ case: att, target_status: "verified", actor: { actor_type: "customer", actor_id: "u1" }, evidence: { note_only: true } }).code,
    "verify_requires_evidence");
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
