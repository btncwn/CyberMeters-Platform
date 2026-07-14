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

// ── 5/6. Verified requires evidence; a scan alone cannot verify ──────────────
const av = mkCase({ status: "awaiting_verification" });
eq("verified by a customer is refused (system-only)", canTransitionCase({ case: av, target_status: "verified", actor: { actor_type: "customer" }, evidence: { verified: true } }).code, "system_only");
eq("verified with NO evidence is refused", canTransitionCase({ case: av, target_status: "verified", actor: { actor_type: "system" } }).code, "verify_requires_evidence");
eq("verified from a bare scan completion is refused", canTransitionCase({ case: av, target_status: "verified", actor: { actor_type: "system" }, evidence: { scan_completed_only: true } }).code, "verify_requires_evidence");
ok("verified with a complete 'fixed' probe result succeeds", canTransitionCase({ case: av, target_status: "verified", actor: { actor_type: "system" }, evidence: { decision: "fixed", completeness: "complete" } }).ok);

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

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
