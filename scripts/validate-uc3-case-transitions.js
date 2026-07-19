#!/usr/bin/env node
//
// UC3 managed-case transition UI — backend contract proof. CI-blocking.
//
// The universal base managed-case backend (state machine + canTransitionCase +
// transition route) already existed; the case-detail GET now also returns
// `available_transitions` + `can_manage` so the frontend can render transition
// controls WITHOUT re-deriving the state machine. This suite proves the new
// backend surface is honest and safe:
//
//   • available_transitions is DERIVED from the canonical machine (every advertised
//     target is a real edge from the current status) — no invented shortcut;
//   • an illegal transition is never advertised;
//   • `assigned` carries requires_owner, and the transition itself is unavailable
//     without owner_ref (guard) — advertised, but canTransitionCase refuses it;
//   • a verified target is offered to a customer ONLY by manual attestation;
//     automated/external/unsupported verification is never a customer control,
//     and canTransitionCase enforces the same (system-only / evidence contract);
//   • ASM/Brand (bespoke) expose NO generic transitions here (untouched);
//   • terminal states expose nothing;
//   • the route gates available_transitions behind workspace:manage and routes
//     every mutation through canTransitionCase, workspace-scoped (tenant-safe).
//
// Behaviour-level: it EXECUTES the real functions (not regex over source) plus a
// few static route-wiring assertions. Node 24+.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const enginesDir = path.join(root, "workers", "scan-api", "src", "engines");
const imp = (f) => import(pathToFileURL(path.join(enginesDir, f)).href);

const mcm = await imp("managed-case-model.js");
const { availableTransitionsForCase, canTransitionCase, verificationSupportForCase, BASE_CASE_MACHINE } = mcm;

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };

const mkCase = (over = {}) => ({ id: "mc-t", workspace_id: "ws1", case_type: "identity_case", status: "detected", ...over });
const attest = () => ({
  verification_method: "manual_attestation", verification_result: "fixed",
  evidence_type: "customer_attestation", observed_at: new Date().toISOString(),
  attestation: { statement: "Remediation confirmed by the customer." },
});

// ── 1. Every advertised target is a real edge of the canonical base machine ───
const BASE_STATES = ["detected", "triaged", "assigned", "approved", "action_in_progress",
  "awaiting_verification", "verified", "monitoring", "reopened",
  "accepted_risk", "rejected", "false_positive", "closed_no_action", "superseded"];
let allDerived = true;
for (const status of BASE_STATES) {
  const edges = new Set(BASE_CASE_MACHINE.transitions[status] || []);
  const adv = availableTransitionsForCase(mkCase({ status, owner_ref: "Beta", remediation_id: "identity.exposed_login.remove" }));
  for (const t of adv) if (!edges.has(t.target_status)) allDerived = false;
}
ok("available_transitions targets are all real machine edges (no invented transition)", allDerived);

// ── 2. Illegal transitions are never advertised ───────────────────────────────
const detectedTargets = availableTransitionsForCase(mkCase({ status: "detected" })).map((t) => t.target_status);
ok("from 'detected' only the machine's legal targets are advertised",
   JSON.stringify(detectedTargets.slice().sort()) === JSON.stringify(["false_positive", "superseded", "triaged"]));
ok("from 'detected', 'verified' is NOT advertised", !detectedTargets.includes("verified"));
ok("from 'detected', 'approved' is NOT advertised", !detectedTargets.includes("approved"));

// ── 3. assigned: requires_owner flag + unavailable without owner_ref ───────────
const triagedNoOwner = availableTransitionsForCase(mkCase({ status: "triaged" }));
const assignedNoOwner = triagedNoOwner.find((t) => t.target_status === "assigned");
ok("'assigned' advertised with requires_owner=true when no owner_ref", assignedNoOwner?.requires_owner === true);
const assignedWithOwner = availableTransitionsForCase(mkCase({ status: "triaged", owner_ref: "Beta" }))
  .find((t) => t.target_status === "assigned");
ok("'assigned' requires_owner=false once owner_ref is set", assignedWithOwner?.requires_owner === false);
// The transition itself is unavailable without owner_ref (the machine guard).
const assignNoOwner = canTransitionCase({ case: mkCase({ status: "triaged" }), target_status: "assigned", actor: { actor_type: "customer", actor_id: "u1" } });
ok("canTransitionCase REFUSES assigned without owner_ref", assignNoOwner.ok === false);
const assignOwner = canTransitionCase({ case: mkCase({ status: "triaged", owner_ref: "Beta" }), target_status: "assigned", actor: { actor_type: "customer", actor_id: "u1" } });
ok("canTransitionCase ALLOWS assigned once owner_ref is present", assignOwner.ok === true);

// ── 4. verified / attestation contract ────────────────────────────────────────
// Manual case: verified IS a customer action, flagged requires_attestation.
const manualCase = mkCase({ status: "awaiting_verification" }); // identity_case → manual
ok("manual case is manual support", verificationSupportForCase(manualCase) === "manual");
const manualVerified = availableTransitionsForCase(manualCase).find((t) => t.target_status === "verified");
ok("manual verified advertised with requires_attestation=true + verification_mode=manual",
   manualVerified?.requires_attestation === true && manualVerified?.verification_mode === "manual");
// canTransitionCase honours the evidence contract.
const okAttest = canTransitionCase({ case: manualCase, target_status: "verified", actor: { actor_type: "customer", actor_id: "u1" }, evidence: attest() });
ok("canTransitionCase ACCEPTS manual verified with a structured attestation", okAttest.ok === true);
const bareScan = canTransitionCase({ case: manualCase, target_status: "verified", actor: { actor_type: "customer", actor_id: "u1" }, evidence: { scan_completed_only: true } });
ok("canTransitionCase REJECTS verified from a bare scan completion", bareScan.ok === false);
const noEvidence = canTransitionCase({ case: manualCase, target_status: "verified", actor: { actor_type: "customer", actor_id: "u1" }, evidence: null });
ok("canTransitionCase REJECTS verified with no evidence", noEvidence.ok === false);

// Automated case: verified is NOT a customer control, and canTransitionCase blocks it.
const autoCase = mkCase({ case_type: "email_case", status: "awaiting_verification", remediation_id: "email.hosted_dmarc.reconnect" });
ok("automated case is automated support", verificationSupportForCase(autoCase) === "automated");
const autoVerified = availableTransitionsForCase(autoCase).find((t) => t.target_status === "verified");
ok("automated verified is NOT advertised to a customer", autoVerified === undefined);
const autoAttempt = canTransitionCase({ case: autoCase, target_status: "verified", actor: { actor_type: "customer", actor_id: "u1" }, evidence: attest() });
ok("canTransitionCase REFUSES a customer verifying an automated case", autoAttempt.ok === false);

// ── 5. ASM/Brand expose no generic transitions here (bespoke, untouched) ───────
ok("ASM case exposes no generic transitions", availableTransitionsForCase({ case_type: "asm_exposure", status: "open" }).length === 0);
ok("Brand case exposes no generic transitions", availableTransitionsForCase({ case_type: "brand_abuse", status: "detected" }).length === 0);

// ── 6. Terminal states expose nothing ─────────────────────────────────────────
for (const term of ["rejected", "false_positive", "closed_no_action", "superseded"]) {
  ok(`terminal '${term}' exposes no transitions`, availableTransitionsForCase(mkCase({ status: term })).length === 0);
}

// ── 7. accepted_risk carries note + expiry requirements ───────────────────────
const risk = availableTransitionsForCase(mkCase({ status: "assigned", owner_ref: "Beta" })).find((t) => t.target_status === "accepted_risk");
ok("accepted_risk requires note + expiry", risk?.requires_note === true && risk?.requires_expiry === true);

// ── 8. Route wiring (static): manage-gated + tenant-safe + no bypass ──────────
const routeCode = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "routes", "managed-cases.js"), "utf8");
ok("GET case-detail derives available_transitions from the model",
   /availableTransitionsForCase\(row, \{ actor_type: "customer" \}\)/.test(routeCode));
ok("available_transitions is gated behind a workspace:manage check",
   /requireWorkspaceRole\(user, wsId, "workspace:manage", env\)/.test(routeCode) &&
   /const available_transitions = canManage/.test(routeCode));
ok("a non-manager gets an empty available_transitions list",
   /canManage\s*\?\s*availableTransitionsForCase[\s\S]*?:\s*\[\]/.test(routeCode));
ok("the transition endpoint still routes through canTransitionCase (no bypass)",
   /const decision = canTransitionCase\(/.test(routeCode));
ok("case load is workspace-scoped (tenant isolation preserved)",
   /FROM managed_cases WHERE id = \? AND workspace_id = \?/.test(routeCode));

console.log(`\nvalidate-uc3-case-transitions: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
