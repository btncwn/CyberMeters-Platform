#!/usr/bin/env node
//
// Generic managed-case workflow validation. Covers transitions, guards,
// terminal immutability, non-mutation, queue ordering, and a DMARC-shaped graph
// on the generic engine without touching the live DMARC workflow/tables.
//
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const workflow = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "case-workflow.js")).href);
const asm = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "asm-cases.js")).href);

const {
  applyCaseTransition,
  buildCaseQueue,
  canTransition,
  createCaseMachine,
  isTerminal,
  newCaseEventId,
  newManagedCaseId,
  requireDifferentActor,
  requireExpiry,
  requireReason,
} = workflow;

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

const base = {
  id: "mc-test",
  status: "open",
  owner_ref: null,
  reopened_count: 0,
  created_at: "2026-07-13T08:00:00Z",
};

ok("id helpers use managed-case prefixes", newManagedCaseId().startsWith("mc-") && newCaseEventId().startsWith("mce-"));
ok("ASM machine allows open -> triage", canTransition(asm.ASM_CASE_MACHINE, "open", "triage"));
ok("ASM machine blocks invalid open -> resolved", !canTransition(asm.ASM_CASE_MACHINE, "open", "resolved"));
ok("closed is terminal", isTerminal(asm.ASM_CASE_MACHINE, "closed"));

const triage = applyCaseTransition(asm.ASM_CASE_MACHINE, base, "triage", { now: "2026-07-13T09:00:00Z" });
ok("valid transition succeeds", triage.ok && triage.case.status === "triage");
ok("transition does not mutate input", base.status === "open" && !base.updated_at);

const noOwner = applyCaseTransition(asm.ASM_CASE_MACHINE, triage.case, "owner_assigned", {});
ok("owner guard blocks owner_assigned", !noOwner.ok && /owner_ref/.test(noOwner.error));
const owner = applyCaseTransition(asm.ASM_CASE_MACHINE, { ...triage.case, owner_ref: "IT" }, "owner_assigned", {});
ok("owner guard passes when owner is present", owner.ok && owner.case.status === "owner_assigned");

const falsePositiveNoReason = applyCaseTransition(asm.ASM_CASE_MACHINE, { ...triage.case, owner_ref: "IT" }, "false_positive", {});
ok("reason guard blocks false positive", !falsePositiveNoReason.ok && /reason/i.test(falsePositiveNoReason.error));
const fp = applyCaseTransition(asm.ASM_CASE_MACHINE, { ...triage.case, owner_ref: "IT" }, "false_positive", { reason: "Confirmed not exposed" });
ok("false positive with reason succeeds", fp.ok && fp.case.reason === "Confirmed not exposed");
const terminalMove = applyCaseTransition(asm.ASM_CASE_MACHINE, fp.case, "triage", {});
ok("terminal states are immutable", !terminalMove.ok && /already/.test(terminalMove.error));

const riskReq = applyCaseTransition(asm.ASM_CASE_MACHINE, owner.case, "risk_acceptance_requested", { reason: "Business exception" });
ok("risk acceptance request requires and stores reason", riskReq.ok && riskReq.case.reason === "Business exception");
const riskNoExpiry = applyCaseTransition(asm.ASM_CASE_MACHINE, riskReq.case, "risk_accepted", { reason: "Approved exception" });
ok("risk accepted requires expiry", !riskNoExpiry.ok && /expiry/i.test(riskNoExpiry.error));
const risk = applyCaseTransition(asm.ASM_CASE_MACHINE, riskReq.case, "risk_accepted", { reason: "Approved exception", risk_accepted_until: "2026-08-01T00:00:00Z" });
ok("risk accepted with expiry succeeds", risk.ok && risk.case.risk_accepted_until === "2026-08-01T00:00:00Z");

const queue = buildCaseQueue([
  { id: "new", status: "open", created_at: "2026-07-13T11:00:00Z" },
  { id: "old", status: "open", created_at: "2026-07-13T08:00:00Z" },
], { now: "2026-07-13T12:00:00Z" });
ok("case queue is oldest first with age_hours", queue[0].id === "old" && queue[0].age_hours === 4);

const dmarcMachine = createCaseMachine({
  states: ["draft", "pending_review", "approved", "scheduled", "applying", "verifying", "completed", "rejected", "rolled_back", "cancelled"],
  transitions: {
    draft: ["pending_review", "cancelled"],
    pending_review: ["approved", "rejected", "cancelled"],
    approved: ["scheduled", "applying", "cancelled"],
    scheduled: ["applying", "cancelled"],
    applying: ["verifying", "rolled_back"],
    verifying: ["completed", "rolled_back"],
    completed: [], rejected: [], rolled_back: [], cancelled: [],
  },
  terminals: ["completed", "rejected", "rolled_back", "cancelled"],
  guards: {
    "pending_review->approved": [requireDifferentActor("requested_by")],
    rejected: [requireReason],
    rolled_back: [requireReason],
    scheduled: [(_row, ctx) => ctx.scheduled_at ? true : "A scheduled execution time is required."],
    risk_accepted: [requireExpiry],
  },
});
const dmarcDraft = { id: "cr-test", status: "draft", requested_by: "analyst-a" };
const dmarcPending = applyCaseTransition(dmarcMachine, dmarcDraft, "pending_review", {});
ok("generic engine can express DMARC draft -> pending_review", dmarcPending.ok);
const sameApprover = applyCaseTransition(dmarcMachine, dmarcPending.case, "approved", { actor_id: "analyst-a" });
ok("generic DMARC graph enforces separation of duties", !sameApprover.ok && /different actor/i.test(sameApprover.error));
const approved = applyCaseTransition(dmarcMachine, dmarcPending.case, "approved", { actor_id: "analyst-b" });
ok("generic DMARC approval succeeds with different actor", approved.ok && approved.case.status === "approved");
const applying = applyCaseTransition(dmarcMachine, approved.case, "applying", {});
const verifying = applyCaseTransition(dmarcMachine, applying.case, "verifying", {});
const completed = applyCaseTransition(dmarcMachine, verifying.case, "completed", {});
ok("generic DMARC graph reaches completed", completed.ok && completed.case.status === "completed");

console.log(`\nManaged case workflow: ${pass}/${pass + fail} passed`);
if (fail) { console.error("managed-case-workflow validation FAILED"); process.exit(1); }
console.log("managed-case-workflow validation passed");
