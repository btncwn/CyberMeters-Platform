#!/usr/bin/env node
//
// Managed DMARC change-workflow runtime proof. Epic #7 (Level 3) of the Managed
// DMARC Policy Journey — the analyst review queue + guarded state machine that
// puts a human approval in front of a managed policy change. Drives the pure
// state machine (transitions, guards, separation-of-duties, terminal immutability)
// and the review-queue builder, plus a DB round-trip proving the additive table
// persists and tenant-scopes. Node 24+. CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "dmarc-change-workflow.js")).href);
const {
  CHANGE_STATES, CHANGE_TRANSITIONS, TERMINAL_CHANGE_STATES,
  isTerminalChangeState, canTransitionChange, applyChangeTransition,
  buildChangeReviewQueue, changeRequestToApi,
} = eng;

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

const NOW = "2026-07-13T12:00:00.000Z";
const base = (over = {}) => ({ id: "cr-1", state: "draft", requested_by: "u_owner", domain: "acme.co.uk",
  record_kind: "dmarc", from_policy: "none", to_policy: "reject", created_at: NOW, ...over });

// ── Happy path: draft → pending_review → approved → applying → verifying → completed
let r = base();
r = applyChangeTransition(r, "pending_review", { actor: "u_owner", now: NOW }).request;
ok("draft → pending_review", r.state === "pending_review");
const appr = applyChangeTransition(r, "approved", { actor: "u_analyst", now: NOW });
ok("pending_review → approved by a different analyst", appr.ok && appr.request.state === "approved");
ok("approval records the reviewer + timestamp", appr.request.reviewed_by === "u_analyst" && appr.request.reviewed_at === NOW);
r = appr.request;
r = applyChangeTransition(r, "applying", { actor: "u_analyst", now: NOW }).request;
ok("approved → applying stamps applied_at", r.state === "applying" && r.applied_at === NOW);
r = applyChangeTransition(r, "verifying", { now: NOW }).request;
ok("applying → verifying", r.state === "verifying");
const done = applyChangeTransition(r, "completed", { now: NOW });
ok("verifying → completed", done.ok && done.request.state === "completed");

// ── Separation of duties: requester cannot approve their own change ───────────
const selfAppr = applyChangeTransition(base({ state: "pending_review" }), "approved", { actor: "u_owner", now: NOW });
ok("requester cannot approve their own change (separation of duties)", selfAppr.ok === false && /different/i.test(selfAppr.error));
const noActor = applyChangeTransition(base({ state: "pending_review" }), "approved", { now: NOW });
ok("approval without an analyst is rejected", noActor.ok === false);

// ── Reason required on reject / rollback ──────────────────────────────────────
const noReason = applyChangeTransition(base({ state: "pending_review" }), "rejected", { actor: "u_analyst", now: NOW });
ok("rejection without a reason is blocked", noReason.ok === false && /reason/i.test(noReason.error));
const rejected = applyChangeTransition(base({ state: "pending_review" }), "rejected", { actor: "u_analyst", reason: "unclassified senders", now: NOW });
ok("rejection with a reason succeeds + records reviewer", rejected.ok && rejected.request.state === "rejected" && rejected.request.reason === "unclassified senders" && rejected.request.reviewed_by === "u_analyst");
const rbNoReason = applyChangeTransition(base({ state: "applying" }), "rolled_back", { now: NOW });
ok("rollback without a reason is blocked", rbNoReason.ok === false);
const rb = applyChangeTransition(base({ state: "verifying" }), "rolled_back", { reason: "pass-rate regression", now: NOW });
ok("rollback with a reason succeeds", rb.ok && rb.request.state === "rolled_back");

// ── Scheduling needs a target time ────────────────────────────────────────────
const schedNoTime = applyChangeTransition(base({ state: "approved" }), "scheduled", { now: NOW });
ok("scheduling without a time is blocked", schedNoTime.ok === false);
const sched = applyChangeTransition(base({ state: "approved" }), "scheduled", { scheduled_at: "2026-07-20T09:00:00Z", now: NOW });
ok("scheduling with a time succeeds", sched.ok && sched.request.scheduled_at === "2026-07-20T09:00:00Z");

// ── Illegal + terminal transitions are refused ────────────────────────────────
ok("draft cannot jump straight to completed", applyChangeTransition(base(), "completed", { now: NOW }).ok === false);
ok("a completed request is immutable", applyChangeTransition(base({ state: "completed" }), "rolled_back", { reason: "x", now: NOW }).ok === false);
ok("a rejected request is immutable", applyChangeTransition(base({ state: "rejected" }), "approved", { actor: "u_analyst", now: NOW }).ok === false);
ok("unknown target state is refused", applyChangeTransition(base({ state: "draft" }), "banana", { now: NOW }).ok === false);
ok("transitions never mutate the input object", (() => { const x = base({ state: "pending_review" }); applyChangeTransition(x, "approved", { actor: "a", now: NOW }); return x.state === "pending_review"; })());

// ── State-machine invariants ──────────────────────────────────────────────────
ok("every terminal state has no outgoing edges", [...TERMINAL_CHANGE_STATES].every((s) => (CHANGE_TRANSITIONS[s] || []).length === 0));
ok("every transition target is a known state", Object.values(CHANGE_TRANSITIONS).flat().every((s) => CHANGE_STATES.includes(s)));
ok("canTransitionChange matches the table", canTransitionChange("pending_review", "approved") && !canTransitionChange("pending_review", "completed"));
ok("isTerminalChangeState is correct", isTerminalChangeState("completed") && !isTerminalChangeState("pending_review"));

// ── Review queue: only pending, oldest first, with age ────────────────────────
const queueRows = [
  base({ id: "cr-new", state: "pending_review", created_at: "2026-07-13T10:00:00.000Z" }),
  base({ id: "cr-old", state: "pending_review", created_at: "2026-07-11T10:00:00.000Z" }),
  base({ id: "cr-approved", state: "approved", created_at: "2026-07-10T10:00:00.000Z" }),
];
const q = buildChangeReviewQueue(queueRows, { now: NOW });
ok("queue excludes non-pending requests", q.length === 2 && !q.some((x) => x.id === "cr-approved"));
ok("queue is oldest-first (largest age leads)", q[0].id === "cr-old" && q[1].id === "cr-new");
ok("queue items carry an age in hours", q[0].age_hours >= 48);

// ── changeRequestToApi: safe evidence parse + terminal flag ───────────────────
const api = changeRequestToApi(base({ state: "completed", evidence_snapshot: JSON.stringify({ score: 92, status: "ready" }) }));
ok("evidence JSON parsed to an object", api.evidence?.score === 92);
ok("is_terminal reflects the state", api.is_terminal === true);
ok("malformed evidence JSON degrades to null (never throws)", changeRequestToApi(base({ evidence_snapshot: "{not json" })).evidence === null);

// ── DB round-trip: the additive table persists + tenant-scopes ────────────────
const db = new DatabaseSync(":memory:");
const applySql = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering no-ops */ } };
applySql(path.join(root, "database", "schema.sql"));
for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) applySql(path.join(root, "database", "migrations", f));
db.exec("PRAGMA foreign_keys = OFF");
const ins = (id, ws, state) => db.prepare(`INSERT INTO dmarc_change_requests (id, workspace_id, domain, state, from_policy, to_policy, requested_by, created_at, updated_at) VALUES (?, ?, 'acme.co.uk', ?, 'none', 'reject', 'u1', ?, ?)`).run(id, ws, state, NOW, NOW);
ins("cr-a1", "ws_a", "pending_review");
ins("cr-a2", "ws_a", "approved");
ins("cr-b1", "ws_b", "pending_review");
const rowsA = db.prepare(`SELECT * FROM dmarc_change_requests WHERE workspace_id = ? ORDER BY created_at`).all("ws_a");
ok("table persists rows (round-trip)", rowsA.length === 2);
const queueA = buildChangeReviewQueue(rowsA, { now: NOW });
ok("tenant-scoped queue shows only this workspace's pending request", queueA.length === 1 && queueA[0].id === "cr-a1");

console.log(`\nDMARC change workflow: ${pass}/${pass + fail} passed`);
if (fail) { console.error("dmarc-change-workflow validation FAILED"); process.exit(1); }
console.log("dmarc-change-workflow validation passed");
