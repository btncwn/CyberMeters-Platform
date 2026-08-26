#!/usr/bin/env node
//
// F-027 mutation proof. Each mutant reintroduces one false-healthy / safety
// defect; the plain validator must fail with a NAMED assertion. Mutants 1–7 are
// the original persistence/routing/freshness/deadman guards; 8–13 are the R1
// corrective: the ACTUAL workflow-path deadman (correct booleans, string
// impostors, invalid fields), the recent-DLQ read-failure-vs-zero distinction and
// its deadman consumption, and the workflow's wiring to the strict entrypoint;
// 14-15 are the delta corrective: the recent_dlq_readable TYPE-AND-VALUE contract
// (both consumers reject unless literal `true`), proven by weakening each predicate
// back to the permissive form.
// Mutations run in-process against a temporary copy of the source, restored in
// finally; the worktree fingerprint is checked so a killed mutant can never leak
// edits. Node 24+.

import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const f = (rel) => path.join(root, rel);
function git(args) { return execFileSync("git", args, { cwd: root, encoding: "utf8" }); }
function worktreeFingerprint() {
  return crypto.createHash("sha256").update(git(["status", "--porcelain=v1", "-z"])).digest("hex");
}
function replaceExactly(src, from, to, id) {
  const n = src.split(from).length - 1;
  if (n !== 1) throw new Error(`${id}: anchor count ${n}, expected 1`);
  return src.replace(from, to);
}

const LANE = "scripts/validate-f027-internal-observability.js";
const OPS = "workers/scan-api/src/lib/operational-events.js";
const OBS = "workers/scan-api/src/queues/scan-dlq-observer.js";
const HEALTH = "workers/scan-api/src/lib/ops-health.js";

const mutants = [
  { // 1. DLQ routed into engine
    id: "DLQ_ROUTED_INTO_ENGINE", file: OPS,
    from: 'return queueName === SCAN_DLQ_NAME ? "dlq_observer" : "scan_dispatch";',
    to:   'return "scan_dispatch";',
    mustContain: "FAIL routing: the scan DLQ goes to the observer, never the engine",
  },
  { // 2. ack before write
    id: "ACK_BEFORE_WRITE", file: OBS,
    from: "    if (result.persisted) {\n      message.ack?.();       // durable — safe to ack\n      observed += 1;\n    } else {\n      message.retry?.();     // NOT persisted — no-ack, redeliver (fail closed)\n      deferred += 1;\n    }",
    to:   "    message.ack?.();\n    if (result.persisted) { observed += 1; } else { deferred += 1; }",
    mustContain: "FAIL DLQ fail closed: unpersisted message is NOT acked, it retries",
  },
  { // 3. non-deterministic idempotency
    id: "NON_DETERMINISTIC_IDEMPOTENCY", file: OPS,
    from: "  const data = new TextEncoder().encode(`${eventType} ${correlationId}`);",
    to:   "  const data = new TextEncoder().encode(`${eventType} ${correlationId} ${crypto.randomUUID()}`);",
    mustContain: "FAIL deterministic id: duplicate maps to the same primary key",
  },
  { // 4. sent:false discarded
    id: "SENT_FALSE_DISCARDED", file: OPS,
    from: "  if (sendResult && sendResult.sent === true) return { recorded: false };",
    to:   "  return { recorded: false };",
    mustContain: "FAIL alert outcome: a {sent:false} is recorded as a durable failure event",
  },
  { // 5. event-write failure swallowed
    id: "EVENT_WRITE_FAILURE_SWALLOWED", file: OPS,
    from: '    return { persisted: false, reason: "insert_threw" };',
    to:   '    return { persisted: true, reason: "insert_threw" };',
    mustContain: "FAIL fail closed: a DB error yields persisted:false",
  },
  { // 6. freshness check removed/inverted
    id: "FRESHNESS_CHECK_INVERTED", file: HEALTH,
    from: "    cron_fresh:        cronAge !== null && cronAge <= CRON_STALE_AFTER_MIN,",
    to:   "    cron_fresh:        cronAge === null || cronAge <= CRON_STALE_AFTER_MIN,",
    mustContain: "FAIL freshness fail-closed: absent cron tick -> cron_fresh:false",
  },
  { // 7. deadman accepts 200 without valid JSON / true operational fields
    id: "DEADMAN_ACCEPTS_200_BLINDLY", file: HEALTH,
    from: "  if (!parsedBody || typeof parsedBody !== \"object\") return { healthy: false, reason: \"invalid_json\" };",
    to:   "  if (!parsedBody || typeof parsedBody !== \"object\") return { healthy: true, reason: \"invalid_json\" };",
    mustContain: "FAIL deadman: 200 but body did not parse -> NOT healthy",
  },
  { // 8. R1-01 (correct booleans): the strict evaluator rejects the CORRECT healthy
    //    payload (stale_queued_scan:false) -> the shipped recovery branch is unreachable.
    id: "DEADMAN_REJECTS_HEALTHY_STALE_FALSE", file: HEALTH,
    from: "op.stale_queued_scan !== false",
    to:   "op.stale_queued_scan !== true",
    mustContain: "FAIL entrypoint(REAL path): correct healthy booleans @200 -> healthy=true reason=ok",
  },
  { // 9. R1-01 (string impostors): a JSON STRING "false" is accepted as the boolean.
    id: "DEADMAN_ACCEPTS_STALE_STRING_IMPOSTOR", file: HEALTH,
    from: "  if (op.stale_queued_scan !== false) return { healthy: false, reason: \"stale_queued_scan\" };",
    to:   "  if (String(op.stale_queued_scan) !== \"false\") return { healthy: false, reason: \"stale_queued_scan\" };",
    mustContain: "FAIL entrypoint: a single string impostor on stale_queued_scan -> fail closed",
  },
  { // 10. R1-01 (invalid fields): the ACTUAL workflow entrypoint clears an unparseable body.
    id: "ENTRYPOINT_HEALTHY_ON_INVALID_JSON", file: "scripts/ops-deadman-verdict.mjs",
    from: "  emit(false, \"invalid_json\");",
    to:   "  emit(true, \"invalid_json\");",
    mustContain: "FAIL entrypoint: invalid JSON body @200 -> fail closed (invalid_json)",
  },
  { // 11. R1-02 (read failure vs zero): an unreadable window is fabricated back into a proven 0.
    id: "RECENT_DLQ_READ_FAILURE_AS_ZERO", file: OPS,
    from: "  } catch { return { readable: false, count: null }; }",
    to:   "  } catch { return { readable: true, count: 0 }; }",
    mustContain: "FAIL R1-02: a DLQ read FAILURE is DISTINGUISHABLE from zero",
  },
  { // 12. R1-02 (deadman consumes it): the deadman stops reading the read-failure signal.
    id: "DEADMAN_IGNORES_DLQ_UNREADABLE", file: HEALTH,
    from: "  if (op.recent_dlq_readable !== true) return { healthy: false, reason: \"recent_dlq_unreadable\" };",
    to:   "  if (false) return { healthy: false, reason: \"recent_dlq_unreadable\" };",
    mustContain: "FAIL R1-02: the actual deadman CONSUMES the read-failure truth",
  },
  { // 14. delta R1: weakening the deadman's readable predicate to the permissive
    //    (=== false only) form lets string/null/absent readability fail OPEN.
    id: "DEADMAN_READABLE_PREDICATE_WEAKENED", file: HEALTH,
    from: "  if (op.recent_dlq_readable !== true) return { healthy: false, reason: \"recent_dlq_unreadable\" };",
    to:   "  if (op.recent_dlq_readable === false) return { healthy: false, reason: \"recent_dlq_unreadable\" };",
    mustContain: "FAIL entrypoint(ISOLATED): recent_dlq_readable string 'false' -> healthy=false reason=recent_dlq_unreadable",
  },
  { // 15. delta R1: the SAME weakening on the other consumer (isOperationallyHealthy).
    id: "ISHEALTHY_READABLE_PREDICATE_WEAKENED", file: HEALTH,
    from: "    booleans.recent_dlq_readable === true;",
    to:   "    booleans.recent_dlq_readable !== false;",
    mustContain: "FAIL isOperationallyHealthy(ISOLATED): recent_dlq_readable string 'false' -> false",
  },
  { // 13. R1-01/03 (real path is the workflow): the workflow drops the strict entrypoint.
    id: "WORKFLOW_UNWIRES_ENTRYPOINT", file: ".github/workflows/ops-deadman.yml",
    from: "          node scripts/ops-deadman-verdict.mjs \"$code\" /tmp/ready.json >> \"$GITHUB_OUTPUT\"",
    to:   "          printf 'healthy=true\\nreason=ok\\n' >> \"$GITHUB_OUTPUT\"",
    mustContain: "FAIL workflow wires the strict entrypoint",
  },
];

let killed = 0; const failures = [];
const initial = worktreeFingerprint();
for (const m of mutants) {
  const abs = f(m.file);
  const original = fs.readFileSync(abs);
  try {
    fs.writeFileSync(abs, replaceExactly(original.toString("utf8"), m.from, m.to, m.id));
    const child = spawnSync(process.execPath, [f(LANE)], { cwd: root, encoding: "utf8", timeout: 120000 });
    const out = `${child.stdout || ""}\n${child.stderr || ""}`;
    if (child.status !== 0 && out.includes(m.mustContain)) { killed++; console.log(`PASS ${m.id}: killed by "${m.mustContain}"`); }
    else { failures.push(m.id); console.error(`FAIL ${m.id}: not killed for the named reason (status ${child.status})`); }
  } finally {
    fs.writeFileSync(abs, original);
  }
}
if (worktreeFingerprint() !== initial) { failures.push("worktree-not-restored"); console.error("FAIL worktree fingerprint changed"); }

console.log(`\nF-027 mutations: ${killed}/${mutants.length} killed`);
if (failures.length) process.exit(1);
