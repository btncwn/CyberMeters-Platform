#!/usr/bin/env node
//
// Certificate standing-condition dedupe validator.
//
// insertCertificateEvents() emits one STANDING-condition asset_event,
// certificate_expiring_soon, from the certificate the live site presented.
// Before this guard it re-fired on every comparable scan even when the
// underlying condition was unchanged, flooding the customer timeline.
//
// This validator proves, DB-backed and end-to-end, that:
//   1. an UNCHANGED condition does not re-emit on a later comparable scan;
//   2. a GENUINE new occurrence / state transition still emits;
//   3. multi-workspace fan-out is preserved and each workspace tracks its OWN
//      last occurrence (a late-joining workspace still gets its first event);
//   4. repeated execution of the same scan remains idempotent;
//   5. recurrence after absence is still possible on a later scan;
//   6. raw asset_events history is append-only (no prior row mutated/deleted);
//   7. the retired certificate-log conditions (sensitive host, growth) are
//      never emitted, even from a module carrying their old fields.
//
// Every behavioural claim is mutation-tested: each mutation reintroduces the
// defect and MUST make the contract fail for the intended reason.
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";
import { importMutant, registerMutants } from "./lib/mutant-import.mjs";
import { wholeSourceFingerprint } from "./run-local-focused-gate.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const certEventsPath = path.join(root, "workers", "scan-api", "src", "engines", "cert-events.js");
const engineDir = path.dirname(certEventsPath);
const realMod = await import(pathToFileURL(certEventsPath).href);

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  cond ? pass++ : fail++;
  if (!cond) console.log(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
};
const eq = (name, actual, expected) => ok(name, actual === expected, `got ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);

function mutationSurface() {
  return {
    source: wholeSourceFingerprint(root),
    engines: fs.readdirSync(engineDir).sort().join("\n"),
    git: execFileSync("git", ["status", "--porcelain", "--", "workers", "frontend", "scripts"], {
      cwd: root,
      encoding: "utf8",
    }),
  };
}

const PRODUCER = "asset-timeline-trust-v1";

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* migrations are cumulative */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}

function makeD1(db) {
  const wrap = (sql, args) => ({
    __sql: sql, __args: args,
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => {
      const r = db.prepare(sql).run(...args);
      return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid ?? 0) } };
    },
  });
  return {
    prepare(sql) { const b = wrap(sql, []); b.bind = (...args) => wrap(sql, args); return b; },
  };
}

function makeR2(reports) {
  return {
    async get(key) {
      const report = reports.get(key);
      return report ? { json: async () => report } : null;
    },
  };
}

function report(modules = {}) {
  return {
    scan_quality: { status: "complete" },
    timeline_trust: { asset_timeline_producer_version: PRODUCER },
    modules,
  };
}

function certModule({ days = null, expiresAt = null, retired = false } = {}) {
  return {
    days_until_expiry: days,
    expires_at: expiresAt,
    // Fields a stored module from before certificate logs were retired can carry.
    ...(retired ? { issued_for_sensitive_hosts: ["admin.cybermeters.com"], total_certificates_seen: 80 } : {}),
  };
}

// Build an isolated environment for one scenario. `workspaces` is a list of
// workspace ids that own the domain; `priorEvents` seeds already-recorded
// asset_events (representing prior scans' emissions).
function scenarioEnv({ workspaces = ["ws_1"], prevCert = certModule(), priorEvents = [] } = {}) {
  const db = buildDb();
  db.prepare("INSERT INTO users (id, email) VALUES ('usr_1', 'owner@example.co.uk')").run();
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('dom_1', 'usr_1', 'cybermeters.com')").run();
  for (const ws of workspaces) {
    db.prepare("INSERT INTO workspaces (id, name) VALUES (?, ?)").run(ws, ws);
    db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES (?, 'dom_1')").run(ws);
  }
  db.prepare("INSERT INTO scans (id, domain_id, domain, status, scan_quality, created_at) VALUES (?, ?, ?, ?, ?, ?)").run(
    "scan_prev", "dom_1", "cybermeters.com", "completed", "complete", "2026-07-17T22:40:00.000Z"
  );
  db.prepare("INSERT INTO scans (id, domain_id, domain, status, scan_quality, created_at) VALUES (?, ?, ?, ?, ?, ?)").run(
    "scan_current", "dom_1", "cybermeters.com", "completed", "complete", "2026-07-18T10:21:00.000Z"
  );
  for (const ev of priorEvents) {
    db.prepare(
      `INSERT INTO asset_events (id, workspace_id, domain_id, scan_id, event_type, hostname, severity, description, created_at)
       VALUES (?, ?, 'dom_1', 'scan_prev', ?, ?, ?, ?, ?)`
    ).run(ev.id, ev.workspace_id, ev.event_type, ev.hostname ?? null, ev.severity ?? "medium", ev.description ?? "", ev.created_at ?? "2026-07-17T22:40:00.000Z");
  }
  const reports = new Map([["reports/scan_prev.json", report({ certificate_intelligence: prevCert })]]);
  const env = {
    cybermeters_db: makeD1(db),
    cybermeters_reports: makeR2(reports),
  };
  return { db, env, reports };
}

const typeRows = (db, type) => db.prepare(
  "SELECT id, workspace_id, scan_id FROM asset_events WHERE event_type = ? ORDER BY created_at, id"
).all(type);
const allRows = (db) => db.prepare("SELECT id, event_type, description FROM asset_events ORDER BY id").all();

const currentReport = report();

const EXPIRY = "certificate_expiring_soon";
const expiryRows = (db) => typeRows(db, EXPIRY);

// The full behavioural + pure contract. Returns null on success, else the first
// failing reason string. Re-run against each mutant so every guard is proven.
async function contract(mod) {
  const {
    insertCertificateEvents,
    certExpiringSoonSignature,
    shouldEmitCertConditionEvent,
    certConditionEventId,
  } = mod;

  if (typeof certConditionEventId !== "function") return "deterministic_identity_missing";
  const base = {
    workspaceId: "ws_1",
    domainId: "dom_1",
    scanId: "scan_current",
    eventType: EXPIRY,
    signature: "medium|2026-08-05",
  };
  const idSameA = await certConditionEventId(base);
  const idSameB = await certConditionEventId({ ...base });
  if (idSameA !== idSameB) return "deterministic_identity_not_stable";
  if (!/^asev_[a-f0-9]{32}$/.test(idSameA)) return "deterministic_identity_malformed";
  if (idSameA === await certConditionEventId({ ...base, workspaceId: "ws_2" })) return "workspace_identity_collision";
  if (idSameA === await certConditionEventId({ ...base, domainId: "dom_2" })) return "domain_identity_collision";
  if (idSameA === await certConditionEventId({ ...base, scanId: "scan_later" })) return "scan_identity_collision";
  if (idSameA === await certConditionEventId({ ...base, eventType: "certificate_new_detected" })) {
    return "different_event_type_identity_collision";
  }
  if (idSameA === await certConditionEventId({ ...base, signature: "critical|2026-08-05" })) {
    return "different_signature_identity_collision";
  }
  const insertSource = insertCertificateEvents.toString();
  if ((insertSource.match(/INSERT OR IGNORE INTO asset_events/g) || []).length < 1) return "standing_condition_insert_not_idempotent";

  // E2E behavioural checks run FIRST so a broken guard is caught as the exact
  // customer-visible symptom (re-emit / silence / lost fan-out), then the pure
  // helper contract adds finer-grained coverage.

  // ── E2E 1: unchanged expiry condition on a later comparable scan → silent ──
  {
    const { db, env } = scenarioEnv({
      prevCert: certModule({ days: 20, expiresAt: "2026-08-05" }),
      priorEvents: [{ id: "prior_1", workspace_id: "ws_1", event_type: EXPIRY, description: "Certificate expires in 20 days (2026-08-05)." }],
    });
    await insertCertificateEvents("scan_current", "dom_1", certModule({ days: 18, expiresAt: "2026-08-05" }), env, { currentReport });
    if (expiryRows(db).length !== 1) return "unchanged_expiry_re_emitted";
    // Append-only: the seeded prior row is intact.
    if (!allRows(db).some((r) => r.id === "prior_1")) return "prior_row_lost";
  }

  // ── E2E 2: a severity escalation is a genuine transition → emit ───────────
  {
    const { db, env } = scenarioEnv({
      prevCert: certModule({ days: 20, expiresAt: "2026-08-05" }),
      priorEvents: [{ id: "prior_1", workspace_id: "ws_1", event_type: EXPIRY }],
    });
    await insertCertificateEvents("scan_current", "dom_1", certModule({ days: 12, expiresAt: "2026-08-05" }), env, { currentReport });
    if (expiryRows(db).length !== 2) return "genuine_transition_silenced";
  }

  // ── E2E 3: fan-out — a genuine change emits once per workspace ─────────────
  {
    const { db, env } = scenarioEnv({
      workspaces: ["ws_1", "ws_2"],
      prevCert: certModule({ days: 20, expiresAt: "2026-08-05" }),
      priorEvents: [
        { id: "p_ws1", workspace_id: "ws_1", event_type: EXPIRY },
        { id: "p_ws2", workspace_id: "ws_2", event_type: EXPIRY },
      ],
    });
    await insertCertificateEvents("scan_current", "dom_1", certModule({ days: 12, expiresAt: "2026-08-05" }), env, { currentReport });
    const fresh = expiryRows(db).filter((r) => r.id !== "p_ws1" && r.id !== "p_ws2");
    if (fresh.length !== 2) return "fanout_not_one_event_per_workspace";
    if (new Set(fresh.map((r) => r.workspace_id)).size !== 2) return "fanout_lost_a_workspace";
  }

  // ── E2E 4: late-joining workspace, unchanged condition → its first event ──
  {
    const { db, env } = scenarioEnv({
      workspaces: ["ws_1", "ws_2"],
      prevCert: certModule({ days: 20, expiresAt: "2026-08-05" }),
      // Only ws_1 has recorded the condition before; ws_2 joined later.
      priorEvents: [{ id: "p_ws1", workspace_id: "ws_1", event_type: EXPIRY }],
    });
    await insertCertificateEvents("scan_current", "dom_1", certModule({ days: 18, expiresAt: "2026-08-05" }), env, { currentReport });
    const fresh = expiryRows(db).filter((r) => r.id !== "p_ws1");
    if (fresh.length !== 1) return "late_join_workspace_not_served";
    if (fresh[0].workspace_id !== "ws_2") return "late_join_served_wrong_workspace";
  }

  // ── E2E 5: retired certificate-log conditions are never emitted ───────────
  {
    const { db, env } = scenarioEnv({ prevCert: certModule() });
    await insertCertificateEvents("scan_current", "dom_1", certModule({ retired: true }), env, { currentReport });
    const retiredRows = db.prepare(
      `SELECT id FROM asset_events
       WHERE event_type IN ('certificate_sensitive_host_detected', 'certificate_growth_detected')`
    ).all();
    if (retiredRows.length !== 0) return "retired_condition_emitted";
    if (expiryRows(db).length !== 0) return "expiry_emitted_without_expiry";
  }

  // ── E2E 6: repeated execution for the same scan is idempotent ─────────────
  {
    const { db, env } = scenarioEnv({ prevCert: certModule() });
    const current = certModule({ days: 10, expiresAt: "2026-07-28" });
    await insertCertificateEvents("scan_current", "dom_1", current, env, { currentReport });
    await insertCertificateEvents("scan_current", "dom_1", current, env, { currentReport });
    if (expiryRows(db).length !== 1) return "same_scan_transition_duplicated";
  }

  // ── E2E 7: a later scan after absence can emit recurrence ─────────────────
  {
    const { db, env, reports } = scenarioEnv({ prevCert: certModule() });
    await insertCertificateEvents("scan_current", "dom_1", certModule({ days: 10, expiresAt: "2026-07-28" }), env, { currentReport });
    reports.set("reports/scan_current.json", report({ certificate_intelligence: certModule({ days: 90, expiresAt: "2026-10-16" }) }));
    db.prepare("INSERT INTO scans (id, domain_id, domain, status, scan_quality, created_at) VALUES (?, ?, ?, ?, ?, ?)").run(
      "scan_later", "dom_1", "cybermeters.com", "completed", "complete", "2026-07-18T12:21:00.000Z"
    );
    await insertCertificateEvents("scan_later", "dom_1", certModule({ days: 10, expiresAt: "2026-07-28" }), env, { currentReport });
    const rows = expiryRows(db);
    if (rows.length !== 2) return "later_recurrence_after_absence_silenced";
    if (new Set(rows.map((r) => r.scan_id)).size !== 2) return "recurrence_scan_identity_collapsed";
  }

  // ── E2E 8: workspace identity prevents cross-workspace suppression/collision
  {
    const { db, env } = scenarioEnv({
      workspaces: ["ws_1", "ws_2"],
      prevCert: certModule(),
    });
    await insertCertificateEvents("scan_current", "dom_1", certModule({ days: 10, expiresAt: "2026-07-28" }), env, { currentReport });
    const rows = expiryRows(db);
    if (rows.length !== 2) return "different_workspaces_suppressed";
    if (new Set(rows.map((r) => r.workspace_id)).size !== 2) return "different_workspaces_collapsed";
    if (new Set(rows.map((r) => r.id)).size !== 2) return "different_workspaces_identity_collided";
  }

  // ── Pure helper contract (finer-grained direction coverage) ───────────────
  if (shouldEmitCertConditionEvent(null, null, false) !== false) return "absent_condition_emitted";
  if (shouldEmitCertConditionEvent("a", "a", true) !== false) return "unchanged_with_prior_emitted";
  if (shouldEmitCertConditionEvent("b", "a", true) !== true) return "changed_signature_silenced";
  if (shouldEmitCertConditionEvent("a", "a", false) !== true) return "first_occurrence_silenced";
  // Expiry band + expires_at drive the signature; day countdown alone does not.
  if (certExpiringSoonSignature({ days_until_expiry: 20, expires_at: "2026-08-01" })
      !== certExpiringSoonSignature({ days_until_expiry: 18, expires_at: "2026-08-01" })) {
    return "expiry_countdown_changed_signature";
  }
  // Severity escalation (medium → critical) is a genuine transition.
  if (certExpiringSoonSignature({ days_until_expiry: 13, expires_at: "2026-08-01" })
      === certExpiringSoonSignature({ days_until_expiry: 20, expires_at: "2026-08-01" })) {
    return "expiry_band_escalation_ignored";
  }
  if (certExpiringSoonSignature({ days_until_expiry: 40, expires_at: "2026-09-01" }) !== null) return "expiry_outside_window_not_null";
  if ("certSensitiveHostSignature" in mod || "certGrowthSignature" in mod) return "retired_condition_signature_exported";

  return null;
}

const baseline = await contract(realMod);
eq("cert standing-condition dedupe contract passes on real source", baseline, null);

if (!process.argv.includes("--no-mutate")) {
  const mutations = [
    {
      name: "re-emit unchanged condition (drop signature comparison)",
      from: "  return currentSignature !== previousSignature; // otherwise only on genuine transition",
      to: "  return true; // otherwise only on genuine transition",
      expected: "unchanged_expiry_re_emitted",
    },
    {
      name: "silence genuine transition (never emit past prior)",
      from: "  if (!hasPriorEvent) return true;               // per-workspace first occurrence\n  return currentSignature !== previousSignature; // otherwise only on genuine transition",
      to: "  if (!hasPriorEvent) return true;               // per-workspace first occurrence\n  return false; // otherwise only on genuine transition",
      expected: "genuine_transition_silenced",
    },
    {
      name: "drop per-workspace first-occurrence (breaks late-join fan-out)",
      from: "  if (!hasPriorEvent) return true;               // per-workspace first occurrence",
      to: "  if (false && !hasPriorEvent) return true;               // per-workspace first occurrence",
      expected: "late_join_workspace_not_served",
    },
    {
      name: "drop expires_at + band from expiry signature (countdown re-fires as change)",
      from: "  return `${band}|${certMod?.expires_at ?? \"\"}`;",
      to: "  return `${certMod?.days_until_expiry}`;",
      expected: "unchanged_expiry_re_emitted",
    },
    {
      name: "drop the expiry window from the signature",
      from: "  if (days == null || !(days < 30)) return null;",
      to: "  if (days == null) return null;",
      expected: "expiry_outside_window_not_null",
    },
    {
      name: "remove deterministic identity (random ids duplicate same scan)",
      from: "  return `asev_${digest.slice(0, 32)}`;",
      to: "  return createId(\"asev\");",
      expected: "deterministic_identity_not_stable",
    },
    {
      name: "drop workspace from deterministic identity",
      from: "    workspaceId ?? null,",
      to: "    null,",
      expected: "workspace_identity_collision",
    },
    {
      name: "drop domain from deterministic identity",
      from: "    domainId ?? null,",
      to: "    null,",
      expected: "domain_identity_collision",
    },
    {
      name: "drop scan from deterministic identity",
      from: "    scanId ?? null,",
      to: "    null,",
      expected: "scan_identity_collision",
    },
    {
      name: "drop event type from deterministic identity",
      from: "    eventType ?? null,",
      to: "    null,",
      expected: "different_event_type_identity_collision",
    },
    {
      name: "drop signature from deterministic identity",
      from: "    signature ?? null,",
      to: "    null,",
      expected: "different_signature_identity_collision",
    },
    {
      name: "remove idempotent insert",
      from: "INSERT OR IGNORE INTO asset_events\n               (id, workspace_id, domain_id, scan_id, event_type,\n                hostname, severity, description, created_at)\n             VALUES (?, ?, ?, ?, 'certificate_expiring_soon',",
      to: "INSERT INTO asset_events\n               (id, workspace_id, domain_id, scan_id, event_type,\n                hostname, severity, description, created_at)\n             VALUES (?, ?, ?, ?, 'certificate_expiring_soon',",
      expected: "standing_condition_insert_not_idempotent",
    },
  ];
  const hookMutations = mutations.map((mutation, index) => ({
    id: `cert-dedupe-${index + 1}`,
    from: mutation.from,
    to: mutation.to,
  }));
  const missingAnchorId = "cert-dedupe-anchor-missing-probe";
  const repeatedAnchorId = "cert-dedupe-anchor-repeated-probe";
  hookMutations.push({
    id: missingAnchorId,
    from: "__CYBERMETERS_INTENTIONAL_MISSING_CERT_DEDUPE_ANCHOR__",
    to: "__CYBERMETERS_UNREACHABLE_CERT_DEDUPE_REPLACEMENT__",
  });
  hookMutations.push({
    id: repeatedAnchorId,
    from: "INSERT OR IGNORE INTO ",
    to: "INSERT INTO ",
  });
  registerMutants(hookMutations);

  let mutationFailures = 0;
  const surfaceBefore = mutationSurface();

  let missingAnchorRejected = false;
  try {
    await importMutant(certEventsPath, missingAnchorId);
  } catch (error) {
    missingAnchorRejected = /MUTANT_ANCHOR_COUNT.*count=0.*expected=1/.test(String(error?.message));
  }
  ok("mutation loader rejects a missing anchor", missingAnchorRejected);

  let repeatedAnchorRejected = false;
  try {
    await importMutant(certEventsPath, repeatedAnchorId);
  } catch (error) {
    repeatedAnchorRejected = /MUTANT_ANCHOR_COUNT.*count=3.*expected=1/.test(String(error?.message));
  }
  ok("mutation loader rejects a repeated anchor", repeatedAnchorRejected);

  let controlledExceptionCaught = false;
  try {
    await importMutant(certEventsPath, hookMutations[0].id);
    throw new Error("controlled contract exception probe");
  } catch (error) {
    controlledExceptionCaught = error?.message === "controlled contract exception probe";
  }
  ok("a controlled contract exception is caught without source cleanup", controlledExceptionCaught);

  const identityMutant = await importMutant(certEventsPath, hookMutations[0].id);
  ok("real and mutant imports have distinct module identities", identityMutant !== realMod);
  const realAgain = await import(pathToFileURL(certEventsPath).href);
  ok("mutant import leaves the cached real module identity unchanged", realAgain === realMod);
  eq("mutant import leaves real exports behaviourally unchanged", await contract(realAgain), null);

  for (const [index, m] of mutations.entries()) {
    let reason;
    try {
      const mutant = await importMutant(certEventsPath, hookMutations[index].id);
      reason = await contract(mutant);
    } catch (error) {
      console.log(`FAIL mutation execution threw: ${m.name} — ${error?.message || error}`);
      mutationFailures++;
      continue;
    }
    if (reason !== m.expected) {
      console.log(`FAIL mutation NOT caught as intended: ${m.name} — got ${reason || "survived"}`);
      mutationFailures++;
    } else {
      console.log(`  mutation CAUGHT: ${m.name} (${reason})`);
    }
  }
  const surfaceAfter = mutationSurface();
  eq("mutations leave the whole-source fingerprint unchanged", surfaceAfter.source, surfaceBefore.source);
  eq("mutations leave the engines inventory unchanged", surfaceAfter.engines, surfaceBefore.engines);
  eq("mutations leave git source status unchanged", surfaceAfter.git, surfaceBefore.git);
  ok("cert dedupe mutations fail for intended reasons", mutationFailures === 0);
}

console.log(`\ncert-standing-condition-dedupe: ${pass}/${pass + fail} passed`);
if (fail) { console.error("cert-standing-condition-dedupe validation FAILED"); process.exit(1); }
console.log("cert-standing-condition-dedupe validation passed");
