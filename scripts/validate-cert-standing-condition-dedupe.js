#!/usr/bin/env node
//
// Certificate standing-condition dedupe validator.
//
// insertCertificateEvents() emits three STANDING-condition asset_events
// (certificate_sensitive_host_detected / certificate_expiring_soon /
// certificate_growth_detected). Before this guard they re-fired on every
// comparable scan even when the underlying condition was unchanged, flooding
// the customer timeline with duplicate noise.
//
// This validator proves, DB-backed and end-to-end, that:
//   1. an UNCHANGED condition does not re-emit on a later comparable scan;
//   2. a GENUINE new occurrence / state transition still emits;
//   3. multi-workspace fan-out is preserved and each workspace tracks its OWN
//      last occurrence (a late-joining workspace still gets its first event);
//   4. repeated execution of the same scan remains idempotent;
//   5. recurrence after absence is still possible on a later scan;
//   6. raw asset_events history is append-only (no prior row mutated/deleted).
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

function certModule({ sensitive = [], days = null, expiresAt = null, total = 0 } = {}) {
  return {
    issued_for_sensitive_hosts: sensitive,
    days_until_expiry: days,
    expires_at: expiresAt,
    total_certificates_seen: total,
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

const sensitiveRows = (db) => db.prepare(
  "SELECT id, workspace_id, scan_id, description FROM asset_events WHERE event_type = 'certificate_sensitive_host_detected' ORDER BY created_at, id"
).all();
const typeRows = (db, type) => db.prepare(
  "SELECT id, workspace_id, scan_id FROM asset_events WHERE event_type = ? ORDER BY created_at, id"
).all(type);
const allRows = (db) => db.prepare("SELECT id, event_type, description FROM asset_events ORDER BY id").all();

const currentReport = report();

// The full behavioural + pure contract. Returns null on success, else the first
// failing reason string. Re-run against each mutant so every guard is proven.
async function contract(mod) {
  const {
    insertCertificateEvents,
    certSensitiveHostSignature,
    certExpiringSoonSignature,
    certGrowthSignature,
    shouldEmitCertConditionEvent,
    certConditionEventId,
  } = mod;

  if (typeof certConditionEventId !== "function") return "deterministic_identity_missing";
  const idSameA = await certConditionEventId({
    workspaceId: "ws_1",
    domainId: "dom_1",
    scanId: "scan_current",
    eventType: "certificate_sensitive_host_detected",
    signature: "admin.cybermeters.com",
  });
  const idSameB = await certConditionEventId({
    workspaceId: "ws_1",
    domainId: "dom_1",
    scanId: "scan_current",
    eventType: "certificate_sensitive_host_detected",
    signature: "admin.cybermeters.com",
  });
  if (idSameA !== idSameB) return "deterministic_identity_not_stable";
  if (!/^asev_[a-f0-9]{32}$/.test(idSameA)) return "deterministic_identity_malformed";
  if (idSameA === await certConditionEventId({ workspaceId: "ws_2", domainId: "dom_1", scanId: "scan_current", eventType: "certificate_sensitive_host_detected", signature: "admin.cybermeters.com" })) {
    return "workspace_identity_collision";
  }
  if (idSameA === await certConditionEventId({ workspaceId: "ws_1", domainId: "dom_2", scanId: "scan_current", eventType: "certificate_sensitive_host_detected", signature: "admin.cybermeters.com" })) {
    return "domain_identity_collision";
  }
  if (idSameA === await certConditionEventId({ workspaceId: "ws_1", domainId: "dom_1", scanId: "scan_later", eventType: "certificate_sensitive_host_detected", signature: "admin.cybermeters.com" })) {
    return "scan_identity_collision";
  }
  if (idSameA === await certConditionEventId({ workspaceId: "ws_1", domainId: "dom_1", scanId: "scan_current", eventType: "certificate_expiring_soon", signature: "admin.cybermeters.com" })) {
    return "different_event_type_identity_collision";
  }
  if (idSameA === await certConditionEventId({ workspaceId: "ws_1", domainId: "dom_1", scanId: "scan_current", eventType: "certificate_sensitive_host_detected", signature: "vpn.cybermeters.com" })) {
    return "different_signature_identity_collision";
  }
  const insertSource = insertCertificateEvents.toString();
  if ((insertSource.match(/INSERT OR IGNORE INTO asset_events/g) || []).length < 3) return "standing_condition_insert_not_idempotent";

  // E2E behavioural checks run FIRST so a broken guard is caught as the exact
  // customer-visible symptom (re-emit / silence / lost fan-out), then the pure
  // helper contract adds finer-grained coverage.

  // ── E2E 1: unchanged sensitive set on a later comparable scan → silent ─────
  {
    const set = ["api.cybermeters.com", "app.cybermeters.com"];
    const { db, env } = scenarioEnv({
      prevCert: certModule({ sensitive: set }),
      priorEvents: [{ id: "prior_1", workspace_id: "ws_1", event_type: "certificate_sensitive_host_detected", hostname: set[0], description: "2 sensitive hostname(s) found in CT logs: " + set.join(", ") }],
    });
    await insertCertificateEvents("scan_current", "dom_1", certModule({ sensitive: set }), env, { currentReport });
    if (sensitiveRows(db).length !== 1) return "unchanged_set_re_emitted";
    // Append-only: the seeded prior row is intact.
    if (!allRows(db).some((r) => r.id === "prior_1")) return "prior_row_lost";
  }

  // ── E2E 2: a new sensitive host appears → emit ─────────────────────────────
  {
    const prev = ["api.cybermeters.com", "app.cybermeters.com"];
    const curr = ["admin.cybermeters.com", "api.cybermeters.com", "app.cybermeters.com"];
    const { db, env } = scenarioEnv({
      prevCert: certModule({ sensitive: prev }),
      priorEvents: [{ id: "prior_1", workspace_id: "ws_1", event_type: "certificate_sensitive_host_detected", hostname: prev[0] }],
    });
    await insertCertificateEvents("scan_current", "dom_1", certModule({ sensitive: curr }), env, { currentReport });
    if (sensitiveRows(db).length !== 2) return "genuine_new_host_silenced";
  }

  // ── E2E 3: fan-out — a genuine change emits once per workspace ─────────────
  {
    const prev = ["api.cybermeters.com"];
    const curr = ["api.cybermeters.com", "vpn.cybermeters.com"];
    const { db, env } = scenarioEnv({
      workspaces: ["ws_1", "ws_2"],
      prevCert: certModule({ sensitive: prev }),
      priorEvents: [
        { id: "p_ws1", workspace_id: "ws_1", event_type: "certificate_sensitive_host_detected", hostname: prev[0] },
        { id: "p_ws2", workspace_id: "ws_2", event_type: "certificate_sensitive_host_detected", hostname: prev[0] },
      ],
    });
    await insertCertificateEvents("scan_current", "dom_1", certModule({ sensitive: curr }), env, { currentReport });
    const fresh = sensitiveRows(db).filter((r) => r.id !== "p_ws1" && r.id !== "p_ws2");
    if (fresh.length !== 2) return "fanout_not_one_event_per_workspace";
    if (new Set(fresh.map((r) => r.workspace_id)).size !== 2) return "fanout_lost_a_workspace";
  }

  // ── E2E 4: late-joining workspace, unchanged set → it still gets its first ─
  {
    const set = ["api.cybermeters.com"];
    const { db, env } = scenarioEnv({
      workspaces: ["ws_1", "ws_2"],
      prevCert: certModule({ sensitive: set }),
      // Only ws_1 has recorded the condition before; ws_2 joined later.
      priorEvents: [{ id: "p_ws1", workspace_id: "ws_1", event_type: "certificate_sensitive_host_detected", hostname: set[0] }],
    });
    await insertCertificateEvents("scan_current", "dom_1", certModule({ sensitive: set }), env, { currentReport });
    const fresh = sensitiveRows(db).filter((r) => r.id !== "p_ws1");
    if (fresh.length !== 1) return "late_join_workspace_not_served";
    if (fresh[0].workspace_id !== "ws_2") return "late_join_served_wrong_workspace";
  }

  // ── E2E 5: expiring-soon standing condition does not re-fire on countdown ──
  {
    const { db, env } = scenarioEnv({
      prevCert: certModule({ days: 20, expiresAt: "2026-08-05" }),
      priorEvents: [{ id: "exp_1", workspace_id: "ws_1", event_type: "certificate_expiring_soon" }],
    });
    await insertCertificateEvents("scan_current", "dom_1", certModule({ days: 18, expiresAt: "2026-08-05" }), env, { currentReport });
    if (typeRows(db, "certificate_expiring_soon").length !== 1) return "expiry_countdown_re_emitted";
  }

  // ── E2E 6: growth standing condition does not re-fire while over threshold ─
  {
    const { db, env } = scenarioEnv({
      prevCert: certModule({ total: 60 }),
      priorEvents: [{ id: "grow_1", workspace_id: "ws_1", event_type: "certificate_growth_detected" }],
    });
    await insertCertificateEvents("scan_current", "dom_1", certModule({ total: 72 }), env, { currentReport });
    if (typeRows(db, "certificate_growth_detected").length !== 1) return "growth_standing_re_emitted";
  }

  // ── E2E 7: repeated execution for the same scan is idempotent ─────────────
  {
    const { db, env } = scenarioEnv({
      prevCert: certModule(),
      priorEvents: [{ id: "older_sensitive", workspace_id: "ws_1", event_type: "certificate_sensitive_host_detected", hostname: "old.cybermeters.com" }],
    });
    const current = certModule({ sensitive: ["admin.cybermeters.com"] });
    await insertCertificateEvents("scan_current", "dom_1", current, env, { currentReport });
    await insertCertificateEvents("scan_current", "dom_1", current, env, { currentReport });
    const fresh = sensitiveRows(db).filter((r) => r.id !== "older_sensitive");
    if (fresh.length !== 1) return "same_scan_transition_duplicated";
  }

  // ── E2E 8: a later scan after absence can emit recurrence ─────────────────
  {
    const { db, env, reports } = scenarioEnv({
      prevCert: certModule(),
      priorEvents: [{ id: "older_sensitive", workspace_id: "ws_1", event_type: "certificate_sensitive_host_detected", hostname: "old.cybermeters.com" }],
    });
    await insertCertificateEvents("scan_current", "dom_1", certModule({ sensitive: ["admin.cybermeters.com"] }), env, { currentReport });
    reports.set("reports/scan_current.json", report({ certificate_intelligence: certModule() }));
    db.prepare("INSERT INTO scans (id, domain_id, domain, status, scan_quality, created_at) VALUES (?, ?, ?, ?, ?, ?)").run(
      "scan_later", "dom_1", "cybermeters.com", "completed", "complete", "2026-07-18T12:21:00.000Z"
    );
    await insertCertificateEvents("scan_later", "dom_1", certModule({ sensitive: ["admin.cybermeters.com"] }), env, { currentReport });
    const fresh = sensitiveRows(db).filter((r) => r.id !== "older_sensitive");
    if (fresh.length !== 2) return "later_recurrence_after_absence_silenced";
    if (new Set(fresh.map((r) => r.scan_id)).size !== 2) return "recurrence_scan_identity_collapsed";
  }

  // ── E2E 9: workspace identity prevents cross-workspace suppression/collision
  {
    const { db, env } = scenarioEnv({
      workspaces: ["ws_1", "ws_2"],
      prevCert: certModule(),
    });
    await insertCertificateEvents("scan_current", "dom_1", certModule({ sensitive: ["admin.cybermeters.com"] }), env, { currentReport });
    const rows = sensitiveRows(db);
    if (rows.length !== 2) return "different_workspaces_suppressed";
    if (new Set(rows.map((r) => r.workspace_id)).size !== 2) return "different_workspaces_collapsed";
    if (new Set(rows.map((r) => r.id)).size !== 2) return "different_workspaces_identity_collided";
  }

  // ── E2E 10: event type identity prevents cross-type collision ──────────────
  {
    const { db, env } = scenarioEnv({ prevCert: certModule() });
    await insertCertificateEvents(
      "scan_current",
      "dom_1",
      certModule({ sensitive: ["admin.cybermeters.com"], days: 10, expiresAt: "2026-07-28", total: 80 }),
      env,
      { currentReport }
    );
    const rows = db.prepare(
      `SELECT id, event_type FROM asset_events
       WHERE event_type IN ('certificate_sensitive_host_detected',
                            'certificate_expiring_soon',
                            'certificate_growth_detected')
       ORDER BY event_type`
    ).all();
    if (rows.length !== 3) return "different_event_types_collided";
    if (new Set(rows.map((r) => r.id)).size !== 3) return "different_event_type_identity_collided";
  }

  // ── Pure helper contract (finer-grained direction coverage) ───────────────
  // Signature is order-independent (set semantics).
  if (certSensitiveHostSignature({ issued_for_sensitive_hosts: ["b.x", "a.x"] })
      !== certSensitiveHostSignature({ issued_for_sensitive_hosts: ["a.x", "b.x"] })) {
    return "signature_not_order_independent";
  }
  // A different set yields a different signature.
  if (certSensitiveHostSignature({ issued_for_sensitive_hosts: ["a.x"] })
      === certSensitiveHostSignature({ issued_for_sensitive_hosts: ["a.x", "b.x"] })) {
    return "signature_ignores_set_change";
  }
  // Absent condition → null signature → never emits.
  if (certSensitiveHostSignature({ issued_for_sensitive_hosts: [] }) !== null) return "empty_set_not_null";
  if (shouldEmitCertConditionEvent(null, null, false) !== false) return "absent_condition_emitted";
  // Present-but-unchanged with a prior event → silent.
  if (shouldEmitCertConditionEvent("a", "a", true) !== false) return "unchanged_with_prior_emitted";
  // Present + changed signature → emit.
  if (shouldEmitCertConditionEvent("a\nb", "a", true) !== true) return "changed_signature_silenced";
  // Present + no prior event for this workspace → emit (first occurrence).
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
  if (certGrowthSignature({ total_certificates_seen: 40 }) !== null) return "growth_below_threshold_not_null";
  if (certGrowthSignature({ total_certificates_seen: 60 }) === null) return "growth_above_threshold_null";

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
      expected: "unchanged_set_re_emitted",
    },
    {
      name: "silence genuine transition (never emit past prior)",
      from: "  if (!hasPriorEvent) return true;               // per-workspace first occurrence\n  return currentSignature !== previousSignature; // otherwise only on genuine transition",
      to: "  if (!hasPriorEvent) return true;               // per-workspace first occurrence\n  return false; // otherwise only on genuine transition",
      expected: "genuine_new_host_silenced",
    },
    {
      name: "drop per-workspace first-occurrence (breaks late-join fan-out)",
      from: "  if (!hasPriorEvent) return true;               // per-workspace first occurrence",
      to: "  if (false && !hasPriorEvent) return true;               // per-workspace first occurrence",
      expected: "late_join_workspace_not_served",
    },
    {
      name: "collapse sensitive-host set to a constant (set change no longer emits)",
      from: "  return [...new Set(hosts.map((h) => String(h)))].sort().join(\"\\n\");",
      to: "  return \"sensitive\";",
      expected: "genuine_new_host_silenced",
    },
    {
      name: "drop expires_at + band from expiry signature (countdown re-fires as change)",
      from: "  return `${band}|${certMod?.expires_at ?? \"\"}`;",
      to: "  return `${certMod?.days_until_expiry}`;",
      expected: "expiry_countdown_re_emitted",
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
      from: "INSERT OR IGNORE INTO asset_events\n               (id, workspace_id, domain_id, scan_id, event_type,\n                hostname, severity, description, created_at)\n             VALUES (?, ?, ?, ?, 'certificate_sensitive_host_detected',",
      to: "INSERT INTO asset_events\n               (id, workspace_id, domain_id, scan_id, event_type,\n                hostname, severity, description, created_at)\n             VALUES (?, ?, ?, ?, 'certificate_sensitive_host_detected',",
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
    from: "INSERT OR IGNORE INTO asset_events",
    to: "INSERT INTO asset_events",
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
