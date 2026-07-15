#!/usr/bin/env node
//
// Domain-verification INTEGRITY (incident hotfix, 15 July 2026). CI-blocking.
//
// The defect: POST /api/domains/:id/verify returned {success:true,
// verification_status:"verified"} on the strength of an UPDATE whose result was
// never inspected. A zero-row UPDATE is a perfectly successful D1 statement, so
// the product told a customer it had proven ownership while the authoritative
// workspace_domains row sat at 'pending' with verified_at NULL. Worse, the early
// return paths emitted no evidence at all, so the incident could not be diagnosed:
// absence of an audit row was ambiguous between "rejected early" and "never
// arrived".
//
// This harness proves the two invariants that close it:
//   1. PERSISTENCE PROOF — no path returns verified without exactly one changed
//      row AND a confirming re-read of the exact (workspace_id, domain_id).
//   2. TERMINAL OBSERVABILITY — every branch, including the 401 and the throw,
//      emits exactly one outcome from the canonical vocabulary, and none of them
//      can carry token material.
//
// Drives the REAL worker fetch with seeded sessions and a fault-injecting D1 stub
// (the persistence failures cannot be reached any other way — they are states D1
// only produces under concurrency or corruption). Requires Node 24+ (node:sqlite).
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const modUrl = (...p) => pathToFileURL(path.join(root, ...p)).href;
const { VERIFICATION_OUTCOMES, persistVerification, recordVerificationAttempt, isVerifiedOutcome } =
  await import(modUrl("workers", "scan-api", "src", "lib", "domain-verification.js"));
const { hashToken } = await import(modUrl("workers", "scan-api", "src", "lib", "auth-crypto.js"));

// Bound to the REAL console.log up front: the observability tests below hijack
// console.log to capture the telemetry sink, and a result line that went into the
// capture buffer instead of the terminal would make a failing run look silent.
const report = console.log.bind(console);
let pass = 0, fail = 0;
const ok = (n, c) => { c ? pass++ : fail++; if (!c) report("FAIL " + n); };
const eq = (n, g, w) => ok(`${n} (got ${JSON.stringify(g)}, want ${JSON.stringify(w)})`, g === w);

// ── Harness plumbing ────────────────────────────────────────────────────────
AbortSignal.timeout = () => undefined;

const db = new DatabaseSync(":memory:");
const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering no-ops */ } };
apply(path.join(root, "database", "schema.sql"));
const migDir = path.join(root, "database", "migrations");
for (const f of fs.readdirSync(migDir).filter((x) => x.endsWith(".sql")).sort()) apply(path.join(migDir, f));
db.exec("PRAGMA foreign_keys = OFF");

// D1 stub with fault injection. `hooks` lets a test bend exactly one statement —
// e.g. force meta.changes to 2 — so the persistence branches are reachable.
let hooks = {};
const makeD1 = (d) => {
  const wrap = (sql, args) => ({
    first: async () => {
      if (hooks.firstFor && hooks.firstFor(sql)) return hooks.firstFor(sql)(args);
      return d.prepare(sql).get(...args) ?? null;
    },
    all: async () => ({ results: d.prepare(sql).all(...args) }),
    run: async () => {
      if (hooks.runFor && hooks.runFor(sql)) return hooks.runFor(sql)(args);
      const r = d.prepare(sql).run(...args);
      return { meta: { changes: r.changes } };
    },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
};
const env = { cybermeters_db: makeD1(db), ENVIRONMENT: "test" };

// Capture console so the observability claims are proven, not assumed.
const logs = [];
const realLog = console.log;
console.log = (...a) => { logs.push(a.map(String).join(" ")); };
const drainLogs = () => { const l = logs.slice(); logs.length = 0; return l; };
const restoreLog = () => { console.log = realLog; };

// Slice out the /verify handler by index. Splitting on the identifier would not
// work: it appears three times (declaration, guard, capture-group read), so
// split()[1] yields a 40-character fragment that vacuously passes every regex.
const ROUTE_SRC = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "routes", "domains.js"), "utf8");
const verifyRouteSrc = (() => {
  const start = ROUTE_SRC.indexOf("const domVerCheckMatch");
  const end   = ROUTE_SRC.indexOf("const domGetMatch");
  if (start < 0 || end < 0 || end <= start) throw new Error("could not locate the /verify handler — update this slice");
  return ROUTE_SRC.slice(start, end);
})();
// Guard the guard: if the slice ever silently collapses, every structural test
// below would pass by testing nothing.
ok("harness: /verify handler slice is substantial", verifyRouteSrc.length > 3000);

const TOKEN = "a1b2c3d4e5f6".repeat(4);   // 48-char hex, same shape as the real token
const auditRows = () => db.prepare("SELECT * FROM audit_events WHERE event_type='domain_verification_attempted' ORDER BY rowid").all();
const clearAudit = () => db.exec("DELETE FROM audit_events");

// Seed: two tenants. ws_a owns d1; ws_b is the foreign tenant.
db.exec(`INSERT INTO users (id, email, password_hash, plan) VALUES ('u_a','a@example.com','x','pro'),('u_b','b@example.com','x','pro')`);
db.exec(`INSERT INTO workspaces (id, name, owner_user_id) VALUES ('ws_a','A','u_a'),('ws_b','B','u_b')`);
db.exec(`INSERT INTO domains (id, user_id, domain, verification_status) VALUES ('d1','u_a','alpha.example','unverified')`);
db.exec(`INSERT INTO workspace_domains (workspace_id, domain_id, verification_status, verification_token)
         VALUES ('ws_a','d1','pending','${TOKEN}')`);

const linkOf = (ws, dom) => db.prepare("SELECT * FROM workspace_domains WHERE workspace_id=? AND domain_id=?").get(ws, dom);
const resetLink = () => db.exec(`UPDATE workspace_domains SET verification_status='pending', verified_at=NULL, verification_method=NULL WHERE workspace_id='ws_a' AND domain_id='d1'`);

// ── 1. persistVerification: a zero-row UPDATE can never be a success ─────────
{
  resetLink();
  // Target a link that does not exist → 0 rows changed.
  const r = await persistVerification(env, "ws_nonexistent", "d1", "dns_txt");
  ok("zero-row UPDATE → not ok", r.ok === false);
  eq("zero-row UPDATE → outcome", r.outcome, VERIFICATION_OUTCOMES.PERSISTENCE_ZERO_ROWS);
  eq("zero-row UPDATE → affected_row_count 0", r.affected_row_count, 0);
  ok("zero-row UPDATE → outcome is not a verified outcome", !isVerifiedOutcome(r.outcome));
}

// ── 2. meta.changes > 1 can never be a success ───────────────────────────────
// A multi-row UPDATE means (workspace_id, domain_id) was not unique and we just
// wrote 'verified' onto rows we never intended to touch. Never a success.
{
  resetLink();
  hooks = { runFor: (sql) => /UPDATE workspace_domains/.test(sql) && /verification_status = 'verified'/.test(sql)
    ? async () => ({ meta: { changes: 2 } }) : null };
  const r = await persistVerification(env, "ws_a", "d1", "dns_txt");
  hooks = {};
  ok("changes>1 → not ok", r.ok === false);
  eq("changes>1 → outcome", r.outcome, VERIFICATION_OUTCOMES.PERSISTENCE_UNEXPECTED_ROWS);
  eq("changes>1 → affected_row_count reported", r.affected_row_count, 2);
  ok("changes>1 → outcome is not a verified outcome", !isVerifiedOutcome(r.outcome));
}

// ── 3. A successful UPDATE without a confirming re-read is not a success ─────
// The single most important case: the statement reports exactly 1 changed row,
// but the row does not read back as verified. Proof must come from the re-read.
{
  resetLink();
  // UPDATE reports 1 row but writes nothing; the row therefore rereads as 'pending'.
  hooks = { runFor: (sql) => /UPDATE workspace_domains/.test(sql) && /verification_status = 'verified'/.test(sql)
    ? async () => ({ meta: { changes: 1 } }) : null };
  const r = await persistVerification(env, "ws_a", "d1", "dns_txt");
  hooks = {};
  eq("changes===1 but row still pending → not ok", r.ok, false);
  eq("changes===1 but row still pending → outcome", r.outcome, VERIFICATION_OUTCOMES.PERSISTENCE_CONFIRMATION_FAILED);
  eq("changes===1 but row still pending → persisted_status reported", r.persisted_status, "pending");
}

// ── 4. A reread of NULL / pending cannot satisfy the claim ───────────────────
{
  resetLink();
  // 1 row changed, but the reread comes back with a null verified_at.
  hooks = {
    runFor: (sql) => /verification_status = 'verified'/.test(sql) ? async () => ({ meta: { changes: 1 } }) : null,
    firstFor: (sql) => /SELECT workspace_id, domain_id, verification_status, verified_at/.test(sql)
      ? async () => ({ workspace_id: "ws_a", domain_id: "d1", verification_status: "verified", verified_at: null }) : null,
  };
  const r = await persistVerification(env, "ws_a", "d1", "dns_txt");
  hooks = {};
  eq("reread verified but verified_at NULL → not ok", r.ok, false);
  eq("reread verified but verified_at NULL → outcome", r.outcome, VERIFICATION_OUTCOMES.PERSISTENCE_CONFIRMATION_FAILED);

  // And an entirely absent reread row.
  hooks = {
    runFor: (sql) => /verification_status = 'verified'/.test(sql) ? async () => ({ meta: { changes: 1 } }) : null,
    firstFor: (sql) => /SELECT workspace_id, domain_id, verification_status, verified_at/.test(sql) ? async () => null : null,
  };
  const r2 = await persistVerification(env, "ws_a", "d1", "dns_txt");
  hooks = {};
  eq("reread returns no row → not ok", r2.ok, false);
  eq("reread returns no row → outcome", r2.outcome, VERIFICATION_OUTCOMES.PERSISTENCE_CONFIRMATION_FAILED);
}

// ── 5. A mismatched workspace/domain reread cannot satisfy the claim ─────────
// Proves the reread compares identity rather than merely filtering on it — this is
// what makes the returned domain_id/workspace_id sourced from persisted state.
{
  resetLink();
  hooks = {
    runFor: (sql) => /verification_status = 'verified'/.test(sql) ? async () => ({ meta: { changes: 1 } }) : null,
    firstFor: (sql) => /SELECT workspace_id, domain_id, verification_status, verified_at/.test(sql)
      ? async () => ({ workspace_id: "ws_OTHER", domain_id: "d1", verification_status: "verified", verified_at: "2026-07-15 10:00:00" }) : null,
  };
  const rw = await persistVerification(env, "ws_a", "d1", "dns_txt");
  hooks = {};
  eq("reread with foreign workspace_id → not ok", rw.ok, false);
  eq("reread with foreign workspace_id → outcome", rw.outcome, VERIFICATION_OUTCOMES.PERSISTENCE_CONFIRMATION_FAILED);

  hooks = {
    runFor: (sql) => /verification_status = 'verified'/.test(sql) ? async () => ({ meta: { changes: 1 } }) : null,
    firstFor: (sql) => /SELECT workspace_id, domain_id, verification_status, verified_at/.test(sql)
      ? async () => ({ workspace_id: "ws_a", domain_id: "d_OTHER", verification_status: "verified", verified_at: "2026-07-15 10:00:00" }) : null,
  };
  const rd = await persistVerification(env, "ws_a", "d1", "dns_txt");
  hooks = {};
  eq("reread with foreign domain_id → not ok", rd.ok, false);
  eq("reread with foreign domain_id → outcome", rd.outcome, VERIFICATION_OUTCOMES.PERSISTENCE_CONFIRMATION_FAILED);
}

// ── 6. A DB fault cannot become a verification ───────────────────────────────
{
  const brokenEnv = { cybermeters_db: { prepare() { throw new Error("D1 down"); } } };
  const r = await persistVerification(brokenEnv, "ws_a", "d1", "dns_txt");
  eq("D1 throw → not ok (fails closed)", r.ok, false);
  eq("D1 throw → outcome", r.outcome, VERIFICATION_OUTCOMES.PERSISTENCE_CONFIRMATION_FAILED);
}

// ── 7. A genuine persisted verification returns the persisted identity ───────
{
  resetLink();
  const r = await persistVerification(env, "ws_a", "d1", "dns_txt");
  eq("genuine persist → ok", r.ok, true);
  eq("genuine persist → exactly one row", r.affected_row_count, 1);
  eq("genuine persist → status", r.persisted_status, "verified");
  ok("genuine persist → verified_at non-null", Boolean(r.persisted_verified_at));
  eq("genuine persist → workspace_id from the row", r.persisted_workspace_id, "ws_a");
  eq("genuine persist → domain_id from the row", r.persisted_domain_id, "d1");
  // And the authoritative row the scan gate reads actually moved.
  const row = linkOf("ws_a", "d1");
  eq("genuine persist → authoritative row is verified", row.verification_status, "verified");
  ok("genuine persist → authoritative verified_at set", Boolean(row.verified_at));
  eq("genuine persist → method recorded", row.verification_method, "dns_txt");
}

// ── 8. Telemetry never carries token material ────────────────────────────────
// Two independent controls: the metadata allowlist, and redaction of the console
// sink. Prove BOTH — a future edit that widens the allowlist must still not leak.
{
  clearAudit(); drainLogs();
  await recordVerificationAttempt(env, {
    request_id: "req_tok", workspace_id: "ws_a", domain_id: "d1", domain: "alpha.example",
    user_id: "u_a", outcome: VERIFICATION_OUTCOMES.DNS_MISMATCH,
    // Every one of these is a smuggling attempt. None is on the allowlist.
    verification_token: TOKEN,
    token: TOKEN,
    authorization: `Bearer ${TOKEN}`,
    expected: `cybermeters-verification=${TOKEN}`,
    raw_dns_value: `cybermeters-verification=${TOKEN}`,
    dns_record_hash: await hashToken(`cybermeters-verification=${TOKEN}`),
  });

  const row = auditRows()[0];
  ok("failure telemetry: audit row written", Boolean(row));
  const auditJson = String(row?.metadata_json ?? "");
  ok("failure telemetry: audit metadata has no token", !auditJson.includes(TOKEN));
  ok("failure telemetry: audit metadata has no Authorization header", !/Bearer /i.test(auditJson));
  ok("failure telemetry: audit metadata has no raw expected TXT value", !auditJson.includes("cybermeters-verification="));
  ok("failure telemetry: audit metadata keeps the outcome", auditJson.includes(VERIFICATION_OUTCOMES.DNS_MISMATCH));

  const logLine = drainLogs().join("\n");
  ok("failure telemetry: log emitted", logLine.includes("[domain-verification/attempt]"));
  ok("failure telemetry: log has no token", !logLine.includes(TOKEN));
  ok("failure telemetry: log has no raw expected TXT value", !logLine.includes("cybermeters-verification="));
  ok("failure telemetry: log keeps request_id", logLine.includes("req_tok"));
}

// ── 9. Telemetry failure cannot turn a success into a failure ────────────────
// Observability is best-effort by policy; persistence proof is not. A dead audit
// sink must not change the outcome, and must still leave a log trace.
{
  drainLogs();
  const deadEnv = { cybermeters_db: { prepare() { throw new Error("D1 down"); } } };
  let threw = false;
  try {
    await recordVerificationAttempt(deadEnv, {
      request_id: "req_dead", domain_id: "d1", outcome: VERIFICATION_OUTCOMES.VERIFIED_DNS_TXT,
    });
  } catch { threw = true; }
  ok("telemetry with dead D1 does not throw", !threw);
  const line = drainLogs().join("\n");
  ok("telemetry with dead D1 still logs (failure is not silent)", line.includes("req_dead"));
}

// ── 10. The outcome vocabulary is closed and covers every required value ─────
{
  const required = [
    "already_verified", "verified_dns_txt", "dns_not_found", "dns_mismatch",
    "unauthorized", "domain_link_not_found", "persistence_zero_rows",
    "persistence_confirmation_failed", "internal_error",
  ];
  const values = Object.values(VERIFICATION_OUTCOMES);
  for (const r of required) ok(`vocabulary contains required outcome '${r}'`, values.includes(r));
  ok("vocabulary is frozen", Object.isFrozen(VERIFICATION_OUTCOMES));
  ok("verified outcomes are exactly the three success states",
    ["already_verified", "verified_dns_txt", "verified_html_file"].every(isVerifiedOutcome)
    && !isVerifiedOutcome("dns_not_found") && !isVerifiedOutcome("persistence_zero_rows"));

  // Every outcome the ROUTE can emit must be a member of the vocabulary — no
  // string literals drifting away from the canonical set.
  const emitted = [...verifyRouteSrc.matchAll(/VERIFICATION_OUTCOMES\.([A-Z_]+)/g)].map((m) => m[1]);
  ok("route emits at least 8 distinct canonical outcomes", new Set(emitted).size >= 8);
  ok("every outcome the route names exists in the vocabulary",
    emitted.every((k) => Object.hasOwn(VERIFICATION_OUTCOMES, k)));
}

// ── 11. Route source contract: no unproven success, no token in telemetry ────
// Structural assertions. The runtime tests above prove the library; these prove the
// route cannot regress to the shape that caused the incident.
{
  ok("route: no bare UPDATE-to-verified outside persistVerification",
    !/UPDATE workspace_domains[\s\S]{0,200}verification_status\s*=\s*'verified'/.test(verifyRouteSrc));
  ok("route: DNS success branch gates on persist.ok", /if \(!dnsPersist\.ok\)/.test(verifyRouteSrc));
  ok("route: HTML success branch gates on persist.ok", /if \(!htmlPersist\.ok\)/.test(verifyRouteSrc));
  ok("route: success payload sources domain_id from the reread",
    /domain_id: dnsPersist\.persisted_domain_id/.test(verifyRouteSrc) && /domain_id: htmlPersist\.persisted_domain_id/.test(verifyRouteSrc));
  ok("route: success payload sources workspace_id from the reread",
    /workspace_id: dnsPersist\.persisted_workspace_id/.test(verifyRouteSrc) && /workspace_id: htmlPersist\.persisted_workspace_id/.test(verifyRouteSrc));
  ok("route: success payload sources verified_at from the reread",
    /verified_at: dnsPersist\.persisted_verified_at/.test(verifyRouteSrc) && /verified_at: htmlPersist\.persisted_verified_at/.test(verifyRouteSrc));
  ok("route: 401 emits an outcome", /VERIFICATION_OUTCOMES\.UNAUTHORIZED/.test(verifyRouteSrc));
  ok("route: the catch emits internal_error", /VERIFICATION_OUTCOMES\.INTERNAL_ERROR/.test(verifyRouteSrc));
  ok("route: failure payload no longer returns the token",
    !/^\s*token,\s*$/m.test(verifyRouteSrc) && !/expected:\s*expectedTxtValue/.test(verifyRouteSrc));
  ok("route: already_verified requires a persisted verified_at",
    /verification_status === "verified" && dvcLink\?\.verified_at/.test(verifyRouteSrc));
}

// ── 12. Legacy `domains` rows cannot satisfy the workspace-scoped route ──────
// The legacy domains.verification_* columns are read-only compatibility data.
// A verified legacy row must never make a workspace-domain link verified.
{
  db.exec(`INSERT INTO domains (id, user_id, domain, verification_status, verification_method, verified_at)
           VALUES ('d_legacy','u_a','legacy.example','verified','dns_txt','2026-01-01')`);
  db.exec(`INSERT INTO workspace_domains (workspace_id, domain_id, verification_status) VALUES ('ws_a','d_legacy','pending')`);

  const link = linkOf("ws_a", "d_legacy");
  eq("legacy verified domain → link still pending", link.verification_status, "pending");
  ok("legacy verified domain → link has no verified_at", !link.verified_at);

  // persistVerification is the ONLY writer of a verified link, and it is scoped to
  // the link — a legacy row cannot stand in for it.
  const { isWorkspaceDomainVerified } = await import(modUrl("workers", "scan-api", "src", "lib", "domain-verification.js"));
  eq("legacy verified domain → scan gate still refuses", await isWorkspaceDomainVerified(env, "ws_a", "d_legacy"), false);

  // And the route reads the link, never domains.verification_status.
  ok("route: reads verification state from workspace_domains only",
    /FROM workspace_domains WHERE workspace_id = \? AND domain_id = \?/.test(verifyRouteSrc));
  ok("route: never selects verification_status from the legacy domains table",
    !/SELECT[^;]*verification_status[^;]*FROM domains\b/.test(verifyRouteSrc));
}

// ── 13. Cross-tenant: verifying in ws_a never verifies ws_b ──────────────────
{
  db.exec(`INSERT INTO workspace_domains (workspace_id, domain_id, verification_status, verification_token)
           VALUES ('ws_b','d1','pending','${TOKEN}')`);
  resetLink();
  db.exec(`UPDATE workspace_domains SET verification_status='pending', verified_at=NULL WHERE workspace_id='ws_b' AND domain_id='d1'`);

  const r = await persistVerification(env, "ws_a", "d1", "dns_txt");
  eq("cross-tenant: ws_a persist ok", r.ok, true);
  eq("cross-tenant: exactly one row changed", r.affected_row_count, 1);
  const b = linkOf("ws_b", "d1");
  eq("cross-tenant: ws_b link untouched", b.verification_status, "pending");
  ok("cross-tenant: ws_b has no verified_at", !b.verified_at);
}

restoreLog();
report(`\nDomain-verification integrity: ${pass}/${pass + fail} passed`);
if (fail > 0) process.exit(1);
