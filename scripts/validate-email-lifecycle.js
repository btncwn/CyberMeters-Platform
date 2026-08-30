#!/usr/bin/env node
//
// A1r lifecycle-email recovery contract. Real lifecycle functions, real schema,
// in-memory D1, mocked Resend, and loader-hook mutants. Node 24+.
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";
import { importMutant, registerMutants } from "./lib/mutant-import.mjs";
import { wholeSourceFingerprint } from "./run-local-focused-gate.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const lifecyclePath = path.join(root, "workers", "scan-api", "src", "lib", "lifecycle-email.js");
const sourceDir = path.join(root, "workers", "scan-api", "src");
const real = await import(pathToFileURL(lifecyclePath).href);

let groupsPassed = 0;
let groupsFailed = 0;
const group = async (name, run) => {
  try {
    const result = await run();
    if (result === false) throw new Error("contract returned false");
    groupsPassed += 1;
  } catch (error) {
    groupsFailed += 1;
    console.log(`FAIL group ${name} — ${error?.message || error}`);
  }
};
const must = (condition, message) => {
  if (!condition) throw new Error(message);
};

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* cumulative migrations */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const file of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", file));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  db.prepare("INSERT INTO users (id,email,email_verified) VALUES ('usr_ok','owner@example.co.uk',1)").run();
  db.prepare("INSERT INTO users (id,email,email_verified) VALUES ('usr_unv','pending@example.co.uk',0)").run();
  db.prepare("INSERT INTO workspaces (id,owner_user_id,name) VALUES ('ws_active','usr_ok','Acme')").run();
  db.prepare("INSERT INTO workspaces (id,owner_user_id,name,deleted_at) VALUES ('ws_deleted','usr_ok','Deleted',datetime('now'))").run();
  db.prepare("INSERT INTO workspaces (id,owner_user_id,name) VALUES ('ws_other','usr_ok','Other')").run();
  return db;
}

function makeD1(db, hooks = {}) {
  const trace = [];
  const wrap = (sql, args) => ({
    first: async () => {
      trace.push({ method: "first", sql, args });
      return db.prepare(sql).get(...args) ?? null;
    },
    all: async () => {
      trace.push({ method: "all", sql, args });
      return { results: db.prepare(sql).all(...args), success: true, meta: {} };
    },
    run: async () => {
      trace.push({ method: "run", sql, args });
      const overridden = await hooks.beforeRun?.({ db, sql, args, trace });
      if (overridden) return overridden;
      const result = db.prepare(sql).run(...args);
      const wrapped = { success: true, meta: { changes: result.changes } };
      await hooks.afterRun?.({ db, sql, args, trace, result: wrapped });
      return wrapped;
    },
  });
  return {
    trace,
    prepare(sql) {
      const base = wrap(sql, []);
      base.bind = (...args) => wrap(sql, args);
      return base;
    },
  };
}

let fetchHandler = async () => Response.json({ id: "re_default" });
let fetches = [];
const originalFetch = globalThis.fetch;
const originalTimeout = AbortSignal.timeout;
globalThis.fetch = async (url, options = {}) => {
  const record = { url: String(url), options };
  fetches.push(record);
  return fetchHandler(record);
};
AbortSignal.timeout = () => undefined;

function fixture({ hooks = {}, apiKey = "re_test" } = {}) {
  const db = buildDb();
  const d1 = makeD1(db, hooks);
  const env = {
    cybermeters_db: d1,
    RESEND_API_KEY: apiKey,
    HELLO_EMAIL_FROM: "hello@cybermeters.com",
    ALERT_EMAIL_FROM: "alerts@cybermeters.com",
    SAFE_EMAIL_FROM: "safe@cybermeters.com",
    FRONTEND_URL: "https://app.cybermeters.com",
    ALLOWED_ORIGIN: "https://app.cybermeters.com",
  };
  fetches = [];
  fetchHandler = async () => Response.json({ id: "re_ok" });
  return { db, d1, env };
}

function insertLifecycle(db, {
  id,
  type = "lifecycle_domain_added",
  userId = "usr_ok",
  workspaceId = "ws_active",
  domain = "acme.example",
  status,
  error = null,
  age = "-20 minutes",
} = {}) {
  const dedupeKey = real.lifecycleDedupeKey({ type, user_id: userId, workspace_id: workspaceId, domain });
  db.prepare(`INSERT INTO lifecycle_email_events
    (id,user_id,workspace_id,domain,type,dedupe_key,status,error,created_at)
    VALUES (?,?,?,?,?,?,?,?,datetime('now',?))`)
    .run(id, userId, workspaceId, domain, type, dedupeKey, status, error, age);
  return dedupeKey;
}

const row = (db, id) => db.prepare("SELECT * FROM lifecycle_email_events WHERE id=?").get(id);
const header = (record, name) => {
  const entries = record?.options?.headers instanceof Headers
    ? [...record.options.headers.entries()]
    : Object.entries(record?.options?.headers || {});
  return entries.find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1] ?? null;
};
const success = () => Response.json({ id: "re_accepted" }, { status: 200 });

// 1. New marked pending -> sending CAS -> sent, exactly one presentation.
await group("1 new marked claim", async () => {
  const { db, env } = fixture();
  let statusAtFetch = null;
  fetchHandler = async () => {
    statusAtFetch = db.prepare("SELECT status FROM lifecycle_email_events LIMIT 1").get()?.status;
    return success();
  };
  const result = await real.sendLifecycleEmail(env, { type: "lifecycle_welcome", user_id: "usr_ok" });
  const stored = db.prepare("SELECT * FROM lifecycle_email_events WHERE type='lifecycle_welcome'").get();
  must(result.sent === true && fetches.length === 1, "new send was not accepted exactly once");
  must(statusAtFetch === "sending", "provider was reached before sending CAS");
  must(stored.status === "sent" && stored.provider_id === "re_accepted", "terminal sent ledger missing");
});

// 2. Stale marked pending recovers; fresh marked pending does not.
await group("2 marked pending age boundary", async () => {
  const { db, env } = fixture();
  insertLifecycle(db, { id: "stale", domain: "stale.example", status: "pending", error: "provider_not_started", age: "-20 minutes" });
  insertLifecycle(db, { id: "fresh", domain: "fresh.example", status: "pending", error: "provider_not_started", age: "-1 minute" });
  insertLifecycle(db, { id: "expired", domain: "expired.example", status: "pending", error: "provider_not_started", age: "-4 days" });
  await real.retryFailedLifecycleEmails(env);
  must(fetches.length === 1 && row(db, "stale").status === "sent", "stale marked row not recovered once");
  must(row(db, "fresh").status === "pending", "fresh marked row was presented");
  must(row(db, "expired").status === "pending", "row outside three-day window was presented");

  const bounded = fixture();
  for (let index = 0; index < 12; index += 1) {
    insertLifecycle(bounded.db, { id: `bounded_${index}`, domain: `bounded-${index}.example`, status: "pending", error: "provider_not_started" });
  }
  await real.retryFailedLifecycleEmails(bounded.env);
  must(fetches.length === 10, "shared recovery selector did not enforce LIMIT 10");
});

// 3. Legacy/unmarked pending is terminal unknown, never recovered.
await group("3 legacy pending excluded", async () => {
  const { db, env } = fixture();
  insertLifecycle(db, { id: "legacy_pending", status: "pending", error: null, age: "-2 days" });
  await real.retryFailedLifecycleEmails(env);
  must(fetches.length === 0 && row(db, "legacy_pending").status === "pending", "legacy pending was replayed");
});

// 4. Sending remains terminal unknown on both sides of provider-key expiry.
await group("4 sending never replays", async () => {
  const { db, env } = fixture();
  insertLifecycle(db, { id: "sending_23", domain: "s23.example", status: "sending", error: "timeout", age: "-23 hours" });
  insertLifecycle(db, { id: "sending_25", domain: "s25.example", status: "sending", error: "network_error", age: "-25 hours" });
  insertLifecycle(db, { id: "legacy_timeout", domain: "legacy-timeout.example", status: "failed", error: "timeout", age: "-2 days" });
  insertLifecycle(db, { id: "legacy_network", domain: "legacy-network.example", status: "failed", error: "network_error", age: "-2 days" });
  await real.retryFailedLifecycleEmails(env);
  must(fetches.length === 0, "sending outcome replayed around 24h boundary");
  must(row(db, "legacy_timeout").status === "failed" && row(db, "legacy_network").status === "failed", "legacy unknown failure was reclaimed");
});

// 5. Concurrent cron recoveries and cron/live overlap have one CAS winner.
await group("5 concurrent single winner", async () => {
  const first = fixture();
  insertLifecycle(first.db, { id: "race", status: "pending", error: "provider_not_started" });
  let releaseFetch;
  let signalFetch;
  const entered = new Promise((resolve) => { signalFetch = resolve; });
  const held = new Promise((resolve) => { releaseFetch = resolve; });
  fetchHandler = async () => { signalFetch(); await held; return success(); };
  const one = real.retryFailedLifecycleEmails(first.env);
  await entered;
  const two = real.retryFailedLifecycleEmails(first.env);
  await two;
  releaseFetch();
  await one;
  must(fetches.length === 1 && row(first.db, "race").status === "sent", "two cron ticks presented twice");

  const second = fixture();
  insertLifecycle(second.db, { id: "cron_live", status: "pending", error: "provider_not_started" });
  await Promise.all([
    real.retryFailedLifecycleEmails(second.env),
    real.sendLifecycleEmail(second.env, { type: "lifecycle_domain_added", user_id: "usr_ok", workspace_id: "ws_active", domain: "acme.example" }),
  ]);
  must(fetches.length === 1 && row(second.db, "cron_live").status === "sent", "cron/live overlap presented twice");
});

// 6. Deterministic preflight refusal precedes attempt CAS and fetch.
await group("6 preflight before admission", async () => {
  const { db, d1, env } = fixture();
  env.HELLO_EMAIL_FROM = "not-an-email";
  const result = await real.sendLifecycleEmail(env, { type: "lifecycle_welcome", user_id: "usr_ok" });
  const stored = db.prepare("SELECT * FROM lifecycle_email_events WHERE type='lifecycle_welcome'").get();
  must(result.reason === "invalid_sender" && fetches.length === 0, "invalid sender reached provider");
  must(stored.status === "failed" && stored.error === "invalid_sender", "safe preflight class not recorded");
  must(!d1.trace.some((entry) => /SET status = 'sending'/.test(entry.sql)), "attempt CAS ran before preflight refusal");
});

// 7. Zero-change attempt CAS stops before fetch.
await group("7 admission CAS refusal", async () => {
  const hooks = { beforeRun: ({ sql }) => /SET status = 'sending'/.test(sql) ? { meta: { changes: 0 } } : null };
  const { db, env } = fixture({ hooks });
  const result = await real.sendLifecycleEmail(env, { type: "lifecycle_welcome", user_id: "usr_ok" });
  const stored = db.prepare("SELECT * FROM lifecycle_email_events WHERE type='lifecycle_welcome'").get();
  must(result.skipped === "duplicate" && fetches.length === 0 && stored.status === "pending", "refused CAS still presented");
});

// 8. Guarded credential is re-read after CAS; a freeze emits no fetch.
await group("8 post-CAS credential freeze", async () => {
  const { db, env: base } = fixture();
  let keyReads = 0;
  const env = new Proxy(base, { get(target, property) {
    if (property === "RESEND_API_KEY") { keyReads += 1; return undefined; }
    return target[property];
  } });
  const result = await real.sendLifecycleEmail(env, { type: "lifecycle_welcome", user_id: "usr_ok" });
  const stored = db.prepare("SELECT * FROM lifecycle_email_events WHERE type='lifecycle_welcome'").get();
  must(fetches.length === 0 && keyReads === 1, "credential was captured early or fetch survived freeze");
  must(result.sent === false && stored.status === "failed" && stored.error === "missing_api_key", "known no-provider result not recorded safely");
});

// 9. Network/timeout/5xx and accepted-response final-CAS refusal stay unknown.
await group("9 unknown outcomes remain sending", async () => {
  const cases = [
    ["network", async () => { throw new Error("network down"); }, "network_error"],
    ["timeout", async () => { const error = new Error("timeout"); error.name = "TimeoutError"; throw error; }, "timeout"],
    ["server", async () => Response.json({ name: "internal_error" }, { status: 503 }), "provider_server_error"],
  ];
  for (const [label, handler, reason] of cases) {
    const { db, env } = fixture();
    fetchHandler = handler;
    const result = await real.sendLifecycleEmail(env, { type: "lifecycle_domain_added", user_id: "usr_ok", domain: `${label}.example` });
    const stored = db.prepare("SELECT * FROM lifecycle_email_events WHERE domain=?").get(`${label}.example`);
    must(result.sent === false && stored.status === "sending" && stored.error === reason, `${label} became definitive`);
    const count = fetches.length;
    await real.retryFailedLifecycleEmails(env);
    must(fetches.length === count, `${label} was auto-retried`);
  }

  const hooks = { beforeRun: ({ sql }) => /SET status = 'sent'/.test(sql) ? { meta: { changes: 0 } } : null };
  const { db, env } = fixture({ hooks });
  const result = await real.sendLifecycleEmail(env, { type: "lifecycle_welcome", user_id: "usr_ok" });
  const stored = db.prepare("SELECT * FROM lifecycle_email_events WHERE type='lifecycle_welcome'").get();
  must(result.sent !== true && stored.status === "sending", "accepted response bypassed refused terminal CAS");
});

// 10. Every 409 class stays sending with a bounded safe enum and no replay.
await group("10 idempotency conflicts terminal unknown", async () => {
  const cases = [
    ["invalid_idempotent_request", "idempotency_conflict_invalid"],
    ["concurrent_idempotent_requests", "idempotency_conflict_concurrent"],
    ["unexpected_conflict", "idempotency_conflict_unknown"],
  ];
  for (const [providerCode, expected] of cases) {
    const { db, env } = fixture();
    fetchHandler = async () => Response.json({ name: providerCode, message: "do not persist" }, { status: 409 });
    await real.sendLifecycleEmail(env, { type: "lifecycle_domain_added", user_id: "usr_ok", domain: `${providerCode}.example` });
    const stored = db.prepare("SELECT * FROM lifecycle_email_events WHERE domain=?").get(`${providerCode}.example`);
    const key = header(fetches[0], "Idempotency-Key");
    must(stored.status === "sending" && stored.error === expected, `${providerCode} was not safely classified`);
    const count = fetches.length;
    await real.retryFailedLifecycleEmails(env);
    must(fetches.length === count && header(fetches[0], "Idempotency-Key") === key, `${providerCode} replayed or key churned`);
  }
});

// 11. Header identity is exact, deterministic and payload-independent.
await group("11 deterministic provider identity", async () => {
  const captures = [];
  for (const recipient of ["first@example.co.uk", "changed@example.co.uk"]) {
    const { db, env } = fixture();
    db.prepare("UPDATE users SET email=? WHERE id='usr_ok'").run(recipient);
    await real.sendLifecycleEmail(env, { type: "lifecycle_domain_added", workspace_id: "ws_active", domain: "stable.example" });
    captures.push({ key: header(fetches[0], "Idempotency-Key"), body: fetches[0].options.body });
  }
  const logical = real.lifecycleDedupeKey({ type: "lifecycle_domain_added", workspace_id: "ws_active", domain: "stable.example" });
  const expected = `cybermeters:lifecycle:v1:${createHash("sha256").update(logical).digest("hex")}`;
  must(captures[0].key === expected && captures[1].key === expected && expected.length === 89, "provider key is not exact/stable");
  must(captures[0].body !== captures[1].body, "fixture did not prove payload independence");
});

// 12. Changed payload under one key fails closed through 409, without key churn.
await group("12 changed payload same key", async () => {
  const { db, env } = fixture();
  const presented = new Map();
  fetchHandler = async (record) => {
    const key = header(record, "Idempotency-Key");
    const prior = presented.get(key);
    if (prior && prior !== record.options.body) {
      return Response.json({ name: "invalid_idempotent_request" }, { status: 409 });
    }
    presented.set(key, record.options.body);
    return Response.json({ name: "validation_error" }, { status: 400 });
  };
  await real.sendLifecycleEmail(env, { type: "lifecycle_domain_added", workspace_id: "ws_active", domain: "drift.example" });
  const first = db.prepare("SELECT * FROM lifecycle_email_events WHERE domain='drift.example'").get();
  must(first.status === "failed" && first.error === "provider_rejected", "definitive first rejection missing");
  db.prepare("UPDATE lifecycle_email_events SET created_at=datetime('now','-25 hours') WHERE id=?").run(first.id);
  db.prepare("UPDATE users SET email='changed@example.co.uk' WHERE id='usr_ok'").run();
  await real.retryFailedLifecycleEmails(env);
  const second = row(db, first.id);
  must(fetches.length === 2 && header(fetches[0], "Idempotency-Key") === header(fetches[1], "Idempotency-Key"), "changed body churned provider key");
  must(fetches[0].options.body !== fetches[1].options.body, "payload did not change in drift fixture");
  must(second.status === "sending" && second.error === "idempotency_conflict_invalid", "payload drift did not fail closed");
});

// 13. Soft delete is enforced at lookup and again atomically at admission.
await group("13 soft-delete containment", async () => {
  const before = fixture();
  const skipped = await real.sendLifecycleEmail(before.env, { type: "lifecycle_domain_added", workspace_id: "ws_deleted", domain: "deleted.example" });
  must(skipped.skipped === "no_verified_email" && fetches.length === 0, "pre-deleted workspace presented");

  let deleted = false;
  const hooks = { beforeRun: ({ db, sql }) => {
    if (!deleted && /SET status = 'sending'/.test(sql)) {
      deleted = true;
      db.prepare("UPDATE workspaces SET deleted_at=datetime('now') WHERE id='ws_active'").run();
    }
    return null;
  } };
  const raced = fixture({ hooks });
  await real.sendLifecycleEmail(raced.env, { type: "lifecycle_domain_added", workspace_id: "ws_active", domain: "race-delete.example" });
  must(fetches.length === 0, "delete race crossed provider admission");
});

// 14. Recovery of one tenant never mutates another tenant's row.
await group("14 tenant row binding", async () => {
  const { db, env } = fixture();
  insertLifecycle(db, { id: "owned", workspaceId: "ws_active", domain: "owned.example", status: "pending", error: "provider_not_started" });
  insertLifecycle(db, { id: "other", workspaceId: "ws_other", domain: "other.example", status: "sent", error: null });
  const before = JSON.stringify(row(db, "other"));
  await real.retryFailedLifecycleEmails(env);
  must(row(db, "owned").status === "sent", "owned recovery did not finish");
  must(JSON.stringify(row(db, "other")) === before, "another tenant row changed");
});

// 15. Existing templates/dedupe/safe retry/payment exclusion remain intact.
await group("15 compatibility behavior", async () => {
  const { db, env } = fixture({ apiKey: null });
  for (const type of real.LIFECYCLE_TYPES) {
    const email = real.buildLifecycleEmail(type, { origin: env.FRONTEND_URL, wsName: "Acme", domain: "acme.example" });
    must(email.subject && email.text && email.html, `template missing for ${type}`);
  }
  must(real.LIFECYCLE_TYPES.size === 6, "lifecycle type set drifted");
  const failed = await real.sendLifecycleEmail(env, { type: "lifecycle_welcome", user_id: "usr_ok" });
  const welcome = db.prepare("SELECT * FROM lifecycle_email_events WHERE type='lifecycle_welcome'").get();
  must(failed.reason === "missing_api_key" && welcome.status === "failed", "safe failure compatibility broke");
  env.RESEND_API_KEY = "re_test";
  await real.retryFailedLifecycleEmails(env);
  must(row(db, welcome.id).status === "sent", "safe pre-provider failure did not recover");
  const duplicate = await real.sendLifecycleEmail(env, { type: "lifecycle_welcome", user_id: "usr_ok" });
  must(duplicate.skipped === "duplicate", "sent row was not deduped");
  insertLifecycle(db, { id: "payment", type: "lifecycle_payment_failed", workspaceId: null, domain: null, status: "failed", error: "missing_api_key" });
  await real.retryFailedLifecycleEmails(env);
  must(row(db, "payment").status === "failed", "payment failure entered generic recovery");
});

// 16. Maximum logical key is hashed to 89 bytes; non-lifecycle trunks get none.
await group("16 max key and header scope", async () => {
  const { db, env } = fixture();
  const longWorkspace = `ws_${"w".repeat(220)}`;
  const longDomain = `${"d".repeat(63)}.${"d".repeat(63)}.${"d".repeat(63)}.${"d".repeat(57)}`;
  db.prepare("INSERT INTO workspaces (id,owner_user_id,name) VALUES (?,?,?)").run(longWorkspace, "usr_ok", "Long");
  await real.sendLifecycleEmail(env, { type: "lifecycle_domain_added", workspace_id: longWorkspace, domain: longDomain });
  const lifecycleHeader = header(fetches[0], "Idempotency-Key");
  must(lifecycleHeader?.length === 89 && /^cybermeters:lifecycle:v1:[a-f0-9]{64}$/.test(lifecycleHeader), "max logical key was not safely hashed");
  const lifecycleCount = fetches.length;
  await real.deliverEmail("Generic", "text", "<p>text</p>", env, "HELLO_EMAIL_FROM", ["owner@example.co.uk"]);
  await real.deliverEmail("Alert", "text", "<p>text</p>", env, "ALERT_EMAIL_FROM", ["owner@example.co.uk"]);
  await real.deliverEmail("Digest", "text", "<p>text</p>", env, "HELLO_EMAIL_FROM", ["owner@example.co.uk"]);
  must(fetches.slice(lifecycleCount).every((record) => header(record, "Idempotency-Key") === null), "generic/alert/digest trunk gained lifecycle header");
  fetchHandler = async () => Response.json({ name: "concurrent_idempotent_requests" }, { status: 409 });
  const generic409 = await real.deliverEmail("Generic conflict", "text", "<p>text</p>", env, "HELLO_EMAIL_FROM", ["owner@example.co.uk"]);
  must(generic409.reason === "provider_rejected", "generic provider outcome semantics drifted into lifecycle contract");
});

// 17. Provider body is serialized once before CAS and the exact bytes are sent.
await group("17 single serialization byte stability", async () => {
  let serialized = 0;
  let serializedBytes = null;
  const originalStringify = JSON.stringify;
  JSON.stringify = (value, ...rest) => {
    const bytes = originalStringify(value, ...rest);
    if (value?.from && Array.isArray(value?.to) && value?.subject && value?.text && value?.html) {
      serialized += 1;
      serializedBytes = bytes;
    }
    return bytes;
  };
  try {
    const hooks = { afterRun: ({ db, sql }) => {
      if (/SET status = 'sending'/.test(sql)) db.prepare("UPDATE workspaces SET name='Post-CAS mutation' WHERE id='ws_active'").run();
    } };
    const { env } = fixture({ hooks });
    await real.sendLifecycleEmail(env, { type: "lifecycle_workspace_created", workspace_id: "ws_active" });
    must(serialized === 1, `provider body serialized ${serialized} times`);
    must(fetches[0].options.body === serializedBytes, "fetch body differs from prepared bytes");
    must(JSON.parse(serializedBytes).text.includes("Acme"), "post-CAS mutation changed prepared body");
  } finally {
    JSON.stringify = originalStringify;
  }
});

// 18. A-1: young rejection waits; >24h and <3d reclaims via marked pending.
await group("18 definitive rejection 24h boundary", async () => {
  const transitions = [];
  const hooks = { afterRun: ({ db, sql }) => {
    if (/SET status = 'pending'/.test(sql)) {
      const candidate = db.prepare("SELECT status,error FROM lifecycle_email_events WHERE id='old_reject'").get();
      if (candidate) transitions.push(candidate);
    }
  } };
  const { db, env } = fixture({ hooks });
  insertLifecycle(db, { id: "young_reject", domain: "young.example", status: "failed", error: "provider_rejected", age: "-23 hours" });
  insertLifecycle(db, { id: "old_reject", domain: "old.example", status: "failed", error: "provider_rejected", age: "-25 hours" });
  await real.retryFailedLifecycleEmails(env);
  must(row(db, "young_reject").status === "failed", "young definitive rejection was re-presented");
  must(row(db, "old_reject").status === "sent" && fetches.length === 1, "eligible definitive rejection did not present once");
  must(transitions.some((entry) => entry.status === "pending" && entry.error === "provider_not_started"), "eligible rejection bypassed marked pending");
});

const mutations = [
  { id: "legacy_pending_marker_removed", from: "AND le.error = 'provider_not_started'", to: "AND 1 = 1 /* mutant: legacy pending admitted */", reason: "legacy pending marker requirement removed" },
  { id: "staleness_floor_removed", from: "AND (? = 1 OR created_at < datetime('now', '-15 minutes'))", to: "AND (? = 1 OR created_at < datetime('now', '+15 minutes'))", reason: "15-minute attempt staleness floor removed" },
  { id: "attempt_cas_result_ignored", from: "if ((attempt.meta?.changes ?? 0) === 0) return { skipped: \"duplicate\" };", to: "if (false) return { skipped: \"duplicate\" };", reason: "expected-state attempt CAS refusal ignored" },
  {
    id: "fetch_before_attempt_cas",
    from: "const attempt = await claimLifecycleProviderAttempt(env, {\n      rowId,\n      dedupeKey,\n      workspaceId: workspace_id,\n      allowImmediate,\n    });",
    to: "const prematureProviderCall = await deliverPreparedEmail(prepared, env, { idempotencyKey });\n    void prematureProviderCall;\n    const attempt = await claimLifecycleProviderAttempt(env, {\n      rowId,\n      dedupeKey,\n      workspaceId: workspace_id,\n      allowImmediate,\n    });",
    reason: "provider call moved before attempt CAS",
  },
  { id: "sending_added_to_selector", from: "OR (le.status = 'failed' AND (", to: "OR (le.status = 'sending') OR (le.status = 'failed' AND (", reason: "sending added to retry selector" },
  { id: "provider_key_raw", from: "return `cybermeters:lifecycle:v1:${hex}`;", to: "return String(dedupeKey);", reason: "provider key removed or allowed raw overlength identity" },
  {
    id: "network_became_failed",
    from: "return lifecycleOutcomeContract\n      ? { sent: false, reason, outcomeUnknown: true }\n      : { sent: false, reason };",
    to: "return lifecycleOutcomeContract\n      ? { sent: false, reason, definitive: true }\n      : { sent: false, reason };",
    reason: "timeout/network uncertainty collapsed to retryable failed",
  },
  { id: "conflict_became_failed", from: "return { sent: false, reason, status: response.status, outcomeUnknown: true };", to: "return { sent: false, reason, status: response.status, definitive: true };", reason: "HTTP 409 collapsed to retryable failed" },
  {
    id: "terminal_sent_cas_weakened",
    from: "WHERE id = ? AND dedupe_key = ? AND status = 'sending'\n                  AND ((? IS NULL AND workspace_id IS NULL) OR workspace_id = ?)`)\n      .bind(result.provider_id || null, rowId, dedupeKey, workspaceId, workspaceId)",
    to: "WHERE id = ? AND dedupe_key = ? AND status != 'sent'\n                  AND ((? IS NULL AND workspace_id IS NULL) OR workspace_id = ?)`)\n      .bind(result.provider_id || null, rowId, dedupeKey, workspaceId, workspaceId)",
    reason: "terminal sent CAS no longer requires sending",
  },
  { id: "soft_delete_admission_removed", from: "SELECT 1 FROM workspaces WHERE id = ? AND deleted_at IS NULL", to: "SELECT 1 FROM workspaces WHERE id = ?", reason: "soft-delete condition removed from attempt admission" },
  {
    id: "sending_replay_after_expiry",
    from: "if (existing.status === \"failed\") {",
    to: "if (existing.status === \"sending\") {\n        const unsafe = await env.cybermeters_db.prepare(\"UPDATE lifecycle_email_events SET status='pending', error='provider_not_started' WHERE id=? AND dedupe_key=? AND status='sending'\").bind(rowId, dedupeKey).run();\n        if ((unsafe.meta?.changes ?? 0) === 0) return { skipped: \"duplicate\" };\n        allowImmediate = true;\n      } else if (existing.status === \"failed\") {",
    reason: "outcome-unknown sending replay enabled after 24h",
  },
  { id: "young_rejection_replayed", from: "OR (error = 'provider_rejected' AND created_at < datetime('now', '-24 hours'))", to: "OR (error = 'provider_rejected' AND created_at < datetime('now', '+24 hours'))", reason: "definitive provider rejection re-presented inside 24h" },
];
registerMutants(mutations);

function mutationSurface() {
  return {
    source: wholeSourceFingerprint(root),
    sourceInventory: fs.readdirSync(sourceDir).sort().join("\n"),
    git: execFileSync("git", ["status", "--porcelain", "--", "workers", "frontend", "scripts"], { cwd: root, encoding: "utf8" }),
  };
}

async function mutantContract(mod, id) {
  if (id === "legacy_pending_marker_removed" || id === "sending_added_to_selector") {
    let selector = "";
    const env = { cybermeters_db: { prepare(sql) { selector = sql; return { all: async () => ({ results: [] }) }; } } };
    await mod.retryFailedLifecycleEmails(env);
    if (id === "legacy_pending_marker_removed") return /le\.error = 'provider_not_started'/.test(selector);
    return !/le\.status = 'sending'/.test(selector);
  }
  if (id === "staleness_floor_removed") {
    const { db, env } = fixture();
    insertLifecycle(db, { id: "fresh_mutant", status: "pending", error: "provider_not_started", age: "-1 minute" });
    await mod.sendLifecycleEmail(env, { type: "lifecycle_domain_added", user_id: "usr_ok", workspace_id: "ws_active", domain: "acme.example", _recovery_id: "fresh_mutant" });
    return fetches.length === 0;
  }
  if (id === "attempt_cas_result_ignored" || id === "fetch_before_attempt_cas") {
    const hooks = { beforeRun: ({ sql }) => /SET status = 'sending'/.test(sql) ? { meta: { changes: 0 } } : null };
    const { env } = fixture({ hooks });
    await mod.sendLifecycleEmail(env, { type: "lifecycle_welcome", user_id: "usr_ok" });
    return fetches.length === 0;
  }
  if (id === "provider_key_raw") {
    const { db, env } = fixture();
    const longWorkspace = `ws_${"x".repeat(220)}`;
    db.prepare("INSERT INTO workspaces (id,owner_user_id,name) VALUES (?,?,?)").run(longWorkspace, "usr_ok", "Long");
    await mod.sendLifecycleEmail(env, { type: "lifecycle_domain_added", workspace_id: longWorkspace, domain: `${"d".repeat(250)}.example` });
    const key = header(fetches[0], "Idempotency-Key");
    return key?.length === 89 && /^cybermeters:lifecycle:v1:[a-f0-9]{64}$/.test(key);
  }
  if (id === "network_became_failed") {
    const { db, env } = fixture();
    fetchHandler = async () => { throw new Error("network"); };
    await mod.sendLifecycleEmail(env, { type: "lifecycle_welcome", user_id: "usr_ok" });
    const stored = db.prepare("SELECT * FROM lifecycle_email_events LIMIT 1").get();
    return stored.status === "sending" && stored.error === "network_error";
  }
  if (id === "conflict_became_failed") {
    const { db, env } = fixture();
    fetchHandler = async () => Response.json({ name: "invalid_idempotent_request" }, { status: 409 });
    await mod.sendLifecycleEmail(env, { type: "lifecycle_welcome", user_id: "usr_ok" });
    const stored = db.prepare("SELECT * FROM lifecycle_email_events LIMIT 1").get();
    return stored.status === "sending" && stored.error === "idempotency_conflict_invalid";
  }
  if (id === "terminal_sent_cas_weakened") {
    let changed = false;
    const hooks = { beforeRun: ({ db, sql }) => {
      if (!changed && /SET status = 'sent'/.test(sql)) {
        changed = true;
        db.prepare("UPDATE lifecycle_email_events SET status='failed' WHERE status='sending'").run();
      }
      return null;
    } };
    const { db, env } = fixture({ hooks });
    const result = await mod.sendLifecycleEmail(env, { type: "lifecycle_welcome", user_id: "usr_ok" });
    const stored = db.prepare("SELECT * FROM lifecycle_email_events LIMIT 1").get();
    return result.sent !== true && stored.status === "failed";
  }
  if (id === "soft_delete_admission_removed") {
    let deleted = false;
    const hooks = { beforeRun: ({ db, sql }) => {
      if (!deleted && /SET status = 'sending'/.test(sql)) {
        deleted = true;
        db.prepare("UPDATE workspaces SET deleted_at=datetime('now') WHERE id='ws_active'").run();
      }
      return null;
    } };
    const { env } = fixture({ hooks });
    await mod.sendLifecycleEmail(env, { type: "lifecycle_domain_added", workspace_id: "ws_active", domain: "delete-mutant.example" });
    return fetches.length === 0;
  }
  if (id === "sending_replay_after_expiry") {
    const { db, env } = fixture();
    insertLifecycle(db, { id: "sending_old", status: "sending", error: "timeout", age: "-25 hours" });
    await mod.sendLifecycleEmail(env, { type: "lifecycle_domain_added", user_id: "usr_ok", workspace_id: "ws_active", domain: "acme.example", _recovery_id: "sending_old" });
    return fetches.length === 0;
  }
  if (id === "young_rejection_replayed") {
    const { db, env } = fixture();
    insertLifecycle(db, { id: "young", status: "failed", error: "provider_rejected", age: "-23 hours" });
    await mod.sendLifecycleEmail(env, { type: "lifecycle_domain_added", user_id: "usr_ok", workspace_id: "ws_active", domain: "acme.example", _recovery_id: "young" });
    return fetches.length === 0 && row(db, "young").status === "failed";
  }
  throw new Error(`no mutant contract for ${id}`);
}

let mutantsKilled = 0;
let mutantsSurvived = 0;
const surfaceBefore = mutationSurface();
for (const mutation of mutations) {
  try {
    const mutant = await importMutant(lifecyclePath, mutation.id);
    must(mutant !== real, `mutant ${mutation.id} reused real module identity`);
    const contractHeld = await mutantContract(mutant, mutation.id);
    if (contractHeld) {
      mutantsSurvived += 1;
      console.log(`FAIL mutant survived: ${mutation.reason}`);
    } else {
      mutantsKilled += 1;
    }
  } catch (error) {
    mutantsSurvived += 1;
    console.log(`FAIL mutant ${mutation.id} did not execute exactly — ${error?.message || error}`);
  }
}
const surfaceAfter = mutationSurface();
const surfaceStable = JSON.stringify(surfaceAfter) === JSON.stringify(surfaceBefore);
if (!surfaceStable) console.log("FAIL loader mutations changed source identity or residue surface");

globalThis.fetch = originalFetch;
AbortSignal.timeout = originalTimeout;

console.log(`\nEmail lifecycle behavioral groups: ${groupsPassed}/${groupsPassed + groupsFailed} passed`);
console.log(`Email lifecycle loader mutants: ${mutantsKilled}/${mutations.length} killed`);
console.log(`Email lifecycle source/residue identity: ${surfaceStable ? "PASS" : "FAIL"}`);
if (groupsFailed || mutantsSurvived || !surfaceStable || groupsPassed !== 18 || mutations.length !== 12) {
  console.error("email-lifecycle validation FAILED");
  process.exit(1);
}
console.log("email-lifecycle validation passed");
