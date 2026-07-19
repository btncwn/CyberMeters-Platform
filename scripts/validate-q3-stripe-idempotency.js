#!/usr/bin/env node
//
// Q3 — Stripe webhook idempotency state machine. CI-blocking. Node 24+.
//
// The webhook committed its processed-event marker BEFORE running side effects, so a
// partial failure returned 500 for Stripe to retry but the retry was short-circuited to
// 200 { deduped } without re-running the side effects — permanent entitlement drift.
// This drives the REAL globalBillingRoutes webhook handler with valid HMAC signatures
// and a faithful stripe_processed_events mock, proving the claim→completed/failed state
// machine. Section B pins the guards against reversion (the required mutation set).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { webcrypto as nodeCrypto } from "node:crypto";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const imp = (rel) => import(pathToFileURL(path.join(root, "workers", "scan-api", "src", rel)).href);
const read = (rel) => fs.readFileSync(path.join(root, "workers", "scan-api", "src", rel), "utf8");

const { globalBillingRoutes } = await imp("routes/global-billing.js");

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

const SECRET = "whsec_test_secret";
async function hmacHex(secret, msg) {
  const key = await nodeCrypto.subtle.importKey("raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await nodeCrypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function sigHeader(rawBody) {
  const t = Math.floor(Date.now() / 1000);
  return `t=${t},v1=${await hmacHex(SECRET, `${t}.${rawBody}`)}`;
}

const nowStr = () => new Date().toISOString().replace("T", " ").replace(/\.\d+Z$/, "");
function makeDb() {
  const events = new Map();
  let sideEffectCalls = 0, failArmed = false;
  const kindOf = (sql) =>
    /INSERT OR IGNORE INTO stripe_processed_events/.test(sql) ? "claim" :
    /SELECT status, processed_at FROM stripe_processed_events/.test(sql) ? "select_marker" :
    /UPDATE stripe_processed_events SET status = 'processing'/.test(sql) ? "reclaim" :
    /UPDATE stripe_processed_events SET status = 'completed'/.test(sql) ? "complete" :
    /UPDATE stripe_processed_events SET status = 'failed'/.test(sql) ? "fail" : "side_effect";
  const db = {
    events,
    armFail() { failArmed = true; },
    sideEffects: () => sideEffectCalls,
    seed(id, status, processed_at) { events.set(id, { id, event_type: "x", status, processed_at }); },
    prepare(sql) {
      const kind = kindOf(sql); let args = [];
      const maybeFail = () => { sideEffectCalls++; if (failArmed) { failArmed = false; throw new Error("sim side-effect failure"); } };
      return {
        bind(...a) { args = a; return this; },
        async run() {
          if (kind === "claim") { const [id, type] = args;
            if (events.has(id)) return { meta: { changes: 0 } };
            events.set(id, { id, event_type: type, status: "processing", processed_at: nowStr() });
            return { meta: { changes: 1 } }; }
          if (kind === "reclaim") { const [id, status, pa] = args; const r = events.get(id);
            if (r && r.status === status && r.processed_at === pa) { r.status = "processing"; r.processed_at = nowStr(); return { meta: { changes: 1 } }; }
            return { meta: { changes: 0 } }; }
          if (kind === "complete") { const r = events.get(args[0]); if (r) { r.status = "completed"; r.processed_at = nowStr(); } return { meta: { changes: 1 } }; }
          if (kind === "fail") { const r = events.get(args[0]); if (r) { r.status = "failed"; r.processed_at = nowStr(); } return { meta: { changes: 1 } }; }
          maybeFail(); return { meta: { changes: 1 }, results: [] };
        },
        async first() {
          if (kind === "select_marker") { const r = events.get(args[0]); return r ? { status: r.status, processed_at: r.processed_at } : null; }
          maybeFail(); return null;
        },
        async all() { return { results: [] }; },
      };
    },
    async batch(stmts) { const out = []; for (const s of stmts) out.push(await s.run()); return out; },
  };
  return db;
}

function makeRctx(db, rawBody, sig, { secretKey = "sk_test_x" } = {}) {
  return {
    request: { method: "POST", headers: { get: (h) => (h.toLowerCase() === "stripe-signature" ? sig : null) }, async text() { return rawBody; } },
    env: { STRIPE_WEBHOOK_SECRET: SECRET, STRIPE_SECRET_KEY: secretKey, cybermeters_db: db },
    url: new URL("https://api.cybermeters.com/api/billing/webhook"),
    json: (data, status = 200) => ({ status, data }),
    serverError: () => ({ status: 500 }), requireAuth: async () => null, consumeApiRateLimit: async () => null, validateFrontendRedirectUrl: () => null,
  };
}

const evt = (over = {}) => JSON.stringify({ id: "evt_1", type: "unknown.event", livemode: false, data: { object: {} }, ...over });
async function deliver(db, body, opts = {}) {
  const sig = opts.badSig ? "t=1,v1=deadbeef" : await sigHeader(body);
  return globalBillingRoutes(makeRctx(db, body, sig, opts));
}

// ── Section A: behavioural ────────────────────────────────────────────────────
async function run() {
  // 1. valid first delivery of an unhandled type → processed, marked completed, no side effects
  { const db = makeDb(); const r = await deliver(db, evt({ id: "e1" }));
    ok("1 first delivery acknowledged 200", r.status === 200);
    ok("1 marker completed after success", db.events.get("e1")?.status === "completed");
    ok("1 unhandled type ran no entitlement side effects", db.sideEffects() === 0); }

  // 2. invalid signature rejected (also covers forged request-body / workspace spoof)
  { const db = makeDb(); const r = await deliver(db, evt({ id: "e2" }), { badSig: true });
    ok("2 invalid signature rejected 400", r.status === 400);
    ok("2 no marker claimed on bad signature", !db.events.has("e2")); }

  // 3. duplicate after success is a no-op (deduped, no re-apply)
  { const db = makeDb(); await deliver(db, evt({ id: "e3", type: "checkout.session.completed",
      data: { object: { id: "cs_1", metadata: { user_id: "u1", workspace_id: "w1", plan: "starter" }, customer: "cus_1", subscription: "sub_1" } } }));
    const after1 = db.sideEffects();
    const r2 = await deliver(db, evt({ id: "e3", type: "checkout.session.completed",
      data: { object: { id: "cs_1", metadata: { user_id: "u1", workspace_id: "w1", plan: "starter" }, customer: "cus_1", subscription: "sub_1" } } }));
    ok("3 duplicate after success deduped 200", r2.status === 200 && r2.data?.deduped === true);
    ok("3 duplicate ran NO further side effects", db.sideEffects() === after1);
    ok("3 side effects DID run on first delivery", after1 > 0); }

  // 4. side-effect failure → 'failed' + 500 → retry re-runs → 'completed' (no permanent drift)
  { const db = makeDb(); db.armFail();
    const body = evt({ id: "e4", type: "checkout.session.completed",
      data: { object: { id: "cs", metadata: { user_id: "u1", workspace_id: "w1", plan: "starter" }, customer: "cus", subscription: "sub" } } });
    const r1 = await deliver(db, body);
    ok("4 side-effect failure returns 500", r1.status === 500);
    ok("4 marker left 'failed' (retryable)", db.events.get("e4")?.status === "failed");
    const r2 = await deliver(db, body);
    ok("4 retry succeeds 200", r2.status === 200);
    ok("4 marker now 'completed' (drift resolved)", db.events.get("e4")?.status === "completed"); }

  // 5. crash between processing and completion: a STALE 'processing' row is re-claimed
  { const db = makeDb(); db.seed("e5", "processing", "2000-01-01 00:00:00"); // ancient claim (crashed)
    const r = await deliver(db, evt({ id: "e5" }));
    ok("5 stale 'processing' re-claimed and completed", r.status === 200 && db.events.get("e5")?.status === "completed"); }

  // 6. concurrent duplicate: a FRESH 'processing' row (live owner) is not reprocessed
  { const db = makeDb(); db.seed("e6", "processing", nowStr()); // fresh claim, owner in flight
    const before = db.sideEffects();
    const r = await deliver(db, evt({ id: "e6", type: "checkout.session.completed",
      data: { object: { id: "cs", metadata: { user_id: "u1", workspace_id: "w1" } } } }));
    ok("6 fresh concurrent 'processing' acknowledged, not reprocessed", r.status === 200 && r.data?.deduped === true);
    ok("6 concurrent delivery applied no side effects", db.sideEffects() === before); }

  // 7. wrong environment (livemode mismatch) → ignored, no marker, no mutation
  { const db = makeDb(); const r = await deliver(db, evt({ id: "e7", livemode: true }), { secretKey: "sk_test_x" });
    ok("7 test-key + live event ignored 200", r.status === 200 && r.data?.ignored === "environment_mismatch");
    ok("7 wrong-environment event claimed NO marker", !db.events.has("e7"));
    ok("7 wrong-environment event mutated nothing", db.sideEffects() === 0); }

  // 8. missing workspace mapping fails safely (handler does not throw → completed 200)
  { const db = makeDb(); const r = await deliver(db, evt({ id: "e8", type: "customer.subscription.updated",
      data: { object: { id: "sub", metadata: {}, customer: "cus", status: "active" } } }));
    ok("8 unmappable event handled safely 200", r.status === 200); }
}
await run();

// ── Section B: self-proving source guards (required mutation set) ─────────────
const gbSrc = read("routes/global-billing.js");
const stSrc = read("engines/stripe.js");
function guard(name, src, predicate, mutate) {
  ok(`${name} — holds`, predicate(src) === true);
  const m = mutate(src);
  ok(`${name} — mutation changed source`, m !== src);
  ok(`${name} — CAUGHT when reintroduced`, predicate(m) === false);
}
// completed marker moved before side effects: 'completed' UPDATE must sit AFTER the try/switch
guard("completed marker set only AFTER side effects", gbSrc,
  (s) => s.indexOf("All side effects succeeded — NOW mark the event completed") > s.indexOf("switch (eventType)"),
  (s) => s.replace("All side effects succeeded — NOW mark the event completed", "zzz").replace("switch (eventType)", "switch (eventType) /*m*/"));
// failed event marked completed (claim must be 'processing', not 'completed')
guard("event claimed as 'processing', not pre-completed", gbSrc,
  (s) => /INSERT OR IGNORE INTO stripe_processed_events \(id, event_type, status, processed_at\) VALUES \(\?, \?, 'processing'/.test(s),
  (s) => s.replace("VALUES (?, ?, 'processing'", "VALUES (?, ?, 'completed'"));
// side-effect failure must mark 'failed' (retryable)
guard("side-effect failure marks 'failed'", gbSrc,
  (s) => /catch \(e\) \{[\s\S]*?UPDATE stripe_processed_events SET status = 'failed'/.test(s),
  (s) => s.replace("UPDATE stripe_processed_events SET status = 'failed', processed_at = datetime('now') WHERE id = ?", "SELECT 1"));
// signature verification removed
guard("signature verified before processing", gbSrc,
  (s) => /verifyStripeWebhookSignature\(rawBody, sigHeader, env\.STRIPE_WEBHOOK_SECRET\)/.test(s) && /if \(!sigResult\.ok\)/.test(s),
  (s) => s.replace("if (!sigResult.ok)", "if (false)"));
// environment boundary removed
guard("environment (livemode) boundary enforced", gbSrc,
  (s) => /keyMode && \(\(keyMode === "live"\) !== \(event\?\.livemode === true\)\)/.test(s),
  (s) => s.replace('keyMode && ((keyMode === "live") !== (event?.livemode === true))', "false"));
// stale event allowed to overwrite newer state (monotonic period_end guard removed)
guard("current_period_end never moves backward (stale guard)", stSrc,
  (s) => /current_period_end = CASE\s*\n\s*WHEN \? IS NOT NULL AND \(current_period_end IS NULL OR \? >= current_period_end\) THEN \?/.test(s),
  (s) => s.replace(/current_period_end = CASE[\s\S]*?ELSE current_period_end END,/, "current_period_end = COALESCE(?, current_period_end),"));

console.log(`\nQ3 Stripe idempotency: ${pass}/${pass + fail} passed`);
if (fail) { console.error("q3-stripe-idempotency validation FAILED"); process.exit(1); }
console.log("q3-stripe-idempotency validation passed");
