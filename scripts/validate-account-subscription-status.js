#!/usr/bin/env node
//
// Account subscription status honesty. GET /api/account/subscription and the
// published GET /api/billing/subscription must derive plan AND status from the
// canonical resolver: no row is `none` (never an invented "active"/"manual"/
// "monthly"), an unreadable state is `unavailable`, a trial is `trialing`, and
// every non-entitling row keeps its own meaning. getEffectivePlanState keeps
// its public shape (the governing row never leaks). CI-blocking; no network.
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = (...p) => pathToFileURL(path.join(root, "workers", "scan-api", "src", ...p)).href;
const {
  ACCOUNT_SUBSCRIPTION_STATUSES, describeAccountSubscription, getEffectivePlanState, planStateFromRows,
} = await import(src("engines", "entitlements.js"));
const { accountRoutes } = await import(src("routes", "account.js"));
const { globalBillingRoutes } = await import(src("routes", "global-billing.js"));

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) pass++;
  else { fail++; console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
};
const eq = (name, got, want) => ok(name, JSON.stringify(got) === JSON.stringify(want), `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);

const DAY = 86_400_000;
const iso = (offsetDays) => new Date(Date.now() + offsetDays * DAY).toISOString();
const row = (over = {}) => ({
  id: "sub_1", workspace_id: "ws_1", plan: "professional", status: null,
  subscription_status: "active", billing_interval: "month", trial_end: null,
  expires_at: null, current_period_end: iso(20), payment_failed_at: null,
  stripe_subscription_id: "sub_stripe_1", created_at: iso(-30), updated_at: iso(-1),
  ...over,
});

// ── 1. Status matrix (pure) ─────────────────────────────────────────────────
const cases = [
  ["no rows", [], "none", "free", false],
  ["active paid", [row()], "active", "professional", true],
  ["active trial", [row({ subscription_status: "trialing", trial_end: iso(5), current_period_end: null, stripe_subscription_id: null })], "trialing", "professional", true],
  ["trial ended", [row({ subscription_status: "trialing", trial_end: iso(-1), current_period_end: null, stripe_subscription_id: null })], "trial_expired", "free", false],
  ["past due in grace", [row({ subscription_status: "past_due", payment_failed_at: iso(-1) })], "past_due", "professional", true],
  ["past due beyond grace", [row({ subscription_status: "past_due", payment_failed_at: iso(-30), current_period_end: iso(-20) })], "past_due_lapsed", "free", false],
  ["cancelled", [row({ subscription_status: "canceled", current_period_end: iso(-2) })], "canceled", "free", false],
  ["cancelled (UK spelling)", [row({ subscription_status: "cancelled", current_period_end: iso(-2) })], "canceled", "free", false],
  ["paid period ended", [row({ current_period_end: iso(-3) })], "expired", "free", false],
  ["incomplete", [row({ subscription_status: "incomplete", current_period_end: null })], "inactive", "free", false],
  ["active beats concurrent trial", [row({ id: "t", subscription_status: "trialing", trial_end: iso(5), workspace_id: "ws_2", stripe_subscription_id: null }), row()], "active", "professional", true],
];
for (const [label, rows, status, plan, entitled] of cases) {
  const d = describeAccountSubscription(rows);
  eq(`${label}: status`, d.status, status);
  eq(`${label}: plan`, d.plan, plan);
  eq(`${label}: entitled`, d.entitled, entitled);
  ok(`${label}: status is canonical`, ACCOUNT_SUBSCRIPTION_STATUSES.includes(d.status));
  // Plan always agrees with the canonical resolver.
  eq(`${label}: plan agrees with planStateFromRows`, d.plan, planStateFromRows(rows).plan);
}
eq("read error → unavailable", describeAccountSubscription([], { error: true }).status, "unavailable");
eq("read error → plan unknown (null), never free", describeAccountSubscription([], { error: true }).plan, null);
{
  // Unmapped Stripe price stored fail-closed as plan "free" on an active row.
  const d = describeAccountSubscription([row({ plan: null })]);
  eq("active row with free plan → inactive, not entitled", [d.status, d.entitled, d.plan], ["inactive", false, "free"]);
}
{
  // Exact updated_at tie inside one lineage: latest row uses the resolver's
  // code-unit id ordering, so the cancelled successor wins over the old row.
  const t = iso(-2);
  const d = describeAccountSubscription([
    row({ id: "sub_B", subscription_status: "canceled", current_period_end: iso(10), updated_at: t, stripe_subscription_id: "same" }),
    row({ id: "sub_a", subscription_status: "active", current_period_end: iso(-1), updated_at: t, stripe_subscription_id: "same" }),
  ]);
  ok("tie-break follows resolver ordering", ["canceled", "expired"].includes(d.status), d.status);
  const ids = ["sub_B", "sub_a"].sort(); // code-unit: "sub_B" < "sub_a"
  eq("tie-break: latest is the code-unit-greatest id", d.row?.id, ids[1]);
}
ok("only canonical paid source reads active",
  cases.every(([, rows]) => (describeAccountSubscription(rows).status === "active") === (planStateFromRows(rows).source === "paid")));

// ── 2. getEffectivePlanState keeps its public shape ─────────────────────────
function createDb(rows) {
  const db = new DatabaseSync(":memory:");
  db.exec(`CREATE TABLE subscriptions (
    id TEXT PRIMARY KEY, owner_user_id TEXT, workspace_id TEXT, plan TEXT, status TEXT,
    subscription_status TEXT, billing_interval TEXT, trial_end TEXT, expires_at TEXT,
    current_period_end TEXT, payment_failed_at TEXT, stripe_subscription_id TEXT,
    created_at TEXT, updated_at TEXT)`);
  const ins = db.prepare(`INSERT INTO subscriptions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  for (const r of rows) ins.run(r.id, r.owner_user_id ?? "u1", r.workspace_id, r.plan, r.status, r.subscription_status,
    r.billing_interval, r.trial_end, r.expires_at, r.current_period_end, r.payment_failed_at,
    r.stripe_subscription_id, r.created_at, r.updated_at);
  return db;
}
function d1(db, { failing = false } = {}) {
  return {
    prepare(sql) {
      if (failing) throw new Error("D1_ERROR: no such table");
      const st = db.prepare(sql);
      const bound = (...a) => ({ all: async () => ({ results: st.all(...a) }), first: async () => st.get(...a) ?? null });
      return { bind: (...a) => bound(...a), all: async () => ({ results: st.all() }), first: async () => st.get() ?? null };
    },
  };
}
{
  const env = { cybermeters_db: d1(createDb([row()])) };
  const state = await getEffectivePlanState("u1", env);
  ok("getEffectivePlanState does not expose the governing row", !("row" in state), JSON.stringify(Object.keys(state)));
  eq("getEffectivePlanState paid plan unchanged", [state.plan, state.source, state.is_trial], ["professional", "paid", false]);
  const errState = await getEffectivePlanState("u1", { cybermeters_db: d1(null, { failing: true }) });
  eq("getEffectivePlanState read error unchanged", [errState.plan, errState.source], ["free", "error"]);
}

// ── 3. Routes ───────────────────────────────────────────────────────────────
function rctx(pathname, db, { failing = false, user = { id: "u1", email: "u1@example.test" } } = {}) {
  const request = new Request(`https://api.example${pathname}`);
  return {
    request, url: new URL(request.url),
    env: { cybermeters_db: d1(db, { failing }) },
    json: (body, status = 200) => Response.json(body, { status }),
    serverError: () => Response.json({ error: "server" }, { status: 500 }),
    requireAuth: async () => user,
    requireWorkspaceRole: async () => null, requireWorkspaceAccess: async () => null,
    getAccessibleWorkspaceIds: async () => [], isPlatformAdmin: async () => false,
    evaluateRegressionFixtures: async () => null, consumeApiRateLimit: async () => null,
    validateFrontendRedirectUrl: () => null,
  };
}
async function account(db, opts) { const r = await accountRoutes(rctx("/api/account/subscription", db, opts)); return [r.status, await r.json()]; }
async function billing(db, opts) { const r = await globalBillingRoutes(rctx("/api/billing/subscription", db, opts)); return [r.status, await r.json()]; }

{
  const [st, body] = await account(createDb([]));
  eq("account: no row → 200", st, 200);
  eq("account: no row → status none (not active)", body.subscription.status, "none");
  eq("account: no row → no invented provider/cycle", [body.subscription.billing_provider, body.subscription.billing_cycle], [null, null]);
  eq("account: no row → free plan", body.subscription.plan, "free");
}
{
  const [, body] = await account(createDb([row({ subscription_status: "trialing", trial_end: iso(4), current_period_end: null, stripe_subscription_id: null })]));
  eq("account: trial → trialing", body.subscription.status, "trialing");
  ok("account: trial carries trial_ends_at", !!body.subscription.trial_ends_at);
  eq("account: local trial provider", body.subscription.billing_provider, "cybermeters");
}
{
  const [, body] = await account(createDb([row()]));
  eq("account: paid → active + stripe + monthly", [body.subscription.status, body.subscription.billing_provider, body.subscription.billing_cycle], ["active", "stripe", "monthly"]);
  ok("account: no Stripe id leaked", !JSON.stringify(body).includes("sub_stripe_1"));
}
{
  const [st, body] = await account(null, { failing: true });
  eq("account: unreadable → 200 unavailable with unknown plan", [st, body.subscription.status, body.subscription.plan], [200, "unavailable", null]);
}
{
  const r = await accountRoutes(rctx("/api/account/subscription", createDb([]), { user: null }));
  eq("account: unauthenticated → 401", r.status, 401);
}
{
  const [st, body] = await billing(createDb([]));
  eq("billing: no row → status none, null cycle", [st, body.status, body.billing_cycle, body.plan], [200, "none", null, "free"]);
  const [, paid] = await billing(createDb([row({ billing_interval: "annual" })]));
  eq("billing: paid annual", [paid.status, paid.billing_cycle, paid.plan], ["active", "annual", "professional"]);
  const [, lapsed] = await billing(createDb([row({ subscription_status: "past_due", payment_failed_at: iso(-30), current_period_end: iso(-20) })]));
  eq("billing: lapsed past due is not active", [lapsed.status, lapsed.plan], ["past_due_lapsed", "free"]);
  const [errSt, err] = await billing(null, { failing: true });
  eq("billing (published API): unreadable → 503, plan null", [errSt, err.status, err.plan], [503, "unavailable", null]);
  // Both surfaces agree for every matrix case.
  for (const [label, rows] of cases) {
    const [, a] = await account(createDb(rows.map((r) => ({ ...r, owner_user_id: "u1" }))));
    const [, b] = await billing(createDb(rows.map((r) => ({ ...r, owner_user_id: "u1" }))));
    eq(`surfaces agree (${label})`, [a.subscription.status, a.subscription.plan], [b.status, b.plan]);
  }
}
{
  // /api/account/profile no longer invents an active manual subscription.
  const db = createDb([]);
  db.exec("CREATE TABLE customer_profiles (id TEXT, owner_user_id TEXT, company_name TEXT, website TEXT, industry TEXT, company_size TEXT, contact_email TEXT, contact_name TEXT, created_at TEXT, updated_at TEXT)");
  const r = await accountRoutes(rctx("/api/account/profile", db));
  const body = await r.json();
  eq("profile: no row → status none, no invented provider/email", [r.status, body.subscription.status, body.subscription.billing_provider, body.subscription.billing_email], [200, "none", null, null]);
  const db2 = createDb([row({ subscription_status: "trialing", trial_end: iso(3), current_period_end: null, stripe_subscription_id: null })]);
  db2.exec("CREATE TABLE customer_profiles (id TEXT, owner_user_id TEXT, company_name TEXT, website TEXT, industry TEXT, company_size TEXT, contact_email TEXT, contact_name TEXT, created_at TEXT, updated_at TEXT)");
  const body2 = await (await accountRoutes(rctx("/api/account/profile", db2))).json();
  eq("profile: trial row → trialing (canonical)", body2.subscription.status, "trialing");
}
{
  // Tenant isolation: another owner's paid row never reaches this account.
  const [, body] = await account(createDb([row({ owner_user_id: "someone_else" })]));
  eq("account: foreign owner's row ignored", [body.subscription.status, body.subscription.plan], ["none", "free"]);
}

console.log(`validate-account-subscription-status: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
