# CyberMeters — Subscription Architecture v1

**Sprint 14 — Phase 2**
**Date:** June 2026
**Status:** Architecture document — reflects implemented + Sprint 14 additions

---

## Overview

CyberMeters uses a **workspace-owned subscription model**.

Each workspace has a subscription record that determines:
- Which plan features are available in that workspace
- Whether a trial is active
- Whether the subscription is paid and current

The account owner (user) is the billing entity. Subscription state is stored per workspace and linked to the owning user.

---

## Entity Relationships

```
users
  └── owns (owner_user_id) → workspaces (1:many)
                                └── has → subscriptions (1:1 per workspace)
                                              └── logs → subscription_events (1:many)

workspace_members
  └── grants users access to workspaces with a role (owner/admin/analyst/viewer)
```

### Key rules

1. **One subscription per workspace.** Each workspace has exactly one active subscription row.
2. **Subscription owner = workspace owner.** The `owner_user_id` on the subscriptions table matches the `owner_user_id` on the workspaces table.
3. **Billing is per workspace, not per seat.** Team members added to a workspace consume the workspace's plan limits, but are not separately billed.
4. **Plan limits are scoped to the workspace.** A user who owns multiple workspaces can have different plan states per workspace (e.g., one workspace on Professional trial, another on free after trial expiry).

---

## Subscription Lifecycle

```
Workspace created
    ↓
Trial row inserted
  { plan: 'professional', status: 'trialing',
    trial_start: now, trial_end: now + 14d }
    ↓
Trial active (14 days)
    ↓
[Path A] User upgrades → Stripe checkout
    → subscription row updated with Stripe IDs
    → status: 'active', plan: paid plan
    ↓
Active paid subscription
    ↓
[Path B] Trial expires without upgrade
    → isTrialActive() → false
    → getWorkspaceSubscription() returns free plan
    ↓
Free plan enforced (limits applied at API layer)
```

### Status values

| status      | Meaning                                          | Plan effective? |
|-------------|--------------------------------------------------|:---------------:|
| `trialing`  | Within the 14-day trial window                   | Yes (trial plan)|
| `active`    | Paid subscription, current period not expired    | Yes             |
| `past_due`  | Payment failed, grace period active              | Yes (grace)     |
| `canceled`  | Subscription cancelled, period may still be live | Yes (until end) |
| `expired`   | Trial or period end passed without renewal       | No (→ free)     |
| `free`      | No subscription row, or row is post-expiry free  | Yes (free tier) |

---

## Database Schema

### subscriptions

The subscriptions table was originally created manually and retroactively documented in `migration 047-subscriptions-table.sql`. Sprint 14 adds the trial columns via `migration 050-subscription-trial.sql`.

```sql
CREATE TABLE IF NOT EXISTS subscriptions (
  id                    TEXT PRIMARY KEY,
  owner_user_id         TEXT,           -- billing owner (links to users.id)
  workspace_id          TEXT,           -- workspace scope (links to workspaces.id)
  plan                  TEXT DEFAULT 'free',
  status                TEXT DEFAULT 'active',
  subscription_status   TEXT,           -- Stripe-aligned: active|trialing|past_due|canceled
  trial_start           TEXT,           -- ISO-8601, set on workspace creation (Sprint 14)
  trial_end             TEXT,           -- ISO-8601 = trial_start + 14 days (Sprint 14)
  current_period_start  TEXT,           -- ISO-8601, set on Stripe subscription update (Sprint 14)
  current_period_end    TEXT,           -- ISO-8601, expiry for paid subscriptions
  billing_interval      TEXT DEFAULT 'monthly',
  stripe_customer_id    TEXT,
  stripe_subscription_id TEXT,
  stripe_price_id       TEXT,
  expires_at            TEXT,           -- legacy alias for current_period_end
  cancel_at_period_end  INTEGER DEFAULT 0,
  cancelled_at          TEXT,
  payment_failed_at     TEXT,
  payment_retry_count   INTEGER DEFAULT 0,
  created_at            TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at            TEXT
);
```

### subscription_events

Audit log for all subscription lifecycle events. Created in Sprint 14 migration 050.

```sql
CREATE TABLE IF NOT EXISTS subscription_events (
  id              TEXT PRIMARY KEY,
  subscription_id TEXT NOT NULL REFERENCES subscriptions(id),
  event_type      TEXT NOT NULL,   -- trial_started|trial_expired|plan_upgraded|plan_downgraded|
                                   -- payment_succeeded|payment_failed|subscription_cancelled
  payload_json    TEXT,            -- event-specific data as JSON string
  created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
```

---

## Worker Helpers

### Existing (unchanged)

| Helper                              | Purpose                                          |
|-------------------------------------|--------------------------------------------------|
| `getUserPlan(userId, env)`          | Resolves effective plan for a user (user-level)  |
| `getEffectivePlan(userId, env)`     | Alias for getUserPlan                            |
| `getPlanFeatures(plan)`             | Returns feature array for a plan                 |
| `getPlanLimits(plan)`               | Returns limit object for a plan                  |
| `hasFeatureEntitlement(plan, key)`  | True if plan includes feature key                |
| `normalizePlan(plan)`               | Validates and normalises plan string             |

### New (Sprint 14)

| Helper                                    | Purpose                                                      |
|-------------------------------------------|--------------------------------------------------------------|
| `getWorkspaceSubscription(wsId, env)`     | Fetches subscription row for a workspace                     |
| `isTrialActive(sub)`                      | True if subscription is in active trial window               |
| `isSubscriptionActive(sub)`              | True if subscription is paid and current                     |
| `getTrialRemainingDays(sub)`             | Integer days remaining in trial (0 if expired/not trialing)  |
| `canUseFeature(plan, featureKey)`        | Gate check — true if plan has feature entitlement            |
| `createWorkspaceTrialSubscription(wsId, ownerId, env)` | Inserts 14-day trial row on workspace creation |

---

## Plan Resolution at the API Layer

When an API endpoint needs to enforce a plan limit or feature gate, it follows this pattern:

```
1. Get workspace owner: getWorkspaceOwnerId(workspaceId, env)
2. Get effective plan:  getEffectivePlan(ownerId, env)
3. Check limit:         getPlanLimits(plan).scheduled_scans > current_count
4. Check feature:       canUseFeature(plan, 'alerts')
5. Return 403 with planLimitExceeded() or featureGated() if check fails
```

For workspace-level subscription display (billing page), the `getWorkspaceSubscription()` helper is used directly to get the full subscription row including trial dates and status.

---

## Subscription Ownership: Why Workspace-Level?

**Alternative considered: Account-level subscription** (one subscription per user, applies to all their workspaces).

**Rejected because:**

1. **MSP model requires per-workspace billing.** An MSP managing 50 client workspaces cannot be on a single account-level plan — each client has different needs and billing.
2. **Workspace lifecycle independence.** A workspace can be transferred, archived, or handed to a new owner without disrupting other workspaces.
3. **Future: per-workspace Stripe subscriptions.** The Stripe model (one customer, one subscription) maps cleanly to one workspace, one subscription.
4. **Existing code already uses workspace-scoped limits.** `getPlanLimits()` is called with workspace context in all limit-enforcement routes.

**The current implementation uses `owner_user_id`** as the FK in the subscriptions table because:
- Stripe payments are made by a person (the owner), not a workspace
- The owner may have multiple workspaces — billing is consolidated on their Stripe customer record
- A future workspace transfer will update `owner_user_id` on the subscription row

This means: today, all workspaces owned by the same user share a plan. Per-workspace billing differentiation is a v2 concern once MSP customers arrive.

---

## Feature Gate Framework

Feature gates are boolean checks on the resolved plan. They are evaluated in the Worker at route handler time and return `403` if the gate fails.

### Gate definitions (Sprint 14)

| Gate key          | Plans that include it              | Description                             |
|-------------------|------------------------------------|-----------------------------------------|
| `scheduled_scans` | starter, professional, business, enterprise | Access to scheduled scan creation   |
| `alerts`          | starter, professional, business, enterprise | Email/in-app alert notifications    |
| `pdf_reports`     | starter, professional, business, enterprise | PDF report generation and download  |
| `multi_workspace` | starter, professional, business, enterprise | Create more than 1 workspace        |
| `team_members`    | starter, professional, business, enterprise | Invite and manage workspace members |

### Existing gates (unchanged)

| Gate key              | Plans that include it              | Description                           |
|-----------------------|------------------------------------|---------------------------------------|
| `business_risk_score` | starter, professional, business, enterprise | Business Risk Score module    |
| `cyber_essentials`    | professional, business, enterprise | Cyber Essentials Readiness            |
| `vendor_risk`         | professional, business, enterprise | Vendor Risk Intelligence              |
| `executive_dashboard` | professional, business, enterprise | Executive Risk Dashboard              |
| `audit_logs`          | professional, business, enterprise | Workspace audit log access            |
| `portfolio_monitoring`| business, enterprise               | Portfolio dashboard and monitoring    |
| `white_label`         | business, enterprise               | White-label PDF reports               |
| `msp_dashboard`       | enterprise                         | MSP portfolio dashboard               |

---

## Multi-Tenant Considerations

Each workspace is a fully isolated tenant boundary:

- Scans belong to workspaces via `workspace_id`
- Domains are scoped to workspaces
- Subscription state is scoped to workspace owner
- RBAC (owner/admin/analyst/viewer) controls access within the workspace
- Data isolation: all queries filter by `workspace_id`

Future MSP model:
- One MSP account owns N client workspaces
- Each client workspace could have its own subscription (v2)
- MSP user gets `msp_dashboard` feature to view all workspaces in a portfolio view

---

## Version History

| Version | Date      | Notes                                             |
|---------|-----------|---------------------------------------------------|
| v1      | June 2026 | Initial architecture — workspace-owned subscriptions, Sprint 14 additions |
