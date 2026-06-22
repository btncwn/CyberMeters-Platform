# CyberMeters — Alerting & Notifications Audit v1

**Sprint 12A — Phase 1**
**Date:** June 2026
**Status:** Audit complete — implementation follows

---

## Executive Summary

CyberMeters currently has **two entirely separate alert systems** that share no data, no code path, and no cross-reference:

1. **Email Alert Engine** — fires emails via Resend when scheduled scans detect historical changes (score drop, new takeovers, exposed assets, new high/critical findings). Writes to `asset_alert_records` for dedup. Does **not** create `notification_events` rows.

2. **In-App Notification System** — creates `notification_events` rows after every scan completion. Powers the NotificationBell dropdown. Does **not** trigger emails.

These two systems are effectively invisible to each other. A customer who receives an email alert has no corresponding in-app notification for that alert, and vice versa.

---

## Database Schema

### `notification_events`

Source: `database/migrations/014-notifications.sql`

| Column | Type | Notes |
|--------|------|-------|
| `id` | TEXT PK | `notif_` prefix via `createId()` |
| `workspace_id` | TEXT NOT NULL | Workspace scope |
| `user_id` | TEXT | NULL = workspace-global notification |
| `type` | TEXT NOT NULL | See event types below |
| `severity` | TEXT NOT NULL | `critical \| high \| medium \| low \| info` |
| `title` | TEXT NOT NULL | Display title |
| `message` | TEXT | Optional short description |
| `metadata_json` | TEXT | JSON payload (scan_id, domain, score, risk_level) |
| `status` | TEXT NOT NULL | `unread \| read` (default: `unread`) |
| `created_at` | TEXT | `datetime('now')` |
| `read_at` | TEXT | Set when marked read |
| `sent_at` | TEXT | Reserved for future email cross-reference |

Indexes: `(workspace_id, created_at DESC)`, `(workspace_id, status)`, `(type)`.

**Event types defined in schema:**
- `scan_completed` — implemented
- `critical_finding` — implemented
- `high_finding` — implemented
- `scan_failed` — **defined but never generated**
- `domain_verified` — **defined but never generated**
- `report_generated` — **defined but never generated**
- `asset_change` — **defined but never generated**

### `notification_preferences`

Source: `database/migrations/014-notifications.sql`

| Column | Type | Notes |
|--------|------|-------|
| `id` | TEXT PK | |
| `workspace_id` | TEXT NOT NULL | |
| `user_id` | TEXT | NULL = workspace-level |
| `event_type` | TEXT NOT NULL | Matches notification type |
| `enabled` | INTEGER NOT NULL | 1 = on, 0 = off (default: 1) |
| `channel` | TEXT NOT NULL | `in_app \| email` (default: `in_app`) |
| `created_at` | TEXT | |

UNIQUE constraint on `(workspace_id, user_id, event_type, channel)`.

**Status: Dead table.** No Worker code reads or writes this table. No API endpoints reference it. No frontend UI exists to set preferences.

---

## Alert Trigger Inventory

### Path A — In-App Notifications (post-scan)

**Function:** `createNotificationsForDomain()` at Worker line 16448
**Called by:** scan completion pipeline (after every scan)

Triggers 1–3 in-app notifications per workspace associated with the domain:

| Notification | Condition | Severity |
|-------------|-----------|---------|
| `scan_completed` | Always (after every scan) | Auto-derived: `critical` if criticalCount>0, `high` if highCount>0, else `info` |
| `critical_finding` | If `criticalCount > 0` | `critical` |
| `high_finding` | If `highCount > 0` | `high` |

Metadata stored: `{ scan_id, domain, score, risk_level }`

**No dedup.** Every scan creates 1–3 new notification rows, regardless of whether the same domain was scanned yesterday. Active workspaces with daily scheduled scans accumulate notifications rapidly.

### Path B — Email Alert Engine (scheduled scan change detection)

**Functions:** `shouldSendAlert()` at line 12701, `buildAlertEmail()` at line 12746, `sendAlertEmail()` at line 12831

**Called by:** scheduled scan completion (separate code path from Path A)

Alert conditions checked:

| Trigger | Condition |
|---------|-----------|
| `score_drop` | Score dropped ≥10 points vs previous scan |
| `takeover_risk` | ≥1 new subdomain takeover risk detected |
| `exposed_asset` | ≥1 new exposed asset detected |
| `new_finding` | ≥1 new `high` or `critical` severity finding |

Dedup via `asset_alert_records` table: `INSERT OR IGNORE` on `(workspace_id, scan_id)`.

Email sent via Resend API (`env.RESEND_API_KEY`).
From: `alerts@cybermeters.com` (env `ALERT_EMAIL_FROM`).
To: `env.ALERT_EMAIL_TO` — **single hardcoded recipient**. Not per-workspace, not per-user. Defaults to `ttrnn47@gmail.com` if not set. No per-workspace or per-user email routing exists.

**Does not create notification_events rows.** Email-only.

### Path C — Asset Change Alert (separate from Path B)

**Function:** `sendAssetChangeAlert()` at line 12586

A third separate alert path, specifically for `asset_events` changes (new asset discovered, takeover risk, etc.). Also email-only. Same Resend infrastructure. Dedup via `asset_alert_records`. Does not create notification_events rows.

---

## API Layer

### GET `/api/workspaces/:id/notifications`
- Returns: `{ workspace_id, unread_count, count, notifications[] }`
- Query params: `?status` (filter by status), `?limit` (max 200, default probably ~30)
- Permission: any authenticated workspace member (viewer+)

### POST `/api/workspaces/:id/notifications/:notifId/read`
- Marks a single notification as read, or all if `notifId === 'all'`
- Permission: `notification:mark_read` — requires `viewer` role

### Frontend wrappers (`frontend/src/api.js`)

```js
api.getWorkspaceNotifications(workspaceId, { status, limit })
api.markNotificationRead(workspaceId, notifId)  // notifId can be 'all'
```

Both are implemented. No gaps in the API wrapper layer.

---

## NotificationBell.jsx — Current Behaviour Audit

Source: `frontend/src/components/NotificationBell.jsx`

### What works
- Reads `cybermeters_workspace_id` from localStorage
- Polls every 60 seconds (silent background refresh)
- Fetches 30 most recent notifications on mount and on panel open
- Unread count badge: red dot (shows `unread_count`)
- Panel header: notification count pill (99+ cap), "All read" button
- Per-notification: TypeIcon, title, message (2-line clamp), severity dot, relative timestamp
- Mark individual as read: optimistic update + API call
- Mark all read: optimistic update + API call (bulk)
- Falls back gracefully if no workspace selected (shows plain bell, no panel)

### What is missing
- **No navigation on click**: clicking a notification does nothing. No link to the scan, domain, or finding that triggered it.
- **No "View all" link**: no path to a dedicated Notification Center page
- **No filter or grouping**: all notification types rendered in one flat list
- **Unread count cap**: badge shows the raw unread_count from the API but doesn't auto-mark-read when panel opens — unread count only drops when user explicitly dismisses items
- **No empty state for specific filters**: only one global empty state
- **TypeIcon coverage gaps**: `scan_failed`, `domain_verified`, `report_generated`, `asset_change` would fall through to the `default` Info icon (they're defined in schema but never generated, so not a current UX issue)

---

## Gap Analysis

### Critical gaps

| # | Gap | Impact | Sprint 12A Phase |
|---|-----|--------|-----------------|
| G1 | Dual alert paths (email + in-app) are entirely disconnected | Customer receives email alert but sees no notification bell update | Ph 1 (documented) |
| G2 | Email alerts go to single env var recipient, not per-workspace users | No workspace member receives alerts for their workspace | Ph 4 |
| G3 | `notification_preferences` table exists but is completely unused | Preferences sprint will require this to be wired up | Ph 4 |
| G4 | No dedup in `createNotificationsForDomain` | Bell floods after high-frequency scheduled scans | Ph 2 |
| G5 | Clicking a notification does nothing (no navigation) | Notifications are informational dead-ends | Ph 8 |
| G6 | No Notification Center page | No place to see full history, filter by type/severity | Ph 2 |

### Medium gaps

| # | Gap | Impact | Sprint 12A Phase |
|---|-----|--------|-----------------|
| G7 | 4 of 7 event types (scan_failed, domain_verified, report_generated, asset_change) never generated | Bell is sparse — only scan activity shows up | Future |
| G8 | No "View all" link in bell panel | Can't escape panel to history view | Ph 8 |
| G9 | No daily digest architecture | No batching — every scan creates fresh notifications | Ph 5 |
| G10 | Bell panel limited to 30 items — no pagination | Older notifications inaccessible without center page | Ph 2 |

### Minor gaps

| # | Gap | Impact |
|---|-----|--------|
| G11 | Panel auto-refresh is 60s, not configurable | Not user-controllable |
| G12 | No Slack / Teams delivery | Only email + in-app (design only for Sprint 12A) |
| G13 | `sent_at` column exists on `notification_events` but never written | Email cross-reference column unused |

---

## Email Alert Infrastructure

**Provider:** Resend (`https://api.resend.com/emails`)

**Environment variables:**
- `RESEND_API_KEY` — Wrangler secret (required for delivery; missing = silent no-op)
- `ALERT_EMAIL_TO` — single recipient address (defaults to `ttrnn47@gmail.com`)
- `ALERT_EMAIL_FROM` — sender, default `alerts@cybermeters.com`
- `SAFE_EMAIL_FROM` — sender for lower-urgency alerts
- `HELLO_EMAIL_FROM` — sender for onboarding/customer emails

**Email functions:**
- `sendAlertEmail()` — workspace alert emails (non-fatal, all errors swallowed)
- `sendCustomerEmail()` — strict user-facing variant (never falls back to ALERT_EMAIL_TO)
- `buildAlertEmail()` — branded HTML + plain text template
- `buildAssetAlertEmail()` — separate template for asset change alerts

**Known issues:**
- No per-workspace email routing — all alerts go to one address
- `sendCustomerEmail` requires `toEmails` to be non-null — no fallback, silently does nothing

---

## Recommended Sprint 12A Implementation Order

Based on this audit:

1. **Phase 2 — Notification Center page** (`/notifications`): unread/severity/type filters, full history, mark read. This is the foundational UI that unlocks navigation from the bell.
2. **Phase 3 — Severity category mapping**: wire finding severity → notification severity (already correct in `createNotificationsForDomain` — auto-derives from criticalCount/highCount).
3. **Phase 4 — User notification preferences**: activate the `notification_preferences` table. Add API endpoints. Add frontend settings UI.
4. **Phase 5 — Daily digest architecture**: document the batching design; optionally implement.
5. **Phase 6–7 — Slack/Teams design docs**: design only, no implementation.
6. **Phase 8 — Bell UX**: add "View all" → `/notifications`, click-through navigation to scan, auto-mark-read on panel open.
7. **Phase 9 — Validation**: existing notifications API unchanged, bell still functional, no regressions.

---

## File Inventory

| File | Role | Status |
|------|------|--------|
| `workers/scan-api/src/index.js:16357` | `createNotificationEvent()` | Working |
| `workers/scan-api/src/index.js:16448` | `createNotificationsForDomain()` | Working, no dedup |
| `workers/scan-api/src/index.js:12701` | `shouldSendAlert()` — email engine | Working, disconnected from in-app |
| `workers/scan-api/src/index.js:12831` | `sendAlertEmail()` | Working, single recipient |
| `workers/scan-api/src/index.js:12586` | `sendAssetChangeAlert()` | Working, email-only |
| `workers/scan-api/src/index.js:26308` | GET notifications API | Working |
| `workers/scan-api/src/index.js:26377` | POST mark-read API | Working |
| `frontend/src/components/NotificationBell.jsx` | Bell dropdown UI | Working, no click-through |
| `frontend/src/api.js:499` | `getWorkspaceNotifications()` | Working |
| `frontend/src/api.js:511` | `markNotificationRead()` | Working |
| `database/migrations/014-notifications.sql` | Schema | Applied; preferences table unused |

---

## Version History

| Version | Date | Notes |
|---------|------|-------|
| v1 | June 2026 | Full alerting audit — schema, triggers, API, email engine, bell behaviour, gap analysis |
