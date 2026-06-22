# CyberMeters — Daily Digest Architecture v1

**Sprint 12A — Phase 5**
**Date:** June 2026
**Status:** Architecture design — implementation deferred pending notification_preferences wiring

---

## Problem Statement

CyberMeters currently fires up to 3 notifications per scan completion. An active workspace with daily scheduled scans across 10 domains accumulates 30+ notifications per day, most of which are routine `scan_completed` events. Users stop reading notifications when they're all noise.

A daily digest batches routine events into one structured summary email, reserving real-time notifications for actionable security events (critical/high findings, new takeover risks, exposed assets).

---

## Design Goals

- One digest email per workspace per day (not per scan, not per user)
- Real-time alerts still fire immediately for critical events (no digest batching for critical/high severity)
- Digest is opt-in per workspace or per user (default: on for workspaces, respects `notification_preferences`)
- Digest covers the 24h window ending at delivery time
- No new scanner runs — digest reads from existing `notification_events` and `scan_history` tables
- Fully Cloudflare-native — implemented as a scheduled Worker trigger (cron)

---

## Architecture

### Delivery mechanism

Cloudflare Workers support cron triggers via `wrangler.toml`. A dedicated cron entry fires the digest job:

```toml
[triggers]
crons = [
  "0 8 * * *"   # 08:00 UTC daily — digest delivery window
]
```

The Worker's `scheduled(event, env, ctx)` handler dispatches based on `event.cron`.

### Digest query

The digest job queries `notification_events` for the past 24 hours per workspace:

```sql
SELECT
  workspace_id,
  type,
  severity,
  COUNT(*) AS count,
  MIN(created_at) AS first_at,
  MAX(created_at) AS last_at
FROM notification_events
WHERE
  created_at >= datetime('now', '-24 hours')
  AND status = 'unread'
GROUP BY workspace_id, type, severity
ORDER BY workspace_id, severity DESC
```

A second query collects domain-level summary:

```sql
SELECT
  ne.workspace_id,
  JSON_EXTRACT(ne.metadata_json, '$.domain') AS domain,
  JSON_EXTRACT(ne.metadata_json, '$.score')  AS score,
  JSON_EXTRACT(ne.metadata_json, '$.risk_level') AS risk_level,
  COUNT(*) AS scans_completed
FROM notification_events ne
WHERE
  ne.type = 'scan_completed'
  AND ne.created_at >= datetime('now', '-24 hours')
GROUP BY ne.workspace_id, domain
ORDER BY risk_level DESC
```

### Digest email structure

```
Subject: CyberMeters Daily Summary — [Workspace Name] · [Date]

───────────────────────────────────────────
  Today's Security Activity
  [date range, e.g. "18 June 08:00 → 19 June 08:00 UTC"]
───────────────────────────────────────────

  🔴 Critical alerts       2
  🟠 High alerts           5
  ✅ Scans completed      12
  
───────────────────────────────────────────
  Domain Summary
───────────────────────────────────────────
  example.com          Score: 42  Risk: Critical  ⚠ 2 critical findings
  api.example.com      Score: 71  Risk: High      1 scan completed
  staging.example.com  Score: 89  Risk: Low       1 scan completed

───────────────────────────────────────────
  [View Dashboard →]  [View All Notifications →]
───────────────────────────────────────────
```

### Dedup / sent_at tracking

Use the `sent_at` column on `notification_events` (already in schema, currently unused) to record when a notification was included in a digest:

```sql
UPDATE notification_events
SET sent_at = datetime('now')
WHERE workspace_id = ?
  AND created_at >= datetime('now', '-24 hours')
  AND sent_at IS NULL
```

This prevents re-inclusion if the cron fires more than once in a window (e.g. due to Worker retry).

### Workspace email recipients

The digest job must look up workspace member emails to route per-workspace digests correctly. This is the same gap identified in the alerting audit (G2). Query:

```sql
SELECT u.email, u.display_name
FROM workspace_members wm
JOIN users u ON u.id = wm.user_id
WHERE wm.workspace_id = ?
  AND wm.status = 'active'
  AND u.email_verified = 1
```

Filter by `notification_preferences` once that table is wired:

```sql
AND EXISTS (
  SELECT 1 FROM notification_preferences np
  WHERE np.workspace_id = wm.workspace_id
    AND np.user_id = wm.user_id
    AND np.event_type = 'daily_digest'
    AND np.enabled = 1
    AND np.channel = 'email'
)
```

Default behaviour (before preferences are wired): send to all active, verified workspace members.

---

## Suppression Rules

Real-time notifications are NOT digested. They still fire immediately:

| Type | Delivery |
|------|---------|
| `critical_finding` | Immediate email + in-app |
| `high_finding` | Immediate in-app (email optional via preferences) |
| `scan_completed` | In-app only → batched into daily digest |
| `scan_failed` | Immediate in-app (not yet generated — future) |
| `domain_verified` | Immediate in-app (not yet generated — future) |

---

## Opt-out mechanism

When `notification_preferences` is wired (Sprint 12A Phase 4), users can set:

```
event_type = 'daily_digest'
channel    = 'email'
enabled    = 0
```

Until then, all active workspace members receive the digest.

---

## Implementation Prerequisites

1. `notification_preferences` table populated and API wired (Phase 4)
2. `wrangler.toml` updated with cron trigger `"0 8 * * *"`
3. `scheduled()` handler added to Worker
4. Workspace member email lookup query confirmed working
5. `buildDigestEmail()` function written (similar pattern to `buildAlertEmail()`)
6. `sent_at` update query added after successful delivery

---

## Files to create/modify

| File | Change |
|------|--------|
| `workers/scan-api/src/index.js` | Add `scheduled()` handler, `buildDigestEmail()`, `sendDailyDigest()` |
| `wrangler.toml` | Add cron trigger |
| `database/migrations/` | None required — `sent_at` column already in schema |

---

## Version History

| Version | Date | Notes |
|---------|------|-------|
| v1 | June 2026 | Initial architecture design for daily digest |
