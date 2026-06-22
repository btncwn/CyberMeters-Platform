# CyberMeters — Slack Alerting Design v1

**Sprint 12A — Phase 6**
**Date:** June 2026
**Status:** Design only — no implementation in Sprint 12A

---

## Overview

Slack is the highest-value notification channel for security teams. CyberMeters findings are actionable; a well-structured Slack message lets an analyst triage a critical finding in seconds without opening the platform.

This document specifies the design for a future Slack integration. No implementation is done in Sprint 12A.

---

## Integration Model

**Approach: Incoming Webhooks (not Slack Bot)**

Incoming Webhooks are the correct v1 approach:

- No OAuth app required — workspace admins paste a webhook URL into CyberMeters settings
- Webhook URL is per-channel — team controls which channel receives alerts
- Simpler auth — no token refresh, no bot management
- Sufficient for all v1 alert types (post messages to one channel)

Bot API (v2) would add: thread replies, interactive mark-resolved buttons, multi-channel routing. Deferred.

---

## User Setup Flow

1. User navigates to **Settings → Notifications → Slack**
2. User clicks "Connect Slack channel" → opens Slack app directory to create an Incoming Webhook
3. User copies the webhook URL (format: `https://hooks.slack.com/services/T.../B.../...`)
4. User pastes URL into CyberMeters settings and clicks "Send test message"
5. CyberMeters POSTs a test message to the webhook
6. User confirms test message appeared in their Slack channel

Storage: `notification_preferences` table, adding channel `= 'slack'` row with metadata containing the encrypted webhook URL.

**Webhook URL storage:** Must be encrypted at rest (not stored as plain text in D1). Use `env.ENCRYPTION_KEY` or equivalent Wrangler secret to AES-256-GCM encrypt the webhook URL before storing.

---

## Message Format

### Critical / High finding alert

```
┌─────────────────────────────────────────────────────────────┐
│ 🚨 CyberMeters Alert — Critical Finding                      │
│ ─────────────────────────────────────────────────────────── │
│ Domain:   api.example.com                                    │
│ Finding:  Subdomain takeover vulnerability detected          │
│ Severity: CRITICAL · Score impact: -18 points               │
│ Risk:     An unclaimed DNS record points to an unregistered  │
│           cloud resource. An attacker can claim it.          │
│ ─────────────────────────────────────────────────────────── │
│ 🔗 View scan  →  https://app.cybermeters.com/scans/sc_xxx    │
│                                                             │
│ 19 Jun 2026 · 14:32 UTC                                     │
└─────────────────────────────────────────────────────────────┘
```

Implemented as Slack Block Kit:

```json
{
  "blocks": [
    {
      "type": "header",
      "text": { "type": "plain_text", "text": "🚨 CyberMeters Alert — Critical Finding" }
    },
    {
      "type": "section",
      "fields": [
        { "type": "mrkdwn", "text": "*Domain*\napi.example.com" },
        { "type": "mrkdwn", "text": "*Severity*\n🔴 CRITICAL" },
        { "type": "mrkdwn", "text": "*Finding*\nSubdomain takeover vulnerability detected" },
        { "type": "mrkdwn", "text": "*Scan Score*\n42 / 100 (High Risk)" }
      ]
    },
    {
      "type": "actions",
      "elements": [
        {
          "type": "button",
          "text": { "type": "plain_text", "text": "View Scan →" },
          "url": "https://app.cybermeters.com/scans/sc_xxx",
          "style": "danger"
        }
      ]
    },
    {
      "type": "context",
      "elements": [
        { "type": "mrkdwn", "text": "CyberMeters · 19 Jun 2026 14:32 UTC" }
      ]
    }
  ]
}
```

### Scan completed (daily digest mode)

In digest mode, Slack receives one message per workspace per day summarising all completed scans:

```
📊 CyberMeters Daily Summary — Example Workspace
─────────────────────────────
✅ 12 scans completed   🔴 2 critical alerts   🟠 5 high alerts
─────────────────────────────
Highest risk: api.example.com — Score 42 · Critical Risk
             staging.example.com — Score 55 · High Risk
─────────────────────────────
View Dashboard →
```

---

## Alert Routing Rules

| Event | Slack message? | Timing |
|-------|---------------|--------|
| `critical_finding` | Yes | Immediate |
| `high_finding` | Yes (if enabled in preferences) | Immediate |
| `scan_completed` | No (batched into daily digest) | Daily 08:00 UTC |
| `scan_failed` | Yes | Immediate (future) |
| `domain_verified` | Yes | Immediate (future) |
| `asset_change` | Yes for takeover risk | Immediate (future) |

---

## Worker Implementation Plan (future sprint)

```js
async function sendSlackAlert(webhookUrl, payload) {
  if (!webhookUrl) return
  try {
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(8_000),
    })
  } catch { /* non-fatal */ }
}

function buildSlackFindingAlert(domain, finding, scanId) {
  // Returns Block Kit payload
}
```

Call site: inside `createNotificationsForDomain()`, after creating in-app notifications, if workspace has a Slack webhook configured.

---

## Scope Boundaries

**In scope (v1):**
- Incoming Webhook configuration (settings UI)
- Critical and high finding alerts
- Daily digest summary message
- Test message on webhook save

**Out of scope (v1):**
- Slack OAuth app / bot
- Interactive buttons (mark resolved, acknowledge)
- Thread replies on existing messages
- Multi-channel routing (one webhook per workspace)
- Slack channel picker (user manages this in Slack)

---

## Version History

| Version | Date | Notes |
|---------|------|-------|
| v1 | June 2026 | Initial design — Incoming Webhook approach, Block Kit format, alert routing rules |
