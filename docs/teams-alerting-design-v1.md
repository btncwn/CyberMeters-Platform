# CyberMeters — Microsoft Teams Alerting Design v1

**Sprint 12A — Phase 7**
**Date:** June 2026
**Status:** Design only — no implementation in Sprint 12A

---

## Overview

Microsoft Teams is the primary collaboration platform for enterprise customers — particularly relevant given CyberMeters already detects Microsoft 365 and Entra ID exposure. Security teams running M365 environments are a natural fit.

This document specifies the design for a future Teams integration. No implementation is done in Sprint 12A.

---

## Integration Model

**Approach: Incoming Webhooks (Power Automate / Workflows connector)**

Microsoft deprecated the old Office 365 Connector webhook URL format in late 2024. The correct modern approach uses **Power Automate Workflows**:

1. Teams workspace admin creates a new Workflow in the target channel using the "Post to a channel when a webhook request is received" template
2. Workflow generates a webhook URL (format: `https://prod-xx.westeurope.logic.azure.com/...`)
3. Admin pastes this URL into CyberMeters settings
4. CyberMeters POSTs JSON payloads to the Workflow URL

Payload format: Microsoft Adaptive Cards (v1.4+), posted via the Workflows connector.

**Note:** The legacy `https://xxxxx.webhook.office.com/...` format is deprecated and channels may stop accepting it. CyberMeters should document that users must create a Workflow, not use the legacy Connector.

---

## User Setup Flow

1. User navigates to **Settings → Notifications → Microsoft Teams**
2. User reads the setup instructions:
   - Open Microsoft Teams → go to target channel → select "Workflows" → choose "Post to a channel when a webhook request is received"
   - Give it a name (e.g. "CyberMeters Alerts")
   - Copy the generated webhook URL
3. User pastes URL into CyberMeters and clicks "Send test message"
4. CyberMeters POSTs an Adaptive Card test message
5. User confirms the card appeared in Teams

Storage: same as Slack — `notification_preferences` channel `= 'teams'` with encrypted webhook URL in metadata.

---

## Message Format

### Critical / High finding alert (Adaptive Card)

```json
{
  "type": "message",
  "attachments": [
    {
      "contentType": "application/vnd.microsoft.card.adaptive",
      "content": {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": [
          {
            "type": "TextBlock",
            "text": "🚨 CyberMeters Alert — Critical Finding",
            "weight": "Bolder",
            "size": "Medium",
            "color": "Attention"
          },
          {
            "type": "FactSet",
            "facts": [
              { "title": "Domain",   "value": "api.example.com" },
              { "title": "Severity", "value": "🔴 Critical" },
              { "title": "Finding",  "value": "Subdomain takeover vulnerability detected" },
              { "title": "Score",    "value": "42 / 100 · High Risk" },
              { "title": "Time",     "value": "19 Jun 2026 14:32 UTC" }
            ]
          }
        ],
        "actions": [
          {
            "type": "Action.OpenUrl",
            "title": "View Scan →",
            "url": "https://app.cybermeters.com/scans/sc_xxx"
          }
        ]
      }
    }
  ]
}
```

### Daily digest (Adaptive Card)

```json
{
  "type": "message",
  "attachments": [
    {
      "contentType": "application/vnd.microsoft.card.adaptive",
      "content": {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": [
          {
            "type": "TextBlock",
            "text": "📊 CyberMeters Daily Summary",
            "weight": "Bolder",
            "size": "Medium"
          },
          {
            "type": "TextBlock",
            "text": "Example Workspace · 19 Jun 2026",
            "isSubtle": true,
            "spacing": "None"
          },
          {
            "type": "FactSet",
            "facts": [
              { "title": "✅ Scans completed", "value": "12" },
              { "title": "🔴 Critical alerts", "value": "2" },
              { "title": "🟠 High alerts",     "value": "5" },
              { "title": "Highest risk",       "value": "api.example.com · Score 42 · Critical" }
            ]
          }
        ],
        "actions": [
          {
            "type": "Action.OpenUrl",
            "title": "View Dashboard →",
            "url": "https://app.cybermeters.com/ws/dashboard"
          }
        ]
      }
    }
  ]
}
```

---

## Alert Routing Rules

Mirrors Slack routing:

| Event | Teams message? | Timing |
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
async function sendTeamsAlert(webhookUrl, adaptiveCard) {
  if (!webhookUrl) return
  try {
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: 'message',
        attachments: [{
          contentType: 'application/vnd.microsoft.card.adaptive',
          content: adaptiveCard,
        }],
      }),
      signal: AbortSignal.timeout(8_000),
    })
  } catch { /* non-fatal */ }
}

function buildTeamsFindingCard(domain, finding, scanId) {
  // Returns AdaptiveCard content object
}
```

Call site: same as Slack — inside `createNotificationsForDomain()` after in-app notifications.

---

## Scope Boundaries

**In scope (v1):**
- Workflows webhook configuration (settings UI + instructions for creating the Workflow)
- Critical and high finding alerts via Adaptive Card
- Daily digest summary card
- Test card on webhook save

**Out of scope (v1):**
- Microsoft Graph API / bot registration
- Actionable buttons that write back to CyberMeters (require bot registration + OAuth)
- Channel picker inside Teams (user manages this in Teams)
- Azure AD-specific alert enrichment (Entra ID findings → Teams integration)

---

## Key Difference from Slack

Teams requires Adaptive Card JSON wrapped in a `message` envelope. The `attachments[0].contentType` must be `application/vnd.microsoft.card.adaptive`. Plain text `text` fields are not rendered as rich cards. Block Kit (Slack) and Adaptive Cards (Teams) have different schemas — the Worker must maintain separate `buildSlackPayload()` and `buildTeamsCard()` functions.

---

## Version History

| Version | Date | Notes |
|---------|------|-------|
| v1 | June 2026 | Initial design — Workflows webhook, Adaptive Cards format, alert routing |
