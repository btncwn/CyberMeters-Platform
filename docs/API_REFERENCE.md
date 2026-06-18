# CyberMeters API Reference

**Base URL:** `https://cybermeters-platform.ttrnn47.workers.dev`

---

## Health Check

```
GET /health
```

**Response**
```json
{
  "status": "ok",
  "service": "cybermeters-scan-api"
}
```

**curl**
```bash
curl https://cybermeters-platform.ttrnn47.workers.dev/health
```

---

## Submit Scan

```
POST /api/scan
```

**Request body**
```json
{
  "domain": "example.com"
}
```

**Response**
```json
{
  "status": "queued",
  "scan_id": "scan_abc123",
  "domain_id": "domain_xyz789",
  "domain": "example.com",
  "report_key": "reports/scan_abc123.json",
  "message": "Scan request stored in D1 and initial report stored in R2"
}
```

**curl**
```bash
curl -X POST https://cybermeters-platform.ttrnn47.workers.dev/api/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

---

## List Scans

```
GET /api/scans
```

Returns the 20 most recent scans across all domains.

**Response**
```json
{
  "scans": [
    {
      "id": "scan_abc123",
      "domain": "example.com",
      "status": "queued",
      "created_at": "2026-06-18 10:00:00"
    }
  ]
}
```

**curl**
```bash
curl https://cybermeters-platform.ttrnn47.workers.dev/api/scans
```

---

## Scan Detail

```
GET /api/scans/:id
```

**Response**
```json
{
  "scan": {
    "id": "scan_abc123",
    "domain_id": "domain_xyz789",
    "domain": "example.com",
    "status": "queued",
    "created_at": "2026-06-18 10:00:00"
  },
  "report_key": "reports/scan_abc123.json"
}
```

**curl**
```bash
curl https://cybermeters-platform.ttrnn47.workers.dev/api/scans/scan_abc123
```

---

## Scan Report

```
GET /api/scans/:id/report
```

Reads the scan report JSON from R2 and returns it in a structured format.

**Response — report found**
```json
{
  "scan_id": "scan_abc123",
  "domain": "example.com",
  "status": "queued",
  "cyber_metrics_score": 0,
  "risk_level": "unknown",
  "findings": [],
  "recommendations": [],
  "report_type": "initial_scan_record",
  "created_at": "2026-06-18T10:00:00.000Z",
  "message": "Initial queued scan report stored in R2"
}
```

**Field reference**

| Field | Type | Description |
|---|---|---|
| `scan_id` | string | Scan identifier |
| `domain` | string | Target domain |
| `status` | string | Current scan status (`queued`, `running`, `completed`, `failed`) |
| `cyber_metrics_score` | number | 0–100 risk score. 0 = unscored, higher = better posture |
| `risk_level` | string | `unknown`, `low`, `medium`, `high`, `critical` |
| `findings` | array | List of findings written by the scan engine |
| `recommendations` | array | Prioritised remediation actions written by the scan engine |

**Response — scan not found (404)**
```json
{
  "error": "Scan not found"
}
```

**Response — report not in R2 (404)**
```json
{
  "error": "Report not found"
}
```

**curl**
```bash
curl https://cybermeters-platform.ttrnn47.workers.dev/api/scans/scan_abc123/report
```

**curl — with real scan ID**
```bash
# 1. Submit a scan and capture the ID
SCAN_ID=$(curl -s -X POST https://cybermeters-platform.ttrnn47.workers.dev/api/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}' | jq -r '.scan_id')

# 2. Fetch the report
curl https://cybermeters-platform.ttrnn47.workers.dev/api/scans/$SCAN_ID/report
```

---

## Domain History

```
GET /api/domain/:domain/history
```

Returns all scans for a given domain, newest first.

**Response**
```json
{
  "domain": "example.com",
  "scans": [
    {
      "id": "scan_abc123",
      "domain_id": "domain_xyz789",
      "domain": "example.com",
      "status": "queued",
      "created_at": "2026-06-18 10:00:00"
    }
  ]
}
```

**curl**
```bash
curl https://cybermeters-platform.ttrnn47.workers.dev/api/domain/example.com/history
```

---

## Notes

- All timestamps are stored in D1 as UTC strings (`YYYY-MM-DD HH:MM:SS`).
- `created_at` in R2 report bodies is ISO 8601 (`2026-06-18T10:00:00.000Z`).
- Reports are stored in R2 at key `reports/<scan_id>.json`.
- `cyber_metrics_score`, `risk_level`, `findings`, and `recommendations` are populated by the scan engine when a scan completes. Initial queued reports contain default/empty values.
- The scan engine writes to R2 directly; this API reads from it without modification.
