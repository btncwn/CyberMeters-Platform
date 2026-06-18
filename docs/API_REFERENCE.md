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

The scan engine runs asynchronously via `ctx.waitUntil()`. The API returns `202 Accepted` immediately with `status: "running"`. Poll `GET /api/scans/:id` until status is `completed` or `failed`, then fetch the full report from `GET /api/scans/:id/report`.

**Request body**
```json
{
  "domain": "example.com"
}
```

**Response — 202 Accepted**
```json
{
  "status": "running",
  "scan_id": "scan_abc123",
  "domain_id": "domain_xyz789",
  "domain": "example.com",
  "report_key": "reports/scan_abc123.json",
  "message": "Scan engine started. Poll GET /api/scans/:id until status is completed, then GET /api/scans/:id/report."
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

**Response — scan in progress**
```json
{
  "scan_id": "scan_abc123",
  "domain": "example.com",
  "status": "running",
  "cyber_metrics_score": 0,
  "risk_level": "unknown",
  "findings": [],
  "recommendations": {},
  "modules": {},
  "message": "Scan engine is running. Poll GET /api/scans/:id for completion."
}
```

**Response — scan completed**
```json
{
  "scan_id": "scan_abc123",
  "domain": "example.com",
  "status": "completed",
  "cyber_metrics_score": 74,
  "risk_level": "moderate",
  "started_at": "2026-06-18T10:00:00.000Z",
  "completed_at": "2026-06-18T10:00:08.000Z",
  "findings": [
    {
      "id": "header_missing_strict_transport_security",
      "module": "headers",
      "severity": "high",
      "title": "Missing HTTP Strict Transport Security (HSTS) Header",
      "description": "The Strict-Transport-Security header was not returned.",
      "score_impact": -5
    }
  ],
  "recommendations": [
    {
      "priority": 2,
      "module": "headers",
      "title": "Add HTTP Strict Transport Security (HSTS) Header",
      "description": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    }
  ],
  "modules": {
    "dns":            { "resolves": true, "has_ipv6": false, "has_mx": true, "nameservers": ["ns1.example.com."] },
    "ssl":            { "https_available": true, "http_redirects_to_https": true },
    "headers":        { "accessible": true, "status_code": 200, "present": ["x-content-type-options"], "missing": ["strict-transport-security"] },
    "email_security": { "spf": { "present": true }, "dmarc": { "present": true, "policy": "quarantine" }, "dkim": { "present": false, "selector": null } }
  }
}
```

**Field reference**

| Field | Type | Description |
|---|---|---|
| `scan_id` | string | Scan identifier |
| `domain` | string | Target domain |
| `status` | string | `running` → `completed` or `failed` |
| `cyber_metrics_score` | number | 0–100. Score starts at 100; deductions applied per finding. Higher = better. |
| `risk_level` | string | `excellent` (90–100), `good` (75–89), `moderate` (50–74), `high` (25–49), `critical` (0–24) |
| `findings` | array | Issues found. Each has `id`, `module`, `severity`, `title`, `description`, `score_impact` |
| `recommendations` | array | Remediation steps sorted by `priority` (1 = most urgent) |
| `modules` | object | Raw output from each of the 4 scan modules |
| `started_at` | string | ISO 8601 — when the engine started |
| `completed_at` | string | ISO 8601 — when the engine finished (only on `completed`) |
| `failed_at` | string | ISO 8601 — when the engine failed (only on `failed`) |

**Scan engine modules**

| Module | What it checks |
|---|---|
| `dns` | A/AAAA resolution, MX records, IPv6, nameservers |
| `ssl` | HTTPS availability, HTTP→HTTPS redirect |
| `headers` | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| `email_security` | SPF TXT record, DMARC policy, DKIM (11 common selectors probed) |

**Scoring deductions**

| Finding | Deduction |
|---|---|
| Domain does not resolve | −30 |
| HTTPS not available | −25 |
| HTTP does not redirect to HTTPS | −5 |
| Missing HSTS header | −5 |
| Missing CSP header | −3 |
| Missing X-Frame-Options | −2 |
| Missing X-Content-Type-Options | −2 |
| Missing Referrer-Policy | −1 |
| Missing Permissions-Policy | −1 |
| Missing DMARC | −15 |
| DMARC policy is `none` | −5 |
| Missing SPF | −10 |
| DKIM not detected | −5 |

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

- All timestamps in D1 are UTC strings (`YYYY-MM-DD HH:MM:SS`). R2 report timestamps are ISO 8601.
- Reports are stored in R2 at key `reports/<scan_id>.json`.
- Scan lifecycle: `POST /api/scan` creates the row at status `running`, writes a placeholder R2 report, then fires the engine asynchronously. The engine updates D1 and R2 when done.
- `cyber_metrics_score`, `risk_level`, `findings`, `recommendations`, and `modules` are all `0`/`"unknown"`/`[]`/`{}` in the placeholder report and are fully populated only when status is `completed`.
- No mock data — all findings are derived from live DNS, HTTP, and header responses at scan time.
- DKIM discovery probes 13 common selectors in parallel. A DKIM finding of "not detected" means none of the probed selectors returned a valid record; custom selectors are not exhausted.
