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
    "email_security": { "spf": { "present": true }, "dmarc": { "present": true, "policy": "quarantine" }, "dkim": { "present": false, "selector": null } },
    "subdomains": {
      "count": 12,
      "items": ["www.example.com", "mail.example.com", "dev.example.com", "staging.example.com"],
      "sensitive": ["dev.example.com", "staging.example.com"],
      "source": "certificate_transparency"
    }
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
| `modules` | object | Raw output from each of the 5 scan modules |
| `started_at` | string | ISO 8601 — when the engine started |
| `completed_at` | string | ISO 8601 — when the engine finished (only on `completed`) |
| `failed_at` | string | ISO 8601 — when the engine failed (only on `failed`) |

**Scan engine modules**

| Module | What it checks |
|---|---|
| `dns` | A/AAAA resolution, MX records, IPv6, nameservers |
| `ssl` | HTTPS availability, HTTP→HTTPS redirect |
| `headers` | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| `email_security` | SPF TXT record, DMARC policy, DKIM (13 common selectors probed) |
| `subdomains` | Certificate Transparency lookup via crt.sh; sensitive-name classification |
| `subdomain_takeover` | CNAME-based takeover detection against 4 known vulnerable hosting providers |
| `asset_exposure` | HTTP/HTTPS reachability probe of up to 50 subdomains; collects status, title, server, tech stack |

**`modules.subdomains` shape**

| Field | Type | Description |
|---|---|---|
| `count` | number | Total unique subdomains discovered |
| `items` | string[] | All discovered hostnames, alphabetically sorted, capped at 200 |
| `sensitive` | string[] | Subset of `items` whose labels match dev/staging/admin/backup patterns |
| `source` | string | Always `"certificate_transparency"` in v1 |
| `error` | string? | Present only when the CT lookup failed; scan still completes |

**`modules.subdomain_takeover` shape**

| Field | Type | Description |
|---|---|---|
| `checked` | number | Number of subdomains checked for takeover (capped at 100) |
| `potential_risks` | number | Subdomains whose CNAME matched a known vulnerable provider (pre-confirmation) |
| `risks` | object[] | Confirmed takeover risks (CNAME match + body fingerprint confirmed) |
| `error` | string? | Present only if the module itself errored; scan still completes |

Each entry in `risks`:

| Field | Type | Description |
|---|---|---|
| `host` | string | The vulnerable subdomain |
| `service` | string | Provider name (e.g. `"GitHub Pages"`, `"Heroku"`) |
| `cname` | string | The dangling CNAME target |
| `evidence` | string | Body text fragment that confirmed the takeover |
| `severity` | string | Always `"high"` |

**`modules.asset_exposure` shape**

| Field | Type | Description |
|---|---|---|
| `checked` | number | Subdomains probed (capped at 50) |
| `reachable` | number | Subdomains that returned any HTTP status < 500 |
| `assets` | object[] | One entry per checked subdomain |
| `source` | string | Always `"http_probe"` in v1 |
| `error` | string\|null | Module-level error; null on success |

Each entry in `assets`:

| Field | Type | Description |
|---|---|---|
| `host` | string | Subdomain hostname |
| `url` | string | Final URL after redirects |
| `status` | number\|null | HTTP status code; null if unreachable |
| `reachable` | boolean | `true` when status < 500 and not null |
| `title` | string\|null | `<title>` tag content from HTML response |
| `server` | string\|null | Value of the `Server` response header |
| `content_type` | string\|null | MIME type from `Content-Type` header |
| `tech` | string[] | Tech stack hints derived from headers and body |

**Asset exposure tech detection (v1)**

Tech hints are derived from response headers (`Server`, `X-Powered-By`, `CF-Ray`, etc.) and the first 8 KB of HTML body. Detected technologies include: Nginx, Apache, Cloudflare, IIS, LiteSpeed, Caddy, OpenResty, PHP, ASP.NET, Express, Next.js, WordPress, React, Angular, Vue.js, jQuery, Bootstrap, Drupal, Joomla, Laravel, Django, Shopify.

**Takeover fingerprints (v1)**

| Service | CNAME suffix | Body fingerprint |
|---|---|---|
| GitHub Pages | `github.io` | `There isn't a GitHub Pages site here.` |
| Heroku | `herokuapp.com` | `No such app` |
| Azure | `azurewebsites.net` | `404 Web Site not found` |
| Netlify | `netlify.app` | `Not Found` |

**Sensitive subdomain label patterns (v1)**

Labels matched against each dot-separated part of the subdomain: `dev`, `development`, `staging`, `stage`, `stg`, `test`, `testing`, `qa`, `uat`, `sandbox`, `alpha`, `beta`, `preprod`, `demo`, `admin`, `administrator`, `cp`, `cpanel`, `webmin`, `plesk`, `backup`, `bak`, `old`, `legacy`, `archive`, `temp`, `internal`, `intranet`, `vpn`, `ssh`, `ftp`, `db`, `jenkins`, `ci`, `jira`, `wiki` — plus numeric variants (`dev1`, `test2`, `stage-eu`, etc.).

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
| Sensitive subdomain discovered | −5 each (max 4 findings, −20 cap) |
| >20 subdomains (large attack surface) | −3 |
| Subdomain takeover risk (1 subdomain) | −15 |
| Subdomain takeover risks (2+ subdomains) | −25 (single finding, max cap) |
| Management tool exposed (Jenkins, Grafana, Kibana, etc.) — status 200 | −10 |
| Admin/login/dashboard interface exposed — status 200 | −8 |
| Dev/staging/test environment exposed — status 200 | −5 |
| Asset returning 401 or 403 | 0 (informational only) |

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
- No mock data — all findings are derived from live DNS, HTTP, header, and Certificate Transparency responses at scan time.
- DKIM discovery probes 13 common selectors in parallel. A DKIM finding of "not detected" means none of the probed selectors returned a valid record; custom selectors are not exhausted.
- Subdomain discovery uses Certificate Transparency logs only (crt.sh). Results are capped at 200 unique hostnames. If crt.sh is unreachable or times out (25 s), `modules.subdomains` returns `count: 0` with an `error` field and the rest of the scan completes normally. No paid APIs or Shodan are used.
- The first five scan modules run in parallel via `Promise.allSettled`. The takeover module (`subdomain_takeover`) runs in a second phase using the discovered subdomains as input. A failure in any module does not prevent the others from completing.
- Asset exposure probing checks up to 50 subdomains. Each probe prefers HTTPS; falls back to HTTP only if HTTPS is unreachable. A per-request timeout of 8 s is applied. 401 and 403 responses are included in reachable counts but generate no score deductions — they indicate an access-controlled surface, not a misconfiguration.
- Takeover detection checks up to 100 subdomains. For each, it looks up the CNAME record via DoH. If the CNAME target matches a known vulnerable provider, it fetches the URL and checks the response body for the provider's "unclaimed resource" fingerprint text. Both checks must pass for a risk to be reported.
