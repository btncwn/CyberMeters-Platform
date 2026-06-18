# CyberMeters API Reference

Base URL:

https://cybermeters-platform.ttrnn47.workers.dev

## Health Check

GET /health

## Submit Scan

POST /api/scan

Request:

{
  "domain": "example.com"
}

Response:

{
  "status": "queued",
  "scan_id": "...",
  "domain_id": "...",
  "domain": "example.com",
  "report_key": "reports/scan_x.json",
  "message": "Scan request stored in D1 and initial report stored in R2"
}

## List Scans

GET /api/scans

## Scan Detail

GET /api/scans/:id

## Domain History

GET /api/domain/:domain/history

---

## Workspaces

Base URL: `https://cybermeters-platform.ttrnn47.workers.dev`

### List Workspaces

```
GET /api/workspaces
```

Response:
```json
{
  "workspaces": [
    { "id": "workspace_<uuid>", "name": "Turhan Workspace", "created_at": "2026-06-18T10:00:00.000Z" }
  ]
}
```

```bash
curl https://cybermeters-platform.ttrnn47.workers.dev/api/workspaces
```

---

### Create Workspace

```
POST /api/workspaces
```

Request:
```json
{ "name": "Turhan Workspace" }
```

Response — 201 Created:
```json
{
  "workspace": {
    "id": "workspace_<uuid>",
    "name": "Turhan Workspace",
    "created_at": "2026-06-18T10:00:00.000Z"
  }
}
```

Errors: `400` if `name` is missing or empty.

```bash
curl -X POST https://cybermeters-platform.ttrnn47.workers.dev/api/workspaces \
  -H "Content-Type: application/json" \
  -d '{"name": "Turhan Workspace"}'
```

---

### Get Workspace Domains

```
GET /api/workspaces/:id/domains
```

Returns all domains linked to the workspace, joined with the latest scan data for each domain.

Response:
```json
{
  "workspace_id": "workspace_<uuid>",
  "domains": [
    {
      "domain_id": "domain_<uuid>",
      "domain": "example.com",
      "last_scan_id": "scan_<uuid>",
      "latest_score": 74,
      "latest_status": "completed",
      "last_scanned_at": "2026-06-18 10:00:00"
    }
  ]
}
```

`last_scan_id`, `latest_score`, `latest_status`, and `last_scanned_at` are `null` for domains that have never been scanned.

Errors: `404` if workspace not found.

```bash
curl https://cybermeters-platform.ttrnn47.workers.dev/api/workspaces/workspace_<uuid>/domains
```

---

### Add Domain to Workspace

```
POST /api/workspaces/:id/domains
```

Request:
```json
{ "domain": "example.com" }
```

Behaviour:
- Domain is normalised to lowercase.
- If `example.com` already exists in the `domains` table, the existing row is reused.
- Otherwise, a new domain row is created.
- The domain is linked to the workspace via `workspace_domains`. Duplicate links are silently ignored.

Response — 201 Created:
```json
{
  "domain": {
    "domain_id": "domain_<uuid>",
    "domain": "example.com",
    "workspace_id": "workspace_<uuid>"
  }
}
```

Errors: `400` if `domain` is missing or invalid; `404` if workspace not found.

```bash
curl -X POST https://cybermeters-platform.ttrnn47.workers.dev/api/workspaces/workspace_<uuid>/domains \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

---

### Remove Domain from Workspace

```
DELETE /api/workspaces/:id/domains/:domainId
```

Removes the workspace↔domain link only. The domain row in the `domains` table is not deleted.

Response:
```json
{
  "success": true,
  "workspace_id": "workspace_<uuid>",
  "domain_id": "domain_<uuid>"
}
```

Errors: `404` if workspace not found or domain link not found.

```bash
curl -X DELETE https://cybermeters-platform.ttrnn47.workers.dev/api/workspaces/workspace_<uuid>/domains/domain_<uuid>
```

---

### Notes

- `workspaces` table: `id` (TEXT, PK), `name` (TEXT), `created_at` (DATETIME)
- `workspace_domains` table: `workspace_id` + `domain_id` composite PK; no cascade delete
- Domain reuse is matched by exact lowercase domain string against the `domains` table
- All workspace routes return `500` on unexpected database errors
