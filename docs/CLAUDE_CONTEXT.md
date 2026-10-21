# CyberMeters Platform Context

## Product

CyberMeters is a cloud-native external security check and Attack Surface Management (ASM) platform for SMBs.

## Core Capabilities

- Attack Surface Discovery
- Hidden Asset Intelligence
- CISA KEV Intelligence
- Historical Exposure Tracking
- external security check Scoring
- Executive Reporting

## Infrastructure

Cloudflare Worker (canonical API host):

https://api.cybermeters.com

Same Worker, direct workers.dev origin — rollback path and hostname-fault isolation
only, never the documented base:

https://cybermeters-platform.ttrnn47.workers.dev

Cloudflare D1:

cybermeters-db

Cloudflare R2:

cybermeters-reports

## Implemented APIs

- POST /api/scan
- GET /api/scans
- GET /api/scans/:id
- GET /api/domain/:domain/history
- GET /api/workspaces
- POST /api/workspaces
- GET /api/workspaces/:id/domains
- POST /api/workspaces/:id/domains
- DELETE /api/workspaces/:id/domains/:domainId

## D1 Schema

Core tables: users, domains, scans, findings, hidden_assets, kev_matches, remediation_items, reports

Workspace tables (migration 003-workspaces.sql):
- workspaces: id (TEXT PK), name (TEXT), created_at (DATETIME)
- workspace_domains: workspace_id + domain_id composite PK; no cascade delete

## Current Status

### Completed

- Cloudflare Worker
- Cloudflare D1
- Cloudflare R2
- Scan Queue
- Scan Detail API
- Domain History API
- Dashboard v1
- Workspace schema v1 (workspaces + workspace_domains tables)
- Workspace API v1 (5 routes — CRUD for workspaces and domain links)

### In Progress

- Scan Engine Integration
- external security check Scoring

### Not Started

- Authentication
- Billing
- Multi-Tenant Support

## Dashboard Design

Visual style:

- ESET
- Kaspersky
- Apple

Do NOT use:

- Dark themes
- Admin templates
- Developer dashboards

Focus on:

- external security check Score
- Risk Posture
- Exposure Tracking
- Executive Reporting

## Development Rules

- Use real APIs only.
- No mock data.
- No fake findings.
- No hardcoded scores.
- Use Cloudflare services where possible.
- Prioritize attack surface intelligence features.
