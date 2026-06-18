# CyberMeters AI Context

## Project Overview

CyberMeters is a Cloudflare-native Attack Surface Management (ASM) and Security Posture Monitoring platform.

Current stack:

- Cloudflare Workers
- Cloudflare D1
- Cloudflare R2
- Cloudflare Pages
- React + Vite frontend

Repository:

CyberMeters-Platform

Primary branch:

subdomain-takeover-engine-v1

---

## Current Architecture

Frontend:

frontend/
- Dashboard
- Scans
- Scan Detail
- Assets
- Reports (planned)
- Settings (planned)

Backend:

workers/scan-api/

Worker responsibilities:

- Scan orchestration
- Scoring
- Report generation
- D1 persistence
- R2 report storage
- Scheduled monitoring

---

## Current APIs

POST /api/scan

GET /api/scans

GET /api/scans/:id

GET /api/scans/:id/report

GET /api/domain/:domain/history

POST /api/schedules

GET /api/schedules

DELETE /api/schedules/:id

---

## Current Scan Modules

1. DNS
2. SSL
3. Security Headers
4. Email Security
   - SPF
   - DKIM
   - DMARC
5. Subdomain Discovery
   - crt.sh
6. Subdomain Takeover Detection
7. Asset Exposure
8. Historical Change Monitoring

---

## Current Report Schema

modules:

- dns
- ssl
- headers
- email_security
- subdomains
- subdomain_takeover
- asset_exposure
- historical_changes

findings:

Top-level findings array

score:

0-100

rating:

excellent
good
moderate
high
critical

---

## D1 Schema

Table: scans

- id
- domain
- status
- score
- rating
- created_at
- completed_at

Table: scheduled_scans

- id
- domain
- frequency
- enabled
- last_run_at
- next_run_at
- created_at

---

## R2 Structure

reports/

reports/{scan_id}.json

---

## Current Scoring

DNS findings

SSL findings

Header findings

Email findings

Sensitive subdomains:
-5 each
Cap: -20

Large attack surface:
-3

Takeover risk:
-15 high
-25 critical

Asset exposure:
-5
-10
Depending on exposure type

---

## Current Roadmap

Completed:

✅ DNS
✅ SSL
✅ Headers
✅ Email Security
✅ Subdomains
✅ Takeover Detection
✅ Asset Exposure
✅ Historical Monitoring
✅ Scheduled Scans v1
✅ Email Alerts v1

Next:

- TLS Intelligence v1
- Exposure Intelligence v2
- Authentication
- Monitoring Dashboard

---

## Known Constraints

- Cloudflare Worker runtime
- No Shodan
- No paid APIs
- No fake data
- No mock assets
- Graceful failure required
- Scan completion must continue even if modules fail

---

## AI Rules

Before changing code:

1. Read this file first.
2. Verify actual code before assumptions.
3. Never assume schema names.
4. Never replace wrangler.toml without reading it.
5. Prefer surgical diffs.
6. Preserve backward compatibility.
7. Run syntax validation before deployment.

If schema conflicts with code:

Code is source of truth.
Update this file afterwards.
