# AGENTS.md

# CyberMeters Platform — AI Engineering Context

Version: June 2026

---

# Project Overview

CyberMeters is a production-oriented:

* Attack Surface Management (ASM) Platform
* Security Posture Management (SPM) Platform
* Portfolio Monitoring Platform
* Executive Reporting Platform

CyberMeters is no longer a scanner project.

CyberMeters is currently in the Productization Phase.

Primary objective:

Convert the existing ASM platform into a commercially viable multi-tenant SaaS product.

---

# Current Strategic Status

| Area                 | Completion |
| -------------------- | ---------: |
| Core Scanner Engine  |        92% |
| ASM Engine           |        82% |
| Reporting Platform   |        90% |
| Historical Tracking  |        90% |
| Asset Inventory      |        90% |
| Portfolio Platform   |        85% |
| Product Platform     |        35% |
| Commercial Readiness |        50% |

---

# Current Priorities

Priority order:

1. Authentication
2. Domain Ownership Verification
3. Notifications
4. Dedicated Asset Inventory API
5. RBAC
6. Customer Portal
7. Billing
8. Team Management

New scanner development is not currently a priority.

---

# Repository Layout

CyberMeters-Platform/

frontend/
workers/scan-api/
database/schema.sql
docs/

---

# Commands

## Frontend

npm run dev
npm run build
npm run preview

## Worker

npm run dev
npm run deploy

Syntax check:

node --input-type=module --check < src/index.js

## Database

wrangler d1 execute cybermeters-db --remote --file=../../database/schema.sql

---

# Current Architecture

Frontend:

* React
* Vite
* Tailwind CSS

Backend:

* Cloudflare Workers

Storage:

* Cloudflare D1
* Cloudflare R2

Hosting:

* Cloudflare Pages

Architecture goal:

Remain fully Cloudflare-native.

Do not introduce:

* Express.js
* Traditional Node servers
* Dedicated VPS infrastructure

unless explicitly requested.

---

# Current Scan Modules

Implemented:

* DNS Analysis
* SSL Analysis
* Security Headers
* Email Security
* Subdomain Discovery
* Subdomain Takeover Detection
* Asset Exposure Detection
* Historical Tracking
* Executive Reporting

---

# Current Platform Modules

Implemented:

* Dashboard
* Portfolio Dashboard
* Workspace Dashboard
* Historical Monitoring
* Reports
* Workspace Reports
* Asset Events
* Scheduled Scans

---

# Known Architectural Notes

Assets Page currently consumes:

modules.subdomains

from report JSON.

There is no dedicated Asset Inventory API yet.

Future asset work should consider:

* Dedicated asset APIs
* Asset lifecycle tracking
* Portfolio-level asset intelligence

---

# Engineering Constitution

## Rule 1 — Never Rewrite Working Systems

If existing functionality works:

* Do not redesign it
* Do not replace it
* Extend it

---

## Rule 2 — Backward Compatibility Is Mandatory

Do not break:

* Existing scans
* Reports
* Portfolio APIs
* Frontend pages
* Scheduled scans

---

## Rule 3 — Reuse Before Creating

Before adding:

* Functions
* APIs
* Tables
* Components

Check whether similar functionality already exists.

Avoid duplicate logic.

---

## Rule 4 — Productization First

Prefer:

* Authentication
* Domain Verification
* Notifications
* RBAC
* Customer Portal
* Billing

over:

* New scanning engines

---

## Rule 5 — Historical Data Is Sacred

Never delete:

* Scans
* Findings
* Assets
* Reports
* Events

Prefer:

* archived
* inactive
* resolved

---

## Rule 6 — Multi-Tenant Design

Assume future support for:

* Multiple customers
* Multiple users
* Multiple workspaces
* MSP environments

Avoid single-user assumptions.

---

## Rule 7 — Security First

Every feature must consider:

* Authentication
* Authorization
* Data isolation
* Auditability
* Report access control

---

## Rule 8 — Cloudflare Native

All implementations must remain compatible with:

* Workers
* D1
* R2
* Pages

---

## Rule 9 — Database Safety

Schema changes require:

* Migration file
* Validation commands
* Rollback strategy

Never silently modify production tables.

---

## Rule 10 — No N+1 Queries

Use:

* JOIN
* GROUP BY
* Aggregation
* Batch processing

Avoid per-row queries.

---

## Rule 11 — Validation Required

Every sprint must include:

npm run build

wrangler deploy

curl validation commands

---

## Rule 12 — No Placeholder Implementations

Avoid:

* TODOs
* Fake logic
* Mock findings
* Hardcoded scores

---

## Rule 13 — Ownership Verification Is Strategic

Future onboarding must support:

* DNS TXT verification
* HTML verification
* Email verification

---

## Rule 14 — Portfolio-Level Thinking

Every feature should consider:

* Domain level
* Workspace level
* Customer level
* Portfolio level

---

## Rule 15 — Commercial Readiness

Choose implementations that improve:

* Beta readiness
* Customer onboarding
* Revenue generation
* Operational scalability

---

## Rule 16 — Duplicate Feature Detection

Before implementing:

Check:

* Existing APIs
* Existing pages
* Existing tables
* Existing modules

Never build duplicates.

---

## Rule 17 — Sprint Awareness

Before proposing work:

Review:

* Current branch
* Recent commits
* Latest completed sprint

Avoid re-proposing completed work.

---

## Rule 18 — Historical Tracking First

Prefer data that supports:

* first_seen
* last_seen
* created_at
* updated_at

Trendable data is preferred.

---

## Rule 19 — API Stability

Existing APIs are public contracts.

Do not:

* Rename fields
* Remove fields
* Change response structures

without versioning.

Prefer:

/api/v1/

for future evolution.

---

## Rule 20 — Mandatory Sprint Format

Every implementation response must contain:

Goal

Current State

Tasks

Validation

Expected Outcome

Suggested Commit

---

# Development Workflow

Before implementing any feature:

1. Review current architecture
2. Review existing APIs
3. Review database schema
4. Review active branch
5. Review latest commits
6. Review roadmap priority
7. Check for duplicate functionality

Only then propose implementation.

---

# Final Directive

CyberMeters is no longer in the Scanner Development Phase.

CyberMeters is in the Productization Phase.

When uncertain:

* Prefer stability over complexity
* Prefer reuse over rewrites
* Prefer productization over new scanners
* Prefer commercial value over technical novelty

Act as a Senior Software Engineer maintaining a production SaaS platform.
