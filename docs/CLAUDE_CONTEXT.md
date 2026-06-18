# CyberMeters Platform Context

## Product

CyberMeters is a cloud-native Cyber MOT and Attack Surface Management (ASM) platform for SMBs.

## Core Capabilities

- Attack Surface Discovery
- Hidden Asset Intelligence
- CISA KEV Intelligence
- Historical Exposure Tracking
- Cyber MOT Scoring
- Executive Reporting

## Infrastructure

Cloudflare Worker:

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

## Current Status

### Completed

- Cloudflare Worker
- Cloudflare D1
- Cloudflare R2
- Scan Queue
- Scan Detail API
- Domain History API
- Dashboard v1

### In Progress

- Scan Engine Integration
- Cyber MOT Scoring

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

- Cyber MOT Score
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
