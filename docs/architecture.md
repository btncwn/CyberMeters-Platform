# CyberMeters Platform Architecture

## Vision

CyberMeters is a cloud-native Cyber MOT and Attack Surface Management platform designed for small and medium-sized businesses.

The platform continuously discovers internet-facing assets, identifies security weaknesses, prioritizes remediation, and provides executive-level cyber risk reporting.

---

## Core Platform Components

### Frontend

Cloudflare Pages

Responsibilities:

- Landing page
- Dashboard
- Historical reports
- Executive reports
- Domain management

---

### API Layer

Cloudflare Workers

Responsibilities:

- Scan submission
- Report retrieval
- Historical queries
- Scheduled scans

---

### Storage Layer

Cloudflare D1

Stores:

- Users
- Domains
- Scans
- Findings
- Hidden Assets
- KEV Intelligence
- Remediation Plans

---

### Report Storage

Cloudflare R2

Stores:

- PDF Reports
- JSON Reports
- Historical Snapshots

---

### Intelligence Engine

Attack-Surface-Discovery-Toolkit

Capabilities:

- DNS Analysis
- SSL Analysis
- Security Headers
- Subdomain Discovery
- Certificate Transparency Intelligence
- Hidden Asset Discovery
- CVE Correlation
- CISA KEV Intelligence
- Executive Intelligence
- Remediation Prioritization

---

## High-Level Flow

User
↓
Cloudflare Pages
↓
Cloudflare Workers
↓
CyberMeters Engine
↓
D1 + R2
↓
Dashboard & Reports

