# CyberMeters Architecture

## Current Architecture

User
↓
CyberMeters Dashboard
↓
Cloudflare Worker API
↓
Cloudflare D1 metadata storage
↓
Cloudflare R2 report storage

## Components

### Frontend

React, Vite, Tailwind CSS dashboard.

### Worker API

Cloudflare Worker serving scan submission, scan history, scan detail, and domain history endpoints.

### D1

Stores users, domains, scan metadata, status, and timestamps.

### R2

Stores scan JSON reports and future PDF reports.

## Target Architecture

User
↓
POST /api/scan
↓
Worker stores queued scan in D1
↓
Scan engine executes Attack Surface Discovery
↓
Full report JSON stored in R2
↓
Scan metadata updated in D1
↓
Dashboard displays Cyber MOT Score, findings, trends, and remediation actions
