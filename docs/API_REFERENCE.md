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
