# CyberMeters Project Status

## Current Phase

Scan Engine v1 + Asset Intelligence v1 + Subdomain Takeover Detection v1 + Asset Exposure Engine v1 complete. Platform is live on Cloudflare.

---

## Infrastructure

| Component | Status | Detail |
|---|---|---|
| Cloudflare Worker | ✅ Live | `cybermeters-platform.ttrnn47.workers.dev` |
| Cloudflare D1 | ✅ Connected | `cybermeters-db` |
| Cloudflare R2 | ✅ Connected | `cybermeters-reports` |
| Cloudflare Pages | ✅ Live | Frontend deployed |
| CORS | ✅ Enabled | All origins, preflight handled |

---

## Backend APIs

| Route | Status | Notes |
|---|---|---|
| `POST /api/scan` | ✅ Live | Triggers async scan engine via `ctx.waitUntil` |
| `GET /api/scans` | ✅ Live | Returns 20 most recent scans with score + rating |
| `GET /api/scans/:id` | ✅ Live | Returns scan metadata |
| `GET /api/scans/:id/report` | ✅ Live | Returns full structured report from R2 |
| `GET /api/domain/:domain/history` | ✅ Live | Returns all scans for a domain |

---

## Scan Engine Modules

| Module | Status | What it does |
|---|---|---|
| DNS Analysis | ✅ Live | A/AAAA/MX/NS records via Cloudflare DoH |
| SSL Detection | ✅ Live | HTTPS availability + HTTP→HTTPS redirect |
| Security Headers | ✅ Live | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| Email Security | ✅ Live | SPF, DMARC (policy), DKIM (13 selectors) |
| Subdomain Discovery | ✅ Live | Certificate Transparency via crt.sh; sensitive-name classification |
| Subdomain Takeover Detection | ✅ Live | CNAME check + body fingerprint against 4 providers (GitHub Pages, Heroku, Azure, Netlify) |
| Asset Exposure Engine | ✅ Live | HTTP/HTTPS probe of up to 50 subdomains; collects status, title, server, tech stack |

The first 5 modules run in parallel via `Promise.allSettled`. The takeover module runs in a second phase, using discovered subdomains as input. Individual module failures do not fail the scan.

---

## Cyber Metrics Score

- Starts at 100, deductions applied per finding
- Risk levels: Excellent (90–100), Good (75–89), Moderate (50–74), High (25–49), Critical (0–24)
- Score and rating written to D1 on completion; full report written to R2
- Subdomain scoring: −5 per sensitive subdomain (cap −20); −3 for >20 subdomains
- Takeover scoring: −15 for 1 confirmed risk; −25 (single finding) for 2+ risks
- Exposure scoring: −10 management tool exposed (status 200); −8 admin/login interface; −5 dev/staging env; 401/403 informational only

---

## Frontend Pages

| Page | Status | Notes |
|---|---|---|
| Dashboard (`/dashboard`) | ✅ Live | Real score, findings, health from report API |
| Scans (`/scans`) | ✅ Live | Full scan list with status + score |
| Scan Detail (`/scans/:id`) | ✅ Live | Score ring, findings, all 5 module panels |
| Assets (`/assets`) | ✅ Live | Subdomains from CT populated from latest completed scan |
| Reports (`/reports`) | 🔲 Stub | Coming soon |
| Settings (`/settings`) | 🔲 Stub | Coming soon |
| New Scan (`/scans/new`) | ✅ Live | Domain submission form |
| Domain History | ✅ Live | Per-domain scan history |

---

## Asset Intelligence v1

- Subdomains discovered via Certificate Transparency (crt.sh), capped at 200 per scan
- Sensitive subdomain detection: dev, staging, admin, backup, and 40+ label patterns
- Assets page reads `modules.subdomains` from the latest completed scan's report
- `AssetSummary`, `AssetInventory`, `AssetEmptyState` components wired to real data
- Source attribution shown in UI (domain, scan date, link to full scan report)

---

## Not Started

| Feature | Priority |
|---|---|
| Authentication | High |
| Multi-tenant accounts | High |
| Scheduled / recurring scans | Medium |
| PDF report export | Medium |
| Email notifications | Medium |
| Exposed services module (port scan) | Medium |
| TLS certificate detail module | Medium |
| CISA KEV correlation | Medium |
| Billing | Low |
| Custom domain | Low |
