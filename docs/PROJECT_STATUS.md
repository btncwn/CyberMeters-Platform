# CyberMeters Project Status

## Current Phase

Scan Engine v1 + Asset Intelligence v1 + Subdomain Takeover Detection v1 + Asset Exposure Engine v1 + Historical Change Monitoring v1 + Scheduled Scans v1 + Email Alerts v1 complete. Platform is live on Cloudflare.

---

## Infrastructure

| Component | Status | Detail |
|---|---|---|
| Cloudflare Worker | ✅ Live | `api.cybermeters.com` |
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
| `POST /api/schedules` | ✅ Live | Create a scheduled scan (daily or weekly) |
| `GET /api/schedules` | ✅ Live | List all scheduled scans |
| `DELETE /api/schedules/:id` | ✅ Live | Delete a scheduled scan |

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
| Historical Change Monitoring | ✅ Live | Diffs current scan vs. previous scan for the same domain; exposes score delta, new/resolved findings, new subdomains, new takeover risks, new exposed assets |

Phase 1 (DNS, SSL, headers, email, subdomains) runs in parallel via `Promise.allSettled`. Phase 2 (takeover detection) uses Phase 1 subdomain output. Phase 3 (asset exposure) probes reachable subdomains. Phase 4 (historical diff) compares against the most recent prior completed scan. Individual module failures do not fail the scan.

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
| Scan Detail (`/scans/:id`) | ✅ Live | Score ring, findings, all module panels including historical changes diff |
| Assets (`/assets`) | ✅ Live | Subdomains from CT populated from latest completed scan |
| Schedules (`/schedules`) | ✅ Live | Create, view, and delete scheduled scans |
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

## Scheduled Scans v1

- Cron trigger fires at the top of every hour (`0 * * * *` in `wrangler.toml`)
- D1 table `scheduled_scans`: `id`, `domain`, `frequency` (`daily`|`weekly`), `enabled`, `last_run_at`, `next_run_at`, `created_at`
- `POST /api/schedules` is self-bootstrapping — creates the table if it doesn't exist yet
- Each triggered scan is identical to a manual `POST /api/scan` (same engine, same report format)
- `next_run_at` is computed as `+24h` (daily) or `+7d` (weekly) from the moment the scan starts

---

## Email Alerts v1

- Fires automatically after each scheduled scan when security-relevant changes are detected
- Reads `modules.historical_changes` from the completed R2 report
- Alert conditions: score drop ≥ 10 pts, new takeover risk, new exposed asset, new high/critical finding
- No alert on first scan for a domain (`has_previous: false`)
- Delivered via Resend API (`fetch` POST, no npm package)
- `RESEND_API_KEY` stored as a Wrangler secret (never committed); `ALERT_EMAIL_TO` and `ALERT_EMAIL_FROM` in `wrangler.toml [vars]`
- Email delivery errors are swallowed — alert failure never surfaces to the user or breaks the scan pipeline

---

## Not Started

| Feature | Priority |
|---|---|
| Authentication | High |
| Multi-tenant accounts | High |
| PDF report export | Medium |
| TLS Intelligence v1 (cert detail, expiry alerts) | Medium |
| Exposure Intelligence v2 (port scan, service fingerprint) | Medium |
| CISA KEV correlation | Medium |
| Monitoring Dashboard | Medium |
| Billing | Low |
| Custom domain | Low |
