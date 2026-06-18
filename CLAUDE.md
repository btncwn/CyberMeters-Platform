# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Layout

```
CyberMeters-Platform/
├── frontend/                  # React SPA (Vite + Tailwind)
├── workers/scan-api/          # Cloudflare Worker (single file: src/index.js)
├── database/schema.sql        # D1 SQLite schema (source of truth)
└── docs/                      # API_REFERENCE.md, PROJECT_STATUS.md, ARCHITECTURE.md
```

## Commands

### Frontend (`frontend/`)
```bash
npm run dev      # Vite dev server on 0.0.0.0 (connects to live Worker API)
npm run build    # Production build → dist/
npm run preview  # Serve dist/ locally
```

### Worker (`workers/scan-api/`)
```bash
npm run dev      # wrangler dev — local Worker with real D1/R2 bindings
npm run deploy   # wrangler deploy — push to production

# Syntax check before deploying (no test suite exists):
node --input-type=module --check < src/index.js
```

### Database
```bash
# Apply schema to remote D1
wrangler d1 execute cybermeters-db --remote --file=../../database/schema.sql
# Query remote D1
wrangler d1 execute cybermeters-db --remote --command="SELECT * FROM scans ORDER BY created_at DESC LIMIT 5"
```

## Architecture

### Data Flow

```
POST /api/scan
  → D1: insert scan row (status=running)
  → R2: write placeholder report JSON
  → return 202 immediately
  → ctx.waitUntil(runScanEngine(...))   ← async, after response

runScanEngine
  → Promise.allSettled([dns, ssl, headers, email, subdomains])  ← all parallel
  → computeScore(modules, domain)
  → R2: overwrite report with completed JSON
  → D1: UPDATE scans SET status='completed', score=?, rating=?
  → D1: INSERT findings + remediation_items rows
```

### Worker (`workers/scan-api/src/index.js`)

Single-file Worker. Key sections in order:
1. **Utilities** — `createId()`, `isValidDomain()`, `dnsQuery()` (DoH via `cloudflare-dns.com/dns-query`), `safeFetch()`
2. **Config constants** — `SECURITY_HEADERS[]`, `DKIM_SELECTORS[]`, `SENSITIVE_LABELS` Set
3. **Scan modules** — `runDnsModule`, `runSslModule`, `runHeadersModule`, `runEmailModule`, `runSubdomainsModule`
4. **`computeScore(modules, domain)`** — mutates a score starting at 100; each finding calls the inner `finding(f)` helper which deducts `f.score_impact`
5. **`runScanEngine(scanId, domainId, domain, env)`** — orchestrator, called via `ctx.waitUntil()`
6. **CORS** — `corsHeaders` constant + `json(data, status)` helper wrapping `Response.json`
7. **`export default { fetch(request, env, ctx) }`** — route dispatcher; OPTIONS → 404 in order

**Route ordering matters:** `/api/scans/:id/report` regex must be tested *before* `/api/scans/:id` `startsWith` check.

Worker bindings (from `wrangler.toml`):
- `env.cybermeters_db` → D1 database `cybermeters-db`
- `env.cybermeters_reports` → R2 bucket `cybermeters-reports`

R2 key convention: `reports/{scan_id}.json`

### Frontend

**API layer** (`src/api.js`): single `request()` wrapper; base URL from `VITE_API_BASE_URL` env var (falls back to live Worker URL). All pages import `{ api }`.

**Page → data pattern** (consistent across all pages):
```js
const load = useCallback(async (silent = false) => { ... }, [deps])
useEffect(() => { load() }, [load])
```
Silent refreshes (`load(true)`) set `refreshing` instead of `loading` to avoid full re-renders.

**ScanDetail polling**: `setInterval` via `useRef` polls every 4 s while `scan.status` is in `{queued, running, processing}`; clears on completion and triggers `loadReport()`.

**Dashboard score**: reads `scan.score` and `scan.rating` directly from the `GET /api/scans` list (D1 columns), then fetches the full report for the latest completed scan to populate findings and health indicators.

**AssetsPage**: reads `modules.subdomains` from `GET /api/scans/:id/report` for the latest completed scan. No dedicated assets API yet.

### Design System

Tailwind-based; custom utilities in `src/index.css`:
- `.card` / `.card-md` — white rounded cards with shadow
- `.btn-primary` / `.btn-secondary` / `.btn-ghost`
- `.badge-critical` / `.badge-high` / `.badge-medium` / `.badge-low`
- `.label` — tiny uppercase tracking label
- `.mono` — monospace font class
- `.input` — styled form input
- `.data-table` — styled `<table>` with `th`/`td` classes

Brand color: `brand-600` = `#00876A` (green). No dark theme — white/light backgrounds only.

SPA routing: `public/_redirects` contains `/* /index.html 200` for Cloudflare Pages.

### D1 Schema Key Points

- `scans.score INTEGER` and `scans.rating TEXT` — written by the scan engine on completion; read by `GET /api/scans` list and `GET /api/scans/:id`
- `findings.recommendation` stores the finding *description* (not a separate recommendations table)
- `remediation_items.action` stores the recommendation description; `.reason` stores the module name
- `reports` table exists in schema but is unused — R2 is the source of truth for report JSON

## Cloudflare Worker Constraints

- No raw DNS sockets → use DoH: `https://cloudflare-dns.com/dns-query?name=X&type=Y` with `Accept: application/dns-json`
- No npm packages at runtime → all logic is in `src/index.js` (no bundler for the Worker)
- CPU time limit (free plan: 10 ms excluding I/O) → `ctx.waitUntil()` for all heavy work post-response
- `AbortSignal.timeout(ms)` is available for per-fetch timeouts
- All modules use `Promise.allSettled` so one failure never aborts others

## Development Rules (from `docs/CLAUDE_CONTEXT.md`)

- No mock data, no fake findings, no hardcoded scores
- Use real API responses only; all scan findings derive from live external checks
- Keep architecture Cloudflare-native (Worker + D1 + R2 + Pages)
- Prioritise attack surface intelligence features
