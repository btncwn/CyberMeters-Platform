# CyberMeters — Free Scan Audit v1

**Sprint 13 — Phase 1**
**Date:** June 2026
**Status:** Audit complete — implementation follows

---

## Clicks to First Value (Current State)

| Step | Action | Blocker? |
|------|--------|---------|
| 1 | Land on login page | — |
| 2 | Click "Create account" | — |
| 3 | Fill signup form (name, email, password) | — |
| 4 | Submit signup → wait for email | ✋ Email verification gate |
| 5 | Open email, click verify link | ✋ Requires valid email |
| 6 | Land on `/verify-email` page | — |
| 7 | Click "Login" → enter credentials | — |
| 8 | Navigate through onboarding (workspace auto-created) | — |
| 9 | Add domain | — |
| 10 | Trigger scan → wait 15–30s | — |
| 11 | **See first finding** | ✅ First value |

**Total: 11 steps, 2 hard blockers, ~5–10 minutes minimum.**

A motivated visitor who lands on the product has to wait for an email before seeing a single finding. Most will not.

---

## What Blocks Anonymous Users Today

**Hard blockers (technical):**

1. `POST /api/scan` calls `requireAuth()` — returns 401 immediately for unauthenticated requests. No public scan path exists.
2. `App.jsx` wraps all app routes inside `<ProtectedRoute>` which redirects to `/login` if no token exists. Anonymous users cannot reach the Dashboard, Scans, or any result page.
3. Email verification is enforced at login — even after signup, the user cannot proceed without clicking a verification email.

**Soft blockers (UX):**

4. No public landing page explains what CyberMeters scans or shows example output.
5. No pricing is visible before signup.
6. The onboarding page (workspace → domain → scan) adds 3 more steps after login.

---

## What Can Be Reused

**Worker (100% reusable without modification):**

| Asset | Reuse Plan |
|-------|-----------|
| `isValidDomain()` | Domain validation in free-scan endpoint |
| `runDnsModule(domain)` | Core free scan module |
| `runSslModule(domain)` | Core free scan module |
| `runHeadersModule(domain)` | Core free scan module |
| `runEmailModule(domain)` | Core free scan module |
| `computeScore(modules, domain)` | Score + findings from module results |
| `normalizeFindingSchema(finding)` | Finding normalisation |
| `consumeApiRateLimit(env, scopes, ...)` | IP-based rate limiting |
| `buildCorsHeaders(env)` | CORS headers on public endpoint |

**Frontend (reusable patterns):**

| Asset | Reuse Plan |
|-------|-----------|
| `getAcademyArticleForFinding()` | Resolve Academy slug for each preview finding |
| Severity colour classes from ScanDetail.jsx | Severity pills on preview findings |
| Score ring design pattern | Security score display |
| LoginPage/SignupPage routes | CTA targets with `?domain=` param |
| Brand colours + Tailwind config | Full design consistency |

---

## Free Scan Module Selection

Full scan modules and their suitability for anonymous free scan:

| Module | Time | Include? | Reason |
|--------|------|---------|--------|
| DNS | ~1s | ✅ Yes | Fast, high-value, always informative |
| SSL/TLS | ~2s | ✅ Yes | Certificate expiry is immediately actionable |
| Security Headers | ~1s | ✅ Yes | Fast, high signal-to-noise for SMBs |
| Email Security | ~2s | ✅ Yes | SPF/DMARC/DKIM is the most common gap |
| Subdomains | ~15s | ❌ No | Too slow, too resource-intensive for anonymous |
| DNS Brute-force | ~8s | ❌ No | Too slow for free scan |
| Subdomain Takeover | depends | ❌ No | Requires subdomain list |
| Cloud Storage | ~5s | ❌ No | Depends on subdomain results |
| Asset Exposure | ~10s | ❌ No | Depends on subdomain results |
| Technology Detection | ~3s | ❌ No | Low value for SMB free scan |
| WHOIS | ~3s | ❌ No | Nice to have, not critical for v1 |
| CVE/KEV | ~5s | ❌ No | Depends on tech detection |

**Free scan runs 4 modules in parallel. Estimated wall time: 4–6 seconds.**

The 4 selected modules cover the most common and actionable external security findings for an SMB. They are also the findings with the strongest Academy article coverage.

---

## Public Endpoint Design

```
POST /api/free-scan
No authentication required.
Body: { "domain": "example.com" }
Rate limit: 5 scans per IP per hour (IP-keyed via consumeApiRateLimit)

Response:
{
  "domain":           "example.com",
  "score":            65,
  "risk_level":       "medium",
  "severity_counts":  { "critical": 0, "high": 2, "medium": 3, "low": 1, "info": 0 },
  "total_findings":   6,
  "preview_findings": [ ...top 5, sorted by severity, limited fields ],
  "hidden_count":     1,
  "scanned_at":       "2026-06-22T..."
}
```

Each preview finding contains: `id`, `title`, `severity`, `description`, `academy_slug`.
Does NOT contain: `evidence`, `remediation`, `confidence`.

---

## Frontend Page Design

Route: `/free-scan` — **public, no auth required, outside Layout shell.**

Sections:
1. **Hero** — headline + domain input form + "Scan Domain" button
2. **Loading state** — progress indicator with friendly messages
3. **Score card** — numeric score, risk level badge, severity breakdown
4. **Preview findings** — top 5 findings, each with Academy "Learn More" link
5. **Gated panels** — blurred/locked sections for remediation, history, monitoring, PDF
6. **CTA strip** — primary + secondary conversion buttons

---

## Conversion Funnel

```
Visitor lands on /free-scan
         ↓
Enters domain → clicks Scan
         ↓
Sees real score for their domain (4–6s)
         ↓
Reads top 5 findings with Academy links
         ↓
Sees locked panels: "Full remediation steps • Historical tracking • Monitoring alerts • PDF report"
         ↓
Primary CTA: "Start Monitoring This Domain →" → /signup?domain=example.com
Secondary CTA: "Create free account" → /signup
         ↓
After signup + verify: onboarding drops them into workspace with domain pre-populated
```

---

## What Is NOT Changed

- Scanner modules (DNS, SSL, headers, email) — called read-only, no modification
- Scoring logic (`computeScore`) — called as-is, no modification
- Trust layer — not exposed in free scan preview (intentionally gated)
- Academy content — linked read-only via `getAcademyArticleForFinding()`
- Remediation Intelligence — not exposed (gated conversion asset)
- Billing — untouched
- Existing authenticated scan flow — untouched
- All existing routes — untouched

---

## Version History

| Version | Date | Notes |
|---------|------|-------|
| v1 | June 2026 | Initial audit — 11 clicks to first value, 4-module free scan design |
