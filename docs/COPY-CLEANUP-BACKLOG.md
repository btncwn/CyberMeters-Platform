# Copy Cleanup Backlog — "scan / attack surface" → Cyber MOT wording pass

> **Owner of wording decisions: ChatGPT** (positioning) → **Codex** builds → **Claude** reviews.
> This file is the *inventory / spec target* Claude compiled from the codebase so nothing
> gets missed — it does NOT prescribe final wording. Direction (from Turhan + GROWTH-ROADMAP):
> lead with **Cyber MOT / Website Security / passive posture / monitoring**; avoid framing the
> product around "external attack surface" or "scan" in customer-facing *positioning* copy.
> Not a trust/forbidden-term issue — "Attack Surface" is a real service name and "scan" is an
> approved action; this is positioning consistency. No urgent deploy.

## Nuance (do NOT blanket-replace)
- **KEEP "Attack Surface"** as one of the four service names (nav, service card, headings).
- **KEEP Academy "Attack Surface Management / ASM"** content — those are intentional SEO
  keywords people search for; softening would hurt discovery.
- **KEEP functional scan buttons/labels** where "scan" is the literal action the user takes
  (Run a new scan, New Scan, Scanning…). Changing these adds risk for little positioning gain.
- **Legal docs** (Terms/Privacy/DPA) describe the service as "ASM/SPM" — preserve legal meaning;
  soften only if ChatGPT confirms it stays accurate.

## SOFTEN — positioning copy (highest priority: first impressions)
| File:line | Current text |
|---|---|
| `frontend/src/pages/PricingPage.jsx:189` | "Start with external attack surface monitoring, then add executive reporting, vendor risk, and MSP-ready capabilities as you grow." |
| `workers/scan-api/src/lib/lifecycle-email.js:170` | "CyberMeters protects your email, brand, external attack surface and certificates from one workspace." |
| `workers/scan-api/src/lib/lifecycle-email.js:172` | "To get started, add a domain and run your first scan." (→ "run your first Cyber MOT") — *the welcome-email flag from the 2026-07-09 dogfood report* |
| `frontend/src/components/ServiceLauncher.jsx:121` | step "Run your first scan" / "Map your external attack surface and email posture." / actionLabel "Run scan" |
| `frontend/src/components/ServiceLauncher.jsx:142` | "…monitor email impersonation risk, brand abuse, external attack surface, and certificate trust — all from one workspace." |
| `frontend/src/pages/Dashboard.jsx:117` | "Run your first security scan" / "Add a domain to discover your external attack surface exposure." / cta "Start Scan" |
| `frontend/src/pages/WorkspacesPage.jsx:206` | "Security Scanning" / "Run on-demand or scheduled scans to continuously assess your external attack surface." |
| `frontend/src/pages/ScansPage.jsx:89` | "A scan runs CyberMeters' Intelligence Engines across your domain — Attack Surface, Business Email and …" |
| `frontend/src/pages/OnboardingPage.jsx:387,389,391,396` | step title "Run First Scan" + supporting copy |
| `frontend/src/components/FirstResultsGuide.jsx:56` | "…detected on your attack surface, each assessed for risk level." |

## JUDGMENT — functional labels (recommend KEEP unless ChatGPT decides otherwise)
`frontend/src/pages/ScanDetail.jsx:1456,1459` ("Run a new scan") · `DomainHistory.jsx:83`
("New Scan") · `AssetsPage.jsx:246` ("Run a scan to start tracking…") ·
`WorkspaceDetailPage.jsx:552` ("Scanning…") · `FreeScanPage.jsx` (state vars only, not copy).

## CAREFUL — legal (preserve meaning; low priority)
`frontend/src/pages/PrivacyPage.jsx:37` ("Attack Surface Management (ASM) platform, Security
Posture Management (SPM)…") · `frontend/src/pages/DpaPage.jsx:48` ("external attack surface
management, security posture monitoring…").

## KEEP — service name / SEO (no change)
`ServiceLauncher.jsx:26` "Attack Surface" service card · `Layout.jsx` / `WorkspaceNav.jsx` nav ·
`frontend/src/data/academy.js` "Attack Surface Management" articles (intentional SEO) ·
`frontend/src/data/remediation.js` technical remediation text (legit security wording).

---
Related: [GROWTH-ROADMAP.md](GROWTH-ROADMAP.md) customer-facing naming table; the forbidden-term
list (DAST / scanner / pen test / certification / guaranteed secure / fully verified) is a
*separate, stricter* rule already enforced — none of the above are forbidden terms.
