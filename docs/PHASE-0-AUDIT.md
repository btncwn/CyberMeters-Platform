# Phase 0 — Public-readiness audit (2026-07-08)

> Goal: before building growth features, establish what ALREADY exists so Codex
> doesn't rebuild it. Verified against the actual code + live production.
> **Headline: the growth infrastructure is ~80% already built.** The roadmap is
> reposition + fill two real gaps, not greenfield.

## What already exists (evidence)

| Capability | Status | Evidence |
|---|---|---|
| **Cyber MOT hook** (public passive scan) | **LIVE** | `POST /api/free-scan` (no auth), `FreeScanPage.jsx`, route `/free-scan`. Live test on blackbullbarbers.co.uk → score 95, 4 modules scanned (DNS+TLS+headers+email), `preview_findings` + `hidden_count` (sign-up conversion mechanic) + severity breakdown. |
| Passive coverage | Built | free-scan runs DNS + SSL/TLS + HTTP headers + email (SPF/DMARC/DKIM) via `Promise.allSettled` → `computeScore` → AI-explainer mapping. This IS "Website Security + Email Security" passive. |
| Public marketing surface | Built | `PublicLandingPage` (`/`), `PricingPage` (`/pricing`), `AcademyPage` + `AcademyArticlePage` (content/SEO), `AccuracyPage`. |
| Self-serve funnel backend | Built | `POST /api/auth/signup`, `GET /api/auth/verify-email`, `POST /api/billing/checkout` → Stripe `checkout_url`; `CheckoutSuccessPage`/`CheckoutCancelPage`. Billing lifecycle + webhook proven in the pipeline suite. |
| Cyber Essentials scoring | Partial | `cyberEssentialsGrade/Status/Category`, `GET /api/workspaces/:id/cyber-essentials-readiness` — measured side exists. |
| 4 core services | Built | Email / Brand / Attack Surface / Certificates — all have routes + pages. |
| Domain ownership verification | Built | `generateDomainVerification` / `verifyDomain` / DNS TXT — the ownership gate is already there (paying customers pass it). |

## The real gaps (the work-list)

1. **Reposition free-scan → "Cyber MOT"** (naming/copy/report polish). No new engine — rename, brand, present. Add robots.txt / security.txt to the passive set if not already covered. — *ChatGPT copy + Codex frontend.*
2. **Cyber Essentials Readiness — questionnaire hybrid** (the one real net-new build). Measured side exists; add: (a) guided self-attestation questionnaire mirroring the current IASME control set for the *internal* controls we can't observe; (b) merge logic where **measured signal overrides optimistic self-attestation** (claim "secure config ✔" but we observe an exposed admin panel → flagged gap); (c) readiness output = per-control traffic-light + gap list + "close these before applying." NOT certification. — *Claude backend + Codex UI.*
3. **Funnel hardening** — verify signup→verify→add-domain→pick-plan→pay end-to-end on a fresh public account; wire the domain-based tiers (Free/Starter ~£29·1 / Pro ~£79·5 / Business ~£199·20 / MSP ~£399·20-100+) into Stripe; enforce domain caps server-side. — *Turhan (Stripe products/prices) + Claude (cap enforcement) + Codex (pricing UI).*
4. **Public-ready polish** across the 4 services (empty states, onboarding copy, "Attack Surface"/"Certificates" plain-language for SMB). — *Codex + ChatGPT.*
5. **DMARC gate** — first real inbound report not yet landed (0 as of 2026-07-08 22:00 UTC); passive watch, non-blocking. First realistic window ~09 Jul morning.

## Immediate sequence

- **Claude (now → next):** this audit (done); then build the CE Readiness questionnaire hybrid (schema + question set + merge/contradiction logic + endpoint). Medium risk (new migration) → build + validate + commit; manual deploy stays gated on Turhan.
- **Codex (routed by Claude):** from spec — Cyber MOT reposition UI + pricing/funnel UI. Claude reviews + integrates every merge (two AI coders, one integration owner — divergence discipline from Sprints 4/9).
- **ChatGPT:** Cyber MOT + landing copy (English/UK), Academy/SEO articles, CE guidance text, grant-application drafts.
- **Turhan:** Stripe products/prices for the tiers, MSP design-partner outreach, medium/high-risk deploy approvals.

## Why this matters

The £100k plan is de-risked: the acquisition hook is already live and the funnel
already exists. The bottleneck was never engineering — it is distribution
(getting the hook in front of UK SMBs/MSPs) + the one net-new feature (CE
questionnaire) that turns a UK-compliance need into a paid reason to stay.
