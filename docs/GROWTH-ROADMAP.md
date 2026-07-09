# CyberMeters — Growth Roadmap (private beta → public beta → revenue)

> Owner: Turhan. Thesis: the **UK Cyber MOT** — a self-serve, affordable cyber
> posture platform for UK SMBs and the MSPs who serve them. Two free hooks pull
> people in; the paid membership is the four core services. Positioned like
> Red Sift + Hardenize combined, but **passive, self-serve, and far cheaper** —
> make them irrelevant to the UK SMB, don't out-feature them.
> Targets: **£100k Y1 · £150k Y2 · £200k Y3** (bootstrap, high-margin on Cloudflare).
> Date: 2026-07-08.

## Customer-facing naming (never say "DAST" / "scanner" / "vulnerability testing")

| Internal | Customer-facing name | Notes |
|---|---|---|
| Passive web-posture ("DAST") | **Website Security** | Plain English; lives inside the Cyber MOT + as a paid service signal. Best-in-class *passive* (Hardenize/SSL-Labs lineage), never active. |
| Free instant scan (umbrella hook #1) | **Cyber MOT** | "The 2-minute security MOT for your business." Any domain, no signup. Surfaces Email Security + Website Security + TLS/DNS, passive. |
| Free hook #2 | **Cyber Essentials Readiness** | Measured-evidence + guided-questionnaire hybrid. Readiness/gap, NOT certification. |
| Paid core services | Email Protection · Brand Protection · Attack Surface · Certificates & Trust | Existing names; may plain-language "Attack Surface"/"Certificates" for SMB later. |

## The offering map

- **2 free hooks (lead-gen):** Cyber MOT (instant passive scan) + Cyber Essentials Readiness.
- **4 paid core services (the membership):** Email / Brand / Attack Surface / Certificates.

### Cyber Essentials — TWO separate surfaces (IA decision, do not merge)

| | Public free hook | Paid in-app service |
|---|---|---|
| Route | `/cyber-essentials-readiness` (no login) | `ws/cyber-essentials` (authenticated) |
| Name | **Cyber Essentials Readiness Preview** | **Cyber Essentials Readiness Dashboard** |
| Purpose | lead-gen / convince | real service / retain |
| Data | local/temporary, lightweight preview | saved answers + workspace + Cyber MOT evidence via the authenticated `/cyber-essentials/answers` + readiness `self_assessment` |
| CTA | Create free account · Run Cyber MOT | Save · review · fix |

CTA routing: dashboard/account → `ws/cyber-essentials`; marketing/public → `/cyber-essentials-readiness`; Cyber MOT → `/free-scan`. No surface uses "certification" or implies CyberMeters certifies.
- **2 private validation domains:** cybermeters.com + blackbullbarbers.co.uk (dogfood everything here before public).
- **Pricing (DECIDED 2026-07-09 — competitor research closed, do not re-research):**
  live Stripe-aligned prices are FROZEN for the beta: Free MOT · Starter £29/mo
  (1 monitored domain) · Professional £149/mo (up to 5) · Business £399/mo
  (up to 20, an SMB plan, never presented as MSP) · **MSP/Partner =
  sales-led, platform fee + per monitored client domain** (Mailhardener-style;
  fixed 20–100+ bands are banned). Public value metric = **monitored domains**;
  cards never show workspaces/users/scans/reports. Annual copy = "Save with
  annual billing." only (live annuals ≈ 20% off, so no "pay for 10, get 12"
  claim). At most ONE final pre-beta price change (candidate on the table:
  Pro £79 / Business £199 / MSP £199 + £5/domain, min 25) — if triggered, Stripe
  + backend metadata + cards change in one lockstep step with founder approval.

## Sequencing (the founder's plan, locked)

```
Finish 4 services + 2 free hooks, validated on the 2 private domains
        ↓
Public beta launch (open signup + self-serve billing)
        ↓  (in parallel, at launch)
Grant / funding applications (UK + Scotland cyber)
```

## Stage C decision: PARKED

Worker decomposition Stage C (cron split + old email-handler removal) is **frozen
at its current stable point** (Stage A+B deployed, main==prod, all suites green,
email cutover done). It is architecture polish, not revenue-critical. We do not
let it delay the growth path; revisit post-revenue or never.

## Phased execution

### Phase 0 — Foundation lock (Week 1-2) — START NOW
- Confirm the first real DMARC report processes on the new email worker (passive watch — does not block).
- Freeze Stage C; audit the 4 services + 2 domains for "public-ready" gaps.
- Spec the two free hooks + the self-serve billing funnel for Codex.
- Stand up the marketing site skeleton + "Cyber MOT" positioning.

### Phase 1 — The two free hooks (Week 3-6)
- **Cyber MOT** (public, no-signup, any domain): passive Email + Website Security + TLS/DNS → beautiful report + AI business-impact + "fix these" → CTA to sign up. Reuses existing passive capability.
- **Cyber Essentials Readiness**: measured-evidence (external subset) + guided questionnaire (internal controls); measured signal overrides optimistic self-attestation → gap list. Readiness, not certification.

### Phase 2 — Self-serve membership (Week 6-10)
- Self-serve billing funnel: signup → verify email → add + verify domain → pick plan → pay (Stripe). Domain-based tiers.
- Polish the 4 core services for public consumption (empty states, onboarding, copy) on the 2 domains.

### Phase 3 — Public beta + grants (Week 10-14)
- Launch open signup (public beta).
- In parallel: submit grant/funding applications (see Funding track).
- Turn on the acquisition engine: free Cyber MOT hook + UK DMARC/Cyber-Essentials content/SEO. £3k ad budget = narrow experiments only, not broad spend.

## Funding track (parallel from public-beta launch)

Non-dilutive is unusually well-matched to this company (UK/Scotland cyber, SMB
enablement, Cyber-Essentials-aligned). Avenues to verify current status:
Innovate UK · UK Cyber Runway (Plexal/DSIT) · NCSC For Startups · Scottish EDGE ·
CivTech · Scottish Enterprise · **R&D tax credits (SME relief)** — the most
concrete near-term lever for a dev-heavy company. Grants take months + have
application overhead; a parallel track, never the whole plan.

## Operating model & authority (4-way)

Managed by **risk level, ownership and approval authority** — not "who codes fastest".

> **Codex builds. Claude reviews. ChatGPT directs. Turhan decides.**

| Role | Owns | Never does |
|---|---|---|
| **Turhan** — Founder / final approver | Company direction, pricing sign-off, launch timing, public-beta go/no-go, customer + MSP conversations, design-partner outreach, grant submissions, Cloudflare/Stripe/legal, **final approval on medium/high-risk prod deploys** | Get buried in low-level debugging; let engineering polish delay revenue validation; approve vague work |
| **ChatGPT** — Product + growth + positioning + task specs | Positioning, Cyber MOT messaging, public-beta scope, growth/SEO/Academy content, CE Readiness wording, competitor teardowns, grant drafts, MSP outreach templates, **Claude/Codex task specs + acceptance criteria** | Write production code; own architecture; approve deploys; change migrations/auth/billing/cron/tenant-isolation |
| **Claude** — Technical lead / codebase owner / reviewer | Architecture, Workers backend, D1/R2, migrations, billing backend, auth/session, tenant isolation, cron, report consistency, tests/CI, deploy discipline, **spec boundaries + review + integration of all Codex work** | Own outreach; decide pricing/launch/positioning; **approve its own medium/high-risk deploys**; give Codex unsupervised access to sensitive areas |
| **Codex** — Scoped implementation engineer | Well-scoped isolated build from specs: free-hook UIs, marketing/Academy pages, result/report cards, fix-list, pricing cards, questionnaire UI, empty/loading states, small isolated fixes | Touch billing/auth/cron/migrations/tenant-isolation unsupervised; merge to main without review; deploy; refactor architecture; work from vague prompts |

### Risk-based ownership

| Risk | Examples | Owner |
|---|---|---|
| Low | static pages, UI cards, Academy templates, CTA, empty states | **Codex** |
| Medium | onboarding, pricing UI, result-page integration, questionnaire frontend | **Claude specs → Codex builds → Claude reviews** |
| High | auth, billing, D1 migrations, R2, cron, tenant isolation, domain verification | **Claude only** |
| Business | pricing, launch timing, grants, MSP outreach, public-beta approval | **Turhan (+ ChatGPT)** |
| Positioning | Cyber MOT wording, CE claims, competitor messaging | **ChatGPT (+ Turhan)** |
| Production | deploys, main merge, release readiness | **Claude prepares → Turhan approves** |

### Required workflow (every meaningful task)

`Turhan states goal → ChatGPT writes product scope + spec → Claude reviews risk + sets implementation boundaries → Codex builds only the assigned scope → Claude reviews/tests/integrates → Turhan approves medium/high-risk prod changes.`

### Claude-only areas (never Codex-unsupervised)

Stripe/webhook logic · subscription state · plan enforcement · auth/session/MFA · D1 migration design · R2 report consistency · cron/scheduled scans · tenant isolation · domain-ownership verification · production deploy · main-branch integration · Stage C / worker-decomposition decisions.

### Non-negotiable rules

1. **Stage C stays frozen** unless Turhan explicitly reopens it.
2. Codex does not touch billing/auth/cron/migrations without Claude approval.
3. Claude is the final technical reviewer; Turhan is the final business approver.
4. No customer-facing "DAST / scanner / pen test / certification / guaranteed secure" — Cyber MOT, Website Security, passive posture check, Cyber Essentials **Readiness** (not certification).
5. Public beta is blocked by trust-breaking bugs, not missing nice-to-haves.
6. Revenue-critical work beats architecture polish.
7. No vague AI tasks — every task carries scope, exclusions, acceptance criteria and test expectations.

## Leading indicators / honest reset

- Month 3 checkpoint: do people **pay**, at what price? If <£3-5k MRR and no MSP
  design partner engaged, reset expectations to a slower ramp (£100k is the
  target, not a guarantee).
- Binding constraint is **go-to-market**, not engineering (AI covers build).
  Distribution wins or loses this, not features.
