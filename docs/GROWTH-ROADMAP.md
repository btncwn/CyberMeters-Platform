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
- **2 private validation domains:** cybermeters.com + blackbullbarbers.co.uk (dogfood everything here before public).
- **Pricing (proposal, validate in Phase 2):** Free MOT · Starter ~£29/1 domain · Professional ~£79/~5 · Business ~£199/~20 · MSP/Partner ~£399+/20-100+ (per-domain overage). Annual = pay 10, get 12. Domain count = value metric + abuse control.

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

## Task distribution (4-way)

| Who | Owns | Does NOT do |
|---|---|---|
| **Claude** (this codebase) | Architecture, Workers backend, migrations, billing logic (medium-risk, careful), tests/CI, deploy discipline, **spec + review of all Codex work + integration** | Send outreach; dashboard actions; approve own medium/high-risk prod deploys |
| **Codex** (new hire) | Well-scoped, isolated build: free-hook UIs, marketing site, self-serve funnel front-end, component work — **from Claude's specs, Claude reviews/integrates** | Touch billing/auth/cron/migrations unsupervised; merge to main without review (two AI coders → one reviewer owns integration, per the divergence lessons this session) |
| **ChatGPT** | Non-code: positioning/copy (English, UK spelling), landing pages, content/SEO, competitor teardowns, grant-application drafting, MSP outreach templates, CE question-set mirroring | Write production code; make architecture calls |
| **Turhan** (owner) | Cloudflare/Stripe/business setup, pricing sign-off, **MSP design-partner outreach**, grant submissions, customer conversations, legal/company, **final approval on medium/high-risk deploys** | — |

## Leading indicators / honest reset

- Month 3 checkpoint: do people **pay**, at what price? If <£3-5k MRR and no MSP
  design partner engaged, reset expectations to a slower ramp (£100k is the
  target, not a guarantee).
- Binding constraint is **go-to-market**, not engineering (AI covers build).
  Distribution wins or loses this, not features.
