---
name: cybermeters-frontend-design
description: Designs and implements CyberMeters frontend and website work with professional SaaS UX, backend-owned security states, eight-domain consistency, accessibility, responsive behavior, and complete loading/empty/error states. Use for React, Pages, UI, UX, navigation, dashboard, or public website changes.
---

# CyberMeters Frontend and Product Design

Use the installed frontend-design plugin where useful, but obey CyberMeters product truth and backend contracts.

## Product tone

CyberMeters must feel:

- modern
- calm
- structured
- commercially credible
- executive-friendly
- security-serious
- consistent

Avoid playful security theatre, clutter and raw database presentation.

## Permanent visual rule

> Explanation first, number second.

Numbers support the story; they do not replace it.

## Backend ownership

The frontend must not independently derive:

- security verdicts
- coverage state
- risk
- verification
- remediation meaning
- allowed workflow actions

Display server-owned canonical states.

Do not fabricate missing metrics.

## State completeness

Every changed surface must consider:

- loading
- empty
- partial evidence
- unavailable
- error
- success
- stale
- permission denied
- mobile/responsive
- keyboard/accessibility

Customer-safe errors only. Never show Worker, D1, SQL or stack details.

## Security language

Do not use labels such as:

- Connected
- Protected
- Healthy
- Verified
- Resolved
- Removed

unless evidence supports that exact state.

Distinguish visibly:

```text
Observed by CyberMeters
Classified by customer
Action recorded by customer
Externally verified by CyberMeters
```

## Eight-domain consistency

The canonical domains are:

1. Email Protection
2. Brand Protection
3. Attack Surface
4. Certificates & Trust
5. Cyber Essentials Readiness
6. Website Security
7. Identity Exposure
8. Shadow IT & Unmanaged Technology

Do not revert to a four-service model.

Domain visibility and sidebar density are separate problems. Do not hide domains merely to simplify navigation.

## Component quality

Prefer:

- reusable components
- consistent spacing and typography
- accessible labels
- semantic controls
- responsive layouts
- clear primary action
- evidence and limitation explanations
- stable URLs and route contracts

Avoid:

- giant components
- duplicated display maps
- UI-only state machines
- hardcoded scores
- unexplained badges
- colour-only meaning
- unnecessary dashboard redesign during a focused episode

## Required validation

Run:

```bash
cd frontend
npm run test
npm run test:coverage
npm run build
```

Add or update co-located tests for display helpers and workflow rendering.

Confirm affected routes in production or a running app. A successful build alone is not UX proof.
