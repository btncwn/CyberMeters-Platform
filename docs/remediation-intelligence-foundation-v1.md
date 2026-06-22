# CyberMeters — Remediation Intelligence Foundation v1

**Sprint 11 — Academy Foundation**
**Date:** June 2026
**Status:** Foundation design — Sprint 11A implementation

---

## Purpose

This document defines the reusable remediation intelligence architecture that connects Academy articles to platform findings, reports, and customer onboarding. It is the design specification for Sprint 11A's "Learn More" integration and the long-term knowledge graph that supports contextual security guidance throughout the platform.

---

## Strategic Context

CyberMeters findings are currently presented with:
- Finding title and severity
- Description (1–2 sentences)
- Evidence (structured evidence chain)
- Confidence score and rating

What is missing is **actionable remediation context** — a direct link from "you have this problem" to "here is how you fix it, with verification steps, and a real-world example of why it matters."

The Academy articles created in Sprint 11 contain exactly this content. Remediation Intelligence is the integration layer that connects them.

---

## Data Model

### Finding → Remediation Intelligence link

Each finding type maps to zero or more Academy articles via the `FINDING_TO_ACADEMY` table (defined in `docs/finding-to-academy-mapping-v1.md`).

The link is one-way at the finding level (finding → article) but bidirectional via the `findingIds[]` array on each article:

```
Worker finding type ID  →  Academy article slug  →  7-section article content
     email_missing_spf  →  spf-explained         →  Why It Matters, How Attackers Abuse It,
                                                      Real World Example, What CyberMeters Detects,
                                                      Remediation Overview, Verification
```

### Remediation section structure (per article)

Every cornerstone article includes a **Remediation Overview** section following this consistent pattern:

1. **What needs to change** — the specific configuration or system to modify
2. **Step-by-step guidance** — ordered list of actions with CLI/config examples
3. **Common pitfalls** — callout block with the most frequent mistakes
4. **Verification** — how to confirm the fix worked (separate section)

This structure is consistent across all 12 v1 articles and is the pattern all future Academy articles must follow.

---

## Integration Architecture

### Sprint 11A — Finding row "Learn More" link

**Location:** `ScanDetail.jsx` — finding row component

**Implementation:**

```jsx
// 1. Add derived mapping to academy.js:
export const FINDING_TO_ACADEMY = Object.fromEntries(
  ARTICLES.flatMap(a =>
    (a.findingIds || []).map(id => [id, a.slug])
  )
)

// 2. In ScanDetail.jsx finding row:
import { FINDING_TO_ACADEMY } from '../../data/academy'

const academySlug = FINDING_TO_ACADEMY[finding.finding_id]
{academySlug && (
  <Link
    to={`/academy/${academySlug}`}
    className="inline-flex items-center gap-1 text-xs text-brand-600 hover:underline"
  >
    Learn more
    <ExternalLink className="w-3 h-3" />
  </Link>
)}
```

**Data flow:** Finding ID (from scan report JSON) → `FINDING_TO_ACADEMY` lookup → Academy slug → `/academy/:slug` route

**No backend changes required** — the lookup is fully client-side.

### Sprint 11B — PDF report remediation links

**Location:** Worker `generatePdfReport()` — per-finding section

The PDF trust layer (Sprint 10A) already includes finding severity and confidence in the PDF output. In Sprint 11B, each finding in the PDF's "Top Security Findings" section should include:

```
📚 Learn more: cybermeters.io/academy/[slug]
```

This requires the Worker to embed the `FINDING_TO_ACADEMY` mapping (a simple object literal) into the report generation code. No database changes required.

### Sprint 11C — Onboarding remediation checklist

**Location:** `OnboardingPage.jsx` (future) or `WorkspaceDashboard.jsx`

After an initial scan, surface the top 3–5 findings with inline remediation summaries pulled from Academy article `sections[4]` (Remediation Overview). This creates a guided "fix these first" experience for new customers without requiring them to read full articles.

---

## Remediation Severity × Urgency Matrix

This matrix defines how remediation intelligence is presented based on finding severity:

| Severity | Urgency | Academy presentation | SLA target |
|----------|---------|----------------------|-----------|
| Critical | Immediate | Finding row + inline remediation summary + CTA | 24 hours |
| High | This week | Finding row + Learn More link | 7 days |
| Medium | This month | Learn More link | 30 days |
| Low | Backlog | Learn More link (subtle) | 90 days |
| Informational | No SLA | Optional Learn More | — |

The inline remediation summary for Critical findings (Sprint 11C) extracts `article.sections[4].blocks` (Remediation Overview) and renders the first paragraph and bullet list directly in the finding panel.

---

## Content Quality Standards

All Academy articles used in Remediation Intelligence must meet these standards:

### Required sections (enforced by content model)
1. Summary — executive lede, 2–3 sentences
2. Why It Matters — business impact
3. How Attackers Abuse It — realistic attack scenario
4. Real World Example — named incident
5. What CyberMeters Detects — maps to `findingIds[]`
6. Remediation Overview — actionable guidance
7. Verification — how to confirm the fix

### Writing standards
- No marketing language ("protect your business today")
- No generic advice not tied to specific configurations
- All CLI/DNS examples must be tested against real services
- Real World Examples must cite verifiable incidents
- Verification steps must be executable by a non-expert

### Prohibited content
- TODOs or placeholder text
- "Contact your vendor" as the only remediation
- Generic "best practices" without specific implementation guidance
- Security advice that contradicts current CIS/NIST guidance

---

## Finding ID Naming Convention

Finding IDs used in `findingIds[]` must follow this format:

```
{category}_{descriptor}[_{qualifier}]
```

Examples:
- `email_missing_spf`
- `email_spf_softfail`
- `subdomain_takeover_detected`
- `cloud_storage_public_bucket`
- `header_csp_unsafe_inline`

**Categories:** `email`, `dns`, `ssl`, `header`, `subdomain`, `cloud_storage`, `identity`, `saas`, `vendor`, `supply_chain`, `asset`, `port`, `brand`

Finding IDs defined in Academy articles must match exactly the `finding_type` field emitted by the Worker in scan report JSON. If a finding ID in an article does not match any Worker finding type, it will silently produce no link (graceful degradation).

---

## Scalability Design

### Adding a new article

1. Add the article object to `ARTICLES` array in `academy.js`
2. Include `findingIds[]` matching Worker finding type IDs
3. The `FINDING_TO_ACADEMY` computed mapping picks it up automatically
4. Finding rows in ScanDetail.jsx render the link automatically
5. No other changes required

### Adding a new finding type to the Worker

1. Emit `finding_type: 'category_descriptor'` in the finding object
2. Create or update the corresponding Academy article to include the finding ID in `findingIds[]`
3. If no article exists yet, the finding renders without a Learn More link (graceful degradation)

### Category expansion

New Academy categories are added to `CATEGORIES` in `academy.js`. No routing, backend, or database changes are required. The category pill filter on the Academy index page picks up new categories automatically.

---

## Future Roadmap

| Sprint | Feature | Description |
|--------|---------|-------------|
| 11A | Finding row links | "Learn More →" in ScanDetail.jsx |
| 11B | PDF remediation links | Academy URLs in generated PDF reports |
| 11C | Onboarding checklist | Inline remediation summaries for new customers |
| 12 | Finding-to-article navigation | Click finding in Academy "What CyberMeters Detects" → see live findings |
| 13 | Remediation status tracking | Mark findings "in remediation" with expected resolution date |
| 14 | Customer remediation reports | PDF export of open findings with Academy remediation guidance |

---

## Version History

| Version | Date | Notes |
|---------|------|-------|
| v1 | June 2026 | Foundation design — 12 articles, 37 finding mappings, Sprint 11A spec |
