# CyberMeters Academy Architecture v1

**Sprint 11 — Academy Foundation**
**Date:** June 2026
**Status:** Implemented

---

## Overview

CyberMeters Academy is a customer education and trust platform built as a first-class feature inside the CyberMeters frontend. It is not a blog — it is a structured security knowledge base that maps directly to platform findings, remediation intelligence, and customer onboarding.

---

## Decisions

### Routing

Academy lives inside the existing Layout shell (protected route). All authenticated users can access it.

```
/academy              → AcademyPage (index: categories, search, featured articles)
/academy/:slug        → AcademyArticlePage (single article renderer)
```

Routes are added to `App.jsx` under the protected `<Route path="/">` tree, consistent with all other feature pages.

Future: public (unauthenticated) access to `/academy/*` can be added by duplicating the routes outside the protected wrapper for SEO purposes.

### Content Storage

**Decision: Static JavaScript objects in `frontend/src/data/academy.js`.**

Alternatives considered:

| Option | Verdict |
|--------|---------|
| Markdown files + remark/unified parser | Rejected — adds ~200KB dependency, build complexity |
| CMS / headless API | Rejected — over-engineered for v1, requires backend work |
| JSON files | Rejected — no JSX in content, limits rich section rendering |
| Static JS with structured sections | **Chosen** — zero new dependencies, type-safe, searchable, supports JSX |

Each article is a plain JS object:

```js
{
  slug: 'spf-explained',
  title: 'SPF Explained',
  category: 'email-security',
  summary: '...',
  readTime: 8,
  featured: false,
  sections: [
    { heading: 'Why It Matters',         content: '...' },
    { heading: 'How Attackers Abuse It', content: '...' },
    { heading: 'Real World Example',     content: '...' },
    { heading: 'What CyberMeters Detects', content: '...' },
    { heading: 'Remediation',            content: '...' },
    { heading: 'Verification',           content: '...' },
  ],
  relatedSlugs: ['dmarc-explained', 'dkim-explained'],
  findingIds: ['email_missing_spf', 'email_spf_softfail'],
}
```

### Content Model

Every article has exactly 6 sections (plus executive summary):

1. **Summary** — 2–3 sentence executive explanation (top-level field, rendered as lede)
2. **Why It Matters** — business impact, board-level language
3. **How Attackers Abuse It** — realistic attack scenario, no sensationalism
4. **Real World Example** — named incident where possible
5. **What CyberMeters Detects** — maps to specific finding IDs
6. **Remediation Overview** — actionable high-level fix guidance
7. **Verification** — how customers confirm the fix was effective

### Markdown Support

No external markdown library. Content is stored as plain prose paragraphs in JS strings. The article renderer applies Tailwind typography classes directly. Code blocks use `<code>` elements styled inline.

If formatted content (bullet lists, code, etc.) is needed in a specific section, the `content` field can be an array of block objects:

```js
{ type: 'para', text: '...' }
{ type: 'list', items: ['...', '...'] }
{ type: 'code', lang: 'dns', text: 'v=spf1 include:...' }
{ type: 'callout', variant: 'warning', text: '...' }
```

The `AcademyArticlePage` renderer dispatches on `type`. Default is `para`.

### Navigation

Academy added as a primary nav link in `Layout.jsx` NAV array:

```js
{ to: '/academy', icon: GraduationCap, label: 'Academy' }
```

Placed after Reports, before Pricing (current position: 8th in nav).

### Category Navigation

Categories are defined in `academy.js` alongside articles. The `AcademyPage` renders:
- Category filter tabs across the top
- Article cards in the active category
- Featured articles in a hero row
- Search box (client-side filter on title + summary)

### Search

Client-side only. Filters `articles` array on `title.toLowerCase().includes(q)` or `summary.toLowerCase().includes(q)`. No backend search needed for v1.

---

## File Structure

```
frontend/src/
  data/
    academy.js          — all category + article definitions
  pages/
    AcademyPage.jsx     — index (categories, search, featured)
    AcademyArticlePage.jsx — single article renderer
```

---

## Finding Integration (Future — Sprint 11A)

`findingIds` on each article maps to finding type strings in the Worker. The `ScanDetail.jsx` finding row will eventually render a "Learn More →" link that navigates to `/academy/:slug` when a matching article exists.

The mapping document is at `docs/finding-to-academy-mapping-v1.md`.

---

## No Migration Required

Academy is fully frontend. No backend changes, no database schema changes, no Worker modifications.

---

## Scalability

- Articles are plain JS — adding content is a one-file edit
- Category IDs are stable strings — adding categories does not break existing slugs
- `relatedSlugs` and `findingIds` enable future graph traversal
- All slugs are URL-safe lowercase-hyphenated strings
