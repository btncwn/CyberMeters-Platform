# Design Note — Eight-Domain Colour Identity System

Status: **CAPTURED (founder direction, 21 July 2026) — NOT scheduled.** Implementation belongs to the website design/conversion gate (or a founder-approved focused frontend episode after M7 go-live). This note exists so the direction is not lost; it changes no code.

## Founder direction (verbatim intent)

Each of the eight canonical customer-facing domains ("modules") gets its own colour scale. Clicking a module loads that module's data into the central content area, and the screen **subtly** shifts toward that module's colour — "orta alan hafifçe o rengi andıracak" (the centre area faintly evokes the colour), never a fully saturated background.

Palette supplied by the founder as an 8-swatch scale (7 swatches in the reference image + light purple).

## Proposed domain → colour mapping (founder may reorder)

| # | Domain | Colour | Rationale |
|---|--------|--------|-----------|
| 1 | Email Protection | Emerald green | healthy-mail connotation |
| 2 | Brand Protection | Soft rose/pink | brand/visibility; most distinct swatch |
| 3 | Attack Surface | Cobalt/royal blue | technical depth |
| 4 | Certificates & Trust | Turquoise | close to existing certificate UI accents |
| 5 | Cyber Essentials Readiness | Amber/sand | checklist/readiness feel |
| 6 | Website Security | Bright cyan | web association |
| 7 | Identity Exposure | Light purple | industry convention: identity/IAM = purple |
| 8 | Shadow IT & Unmanaged Technology | Steel/ice blue | neutral "shadow" tone |

Exact hex values to be sampled/finalised at implementation time and defined **once** as CSS custom properties (e.g. `--domain-email`, `--domain-brand`, …) in the Tailwind theme — no second colour source of truth, no per-page hardcoded hexes.

## Binding design rules (agreed up front)

1. **Identity colour ≠ status colour.** Red/amber/green remain reserved for severity/state across ALL domains. Domain identity appears only as: (a) a very low-chroma background tint (~4–6%) on the module's content area, (b) full-saturation accents on the module header, icon, and active-nav state. Severity badges, health states and alert colours are identical in every domain — an amber-tinted Cyber Essentials page must never read as "everything is warning".
2. **Colour is reinforcement, never the sole carrier of meaning.** Five of the eight swatches sit in the blue-green family; colour-blind users cannot rely on them. Labels + icons always carry the meaning (existing accessibility rule).
3. **Calm, professional restraint.** The tint must keep text contrast AA-compliant and preserve the "modern, trustworthy, executive-friendly" feel — if in doubt, less chroma.
4. **All eight domains stay visible** per the coverage-honesty rule; colour coding does not change navigation structure. The four-service sidebar decision (founder-locked) is a separate concern from domain colour identity.

## Scope when implemented

Frontend-only theming (CSS tokens + per-domain page/nav accents). No backend change, no data change, no navigation-IA redesign bundled in. One focused PR, verified against light/dark and responsive states.
