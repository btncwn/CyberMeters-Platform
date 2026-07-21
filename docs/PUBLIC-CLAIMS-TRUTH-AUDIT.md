# Public Claims Truth Audit

Status: **READ-ONLY AUDIT — findings only, no edits.** Prepared 21 July 2026 (parallel docs/audit track, alongside CLI billing track).
Scope: public + in-app customer-facing surfaces (homepage, invitation landing, onboarding, academy, workspace pages, SEO metadata) checked against the canonical eight-domain Cyber MOT model and the honesty rules (no over-claim: "verified"/"real-time"/"complete protection"/dark-web/pentest/ransomware/takedown-execution). Billing surface was already cleaned by PR #230 (v2026.07.21-1) — this audit covers the NON-billing residuals the CLI flagged, plus a full over-claim sweep.

## Verdict
Over-claim discipline is **mostly strong** — dark-web, pentest, ransomware and takedown are honestly disclaimed/scoped in most places. **One material finding**: the retired "Vendor Risk / Supply Chain" claims are still live as full, reachable customer pages and across invitation/onboarding/academy, inconsistent with the eight-domain model and with the billing surface that #230 just cleaned. Plus three P3 wording/SEO items. Every fix is a FOUNDER product-scope decision (retire vs honest-relabel) — this audit surfaces, it does not decide.

---

## P2 (material) — Retired Vendor Risk / Supply Chain claims still live customer-facing

The canonical model has **eight** domains; Vendor Risk and Supply Chain are **not** among them (memory: "customer-facing claims retired/suppressed, underlying evidence preserved"). PR #230 removed these claims from the **billing** surface and relabelled `vendor_risk` to the honest floor "**Third-party technology detection**". But the same claims remain live elsewhere:

**Full ROUTED, REACHABLE pages (not just stray text):**
- `/ws/vendors` → `pages/ws/VendorsPage.jsx:95` — h1 "**Vendor Risk**"
- `/ws/supply-chain` → `pages/ws/WorkspaceSupplyChainPage.jsx:238/254/293` — h1 "**Supply Chain Risk**", "**Supply Chain Score**" ring
- `/portfolio/risk` → `pages/PortfolioRiskPage.jsx:472` — "supply chain intelligence, and vendor risk data"

**Acquisition / onboarding / education surfaces:**
- `pages/InvitationLandingPage.jsx:81-82` — "**Vendor Risk Visibility**" / "third-party exposure and supply chain risk" (shown to invited prospects)
- `components/TeamOnboardingCard.jsx:44`, `components/FirstResultsGuide.jsx:5,55` — "**Vendor Risk**" cards
- `pages/ws/WorkspaceBusinessRiskPage.jsx:145` — composite "…brand, and supply chain"
- `pages/ws/WorkspaceIdentityPage.jsx:271` — "appear in **Vendor Risk** inventory"
- `data/academy.js:40-41,770-792` — full "**Vendor Risk Explained**" + "**Supply Chain Intelligence**" articles + academy categories

**Why it's a claim problem.** "Vendor Risk" / "Supply Chain Risk" / "Supply Chain Score" imply a vendor-/supply-chain-risk-management programme (questionnaires, external feeds, continuous vendor monitoring) the product does **not** provide. What it actually does is external observation from scan data — `WorkspaceSupplyChainPage.jsx:351` even says so honestly ("derived entirely from existing CyberMeters scan data — no external feeds, no vendor questionnaires, no active probing"). So the inline bodies are honest, but the **headings, navigation, scores, onboarding and invitation lead with the over-claiming names.**

**Recommendation (founder decision — retire vs relabel; keep it CONSISTENT with #230):**
- Option A — **Honest relabel** everywhere to the external-observation floor (as #230 did on billing): e.g. "Third-party & Shadow Technology", drop the "Score" framing that implies a risk-management rating. Keep the underlying data.
- Option B — **Retire** the `/ws/vendors` + `/ws/supply-chain` pages from customer navigation (data preserved), fold signals into Shadow IT & Unmanaged Technology (the canonical eighth domain).
- Either way: sweep invitation/onboarding/academy for the same naming so the whole product tells one story. This is a frontend/content PR (CLI or docs track) once the founder picks A or B.

---

## P3 (minor wording / SEO)

1. **`pages/InvitationLandingPage.jsx:58`** — "**Real-time** visibility across all domains". Scanning is scheduled/periodic, not real-time. Soften to "continuous/scheduled monitoring" or "always-on visibility". (StatusPage's "real-time health check" is fine — it genuinely is.)
2. **`pages/ws/WorkspaceEmailProtectionPage.jsx:519`** — "This is **full protection** against spoofing." Defensible only at DMARC `p=reject`; "full protection" is strong absolute language. Consider "blocks spoofed mail that fails authentication" — outcome-accurate without the absolute.
3. **SEO — `index.html` meta description + og:description** name only **four** domains ("email security, brand exposure, attack surface risk, and certificate trust"). The product is the **eight-domain** Cyber MOT. Under-represents (not an over-claim, but an inconsistency) — update to reflect the eight-domain Cyber MOT for accuracy + SEO coverage.

## Good — honest, no action (recorded so they're not "fixed" by mistake)
- Homepage `PublicLandingPage.jsx` — leads with the **eight canonical domains**; "One posture across eight domains" ✓. "vendors" appears only as an observed Shadow-IT signal type, not a claimed domain ✓.
- `TrustPage.jsx:111` — pentest "**planned before commercial general availability**" ✓
- `PublicLandingPage.jsx:63` — "without unsupported **breach or dark-web** claims" ✓
- `components/CyberMotDomains.jsx:68` — Identity Exposure "(not credential/breach monitoring)" ✓
- `BrandMonitoringPage.jsx` — takedown framed as "**prep** / prepared for submission", never "we took it down" ✓ (matches canonical prepare/track, not execute)
- `academy.js:935` — "a Cyber MOT does **not** claim your business is fully secure" ✓
- No four/six/seven-domain claims anywhere ✓ (SEO under-count is a separate copy gap, not a domain-model claim)

## Notes
- Dark-web/pentest/ransomware/stealer strings in `academy.js` are **educational content** (explaining attacks), not product capability claims — correctly out of scope.
- All fixes above are frontend/content changes; this audit made **no edits**. Sequencing: fold the P3 SEO + wording into the next public-copy PR; the P2 Vendor/Supply relabel-or-retire needs the founder's product-scope decision first, then one consistent content PR.
