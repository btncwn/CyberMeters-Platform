# Episode — Vendor Risk / Supply Chain Customer-Facing Retirement (fold into Shadow IT)

Status: **QUEUED (founder-approved 21 July 2026, "Option B").** Not started. Sequencing: **pre-public-beta public-claims cleanup — AFTER the M7 go-live billing work (B2/B3 + legal PR #232) and the live cutover; a proper episode, not rushed.** Product-scope change → founder-gated (it retires customer-facing surfaces), already approved in principle by the founder.

Source: `docs/PUBLIC-CLAIMS-TRUTH-AUDIT.md` P2. Precedent: PR #230 already did this on the billing surface (relabelled `vendor_risk` → "Third-party technology detection").

## Goal
Make the product tell ONE honest story — the canonical **eight domains** — by removing the standalone, over-claiming "Vendor Risk" and "Supply Chain Risk/Score" customer surfaces and folding the genuine signal (externally observed third-party/vendor technology) into the canonical eighth domain, **Shadow IT & Unmanaged Technology**, which is already defined as "externally observed SaaS, vendors, third-party scripts and unmanaged technology signals". Kill the "Supply Chain Score" (score-theatre: derived only from re-badged scan signals, no external supply-chain evidence). **Preserve all underlying data and its internal use** — retire ≠ delete.

## Exact pre-change map

**Customer-facing surfaces to retire / relabel / fold:**
- `pages/ws/VendorsPage.jsx` (route `/ws/vendors`) — h1 "Vendor Risk"
- `pages/ws/WorkspaceSupplyChainPage.jsx` (route `/ws/supply-chain`) — "Supply Chain Risk" + "Supply Chain Score" ring
- `pages/PortfolioRiskPage.jsx` (route `/portfolio/risk`) — "supply chain intelligence, vendor risk data" copy
- `pages/InvitationLandingPage.jsx:81-82` — "Vendor Risk Visibility" card
- `components/TeamOnboardingCard.jsx:44`, `components/FirstResultsGuide.jsx:5,55` — "Vendor Risk" cards
- `pages/ws/WorkspaceBusinessRiskPage.jsx:145` — "…brand, and supply chain" composite copy
- `pages/ws/WorkspaceIdentityPage.jsx:271` — "appear in Vendor Risk inventory"
- `data/academy.js:40-41,770-792` — "Vendor Risk Explained" + "Supply Chain Intelligence" articles + academy categories
- API client methods (frontend): `getWorkspaceVendors`, `getWorkspaceVendorsSummary`, `getWorkspaceSupplyChain`, `getPortfolioRisk`
- `App.jsx` routes: `ws/vendors`, `ws/supply-chain`, `portfolio/risk`

**MUST PRESERVE (data + internal pipeline — do NOT delete):**
- Tables: `workspace_vendors`, `vendor_risk_scores`, `vendor_risk_scores_history`, `workspace_supply_chain_scores`, `workspace_supply_chain_history`, `vendor_relationships`
- Engines: `vendor-signatures.js`, `vendor-risk.js`, `supply-chain.js`, `portfolio-risk.js`, `vendor-relationship.js`
- Scan phases 8c (vendor risk) + 8g (vendor relationships) — internal detection
- **`business-risk.js` uses `drivers.vendor_risk` as a Business Risk Score driver** (lines ~40-121) — the BRS composite MUST keep working; the vendor signal stays an internal input to BRS even after the customer-facing "Vendor Risk" surface is retired.
- Historical continuity: these are append-only history tables — never destructively removed.

## Design decision
1. **Retire** `/ws/vendors` and `/ws/supply-chain` as standalone customer pages. Route redirects → the Shadow IT & Unmanaged Technology surface (or a 410/hidden nav), preserving deep links safely.
2. **Fold** the honest signal — "externally observed third-party / vendor technology" — into **Shadow IT & Unmanaged Technology** (its canonical home). No new claim; it's the same external-observation floor #230 used ("Third-party technology detection").
3. **Drop the "Supply Chain Score"** ring/number from customer view (score-theatre). If a portfolio/BRS view needs the underlying number, keep it internal to BRS, not surfaced as a standalone "score".
4. **Sweep naming** across invitation, onboarding (`TeamOnboardingCard`, `FirstResultsGuide`), business-risk composite copy, identity page cross-reference, and academy (retire/rename the two articles + categories) so the whole product reflects eight domains, no ninth "Vendor/Supply" domain.
5. Keep the backend endpoints if still consumed internally (BRS/portfolio); otherwise gate/hide. Decide per-endpoint during the episode.

## Scope boundaries
- DO NOT delete any data, table, engine, or the BRS vendor driver. Retire ≠ delete.
- DO NOT touch the canonical eight-domain definitions except to ensure vendor/third-party signals sit under Shadow IT.
- DO NOT expand scope into unrelated copy or the M7/legal work.
- This is customer-facing content + routing + a possible additive nav change — **no destructive migration.**

## Risks & compatibility
- BRS regression: verify `business-risk.js` still computes with the vendor driver after any surface change (it's internal — should be untouched, but assert with the BRS validator).
- Deep-link breakage: `/ws/vendors` and `/ws/supply-chain` may be bookmarked — add redirects, don't hard-404.
- Academy: retiring two articles must not break academy routing/indexing (check `academy.js` slug references + internal links).
- Portfolio: `PortfolioRiskPage` and `getPortfolioRisk` may be entitlement-gated (business/MSP) — keep the portfolio surface honest (drop the vendor/supply framing, keep the real per-domain portfolio state).
- Tests: extend a validator/guard asserting no "Vendor Risk"/"Supply Chain Score" customer-facing strings return (mirror #230's source guard, extended to the non-billing files).

## Sequencing (queue position)
Pre-public-beta, in the **public-claims cleanup** slot, AFTER: M7 B2/B3 billing-flow + legal PR #232 + live cutover. Fold the audit's three P3s (SEO four-domain meta, "real-time" on invitation, "full protection" wording) into the SAME content PR/episode for one coherent public-copy pass. Founder-gated (product-scope). One focused frontend/content PR (+ optional additive nav), mutation/source-guard tested, no migration.
