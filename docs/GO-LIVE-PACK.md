# Go-Live Commercial / Legal / Onboarding Closure Pack

Prepared by the product-owner (Desktop) workstream, docs-only. **No runtime, Stripe, secret, or deploy action was taken.** This pack makes the go-live decisions and actions explicit so the founder can execute them; it does not perform them. Where a founder decision or live action is required, it is labelled, not resolved on the founder's behalf.

**Action legend used throughout:** `[DESKTOP-DONE]` prepared here · `[FOUNDER-DECISION]` needs a founder ruling · `[FOUNDER-DASHBOARD]` a Stripe/registrar action only the founder can do · `[CLI/DEPLOY]` a runtime/deploy action for the engineering lane · `[EXTERNAL-PENTESTER]` a later third-party action.

---

## A. Legal #232 — final readiness review + consistency matrix

**Critical process finding first:** PR #232 (branch `fix/legal-sole-trader-scotland-subprocessors`) was branched early and **is now far behind `main`** (it predates the security suites, CAPABILITIES.md, SPF, colour work, etc.). Merging it as-is risks conflicts and regressions on shared files (e.g. `serviceColors.js`, `stripe.js`, `billing.js`). **`[CLI/DEPLOY]` #232 must be rebased onto current `main` (or its legal-page edits re-applied as a fresh branch) before merge.** The legal-page *content* below is sound; the *branch* is stale.

**Consistency matrix** — every clause, current live wording (on `main`) vs the #232-intended wording, with a classification.

| # | Clause | Current live (`main`) | #232 intended | Classification |
|---|--------|------------------------|----------------|----------------|
| 1 | Sole-trader identity | absent / generic "CyberMeters" | "CyberMeters is a trading name of Turhan Acar, a sole trader in the UK" | **settled but wording drift exists** (fix in #232) |
| 2 | Business/contact details | `legal@` / `privacy@` / `dpa@` (multiple) | consolidated to `hello@cybermeters.com` | **settled but wording drift exists** |
| 3 | Contact address | not published | home address deliberately NOT on public Terms (data-min); full address on Stripe invoices via KYC | **settled and aligned** (founder ruling) |
| 4 | Service description | present | unchanged | **settled and aligned** — must match `CAPABILITIES.md` |
| 5 | External scanning authorization | present | unchanged | **settled but VERIFY** the customer warrants ownership/authority to scan |
| 6 | Acceptable use | present | unchanged | **settled and aligned** |
| 7 | Trial | 14-day full trial, 1 domain, no card | unchanged | **settled and aligned** (matches runtime) |
| 8 | Recurring billing | present | unchanged | **settled and aligned** |
| 9 | Cancellation timing | "cancel" mentioned | should state **cancellation effective at period end** (matches portal behaviour) | **settled but wording drift exists** — confirm the page states period-end explicitly |
| 10 | Cooling-off waiver | 14-day + waiver text (checkout consent) | unchanged; checkout consent already collects it | **settled and aligned** |
| 11 | Refunds | "non-refundable except where required by law" | unchanged | **founder decision still required** — see B (refund detail) |
| 12 | Proration | not customer-worded | should reflect "prorate charges and credits" on plan change | **settled but wording drift exists** |
| 13 | Failed-payment grace | not customer-worded | runtime enforces a 7-day grace | **settled but wording drift exists** — consider disclosing the grace window |
| 14 | Data retention | present | unchanged | **settled and aligned** (verify against Privacy/DPA retention numbers) |
| 15 | Subprocessors | Cloudflare + Stripe only | **+ Resend (Plus Five Five, Inc.) + Microsoft (Entra ID)** + international-transfer clause | **settled but wording drift exists** (fix in #232 — current pages are INCOMPLETE/inaccurate) |
| 16 | Customer responsibilities | present | unchanged | **settled and aligned** |
| 17 | Liability limitations | present | unchanged | **external legal review recommended** (sole-trader liability cap) |
| 18 | Service limitations / security-claim boundaries | present | must match `CAPABILITIES.md` (external-observation, not pentest/EDR/SIEM/DAST) | **settled but VERIFY** against CAPABILITIES.md |
| 19 | Governing law + disputes | **"England and Wales"** (2×) | **"law of Scotland / Scottish courts"** + consumer-rights note | **settled but wording drift exists** (fix in #232 — current is WRONG for the founder's jurisdiction) |

**Merge-ready status:** the #232 *content* is merge-ready for items classed "settled but wording drift" once the branch is rebased. Items 11 (refunds) and 17 (liability) carry a **[FOUNDER-DECISION]** / external-review flag and must not be silently merged as settled. **Do not merge #232 while items 11/17 are unresolved.** `[CLI/DEPLOY]` rebase + `[FOUNDER-DECISION]` refund/liability, then merge at go-live.

---

## B. Remaining commercial decision register

Already founder-approved (do **not** reopen): not VAT registered / no VAT charged · proration model (prorate charges + credits) · cooling-off waiver approach · canonical pricing (Starter £9.99/£99.90 · Professional £19.99/£199.90 · Business £49.99/£499.90, 10 domains).

Open decisions — one table, current fact → recommendation → consequence.

| Decision | Current runtime behaviour | Current customer wording | Recommended | Alternative | Consequence | Affects later |
|---|---|---|---|---|---|---|
| **Refund detail** | none automated (Stripe refunds are manual) | "non-refundable except where required by law" | No proactive refunds; honour statutory rights; goodwill refunds case-by-case | Fixed N-day money-back | UK consumer law: with the immediate-start waiver, prepaid is non-refundable except statutory — the wording is defensible; a money-back promise is a commercial giveaway | Terms refund clause; support playbook |
| **Failed-payment grace** | **7 days** enforced (`getPaymentGraceState`), paid access continues while Stripe retries | not disclosed | Disclose the 7-day grace in Terms/billing copy | Leave undisclosed | Disclosure is customer-friendly and matches runtime; non-disclosure risks a "why did access stop" dispute | Terms/billing wording only (runtime already does it) |
| **Cancellation timing** | portal cancel = **at period end** (verified) | "cancel" mentioned, not explicit | State "cancellation takes effect at the end of the current billing period; access continues until then" | Immediate-cancel option | Period-end matches Stripe portal default + the immediate-start waiver; immediate-cancel would need proration-out logic not built | Terms wording |
| **Annual-plan treatment** | annual = 10× monthly (2 months free); prorated on switch | plan card shows annual price | Keep 10×-monthly; annual refund follows the same non-refundable-except-statutory rule | Different annual refund | Consistent, simple | Pricing copy |
| **Proration wording** | prorate charges + credits (verified: £10 = £19.99 − £9.99 credit) | not worded | Add one plain sentence: upgrades are prorated | none | Transparency | Terms/billing copy |
| **Business >10-domain overage** | entitlement **fails closed at 10** (per-domain overage NOT wired to Stripe) | Business = "10 monitored domains" | Sell Business at **10 domains, self-service**; 11–25 = "contact us" | Advertise 11–25 now | Selling overage now would over-promise a billing path that isn't wired | Pricing copy; CAPABILITIES.md (already honest) |
| **MSP / metered** | MSP price is null (metered, floor £129.99); portal unreachable in prod | "contact us" appropriate | MSP = **"contact us"**, not self-service | Self-service MSP | MSP metered billing + portfolio are not production-exercised | Pricing copy |
| **Support & escalation** | none formal | none | Single `hello@cybermeters.com`; best-effort next-business-day for the controlled beta | SLA promise | An SLA is premature for a 1–2 customer beta | Support playbook (D) |

All rows above marked **[FOUNDER-DECISION]** except where the recommendation simply *discloses* existing runtime behaviour (grace, cancellation, proration), which are wording-only and can be applied once the founder confirms the sentence.

---

## C. Live Stripe cutover — founder-executable action sheet

Exact order. **The engineer never handles `sk_live` or the webhook secret — those are founder-entered.** Price IDs are not secret; map the 6 live price IDs already created in the live account (recorded in the founder's secure notes / `contracting-entity-sole-trader` memory).

1. `[FOUNDER-DASHBOARD]` Live **Turhan Acar** account → confirm public details / sole-trader identity (do NOT create a public profile that exposes the home address).
2. `[FOUNDER-DASHBOARD]` Set **Terms URL** = `https://cybermeters.com/terms` and **Privacy URL** = `https://cybermeters.com/privacy` (live dashboard renders this correctly — unlike the sandbox).
3. `[FOUNDER-DASHBOARD]` Confirm **products + monthly/annual prices**: Starter £9.99/£99.90 · Professional £19.99/£199.90 · Business £49.99/£499.90. Verify each **lookup key + plan metadata** matches the canonical registry.
4. `[FOUNDER-DASHBOARD]` **Customer portal** config: enable "customers can switch plans", add the 6 prices, set proration = "prorate charges and credits" (replicate the sandbox config that passed B3).
5. `[FOUNDER-DASHBOARD]` Create the **live webhook endpoint** → the production Worker billing webhook URL; capture the **live webhook secret**.
6. `[FOUNDER-DASHBOARD]` `[CLI/DEPLOY]` Set Worker secrets/config: `sk_live`, live webhook secret, the 6 live price IDs (founder-entered; engineer verifies non-secret mapping only).
7. `[CLI/DEPLOY]` **Deployment sequencing:** legal #232 merged (so `/terms` shows the corrected text) → Worker deploy carrying live-key config → verify `/health`. **Do this in its own release window — NOT bundled with the SPF deploy.**
8. `[FOUNDER-DASHBOARD]` **Low-risk real checkout:** a real card on the cheapest plan (Starter £9.99) — or a founder-owned card refunded after — to prove the live path.
9. `[FOUNDER-DASHBOARD]` `[DESKTOP/READ-ONLY]` **Terms consent proof:** confirm `terms_consent: accepted` in the subscription event trail (as proven in sandbox).
10. `[FOUNDER-DASHBOARD]` **Invoice verification:** invoice generated, correct amount, VAT = none.
11. `[DESKTOP/READ-ONLY]` **Entitlement transition:** confirm the workspace resolves to the paid plan (`subscription_status = active`, correct plan/limits).
12. `[FOUNDER-DASHBOARD]` **Portal plan change** → Professional; confirm **single active subscription** (no stacking) + correct proration (as in sandbox).
13. `[FOUNDER-DASHBOARD]` **Cancellation** → at period end; confirm entitlement continues to period end then drops.
14. `[FOUNDER-DECISION]` **Refund test:** only if a refund policy is chosen (B) — otherwise skip.
15. **Rollback / stop conditions:** if checkout fails closed, if the webhook doesn't reach the Worker, or if entitlement doesn't transition → STOP, roll the Worker back to the recorded rollback ID, do not onboard a customer.
16. `[CLI/DEPLOY]` **Release-ledger update:** record live/rollback Worker IDs, tag, migration state, and the live-cutover facts in the CHANGELOG.

---

## D. First-customer onboarding checklist + support playbook

### Onboarding acceptance checklist (`[FOUNDER-DASHBOARD]` founder runs each; `[DESKTOP/READ-ONLY]` verifies evidence)

| Step | Expected customer-visible result | Evidence to capture | Stop condition | Automatable later? |
|---|---|---|---|---|
| Signup | account created, verification email received | email delivery + audit event | no email / error leak | partly |
| Account verification | verified state | audit event | token invalid/expired | yes |
| Workspace creation | workspace visible | D1 row | error | yes |
| Domain verification | domain verified | verification record | verify loop fails | yes |
| First scan | scan completes, 8 domains render | scan snapshot, `scan_quality=complete` | partial/empty scan | yes |
| First findings | findings + honest coverage states | screenshot | false "healthy" on missing evidence | partly |
| Report / PDF | Executive PDF generates, ASCII-clean, real logo | PDF file | render error / over-claim wording | partly |
| Alert | at least one canonical alert with deep link | alert + email | no alert / broken link | yes |
| Remediation | canonical remediation shows | screenshot | invented advice | yes |
| Weekly digest | next real Monday, honest quiet/coverage state | digest email | duplicate/noisy/false-quiet | on Monday |
| Checkout | paid plan, consent captured | `terms_consent: accepted` | consent skipped | yes |
| Portal | plan change works, single subscription | D1 single row | stacking | yes |
| Cancellation | period-end cancel | audit event | immediate loss of access | yes |
| Support contact | `hello@` reachable | reply | unrouted | manual |
| Data deletion / retention | deletion honoured; retention explained | audit + email | "removed" that isn't | partly |

### First-customer support / playbook (`[DESKTOP-DONE]` drafts)
- **Welcome:** what CyberMeters does / does not do (link the `CAPABILITIES.md`-aligned known-limitations disclosure), the eight domains, how to read coverage states honestly, where to get help (`hello@cybermeters.com`).
- **Incident / escalation path:** customer-reported issue → triage → if security/tenant/billing/data-integrity → treat as priority per the incident runbook; acknowledge same day (best-effort for the controlled beta, no SLA promise).
- **Cancellation / refund script:** cancellation is self-service in the billing portal and effective at period end; refunds follow the chosen policy (B) — statutory rights always honoured.
- **Known-limitations disclosure:** external-observation only; Brand Protection is bounded/partial; passive checks, not full DAST; not SIEM/EDR/NDR/dark-web; independent pentest status stated honestly (see F). Must match `CAPABILITIES.md` exactly.

---

## E. Public-claims consistency audit (remaining live surfaces)

Compared against `CAPABILITIES.md` + `PUBLIC-CLAIMS-TRUTH-AUDIT.md`. Focused on remaining live surfaces only; **no visual redesign**.

**Confirmed intact:**
- Eight-domain model intact on the homepage; no ninth domain.
- No full-DAST / SIEM / EDR / NDR / dark-web / exhaustive-phishing claims found.
- Independent pentest is not claimed anywhere.

**Drift findings (patch where settled, else flag):**
1. **P2 — Vendor Risk / Supply Chain still live as reachable surfaces** (`/ws/vendors`, `/ws/supply-chain`, portfolio copy, invitation/onboarding/academy). `CAPABILITIES.md` marks these **Retired**, but the customer surfaces still exist. → **[FOUNDER-DECISION already made — Option B]**; execution is the queued Vendor/Supply retirement episode (post-go-live). Until executed, this is a known contradiction between the register and the live UI. Recommend either executing the retirement before first sale OR (interim) suppressing the nav entries.
2. **P3 — Brand wording:** ensure Brand Protection copy reflects **bounded/partial** evidence, not a strong phishing-protection guarantee (aligns with the B-lane recommendation to suppress the strong claim until registered-lookalike acceptance). → wording patch, **[FOUNDER-DECISION]** on final phrasing.
3. **P3 — "Real-time" on the invitation landing** → "scheduled/continuous". Settled-wording patch candidate.
4. **P3 — "full protection against spoofing"** (email page) → outcome-accurate wording. Settled-wording patch candidate.
5. **P3 — SEO meta names only four domains** → eight-domain description. Settled-wording patch candidate.
6. **SPF include-aware detection must NOT be described as live** until deployed — currently no surface claims it (good); keep it out of copy until the Worker deploy lands.

Patches 3/4/5 are settled-wording and can be prepared as a focused docs/copy PR; 1 and 2 carry founder-scope decisions and are flagged, not merged.

---

## F. Independent pentest decision pack

| Option | Scope | Must-test | Deliverables | Retest | Disclosure language | Risk | Scheduling | May claim |
|---|---|---|---|---|---|---|---|---|
| **1. Scoped pentest BEFORE first controlled sale** *(recommended)* | authenticated web/API, founder-controlled env with realistic (not real-customer) data | tenant isolation/IDOR, auth/session/MFA, billing/webhook abuse, R2/PDF authz, live OAuth, rate limits | report + P0/P1 list | **mandatory** on P0/P1 | "independently security-tested (scoped web/API), [date], scope: …" — only after the report + retest complete | small residual (bounded scope) | depends on freelancer/boutique availability (~3–5 day engagement) | "independently pentested" (scoped) once done; NOT "fully pentested" |
| **2. Scoped pentest AFTER first private customer, before public beta** | same, but first customer runs pre-pentest under honest disclosure | same | same | mandatory | first customer told "pre-independent-audit controlled beta" in the agreement | higher — a real customer before third-party eyes | more flexible | cannot claim independently pentested to that first customer |
| **3. Full public-beta-gate pentest only** | broad web/API + infra | superset | full report | mandatory | full "independently pentested" | highest pre-that-gate exposure | longest (enterprise scheduling) | full claim only after it |

**Feed the pentester** `CAPABILITIES.md` + `SECURITY-VERIFICATION-MATRIX.md` so they focus on human/logic gaps rather than re-proving the 204-assertion fixture layer — makes the bounded engagement efficient. **[FOUNDER-DECISION]** — the choice most affects the go-live timeline. The Desktop recommendation is **Option 1**.

---

## Remaining actions — categorised

**`[DESKTOP-DONE]` (this pack):** legal consistency matrix · commercial decision register · Stripe action sheet · onboarding checklist · support/cancellation playbook · public-claims drift findings · pentest decision pack. Settled-wording copy patches (E3/E4/E5) are drafted-ready.

**`[FOUNDER-DECISION]`:** refund detail (B/A#11) · liability review (A#17, external) · grace/cancellation/proration disclosure sentences (B, wording-only) · Brand final phrasing (E2) · Vendor/Supply interim suppression vs retire-first (E1) · pentest option (F).

**`[FOUNDER-DASHBOARD]`:** all of section C steps marked so (live account identity, Terms/Privacy URLs, prices/portal config, webhook, real checkout + acceptance).

**`[CLI/DEPLOY]`:** rebase #232 · merge #232 at go-live · Worker deploy with live-key config (its own window) · SPF Worker deploy (separate window) · release-ledger update · (optionally) the E3/E4/E5 wording PR.

**`[EXTERNAL-PENTESTER]`:** the chosen scoped engagement + P0/P1 retest before the disclosure claim is made.

---

`GO-LIVE COMMERCIAL/LEGAL PACK COMPLETE / FOUNDER DECISIONS AND LIVE ACTIONS PENDING`
