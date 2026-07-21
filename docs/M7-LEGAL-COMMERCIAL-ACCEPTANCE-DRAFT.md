# M7 Go-Live — Legal (C) + Commercial (B) Acceptance Draft

Status: **DRAFT — FOUNDER LEGAL/COMMERCIAL APPROVAL PENDING.** Prepared 21 July 2026.
Not legal advice. Wording below is a starting draft to be reviewed, filled (placeholders), and legally approved by the founder before it goes live. These are the **B (commercial decisions)** and **C (legal wording)** that gate the M7 live-mode cutover (per `docs/ROADMAP-TO-FIRST-PAYING-CUSTOMER.md` and [[m7-pricing-lockstep-shipped]]). ⚠️ **Governing law must be SCOTLAND (Scots law) — the current Terms wrongly say "England and Wales"; the sole trader Turhan Acar is based in Scotland (Edinburgh, 12+ years). See C0.**

Authority context: contracting entity = **sole trader Turhan Acar**, **not VAT registered** ([[contracting-entity-sole-trader]]); disclosure minimisation applies — legal transparency is fine, but no tech secrets/thresholds/table names ([[public-disclosure-minimisation]]).

---

## Part C — Legal wording (P1 closures)

### C0 — Governing law & jurisdiction (currently WRONG: says England & Wales)

Current Terms (`TermsPage.jsx` §governing law): *"These Terms are governed by and construed in accordance with the laws of England and Wales... the exclusive jurisdiction of the courts of England and Wales."* — WRONG for a Scotland-based sole trader.

**Draft replacement:**
> These Terms are governed by and construed in accordance with the **law of Scotland**. Any dispute arising out of or in connection with these Terms shall be subject to the exclusive jurisdiction of the **Scottish courts**.

Notes: Scotland has a separate legal system from England & Wales (separate courts and contract-law rules). This is the founder's home jurisdiction (Edinburgh). For UK **consumers**, mandatory local consumer-protection law still applies regardless of the chosen governing law — that's fine and expected; the governing-law clause is still Scots law. Also review any other doc (Privacy/DPA) for stray "England and Wales" references and change to Scotland.

### C1 — Contracting-entity identity (currently MISSING everywhere)

Current state: Terms/Privacy/DPA all say "CyberMeters" generically; no legal entity named. Fix = insert an identity block. **Do NOT write "Scotist Ltd" anywhere** (closing).

**Draft identity block** (place at the top of Terms §1, Privacy §1, DPA §1, and the checkout/invoice footer):

> CyberMeters is a trading name of **Turhan Acar**, a sole trader established in the United Kingdom. References to "CyberMeters", "we", "us" or "our" mean Turhan Acar trading as CyberMeters. Contact: **[SUPPORT EMAIL]**. Business address: **[BUSINESS/CORRESPONDENCE ADDRESS]**.

FOUNDER FILL — RESOLVED 21 Jul 2026:
- `[SUPPORT EMAIL]` → **hello@cybermeters.com** ✓
- `[BUSINESS/CORRESPONDENCE ADDRESS]` → **founder's HOME address (Scotland; full address held in Stripe KYC — deliberately NOT stored in-repo, data-minimisation) for the beta**, carried on Stripe invoices (NOT published on the public Terms page — see legal PR #232). ⚠️ Founder decision: accept using the home address for the beta; **switch to an office/correspondence address after the first 10 paying customers**. (Sole traders have no Companies House number — do not invent one.)
- ICO: gate-12 item — confirm registration + pay the data-protection fee (see ICO explainer). A fee is likely due (Tier 1, ~£40/yr).

### C2 — VAT wording (currently WRONG for a non-registered sole trader)

Current Terms § payments: *"All fees are stated exclusive of VAT unless otherwise specified."* — inaccurate; you charge no VAT.

**Draft replacement:**
> All fees are stated in pounds sterling (GBP). CyberMeters (Turhan Acar) is **not currently registered for VAT**; no VAT is charged on subscriptions and invoices will not show a VAT line. If CyberMeters becomes VAT-registered in future, fees and invoices will be updated accordingly and you will be notified.

### C3 — Subprocessor list (currently INCOMPLETE: only Cloudflare + Stripe)

The DPA subprocessor table must reflect ALL third parties that process personal data. **Missing: Resend (email delivery), Microsoft (Azure AD / Microsoft SSO).** Google OAuth: **CONFIRMED NOT USED (founder, 21 Jul — Microsoft SSO only for now)** → no Google row. Final subprocessor list = the 4 rows below.

**Draft complete subprocessor table:**

| Sub-Processor | Service | Location |
| --- | --- | --- |
| Cloudflare, Inc. | Compute (Workers), database (D1), storage (R2), CDN delivery (Pages) | US / Global edge |
| Stripe, Inc. | Payment processing and subscription management | US / EU |
| Resend (Plus Five Five, Inc.) | Transactional email delivery (alerts, reports, lifecycle and billing emails) | US |
| Microsoft Corporation (Microsoft Entra ID) | Authentication for customers who sign in with Microsoft SSO (processes sign-in identity: name, email, tenant/object identifiers) | US / Global |

Note (international transfers): Cloudflare/Stripe/Resend/Microsoft may process data outside the UK. Add a sentence that transfers rely on appropriate safeguards (each provider's UK/EU addendum / SCCs / UK IDTA). Keep the existing 14-day subprocessor-change-notice clause.

### C4 — Where each change lands (for the eventual docs/frontend PR — NOT done here)

- `frontend/src/pages/TermsPage.jsx` — §1 identity block; payments § VAT wording
- `frontend/src/pages/PrivacyPage.jsx` — controller identity block
- `frontend/src/pages/DpaPage.jsx` — §1 identity; subprocessor table (add 2 rows); transfer-safeguards sentence
- Checkout + invoice footer (Stripe invoice settings + app checkout copy) — identity + not-VAT note
- Cookie policy — no change needed for entity (already generic)

---

## Part B — Commercial decisions (founder must decide)

**STATUS: ALL RECOMMENDED OPTIONS APPROVED by founder, 21 July 2026.** B1 self-service cancel at period-end; B2 no refunds + 14-day trial + immediate-start consent checkbox; B3 portal-only plan changes for beta + controlled upgrade test before go-live; B4 not VAT registered; B5 GBP/UK-only for beta. These now flow into Terms + Stripe config at go-live.

Each item is a plain-English decision. Read the "What it is", pick an option, and the wording flows into Terms + Stripe config at go-live.

### B1 — Cancellation: how does a customer stop paying?

**What it is.** When a paying customer wants to stop, how do they cancel, and when does it take effect?

**Recommended.** The customer cancels themselves — no email to you, no manual work. They click "Manage Billing" in the app, which opens the Stripe billing portal, and hit "Cancel subscription". The cancellation takes effect **at the end of the period they've already paid for** (not instantly). Example: they pay monthly and cancel on the 10th — they keep full access until the end of that paid month, are **not** charged again, and then drop to the free read-only tier. This is standard SaaS, it's fair (they keep what they paid for), and it matches what the current Terms already say.

- Decision: ☐ Approve (self-service cancel, effect at period end, no mid-period refund) ☐ Change

### B2 — Refunds: do you give money back?

**What it is.** If a customer asks for a refund of fees they've already paid, do you refund?

**Recommended.** No refunds of already-paid fees, **except where the law requires it**. Two legal points:
- **Consumers** (an individual buying, not a company) who buy online normally get a **14-day "cooling-off" period** to cancel and get their money back. BUT for a digital service that starts straight away, you're allowed to ask them to tick a box at checkout: *"I want to start using CyberMeters now and I understand I give up my 14-day right to a refund."* Once they tick it and start using it, the 14-day refund right no longer applies. This is the normal SaaS pattern.
- **Business customers** (B2B) get **no** 14-day cooling-off at all.

So the practical policy: no refunds of prepaid fees; the free **14-day trial** already lets people try before paying (which reduces refund requests); add the "start now / I waive my 14-day right" checkbox at checkout for consumers.

- Decision: ☐ Approve (no refunds + rely on the trial + add the immediate-start consent checkbox) ☐ Offer a voluntary money-back guarantee (e.g. 14 or 30 days) as a trust/marketing tool ☐ Change

### B3 — Changing plan (upgrade/downgrade) and proration

**What it is.** When a customer moves between plans (e.g. Starter → Business, or Business → Professional), how is it handled, and how is the money adjusted?

**The open concern from testing.** The in-app "Upgrade to X" button starts a **fresh** checkout. We do **not** yet know for certain whether it (a) cleanly switches the existing subscription to the new plan, or (b) creates a **second** subscription alongside the old one (which would charge the customer for **both**). Important honesty note: earlier in the session I claimed (b) was happening — I **withdrew** that, because the evidence was a leftover June test subscription, not proof. So this is **unverified**, not a known bug.

**"Proration" explained.** If a customer upgrades in the middle of a paid month, "proration" means Stripe charges only the **difference** for the remaining days and credits the unused time — so they don't pay twice for overlapping days. It's the fair way to handle mid-cycle changes.

**Recommended for beta.** Keep it simple and safe:
1. For the beta, route plan changes through the **Stripe billing portal** ("Manage Billing"), where switching and proration are handled cleanly by Stripe.
2. **Before** charging any real customer, run ONE controlled test: take an account with a single active subscription, click the in-app "Upgrade", and check whether it switches the plan or creates a second subscription. If it creates a second one, it's a small fix (either point the "Upgrade" button at the billing portal, or make it cancel the old subscription first).

- Decision: ☐ Portal-only plan changes for the beta (simplest, safe) ☐ Fix the in-app Upgrade button first ☐ Change
- Required either way: the controlled upgrade test before go-live.

### B4 — VAT

**Already decided (20 Jul).** You are **not** VAT registered, so **no VAT is charged**. The prices are final (£9.99 is £9.99, nothing added). Stripe Tax stays off. You only revisit this if your yearly turnover gets close to the **UK VAT registration threshold (~£90,000)** — then registration becomes mandatory and prices/invoices get updated. Nothing to do now.

### B5 — Currency and which countries you sell to in the beta

**What it is.** Which currency do you charge in, and which countries' customers can subscribe, during the beta?

**Recommended.** **GBP (pounds) only, UK customers only**, for the beta. Selling abroad adds real complexity: EU VAT rules, US sales tax, currency conversion, and the "registrable-domain" handling for non-UK domains. For your first ~10 customers that's not worth it — stay UK-only and expand later.

- Decision: ☐ Approve (GBP / UK-only for the beta) ☐ Change

---

## Founder placeholder matrix (fill before go-live)

| # | Item | Value to lock |
| - | --- | --- |
| 0 | Governing law | **Scotland (Scots law) + Scottish courts** — change from England & Wales (C0) |
| 1 | Legal name format | "CyberMeters is a trading name of Turhan Acar, a sole trader" (confirm exact) |
| 2 | Public support email | e.g. hello@cybermeters.com |
| 3 | Public business/correspondence address | ⚠️ home vs correspondence address (privacy) |
| 4 | ICO registration + data-protection fee | confirm registered + fee paid (gate 12) |
| 5 | Google OAuth used? | confirm (affects subprocessor list) |
| 6 | B1 cancellation | approve/change |
| 7 | B2 refund + checkout consent | approve/change |
| 8 | B3 plan-change path + controlled test | approve/change |

## Sequencing

These are **preparation drafts**. Once the founder decides B1–B5 and fills the placeholders, a focused **docs/frontend PR** (CLI or docs track) lands the wording into Terms/Privacy/DPA/checkout, and the go-live live-key cutover proceeds (RC gate). Nothing here deploys or edits legal pages yet — approval first.
