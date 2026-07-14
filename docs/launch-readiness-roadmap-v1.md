# CyberMeters — Launch Readiness Roadmap v1

> **Status: Historical / Superseded (15 July 2026).** Retained for historical
> context; no longer a source of truth. Canonical roadmap:
> `docs/ROADMAP-TO-FIRST-PAYING-CUSTOMER.md` · current canonical episode and
> release facts: `CLAUDE.md` · shipped truth: `CHANGELOG.md`.

**Version:** 1.0 | **Date:** June 2026 | **Status:** Superseded (was: Active Operational Plan)

**Scope:** Pre-launch blockers, must-haves, GTM, pricing validation, launch criteria  
**Core question answered:** *What must happen before CyberMeters can accept its first paying customer?*

> This document defines the concrete, sequenced work required between the current state and the moment CyberMeters charges its first customer. It does not redesign the platform, the pricing, or the commercial packaging. It defines the gap between what exists and what a paying customer requires.

---

## Table of Contents

1. [Current Product Maturity Assessment](#1-current-product-maturity-assessment)
2. [Launch Blockers](#2-launch-blockers)
3. [Must-Have Before First Paying Customer](#3-must-have-before-first-paying-customer)
4. [Nice-To-Have After Launch](#4-nice-to-have-after-launch)
5. [Consultant / vCISO Acquisition Strategy](#5-consultant--vciso-acquisition-strategy)
6. [MSP Acquisition Strategy](#6-msp-acquisition-strategy)
7. [First 90 Days Go-To-Market Plan](#7-first-90-days-go-to-market-plan)
8. [Pricing Validation Plan](#8-pricing-validation-plan)
9. [Customer Feedback Loop Design](#9-customer-feedback-loop-design)
10. [Recommended Launch Criteria](#10-recommended-launch-criteria)

---

## 1. Current Product Maturity Assessment

### Platform Maturity by Area

| Area | Maturity | Assessment |
|---|---|---|
| Core Scanner Engine | 92% | Production quality. DNS, SSL, headers, email security, subdomains, takeover detection, asset exposure all live and reliable. Minor edge cases remain. |
| ASM Engine | 82% | All primary modules live. Vendor risk, SaaS exposure, third-party detection, brand monitoring, certificate intelligence all operational. |
| Reporting Platform | 90% | Executive reports, workspace reports, scheduled reports, PDF generation all working. White-label output pending. |
| Historical Tracking | 90% | Score history, finding history, BRS trend, asset events all live. Historical data is retained and queryable. |
| Asset Inventory | 90% | Subdomain discovery, asset exposure, certificate intelligence live. Dedicated asset API pending. |
| Portfolio Platform | 85% | Portfolio dashboard, cross-workspace alerts, and trend reports operational. Portfolio-level intelligence aggregation working. |
| Product Platform | 35% | **Critical gap.** Authentication, RBAC, domain verification, and notifications are complete. Billing, self-service onboarding, feature gating, and customer portal are not. |
| Commercial Readiness | 50% | Commercial packaging approved and documented. Stripe architecture designed. No payment processing implemented. No pricing page. No upgrade flow. |

### What Is Already Working

The scanning and intelligence engine is production-grade. A customer who gets access to CyberMeters today receives:

- Continuous attack surface monitoring with historical tracking
- Business Risk Score with grade, narrative, and category breakdown
- Cyber Essentials readiness assessment
- Vendor risk and SaaS exposure intelligence
- Executive dashboard and scheduled reports
- Portfolio monitoring across multiple workspaces
- Asset inventory with subdomain and certificate intelligence

The product quality is not the launch blocker. The commercial infrastructure is.

### What Is Missing for Launch

Three systems need to be in place before the first paying customer can be accepted:

1. **Payment processing** — customers cannot pay for a plan that has no checkout flow
2. **Feature entitlement enforcement** — customers on Free should not access Professional features; this creates both a commercial leak and a credibility risk
3. **Self-service onboarding** — a customer who discovers CyberMeters must be able to sign up, scan their domain, and see value without human intervention

Everything else is refinement. These three are binary blockers.

---

## 2. Launch Blockers

A launch blocker is any gap that would prevent a customer from successfully purchasing and using CyberMeters without manual intervention from the founding team. Each blocker below must be resolved before the launch criteria in Section 10 can be declared met.

### Blocker 1 — No Payment Processing (Critical)

**Current state:** The `subscription_accounts` table exists and tracks plan and status. All quota enforcement is live. There is no mechanism for a customer to pay for a plan — no Stripe Checkout, no Customer Portal, no webhook handler. Plan values are set manually in D1.

**Impact:** Zero revenue is possible. Every paid customer requires manual provisioning by the founding team. This is not scalable at any volume and creates a credibility risk if a customer discovers that billing is manual.

**Resolution:** Stripe Billing Foundation sprint (see `docs/stripe-billing-architecture-v1.md`). The minimum viable billing implementation is:
- Stripe Checkout session creation (`POST /api/billing/checkout`)
- Stripe Customer Portal (`POST /api/billing/portal`)
- Webhook handler for subscription lifecycle (`POST /api/webhooks/stripe`)
- Pricing page at `/pricing`
- Plan activation on `checkout.session.completed`

**Estimated effort:** 5–7 engineering days.

---

### Blocker 2 — No Feature Entitlement Enforcement (Critical)

**Current state:** All plan limits (quotas: scan counts, domain counts, workspace counts) are enforced. Feature entitlements (boolean capability flags: is BRS available? is CE readiness available?) are not enforced. A Free user can access Professional features if they know the URL.

**Impact:** Commercial leak — customers who should be paying for Professional can access its value on Free. Credibility risk — a paying Professional customer may discover that their features are accessible for free. Investor and partner credibility risk if discovered during due diligence.

**Resolution:** Implement `hasFeatureEntitlement(plan, featureKey)` based on the approved feature map in `docs/final-commercial-packaging-v1.md`. Apply backend `403` gates to:
- `GET /api/workspaces/:id/business-risk` — Starter+
- `GET /api/workspaces/:id/cyber-essentials-readiness` — Professional+
- `GET /api/workspaces/:id/vendors` — Professional+
- `GET /api/portfolio/*` — Business+
- White-label report generation — Business+

Frontend locked states (grayed-out tabs, upgrade prompts) are the UX layer on top of backend enforcement. Backend enforcement must come first — frontend hiding alone is never sufficient.

**Estimated effort:** 3–4 engineering days (after Stripe billing is live and plan values are reliably populated by webhooks).

---

### Blocker 3 — No Pricing Page or Self-Service Upgrade Flow (Critical)

**Current state:** No `/pricing` page exists. No in-app upgrade CTA links to a payment destination. A customer who wants to upgrade has no self-service path — they would need to contact the team.

**Impact:** Zero inbound conversion from organic traffic or trials. All upgrades require manual outreach. Not viable as a commercial product.

**Resolution:**
- Public `/pricing` page with plan comparison, monthly/annual toggle, and feature matrix
- Upgrade CTAs in AccountPage and at feature lock surfaces
- UpgradeBanner component wired to `plan_limit_exceeded` and `feature_not_available` events
- CheckoutSuccessPage confirming plan activation after payment

**Estimated effort:** 3–4 engineering days (frontend, built on top of billing endpoints).

---

### Blocker 4 — No Terms of Service or Privacy Policy (Critical)

**Current state:** No Terms of Service or Privacy Policy exist on the platform or the website. Stripe Checkout requires linking to ToS at the point of payment.

**Impact:** Cannot legally take payment without a ToS. GDPR compliance requires a Privacy Policy for any UK/EU user who creates an account or is scanned.

**Resolution:**
- Engage a solicitor for a UK-appropriate SaaS ToS (1–2 days of legal drafting time)
- Privacy Policy covering GDPR obligations: data collected, purpose, retention, rights
- Both linked from the checkout flow and the website footer
- Cookie consent for the marketing website (if analytics are used)

**Estimated effort:** Legal review 3–5 days. Implementation (adding pages and Stripe links) 1 day.

---

### Blocker 5 — No Reliable Self-Service Signup Flow (High)

**Current state:** Authentication is implemented (signup, login, session management). It is not known whether the signup flow is polished enough for a cold visitor arriving from a marketing campaign — no user outside the founding team has tested it end-to-end.

**Impact:** A broken or confusing signup flow kills conversion at the top of the funnel. The cost of a bad first impression with an early-adopter customer (likely a vCISO or IT Manager who was genuinely considering purchase) is disproportionate — they will not return.

**Resolution:**
- End-to-end user testing of the signup → first scan → first BRS result flow with at least 3 external testers
- Onboarding improvements: a clear "add your first domain" prompt on first login, a first-scan result that immediately shows value (BRS grade visible, Cyber Essentials tab locked but visible)
- Error state testing: what happens when a scan fails? What happens if a domain doesn't resolve?

**Estimated effort:** 2–3 engineering days for polish and testing.

---

### Blocker 6 — No Support Channel (High)

**Current state:** No customer-facing support mechanism exists. No email address, no help documentation, no chat widget, no contact form.

**Impact:** A paying customer who encounters a problem has no recourse. This is a churn trigger — if a customer cannot get help, they cancel. Early customers are disproportionately important: each one is a potential case study, referral source, and product feedback contributor.

**Resolution:**
- A support email address (e.g. support@cybermeters.com) that reaches the founding team, configured before first paid customer
- A basic FAQ or Getting Started page covering: how to add a domain, how to read the BRS, what Cyber Essentials Readiness measures, how to generate a report
- Response time commitment: within 24 hours for Professional, within 48 hours for Starter

**Estimated effort:** 1 day (email setup and basic help content).

---

### Blocker 7 — No White-Label Report Output (High, for Business tier)

**Current state:** Executive reports are generated and downloadable as PDF. They carry CyberMeters branding. No white-label option exists.

**Impact:** The Business plan's two primary upgrade drivers — white-label reports and portfolio monitoring — cannot be offered if white-label is not implemented. Consultants and MSPs who are the highest-value early customers will not convert to Business without it.

**Resolution:**
- White-label report generation: customer logo, company name, and colour scheme applied to the PDF output
- Logo upload in account settings
- Report template selection (at minimum: CyberMeters branded vs. white-label)

**Estimated effort:** 3–5 engineering days. Can follow initial launch if the initial target is Starter and Professional customers only.

---

## 3. Must-Have Before First Paying Customer

These items define the minimum viable commercial product. Nothing below this line is optional for a paid customer.

### Commercial Infrastructure

| Item | Status | Required For |
|---|---|---|
| Stripe Checkout session endpoint | Not built | Any paid plan |
| Stripe Customer Portal endpoint | Not built | Plan management, cancellation |
| Stripe webhook handler | Not built | Plan activation, renewal, cancellation |
| Pricing page (`/pricing`) | Not built | Inbound conversion |
| Upgrade CTA flow in product | Not built | Trial-to-paid conversion |
| CheckoutSuccessPage | Not built | Post-payment confirmation |
| Feature entitlement enforcement (backend) | Not built | Plan integrity |
| Feature lock states in UI (frontend) | Not built | Upgrade motivation |
| Invoice history in AccountPage | Not built | Paying customer trust |

### Legal and Trust

| Item | Status | Required For |
|---|---|---|
| Terms of Service | Not drafted | Taking any payment (Stripe requirement) |
| Privacy Policy | Not drafted | GDPR compliance for any UK user |
| Cookie consent | Not implemented | Any analytics/tracking on marketing site |
| Data Processing Agreement template | Not drafted | Business and Enterprise customers who require one |

### Onboarding and Support

| Item | Status | Required For |
|---|---|---|
| Support email address | Not configured | Any paying customer |
| Basic help documentation | Not written | Self-service onboarding |
| First-login onboarding flow (domain prompt) | Not built | Cold trial conversion |
| End-to-end signup flow tested externally | Not done | Confidence in conversion funnel |

### Plan Integrity

| Item | Status | Required For |
|---|---|---|
| `hasFeatureEntitlement()` helper | Not built | Feature enforcement |
| BRS gated at Starter (Free users see locked preview) | Not built | Starter conversion |
| Cyber Essentials gated at Professional (Starter sees locked tab) | Not built | Professional conversion |
| Portfolio Monitoring gated at Business | Not built | Business conversion |
| White-label gated at Business | Not built | Plan integrity |

### The Absolute Minimum (First Paid Customer Threshold)

If white-label is not yet implemented, the first paying customer can be a Starter or Professional customer — an IT Manager or compliance-driven SMB. The Business tier (consultants, MSPs) requires white-label. The sequencing therefore is:

**Phase A — Accept first Starter / Professional customer (2–3 weeks)**
1. Stripe billing (checkout, portal, webhooks)
2. Pricing page and upgrade flow
3. Feature entitlement enforcement for BRS and CE Readiness
4. Terms of Service and Privacy Policy
5. Support email

**Phase B — Accept first Business customer (1–2 weeks after Phase A)**
6. White-label report output
7. Business feature entitlement enforcement (portfolio, white-label)
8. Business upgrade CTA and UI states

---

## 4. Nice-To-Have After Launch

These items add commercial and product value but do not block the first paying customer. They should be prioritised in the first 60 days post-launch based on customer feedback.

### Product Refinements

| Item | Commercial Value | Priority |
|---|---|---|
| Dedicated Asset Inventory API | Enables asset-first workflows for technical customers | High post-launch |
| CE Readiness report as a standalone downloadable PDF | Strongest lead magnet for Professional | High post-launch |
| BRS trend chart showing 90-day history | Makes Starter stickier; board meeting value | Medium |
| Scheduled report delivery improvements (custom subject lines, delivery timing) | Professional and Business retention | Medium |
| Subdomain takeover remediation guidance in findings | Increases finding quality and customer action rate | Medium |
| In-app domain verification status badge | Trust signal during customer onboarding | Low |

### Commercial Features

| Item | Commercial Value | Priority |
|---|---|---|
| Annual billing default on pricing page | Increases ACV by 20%, reduces churn | High post-launch |
| Referral or partner programme (affiliate links) | Consultant and MSP acquisition channel | Medium |
| Cyber Essentials Readiness Report lead magnet (gated by email) | Top-of-funnel SMB acquisition | High (marketing, not engineering) |
| In-app NPS survey | Early customer feedback collection | Medium |
| Usage dashboard in AccountPage | Reduces support queries about quotas | Low |

### Enterprise Readiness (Deferred)

| Item | Commercial Value | Priority |
|---|---|---|
| SSO / SAML integration | Enterprise and large MSP requirement | Post Business-tier launch |
| MSP Dashboard (purpose-built multi-tenant view) | Enterprise tier primary driver | Post Business-tier launch |
| Custom report templates | Enterprise tier differentiator | Post Business-tier launch |
| Data Processing Agreement (executed, not just templated) | Enterprise procurement requirement | Post Business-tier launch |
| Audit log export | Enterprise compliance requirement | Post Business-tier launch |
| Dedicated onboarding sessions | Enterprise differentiator | Post Business-tier launch |

---

## 5. Consultant / vCISO Acquisition Strategy

Consultants and vCISOs are the highest-priority first-customer segment. They convert fast, they convert at Business (high ARR), and each one brings downstream SMB customers through their client relationships.

### Target Profile

UK-based security consultants, fractional CISOs, and small security consultancies who:
- Serve 5–20 UK SMB clients
- Currently perform CE gap assessments manually or not at all
- Charge clients for security advisory and reporting
- Need professional, client-facing deliverables
- Have a business need for white-label output

### Acquisition Approach

**Step 1 — Identify the right consultants (Week 1)**

The UK vCISO and security consultant community is small and concentrated. It is present in:
- LinkedIn (search: "vCISO", "virtual CISO", "fractional CISO", UK, 1–10 person company)
- CREST member directory (accredited security consultancies)
- ISACA UK chapter membership
- (ISC)² UK chapter
- Dedicated vCISO Slack communities and LinkedIn groups

Build a targeted list of 50–100 consultants before any outreach begins. Quality over quantity — the first 10 consultants who trial the product will shape the product's early trajectory.

**Step 2 — Outreach with a specific offer (Week 2–3)**

Direct LinkedIn message, not a marketing email. The message must be specific, credible, and immediately valuable:

> *"Hi [Name], I saw your work in [context — shared group, post, mutual connection]. I've built a platform that does continuous Cyber Essentials readiness monitoring and produces white-label reports for SMB clients. I'd like to give you a 30-day Business trial to use with one of your clients — no payment required. If it saves you time on your next CE engagement, I'd love your feedback. Would a brief call work?"*

This is not a sales pitch. It is a product research conversation disguised as a gift. The 30-day Business trial (white-label included) demonstrates the product in the context the consultant actually cares about. It also creates a natural follow-up: "Did it save you time? Did your client like the report?"

**Step 3 — Onboard personally (Week 2–4)**

The first 5–10 consultant customers should be onboarded personally by the founder. This means:
- A 20-minute onboarding call to set up their first workspace and run their first scan
- A walkthrough of the white-label report output
- A follow-up email 7 days later asking for feedback
- A follow-up call at the end of the trial to discuss conversion

This is not scalable. It is intentionally not scalable. The intelligence gathered from 10 personal onboarding conversations is worth more than 100 self-service signups at this stage.

**Step 4 — Convert to Business (End of trial)**

The conversion conversation should happen at day 25 of a 30-day trial. The consultant has now used the platform with at least one client. The questions to ask:

1. Did the white-label report meet the quality standard you need for client work?
2. How much time did it save you compared to your previous process?
3. Would you pay £399/month if it saved you that time every month?

If the answer to Q3 is yes, the conversion is immediate. If the answer is "I'd need it to also do X", that is product intelligence. Either outcome is valuable.

**Conversion target:** 4 Business customers from the first 10 consultant trials (40% conversion rate). This generates £1,596/month ARR from the first cohort.

---

### Messaging for Consultants

**LinkedIn connection request:**
> *"I've built a tool for UK security consultants doing CE gap assessments — generates white-label readiness reports for clients automatically. Would be great to connect."*

**First message after connection:**
> *"Doing a small founder-led beta with 10 UK security consultants. Free 30-day Business access if you want to try it with a client. Happy to onboard you personally — takes about 20 minutes. Interested?"*

**Trial activation email:**
> Subject: Your CyberMeters Business trial is ready
>
> I've activated your 30-day Business trial. Here's how to get the most out of it in the first week:
> 1. Add a client domain as a new workspace (takes 2 minutes)
> 2. Run your first scan
> 3. Open the report export settings and switch on white-label
> 4. Download the PDF and see if it meets your client delivery standard
>
> I'll check in on day 7 to see how it's going.

---

## 6. MSP Acquisition Strategy

MSPs are the highest long-term value segment but require more relationship-building before they commit. The MSP acquisition strategy runs in parallel with consultant acquisition but at a slower cadence — begin at week 4–6 once at least 2 consultant customers are onboarded and can serve as reference points.

### Target Profile

UK-based MSPs with:
- 10–80 SMB clients
- An active or planned security services line
- A need to offer CE readiness monitoring or reporting to clients
- An interest in white-label client delivery

### Acquisition Approach

**Step 1 — Community presence before outreach**

MSPs are sceptical of cold outreach from tools they haven't heard of. Before direct outreach, establish a presence in the communities where MSPs talk:
- CompTIA UK community
- MSP community forums (r/msp on Reddit, MSP Alliance)
- LinkedIn MSP groups (UK MSP, IT Service Management)
- MSPU (MSP University) community

The goal is not to pitch — it is to be recognisably present and helpful. Answer questions about Cyber Essentials. Share the CE content from the marketing content strategy. Mention CyberMeters when directly relevant.

**Step 2 — Targeted outreach with a specific MSP value proposition**

The MSP pitch is different from the consultant pitch. It is not about saving time on an engagement — it is about adding a revenue line:

> *"Hi [Name], I've built a platform for MSPs who want to offer Cyber Essentials readiness monitoring as a managed service. Business tier gives you a portfolio view of all client workspaces, white-label reports under your brand, and automated monthly delivery — all for £399/month regardless of how many clients you manage up to 25. I'm working with a small group of MSPs at launch and would like your feedback. Interested in a 30-day trial?"*

**Step 3 — The MSP onboarding experience**

MSPs need to see the portfolio view before they can evaluate the platform. The onboarding for an MSP should be structured around this:

1. Set up 3 client workspaces (representing 3 clients)
2. Run scans on all 3 simultaneously
3. View the portfolio dashboard to see all 3 clients' BRS grades in one view
4. Generate white-label reports for all 3 clients with their logo
5. Set up scheduled monthly report delivery for all 3

This 5-step onboarding (20–30 minutes) demonstrates the core value. An MSP who completes this onboarding will convert at a high rate.

**Step 4 — The MSP conversion conversation**

At day 25 of the trial:

1. How many client workspaces are you actively monitoring?
2. Is the portfolio view saving you time compared to your previous approach?
3. Are the white-label reports meeting the quality standard you need for client delivery?
4. What would make this tool a permanent part of your service stack?

**Conversion target:** 2 Business customers from the first 8 MSP trials (25% conversion rate). MSP conversion is slower but higher LTV — at Business annual billing (£3,828), each MSP conversion is meaningful.

### MSP Partner Programme (Month 2–3)

Once 2–3 MSP customers are live, formalise a lightweight partner programme:
- A named "CyberMeters Partner" designation for MSPs on Business
- A co-branded one-page partner spec sheet MSPs can use when pitching CE services to their clients
- A partner pricing discussion for MSPs managing 25+ clients who need Enterprise

The partner programme does not require new product work. It requires documentation, a partner landing page, and a designated contact for partner MSPs.

---

## 7. First 90 Days Go-To-Market Plan

### Phase 1 — Closed Beta (Days 1–30)

**Goal:** 5 paying customers. No public launch. Founder-led.

The closed beta phase is not about acquisition at scale — it is about validating that the payment flow works end-to-end, that the product delivers value in a paying context, and that early customers are willing to provide feedback. Every paying customer in this phase is a reference, a case study candidate, and a product intelligence source.

**Week 1 — Billing infrastructure live**
- Stripe Checkout and webhook handler deployed to production
- Pricing page live at `/pricing`
- Feature entitlement enforcement live for BRS (Starter) and CE Readiness (Professional)
- Terms of Service and Privacy Policy live
- Support email configured

**Week 2 — First outreach to consultants**
- Personal LinkedIn outreach to 20 target consultants
- Goal: 5 trial activations by end of week 2
- Founder personally onboards each trial customer

**Week 3 — First onboarding conversations**
- 20-minute onboarding call with each trial customer
- First scan runs, first BRS grade seen, first CE readiness report downloaded
- Collect: what did they expect? what surprised them? what's missing?

**Week 4 — First conversion attempt**
- Follow-up with each trial customer: ready to convert?
- Target: 2 Professional and 2 Business paying customers by end of week 4
- First ARR: ~£(149×2) + £(399×2) = £1,096/month

**White-label readiness:** If white-label is not yet complete by week 4, the first Business conversions may need to wait. Starter and Professional conversions can proceed. Do not offer Business without white-label — it is the primary Business value proposition for consultants.

---

### Phase 2 — Soft Public Launch (Days 31–60)

**Goal:** 15 paying customers. First content marketing live.

**Week 5–6 — Content foundation**
- Publish first CE content piece: *"Is your business Cyber Essentials ready? A guide for UK IT Managers"*
- Publish pricing page with plan comparison (already live from Phase 1)
- Set up Google Search Console and basic analytics
- LinkedIn Company Page for CyberMeters with first 3 posts (CE education, product announcement, consultant use case)

**Week 6–7 — Lead magnet launch**
- Launch the Cyber Essentials Readiness Report lead magnet: enter your domain, receive a free one-page PDF
- This is a marketing landing page separate from the product trial — email capture, scan, PDF email delivery
- Email sequence: Day 1 (report), Day 3 (how to read it), Day 7 (upgrade to Professional for continuous monitoring)

**Week 7–8 — First MSP outreach**
- Personal LinkedIn outreach to 15 target MSPs
- Goal: 3 MSP trial activations by end of week 8
- Founders personally onboard MSP trials

**Metrics to track in Phase 2:**
- Visitors to `/pricing` page
- Trial signups (Free plan activations)
- Trial to Starter conversion rate
- Starter to Professional conversion rate
- Support volume and ticket categories

---

### Phase 3 — Accelerated Acquisition (Days 61–90)

**Goal:** 30 paying customers. First SMB inbound conversions via content.

**Week 9–10 — Content cadence**
- Publish second CE content piece: *"Cyber Essentials for UK government contracts: what you need to know"*
- First webinar announced: *"Is your business Cyber Essentials ready? A live readiness check"* (scheduled for week 12)
- LinkedIn posts: 3 per week (CE tips, product updates, customer stories)

**Week 11–12 — Referral activation**
- Ask each of the first 10–15 customers for one referral
- Offer a month free (for the referring customer) for each referral that converts to a paid plan
- A warm referral from a trusted consultant or IT Manager converts at a higher rate than any cold channel

**Week 12 — First webinar**
- *"Is your business Cyber Essentials ready? A live readiness check"*
- 30–45 minute webinar: live CE readiness scan on a demo domain, walkthrough of the gap report, Q&A
- Registration gated by email — adds to the nurture sequence
- CTA at end: 14-day Professional trial

**End of Day 90 targets:**
- 30 paying customers (mix: 15 Professional, 10 Business, 5 Starter)
- Monthly ARR: ~£(29×5) + £(149×15) + £(399×10) = £6,220/month
- Annual run rate: ~£74,640
- 3 case studies (one consultant, one SMB IT Manager, one MSP) in draft

---

## 8. Pricing Validation Plan

The approved pricing (Starter £29, Professional £149, Business £399) has been set based on market research and commercial judgement. Pricing must be validated against real customer behaviour within the first 90 days. The following metrics determine whether the pricing is working.

### Metrics to Track

**Conversion rates by plan:**

| Metric | Target | Action if Below Target |
|---|---|---|
| Free → Starter conversion (active Free users) | 15–25% within 30 days | Review BRS lock state — is the upgrade prompt visible enough? |
| Starter → Professional conversion | 25–35% within 90 days | Review CE Readiness lock state — is the upgrade trigger clear? |
| Professional → Business conversion | 20–30% (among consultants) | Review white-label quality — is the output meeting consultant standards? |
| Trial → Paid (any plan) | 30%+ | Review onboarding flow — do users reach value before trial expires? |

**Pricing objections to log:**

Every time a customer declines to convert or cancels, capture the stated reason. Log:
- "Too expensive" → note which plan and what they said they'd pay
- "Missing feature X" → product gap, not a pricing problem
- "Using a different tool" → competitive intelligence
- "Not the right time" → timing, not price

After 30 paying customers, audit the objection log. If more than 30% of non-conversions cite price as the primary objection, revisit the pricing decision. If fewer than 10% cite price, pricing is not the conversion bottleneck — product experience or awareness is.

**Revenue mix check (Day 60):**

| Check | Target | Concern if Failed |
|---|---|---|
| Professional accounts > 40% of paying customers | >40% | Starter is performing as a terminal plan, not a stepping stone |
| Business accounts > 20% of paying customers | >20% | Consultants and MSPs are not converting — review white-label and portfolio experience |
| Annual vs. monthly mix | >30% annual by Day 90 | Insufficient incentive for annual — review annual discount prominence on pricing page |

### Price Sensitivity Test (Month 2)

At the start of month 2, when there are 10+ paying customers, conduct a direct price sensitivity conversation with 5 of them:

> *"If the price of Professional was £199/month instead of £149, would you still be a customer?"*

If the answer is yes from 4 of 5, there is headroom to raise Professional pricing in a future commercial review. If the answer is no from 3 of 5, the £149 price point is correctly calibrated.

This is not a commitment to change pricing — it is a data collection exercise.

### Pricing Page A/B Test (Month 3)

Once traffic to `/pricing` is sufficient (100+ unique visitors per month):

- **Variant A:** Annual billing default (monthly shown as an option)
- **Variant B:** Monthly billing default (annual shown with savings badge)

Measure: checkout starts, plan selection distribution, annual vs. monthly split. The variant that produces more Professional annual checkouts wins. Run for 30 days minimum.

---

## 9. Customer Feedback Loop Design

Early customer feedback is the most valuable intelligence available to the founding team. It is not about measuring satisfaction — it is about understanding what the product is and is not doing for real users in commercial contexts. The feedback loop must be designed before the first customer is onboarded.

### Feedback Touchpoints

**Touchpoint 1 — Onboarding call (Days 1–3)**

For all beta customers (first 20) and all Business customers: a 20-minute call within the first 3 days of trial activation. The call is structured around three questions:

1. What problem were you hoping CyberMeters would solve?
2. What did you expect the product to do that it didn't do in the first 30 minutes?
3. What would make this a tool you'd use every week without thinking about it?

Record the calls (with permission). Review after every 5 calls for patterns.

**Touchpoint 2 — Day 7 email (automated)**

Sent automatically 7 days after trial activation:

> *"You've been using CyberMeters for a week. Quick question: what's one thing you wish the platform showed you that it doesn't currently? Reply to this email — I read every response."*

This is founder-signed, not a support template. Replies from early customers get a personal response within 24 hours.

**Touchpoint 3 — Day 25 check-in (conversion call)**

For trial customers approaching the end of their trial: a 15-minute call or personalised email. Questions:

1. Has the platform saved you time or effort in the last 25 days?
2. Is there anything preventing you from converting to a paid plan?
3. What would make this a permanent part of your workflow?

This is simultaneously a customer feedback call and a conversion conversation. It is not a sales call — it is a genuine enquiry about whether the product is working.

**Touchpoint 4 — 30-day post-payment survey (paying customers only)**

After a customer has been paying for 30 days, send a short survey (4 questions, 2 minutes):

1. On a scale of 1–10, how likely are you to recommend CyberMeters to a colleague?
2. What is the single most valuable thing CyberMeters does for you?
3. What is the single biggest gap or frustration?
4. What one feature would make you recommend this to someone else immediately?

Track NPS (question 1). The raw NPS number is less useful than the verbatim answers to questions 2–4.

**Touchpoint 5 — Churn interview (cancelled customers)**

If a customer cancels, reach out personally within 24 hours:

> *"I saw you've cancelled your CyberMeters subscription. I'd really like to understand what went wrong — it's the most useful feedback I can get at this stage. Would you be willing to spend 15 minutes on a call with me?"*

Churn interviews are more valuable than NPS surveys. A customer who leaves and tells you why has given you information worth more than 10 customers who stay and say nothing.

### Feedback Aggregation

All feedback — from calls, emails, surveys, and support tickets — should be logged in a single document or lightweight CRM before 10 customers are onboarded. The minimum structure:

| Customer | Date | Feedback Type | Verbatim | Category | Action |
|---|---|---|---|---|---|
| [Name] | [Date] | Onboarding call | "I expected the report to include remediation steps" | Product gap | Product backlog |
| [Name] | [Date] | Day 7 email | "I wish I could see all my clients' BRS grades on one screen" | Business tier value | Confirms Portfolio Monitoring priority |

Review this log weekly for the first 90 days. Patterns in the first 10 feedback responses will correctly prioritise the product roadmap better than any internal planning session.

---

## 10. Recommended Launch Criteria

CyberMeters is ready to accept its first paying customer when all of the following criteria are met. These are binary — each is either complete or not.

### Commercial Infrastructure

| Criterion | Status |
|---|---|
| Stripe Checkout: customer can initiate and complete a payment for Starter, Professional, or Business | Not met |
| Stripe webhooks: plan activates in D1 automatically on successful payment | Not met |
| Stripe Customer Portal: customer can manage, upgrade, downgrade, or cancel without contacting support | Not met |
| Pricing page: `/pricing` is live with plan comparison, monthly/annual toggle, and checkout CTAs | Not met |
| Post-checkout confirmation: customer sees their activated plan immediately after payment | Not met |
| Invoice history: paying customer can view and download past invoices | Not met |

### Feature Integrity

| Criterion | Status |
|---|---|
| Business Risk Score is accessible to Starter+ customers and locked (with upgrade prompt) for Free customers | Not met |
| Cyber Essentials Readiness is accessible to Professional+ customers and locked for Starter customers | Not met |
| Portfolio Monitoring is accessible to Business+ customers and locked for Professional customers | Not met |
| White-label reports are accessible to Business+ customers and locked for Professional customers | Not met |
| All entitlement enforcement is enforced at the backend API level, not only in the frontend | Not met |

### Legal and Trust

| Criterion | Status |
|---|---|
| Terms of Service is live and linked from the checkout flow and website footer | Not met |
| Privacy Policy is live and linked from the checkout flow and website footer | Not met |
| Support email address is configured and monitored (response within 24 hours for Professional) | Not met |

### Product Quality

| Criterion | Status |
|---|---|
| Signup → first scan → BRS result flow has been tested end-to-end by at least 3 people outside the founding team | Not met |
| At least one generated report (Professional PDF) has been reviewed by a person who would plausibly receive it as a client document | Not met |
| At least one white-label report has been reviewed by a consultant or MSP who delivers client reports professionally | Not met |
| Scan failure states are handled gracefully (no unhandled errors shown to users) | Status unknown — verify |

### Confidence Threshold

| Criterion | Status |
|---|---|
| The founding team would be comfortable if a journalist or investor signed up tomorrow and went through the full product experience | Not met |
| The founding team would be comfortable if the first paying customer had a problem and contacted support at 9am on a Monday | Not met |

---

### Summary Checklist

The answer to *"What must happen before CyberMeters can accept its first paying customer?"* is:

1. **Stripe billing is live** — checkout, portal, webhooks, pricing page
2. **Feature entitlement enforcement is live** — plan-gated features at the backend
3. **Terms of Service and Privacy Policy are live**
4. **Support email is configured and monitored**
5. **Signup-to-value flow has been tested externally**
6. **White-label reports work** (for Business tier customers)

Items 1–5 define the Starter and Professional launch threshold. Item 6 defines the Business launch threshold. Nothing else on this list is optional for a paying customer. Everything else is post-launch iteration.

**Estimated time to launch readiness from current state:** 3–4 weeks of focused engineering and legal work, assuming no other priorities.

---

*CyberMeters Platform — Launch Readiness Roadmap v1 — June 2026*  
*Next review: when all launch criteria in Section 10 are met, or at Day 30 of the closed beta.*
