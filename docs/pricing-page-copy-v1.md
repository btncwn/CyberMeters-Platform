# CyberMeters — Pricing Page Copy v1

> **Status: Historical / Superseded (16 July 2026).** Retained for historical
> context; **not** ready for implementation and **not** approved copy. Canonical
> pricing and card rules: `docs/PRICING-POLICY.md` (DECIDED 2026-07-09) · current
> canonical episode and release facts: `CLAUDE.md`.
>
> **Why superseded.** Three reasons, any one of which is disqualifying:
>
> 1. Its prices are the legacy set (£29 / £149 / £399), not the adopted tiers.
> 2. Its annual claim — *"Save 20% with annual billing — that's up to £960 off per
>    year on the Business plan"* — is banned copy. The canonical policy permits a
>    plain discount statement **only** because the adopted Stripe annual prices are
>    exactly 9× monthly; against the legacy ~20% annuals the only permitted card
>    copy is "Save with annual billing."
> 3. Its cards show **workspaces** and an **MSP dashboard row**. The canonical
>    permanent rule is that the public value metric is **monitored domains** and
>    that workspaces, users, scans/month and reports/month must never appear on a
>    pricing card.
>
> A card that states a price Stripe does not charge is, in the canonical policy's
> words, "a trust catastrophe". Do not implement any copy in this document.

**Version:** 1.0 | **Date:** June 2026 | **Status:** Superseded (was: Ready for implementation)

**Legacy pricing recorded below (NOT canonical):** Free / Starter £29/mo / Professional £149/mo / Business £399/mo / Enterprise Custom

**Scope:** Pricing page hero, plan cards, comparison table, FAQ, upgrade CTAs, BRS messaging, CE messaging

> All copy below is ready to paste into the frontend. Section headings indicate the UI component. Bracketed notes are implementation hints, not copy.

---

## 1. Pricing Page Hero

### Headline

```
Know your attack surface.
Prove your security posture.
```

### Subheadline

```
Continuous attack surface monitoring and Cyber Essentials readiness for UK businesses, consultants, and managed service providers.
```

### Supporting line [shown below subheadline, smaller]

```
Trusted by IT managers, security consultants, and vCISOs across the UK.
```

### Billing toggle [toggle component: Monthly | Annual — Save 20%]

```
Monthly    Annual  Save 20%
```

---

## 2. Plan Cards

### Free Plan Card

**Badge:** None  
**Plan name:** Free  
**Price:** £0  
**Price subline:** Forever free. No credit card required.  
**Tagline:** See your attack surface in minutes.

**Included features list:**
```
✓ 1 domain
✓ On-demand scans
✓ DNS & SSL analysis
✓ Security headers check
✓ Email security (SPF, DKIM, DMARC)
✓ Subdomain discovery
✓ Asset exposure detection
✓ 1 user
```

**Locked features teaser [grayed out, with lock icon]:**
```
🔒 Business Risk Score — upgrade to Starter
🔒 Scheduled scans & reports
🔒 Executive dashboard
```

**CTA button:** `Start for free`  
**CTA subline:** No credit card required.

---

### Starter Plan Card

**Badge:** None  
**Plan name:** Starter  
**Price:** £29 /month [or £23 /month billed annually]  
**Tagline:** Monitor, score, and report — automatically.

**Included features list:**
```
✓ Everything in Free
✓ Business Risk Score (A–F grade with full breakdown)
✓ Scheduled scans — daily, weekly, or monthly
✓ Scheduled report delivery
✓ Executive dashboard
✓ Asset change event alerts
✓ Email notifications
✓ Historical tracking (30 days)
✓ 3 domains
✓ 2 users
```

**Locked features teaser [grayed out, with lock icon]:**
```
🔒 Cyber Essentials Readiness — upgrade to Professional
🔒 Vendor risk monitoring
🔒 SaaS exposure detection
```

**CTA button:** `Start Starter trial`  
**CTA subline:** 14-day free trial. Cancel anytime.

---

### Professional Plan Card

**Badge:** `Most popular`  
**Plan name:** Professional  
**Price:** £149 /month [or £119 /month billed annually]  
**Tagline:** The compliance and risk platform for UK IT managers and security teams.

**Included features list:**
```
✓ Everything in Starter
✓ Cyber Essentials Readiness assessment
✓ Vendor risk monitoring
✓ SaaS exposure detection
✓ Third-party risk intelligence
✓ Advanced executive reports (PDF)
✓ Business Risk Score trend history (12 months)
✓ BRS category breakdown
✓ Audit trail
✓ 1-year data retention
✓ 10 domains
✓ 5 users
```

**Locked features teaser [grayed out, with lock icon]:**
```
🔒 Portfolio monitoring — upgrade to Business
🔒 White-label reports
🔒 Multi-workspace management
```

**CTA button:** `Start Professional trial`  
**CTA subline:** 14-day free trial. Cancel anytime.

---

### Business Plan Card

**Badge:** None  
**Plan name:** Business  
**Price:** £399 /month [or £319 /month billed annually]  
**Tagline:** Built for security consultants, vCISOs, and MSPs delivering security services to clients.

**Included features list:**
```
✓ Everything in Professional
✓ Portfolio monitoring (all clients in one view)
✓ White-label reports (your logo, your brand)
✓ Multi-workspace management
✓ vCISO workflow tools
✓ API access
✓ 7-year data retention
✓ Up to 25 domains
✓ 10 users
✓ Priority email support
```

**Locked features teaser [grayed out, with lock icon]:**
```
🔒 MSP dashboard — upgrade to Enterprise
🔒 SSO / SAML
🔒 Custom limits
```

**CTA button:** `Start Business trial`  
**CTA subline:** 14-day free trial. Cancel anytime.

---

### Enterprise Plan Card

**Badge:** None  
**Plan name:** Enterprise  
**Price:** Custom pricing  
**Tagline:** For MSPs and large organisations with custom scale requirements.

**Included features list:**
```
✓ Everything in Business
✓ MSP dashboard (purpose-built multi-tenant view)
✓ Custom domain and user limits
✓ SSO / SAML
✓ Dedicated onboarding
✓ Priority support with SLA
✓ Custom report templates
✓ Audit log export
✓ Data Processing Agreement
```

**CTA button:** `Talk to us`  
**CTA subline:** We'll respond within one business day.

---

## 3. Annual Billing Banner [shown above plan cards when annual toggle selected]

```
Save 20% with annual billing — that's up to £960 off per year on the Business plan.
```

---

## 4. Full Feature Comparison Table

[Table header row]

| Feature | Free | Starter | Professional | Business | Enterprise |
|---|---|---|---|---|---|
| **Scanning** | | | | | |
| On-demand scans | ✓ | ✓ | ✓ | ✓ | ✓ |
| Scheduled scans (daily/weekly/monthly) | — | ✓ | ✓ | ✓ | ✓ |
| DNS & SSL analysis | ✓ | ✓ | ✓ | ✓ | ✓ |
| Security headers check | ✓ | ✓ | ✓ | ✓ | ✓ |
| Email security (SPF, DKIM, DMARC) | ✓ | ✓ | ✓ | ✓ | ✓ |
| Subdomain discovery | ✓ | ✓ | ✓ | ✓ | ✓ |
| Asset exposure detection | ✓ | ✓ | ✓ | ✓ | ✓ |
| Subdomain takeover detection | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Risk & Compliance** | | | | | |
| Business Risk Score (A–F grade) | — | ✓ | ✓ | ✓ | ✓ |
| BRS category breakdown | — | ✓ | ✓ | ✓ | ✓ |
| BRS trend history | — | 30 days | 12 months | 12 months | Custom |
| Cyber Essentials Readiness assessment | — | — | ✓ | ✓ | ✓ |
| Vendor risk monitoring | — | — | ✓ | ✓ | ✓ |
| SaaS exposure detection | — | — | ✓ | ✓ | ✓ |
| Third-party risk intelligence | — | — | ✓ | ✓ | ✓ |
| **Reporting** | | | | | |
| Executive dashboard | — | ✓ | ✓ | ✓ | ✓ |
| Scheduled report delivery | — | ✓ | ✓ | ✓ | ✓ |
| Executive PDF reports | — | Basic | Advanced | Advanced | Custom |
| White-label reports (your logo/brand) | — | — | — | ✓ | ✓ |
| Custom report templates | — | — | — | — | ✓ |
| **Portfolio & Multi-Client** | | | | | |
| Portfolio monitoring (all clients, one view) | — | — | — | ✓ | ✓ |
| Multi-workspace management | — | — | — | ✓ | ✓ |
| vCISO workflow tools | — | — | — | ✓ | ✓ |
| MSP dashboard | — | — | — | — | ✓ |
| **Data & History** | | | | | |
| Historical tracking | — | 30 days | 12 months | 7 years | Custom |
| Asset change event alerts | — | ✓ | ✓ | ✓ | ✓ |
| Audit trail | — | — | ✓ | ✓ | ✓ |
| Audit log export | — | — | — | — | ✓ |
| **Access & Integrations** | | | | | |
| Domains | 1 | 3 | 10 | 25 | Custom |
| Users | 1 | 2 | 5 | 10 | Custom |
| Email notifications | — | ✓ | ✓ | ✓ | ✓ |
| API access | — | — | — | ✓ | ✓ |
| SSO / SAML | — | — | — | — | ✓ |
| **Support** | | | | | |
| Support | Community | Email | Email | Priority email | SLA-backed |
| Dedicated onboarding | — | — | — | — | ✓ |
| Data Processing Agreement | — | — | — | — | ✓ |

---

## 5. Social Proof Strip [shown between plan cards and comparison table]

### Section heading
```
Trusted by security professionals across the UK
```

### Quote 1 [consultant persona]
```
"I deliver Cyber Essentials readiness reports to 12 clients every quarter. CyberMeters does in 10 minutes what used to take me half a day."
— Security Consultant, London
```

### Quote 2 [IT Manager persona]
```
"The Business Risk Score gives me something I can actually show the board. A letter grade they understand, with evidence behind it."
— IT Manager, Manchester
```

### Quote 3 [MSP persona]
```
"The portfolio view is exactly what I needed. I can see every client's risk posture in one screen and prioritise my week accordingly."
— MSP Director, Birmingham
```

---

## 6. Business Risk Score Messaging

### Pricing page callout block [positioned between hero and plan cards]

**Heading:**
```
Your security posture, scored and explained
```

**Body:**
```
The Business Risk Score (BRS) grades your attack surface from A to F — the same way your customers and insurers think about risk. Not a list of technical findings. A score, a grade, and a plain-English explanation of what it means and what to do next.

Available from the Starter plan.
```

**Visual hint:** [BRS grade wheel graphic, showing A–F, with grade A highlighted — to be designed]

---

### BRS feature lock state copy [shown on Free plan dashboard, over locked BRS card]

**Lock overlay heading:**
```
See your Business Risk Score
```

**Lock overlay body:**
```
Get an A–F grade for your attack surface, with a full breakdown by category: DNS, SSL, email security, asset exposure, and more. Updated automatically every time you scan.
```

**CTA inside lock:** `Upgrade to Starter — £29/month`  
**CTA subline:** 14-day free trial. Cancel anytime.

---

### BRS upgrade prompt [shown in Starter trial banner, day 10–14]

**Heading:**
```
Your Business Risk Score is live
```

**Body:**
```
You've been monitoring your attack surface for [X] days. Your current grade: [GRADE]. Keep it — and track how it changes over time — by continuing on Starter.
```

**CTA:** `Continue on Starter — £29/month`

---

## 7. Cyber Essentials Readiness Messaging

### Pricing page callout block [positioned between plan cards and comparison table]

**Heading:**
```
Cyber Essentials readiness — continuously monitored
```

**Body:**
```
Cyber Essentials is the UK government's baseline cybersecurity standard — required for government contracts over £25,000, increasingly required by cyber insurers, and a growing requirement in supply chains across the UK.

CyberMeters continuously assesses your attack surface against all five Cyber Essentials technical controls: firewalls, secure configuration, access control, malware protection, and software updates. When something changes on your attack surface that affects your CE readiness, you'll know before your assessor does.
```

**Supporting detail line:**
```
Cyber Essentials readiness is available on the Professional plan.
```

---

### CE feature lock state copy [shown on Starter dashboard, over locked CE Readiness tab]

**Lock overlay heading:**
```
Cyber Essentials Readiness
```

**Lock overlay body:**
```
See how your attack surface measures up against all five Cyber Essentials technical controls. Identify gaps before your formal assessment. Track your readiness over time. Generate a CE readiness report you can share with clients or your assessor.

Required for UK government contracts over £25,000. Now required by most cyber insurers.
```

**CTA inside lock:** `Upgrade to Professional — £149/month`  
**CTA subline:** 14-day free trial. Cancel anytime.

---

### CE standalone value prop [for use in marketing emails, LinkedIn, lead magnet landing page]

**Short version (tweet-length):**
```
CyberMeters checks your Cyber Essentials readiness continuously — not just at assessment time. Know your gaps before your assessor does.
```

**Medium version (email paragraph):**
```
Cyber Essentials certification costs £300–£500 and takes weeks to prepare for. Most businesses find out they have gaps during the assessment itself — which means failed first attempts, delays, and emergency remediation. CyberMeters assesses your attack surface against all five CE technical controls automatically, shows you exactly where your gaps are, and updates your readiness score every time you scan. Prepare in days, not months.
```

**Long version (landing page / blog):**
```
Cyber Essentials is no longer optional for many UK businesses. If you're bidding for government contracts over £25,000, you need it. If you're renewing your cyber insurance, your insurer is asking for it. If you're a supplier to a regulated organisation, your customer is requiring it.

The problem is the traditional route: hire a consultant for a gap analysis (£500–£2,000), spend weeks fixing issues, pay for the formal assessment (£300–£500), fail the first time, fix more issues, try again. Total cost: £1,500–£4,000. Total time: 6–12 weeks.

CyberMeters does the gap analysis automatically. Every time you scan, we check your attack surface against all five Cyber Essentials technical controls — firewalls, secure configuration, access control, malware protection, and software updates — and show you exactly where you stand. Not a one-time report. A continuously updated readiness score that tracks changes to your attack surface the moment they happen.

When your assessor arrives, there are no surprises. Because you've been monitoring your readiness for months, not days.

Available on the Professional plan — £149/month.
```

---

## 8. Upgrade CTAs

### In-product upgrade banner [shown to Free users — general]

**Heading:** `You're on the Free plan`  
**Body:** `Add your Business Risk Score, scheduled scans, and executive dashboard. Upgrade to Starter from £29/month.`  
**CTA:** `See plans`

---

### In-product upgrade banner [shown to Free users — after running first scan]

**Heading:** `Your scan is complete`  
**Body:** `Unlock your Business Risk Score to see your A–F grade, category breakdown, and what to fix first.`  
**CTA:** `Upgrade to Starter — £29/month`

---

### In-product upgrade prompt [shown to Starter users on CE Readiness tab]

**Heading:** `Cyber Essentials Readiness`  
**Body:** `Assess your attack surface against all five Cyber Essentials technical controls. Available on Professional.`  
**CTA:** `Upgrade to Professional — £149/month`  
**Secondary CTA:** `Learn more about Professional`

---

### In-product upgrade prompt [shown to Starter users on Vendor Risk tab]

**Heading:** `Vendor Risk Monitoring`  
**Body:** `See which third-party tools and vendors have access to your environment and flag exposures automatically.`  
**CTA:** `Upgrade to Professional — £149/month`

---

### In-product upgrade prompt [shown to Professional users on Portfolio tab]

**Heading:** `Portfolio Monitoring`  
**Body:** `See all your client workspaces in a single view. White-label reports. Multi-workspace management. Built for consultants and MSPs.`  
**CTA:** `Upgrade to Business — £399/month`  
**Secondary CTA:** `Talk to us about Business`

---

### In-product upgrade prompt [shown to Professional users on Report Export — white-label option]

**Heading:** `White-label reports`  
**Body:** `Export reports with your logo and brand, not ours. Available on Business — built for consultants and MSPs who deliver reports to clients.`  
**CTA:** `Upgrade to Business — £399/month`

---

### Post-checkout success page

**Heading:** `You're on [PLAN NAME].`  
**Body:** `Your [PLAN] plan is now active. Here's where to start:`

```
→ Add your first domain  [link to workspace setup]
→ Run your first scan   [link to scan trigger]
→ View your Business Risk Score  [link to BRS dashboard]  [Starter+]
→ Check your Cyber Essentials readiness  [link to CE tab]  [Professional+]
→ Set up your first portfolio workspace  [link to portfolio]  [Business+]
```

**Support line:** `Questions? Email us at support@cybermeters.com — we respond within 24 hours.`

---

### Trial expiry email [sent day 12 of 14-day trial]

**Subject:** `Your CyberMeters trial ends in 2 days`

**Body:**
```
Hi [First name],

Your 14-day [PLAN] trial ends on [DATE].

Here's what you'll keep if you continue:

[Starter] Your Business Risk Score, scheduled scans, and executive dashboard — running automatically, every week.
[Professional] Everything above, plus your Cyber Essentials Readiness assessment and vendor risk monitoring.
[Business] Everything above, plus your portfolio view and white-label report output.

After your trial ends, your account moves to Free. Your scan history is preserved — nothing is deleted.

[CTA button: Continue on [PLAN] — £[PRICE]/month]

If you have any questions before you decide, reply to this email. I read every response.

— Turhan, CyberMeters
```

---

## 9. Pricing Page FAQ

### Section heading
```
Frequently asked questions
```

---

**Q: Is there a free trial?**

```
Yes. All paid plans include a 14-day free trial. No credit card is required to start. If you don't upgrade before the trial ends, your account moves to the Free plan automatically — your scan history is preserved.
```

---

**Q: Can I change plans at any time?**

```
Yes. You can upgrade or downgrade at any time from your account settings. When you upgrade, the change takes effect immediately. When you downgrade, the change takes effect at the end of your current billing period.
```

---

**Q: What happens to my data if I downgrade?**

```
Your scan history and reports are preserved. If you downgrade from Professional to Starter, your Cyber Essentials Readiness data is retained — you'll need to be on Professional or above to run new assessments or access the CE dashboard. Your data is never deleted when you change plans.
```

---

**Q: What is a Business Risk Score?**

```
Your Business Risk Score (BRS) is a letter grade (A–F) that summarises the security posture of your attack surface — the parts of your business that are visible and potentially accessible from the internet. It's calculated from your DNS configuration, SSL certificates, email security settings, asset exposure, and other technical signals. The score updates every time you run a scan. Available from the Starter plan.
```

---

**Q: What is Cyber Essentials Readiness?**

```
Cyber Essentials is the UK government's baseline cybersecurity certification scheme, backed by the NCSC. CyberMeters assesses your attack surface against all five Cyber Essentials technical controls — firewalls, secure configuration, access control, malware protection, and software updates — and shows you how ready you are for formal certification. It is not a substitute for a formal Cyber Essentials assessment, but it tells you where your gaps are before your assessor arrives. Available on the Professional plan.
```

---

**Q: I'm a security consultant or vCISO. Which plan is right for me?**

```
The Business plan is designed for security consultants, fractional CISOs, and vCISOs who deliver security services to clients. It includes white-label reports (your logo, not ours), portfolio monitoring (all client workspaces in one view), multi-workspace management, and vCISO workflow tools. It supports up to 25 domains and 10 users, with priority email support.
```

---

**Q: I'm an MSP. Do you have a plan for managed service providers?**

```
The Business plan covers most MSP use cases — portfolio view, white-label reports, and up to 25 client domains. If you manage more than 25 clients or need the dedicated MSP dashboard, custom limits, SSO, or SLA-backed support, talk to us about the Enterprise plan. Email hello@cybermeters.com and we'll respond within one business day.
```

---

**Q: Do you offer annual billing?**

```
Yes. Annual billing saves 20% compared to monthly. You can switch to annual billing at any time from your account settings. Annual plans are billed as a single upfront payment.
```

---

**Q: Is CyberMeters a Cyber Essentials certification body?**

```
No. CyberMeters is not a Cyber Essentials Certification Body (CB). We help you prepare for Cyber Essentials certification by continuously monitoring your readiness against the five technical controls. For formal certification, you'll need to work with an NCSC-approved Certification Body. CyberMeters makes sure there are no surprises when you do.
```

---

**Q: How is CyberMeters different from a vulnerability scanner?**

```
Traditional vulnerability scanners produce long lists of technical findings for security engineers to triage. CyberMeters produces a risk posture — a grade, a narrative, and prioritised guidance — that is useful to IT managers, business owners, and boardrooms, not just security teams. We focus on your attack surface: the assets and services visible from the internet, and how they contribute to your overall security posture. The output is designed to be shared with clients, boards, and insurers, not just ticked off a remediation list.
```

---

**Q: Where is my data stored?**

```
CyberMeters is built on Cloudflare's global infrastructure. All data is processed and stored within Cloudflare's network. Scan data, reports, and account information are stored in Cloudflare D1 (database) and R2 (object storage). We do not sell or share your data with third parties.
```

---

**Q: Do you offer a Data Processing Agreement (DPA)?**

```
A Data Processing Agreement is available for Enterprise plan customers. If you require a DPA for compliance or procurement purposes, contact us at hello@cybermeters.com.
```

---

## 10. Enterprise / Contact Section

### Section heading
```
Need something custom?
```

### Body
```
If you're an MSP managing more than 25 clients, a large organisation with specific data residency or compliance requirements, or a security team that needs custom limits, SSO, or SLA-backed support — let's talk.
```

### Detail line
```
Enterprise pricing is custom. We'll respond within one business day.
```

### CTA button: `Talk to us`  
### CTA subline: `hello@cybermeters.com`

---

## 11. Page Footer Copy [pricing page specific additions to site footer]

```
All prices shown in GBP and exclude VAT. VAT will be added at checkout where applicable.
Annual plans are billed as a single upfront payment. Monthly plans are billed on the same date each month.
CyberMeters is not a Cyber Essentials Certification Body. Cyber Essentials is a UK government-backed scheme owned by the NCSC.
```

---

## 12. Meta Copy [for SEO and social sharing]

**Page title:**
```
CyberMeters Pricing — Attack Surface Monitoring for UK Businesses
```

**Meta description:**
```
Continuous attack surface monitoring and Cyber Essentials readiness for UK businesses, consultants, and MSPs. Free plan available. Starter from £29/month.
```

**Open Graph title:**
```
CyberMeters — Know your attack surface. Prove your security posture.
```

**Open Graph description:**
```
Business Risk Score, Cyber Essentials Readiness, and portfolio monitoring for UK security teams and consultants. Free plan available.
```

---

## Implementation Notes

These are not copy — they are guidance for the frontend engineer implementing this page.

- The plan card order (left to right) should be: Free → Starter → Professional → Business → Enterprise
- "Most popular" badge goes on Professional
- Annual toggle defaults to **monthly** initially; when user selects annual, prices update in place (no page reload)
- Annual prices: Starter £23/mo (£276/yr), Professional £119/mo (£1,428/yr), Business £319/mo (£3,828/yr)
- Feature lock states in plan cards link directly to the checkout/upgrade flow for the relevant next plan
- All CTA buttons on the pricing page should be tracked with analytics events: `pricing_cta_clicked`, `plan_name`, `billing_period`
- The comparison table should be collapsible by category on mobile
- FAQ should use an accordion component (one question open at a time)
- Cyber Essentials callout block and BRS callout block are optional on mobile (can be hidden to reduce scroll depth on small screens)

---

*CyberMeters Platform — Pricing Page Copy v1 — June 2026*  
*Approved pricing: Free / Starter £29 / Professional £149 / Business £399 / Enterprise Custom*  
*Next review: after first 30 paying customers — validate copy against conversion data*
