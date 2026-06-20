# CyberMeters — Commercial Packaging & Pricing Strategy

**Version:** 1.0 | **Date:** June 2026 | **Status:** Internal Review  
**Scope:** Plan packaging, feature placement, pricing, upgrade incentives, customer personas  
**Market:** UK SMBs, MSPs, vCISO services, security consultants

---

## Table of Contents

1. [Verdict on the Current Proposal](#1-verdict-on-the-current-proposal)
2. [The Core Pricing Problem](#2-the-core-pricing-problem)
3. [Customer Persona Analysis](#3-customer-persona-analysis)
4. [Feature Placement Audit](#4-feature-placement-audit)
5. [Upgrade Driver Analysis](#5-upgrade-driver-analysis)
6. [Commercial Packaging Audit — 10 Questions Answered](#6-commercial-packaging-audit--10-questions-answered)
7. [Recommended Final Plan Matrix](#7-recommended-final-plan-matrix)
8. [Upgrade Path Analysis](#8-upgrade-path-analysis)
9. [Features Currently Underpriced](#9-features-currently-underpriced)
10. [Features Currently Overpriced](#10-features-currently-overpriced)
11. [Revenue Optimization Recommendations](#11-revenue-optimization-recommendations)
12. [Final Pricing Recommendation](#12-final-pricing-recommendation)

---

## 1. Verdict on the Current Proposal

The proposed plan structure is architecturally sound — the feature groupings are broadly logical and the tier progression makes sense. However, the pricing is severely misaligned with the UK B2B security market, and several features are placed at tiers that undermine their perceived value and dilute upgrade motivation.

**What is right:**
- Four commercial tiers plus Enterprise is the correct structure
- Business Risk Score above basic scanning is correct
- Portfolio Monitoring above single-workspace is correct
- White-label above standard reporting is correct

**What is wrong:**

| Problem | Impact |
|---|---|
| £9.90 Starter positions CyberMeters as a consumer product | Kills credibility with IT buyers and MSPs |
| £29.90 Professional makes Cyber Essentials Readiness feel like a minor add-on | Undersells the most powerful UK compliance feature in the product |
| £99.90 Business is viable but still 30–50% below market | Leaves revenue on the table from MSPs who would pay £300+ without hesitation |
| BRS + Cyber Essentials + Vendor Risk all on the same tier | Removes upgrade incentive from Professional to Business; tier feels overloaded |
| Executive Reporting not explicitly tiered | Every buyer asks "what do I get to show my board" before they sign — this must be explicitly tiered |

---

## 2. The Core Pricing Problem

### The Market Reality

CyberMeters is not a consumer cybersecurity product. It is a B2B Attack Surface Management and Security Posture platform. The relevant UK market benchmarks are:

| Competitor / Tool | Entry Pricing | Target Buyer |
|---|---|---|
| UpGuard Cyber Risk | $500+/month | Mid-market |
| SecurityScorecard | $500+/month | Mid-market |
| RiskXchange | £200+/month | SMB / MSP |
| Hacker Target Pro | £50–200/month | Technical SMB |
| Qualys VMDR | £300+/month | Mid-market |
| Detectify | £200+/month | Dev/Security teams |

CyberMeters at £9.90/month does not compete in this landscape — it sits below it entirely, implying it is a basic tool rather than a professional platform. In B2B security, price is a signal of capability and trustworthiness. Underpricing communicates risk, not value.

### What UK SMB Buyers Actually Pay

A UK SMB IT Manager with a £50,000–£200,000 annual IT budget treats any tool under £50/month as a utility. They do not budget-approve it. They put it on a company card and forget it. This means:

- No internal champion
- No renewal conversation
- No expansion
- High churn when the card changes

Tools in the £99–£399/month range require a purchasing decision, which creates an internal champion who actively defends the tool at renewal. This is the revenue model that scales.

### The £9.90 Problem Specifically

At £9.90/month, CyberMeters generates £118.80 ARR per Starter customer. To reach £100k ARR, you need 842 paying Starter customers. This is not achievable in the UK SMB/MSP market in year one. At £49/month (the correct Starter price), you need 170 customers for the same ARR — a completely different acquisition challenge.

---

## 3. Customer Persona Analysis

### Persona 1 — The UK SMB IT Manager (Primary Early Adopter)

**Profile:** Head of IT or IT Manager at a 50–500 employee UK company. Responsible for security posture but does not have a dedicated security team. Reports to the FD or CEO.

**Pain points:**
- Board asks "are we secure?" and they have no credible answer
- Cyber insurance renewal is coming and the questionnaire is getting longer
- A supplier or government contract requires evidence of security controls
- They've heard of Cyber Essentials but haven't formally assessed against it

**Features they will pay for:**
- Cyber Essentials Readiness (direct compliance need — often has a hard deadline)
- Business Risk Score (a single number they can put in front of the CEO)
- Executive Reports (something to show at the quarterly board meeting)
- Scheduled Scans (hands-off monitoring without manual intervention)

**Price sensitivity:** £50–£200/month is budget-approvable without escalation. Above £200 requires sign-off.

**Most likely conversion trigger:** Cyber insurance renewal, government contract requirement, or a supply chain security questionnaire from a customer.

**Target plan:** Starter → Professional

---

### Persona 2 — The vCISO / Fractional Security Consultant (Highest Value Early Customer)

**Profile:** Solo practitioner or small consultancy providing virtual CISO services to 5–20 UK SMB clients. Charges clients £1,500–£5,000/month per engagement.

**Pain points:**
- Needs professional, branded deliverables to justify their day rate
- Manages multiple clients and needs a tool that scales across them
- Current tools are either enterprise-grade (too expensive) or basic (not credible)
- Needs to demonstrate continuous monitoring, not just point-in-time assessments

**Features they will pay for:**
- White-label Reports (their name on the deliverable, not CyberMeters')
- Portfolio Monitoring (see all clients in one view)
- Business Risk Score (the executive narrative their clients need)
- Cyber Essentials Readiness (a service they charge extra for)
- Scheduled Reports (automated delivery to clients without manual work)

**Price sensitivity:** Extremely low — they bill it back to clients at 3–5x markup. £300/month becomes £900–1,500/month in recovered cost across 3 clients.

**Most likely conversion trigger:** A new client engagement that requires ongoing monitoring and board-level reporting.

**Target plan:** Business (direct) — possibly bypassing Starter and Professional entirely.

---

### Persona 3 — The MSP Adding Security Services (Strategic Growth Segment)

**Profile:** Managed Service Provider with 20–100 SMB clients, currently offering IT support, backup, and Microsoft 365. Looking to add security as a new revenue line.

**Pain points:**
- Clients are asking about cybersecurity but the MSP has no differentiated answer
- Existing RMM and PSA tools don't provide security posture reporting
- They need a tool they can resell or bundle, not one that exposes their tooling to clients
- White-label is non-negotiable — their client relationship is their asset

**Features they will pay for:**
- Portfolio Monitoring (essential — they manage 20–100 client environments)
- White-label Reports (mandatory for their client relationship)
- Bulk Scheduled Reports (efficiency at scale — one click, all clients)
- Business Risk Score (per-client risk summary they can use in QBRs)
- API access (automation, PSA integration)
- Cyber Essentials Readiness (a service they can charge clients separately for)

**Price sensitivity:** Low per-seat, but they expect a volume arrangement or MSP pricing at Business/Enterprise. A Business plan at £399/month covering 25 workspaces costs them £16/client/month — invisible in their billing.

**Most likely conversion trigger:** A client asking for cybersecurity reporting, or the MSP proactively adding security to their service stack.

**Target plan:** Business → Enterprise

---

### Persona 4 — The Compliance-Driven IT Director (Secondary Segment)

**Profile:** IT Director or Head of IT Security at a 200–2,000 employee UK company. Has a small security team. Procurement process exists.

**Pain points:**
- Needs to demonstrate security posture to the board quarterly
- Vendor risk is a real concern after supply chain incidents
- Historical trending matters — they need to show improvement over time
- Cyber Essentials Plus may be on the roadmap

**Features they will pay for:**
- Vendor Risk Intelligence
- Business Risk Score with trend history
- Extended data retention (compliance evidence)
- Executive Dashboard
- Portfolio view across business units

**Price sensitivity:** £150–£500/month is within discretionary budget. Larger amounts require procurement.

**Target plan:** Professional → Business

---

## 4. Feature Placement Audit

### Current vs. Recommended Placement

| Feature | Current Tier | Recommended Tier | Rationale |
|---|---|---|---|
| Basic domain scan | Free | Free | Correct — this is the hook |
| Basic scan results | Free | Free | Correct |
| Manual scan history | Free | Free (7-day limit) | Add a hard time limit to create upgrade pressure |
| Scheduled Scans | Starter | Starter | Correct — automation is the first paid unlock |
| Business Risk Score | Professional | **Starter** | BRS is the "so what" answer to scan data. Without it, Starter feels like a manual tool. It's the core upgrade driver from Free. |
| Basic Executive Report | Starter | Starter | Move to Starter — every paying customer needs something to show |
| Advanced Executive Reports (PDF, branded) | Professional | Professional | Correct |
| Cyber Essentials Readiness | Professional | Professional | Correct placement — this is the compliance unlock |
| Vendor Risk | Professional | Professional | Correct |
| Historical Trending (90-day+) | Starter (implied) | Professional | Trend data has high perceived value; lock extended history to Professional |
| Portfolio Monitoring | Business | Business | Correct |
| White-label Reports | Business | Business | Correct — keep here, not Enterprise |
| Extended Retention (7yr) | Business | Business | Correct |
| Scheduled Reports | Professional | Professional | Automate report delivery at Professional, not Starter |
| API Access | Not listed | Business | Strong MSP unlock; must be explicitly offered |
| MSP Dashboard | Enterprise | Enterprise | Correct |
| Custom Limits | Enterprise | Enterprise | Correct |
| Priority Support | Enterprise | Enterprise | Correct |
| Asset Inventory | Not listed | Starter | ASM core — should be explicitly called out |
| Historical Change Tracking | Not listed | Professional | Strong compliance and security value |

### Features Missing from the Current Packaging Entirely

These features exist in the platform but are not mentioned in the proposed plan matrix. They have commercial value and should be surfaced explicitly:

- **Asset Inventory** — customers want to know "what do I have?" Not just "what's wrong with it?"
- **Historical Change Tracking** — showing that a finding was introduced 3 months ago is a powerful compliance narrative
- **API Rate Limits / API Access** — MSPs and technical buyers ask about this before purchase
- **Subdomain Discovery** — a tangible deliverable that justifies early spend
- **Asset Events / Change Alerts** — proactive notification is a strong retention feature

---

## 5. Upgrade Driver Analysis

An upgrade driver is a feature that a customer actively feels they are missing when on a lower tier. The strongest upgrade drivers are features with high visibility, clear business value, and low technical complexity to explain.

### Tier 1 Upgrade Drivers (Highest Pull)

**Cyber Essentials Readiness**
The single most powerful UK-specific upgrade driver in the product. Cyber Essentials is a UK government-backed certification scheme. It is mandatory for UK government contracts over £25,000. It is increasingly required by cyber insurance providers. It is required by many supply chain partners as a condition of doing business. An IT Manager who needs Cyber Essentials certification has a hard deadline and a business consequence for not achieving it. This is not a "nice to have" — it is a budget-unlocking compliance requirement.

**Business Risk Score**
The BRS translates technical scan findings into a single letter grade with a narrative explanation. This is what every non-technical buyer actually wants. Every IT Manager who has ever had to explain "what does this mean?" to a CEO will immediately understand the value. The grade format (A–F) is universally understood. The narrative removes the need for interpretation. This feature should be the primary "aha moment" in the trial-to-paid conversion.

**Portfolio Monitoring**
For MSPs and vCISOs, this is non-negotiable. A consultant managing 10 clients cannot use a tool that only shows one client at a time. The moment they realise they need to monitor multiple domains simultaneously is the moment they upgrade to Business.

### Tier 2 Upgrade Drivers (Strong Pull)

**Scheduled Scans and Reports**  
Manual = work. Scheduled = the tool works for you. Every customer who runs three manual scans will want automation. The upgrade trigger is friction: clicking "run scan" repeatedly is the conversion funnel.

**White-label Reports**  
For any customer who delivers work product to a client under their own brand, white-label is a professional necessity. A vCISO cannot send a report with CyberMeters branding to their client — it exposes their tooling and undermines their perceived value.

**Executive Report (PDF)**  
A scan results page on a screen is not a deliverable. A PDF with a cover page, an executive summary, and a risk score is a deliverable. Customers who have a board meeting coming up will pay for a document.

### Tier 3 Upgrade Drivers (Moderate Pull)

**Vendor Risk Intelligence**  
Relevant after a customer has their own domain under control. Pull increases significantly after supply chain incidents in their industry.

**Extended Data Retention**  
Strong pull for compliance-driven buyers (finance, healthcare, professional services). Weak pull for early-stage SMBs. Place at Business; mention in Professional as a future upgrade path.

**Historical Trending**  
Showing improvement over time is valuable for board reporting and insurance evidence. Moderate pull but becomes stronger once a customer has 60+ days of data.

---

## 6. Commercial Packaging Audit — 10 Questions Answered

### Q1. Which features are the strongest upgrade drivers?

Ranked by commercial pull in the UK SMB/MSP/vCISO market:

1. **Cyber Essentials Readiness** — compliance deadline creates budget urgency; strongest UK-specific driver
2. **Business Risk Score** — executive communication need is universal; unlocks the non-technical buyer
3. **Portfolio Monitoring** — non-negotiable for MSPs and vCISOs; instant Business upgrade trigger
4. **White-label Reports** — mandatory for any customer delivering work to clients under their own brand
5. **Scheduled Scans** — automation need emerges after the third manual scan; reliable Free→Starter driver
6. **Executive Reports (PDF)** — board meeting creates deadline; strong Professional trigger
7. **Scheduled Reports** — same automation logic as scans, but for reporting; multiplies value of Executive Reports

---

### Q2. Which features should never be in Free?

| Feature | Reason |
|---|---|
| Business Risk Score | Core value proposition — giving it away eliminates upgrade motivation |
| Cyber Essentials Readiness | Compliance value is too high; free access removes the primary Professional upgrade driver |
| Scheduled Scans | Automation is the first commercial unlock; free automation removes Free→Starter conversion |
| Executive Reports | The deliverable that justifies payment; free reports remove Professional conversion |
| Portfolio Monitoring | MSP/multi-tenant — giving it free removes Business conversion entirely |
| White-label Reports | Premium reseller feature; free access destroys the Business tier for consultants |
| Vendor Risk | Advanced intelligence layer; must remain behind a paywall |
| Historical data beyond 7 days | Retention limits create natural, low-friction upgrade pressure |
| API access | Technical automation feature; free API removes a Business-tier anchor |

---

### Q3. Is Business Risk Score correctly placed?

**No — BRS should move to Starter.**

At Professional (£29.90 current / a higher price recommended), BRS sits behind a paywall that many early buyers will not cross without first experiencing the value. BRS is the feature that makes scan data legible to non-technical stakeholders. Without it, Starter customers see a list of findings but lack the executive communication tool that justifies the spend.

Moving BRS to Starter serves two goals:
1. It becomes the primary reason to upgrade from Free to Starter
2. It makes Starter customers stickier because the board-level reporting is embedded in their workflow

The risk of "giving away" BRS at Starter is low because BRS without Cyber Essentials, Vendor Risk, and extended historical data is an incomplete picture. The full risk story — which is what boards and insurers want — remains at Professional.

---

### Q4. Is Cyber Essentials Readiness correctly placed?

**Yes — Professional is the right tier. The price is wrong, not the placement.**

Cyber Essentials should sit at Professional because:
- It signals that Professional is the compliance tier, not just the "more features" tier
- It creates a named, marketable reason to upgrade: "Get your Cyber Essentials readiness assessment"
- It differentiates Professional from Starter with a concrete, externally-valued deliverable

What is wrong: at £29.90/month, Professional is priced as though Cyber Essentials readiness is a minor feature. It is not. UK SMBs pay consultants £500–£2,000 for a Cyber Essentials gap assessment. CyberMeters automates this continuously. The price should reflect that.

At the recommended £149/month Professional price, the Cyber Essentials readiness tool alone provides positive ROI against a one-time consultant assessment within two months.

---

### Q5. Is Vendor Risk correctly placed?

**Yes — Professional is correct.**

Vendor Risk is a natural companion to Cyber Essentials (supply chain risk is explicitly assessed under CE) and to Business Risk Score (vendor exposure is a BRS input category). Keeping it at Professional reinforces Professional as the complete security intelligence tier.

However: Vendor Risk depth should scale by tier. Professional gets vendor detection and risk categorisation. Business gets vendor trend history, portfolio-level vendor risk aggregation, and vendor risk in white-label reports. This creates intra-tier progression without moving the feature.

---

### Q6. Should Executive Reporting start at Starter or Professional?

**Both — but with explicit tier differentiation.**

| Report Type | Tier | Format |
|---|---|---|
| Scan summary (on-screen) | Free | Web UI only, no download |
| Basic Executive Summary | Starter | PDF download, CyberMeters branded |
| Full Executive Report (BRS + findings + recommendations + trend) | Professional | PDF, CyberMeters branded |
| White-label Executive Report | Business | PDF, customer brand |
| Custom-template Executive Report | Enterprise | Custom format |

The key insight: every buyer asks "what can I show my board?" before they pay. The answer for Starter must not be "nothing" — that kills conversion. But the Starter answer ("a basic summary") must be visibly inferior to the Professional answer ("a full board-ready report with risk score, trend charts, and recommendations") to create upgrade pull.

---

### Q7. Should White-label Reporting be Business or Enterprise?

**Business — keep it here. Do not move it to Enterprise.**

Moving white-label to Enterprise removes it from the most commercially important segment: vCISOs and MSPs who are likely to be among the first 50 paying customers. These buyers cannot justify Enterprise pricing at this stage of CyberMeters' commercial maturity. They will convert at Business.

White-label at Enterprise is a common SaaS mistake — it treats a feature as a luxury when it is actually a buying requirement for a core segment. The result is that the core segment doesn't convert, and Enterprise remains empty.

The correct use of Enterprise white-label is not the feature itself but the customisation around it: custom report templates, custom domain for the portal, custom branding beyond just a logo. That is the Enterprise delta.

---

### Q8. Which features create the strongest MSP appeal?

Ranked by importance to MSP buyers:

1. **Portfolio Monitoring** — seeing all clients in one dashboard is the table-stakes requirement
2. **White-label Reports** — non-negotiable; their client relationship depends on their brand, not the tool's
3. **Scheduled Reports** — bulk automated delivery to clients without manual effort
4. **Business Risk Score** — per-client risk grade for quarterly business reviews (QBRs)
5. **API Access** — integration with PSA tools (ConnectWise, Autotask, HaloPSA)
6. **Cyber Essentials Readiness** — a billable add-on service they can offer to all clients
7. **Asset Inventory** — "what does my client have?" is the first question MSPs get
8. **Per-workspace billing clarity** — MSPs need to understand the cost model before committing

The MSP sales conversation is: "I manage 30 clients. Can I see all of them? Can I send them reports under my brand? Can I automate it? What does it cost per client?" CyberMeters Business answers all four questions correctly at the recommended pricing.

---

### Q9. What is the most likely first paying customer profile?

**The UK SMB IT Manager converting from the Cyber Essentials trigger.**

Profile:
- Head of IT or IT Manager at a 100–500 employee UK company
- Has a pending government contract, cyber insurance renewal, or supply chain security questionnaire
- Has tried free scanning tools but cannot produce anything credible from them
- Needs a Cyber Essentials gap assessment without paying a consultant £1,500
- Will start a free trial, run a scan, see the BRS grade, and immediately understand the value
- Will convert to Professional when they need the Cyber Essentials readiness report as a formal deliverable

**The second most likely first paying customer:**

The solo vCISO who finds CyberMeters while looking for a lightweight continuous monitoring tool for a new client engagement. They skip Free entirely, try Professional or Business on a trial, and convert directly because the white-label report saves them 3 hours of manual report writing per client per month.

---

### Q10. What feature mix maximises Free → Starter → Professional conversion?

**Free must create genuine value AND genuine pain.**

The trap is making Free either too good (no reason to upgrade) or too restrictive (no value to discover). The correct Free tier gives enough to demonstrate the platform's capability while creating three clear pain points that only Starter resolves.

**Free pain points that drive Starter conversion:**
1. "I have to run this manually every time" — Scheduled Scans is the unlock
2. "I can't send this web page to my CEO" — Executive Summary PDF is the unlock
3. "I can only see today's results, not last month's" — History access is the unlock

**Starter pain points that drive Professional conversion:**
1. "My report doesn't include the risk score breakdown by category" — Full BRS detail is the unlock
2. "I need to know if we'd pass Cyber Essentials" — CE Readiness is the unlock
3. "My board wants to see improvement over time, not just today's score" — Trend charts and extended history is the unlock
4. "I want to understand our third-party risk" — Vendor Risk is the unlock

**The conversion funnel logic:**

- Free → Starter: Automation + a deliverable. The customer is doing manual work and has nothing to show their boss.
- Starter → Professional: Compliance + intelligence. The customer has a deliverable but it's not complete enough for their board or their auditor.
- Professional → Business: Scale + brand. The customer wants to do this for more than one domain, under their own brand, for other people.

---

## 7. Recommended Final Plan Matrix

### Plan Summary

| | Free | Starter | Professional | Business | Enterprise |
|---|---|---|---|---|---|
| **Price (monthly)** | £0 | £49 | £149 | £399 | Custom |
| **Price (annual equiv/mo)** | £0 | £39 | £119 | £319 | Custom |
| **Domains** | 1 | 5 | 25 | 250 | Unlimited |
| **Workspaces** | 1 | 3 | 10 | 25 | Unlimited |
| **Users** | 1 | 3 | 10 | 25 | Unlimited |
| **Scan history** | 7 days | 90 days | 365 days | 730 days | Unlimited |
| **Report retention** | 7 days | 90 days | 1 year | 7 years | Unlimited |
| **Scans/month** | 5 | 50 | 500 | 2,500 | Unlimited |
| **Scheduled scans** | ✗ | ✓ | ✓ | ✓ | ✓ |
| **Scheduled reports** | ✗ | ✗ | ✓ | ✓ | ✓ |
| **API access** | ✗ | ✗ | ✗ | ✓ | ✓ |

### Feature Matrix

| Feature | Free | Starter | Professional | Business | Enterprise |
|---|---|---|---|---|---|
| **ASM Core** | | | | | |
| Domain scanning | ✓ | ✓ | ✓ | ✓ | ✓ |
| DNS analysis | ✓ | ✓ | ✓ | ✓ | ✓ |
| SSL/TLS analysis | ✓ | ✓ | ✓ | ✓ | ✓ |
| Security headers | ✓ | ✓ | ✓ | ✓ | ✓ |
| Email security (SPF/DKIM/DMARC) | ✓ | ✓ | ✓ | ✓ | ✓ |
| Asset inventory | Basic | Full | Full | Full | Full |
| Subdomain discovery | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Risk Scoring** | | | | | |
| ASM technical score | ✓ | ✓ | ✓ | ✓ | ✓ |
| Business Risk Score (BRS) | ✗ | ✓ | ✓ | ✓ | ✓ |
| BRS category breakdown | ✗ | Summary | Full | Full | Full |
| BRS trend history | ✗ | ✗ | ✓ | ✓ | ✓ |
| **Compliance** | | | | | |
| Cyber Essentials Readiness | ✗ | ✗ | ✓ | ✓ | ✓ |
| Cyber Essentials gap report | ✗ | ✗ | ✓ | ✓ | ✓ |
| **Intelligence** | | | | | |
| Vendor Risk detection | ✗ | ✗ | ✓ | ✓ | ✓ |
| Vendor risk history | ✗ | ✗ | ✗ | ✓ | ✓ |
| Brand monitoring (typosquats) | ✗ | ✗ | ✓ | ✓ | ✓ |
| Certificate intelligence | ✓ | ✓ | ✓ | ✓ | ✓ |
| Admin surface detection | ✗ | ✓ | ✓ | ✓ | ✓ |
| Cloud asset detection | ✗ | ✓ | ✓ | ✓ | ✓ |
| SaaS exposure | ✗ | ✗ | ✓ | ✓ | ✓ |
| **Reporting** | | | | | |
| On-screen scan results | ✓ | ✓ | ✓ | ✓ | ✓ |
| Basic executive summary (PDF) | ✗ | ✓ | ✓ | ✓ | ✓ |
| Full executive report (PDF) | ✗ | ✗ | ✓ | ✓ | ✓ |
| White-label reports | ✗ | ✗ | ✗ | ✓ | ✓ |
| Custom report templates | ✗ | ✗ | ✗ | ✗ | ✓ |
| Scheduled reports | ✗ | ✗ | ✓ | ✓ | ✓ |
| **Monitoring** | | | | | |
| Historical tracking | 7 days | 90 days | 365 days | 730 days | Unlimited |
| Asset change events | ✗ | ✓ | ✓ | ✓ | ✓ |
| Notifications/alerts | ✗ | ✓ | ✓ | ✓ | ✓ |
| Executive Dashboard | ✗ | ✓ | ✓ | ✓ | ✓ |
| **Portfolio / Multi-tenant** | | | | | |
| Portfolio dashboard | ✗ | ✗ | ✗ | ✓ | ✓ |
| Portfolio alerts | ✗ | ✗ | ✗ | ✓ | ✓ |
| Portfolio trend reports | ✗ | ✗ | ✗ | ✓ | ✓ |
| MSP dashboard | ✗ | ✗ | ✗ | ✗ | ✓ |
| **Platform** | | | | | |
| API access | ✗ | ✗ | ✗ | ✓ | ✓ |
| RBAC / team members | ✗ | Basic | Full | Full | Full |
| Audit trail | ✗ | ✗ | ✓ | ✓ | ✓ |
| SSO / SAML | ✗ | ✗ | ✗ | ✗ | ✓ |
| SLA / uptime guarantee | ✗ | ✗ | ✗ | ✗ | ✓ |
| Priority support | ✗ | ✗ | ✗ | ✗ | ✓ |
| Custom limits | ✗ | ✗ | ✗ | ✗ | ✓ |

### Plan Positioning

| Plan | Primary Buyer | Primary Value Proposition | Key Differentiator vs. Previous Tier |
|---|---|---|---|
| Free | IT Manager evaluating the platform | "See what your attack surface looks like" | — |
| Starter | UK SMB IT Manager | "Monitor your security automatically and show your board a risk score" | Automation + BRS + a deliverable |
| Professional | Compliance-driven SMB, vCISO, security consultant | "Get Cyber Essentials readiness, vendor risk, and full executive reports" | Compliance + intelligence |
| Business | MSP, multi-client vCISO | "Manage and report across all your clients under your brand" | Portfolio + white-label + API |
| Enterprise | Large MSP, enterprise security team | "Custom scale, SLA, and integration" | Unlimited scale + contractual guarantees |

---

## 8. Upgrade Path Analysis

### Path 1: Free → Starter (Primary conversion path)

**Target persona:** IT Manager who ran a manual scan, saw findings, but cannot schedule it or show anyone a clean report.

**Friction at Free:**
- Must remember to run scans manually
- Only 7 days of history — no trend data
- No PDF to show anyone
- No Business Risk Score — findings are a raw list with no executive narrative

**Starter unlock moment:** "I can set it to run every week and send me a summary, and I can download a one-page risk score to email to the CEO."

**Conversion tactics:**
- Show a preview of the BRS (grayed out, locked) immediately after first scan in Free
- Show "You've run 3 manual scans. Set up a weekly schedule →" prompt after third manual scan
- Show the Executive Summary PDF template locked in the Free UI with "Upgrade to share this"
- 14-day trial of Starter with no card required on signup

---

### Path 2: Starter → Professional (Compliance conversion path)

**Target persona:** IT Manager whose board asked about Cyber Essentials, or who has a government contract application in progress.

**Friction at Starter:**
- BRS shows a grade but not the full category breakdown or trend over time
- No Cyber Essentials readiness assessment
- No vendor risk visibility
- Reports are basic — not the full board-ready format with recommendations

**Professional unlock moment:** "I need to know if we'd pass Cyber Essentials, and I need a report that shows the gap analysis."

**Conversion tactics:**
- Show Cyber Essentials Readiness as a locked tab in the navigation for Starter users
- After 30 days on Starter, send email: "You've been monitoring for 30 days. Here's what a Cyber Essentials assessment would show →"
- Include a "BRS detail locked" state in the Starter BRS view showing the category breakdown grayed out
- In-app banner: "Your renewal is coming up. Get your Cyber Essentials readiness report before your insurer asks."

---

### Path 3: Professional → Business (Scale conversion path)

**Target persona:** vCISO who has onboarded a second client, or MSP who wants to add security to their service stack.

**Friction at Professional:**
- Can only manage one workspace — cannot see all clients together
- Reports carry CyberMeters branding, not the consultant's brand
- No API for automation
- No portfolio-level alerts

**Business unlock moment:** "I need to manage five clients and send them reports under my company name."

**Conversion tactics:**
- Show "Add workspace" locked behind Business on workspace selection
- Show white-label as a locked option in report settings
- When a Professional user adds their second domain, show: "Managing multiple clients? Business gives you a portfolio view and white-label reports."
- vCISO and MSP landing page content that speaks directly to this persona

---

### Path 4: Business → Enterprise (Scale trigger path)

**Target persona:** MSP with 50+ clients, or an SME security team that needs SLA guarantees and SSO.

**Unlock triggers:**
- Approaching workspace or domain limits on Business
- Requesting SSO/SAML integration
- Needing a contractual SLA
- Requiring custom report templates
- PSA tool integration requirement

---

## 9. Features Currently Underpriced

### Cyber Essentials Readiness — Severely Underpriced

**Proposed price:** Included in Professional at £29.90/month  
**Market value:** UK consultants charge £500–£2,000 for a single Cyber Essentials gap assessment  
**Recommended price:** Included in Professional at £149/month

A continuous, automated Cyber Essentials readiness assessment is not a £29.90/month feature. UK SMBs with a government contract requirement will pay £149/month without hesitation if CyberMeters replaces a £1,500 consultant engagement. The price needs to signal that this is a premium compliance capability, not a basic feature add-on.

### Business Risk Score — Underpriced at Professional

**Proposed price:** Professional at £29.90/month  
**Recommended repositioning:** Starter at £49/month (summary) + Professional at £149/month (full detail)  
**Rationale:** Moving BRS to Starter increases the value of Starter substantially, making the Free→Starter conversion stronger. Full BRS detail (category breakdown, trend, narrative) remains the Professional differentiator.

### White-label Reports — Underpriced at Business

**Proposed price:** Business at £99.90/month  
**Recommended price:** Business at £399/month  
**Rationale:** A vCISO or MSP who gets white-label reports is building their service delivery on top of CyberMeters. They are charging their clients for this output. At £399/month, they are capturing the value of white-label as a professional service tool. At £99.90, they would feel guilty not charging more — and that guilt is a risk signal, not a selling point.

### Portfolio Monitoring — Underpriced at Business

**Proposed price:** Business at £99.90/month  
**Recommended price:** Business at £399/month  
**Rationale:** An MSP managing 25 client workspaces on a single platform at £99.90/month is paying £4/client/month. This is not credible pricing for a security platform. At £399/month, they are paying £16/client/month — still exceptionally good value for a tool they bill back at £50–£150/client/month.

### Scheduled Reports — Underpriced (not explicitly tiered)

**Proposed price:** Not separately called out  
**Recommended tier:** Professional (£149/month)  
**Rationale:** Automated report delivery is a professional workflow feature. Include it explicitly in Professional and above. The combination of Scheduled Scans (Starter) + Scheduled Reports (Professional) creates a clear automation progression.

---

## 10. Features Currently Overpriced

**There are no features that are overpriced at the recommended pricing.** The current proposal is universally underpriced. The question is not where to reduce price — it is where the largest value gaps exist between what is charged and what the market will pay.

The closest to "watch this" is:

### Enterprise — Risk of Over-engineering

If Enterprise is positioned too far above Business (e.g., £2,000+/month for features that MSPs need), there is a risk that the Business→Enterprise gap becomes a barrier rather than a path. Enterprise should primarily be for MSPs needing custom limits, SSO, and SLA guarantees — not for features that belong at Business. The boundary between Business and Enterprise must be clearly "scale and contractual guarantees," not "extra features."

---

## 11. Revenue Optimization Recommendations

### 1. Lead with Cyber Essentials in UK Marketing

No other feature in the product has the UK-specific commercial power of Cyber Essentials Readiness. UK government contracts, cyber insurance, and supply chain requirements make this a hard-deadline, budget-unlocking feature. Every UK marketing channel should lead with this.

Recommended messaging: *"Find out if you'd pass Cyber Essentials — in 5 minutes, not 5 months."*

### 2. Price Annual Billing Prominently

Annual billing improves cash flow and reduces churn. Offer a 20% discount on annual:

| Plan | Monthly | Annual (per month) | Annual saving |
|---|---|---|---|
| Starter | £49 | £39 | £120/year |
| Professional | £149 | £119 | £360/year |
| Business | £399 | £319 | £960/year |

Position annual as the default on the pricing page — monthly as the explicit choice. This is standard SaaS practice and meaningfully increases ACV.

### 3. Create a vCISO/Consultant Bundle

Package Business specifically for the consultant persona with explicit messaging:

- "Manage up to 25 client workspaces"
- "White-label reports under your brand"
- "One portfolio view for all clients"
- "Automated report delivery to clients"

This is not a pricing change — it is positioning the same Business tier differently for a specific persona. vCISOs will self-identify and convert faster if they see their workflow described explicitly.

### 4. MSP Partner Programme at Enterprise

MSPs who manage 50+ clients should not be on the standard Business tier — they should be on a named MSP programme with:
- Volume pricing (per-workspace rate, not flat fee)
- A dedicated partner portal
- Co-marketing opportunities
- A named account contact

This is a route to £10k+ ARR from a single MSP customer.

### 5. Add a Cyber Essentials Readiness Report as a Standalone Upsell

Consider offering a one-time Cyber Essentials Readiness Report as a £99–£149 standalone purchase for Free and Starter users who are not ready to commit to Professional monthly. This:
- Converts fence-sitters who have a compliance need but resist monthly subscription
- Gets their card on file
- Creates a natural conversion path to Professional when they want continuous monitoring

### 6. Use Trial Strategically

The recommended trial model:
- **Free:** No trial, permanent. Gets them into the product.
- **Starter:** 14-day trial, no card required. Removes friction at first paid conversion.
- **Professional:** 14-day trial when upgrading from Starter. The Cyber Essentials report alone should convert within 14 days.
- **Business:** 14-day trial. MSPs need time to set up workspaces before they commit.

Do not offer trials as a way to access Enterprise. Enterprise is sales-assisted.

### 7. Show the Competitor Cost Comparison In-App

When a user hits a plan limit or explores an upgrade, show: *"A single Cyber Essentials gap assessment costs £500–£2,000 with a consultant. CyberMeters Professional gives you continuous readiness monitoring at £149/month."*

This is not aggressive — it is accurate, and it reframes the price from "cost" to "ROI."

---

## 12. Final Pricing Recommendation

### Recommended Plan Pricing

| Plan | Monthly | Annual (per month) | Annual (billed upfront) | Target ARR per customer |
|---|---|---|---|---|
| Free | £0 | £0 | £0 | £0 |
| Starter | £49 | £39 | £468 | £468–£588 |
| Professional | £149 | £119 | £1,428 | £1,428–£1,788 |
| Business | £399 | £319 | £3,828 | £3,828–£4,788 |
| Enterprise | Custom | Custom | Custom | £6,000–£24,000+ |

### Revenue Scenarios

| Mix | Customers | Monthly Revenue | ARR |
|---|---|---|---|
| 50 Starter (monthly) | 50 | £2,450 | £29,400 |
| 20 Professional (monthly) | 20 | £2,980 | £35,760 |
| 5 Business (monthly) | 5 | £1,995 | £23,940 |
| **Year 1 realistic mix** | **75** | **£7,425** | **£89,100** |

Compare this to the current proposed pricing (same mix):

| Mix | Customers | Monthly Revenue | ARR |
|---|---|---|---|
| 50 Starter @ £9.90 | 50 | £495 | £5,940 |
| 20 Professional @ £29.90 | 20 | £598 | £7,176 |
| 5 Business @ £99.90 | 5 | £500 | £5,994 |
| **Year 1 realistic mix** | **75** | **£1,593** | **£19,110** |

**The recommended pricing generates 4.6x more ARR from the same number of customers.**

### Summary of Changes vs. Current Proposal

| Item | Current Proposal | Recommended |
|---|---|---|
| Starter price | £9.90 | £49 |
| Professional price | £29.90 | £149 |
| Business price | £99.90 | £399 |
| BRS placement | Professional | Starter (summary) + Professional (full) |
| Executive Report | Starter | Starter (basic) + Professional (full) |
| Scheduled Reports | Not tiered | Professional |
| BRS trend history | Not tiered | Professional |
| Vendor risk history | Not tiered | Business |
| API access | Not listed | Business |
| White-label price | Business @ £99.90 | Business @ £399 |
| Annual discount | Not specified | 20% |

### Final Verdict

The current feature set justifies premium UK B2B pricing. The platform has Cyber Essentials Readiness, Business Risk Score, Portfolio Monitoring, White-label Reports, Vendor Risk, Historical Tracking, Scheduled Scans, and Executive Reports — this is a complete commercial security intelligence product, not a basic scanning tool.

Price it accordingly. The UK SMB, MSP, and vCISO market will not respect or trust a security platform at £9.90/month. They will pay £49, £149, and £399/month for a product that makes them look competent to their boards, their clients, and their auditors. CyberMeters does exactly that.

---

*CyberMeters Platform — Commercial Packaging & Pricing Strategy v1 — Confidential — June 2026*
