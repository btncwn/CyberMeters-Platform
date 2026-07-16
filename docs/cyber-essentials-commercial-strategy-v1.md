# CyberMeters — Cyber Essentials Commercialisation Strategy v1

> **Status: Historical / Superseded (16 July 2026).** Retained for historical
> context — the market analysis and buyer personas are still useful background —
> but this is **not** a source of truth, not current messaging, and not an
> instruction to engineering, product or marketing. Canonical pricing and
> packaging: `docs/PRICING-POLICY.md` (DECIDED 2026-07-09) · canonical Cyber
> Essentials product boundary: `docs/cyber-essentials-readiness.md` and
> `docs/alerts-eight-domain-coverage.md` · canonical competitive positioning:
> `docs/competitive-battlecard-v2.md` · current canonical episode and release
> facts: `CLAUDE.md`.
>
> **Why superseded — pricing.** Every price below (Professional £149, Business
> £399, annual £1,428 / £3,828, and the ARR arithmetic built on them) is legacy.
> The adopted policy of 2026-07-09 relabels `professional` to "Growth" and
> `enterprise` to "MSP / Partner" and adopts different prices. Do not quote any
> figure in this document.
>
> **Why superseded — Cyber Essentials honesty.** This document was written before
> the CE evidence boundary was settled, and several of its messaging lines now
> exceed what CyberMeters can evidence. **Do not reuse them.** Specifically:
>
> - **"Find out if you'd pass Cyber Essentials" / "would we pass today"** — CE has
>   five controls. Two of them, **User Access Control** and **Malware Protection**,
>   are `external_coverage: none`: CyberMeters cannot observe them at all and
>   persists them as `not_externally_assessable`. A pass/fail prediction cannot be
>   supported by external evidence and must never be claimed.
> - **"a report your auditor can rely on" / "be audit-ready, always"** — CyberMeters
>   is not a certification body, produces no audit-grade artefact, and cannot
>   guarantee compliance. Readiness is guidance, not assurance.
> - **"the consultant replacement argument"** — a consultant assesses all five
>   controls, including the two CyberMeters cannot see. CyberMeters does not
>   replace that assessment.
> - **"the 5 Cyber Essentials controls and how to check them continuously"** — the
>   platform cannot continuously check two of the five.
> - **"am I cyber essentials compliant"** (SEO target) — the product cannot answer
>   this question and must not be marketed as if it can.
> - **"Join UK businesses ... who use CyberMeters"** — CyberMeters has no
>   customers yet; this is an unevidenced social-proof claim.
>
> The honest boundary, which this document states correctly at §3 and which
> remains canonical: **readiness is estimated from externally observable evidence
> only; CyberMeters prepares customers for certification and does not certify,
> assess or guarantee compliance.** Since PR #106 the questionnaire is excluded
> from readiness entirely — no customer answer is treated as security truth.
>
> **Portfolio claims.** Lines describing portfolio-level CE monitoring, a portfolio
> view, or a Business-trial portfolio evaluation describe **entitlement placement
> and intent**, not shipped capability. MSP Portfolio Per-Domain State and Trend is
> a planned canonical episode that has not started.

**Version:** 1.0 | **Date:** June 2026 | **Status:** Superseded (was: Active Commercial Direction)

**Scope:** Market opportunity, buyer personas, positioning, messaging, conversion funnel, GTM  
**Classification:** Internal commercial strategy — not for external distribution

> Cyber Essentials Readiness is the primary upgrade driver from Starter to Professional (£149/month). This document defines the commercial strategy for making that conversion reliable, repeatable, and scalable across the UK SMB, consultant, MSP, and government contractor market.

---

## Table of Contents

1. [Market Opportunity](#1-market-opportunity)
2. [Buyer Personas](#2-buyer-personas)
3. [Competitive Positioning](#3-competitive-positioning)
4. [Professional Plan Value Proposition](#4-professional-plan-value-proposition)
5. [Messaging Framework](#5-messaging-framework)
6. [Conversion Funnel](#6-conversion-funnel)
7. [Revenue Potential](#7-revenue-potential)
8. [Go-To-Market Recommendations](#8-go-to-market-recommendations)

---

## 1. Market Opportunity

### What Cyber Essentials Is

Cyber Essentials is a UK government-backed cybersecurity certification scheme, operated by the National Cyber Security Centre (NCSC) and delivered through accreditation bodies including IASME and QG. It defines five technical controls — boundary firewalls, secure configuration, access control, malware protection, and patch management — and provides a standardised framework against which organisations can assess and certify their baseline security posture.

There are two levels:

- **Cyber Essentials** — self-assessed questionnaire, externally verified by a certifying body
- **Cyber Essentials Plus** — all of the above, plus independent technical testing

A Cyber Essentials certificate is valid for 12 months and must be renewed annually.

### Why It Matters Commercially

Cyber Essentials is not optional for a growing segment of UK businesses. It has moved from a best-practice recommendation to a procurement and insurance requirement in four distinct areas, each of which creates a hard buying trigger:

**Government contracts.** The UK Cabinet Office has mandated Cyber Essentials certification for all government contracts involving the handling of personal data or the provision of certain technical services since 2014. The Ministry of Defence extended this requirement across its supply chain. In practice, any company bidding for a UK public sector contract will encounter a Cyber Essentials requirement at some point in the procurement process. There are approximately 500,000 companies on UK government supplier registers. Every one of them is a potential CyberMeters Professional customer.

**Cyber insurance.** The cyber insurance market hardened significantly following the wave of ransomware incidents in 2021–2023. UK insurers including Hiscox, AXA, and QBE now actively use Cyber Essentials as a risk indicator. Many policies offer premium discounts for certified organisations; an increasing number are beginning to use certification status as an underwriting criterion. The cyber insurance renewal cycle — typically annual — creates a recurring, time-pressured buying event.

**Supply chain requirements.** Large UK enterprises — particularly in financial services, defence, healthcare, and retail — are increasingly mandating Cyber Essentials certification from their suppliers and subcontractors as a condition of doing business. A small company winning a contract with a FTSE 250 client may find that Cyber Essentials certification is embedded in the contract terms. This cascades the requirement down the supply chain to businesses of all sizes.

**Professional credibility.** For SMBs that are not subject to a hard mandate, Cyber Essentials certification is increasingly used as a differentiator — a signal to customers, partners, and investors that the business takes security seriously. In competitive tenders for professional services, legal, or technology work, having a current Cyber Essentials certificate is becoming a selection criterion.

### The UK SMB Market

The UK has approximately 5.5 million businesses with fewer than 250 employees. Of these, the commercially relevant segment for CyberMeters Professional is broadly defined by two criteria: they have a meaningful internet presence (a domain, email, some web-facing infrastructure) and they have an external reason to demonstrate security posture (a contract, an insurer, or a client relationship that requires it). This addressable market is conservatively 300,000–800,000 businesses in the UK.

Cyber Essentials certification numbers are growing at approximately 20–30% per year. As of 2025, approximately 40,000–50,000 certificates were issued annually. The gap between demand (hundreds of thousands of businesses with a need to certify) and supply (tens of thousands actually certifying) represents a market where awareness and friction are the primary barriers — exactly the problem CyberMeters Professional is designed to solve.

### The UK Consultant and vCISO Market

The UK has a large and growing market for fractional and outsourced security services. Virtual CISO services, security consultancies, and managed security advisors collectively serve tens of thousands of UK SMBs who cannot justify a full-time security hire. For this segment, Cyber Essentials gap assessment and remediation support is a standard, billable service offering.

A typical Cyber Essentials engagement with a security consultant involves:
- An initial gap assessment: £500–£2,000
- Remediation advisory: £500–£3,000
- Certification support: £250–£500

Total: £1,250–£5,500 per client per year. A vCISO with 10 clients performing annual CE assessments manually is spending 2–5 days per client per engagement on work that CyberMeters automates continuously.

The consultant market is strategically important for two reasons: consultants are high-LTV Business plan customers (they need white-label reports and portfolio monitoring), and they are influencers within the SMB market — their clients follow their tool recommendations.

### The MSP Market

The UK managed service provider market comprises approximately 3,000–5,000 active MSPs. MSPs are under significant pressure from their SMB clients to offer security services alongside their traditional IT management offerings. Cyber Essentials is the natural entry point for an MSP expanding into security: it is well-known, government-endorsed, not technically overwhelming, and directly relevant to the client base an MSP already serves.

For an MSP, Cyber Essentials is a service they can sell, not just a compliance exercise. An MSP that offers "Cyber Essentials Readiness Monitoring" as a managed service to 30 clients at £50/client/month generates £1,500/month from CyberMeters Business (£399/month) — a 3.75x return before any additional services.

The MSP market is the highest-value long-term segment. MSP customers convert at Business (£399/month), have high retention (they embed the tool in their client delivery workflow), and create downstream SMB awareness through their client relationships.

### The Government Contractor Ecosystem

The UK public sector supply chain is one of the most structurally compelling Cyber Essentials markets. It is large, mandate-driven, and subject to annual renewal cycles. Key characteristics:

- Crown Commercial Service (CCS) framework suppliers are subject to ongoing CE requirements
- NHS supply chain mandates extend CE requirements to medical technology and IT suppliers
- Defence suppliers under DEFSTAN and MOD requirements have multi-year CE obligations
- Local authority procurement increasingly includes CE in supplier pre-qualification questionnaires

Government contractor buyers are motivated by a specific, externally-imposed deadline rather than discretionary security investment. This makes them among the easiest Professional plan conversions — they already have budget allocated, they already have a timeline, and they need a credible ongoing readiness assessment, not a one-time certification support engagement.

---

## 2. Buyer Personas

### Persona 1 — The SMB Owner

**Who they are:** Founder or Managing Director of a 10–100 person UK business. Not a technology specialist. Has delegated IT to an IT Manager or a part-time IT support contractor. Cares about security only when a specific business event forces the issue.

**Their world:** They are busy running a business. Security is not on their radar until it becomes a commercial problem. They've heard of Cyber Essentials — probably from a government tender portal, their bank, or their insurance broker — but they don't know what it means in practical terms or whether their business would pass.

**Pain points:**
- A tender requirement asks for a current Cyber Essentials certificate and they don't have one
- Their cyber insurance broker has asked about their security posture for the upcoming renewal
- A potential enterprise client has included Cyber Essentials as a condition in a contract
- They experienced a security incident (a phishing attack, a data breach scare) and want to be able to say "we've done something about it"

**Buying triggers:**
- Procurement portal asks for CE certificate — hard deadline, weeks away
- Insurance renewal — annual event, broker raises CE as a question
- Client contract requirement — immediate commercial pressure
- Post-incident — emotional and reputational pressure

**Why they would pay £149/month for Professional:**
They won't think about this as a £149/month decision. They will think about it as "this helps me win the contract" or "this satisfies my insurer." The £149/month cost is invisible against the value of the contract or the insurance premium. What matters is that the output — a readiness report they can show someone — exists and is credible.

The SMB Owner does not need to understand the tool in detail. They need to be able to say: "We run continuous Cyber Essentials monitoring and here's our current readiness report." CyberMeters Professional gives them that sentence.

**How they make the purchase decision:** They ask their IT Manager (or IT support contractor) to look into it. The IT Manager evaluates it. The SMB Owner approves the spend if the IT Manager recommends it. The decision is made in days, not months.

---

### Persona 2 — The IT Manager

**Who they are:** Head of IT or IT Manager at a 50–500 person UK company. May have a small team or work solo. Technically capable but not a dedicated security specialist. Responsible for making security-adjacent decisions and producing evidence of security posture for management and external parties.

**Their world:** They manage a mix of infrastructure, helpdesk, vendor relationships, and increasingly security. They've been asked by their CEO or CFO to "sort out the Cyber Essentials thing" without being given additional budget or resource. They know what Cyber Essentials is. They know they should probably have it. They don't have time to spend weeks on a manual assessment.

**Pain points:**
- Management has asked for a Cyber Essentials update and they don't have a credible answer
- They've tried to self-assess using the official questionnaire but it's time-consuming and ambiguous
- They know their IT environment has issues but don't know which ones are CE-relevant
- They need to produce a gap report but don't have a professional document to put in front of management
- They've been asked about CE by a client or partner and are not confident in their answer

**Buying triggers:**
- Management request with a deadline (board meeting, audit, contract bid)
- Completing the IASME self-assessment questionnaire and finding it overwhelming
- A client or partner asking for evidence of CE compliance
- Starting the CE certification process and wanting a continuous view of readiness between assessments

**Why they would pay £149/month for Professional:**

The IT Manager's primary concern is being able to produce evidence quickly when asked. CyberMeters Professional gives them a current Cyber Essentials readiness score at any point in time, a gap report they can present to management, and continuous monitoring so they are never caught off-guard by an audit or a client enquiry.

The alternative is hiring a consultant for £500–£2,000 to produce a point-in-time assessment that is out of date in three months. At £149/month, CyberMeters Professional is cheaper than one consultant engagement per quarter. The IT Manager can explain this ROI clearly to their manager.

**How they make the purchase decision:** They evaluate the tool during a trial, run a CE readiness scan, see the gap report, and either approve the spend themselves (if within their discretionary budget) or present the recommendation to their line manager with the ROI argument. Decision cycle: 2–4 weeks.

---

### Persona 3 — The MSP

**Who they are:** Owner or sales/service director at a UK managed service provider with 20–100 SMB clients. Currently provides IT support, Microsoft 365 management, backup, and networking. Looking to add security services as a new revenue line or is already doing so in a basic way.

**Their world:** Their clients are asking about cybersecurity — they've seen news coverage of ransomware and data breaches. The MSP knows they need to offer something, but a full MSSP capability is too expensive and complex to build. They need a tool that lets them offer Cyber Essentials as a managed service: assessing client readiness, reporting to clients, and supporting certification — all under their own brand.

**Pain points:**
- Clients ask "are we Cyber Essentials compliant?" and the MSP has no professional answer
- Manual CE assessments for clients are time-consuming and don't scale
- Competitor MSPs are starting to offer security services; they risk being differentiated against
- They don't want to expose their tooling to clients — they need white-label delivery
- They need a single view of all clients' security posture, not a separate tool per client

**Buying triggers:**
- A client is bidding for a government contract and needs CE — the MSP needs to help them
- A competitor MSP starts offering CE-as-a-service and the MSP needs to match the offer
- A client suffers a security incident and the MSP needs a credible response capability
- The MSP decides to formally launch a security services line and needs a platform to anchor it

**Why they would pay £399/month for Business:**

The MSP does not pay £399/month for security monitoring. They pay £399/month to offer a managed Cyber Essentials readiness service to 25 clients at whatever margin they choose — typically £30–£100/client/month in additional monthly billing. CyberMeters Business costs them £16/client/month across 25 clients and enables revenue of £750–£2,500/month from those clients. The ROI is immediate and obvious.

White-label reports are non-negotiable for the MSP — the client relationship is their business asset, and they cannot allow a vendor's brand to appear in client-facing work. Portfolio Monitoring is equally essential — managing 25 clients one at a time is not a business, it is a manual process.

**How they make the purchase decision:** The MSP owner or service director makes the decision. They evaluate the Business plan trial, set up two or three client workspaces, and assess whether the portfolio view and white-label reporting meet their delivery requirements. Decision cycle: 1–3 weeks. The key moment is seeing a white-label PDF report with their logo on it.

---

### Persona 4 — The vCISO Consultant

**Who they are:** Solo practitioner or small-team security consultancy providing fractional CISO services to 5–20 UK SMB clients. Charges £1,500–£5,000/month per client engagement. Cyber Essentials gap assessment and support is a standard part of their service offering.

**Their world:** They sell expertise, not software. Their clients pay for their knowledge, their professional judgment, and their ability to produce credible security deliverables — reports, roadmaps, assessments. They spend a disproportionate amount of their billable time producing documentation manually: gap analyses, risk summaries, compliance reports. Every hour spent on documentation is an hour not spent on higher-value advisory work.

**Pain points:**
- Manual CE gap assessments take 1–2 days per client per cycle
- Client reports are produced in Word or PowerPoint — not scalable and not continuously updated
- They have no continuous visibility between assessments — only point-in-time knowledge
- They cannot monitor 15 clients simultaneously without a platform
- They want to offer proactive monitoring, not reactive assessments

**Buying triggers:**
- A new client engagement that requires ongoing CE monitoring and reporting
- An existing client asks for more frequent CE status updates between annual assessments
- The consultant wants to move from project-based CE assessments to a monthly retainer model
- A competitor consultant starts offering continuous CE monitoring and the vCISO needs to match

**Why they would pay £399/month for Business:**

The vCISO's economic case is straightforward: CyberMeters Business saves them 1–2 days of billable time per client per month on documentation and status reporting. At a day rate of £600–£1,200, this is £600–£2,400 saved per client per month, across however many clients they manage. At 10 clients, the tool saves £6,000–£24,000/month in manual effort, at a cost of £399/month. There is no meaningful price objection.

Beyond economics, CyberMeters Professional and Business give the vCISO continuous readiness data that a manual assessment cannot provide. They can tell a client what their CE status is today, not what it was six months ago when the last assessment was conducted.

White-label reports are the key feature: a vCISO cannot send a CyberMeters-branded report to a client and maintain their professional positioning. Their name on the report is part of what the client is paying for.

**How they make the purchase decision:** The vCISO evaluates the tool on a specific client use case. They run a CE readiness report for one client, export the white-label PDF, and assess whether it meets the quality standard they present to clients. Decision cycle: 1–2 weeks. The conversion is driven by the quality of the white-label report output.

---

## 3. Competitive Positioning

### Certification Bodies (IASME, QG, Pentest People, etc.)

**What they do:** Certification bodies offer the official Cyber Essentials and Cyber Essentials Plus certification process. They administer the self-assessment questionnaire, verify answers, and issue certificates. Some offer gap assessment services as a precursor to certification.

**Their limitation:** Certification bodies offer a point-in-time service. They certify what exists today. They provide no ongoing monitoring, no continuous readiness status, and no alert when configuration drift introduces a gap. The certificate is valid for 12 months, but posture can change within days.

**CyberMeters position:** CyberMeters is not a certification body and does not compete with them. CyberMeters is what you use to prepare for certification and to maintain readiness between cycles. The relationship is complementary: CyberMeters keeps you ready; the certification body formally validates and certifies you.

**Messaging:** *"Use CyberMeters to know you're ready before you apply. Use a certification body to get the certificate."*

---

### Basic Vulnerability Scanners (Qualys, Tenable, Nessus, OpenVAS)

**What they do:** Vulnerability scanners identify known technical vulnerabilities in systems and networks. They produce long lists of CVEs, severity scores, and patch recommendations. They are powerful tools designed for security professionals with dedicated expertise.

**Their limitation for this market:** Vulnerability scanners are not CE-specific. They do not map findings to the five Cyber Essentials control areas. Their output is technical — lists of CVEs and CVSS scores — which is inaccessible to an IT Manager or SMB Owner without security training. They are typically designed for internal network scanning, not the external attack surface that CE predominantly addresses. Enterprise pricing (£300–£1,500+/year for entry-level tools) and complexity make them unsuitable for the SMB segment.

**CyberMeters position:** CyberMeters speaks in business language, not CVE language. It maps findings to CE control areas, produces a readiness assessment rather than a vulnerability list, and generates a board-ready report rather than a technical remediation backlog. It is designed for the person responsible for security posture, not the person responsible for patching systems.

**Messaging:** *"Qualys tells your security team what's broken. CyberMeters tells your board whether you're ready for Cyber Essentials."*

---

### Security Scorecard Tools (SecurityScorecard, UpGuard, BitSight, RiskRecon)

**What they do:** External risk rating platforms continuously monitor the external attack surface of organisations (and their vendors) and assign risk scores, typically on a letter-grade scale. They are used primarily by enterprise risk, procurement, and vendor management teams to assess third-party risk.

**Their limitation for this market:**
- They are not CE-specific — their scoring models are proprietary and not aligned to the UK CE framework
- They are not UK-specific — their scoring models are built around US-centric frameworks and compliance requirements
- They are priced for enterprise ($500–$5,000+/month) and are entirely inaccessible to the UK SMB market
- They produce vendor risk intelligence, not self-assessment readiness reports
- Their output is comparative (how do you compare to peers?) not prescriptive (what do you need to fix to pass Cyber Essentials?)

**CyberMeters position:** CyberMeters shares the external monitoring approach of these tools but is purpose-built for the UK market, CE-aligned, and priced for SMBs. Where SecurityScorecard answers "how risky is this vendor?", CyberMeters answers "would we pass Cyber Essentials today, and what do we need to fix?"

**Messaging:** *"SecurityScorecard is built for enterprise vendor risk teams. CyberMeters is built for UK IT Managers who need to know if they're Cyber Essentials ready."*

---

### Compliance Platforms (Vanta, Drata, Sprinto, Tugboat Logic)

**What they do:** Compliance automation platforms help organisations achieve and maintain certifications like SOC 2, ISO 27001, GDPR, and HIPAA. They connect to cloud infrastructure, collect evidence, and manage the compliance workflow from assessment through to certification.

**Their limitation for this market:**
- Their primary frameworks are SOC 2 and ISO 27001 — Cyber Essentials is rarely a first-class feature
- They are evidence management platforms, not attack surface monitors — they track what you've done, not what your external footprint looks like
- Enterprise pricing (£500–£2,000+/month) makes them inaccessible to UK SMBs
- Their primary market is US SaaS companies preparing for enterprise customer audits, not UK SMBs preparing for government contracts

**CyberMeters position:** CyberMeters occupies a distinct position between the compliance platform world and the attack surface monitoring world. It continuously monitors the external attack surface and maps findings directly to CE control requirements — without requiring the overhead of a full compliance management platform. It is the right tool for the 95% of UK SMBs who need CE but are not yet thinking about SOC 2 or ISO 27001.

**Messaging:** *"Vanta is where you go when you need SOC 2 for a US enterprise client. CyberMeters is where you go when you need Cyber Essentials for a UK government contract."*

---

### The Unserved Market Gap

No current tool in the UK market:
- Continuously monitors external attack surface against CE control areas
- Produces a plain-language CE readiness score and gap report
- Is priced accessibly for UK SMBs (sub-£200/month)
- Offers white-label delivery for consultants and MSPs
- Provides portfolio-level CE monitoring across multiple clients

This gap is the commercial opportunity. CyberMeters Professional fills it.

---

## 4. Professional Plan Value Proposition

### Why Cyber Essentials Readiness Belongs at Professional (£149/month)

Cyber Essentials Readiness is not a feature — it is a commercial outcome. When an IT Manager subscribes to Professional, what they are purchasing is the ability to answer yes to the question: *"Are you Cyber Essentials ready?"* — at any point in time, with evidence.

**The consultant replacement argument.** A UK IT Manager who needs a CE gap assessment has two choices: hire a consultant (£500–£2,000, point-in-time, outdated within weeks) or subscribe to CyberMeters Professional (£149/month, continuous, always current). The ROI case closes within one billing cycle. CyberMeters Professional pays for itself against one avoided consultant engagement within 1–3 months. Every month after that is net positive.

**The compliance insurance argument.** A business that holds Cyber Essentials certification and loses it — because their configuration drifted, because a new system was added without security review, because a certificate expired — faces immediate commercial consequences: losing a contract eligibility, losing an insurance premium discount, failing a client audit. CyberMeters Professional is the insurance policy against silent compliance drift. You cannot know you've failed until you check — and continuous monitoring means you check automatically.

**The pricing signal argument.** Placing Cyber Essentials Readiness at Professional rather than Starter sends the correct market signal: this is a serious compliance capability, not a basic feature. It communicates that CyberMeters Professional is the platform for businesses that need to demonstrate security posture — to clients, auditors, insurers, and government bodies. £149/month for continuous CE monitoring is not a technology purchase; it is a compliance risk management decision.

**Why it cannot be at Starter.** If Cyber Essentials Readiness is available at Starter (£29/month), the Professional plan loses its primary commercial anchor. Starter becomes the tool with everything a UK SMB needs. The conversion from Starter to Professional has no meaningful trigger. The revenue impact of this error is significant: every Professional customer who would have paid £149/month instead pays £29/month.

**Why it cannot be at Business.** If Cyber Essentials Readiness is at Business (£399/month), the vast majority of the UK SMB market — the most commercially significant volume segment — cannot access it at a reasonable price. The MSP and vCISO market can afford Business, but the government contractor ecosystem, the insurance-triggered SMB, and the supply chain compliance buyer all need CE readiness at a price point they can approve without escalation. £149/month is that price. £399/month is not.

### The Professional Plan Commercial Identity

Professional is the **compliance tier**. It answers the question every UK IT Manager and SMB Owner with an external compliance obligation needs answered: *"Are we ready?"*

| Capability | What It Answers |
|---|---|
| Cyber Essentials Readiness | "Would we pass Cyber Essentials today?" |
| Vendor Risk | "Are the tools and services we rely on creating risk?" |
| SaaS Exposure | "What SaaS tools are we using and what risk do they carry?" |
| Third-Party Risk | "What third-party dependencies are in our attack surface?" |
| Advanced Reporting | "What can I show my board, my insurer, my client?" |
| Extended Retention | "Can I produce 12 months of compliance evidence?" |

Every capability in Professional serves a compliance or audit context. Professional is not "more features" — it is a coherent answer to "can we prove we're secure?"

---

## 5. Messaging Framework

### Homepage Messaging

**Primary headline:**
> Know if your business would pass Cyber Essentials — today, not six months ago.

**Supporting statement:**
> CyberMeters continuously monitors your attack surface and tells you exactly where you stand against the UK's Cyber Essentials framework. No consultant needed. No waiting. Always current.

**Social proof anchor:**
> Join UK businesses, IT consultants, and MSPs who use CyberMeters to stay audit-ready year-round.

**Secondary headline (for scroll):**
> Cyber Essentials readiness, continuously monitored for £149/month.

---

### Pricing Page Messaging

**Professional plan header:**
> Be audit-ready, always.

**Professional plan subheading:**
> Continuous Cyber Essentials readiness monitoring, vendor risk intelligence, and board-ready executive reports.

**Feature callout (CE):**
> ✓ Cyber Essentials Readiness — know your gap before your auditor finds it

**Pricing justification line:**
> A single Cyber Essentials gap assessment with a consultant costs £500–£2,000. CyberMeters Professional gives you continuous monitoring for £149/month.

**Annual billing nudge:**
> Save 20% with annual billing — £119/month, billed as £1,428/year.

---

### Professional Plan Upgrade Messaging (In-App)

**Locked feature surface (Cyber Essentials tab in Starter):**
> **Cyber Essentials Readiness — Professional**
> Find out exactly where you stand against the UK's Cyber Essentials framework. Identify gaps before your next audit, tender, or insurance renewal.
> [Upgrade to Professional — £149/month]

**After running a scan on Starter:**
> Your Business Risk Score is ready. To see how you'd perform against Cyber Essentials and where your gaps are, upgrade to Professional.
> [See your Cyber Essentials readiness]

**Starter user — triggered by 30 days of monitoring:**
> You've been monitoring for 30 days. Are you Cyber Essentials ready? Professional gives you a continuous readiness assessment and a gap report you can share with clients, auditors, or your management team.
> [Upgrade to Professional]

---

### Upgrade Banner Messaging (Context-Specific)

**When a Starter user views the Cyber Essentials tab:**
> Cyber Essentials Readiness is a Professional feature. Upgrade to see your current gap assessment and produce a report your auditor can rely on.

**When a Starter user is within 60 days of their annual renewal period:**
> Your Cyber Essentials certificate renewal is coming up. Stay ahead of your audit with continuous readiness monitoring. Upgrade to Professional.

**When a Starter user hits a report limit:**
> You're getting value from CyberMeters. Upgrade to Professional to unlock advanced reports, Cyber Essentials readiness, and extended retention for compliance evidence.

**When a Free user sees their BRS for the first time (teaser):**
> Your Business Risk Score shows you're exposed. To see how this maps to Cyber Essentials and what you'd need to fix before certification, upgrade to Starter — then Professional.

---

### Sales / Outbound Email Messaging

**Subject:** Is your business Cyber Essentials ready?

> Hi [Name],
>
> If your business bids for UK government contracts, holds cyber insurance, or supplies products and services to larger companies, there's a good chance you've been asked about Cyber Essentials.
>
> Most IT teams find out they're not ready at the worst possible time — when a contract is on the line.
>
> CyberMeters continuously monitors your external attack surface and tells you exactly where you stand against Cyber Essentials — today, not when your next assessment is due.
>
> [Start your free trial]

---

## 6. Conversion Funnel

### Free → Starter

**Primary mechanism: Business Risk Score as the visibility hook**

When a Free user runs their first scan, they see their ASM technical score — a raw number with a list of findings. They do not see the Business Risk Score. In the UI, the BRS is visible but locked: the grade (the letter) is shown grayed out; the narrative and category breakdown are hidden behind an upgrade prompt.

This is deliberate. The BRS grade is the single most legible output the platform produces. An IT Manager who sees a partially revealed "C — Elevated Risk" grade for their domain immediately wants to know what that means, what the breakdown is, and how to show it to their CEO. Starter unlocks that.

**Objections and responses:**

| Objection | Response |
|---|---|
| "I can get this information from free tools" | Free tools give you a vulnerability list. The BRS gives you a business risk narrative your CEO can read. |
| "£29/month is a monthly cost I need to justify" | One scheduled scan delivers this automatically every week. The cost of your time to do it manually is more than £29/month. |
| "I'm not sure I'll use it enough" | Set up a scheduled scan. It runs automatically. You don't need to think about it. |

**Expected Free → Starter conversion rate:** 15–25% of active Free users (users who have run at least 3 manual scans). The trigger is typically the third manual scan — at this point, the friction of manual operation is felt.

---

### Starter → Professional

**Primary mechanism: Cyber Essentials Readiness as the compliance lock**

In the Starter UI, the Cyber Essentials Readiness tab is visible in the workspace navigation. Clicking it shows a locked state: a preview of what the readiness assessment looks like, the control areas it covers, and a clear upgrade prompt. The tab is never hidden — it is always reachable and always visible as an available (but locked) capability.

Three types of Starter users convert to Professional:

**Type 1 — The deadline-driven converter.** A contract bid, insurance renewal, or client request creates an immediate deadline. They see the Cyber Essentials tab, click it, hit the upgrade prompt, and upgrade within hours. This is the fastest conversion — triggered by an external event, not a product experience.

**Type 2 — The report-quality converter.** After 30–60 days on Starter, they need to produce a comprehensive report for management. The basic executive summary in Starter is not sufficient for a board presentation. They want the full report with BRS trend, category breakdown, and CE readiness — Professional unlocks all of this.

**Type 3 — The intelligence-gap converter.** After using Starter for a while, they notice the Vendor Risk and SaaS Exposure sections are locked. They've become aware of third-party risk (either from industry news or from a client asking about it) and want to understand their exposure. Professional unlocks this.

**Conversion timing:** Type 1 converts within days. Types 2 and 3 convert within 30–90 days of Starter activation. The 14-day Professional trial (offered when upgrading from Starter) should be structured to deliver a CE readiness report within the first week — making the value tangible before the trial expires.

**The 14-day Professional trial structure:**

| Day | Suggested action | Value delivered |
|---|---|---|
| 1 | Scan runs automatically | CE readiness score appears |
| 2 | Email: "Your Cyber Essentials readiness report is ready" | Customer sees their gap for the first time |
| 7 | Email: "Here's your gap report — ready to share" | PDF download with CE breakdown |
| 12 | Email: "Your trial ends in 2 days — keep your CE monitoring active" | Conversion prompt with annual pricing |
| 14 | Trial ends | Upgrade or revert to Starter |

**Objections and responses:**

| Objection | Response |
|---|---|
| "I already know we have gaps — I don't need a report to tell me" | Your auditor, insurer, or client does need a report. CyberMeters gives you the evidence in a format they can act on. |
| "£149/month is more than I expected" | One CE gap assessment with a consultant costs more than £149. This gives you continuous monitoring for the same annual cost as two consultants visits. |
| "We're not going for CE certification yet" | CE readiness monitoring is valuable before you certify, while you certify, and after — to stay ready for your next renewal. |
| "We already have a consultant who does this" | Your consultant does it annually. CyberMeters does it continuously. You'll know about gaps before they do. |

**Expected Starter → Professional conversion rate:** 25–35% of Starter users within 90 days. The conversion is highest for users who have received a government contract tender or insurance renewal communication while on Starter.

---

### Professional → Business

**Primary mechanism: White-Label Reports + Portfolio Monitoring as the scale lock**

The Professional → Business conversion is driven by scale: the customer needs to manage more than one client, or they need to remove CyberMeters branding from their client deliverables.

In the Professional UI:
- The "Add workspace" function is accessible but limited; attempting to create a workspace beyond the Professional limit surfaces the Business upgrade prompt
- The report export settings show a locked "White-label" option with an upgrade prompt
- The Portfolio Dashboard tab is visible but locked

**Expected Professional → Business conversion rate:** 20–30% of Professional users who are consultants or MSPs. SMB IT Managers rarely need Business — it is a segment-specific conversion rather than a universal one.

---

## 7. Revenue Potential

### Segment Analysis

**UK SMB IT Managers — Largest volume, Professional tier**

The UK SMB IT Manager segment is the broadest and most accessible. It does not require outbound sales — it converts through content, search, and trial. The buying trigger (government contract, insurance renewal, client requirement) is externally supplied.

Conservative Professional customer assumptions:
- Addressable market: 300,000+ UK SMBs with an external CE obligation
- Awareness and trial conversion: 0.05% in year one = 150 trial starts
- Trial to Professional conversion: 30% = 45 Professional customers
- ARR per Professional customer (annual billing): £1,428
- **Year 1 SMB Professional ARR: ~£64,000**

This is a conservative floor. As content and search presence builds, trial volumes scale without proportional cost increase.

---

**UK vCISOs and Consultants — Highest LTV per customer, Business tier**

This segment converts faster (higher intrinsic motivation, professional purchase) and at a higher plan level (Business, for white-label reports and portfolio monitoring). There are approximately 2,000–5,000 active UK security consultants and vCISOs who serve the SMB market.

Conservative Business customer assumptions from the consultant segment:
- Reachable consultants in year one: 500 (via LinkedIn, security communities, referral)
- Trial starts: 50 (10% conversion from awareness)
- Trial to Business conversion: 40% = 20 Business customers
- ARR per Business customer (annual billing): £3,828
- **Year 1 Consultant Business ARR: ~£77,000**

This segment also drives downstream SMB adoption — every vCISO on Business is managing clients who may eventually want their own CyberMeters account.

---

**UK MSPs — Highest strategic value, Business/Enterprise tier**

MSPs represent the most strategically important long-term segment. They have high retention (embedded in service delivery), high LTV, and a multiplier effect on SMB market awareness. There are approximately 3,000–5,000 MSPs in the UK; the addressable segment for CyberMeters Business in year one is MSPs who are actively expanding into security services — approximately 500–1,000.

Conservative Business customer assumptions from the MSP segment:
- Reachable MSPs in year one: 200 (via MSP communities, LinkedIn, trade events)
- Trial starts: 30 (15% conversion from awareness)
- Trial to Business conversion: 35% = 10 Business customers
- ARR per Business customer (annual billing): £3,828
- **Year 1 MSP Business ARR: ~£38,000**

---

### Which Segment to Target First

**Recommended priority: vCISOs and security consultants**

The consultant segment should be the primary acquisition focus in the first commercial phase for five reasons:

1. **They convert fast.** A consultant evaluating a new tool for client delivery makes a decision in days, not weeks. They have a specific use case, they know what they need, and they have budget authority.

2. **They convert at Business.** Business ARR per customer is 2.7x Professional ARR. Acquiring consultant customers is more efficient per customer than acquiring SMB customers.

3. **They create downstream SMB demand.** A consultant with 10 clients who recommends CyberMeters creates 10 potential future direct customers. The consultant is a distribution channel, not just a customer.

4. **They provide product feedback.** Consultants use the platform intensively and professionally. Their feedback on the CE readiness report quality, the gap analysis depth, and the white-label output is more commercially valuable than SMB feedback at this stage.

5. **They are reachable efficiently.** The UK vCISO and security consultant community is present on LinkedIn, in CREST and ISACA networks, and in dedicated communities (vCISO communities, IT security forums). Targeted outreach is cost-effective.

**Second priority: UK SMBs with a government contract trigger**

Government contractor communities (G-Cloud, CCS framework suppliers, Crown supplier networks) are a well-defined, CE-motivated segment. Content marketing targeting the "Cyber Essentials for government contracts" search intent has clear conversion intent and requires no outbound sales effort.

**Third priority: MSPs**

MSPs are the highest long-term value segment but the slowest to convert. They require more relationship-building, more trust in the platform's reliability, and often want a partner programme or reseller arrangement before committing at volume. Begin targeted MSP outreach in month 3–6 once the product has reference customers and case studies from the consultant segment.

---

## 8. Go-To-Market Recommendations

### Campaign 1 — "Is Your Business Cyber Essentials Ready?"

**Format:** Inbound content campaign with a high-intent lead magnet.

**Audience:** UK IT Managers, SMB owners, and compliance managers who are in or near a CE buying situation (government contract, insurance renewal, supply chain requirement).

**Channels:** Google Search (CE readiness keywords), LinkedIn (IT Manager targeting, UK, 50–500 employee companies), and UK tech press (IT Pro, Computing, The Register).

**Core offer:** A free Cyber Essentials Readiness Report for one domain — delivered via the Free plan with a clear upgrade prompt to Professional for continuous monitoring.

**Keywords to target:**
- "cyber essentials readiness"
- "cyber essentials gap assessment"
- "cyber essentials checklist"
- "am I cyber essentials compliant"
- "cyber essentials preparation"
- "cyber essentials for government contracts"
- "how to get cyber essentials"

**Landing page message:** *"Find out if your business would pass Cyber Essentials — in 5 minutes, not 5 months. Free for one domain."*

---

### Campaign 2 — Consultant and vCISO Outreach

**Format:** Targeted LinkedIn outreach and community engagement.

**Audience:** UK-based security consultants, vCISOs, and fractional security leaders.

**Message:** *"If you're doing Cyber Essentials gap assessments manually, CyberMeters does it continuously — and gives you white-label reports under your brand. Let me show you what it looks like for one of your clients."*

**Offer:** A free 14-day Business trial (not Professional) for consultants who want to evaluate the white-label and portfolio features. Seeing the output for a real client converts consultants faster than any demo.

**Communities to engage:**
- UK vCISO communities on LinkedIn and Slack
- CREST member forums
- ISACA UK chapter
- (ISC)² UK chapter
- Small MSP community forums (CompTIA, MSPU)

---

### Campaign 3 — Insurance Broker Partnership

**Format:** Partnership and co-marketing with UK cyber insurance brokers.

**Opportunity:** Cyber insurance brokers are directly upstream of the CE buying decision. When a broker asks a client about CE status and the client doesn't know, they need a tool. If CyberMeters is the tool the broker recommends, the conversion happens without any direct marketing effort by CyberMeters.

**Target partners:** UK-based cyber insurance brokers and underwriters who work with SMBs — particularly those writing policies for businesses in the government supply chain or professional services sectors.

**Partnership offer:** Co-branded CE readiness tool for the broker's clients. The broker recommends CyberMeters as their preferred readiness monitoring tool; CyberMeters offers an affiliate commission or co-branded landing page.

---

### Content Strategy

**Pillar 1 — Cyber Essentials Education**

UK SMBs search for CE information but often find only the NCSC's official documentation, which is written for a technical audience. CyberMeters can own the plain-language, business-focused CE content space.

Content to produce:
- "What is Cyber Essentials and why does your UK business need it?" (foundational explainer)
- "Cyber Essentials vs Cyber Essentials Plus — which one do you need?"
- "How to prepare for Cyber Essentials certification: a step-by-step guide for IT Managers"
- "Does my business need Cyber Essentials for a government contract?"
- "What cyber insurers are actually asking about Cyber Essentials in 2026"
- "Cyber Essentials renewal: what changes and what doesn't"

**Pillar 2 — Tools and Comparisons**

- "CyberMeters vs hiring a consultant for Cyber Essentials gap assessment"
- "How to run a Cyber Essentials readiness check without a consultant"
- "The 5 Cyber Essentials controls and how to check them continuously"

**Pillar 3 — Case Studies and Social Proof**

Once early customers are onboarded:
- "How [UK SMB] passed Cyber Essentials in 6 weeks using CyberMeters" (government contractor angle)
- "How [vCISO] delivers CE readiness reports to 10 clients with one platform"
- "How [MSP] added Cyber Essentials monitoring to their service stack"

---

### Webinar Ideas

**Webinar 1 — "Is Your Business Cyber Essentials Ready? A Live Readiness Check"**

Format: 45-minute live webinar. CyberMeters demonstrates a live CE readiness scan on a real domain (with permission) and walks through the gap report output. Attendees can run a free scan on their own domain during the session.

Audience: IT Managers, SMB owners, compliance managers.

Conversion goal: Free trial → Professional trial.

**Webinar 2 — "Adding Cyber Essentials Monitoring to Your MSP Service Stack"**

Format: 60-minute live webinar for MSPs. Demonstrates the Business plan portfolio view, white-label report generation, and bulk scheduling.

Audience: MSP owners and service directors.

Conversion goal: Business trial → Business subscription.

**Webinar 3 — "Cyber Essentials in 2026: What's Changed and How to Prepare"**

Format: 30-minute thought leadership webinar. Discusses NCSC guidance updates, insurer requirements, and supply chain pressures. CyberMeters is positioned as the ongoing solution, not the topic.

Audience: Broad SMB / IT professional audience.

Conversion goal: Awareness → Free trial.

---

### Lead Magnet Ideas

**Lead Magnet 1 — The Cyber Essentials Readiness Report (Primary)**

A branded, one-page PDF produced automatically by CyberMeters after a scan of a submitted domain. Shows: overall CE readiness score, traffic light status per control area, top 3 gaps, and a CTA to Professional for continuous monitoring.

This is gated behind email capture (not a Free plan trial). The prospect receives their report by email within minutes of entering their domain. The email sequence that follows converts them from a report recipient to a Free plan user to a Professional trial.

**Lead Magnet 2 — The Cyber Essentials Checklist for UK SMBs**

A practical PDF checklist mapping the 5 CE control areas to actionable steps for an IT Manager. Not a marketing document — genuinely useful. Includes a self-assessment column where IT Managers can rate their current status. At the end, a CTA: "Want to run this check automatically? Start your free trial."

**Lead Magnet 3 — The MSP Guide to Selling Cyber Essentials as a Service**

A guide for MSPs on how to package and price CE readiness monitoring as a managed service. Includes a sample pricing model (CyberMeters Business as the underlying platform) and a sample client pitch deck (white-label template). This is a direct conversion tool for the MSP segment — it gives them what they need to sell CE to clients, with CyberMeters embedded as the delivery mechanism.

---

### The Cyber Essentials Readiness Report as a Product Concept

The most powerful marketing asset CyberMeters can produce is not a blog post or a webinar — it is a live, automated Cyber Essentials Readiness Report that a prospect can generate in minutes for their own domain.

**How it works in the conversion funnel:**

1. A prospect lands on the CyberMeters website via search, LinkedIn, or referral.
2. They enter their domain on a dedicated landing page: *"Find out if you'd pass Cyber Essentials."*
3. They enter their email address to receive the report.
4. CyberMeters runs an automated scan and produces a branded one-page PDF.
5. The prospect receives the PDF by email within minutes.
6. The PDF shows: CE readiness grade, traffic light per control area, top 3 gaps, and a CTA to Professional for continuous monitoring and a full gap report.
7. A follow-up email sequence converts them from report recipient to Free plan user to Professional trial.

**Why this works:**

The report is the product. It demonstrates, in the prospect's own context, with their own domain, what CyberMeters does and what value it produces. It requires no product tour, no demo call, no sales conversation. The value is self-evident — either the prospect passes or they don't, and in both cases they want to know more.

For the consultant and MSP segment, the same concept applies: they enter a client's domain, receive the CE readiness report for that client, and immediately see the value of scaling this across their entire client portfolio.

---

*CyberMeters Platform — Cyber Essentials Commercialisation Strategy v1 — Confidential — June 2026*
