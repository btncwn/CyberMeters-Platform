# CyberMeters Product Roadmap

> **Status: Historical / Superseded (15 July 2026).** Retained for historical
> context; no longer a source of truth. Canonical roadmap:
> `docs/ROADMAP-TO-FIRST-PAYING-CUSTOMER.md` · current canonical episode and
> release facts: `CLAUDE.md` · shipped truth: `CHANGELOG.md`.

## Purpose

This roadmap defines the staged evolution of CyberMeters.

It exists to keep the project focused, commercially realistic, and aligned with the CyberMeters Product Constitution.

CyberMeters will not build random cybersecurity features.

CyberMeters will evolve stage by stage into the most focused and trusted External Exposure Intelligence Platform for UK SMBs.

---

# Product Direction

CyberMeters is:

**The External Exposure Intelligence Platform**

CyberMeters helps organisations answer five questions:

1. What can attackers see?
2. Can attackers impersonate us?
3. Is our identity exposed?
4. Is our brand being abused?
5. What should we fix first?

Every roadmap item must strengthen at least one of the five intelligence pillars:

- Attack Surface Intelligence
- Business Email Intelligence
- Identity Intelligence
- Brand Intelligence
- Executive Intelligence

---

# Roadmap Rules

## Rule 1 — Every stage must be commercially useful on its own

CyberMeters must not wait three years to become valuable.

Each stage must be sellable, useful, and demonstrable.

---

## Rule 2 — Do not build Stage 4 before Stage 1, 2, and 3 are strong

BEC Protection is the long-term destination.

It must not distract from the near-term product.

---

## Rule 3 — No unnecessary product expansion

CyberMeters will not become:

- SIEM
- EDR
- XDR
- SOAR
- GRC
- Vendor Risk
- Supply Chain Risk
- Compliance Management

---

## Rule 4 — Build what customers can understand

UK SMBs and MSPs must immediately understand the value.

If a feature is technically clever but commercially unclear, delay it.

---

# Stage 1 — External Attack Surface Intelligence

## Goal

Become one of the best External Attack Surface Intelligence platforms for UK SMBs.

## Commercial Purpose

Help customers understand what attackers can see from the outside.

## Core Capabilities

- Domain monitoring
- DNS intelligence
- SSL/TLS analysis
- Security headers
- Subdomain discovery
- Certificate intelligence
- Cloud exposure
- Public storage exposure
- Admin surface discovery
- Historical asset tracking
- Executive reports

## Must-Have Before Public Beta

### 1. Asset Discovery Accuracy

Improve:

- Subdomain discovery accuracy
- Wildcard handling
- CDN detection
- Hosting provider identification
- Historical asset inventory
- False positive reduction

### 2. Certificate Intelligence

Improve:

- Expiry detection
- Certificate timeline
- Wildcard certificate discovery
- Certificate authority visibility
- Suspicious certificate monitoring

### 3. Cloud Exposure

Improve:

- AWS exposure detection
- Azure exposure detection
- Google Cloud exposure detection
- Cloudflare R2 exposure detection
- Public storage warnings
- CDN origin exposure checks

### 4. Executive Reporting

Improve:

- PDF report quality
- Business explanations
- Priority fixes
- Historical trends
- Clear customer-safe language

## Public Beta Output

By the end of Stage 1, a customer should be able to:

- Add a domain
- Run a scan
- Understand their external exposure
- Receive clear findings
- Download an executive report
- Know what to fix first

---

# Stage 2 — Business Email Intelligence

## Goal

Become the strongest UK SMB-focused Business Email Exposure platform.

## Commercial Purpose

Help customers understand and reduce the conditions that lead to email spoofing, impersonation, and Business Email Compromise risk.

## Core Capabilities

- SPF analysis
- DKIM analysis
- DMARC analysis
- MTA-STS
- TLS-RPT
- MX infrastructure
- Mail provider identification
- Email DNS hygiene
- Domain spoofing risk
- Business Email Exposure Score

## Must-Have Before Public Beta

### 1. Email Security Excellence

Improve:

- DMARC policy analysis
- SPF flattening warnings
- Multiple SPF record detection
- Mail provider identification
- Email security recommendations
- Clear remediation instructions

### 2. Brand Protection

Build or improve:

- Typosquatting detection
- Homoglyph domains
- Lookalike domains
- Certificate abuse detection
- Newly registered similar domains
- Public phishing infrastructure signals

### 3. Business Email Exposure Score

Create a lightweight scoring engine using:

- SPF status
- DKIM status
- DMARC policy strength
- MTA-STS
- TLS-RPT
- MX posture
- Brand impersonation signals
- Lookalike domain exposure

Do not use Microsoft 365 mailbox data yet.

Do not claim full BEC Protection yet.

## Public Beta Output

By the end of Stage 2, a customer should be able to answer:

- Can attackers spoof our domain?
- Is our email authentication weak?
- Are lookalike domains targeting us?
- How exposed are we to business email impersonation?
- What should we fix first?

---

# Stage 3 — Continuous Exposure Intelligence

## Goal

Turn CyberMeters into a recurring subscription product customers keep using.

## Commercial Purpose

Show customers what changed, what improved, what worsened, and what needs attention.

## Core Capabilities

- Historical exposure timeline
- New findings
- Resolved findings
- Recurring scans
- Scheduled monitoring
- Smart alerts
- Monthly summaries
- Exposure trend analysis

## Build Before or During Public Beta

### 1. Historical Intelligence

Improve:

- New finding tracking
- Resolved finding tracking
- Exposure timeline
- Score history
- Domain history
- Asset history

### 2. Smart Monitoring

Support:

- Daily monitoring
- Weekly monitoring
- Monthly monitoring
- Quarterly monitoring

### 3. Intelligent Alerts

Move from simple alerts to contextual alerts.

Instead of:

> New finding detected.

Say:

> Your external exposure increased because CyberMeters discovered a new admin portal, new certificate, and new mail infrastructure.

## Post-Beta

Delay:

- Risk prediction
- ML-based forecasting
- Advanced anomaly detection

These require more customer data and should not block Public Beta.

---

# Stage 4 — Executive Intelligence

## Goal

Translate technical exposure into business decisions.

## Commercial Purpose

Help business owners, directors, MSPs, and non-technical stakeholders understand risk clearly.

## Core Capabilities

- Executive dashboard
- Cyber Score
- Business Email Exposure Score
- Historical trends
- Executive PDF reports
- Board-level summaries
- Prioritised remediation
- Business impact explanations

## Must-Have Before Public Beta

### 1. Executive Dashboard

Show:

- Current score
- Key risks
- Recent changes
- Priority fixes
- Email exposure
- Brand exposure
- Attack surface growth

### 2. Executive Reports

Improve:

- PDF layout
- Risk narrative
- Action plan
- Business language
- Historical comparisons
- Customer-safe wording

### 3. Business Language

Every finding should answer:

- What was discovered?
- Why does it matter?
- What is the business impact?
- How should it be fixed?

## Post-Beta

Add:

- Monthly board reports
- Automated report delivery
- MSP-branded reports
- White-label reports

---

# Stage 5 — Customer Experience and Public Beta

## Goal

Make CyberMeters usable, understandable, and commercially ready.

## Commercial Purpose

Convert visitors into users, users into customers, and customers into long-term subscribers.

## Must-Have Before Public Beta

### 1. Onboarding

Build:

- Guided setup
- First workspace creation
- First domain entry
- First scan
- Email security explanation
- First recommendations
- Empty states

### 2. Customer Lifecycle

Create lifecycle communications:

- Day 1 welcome
- Day 3 first scan reminder
- Day 7 remediation reminder
- Day 14 report reminder
- Monthly security summary

### 3. Marketing Site

Build:

- Homepage
- Pricing page
- Feature pages
- Example report
- Live demo or demo screenshots
- Clear positioning
- FAQ

### 4. Public Beta Operations

Support:

- Beta invitations
- Feedback collection
- Analytics
- NPS
- Roadmap feedback
- Customer support workflow

---

# Stage 6 — Platform Reliability and Security

## Goal

Make CyberMeters feel like a professional SaaS product.

## Commercial Purpose

Trust depends on reliability.

A security product must be stable, fast, secure, and predictable.

## Continuous Workstream

This stage runs in parallel with every other stage.

### Security

Follow:

- Engineering Constitution
- Security Playbook
- Nessus
- SSL Labs
- Mozilla Observatory
- SecurityHeaders
- Manual web app review
- Authenticated testing

### Reliability

Improve:

- Error handling
- Retry logic
- Scheduled scan resilience
- Worker timeout handling
- Alert delivery reliability
- Report generation reliability

### Performance

Improve:

- Dashboard speed
- Scan detail loading
- API response time
- Frontend bundle size
- Caching strategy

### Observability

Improve:

- Audit logs
- Security events
- Scan failure visibility
- Operator notifications
- Health checks

### Release Gate

No Public Beta or Production release should proceed with:

- Critical vulnerabilities
- High vulnerabilities
- Broken authentication
- Broken authorization
- Tenant isolation failure
- Known exploitable weakness

---

# Stage 7 — MSP Readiness

## Goal

Prepare CyberMeters for consultants, IT support companies, and MSPs.

## Commercial Purpose

MSPs can bring many SMB customers through one partner relationship.

## Post-Beta Capabilities

Build:

- Client portfolio view
- Multi-client dashboard
- Bulk domain import
- White-label reports
- Client switching
- Role management
- Partner billing
- Partner health overview
- MSP-ready executive reports

## Timing

Do not block Public Beta for MSP features.

Start after CyberMeters has a stable direct-customer workflow.

---

# Stage 8 — Identity Intelligence

## Goal

Extend CyberMeters from external domain/email intelligence into external identity exposure.

## Commercial Purpose

Help customers understand identity risks that contribute to account takeover and BEC.

## Timing

Post-Beta.

Do not build before Stage 1 and Stage 2 are commercially strong.

## Microsoft 365 Integration

Build:

- Entra ID posture
- MFA visibility
- Mail forwarding rules
- Inbox rules
- OAuth applications
- Legacy authentication visibility
- Risky sign-in visibility where available

## Google Workspace Integration

Build later:

- Gmail forwarding rules
- OAuth applications
- Workspace security posture
- Admin alerts
- Mailbox exposure signals

## Rules

Start read-only.

Do not ingest email content.

Do not quarantine.

Do not claim full BEC Protection yet.

---

# Stage 9 — BEC Monitoring

## Goal

Move from Business Email Exposure into Business Email Compromise Monitoring.

## Commercial Purpose

Detect conditions and signals associated with BEC risk.

## Required Dependencies

Do not start until these exist:

- Business Email Intelligence
- Brand Intelligence
- Identity Intelligence
- Microsoft 365 integration
- Mailbox rule visibility
- OAuth app visibility

## Capabilities

Build:

- Mail forwarding risk detection
- Inbox rule abuse detection
- Executive impersonation signals
- Lookalike domain correlation
- External sender anomalies
- OAuth consent abuse signals
- Account takeover indicators

## Rules

Still avoid expensive NLP unless necessary.

Prioritise deterministic detection first:

1. Authentication checks
2. Header intelligence
3. Domain similarity
4. Brand intelligence
5. Identity configuration
6. Behaviour signals

---

# Stage 10 — BEC Protection

## Goal

Evolve into active Business Email Compromise Protection.

## Commercial Purpose

Offer premium protection for customers who need more than monitoring.

## Timing

Long-term.

Do not build until CyberMeters has customers, revenue, identity telemetry, and operational maturity.

## Capabilities

Future capabilities may include:

- Email ingestion
- MIME parsing
- Header analysis
- Behavioural analysis
- NLP classification
- Executive impersonation detection
- Quarantine
- Warning banners
- Teams or Slack alerts
- SOC notification
- Automated remediation

## Infrastructure

This stage may require:

- Cloudflare Queues
- External compute nodes
- AI inference
- Behaviour graph storage
- High availability pipeline
- Customer-specific tuning

## Rule

Do not begin with AI.

Build in this order:

1. Authentication Engine
2. Header Intelligence
3. Brand Intelligence
4. Identity Intelligence
5. Behaviour Engine
6. NLP
7. LLM Reasoning
8. Automated Remediation

---

# Public Beta Roadmap

## P0 — Must Finish Before Public Beta

- Onboarding flow
- First scan journey
- Email Security Excellence
- Business Email Exposure Score v1
- Brand Protection v1
- Executive Report v1
- Marketing homepage
- Pricing page
- Security hardening
- Lifecycle emails v1
- Beta feedback collection

## P1 — Strongly Preferred Before Public Beta

- Asset Discovery accuracy improvements
- Cloud Exposure improvements
- Historical timeline improvements
- Smart monitoring improvements
- Intelligent alert wording
- Executive dashboard polish

## P2 — Can Wait Until After Public Beta

- Microsoft 365 integration
- Google Workspace integration
- Risk prediction
- Advanced internet exposure discovery
- Monthly board report automation
- MSP portal
- BEC Monitoring
- BEC Protection

---

# 12-Month Roadmap

## Quarter 1 — Public Beta Foundation

Focus:

- Onboarding
- Marketing site
- Security hardening
- Email Security Excellence
- Executive reports
- First beta users

Goal:

Launch Public Beta.

---

## Quarter 2 — Revenue Drivers

Focus:

- Business Email Exposure Score
- Brand Protection
- Better reports
- Customer lifecycle
- Pricing validation
- First paying customers

Goal:

Convert beta users into paying customers.

---

## Quarter 3 — Product Credibility

Focus:

- Asset Discovery Excellence
- Cloud Exposure
- Historical Intelligence
- Smart Monitoring
- Intelligent Alerts

Goal:

Make CyberMeters feel like a serious continuous monitoring platform.

---

## Quarter 4 — Scale and Partner Readiness

Focus:

- MSP readiness
- White-label reports
- Monthly reports
- Improved dashboards
- Sales materials
- Case studies

Goal:

Prepare CyberMeters for partner-led growth.

---

# 3-Year Roadmap

## Year 1 — ASM + Business Email Exposure

Target:

- Public Beta
- First paying customers
- Strong ASM
- Strong email exposure intelligence
- Strong executive reports

Commercial target:

- 50–100 paying customers
- Initial UK SMB traction

---

## Year 2 — Identity Intelligence and MSP Expansion

Target:

- Microsoft 365 integration
- Google Workspace integration
- MSP dashboard
- White-label reporting
- Identity exposure monitoring

Commercial target:

- MSP partners
- Recurring revenue growth
- Clear upgrade path

---

## Year 3 — BEC Monitoring and Protection

Target:

- BEC Monitoring
- Account takeover indicators
- Executive impersonation signals
- Optional BEC Protection capabilities
- Premium tiers

Commercial target:

- Higher-value plans
- MSP expansion
- Differentiated market position

---

# What We Will Not Build

CyberMeters will not build:

- SIEM
- EDR
- XDR
- SOAR
- GRC
- Broad compliance management
- Vendor Risk as a product
- Supply Chain Risk as a product
- Cyber Essentials as a product
- Full vulnerability scanner replacement
- Penetration testing platform

If a capability does not strengthen External Exposure Intelligence, it does not belong.

---

# Execution Model

## Codex

Backend engineering:

- APIs
- Workers
- D1
- R2
- Scanning engines
- Detection logic
- Security fixes
- Reliability

## Claude

Frontend and UX:

- Dashboard
- Reports
- Onboarding
- Marketing pages
- Navigation
- Lifecycle emails
- Executive experience

## ChatGPT

Product architecture:

- Roadmap
- Strategy
- Release readiness
- Security review
- Prompt design
- Product decisions

## Founder

Business and validation:

- Beta users
- Pricing
- Customer interviews
- Market research
- Competitor analysis
- Sales messaging
- Final decisions

---

# Final Principle

CyberMeters will not win by building everything.

CyberMeters will win by becoming exceptionally clear, focused, useful, and trusted in one category:

**External Exposure Intelligence for UK SMBs.**

