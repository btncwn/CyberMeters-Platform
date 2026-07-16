# CyberMeters — Competitive Battlecard v2 (canonical)

> **Status: CANONICAL — this is the single current battlecard (16 July 2026).**
> It supersedes `docs/competitive-battlecard-v1.md`, which is retained as
> historical context only. If you find any other document making competitive
> claims, this one wins.

**Audience:** internal — founder, sales conversations, investor/grant Q&A. Not a public document.

**Rule of use:** every claim here is either independently verified (method noted) or
clearly marked as our positioning. Never present the unverified parts as fact.
Accuracy is our brand; the battlecard must live by it.

**Sources of truth this card defers to:** pricing and packaging →
`docs/PRICING-POLICY.md` (DECIDED 2026-07-09) · product model and roadmap state →
`CLAUDE.md` · alerting coverage and its limits → `docs/alerts-eight-domain-coverage.md`
· Cyber Essentials boundary → `docs/cyber-essentials-readiness.md` · shipped truth →
`CHANGELOG.md`.

**Last verified:** competitor landscape 7 July 2026 (Red Sift/Cloudflare 6 July;
Intruder 7 July), carried forward from v1. Competitor **pricing** benchmarks are the
settled set recorded in `PRICING-POLICY.md` §8 — **research is CLOSED; cite, do not
re-research.** Re-verify the landscape quarterly (next: October 2026).

---

## What changed from v1, and why

v1 was accurate about Red Sift, Cloudflare and Intruder, and its evidence culture and
self-audit were sound. Four things were wrong or missing, and this version fixes them.

1. **The competitor set was off-band.** v1 benchmarked us against enterprise products
   whose pricing and buying motion make the comparison misleading — and other
   commercial documents went further, comparing us to UpGuard and SecurityScorecard.
   We do not sell into that market. §2 fixes the band.
2. **Scope was framed as a weakness to apologise for.** It is the product. §3 states
   the narrow-scope / high-evidential-accuracy principle positively and honestly.
3. **The lifecycle was missing entirely.** It is our most defensible commercial
   difference and v1 never mentioned it. §4.
4. **MSP was one line ("our channel is minimal today").** MSP is a weighted channel
   with a distinct value story — and one that must be sold honestly, because the
   portfolio episode has not been built. §5.

Also corrected throughout: v1 described **four services**. CyberMeters has **eight
canonical domains**. v1 predates domains 5–8.

---

## 1. The eight canonical domains

Every competitive claim must be anchored to these. Do not describe the platform as
four, six or seven domains, and do not substitute internal scanner-module names.

1. Email Protection
2. Brand Protection
3. Attack Surface
4. Certificates & Trust
5. Cyber Essentials Readiness
6. Website Security
7. Identity Exposure
8. Shadow IT & Unmanaged Technology

---

## 2. The landscape — in our actual band

### 2.1 Our band, and who is in it

CyberMeters sells to **UK SMBs and the MSPs who serve them**, self-serve, on a company
card, without procurement. The value metric is **monitored domains**. That band —
single-digit to low-double-digit pounds per domain per month — is the only fair
comparison set.

Benchmarks below are the settled set from `PRICING-POLICY.md` §8. They are competitor
prices, cited as recorded; do not re-derive them in a sales conversation.

| In our band | Model | Recorded signal |
|---|---|---|
| **DMARC Digests** | DMARC only | Flat **$14/mo per domain**, 60-day history — the cheapest per-domain DMARC benchmark |
| **URIports** | DMARC/TLS/DNS packs | €5/5 · €25/25 · €100/100 · €400/400 domains — domain bundles are market-normal |
| **Red Sift / OnDMARC (entry)** | DMARC, tiered | **Express $9/mo (4 domains)**; Essentials 25 sender domains; upper tiers sales-led |
| **Attack Surface Center** (UK) | ASM | Free · **£89/10 assets** · £179/30 · £499/100 — closest UK ASM analog |
| **HostedScan** | External scanning | $39 / $109 / $189 per month, 5 targets each |
| **Mailhardener MSP** | DMARC MSP | **€149 base + €1/domain** — the MSP model we emulate |
| **DMARC Report** | DMARC / MSP | Core 1 / Guard 5 / Shield 10 / Defender 25; **MSP 50% off + volume** |

**Not our band — do not benchmark against these in a customer conversation:**

| Out of band | Why the comparison misleads |
|---|---|
| **UpGuard** | $1,750/mo (50 vendors), +$79/vendor. Enterprise ratings/vendor-risk, procurement-led. A prospect who can buy UpGuard is not our buyer. |
| **SecurityScorecard / BitSight** | Enterprise security ratings, $500–$5,000+/mo, sales-led. Different product, different buyer. |
| **Qualys / Tenable / Nessus** | Enterprise vulnerability management. We do not do CVE scanning at all (§3). |
| **Censys ASM** | Credit-based internet-visibility packages. Enterprise motion. |
| **Vanta / Drata** | Compliance automation. Adjacent category; we are not a compliance platform. |
| **Detectify** | Platform fee + per-domain/per-target with an app-scanning core we do not have. |

Quoting an enterprise price to make our price look good is a **losing move**: it
invites a feature comparison we lose, against a buyer we cannot serve. Compare us to
the tools our buyer actually stacks.

### 2.2 The bundle argument (the honest version of "unbeatable")

The claim is **bundle economics per domain for the full external posture**, never
"cheaper than every single-purpose tool at its one job". DMARC Digests at $14/domain
beats us on nothing but focus — but a UK SMB wanting the full external picture stacks
a DMARC tool + an ASM tool (£89/10 assets) + a certificate monitor and lands at
£150–250/mo. That stack is what we replace.

Our Cloudflare-native cost base (~£0.10–0.20/domain/mo all-in) is what makes the band
defensible and, per policy, is the real moat behind a **Free tier competitors cannot
match** — not undercutting any single price.

### 2.3 Red Sift (includes Hardenize)

**The single most misunderstood fact:** Hardenize is not a separate competitor. Red
Sift acquired Hardenize in January 2022; its technology powers Red Sift ASM, and
founder Ivan Ristić (creator of SSL Labs) joined Red Sift. *Verified live 6 July 2026:
hardenize.com carries Red Sift navigation and its legal links point to redsift.com
customer agreements.*

Red Sift mirrors us product-for-product on four of our eight domains:

| CyberMeters domain | Red Sift product | Notes |
|---|---|---|
| Email Protection | **OnDMARC** | Their flagship; hosted DMARC management, strong enforcement tooling |
| Brand Protection | **Brand Trust** | Lookalike/impersonation discovery — do NOT claim they lack this |
| Attack Surface | **ASM** (Hardenize engine) | Deep hygiene heritage: TLS, DNSSEC, headers, CT |
| Certificates & Trust | **Certificates** | Real-time certificate discovery/monitoring |
| — | **Radar** | AI assistant layer across the platform |

**Their DNA:** enterprise security suite — analyst-grade depth, enterprise pricing and
sales motion. **Their customer:** security teams with budget and process.

**Band note:** Red Sift is the one competitor spanning both bands. Their **Express
tier ($9/mo, 4 domains)** is genuinely in our band and is the tier we actually meet in
a deal; their upper tiers are not. Compare against Express, not against an enterprise
OnDMARC contract.

### 2.4 Cloudflare Security Insights

Free, bundled with the zone dashboard, enormous distribution. **But measurably
inaccurate on our shared test:** on cybermeters.com (6 July 2026) it produced a DMARC
false positive (reported ×3), a security.txt false negative, and 13/16 findings that
were prompts to enable Cloudflare's own products — and its own DMARC Management
product contradicted its Security Insights on the same record, same day. Full
reproducible pack: `docs/evidence-pack-accuracy-vs-cloudflare-v1.md` (Findings 1–4).

### 2.5 Intruder — adjacent, NOT a competitor

*Verified live 7 July 2026 (intruder.io): a unified exposure-management platform —
external/internal vulnerability scanning, web/DAST, cloud config checks, API testing,
ASM. Detection + prioritisation + remediation **guidance** — it does **not**
auto-remediate. No email security anywhere.*

The only shared surface is external exposure discovery, and even there we do not
compete on their core: Intruder does real vulnerability detection (versioned services,
CVE matching, CVSS); we do exposure/hygiene signals. **On the overlap Intruder is
deeper**, and our Workers architecture structurally caps scan depth.

They are the neighbour, not the rival. A serious company runs both. **Never** claim
"Intruder finds it, we fix it" — what Intruder detects is almost entirely what we
neither detect nor remediate.

---

## 3. Narrow scope, high evidential accuracy

**The principle:** narrower coverage we can evidence beats broad coverage we cannot.
Scope discipline is the product, not an apology.

**What we are not, and must never be sold as:**

- not a replacement for **Nessus / Qualys / Tenable** — we do no CVE scanning
- not **EDR** — no endpoint or device visibility
- not **SIEM** — no log or telemetry ingestion
- not full **DAST** — no active application testing
- not **penetration testing** — no exploitation, no manual assessment
- not **enterprise ASM** — Intruder and Red Sift/Hardenize are deeper on raw discovery
- not a **certification body** — see §6

**What we actually are:** passive, external, evidence-led observation of eight domains,
explained in business language, with a managed lifecycle behind it (§4).

**What "evidential accuracy" buys, concretely:**

- **Honest unknown states.** Missing, unsupported or unobservable evidence renders as
  `evidence insufficient`, `not yet assessed`, `unavailable` or `unknown` — never as
  healthy. A probe that never executed is unknown, not clean. We shipped a live P1 fix
  for exactly this (#105): a site nobody could reach had been rendering as healthy.
- **Customer assertion ≠ our verification.** These are distinct states. A customer
  saying "fixed" is recorded as an assertion, not a verified outcome.
- **Verification requires structured evidence** — method, result, evidence type,
  observation time. A completed scan alone cannot verify a fix; nor can a note; nor a
  boolean flag.
- **Registration-reality brand scoring.** An unregistered lookalike is a watchlist
  item, not a "high risk" alarm. No fear-inflation.
- **Reproducible accuracy packs.** We publish the commands. Ask a competitor for the same.

**The line:** *"We would rather tell you we could not see something than tell you it
was fine. Every incumbent we tested does the opposite at least once."*

---

## 4. The lifecycle — our strongest commercial difference

**The gap in the market:** almost every tool in our band rescans and redraws a score.
The customer gets a new number and no memory. CyberMeters runs a managed lifecycle:

```text
observe → assess evidence → explain risk → prioritise → canonical remediation
→ managed case → assign ownership → track action → verify outcome
→ monitor recurrence → reopen when required
```

What that gives us that a rescan-and-rescore tool structurally cannot:

- **Persisted condition identity.** A finding is a thing with a life, not a row in
  today's report. The same issue is the same issue next week.
- **Baseline and activation safety.** A new domain's pre-existing backlog is not
  fabricated into a flood of "new" events on day one.
- **Recurrence and reappearance.** We know an issue came back — and that is different
  from it being found for the first time.
- **Verified recovery.** Recovery is an evidenced state, not the absence of a finding.
  Disappearance does not prove remediation.
- **Canonical managed cases** across all eight domains, with one transition validator
  — ownership, action, evidence, audit trail.
- **Append-only evidence history.** History is not overwritten. What we saw, when, and
  why we said it, is recoverable.
- **Honest incomplete states** carried through the lifecycle rather than smoothed away.
- **Explainable per-domain trend** — the direction of a domain, backed by the events
  that moved it.

**The line:** *"Most tools tell you your score changed. We tell you which condition
came back, who owns it, what was done, and whether the fix actually held."*

**Guardrail — what we do not claim here.** Alerting is proven by CI and no-op
deployment. **Genuine live-event acceptance is outstanding for every one of the eight
domains** (`docs/alerts-eight-domain-coverage.md`). Controlled, founder-led acceptance
with real events is a release-gate activity. Do **not** describe alerting as
production-proven or say "we have alerted customers to real incidents". We have not
had a customer yet.

---

## 5. MSP / Partner channel

MSP is a distinct, weighted channel — different buyer, different maths, different
value story. Keep it separate from the direct SMB story.

### 5.1 Direct SMB value

One integrated view of the eight domains, in business language, self-serve, minutes to
first value, at a price payable on a company card. The buyer is a director or an IT
manager who will never issue an RFP. The pitch is comprehension: *what is exposed, who
is abusing our name, what do we fix first.*

### 5.2 MSP / Partner value

The buyer is delivering security to a portfolio of SMB clients and is measured on
leverage per client-hour. Value:

- **Per-client workspaces** with real tenant isolation — the multi-workspace tier.
- **White-label reporting** — the MSP's brand in front of their client.
- **A managed-case workflow** their technician can actually work: ownership, action,
  verification, recurrence — not a PDF they must re-interpret each month.
- **Customer reporting** they can hand over without rewriting.
- **Portfolio prioritisation** — which client, which domain, first.
- **Pricing that scales with the portfolio, not against it** — the adopted MSP model is
  a platform fee plus per-domain, which is why fixed bands ("20–100+ from £X") are
  banned by policy: 21 and 99 domains must never cost the same. Mailhardener's
  €149 + €1/domain is the model we emulate; DMARC Report's MSP discount is the
  channel norm.

### 5.3 What is shipped vs planned — sell this honestly

| Capability | State | May we sell it? |
|---|---|---|
| Per-client workspaces + tenant isolation | **Live** | Yes |
| White-label reports | **Live** | Yes |
| Managed cases across all eight domains | **Live** | Yes |
| Canonical remediation across all eight domains | **Live** | Yes |
| Eight-domain coverage-state honesty | **Live** | Yes |
| Alerting across all eight domains | **Live** (engineering closed) | Yes — but **never** as live-event-proven (§4 guardrail) |
| **MSP Portfolio Per-Domain State and Trend** | **PLANNED — NOT STARTED** | **No.** Roadmap only, explicitly future |
| M5 completion across all eight domains | **Planned** | No |
| SOC 2 / ISO 27001 / independent pen-test | **Not started** | No |

**This is the discipline that matters most in this section.** MSP Portfolio Per-Domain
State and Trend is the **next canonical episode and has not been started**. Several
superseded commercial documents describe a portfolio view, portfolio trend reports and
portfolio alerts as delivered `✓`. They are wrong; that is one reason they were
superseded. Do not demo, promise a trial of, or imply the existence of a portfolio
per-domain state/trend surface. If an MSP prospect asks: *"That's on the roadmap as our
next build — here's what exists today."*

---

## 6. Cyber Essentials — the UK wedge, honestly

CE Readiness is a genuine differentiator in our band: no mainstream competitor in the
SME price band offers a UK CE readiness signal, and the buyer is real and funded.

**The boundary, which is not negotiable** (`docs/cyber-essentials-readiness.md`):

- Readiness is estimated from **externally observable evidence only**. Since PR #106
  the questionnaire is **not** an input — no customer answer is treated as security truth.
- **Two of the five controls cannot be observed at all.** User Access Control and
  Malware Protection are `external_coverage: none`. The other three are *partial*.
- Therefore we **cannot** predict a certification outcome.

**Never say:** "find out if you'd pass Cyber Essentials" · "would we pass today" · "a
report your auditor can rely on" · "be audit-ready, always" · "replaces a consultant's
gap assessment" · "the 5 controls, checked continuously" · "am I Cyber Essentials
compliant" · or that CyberMeters certifies, assesses or guarantees compliance.

**Say instead:** *"Cyber Essentials asks about five controls. We can externally observe
three of them, partially — and we tell you plainly which two we cannot see. Use
CyberMeters to find and close the gaps we can evidence before you apply; use a
certification body to get the certificate."*

That is a weaker claim than the superseded strategy document made, and it is the only
one we can stand behind.

---

## 7. Where they win (do not pretend otherwise)

| Their strength | Reality for us |
|---|---|
| Brand recognition, enterprise references, certifications | We are pre-public-beta; we have no logos to drop |
| Integrations (SIEM/SOAR, SSO ecosystems, MSP channel) | Ours are minimal today |
| Analyst-grade DMARC forensics at scale | OnDMARC has processed billions of RUA reports; we have processed ~zero |
| CT/passive-DNS data scale (SSL Labs heritage) | Their raw coverage depth exceeds ours in places |
| Vulnerability depth (Intruder) | Real CVE detection; we do not do this at all |
| Cloudflare: free and already in the dashboard | We must be visibly more accurate and more actionable to justify existing |

**Consequence:** we do not fight Red Sift for the enterprise RFP, and we do not fight
Cloudflare on price. We win the underserved middle: companies that need the eight
answers, in business language, this week, without procurement.

---

## 8. Killer lines

**Primary (vs Red Sift, incl. Hardenize):**
> "Red Sift sells enterprise products that grade your configuration. CyberMeters is one
> platform that turns the same signals into a single business answer — and then keeps
> the thread: who owns the fix, did it hold, did it come back."

**The lifecycle line (our real difference):**
> "Most tools rescan and redraw a score. We remember. The same problem next month is the
> same problem, with its history, its owner, and whether your last fix actually held."

**The lock metaphor (works in any meeting):**
> "A hygiene tool checks whether your door lock is fitted correctly. CyberMeters also
> checks whether someone in the neighbourhood is cutting keys with your name on them —
> and tells you which problem to fix first."

**Vs Cloudflare (backed by the evidence pack):**
> "On the same domain, on the same day, Cloudflare's scanner reported a DMARC record as
> missing while Cloudflare's own DMARC tool confirmed it exists. We publish reproducible
> accuracy packs instead — you don't have to take our word for anything."

**Vs "we already have a DMARC tool":**
> "DMARC tells you about your mail. It doesn't tell you about the twelve domains
> registered last month that look like yours, or which of them can actually send email
> as you. That's the half of impersonation risk a DMARC tool never sees."

**Vs a per-domain point tool (e.g. DMARC Digests at $14/domain):**
> "They'll do DMARC well. Then you need attack surface, certificates, brand, website
> security — and you're stacking three more tools and £150+ a month. We're one bill for
> the whole external picture."

**MSP:**
> "Your technician doesn't need another dashboard. They need to know which client, which
> domain, what to do, and whether last month's fix held — with your logo on the report."

---

## 9. Objection handling

**"We use OnDMARC / Red Sift."**
Respect it — a strong enforcement tool. Ask: "Who reads it?" If the answer is "our
analyst", ask what the board sees. Our value: the executive translation layer plus the
other seven domains in the same pane, and a lifecycle that remembers. We coexist with
OnDMARC before we replace it.

**"We used Hardenize" / "Hardenize was great."**
Agree — genuinely excellent hygiene engineering (its founder built SSL Labs). Then:
"It's part of Red Sift's enterprise suite now. If you want that depth on an enterprise
contract, that's a fair choice. If you want the answers without the suite, that's us."

**"Cloudflare already shows us security insights."**
Never mock the free tool. Show the accuracy pack: two factual errors and a
self-contradiction on one domain in one day, and 13/16 findings that were product
prompts. "Free is the right price for that signal-to-noise ratio. Accuracy is what we
charge for."

**"Isn't this just a scanner?"**
"A scanner tells you what today looks like. The scan is the cheap part. What you're
buying is what happens after: the issue gets an identity, an owner, an action, evidence
that it was actually fixed, and a flag when it comes back."

**"Why not UpGuard / SecurityScorecard?"**
Don't take the bait — reframe the band. "Different product for a different buyer, at
$1,750 a month with a procurement cycle. If you have a vendor-risk programme and a team
to run it, buy that. If you need to know what's exposed about *your* eight domains by
Friday, that's us."

**"You're small / new — why trust you?"**
Lean into evidence culture: reproducible packs, honest unknown states, no inflated
threat counts, dogfooding on our own domain. "We publish the commands to check our
claims. Ask our competitors for the same." Then be straight about §11.

---

## 10. Guardrails — what we never claim

- No monetary loss figures we cannot substantiate ("this will cost you £X" is banned;
  "invoice-fraud exposure" as a category is fine).
- No claim that Red Sift "can't do brand protection" (Brand Trust exists) or "can't do
  ASM" (Hardenize engine exists). Our edge is integration + translation + lifecycle +
  accessibility, not their absence.
- No feature-parity claims against enterprise capabilities we lack (hosted DMARC
  forensics at scale, SIEM integrations, analyst tooling).
- No new scores invented for marketing. Score proliferation is the Cloudflare noise
  trap we criticise.
- **No enterprise-band price comparisons** (§2.1) — they invite a feature fight we lose
  with a buyer we cannot serve.
- **No "would you pass Cyber Essentials"** in any form (§6).
- **No MSP Portfolio per-domain state/trend** as an existing capability (§5.3).
- **No live-event alerting proof** until controlled founder-led acceptance is done (§4).
- No claim that we perform a customer, provider, registrar, certification-body or
  takedown-provider action when we prepare, track or verify it.
- No customer references, logos or social proof. We have no customers.

---

## 11. Brutal self-audit — where we actually stand (16 July 2026)

Written to counter our own optimism. If a claim flatters us without evidence, it goes.
v1's self-audit was the most honest section in the document; this updates it.

### The existential gaps (these kill us, not features)

1. **Zero customers, zero validation.** Every "we win on X" remains an untested
   hypothesis. Both competitors have thousands of paying customers, references, funding
   and years of real data. This has not changed since v1.
2. **Bus factor = 1.** One founder. The monolith is now decomposed (2.2k core + engines
   + route modules), which helps maintainability — it does not change the bus factor.
3. **No trust artifacts.** No SOC 2, no ISO 27001, no independent pen-test. We sell
   *security* without our own security badges — a hard credibility wall above SMB.
   Pentesting is a planned post-roadmap phase, not done.
4. **Architecture ceiling.** Workers subrequest limits structurally cap scan depth. Deep
   scanning at scale would need re-architecture.
5. **Nothing is proven with a real customer event.** Alerting across eight domains is
   engineering-closed and CI-proven, and live-event acceptance is outstanding for every
   domain. Our lifecycle claims (§4) are architecturally real and commercially untested.
6. **The pricing bet is unvalidated.** The adopted land-grab pricing is a deliberate bet
   that free-funnel virality plus the MSP channel convert better than higher prices. It
   is volume-bound and **distribution, not engineering, is the constraint.**

### Honest gaps vs Red Sift

- **DMARC maturity:** OnDMARC has processed billions of RUA reports over years; we have
  processed ~zero. Our BEC score and sender heuristics are calibrated on tiny data and
  may not hold at scale.
- **Data-scale moat:** Hardenize brings a CT firehose and years of passive DNS; our
  detection is lighter. Their Brand Trust data depth beats ours.
- **Missing capabilities they have:** dynamic SPF hosting, DKIM key management/rotation,
  BIMI/VMC execution.

### What is genuinely ours (defensible, not cheerleading)

- **The managed lifecycle across eight domains** (§4) — identity, ownership, structured
  verification, recurrence, append-only history, one transition validator. Structurally
  hard for siloed point products to copy, and the thing v1 failed to name.
- **Evidence-honesty as an engineering discipline**, not a marketing line — enforced in
  CI, including mutation-tested guards, and proven by us shipping fixes that made our
  own product look *worse* (#105, #106) rather than keeping a flattering state.
- One integrated **self-serve** product against sales-led suites — a real SMB gap.
- **Cost base**: Cloudflare-native economics no competitor's infrastructure can follow.
- **The UK / Cyber Essentials wedge**, within the honest boundary of §6.
- Engineering discipline — a large CI contract suite this early is rare. But **good code
  is not a proven business.**

### The one honest line

> *CyberMeters is an integrated, self-serve, evidence-led external security platform for
> UK SMBs and their MSPs: eight domains, a lifecycle that remembers, and honest unknowns
> — priced where a company card can reach. Architecturally sound, commercially unproven,
> and not yet tested by a single real customer.*

---

*Maintenance: re-verify the Red Sift product line-up and Hardenize status quarterly
(next: October 2026). Competitor pricing is settled in `PRICING-POLICY.md` §8 — do not
re-research. Update the shipped-vs-planned table in §5.3 the moment an episode closes;
a stale `Planned` row is how a battlecard starts lying.*
