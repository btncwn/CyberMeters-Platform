# CyberMeters — Competitive Battlecard v1

> **Status: Historical / Superseded (16 July 2026).** Retained for historical
> context; **not** the battlecard. The single canonical battlecard is
> `docs/competitive-battlecard-v2.md` — use that one. Canonical pricing:
> `docs/PRICING-POLICY.md` · current canonical episode and release facts:
> `CLAUDE.md`.
>
> **Why superseded.** Its verified competitor research (Red Sift/Hardenize,
> Cloudflare, Intruder) was sound and is carried forward into v2 — but the framing
> was wrong in four ways: it benchmarked outside our SME price band, treated our
> narrow scope as an apology rather than the product, never mentioned the managed
> lifecycle (our strongest commercial difference), and gave the MSP channel a
> single line. It also describes **four services**; CyberMeters has **eight
> canonical domains** — this document predates domains 5–8. Do not quote it.

**Audience:** internal — founder, sales conversations, investor/grant Q&A. Not a public document.
**Rule of use:** every claim here is either independently verified (method noted) or clearly marked as our positioning. Never present the unverified parts as fact. Accuracy is our brand; the battlecard must live by it.
**Last verified:** 7 July 2026 (Intruder added; Red Sift/Cloudflare 6 July). Re-verify the landscape quarterly (competitors ship and acquire fast).

---

## 1. The landscape — verified

### Red Sift (includes Hardenize)

**The single most misunderstood fact:** Hardenize is not a separate competitor. Red Sift acquired
Hardenize in January 2022; its technology powers Red Sift ASM, and founder Ivan Ristić (creator of
SSL Labs) joined Red Sift. *Verified live 6 July 2026: hardenize.com carries Red Sift navigation and
its legal links point to redsift.com customer agreements.*

Red Sift's platform is a product-for-product mirror of our four services:

| CyberMeters service | Red Sift product | Notes |
|---|---|---|
| Email Protection | **OnDMARC** | Their flagship; hosted DMARC management, strong enforcement tooling |
| Brand Protection | **Brand Trust** | Lookalike/impersonation discovery — do NOT claim they lack this |
| Attack Surface | **ASM** (Hardenize engine) | Deep hygiene heritage: TLS, DNSSEC, headers, CT |
| Certificates & Trust | **Certificates** | Real-time certificate discovery/monitoring |
| — | **Radar** | AI assistant layer across the platform |

**Their DNA:** enterprise security suite — five products, analyst-grade depth, enterprise pricing and
sales motion. **Their customer:** security teams with budget and process (compliance-driven,
integrations, procurement).

### Cloudflare Security Insights

Free, bundled with the zone dashboard, enormous distribution. **But measurably inaccurate on our
shared test:** on cybermeters.com (6 July 2026) it produced a DMARC false positive (reported ×3), a
security.txt false negative, 13/16 findings that were prompts to enable Cloudflare's own products —
and its own DMARC Management product contradicted its Security Insights on the same record, same
day. Full reproducible pack: `docs/evidence-pack-accuracy-vs-cloudflare-v1.md` (Findings 1–4).

### Intruder — adjacent, NOT a competitor

*Verified live 7 July 2026 (intruder.io): a unified exposure-management platform — external/internal
vulnerability scanning, web/DAST, cloud config checks (CSPM, AWS/Azure/GCP), API testing, and attack
surface management. Detection + prioritisation + remediation **guidance** — it does **not**
auto-remediate. No email security (DMARC/SPF/DKIM) anywhere.*

The only surface we share is **external attack surface / exposure discovery** — and even there we do
not compete on their core: Intruder does real vulnerability detection (versioned services, CVE
matching, CVSS); we do exposure/hygiene signals (DNS, certs, headers, admin surfaces), not CVE
scanning. On the overlap **Intruder is deeper**, and our Cloudflare Workers architecture (subrequest
limits) structurally caps scan depth.

**Positioning:** they are the neighbour, not the rival. A serious company runs both. **Never** claim
"Intruder finds it, we fix it" — the things Intruder detects (infra CVEs, cloud misconfig, web/API
vulns) are almost entirely things we neither detect nor remediate; our autonomy is scoped to the
DNS/email slice Intruder does not touch. Correct line: *"Intruder finds infrastructure
vulnerabilities; CyberMeters manages and fixes your email and domain security. Where we overlap —
external attack surface — they scan broad, we feed the four-service story."*

---

## 2. Where we win (honest, evidence-backed)

1. **Business-risk translation.** They grade configuration; we translate the same signals into a
   business answer: BEC Exposure Score (higher = worse, with reasons, confidence and evidence),
   Business Risk Score, and a single "do this next" action. A director understands our output
   without an analyst in the room.
2. **One platform, one story, one price.** Their four capabilities are four products (plus Radar) on
   an enterprise contract. Ours is one integrated view: email, brand, attack surface, certificates —
   with the interactions between them (e.g. a lookalike domain that can actually send mail scores
   higher than a theoretical permutation).
3. **SME accessibility.** Self-serve onboarding, guided remediation, minutes to first value, priced
   for companies that will never issue an RFP. Red Sift overserves this segment; Cloudflare
   underserves it with noise.
4. **Evidence and honesty as product.** Registration-reality brand scoring (an unregistered
   permutation is a watchlist item, not a "high risk" alarm), findings vs observations separation,
   honest "unknown" states, reproducible accuracy packs. We can show, with public commands, that we
   were right where an incumbent was wrong.
5. **Speed of the email wedge.** Paste raw headers → instant sender verdict; DMARC setup with live
   DNS verification; posture hero that reconciles against live DNS. The demo lands in the first two
   minutes.

## 3. Where they win (do not pretend otherwise)

| Their strength | Reality for us |
|---|---|
| Brand recognition, enterprise references, certifications | We are invite-only beta; we do not have logos to drop |
| Integrations (SIEM/SOAR, SSO ecosystems, MSP channel) | Ours are minimal today |
| Hosted DMARC record management & analyst-grade forensics | We guide the customer to publish records; we do not host them |
| CT/passive-DNS data scale (SSL Labs heritage) | Their raw coverage depth exceeds ours in places |
| Cloudflare: free and already in the dashboard | We must be visibly more accurate and more actionable to justify existing |

**Consequence:** we do not fight Red Sift for the enterprise RFP, and we do not fight Cloudflare on
price. We win the underserved middle: companies that need all four answers, in business language,
this week, without procurement.

---

## 4. Killer lines

**Primary (vs Red Sift, incl. Hardenize):**
> "Red Sift sells five enterprise products that grade your configuration. CyberMeters is one
> platform that turns the same signals into a single business answer: how exposed are you, who is
> abusing your name, and what should you fix first."

**The lock metaphor (works in any meeting):**
> "A hygiene tool checks whether your door lock is fitted correctly. CyberMeters also checks whether
> someone in the neighbourhood is cutting keys with your name on them — and tells you which problem
> to fix first."

**Vs Cloudflare (backed by the evidence pack):**
> "On the same domain, on the same day, Cloudflare's scanner reported a DMARC record as missing
> while Cloudflare's own DMARC tool confirmed it exists. We publish reproducible accuracy packs
> instead — you don't have to take our word for anything."

**Vs "we already have a DMARC tool":**
> "DMARC tells you about your mail. It doesn't tell you about the twelve domains registered last
> month that look like yours, or which of them can actually send email as you. That's the half of
> impersonation risk a DMARC tool never sees."

## 5. Objection handling

**"We use OnDMARC / Red Sift."**
Respect it — it's a strong enforcement tool. Ask: "Who reads it?" If the answer is "our analyst",
ask what the board sees. Our value: the executive translation layer plus brand/attack-surface
context in the same pane. We coexist with OnDMARC before we replace it.

**"We used Hardenize" / "Hardenize was great."**
Agree — genuinely excellent hygiene engineering (its founder built SSL Labs). Then: "It's part of
Red Sift's enterprise suite now. If you want that depth with an enterprise contract, that's a fair
choice. If you want the answers without the suite, that's us."

**"Cloudflare already shows us security insights."**
Never mock the free tool. Show the accuracy pack: two factual errors and a self-contradiction on one
domain in one day, and 13/16 findings that were product prompts. "Free is the right price for that
signal-to-noise ratio. Accuracy is what we charge for."

**"You're small / new — why trust you?"**
Lean into evidence culture: reproducible packs, honest unknown states, no inflated threat counts,
dogfooding on our own domain. "We publish the commands to check our claims. Ask our competitors for
the same."

## 6. Guardrails — what we never claim

- No monetary loss figures we cannot substantiate ("this will cost you £X" is banned; "invoice-fraud
  exposure" as a category is fine).
- No claim that Red Sift "can't do brand protection" (Brand Trust exists) or "can't do ASM"
  (Hardenize engine exists). Our edge is integration + translation + accessibility, not their absence.
- No feature-parity claims against enterprise capabilities we lack (hosted DMARC, SIEM integrations,
  forensic analyst tooling).
- No new scores invented for marketing. Four services, three established scores (Cyber Metrics, BRS,
  BEC Exposure). Score proliferation is the Cloudflare noise trap we criticise.

## 7. Proof points to cite (all reproducible)

- `docs/evidence-pack-accuracy-vs-cloudflare-v1.md` — Findings 1–4 incl. Cloudflare-vs-Cloudflare contradiction
- DMARC dogfood: `_dmarc.cybermeters.com` live, monitor-only, RUA to our own ingestion (`dig +short TXT _dmarc.cybermeters.com`)
- Registration-reality brand scoring: unregistered lookalikes capped at "low/watchlist" — no fear-inflation
- security.txt (RFC 9116) live on our own domain while an incumbent scanner reported it absent

---

## 8. Brutal self-audit — where we actually stand (7 July 2026)

Written to counter our own optimism. If a claim here flatters us without evidence, it is deleted.

### The existential gaps (these kill us, not features)

1. **Zero customers, zero validation.** Every "we win on X" is an untested hypothesis. Both
   competitors have thousands of paying customers, references, funding, and years of real data.
2. **Bus factor = 1.** ~35k-line monolith, one founder. Enterprise does not buy from bus-factor-1.
3. **No trust artifacts.** No SOC 2, ISO 27001, or independent pen-test. We sell *security* without
   our own security badges — a hard credibility wall above SMB.
4. **Architecture ceiling.** Cloudflare Workers subrequest limits structurally cap scan depth; deep
   scanning at scale would need re-architecture.
5. **Autonomy is double-edged.** "We change your DNS automatically" attracts SMBs (low ARPU, high
   churn) but scares the enterprise security teams who would pay most. The self-driving USP may repel
   the highest-value buyers. Mitigation on roadmap: an approve-then-act mode.

### Honest gaps vs Red Sift (the real head-to-head, all four services)

- **DMARC maturity:** OnDMARC has processed billions of RUA reports over years; we have processed
  ~zero. Our BEC score and sender heuristics are calibrated on tiny data and may not hold at scale.
- **Data-scale moat:** Hardenize (Ivan Ristić / SSL Labs) brings CT firehose + years of passive DNS;
  our detection is lighter. Their Brand Trust data depth beats ours.
- **Missing capabilities they have:** hosted/dynamic SPF (we only analyse), DKIM key management/
  rotation (none), fully hosted MTA-STS (custom-hostname TLS gap), BIMI/VMC execution.

### What is genuinely ours (defensible, not cheerleading)

- Closed-loop **Self-Driving DMARC** (host + measure in one engine) — novel, structurally hard for
  their siloed products to copy.
- One integrated **self-serve** product vs their five sales-led products — a real market gap for SMB.
- Business-language BEC translation; **evidence/honesty culture**; UK / Cyber Essentials wedge.
- Engineering discipline (Saga/write-ahead, 218 regression contracts) — rare this early. But **good
  code is not a proven business.**

### Roadmap — proof and trust before features

**Phase 0 — Stop and prove (0–4 wks):** send the first 2 invites; **freeze** deepening the
autonomy/registry `apply` tier until a real user asks; collect real RUA data to recalibrate.
**Phase 1 — Trust artifacts (1–3 mo):** public trust page + an independent pen-test; start SOC 2
Type I (Vanta/Drata); document the riskiest monolith seams to cut bus-factor.
**Phase 2 — Deepen the lane we win (3–6 mo, feedback-led):** finish the email wedge to parity
(TLS-RPT hosted apply → dynamic SPF hosting → DKIM rotation); ship approve-then-act autopilot;
productise Cyber Essentials Readiness.
**Phase 3 — Only if feedback demands (6 mo+):** integrate-don't-compete with Intruder on ASM; pick
Brand data-depth battles carefully.

**One honest line:** *CyberMeters is the only integrated, self-serve platform that autonomously
manages email and domain security for SMB/mid-market — neighbour to Intruder's infra scanning, the
self-serve alternative to Red Sift's five-product enterprise suite. Unproven, but its engineering and
honesty are sound.*

---

*Maintenance: re-verify Red Sift product line-up and Hardenize status quarterly (next: October 2026).
Update killer lines as invited-user feedback shows which framing lands.*
