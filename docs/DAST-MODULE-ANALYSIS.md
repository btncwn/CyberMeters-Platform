# CyberMeters × DAST — CTO / Market Analysis & Go-No-Go

> Decision document. Evidence-based; facts (web-verified) are tagged `[FACT]`,
> synthesis is `[ASSESSMENT]`, and claims about our own system are `[STACK]`
> (direct knowledge of this codebase). Written 2026-07-08.
> Trigger: founder considering a "lightweight DAST" module as a signup/lead-gen
> hook (crawler + headers/TLS/cookies/robots/security.txt + reflected XSS + SQL
> error leakage + CSP/HSTS/CORS + AI report), explicitly NOT competing with
> Burp/Invicti/Acunetix/Detectify/Intruder.

## Headline verdict (answer first)

The question is "should I build DAST?" but the evidence shows the ask bundles
**two different products** under one name. Split them and the answer is clear:

| Part | Verdict | Why |
|---|---|---|
| **Passive "instant posture scan" hook** (headers, HTTPS, TLS, cookies, robots/security.txt, CSP/HSTS/CORS) | **GO** — post-beta, and **~80 % is already built** | Market-validated + stack-compatible + repackaging of existing Attack Surface / Certificates scope |
| **Active DAST engine** (crawler + reflected XSS + SQLi payload probing) | **NO-GO** (now, and largely permanently) | Crowded/mature market we've said we won't enter, legally heavy, and **architecturally incompatible with our current Cloudflare Workers stack** |

This is not the naive "yes/no DAST" the prompt expects — it is what the evidence supports.

## Most important finding: the closest competitor already ships the unified thesis

`[FACT]` **Red Sift — our most-benchmarked DMARC competitor — acquired Hardenize
(the SSL Labs team) in October 2022** specifically to combine email + web + DNS +
nameserver posture into one platform. VentureBeat's framing is our exact thesis:
"attack surface management should include email." So Q3 ("can email + DMARC +
domain health + website security combine into one dashboard?") is answered:
**yes — the closest competitor sells it.**

`[ASSESSMENT]` Two consequences: (1) the unified-posture thesis is validated, not
speculative. (2) Red Sift/Hardenize's web side is **passive** posture
(TLS/DNS/headers/cert/nameserver — the SSL Labs lineage), **not active DAST**.
The one player combining "email + web" does it with the *passive* half of the
list, not XSS/SQLi. This is the single strongest support for the verdict.

## The free-scanner hook pattern is real and huge — and entirely passive

`[FACT]` Mozilla HTTP Observatory: **6.9M websites, 47M scans** since 2016.
SecurityHeaders instant letter grade. SSL Labs is the industry standard. All
three are proven top-of-funnel magnets — **and all three are passive header/TLS
checks, none do XSS/SQLi.**

`[FACT]` Small opening: Snyk is discontinuing the SecurityHeaders.com **API in
April 2026** (the web scanner stays) — developers wiring that into products will
need an alternative.

`[ASSESSMENT]` **The marketing hook you want does not require the DAST engine you
scoped.** The entire 47M-scan demand is for passive checks.

## Competitor table (pricing = "real DAST" context)

| Product | Positioning | Price `[FACT]` | Active DAST? |
|---|---|---|---|
| Intruder | Continuous vuln management | $157/mo/app | Yes |
| Detectify | AppSec, EASM | $89/mo/scan-profile | Yes |
| Probely | API/SPA DAST | $98/mo/target | Yes (headless Chrome) |
| HostedScan | Affordable multi-engine | Free tier + paid | Yes (OWASP ZAP under the hood) |
| Pentest-Tools / ImmuniWeb | Freemium web scanner | Free demo + paid | Yes |
| **Red Sift (Hardenize)** | **Email + web/DNS posture** | Enterprise | **No — passive** |
| SecurityHeaders / Observatory / SSL Labs | Free instant scan | Free | **No — passive** |

`[ASSESSMENT]` Active DAST is **mature and full at $89-157/mo** — precisely the
fight we've said we won't pick. Building the active engine means investing
infrastructure in a battle we're declining. The open lane is Red Sift's:
**email-centric unified *passive* posture**, where there is one serious player
and we are already strong on the email side.

## Open-source components (for build-vs-buy)

| Tool | License | State | Role |
|---|---|---|---|
| Nuclei | **MIT** `[FACT]` — commercial use OK | Active; PD sells a separate cloud, CLI stays free | Active scan engine |
| Katana / httpx / subfinder (ProjectDiscovery) | MIT | Active | Crawl / probe / subdomains |
| OWASP Amass | **Apache 2.0** `[FACT]` | Active (2017-2025) | Recon / ASM |
| OWASP ZAP | Apache 2.0 | Active | Full DAST (HostedScan builds on it) |
| ffuf / Dalfox / gau / waybackurls | Apache 2.0 / MIT | Active | Fuzzing / XSS / URL harvest |

`[ASSESSMENT]` Licenses are clean — orchestration is legally possible. **But the
license is not the blocker here.**

## Stack reality (CORRECTED 2026-07-08 — see adversarial DD below)

`[STACK]` CyberMeters runs on **Cloudflare Workers**. The `Katana → httpx →
Nuclei → analyzers` chain are **Go binaries** needing subprocess execution, long
run times, and broad egress — which **Workers themselves cannot do** (no
subprocesses, CPU/time limits, subrequest limits; we hit "Too many subrequests"
in this project).

**Correction:** an earlier draft called this "incompatible with the current
infrastructure." That is now imprecise. `[FACT]` **Cloudflare Containers reached
GA in April 2026**, runs statically-linked Go binaries (<80 ms cold start),
won't force-shutdown long-running instances, 2 GB image cap. So the orchestration
CAN run **inside the Cloudflare platform** (a new *native* compute tier, not a
foreign cloud) — the barrier drops from "wrong vendor" to "a whole new build +
ops + legal surface from zero." Technical feasibility is therefore **higher**
than this section originally said; the reason not to build is competitive, not
technical (adversarial DD below).

`[STACK]` Meanwhile **passive checks already run on Workers** — just HTTP fetch +
header/TLS parsing — and CyberMeters already does most of them (Certificates &
Trust + Attack Surface). So the asymmetry holds where it matters:

- **Passive hook** = market-validated + stack-compatible **today** + largely existing code.
- **Active DAST** = now technically buildable (Containers) but market-crowded + legally heavy + maintenance-heavy + off our moat.

## Legal risk (the make-or-break for the active side)

`[FACT]` **Domain-ownership verification** (DNS TXT / file challenge) before an
active scan is the industry standard; unauthorized active scanning can violate
computer-misuse law — **illegal**. Passive header/TLS checks (a GET on a URL) are
low-risk; XSS/SQLi payload injection requires proof of ownership.

`[STACK]` CyberMeters already solves this for Attack Surface via domain-ownership
verification — the infra exists — but any active-payload "user enters any URL"
flow **must** sit behind that gate. The passive hook's "scan the URL you typed"
flow is comparatively safe; the active one is not.

## Effort & 3-year maintenance (build vs buy)

`[ASSESSMENT]`

| | Passive hook | Active DAST orchestration |
|---|---|---|
| First MVP | ~1-2 weeks (mostly packaging existing code + report/AI layer) | ~2-3 months (separate container infra + orchestration + ownership gate + reporting) |
| 3-year maintenance | Low — a few new HTTP checks/year | **High** — Nuclei template drift, false-positive tuning, engine upgrades, ops of the separate tier, legal surface |
| Differentiation | Email + web unified posture (Red Sift's lane, but we're strong on email) | Low — mature $89/mo competitors own it |
| ROI | High (top-of-funnel magnet, low cost) | Uncertain/negative (heavy investment in a market we're declining) |

## Recommendation

**Smallest MVP (build): a free "Unified Posture Scan."** One URL/domain in →
**passive** email (DMARC/SPF/DKIM, already built) + TLS/cert (already built) +
security headers/HSTS/CSP/CORS/cookies + robots/security.txt → a polished report +
AI business-impact explanation → upsell into CyberMeters. This is the self-serve,
top-of-funnel version of what Red Sift/Hardenize sells to enterprise, and it
leverages our email strength.

**Do NOT build (now):** crawler + reflected-XSS + SQLi payload engine. Market
full, legally heavy, stack-incompatible.

**Postpone (possibly forever):** active DAST — only if a specific invited user
pulls for it AND we decide to invest in the separate container tier. If that day
comes, ZAP-style orchestration (like HostedScan) is the route; never a
from-scratch engine.

**Pricing:** passive scan is **free / lead-gen** (the magnet must be free — the
Observatory's 47M scans exist because it's free). Depth (history, monitoring,
multi-domain, PDF, alerting) upsells into the paid CyberMeters plan.

## Timing (respect the roadmap discipline)

`[ASSESSMENT]` This says "GO (passive)" but **not "now."** We are in a two-domain
private beta, at the Stage C gate, with the new email worker yet to process a
single real DMARC report. CLAUDE.md: "Do not chase breadth ahead of what real
invited users need. Let feedback lead." Even though the passive hook is cheap and
correct, the order is: **clear the Stage C gate → see the first real report →
gather invited-user signal → then top-of-funnel.** Ship the hook when feedback
shows a pull, not as a "nice to have."

---

# Adversarial DD update (2026-07-08) — "orchestration platform" framing

> Follow-up commission: evaluate a broader **orchestration platform** (Katana →
> httpx → Nuclei → ZAP + our email/DMARC/DNS analysis → one dashboard), with an
> explicit adversarial brief ("find evidence I am WRONG") and VC-style scores.
> This section supersedes the passive/active framing above with a competitor-led
> verdict; the passive-hook recommendation still stands as the fallback.

## Scores & verdict

| Dimension | Score | Basis (evidenced) |
|---|---:|---|
| Overall market | **3/10** | Every sub-layer is saturated: DAST, ASM/EASM, scanner-consolidation, security-ratings — funded incumbents in each |
| Technical feasibility | **6/10** | Now possible via Cloudflare Containers GA; but heavy new build + ops + legal + false-positive maintenance |
| Competitive difficulty | **9/10** | Aikido, ProjectDiscovery Cloud, UpGuard/SecurityScorecard, Red Sift all hold lanes |
| Time-to-market | **4/10** | Active-DAST orchestration = months + new container tier; passive posture score = weeks |
| Differentiation (as framed) | **2-3/10** | "Combine scanners into one dashboard" is Aikido's and PD Cloud's exact value prop |
| Revenue potential | **4/10** | SMB DMARC niche is real but modest; the DAST-orchestration TAM isn't ours |
| Founder-market fit | **email/DMARC 8/10 · DAST 3/10** | Deep email-security signal; no AppSec/pentest signal |

**Recommendation: NICHE DOWN.** Not Option A (full DAST engine) and not Option B
(the scoped scanner orchestration). **Option C:** a DMARC-native, SMB/MSP unified
*passive* posture score (existing email strength + passive web/TLS/DNS/headers on
Workers + AI explanation + MSP multi-tenant dashboard). No active Nuclei/ZAP.

## Why (competitor evidence)

- `[FACT]` **Aikido** — "SAST+DAST+SCA+secrets+IaC+container+CSPM in one app,"
  free-forever tier, $350/mo — *is* the "consolidate scanners into one dashboard"
  value prop, funded and cheap. The core differentiation is already occupied.
- `[FACT]` **ProjectDiscovery Cloud** — the *makers* of Nuclei/Katana/httpx
  already sell hosted orchestration (asset discovery + Nuclei scanning; free +
  enterprise; former Growth tier $3,500/yr). Orchestrating PD's own tools is
  their product, not a moat.
- `[FACT]` **UpGuard's security rating already spans five categories: website
  security, email security, phishing/malware, brand & reputation, network
  security** — the "combine email + web + DNS into one score" thesis, shipped
  (enterprise TPRM, not self-serve SMB/DMARC-first).
- `[FACT]` **Microsoft Defender EASM / SecurityScorecard** own external attack
  surface at enterprise scale.
- `[ASSESSMENT]` Adding **active** DAST makes the idea *less* differentiated — it
  walks into Aikido + PD Cloud + mature DAST vendors and away from the founder's
  actual moat (email/DMARC). The only defensible seam is **DMARC-native unified
  passive posture for the SMB/MSP segment the enterprise players underserve** —
  which generic DAST/ASM tools treat as a shallow "SPF/DMARC present?" checkbox.

## Legal kill-switch (active, multi-tenant)

`[FACT]` Ownership verification (DNS TXT / file challenge) before active scanning
is standard; unauthorized active scanning can violate computer-misuse law.
`[ASSESSMENT]` In self-serve multi-tenant, "customer enters a scan target" +
active payloads = operating an attack service if the target isn't theirs.
Mandatory per-target ownership gates kill the "instant scan" hook the idea needs.

## AI reality (Part 7)

`[ASSESSMENT]` Industry "AI" is mostly LLM report-writing / explanation / dedup /
prioritization text — real, cheap, and **no longer a moat** (everyone, incl.
Aikido, ships it). "AI exploit generation / attack simulation" is largely
marketing. CyberMeters' AI-explanation layer is legitimate but not defensible.

## Honest correction carried up

The pre-existing "stack-incompatible" claim was softened above: Cloudflare
Containers (GA Apr 2026) makes the orchestration technically buildable on-platform.
This *raised* feasibility and did **not** change the verdict — the reason to pass
is competition + founder-fit + moat, not the runtime.

## Sources (adversarial DD)

- Aikido pricing: https://www.aikido.dev/pricing · platform: https://www.aikido.dev/platform
- Cloudflare Containers docs: https://developers.cloudflare.com/containers/ · GA (InfoQ): https://www.infoq.com/news/2026/04/cloudflare-sandboxes-ga/
- ProjectDiscovery Cloud: https://projectdiscovery.io/blog/announcing-pdcp · pricing: https://projectdiscovery.io/pricing
- UpGuard 5-category rating: https://www.upguard.com/security-report/securityscorecard
- SecurityScorecard EASM: https://securityscorecard.com/platform/external-attack-surface-management/
- Microsoft Defender EASM pricing: https://www.microsoft.com/en-us/security/pricing/microsoft-defender-external-attack-surface-management
- Invicti — DAST false positives: https://www.invicti.com/blog/web-security/reduce-dast-false-positives

---

## Sources

- Red Sift/Hardenize: https://redsift.com/blog/why-weve-acquired-hardenize-and-what-this-means-for-our-customers
- VentureBeat (ASM should include email): https://venturebeat.com/security/attack-surface-management-red-sift
- BusinessWire (acquisition): https://www.businesswire.com/news/home/20221013005168/en/Red-Sift-Acquires-Hardenize-to-Redefine-Enterprise-Attack-Surface-Protection
- Nuclei license FAQ: https://docs.projectdiscovery.io/opensource/nuclei/faq
- Nuclei GitHub: https://github.com/projectdiscovery/nuclei
- OWASP Amass: https://owasp.org/www-project-amass/
- Mozilla HTTP Observatory: https://developer.mozilla.org/en-US/observatory
- Intruder pricing: https://www.intruder.io/pricing
- Detectify pricing: https://detectify.com/pricing
- HostedScan pricing: https://hostedscan.com/pricing
- Pentest-Tools website scanner: https://pentest-tools.com/website-vulnerability-scanning/website-scanner
- ImmuniWeb websec: https://www.immuniweb.com/websec/
