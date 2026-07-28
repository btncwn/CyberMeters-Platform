# Detection-Signal Candidate Pool (v2) — filtered RESEARCH QUEUE, post-backlog

Status: **A filtered research queue, NOT committed roadmap and NOT a build spec. Post-backlog.
Does NOT jump the frozen order (Item 5 closed live on 24 July; Item 6 is the next sequenced
line). No new 9th domain — every candidate fits an existing canonical domain.** Captured
24 July 2026 (founder + ChatGPT + Claude, v2 after adversarial review).

Gaps are LIKELY but must be **confirmed against the code before building** — every candidate is
`current_code_status: unverified`. We already use CT for cert *observation*, have SPF/DMARC/DKIM,
TLS-RPT ingest, Brand DNS enrichment; several candidates DEEPEN those rather than start fresh.

**Related but a DIFFERENT question:** `docs/SCENARIO-DETECTION-FEASIBILITY-PROGRAMME.md` asks whether
whole attack SCENARIOS (phishing infrastructure, ransomware entry path) can be proven end-to-end from the
sensors we ALREADY run, with a founder GO/NO-GO gate. This pool proposes NEW individual signals. Do not
merge the two queues.

## Selection FILTER
A signal qualifies only if: **externally observable (→ can reach L4/L5) + detects REAL harm +
citable to a recognised authority (RFC/CIS/scheme) + has an honest stated limit.**
**Excluded (overclaim trap, not the moat):** internal-visibility signals (endpoint/patch/EDR/
internal-MFA/dark-web) cap at L0 and break external-scope honesty.

## PRIORITISATION (4 axes — grade-ceiling alone is NOT the criterion)
```
priority ≈ (customer_harm × detection_confidence × actionable_remediation) ÷ impl/op_cost
```
A cryptographically-perfect signal with low actionability is not automatically top priority.
Each candidate carries: `canonical_domain · likely_grade_ceiling · current_code_status:
unverified · expected_false_positive_risk · operational_safety_constraints · impl_size`.
(This is a research queue — do NOT expand into a full per-candidate spec before founder commit.)

## New-scan cost nuance
First working code = days (probe + normalisation + derivation + grade contract + tests) against
the reused canonical systems (orchestration/budget/persistence/snapshot/alerts/remediation/
cases/reports/coverage). **Production-accepted time expands with downstream semantic scope:** an
observational-only signal (records + shows + `unknown` behaviour, no score/automation) is fast;
the same signal touching score / alert / case / trend needs materially broader acceptance.

---

## Candidates (ranked by value/effort)

### 1. CAA issuance-policy posture + CT certificate-change correlation (Certificates & Trust)
Lowest cost, high value. CAA (which CAs may issue) is DNS-observable; correlate with CT
certificate-change/policy signals. `likely_ceiling L4` · `fp_risk low` · `safety: DNS reads only`.
Honest limit: missing/weak CAA is not itself an active vulnerability; it is an issuance-policy gap.

### 2. DNS & PKI Trust Controls — DNSSEC (chain + broken-state monitoring) (Certificates & Trust)
DNSSEC verdict is cryptographically *decidable* (root KSK anchor). SEPARATE signals, separate
contracts: `dnssec_chain_state · dnssec_signature_health · dnssec_rollover_risk`. Honest states:
`unsigned · signed-but-unchained (no parent DS) · valid · invalid · indeterminate · temporarily-
unreachable · resolver-disagreement` — never a green/red badge. **Broken DNSSEC = availability/
outage-class event** (domain goes dark to validating resolvers) → a high-priority managed-alert
candidate, not just a posture card. `likely_ceiling L5 (ceiling, NOT auto-grade — each result
still needs retained responses / resolver-path provenance / trust-anchor version / chain-of-
custody / no-silent-degrade / limit statement)`. Neck-and-neck with #1 on value; slightly more
effort. Honest limit: proves DNS-response origin authenticity + chain state; does NOT prove
website/email/app security, and a signed phishing domain is not "good".

### 3. MTA-STS effective-policy validation (Email Protection)
The easiest high-quality win — a natural complement to SPF/DMARC/DKIM/TLS-RPT with a clear,
bounded scope: `_mta-sts` TXT discovery, policy fetch, version, mode (testing→enforce), max_age,
MX pattern match, HTTPS/TLS validity, redirect/content-type/body-size semantics, policy-ID change,
stale/unreachable policy, TLS-RPT correlation. Cited to RFC 8461. `likely_ceiling L4` · `fp_risk
low`. Honest limit: proves published transport-security intent + policy validity, not that every
receiver enforced TLS on every message.

### 4. CT unexpected-certificate detection & correlation — depth: approved inventory + ownership (Certificates & Trust + Shadow IT/Brand)
Heavier tier of #1. Watch CT for certs naming the customer's domains. **A CT record does NOT by
itself prove rogue/unauthorised/mis-issued** — it may be a legitimate CDN/SaaS-managed/ACME/
wildcard-rotation/DR/forgotten-legit/pre-cert/issued-but-unused certificate. Product escalation:
```
New / unexpected certificate observed (unexpected issuer / unexpected SAN / outside approved
inventory / requires owner confirmation)
  → investigate ownership + activity (approved-issuer policy, inventory, active TLS presentation,
    DNS/HTTP relationship, ownership confirmation or customer rejection)
  → only THEN: corroborated "unauthorised / mis-issued" finding
```
The real moat is the CORRELATION (CT + approved-cert inventory + expected-issuer policy + DNS
activity + active-TLS presentation + first-seen/reappearance history + ownership workflow) — the
natural join of Certificates & Trust with Shadow IT/Brand. `likely_ceiling L5 (CT is append-only
→ strong evidence source)` · `fp_risk HIGH without correlation` (hence the escalation ladder).

### 5. Public exposed-artifact detection (Attack Surface)
`.git`/`.env`/backups/dir-listing/swagger. High customer harm, but **heavier legal/data-
minimisation guards than CT/CAA**. Bounded model is mandatory: founder-approved path list only ·
HEAD/range-bounded retrieval · strict size cap · content fingerprinting, classify WITHOUT storing
secret values · no recursive enumeration · no authentication attempt · no downloaded-archive
retention · avoid shared-host resources outside the customer. Verdict = "publicly reachable
sensitive-looking artifact"; "secret leaked" ONLY if content is safely and genuinely verified.
Watch for honeypot/deception, WAF/error-page false positives. `likely_ceiling L3/L4` · `fp_risk
medium` · `safety: HIGH constraints`.

### 6. Web third-party script change & sensitive-context intelligence (Website Security)
NOT an "SRI checker" (SRI is not usable for many dynamic/versioned/loader/tag-manager/CSP-nonce
resources). Real value = **behavioural change**: newly-introduced third-party origin · origin
outside approved inventory · third-party execution on a sensitive page (near payment/login form) ·
origin ownership missing · no observed integrity control · broad CSP · script changed since
baseline. Biggest e-commerce/insurance differentiator (Magecart-class) — and the **heaviest
technical cost**. Honestly bounded first version: `public-page observed script exposure` (we see
what the public page LOADS, not client-side/consent-gated/route-specific/SPA-runtime/geo-device
variation). `likely_ceiling L3/L4` · `fp_risk medium-high`.

### 7. DANE / TLSA — HOLD (Certificates & Trust crypto-agility roadmap)
Technically strong, DNSSEC-dependent (`tlsa_presence · tlsa_validation_state`). Lower SMB
adoption, harder remediation, misconfiguration → interoperability/availability risk, harder sales
story. Do NOT force into the first expansion wave; keep for when real customer/adoption need is
proven.

## Secondary (hold)
TLS config depth vs CIS/Mozilla baseline (`configuration_baseline`, clean L4); BIMI posture;
SPF/DMARC enforcement drift-over-time (continuity monitoring); lookalike domains with MX or a cert
= phishing-capable vs parked (deepens Brand Protection).

## Sequencing discipline
Nothing here starts before the frozen backlog reaches it. Each is a MEDIUM detection-depth episode
(an honest posture engine, not a checkbox), shipped WITH its Evidence-Grade contract. Adding a new
signal in an existing domain is bounded/repeatable; a **9th customer-facing domain is founder-gated
because it changes navigation, coverage-state, reporting, pricing and positioning** (a product-model
decision, not the sidebar-services grouping). See [[evidence-grade-legal-defensibility-law]],
[[module-source-fidelity-freshness-law]], [[pre-beta-execution-resequencing]].
