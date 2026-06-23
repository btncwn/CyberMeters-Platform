# Detection Trust & Signal Quality Program — v1

**Date:** June 2026  
**Classification:** Internal Engineering  
**Purpose:** Full audit of detection confidence, evidence quality, and signal trustworthiness across the scanner. The scanner is not being expanded. This program exists to make what already exists more credible.

---

## Executive Position

CyberMeters currently produces accurate results with conservative false-positive suppression. The problem is presentation, not detection. The same scan that correctly scores a domain at 95/100 surfaces 8 findings, 7 of which are informational with zero score impact. The customer reads "8 Findings" and perceives a meaningful security gap.

The deeper issue: the scanner's internal quality signals (confidence, validation_quality, evidence_quality) are rich and correct in the data layer but are not usefully communicated in the UI. A finding with confidence 60 and a finding with confidence 90 are displayed with the same card, same severity badge, same finding count. The distinction appears only in a small numeric badge that most customers do not interpret.

This program reframes the problem. The goal is not to suppress findings — it is to present findings with appropriate weight so customers understand what is confirmed versus what is uncertain.

---

## Part 1 — HTTP Redirect Validation

### Current Detection Architecture

**Module:** SSL (`runSslModule()`)  
**Probe:** Single HEAD request to `http://<domain>` with `redirect: "manual"`, 10-second timeout via `safeFetch()`  
**Redirect chain:** Up to 2 hops — catches `http→http→https` patterns  
**Result:** `http_redirect_validated` flag, set only when `safeFetch()` returns non-null

### Complete Outcome Map

```
Port 80 fetch outcome
│
├── safeFetch() returns null (timeout, connection refused, syn-drop, geo-block)
│   └── http_redirect_validated = false
│       └── Finding: "HTTP Redirect — Validation Uncertain" [info, confidence 60, score 0]
│
├── safeFetch() returns a response
│   │
│   ├── Status 301/302/307/308 + Location header starts with https://
│   │   └── httpRedirectsToHttps = true → NO FINDING (correct behaviour)
│   │
│   ├── Status 301/302/307/308 + Location is http:// (intermediate hop)
│   │   ├── Second safeFetch() → 301 → https://
│   │   │   └── httpRedirectsToHttps = true → NO FINDING
│   │   └── Second safeFetch() → no https redirect
│   │       └── Finding: "HTTP Does Not Redirect to HTTPS" [medium, confidence 90, score -5]
│   │
│   ├── Status 200 (serves HTTP directly without redirect)
│   │   ├── Domain in ENTERPRISE_DOMAINS + HTTPS headers also succeed
│   │   │   └── Finding: "HTTP Redirect — Validation Uncertain" [info, confidence 60, score 0]
│   │   └── Normal domain
│   │       └── Finding: "HTTP Does Not Redirect to HTTPS" [medium, confidence 90, score -5]
│   │
│   └── Status 4xx/5xx (error on port 80)
│       └── http_redirect_validated = true, httpRedirectsToHttps = false
│           └── Finding: "HTTP Does Not Redirect to HTTPS" [medium, confidence 90, score -5]
│           ⚠ Potential false positive: port 80 error ≠ unencrypted access confirmed
```

### The Core Problem

The scanner uses a single outcome to represent three distinct realities:

| Actual situation | Scanner outcome | Accuracy |
|---|---|---|
| CDN blocks scanner IP on port 80; site correctly redirects for real browsers | "Validation Uncertain" | Correct |
| Firewall drops port 80; site has no HTTP listener at all | "Validation Uncertain" | Correct — but same label as above |
| GoDaddy hosting: port 80 returns 200 with no redirect | "HTTP Does Not Redirect to HTTPS" | Correct |
| Enterprise CDN: port 80 returns 200 to scanner (different edge node) | Edge uncertainty path | Correct for ENTERPRISE_DOMAINS only |
| Anycast CDN: scanner hits nearest PoP, real users hit different PoP | Unpredictable | Architecture limitation |

**The "Validation Uncertain" label covers two different technical outcomes** (null response vs contradictory response) that have different interpretations. A null response from `safeFetch()` means the scanner could not reach port 80 at all. A contradictory response means port 80 responded but didn't redirect, while HTTPS works fine.

### False Positive Analysis

**False positive rate: estimated 60–80% for consumer hosting**

Modern consumer hosting (GoDaddy, Bluehost, Squarespace, Shopify, Wix, Cloudflare Pages) blocks scanner IPs on port 80 via geo-filtering or UA-based rate limits while correctly redirecting real browser traffic. The null response from `safeFetch()` generates "Validation Uncertain" for sites that are correctly configured.

Evidence from blackbullbarbers.co.uk: the domain has confirmed HTTPS (`https_available: true`), HSTS present, A-records point to known CDN infrastructure. Port 80 status is architecturally irrelevant once HTTPS is confirmed.

### False Negative Analysis

**False negative rate: low**

When port 80 is genuinely open and not redirecting, `safeFetch()` almost always returns a response (a 200 or a redirect). The false negative scenario (port 80 open, scanner misses it) requires a rate-limit that allows the connection but drops it mid-response — unusual.

A real false negative path: `safeFetch()` returns 4xx on port 80 (error page) but port 80 is technically serving unencrypted content. The 4xx triggers the scored finding, which is correct, but the finding description ("does not redirect to HTTPS") is inaccurate if the server is returning an error rather than content.

### Proposed Outcome Model — Five Definitive States

Replace the binary validated/uncertain split with five explicit outcome states:

| State | Trigger | Recommended Presentation |
|---|---|---|
| **Confirmed Redirect** | 301/302 → https:// observed | No finding |
| **Blocked/Unreachable** | `safeFetch()` null + HTTPS confirmed | Suppress entirely — HTTPS confirmed, HTTP status irrelevant |
| **Blocked/Unreachable (no HTTPS)** | `safeFetch()` null + HTTPS unavailable | Informational note: "HTTP port status unknown; HTTPS also unavailable" |
| **No Redirect Observed** | 200 or 4xx response, no https:// redirect | Finding: medium severity, score -5 (current behaviour) |
| **Contradictory** | Non-redirect response + HTTPS succeeds (CDN behaviour) | Note: "HTTP response inconsistent with HTTPS availability — likely CDN differential routing" |

The biggest improvement is the "Blocked/Unreachable + HTTPS confirmed" case. When a domain has confirmed HTTPS, blocking the HTTP redirect check generates noise with zero signal value. This state should produce no finding.

### Recommendations

**P1 — Suppress "Validation Uncertain" when HTTPS is confirmed**  
Condition: `!http_redirect_validated && https_available === true`  
Action: No finding. No informational note. The customer already has HTTPS.

**P2 — Shorten port 80 timeout from 10s to 4s**  
TCP connections to filtered ports stall until OS timeout (~4s on Linux, ~30s elsewhere). Workers run in V8 isolation. A 4-second timeout catches real responses while releasing CPU on filtered ports faster.

**P3 — Add one retry before marking uncertain**  
Single retry with a fresh `AbortSignal.timeout(4_000)`. Total time budget: 8 seconds max. This catches transient CDN rate-limit drops without hanging on permanently filtered ports.

**P4 — Distinguish null response from contradictory response in the finding description**  
These are different technical situations. The current finding description is the same for both. Separate them into different description strings even if the finding ID is shared.

---

## Part 2 — Security Header Validation

### Current Detection Architecture

**Module:** Headers (`runHeadersModule()`)  
**Probes:** GET to HTTPS, fallback to HTTP, optional HEAD fallback when bot protection detected, optional HEAD to www-variant  
**Bot detection:** `detectBotProtection()` watches for 5 signal types (challenge redirect, cf-mitigated header, Imperva headers, rate-limit 429/503, minimal 200)  
**Quality gate:** `responseQualityOk = finalHttps && !validationUncertain && statusCode === 200 && !enterpriseEdge`

### Header Severity Classification (current)

| Header | Severity | score_impact | Can produce scored finding? |
|---|---|---|---|
| HSTS | high | -5 | Yes (Branch D) |
| CSP | medium | -3 | No — always Branch C or lower |
| X-Frame-Options | medium | -2 | No — always Branch C or lower |
| X-Content-Type-Options | low | -2 | No — always Branch C or lower |
| Referrer-Policy | low | -1 | No — always Branch C or lower |
| Permissions-Policy | info | -1 | No — always Branch C or lower |

**Only HSTS can ever produce a scored finding.** CSP and XFO are classified as "medium" in `SECURITY_HEADERS` but their severity doesn't matter — the finding generation code (`h.severity !== "high"`) gates on the header's configured severity, not its actual security importance. CSP is medium severity but always hits Branch C.

### Four-Branch Finding Matrix

| Branch | Conditions | Title Suffix | Confidence | Impact |
|---|---|---|---|---|
| A | Header absent from primary, present on other checked path | "— Validation Uncertain" | 70 | 0 |
| B | `responseQualityOk === false` (any reason) | "— Validation Uncertain" | 60 | 0 |
| C | `responseQualityOk === true` + severity ≠ "high" | "(Unverified)" | 70 | 0 |
| D | `responseQualityOk === true` + severity = "high" | *(none)* | 90 | -2 to -5 |

**The semantic problem:** Branch C produces a finding called "(Unverified)" when the response quality gate passed. The response was HTTPS, status 200, no bot protection. The scanner observed the header's absence clearly. What is "unverified" is not the observation — it is whether the absence represents a genuine misconfiguration or a CDN/framework injection the scanner cannot see.

The "(Unverified)" label conflates two different things:
1. Measurement uncertainty (Branch B — the scanner got a bad response)
2. Interpretive uncertainty (Branch C — the scanner got a good response but can't confirm the CDN isn't injecting headers)

These require different messages.

### CDN and Framework Injection Analysis

**Headers frequently injected upstream of the origin:**

| Header | CDN/Layer | Injection method |
|---|---|---|
| X-Frame-Options | Cloudflare, Fastly, Akamai | WAF rule, zone setting |
| X-Content-Type-Options | Cloudflare (default: nosniff on all responses), Nginx defaults | Automatic |
| Referrer-Policy | Nginx, Apache `Header always set`, framework middleware | Server-level config |
| Permissions-Policy | Cloudflare, framework security packages (helmet.js) | CDN or middleware |
| HSTS | Cloudflare HSTS setting, Nginx `add_header Strict-Transport-Security` | CDN zone setting |
| CSP | Next.js security headers, Nuxt, SvelteKit | Framework config in `next.config.js`, `nuxt.config.ts` |

**The key insight:** For XFO, XCTO, Referrer-Policy, and Permissions-Policy, Cloudflare's own security settings inject these headers on every response by default when enabled in the zone. A domain behind Cloudflare with these settings enabled will pass a scanner, while an identical domain served from origin without Cloudflare will fail. The scanner cannot distinguish "header absent from origin" from "Cloudflare security headers disabled."

**Path-specific behaviour** is the other major source of uncertainty. Many sites set CSP, XFO, and XCTO on sensitive paths (login, admin, payment pages) but not on the marketing homepage the scanner probes. The scanner always probes `/` (root path). A finding against `/` does not indicate the header is globally absent.

### False Positive Analysis by Header

| Header | Estimated FP Rate | Primary cause |
|---|---|---|
| HSTS | Low (5–10%) | Rarely injected by CDN without explicit config; direct HTTPS server config |
| CSP | High (40–60%) | Framework injection, per-path policies, SPA served from CDN |
| X-Frame-Options | Medium (30–50%) | Cloudflare zone security, Nginx defaults, often set site-wide but may not appear on root |
| X-Content-Type-Options | Medium (30–50%) | Cloudflare adds `nosniff` automatically for many configurations |
| Referrer-Policy | Medium (30–50%) | Nginx / Apache defaults, framework middleware |
| Permissions-Policy | High (50–70%) | Very inconsistent — many frameworks add it via middleware; scanner probes `/` only |

### False Negative Analysis

**HSTS (Branch D):** The quality gate suppresses HSTS findings when `validationUncertain === true`. A site genuinely missing HSTS behind a WAF that challenges scanner IPs will never receive an HSTS finding. This is the correct trade-off — false positives on HSTS are more damaging than false negatives.

**CSP/XFO/XCTO (Branch C):** These never score. False negatives are structurally impossible — a false negative would require a site to have the header but the scanner to not report it as present. Since absent headers always fire Branch C or lower, the only false negatives are in scoring, not detection.

### The "(Unverified)" Title Problem

The title "Missing X-Frame-Options Header (Unverified)" creates a logical contradiction in the customer's reading:

- "Missing" → I am sure it is absent
- "(Unverified)" → I am not sure

Both cannot be true simultaneously. The scanner is certain the header was absent from its response. What is uncertain is whether that absence reflects the origin's actual configuration.

The correct framing: "X-Frame-Options Header Not Detected" (confident about the observation, silent about interpretation) plus a description that explains why absence might not indicate a configuration gap.

### Proposed Severity Reconsideration

The current approach gives CSP medium severity but treats it identically to Permissions-Policy (info severity) in terms of scoring impact (both: score 0 always). This creates an internal inconsistency — severity says "medium risk" but score impact says "doesn't matter."

**Option A — Promote CSP to high severity:**  
Allow CSP to reach Branch D and score -3 when a clean HTTPS 200 response confirms absence. Risk: higher false positive rate than HSTS. CSP has 40–60% FP rate versus ~5% for HSTS.

**Option B — Demote CSP, XFO, XCTO, Referrer-Policy, Permissions-Policy to "informational observation":**  
Remove from the scored finding tree entirely. Surface them only as advisory notes in a separate "Observations" section. Reduces finding count without hiding information.

**Option C — Add a www-variant probe and cross-check:**  
The scanner already probes www-variant with HEAD. If the header is present on `www.` but absent from the apex, report "Header Present on www Variant" instead of a finding. If absent from both, report with higher confidence.

**Recommendation: Option B + Option C together.** Remove CSP/XFO/XCTO/Referrer/Permissions from the scored finding list. Add www cross-check. Surface as observations only. Reserve the finding list for HSTS (which can be definitively confirmed or denied from a single probe).

### Recommendations

**P1 — Consolidate Branch C findings into a single observation**  
Instead of 4–5 separate finding cards, one aggregated card: "Security Headers Not Fully Observed — [list]" with score_impact 0 and a single explanation. Reduces headline finding count from 8 to 4–5 for typical consumer domains.

**P2 — Fix Branch C title semantics**  
Change "(Unverified)" to "Not Detected" for Branch C. Reserve "Validation Uncertain" for Branch B (quality gate failed). These are different situations and deserve different language.

**P3 — Separate Branch A and Branch C language**  
Branch A (header absent from primary, present elsewhere) is an actively contradictory signal. Its description should call out the contradiction: "This header was observed on the www-variant but not the apex domain. Header policy may differ by host."

**P4 — Fix Academy link mapping**  
All five non-HSTS header findings currently link to `hsts-explained`. This is a content accuracy bug:

| Finding ID | Should link to |
|---|---|
| header_missing_x_frame_options | `xfo-explained` (needs creation) or `csp-explained` |
| header_missing_x_content_type_options | `xcto-explained` (needs creation) |
| header_missing_referrer_policy | `referrer-policy-explained` (needs creation) |
| header_missing_permissions_policy | `permissions-policy-explained` (needs creation) |

**P5 — Add HEAD probe on the canonical path before declaring absent**  
The scanner makes a GET to `/`. Some WAFs respond differently to GET vs HEAD. If GET triggers a bot-protection response but HEAD doesn't, the HEAD may return real application headers. The scanner already does this — but only when `botProtectionSignals.length > 0`. Consider running HEAD unconditionally as a second probe and using the result with more security headers.

---

## Part 3 — DKIM Selector Detection

### Current Architecture

**Probe:** 13 DNS TXT lookups in parallel, one per selector  
**Selectors:** `default, mail, google, k1, selector1, selector2, dkim, smtp, email, mailchimp, sendgrid, s1, s2`  
**Match:** Any TXT record containing `v=DKIM1` or `p=`  
**Outcome when no match:** confidence 60, validation_quality "partial", score_impact 0

### Provider-by-Provider Analysis

| Provider | Used by | Typical selectors | In probe list? |
|---|---|---|---|
| **Google Workspace** | SMBs, agencies | `google`, `20230601`, `20240101` (rotated quarterly) | `google` ✓ — static; rotating selectors ✗ |
| **Microsoft 365** | Enterprises, SMBs | `selector1`, `selector2` | Both ✓ |
| **GoDaddy Email** | Consumer, small business | `default`, `godaddy1`, `godaddy2` | `default` ✓ — but GoDaddy managed email often uses `godaddy1` ✗ |
| **Mimecast** | Enterprise | `mc1`, `mc2`, `selector1` | `selector1` ✓ — but mc1/mc2 ✗ |
| **Proofpoint** | Enterprise | `pp1`, `pp2`, `proofpoint`, `selector1` | `selector1` ✓ — provider selectors ✗ |
| **Mailchimp Transactional** | Marketing | `k1`, `k2`, `k3` | `k1` ✓ — k2/k3 ✗ |
| **SendGrid** | Transactional | `s1`, `s2`, `smtpapi` | `s1` ✓, `s2` ✓ — smtpapi ✗ |
| **Postmark** | Transactional | `20211021`, `pm`, `postmark` | None ✗ |
| **Amazon SES** | Transactional | `amazonses`, `<account-id>` | None ✗ |
| **Zoho Mail** | SMBs | `zoho`, `zmail` | None ✗ |
| **Fastmail** | Individuals, agencies | `fm1`, `fm2`, `fm3` | None ✗ |
| **ProtonMail** | Privacy-focused | `protonmail`, `protonmail2` | None ✗ |
| **cPanel/DirectAdmin** | SMBs, hosting | `default`, `mail`, `x._domainkey` | `default` ✓, `mail` ✓ |
| **Rackspace Email** | SMBs | `mail` | `mail` ✓ |
| **Date-based (rotating)** | Google Workspace, O365 | `YYYYMMDD._domainkey.*` | None ✗ |

**Coverage assessment:** The 13-selector probe covers Microsoft 365, basic Google Workspace, basic GoDaddy, Mailchimp, and SendGrid. It misses Postmark, Amazon SES, Zoho, Fastmail, ProtonMail, Mimecast, Proofpoint (partially), and all date-based rotating selectors.

### SPF-Based Provider Inference

The scanner already has SPF data from the DNS module when DKIM probing runs. SPF `include:` tags reliably identify the outbound email provider:

| SPF include | Provider |
|---|---|
| `include:_spf.google.com` | Google Workspace |
| `include:spf.protection.outlook.com` | Microsoft 365 |
| `include:secureserver.net` | GoDaddy Email |
| `include:servers.mcsv.net` | Mailchimp |
| `include:sendgrid.net` | SendGrid |
| `include:_netblocks.mimecast.com` | Mimecast |
| `include:pphosted.com` | Proofpoint |
| `include:spf.mandrillapp.com` | Mandrill |
| `include:zoho.com` | Zoho Mail |
| `include:amazonses.com` | Amazon SES |
| `include:spf.messagelabs.com` | Symantec/Broadcom |
| `include:mailgun.org` | Mailgun |

This inference is already implemented in the vendor detection module for asset intelligence purposes but is **not used to inform DKIM selector selection**. The scanner has the provider identity in-hand by the time DKIM probing occurs but does not exploit it.

### Proposed Provider-Aware Selector Strategy

**Tier 1: Provider-targeted probes (when provider identified from SPF)**

When the SPF record is parsed and a provider is identified, add 3–5 provider-specific selectors to the probe list before the generic list:

```
Google Workspace → probe: google, 20240101, 20230601, 20231201, 20240601
Microsoft 365    → probe: selector1, selector2
GoDaddy          → probe: default, godaddy1, godaddy2, mail
Mimecast         → probe: mc1, mc2, selector1, mc3
Proofpoint       → probe: pp1, pp2, proofpoint, selector1
Mailchimp        → probe: k1, k2, k3
SendGrid         → probe: s1, s2, smtpapi
Amazon SES       → probe: amazonses (note: SES uses subdomain CNAME, not DKIM directly)
Zoho             → probe: zoho, zmail, mail
Fastmail         → probe: fm1, fm2, fm3
ProtonMail       → probe: protonmail, protonmail2, protonmail3
Postmark         → probe: pm, postmark
```

**Tier 2: Generic selectors (current list, as fallback)**

`default, mail, google, k1, selector1, selector2, dkim, smtp, email, mailchimp, sendgrid, s1, s2`

**Tier 3: Date-based rotating selectors**

Google Workspace and some Microsoft 365 deployments use date-format selectors that rotate quarterly. These cannot be enumerated statically. **Option:** probe the last 8 quarterly dates (2 years of coverage):

```
20240901, 20240601, 20240301, 20231201, 20230901, 20230601, 20230301, 20221201
```

This adds 8 more queries but catches the majority of Google Workspace deployments that rotate. Budget: 13 current + ~8 date probes + ~5 provider-specific = ~26 total. All fire in parallel. The DNS module already runs 17 parallel queries without issues.

### DKIM Confidence Model Assessment

| Outcome | Current confidence | Justification | Proposed |
|---|---|---|---|
| Selector found, record validated | 100 (no finding) | Deterministic | No change |
| Selector not found (generic list, no provider context) | 60 | Appropriate — weak heuristic | No change |
| Selector not found (provider identified, targeted probes ran) | 60 | **Too low** — provider-targeted probe miss is stronger evidence | Raise to 70 |
| Selector not found (provider identified, selector should be known) | 60 | **Too low** — if we know the provider and its standard selectors and still find nothing, DKIM is likely absent | Raise to 80 |

When provider is Microsoft 365 (selector1/selector2 are the only valid selectors) and both return empty, the finding should be more confident: `selector1` and `selector2` are Microsoft-defined and stable. Absence is definitive.

### Evidence Field Bug

The `observed_value` in the DKIM finding hardcodes 7 selectors:
```
"No DKIM TXT record found on common selectors: google, selector1, default, mail, k1, s1, s2"
```
But the code probes 13. The evidence understates what was checked. This reduces customer trust in the finding — customers who know their selector (`smtp`, `email`, `sendgrid`) may check the evidence and not see it listed, assuming it wasn't tested.

### Recommendations

**P1 — Implement provider-aware DKIM selector ordering using SPF inference**  
Use the already-parsed SPF include tags to prioritize provider-specific selectors. GoDaddy + Microsoft 365 together cover ~35% of SMB domains. This one change fixes the majority of DKIM false positives.

**P2 — Expand generic probe list from 13 to 20 selectors**  
Add: `godaddy1, godaddy2, pm, postmark, zoho, fm1, mc1, relay`

**P3 — Add quarterly date-based probes for Google Workspace**  
8 selectors covering last 2 years of Google's quarterly rotation. Increases detection rate for Google Workspace deployments significantly.

**P4 — Raise confidence to 70–80 when provider is identified and all provider-specific selectors miss**  
When we know the provider and its selectors and still find nothing, the evidence is stronger than generic selector misses.

**P5 — Fix evidence observed_value to list all actually-probed selectors**  
This is a data accuracy fix, not a detection change. Always list the full set probed.

**P6 — Rewrite finding title**  
Current: "DKIM Could Not Be Verified Using Common Selectors"  
Option A: "DKIM Selector Not Found — May Use Custom Configuration"  
Option B (when provider identified): "DKIM Not Found on [Provider] Standard Selectors"  
Option B is more actionable — the customer knows exactly what was checked.

---

## Part 4 — DNSSEC Finding Model

### Current Implementation

**Probes:** Three parallel `dnsQueryDnssec()` calls — DS, DNSKEY, RRSIG on A records  
**Enabled condition:** All three record types present (DS ∧ DNSKEY ∧ RRSIG)  
**Finding fires:** Only when all three lookups succeed with no errors AND all return empty  
**Severity:** info | **Confidence:** 90 (high) | **Score impact:** 0

### Is the Severity Classification Correct?

The finding is currently "info" with score_impact 0. The audit question: should DNSSEC absence be:

1. A security **finding** (scored)?
2. An **informational observation** (zero score, surfaced)?
3. A **recommendation** (advisory, no finding card)?

**Arguments for keeping "info" + zero score:**
- DNSSEC adoption is ~3–5% globally for consumer/SMB domains
- Most hosting providers (GoDaddy, Bluehost, SiteGround, Wix, Squarespace) do not enable DNSSEC by default
- The registrar must support DNSSEC (not all do)
- Enabling DNSSEC requires careful coordination between registrar and DNS provider; misconfiguration breaks DNS entirely
- DNS cache poisoning attacks (the threat DNSSEC mitigates) are largely theoretical at scale due to source port randomization and 0x20 encoding
- Customers cannot reasonably be expected to fix this without significant technical guidance

**Arguments for promoting to a scored finding:**
- DNS spoofing is a real attack vector on corporate networks and cafe WiFi
- DNSSEC is available on most major providers (Cloudflare, Route53, Google Cloud DNS)
- Other platforms (SecurityScorecard, Qualys SSL Labs) surface DNSSEC absence as a finding

**Assessment:** The current "info, zero score" is correct for a platform targeting SMBs and consumer businesses. Scoring DNSSEC absence would penalize ~95% of scanned domains for a control they cannot easily implement. The issue is not the classification — it is the **presentation**.

### The Wording Problem

Current: "DNSSEC does not appear to be enabled for this zone."

The phrase "does not appear to be" is hedged. But the finding has `confidence: 90` and `Evidence: Excellent`. These contradict the hedged wording. Three DNS record types returned empty with no errors. The observation is as close to certain as DNS allows.

The hedging was introduced to acknowledge that DNS has caching and propagation delay. However, the `dnsQueryDnssec()` function uses DNSSEC-enabled resolvers with DO bit set — these resolvers specifically query for authenticated records. If DS/DNSKEY/RRSIG are absent, they are genuinely absent at the authoritative level (not just cached absence).

**Proposed wording:** "DNSSEC is not configured for this domain."

### Recommended Classification

Keep: info severity, score_impact 0  
Keep: confidence 90  
Change: description wording (remove hedging)  
Change: presentation model (see Part 6 — Observation vs Finding)  
Add: brief business context explaining why DNSSEC matters and that most providers don't enable it by default

---

## Part 5 — Confidence Framework Audit

### Current Model

**Scale (6 levels):**
```
95 — Verified observation     (direct probe, deterministic)
90 — Multiple confirmations   (strong single source or corroborating signals)
80 — Strong evidence          (single validated probe, no ambiguity)
70 — Probable                 (heuristic with reasonable signal quality)
60 — Weak signal              (indirect inference or common-pattern heuristic)
40 — Unvalidated candidate    (generated algorithmically, no probe validation)
```

**Assignment priority:**
1. Already numeric → keep
2. Legacy string (high/medium/low/confirmed) → convert
3. Direct ID lookup in `FINDING_CONFIDENCE_SCORES`
4. Prefix pattern match (header_missing_*, dse_*, etc.)
5. Default: 70

### Consistency Analysis

**Where the engine works correctly:**

| Finding | Assigned | Justification | Assessment |
|---|---|---|---|
| `email_missing_dmarc` | 90 | Direct DNS TXT lookup | ✓ Correct |
| `email_missing_spf` | 90 | Direct DNS TXT lookup | ✓ Correct |
| `ssl_not_available` | 90 | TLS handshake confirmed failed | ✓ Correct |
| `whois_domain_expired` | 95 | RDAP expiry date is deterministic | ✓ Correct |
| `dse_missing_caa` | 95 | Direct DNS CAA lookup | ✓ Correct |
| `email_dkim_not_detected` | 60 | Common selector heuristic | ✓ Correct |
| `subdomain_takeover` | 90 | CNAME + body fingerprint | ✓ Correct |

**Where conflicts exist:**

| Problem | Detail |
|---|---|
| `header_missing_*` prefix assigns 90 | But Branch B (bad response quality) overrides to 60, and Branch C overrides to 70. The engine's value is discarded. |
| `ssl_no_http_redirect` engine assigns 90 | But the "uncertain" variant hardcodes `confidence: "low"` → converts to 60 via `CONFIDENCE_STRING_TO_NUMERIC`. Engine value used only for confirmed variant. |
| `dnssec_not_enabled` assigns 90 | But description says "does not appear to be" (hedged). Confidence and language are misaligned. |
| Branch C findings: engine=90, actual=70 | Finding generation overrides with `confidence: "medium"` (→70) before engine runs. 90 from prefix pattern is never reached. |

**The fundamental conflict:** The engine assigns confidence based on finding ID. But for header findings, the confidence is properly a function of the *response quality*, not the finding ID. The same `header_missing_x_frame_options` can have confidence 60 (bad response) or 70 (clean response) depending on runtime conditions. The engine's static ID-based assignment cannot capture this.

### UI Layer Problems

**Problem 1 — The number is uninterpreted**  
Customers see "60 Confidence" without any legend. The number is meaningless without context. "60 out of 100" could mean many things.

**Problem 2 — "Needs Verification" banner threshold is 70 (strictly less than)**  
Branch C findings have confidence exactly 70 — they do not trigger the banner. But Branch C findings have "(Unverified)" in their title. A finding can be named "(Unverified)" but not show the "Needs Verification" warning. This is the most confusing inconsistency in the current UI.

**Problem 3 — Confidence and evidence quality are displayed independently but interpreted together**  
A finding with `60 Confidence` and `Evidence: Excellent` reads as contradictory. The evidence structure is excellent (all fields present), but the conclusion is weak. These measure different things but appear side-by-side with no explanation of their relationship.

**Problem 4 — No aggregate confidence signal**  
The scan has no overall "result confidence" metric. A scan that produced 8 informational findings (average confidence 65) looks identical to a scan that produced 8 high-severity findings (average confidence 90) from the outside.

### Proposed Unified Trust Model

**Replace the raw numeric with a 4-label system in the UI** (keep numeric internally):

| Numeric range | UI Label | Display style | Meaning |
|---|---|---|---|
| ≥ 90 | **Confirmed** | Green • | Direct probe, deterministic result |
| 75–89 | **Probable** | Blue • | Strong evidence, single verified source |
| 60–74 | **Likely — Verify** | Amber • | Reasonable signal, manual confirmation recommended |
| < 60 | **Unverified** | Gray • | Heuristic only, do not act without verification |

**Mapping current findings to new labels:**

| Finding | Current confidence | New label |
|---|---|---|
| `email_missing_dmarc` | 90 | Confirmed |
| `ssl_not_available` | 90 | Confirmed |
| `dnssec_not_enabled` | 90 | Confirmed |
| `header_missing_strict_transport_security` (Branch D) | 90 | Confirmed |
| `subdomain_takeover` | 90 | Confirmed |
| `header_missing_*` (Branch C) | 70 | Likely — Verify |
| `email_dkim_not_detected` | 60 | Likely — Verify |
| `header_missing_*` (Branch B) | 60 | Likely — Verify |
| `ssl_no_http_redirect` (uncertain) | 60 | Likely — Verify |
| `admin_surface_medium` | 60 | Likely — Verify |

This gives customers an interpretable signal without exposing the 6-level internal scale. The numeric values remain in the data for engineering analysis.

**Keep "Needs Verification" banner** but align its threshold with the new model: show banner for all findings where the new label is "Likely — Verify" or lower (confidence < 75). This captures both Branch B (60) and Branch C (70) header findings — the current inconsistency is resolved.

---

## Part 6 — Evidence Framework

### Current Architecture

**`validateFindingEvidence()`** checks 6 fields on finding.evidence[0]:
1. source
2. probe target (label / probe_target / target / queried_hostname / requested_url)
3. observed value (value / observed_value / headers_observed / returned_records)
4. expected_value (only checked when score_impact ≠ 0)
5. manual_verification_command
6. checked_at

**Scoring:** 0 warnings → "excellent", ≤2 warnings → "good", >2 warnings → "partial"

**Display:** Three badges in FindingRow: `Confidence`, `Validation: [quality]`, `Evidence: [quality]`

### The Conceptual Separation Problem

Three signals are displayed simultaneously:
1. **Confidence** — how certain the scanner is about its conclusion
2. **Validation quality** — how well the evidence supports the finding's accuracy
3. **Evidence quality** — how complete the evidence object's data fields are

**These are not the same thing, but they are being conflated.**

"Evidence: Excellent" means all 6 evidence fields are populated — it is a structural completeness check, not an assessment of evidence strength. A finding can have:
- Excellent evidence structure (all fields populated)
- Low confidence (the probe yielded an ambiguous result)
- Partial validation (the conclusion is uncertain)

This is exactly what happens with the DKIM finding: `60 Confidence | Validation: Partial | Evidence: Excellent`. All three badges are correct, but they appear contradictory to a non-expert reader. "Excellent evidence" alongside "Partial validation" doesn't parse intuitively.

### Proposed Framework Separation

**Two visible dimensions, not three:**

| Dimension | What it measures | How to display |
|---|---|---|
| **Detection confidence** | How certain the scanner is about its observation | Single label: Confirmed / Probable / Likely—Verify / Unverified |
| **Evidence available** | Whether supporting evidence exists for the customer to review | Binary: show "View Evidence" button or not |

Remove the `Evidence: Excellent/Good/Partial` badge from the UI. It is an internal engineering metric (evidence completeness) that means nothing to a customer and creates confusion when paired with low confidence.

Keep `validation_quality` internally for engineering analytics (the portfolio dashboard uses it). Do not surface it to end customers as a badge.

**Evidence panel should remain** — the actual evidence content (observed value, expected value, verification command, timestamp, source) is valuable. The panel just shouldn't have a quality rating badge attached to it.

### Evidence Field Standardisation

Across the codebase, evidence fields use inconsistent names depending on when the code was written:

| Concept | Legacy name | Post-9C name | Current status |
|---|---|---|---|
| Probe target | `probe_target`, `target`, `queried_hostname` | `label` | `validateFindingEvidence()` handles both |
| Observed value | `observed_value`, `headers_observed`, `returned_records` | `value` | `EvidencePanel` handles both |
| Evidence type | `evidence_type` | `type` | `EvidencePanel` handles both |

This dual-format situation is managed but carries ongoing risk. Any new evidence field added must handle both formats, creating an ever-growing normalization surface.

**Recommendation:** Issue a `POST /api/migrate-evidence` internal endpoint that re-normalizes all historical scan reports in R2 to Sprint 9C array format. This is a one-time batch operation that can run on a schedule. After normalization, remove legacy field handling. (Not in scope for this program — flag for a future maintenance sprint.)

### Evidence for Zero-Impact Informational Findings

Zero-impact informational findings (DNSSEC, DKIM uncertain, header Unverified) currently include the same evidence structure as scored findings. For informational findings, the verification command is the most valuable piece for the customer. Everything else (observed_value, expected_value, source) adds technical noise.

**Proposed:** For `score_impact === 0` findings, simplify evidence display to two rows:
1. "What was checked" (probe_target)  
2. "How to verify yourself" (manual_verification_command)

Full evidence panel available on expand. This reduces the visual weight of informational findings without removing information.

---

## Implementation Roadmap

### Principle

Every recommendation below is a change to existing detection logic or display logic. No new modules, no new pages, no new scanner capabilities. All work targets what already exists.

### Tier 1 — High Signal, Low Effort (do first)

These changes require ≤10 lines of code each and have immediate customer-visible impact.

| ID | Change | File | Estimated Lines | Expected Impact |
|---|---|---|---|---|
| T1.1 | Suppress "Validation Uncertain" HTTP redirect finding when HTTPS confirmed | `index.js` | 3 | Eliminates most common false-positive finding |
| T1.2 | Fix "Needs Verification" banner threshold from <70 to ≤74 | `ScanDetail.jsx` | 1 | Captures Branch C findings in banner — aligns label with behavior |
| T1.3 | Fix Academy link mapping for XFO, XCTO, Referrer-Policy, Permissions-Policy | `index.js` or `ScanDetail.jsx` | 4 | Eliminates content accuracy bug |
| T1.4 | Fix DKIM evidence `observed_value` to list all 13 probed selectors | `index.js` | 1 | Evidence accuracy — customers can verify what was checked |
| T1.5 | Rewrite DNSSEC description — remove hedging | `index.js` | 2 | Resolves confidence/wording mismatch |
| T1.6 | Rewrite DKIM title to "DKIM Selector Not Found — May Use Custom Configuration" | `index.js` | 1 | Reframes from "broken" to "unknown" |
| T1.7 | Rewrite HTTP redirect finding title when HTTPS confirmed | `index.js` | 2 | Better customer communication |

### Tier 2 — Medium Effort, High Impact

These require more engineering but resolve the core structural problems.

| ID | Change | File | Estimated Lines | Expected Impact |
|---|---|---|---|---|
| T2.1 | Consolidate Branch C header findings into one aggregated observation | `index.js` | 25–40 | Reduces informational noise from 4–5 findings to 1 |
| T2.2 | Implement confidence label system (Confirmed/Probable/Likely—Verify/Unverified) in ScanDetail | `ScanDetail.jsx` | 15–20 | Customers can interpret confidence without numeric fluency |
| T2.3 | Implement SPF-inferred provider-aware DKIM selector ordering | `index.js` | 30–50 | Fixes GoDaddy and most Microsoft 365 false positives |
| T2.4 | Expand DKIM probe list to 20 selectors + 8 date-based | `index.js` | 5 | Improves detection coverage for Google Workspace |
| T2.5 | Remove Evidence quality badge from UI; keep evidence panel content | `ScanDetail.jsx` | 5 | Removes confusing structural-vs-substantive conflation |
| T2.6 | Rename Branch C title from "(Unverified)" to "Not Detected" | `index.js` | 2 | Fixes semantic contradiction in title |

### Tier 3 — Structural Improvements

These require design decisions and more substantial implementation.

| ID | Change | File | Estimated Lines | Expected Impact |
|---|---|---|---|---|
| T3.1 | Add `finding_type: "observation"` to all zero-impact informational findings | `index.js` | 8 | Data model foundation for separating observations from findings |
| T3.2 | Frontend: separate "Observations" section from "Findings" list | `ScanDetail.jsx` | 30–50 | Headline finding count reflects only actionable items |
| T3.3 | Add `detection_quality` aggregate block to scan report JSON | `index.js` | 15 | Enables dashboard-level quality signals |
| T3.4 | Port 80 timeout reduction to 4s + one retry | `index.js` | 10 | Reduces scan time and false uncertain rate |
| T3.5 | Add DKIM confidence scaling based on provider identification | `index.js` | 15 | More accurate confidence when provider known |

### Suggested Sprint Sequencing

**Sprint A (1–2 days):** T1.1 through T1.7 — all Tier 1 items. Deployable as a single Worker + frontend update. Immediate visible improvement on every scan.

**Sprint B (2–3 days):** T2.3 + T2.4 (DKIM provider awareness), T2.6 (Branch C title rename), T2.1 (header consolidation). Worker-only changes.

**Sprint C (2–3 days):** T2.2 + T2.5 (confidence label system, remove evidence badge). Frontend-only changes.

**Sprint D (3–4 days):** T3.1 + T3.2 (finding_type + UI separation). Requires both Worker and frontend coordination.

---

## Summary — Root Causes vs Symptoms

| Symptom observed | Root cause | Tier |
|---|---|---|
| "8 Findings" on a 95/100 domain | Informational observations in the scored findings list | T3 |
| "HTTP Redirect — Validation Uncertain" appears on most CDN-hosted sites | Single probe, 10s timeout, no suppression when HTTPS confirmed | T1 |
| 4 header findings with zero score impact on every scan | Branch C hard-coded as never-score regardless of quality | T2 |
| "Missing X-Frame-Options (Unverified)" but no "Needs Verification" banner | Banner threshold at <70; Branch C confidence is exactly 70 | T1 |
| Academy link for header findings all point to HSTS article | Static mapping not updated when non-HSTS header articles were added | T1 |
| "60 Confidence" next to "Evidence: Excellent" | Confidence measures observation certainty; evidence quality measures field completeness — different concepts | T2 |
| DKIM false positive for GoDaddy / custom selectors | Probe list generic, provider not inferred from SPF | T2 |
| "does not appear to be enabled" with confidence 90 | DNSSEC wording hedged without cause — three DNS lookups confirm absence | T1 |

---

*CyberMeters Detection Trust & Signal Quality Program — v1 — June 2026*
