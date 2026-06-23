# Detection Quality Audit — v1

**Date:** June 2026  
**Scope:** Findings currently marked Validation Uncertain, Unverified, or Partial Validation  
**Purpose:** Identify root causes of informational noise, assess false positive / false negative risk, and recommend improvements to evidence quality

---

## Executive Summary

The scanner currently produces four distinct categories of degraded-confidence findings:

| Category | Display Label | Root Cause | Finding Count (typical scan) |
|---|---|---|---|
| HTTP redirect blocked | "HTTP Redirect — Validation Uncertain" | `safeFetch()` returns null — no response at all | 1 |
| Header probe uncertain | "Missing [Header] (Unverified)" | Response quality gate failed (bot protection, non-200, HTTP fallback) | 4–5 |
| DKIM selector miss | "DKIM Could Not Be Verified Using Common Selectors" | Custom selector not in 13-item probe list | 1 |
| DNSSEC not enabled | "DNSSEC Not Enabled" | Absence of DS/DNSKEY/RRSIG observed cleanly | 1 |

The blackbullbarbers.co.uk scan in the brief illustrates all four in one result. The domain earns a 95/100 score despite 8 findings because 7 of them are informational with zero score impact. The customer sees 8 findings and perceives higher risk than the score reflects. The core tension: the scanner correctly avoids false positives by downgrading uncertain findings, but the volume of informational noise reduces customer trust in the result quality.

---

## 1. HTTP Redirect — Validation Uncertain

### Detection Logic

File: `workers/scan-api/src/index.js`

**Phase 1 — SSL module** runs a HEAD request to `http://<domain>` with `redirect: "manual"`:

```js
const httpRes = await safeFetch(httpOrigUrl, { method: "HEAD", redirect: "manual" });
```

`safeFetch()` has a 10-second timeout and returns `null` on any network error or timeout. The probe follows up to 2 redirect hops to catch `http→http→https` chains.

**The `http_redirect_validated` flag** is set only when `safeFetch()` returns a non-null response. A null response means the entire connection was blocked — firewall, geo-routing, bot protection, or port 80 filtering. When validated is false, the finding score_impact is set to 0 and severity to "info".

**Finding generation** (lines 6397–6463):

Two distinct paths:
1. `!redirectValidated` (`http_redirect_validated === false`): HTTP fetch returned null. Finding: confidence "low", score_impact 0, title "HTTP Redirect — Validation Uncertain".
2. `enterpriseEdgeUncertain`: HTTP probe returned a non-redirecting response, but HTTPS headers probe succeeded — a contradiction. Only triggered for `ENTERPRISE_DOMAINS` (google.com, github.com, etc.). Finding: same severity/confidence as path 1.
3. Normal redirect failure (confirmed response, no redirect): confidence "high", severity "medium", score_impact -5. This is the legitimate finding.

### Confidence Calculation

| Scenario | Confidence | Score Impact |
|---|---|---|
| HTTP fetch blocked (null response) | 60 (low) | 0 |
| Enterprise edge contradiction | 60 (low) | 0 |
| Redirect confirmed absent | "high" → numeric 90 | -5 |

The confidence engine (line 768) maps `ssl_no_http_redirect` to 90 for the confirmed variant. The uncertain path hardcodes `confidence: "low"` before the confidence engine runs, so the engine's 90 is overridden.

### False Positive Risk

**Low.** When the HTTP fetch is blocked, the scanner correctly withholds the scored finding. The informational finding generated is accurate — something blocked port 80, which is itself evidence that the site may not serve plain HTTP.

However: **CDN behaviour on port 80 is the dominant reason this fires**. Cloudflare, GoDaddy Managed WordPress, and most modern hosting providers respond to port 80 with an immediate 301 from the CDN edge — but that edge may also block scanner IPs with a syn-drop or rate-limit, returning null. The site may be correctly configured but the scanner cannot see it.

### False Negative Risk

**Medium.** If port 80 is open and not redirecting, but a rate-limit or firewall drops the third or fourth connection attempt mid-scan, the probe returns null and the real finding is never reported. A plaintext HTTP endpoint remains open and undetected.

### Root Issues

1. The probe uses only a single HEAD request to port 80. One failed request causes the entire finding to collapse to "uncertain". There is no retry.
2. `safeFetch()` has a 10-second timeout for all probes. Port 80 connection attempts to filtered ports often hang for 10 seconds before the OS resets the socket. This burns 10 seconds of CPU time on a common code path.
3. The display of this finding is confusing to customers. Seeing "HTTP Redirect — Validation Uncertain" as an informational finding with no score impact is unclear. They cannot tell whether port 80 is open or closed.

### Recommendations

**R1.1 — Two-attempt retry with a shorter timeout for port 80**  
Use `AbortSignal.timeout(4_000)` for the HTTP redirect probe (down from 10s). If the first attempt returns null, retry once with a 4-second timeout before marking as uncertain. Total time budget stays under 10 seconds.

**R1.2 — Suppress the informational finding when HTTPS confirmed**  
If `https_available === true` and the HTTP probe returned null (port blocked), suppress the uncertain finding entirely. A blocked port 80 on a site with confirmed HTTPS is not a meaningful observation for the customer. Show it only when HTTPS is unavailable (where knowing port 80 state matters more).

**R1.3 — Rewrite the finding title**  
Current: "HTTP Redirect — Validation Uncertain"  
Proposed: "Plain HTTP Status Could Not Be Determined"  
Reason: the current title implies the redirect exists but couldn't be validated. The actual situation is the opposite — the port was unreachable, so the redirect's existence is unknown.

---

## 2. Security Header Validation

### Detection Logic

File: `workers/scan-api/src/index.js`, `runHeadersModule()` (line 1748)

The scanner makes two probes: a primary GET request (HTTPS preferred, HTTP fallback) with `redirect: "follow"`, then optionally a HEAD request if bot protection is detected.

**Response quality gate** (`responseQualityOk`):

```js
const responseQualityOk = finalHttps         // response came from an HTTPS URL
  && !validationUncertain                     // no bot-protection signals detected
  && statusCode === 200                       // real application response
  && !headerEnterpriseUncertain;             // no enterprise CDN contradiction
```

All four conditions must be true for any header to be considered a scored finding.

**Bot protection detection** (`detectBotProtection()`, line 1645) watches for:
- Challenge/consent URL redirects (Cloudflare challenge, Google consent, Imperva)
- `cf-mitigated: challenge` header
- Imperva headers
- 429/503 with `Retry-After`
- 200 response with no `Content-Type` and no `Server` header

When bot protection is detected, the module tries a HEAD fallback and picks the response with more security headers.

**Four-branch finding generation** for each missing header:

| Branch | Condition | Title | Confidence | Score Impact |
|---|---|---|---|---|
| A | Header missing from primary but present on another checked path | "[Header] — Validation Uncertain" | medium (70) | 0 |
| B | `responseQualityOk === false` (any reason) | "[Header] — Validation Uncertain" | low (60) | 0 |
| C | `responseQualityOk === true` AND header severity not "high" | "Missing [Header] Header (Unverified)" | medium (70) | 0 |
| D | `responseQualityOk === true` AND severity "high" | "Missing [Header] Header" | high (90) | per-header (-2 to -5) |

**Header severity classification:**

| Header | Severity | Score Impact |
|---|---|---|
| HSTS | high | -5 |
| CSP | medium | -3 |
| X-Frame-Options | medium | -2 |
| X-Content-Type-Options | low | -2 |
| Referrer-Policy | low | -1 |
| Permissions-Policy | info | -1 |

Only HSTS reaches Branch D (high severity). CSP, XFO, XCTO, Referrer-Policy, and Permissions-Policy always reach Branch C or lower — they **can never produce a scored finding regardless of response quality**. The "(Unverified)" suffix on Branch C findings is a design choice, not a measurement outcome.

### Confidence Calculation

The confidence engine (line 845) assigns 90 to all `header_missing_*` IDs by default ("direct HTTP header observation"). But Branch B overrides this with a hardcoded `confidence: "low"` (60), and Branches A and C override with `confidence: "medium"` (70). Only Branch D allows the engine's 90 to stand.

The "Needs Verification" UI banner (`ScanDetail.jsx`, line 352) triggers when `f.confidence < 70`. This means Branch B findings (confidence 60) always show the banner, while Branch C (confidence 70) does not.

### False Positive Risk

**Branch D (HSTS, scored):** Low. The response quality gate is strict.

**Branch C (CSP, XFO, XCTO, Referrer-Policy, Permissions-Policy — Unverified):**  
**High false positive rate by design.** These headers are frequently delivered by:
- CDN edge nodes (Cloudflare, Fastly, Akamai automatically add XFO, XCTO)
- Framework middleware (Next.js, Nuxt inject headers server-side)
- Per-path policies (admin routes may have headers, public pages may not)
- WAF/RASP layers
- Nginx/Apache config separate from the application

The scanner correctly identifies this risk and uses "(Unverified)" + zero score impact for these. But the findings still appear in the customer's finding list. For blackbullbarbers.co.uk, 4 of 8 findings are Branch C header findings with zero impact — half the visible finding list.

**Branch B:** The finding reflects a real measurement limitation, not a misconfiguration.

### False Negative Risk

**Medium for Branch D (HSTS).** If a site is behind a WAF that responds to scanner IPs with a challenge page, `validation_uncertain` becomes true, `responseQualityOk` fails, and the finding falls to Branch B (informational). A genuinely missing HSTS header will not be scored.

**Very low for Branches A/B/C.** These deliberately do not score anything, so there is no false negative in the classic sense — the finding is suppressed or informational.

### Root Issues

1. **Branches A and C are structurally identical from a customer perspective** despite representing different situations. Branch A (header missing on primary, present on another path) is a better observation than Branch C (header absent from a clean 200 response), but both produce the same "(Unverified)" title with medium confidence.

2. **The "(Unverified)" suffix on Branch C is misleading.** The response was clean (HTTPS 200, no bot protection). The scanner is not uncertain about whether the header was present — it was definitively absent from a 200 response. The "(Unverified)" label implies measurement uncertainty when in reality the limitation is about remote observability of CDN-injected headers, not the observation itself.

3. **The HSTS page link in all five header findings links to `hsts-explained`**, even for XFO, XCTO, Referrer-Policy, and Permissions-Policy findings. Customers clicking "Learn more" on an X-Frame-Options finding are taken to HSTS documentation. This is a content mapping error.

4. **Five header findings from one probe** multiplies the informational noise. A customer sees five separate findings, each requiring a decision, when the root issue is a single assessment limitation.

### Recommendations

**R2.1 — Consolidate Branch C findings into one**  
Instead of five separate "(Unverified)" findings, produce a single finding: "Security Headers — Partially Verified" that lists all missing medium/low headers in its description. This reduces 4–5 informational findings to 1 and makes the scan result cleaner.

**R2.2 — Rewrite Branch C title**  
Current: "Missing X-Frame-Options Header (Unverified)"  
Proposed: "X-Frame-Options Header Not Observed"  
Reason: "Missing" implies a confirmed absence. "Not Observed" accurately describes what happened — the header wasn't in the scanner's response, which may not reflect the canonical origin. Removing "(Unverified)" from the title and moving that context into the description reduces anxiety without hiding information.

**R2.3 — Fix Academy links**  
Map each header finding ID to its correct Academy article:
- `header_missing_x_frame_options` → `xfo-explained` (currently links to `hsts-explained`)
- `header_missing_x_content_type_options` → `xcto-explained` (currently links to `hsts-explained`)
- `header_missing_referrer_policy` → `referrer-policy-explained`
- `header_missing_permissions_policy` → `permissions-policy-explained`

**R2.4 — Add a second probe with a browser-like UA for bot-triggered sites**  
The current UA is honest scanner identification (`CyberMeters-Scanner/1.0`). Some WAFs challenge on UA alone without a CAPTCHA. A secondary probe using a genuine browser UA string would bypass UA-based challenges on many consumer sites (barbershops, small businesses) without impersonation concerns, since modern WAFs use JS-based fingerprinting rather than UA alone.

---

## 3. DKIM Selector Detection

### Detection Logic

File: `workers/scan-api/src/index.js`, `runEmailModule()` (line 1935)

The DKIM check fires 13 DNS TXT lookups in parallel, one per common selector:

```js
const DKIM_SELECTORS = [
  "default", "mail", "google", "k1", "selector1", "selector2",
  "dkim", "smtp", "email", "mailchimp", "sendgrid", "s1", "s2",
];
```

A DKIM record is considered found when any selector's DNS response contains `v=DKIM1` or `p=` in a TXT answer.

When no selector matches:

```js
findings.push({
  id:                "email_dkim_not_detected",
  severity:          "info",
  confidence:         60,
  validation_quality: "partial",
  title:             "DKIM Could Not Be Verified Using Common Selectors",
  description:       "No DKIM public key record was found..."
  score_impact:      0,
})
```

The confidence engine default for `email_dkim_not_detected` is 60 (line 775), confirming the design intent: selector heuristic failure is not evidence of absence.

### Confidence Calculation

Confidence 60 maps to "weak signal" on the scale:
- 95: Verified observation
- 90: Multiple confirmations
- 80: Strong evidence
- 70: Probable
- 60: Weak signal / indirect inference
- 40: Unvalidated candidate

The scanner's own comment (line 6832–6833) is accurate: "Enterprise domains use custom selectors; absence is not certainty of absence."

### False Positive Risk

**High, by design.** The finding fires for every domain that uses a selector not in the 13-item list. Common real-world selectors not in the list include:
- GoDaddy managed email: selectors like `godaddy1`, `godaddy2`
- Microsoft 365 business plans: rotating selectors (`20230601._domainkey.*`)
- cPanel/Plesk hosted email: `default` is often renamed or uses account-specific selectors
- Custom corporate selectors: `corp`, `outbound`, `pm`, `mx`
- Date-based selectors (Google Workspace, Microsoft 365 DKIM rotation): `20231201`, `mx2023`

The blackbullbarbers.co.uk scan is a real example: the domain uses GoDaddy email (SPF `secureserver.net`), and GoDaddy uses selectors not in the probe list. The finding fires despite DKIM almost certainly being enabled via GoDaddy's managed email product.

### False Negative Risk

**None.** When DKIM is found, no finding fires. The false negative risk is in the opposite direction — the scoring awards partial credit (`dkimScore = W.dkim * 0.5`) even when DKIM is not detected, acknowledging selector uncertainty.

### Root Issues

1. **The probe list is generic** (13 selectors). The scanner already detects email providers from SPF (`include:secureserver.net` → GoDaddy, `include:sendgrid.net` → SendGrid, etc.). When the email provider is identifiable, the selector probe could target provider-specific selectors first.

2. **The observed_value field hardcodes a 7-item list** ("google, selector1, default, mail, k1, s1, s2") even though the code probes 13 selectors. The evidence is understating what was checked.

3. **The manual verification command** suggests `dig TXT default._domainkey.<domain>` — but for GoDaddy users, `default` is unlikely to work. The suggested command should probe the most likely provider-specific selector based on the SPF `include:` tag.

4. **The finding title** — "DKIM Could Not Be Verified Using Common Selectors" — is technically accurate but sounds alarming. Most customers see "DKIM" and a finding card and assume something is broken. The display confidence badge ("60 Confidence") and the "Needs Verification" banner correctly reduce alarm, but the title sets the initial tone.

### Recommendations

**R3.1 — Provider-aware selector ordering**  
When the email provider can be inferred from SPF, prioritise provider-specific selectors:

| SPF include | Probe first |
|---|---|
| `secureserver.net` (GoDaddy) | `default`, `godaddy1`, `godaddy2` |
| `sendgrid.net` | `s1`, `s2`, `smtpapi` |
| `mailchimp.com` | `k1`, `k2`, `k3` |
| `protection.outlook.com` | `selector1`, `selector2` |
| `_spf.google.com` | `google` |

This alone would resolve the false positive for most GoDaddy and Office 365 managed domains.

**R3.2 — Expand the hardcoded probe list to 20 selectors**  
Add: `godaddy1`, `godaddy2`, `pm`, `mx`, `outbound`, `corp`, `relay`

**R3.3 — Fix the evidence observed_value to list all 13 probed selectors**  
Current: "google, selector1, default, mail, k1, s1, s2" (7 items)  
Correct: all 13 selectors actually probed

**R3.4 — Make the verification command provider-aware**  
When provider is detected from SPF, suggest the most likely selector:  
`dig TXT selector1._domainkey.blackbullbarbers.co.uk @8.8.8.8` (for Office 365)  
`dig TXT godaddy1._domainkey.blackbullbarbers.co.uk @8.8.8.8` (for GoDaddy)

**R3.5 — Rewrite the finding title**  
Current: "DKIM Could Not Be Verified Using Common Selectors"  
Proposed: "DKIM Selector Not Found — Custom Selector May Be in Use"  
Reason: shifts the customer's interpretation from "probably broken" to "possibly using a non-standard selector."

---

## 4. DNSSEC Detection

### Detection Logic

File: `workers/scan-api/src/index.js`, DNS module (lines 1296–1429) and finding generation (lines 6314–6368)

The scanner queries Cloudflare DoH with DNSSEC validation enabled via a dedicated `dnsQueryDnssec()` function. Three record types are probed in parallel:
- DS (Delegation Signer) — at the parent zone level
- DNSKEY — at the zone itself
- RRSIG on A records — signature coverage

**Enabled logic:**

```js
const dnssec = {
  enabled: dsRecords.length > 0 && dnskeyRecords.length > 0 && rrsigRecords.length > 0,
  ...
}
```

All three must be present to consider DNSSEC enabled. This is conservative and correct — a DS without DNSKEY (or vice versa) fires the `dnssec_misconfigured` finding instead.

**The finding fires only when:**
- All three lookups succeeded (no DNS errors)
- All three record types returned empty results

When any lookup fails (DNS error, timeout), the finding is suppressed entirely. This is the correct conservative approach.

### Confidence Calculation

The finding uses `confidence: "high"` — this is appropriate because the observation is direct (three DNS lookups all returning empty with no errors). The confidence engine default (line 764) is 90, and the finding doesn't override it.

However: the **wording** creates a confidence mismatch with the display. The finding says "DNSSEC does not appear to be enabled" (hedged) but is labelled `confidence: "high"` and `severity: "info"`. Customers see "90 Confidence" next to a hedged statement, creating confusion about what "high confidence" means in context.

### False Positive Risk

**Very low.** The three-record check with DNS error suppression is a well-designed gate. The only realistic false positive scenario is a zone that has DS records at the parent but hasn't published DNSKEY yet (in-flight delegation). This is caught by the `dnssec_misconfigured` branch (DS present, DNSKEY absent).

### False Negative Risk

**Low.** If Cloudflare DoH fails to return DS records for a correctly signed zone (caching issue, resolver lag), DNSSEC would appear absent. The probability is low for a well-propagated zone.

One edge case: some registrars publish DS records only at the registrar level (not in the public DNS parent zone) during transition periods. These zones appear unsigned to the scanner.

### Root Issues

1. **Wording mismatch.** "DNSSEC does not appear to be enabled" uses hedged language ("does not appear") but `confidence: "high"` contradicts it. Either the confidence should be lower, or the language should be definitive: "DNSSEC is not enabled on this domain."

2. **The finding is purely informational** (`score_impact: 0`) but appears in the finding list with "90 Confidence" and "Evidence: Excellent." A customer seeing this may assume it affects their score when it doesn't. There is no in-UI signal that this is purely advisory.

3. **DNSSEC adoption is low overall** (~3–5% of consumer domains). Surfacing "DNSSEC Not Enabled" for nearly every scan creates a persistent informational finding that customers learn to ignore, reducing the signal value of informational findings generally.

### Recommendations

**R4.1 — Rewrite for definitiveness**  
When all three lookups succeed and return empty, state definitively:  
"DNSSEC is not configured for this domain. DS, DNSKEY, and RRSIG records were queried and returned no results."  
Remove the "does not appear to be" hedging — the evidence supports a definitive statement.

**R4.2 — Separate informational observations from findings**  
DNSSEC absence is advisory and affects zero score. Consider moving it to a "Security Observations" section rather than the "Findings" list, to reduce noise in the main finding count. This reduces the headline "8 findings" number when 1–2 are purely advisory observations with no remediation urgency.

**R4.3 — Add business context to the description**  
The finding currently states the technical observation. Add: "DNSSEC prevents DNS spoofing attacks. Most consumer hosting providers do not enable DNSSEC by default. Enabling it requires support from your domain registrar."  
This gives customers actionability context without implying urgency.

---

## 5. Confidence Scoring Model Assessment

### Current Model

The confidence engine (`resolveConfidence()`, lines 757–870) assigns numeric scores on a 0–100 scale:

```
95 — Verified observation (direct probe, deterministic result)
90 — Multiple confirmations
80 — Strong evidence
70 — Probable
60 — Weak signal / indirect inference
40 — Unvalidated candidate
```

Finding IDs have hardcoded default scores; dynamic ID prefixes are handled by pattern matching:
- `header_missing_*` → 90 (direct HTTP header observation)
- `email_dkim_not_detected` → 60
- `dnssec_not_enabled` → 90

These defaults are **overridden by the finding generation code** in many cases before the engine runs.

### UI rendering

`ScanDetail.jsx` (line 352): The "Needs Verification" banner appears when `f.confidence < 70`. This means:
- 60 (weak) → banner shows ✓
- 70 (medium) → no banner ✓
- 90 (high) → no banner ✓

The evidence quality badge ("Evidence: Excellent / Good / Partial") is driven by `validateFindingEvidence()`, which checks presence of evidence fields. Most findings have all required fields and therefore receive "Evidence: Excellent" regardless of confidence.

### Structural Issues

**Issue A — Evidence quality and confidence are decoupled but displayed together**  
"90 Confidence" and "Evidence: Excellent" appear side by side. A finding can have "Evidence: Excellent" (all evidence fields populated) and confidence 60 (weak signal). For the DKIM finding, customers see "60 Confidence / Evidence: Excellent" — the evidence structure is excellent, but the conclusion is weak. This reads as contradictory.

**Issue B — The "Needs Verification" threshold at <70 catches only explicit low-confidence findings**  
Branch B header findings (confidence 60) correctly show the banner. Branch C header findings (confidence 70) do not — yet Branch C is explicitly calling the finding "(Unverified)" in the title. The threshold and the title label are inconsistent: a finding can be called "(Unverified)" but not show the "Needs Verification" banner.

**Issue C — The confidence number is not interpreted for the customer**  
Customers see "60 Confidence" without context. The UI doesn't explain what 60 means relative to 90 or 40. A tooltip or label ("Weak Signal", "Probable", "Verified") would significantly improve interpretability.

**Issue D — No aggregate finding quality metric**  
Each finding has a confidence score, but the scan report has no aggregate finding quality signal. A scan that produced 8 informational-only findings with average confidence 65 looks superficially similar to a scan that produced 8 high-severity findings with confidence 90. 

### Recommendations

**R5.1 — Add a confidence label alongside the number**  
Display: `60 Confidence — Weak Signal` or `90 Confidence — Verified`  
Map: 95/90 → "Verified", 80 → "Strong", 70 → "Probable", 60 → "Weak Signal", 40 → "Unvalidated"

**R5.2 — Align the "Needs Verification" banner with the "(Unverified)" title label**  
If a finding title contains "(Unverified)", the banner should always appear regardless of confidence threshold. This removes the current inconsistency where Branch C findings are called "Unverified" but show no warning banner.

**R5.3 — Add `finding_type: "observation"` to zero-impact informational findings**  
Distinguish scored findings from pure observations at the data model level. The front-end can then group or separate them:
- **Findings** (score_impact ≠ 0): displayed in the main findings list
- **Observations** (score_impact = 0, informational): displayed in a separate "Advisory Notes" section

This reduces the headline finding count to only actionable items and moves informational noise out of the primary customer view.

**R5.4 — Add a scan quality summary field**  
Expose aggregate confidence statistics in the scan report:

```json
"detection_quality": {
  "findings_count": 8,
  "scored_findings": 1,
  "informational_findings": 7,
  "average_confidence": 71,
  "low_confidence_count": 2,
  "validation_uncertain": true
}
```

This gives the dashboard and executive reports a single signal about result reliability without exposing per-finding complexity.

---

## Priority Matrix

| ID | Recommendation | Impact | Effort | Priority |
|---|---|---|---|---|
| R3.1 | Provider-aware DKIM selector ordering | High — eliminates #1 FP type for GoDaddy/O365 domains | Low | P1 |
| R2.1 | Consolidate Branch C header findings into one | High — halves visible finding count on most scans | Low | P1 |
| R1.2 | Suppress HTTP redirect finding when HTTPS confirmed | High — eliminates most common uncertain finding | Low | P1 |
| R2.2 | Rename Branch C title to "Not Observed" | Medium — reduces customer alarm | Low | P1 |
| R3.5 | Rename DKIM finding title | Medium — shifts interpretation from "broken" to "unknown" | Low | P1 |
| R5.3 | Add `finding_type: "observation"` to zero-impact findings | High — separates noise from signal | Medium | P2 |
| R5.1 | Add confidence label to the numeric score | Medium — improves interpretability | Low | P2 |
| R4.1 | Rewrite DNSSEC wording to be definitive | Low — removes hedging inconsistency | Low | P2 |
| R2.3 | Fix Academy links for XFO/XCTO/Referrer/Permissions | Medium — reduces content errors | Low | P2 |
| R3.2 | Expand DKIM probe list to 20 selectors | Medium — improves detection coverage | Low | P2 |
| R3.3 | Fix DKIM evidence observed_value (list all 13 selectors) | Low — accuracy improvement | Low | P2 |
| R1.1 | Two-attempt retry for HTTP redirect probe | Medium — reduces false uncertain rate | Medium | P3 |
| R5.2 | Align "Needs Verification" banner with "(Unverified)" title | Low — removes UI inconsistency | Low | P3 |
| R5.4 | Add `detection_quality` aggregate to scan report | Medium — enables dashboard signals | High | P3 |
| R3.4 | Provider-aware verification command | Low — improves UX | Low | P3 |
| R4.2 | Move informational observations to separate section | Medium — cleaner UI | High | P4 |
| R2.4 | Secondary probe with browser UA | Medium — improves WAF bypass | High | P4 |

---

## Findings by Domain — blackbullbarbers.co.uk

Mapping each finding from the scan to its root cause and category:

| Finding | Root Cause | Category | Recommended Fix |
|---|---|---|---|
| DMARC p=none | Direct DNS TXT observation — confidence 90 | Legitimate scored finding | No change needed |
| DNSSEC Not Enabled | All three DNS lookups clean, all empty | Observation (zero score) | R4.1 — rewrite wording |
| HTTP Redirect Uncertain | Port 80 fetch returned null (CDN blocks scanner) | False positive / uncertain | R1.2 — suppress when HTTPS confirmed |
| Missing X-Frame-Options (Unverified) | Branch C: clean 200 but non-high severity | Informational noise | R2.1 + R2.2 |
| Missing X-Content-Type-Options (Unverified) | Branch C | Informational noise | R2.1 + R2.2 |
| Missing Referrer-Policy (Unverified) | Branch C | Informational noise | R2.1 + R2.2 |
| Missing Permissions-Policy (Unverified) | Branch C | Informational noise | R2.1 + R2.2 |
| DKIM Could Not Be Verified | GoDaddy email not in 13-selector probe list | False positive | R3.1 + R3.5 |

If P1 recommendations are implemented:
- Finding count: 8 → 3 (DMARC + DNSSEC observation + one consolidated header observation)
- Scored findings: unchanged (still 1 — DMARC)
- Customer signal: clearer, fewer false alarms

---

*CyberMeters Detection Quality Audit — v1 — June 2026*
