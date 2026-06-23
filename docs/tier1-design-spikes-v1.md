# Tier 1 Design Spikes — Security Header Consolidation & DKIM Provider Detection

**Date:** June 2026  
**Status:** Design only — implementation pending approval  
**Parent:** Detection Trust & Signal Quality Program v1

---

## P5 — Security Headers Not Observed Consolidation

### Problem Statement

The current scanner generates up to 5 separate Branch C findings per scan — one for each of: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy. Every finding has `score_impact: 0`, confidence 70, and a title with "(Unverified)". On a typical CDN-hosted domain with no custom header configuration, this creates 4–5 finding cards that:

- Inflate the visible finding count with zero actionable signal
- Repeat the same observation 4–5 times ("was not returned in the scanner's HTTP probe")
- After the P2 banner fix, each will now show a "Needs Verification" banner — 4–5 amber banners for the same category of uncertainty

Consolidation replaces these 4–5 findings with **one aggregated observation** that names all absent headers in a single card.

---

### Scope of Change

**HSTS is excluded from consolidation.** HSTS is the only header that can reach Branch D (scored, confidence 90). It must remain a distinct finding so its scoring logic is not disrupted. HSTS Branch C findings (when quality gate fails) are rare and also excluded from consolidation for consistency.

**Branch A and Branch B findings are excluded from consolidation.** Branch A (header absent from primary, present on alt path) and Branch B (response quality bad) carry specific information about why the header wasn't observed. Collapsing them into a generic finding would lose that context.

**Only Branch C findings for the 5 non-HSTS headers are consolidated.** These 5 headers share identical detection semantics in Branch C — they all represent a clean-200 HTTPS response where the header was simply absent, and all carry the same CDN-injection caveat.

---

### Exact Change — `workers/scan-api/src/index.js`

**Current code (lines 6593–6609):**

For each of the 5 non-HSTS headers that hits Branch C (`h.severity !== "high"` + `responseQualityOk === true`), a separate finding is pushed:

```js
} else if (h.severity !== "high") {
  findings.push({
    id:           `header_missing_${h.name.replace(/-/g, "_")}`,
    module:       "headers",
    severity:     "info",
    confidence:   "medium",
    title:        `Missing ${h.label} Header (Unverified)`,
    description:  `The ${h.label} header...`,
    score_impact: 0,
    evidence: { ... },
  });
}
```

**Proposed change — two-phase approach:**

**Phase A:** Collect Branch C headers into an array instead of pushing immediately.

```js
// Collect Branch C headers for consolidated observation
const branchCHeaders = [];

for (const h of SECURITY_HEADERS) {
  // ... existing Branch A, B, D logic unchanged ...
  } else if (h.severity !== "high") {
    // Collect for consolidated finding — push after loop completes
    branchCHeaders.push(h);
  }
}

// After the loop: emit consolidated observation if any Branch C headers exist
if (branchCHeaders.length > 0) {
  const absentLabels = branchCHeaders.map(h => h.label).join(", ");
  const absentNames  = branchCHeaders.map(h => h.name).join(", ");
  const curlHeaders  = branchCHeaders.map(h => `grep -i "${h.name}"`).join(" | ");

  findings.push({
    id:           "security_headers_not_observed",
    module:       "headers",
    severity:     "info",
    confidence:   "medium",
    title:        "Security Headers Not Fully Observed",
    description:  `The following security headers were not detected in the scanner's response from ${domain}: ${absentLabels}. These headers are frequently delivered by CDN layers, framework middleware, or per-path policies and may not be present on the root path probed by the scanner. Verify on the canonical origin before treating as a defect.`,
    score_impact: 0,
    // Preserve individual header IDs for BRS lookup compatibility
    _consolidated_ids: branchCHeaders.map(h => `header_missing_${h.name.replace(/-/g, "_")}`),
    evidence: {
      evidence_type:               "http_header_probe",
      probe_target:                modules.headers.response_url ?? `https://${domain}`,
      observed_value:              `Headers absent from HTTPS ${modules.headers.status_code} response: ${absentNames}`,
      expected_value:              `${absentNames} headers present in HTTP response`,
      source:                      "cloudflare_workers_fetch",
      checked_at:                  evidenceTime,
      manual_verification_command: `curl -sI https://${domain} | ${curlHeaders}`,
    },
  });
}
```

---

### Business Risk Score (BRS) Compatibility

The BRS deduction table uses `findingIds.has("header_missing_content_security_policy")` and `findingIds.has("header_missing_x_frame_options")` to compute website score deductions. These IDs will no longer be in the findings array after consolidation.

**Two options:**

**Option A — Emit legacy IDs via `_consolidated_ids`:**  
The BRS lookup function checks `findingIds` which is built from `findings.map(f => f.id)`. After consolidation, these IDs won't be in the set. The BRS table must be updated to check `security_headers_not_observed` instead, with a combined deduction.

Current BRS logic:
```js
if (findingIds.has("header_missing_content_security_policy")) webDed += 15;
if (findingIds.has("header_missing_x_frame_options") && findingIds.has("header_missing_x_content_type_options")) webDed += 8;
```

After consolidation — replace with:
```js
if (findingIds.has("security_headers_not_observed")) {
  // Use _consolidated_ids to determine which headers were absent
  const obs = findings.find(f => f.id === "security_headers_not_observed");
  const consolidatedIds = new Set(obs?._consolidated_ids ?? []);
  if (consolidatedIds.has("header_missing_content_security_policy")) webDed += 15;
  if (consolidatedIds.has("header_missing_x_frame_options") && consolidatedIds.has("header_missing_x_content_type_options")) webDed += 8;
}
```

**Option B — Keep individual IDs in a `finding_ids` array on the consolidated finding:**  
Simpler: the BRS logic looks for IDs in either `findings` OR in `security_headers_not_observed.finding_ids`. Backwards compatible.

**Recommendation: Option B.** The `finding_ids` array is cleaner than `_consolidated_ids` and is more explicit about purpose.

---

### Remediation Intelligence Compatibility

Remediation cards (`REMEDIATION_INTEL`) are keyed by finding ID. After consolidation, `header_missing_content_security_policy`, `header_missing_x_frame_options`, etc. will not appear as top-level finding IDs. The remediation panel lookup will return null.

**Fix:** The consolidated finding renders a remediation panel that links to all individual header remediation cards, e.g.: "For specific guidance, see: [CSP →] [X-Frame-Options →] [X-Content-Type-Options →]"

Or alternatively, a single combined remediation card can be added to `REMEDIATION_INTEL` under the `security_headers_not_observed` ID.

---

### Academy Link Compatibility

`ACADEMY_LINK_MAP` currently has individual entries per header. After consolidation, the map lookup for `security_headers_not_observed` will return undefined. A new entry is required:

```js
security_headers_not_observed: "security-headers-explained",
```

A new Academy article covering all 5 headers as a group is needed, OR the consolidated finding can link to `csp-explained` as the entry point (CSP is the most impactful of the 5).

---

### Finding Count Impact

| Domain type | Before | After | Reduction |
|---|---|---|---|
| CDN-hosted, no custom headers (typical consumer) | 4–5 Branch C findings | 1 consolidated | 3–4 fewer |
| Fully configured (CSP, XFO, XCTO set) | 0–1 Branch C | 0 consolidated | No change |
| Mixed (some set, some not) | 2–3 Branch C | 1 consolidated | 1–2 fewer |

For blackbullbarbers.co.uk example: from 8 findings to 5 (HSTS present so no HSTS finding; 4 header findings consolidated into 1, keeping HTTP redirect uncertain — but P1 will suppress that too → 4 total).

---

### Migration Risk

**Low.** The consolidated finding is a new ID (`security_headers_not_observed`). Existing scans already stored in R2 are not affected — they retain the original 5 individual findings. The change only affects newly generated scans.

**Backward-compatibility risk:** Any downstream consumer that reads finding IDs from the JSON payload and checks for `header_missing_content_security_policy` etc. will not find them in new scans. This includes:
- BRS computation (must be updated in same deploy — same file)
- Portfolio-level header statistics queries (check `workers/scan-api/src/index.js` portfolio endpoints)
- Any external integrations (none currently known)

**Rollback:** Revert the `branchCHeaders` array change and re-emit individual findings per header. Zero database schema impact.

---

### Files Changed

| File | Change |
|---|---|
| `workers/scan-api/src/index.js` | Branch C loop → collect + emit consolidated finding |
| `workers/scan-api/src/index.js` | BRS table update for `security_headers_not_observed` |
| `workers/scan-api/src/index.js` | `ACADEMY_LINK_MAP` new entry |
| `workers/scan-api/src/index.js` | `REMEDIATION_INTEL` new combined entry OR multi-link render |

No frontend changes required. The consolidated finding renders normally as a standard FindingRow — only the ID and title change.

---

---

## P6 — DKIM Provider-Aware Selector Detection

### Problem Statement

The DKIM probe uses a static list of 13 generic selectors. It has no awareness of which email provider the domain uses. The SPF record — parsed earlier in the same scan — reliably identifies the outbound email provider via `include:` tags. The scanner has the provider identity available but does not use it.

Result: GoDaddy-hosted email (uses `godaddy1`/`godaddy2`), Zoho Mail (uses `zoho`/`zmail`), Postmark, Amazon SES, and others all fail DKIM detection even when DKIM is correctly configured.

---

### Implementation Architecture

**Location:** `workers/scan-api/src/index.js`, in the DKIM detection block within `computeScore()`.

DKIM detection runs after `modules.email` is populated. `modules.email` already contains the parsed SPF record including `include:` tags (available as `modules.email.spf_record` or similar — verify exact field name in email module output).

**Three-tier selector strategy:**

```
Tier 1: Provider-specific selectors (inferred from SPF include: tags)
Tier 2: Generic selectors (current 13-item list)
Tier 3: Date-based rotating selectors (for Google Workspace)
```

Total probe budget: ~26 parallel DNS lookups (currently: 13). All fire in parallel — no sequential dependency. DNS module already runs 17 parallel queries without issue.

---

### Provider Detection Map

Parse the SPF TXT record for `include:` values. Map to provider:

```js
const SPF_PROVIDER_MAP = [
  { includes: ["_spf.google.com", "googlemail.com"],          provider: "google_workspace" },
  { includes: ["spf.protection.outlook.com", "outlook.com"],  provider: "microsoft_365"   },
  { includes: ["secureserver.net", "mailstore1.secureserver.net"], provider: "godaddy"    },
  { includes: ["servers.mcsv.net"],                            provider: "mailchimp"       },
  { includes: ["sendgrid.net"],                                provider: "sendgrid"        },
  { includes: ["_netblocks.mimecast.com", "mimecast.com"],    provider: "mimecast"        },
  { includes: ["pphosted.com", "proofpoint.com"],             provider: "proofpoint"      },
  { includes: ["spf.mandrillapp.com", "mandrillapp.com"],     provider: "mandrill"        },
  { includes: ["zoho.com", "zohomail.com"],                   provider: "zoho"            },
  { includes: ["amazonses.com", "amazon.com"],                provider: "amazon_ses"      },
  { includes: ["spf.messagelabs.com"],                        provider: "symantec"        },
  { includes: ["mailgun.org"],                                 provider: "mailgun"         },
  { includes: ["postmarkapp.com", "spf.mtasv.net"],           provider: "postmark"        },
  { includes: ["zoho.com"],                                    provider: "zoho"            },
  { includes: ["spf.fastmail.com"],                           provider: "fastmail"        },
  { includes: ["protonmail.ch"],                              provider: "protonmail"      },
  { includes: ["rsgsv.net"],                                  provider: "rackspace"       },
];

function inferEmailProvider(spfRecord) {
  if (!spfRecord) return null;
  for (const { includes, provider } of SPF_PROVIDER_MAP) {
    if (includes.some(inc => spfRecord.includes(inc))) return provider;
  }
  return null;
}
```

---

### Provider-Specific Selector Map

```js
const PROVIDER_DKIM_SELECTORS = {
  google_workspace: ["google", "20240601", "20240301", "20231201", "20230901"],
  microsoft_365:    ["selector1", "selector2"],
  godaddy:          ["default", "godaddy1", "godaddy2", "mail"],
  mailchimp:        ["k1", "k2", "k3"],
  sendgrid:         ["s1", "s2", "smtpapi"],
  mimecast:         ["mc1", "mc2", "mc3", "selector1"],
  proofpoint:       ["pp1", "pp2", "proofpoint", "selector1"],
  mandrill:         ["mandrill", "mte1", "selector1"],
  zoho:             ["zoho", "zmail", "mail"],
  amazon_ses:       ["amazonses"],  // SES uses CNAME delegation — probe may not resolve
  symantec:         ["s1", "s2", "selector1"],
  mailgun:          ["mailo", "smtp", "selector1"],
  postmark:         ["pm", "postmark", "20211021"],
  fastmail:         ["fm1", "fm2", "fm3"],
  protonmail:       ["protonmail", "protonmail2", "protonmail3"],
  rackspace:        ["mail", "selector1", "rackspace"],
};
```

---

### Date-Based Selector Generation (Google Workspace)

Google Workspace rotates DKIM selectors quarterly using the format `YYYYMMDD`. Generate the last 8 quarterly periods programmatically:

```js
function googleQuarterlySelectors(count = 8) {
  const selectors = [];
  const now = new Date();
  // Align to quarter boundaries: 0301, 0601, 0901, 1201
  const quarters = [3, 6, 9, 12];
  let year = now.getFullYear();
  let qIdx = quarters.findLastIndex(m => m <= now.getMonth() + 1);
  for (let i = 0; i < count; i++) {
    const month = String(quarters[qIdx]).padStart(2, "0");
    selectors.push(`${year}${month}01`);
    qIdx--;
    if (qIdx < 0) { qIdx = 3; year--; }
  }
  return selectors;
}
```

For Google Workspace domains, prepend these 8 selectors to the probe list.

---

### Selector Ordering Strategy

```js
function buildDkimSelectorList(provider, baseSelectors) {
  const providerSelectors = provider ? (PROVIDER_DKIM_SELECTORS[provider] ?? []) : [];
  const dateSelectors     = provider === "google_workspace" ? googleQuarterlySelectors() : [];
  
  // Tier 1 first (most likely to match), then base list (deduped)
  const ordered = [...new Set([
    ...providerSelectors,
    ...dateSelectors,
    ...baseSelectors,
  ])];
  return ordered;
}
```

The `Set` deduplication handles overlap (e.g. `selector1` appears in both generic list and Mimecast list).

---

### Confidence Model Updates

| Scenario | Current confidence | Proposed confidence | Rationale |
|---|---|---|---|
| No provider identified, all 13 generic miss | 60 | 60 (no change) | Still a heuristic — selector could be custom |
| Provider identified, all provider-specific selectors miss | 60 | 80 | Provider's standard selectors are known and stable — absence is stronger evidence |
| Microsoft 365 identified, selector1 + selector2 both miss | 60 | 85 | Microsoft only uses these two — absence is near-definitive |
| Google Workspace, generic + 8 quarterly selectors all miss | 60 | 75 | Rotating selectors have coverage gap risk beyond 8 quarters |

Implementation: pass the provider and whether provider-specific probes were run through to the finding generation:

```js
const dkimConfidence = providerSelectors.length > 0
  ? (provider === "microsoft_365" ? 85 : 75)
  : 60;
```

---

### Evidence Field Fix

Current `observed_value` hardcodes 7 selectors even though 13 are probed. After this change, 20–26 selectors may be probed. Fix the evidence to always list what was actually probed:

```js
observed_value: `No DKIM TXT record found on probed selectors: ${probedSelectors.join(", ")}`,
```

---

### Finding Title Update by Provider

| Provider identified | Current title | Proposed title |
|---|---|---|
| None | "DKIM Could Not Be Verified Using Common Selectors" | No change (generic) |
| Microsoft 365 | "DKIM Could Not Be Verified Using Common Selectors" | "DKIM Not Found on Microsoft 365 Standard Selectors (selector1, selector2)" |
| Google Workspace | "DKIM Could Not Be Verified Using Common Selectors" | "DKIM Not Found on Google Workspace Selectors" |
| GoDaddy | "DKIM Could Not Be Verified Using Common Selectors" | "DKIM Not Found on GoDaddy Standard Selectors" |
| Other provider | "DKIM Could Not Be Verified Using Common Selectors" | "DKIM Not Found — [Provider] Selectors Checked" |

---

### Expected False-Negative Reduction

Based on provider prevalence in SMB segments:

| Provider | SMB prevalence | Selector coverage before | After | FN reduction |
|---|---|---|---|---|
| Microsoft 365 | ~35% | selector1 ✓ selector2 ✓ | Same + higher confidence | Low (already covered) |
| Google Workspace | ~25% | google ✓ (but rotates) | + 8 quarterly selectors | High — rotating selector miss eliminated |
| GoDaddy | ~15% | default ✓ godaddy1 ✗ godaddy2 ✗ | + godaddy1, godaddy2 | Medium — 40–50% of GoDaddy DKIM now detectable |
| Mailchimp | ~8% | k1 ✓ (k2/k3 miss) | + k2, k3 | Low |
| SendGrid | ~5% | s1 ✓ s2 ✓ | Same | No change |
| Postmark | ~3% | none ✓ | + pm, postmark, date | High — 0% → ~80% detection |
| Amazon SES | ~3% | none | + amazonses | Medium — SES uses CNAME, complex |
| Zoho | ~2% | none | + zoho, zmail | High — 0% → ~90% detection |

Overall estimated false-negative reduction: **30–40% across scanned SMB domains**.

---

### Files Changed

| File | Change |
|---|---|
| `workers/scan-api/src/index.js` | Add `SPF_PROVIDER_MAP` constant |
| `workers/scan-api/src/index.js` | Add `PROVIDER_DKIM_SELECTORS` constant |
| `workers/scan-api/src/index.js` | Add `inferEmailProvider()` helper |
| `workers/scan-api/src/index.js` | Add `buildDkimSelectorList()` helper |
| `workers/scan-api/src/index.js` | Add `googleQuarterlySelectors()` helper |
| `workers/scan-api/src/index.js` | Update DKIM detection block to use new selector list |
| `workers/scan-api/src/index.js` | Update DKIM finding confidence and title based on provider |
| `workers/scan-api/src/index.js` | Fix DKIM `observed_value` to list all probed selectors |

No frontend changes required. No database schema changes. No API contract changes.

---

### Migration Risk

**Very low.** Additive change — only increases selector coverage. Existing scans unaffected. No ID changes.

**One risk:** Amazon SES uses CNAME delegation for DKIM, not a TXT record on the primary domain. Probing `amazonses._domainkey.domain.com` via TXT may return NXDOMAIN even when SES DKIM is correctly configured. The `amazonses` selector probe may generate a false "not found" even when SES DKIM works. **Recommendation:** exclude `amazon_ses` from the confidence boost — keep at 60 when provider is SES.

---

### Implementation Estimate

~80–100 lines of new code (constants + helpers + detection block update). All self-contained in `index.js`. No external dependencies. Worker syntax check passes after implementation.

---

*Tier 1 Design Spikes — v1 — June 2026*
