# Scanner Accuracy Framework

CyberMeters scanner accuracy is built around five validation layers. The goal is to make every finding explainable, reproducible, and conservative when remote evidence is ambiguous.

## 1. Evidence-Based Findings

Findings should include structured evidence with source, target, observed value, expected value where relevant, manual verification command, and checked timestamp.

Current coverage:

- DNS, SSL, email, and header findings generally include structured evidence.
- Findings now receive `evidence_quality`: `excellent`, `good`, `partial`, or `missing`.
- Missing fields produce non-blocking `evidence_warnings`.

Remaining gaps:

- Some asset, subdomain, and takeover findings still need richer per-finding evidence.
- D1 stores evidence JSON but does not have dedicated columns for evidence quality.

## 2. Confidence Levels

Confidence controls how CyberMeters presents ambiguous results. Low-confidence findings should be informational or non-scoring unless confirmed by consistent evidence.

Current coverage:

- DKIM common-selector misses are low confidence and non-scoring.
- Header validation uncertainty is downgraded to low or medium confidence.
- Header absence observed on only one path remains non-scoring.

Remaining gaps:

- Confidence is not yet backed by a formal rules table.
- Some modules use confidence language outside the main finding model.

## 3. Cross-Checking And Resolver Agreement Model (v4)

Cross-checking compares multiple resolver perspectives before treating a DNS result as reliable.

### Resolver Agreement Score

CyberMeters queries three independent resolvers for DNS A records on every scan:

- Cloudflare DoH (`1.1.1.1`)
- Google DoH (`dns.google`)
- Quad9 DoH (`dns.quad9.net`)

`resolver_agreement_score` is computed per record type by `computeResolverAgreementScore(resolvers)`:

- Requires at least 2 resolvers to return a result.
- Reference is the first available resolver's returned records (sorted).
- Agreement is the fraction of resolvers whose returned records exactly match the reference.
- Returns `null` when fewer than 2 resolvers succeed.

Score interpretation:

| Score | Meaning |
|-------|---------|
| 100   | All queried resolvers agree |
| 50–99 | Partial agreement — possible propagation lag |
| 0–49  | Significant disagreement — treat results with caution |
| null  | Insufficient resolver coverage for agreement scoring |

`resolver_disagreement: true` is emitted in finding evidence when agreement score < 50.

The platform-level `resolver_agreement_avg` is the mean score across all cross-checked scans. It contributes 10% to the platform Accuracy Score. Null values default to 50 in the accuracy score calculation.

Current coverage:

- DNS A record cross-check runs against all three resolvers.
- MX and TXT (SPF, DMARC) cross-checks run against Cloudflare and Google only.
- AAAA cross-check runs against Cloudflare and Google.
- `resolver_agreement_score` is included in DNS finding evidence and `cross_checks` output.

Remaining gaps:

- Quad9 is only used for A records. Extending to MX, TXT, and CAA is future work.
- Authoritative queries require a separate controlled resolver service if needed.

## 4. Canonical URL Profile Model (v4)

The canonical URL profile is a pure computation over existing ssl and headers module data. It adds no new network calls.

`buildCanonicalUrlProfile(modules)` derives:

- `canonical_url` — the authoritative HTTPS URL for the domain (e.g. `https://example.com`)
- `canonical_confidence` — `"high"`, `"medium"`, or `"low"`
- `http_redirects_to_https` — true when an HTTP→HTTPS redirect was observed
- `http_redirect_validated` — true when the redirect was confirmed and headers fetched at the redirect target
- `validation_uncertain` — true when evidence is incomplete or inconsistent
- `variants` — list of URL variants checked (`http`, `http_www`, `https`, `https_www`)

Confidence rules:

| Condition | Confidence |
|-----------|-----------|
| Clean HTTPS confirmed, redirect validated, no uncertainty | `high` |
| Some evidence available but uncertainty flag is true | `medium` |
| No usable ssl or headers data | `low` |

`validation_uncertain` is set when the redirect chain is empty or headers were not fetched at the final HTTPS destination. Findings with `validation_uncertain: true` are non-scoring by policy.

The profile is available in scan results as `modules.canonical_url_profile`. It is used to improve header finding confidence decisions.

## 5. Header Strength Classification Model (v4)

`classifyHeaderStrength(name, value)` evaluates present security headers beyond simple presence/absence.

It returns `{ status, details }` per header where status is one of:

- `valid` — header is present and correctly configured
- `weak` — header is present but configuration is insufficient
- `malformed` — header has an invalid or unparseable value
- `unknown` — unrecognised header or value pattern

Classification rules by header:

| Header | `valid` criteria | `weak` criteria |
|--------|-----------------|-----------------|
| Strict-Transport-Security | `max-age` ≥ 15,552,000 (180 days) | `max-age` present but < 15,552,000 |
| Content-Security-Policy | No `unsafe-inline` or wildcard `*` source | `unsafe-inline` or wildcard present |
| X-Frame-Options | `DENY` or `SAMEORIGIN` | Any other value |
| X-Content-Type-Options | `nosniff` | Any other value |
| Referrer-Policy | `no-referrer`, `same-origin`, or `strict-origin` variants | `unsafe-url` or `no-referrer-when-downgrade` |
| Permissions-Policy | Any non-empty value | Empty value |

Header strength is stored in `modules.headers.header_strength` as a map of header name to `{ status, details }`. This is evidence metadata only. Scoring on weakness status is deferred to a future sprint; the existing presence/absence scoring is unchanged.

## 6. Regression Fixtures And Golden Domains

Regression fixtures are offline examples for expected scanner behaviour. Golden domains are future controlled live targets.

Current coverage:

- `docs/regression-fixtures.json` defines key expected findings.
- `scripts/validate-regression-fixtures.js` validates fixture shape and lightweight expectations offline.
- `docs/golden-test-domains.md` defines future controlled domains and expected outcomes.

Remaining gaps:

- Fixtures do not yet execute the production `computeScore` function directly.
- Golden domains are a plan only; DNS/TLS/header/email hosting must be provisioned later.

## 7. Manual Verification Playbooks

Manual verification gives customers and developers a reproducible way to confirm scanner results.

Current coverage:

- Findings are expected to include `manual_verification_command`.
- Scan Details displays evidence and manual commands in a collapsed evidence panel.
- Partial or missing evidence now shows: `Evidence incomplete - verify manually`.

Remaining gaps:

- Manual commands are shell-oriented and may need platform-specific variants.
- Some non-primary module findings do not yet expose manual commands.

## Accuracy Score Formula (v4)

The platform Accuracy Score is a weighted composite of five metrics, computed by `GET /api/platform/accuracy`:

```
accuracy_score = (evidence_complete_pct × 0.40)
               + (high_confidence_pct   × 0.20)
               + (regression_pass_rate  × 0.20)
               + (max(0, 100 − validation_uncertain_pct) × 0.10)
               + (resolver_agreement_avg × 0.10)
```

Where:

| Metric | Weight | Source |
|--------|--------|--------|
| `evidence_complete_pct` | 40% | % findings where `evidence_quality` is `excellent` or `good` |
| `high_confidence_pct` | 20% | % findings with `confidence: "high"` |
| `regression_pass_rate` | 20% | % regression fixtures that pass validation |
| `100 − validation_uncertain_pct` | 10% | Inverse of % findings with `validation_uncertain: true` |
| `resolver_agreement_avg` | 10% | Mean `resolver_agreement_score` across scans; null defaults to 50 |

Score bands:

| Score | Label |
|-------|-------|
| 80–100 | High accuracy |
| 60–79  | Good accuracy |
| 40–59  | Fair accuracy |
| 0–39   | Low accuracy |

The score and all component metrics are returned by `GET /api/platform/accuracy` and displayed on the Scanner Accuracy page.

## Current Accuracy Policy

- Do not score findings when the scanner cannot establish a reliable canonical response.
- Prefer informational findings over false positives.
- Keep scan completion non-blocking even when secondary validation fails.
- Preserve evidence for later audit rather than hiding uncertain observations.
- Header weakness (`classifyHeaderStrength` status `weak`) is evidence-only; scoring changes are deferred.
- Resolver disagreement is evidence-only; it does not suppress or block findings.
