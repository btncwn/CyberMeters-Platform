# CyberMeters False Positive Audit v1

**Sprint 8 — Trust & Methodology**
**Date:** June 2026
**Status:** Internal Reference — Not Customer-Facing

---

## Overview

This audit identifies the highest-risk false positive sources in the CyberMeters scan engine. Each item references specific code behaviour in `workers/scan-api/src/index.js` and assesses its impact on customer trust.

False positives are grouped by module and ranked by likelihood × impact.

---

## Executive Summary

| # | Finding | FP Risk | Score Impact | Customer Impact |
|---|---|---|---|---|
| 1 | `ssl_no_http_redirect` on enterprise CDN domains | High | −5 suppressed (but finding visible) | Low (suppression works; visible finding confuses) |
| 2 | `email_dkim_not_detected` on any domain with non-standard selector | High | 0 | Low score, misleading trust signal |
| 3 | `subdomain_sensitive_*` on public-facing subdomains | High | −5 each, up to −20 | Score deduction with no real risk |
| 4 | Typosquat candidates reported as high-risk before DNS validation | Medium | 0 (Business Risk uses confirmed only) | Dashboard misleads on unvalidated candidates |
| 5 | `subdomain_takeover` false positive — shared CDN pattern | Medium | −15 to −25 | High impact if fires incorrectly |
| 6 | `cloud_storage_takeover_risk` on legitimate redirects | Medium | 0 | Incorrect severe finding in intelligence view |
| 7 | Asset exposure findings on CDN edge nodes | Medium | −5 to −10 | Score deduction; `ENTERPRISE_DOMAINS` only partially mitigates |
| 8 | `admin_surface_critical` for Jenkins on legitimate CI/CD | Low | 0 | Posture score reduction; correct but may feel aggressive |

---

## 1. SSL Redirect False Positive on Enterprise CDN (HIGH)

### Finding

`ssl_no_http_redirect` with `score_impact: −5` (or `info` with score 0 in suppressed case)

### Trigger

HTTP probe to the domain does not observe a redirect to HTTPS.

### False Positive Scenario

A domain fronted by Cloudflare, Akamai, Fastly, or AWS CloudFront may perform the HTTP→HTTPS redirect at the CDN edge. The Worker makes a direct HTTP request, which may:

1. Return a redirect (correctly suppressed), or
2. Return a direct 200 response (incorrectly flagged), or
3. Return a connection error (CDN blocks direct probing)

### Current Mitigation

`ENTERPRISE_DOMAINS` constant contains known CDN edge domains. When a domain's final HTTPS URL resolves to one of these, and the headers module confirms final HTTPS delivery, the score deduction is suppressed (finding severity drops to `info`, score_impact becomes 0).

`ENTERPRISE_BENCHMARK` list is checked to skip the redirect check for known CDN apex domains.

### Remaining Gap

The enterprise exception only fires when `headers.final_https !== false`. If the headers module also fails (e.g., timeout), both modules may fire incorrectly. Additionally, the `info`-severity finding is still present in the API response, which customers may query and misinterpret.

### Recommendation

Add a `suppression_reason` field to the finding when the enterprise CDN exception fires, so API consumers can distinguish suppressed from genuine findings.

---

## 2. DKIM Not Detected (HIGH)

### Finding

`email_dkim_not_detected` — severity: info, score_impact: 0

### Trigger

None of 6 common DKIM selectors (google, default, mail, k1, selector1, selector2) resolve to a TXT record.

### False Positive Scenario

Any organisation using:
- Proofpoint: `proofpoint`, `pm` selectors
- Mimecast: `mimecast20XXXXXX` selectors
- Barracuda: custom selectors
- Any vendor using non-standard selector names

…will receive this finding despite having DKIM configured and operational.

### Current Mitigation

Confidence is `low`. Score impact is 0. The finding is informational only.

### Remaining Gap

The finding still appears in reports and email intelligence (`email_intel_dkim_not_found` at `medium` severity). A customer reading their report will see "DKIM not found" and conclude their email security is deficient when it is not.

### Recommendation

When SPF includes contain known email security vendor patterns (Proofpoint, Mimecast, Barracuda — which are already detected in vendor_risk), suppress `email_dkim_not_detected` or change its label to "DKIM selector not verified (common selectors only)".

---

## 3. Sensitive Subdomain False Positive (HIGH)

### Finding

`subdomain_sensitive_{sub}` — severity: medium, confidence: medium, score_impact: −5 each

### Trigger

Discovered subdomain hostname matches any of 70+ entries in `SENSITIVE_LABELS`.

### False Positive Scenario

The following subdomain patterns legitimately serve public-facing content in many organisations:

- `portal.example.com` — public customer portal
- `app.example.com` — public SaaS application
- `api.example.com` — public API endpoint
- `mail.example.com` — public webmail (often Microsoft OWA or Google)
- `confluence.example.com` — may be intentionally public for documentation

All of these are in `SENSITIVE_LABELS` and will trigger `subdomain_sensitive_*` findings with a −5 score deduction each.

### Current Mitigation

Maximum of 4 findings (−20 total). Confidence is `medium`.

### Remaining Gap

Reachability is not checked at finding time. A discovered subdomain that does not resolve (e.g., a decommissioned CT log entry) still generates the finding. There is no asset lifecycle filter applied before the sensitive label check.

### Recommendation

Filter `SENSITIVE_LABELS` matches through the asset_exposure reachability data before generating findings. Only generate `subdomain_sensitive_*` for subdomains that are actively resolving.

---

## 4. Typosquat Candidates Shown Before DNS Validation (MEDIUM)

### Finding

No finding ID. Brand monitoring `domains[]` array.

### Trigger

`runTyposquatModule` generates up to 40 candidates algorithmically at scan time. DNS validation is deferred.

### False Positive Scenario

The brand monitoring dashboard (frontend: `BrandMonitoringPage`) may show a list of "high-risk" candidates that do not exist in DNS. A domain like `cyb3rmeters.com` scored as high-risk is not a real threat until DNS-confirmed.

### Current Mitigation

Business Risk Score and Security Posture use only DNS-confirmed candidates (`status = 'active'` from `workspace_brand_assets`). Scoring is correct.

### Remaining Gap

The `brand_monitoring.domains[]` array in scan JSON includes all candidates, validated or not. A customer reading raw API output or a poorly-scoped UI component could mistake unvalidated candidates for confirmed threats.

### Recommendation

The API response for brand monitoring should clearly distinguish `validated: true/false` per candidate. Frontend should only display risk_level badges after validation.

---

## 5. Subdomain Takeover False Positive — Shared CDN Patterns (MEDIUM)

### Finding

`subdomain_takeover` — severity: high, confidence: high, score_impact: −15 to −25

### Trigger

CNAME resolves to a suffix matching one of 38 `TAKEOVER_FINGERPRINTS`, AND the HTTP body matches the unclaimed service pattern.

### False Positive Scenario

Some CDN and hosting providers serve identical body patterns across claimed and unclaimed sites (e.g., a default landing page that contains the unclaimed text string but for a claimed account). Specifically:

- Fastly: `FASTLY_ERROR` appears in their generic error pages for misconfigured but claimed services
- Azure Blob Storage: generic storage pages can appear even for locked-down containers
- S3 buckets: `NoSuchBucket` XML appears only for truly absent buckets — this is low-risk for false positives

### Current Mitigation

Two-condition match required: CNAME suffix + body pattern. The body pattern is designed to match the specific "not found" / "unclaimed" error page. This significantly reduces false positives.

### Remaining Gap

No HTTP status code check is applied. A service that returns a 403 (access denied, meaning the bucket exists and is claimed) may still match the body pattern if the 403 page text contains the fingerprint pattern.

### Recommendation

Add HTTP status code to the takeover detection condition. `cloud_storage_takeover_risk` specifically should require HTTP 4xx with body match, not just body match alone.

---

## 6. Cloud Storage Takeover Risk on Legitimate Redirects (MEDIUM)

### Finding

`cloud_storage_takeover_risk` — severity: high (cname) or medium, score_impact: 0

### Trigger

CNAME points to an S3 or Azure blob hostname pattern.

### False Positive Scenario

An organisation may CNAME `assets.example.com` → `example-assets.s3.amazonaws.com` where the bucket is claimed, configured, and intentionally public. The CNAME target matches the S3 suffix pattern, triggering the finding.

### Current Mitigation

`cloud_storage_exposure_observed` (medium) fires only when the bucket is actually accessible. `cloud_storage_takeover_risk` (high) is supposed to fire only when the bucket is unclaimed — but the body match alone may be insufficient to distinguish.

### Remaining Gap

The distinction between a claimed-but-public bucket and an unclaimed bucket depends entirely on body pattern matching. If the organisation has a bucket that serves content with no `NoSuchBucket` response, the takeover finding should not fire. This logic is in `cloudStorageFindingFromCandidate()` but the implementation details need audit against each S3 region variant.

### Recommendation

Audit `cloudStorageFindingFromCandidate()` body patterns against current S3 and Azure Blob "bucket not found" response bodies. Update patterns if vendor responses have changed.

---

## 7. Asset Exposure Findings on CDN Edge Nodes (MEDIUM)

### Finding

`asset_exposure_sensitive_tool`, `asset_exposure_admin_interface`, `asset_exposure_dev_env`

### Trigger

A subdomain resolves to an IP that belongs to a CDN provider (Cloudflare, Akamai, Fastly) and the HTTP probe returns content matching an ADMIN_SURFACE_SIG or asset exposure pattern.

### False Positive Scenario

A subdomain `api.example.com` may proxy through Cloudflare to an internal API. If the Cloudflare IP serves a page whose title or content matches a signature (e.g., an error page that contains "jenkins" in the body), a false positive fires.

### Current Mitigation

`ENTERPRISE_DOMAINS` set filters known CDN domains from certain probe outcomes. `ENTERPRISE_BENCHMARK` list suppresses some checks for known large-scale CDN targets.

### Remaining Gap

The ENTERPRISE_DOMAINS and ENTERPRISE_BENCHMARK lists are manually maintained. They require periodic updates as CDN IP ranges and hostnames change. There is no automated CDN detection fallback.

### Recommendation

Add CDN IP range detection (Cloudflare: 103.21.244.0/22 and public range list; Akamai: known prefixes) to the probe result. When an asset's IP is confirmed CDN-hosted, lower the maximum confidence assignable to its exposure findings.

---

## 8. Admin Surface False Positive for Self-Hosted Production Services (LOW)

### Finding

`admin_surface_critical`, `admin_surface_high`

### Trigger

`runAdminSurfaceModule` detects services matching `ADMIN_SURFACE_SIGS` via hostname/title/server patterns.

### False Positive Scenario

- `monitoring.example.com` hosting Grafana behind Cloudflare Access (not publicly accessible)
- `jenkins.example.com` requiring SSO authentication

In these cases, the service is detected because the hostname matches the pattern, but the service is not exposed to unauthenticated attackers.

### Current Mitigation

Currently none. The module probes only reachable assets (from `asset_exposure.assets` where `reachable = true`), which means the service responded. However, responding does not indicate it is accessible without authentication.

### Remaining Gap

Authentication status of detected services is not assessed. A Jenkins instance that returns HTTP 403 from the initial probe would appear as reachable but would be incorrectly flagged.

### Assessment

This is flagged as **low** FP risk because the current finding has `score_impact: 0`. The Admin Exposure Posture category will deduct, but the customer Security Score is unaffected. However, this will become a medium-to-high FP risk if `admin_surface_critical` is promoted to score-impacting in a future phase.

### Recommendation

Before promoting admin surface findings to score-impacting, add an authentication detection step: check HTTP status code (403, 401, 302 to auth endpoint) and treat these as "detected but access-controlled" rather than "exposed."

---

## Prioritised Recommendations

Ranked by: false positive reduction value × implementation effort

1. **Filter `subdomain_sensitive_*` through reachability data** — Quick win. Join against asset_exposure results before generating findings. Eliminates false positives on decommissioned CT log entries.

2. **Suppress DKIM finding when known email security vendor is detected** — Cross-reference vendor_risk detections. If Proofpoint, Mimecast, or Barracuda is in vendor_risk, annotate `email_dkim_not_detected` as "selector not probed — vendor-specific selector required."

3. **Add `suppression_reason` to enterprise CDN exception** — Adds transparency without changing logic. Customers can distinguish suppressed from genuine findings via API.

4. **Validate brand monitoring candidates before showing risk badges in UI** — Frontend change. Only render `high`/`medium` risk badge after `dns_resolved = true`.

5. **HTTP status check in takeover detection** — Treat HTTP 403 as "access controlled, not unclaimed." Reduces false positives on private-but-reachable cloud storage.
