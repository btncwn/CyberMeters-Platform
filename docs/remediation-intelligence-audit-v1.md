# CyberMeters — Remediation Intelligence Audit v1

**Sprint 11B — Remediation Intelligence**
**Date:** June 2026
**Status:** Audit complete — implementation follows

---

## Scope

This audit covers every finding ID emitted by the Worker. For each finding, we assign:
- `remediation_priority` — P1 through P4
- `remediation_owner` — which team owns the fix
- `estimated_effort` — wall-clock time for a competent engineer
- `business_impact` — board-language consequence of leaving unfixed
- `verification_command` — the concrete command to confirm the fix

No code changes are made in this phase.

---

## Priority Framework

| Priority | Criteria | SLA |
|----------|---------|-----|
| P1 | Active risk: data exposure, domain impersonation, confirmed takeover, expired cert | 24 hours |
| P2 | Weakened defence: policy gaps, missing enforcement headers, degraded authentication | 7 days |
| P3 | Informational risk: candidates, low-confidence findings, hygiene improvements | 30 days |
| P4 | Advisory: informational, best-practice, no active exploitation risk | 90 days |

---

## Owner Framework

| Module / Category | Remediation Owner |
|------------------|-----------------|
| Email Security | Email Team |
| DNS | DNS / Infrastructure Team |
| SSL/TLS | Infrastructure Team |
| Security Headers | Web Team |
| Subdomain Takeover | Cloud Team |
| Cloud Storage | Cloud Platform Team |
| Identity Discovery | IAM Team |
| Admin Surfaces | Infrastructure Team |
| Vendor / Supply Chain | Procurement + Security |
| SaaS Exposure | IT Operations |
| WHOIS / Domain | Legal / Domain Admin |
| Technology Disclosure | Web Team |

---

## Assumptions

1. `estimated_effort` assumes the engineer already has access to the relevant DNS provider, hosting console, or server. Procurement of access adds time not reflected here.
2. `business_impact` is written for board-level briefing — not technical. The goal is to communicate consequence, not mechanism.
3. Where the Worker emits a severity of `info` for what is conceptually a medium risk (e.g. DNSSEC), the remediation priority reflects the actual security impact, not the scan severity.
4. Verification commands assume a Unix/macOS terminal with standard tools (`dig`, `curl`, `nslookup`, `openssl`).
5. Dynamic finding IDs (`header_missing_*`, `subdomain_sensitive_*`) use the pattern's base prefix.

---

## Finding Inventory with Remediation Intelligence

### Email Security — Core Module

---

#### `email_missing_spf`

| Field | Value |
|-------|-------|
| Module | `email_security` |
| Severity | high |
| Confidence | high |
| Score Impact | -10 pts |
| Current Recommendation | "Publish an SPF record in DNS specifying which mail servers are authorised to send email on your behalf." |
| Evidence Availability | DNS TXT lookup — high quality |
| **Remediation Priority** | **P1** |
| **Owner** | **Email Team** |
| **Effort** | **30 minutes** |
| **Business Impact** | **Any attacker can send email appearing to come from your domain. Enables phishing, BEC, and reputational damage with no technical barrier.** |
| **Verification Command** | `dig TXT example.com +short \| grep "v=spf1"` |

---

#### `email_missing_dmarc`

| Field | Value |
|-------|-------|
| Module | `email_security` |
| Severity | high |
| Confidence | high |
| Score Impact | -15 pts |
| Current Recommendation | "Publish a DMARC record at p=reject to block unauthorised use of your domain in email." |
| Evidence Availability | DNS TXT lookup — high quality |
| **Remediation Priority** | **P1** |
| **Owner** | **Email Team** |
| **Effort** | **45 minutes (including 30-day monitoring window before enforcement)** |
| **Business Impact** | **Domain can be impersonated in email with zero enforcement. Customers, partners, and staff can receive convincing phishing emails from your domain.** |
| **Verification Command** | `dig TXT _dmarc.example.com +short` |

---

#### `email_dmarc_policy_none`

| Field | Value |
|-------|-------|
| Module | `email_security` |
| Severity | medium |
| Confidence | high |
| Score Impact | -5 pts |
| Current Recommendation | "Upgrade your DMARC policy from p=none to p=quarantine or p=reject." |
| Evidence Availability | DNS TXT with parsed policy — high quality |
| **Remediation Priority** | **P2** |
| **Owner** | **Email Team** |
| **Effort** | **15 minutes change + 30-day monitoring window** |
| **Business Impact** | **DMARC is configured for visibility only. Spoofed emails are not blocked. The record provides reporting but no protection.** |
| **Verification Command** | `dig TXT _dmarc.example.com +short` |

---

#### `email_dkim_not_detected`

| Field | Value |
|-------|-------|
| Module | `email_security` |
| Severity | info (medium in practice) |
| Confidence | low (selector not known) |
| Score Impact | 0 pts |
| Current Recommendation | "Configure DKIM signing for all outbound email streams and publish the public key in DNS." |
| Evidence Availability | DNS probe on common selectors — low quality (unknown selector) |
| **Remediation Priority** | **P3** |
| **Owner** | **Email Team** |
| **Effort** | **1 hour (requires coordination with email platform admin)** |
| **Business Impact** | **Without DKIM, SPF→DMARC alignment may fail for forwarded email, reducing effective DMARC coverage. Also prevents proof of message integrity.** |
| **Verification Command** | `dig TXT google._domainkey.example.com +short` |

---

### Email Security Intelligence Module

---

#### `email_intel_spf_missing`

| Field | Value |
|-------|-------|
| Module | `email_security_intelligence` |
| Severity | high |
| Current Recommendation | "Publish an SPF TXT record listing all services that send email for this domain. End with -all to reject unauthorised senders." |
| Evidence Availability | DNS lookup — high quality |
| **Remediation Priority** | **P1** |
| **Owner** | **Email Team** |
| **Effort** | **30 minutes** |
| **Business Impact** | Same as `email_missing_spf` — domain spoofing enabled. |
| **Verification Command** | `dig TXT example.com +short \| grep "v=spf1"` |

---

#### `email_intel_spf_permissive`

| Field | Value |
|-------|-------|
| Module | `email_security_intelligence` |
| Severity | high |
| Current Recommendation | "Remove +all and replace with -all after listing all legitimate sending sources explicitly." |
| Evidence Availability | DNS TXT value parsed — high quality |
| **Remediation Priority** | **P2** |
| **Owner** | **Email Team** |
| **Effort** | **30 minutes** |
| **Business Impact** | **SPF exists but does not reject unauthorised senders. The ~all or ?all mechanism allows spoofed email to reach inboxes.** |
| **Verification Command** | `dig TXT example.com +short \| grep "v=spf1"` |

---

#### `email_intel_dmarc_missing`

| Field | Value |
|-------|-------|
| Module | `email_security_intelligence` |
| Severity | high |
| Current Recommendation | "Publish a DMARC TXT record. Start with p=none to collect aggregate reports (rua=), then graduate to p=quarantine and p=reject." |
| **Remediation Priority** | **P1** |
| **Owner** | **Email Team** |
| **Effort** | **45 minutes** |
| **Business Impact** | Same as `email_missing_dmarc`. |
| **Verification Command** | `dig TXT _dmarc.example.com +short` |

---

#### `email_intel_dmarc_reporting_only`

| Field | Value |
|-------|-------|
| Module | `email_security_intelligence` |
| Severity | medium |
| Current Recommendation | "Review DMARC aggregate reports and migrate to p=quarantine, then p=reject once all email sources are validated." |
| **Remediation Priority** | **P2** |
| **Owner** | **Email Team** |
| **Effort** | **15 minutes change + monitoring** |
| **Business Impact** | Same as `email_dmarc_policy_none`. |
| **Verification Command** | `dig TXT _dmarc.example.com +short` |

---

#### `email_intel_dkim_not_found`

| Field | Value |
|-------|-------|
| Module | `email_security_intelligence` |
| Severity | medium |
| Current Recommendation | "Configure DKIM signing with your email service provider and publish the DKIM public key as a TXT record at <selector>._domainkey.<domain>." |
| **Remediation Priority** | **P3** |
| **Owner** | **Email Team** |
| **Effort** | **1 hour** |
| **Business Impact** | Same as `email_dkim_not_detected`. |
| **Verification Command** | `dig TXT google._domainkey.example.com +short` |

---

#### `email_intel_mta_sts_missing`

| Field | Value |
|-------|-------|
| Module | `email_security_intelligence` |
| Severity | low |
| Current Recommendation | "Publish an MTA-STS policy file and a supporting _mta-sts.<domain> DNS TXT record once SPF, DKIM, and DMARC are fully deployed." |
| **Remediation Priority** | **P4** |
| **Owner** | **Email Team** |
| **Effort** | **1–2 hours** |
| **Business Impact** | **Without MTA-STS, inbound email transport between mail servers can be downgraded from TLS. Low risk for most organisations unless handling sensitive regulated data.** |
| **Verification Command** | `dig TXT _mta-sts.example.com +short` |

---

#### `email_intel_tls_rpt_missing`

| Field | Value |
|-------|-------|
| Module | `email_security_intelligence` |
| Severity | low |
| Current Recommendation | "Add a TLS-RPT TXT record at _smtp._tls.<domain>: v=TLSRPTv1; rua=mailto:<address>" |
| **Remediation Priority** | **P4** |
| **Owner** | **Email Team** |
| **Effort** | **15 minutes** |
| **Business Impact** | **Informational — TLS-RPT provides reporting on TLS failures in transit. No active exploit risk.** |
| **Verification Command** | `dig TXT _smtp._tls.example.com +short` |

---

### Security Headers Module

---

#### `header_missing_strict_transport_security`

| Field | Value |
|-------|-------|
| Module | `headers` |
| Severity | high |
| Current Recommendation | "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" |
| Evidence Availability | HTTP response header probe — high quality |
| **Remediation Priority** | **P2** |
| **Owner** | **Web Team** |
| **Effort** | **30 minutes** |
| **Business Impact** | **Users connecting over HTTP before the first redirect can be SSL-stripped by an on-path attacker, exposing session tokens and credentials.** |
| **Verification Command** | `curl -sI https://example.com \| grep -i strict-transport` |

---

#### `header_weak_hsts` / `dse_hsts_short_maxage`

| Field | Value |
|-------|-------|
| Module | `headers` / `domain_security_enrichment` |
| Severity | medium / low |
| **Remediation Priority** | **P2** |
| **Owner** | **Web Team** |
| **Effort** | **15 minutes** |
| **Business Impact** | **HSTS is present but with an insufficient max-age, reducing the protection window. Browsers will not remember the HTTPS preference as long.** |
| **Verification Command** | `curl -sI https://example.com \| grep -i strict-transport` |

---

#### `header_missing_content_security_policy`

| Field | Value |
|-------|-------|
| Module | `headers` |
| Severity | medium |
| Current Recommendation | "Add a Content-Security-Policy header to restrict which resources the browser may load." |
| Evidence Availability | HTTP response header probe — high quality |
| **Remediation Priority** | **P2** |
| **Owner** | **Web Team** |
| **Effort** | **2–4 hours (policy design) + 30 minutes (deployment)** |
| **Business Impact** | **Without CSP, successful XSS attacks have full browser execution scope. Credentials, session tokens, and page content can be exfiltrated.** |
| **Verification Command** | `curl -sI https://example.com \| grep -i content-security-policy` |

---

#### `csp_weak_policy`

| Field | Value |
|-------|-------|
| Module | `headers` |
| Severity | medium |
| **Remediation Priority** | **P2** |
| **Owner** | **Web Team** |
| **Effort** | **1–2 hours** |
| **Business Impact** | **CSP is present but includes unsafe-inline or wildcard directives that defeat XSS protection. The header provides false assurance.** |
| **Verification Command** | `curl -sI https://example.com \| grep -i content-security-policy` |

---

#### `header_missing_x_frame_options`

| Field | Value |
|-------|-------|
| Module | `headers` |
| Severity | medium |
| **Remediation Priority** | **P3** |
| **Owner** | **Web Team** |
| **Effort** | **15 minutes** |
| **Business Impact** | **Pages can be embedded in iframes by third-party sites, enabling clickjacking attacks that trick users into unintended actions.** |
| **Verification Command** | `curl -sI https://example.com \| grep -i x-frame-options` |

---

#### `header_missing_x_content_type_options`

| Field | Value |
|-------|-------|
| Module | `headers` |
| Severity | low |
| **Remediation Priority** | **P3** |
| **Owner** | **Web Team** |
| **Effort** | **15 minutes** |
| **Business Impact** | **Browsers may interpret response content as a different MIME type, enabling content sniffing attacks in some scenarios.** |
| **Verification Command** | `curl -sI https://example.com \| grep -i x-content-type-options` |

---

#### `header_missing_referrer_policy` / `header_missing_permissions_policy`

| Field | Value |
|-------|-------|
| Module | `headers` |
| Severity | low |
| **Remediation Priority** | **P4** |
| **Owner** | **Web Team** |
| **Effort** | **15 minutes** |
| **Business Impact** | **Privacy and feature control hygiene. Low active exploit risk.** |
| **Verification Command** | `curl -sI https://example.com \| grep -i referrer-policy` |

---

### DNS Module

---

#### `dnssec_not_enabled`

| Field | Value |
|-------|-------|
| Module | `dns` |
| Severity | info (medium risk in practice) |
| **Remediation Priority** | **P2** |
| **Owner** | **DNS / Infrastructure Team** |
| **Effort** | **1–2 hours** |
| **Business Impact** | **DNS responses for this domain can be forged by attackers (cache poisoning), redirecting users and email to malicious infrastructure.** |
| **Verification Command** | `dig +dnssec A example.com \| grep -i "ad\|rrsig"` |

---

#### `dnssec_misconfigured`

| Field | Value |
|-------|-------|
| Module | `dns` |
| Severity | info (high risk in practice) |
| **Remediation Priority** | **P2** |
| **Owner** | **DNS / Infrastructure Team** |
| **Effort** | **1 hour** |
| **Business Impact** | **DNSSEC is enabled but the chain of trust is broken. This causes validation failures and may result in domains being treated as untrustworthy by DNSSEC-validating resolvers.** |
| **Verification Command** | `dig DS example.com +short && dig DNSKEY example.com +short` |

---

#### `dns_no_resolution`

| Field | Value |
|-------|-------|
| Module | `dns` |
| Severity | critical |
| **Remediation Priority** | **P1** |
| **Owner** | **DNS / Infrastructure Team** |
| **Effort** | **1 hour** |
| **Business Impact** | **Domain is not resolving. All services (web, email, APIs) are unavailable. May indicate DNS zone deletion, expired domain, or registrar issue.** |
| **Verification Command** | `dig A example.com` |

---

### SSL / TLS Module

---

#### `ssl_certificate_expired`

| Field | Value |
|-------|-------|
| Module | `ssl` |
| Severity | critical |
| Current Recommendation | "Renew your SSL certificate immediately and configure automated renewal to prevent future lapses." |
| **Remediation Priority** | **P1** |
| **Owner** | **Infrastructure Team** |
| **Effort** | **30 minutes** |
| **Business Impact** | **All users receive browser security warnings and most will leave. HTTPS connections may fail entirely for API clients. Revenue and reputation impact immediate.** |
| **Verification Command** | `echo \| openssl s_client -connect example.com:443 2>/dev/null \| openssl x509 -noout -dates` |

---

#### `ssl_certificate_expiring_soon`

| Field | Value |
|-------|-------|
| Module | `ssl` |
| Severity | medium |
| Current Recommendation | "Renew your SSL certificate before the expiry date to prevent service disruption." |
| **Remediation Priority** | **P1** (treat as P1 given consequence of missing it) |
| **Owner** | **Infrastructure Team** |
| **Effort** | **30 minutes** |
| **Business Impact** | **Certificate will expire, causing immediate P1 impact. Renewal now costs 30 minutes; ignoring it costs hours of incident response.** |
| **Verification Command** | `echo \| openssl s_client -connect example.com:443 2>/dev/null \| openssl x509 -noout -dates` |

---

#### `ssl_not_available` / `ssl_no_certificate`

| Field | Value |
|-------|-------|
| Module | `ssl` |
| Severity | critical |
| **Remediation Priority** | **P1** |
| **Owner** | **Infrastructure Team** |
| **Effort** | **1–2 hours** |
| **Business Impact** | **No HTTPS available. All traffic is unencrypted. Login credentials, session tokens, and sensitive data transmitted in plaintext. Modern browsers block interaction.** |
| **Verification Command** | `curl -I https://example.com` |

---

#### `ssl_no_http_redirect` / `no_https_redirect`

| Field | Value |
|-------|-------|
| Module | `ssl` |
| Severity | medium |
| **Remediation Priority** | **P3** |
| **Owner** | **Infrastructure Team** |
| **Effort** | **30 minutes** |
| **Business Impact** | **Users who visit the HTTP URL are not redirected to HTTPS and may submit data over unencrypted connections.** |
| **Verification Command** | `curl -I http://example.com \| grep -i location` |

---

### Subdomain Takeover Module

---

#### `subdomain_takeover`

| Field | Value |
|-------|-------|
| Module | `subdomain_takeover` |
| Severity | high |
| Confidence | high (dual signal: CNAME fingerprint + body match) |
| Score Impact | -15 to -25 pts |
| **Remediation Priority** | **P1** |
| **Owner** | **Cloud Team** |
| **Effort** | **30 minutes (DNS record removal or service reclaim)** |
| **Business Impact** | **Attacker can serve content under your trusted domain. Phishing, credential harvesting, cookie theft, malware distribution — all under your brand, with a valid TLS certificate.** |
| **Verification Command** | `dig CNAME affected.example.com && curl -sI https://affected.example.com \| head -5` |

---

#### `subdomain_takeover_risk`

| Field | Value |
|-------|-------|
| Module | `subdomain_takeover` |
| Severity | medium (candidate — not confirmed) |
| Confidence | medium |
| **Remediation Priority** | **P2** |
| **Owner** | **Cloud Team** |
| **Effort** | **30 minutes** |
| **Business Impact** | **Dangling DNS record pointing to an unclaimed resource. Risk of takeover if an attacker registers the target service before this is remediated.** |
| **Verification Command** | `dig CNAME affected.example.com` |

---

### Cloud Storage Module

---

#### `cloud_storage_exposure_observed` / `cloud_storage_public_listing`

| Field | Value |
|-------|-------|
| Module | `cloud_storage_discovery` |
| Severity | high (exposure_observed) / high (public_listing) |
| **Remediation Priority** | **P1** |
| **Owner** | **Cloud Platform Team** |
| **Effort** | **30 minutes** |
| **Business Impact** | **Customer data, credentials, backups, or internal documents publicly accessible to the internet without authentication. Regulatory notification obligations may apply (GDPR, HIPAA, PCI-DSS).** |
| **Verification Command** | `curl -I https://BUCKET.s3.amazonaws.com/ \| grep -E "HTTP|ListBucketResult"` |

---

#### `cloud_storage_takeover_risk`

| Field | Value |
|-------|-------|
| Module | `cloud_storage_discovery` |
| Severity | high |
| **Remediation Priority** | **P1** |
| **Owner** | **Cloud Platform Team** |
| **Effort** | **30 minutes** |
| **Business Impact** | **Unclaimed storage bucket referenced in DNS. Attacker can register the bucket and serve malicious content from your domain.** |
| **Verification Command** | `dig CNAME bucket.example.com` |

---

### Admin Surface / Asset Exposure Module

---

#### `admin_surface_critical`

| Field | Value |
|-------|-------|
| Module | `admin_surface_detection` |
| Severity | critical |
| **Remediation Priority** | **P1** |
| **Owner** | **Infrastructure Team** |
| **Effort** | **1 hour (firewall rule or VPN enforcement)** |
| **Business Impact** | **Administrative interfaces (build servers, databases, Kubernetes dashboards) exposed to the internet. One compromised credential = full infrastructure access.** |
| **Verification Command** | `curl -I https://admin.example.com` (should return 403 or connection refused from external IP) |

---

#### `admin_surface_high` / `admin_surface_medium`

| Field | Value |
|-------|-------|
| Module | `admin_surface_detection` |
| Severity | high / medium |
| **Remediation Priority** | **P2** |
| **Owner** | **Infrastructure Team** |
| **Effort** | **2–4 hours** |
| **Business Impact** | **Management interfaces exposed but with some access control (login required). Attack surface exists; requires MFA enforcement and patch review.** |
| **Verification Command** | Manual verification — check MFA enforcement and current patch level |

---

### Identity Discovery Module

---

#### `identity_microsoft_365_detected`

| Field | Value |
|-------|-------|
| Module | `identity_discovery` |
| Severity | info |
| **Remediation Priority** | **P3** |
| **Owner** | **IAM Team** |
| **Effort** | **2–4 hours (Conditional Access policy review)** |
| **Business Impact** | **M365 presence confirms the identity attack surface. Password spraying and BEC campaigns are likely being attempted. MFA enforcement and legacy auth blocking are critical mitigations.** |
| **Verification Command** | Azure AD admin: Conditional Access policies → verify legacy auth block is active |

---

### Domain Security Enrichment Module

---

#### `dse_missing_caa`

| Field | Value |
|-------|-------|
| Module | `domain_security_enrichment` |
| Severity | medium |
| **Remediation Priority** | **P3** |
| **Owner** | **DNS / Infrastructure Team** |
| **Effort** | **15 minutes** |
| **Business Impact** | **Any Certificate Authority can issue certificates for your domain. CAA records restrict issuance to approved CAs only.** |
| **Verification Command** | `dig CAA example.com +short` |

---

#### `dse_cookie_no_secure` / `dse_cookie_no_httponly`

| Field | Value |
|-------|-------|
| Module | `domain_security_enrichment` |
| Severity | medium |
| **Remediation Priority** | **P3** |
| **Owner** | **Web Team** |
| **Effort** | **1–2 hours (requires application-level change)** |
| **Business Impact** | **Session cookies without Secure flag can be transmitted over HTTP. Without HttpOnly, they are accessible to JavaScript, enabling cookie theft via XSS.** |
| **Verification Command** | `curl -sI https://example.com \| grep -i set-cookie` |

---

### WHOIS Intelligence Module

---

#### `whois_domain_expired` / `whois_expiry_critical`

| Field | Value |
|-------|-------|
| Module | `whois_intelligence` |
| Severity | high / critical |
| **Remediation Priority** | **P1** |
| **Owner** | **Legal / Domain Admin** |
| **Effort** | **30 minutes (registrar login + renewal)** |
| **Business Impact** | **Domain is expired or expiring within days. Services will become unreachable. An attacker can register an expired domain and inherit all associated trust.** |
| **Verification Command** | Check registrar control panel; `whois example.com \| grep -i expir` |

---

#### `whois_expiry_warning`

| Field | Value |
|-------|-------|
| Module | `whois_intelligence` |
| Severity | medium |
| **Remediation Priority** | **P2** |
| **Owner** | **Legal / Domain Admin** |
| **Effort** | **30 minutes** |
| **Business Impact** | **Domain expires within 90 days. Enable auto-renew now to prevent operational disruption.** |
| **Verification Command** | `whois example.com \| grep -i expir` |

---

### Technology Detection Module

---

#### `tech_server_version_disclosure` / `tech_xpoweredby_version_disclosure`

| Field | Value |
|-------|-------|
| Module | `technology_detection` |
| Severity | low |
| **Remediation Priority** | **P4** |
| **Owner** | **Web Team** |
| **Effort** | **15 minutes** |
| **Business Impact** | **Version disclosure allows attackers to fingerprint software and look up known CVEs without sending a probe. Low-cost reconnaissance.** |
| **Verification Command** | `curl -sI https://example.com \| grep -i "server:\|x-powered-by"` |

---

## Summary Coverage

| Priority | Finding Count | Examples |
|----------|-------------|---------|
| P1 | 12 | email_missing_spf, email_missing_dmarc, subdomain_takeover, ssl_certificate_expired, cloud_storage_exposure_observed, admin_surface_critical, dns_no_resolution, whois_domain_expired |
| P2 | 14 | email_dmarc_policy_none, dnssec_not_enabled, header_missing_hsts, header_missing_csp, csp_weak_policy, email_intel_spf_permissive, admin_surface_high, subdomain_takeover_risk, whois_expiry_warning |
| P3 | 10 | email_dkim_not_detected, header_missing_x_frame_options, identity_microsoft_365_detected, dse_missing_caa, ssl_no_http_redirect, dse_cookie_no_secure |
| P4 | 6 | email_intel_mta_sts_missing, email_intel_tls_rpt_missing, header_missing_referrer_policy, tech_server_version_disclosure, dse_hsts_not_preload_eligible, whois_registrar_info |
| **Total** | **42** | |

---

## Implementation Plan (Sprint 11B)

The audit output above directly informs `buildRemediationIntelligence(finding)` in `frontend/src/data/remediation.js`. The function takes a finding object and returns a deterministic remediation intelligence block — no AI, no LLM, same finding = same output.

The 13 priority findings specified in the sprint receive full remediation step arrays. All other findings receive `priority`, `owner`, `effort`, and `business_impact` fields only.

**Files to create/modify:**
- `frontend/src/data/remediation.js` — new file, deterministic helper (no Worker changes)
- `frontend/src/pages/ScanDetail.jsx` — render remediation block in `FindingRow` (additive only)

**No changes to:**
- Worker / scanner modules
- Scoring or confidence
- Evidence framework
- PDF generation
- Authentication
- Billing
- Any API
