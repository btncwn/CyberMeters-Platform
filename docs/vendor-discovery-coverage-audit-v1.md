# Vendor Discovery Coverage Audit v1

Audit scope: read-only review of current CyberMeters vendor discovery and inference paths.

## Executive Summary

CyberMeters already has a useful passive vendor discovery foundation. The strongest current coverage comes from DNS, MX, SPF, DKIM, CNAME, CSP, HTTP server headers, technology detection, cloud hostname patterns, SaaS exposure mapping, and persisted workspace vendor inventory.

The current implementation is strongest for email providers, CDN providers, cloud/hosting providers, CRM platforms, and customer support platforms. It is weaker for standalone identity providers, payment providers, analytics providers, and deep supply chain risk attribution.

Current vendor discovery is suitable for Vendor Risk Engine v1 if it remains evidence-based and confidence-scored. Supply Chain Risk Engine v1 should treat current vendor data as a starting signal rather than a complete third-party inventory.

## Vendor Discovery Coverage Matrix

| Category | Current Detection Source | Confidence Level | Implementation Location | Data Quality | Business Usefulness |
| --- | --- | --- | --- | --- | --- |
| SaaS providers | Correlated SPF, MX, DKIM selector, CNAME, CSP, server header, and detected technology signals. Current signatures include Atlassian, HubSpot, Salesforce, Marketo, SendGrid, Mailchimp, Mailgun, Brevo, Klaviyo, Stripe, and PayPal. SaaS exposure module adds portal and tenant hints where available. | Low to high. High when three or more independent sources match; medium with two; low with one. | `workers/scan-api/src/index.js`: `VENDOR_SIGNATURES`, `detectVendorsFromModules`, `runThirdPartyDiscoveryModule`, `SAAS_EXPOSURE_SIGS`, `runSaasExposureModule`. Frontend access through `frontend/src/api.js` vendor and SaaS exposure methods. | Medium. DNS and CNAME signals are strong; CSP-only and SPF-only matches are weaker. Payment providers are detected but not currently surfaced as third-party assets. | High. Useful for customer-facing vendor inventory, executive risk, SaaS exposure, and future vendor risk scoring. |
| Email providers | SPF, MX, DKIM, CSP, and nameserver correlation. Current signatures include Microsoft 365, Google Workspace, Zoho Mail, GoDaddy Email, Proton Mail, Proofpoint, Mimecast, and Barracuda. | Medium to high. MX plus SPF/DKIM provides strong confidence. Single SPF include or DKIM selector is weaker. | `workers/scan-api/src/index.js`: DNS/email scan modules feed `detectVendorsFromModules`; email provider signatures live in `VENDOR_SIGNATURES`; SaaS exposure has email and login portal mappings. | High for primary mail platforms and email gateways. Less complete for secondary security tooling not visible in DNS. | Very high. Email and identity dependencies are critical for Cyber Essentials readiness, phishing exposure, executive risk, and supply chain criticality. |
| CDN providers | Nameserver, CNAME, server header, and technology detection. Current signatures include Cloudflare, Akamai, Fastly, and CloudFront through cloud asset patterns. | Medium to high. CNAME, nameserver, and server headers are reliable; generic technology detection is supporting evidence. | `workers/scan-api/src/index.js`: `VENDOR_SIGNATURES`, `runTechnologyModule`, `detectTech`, `CLOUD_ASSET_PATTERNS`, `runCloudStorageModule`. | High for common CDN providers. Coverage is narrower for smaller CDN and edge providers. | High. CDN dependency affects availability, security headers, TLS behavior, and attack surface routing. |
| DNS providers | Nameserver collection from DNS scan data and vendor signatures for Cloudflare, AWS, Azure, Google Cloud, DigitalOcean, GoDaddy, and Squarespace. | High when authoritative nameserver hostnames clearly identify a provider. | `workers/scan-api/src/index.js`: DNS module output feeds `detectVendorsFromModules`; provider signatures use the `ns` signal. | Medium to high. Strong for managed DNS providers with recognizable NS hostnames; incomplete for white-labeled DNS. | Medium to high. DNS provider concentration and misconfiguration risk are important supply chain inputs. |
| Hosting providers | CNAME and hostname pattern matching for GitHub Pages, GitLab Pages, Vercel, Netlify, Heroku, Render, Railway, Fly.io, Firebase, App Engine, Azure App Service, AWS App Runner, and related PaaS/serverless surfaces. | Medium to high. CNAME and service hostname matches are usually reliable. | `workers/scan-api/src/index.js`: hosting signatures in `VENDOR_SIGNATURES`; service patterns in `CLOUD_ASSET_PATTERNS`; `runCloudStorageModule`; asset exposure and takeover modules provide CNAME evidence. | High for modern PaaS and static hosting providers. Less complete for traditional hosting providers without clear DNS patterns. | High. Hosting discovery supports takeover risk, asset ownership, cloud exposure, and remediation routing. |
| Cloud providers | Nameserver, CNAME, SPF, MX, and hostname pattern matching. Current providers include AWS, Azure, Google Cloud, Firebase, and DigitalOcean. Cloud asset module detects storage, CDN, serverless, API gateway, PaaS, and frontend hosting patterns. | Medium to high. Asset-level cloud hostname matches are strong; broad provider inference from SPF/MX is weaker. | `workers/scan-api/src/index.js`: `CLOUD_ASSET_PATTERNS`, `detectCloudAsset`, `runCloudStorageModule`, cloud signatures in `VENDOR_SIGNATURES`; route `/api/workspaces/:id/cloud-assets`. Schema support in `database/migrations/004-asset-inventory.sql` via `workspace_assets.cloud_provider`. | High for public hostname-based cloud assets. Limited for private cloud resources and accounts not exposed through DNS or HTTP. | Very high. Cloud exposure is central to ASM, asset inventory, executive reporting, and future supply chain risk. |
| Identity providers | Current detection is mostly email identity and workspace suite inference through Microsoft 365, Google Workspace, Zoho, Proton, and login portal exposure. No explicit Okta, Auth0, OneLogin, Duo, Ping, JumpCloud, or SAML/OIDC provider detection was found. | Medium for email-suite identity inference; low to none for standalone identity providers. | `workers/scan-api/src/index.js`: email identity signatures in `VENDOR_SIGNATURES`; login portal metadata in `SAAS_EXPOSURE_SIGS`. | Partial. Good for mailbox-driven identity suites, weak for dedicated IAM vendors. | High potential usefulness, currently medium. Identity providers are high-criticality vendors for supply chain and access-control risk. |
| Payment providers | Stripe and PayPal are detected from CSP patterns. Third-party asset remapping currently excludes these from surfaced third-party assets. Platform-internal Stripe billing code is separate and should not be treated as customer vendor discovery. | Low to medium. CSP can show script usage but does not prove contract ownership, payment flow, or active processing. | `workers/scan-api/src/index.js`: Stripe and PayPal entries in `VENDOR_SIGNATURES`; `remapToThirdPartyCategory` currently returns `null` for those providers. | Partial. Detection exists, but surfaced inventory is intentionally incomplete. | Medium to high. Payment providers are commercially important and often handle sensitive customer data. |
| Analytics providers | No explicit analytics vendor signatures were found for Google Analytics, Google Tag Manager, Segment, Mixpanel, Amplitude, Hotjar, Plausible, Matomo, or similar platforms. Current technology detection focuses on frameworks, servers, CMSs, and selected infrastructure. | None currently. | No dedicated implementation found. Nearby future extension points are `VENDOR_SIGNATURES`, CSP/body signal collection, and technology detection helpers in `workers/scan-api/src/index.js`. | Missing. | Medium. Useful for privacy, data sharing, marketing stack, and supply chain visibility. |
| CRM providers | HubSpot, Salesforce, and Marketo are detected from SPF, CNAME, and CSP signals. Third-party remapping categorizes these as CRM. SaaS exposure mapping includes portal and tenant URL hints for Salesforce, HubSpot, and Marketo. | Medium to high depending on number and quality of matching signals. | `workers/scan-api/src/index.js`: CRM-related SaaS signatures in `VENDOR_SIGNATURES`; `remapToThirdPartyCategory`; `SAAS_EXPOSURE_SIGS`; `/api/workspaces/:id/third-party-assets`; `/api/workspaces/:id/saas-exposure`. | Medium to high. Strong when CNAME or tenant hostname exists; weaker when only SPF or CSP is present. | High. CRM providers often imply customer data exposure and should be weighted heavily in vendor risk. |
| Customer support platforms | Zendesk, Intercom, and Freshdesk are detected from SPF, CNAME, MX, and server signals. SaaS exposure mapping adds portal/admin surface hints. | Medium to high. CNAME and portal hints are strong; SPF-only matches are weaker. | `workers/scan-api/src/index.js`: support signatures in `VENDOR_SIGNATURES`; `SAAS_EXPOSURE_SIGS`; `runThirdPartyDiscoveryModule`; persisted vendor inventory through `upsertVendorInventory`. | Medium to high. Good for common support platforms, incomplete for smaller helpdesk providers. | High. Support platforms can contain customer PII and are strong supply chain risk indicators. |

## Current Vendor Inventory Persistence

CyberMeters persists correlated vendor findings to `workspace_vendors`.

Relevant schema:

- `database/migrations/008-vendor-inventory.sql`
- `workspace_vendors.vendor_name`
- `workspace_vendors.category`
- `workspace_vendors.source`
- `workspace_vendors.confidence`
- `workspace_vendors.risk_level`
- `workspace_vendors.evidence_json`
- `workspace_vendors.first_seen`
- `workspace_vendors.last_seen`
- `workspace_vendors.status`

Relevant write path:

- `workers/scan-api/src/index.js`: `upsertVendorInventory`

Relevant read APIs:

- `GET /api/workspaces/:id/vendors`
- `GET /api/workspaces/:id/vendors/summary`
- `GET /api/workspaces/:id/third-party-assets`
- `GET /api/workspaces/:id/third-party-assets/summary`
- `GET /api/workspaces/:id/saas-exposure`
- `GET /api/workspaces/:id/cloud-assets`
- `GET /api/workspaces/:id/admin-surfaces`

Relevant frontend API methods:

- `frontend/src/api.js`: `getWorkspaceVendors`
- `frontend/src/api.js`: `getWorkspaceVendorsSummary`
- `frontend/src/api.js`: `getWorkspaceThirdPartyAssets`
- `frontend/src/api.js`: `getWorkspaceSaasExposure`
- `frontend/src/api.js`: `getWorkspaceCloudAssets`
- `frontend/src/api.js`: `getWorkspaceAdminSurfaces`

## Supply Chain Readiness Score

Score: **68 / 100**

Rationale:

- Broad passive discovery already exists for DNS, email, CDN, cloud, hosting, CRM, support, and several SaaS providers.
- Vendor detections are confidence-scored and supported by evidence sources.
- Vendor inventory is persisted in D1 and exposed through workspace APIs.
- SaaS exposure and cloud asset APIs provide useful customer-facing supply chain context.
- Current taxonomy is still coarse and mixes broad SaaS, email identity, infrastructure, hosting, and support categories.
- Analytics provider detection is missing.
- Standalone identity provider detection is incomplete.
- Payment provider detection exists but is not currently surfaced in third-party asset views.
- Vendor risk is not yet enriched with business criticality, data sensitivity, contract ownership, breach intelligence, or external security posture.

Interpretation:

CyberMeters is ready for a lightweight Vendor Risk Engine v1 using existing signals. It is not yet ready to claim complete supply chain visibility without taxonomy, enrichment, and additional provider coverage.

## Quick Wins for Vendor Risk Engine v1

1. Normalize vendor categories into a more business-friendly taxonomy: `email`, `identity`, `cdn`, `dns`, `hosting`, `cloud`, `crm`, `support`, `payments`, `analytics`, `marketing`, `collaboration`, and `ecommerce`.

2. Surface payment providers instead of dropping Stripe and PayPal during third-party asset remapping. Use a `payments` category and keep confidence tied to CSP evidence.

3. Add explicit analytics provider signatures for Google Analytics, Google Tag Manager, Segment, Mixpanel, Amplitude, Hotjar, Plausible, and Matomo using CSP, script, and page body evidence.

4. Add standalone identity provider signatures for Okta, Auth0, OneLogin, Duo, Ping Identity, JumpCloud, and similar providers using CNAME, CSP, and login portal hostnames where already observable.

5. Weight evidence sources by reliability:
   - High: MX, NS, CNAME, tenant hostname.
   - Medium: CSP, server header, technology detection.
   - Low: SPF include, DKIM selector, generic body match.

6. Add a static vendor metadata map for v1 with fields such as `business_function`, `criticality`, `likely_data_access`, `external_login`, and `default_risk_weight`.

7. Add regression fixtures for vendor detection so signature changes do not silently reduce coverage.

8. Persist SaaS exposure summary fields where useful, while keeping raw scan evidence in R2.

## Quick Wins for Supply Chain Risk Engine v1

1. Create a supply chain risk score using existing signals:
   - vendor category
   - confidence
   - external portal exposure
   - admin surface exposure
   - cloud asset exposure
   - payment, CRM, support, and email criticality

2. Add critical vendor classification:
   - Email and identity providers
   - Cloud and hosting providers
   - Payment providers
   - CRM providers
   - Customer support providers

3. Add exposure multipliers:
   - Public SaaS login portal discovered
   - Admin surface discovered
   - Cloud storage or serverless asset discovered
   - Vendor tied to high or critical findings

4. Add vendor change detection:
   - new vendor discovered
   - vendor inactive
   - vendor category changed
   - critical vendor newly exposed

5. Add concentration indicators:
   - single cloud provider dependency
   - single CDN dependency
   - single email provider dependency
   - multiple customer-data platforms exposed

6. Add executive reporting language:
   - critical third parties observed
   - high-confidence external platforms
   - customer-data platforms
   - internet-exposed vendor portals
   - newly discovered vendors

7. Keep Supply Chain Risk Engine v1 evidence-based. Do not claim vendor compliance status, breach status, contract ownership, or data processing status unless those signals are explicitly collected later.

## Remaining Gaps

- No external vendor enrichment.
- No breach or reputation intelligence.
- No contract, DPA, or ownership data.
- No analytics provider coverage.
- Limited standalone identity provider coverage.
- Payment providers are detected but not surfaced as third-party assets.
- Vendor risk levels are static and not yet calibrated against observed exposure severity.
- Current discovery is domain and public-asset centric, so private SaaS usage cannot be inferred reliably.

## Recommendation

Proceed with Vendor Risk Engine v1 using the current vendor discovery foundation, but keep the product language precise:

- Say "observed vendors" or "inferred vendors."
- Keep confidence visible.
- Distinguish high-confidence DNS/CNAME/MX evidence from lower-confidence CSP/SPF evidence.
- Avoid claiming full supply chain inventory.

Supply Chain Risk Engine v1 should follow after vendor taxonomy, payment and analytics surfacing, standalone identity provider signatures, and vendor criticality metadata are added.
