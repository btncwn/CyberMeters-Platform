/**
 * CyberMeters Remediation Intelligence v1
 *
 * Deterministic remediation helper for scan findings.
 * No AI. No LLM. Same finding → same output.
 *
 * buildRemediationIntelligence(finding) returns:
 * {
 *   priority:        'P1' | 'P2' | 'P3' | 'P4' | null
 *   owner:           string
 *   effort:          string
 *   business_impact: string
 *   steps:           string[]   (populated for 13 high-value findings)
 *   verification:    string     (CLI command)
 * }
 *
 * Returns null if the finding ID is not in the library and cannot be
 * matched via prefix or module fallback. The UI renders nothing in
 * that case — no broken placeholders.
 */

// ── Priority Framework ────────────────────────────────────────────────────────

export const PRIORITY_LABELS = {
  P1: { label: 'P1 — Critical',  color: 'text-red-600',    bg: 'bg-red-50 border-red-100',    dot: 'bg-red-500'    },
  P2: { label: 'P2 — High',      color: 'text-orange-600', bg: 'bg-orange-50 border-orange-100', dot: 'bg-orange-500' },
  P3: { label: 'P3 — Medium',    color: 'text-amber-600',  bg: 'bg-amber-50 border-amber-100',   dot: 'bg-amber-500'  },
  P4: { label: 'P4 — Advisory',  color: 'text-gray-500',   bg: 'bg-gray-50 border-gray-200',     dot: 'bg-gray-400'   },
}

export const PRIORITY_SLA = {
  P1: '24 hours',
  P2: '7 days',
  P3: '30 days',
  P4: '90 days',
}

// ── Owner Framework ───────────────────────────────────────────────────────────

const MODULE_OWNER = {
  email_security:              'Email Team',
  email_security_intelligence: 'Email Team',
  headers:                     'Web Team',
  dns:                         'DNS Team',
  ssl:                         'Infrastructure Team',
  subdomain_takeover:          'Cloud Team',
  cloud_storage_discovery:     'Cloud Platform Team',
  admin_surface_detection:     'Infrastructure Team',
  identity_discovery:          'IAM Team',
  domain_security_enrichment:  'Web Team',
  technology_detection:        'Web Team',
  whois_intelligence:          'Domain Admin',
  vendor_risk:                 'Procurement + Security',
  saas_exposure_analysis:      'IT Operations',
}

// ── Full Remediation Library (13 priority findings + all others) ──────────────

const LIBRARY = {

  // ── EMAIL SECURITY ──────────────────────────────────────────────────────────

  email_missing_spf: {
    priority:        'P1',
    owner:           'Email Team',
    effort:          '30 minutes',
    business_impact: 'Anyone can send email appearing to come from your domain, enabling phishing, business email compromise, and reputational damage with no technical barrier.',
    steps: [
      'Log in to your DNS provider (Cloudflare, Route 53, GoDaddy, etc.).',
      'Identify all services that send email on your behalf: your email platform (Google Workspace, Microsoft 365), CRM, marketing tools, ticketing systems.',
      'Add a TXT record at the root domain with value: v=spf1 include:<provider> -all',
      'Example for Google Workspace: v=spf1 include:_spf.google.com -all',
      'Example for Microsoft 365: v=spf1 include:spf.protection.outlook.com -all',
      'If using multiple senders: v=spf1 include:_spf.google.com include:sendgrid.net -all',
      'Use -all (hard fail), not ~all (soft fail). Soft fail does not reject spoofed email.',
      'Verify DNS propagation within 24 hours and re-scan in CyberMeters.',
    ],
    verification: 'dig TXT example.com +short | grep "v=spf1"',
  },

  email_missing_dmarc: {
    priority:        'P1',
    owner:           'Email Team',
    effort:          '45 minutes + 30-day monitoring window',
    business_impact: 'Your domain can be impersonated in email with no enforcement. Customers, partners, and staff can receive convincing phishing emails appearing to come from your organisation.',
    steps: [
      'Confirm SPF and DKIM are configured before deploying DMARC.',
      'Add a TXT record at _dmarc.yourdomain.com',
      'Start with p=none to collect data: v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com; fo=1',
      'Monitor aggregate reports (rua) for 30 days to identify all legitimate email sources.',
      'Once all senders are confirmed in SPF/DKIM, advance to p=quarantine: v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@yourdomain.com',
      'After another 7–14 days with no legitimate mail being quarantined, advance to p=reject: v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@yourdomain.com; sp=reject',
      'Add sp=reject to protect subdomains as well.',
    ],
    verification: 'dig TXT _dmarc.example.com +short',
  },

  email_dmarc_policy_none: {
    priority:        'P2',
    owner:           'Email Team',
    effort:          '15 minutes change + monitoring period',
    business_impact: 'DMARC is configured for visibility only. Spoofed emails using your domain are not blocked or quarantined. The record provides reporting but zero protection.',
    steps: [
      'Review your DMARC aggregate reports (rua address) to confirm all legitimate senders are passing SPF or DKIM alignment.',
      'If reports show no unexpected failures, advance to p=quarantine: change p=none to p=quarantine',
      'Full record: v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@yourdomain.com',
      'Monitor for 7–14 days. If no legitimate mail is quarantined, advance to p=reject.',
      'Final record: v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@yourdomain.com; sp=reject',
      'Do not remain at p=none — it is a starting point, not a destination.',
    ],
    verification: 'dig TXT _dmarc.example.com +short',
  },

  email_intel_dmarc_reporting_only: {
    priority:        'P2',
    owner:           'Email Team',
    effort:          '15 minutes change + monitoring period',
    business_impact: 'DMARC is configured for monitoring only. Domain impersonation via email is not being blocked.',
    steps: [
      'Review DMARC aggregate reports for 30 days to identify all legitimate sending sources.',
      'Confirm all legitimate senders are passing SPF or DKIM alignment.',
      'Update the DMARC record: change p=none to p=quarantine.',
      'After 7–14 days with no legitimate mail affected, advance to p=reject.',
    ],
    verification: 'dig TXT _dmarc.example.com +short',
  },

  email_dkim_not_detected: {
    priority:        'P3',
    owner:           'Email Team',
    effort:          '15 minutes to verify',
    business_impact: 'DKIM could not be verified using common selectors. A custom selector may be in use, so this observation does not confirm that DKIM is absent.',
    steps: [
      'Check the email platform admin console for the active DKIM selector.',
      'Query the exact TXT record at <selector>._domainkey.yourdomain.com.',
      'Send a test email to Gmail or Outlook and check the Authentication-Results header to confirm dkim=pass.',
      'Only configure or change DKIM if provider checks confirm that signing is not enabled.',
    ],
    verification: 'dig TXT <selector>._domainkey.example.com +short',
  },

  // email_intel_spf_missing → same steps as email_missing_spf
  email_intel_spf_missing: {
    priority:        'P1',
    owner:           'Email Team',
    effort:          '30 minutes',
    business_impact: 'Anyone can send email appearing to come from your domain, enabling phishing and business email compromise.',
    steps: [
      'Add a TXT record at the root domain with value: v=spf1 include:<your-email-provider> -all',
      'For Google Workspace: v=spf1 include:_spf.google.com -all',
      'For Microsoft 365: v=spf1 include:spf.protection.outlook.com -all',
      'Use -all (hard fail) to reject unauthorised senders.',
    ],
    verification: 'dig TXT example.com +short | grep "v=spf1"',
  },

  email_intel_spf_permissive: {
    priority:        'P2',
    owner:           'Email Team',
    effort:          '30 minutes',
    business_impact: 'SPF record exists but uses ~all (soft fail) or ?all (neutral), meaning unauthorised senders are not rejected. Spoofed email may reach inboxes.',
    steps: [
      'Review your current SPF record: dig TXT yourdomain.com +short | grep spf1',
      'Identify the current ending mechanism (~all, ?all, or +all).',
      'Replace the ending with -all (hard fail): v=spf1 include:_spf.google.com -all',
      'Verify all legitimate sending services are included in the SPF record before making this change — legitimate email from unlisted sources will be rejected.',
    ],
    verification: 'dig TXT example.com +short | grep "v=spf1"',
  },

  email_intel_dmarc_missing: {
    priority:        'P1',
    owner:           'Email Team',
    effort:          '45 minutes + 30-day monitoring window',
    business_impact: 'No DMARC record found. Email impersonation from this domain is undetected and unenforced.',
    steps: [
      'Add TXT record at _dmarc.yourdomain.com: v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com; fo=1',
      'Review aggregate reports for 30 days.',
      'Advance to p=quarantine, then p=reject once confirmed.',
    ],
    verification: 'dig TXT _dmarc.example.com +short',
  },

  email_intel_dkim_not_found: {
    priority:        'P3',
    owner:           'Email Team',
    effort:          '15 minutes to verify',
    business_impact: 'DKIM could not be verified using common selectors. A custom selector may be in use, so this observation does not confirm that DKIM is absent.',
    steps: [
      'Confirm the active DKIM selector in your email platform admin console.',
      'Query the exact TXT record at <selector>._domainkey.yourdomain.com.',
      'Verify with a test email — check Authentication-Results header for dkim=pass.',
      'Only configure or change DKIM if provider checks confirm that signing is not enabled.',
    ],
    verification: 'dig TXT <selector>._domainkey.example.com +short',
  },

  // ── SECURITY HEADERS ────────────────────────────────────────────────────────

  header_missing_strict_transport_security: {
    priority:        'P2',
    owner:           'Web Team',
    effort:          '30 minutes',
    business_impact: 'Users connecting over HTTP before the first redirect can be SSL-stripped by an on-path attacker, exposing session tokens, credentials, and sensitive data.',
    steps: [
      'Add the Strict-Transport-Security header to all HTTPS responses.',
      'Nginx: add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
      'Apache: Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
      'Cloudflare Workers: response.headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")',
      'Set max-age to at least 31536000 (one year).',
      'Add includeSubDomains to protect all subdomains — ensure all subdomains support HTTPS first.',
      'Add preload only if you intend to submit to https://hstspreload.org (this is not easily reversed).',
    ],
    verification: 'curl -sI https://example.com | grep -i strict-transport',
  },

  header_weak_hsts: {
    priority:        'P2',
    owner:           'Web Team',
    effort:          '15 minutes',
    business_impact: 'HSTS is configured but with an insufficient max-age. Browser HTTPS enforcement memory is short, leaving a window for SSL stripping attacks.',
    steps: [
      'Update the Strict-Transport-Security header max-age to at least 31536000 (one year).',
      'Current header may have a short max-age like max-age=3600 or max-age=86400.',
      'Recommended: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    ],
    verification: 'curl -sI https://example.com | grep -i strict-transport',
  },

  dse_hsts_short_maxage: {
    priority:        'P2',
    owner:           'Web Team',
    effort:          '15 minutes',
    business_impact: 'HSTS max-age is below the recommended one-year minimum, reducing the effectiveness of SSL stripping protection.',
    steps: [
      'Update HSTS max-age to 31536000 (one year) or greater.',
      'Recommended full header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    ],
    verification: 'curl -sI https://example.com | grep -i strict-transport',
  },

  header_missing_content_security_policy: {
    priority:        'P2',
    owner:           'Web Team',
    effort:          '2–4 hours (policy design) + 30 minutes (deployment)',
    business_impact: 'Without CSP, successful XSS attacks have full browser execution scope. Credentials, session tokens, and page content can be captured and exfiltrated.',
    steps: [
      'Start with Content-Security-Policy-Report-Only to understand your page\'s resource requirements without breaking anything.',
      'Add: Content-Security-Policy-Report-Only: default-src \'self\'; report-uri /csp-report',
      'Check browser console and your report endpoint for violations over 24–48 hours.',
      'Build the policy based on violations: identify all script sources, style sources, image sources, and API endpoints.',
      'Avoid unsafe-inline in script-src — use nonces or hashes instead.',
      'Switch from Report-Only to enforcement: Content-Security-Policy: default-src \'self\'; script-src \'self\' \'nonce-{random}\'; ...',
      'Add frame-ancestors \'none\' or \'self\' to prevent clickjacking.',
    ],
    verification: "curl -sI https://example.com | grep -i 'content-security-policy'",
  },

  csp_weak_policy: {
    priority:        'P2',
    owner:           'Web Team',
    effort:          '1–2 hours',
    business_impact: 'CSP is present but uses unsafe-inline or wildcard script-src directives, defeating XSS protection. The header provides false assurance of security.',
    steps: [
      'Check current CSP: curl -sI https://example.com | grep -i content-security-policy',
      'If script-src contains \'unsafe-inline\': replace with nonces. Add a random nonce to each inline script and reference it in the CSP: script-src \'nonce-RANDOM\'',
      'If script-src contains * (wildcard): replace with an explicit list of allowed script sources.',
      'Test with CSP Evaluator: https://csp-evaluator.withgoogle.com',
      'Deploy in report-only mode first to catch regressions.',
    ],
    verification: "curl -sI https://example.com | grep -i 'content-security-policy'",
  },

  // ── DNS ─────────────────────────────────────────────────────────────────────

  dnssec_not_enabled: {
    priority:        'P2',
    owner:           'DNS Team',
    effort:          '1–2 hours',
    business_impact: 'DNS responses for this domain can be forged by attackers (DNS cache poisoning), potentially redirecting users, email, and API traffic to malicious infrastructure.',
    steps: [
      'Log in to your DNS hosting provider (Cloudflare, Route 53, Google Cloud DNS).',
      'Locate the DNSSEC settings for this zone and enable DNSSEC.',
      'The provider will generate a key pair and sign the zone automatically.',
      'Retrieve the DS record from your DNS provider.',
      'Log in to your domain registrar and publish the DS record to complete the chain of trust.',
      'Verify with dnsviz.net — the chain from root to zone should be validated (green).',
      'Test: dig +dnssec A example.com — look for the AD (Authenticated Data) flag.',
    ],
    verification: 'dig +dnssec A example.com | grep -i "ad\\|rrsig"',
  },

  dnssec_misconfigured: {
    priority:        'P2',
    owner:           'DNS Team',
    effort:          '1 hour',
    business_impact: 'DNSSEC is enabled but the chain of trust is broken. DNSSEC-validating resolvers may reject responses for this domain, causing intermittent resolution failures.',
    steps: [
      'Run dnsviz.net for a visual chain analysis — identify the broken link.',
      'Common causes: DS record at registrar does not match current DNSKEY (key rollover not completed), expired RRSIG, or zone not signed.',
      'If the issue is a key rollover: ensure the new DS record is published at the registrar before deactivating the old key.',
      'If RRSIG is expired: the zone needs to be re-signed — contact your DNS provider or re-sign the zone.',
      'After fixing, verify: dig DS example.com +short matches dig DNSKEY example.com +short.',
    ],
    verification: 'dig DS example.com +short && dig DNSKEY example.com +short',
  },

  // ── SSL / TLS ───────────────────────────────────────────────────────────────

  ssl_certificate_expired: {
    priority:        'P1',
    owner:           'Infrastructure Team',
    effort:          '30 minutes',
    business_impact: 'All users receive browser security errors and most will leave. HTTPS connections fail for API clients. Revenue and operational impact is immediate.',
    steps: [
      'If using Let\'s Encrypt (Certbot): run certbot renew --force-renewal',
      'If using a commercial CA: log in to the CA portal, generate a new certificate (may require a new CSR), and install it on your web server.',
      'Nginx: update ssl_certificate and ssl_certificate_key in nginx.conf and reload: nginx -s reload',
      'Apache: update SSLCertificateFile and SSLCertificateKeyFile in the VirtualHost config and reload: apachectl graceful',
      'Cloudflare origin cert: issue a new certificate from the Cloudflare dashboard under SSL/TLS → Origin Server.',
      'Set up automated renewal to prevent recurrence: Let\'s Encrypt with cron or systemd timer, AWS ACM auto-renewal, or Cloudflare managed certificates.',
    ],
    verification: 'echo | openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -noout -dates',
  },

  ssl_certificate_expiring_soon: {
    priority:        'P1',
    owner:           'Infrastructure Team',
    effort:          '30 minutes',
    business_impact: 'Certificate will expire shortly, causing immediate P1 impact to all HTTPS connections. Renewing now costs 30 minutes; responding to the outage costs hours.',
    steps: [
      'Renew the certificate immediately — do not wait until closer to expiry.',
      'If using Let\'s Encrypt: certbot renew',
      'If using a commercial CA: initiate renewal in the CA portal now.',
      'After renewal, configure automated renewal monitoring to alert 30 days before expiry.',
    ],
    verification: 'echo | openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -noout -dates',
  },

  ssl_not_available: {
    priority:        'P1',
    owner:           'Infrastructure Team',
    effort:          '1–2 hours',
    business_impact: 'No HTTPS endpoint available. All traffic is unencrypted. Login credentials, session tokens, and sensitive data are transmitted in plaintext. Modern browsers block interaction with HTTP-only sites.',
    steps: [
      'Obtain an SSL certificate: use Let\'s Encrypt (free) via Certbot, or obtain a commercial certificate.',
      'Install the certificate on your web server (Nginx, Apache, Caddy, or cloud load balancer).',
      'Configure HTTPS listener on port 443.',
      'Add a 301 redirect from HTTP (port 80) to HTTPS.',
      'Verify: curl -I https://example.com returns 200 and curl -I http://example.com returns 301.',
    ],
    verification: 'curl -I https://example.com',
  },

  ssl_no_certificate: {
    priority:        'P1',
    owner:           'Infrastructure Team',
    effort:          '1–2 hours',
    business_impact: 'No valid SSL certificate installed. HTTPS connections will fail. All data transmitted over HTTP only.',
    steps: [
      'Obtain and install an SSL certificate — see ssl_not_available steps above.',
    ],
    verification: 'echo | openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -noout -subject',
  },

  // ── SUBDOMAIN TAKEOVER ──────────────────────────────────────────────────────

  subdomain_takeover: {
    priority:        'P1',
    owner:           'Cloud Team',
    effort:          '30 minutes',
    business_impact: 'An attacker can serve content under your trusted domain — including phishing pages, credential harvesting forms, or malware — with a valid TLS certificate. Full brand trust is inherited.',
    steps: [
      'Identify the affected subdomain(s) from the finding details.',
      'Check what the dangling CNAME points to: dig CNAME affected.example.com',
      'If the underlying service is no longer needed: remove the DNS CNAME record immediately.',
      'If the service is still needed: reclaim the resource on the third-party platform (GitHub Pages repo, Azure app, Heroku app, S3 bucket) before removing the DNS record.',
      'After removing or fixing the DNS record, verify the subdomain no longer resolves to an unclaimed service.',
      'Implement a DNS change control process: all CNAME deletions must be reviewed for dangling record risk.',
    ],
    verification: 'dig CNAME affected.example.com && curl -sI https://affected.example.com | head -5',
  },

  subdomain_takeover_risk: {
    priority:        'P2',
    owner:           'Cloud Team',
    effort:          '30 minutes',
    business_impact: 'Dangling DNS CNAME pointing to an unclaimed resource. An attacker who registers the target resource will gain control of this subdomain and can serve malicious content under your domain.',
    steps: [
      'Check the CNAME target: dig CNAME affected.example.com',
      'Determine if the pointed-to resource (GitHub Pages repo, Azure app, etc.) is still active and owned by you.',
      'If the resource is no longer needed: remove the DNS CNAME record.',
      'If the resource is needed: reclaim it on the platform before someone else does.',
    ],
    verification: 'dig CNAME affected.example.com',
  },

  // ── CLOUD STORAGE ───────────────────────────────────────────────────────────

  cloud_storage_exposure_observed: {
    priority:        'P1',
    owner:           'Cloud Platform Team',
    effort:          '30 minutes',
    business_impact: 'Customer data, credentials, backups, or internal documents are publicly accessible to any internet user without authentication. Regulatory breach notification obligations may apply under GDPR, HIPAA, or PCI-DSS.',
    steps: [
      'Immediately set the bucket to private.',
      'AWS S3: aws s3api put-bucket-acl --bucket BUCKET_NAME --acl private',
      'AWS — enable Block Public Access (all four options): aws s3control put-public-access-block --account-id ACCOUNT_ID --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"',
      'Azure Blob: Set container access level to "Private (no anonymous access)" in the Azure Portal → Storage Account → Containers.',
      'GCS: gcloud storage buckets update gs://BUCKET_NAME --no-public-access-prevention',
      'Audit the bucket contents for sensitive data — determine if a breach notification is required.',
      'Enable storage access logging (CloudTrail / Azure Monitor) to understand what was accessed and when.',
      'Rotate any credentials, API keys, or secrets found in the bucket.',
    ],
    verification: 'curl -I https://BUCKET.s3.amazonaws.com/ | grep -E "HTTP|Forbidden"',
  },

  cloud_storage_public_listing: {
    priority:        'P1',
    owner:           'Cloud Platform Team',
    effort:          '30 minutes',
    business_impact: 'Bucket listing is enabled — anyone can enumerate all files in this bucket. Even if individual files are not readable, their names reveal internal structure and may expose sensitive paths.',
    steps: [
      'Remove the ListBucket permission from the bucket policy.',
      'AWS: Remove the s3:ListBucket action from any public bucket policy statement.',
      'Ensure Block Public Access is enabled at both bucket and account level.',
      'Verify: curl -I https://BUCKET.s3.amazonaws.com/ should return 403 Forbidden, not a ListBucketResult XML response.',
    ],
    verification: 'curl -I https://BUCKET.s3.amazonaws.com/ | grep "HTTP/"',
  },

  cloud_storage_takeover_risk: {
    priority:        'P1',
    owner:           'Cloud Platform Team',
    effort:          '30 minutes',
    business_impact: 'DNS record references an unclaimed cloud storage bucket. An attacker can register the bucket and serve malicious content from your domain.',
    steps: [
      'Identify the unclaimed bucket from the finding details.',
      'Either: remove the DNS record pointing to the bucket (if the bucket is no longer needed).',
      'Or: register the bucket in your cloud account to claim it before an attacker does, then secure it as private.',
    ],
    verification: 'dig CNAME bucket.example.com',
  },

  // ── ADMIN SURFACE ───────────────────────────────────────────────────────────

  admin_surface_critical: {
    priority:        'P1',
    owner:           'Infrastructure Team',
    effort:          '1 hour',
    business_impact: 'Administrative interfaces (CI/CD systems, database consoles, Kubernetes dashboards, management portals) are accessible from the public internet. A single compromised credential provides full infrastructure access.',
    steps: [
      'Immediately restrict network access to the exposed interface(s).',
      'Firewall rule: allow only VPN/bastion IP ranges, deny all others on the relevant port.',
      'If using a cloud provider: configure Security Groups (AWS), NSG (Azure), or VPC firewall rules (GCP) to block public access.',
      'If using Cloudflare: add a Zero Trust policy requiring authentication before the admin interface is reachable.',
      'Do not rely on authentication alone for internet-exposed admin interfaces — network-level isolation is required.',
      'After restriction, verify the service is no longer reachable from an external IP: curl -I https://admin.example.com should return connection refused or timeout.',
    ],
    verification: 'curl -I --max-time 5 https://admin.example.com (should timeout or return connection refused)',
  },

  admin_surface_high: {
    priority:        'P2',
    owner:           'Infrastructure Team',
    effort:          '2–4 hours',
    business_impact: 'Management interface exposed to the internet with authentication. Attack surface exists — credential attacks, brute force, and unpatched CVEs are all possible attack vectors.',
    steps: [
      'Enforce MFA on all accounts with access to this interface.',
      'Verify the software is on the latest patched version.',
      'Consider restricting network access to VPN/office IP ranges.',
      'Enable login attempt monitoring and alerting.',
    ],
    verification: 'Check admin interface login page — confirm MFA prompt appears and software version is current',
  },

  // ── IDENTITY ────────────────────────────────────────────────────────────────

  identity_microsoft_365_detected: {
    priority:        'P3',
    owner:           'IAM Team',
    effort:          '2–4 hours',
    business_impact: 'Microsoft 365 presence is confirmed. Password spraying attacks against M365 accounts are pervasive. Without MFA and legacy auth blocking, accounts are vulnerable to credential-based compromise that bypasses MFA.',
    steps: [
      'Enable MFA for all users via Azure AD Conditional Access (not per-user MFA — that method is deprecated).',
      'Create a Conditional Access policy: Block legacy authentication (applies to all users, all cloud apps, conditions: client apps = Exchange ActiveSync + Other clients, action = Block).',
      'Enable Microsoft Defender for Identity to detect password spraying and enumeration attempts.',
      'Review Azure AD sign-in logs for failed login attempts (filter by: Status = Failure, Client app = SMTP/IMAP/POP3/MAPI to identify legacy auth usage).',
      'Ensure Self-Service Password Reset (SSPR) requires multi-factor verification.',
    ],
    verification: 'Azure AD admin centre → Security → Conditional Access → confirm legacy auth block policy is active',
  },

  // ── DOMAIN SECURITY ENRICHMENT ──────────────────────────────────────────────

  dse_missing_caa: {
    priority:        'P3',
    owner:           'DNS Team',
    effort:          '15 minutes',
    business_impact: 'Without CAA records, any Certificate Authority can issue an SSL certificate for your domain. CAA restricts certificate issuance to approved CAs only.',
    steps: [
      'Identify which CA(s) issue certificates for your domain.',
      'Add CAA records to DNS: 0 issue "ca-name.com"',
      'Example for Let\'s Encrypt: example.com CAA 0 issue "letsencrypt.org"',
      'Example for DigiCert: example.com CAA 0 issue "digicert.com"',
      'Add mis-issuance reporting: example.com CAA 0 iodef "mailto:security@example.com"',
    ],
    verification: 'dig CAA example.com +short',
  },

  dse_hsts_not_preload_eligible: {
    priority:        'P4',
    owner:           'Web Team',
    effort:          '15 minutes (+ preload list propagation time)',
    business_impact: 'Domain is not eligible for HSTS preloading. Preloading prevents the initial HTTP connection even on first visit, eliminating the first-connection SSL stripping window.',
    steps: [
      'Ensure HSTS header meets preload requirements: max-age >= 31536000; includeSubDomains; preload',
      'Ensure all subdomains also support HTTPS before adding includeSubDomains.',
      'Submit the domain at https://hstspreload.org',
      'Note: preload list removal takes months — only submit if you are committed to HTTPS-only on all subdomains permanently.',
    ],
    verification: 'curl -sI https://example.com | grep -i strict-transport',
  },

  dse_cookie_no_secure: {
    priority:        'P3',
    owner:           'Web Team',
    effort:          '1–2 hours',
    business_impact: 'Session cookies without the Secure flag can be transmitted over HTTP connections, exposing them to interception on the network.',
    steps: [
      'Add the Secure flag to all session and authentication cookies.',
      'Framework-level fix (Express.js): app.use(session({ cookie: { secure: true, httpOnly: true, sameSite: "strict" } }))',
      'Test after change: curl -sI https://example.com | grep -i set-cookie — confirm "Secure" appears in cookie attributes.',
    ],
    verification: 'curl -sI https://example.com | grep -i set-cookie',
  },

  dse_cookie_no_httponly: {
    priority:        'P3',
    owner:           'Web Team',
    effort:          '1–2 hours',
    business_impact: 'Session cookies without HttpOnly are accessible via JavaScript, enabling cookie theft in the event of an XSS vulnerability.',
    steps: [
      'Add the HttpOnly flag to all session and authentication cookies.',
      'This prevents JavaScript (and therefore XSS payloads) from reading the cookie value.',
      'Framework fix: set httpOnly: true in session cookie configuration.',
    ],
    verification: 'curl -sI https://example.com | grep -i set-cookie',
  },

  // ── WHOIS ───────────────────────────────────────────────────────────────────

  whois_domain_expired: {
    priority:        'P1',
    owner:           'Domain Admin',
    effort:          '30 minutes',
    business_impact: 'Domain registration has expired. Services are unavailable or at risk. An attacker can register the expired domain and inherit all associated trust and DNS infrastructure.',
    steps: [
      'Log in to your domain registrar immediately.',
      'Renew the domain — most registrars allow renewal during a grace period after expiry.',
      'If the grace period has passed, initiate a redemption (more expensive and time-limited).',
      'After renewal, enable auto-renew to prevent recurrence.',
      'Set up expiry alerts at 90, 30, and 7 days before renewal due date.',
    ],
    verification: 'whois example.com | grep -i expir',
  },

  whois_expiry_critical: {
    priority:        'P1',
    owner:           'Domain Admin',
    effort:          '30 minutes',
    business_impact: 'Domain expires within 30 days. Immediate renewal required to prevent service disruption and domain hijacking risk.',
    steps: [
      'Log in to your registrar and renew the domain immediately.',
      'Enable auto-renew.',
    ],
    verification: 'whois example.com | grep -i expir',
  },

  whois_expiry_warning: {
    priority:        'P2',
    owner:           'Domain Admin',
    effort:          '30 minutes',
    business_impact: 'Domain expires within 90 days. Schedule renewal now and enable auto-renew to eliminate the risk of operational disruption.',
    steps: [
      'Log in to your registrar and renew the domain.',
      'Enable auto-renew and set a reminder 30 days before the next renewal date.',
    ],
    verification: 'whois example.com | grep -i expir',
  },

}

// ── Prefix alias map — finding IDs that share remediation with another entry ──

const PREFIX_ALIASES = {
  email_intel_spf:   'email_intel_spf_missing',   // covers email_intel_spf_permissive etc.
  email_intel_dmarc: 'email_intel_dmarc_missing',
  email_intel_dkim:  'email_intel_dkim_not_found',
  email_missing:     'email_missing_spf',          // catches future email_missing_* variants
  dse_hsts:          'header_weak_hsts',
  cloud_storage:     'cloud_storage_exposure_observed',
  subdomain_takeover: 'subdomain_takeover',
  admin_surface:     'admin_surface_critical',
  ssl_certificate:   'ssl_certificate_expired',
}

// ── Metadata-only entries (no steps — for findings not in the full library) ──

const METADATA_ONLY = {
  email_not_applicable:              { priority: 'P4', owner: 'Email Team',           effort: '—', business_impact: 'Domain has no MX record — email authentication controls are not applicable.' },
  email_intel_mta_sts_missing:       { priority: 'P4', owner: 'Email Team',           effort: '1–2 hours', business_impact: 'MTA-STS policy absent. Inbound email transport TLS enforcement is not configured.' },
  email_intel_tls_rpt_missing:       { priority: 'P4', owner: 'Email Team',           effort: '15 minutes', business_impact: 'TLS reporting not configured. No visibility into TLS failures on inbound email.' },
  dns_no_resolution:                 { priority: 'P1', owner: 'DNS Team',             effort: '1 hour', business_impact: 'Domain does not resolve. All services are unreachable.' },
  dns_resolver_disagreement:         { priority: 'P3', owner: 'DNS Team',             effort: '1 hour', business_impact: 'DNS resolvers return inconsistent responses — possible propagation issue or DNS hijack.' },
  ssl_no_http_redirect:              { priority: 'P3', owner: 'Infrastructure Team',  effort: '30 minutes', business_impact: 'HTTP traffic is not redirected to HTTPS. Users may submit data over unencrypted connections.' },
  no_https_redirect:                 { priority: 'P3', owner: 'Infrastructure Team',  effort: '30 minutes', business_impact: 'HTTP traffic is not redirected to HTTPS.' },
  canonical_url_uncertain:           { priority: 'P4', owner: 'Web Team',             effort: '—', business_impact: 'Scanner could not confirm the canonical HTTPS URL. Manual verification recommended.' },
  header_missing_x_frame_options:    { priority: 'P3', owner: 'Web Team',             effort: '15 minutes', business_impact: 'Pages can be embedded in iframes, enabling clickjacking attacks.' },
  header_missing_x_content_type_options: { priority: 'P3', owner: 'Web Team',        effort: '15 minutes', business_impact: 'Browsers may interpret responses as a different MIME type, enabling content-sniffing attacks.' },
  header_missing_referrer_policy:    { priority: 'P4', owner: 'Web Team',             effort: '15 minutes', business_impact: 'Referrer data may be leaked to third-party resources loaded by the page.' },
  header_missing_permissions_policy: { priority: 'P4', owner: 'Web Team',             effort: '15 minutes', business_impact: 'Browser feature policy not configured. Low active exploit risk.' },
  admin_surface_medium:              { priority: 'P3', owner: 'Infrastructure Team',  effort: '1–2 hours', business_impact: 'Management interface detected. Ensure MFA enforcement and current patch level.' },
  dse_caa_no_issuers:                { priority: 'P3', owner: 'DNS Team',             effort: '15 minutes', business_impact: 'CAA record present but no issuers listed — effectively blocks all certificate issuance.' },
  dse_cookie_no_samesite:            { priority: 'P4', owner: 'Web Team',             effort: '30 minutes', business_impact: 'Cookies without SameSite may be sent on cross-site requests, enabling CSRF in some scenarios.' },
  tech_server_version_disclosure:    { priority: 'P4', owner: 'Web Team',             effort: '15 minutes', business_impact: 'Server version exposed in headers. Enables targeted CVE reconnaissance without active probing.' },
  tech_xpoweredby_version_disclosure: { priority: 'P4', owner: 'Web Team',            effort: '15 minutes', business_impact: 'Framework version exposed. Enables targeted CVE reconnaissance.' },
  cve_high_severity_detected:        { priority: 'P1', owner: 'Web Team',             effort: 'Varies', business_impact: 'Detected technology matches a high-severity CVE. Patch or mitigate immediately.' },
  kev_active_exploitation:           { priority: 'P1', owner: 'Infrastructure Team',  effort: 'Immediate', business_impact: 'Technology in CISA Known Exploited Vulnerabilities list. Active exploitation confirmed in the wild.' },
  whois_new_domain:                  { priority: 'P4', owner: 'Domain Admin',         effort: '30 minutes', business_impact: 'Recently registered domain. May attract spam filtering and phishing suspicion.' },
  subdomains_large_attack_surface:   { priority: 'P3', owner: 'Cloud Team',           effort: '4+ hours', business_impact: 'Large number of subdomains increases the attack surface. Review for orphaned or unnecessary subdomains.' },
  identity_legacy_auth_exposed:      { priority: 'P2', owner: 'IAM Team',             effort: '2–4 hours', business_impact: 'Legacy authentication endpoints reachable. Password spraying attacks bypass MFA via these endpoints.' },
  identity_autodiscover_exposed:     { priority: 'P3', owner: 'IAM Team',             effort: '1 hour', business_impact: 'Autodiscover endpoint exposed. Enables M365 tenant and username enumeration.' },
  vendor_risk_detected:              { priority: 'P3', owner: 'Procurement + Security', effort: '4+ hours', business_impact: 'Third-party vendor relationships identified. Vendor security posture directly affects your risk profile.' },
  supply_chain_vendor_detected:      { priority: 'P3', owner: 'Procurement + Security', effort: '4+ hours', business_impact: 'Supply chain dependency detected. Vendor compromise can cascade to your organisation.' },
  third_party_js_detected:           { priority: 'P3', owner: 'Web Team',             effort: '2 hours', business_impact: 'Third-party JavaScript detected. Compromise of the provider\'s CDN affects all pages loading this script.' },
  known_vulnerable_component:        { priority: 'P2', owner: 'Web Team',             effort: 'Varies', business_impact: 'A known-vulnerable component version detected in use. Update to a patched version.' },
}

// ── Main helper ───────────────────────────────────────────────────────────────

/**
 * buildRemediationIntelligence(finding)
 *
 * Takes a scan finding object (must have at least .id and optionally .module).
 * Returns a remediation intelligence block, or null if no information is available.
 *
 * Lookup order:
 *  1. Exact match in LIBRARY (full steps + metadata)
 *  2. Exact match in METADATA_ONLY (metadata, no steps)
 *  3. Prefix alias → resolve to LIBRARY entry
 *  4. Module fallback → minimal metadata from MODULE_OWNER
 *  5. null
 */
export function buildRemediationIntelligence(finding) {
  if (!finding) return null
  const id     = finding.id     ?? ''
  const module = finding.module ?? ''

  // Tier 1 — full library entry
  if (id && LIBRARY[id]) {
    return { steps: [], verification: '', ...LIBRARY[id] }
  }

  // Tier 2 — metadata-only entry
  if (id && METADATA_ONLY[id]) {
    return { steps: [], verification: '', ...METADATA_ONLY[id] }
  }

  // Tier 3 — prefix alias (most-specific first)
  if (id) {
    const parts = id.split('_')
    for (let len = parts.length - 1; len >= 1; len--) {
      const prefix = parts.slice(0, len).join('_')
      if (PREFIX_ALIASES[prefix]) {
        const target = PREFIX_ALIASES[prefix]
        if (LIBRARY[target])       return { steps: [], verification: '', ...LIBRARY[target] }
        if (METADATA_ONLY[target]) return { steps: [], verification: '', ...METADATA_ONLY[target] }
      }
    }
  }

  // Tier 4 — module fallback (owner only)
  const owner = MODULE_OWNER[module]
  if (owner) {
    return { priority: null, owner, effort: null, business_impact: null, steps: [], verification: '' }
  }

  return null
}
