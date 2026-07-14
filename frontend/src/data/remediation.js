/**
 * CyberMeters Remediation Presentation Layer v2
 *
 * The scan report API attaches a canonical `remediation` object to each
 * finding (finding.remediation). All remediation SEMANTICS — title, owner,
 * effort, business impact, recommended action, verification method,
 * evidence requirements — come from that server-supplied object.
 *
 * This module keeps ONLY presentation detail:
 *  - PRIORITY_LABELS / PRIORITY_SLA (visual priority framework)
 *  - REMEDIATION_STEPS: step-by-step instructions + a CLI verification
 *    command, keyed by canonical remediation_id
 *  - OWNER_LABELS / EFFORT_LABELS: display strings for server enums
 *
 * buildRemediationIntelligence(finding) returns:
 * {
 *   remediation_id:        string
 *   priority:              'P1' | 'P2' | 'P3' | 'P4' | null   (derived from finding.severity)
 *   title:                 string          (server: customer_title)
 *   owner:                 string | null   (label for server owner_type)
 *   effort:                string | null   (label for server effort)
 *   business_impact:       string | null   (server)
 *   recommended_action:    string | null   (server)
 *   verification_method:   string | null   (server)
 *   verification_evidence: string | null   (server)
 *   steps:                 string[]        (frontend, keyed by remediation_id)
 *   verification:          string          (frontend CLI command, keyed by remediation_id)
 * }
 *
 * Returns null when finding.remediation is null/absent — the server said
 * there is no canonical remediation, so the UI renders nothing.
 */

// ── Priority Framework (presentation over finding.severity) ──────────────────

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

// ── Display labels for server-supplied enums ─────────────────────────────────

export const OWNER_LABELS = {
  customer:       'Account Owner',
  customer_it:    'IT / DNS Administrator',
  email_provider: 'Email Provider',
  registrar:      'Domain Registrar',
  cybermeters:    'CyberMeters',
  external_body:  'External Body',
}

export const EFFORT_LABELS = {
  low:    'Low',
  medium: 'Medium',
  high:   'High',
}

// ── Step-by-step instructions + CLI verification, keyed by remediation_id ────
// Presentation detail only. All meaning (title, impact, owner, effort, action)
// comes from the server's canonical remediation object.

export const REMEDIATION_STEPS = {

  // ── EMAIL SECURITY ──────────────────────────────────────────────────────────

  'email.spf.publish': {
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

  'email.spf.tighten': {
    steps: [
      'Review your current SPF record: dig TXT yourdomain.com +short | grep spf1',
      'Identify the current ending mechanism (~all, ?all, or +all).',
      'Replace the ending with -all (hard fail): v=spf1 include:_spf.google.com -all',
      'Verify all legitimate sending services are included in the SPF record before making this change — legitimate email from unlisted sources will be rejected.',
    ],
    verification: 'dig TXT example.com +short | grep "v=spf1"',
  },

  'email.dmarc.publish': {
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

  'email.dmarc.enforce': {
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

  'email.dkim.verify': {
    steps: [
      'Check the email platform admin console for the active DKIM selector.',
      'Query the exact TXT record at <selector>._domainkey.yourdomain.com.',
      'Send a test email to Gmail or Outlook and check the Authentication-Results header to confirm dkim=pass.',
      'Only configure or change DKIM if provider checks confirm that signing is not enabled.',
    ],
    verification: 'dig TXT <selector>._domainkey.example.com +short',
  },

  // ── SECURITY HEADERS ────────────────────────────────────────────────────────

  'web.header.hsts': {
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

  'web.header.csp': {
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

  'web.cookie.flags': {
    steps: [
      'Add the Secure flag to all session and authentication cookies.',
      'Framework-level fix (Express.js): app.use(session({ cookie: { secure: true, httpOnly: true, sameSite: "strict" } }))',
      'Test after change: curl -sI https://example.com | grep -i set-cookie — confirm "Secure" appears in cookie attributes.',
    ],
    verification: 'curl -sI https://example.com | grep -i set-cookie',
  },

  // ── DNS ─────────────────────────────────────────────────────────────────────

  'asm.dnssec.enable': {
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

  // ── SSL / TLS ───────────────────────────────────────────────────────────────

  'cert.expiry.expired': {
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

  'cert.expiry.expiring': {
    steps: [
      'Renew the certificate immediately — do not wait until closer to expiry.',
      'If using Let\'s Encrypt: certbot renew',
      'If using a commercial CA: initiate renewal in the CA portal now.',
      'After renewal, configure automated renewal monitoring to alert 30 days before expiry.',
    ],
    verification: 'echo | openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -noout -dates',
  },

  'cert.tls.install': {
    steps: [
      'Obtain an SSL certificate: use Let\'s Encrypt (free) via Certbot, or obtain a commercial certificate.',
      'Install the certificate on your web server (Nginx, Apache, Caddy, or cloud load balancer).',
      'Configure HTTPS listener on port 443.',
      'Add a 301 redirect from HTTP (port 80) to HTTPS.',
      'Verify: curl -I https://example.com returns 200 and curl -I http://example.com returns 301.',
    ],
    verification: 'curl -I https://example.com',
  },

  'cert.caa.configure': {
    steps: [
      'Identify which CA(s) issue certificates for your domain.',
      'Add CAA records to DNS: 0 issue "ca-name.com"',
      'Example for Let\'s Encrypt: example.com CAA 0 issue "letsencrypt.org"',
      'Example for DigiCert: example.com CAA 0 issue "digicert.com"',
      'Add mis-issuance reporting: example.com CAA 0 iodef "mailto:security@example.com"',
    ],
    verification: 'dig CAA example.com +short',
  },

  // ── SUBDOMAIN TAKEOVER ──────────────────────────────────────────────────────

  'asm.subdomain.takeover': {
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

  // ── CLOUD STORAGE ───────────────────────────────────────────────────────────

  'asm.cloud_storage.review': {
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

  'asm.cloud_storage.public': {
    steps: [
      'Remove the ListBucket permission from the bucket policy.',
      'AWS: Remove the s3:ListBucket action from any public bucket policy statement.',
      'Ensure Block Public Access is enabled at both bucket and account level.',
      'Verify: curl -I https://BUCKET.s3.amazonaws.com/ should return 403 Forbidden, not a ListBucketResult XML response.',
    ],
    verification: 'curl -I https://BUCKET.s3.amazonaws.com/ | grep "HTTP/"',
  },

  // ── ADMIN SURFACE ───────────────────────────────────────────────────────────

  'asm.exposure.admin': {
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

  // ── IDENTITY ────────────────────────────────────────────────────────────────

  'identity.m365.harden': {
    steps: [
      'Enable MFA for all users via Azure AD Conditional Access (not per-user MFA — that method is deprecated).',
      'Create a Conditional Access policy: Block legacy authentication (applies to all users, all cloud apps, conditions: client apps = Exchange ActiveSync + Other clients, action = Block).',
      'Enable Microsoft Defender for Identity to detect password spraying and enumeration attempts.',
      'Review Azure AD sign-in logs for failed login attempts (filter by: Status = Failure, Client app = SMTP/IMAP/POP3/MAPI to identify legacy auth usage).',
      'Ensure Self-Service Password Reset (SSPR) requires multi-factor verification.',
    ],
    verification: 'Azure AD admin centre → Security → Conditional Access → confirm legacy auth block policy is active',
  },

  // ── DOMAIN EXPIRY ───────────────────────────────────────────────────────────

  'asm.domain.expiry': {
    steps: [
      'Log in to your domain registrar immediately.',
      'Renew the domain — most registrars allow renewal during a grace period after expiry.',
      'If the grace period has passed, initiate a redemption (more expensive and time-limited).',
      'After renewal, enable auto-renew to prevent recurrence.',
      'Set up expiry alerts at 90, 30, and 7 days before renewal due date.',
    ],
    verification: 'whois example.com | grep -i expir',
  },

}

// ── Severity → presentation priority ─────────────────────────────────────────

const SEVERITY_PRIORITY = {
  critical:      'P1',
  high:          'P2',
  medium:        'P3',
  low:           'P4',
  info:          'P4',
  informational: 'P4',
}

// ── Main helper ───────────────────────────────────────────────────────────────

/**
 * buildRemediationIntelligence(finding)
 *
 * Reads the server-supplied canonical remediation object at
 * finding.remediation. Returns null when it is absent — the server is the
 * single source of truth for whether a finding has a remediation, and the
 * UI renders nothing in that case.
 *
 * All semantic fields (title, owner, effort, business_impact,
 * recommended_action, verification_method, verification_evidence) come from
 * the server object. This module only adds:
 *  - priority: presentation mapping of finding.severity (P1–P4)
 *  - owner/effort display labels for server enums
 *  - steps + CLI verification command, keyed by canonical remediation_id
 */
export function buildRemediationIntelligence(finding) {
  const rem = finding && finding.remediation
  if (!rem) return null

  const severity = typeof finding.severity === 'string' ? finding.severity.toLowerCase() : ''
  const priority = SEVERITY_PRIORITY[severity] || null

  const presentation = REMEDIATION_STEPS[rem.remediation_id]

  return {
    remediation_id:        rem.remediation_id,
    priority,
    title:                 rem.customer_title,
    owner:                 OWNER_LABELS[rem.owner_type] || rem.owner_type || null,
    effort:                EFFORT_LABELS[rem.effort] || rem.effort || null,
    business_impact:       rem.business_impact || null,
    recommended_action:    rem.recommended_action || null,
    verification_method:   rem.verification_method || null,
    verification_evidence: rem.verification_evidence_requirements || null,
    steps:                 (presentation && presentation.steps) || [],
    verification:          (presentation && presentation.verification) || '',
  }
}
