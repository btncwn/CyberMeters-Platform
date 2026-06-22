/**
 * CyberMeters Academy — Content Data Store v1
 *
 * All Academy categories and articles are defined here.
 * No external CMS, no markdown parser — structured JS for zero build overhead.
 *
 * Article content model:
 *   slug          — URL-safe identifier (kebab-case)
 *   title         — Display title
 *   category      — Category slug
 *   summary       — 2–3 sentence executive lede (rendered above sections)
 *   readTime      — Estimated minutes
 *   featured      — Show in hero row on index
 *   sections      — Array of { heading, blocks[] }
 *                   Each block: { type, text } | { type:'list', items[] } | { type:'code', text }
 *   relatedSlugs  — Related article slugs
 *   findingIds    — Maps to Worker finding type IDs (Sprint 11A integration)
 *   publishedAt   — ISO date string
 */

// ── Block helpers (called inline for readability) ────────────────────────────

function p(text) { return { type: 'para', text } }
function li(items) { return { type: 'list', items } }
function code(text, lang = '') { return { type: 'code', text, lang } }
function callout(text, variant = 'info') { return { type: 'callout', text, variant } }

// ── Categories ───────────────────────────────────────────────────────────────

export const CATEGORIES = [
  { slug: 'attack-surface-management', label: 'Attack Surface Management', icon: 'Radar',      color: 'brand'  },
  { slug: 'email-security',            label: 'Email Security',            icon: 'Mail',        color: 'blue'   },
  { slug: 'dns-security',              label: 'DNS Security',              icon: 'Globe',       color: 'indigo' },
  { slug: 'ssl-tls',                   label: 'SSL / TLS',                 icon: 'Lock',        color: 'green'  },
  { slug: 'security-headers',          label: 'Security Headers',          icon: 'Shield',      color: 'purple' },
  { slug: 'subdomain-takeover',        label: 'Subdomain Takeover',        icon: 'AlertTriangle', color: 'red'  },
  { slug: 'cloud-storage-security',    label: 'Cloud Storage Security',    icon: 'Cloud',       color: 'cyan'   },
  { slug: 'identity-discovery',        label: 'Identity Discovery',        icon: 'Users',       color: 'amber'  },
  { slug: 'saas-exposure',             label: 'SaaS Exposure',             icon: 'Layers',      color: 'pink'   },
  { slug: 'vendor-risk',               label: 'Vendor Risk',               icon: 'Briefcase',   color: 'orange' },
  { slug: 'supply-chain-intelligence', label: 'Supply Chain Intelligence', icon: 'Link',        color: 'rose'   },
]

// ── Articles ─────────────────────────────────────────────────────────────────

export const ARTICLES = [

  // ── 1. What is Attack Surface Management? ─────────────────────────────────
  {
    slug: 'what-is-attack-surface-management',
    title: 'What is Attack Surface Management?',
    category: 'attack-surface-management',
    summary: 'Attack Surface Management (ASM) is the continuous practice of discovering, inventorying, and monitoring every digital asset an organisation exposes to the internet — before attackers find and exploit them. Where traditional security starts from the inside, ASM starts from where attackers start: the outside.',
    readTime: 9,
    featured: true,
    publishedAt: '2026-06-01',
    sections: [
      {
        heading: 'Why It Matters',
        blocks: [
          p('Most organisations do not have a complete picture of their own internet-facing assets. Shadow IT, forgotten subdomains, cloud misconfigurations, and acquired infrastructure accumulate silently. Attackers systematically scan the entire internet for exposed assets, meaning they often know more about your digital footprint than your security team does.'),
          p('ASM closes this gap. By continuously discovering and assessing every internet-facing asset — including those your team did not create — ASM provides the context needed to prioritise remediation before a breach occurs. It answers the question every CISO faces: "What can an attacker see that we cannot?"'),
          callout('ASM is not a one-time assessment. Threat landscapes change daily. New cloud deployments, partner integrations, and code commits constantly alter your exposure.', 'info'),
        ],
      },
      {
        heading: 'How Attackers Abuse It',
        blocks: [
          p('Sophisticated threat actors begin every targeted attack with reconnaissance. They map your organisation\'s domain infrastructure, enumerate subdomains, check certificate transparency logs, and probe open ports. They look for forgotten test servers, administrative panels exposed to the internet, outdated software with known CVEs, and misconfigured cloud storage buckets.'),
          p('Nation-state actors and ransomware groups both use automated ASM-equivalent tools — often the same commercial platforms security teams use. The difference is they use this intelligence to attack, while defenders should use it to harden.'),
          li([
            'Scan certificate transparency logs for every subdomain ever registered',
            'Probe DNS records for dangling entries pointing to decommissioned infrastructure',
            'Identify cloud assets via reverse IP lookups and ASN enumeration',
            'Fingerprint technology stacks to match against CVE databases',
            'Find exposed admin portals, login pages, and default credentials',
          ]),
        ],
      },
      {
        heading: 'Real World Example',
        blocks: [
          p('In 2021, a major healthcare provider suffered a breach traced to a forgotten test server that had been abandoned years earlier following a product sunset. The server still ran unpatched software and was reachable from the public internet. The breach exposed patient records for over 1.5 million individuals. The organisation\'s internal asset inventory had no record of the server — it had been provisioned by a team that no longer existed.'),
          p('This pattern repeats across industries. The challenge is not always new vulnerabilities — it is unknown assets carrying old vulnerabilities. ASM solves the discovery problem that makes these breaches possible.'),
        ],
      },
      {
        heading: 'What CyberMeters Detects',
        blocks: [
          p('CyberMeters performs continuous ASM across your registered domains. Each scan identifies:'),
          li([
            'Subdomains discovered via DNS enumeration and certificate transparency',
            'Open ports and service banners across detected IP addresses',
            'Exposed administrative interfaces and login pages',
            'Dangling DNS records pointing to decommissioned cloud resources',
            'SSL/TLS certificate health, expiry dates, and chain issues',
            'Email security posture (SPF, DMARC, DKIM)',
            'Security header configuration across web-facing endpoints',
            'Cloud storage misconfigurations and public bucket exposure',
          ]),
          p('All findings are scored by severity and enriched with confidence ratings, evidence chains, and remediation guidance. The platform tracks asset changes over time so new exposures are detected within 24 hours of introduction.'),
        ],
      },
      {
        heading: 'Remediation Overview',
        blocks: [
          p('Effective ASM remediation follows a consistent workflow: discover, prioritise, remediate, verify, and monitor. The discovery phase is automated — the remaining steps require human judgment and process.'),
          li([
            'Maintain an accurate inventory: treat every asset found in ASM as ground truth, not your internal CMDB',
            'Decommission forgotten assets: shut down servers, revoke certificates, and remove DNS records for anything no longer in use',
            'Establish an asset ownership policy: every internet-facing asset must have a named owner who receives ASM alerts',
            'Integrate ASM into change management: any new domain, cloud deployment, or subdomain should trigger an ASM scan within 24 hours',
            'Prioritise critical + high severity findings within 7 days, medium within 30 days',
          ]),
        ],
      },
      {
        heading: 'Verification',
        blocks: [
          p('After remediation, re-run a CyberMeters scan on the affected domain. Confirmed fixes will no longer appear in the findings list. For decommissioned assets, verify the DNS record has been removed and the asset no longer responds to HTTP requests.'),
          code('# Verify subdomain is no longer resolving\nnslookup old-test.example.com\n# Expected: NXDOMAIN or empty result\n\n# Verify HTTP endpoint is gone\ncurl -I https://old-test.example.com\n# Expected: connection refused or 404', 'bash'),
        ],
      },
    ],
    relatedSlugs: ['spf-explained', 'what-is-subdomain-takeover', 'public-cloud-storage-risks'],
    findingIds: ['subdomain_discovered', 'exposed_admin_panel', 'dangling_dns_record'],
  },

  // ── 2. SPF Explained ──────────────────────────────────────────────────────
  {
    slug: 'spf-explained',
    title: 'SPF Explained',
    category: 'email-security',
    summary: 'Sender Policy Framework (SPF) is a DNS-based email authentication mechanism that specifies which mail servers are authorised to send email on behalf of your domain. Without SPF, anyone can send email that appears to come from your organisation — enabling phishing, business email compromise, and reputational damage.',
    readTime: 7,
    featured: true,
    publishedAt: '2026-06-01',
    sections: [
      {
        heading: 'Why It Matters',
        blocks: [
          p('Email spoofing is one of the most prevalent attack techniques in use today. Business Email Compromise (BEC) — where attackers impersonate executives or suppliers via email — costs organisations billions of dollars annually. SPF is the first layer of defence that prevents unauthorised parties from using your domain name as a sender.'),
          p('Without a valid SPF record, your domain can be used to send phishing emails targeting your customers, partners, and employees. Receiving mail servers have no technical basis to reject these messages. With SPF, you define an explicit allowlist of authorised sending infrastructure.'),
          callout('SPF alone is not sufficient. It must be combined with DMARC to provide enforcement and reporting. SPF without DMARC provides limited protection because SPF only validates the envelope sender, not the displayed "From" address.', 'warning'),
        ],
      },
      {
        heading: 'How Attackers Abuse It',
        blocks: [
          p('When SPF is absent or misconfigured, attackers can send email that passes as coming from your domain. In a typical Business Email Compromise attack, an adversary identifies a target company, registers a lookalike domain or exploits the absence of SPF on the real domain, and then sends fraudulent wire transfer requests or credential harvesting emails that appear to come from legitimate internal accounts.'),
          p('A missing SPF record on a domain used only for web (not for sending email) is equally dangerous. Attackers specifically target non-sending domains because organisations often overlook them. If you own example-hr.com and never use it for email, an attacker can send convincing phishing emails from hr@example-hr.com with no SPF barrier.'),
        ],
      },
      {
        heading: 'Real World Example',
        blocks: [
          p('The FBI reported that BEC attacks accounted for over $2.9 billion in losses in 2023 alone. A significant proportion of these attacks exploited the absence of SPF or DMARC on the impersonated domains. In one documented case, a European manufacturing firm lost €6 million when an attacker impersonated their CFO via a domain that had no email authentication configured, successfully diverting a supplier payment.'),
        ],
      },
      {
        heading: 'What CyberMeters Detects',
        blocks: [
          p('CyberMeters checks the SPF record for every domain in your workspace. The following conditions are flagged:'),
          li([
            'Missing SPF record (no TXT record starting with v=spf1)',
            'SPF soft fail (~all) — mail from unknown sources is accepted with a warning',
            'SPF neutral (?all) — SPF provides no guidance to receivers',
            'SPF record exceeds 10 DNS lookup limit (causes intermittent failures)',
            'Multiple SPF records (invalid — only one TXT SPF record is permitted)',
            'SPF record includes deprecated mechanisms (ptr:)',
          ]),
        ],
      },
      {
        heading: 'Remediation Overview',
        blocks: [
          p('Add a TXT record to your domain\'s DNS that defines your authorised sending sources. The record must start with v=spf1 and end with -all (hard fail) or ~all (soft fail, not recommended for enforced authentication).'),
          code('# For a domain using Google Workspace:\nv=spf1 include:_spf.google.com -all\n\n# For a domain using Microsoft 365:\nv=spf1 include:spf.protection.outlook.com -all\n\n# For a non-sending domain (no legitimate email):\nv=spf1 -all', 'dns'),
          li([
            'Use -all (hard fail) not ~all (soft fail) for enforced rejection',
            'Keep DNS lookups under 10 to prevent SPF permerror',
            'Use include: mechanisms for third-party senders (CRMs, marketing platforms)',
            'Audit sending sources before finalising the record — missing a legitimate sender breaks email delivery',
            'Deploy DMARC alongside SPF to gain enforcement and reporting',
          ]),
        ],
      },
      {
        heading: 'Verification',
        blocks: [
          p('After adding the SPF record, verify it resolves correctly and re-scan in CyberMeters.'),
          code('# Query SPF record\nnslookup -type=TXT example.com | grep "v=spf1"\n\n# Or using dig\ndig TXT example.com +short | grep "v=spf1"', 'bash'),
          p('Use an SPF validator tool (MXToolbox, dmarcian) to test the record evaluates correctly and stays within the 10-lookup limit. Send a test email to a Gmail or Outlook address and view the message headers to confirm SPF=pass.'),
        ],
      },
    ],
    relatedSlugs: ['dmarc-explained', 'dkim-explained', 'business-email-compromise'],
    findingIds: ['email_missing_spf', 'email_spf_softfail', 'email_spf_neutral', 'email_spf_permerror'],
  },

  // ── 3. DMARC Explained ────────────────────────────────────────────────────
  {
    slug: 'dmarc-explained',
    title: 'DMARC Explained',
    category: 'email-security',
    summary: 'Domain-based Message Authentication, Reporting, and Conformance (DMARC) builds on SPF and DKIM to give domain owners control over what happens when an email fails authentication checks. It is the enforcement layer that turns email authentication from advisory to mandatory — and the single most impactful configuration you can make to protect your domain against impersonation.',
    readTime: 10,
    featured: true,
    publishedAt: '2026-06-01',
    sections: [
      {
        heading: 'Why It Matters',
        blocks: [
          p('SPF and DKIM authenticate email at a technical level, but without DMARC there is no instruction to receiving mail servers about what to do when authentication fails. A DMARC policy of p=reject tells the world\'s mail servers: "If an email claims to be from our domain and does not pass authentication, delete it." This is the definitive protection against domain impersonation.'),
          p('DMARC also provides reporting. Mail servers send aggregate reports (RUA) and forensic reports (RUF) back to the domain owner, providing visibility into who is sending email on your behalf — including attackers and misconfigured third-party services.'),
          callout('A DMARC policy of p=none provides visibility but zero enforcement. It is a starting point, not a destination. The goal is p=quarantine or p=reject. Many organisations stop at p=none and believe they are protected — they are not.', 'warning'),
        ],
      },
      {
        heading: 'How Attackers Abuse It',
        blocks: [
          p('Without DMARC enforcement, attackers can send email with a "From:" header showing any address at your domain. This is distinct from the SPF envelope sender — the From header is what recipients actually see in their email client. DMARC is the only control that aligns the visible From address with authentication results.'),
          p('A common attack pattern: an attacker sends a phishing email where the From header reads "payroll@yourcompany.com". Even if SPF fails for the sending IP, without DMARC the email may still be delivered. With DMARC p=reject, the receiving server will discard it before it ever reaches the inbox.'),
        ],
      },
      {
        heading: 'Real World Example',
        blocks: [
          p('In 2022, a healthcare system\'s supplier submitted a fraudulent invoice via email appearing to come from a known internal email address. The domain had an SPF record but no DMARC policy. The receiving server accepted the message because SPF\'s envelope checks passed on the spoofed infrastructure. A $4.2 million payment was diverted. If DMARC had been at p=reject, the email would have been discarded at delivery.'),
          p('Google and Yahoo mandated DMARC at p=none or stronger for bulk senders in early 2024, making it a de facto requirement for email deliverability — not just security.'),
        ],
      },
      {
        heading: 'What CyberMeters Detects',
        blocks: [
          p('CyberMeters evaluates DMARC configuration for every domain in your workspace:'),
          li([
            'Missing DMARC record (no _dmarc.yourdomain TXT record)',
            'DMARC policy set to p=none (monitoring only, no enforcement)',
            'DMARC percentage (pct) less than 100 (partial enforcement)',
            'No reporting address configured (rua, ruf) — missing visibility',
            'Subdomain policy (sp) not set — subdomains may be unprotected',
            'Invalid or malformed DMARC record syntax',
          ]),
        ],
      },
      {
        heading: 'Remediation Overview',
        blocks: [
          p('DMARC is implemented as a TXT record on the _dmarc subdomain of your domain. The recommended migration path is p=none → p=quarantine → p=reject, using reporting data to identify legitimate sending sources before tightening enforcement.'),
          code('# Step 1: Start with monitoring (p=none)\n_dmarc.example.com TXT "v=DMARC1; p=none; rua=mailto:dmarc@example.com; ruf=mailto:dmarc@example.com; fo=1"\n\n# Step 2: Move to quarantine after 30+ days of clean reports\n_dmarc.example.com TXT "v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@example.com"\n\n# Step 3: Full enforcement\n_dmarc.example.com TXT "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com; sp=reject"', 'dns'),
          li([
            'Set rua to receive aggregate reports — parse them with dmarcian or Postmark DMARC Digests',
            'Review reports for 30 days before advancing from p=none to p=quarantine',
            'Set sp=reject to protect subdomains as well as the root domain',
            'Do not rely on p=none as a final state — it provides zero protection',
          ]),
        ],
      },
      {
        heading: 'Verification',
        blocks: [
          code('# Verify DMARC record\ndig TXT _dmarc.example.com +short\n\n# Expected output example:\n"v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com; sp=reject"', 'bash'),
          p('Re-scan in CyberMeters after publishing the record. Use an email header analyser to send a test message and confirm DMARC=pass. Monitor aggregate reports for the first 30 days to catch any delivery issues with legitimate senders.'),
        ],
      },
    ],
    relatedSlugs: ['spf-explained', 'dkim-explained'],
    findingIds: ['email_missing_dmarc', 'email_dmarc_policy_none', 'email_dmarc_no_reporting'],
  },

  // ── 4. DKIM Explained ────────────────────────────────────────────────────
  {
    slug: 'dkim-explained',
    title: 'DKIM Explained',
    category: 'email-security',
    summary: 'DomainKeys Identified Mail (DKIM) signs outgoing email with a cryptographic signature that receiving servers can verify using a public key published in DNS. It proves that an email was sent by an authorised server and that the message content was not altered in transit — making it an essential component of a complete email authentication stack.',
    readTime: 7,
    featured: false,
    publishedAt: '2026-06-01',
    sections: [
      {
        heading: 'Why It Matters',
        blocks: [
          p('DKIM complements SPF by authenticating the message content rather than just the sending server. Where SPF says "this IP is allowed to send for this domain," DKIM says "this message was signed by the private key held by this domain." Together, they provide two independent authentication signals that DMARC can align.'),
          p('Without DKIM, even a correctly delivered email cannot prove it has not been tampered with. DKIM signatures survive email forwarding where SPF often does not — making DKIM critical for organisations whose legitimate email is frequently forwarded by recipients.'),
        ],
      },
      {
        heading: 'How Attackers Abuse It',
        blocks: [
          p('An absent or misconfigured DKIM record weakens the DMARC authentication chain. If SPF fails for a forwarded message (common with email lists and aliases), DMARC falls back to the DKIM result. Without DKIM, that fallback fails, potentially causing legitimate email to be rejected — or creating gaps that attackers can exploit.'),
          p('Attackers also look for exposed or leaked DKIM private keys. If a private key is compromised, an attacker can sign malicious email that passes DKIM verification. This is rare but has occurred via source code leaks and compromised mail infrastructure.'),
        ],
      },
      {
        heading: 'Real World Example',
        blocks: [
          p('In 2020, a DKIM key rotation failure at a financial services firm caused months of email delivery failures. Their marketing platform had rotated the signing key without updating the DNS record, resulting in DKIM failures and subsequent DMARC quarantine actions on all outbound emails. The resolution required coordination across three teams and caused material business disruption — demonstrating that DKIM operational hygiene matters as much as the initial configuration.'),
        ],
      },
      {
        heading: 'What CyberMeters Detects',
        blocks: [
          p('CyberMeters probes for DKIM records on common selector names for the major email providers, including Google Workspace, Microsoft 365, Mailchimp, SendGrid, and others. Findings include:'),
          li([
            'No DKIM record found on standard selectors (google, selector1, selector2)',
            'DKIM record using an RSA key shorter than 2048 bits (vulnerable to brute force)',
            'Expired or revoked DKIM key (key with p= empty or missing)',
          ]),
          callout('CyberMeters cannot discover DKIM selectors it has not been told about. Use your email provider\'s admin console to confirm which selector your outbound mail uses, then verify the DNS record matches.', 'info'),
        ],
      },
      {
        heading: 'Remediation Overview',
        blocks: [
          li([
            'Enable DKIM signing in your email platform (Google Workspace Admin, Microsoft 365 Exchange Admin)',
            'Publish the DKIM public key as a TXT record at selector._domainkey.yourdomain',
            'Use 2048-bit RSA keys — 1024-bit keys are considered deprecated',
            'Rotate DKIM keys annually or when staff with key access depart',
            'Keep old selectors in DNS for 48 hours after rotation to allow in-flight messages to verify',
          ]),
          code('# Example DKIM record (Google Workspace, default selector)\ngoogle._domainkey.example.com TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhk..."', 'dns'),
        ],
      },
      {
        heading: 'Verification',
        blocks: [
          code('# Verify a specific DKIM selector\ndig TXT google._domainkey.example.com +short\n\n# Or with nslookup\nnslookup -type=TXT google._domainkey.example.com', 'bash'),
          p('Send a test email and inspect the Authentication-Results header. It should show dkim=pass for your domain. After any DKIM changes, allow 24–48 hours for DNS propagation before re-scanning in CyberMeters.'),
        ],
      },
    ],
    relatedSlugs: ['spf-explained', 'dmarc-explained'],
    findingIds: ['email_missing_dkim', 'email_dkim_weak_key', 'email_dkim_unknown_selector'],
  },

  // ── 5. DNSSEC Explained ───────────────────────────────────────────────────
  {
    slug: 'dnssec-explained',
    title: 'DNSSEC Explained',
    category: 'dns-security',
    summary: 'DNS Security Extensions (DNSSEC) add cryptographic signatures to DNS records, allowing resolvers to verify that responses have not been tampered with in transit. Without DNSSEC, DNS responses can be forged by attackers to redirect users and systems to malicious infrastructure — a technique known as DNS cache poisoning.',
    readTime: 8,
    featured: false,
    publishedAt: '2026-06-01',
    sections: [
      {
        heading: 'Why It Matters',
        blocks: [
          p('DNS is the address book of the internet — translating human-readable names into IP addresses. It was designed in an era when internet participants were trusted. DNSSEC retrofits authenticity into this system by signing records with cryptographic keys, enabling any resolver to verify the answer came from the authoritative source and was not modified in transit.'),
          p('DNS hijacking can redirect entire organisations\' internet traffic to attacker-controlled servers — not just web traffic, but email, VPN, authentication systems, and any other service that uses DNS for discovery. DNSSEC prevents this class of attack at the protocol level.'),
          callout('DNSSEC protects the integrity of DNS responses. It does not provide privacy (DNS over HTTPS/TLS does that), and it does not prevent a legitimate DNS record from pointing to a compromised server.', 'info'),
        ],
      },
      {
        heading: 'How Attackers Abuse It',
        blocks: [
          p('DNS cache poisoning attacks inject forged DNS responses into recursive resolvers, causing them to serve malicious IP addresses for legitimate domain names. The Kaminsky attack (2008) demonstrated that DNS resolvers could be poisoned in minutes without DNSSEC. While resolver implementations have improved, the fundamental protocol weakness remains.'),
          p('In BGP hijacking attacks combined with DNS manipulation, nation-state actors have redirected internet traffic for entire country code top-level domains. State-sponsored groups have used DNS hijacking to intercept email, VPN traffic, and authentication credentials for government agencies and critical infrastructure operators.'),
        ],
      },
      {
        heading: 'Real World Example',
        blocks: [
          p('In 2019, a widespread DNS hijacking campaign (later attributed to Iranian threat actors) targeted dozens of government, military, and private sector organisations globally. The attackers modified DNS A records and MX records to redirect traffic through attacker-controlled infrastructure, intercepting email and credentials before passing traffic to the legitimate destination. Several of the targeted domains lacked DNSSEC, making the modifications undetectable to users and systems.'),
        ],
      },
      {
        heading: 'What CyberMeters Detects',
        blocks: [
          p('CyberMeters validates DNSSEC configuration for every domain in your workspace:'),
          li([
            'DNSSEC not enabled (no DNSKEY or RRSIG records found)',
            'DNSSEC chain broken (DS record at parent does not match DNSKEY at zone)',
            'DNSSEC signatures expired',
            'Algorithm downgrade detected (using RSASHA1 instead of RSASHA256/ECDSAP256SHA256)',
          ]),
        ],
      },
      {
        heading: 'Remediation Overview',
        blocks: [
          p('DNSSEC is enabled at the DNS registrar and zone level. The process requires generating a Zone Signing Key (ZSK) and Key Signing Key (KSK), signing zone records, and publishing a DS record at the parent zone via your registrar.'),
          li([
            'Enable DNSSEC in your DNS hosting provider (Cloudflare, Route 53, Google Cloud DNS all support this)',
            'Publish the DS record through your domain registrar to complete the chain of trust',
            'Use ECDSAP256SHA256 (Algorithm 13) — preferred over RSA-based algorithms for performance',
            'Monitor key rollover dates — unsigned zones after a key expiry become broken',
            'Test with a DNSSEC validator (dnsviz.net) after enabling',
          ]),
        ],
      },
      {
        heading: 'Verification',
        blocks: [
          code('# Check DNSSEC validation\ndig +dnssec A example.com\n# Look for the AD (Authenticated Data) flag in the response\n\n# Check DS record at parent\ndig DS example.com +short\n\n# Full chain validation\ndig @8.8.8.8 +dnssec +multi A example.com', 'bash'),
          p('Use dnsviz.net for a visual representation of the DNSSEC chain. After enabling DNSSEC, re-scan in CyberMeters. The DNSSEC finding should be resolved, and the scan should show a validated chain from root to zone.'),
        ],
      },
    ],
    relatedSlugs: ['dns-hijacking', 'dangling-dns-records'],
    findingIds: ['dns_dnssec_not_enabled', 'dns_dnssec_chain_broken'],
  },

  // ── 6. HSTS Explained ────────────────────────────────────────────────────
  {
    slug: 'hsts-explained',
    title: 'HSTS Explained',
    category: 'security-headers',
    summary: 'HTTP Strict Transport Security (HSTS) instructs browsers to always connect to a domain over HTTPS, even if a user types the HTTP address or follows an HTTP link. It eliminates an entire class of protocol downgrade attacks and is one of the fastest, highest-impact security improvements a web team can deploy.',
    readTime: 6,
    featured: false,
    publishedAt: '2026-06-01',
    sections: [
      {
        heading: 'Why It Matters',
        blocks: [
          p('When a user visits your website over HTTP (the unencrypted default), an on-path attacker — on the same Wi-Fi network, at a malicious access point, or in a position to intercept traffic — can intercept and modify the connection before the HTTPS redirect occurs. This is known as an SSL stripping attack. HSTS prevents this by storing a browser-side instruction to always use HTTPS, with no opportunity for downgrade.'),
          p('Without HSTS, HTTPS is only as strong as the initial HTTP request. An attacker positioned between the user and server can strip TLS from the first connection, then proxy all subsequent traffic in cleartext — invisible to the user.'),
        ],
      },
      {
        heading: 'How Attackers Abuse It',
        blocks: [
          p('sslstrip (developed by Moxie Marlinspike in 2009) demonstrated that HTTPS could be silently stripped from connections in shared network environments. In a corporate Wi-Fi or hotel network scenario, an attacker running a man-in-the-middle proxy can convert all HTTPS connections to HTTP, capturing credentials, session cookies, and sensitive data — while the user\'s browser shows no warning.'),
          p('Without HSTS, even a perfectly configured TLS server is vulnerable to this attack on every user\'s first visit to a domain. HSTS eliminates this window entirely after the first visit, and HSTS preloading eliminates it even on the first visit.'),
        ],
      },
      {
        heading: 'Real World Example',
        blocks: [
          p('In 2017, a penetration testing engagement at a European bank demonstrated that internal employees connecting via the corporate network were susceptible to SSL stripping on the bank\'s own customer-facing portal. The portal had valid TLS but no HSTS header. Testers successfully intercepted session tokens for a simulated customer login. The finding was rated critical. Adding a single HSTS response header resolved the vulnerability.'),
        ],
      },
      {
        heading: 'What CyberMeters Detects',
        blocks: [
          li([
            'Missing HSTS header (no Strict-Transport-Security header present)',
            'HSTS max-age below recommended minimum (less than 1 year / 31536000 seconds)',
            'HSTS without includeSubDomains directive (subdomains may be downgraded)',
            'HSTS header present on HTTP response (invalid — must only be on HTTPS)',
            'Weak HSTS configuration (max-age=0, which effectively revokes HSTS)',
          ]),
        ],
      },
      {
        heading: 'Remediation Overview',
        blocks: [
          p('Add the Strict-Transport-Security header to all HTTPS responses. The recommended configuration for most organisations:'),
          code('# Add to your web server / reverse proxy HTTPS configuration:\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\n\n# Nginx example:\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;\n\n# Apache example:\nHeader always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"', 'nginx'),
          li([
            'Set max-age to at least 31536000 (one year)',
            'Include includeSubDomains to protect all subdomains',
            'Include preload if you intend to submit the domain to the HSTS preload list (https://hstspreload.org)',
            'Test with a staging environment first — HSTS is not easily reversed once the header is cached',
            'Ensure all subdomains support HTTPS before adding includeSubDomains',
          ]),
          callout('HSTS preloading hardcodes your domain into browsers so users never make an initial HTTP request, even on first visit. Preloading requires a max-age of at least 1 year and includeSubDomains. Removal from the preload list takes months to propagate.', 'info'),
        ],
      },
      {
        heading: 'Verification',
        blocks: [
          code('# Verify HSTS header\ncurl -I https://example.com | grep -i strict\n\n# Expected:\n# Strict-Transport-Security: max-age=31536000; includeSubDomains; preload', 'bash'),
          p('Re-scan in CyberMeters after deploying the header. Use securityheaders.com to validate the full security header configuration. Confirm the max-age value is at least 31536000 and the header is only served over HTTPS.'),
        ],
      },
    ],
    relatedSlugs: ['csp-explained', 'why-https-matters'],
    findingIds: ['header_missing_hsts', 'header_weak_hsts', 'header_hsts_no_subdomains'],
  },

  // ── 7. Content Security Policy Explained ─────────────────────────────────
  {
    slug: 'csp-explained',
    title: 'Content Security Policy Explained',
    category: 'security-headers',
    summary: 'Content Security Policy (CSP) is a browser security mechanism that restricts which resources a web page is allowed to load and execute. It is the primary defence against Cross-Site Scripting (XSS) attacks — where attackers inject malicious scripts into pages viewed by other users — and is one of the most impactful security headers available to web developers.',
    readTime: 9,
    featured: false,
    publishedAt: '2026-06-01',
    sections: [
      {
        heading: 'Why It Matters',
        blocks: [
          p('Cross-Site Scripting (XSS) remains one of the most prevalent web application vulnerabilities. An XSS vulnerability allows attackers to execute arbitrary JavaScript in the browser context of legitimate users — stealing session tokens, capturing keystrokes, redirecting to phishing pages, or exfiltrating data. CSP restricts what code the browser is permitted to execute, neutralising XSS even when injection points exist.'),
          p('Without CSP, a single XSS vulnerability in a web application gives an attacker full access to the application context — including cookies, local storage, the DOM, and any APIs the page calls. CSP transforms XSS from a full session takeover to a significantly contained event.'),
          callout('CSP does not prevent XSS injection — it limits the damage. A strict CSP policy means that even if an attacker successfully injects malicious content, the browser refuses to execute it.', 'info'),
        ],
      },
      {
        heading: 'How Attackers Abuse It',
        blocks: [
          p('In a reflected XSS attack, an attacker crafts a URL containing malicious JavaScript. When a victim clicks the link, the server reflects the script back in the HTML response and the browser executes it. In a stored XSS attack, the malicious content is saved in the application\'s database and executed every time a page loads for any user.'),
          p('Without CSP, these attacks can achieve account takeover (by stealing session cookies), credential harvesting (by injecting fake login forms), malware distribution (by loading malicious scripts from external domains), and data exfiltration (by sending captured data to attacker-controlled endpoints). CSP with strict-dynamic or nonce-based policies eliminates the ability to execute injected scripts even when they are present in the HTML.'),
        ],
      },
      {
        heading: 'Real World Example',
        blocks: [
          p('In 2021, a major e-commerce platform experienced a Magecart attack — a form of stored XSS where attackers injected a JavaScript payment card skimmer into the checkout page. The script silently captured credit card data from over 40,000 customers before detection. A Content Security Policy that blocked scripts from unauthorised external domains would have prevented the skimmer from loading entirely. The attack cost the company $18 million in settlements and fines.'),
        ],
      },
      {
        heading: 'What CyberMeters Detects',
        blocks: [
          p('CyberMeters evaluates the CSP header returned by each web-facing domain:'),
          li([
            'Missing Content-Security-Policy header',
            'CSP using unsafe-inline for script-src (defeats XSS protection)',
            'CSP using unsafe-eval (allows code evaluation from strings)',
            'CSP using a wildcard (*) in script-src (allows any script source)',
            'CSP present but in report-only mode (no enforcement, monitoring only)',
            'CSP missing default-src fallback directive',
          ]),
        ],
      },
      {
        heading: 'Remediation Overview',
        blocks: [
          p('CSP is delivered as an HTTP response header. Implementing a strict policy requires understanding every resource your page loads — scripts, styles, fonts, images, and API endpoints. Start with report-only mode to identify violations before enforcing.'),
          code('# Report-only mode (monitoring, no enforcement)\nContent-Security-Policy-Report-Only: default-src \'self\'; script-src \'self\' \'nonce-{random}\'; report-uri /csp-report\n\n# Enforcement mode (recommended target policy)\nContent-Security-Policy: default-src \'self\'; script-src \'self\' \'nonce-{random}\'; style-src \'self\' \'nonce-{random}\'; img-src \'self\' data: https:; connect-src \'self\'; font-src \'self\'; frame-ancestors \'none\'', 'http'),
          li([
            'Avoid unsafe-inline — use nonces or hashes to allow specific inline scripts',
            'Start with Content-Security-Policy-Report-Only and fix violations before switching to enforcement',
            'Use strict-dynamic with nonces for modern applications — it automatically trusts scripts loaded by trusted scripts',
            'Include frame-ancestors \'none\' or \'self\' to prevent clickjacking',
            'Report violations to a CSP reporting endpoint for ongoing monitoring',
          ]),
        ],
      },
      {
        heading: 'Verification',
        blocks: [
          code('# Check CSP header\ncurl -I https://example.com | grep -i "content-security-policy"\n\n# Test CSP in browser:\n# Open Developer Tools → Network tab → select a request → Headers\n# Look for Content-Security-Policy or Content-Security-Policy-Report-Only', 'bash'),
          p('Use Google\'s CSP Evaluator (csp-evaluator.withgoogle.com) to score your policy. CyberMeters will clear CSP findings once a policy that avoids unsafe-inline, unsafe-eval, and wildcard script-src is detected. Test for regressions after any dependency updates or CMS changes.'),
        ],
      },
    ],
    relatedSlugs: ['hsts-explained', 'clickjacking-risks'],
    findingIds: ['header_missing_csp', 'header_csp_unsafe_inline', 'header_csp_weak_policy'],
  },

  // ── 8. What is Subdomain Takeover? ────────────────────────────────────────
  {
    slug: 'what-is-subdomain-takeover',
    title: 'What is Subdomain Takeover?',
    category: 'subdomain-takeover',
    summary: 'Subdomain takeover occurs when an attacker gains control of a subdomain belonging to a legitimate organisation because the subdomain\'s DNS record points to a service that has been decommissioned or is unclaimed. The attacker claims the underlying resource on the third-party platform, effectively serving content — including malicious content — under the victim organisation\'s trusted domain.',
    readTime: 10,
    featured: true,
    publishedAt: '2026-06-01',
    sections: [
      {
        heading: 'Why It Matters',
        blocks: [
          p('Subdomain takeover is uniquely dangerous because the attacker operates under the victim\'s trusted domain. A browser visiting https://careers.example.com does not know that example.com\'s IT team forgot to remove a DNS entry. The attacker\'s content appears to originate from a legitimate company domain, complete with a valid TLS certificate obtained in the victim\'s subdomain name.'),
          p('This trust inheritance makes subdomain takeovers ideal for highly credible phishing campaigns, cookie theft (via same-site cookie policies), and bypassing email security controls. It is one of the few attack scenarios where an attacker can serve content under your brand without breaching any of your actual infrastructure.'),
          callout('Subdomain takeovers are discovered and exploited by bug bounty researchers and malicious actors alike. Vulnerability disclosure programmes at major organisations receive dozens of valid subdomain takeover submissions annually.', 'warning'),
        ],
      },
      {
        heading: 'How Attackers Abuse It',
        blocks: [
          p('The typical attack follows three steps. First, the attacker scans DNS records for subdomains pointing to third-party services (GitHub Pages, Azure, Heroku, Fastly, S3). Second, they probe the target service to see if the claimed resource (repository, app, bucket) still exists. When the resource is absent, the third-party platform serves a "404 Not Found" or "unclaimed" response. Third, the attacker creates an account on the third-party platform and claims the resource name — meaning all traffic to the victim\'s subdomain now lands on attacker-controlled infrastructure.'),
          p('Once in control, attackers can serve phishing pages, harvest session cookies via JavaScript (cookies scoped to the parent domain), obtain valid TLS certificates from Let\'s Encrypt (which only verify DNS control), send email from the subdomain, or use the subdomain as a command-and-control server.'),
        ],
      },
      {
        heading: 'Real World Example',
        blocks: [
          p('In 2018, a researcher demonstrated subdomain takeover vulnerabilities across dozens of Fortune 500 companies, including several where critical subdomains like shop., api., and staging. were pointing to unclaimed Heroku or Azure resources. Multiple companies paid bug bounties of $5,000–$10,000 per finding. In one case, a subdomain was taken over and used to serve a convincing credential harvesting page for several days before detection.'),
          p('Microsoft\'s own azure.com domain has had subdomain takeover findings reported against it by security researchers, demonstrating that the problem affects organisations of every size and sophistication.'),
        ],
      },
      {
        heading: 'What CyberMeters Detects',
        blocks: [
          p('CyberMeters identifies dangling DNS records and vulnerable subdomain configurations:'),
          li([
            'CNAME records pointing to unclaimed GitHub Pages repositories',
            'CNAME records pointing to unclaimed Azure App Service, Azure Blob Storage, or Azure CDN resources',
            'CNAME records pointing to deleted or unclaimed Heroku applications',
            'CNAME records pointing to unclaimed Fastly, Pantheon, Shopify, or other CDN/hosting providers',
            'CNAME records pointing to decommissioned AWS Elastic Beanstalk environments or S3 website endpoints',
            'A records pointing to IP addresses with no active host (unclaimed Elastic IPs)',
          ]),
          p('Findings are enriched with the specific third-party service, the CNAME chain, and the evidence from the HTTP response that confirms the resource is unclaimed.'),
        ],
      },
      {
        heading: 'Remediation Overview',
        blocks: [
          p('The remediation for a subdomain takeover vulnerability is to either reclaim the resource or remove the DNS record. Removal is always the correct action for decommissioned services.'),
          li([
            'Remove the CNAME or A record from DNS immediately for decommissioned services',
            'If the subdomain is still needed, reclaim the resource on the third-party platform before making it live again',
            'Implement a DNS change control policy — all DNS record removals must be reviewed for dangling records',
            'Maintain a mapping of all subdomains to their intended services and owners',
            'Run regular ASM scans to detect new dangling records within 24 hours of introduction',
          ]),
        ],
      },
      {
        heading: 'Verification',
        blocks: [
          code('# Check what a CNAME resolves to\ndig CNAME staging.example.com\n\n# Test if the resource is claimed\ncurl -v https://staging.example.com\n# If response contains platform-specific 404 text (e.g., "There\'s nothing here", "No such app"),\n# the subdomain is vulnerable to takeover', 'bash'),
          p('After removing the DNS record, verify it no longer resolves using nslookup or dig. CyberMeters will confirm the finding is resolved in the next scan cycle. For reclaimed resources, verify the expected content is served at the subdomain.'),
        ],
      },
    ],
    relatedSlugs: ['what-is-attack-surface-management', 'azure-takeovers', 'github-pages-takeovers'],
    findingIds: ['subdomain_takeover_detected', 'dangling_cname_github', 'dangling_cname_azure', 'dangling_cname_heroku'],
  },

  // ── 9. Public Cloud Storage Risks ─────────────────────────────────────────
  {
    slug: 'public-cloud-storage-risks',
    title: 'Public Cloud Storage Risks',
    category: 'cloud-storage-security',
    summary: 'Misconfigured cloud storage buckets — publicly accessible AWS S3 buckets, Azure Blob Storage containers, and Google Cloud Storage buckets — represent one of the most common and consequential data exposure risks in modern organisations. Data breach after data breach traces back to the same root cause: a storage bucket set to public read, often unintentionally.',
    readTime: 9,
    featured: false,
    publishedAt: '2026-06-01',
    sections: [
      {
        heading: 'Why It Matters',
        blocks: [
          p('Cloud storage services default to private access for a reason — their default state is safe. Breaches occur when developers, DevOps engineers, or automated processes change bucket permissions to public for convenience and forget to reverse the change, or when legacy infrastructure predating secure defaults was never reviewed.'),
          p('A publicly readable storage bucket means any file stored within it is accessible to anyone on the internet without authentication. This includes backup archives, database exports, application logs, configuration files containing API keys and credentials, customer data exports, and internal documents.'),
          callout('Cloud storage is searchable. Services like Grayhat Warfare and GrayhatWarfare index public bucket contents. Your exposed data may already be indexed and discoverable via a simple search.', 'warning'),
        ],
      },
      {
        heading: 'How Attackers Abuse It',
        blocks: [
          p('Attackers systematically enumerate cloud storage buckets by guessing names based on company domain, product names, and common patterns (e.g., company-backups, company-prod-logs, company-archive). Cloud provider APIs allow public bucket listing and file download without authentication when bucket policies permit it.'),
          p('Automated tools like S3Scanner, bucket-stream, and cloud_enum can enumerate thousands of bucket names per minute, downloading any publicly accessible files. Once credentials, API keys, or sensitive data are found, attackers use them for lateral movement, data theft, or resale on dark web markets.'),
        ],
      },
      {
        heading: 'Real World Example',
        blocks: [
          p('In 2019, Capital One experienced a breach affecting over 100 million customers. While the root cause was a Server-Side Request Forgery (SSRF) vulnerability rather than a public bucket, the attacker was able to extract data from S3 because the compromised IAM role had overly permissive access. The breach cost Capital One over $300 million in settlement, fines, and remediation costs.'),
          p('In 2020, an unprotected AWS S3 bucket belonging to a US defence contractor was discovered to contain 1.8 billion social media records gathered by a surveillance programme. The data included personal information from Twitter, Facebook, and other platforms — all accessible to anyone who knew the bucket name.'),
        ],
      },
      {
        heading: 'What CyberMeters Detects',
        blocks: [
          p('CyberMeters discovers and probes cloud storage assets referenced in DNS records, web page source code, and JavaScript files associated with your domains:'),
          li([
            'Publicly accessible S3 buckets associated with your organisation\'s domains',
            'Azure Blob Storage containers with anonymous read access',
            'Google Cloud Storage buckets with allUsers read access',
            'Bucket listing enabled (allows enumeration of all files in the bucket)',
            'S3 website endpoints pointing to unclaimed bucket names (subdomain takeover risk)',
            'Storage buckets in DNS with no active hosting (dangling CNAME)',
          ]),
        ],
      },
      {
        heading: 'Remediation Overview',
        blocks: [
          li([
            'Set all storage buckets to private by default — enable S3 Block Public Access at account level',
            'Audit existing buckets for public access: use AWS Trusted Advisor, Azure Security Centre, or GCP Security Command Centre',
            'Remove public ACLs: aws s3api put-bucket-acl --bucket BUCKET --acl private',
            'Enable S3 Block Public Access at both bucket and account level',
            'Use bucket policies to restrict access to specific IAM roles or VPC endpoints',
            'Enable CloudTrail / Storage Audit Logs to detect future policy changes',
            'For public content delivery, use CloudFront / Azure CDN / Cloud CDN with signed URLs',
          ]),
          code('# AWS: Block all public access at account level\naws s3control put-public-access-block \\\n  --account-id YOUR_ACCOUNT_ID \\\n  --public-access-block-configuration \\\n  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"\n\n# Check existing bucket ACL\naws s3api get-bucket-acl --bucket YOUR_BUCKET_NAME', 'bash'),
        ],
      },
      {
        heading: 'Verification',
        blocks: [
          code('# Test if a bucket is publicly accessible\ncurl -I https://YOUR_BUCKET_NAME.s3.amazonaws.com/\n# 403 Forbidden = private (correct)\n# 200 OK or ListBucketResult = public (misconfigured)', 'bash'),
          p('Re-scan in CyberMeters after applying private access settings. Use the AWS S3 console to verify Block Public Access shows all four settings as "On". For Azure, verify the container access level shows "Private (no anonymous access)".'),
        ],
      },
    ],
    relatedSlugs: ['what-is-attack-surface-management', 'cloud-storage-misconfigurations'],
    findingIds: ['cloud_storage_public_bucket', 'cloud_storage_bucket_listing', 's3_public_read'],
  },

  // ── 10. Microsoft 365 Exposure Risks ──────────────────────────────────────
  {
    slug: 'microsoft-365-exposure-risks',
    title: 'Microsoft 365 Exposure Risks',
    category: 'identity-discovery',
    summary: 'Microsoft 365 is the world\'s most widely deployed enterprise productivity suite — and its public-facing infrastructure reveals significant information about an organisation\'s identity and authentication configuration. From tenant enumeration to Autodiscover configuration, these exposures give attackers intelligence that accelerates credential-based attacks.',
    readTime: 8,
    featured: false,
    publishedAt: '2026-06-01',
    sections: [
      {
        heading: 'Why It Matters',
        blocks: [
          p('Microsoft 365 deployments leave a distinctive fingerprint across DNS records (MX, TXT), Autodiscover endpoints, and Azure AD metadata APIs. This fingerprint is by design — it enables email routing and authentication to work. However, it also provides attackers with actionable intelligence about the organisation\'s identity infrastructure before they attempt a single login.'),
          p('Understanding that a target organisation uses Microsoft 365, which tenant they belong to, whether MFA is enforced, and which identity federation configuration is in use gives attackers a precise roadmap for password spraying, phishing, and Business Email Compromise campaigns.'),
        ],
      },
      {
        heading: 'How Attackers Abuse It',
        blocks: [
          p('Microsoft 365 tenant enumeration is trivially easy. The Azure AD OpenID Connect metadata endpoint returns tenant information for any registered domain. Tools like o365spray and AADInternals use this information to enumerate valid usernames, test credentials against multiple M365 services, and identify whether legacy authentication (Basic Auth) is enabled — a common gap that bypasses MFA.'),
          p('Password spraying attacks against M365 are pervasive. Attackers use known username formats (first.last@company.com) combined with commonly used passwords, spreading attempts across many accounts to avoid lockout policies. When legacy authentication endpoints are reachable, these attacks bypass even modern MFA policies.'),
          li([
            'Tenant enumeration via login.microsoftonline.com/TENANT/v2.0/.well-known/openid-configuration',
            'Username enumeration via Autodiscover and GetMSOLUserByEmail endpoints',
            'Password spraying via /common/oauth2/token (Basic Auth endpoints)',
            'Phishing kits that clone M365 login pages targeting discovered user accounts',
            'SSPR (Self-Service Password Reset) abuse to reset passwords for discovered accounts',
          ]),
        ],
      },
      {
        heading: 'Real World Example',
        blocks: [
          p('In 2020, the SolarWinds supply chain attack\'s impact was significantly amplified because attackers used forged SAML tokens to access Microsoft 365 email and documents at hundreds of organisations. Discovery of M365 deployment in reconnaissance phases was the first step in targeting decisions. Organisations without proper M365 security configuration — conditional access policies, legacy auth blocking, and MFA enforcement — were disproportionately affected.'),
          p('In 2022, Microsoft reported that 99.9% of compromised accounts that used MFA were not breached via credential attacks. Legacy authentication (which bypasses MFA) was the primary vector for the remaining breached accounts.'),
        ],
      },
      {
        heading: 'What CyberMeters Detects',
        blocks: [
          li([
            'Microsoft 365 tenant presence confirmed via DNS MX records and autodiscover configuration',
            'Legacy authentication endpoints accessible (indicates MFA bypass risk)',
            'Autodiscover endpoint exposed without HTTPS redirect',
            'Azure AD tenant ID enumerable (enables targeted phishing and spraying)',
            'Microsoft Online Services presence flagged as part of identity attack surface report',
          ]),
        ],
      },
      {
        heading: 'Remediation Overview',
        blocks: [
          li([
            'Enable MFA for all users in Azure AD — use Conditional Access policies, not per-user MFA settings',
            'Block legacy authentication: create a Conditional Access policy blocking all legacy auth protocols (POP3, IMAP, SMTP AUTH, Basic Auth)',
            'Enable Microsoft Defender for Identity to detect password spraying and enumeration attempts',
            'Enable SSPR with additional verification steps (not just email verification)',
            'Restrict Autodiscover to HTTPS and internal IP ranges where possible',
            'Enable Azure AD Identity Protection risk-based Conditional Access policies',
            'Review and remove unused service accounts and application registrations',
          ]),
          callout('Blocking legacy authentication can break older email clients and applications. Audit which clients and services use legacy auth before enforcing the block. Use Azure AD sign-in logs filtered by client app to identify legacy auth usage.', 'warning'),
        ],
      },
      {
        heading: 'Verification',
        blocks: [
          code('# Check if MX record indicates M365\ndig MX example.com +short\n# If result ends in mail.protection.outlook.com = M365 confirmed\n\n# Check autodiscover\ncurl -I https://autodiscover.example.com/autodiscover/autodiscover.xml\n# Should return 401 with HTTPS only, not HTTP redirect', 'bash'),
          p('In the Azure AD admin centre, verify that Conditional Access policies blocking legacy authentication are in place and applied to all users. Check the Azure AD sign-in logs for any successful legacy auth logins in the past 30 days. Re-scan in CyberMeters — M365 identity exposure findings will reflect updated configuration.'),
        ],
      },
    ],
    relatedSlugs: ['password-spraying', 'okta-exposure', 'identity-attack-surface'],
    findingIds: ['identity_microsoft_365_detected', 'identity_legacy_auth_exposed', 'identity_autodiscover_exposed'],
  },

  // ── 11. Vendor Risk Explained ──────────────────────────────────────────────
  {
    slug: 'vendor-risk-explained',
    title: 'Vendor Risk Explained',
    category: 'vendor-risk',
    summary: 'Vendor risk — also known as third-party risk — is the exposure an organisation inherits from the companies it does business with. When you share data with a supplier, integrate their software into your systems, or rely on their infrastructure, their security posture becomes part of your attack surface. Managing this inherited risk is a core responsibility of modern security programmes.',
    readTime: 9,
    featured: false,
    publishedAt: '2026-06-01',
    sections: [
      {
        heading: 'Why It Matters',
        blocks: [
          p('Organisations increasingly rely on third-party vendors for critical business functions — cloud infrastructure, payroll, HR, customer data processing, legal services, and software development. Each of these relationships creates a connection between your organisation\'s data and systems and another organisation\'s security posture. A breach at a vendor can expose your data, disrupt your operations, or compromise your customers — even if your own defences are perfect.'),
          p('Regulators including the ICO, FCA, and SOC 2 auditors hold organisations responsible for the security of personal and sensitive data even when that data is held by third parties. This means vendor risk is not just a security concern — it is a legal and compliance obligation.'),
          callout('The average organisation shares sensitive data with 583 third-party vendors. Only 34% of organisations have a formal third-party risk management programme that reviews vendor security annually.', 'info'),
        ],
      },
      {
        heading: 'How Attackers Abuse It',
        blocks: [
          p('Attackers target the weakest link in the supply chain. Instead of attacking a well-defended enterprise directly, they identify which third-party vendors have access to that enterprise\'s data or systems, and attack the vendor. A single successful vendor breach can cascade to hundreds or thousands of downstream customers.'),
          p('Attack patterns include: compromising vendor software development pipelines to distribute malicious updates (supply chain attack), breaching vendor infrastructure that holds customer data (data supply chain breach), and using stolen vendor credentials or API keys to access customer environments (credential supply chain).'),
        ],
      },
      {
        heading: 'Real World Example',
        blocks: [
          p('Target\'s 2013 data breach — the largest retail breach in history at the time, affecting 40 million credit card accounts — began through an HVAC vendor. The vendor had remote access to Target\'s network for energy management purposes. Attackers compromised the vendor, used those credentials to enter Target\'s network, and moved laterally to point-of-sale systems. The breach cost Target over $200 million.'),
          p('The lesson: the security of your most privileged vendors determines the security of your own organisation. Network-connected vendors deserve the same security scrutiny as internal systems.'),
        ],
      },
      {
        heading: 'What CyberMeters Detects',
        blocks: [
          p('CyberMeters provides vendor risk intelligence across your technology stack:'),
          li([
            'Third-party services detected in DNS records, JavaScript includes, and web page source (tracking pixels, CDNs, analytics)',
            'Vendor domains with poor security posture (missing email authentication, weak TLS)',
            'Shared infrastructure between your domains and known high-risk vendor platforms',
            'Exposure of vendor management portals (SaaS admin interfaces accessible from internet)',
            'Vendor subprocessors identified in privacy disclosures and cookie consent banners',
          ]),
        ],
      },
      {
        heading: 'Remediation Overview',
        blocks: [
          li([
            'Maintain a vendor inventory: document every third party with access to your data, systems, or network',
            'Classify vendors by risk tier: critical (access to sensitive data or production systems), high, medium, low',
            'Conduct security questionnaires for critical vendors annually — use standardised frameworks (CIS Controls, ISO 27001, SIG Lite)',
            'Review vendor SOC 2 Type II reports where available',
            'Include security requirements in vendor contracts — right to audit, breach notification timelines, minimum security standards',
            'Implement least-privilege for vendor network access — use VPN segmentation or identity-based access rather than full network access',
            'Monitor for vendor breaches using threat intelligence feeds',
          ]),
        ],
      },
      {
        heading: 'Verification',
        blocks: [
          p('For each critical vendor, verify the following annually: current SOC 2 Type II report, evidence of penetration test completion, MFA enforcement on vendor systems with access to your data, and incident response contact details.'),
          p('In CyberMeters, review the Vendor Risk dashboard for your workspace. Set risk ratings for identified vendors and track posture changes over time. Configure alerts for critical vendor domain changes — a new IP address or certificate for a vendor\'s API endpoint can indicate infrastructure changes that require security review.'),
        ],
      },
    ],
    relatedSlugs: ['supply-chain-attacks-explained', 'third-party-risk', 'shadow-it'],
    findingIds: ['vendor_risk_detected', 'third_party_service_detected', 'saas_exposure_detected'],
  },

  // ── 12. Supply Chain Attacks Explained ────────────────────────────────────
  {
    slug: 'supply-chain-attacks-explained',
    title: 'Supply Chain Attacks Explained',
    category: 'supply-chain-intelligence',
    summary: 'Supply chain attacks target the software, services, or infrastructure that organisations rely on — rather than attacking the organisation directly. By compromising a trusted supplier, attackers gain access to all downstream customers simultaneously. They represent one of the most sophisticated and impactful threat categories in modern cybersecurity.',
    readTime: 11,
    featured: true,
    publishedAt: '2026-06-01',
    sections: [
      {
        heading: 'Why It Matters',
        blocks: [
          p('Software supply chain attacks exploit the trust organisations place in their vendors and development tools. Every software dependency, development platform, CI/CD tool, and managed service represents a potential supply chain entry point. When attackers compromise the supply chain, they inherit all of the trust relationships downstream customers have built with the compromised vendor.'),
          p('Supply chain attacks are particularly dangerous because they are difficult to detect (malicious code is signed by the legitimate vendor), difficult to scope (the blast radius is all downstream customers), and difficult to remediate (the fix requires both the vendor and every customer to take action simultaneously).'),
          callout('Supply chain attacks often have a long dwell time. The SolarWinds attack had a backdoor active for at least 9 months before detection. During this time, attackers had persistent access to thousands of organisations.', 'warning'),
        ],
      },
      {
        heading: 'How Attackers Abuse It',
        blocks: [
          p('Supply chain attacks take several forms. Software dependency attacks inject malicious code into open-source libraries (npm, PyPI, RubyGems) — either by compromising maintainer accounts or by registering typosquatting packages that developers accidentally install. Build pipeline attacks compromise CI/CD infrastructure to insert malicious code during the build and packaging phase. Update mechanism attacks modify legitimate software updates to distribute backdoors.'),
          p('In service supply chain attacks, attackers compromise a managed service provider (MSP) or SaaS platform to gain access to all downstream clients. Once inside an MSP\'s infrastructure, a single set of credentials can provide access to hundreds or thousands of client environments.'),
          li([
            'Malicious npm package published with legitimate-looking name (typosquatting)',
            'Compromised build server injects malicious code into signed release',
            'SaaS platform breached — attacker gains API access to all tenant accounts',
            'MSP management infrastructure compromised — attacker accesses all managed environments',
            'Open-source maintainer account takeover — malicious code merged to trusted repository',
          ]),
        ],
      },
      {
        heading: 'Real World Example',
        blocks: [
          p('SolarWinds (2020): Attackers (later attributed to Russian SVR) compromised SolarWinds\' build pipeline and inserted malicious code into the Orion software update package. The update was distributed to approximately 18,000 organisations. Approximately 100 organisations were subsequently targeted for deeper exploitation, including US government agencies, major technology companies, and defence contractors. The attack went undetected for 9 months.'),
          p('MOVEit (2023): A zero-day SQL injection vulnerability in Progress Software\'s MOVEit Transfer file transfer software was exploited by the Cl0p ransomware group. Over 2,000 organisations were affected across healthcare, finance, government, and education sectors. The attackers did not need to breach each organisation individually — they exploited a single product and harvested data from all customers using it.'),
          p('Kaseya VSA (2021): A zero-day vulnerability in Kaseya\'s IT management software was exploited to distribute REvil ransomware to approximately 1,500 organisations through 60 MSP customers. Attackers specifically targeted an MSP management platform to maximise blast radius from a single intrusion point.'),
        ],
      },
      {
        heading: 'What CyberMeters Detects',
        blocks: [
          p('CyberMeters monitors your organisation\'s external-facing supply chain footprint:'),
          li([
            'Third-party software components detected in web page source (JavaScript libraries, CDN-hosted scripts)',
            'Software vendors identified in DNS, SSL certificates, and HTTP headers',
            'Known vulnerable vendor components detected in use (matched against public CVE data)',
            'Vendor infrastructure changes that may indicate compromise (new IP, new certificate, DNS change)',
            'MSP-managed infrastructure identified in your workspace (shared certificates, management platforms)',
          ]),
        ],
      },
      {
        heading: 'Remediation Overview',
        blocks: [
          li([
            'Maintain a software bill of materials (SBOM) for all applications — track every dependency and its version',
            'Use dependency scanning tools (Snyk, GitHub Dependabot, OWASP Dependency-Check) in CI/CD pipelines',
            'Pin dependency versions and review changes before upgrading',
            'Subscribe to vendor security advisories for all critical suppliers',
            'Implement network segmentation — vendor management access should not have unrestricted internal network access',
            'Test incident response plans for supply chain breach scenarios — the response is different from a direct breach',
            'Assess MSP and SaaS vendors for supply chain security practices',
          ]),
          callout('No single control prevents all supply chain attacks. Defence in depth — combining code signing verification, network segmentation, monitoring, and rapid response capability — is the appropriate strategy.', 'info'),
        ],
      },
      {
        heading: 'Verification',
        blocks: [
          p('In CyberMeters, review the Supply Chain Intelligence dashboard for your workspace. Identified vendor relationships are listed with associated risk indicators. For each critical vendor, verify you are subscribed to their security advisories and have an incident response runbook for a vendor compromise scenario.'),
          p('Conduct an annual tabletop exercise simulating a supply chain breach scenario — specifically a scenario where one of your critical SaaS providers or software dependencies is compromised. This tests whether your organisation can detect, scope, and respond effectively when the attack vector is outside your direct control.'),
        ],
      },
    ],
    relatedSlugs: ['vendor-risk-explained', 'third-party-risk', 'solarwinds'],
    findingIds: ['supply_chain_vendor_detected', 'third_party_js_detected', 'known_vulnerable_component'],
  },

]

// ── Lookup helpers ────────────────────────────────────────────────────────────

export function getArticle(slug) {
  return ARTICLES.find(a => a.slug === slug) ?? null
}

export function getArticlesByCategory(categorySlug) {
  return ARTICLES.filter(a => a.category === categorySlug)
}

export function getFeaturedArticles() {
  return ARTICLES.filter(a => a.featured)
}

export function searchArticles(query) {
  if (!query || query.trim().length < 2) return ARTICLES
  const q = query.trim().toLowerCase()
  return ARTICLES.filter(a =>
    a.title.toLowerCase().includes(q) ||
    a.summary.toLowerCase().includes(q) ||
    a.category.toLowerCase().includes(q)
  )
}

export function getRelatedArticles(slug) {
  const article = getArticle(slug)
  if (!article || !article.relatedSlugs) return []
  return article.relatedSlugs
    .map(s => getArticle(s))
    .filter(Boolean)
}

export function getCategoryMeta(slug) {
  return CATEGORIES.find(c => c.slug === slug) ?? null
}

// ── Finding-to-Academy mapping (Sprint 11A) ───────────────────────────────────

/**
 * Exact finding ID → article slug.
 * Computed once at module load from each article's findingIds[].
 * Includes manual overrides for finding IDs that differ from the
 * Worker's emitted ID vs. the v1 article findingIds naming.
 */
export const FINDING_TO_ACADEMY = {
  // ── Manual overrides — Worker IDs that differ from article findingIds ──────
  // Email security
  email_intel_spf_missing:             'spf-explained',
  email_intel_spf_permissive:          'spf-explained',
  email_intel_dmarc_missing:           'dmarc-explained',
  email_intel_dmarc_reporting_only:    'dmarc-explained',
  email_intel_dkim_not_found:          'dkim-explained',
  email_weak_dmarc:                    'dmarc-explained',
  email_dmarc_policy_none:             'dmarc-explained',
  email_dkim_not_detected:             'dkim-explained',
  email_no_dkim:                       'dkim-explained',
  email_no_dmarc:                      'dmarc-explained',
  email_no_spf:                        'spf-explained',
  // DNSSEC (Worker uses dnssec_ prefix, articles used dns_dnssec_ prefix)
  dnssec_not_enabled:                  'dnssec-explained',
  dnssec_misconfigured:                'dnssec-explained',
  // Headers
  header_missing_strict_transport_security: 'hsts-explained',
  header_weak_hsts:                    'hsts-explained',
  dse_hsts_short_maxage:               'hsts-explained',
  dse_hsts_not_preload_eligible:       'hsts-explained',
  header_missing_content_security_policy: 'csp-explained',
  csp_weak_policy:                     'csp-explained',
  // Subdomain takeover
  subdomain_takeover:                  'what-is-subdomain-takeover',
  subdomain_takeover_risk:             'what-is-subdomain-takeover',
  // Cloud storage
  cloud_storage_exposure_observed:     'public-cloud-storage-risks',
  cloud_storage_public_listing:        'public-cloud-storage-risks',
  cloud_storage_takeover_risk:         'public-cloud-storage-risks',
  cloud_storage_detected:              'public-cloud-storage-risks',
  // Identity / M365
  identity_microsoft_365_detected:     'microsoft-365-exposure-risks',
  identity_legacy_auth_exposed:        'microsoft-365-exposure-risks',
  identity_autodiscover_exposed:       'microsoft-365-exposure-risks',
  // ASM / admin surfaces
  admin_surface_critical:              'what-is-attack-surface-management',
  admin_surface_high:                  'what-is-attack-surface-management',
  admin_surface_medium:                'what-is-attack-surface-management',
  asset_exposure_admin_interface:      'what-is-attack-surface-management',
  asset_exposure_dev_env:              'what-is-attack-surface-management',
  asset_exposure_sensitive_tool:       'what-is-attack-surface-management',
  subdomains_large_attack_surface:     'what-is-attack-surface-management',
  // Vendor / supply chain
  vendor_risk_detected:                'vendor-risk-explained',
  third_party_service_detected:        'vendor-risk-explained',
  saas_exposure_detected:              'vendor-risk-explained',
  supply_chain_vendor_detected:        'supply-chain-attacks-explained',
  third_party_js_detected:             'supply-chain-attacks-explained',
  known_vulnerable_component:          'supply-chain-attacks-explained',
  // ── Auto-generated from article findingIds[] ─────────────────────────────
  ...Object.fromEntries(
    ARTICLES.flatMap(a => (a.findingIds || []).map(id => [id, a.slug]))
  ),
}

/**
 * Module-level fallback mapping.
 * Used when no exact or prefix match is found for a finding ID.
 */
const MODULE_TO_ACADEMY = {
  email_security:              'spf-explained',
  email_security_intelligence: 'dmarc-explained',
  headers:                     'hsts-explained',
  dns:                         'dnssec-explained',
  subdomain_takeover:          'what-is-subdomain-takeover',
  cloud_storage_discovery:     'public-cloud-storage-risks',
  admin_surface_detection:     'what-is-attack-surface-management',
  technology_detection:        'what-is-attack-surface-management',
}

/**
 * getAcademyArticleForFinding(finding)
 *
 * Returns the Academy article slug for a given scan finding, or null if none.
 *
 * Lookup order:
 *   1. Exact match on finding.id in FINDING_TO_ACADEMY
 *   2. Prefix match — strips trailing segments of finding.id and retries
 *      (e.g. email_intel_spf_permissive → email_intel_spf → email_intel → email)
 *   3. Module fallback — MODULE_TO_ACADEMY[finding.module]
 *   4. null — render no link
 */
export function getAcademyArticleForFinding(finding) {
  if (!finding) return null
  const id     = finding.id     ?? ''
  const module = finding.module ?? ''

  // Tier 1 — exact match
  if (id && FINDING_TO_ACADEMY[id]) return FINDING_TO_ACADEMY[id]

  // Tier 2 — prefix match (most-specific first)
  if (id) {
    const parts = id.split('_')
    for (let len = parts.length - 1; len >= 1; len--) {
      const prefix = parts.slice(0, len).join('_')
      if (FINDING_TO_ACADEMY[prefix]) return FINDING_TO_ACADEMY[prefix]
    }
  }

  // Tier 3 — module fallback
  if (module && MODULE_TO_ACADEMY[module]) return MODULE_TO_ACADEMY[module]

  return null
}
