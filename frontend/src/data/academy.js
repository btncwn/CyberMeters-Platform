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
 *   aliases       — Earlier slugs that still open the article (optional)
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
  { slug: 'vendor-risk',               label: 'Third-party risk',               icon: 'Briefcase',   color: 'orange' },
  { slug: 'supply-chain-intelligence', label: 'Third-party dependencies', icon: 'Link',        color: 'rose'   },
  { slug: 'cyber-essentials',          label: 'Cyber Essentials',          icon: 'ClipboardCheck', color: 'green' },
  { slug: 'using-cybermeters',         label: 'Using CyberMeters',         icon: 'Link',        color: 'brand'  },
]

// ── Articles ─────────────────────────────────────────────────────────────────

export const ARTICLES = [

  // ── Using CyberMeters: AI assistant access (MCP) ──────────────────────────
  // Facts match the consent page (api.cybermeters.com/authorize) and the
  // Support page's setup steps; this article explains, Support shows how.
  {
    slug: 'connect-your-ai-assistant',
    title: 'Connect your AI assistant (MCP)',
    category: 'using-cybermeters',
    summary: 'You can give an AI assistant you already use read-only access to your CyberMeters evidence, through the Model Context Protocol (MCP). It can answer questions about your posture in plain language. It cannot change anything.',
    readTime: 4,
    featured: false,
    publishedAt: '2026-10-22',
    sections: [
      {
        heading: 'What it is',
        blocks: [
          p('MCP is an open standard that lets an AI assistant read from a service you approve. With CyberMeters connected, you can ask your assistant questions such as "what needs fixing first?" or "why is email protection provisional?" and it answers from your workspace\'s evidence.'),
          p('Access is available for eligible workspaces. Your assistant\'s own account and administrator settings may also limit it.'),
        ],
      },
      {
        heading: 'What it can read',
        blocks: [
          li([
            'The workspaces you approve, and their domains',
            'Security posture for every area, findings and the evidence behind them',
            'Recent scans and their status, and managed cases',
            'Certificate and email posture, and existing report summaries',
            'For an MSP: a portfolio summary of only the customer workspaces you separately approve',
          ]),
          callout('Answers keep the same evidence rules as the product: something CyberMeters did not observe is never presented as healthy, and a customer\'s own statement is never presented as CyberMeters verification.', 'info'),
        ],
      },
      {
        heading: 'What it cannot do',
        blocks: [
          p('The connection is read-only. It cannot start scans, change DNS, create or close cases, manage users, change settings or fix issues.'),
        ],
      },
      {
        heading: 'What you approve',
        blocks: [
          li([
            'You sign in to CyberMeters and choose one workspace, or, for portfolio access, up to 50 customer workspaces. None are selected for you.',
            'The name shown for the app is the name it registered for itself. CyberMeters has not verified it, so connect only an app you started yourself.',
            'The app receives a 15-minute access token and can renew read access for up to 7 days from your approval. After 7 days you reconnect.',
          ]),
        ],
      },
      {
        heading: 'Your data and removing access',
        blocks: [
          p('The app, or the company that provides it, may keep what it receives under its own terms and settings. Check those before you connect.'),
          p('To stop access, open Account → AI assistant (MCP) and select Remove access, then remove the connection in the app too. This stops future CyberMeters reads. It cannot delete data the app has already received.'),
        ],
      },
      {
        heading: 'Set it up',
        blocks: [
          p('The server address and the setup steps for each assistant are on the Support page, under "Connect your AI assistant": cybermeters.com/support#mcp.'),
          callout('Never paste a password or an access token into a chat, and never send one to support.', 'warning'),
        ],
      },
    ],
    relatedSlugs: [],
  },

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
        heading: 'Illustrative example',
        blocks: [
          p('Suppose a retired project leaves a public test hostname in DNS. An external inventory reveals the responding host, and its owner confirms that the service is no longer needed. The team removes the exposure and checks the resulting DNS and service evidence; the initial observation alone does not establish that a breach occurred.'),
        ],
      },
      {
        heading: 'What CyberMeters Detects',
        blocks: [
          p('CyberMeters runs ASM scans of your verified domains, when you ask and on the schedule you set. Each scan looks for:'),
          li([
            'Subdomains discovered via DNS enumeration, DNS records and links on your website',
            'HTTP and HTTPS services responding on discovered hosts, with technology fingerprinting',
            'Exposed administrative interfaces and login pages',
            'Dangling DNS records pointing to decommissioned cloud resources',
            'The certificate your website presents: whether it matches the name, when it expires and whether it is trusted',
            'Email security posture (SPF, DMARC, DKIM)',
            'Security header configuration across web-facing endpoints',
            'Cloud storage your website or DNS points to, and whether it can be read publicly',
          ]),
          p('All findings are scored by severity and come with confidence ratings, evidence and remediation guidance. The platform tracks asset changes from scan to scan, so new exposure is found on the next scan after it appears. A scan sees what is visible from the internet at that moment; names nothing points to, and services that answer only some networks, can be missed.'),
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
    summary: 'Sender Policy Framework (SPF) publishes which sending systems are authorised for a domain used in the SMTP envelope sender. Receiving services can check the connecting server against that policy. SPF does not authenticate the visible From address or stop lookalike-domain impersonation.',
    readTime: 7,
    featured: true,
    publishedAt: '2026-06-01',
    sections: [
      {
        heading: 'Why It Matters',
        blocks: [
          p('An attacker can claim a domain in an email sender address without controlling its mail service. SPF gives receiving services an authorisation signal for the envelope-sender domain by identifying permitted sending infrastructure.'),
          p('Without a valid SPF record, receivers lack that SPF signal. They may still apply DKIM, DMARC, reputation and other filtering. An SPF pass alone does not establish that a message is safe or that its visible From address is authentic.'),
          callout('SPF checks the envelope sender, not the displayed From address. DMARC checks whether a passing SPF or DKIM identity aligns with that visible address and lets the domain owner request handling and reporting.', 'warning'),
        ],
      },
      {
        heading: 'How Attackers Abuse It',
        blocks: [
          p('An unauthorised server may claim your domain as its envelope sender. A restrictive SPF policy can produce a fail result for that server, but the receiver decides how to handle the message. A forged visible From address or a lookalike domain requires other checks; it is not resolved by SPF alone.'),
          p('Non-sending domains also need an intentional email policy. Publishing v=spf1 -all declares that no sending server is authorised for that envelope-sender domain. Combine it with an appropriate DMARC policy for visible From alignment.'),
        ],
      },
      {
        heading: 'Illustrative example',
        blocks: [
          p('Suppose an unauthorised mail server claims example.com as its envelope-sender domain. A published SPF policy that excludes that server can produce SPF fail. If the visible From address instead uses a lookalike domain, SPF for example.com does not address that impersonation.'),
        ],
      },
      {
        heading: 'What CyberMeters Detects',
        blocks: [
          p('CyberMeters checks the SPF record for every domain in your workspace. The following conditions are flagged:'),
          li([
            'Missing SPF record (no TXT record starting with v=spf1)',
            'SPF soft fail (~all), rather than a hard-fail (-all) policy',
            'SPF neutral (?all) — SPF provides no guidance to receivers',
            'SPF evaluation exceeds the budget of 10 DNS-lookup-causing terms, including nested includes and redirects (a permanent SPF evaluation error)',
            'Multiple SPF records (invalid — only one TXT SPF record is permitted)',
            'SPF record includes deprecated mechanisms (ptr:)',
          ]),
        ],
      },
      {
        heading: 'Remediation Overview',
        blocks: [
          p('Publish a TXT record beginning with v=spf1 that covers your legitimate sending sources. After validating them, choose an appropriate final all mechanism: -all produces SPF fail for unmatched sources, while ~all produces softfail. Receiving services apply their own delivery policy.'),
          code('# For a domain using Google Workspace:\nv=spf1 include:_spf.google.com -all\n\n# For a domain using Microsoft 365:\nv=spf1 include:spf.protection.outlook.com -all\n\n# For a non-sending domain (no legitimate email):\nv=spf1 -all', 'dns'),
          li([
            'Use -all to declare unmatched sources unauthorised; it does not guarantee receiver rejection',
            'Keep SPF evaluation within the budget of 10 DNS-lookup-causing terms, including nested includes and redirects',
            'Use include: mechanisms for third-party senders (CRMs, marketing platforms)',
            'Audit sending sources before finalising the record — omitting a legitimate sender can cause authentication and delivery problems',
            'Deploy DMARC alongside SPF for visible From alignment, requested handling and requested reporting',
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
    summary: 'Domain-based Message Authentication, Reporting, and Conformance (DMARC) checks whether a passing SPF or DKIM identity aligns with the visible From domain. Domain owners can publish a requested handling policy and reporting addresses; receiving services apply their own delivery and reporting policies.',
    readTime: 10,
    featured: true,
    publishedAt: '2026-06-01',
    sections: [
      {
        heading: 'Why It Matters',
        blocks: [
          p('DMARC checks whether SPF or DKIM passes with an identity aligned to the visible From domain. If neither aligned method passes, p=quarantine or p=reject requests handling by the receiving service. This helps reduce direct-domain spoofing; the receiver applies its own delivery policy, and DMARC does not stop lookalike domains or misuse of an authorised account.'),
          p('DMARC can request aggregate reports through rua and failure reports through ruf. Reports that arrive can reveal authentication and alignment problems. Publishing an address does not establish that a receiver sends reports or that your reporting service receives them.'),
          callout('A DMARC policy of p=none requests monitoring without requesting quarantine or rejection. Aggregate reports can help you identify legitimate senders and authentication problems before choosing a stricter requested policy.', 'info'),
        ],
      },
      {
        heading: 'How Attackers Abuse It',
        blocks: [
          p('An attacker can forge the visible From address independently of the SPF envelope sender. DMARC evaluates alignment between that visible domain and a passing SPF or DKIM identity, then exposes the domain owner\'s requested handling policy to receivers.'),
          p('A common attack pattern is a message with a forged visible From address such as "payroll@yourcompany.com". When neither SPF nor DKIM passes with an aligned identity, DMARC p=reject requests rejection. It does not prove that every receiver will reject the message.'),
        ],
      },
      {
        heading: 'Illustrative example',
        blocks: [
          p('Suppose a message displays a From address at example.com but passes SPF only for an unrelated envelope-sender domain and has no aligned DKIM pass. DMARC fails, so a published p=reject policy requests rejection. The receiver decides delivery, and a configured reporting address does not prove a report was received.'),
        ],
      },
      {
        heading: 'What CyberMeters Detects',
        blocks: [
          p('CyberMeters evaluates DMARC configuration for every domain in your workspace:'),
          li([
            'Missing DMARC record (no _dmarc.yourdomain TXT record)',
            'DMARC policy set to p=none (monitoring; no quarantine or rejection requested)',
            'A legacy pct tag, which RFC 9989 removed (receivers that follow it ignore the value)',
            'No reporting address configured (rua, ruf); configured addresses request reports but do not prove receipt',
            'Subdomain policy (sp) not separately set — subdomains inherit the applicable DMARC policy',
            'Invalid or malformed DMARC record syntax',
          ]),
        ],
      },
      {
        heading: 'Remediation Overview',
        blocks: [
          p('DMARC is implemented as a TXT record on the _dmarc subdomain of your domain. The recommended migration path is p=none → p=quarantine → p=reject, using reporting data to identify legitimate sending sources before tightening enforcement.'),
          code('# Step 1: Request monitoring (p=none)\n_dmarc.example.com TXT "v=DMARC1; p=none; rua=mailto:dmarc@example.com; ruf=mailto:dmarc@example.com; fo=1"\n\n# Step 2: Request quarantine after validating legitimate senders\n_dmarc.example.com TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"\n\n# Step 3: Request rejection\n_dmarc.example.com TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; sp=reject"', 'dns'),
          li([
            'Set rua to request aggregate reports, then separately confirm that reports arrive and can be parsed',
            'Review received reports and validate legitimate sending paths before requesting stricter handling',
            'Set sp when you need a distinct requested subdomain policy; otherwise the applicable policy is inherited',
            'p=none requests monitoring without requesting quarantine or rejection',
          ]),
        ],
      },
      {
        heading: 'Verification',
        blocks: [
          code('# Verify DMARC record\ndig TXT _dmarc.example.com +short\n\n# Expected output example:\n"v=DMARC1; p=reject; rua=mailto:dmarc@example.com; sp=reject"', 'bash'),
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
    summary: 'DomainKeys Identified Mail (DKIM) attaches a cryptographic signature that receivers can verify using a public key in DNS. A valid signature authenticates the signing domain and the signed portions of the message. It does not by itself authenticate the visible From address or establish that the content is safe.',
    readTime: 7,
    featured: false,
    publishedAt: '2026-06-01',
    sections: [
      {
        heading: 'Why It Matters',
        blocks: [
          p('DKIM complements SPF by authenticating the message content rather than just the sending server. Where SPF says "this IP is allowed to send for this domain," DKIM says "this message was signed by the private key held by this domain." Together, they provide two independent authentication signals that DMARC can align.'),
          p('DKIM provides a message-signature signal separate from SPF. A signature can survive forwarding when the signed content remains compatible with verification; changes by a forwarder or mailing list can invalidate it. DMARC can use a passing aligned DKIM signature even when SPF does not align.'),
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
        heading: 'Illustrative example',
        blocks: [
          p('Suppose a mail service changes its DKIM signing key but the published selector still contains the previous key. Signature verification can fail. Delivery depends on the receiver and other authentication results, so the operator checks the selector, signing configuration and test-message headers before declaring the change complete.'),
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
          p('DNS translates human-readable names into addresses and other service records. DNSSEC signs DNS data so a validating resolver can check its authenticity through a chain of trust. Requesting DNSSEC records alone does not establish that validation took place.'),
          p('Forged DNS answers can direct clients to unintended infrastructure. With a valid chain of trust, DNSSEC lets validating resolvers reject answers that fail signature validation. This protection depends on validation and does not cover every way DNS records can change.'),
          callout('DNSSEC authenticates signed DNS data; it does not encrypt it. Correctly signed changes made through an operator or registrar account can still validate, including changes pointing to a compromised server. DNSSEC is not an approval check for the intended destination.', 'info'),
        ],
      },
      {
        heading: 'How Attackers Abuse It',
        blocks: [
          p('A cache-poisoning attempt supplies forged DNS answers so a resolver may cache an unintended destination. DNSSEC validation can reject a forged answer for a securely delegated signed zone when the attacker cannot produce valid signatures.'),
          p('Compromising a DNS operator or registrar account is a different path: an attacker may alter records or delegation through authorised interfaces. Correctly signed resulting data can pass DNSSEC validation, so account protection and change review remain necessary.'),
        ],
      },
      {
        heading: 'Illustrative example',
        blocks: [
          p('Suppose an attacker supplies a forged answer for a securely delegated, signed zone. A validating resolver can reject an answer without a valid signature. If an operator account instead changes the authoritative record and the zone signs it correctly, DNSSEC can still validate it; account and change controls address that separate risk.'),
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
    summary: 'HTTP Strict Transport Security (HSTS) tells supporting browsers to use HTTPS for hosts covered by an active policy. A stored or preloaded policy reduces exposure to HTTP-starting downgrade attacks. It does not replace valid TLS configuration or fix application vulnerabilities.',
    readTime: 6,
    featured: false,
    publishedAt: '2026-06-01',
    sections: [
      {
        heading: 'Why It Matters',
        blocks: [
          p('When navigation starts over HTTP, an on-path attacker may intercept that unencrypted request before an HTTPS redirect reaches the browser. A supporting browser with an active HSTS policy upgrades covered requests to HTTPS before sending them.'),
          p('HSTS learned from a secure response helps subsequent requests while the policy remains active. It does not protect an initial HTTP visit before a policy is known unless an applicable preload policy or another browser protection already covers the host.'),
        ],
      },
      {
        heading: 'How Attackers Abuse It',
        blocks: [
          p('In an HTTP-starting session without an applicable upgrade protection, an on-path attacker may alter links or redirects to keep the browser on an unencrypted connection. This does not mean an attacker can silently convert an already authenticated HTTPS connection into HTTP.'),
          p('An active HSTS policy reduces this HTTP-starting path for covered hosts in supporting browsers. Preloading can extend that protection to an initial visit, but the host must be in the browser\'s applicable preload data and continue to serve valid HTTPS.'),
        ],
      },
      {
        heading: 'Illustrative example',
        blocks: [
          p('Suppose a visitor follows an HTTP bookmark. A supporting browser with an active HSTS policy upgrades the covered request to HTTPS before sending it. A browser without that policy may still make the initial HTTP request, and the service must continue to provide valid TLS and secure application behaviour.'),
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
          callout('HSTS preloading can apply HTTPS upgrade rules before a supporting browser first visits a covered host. Check the preload service requirements and ensure every covered subdomain supports HTTPS. Browser preload updates and removals are not immediate.', 'info'),
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
    summary: 'Content Security Policy (CSP) restricts resource loading and script execution in supporting browsers. A carefully configured, enforced policy can reduce some Cross-Site Scripting (XSS) paths and their impact. It complements secure application code; it does not guarantee that all injected content is harmless.',
    readTime: 9,
    featured: false,
    publishedAt: '2026-06-01',
    sections: [
      {
        heading: 'Why It Matters',
        blocks: [
          p('An XSS flaw can let attacker-controlled script run in a page and interact with data or actions available to that page. An enforced CSP can block execution or loading that violates its directives, reducing some exploitation paths.'),
          p('The result depends on the policy and application. Allowed scripts, trusted script loaders and application behaviour can still expose attack paths. Fix injection flaws and test the policy rather than treating a CSP header as proof that XSS is contained.'),
          callout('CSP does not remove injection flaws. It can block disallowed script behaviour, but permitted code or policy weaknesses may still be exploitable. Report-only policies record violations without enforcing those restrictions.', 'info'),
        ],
      },
      {
        heading: 'How Attackers Abuse It',
        blocks: [
          p('In a reflected XSS attack, an attacker crafts a URL containing malicious JavaScript. When a victim clicks the link, the server reflects the script back in the HTML response and the browser executes it. In a stored XSS attack, the malicious content is saved in the application\'s database and executed every time a page loads for any user.'),
          p('XSS can expose page data or allow actions in the user\'s session. Nonce- or hash-based script policies can block unapproved scripts, but their effectiveness depends on correct deployment and how trusted scripts handle untrusted content. These policies do not replace application fixes.'),
        ],
      },
      {
        heading: 'Illustrative example',
        blocks: [
          p('Suppose a page is altered to load an unapproved external script. A correctly enforced CSP that disallows that source can block the load. If an allowed script is compromised or handles untrusted data unsafely, the policy may not block the resulting behaviour; the underlying application issue still needs remediation.'),
        ],
      },
      {
        heading: 'What CyberMeters Detects',
        blocks: [
          p('CyberMeters evaluates the CSP header returned by each web-facing domain:'),
          li([
            'Missing Content-Security-Policy header',
            'CSP using unsafe-inline for script-src (can weaken restrictions on inline script execution)',
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
            'Use frame-ancestors to restrict which sites may embed the page and reduce framing-based attacks',
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
          callout('A dangling DNS record deserves review, but an error page alone does not prove that an outsider can claim the resource. Check the provider-specific evidence and intended ownership without attempting an unauthorised takeover.', 'warning'),
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
        heading: 'Illustrative example',
        blocks: [
          p('Suppose a retired service leaves a CNAME pointing at an unclaimed hosting resource. The DNS chain and provider response warrant ownership review, but an error response alone does not prove claimability. The owner removes the stale record or restores the intended resource, then checks complete DNS and service evidence without attempting an unauthorised claim.'),
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
          p('Attackers can automate guesses at storage names and test the access permitted by a service. Exposed files may reveal sensitive data or secrets that create further risk. Public metadata, listing permission and access to a particular object are different observations.'),
        ],
      },
      {
        heading: 'Illustrative example',
        blocks: [
          p('Suppose a backup object is made anonymously readable while publishing public website assets. An unauthenticated read of that object would expose its contents, even if bucket listing were disabled. The owner separates public assets from backups, restricts access and verifies the affected object and listing permissions independently.'),
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
    title: 'Microsoft 365 Provider Evidence',
    category: 'identity-discovery',
    summary: 'Public Microsoft 365 provider and identity-surface evidence, with separately authorised account observations and clear limits on what each source establishes.',
    readTime: 8,
    featured: false,
    publishedAt: '2026-06-01',
    sections: [
      {
        heading: 'What CyberMeters can observe',
        blocks: [
          p('CyberMeters can identify an observed or possible provider relationship from external evidence such as bounded MX, SPF, CNAME and Content Security Policy values. Exact host and label-boundary matches are stronger provider-identification evidence than substring or token matches.'),
          p('A hostname pattern can also create a possible identity-facing hostname for review. DNS resolution is reported separately. Neither provider identification, hostname classification nor DNS resolution establishes that an HTTP endpoint is reachable.'),
          p('On verified domains, bounded OIDC discovery can record a valid public issuer document and its advertised authorisation endpoint. It does not follow the advertised login or token flows.'),
          p('Separately, eligible workspace administrators can authorise a Microsoft account read. It can return available direct-role names and MFA registration when Microsoft permissions and licensing allow. Registration is not evidence that MFA is enforced.'),
        ],
      },
      {
        heading: 'What CyberMeters cannot observe',
        blocks: [
          p('Public provider, hostname and OIDC evidence does not establish successful sign-in, secure tenant policy or account compromise. Automatic public identity discovery does not attempt account authentication.'),
          p('The optional Microsoft account read does not assess MFA enforcement, Conditional Access or sign-in history, and it does not provide an employee-password breach feed. Missing provider permissions or licence data remains unavailable.'),
          li([
            'Provider relationship: observed, possible or unknown',
            'Hostname classification: possible or unknown',
            'Name resolution: resolved, MX-only, not evaluated or legacy unknown',
            'Endpoint reachability: shown only where the scan collected HTTP evidence',
          ]),
        ],
      },
      {
        heading: 'Illustrative example',
        blocks: [
          p('Suppose public mail records indicate a hosted mail provider. That observation helps an owner locate the relevant administration tools; it does not establish the tenant\'s security settings. A separately authorised account read may show a registered authentication method without proving that policy requires its use.'),
        ],
      },
      {
        heading: 'How to use the evidence',
        blocks: [
          li([
            'Confirm whether the provider relationship is expected',
            'Assign a business, technical or identity owner',
            'Review possible identity-facing hostnames without treating them as measured endpoints',
            'Check tenant policy directly in the Microsoft administration tools when your governance requires it',
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
          code('# Inspect the MX provider relationship\ndig MX example.com +short\n# A host within mail.protection.outlook.com supports a Microsoft mail-provider relationship\n# It does not establish tenant identity, tenant policy or account security\n\n# Observe an Autodiscover HTTP response without credentials\ncurl -I https://autodiscover.example.com/autodiscover/autodiscover.xml\n# A 401 response or redirect alone does not establish correct configuration or successful sign-in', 'bash'),
          p('Provider configuration and sign-in controls must be verified in the Microsoft administration tools. An ordinary public scan may refresh provider, hostname, OIDC or measured HTTP evidence; it does not verify tenant policy or successful sign-in. Optional account observations and Website Security test-account checks remain separate scopes.'),
        ],
      },
    ],
    relatedSlugs: ['password-spraying', 'okta-exposure', 'identity-attack-surface'],
    findingIds: ['identity_microsoft_365_detected', 'identity_legacy_auth_exposed', 'identity_autodiscover_exposed'],
  },

  // ── 11. Third-party risk explained ──────────────────────────────────────────────
  {
    slug: 'vendor-risk-explained',
    title: 'Third-party risk explained',
    category: 'vendor-risk',
    summary: 'Third-party risk — is the exposure an organisation inherits from the companies it does business with. When you share data with a supplier, integrate their software into your systems, or rely on their infrastructure, their security posture becomes part of your attack surface. Managing this inherited risk is a core responsibility of modern security programmes.',
    readTime: 9,
    featured: false,
    publishedAt: '2026-06-01',
    sections: [
      {
        heading: 'Why It Matters',
        blocks: [
          p('Organisations increasingly rely on third-party vendors for critical business functions — cloud infrastructure, payroll, HR, customer data processing, legal services, and software development. Each of these relationships creates a connection between your organisation\'s data and systems and another organisation\'s security posture. A breach at a vendor can expose your data, disrupt your operations, or compromise your customers — even if your own defences are perfect.'),
          p('Depending on your organisation, law, contracts or assurance requirements may call for a review of third-party access and data handling. External provider discovery does not establish that those requirements are met.'),
          callout('Prioritise vendor review by the data, permissions and operational dependency involved. An externally observed provider relationship is a starting point for ownership review, not a rating of the provider\'s security.', 'info'),
        ],
      },
      {
        heading: 'How Attackers Abuse It',
        blocks: [
          p('An attacker may target a vendor with access to another organisation\'s data or systems. The downstream impact depends on the compromised permissions, integrations and safeguards; it is not established by the existence of a provider relationship.'),
          p('Attack patterns include: compromising vendor software development pipelines to distribute malicious updates (third-party compromise), breaching vendor infrastructure that holds customer data (data third-party breach), and using stolen vendor credentials or API keys to access customer environments (credential third-party dependency).'),
        ],
      },
      {
        heading: 'Illustrative example',
        blocks: [
          p('Suppose a supplier account can access an internal document service. If the account is compromised, the data exposed depends on its granted permissions and the surrounding controls. The customer reviews access, removes unnecessary privileges and checks activity; observing the supplier in public DNS does not reveal those internal controls.'),
        ],
      },
      {
        heading: 'What CyberMeters Detects',
        blocks: [
          p('CyberMeters observes, from the outside, the third-party services your domains visibly rely on:'),
          li([
            'Services named in your DNS records, such as email, verification and SaaS records',
            'Scripts and services your public web pages load, such as analytics, tag managers and CDNs',
            'SaaS and identity providers your domains point to',
          ]),
          p('It does not rate vendors or assess their security, and it does not read contracts, privacy notices or subprocessor lists. Each service shows a tier for its kind of service; that tier is a catalogue label, not an assessment of the provider.'),
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
          p('In CyberMeters, review Shadow IT & Unmanaged Technology for your workspace. Third-party providers, SaaS portals and scripts observed on your domains are listed there so you can classify each one as approved, under review or unmanaged, assign an owner and keep the inventory current as your external footprint changes.'),
        ],
      },
    ],
    relatedSlugs: ['supply-chain-attacks-explained', 'third-party-risk', 'shadow-it'],
    findingIds: ['vendor_risk_detected', 'third_party_service_detected', 'saas_exposure_detected'],
  },

  // ── 12. Attacks through third parties explained ────────────────────────────────────
  {
    slug: 'supply-chain-attacks-explained',
    title: 'Attacks through third parties explained',
    category: 'supply-chain-intelligence',
    summary: 'Third-party compromises target software, services or infrastructure that an organisation relies on. Compromising a supplier can expose customers through trusted updates or access. The impact depends on the affected dependency, permissions and safeguards.',
    readTime: 11,
    featured: true,
    publishedAt: '2026-06-01',
    sections: [
      {
        heading: 'Why It Matters',
        blocks: [
          p('Software third-party compromises exploit the trust organisations place in their vendors and development tools. Every software dependency, development platform, CI/CD tool, and managed service represents a potential third-party dependency entry point. When attackers compromise the third-party dependency, they inherit all of the trust relationships downstream customers have built with the compromised vendor.'),
          p('A compromised build may produce malicious code signed with a legitimate release key, so a signature alone does not establish that the code is safe. Response requires identifying affected versions and access paths, then coordinating action with the supplier and affected customers.'),
          callout('Trusted suppliers and signed updates still need scoped access, change review and incident response planning. External provider evidence alone cannot establish that a supplier is compromised or uncompromised.', 'warning'),
        ],
      },
      {
        heading: 'How Attackers Abuse It',
        blocks: [
          p('Third-party compromises take several forms. Software dependency attacks inject malicious code into open-source libraries (npm, PyPI, RubyGems) — either by compromising maintainer accounts or by registering typosquatting packages that developers accidentally install. Build pipeline attacks compromise CI/CD infrastructure to insert malicious code during the build and packaging phase. Update mechanism attacks modify legitimate software updates to distribute backdoors.'),
          p('A compromised managed service provider (MSP) or SaaS account may expose downstream environments reachable with its permissions. Segmentation, tenant isolation and limited privileges can restrict that reach; compromise does not automatically establish access to every client.'),
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
        heading: 'Illustrative example',
        blocks: [
          p('Suppose an attacker alters a software supplier\'s build process and a customer installs the resulting update. Impact depends on the affected software and the permissions it runs with. Release verification, scoped access and an incident response plan help manage the risk; a public provider inventory cannot determine whether the update is compromised.'),
        ],
      },
      {
        heading: 'What CyberMeters Detects',
        blocks: [
          p('CyberMeters observes the third-party components your public website and DNS expose:'),
          li([
            'Third-party scripts and CDN-hosted libraries in your public web pages',
            'Software vendors named in your DNS records and HTTP headers',
            'Software versions that servers publish in their responses (reported as a disclosure, not as a confirmed vulnerability)',
          ]),
          p('It does not detect a compromise inside a vendor, watch a vendor\'s infrastructure for changes, or identify systems an MSP manages for you.'),
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
            'Test incident response plans for third-party breach scenarios — the response is different from a direct breach',
            'Assess MSP and SaaS vendors for third-party dependency security practices',
          ]),
          callout('No single control prevents all third-party compromises. Defence in depth — combining code signing verification, network segmentation, monitoring, and rapid response capability — is the appropriate strategy.', 'info'),
        ],
      },
      {
        heading: 'Verification',
        blocks: [
          p('In CyberMeters, the providers and third-party scripts observed on your domains appear under Shadow IT & Unmanaged Technology, and externally visible technologies appear in Attack Surface. For each critical provider, verify you are subscribed to its security advisories and have an incident response runbook for a provider compromise scenario.'),
          p('Conduct an annual tabletop exercise simulating a third-party breach scenario — specifically a scenario where one of your critical SaaS providers or software dependencies is compromised. This tests whether your organisation can detect, scope, and respond effectively when the attack vector is outside your direct control.'),
        ],
      },
    ],
    relatedSlugs: ['vendor-risk-explained', 'third-party-risk', 'solarwinds'],
    findingIds: ['supply_chain_vendor_detected', 'third_party_js_detected', 'known_vulnerable_component'],
  },

  // ── SEO: external security check ───────────────────────────────────────────────────────
  {
    slug: 'what-is-an-external-security-check',
    title: 'What is an external security check and why your business needs one',
    category: 'cyber-essentials',
    summary: 'An external security check is a quick, plain-English check of how safe and trusted your business looks from the outside — email, website, TLS, DNS, certificates and Cyber Essentials readiness gaps.',
    readTime: 5,
    featured: true,
    publishedAt: '2026-07-08',
    sections: [
      {
        heading: 'What an External Security Check Covers',
        blocks: [
          p('An external security check is a simple way to check whether your business looks safe, trusted and well configured from the outside.'),
          p('An external security check does not make a business perfect, and it does not claim your business is fully secure. It checks important visible signals that are often missed: your email protection, website security, TLS, DNS settings, certificates and Cyber Essentials readiness gaps.'),
          p('For any business, this matters because your domain is part of your reputation. Your website, email setup and public records are often the first things customers, suppliers, insurers and attackers can see. A weak setup can make your business easier to impersonate, easier to distrust and harder to work with.'),
        ],
      },
      {
        heading: 'Why Every Business Needs It',
        blocks: [
          p('Cyber security can feel like too big a job. Many teams think they need a large consultancy project before they can understand their position. In reality, the first step should be simpler: check the public-facing basics, explain the findings in plain English and fix the highest-risk gaps first. That is the purpose of an external security check.'),
          li([
            'Is your business email protected against spoofing? SPF, DKIM and DMARC help receiving mail services decide whether a message really came from your domain.',
            'Does your website give the right trust signals? A modern site should use HTTPS properly, avoid expired certificates and include sensible browser protections.',
            'Are your DNS records clean and understandable? Incorrect records create email delivery problems, trust issues and avoidable operational risk.',
            'Are your certificates healthy? Expired or misconfigured certificates break websites and damage customer confidence.',
            'Are you ready for Cyber Essentials? An external security check should not certify you; it should help you spot gaps before you start the formal self-assessment route.',
          ]),
        ],
      },
      {
        heading: 'Cyber Essentials Readiness, Not Certification',
        blocks: [
          p('This distinction is important. CyberMeters provides readiness support, not certification. Certification is delivered through the official Cyber Essentials scheme and its approved Certification Bodies.'),
          callout('An external security check helps you spot readiness gaps before the formal route. It is not a Cyber Essentials certificate and should not be treated as one.', 'info'),
        ],
      },
      {
        heading: 'What You Get From an External Security Check',
        blocks: [
          p('For most businesses, the real value of an external security check is clarity. You do not need to understand every technical detail. You need to know whether your domain is protected, whether customers can trust your online presence and whether there are obvious gaps that should be fixed.'),
          p('For MSPs, an external security check is also a useful client conversation starter. Instead of leading with fear, the MSP can show a simple report: here is what is good, here is what needs attention and here is the plan.'),
          p('The best external security check is not about creating panic. It is about making cyber hygiene visible, affordable and repeatable. Run it once to understand your current posture. Run it regularly to catch changes. Use it before supplier reviews, insurance renewals, Cyber Essentials preparation or customer security questions.'),
          p('You do not need enterprise complexity to make progress. You need a clear starting point. That is what an external security check gives you.'),
        ],
      },
    ],
    relatedSlugs: [],
    findingIds: [],
  },

  // ── SEO: DMARC and email impersonation ───────────────────────────────────
  {
    slug: 'dmarc-stop-email-impersonation',
    aliases: ['dmarc-explained-for-uk-small-businesses'],
    title: 'DMARC: make it much harder for criminals to send email as your business',
    category: 'email-security',
    summary: 'DMARC helps stop criminals sending emails that appear to come from your domain. It is one of the most practical ways to reduce impersonation risk and improve trust in business email.',
    readTime: 6,
    featured: false,
    publishedAt: '2026-07-08',
    sections: [
      {
        heading: 'What DMARC Does',
        blocks: [
          p('DMARC stands for Domain-based Message Authentication, Reporting and Conformance. It lets a domain owner request handling when a message fails to authenticate with an identity aligned to the visible From domain. Receiving services apply their own delivery policy.'),
          p('SPF checks sending infrastructure for an envelope-sender domain. DKIM verifies a signing domain and signed message content. DMARC checks whether a passing SPF or DKIM identity aligns with the visible From domain that recipients see.'),
          callout('DMARC publishes a requested handling policy and can request reporting. A DNS record proves neither that every receiver follows the request nor that reports have arrived.', 'info'),
        ],
      },
      {
        heading: 'Why It Matters for Your Business',
        blocks: [
          p('Businesses are attractive targets for impersonation because customers and suppliers often trust familiar names. If your domain has weak email authentication, criminals may be able to send convincing fake invoices, payment changes or password reset messages that appear to come from your business.'),
          p('DMARC also supports deliverability. Mail providers increasingly expect domains to have modern authentication in place. A clear DMARC setup helps legitimate email look more trustworthy and helps suspicious email get handled correctly.'),
          li([
            'Protect customers and suppliers from fake emails using your domain',
            'Reduce the risk of business email compromise and invoice fraud',
            'Improve visibility into who is sending email on behalf of your domain',
            'Support better delivery of legitimate business email',
          ]),
        ],
      },
      {
        heading: 'The Three DMARC Policies',
        blocks: [
          p('A DMARC record usually starts in monitoring mode, then moves towards enforcement once you understand your legitimate senders.'),
          li([
            'p=none requests no quarantine or rejection; reports may arrive when reporting is configured and receivers send them.',
            'p=quarantine requests that receivers quarantine messages that fail DMARC.',
            'p=reject requests that receivers reject messages that fail DMARC; receivers retain their own delivery policy.',
          ]),
          callout('For many businesses, p=none is a useful starting point, but it is not the final goal. Protection improves when you move carefully towards quarantine or reject.', 'info'),
        ],
      },
      {
        heading: 'How to Approach DMARC Safely',
        blocks: [
          p('Do not jump straight to reject if you are unsure who sends email for your domain. First identify your legitimate senders: Microsoft 365, Google Workspace, CRM tools, invoicing platforms, marketing systems and support desks.'),
          li([
            'Confirm SPF covers your legitimate sending services',
            'Enable DKIM signing where your mail provider supports it',
            'Publish DMARC in monitoring mode and review aggregate reports',
            'Fix legitimate services that fail authentication',
            'Move towards quarantine or reject once reports are clean',
          ]),
          p('An external security check can highlight whether DMARC is missing, weak or only in monitoring mode. That gives you a practical starting point without needing to read raw DNS records yourself.'),
        ],
      },
    ],
    relatedSlugs: [],
    findingIds: [],
  },

  // ── SEO: Cyber Essentials Readiness ──────────────────────────────────────
  {
    slug: 'cyber-essentials-what-you-actually-need-to-pass',
    title: 'Cyber Essentials: what you actually need to pass',
    category: 'cyber-essentials',
    summary: 'Cyber Essentials is the UK baseline for practical cyber hygiene. To prepare well, you need to understand the five control areas and close obvious gaps before starting the formal assessment route.',
    readTime: 7,
    featured: false,
    publishedAt: '2026-07-08',
    sections: [
      {
        heading: 'What Cyber Essentials Covers',
        blocks: [
          p('Cyber Essentials is a UK government-backed scheme designed to help organisations protect themselves against common online threats. It focuses on practical controls rather than complex enterprise security programmes.'),
          p('The scheme is built around five technical control areas: firewalls, secure configuration, user access control, malware protection and security update management. These are the basics that reduce many common risks when they are applied consistently.'),
          li([
            'Firewalls that block unwanted inbound access',
            'Secure configuration of devices, services and cloud systems',
            'User access control so people only have the access they need',
            'Malware protection on devices and supported platforms',
            'Security updates applied promptly to software and operating systems',
          ]),
        ],
      },
      {
        heading: 'What You Actually Need to Prepare',
        blocks: [
          p('Passing Cyber Essentials is not about buying one tool. It is about knowing what technology you use, removing unnecessary exposure and being able to answer the self-assessment questions accurately.'),
          p('Start with an inventory. Know your laptops, desktops, phones, tablets, servers, cloud services, routers, firewalls and admin accounts. If you do not know what you have, you cannot confidently say it is configured safely.'),
          li([
            'Remove or protect exposed admin panels and remote access services',
            'Check that unsupported software and operating systems are no longer in use',
            'Make sure default passwords are changed and multi-factor authentication is used where appropriate',
            'Limit administrator privileges to people who genuinely need them',
            'Keep evidence of patching, malware protection and access control decisions',
          ]),
        ],
      },
      {
        heading: 'Where Businesses Commonly Fail',
        blocks: [
          p('Many businesses struggle because their public-facing basics and internal controls do not match what they believe is in place. A forgotten service, old DNS record, exposed login page or unsupported device can create a gap that only becomes visible late in the process.'),
          li([
            'Assuming Microsoft 365 or Google Workspace is secure without checking the settings',
            'Leaving old remote access tools exposed to the internet',
            'Keeping unused accounts with administrator privileges',
            'Missing security updates on laptops, servers or network devices',
            'Treating Cyber Essentials as paperwork rather than operational hygiene',
          ]),
          callout('CyberMeters provides Cyber Essentials readiness support, not certification. Certification is handled through the official Cyber Essentials scheme and its approved Certification Bodies.', 'info'),
        ],
      },
      {
        heading: 'How an External Security Check Helps',
        blocks: [
          p('An external security check cannot answer every internal Cyber Essentials question for you, but it can highlight visible gaps that often cause trouble: weak email protection, certificate issues, risky DNS records, missing website protections and externally visible services.'),
          p('Use the report before the formal route so you can fix obvious issues early. That makes the assessment conversation simpler, reduces last-minute surprises and gives directors, insurers or suppliers a clearer view of progress.'),
          li([
            'Run an external security check before starting the self-assessment',
            'Fix high-priority website, email, DNS and certificate issues first',
            'Review internal controls against the five Cyber Essentials areas',
            'Keep repeating checks so new gaps do not appear unnoticed',
          ]),
        ],
      },
    ],
    relatedSlugs: [],
    findingIds: [],
  },

]

// ── Lookup helpers ────────────────────────────────────────────────────────────

export function getArticle(slug) {
  return ARTICLES.find(a => a.slug === slug || a.aliases?.includes(slug)) ?? null
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
  // Third parties
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
