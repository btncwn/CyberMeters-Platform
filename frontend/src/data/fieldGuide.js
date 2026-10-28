/**
 * CyberMeters Field Guide — the customer guide to the eight areas.
 *
 * One entry per canonical customer-facing area, in the order the product shows
 * them (founder order, 14 Oct 2026: strongest evidence first, readiness last).
 * Every entry has the same four sections so a reader always knows where to
 * look:
 *   covers   — what the area is about, in a business owner's words
 *   checks   — what CyberMeters measures, why, and what it cannot establish
 *   reading  — the states and findings as the product shows them, and what they mean
 *   next     — who usually makes the change, and how a fix is verified
 *
 * The guide describes the product as it is. It never claims an observation the
 * scanner does not make, and it never calls a customer's own word "verified":
 * that wording is reserved for what CyberMeters re-observed itself
 * (docs/verification-vocabulary.md).
 *
 * In-depth articles live in ./academy.js and hang off an area as deeper reading
 * through ARTICLE_AREAS below.
 */
import { ARTICLES } from './academy'
import { sortByAreaOrder } from '../../../shared/areas.js'
import { statusExplanationRows } from '../lib/statusExplanations'

// Shared vocabulary: the coverage states every area can show, as the product
// labels them, with what each means for the reader. Areas add their own rows.
const COMMON_STATES = statusExplanationRows().map(([, label, meaning]) => [label, meaning])

// Wording shared by every area's "How a fix is verified" section.
const VERIFIED_MEANS = 'When CyberMeters re-observes the change itself, the case reads Verified. That word is reserved for CyberMeters’ own observation. Customer statements stay separate from CyberMeters observations. Where the case permits self-attestation, it is labelled as attested by you; other verification methods still need their required evidence.'

const GUIDE_AREA_DEFINITIONS = [
  {
    key: 'email-protection',
    colourKey: 'email',
    domainKey: 'email_protection',
    title: 'Email Protection',
    shortTitle: 'Email Protection',
    route: '/ws/email-protection',
    summary: 'Your domain’s published email-authentication and mail-transport settings, requested receiver policies and reporting evidence.',
    intro: 'Email Protection checks the records your domain publishes for authorised senders, message authentication, requested receiver policy and mail transport. It explains the observed configuration and reporting evidence, so you can review legitimate senders and choose the next change.',
    covers: [
      'Email Protection is about the public records your domain publishes to identify authorised senders, request how receiving servers handle messages that fail aligned authentication, and publish mail-transport and reporting policies.',
      'It assesses domain-level settings and available aggregate authentication evidence. It does not read your mailbox or determine whether an individual message is phishing.',
    ],
    checks: {
      why: [
        'CyberMeters resolves SPF includes and redirects and checks the evaluation budget: no more than ten DNS-lookup-causing terms, including nested evaluations. This is not simply a count of include statements. DMARC p=none requests monitoring without requesting quarantine or rejection; aggregate reports can still help you identify senders and authentication problems.',
        'Each record is checked against the current standard it belongs to, and the result is described as standards-aware rather than as a compliance verdict. CyberMeters checks what it can read; it does not certify your email provider.',
      ],
      observed: [
        'SPF: whether a record exists, which sources it authorises after every include is resolved, whether it stays within the lookup limit, and whether it ends permissively.',
        'DKIM: whether signing keys can be found for common selectors. A key that is not found is reported as not detected, because your provider may sign under a selector CyberMeters cannot guess.',
        'DMARC: whether a policy exists, its requested receiver policy (none, quarantine or reject), aggregate-report configuration and authorisation of external report destinations.',
        'MTA-STS and TLS-RPT: whether a published policy requests encrypted delivery, and whether transport-failure reporting is configured.',
        'BIMI: whether a brand indicator is configured and whether DMARC enforcement supports it.',
        'If you use CyberMeters hosted DMARC reporting: which services are seen sending as your domain, whether each one is recognised, and whether the hosted record is still connected.',
      ],
      notObserved: [
        'The contents of any email, your mailboxes, or anything inside your email provider’s admin console.',
        'Whether a particular message was phishing. CyberMeters sees sending sources and authentication results, not intent.',
        'DKIM keys published under a selector it has not seen. Not detected means not found, not absent.',
        'Mail that uses a domain you have not added to the workspace.',
      ],
    },
    reading: {
      intro: [
        'Read the area summary alongside its evidence and coverage. A monitoring-only DMARC policy can provide reporting but does not request quarantine or rejection. Published records describe your requested policy; they do not prove how every receiving server handles each message.',
        'Every finding carries the record CyberMeters read, the time it read it, and the exact change needed.',
      ],
      states: [
        ...COMMON_STATES,
        ['Sender unrecognised', 'Shown only with hosted DMARC reporting. A service is sending mail as your domain and you have not told CyberMeters whether it is yours. Mark it recognised or a threat; CyberMeters never decides that for you.'],
      ],
      findings: [
        'SPF record missing, permissive, duplicated, or over the ten-lookup limit.',
        'DKIM keys not detected for probed selectors; this does not prove messages are unsigned.',
        'DMARC missing, monitoring-only, invalid, duplicated, or sending reports to an unauthorised address.',
        'MTA-STS or TLS-RPT not configured.',
        'A hosted DMARC record disconnected, or a sending source failing authentication.',
      ],
    },
    next: {
      intro: [
        'Email records live in DNS, so almost every fix here is a DNS change at the company that hosts your domain’s name servers. The finding tells you the exact record to add or change; copy it rather than retyping it.',
        'Move DMARC to enforcement in steps: monitoring first, then quarantine, then reject, checking the reports between each step so legitimate senders are not blocked.',
      ],
      owners: [
        'Your DNS or domain host for SPF, DMARC, MTA-STS, TLS-RPT, CAA and BIMI records.',
        'Your email provider for DKIM, which is enabled in the provider’s console and then published as a DNS record.',
        'You, for classifying senders seen in DMARC reports: only you know which services legitimately send as your domain.',
      ],
      verification: [
        'Most Email Protection fixes are DNS changes, so CyberMeters re-reads the record on the next scan or when you ask it to re-check, and closes the case from what it observes.',
        'DKIM and sender classification are different: CyberMeters cannot see inside your provider or know your suppliers, so those are recorded as attested by you.',
        VERIFIED_MEANS,
      ],
    },
  },
  {
    key: 'attack-surface',
    colourKey: 'surface',
    domainKey: 'attack_surface',
    title: 'Attack Surface',
    shortTitle: 'Attack Surface',
    route: '/assets',
    summary: 'Public hostnames, services and exposures observed for your domain, including unfamiliar systems and changes worth reviewing.',
    intro: 'Your attack surface is every hostname, service and record that answers to your name on the public internet. Attackers map it before they do anything else. This area maps what CyberMeters can see from outside and updates the map with every scan, so a forgotten test server or an expiring domain is easier to spot.',
    covers: [
      'Attack Surface covers discovery (what exists), exposure (what each thing shows to the internet) and change (what appeared, disappeared or changed since last time). The Timeline shows the change history; Scans and Schedules control when CyberMeters looks.',
      'It also covers the two foundations the rest of your presence rests on: whether your DNS is signed, and whether your domain registration is about to lapse.',
    ],
    checks: {
      why: [
        'A forgotten subdomain, exposed administration page, public storage location or expiring registration can need action. CyberMeters makes bounded DNS, web and TLS checks and records what it observes about those public services.',
        'Normal domain scans include real TLS handshakes. Declared-range port scanning uses separate Network assets consent; the three available intrusive TLS checks require their own scoped Active Checks permission and a scan you start.',
      ],
      observed: [
        'Hostnames under your domain, resolved to whether they still point at something, and whether any points at a service that no longer recognises it (takeover risk).',
        'Hostnames whose names suggest sensitive purposes, such as development, staging or VPN endpoints.',
        'Administration interfaces, developer environments and sensitive tools reachable on your public hostnames.',
        'Public cloud storage that lists its contents or is observed to be exposed.',
        'Software and service fingerprints a server announces about itself. The current scan pack does not match these against external CVE or known-exploited-vulnerability databases.',
        'Whether DNSSEC is enabled and valid, and when your domain registration expires.',
      ],
      notObserved: [
        'Anything inside your network, on your devices or behind a login.',
        'A complete inventory of all ports and services. Separate Network assets checks cover only the public targets and port scope you authorise.',
        'Whether a declared software version is exploitable or a system is compromised. A fingerprint is an observation, not an exploit test.',
        'Hostnames that exist but are not discoverable from public DNS.',
      ],
    },
    reading: {
      intro: [
        'The asset list is the map. Each asset shows what CyberMeters observed about it and when; the Timeline shows how that changed. New or changed assets are worth a look even when nothing is flagged, because you may not have expected them.',
        'A finding’s severity reflects how useful the exposure is to an attacker, not how certain CyberMeters is. Certainty is stated separately in the evidence.',
      ],
      states: [
        ...COMMON_STATES,
        ['New asset', 'A hostname or service appeared that was not seen before. Confirm you expected it.'],
        ['Disappeared', 'An asset was not observed. Disappearance alone does not prove removal; a relevant case can be verified when CyberMeters records qualified, complete and trustworthy DNS-removal evidence. A timeout or incomplete check is not that evidence.'],
      ],
      findings: [
        'Subdomain takeover risk: a hostname points at a service that no longer claims it.',
        'Administration interface, developer environment or sensitive tool on a public hostname.',
        'Public cloud storage listing its contents.',
        'DNSSEC not enabled or misconfigured.',
        'Domain registration expiring soon or expired.',
      ],
    },
    next: {
      intro: [
        'Start with anything an attacker could use today: takeover risks, open storage and public admin interfaces. Then remove or restrict what you did not know existed. Finally fix the foundations: DNSSEC and registration renewal.',
        'For a takeover risk, either reclaim the service the hostname points at or delete the DNS record. Deleting the record is usually the quickest fix.',
      ],
      owners: [
        'Whoever manages your DNS, for stale records, DNSSEC and hostnames that should no longer exist.',
        'Whoever runs the hosting or cloud account, for admin interfaces, developer environments, storage permissions and software updates.',
        'Your domain registrar, for registration renewal and the registrar lock.',
      ],
      verification: [
        'CyberMeters re-checks the specific finding using complete, trustworthy evidence, such as qualified DNS removal, a conclusive cleared exposure or a valid DNSSEC observation. Verification follows that finding’s evidence rules. A timeout, unreachable response or partial or stale check does not by itself prove a fix.',
        'A domain renewal is confirmed through the registration record on re-check.',
        VERIFIED_MEANS,
      ],
    },
  },
  {
    key: 'website-security',
    colourKey: 'website',
    domainKey: 'website_security',
    title: 'Website Security',
    shortTitle: 'Website Security',
    route: '/ws/website-security',
    summary: 'Whether your public website protects its visitors: forced HTTPS, protective headers, safe cookies and sign-in forms that do not leak.',
    intro: 'Your website is the one system every customer touches. This area checks the protections a browser relies on when it loads your pages, and whether a sign-in form on your site handles credentials safely. Everything here is observed exactly as a visitor’s browser would see it.',
    covers: [
      'Website Security covers the transport (is HTTP forced to HTTPS, is HSTS set), the response headers that instruct the browser how to behave, the cookie flags that keep sessions private, and the behaviour of any sign-in form on the site.',
      'Public-page checks need no account. Optional signed-in scanning uses the test account you configure on a verified domain for a small read-only crawl. It covers only pages that account can reach, not every role or your application’s source code; it is not a penetration test.',
    ],
    checks: {
      why: [
        'Browsers will protect your visitors from a whole class of attacks, but only if your site tells them to. A missing header costs nothing to add and removes a real avenue for script injection, click-jacking or session theft.',
        'CyberMeters requests your home page and a small number of related pages the way a browser would, reads the response, and compares every header, cookie and form against current guidance. If the page cannot be fetched, the area says so instead of guessing: an unreachable site is never reported as healthy.',
      ],
      observed: [
        'Whether plain HTTP redirects to HTTPS, and whether HSTS is present, long enough and well formed.',
        'Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy and Permissions-Policy: present, missing or malformed.',
        'Cookie flags: Secure, HttpOnly and SameSite.',
        'Sign-in forms: whether they submit over HTTPS, to your own origin, and set secure cookies.',
        'Software versions the server announces in its headers.',
        'Whether the home page exists and could be loaded at all.',
        'With optional signed-in scanning configured: whether the supplied test account signed in and which pages the bounded read-only crawl checked. This evidence remains private to that workspace.',
      ],
      notObserved: [
        'Pages or roles the supplied test account cannot reach, internal systems and your application’s source code.',
        'Vulnerabilities that require sending attack traffic to find. CyberMeters reads responses; it does not probe for injection or run exploit checks.',
        'Whether a header’s policy is the right one for your application. CyberMeters reports weak or missing policies; what the policy should allow is a decision for whoever built the site.',
      ],
    },
    reading: {
      intro: [
        'Each finding names the header or cookie, shows the value CyberMeters received, and states the value that would resolve it. Findings on the sign-in form are ranked above headers, because they protect credentials directly.',
        'When the home page could not be loaded, the whole area reads Evidence insufficient. That is a fact about the check, not a verdict about your site.',
      ],
      states: [
        ...COMMON_STATES,
      ],
      findings: [
        'HTTP not redirected to HTTPS; HSTS missing, short or malformed.',
        'Content-Security-Policy missing or weak; frame, content-type, referrer or permissions headers missing.',
        'Cookies set without Secure, HttpOnly or SameSite.',
        'A sign-in form posting over plain HTTP or to another origin.',
        'Server or framework version disclosed in response headers.',
      ],
    },
    next: {
      intro: [
        'Headers and cookie flags are configured on the web server, the hosting platform or the content delivery network in front of your site. Most providers expose them as settings; the finding gives the exact value to set.',
        'Introduce Content-Security-Policy in report-only mode first, so a strict policy does not break your own pages before you have tuned it.',
      ],
      owners: [
        'Your web developer or agency, for headers, cookies and sign-in form changes.',
        'Your hosting provider or CDN, where headers and redirects are set at the platform level.',
      ],
      verification: [
        'Every Website Security finding is verified by re-fetching the page: CyberMeters re-reads the headers, cookies and form on the next scan or re-check and closes the case when the condition is gone.',
        'No Website Security case relies on your word, because every condition here is observable from outside.',
        VERIFIED_MEANS,
      ],
    },
  },
  {
    key: 'identity-exposure',
    colourKey: 'identity',
    domainKey: 'identity_exposure',
    title: 'Identity Exposure',
    shortTitle: 'Identity Exposure',
    route: '/ws/identity-exposure',
    summary: 'Public identity-provider and hostname evidence, ownership records, and optional authorised account and public-file observations.',
    intro: 'Identity Exposure brings together public provider and hostname evidence so you can confirm what is known, owned and intended. Optional administrator-requested checks add scoped Microsoft account observations or masked key-pattern evidence from your public web files.',
    covers: [
      'Identity Exposure covers provider relationships (your domain is configured for a particular identity provider), possible identity-facing hostnames (names or records that suggest a sign-in or directory endpoint), and ownership: whether someone in your business is accountable for each one.',
      'Automatic discovery observes public relationships, hostnames and bounded OIDC metadata on verified domains. Separately, eligible workspace administrators can request public-file key-pattern checks and authorised Microsoft account observations. These are distinct sources of evidence, not an employee-password breach feed.',
    ],
    checks: {
      why: [
        'An identity endpoint nobody owns is a gap: it stays configured after a provider migration, keeps a legacy protocol enabled, or belongs to a tenant nobody checks. CyberMeters surfaces these relationships so you can account for them.',
        'Every identity claim carries a confidence and an evidence grade. CyberMeters tells you how it reached the conclusion and how sure it is. Where reachability of an endpoint has not been measured, the claim says not evaluated rather than implying anything.',
      ],
      observed: [
        'Provider relationships visible in DNS, such as records that configure your domain for Microsoft 365 or another identity provider.',
        'Possible identity-facing hostnames: names and records that suggest sign-in, autodiscover or directory endpoints.',
        'Changes to a provider relationship between scans.',
        'Which identity items have an assigned owner, and whether a recorded exception has expired.',
        'Bounded public OIDC discovery metadata on verified domains, when a valid document is observed; advertised login and token endpoints are not followed.',
        'Optional authorised Microsoft account observations: available direct-role names and MFA registration, subject to Microsoft permissions and licensing. Registration does not establish MFA enforcement.',
        'On an administrator’s request, one public page and up to three directly linked same-origin JavaScript files for supported secret-key patterns. Candidates are masked and never used or tested.',
      ],
      notObserved: [
        'Employee-password breach feeds, stealer logs or dark-web data. Public-file key-pattern checks do not search these sources.',
        'MFA enforcement, Conditional Access policy, sign-in history or account compromise. Missing Microsoft permission or licence data remains unavailable.',
        'Whether an account can sign in from public identity discovery alone. Provider relationships and metadata do not prove successful authentication.',
      ],
    },
    reading: {
      intro: [
        'Each item is a claim with its evidence: what was observed, how confident CyberMeters is, and what has not been evaluated. Read the confidence before the conclusion.',
        'An item that needs an owner is not a security finding; it is an accountability gap. Assign it and the item is complete.',
      ],
      states: [
        ...COMMON_STATES,
        ['Not evaluated', 'This aspect of the claim, usually reachability, has not been measured. It is neither good nor bad; it is unmeasured.'],
        ['Owner missing', 'Nobody in your workspace is recorded as accountable for this identity item.'],
      ],
      findings: [
        'A provider relationship observed for your domain.',
        'A possible identity-facing hostname that should be confirmed as intended.',
        'A provider relationship that changed since the last scan.',
        'An identity item without an owner, or an exception past its review date.',
      ],
    },
    next: {
      intro: [
        'Confirm each provider relationship and hostname is intended. Assign an owner to every item. Where a hostname should not exist, remove its DNS record. Where a legacy protocol is enabled in your identity provider, disable it there.',
      ],
      owners: [
        'Your IT administrator or the person who manages your Microsoft 365 or identity tenant.',
        'Your DNS host, for records that configure or expose identity endpoints.',
      ],
      verification: [
        'Identity Exposure is the one area where CyberMeters mostly cannot verify from outside: tenant settings, legacy protocols and ownership are not externally observable. Those outcomes are recorded as attested by you, and the case says so.',
        'Only a DNS change, such as a removed identity-related record, is re-observed and can read Verified.',
        VERIFIED_MEANS,
      ],
    },
  },
  {
    key: 'shadow-it',
    colourKey: 'shadow_it',
    domainKey: 'shadow_it_unmanaged_technology',
    title: 'Shadow IT & Unmanaged Technology',
    shortTitle: 'Shadow IT',
    route: '/ws/shadow-it',
    summary: 'The online services and third parties your public presence reveals, and whether each one is known to you and approved.',
    intro: 'Businesses run on dozens of online services, many adopted by one team without anyone else knowing. This area shows which services your domain and website visibly depend on, so you can decide which are approved, which are not, and which you did not know about.',
    covers: [
      'Shadow IT covers the SaaS services your DNS records point at, and the third-party scripts and services your website loads. The Approved Inventory is where you record which ones your business sanctions.',
      'Observation and approval are separate on purpose. CyberMeters observes; you classify. Approved does not mean secure, and Rejected does not mean the service is gone.',
    ],
    checks: {
      why: [
        'Every service your domain is wired to is a place your data may live and a login someone may have forgotten. You cannot protect what you do not know you use. The external footprint is the one list of your services that no one has to remember to update.',
        'CyberMeters never asserts that a service is unauthorised. It shows what is observed and asks you to classify it, because only you know what your business approved.',
      ],
      observed: [
        'SaaS services referenced by your DNS records, such as verification records, mail and CNAME entries.',
        'Third-party scripts and services your public website loads, and the origins your content security policy allows.',
        'Whether each observed service matches an entry in your Approved Inventory, and how that changes over time.',
      ],
      notObserved: [
        'Anything inside your network: installed software, browser extensions, devices or employee behaviour.',
        'Services that leave no public trace in DNS or on your website.',
        'Licences, seat counts, who uses a service or what data it holds.',
        'Whether a service is secure. CyberMeters reports the relationship, not the vendor’s security.',
      ],
    },
    reading: {
      intro: [
        'Each observed service shows where it was seen and when. Your classification sits beside the observation and never replaces it. An observed service marked Removed by you stays observed until CyberMeters stops seeing it, and even then the disappearance is recorded as a change, not as proof of removal.',
      ],
      states: [
        ...COMMON_STATES,
        ['Observed, unclassified', 'A service was seen and you have not yet said whether it is approved.'],
        ['Approved', 'You sanction this service. It stays monitored for change.'],
        ['Rejected', 'You do not sanction it. CyberMeters keeps observing until it is gone; it does not remove anything.'],
        ['Not seen in the latest scan', 'The service was not seen on the latest scan. This is not the same as verified removal, and it is not counted as externally observed.'],
      ],
      findings: [
        'A SaaS service or third party observed that is not in your Approved Inventory.',
        'A new third-party script on your website.',
        'A vendor relationship with cascading dependencies worth reviewing.',
      ],
    },
    next: {
      intro: [
        'Classify every observed service: approve what the business uses, reject what it should not, and investigate what nobody recognises. For a rejected service, remove the DNS record or script that connects it, then close the account with the vendor.',
      ],
      owners: [
        'You or the team that adopted the service, for the classification decision.',
        'Your DNS host or web developer, for the record or script that connects the service.',
      ],
      verification: [
        'Removal of a service is a decision inside the vendor’s account, which CyberMeters cannot see, so the outcome is recorded as attested by you.',
        'What CyberMeters can observe is the external trace: when the DNS record or script disappears, that change is recorded in the inventory history, and the item reads no longer observed.',
        VERIFIED_MEANS,
      ],
    },
  },
  {
    key: 'certificates-trust',
    colourKey: 'certs',
    domainKey: 'certificates_trust',
    title: 'Certificates & Trust',
    shortTitle: 'Certificates',
    route: '/ws/certificates',
    summary: 'Live TLS connections, certificate and trust evidence, protocol and key-exchange choices, and changes on your public endpoints.',
    intro: 'CyberMeters makes real TLS connections to record certificate, protocol and key-exchange evidence. It tracks expiry, names, issuers and certificate changes, and reports the endpoint, scope and observation time behind the result.',
    covers: [
      'Certificates & Trust covers the live certificate each public hostname presents, its expiry and renewal, the issuer behind it, the CAA record that controls who may issue for your domain, and the Managed Lifecycle that tracks renewals and replacements over time.',
      'TLS checks also record protocol versions, representative cipher and key-exchange choices, trust-chain evidence, downgrade behaviour and whether a server selects an offered hybrid TLS 1.3 key exchange.',
      'It covers what a connecting browser can see. Private keys, internal certificates and the full trust path are stated as unknown unless evidence supports otherwise.',
    ],
    checks: {
      why: [
        'An expired or mismatched certificate can interrupt HTTPS access. Recording certificate changes helps you review renewals and unexpected issuers alongside the actual connection evidence.',
        'Only facts a connecting client can establish are asserted. A certificate that has not expired is not automatically trusted; chain validity, revocation and private-key safety stay unknown unless they were actually checked.',
      ],
      observed: [
        'The certificate each public hostname presents: validity dates, hostname coverage and issuer.',
        'Expired, expiring soon, self-signed, hostname-mismatched or untrusted certificates, and hostnames with no certificate at all.',
        'Certificates whose issuer, names or wildcard scope differ from what the hostname previously used.',
        'Concentration on a single issuer, and CAA records that say which authorities may issue for your domain.',
        'Renewal and replacement history in the Managed Lifecycle.',
        'TLS protocol versions, representative ciphers and key exchanges, and recorded certificate-chain, hostname and trust-store checks.',
        'Protocol fallback/downgrade behaviour and the group selected when a TLS 1.3 connection offers a hybrid key exchange. This is a connection observation, not a claim that the whole service is quantum-safe.',
        'Heartbleed, ROBOT and CCS injection checks only when a named domain/host grant, an eligible customer-owned public address and a manually started scan permit them. Shared provider infrastructure is refused; five other active check types remain unavailable and are not offered.',
      ],
      notObserved: [
        'Complete chain validity, trusted-root status, OCSP and revocation status. These read unknown unless checked.',
        'Private keys, internal keystores or certificates on internal systems.',
        'Whether an unexpected issuer is malicious. CyberMeters reports the change; you confirm whether you ordered it.',
      ],
    },
    reading: {
      intro: [
        'Expiry findings carry the date and a countdown. Trust findings carry the exact failure a browser would show. An unexpected-issuer finding is a question to you, not an accusation: did you or your provider request this certificate?',
        'Fields that read unknown are being honest. They are not a defect in your certificate.',
        'Active Checks shows permissions separately from saved results. Select a saved scan to read explicit results or not-tested states; a grant or a completed scan alone never proves an intrusive check ran.',
      ],
      states: [
        ...COMMON_STATES,
        ['Unknown', 'This property, such as revocation status, was not checked from outside. It is unmeasured, not failing.'],
        ['Expiring soon', 'The certificate expires within the warning window. Renew before the date.'],
      ],
      findings: [
        'Certificate expired, expiring soon or absent.',
        'Hostname mismatch, self-signed or untrusted certificate.',
        'Unexpected issuer, name or wildcard compared with the hostname’s history.',
        'CAA record missing or allowing no issuer.',
      ],
    },
    next: {
      intro: [
        'Renew before expiry and, where your host supports it, turn on automatic renewal. Add a CAA record naming only the authorities you use. When an unexpected issuer appears, confirm it with whoever manages your hosting before dismissing it.',
        'Use Active Checks in the main menu to manage the three available intrusive TLS permissions and read saved check history. Public IP targets and declared-range port scanning use the separate Network assets consent.',
      ],
      owners: [
        'Your hosting provider or CDN, which usually issues and renews certificates for you.',
        'Your DNS host, for the CAA record.',
        'Your IT administrator, to confirm whether an unexpected certificate was requested.',
      ],
      verification: [
        'Expiry, mismatch, trust and CAA findings are verified by CyberMeters re-connecting to the hostname and re-reading the certificate or the DNS record.',
        'Whether an unexpected certificate was authorised is something only you know, so that outcome is recorded as attested by you.',
        VERIFIED_MEANS,
      ],
    },
  },
  {
    key: 'brand-protection',
    colourKey: 'brand',
    domainKey: 'brand_protection',
    title: 'Brand Protection',
    shortTitle: 'Brand Protection',
    route: '/ws/brand-monitoring',
    summary: 'Domains registered to look like yours, and the case workflow for preparing and tracking takedown requests.',
    intro: 'Criminals register domains that look like yours to send email and host pages in your name. This area watches for look-alike registrations, explains how each one resembles your domain, and tracks the takedown you pursue with the registrar or provider.',
    covers: [
      'Brand Protection covers look-alike domains: typosquats, character substitutions that look identical in a browser, and other variations of your registered domain. Each detection becomes a case you can own, work and close.',
      'CyberMeters prepares and tracks takedowns. It does not file them for you and does not claim a domain is malicious from its name alone.',
    ],
    checks: {
      why: [
        'A look-alike domain is cheap to register and often the first step in invoice fraud against your customers. Knowing it exists early, before mail has been sent from it, is the whole advantage.',
        'CyberMeters generates the variants of your domain an attacker would try, checks which are registered, and records what each one currently does. Registration is a fact; intent is not. The wording reflects that.',
      ],
      observed: [
        'Registered domains that resemble yours by typo, character substitution or added words.',
        'What each look-alike resolves to and whether it is configured to send mail.',
        'Changes to a look-alike over time, so a parked domain that comes to life is noticed.',
      ],
      notObserved: [
        'Who registered the domain or why. Registration data is often private.',
        'Whether phishing has been sent from it. CyberMeters sees configuration, not the mail.',
        'Social media impersonation, marketplace listings or other brand abuse outside the domain name system.',
      ],
    },
    reading: {
      intro: [
        'Each detection says how the name resembles yours and what it currently does. A parked look-alike with no mail configuration is a lower priority than one with live mail records. Severity follows the configuration, not the name.',
      ],
      states: [
        ...COMMON_STATES,
        ['Takedown in progress', 'You have opened a case and are pursuing the domain with its registrar or hosting provider. CyberMeters tracks the case; it did not file the request.'],
      ],
      findings: [
        'Look-alike, homoglyph or typosquat domain registered.',
        'A look-alike domain that has gained mail or web configuration since it was first seen.',
      ],
    },
    next: {
      intro: [
        'Open a case for any look-alike you did not register. Use the registrar’s abuse process, and the hosting provider’s if it serves content. Consider registering the most convincing variants yourself. Warn customers if the domain is actively sending mail.',
      ],
      owners: [
        'The registrar of the look-alike domain, for the takedown request.',
        'You or your marketing lead, for defensive registrations and customer communication.',
      ],
      verification: [
        'A takedown is verified when CyberMeters re-checks the look-alike and finds it no longer registered or no longer resolving. The case closes from that observation.',
        VERIFIED_MEANS,
      ],
    },
  },
  {
    key: 'cyber-essentials',
    colourKey: 'cyber_essentials',
    domainKey: 'cyber_essentials_readiness',
    title: 'Cyber Essentials Readiness',
    shortTitle: 'Cyber Essentials',
    route: '/ws/cyber-essentials',
    summary: 'How ready you are for the UK Cyber Essentials certification, separating what CyberMeters can observe from what only you can attest.',
    intro: 'Cyber Essentials is the UK government-backed baseline certification. This area is a readiness view, not a scan result: it combines the small part of the scheme that is visible from outside with a questionnaire only you can answer, and it never blurs the two.',
    covers: [
      'Cyber Essentials Readiness covers the five control areas of the scheme: boundary protection, secure configuration, access control, malware protection and security update management. For each, it shows whether CyberMeters can observe anything externally and what your own answers say.',
      'It does not cover certification itself. Certification is granted by an accredited external body after your own assessment; CyberMeters helps you prepare and keeps the record honest.',
    ],
    checks: {
      why: [
        'Most of Cyber Essentials concerns things inside your business: who has admin rights, whether devices run antivirus, how quickly patches are applied. None of that is visible from the internet. Pretending otherwise would be the most misleading thing a tool like this could do.',
        'So CyberMeters measures only the two areas it can partly see, boundary protection and secure configuration, and states that the readiness indicator is the average of those two out of five. The other three read "not externally assessable" and rely entirely on your questionnaire answers.',
      ],
      observed: [
        'Boundary protection, partially: externally visible exposures from the Attack Surface area that bear on the boundary.',
        'Secure configuration, partially: externally visible web and transport configuration from Website Security and Certificates & Trust.',
        'Your questionnaire answers, recorded with the question-set version they were given under.',
        'Open findings elsewhere in the workspace that would be questioned in an assessment.',
      ],
      notObserved: [
        'Access control, malware protection and security update management. These are not externally assessable and carry no score, band or health from CyberMeters.',
        'Whether your questionnaire answers are true. They are self-attestation, and the product labels them that way.',
        'Certification status. Only the certification body can grant or confirm it.',
      ],
    },
    reading: {
      intro: [
        'The readiness indicator states its denominator: it is the mean of the two externally assessable areas, out of five. A change to the methodology is versioned so it can never look like a change in your posture.',
        'Questionnaire answers never move your Cyber Metrics Score or Business Risk Indicator and never create a case on their own. They inform readiness only.',
      ],
      states: [
        ...COMMON_STATES,
        ['Not externally assessable', 'This control area cannot be observed from the internet. It shows no number and no health; your own answers are the only evidence.'],
      ],
      findings: [
        'A control area whose observable evidence is not ready or has worsened.',
        'Open findings elsewhere that an assessor would ask about.',
        'Certification scope that needs confirming before you apply.',
      ],
    },
    next: {
      intro: [
        'Resolve the externally observable findings first, because an assessor will see them too. Then answer the questionnaire honestly and act on the answers you are not proud of. When both are in order, apply to an accredited certification body.',
      ],
      owners: [
        'You or your IT provider, for the internal controls and the questionnaire.',
        'The accredited certification body, for the assessment and the certificate itself.',
      ],
      verification: [
        'Externally observable evidence is re-checked like any other finding. Internal controls are self-attested and remain labelled that way. Certification is confirmed by the external body, which is neither CyberMeters’ observation nor your word, and is recorded as external.',
        VERIFIED_MEANS,
      ],
    },
  },
]

// Founder order from shared/areas.js — the same constant the area sheet and the Overview list use.
export const GUIDE_AREAS = Object.freeze(sortByAreaOrder(GUIDE_AREA_DEFINITIONS))

// Article slug → area key, so each article appears as deeper reading under the
// one area it belongs to. Articles not listed here are reachable by search
// only.
export const ARTICLE_AREAS = {
  'spf-explained': 'email-protection',
  'dmarc-explained': 'email-protection',
  'dkim-explained': 'email-protection',
  'dmarc-stop-email-impersonation': 'email-protection',
  'what-is-attack-surface-management': 'attack-surface',
  'what-is-subdomain-takeover': 'attack-surface',
  'public-cloud-storage-risks': 'attack-surface',
  'dnssec-explained': 'attack-surface',
  'hsts-explained': 'website-security',
  'csp-explained': 'website-security',
  'microsoft-365-exposure-risks': 'identity-exposure',
  'vendor-risk-explained': 'shadow-it',
  'supply-chain-attacks-explained': 'shadow-it',
  'what-is-an-external-security-check': 'cyber-essentials',
  'cyber-essentials-what-you-actually-need-to-pass': 'cyber-essentials',
}

// Articles about using the product itself rather than one area (founder,
// 22 Oct 2026: the Field Guide gains an MCP section). They are listed under
// "Using CyberMeters" on the guide index instead of under an area.
export const GUIDE_PRODUCT_ARTICLES = Object.freeze(['connect-your-ai-assistant'])

export function getGuideArea(slug) {
  if (!slug) return null
  return GUIDE_AREAS.find(a => a.key === slug) || null
}

export function getGuideAreaArticles(areaKey) {
  return ARTICLES.filter(a => ARTICLE_AREAS[a.slug] === areaKey)
}

export function getGuideAreaForArticle(slug) {
  const key = ARTICLE_AREAS[slug]
  return key ? getGuideArea(key) : null
}

// The sidebar and area pages address an area by its service colour key.
export function guideSlugForColourKey(colourKey) {
  const area = GUIDE_AREAS.find(a => a.colourKey === colourKey)
  return area ? area.key : ''
}

export function guideAreaForDomainKey(domainKey) {
  return GUIDE_AREAS.find(a => a.domainKey === domainKey) || null
}

export { COMMON_STATES }
