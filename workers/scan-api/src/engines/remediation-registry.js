// ── Canonical remediation registry ──────────────────────────────────────────
// ONE source of truth for customer-facing remediation content across all eight
// Cyber MOT domains. Every surface — scan findings, Scan Detail, recommendations,
// scorecard, Business Risk Score, executive summary, executive report UI, the
// executive PDF, and managed cases — resolves the same canonical meaning for a
// given finding type through resolveRemediation(). Surface-specific formatting is
// allowed; the semantic meaning must not drift.
//
// Design contract (non-negotiable):
//   1. remediation_id is a stable dotted slug, NEVER derived from mutable display
//      copy. Copy can be re-worded without changing identity.
//   2. One finding type resolves to exactly one PRIMARY remediation (optional
//      secondaries). Two entries may not claim the same finding type as primary.
//   3. One remediation may serve several finding types where the advice is
//      genuinely identical.
//   4. Historical reports must keep resolving: legacy finding types are ALIASES,
//      and nothing here is persisted — resolution happens at read time, so no
//      migration is required.
//   5. Unknown / unsupported verification stays EXPLICIT (verification_method
//      "unsupported") — never implied.
//   6/7/8/9/10. Honest scope per domain: no unsupported automation claims, no
//      credential-breach claim for Identity, no internal Shadow-IT visibility
//      claim, Cyber Essentials certification stays external, brand takedown
//      execution stays customer/provider-operated.
//
// This registry is CODE-BACKED (compute-on-read). It stores no rows and adds no
// schema. resolveRemediation is pure and deterministic.

import { CYBER_MOT_DOMAINS } from "./cyber-mot-domains.js";

// The eight canonical domain keys are DERIVED from the Cyber MOT domain model so
// they can never drift from it. Every registry entry must use one of these.
export const CANONICAL_DOMAIN_KEYS = Object.freeze(
  CYBER_MOT_DOMAINS.map((d) => d.domain_key),
);
const DOMAIN_KEY_SET = new Set(CANONICAL_DOMAIN_KEYS);

const REGISTRY_INTRODUCED_AT = "2026-07-14";

// Effort / owner / verification vocabularies kept small and explicit so surfaces
// and tests can reason about them.
export const REMEDIATION_EFFORT = Object.freeze(["low", "medium", "high"]);
export const REMEDIATION_OWNER = Object.freeze([
  "customer",        // the account holder can do it themselves
  "customer_it",     // needs IT / DNS / hosting administrator
  "email_provider",  // needs the mail provider / gateway
  "registrar",       // needs the domain registrar / abuse contact
  "cybermeters",     // CyberMeters can host / self-drive it
  "external_body",   // handled outside the product (e.g. IASME for CE)
]);
export const VERIFICATION_METHOD = Object.freeze([
  "dns_recheck",       // re-query DNS after the change
  "https_recheck",     // re-fetch the HTTPS endpoint / headers
  "certificate_recheck", // re-observe the certificate via CT / probe
  "rescan",            // a fresh Cyber MOT confirms the evidence
  "receiver_reports",  // subsequent DMARC aggregate reports from receiving providers
  "manual_attestation",// customer confirms; product cannot observe it
  "external",          // confirmed by an external body / provider console
  "unsupported",       // product cannot verify this signal (kept explicit)
]);

// ── The registry ─────────────────────────────────────────────────────────────
// Each entry is authored in British English, customer language, and stays within
// the honest scope of its domain. `finding_types` are the PRIMARY bindings.
// `secondary_finding_types` (optional) attach the entry as a secondary option.
function entry(e) {
  return Object.freeze({
    version: 1,
    status: "active",
    effort: "medium",
    owner_type: "customer_it",
    supporting_evidence_types: [],
    managed_workflow_compatible: false,
    case_type: null,
    applicability: "Applies whenever the associated finding is raised.",
    limitations: [],
    references: [],
    secondary_finding_types: [],
    introduced_at: REGISTRY_INTRODUCED_AT,
    deprecated_at: null,
    replacement_remediation_id: null,
    ...e,
  });
}

export const REMEDIATION_REGISTRY = Object.freeze([
  // ─────────────────────────── EMAIL PROTECTION ──────────────────────────────
  entry({
    remediation_id: "email.dmarc.publish",
    domain_key: "email_protection",
    finding_types: ["email_missing_dmarc", "email_intel_dmarc_missing", "dmarc_missing"],
    customer_title: "Publish a DMARC policy",
    technical_explanation: "No DMARC record was found at _dmarc.<domain>, so receiving mail servers have no published instruction for messages that fail authentication.",
    business_impact: "Attackers can send email that appears to come from your domain, enabling invoice fraud, supplier impersonation and business email compromise.",
    recommended_action: "Publish a DMARC record at _dmarc.<domain> starting at p=none with aggregate reporting (rua=), review who is sending as you, then move towards p=quarantine and p=reject once every legitimate sender is validated.",
    effort: "medium",
    owner_type: "customer_it",
    verification_method: "dns_recheck",
    verification_evidence_requirements: "A DMARC TXT record is observed at _dmarc.<domain>.",
    supporting_evidence_types: ["dns_txt_lookup"],
    managed_workflow_compatible: true,
    references: ["https://www.ncsc.gov.uk/collection/email-security-and-anti-spoofing"],
  }),
  entry({
    remediation_id: "email.dmarc.enforce",
    domain_key: "email_protection",
    finding_types: ["email_dmarc_policy_none", "email_intel_dmarc_reporting_only", "dmarc_policy_monitoring_only", "dmarc_partial_percentage"],
    customer_title: "Strengthen DMARC enforcement",
    technical_explanation: "A DMARC record exists but is monitor-only (p=none) or partially applied, so failing messages are still delivered.",
    business_impact: "Monitoring alone does not block spoofed mail — until you enforce, impersonation of your domain still reaches recipients.",
    recommended_action: "Confirm every legitimate sending source passes alignment, then move DMARC from p=none to p=quarantine, and finally to p=reject with pct=100.",
    effort: "medium",
    owner_type: "customer_it",
    verification_method: "dns_recheck",
    verification_evidence_requirements: "The DMARC policy is observed at p=quarantine or p=reject.",
    supporting_evidence_types: ["dns_txt_lookup"],
    managed_workflow_compatible: true,
  }),
  entry({
    remediation_id: "email.dmarc.reporting",
    domain_key: "email_protection",
    finding_types: ["dmarc_reporting_missing"],
    customer_title: "Turn on DMARC aggregate reporting",
    technical_explanation: "The DMARC record has no aggregate reporting (rua=) destination, so you cannot see who is sending email as your domain.",
    business_impact: "Without reporting you are enforcing — or planning to enforce — blind, which risks blocking legitimate mail or missing abuse.",
    recommended_action: "Add a monitored aggregate reporting address (rua=) to your DMARC record so sender activity becomes visible before you tighten the policy.",
    effort: "low",
    owner_type: "customer_it",
    verification_method: "dns_recheck",
    verification_evidence_requirements: "An rua= destination is present in the DMARC record.",
    supporting_evidence_types: ["dns_txt_lookup"],
    managed_workflow_compatible: true,
  }),
  entry({
    remediation_id: "email.dmarc.single_record",
    domain_key: "email_protection",
    finding_types: ["dmarc_multiple_records", "multiple_dmarc_records"],
    customer_title: "Publish exactly one DMARC record",
    technical_explanation: "More than one DMARC TXT record was found at _dmarc.<domain>; receivers ignore DMARC entirely when multiple records exist.",
    business_impact: "Duplicate records silently disable DMARC, leaving your domain unprotected while appearing configured.",
    recommended_action: "Merge the required tags into a single TXT record at _dmarc.<domain> and remove the duplicates.",
    effort: "low",
    owner_type: "customer_it",
    verification_method: "dns_recheck",
    verification_evidence_requirements: "Exactly one DMARC record is observed.",
    supporting_evidence_types: ["dns_txt_lookup"],
  }),
  entry({
    remediation_id: "email.dmarc.valid_record",
    domain_key: "email_protection",
    finding_types: ["dmarc_invalid_record", "invalid_dmarc"],
    customer_title: "Correct the DMARC record syntax",
    technical_explanation: "A DMARC record was found but is not valid, so receivers cannot apply the policy.",
    business_impact: "An invalid record provides no protection and no reporting, despite appearing to be in place.",
    recommended_action: "Correct the version, policy and percentage tags while preserving any valid reporting destinations, then re-check the record.",
    effort: "low",
    owner_type: "customer_it",
    verification_method: "dns_recheck",
    verification_evidence_requirements: "A syntactically valid DMARC record is observed.",
    supporting_evidence_types: ["dns_txt_lookup"],
  }),
  entry({
    remediation_id: "email.spf.publish",
    domain_key: "email_protection",
    finding_types: ["email_missing_spf", "email_intel_spf_missing", "spf_missing"],
    customer_title: "Publish an SPF record",
    technical_explanation: "No SPF record was found, so receivers cannot tell which servers are authorised to send email for your domain.",
    business_impact: "Without SPF, any server can send mail claiming to be your domain, which underpins spoofing and phishing of your customers and staff.",
    recommended_action: "Inventory every legitimate sending service and publish a single SPF TXT record listing them; use ~all while you confirm coverage, then move to -all once all authorised senders are verified.",
    effort: "medium",
    owner_type: "customer_it",
    verification_method: "dns_recheck",
    verification_evidence_requirements: "A single valid SPF record is observed on the domain.",
    supporting_evidence_types: ["dns_txt_lookup"],
  }),
  entry({
    remediation_id: "email.spf.tighten",
    domain_key: "email_protection",
    finding_types: ["email_intel_spf_permissive", "spf_permissive_all", "spf_neutral_all", "spf_softfail_all"],
    customer_title: "Tighten SPF enforcement",
    technical_explanation: "The SPF record ends in a permissive qualifier (+all, ?all or a softfail you intend to harden), so unauthorised senders are not rejected.",
    business_impact: "A permissive SPF record gives the appearance of protection while still allowing spoofed mail to pass.",
    recommended_action: "Enumerate every authorised sending source, remove +all, and finish the record with -all once you are confident the inventory is complete.",
    effort: "medium",
    owner_type: "customer_it",
    verification_method: "dns_recheck",
    verification_evidence_requirements: "The SPF record ends in -all with all senders enumerated.",
    supporting_evidence_types: ["dns_txt_lookup"],
  }),
  entry({
    remediation_id: "email.spf.single_record",
    domain_key: "email_protection",
    finding_types: ["spf_multiple_records"],
    customer_title: "Publish exactly one SPF record",
    technical_explanation: "Multiple SPF records were found; RFC 7208 requires exactly one, and receivers treat multiple records as a permanent error.",
    business_impact: "Duplicate SPF records break SPF evaluation, undermining DMARC alignment and mail deliverability.",
    recommended_action: "Merge all required mechanisms into one v=spf1 TXT record and remove the duplicates.",
    effort: "low",
    owner_type: "customer_it",
    verification_method: "dns_recheck",
    verification_evidence_requirements: "Exactly one SPF record is observed.",
    supporting_evidence_types: ["dns_txt_lookup"],
  }),
  entry({
    remediation_id: "email.spf.lookup_limit",
    domain_key: "email_protection",
    finding_types: ["spf_lookup_limit"],
    customer_title: "Reduce SPF DNS lookups",
    technical_explanation: "The SPF record exceeds the RFC 7208 limit of ten DNS-lookup mechanisms, causing a permanent error (permerror).",
    business_impact: "An over-limit SPF record fails evaluation, so legitimate mail can fail authentication and DMARC alignment.",
    recommended_action: "Remove unused includes and consolidate sending services; avoid manual record flattening unless you have change management to keep it current.",
    effort: "medium",
    owner_type: "customer_it",
    verification_method: "dns_recheck",
    verification_evidence_requirements: "SPF evaluates within ten DNS lookups.",
    supporting_evidence_types: ["dns_txt_lookup"],
  }),
  entry({
    remediation_id: "email.spf.ptr",
    domain_key: "email_protection",
    finding_types: ["spf_ptr_mechanism"],
    customer_title: "Replace the SPF ptr mechanism",
    technical_explanation: "The SPF record uses the deprecated ptr mechanism, which is slow and discouraged by RFC 7208.",
    business_impact: "ptr can cause inconsistent SPF results and is ignored by some receivers, weakening authentication.",
    recommended_action: "Replace ptr with explicit include, ip4, ip6, a or mx mechanisms where appropriate.",
    effort: "low",
    owner_type: "customer_it",
    verification_method: "dns_recheck",
    verification_evidence_requirements: "The SPF record no longer contains a ptr mechanism.",
    supporting_evidence_types: ["dns_txt_lookup"],
  }),
  entry({
    remediation_id: "email.dkim.verify",
    domain_key: "email_protection",
    finding_types: ["email_dkim_not_detected", "email_intel_dkim_not_found", "dkim_verification_uncertain"],
    customer_title: "Confirm DKIM signing",
    technical_explanation: "DKIM could not be verified using common selectors. This does not prove DKIM is absent — the active selector is provider-specific and cannot be enumerated externally.",
    business_impact: "If outbound mail is not DKIM-signed, it is easier to spoof and less likely to reach the inbox; if it is signed, this is informational only.",
    recommended_action: "Confirm the active DKIM selector with your email provider and verify that selector's DNS record directly, or inspect the Authentication-Results header of a signed message.",
    effort: "low",
    owner_type: "email_provider",
    verification_method: "manual_attestation",
    verification_evidence_requirements: "The active DKIM selector is confirmed with the provider; it cannot be enumerated externally.",
    supporting_evidence_types: ["dns_txt_lookup"],
    limitations: ["The active DKIM selector cannot be discovered externally, so absence cannot be asserted from a scan alone."],
  }),
  entry({
    remediation_id: "email.mta_sts.enable",
    domain_key: "email_protection",
    finding_types: ["email_intel_mta_sts_missing", "mta_sts_policy_missing", "mta_sts"],
    customer_title: "Enable MTA-STS",
    technical_explanation: "No MTA-STS policy was observed. MTA-STS tells sending servers to require TLS when delivering mail to your domain.",
    business_impact: "Without MTA-STS, inbound mail can be delivered over an unencrypted or downgraded connection, exposing it to interception.",
    recommended_action: "Once SPF, DKIM and DMARC are deployed, publish an MTA-STS policy file over HTTPS and the supporting _mta-sts.<domain> TXT record; start in testing mode, then move to enforce.",
    effort: "high",
    owner_type: "customer_it",
    verification_method: "https_recheck",
    verification_evidence_requirements: "Both the _mta-sts TXT record and the HTTPS-served policy file are observed.",
    supporting_evidence_types: ["dns_txt_lookup", "https_probe"],
    managed_workflow_compatible: true,
  }),
  entry({
    remediation_id: "email.tls_rpt.enable",
    domain_key: "email_protection",
    finding_types: ["email_intel_tls_rpt_missing", "tls_rpt_missing", "tls_rpt"],
    customer_title: "Enable TLS reporting (TLS-RPT)",
    technical_explanation: "No TLS-RPT record was found. TLS-RPT gives you reports about failures to establish TLS when other servers deliver mail to you.",
    business_impact: "Without TLS-RPT you have no visibility of SMTP TLS delivery problems that can indicate interception or misconfiguration.",
    recommended_action: "Publish a TLS-RPT TXT record at _smtp._tls.<domain> with an rua= address pointing to a mailbox or service you monitor.",
    effort: "low",
    owner_type: "customer_it",
    verification_method: "dns_recheck",
    verification_evidence_requirements: "A v=TLSRPTv1 record is observed at _smtp._tls.<domain>.",
    supporting_evidence_types: ["dns_txt_lookup"],
  }),
  entry({
    remediation_id: "email.bimi.configure",
    domain_key: "email_protection",
    finding_types: ["bimi_not_configured", "bimi_dmarc_enforcement_required", "bimi_certificate_not_listed", "bimi"],
    customer_title: "Consider BIMI once DMARC is enforced",
    technical_explanation: "BIMI displays your brand logo in supporting inboxes, but only takes effect under enforced DMARC (p=quarantine or reject) and, for some providers, a VMC certificate.",
    business_impact: "BIMI is a brand-trust enhancement, not a security control — prioritise DMARC enforcement first.",
    recommended_action: "Complete DMARC enforcement, then, if the brand value justifies it, publish an SVG Tiny PS logo and evaluate a VMC certificate before adding the BIMI record.",
    effort: "medium",
    owner_type: "customer_it",
    verification_method: "dns_recheck",
    verification_evidence_requirements: "A BIMI record is observed and enforced DMARC is in place.",
    supporting_evidence_types: ["dns_txt_lookup"],
    applicability: "Only meaningful once DMARC is enforced.",
    // Evidence-dependent: BIMI only takes effect under enforced DMARC. When the
    // scan evidence shows DMARC is not yet enforced, the resolution is returned
    // with applicable=false so surfaces can defer it rather than mislead.
    applicable: (evidence) => {
      if (!evidence || typeof evidence !== "object") return true;
      if (evidence.dmarc_enforced === undefined) return true;
      return Boolean(evidence.dmarc_enforced);
    },
  }),

  // ── Email Protection — MANAGED LIFECYCLE conditions (PR-B3) ────────────────
  // The entries above describe POSTURE observed by a scan. These five describe
  // conditions of the two managed EMAIL record families, and their evidence is
  // fundamentally different: DMARC aggregate reports are what RECEIVING mail
  // providers tell us they saw, and hosted-record state is our own persisted
  // saga. Neither depends on our scanner at all.
  //
  // These finding types are raised by email-protection-lifecycle.js, never by a
  // scan module, so they are deliberately absent from the scan-emitter sweep in
  // validate-remediation-coverage.js. The `email_` prefix is load-bearing: the
  // email_protection domain matcher in cyber-mot-domains.js tests
  // /^(email_|dmarc_|spf_|dkim_|mta_|bimi_|tlsrpt_)/, so a `hosted_dmarc_*` slug
  // would match NO domain and the finding would belong nowhere.
  entry({
    remediation_id: "email.hosted_dmarc.reconnect",
    domain_key: "email_protection",
    finding_types: ["email_hosted_dmarc_disconnected"],
    customer_title: "Reconnect your hosted DMARC record",
    technical_explanation: "The CNAME at _dmarc.<domain> no longer points at the CyberMeters-managed record, so the DMARC policy CyberMeters hosts for you is no longer being served to receiving mail providers.",
    business_impact: "If no other DMARC record is published in its place, receiving providers have no instruction for messages that fail authentication, and impersonation of your domain can reach recipients again.",
    recommended_action: "Restore the CNAME at _dmarc.<domain> to the CyberMeters target shown on the Email Protection page, or, if you have deliberately moved to a self-managed DMARC record, remove the hosted record so it stops being monitored.",
    effort: "low",
    owner_type: "customer_it",
    verification_method: "dns_recheck",
    verification_evidence_requirements: "The CNAME at _dmarc.<domain> is observed pointing at the CyberMeters hosted target.",
    supporting_evidence_types: ["dns_txt_lookup"],
    managed_workflow_compatible: true,
    applicability: "Applies only to domains using a CyberMeters-hosted DMARC record.",
    // The honesty boundary. We observed that OUR link is absent, from OUR
    // resolver, at one moment. That is not the same claim as "this domain has no
    // DMARC policy" — the customer may have published their own record directly,
    // which is a legitimate outcome and not a finding.
    limitations: [
      "CyberMeters observes that its own hosted record is no longer linked. It does not claim the domain has no DMARC policy — a self-managed record published directly would not be part of this check.",
    ],
  }),
  entry({
    remediation_id: "email.hosted_dmarc.impact_review",
    domain_key: "email_protection",
    finding_types: ["email_hosted_dmarc_impact_regression"],
    customer_title: "Review the impact of your last DMARC policy change",
    technical_explanation: "After the managed DMARC policy last changed, aggregate reports from receiving providers show a higher proportion of your legitimate mail failing authentication than before the change.",
    business_impact: "A DMARC policy tightened ahead of your senders can cause real business mail to be quarantined or rejected. This is the failure mode that makes enforcement risky, and it is why the ramp exists.",
    recommended_action: "Review the sender inventory on the Email Protection page and confirm every legitimate source aligns on SPF or DKIM before tightening further. Roll the policy back if legitimate mail is being affected.",
    effort: "medium",
    owner_type: "customer_it",
    verification_method: "receiver_reports",
    verification_evidence_requirements: "Subsequent aggregate reports show legitimate senders aligning at the pre-change rate or better.",
    supporting_evidence_types: ["dmarc_aggregate_report"],
    managed_workflow_compatible: true,
    applicability: "Applies only to domains using a CyberMeters-hosted DMARC record, after a policy change.",
    limitations: [
      "This is a correlation between a policy change and reported authentication failures, not proof the change caused them. Aggregate reports are sampled and delayed by receiving providers.",
    ],
  }),
  entry({
    remediation_id: "email.hosted_dmarc.auto_rollback_review",
    domain_key: "email_protection",
    finding_types: ["email_hosted_dmarc_auto_rollback"],
    customer_title: "Validate your senders — the DMARC policy was rolled back automatically",
    technical_explanation: "Authentication compliance dropped after the last managed DMARC policy change, so CyberMeters automatically restored the previous policy to protect your legitimate mail.",
    business_impact: "The rollback protected delivery, but the underlying problem remains: at least one legitimate sending source is not aligned, and enforcement cannot progress until it is.",
    recommended_action: "Review the sender inventory, identify which legitimate sources are failing SPF and DKIM alignment, correct their authentication with the relevant provider, and only then resume the enforcement ramp.",
    effort: "medium",
    owner_type: "customer_it",
    verification_method: "manual_attestation",
    verification_evidence_requirements: "The customer confirms each legitimate sender has been corrected. CyberMeters can observe alignment recover in later aggregate reports, but cannot itself confirm which senders are legitimate.",
    supporting_evidence_types: ["dmarc_aggregate_report"],
    managed_workflow_compatible: true,
    applicability: "Applies only to domains using a CyberMeters-hosted DMARC record with automatic rollback.",
    limitations: [
      "CyberMeters restored its own hosted record. It cannot confirm receiving providers have picked the previous policy back up, and DNS propagation is not verified.",
    ],
  }),
  entry({
    remediation_id: "email.sender.review_unrecognised",
    domain_key: "email_protection",
    finding_types: ["email_sender_unrecognised"],
    customer_title: "Review a sending source using your domain",
    technical_explanation: "Receiving mail providers reported a source sending mail that claims your domain, and it is not yet recognised as one of your legitimate senders. It may be a service you use, a forwarder, or someone impersonating you.",
    business_impact: "Until each sending source is classified, you cannot safely enforce DMARC: tightening the policy with an unclassified legitimate sender still unaligned would block your own business mail.",
    recommended_action: "Open the sender inventory on the Email Protection page and classify this source. If it is a service you use, authorise it and correct its SPF or DKIM alignment. If you do not recognise it, mark it unauthorised and continue the enforcement ramp.",
    effort: "low",
    owner_type: "customer",
    verification_method: "manual_attestation",
    verification_evidence_requirements: "The customer classifies the source. This records a customer decision — it is not a CyberMeters verification that the sender is legitimate.",
    supporting_evidence_types: ["dmarc_aggregate_report"],
    managed_workflow_compatible: true,
    applicability: "Applies when DMARC aggregate reporting is delivering reports for the domain.",
    limitations: [
      "Only sources that receiving providers reported are visible. A sender whose mail no receiver reported on will not appear, so this is not a complete inventory of who sends as you.",
      "Whether a sender is legitimate is a customer decision. CyberMeters classifies from authentication evidence and cannot know which third-party services you have authorised.",
    ],
  }),
  entry({
    remediation_id: "email.sender.unauthorised_failures_active",
    domain_key: "email_protection",
    finding_types: ["email_sender_unauthorised_failures"],
    customer_title: "An unauthorised source is failing authentication using your domain",
    technical_explanation: "Within the last 7 days, receiving mail providers reported at least 50 messages from a source classified as unauthorised that claimed your domain and failed both SPF and DKIM alignment.",
    business_impact: "Mail claiming your domain is failing authentication at volume. If your DMARC policy is enforced, receivers are rejecting or quarantining it. If it is not enforced, some of it may be reaching recipients.",
    recommended_action: "Confirm this source is not a legitimate service of yours that has been misconfigured. If it is not yours, no action can stop it sending — the defence is DMARC enforcement, so complete the ramp to p=reject to ensure receivers discard it.",
    effort: "medium",
    owner_type: "customer_it",
    verification_method: "receiver_reports",
    verification_evidence_requirements: "Subsequent aggregate reports show no failing messages from this source across a complete 7-day window.",
    supporting_evidence_types: ["dmarc_aggregate_report"],
    managed_workflow_compatible: true,
    applicability: "Applies when DMARC aggregate reporting is delivering reports for the domain.",
    // The claim boundary, enforced in copy and in the recurrence name. We hold no
    // prior-period baseline, so we cannot say this is a spike, an increase or an
    // attack. We can say how many failing messages receivers reported in a fixed
    // window, and nothing more.
    limitations: [
      "This is an absolute count of failing messages reported inside a rolling 7-day window. CyberMeters does not compare it against a previous period, so it is not evidence of a spike, an increase, or a targeted attack.",
      "Failed authentication is not proof of spoofing: a misconfigured legitimate sender produces the same evidence, which is why the source should be confirmed before it is treated as hostile.",
      "A failing message is not a delivered message. Aggregate reports describe what receivers saw, not what reached an inbox.",
    ],
  }),

  // ─────────────────────────── BRAND PROTECTION ──────────────────────────────
  entry({
    remediation_id: "brand.lookalike.review",
    domain_key: "brand_protection",
    finding_types: ["brand_lookalike_detected", "brand_homoglyph_detected", "brand_typosquat_detected"],
    customer_title: "Review and prepare action on the lookalike domain",
    technical_explanation: "A domain that closely resembles your brand was observed. Registration and mail-sending capability — not string similarity alone — determine whether it is a live threat.",
    business_impact: "Registered lookalikes that can send mail or host content enable phishing and impersonation of your customers and staff.",
    recommended_action: "Confirm whether the domain is registered and able to send mail or serve content, gather the evidence bundle, then submit a takedown request to the registrar or abuse contact and track it to resolution. CyberMeters prepares and tracks the case; the takedown itself is actioned by the registrar or provider.",
    effort: "medium",
    owner_type: "registrar",
    verification_method: "rescan",
    verification_evidence_requirements: "CyberMeters re-checks the candidate until it is no longer technically present; removal is confirmed by the product, not asserted by the customer.",
    supporting_evidence_types: ["dns_lookup", "whois", "http_probe", "certificate_transparency_observation"],
    managed_workflow_compatible: true,
    case_type: "brand_abuse",
    limitations: ["CyberMeters prepares and tracks takedowns but does not execute them; the registrar or hosting provider actions the removal."],
  }),

  // ─────────────────────────── ATTACK SURFACE ────────────────────────────────
  entry({
    remediation_id: "asm.dns.resolution",
    domain_key: "attack_surface",
    finding_types: ["dns_no_resolution"],
    customer_title: "Restore DNS resolution",
    technical_explanation: "The domain did not resolve to any address, so the site and its services are unreachable.",
    business_impact: "An unresolvable domain means outage — customers cannot reach your services and mail may fail.",
    recommended_action: "Ensure A/AAAA records are published for your domain pointing at your server or hosting provider, and confirm the zone is served by your authoritative nameservers.",
    effort: "medium",
    owner_type: "customer_it",
    verification_method: "dns_recheck",
    verification_evidence_requirements: "The domain resolves to a valid address.",
    supporting_evidence_types: ["dns_lookup"],
  }),
  entry({
    remediation_id: "asm.subdomain.takeover",
    domain_key: "attack_surface",
    finding_types: ["subdomain_takeover", "subdomain_takeover_risk", "cloud_storage_takeover_risk"],
    customer_title: "Fix dangling DNS records",
    technical_explanation: "One or more DNS records point at a service or cloud resource that is no longer claimed, creating a subdomain-takeover risk.",
    business_impact: "An attacker who claims the referenced service can serve content or collect data from a hostname your customers trust.",
    recommended_action: "For each dangling record, either reclaim the referenced service, repoint the record at a valid endpoint, or remove the record entirely.",
    effort: "medium",
    owner_type: "customer_it",
    verification_method: "rescan",
    verification_evidence_requirements: "The dangling reference is removed or the service is reclaimed on a fresh scan.",
    supporting_evidence_types: ["dns_lookup", "http_probe"],
    managed_workflow_compatible: true,
    case_type: "asm_exposure",
  }),
  entry({
    remediation_id: "asm.subdomain.sensitive",
    domain_key: "attack_surface",
    finding_types: ["subdomain_sensitive"],
    customer_title: "Review reachable sensitive subdomains",
    technical_explanation: "Subdomains whose names suggest development or administrative use responded to HTTP probes.",
    business_impact: "Development, staging and admin hostnames exposed to the internet widen your attack surface and often carry weaker controls.",
    recommended_action: "Confirm that public access to each named subdomain is intentional and appropriately protected; restrict any that should not be publicly reachable.",
    effort: "medium",
    owner_type: "customer_it",
    verification_method: "rescan",
    verification_evidence_requirements: "Access to the subdomain is restricted or confirmed intentional on a fresh scan.",
    supporting_evidence_types: ["http_probe", "certificate_transparency_observation"],
    managed_workflow_compatible: true,
    case_type: "asm_exposure",
  }),
  entry({
    remediation_id: "asm.exposure.admin",
    domain_key: "attack_surface",
    finding_types: ["asset_exposure_admin_interface", "admin_surface_critical", "admin_surface_high", "admin_surface_medium"],
    customer_title: "Restrict administrative interfaces",
    technical_explanation: "Administrative interfaces were reachable directly from the public internet.",
    business_impact: "Publicly reachable admin panels are a primary target for credential attacks and unauthorised access.",
    recommended_action: "Limit each admin interface to trusted IP ranges, or place it behind a VPN or MFA-protected gateway.",
    effort: "medium",
    owner_type: "customer_it",
    verification_method: "rescan",
    verification_evidence_requirements: "The admin interface is no longer publicly reachable on a fresh scan.",
    supporting_evidence_types: ["http_probe"],
    managed_workflow_compatible: true,
    case_type: "asm_exposure",
  }),
  entry({
    remediation_id: "asm.exposure.sensitive_tool",
    domain_key: "attack_surface",
    finding_types: ["asset_exposure_sensitive_tool"],
    customer_title: "Restrict exposed management tools",
    technical_explanation: "Sensitive management tools were reachable directly from the public internet.",
    business_impact: "Exposed management tooling can leak configuration or provide a foothold for attackers.",
    recommended_action: "Firewall or VPN-protect the affected interfaces and allow only trusted IP ranges.",
    effort: "medium",
    owner_type: "customer_it",
    verification_method: "rescan",
    verification_evidence_requirements: "The tool is no longer publicly reachable on a fresh scan.",
    supporting_evidence_types: ["http_probe"],
    managed_workflow_compatible: true,
    case_type: "asm_exposure",
  }),
  entry({
    remediation_id: "asm.exposure.dev_env",
    domain_key: "attack_surface",
    finding_types: ["asset_exposure_dev_env"],
    customer_title: "Restrict development environments",
    technical_explanation: "Development or staging environments were reachable directly from the public internet.",
    business_impact: "Non-production environments often carry weaker controls and test data, making public exposure risky.",
    recommended_action: "Firewall or add authentication to development and staging environments so they are not publicly accessible.",
    effort: "medium",
    owner_type: "customer_it",
    verification_method: "rescan",
    verification_evidence_requirements: "The environment is no longer publicly reachable on a fresh scan.",
    supporting_evidence_types: ["http_probe"],
    managed_workflow_compatible: true,
    case_type: "asm_exposure",
  }),
  entry({
    remediation_id: "asm.cloud_storage.public",
    domain_key: "attack_surface",
    finding_types: ["cloud_storage_public_listing"],
    customer_title: "Disable public cloud-storage listing",
    technical_explanation: "A cloud-storage bucket or container allowed anonymous listing of its contents.",
    business_impact: "Anonymous listing can expose files and directory structure to anyone on the internet.",
    recommended_action: "Disable anonymous listing and restrict storage access to explicitly authorised principals.",
    effort: "low",
    owner_type: "customer_it",
    verification_method: "rescan",
    verification_evidence_requirements: "Anonymous listing is no longer possible on a fresh scan.",
    supporting_evidence_types: ["http_probe"],
    managed_workflow_compatible: true,
    case_type: "asm_exposure",
  }),
  entry({
    remediation_id: "asm.cloud_storage.review",
    domain_key: "attack_surface",
    finding_types: ["cloud_storage_exposure_observed"],
    customer_title: "Confirm cloud-storage exposure is intentional",
    technical_explanation: "A publicly reachable cloud-storage endpoint was observed; its contents were not confirmed sensitive.",
    business_impact: "Unintended public storage endpoints can expose data if they hold sensitive material.",
    recommended_action: "Verify the storage endpoint is intentionally public and contains no sensitive data; restrict it otherwise.",
    effort: "low",
    owner_type: "customer_it",
    verification_method: "rescan",
    verification_evidence_requirements: "The endpoint is restricted or confirmed intentionally public.",
    supporting_evidence_types: ["http_probe"],
  }),
  entry({
    remediation_id: "asm.vuln.kev",
    domain_key: "attack_surface",
    finding_types: ["kev_active_exploitation"],
    customer_title: "Patch a known-exploited vulnerability",
    technical_explanation: "An externally observed technology matches a CISA Known Exploited Vulnerabilities (KEV) entry, indicating active exploitation in the wild.",
    business_impact: "Known-exploited vulnerabilities are being used by attackers now and warrant immediate escalation.",
    recommended_action: "Apply the vendor security update per the CISA advisory immediately, or take the affected service offline until patched.",
    effort: "high",
    owner_type: "customer_it",
    verification_method: "rescan",
    verification_evidence_requirements: "The vulnerable version is no longer observed on a fresh scan.",
    supporting_evidence_types: ["http_fingerprint_observation"],
    limitations: ["Detection is based on externally observable version fingerprints and may not confirm the vulnerability is reachable or exploitable in your configuration."],
  }),
  entry({
    remediation_id: "asm.vuln.cve",
    domain_key: "attack_surface",
    finding_types: ["cve_high_severity_detected", "known_vulnerable_component"],
    customer_title: "Update a vulnerable component",
    technical_explanation: "An externally observed technology version matches a high-severity CVE.",
    business_impact: "Unpatched high-severity vulnerabilities can be exploited to compromise the service.",
    recommended_action: "Update the affected component to a fixed version, following the vendor advisory.",
    effort: "high",
    owner_type: "customer_it",
    verification_method: "rescan",
    verification_evidence_requirements: "The vulnerable version is no longer observed on a fresh scan.",
    supporting_evidence_types: ["http_fingerprint_observation"],
    limitations: ["Detection is based on externally observable version fingerprints; reachability and exploitability in your configuration are not confirmed."],
  }),
  entry({
    remediation_id: "asm.dnssec.enable",
    domain_key: "attack_surface",
    finding_types: ["dnssec_not_enabled", "dnssec_misconfigured"],
    customer_title: "Enable or correct DNSSEC",
    technical_explanation: "DNSSEC was not enabled or was misconfigured for the zone.",
    business_impact: "Without valid DNSSEC, DNS responses for your domain can be forged, enabling traffic redirection.",
    recommended_action: "Enable DNSSEC with your DNS provider and publish the DS record at the registrar; if misconfigured, correct the chain of trust.",
    effort: "medium",
    owner_type: "customer_it",
    verification_method: "dns_recheck",
    verification_evidence_requirements: "A valid DNSSEC chain is observed.",
    supporting_evidence_types: ["dnssec_lookup"],
  }),
  entry({
    remediation_id: "asm.domain.expiry",
    domain_key: "attack_surface",
    finding_types: ["whois_domain_expired", "whois_expiry_critical", "whois_expiry_warning"],
    customer_title: "Renew the domain registration",
    technical_explanation: "The domain registration has expired or is approaching expiry according to registry (WHOIS/RDAP) data.",
    business_impact: "An expired domain can be suspended or re-registered by a third party, causing outage and enabling impersonation.",
    recommended_action: "Renew the domain immediately through your registrar and enable auto-renewal to prevent recurrence.",
    effort: "low",
    owner_type: "registrar",
    verification_method: "rescan",
    verification_evidence_requirements: "Registry data shows a future expiry date on a fresh scan.",
    supporting_evidence_types: ["whois"],
  }),

  // ────────────────────────── CERTIFICATES & TRUST ───────────────────────────
  entry({
    remediation_id: "cert.expiry.expired",
    domain_key: "certificates_trust",
    finding_types: ["ssl_certificate_expired", "certificate_expired", "certificate_expiring_critical"],
    customer_title: "Renew the expired certificate",
    technical_explanation: "The TLS certificate observed for this service has expired.",
    business_impact: "Browsers block or warn on expired certificates, breaking access and eroding customer trust.",
    recommended_action: "Renew and deploy the certificate, configure automated renewal, then run a fresh Cyber MOT to confirm the new certificate.",
    effort: "low",
    owner_type: "customer_it",
    verification_method: "certificate_recheck",
    verification_evidence_requirements: "A valid, in-date certificate is observed.",
    supporting_evidence_types: ["certificate_transparency_observation", "https_probe"],
  }),
  entry({
    remediation_id: "cert.expiry.expiring",
    domain_key: "certificates_trust",
    finding_types: ["ssl_certificate_expiring_soon", "certificate_expiring_soon"],
    customer_title: "Renew the certificate before expiry",
    technical_explanation: "The TLS certificate is approaching its expiry date.",
    business_impact: "A lapse causes browser errors and downtime; renewing ahead of time avoids an outage.",
    recommended_action: "Schedule renewal, deploy the replacement certificate, and confirm it is visible after deployment.",
    effort: "low",
    owner_type: "customer_it",
    verification_method: "certificate_recheck",
    verification_evidence_requirements: "A replacement certificate with a later expiry is observed.",
    supporting_evidence_types: ["certificate_transparency_observation", "https_probe"],
  }),
  entry({
    remediation_id: "cert.tls.install",
    domain_key: "certificates_trust",
    finding_types: ["ssl_not_available", "ssl_no_certificate"],
    customer_title: "Enable HTTPS with a valid certificate",
    technical_explanation: "No usable TLS certificate was served for the site, so it cannot be reached securely over HTTPS.",
    business_impact: "Without HTTPS, traffic is unencrypted and browsers mark the site as not secure, deterring customers.",
    recommended_action: "Install a publicly trusted TLS certificate — for example a free certificate from Let's Encrypt via your hosting provider — and enable HTTPS.",
    effort: "medium",
    owner_type: "customer_it",
    verification_method: "https_recheck",
    verification_evidence_requirements: "A valid certificate is served over HTTPS.",
    supporting_evidence_types: ["https_probe", "certificate_transparency_observation"],
  }),
  entry({
    remediation_id: "cert.self_signed",
    domain_key: "certificates_trust",
    finding_types: ["certificate_self_signed"],
    customer_title: "Use a publicly trusted certificate",
    technical_explanation: "A self-signed certificate was observed for a public service.",
    business_impact: "Self-signed certificates trigger browser warnings and are unsuitable for public business services.",
    recommended_action: "Replace the self-signed certificate with one from a publicly trusted certificate authority.",
    effort: "low",
    owner_type: "customer_it",
    verification_method: "certificate_recheck",
    verification_evidence_requirements: "A publicly trusted certificate is observed.",
    supporting_evidence_types: ["https_probe"],
  }),
  entry({
    remediation_id: "cert.ca_concentration",
    domain_key: "certificates_trust",
    finding_types: ["certificate_ca_concentration"],
    customer_title: "Track certificate-authority concentration",
    technical_explanation: "A large share of your certificates are issued by a single certificate authority.",
    business_impact: "Heavy dependence on one CA is an operational resilience risk if that CA has an outage or account issue.",
    recommended_action: "Track CA dependency as an operational risk and ensure renewal runbooks cover issuer outages or account problems.",
    effort: "low",
    owner_type: "customer_it",
    verification_method: "manual_attestation",
    verification_evidence_requirements: "Runbook coverage is an internal process control and is not externally observable.",
    supporting_evidence_types: ["certificate_transparency_observation"],
  }),
  entry({
    remediation_id: "cert.anomaly.review",
    domain_key: "certificates_trust",
    finding_types: ["certificate_unexpected_issuer", "certificate_unexpected_san", "certificate_unexpected_wildcard", "certificate_parallel_observed", "wildcard_dns_detected"],
    customer_title: "Review an unexpected certificate change",
    technical_explanation: "A new issuer, SAN, wildcard or parallel certificate was observed via Certificate Transparency. This is a change signal, not proof of compromise.",
    business_impact: "Unexpected certificate changes can indicate a planned renewal — or, occasionally, unauthorised issuance worth confirming.",
    recommended_action: "Confirm the change was expected and tied to a planned renewal or hosting change; review and retire any certificate coverage that is not intended.",
    effort: "low",
    owner_type: "customer_it",
    verification_method: "manual_attestation",
    verification_evidence_requirements: "The change is confirmed expected by the certificate owner; the product observes the certificate but cannot confirm intent.",
    supporting_evidence_types: ["certificate_transparency_observation"],
    limitations: ["Based on Certificate Transparency observation; chain, root trust, OCSP and revocation status are not verified."],
  }),
  entry({
    remediation_id: "cert.ct_incomplete",
    domain_key: "certificates_trust",
    finding_types: ["ct_source_incomplete", "ct_sources_unavailable", "ct_source_discrepancy"],
    customer_title: "Certificate evidence is incomplete",
    technical_explanation: "Certificate Transparency sources were unavailable or disagreed, so the certificate picture for this scan is incomplete.",
    business_impact: "This is a data-completeness limitation, not a confirmed problem with your certificates.",
    recommended_action: "Review again after the next scan; Certificate Transparency source availability can vary between scans.",
    effort: "low",
    owner_type: "cybermeters",
    verification_method: "unsupported",
    verification_evidence_requirements: "Chain, root trust, OCSP, revocation and served-certificate verification require live TLS inspection, which this scan does not perform.",
    supporting_evidence_types: ["certificate_transparency_observation"],
    limitations: ["Certificate Transparency does not provide chain, root-trust, OCSP or revocation status; those remain unknown without live TLS inspection."],
  }),
  entry({
    remediation_id: "cert.coverage_gap",
    domain_key: "certificates_trust",
    finding_types: ["certificate_coverage_gap"],
    customer_title: "Confirm expected HTTPS coverage",
    technical_explanation: "A domain expected to serve HTTPS did not present a certificate in this scan's evidence.",
    business_impact: "A coverage gap may mean a service is not serving HTTPS where expected, or that evidence was simply not collected.",
    recommended_action: "Run a fresh Cyber MOT and confirm the domain serves HTTPS where expected.",
    effort: "low",
    owner_type: "customer_it",
    verification_method: "rescan",
    verification_evidence_requirements: "HTTPS coverage is observed on a fresh scan.",
    supporting_evidence_types: ["https_probe", "certificate_transparency_observation"],
  }),
  entry({
    remediation_id: "cert.intelligence.review",
    domain_key: "certificates_trust",
    finding_types: ["certificate_intelligence_review", "ce_cert_review"],
    customer_title: "Review certificate intelligence signals",
    technical_explanation: "Certificate intelligence surfaced an elevated risk signal — for example an approaching expiry, an unexpected issuer, or a suspicious certificate observation.",
    business_impact: "Unreviewed certificate signals can hide an impending outage or an unauthorised certificate issued for your domain.",
    recommended_action: "Review certificate expiry, issuer and any suspicious certificate signals; renew or reissue where needed and confirm the change on a fresh scan.",
    effort: "low",
    owner_type: "customer_it",
    verification_method: "rescan",
    verification_evidence_requirements: "The certificate signal is resolved or confirmed expected on a fresh scan.",
    supporting_evidence_types: ["certificate_transparency_observation", "https_probe"],
    limitations: ["Based on Certificate Transparency and HTTP evidence; chain, root trust, OCSP and revocation status are not verified."],
  }),
  entry({
    remediation_id: "cert.caa.configure",
    domain_key: "certificates_trust",
    finding_types: ["dse_missing_caa", "dse_caa_no_issuers", "caa_not_configured"],
    customer_title: "Configure a CAA record",
    technical_explanation: "No CAA record — or a CAA record with no authorised issuer — was found for the domain. CAA restricts which certificate authorities may issue certificates for your domain.",
    business_impact: "Without CAA, any certificate authority can be persuaded to issue a certificate for your domain, widening the mis-issuance attack surface.",
    recommended_action: "Publish a CAA record at the zone apex listing every certificate authority you actually use (0 issue \"<ca>\"), and add an iodef contact to receive mis-issuance reports.",
    effort: "low",
    owner_type: "customer_it",
    verification_method: "dns_recheck",
    verification_evidence_requirements: "A CAA record with at least one authorised issuer is observed.",
    supporting_evidence_types: ["dns_lookup"],
  }),

  // ─────────────────────────── WEBSITE SECURITY ──────────────────────────────
  entry({
    remediation_id: "web.https.redirect",
    domain_key: "website_security",
    finding_types: ["ssl_no_http_redirect", "no_https_redirect"],
    customer_title: "Redirect HTTP to HTTPS",
    technical_explanation: "Requests over plain HTTP are not redirected to HTTPS.",
    business_impact: "Users can land on an unencrypted version of the site, exposing traffic and weakening trust.",
    recommended_action: "Configure your web server or CDN to issue a permanent 301 redirect from http:// to https:// for all requests.",
    effort: "low",
    owner_type: "customer_it",
    verification_method: "https_recheck",
    verification_evidence_requirements: "HTTP requests redirect to HTTPS.",
    supporting_evidence_types: ["http_redirect_probe"],
  }),
  entry({
    remediation_id: "web.header.hsts",
    domain_key: "website_security",
    finding_types: ["header_missing_strict_transport_security", "header_weak_hsts", "header_malformed_strict_transport_security", "dse_hsts_short_maxage", "dse_hsts_not_preload_eligible"],
    customer_title: "Add or strengthen HSTS",
    technical_explanation: "The Strict-Transport-Security header is missing, weak or malformed, so browsers are not told to always use HTTPS.",
    business_impact: "Without strong HSTS, users can be downgraded to HTTP by an attacker on the network.",
    recommended_action: "Send Strict-Transport-Security with a max-age of at least 31536000 seconds and includeSubDomains once all subdomains support HTTPS.",
    effort: "low",
    owner_type: "customer_it",
    verification_method: "https_recheck",
    verification_evidence_requirements: "A valid HSTS header with an adequate max-age is observed.",
    supporting_evidence_types: ["http_header_probe"],
  }),
  entry({
    remediation_id: "web.header.csp",
    domain_key: "website_security",
    finding_types: ["header_missing_content_security_policy", "csp_weak_policy", "header_malformed_content_security_policy"],
    customer_title: "Add a Content Security Policy",
    technical_explanation: "No Content-Security-Policy header — or only a weak one — was observed, so the browser is not restricted in what it may load.",
    business_impact: "A missing or weak CSP makes cross-site scripting and content-injection attacks easier to exploit.",
    recommended_action: "Add a Content-Security-Policy header suited to your application, starting in report-only mode to tune it before enforcing.",
    effort: "medium",
    owner_type: "customer_it",
    verification_method: "https_recheck",
    verification_evidence_requirements: "A Content-Security-Policy header is observed.",
    supporting_evidence_types: ["http_header_probe"],
  }),
  entry({
    remediation_id: "web.header.xfo",
    domain_key: "website_security",
    finding_types: ["header_missing_x_frame_options", "header_malformed_x_frame_options"],
    customer_title: "Add clickjacking protection",
    technical_explanation: "The X-Frame-Options header (or a framing directive in CSP) is missing.",
    business_impact: "Without framing protection, your site can be embedded in an attacker's page for clickjacking.",
    recommended_action: "Add X-Frame-Options: DENY, or a frame-ancestors directive in your Content-Security-Policy.",
    effort: "low",
    owner_type: "customer_it",
    verification_method: "https_recheck",
    verification_evidence_requirements: "A framing-protection header is observed.",
    supporting_evidence_types: ["http_header_probe"],
  }),
  entry({
    remediation_id: "web.header.xcto",
    domain_key: "website_security",
    finding_types: ["header_missing_x_content_type_options", "header_malformed_x_content_type_options"],
    customer_title: "Prevent MIME-type sniffing",
    technical_explanation: "The X-Content-Type-Options header is missing.",
    business_impact: "Without it, browsers may interpret files as a different type, enabling some content-based attacks.",
    recommended_action: "Add X-Content-Type-Options: nosniff to all responses.",
    effort: "low",
    owner_type: "customer_it",
    verification_method: "https_recheck",
    verification_evidence_requirements: "The nosniff header is observed.",
    supporting_evidence_types: ["http_header_probe"],
  }),
  entry({
    remediation_id: "web.header.referrer",
    domain_key: "website_security",
    finding_types: ["header_missing_referrer_policy", "header_malformed_referrer_policy"],
    customer_title: "Set a Referrer-Policy",
    technical_explanation: "No Referrer-Policy header was observed.",
    business_impact: "Without a referrer policy, full URLs may leak to third-party sites, potentially exposing sensitive parameters.",
    recommended_action: "Add Referrer-Policy: strict-origin-when-cross-origin (or stricter) to responses.",
    effort: "low",
    owner_type: "customer_it",
    verification_method: "https_recheck",
    verification_evidence_requirements: "A Referrer-Policy header is observed.",
    supporting_evidence_types: ["http_header_probe"],
  }),
  entry({
    remediation_id: "web.header.permissions",
    domain_key: "website_security",
    finding_types: ["header_missing_permissions_policy", "header_malformed_permissions_policy"],
    customer_title: "Set a Permissions-Policy",
    technical_explanation: "No Permissions-Policy header was observed.",
    business_impact: "Without it, embedded content has broader access to browser features than necessary.",
    recommended_action: "Add a Permissions-Policy header restricting access to features such as camera, microphone and geolocation.",
    effort: "low",
    owner_type: "customer_it",
    verification_method: "https_recheck",
    verification_evidence_requirements: "A Permissions-Policy header is observed.",
    supporting_evidence_types: ["http_header_probe"],
  }),
  entry({
    remediation_id: "web.cookie.flags",
    domain_key: "website_security",
    finding_types: ["dse_cookie_no_secure", "dse_cookie_no_httponly", "dse_cookie_no_samesite"],
    customer_title: "Set secure cookie flags",
    technical_explanation: "Cookies were set without the Secure and/or HttpOnly flags.",
    business_impact: "Cookies without these flags can be sent over HTTP or read by scripts, increasing session-hijacking risk.",
    recommended_action: "Set the Secure and HttpOnly flags on session cookies, and SameSite where appropriate.",
    effort: "low",
    owner_type: "customer_it",
    verification_method: "https_recheck",
    verification_evidence_requirements: "Cookies are observed with Secure and HttpOnly flags.",
    supporting_evidence_types: ["http_header_probe"],
  }),
  entry({
    remediation_id: "web.tech.version_disclosure",
    domain_key: "website_security",
    finding_types: ["tech_xpoweredby_version_disclosure", "tech_server_version_disclosure"],
    customer_title: "Suppress version disclosure headers",
    technical_explanation: "Response headers disclose the exact server or framework version.",
    business_impact: "Version disclosure helps attackers match your stack to known vulnerabilities, though it is low severity on its own.",
    recommended_action: "Configure your web server to return a generic or empty Server / X-Powered-By header.",
    effort: "low",
    owner_type: "customer_it",
    verification_method: "https_recheck",
    verification_evidence_requirements: "The version is no longer disclosed in response headers.",
    supporting_evidence_types: ["http_header_probe"],
  }),

  // ─────────────────────── CYBER ESSENTIALS READINESS ────────────────────────
  entry({
    remediation_id: "ce.certification.external",
    domain_key: "cyber_essentials_readiness",
    finding_types: ["ce_certification_scope"],
    customer_title: "Cyber Essentials certification is issued externally",
    technical_explanation: "CyberMeters estimates readiness from externally observable controls and your self-attested answers. It does not issue Cyber Essentials certification.",
    business_impact: "Readiness indicates likely gaps before assessment; certification itself confers the recognised trust mark.",
    recommended_action: "Close the highlighted readiness gaps, then pursue certification through an IASME-accredited certification body.",
    effort: "medium",
    owner_type: "external_body",
    verification_method: "external",
    verification_evidence_requirements: "Certification is confirmed by an IASME-accredited certification body, not by CyberMeters.",
    supporting_evidence_types: ["self_attestation"],
    limitations: ["Readiness is an estimate over observable controls and self-attestation; it is not a Cyber Essentials certification and does not replace assessment."],
  }),
  entry({
    // The customer-facing meaning of a CE readiness TRANSITION. Without it,
    // emitLifecycleAlert falls back to "<entity>: review required" / "Review this
    // item in CyberMeters." — a content-free email, which is the one thing a
    // readiness alert must never be: its whole value is naming which evidence moved.
    //
    // Deliberately framed as REVIEW, not as a defect. The defect already has its own
    // alert in the domain that owns it (Email Protection, Website Security,
    // Certificates & Trust). This says only that the theme's externally evidenced
    // readiness changed, and points at the evidence.
    remediation_id: "ce.readiness.control_review",
    domain_key: "cyber_essentials_readiness",
    finding_types: ["ce_control_not_ready", "ce_control_worsened"],
    customer_title: "Review a Cyber Essentials control area whose external evidence changed",
    technical_explanation: "The externally observable evidence for this Cyber Essentials control area no longer supports readiness. CyberMeters assesses this control from outside only — from HTTPS, security headers, certificate and email-authentication evidence — and the specific gaps are listed with the alert.",
    business_impact: "Cyber Essentials certification is assessed against these control areas. An externally visible gap is likely to be raised during certification, and is usually cheaper to fix before the assessment than during it.",
    recommended_action: "Open the Cyber Essentials page, review the named external evidence for this control area, and resolve the underlying findings through their own remediation. Re-run a scan to confirm the evidence has changed.",
    effort: "medium",
    owner_type: "customer_it",
    verification_method: "rescan",
    verification_evidence_requirements: "A completed scan observes the control area's external evidence supporting readiness again. This is an indicative external readiness signal — it is not a certification outcome and is not assessed by a certification body.",
    supporting_evidence_types: ["https_probe", "http_header_probe", "certificate_transparency_observation", "dns_lookup"],
    applicability: "Applies only to control areas CyberMeters can observe externally (Firewalls & Boundary Protection, Secure Configuration, Security Update Management).",
    limitations: [
      "CyberMeters does not certify Cyber Essentials. This is an indicative readiness signal from externally observable evidence only.",
      "User Access Control and Malware Protection cannot be assessed externally, so they never raise this alert. MFA, admin account separation, endpoint protection and device patching are not visible from outside.",
      "Readiness is assessed from the latest completed scan of this workspace's own domains. It is not an assessment of internal networks, devices or policies.",
    ],
  }),
  entry({
    remediation_id: "ce.backlog.remediate",
    domain_key: "cyber_essentials_readiness",
    finding_types: ["ce_open_findings_backlog"],
    customer_title: "Close outstanding critical and high findings",
    technical_explanation: "Open critical or high external findings remain in the latest scan. Cyber Essentials expects timely remediation of known issues.",
    business_impact: "Unresolved critical and high findings both raise real risk and weaken a Cyber Essentials assessment.",
    recommended_action: "Work through the open critical and high findings in the scan, remediate each, and confirm closure on a fresh Cyber MOT.",
    effort: "medium",
    owner_type: "customer_it",
    verification_method: "rescan",
    verification_evidence_requirements: "The critical and high findings are no longer present on a fresh scan.",
    supporting_evidence_types: ["scan_findings"],
    limitations: ["Cyber Essentials certification is issued externally by an IASME-accredited body; this is readiness only."],
  }),
  entry({
    remediation_id: "ce.access.saas_review",
    domain_key: "cyber_essentials_readiness",
    finding_types: ["ce_saas_access_review"],
    customer_title: "Review SSO and MFA on externally reachable services",
    technical_explanation: "Externally reachable SaaS or identity portals were observed for this domain. Cyber Essentials user-access-control expects strong authentication on such services.",
    business_impact: "Externally reachable portals without enforced MFA are a common route to account compromise.",
    recommended_action: "Review each externally reachable service, enforce single sign-on and multi-factor authentication, and remove or restrict any portal that does not need to be public.",
    effort: "medium",
    owner_type: "customer_it",
    verification_method: "manual_attestation",
    verification_evidence_requirements: "SSO/MFA coverage is confirmed in the relevant service's admin console; it is not externally observable.",
    supporting_evidence_types: ["saas_exposure", "identity_discovery"],
    limitations: ["Coverage reflects externally observed services only; internal SSO/MFA configuration cannot be assessed from external ASM data."],
  }),

  // ─────────────────────────── IDENTITY EXPOSURE ─────────────────────────────
  entry({
    remediation_id: "identity.m365.harden",
    domain_key: "identity_exposure",
    finding_types: ["identity_microsoft_365_detected"],
    customer_title: "Harden the Microsoft 365 sign-in surface",
    technical_explanation: "Microsoft 365 identity endpoints for this domain are reachable from the internet. This reflects an externally observable sign-in surface, not any credential or breach data.",
    business_impact: "Exposed sign-in endpoints are targets for phishing, password spraying and MFA-fatigue attacks against your users.",
    recommended_action: "Enforce multi-factor authentication and Conditional Access, disable legacy authentication, and review named-location and risk-based policies in your identity console.",
    effort: "medium",
    owner_type: "customer_it",
    verification_method: "manual_attestation",
    verification_evidence_requirements: "MFA and Conditional Access posture is confirmed in your identity console; it is not externally observable.",
    supporting_evidence_types: ["identity_discovery"],
    limitations: ["Identity Exposure covers spoofing, impersonation and exposed sign-in surfaces only. It does NOT include leaked-credential, breached-password or dark-web monitoring."],
  }),
  entry({
    remediation_id: "identity.legacy_auth",
    domain_key: "identity_exposure",
    finding_types: ["identity_legacy_auth_exposed"],
    customer_title: "Disable legacy authentication",
    technical_explanation: "Endpoints associated with legacy authentication protocols were observed for this domain.",
    business_impact: "Legacy authentication bypasses modern MFA and is a common route for account compromise.",
    recommended_action: "Block legacy authentication protocols in your identity provider and move clients to modern authentication.",
    effort: "medium",
    owner_type: "customer_it",
    verification_method: "manual_attestation",
    verification_evidence_requirements: "Legacy-auth blocking is confirmed in your identity console.",
    supporting_evidence_types: ["identity_discovery"],
    limitations: ["Identity Exposure covers exposed sign-in surfaces only, not credential-breach or dark-web data."],
  }),
  entry({
    remediation_id: "identity.autodiscover",
    domain_key: "identity_exposure",
    finding_types: ["identity_autodiscover_exposed"],
    customer_title: "Review exposed Autodiscover endpoints",
    technical_explanation: "Autodiscover endpoints for this domain were observed to be publicly reachable.",
    business_impact: "Autodiscover exposure can aid attackers in profiling and targeting your mail platform.",
    recommended_action: "Review whether the Autodiscover endpoint needs to be public, and restrict or harden it in line with your mail platform's guidance.",
    effort: "medium",
    owner_type: "customer_it",
    verification_method: "manual_attestation",
    verification_evidence_requirements: "Endpoint restriction is confirmed in your mail-platform configuration.",
    supporting_evidence_types: ["identity_discovery"],
    limitations: ["Identity Exposure covers exposed sign-in surfaces only, not credential-breach or dark-web data."],
  }),
  // Managed identity-exposure lifecycle triggers (identity_exposure managed
  // record). Each is EXTERNAL-OBSERVATION only and links the managed case.
  entry({
    remediation_id: "identity.review.unexpected_surface",
    domain_key: "identity_exposure",
    finding_types: ["identity_unexpected_surface"],
    customer_title: "Review an unexpected public identity surface",
    technical_explanation: "A public identity or login surface was observed that has been classified as unexpected, or a retired surface has been observed again. This reflects an externally visible entry point only.",
    business_impact: "An unexpected public sign-in surface widens the attack surface for phishing and password-spraying against your users.",
    recommended_action: "Confirm whether this identity surface is expected. If it should not be public, remove or restrict it with the owning team; if it is legitimate, classify it as expected and assign an owner.",
    effort: "medium",
    owner_type: "customer_it",
    verification_method: "manual_attestation",
    verification_evidence_requirements: "The surface is confirmed expected in your configuration, or its removal is confirmed and re-observed externally.",
    supporting_evidence_types: ["identity_discovery"],
    limitations: ["Identity Exposure covers externally exposed sign-in surfaces only — not leaked-credential, breached-password or dark-web data. A publicly visible login is not itself proof of a weakness."],
  }),
  entry({
    remediation_id: "identity.review.public_admin_surface",
    domain_key: "identity_exposure",
    finding_types: ["identity_public_admin_surface"],
    customer_title: "Review a publicly reachable admin login surface",
    technical_explanation: "A public administrative or management login surface was observed for this domain. This is an externally visible entry point; CyberMeters cannot see who can reach it internally.",
    business_impact: "Publicly reachable admin logins are high-value targets; unrestricted exposure raises the risk of brute-force and credential attacks against privileged access.",
    recommended_action: "Restrict the admin surface to trusted networks or an access gateway where possible, ensure strong authentication is enforced, and confirm the exposure is intended.",
    effort: "medium",
    owner_type: "customer_it",
    verification_method: "manual_attestation",
    verification_evidence_requirements: "Access restriction is confirmed in your configuration, or the surface is confirmed no longer publicly reachable and re-observed externally.",
    supporting_evidence_types: ["identity_discovery"],
    limitations: ["Identity Exposure covers externally exposed sign-in surfaces only — not leaked-credential, breached-password or dark-web data, and not internal access policy."],
  }),
  entry({
    remediation_id: "identity.assign.owner",
    domain_key: "identity_exposure",
    finding_types: ["identity_owner_missing"],
    customer_title: "Assign an owner to an at-risk identity surface",
    technical_explanation: "An unexpected or under-investigation public identity surface has no assigned owner. Ownership is operational metadata you provide; it is not externally observable.",
    business_impact: "Without an owner, exposed identity surfaces go unmanaged and remediation stalls.",
    recommended_action: "Assign a business, technical or identity owner so the surface can be reviewed and remediated, then classify it.",
    effort: "low",
    owner_type: "customer_it",
    verification_method: "manual_attestation",
    verification_evidence_requirements: "An owner is recorded against the managed identity record.",
    supporting_evidence_types: ["identity_discovery"],
    limitations: ["Identity Exposure covers externally exposed sign-in surfaces only — not leaked-credential, breached-password or dark-web data."],
  }),
  entry({
    remediation_id: "identity.review.provider_change",
    domain_key: "identity_exposure",
    finding_types: ["identity_provider_change"],
    customer_title: "Review a changed identity provider or endpoint",
    technical_explanation: "The observed identity provider, endpoint or tenant identifier for this surface changed. The previous evidence is preserved; this is an externally observed change only.",
    business_impact: "An unexpected change of identity provider or endpoint may indicate a migration, misconfiguration or hijacked sign-in route.",
    recommended_action: "Confirm the change was intended by your team. If it was not, investigate the sign-in route with the owning team and restore the expected configuration.",
    effort: "medium",
    owner_type: "customer_it",
    verification_method: "manual_attestation",
    verification_evidence_requirements: "The current provider/endpoint is confirmed correct in your configuration and re-observed externally.",
    supporting_evidence_types: ["identity_discovery"],
    limitations: ["Identity Exposure covers externally exposed sign-in surfaces only — not leaked-credential, breached-password or dark-web data."],
  }),
  entry({
    remediation_id: "identity.review.exception_expired",
    domain_key: "identity_exposure",
    finding_types: ["identity_exception_expired"],
    customer_title: "Re-review an identity surface whose exception has expired",
    technical_explanation: "A time-boxed exception on a public identity surface has passed its expiry while the surface remains observed. The exception no longer applies.",
    business_impact: "An expired exception means a surface you chose to tolerate temporarily is now unmanaged again.",
    recommended_action: "Re-review the surface: renew the exception with a new expiry, classify it as expected, or remediate and confirm removal.",
    effort: "low",
    owner_type: "customer_it",
    verification_method: "manual_attestation",
    verification_evidence_requirements: "A new classification or exception is recorded, or removal is confirmed and re-observed externally.",
    supporting_evidence_types: ["identity_discovery"],
    limitations: ["Identity Exposure covers externally exposed sign-in surfaces only — not leaked-credential, breached-password or dark-web data."],
  }),

  // ─────────────────── SHADOW IT & UNMANAGED TECHNOLOGY ──────────────────────
  // ─────────────────────────── DEPRECATED ───────────────────────────────────
  // Superseded advice kept for historical interpretability. Old reports that
  // referenced "publish DMARC straight at p=reject" resolve forward to the honest
  // ramp guidance in email.dmarc.enforce, flagged as deprecated. Deprecated
  // entries never claim a finding type an active entry owns.
  entry({
    remediation_id: "email.dmarc.reject_immediately",
    status: "deprecated",
    domain_key: "email_protection",
    finding_types: ["email_dmarc_reject_now"],
    customer_title: "Publish DMARC at p=reject (superseded)",
    technical_explanation: "Earlier guidance recommended publishing DMARC directly at p=reject.",
    business_impact: "Enforcing before validating legitimate senders risks blocking real business mail.",
    recommended_action: "Superseded: validate senders and ramp p=none → quarantine → reject instead of enforcing immediately.",
    verification_method: "dns_recheck",
    verification_evidence_requirements: "See the replacement remediation.",
    deprecated_at: "2026-07-14",
    replacement_remediation_id: "email.dmarc.enforce",
  }),

  entry({
    remediation_id: "shadow_it.saas.review",
    domain_key: "shadow_it_unmanaged_technology",
    finding_types: ["saas_exposure", "vendor_risk_detected", "supply_chain_vendor_detected", "third_party_js_detected"],
    customer_title: "Review externally observed third-party services",
    technical_explanation: "Third-party services and vendors were observed from your external footprint. This is externally observed usage only — it is not a claim about internal or unauthorised use.",
    business_impact: "Understanding which external services your footprint depends on helps you manage supply-chain and data-handling risk.",
    recommended_action: "Review each observed service against your approved-technology inventory, confirm it is sanctioned, and record data-handling and access arrangements.",
    effort: "low",
    owner_type: "customer",
    verification_method: "manual_attestation",
    verification_evidence_requirements: "Sanctioning and inventory status are internal records; the product observes external usage only.",
    supporting_evidence_types: ["supporting_infrastructure_observation", "http_fingerprint_observation"],
    limitations: ["Shadow IT findings reflect externally observed services only. The product does not see inside your network and does not assert that any service is unauthorised."],
  }),
]);

// ── Indexing ─────────────────────────────────────────────────────────────────
// finding_type → { primary, secondaries[] }. Built once at module load. A finding
// type may appear as PRIMARY in only one entry (rule 2) — building throws on a
// conflict so the invariant cannot silently break in production.
function buildFindingTypeIndex(registry) {
  const index = new Map();
  const byId = new Map();
  for (const e of registry) {
    if (byId.has(e.remediation_id)) {
      throw new Error(`remediation-registry: duplicate remediation_id ${e.remediation_id}`);
    }
    byId.set(e.remediation_id, e);
    if (!DOMAIN_KEY_SET.has(e.domain_key)) {
      throw new Error(`remediation-registry: ${e.remediation_id} has invalid domain_key ${e.domain_key}`);
    }
  }
  for (const e of registry) {
    if (e.status !== "active") continue; // deprecated entries never claim a primary binding
    for (const ft of e.finding_types) {
      const existing = index.get(ft);
      if (existing?.primary && existing.primary !== e.remediation_id) {
        throw new Error(
          `remediation-registry: finding type "${ft}" claimed as primary by both ${existing.primary} and ${e.remediation_id}`,
        );
      }
      const rec = existing || { primary: null, secondaries: [] };
      rec.primary = e.remediation_id;
      index.set(ft, rec);
    }
  }
  for (const e of registry) {
    if (e.status !== "active") continue;
    for (const ft of e.secondary_finding_types) {
      const rec = index.get(ft) || { primary: null, secondaries: [] };
      if (!rec.secondaries.includes(e.remediation_id)) rec.secondaries.push(e.remediation_id);
      index.set(ft, rec);
    }
  }
  // Deprecated entries fill a finding type's primary ONLY when no active entry
  // claims it. This lets a finding type that historically mapped to a now-retired
  // remediation still resolve (the resolver then forwards to the replacement).
  for (const e of registry) {
    if (e.status !== "deprecated") continue;
    for (const ft of e.finding_types) {
      const rec = index.get(ft) || { primary: null, secondaries: [] };
      if (!rec.primary) rec.primary = e.remediation_id;
      index.set(ft, rec);
    }
  }
  return { index, byId };
}

const { index: FINDING_TYPE_INDEX, byId: REGISTRY_BY_ID } = buildFindingTypeIndex(REMEDIATION_REGISTRY);

// ── Aliases ──────────────────────────────────────────────────────────────────
// Legacy / variant finding types map to a CANONICAL finding type that the index
// knows. This is how historical reports (which persisted the old ids) keep
// resolving to the same meaning without any migration. Left side = legacy id
// seen in stored data; right side = a canonical finding_type in the registry.
export const FINDING_TYPE_ALIASES = Object.freeze({
  // Email — the three parallel generators historically produced these ids.
  email_no_dmarc: "email_missing_dmarc",
  email_no_spf: "email_missing_spf",
  email_no_dkim: "email_dkim_not_detected",
  email_weak_dmarc: "email_dmarc_policy_none",
  dmarc_policy_none: "email_dmarc_policy_none",
  spf_permissive: "spf_permissive_all",
  // Subdomain / prefix-style ids collapse onto their canonical finding type.
  // (subdomain_sensitive_<host> is normalised to subdomain_sensitive before lookup.)
  // Certificates — earlier cert-trust-l2 used bare `type` strings.
  expired: "certificate_expired",
  expiring_soon: "certificate_expiring_soon",
  self_signed: "certificate_self_signed",
  unexpected_issuer: "certificate_unexpected_issuer",
  unexpected_san: "certificate_unexpected_san",
  unexpected_wildcard: "certificate_unexpected_wildcard",
  parallel_certificate: "certificate_parallel_observed",
  coverage_gap: "certificate_coverage_gap",
  // Headers — canonicalise the hyphenated header names to underscore ids.
  "header_missing_strict-transport-security": "header_missing_strict_transport_security",
  "header_missing_content-security-policy": "header_missing_content_security_policy",
  "header_missing_x-frame-options": "header_missing_x_frame_options",
  "header_missing_x-content-type-options": "header_missing_x_content_type_options",
  "header_missing_referrer-policy": "header_missing_referrer_policy",
  "header_missing_permissions-policy": "header_missing_permissions_policy",
});

// Some finding types carry a per-host suffix (subdomain_sensitive_<host>,
// header_missing_<name>). Normalise those to their stable prefix before lookup.
function normalizeFindingType(rawType) {
  const ft = String(rawType || "").trim();
  if (!ft) return "";
  if (ft.startsWith("subdomain_sensitive_")) return "subdomain_sensitive";
  return ft;
}

function canonicalFindingType(rawType) {
  const normalized = normalizeFindingType(rawType);
  if (FINDING_TYPE_INDEX.has(normalized)) return { canonical: normalized, viaAlias: false };
  if (Object.prototype.hasOwnProperty.call(FINDING_TYPE_ALIASES, normalized)) {
    return { canonical: FINDING_TYPE_ALIASES[normalized], viaAlias: true };
  }
  return { canonical: normalized, viaAlias: false };
}

// ── Serialization ────────────────────────────────────────────────────────────
// The customer-safe projection of an entry. Never leaks internal-only bookkeeping
// beyond the declared contract fields.
function entryToResolution(e, extra = {}) {
  return Object.freeze({
    status: "resolved",
    remediation_id: e.remediation_id,
    version: e.version,
    lifecycle_status: e.status,
    domain_key: e.domain_key,
    customer_title: e.customer_title,
    technical_explanation: e.technical_explanation,
    business_impact: e.business_impact,
    recommended_action: e.recommended_action,
    effort: e.effort,
    owner_type: e.owner_type,
    verification_method: e.verification_method,
    verification_evidence_requirements: e.verification_evidence_requirements,
    supporting_evidence_types: e.supporting_evidence_types,
    managed_workflow_compatible: e.managed_workflow_compatible,
    case_type: e.case_type,
    applicability: e.applicability,
    limitations: e.limitations,
    references: e.references,
    deprecated_at: e.deprecated_at,
    replacement_remediation_id: e.replacement_remediation_id,
    ...extra,
  });
}

// An honest "we have no specific remediation for this" result. Carries NO advice
// — rule: unknown finding types fail honestly and never receive unrelated generic
// guidance.
function unknownResolution(findingType, domainKey) {
  return Object.freeze({
    status: "unknown",
    remediation_id: null,
    domain_key: domainKey || null,
    finding_type: findingType || null,
    matched_via: "none",
    customer_title: null,
    technical_explanation: null,
    business_impact: null,
    recommended_action: null,
    verification_method: null,
    note: "No canonical remediation is registered for this finding type.",
  });
}

export function getRemediationById(remediationId) {
  return REGISTRY_BY_ID.get(String(remediationId)) || null;
}

// Reverse lookup by customer_title. Some persisted surfaces (scorecard
// top_recommendations read from remediation_items) carry the canonical
// customer_title but not the finding_type or remediation_id — because scoring.js
// now writes canonical titles, this reunites them with their full remediation
// (id + business_impact) so downstream surfaces (PDF) need not fabricate. Returns
// null for a title that does not match an active entry (fails honestly).
const BY_CUSTOMER_TITLE = new Map(
  REMEDIATION_REGISTRY.filter((e) => e.status === "active").map((e) => [e.customer_title, e]),
);
export function resolveByCustomerTitle(title) {
  const e = BY_CUSTOMER_TITLE.get(String(title || "").trim());
  return e ? entryToResolution(e, { matched_via: "title" }) : null;
}

// ── The resolver ─────────────────────────────────────────────────────────────
// resolveRemediation({finding_type, domain_key, evidence, context, surface})
// returns the SAME canonical meaning for every surface. Behaviour:
//   • known finding type      → primary remediation (+ secondaries)
//   • legacy alias            → resolves to the same canonical remediation
//   • unknown finding type    → honest "unknown" result, no generic advice
//   • deprecated remediation  → resolves to its replacement, flagged deprecated
//   • multiple applicable     → deterministic primary + secondary_remediations[]
//   • evidence-dependent      → `applicable` computed from evidence when a
//                               predicate is declared; entry still returned
//   • remediation unavailable → treated as unknown (honest)
//   • verification unsupported→ verification_method "unsupported", kept explicit
// Pure and deterministic: the same inputs always produce the same output.
// The resolver's ONLY legal arguments. Anything else is a programming error, and the
// destructure below would swallow it silently — which is not hypothetical: passing
// `{remediation_id}` here returned an unknownResolution whose verification_method is null,
// and a case-verification path then refused its own evidence and left every case in that
// domain permanently unverifiable. It failed SILENTLY, in the honest-looking direction, on
// the one path where being wrong is invisible.
//
// So the resolver now refuses to be misused rather than answering "unknown" to a question it
// was never asked. It THROWS, deliberately:
//   • the arguments are written by us, never by a customer, so this can only fire on a
//     developer error — there is no input a request can carry that reaches it;
//   • CI runs every caller, so the throw surfaces at test time, not in production;
//   • the alternative is the silent null that caused the defect. An unknown finding type
//     still returns unknownResolution — that is real data and stays honest.
// `remediation_id` is named explicitly because it is the near-miss: it is a real field on a
// case row and reads as if it should work.
const RESOLVER_ARGS = new Set(["finding_type", "domain_key", "evidence", "context", "surface"]);
function assertResolverArgs(args) {
  for (const k of Object.keys(args || {})) {
    if (RESOLVER_ARGS.has(k)) continue;
    const hint = k === "remediation_id"
      ? " — resolveRemediation resolves by FINDING TYPE; use getRemediationById(id) to look up a remediation by its id"
      : "";
    throw new TypeError(`resolveRemediation: unknown argument '${k}'${hint}`);
  }
}

export function resolveRemediation(args = {}) {
  assertResolverArgs(args);
  const { finding_type: findingType, domain_key: domainKey, evidence, surface } = args;
  if (!findingType) return unknownResolution(null, domainKey);

  const { canonical, viaAlias } = canonicalFindingType(findingType);
  const indexed = FINDING_TYPE_INDEX.get(canonical);
  if (!indexed || !indexed.primary) return unknownResolution(findingType, domainKey);

  let e = REGISTRY_BY_ID.get(indexed.primary);
  if (!e) return unknownResolution(findingType, domainKey); // remediation unavailable → honest

  // Deprecated entry → resolve to its replacement when one exists; otherwise the
  // deprecated entry itself is still returned (interpretable for old reports).
  let deprecatedFrom = null;
  if (e.status === "deprecated") {
    deprecatedFrom = e.remediation_id;
    if (e.replacement_remediation_id && REGISTRY_BY_ID.has(e.replacement_remediation_id)) {
      e = REGISTRY_BY_ID.get(e.replacement_remediation_id);
    }
  }

  // Evidence-dependent applicability: entries may declare `applicable(evidence)`.
  let applicable = true;
  if (typeof e.applicable === "function") {
    try { applicable = Boolean(e.applicable(evidence)); } catch { applicable = true; }
  }

  const matched_via = deprecatedFrom ? "deprecated" : viaAlias ? "alias" : "primary";
  const secondary_remediations = (indexed.secondaries || []).slice();

  return entryToResolution(e, {
    finding_type: canonical,
    requested_finding_type: findingType,
    matched_via,
    applicable,
    secondary_remediations,
    surface: surface || null,
    ...(deprecatedFrom ? { deprecated_from: deprecatedFrom, is_deprecated_source: true } : {}),
  });
}

// Convenience for generators: the canonical recommended-action sentence for a
// finding type, or null when unknown. Generators may append evidence-specific
// detail (host lists, record values) — that is surface formatting, not semantic
// drift. Returns null (never a generic fallback) for unknown types.
export function canonicalRecommendedAction(findingType, opts = {}) {
  const r = resolveRemediation({ finding_type: findingType, ...opts });
  return r.status === "resolved" ? r.recommended_action : null;
}

// Resolve the canonical remediation for a scan finding object. A finding's
// stable type is its `id` (e.g. "email_missing_spf"); `finding_type` is only the
// class ("finding" | "observation"). Returns the customer-safe resolution when a
// canonical remediation exists, or null (honest) for observations / unmapped
// types — so a surface never invents advice for a finding with no remediation.
export function findingRemediation(finding) {
  const ft = finding?.id ?? finding?.finding_type;
  if (!ft || ft === "finding" || ft === "observation") return null;
  const r = resolveRemediation({ finding_type: ft });
  return r.status === "resolved" ? r : null;
}

// Enumerate every canonical finding type the registry resolves (primaries +
// declared aliases). Used by contract tests and coverage tooling.
export function listRegisteredFindingTypes() {
  const types = new Set(FINDING_TYPE_INDEX.keys());
  for (const alias of Object.keys(FINDING_TYPE_ALIASES)) types.add(alias);
  return Array.from(types);
}
