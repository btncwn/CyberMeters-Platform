// ── Email analysis primitives ──
// Pure parsers + builders for the Email Protection wedge: SPF/DMARC/BIMI/DKIM parsing,
// provider inference, DMARC policy journey, transport (TLS-RPT/MTA-STS) detail, and
// remediation-action assembly, plus the DKIM provider lookup tables. Extracted verbatim
// from index.js (monolith decomposition, Phase 1c). Self-contained — no imports. Heavily
// covered by the accuracy + pipeline regression harnesses.

export const DKIM_PROVIDER_MAP = [
  { includes: "secureserver.net",           provider: "godaddy"      },
  { includes: "spf.protection.outlook.com", provider: "microsoft365" },
  { includes: "_spf.google.com",            provider: "google"       },
  { includes: "sendgrid.net",               provider: "sendgrid"     },
  { includes: "servers.mcsv.net",           provider: "mailchimp"    },
  { includes: "mailgun.org",                provider: "mailgun"      },
  { includes: "amazonses.com",              provider: "amazonses"    },
  { includes: "zoho.com",                   provider: "zoho"         },
  { includes: "protonmail",                 provider: "protonmail"   },
  { includes: "fastmail",                   provider: "fastmail"     },
  { includes: "mimecast",                   provider: "mimecast"     },
  { includes: "pphosted.com",               provider: "proofpoint"   },
  { includes: "postmarkapp.com",            provider: "postmark"     },
];

export const DKIM_PROVIDER_LABELS = {
  godaddy:      "GoDaddy",
  microsoft365: "Microsoft 365",
  google:       "Google Workspace",
  sendgrid:     "SendGrid",
  mailchimp:    "Mailchimp",
  mailgun:      "Mailgun",
  amazonses:    "Amazon SES",
  zoho:         "Zoho Mail",
  protonmail:   "ProtonMail",
  fastmail:     "Fastmail",
  mimecast:     "Mimecast",
  proofpoint:   "Proofpoint",
  postmark:     "Postmark",
};

/**
 * inferEmailProvider(spfRecord) → string|null
 * Returns an internal provider key by substring-matching the raw SPF record,
 * or null if no known provider is recognised.
 */
export function inferEmailProvider(spfRecord) {
  if (!spfRecord) return null;
  for (const { includes, provider } of DKIM_PROVIDER_MAP) {
    if (spfRecord.includes(includes)) return provider;
  }
  return null;
}

/**
 * findDkimInResults(selectors, settledResults) → string|null
 * Returns the first selector whose DNS response contains a valid DKIM public key,
 * or null if none found.
 */
export function findDkimInResults(selectors, settledResults) {
  for (let i = 0; i < selectors.length; i++) {
    const r = settledResults[i];
    if (r?.status === "fulfilled" && r.value.Answer?.length > 0) {
      const valid = r.value.Answer.filter(
        (a) => a.data?.includes("v=DKIM1") || a.data?.includes("p=")
      );
      if (valid.length > 0) return selectors[i];
    }
  }
  return null;
}

export function normalizeDnsTxtValue(record) {
  return String(record || "").trim().replace(/^"|"$/g, "").replace(/"\s*"/g, "");
}

export function parseDmarcRecord(record, recordCount = record ? 1 : 0) {
  const raw = normalizeDnsTxtValue(record);
  const tags = {};
  const warnings = [];
  for (const chunk of raw.split(";")) {
    const part = chunk.trim();
    const eq = part.indexOf("=");
    if (eq <= 0) continue;
    const key = part.slice(0, eq).trim().toLowerCase();
    const value = part.slice(eq + 1).trim();
    if (key) tags[key] = value;
  }

  const policy = tags.p?.toLowerCase() || null;
  const subdomainPolicy = tags.sp?.toLowerCase() || null;
  const pctRaw = tags.pct;
  const pctParsed = pctRaw == null || pctRaw === "" ? 100 : Number(pctRaw);
  const pctValid = Number.isInteger(pctParsed) && pctParsed >= 0 && pctParsed <= 100;
  const percentage = pctValid ? pctParsed : 100;
  const rua = (tags.rua || "").split(",").map((value) => value.trim()).filter(Boolean);
  const ruf = (tags.ruf || "").split(",").map((value) => value.trim()).filter(Boolean);

  if (recordCount === 0 || !raw) warnings.push("No DMARC record was found.");
  if (recordCount > 1) warnings.push("Multiple DMARC records were found; DMARC requires exactly one record.");
  if (raw && tags.v?.toUpperCase() !== "DMARC1") warnings.push("The DMARC version tag must be v=DMARC1.");
  if (raw && !["none", "quarantine", "reject"].includes(policy)) warnings.push("The DMARC policy tag must be none, quarantine, or reject.");
  if (!pctValid) warnings.push("The DMARC pct value must be an integer from 0 to 100.");
  if (pctValid && percentage < 100) warnings.push(`DMARC enforcement applies to ${percentage}% of messages.`);
  if (raw && rua.length === 0) warnings.push("No aggregate reporting address (rua) is configured.");
  if (raw && !subdomainPolicy) warnings.push("No explicit subdomain policy (sp) is configured; subdomains inherit the main policy.");

  const valid = Boolean(raw) && recordCount === 1 && tags.v?.toUpperCase() === "DMARC1" &&
    ["none", "quarantine", "reject"].includes(policy) && pctValid;

  return {
    raw: raw || null,
    valid,
    record_count: recordCount,
    policy,
    subdomain_policy: subdomainPolicy,
    percentage,
    pct: percentage,
    rua,
    ruf,
    adkim: ["r", "s"].includes(tags.adkim?.toLowerCase()) ? tags.adkim.toLowerCase() : "r",
    aspf: ["r", "s"].includes(tags.aspf?.toLowerCase()) ? tags.aspf.toLowerCase() : "r",
    fo: tags.fo || null,
    has_reporting: rua.length > 0,
    has_failure_reporting: ruf.length > 0,
    tags,
    warnings,
  };
}

export function parseSpfRecord(record, recordCount = record ? 1 : 0) {
  const raw = normalizeDnsTxtValue(record);
  const tokens = raw.split(/\s+/).filter(Boolean);
  const mechanisms = [];
  const includes = [];
  const redirects = [];
  const ip4 = [];
  const ip6 = [];
  const warnings = [];
  let allMechanism = null;
  let lookupCountEstimate = 0;

  for (const token of tokens.slice(1)) {
    const qualifier = ["+", "-", "~", "?"].includes(token[0]) ? token[0] : "+";
    const body = qualifier === token[0] ? token.slice(1) : token;
    if (body.startsWith("redirect=")) {
      const value = body.slice("redirect=".length);
      if (value) redirects.push(value);
      lookupCountEstimate += 1;
      mechanisms.push({ raw: token, qualifier, mechanism: "redirect", value });
      continue;
    }
    const colon = body.indexOf(":");
    const mechanism = (colon >= 0 ? body.slice(0, colon) : body).split("/")[0].toLowerCase();
    const value = colon >= 0 ? body.slice(colon + 1) : null;
    mechanisms.push({ raw: token, qualifier, mechanism, value });
    if (mechanism === "include" && value) includes.push(value);
    if (mechanism === "ip4" && value) ip4.push(value);
    if (mechanism === "ip6" && value) ip6.push(value);
    if (["include", "a", "mx", "exists", "ptr"].includes(mechanism)) lookupCountEstimate += 1;
    if (mechanism === "all") allMechanism = token;
  }

  const policyStrength = allMechanism === "-all" ? "strong"
    : allMechanism === "~all" ? "soft"
      : allMechanism === "?all" ? "neutral"
        : allMechanism === "+all" || allMechanism === "all" ? "weak"
          : "unknown";
  if (recordCount === 0 || !raw) warnings.push("No SPF record was found.");
  if (recordCount > 1) warnings.push("Multiple SPF records were found; SPF requires exactly one record.");
  if (raw && tokens[0]?.toLowerCase() !== "v=spf1") warnings.push("The SPF record must begin with v=spf1.");
  if (allMechanism === "+all" || allMechanism === "all") warnings.push("The +all mechanism authorises any sender.");
  if (allMechanism === "?all") warnings.push("The ?all mechanism provides no clear policy for unauthorised senders.");
  if (allMechanism === "~all") warnings.push("The ~all mechanism uses softfail rather than strict failure.");
  if (lookupCountEstimate > 10) warnings.push(`The SPF record is estimated to require ${lookupCountEstimate} DNS lookups; SPF permits at most 10.`);
  if (mechanisms.some((item) => item.mechanism === "ptr")) warnings.push("The SPF ptr mechanism is discouraged and can produce unreliable results.");
  if (includes.length > 5) warnings.push("The SPF record contains many broad include mechanisms; review whether each sender is still required.");

  return {
    raw: raw || null,
    valid: Boolean(raw) && recordCount === 1 && tokens[0]?.toLowerCase() === "v=spf1",
    record_count: recordCount,
    mechanisms,
    includes,
    redirects,
    ip4,
    ip6,
    all_mechanism: allMechanism,
    policy_strength: policyStrength,
    lookup_count_estimate: lookupCountEstimate,
    warnings,
  };
}

export function buildDmarcPolicyJourney(detail) {
  if (!detail?.raw || !detail.valid) {
    return {
      stage: "missing",
      label: detail?.raw ? "Invalid DMARC configuration" : "No DMARC",
      next_step: detail?.raw
        ? "Publish one valid DMARC record before moving towards enforcement."
        : "Publish a monitoring policy with aggregate reporting, then validate legitimate senders before enforcement.",
      business_risk: "Receiving systems do not have a reliable DMARC enforcement instruction for this domain.",
    };
  }
  if (detail.policy === "none") {
    return {
      stage: "monitoring",
      label: "Monitoring only",
      next_step: "Review legitimate sending sources, then move gradually to p=quarantine.",
      business_risk: "Reports may be collected, but receivers are not instructed to quarantine or reject messages that fail DMARC alignment.",
    };
  }
  if (detail.policy === "quarantine" || detail.percentage < 100) {
    return {
      stage: "partial_enforcement",
      label: detail.policy === "quarantine" ? "Quarantine" : `Reject at ${detail.percentage}%`,
      next_step: "Confirm legitimate mail remains aligned, then increase coverage towards p=reject with pct=100.",
      business_risk: "Some messages that fail DMARC may still be delivered, depending on policy coverage and receiver handling.",
    };
  }
  return {
    stage: "full_enforcement",
    label: "Reject",
    next_step: "Continue monitoring aggregate reports and maintain SPF and DKIM alignment as senders change.",
    business_risk: "This is the strongest DMARC policy, although receiver behavior and indirect spoofing risks still vary.",
  };
}

export function buildDkimDetail(dkim = {}) {
  if (dkim.present && dkim.selector) {
    return {
      status: "detected",
      confidence: "high",
      selector: dkim.selector,
      provider: dkim.provider || null,
      explanation: `A DKIM DNS record was detected for selector ${dkim.selector}.`,
      limitation: "Full DKIM validation requires a signed email header to confirm that messages are being signed and aligned.",
    };
  }
  const provider = dkim.provider ? (DKIM_PROVIDER_LABELS[dkim.provider] || dkim.provider) : null;
  return {
    status: provider ? "uncertain" : "not_detected",
    confidence: provider ? "medium" : "low",
    selector: null,
    provider: dkim.provider || null,
    explanation: provider
      ? `${provider} was inferred as the email provider, but DKIM could not be verified using the common selectors checked. A custom selector may be in use.`
      : "DKIM could not be verified using the common selectors checked. A custom selector may be in use.",
    limitation: "DKIM can only be fully verified from a signed email header or a known selector.",
  };
}

export function parseBimiRecord(record, dmarcDetail) {
  const raw = normalizeDnsTxtValue(record);
  const tags = {};
  for (const part of raw.split(";")) {
    const eq = part.indexOf("=");
    if (eq <= 0) continue;
    tags[part.slice(0, eq).trim().toLowerCase()] = part.slice(eq + 1).trim();
  }
  const recordFound = Boolean(raw && tags.v?.toUpperCase() === "BIMI1");
  const logoUrl = tags.l || null;
  const certificateUrl = tags.a || null;
  const enforced = dmarcDetail?.valid && ["quarantine", "reject"].includes(dmarcDetail.policy) && dmarcDetail.percentage === 100;
  const blockers = [];
  const warnings = [];
  if (recordFound && !enforced) blockers.push("BIMI normally requires DMARC enforcement with full policy coverage.");
  if (recordFound && !logoUrl) warnings.push("The BIMI record does not include a logo URL.");
  if (recordFound && !certificateUrl) warnings.push("Some mailbox providers require a VMC or CMC mark certificate.");
  return {
    record_found: recordFound,
    raw: raw || null,
    logo_url: logoUrl,
    certificate_url: certificateUrl,
    gmail_ready: "unknown",
    blockers,
    warnings,
  };
}

export function buildEmailTransportDetails(emailIntel = {}) {
  const mta = emailIntel.mta_sts || {};
  const tls = emailIntel.tls_rpt || {};
  return {
    mta_sts_detail: {
      record_found: null,
      policy_found: mta.enabled === true,
      mode: ["enforce", "testing", "none"].includes(mta.policy_mode) ? mta.policy_mode : "unknown",
      warnings: [
        ...(mta.errors || []).map((w) => sanitizeInfraErrorMessage(w, "mta_sts")),
        ...(!mta.enabled ? ["An MTA-STS policy file was not confirmed during this scan."] : []),
        "The _mta-sts DNS TXT record is not assessed separately in this version.",
      ],
    },
    tls_rpt_detail: {
      record_found: tls.enabled === true,
      rua: tls.reporting_uris || [],
      warnings: (tls.errors || []).map((w) => sanitizeInfraErrorMessage(w, "tls_rpt")),
    },
  };
}

export function remediationAction(id, protocol, severity, title, issue, businessRisk, recommendedAction, extra = {}) {
  return {
    id,
    category: "email_authentication",
    protocol,
    severity,
    confidence: extra.confidence || "high",
    title,
    issue,
    business_risk: businessRisk,
    recommended_action: recommendedAction,
    suggested_dns_record: extra.suggested_dns_record || null,
    copyable_value: extra.copyable_value || extra.suggested_dns_record || null,
    caution: extra.caution || null,
    status: "open",
  };
}

export function buildEmailRemediationActions(domain, details, emailIntel = {}) {
  const { spf_detail: spf, dmarc_detail: dmarc, dkim_detail: dkim, bimi_readiness: bimi } = details;
  const actions = [];
  const reportAddress = `dmarc-reports@${domain}`;

  if (!dmarc.raw) {
    const value = `v=DMARC1; p=none; rua=mailto:${reportAddress}; fo=1`;
    actions.push(remediationAction("dmarc_missing", "DMARC", "high", "Publish a DMARC monitoring record",
      "No DMARC record was found.",
      "Receiving systems do not have a domain-owner policy for handling messages that fail DMARC alignment.",
      "Publish a monitoring record, identify legitimate senders from aggregate reports, then move gradually towards enforcement.",
      { suggested_dns_record: value, caution: "Do not move directly to enforcement until legitimate sending services are confirmed." }));
  } else if (dmarc.record_count > 1) {
    actions.push(remediationAction("dmarc_multiple_records", "DMARC", "high", "Consolidate multiple DMARC records",
      `${dmarc.record_count} DMARC records were detected.`,
      "Multiple DMARC records can cause receivers to treat DMARC as invalid.",
      "Merge the required tags into one TXT record at the _dmarc hostname."));
  } else if (!dmarc.valid) {
    actions.push(remediationAction("dmarc_invalid_record", "DMARC", "high", "Correct the invalid DMARC record",
      dmarc.warnings.join(" ") || "The DMARC record could not be validated.",
      "An invalid record may be ignored by receiving systems.",
      "Correct the version, policy, and percentage tags while preserving valid reporting destinations."));
  }
  if (dmarc.valid && dmarc.policy === "none") {
    const value = `v=DMARC1; p=quarantine; pct=100; rua=mailto:${reportAddress}`;
    actions.push(remediationAction("dmarc_policy_monitoring_only", "DMARC", "medium", "DMARC is in monitoring mode only",
      "The DMARC policy is set to p=none.",
      "Receivers are not instructed to quarantine or reject messages that fail DMARC alignment.",
      "Confirm legitimate sending sources, then move gradually towards quarantine and reject.",
      { suggested_dns_record: value, caution: "Do not move to enforcement until legitimate senders are confirmed." }));
  }
  if (dmarc.raw && !dmarc.has_reporting) {
    actions.push(remediationAction("dmarc_reporting_missing", "DMARC", "medium", "Add aggregate DMARC reporting",
      "The DMARC record does not include a rua destination.",
      "Without aggregate reports, legitimate and unauthorised sending sources are harder to validate.",
      "Add a monitored aggregate reporting mailbox or DMARC reporting service.",
      { suggested_dns_record: `rua=mailto:${reportAddress}`, caution: "Use a mailbox or service capable of handling DMARC XML reports." }));
  }
  if (dmarc.valid && dmarc.percentage < 100) {
    actions.push(remediationAction("dmarc_partial_percentage", "DMARC", "medium", "Increase DMARC policy coverage",
      `The DMARC pct tag applies policy to ${dmarc.percentage}% of messages.`,
      "Messages outside the rollout percentage may not receive the requested enforcement treatment.",
      "After validating legitimate senders, increase pct gradually towards 100."));
  }

  if (!spf.raw) {
    const value = "v=spf1 -all";
    actions.push(remediationAction("spf_missing", "SPF", "high", "Publish an SPF policy",
      "No SPF record was found.",
      "Receiving systems cannot use SPF to identify authorised sending infrastructure for this domain.",
      "Inventory every legitimate sender and publish one SPF record.",
      { suggested_dns_record: value, caution: "The example value is suitable only for a domain that sends no mail. Add legitimate senders before using -all." }));
  } else if (spf.record_count > 1) {
    actions.push(remediationAction("spf_multiple_records", "SPF", "high", "Consolidate multiple SPF records",
      `${spf.record_count} SPF records were detected.`,
      "Multiple SPF records can produce a permanent SPF evaluation error.",
      "Merge all required mechanisms into one v=spf1 TXT record."));
  }
  if (spf.all_mechanism === "+all" || spf.all_mechanism === "all") {
    actions.push(remediationAction("spf_permissive_all", "SPF", "critical", "Remove the permissive SPF +all mechanism",
      "The SPF policy authorises any sender.",
      "The record does not provide a meaningful SPF restriction.",
      "Inventory authorised senders, remove +all, and finish with the appropriate restrictive policy.",
      { caution: "Confirm every legitimate sending service before applying -all." }));
  } else if (spf.all_mechanism === "?all") {
    actions.push(remediationAction("spf_neutral_all", "SPF", "medium", "Strengthen the neutral SPF policy",
      "The SPF policy ends with ?all.",
      "Neutral SPF provides no clear instruction for unauthorised senders.",
      "Validate sending sources, then move to ~all or -all as appropriate."));
  } else if (spf.all_mechanism === "~all") {
    actions.push(remediationAction("spf_softfail_all", "SPF", "low", "Review SPF softfail policy",
      "The SPF policy ends with ~all.",
      "Softfail is less restrictive than -all, although it is commonly used during rollout.",
      "Once all legitimate senders are confirmed, consider moving to -all."));
  }
  if (spf.lookup_count_estimate > 10) {
    actions.push(remediationAction("spf_lookup_limit", "SPF", "high", "Reduce SPF DNS lookups",
      `The SPF record is estimated to require ${spf.lookup_count_estimate} DNS lookups.`,
      "SPF evaluation may return a permanent error when the 10-lookup limit is exceeded.",
      "Remove unused includes and consolidate sending services without flattening records manually unless change management is in place."));
  }
  if (spf.mechanisms.some((item) => item.mechanism === "ptr")) {
    actions.push(remediationAction("spf_ptr_mechanism", "SPF", "medium", "Remove the SPF ptr mechanism",
      "The SPF record uses the discouraged ptr mechanism.",
      "PTR evaluation is costly and can be unreliable across receivers.",
      "Replace ptr with explicit include, ip4, ip6, a, or mx mechanisms where appropriate."));
  }

  if (dkim.status !== "detected") {
    actions.push(remediationAction("dkim_verification_uncertain", "DKIM", "info", "Confirm the active DKIM selector",
      "DKIM could not be verified using common selectors.",
      "This does not confirm that DKIM signing is absent; a custom selector may be in use.",
      "Confirm the selector with the email provider or inspect a signed email Authentication-Results header.",
      { confidence: dkim.confidence }));
  }
  if (!bimi.record_found) {
    actions.push(remediationAction("bimi_not_configured", "BIMI", "info", "Consider BIMI after email authentication is mature",
      "No BIMI record was found.",
      "BIMI is optional and does not replace SPF, DKIM, or DMARC.",
      "Prioritise DMARC enforcement first, then evaluate BIMI if brand indicators are valuable."));
  } else {
    if (bimi.blockers.length > 0) actions.push(remediationAction("bimi_dmarc_enforcement_required", "BIMI", "low", "Complete DMARC enforcement for BIMI readiness",
      bimi.blockers.join(" "), "Mailbox providers may not display the BIMI logo until authentication requirements are met.",
      "Complete DMARC enforcement before treating the BIMI record as ready."));
    if (!bimi.certificate_url) actions.push(remediationAction("bimi_certificate_not_listed", "BIMI", "info", "Review BIMI mark certificate requirements",
      "The BIMI record does not include a certificate URL.", "Some mailbox providers require a valid VMC or CMC certificate.",
      "Confirm target mailbox-provider requirements before purchasing or publishing a mark certificate."));
  }

  const transport = buildEmailTransportDetails(emailIntel);
  if (emailIntel.mta_sts && !transport.mta_sts_detail.policy_found) actions.push(remediationAction("mta_sts_policy_missing", "MTA-STS", "low", "Review MTA-STS transport policy",
    "An MTA-STS policy file was not confirmed.", "Inbound SMTP TLS enforcement may be less resilient to downgrade or misconfiguration.",
    "Assess MTA-STS after confirming the domain's MX configuration and operational ownership."));
  if (emailIntel.tls_rpt && !transport.tls_rpt_detail.record_found) actions.push(remediationAction("tls_rpt_missing", "TLS-RPT", "info", "Add TLS delivery reporting",
    "No TLS-RPT record was confirmed.", "Email administrators may have less visibility into SMTP TLS delivery failures.",
    `Publish v=TLSRPTv1; rua=mailto:tls-reports@${domain} at _smtp._tls.${domain}.`,
    { suggested_dns_record: `v=TLSRPTv1; rua=mailto:tls-reports@${domain}` }));

  return actions;
}

export function sanitizeInfraErrorMessage(message, scope) {
  const raw = String(message || "");
  const internal = /subrequest|internal error|exceeded cpu|cpu time|script will never|network connection lost|connection reset|failed to fetch|worker exceeded|too many/i.test(raw);
  if (!internal) return raw;
  const safe = {
    tls_rpt: "TLS-RPT could not be verified during this scan. This may be retried automatically on a future scan.",
    mta_sts: "MTA-STS could not be verified during this scan. This may be retried automatically on a future scan.",
  };
  return safe[scope] || "This check could not be completed during this scan. It may be retried automatically on a future scan.";
}

