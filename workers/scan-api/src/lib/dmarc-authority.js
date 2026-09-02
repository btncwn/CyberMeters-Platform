// ── Aggregate-report trust and authority contract (PR-5.5 Gate 2) ────────────
//
// This is the single source of truth for whether DMARC/TLS-RPT evidence may
// influence an authoritative outcome. Keep these concepts separate:
//
//   actor_authenticated          who submitted the payload
//   source                       the explicit ingestion channel
//   transport_authenticated_sender
//                                an authenticated inbound mailbox identity
//   report_body_identity         what the untrusted report body claims
//   evidence_confidence          a bounded confidence label
//   authoritative_eligible       whether an authoritative consumer may read it
//
// Actor authentication is necessary for customer-submitted evidence, but it
// does NOT authenticate the report producer or make the report body true.
// Header-From and recognised public-mail domains are attacker-controlled
// metadata and MUST NEVER grant authority. Cloudflare Email Routing does not
// expose a trusted Authentication-Results value to this Worker, so inbound
// transport sender authentication is currently unknown.
//
// The present internal-authority contract preserves the pre-Gate-1 behaviour of
// the two explicit, authenticated and workspace/domain-scoped customer
// submission paths. A stronger producer-authority contract would additionally
// require a verified domain-ownership binding, recorded provenance, and bounded
// evidence confidence. That stronger contract is not built.
//
// Destructive/external automation requires additional independent
// corroboration even after those conditions. No corroboration model exists yet,
// so NO aggregate-report source is eligible to drive hosted-DMARC DNS changes.
// Inbound-driven external automation therefore remains suspended.
export const DMARC_AUTHORITY_ELIGIBLE_SOURCES = Object.freeze([
  "manual_paste",
  "signed_upload",
]);

export const DMARC_EXTERNAL_AUTOMATION_ELIGIBLE_SOURCES = Object.freeze([]);

export const DMARC_AUTHORITY_EVIDENCE_SCOPE = "authenticated_customer_submission";
export const DMARC_OBSERVATIONAL_EVIDENCE_SCOPE = "reported_to_us_observational";
export const DMARC_EXTERNAL_AUTOMATION_EVIDENCE_SCOPE =
  "external_automation_suspended_pending_corroboration";

const EXPLICIT_SOURCES = new Set([
  ...DMARC_AUTHORITY_ELIGIBLE_SOURCES,
  "inbound_email",
]);

const TRANSPORT_SENDER_STATUSES = new Set([
  "sender_domain_claimed_recognised",
  "sender_domain_claimed",
  "sender_identity_unavailable",
]);

function normalizedSource(source) {
  const candidate = String(source || "").trim();
  return EXPLICIT_SOURCES.has(candidate) ? candidate : "unknown";
}

export function normalizeTransportSenderStatus(value, reporterDomain = null) {
  const stored = String(value || "").trim();
  if (TRANSPORT_SENDER_STATUSES.has(stored)) return stored;

  // Migration 066-era rows may contain "verified" solely because header-From
  // matched a public-mail allow-list. Normalize that legacy value to an honest
  // claim label at every read boundary; it is not producer authentication.
  if (stored === "verified") return "sender_domain_claimed_recognised";
  if (reporterDomain) return "sender_domain_claimed";
  return "sender_identity_unavailable";
}

export function buildAggregateReportTrustSemantics({
  source,
  storedTransportVerdict = null,
  reporterDomain = null,
  claimedDomain = null,
} = {}) {
  const explicitSource = normalizedSource(source);
  const customerSubmitted = DMARC_AUTHORITY_ELIGIBLE_SOURCES.includes(explicitSource);
  const externalAutomationEligible =
    DMARC_EXTERNAL_AUTOMATION_ELIGIBLE_SOURCES.includes(explicitSource);
  const inbound = explicitSource === "inbound_email";
  const transportSenderStatus = inbound
    ? normalizeTransportSenderStatus(storedTransportVerdict, reporterDomain)
    : "not_applicable";
  const recognisedReporterDomain = transportSenderStatus === "sender_domain_claimed_recognised";

  return {
    actor_authenticated: customerSubmitted,
    actor_authentication: explicitSource === "manual_paste"
      ? "workspace_session"
      : (explicitSource === "signed_upload"
        ? "scoped_ingest_token"
        : (inbound ? "sender_authentication_unavailable_at_email_routing_boundary" : "unavailable")),
    source: explicitSource,
    transport_authenticated_sender: null,
    transport_sender_status: transportSenderStatus,
    transport_sender_claimed: inbound ? (reporterDomain || null) : null,
    recognised_reporter_domain: recognisedReporterDomain,
    report_body_identity: {
      claimed_domain: claimedDomain || null,
      independently_verified: false,
    },
    claimed_domain: claimedDomain || null,
    domain_ownership_bound: false,
    provenance_recorded: explicitSource !== "unknown",
    report_producer_authenticated: false,
    evidence_confidence: customerSubmitted
      ? "customer_submitted_unverified_content"
      : (inbound ? "unverified_observational" : "unknown"),
    authoritative_eligible: customerSubmitted,
    external_automation_eligible: externalAutomationEligible,
    authority_basis: customerSubmitted ? "authenticated_customer_submission" : null,
    authority_reason: customerSubmitted
      ? "explicit_authenticated_scoped_customer_submission"
      : (inbound ? "inbound_report_producer_not_authenticated" : "source_not_authority_eligible"),
  };
}

export function isDmarcAuthorityEligibleSource(source) {
  return buildAggregateReportTrustSemantics({ source }).authoritative_eligible;
}

export function isDmarcExternalAutomationEligibleSource(source) {
  return buildAggregateReportTrustSemantics({ source }).external_automation_eligible;
}

// Static SQL fragment only. `alias` is supplied exclusively by source code, but
// validate it anyway so this helper can never become an identifier-injection path.
export function dmarcAuthoritySourceSql(alias = "rep") {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(alias)) throw new Error("invalid_sql_alias");
  const literals = DMARC_AUTHORITY_ELIGIBLE_SOURCES
    .map((source) => `'${source.replaceAll("'", "''")}'`)
    .join(", ");
  return `${alias}.source IN (${literals})`;
}

// Non-authoritative product signals may use recognised inbound aggregate
// reports, while authority and external-automation consumers remain stricter.
// `sender_domain_claimed_recognised` (and its legacy stored value `verified`)
// still describes sender-controlled transport metadata: admitting it here does
// not authenticate the producer or grant DNS/DMARC authority.
export function dmarcOperationalSignalSourceSql(alias = "rep") {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(alias)) throw new Error("invalid_sql_alias");
  return `(${alias}.source IN ('manual_paste', 'signed_upload') OR (` +
    `${alias}.source = 'inbound_email' AND ` +
    `${alias}.auth_verdict IN ('sender_domain_claimed_recognised', 'verified')))`;
}

// Deliberately independent of transport/header-From labels. No current source
// meets the required corroboration contract, so destructive automation fails
// closed even for authenticated customer-submission channels.
export function dmarcExternalAutomationSourceSql(alias = "rep") {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(alias)) throw new Error("invalid_sql_alias");
  return "0 = 1";
}
