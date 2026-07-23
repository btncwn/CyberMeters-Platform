// ── DMARC report authority containment (PR-5.5 Gate 1) ──────────────────────
//
// Inbound aggregate-report email is public, attacker-addressable telemetry.
// Cloudflare Email Routing does not give this Worker a trusted authentication
// result that authorises the sender as a report producer. Gate 1 therefore keeps
// source=inbound_email (and every missing/unknown source) observational only.
//
// The two explicit non-inbound paths below retain their pre-Gate-1 behaviour.
// This allow-list is a containment boundary, NOT a new provenance/trust verdict;
// Gate 2 owns that later evidence-contract work.
export const DMARC_AUTHORITY_ELIGIBLE_SOURCES = Object.freeze([
  "manual_paste",
  "signed_upload",
]);

export const DMARC_AUTHORITY_EVIDENCE_SCOPE = "authority_eligible_non_inbound";
export const DMARC_OBSERVATIONAL_EVIDENCE_SCOPE = "reported_to_us_observational";

export function isDmarcAuthorityEligibleSource(source) {
  return DMARC_AUTHORITY_ELIGIBLE_SOURCES.includes(String(source || ""));
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
