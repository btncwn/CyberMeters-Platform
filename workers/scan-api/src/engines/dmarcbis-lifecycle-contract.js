// Item 7 P4's dependency-free migration-088 application vocabulary.
// Kept separate so the lifecycle writer and Related Changes adapter can share
// exact allowlists without creating an engine import cycle.
export const DMARC_POLICY_CONDITION_RECORD_TYPE = "dmarc_policy_condition";
export const EMAIL_EVENT_DMARC_DOMAIN_BASELINE =
  "dmarc_domain_baseline_established";
export const EMAIL_EVENT_DMARC_POLICY_TRANSITION = "dmarc_policy_transition";
export const EMAIL_EVENT_DMARC_MONITORING_DEGRADED =
  "dmarc_monitoring_degraded";
export const EMAIL_EVENT_DMARC_CONDITION_CLEARED =
  "condition_no_longer_observed";

export const DMARC_LIFECYCLE_SUBTYPES = Object.freeze([
  "record_created",
  "record_removed",
  "record_became_malformed",
  "multiple_records_detected",
  "policy_changed",
  "policy_inherited",
  "inheritance_source_changed",
  "organisational_domain_changed",
  "subdomain_policy_changed",
  "non_existent_subdomain_policy_changed",
  "enforcement_strengthened",
  "enforcement_weakened",
  "legacy_pct_observed",
  "external_rua_added",
  "external_rua_removed",
  "external_rua_authorised",
  "external_rua_unauthorised",
  "external_rua_authorisation_unavailable",
  "monitoring_degraded",
]);

export const DMARC_RELATED_CHANGES_SUBTYPES = Object.freeze([
  "record_created",
  "record_removed",
  "record_became_malformed",
  "multiple_records_detected",
  "policy_changed",
  "policy_inherited",
  "inheritance_source_changed",
  "organisational_domain_changed",
  "subdomain_policy_changed",
  "non_existent_subdomain_policy_changed",
  "enforcement_strengthened",
  "enforcement_weakened",
  "external_rua_added",
  "external_rua_removed",
  "external_rua_authorised",
  "external_rua_unauthorised",
]);
