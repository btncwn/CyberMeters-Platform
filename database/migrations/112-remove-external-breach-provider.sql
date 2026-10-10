-- Founder requested full provider removal before customer onboarding.
-- Remove only provider-specific results and its retention cursor.
DROP TABLE IF EXISTS identity_breach_checks;
DROP TABLE IF EXISTS identity_breach_cleanup_state;
