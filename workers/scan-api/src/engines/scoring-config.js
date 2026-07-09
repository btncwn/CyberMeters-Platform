// ── Scoring config ──
// Enterprise benchmark set + posture weights used by the scoring engine. Extracted
// verbatim from index.js (monolith decomposition, Phase 1c). Data only — no logic.

export const ENTERPRISE_BENCHMARK = [
  { domain: "google.com",     max_header_findings: 0, max_email_findings: 0, expect_https_redirect: true },
  { domain: "github.com",     max_header_findings: 0, max_email_findings: 0, expect_https_redirect: true },
  { domain: "cloudflare.com", max_header_findings: 0, max_email_findings: 0, expect_https_redirect: true },
  { domain: "microsoft.com",  max_header_findings: 0, max_email_findings: 0, expect_https_redirect: true },
  { domain: "amazon.com",     max_header_findings: 0, max_email_findings: 0, expect_https_redirect: true },
  { domain: "openai.com",     max_header_findings: 0, max_email_findings: 0, expect_https_redirect: true },
];

// Fast O(1) membership test used in computeScore
export const ENTERPRISE_DOMAINS = new Set(ENTERPRISE_BENCHMARK.map(b => b.domain));

// Security posture category metadata — shared by computeSecurityPosture and
// the /scorecard/pdf-data route.  Defined at module scope so both can reference it.
export const POSTURE_WEIGHTS = {
  email_security:   { label: 'Email Security',     pct: 20 },
  ssl_certificates: { label: 'SSL & Certificates', pct: 20 },
  attack_surface:   { label: 'Attack Surface',     pct: 25 },
  third_party_risk: { label: 'Third-Party Risk',   pct: 15 },
  admin_exposure:   { label: 'Admin Exposure',     pct: 20 },
};
