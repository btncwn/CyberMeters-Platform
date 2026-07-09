// ── Scanner regression fixtures ──
// Golden test cases for the scoring/finding pipeline. Extracted verbatim from
// index.js (monolith decomposition, Phase 1c). Data only — no logic.

export const SCANNER_REGRESSION_FIXTURES = [
  {
    scenario: "good_security_headers",
    domain: "good.cybermeters.test",
    mock_modules: {
      dns: { resolves: true, has_mx: true },
      ssl: { https_available: true, http_redirects_to_https: true },
      headers: {
        accessible: true,
        final_https: true,
        validation_uncertain: false,
        status_code: 200,
        values: {
          "strict-transport-security": "max-age=31536000; includeSubDomains",
          "content-security-policy": "default-src 'self'",
          "x-frame-options": "DENY",
          "x-content-type-options": "nosniff",
          "referrer-policy": "no-referrer",
          "permissions-policy": "geolocation=()",
        },
      },
      email_security: {
        spf: { present: true, record: "v=spf1 include:_spf.google.com -all" },
        dmarc: { present: true, policy: "reject", record: "v=DMARC1; p=reject" },
        dkim: { present: true, selector: "google" },
      },
    },
    expected_absent: [
      "dns_no_resolution",
      "ssl_not_available",
      "ssl_no_http_redirect",
      "header_missing_strict_transport_security",
      "email_missing_dmarc",
      "email_missing_spf",
      "email_dkim_not_detected",
    ],
  },
  {
    scenario: "missing_hsts_header",
    domain: "missing-headers.cybermeters.test",
    mock_modules: {
      dns: { resolves: true, has_mx: true },
      ssl: { https_available: true, http_redirects_to_https: true },
      headers: {
        accessible: true,
        final_https: true,
        validation_uncertain: false,
        status_code: 200,
        values: { "strict-transport-security": null },
      },
      email_security: {
        spf: { present: true },
        dmarc: { present: true, policy: "reject" },
        dkim: { present: true },
      },
    },
    expected: { id: "header_missing_strict_transport_security", severity: "high", confidence: "high", score_impact: -5 },
  },
  {
    scenario: "dmarc_policy_none",
    domain: "weak-email.cybermeters.test",
    mock_modules: {
      dns: { resolves: true, has_mx: true },
      email_security: {
        spf: { present: true, record: "v=spf1 include:_spf.google.com -all" },
        dmarc: { present: true, policy: "none", record: "v=DMARC1; p=none" },
        dkim: { present: true },
      },
    },
    expected: { id: "email_dmarc_policy_none", severity: "medium", confidence: "high", score_impact: -5 },
  },
  {
    scenario: "missing_dmarc",
    domain: "no-dmarc.cybermeters.test",
    mock_modules: {
      dns: { resolves: true, has_mx: true },
      email_security: {
        spf: { present: true },
        dmarc: { present: false, policy: null, record: null },
        dkim: { present: true },
      },
    },
    expected: { id: "email_missing_dmarc", severity: "high", confidence: "high", score_impact: -15 },
  },
  {
    scenario: "missing_spf",
    domain: "missing-spf.cybermeters.test",
    mock_modules: {
      dns: { resolves: true, has_mx: true },
      email_security: {
        spf: { present: false, record: null },
        dmarc: { present: true, policy: "reject" },
        dkim: { present: true },
      },
    },
    expected: { id: "email_missing_spf", severity: "high", confidence: "high", score_impact: -10 },
  },
  {
    scenario: "dkim_unknown_selector",
    domain: "dkim-unknown.cybermeters.test",
    mock_modules: {
      dns: { resolves: true, has_mx: true },
      email_security: {
        spf: { present: true },
        dmarc: { present: true, policy: "reject" },
        dkim: { present: false, selector: null },
      },
    },
    expected: { id: "email_dkim_not_detected", severity: "info", confidence: "low", score_impact: 0 },
  },
];
