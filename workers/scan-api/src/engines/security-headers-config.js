// ── Security Headers Config ───────────────────────────────────────────────────
// Canonical list of HTTP security headers the scanner evaluates: name, customer
// label, severity, score impact, and remediation guidance.
//
// This is a leaf module (no imports) shared by the two consumers that must agree
// on the exact same header set:
//   • headers-scan.js — probes hosts and records which headers are present/missing
//   • scoring.js      — turns present/missing headers into findings + score impact
//
// It lives here (not inside either consumer) to avoid a circular import:
// scoring.js already imports classifyHeaderStrength from headers-scan.js, so the
// header config cannot live in scoring.js and be imported back into headers-scan.js.
// A dangling reference to this list (extraction that forgot the import) is a
// runtime ReferenceError, not a build error — see security-headers-binding test.

export const SECURITY_HEADERS = [
  {
    name:         "strict-transport-security",
    label:        "HTTP Strict Transport Security (HSTS)",
    severity:     "high",
    score_impact: -5,
    recommendation:
      'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
  },
  {
    name:         "content-security-policy",
    label:        "Content Security Policy (CSP)",
    severity:     "medium",
    score_impact: -3,
    recommendation:
      "Add a Content-Security-Policy header to restrict which resources the browser may load.",
  },
  {
    name:         "x-frame-options",
    label:        "X-Frame-Options",
    severity:     "medium",
    score_impact: -2,
    recommendation: "Add: X-Frame-Options: DENY to prevent clickjacking attacks.",
  },
  {
    name:         "x-content-type-options",
    label:        "X-Content-Type-Options",
    severity:     "low",
    score_impact: -2,
    recommendation: "Add: X-Content-Type-Options: nosniff to prevent MIME-type sniffing.",
  },
  {
    name:         "referrer-policy",
    label:        "Referrer-Policy",
    severity:     "low",
    score_impact: -1,
    recommendation:
      "Add: Referrer-Policy: strict-origin-when-cross-origin",
  },
  {
    name:         "permissions-policy",
    label:        "Permissions-Policy",
    severity:     "info",
    score_impact: -1,
    recommendation:
      "Add a Permissions-Policy header to restrict access to browser APIs (camera, microphone, geolocation).",
  },
];
