# Golden Test Domain Plan

These domains are planned controlled fixtures for future scanner validation. They do not need to exist yet. Each domain should be hosted by CyberMeters with stable DNS, TLS, headers, and email records so scanner changes can be regression-tested without relying on third-party behaviour.

The machine-readable provisioning plan lives in `docs/golden-test-domains.json`. Actual DNS, TLS, web server, and email record provisioning remains external infrastructure work.

## good.cybermeters.com

Purpose: Clean baseline with HTTPS, HTTP to HTTPS redirect, strong security headers, SPF, DMARC reject, and DKIM.

Expected findings: none from DNS, SSL, headers, or email security.

Expected confidence: high confidence for absence of findings.

Expected score impact: 0.

Expected resolver agreement: `resolver_agreement_score: 100` for A record — all three resolvers (Cloudflare, Google, Quad9) should return identical A records.

Expected canonical URL profile: `canonical_confidence: "high"`, `http_redirects_to_https: true`, `http_redirect_validated: true`, `validation_uncertain: false`.

Expected header strength: HSTS `status: "valid"` (max-age ≥ 15,552,000), CSP `status: "valid"` (no unsafe-inline), X-Frame-Options `status: "valid"` (DENY or SAMEORIGIN).

Manual verification commands:

```bash
dig A good.cybermeters.com @1.1.1.1
dig A good.cybermeters.com @8.8.8.8
dig A good.cybermeters.com @9.9.9.9
curl -sI http://good.cybermeters.com
curl -sI https://good.cybermeters.com
dig TXT good.cybermeters.com @1.1.1.1
dig TXT _dmarc.good.cybermeters.com @1.1.1.1
```

## missing-headers.cybermeters.com

Purpose: HTTPS site with intentionally missing HSTS and optional secondary headers.

Expected findings: `header_missing_strict_transport_security`; optional informational missing header observations.

Expected confidence: high for HSTS only when missing consistently on canonical HTTPS 200 responses; medium or low if path-specific.

Expected score impact: HSTS impact only when absence is consistent. Other header findings should remain 0 unless explicitly promoted in a later scoring sprint.

Expected resolver agreement: `resolver_agreement_score: 100` for A record — resolver disagreement should not affect header finding confidence.

Expected canonical URL profile: `canonical_confidence: "high"`, `http_redirect_validated: true`, `validation_uncertain: false` — allows header findings to be scored confidently.

Expected header strength: no HSTS entry in `header_strength` map (header absent, not weak). CSP and X-Frame-Options entries present if configured; otherwise also absent.

Manual verification commands:

```bash
curl -sI https://missing-headers.cybermeters.com
curl -sI https://www.missing-headers.cybermeters.com
```

## weak-email.cybermeters.com

Purpose: Email-enabled domain with SPF present but weak DMARC policy.

Expected findings: `email_dmarc_policy_none`.

Expected confidence: high.

Expected score impact: -5.

Manual verification commands:

```bash
dig MX weak-email.cybermeters.com @1.1.1.1
dig TXT weak-email.cybermeters.com @1.1.1.1
dig TXT _dmarc.weak-email.cybermeters.com @1.1.1.1
```

## no-dmarc.cybermeters.com

Purpose: Email-enabled domain with SPF but no DMARC TXT record.

Expected findings: `email_missing_dmarc`.

Expected confidence: high.

Expected score impact: -15.

Manual verification commands:

```bash
dig MX no-dmarc.cybermeters.com @1.1.1.1
dig TXT _dmarc.no-dmarc.cybermeters.com @1.1.1.1
dig TXT _dmarc.no-dmarc.cybermeters.com @8.8.8.8
```

## expired-cert.cybermeters.com

Purpose: TLS endpoint with an expired certificate.

Expected findings: HTTPS/certificate-related finding once certificate expiry is promoted into primary findings.

Expected confidence: high.

Expected score impact: To be defined when certificate expiry scoring is introduced.

Manual verification commands:

```bash
echo | openssl s_client -servername expired-cert.cybermeters.com -connect expired-cert.cybermeters.com:443 2>/dev/null | openssl x509 -noout -dates
curl -Iv https://expired-cert.cybermeters.com
```

## redirect-edgecase.cybermeters.com

Purpose: Validate HTTP redirect and canonical URL handling, including cases where headers differ between root, redirect target, and www host.

Expected findings: no scored header finding when the header is present on the canonical URL but missing on an intermediate path; validation-uncertain informational finding is acceptable.

Expected confidence: low or medium for inconsistent path evidence.

Expected score impact: 0 unless absence is consistent on canonical HTTPS 200 responses.

Expected canonical URL profile: `canonical_confidence: "medium"`, `validation_uncertain: true` — redirect present but headers inconsistent across variants. This correctly suppresses header finding scoring.

Expected header strength: classifiable entries in `header_strength` only for headers actually present on the fetched response. No `status: "valid"` assertion possible when evidence is uncertain.

Manual verification commands:

```bash
curl -sI http://redirect-edgecase.cybermeters.com
curl -sI https://redirect-edgecase.cybermeters.com
curl -sI https://www.redirect-edgecase.cybermeters.com
```

## wildcard-dns.cybermeters.com

Purpose: Wildcard DNS behaviour where arbitrary subdomains resolve.

Expected findings: wildcard DNS asset event and cautionary inventory metadata; no takeover finding based only on wildcard DNS.

Expected confidence: medium.

Expected score impact: 0 unless a separate confirmed exposure is present.

Expected resolver agreement: `resolver_agreement_score: 100` for known subdomains (all resolvers return the wildcard IP); `resolver_agreement_score: 100` for random subdomains too if wildcard is consistent. Resolver disagreement on wildcard responses would increase uncertainty.

Manual verification commands:

```bash
dig A wildcard-dns.cybermeters.com @1.1.1.1
dig A wildcard-dns.cybermeters.com @8.8.8.8
dig A wildcard-dns.cybermeters.com @9.9.9.9
dig A random-test-value.wildcard-dns.cybermeters.com @1.1.1.1
dig A random-test-value.wildcard-dns.cybermeters.com @8.8.8.8
```

## weak-headers.cybermeters.com

Purpose: HTTPS site with security headers present but misconfigured — specifically HSTS with short max-age and CSP with unsafe-inline.

Expected findings: header presence confirmed (no `header_missing_*` findings); optional informational weak-header observations.

Expected confidence: high for confirmed presence of headers; weakness classification is evidence-only and non-scoring.

Expected score impact: 0 from header weakness. Header absence findings suppressed because headers are present.

Expected resolver agreement: `resolver_agreement_score: 100` for A record.

Expected canonical URL profile: `canonical_confidence: "high"`, `http_redirect_validated: true`.

Expected header strength:
- HSTS: `status: "weak"`, details note max-age below 15,552,000 threshold.
- CSP: `status: "weak"`, details note unsafe-inline present.
- X-Frame-Options: `status: "valid"` if DENY or SAMEORIGIN is set.

Manual verification commands:

```bash
curl -sI https://weak-headers.cybermeters.com | grep -i 'strict-transport\|content-security\|x-frame'
```
