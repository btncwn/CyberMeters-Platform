// ── Cyber Metrics scoring engine ──
// The central posture-scoring engine: security-headers config, email-applicability gating,
// computeScore (translates all module evidence into score + findings + recommendations),
// and score→risk-level mapping. Extracted verbatim from index.js (monolith decomposition,
// Phase 1c). NON_MAIL_PREFIXES is module-internal; SECURITY_HEADERS is the shared
// leaf config in security-headers-config.js (see that file for the anti-cycle rationale).
import { assetFingerprintSignals } from "./asset-intel.js";
import { resolveDnsResolution } from "./attack-surface-signal-completeness.js";
import { runTyposquatModule } from "./brand-typosquat.js";
import { DKIM_PROVIDER_LABELS, DKIM_SELECTORS, isEmailProbeUnobserved } from "./email-analysis.js";
import { applyEvidenceQuality } from "./findings.js";
import { classifyHeaderStrength } from "./headers-scan.js";
import { ENTERPRISE_BENCHMARK, ENTERPRISE_DOMAINS } from "./scoring-config.js";
import { SECURITY_HEADERS } from "./security-headers-config.js";
import { resolveRemediation } from "./remediation-registry.js";
import {
  isHttpRedirectPositivelyAbsent,
  resolveTlsRuntimeState,
  TLS_RUNTIME_STATES,
} from "./tls-evidence.js";

// ── Email Security Applicability ─────────────────────────────────────────────
//
// Determines whether SPF / DMARC / DKIM findings are meaningful for a domain.
// Subdomains with well-known non-mail prefixes (www, api, cdn, …) and domains
// with no MX records are not expected to send mail — producing Missing SPF /
// Missing DMARC findings against them is a false positive.
//
// Returns { applicable: boolean, reason?: string }

const NON_MAIL_PREFIXES = [
  "www.", "api.", "cdn.", "static.", "assets.",
  "img.", "docs.", "status.", "help.", "mail.",
];

export function isEmailApplicable(domain, dnsMod) {
  // Subdomain prefix check — these hosts never send mail
  for (const pfx of NON_MAIL_PREFIXES) {
    if (domain.startsWith(pfx)) {
      return { applicable: false, reason: "No mail infrastructure detected" };
    }
  }
  // MX absence is a positive signal: the domain itself publishes no mail exchanger
  // (only skip when we have a successful DNS result — don't skip on DNS error)
  if (dnsMod && !dnsMod.error && dnsMod.has_mx === false) {
    return { applicable: false, reason: "No mail infrastructure detected" };
  }
  return { applicable: true };
}

// ── Cyber Metrics Scoring Engine ──────────────────────────────────────────────

export function computeScore(modules, domain) {
  let score = 100;
  const findings        = [];
  const recommendations = [];
  const evidenceTime    = new Date().toISOString();

  function finding(f) {
    score += f.score_impact; // negative number
    findings.push({ ...f, finding_type: "finding" });
  }

  // Canonical remediation copy comes from the shared registry so every surface
  // that reads remediation_items (scan detail, scorecard, executive report, PDF)
  // shows the SAME honest, non-conflicting advice. `detail` carries the concrete,
  // domain- or host-specific text (record to publish, affected hosts) — that is
  // surface formatting, not semantic drift. Falls back to the provided literals
  // if the registry ever lacks the finding type (CI asserts every wired type
  // resolves, so this path is a safety net, not the norm).
  function canonicalRec(findingType, { priority, module, detail = "", title, description } = {}) {
    const r = resolveRemediation({ finding_type: findingType });
    const resolved = r.status === "resolved";
    const recTitle = resolved ? r.customer_title : title;
    const baseAction = resolved ? r.recommended_action : description;
    const recDescription = detail ? `${baseAction} ${detail}`.trim() : baseAction;
    return { priority, module, title: recTitle, description: recDescription };
  }

  // ── DNS ────────────────────────────────────────────────────────────────
  // "Domain Does Not Resolve" is CRITICAL and costs -30, so it must reflect an
  // AUTHORITATIVE absence — never a probe that did not run.
  //
  // This gate previously read `resolution_assessed !== false`, which treats a
  // MISSING contract field as if the resolvers had answered. The DNS deadline
  // fallback carries no resolution fields at all, so a scan where not one lookup was
  // performed emitted the critical finding and took 30 points off the customer's
  // score. Absence of evidence was scored as evidence of absence.
  //
  // The legacy missing-field fallback is REMOVED. Historical compatibility cannot
  // outrank evidence honesty: an old report that never recorded the contract simply
  // does not support a critical verdict, and the honest reading of it is "unknown".
  //
  // The decision now comes from the canonical DNS resolution vocabulary already
  // implemented for Attack Surface (attack-surface-signal-completeness.js), so there
  // is ONE definition rather than two that can drift:
  //   observed      — records seen                     → no finding
  //   absent        — resolution_assessed === true and no A/AAAA  → FIRE (the only case)
  //   incomplete    — contract not recorded (missing fields)      → defer
  //   unavailable   — resolvers did not answer / module error     → defer
  //   not_assessed  — module skipped or executed === false        → defer
  const dnsResolutionSignal = resolveDnsResolution(modules);
  const dnsAuthoritativelyUnresolved =
    dnsResolutionSignal.state === "absent" &&
    dnsResolutionSignal.reason === "authoritative_dns_absence";
  if (dnsAuthoritativelyUnresolved) {
    finding({
      id:           "dns_no_resolution",
      module:       "dns",
      severity:     "critical",
      confidence:   "high",
      title:        "Domain Does Not Resolve",
      description:  `No A or AAAA DNS records found for ${domain}. The domain cannot be reached.`,
      score_impact: -30,
      evidence: {
        evidence_type:               "dns_lookup",
        probe_target:                domain,
        observed_value:              "No A or AAAA records returned",
        expected_value:              "At least one A or AAAA record pointing to a server IP",
        source:                      "cloudflare_doh",
        checked_at:                  evidenceTime,
        manual_verification_command: `dig A ${domain} @8.8.8.8`,
        resolver_agreement_score:    modules.dns?.cross_checks?.a?.resolver_agreement_score ?? null,
        resolver_disagreement:       modules.dns?.cross_checks?.a?.resolver_disagreement ?? false,
        resolver_results: [
          modules.dns?.cross_checks?.a?.cloudflare_resolver ?? null,
          modules.dns?.cross_checks?.a?.google_resolver     ?? null,
          modules.dns?.cross_checks?.a?.quad9_resolver      ?? null,
        ].filter(Boolean),
        cross_checked_at:            modules.dns?.cross_checks?.cross_checked_at ?? null,
      },
    });
    recommendations.push(canonicalRec("dns_no_resolution", {
      priority: 1, module: "dns",
      title: "Fix DNS Configuration",
      description: "Ensure A records are published for your domain pointing to your server's IP address.",
    }));
  }

  // ── DNS Resolver Disagreement ─────────────────────────────────────────
  // v5: Fire when the overall cross-check agreement score is below 75.
  // This is informational only — DNS record differences across resolvers
  // may indicate a propagation delay, split-horizon DNS, or CDN anycast.
  // score_impact: 0 — never affects Business Risk Score.
  {
    const overallAgreement = modules.dns?.cross_checks?.resolver_agreement_score;
    if (overallAgreement != null && overallAgreement < 75) {
      findings.push({
        id:           "dns_resolver_disagreement",
        module:       "dns",
        severity:     "info",
        confidence:   "medium",
        title:        "DNS Resolver Disagreement Detected",
        description:  `DNS records for ${domain} differ between resolvers (Cloudflare vs Google DoH). Agreement score: ${overallAgreement}/100. This may indicate DNS propagation in progress, split-horizon DNS, or anycast edge differences. Verify records are consistent across resolvers.`,
        score_impact: 0,
        evidence: {
          evidence_type:               "dns_cross_check",
          probe_target:                domain,
          observed_value:              `Resolver agreement score: ${overallAgreement}/100 (threshold: 75)`,
          expected_value:              "All resolvers return identical records (score ≥ 75)",
          source:                      "cloudflare_doh + google_doh",
          checked_at:                  evidenceTime,
          manual_verification_command: `dig A ${domain} @1.1.1.1 && dig A ${domain} @8.8.8.8`,
          resolver_agreement_score:    overallAgreement,
          cross_checked_at:            modules.dns?.cross_checks?.cross_checked_at ?? null,
          per_type_scores: {
            a:         modules.dns?.cross_checks?.a?.resolver_agreement_score         ?? null,
            aaaa:      modules.dns?.cross_checks?.aaaa?.resolver_agreement_score      ?? null,
            mx:        modules.dns?.cross_checks?.mx?.resolver_agreement_score        ?? null,
            txt_spf:   modules.dns?.cross_checks?.txt_spf?.resolver_agreement_score   ?? null,
            txt_dmarc: modules.dns?.cross_checks?.txt_dmarc?.resolver_agreement_score ?? null,
            caa:       modules.dns?.cross_checks?.caa?.resolver_agreement_score       ?? null,
          },
        },
      });
    }
  }

  // ── DNSSEC Trust Evidence ──────────────────────────────────────────────
  // Intelligence-only: DNSSEC posture is reported from observed DS, DNSKEY,
  // and RRSIG records without changing the CyberMeters score.
  {
    const dnssec = modules.dns?.dnssec;
    const noDnssecLookupErrors = dnssec && !dnssec.errors?.ds && !dnssec.errors?.dnskey && !dnssec.errors?.rrsig;
    const dsPresent = !!dnssec?.ds?.present;
    const dnskeyPresent = !!dnssec?.dnskey?.present;
    const rrsigPresent = !!dnssec?.rrsig?.present;

    if (noDnssecLookupErrors && !dsPresent && !dnskeyPresent && !rrsigPresent) {
      findings.push({
        id:           "dnssec_not_enabled",
        module:       "dns",
        severity:     "info",
        confidence:   "high",
        title:        "DNSSEC Not Configured",
        description:  `No DS, DNSKEY, or RRSIG records were found for ${domain}. DNSSEC is not configured for this domain.`,
        score_impact: 0,
        evidence: {
          evidence_type:               "dnssec_lookup",
          probe_target:                domain,
          observed_value:              "DS absent, DNSKEY absent, RRSIG absent",
          expected_value:              "DS, DNSKEY, and RRSIG records present",
          source:                      dnssec.evidence_source,
          checked_at:                  evidenceTime,
          manual_verification_command: `dig DS ${domain} @1.1.1.1 +dnssec && dig DNSKEY ${domain} @1.1.1.1 +dnssec && dig A ${domain} @1.1.1.1 +dnssec`,
          ds:                          dnssec.ds,
          dnskey:                      dnssec.dnskey,
          rrsig:                       dnssec.rrsig,
        },
      });
    } else if (noDnssecLookupErrors && ((dsPresent && !dnskeyPresent) || (!dsPresent && dnskeyPresent))) {
      findings.push({
        id:           "dnssec_misconfigured",
        module:       "dns",
        severity:     "info",
        confidence:   "medium",
        title:        "DNSSEC Configuration Incomplete",
        description:  `DNSSEC evidence for ${domain} is incomplete. DS present: ${dsPresent}; DNSKEY present: ${dnskeyPresent}; RRSIG present: ${rrsigPresent}.`,
        score_impact: 0,
        evidence: {
          evidence_type:               "dnssec_lookup",
          probe_target:                domain,
          observed_value:              `DS=${dsPresent}, DNSKEY=${dnskeyPresent}, RRSIG=${rrsigPresent}`,
          expected_value:              "DS and DNSKEY records consistently present for a signed delegation",
          source:                      dnssec.evidence_source,
          checked_at:                  evidenceTime,
          manual_verification_command: `dig DS ${domain} @1.1.1.1 +dnssec && dig DNSKEY ${domain} @1.1.1.1 +dnssec`,
          ds:                          dnssec.ds,
          dnskey:                      dnssec.dnskey,
          rrsig:                       dnssec.rrsig,
        },
      });
    }
  }

  // ── SSL ────────────────────────────────────────────────────────────────
  const tls = resolveTlsRuntimeState(modules.ssl, { assessedDomain: domain ?? null });
  if (tls.state === TLS_RUNTIME_STATES.POSITIVELY_ABSENT) {
    finding({
      id:           "ssl_not_available",
      module:       "ssl",
      severity:     "critical",
      confidence:   "high",
      title:        "HTTPS Not Available",
      description:  `${domain} does not serve content over HTTPS. All traffic is transmitted unencrypted.`,
      score_impact: -25,
      evidence: {
        evidence_type:               "active_tls_positive_absence",
        probe_target:                `https://${domain}`,
        observed_value:              tls.evidence.absence_outcome,
        expected_value:              "TLS 1.2+ handshake success with valid certificate",
        source:                      tls.evidence.source_type,
        checked_at:                  tls.evidence.observed_at,
        tls_state:                   tls.state,
        tls_positive_absence_evidence: { ...tls.evidence },
        manual_verification_command: `curl -sI https://${domain} | head -3`,
      },
    });
    recommendations.push(canonicalRec("ssl_not_available", {
      priority: 1, module: "ssl",
      title: "Install a TLS Certificate",
      description: "Enable HTTPS using a free certificate from Let's Encrypt via Certbot, or through your hosting provider.",
    }));
  } else if (!modules.ssl?.http_redirects_to_https) {
    // Two situations suppress the scored finding:
    //
    // 1. http_redirect_validated === false: the HTTP fetch was blocked entirely
    //    (firewall, bot protection) — we cannot conclude anything.
    //
    // 2. Enterprise edge uncertainty: ENTERPRISE_DOMAINS that show no HTTPS
    //    redirect on the HTTP probe yet successfully serve HTTPS on the headers
    //    probe.  This contradiction is characteristic of large CDN edge deployments
    //    (Google Front End, Cloudflare Workers, etc.) that respond differently to
    //    scanner IPs than to real browsers.  We cannot confirm plaintext HTTP
    //    remains accessible, so we must not generate a scored finding.
    // PR-A2: the DEFINITIVE "HTTP Does Not Redirect to HTTPS" verdict (medium,
    // score_impact -5) requires POSITIVE origin evidence, not merely the absence of
    // an explicit false. `!== false` treated a missing field as validated, so any
    // producer that failed to set it — or a Cloudflare edge Response, which used to
    // set it TRUE — reached the definitive branch. The redirect chain now carries an
    // observation state from the shared classifier; a verdict is only sayable when
    // the initial hop was a genuine origin_response.
    const redirectChain           = modules.ssl?.http_redirect_chain;
    const redirectObservation     = redirectChain?.observation_state;
    // ABSENCE IS NEVER CONSENT. The legacy branch accepts only an EXPLICIT positive.
    // `!== false` read a missing field as validated, so PR-A1's deadline fallback —
    // which carries no http_redirect_chain at all — produced the definitive medium
    // -5 "HTTP Does Not Redirect to HTTPS" with no HTTP probe having run. A missing
    // chain, a missing field, false, edge, incomplete, unavailable and not-assessed
    // are now all non-definitive; only an old report carrying an explicit `true`
    // keeps working, which is the sole reason the legacy branch exists.
    const redirectValidated       = isHttpRedirectPositivelyAbsent(modules.ssl);
    const headersFinalHttps       = modules.headers?.final_https !== false;
    const enterpriseEdgeUncertain = ENTERPRISE_DOMAINS.has(domain)
      && redirectValidated
      && headersFinalHttps;   // redirect failed but HTTPS reachable → contradiction

    // P1 Trust Fix: when HTTPS is confirmed, the port 80 probe result is irrelevant.
    // A blocked/unreachable HTTP probe is only meaningful if the site has no HTTPS.
    // Suppressing the uncertain finding reduces informational noise on CDN-hosted domains.
    const httpsConfirmed = tls.state === TLS_RUNTIME_STATES.OBSERVED_PRESENT;

    if (!redirectValidated || enterpriseEdgeUncertain) {
      if (!httpsConfirmed) {
        // HTTPS unavailable and port 80 uncertain — surface the observation
        findings.push({
          id:           "ssl_no_http_redirect",
          module:       "ssl",
          severity:     "info",
          confidence:   "low",
          title:        "HTTP Redirect — Validation Uncertain",
          description:  enterpriseEdgeUncertain
            ? `The HTTP probe of ${domain} returned a non-redirecting response, but the HTTPS headers probe succeeded — a contradiction typical of enterprise CDN edge behaviour where scanner IPs receive different treatment than real browsers. The scanner cannot confirm whether plain HTTP is actually accessible. This is an informational observation only.`
            : `Plain HTTP (port 80) connectivity to ${domain} could not be validated. The scanner's request may have been blocked by an edge firewall or bot-protection layer. This is an informational observation only.`,
          score_impact: 0,
          evidence: {
            evidence_type:               "http_redirect_probe",
            probe_target:                `http://${domain}`,
            observed_value:              enterpriseEdgeUncertain
              ? "HTTP probe returned non-redirect; HTTPS probe succeeded — contradictory result"
              : "HTTP probe blocked or no response received",
            expected_value:              `HTTP 301/302 redirect to https://${domain}`,
            source:                      "cloudflare_workers_fetch",
            checked_at:                  evidenceTime,
            manual_verification_command: `curl -sI http://${domain} | head -5`,
          },
        });
      }
      // else: HTTPS confirmed — port 80 status irrelevant, finding suppressed
    } else {
      finding({
        id:           "ssl_no_http_redirect",
        module:       "ssl",
        severity:     "medium",
        confidence:   "high",
        title:        "HTTP Does Not Redirect to HTTPS",
        description:  `Plain HTTP (port 80) requests to ${domain} are not redirected to HTTPS, allowing unencrypted access.`,
        score_impact: -5,
        evidence: {
          evidence_type:               "http_redirect_probe",
          probe_target:                `http://${domain}`,
          observed_value:              "HTTP response did not issue a redirect to HTTPS",
          expected_value:              `HTTP 301/302 redirect to https://${domain}`,
          source:                      "cloudflare_workers_fetch",
          checked_at:                  evidenceTime,
          manual_verification_command: `curl -sI http://${domain} | head -5`,
        },
      });
      recommendations.push(canonicalRec("ssl_no_http_redirect", {
        priority: 2, module: "ssl",
        title: "Enforce HTTPS Redirect",
        description: "Configure your web server or CDN to issue a 301 redirect from http:// to https:// for all requests.",
      }));
    }
  }

  // ── Canonical URL Consistency (v5) ────────────────────────────────────
  // Fired when the canonical URL profile is incomplete or uncertain.
  // score_impact: 0 — informational only.
  {
    const prof = modules.canonical_url_profile;
    if (prof && (prof.canonical_consistency_score < 70 || prof.profile_complete === false)) {
      findings.push({
        id:           "canonical_url_uncertain",
        module:       "ssl",
        severity:     "info",
        confidence:   "medium",
        title:        "Canonical URL Could Not Be Confirmed",
        description:  `The canonical URL for ${domain} could not be determined with high confidence (consistency score: ${prof.canonical_consistency_score ?? "n/a"}/100). ${prof.validation_uncertain ? "The scanner response may be from a bot-protection layer. " : ""}${!prof.http_redirect_validated ? "HTTP probe was blocked or unavailable. " : ""}Verify the canonical URL manually.`,
        score_impact: 0,
        evidence: {
          evidence_type:               "canonical_url_probe",
          probe_target:                domain,
          observed_value:              prof.canonical_url ?? "undetermined",
          expected_value:              `https://${domain} or https://www.${domain}`,
          canonical_confidence:        prof.canonical_confidence,
          canonical_consistency_score: prof.canonical_consistency_score,
          profile_complete:            prof.profile_complete,
          validation_uncertain:        prof.validation_uncertain,
          http_redirect_validated:     prof.http_redirect_validated,
          source:                      "cloudflare_workers_fetch",
          checked_at:                  evidenceTime,
          manual_verification_command: `curl -sIL http://${domain} | grep -E "(HTTP|Location)"`,
          variants_checked:            (prof.variants || []).map((v) => ({ variant: v.variant, requested_url: v.requested_url, final_url: v.final_url, probe_method: v.probe_method })),
        },
      });
    }
  }

  // ── Security Headers ───────────────────────────────────────────────────
  if (modules.headers?.accessible) {
    // Three conditions must ALL be true for any header finding to be scored:
    //   1. final_https: response came from an HTTPS endpoint (not HTTP fallback)
    //   2. validation_uncertain: false — no bot-protection / challenge interception
    //   3. status_code: 200 — a real application response, not an error or redirect
    //
    // Beyond that, only HSTS (severity "high") is treated as a confirmed/high-confidence
    // finding.  CSP, X-Frame-Options, XCTO, Referrer-Policy, and Permissions-Policy are
    // routinely delivered by CDN edges, per-path policies, or injected by frameworks
    // and are unreliable to validate remotely — they are downgraded to informational
    // (confidence: medium, score_impact: 0) even on clean responses.
    //
    // Additionally, for ENTERPRISE_BENCHMARK domains, any contradictory signal between
    // the SSL HTTP probe and the headers HTTPS probe (enterprise edge uncertainty)
    // prevents HSTS from being scored — the HTTPS response headers may come from the
    // CDN's edge node, not the canonical origin server.
    const finalHttps          = modules.headers.final_https !== false;
    const validationUncertain = !!modules.headers.validation_uncertain;
    const statusCode          = modules.headers.status_code ?? 0;
    // Enterprise edge uncertainty: see ssl_no_http_redirect gate above for rationale
    const sslNoHttpsRedirect        = !modules.ssl?.http_redirects_to_https;
    // Same explicit-evidence rule as the ssl_no_http_redirect gate above (second
    // instance of the identical missing-field-as-evidence pattern). "Enterprise edge
    // uncertainty" asserts a CONTRADICTION between two probes; a redirect we never
    // observed cannot evidence a contradiction, so it must not be inferred from an
    // absent field. Prefer the chain's own observation state when present.
    const sslRedirectWasObservable  = isHttpRedirectPositivelyAbsent(modules.ssl);
    const headerEnterpriseUncertain = ENTERPRISE_DOMAINS.has(domain)
      && sslRedirectWasObservable
      && sslNoHttpsRedirect
      && finalHttps;
    // responseQualityOk requires all base conditions AND no enterprise edge contradiction
    const responseQualityOk = finalHttps && !validationUncertain && statusCode === 200 && !headerEnterpriseUncertain;

    // Collect Branch C (medium-severity, unverified) headers for consolidated output
    const branchCHeaders = [];

    for (const h of SECURITY_HEADERS) {
      // HSTS is only meaningful on HTTPS — skip entirely on HTTP fallback
      if (h.name === "strict-transport-security" && !finalHttps) continue;
      // Header is present — nothing to report
      if (modules.headers.values?.[h.name]) continue;

      const headerProbeUrl = modules.headers.response_url ?? `https://${domain}`;
      const headerObservedElsewhere = (modules.headers.checked_paths || []).some(
        (p) => p.headers_observed?.[h.name]
      );
      const headerBaseEvidence = {
        evidence_type:               "http_header_probe",
        probe_target:                headerProbeUrl,
        requested_url:               modules.headers.original_url ?? `https://${domain}`,
        final_url:                   modules.headers.response_url ?? null,
        redirect_chain:              modules.headers.raw_capture?.redirect_chain ?? [],
        status_code:                 modules.headers.status_code,
        headers_observed:            modules.headers.raw_capture?.headers_snapshot ?? {},
        checked_paths:               modules.headers.checked_paths ?? [],
        missing_header:              h.name,
        expected_value:              `${h.name} header present in response`,
        source:                      "cloudflare_workers_fetch",
        checked_at:                  evidenceTime,
        manual_verification_command: `curl -sI https://${domain} | grep -i "${h.name}"`,
      };

      if (headerObservedElsewhere) {
        findings.push({
          id:           `header_missing_${h.name.replace(/-/g, "_")}`,
          module:       "headers",
          severity:     "info",
          confidence:   "medium",
          title:        `${h.label} — Validation Uncertain`,
          description:  `The ${h.label} header was missing from the primary response for ${domain}, but was observed on another checked path. Header policy may vary by host, redirect target, or canonical URL. Verify manually before treating this as a defect.`,
          score_impact: 0,
          evidence: {
            ...headerBaseEvidence,
            observed_value: `Header absent from primary response, present on at least one checked path`,
          },
        });
      } else if (!responseQualityOk) {
        // Response quality too low to make any finding — informational only
        findings.push({
          id:           `header_missing_${h.name.replace(/-/g, "_")}`,
          module:       "headers",
          severity:     "info",
          confidence:   "low",
          title:        `${h.label} — Validation Uncertain`,
          description:  `The ${h.label} header was not observed on ${domain}, but the scanner response may be from a bot-protection layer, edge cache, or non-canonical host. This is an informational observation only.`,
          score_impact: 0,
          evidence: {
            ...headerBaseEvidence,
            observed_value: `Header absent; response may be from bot-protection layer (HTTP ${modules.headers.status_code ?? "unknown"})`,
          },
        });
      } else if (h.severity !== "high") {
        // Medium/low/info severity headers: collected and emitted as a single
        // consolidated observation after this loop. Individual IDs are preserved
        // in _consolidated_ids so BRS and other ID-based checks remain accurate.
        branchCHeaders.push({ h, headerBaseEvidence });
      } else {
        // High-severity, high-confidence, verified HTTPS 200 response — score it
        finding({
          id:           `header_missing_${h.name.replace(/-/g, "_")}`,
          module:       "headers",
          severity:     "high",
          confidence:   "high",
          title:        `Missing ${h.label} Header`,
          description:  `The ${h.label} header (${h.name}) was not returned in HTTP responses from ${domain}. This was confirmed on a direct HTTPS 200 response.`,
          score_impact: h.score_impact,
          evidence: {
            ...headerBaseEvidence,
            observed_value: `Header absent from confirmed HTTPS 200 response at ${headerProbeUrl}`,
          },
        });
        recommendations.push(canonicalRec(`header_missing_${h.name.replace(/-/g, "_")}`, {
          priority: 2, module: "headers",
          title: `Add ${h.label} Header`,
          description: h.recommendation,
        }));
      }
    }

    // ── Header Consolidation (Observation Consolidation v1) ──────────────
    // Emit a single "Security Headers Not Observed" card for all Branch C headers.
    // _consolidated_ids carries the individual IDs so BRS/flag checks remain accurate
    // without needing to know about the consolidated finding ID.
    if (branchCHeaders.length > 0) {
      const headerProbeUrl   = modules.headers.response_url ?? `https://${domain}`;
      const absentLabels     = branchCHeaders.map(({ h }) => h.label).join(", ");
      const absentNames      = branchCHeaders.map(({ h }) => h.name).join(", ");
      const curlGreps        = branchCHeaders.map(({ h }) => `grep -i '${h.name}'`).join(" | ");
      const consolidatedIds  = branchCHeaders.map(({ h }) => `header_missing_${h.name.replace(/-/g, "_")}`);

      findings.push({
        id:               "security_headers_not_observed",
        module:           "headers",
        severity:         "info",
        confidence:       "medium",
        title:            "Security Headers Not Fully Observed",
        description:      `The following security headers were not detected in the scanner response from ${domain}: ${absentLabels}. These headers are frequently delivered by CDN layers, framework middleware, or per-path policies and may not appear on the root path scanned. Verify on the canonical origin before treating as a defect.`,
        score_impact:     0,
        _consolidated_ids: consolidatedIds,
        evidence: {
          evidence_type:               "http_header_probe",
          probe_target:                headerProbeUrl,
          requested_url:               modules.headers.original_url ?? `https://${domain}`,
          observed_value:              `Headers absent from HTTPS ${modules.headers.status_code} response: ${absentNames}`,
          expected_value:              `${absentNames} headers present in HTTP response`,
          checked_paths:               modules.headers.checked_paths ?? [],
          source:                      "cloudflare_workers_fetch",
          checked_at:                  evidenceTime,
          manual_verification_command: `curl -sI https://${domain} | ${curlGreps}`,
        },
      });
    }

    // ── Header Strength Findings (v5) ────────────────────────────────────
    // Second pass over PRESENT headers — check strength classification.
    // Only fires when the response quality is sufficient to trust the result:
    //   - final_https and status_code === 200 (same gate as scored findings)
    //   - validation_uncertain === false
    // All strength findings are score_impact: 0 (informational).
    if (responseQualityOk) {
      for (const h of SECURITY_HEADERS) {
        const rawValue = modules.headers.values?.[h.name];
        if (!rawValue) continue;  // header absent — handled by missing-header loop above

        const strength = classifyHeaderStrength(h.name, rawValue);

        if (h.name === "strict-transport-security" && strength.status === "weak") {
          findings.push({
            id:           "header_weak_hsts",
            module:       "headers",
            severity:     "info",
            confidence:   "high",
            title:        "Weak HSTS Configuration",
            description:  `The HSTS header on ${domain} is present but configured with a short max-age. ${strength.details}. Recommended minimum: max-age=31536000 (1 year) with includeSubDomains.`,
            score_impact: 0,
            evidence: {
              evidence_type:               "http_header_probe",
              probe_target:                modules.headers.response_url ?? `https://${domain}`,
              header_name:                 h.name,
              observed_value:              rawValue,
              expected_value:              "max-age=31536000; includeSubDomains; preload",
              strength_classification:     strength.status,
              strength_details:            strength.details,
              source:                      "cloudflare_workers_fetch",
              checked_at:                  evidenceTime,
              manual_verification_command: `curl -sI https://${domain} | grep -i strict-transport-security`,
            },
          });
        } else if (h.name === "content-security-policy" && strength.status === "weak") {
          findings.push({
            id:           "csp_weak_policy",
            module:       "headers",
            severity:     "medium",
            confidence:   "high",
            title:        "Weak Content Security Policy",
            description:  `The Content-Security-Policy header on ${domain} is present but contains directives that reduce its effectiveness. ${strength.details}.`,
            score_impact: 0,
            evidence: {
              evidence_type:               "http_header_probe",
              probe_target:                modules.headers.response_url ?? `https://${domain}`,
              header_name:                 h.name,
              observed_value:              rawValue,
              expected_value:              "default-src 'self'; no unsafe-inline or wildcard source",
              strength_classification:     strength.status,
              strength_details:            strength.details,
              source:                      "cloudflare_workers_fetch",
              checked_at:                  evidenceTime,
              manual_verification_command: `curl -sI https://${domain} | grep -i content-security-policy`,
            },
          });
        } else if (strength.status === "malformed") {
          findings.push({
            id:           `header_malformed_${h.name.replace(/-/g, "_")}`,
            module:       "headers",
            severity:     "medium",
            confidence:   "high",
            title:        `Malformed ${h.label} Header`,
            description:  `The ${h.label} header (${h.name}) on ${domain} is present but cannot be parsed correctly. ${strength.details}.`,
            score_impact: 0,
            evidence: {
              evidence_type:               "http_header_probe",
              probe_target:                modules.headers.response_url ?? `https://${domain}`,
              header_name:                 h.name,
              observed_value:              rawValue,
              expected_value:              h.recommendation,
              strength_classification:     "malformed",
              strength_details:            strength.details,
              source:                      "cloudflare_workers_fetch",
              checked_at:                  evidenceTime,
              manual_verification_command: `curl -sI https://${domain} | grep -i "${h.name}"`,
            },
          });
        }
      }
    }
  }

  // ── Email Security ─────────────────────────────────────────────────────
  // Phase 4: Applicability gate — subdomains with non-mail prefixes and domains
  // without MX records do not send mail; skip SPF/DMARC/DKIM findings entirely.
  const emailApp = isEmailApplicable(domain, modules.dns);
  if (!emailApp.applicable) {
    // Informational observation only — no score deduction
    findings.push({
      id:           "email_not_applicable",
      module:       "email_security",
      severity:     "info",
      confidence:   "high",
      title:        "Email Security: Not Applicable",
      description:  `Email security checks were skipped for ${domain}: ${emailApp.reason}. Configure SPF, DMARC, and DKIM on the apex domain if this organisation sends mail.`,
      score_impact: 0,
      evidence: {
        evidence_type:               "dns_mx_lookup",
        probe_target:                domain,
        observed_value:              emailApp.reason,
        expected_value:              "MX records present indicating this domain sends mail",
        source:                      "cloudflare_doh",
        checked_at:                  evidenceTime,
        manual_verification_command: `dig MX ${domain} @8.8.8.8`,
      },
    });
  } else {
    // Canonical DMARC state (ADR-003). `dmarc_state` is NON-ENUMERABLE on the
    // live email module result — read it directly from the source object here.
    // A spread/JSON copy drops it, which would silently fall back to legacy and
    // re-penalise an UNAVAILABLE lookup as a missing record. When it is absent
    // (pre-ADR reports / R2 reconstruction) we fall back to the legacy raw read,
    // so historical scans are never rewritten. Scoring only expresses two DMARC
    // findings; the full nine-rung ladder (invalid/quarantine/partials as issues,
    // reject as healthy) is the Cyber MOT authority (cyber-mot-domains.js).
    const dmarcState = modules.email_security?.dmarc_state;
    const dmarcLevel = dmarcState?.enforcement_level ?? null;
    // not_observed / not_yet_assessed → neither branch → score-neutral (ADR §11):
    // an unobservable domain must never take the missing-DMARC penalty.
    const missingDmarc = dmarcLevel !== null
      ? dmarcLevel === "no_record"
      : !modules.email_security?.dmarc?.present;
    const dmarcMonitorOnly = dmarcLevel !== null
      ? dmarcLevel === "monitoring"
      : modules.email_security?.dmarc?.policy === "none";
    if (missingDmarc) {
      finding({
        id:           "email_missing_dmarc",
        module:       "email_security",
        severity:     "high",
        confidence:   "high",
        title:        "Missing DMARC Policy",
        description:  `No DMARC TXT record was found at _dmarc.${domain}. Receivers have no domain-owner policy for handling messages that fail DMARC alignment.`,
        score_impact: -15,
        evidence: {
          evidence_type:               "dns_txt_lookup",
          probe_target:                `_dmarc.${domain}`,
          observed_value:              null,
          expected_value:              `v=DMARC1; p=reject; rua=mailto:dmarc-reports@${domain}`,
          source:                      "cloudflare_doh",
          checked_at:                  evidenceTime,
          manual_verification_command: `dig TXT _dmarc.${domain} @8.8.8.8`,
          resolver_agreement_score:    modules.dns?.cross_checks?.txt_dmarc?.resolver_agreement_score ?? null,
          resolver_disagreement:       modules.dns?.cross_checks?.txt_dmarc?.resolver_disagreement ?? false,
          cross_checked_at:            modules.dns?.cross_checks?.cross_checked_at ?? null,
        },
      });
      recommendations.push(canonicalRec("email_missing_dmarc", {
        priority: 1, module: "email_security",
        detail: `Example starting record for _dmarc.${domain}: v=DMARC1; p=none; rua=mailto:dmarc-reports@${domain}`,
        title: "Implement DMARC",
        description: `Create a TXT record at _dmarc.${domain}: v=DMARC1; p=none; rua=mailto:dmarc-reports@${domain}`,
      }));
    } else if (dmarcMonitorOnly) {
      finding({
        id:           "email_dmarc_policy_none",
        module:       "email_security",
        severity:     "medium",
        confidence:   "high",
        title:        "DMARC Policy is Monitor-Only (p=none)",
        description:  `DMARC is configured at _dmarc.${domain} with p=none. Receivers are not instructed to quarantine or reject messages that fail DMARC alignment.`,
        score_impact: -5,
        evidence: {
          evidence_type:               "dns_txt_lookup",
          probe_target:                `_dmarc.${domain}`,
          observed_value:              modules.email_security.dmarc.record,
          expected_value:              "v=DMARC1; p=quarantine or p=reject",
          source:                      "cloudflare_doh",
          checked_at:                  evidenceTime,
          manual_verification_command: `dig TXT _dmarc.${domain} @8.8.8.8`,
          resolver_agreement_score:    modules.dns?.cross_checks?.txt_dmarc?.resolver_agreement_score ?? null,
          resolver_disagreement:       modules.dns?.cross_checks?.txt_dmarc?.resolver_disagreement ?? false,
          cross_checked_at:            modules.dns?.cross_checks?.cross_checked_at ?? null,
        },
      });
      recommendations.push(canonicalRec("email_dmarc_policy_none", {
        priority: 2, module: "email_security",
        title: "Strengthen DMARC Policy",
        description: "Change DMARC policy from p=none to p=quarantine or p=reject to actively block spoofed emails.",
      }));
    }

    // A1: SPF evidence status (NON-ENUMERABLE — direct read off the source object,
    // never a spread/JSON copy). A failed/unexecuted SPF probe is unavailable /
    // not_yet_assessed → score-neutral, NOT a missing record. Absent (pre-A1 reports
    // / R2 reconstruction) → legacy present-based read, so history is not rewritten.
    const spfEvidence = modules.email_security?.spf_evidence_status ?? null;
    const spfUnobserved = spfEvidence ? isEmailProbeUnobserved(spfEvidence) : false;
    if (!spfUnobserved && !modules.email_security?.spf?.present) {
      finding({
        id:           "email_missing_spf",
        module:       "email_security",
        severity:     "high",
        confidence:   "high",
        title:        "Missing SPF Record",
        description:  `No SPF TXT record was found for ${domain}. Receivers cannot use SPF to identify authorised sending infrastructure for this domain.`,
        score_impact: -10,
        evidence: {
          evidence_type:               "dns_txt_lookup",
          probe_target:                domain,
          observed_value:              null,
          expected_value:              "v=spf1 include:<mail-provider> -all",
          source:                      "cloudflare_doh",
          checked_at:                  evidenceTime,
          manual_verification_command: `dig TXT ${domain} @8.8.8.8 | grep spf`,
          resolver_agreement_score:    modules.dns?.cross_checks?.txt_spf?.resolver_agreement_score ?? null,
          resolver_disagreement:       modules.dns?.cross_checks?.txt_spf?.resolver_disagreement ?? false,
          cross_checked_at:            modules.dns?.cross_checks?.cross_checked_at ?? null,
        },
      });
      recommendations.push(canonicalRec("email_missing_spf", {
        priority: 1, module: "email_security",
        detail: `Example starting record on ${domain}: v=spf1 include:your-mail-provider.com ~all`,
        title: "Add SPF Record",
        description: `Create a TXT record on ${domain}: v=spf1 include:your-mail-provider.com ~all`,
      }));
    }

    // A1 mirror of the SPF gate above: a failed/unexecuted DKIM probe sweep is
    // unavailable / not_yet_assessed — it must not publish an observation that
    // claims selectors were probed. Absent status (pre-A1 reports / R2
    // reconstruction) keeps the legacy present-based read.
    const dkimEvidence = modules.email_security?.dkim_evidence_status ?? null;
    const dkimUnobserved = dkimEvidence ? isEmailProbeUnobserved(dkimEvidence) : false;
    if (!dkimUnobserved && !modules.email_security?.dkim?.present) {
      // Provider-aware DKIM observation.
      // Common-selector probing is best-effort — enterprise domains often use custom
      // selectors. This is an informational observation; never deducts score.
      const dkimProvider     = modules.email_security?.dkim?.provider ?? null;
      const dkimProbed       = modules.email_security?.dkim?.selectors_probed ?? DKIM_SELECTORS;
      const providerLabel    = dkimProvider ? (DKIM_PROVIDER_LABELS[dkimProvider] ?? dkimProvider) : null;

      const dkimTitle = "DKIM Could Not Be Verified Using Common Selectors";

      // Description: include provider signal when available
      const dkimDescription = providerLabel
        ? `${providerLabel} was inferred as the email provider, but DKIM could not be verified for ${domain} using the selectors checked. The domain may use a custom selector. This is an informational observation, not confirmation that DKIM is absent.`
        : `DKIM could not be verified for ${domain} using common selectors. The domain may use a custom selector. This is an informational observation, not confirmation that DKIM is absent.`;

      // Confidence model:
      //   60 — provider unknown, generic selectors miss (high false-negative risk)
      //   70 — provider known, broad provider selectors miss
      //   80 — Microsoft 365 identified and both selector1 + selector2 miss
      //        (M365 mandates exactly these two selectors; absence is high-confidence)
      let dkimConfidence = 60;
      if (dkimProvider) {
        dkimConfidence = 70;
        if (dkimProvider === "microsoft365") {
          const probedSet = new Set(dkimProbed);
          if (probedSet.has("selector1") && probedSet.has("selector2")) {
            dkimConfidence = 80;
          }
        }
      }

      // Evidence: list all selectors actually probed
      const probedList = dkimProbed.join(", ");
      const firstSel   = dkimProbed[0] ?? "default";

      findings.push({
        id:                "email_dkim_not_detected",
        module:            "email_security",
        severity:          "info",
        confidence:         dkimConfidence,
        validation_quality: "partial",
        title:             dkimTitle,
        description:       dkimDescription,
        score_impact: 0,
        evidence: {
          evidence_type:               "dns_txt_lookup",
          probe_target:                `<selector>._domainkey.${domain}`,
          observed_value:              `No DKIM TXT record found on selectors: ${probedList}`,
          expected_value:              "v=DKIM1; k=rsa; p=<public-key>",
          source:                      "cloudflare_doh",
          checked_at:                  evidenceTime,
          manual_verification_command: `dig TXT ${firstSel}._domainkey.${domain} @8.8.8.8`,
          resolver_agreement_score:    null,
          resolver_disagreement:       false,
          cross_checked_at:            modules.dns?.cross_checks?.cross_checked_at ?? null,
        },
      });
    }
  }

  // ── Subdomains ─────────────────────────────────────────────────────────
  const subMod = modules.subdomains;
  if (subMod && !subMod.error) {
    const sensitiveList = subMod.sensitive || [];

    // Sprint 9D: three-tier confidence based on available validation evidence.
    // Tier 1 — HTTP confirmed (asset_exposure reachable):   confidence 80 / good
    // Tier 2 — DNS confirmed (dns_bruteforce resolved):     confidence 70 / partial
    // Tier 3 — CT log only (no validation):                 confidence 60 / weak
    const reachableSubdomains = new Set(
      (modules.asset_exposure?.assets || [])
        .filter(a => a.reachable)
        .map(a => a.host)
    );
    const bruteDnsSubdomains = new Set(
      (modules.dns_bruteforce?.items || [])
        .filter((item) => item?.wildcard_match !== true)
        .map((item) => item?.hostname || item)
        .filter(Boolean)
    );

    // Keep the result visible, but only score an HTTP-confirmed sensitive service.
    const cappedSensitive = sensitiveList.slice(0, 4);
    let confirmedSensitiveCount = 0;
    for (const sub of cappedSensitive) {
      let subConf, subVQ, severity, scoreImpact, title, description;
      if (reachableSubdomains.has(sub) && !subMod.wildcard_dns) {
        subConf = 80;
        subVQ = "good";
        severity = "medium";
        scoreImpact = -5;
        title = "Potentially Sensitive Subdomain Confirmed Reachable";
        description = `The subdomain "${sub}" suggests development, staging, or administrative use and responded to an HTTP probe. Verify that public access is intentional and appropriately protected.`;
        confirmedSensitiveCount += 1;
      } else if (reachableSubdomains.has(sub) && subMod.wildcard_dns) {
        subConf = 60;
        subVQ = "weak";
        severity = "info";
        scoreImpact = 0;
        title = "Potentially Sensitive Subdomain Name Observed";
        description = `The name "${sub}" was observed in Certificate Transparency data and responded through wildcard DNS behavior. The response may be a shared wildcard endpoint, so customer ownership and a distinct exposed service were not confirmed.`;
      } else if (bruteDnsSubdomains.has(sub)) {
        subConf = 70;
        subVQ = "partial";
        severity = "low";
        scoreImpact = 0;
        title = "Potentially Sensitive Subdomain Name Observed";
        description = `The subdomain name "${sub}" resolved in DNS, but no HTTP probe confirmed a publicly reachable service. Review it as an inventory observation, not as confirmed exposure.`;
      } else {
        subConf = 60;
        subVQ = "weak";
        severity = "info";
        scoreImpact = 0;
        title = "Potentially Sensitive Subdomain Name Observed";
        description = `The name "${sub}" was observed only in Certificate Transparency logs. No HTTP probe, takeover risk, or public service was confirmed. This observation should be reviewed, not treated as confirmed exposure.`;
      }
      const sensitiveFinding = {
        id:                `subdomain_sensitive_${sub.replace(/\./g, "_")}`,
        module:            "subdomains",
        severity,
        confidence:        subConf,
        validation_quality: subVQ,
        title,
        description,
        score_impact:      scoreImpact,
        evidence: {
          evidence_type:               scoreImpact < 0 ? "http_probe" : "certificate_transparency_observation",
          probe_target:                sub,
          observed_value:              scoreImpact < 0
            ? `${sub} responded to an HTTP probe`
            : `${sub} was observed without a confirmed reachable service`,
          expected_value:              scoreImpact < 0
            ? "Sensitive-looking service is not publicly reachable or has appropriate access controls"
            : "Independent DNS or HTTP evidence before classifying as exposure",
          source:                      scoreImpact < 0 ? "cloudflare_workers_fetch" : "certificate_transparency",
          checked_at:                  evidenceTime,
          manual_verification_command: `curl -sSI --max-time 10 https://${sub}`,
        },
      };
      if (scoreImpact < 0) {
        finding(sensitiveFinding);
      } else {
        findings.push({ ...sensitiveFinding, finding_type: "observation" });
      }
    }
    if (confirmedSensitiveCount > 0) {
      recommendations.push(canonicalRec("subdomain_sensitive", {
        priority:    2,
        module:      "subdomains",
        title:       "Review Sensitive Subdomains",
        description: `${confirmedSensitiveCount} subdomain${confirmedSensitiveCount !== 1 ? "s" : ""} with names suggesting development or administrative use responded to HTTP probes. Confirm that public access is intentional and appropriately protected.`,
      }));
    }

    // Large attack surface
    if (subMod.count > 20) {
      findings.push({
        id:           "subdomains_large_attack_surface",
        module:       "subdomains",
        severity:     "info",
        confidence:   60,
        validation_quality: "weak",
        title:        "Large Certificate Inventory Observed",
        description:  `${subMod.count} subdomain names were observed in Certificate Transparency logs for ${domain}. A larger inventory requires asset ownership and lifecycle tracking, but CT volume alone does not indicate that the domain is unsafe or that these services are currently reachable.`,
        score_impact: 0,
        finding_type: "observation",
        evidence: {
          evidence_type:               "certificate_transparency_observation",
          probe_target:                domain,
          observed_value:              `${subMod.count} names observed in Certificate Transparency logs`,
          expected_value:              "Reachability or exposure evidence before applying score impact",
          source:                      "certificate_transparency",
          checked_at:                  evidenceTime,
          manual_verification_command: `curl -s "https://crt.sh/?q=%25.${domain}&output=json"`,
        },
      });
    }
  }

  // ── Subdomain Takeover ─────────────────────────────────────────────────
  const takeoverMod = modules.subdomain_takeover;
  if (takeoverMod && !takeoverMod.error && takeoverMod.risks?.length > 0) {
    const riskCount = takeoverMod.risks.length;
    // −15 for a single risk; −25 max for multiple
    const impact = riskCount === 1 ? -15 : -25;
    finding({
      id:           "subdomain_takeover",
      module:       "subdomain_takeover",
      severity:     "high",
      confidence:   "high",
      // Machine-readable affected hosts. Managed cases derive their verification
      // target from this — never from the prose description below.
      affected_hosts: takeoverMod.risks.map((r) => r.host).filter(Boolean),
      title:        `Subdomain Takeover Risk${riskCount > 1 ? "s" : ""} Detected`,
      description:  `${riskCount} subdomain${riskCount > 1 ? "s" : ""} with dangling CNAME records pointing to unclaimed services ${riskCount > 1 ? "were" : "was"} found: ${takeoverMod.risks.map((r) => r.host).join(", ")}. These may be vulnerable to hijacking by a third party.`,
      score_impact: impact,
    });
    recommendations.push(canonicalRec("subdomain_takeover", {
      priority: 1, module: "subdomain_takeover",
      detail: `Affected records: ${takeoverMod.risks.map((r) => `${r.host} → ${r.cname}`).join("; ")}.`,
      title: "Fix Dangling DNS Records",
      description: `Remove or update the CNAME records for: ${takeoverMod.risks.map((r) => `${r.host} → ${r.cname}`).join("; ")}. Either reclaim the service, point the CNAME to a valid endpoint, or delete the DNS record entirely.`,
    }));
  }

  // ── Asset Exposure ─────────────────────────────────────────────────────
  const exposureMod = modules.asset_exposure;
  if (exposureMod && !exposureMod.error && exposureMod.assets?.length > 0) {
    // Only 200-status assets are considered risky; 401/403 are informational
    const ok200 = exposureMod.assets.filter((a) => a.status === 200);

    // A direct product fingerprint is strong enough to promote independently.
    const toolAssets = ok200.filter((asset) => {
      const signals = assetFingerprintSignals(asset);
      return signals.sensitive_service && !signals.generic_default_page;
    });
    if (toolAssets.length > 0) {
      finding({
        id:           "asset_exposure_sensitive_tool",
        module:       "asset_exposure",
        severity:     "high",
        confidence:   90,
        affected_hosts: toolAssets.map((a) => a.host).filter(Boolean),
        title:        `Sensitive Management Tool${toolAssets.length > 1 ? "s" : ""} Exposed`,
        description:  `${toolAssets.length} management or monitoring tool${toolAssets.length > 1 ? "s are" : " is"} publicly reachable: ${toolAssets.map((a) => a.host).join(", ")}. These provide privileged access and should not be internet-facing.`,
        score_impact: -10,
      });
      recommendations.push(canonicalRec("asset_exposure_sensitive_tool", {
        priority: 1, module: "asset_exposure",
        detail: `Affected interfaces: ${toolAssets.map((a) => `${a.host}${a.title ? ` (${a.title})` : ""}`).join(", ")}.`,
        title: "Restrict Access to Management Tools",
        description: `Firewall or VPN-protect the following interfaces and allow only trusted IP ranges: ${toolAssets.map((a) => `${a.host}${a.title ? ` (${a.title})` : ""}`).join(", ")}.`,
      }));
    }

    // Generic admin/login terms require corroboration from both hostname and title.
    const adminCandidates = ok200.filter((asset) => {
      if (toolAssets.includes(asset)) return false;
      const signals = assetFingerprintSignals(asset);
      return signals.admin_hostname || signals.admin_title;
    });
    const adminAssets = adminCandidates.filter((asset) => {
      const signals = assetFingerprintSignals(asset);
      return signals.admin_hostname && signals.admin_title &&
        !signals.generic_default_page &&
        !asset.provider_owned_infrastructure &&
        !subMod?.wildcard_dns;
    });
    if (adminAssets.length > 0) {
      finding({
        id:           "asset_exposure_admin_interface",
        module:       "asset_exposure",
        severity:     "medium",
        confidence:   80,
        affected_hosts: adminAssets.map((a) => a.host).filter(Boolean),
        title:        `Administrative Interface${adminAssets.length > 1 ? "s" : ""} Publicly Reachable`,
        description:  `${adminAssets.length} administrative or login interface${adminAssets.length > 1 ? "s are" : " is"} publicly accessible: ${adminAssets.map((a) => a.host).join(", ")}. Restrict access to authorised IP ranges or enforce MFA.`,
        score_impact: -8,
      });
      recommendations.push(canonicalRec("asset_exposure_admin_interface", {
        priority: 2, module: "asset_exposure",
        detail: `Affected interfaces: ${adminAssets.map((a) => a.host).join(", ")}.`,
        title: "Restrict Administrative Interfaces",
        description: `Limit the following admin interfaces to trusted IP ranges or protect with a VPN or MFA: ${adminAssets.map((a) => a.host).join(", ")}.`,
      }));
    }

    // Development/staging names also require a corroborating page title.
    const devCandidates = ok200.filter((asset) => {
      if (toolAssets.includes(asset)) return false;
      const signals = assetFingerprintSignals(asset);
      return signals.dev_hostname || signals.dev_title;
    });
    const devAssets = devCandidates.filter((asset) => {
      const signals = assetFingerprintSignals(asset);
      return signals.dev_hostname && signals.dev_title &&
        !signals.generic_default_page &&
        !asset.provider_owned_infrastructure &&
        !subMod?.wildcard_dns;
    });
    if (devAssets.length > 0) {
      finding({
        id:           "asset_exposure_dev_env",
        module:       "asset_exposure",
        severity:     "medium",
        confidence:   80,
        affected_hosts: devAssets.map((a) => a.host).filter(Boolean),
        title:        `Development Environment${devAssets.length > 1 ? "s" : ""} Publicly Reachable`,
        description:  `${devAssets.length} development or staging environment${devAssets.length > 1 ? "s are" : " is"} publicly accessible: ${devAssets.map((a) => a.host).join(", ")}. These often contain debug endpoints, test credentials, or reduced security controls.`,
        score_impact: -5,
      });
      recommendations.push(canonicalRec("asset_exposure_dev_env", {
        priority: 2, module: "asset_exposure",
        detail: `Affected environments: ${devAssets.map((a) => a.host).join(", ")}.`,
        title: "Restrict Development Environments",
        description: `Development and staging environments should not be publicly accessible. Firewall or add authentication to: ${devAssets.map((a) => a.host).join(", ")}.`,
      }));
    }

    const weakHeuristicAssets = [...new Set([...adminCandidates, ...devCandidates])]
      .filter((asset) => !adminAssets.includes(asset) && !devAssets.includes(asset));
    const providerHeuristicAssets = weakHeuristicAssets.filter((asset) => asset.provider_owned_infrastructure);
    if (providerHeuristicAssets.length > 0) {
      findings.push({
        id:           "asset_provider_infrastructure_observed",
        module:       "asset_exposure",
        severity:     "info",
        confidence:   50,
        validation_quality: "weak",
        finding_type: "observation",
        title:        "Provider-Hosted Asset Name Observed",
        description:  `${providerHeuristicAssets.length} hostname${providerHeuristicAssets.length > 1 ? "s" : ""} with sensitive-looking labels resolved through external provider infrastructure. Provider ownership alone does not confirm a customer exposure or an unsafe service.`,
        score_impact: 0,
        evidence: {
          evidence_type:  "supporting_infrastructure_observation",
          probe_target:   providerHeuristicAssets.map((asset) => asset.host).join(", "),
          observed_value: providerHeuristicAssets.map((asset) => `${asset.host} via ${asset.infrastructure_provider}`).join(", "),
          expected_value: "Independent service fingerprint before classifying as customer exposure",
          source:         "dns_cname_or_http_provider_signal",
          checked_at:     evidenceTime,
        },
      });
    }

    const genericHeuristicAssets = weakHeuristicAssets.filter((asset) => !asset.provider_owned_infrastructure);
    if (genericHeuristicAssets.length > 0) {
      findings.push({
        id:           "asset_exposure_interface_observed",
        module:       "asset_exposure",
        severity:     "info",
        confidence:   60,
        validation_quality: "weak",
        finding_type: "observation",
        title:        "Potential Administrative or Development Surface Observed",
        description:  `${genericHeuristicAssets.length} reachable hostname${genericHeuristicAssets.length > 1 ? "s" : ""} matched only a generic hostname, title, wildcard response, or default-page heuristic. No specific sensitive service was confirmed.`,
        score_impact: 0,
        evidence: {
          evidence_type:  "http_fingerprint_observation",
          probe_target:   genericHeuristicAssets.map((asset) => asset.host).join(", "),
          observed_value: genericHeuristicAssets.map((asset) => `${asset.host}${asset.title ? ` (${asset.title})` : ""}`).join(", "),
          expected_value: "Multiple independent signals or a known sensitive service fingerprint",
          source:         "cloudflare_workers_fetch",
          checked_at:     evidenceTime,
        },
      });
    }
  }

  // Brand monitoring findings — generated from modules.brand_monitoring (pure computation).
  // Only high/critical candidates surface as scored findings; medium/low are informational only.
  // modules.brand_monitoring is pre-populated before computeScore is called (in runScanEngine),
  // or may be passed directly in mock_modules for regression fixture testing.
  // null  = explicit opt-out (lightweight routes: free-scan, domain preview).
  // undefined = fallback: generate inline via runTyposquatModule.
  const brandMod = modules.brand_monitoring !== undefined
    ? modules.brand_monitoring
    : runTyposquatModule(domain);
  let brandScoreDeduction = 0;
  for (const c of (brandMod?.domains || [])) {
    if (!['high', 'critical'].includes(c.risk_level)) continue;
    const isIdn = c.variant_type === 'homoglyph_idn' ||
      c.idn_homograph?.is_homograph === true ||
      c.idn_homograph?.visually_confusable === true;
    const findingId = isIdn || c.variant_type === 'substitution'
      ? 'brand_homoglyph_detected'
      : (c.variant_type === 'hyphen_keyword' || c.variant_type === 'prefix_keyword')
        ? 'brand_lookalike_detected'
        : 'brand_typosquat_detected';
    const scoreImpact = c.risk_level === 'critical' ? -5 : -3;
    const riskSignals = (c.risk_reasons || []).join(', ') || 'none';
    findings.push({
      id:          findingId,
      title:       isIdn
        ? `Visually confusable IDN lookalike observed: ${c.candidate_domain}`
        : `Brand lookalike domain detected: ${c.candidate_domain}`,
      severity:    c.risk_level === 'critical' ? 'critical' : 'high',
      description: isIdn
        ? `The domain ${c.candidate_domain} is visually confusable with the protected brand under CyberMeters' bounded product policy. This is a lookalike signal, not proof of abuse. Observed risk signals: ${riskSignals}.`
        : `The domain ${c.candidate_domain} is a ${c.variant_type.replace(/_/g, ' ')} variant of your brand. Risk signals: ${riskSignals}.`,
      evidence: [
        { label: 'Candidate Domain', value: c.candidate_domain },
        ...(isIdn && c.unicode_domain
          ? [{ label: 'Unicode Display Form', value: c.unicode_domain }]
          : []),
        { label: 'Variant Type',     value: c.variant_type     },
        { label: 'Risk Level',       value: c.risk_level       },
      ],
      score_impact:       scoreImpact,
      finding_type:       'finding',
      confidence:         c.confidence ?? 40,
      validation_quality: c.validation_quality ?? 'weak',
    });
    brandScoreDeduction += Math.abs(scoreImpact);
  }
  // Cap total brand score deduction at -15 regardless of candidate count.
  score -= Math.min(15, brandScoreDeduction);

  // Clamp and classify
  score = Math.max(0, Math.min(100, Math.round(score)));
  const risk_level = riskLevelForScore(score);

  // Deduplicate recommendations and sort by priority
  const seen = new Set();
  const uniqueRecs = recommendations.filter((r) => {
    const key = r.title;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  uniqueRecs.sort((a, b) => a.priority - b.priority);

  return { score, risk_level, findings: applyEvidenceQuality(findings), recommendations: uniqueRecs };
}

// ── The canonical Cyber Metrics Score band ladder (M5.e) ─────────────────────
// The ONE score→band partition for every surface that labels the Cyber Metrics
// Score. The frontend carries a MIRROR of these values in
// frontend/src/lib/score-presentation.js (no cross-build import — the two are
// held value-identical by scripts/validate-band-ladder-contract.js, which fails
// CI if either side drifts). Any OTHER band ladder in this codebase must be a
// documented, deliberately-distinct semantic model (workspace BRS, CE grade,
// posture status, …) — never a second opinion on this score.
export const CYBER_METRICS_SCORE_BANDS = Object.freeze({
  excellent: 90,
  good: 75,
  moderate: 50,
  high: 25,
  // below `high` → critical
});

export function riskLevelForScore(score) {
  const b = CYBER_METRICS_SCORE_BANDS;
  return score >= b.excellent ? "excellent" :
    score >= b.good ? "good" :
    score >= b.moderate ? "moderate" :
    score >= b.high ? "high" : "critical";
}

// Canonical scan-score resolution (moved from executive-report.js in M5.d —
// it is score semantics, not renderer logic): the stored D1 score wins over
// the report copy; a missing pair resolves to 0, never NaN.
export function resolveCanonicalScanScore(storedScore, reportScore) {
  const storedValue = storedScore == null || storedScore === "" ? NaN : Number(storedScore);
  if (Number.isFinite(storedValue)) return storedValue;
  const reportValue = reportScore == null || reportScore === "" ? NaN : Number(reportScore);
  return Number.isFinite(reportValue) ? reportValue : 0;
}

// AS-B2 (KEV/CVE score wiring). Weights are DERIVED from the existing critical/high
// deduction scale in this engine — no new constant system:
//   • dns_no_resolution = -30 and ssl_not_available = -25 are the two existing criticals;
//   • high-severity siblings deduct -15 / -10.
// CISA KEV = confirmed active in-the-wild exploitation, which by definition is >= any
// UNexploited critical on the same scale, so it takes the TOP of the critical band (-30).
// A critical CVE (not confirmed exploited) sits at the other critical sibling's weight
// (-25); a high CVE takes the higher of the high siblings (-15). Ordering is preserved:
// KEV (-30) < CVE-critical (-25) < CVE-high (-15) in deduction magnitude.
export const KEV_CVE_SCORE_WEIGHTS = Object.freeze({
  kev_active_exploitation: -30,
  cve_critical:            -25,
  cve_high:                -15,
});

// Canonical KEV/CVE deduction for the customer Cyber Metrics Score. Single source of
// truth (consumed by resolvePhase5CustomerAssessment, which owns the customer score
// post-phase5; the asset-intel display notes read the per-note magnitude it stamps).
// Evidence-floor discipline (P1 class):
//   • gated by the phase5 publishable contract — an unexecuted/incomplete KEV or CVE
//     module contributes NOTHING (no impact, never a guessed deduction);
//   • impact applies ONLY to matched evidence (KEV matches present; CVE critical/high
//     counts > 0). Unmeasured technologies (partial coverage) never add impact — the
//     weight is per matched-severity, not scaled by unmeasured breadth.
export function computeKevCveDeduction({ modules = {}, evidence = {} } = {}) {
  // Defense-in-depth evidence-floor: no deduction unless the WHOLE phase5 evidence
  // contract is complete. A score is a conclusion over a completed assessment; an
  // incomplete scan never earns a KEV/CVE deduction, whatever a single surface says.
  if (evidence?.complete !== true) return { total: 0, kev: 0, cve: 0 };
  const publishable = evidence?.publishable || {};
  let kev = 0;
  let cve = 0;
  if (publishable.kev === true) {
    const matches = modules?.known_exploited_vulnerabilities?.matches || [];
    if (matches.length > 0) kev = KEV_CVE_SCORE_WEIGHTS.kev_active_exploitation;
  }
  if (publishable.cve === true) {
    const cveIntel = modules?.cve_intelligence || {};
    if ((cveIntel.critical_count || 0) > 0) cve = KEV_CVE_SCORE_WEIGHTS.cve_critical;
    else if ((cveIntel.high_count || 0) > 0) cve = KEV_CVE_SCORE_WEIGHTS.cve_high;
  }
  return { total: kev + cve, kev, cve };
}

// Methodology stamp for the Cyber Metrics Score (M5.c). The value dates the CURRENT
// deduction weights + band cutoffs; bump it whenever either changes, so a persisted
// snapshot can refuse to present a methodology change as posture movement
// (the CYBER_MOT_RESOLVER_VERSION / CE_READINESS_METHODOLOGY_VERSION precedent).
// 2026-08-23.1 — AS-B2: KEV/CVE evidence now moves the customer score (was 0-impact).
export const CYBER_METRICS_SCORE_METHODOLOGY_VERSION = "2026-08-23.1";
