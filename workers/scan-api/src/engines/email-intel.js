// ── Email security intelligence module ──
// The Email Protection wedge intelligence layer: enriches SPF/DMARC/DKIM results with
// status/score/issues, probes MTA-STS + TLS-RPT + STARTTLS, computes the email security
// score + business impacts + findings, and the runEmailIntelModule roll-up. Extracted
// verbatim from index.js (monolith decomposition, Phase 1c). Only fetchMtaSts +
// runEmailIntelModule are public; the enrich/compute/build helpers are module-internal.
import { safeFetch } from "../lib/http.js";
import { runDnsModule } from "./dns-scan.js";
import { dnsQuery } from "./dns.js";
import { DMARC_INTEL_STATUS, isDmarcScoreNeutral } from "./dmarc-canonical-consumers.js";
import { buildDkimDetail, isEmailProbeUnobserved, parseDmarcRecord, parseSpfRecord } from "./email-analysis.js";
import { runEmailModule } from "./email-scan.js";
import { resolveRemediation } from "./remediation-registry.js";
import { computeScore } from "./scoring.js";
import { classifyServiceability, mayGroundAbsence } from "../lib/serviceability.js";
import { classifyFetchObservation, FETCH_OBSERVATION_STATES } from "../lib/fetch-observation.js";

/**
 * Enrich existing SPF result (from runEmailModule) with status/score/issue.
 * Ported from spf.py analyze_spf() — status enum: PASS / SOFTFAIL / FAIL / PARTIAL / MISSING.
 */
export function enrichSpf(emailMod) {
  const spf    = emailMod?.spf || {};
  const record = spf.record || null;
  const detail = emailMod?.spf_detail || parseSpfRecord(record, spf.record_count ?? (record ? 1 : 0));
  if (!spf.present || !record) {
    // A1: a failed/unexecuted SPF probe (unavailable / not_yet_assessed) is NOT a
    // missing record. Status stays MISSING for the (excluded) frontend display, but
    // observation_unavailable gates the missing finding + business impact below.
    const observation_unavailable = isEmailProbeUnobserved(emailMod?.spf_evidence_status);
    return { status: "MISSING", record: null, score: 0, issue: "No SPF record found.", detail, observation_unavailable };
  }
  if (!detail.valid || detail.record_count > 1) {
    return { status: "FAIL", record, score: 5, issue: detail.warnings.join(" "), detail };
  }
  if (detail.all_mechanism === "+all" || detail.all_mechanism === "all") {
    return { status: "FAIL", record, score: 5, issue: "SPF uses +all, which authorises any sender.", detail };
  }
  if (detail.all_mechanism === "-all") {
    return { status: "PASS", record, score: 20, issue: detail.lookup_count_estimate > 10 ? detail.warnings.join(" ") : "", detail };
  }
  if (detail.all_mechanism === "~all") {
    return { status: "SOFTFAIL", record, score: 15, issue: "SPF uses ~all (softfail), which is less restrictive than -all.", detail };
  }
  return { status: "PARTIAL", record, score: 10, issue: "SPF is present but does not use a strict -all policy.", detail };
}

/**
 * Enrich existing DMARC result (from runEmailModule) with full policy breakdown.
 * Ported from dmarc.py DMARCScanner.scan() — parses pct, sp, rua, ruf from raw record.
 * Status enum: FULLY_PROTECTED / PARTIAL_PROTECTED / REPORTING_ONLY / MISSING / ERROR
 */
function enrichDmarc(emailMod) {
  const dmarc     = emailMod?.dmarc || {};
  const rawRecord = dmarc.record || null;

  // Canonical DMARC state (ADR-003). `dmarc_state` is NON-ENUMERABLE on the live
  // email module result — read it directly from the source object (a spread/JSON
  // copy drops it, silently reverting to the legacy raw path below and mislabelling
  // an UNAVAILABLE lookup as MISSING). Status/risk are derived from the canonical
  // enforcement_level, never from raw p/pct/valid (ADR-003 binding rule). When
  // dmarc_state is absent (pre-ADR reports / R2 reconstruction) the legacy raw
  // derivation runs unchanged, so historical scans are never rewritten.
  const dmarcState = emailMod?.dmarc_state;
  const level = dmarcState?.enforcement_level ?? null;
  if (level !== null) {
    const parsed = emailMod?.dmarc_detail || parseDmarcRecord(rawRecord, dmarc.record_count ?? (rawRecord ? 1 : 0));
    const status = DMARC_INTEL_STATUS[level] ?? "ERROR";        // unknown level → fail closed
    const unavailable = isDmarcScoreNeutral(level);             // not_observed / not_yet_assessed
    const RISK = {
      reject_enforced: "LOW", quarantine_enforced: "MEDIUM", partial_reject: "MEDIUM",
      partial_quarantine: "HIGH", monitoring: "HIGH", invalid_record: "HIGH",
      no_record: "CRITICAL", not_observed: "UNKNOWN", not_yet_assessed: "UNKNOWN",
    };
    const MSG = {
      reject_enforced: "Full DMARC protection active (p=reject).",
      quarantine_enforced: "Quarantine policy is enforced at 100%. Move to p=reject for full protection.",
      partial_reject: "DMARC reject is not applied to all mail (pct<100 or an unprotected subdomain policy).",
      partial_quarantine: "DMARC quarantine is not applied to all mail (pct<100 or an unprotected subdomain policy).",
      monitoring: "DMARC is in reporting-only mode (p=none). Enforcement is not active.",
      invalid_record: parsed.warnings.join(" ") || "The DMARC record is invalid.",
      no_record: "DMARC record not found. Email spoofing risk is high.",
      not_observed: "DMARC could not be observed this scan — the DNS lookup did not complete. This is not a finding about your protection.",
      not_yet_assessed: "DMARC has not been assessed yet.",
    };
    return {
      status,
      policy: parsed.policy || null,
      subdomain_policy: parsed.subdomain_policy || null,
      pct: typeof parsed.percentage === "number" ? parsed.percentage : 0,
      rua: parsed.rua.join(", ") || null,
      ruf: parsed.ruf.join(", ") || null,
      risk_level: RISK[level] ?? "HIGH",
      message: MSG[level] ?? "",
      record: rawRecord,
      detail: parsed,
      enforcement_level: level,
      evidence_status: dmarcState?.evidence_status ?? null,
      // Backend-truth gate: a not_observed / not_yet_assessed DMARC never counts as
      // a "missing DMARC" finding or business impact (ADR-003 §11). The honest
      // display status/label is deferred to the excluded frontend PR.
      observation_unavailable: unavailable,
    };
  }

  if (!dmarc.present || !rawRecord) {
    const detail = emailMod?.dmarc_detail || parseDmarcRecord(null, 0);
    return {
      status: "MISSING", policy: null, subdomain_policy: null, pct: 0,
      rua: null, ruf: null, risk_level: "CRITICAL",
      message: "DMARC record not found. Email spoofing risk is high.",
      record: null, detail,
    };
  }

  const parsed = emailMod?.dmarc_detail || parseDmarcRecord(rawRecord, dmarc.record_count ?? 1);
  const policy = parsed.policy || "none";
  const sp     = parsed.subdomain_policy || null;
  const pct    = parsed.percentage;
  const rua    = parsed.rua.join(", ") || null;
  const ruf    = parsed.ruf.join(", ") || null;

  let status, riskLevel, message;
  if (!parsed.valid) {
    status = "ERROR"; riskLevel = "HIGH";
    message = parsed.warnings.join(" ") || "The DMARC record is invalid.";
  } else if (policy === "reject" && pct === 100) {
    status = "FULLY_PROTECTED";   riskLevel = "LOW";
    message = "Full DMARC protection active (p=reject, pct=100).";
  } else if (policy === "reject" && pct < 100) {
    status = "PARTIAL_PROTECTED"; riskLevel = "MEDIUM";
    message = `DMARC protection is partial (p=reject, pct=${pct}).`;
  } else if (policy === "quarantine" && pct === 100) {
    status = "PARTIAL_PROTECTED"; riskLevel = "MEDIUM";
    message = "Quarantine policy is active (pct=100). Move to p=reject for full protection.";
  } else if (policy === "quarantine" && pct < 100) {
    status = "PARTIAL_PROTECTED"; riskLevel = "HIGH";
    message = `Quarantine policy is partial (pct=${pct}).`;
  } else if (policy === "none") {
    status = "REPORTING_ONLY";    riskLevel = "HIGH";
    message = "DMARC is in reporting-only mode (p=none). Enforcement is not active.";
  } else {
    status = "ERROR";             riskLevel = "HIGH";
    message = `Unknown or unparseable DMARC policy: '${policy}'.`;
  }

  return { status, policy, subdomain_policy: sp, pct, rua, ruf, risk_level: riskLevel, message, record: rawRecord, detail: parsed };
}

/**
 * Enrich existing DKIM result (from runEmailModule).
 * Status: VERIFIED (selector found) / NOT_VERIFIED (no selector found).
 */
export function enrichDkim(emailMod) {
  const dkim = emailMod?.dkim || {};
  const detail = emailMod?.dkim_detail || buildDkimDetail(dkim);
  if (dkim.present && dkim.selector) {
    return { status: "VERIFIED", selector: dkim.selector, issue: "", detail, observation_unavailable: false };
  }
  // A1: DKIM is "NOT_VERIFIED" only when we actually probed and found no selector.
  // If every selector probe failed (unavailable) or none ran (not_yet_assessed) this
  // is unobserved, not a not-verified conclusion — observation_unavailable gates the
  // not-found finding + business impact below.
  const observation_unavailable = isEmailProbeUnobserved(emailMod?.dkim_evidence_status);
  return { status: "NOT_VERIFIED", selector: null, issue: detail.explanation, detail, observation_unavailable };
}

/**
 * Fetch and parse MTA-STS policy.
 * Ported from mta_sts.py analyze_mta_sts() — HTTP GET, not DNS.
 */
export function mtaStsAdmission(mtaSts = {}) {
  const state = mtaSts.observation_state || "not_observed";
  return Object.freeze({
    state,
    missing_finding: state === "definitive_absent",
    score_admitted: state === "present",
    remediation_admitted: state === "definitive_absent",
  });
}

export async function fetchMtaSts(domain, opts = {}) {
  const accounting = opts.accounting || null;
  const result = {
    enabled: false, policy_version: null, policy_mode: null, mx_patterns: [], max_age: null, errors: [],
    observation_state: "not_observed", status_code: null, reason: null, serviceability: null,
  };
  const fetcher = opts.fetcher || safeFetch;
  try {
    const res = await fetcher(`https://mta-sts.${domain}/.well-known/mta-sts.txt`, {
      signal: AbortSignal.timeout(10_000),
      accounting,
    });
    const observation = classifyFetchObservation({ response: res });
    const serviceability = classifyServiceability(observation);
    result.status_code = observation.origin_status;
    result.serviceability = serviceability;
    if (!res) {
      result.observation_state = "unavailable";
      result.reason = "transport_error";
      result.errors.push("MTA-STS policy fetch was unavailable.");
      return result;
    }
    if (res.status === 404 && mayGroundAbsence(serviceability)) {
      result.observation_state = "definitive_absent";
      result.reason = "well_known_404";
      return result;
    }
    if (res.status >= 500 || observation.state === FETCH_OBSERVATION_STATES.TRANSPORT_UNAVAILABLE) {
      result.observation_state = "unavailable";
      result.reason = res.status >= 500 ? "http_5xx" : "transport_error";
      result.errors.push("MTA-STS policy could not be verified during this scan.");
      return result;
    }
    if (res.status !== 200 || !mayGroundAbsence(serviceability)) {
      result.observation_state = "unavailable";
      result.reason = "transport_error";
      result.errors.push("MTA-STS policy could not be verified during this scan.");
      return result;
    }
    result.enabled = true;
    result.observation_state = "present";
    const text = await res.text();
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim();
      if (line.startsWith("version:")) {
        result.policy_version = line.split(":", 2)[1]?.trim() || null;
      } else if (line.startsWith("mode:")) {
        result.policy_mode = line.split(":", 2)[1]?.trim() || null;
      } else if (line.startsWith("mx:")) {
        const mx = line.split(":", 2)[1]?.trim();
        if (mx) result.mx_patterns.push(mx);
      } else if (line.startsWith("max_age:")) {
        const n = parseInt((line.split(":", 2)[1] || "").trim(), 10);
        if (!isNaN(n)) result.max_age = n;
      }
    }
  } catch (e) {
    result.observation_state = "unavailable";
    result.reason = e?.name === "TimeoutError" || e?.name === "AbortError" ? "timeout" : "transport_error";
    result.errors.push("MTA-STS policy could not be verified during this scan.");
  }
  return result;
}

/**
 * Check TLS-RPT DNS record.
 * Ported from tls_rpt.py analyze_tls_rpt() — queries _smtp._tls.<domain> TXT.
 */
async function checkTlsRpt(domain, opts = {}) {
  const accounting = opts.accounting || null;
  const cache = opts.cache || null;
  const recordName = `_smtp._tls.${domain}`;
  const result = { enabled: false, record_name: recordName, record: null, reporting_uris: [], errors: [] };
  try {
    const res     = await dnsQuery(recordName, "TXT", { accounting, cache });
    const answers = res?.Answer || [];
    for (const ans of answers) {
      const txt = ans.data || "";
      if (txt.toLowerCase().startsWith("v=tlsrptv1")) {
        result.enabled = true;
        result.record  = txt;
        for (const part of txt.split(";")) {
          const p = part.trim();
          if (p.toLowerCase().startsWith("rua=")) {
            result.reporting_uris = p.slice(p.indexOf("=") + 1)
              .split(",").map(u => u.trim()).filter(Boolean);
          }
        }
        return result;
      }
    }
    if (answers.length > 0) result.errors.push("No valid TLS-RPT record found (missing v=TLSRPTv1).");
    else                    result.errors.push("No TXT record found at " + recordName + ".");
  } catch (e) {
    result.errors.push(e?.message ?? "TLS-RPT DNS query failed");
  }
  return result;
}

/**
 * STARTTLS — cannot open raw TCP sockets from Cloudflare Worker runtime.
 * Returns structured stub preserving starttls.py data model with MX records
 * from the existing DNS module so the data is still useful.
 */
function buildStarttlsStub(dnsModule) {
  const mxRecords = (dnsModule?.mx_records || []).map(r => {
    const raw    = (r.value || "").trim();
    const parts  = raw.split(/\s+/);
    const host   = parts[parts.length - 1].replace(/\.$/, "");
    const prio   = parts.length >= 2 ? parseInt(parts[0], 10) : 0;
    return { priority: isNaN(prio) ? 0 : prio, host };
  });
  return {
    method:                   "not_supported_in_worker_runtime",
    warning:                  "Raw SMTP connections to port 25 cannot be established from Cloudflare Worker runtime. STARTTLS support cannot be tested directly. Use a dedicated server-side probe for full STARTTLS validation.",
    mx_records:               mxRecords,
    starttls_supported_hosts: null,
    starttls_failed_hosts:    null,
    score:                    null,
  };
}

/**
 * Compute weighted email security score.
 * Ported from scoring.py EmailScoringEngine v1.1.
 * Weights: DMARC=50, SPF=20, DKIM=20, MTA-STS=5, TLS-RPT=5 (exact match).
 * DMARC interpolation bands preserved exactly (reject 75-100%, quarantine 37.5-62.5%).
 */
function computeEmailScore(spf, dmarc, dkim, mtaSts, tlsRpt) {
  const W = { spf: 20, dkim: 20, dmarc: 50, mta_sts: 5, tls_rpt: 5 };

  // SPF — mirrors _score_spf()
  let spfScore = 0;
  switch (spf.status) {
    case "PASS":     spfScore = W.spf; break;
    case "SOFTFAIL": spfScore = Math.round(W.spf * 0.75); break;
    case "PARTIAL":  spfScore = Math.round(W.spf * 0.50); break;
    case "FAIL":     spfScore = Math.round(W.spf * 0.25); break;
    // MISSING → 0
  }

  // DKIM — mirrors _score_dkim()
  let dkimScore = 0;
  if (dkim.status === "VERIFIED")     dkimScore = W.dkim;
  else if (dkim.status === "NOT_VERIFIED") dkimScore = Math.round(W.dkim * 0.5);

  // DMARC — mirrors _score_dmarc() with exact fraction bands
  let dmarcScore = 0;
  const dPolicy = dmarc.policy || "none";
  const dPct    = typeof dmarc.pct === "number" ? Math.max(0, Math.min(100, dmarc.pct)) : 100;
  if (dmarc.status === "MISSING") {
    dmarcScore = 0;
  } else if (dmarc.status === "ERROR") {
    dmarcScore = Math.round(W.dmarc * 0.125);                            // 6
  } else if (dPolicy === "reject") {
    // 75%→100% of weight interpolated by pct  (38 .. 50)
    dmarcScore = Math.round(W.dmarc * 0.75 + W.dmarc * 0.25 * (dPct / 100));
  } else if (dPolicy === "quarantine") {
    // 37.5%→62.5% of weight interpolated by pct  (19 .. 31)
    dmarcScore = Math.round(W.dmarc * 0.375 + W.dmarc * 0.25 * (dPct / 100));
  } else {
    // none or unknown — fixed at 25%  (13)
    dmarcScore = Math.round(W.dmarc * 0.25);
  }

  // MTA-STS — mirrors _score_mta_sts()
  let mtaScore = 0;
  if (mtaSts.observation_state === "present" && mtaSts.policy_mode === "enforce") mtaScore = W.mta_sts;
  else if (mtaSts.observation_state === "present") mtaScore = Math.round(W.mta_sts * 0.6);

  // TLS-RPT — mirrors _score_tls_rpt()
  const tlsRptScore = tlsRpt.enabled ? W.tls_rpt : 0;

  const total = spfScore + dkimScore + dmarcScore + mtaScore + tlsRptScore;

  let status;
  if (total >= 90)      status = "EXCELLENT";
  else if (total >= 70) status = "GOOD";
  else if (total >= 50) status = "FAIR";
  else if (total >= 30) status = "POOR";
  else                  status = "CRITICAL";

  return { total, spf: spfScore, dkim: dkimScore, dmarc: dmarcScore, mta_sts: mtaScore, tls_rpt: tlsRptScore, status };
}

/**
 * Convert technical results to business impact statements.
 * Ported from business_impact.py BusinessImpactEngine.generate().
 */
export function buildEmailBusinessImpacts(spf, dmarc, dkim, mtaSts, tlsRpt) {
  const impacts = [];

  // DMARC — an unobservable lookup (not_observed) is not a "DMARC Missing" impact.
  if (dmarc.status === "MISSING" && !dmarc.observation_unavailable) {
    impacts.push({
      technical:        "DMARC Missing",
      risk_level:       "CRITICAL",
      business_impact:  "Attackers may impersonate your company and send fraudulent emails to customers, suppliers, or staff.",
      recommendation:   "Add a DMARC record and move towards p=reject after validating all legitimate email sources.",
    });
  } else if (dmarc.status === "REPORTING_ONLY") {
    impacts.push({
      technical:        "DMARC Reporting Only",
      risk_level:       "HIGH",
      business_impact:  "Your domain is collecting DMARC reports but is not actively blocking spoofed emails.",
      recommendation:   "Move from p=none to p=quarantine, then to p=reject once email flows are fully validated.",
    });
  } else if (dmarc.status === "PARTIAL_PROTECTED") {
    impacts.push({
      technical:        "DMARC Partial Protection",
      risk_level:       dmarc.risk_level || "MEDIUM",
      business_impact:  "Some spoofed emails may still reach recipients because DMARC is not fully enforced.",
      recommendation:   "Increase DMARC enforcement to p=reject with pct=100 where safe to do so.",
    });
  }

  // DKIM
  if (dkim.status === "NOT_VERIFIED" && !dkim.observation_unavailable) {
    impacts.push({
      technical:        "DKIM Not Verified",
      risk_level:       "INFO",
      business_impact:  "DKIM could not be confirmed from common selectors. A custom selector may be in use, so this is not evidence that signing is absent.",
      recommendation:   "Confirm the active selector with the email provider and verify that DNS record directly.",
    });
  }

  // SPF
  if (spf.status === "MISSING" && !spf.observation_unavailable) {
    impacts.push({
      technical:        "SPF Missing",
      risk_level:       "HIGH",
      business_impact:  "Mail servers cannot verify which systems are authorised to send email on behalf of your domain, enabling impersonation.",
      recommendation:   "Publish an SPF TXT record listing all authorised sending services and end with -all.",
    });
  } else if (spf.status === "SOFTFAIL") {
    impacts.push({
      technical:        "SPF SoftFail",
      risk_level:       "MEDIUM",
      business_impact:  "Your SPF record uses softfail (~all) which is not fully strict, reducing protection against spoofed email.",
      recommendation:   "Consider changing ~all to -all after confirming all legitimate email sources are listed.",
    });
  } else if (spf.status === "FAIL") {
    impacts.push({
      technical:        "SPF Permissive Policy (+all)",
      risk_level:       "HIGH",
      business_impact:  "Your SPF policy allows any mail server to send email using your domain, providing no meaningful protection.",
      recommendation:   "Remove +all and replace with -all after enumerating all authorised sending IP ranges.",
    });
  }

  // MTA-STS
  if (mtaSts.observation_state === "definitive_absent") {
    impacts.push({
      technical:        "MTA-STS Missing",
      risk_level:       "LOW",
      business_impact:  "Inbound email transport encryption is not strictly enforced, reducing resilience against TLS downgrade attacks.",
      recommendation:   "Enable MTA-STS after SPF, DKIM, and DMARC are fully deployed and validated.",
    });
  }

  // TLS-RPT
  if (!tlsRpt.enabled) {
    impacts.push({
      technical:        "TLS-RPT Missing",
      risk_level:       "LOW",
      business_impact:  "You will not receive automated reports about email TLS delivery failures or configuration problems.",
      recommendation:   "Add a TLS-RPT DNS TXT record so email delivery security issues are monitored automatically.",
    });
  }

  return impacts;
}

/**
 * Build CyberMeters findings for the email intelligence module.
 * Only the 7 finding types specified in the sprint.  score_impact: 0 on all —
 * deductions are already handled by computeScore (modules.email_security path).
 * These findings live in modules.email_security_intelligence.findings only,
 * NOT in the main findings array, to avoid double-counting.
 */
export function buildEmailIntelFindings(spf, dmarc, dkim, mtaSts, tlsRpt) {
  const findings = [];

  // A not_observed / not_yet_assessed DMARC surfaces status MISSING for display,
  // but is NOT a missing-record finding — it never reaches Cyber MOT as an email
  // issue (ADR-003 §11). observation_unavailable is set only on the canonical path.
  if (dmarc.status === "MISSING" && !dmarc.observation_unavailable) {
    findings.push({
      id:             "email_intel_dmarc_missing",
      module:         "email_security_intelligence",
      severity:       "high",
      title:          "DMARC record is missing",
      description:    "No DMARC record was found at _dmarc.<domain>. Receivers therefore have no domain-owner policy for handling messages that fail DMARC alignment.",
      recommendation: "Publish a DMARC TXT record. Start with p=none to collect aggregate reports (rua=), then graduate to p=quarantine and p=reject.",
      score_impact:   0,
    });
  } else if (dmarc.status === "REPORTING_ONLY") {
    findings.push({
      id:             "email_intel_dmarc_reporting_only",
      module:         "email_security_intelligence",
      severity:       "medium",
      title:          "DMARC is in monitoring mode only (p=none)",
      description:    "A DMARC record exists with p=none. Receivers are not instructed to quarantine or reject messages that fail DMARC alignment.",
      recommendation: "Review DMARC aggregate reports and migrate to p=quarantine, then p=reject once all email sources are validated.",
      score_impact:   0,
    });
  }

  if (spf.status === "MISSING" && !spf.observation_unavailable) {
    findings.push({
      id:             "email_intel_spf_missing",
      module:         "email_security_intelligence",
      severity:       "high",
      title:          "SPF record is missing",
      description:    "No SPF TXT record was found. Receiving mail servers cannot verify which IP addresses are authorised to send email for this domain.",
      recommendation: "Publish an SPF TXT record listing all services that send email for this domain. End with -all to reject unauthorised senders.",
      score_impact:   0,
    });
  } else if (spf.status === "FAIL") {
    findings.push({
      id:             "email_intel_spf_permissive",
      module:         "email_security_intelligence",
      severity:       "high",
      title:          "SPF record uses +all (permits any sender)",
      description:    `The SPF record "${spf.record}" uses +all, meaning any IP address in the world is authorised to send email on behalf of this domain.`,
      recommendation: "Remove +all and replace with -all after listing all legitimate sending sources explicitly.",
      score_impact:   0,
    });
  }

  if (dkim.status === "NOT_VERIFIED" && !dkim.observation_unavailable) {
    findings.push({
      id:                "email_intel_dkim_not_found",
      module:            "email_security_intelligence",
      severity:          "info",
      // Sprint 9D: common-selector heuristic failure — not confirmed absence of DKIM
      confidence:         60,
      validation_quality: "partial",
      title:             "DKIM Could Not Be Verified Using Common Selectors",
      description:       "DKIM could not be verified using common selector names. The domain may use a custom selector, so this is not confirmation that DKIM is absent.",
      recommendation:    "Confirm the active DKIM selector with the email provider and verify that selector directly.",
      score_impact:      0,
    });
  }

  if (mtaSts.observation_state === "definitive_absent") {
    findings.push({
      id:             "email_intel_mta_sts_missing",
      module:         "email_security_intelligence",
      severity:       "low",
      title:          "MTA-STS policy not published",
      description:    "No MTA-STS policy was found at https://mta-sts.<domain>/.well-known/mta-sts.txt. MTA-STS instructs sending servers to require TLS for delivery to this domain.",
      recommendation: "Publish an MTA-STS policy file and a supporting _mta-sts.<domain> DNS TXT record once SPF, DKIM, and DMARC are fully deployed.",
      score_impact:   0,
    });
  }

  if (!tlsRpt.enabled) {
    findings.push({
      id:             "email_intel_tls_rpt_missing",
      module:         "email_security_intelligence",
      severity:       "low",
      title:          "TLS-RPT reporting not configured",
      description:    "No TLS-RPT record was found at _smtp._tls.<domain>. Without TLS-RPT you will not receive automated reports about email TLS delivery failures.",
      recommendation: "Add a TLS-RPT TXT record at _smtp._tls.<domain>: v=TLSRPTv1; rua=mailto:<address>",
      score_impact:   0,
    });
  }

  // Canonicalise the recommended action through the shared registry so email
  // advice is identical across every surface (no SPF ~all/-all or DMARC policy
  // conflicts). The module-specific title/description are preserved; only the
  // remediation action is unified.
  for (const f of findings) {
    const r = resolveRemediation({ finding_type: f.id });
    if (r.status === "resolved") f.recommendation = r.recommended_action;
  }

  return findings;
}

/**
 * Main Email Security Intelligence orchestrator.
 * Ported from intelligence.py build_email_security_intelligence().
 *
 * Reuses runEmailModule results for SPF/DMARC/DKIM to avoid redundant DNS queries.
 * Adds MTA-STS (HTTP), TLS-RPT (DNS), STARTTLS stub, weighted score, business impacts.
 *
 * @param {string} domain    — domain under scan
 * @param {object} emailMod  — modules.email_security (from runEmailModule)
 * @param {object} dnsModule — modules.dns (from runDnsModule — supplies MX for STARTTLS stub)
 */
export async function runEmailIntelModule(domain, emailMod, dnsModule, opts = {}) {
  const accounting = opts.accounting || null;
  const cache = opts.cache || null;
  // Step 1: Enrich existing results — no extra DNS calls needed
  const spf   = enrichSpf(emailMod);
  const dmarc = enrichDmarc(emailMod);
  const dkim  = enrichDkim(emailMod);

  // Step 2: MTA-STS + TLS-RPT in parallel (both are fast, independent)
  const [mtaStsSettled, tlsRptSettled] = await Promise.allSettled([
    fetchMtaSts(domain, { accounting }),
    checkTlsRpt(domain, { accounting, cache }),
  ]);
  const mtaSts = mtaStsSettled.status === "fulfilled"
    ? mtaStsSettled.value
    : { enabled: false, policy_mode: null, mx_patterns: [], max_age: null, errors: ["MTA-STS fetch failed"] };
  const tlsRpt = tlsRptSettled.status === "fulfilled"
    ? tlsRptSettled.value
    : { enabled: false, record_name: `_smtp._tls.${domain}`, record: null, reporting_uris: [], errors: ["TLS-RPT lookup failed"] };

  // Step 3: STARTTLS stub (raw TCP port 25 not available in Worker)
  const starttls = buildStarttlsStub(dnsModule);

  // Step 4: Weighted email security score (scoring.py weights: DMARC=50,SPF=20,DKIM=20,MTA-STS=5,TLS-RPT=5)
  const scoreResult = computeEmailScore(spf, dmarc, dkim, mtaSts, tlsRpt);

  // Step 5: Business impact statements (business_impact.py)
  const businessImpacts = buildEmailBusinessImpacts(spf, dmarc, dkim, mtaSts, tlsRpt);

  // Step 6: Strengths (intelligence.py pattern)
  const strengths = [];
  if (spf.status === "PASS")               strengths.push("SPF record published with -all enforcement.");
  else if (spf.status === "SOFTFAIL")      strengths.push("SPF record is present (softfail mode).");
  if (dkim.status === "VERIFIED")          strengths.push(`DKIM signing configured (selector: ${dkim.selector}).`);
  if (dmarc.status === "FULLY_PROTECTED")  strengths.push("DMARC fully enforced (p=reject, pct=100).");
  else if (dmarc.status === "PARTIAL_PROTECTED") strengths.push(`DMARC enforcement partially active (${dmarc.policy}, pct=${dmarc.pct}).`);
  if (mtaSts.enabled && mtaSts.policy_mode === "enforce") strengths.push("MTA-STS enabled in enforce mode — inbound TLS delivery is required.");
  else if (mtaSts.enabled)                 strengths.push("MTA-STS policy is published.");
  if (tlsRpt.enabled)                      strengths.push("TLS-RPT configured — email TLS delivery problems will be reported.");
  if (dmarc.rua)                           strengths.push("DMARC aggregate reporting (rua) is configured.");

  // Step 7: Rating and business risk level
  const total = scoreResult.total;
  let rating, businessRisk;
  if (total >= 90)      { rating = "Excellent"; businessRisk = "Low"; }
  else if (total >= 70) { rating = "Good";      businessRisk = "Low"; }
  else if (total >= 50) { rating = "Fair";      businessRisk = "Moderate"; }
  else if (total >= 30) { rating = "Poor";      businessRisk = "High"; }
  else                  { rating = "Critical";  businessRisk = "Critical"; }

  // Step 8: Module-scoped findings (score_impact: 0 — not added to main findings array)
  const findings = buildEmailIntelFindings(spf, dmarc, dkim, mtaSts, tlsRpt);

  return {
    domain,
    spf,
    dkim,
    dmarc,
    mta_sts:              mtaSts,
    tls_rpt:              tlsRpt,
    starttls,
    email_security_score: scoreResult.total,
    email_score_breakdown: {
      spf:      scoreResult.spf,
      dkim:     scoreResult.dkim,
      dmarc:    scoreResult.dmarc,
      mta_sts:  scoreResult.mta_sts,
      tls_rpt:  scoreResult.tls_rpt,
      status:   scoreResult.status,
    },
    rating,
    business_email_risk:  businessRisk,
    strengths,
    findings,
    business_impacts:     businessImpacts,
  };
}
