// ── DMARC-RUA ↔ resolved-SPF corroboration (PR-B) ─────────────────────────────
//
// Cross-checks the OBSERVED outcome in a DMARC aggregate (RUA) report against the
// statically-resolved PASS-authorisation set from spf-resolver.js (PR-A). The RUA
// report's OWN SPF result is the AUTHORITATIVE observed outcome — CyberMeters does
// NOT derive an SPF-fail verdict from local set membership. Local membership only
// decides whether an ALREADY-OBSERVED failure came from a source outside the
// resolved authorised set (a candidate unauthorised sender) versus one inside it
// (an alignment/config issue, NOT an authorisation problem).
//
// SAFETY GATES (all must hold to raise the firm "unauthorised source" finding):
//   1. the RUA record carries a source_ip;
//   2. it records SPF FAILURE (raw auth result === "fail") for the relevant domain;
//   3. the latest static resolution is COMPLETE and successful;
//   4. the source IP is NOT contained in any resolved authorised CIDR;
//   5. tenant/domain attribution (spf_domain / header_from) is unambiguous.
// If resolution is partial/unavailable → keep the failure evidence but use LIMITED
// wording ("complete SPF-authorisation comparison was unavailable"), never claiming
// a complete comparison. For ~all/?all/+all policies, "unauthorised" language is
// used cautiously (softfail/neutral ≠ hard reject). A provider IP with no DNS/DMARC
// evidence is never given a verdict — only sources that actually appear in a RUA
// report with a fail result are evaluated (external-scope honesty).
//
// Pure + deterministic: no DNS, no DB, no time. The caller supplies the RUA source
// rows, the resolved-authorisation snapshot, the root SPF policy strength, and a
// timestamp. Emission (canonical alert + remediation + dedupe) is the caller's job.

import { ipContainedInAnyCidr } from "./spf-resolver.js";
import { emitManagedAlert } from "./managed-alerts.js";
import { resolveRemediation } from "./remediation-registry.js";

export const SPF_CORROBORATION_TIER = Object.freeze({
  UNAUTHORISED_CONFIRMED: "unauthorised_confirmed",     // complete + not-contained + enforcing (-all) policy
  UNAUTHORISED_SOFT_POLICY: "unauthorised_soft_policy", // complete + not-contained + ~all/?all/+all policy
  FAIL_COMPARISON_UNAVAILABLE: "fail_comparison_unavailable", // failure observed, resolution not complete
});

export const SPF_UNAUTHORISED_REMEDIATION_ID = "email.spf.unauthorised_source";

// Registrable-domain-ish suffix match: the RUA record is "ours" when its
// spf_domain / header_from equals the monitored domain or a subdomain of it. A
// different registrable domain is ambiguous and never attributed to this tenant.
function attributedToDomain(recordDomain, monitoredDomain) {
  const rd = String(recordDomain || "").trim().toLowerCase().replace(/\.$/, "");
  const md = String(monitoredDomain || "").trim().toLowerCase().replace(/\.$/, "");
  if (!rd || !md) return false;
  return rd === md || rd.endsWith(`.${md}`);
}

const isComplete = (auth) => auth && auth.resolution_status === "complete" && Array.isArray(auth.resolved_pass_authorisations);

/**
 * evaluateSpfAuthorizationCorroboration
 *
 * @param {object} opts
 * @param {string} opts.domain                the monitored domain
 * @param {Array}  opts.sources              RUA source rows: { source_ip, spf_result,
 *                                            spf_domain, header_from, message_count }
 * @param {object} opts.resolvedAuthorization spf-resolver snapshot (PR-A)
 * @param {string} opts.spfPolicy            policy_strength: strong|soft|neutral|weak|unknown
 * @param {string} opts.nowIso               injected timestamp
 * @returns {{ findings: Array, comparison_performed: boolean }}
 */
export function evaluateSpfAuthorizationCorroboration({ domain, sources = [], resolvedAuthorization = null, spfPolicy = "unknown", nowIso = null }) {
  const complete = isComplete(resolvedAuthorization);
  const cidrs = complete ? resolvedAuthorization.resolved_pass_authorisations : [];
  const findings = [];
  const seenIps = new Set();

  for (const src of sources) {
    const sourceIp = String(src?.source_ip || "").trim();
    if (!sourceIp) continue;                                            // gate 1: no IP → no verdict
    const spfResult = String(src?.spf_result || "").trim().toLowerCase();
    if (spfResult !== "fail") continue;                                 // gate 2: only an OBSERVED hard failure
    const recordDomain = src.spf_domain || src.header_from;
    if (!attributedToDomain(recordDomain, domain)) continue;            // gate 5: unambiguous attribution
    if (seenIps.has(sourceIp)) continue;                                // one finding per source IP
    seenIps.add(sourceIp);

    const dedupeKey = `spf_unauthorised:${String(domain).toLowerCase()}:${sourceIp}`;
    const baseEvidence = {
      source_ip: sourceIp,
      observed_spf_result: "fail",
      spf_domain: src.spf_domain || null,
      header_from: src.header_from || null,
      message_count: Number(src.message_count) || null,
      resolution_status: resolvedAuthorization?.resolution_status ?? null,
      observed_at: nowIso,
    };

    // gate 3: resolution must be COMPLETE to make an authorisation claim.
    if (!complete) {
      findings.push({
        tier: SPF_CORROBORATION_TIER.FAIL_COMPARISON_UNAVAILABLE,
        source_ip: sourceIp,
        severity: "low",
        dedupe_key: dedupeKey,
        remediation_id: SPF_UNAUTHORISED_REMEDIATION_ID,
        title: `A sending source reported SPF failure for ${domain}`,
        message: `A sending source (${sourceIp}) reported SPF failure for ${domain}; a complete SPF-authorisation comparison was unavailable, so CyberMeters cannot confirm whether it is outside your authorised senders.`,
        evidence: baseEvidence,
      });
      continue;
    }

    // gate 4: containment. An IP INSIDE the resolved set is authorised — a failure
    // there is an alignment/config issue, NOT an authorisation problem. No finding.
    if (ipContainedInAnyCidr(sourceIp, cidrs)) continue;

    // Not contained + complete resolution → a candidate unauthorised source. The
    // firmness of the language depends on the enforcing policy (softfail/neutral ≠
    // hard reject), so ~all/?all/+all get the cautious tier.
    const enforcing = spfPolicy === "strong"; // -all
    if (enforcing) {
      findings.push({
        tier: SPF_CORROBORATION_TIER.UNAUTHORISED_CONFIRMED,
        source_ip: sourceIp,
        severity: "medium",
        dedupe_key: dedupeKey,
        remediation_id: SPF_UNAUTHORISED_REMEDIATION_ID,
        title: `New sending source not authorised by your SPF record: ${sourceIp}`,
        message: `A sending source (${sourceIp}) reported SPF failure for ${domain} and is not contained in any range authorised by your resolved SPF record (policy -all). Confirm whether this sender is legitimate; if so, add it to your SPF authorisation, otherwise treat it as an impersonation attempt.`,
        evidence: { ...baseEvidence, spf_policy: spfPolicy, contained_in_authorised_set: false },
      });
    } else {
      findings.push({
        tier: SPF_CORROBORATION_TIER.UNAUTHORISED_SOFT_POLICY,
        source_ip: sourceIp,
        severity: "low",
        dedupe_key: dedupeKey,
        remediation_id: SPF_UNAUTHORISED_REMEDIATION_ID,
        title: `Sending source outside your SPF authorisation: ${sourceIp}`,
        message: `A sending source (${sourceIp}) reported SPF failure for ${domain} and is not contained in any range authorised by your resolved SPF record. Your SPF policy is ${spfPolicy === "soft" ? "softfail (~all)" : spfPolicy === "neutral" ? "neutral (?all)" : "permissive"}, so receiving systems may not reject it. Review this sender and consider moving towards -all once every legitimate sender is authorised.`,
        evidence: { ...baseEvidence, spf_policy: spfPolicy, contained_in_authorised_set: false },
      });
    }
  }

  return { findings, comparison_performed: complete };
}

// ── Wiring: run at scan-finalize, emit through the canonical alert path ────────
// Reads the FRESH resolved-authorisation snapshot from the report being finalised
// (modules.email_security.spf) + the domain's recent RUA fail-sources, evaluates,
// and routes each finding through emitManagedAlert (which owns dedupe / activation
// watermark / entitlement / delivery). Non-fatal by contract — a corroboration
// failure never affects scan completion. Bounded: recent RUA rows only, grouped
// per source IP, one alert per (domain, source_ip) via the dedupe_key.
export async function recordSpfRuaCorroboration(scanId, domainId, domain, modules, env, opts = {}) {
  const spf = modules?.email_security?.spf;
  const spfPolicy = modules?.email_security?.spf_detail?.policy_strength || "unknown";
  // Nothing to corroborate without a resolved snapshot; a temperror/partial/permerror
  // still yields the LIMITED-wording tier, so we proceed as long as spf exists.
  if (!spf) return { emitted: 0 };
  const nowIso = opts.nowIso || new Date().toISOString();

  const wsRows = await env.cybermeters_db
    .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
    .bind(domainId)
    .all()
    .catch(() => ({ results: [] }));
  let emitted = 0;

  for (const { workspace_id } of (wsRows.results || [])) {
    // Recent RUA fail-sources for this domain, grouped per source IP (bounded window).
    const sources = await env.cybermeters_db
      .prepare(
        `SELECT source_ip,
                MAX(spf_result)  AS spf_result,
                MAX(spf_domain)  AS spf_domain,
                MAX(header_from) AS header_from,
                SUM(message_count) AS message_count
           FROM dmarc_aggregate_records
          WHERE workspace_id = ? AND domain = ?
            AND LOWER(spf_result) = 'fail'
            AND source_ip IS NOT NULL AND source_ip != ''
            AND created_at >= datetime('now', '-30 days')
          GROUP BY source_ip
          LIMIT 200`
      )
      .bind(workspace_id, domain)
      .all()
      .catch(() => ({ results: [] }));
    if ((sources.results || []).length === 0) continue;

    const { findings } = evaluateSpfAuthorizationCorroboration({
      domain,
      sources: sources.results,
      resolvedAuthorization: spf,
      spfPolicy,
      nowIso,
    });

    for (const f of findings) {
      const resolved = resolveRemediation({ finding_type: "email_spf_unauthorised_source", domain_key: "email_protection" });
      const res = await emitManagedAlert(env, {
        workspace_id,
        domain_key: "email_protection",
        kind: "email_spf_unauthorised_source",
        severity: f.severity,
        title: f.title,
        message: f.message,
        dedupe_key: f.dedupe_key,
        remediation_id: f.remediation_id || resolved?.remediation_id || null,
        observed_at: nowIso,
        cooldown_entity: f.source_ip,
        metadata: {
          hostname: domain,
          monitored_domain: domain,
          entity_type: "sending_source",
          entity_display: f.source_ip,
          evidence_source: "dmarc_aggregate_report",
          corroboration_tier: f.tier,
          recommended_action: resolved?.recommended_action || null,
          evidence: f.evidence,
        },
      }).catch(() => null);
      if (res?.emitted) emitted += 1;
    }
  }
  return { emitted };
}
