// ── DMARC sender classification engine ──────────────────────────────────────
// Evidence-based, deterministic sender classification for DMARC aggregate
// senders. Manual customer decisions stay in email_sender_sources.classification;
// this engine only writes auto_* evidence fields and provider_map_version.
import { aggregateReportCompleteSql } from "../lib/aggregate-report-ingest.js";

export const PROVIDER_MAP_VERSION = "2026-07-13.1";

// ── The canonical sender vocabulary — ONE authority ─────────────────────────
// This module imports only the cycle-safe complete-ingest read guard, so every
// consumer can still reach it without pulling in routes or the Worker entry:
// the lifecycle engine, dmarc-impact, rua-routing and the classify route.
//
// THE DEFECT THIS EXISTS TO PREVENT (reproduced live, 2026-07-16): the product
// carried TWO vocabularies for senders and pushed both through ONE slot.
//   • OBSERVED  — what CyberMeters saw, from receiver-reported evidence
//                 (authorised … unauthorised). Produced by classifySender().
//   • DISPOSITION — what the CUSTOMER decided (trusted / suspicious / threat /
//                 ignored / unknown). Accepted by the classify route.
// They overlap on only `suspicious` and `unknown`. `effectiveClassification`
// returned the customer's word verbatim and handed it to senderAlertBand(), which
// speaks OBSERVED — so `threat`, `trusted` and `ignored` all fell through to
// band = null. **Marking a sender a THREAT turned its own high alert off.**
//
// The mapping below already existed, correctly, as a PRIVATE copy inside
// dmarc-impact.js, while email-protection-lifecycle.js and rua-routing.js each
// carried their own copy WITHOUT it. Three implementations, two wrong: that is the
// two-taxonomy problem, and it is why aliasing one function would have fixed
// nothing. There is now one mapping, here, and the duplicates import it.
//
// A disposition is a CLAIM in the observed vocabulary, never an alert verdict.
// What it is allowed to do to severity is policy, and policy lives with the bands
// and thresholds in email-protection-lifecycle.js (resolveSenderPolicy).

// AXIS 1 — evidence. The vocabulary classifySender() emits.
export const OBSERVED_SENDER_CLASSIFICATIONS = Object.freeze([
  "authorised", "likely_authorised", "mailing_list", "forwarder",
  "unknown", "misconfigured", "suspicious", "unauthorised",
]);

// AXIS 2 — the customer's decision. The vocabulary the classify route accepts and
// email_sender_sources.classification stores. The UI renders exactly these.
export const CUSTOMER_SENDER_DISPOSITIONS = Object.freeze([
  "trusted", "suspicious", "threat", "ignored", "unknown",
]);

// The ONE mapping: what each disposition CLAIMS in the observed vocabulary.
// `ignored` deliberately claims nothing — it is a request not to be told about a
// sender, not an assertion about what the sender is. Conflating "don't tell me"
// with "it is safe" is how a suppression silently became a clean bill of health.
export const DISPOSITION_ASSERTS = Object.freeze({
  trusted:    "authorised",
  suspicious: "suspicious",
  threat:     "unauthorised",
  ignored:    null,
  unknown:    "unknown",
});

export const isObservedClassification = (c) => OBSERVED_SENDER_CLASSIFICATIONS.includes(String(c || "").toLowerCase());
export const isCustomerDisposition   = (d) => CUSTOMER_SENDER_DISPOSITIONS.includes(String(d || "").toLowerCase());

/**
 * The observed classification a customer decision CLAIMS, or null when it claims
 * nothing (`ignored`) or is not a disposition we recognise.
 */
export function assertedClassification(disposition) {
  const d = String(disposition || "").toLowerCase();
  return isCustomerDisposition(d) ? (DISPOSITION_ASSERTS[d] ?? null) : null;
}

/**
 * resolveEffectiveClassification — the single implementation that replaced three.
 *
 * Returns a value in the OBSERVED vocabulary, ALWAYS, so no caller can hand a
 * customer's word to something that speaks evidence. A customer decision is
 * translated through DISPOSITION_ASSERTS; `ignored` claims nothing, so the
 * observed evidence stands.
 *
 * This answers "what is this sender, all things considered" for reporting and
 * impact maths. It does NOT decide severity — see resolveSenderPolicy, which is
 * where "the customer may escalate but never silently de-escalate" is enforced.
 */
export function resolveEffectiveClassification(row = {}) {
  const observed = String(row.auto_classification || "").toLowerCase();
  const observedSafe = isObservedClassification(observed) ? observed : null;

  if (row.classified_at) {
    const claim = assertedClassification(row.classification);
    if (claim) return claim;
    // `ignored`, or a value we do not recognise: the customer asserted nothing we
    // can express as evidence, so the evidence stands. Fail closed to "unknown"
    // rather than to a clean verdict.
    return observedSafe || "unknown";
  }
  return observedSafe || "unknown";
}

export const SENDER_CLASSIFICATION_THRESHOLDS = {
  MIN_VOLUME: 5,
  MEANINGFUL_VOLUME: 20,
  HIGH_VOLUME: 50,
  ALIGN_HIGH: 0.98,
  ALIGN_LOW: 0.10,
  ALIGN_POOR: 0.50,
  FAIL_HIGH: 0.90,
};

const LIST_PROVIDERS = new Set(["mailchimp", "sendgrid", "constantcontact", "google-groups", "googlegroups"]);
const ESP_PROVIDERS = new Set(["mailchimp", "sendgrid", "constantcontact", "mailgun", "postmark", "amazonses", "shopify", "wix", "squarespace"]);

function ratio(part, total) {
  const n = Number(part || 0);
  const d = Number(total || 0);
  return d > 0 ? n / d : 0;
}

function pct(value) {
  return `${Math.round(Number(value || 0) * 1000) / 10}%`;
}

function providerKnown(provider) {
  const p = String(provider || "unknown").toLowerCase();
  return Boolean(p && p !== "unknown");
}

function claimsProtectedDomain(headerFrom, protectedDomain) {
  const from = String(headerFrom || "").trim().toLowerCase().replace(/\.$/, "");
  const domain = String(protectedDomain || "").trim().toLowerCase().replace(/\.$/, "");
  return Boolean(from && domain && (from === domain || from.endsWith("." + domain)));
}

export function classifySender(evidence = {}) {
  const total = Number(evidence.total_messages || 0);
  const spf = Number(evidence.spf_aligned_messages || 0);
  const dkim = Number(evidence.dkim_aligned_messages || 0);
  const aligned = Number(evidence.aligned_messages || 0);
  const failed = Number(evidence.failed_messages || Math.max(0, total - aligned));
  const provider = String(evidence.provider_guess || "unknown").toLowerCase();
  const providerConfidence = String(evidence.provider_confidence || "low").toLowerCase();
  const knownProvider = providerKnown(provider);
  const spfRate = ratio(spf, total);
  const dkimRate = ratio(dkim, total);
  const alignedRate = ratio(aligned, total);
  const failedRate = ratio(failed, total);
  const claimsDomain = claimsProtectedDomain(evidence.header_from, evidence.protected_domain);
  const t = SENDER_CLASSIFICATION_THRESHOLDS;

  if (total < t.MIN_VOLUME) {
    return {
      classification: "unknown",
      confidence: 0.2,
      reasons: [`Only ${total} message${total === 1 ? "" : "s"} observed; at least ${t.MIN_VOLUME} are needed before classifying this sender.`],
    };
  }

  if (spf === 0 && dkim === 0 && aligned === 0 && failed === 0) {
    return {
      classification: "unknown",
      confidence: 0.2,
      reasons: [`${total} messages were observed, but no SPF or DKIM alignment signal was available.`],
    };
  }

  if (knownProvider && spfRate >= t.ALIGN_HIGH && dkimRate >= t.ALIGN_HIGH) {
    return {
      classification: "authorised",
      confidence: providerConfidence === "medium" || providerConfidence === "high" ? 0.95 : 0.9,
      reasons: [
        `SPF aligned on ${spf} of ${total} messages (${pct(spfRate)}).`,
        `DKIM aligned on ${dkim} of ${total} messages (${pct(dkimRate)}).`,
        `Provider matched ${provider}.`,
      ],
    };
  }

  if (LIST_PROVIDERS.has(provider) && alignedRate >= t.ALIGN_LOW) {
    return {
      classification: "mailing_list",
      confidence: 0.72,
      reasons: [
        `Provider matched ${provider}, a common bulk or list sending platform.`,
        `${aligned} of ${total} messages aligned (${pct(alignedRate)}). Review this sender as a mailing-list or campaign source.`,
      ],
    };
  }

  if (dkimRate >= t.ALIGN_HIGH && spfRate <= t.ALIGN_LOW) {
    return {
      classification: "forwarder",
      confidence: knownProvider ? 0.78 : 0.7,
      reasons: [
        `DKIM aligned on ${dkim} of ${total} messages (${pct(dkimRate)}).`,
        `SPF aligned on ${spf} of ${total} messages (${pct(spfRate)}), consistent with forwarding.`,
      ],
    };
  }

  const oneStrongMethod = (spfRate >= t.ALIGN_HIGH && dkimRate < t.ALIGN_HIGH)
    || (dkimRate >= t.ALIGN_HIGH && spfRate < t.ALIGN_HIGH);
  if (knownProvider && oneStrongMethod) {
    const method = spfRate >= t.ALIGN_HIGH ? "SPF" : "DKIM";
    const count = spfRate >= t.ALIGN_HIGH ? spf : dkim;
    return {
      classification: "likely_authorised",
      confidence: 0.76,
      reasons: [
        `${method} aligned on ${count} of ${total} messages.`,
        `Provider matched ${provider}, but both SPF and DKIM are not consistently aligned.`,
      ],
    };
  }

  if (knownProvider && total >= t.MEANINGFUL_VOLUME && alignedRate < t.ALIGN_POOR) {
    return {
      classification: "misconfigured",
      confidence: 0.68,
      reasons: [
        `Provider matched ${provider}, but only ${aligned} of ${total} messages aligned (${pct(alignedRate)}).`,
        "This looks like a legitimate service that may need SPF or DKIM alignment fixes.",
      ],
    };
  }

  if (!knownProvider && claimsDomain && failedRate >= t.FAIL_HIGH && spfRate <= t.ALIGN_LOW && dkimRate <= t.ALIGN_LOW) {
    return {
      classification: "unauthorised",
      confidence: total >= t.HIGH_VOLUME ? 0.86 : 0.74,
      reasons: [
        `${failed} of ${total} messages failed alignment (${pct(failedRate)}).`,
        `The visible sender claims ${evidence.protected_domain || "the protected domain"} with no recognised provider.`,
      ],
    };
  }

  if (!knownProvider && alignedRate <= t.ALIGN_LOW && failedRate >= t.FAIL_HIGH) {
    return {
      classification: "suspicious",
      confidence: total >= t.HIGH_VOLUME ? 0.7 : 0.58,
      reasons: [
        `${failed} of ${total} messages failed alignment (${pct(failedRate)}).`,
        "No recognised provider pattern matched this sender.",
      ],
    };
  }

  if (knownProvider && ESP_PROVIDERS.has(provider) && alignedRate >= t.ALIGN_LOW) {
    return {
      classification: "likely_authorised",
      confidence: 0.62,
      reasons: [
        `Provider matched ${provider}.`,
        `${aligned} of ${total} messages aligned (${pct(alignedRate)}), but the evidence is not strong enough for an authorised verdict.`,
      ],
    };
  }

  return {
    classification: "unknown",
    confidence: 0.35,
    reasons: [
      `${total} messages were observed with ${aligned} aligned and ${failed} failing alignment.`,
      "Evidence is mixed or incomplete, so this sender needs review.",
    ],
  };
}

export async function classifyWorkspaceDomainSenders(env, workspaceId, domain, { reportSources = null } = {}) {
  if (!env?.cybermeters_db || !workspaceId || !domain) return { classified: 0 };
  let rows;
  if (Array.isArray(reportSources)) {
    const sources = reportSources.filter((source) => typeof source === "string" && source.length > 0);
    if (sources.length === 0) return { classified: 0 };
    const placeholders = sources.map(() => "?").join(", ");
    rows = await env.cybermeters_db
      .prepare(`SELECT s.id, s.workspace_id, s.domain, s.source_ip,
                       s.provider_guess, s.provider_confidence,
                       MAX(r.header_from) AS header_from,
                       SUM(r.message_count) AS total_messages,
                       SUM(CASE WHEN r.spf_aligned_result = 'pass' OR r.dkim_aligned_result = 'pass'
                                THEN r.message_count ELSE 0 END) AS aligned_messages,
                       SUM(CASE WHEN r.spf_aligned_result = 'pass' OR r.dkim_aligned_result = 'pass'
                                THEN 0 ELSE r.message_count END) AS failed_messages,
                       SUM(CASE WHEN r.spf_aligned_result = 'pass' THEN r.message_count ELSE 0 END)
                         AS spf_aligned_messages,
                       SUM(CASE WHEN r.dkim_aligned_result = 'pass' THEN r.message_count ELSE 0 END)
                         AS dkim_aligned_messages
                FROM email_sender_sources s
                JOIN dmarc_aggregate_records r
                  ON r.workspace_id = s.workspace_id
                 AND r.domain = s.domain
                 AND r.source_ip = s.source_ip
                JOIN dmarc_aggregate_reports rep
                  ON rep.id = r.report_id
                 AND rep.workspace_id = r.workspace_id
                 AND rep.domain = r.domain
                WHERE s.workspace_id = ? AND s.domain = ?
                  AND ${aggregateReportCompleteSql("rep", "dmarc")}
                  AND rep.source IN (${placeholders})
                GROUP BY s.id, s.workspace_id, s.domain, s.source_ip,
                         s.provider_guess, s.provider_confidence, s.header_from`)
      .bind(workspaceId, domain, ...sources).all();
  } else {
    rows = await env.cybermeters_db
      .prepare(`SELECT id, workspace_id, domain, source_ip, provider_guess, provider_confidence,
                       header_from, total_messages, aligned_messages, failed_messages,
                       spf_aligned_messages, dkim_aligned_messages
                FROM email_sender_sources
                WHERE workspace_id = ? AND domain = ?`)
      .bind(workspaceId, domain).all();
  }
  let classified = 0;
  for (const row of rows.results || []) {
    const result = classifySender({ ...row, protected_domain: domain });
    await env.cybermeters_db
      .prepare(`UPDATE email_sender_sources
                SET auto_classification = ?, auto_confidence = ?, auto_reasons = ?,
                    provider_map_version = ?, updated_at = datetime('now')
                WHERE id = ? AND workspace_id = ? AND domain = ?`)
      .bind(result.classification, result.confidence, JSON.stringify(result.reasons),
            PROVIDER_MAP_VERSION, row.id, workspaceId, domain).run();
    classified += 1;
  }
  return { classified };
}
