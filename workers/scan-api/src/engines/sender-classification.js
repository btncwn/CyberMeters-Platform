// ── DMARC sender classification engine ──────────────────────────────────────
// Evidence-based, deterministic sender classification for DMARC aggregate
// senders. Manual customer decisions stay in email_sender_sources.classification;
// this engine only writes auto_* evidence fields and provider_map_version.

export const PROVIDER_MAP_VERSION = "2026-07-13.1";

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

export async function classifyWorkspaceDomainSenders(env, workspaceId, domain) {
  if (!env?.cybermeters_db || !workspaceId || !domain) return { classified: 0 };
  const rows = await env.cybermeters_db
    .prepare(`SELECT id, workspace_id, domain, source_ip, provider_guess, provider_confidence,
                     header_from, total_messages, aligned_messages, failed_messages,
                     spf_aligned_messages, dkim_aligned_messages
              FROM email_sender_sources
              WHERE workspace_id = ? AND domain = ?`)
    .bind(workspaceId, domain).all();
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
