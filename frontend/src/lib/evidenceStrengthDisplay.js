export const EVIDENCE_STRENGTH = Object.freeze({
  L0: 'Limited',
  L1: 'Limited',
  L2: 'Medium',
  L3: 'High',
  L4: 'High',
  L5: 'High',
})

export const HOW_TO_READ_REPORT =
  'Evidence strength shows how strongly the available evidence supports a conclusion — it is NOT your security score. ' +
  'Limited evidence is normal for external assessment and does not mean weak security. ' +
  'A domain we could not fully assess is shown as evidence-insufficient, not as low-risk.'

export function evidenceStrengthLabel(assertion) {
  return EVIDENCE_STRENGTH[assertion?.grade] || 'Limited'
}

// Keep formal RFC identifiers in the PDF technical appendix. The in-app report
// body uses protocol names for readable customer-facing explanations.
export function customerEvidenceText(value) {
  return String(value || '')
    .replace(/\s*\(RFC\s+\d+\)/gi, '')
    .replace(/\bRFC 7208 SPF\b/gi, 'SPF')
    .replace(/\bRFC 9989 DMARC\b/gi, 'DMARC')
    .replace(/\bRFC 6376 DKIM\b/gi, 'DKIM')
    .replace(/\bRFC 8461 MTA-STS\b/gi, 'MTA-STS')
    .replace(/\bRFC 8460 TLS reporting\b/gi, 'TLS reporting')
    .replace(/\bHSTS RFC 6797\b/gi, 'HSTS')
    .replace(/\bRFC\s+7208\b/gi, 'the SPF protocol')
    .replace(/\bRFC\s+6376\b/gi, 'the DKIM protocol')
    .replace(/\bRFC\s+9989\b/gi, 'the DMARC protocol')
    .replace(/\bRFC\s+8461\b/gi, 'the MTA-STS protocol')
    .replace(/\bRFC\s+8460\b/gi, 'the TLS reporting protocol')
    .replace(/\bRFC\s+9162\b/gi, 'the Certificate Transparency protocol')
    .replace(/\bRFC\s+1035\b/gi, 'the DNS protocol')
    .replace(/\bRFC\s+9110\b/gi, 'the HTTP protocol')
    .replace(/\bRFC\s+6797\b/gi, 'the HSTS standard')
    .replace(/\bRFC\s+\d+\b/gi, 'the applicable protocol')
    .replace(/\s{2,}/g, ' ')
    .replace(/\s+([,.;:])/g, '$1')
    .trim()
}

export function evidenceLimits(assertions) {
  return [...new Set(
    (assertions || [])
      .flatMap((assertion) => Array.isArray(assertion?.limits) ? assertion.limits : [])
      .map(customerEvidenceText)
      .filter(Boolean)
  )]
}
