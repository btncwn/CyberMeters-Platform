// The current workspace inventory is the customer-facing Shadow IT count.
// Scan-module occurrences have a different grain and must not be substituted.
export function withShadowItInventoryCount(domains, count, hasScan) {
  if (!hasScan) return domains;
  const total = Number(count);
  if (!Number.isSafeInteger(total) || total < 0) throw new Error("Invalid inventory count");
  return domains.map((entry) => entry.domain_key === "shadow_it_unmanaged_technology"
    ? { ...entry, evidence_count: total,
        summary: `${total} externally observed technologies/services in the current inventory; compare against your approved inventory in Shadow IT.` }
    : entry);
}
