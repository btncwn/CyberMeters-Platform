// The current workspace inventory is the customer-facing Shadow IT count.
// Scan-module occurrences have a different grain and must not be substituted.
//
// "Externally observed" means seen in the latest scan that could decide it
// (founder/Seat 2, 21 Oct 2026: a rejected item no longer seen was still counted
// as observed). Items the latest decisive scan did not see are counted apart,
// as "not seen in the latest scan" — never folded into the observed figure and
// never described as removed.
export const SHADOW_IT_INVENTORY_COUNT_SQL =
  "SELECT COUNT(*) AS n, COALESCE(SUM(CASE WHEN monitoring_status = 'no_longer_observed' THEN 1 ELSE 0 END), 0) AS not_seen " +
  "FROM shadow_it_inventory WHERE workspace_id = ?";

/** { total, not_seen } for one workspace, or null when the read failed or was malformed. */
export async function readShadowItInventoryCounts(db, workspaceId) {
  const row = await db.prepare(SHADOW_IT_INVENTORY_COUNT_SQL).bind(workspaceId).first();
  const total = Number(row?.n);
  const notSeen = Number(row?.not_seen ?? 0);
  if (!Number.isSafeInteger(total) || !Number.isSafeInteger(notSeen) || total < 0 || notSeen < 0 || notSeen > total) return null;
  return { total, not_seen: notSeen };
}

// `count` is { total, not_seen } (a bare number from an older caller means no
// item is known to be unseen).
export function withShadowItInventoryCount(domains, count, hasScan) {
  if (!hasScan) return domains;
  const total = Number(typeof count === "object" && count !== null ? count.total : count);
  const notSeen = Number(typeof count === "object" && count !== null ? (count.not_seen ?? 0) : 0);
  if (!Number.isSafeInteger(total) || total < 0 || !Number.isSafeInteger(notSeen) || notSeen < 0 || notSeen > total) {
    throw new Error("Invalid inventory count");
  }
  const observed = total - notSeen;
  const unseen = notSeen > 0 ? ` ${notSeen} not seen in the latest scan.` : "";
  return domains.map((entry) => entry.domain_key === "shadow_it_unmanaged_technology"
    ? { ...entry, evidence_count: observed, not_seen_count: notSeen,
        summary: `${observed} technologies/services externally observed in the latest scan.${unseen} Compare against your approved inventory in Shadow IT.` }
    : entry);
}
