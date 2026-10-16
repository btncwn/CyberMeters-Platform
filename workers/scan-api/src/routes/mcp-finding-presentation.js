// The critical/high MCP list is deliberately narrower than historical D1
// findings. Scan-time brand lookalikes are unvalidated candidates, and the
// canonical customer snapshot presents them as observations. D1 does not
// persist a per-finding validation decision, so the MCP list must exclude
// those rows before LIMIT/keyset pagination rather than relabel raw severity.
// Historical rows written before finding_slug also used these fixed titles.
export function mcpCriticalFindingSql(alias = "f") {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(alias)) throw new TypeError("Invalid finding alias");
  return `(COALESCE(substr(${alias}.finding_slug, 1, 6), '') <> 'brand_'
    AND NOT (${alias}.finding_slug IS NULL AND (
      ${alias}.title LIKE 'Brand lookalike domain detected:%'
      OR ${alias}.title LIKE 'Visually confusable IDN lookalike observed:%'
    )))`;
}
