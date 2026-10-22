// DNS and HTTP enrichment can overlap. Each writer compares the exact evidence
// it merged; a bounded retry re-merges current evidence without repeating probes.
export async function writeBrandEvidence(env, workspaceId, row, write) {
  let expected = row.evidence_json ?? null;
  let result;
  for (let attempt = 0; attempt < 3; attempt++) {
    result = await write(expected);
    if (Number(result?.meta?.changes ?? result?.changes) === 1) return result;
    if (attempt === 2) break;
    const current = await env.cybermeters_db.prepare(
      "SELECT evidence_json FROM workspace_brand_assets WHERE id = ? AND workspace_id = ?"
    ).bind(row.id, workspaceId).first();
    if (!current || (current.evidence_json ?? null) === expected) break;
    expected = current.evidence_json ?? null;
  }
  return result;
}
