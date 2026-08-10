// ── Canonical D1 finding identity + bounded legacy compatibility ─────────────
// New rows retain the runtime finding `id` as `finding_slug`. Historical rows are
// never rewritten. A deliberately narrow read-time rule excludes only the exact
// null-identity provenance emitted by the old unproven TLS finding path.
//
// Runtime tri-state policy is owned by tls-evidence.js. In this combined candidate,
// a new row with finding_slug='ssl_not_available' remains visible only because the
// forward writer can receive that identity solely from approved positive-absence
// evidence; this compatibility classifier never invents runtime evidence.

import { createId } from "../lib/util.js";
import { TLS_INSTALL_TITLES } from "./tls-evidence.js";

export const LEGACY_UNPROVEN_TLS_SLUG = "ssl_not_available";
export const LEGACY_IDENTITY_PROJECTION = "historical_unproven_tls";

// Migration 091 first persisted domain-state history at 2026-07-16.1. These are
// the mechanically traced resolver versions that could have recorded the legacy
// unproven-TLS-only Website state before this identity layer existed. New/future
// versions are intentionally excluded.
export const LEGACY_TLS_DOMAIN_RESOLVER_VERSIONS = Object.freeze([
  "2026-07-16.1",
  "2026-07-16.2",
  "2026-07-24.3",
  "2026-07-24.4",
]);
const LEGACY_TLS_DOMAIN_RESOLVER_SET = new Set(LEGACY_TLS_DOMAIN_RESOLVER_VERSIONS);

const LEGACY_TLS_EVIDENCE_KEYS = Object.freeze([
  "checked_at",
  "evidence_type",
  "expected_value",
  "manual_verification_command",
  "observed_value",
  "probe_target",
  "source",
]);
const LEGACY_TLS_OBSERVED = "TLS handshake failed or connection refused on port 443";
const LEGACY_TLS_EXPECTED = "TLS 1.2+ handshake success with valid certificate";

function exactObjectKeys(value, expected) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Object.keys(value).sort();
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
}

/**
 * Testable oracle for the shared SQL classifier. Customer-visible title is not
 * read. Missing, malformed, mixed, reused or ambiguous provenance returns false.
 */
export function isConclusiveLegacyUnprovenTlsFinding(row) {
  if (!row || row.finding_slug != null || typeof row.domain !== "string" || !row.domain) return false;
  let evidence;
  try { evidence = JSON.parse(row.evidence_json); } catch { return false; }
  // Forward writer bytes were JSON.stringify output. Requiring that exact
  // canonical encoding rejects duplicate keys and whitespace variants before
  // JS can collapse them differently from SQLite json_each/json_extract.
  if (JSON.stringify(evidence) !== row.evidence_json) return false;
  if (!exactObjectKeys(evidence, LEGACY_TLS_EVIDENCE_KEYS)) return false;
  let checkedAtCanonical = false;
  try {
    checkedAtCanonical = new Date(evidence.checked_at).toISOString() === evidence.checked_at;
  } catch {
    checkedAtCanonical = false;
  }
  return evidence.evidence_type === "https_probe"
    && evidence.probe_target === `https://${row.domain}`
    && evidence.observed_value === LEGACY_TLS_OBSERVED
    && evidence.expected_value === LEGACY_TLS_EXPECTED
    && evidence.source === "cloudflare_workers_fetch"
    && checkedAtCanonical
    && evidence.manual_verification_command === `curl -sI https://${row.domain} | head -3`;
}

const sqlAlias = (value, label) => {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) throw new TypeError(`Invalid ${label} SQL alias`);
  return value;
};
const sqlLiteral = (value) => `'${String(value).replaceAll("'", "''")}'`;

/**
 * visibleFindingSql(findingAlias, scanAlias) -> SQL boolean expression.
 *
 * Every D1 findings reader composes this one predicate into its existing scoped
 * query. json_valid + CASE makes malformed legacy bytes visible rather than
 * raising. Exact key cardinality prevents mixed evidence from being suppressed.
 */
export function visibleFindingSql(findingAlias = "f", scanAlias = "s") {
  const f = sqlAlias(findingAlias, "finding");
  const s = sqlAlias(scanAlias, "scan");
  const safe = `(CASE WHEN json_valid(${f}.evidence_json) THEN ${f}.evidence_json ELSE '{}' END)`;
  const legacy = `(
    ${f}.finding_slug IS NULL
    AND json(${safe}) = ${f}.evidence_json
    AND json_type(${safe}) = 'object'
    AND (SELECT COUNT(*) FROM json_each(${safe})) = ${LEGACY_TLS_EVIDENCE_KEYS.length}
    AND json_extract(${safe}, '$.evidence_type') = 'https_probe'
    AND json_extract(${safe}, '$.probe_target') = ('https://' || ${s}.domain)
    AND json_extract(${safe}, '$.observed_value') = ${sqlLiteral(LEGACY_TLS_OBSERVED)}
    AND json_extract(${safe}, '$.expected_value') = ${sqlLiteral(LEGACY_TLS_EXPECTED)}
    AND json_extract(${safe}, '$.source') = 'cloudflare_workers_fetch'
    AND json_type(${safe}, '$.checked_at') = 'text'
    AND strftime('%Y-%m-%dT%H:%M:%fZ', json_extract(${safe}, '$.checked_at'), '+0 seconds') = json_extract(${safe}, '$.checked_at')
    AND json_extract(${safe}, '$.manual_verification_command') = ('curl -sI https://' || ${s}.domain || ' | head -3')
  )`;
  // The '+0 seconds' modifier forces SQLite to normalise parsed date fields the
  // way JavaScript's Date does (hour 24 and invalid calendar days roll over and
  // then fail the equality), and COALESCE forces a strict boolean so a NULL from
  // an absent key or an unparseable timestamp keeps the row VISIBLE — SQL
  // three-valued logic must never hide evidence the JS oracle calls ambiguous.
  return `(NOT COALESCE(${legacy}, 0))`;
}

/**
 * suppressedLegacyTlsRemediationSql(remediationAlias) -> SQL boolean expression.
 *
 * A remediation row is suppressed ONLY when its scan also holds the exact
 * classified legacy unproven-TLS finding and no forward-written (slugged)
 * ssl_not_available finding replaced it. Title alone never suppresses; the
 * outer COALESCE errs VISIBLE on any ambiguity. Read-time projection only —
 * historical remediation_items bytes are never rewritten.
 */
export function suppressedLegacyTlsRemediationSql(remediationAlias = "ri") {
  const r = sqlAlias(remediationAlias, "remediation");
  const titles = [...TLS_INSTALL_TITLES].map(sqlLiteral).join(", ");
  return `COALESCE((
    ${r}.title IN (${titles})
    AND EXISTS (
      SELECT 1 FROM findings lf JOIN scans ls ON ls.id = lf.scan_id
      WHERE lf.scan_id = ${r}.scan_id AND NOT ${visibleFindingSql("lf", "ls")}
    )
    AND NOT EXISTS (
      SELECT 1 FROM findings sf
      WHERE sf.scan_id = ${r}.scan_id AND sf.finding_slug = ${sqlLiteral(LEGACY_UNPROVEN_TLS_SLUG)}
    )
  ), 0)`;
}

/**
 * Forward-only persistence. The scan must belong to the supplied active
 * workspace before any finding is written. All canonical identities are checked
 * before the first insert so an invalid batch cannot partially persist.
 */
export async function persistFindingsWithIdentity(env, { scanId, workspaceId, findings } = {}) {
  if (!scanId || !workspaceId || !Array.isArray(findings) || findings.length === 0) {
    return { written: 0, skipped: "missing_scope_or_findings" };
  }
  if (findings.some((finding) => typeof finding?.id !== "string" || finding.id.trim() === "")) {
    throw new TypeError("Every persisted finding requires a canonical runtime identity");
  }

  const scopedScan = await env.cybermeters_db.prepare(
    `SELECT s.id
     FROM scans s
     JOIN workspaces w ON w.id = s.workspace_id
     WHERE s.id = ? AND s.workspace_id = ? AND w.deleted_at IS NULL
     LIMIT 1`
  ).bind(scanId, workspaceId).first();
  if (!scopedScan) return { written: 0, skipped: "inactive_or_cross_workspace_scan" };

  const statements = findings.map((finding) =>
    env.cybermeters_db.prepare(
      `INSERT INTO findings
         (id, scan_id, finding_slug, severity, title, recommendation, evidence_json, confidence)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      createId("finding"),
      scanId,
      finding.id,
      finding.severity,
      finding.title,
      finding.description,
      finding.evidence ? JSON.stringify(finding.evidence) : null,
      finding.confidence ?? null,
    )
  );
  // Cloudflare D1 batch() executes the statement sequence transactionally. A
  // preparation/constraint/runtime failure therefore commits none of the batch;
  // callers never observe a prefix of newly persisted findings.
  const results = await env.cybermeters_db.batch(statements);
  const written = results.reduce(
    (total, result) => total + Number(result?.meta?.changes || 0),
    0,
  );
  return { written, skipped: null };
}

/**
 * Bounded projection for immutable domain-state rows, which store identities but
 * not evidence_json. Only an exact, TLS-only historical Website row produced by
 * an allowlisted old resolver is projected. Mixed/malformed/new rows are returned
 * unchanged so another material identity can never be downgraded.
 */
export function projectLegacyWebsiteDomainState(row) {
  if (!row
      || row.domain_key !== "website_security"
      || row.state !== "issue_detected"
      || row.highest_severity !== "critical"
      || Number(row.finding_count) !== 1
      || !LEGACY_TLS_DOMAIN_RESOLVER_SET.has(row.resolver_version)) return row;
  let ids;
  try { ids = JSON.parse(row.finding_ids_json); } catch { return row; }
  if (!Array.isArray(ids) || ids.length !== 1 || ids[0] !== LEGACY_UNPROVEN_TLS_SLUG) return row;
  return {
    ...row,
    state: "evidence_insufficient",
    coverage: "degraded",
    summary: "Historical TLS evidence was insufficient to support this Website Security finding.",
    highest_severity: null,
    finding_count: 0,
    finding_ids_json: "[]",
    legacy_identity_projection: LEGACY_IDENTITY_PROJECTION,
  };
}
