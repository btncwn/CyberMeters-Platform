import { createId } from "./util.js";

// Cloudflare D1 permits at most 1,000 queries in one paid Worker invocation.
// DMARC is the worst case: 300 child rows + at most 300 sender-source upserts +
// one repair delete + one parent write + one complete transition + one
// completion assertion = 604 transactional statements.
// The remaining 396 queries are reserved for claim acquisition, audit,
// endpoint updates, and bounded post-ingest work. TLS-RPT uses fewer statements.
export const AGGREGATE_REPORT_D1_QUERY_BUDGET = 1000;
export const AGGREGATE_REPORT_MAX_PERSISTED_ROWS = 300;
export const AGGREGATE_REPORT_MAX_TRANSACTION_STATEMENTS = 604;

const CLAIM_LEASE_SQL = "datetime('now', '+10 minutes')";

export async function sha256Hex(input) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(String(input)),
  );
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function identityValue(value) {
  return value == null ? "" : String(value);
}

export function aggregateReportIdentity({
  orgName = null,
  externalReportId,
  dateBegin = null,
  dateEnd = null,
} = {}) {
  return {
    identity_org_name: identityValue(orgName),
    identity_report_id: identityValue(externalReportId),
    identity_date_begin: identityValue(dateBegin),
    identity_date_end: identityValue(dateEnd),
  };
}

export function aggregateReportSourceScope(authorityEligible) {
  return authorityEligible ? "authoritative" : "observational";
}

// Existing test/legacy rows without a claim remain readable. Once a claim
// exists, any pending/failed state hides the parent from observational and
// authoritative readers until redelivery repairs it. Aliases/types are static
// source-code inputs but validated defensively.
export function aggregateReportCompleteSql(alias, reportType) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(alias)) {
    throw new Error("invalid_aggregate_report_sql_alias");
  }
  if (!["dmarc", "tlsrpt"].includes(reportType)) {
    throw new Error("invalid_aggregate_report_type");
  }
  const sourceScope = `CASE
    WHEN ${alias}.source IN ('manual_paste', 'signed_upload') THEN 'authoritative'
    ELSE 'observational'
  END`;
  const identity = reportType === "dmarc"
    ? `ingest_claim.workspace_id = ${alias}.workspace_id
       AND ingest_claim.domain = ${alias}.domain
       AND ingest_claim.source_scope = ${sourceScope}
       AND ingest_claim.identity_org_name = COALESCE(${alias}.org_name, '')
       AND ingest_claim.identity_report_id = ${alias}.external_report_id
       AND ingest_claim.identity_date_begin = COALESCE(CAST(${alias}.date_range_begin AS TEXT), '')
       AND ingest_claim.identity_date_end = COALESCE(CAST(${alias}.date_range_end AS TEXT), '')`
    : `ingest_claim.workspace_id = ${alias}.workspace_id
       AND ingest_claim.domain = ${alias}.domain
       AND ingest_claim.source_scope = ${sourceScope}
       AND ingest_claim.identity_org_name = ''
       AND ingest_claim.identity_report_id = ${alias}.external_report_id
       AND ingest_claim.identity_date_begin = ''
       AND ingest_claim.identity_date_end = ''`;
  return `NOT EXISTS (
      SELECT 1 FROM aggregate_report_ingest_claims ingest_claim
      WHERE ingest_claim.report_type = '${reportType}'
        AND ingest_claim.report_id = ${alias}.id
        AND ingest_claim.ingest_state <> 'complete'
    )
    AND (
      NOT EXISTS (
        SELECT 1 FROM aggregate_report_ingest_claims ingest_claim
        WHERE ingest_claim.report_type = '${reportType}' AND ${identity}
      )
      OR EXISTS (
        SELECT 1 FROM aggregate_report_ingest_claims ingest_claim
        WHERE ingest_claim.report_type = '${reportType}' AND ${identity}
          AND ingest_claim.report_id = ${alias}.id
          AND ingest_claim.ingest_state = 'complete'
      )
    )`;
}

function claimSelectSql() {
  return `SELECT id, report_id, content_hash, ingest_state, attempt_token,
                 lease_expires_at, source, source_scope
          FROM aggregate_report_ingest_claims
          WHERE report_type = ? AND workspace_id = ? AND domain = ?
            AND source_scope = ? AND identity_org_name = ?
            AND identity_report_id = ? AND identity_date_begin = ?
            AND identity_date_end = ?
          LIMIT 1`;
}

function identityBindings(input) {
  return [
    input.reportType,
    input.workspaceId,
    input.domain,
    input.sourceScope,
    input.identity.identity_org_name,
    input.identity.identity_report_id,
    input.identity.identity_date_begin,
    input.identity.identity_date_end,
  ];
}

function contentHashesMatch(storedHash, incomingHash) {
  // Migration 100 cannot reconstruct a missing legacy hash. Preserve historical
  // dedupe for that bounded compatibility case; all Gate-3B writes have a hash
  // and compare it before any duplicate/collision decision.
  return !storedHash || storedHash === incomingHash;
}

export async function acquireAggregateReportClaim(env, input) {
  const attemptToken = createId("ingest_attempt");
  const claimId = createId("ingest_claim");
  const reportId = input.reportId || createId(
    input.reportType === "tlsrpt" ? "tlsr" : "dmarcrep",
  );

  const inserted = await env.cybermeters_db
    .prepare(`INSERT OR IGNORE INTO aggregate_report_ingest_claims
              (id, report_type, workspace_id, domain, source, source_scope,
               identity_org_name, identity_report_id, identity_date_begin, identity_date_end,
               report_id, content_hash, ingest_state, attempt_token, lease_expires_at,
               created_at, updated_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ${CLAIM_LEASE_SQL},
                      datetime('now'), datetime('now'))`)
    .bind(
      claimId,
      input.reportType,
      input.workspaceId,
      input.domain,
      input.source,
      input.sourceScope,
      input.identity.identity_org_name,
      input.identity.identity_report_id,
      input.identity.identity_date_begin,
      input.identity.identity_date_end,
      reportId,
      input.contentHash,
      attemptToken,
    )
    .run();

  if ((inserted?.meta?.changes ?? 0) > 0) {
    return {
      acquired: true,
      repaired: false,
      claimId,
      reportId,
      attemptToken,
    };
  }

  const existing = await env.cybermeters_db
    .prepare(claimSelectSql())
    .bind(...identityBindings(input))
    .first();
  if (!existing) throw new Error("aggregate_ingest_claim_conflict_missing");

  if (!contentHashesMatch(existing.content_hash, input.contentHash)) {
    return {
      acquired: false,
      collision: true,
      claimId: existing.id,
      reportId: existing.report_id,
      storedHash: existing.content_hash,
    };
  }

  if (existing.ingest_state === "complete") {
    return {
      acquired: false,
      duplicate: true,
      claimId: existing.id,
      reportId: existing.report_id,
    };
  }

  const reacquired = await env.cybermeters_db
    .prepare(`UPDATE aggregate_report_ingest_claims
              SET source = ?, content_hash = ?, ingest_state = 'pending',
                  attempt_token = ?, lease_expires_at = ${CLAIM_LEASE_SQL},
                  failure_code = NULL, failed_at = NULL, updated_at = datetime('now')
              WHERE id = ?
                AND (
                  ingest_state = 'failed'
                  OR (ingest_state = 'pending' AND lease_expires_at <= datetime('now'))
                )`)
    .bind(input.source, input.contentHash, attemptToken, existing.id)
    .run();

  if ((reacquired?.meta?.changes ?? 0) === 0) {
    return {
      acquired: false,
      inProgress: true,
      claimId: existing.id,
      reportId: existing.report_id,
    };
  }

  return {
    acquired: true,
    repaired: true,
    claimId: existing.id,
    reportId: existing.report_id,
    attemptToken,
  };
}

export function completeAggregateReportClaimStatement(env, claim) {
  return env.cybermeters_db
    .prepare(`UPDATE aggregate_report_ingest_claims
              SET ingest_state = 'complete', failure_code = NULL,
                  lease_expires_at = NULL, completed_at = datetime('now'),
                  failed_at = NULL, updated_at = datetime('now')
              WHERE id = ? AND attempt_token = ? AND ingest_state = 'pending'`)
    .bind(claim.claimId, claim.attemptToken);
}

// D1 batch() rolls back when any statement fails. The preceding conditional
// UPDATE could otherwise affect zero rows without failing, so this final guard
// deliberately attempts a CHECK-violating insert only when the claim did not
// reach complete under the owning attempt token. A lost state transition can
// therefore never commit parent/child/rollup rows.
export function assertAggregateReportClaimCompleteStatement(env, claim) {
  return env.cybermeters_db
    .prepare(`INSERT INTO aggregate_report_ingest_claims
                (id, report_type, workspace_id, domain, source, source_scope,
                 identity_org_name, identity_report_id, identity_date_begin, identity_date_end,
                 report_id, content_hash, ingest_state, attempt_token)
              SELECT ?, 'invalid', '', '', '', 'observational', '', '', '', '',
                     '', '', 'pending', ''
              WHERE NOT EXISTS (
                SELECT 1 FROM aggregate_report_ingest_claims
                WHERE id = ? AND attempt_token = ? AND ingest_state = 'complete'
              )`)
    .bind(`assert_${claim.attemptToken}`, claim.claimId, claim.attemptToken);
}

export async function failAggregateReportClaim(env, claim, failureCode) {
  const failed = await env.cybermeters_db
    .prepare(`UPDATE aggregate_report_ingest_claims
              SET ingest_state = 'failed', failure_code = ?,
                  lease_expires_at = NULL, failed_at = datetime('now'),
                  updated_at = datetime('now')
              WHERE id = ? AND attempt_token = ? AND ingest_state = 'pending'`)
    .bind(String(failureCode || "transient_storage_failure").slice(0, 100),
      claim.claimId, claim.attemptToken)
    .run();
  return (failed?.meta?.changes ?? 0) > 0;
}
