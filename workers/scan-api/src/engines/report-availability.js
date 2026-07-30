import {
  historicalReportSnapshotAvailability,
  readScanReportSnapshot,
} from "./report-snapshot.js";

// A failed canonical build is a real report error, not a preparation state.
// One later, explicit customer retry may reuse repair-on-read; a second failed
// attempt closes automatic/read-triggered repair so repeated reads cannot create
// an unbounded stream of snapshot builds.
export const MAX_REPORT_REPAIR_ATTEMPTS = 2;

export const REPORT_PREPARING_MESSAGE =
  "Your assessment is complete. CyberMeters is preparing the report.";
export const REPORT_UNAVAILABLE_MESSAGE =
  "The assessment completed, but the report could not be prepared. Please try again.";

function publicState(status, extra = {}) {
  return { status, ...extra };
}

function terminalState(code, message, reason, extra = {}) {
  return {
    availability: publicState("report_unavailable", {
      code,
      message,
      retryable: false,
      reason: reason ?? null,
      ...extra,
    }),
    read: null,
  };
}

async function snapshotAttemptState(env, scanId) {
  const result = await env.cybermeters_db
    .prepare(
      `SELECT status
       FROM scan_report_snapshots
       WHERE scan_id = ? AND status = 'failed'
       LIMIT ${MAX_REPORT_REPAIR_ATTEMPTS}`
    )
    .bind(scanId)
    .all()
    .catch(() => ({ results: [] }));
  const rows = Array.isArray(result?.results) ? result.results : [];
  return {
    failedCount: rows.filter((row) => row.status === "failed").length,
  };
}

/**
 * Resolve customer report availability from the canonical snapshot contract.
 *
 * Authorization is deliberately NOT performed here. Every route must complete
 * requireScanReadAccess first, so foreign/nonexistent scans and soft-deleted
 * workspaces cannot trigger snapshot reads or repair work.
 *
 * @returns {Promise<{availability: object, read: object|null}>}
 */
export async function resolveScanReportAvailability(env, scan, opts = {}) {
  const { allowRepair = true, retryFailed = false } = opts;
  if (!scan?.id || scan.status !== "completed") {
    return {
      availability: publicState("scan_in_progress", {
        retryable: false,
        message: "The assessment is still in progress.",
      }),
      read: null,
    };
  }

  const before = await snapshotAttemptState(env, scan.id);

  let read;
  try {
    read = await readScanReportSnapshot(env, scan.id, {
      repair: false,
      allowReconstruction: false,
    });
    if (read.status === "not_found" && before.failedCount > 0 && !retryFailed) {
      return terminalState(
        "report_generation_failed",
        REPORT_UNAVAILABLE_MESSAGE,
        before.failedCount >= MAX_REPORT_REPAIR_ATTEMPTS
          ? "repair_attempt_limit"
          : "snapshot_build_failed",
        {
          manual_retry_available:
            before.failedCount < MAX_REPORT_REPAIR_ATTEMPTS,
        },
      );
    }
    // A completed active snapshot always wins over historical failed attempts.
    // Only an absent/unfinished active snapshot may enter bounded repair.
    if (
      allowRepair &&
      (read.status === "building" || read.status === "not_found") &&
      !(
        read.status === "not_found" &&
        before.failedCount >= MAX_REPORT_REPAIR_ATTEMPTS
      )
    ) {
      read = await readScanReportSnapshot(env, scan.id, {
        repair: true,
        allowReconstruction: true,
      });
    }
  } catch {
    return terminalState(
      "report_read_failed",
      REPORT_UNAVAILABLE_MESSAGE,
      "report_read_failed",
      { manual_retry_available: true },
    );
  }

  if (
    read.status === "not_found" &&
    before.failedCount >= MAX_REPORT_REPAIR_ATTEMPTS
  ) {
    return terminalState(
      "report_generation_failed",
      REPORT_UNAVAILABLE_MESSAGE,
      "repair_attempt_limit",
      { manual_retry_available: false },
    );
  }

  if (read.status === "ok") {
    return {
      availability: publicState("report_ready", {
        retryable: false,
        snapshot_id: read.row?.id ?? null,
      }),
      read,
    };
  }

  if (read.status === "building") {
    return {
      availability: publicState("report_preparing", {
        code: "report_preparing",
        message: REPORT_PREPARING_MESSAGE,
        retryable: true,
        retry_after_ms: 2000,
        reason: read.reason ?? null,
      }),
      read,
    };
  }

  if (read.status === "integrity_error" || read.status === "unsupported_schema_version") {
    return terminalState(
      "report_integrity_error",
      "The report is unavailable because its integrity could not be verified.",
      read.reason ?? read.status,
      { manual_retry_available: false },
    );
  }

  if (read.status === "not_found") {
    const historical = historicalReportSnapshotAvailability(scan);
    if (historical) {
      return { availability: historical, read: null };
    }

    const after = await snapshotAttemptState(env, scan.id);
    const buildFailed = after.failedCount > before.failedCount;
    return terminalState(
      buildFailed ? "report_generation_failed" : "report_not_found",
      buildFailed ? REPORT_UNAVAILABLE_MESSAGE : "The completed assessment report is unavailable.",
      buildFailed
        ? "snapshot_build_failed"
        : read.reason ?? "no_snapshot",
      {
        // A first failed attempt may be retried only by an explicit customer
        // action. Automatic preparation polling always stops on this state.
        manual_retry_available:
          buildFailed && after.failedCount < MAX_REPORT_REPAIR_ATTEMPTS,
      },
    );
  }

  return terminalState(
    "report_read_failed",
    REPORT_UNAVAILABLE_MESSAGE,
    read.reason ?? read.status ?? "unknown_report_state",
    { manual_retry_available: true },
  );
}

export function reportAvailabilityError(availability) {
  if (availability?.status === "report_preparing") {
    return {
      status: 409,
      body: {
        error: availability.message,
        code: "report_preparing",
        report_availability: availability,
      },
    };
  }
  if (availability?.status === "historical_scan_no_canonical_snapshot") {
    return {
      status: 404,
      body: {
        error: availability.message,
        code: availability.status,
        report_availability: availability,
      },
    };
  }
  return {
    status: ["report_not_found", "report_source_missing"].includes(availability?.code)
      ? 404
      : 500,
    body: {
      error: availability?.message || REPORT_UNAVAILABLE_MESSAGE,
      code: availability?.code || "report_unavailable",
      report_availability: availability,
    },
  };
}
