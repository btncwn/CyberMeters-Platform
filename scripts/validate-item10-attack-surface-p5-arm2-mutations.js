#!/usr/bin/env node

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  analyseOrderedRegistry,
  classifySemanticMutation,
  createMutationSandbox,
  filesUnder,
  fingerprintFiles,
  forcedInterruptionLeavesFingerprint,
  handledSignalCleansSandbox,
  installMutationSignalCleanup,
  preflightMutationTargets,
  replaceExactly,
} from "./item10-p5-mutation-harness.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const VALIDATOR = path.join(ROOT, "scripts/validate-item10-attack-surface-p5-arm2.js");
const CUSTOMER_PARITY_VALIDATOR = path.join(
  ROOT,
  "scripts/validate-item10-attack-surface-p5-customer-parity.js",
);
const PORTFOLIO_VALIDATOR = path.join(ROOT, "scripts/validate-portfolio.js");
const WORKER_ROOT = path.join(ROOT, "workers/scan-api");
const ENGINE_DIR = path.join(ROOT, "workers/scan-api/src/engines");
const CONTROLS_ONLY = process.argv.includes("--controls-only");
installMutationSignalCleanup();

const EXPECTED_NEGATIVE_CONTROL_IDS = Object.freeze([
  "registry_missing_name",
  "registry_reordered_name",
  "registry_duplicate_name",
  "registry_unexpected_name",
  "mutant_syntax_failure_is_not_kill",
  "mutant_import_failure_is_not_kill",
  "mutant_runtime_failure_is_not_kill",
  "mutant_module_failure_is_not_kill",
  "summary_output_bound_assertion_fails_on_raw_parity",
  "timeline_output_bound_assertion_fails_on_raw_parity",
  "frontend_vocabulary_guard_detects_real_declaration",
  "mutation_anchor_zero_replacements_fails",
  "mutation_anchor_multiple_replacements_fails",
]);
const EXPECTED_NEGATIVE_CONTROL_COUNT = 13;

const EXPECTED_ARM2_MUTANT_IDS = Object.freeze([
  "physical_recency_replaces_relevant_window",
  "future_row_enters_event_relative_window",
  "exact_anchor_requirement_removed",
  "canonical_order_drops_created_at_tiebreak",
  "canonical_order_drops_scan_id_tiebreak",
  "sqlite_space_timestamp_interpreted_as_local_time",
  "d1_binding_capacity_off_by_one",
  "delivery_bypasses_shared_replay",
  "neutral_rows_suppress_removal_alert",
  "neutral_rows_suppress_reappearance_alert",
  "null_asset_becomes_unsupported",
  "null_scan_becomes_unsupported",
  "missing_anchor_becomes_unsupported",
  "schema_absent_becomes_zero",
  "read_failure_becomes_zero",
  "unknown_policy_becomes_unsupported",
  "malformed_source_detail_becomes_unsupported",
  "invalid_relevant_timestamp_becomes_unsupported",
  "replay_truncation_publishes_partial_count",
  "hostname_fallback_borrows_evidence",
  "workspace_scope_removed",
  "unsupported_enters_supported_count",
  "uncertain_enters_supported_count",
  "supported_reappearance_enters_no_longer_observed_count",
  "route_reappearance_enters_no_longer_observed_count",
  "asset_timeline_collapses_before_projection",
  "posture_timeline_collapses_before_projection",
  "timestamp_outranks_replay_completeness",
  "secondary_limitation_is_dropped",
  "limitation_order_is_unstable",
  "malformed_source_detail_hidden_by_unknown_policy",
  "count_partition_drops_non_lifecycle",
  "raw_description_renders_unqualified",
  "unsupported_or_uncertain_row_collapses",
  "legacy_schedule_writer_bypasses_projection",
  "queue_schedule_writer_bypasses_projection",
  "schedule_null_projection_renders_zero",
  "honest_summary_reverts_to_legacy_raw",
  "honest_timeline_reverts_to_legacy_raw",
]);
const EXPECTED_ARM2_MUTANT_COUNT = 39;
const EXPECTED_ARM2_MUTATION_CASE_COUNT = 40;
const EXPECTED_ARM2_MUTATION_REPLACEMENT_COUNT = 41;
const EXPECTED_VALIDATOR_ASSERTIONS = 130;
const EXPECTED_CUSTOMER_PARITY_ASSERTIONS = 258;
const EXPECTED_PORTFOLIO_ASSERTIONS = 81;
const EXPECTED_HARNESS_SAFETY_ASSERTIONS = 3;

const TARGETS = Object.freeze({
  support: {
    file: path.join(ENGINE_DIR, "asset-lifecycle-event-support.js"),
    env: "ITEM10_P5_ARM2_SUPPORT_MODULE_URL",
    module: true,
  },
  timeline: {
    file: path.join(ENGINE_DIR, "timeline-trust.js"),
    env: "ITEM10_P5_ARM2_TIMELINE_MODULE_URL",
    module: true,
  },
  delivery: {
    file: path.join(ENGINE_DIR, "asset-alert-delivery.js"),
    env: "ITEM10_P5_ARM2_DELIVERY_SOURCE",
  },
  index: {
    file: path.join(ROOT, "workers/scan-api/src/index.js"),
    env: "ITEM10_P5_ARM2_INDEX_SOURCE",
  },
  scans: {
    file: path.join(ROOT, "workers/scan-api/src/routes/scans.js"),
    env: "ITEM10_P5_ARM2_SCANS_SOURCE",
  },
  attackSurface: {
    file: path.join(ROOT, "workers/scan-api/src/routes/attack-surface.js"),
    env: "ITEM10_P5_ARM2_ATTACK_SURFACE_SOURCE",
  },
});

const EXPECTED_FAILURES = Object.freeze({
  physical_recency_replaces_relevant_window: [
    "physical_recency_cannot_replace_decision_relevant_window",
    "neutral physical rows cannot suppress supported removal",
    "supported removal retains frozen right reason",
    "neutral physical rows cannot suppress supported reappearance",
    "supported reappearance retains frozen right reason",
    "future rows cannot change historical support",
    "future_row_is_excluded_from_event_relative_window",
  ],
  future_row_enters_event_relative_window: [
    "future rows cannot change historical support",
    "future_row_is_excluded_from_event_relative_window",
  ],
  exact_anchor_requirement_removed: [
    "future rows cannot change historical support",
    "future_row_is_excluded_from_event_relative_window",
    "missing exact anchor is uncertain",
    "missing exact anchor is uncertain exposes exact limitation",
    "missing exact anchor is uncertain never invents boolean evidence",
  ],
  canonical_order_drops_created_at_tiebreak: [
    "mixed-format replay preserves supported reappearance",
    "mixed_format_replay_preserves_supported_reappearance",
  ],
  canonical_order_drops_scan_id_tiebreak: [
    "bytewise_scan_id_tiebreak_preserves_supported_reappearance",
  ],
  sqlite_space_timestamp_interpreted_as_local_time: [
    "SQLite UTC and equivalent zoned ISO share epoch",
    "SQLite timestamp canonicalises to UTC",
    "sqlite_space_timestamp_is_utc_across_sql_worker_node",
    "mixed-format replay preserves supported reappearance",
    "mixed_format_replay_preserves_supported_reappearance",
  ],
  d1_binding_capacity_off_by_one: [
    "Cloudflare D1's lifecycle binding ceiling is literally pinned to 100",
    "205 authorised ids use three bounded source reads, not one oversized statement",
    "portfolio reads with LIMIT binds pack 99 workspace ids per statement",
    "no portfolio authorised-id source statement exceeds 100 bindings",
  ],
  delivery_bypasses_shared_replay: [
    "delivery_uses_shared_event_relative_replay",
  ],
  neutral_rows_suppress_removal_alert: [
    "physical_recency_cannot_replace_decision_relevant_window",
    "neutral physical rows cannot suppress supported removal",
    "supported removal retains frozen right reason",
    "future rows cannot change historical support",
    "future_row_is_excluded_from_event_relative_window",
  ],
  neutral_rows_suppress_reappearance_alert: [
    "neutral physical rows cannot suppress supported reappearance",
    "supported reappearance retains frozen right reason",
  ],
  null_asset_becomes_unsupported: [
    "null asset is uncertain",
    "null asset is uncertain exposes exact limitation",
    "null asset is uncertain never invents boolean evidence",
  ],
  null_scan_becomes_unsupported: [
    "null scan is uncertain",
    "null scan is uncertain exposes exact limitation",
    "null scan is uncertain never invents boolean evidence",
  ],
  missing_anchor_becomes_unsupported: [
    "missing exact anchor is uncertain",
    "missing exact anchor is uncertain exposes exact limitation",
    "missing exact anchor is uncertain never invents boolean evidence",
    "hostname_fallback_cannot_borrow_evidence",
    "hostname_fallback_reports_exact_anchor_absence",
  ],
  schema_absent_becomes_zero: [
    "schema_absence_is_collection_unavailable",
    "schema_absence_never_becomes_honest_zero",
  ],
  read_failure_becomes_zero: [
    "read_failure_is_collection_unavailable",
    "read_failure_never_becomes_honest_zero",
  ],
  unknown_policy_becomes_unsupported: [
    "unknown policy is uncertain",
    "unknown policy is uncertain exposes exact limitation",
    "unknown policy is uncertain never invents boolean evidence",
    "unknown policy precedes malformed source",
    "policy and source retain both limitations",
  ],
  malformed_source_detail_becomes_unsupported: [
    "malformed source detail is uncertain",
    "malformed source detail is uncertain exposes exact limitation",
    "malformed source detail is uncertain never invents boolean evidence",
    "unknown policy precedes malformed source",
    "policy and source retain both limitations",
  ],
  invalid_relevant_timestamp_becomes_unsupported: [
    "invalid relevant timestamp is uncertain",
    "invalid relevant timestamp is uncertain exposes exact limitation",
    "invalid relevant timestamp is uncertain never invents boolean evidence",
    "replay truncation precedes invalid timestamp",
    "replay and timestamp retain both limitations",
  ],
  replay_truncation_publishes_partial_count: [
    "truncated collection nulls total",
    "truncated collection nulls supported",
    "truncated collection nulls unsupported",
    "truncated collection nulls uncertain",
    "truncated collection nulls non_lifecycle",
    "truncated collection nulls customer_change_count",
    "collection_truncation_never_publishes_partial_count",
    "schema_absence_never_becomes_honest_zero",
    "read_failure_never_becomes_honest_zero",
  ],
  hostname_fallback_borrows_evidence: [
    "hostname_fallback_cannot_borrow_evidence",
    "hostname_fallback_reports_exact_anchor_absence",
  ],
  workspace_scope_removed: [
    "workspace_scope_mismatch_fails_collection_closed",
    "workspace_scope_mismatch_has_frozen_reason",
  ],
  unsupported_enters_supported_count: [
    "count partition supported is exact",
    "count partition unsupported is exact",
    "removal-only supported count excludes supported reappearance",
    "summary_no_longer_observed_count_excludes_supported_reappearance",
  ],
  uncertain_enters_supported_count: [
    "count partition supported is exact",
    "count partition uncertain is exact",
    "removal-only supported count excludes supported reappearance",
    "summary_no_longer_observed_count_excludes_supported_reappearance",
    "per_event_replay_truncation_is_exactly_counted_uncertain",
    "per_event_replay_truncation_keeps_supported_removal_zero",
  ],
  supported_reappearance_enters_no_longer_observed_count: [
    "removal-only supported count excludes supported reappearance",
    "summary_no_longer_observed_count_excludes_supported_reappearance",
    "reappearance bucket is separate",
    "removal_type_is_omitted_when_out_of_scope",
  ],
  route_reappearance_enters_no_longer_observed_count: Object.freeze({
    asset_timeline_all: [
      "posture timeline preserves raw history but excludes unsupported honest count",
    ],
    posture_timeline_90d: [
      "posture timeline preserves raw history but excludes unsupported honest count",
    ],
  }),
  asset_timeline_collapses_before_projection: ["asset_timeline_projects_before_customer_collapse"],
  posture_timeline_collapses_before_projection: ["posture_timeline_projects_before_customer_collapse"],
  timestamp_outranks_replay_completeness: [
    "per_event_replay_truncation_is_uncertain",
    "per_event_replay_truncation_has_frozen_reason",
    "per_event_replay_truncation_has_frozen_limitation",
    "replay truncation precedes invalid timestamp",
    "replay and timestamp retain both limitations",
    "per_event_replay_truncation_is_exactly_counted_uncertain",
    "per_event_replay_truncation_keeps_supported_removal_zero",
  ],
  secondary_limitation_is_dropped: [
    "invalid relevant timestamp is uncertain",
    "invalid relevant timestamp is uncertain exposes exact limitation",
    "invalid relevant timestamp is uncertain never invents boolean evidence",
    "replay and timestamp retain both limitations",
  ],
  limitation_order_is_unstable: [
    "replay truncation precedes invalid timestamp",
    "replay and timestamp retain both limitations",
    "unknown policy precedes malformed source",
    "policy and source retain both limitations",
  ],
  malformed_source_detail_hidden_by_unknown_policy: [
    "malformed source detail is uncertain",
    "malformed source detail is uncertain exposes exact limitation",
    "malformed source detail is uncertain never invents boolean evidence",
    "policy and source retain both limitations",
  ],
  count_partition_drops_non_lifecycle: [
    "count partition non-lifecycle is exact",
  ],
  raw_description_renders_unqualified: [
    "projector replaces assertive unsupported description",
  ],
  unsupported_or_uncertain_row_collapses: [
    "unsupported_rows_remain_visible_and_do_not_collapse",
    "uncertain_rows_remain_visible_and_do_not_collapse",
    "projected unsupported uncertain pair remains visible",
  ],
  legacy_schedule_writer_bypasses_projection: [
    "both_scheduled_writers_use_one_projection_writer",
  ],
  queue_schedule_writer_bypasses_projection: [
    "both_scheduled_writers_use_one_projection_writer",
  ],
  schedule_null_projection_renders_zero: [
    "schedule_null_projection_is_not_evaluated",
    "schedule_null_projection_does_not_emit_honest_zero",
  ],
  honest_summary_reverts_to_legacy_raw: [
    "honest_summary_uses_supported_removal_bucket_not_legacy_raw",
  ],
  honest_timeline_reverts_to_legacy_raw: [
    "honest_timeline_uses_supported_removal_rows_not_legacy_raw",
  ],
});

function replacement(target, from, to) {
  return { target, from, to };
}

const MUTANTS = Object.freeze([
  {
    id: "physical_recency_replaces_relevant_window",
    changes: [replacement(
      "support",
      `  const preceding = assetRows
    .filter((row) => row.scan_id !== anchor.scan_id && compareLifecycleObservationOrder(row, anchor) < 0)
    .sort(compareLifecycleObservationOrder)
    .slice(-3);`,
      `  const preceding = matchingRows
    .filter((row) => row.scan_id !== anchor.scan_id)
    .slice(-3);`,
    )],
  },
  {
    id: "future_row_enters_event_relative_window",
    changes: [
      replacement(
        "support",
        `    .filter((row) => row.scan_id !== anchor.scan_id && compareLifecycleObservationOrder(row, anchor) < 0)`,
        `    .filter((row) => row.scan_id !== anchor.scan_id)`,
      ),
      replacement(
        "support",
        `    if (row.scan_id === anchor.scan_id) targetTransition = next.transition;`,
        `    targetTransition = next.transition;`,
      ),
    ],
  },
  {
    id: "exact_anchor_requirement_removed",
    changes: [replacement(
      "support",
      `  const anchor = matchingRows.find((row) => row.scan_id === event.scan_id);`,
      `  const anchor = matchingRows.at(-1);`,
    )],
  },
  {
    id: "canonical_order_drops_created_at_tiebreak",
    changes: [replacement(
      "support",
      `  if (createdA.epoch_ms !== createdB.epoch_ms) {
    return createdA.epoch_ms < createdB.epoch_ms ? -1 : 1;
  }`,
      `  if (false) {
    return createdA.epoch_ms < createdB.epoch_ms ? -1 : 1;
  }`,
    )],
  },
  {
    id: "canonical_order_drops_scan_id_tiebreak",
    changes: [replacement(
      "support",
      `  return compareBytewise(a?.scan_id, b?.scan_id);`,
      `  return 0;`,
    )],
  },
  {
    id: "sqlite_space_timestamp_interpreted_as_local_time",
    changes: [replacement(
      "support",
      `  const epochMs = localEpoch - offsetMinutes * 60_000;`,
      `  const epochMs = sqlite
    ? new Date(value).getTime()
    : localEpoch - offsetMinutes * 60_000;`,
    )],
  },
  {
    id: "d1_binding_capacity_off_by_one",
    validator: "portfolio",
    changes: [replacement(
      "support",
      `export const ASSET_LIFECYCLE_D1_BINDING_LIMIT = 100;`,
      `export const ASSET_LIFECYCLE_D1_BINDING_LIMIT = 101;`,
    )],
  },
  {
    id: "delivery_bypasses_shared_replay",
    changes: [replacement(
      "delivery",
      `    : loadAssetLifecycleEventSupport(env, {`,
      `    : loadLegacyPhysicalLifecycleRows(env, {`,
    )],
  },
  {
    id: "neutral_rows_suppress_removal_alert",
    changes: [replacement(
      "support",
      `      row.scan_id !== anchor.scan_id && isDecisionRelevantLifecycleObservation(row)),`,
      `      row.scan_id !== anchor.scan_id &&
        (eventType === "asset_no_longer_seen" || isDecisionRelevantLifecycleObservation(row))),`,
    )],
  },
  {
    id: "neutral_rows_suppress_reappearance_alert",
    changes: [replacement(
      "support",
      `      row.scan_id !== anchor.scan_id && isDecisionRelevantLifecycleObservation(row)),`,
      `      row.scan_id !== anchor.scan_id &&
        (eventType === "asset_reappeared" || isDecisionRelevantLifecycleObservation(row))),`,
    )],
  },
  {
    id: "null_asset_becomes_unsupported",
    changes: [replacement(
      "support",
      `    return uncertain("withheld_support_not_evaluable", "asset_identity_not_recorded", eventType);`,
      `    return { state: "unsupported", evidence_backed: false,
      reason_code: "withheld_removal_confirmation_not_satisfied",
      limitation: null, limitation_codes: [], event_type: eventType };`,
    )],
  },
  {
    id: "null_scan_becomes_unsupported",
    changes: [replacement(
      "support",
      `    return uncertain("withheld_support_not_evaluable", "event_scan_not_recorded", eventType);`,
      `    return { state: "unsupported", evidence_backed: false,
      reason_code: "withheld_removal_confirmation_not_satisfied",
      limitation: null, limitation_codes: [], event_type: eventType };`,
    )],
  },
  {
    id: "missing_anchor_becomes_unsupported",
    changes: [replacement(
      "support",
      `    return uncertain(
      "withheld_lifecycle_evidence_not_recorded",
      "exact_lifecycle_anchor_absent",
      eventType,
    );`,
      `    return { state: "unsupported", evidence_backed: false,
      reason_code: "withheld_removal_confirmation_not_satisfied",
      limitation: null, limitation_codes: [], event_type: eventType };`,
    )],
  },
  {
    id: "schema_absent_becomes_zero",
    changes: [replacement(
      "support",
      `function unavailableProjection(descriptors, scope, status, coverageReason = null) {
  const reason = coverageReason || (status === "schema_absent"
    ? "lifecycle_schema_absent"
    : "lifecycle_evidence_read_failed");
  return {
    ...projectionBase(scope),
    coverage: "unavailable",
    coverage_reason: reason,`,
      `function unavailableProjection(descriptors, scope, status, coverageReason = null) {
  const reason = coverageReason || (status === "schema_absent"
    ? "lifecycle_schema_absent"
    : "lifecycle_evidence_read_failed");
  return {
    ...projectionBase(scope),
    coverage: status === "schema_absent" ? "complete" : "unavailable",
    coverage_reason: status === "schema_absent" ? null : reason,`,
    )],
  },
  {
    id: "read_failure_becomes_zero",
    changes: [replacement(
      "support",
      `    const failedStatus = failedWorkspaceStatus.get(workspaceId);`,
      `    const recordedFailure = failedWorkspaceStatus.get(workspaceId);
    const failedStatus = recordedFailure === "unavailable" ? null : recordedFailure;`,
    )],
  },
  {
    id: "unknown_policy_becomes_unsupported",
    changes: [replacement(
      "support",
      `      interpretationLimitations.push("unknown_policy_version");`,
      `      return { state: "unsupported", evidence_backed: false,
        reason_code: "withheld_removal_confirmation_not_satisfied",
        limitation: null, limitation_codes: [], event_type: eventType };`,
    )],
  },
  {
    id: "malformed_source_detail_becomes_unsupported",
    changes: [replacement(
      "support",
      `      interpretationLimitations.push("malformed_source_detail");`,
      `      return { state: "unsupported", evidence_backed: false,
        reason_code: "withheld_removal_confirmation_not_satisfied",
        limitation: null, limitation_codes: [], event_type: eventType };`,
    )],
  },
  {
    id: "invalid_relevant_timestamp_becomes_unsupported",
    changes: [replacement(
      "support",
      `    initialLimitations.push("invalid_relevant_timestamp");`,
      `      return { state: "unsupported", evidence_backed: false,
        reason_code: "withheld_removal_confirmation_not_satisfied",
        limitation: null, limitation_codes: [], event_type: eventType };`,
    )],
  },
  {
    id: "replay_truncation_publishes_partial_count",
    changes: [replacement(
      "support",
      `  if (base.coverage !== "complete") {`,
      `  if (false) {`,
    )],
  },
  {
    id: "hostname_fallback_borrows_evidence",
    changes: [replacement(
      "support",
      `    (row) => row?.asset_id === event.asset_id,`,
      `    (row) => row?.asset_id === event.asset_id || row?.hostname === event.hostname,`,
    )],
  },
  {
    id: "workspace_scope_removed",
    changes: [replacement(
      "support",
      `  if (descriptors.some((descriptor) => !allowed.has(descriptor.workspace_id))) {
    for (const workspaceId of allowedWorkspaceIds) {
      result.set(workspaceId, unavailableProjection(
        byWorkspace.get(workspaceId), scope, "unavailable", "workspace_scope_mismatch",
      ));
    }
    return result;
  }
  for (const descriptor of descriptors) byWorkspace.get(descriptor.workspace_id).push(descriptor);`,
      `  // Mutant: silently admit event-owned workspaces outside the caller's allowlist.
  for (const descriptor of descriptors) {
    if (!byWorkspace.has(descriptor.workspace_id)) {
      byWorkspace.set(descriptor.workspace_id, []);
      allowedWorkspaceIds.push(descriptor.workspace_id);
    }
    byWorkspace.get(descriptor.workspace_id).push(descriptor);
  }`,
    )],
  },
  {
    id: "unsupported_enters_supported_count",
    changes: [replacement(
      "support",
      `    const state = ["supported", "unsupported", "uncertain"].includes(claim.state)
      ? claim.state
      : "uncertain";`,
      `    const state = claim.state === "unsupported"
      ? "supported"
      : ["supported", "unsupported", "uncertain"].includes(claim.state)
        ? claim.state
        : "uncertain";`,
    )],
  },
  {
    id: "uncertain_enters_supported_count",
    changes: [replacement(
      "support",
      `    const state = ["supported", "unsupported", "uncertain"].includes(claim.state)
      ? claim.state
      : "uncertain";`,
      `    const state = claim.state === "uncertain"
      ? "supported"
      : ["supported", "unsupported", "uncertain"].includes(claim.state)
        ? claim.state
        : "uncertain";`,
    )],
  },
  {
    id: "supported_reappearance_enters_no_longer_observed_count",
    changes: [replacement(
      "support",
      `    byType[event.event_type].total += 1;
    byType[event.event_type][state] += 1;`,
      `    const countType = event.event_type === "asset_reappeared"
      ? "asset_no_longer_seen"
      : event.event_type;
    if (!byType[countType]) byType[countType] = { total: 0, supported: 0, unsupported: 0, uncertain: 0 };
    byType[countType].total += 1;
    byType[countType][state] += 1;`,
    )],
  },
  {
    id: "route_reappearance_enters_no_longer_observed_count",
    cases: Object.freeze([
      {
        name: "asset_timeline_all",
        validator: "customerParity",
        changes: [replacement(
          "attackSurface",
          `          const projected = await projectLifecycleEvents(
            env,
            wsId,
            result.results || [],
            "asset_timeline_all",
          );
          const legacyTimeline = countCustomerTimelineEventsByDay(
            result.results || [],
            EVENT_TYPES,
          );
          const supportedNoLongerByDay = new Map();
          if (projected.summary.coverage === "complete") {
            for (const event of projected.events) {
              if (
                event.event_type === "asset_no_longer_seen" &&`,
          `          const projected = await projectLifecycleEvents(
            env,
            wsId,
            result.results || [],
            "asset_timeline_all",
          );
          const legacyTimeline = countCustomerTimelineEventsByDay(
            result.results || [],
            EVENT_TYPES,
          );
          const supportedNoLongerByDay = new Map();
          if (projected.summary.coverage === "complete") {
            for (const event of projected.events) {
              if (
                ["asset_no_longer_seen", "asset_reappeared"].includes(event.event_type) &&`,
        )],
      },
      {
        name: "posture_timeline_90d",
        validator: "customerParity",
        changes: [replacement(
        "attackSurface",
          `          const projected = await projectLifecycleEvents(
            env,
            wsId,
            eventRows.results || [],
            "posture_timeline_90d",
          );
          const supportedNoLongerByDay = new Map();
          if (projected.summary.coverage === "complete") {
            for (const event of projected.events) {
              if (
                event.event_type === "asset_no_longer_seen" &&`,
          `          const projected = await projectLifecycleEvents(
            env,
            wsId,
            eventRows.results || [],
            "posture_timeline_90d",
          );
          const supportedNoLongerByDay = new Map();
          if (projected.summary.coverage === "complete") {
            for (const event of projected.events) {
              if (
                ["asset_no_longer_seen", "asset_reappeared"].includes(event.event_type) &&`,
        )],
      },
    ]),
  },
  {
    id: "asset_timeline_collapses_before_projection",
    changes: [replacement(
      "attackSurface",
      `          const timelineDays = buildProjectionAwareTimelineDays(\n            legacyTimeline`,
      `          const timelineDays = buildProjectionAwareTimelineDays(\n            []`,
    )],
  },
  {
    id: "posture_timeline_collapses_before_projection",
    changes: [replacement(
      "attackSurface",
      `          const timelineDays = buildProjectionAwareTimelineDays(\n            [...eventMap.values()]`,
      `          const timelineDays = buildProjectionAwareTimelineDays(\n            []`,
    )],
  },
  {
    id: "timestamp_outranks_replay_completeness",
    changes: [replacement(
      "support",
      `  if (!replayComplete) initialLimitations.push("bounded_relevant_replay_truncated");`,
      `  if (false && !replayComplete) initialLimitations.push("bounded_relevant_replay_truncated");`,
    )],
  },
  {
    id: "secondary_limitation_is_dropped",
    changes: [replacement(
      "support",
      `    initialLimitations.push("invalid_relevant_timestamp");`,
      `    // mutant: secondary limitation dropped`,
    )],
  },
  {
    id: "limitation_order_is_unstable",
    changes: [replacement(
      "support",
      `    LIMITATION_PRECEDENCE.indexOf(a) - LIMITATION_PRECEDENCE.indexOf(b));`,
      `    LIMITATION_PRECEDENCE.indexOf(b) - LIMITATION_PRECEDENCE.indexOf(a));`,
    )],
  },
  {
    id: "malformed_source_detail_hidden_by_unknown_policy",
    changes: [replacement(
      "support",
      `    if (!parsed.valid) {`,
      `    if (false && !parsed.valid) {`,
    )],
  },
  {
    id: "count_partition_drops_non_lifecycle",
    changes: [replacement(
      "support",
      `      counts.non_lifecycle += 1;`,
      `      // mutant: non-lifecycle partition silently dropped`,
    )],
  },
  {
    id: "raw_description_renders_unqualified",
    changes: [replacement(
      "support",
      `    description,
    lifecycle_claim_support: {`,
      `    description: event?.description || description,
    lifecycle_claim_support: {`,
    )],
  },
  {
    id: "unsupported_or_uncertain_row_collapses",
    changes: [replacement(
      "timeline",
      `    if (
      ["unsupported", "uncertain"].includes(
        indexed.row?.lifecycle_claim_support?.state,
      )
    ) continue;`,
      `    if (false) continue;`,
    )],
  },
  {
    id: "legacy_schedule_writer_bypasses_projection",
    changes: [replacement(
      "index",
      `        const persisted = await persistScheduledAssetChangeProjection(env, {
          scheduleId: schedule.id,
          workspaceId: schedule.workspace_id,
          scanId,
        });`,
      `        const persisted = await persistLegacyAssetCountOnly(env, {
          scheduleId: schedule.id,
          workspaceId: schedule.workspace_id,
          scanId,
        });`,
    )],
  },
  {
    id: "queue_schedule_writer_bypasses_projection",
    changes: [replacement(
      "index",
      `      const persisted = await persistScheduledAssetChangeProjection(env, {
        scheduleId: schedRow.id,
        workspaceId: row.workspace_id,
        scanId,
      });`,
      `      const persisted = await persistLegacyAssetCountOnly(env, {
        scheduleId: schedRow.id,
        workspaceId: row.workspace_id,
        scanId,
      });`,
    )],
  },
  {
    id: "schedule_null_projection_renders_zero",
    changes: [replacement(
      "scans",
      `  if (typeof value !== "string" || value.length === 0) return null;`,
      `  if (typeof value !== "string" || value.length === 0) return { customer_change_count: 0 };`,
    )],
  },
  {
    id: "honest_summary_reverts_to_legacy_raw",
    changes: [replacement(
      "attackSurface",
      `            no_longer_observed_assets_30d: noLongerObservedAssets30d,`,
      `            no_longer_observed_assets_30d: removedAssets30d,`,
    )],
  },
  {
    id: "honest_timeline_reverts_to_legacy_raw",
    changes: [replacement(
      "attackSurface",
      `                projected.summary.coverage === "complete"
                  ? supportedNoLongerByDay.get(day) || 0
                  : null,`,
      `                projected.summary.coverage === "complete"
                  ? ev.removed_assets
                  : null,`,
    )],
  },
]);

let passed = 0;
let failed = 0;
let mutantsKilled = 0;
function check(name, condition, detail = "") {
  if (condition) passed += 1;
  else {
    failed += 1;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

function parityResult({ routeSource = null, assetsPageSource = null }) {
  const sandbox = createMutationSandbox(ROOT, "item10-p5-control-");
  try {
    const env = { ...process.env };
    if (routeSource != null) {
      const routeFile = path.join(sandbox.workerSource, "routes/attack-surface.js");
      fs.writeFileSync(routeFile, routeSource);
      env.ITEM10_P5_ROUTE_MODULE_URL = pathToFileURL(routeFile).href;
    }
    if (assetsPageSource != null) {
      const assetsPageFile = path.join(sandbox.tempRoot, "AssetsPage.jsx");
      fs.writeFileSync(assetsPageFile, assetsPageSource);
      env.ITEM10_P5_ASSETS_PAGE_SOURCE = assetsPageFile;
    }

    const child = spawnSync(process.execPath, [CUSTOMER_PARITY_VALIDATOR], {
      cwd: ROOT,
      encoding: "utf8",
      env,
    });
    const output = `${child.stdout || ""}\n${child.stderr || ""}`;
    const actualFailures = output
      .split(/\r?\n/)
      .filter((line) => line.startsWith("FAIL "))
      .map((line) => line.slice(5).split(" — ")[0]);
    const summaries = [...output.matchAll(
      /Item 10 P5 customer parity: (\d+)\/(\d+) assertions passed/g,
    )];
    return { child, output, actualFailures, summaries };
  } finally {
    sandbox.cleanup();
  }
}

function rejectedPreflight(kind) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), `item10-p5-${kind}-`));
  try {
    if (kind === "module") {
      const target = path.join(tmp, "unsupported.txt");
      fs.writeFileSync(target, "export default true;\n");
      return preflightMutationTargets({ moduleUrls: [pathToFileURL(target).href] });
    }
    const target = path.join(tmp, `${kind}.mjs`);
    const source = {
      syntax: "this is not valid JavaScript !\n",
      import: `import "./missing-negative-control.mjs";\n`,
      runtime: `throw new TypeError("negative-control-runtime");\n`,
    }[kind];
    fs.writeFileSync(target, source);
    return preflightMutationTargets({ moduleUrls: [pathToFileURL(target).href] });
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

function parityHasExactFailure(result, expectedFailure) {
  return result.child.status === 1 && result.child.signal == null &&
    result.summaries.length === 1 &&
    Number(result.summaries[0][2]) === EXPECTED_CUSTOMER_PARITY_ASSERTIONS &&
    JSON.stringify(result.actualFailures) === JSON.stringify([expectedFailure]);
}

function parityIsClean(result) {
  return result.child.status === 0 && result.child.signal == null &&
    result.summaries.length === 1 &&
    Number(result.summaries[0][1]) === EXPECTED_CUSTOMER_PARITY_ASSERTIONS &&
    Number(result.summaries[0][2]) === EXPECTED_CUSTOMER_PARITY_ASSERTIONS &&
    result.actualFailures.length === 0;
}

function runNegativeControls() {
  let controlsPassed = 0;
  let controlsFailed = 0;
  const registeredControls = [];
  const control = (id, condition, detail = "") => {
    registeredControls.push(id);
    if (condition) {
      controlsPassed += 1;
      console.log(`PASS ${id}`);
    } else {
      controlsFailed += 1;
      console.error(`FAIL ${id}${detail ? ` — ${detail}` : ""}`);
    }
  };

  const registryAnalysis = (registeredIds) => analyseOrderedRegistry({
    registeredIds,
    expectedIds: EXPECTED_ARM2_MUTANT_IDS,
    expectedCount: EXPECTED_ARM2_MUTANT_COUNT,
    expectedFailureIds: Object.keys(EXPECTED_FAILURES),
  });
  const missingAnalysis = registryAnalysis(EXPECTED_ARM2_MUTANT_IDS.slice(0, -1));
  control("registry_missing_name",
    !missingAnalysis.valid && missingAnalysis.missing.length === 1 &&
      missingAnalysis.unexpected.length === 0);
  const reordered = [...EXPECTED_ARM2_MUTANT_IDS];
  [reordered[0], reordered[1]] = [reordered[1], reordered[0]];
  const reorderedAnalysis = registryAnalysis(reordered);
  control("registry_reordered_name",
    !reorderedAnalysis.valid && reorderedAnalysis.countExact &&
      !reorderedAnalysis.exactOrder && reorderedAnalysis.missing.length === 0 &&
      reorderedAnalysis.unexpected.length === 0 &&
      reorderedAnalysis.duplicates.length === 0);
  const duplicated = [...EXPECTED_ARM2_MUTANT_IDS];
  duplicated[duplicated.length - 1] = duplicated[0];
  const duplicateAnalysis = registryAnalysis(duplicated);
  control("registry_duplicate_name",
    !duplicateAnalysis.valid && duplicateAnalysis.duplicates.length === 1);
  const unexpected = [...EXPECTED_ARM2_MUTANT_IDS];
  unexpected[unexpected.length - 1] = "unexpected_mutant";
  const unexpectedAnalysis = registryAnalysis(unexpected);
  control("registry_unexpected_name",
    !unexpectedAnalysis.valid && unexpectedAnalysis.unexpected.length === 1 &&
      unexpectedAnalysis.duplicates.length === 0);

  const semanticEnvelope = (
    preflight,
    childOverrides = {},
    envelopeOverrides = {},
  ) => {
    const expectedFailures = ["semantic_contract"];
    const expectedPassed = EXPECTED_VALIDATOR_ASSERTIONS - expectedFailures.length;
    const output = `FAIL semantic_contract: negative control\n` +
      `ITEM10_P5_ARM2: ${expectedPassed}/${EXPECTED_VALIDATOR_ASSERTIONS} PASS\n`;
    return classifySemanticMutation({
      child: { status: 1, signal: null, error: null, ...childOverrides },
      output: envelopeOverrides.output ?? output,
      actualFailures: envelopeOverrides.actualFailures ?? expectedFailures,
      expectedFailures,
      summaries: envelopeOverrides.summaries ?? [{
        passed: expectedPassed,
        total: EXPECTED_VALIDATOR_ASSERTIONS,
      }],
      expectedAssertions: EXPECTED_VALIDATOR_ASSERTIONS,
      preflight,
    }).killed;
  };
  const acceptedPreflight = { ok: true, failures: [] };
  control("mutant_syntax_failure_is_not_kill",
    !semanticEnvelope(rejectedPreflight("syntax")));
  control("mutant_import_failure_is_not_kill",
    !semanticEnvelope(rejectedPreflight("import")));
  control("mutant_runtime_failure_is_not_kill",
    !semanticEnvelope(rejectedPreflight("runtime")) &&
      !semanticEnvelope(acceptedPreflight, { status: null, signal: "SIGSEGV" }) &&
      !semanticEnvelope(acceptedPreflight, { status: 2 }) &&
      !semanticEnvelope(acceptedPreflight, {}, {
        output: "TypeError: mutation crashed before semantic completion\n",
      }));
  const modulePreflight = rejectedPreflight("module");
  control("mutant_module_failure_is_not_kill",
    !semanticEnvelope(modulePreflight) &&
      !semanticEnvelope(acceptedPreflight, {
        error: new Error("spawn/module negative control"),
      }));

  const canonicalRoute = fs.readFileSync(TARGETS.attackSurface.file, "utf8");
  const summaryResult = parityResult({
    routeSource: replaceExactly(
      canonicalRoute,
      `            no_longer_observed_assets_30d: noLongerObservedAssets30d,`,
      `            no_longer_observed_assets_30d: removedAssets30d,`,
      "summary output-bound negative control",
    ),
  });
  control("summary_output_bound_assertion_fails_on_raw_parity",
    parityHasExactFailure(
      summaryResult,
      "posture summary keeps unsupported raw history out of honest count",
    ) &&
      !semanticEnvelope(acceptedPreflight, {}, { summaries: [] }) &&
      !semanticEnvelope(acceptedPreflight, {}, {
        summaries: [
          { passed: EXPECTED_VALIDATOR_ASSERTIONS - 1, total: EXPECTED_VALIDATOR_ASSERTIONS },
          { passed: EXPECTED_VALIDATOR_ASSERTIONS - 1, total: EXPECTED_VALIDATOR_ASSERTIONS },
        ],
      }) &&
      !semanticEnvelope(acceptedPreflight, {}, {
        summaries: [{
          passed: EXPECTED_VALIDATOR_ASSERTIONS - 1,
          total: EXPECTED_VALIDATOR_ASSERTIONS - 1,
        }],
      }), `status=${summaryResult.child.status} signal=${summaryResult.child.signal} ` +
      `summaries=${summaryResult.summaries.length} ` +
      `failures=${JSON.stringify(summaryResult.actualFailures)} ` +
      `output=${JSON.stringify(summaryResult.output.slice(-600))}`);

  const timelineResult = parityResult({
    routeSource: replaceExactly(
      canonicalRoute,
      `                  ? supportedNoLongerByDay.get(day) || 0
                  : null,`,
      `                  ? ev.removed_assets
                  : null,`,
      "timeline output-bound negative control",
    ),
  });
  control("timeline_output_bound_assertion_fails_on_raw_parity",
    parityHasExactFailure(
      timelineResult,
      "posture timeline preserves raw history but excludes unsupported honest count",
    ), `status=${timelineResult.child.status} signal=${timelineResult.child.signal} ` +
      `summaries=${timelineResult.summaries.length} ` +
      `failures=${JSON.stringify(timelineResult.actualFailures)} ` +
      `output=${JSON.stringify(timelineResult.output.slice(-600))}`);

  const canonicalAssetsPage = fs.readFileSync(
    path.join(ROOT, "frontend/src/pages/AssetsPage.jsx"),
    "utf8",
  );
  const vocabularyResult = parityResult({
    assetsPageSource: `${canonicalAssetsPage}\nconst SIGNAL_STATE_LABELS = {};\n`,
  });
  const nearMatchResult = parityResult({
    assetsPageSource: `${canonicalAssetsPage}\nconst SIGNAL_STATE_LABEL = {};\n`,
  });
  control("frontend_vocabulary_guard_detects_real_declaration",
    parityHasExactFailure(
      vocabularyResult,
      "frontend owns no second ASM state vocabulary",
    ) && parityIsClean(nearMatchResult),
  `real_status=${vocabularyResult.child.status} real_summaries=${vocabularyResult.summaries.length} ` +
      `real=${JSON.stringify(vocabularyResult.actualFailures)} ` +
      `near_status=${nearMatchResult.child.status} near_summaries=${nearMatchResult.summaries.length} ` +
      `near=${JSON.stringify(nearMatchResult.actualFailures)} ` +
      `real_output=${JSON.stringify(vocabularyResult.output.slice(-600))}`);

  let zeroRejected = false;
  try {
    replaceExactly("no anchor", "missing", "replacement", "zero control");
  } catch {
    zeroRejected = true;
  }
  control("mutation_anchor_zero_replacements_fails", zeroRejected);
  let multipleRejected = false;
  try {
    replaceExactly("anchor anchor", "anchor", "replacement", "multiple control");
  } catch {
    multipleRejected = true;
  }
  control("mutation_anchor_multiple_replacements_fails", multipleRejected);

  const registryExact =
    JSON.stringify(registeredControls) ===
      JSON.stringify(EXPECTED_NEGATIVE_CONTROL_IDS) &&
    registeredControls.length === EXPECTED_NEGATIVE_CONTROL_COUNT &&
    EXPECTED_NEGATIVE_CONTROL_IDS.length === EXPECTED_NEGATIVE_CONTROL_COUNT;
  if (!registryExact) {
    controlsFailed += 1;
    console.error("FAIL negative-control registry is exact and ordered");
  }
  console.log(
    `ITEM10_P5_MUTATION_CONTROLS: ${controlsPassed}/${EXPECTED_NEGATIVE_CONTROL_COUNT} PASS`,
  );
  return { controlsPassed, controlsFailed, registryExact };
}

const canonicalTargetFiles = () => filesUnder(path.join(WORKER_ROOT, "src"));
const initialTargetFingerprint = fingerprintFiles(canonicalTargetFiles);
let mutationCasesKilled = 0;
let mutationReplacementsApplied = 0;

function casesFor(mutant) {
  return mutant.cases || [{
    name: "default",
    validator: mutant.validator || "arm2",
    changes: mutant.changes,
  }];
}

function expectedFailuresFor(mutant, mutationCase) {
  const registered = EXPECTED_FAILURES[mutant.id];
  return Array.isArray(registered) ? registered : registered?.[mutationCase.name];
}

function executeMutationCase(mutant, mutationCase) {
  const caseId = mutationCase.name === "default"
    ? mutant.id
    : `${mutant.id}/${mutationCase.name}`;
  const sandbox = createMutationSandbox(ROOT, "item10-p5-arm2-mutant-");
  const env = { ...process.env, TZ: "Europe/London" };
  let anchorCount = 0;
  try {
    const changedTargets = new Map();
    for (const change of mutationCase.changes) {
      const target = TARGETS[change.target];
      if (!target) throw new Error(`${caseId}: unknown target ${change.target}`);
      const current = changedTargets.get(change.target) ??
        fs.readFileSync(target.file, "utf8");
      const mutated = replaceExactly(
        current,
        change.from,
        change.to,
        `${caseId}/${change.target}`,
      );
      anchorCount += 1;
      changedTargets.set(change.target, mutated);
    }

    const moduleUrls = [];
    const sourceFiles = [];
    for (const [targetName, content] of changedTargets) {
      const target = TARGETS[targetName];
      const relative = path.relative(path.join(WORKER_ROOT, "src"), target.file);
      const file = path.join(sandbox.workerSource, relative);
      fs.writeFileSync(file, content);
      if (mutationCase.validator === "customerParity") {
        if (targetName !== "attackSurface") {
          throw new Error(`${caseId}: customer parity supports only attackSurface mutations`);
        }
        env.ITEM10_P5_ROUTE_MODULE_URL = pathToFileURL(file).href;
        moduleUrls.push(pathToFileURL(file).href);
      } else if (mutationCase.validator === "portfolio") {
        if (!target.module) {
          throw new Error(`${caseId}: portfolio mutations must target importable modules`);
        }
        moduleUrls.push(pathToFileURL(file).href);
      } else {
        env[target.env] = target.module ? pathToFileURL(file).href : file;
        if (target.module) moduleUrls.push(pathToFileURL(file).href);
        else sourceFiles.push(file);
      }
    }
    const preflight = preflightMutationTargets({ moduleUrls, sourceFiles });
    let validator = VALIDATOR;
    let cwd = ROOT;
    if (mutationCase.validator === "customerParity") {
      validator = CUSTOMER_PARITY_VALIDATOR;
    } else if (mutationCase.validator === "portfolio") {
      const scriptsRoot = path.join(sandbox.tempRoot, "scripts");
      fs.mkdirSync(scriptsRoot, { recursive: true });
      validator = path.join(scriptsRoot, path.basename(PORTFOLIO_VALIDATOR));
      fs.copyFileSync(PORTFOLIO_VALIDATOR, validator);
      fs.symlinkSync(path.join(ROOT, "database"), path.join(sandbox.tempRoot, "database"), "dir");
      cwd = sandbox.tempRoot;
    }
    const child = spawnSync(process.execPath, [validator], {
      cwd,
      encoding: "utf8",
      env,
    });
    const output = `${child.stdout || ""}\n${child.stderr || ""}`;
    const actualFailures = output
      .split(/\r?\n/)
      .filter((line) => line.startsWith("FAIL "))
      .map((line) => {
        if (mutationCase.validator === "customerParity") {
          return line.slice(5).split(" — ")[0];
        }
        if (mutationCase.validator === "portfolio") return line.slice(5);
        return line.slice(5).split(": ")[0];
      });
    const summaryPattern = mutationCase.validator === "customerParity"
      ? /Item 10 P5 customer parity: (\d+)\/(\d+) assertions passed/g
      : mutationCase.validator === "portfolio"
        ? /Portfolio: (\d+)\/(\d+) passed/g
        : /ITEM10_P5_ARM2: (\d+)\/(\d+) PASS/g;
    const summaryMatches = [...output.matchAll(summaryPattern)];
    const summaries = summaryMatches.map((summary) => ({
      passed: Number(summary[1]),
      total: Number(summary[2]),
    }));
    const expectedAssertions = mutationCase.validator === "customerParity"
      ? EXPECTED_CUSTOMER_PARITY_ASSERTIONS
      : mutationCase.validator === "portfolio"
        ? EXPECTED_PORTFOLIO_ASSERTIONS
        : EXPECTED_VALIDATOR_ASSERTIONS;
    const expectedFailures = expectedFailuresFor(mutant, mutationCase);
    const classified = classifySemanticMutation({
      child,
      output,
      actualFailures,
      expectedFailures,
      summaries,
      expectedAssertions,
      preflight,
    });
    return {
      caseId,
      killed: classified.killed,
      completedSemantically: classified.completedSemantically,
      anchorCount,
      expectedAnchors: mutationCase.changes.length,
      child,
      summaries,
      preflight,
      actualFailures,
    };
  } finally {
    sandbox.cleanup();
    if (fingerprintFiles(canonicalTargetFiles) !== initialTargetFingerprint) {
      throw new Error(`${caseId}: canonical mutation targets changed`);
    }
  }
}

if (!CONTROLS_ONLY) {
  for (const mutant of MUTANTS) {
    let identityKilled = true;
    for (const mutationCase of casesFor(mutant)) {
      let result = null;
      try {
        result = executeMutationCase(mutant, mutationCase);
        if (result.killed) mutationCasesKilled += 1;
        else identityKilled = false;
        mutationReplacementsApplied += result.anchorCount;
        check(`${result.caseId}: exact semantic kill`, result.killed,
          `status=${result.child.status} signal=${result.child.signal} ` +
          `semantic=${result.completedSemantically} summaries=${result.summaries.length} ` +
          `preflight=${JSON.stringify(result.preflight.failures)} ` +
          `failures=${JSON.stringify(result.actualFailures)}`);
        check(`${result.caseId}: exact mutation replacement count`,
          result.anchorCount === result.expectedAnchors,
          `anchors=${result.anchorCount} expected=${result.expectedAnchors}`);
      } catch (error) {
        identityKilled = false;
        const caseId = mutationCase.name === "default"
          ? mutant.id
          : `${mutant.id}/${mutationCase.name}`;
        check(`${caseId}: exact semantic kill`, false, String(error?.message || error));
        check(`${caseId}: exact mutation replacement count`, false,
          String(error?.message || error));
      }
    }
    if (identityKilled) mutantsKilled += 1;
  }

  const registeredIds = MUTANTS.map((mutant) => mutant.id);
  const registry = analyseOrderedRegistry({
    registeredIds,
    expectedIds: EXPECTED_ARM2_MUTANT_IDS,
    expectedCount: EXPECTED_ARM2_MUTANT_COUNT,
    expectedFailureIds: Object.keys(EXPECTED_FAILURES),
  });
  const actualCaseCount = MUTANTS.reduce(
    (count, mutant) => count + casesFor(mutant).length,
    0,
  );
  const actualReplacementCount = MUTANTS.reduce(
    (count, mutant) => count + casesFor(mutant).reduce(
      (caseCount, mutationCase) => caseCount + mutationCase.changes.length,
      0,
    ),
    0,
  );
  const failureSetsComplete = MUTANTS.every((mutant) => {
    const registered = EXPECTED_FAILURES[mutant.id];
    if (Array.isArray(registered)) return registered.length > 0;
    const cases = casesFor(mutant);
    return registered &&
      JSON.stringify(Object.keys(registered)) ===
        JSON.stringify(cases.map((mutationCase) => mutationCase.name)) &&
      Object.values(registered).every(
        (failures) => Array.isArray(failures) && failures.length > 0,
      );
  });
  check("33-mutant identity registry is exact, unique and ordered",
    registry.exactOrder && registry.duplicates.length === 0 &&
      registry.missing.length === 0 && registry.unexpected.length === 0);
  check("33-mutant, 34-case and 35-replacement denominators are independent literals",
    registry.countExact && actualCaseCount === EXPECTED_ARM2_MUTATION_CASE_COUNT &&
      actualReplacementCount === EXPECTED_ARM2_MUTATION_REPLACEMENT_COUNT);
  check("expected failure-set registry is independently complete",
    registry.failureRegistryExact && failureSetsComplete);
  const harnessSource = fs.readFileSync(fileURLToPath(import.meta.url), "utf8");
  check("mutant registrations are separately authored literals",
    !/\bid:\s*EXPECTED_ARM2_MUTANT_IDS\s*\[/.test(harnessSource));
  check("canonical mutation targets remain byte-identical after sandboxed cases",
    fingerprintFiles(canonicalTargetFiles) === initialTargetFingerprint);
  const signalCleanupProof = handledSignalCleansSandbox({
    root: ROOT,
    files: canonicalTargetFiles,
  });
  check("handled termination cleans the dedicated mutation sandbox",
    signalCleanupProof.ok, JSON.stringify(signalCleanupProof));
  check("forced interruption cannot write into canonical mutation targets",
    forcedInterruptionLeavesFingerprint({ files: canonicalTargetFiles }));
}

const controls = runNegativeControls();
if (!CONTROLS_ONLY) {
  const expectedAssertions = EXPECTED_ARM2_MUTATION_CASE_COUNT * 2 + 4 +
    EXPECTED_HARNESS_SAFETY_ASSERTIONS;
  console.log(
    `ITEM10_P5_ARM2_MUTATIONS: ${passed}/${expectedAssertions} PASS; ` +
    `${mutantsKilled}/${EXPECTED_ARM2_MUTANT_COUNT} identities; ` +
    `${mutationCasesKilled}/${EXPECTED_ARM2_MUTATION_CASE_COUNT} cases; ` +
    `${mutationReplacementsApplied}/${EXPECTED_ARM2_MUTATION_REPLACEMENT_COUNT} replacements`,
  );
  if (
    failed || passed !== expectedAssertions ||
    mutantsKilled !== EXPECTED_ARM2_MUTANT_COUNT ||
    mutationCasesKilled !== EXPECTED_ARM2_MUTATION_CASE_COUNT ||
    mutationReplacementsApplied !== EXPECTED_ARM2_MUTATION_REPLACEMENT_COUNT ||
    controls.controlsFailed ||
    controls.controlsPassed !== EXPECTED_NEGATIVE_CONTROL_COUNT
  ) process.exit(1);
} else if (
  controls.controlsFailed ||
  controls.controlsPassed !== EXPECTED_NEGATIVE_CONTROL_COUNT
) process.exit(1);
