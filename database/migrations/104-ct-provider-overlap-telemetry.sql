-- CT-R2 PR-2A: policy-independent CT provider-overlap telemetry.
-- Additive, append-only and internal-only. This migration is committed for a
-- later controlled release; the implementation PR does not apply it.

CREATE TABLE IF NOT EXISTS ct_provider_overlap_telemetry (
    id                                      TEXT PRIMARY KEY,
    scan_id                                 TEXT NOT NULL,
    module                                  TEXT NOT NULL CHECK (module = 'subdomains'),
    source_set_version                      TEXT NOT NULL,
    observed_at                             TEXT NOT NULL,
    normalization_candidate_limit           INTEGER NOT NULL CHECK (normalization_candidate_limit > 0),
    retained_hostname_limit                 INTEGER NOT NULL CHECK (
                                              retained_hostname_limit > 0 AND
                                              retained_hostname_limit <= normalization_candidate_limit
                                            ),

    crt_sh_attempt_state                    TEXT NOT NULL CHECK (crt_sh_attempt_state IN (
                                              'terminal_success', 'terminal_failure',
                                              'not_started', 'in_flight_at_consumer_release'
                                            )),
    crt_sh_raw_record_count                 INTEGER CHECK (crt_sh_raw_record_count >= 0),
    crt_sh_expanded_candidate_count         INTEGER CHECK (crt_sh_expanded_candidate_count >= 0),
    crt_sh_normalization_input_count        INTEGER CHECK (crt_sh_normalization_input_count >= 0),
    crt_sh_normalization_dropped_candidate_count INTEGER CHECK (crt_sh_normalization_dropped_candidate_count >= 0),
    crt_sh_normalization_truncated          INTEGER CHECK (crt_sh_normalization_truncated IN (0, 1)),
    crt_sh_normalized_candidate_count       INTEGER CHECK (crt_sh_normalized_candidate_count >= 0),
    crt_sh_unique_hostname_count            INTEGER CHECK (crt_sh_unique_hostname_count >= 0),
    crt_sh_retained_hostname_count          INTEGER CHECK (crt_sh_retained_hostname_count >= 0),
    crt_sh_dropped_hostname_count           INTEGER CHECK (crt_sh_dropped_hostname_count >= 0),
    crt_sh_truncated                        INTEGER CHECK (crt_sh_truncated IN (0, 1)),

    certspotter_attempt_state               TEXT NOT NULL CHECK (certspotter_attempt_state IN (
                                              'terminal_success', 'terminal_failure',
                                              'not_started', 'in_flight_at_consumer_release'
                                            )),
    certspotter_raw_record_count            INTEGER CHECK (certspotter_raw_record_count >= 0),
    certspotter_expanded_candidate_count    INTEGER CHECK (certspotter_expanded_candidate_count >= 0),
    certspotter_normalization_input_count   INTEGER CHECK (certspotter_normalization_input_count >= 0),
    certspotter_normalization_dropped_candidate_count INTEGER CHECK (certspotter_normalization_dropped_candidate_count >= 0),
    certspotter_normalization_truncated     INTEGER CHECK (certspotter_normalization_truncated IN (0, 1)),
    certspotter_normalized_candidate_count  INTEGER CHECK (certspotter_normalized_candidate_count >= 0),
    certspotter_unique_hostname_count       INTEGER CHECK (certspotter_unique_hostname_count >= 0),
    certspotter_retained_hostname_count     INTEGER CHECK (certspotter_retained_hostname_count >= 0),
    certspotter_dropped_hostname_count      INTEGER CHECK (certspotter_dropped_hostname_count >= 0),
    certspotter_truncated                   INTEGER CHECK (certspotter_truncated IN (0, 1)),

    comparison_status                       TEXT NOT NULL CHECK (comparison_status IN (
                                              'compared', 'compared_truncated',
                                              'censored_provider_failure',
                                              'censored_in_flight', 'not_started'
                                            )),
    intersection_count                      INTEGER CHECK (intersection_count >= 0),
    crt_sh_only_count                       INTEGER CHECK (crt_sh_only_count >= 0),
    certspotter_only_count                  INTEGER CHECK (certspotter_only_count >= 0),
    union_count                             INTEGER CHECK (union_count >= 0),
    created_at                              TEXT NOT NULL DEFAULT (datetime('now')),

    FOREIGN KEY (scan_id) REFERENCES scans(id),
    UNIQUE (scan_id, module, source_set_version),

    CHECK (
      (
        crt_sh_attempt_state = 'terminal_success' AND
        crt_sh_raw_record_count IS NOT NULL AND
        crt_sh_expanded_candidate_count IS NOT NULL AND
        crt_sh_normalization_input_count IS NOT NULL AND
        crt_sh_normalization_dropped_candidate_count IS NOT NULL AND
        crt_sh_normalization_truncated IS NOT NULL AND
        crt_sh_normalized_candidate_count IS NOT NULL AND
        crt_sh_unique_hostname_count IS NOT NULL AND
        crt_sh_retained_hostname_count IS NOT NULL AND
        crt_sh_dropped_hostname_count IS NOT NULL AND
        crt_sh_truncated IS NOT NULL AND
        crt_sh_normalization_input_count + crt_sh_normalization_dropped_candidate_count = crt_sh_expanded_candidate_count AND
        crt_sh_normalized_candidate_count <= crt_sh_normalization_input_count AND
        crt_sh_unique_hostname_count <= crt_sh_normalized_candidate_count AND
        crt_sh_unique_hostname_count = crt_sh_retained_hostname_count + crt_sh_dropped_hostname_count AND
        crt_sh_retained_hostname_count <= retained_hostname_limit AND
        crt_sh_normalization_truncated = (crt_sh_normalization_dropped_candidate_count > 0) AND
        crt_sh_truncated = (crt_sh_dropped_hostname_count > 0)
      ) OR (
        crt_sh_attempt_state != 'terminal_success' AND
        crt_sh_raw_record_count IS NULL AND crt_sh_expanded_candidate_count IS NULL AND
        crt_sh_normalization_input_count IS NULL AND crt_sh_normalization_dropped_candidate_count IS NULL AND
        crt_sh_normalization_truncated IS NULL AND crt_sh_normalized_candidate_count IS NULL AND
        crt_sh_unique_hostname_count IS NULL AND crt_sh_retained_hostname_count IS NULL AND
        crt_sh_dropped_hostname_count IS NULL AND crt_sh_truncated IS NULL
      )
    ),
    CHECK (
      (
        certspotter_attempt_state = 'terminal_success' AND
        certspotter_raw_record_count IS NOT NULL AND
        certspotter_expanded_candidate_count IS NOT NULL AND
        certspotter_normalization_input_count IS NOT NULL AND
        certspotter_normalization_dropped_candidate_count IS NOT NULL AND
        certspotter_normalization_truncated IS NOT NULL AND
        certspotter_normalized_candidate_count IS NOT NULL AND
        certspotter_unique_hostname_count IS NOT NULL AND
        certspotter_retained_hostname_count IS NOT NULL AND
        certspotter_dropped_hostname_count IS NOT NULL AND
        certspotter_truncated IS NOT NULL AND
        certspotter_normalization_input_count + certspotter_normalization_dropped_candidate_count = certspotter_expanded_candidate_count AND
        certspotter_normalized_candidate_count <= certspotter_normalization_input_count AND
        certspotter_unique_hostname_count <= certspotter_normalized_candidate_count AND
        certspotter_unique_hostname_count = certspotter_retained_hostname_count + certspotter_dropped_hostname_count AND
        certspotter_retained_hostname_count <= retained_hostname_limit AND
        certspotter_normalization_truncated = (certspotter_normalization_dropped_candidate_count > 0) AND
        certspotter_truncated = (certspotter_dropped_hostname_count > 0)
      ) OR (
        certspotter_attempt_state != 'terminal_success' AND
        certspotter_raw_record_count IS NULL AND certspotter_expanded_candidate_count IS NULL AND
        certspotter_normalization_input_count IS NULL AND certspotter_normalization_dropped_candidate_count IS NULL AND
        certspotter_normalization_truncated IS NULL AND certspotter_normalized_candidate_count IS NULL AND
        certspotter_unique_hostname_count IS NULL AND certspotter_retained_hostname_count IS NULL AND
        certspotter_dropped_hostname_count IS NULL AND certspotter_truncated IS NULL
      )
    ),
    CHECK (
      (
        comparison_status IN ('compared', 'compared_truncated') AND
        crt_sh_attempt_state = 'terminal_success' AND
        certspotter_attempt_state = 'terminal_success' AND
        intersection_count IS NOT NULL AND crt_sh_only_count IS NOT NULL AND
        certspotter_only_count IS NOT NULL AND union_count IS NOT NULL AND
        union_count = intersection_count + crt_sh_only_count + certspotter_only_count AND
        (comparison_status = 'compared_truncated') = (
          crt_sh_truncated = 1 OR certspotter_truncated = 1 OR
          crt_sh_normalization_truncated = 1 OR certspotter_normalization_truncated = 1
        )
      ) OR (
        comparison_status NOT IN ('compared', 'compared_truncated') AND
        intersection_count IS NULL AND crt_sh_only_count IS NULL AND
        certspotter_only_count IS NULL AND union_count IS NULL
      )
    ),
    CHECK (
      comparison_status != 'censored_provider_failure' OR
      (crt_sh_attempt_state = 'terminal_failure' OR certspotter_attempt_state = 'terminal_failure')
    ),
    CHECK (
      comparison_status != 'censored_in_flight' OR
      (crt_sh_attempt_state = 'in_flight_at_consumer_release' OR
       certspotter_attempt_state = 'in_flight_at_consumer_release')
    ),
    CHECK (
      comparison_status != 'not_started' OR
      (crt_sh_attempt_state = 'not_started' OR certspotter_attempt_state = 'not_started')
    )
);

CREATE INDEX IF NOT EXISTS idx_ct_provider_overlap_telemetry_scan
  ON ct_provider_overlap_telemetry (scan_id, observed_at);

CREATE INDEX IF NOT EXISTS idx_ct_provider_overlap_telemetry_status_time
  ON ct_provider_overlap_telemetry (comparison_status, observed_at);
