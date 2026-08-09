-- Item 10 P5 Arm 2: preserve the legacy raw scheduled asset-change count while
-- storing the exact, versioned lifecycle-support projection for that run.
-- Additive and nullable by design; historical rows remain not evaluated.
ALTER TABLE scheduled_scans
  ADD COLUMN asset_change_projection_json TEXT;
