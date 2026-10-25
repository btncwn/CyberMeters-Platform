-- Preserve target identities and historical scan joins when authorisation is withdrawn.
ALTER TABLE network_targets ADD COLUMN withdrawn_at TEXT;
ALTER TABLE network_targets ADD COLUMN withdrawn_by TEXT;
