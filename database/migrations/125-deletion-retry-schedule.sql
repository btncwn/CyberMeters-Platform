-- Keep failed purge requests retryable without making them block healthy work.
ALTER TABLE deletion_requests ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE deletion_requests ADD COLUMN next_attempt_at TEXT;
CREATE INDEX IF NOT EXISTS idx_deletion_requests_retry
  ON deletion_requests (status, next_attempt_at, created_at);
