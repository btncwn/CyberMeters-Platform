-- Automated evidence-based DMARC sender classification.
--
-- Manual classification remains in email_sender_sources.classification and is
-- never overwritten by the classifier. These columns are engine-owned evidence
-- and explainability fields; classified_at is written only by the manual
-- override endpoint as the human-wins signal.

ALTER TABLE email_sender_sources ADD COLUMN auto_classification TEXT;
ALTER TABLE email_sender_sources ADD COLUMN auto_confidence REAL;
ALTER TABLE email_sender_sources ADD COLUMN auto_reasons TEXT;
ALTER TABLE email_sender_sources ADD COLUMN classified_at TEXT;
ALTER TABLE email_sender_sources ADD COLUMN spf_aligned_messages INTEGER NOT NULL DEFAULT 0;
ALTER TABLE email_sender_sources ADD COLUMN dkim_aligned_messages INTEGER NOT NULL DEFAULT 0;
ALTER TABLE email_sender_sources ADD COLUMN provider_map_version TEXT;
