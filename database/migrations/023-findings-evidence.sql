-- Migration 023: Add evidence_json and confidence columns to findings table
-- Sprint 4: Scanner Accuracy & Evidence Framework v1

ALTER TABLE findings ADD COLUMN evidence_json TEXT;
ALTER TABLE findings ADD COLUMN confidence TEXT;

-- Validation:
-- SELECT id, severity, title, confidence, evidence_json FROM findings LIMIT 5;
