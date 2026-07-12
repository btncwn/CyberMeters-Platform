-- White-label report branding (MSP "send the report with my own logo").
-- Owner-level (customer_profiles keyed by owner_user_id) so an MSP's brand applies
-- to every customer workspace they own. Additive, idempotent.
--   brand_logo         : small data: URI (PNG/SVG) rendered on the HTML/web report
--   brand_accent       : hex accent colour (#RRGGBB) for report headers
--   report_white_label : 0/1 — when on, reports lead with the MSP's brand
--                        ("Prepared by <company> · Powered by CyberMeters")

ALTER TABLE customer_profiles ADD COLUMN brand_logo TEXT;
ALTER TABLE customer_profiles ADD COLUMN brand_accent TEXT;
ALTER TABLE customer_profiles ADD COLUMN report_white_label INTEGER NOT NULL DEFAULT 0;
