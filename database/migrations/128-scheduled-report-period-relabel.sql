-- Migration 128: label each earlier weekly / monthly executive report with the
-- period it actually covers.
--
-- Before this release a weekly report made on Monday 19 Oct 2026 was labelled
-- with the week it was made in ("2026-W43", 19–25 Oct) although it reports the
-- state at the end of 12–18 Oct; a monthly report made on 1 Oct was labelled
-- October although it reports September. The Worker now labels the period that
-- just ended (coveredReportPeriod). Without this correction the next weekly run
-- (label 2026-W43) would collide with the mislabelled 2026-W43 rows on the
-- active-occurrence UNIQUE index and that week's report would not be made.
--
-- A report is relabelled only when it was made INSIDE the period its label names
-- — the old rule. Reports made after their period ended (the new rule, or an
-- explicit period) are not touched. Quarterly reports are not touched.
--
-- UPDATE only: no row is deleted, no PDF or R2 object is touched (report_key is
-- unchanged), and every changed row keeps its original label in
-- metadata_json.original_report_period. Rows already carrying that key are
-- skipped, so the file can be re-run.
--
-- Two steps: rows first move to a 'relabel-128:' holding label, then drop the
-- prefix. A one-step UPDATE could briefly give a workspace two rows with the
-- same label (W43→W42 while the old W42 is still W42) and fail the UNIQUE index.
--
-- Apply (before the Worker deploy):
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/128-scheduled-report-period-relabel.sql
--
-- Rollback (exact reverse; run before any report has been made under the new
-- labels, or a restored label can collide with a new row and stop the second
-- statement — rerun after resolving that row):
--   UPDATE workspace_reports
--      SET report_period = 'revert-128:' || json_extract(metadata_json, '$.original_report_period')
--    WHERE report_type IN ('weekly_executive', 'monthly_executive')
--      AND json_extract(metadata_json, '$.original_report_period') IS NOT NULL
--      AND report_period NOT LIKE 'revert-128:%';
--   UPDATE workspace_reports
--      SET report_period = substr(report_period, 12),
--          metadata_json = CASE
--            WHEN json_remove(metadata_json, '$.original_report_period') = '{}' THEN NULL
--            ELSE json_remove(metadata_json, '$.original_report_period') END
--    WHERE report_period LIKE 'revert-128:%';

-- Weekly. The label's Monday is Monday of ISO week 1 (the week holding 4 Jan)
-- plus (week − 1) weeks; the covered week's Thursday is that Monday − 4 days, and
-- its ISO year/week name the corrected label.
UPDATE workspace_reports
   SET metadata_json = json_set(COALESCE(metadata_json, '{}'), '$.original_report_period', report_period),
       report_period = 'relabel-128:'
         || strftime('%Y', date(substr(report_period, 1, 4) || '-01-04',
              '-' || ((CAST(strftime('%w', substr(report_period, 1, 4) || '-01-04') AS INTEGER) + 6) % 7) || ' days',
              '+' || ((CAST(substr(report_period, 7, 2) AS INTEGER) - 1) * 7) || ' days',
              '-4 days'))
         || '-W'
         || substr('0' || (CAST((
              julianday(date(substr(report_period, 1, 4) || '-01-04',
                '-' || ((CAST(strftime('%w', substr(report_period, 1, 4) || '-01-04') AS INTEGER) + 6) % 7) || ' days',
                '+' || ((CAST(substr(report_period, 7, 2) AS INTEGER) - 1) * 7) || ' days',
                '-4 days'))
              - julianday(strftime('%Y', date(substr(report_period, 1, 4) || '-01-04',
                '-' || ((CAST(strftime('%w', substr(report_period, 1, 4) || '-01-04') AS INTEGER) + 6) % 7) || ' days',
                '+' || ((CAST(substr(report_period, 7, 2) AS INTEGER) - 1) * 7) || ' days',
                '-4 days')) || '-01-01')
            ) / 7 AS INTEGER) + 1), -2)
 WHERE report_type = 'weekly_executive'
   AND report_period GLOB '[0-9][0-9][0-9][0-9]-W[0-9][0-9]'
   AND json_extract(COALESCE(metadata_json, '{}'), '$.original_report_period') IS NULL
   AND substr(created_at, 1, 10) >= date(substr(report_period, 1, 4) || '-01-04',
         '-' || ((CAST(strftime('%w', substr(report_period, 1, 4) || '-01-04') AS INTEGER) + 6) % 7) || ' days',
         '+' || ((CAST(substr(report_period, 7, 2) AS INTEGER) - 1) * 7) || ' days')
   AND substr(created_at, 1, 10) < date(substr(report_period, 1, 4) || '-01-04',
         '-' || ((CAST(strftime('%w', substr(report_period, 1, 4) || '-01-04') AS INTEGER) + 6) % 7) || ' days',
         '+' || ((CAST(substr(report_period, 7, 2) AS INTEGER) - 1) * 7) || ' days',
         '+7 days');

-- Monthly. A report made in the month it names covers the month before.
UPDATE workspace_reports
   SET metadata_json = json_set(COALESCE(metadata_json, '{}'), '$.original_report_period', report_period),
       report_period = 'relabel-128:' || strftime('%Y-%m', report_period || '-01', '-1 month')
 WHERE report_type = 'monthly_executive'
   AND report_period GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]'
   AND json_extract(COALESCE(metadata_json, '{}'), '$.original_report_period') IS NULL
   AND substr(created_at, 1, 7) = report_period;

UPDATE workspace_reports
   SET report_period = substr(report_period, 13)
 WHERE report_period LIKE 'relabel-128:%';
