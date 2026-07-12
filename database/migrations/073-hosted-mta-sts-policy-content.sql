-- Hosted MTA-STS guided-hybrid support.
--
-- The TXT half uses hosted_dns_entries(record_kind='mtasts') without any schema
-- change. The HTTPS policy content is pinned at creation so MX drift can be
-- surfaced without silently changing the policy or bumping the DNS policy id.

ALTER TABLE hosted_dns_entries ADD COLUMN policy_content TEXT;
