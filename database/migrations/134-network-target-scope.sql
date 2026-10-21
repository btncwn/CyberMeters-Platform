-- Migration 134: network targets are scanned only when every address is
-- observed in the DNS of a domain the workspace has verified.
--
-- Founder decision (21 Oct 2026). A customer's attestation alone no longer
-- authorises an address: the scope check (engines/network-ownership.js) looks
-- at the A/AAAA of the workspace's verified domains, of the hosts discovered
-- under them, and of their MX hosts under a verified domain, and excludes
-- shared provider infrastructure. The decision is stored here, checked again
-- before every scan request, and enforced in SQL at dispatch and by the TLS
-- paths. A target out of scope keeps all its history; it is just not scanned,
-- and the customer sees why.
--
-- Additive: four nullable columns. Existing targets start NULL ("not checked")
-- and are checked before their next scan; nothing is deleted or rewritten.
--
-- Apply (before the Worker deploy, which reads and writes these columns):
--   wrangler d1 execute cybermeters-db --remote \
--     --file=database/migrations/134-network-target-scope.sql
--
-- Rollback:
--   Roll the Worker back first. The columns can stay; the previous Worker
--   does not read them.

ALTER TABLE network_targets ADD COLUMN scope_state TEXT CHECK (scope_state IN ('in_scope', 'out_of_scope'));
ALTER TABLE network_targets ADD COLUMN scope_reason TEXT;
ALTER TABLE network_targets ADD COLUMN scope_checked_at TEXT;
ALTER TABLE network_targets ADD COLUMN scope_evidence_json TEXT;
