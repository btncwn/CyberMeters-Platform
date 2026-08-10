-- Canonical runtime finding identity for new D1 rows.
-- Nullable by design: historical rows remain byte-for-byte untouched and receive
-- only the bounded read-time compatibility treatment in finding-identity.js.
ALTER TABLE findings ADD COLUMN finding_slug TEXT;
