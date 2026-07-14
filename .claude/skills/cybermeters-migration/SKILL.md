---
name: cybermeters-migration
description: Plans, writes, validates, applies, and verifies safe Cloudflare D1 migrations for CyberMeters. Use whenever schema, indexes, lifecycle tables, purge order, or production D1 data shape changes.
---

# CyberMeters D1 Migration

## Before writing SQL

1. Inspect `database/schema.sql`.
2. Inspect recent numbered migrations.
3. Determine the next migration number.
4. Map all readers, writers, purge code and tests.
5. Check tenant keys and workspace scope.
6. Decide whether persistence is truly required.
7. Prefer extending an existing table over duplicate authority.

## Safety default

Migrations are additive by default.

Do not perform without explicit founder approval:

- DROP TABLE
- destructive column removal
- broad DELETE
- irreversible rewrite
- tenant-key redesign

Do not apply `database/schema.sql` directly to production as a normal migration.

## Required design checks

For every new table or column, evaluate:

- authoritative source
- stable identity
- workspace/domain foreign keys
- uniqueness
- indexes
- nullable rollout
- defaults
- append-only requirements
- purge order
- soft-delete behavior
- backward compatibility
- rollback behavior

## D1 constraints

Account for SQLite/D1 behavior.

Do not claim perfect idempotency where SQLite syntax does not support it. Document the limitation honestly.

## Validation

Run migration validators and all affected tests.

Verify the generated schema and query paths.

Use a dry run before deployment.

## Production application

This skill does not grant automatic deployment authority.

Apply only during an approved release:

```bash
npx wrangler d1 execute cybermeters-db \
  --remote \
  --file=database/migrations/<NNN-name>.sql
```

Then verify exact expected tables, columns or indexes with read-only queries.

## Rollback

Repository migrations are forward-only.

For additive migrations, code rollback may leave inert columns/tables.

For a bad migration:

- stop
- preserve evidence
- assess D1 Time Travel
- use a corrective migration or approved restore
- never improvise destructive SQL
