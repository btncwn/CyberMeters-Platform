---
name: cybermeters-security-review
description: Performs a focused CyberMeters security review for a feature or later full hardening phase, covering tenant isolation, auth, business logic, Workers/D1/R2, rate limits, input handling, and evidence integrity. Use for security review, debugging, pentest preparation, or suspected security defects.
---

# CyberMeters Security Review

Target:

`$ARGUMENTS`

This skill may be used for focused security testing during an episode or for the later dedicated hardening phase.

## Scope map

Map:

- entry points
- authentication
- authorisation
- workspace scoping
- database queries
- R2 access
- external fetches
- webhooks
- scheduled jobs
- retries
- audit events
- customer-facing errors
- secrets/bindings
- rate limits

## Priority checks

### Tenant isolation

- horizontal access
- foreign/nonexistent parity
- workspace ID tampering
- domain/case/report cross-tenant access
- soft-deleted workspace behavior
- SQL workspace predicates

Treat a confirmed cross-tenant issue as SEV-1.

### Authentication and sessions

As relevant:

- email verification
- password reset
- MFA/TOTP
- recovery
- Microsoft SSO
- session revocation
- login history
- CSRF exposure
- token leakage

Do not redesign auth architecture without approval.

### API and business logic

Check:

- missing authorisation
- state-machine bypass
- direct status mutation
- duplicate/idempotency abuse
- rate-limit fail-open behavior
- invitation abuse
- billing entitlement bypass
- verification forgery
- customer assertion promoted to verified
- enumeration

### Input and fetch safety

Check:

- SQL injection
- XSS
- SSRF
- unsafe redirects
- unsafe URL fetching
- XML parser risk
- oversized payloads
- header injection
- path/object-key manipulation

### Cloudflare

Check:

- Worker CPU/subrequest bounds
- Cron boundedness
- D1 query amplification
- R2 object access
- binding/secret exposure
- retry storms
- email-ingest abuse
- deployment/rollback safety

## Testing rules

Use founder-controlled data.

Do not conduct destructive or broad production pentesting without explicit approval.

Automated tools support judgment; they are not proof of security.

## Output

Report:

- scope
- attack paths reviewed
- confirmed findings
- severity
- evidence
- affected files/routes
- exploit preconditions
- recommended fix
- regression test
- residual risk
- what was not tested
