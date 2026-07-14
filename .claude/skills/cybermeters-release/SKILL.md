---
name: cybermeters-release
description: Performs the approved CyberMeters release sequence after implementation and CI readiness: merge, migration, manual Worker deploy, Pages verification, tag, CHANGELOG, production proof, and rollback recording. Invoke manually only when a feature is ready to release.
disable-model-invocation: true
---

# CyberMeters Release

Release target:

`$ARGUMENTS`

Do not use this skill until implementation and the full required validation gate are green.

## Preflight

Confirm:

- focused PR
- CI green
- no unrelated working-tree changes
- migration is additive/reversible if present
- rollback target is known
- no high-risk change lacks founder approval
- current `main`, latest release tag and deployment facts are known

Record current Worker version before merge/deploy.

## Sequence

```text
PR green
→ merge
→ update local main
→ apply additive migration
→ verify migration
→ manual Worker deploy
→ verify /health and /ready
→ verify protected route is auth-gated
→ verify Pages production deployment
→ authenticated production smoke where access exists
→ release tag
→ CHANGELOG
→ final report
```

## Commands

Use repository paths and current Wrangler syntax from `OPERATIONS.md`.

The primary Worker deploys manually.

Pushing to `main` does not deploy the Worker.

Pages may auto-deploy from `main`.

## Proof standards

A `401` proves only:

- route exists
- authentication is enforced

It does not prove:

- authenticated lifecycle
- tenant isolation
- action endpoint behavior
- case linkage
- verification
- frontend rendering

Use `/cybermeters-production-smoke` for customer-workflow proof.

## Required record

Record:

- feature PR
- merge commit
- migration
- previous Worker Version ID
- live Worker Version ID
- Pages status
- release tag
- validation
- production proof
- limitations
- rollback command

## Stop conditions

Stop before deployment if:

- CI is not green
- migration is destructive
- tenant isolation is uncertain
- unrelated changes are mixed in
- rollback target is missing
- live contract regression exists
- founder approval is required

Do not hide a blocked deployment behind optimistic language.
