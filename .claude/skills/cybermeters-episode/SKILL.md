---
name: cybermeters-episode
description: Runs a complete CyberMeters canonical roadmap episode from exact pre-change map through implementation, validation, PR, release evidence, and stop. Use for Identity Exposure, ASM verification, alerts, MSP portfolio, M5, or any named roadmap phase.
---

# CyberMeters Canonical Episode

Use this skill for one bounded canonical roadmap episode.

## Read first

Read:

- `CLAUDE.md`
- `AGENTS.md`
- `README.md`
- `OPERATIONS.md`
- recent `CHANGELOG.md`
- current branch, recent commits, PRs, migrations, latest release tag and live deployment facts

Treat those files as authoritative. Do not restate old roadmap assumptions from memory.

## Episode argument

The requested episode is:

`$ARGUMENTS`

If the argument is empty, identify the `Next canonical episode` from `CLAUDE.md` and `AGENTS.md`.

## Pre-change gate

Before editing:

1. Confirm repository status and active branch.
2. Confirm the episode has not already shipped.
3. Identify unrelated working-tree changes and keep them out.
4. Build an exact pre-change map:
   - files
   - routes
   - tables
   - migrations
   - engines
   - frontend consumers
   - reports/PDF consumers
   - state machines
   - remediation entries
   - tenant boundaries
   - purge order
   - tests
   - production dependencies
5. Search for duplicate functionality.
6. State what will be reused, extended and not created.
7. Define explicit scope boundaries and later phases that will not be started.

Do not create a table or parallel system before the map is complete.

## Implementation principles

- Extend canonical systems; do not duplicate them.
- Preserve backward compatibility.
- Preserve append-only history where auditability matters.
- Keep all workspace reads/writes tenant-scoped.
- Treat soft-deleted workspaces as nonexistent.
- Use safe non-enumerating responses where required.
- Keep frontend states backend-owned.
- Keep customer assertions separate from CyberMeters verification.
- Use the Canonical Remediation Registry.
- Use the Universal Managed-Case Model.
- Base case creation uses `createManagedCase(...)`.
- Case transitions use `canTransitionCase(...)`.
- Do not start a later roadmap phase.
- Do not mix unrelated docs or cosmetic work into the feature PR.

## Required lifecycle pattern

Where the episode creates a managed lifecycle, use:

```text
observe
→ correlate
→ explain
→ classify or assess
→ assign ownership
→ remediate
→ record customer action
→ verify with structured evidence
→ monitor
→ reopen on recurrence
```

## Testing

Add focused, CI-blocking tests proving:

- deterministic identity
- no duplicate records
- append-only evidence/history
- valid and invalid actions
- customer assertion is not verification
- case create/reopen/update
- tenant isolation
- foreign/nonexistent parity
- soft-delete protection
- purge order
- deterministic API output
- frontend does not invent state

Run all relevant focused validators and the full gate when shared systems change.

## Release boundary

Do not deploy merely because code compiles.

Follow the repository release model:

```text
feature branch
→ implementation
→ focused tests
→ full gate
→ PR
→ CI green
→ merge
→ additive migration if required
→ manual Worker deploy
→ Pages verification
→ release tag
→ CHANGELOG
→ production proof
```

Use `/cybermeters-release` for the release stage.

## Required report

Return:

1. final verdict
2. exact pre-change map
3. design decision
4. schema/migration
5. identity and correlation model
6. lifecycle/state model
7. ownership model
8. verification contract
9. monitoring/recurrence matrix
10. remediation and case linkage
11. history/evidence model
12. APIs
13. frontend
14. reports
15. files changed
16. tests
17. PR/merge
18. deployment IDs
19. production proof
20. rollback
21. residual risks
22. confirmation later phases were not started

Stop after the named episode.
