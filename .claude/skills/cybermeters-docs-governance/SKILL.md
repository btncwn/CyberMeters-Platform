---
name: cybermeters-docs-governance
description: Updates CyberMeters README, OPERATIONS, AGENTS, CLAUDE, roadmap and release facts without mixing feature code. Use after a release or when canonical product/engineering facts drift.
---

# CyberMeters Documentation Governance

Use for docs-only governance changes.

## Canonical documents

- `README.md`: product, architecture, setup and development
- `OPERATIONS.md`: deploy, rollback, secrets, observability and incidents
- `AGENTS.md`: engineering constitution and roadmap discipline
- `CLAUDE.md`: product ownership, authority and permanent rules
- `CHANGELOG.md`: release history

## Rules

- Use exactly eight customer-facing domains.
- Confirm latest release, migration and next episode from git/repo facts.
- Use milestone status, not speculative percentages.
- Do not state beta is GO unless the current gate says so.
- Keep completed phases `Live`.
- Describe future completion positively: `Foundation live — completion planned`.
- Keep feature code out of docs-only commits.
- Do not add temporary probe comments.
- Do not duplicate full operational procedures across every document.
- Keep `.claude/skills/` in sync: when a governance rule, release procedure or roadmap fact changes in the canonical documents, update any skill under `.claude/skills/` that restates it in the same docs commit.

## Validation

Check:

```bash
git diff --check
git status --short
git diff -- README.md OPERATIONS.md AGENTS.md CLAUDE.md CHANGELOG.md
```

Confirm internal consistency for:

- current phase
- latest release
- latest migration
- next canonical episode
- Workers plan
- manual Worker deployment
- public-beta gate

Use one focused docs commit.
