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
- `CHANGELOG.md`: release history (the timeline of WHEN things shipped)
- `docs/CAPABILITIES.md`: canonical CURRENT-STATE capability register (what the product can/cannot do NOW, at what evidence level) — distinct from CHANGELOG (timeline) and PUBLIC-CLAIMS-TRUTH-AUDIT (claim accuracy)

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

## CAPABILITIES.md governance hook

Any PR that **adds, removes, expands, narrows, or changes the customer language of** a product capability must update `docs/CAPABILITIES.md` in the same PR, **or** state in the PR description why no update is needed. This is a **checklist obligation + a drift validator** (`validate-capabilities-doc.js`) — NOT a crude "file unchanged → CI fail" gate (which would block every unrelated PR).

Rules for `CAPABILITIES.md`:
- Current state only — verified present behaviour, never roadmap ambition. Future work → roadmap/backlog; when shipped → `CHANGELOG.md`; claim accuracy → `PUBLIC-CLAIMS-TRUTH-AUDIT.md`.
- Exactly eight domains, no ninth (third-party/vendor tech lives under Shadow IT).
- Every capability carries exactly one status label: `Live — production-verified` · `Live — founder acceptance pending` · `Engineering complete — deployment pending` · `Partial / bounded coverage` · `Planned` · `Retired from customer-facing claims`. No bare "Supported"/"Available".
- Keep the evidence-language taxonomy distinct: Observed / Derived / Correlated / Customer-declared / Inferred.
- Retired claims (Vendor Risk / Supply Chain Score) stay retired, never a live capability.
- Sensitive-information boundary: customer truth, not an attacker blueprint — no secret names, internal route maps, private table names, exact rate-limit thresholds, or rollback internals.
- `Engineering complete — deployment pending` is NOT `Live` — a merged-but-undeployed capability is never described as live.

## Validation

Check:

```bash
git diff --check
git status --short
git diff -- README.md OPERATIONS.md AGENTS.md CLAUDE.md CHANGELOG.md docs/CAPABILITIES.md
node scripts/validate-capabilities-doc.js
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
