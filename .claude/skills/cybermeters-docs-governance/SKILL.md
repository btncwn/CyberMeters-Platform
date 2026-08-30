---
name: cybermeters-docs-governance
description: Updates CyberMeters README, OPERATIONS, AGENTS, CLAUDE, roadmap and release facts without mixing feature code. Use after a release or when canonical product/engineering facts drift.
---

# CyberMeters Documentation Governance

Use for docs-only governance changes.

## Canonical documents

- `docs/AI-EXECUTIVE-OPERATING-MODEL.md`: sole active governance authority
- `docs/PRE-BETA-EXECUTION-BACKLOG.md`: current execution order and rescue gate
- `docs/ROADMAP-TO-FIRST-PAYING-CUSTOMER.md`: strategic/customer acceptance spine
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
- Governance or decision texts first written before 1 August 2026 are historical evidence unless explicitly re-ratified by a current canonical source. Preserve them; do not let their old self-labels override the operating model or backlog.
- Historical classification does not erase permanent security/data invariants, accepted evidence, release facts or current technical standards.
- Never mark rescue/candidate work `Live` before deployment and required production proof.
- A release discovered without its tag/CHANGELOG record is reconciled explicitly after the fact, never backdated and never by rewriting the preceding release.
- Keep tracked `.claude/skills/` current. If a local untracked `.agents/skills/` mirror is present, it may be synchronized as a local-only copy but must not be staged or treated as repository authority by default.

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
git diff -- README.md OPERATIONS.md AGENTS.md CLAUDE.md CHANGELOG.md docs/AI-EXECUTIVE-OPERATING-MODEL.md docs/PRE-BETA-EXECUTION-BACKLOG.md docs/ROADMAP-TO-FIRST-PAYING-CUSTOMER.md docs/CAPABILITIES.md .claude/skills
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
