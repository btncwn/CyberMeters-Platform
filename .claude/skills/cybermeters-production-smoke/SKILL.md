---
name: cybermeters-production-smoke
description: Runs a founder-controlled, side-effect-safe production smoke test for a CyberMeters release and distinguishes route liveness from real authenticated workflow proof. Invoke manually with the feature or workflow name.
disable-model-invocation: true
---

# CyberMeters Production Smoke

Workflow:

`$ARGUMENTS`

Use only founder-controlled workspaces, domains and records.

## Safety

Do not:

- alter unrelated customer data
- send unrelated emails or reports
- trigger broad notifications
- modify third-party DNS without approval
- mark real customer cases resolved for testing
- disclose tokens or secrets

## Minimum proof

Prove as relevant:

- login/authenticated session
- correct founder workspace
- list/detail route
- record creation or correlation
- repeat observation without duplication
- valid action accepted
- invalid action rejected
- append-only history
- canonical remediation
- managed-case create/link
- recurrence/reopen
- frontend state
- audit event
- foreign/nonexistent parity
- no unrelated side effect

## Verification honesty

Confirm customer action remains separate from CyberMeters verification.

For a verification workflow, prove:

- structured evidence exists
- failed/inconclusive does not verify
- positive result meets the method contract
- limitations remain visible

## When no founder session exists

Do not claim full production proof.

Report separately:

- migration verified
- route live
- route auth-gated
- DB-backed contract tests green
- authenticated smoke deferred to final release gate

A `401` is not workflow proof.

## Output

Return:

- workspace/domain used
- actions performed
- observed results
- evidence
- cleanup
- side effects
- limitations
- pass/fail verdict
