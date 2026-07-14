---
name: cybermeters-managed-lifecycle
description: Applies CyberMeters managed-lifecycle architecture: deterministic identity, ownership, classification, structured verification, monitoring, recurrence, canonical remediation, and universal managed cases. Use when building or changing a managed domain workflow.
---

# CyberMeters Managed Lifecycle

Apply this skill whenever work creates or changes a managed workflow.

## Source-of-truth split

Keep two layers distinct:

```text
raw observations
→ externally observed evidence and history

managed lifecycle record
→ customer classification, ownership, planning, remediation, verification and monitoring
```

Do not turn the managed table into a duplicate scanner evidence store.

## Canonical identity

Use a deterministic, machine-stable identity.

Do not use mutable display text as identity.

Identity tests must prove:

- repeat observation resolves to the same record
- unrelated entities remain separate
- aliases are explicit, not fuzzy
- provider/product distinctions remain intact
- replacement or material change preserves old evidence
- cross-workspace data never merges

## Evidence union

Every source contribution should retain structured evidence such as:

```text
source_table
source_record_id
source_type
observed_identifier
hostname or URL
first_seen_at
last_seen_at
confidence
```

Evidence union must be non-destructive and bounded.

Preserve original `first_seen_at`; advance `last_seen_at`; do not grow duplicate evidence indefinitely.

## Separate state dimensions

Do not overload one status field.

Keep separate where applicable:

- observation/exposure state
- customer classification
- ownership status
- remediation status
- customer-action status
- verification status
- monitoring status
- risk state

Legitimate example:

```text
customer_action_status = completed
verification_status = pending
monitoring_status = observed
```

## Ownership

Support appropriate owner roles.

Derive:

```text
known
partial
missing
```

server-side.

Owner assignment must be validated, tenant-scoped and append-only audited.

Ownership is customer-provided metadata, not external verification.

## Customer action versus verification

Customer actions are assertions.

A note, completed scan, checkbox or bare boolean cannot verify a fix.

Verification requires structured evidence:

```text
verification_method
verification_result
evidence_type
observed_at
previous_observation
current_observation
expected_outcome
actual_outcome
confidence
reference
limitations
```

Supported results:

```text
pending
verified
failed
inconclusive
unsupported
```

Only supported positive evidence may produce `verified`.

## Monitoring evaluator

Use one deterministic backend evaluator.

It should cover as relevant:

- new observation
- repeat observation
- material change
- disappearance
- recurrence
- owner missing
- evidence stale
- exception expired
- customer-removal contradiction
- verification pending/failed
- retired item reappearance

Persist or return:

```text
monitoring_status
monitoring_reason
material_change
recurrence_type
required_case_action
evaluated_at
```

Do not duplicate evaluator logic in frontend, reports or alerts.

## Universal Managed Cases

Do not create a parallel domain-specific case table.

Use:

- `createManagedCase(...)` for base creation
- `canTransitionCase(...)` for transitions
- Canonical Remediation Registry for customer meaning

Existing case behavior:

```text
no case
→ create

active case
→ append recurrence/material-change event

verified or monitoring case
→ reopen through canTransitionCase
```

Never return a deduplicated case without recording the new event.

## Exceptions

An exception requires:

- reason
- expiry
- actor
- audit event

An exception does not mean healthy, secure or verified.

## History

Preserve:

- raw observations
- classifications
- owners
- customer actions
- verification attempts
- exceptions
- monitoring changes
- recurrence
- case linkage

Use append-only events where audit integrity matters.
