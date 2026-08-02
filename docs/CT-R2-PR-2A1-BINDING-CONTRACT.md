# CT-R2 PR-2A.1 Binding Contract

Status: **BINDING CONTRACT v1.0**

Issued: **2026-08-02**

This document is the single authoritative semantic contract for CT-R2
PR-2A.1 oracle traceability.

It does not authorise migration application, Worker deployment, production
writes or PR merge.

## Authority and supersession

The CT2A1 rulings previously existed only in chat messages and therefore had
no stable repository address.

Three chat-only statements of `CT2A1-PROV-01` through `CT2A1-PROV-04` were
issued on 2026-08-02, and they differed materially from one another.

This file is version 1.0 and is the only binding text.

If an earlier chat-only CT2A1 statement is found, it is withdrawn, not
reconciled.

The divergence is recorded here so that the supersession is visible rather
than silent.

From the commit that introduces this file:

- this file is the sole authoritative semantic source for these rulings;
- later chat summaries and restatements are non-authoritative;
- an unchanged ruling ID must not acquire a changed meaning;
- every ruling change requires an explicit versioned git diff and governance
  review;
- the oracle must derive its allowed CT2A1 ID namespace from this file;
- the oracle must not maintain a separate hand-written authoritative ruling
  namespace.

## Binding rulings

### CT2A1-CACHE-01

One physical request exists per scan, domain and provider.

A consumer or module release may release only that consumer. It must not
terminate shared physical work.

### CT2A1-CACHE-02

Only the canonical scan-global deadline may terminate shared physical work.

A sibling consumer retains entitlement to a later result, while an already
released consumer's published output remains immutable.

### CT2A1-PROV-01

Physical provider or transport outcome must be recorded independently from a
CyberMeters platform-global abort.

Platform cancellation is not provider failure or provider unavailability.

### CT2A1-PROV-02

Consumer wait and release state is distinct from physical attempt state.

Settlement presence must not be used as a substitute for signal and release
ordering.

### CT2A1-PROV-03

Comparison status must remain distinct from physical attempt state and
consumer wait state.

CT-R1 and overlap telemetry for the same physical request must be causally
coherent.

### CT2A1-PROV-04

Persistence outcome is a fourth independent state machine.

`persisted`, `persistence_failed` and `not_attempted_empty` must not rewrite
evidence meaning.

### CT2A1-PAIF-01

The real shared-signal composition must not persist the incoherent pair
`terminal_platform_deadline_abort` and `censored_in_flight` for the same
consumer-release boundary.

Final proof requires executed promise, signal and release ordering. Static map
inspection or direct state injection is not final proof.

### CT2A1-CUSTOMER-01

For a platform-global abort, customer-facing error wording must state exactly:

`CyberMeters did not observe the provider result within the scan's global execution window.`

### CT2A1-CUSTOMER-02

The platform-abort customer projection must not say or imply that the provider
failed or was unavailable.

It must explicitly reject the historical `fetch failed` wording and
provider-unavailable wording for this cause.

### CT2A1-CUSTOMER-03

The compatibility shape remains exactly two fields:

`{ count, error }`

Lifecycle, ownership and provenance fields must not escape into this object.

### CT2A1-CUSTOMER-04

SSL, subdomains and reserved customer projections must apply the same
platform-abort meaning and wording.

### CT2A1-SENTINEL-01

A successful empty provider result remains the measured value:

`{ count: 0, error: null }`

### CT2A1-SENTINEL-02

When `error` is non-null, `count` is a non-authoritative compatibility
sentinel.

No runtime consumer may treat `count` as measured while ignoring `error`.

The complete runtime consumer inventory must be mechanically derived rather
than hand-written.

### CT2A1-RESERVED-01

The reserved path must use the same real consumer-isolation and release
boundary.

Function existence or static source inspection is not final proof.

### CT2A1-VERSION-01

Corrected telemetry rows use `source_set_version` value
`ct-provider-overlap/2`.

Historical version-1 rows remain preserved but quarantined from CT-R2 decision
use.

### CT2A1-INVENTORY-01

The complete runtime provider-source read inventory must be mechanically
derived and pinned only after final runtime implementation.

It is the sole post-oracle freeze exemption.

Hand-written consumer lists are non-authoritative.

### CT2A1-VOCAB-01

The canonical persisted vocabulary for platform-global abort is exactly:

- CT-R1 `ct_provider_telemetry.outcome`:
  `platform_deadline_abort`
- overlap `attempt_state`:
  `terminal_platform_deadline_abort`
- overlap `comparison_status`:
  `censored_platform_deadline_abort`

Release-before-abort retains the existing vocabulary:

- overlap `attempt_state`:
  `in_flight_at_consumer_release`
- overlap `comparison_status`:
  `censored_in_flight`

These strings are exact.

The canonical migration-105 candidate already carries these values. This
clause makes them citable by assertions without reopening, applying or
authorising that migration.

## Oracle traceability requirement

A later oracle-corrective commit must mechanically enforce all of the
following:

1. every one of the 17 CT2A1 IDs in this document maps to at least one
   assertion;
2. every assertion cites at least one CT2A1 ID from this document;
3. no assertion cites an ID outside this document;
4. each assertion tests the meaning of every ruling ID it cites;
5. a missing ruling must not be closed by attaching its ID to an unrelated
   assertion;
6. the machine-readable mapping must cover ruling, assertion, fixture and
   mutant in both directions.

The old-runtime PASS and FAIL sets must be declared before execution.

Old-runtime structural feature detection may prove only that a capability is
absent at the frozen base. It is not final behavioural proof.

`CT2A1-PAIF-01` and `CT2A1-RESERVED-01` require real executed composition on
the final implementation head.

## Commit separation

The commit introducing this document must add only this file.

It must not modify oracle scripts, mutation runners, runtime implementation,
migration 105, CI governance or the final runtime inventory pin.

The oracle may be corrected in a later, separately reviewed commit only after
the bytes of this document are approved.

Neither the semantic oracle nor its mutation runner may be executed before
that approval.
