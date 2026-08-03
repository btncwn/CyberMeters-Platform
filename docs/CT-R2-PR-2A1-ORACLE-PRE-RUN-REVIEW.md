# CT-R2 PR-2A.1 oracle pre-run review

Status: **ORACLE-CORRECTIVE COMMIT 2 CANDIDATE — NOT EXECUTED**

Frozen runtime base: `5fa32135fd5adc18e62649bbe22bc92cb9f83f19`

Binding contract: `docs/CT-R2-PR-2A1-BINDING-CONTRACT.md`

Binding-contract SHA-256:
`02266fd63b014773b340230c15f10cb0c830dc391efe4a8e2f8d66412c43cc0b`

The semantic oracle derives its allowed ruling namespace only from the 17
`### CT2A1-*` headings in the binding contract. It pins the contract bytes but
does not maintain a second authoritative ruling-ID list. All invented
identifiers from the superseded candidate have been removed.

The old-runtime PASS and FAIL sets below are declared before execution. The
semantic mutation runner also declares every exact ordered failure set before
execution. Every registered CT2A1 assertion, including every PASS positive
control, maps to at least one meaningful semantic mutant. There is no assertion
exemption. The syntax/import and wrong-failure-set controls are not CT2A1
assertions and therefore sit outside the semantic graph.

## Parsed authoritative namespace

1. `CT2A1-CACHE-01`
2. `CT2A1-CACHE-02`
3. `CT2A1-PROV-01`
4. `CT2A1-PROV-02`
5. `CT2A1-PROV-03`
6. `CT2A1-PROV-04`
7. `CT2A1-PAIF-01`
8. `CT2A1-CUSTOMER-01`
9. `CT2A1-CUSTOMER-02`
10. `CT2A1-CUSTOMER-03`
11. `CT2A1-CUSTOMER-04`
12. `CT2A1-SENTINEL-01`
13. `CT2A1-SENTINEL-02`
14. `CT2A1-RESERVED-01`
15. `CT2A1-VERSION-01`
16. `CT2A1-INVENTORY-01`
17. `CT2A1-VOCAB-01`

## Predeclared old-runtime partition

Expected PASS IDs, in assertion order:

1. `SHARED_PHYSICAL_REQUEST_ONE`
2. `SUCCESSFUL_EMPTY_IS_ZERO`
3. `GENUINE_FAILURE_REMAINS_PROVIDER_FAILURE`
4. `GLOBAL_DEADLINE_STOPS_PHYSICAL_WORK`
5. `FROZEN_OVERLAP_REJECTS_LATE_OBSERVE`
6. `PERSISTENCE_OUTCOME_IS_INDEPENDENT`
7. `CUSTOMER_SOURCE_SCHEMA_IS_STABLE`
8. `CUSTOMER_SOURCE_HAS_NO_LIFECYCLE_FIELDS`
9. `SENTINEL_ERROR_PRECEDENCE`
10. `INVENTORY_MECHANISM_IS_UNPINNED`

Expected BEHAVIOURAL FAIL IDs, in assertion order:

1. `SSL_RELEASE_IS_CONSUMER_ONLY`
2. `SIBLING_LATE_SUCCESS_RECEIVED`
3. `CT_R1_LATE_SUCCESS_IS_OK`
4. `CT_R1_GLOBAL_DEADLINE_CAUSE`
5. `CUSTOMER_PLATFORM_ABORT_WORDING_EXACT`
6. `CUSTOMER_PLATFORM_ABORT_FORBIDS_PROVIDER_FAILURE`
7. `SSL_SUBDOMAINS_PLATFORM_ABORT_WORDING_MATCH`
8. `SOURCE_SET_VERSION_IS_V2`

Expected STRUCTURAL FAIL IDs, in assertion order:

1. `RELEASED_CONSUMER_REJECTS_LATE_RESULT`
2. `CONSUMER_STATE_SEPARATE_FROM_PHYSICAL`
3. `RELEASED_OUTPUT_IMMUTABLE`
4. `CONSUMER_FAILURE_STATE_MATCHES_PHYSICAL`
5. `STRUCTURED_GLOBAL_DEADLINE_PROVENANCE`
6. `STATE_MACHINE_TYPES_REMAIN_DISTINCT`
7. `ABORT_BEFORE_RELEASE_IS_PLATFORM_ABORT`
8. `RELEASE_BEFORE_ABORT_IS_IN_FLIGHT`
9. `PA_IF_UNREACHABLE_ON_SHARED_SIGNAL`
10. `RESERVED_PLATFORM_ABORT_WORDING_MATCH`
11. `V1_ROWS_ARE_DECISION_QUARANTINED`
12. `EXACT_PLATFORM_ABORT_VOCABULARY`
13. `ANALYZER_COUNTS_DIRECT_ATTEMPT_POPULATION`
14. `RESERVED_PATH_USES_ISOLATED_BOUNDARY`
15. `CT_R1_OVERLAP_CAUSAL_COHERENCE`

Expected old-runtime result: exactly **23 named failures**—8 BEHAVIOURAL
and 15 STRUCTURAL—and **10 named passes**. Any larger or smaller set, changed
classification, non-assertion exit, import failure, syntax failure or harness
failure is STOP. The expected sets must not be edited after execution.

## Bidirectional ruling/assertion/fixture/classification/mutant matrix

| Binding ruling(s) | Assertion | Old-runtime fixture/carrier | Class | Semantic mutant(s) |
| --- | --- | --- | --- | --- |
| `CT2A1-CACHE-01` | `SHARED_PHYSICAL_REQUEST_ONE` | `shared_late_success` | PASS positive control | `DUPLICATE_PHYSICAL_REQUEST` |
| `CT2A1-CACHE-01`, `CT2A1-CACHE-02` | `SSL_RELEASE_IS_CONSUMER_ONLY` | `shared_late_success` | BEHAVIOURAL | `RESTORE_FIRST_CONSUMER_SIGNAL_CAPTURE`; `REPORT_CONSUMER_RELEASE_AS_PROVIDER_FAILURE` |
| `CT2A1-CACHE-02` | `SIBLING_LATE_SUCCESS_RECEIVED` | `shared_late_success` | BEHAVIOURAL | `RESTORE_FIRST_CONSUMER_SIGNAL_CAPTURE` |
| `CT2A1-PROV-01`, `CT2A1-PROV-03` | `CT_R1_LATE_SUCCESS_IS_OK` | `shared_late_success` | BEHAVIOURAL | `DUPLICATE_PHYSICAL_REQUEST`; `RESTORE_FIRST_CONSUMER_SIGNAL_CAPTURE` |
| `CT2A1-PROV-02` | `RELEASED_CONSUMER_REJECTS_LATE_RESULT` | `shared_late_success` | STRUCTURAL | `ACCEPT_LATE_RESULT_FOR_RELEASED_CONSUMER`; `ALLOW_LATE_RESERVED_PUBLICATION` |
| `CT2A1-PROV-01`, `CT2A1-PROV-02` | `CONSUMER_STATE_SEPARATE_FROM_PHYSICAL` | `shared_late_success` | STRUCTURAL | `RESTORE_FIRST_CONSUMER_SIGNAL_CAPTURE`; `ACCEPT_LATE_RESULT_FOR_RELEASED_CONSUMER`; `ALLOW_LATE_RESERVED_PUBLICATION`; `CONFUSE_CONSUMER_AND_PHYSICAL_STATE` |
| `CT2A1-CACHE-02`, `CT2A1-PROV-02` | `RELEASED_OUTPUT_IMMUTABLE` | `reserved_late_success` | STRUCTURAL | `ALLOW_LATE_RESERVED_PUBLICATION` |
| `CT2A1-SENTINEL-01` | `SUCCESSFUL_EMPTY_IS_ZERO` | `successful_empty` | PASS positive control | `COLLAPSE_SUCCESSFUL_EMPTY` |
| `CT2A1-PROV-01` | `GENUINE_FAILURE_REMAINS_PROVIDER_FAILURE` | `genuine_http_failure` | PASS positive control | `ERASE_GENUINE_PROVIDER_FAILURE` |
| `CT2A1-PROV-01`, `CT2A1-PROV-02` | `CONSUMER_FAILURE_STATE_MATCHES_PHYSICAL` | `genuine_http_failure` | STRUCTURAL | `ERASE_GENUINE_PROVIDER_FAILURE`; `CONFUSE_CONSUMER_AND_PHYSICAL_STATE` |
| `CT2A1-CACHE-02`, `CT2A1-PROV-01`, `CT2A1-PROV-02` | `STRUCTURED_GLOBAL_DEADLINE_PROVENANCE` | `scan_deadline_controller` | STRUCTURAL | `ERASE_STRUCTURED_DEADLINE_OWNER` |
| `CT2A1-CACHE-02` | `GLOBAL_DEADLINE_STOPS_PHYSICAL_WORK` | `global_abort` | PASS positive control | `LOSE_GLOBAL_DEADLINE_CANCELLATION` |
| `CT2A1-PROV-01`, `CT2A1-PROV-03`, `CT2A1-VOCAB-01` | `CT_R1_GLOBAL_DEADLINE_CAUSE` | `global_abort` | BEHAVIOURAL | `ERASE_STRUCTURED_DEADLINE_OWNER`; `LOSE_GLOBAL_DEADLINE_CANCELLATION`; `SPLIT_CT_R1_OVERLAP_PROVENANCE` |
| `CT2A1-PROV-01`, `CT2A1-PROV-02`, `CT2A1-PROV-03`, `CT2A1-PROV-04` | `STATE_MACHINE_TYPES_REMAIN_DISTINCT` | `state_machine_exports` | STRUCTURAL | `COLLAPSE_STATE_MACHINE_TYPES`; `OMIT_PLATFORM_ABORT_VOCABULARY` |
| `CT2A1-PROV-02`, `CT2A1-PROV-03`, `CT2A1-VOCAB-01` | `ABORT_BEFORE_RELEASE_IS_PLATFORM_ABORT` | `real_abort_before_release` | STRUCTURAL | `ERASE_STRUCTURED_DEADLINE_OWNER`; `ABORT_BEFORE_RELEASE_AS_IN_FLIGHT` |
| `CT2A1-PROV-02`, `CT2A1-PROV-03`, `CT2A1-VOCAB-01` | `RELEASE_BEFORE_ABORT_IS_IN_FLIGHT` | `real_release_before_abort` | STRUCTURAL | `RELEASE_BEFORE_ABORT_AS_PLATFORM_ABORT` |
| `CT2A1-PROV-03` | `FROZEN_OVERLAP_REJECTS_LATE_OBSERVE` | `frozen_overlap` | PASS positive control | `ALLOW_LATE_OVERLAP_OBSERVE` |
| `CT2A1-PAIF-01` | `PA_IF_UNREACHABLE_ON_SHARED_SIGNAL` | `real_asymmetric_shared_abort` | STRUCTURAL | `ERASE_STRUCTURED_DEADLINE_OWNER`; `ABORT_BEFORE_RELEASE_AS_IN_FLIGHT`; `ADMIT_PA_IF_SHARED_SIGNAL` |
| `CT2A1-PROV-04` | `PERSISTENCE_OUTCOME_IS_INDEPENDENT` | `persistence_outcomes` | PASS positive control | `COLLAPSE_PERSISTENCE_OUTCOME` |
| `CT2A1-CUSTOMER-01` | `CUSTOMER_PLATFORM_ABORT_WORDING_EXACT` | `global_abort_customer_projection` | BEHAVIOURAL | `ERASE_STRUCTURED_DEADLINE_OWNER`; `LOSE_GLOBAL_DEADLINE_CANCELLATION`; `TYPO_PLATFORM_ABORT_WORDING`; `PLATFORM_ABORT_AS_PROVIDER_UNAVAILABLE`; `DRIFT_SSL_PLATFORM_WORDING` |
| `CT2A1-CUSTOMER-02` | `CUSTOMER_PLATFORM_ABORT_FORBIDS_PROVIDER_FAILURE` | `global_abort_customer_projection` | BEHAVIOURAL | `ERASE_STRUCTURED_DEADLINE_OWNER`; `LOSE_GLOBAL_DEADLINE_CANCELLATION`; `PLATFORM_ABORT_AS_PROVIDER_UNAVAILABLE`; `DRIFT_SSL_PLATFORM_WORDING` |
| `CT2A1-CUSTOMER-03` | `CUSTOMER_SOURCE_SCHEMA_IS_STABLE` | `customer_source_shape` | PASS positive control | `LEAK_LIFECYCLE_INTO_SOURCE_OBJECT` |
| `CT2A1-CUSTOMER-03` | `CUSTOMER_SOURCE_HAS_NO_LIFECYCLE_FIELDS` | `customer_source_shape` | PASS positive control | `LEAK_LIFECYCLE_INTO_SOURCE_OBJECT` |
| `CT2A1-CUSTOMER-04` | `SSL_SUBDOMAINS_PLATFORM_ABORT_WORDING_MATCH` | `global_abort_cross_module_projection` | BEHAVIOURAL | `ERASE_STRUCTURED_DEADLINE_OWNER`; `LOSE_GLOBAL_DEADLINE_CANCELLATION`; `TYPO_PLATFORM_ABORT_WORDING`; `PLATFORM_ABORT_AS_PROVIDER_UNAVAILABLE`; `DRIFT_SSL_PLATFORM_WORDING` |
| `CT2A1-CUSTOMER-04`, `CT2A1-RESERVED-01` | `RESERVED_PLATFORM_ABORT_WORDING_MATCH` | `reserved_global_abort` | STRUCTURAL | `DRIFT_RESERVED_PLATFORM_WORDING` |
| `CT2A1-SENTINEL-02`, `CT2A1-INVENTORY-01` | `SENTINEL_ERROR_PRECEDENCE` | `inventory_detector_calibration` | PASS positive control | `IGNORE_SENTINEL_ERROR_PRECEDENCE` |
| `CT2A1-VERSION-01` | `SOURCE_SET_VERSION_IS_V2` | `source_set_version` | BEHAVIOURAL | `RESTORE_SOURCE_SET_V1` |
| `CT2A1-VERSION-01` | `V1_ROWS_ARE_DECISION_QUARANTINED` | `analyzer_v1_quarantine` | STRUCTURAL | `ALLOW_V1_DECISION_ROWS` |
| `CT2A1-INVENTORY-01` | `INVENTORY_MECHANISM_IS_UNPINNED` | `inventory_detector_metadata` | PASS positive control | `PIN_INVENTORY_BEFORE_RUNTIME` |
| `CT2A1-VOCAB-01` | `EXACT_PLATFORM_ABORT_VOCABULARY` | `state_machine_exports` | STRUCTURAL | `OMIT_PLATFORM_ABORT_VOCABULARY` |
| `CT2A1-PROV-01`, `CT2A1-VERSION-01` | `ANALYZER_COUNTS_DIRECT_ATTEMPT_POPULATION` | `analyzer_population` | STRUCTURAL | `FILTER_ATTEMPTS_BY_IMPACT_FIRST` |
| `CT2A1-CACHE-01`, `CT2A1-CACHE-02`, `CT2A1-RESERVED-01` | `RESERVED_PATH_USES_ISOLATED_BOUNDARY` | `reserved_real_composition` | STRUCTURAL | `OMIT_RESERVED_CONSUMER_BOUNDARY` |
| `CT2A1-PROV-01`, `CT2A1-PROV-03` | `CT_R1_OVERLAP_CAUSAL_COHERENCE` | `real_abort_before_release` | STRUCTURAL | `ERASE_STRUCTURED_DEADLINE_OWNER`; `LOSE_GLOBAL_DEADLINE_CANCELLATION`; `ABORT_BEFORE_RELEASE_AS_IN_FLIGHT`; `SPLIT_CT_R1_OVERLAP_PROVENANCE` |

The machine-readable matrix is built from the same assertion and mutant records
and is checked bidirectionally before any semantic assertion runs. It rejects
unknown rulings, missing ruling coverage, assertions without fixtures, duplicate
assertion IDs, duplicate ruling IDs within an assertion, mutants without
assertions, assertions without mutants, duplicate mutant IDs, and unordered or
unknown expected FAIL IDs.

## Classification and carrier review

- Each BEHAVIOURAL failure uses a public path available at the frozen base and
  cites the exact responsible base producer/consumer.
- Each STRUCTURAL failure intentionally feature-detects a missing capability and
  returns a normal assertion `false`. A missing proposed export, `TypeError`,
  syntax error, load error or harness error cannot count as semantic evidence.
- The nine independently verified entries in `BASE_EVIDENCE` remain byte-for-byte
  unchanged. Four newly required evidence entries were appended separately and
  are verified against frozen base `5fa32135` by path, line, exact snippet and
  SHA-256 during static preflight.
- Positive controls use base-compatible public carriers and are predeclared
  PASS. They are mutation-protected exactly like failing assertions.
- Exact CUSTOMER-01 wording is parsed from the binding contract and compared
  character-for-character. The preflight separately requires the apostrophe in
  `scan's` to be ASCII U+0027.
- CUSTOMER-02 separately rejects `fetch failed` and unavailable-provider meaning
  for platform-global abort.
- The final inventory count, site set and fingerprint remain null/unpinned. The
  detector algorithm and calibration cover direct, optional, computed-literal,
  destructured, alias, array/object, helper, spread/serialization and unresolved
  dynamic forms. Dynamic access fails closed.

## Final-proof limit

Old-runtime structural absence is not final implementation proof.

- `CT2A1-PAIF-01` must execute real shared signal, provider promises and consumer
  release ordering. Direct `observe()`/`freeze()` state injection is inadmissible.
- `CT2A1-RESERVED-01` must execute the actual `runReservedScan` composition.
  Static source inspection or helper existence is inadmissible final proof.
- Abort-before-release and release-before-abort use the same real composition and
  persist its naturally derived snapshot through the real persistence function.
- CT-R1 and overlap causality must originate from the same canonical deadline
  controller event.

## Mutation discipline

The runner predeclares **29 semantic mutants** and their exact ordered FAIL sets,
plus **2 non-assertion harness controls**. Each semantic mutant is registered
exactly once. Every run uses a fresh Node process, rejects syntax/import/harness
failures, restores target bytes, restores the full worktree fingerprint and has
interruption cleanup.

## Approval gate

Only syntax parsing, contract parsing, classification/evidence validation,
traceability checks, `git diff --check` and exact diff inspection are authorised
for this commit. The semantic oracle and mutation runner remain unexecuted.

Before authorising the old-runtime run, primary review must verify:

1. the contract SHA and parsed 17-ID namespace;
2. complete ruling-to-assertion coverage and semantic relevance;
3. all failure classifications and frozen-base evidence;
4. base-compatible positive controls;
5. every assertion-to-mutant and mutant-to-assertion edge;
6. the exact 23-FAIL/10-PASS old-runtime partition;
7. the final-proof limits for PA+IF and reserved execution;
8. absence of runtime, migration, CI and final-inventory-pin changes.

Execution requires explicit approval after this review. Until then, neither the
semantic oracle nor the mutation runner may be executed.
