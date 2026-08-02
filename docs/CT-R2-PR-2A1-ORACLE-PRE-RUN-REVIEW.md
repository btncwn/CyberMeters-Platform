# CT-R2 PR-2A.1 corrective oracle pre-run review record

Status: **CANDIDATE — NOT EXECUTED**

Frozen runtime base: `5fa32135fd5adc18e62649bbe22bc92cb9f83f19`

This record governs the first authorised old-runtime execution of
`scripts/validate-ct-consumer-isolation-oracle.js --expect-old-runtime`.
The earlier oracle revision is superseded: it coupled three preserved controls
to implementation-only projection helpers and therefore did not provide an
admissible base-compatible carrier. No result from that revision is evidence for
this candidate.

The machine-readable classification, exact base snippets and snippet SHA-256
values are in `scripts/ct-consumer-isolation-old-runtime-classification.js`.
The semantic contracts and predeclared exact mutant kill sets are in the two
`validate-ct-consumer-isolation-oracle*.js` files. The final runtime consumer
inventory count/set/fingerprint is intentionally absent until after the runtime
implementation is committed.

## Ruling-to-assertion map

| Ruling / preserved contract | Assertion ID | Expected base result | Class |
| --- | --- | --- | --- |
| One physical request per domain/provider | `SHARED_PHYSICAL_REQUEST_ONE` | PASS | positive control |
| SSL release is consumer-only | `SSL_RELEASE_IS_CONSUMER_ONLY` | FAIL | BEHAVIOURAL |
| Subdomains retains its later entitlement | `SIBLING_LATE_SUCCESS_RECEIVED` | FAIL | BEHAVIOURAL |
| CT-R1 remains physical-provider truth | `CT_R1_LATE_SUCCESS_IS_OK` | FAIL | BEHAVIOURAL |
| Released consumer rejects late settlement | `RELEASED_CONSUMER_REJECTS_LATE_RESULT` | FAIL | STRUCTURAL |
| Consumer wait and physical state are separate | `CONSUMER_STATE_SEPARATE_FROM_PHYSICAL` | FAIL | STRUCTURAL |
| Released reserved output is immutable | `RELEASED_OUTPUT_IMMUTABLE` | FAIL | STRUCTURAL |
| Successful-empty remains a real zero | `SUCCESSFUL_EMPTY_IS_ZERO` | PASS | positive control |
| Genuine provider failure remains unavailable | `GENUINE_FAILURE_REMAINS_PROVIDER_FAILURE` | PASS | positive control |
| Genuine failure has separate consumer/physical state | `CONSUMER_FAILURE_STATE_MATCHES_PHYSICAL` | FAIL | STRUCTURAL |
| Global deadline has canonical structured provenance | `STRUCTURED_GLOBAL_DEADLINE_PROVENANCE` | FAIL | STRUCTURAL |
| Global deadline still stops physical work | `GLOBAL_DEADLINE_STOPS_PHYSICAL_WORK` | PASS | positive control |
| CT-R1 records platform deadline cause | `CT_R1_GLOBAL_DEADLINE_CAUSE` | FAIL | BEHAVIOURAL |
| Abort-before-release is platform abort | `ABORT_BEFORE_RELEASE_IS_PLATFORM_ABORT` | FAIL | BEHAVIOURAL |
| Release-before-abort is honestly in flight | `RELEASE_BEFORE_ABORT_IS_IN_FLIGHT` | PASS | positive control |
| Freeze prevents late observation mutation | `FROZEN_OVERLAP_REJECTS_LATE_OBSERVE` | PASS | positive control |
| Shared signal does not admit PA+IF | `PA_IF_UNREACHABLE_ON_SHARED_SIGNAL` | FAIL | STRUCTURAL |
| Reserved scan uses the isolation boundary | `RESERVED_PATH_USES_ISOLATED_BOUNDARY` | FAIL | STRUCTURAL |
| Corrected rows use source-set v2 | `SOURCE_SET_VERSION_IS_V2` | FAIL | BEHAVIOURAL |
| Analyzer counts direct attempt population first | `ANALYZER_COUNTS_DIRECT_ATTEMPT_POPULATION` | FAIL | STRUCTURAL |
| SSL provider-source JSON shape is preserved | `CUSTOMER_SOURCE_SCHEMA_IS_STABLE` | PASS | positive control |
| Lifecycle state is not projected into SSL source JSON | `CUSTOMER_SOURCE_HAS_NO_LIFECYCLE_FIELDS` | PASS | positive control |

Expected old-runtime result: exactly **14 named failures** and **8 named
passes**, in the immutable contract order. A different set or a non-assertion
exit is STOP.

## Carrier review

- Behavioural cache contracts use `createCertificateTransparencyCache().get`
  and `telemetrySnapshot()`, both exported at the base. The fetch double records
  whether the actual physical fetch signal is aborted; no new lifecycle export
  is required to observe the wrong base behaviour.
- The CT-R1 global-abort contract uses the base cache's public global signal and
  telemetry output. It does not inspect error text to derive corrected meaning.
- Abort-before-release uses the existing overlap collector's public
  `begin()`/`freeze()` carrier. JavaScript accepts the structured context at the
  base, where `freeze()` ignores it and returns the wrong in-flight state.
- The source-set contract reads the existing public version constant.
- Consumer lifecycle, structured deadline provenance, PA+IF vocabulary,
  reserved isolation and analyzer population contracts explicitly feature-detect
  missing capability and return `false` through the normal assertion carrier.
- Reserved capability detection starts from the actual base public
  `runReservedScan` composition. It only examines or invokes
  `runReservedCtConsumer` if that composition calls the boundary and the export
  exists. A missing proposed helper cannot throw or impersonate evidence.
- Preserved successful-empty and customer-projection controls run through the
  base `resolveCertificateTransparency` interface. They do not import proposed
  projection helpers.
- Preserved global cancellation observes delivery to the base fetch signal. It
  does not require the proposed `physicalSnapshot()` capability.

## Predeclared mutation map

The fresh-process mutation runner defines **17 semantic mutants** plus two
harness controls before any execution:

1. restore first-consumer signal capture;
2. let SSL release abort physical work;
3. report consumer release as provider failure;
4. accept late settlement into released consumer state;
5. allow late SSL output publication;
6. classify abort-before-release as in flight;
7. erase structured global-deadline owner;
8. allow late overlap observation mutation;
9. duplicate the physical provider request;
10. lose global-deadline cancellation;
11. let consumer release overwrite physical state;
12. confuse consumer wait with physical outcome;
13. collapse successful-empty into unavailable;
14. restore acceptance-only source-set v1;
15. admit PA+IF as a canonical shared-signal pair;
16. omit the reserved consumer-release boundary;
17. filter attempt rows by completeness impact before platform counting.

Each mutant's exact ordered failure-ID set is literal in the runner. The two
controls reject syntax/import/load failure and a wrong-reason failure set. The
runner also requires fresh Node processes, target-byte preservation, complete
worktree-fingerprint preservation and interruption cleanup.

## Approval gate

Before running the old-runtime oracle, primary review must verify:

1. every binding ruling above maps to an assertion;
2. every expected failure has all required classification fields;
3. every behavioural carrier exists at base and its cited source evidence and
   snippet SHA match the frozen commit;
4. every structural feature is genuinely absent and cannot be expressed by an
   existing base public carrier;
5. every positive control uses a base-compatible interface and is predeclared
   PASS;
6. no assertion can fail because a proposed helper/import/export is missing;
7. the old failure and pass sets exactly partition all 22 contract IDs;
8. no runtime implementation or final-runtime inventory pin is present in this
   candidate diff.

Execution requires explicit primary approval after that review. Until then,
neither the semantic oracle nor its mutation runner is to be executed.
