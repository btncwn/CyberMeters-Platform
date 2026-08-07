# CT-R2 PR-3 mutation contract — pre-execution freeze

Date frozen: **2026-08-07**

Base: `6699f88c396bdc6a5925d2c68f4f939b15091f25`

Status: **PRE-EXECUTION CONTRACT**

This ordered map was written before the PR-3 runtime implementation and before
executing the mutation runner. Runtime results must not change the expected sets.
A mismatch is a finding.

The semantic validator emits stable assertion IDs. Each mutant runs only its named
right-reason predicate in a fresh Node process. A kill counts only when:

1. the mutation anchor is present exactly once and the bytes change;
2. the validator reaches its normal summary;
3. the process exits `1`;
4. the exact ordered FAIL set matches this table;
5. no syntax, import, load or harness failure occurred;
6. the mutation target bytes and complete worktree fingerprint are restored.

| Order | Mutant | Defect introduced | Frozen ordered FAIL set | Right-reason predicate |
| ---: | --- | --- | --- | --- |
| 1 | M1 | One success clears degradation | `M1_ONE_SUCCESS_RETAINS_DEGRADATION` | one-provider subdomains output retains `incomplete: true` |
| 2 | M2 | One success claims two-provider complete | `M2_ONE_SUCCESS_NOT_TWO_PROVIDER_COMPLETE` | canonical discovery-completeness predicate stays false |
| 3 | M3 | One success regrades partial to degraded/complete | `M3_SCAN_QUALITY_REMAINS_PARTIAL` | canonical `buildScanQuality` remains `partial` |
| 4 | M4 | First settled failure wins | `M4_FIRST_FAILURE_CANNOT_WIN` | failure leaves race pending; later success wins |
| 5 | M5 | Consumer release cancels physical request | `M5_RELEASE_DOES_NOT_CANCEL_PHYSICAL` | sibling physical signal remains live and later succeeds |
| 6 | M6 | Late settlement mutates released output | `M6_LATE_SETTLEMENT_CANNOT_MUTATE_OUTPUT` | released bytes remain identical after late success |
| 7 | M7 | Unavailable collapses to `[]` | `M7_UNAVAILABLE_NEVER_COLLAPSES_TO_EMPTY` | failed providers retain `status=unavailable,data=null` |
| 8 | M8 | CertSpotter-only writes shared-SAN zero | `M8_CERTSPOTTER_SHARED_SAN_STAYS_NULL` | `cert_shared_san_count` remains `null` |
| 9 | M9 | Degradation/error wording disappears | `M9_DEGRADATION_WORDING_REMAINS_EXPLICIT` | excluded in-flight source has the exact non-empty release wording |
| 10 | M10 | Successful empty becomes unavailable | `M10_SUCCESSFUL_EMPTY_STAYS_MEASURED` | HTTP-200 JSON `[]` wins with `available`, zero and no error |
| 11 | M11 | Slower pre-release success is discarded | `M11_BOTH_PRE_RELEASE_SUCCESSES_RETAINED` | both terminal-before-release source results remain included |

Negative controls are also frozen: syntax failure, import/load failure and a
wrong-reason FAIL ID must all be rejected as mutation kills.

No expectation may be adjusted from mutation execution. A contract change requires
a separate founder-visible decision before another run.
