# CT-R2 PR-3 structural first-success-wins — local candidate freeze

Date frozen: **2026-08-07**

Status: **LOCAL READ-ONLY CANDIDATE — STOP FOR INDEPENDENT REVIEW**

## Exact bindings

- Repository base: `6699f88c396bdc6a5925d2c68f4f939b15091f25`
- Candidate `HEAD`: `6699f88c396bdc6a5925d2c68f4f939b15091f25` (intentionally uncommitted)
- Branch: `codex/ct-r2-pr3-first-success-wins`
- Worktree: `/private/tmp/cybermeters-ct-r2-pr3-first-success-wins`
- Payload diff: 15 files, 989 insertions, 71 deletions
- Payload binary-diff SHA-256 before this freeze record:
  `1927a90d8dfe5984dd4f7be7d99d6e7c96ef131805fa30bd8b09c58d818d4a17`
- Main checkout: not edited; its pre-existing dirty files remain outside this worktree.

## Goal

Release each CT consumer on the first successful provider result, never on the
first settlement, while the sibling physical request continues under the existing
bounds. Keep degradation explicit, preserve source identity, retain terminal
telemetry, and prevent late results from mutating released customer evidence.

## Exact pre-change map

- `ct-provider-cache.js` already owned one physical request per domain/provider,
  successful-empty versus unavailable semantics, bounded timeout/retry policy,
  consumer-only release, physical attempt telemetry and global-deadline aborts.
- `subdomains-scan.js` launched both providers but awaited both consumer results.
- `ssl-scan.js` awaited crt.sh first and launched CertSpotter only as fallback.
- `scan-engine.js::buildScanQuality` made CT source degradation `partial` through
  the existing module `incomplete` contract.
- `cert_shared_san_count` was already a crt.sh-specific nullable measurement.
- CT-R1 terminal telemetry and CT-R2 PR-2A overlap-at-release telemetry already
  existed; no parallel telemetry or evidence authority was needed.

## Design decision

- Add one provider-neutral orchestration helper over the existing cache.
- Launch both providers together; release only after `status=available` or after
  both terminal failures.
- Admit both providers when both were terminal at the release boundary.
- Snapshot and freeze the released provider projection.
- Keep a released/in-flight provider unavailable in customer evidence with exact
  exclusion wording; later settlement updates terminal telemetry disposition only.
- Preserve the existing cache's physical-request lifetime, provider policy,
  attempt cap, retry count, timeouts and global abort authority.
- Preserve existing subdomain degradation and scan-quality semantics.

## Scope boundaries and compatibility

In scope: CT cache/orchestration, SSL and subdomain consumers, additive terminal
telemetry disposition, source-honesty tests, frozen semantic mutations, CI wiring,
and the dated founder gate/D0 decision.

Out of scope and unchanged: quality regrading, timeout/retry calibration, provider
preference, overlap-rate claims, chronic partial-rate promises, schemas/migrations,
production data, production scans, deployment, Item 10/Item 11 implementation and
unrelated roadmap work.

Existing response fields and meanings remain compatible. New cache snapshot and
telemetry fields are additive. No frontend verdict or remediation source was added.

## Founder decision and D0

`CT-R2-PR-3-FOUNDER-DECISION-2026-08-07.md` records that the historical gate was
**split, not passed**. Structural work is authorised; the 14-day gate remains
binding for numeric calibration, overlap claims, measured provider preference and
any quality regrade. The canonical historical attribution report was not edited.

HTTP 404 remains unavailable. HTTP 200 JSON `[]` remains a measured successful
zero. No metric-improving 404 reinterpretation was introduced.

## Fail-first transcript

Before any runtime file was added or edited:

```text
$ node scripts/validate-ct-first-success-wins.js
exit: 1
result: 0/18 passed; all 18 stable predicates failed because
workers/scan-api/src/engines/ct-first-success.js did not exist on the exact base.
```

The failing matrix already covered fast CertSpotter, fast crt.sh, first failure,
both failure, both pre-release successes, successful empty, late success, late
failure, immutable release, explicit telemetry exclusion, shared-SAN null and
one-provider degradation/partial quality.

## Frozen mutation map and result

The pre-execution ordered map is in
`CT-R2-PR-3-MUTATION-CONTRACT.md`. Expected FAIL sets were not changed after any
run.

```text
M1  -> M1_ONE_SUCCESS_RETAINS_DEGRADATION
M2  -> M2_ONE_SUCCESS_NOT_TWO_PROVIDER_COMPLETE
M3  -> M3_SCAN_QUALITY_REMAINS_PARTIAL
M4  -> M4_FIRST_FAILURE_CANNOT_WIN
M5  -> M5_RELEASE_DOES_NOT_CANCEL_PHYSICAL
M6  -> M6_LATE_SETTLEMENT_CANNOT_MUTATE_OUTPUT
M7  -> M7_UNAVAILABLE_NEVER_COLLAPSES_TO_EMPTY
M8  -> M8_CERTSPOTTER_SHARED_SAN_STAYS_NULL
M9  -> M9_DEGRADATION_WORDING_REMAINS_EXPLICIT
M10 -> M10_SUCCESSFUL_EMPTY_STAYS_MEASURED
M11 -> M11_BOTH_PRE_RELEASE_SUCCESSES_RETAINED

final: 11/11 semantic mutants killed by exact ordered right-reason FAIL sets
controls: syntax 1/1, load 1/1, wrong-reason 1/1 rejected
```

The first mutation execution exposed harness findings, not expectation changes:
M9 compared the mutated exported wording, M10 left its sibling pending, and the
invalid-kill controls accepted non-semantic exits. The harness was corrected to
use the frozen literal, terminate the sibling, and require a normal predicate-false
summary. The frozen expected sets remained unchanged.

An adjacent existing mutation also exposed right-reason drift: its reserved-path
predicate mistook the new helper's `first_success` release for the outer reserved
boundary. The oracle now requires an independent non-`first_success` outer release;
the existing frozen mutant then killed both intended predicates and finished
29/29 with 2/2 controls.

A detached local scan-quality mutation command was accidentally retried once. Its
sole temporary target (`asm-cases.js`) was restored to exact base bytes before a
single attached rerun completed 20/20 kills, 1/1 negative control and a restored
whole-worktree fingerprint. No mutant residue remains.

## Focused validation

All commands below finished green on the frozen source:

- PR-3 semantics: 18/18; PR-3 mutations: 11/11 + 3/3 controls.
- Shared CT cache: 64/64; SSL concurrency: 12/12.
- CT provider resilience: 52/52; blackout honesty: 49/49.
- CT overlap: 118/118; engine trace: 24/24; mutations: 21/21.
- Consumer isolation: 33/33; mutations: 29/29 + 2/2 controls.
- Platform abort: 35/35; mutations: 15/15 + 1/1 control; exact Wrangler
  command atomicity: 7/7 (run with local sandbox permission, no remote access).
- Certificate/shared-SAN: 39/39; mutations: 2/2 + 3/3 controls.
- CT-R1 telemetry: 125/125; engine trace: 43/43; mutations: 11/11.
- Scan-quality inventory: 10/10 with counts unchanged at 49 runtime comparisons,
  90 runtime direct reads, 35 SQL predicates and 23 SQL projections.
- Scan-quality mutations: 20/20 + 1/1 negative control; partial-scan honesty:
  57/57; BRS honesty: 47/47; BRS trace: 24/24.
- Email Worker equivalence: 18/18; ingestion reliability: 38/38; parser: 50/50;
  cutover: 22/22; deploy traceability: 14/14.
- Worker syntax, `git diff --check`, certificate and attack-surface regression
  traces, tenant isolation and migration validators passed.

## Full validation

- CI single-line Node-script inventory: 294/295 commands passed. This includes
  all 26 pre-CT commands, all security/tenant/report/case gates, all CT gates,
  every remaining mutation suite and licence validation.
- The remaining command, `validate-ci-safe-docs-only.js`, deliberately requires
  each mutation target to equal committed `HEAD`. Default invocation failed closed
  before writes because this authorised candidate changes `ci.yml` and
  `ci-workflow-policy.js` but may not be committed. A local candidate-snapshot run
  proved 83/85 assertions, 31/31 fixtures and 26/26 mutants; only the two nested
  interrupt children repeated the same committed-HEAD refusal. Default fail-closed
  code was restored. `validate-ci-governance.js` passed 29/29 against the actual
  candidate workflow. Independent review after a permitted commit must rerun the
  exact safe-docs validator to close this commit-bound gate.
- Frontend: 64 files, 524/524 tests; coverage 95.88% statements / 86.43% branches;
  TypeScript passed; production build passed.
- Dependency gates: Worker audit found 0 vulnerabilities; frontend high-severity
  audit gate passed with one pre-existing moderate PostCSS advisory reported.
- Dry-runs: scan Worker, DMARCbis fixture bundle and standalone email Worker passed.
- Semgrep: 88 rules across the four changed runtime files, 0 findings.
- Secret filename scan passed. No production or remote mutation command ran.

## Files changed

Runtime:

- `workers/scan-api/src/engines/ct-first-success.js`
- `workers/scan-api/src/engines/ct-provider-cache.js`
- `workers/scan-api/src/engines/ssl-scan.js`
- `workers/scan-api/src/engines/subdomains-scan.js`

Tests/governance:

- `scripts/validate-ct-first-success-wins.js`
- `scripts/validate-ct-first-success-wins-mutations.js`
- `scripts/validate-shared-ct-provider-cache.js`
- `scripts/validate-ssl-concurrent-ct.js`
- `scripts/validate-ct-consumer-isolation-oracle.js`
- `scripts/validate-scan-telemetry.js`
- `scripts/validate-scan-quality-vocabulary-inventory.js`
- `scripts/ci-workflow-policy.js`
- `.github/workflows/ci.yml`

Decision/evidence:

- `docs/CT-R2-PR-3-FOUNDER-DECISION-2026-08-07.md`
- `docs/CT-R2-PR-3-MUTATION-CONTRACT.md`
- this freeze record.

## Schema and migrations

None. `database/schema.sql`, every migration and purge ordering are unchanged.
`node scripts/validate-migrations.js` passed. If a migration is later proposed,
this candidate is no longer the authorised PR-3 scope and work must stop.

## Behavioural changes

- SSL and subdomain CT consumers launch both providers through the existing cache.
- First available result releases the consumer; first unavailable result cannot.
- Both pre-release terminal successes remain source-specific evidence.
- In-flight sibling output is an explicit unavailable/degraded source, never a
  manufactured second success.
- Physical work is not aborted by the consumer release.
- Late success/failure updates terminal telemetry disposition and cannot alter the
  frozen customer projection.
- Successful empty remains available with count zero.
- CertSpotter-only shared SAN remains null.

## Explicit scan-quality proof

- `workers/scan-api/src/engines/scan-engine.js` is byte-identical to the exact base:
  SHA-256 `76da5b866834c835e42f4d74bfb5ff9d5be72bd12aee50ee7dd701ee98b784f6`
  on both base and candidate.
- No timeout, retry, backoff, attempt-cap or budget constant changed.
- The inventory counts above are unchanged; only reviewed source-position
  fingerprints moved.
- M3 kills any attempt to remove subdomain degradation from the partial-quality
  input, and M1/M2 prove one-provider evidence remains degraded/incomplete.
- No `partial` to `degraded`/`complete` regrade exists in this diff.

## PR, merge, deployment and production proof

- Commit: not created.
- Push: not performed.
- PR: not created.
- Merge: not performed.
- Migration application: not performed.
- Worker/Pages deployment IDs: none.
- Production scans or writes: none.
- Production acceptance: not attempted; this is a local candidate only.

## Rollback design

Because there is no migration and no production action, rollback is source-only:
remove the new helper and its two CI gates, restore the prior direct CT awaits in
SSL/subdomains, and restore the additive cache snapshot/telemetry fields and
reviewed validator pins. Historical D1/R2/customer data requires no rollback.
The existing physical provider cache, retry/timeout policy and quality resolver
remain the rollback substrate.

## Residual risks

- The 14-day gate remains binding; no latency/success preference, overlap claim,
  timeout/retry calibration or quality regrade is supported by current data.
- This PR does not promise to reduce the chronic partial-scan rate. A released
  one-provider result deliberately retains CT degradation and may remain partial.
- Late physical results are terminal cache/CT-R1 telemetry evidence when they
  settle within the scan execution window; an execution terminated by the global
  platform boundary can only record the canonical platform-abort outcome.
- The exact safe-docs mutation validator needs the first permitted commit before
  its two nested HEAD-equality interruption proofs can run green.
- No founder production acceptance was authorised or performed.

## Later-phase confirmation

No quality-policy phase, Item 10, Item 11, production acceptance, deployment or
unrelated roadmap work was started. Stop here for Claude's independent review.
