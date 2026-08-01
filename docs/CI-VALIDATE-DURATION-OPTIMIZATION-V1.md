# CI Validate Duration Optimisation V1

Status: implemented for review; not merged or deployed

Measurement date: 1 August 2026
Exact baseline: `20ed322c197528f6c11485016bca7393596c3bd3`

## Goal

Reduce pull-request wait time only for two narrow, proven content classes:

1. exactly one regular textual `CHANGELOG.md` change; or
2. regular textual `docs/**/*.md` additions/modifications, excluding
   `docs/security/**` and `docs/CAPABILITIES.md`.

All push events, including every `push: main`, run the complete CI gate. This is
a duration/wait-time optimisation, not a GitHub billing or spending change.

## Exact pre-change map

At the baseline SHA, `.github/workflows/ci.yml` was 1,194 lines and started two
jobs for every pull request and every push to `main`:

- `validate`, containing 274 unique CI-wired `scripts/validate-*.js` commands,
  dependency installation, syntax, bundle, audit, test, build, licence and SBOM
  gates;
- `sast`, running Semgrep independently.

There was no diff classifier, positive skip manifest or step-reachability
contract. `scripts/validate-ci-governance.js` proved trigger shape and textual
validator wiring, but a present step could be made unreachable with `if: false`
without that validator noticing.

## Phase 0 measurement report

The measurement set is the most recent 100 completed CI workflow runs returned
by the private GitHub Actions API, from 28 July through 1 August 2026. It contains
74 `pull_request` and 26 `push` runs. PR file metadata and local git history were
used to classify the associated 28 PRs; implementation classification does not
use the GitHub PR Files API.

| Event | Change class | Runs | Distinct PRs | Successful Validate samples |
| --- | --- | ---: | ---: | ---: |
| pull_request | CHANGELOG-only | 9 | 6 | 6 |
| pull_request | docs-only | 9 | 5 | 9 |
| pull_request | mixed | 30 | 7 | 15 |
| pull_request | substantive | 26 | 10 | 20 |
| push:main | CHANGELOG-only merge | 6 | 6 | 6 |
| push:main | docs-only merge | 3 | 3 | 3 |
| push:main | mixed merge | 7 | 7 | 7 |
| push:main | substantive merge | 10 | 10 | 10 |

Cancelled or failed Validate jobs are not used as successful wall-time
baselines. SAST can complete even when Validate later fails or is cancelled.

### Observed wall time

| Event/class | Validate p50 | Validate p90 | SAST p50 | SAST p90 |
| --- | ---: | ---: | ---: | ---: |
| PR CHANGELOG-only | 605s | 676s | 132s | 147s |
| PR docs-only | 620s | 665s | 129s | 136s |
| PR mixed | 566s | 931s | 130s | 139s |
| PR substantive | 599s | 637s | 128s | 134s |
| push:main CHANGELOG-only | 609s | 669s | 133s | 139s |
| push:main docs-only | 649s | 654s | 135s | 140s |

The exact current-main run `30699425358` at the baseline SHA took **1,138s**
for Validate and **136s** for SAST. It includes the newly merged scan-quality
strict-mutation step at 446s. Across the available #368 samples that step had a
244s median and 467s maximum.

The required full-history checkout measured 4s on exact-head run `30705759295`,
versus 2s on baseline run `30699425358`. This observed 2s overhead plus the 1s
classifier execution remains inside the conservative 5s allowance used below.

Cloudflare Pages reported 99 checks for the 100 commits, but its GitHub check
records set `started_at` equal to `completed_at`; therefore a real Pages wall
duration is **unknown**. The commit/run-created-to-terminal proxy was roughly
29s p50 for narrow PRs, but reruns can produce negative proxy values because the
Pages check already existed. That proxy is not presented as a build duration.

### Billing data

Faturalanan/billable minutes are **unknown**. The Actions timing API returned
`billable.UBUNTU.total_ms = 0` for all 100 runs, while the billing endpoint was
not available (404). This report makes no billed-minute, dollar or cost-saving
claim. All savings below are wall-clock estimates.

### Docs-only does not mean validator-free

The baseline had 274 CI-wired validator scripts. No wired validator read the
contents of `CHANGELOG.md`. The following real documentation inputs were found
and remain unconditional in V1:

- `validate-capabilities-doc.js` reads `docs/CAPABILITIES.md`;
- `validate-openapi.js`, `validate-dmarcbis-p6.js` and
  `validate-frontend-env-contract.js` read `docs/openapi.json`;
- `validate-frontend-env-contract.js` also reads `docs/API_REFERENCE.md`;
- `validate-gate5-cutover-prep.js` reads the Gate 5 security runbook.

Security/auth/tenant/billing validator comments also map their contracts to
security inventories. V1 does not conditionalise those gates. Secret scan,
classifier validation, CI governance, SAST, builds, audits, bundle checks and
all non-manifest validators continue to run.

## Design decision

The proof burden is inverted. V1 does not claim to have discovered every
validator that might be needed. It has a versioned, positive skip-list of seven
heavy steps whose independence was reviewed and executed both with and without
the docs tree. Any missing optimisation only increases wait time.

The classifier returns one of:

- `RUN_ALL`;
- `SAFE_DOCS_ONLY`, with `content_class` equal to `CHANGELOG_ONLY` or
  `DOCS_ONLY`;
- `UNKNOWN_FAIL_CLOSED`, whose effective mode is always `RUN_ALL`.

The workflow writes RUN-ALL outputs before launching the classifier. A syntax,
load, payload or git failure therefore cannot create a narrow run. Only the exact
decision string `SAFE_DOCS_ONLY` activates a skip condition.

The classifier uses local git objects, never a truncated Files API response. It
requires:

- `actions/checkout` with `fetch-depth: 0`;
- valid and present exact event base/head commit objects;
- a non-shallow repository;
- a resolvable merge-base equal to the exact event base;
- a non-empty three-dot diff;
- at most 300 changed files;
- only A/M status, regular mode `100644`, blob type, textual diff;
- one unmixed content class.

Rename/copy, deletion, symlink, submodule/type change, binary, unexpected path,
mixed content, stale evidence, malformed event data or any git inconsistency is
RUN-ALL (directly or through `UNKNOWN_FAIL_CLOSED`).

## Threat model and governance

| Threat | Fail-closed control |
| --- | --- |
| shallow/missing history or wrong merge-base | exact object, shallow and merge-base checks; dedicated negative fixtures |
| Files API truncation above 300 | no Files API; local diff plus explicit 300-file ceiling |
| workflow/classifier/manifest self-bypass | all are non-allowlisted paths, so this PR and every such PR run all |
| mixed runtime disguised as docs | every path/status/object is classified; one unsafe entry runs all |
| binary/symlink/rename/copy/deletion | object/status/numstat checks run all |
| stale or narrowed step-independence proof | source-byte drift makes the classifier RUN-ALL; a semantic pin prevents evidence definitions from being silently narrowed |
| visible, unreachable or non-blocking validator step | YAML AST reachability policy; only seven exact steps may carry one canonical condition, and `continue-on-error` is forbidden |
| classifier process crash | workflow writes RUN-ALL outputs first and retains them on failure |
| broken main hidden by a green docs PR | every push to main runs full CI; a main failure is a release blocker |

`yaml@2.9.0` is pinned as a Worker development dependency so governance parses
the workflow as YAML rather than treating step-name text presence as reachability.

## Versioned skip-list and proof

Source of truth: `.github/ci-safe-docs-only-v1.json`.

| Skipped only for a safe class | Baseline wall time | Independence evidence |
| --- | ---: | --- |
| Scan-quality vocabulary inventory | 20s | source roots exclude docs/CHANGELOG; positive 10/10; docs-absent positive 10/10 |
| Scan-quality vocabulary strict mutations | 446s | child/targets exclude docs; positive 20/20 mutants + 1/1 control; same result docs-absent |
| M5.b remaining reconciliation | 35s | DB/Worker/shared/frontend graph; positive and docs-absent 171/171 |
| M5.a Cyber Essentials cases | 28s | DB/Worker/frontend graph; positive and docs-absent 233/233 |
| ScanDetail strict mutations | 26s | frontend AST/Vitest graph; positive and docs-absent 8/8 exact kills |
| IntelligencePage strict mutations | 27s | frontend AST/Vitest graph; positive and docs-absent 9/9 exact kills |
| Frontend Vitest coverage | 80s | frontend graph; positive and docs-absent 63/63 files, 521/521 tests |

Gross measured skip-list time is 662s. With a conservative 5s classifier
allowance, the current 1,138s Validate run is projected at approximately 481s
for a qualifying PR: about **657s (10m57s) of Validate wall-clock reduction**.
This sits within the independently estimated 7–15 minute range. It is not a
promise until a later real CHANGELOG-only PR proves the live path.

SAST remains parallel and approximately 130–140s. A hypothetical broader
42–50s Validate-only fast path would still not make total CI sub-minute; V1 does
not implement or claim that broader path. Using the independent 15/27 narrow-run
mix, the modelled weighted all-CI effect is roughly 20–25%, not a measured billing
reduction.

## Always-run set

The YAML-AST policy pins these named gates as present exactly once and without
any step-level `if`:

- secret scan;
- classifier validation and conditional-step governance;
- M5.a Website Security cases;
- M5 closure;
- CI governance;
- date-rot governance;
- commercial canonicalisation;
- frontend environment contract;
- CAPABILITIES drift.

Only versioned skip-list steps may have a condition. All other working-directory
or generated-inventory gates remain unconditional because their independence is
not proven.

## Executable proof

`scripts/validate-ci-safe-docs-only.js` pins:

- 28 fresh-process, real-git fixtures;
- 15 fresh-process load-bearing mutants;
- 63 exact assertions;
- exact mutant FAIL-name sets;
- rejection of syntax/load/spawn/signal failures as kills;
- byte restoration of every mutated target;
- complete pre/post worktree fingerprint equality.

The matrix covers CHANGELOG-only, ordinary docs modification and addition, docs+runtime, docs+scripts,
docs+workflow, docs+CHANGELOG, rename, copy, deletion, symlink, submodule, binary, root
governance, security inventory, workflow, scripts, classifier, manifest, 301
files, malformed/missing base, stale evidence, shallow checkout,
unresolved/wrong merge-base, a real allow-empty commit, unexpected event and
push:main. Only CHANGELOG-only and ordinary
allowlisted docs are safe.

## Residual risks and backlog

1. **PR-green is not merged-main-green.** `push: main` remains full CI. Any main
   failure is a release blocker even if a preceding narrow PR was green.
2. The first real narrow path remains pending a later genuine CHANGELOG-only PR;
   this mechanism-changing PR must and will run all.
3. Source/call-graph review plus docs-absent execution cannot prove every future
   dynamically constructed conditional read. Evidence-source byte drift does
   not block a substantive full run; it disables the fast path until explicitly
   re-proven. Evidence-definition narrowing remains a pinned governance failure.
4. Cloudflare Pages-before-main-CI ordering is unchanged.
5. Billing/spending settings, sharding, matrix parallelism and product runtime
   are unchanged.
6. **`SCAN-QUALITY-MUTATION-RUNTIME`:** the strict runner executes on every full
   CI run, measured 244s median and 467s maximum, and can account for roughly
   39–47% of current Validate time. V1 removes it only from proven narrow content
   PRs and does not reduce substantive PR time. Any optimisation requires a
   separate governed PR that preserves fresh-process execution, exact FAIL sets,
   mutation strength and restore/fingerprint discipline. This PR does not alter
   that runner, parallelise it or shard it.

## Scope boundaries and rollback

No runtime product behaviour, schema, migration, deployment, tag, release
CHANGELOG entry, billing/spending setting, sharding or Pages ordering is changed.
Rollback is code-only: revert the V1 workflow, classifier, manifest, validators,
YAML dependency and this design record. No historical or production data is
affected.
