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

The sample is reproducible rather than a moving "latest 100" assertion. Ordered
newest-first run IDs are:

`30699425358, 30698741738, 30697189005, 30696208119, 30695691408, 30694992556, 30694702432, 30694178626, 30675733571, 30675285493, 30674636479, 30674176054, 30670627324, 30668744379, 30661647878, 30660897616, 30659842490, 30658449471, 30648589886, 30647587524, 30641518000, 30638483912, 30636919508, 30636892240, 30635859903, 30635095376, 30634160899, 30633538085, 30633077456, 30632086438, 30631193822, 30630385565, 30627359276, 30624613805, 30624008610, 30605638560, 30605154468, 30605002270, 30604846939, 30604443382, 30603965563, 30602817521, 30601894393, 30601523176, 30601141708, 30597470432, 30594157208, 30591991586, 30591748030, 30589903158, 30589449350, 30587229158, 30582935425, 30567074846, 30562696766, 30535473311, 30533597737, 30533030155, 30500995397, 30500498980, 30500124321, 30493989227, 30491403374, 30482803417, 30474313711, 30472042418, 30468463675, 30458487985, 30457619216, 30456732521, 30456285859, 30451773076, 30448647561, 30446868814, 30445700266, 30444838839, 30415465588, 30414616056, 30412346901, 30408607092, 30406502419, 30404035414, 30400633581, 30399737357, 30399608417, 30397401267, 30391383396, 30384901842, 30381517617, 30378744078, 30377755912, 30359706507, 30358983531, 30357983576, 30355109291, 30353515898, 30350127410, 30348825641, 30318325048, 30317568320`.

The newline-joined ID list has SHA-256
`c1d15aa3731c33cde6ce0409bf0bc3a1e14e7f9afe48ac7ca8e50ba1d75d4032`.
For each ID, the source is `GET /repos/btncwn/CyberMeters-Platform/actions/runs/{id}/jobs?per_page=100`.
Durations are `completed_at - started_at`; only successful jobs enter the
wall-time percentiles. The reported percentile is the sorted sample at
`min(n - 1, floor(p * n))`, matching the table below. The manifest separately
pins every skip-step timing sample and source run ID used by the savings formula.

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
classifier allowance is not the whole overhead: the new governance/proof step
measured 8s on exact-head RUN-ALL run `30713452775`. A further 4s safety
allowance produces the 15s fast-path overhead used below.

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

| Skipped only for a safe class | n | Min / median / max | Source run IDs | Independence evidence |
| --- | ---: | ---: | --- | --- |
| Scan-quality vocabulary inventory | 1 | 20 / 20 / 20s | `30699425358` | source roots exclude docs/CHANGELOG; positive 10/10; docs-absent positive 10/10 |
| Scan-quality vocabulary strict mutations | 3 | 146 / 244 / 467s | `30670627324`, `30675733571`, `30698741738` | successful PR samples; child/targets exclude docs; positive 20/20 mutants + 1/1 control; same result docs-absent |
| M5.b remaining reconciliation | 1 | 35 / 35 / 35s | `30699425358` | DB/Worker/shared/frontend graph; positive and docs-absent 171/171 |
| M5.a Cyber Essentials cases | 1 | 28 / 28 / 28s | `30699425358` | DB/Worker/frontend graph; positive and docs-absent 233/233 |
| ScanDetail strict mutations | 1 | 26 / 26 / 26s | `30699425358` | frontend AST/Vitest graph; positive and docs-absent 8/8 exact kills |
| IntelligencePage strict mutations | 1 | 27 / 27 / 27s | `30699425358` | frontend AST/Vitest graph; positive and docs-absent 9/9 exact kills |
| Frontend Vitest coverage | 1 | 80 / 80 / 80s | `30699425358` | frontend graph; positive and docs-absent 63/63 files, 521/521 tests |

The exact baseline run happened to total 662s across these steps, but that
single-run sum is not the expected saving. The reproducible median-based model
is:

```text
gross = 20 + 244 + 35 + 28 + 26 + 27 + 80 = 460s
overhead = 2s full-history delta + 1s classifier + 8s proof suite + 4s allowance = 15s
net = 460 - 15 = 445s (7m25s)
```

Applied to the observed narrow PR p50 values, that gives a modelled Validate
duration of about 160s for CHANGELOG-only (`605 - 445`) and 175s for ordinary
docs (`620 - 445`). The exact 1,138s outlier would model at 491s using its 662s
step sum, but that is explicitly an outlier scenario, not a 647s general claim.
The honest current estimate is therefore about **7m25s median-based reduction**,
within the independent 7–15 minute range. It is not a production result until a
later real CHANGELOG-only PR proves the live path.

SAST remains parallel and approximately 130–140s. A hypothetical broader
42–50s Validate-only fast path would still not make total CI sub-minute; V1 does
not implement or claim that broader path. The independent relay's roughly
20–25% weighted all-CI estimate is retained only as an external model: the
effective production eligibility rate has not yet been measured, so V1 does not
present that percentage as an observed result or billing reduction.

## Always-run set

The YAML-AST policy pins these named gates as present exactly once and without
any step-level `if`:

- secret scan;
- classifier validation and conditional-step governance;
- entry-point inventory generation/drift validation;
- tenant-isolation matrix generation/drift validation;
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

- 31 fresh-process, real-git fixtures;
- 26 fresh-process load-bearing mutants;
- 85 exact assertions;
- exact mutant FAIL-name sets;
- rejection of syntax/load/spawn/signal failures as kills;
- byte restoration of every mutated target;
- complete pre/post worktree fingerprint equality.

The matrix covers CHANGELOG-only, ordinary docs modification and addition, docs+runtime, docs+scripts,
docs+workflow, docs+CHANGELOG, rename, copy, deletion, symlink, submodule, binary, root
governance, security inventory, workflow, scripts, classifier, manifest, 301
files, malformed/missing base, stale evidence, shallow checkout,
unresolved/wrong merge-base, a real allow-empty commit, unexpected event and
push:main, case-varied security/governance names and deny-over-allow precedence.
Only CHANGELOG-only and ordinary
allowlisted docs are safe.

Before any mutation write, every target must equal its exact `HEAD` bytes. The
suite centrally retains originals, restores in per-mutant and outer `finally`
blocks, and installs synchronous `SIGINT`/`SIGTERM` restore handlers. Controlled
children prove both signal paths restore target bytes and the full worktree
fingerprint. `SIGKILL` cannot be handled by a process and remains an explicit
residual: after any hard kill, the operator must assume the tree is dirty and
rerun the target-byte/fingerprint preflight before any commit or push.

## Residual risks and backlog

1. **PR-green is not merged-main-green.** `push: main` remains full CI. Any main
   failure is a release blocker even if a preceding narrow PR was green.
2. The first real narrow path remains pending a later genuine CHANGELOG-only PR;
   this mechanism-changing PR must and will run all.
3. Source/call-graph review plus docs-absent execution cannot prove every future
   dynamically constructed conditional read. Evidence-source byte drift does
   not block a substantive full run; it disables the fast path until explicitly
   re-proven. Evidence-definition narrowing remains a pinned governance failure.
   Re-pin owner is the implementation owner changing the affected skipped-step
   source graph, with an independent reviewer. Re-pins occur only in a normal PR
   after renewed source/import/call-graph review and docs-absent proof; there is
   no periodic, automatic or silent re-pin.
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
7. **Practical fast-path eligibility is deliberately narrow.** The branch must
   contain the exact current event base/main tip, every evidence fingerprint
   must still be current, and the content class must be eligible. A behind-main
   docs branch runs all. If a substantive main merge changes any evidence scope,
   subsequent docs PRs run all until the governed re-proof/re-pin completes.
   Savings are not a production result until this eligibility rate and the first
   genuine `SAFE_DOCS_ONLY` run are observed.
8. `SIGKILL` cannot execute restore handlers; interruption audit remains
   mandatory after any killed mutation process.

## Scope boundaries and rollback

No runtime product behaviour, schema, migration, deployment, tag, release
CHANGELOG entry, billing/spending setting, sharding or Pages ordering is changed.
Rollback is code-only: revert the V1 workflow, classifier, manifest, validators,
YAML dependency and this design record. No historical or production data is
affected.
