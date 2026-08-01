# CI SAFE_DOCS_ONLY V1 Acceptance Protocol

This document alone is not an acceptance claim. Production acceptance requires two linked pieces of evidence:

1. The docs-only pull-request run classifies as `SAFE_DOCS_ONLY` / `DOCS_ONLY`, skips only the seven pinned heavy steps, and completes every other Validate step plus SAST successfully.
2. The `push:main` run for that same pull request's merge commit classifies as `RUN_ALL`, runs all seven heavy steps, and completes Validate plus SAST successfully.

A green pull request is not the same as green merged `main`. Cloudflare Pages may publish before main CI completes; Pages is not an independent release gate.

The first observed durations are reported below as measurements, not estimates. This test does not prove billing or dollar savings.

## Evidence vocabulary

- **MODEL:** a pre-production forecast assembled from historical timing inputs.
- **MEASUREMENT:** an observed duration or result from one exact run.
- **PAIRED OPERATIONAL MEASUREMENT:** near-time PR and merged-main observations over the same tree; this is not a controlled laboratory experiment.

## First production acceptance record

PR #370 passed both linked evidence requirements. PR head `9f840a6130ee82c3467039f1fcba49e07458c0d8` and merge commit `9612e499cbb5be3ca06c548416a06b5bdfacaf90` share tree `be0a58acf2b44a5884a2db86eb0f6921f2be9c06`.

| Leg | CI run | Mode | Validate | SAST | Validate success / skipped | Total successful steps | Pages |
| --- | ---: | --- | ---: | ---: | ---: | ---: | --- |
| PR head | `30719720095` | `SAFE_DOCS_ONLY` / `DOCS_ONLY` | 489s | 140s | 291 / exactly 7 pinned | 299 | success, check `91421379421` |
| merge `push:main` | `30720067642` | `RUN_ALL` | 987s | 130s | 298 / 0 | 306 | success, check `91422298173` |

Counts use GitHub's job-step records, including setup, post-job and completion steps. All seven pinned heavy steps ran successfully on main. Validate and SAST succeeded on both legs; SAST and Pages were not fast-pathed. The measured Validate saving was 498s (8m18s), or 50.5% relative to the full main run.

The original pre-production MODEL forecast of 175s for an ordinary-docs Validate run is retained in the optimisation record but superseded for acceptance by the 489s MEASUREMENT. It was 314s below the observed fast path. The forecast reduction of 445s was 53s below the paired 498s reduction. The model combined medians from different runs and underestimated residual workload; runner/cache variance is only a residual inference. One pair does not establish p50/p90, and billing/dollar savings remain unknown.

**CI-SAFE-DOCS-ONLY-V1 — PRODUCTION ACCEPTANCE: PASS**
