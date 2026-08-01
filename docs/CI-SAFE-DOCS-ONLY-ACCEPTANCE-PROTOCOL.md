# CI SAFE_DOCS_ONLY V1 Acceptance Protocol

This document alone is not an acceptance claim. Production acceptance requires two linked pieces of evidence:

1. The docs-only pull-request run classifies as `SAFE_DOCS_ONLY` / `DOCS_ONLY`, skips only the seven pinned heavy steps, and completes every other Validate step plus SAST successfully.
2. The `push:main` run for that same pull request's merge commit classifies as `RUN_ALL`, runs all seven heavy steps, and completes Validate plus SAST successfully.

A green pull request is not the same as green merged `main`. Cloudflare Pages may publish before main CI completes; Pages is not an independent release gate.

The first observed durations will be reported separately as measurements, not estimates. This test does not prove billing or dollar savings.
