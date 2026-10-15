# Time-limited audit exceptions

An exception accepts a stated risk until a review deadline. It does not install a
fix, remove an advisory, establish production exploitability, or earn a fixed-case
count. Dependency fixes and overrides remain documented in
`DEPENDENCY-OVERRIDES.md`.

`scripts/security/audit-exception-register.json` is the machine-readable record.
`node scripts/validate-audit-exceptions.js` executes `npm audit --json` in the
frontend workspace, explicitly including dev, optional and peer dependencies.
It retains the former high/critical failure threshold. Every high/critical
finding must resolve entirely to an unexpired exception matching its workspace,
package, GHSA identifier and advisory range exactly. A mixed, missing or cyclic
`via` chain fails. Moderate/low findings are not silently removed; they retain
their previous nonblocking treatment.

Tool failures, malformed reports, count drift, stale records, unknown fields,
missing ownership, expired/invalid dates, incorrect lock paths or production
reachability fail the gate. Dates use the UTC calendar day: `review_by` is valid
through that entire day, and may be at most 90 days after `reviewed_on`. An
exception cannot remain after its last matching advisory disappears. The
canonical owner vocabulary is read from the dependency override register.

`node scripts/validate-audit-exceptions-mutations.js` runs offline positive and
negative contracts, then mutates every real guard in fresh processes. A mutation
counts as killed only when its declared test emits an assertion `FAIL` with exit
1. Import errors, tool errors and signals do not count. Identity, graph-walk,
severity and full-graph command mutants supplement the per-guard proof. No-op
and wrong-guard controls must retain the original rejection.

## Resolved E-1

**braces — GHSA-vfj7-8cjw-p6xm — `<=3.0.3`**

Status: **RESOLVED 15 October 2026**. The former time-limited risk acceptance
was authorized by the Founder under LYNCEUS P2 FIX ADDENDUM-R5 on 4 October
2026. The register dates below are the explicit dispatch dates; they do not
backdate this authorization.

- Workspace was `frontend`.
- Locked path was `node_modules/braces`, version `3.0.3`, `dev=true`.
- Reachability was `dev_only`; the complete locked path set was checked and
  `npm ls --omit=dev braces` must return an empty dependency tree after the
  governed install. The `--omit` flag is used only for this separate reachability
  proof, never for the audit.
- Advisory: stack exhaustion through deeply nested patterns. No fixed braces
  version existed, so Tailwind CSS 4 was the upstream removal path.
- Transitive audit records were `chokidar`, `fast-glob`, `micromatch` and
  `tailwindcss`; they were accepted only when **all** of their `via` paths terminated at this exact
  advisory. Their names are not a blanket allowlist.
- Owner: **CyberMeters engineering (founder-owned)**.
- Introduced/reviewed: **2026-10-03**. Review by: **2027-01-01 UTC**.

Tailwind CSS 4.3.3 removed `braces`, `chokidar`, `fast-glob` and `micromatch` from
the frontend dependency graph. E-1 was deleted from the live register after the
complete frontend audit reported zero vulnerabilities and local typecheck,
component tests, production build and browser lifecycle test passed. This section
is retained only as the historical record of the former exception.
