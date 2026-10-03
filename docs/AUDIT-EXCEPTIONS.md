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

## E-1

**braces — GHSA-vfj7-8cjw-p6xm — `<=3.0.3`**

Status: **time-limited risk acceptance, not fixed**. Authorized by the Founder
under LYNCEUS P2 FIX ADDENDUM-R5 on 4 October 2026. The register dates below are
the explicit dispatch dates; they do not backdate this authorization.

- Workspace: `frontend`.
- Locked path: `node_modules/braces`, version `3.0.3`, `dev=true`.
- Reachability: `dev_only`; the complete locked path set is checked and
  `npm ls --omit=dev braces` must return an empty dependency tree after the
  governed install. The `--omit` flag is used only for this separate reachability
  proof, never for the audit.
- Advisory: stack exhaustion through deeply nested patterns. There is no fixed
  braces version in the current advisory. Tailwind CSS 4 is a possible upstream
  removal path, not a migration authorized by this change.
- Transitive audit records: `chokidar`, `fast-glob`, `micromatch`, `tailwindcss`
  are accepted only when **all** of their `via` paths terminate at this exact
  advisory. Their names are not a blanket allowlist.
- Owner: **CyberMeters engineering (founder-owned)**.
- Introduced/reviewed: **2026-10-03**. Review by: **2027-01-01 UTC**.

Remove E-1 when a fixed braces version is installed or an authorized Tailwind CSS
4 migration removes the affected chain. With the record deleted, prove the full
frontend `npm audit --audit-level=high` is clean and run typecheck, coverage and
build. If no supported fix is ready at expiry, CI fails; renewal needs a fresh
explicit decision. This exception leaves the Worker audit unchanged and grants
no case-database transition or verified-fix claim.
