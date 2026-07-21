# Security Release-Gate Closure Pack

Last updated: 21 July 2026.

Purpose: a single, honest view of the security release gate that **separates what
is engineering-complete from what still needs a founder manual action**. It does
not use completion percentages, and it does not claim an independent pentest.

This pack complements `docs/SECURITY-VERIFICATION-MATRIX.md` (the ASVS-mapped
control matrix). Where that document is the control-by-control record, this one is
the gate-closure summary: it states the *verification state* of each area and the
*exact remaining manual actions*.

## Verification-state legend

Each area carries one or more of these states. They are cumulative, not a scale.

- **fixture-verified** — proven by an executable CI suite against the real Worker
  router + in-memory SQLite (or the real frontend under jsdom).
- **code-reviewed** — the source path was inspected and the control confirmed
  present at the responsible layer (not only at the UI).
- **mutation-verified** — the load-bearing guard was defeated in a throwaway edit
  and the suite went red, proving the test actually bites.
- **deployed** — the code carrying the control is live in production.
- **founder-live-acceptance-pending** — a manual action against a real browser /
  live IdP / production surface remains, by design (cannot be safely automated).
- **independent-pentest-pending** — an external third-party opinion is a separate
  gate, deliberately not claimed here.

## Gate areas

| # | Area | State | Evidence (CI suite / source) |
|---|------|-------|------------------------------|
| A–C | Cross-tenant authz / IDOR-BOLA / R2 / API-token | fixture-verified · mutation-verified · deployed | `validate-tenant-authz-coverage.js`, `validate-tenant-isolation*.js`, `validate-authz-properties.js` |
| A6 | Viewer-role enforcement (Related Changes) | fixture-verified · code-reviewed · mutation-verified · deployed · **founder-live-acceptance-pending** | `validate-a6-viewer-enforcement.js` (backend, real router) + `WorkspaceRelatedChangeDetailPage.test.jsx` (frontend) |
| B2–B4,B6 | Session / logout+reset / MFA / password-reset | fixture-verified · mutation-verified · deployed | `validate-auth-coverage.js`, `validate-auth-session-hardening.js` |
| B5 | Microsoft SSO — claims + callback/exchange readiness | fixture-verified · code-reviewed · mutation-verified · deployed · **founder-live-acceptance-pending** | `validate-auth-coverage.js` (B5 claims), `validate-oauth-callback-readiness.js` (route CSRF/OTC/nonce), `validate-sso-linking-guard.js` (nOAuth) |
| D | Billing / webhook abuse | fixture-verified · mutation-verified · deployed | `validate-billing-abuse-coverage.js` |
| E2/E4 | Injection — server render sinks + mass-assignment | fixture-verified · mutation-verified · deployed | `validate-injection-coverage.js` |
| E1/E3 | DOM-XSS (client) | fixture-verified · code-reviewed · mutation-verified · deployed · **bounded-live-DAST-optional** | `validate-dom-xss-sinks.js` (source-guard), `domXssSafety.test.jsx` (escaping + `appPath`) |
| F2–F4 | Workflow abuse — verification / alerts+digest / rate-limit | fixture-verified · mutation-verified · deployed | `validate-workflow-abuse-coverage.js` |
| SSRF | Domain guard + scan guard + per-hop revalidation | fixture-verified · mutation-verified · deployed | `validate-ssrf-*.js`, `validate-reserved-probe-ssrf.js`, `validate-c1-redirect-ssrf.js` |
| DMARC XML | XXE / entity-expansion / size DoS | fixture-verified · deployed | `validate-dmarc-xml-safety.js` |
| Rate limits | Auth / scan-start / expensive endpoints, fail-closed | fixture-verified · mutation-verified · deployed | `validate-workflow-abuse-coverage.js` (F4), route source (`{ failClosed: true }`) |
| Nuclei | Unauthenticated public-surface baseline | code-reviewed (baseline run) | recorded in `docs/SECURITY-VERIFICATION-MATRIX.md` |
| Pentest | Independent external opinion | **independent-pentest-pending** | founder decision (separate gate) |

Notes:
- "deployed" reflects that the *controls* are live in production. Two feature
  branches carry controls that are engineering-complete but **not yet deployed by
  founder decision** and are out of scope of this gate: the SPF authorisation
  detection (#251/#252) and the M7 billing cutover — neither is a release-gate
  blocker for the areas above.
- Every "fixture-verified" area also ran locally, not by CI alone, during its
  authoring episode.

## Remaining manual actions (the only things left)

These are, by design, the actions that cannot be automated safely without founder
credentials, a real browser, a live IdP, or a production surface. Each has a
prepared script so the founder action is minimal.

1. **A6 viewer-role production spot-check** — log in as a viewer-role member on a
   workspace that has a related change; confirm the read-only Review card
   ("available to workspace managers") and the absence of every mutation control.
   The backend refusal and the honest `can_manage` signal are already CI-proven;
   this is a visual confirmation only. (No script doc needed beyond this line.)

2. **B5 live Microsoft-SSO acceptance** — run
   `docs/FOUNDER-LIVE-OAUTH-ACCEPTANCE-SCRIPT.md` against the configured Azure App
   Registration. Only the live token exchange + RS256/JWKS verify + browser
   handoff need a real IdP; everything deterministic is already CI-proven.

3. **Bounded production DOM-XSS acceptance (optional)** — if still required, run
   `docs/FOUNDER-DOM-XSS-DAST-PLAN.md` (founder test workspace only, ≤1 req/s,
   non-destructive payloads). The static posture (no raw-HTML sink, React
   escaping, origin-locked link sanitiser) is already CI-proven, so this is a
   confirmation and can reasonably be deferred.

4. **Independent pentest decision** — a founder decision: commission an external
   third-party pentest + retest, or defer with a documented risk acceptance. This
   gate is deliberately not claimed as complete by internal work.

## What did NOT happen in the closure work

No deployment (Worker or Pages), no live OAuth login, no production DAST or
fuzzing, no Stripe/product/price/secret/webhook change, no legal/commercial
wording change, no SPF runtime change or deploy of #251/#252, and no independent
pentest claim. All closure work was test-, source-, and evidence-preparation only,
merged CI-green.

## Final gate status

`SECURITY RELEASE-GATE ENGINEERING COMPLETE / FOUNDER LIVE ACCEPTANCE PENDING`

The remaining items (1)–(4) above are manual founder actions and the external
pentest decision; no further safe automation remains for these areas.
