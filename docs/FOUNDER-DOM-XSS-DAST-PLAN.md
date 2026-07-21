# Founder-Approved Live DOM-XSS DAST Plan (minimal, bounded)

Purpose: a small, controlled dynamic test of the deployed app for DOM-XSS, to run
ONLY after a founder go-decision. Most of the risk is already retired statically
(see "What is already proven"), so this live pass is a confirmation, not a hunt.

Do not execute this plan in this engineering task. It is a founder-gated action.

## Why the live surface is small

- The frontend is React and uses **no** raw-HTML sink anywhere in `frontend/src`
  (`dangerouslySetInnerHTML`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`,
  `document.write`, `eval`, `new Function`). This is CI-enforced by
  `scripts/validate-dom-xss-sinks.js`, which fails the build if one is added.
- All customer/API/URL data is rendered as React text nodes, which auto-escape.
- The one place attacker-influenced data reaches navigation — alert deep-links
  (`NotificationBell` `meta.link`) — is sanitised by `appPath`, which admits only
  same-origin paths and returns null for `javascript:` / `data:` / cross-origin.
  Proven by `frontend/src/__tests__/domXssSafety.test.jsx`.

## Targets (exact)

Only these customer-controlled or URL-controlled inputs need a live confirmation,
because they are stored and later rendered:

1. Workspace name (rendered across dashboard, reports, emails).
2. Domain / hostname strings (scan results, evidence, related-changes).
3. Managed-case reason / owner_ref / note fields.
4. Related-change evidence entity keys.
5. Query/route parameters that echo into the page (e.g. `?ms_error=`, filters).
6. Notification / alert deep-link (`meta.link`).

## Payload class (bounded, non-destructive)

- Reflected/stored HTML/JS breakout probes ONLY:
  `<script>…</script>`, `"><img src=x onerror=…>`, `javascript:` and `data:` URLs,
  attribute-breakout quotes, and a benign unique beacon (e.g. set a window flag or
  request a controlled collaborator URL) — never a destructive or data-exfiltrating
  payload, never a payload that mutates another tenant's data.
- No SQLi, SSRF, or auth payloads here — those are separate suites already covered.

## Rate & scope

- Manual or a single-threaded, low-rate crawler (≤ 1 req/s), authenticated as a
  FOUNDER-CONTROLLED test account only.
- One workspace, founder-owned, seeded with the probe strings. Never a real
  customer workspace.
- Read-and-render focus: submit a probe into a field, then load every surface that
  renders it and observe whether the beacon fires.

## Exclusions

- No production customer workspaces, domains, or data.
- No email send to real recipients (use the founder address).
- No Stripe/billing surfaces (out of scope; covered separately).
- No auth/session/OAuth endpoints (covered by their own suites).

## Stop / rollback conditions

- Stop immediately if any beacon fires (a real finding → file it, fix in a focused
  PR with a source/sink regression test, do not continue probing that surface).
- Stop if any tenant other than the founder test workspace shows the probe.
- Rollback: the probe strings live only in the founder test workspace; delete that
  workspace to remove them. No schema or config change is made by this plan.

## Evidence to collect

- Per target: the exact probe submitted, the surfaces loaded, and PASS (rendered
  inert / beacon silent) or FAIL (beacon fired) with a screenshot + the response.
- A short summary table mapping each target to PASS/FAIL.

## What is already proven (do not re-test manually)

- No dangerous DOM sink exists (`validate-dom-xss-sinks.js`, CI, mutation-guarded).
- React escaping of stored payloads on a representative rendered surface
  (`domXssSafety.test.jsx`).
- `appPath` rejects `javascript:` / `data:` / protocol-relative / cross-origin
  links and preserves only same-origin paths (`domXssSafety.test.jsx`).
- Server-side render-sink escaping (PDF content stream, alert/digest/invitation
  email HTML, JSON API echo Content-Type) — `validate-injection-coverage.js` (E2).
