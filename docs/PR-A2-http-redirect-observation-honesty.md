# PR-A2 — HTTP Redirect Observation Honesty

**Status: RECORDED, NOT STARTED.** Founder-gated. Do not begin before PR-A1 is
reviewed and merged.

## Why this exists

Discovered during the PR-A exact-head review, in the same module and of the same
root class as the PR-A1 defect: **probe execution read as evidence completion.**

`ssl-scan.js` probes `http://<domain>` and sets `http_redirect_chain
.http_redirect_validated = true` whenever the fetch returns a non-null `Response`.
A Cloudflare-synthesised 52x/530 **is** a non-null Response, so the redirect chain
is marked *validated* on evidence that never reached the customer's origin.

`scoring.js` then reads `redirectValidated === true` together with
`httpsConfirmed === false` and takes its definitive branch, producing the
customer-visible medium finding:

> **HTTP Does Not Redirect to HTTPS**

with its score impact — concluded entirely from a Cloudflare edge error page.

### Independently reproduced (exact head `ffb4841`, real `runScanEngine`)

With every fetch to the target returning a Cloudflare-signed 522:

```
report findings : dnssec_not_enabled, ssl_no_http_redirect, header_missing_*, …
D1 finding title: "HTTP Does Not Redirect to HTTPS"
```

**Pre-existing, not a PR-A regression.** Before PR-A the edge error produced
`https_available: false`; `httpsConfirmed` was false then too, so the same branch
was reached. PR-A neither introduced nor closed it. PR-A1 deliberately isolates it:
the engine trace answers `http://` with a genuine origin 301 so that PR-A1 tests
HTTPS observation classification and not the redirect path.

## Required scope

- Reuse the shared `lib/fetch-observation.js` classifier for the initial HTTP
  response **and** every second-hop response in the redirect chain.
- A Cloudflare-synthesised response must never set `http_redirect_validated = true`.
- Edge / incomplete evidence must never produce the definitive medium/high
  "HTTP Does Not Redirect to HTTPS" verdict or its score impact.
- Preserve honest observation metadata (state / reason / provenance) on the
  redirect chain, in the same additive style PR-A1 used for the HTTPS probe.
- Add real scoring and customer-projection fixtures plus anchor-guarded mutations
  with pinned counts.

## Explicitly NOT in PR-A2

- PR-B wording and typed field labels.
- Alert eligibility, severity, dedupe, delivery, grouping or preferences.
- Lifecycle or case policy changes.
- `brand-http-enrichment` (separate customer-visible follow-up: it applies Rule A
  correctly but has no Cloudflare-edge handling, so a signed 530 for a brand
  candidate persists `https_available = 1` and inflates `can_host_login`).
- Migration, deployment or production mutation.

## Frozen ordering

```
PR-A1 review + merge
  → PR-A2 review + merge
    → PR-B review + merge
      → separate founder-approved deployment
```

**No deployment after PR-A1 alone.**
