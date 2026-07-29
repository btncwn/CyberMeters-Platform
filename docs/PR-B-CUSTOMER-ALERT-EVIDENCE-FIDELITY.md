# PR-B — Customer Alert Evidence-Fidelity

Audit and implementation date: 29 July 2026

Canonical base: `e3ffecb1425ceadb45a303102b85c3295ac4f07c`

Status: engineering complete on a dedicated branch; not merged, not deployed.

## Goal and evidence law

This corrective changes customer presentation only. It does not change provider
I/O, fetch classification, retries, timeouts, scoring, finding eligibility,
severity, lifecycle progression, case state, alert deduplication, recipients,
delivery scheduling or grouping.

PR-A1 and PR-A2 remain the authorities for HTTPS and redirect observation
classification. PR-B consumes their canonical fields and the existing
`isPublishableModuleEvidence()` contract. It never receives a raw `Response`,
Cloudflare status code, timeout or provider error.

An unavailable, incomplete or not-assessed observation means only:

> CyberMeters could not complete an HTTPS/TLS observation during this
> assessment.

It is not proof that HTTPS is absent, a certificate is missing, or traffic is
unencrypted.

## Exact pre-change map

The material new-scan paths were already evidence-gated:

- `scoring.js` creates `ssl_not_available` only when
  `modules.ssl.https_available === false`.
- `scoring.js` creates a material `ssl_no_http_redirect` only when the canonical
  redirect observation is a completed origin response. Unavailable observations
  are informational and score-neutral.
- `website-security-lifecycle.js` records unavailable/incomplete evidence as
  `unknown`, never recovery, and does not verify a managed case from it.
- `ce-readiness.js` records a null HTTPS result as unknown and does not create an
  HTTPS control gap.

The remaining defect was at the managed-alert presentation boundary.
`emitLifecycleAlert()` selected its subject and action from the static
remediation registry without accepting the canonical SSL module result.
`emitManagedAlert()` then propagated that selection to the notification feed,
email and outbound channel payload. A stale or incorrectly invoked
`ssl_not_available` occurrence could therefore acquire “Enable HTTPS with a
valid certificate” and “Install a publicly trusted TLS certificate” even when
the observation was unavailable.

Cyber Essentials used the same renderer but supplied only a raw control key, so
the compatibility fallback rendered `Affected Domain: boundary_protection`.

## Customer-consumer inventory

| Customer consumer | Source and pre-change behaviour | Incomplete evidence reachability | Corrective action and proof |
| --- | --- | --- | --- |
| Alert email subject | `notification_events.title`, selected in `emitLifecycleAlert()` from the remediation registry | Yes on an alert occurrence lacking explicit presentation evidence | The shared resolver selects the subject from the canonical module state. Real Resend-payload fixtures cover edge, unavailable, not-assessed, positive defect and redirect states. |
| Alert email “What Changed” | Recurrence copy in `alert-consumers.js` | Yes; the old generic recurrence text did not constrain the certificate claim in the subject/action | One resolver returns subject, explanation and action together. Parity assertions compare the email body with the persisted notification. |
| Alert email recommended action | Registry action copied to `metadata.recommended_action` | Yes; this was the production “install a certificate” overclaim | Unpublishable SSL evidence gets the bounded review/reassess action and no certificate remediation id. Positive completed evidence retains the registry action. |
| Alert email affected-object label | `buildAlertEmailFields()` → `formatAlertEmail()` | CE control keys fell through to legacy domain labelling | The bounded typed-entity vocabulary adds `control_area`; both CE emit sites pass the human label. `boundary_protection` and `secure_configuration` fixtures render `Affected Control Area`. Domain alerts continue to render `Affected Domain`. |
| Notification/feed card | `GET /api/workspaces/:id/notifications` returns persisted `title`, `message` and parsed metadata; `NotificationsPage.jsx` renders them without deriving security meaning | Yes, because it repeated the same stale backend selection | No frontend classifier was added. The persisted row now receives the same resolver decision as email. Each fixture asserts notification/email title, body and action parity. |
| Slack, Teams and webhook channel payloads | `emitManagedAlert()` passes the same `title` and `message` to `deliverWorkspaceAlert()` | Yes when enabled | No channel-specific copy fork. The channel fan-out consumes the already-projected title/message. Delivery policy is unchanged. |
| Website Security lifecycle list/detail | `websiteSecurityConditionToApi()` exposes title, monitoring state, unknown reason, scan quality and detecting module | Yes, but it already represents incomplete evidence as `unknown`; it does not generate remediation copy | No change. Existing lifecycle validators prove unavailable evidence is not recovery and cannot verify a case. |
| Website Security managed cases | Created only from material findings; remediation identity comes from the canonical registry | No on the canonical PR-A1/A2 new-scan path; incomplete evidence is not a material finding | No case/lifecycle policy change. Positive certificate and redirect controls prove the existing specific remediation remains available. |
| Cyber Essentials lifecycle and readiness emails | CE lifecycle occurrence plus canonical `ce.readiness.control_review` remediation | Yes for the affected-object label, not for the underlying readiness evidence (unknown controls are non-alertable) | Shared typed-entity adapter only. Existing CE readiness and lifecycle semantics are unchanged and revalidated. |
| Cyber Essentials page/API | `buildCyberEssentialsReadiness()` and the workspace readiness route | Canonical null/unavailable evidence reaches `unknown`, not a gap | No copy fork and no change. Existing CE validators remain the proof. |
| Scan detail and dashboard findings/actions | Current R2 report findings and canonical remediation projections | PR-A1/A2 prevent uncertain SSL evidence becoming a material finding | No change. Specific certificate/redirect copy remains correct for completed positive evidence. |
| Immutable report snapshot | Frozen observed findings, observations and remediation actions | Historical snapshots may contain old copy, but are tamper-evident audit objects | Intentionally unchanged. PR-B does not rewrite snapshots, reports or checksums. |
| Executive report and PDF | Integrity-verified immutable snapshot projection through `executive-report.js` and `pdf.js` | Same as the immutable snapshot | No change. Their inputs are frozen audit evidence; new snapshots inherit PR-A1/A2 finding gates. |
| Scorecard/current posture/business risk | Latest scan report/D1 counts plus canonical remediations | New incomplete evidence is handled by existing partial/publishability contracts | No change. PR-B does not alter scoring, risk, BRS or Phase-5 behaviour. |
| Historical scan diff and legacy `new_finding` notification | Stored report finding IDs/titles; legacy outbound delivery for `new_finding` is already suppressed | Historical false rows can remain visible as immutable history; no new uncertain material finding is produced | Intentionally unchanged. Historical notification/finding rows are not rewritten. The managed lifecycle path is the authoritative new alert path. |
| Canonical remediation registry | Static specific actions for `ssl_not_available` and `ssl_no_http_redirect` | Safe only when the finding is backed by completed positive evidence | Registry meaning is preserved. The presentation resolver withholds that specific action only when the supplied canonical evidence is non-publishable. |

No other customer-facing consumer was found that applies the certificate-install
action, the unencrypted-traffic claim or the CE domain label to an uncertainty
state. `scoring.js` and the remediation registry intentionally retain their
specific copy for completed, positive `ssl_not_available` and
`ssl_no_http_redirect` evidence; the positive-control fixtures protect that
distinction.

## Design decision

`customer-alert-presentation.js` is the single backend presentation decision:

1. It receives the domain, recurrence, finding type, canonical SSL module result
   and the existing registry/recurrence copy.
2. It delegates execution/completeness truth to
   `isPublishableModuleEvidence()`.
3. A certificate action requires a publishable result with the canonical
   `https_available === false` positive fact.
4. A redirect action requires a publishable result with
   `http_redirects_to_https === false`, explicit validation, and canonical
   `origin_response` observation state (or the existing explicit legacy
   validation field when no observation state exists).
5. Missing, unavailable, deferred or incomplete evidence selects one bounded
   uncertainty presentation and clears the certificate/redirect remediation id.
6. Completed healthy evidence is a contradiction guard that refuses publication;
   the normal finding and lifecycle gates already prevent that combination.

`emitLifecycleAlert()` consumes the decision as one object. Subject, body,
recommended action and remediation identity cannot select different evidence
states.

The CE correction reuses the existing typed entity contract:

```text
entity_type: control_area
entity_display: Boundary Protection | Secure Configuration
```

It does not create a CE-specific email engine or template.

## Before/after wording matrix

| Canonical evidence | Before | After |
| --- | --- | --- |
| Cloudflare edge/origin unreachable | Could inherit “Enable HTTPS with a valid certificate” / install-certificate action | “HTTPS could not be verified”; the body says the observation could not complete; action is review evidence, reassess, then check with the hosting provider if persistent |
| Generic transport unavailable | Could imply HTTPS/certificate absence and unencrypted traffic | Same bounded uncertainty presentation; no absence or unencrypted-traffic claim |
| Deadline-deferred/not assessed | Could inherit specific certificate remediation if an occurrence reached the consumer | Same bounded uncertainty presentation and explicit `not_assessed` metadata |
| Completed positive certificate defect | Specific certificate copy | Preserved: specific certificate subject, positive completed-evidence explanation and install action |
| Completed positive no-redirect defect | Specific redirect copy | Preserved: redirect subject, completed origin-observation explanation and 301 redirect action |
| Completed healthy evidence | No alert | No alert; it is never converted into an uncertainty warning |
| CE `boundary_protection` | `Affected Domain: boundary_protection` | `Affected Control Area: Boundary Protection` |
| CE `secure_configuration` | `Affected Domain: secure_configuration` | `Affected Control Area: Secure Configuration` |

## Exact renderer proof

`scripts/validate-customer-alert-evidence-fidelity.js` uses the real schema and
drives:

```text
emitLifecycleAlert
  → resolveCustomerAlertPresentation
  → emitManagedAlert
  → notification_events
  → buildAlertEmailFields
  → formatAlertEmail
  → sendTenantAlertEmail
  → captured Resend subject/text/html
```

It covers:

1. Cloudflare edge/origin unreachable;
2. generic transport unavailable;
3. not assessed/deadline incomplete;
4. positively proven certificate defect;
5. positively proven no-redirect defect;
6. completed healthy evidence;
7. CE Boundary Protection;
8. CE Secure Configuration; and
9. mixed uncertainty with independent Certificate Transparency sibling evidence.

The suite pins 125 assertions and seven mutants. Every mutant runs in a fresh
Node process against a copied real engine tree. The anchors must each match
exactly once, and the validator fails if fewer than seven mutants are killed.

The mutants restore:

- certificate-install advice for unavailable evidence;
- unencrypted-traffic copy;
- `Affected Domain` for CE controls;
- a finding-derived subject instead of the evidence-state subject;
- generic uncertainty for a genuine certificate defect;
- generic uncertainty for a genuine redirect defect; and
- body/action selection from different evidence states.

## Compatibility, closure and limitations

- No schema or migration.
- No historical report, snapshot, finding, notification, condition, case or
  lifecycle row is rewritten.
- No provider, retry, timeout, ordering, cache, score, severity, eligibility,
  lifecycle, case, dedupe, recipient, frequency or scheduling change.
- Trustworthy sibling evidence remains present in the email’s bounded “How this
  was observed” section.
- The frontend remains presentation-only and receives backend-resolved copy.
- `alert-consumers.js` is in the standalone email Worker’s shared import closure,
  so the committed closure manifest and closure-derived `APP_VERSION` must be
  refreshed. Its status remains `pending_founder_approval`.
- Neither Worker is deployed by this PR. Live deployment baselines must be read
  from Cloudflare during the separately authorised combined cutover.

Residual risk: historical customer-visible rows retain the exact language stored
at creation time. This is deliberate historical integrity, not a claim that the
old wording is now valid. This PR prevents the shared current alert renderer from
creating the same overclaim again.
