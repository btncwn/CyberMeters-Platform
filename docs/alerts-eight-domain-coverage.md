# Alerts — eight-domain canonical coverage

**Authoritative as of 16 July 2026.** Engineering closed at `510d240`, release
tag `v2026.07.16-1`, live Worker `e0ce455f-034b-41e4-aad6-d546170b9ec7`.

> **All eight canonical domains alert through the canonical pipeline.**
> Engineering is closed at 8/8. **Genuine live occurrence proof remains outstanding
> for every domain** — see *Honest limitations*.

This document **replaces** the six-of-eight record of `v2026.07.15-2`. That tag is
preserved as an intermediate, premature closure; the section at the end explains why
it was wrong, because the reason is more useful than the conclusion.

---

## What "canonical" requires

An alert is canonical only when every one of these is true. They are not
aspirational — `findConditionOccurrence` fails **closed** without them, so a domain
missing any one raises nothing at all, silently.

| Requirement | Where it lives |
| --- | --- |
| Stable persisted entity identity, surviving rescans | the domain's own record table |
| **Append-only** events table with `monitoring_changed` carrying `detail.to_recurrence_type` | `LIFECYCLE_EVENT_SOURCES` (`engines/alert-occurrence.js`) |
| Transition semantics — only a real change appends | `isMonitoringTransition` |
| A severity for every recurrence, namespaced by domain | `RECURRENCE_SEVERITY` (`engines/alert-consumers.js`) |
| An activation watermark, so pre-existing conditions cannot masquerade as new | `alert_activation(workspace_id, domain_key)` |
| Database-enforced dedupe — never an advisory read-then-write | migration 087 partial UNIQUE index + `INSERT OR IGNORE` |
| Customer-facing meaning from the canonical registry | `resolveRemediation` |

The occurrence **is** the persisted lifecycle event row: its `created_at` is when the
condition began, its `id` is the occurrence identity. Nothing is denormalised.

---

## The eight domains

| # | Domain | Canonical | Evidence source | Migration | Live occurrence proof |
| --- | --- | --- | --- | --- | --- |
| 1 | Email Protection | ✅ | `email_protection_events` | 088 | ❌ outstanding |
| 2 | Brand Protection | ✅ | `managed_case_events` | 076 | ❌ outstanding |
| 3 | Attack Surface | ✅ | `managed_case_events` | 076 | ❌ outstanding |
| 4 | Certificates & Trust | ✅ | `certificate_lifecycle_events` | 085 | ❌ outstanding |
| 5 | **Cyber Essentials Readiness** | ✅ **new** | `cyber_essentials_events` | **090** | ❌ outstanding |
| 6 | **Website Security** | ✅ **new** | `website_security_events` | **089** | ❌ outstanding |
| 7 | Identity Exposure | ✅ | `identity_exposure_events` | 086 | ❌ outstanding |
| 8 | Shadow IT & Unmanaged Technology | ✅ | `shadow_it_inventory_events` | 083 | ❌ outstanding |

`scripts/validate-alert-occurrence.js` asserts this exact set. **That assertion is the
8/8 claim** — if a domain is absent from `LIFECYCLE_EVENT_SOURCES` it cannot alert,
whatever this document says.

### Per-domain detail

| Domain | Entity identity | Actionable recurrences | Severity provenance | Recovery / re-entry |
| --- | --- | --- | --- | --- |
| `certificates_trust` | `certificate_lifecycle.id` | `expired`, `renewal_overdue` (+7-day band), `replacement_contradicted`, `verification_failed`, `replacement_unverified`, `coverage_regression`, `unexpected_san`, `exception_expired`, `owner_missing`, `evidence_stale` | fixed + INHERIT band | ✅ |
| `identity_exposure` | `identity_exposure.canonical_identity_key` | `public_admin_surface`, `removal_contradicted`, `verification_failed`, `unexpected_surface`, `retired_reappeared`, `investigate_unresolved`, `exception_expired`, `provider_change`, `owner_missing`, `evidence_stale` | fixed | ✅ |
| `shadow_it_unmanaged_technology` | `canonical_technology_key` | `removal_incomplete`, `rejected_reappeared`, `removal_contradicted`, `retired_reappeared`, `exception_expired`, `approved_disappeared`, `material_change`, `owner_missing`, `evidence_stale` | fixed | ✅ |
| `brand_protection` | `managed_cases.id` | `case_opened`, `case_reappeared`, `case_resolved` | INHERIT | ✅ |
| `attack_surface` | `managed_cases.id` | `case_opened`, `case_reopened`, `case_verification_failed`, `case_resolved` | INHERIT | ✅ |
| `email_protection` | `hosted_dns_entries.id` / `email_sender_sources.id` | `sender_unrecognised`, `sender_classification_worsened`, `sender_unauthorised_failures_active`, `hosted_record_disconnected`, `hosted_impact_regression`, `hosted_rolled_back_auto` | INHERIT band | ✅ windowed evidence |
| **`website_security`** | **(workspace, domain_id, canonical finding id)** | `transport_not_available`, `insecure_redirect`, `browser_protection_missing`, `browser_protection_malformed` | **INHERIT** from `scoring.js` | ✅ + `unknown` ≠ recovery |
| **`cyber_essentials_readiness`** | **(workspace, control_key)** | `externally_observed_control_not_ready`, `externally_observed_control_worsened` | **fixed `medium`** | ✅ + `unknown` ≠ recovery |

All eight share one preferences/entitlement path (`engines/alert-gate.js`), one email
chokepoint (`sendTenantAlertEmail`), one channel trunk (`deliverWorkspaceAlert`), one
append-only ledger (`alert_deliveries`) and one retry sweep. **No domain engine holds
a sender** — asserted in CI for all six lifecycle engines.

---

## Website Security — what was actually missing

Not evidence. `headers-scan`/`ssl-scan`/`tech-scan` collect it every scan, `scoring.js`
turns it into findings with **stable canonical ids**, the module output and those ids
are persisted immutably in the R2 report, and nine canonical remediations key on those
exact slugs.

What was missing was **continuity**: the D1 `findings` INSERT binds
`createId("finding")` and **drops** the canonical slug, so the same condition carries a
different id every scan. No row recorded when a condition began. Migration 089 is that
row. The evaluator reads the slug from the in-memory findings at scan time (Phase 8m),
as `createManagedAsmCasesForScan` already does.

**Identity granularity is an honesty decision.** `(workspace, domain_id, condition_key)`
— *not* per-hostname. No Website Security finding carries `affected_hosts`, a hostname
or a path; the per-path evidence that exists is consumed only as a boolean. A
per-hostname key would have to **invent** the attribution, and its obvious source
(`evidence.final_url`) is the redirect target — so a customer fixing their canonical
redirect would "resolve" one record and "create" another, **alerting twice for an
improvement**. Hostname travels in event detail as observed context.

**Only material (medium+) conditions are actionable.** The info/low grades this domain
also emits (`security_headers_not_observed`, `header_weak_hsts`,
`canonical_url_uncertain`, `tech_*`) have **no mapping at all** — so a new info/low
detection rule cannot mint a record, an occurrence or an alert for anyone.

---

## Cyber Essentials — the ownership decision

CE **detects nothing of its own** (`modules: []`, `match: () => false`). Every control
re-interprets evidence another domain already owns **and already alerts**. So:

- **Technical domains own evidence-level alerts.** DMARC → Email Protection. HSTS/CSP
  → Website Security. Certificate expiry → Certificates & Trust. Exposed admin surface
  → Attack Surface.
- **CE owns control-theme readiness transitions only** — a claim no other domain
  makes, at a **fixed `medium`**, because the technical domain already carries the
  urgent grade. Inheriting it would re-raise the same urgency under a second name.

### Which controls may alert, and which never can

| Control | `external_coverage` | Canonical alerts |
| --- | --- | --- |
| Firewalls & Boundary Protection | `partial` | ✅ |
| Secure Configuration | `partial` | ✅ |
| Security Update Management | `partial` | ✅ |
| **User Access Control** | **`none`** | ❌ **never** |
| **Malware Protection** | **`none`** | ❌ **never** |

The last two are scored from **email-auth proxies** (SPF/DMARC) that measure
anti-spoofing — not user access control or endpoint AV. MFA, admin separation,
joiner/leaver and device patching are not observable from outside. They remain
**visible** in the readiness product and are persisted as `not_externally_assessable`.
This is the repo's own honesty metadata (`lib/cyber-essentials.js`), read at runtime
rather than restated, so it cannot drift.

**The questionnaire is not security truth.** `buildCyberEssentialsReadiness` never
reads `cyber_essentials_answers`; the evaluator calls it **directly** and never
`getCyberEssentialsSnapshot`, where answers gate *display*. Through the snapshot a
customer flipping one answer to `"unknown"` would mint a security occurrence from a
form edit.

**A score moving is not an event.** State comes from the sorted **set of failing
canonical remediation ids**, never the percentage.

CE may state that a control theme's externally evidenced readiness moved, naming the
evidence. It must never state: certified, compliant, audit passed/failed, formal
Cyber Essentials status, that an attack occurred, or that an answer changed.

---

## The prerequisites that had to ship first

Neither lifecycle was buildable on the foundations that existed. Both P1s were live in
production and neither was about alerting:

1. **A probe that never executed reported healthy** (#105). `safeFetch` returns null on
   a 10s timeout, a redirect loop, `>MAX_REDIRECT_HOPS` or any error;
   `runHeadersModule` reported that as an ordinary success, so `scan_quality` graded
   `complete` and **Website Security rendered `assessed_healthy` — "no material issue
   observed" — for a site nobody could reach.** Without the fix, the lifecycle's
   recovery gate would have told customers they fixed a defect because a fetch timed
   out. `ssl-scan` had the mirror defect: a timed-out probe became a **critical**
   "HTTPS Not Available".
2. **CE data integrity** (#106). `cyber_essentials_answers` survived every workspace
   purge for the life of the table, while the deletion email said "permanently
   removed" — and the purge suite only ever seeded tables *already on the list*, so it
   could not catch it. CE also graded a client workspace from its **MSP's** scan
   (`OR wd.workspace_id`, plus the same leak through `buildScorecardData`).

---

## Honest limitations

- **No genuine live occurrence proof exists for any of the eight domains.** Every
  domain is proven by CI (DB-backed, mutation-tested against the real engines) and by
  no-op production deployment. **Nothing here has been demonstrated end-to-end by a
  real production alert firing to a real recipient.** Controlled, founder-led
  acceptance with genuine events remains a release-gate activity. **Do not describe
  alerting as production-proven until it is done.**
- No alerts were manufactured in production to prove delivery.
- Website Security identity is domain-level because the evidence is. Per-hostname or
  per-path identity awaits a scan change that attributes a host to a website finding.
- CE covers 3 of 5 control themes for alerting; the other 2 are not externally
  assessable and say so.
- Website Security's `ssl_not_available` resolves `cert.tls.install`
  (`domain_key: certificates_trust`) — a pre-existing registry/resolver split. The
  alert copy is correct; the attribution is inconsistent. P2.

---

## Why the six-of-eight closure was wrong

`v2026.07.15-2` closed this episode at 6/8, deferring both domains as "outcome B —
lifecycle foundation missing". **The conclusion was wrong and the stated reasons were
wrong.** Preserved here because the failure mode is reusable:

| Claim made then | Reality |
| --- | --- |
| "CE would alert on a customer's self-attestation changing" | **False.** `buildCyberEssentialsReadiness` never reads the questionnaire. Every control was already 100% externally observed. |
| "Website Security engines write nothing to D1, so there is no persistence" | **Misleading.** Findings *are* persisted — immutably in R2, with stable canonical ids. The gap was continuity, not persistence. |
| "Both are outcome B — defer" | **Wrong.** Both were buildable. |

The method error was stopping at the engine file and concluding from the absence of an
`INSERT` there, instead of following the evidence through scan orchestration →
scoring → findings → R2 → historical comparison. The re-audit that corrected it also
found the two P1s above — which the original audit, looking for reasons to defer, had
missed entirely.
