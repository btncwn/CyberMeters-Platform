# Alerts — eight-domain canonical coverage (episode close)

**Status as of 15 July 2026.** Engineering closed at `45a327b`, release tag
`v2026.07.15-2`, live Worker `d633118f-64f4-4baf-8d5b-cc486b8cf210`.

This is the authoritative, honest record of what alerts CyberMeters can and cannot
raise. It exists because the episode's title — *Alerts Across All Eight Domains* —
is **not** what shipped, and the gap must be written down rather than implied.

> **Six of eight canonical domains alert through the canonical pipeline.**
> **Two (Website Security, Cyber Essentials Readiness) are deferred**, because
> neither has the lifecycle foundation an honest alert requires. They are **not**
> counted as canonical alert coverage anywhere.

---

## What "canonical" requires

An alert is canonical only when every one of these is true. They are not
aspirational — `findConditionOccurrence` fails **closed** without them, so a domain
missing any one of them raises nothing at all:

| Requirement | Where it lives |
| --- | --- |
| A stable persisted entity identity that survives rescans | the domain's own record table |
| An **append-only** events table with `monitoring_changed` carrying `detail.to_recurrence_type` | `LIFECYCLE_EVENT_SOURCES` (`engines/alert-occurrence.js`) |
| `monitoring_status` / `recurrence_type` transition semantics | `isMonitoringTransition` |
| A severity mapping for the recurrence vocabulary | `RECURRENCE_SEVERITY` (`engines/alert-consumers.js`) |
| An activation watermark, so pre-existing conditions cannot masquerade as new | `alert_activation(workspace_id, domain_key)` |
| Database-enforced dedupe (never an advisory read-then-write) | migration 087 partial UNIQUE index + `INSERT OR IGNORE` |

The occurrence **is** the persisted lifecycle event row: its `created_at` is when the
condition began, and its `id` is the occurrence identity. Nothing is denormalised.

---

## The eight domains

| # | Domain | Canonical alerts | Evidence source | Deployed | Genuine live occurrence proof |
| --- | --- | --- | --- | --- | --- |
| 1 | Email Protection | ✅ | `email_protection_events` | ✅ | ❌ outstanding |
| 2 | Brand Protection | ✅ | `managed_case_events` | ✅ | ❌ outstanding |
| 3 | Attack Surface | ✅ | `managed_case_events` | ✅ | ❌ outstanding |
| 4 | Certificates & Trust | ✅ | `certificate_lifecycle_events` | ✅ | ❌ outstanding |
| 5 | **Cyber Essentials Readiness** | ❌ **deferred** | — none — | n/a | n/a |
| 6 | **Website Security** | ❌ **deferred** | — none — | n/a | n/a |
| 7 | Identity Exposure | ✅ | `identity_exposure_events` | ✅ | ❌ outstanding |
| 8 | Shadow IT & Unmanaged Technology | ✅ | `shadow_it_inventory_events` | ✅ | ❌ outstanding |

### Per-domain detail (the six that alert)

| Domain | Entity identity | Actionable recurrences | Activation | Dedupe / ledger | Recovery & re-entry |
| --- | --- | --- | --- | --- | --- |
| `certificates_trust` | `certificate_lifecycle.id` | `expired`, `renewal_overdue` (+7-day band escalation), `replacement_contradicted`, `verification_failed`, `replacement_unverified`, `coverage_regression`, `unexpected_san`, `exception_expired`, `owner_missing`, `evidence_stale` | per-domain watermark | 087 index + `alert_deliveries` | ✅ new event = new occurrence |
| `identity_exposure` | `identity_exposure_records.id` | `public_admin_surface`, `removal_contradicted`, `verification_failed`, `unexpected_surface`, `retired_reappeared`, `investigate_unresolved`, `exception_expired`, `provider_change`, `owner_missing`, `evidence_stale` | ✅ | ✅ | ✅ |
| `shadow_it_unmanaged_technology` | `shadow_it_inventory.id` | `removal_incomplete`, `rejected_reappeared`, `removal_contradicted`, `retired_reappeared`, `exception_expired`, `approved_disappeared`, `material_change`, `owner_missing`, `evidence_stale` | ✅ | ✅ | ✅ |
| `brand_protection` | `managed_cases.id` | `case_opened`, `case_reappeared`, `case_resolved` | ✅ | ✅ | ✅ |
| `attack_surface` | `managed_cases.id` | `case_opened`, `case_reopened`, `case_verification_failed`, `case_resolved` | ✅ | ✅ | ✅ |
| `email_protection` | `hosted_dns_entries.id` (`hd-`) / `email_sender_sources.id` (`esender_`) | `sender_unrecognised`, `sender_classification_worsened`, `sender_unauthorised_failures_active`, `hosted_record_disconnected`, `hosted_impact_regression`, `hosted_rolled_back_auto` | ✅ | ✅ | ✅ windowed evidence can empty and refill |

All six share one preferences/entitlement path (`engines/alert-gate.js`), one email
chokepoint (`sendTenantAlertEmail`), one channel trunk (`deliverWorkspaceAlert`),
one append-only ledger (`alert_deliveries`) and one retry sweep
(`retryFailedAlertDeliveries`).

---

## The two deferred domains — exactly what is missing

Assessed independently against primary code and schema on 15 July 2026. Both are
**outcome B: the lifecycle foundation is missing.** Neither is outcome C — neither
has an unevidenced outbound path left to retract.

Both already have the *presentation* layer (a resolver entry in
`engines/cyber-mot-domains.js`, display names, canonical remediation entries, a
registered `case_type`) and the *watermark* layer (`alert_activation` is
domain-agnostic and would accept either key unchanged). **What both lack is the
entire middle**: persisted entity identity → monitoring/recurrence semantics →
append-only `monitoring_changed` evidence.

This is why the presence of a registry entry must not be mistaken for readiness.

### 6. Website Security (`website_security`)

Findings come from `headers-scan.js`, `ssl-scan.js`, `dns-scan.js` and
`tech-scan.js`. **None of them writes to D1.** Domain state is recomputed from
scratch on every scan and lives only in the R2 report; the nearest thing to an
identity is a finding *type* slug (`header_weak_hsts`), re-derived each pass.

Missing, in dependency order:

1. A durable per-entity record table with a `record_id` that survives rescans.
2. `monitoring_status` + `recurrence_type` on that record, driven through `isMonitoringTransition`.
3. An append-only `website_security_events` table writing `monitoring_changed` with `to_recurrence_type`.
4. A `LIFECYCLE_EVENT_SOURCES.website_security` entry.
5. A `RECURRENCE_SEVERITY.website_security` block — **the recurrence vocabulary does not exist yet**.

Has: 9 canonical remediation entries (`web.header.*`, `web.https.redirect`,
`web.cookie.flags`, `web.tech.version_disclosure`), each with
`verification_method: "https_recheck"`. A `website_case` case_type is registered but
has **zero production call sites**.

### 5. Cyber Essentials Readiness (`cyber_essentials_readiness`)

Blocked more fundamentally. The readiness verdict (`status`, `top_gaps`) is
**compute-on-read and persisted nowhere** — `getCyberEssentialsSnapshot` recomputes
it on every call, so there is no row to attach an occurrence to. The one durable
table, `cyber_essentials_answers` (migration 068), is **mutable by upsert**
(`ON CONFLICT … DO UPDATE SET answer = excluded.answer, updated_at = datetime('now')`):
a changed answer overwrites its predecessor irrecoverably, and its `updated_at`
drifts forward on every write — precisely the drift-forward failure the occurrence
module exists to prevent. It can therefore never serve as an occurrence source.

Missing: everything Website Security is missing, **plus** any persisted readiness
state at all, **plus** a stable per-gap identity (gaps are ephemeral array members).

**And a product-semantics blocker, not just an engineering one:** the domain's
evidence is largely the customer's own self-attestation. A CE alert would be
alerting on *a customer's answer changing*, which is not an externally observed
condition. Defining what a CE "recurrence" even means (`gap_opened`?
`answer_contradicted_by_measurement`?) is a **product decision that does not exist
yet** — and inventing one was explicitly out of scope for this episode.

> Neither domain may be described as having canonical alert coverage, in the
> product, in commercial material, or in the roadmap, until the foundations above
> are built and shipped in their own scoped episode.

---

## Legacy paths — final state

| Path | Outbound | Reason |
| --- | --- | --- |
| `score_drop` | ❌ suppressed | `evidence_not_attributable` — a score is a recomputation; the row never records *which* evidence moved, and the email asserts a cause the code never checks |
| `new_finding` | ❌ suppressed | `evidence_not_attributable` — the baseline is selected `WHERE domain = ?` with no `workspace_id`, so "new since your last scan" may mean another tenant's scan of the same domain |
| `new_vendor` | ❌ suppressed (B4a) | `evidence_not_attributable` — vendor identity is free-text on a mutable shared table |
| `supply_chain_risk_increase` | ❌ suppressed (B4a) | `evidence_not_attributable` — a score delta, not an observation |
| `asset_change` | ✅ **retained** | append-only `asset_events` evidence + DB-backed `INSERT OR IGNORE` dedupe on `asset_alert_records` |
| weekly digest | ✅ retained | DB-backed per-ISO-week dedupe; a summary, not an occurrence claim. **Not entitlement- or preference-gated — see P2** |
| `isAlertDuplicate` | **deleted** | advisory read-then-write; failed *open* into duplicate sends |
| `sendTakeoverAlert`, `sendSslExpiryAlert` | **deleted** | dead code that fell back to the **operator's** inbox with every gate bypassed |
| `runDmarcAlertsSweep` | **deleted** (B3) | latched forever on cumulative counters; recovery was inexpressible |

Suppressed does **not** mean erased: every suppressed condition still writes its
`notification_events` row, so the bell and dashboard history are unchanged. The
claim stops leaving the platform; the observation is kept.

---

## Honest limitations

- **No genuine live occurrence proof exists for any domain.** Every domain is
  proven by CI (DB-backed, mutation-tested) and by no-op production deployment.
  Nothing here has been demonstrated end-to-end by a real production alert firing to
  a real recipient. **Controlled, founder-led acceptance with genuine events across
  all six wired domains remains outstanding** and is a release-gate activity. Do not
  describe alerting as production-proven until it is done.
- Alerts were deliberately **not** manufactured in production to prove delivery.
- Two of eight canonical domains do not alert at all (above).
- `new_finding`'s suppression removed the platform's only cross-domain "something
  new appeared" outbound alert. That is the honest position on today's evidence, and
  the fix is a workspace-scoped finding-occurrence source — not re-enabling the claim.
