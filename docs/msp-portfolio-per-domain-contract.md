# MSP Portfolio — Per-Domain State and Trend Contract

Authoritative for the MSP Portfolio per-domain surface. Shipped `v2026.07.16-5`
(PRs #119, #120, #121; migration `091-cyber-mot-domain-states.sql`).

---

## 1. The question this surface answers

> For every domain I manage, for each customer: what state is each of the eight Cyber MOT
> domains in, what materially changed, is the evidence current, and who needs me first?

The pre-existing portfolio (`portfolio-customers.js`, `portfolio-risk.js`) answers a
different question one level up — *which customer* is worst — and collapses the domain
dimension away with `GROUP BY wd.workspace_id`. Both remain; they are not duplicates.

---

## 2. Architecture decision: persist the resolver's output

`resolveCyberMotDomainStates()` (`engines/cyber-mot-domains.js`) remains the **only** thing
that decides what state a domain is in. Its own header says "No new storage, no migration",
and that is correct **for its consumers**: Dashboard, Scan Detail, Executive Report and PDF
each read one R2 report and resolve eight states from it.

It does not survive contact with a portfolio, for two independent reasons:

| | Why compute-on-read fails for a portfolio |
|---|---|
| **Scale** | R2 has no multi-get. 50 customers = 50 R2 reads + ~100 D1 reads + 50 full report parses, per page load, uncached. The cheap portfolio path next door does 9 D1 queries and 0 R2 reads. |
| **History** | Re-deriving the past through today's resolver *rewrites* it. The same historical report resolves differently after any resolver change, with no stored value to diff against. |

So the resolver's output is **persisted at scan finalize**, from the report already in
memory (zero extra R2 reads), and the portfolio reads D1 only.

**This is a cache with a memory, not a second opinion.** Nothing in portfolio code derives
a state. If a change requires `if (state === ...)` to *decide* a state, it belongs in the
resolver.

### Why not an existing table

| Candidate | Why not |
|---|---|
| `portfolio_risk_snapshots` (036) | Four scalars keyed by `users.id`. No workspace dimension, no domain dimension, no Cyber-MOT-domain dimension. 0 rows ever; writer deliberately deleted (#116). **Stays dead.** |
| `historical_scores` (022) | One *score* per scan, not eight states. Its "domain" is a hostname. |
| 085–090 lifecycle tables | Four of eight domains, four incompatible grains; `cyber_essentials_control_records` has no `domain_id` by an explicit honesty decision. None carries the resolver's vocabulary (`provisional`, `evidence_insufficient`, `not_yet_assessed`, `monitoring_only`), which derives from `scan_quality` + module presence. |
| `asset_events` (004) | Right skeleton, wrong vocabulary: hostname/DNS/cert event types, no `domain_key`, no state column. |

---

## 3. Storage contract — `cyber_mot_domain_states`

Append-only. Grain **(workspace_id, domain_id, scan_id, domain_key)** — 8 rows per assessed
scan.

- **Keyed on the domain RECORD, never the hostname.** `domains` has no `UNIQUE` on `domain`,
  and one `domains.id` can link to several workspaces. Migration 079 settled the rule: *"A
  domain verified in one workspace must NOT authorize scanning in another."* Two MSP clients
  on the same hostname are two customers and never share a row, a trend or a verdict.
- **No FK to `scans`** — the 085–090 precedent (history outlives the record), which also
  keeps the table out of `SCAN_CHILD_TABLES`, where an FK would stall the purge forever.
- **`workspace_id NOT NULL`** — this is what makes `validate-purge-completeness` *see* the
  table (it discovers tenant-scoped tables via `PRAGMA table_info`). Registered in
  `WORKSPACE_PURGE_TABLES`. `portfolio_risk_snapshots` evades that gate by being keyed on
  `owner_id`; this table does not.
- **`assessed_at` is the scan's time, not `now()`** — the occurrence identity is when the
  evidence was observed. There is no `evaluated_at`: the write happens once, at finalize.
- **Idempotent** via `INSERT OR IGNORE` against the UNIQUE. A re-finalize or reconciler
  re-run adds nothing and overwrites nothing.
- **Write is non-fatal.** A scan that completed must never be reported as failed because
  recording a cache did not. A missing row reads as `not_yet_assessed`, which is honest.

### Honest scope (permanent)

A row records **what the resolver said** about one domain from one scan's evidence. It does
**not** prove the customer's posture changed (only that the state did), that a row from a
different `resolver_version` is comparable, that evidence is current, or — critically —
that an **absent row means healthy**. An absent row means **not assessed**.

---

## 4. `resolver_version` — the comparability gate

`CYBER_MOT_RESOLVER_VERSION` is the **first algorithm version stamped on a state a customer
sees**. Before it, the repo's only persisted stamp was `PROVIDER_MAP_VERSION`, on one column.

The gap it closes: `comparable` has always meant `scan_quality === 'complete'`. That answers
*"did enough checks run?"* It is silent on *"was the same ruler used?"* Adding `"dns"` to
`website_security.required`, or tightening a `match()` regex, shifts every historical state
with nothing recording that **the ruler moved rather than the thing measured**. A trend built
on that attributes *our* engineering to *their* security posture.

**Bump it** on any change to: `CYBER_MOT_STATES`, a domain's `modules`/`required` list, a
`match()` regex, the severity gate, or the resolver's precedence ladder.
**Do not bump** for display copy (`description`, `summary` prose, `limitations`) — those do
not change which state is resolved.

---

## 5. Trend contract — stated as refusals

Every entry below is a way a trend lies.

| Situation | Result |
|---|---|
| No previous comparable row | `insufficient_history` — **never** `stable` |
| Either side not `scan_quality='complete'` | `not_comparable` — a partial scan is not an improvement; a failed one is not a recovery |
| `resolver_version` differs | `not_comparable` — we changed, they did not |
| Verdict → unknown/insufficient | `not_comparable` — **never** `recovered`. A rule that stopped running is not a problem that got fixed. |
| Unknown/insufficient → verdict | `not_comparable` — there was nothing to compare against |
| Both sides identical | `stable`, and only then |

Vocabulary: `improving · stable · worsening · new_risk · recovered · insufficient_history ·
not_comparable`.

**Direction comes from the finding-id SET and severity — never from a score.** The trend
never reads `scans.score`. This follows migration 090's rule: *"A readiness percentage moving
is not an event: the score is a recomputation, and 72→68 says nothing about which evidence
changed."* A set difference names *which* finding appeared or cleared, and is stable against
scoring-weight churn.

Only `assessed_healthy` and `issue_detected` carry a verdict and participate in direction.
Every other state is deliberately **outside** the ordering: moving between "we found a
problem" and "we could not look" is a change in **our evidence**, not their posture, and the
trend says so by name rather than by an arrow.

---

## 6. Freshness — a separate axis, never folded into the state

`resolveCyberMotDomainStates` has **no clock**. A `complete` scan from 2019 resolves
`assessed_healthy` with full confidence, because coverage and age are different questions and
it only answers the first. Defensible for a Dashboard opened right after a scan; not for a
portfolio whose whole job is *"who has nobody looked at lately"*.

So freshness is computed at **read** time against `assessed_at` and published **alongside**
the resolver's word:

- `current` ≤ 14 days · `aging` > 14 · `stale` > 45 · `none` = never assessed or unparseable.
- 45 days matches the three existing lifecycle constants (`STALE_EVIDENCE_DAYS`,
  `IDENTITY_STALE_EVIDENCE_DAYS`, `CERT_STALE_EVIDENCE_DAYS` — three copies of 45 in three
  engines). This is a fourth, exported so the eventual unification has something to unify.
- A stale healthy is **never** priority `low` and always carries an `evidence_stale`
  attention reason, so it cannot read as a current all-clear.

---

## 7. Priority — an ordering with its evidence attached

Not a score, and deliberately not 0–100. `critical · high · medium · unknown · low`, each
published with `attention_reasons[]` attributable to a specific `domain_key`.

**There is no path from "everything is unknown" to `low`.** A domain nobody assessed cannot
earn a low priority by being quiet — that is green-by-absence with an ordering attached.

### No blended portfolio score

There is no `portfolio_score`, no `average_score`, no mean of the eight. A customer at 86
with one critical domain and nine healthy ones is **not "Low risk"**, and a mean is exactly
how that gets said out loud. The headline is counts + worst-case + named reasons.

Overall score/rating still comes from the canonical `resolveAssessmentPresentation` — the
portfolio owns **no** band ladder and must never grow one.

---

## 8. Canonical source per domain

All eight resolve through the **same** resolver, from the same R2 report. Persisted per
domain:

| # | Domain | Evidence |
|---|---|---|
| 1 | Email Protection | `modules.email_security` (required) + `email_/dmarc_/spf_/dkim_/mta_/bimi_/tlsrpt_` findings |
| 2 | Brand Protection | `modules.brand_monitoring` (required) + `brand_` findings |
| 3 | Attack Surface | `modules.subdomains`, `dns` (required) + `asset_/subdomain_/admin_/takeover_/exposure_/dse_/cve_/kev_/cloud_/dns_` findings |
| 4 | Certificates & Trust | `modules.certificate_intelligence` (required) + `cert_` findings |
| 5 | Cyber Essentials Readiness | **Workspace-level**, from `getCyberEssentialsSnapshot` (questionnaire + external evidence). Not domain-specific — the same value for every domain in a workspace, because CE readiness is a property of the customer, not the hostname. |
| 6 | Website Security | `modules.headers`, `ssl` (required) + `header_/https_/redirect_/canonical_/ssl_/tech_` findings |
| 7 | Identity Exposure | `modules.identity_discovery` (required) + `identity_` findings |
| 8 | Shadow IT & Unmanaged Technology | Observation counts across 5 modules; `monitoring_only` — never a verdict |

---

## 9. Tenant boundary

- **No MSP entity, and none is required.** An MSP is a user with `workspace_members` rows.
  `getAccessibleWorkspaceIds()` already answers "which customers are mine"; a second table
  answering it would be a second source of truth for a tenant question — a liability, not an
  asset. Introduce one only when **partner billing** forces it, and let billing define its
  shape.
- **Entitlement** reuses `portfolio_monitoring` (business+) via `requirePortfolioEntitlement`.
  No new entitlement, no new plan, no billing change.
- Entitlement is the plan lock; `getAccessibleWorkspaceIds()` is the tenant boundary. Both
  are required and separate — *"the entitlement is a lock on the door, not a reason the room
  is safe."*

---

## 10. Not a second alert engine

Portfolio code calls **no** occurrence emitter and **no** notification sender, asserted by
name against all 14 (`emitManagedAlert`, `ensureAlertActivation`, `emitCaseLifecycleAlert`,
`emitLifecycleAlert`, `processAlertsForWorkspace`, `retryFailedAlertDeliveries`,
`sendAlertEmail`, `sendTenantAlertEmail`, `sendAssetChangeAlert`, `sendWeeklyDigests`,
`sendLifecycleEmail`, `deliverWorkspaceAlert`, `buildAlertChannelPayload`,
`signAlertWebhookBody`), by import, and by row count across a real read.

The hazard is specific: `emitManagedAlert`'s `observed_at` is the alert flood guard. A
portfolio re-deriving state would pass an evaluation timestamp, clear the watermark, and
release the entire backlog **to every customer at once**.

Note the naming collision: `portfolio-risk.js` already builds objects it calls
`portfolio_alerts`. They are presentation-only and touch no emitter.

---

## 11. API

```
GET /api/portfolio/domains                          rows + summary
    ?limit=1..100 &offset &sort &filter &domain_key &state
GET /api/portfolio/domains/:workspaceId/:domainId   detail + per-domain_key history
```

- **Sorts:** `priority · worsening · severity · score · freshness · cases · customer · domain`.
  Every comparator ends in a total tie-break on `(workspace_id, domain_id)` — without it,
  page 2 can repeat or skip a row page 1 already showed.
- **Filters:** `attention · worsening · stale · unknown · incomplete · cases`.
- **Null score sorts last**, never as 0 (a fake crisis) or 100 (a fake all-clear).
- **The summary folds the same array the caller pages through**, so totals cannot disagree
  with rows and a filtered total cannot leak the unfiltered count.
- Four D1 queries for the whole portfolio, independent of domain count. Zero R2. Zero writes.

---

## 12. Guards

`scripts/validate-msp-portfolio-domains.js` — 114 assertions, CI-blocking, mutation-proved
18×. Drives the real `fetch()` handler against the real schema.
`frontend/src/pages/__tests__/PortfolioDomainsPage.honesty.test.jsx` — 14 rendering
assertions, mutation-proved 4×.

**Three mutations survived the first cut, and the guards were fixed rather than the mutants.**
Worth knowing, because each is a way a test can look right and prove nothing:

1. **Removing `workspace_id` from the state query** — the route looks each series up by an
   already-authorised key, so an unscoped query could not leak *through the route*. Real
   defence in depth, and exactly why the scoping is now asserted on the function directly.
2. **Removing the engine's soft-delete filter** — `getAccessibleWorkspaceIds` already excludes
   deleted workspaces, so every route-level assertion passed without it. The belt only gets
   tested with the braces off.
3. **Reversing the priority sort** — comparing one sorter against itself proves determinism,
   not *direction*. The reversed comparator sorted the healthy customer to the top and passed.

---

## 13. Known limitations and open findings

**Outstanding for this surface:**

- **No entitled account exists in production** (0 business/enterprise subscriptions), so
  `/api/portfolio/*` is unreachable by any real user. Authenticated customer acceptance is a
  release-gate action and is **outstanding**. Billing must not be altered to make it
  reachable.
- **`cyber_mot_domain_states` is empty until the next scan finalizes.** The writer fires only
  at scan completion; no scan was triggered to populate it, because that would manufacture
  production lifecycle transitions and risk minting alerts. Until then the portfolio honestly
  reports `not_yet_assessed`.
- **No backfill.** Historical R2 reports could be re-resolved into rows (precedent:
  `scripts/backfill-scan-quality.js`), which would give trend a head start. Not done: it is a
  separate auditable deployment script, and with the feature unreachable there is nothing to
  serve.
- **CE state can lag its questionnaire.** CE is workspace-level and questionnaire-driven, but
  the row is written at scan finalize. A customer who completes the questionnaire shows the
  previous CE state until the next scan. The row is stamped with its `assessed_at` and the
  freshness axis discloses the age, so it is honest — but it is a lag.

**Recorded, deliberately not actioned (M5 / hardening):**

| Finding | Sev |
|---|---|
| `resolveCyberMotDomainStates` has **no staleness gate**: a `complete` scan from 2019 resolves `assessed_healthy` on Dashboard, Scan Detail, Executive Report and PDF. The portfolio adds freshness as its own axis rather than changing the resolver under four surfaces mid-episode. | **P1** |
| Four of eight domains unreachable from `WorkspaceNav`; `website_security` has **no page**; `IdentityExposurePage`, `ShadowItInventoryPage`, `CertificateLifecyclePage` read `useParams().workspaceId` against routes declaring no param → `GET /api/workspaces/undefined/...`. `WorkspaceAuditLogPage` silently renders empty for the same reason. | **P1** |
| **Six** divergent score-band ladders against a module stating every rating surface "MUST delegate here" (`riskLevelForScore` 90/75/50/25 · `pdf.js` same-with-different-labels · `posture-scoring` 90/70/50 · `business-risk` band 90/70/40 · `business-risk` grade 80/60/40/20 · `portfolioRiskBand` 25/50/75 · `portfolioScoreBand` 75/55/35 · `portfolio-customers` 80/60/40). The audit found more than the three previously recorded. | **P2** |
| `csp_weak_policy` (medium) matches **no** domain regex — a material finding counted in zero domains. `ssl_not_available` and `dse_*` are attributed to a different domain than the remediation registry's `domain_key`. Resolver `match()` and registry `domain_key` are two unreconciled attribution mechanisms. | **P2** |
| `workspace_brs_score_history` is written **inside a GET** (`workspace-analytics.js`) — one row per page load. Its "30-day trend" records when someone opened the page. Same defect class as the `portfolio_risk_snapshots` write removed in #116, still live in a sibling. | **P2** |
| `workspace_domains` has **no soft-delete**; unlinking hard-DELETEs the row and destroys migration 079's verification evidence. Per-domain history survives (no FK) but the domain leaves the portfolio. | **P2** |
| Three divergent "open case" terminal sets (DB partial index · factory dedupe · `CANONICAL_TERMINAL_STATES`) disagree on `accepted_risk`, `superseded`, `closed_no_action`. This surface uses the canonical list + `closed`. | **P2** |
| `msp_dashboard` entitlement is declared in `PLAN_FEATURES` and gates nothing anywhere. | **P2** |
