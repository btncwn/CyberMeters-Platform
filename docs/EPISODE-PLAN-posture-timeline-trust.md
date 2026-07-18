# Episode Plan — Posture Timeline Trust & Actionability

Status: **PLAN — awaiting implementation authorisation. No code, schema, migration, or deploy performed.**
Origin: founder-approved **RESCOPE of M6** (18 July 2026), following the M6.0-B viability gate.
Author role: Product Owner / Lead Engineer (canonical episode).

> This episode is deliberately **NOT** named or marketed as "Behaviour Intelligence." The
> M6.0-B empirical proof showed the sensors do not sustain the cross-domain-correlation
> *category* claim. Future Behaviour Intelligence remains a **sensor-dependent, founder-gated
> programme**, not promised roadmap functionality.

---

## 0. Founder constraints (govern every phase)

| # | Constraint | Where honoured |
|---|---|---|
| C1 | `not_comparable` / `unavailable` / `insufficient_history` are **comparison-STATUS** outcomes, **not** customer security events. Fail closed: no change event, alert, case, remediation, or digest claim. Diagnostic transparency may be provided on a **separate** surface. | Phase A2, A3; §6 status model |
| C2 | UC3 creates **one** canonical managed case per correlated host, owned via the **existing** `assignCaseOwner(...)` path. No legitimate owner → **explicitly unassigned**; never fabricate. | Phase B3; §7 ownership |
| C3 | Controlled detection proof **not** required to merge the standalone guards, but **mandatory** before UC3 is production-enabled. Fixtures: positive, negative, stable-state, unavailable-source, cross-version, recurrence, dedupe. | Phase A gate vs Phase B gate; §16 tests |
| C4 | **No pre-committed migration.** First prove existing canonical tables can safely carry tenant-scoped identity + persistence. Any migration minimal, additive, separately reviewed, justified vs a no-migration design. | Phase B0 spike; §4 schema |
| C5 | **Historical integrity:** guards/dedupe **never mutate or delete** existing `asset_events` rows — they gate go-forward emission and collapse for presentation/alerting only. Raw evidence preserved and **referenced** under any correlated finding. | §11 history/evidence; all phases |
| C6 | UC3 remediation **must link** to an existing Canonical Remediation Registry entry; unmapped → **explicit-unknown**, never invent. | Phase B3; §10 remediation |

---

## 1. Goal

Make the existing Exposure Timeline **trustworthy and actionable**, in two phased slices:

- **Phase A — Timeline Trust (ships first, independently):** give the `asset_events` producer
  path the eligibility + producer-version honesty the trend/snapshot/maturity substrates already
  have, and collapse the appear/disappear flip-flop churn before it reaches the customer.
- **Phase B — UC3 host-level correlation (ships only after A + detection fixtures):** join the
  ≤3 already-historied ASM signals for a single host into one deduplicated finding → one canonical
  managed case → canonical owner (or explicitly unassigned).

Phase A carries value on its own (a quieter, honester timeline). Phase B is gated behind Phase A
and behind the controlled detection corpus (C3).

---

## 2. Exact pre-change map (verified this session)

**Producers & tables**

| Substrate | Producer file | History mode | Eligibility/version guard today |
|---|---|---|---|
| `asset_events` (mig 004) — customer Exposure Timeline + weekly digest + asset-change alert | `posture-events.js`, `asset-inventory.js`, `cert-events.js`, `scan-engine.js` | **Append-only** | **NONE** — only `scan_quality='complete'` baseline + 24 h dedupe; no version stamp |
| `cyber_mot_domain_states` (mig 091) | `cyber-mot-state-history.js` | Append-only | `resolver_version` + `scan_quality='complete'` → emits `not_comparable`/`insufficient_history` |
| `scan_report_snapshots` (mig 093) | `report-snapshot.js` | Immutable + append-supersede | schema+resolver version, registry fingerprint, checksum, fail-closed reader |
| `domain_maturity_ledger` (mig 095) | `domain-maturity.js` | Append-only | `resolver_version` + `ledger_contract_version` |
| `workspace_assets` / `certificate_observations` (mig 004 / cert-events) | ASM engines | Upsert, preserves `first_seen`/`last_seen` | None (free-text `source` only) |

**Timeline event vocabulary** (`lib/exposure-events.js` `EXPOSURE_EVENT_META` + producers):
`new_asset_discovered`, `asset_reappeared`, `asset_no_longer_seen`, `dns_ip_changed`,
`dns_cname_changed`, `dns_redirect_changed`, `wildcard_dns_detected`,
`certificate_new_detected`, `certificate_new_issuer_detected`, `certificate_new_san_detected`,
`certificate_sensitive_host_detected`, `certificate_growth_detected`, `certificate_expiring_soon`,
`takeover_risk_detected`, `exposed_service_detected`, `exposed_service_resolved`,
`brand_domain_detected`, `high_risk_typosquat_detected`, `email_spf_changed`,
`email_dmarc_policy_changed`, `email_dkim_changed`, `admin_surface_detected`.

**Consumers of `asset_events`** (all must stay backward-compatible):
- `routes/attack-surface.js` — `/assets/timeline`, `/posture/timeline` (day×event_type counts).
- `weekly-digest.js` — 7-day rollup email (`computeWeeklyChanges`).
- `asset-alert-delivery.js` — per-scan asset-change alert email + Slack/Teams/webhook, dedup via `asset_alert_records`.
- executive/posture dashboard counters (`attack-surface.js:597`, `first_seen >= now-30d`).

**Canonical systems to reuse (no duplication)**
- `createManagedCase(env, {...})` (managed-case-model.js:520) — dedupes on `source_finding_id`.
- `canTransitionCase(...)` — the only transition validator.
- `assignCaseOwner(env, caseRow, {...})` (managed-case-model.js:277) — the ONE ownership path; refuses empty owner; leaves unassigned cases visibly unassigned. `assigned` state requires `owner_ref` (`:78`).
- Canonical Remediation Registry: `resolveRemediation({findingType, domainKey})` → `unknownResolution` (honest) for unmapped; `remediationRegistryFingerprint()` for versioning.
- Managed alert pipeline (`managed-alerts.js`, `alert-*`), canonical read surfaces.

**Tenant boundary / purge:** every `asset_events` row is `workspace_id`-scoped; correlated
findings + cases follow the universal case model's existing purge order. Soft-deleted workspaces
emit nothing (existing gate).

**Duplicate-functionality search result:** the eligibility/version-guard logic to be ported
**already exists** in `cyber-mot-state-history.js:resolveDomainTrend` (the strongest guard in the
codebase). Phase A **reuses that pattern**; it does not invent a second comparability engine.
Host-level correlation exists **nowhere** (snapshot finding→domain tagging is attribution, not a
join), so Phase B is genuinely new — but built on existing sensors + the universal case model.

**Reuse / extend / not-create**
- **Reuse:** `asset_events`, `workspace_assets`, `certificate_observations`, universal case model, remediation registry, alert pipeline, `resolveDomainTrend` guard pattern.
- **Extend:** the `asset_events` *emission* path (gate go-forward writes) and the timeline/digest/alert *read* path (collapse for presentation).
- **Do NOT create:** any new scanner, probe, CT monitor, content fetch, port scan, baseline store, or second comparability/remediation/case system.

---

## 3. Design decision

Three increments across two phases, all additive and reuse-first.

### Phase A — Timeline Trust (ships first)

**A1. Producer-version + eligibility gate on go-forward `asset_events` emission.**
Before a producer writes a *change* event (new/removed/changed classes), it must pass the same
two gates `resolveDomainTrend` already enforces: the compared baseline and current must share a
comparable producer basis, and the baseline scan must be complete. When they do not, the outcome
is a **comparison STATUS** (`not_comparable` / `unavailable` / `insufficient_history`) — **C1: no
event, no alert, no case, no remediation, no digest claim is emitted.** Fail closed.

Because `asset_events` (mig 004) carries no version column today, the gate reads producer-version
from the **scan-level** provenance the baseline already exposes (the same `scan_quality='complete'`
provenance `posture-events.js` uses, extended to also compare the producing resolver/module basis).
Whether a durable per-row stamp is *needed* — vs deriving it at emission time from scan provenance —
is resolved by the Phase B0 spike (C4); Phase A does not add a column unless the spike proves a
no-migration derivation is unsafe.

**A2. Separate diagnostic transparency surface (C1).**
Comparison statuses are useful to the founder/operator but are **not customer security events**.
They are exposed only on a **separate diagnostic/observability surface** (operator-facing), never
folded into `/assets/timeline`, the weekly digest, or alert emails. No customer-facing "we couldn't
compare" claims.

**A3. Flip-flop dedupe / collapse for presentation (C5).**
The appear/disappear churn (proven live: blackbullbarbers 20 `asset_no_longer_seen` + 19
`asset_reappeared`) is collapsed **at read/alert time only**. The raw `asset_events` rows are
**never mutated or deleted** — the timeline/digest/alert layer folds an oscillating host into a
single stable presentation item that references the underlying rows. Extends the existing
flip-flop suppression already present in `asset-inventory.js` (2 h status-flip guard), applied to
the *presentation* layer rather than persistence.

### Phase B — UC3 host-level correlation (ships after A + fixtures)

**B0. No-migration identity/persistence spike (C4).**
*First deliverable of Phase B, before any table decision.* Prove whether a per-correlated-host
identity + persistence can be carried by **existing** canonical tables (candidate: the universal
managed-case row keyed by a deterministic per-host `source_finding_id`, with correlated raw
`asset_events` referenced by id). Only if that is proven unsafe/insufficient is a **minimal,
additive, separately-reviewed** migration proposed, explicitly justified against the no-migration
design. **No migration is pre-committed by this plan.**

**B1. Deterministic per-host correlation key.**
For a host, join the ≤3 already-historied signals — `new_asset_discovered` (subdomain,
`workspace_assets.first_seen`), `certificate_new_detected`/`_san_detected`
(`certificate_observations`), and `takeover_risk_detected` — into one correlated finding with a
**deterministic identity** (`workspace_id` + normalised hostname + correlation-contract version),
so re-runs dedupe rather than duplicate.

**B2. Deterministic significance (no anomaly language).**
`significance = change type + security direction + persistence + recurrence + corroborating-signal
count`. Historical rarity is at most an enriching factor, never the base. **Banned customer
wording:** anomalous / suspicious / attacker / statistically unusual. **Used:** material /
correlated / requires verification / higher-confidence progression.

**B3. One canonical case + canonical ownership + canonical remediation (C2, C6).**
The correlated finding opens **one** managed case via `createManagedCase(...)` (dedup on the B1
key), transitions via `canTransitionCase(...)`, and is owned only via `assignCaseOwner(...)`.
**No legitimate owner → the case stays visibly unassigned (pre-`assigned`); an owner is never
fabricated.** Remediation is resolved via `resolveRemediation(...)`; an unmapped host-correlation
finding stays **explicit-unknown** (no invented advice).

---

## 4. Schema / migration

**Phase A:** target **zero migrations.** The eligibility gate derives producer basis from existing
scan provenance; the dedupe operates at read/alert time. If A1 provably cannot gate without a
durable stamp, a minimal additive column is raised under its own migration review (not assumed here).

**Phase B:** **decided by the B0 spike (C4)** — no migration pre-committed. Preferred outcome:
reuse the universal managed-case row (deterministic `source_finding_id`) + reference existing
`asset_events`/`certificate_observations` by id. Any migration that proves necessary is minimal,
additive, tenant-scoped, append-only, purge-ordered, and separately reviewed with a written
justification vs the no-migration design.

---

## 5. Identity & correlation model

- **Phase A** adds no new identity; it gates emission and collapses presentation of existing
  `asset_events` (keyed by their existing `id`, `hostname`, `event_type`, `created_at`).
- **Phase B** correlation identity = deterministic `(workspace_id, normalised_hostname,
  correlation_contract_version)`. The correlated finding **references** the contributing raw
  `asset_events` / `certificate_observations` row ids (C5) — it never copies or supersedes them.

---

## 6. Comparison-status model (C1)

Three statuses, all **operator-facing only**, never customer security events:

| Status | Meaning | Customer-facing effect |
|---|---|---|
| `not_comparable` | Baseline vs current differ in producer/resolver basis (cross-version) | **None** — fail closed |
| `unavailable` | A required source was missing/unreadable this scan | **None** — fail closed |
| `insufficient_history` | No comparable prior complete baseline exists yet | **None** — fail closed |

Emitted to a separate diagnostic surface for trust/debugging. A comparison status **never**
becomes a change event, alert, case, remediation, or digest line.

---

## 7. Ownership model (C2)

- Sole path: `assignCaseOwner(env, caseRow, {owner_type, owner_ref, actor_type, actor_id, assigned_user_id})`.
- `owner_type ∈ {person, team, vendor, unknown}` (existing enum).
- No legitimate owner ⇒ case remains **unassigned and visibly so** (stays at `detected`/`triaged`;
  the `assigned` state guard already requires a non-empty `owner_ref`). **No fabricated owner.**
- Assignment appends an `assignment_changed` event (existing append-only evidence).

---

## 8. Verification contract

- Phase A emits no verifiable customer claim (it *removes* false ones); nothing to verify.
- Phase B correlated cases inherit the canonical **per-finding** verification support
  (`verificationSupportForCase` / registry `verification_method`). A host-correlation finding is
  verified only from CyberMeters' own re-observation (disappearance of the correlated surface),
  never from a customer note alone. Customer assertion ≠ verification (canonical rule).

---

## 9. Lifecycle / state model

Phase B follows the canonical managed-case lifecycle unchanged:
`observe → correlate → explain → assess → assign ownership (or explicitly unassigned) → remediate
→ record customer action → verify with structured evidence → monitor → reopen on recurrence`.
All transitions via `canTransitionCase(...)`; base creation via `createManagedCase(...)`.

---

## 10. Remediation & case linkage (C6)

- Correlated case links to an existing registry entry via `resolveRemediation({findingType, domainKey})`.
- Unmapped correlation finding type ⇒ `unknownResolution` (status `unknown`, `verification_method:
  null`, no generic advice) — kept **explicit-unknown**. Never invented.
- Registry version travels via `remediationRegistryFingerprint()`.

---

## 11. History / evidence model (C5)

- **`asset_events` rows are never mutated or deleted.** Guards gate *go-forward* emission;
  dedupe collapses *presentation/alerting* only.
- Raw contributing rows are **preserved and referenced** (by id) under the correlated finding —
  the customer can always drill from a collapsed item to the underlying observations.
- Correlated cases + case events remain append-only per the universal model.

---

## 12. APIs

- Phase A: existing `/assets/timeline`, `/posture/timeline`, digest, alert paths return the
  **collapsed, guarded** view (backward-compatible shape). New **operator-only** diagnostic
  endpoint for comparison statuses (auth-gated, tenant-scoped, non-enumerating).
- Phase B: correlated finding + case exposed through the **existing** managed-case read APIs
  (`routes/managed-cases.js`) — no new customer case system.

---

## 13. Frontend

- Timeline / digest render the collapsed, guarded feed (backend-owned states; frontend invents
  nothing). No new customer verdict logic in the client.
- Phase B correlated case appears in the existing managed-case surfaces. An unassigned case is
  shown **explicitly unassigned**, not defaulted to an owner.

---

## 14. Reports

- No change to canonical snapshot renderers (M5.c/M5.d) in Phase A. Phase B correlated cases, if
  surfaced in reports, reuse the snapshot/verification vocabulary ("verified/confirmed" reserved
  for CyberMeters observation). No new report brain.

---

## 15. Files expected to change (plan-level, not yet edited)

- Phase A: `posture-events.js` / `asset-inventory.js` / `cert-events.js` (emission gate),
  `lib/exposure-events.js` or a new presentation-collapse helper, `weekly-digest.js` +
  `asset-alert-delivery.js` + `routes/attack-surface.js` (read collapse), a new operator
  diagnostic route. **No migration.**
- Phase B: a correlation engine module + wiring into scan-finalize, `routes/managed-cases.js`
  read exposure, remediation-registry mapping entry for the host-correlation finding type (or
  explicit-unknown). **Migration only if B0 proves it necessary.**

---

## 16. Tests (CI-blocking)

**Phase A gate (sufficient to merge Phase A — C3):**
cross-version → status not event; unavailable-source → status not event; stable-state → silent;
flip-flop → single collapsed presentation with raw rows intact (append-only asserted); tenant
isolation; foreign/nonexistent parity; soft-delete emits nothing; deterministic API output;
frontend invents no state.

**Phase B gate (mandatory before UC3 is production-enabled — C3):** controlled detection corpus
with **all seven** fixtures — **positive** (real correlated arming across signals), **negative**
(unrelated coincident events do not correlate), **stable-state** (no fabricated correlation),
**unavailable-source** (missing leg → no false correlation), **cross-version** (fail closed),
**recurrence** (reopen), **dedupe** (one case per host, no duplicates). Plus: deterministic
correlation identity; append-only evidence + raw-row references preserved; `createManagedCase`
dedupe; `assignCaseOwner` never fabricates + unassigned stays unassigned; unmapped → explicit-unknown;
`canTransitionCase` rejects invalid transitions; mutation tests on each guard.

Full CI-equivalent gate runs (shared systems: alerts, cases, remediation, timeline).

---

## 17–21. Release, deployment IDs, production proof, rollback, residual risks

- **Release:** two separate release boundaries — Phase A ships and is proven before Phase B
  begins. Standard model (feature branch → focused tests → full gate → PR → CI green → merge →
  **no migration unless B0 requires** → manual Worker deploy → Pages verify → tag → CHANGELOG →
  production proof). Use `/cybermeters-release` per phase. Immediately before deployment,
  reconfirm and record the currently live Worker version/deployment as rollback evidence, then
  deploy only the exact merged Phase A main SHA.
- **Phase A deploy + live acceptance sequence:** Phase A requires two complete reports stamped with
  the Phase A producer version before customer-facing asset-change comparison is trusted. The
  expected quiet period is therefore approximately **one scan interval after the first v1 baseline**:
  the first v1 complete scan establishes the baseline, and the second v1 complete scan is the first
  comparable scan. It is not necessarily two full scan intervals of silence.
  1. **First v1 baseline:** run/observe one complete scan after deploy; record scan id, producer
     version, and `insufficient_history`; expect zero customer-facing change event/alert/digest
     claims from the comparability gate.
  2. **Second stable comparable scan:** run/observe a second complete scan with no controlled
     asset change; expect `comparable`, zero raw customer-change rows for the controlled target,
     and zero presented events.
  3. **Controlled change:** introduce one founder-controlled externally observable asset change
     only after the stable comparable scan.
  4. **Third detection scan:** run/observe the next complete scan; expect `comparable`, raw event
     rows for the controlled change, and exactly the intended customer-presented event count after
     collapse.
  5. **Controlled reversal / collapse verification:** reverse the controlled change and run the
     verification scan(s); prove short-lived flip-flop churn collapses in customer timeline,
     alerting, and digest presentation while a genuine persistent removal and genuine later
     reappearance remain visible.
- **Phase A live-acceptance evidence table:** every acceptance pass records the exact evidence
  below before any Phase B work is considered:

  | Step | Scan ID | Producer version | Comparison status | Raw event count | Presented event count | Evidence surface |
  | --- | --- | --- | --- | ---: | ---: | --- |
  | First v1 baseline | TBD | `asset-timeline-trust-v1` | `insufficient_history` | TBD | 0 | Operator diagnostic + customer timeline/alert/digest absence |
  | Second stable comparable scan | TBD | `asset-timeline-trust-v1` | `comparable` | 0 expected for controlled target | 0 | Operator diagnostic + customer timeline/alert/digest absence |
  | Third detection scan | TBD | `asset-timeline-trust-v1` | `comparable` | TBD | TBD | Raw `asset_events` count + customer timeline/alert/digest |
  | Controlled reversal / collapse | TBD | `asset-timeline-trust-v1` | `comparable` | TBD | TBD | Raw `asset_events` count + collapsed customer timeline/alert/digest |

- **Deployment IDs / production proof:** not yet applicable (plan only). Production proof will use
  founder-controlled workspaces/domains; UC3 detection proof uses the controlled fixture corpus
  (C3), not live customer data. Live Worker version/deployment must be reconfirmed immediately
  before Phase A deployment.
- **Rollback:** Phase A is presentation/emission-gating only with no destructive migration →
  Worker rollback restores prior emission. Phase B behind a production-enable switch until the
  detection corpus passes.
- **Residual risks:** UC3 provider counterfactual is weak (hosting/CDN partly sees own new host)
  and value skews MSP — honest framing mandatory; the operator diagnostic surface must stay
  operator-only (leaking comparison statuses to customers would violate C1); flip-flop collapse
  must not hide a genuine remove→re-add that matters (mitigated by referencing raw rows + recurrence
  fixture).

---

## 22. Confirmation later phases were not started

M7 Pricing + Billing, debugging/hardening, pentest, acceptance testing, and the release-candidate
gate are **not** started. Future Behaviour Intelligence stays an explicitly deferred, sensor-dependent,
founder-gated programme. This episode is scoped strictly to Timeline Trust (Phase A) then the single
sensor-sufficient UC3 correlation (Phase B), and stops there.

---

## Verdict

**Proceed to implementation only on founder authorisation, Phase A first.** The plan is fully
reuse-first: all six constraints land on existing canonical mechanisms (`resolveDomainTrend` guard
pattern, `assignCaseOwner`, `resolveRemediation` unknown-handling, `createManagedCase` dedupe,
append-only `asset_events`), with **no pre-committed migration** and **no new sensor**.
