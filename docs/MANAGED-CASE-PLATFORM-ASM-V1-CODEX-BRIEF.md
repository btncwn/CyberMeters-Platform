# Codex Build Brief — Managed Case Platform v1 + Managed ASM Remediation Loop

**Decision owner:** Turhan · **Adopted:** 2026-07-13 · **Author of brief:** Claude (Lead Eng / review-integrate)
**Operating model:** Codex builds · Claude reviews + integrates + validates + deploys · Turhan decides
**Risk tier:** MEDIUM (additive migrations + new engine/routes/UI). All work must be additive & reversible.

---

## 0. One-line goal

Build the **first generic Managed Case Platform** and make **Attack Surface** its first real
consumer: an external exposure becomes a governed case that is owned, remediated by the
customer, **independently re-verified by CyberMeters**, closed only when the exposure is
actually gone, and **auto-reopened if it returns** — with a full tenant-scoped audit trail.

After this ships and the DoD scenario (§12) passes live, CyberMeters may honestly market:
> **Managed exposure remediation with independent fix verification.**

---

## 1. Why ASM is the second managed consumer (context, do not re-litigate)

DMARC managed workflow is already shipped (Level 3, `dmarc-change-workflow.js`, deployed
v2026.07.13-7). ASM is chosen as the **second** consumer — and the vehicle to extract the
generic platform — because:

1. It matches CyberMeters' core promise ("what of mine is exposed?" → "who fixes it, and how
   do I know it's fixed?"). Turns a dashboard into an operations tool.
2. **The verification loop is UNBLOCKED**: the scan engine already re-probes exposures
   (`asset_reappeared` / `exposed_service_resolved` / `exposed_service_detected`), so
   "prove it's actually closed" is a real closed loop — unlike Certificates, whose L3 is
   architecturally blocked (Workers cannot do a TLS handshake).
3. Less external dependency than Brand takedown (no registrar/hosting/CA/legal in the loop),
   so lower overclaim risk for a first managed capability.
4. ASM produces the richest variety of case types → it stress-tests the generic platform
   harder than Brand would, so Brand & Certificates adopt a battle-tested engine later.

**Roadmap this epic sits in (locked):**
1. DMARC managed workflow — done.
2. **Managed ASM remediation + verification — THIS EPIC.**
3. Brand evidence bundle + takedown lifecycle (reuses this platform).
4. Certificate L2 intelligence (classification + renewal-readiness + anomaly).
5. External TLS prober (unblocks Cert L3).
6. Managed certificate deployment verification.

---

## 2. Architecture — extract, don't design-from-scratch

The state-machine core in `workers/scan-api/src/engines/dmarc-change-workflow.js` is already
pure and generic-shaped. **Extract a domain-agnostic engine** `engines/case-workflow.js`
whose machine is **parameterized by a state-graph definition**, so each case type supplies its
own states/transitions/guards. The engine is a *runner*, not a fixed state set.

**Critical scoping decision — do NOT retrofit DMARC in v1.** The shipped, tested, deployed
DMARC flow (`dmarc_change_requests` + `dmarc-change-workflow.js` + its routes) must be left
**byte-for-byte untouched**. To still prove the generic engine isn't ASM-overfit, the engine's
validation harness MUST include a unit test that expresses the **DMARC state graph** on the
generic engine (states draft→…→completed + separation-of-duties guard) and drives a few
transitions — proving the abstraction fits two differently-shaped machines — **without touching
any DMARC table, route, or the live engine.** DMARC can migrate onto `managed_cases` in a
later, separate, low-risk epic.

---

## 3. Scope

### IN (Managed Case Platform + ASM Remediation Loop v1)
1. Generic `case-workflow.js` engine (parameterized state machine + reusable guard helpers).
2. `managed_cases` + `managed_case_events` tables (additive migrations).
3. ASM finding → managed case creation (dedup: one open case per `(workspace, domain, finding_id)`).
4. Owner assignment (person/team/vendor/unknown; assigned_by system/analyst/customer).
5. Remediation status workflow (the ASM state machine in §7).
6. Customer "fix completed" action → moves case to `verification_requested`.
7. External re-verification (reuse the existing scan re-probe; see §8d).
8. Verified resolve / `verification_failed`.
9. Auto-reopen if the exposure is seen again after resolution (§8f).
10. Audit log (reuse `createAuditEvent`, add `actor_type`) + notification (reuse
    `createNotificationEvent` / `alerts.js`).

### OUT (explicitly deferred — do NOT build in v1)
- Jira / ServiceNow / any external ticketing integration.
- Comprehensive SLA system (a single optional `due_at` field is allowed; no breach engine,
  no escalation ladder in v1).
- Cross-customer analyst marketplace / MSP white-label queue.
- Bulk remediation, auto-fix, auto-remediation of any kind.
- Retrofitting DMARC onto `managed_cases` (see §2).

Keep v1 tight. A giant "full Managed ASM" task is explicitly rejected.

---

## 4. Data model (additive migrations, enums-in-code, NO CHECK)

Follow the hosted-dns-v2 / migration-075 convention: **all enums live in application code,
NO CHECK constraints**, so a new state/case_type never needs another migration. Migrations
are additive only (the `validate-migrations.js` guard blocks DROP/DELETE/TRUNCATE).

### `managed_cases`
```
id                TEXT PRIMARY KEY            -- 'mc-'+12hex
workspace_id      TEXT NOT NULL
case_type         TEXT NOT NULL              -- 'asm_exposure' (v1); enum in code
domain            TEXT                        -- lowercase; the exposure's domain
finding_id        TEXT                        -- stable finding id, e.g. 'exposed_admin_panel'
asset_ref         TEXT                        -- hostname / asset identity the case concerns
severity          TEXT NOT NULL DEFAULT 'medium'  -- low|medium|high|critical (in code)
status            TEXT NOT NULL DEFAULT 'open'    -- workflow state (in code)
owner_type        TEXT                        -- person|team|vendor|unknown
owner_ref         TEXT                        -- user_id / free label
assigned_by       TEXT                        -- system|analyst|customer
evidence_json     TEXT                        -- snapshot: exposure evidence at open time
recommended_actions_json TEXT                 -- remediation guidance snapshot
reason            TEXT                        -- rejection / risk-acceptance / verify-fail reason
risk_accepted_until TEXT                      -- expiry for risk_accepted (closes the waiver-no-expiry gap)
due_at            TEXT                        -- optional; NO breach engine in v1
last_verified_at  TEXT
resolved_at       TEXT
reopened_count    INTEGER NOT NULL DEFAULT 0
created_by        TEXT
created_at        TEXT NOT NULL DEFAULT (datetime('now'))
updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
```
Indexes: `(workspace_id, status, created_at)` (queue), `(workspace_id, domain, finding_id)`
(dedup / reopen lookup), `(status)` (cross-workspace verification sweep).
**Dedup rule:** at most one NON-terminal case per `(workspace_id, domain, finding_id)`.

### `managed_case_events` (per-case timeline / transition log)
```
id           TEXT PRIMARY KEY               -- 'mce-'+12hex
case_id      TEXT NOT NULL
workspace_id TEXT NOT NULL
actor_type   TEXT NOT NULL                  -- system|customer|analyst
actor_id     TEXT
from_status  TEXT
to_status    TEXT
action       TEXT NOT NULL
detail_json  TEXT                           -- before/after, reason, verification evidence
created_at   TEXT NOT NULL DEFAULT (datetime('now'))
FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
```
Index: `(case_id, created_at)`.

**Both tables MUST be added to `WORKSPACE_PURGE_TABLES` in `index.js` (~line 938)** — the
`purge_covers_all_workspace_fk_tables` regression contract will fail otherwise (this is by
design; it caught migration 075).

---

## 5. Generic engine — `engines/case-workflow.js`

Pure, no DB, no domain imports (mirror the discipline of `dmarc-change-workflow.js`). Export:

- `createCaseMachine({ states, transitions, terminals, guards })` → a machine object, or
  equivalent standalone functions taking a `machineDef`.
- `canTransition(machineDef, from, to)`
- `isTerminal(machineDef, state)`
- `applyCaseTransition(machineDef, caseRecord, to, ctx)` → `{ ok, case }` | `{ ok:false, error }`.
  Never mutates input. Enforces: valid edge, terminal immutability, and any guards the
  machineDef attaches to the target transition.
- Reusable **guard helpers** (composable, so Brand/Cert reuse them):
  `requireActor`, `requireDifferentActor(field)` (separation-of-duties),
  `requireReason`, `requireField(name)`, `requireExpiry`.
- `buildCaseQueue(rows, { now, statusFilter })` → filtered, oldest-first, with `age_hours`.
- `newManagedCaseId()` / `newCaseEventId()` (`mc-`/`mce-` + 12 hex via `crypto.randomUUID`).

The DMARC machine (used only in the harness, §11) and the ASM machine (§7) are both expressed
as `machineDef` values consumed by this engine.

---

## 6. (removed — merged into §5)

---

## 7. ASM case state machine (`case_type = 'asm_exposure'`)

```
open
→ triage
→ owner_assigned
→ remediation_in_progress
→ verification_requested
→ verifying
→ resolved
```
Alternative / branch states:
```
risk_acceptance_requested
risk_accepted            (terminal-ish; carries risk_accepted_until expiry → reassessment)
false_positive           (terminal)
verification_failed      (→ back to remediation_in_progress)
reopened                 (from resolved, when exposure returns → re-enters remediation)
closed                   (terminal)
```
Transition table (author precisely; principles):
- `open → triage → owner_assigned` (owner assignment required to leave owner_assigned forward).
- `owner_assigned → remediation_in_progress` (or `→ risk_acceptance_requested` / `→ false_positive`).
- `remediation_in_progress → verification_requested` (customer "fix completed").
- `verification_requested → verifying` (system picks it up).
- `verifying → resolved` (exposure absent) **or** `verifying → verification_failed` (still present).
- `verification_failed → remediation_in_progress`.
- `risk_acceptance_requested → risk_accepted` (requires `risk_accepted_until` expiry + reason;
  analyst/owner approval, `requireDifferentActor` NOT required here but reason IS).
- `resolved → reopened` (system, on exposure re-detection) → `remediation_in_progress`.
- Terminals: `false_positive`, `closed`. `risk_accepted` re-opens for reassessment at expiry.

Guards: reason required on `false_positive` / `verification_failed` / `risk_acceptance_requested`;
expiry required on `risk_accepted`; owner required to advance past `owner_assigned`.

---

## 8. Integration seams (technically grounded — build against these)

**a. Finding → case creation.** Anchor on the **stable `finding_id`** (e.g.
`exposed_admin_panel`), the same identity `finding_waivers` uses (`(workspace_id, domain,
finding_id)`), NOT on `remediation_items.id` (that table is scan-scoped/ephemeral). On a scan
that surfaces a qualifying exposure with no open case for that key, open a case (`status='open'`,
snapshot evidence + recommended actions). Respect existing `finding_waivers`: a waived finding
must NOT auto-open a case.

**b. Owner assignment.** Route + UI to set `owner_type`/`owner_ref`/`assigned_by`. For v1,
`owner_ref` may be a workspace member `user_id` or a free-text label. Manage-role gated.

**c. Customer "fix completed".** Customer action moves `remediation_in_progress →
verification_requested` (actor_type `customer`).

**d. External re-verification (the heart).** Reuse the EXISTING scan re-probe — do NOT build a
parallel prober. A verification checks: **is this `finding_id` still present for this domain in
the latest scan?** Wire it as either (i) an on-scan hook that resolves `verifying` cases when
their finding is absent in the fresh results, or (ii) an hourly cron sweep (`cron/scheduled.js`)
that triggers a targeted re-check for `verification_requested`/`verifying` cases. Prefer hooking
the existing scan pipeline / change-detection (`asset-inventory.js`, `posture-events.js`) so
verification rides real evidence. Record observed vs expected in `managed_case_events.detail_json`.

**e. Resolve / fail.** Absent → `resolved` (`resolved_at`, `last_verified_at`). Still present →
`verification_failed` with reason, back to `remediation_in_progress`.

**f. Auto-reopen.** When a `resolved` case's `finding_id` is re-detected in a later scan
(the pipeline already emits `asset_reappeared` / `exposed_service_detected`), transition
`resolved → reopened → remediation_in_progress`, increment `reopened_count`, notify. This is the
signature managed behaviour — build it, test it.

**g. Risk acceptance WITH expiry.** `risk_accepted` MUST carry `risk_accepted_until`. This
closes a real gap the audit found: `finding_waivers` today have NO expiry. At/after expiry, the
case returns for reassessment (a cron check flips expired `risk_accepted` back to `triage`).

**h. Audit + notification.** Reuse `createAuditEvent` (`lib/events.js`) — **add an `actor_type`
column** to `audit_events` (additive migration; system/customer/analyst; default derive from
user_id null=system so existing callers keep working). Every transition writes a
`managed_case_events` row AND an audit event. Reuse `createNotificationEvent` + `alerts.js`
`deliverWorkspaceAlert` for owner/customer notifications (new case, verification result, reopen).

---

## 9. Frontend

Add a **Managed Cases** panel to the Attack Surface area (match existing page style; see the
DMARC `ChangeReviewQueue` panel in `WorkspaceEmailProtectionPage.jsx` as a style template):
- Case list (open/in-progress), severity + status pills, exposure summary, age.
- Owner assignment control.
- "Mark fix completed" button (→ verification_requested).
- Verification result surfaced (verifying / resolved / verification_failed with reason).
- Reopen indicator + `reopened_count`.
- Hidden/empty-state when no cases (don't clutter).
- Add `api.js` methods for list / create-is-implicit / transition / assign-owner.

---

## 10. Guardrails (non-negotiable)

- **Additive migrations only** — no DROP/DELETE/TRUNCATE; enums in code, NO CHECK. New tables +
  the `audit_events.actor_type` column are additive.
- **Add `managed_cases` + `managed_case_events` to `WORKSPACE_PURGE_TABLES`** (index.js ~938).
- **Tenant isolation**: every query workspace-scoped + bound params. Add these tables to the
  tenant-isolation test matrix.
- **Do not break** existing ASM change-detection / findings / scoring / `finding_waivers`, and
  **do not touch** the DMARC change-workflow (engine, tables, routes) at all.
- **Reuse** `events.js` (audit) and `alerts.js`/notifications — do NOT invent parallel logging.
- **Customer-safe copy**: no raw Worker/D1/SQL errors; `serverError(...)` sanitisation as
  elsewhere. Never mark a case `resolved` without a real verification observation.
- **No overclaim**: a case is `resolved` ONLY when the exposure is observably absent.

---

## 11. Validation (CI-blocking harnesses — Node 24+, mirror existing `validate-*.js`)

1. `validate-managed-case-workflow.js` — the generic engine: transitions, guards
   (separation-of-duties, reason-required, expiry-required), terminal immutability, no-mutation,
   `buildCaseQueue` ordering, **plus the DMARC-state-graph-on-generic-engine test** (§2) proving
   reusability without touching DMARC tables.
2. `validate-asm-remediation-loop.js` — the ASM machine + a **DB round-trip E2E of the DoD
   scenario** (§12): open → assign → fix-completed → verify(absent)→resolved; verify(present)→
   verification_failed; reopen on re-detection; risk_accepted expiry → reassessment; tenant
   scoping (two workspaces, no leakage).
3. Full gate must stay green: `validate-regression-fixtures.js` (incl. the purge contract),
   `validate-migrations.js`, `validate-pipeline.js`, `validate-cron.js` (if a sweep task is
   added, register it in index.js tasks + `cron/scheduled.js` + both cron/pipeline validators),
   frontend `npm run build`, `wrangler deploy --dry-run`.

---

## 12. Definition of Done (the live scenario — must pass end-to-end)

1. CyberMeters finds a new exposure.
2. A managed case opens for the finding.
3. Customer assigns the asset owner.
4. CyberMeters recommends an evidence-based remediation.
5. Customer marks the fix completed.
6. CyberMeters re-checks the exposure (independent verification via the scan re-probe).
7. Exposure genuinely closed → case `resolved`.
8. Still present → case `verification_failed`.
9. Exposure returns later → case auto-`reopened`.
10. Every transition is written to a tenant-scoped audit log (+ `managed_case_events`).

Until this passes live, we do NOT say "Managed Attack Surface."

---

## 13. Handoff

Codex builds against this brief on a feature branch, PR with the full validation table.
Claude reviews (both gates + guardrails + tenant isolation + no-DMARC-regression), integrates,
and deploys under the standing MEDIUM-risk delegation (additive migrations applied to remote D1
before deploy; rollback Version ID recorded; CHANGELOG + tag). Turhan is informed, not blocked,
unless something turns HIGH risk.
