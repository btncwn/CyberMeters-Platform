# Managed ASM — Live DoD Pilot Runbook

**Goal:** prove the 10-step Managed ASM remediation loop end-to-end on a **real
beta domain in production**, so the claim "Managed exposure remediation with
independent fix verification" is backed by production behaviour, not just CI.

**Live version at pilot start:** v2026.07.13-9 (worker `03e84d63…`).
**Beta domains:** `cybermeters.com`, `blackbullbarbers.co.uk`.
**Roles:** Turhan drives the authenticated UI/API steps (owner assign, "fix
completed", triggering scans). Claude collects the evidence via `wrangler d1`
+ `wrangler tail` at each step. Managed-case mutation endpoints require a
workspace session, so they cannot be self-driven headlessly.

---

## Pre-flight (Claude, autonomous)

1. Confirm the beta domain has (or can be given) a **qualifying ASM finding** —
   one whose module is `admin_surface_detection`, `subdomain_takeover`,
   `cloud_storage_discovery`, `asset_exposure`, or `domain_security_enrichment`,
   or a finding id matching `admin_surface_*` / `*takeover*` / `*cloud_storage*`
   / `exposed_*` / `canonical_url*` / `dse_*`.
   - If neither beta domain currently has one, Turhan introduces a **controlled,
     reversible** exposure on a domain he owns (e.g. a temporary sub that trips
     admin-surface or exposed-service detection) so the loop has something real
     to act on. Never introduce anything unsafe or customer-affecting.
2. Baseline: `SELECT COUNT(*) FROM managed_cases;` (expected 0 at pilot start).

---

## The 10 steps

For each step: **who** does it, then the **evidence query** Claude runs.

| # | Step | Actor | Evidence (Claude) |
|---|------|-------|-------------------|
| 1 | A scan runs on the beta domain (scheduled, or Turhan clicks **Run scan**) that surfaces the qualifying finding | Turhan / cron | `wrangler tail` shows the scan; note scan id |
| 2 | A managed case opens for that finding | system | `SELECT id, domain, finding_id, status, created_by FROM managed_cases WHERE domain='<d>' ORDER BY created_at DESC LIMIT 1;` → status `open`, `created_by='system'` |
| 3 | Customer assigns the asset owner (Managed Cases panel → Assign) | Turhan (UI) | case `status` → `owner_assigned`, `owner_ref` set; `SELECT actor_type,action,from_status,to_status FROM managed_case_events WHERE case_id=? ORDER BY created_at` shows `customer` `owner_assigned` |
| 4 | System has recommended remediation (snapshot at open) | system | `SELECT recommended_actions_json FROM managed_cases WHERE id=?` non-empty |
| 5 | Customer marks **fix completed** (transition → `verification_requested`) | Turhan (UI) | case `status` → `verification_requested`; event `actor_type='customer'` |
| 6 | CyberMeters re-checks via a **fresh scan** (independent verification) | Turhan clicks Run scan / cron | `wrangler tail` shows the new scan; note scan id |
| 7 | Exposure genuinely fixed → case **resolved** | system | case `status` → `resolved`, `resolved_at` set, `last_verified_at` set; event `actor_type='system'` `verified_resolved` |
| 8 | (Negative) Customer **cannot** self-resolve | Turhan (API) | `POST …/managed-cases/<id>/transition {status:"resolved"}` on a non-verified case → **rejected** ("verified by CyberMeters"); DB status unchanged |
| 9 | Exposure returns (Turhan re-introduces it) → next scan **auto-reopens** | Turhan + system | case `status` → `remediation_in_progress`, `reopened_count` incremented; event `system` `reopened` |
| 10 | Whole trail is tenant-scoped + audited | system | `SELECT actor_type,event_type FROM audit_events WHERE entity_id=?` shows the `system`/`customer` split; case + events only under the correct `workspace_id` |

### Extra evidence to capture (verification honesty)
- **Completeness guard:** if a scan comes back with the exposure's module
  errored/skipped or `scan_quality.status='partial'`, the case must show a
  `verification_deferred` event and **stay** `verification_requested` — not
  resolve. Watch for this on any degraded scan during the pilot.
- **Notifications:** each of open / resolved / reopened should produce a
  `notification_events` row: `SELECT type,severity,title FROM notification_events
  WHERE metadata_json LIKE '%<case_id>%';`

---

## Pass criteria (all must hold)

1. Case opened under the **correct workspace** for the real finding.
2. `finding_id` stable across open → verify → reopen (same value throughout).
3. Customer **cannot** drive `verifying`/`resolved`/`verification_failed`/`reopened`.
4. Resolve happened **only** after a real fresh scan observed the finding absent
   (and the module completed — no deferral).
5. Audit trail correctly separates `customer` vs `system` actors.
6. Re-introduced exposure **auto-reopened** (reopened_count ≥ 1).
7. Notifications produced for open/resolved/reopened.

When all pass, update `CLAUDE.md` / landing copy to allow **"Managed Attack
Surface"**. Until then use **"Exposure remediation and independent fix
verification"**.

---

## Rollback / safety

- Nothing here is destructive. If a controlled exposure was introduced, remove
  it after the pilot and let one more scan confirm the case resolves/closes.
- Worker rollback if needed: redeploy `85486b4a…` (pre-guard) or `ab6c2b64…`
  (pre-platform). Migrations 075/076 are additive — no data rollback required.
