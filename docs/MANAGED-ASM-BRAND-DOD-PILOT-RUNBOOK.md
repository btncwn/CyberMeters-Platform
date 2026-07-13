# Live DoD Pilot Runbook — Managed ASM + Managed Brand Protection (combined)

**Goal:** prove, on **real production behaviour**, that the Managed ASM and Managed Brand
workflows drive the correct states end-to-end — so the claims *"Managed exposure remediation with
independent fix verification"* and *"Managed brand-abuse detection, takedown coordination and
reappearance monitoring"* are backed by evidence, not just CI.

**Rules (do not break):**
- **No product-code change** during the pilot unless it exposes a real defect (then: stop, report,
  fix via the normal PR/review flow).
- **Do NOT call either service "Managed" in public copy until its pilot passes.** Until then:
  ASM → "Exposure remediation with independent fix verification"; Brand → "Brand abuse detection
  with guided takedown preparation".
- **Safe / reversible / no third-party harm:** use only assets Turhan controls; remove test assets
  after; **never send a real registrar/host abuse report** — Brand submission is recorded as an
  **internal/test record only**.

**Roles:** Turhan performs the authenticated UI/API actions (they require a workspace session Claude
cannot mint headlessly). Claude collects evidence via `wrangler tail` + D1 queries and returns a
pass/fail verdict per checkpoint.

**Live worker at pilot start:** v2026.07.13-15 (`45b9cd68`). Beta workspace + domain: to be named by
Turhan at run time (referred to below as `WS` / `DOMAIN`). Claude fills real ids from the queries.

---

## Pilot 1 — Managed ASM

### Flow to prove
```
real finding → managed case opens → owner assigned → remediation_in_progress
→ customer requests verification → fresh COMPLETE scan → system-only resolved
→ exposure returns → system-only reopened
```

### Safe scenario
A **controlled, reversible exposure** on a domain Turhan owns that trips an ASM managed module —
e.g. a temporary **admin surface** (a path/subdomain matching admin-surface detection) or a
controlled HTTP endpoint that registers as an exposed service. It must be removable to prove the
resolve, and re-addable to prove reopen.

### Steps (who → action → evidence Claude collects)
| # | Who | Action | Evidence (Claude) |
|---|-----|--------|-------------------|
| 1 | Turhan/cron | Run a scan on `DOMAIN` that surfaces the controlled finding | `wrangler tail` shows the scan; note `scan_id` |
| 2 | system | Case opens | `SELECT id, workspace_id, case_type, domain, finding_id, status, created_by FROM managed_cases WHERE case_type='asm_exposure' AND domain='DOMAIN' ORDER BY created_at DESC LIMIT 1;` → status `open`, correct `workspace_id`, `created_by='system'` |
| 3 | Turhan (UI) | Assign owner (Managed Cases panel → Assign) | status → `owner_assigned`, `owner_ref` set; `SELECT actor_type,from_status,to_status,action FROM managed_case_events WHERE case_id=? ORDER BY created_at` shows `customer owner_assigned` |
| 4 | Turhan (UI) | Move to remediation_in_progress | status `remediation_in_progress`; event actor `customer` |
| 5 | Turhan (UI) | "Mark fix completed" (transition → `verification_requested`) | status `verification_requested`; event actor `customer` |
| 6 | Turhan removes the exposure, then runs a fresh **complete** scan | system re-checks | tail shows the new scan; note `scan_id` |
| 7 | system | Case **resolved** (finding absent + module completed) | status `resolved`, `resolved_at` + `last_verified_at` set; event `system verified_resolved` |
| 8 | Turhan re-adds the exposure, runs another scan | system re-detects | case status `reopened → remediation_in_progress`, `reopened_count`≥1; event `system reopened` |

### Negative tests (mandatory)
- **Customer cannot self-resolve:** Turhan `POST /api/workspaces/WS/managed-cases/<id>/transition
  {"status":"resolved"}` on a non-verified case → **rejected** ("verified by CyberMeters"); DB status
  unchanged. (Also try `verifying`/`verification_failed`/`reopened` → all rejected.)
- **Incomplete scan does NOT resolve:** if any scan during the pilot returns with the finding's
  module errored/skipped or `scan_quality.status='partial'`, the case must show a
  `verification_deferred` event and stay `verification_requested` — never resolve.
- **Tenant isolation:** a foreign-workspace token GET `/managed-cases` and POST `/…/assign` on this
  case → **403** (already CI-proven; spot-check live).
- **Notifications:** `SELECT type FROM notification_events WHERE metadata_json LIKE '%<case_id>%';`
  → `managed_case_opened`, `managed_case_resolved`, `managed_case_reopened`.

### Pass criteria (all)
Case opened under the correct `workspace_id`; `finding_id` stable across open→verify→reopen;
customer could NOT drive verifying/resolved; resolve happened only after a **complete** scan observed
the finding absent; auto-reopen fired on re-detection; audit `actor_type` correctly splits
`customer` vs `system`; notifications produced.

---

## Pilot 2 — Managed Brand Protection

### Flow to prove
```
registered high-risk candidate → brand_abuse case → human confirms abuse → approval
→ immutable evidence bundle v1 → takedown submission record → follow-up
→ technical verification → system-only resolved
→ candidate returns → fresh evidence bundle v2 → reappeared/reopened
```

### Safe scenario
A **controlled test candidate** Turhan owns, e.g. `brand-test.<an-owned-domain>` — registered/live
so it passes the registration-reality gate, documented as a *test* similarity to the protected
brand, **removable** after, and its submission kept **internal/test only** (no real abuse desk
contacted). Ensure the workspace's brand profile is scoped to the protected domain.

### Steps (who → action → evidence)
| # | Who | Action | Evidence (Claude) |
|---|-----|--------|-------------------|
| 1 | Turhan (UI) | Open Brand Protection for `WS` (loads `/brand/summary`, which runs `createBrandCasesForWorkspace`) with the controlled candidate registered/live | `SELECT id, case_type, domain, finding_id, status FROM managed_cases WHERE case_type='brand_abuse' AND workspace_id='WS' ORDER BY created_at DESC;` → a case at `detected` for the test candidate |
| 2 | system | Registration-reality holds | confirm **no** case for any `not_registered_watchlist` candidate: cross-check the candidate list vs opened cases |
| 3 | Turhan (UI) | Confirm abuse (`POST /brand/cases/:id/review`) | status → `confirmed_abuse`; event actor `customer`, reason recorded |
| 4 | Turhan (UI) | Approve takedown (`POST /brand/cases/:id/approve`) → generates **evidence bundle v1** | status `evidence_ready`; `SELECT version, content_hash, captured_at FROM brand_evidence_bundles WHERE case_id=? ORDER BY version;` → exactly **v1**, `content_hash` `sha256:…`; `managed_cases.evidence_json` holds only `{latest_evidence_bundle_id, latest_evidence_version:1}` |
| 5 | Turhan (UI) | Record submission (`POST /brand/cases/:id/submission {submission_reference:"TEST-INTERNAL-001"}`) — **internal test record only** | status `takedown_submitted`; the submission detail binds `evidence_bundle_id`+`version`+`hash` of v1; status is NOT resolved |
| 6 | Turhan removes the test candidate (DNS down), then the hourly `brand_takedown_followup` sweep runs (or wait for the cron tick) | system verifies | event trail shows `provider_followup → verification_pending`; then, candidate gone, **`resolved`** (event `system technically_verified_removed`) |
| 7 | Turhan re-registers/re-points the test candidate; reload Brand summary | system re-detects | **fresh evidence bundle v2** (`SELECT version FROM brand_evidence_bundles WHERE case_id=?` → 1 AND 2, v1 unchanged); a `brand_abuse_campaigns` row linked; case `reappeared → confirmed_abuse`, `reopened_count`≥1 |

### Negative tests (mandatory)
- **`not_registered_watchlist` opens no case** (step 2).
- **Only high/critical + registered** candidates open a case.
- **Customer cannot self-resolve:** `POST /brand/cases/:id/advance {"to":"resolved"}` (or `reappeared`/
  `provider_no_response`) → **rejected** ("set only after CyberMeters technical verification").
- **Evidence bundle append-only + versioned + hashed:** after v2, v1's row (`content_hash`,
  `bundle_json`) is byte-identical to before (no overwrite); versions are distinct.
- **Submission bound to an exact bundle version/hash** (step 5) and **did not resolve** the case.
- **Incomplete probe defers:** if the follow-up probe fails/timeouts, event `verification_deferred`,
  case stays `verification_pending` — never false-resolved.
- **Reappearance produced a fresh bundle + notification** (not a duplicate case).
- **Tenant isolation:** foreign token GET `/brand/cases` → **403**; cannot read this case's bundles.

### Pass criteria (all)
Case opened only for the registered high-risk candidate (watchlist opened none); customer could NOT
self-resolve; evidence bundles append-only/versioned/hashed with v1 preserved after v2; submission
bound to an exact bundle id+version+hash and did not resolve; resolve happened only on system
technical verification of removal; incomplete probe deferred; reappearance linked a campaign + made a
fresh bundle + notification; tenant isolation held; audit `actor_type` correct (`customer`/`system`).

---

## Evidence appendix — exact collection commands (Claude)

Live tail during each triggered scan / sweep:
```
cd workers/scan-api && npx wrangler tail --format pretty
```
Per-case timeline + audit + notifications (fill `<case_id>` / `WS`):
```
npx wrangler d1 execute cybermeters-db --remote --command \
 "SELECT actor_type,from_status,to_status,action,created_at FROM managed_case_events WHERE case_id='<case_id>' ORDER BY created_at;"
npx wrangler d1 execute cybermeters-db --remote --command \
 "SELECT event_type,actor_type,entity_id FROM audit_events WHERE entity_type='managed_case' AND entity_id='<case_id>' ORDER BY created_at;"
npx wrangler d1 execute cybermeters-db --remote --command \
 "SELECT type,severity,title FROM notification_events WHERE metadata_json LIKE '%<case_id>%';"
```
Brand evidence integrity:
```
npx wrangler d1 execute cybermeters-db --remote --command \
 "SELECT version,content_hash,captured_at FROM brand_evidence_bundles WHERE case_id='<case_id>' ORDER BY version;"
```

---

## Sign-off & positioning gate
- **ASM pilot PASS** → ASM may be described as **"Managed exposure remediation with independent fix
  verification"**; update CLAUDE.md / landing copy.
- **Brand pilot PASS** → Brand may be described as **"Managed brand-abuse detection, takedown
  coordination and reappearance monitoring"**.
- Until each passes, keep the guided-not-managed phrasing above.

### Cleanup (mandatory)
Remove all test exposures/candidates; run one more scan/summary to confirm the cases resolve/close
cleanly; delete the internal test submission record if it should not persist. Nothing here is
destructive; no external abuse report was ever sent.

## After the pilots
When both pass, the honest 4-service table is: DMARC = Managed · Attack Surface = Managed,
production-proven · Brand Protection = Managed, production-proven · Certificates & Trust = L2 Guided
Intelligence (L3 not yet). The next epic — **Cert L3 External TLS Ground-Truth Prober** (live leaf +
full chain + hostname validation + TLS version/cipher + edge consistency + old-cert-still-served +
post-renewal verification) — is new infrastructure and should start **only after** these pilots pass.
