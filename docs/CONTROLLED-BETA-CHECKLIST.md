# CyberMeters — Controlled Invite-Only Beta Checklist v1

**Date:** 2026-07-06
**Purpose:** The operational go/no-go gate for inviting the first external users. Work top to bottom; the beta opens only when every P0 gate passes and the pre-invite runbook has been executed once end-to-end.
**Scope:** Invite-only beta (5–10 hand-picked users), not public beta. For the UX acceptance pass see `PUBLIC-BETA-UX-CHECKLIST.md`; for historical audit findings see `PUBLIC_BETA_READINESS_REPORT.md` and `PUBLIC_BETA_BACKLOG.md`.

Statuses below are code-verified on 2026-07-06, not assumed.

---

## 1. Go / No-Go Summary

| Gate | Status |
|------|--------|
| Trust: sanitized customer-facing errors | ✅ Ready |
| Onboarding: /services command center + first-run path | ✅ Ready |
| Dashboard: four-service KPI model, honest fallbacks | ✅ Ready |
| BEC Exposure Score calibrated + explainable | ✅ Ready |
| Email Protection: guided remediation + report history | ✅ Ready (deployed 2026-07-06) |
| Lifecycle emails (7 types) live end-to-end | ✅ Ready (deployed 2026-07-06, D1 table verified) |
| Billing: grace period, cancellation, payment-failure lifecycle | ✅ Code live — ⚠ needs Stripe test-mode verification (§3.4) |
| Stale-deploy resilience (chunk recovery + cache policy) | ✅ Ready |
| Dependency vulnerabilities | ✅ Zero open Dependabot alerts |
| **Deletion requests actually processed** | ❌ **OPEN — P0 BLOCKER (§2.1)** |
| Pre-invite smoke runbook executed once | ⬜ Not yet run (§3) |
| Operational readiness (§4) | ⬜ Partial |

**Verdict: NO-GO until §2.1 is fixed and §3 has been executed once.** Everything else is invite-ready.

---

## 2. P0 Gates — must pass before the first invite

### 2.1 ❌ Deletion requests are never processed (CRITICAL-1, still open)

`POST /api/workspaces/:id/delete-request` and the account deletion path insert a
`deletion_requests` row with `status='pending'` and return 202 — but the
`scheduled()` handler has no processor for them (verified 2026-07-06: the cron
drives scans, reports and retention only). A beta user who requests deletion
keeps all data indefinitely. This is a GDPR/data-retention failure and the one
remaining hard blocker.

**Fix:** add a deletion processor to the hourly cron (medium risk — delete/retention workflow; requires explicit approval per CLAUDE.md before production deploy).

### 2.2 ✅ Customer-facing trust
Raw Worker/D1/Stripe errors are sanitized (`sanitizeInfraErrorMessage`, `serverError` wrappers); regression contract `infra_error_sanitized_for_customer` enforces it. "Connected" claims require DNS verification + reports (enforced in copy and in the `lifecycle_email_protection_next_step` email).

### 2.3 ✅ Lifecycle correctness (closed this cycle)
- Scheduled scans run under the workspace owner (CRITICAL-3 fixed; `user_demo` only when a workspace has no owner).
- Onboarding path exists after first login (CRITICAL-2 fixed via /services + OnboardingProgress).
- Lifecycle emails: welcome, workspace created, domain added, first scan completed, DMARC next-step, payment failed, password changed — all deduped, all live (worker `6ab467b4`, `lifecycle_email_events` verified in prod D1).
- Billing: 7-day grace window is now a single shared source (`getPaymentGraceState`) for runtime entitlements AND the billing UI; subscription page surfaces grace / post-grace downgrade / scheduled cancellation with recovery CTAs.

---

## 3. Pre-Invite Verification Runbook (~1 hour, run once, tick each)

Use a fresh email address and Stripe **test mode**.

**3.1 Account lifecycle**
- [ ] Sign up → verification email arrives (check spam) → verify → welcome email arrives
- [ ] Log out / log in; password reset request → email → reset → confirmation email arrives → old session is signed out
- [ ] Microsoft SSO login (if enabled for invitees)

**3.2 Workspace & scan**
- [ ] Create workspace → "workspace ready" email arrives
- [ ] Add domain → "domain ready" email arrives → run scan → completes → "first scan complete" email arrives
- [ ] Dashboard shows honest four-service KPIs (no fake metrics, Email Protection shows "Not measured" until connected)
- [ ] Second workspace: confirm no data bleed between workspaces (tenant isolation spot-check)

**3.3 Email Protection**
- [ ] Guided remediation shows correct step states for a domain with/without DMARC
- [ ] Import a sample RUA report → sender inventory populates → report history lists it
- [ ] Verify page never claims "Connected" without DNS verification + reports

**3.4 Billing (Stripe test mode)**
- [ ] Upgrade with test card `4242…` → success banner → plan active
- [ ] Cancel at period end via portal → blue "scheduled to cancel" banner with date → resume works
- [ ] Simulate `invoice.payment_failed` (test webhook or failing test card `4000 0000 0000 0341`) → amber grace banner with end date → payment-failed email arrives once (not per retry) → in-app notification appears
- [ ] Confirm features stay on the paid plan during grace, drop to Free after

**3.5 Invitation flow**
- [ ] Send a workspace invitation → `/invitations/:token` landing works logged-out and logged-in → invitee joins with correct role

**3.6 Deploy resilience**
- [ ] After next deploy, an open stale tab navigating to a lazy route recovers via one automatic reload (no white screen)
- [ ] `curl -sI https://app.cybermeters.com/ | grep -i cache-control` → `no-cache, no-store, must-revalidate`; any `/assets/*.js` → `immutable`

---

## 4. Operational Readiness

- [ ] **Monitoring:** `npx wrangler tail` procedure documented; Cloudflare dashboard alerts for Worker error rate reviewed
- [ ] **Email deliverability:** SPF/DKIM/DMARC verified for the three Resend sender identities (hello@, alerts@, safe@) — dogfood our own Email Protection on cybermeters.com
- [ ] **Rollback:** worker rollback = `wrangler rollback` to previous version (last known good: `6ab467b4`); Pages rollback via deployment list; D1 has no destructive migrations pending
- [ ] **Support channel:** support@ inbox monitored daily during beta; in-app FeedbackWidget is live (verify submissions arrive)
- [ ] **Backups:** D1 export taken before first invite (`wrangler d1 export`)
- [ ] **Cost/limits:** Resend and Cloudflare plan limits reviewed for 10 active users

---

## 5. Invite Mechanics

- [ ] Pick 5–10 invitees (mix: 2–3 friendly SMB owners, 2–3 technical, 1–2 security-aware)
- [ ] One-paragraph expectations note in the invite: it's a beta, what works, how to report issues, response-time promise
- [ ] Disclose known limitations (§6) up front
- [ ] Stagger invites: first 2 users → 48h observation → remaining invites

## 6. Known Limitations to Disclose

- Data deletion requests are acknowledged but processed manually until §2.1 ships (state this honestly if asked; fix before invites regardless)
- DMARC "connected" state requires the customer's DNS change to propagate — can take up to 48h
- Report history shows reports from the point ingestion was connected (no backfill)
- Enterprise plan is contact-sales only

## 7. Exit Criteria (widen beyond invite-only)

- All §3 runbook items pass on two consecutive deploys
- ≥5 invitees each completed: signup → domain → scan → understood their findings (interview or session evidence)
- Zero unsanitized-error reports from invitees
- Billing lifecycle exercised by at least one real upgrade + one cancellation without surprise
- §2.1 deletion processor live and verified with a real request

---

*Maintained by the Lead Engineer. Update statuses in place; do not fork this document.*
