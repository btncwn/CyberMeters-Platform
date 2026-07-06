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
| **Deletion requests actually processed** | ✅ Ready (deployed 2026-07-06, worker `f9d62b50`) |
| Pre-invite smoke runbook (§3) | ✅ Run 2026-07-06 — all scriptable items passed; surfaced + fixed the lifecycle-email retry bug (worker `df650c34`) |
| Operational readiness (§4) | ⚠ Backups/rollback/monitoring done — **1 blocker: no DMARC on cybermeters.com (F-OPS-1)** + human steps |

**Verdict: One operational blocker remains — publish DMARC on cybermeters.com (§4 F-OPS-1).** All P0 code gates pass; §3 runbook executed. After DMARC is published and the human §4 steps (Cloudflare alert, support inbox, cost check) are confirmed, this is GO.

---

## 2. P0 Gates — must pass before the first invite

### 2.1 ✅ Deletion lifecycle (CRITICAL-1 — closed 2026-07-06)

Soft-delete + 30-day purge window, live in worker `f9d62b50`:
- Delete request → immediate soft-delete (`deleted_at`), schedules disabled,
  assets archived, `deletion_requests` row scheduled, confirmation email
  stating the restore deadline.
- `POST /api/workspaces/:id/restore` (owner-only) undoes it any time before
  purging starts; the deletion request is marked `cancelled`.
- After 30 days the hourly cron hard-deletes D1 rows and R2 report objects in
  bounded chunks (max 2 requests + 25 R2 objects per run), audits completion,
  and emails the owner. Account purges are refused while a subscription is
  active/trialing/past_due (`blocked_active_subscription`).
- `audit_events`, `subscriptions` and the request row are retained (audit +
  accounting). Regression contract `deletion_purge_respects_30_day_window`
  locks the window semantics.

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

Verified 2026-07-06.

- [x] **Backups:** D1 export taken before first invite — 54 tables, 2.3 MB, stored at `~/Documents/cybermeters-backups/cybermeters-db-backup-2026-07-06.sql` (kept OUT of the repo; contains customer data). Command: `wrangler d1 export cybermeters-db --remote --output=<path>`.
- [x] **Rollback:** worker rollback = `wrangler rollback` (or `wrangler versions deploy <id>`); `wrangler deployments list` confirmed prior versions are retained. Last known good before the current hardening/lifecycle series: `e9725882`. Pages rollback via the Cloudflare Pages deployment list. D1 migrations 043–060 are all additive — no destructive migration pending.
- [x] **Monitoring procedure documented:** live tail = `cd workers/scan-api && npx wrangler tail --format=pretty`; filter errors with `--status error`. Lifecycle/email failures show as `[lifecycle-email]` / `[lifecycle-retry]`; request errors as `[request-error]` with a `request_id`.
- [x] **Support channel — in-app:** `FeedbackWidget` is live (mounted in `Layout.jsx`).
- [~] **Email deliverability (dogfood) — DKIM ✓ / SPF ✓ / DMARC ✗:** see finding F-OPS-1 below. **This is the one operational blocker before inviting users.**
- [ ] **Monitoring — human step:** review/enable a Cloudflare dashboard alert on Worker error rate (needs dashboard access).
- [ ] **Support channel — human step:** commit to monitoring `support@cybermeters.com` daily during beta.
- [ ] **Cost/limits — human step:** confirm Resend + Cloudflare (Workers/D1/Pages) plan limits comfortably cover ~10 active users.

### F-OPS-1 (Medium — blocker): cybermeters.com has no DMARC record

Ran our own Email Protection checks against our own domain:

| Record | Status |
|---|---|
| DKIM (`resend._domainkey.cybermeters.com`) | ✓ valid key published (Resend) |
| SPF sending (`send.cybermeters.com`) | ✓ `v=spf1 include:amazonses.com ~all` (Resend/SES) |
| SPF apex (`cybermeters.com`) | ✓ `include:_spf.mx.cloudflare.net` (Email Routing inbound) |
| **DMARC (`_dmarc.cybermeters.com`)** | ✗ **no record** |

DKIM aligns, so our lifecycle emails can pass DMARC once a policy exists — but with no DMARC record, receivers have no policy signal (weaker inbox placement, especially at Gmail/Outlook where our test invitees are) and we get zero visibility into who sends as us. For a company whose flagship product *is* DMARC/email protection, shipping a beta without DMARC on our own domain is both a deliverability risk and a credibility gap.

**Fix (DNS, needs Cloudflare zone access — not code):** publish, following our own product's guidance (start at monitor, not enforcement):
`_dmarc.cybermeters.com  TXT  "v=DMARC1; p=none; rua=mailto:<your-cybermeters-RUA-address>"`
Then verify in our own Email Protection page. Move to `p=quarantine` only after reports confirm alignment.

---

## 5. Invite Mechanics

- [ ] Pick 5–10 invitees (mix: 2–3 friendly SMB owners, 2–3 technical, 1–2 security-aware)
- [ ] One-paragraph expectations note in the invite: it's a beta, what works, how to report issues, response-time promise
- [ ] Disclose known limitations (§6) up front
- [ ] Stagger invites: first 2 users → 48h observation → remaining invites

## 6. Known Limitations to Disclose

- Deleted workspaces are recoverable for 30 days, then permanently removed (this is a feature — disclose it as the data-retention promise)
- DMARC "connected" state requires the customer's DNS change to propagate — can take up to 48h
- Report history shows reports from the point ingestion was connected (no backfill)
- Enterprise plan is contact-sales only

## 7. Exit Criteria (widen beyond invite-only)

- All §3 runbook items pass on two consecutive deploys
- ≥5 invitees each completed: signup → domain → scan → understood their findings (interview or session evidence)
- Zero unsanitized-error reports from invitees
- Billing lifecycle exercised by at least one real upgrade + one cancellation without surprise
- Deletion lifecycle exercised once end-to-end (delete → restore, and delete → purge on a throwaway workspace with shortened window in test)

---

*Maintained by the Lead Engineer. Update statuses in place; do not fork this document.*
