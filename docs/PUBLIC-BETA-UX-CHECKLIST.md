# CyberMeters — Public Beta UX Acceptance Checklist

**Purpose.** This is the UX acceptance checklist to run **before inviting external users** to the public beta. It focuses on whether a first-time user — a small business owner with no security background and no onboarding call — can sign up, run their first scan, and understand the result.

**How to use.** Work top to bottom. Each item is pass/fail. A journey is "beta ready" only when every ⭐ (critical) item passes. Non-critical items can ship with a known limitation logged in the table at the bottom.

**Scope.** Frontend UX only. Backend is feature-frozen for beta. No redesigns — polish and friction removal only.

**Last reviewed:** Sprint 006-B · _(update date + reviewer each pass)_

---

## 1. Critical User Journeys

The product is acceptable for beta only if a new user can complete this end-to-end without help.

### 1.1 Landing → Signup ⭐
- [ ] Public landing / free-scan page loads and explains what CyberMeters does in plain language.
- [ ] "Create account" path is obvious from a logged-out state.
- [ ] Signup form: name, email, password, confirm password all labelled and keyboard-navigable.
- [ ] Password rule (min 12 chars) is visible before submission, not only after an error.
- [ ] Mismatched / short password shows a clear, friendly inline error.
- [ ] On success, user sees a "Check your email" confirmation naming the address used.
- [ ] "Resend verification email" is available and gives feedback when used.

### 1.2 Verify Email → Login ⭐
- [ ] Verification success screen confirms the account is active and auto-routes to login.
- [ ] Expired/invalid link shows a calm message **and** a resend option (no raw error code).
- [ ] Login with an unverified account surfaces the "Email not verified" state with resend, not a generic failure.
- [ ] Wrong password shows "Invalid email or password" (no stack trace or technical detail).
- [ ] MFA challenge (if enabled) and recovery-code fallback both work and are labelled.
- [ ] New user with no workspace is routed to the guided **Get Started** flow after login.

### 1.3 Workspace → Add Domain → Verify ⭐
- [ ] Empty dashboard for a brand-new user shows "Create your first workspace" with a primary CTA.
- [ ] Guided onboarding shows 5-step progress (Workspace → Domain → Verification → Scan → Report).
- [ ] Add-domain field tells the user to enter a root domain (no `https://` / `www`).
- [ ] DNS TXT verification record is shown with copy-to-clipboard and host/value labelled.
- [ ] Verification failure explains propagation delay and offers retry + advanced path.

### 1.4 Run Scan → Progress → Executive Report ⭐
- [ ] "New Scan" page explains capabilities as **Intelligence Engines** (not raw detector names).
- [ ] Domain input validates live with helpful "valid / not valid" feedback.
- [ ] Submitting shows a clear "Starting scan…" → "Scan started" → redirect to detail.
- [ ] Scan-in-progress state auto-refreshes and tells the user results will appear when complete.
- [ ] Completed scan opens the **Executive Report** by default; **Technical Details** is a secondary tab.
- [ ] Executive Summary leads with a plain-language risk narrative and a 0–100 score with "higher is safer."
- [ ] Verified findings stand out; observations are visually secondary; remediation lists obvious next steps.
- [ ] Engines with no data render "Coming Soon" / "Not Enabled" — never an empty panel.
- [ ] Failed scan shows "This scan didn't finish" + a "Run a new scan" CTA.

### 1.5 Dashboard → Return Visit ⭐
- [ ] Dashboard shows the score, exposure counts, top findings, trend, and recommended actions.
- [ ] All report links read "Executive Report" and lead to the V2 view.
- [ ] Returning user lands on a dashboard scoped to their last-selected workspace.
- [ ] Workspace switcher works and re-scopes the dashboard.
- [ ] Beta "Feedback" entry point is reachable from every authenticated page.

---

## 2. Manual QA Checklist (per major page)

Run for: Dashboard, Workspace dashboard, Scans, Scan detail (Executive Report), Reports, Settings, Account, Billing/Subscription, Onboarding.

For **each** page, confirm all five states render correctly:

- [ ] **Loading** — spinner/skeleton, no layout jump, no flash of empty content.
- [ ] **Empty** — explains what's missing, why it matters, and the next action (primary CTA).
- [ ] **Error** — friendly message + retry/next action; no raw "Failed to fetch" or "HTTP 500".
- [ ] **Success/Populated** — data is readable, hierarchy is clear, numbers are formatted.
- [ ] **Partial** — some engines/sections unavailable degrade gracefully (no blank panels).

Cross-page consistency:
- [ ] Buttons use the shared `btn-primary` / `btn-secondary` / `btn-ghost` styles consistently.
- [ ] Icons are from one set (lucide), sized consistently within a context.
- [ ] Headings follow a single scale; page titles are `h1`, sections `h2`.
- [ ] Card spacing, radius, and borders are consistent across pages.
- [ ] Date/time and score formatting is consistent everywhere.

---

## 3. Error Experience Checklist

- [ ] **Network offline / API unreachable** → "We couldn't reach CyberMeters. Check your connection and try again." (handled centrally in `api.js`).
- [ ] **Server 5xx with empty body** → "Something went wrong on our end. Please try again in a moment." (no "HTTP 500").
- [ ] **Expired session (401 with token)** → soft redirect to login with "Session expired. Please sign in again."; no hard reload mid-action.
- [ ] **Unauthorized (403)** → explains lack of access and suggests switching workspace / contacting admin.
- [ ] **Plan / rate limit** → single upgrade modal (not a duplicate inline error).
- [ ] **Failed scan** → recoverable with a "Run a new scan" CTA.
- [ ] **Empty report / missing data** → "Coming Soon" / "Not Enabled" rather than blank.
- [ ] **Missing/!selected workspace** → guided empty state, not a crash or blank page.
- [ ] No raw exception text, stack trace, internal code, or endpoint path is ever shown to the user.

---

## 4. Browser Checklist

Test the critical journey (section 1) in each:

- [ ] Chrome (latest, desktop)
- [ ] Safari (latest, macOS) — check date parsing, flexbox gaps, `:focus-visible`.
- [ ] Firefox (latest)
- [ ] Edge (latest)
- [ ] Safari (iOS) — see mobile section.
- [ ] Chrome (Android) — see mobile section.

Per browser:
- [ ] Fonts load (Inter / JetBrains Mono) with acceptable fallback.
- [ ] Clipboard copy (DNS record, verification commands) works or fails gracefully.
- [ ] PDF report download saves a file rather than opening a blank tab.

---

## 5. Mobile Checklist (≤ 400px width)

Pages: Dashboard, Workspace, Scans, Executive Report, Settings, Billing.

- [ ] No horizontal overflow / sideways scrolling on any page.
- [ ] Top nav and workspace switcher are usable (or collapse) on narrow screens.
- [ ] Tables (Scans, Reports) scroll horizontally inside their container, not the whole page.
- [ ] Executive Report: score hero stacks vertically; engine cards are readable; counts hide gracefully.
- [ ] Primary CTAs are full-width or comfortably tappable (≥ 44px touch target).
- [ ] Feedback button does not cover primary actions or the page footer content.
- [ ] Modals (upgrade, delete confirm) fit the viewport and are dismissible.
- [ ] Form inputs are not zoomed/clipped; labels remain visible.

---

## 6. Accessibility Checklist

- [ ] **Keyboard navigation:** every interactive element is reachable with Tab in a logical order.
- [ ] **Visible focus:** all buttons, links, inputs show a focus ring on keyboard focus (global `:focus-visible` rule).
- [ ] **Escape** closes menus/modals (feedback menu, workspace selector, dialogs).
- [ ] **Form labels:** every input has a visible label; ideally programmatically associated (`htmlFor`/`id`).
- [ ] **Button labels:** icon-only buttons have `aria-label` or `title`.
- [ ] **Headings:** one `h1` per page; no skipped levels for major sections.
- [ ] **Colour contrast:** body text and badges meet WCAG AA (4.5:1) on their backgrounds.
- [ ] **State not by colour alone:** severity/status use icon + text, not only colour.
- [ ] **Motion:** spinners/animations are subtle; nothing flashes rapidly.

---

## 7. Known UX Limitations (acceptable for beta, track for GA)

| # | Area | Limitation | Severity |
|---|------|------------|----------|
| 1 | Build verification | Production `vite build` not run in this environment (platform-locked `node_modules`, registry blocked). Run locally before release. | Medium |
| 2 | Forms | Labels are visual but not all programmatically associated via `htmlFor`/`id`. | Low |
| 3 | Executive Report | Findings render compactly; per-finding evidence & "how to fix" detail live only in the Technical Details tab. | Low |
| 4 | Feedback | Beta feedback uses `mailto:` — no in-app capture/analytics yet. | Low |
| 5 | Dashboard | "Security Health" grid still uses detector labels (DNS, SSL/HTTPS, headers) rather than engine language. | Low |
| 6 | Mobile nav | Primary nav is horizontal; on very small screens it relies on wrapping rather than a dedicated menu. | Medium |
| 7 | Report ↔ PDF | In-app V2 report and downloadable PDF are styled independently; they have not been visually reconciled. | Low |
| 8 | i18n | Copy is English-only; some apostrophes/curly quotes assume Latin rendering. | Low |

---

## 8. Recommended Improvements After Beta

1. **Add a mobile nav menu** (hamburger) so navigation scales below ~640px without wrapping.
2. **Associate all form labels** with `htmlFor`/`id` and add inline validation summaries for screen readers.
3. **Unify report styling** so the in-app Executive Report and PDF share one design language.
4. **Replace `mailto:` feedback** with a real capture endpoint + lightweight triage dashboard.
5. **Promote Intelligence Engine language** into the dashboard health grid and any remaining detector-named UI.
6. **Add empty-state illustrations** and short "what happens next" timelines to onboarding steps.
7. **Run an automated a11y pass** (axe/Lighthouse) and a real screen-reader sweep (VoiceOver/NVDA).
8. **Add skeleton loaders** on data-heavy pages (dashboard, report) to reduce perceived latency.
9. **Telemetry on drop-off** at each onboarding step to find the real friction points with data.

---

## Sign-off

| Check | Owner | Date | Status |
|-------|-------|------|--------|
| Critical journeys (§1) | | | ☐ |
| Per-page QA (§2) | | | ☐ |
| Error experience (§3) | | | ☐ |
| Browser matrix (§4) | | | ☐ |
| Mobile (§5) | | | ☐ |
| Accessibility (§6) | | | ☐ |

**Beta is ready to open to external users when every ⭐ critical journey passes and §3 (errors) is fully green.**
