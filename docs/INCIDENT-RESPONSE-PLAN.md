# CyberMeters — Incident Response Plan

> A written, practical playbook for when something goes wrong in production.
> Scoped to CyberMeters' actual stack (Cloudflare Workers · D1 · R2 · Pages ·
> Stripe · Resend) and its real lean operating model.
> Not enterprise theatre — every step is an action you can take tonight.

**Routine Incident Commander:** Claude Desktop (Delivery Executive).
**Founder and legal owner:** Turhan Acar. **Last updated:** 2026-08-30.
This is a living document — after every incident, update the relevant playbook.

---

## 0. Roles and authority

| Role | Who | Does |
|---|---|---|
| **Incident Commander (IC)** | Claude Desktop (Delivery Executive) | Declares severity, dispatches bounded responders, authorises immediate reversible containment and recovery, preserves evidence and reports the outcome. |
| **Founder / legal owner** | Turhan | Decides only operating-model §3 reserved consequences, including external customer/regulator communication and destructive or externally high-impact action; performs human-only login, signature, credential or console steps when requested. |
| **Technical Responder** | Assigned Codex or Claude delivery seat | Diagnoses and executes the IC's bounded containment/recovery dispatch, preserves evidence, and drafts comms and the post-mortem. |
| **Scribe** | Assigned delivery seat | Timestamps every action into the incident log from the first minute. |

The lean team is small: **contain first, investigate second, and write everything
down**. Routine containment does not wait for Founder approval. Escalate after
immediate containment if the durable consequence enters operating-model §3; a
human-only action is an execution request, not a fifth approval class.

---

## 1. Severity & response targets

| Sev | Definition | Examples | Acknowledge | Contain |
|---|---|---|---|---|
| **SEV1** | Confirmed customer-data exposure, account/secret compromise, or full outage | Cross-tenant data leak; stolen API/Cloudflare token; secret in a public place; DB corruption | Immediately | ≤ 1 hour |
| **SEV2** | Security control failed but no confirmed exposure yet; partial outage | Auth/rate-limit bypass found live; Stripe webhook abuse; mass scan abuse; one compromised user account | ≤ 1 hour | ≤ 4 hours |
| **SEV3** | Low-impact, contained, or suspected-only | Single failed control with a compensating one; suspicious activity under investigation | Same day | Next release |

When unsure, **treat it one level higher** until proven otherwise.

---

## 2. Lifecycle

```
DETECT → DECLARE → CONTAIN → ERADICATE → RECOVER → NOTIFY → LEARN
```

1. **Detect** — a signal fires (see §3) or a report arrives (security@cybermeters.com).
2. **Declare** — IC assigns a severity, opens an incident log (`incidents/YYYY-MM-DD-slug.md`), records the start time. From here, everything is timestamped.
3. **Contain** — stop the bleeding with the break-glass actions in §4. Containment beats a perfect diagnosis.
4. **Eradicate** — find and remove the root cause (revoke, patch, rotate).
5. **Recover** — restore service from a known-good state; verify with the release smoke.
6. **Notify** — customers and, if required, the ICO (§6).
7. **Learn** — post-incident review (§8); every finding becomes a regression test (per the Secure SDLC roadmap).

---

## 3. Detection signals to watch

From `wrangler tail`, `audit_events`, and `[request-error]` logs — a spike in any
of these opens a triage: 401/403/404 surges · 429 rate-limit bursts · 5xx rate ·
worker exceptions · login/MFA failure rate · password-reset volume · a single
IP/token hitting many workspaces · abnormal domain-verification attempts · sudden
API-token usage · large/anomalous DMARC XML imports · Stripe webhook failures ·
R2 access errors. External: a report to `security@cybermeters.com`, a Stripe
fraud alert, or a Cloudflare account-security email.

---

## 4. Break-glass actions (the command reference)

Run from `workers/scan-api/`. **Record the printed Version ID of every deploy.**

The Executive may immediately pause a rollout, roll back, revoke a bounded
credential or contain harm under this runbook. Preserve evidence and obtain the
Founder decision before a durable consequence enters operating-model §3, such as
destructive customer-data action, a destructive migration, consequential
DNS/secret or production-account change, external communication or an action
affecting unrelated customers. Do not delay temporary containment needed to stop
harm.

**Roll the worker back to the last known-good version**
```bash
wrangler deployments list                 # find the last good Version ID
wrangler versions deploy <ID>             # use the matching service config
```
Read the exact current and rollback identities from `CHANGELOG.md` and the live
deployment list at incident time. Do not use a hardcoded historical version chain.

**Rotate a leaked/abused secret** (invalidates the old value immediately)
```bash
wrangler secret put RESEND_API_KEY          # email
wrangler secret put CLOUDFLARE_API_TOKEN     # DNS / email-routing / hosted-DMARC
wrangler secret put STRIPE_SECRET_KEY        # + roll the key in the Stripe dashboard
wrangler secret put STRIPE_WEBHOOK_SECRET    # + roll the endpoint secret in Stripe
wrangler secret put MFA_ENCRYPTION_KEY       # ⚠ re-encrypts nothing — see note*
wrangler secret put AZURE_CLIENT_SECRET      # + roll in the Azure app registration
```
*Rotating `MFA_ENCRYPTION_KEY` breaks existing TOTP secrets (they were encrypted
with the old key) — only do this if that key itself leaked, and plan an MFA
re-enrolment for affected users.

**Kill a compromised session or all of a user's sessions**
```bash
wrangler d1 execute cybermeters-db --remote --command \
  "DELETE FROM user_sessions WHERE user_id = '<userId>';"
```

**Revoke a stolen API token**
```bash
wrangler d1 execute cybermeters-db --remote --command \
  "UPDATE api_tokens SET status='revoked' WHERE id = '<tokenId>';"
```

**Freeze a compromised account**
```bash
wrangler d1 execute cybermeters-db --remote --command \
  "UPDATE users SET status='suspended' WHERE id = '<userId>';"
```

**Lock the Cloudflare account** (if the CF account itself is compromised): change
the Cloudflare password, force-rotate all CF API tokens in the dashboard, verify
account 2FA, review the audit log for rogue Workers/DNS/route changes.

**Take a fresh evidence snapshot BEFORE destructive containment**
```bash
wrangler d1 export cybermeters-db --remote \
  --output ~/Documents/cybermeters-backups/incident-$(date +%Y%m%d-%H%M).sql
```

---

## 5. Per-incident playbooks

Each: **Detect → Contain → Investigate → Recover → Notify**.

### 5.1 Cross-tenant data exposure (SEV1)
- **Detect:** a report, or the tenant-isolation matrix would have caught it pre-deploy — a live one means a route bypassed it.
- **Contain:** roll the worker back to the last version that passed `validate-tenant-isolation.js`. If the leak is a single route, that rollback removes it.
- **Investigate:** reproduce with two test accounts; add the exact case to `validate-tenant-isolation.js` (it must go red before the fix, green after).
- **Recover:** deploy the fix; re-run the matrix live.
- **Notify:** SEV1 → assess affected workspaces from `audit_events`; ICO within 72h if personal data of others was actually accessible (§6).

### 5.2 Stolen / abused API token (SEV2)
- **Detect:** abnormal token usage, cross-workspace attempts, 429 bursts on a `cm_` token.
- **Contain:** revoke the token (§4); if abuse continues, suspend the owning account.
- **Investigate:** `audit_events` for what the token did; confirm `token_workspace_id` scope held (it should — covered by the isolation matrix).
- **Recover:** owner issues a fresh token; document scope of any data touched.

### 5.3 Compromised user account (SEV2)
- **Contain:** delete all the user's sessions + force password reset; if MFA was bypassed, suspend until re-verified.
- **Investigate:** login-history + audit trail; determine if workspace data was accessed/changed.
- **Recover:** restore any tampered data from backup; owner re-secures the account (new password + MFA).

### 5.4 Compromised admin/platform account (SEV1)
- **Contain:** remove the email from `ADMIN_EMAILS` (`wrangler secret`/var), kill sessions, freeze the account; rotate anything the admin could see.
- **Investigate:** every admin-route action in `audit_events`.
- **Notify:** SEV1 handling.

### 5.5 Secret leak (SEV1)
- **Contain:** rotate the affected secret immediately (§4) — this invalidates the leaked value even before you know how it leaked.
- **Investigate:** where did it leak (repo history, log, screenshot, third party)? Run a git-history secret scan, not just current files.
- **Recover:** confirm services still work on the new secret; if the leak was in git history, purge history or rotate and move on (rotation is what matters).

### 5.6 Malicious / compromised dependency (SEV2)
- **Detect:** `npm audit` alert, a suspicious lockfile diff, or advisory.
- **Contain:** pin/remove the package; the worker lockfiles (`6068eb3`) make the exact tree auditable — diff against last known-good.
- **Recover:** rebuild, re-run all CI harnesses, redeploy.

### 5.7 Stripe webhook abuse / replay (SEV2)
- **Contain:** the signature gate already rejects forged events (verified live, 400). If a valid-but-replayed event is suspected, disable/roll the webhook endpoint secret in Stripe + `wrangler secret put STRIPE_WEBHOOK_SECRET`.
- **Investigate:** `subscription_events` for duplicate/anomalous state transitions; confirm idempotent handling held.
- **Recover:** reconcile subscription state against Stripe as source of truth.

### 5.8 Database corruption / bad migration (SEV1)
- **Contain:** roll the worker back (removes the code that writes bad data). Do NOT run further migrations.
- **Recover:** restore D1 from the latest export (§4 command / backup at `~/Documents/cybermeters-backups/`); if only some rows are bad, write a corrective migration rather than a full restore. Verify against RPO/RTO (§7).

### 5.9 R2 report leak (SEV1)
- **Contain:** report objects are private and served only through a `requireWorkspaceRole`-gated download; if a signed-link or key-guessing path is found, roll back and delete exposed objects.
- **Investigate:** which report keys, which workspaces; the bucket is `cybermeters-reports`.
- **Notify:** treat as data exposure (§6) if another tenant's report was reachable.

### 5.10 Email-account (Resend / inbound) compromise (SEV2)
- **Contain:** rotate `RESEND_API_KEY`; if inbound RUA is abused, review Cloudflare Email Routing rules.
- **Investigate:** outbound send volume for spam abuse; lifecycle-email retry logs.

### 5.11 Mass scan / cost abuse (SEV2)
- **Contain:** scan-start is quota-gated (fail-open on transient DB errors, by design); if abused, tighten the per-account/per-IP limit and redeploy. Suspend the abusing account.
- **Investigate:** `scans` volume per owner; subrequest/cost impact.

### 5.12 Cloudflare account compromise (SEV1)
- The platform root: handle as §4 "Lock the Cloudflare account" first, then rotate every secret and review all Workers/DNS/routes for tampering.

---

## 6. Customer & regulator notification

**CyberMeters is UK-based → UK GDPR applies.** A personal-data breach that risks
individuals' rights must be reported to the **ICO within 72 hours** of becoming
aware; affected individuals must be told without undue delay if the risk is high.

The Executive IC starts the clock, establishes the facts, assesses risk and
drafts the notice. Customer or regulator notification is an external
communication and therefore a Founder-reserved decision under operating-model
§3; this authority boundary never pauses a legal deadline.

Decision path:
1. Was **personal data** of a person (customer, their end-users) actually
   exposed, altered, or lost — not just theoretically reachable? If clearly no →
   document the reasoning, no ICO report, still fix + review.
2. If yes or unclear → IC prepares the risk assessment for the Founder. High
   risk → the Founder authorises notice to affected customers **and** the ICO.
   Low/contained → record the assessment; an ICO report may still be required —
   when in doubt, act within 72h.

**Customer notice — say plainly:** what happened, what data was involved, when,
what you've done, what they should do, and how to reach you. No spin, no jargon.
Draft template lives in `incidents/templates/customer-notice.md` (to add).

---

## 7. Backup, RPO & RTO

- **Backup:** `wrangler d1 export cybermeters-db --remote --output=<path>` →
  `~/Documents/cybermeters-backups/` (kept out of the repo; contains customer
  data). Prefer the guarded `scripts/ops/backup-production-data.sh`, which copies
  D1 **and** the R2 object set into a verified encrypted destination. R2 report
  objects are regenerable from scans; **R2 has no object versioning**, so their
  recovery point is a separately copied object set plus manifest, not an in-bucket
  version. Restore drills use `scripts/ops/restore-production-backup-to-staging.sh`
  into a disposable staging target — never in place, never D1 Time Travel.
- **Targets (initial, revisit at scale):** **RPO ≤ 24h** (at most a day of data
  loss — take a daily export during active beta), **RTO ≤ 4h** (service restored
  within four hours of a SEV1).
- **Prove it:** a restore is not a backup until restored — run a periodic restore
  drill into a scratch D1 and record the result (roadmap P0#8).

---

## 8. Post-incident review (within 3 working days)

Blameless. Answer, in the incident log:
1. **Timeline** — detection → containment → recovery, with timestamps.
2. **Root cause** — the actual technical cause, not the symptom.
3. **Why it wasn't caught** — which gate/test would have stopped it.
4. **The regression test** — the exact automated test now guarding it (mandatory:
   a finding without a test is not closed).
5. **Blast radius** — who/what was affected; customer/regulator actions taken.
6. **Follow-ups** — with owners and dates.

---

## 9. Contacts & references

- **Security reports:** security@cybermeters.com (published in `security.txt`).
- **ICO (UK):** ico.org.uk — breach reporting within 72h.
- **Stripe:** dashboard → Developers (roll keys/webhook secret); Radar for fraud.
- **Cloudflare:** dashboard → account security (rotate API tokens, 2FA, audit log).
- **Rollback IDs & release history:** `CHANGELOG.md`.
- **What each control already does:** `docs/SECURITY-SDLC-ROADMAP.md`.
```
D1: cybermeters-db (fd6792cb-441a-44a7-8ca2-9a0b411ec706)   R2: cybermeters-reports
Worker: cybermeters-platform    Email worker: cybermeters-email
```
