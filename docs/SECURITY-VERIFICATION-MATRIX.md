# Internal Web/API Security Verification — Control Matrix

Status: **IN PROGRESS (started 21 July 2026).** This is the honest scaffold for the internal security gate. It is NOT a claim of completion, and it is NOT an independent pentest.

## What this gate is — and is not

- **Internal** — performed by the team that built the product. It de-risks and hardens; it does not substitute for an independent external opinion.
- **ASVS-L2 mapped** — every control traces to an OWASP ASVS 5.0 requirement (and WSTG test where relevant). L2 is the honest bar for an application handling sensitive multi-tenant data. L3 is explicitly out of scope.
- **Evidence-backed** — each control is PASS / FAIL / NOT-TESTED with a reproducible artefact (request/response, screenshot, log, test name). A control we did not test is recorded as **NOT-TESTED**, never silently green.
- **Two honest gate labels, kept separate:**
  1. `Internal Web/API Security Verification — PASS` (this document, when complete)
  2. `Independent External Pentest + Retest — PASS` (later, a third party)

## Tooling roles (tools serve controls, not the reverse)

| Tool | Role | Safe against prod? |
|------|------|--------------------|
| **Nuclei** | Known-CVE, misconfig, exposed file/panel, TLS/header, tech-detect — template coverage of the **unauthenticated public surface** | Yes, rate-limited, GET-heavy |
| **ZAP** | Spider/passive scan, automated DAST, OpenAPI/API discovery, repeatable YAML automation | **Active scan = destructive** → founder test env only |
| **Burp** | Proxy real user flows, request tampering, session/auth, **IDOR/BOLA + tenant isolation**, business-logic abuse, manual exploit verification | Manual, **founder test tenants only** |
| **Manual + 2-tenant harness** | The high-value work automation cannot assert: cross-tenant access, entitlement state machine, workflow bypass | Founder test tenants only |

**Operational rule:** active/authenticated testing (ZAP active, Burp intruder, form submission, state mutation) runs ONLY against founder-controlled test workspaces in a side-effect-safe way — never prod-with-real-data, never a beta customer's domain. Matches the product's own Production-Proof rule. The two-tenant work waits for the go-live full-reset test environment.

## Existing coverage — we are NOT starting from zero

- **#187 full-repo security assurance:** 234-handler inventory, 83-table tenant-isolation matrix, two-tenant + property test suites, 6 CI gates.
- **#191 hardening v2:** SSRF per-hop guard, Stripe CAS idempotency (webhook replay defence).
- Fail-closed patterns throughout: invitation email, alert gate, verification, checkout consent guard, entitlement resolver (`subscription_status` precedence).
- Data-minimisation baseline accepted.

The gap this gate fills is **outside-in / attacker-view** validation of those inside-out guarantees, plus the CyberMeters-specific business-logic abuse cases below.

---

## Threat model → the abuse cases that matter most

The dangerous bugs for CyberMeters are rarely generic scanner findings. They are:

1. Reading another workspace's domain / scan / report / case.
2. Guessing another tenant's scan or report ID and fetching it (IDOR/BOLA).
3. Accepting an invitation into a soft-deleted workspace.
4. Entitlement staying open after a plan downgrade.
5. Trial-expiry bypass.
6. Case owner / lifecycle-state manipulation.
7. PDF / R2 object authorization (fetching another tenant's report bytes).
8. Webhook replay or wrong subscription resolution (double-entitlement).
9. Alert / digest / case workflow logic bypass.

These drive the matrix priority.

---

## Control matrix

Legend: **P**=PASS · **F**=FAIL(→fix) · **NT**=not tested yet · **N/A**=out of scope. "Env": `pub`=public unauth, `1t`=single founder tenant, `2t`=two founder tenants.

### A. Public / unauthenticated surface
| # | ASVS / WSTG | Control | Method | Env | Status | Evidence |
|---|-------------|---------|--------|-----|--------|----------|
| A1 | V14.4 / WSTG-CONF | Security headers (HSTS, CSP, X-CTO, referrer, frame) present & sane | Nuclei + curl | pub | **P** | Strong: HSTS 1y+includeSubDomains; tight CSP (`default-src 'self'`, `frame-ancestors 'none'`, `object-src 'none'`, scoped script/form-action; API=`default-src 'none'`); Permissions-Policy, Referrer-Policy, X-CTO nosniff, X-Frame DENY; no Server/X-Powered-By leak (21 Jul) |
| A2 | V1.9 / WSTG-CRYP | TLS config: min 1.2, no weak ciphers, HSTS | Nuclei ssl | pub | **P** | Only TLS 1.2 + 1.3 on all hosts, no 1.0/1.1; HSTS present (21 Jul) |
| A3 | V14.3 / WSTG-CONF | No exposed `.env`, `.git`, backups, admin panels, debug endpoints | Nuclei exposures | pub | **P** | Nuclei baseline (48,673 req, 6413 templates): ZERO exposures/panels/files/default-creds. Caveat: Cloudflare WAF absorbed many probes (see note) (21 Jul) |
| A4 | V14.2 | No known-CVE fingerprints on the edge/app | Nuclei cve/tech | pub | **P** | Nuclei baseline: ZERO CVE matches; only info-level tech/TLS/WAF fingerprints (21 Jul) |
| A5 | V7.4 / WSTG-ERRH | Errors never leak Cloudflare/Worker/D1/SQL/stack traces | Code review | pub | **P** | `lib/errors.js` customerSafeFailure logs internally, returns only generic message; `sanitizeInfraErrorMessage`; no raw `err.message` in any JSON response (static, 21 Jul). Runtime DAST confirm still useful. |
| A6 | V13.1 | API surface: no unauthenticated data endpoints; 401 gates hold | Manual + ZAP | pub | NT | |

### B. Authentication, session, recovery, MFA, SSO
| # | ASVS / WSTG | Control | Method | Env | Status | Evidence |
|---|-------------|---------|--------|-----|--------|----------|
| B1 | V2.1 / WSTG-ATHN | Password hashing PBKDF2-SHA256 100k, no plaintext, timing-safe verify | Code review | 1t | **P** | `lib/password.js`: PBKDF2-SHA256, 100_000 iters, 16-byte random salt, stored `pbkdf2:sha256:100000:salt:hash`; verify uses constant-time XOR compare (static, 21 Jul) |
| B2 | V3.2 / WSTG-SESS | Session token: httpOnly, secure, server-side, rotates on login | Burp | 1t | NT | |
| B3 | V3.3 | Logout + password reset invalidate all sessions | Burp | 1t | NT | |
| B4 | V2.2 | MFA (TOTP) enrol/verify, no bypass | Manual | 1t | NT | |
| B5 | V2.x | Microsoft SSO: state/nonce, account-linking safety | Burp | 1t | NT | |
| B6 | V2.5 | Password reset: token single-use, expiring, no user enum | Burp | 1t | NT | |

### C. Authorization & tenant isolation (highest priority)
| # | ASVS / WSTG | Control | Method | Env | Status | Evidence |
|---|-------------|---------|--------|-----|--------|----------|
| C1 | V4.2.1 / WSTG-ATHZ | **BOLA/IDOR**: tenant-B cannot read tenant-A scan/report/case/asset by ID | Static + runtime suite | 2t | **P** | Static delta-audit clean + **runtime #241** (`validate-tenant-authz-coverage.js`, 44/44, ran locally 21 Jul): proves the smuggle vector — wsB-owner requesting A's id via wsB's own path is blocked by handler `workspace_id AND id` scoping (managed-cases/cases/related-changes/assets). Mutation-verified non-vacuous. crown jewel |
| C2 | V4.1.3 | Role/privilege enforcement (viewer vs manager vs owner) | Static + runtime suite | 2t | **P** | `requireWorkspaceRole` + `hasWorkspacePermission`; #241 asserts viewer denied on manager-gated mutations (feedback/link-case/create-case/transition/assign) + positive read control; mutation-verified |
| C3 | V4.2.2 | Soft-deleted workspace receives no new scans/cases/invitations/alerts | Static + Manual | 1t | **static-clean** | All access helpers join `w.deleted_at IS NULL` (verified helper + sweep). Runtime confirm optional |
| C4 | V4.2 | R2 object / PDF report authorization — no cross-tenant byte fetch | Runtime suite | 2t | **P** | #241: owner of wsB cannot fetch A's report/PDF/exec/snapshot bytes (ownership-scoped, not membership-wide) |
| C5 | V13.1.4 | API-token lifecycle: scope, expiry, revocation, no cross-tenant reuse | Static + runtime suite | 2t | **P** | `requireWorkspaceAccess` P0 `token_workspace_id !== workspaceId → null`; #241 end-to-end: wsA-token denied on wsB even when its user is a member of BOTH (isolates token boundary from membership); read-scope can't write; expired+revoked rejected; mutation-verified |

### D. Billing / entitlement business logic
| # | ASVS / WSTG | Control | Method | Env | Status | Evidence |
|---|-------------|---------|--------|-----|--------|----------|
| D1 | V4.x / business | Plan downgrade closes entitlement immediately (no open pro features) | Manual | 1t | NT | today's stale-status finding lives here |
| D2 | business | Trial-expiry cannot be bypassed (clock/param tampering) | Burp | 1t | NT | |
| D3 | V13 | Stripe webhook replay rejected (CAS idempotency #191) | Manual | 1t | NT | |
| D4 | business | Checkout fail-closed: price/plan mismatch rejected (verifyStripePriceMatchesPolicy) | Manual | 1t | NT | |
| D5 | business | Portal-only plan change cannot stack a 2nd subscription (B3) | Done 21 Jul | 1t | **P** | D1 single-row proof, [[m7-b2-b3-checkout-consent-portal]] |

### E. Input validation, injection, SSRF
| # | ASVS / WSTG | Control | Method | Env | Status | Evidence |
|---|-------------|---------|--------|-----|--------|----------|
| E1 | V5.3 / WSTG-INPV | SQLi — bound params everywhere (D1 prepared statements) | Code review | 1t | **P** | 1013 `.prepare()` / 1002 `.bind()`; all values parameterized; template interpolation ONLY for code-controlled identifiers (table/column names from constants, `?,?,?` placeholder lists) — verified portfolio-risk/plan-usage/cert-lifecycle/purge (static, 21 Jul). Runtime ZAP confirm still useful. |
| E2 | V5.2 | Stored/reflected XSS in workspace names, notes, domain inputs | ZAP + manual | 1t | NT | |
| E3 | V12.6 / WSTG-INPV | SSRF: scan-target & fetch paths cannot hit internal/metadata (per-hop guard #191) | Code review | 1t | **P** | `lib/ssrf.js` blocks loopback/private/link-local/reserved across encodings (decimal-IP, IPv4-mapped-IPv6, `169.254.169.254` metadata) + DNS-resolution check on A+AAAA (rebinding) + per-hop redirect guard (#191); `safeFetch` (lib/http.js) is the canonical fetcher used by all scan engines (static, 21 Jul). Runtime confirm still useful. |
| E4 | V5.1 | Mass-assignment / unexpected field injection on writes | Burp | 1t | NT | |

### F. Workflow / lifecycle logic
| # | ASVS / WSTG | Control | Method | Env | Status | Evidence |
|---|-------------|---------|--------|-----|--------|----------|
| F1 | business | Case lifecycle transitions honour canTransitionCase (no illegal jump) | Burp | 1t | NT | |
| F2 | business | Verification cannot be forged (attest ≠ verified) | Manual | 1t | NT | |
| F3 | business | Alert/digest workflow cannot be spoofed or replayed | Manual | 1t | NT | |
| F4 | V11.1 | Rate limiting on scan starts, auth, expensive endpoints | Manual + Nuclei | 1t | NT | |

---

## Nuclei public baseline — result (21 July 2026)

Scoped, rate-limited (15 rps) run against `cybermeters.com, www., app., api., reports.` — founder-owned only. 48,673 requests, 6,413 templates, 45 min. **30 findings, ALL `info` severity** — pure recon (TLS cert/version, tech-detect, WAF-detect). **Zero** exposures, CVEs, misconfigs, exposed panels/files, or default credentials.

**Honest caveat (product's own principle — automated clean ≠ secure):** Cloudflare WAF fired on every host and absorbed/challenged many probes (393 request errors). So a clean unauthenticated Nuclei result behind Cloudflare partly reflects **edge filtering**, not only origin hardening. The origin Worker is only reachable through Cloudflare (by architecture), so edge protection is genuinely part of the posture — but this baseline covers the **public surface only**. The controls that matter most for CyberMeters (auth, tenant isolation, entitlement, business logic — sections C–F) are NOT reachable by unauthenticated scanning and remain the real work.

## C-section static delta-audit (21 July 2026)

The #187 tenant-isolation sweep (`docs/tenant-isolation-sweep-v1.md`, commit `85f8972`, 6 Jul) found no cross-tenant leak across 120 routes. This delta audit re-checks the **new/changed route modules since** that sweep (234 commits touched routes since):

- **Enforcement helpers verified sound:** `requireWorkspaceAccess` (P0 token-workspace boundary hard-reject; `deleted_at IS NULL` join; owner-fallback only for member-less workspaces), `requireWorkspaceRole` (+ `hasWorkspacePermission` — token scopes narrow, never widen), `requireScanReadAccess`, `requireDomainRole`, `getAccessibleWorkspaceIds`.
- **All 27 `routes/*.js` modules** use a scope guard except `auth.js` (public/self-scoped by design — id binds the authenticated user's own id) and `global-billing.js` (verified: `/billing/plans` public, `/dmarc-ingest` token→single-workspace binding fail-closed, `/billing/subscription` self-scoped `owner_user_id=user.id`, `/billing/webhook` signature-gated).
- **BOLA sweep:** every `WHERE id = ?` read that omits `workspace_id` is either self-scoped (user/auth/mfa/reset rows keyed to the caller's own id/token) or a workspace-existence check behind a prior guard. **No workspace-scoped resource (scan/report/case/asset/cert/identity) is read by bare id outside tenant scope.**

**Conclusion:** no new tenant-isolation gap at the route-authorization layer. This is a **static** result — the crown-jewel controls (C1/C4/C5) still deserve **runtime two-tenant proof**, which the CLI's automated cross-tenant authz suite (+ later Burp) provides. Static-clean + runtime-proof together = C-section PASS.

## Sequencing

1. **Today (safe, parallel to M7):** control matrix (this doc) + section **A** via a scoped, rate-limited Nuclei baseline on `*.cybermeters.com` (founder-owned only). Triage → real findings become go-live blockers.
2. **After the go-live full-reset test environment exists** (founder creates one clean test account, then a second test tenant): sections **B–F** with ZAP automation + Burp manual, two founder tenants, side-effect-safe.
3. **Retest** every FAIL after fix; attach evidence.
4. Only when A–F are PASS/NT-resolved with evidence → declare `Internal Web/API Security Verification — PASS`.
5. Independent external pentest + retest remains a separate, later gate.

Related: [[security-hardening-v2-closure-shipped]], [[full-repo-security-assurance]], [[m7-b2-b3-checkout-consent-portal]], [[data-minimization-discovery]].
