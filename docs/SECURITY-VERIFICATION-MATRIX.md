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
| B2 | V3.2 / WSTG-SESS | Session token: hashed-at-rest, high-entropy, rotates on login | Runtime suite | 1t | **P** | #247 (`validate-auth-coverage.js`, 39/39, ran locally 21 Jul): raw token never stored (hash-at-rest), high-entropy, rotates on login. **N/A: cookie flags** — Bearer-token architecture (token in Authorization header, no auth cookie), so httpOnly/Secure/SameSite don't apply; equivalent protections asserted. Mutation-verified |
| B3 | V3.3 | Logout + password reset session invalidation | Runtime suite | 1t | **P** | #247: password reset invalidates ALL sessions + revokes API tokens; logout is per-device **by design** (not all-sessions) — the true oracle, not misrepresented. Mutation-verified |
| B4 | V2.2 | MFA (TOTP) enrol/verify, no bypass | Runtime suite | 1t | **P** | #247: valid RFC-6238 TOTP verifies, wrong code rejected; login-MFA challenge single-use + expiry; recovery codes single-use. Mutation-verified |
| B5 | V2.x | Microsoft SSO id_token claims validation | Runtime suite | 1t | **P (claims)** | #247: alg/aud/exp/nbf/iss/tid/oid/nonce each enforced. **NT: RS256 JWKS signature + live OAuth redirect/state exchange** need a real Microsoft IdP (release-gate). Mutation-verified (drop-aud → red) |
| B6 | V2.5 | Password reset: token single-use, expiring, no user enum | Runtime suite | 1t | **P** | #247: single-use (`used_at`) + expiring; forgot-password does not enumerate accounts. Mutation-verified |

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
| D1 | V4.x / business | Plan downgrade closes entitlement immediately (no open pro features) | Runtime suite | 1t | **P** | #243 (`validate-billing-abuse-coverage.js`, 33/33, ran locally 21 Jul): professional→starter + cancel both drop `getEffectivePlanState` same request; exec-dashboard/vendor_risk + domain limit 3→1 denied after. **Regression-locks #239**: `status == subscription_status` after downgrade AND cancel. Mutation-verified |
| D2 | business | Trial-expiry cannot be bypassed (clock/param tampering) | Runtime suite | 1t | **P** | #243: expired trial→free; trialing row with neither trial_end nor current_period_end fails closed; client-set `plan=business` on expired trial grants nothing. Mutation-verified |
| D3 | V13 | Stripe webhook replay rejected (CAS idempotency #191) | Runtime suite | 1t | **P** | #243: exact event-id replay deduped (no 2nd row); superseded-upgrade replay after downgrade doesn't resurrect higher plan; stale out-of-order event never rewinds current_period_end. Mutation-verified |
| D4 | business | Checkout fail-closed: price/plan mismatch rejected (verifyStripePriceMatchesPolicy) | Runtime suite | 1t | **P** | #243: refuses amount/currency/interval/inactive mismatch, Stripe lookup failure, non-eligible plan — tampered price/higher plan can never charge below canonical registry. Mutation-verified |
| D5 | business | Portal-only plan change cannot stack a 2nd subscription (B3) | Done 21 Jul | 1t | **P** | D1 single-row proof, [[m7-b2-b3-checkout-consent-portal]] |

### E. Input validation, injection, SSRF
| # | ASVS / WSTG | Control | Method | Env | Status | Evidence |
|---|-------------|---------|--------|-----|--------|----------|
| E1 | V5.3 / WSTG-INPV | SQLi — bound params everywhere (D1 prepared statements) | Code review | 1t | **P** | 1013 `.prepare()` / 1002 `.bind()`; all values parameterized; template interpolation ONLY for code-controlled identifiers (table/column names from constants, `?,?,?` placeholder lists) — verified portfolio-risk/plan-usage/cert-lifecycle/purge (static, 21 Jul). Runtime ZAP confirm still useful. |
| E2 | V5.2 | Injection on server-side render sinks (PDF, email, API echo) | Runtime suite | 1t | **P (server sinks)** | #249 (`validate-injection-coverage.js`, 53/53, ran locally 21 Jul): pdfEsc neutralises content-stream breakout (paren/`<script>`/control/backslash, ASCII-only); alert+digest+invitation email templates HTML-escape user fields; API echo is JSON (Content-Type application/json, never text/html); isValidDomain + name length cap. Mutation-verified. **NT: pure DOM-XSS** (React auto-escapes; needs browser/DAST → release-gate) |
| E3 | V12.6 / WSTG-INPV | SSRF: scan-target & fetch paths cannot hit internal/metadata (per-hop guard #191) | Code review | 1t | **P** | `lib/ssrf.js` blocks loopback/private/link-local/reserved across encodings (decimal-IP, IPv4-mapped-IPv6, `169.254.169.254` metadata) + DNS-resolution check on A+AAAA (rebinding) + per-hop redirect guard (#191); `safeFetch` (lib/http.js) is the canonical fetcher used by all scan engines (static, 21 Jul). Runtime confirm still useful. |
| E4 | V5.1 | Mass-assignment / unexpected field injection on writes | Runtime suite | 1t | **P** | #249: profile update ignores injected plan/role/status/email_verified/id; workspace rename ignores owner_user_id/id/deleted_at; member invite→role=owner refused; api-token create ignores internal token_scope/token_workspace_id + refuses non-member ws; case transition writes validator target, never client status/verified_at — each verified unchanged in D1. Mutation-verified |

### F. Workflow / lifecycle logic
| # | ASVS / WSTG | Control | Method | Env | Status | Evidence |
|---|-------------|---------|--------|-----|--------|----------|
| F1 | business | Case lifecycle transitions honour canTransitionCase (no illegal jump) | Static audit | 1t | **P** | `applyCaseTransition` fail-closed (terminal immutability + unknown-target reject + illegal-edge reject + guards); `canTransitionCase` layers system-only + verified-evidence rules; every `managed_cases SET status` write is canTransitionCase-gated (1:1, no bypass); route writes only validator `next.status` under `WHERE …AND status=?` TOCTOU guard; guard-arity P1 fixed+documented via wrapper closure (static, 21 Jul) |
| F2 | business | Verification cannot be forged (attest ≠ verified) | Runtime suite | 1t | **P** | #245 (`validate-workflow-abuse-coverage.js`, 35/35, ran locally 21 Jul): bare completed-scan / note-only / no-evidence never reaches verified; automated-support needs a system actor (customer refused); unsupported refused; manual verifies only with structured attestation; `verificationCeiling('manual')` = "Attested by customer — not externally verifiable". Mutation-verified |
| F3 | business | Alert/digest workflow cannot be spoofed or replayed | Runtime suite | 1t | **P** | #245: `emitManagedAlert` dedupes identical dedupe_key (DB unique index), suppresses soft-deleted workspace, resolves recipients to the alert's own workspace only; `sendWeeklyDigests` idempotent per ISO week. Mutation-verified |
| F4 | V11.1 | Rate limiting on scan starts, auth, expensive endpoints | Runtime suite | 1t | **P** | #245: real login route (cap 10/15min, failClosed) — (cap+1)th from one IP → 429; on rate-store error the failClosed caller DENIES. Mutation-verified |

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

## Progress status (21 July 2026)

**Fixture-testable + code/static layer COMPLETE — no findings.** Six CI-enforced suites (204 assertions, all mutation-verified, each run locally not CI-alone) + the Nuclei public baseline + the code/static audit close every control except the release-gate items:

| Section | Result |
|---|---|
| A public surface | A1–A5 PASS · A6 → release-gate (auth UI smoke) |
| B auth | B1–B4, B6 PASS · B5 claims PASS (RS256 sig + live OAuth → release-gate) |
| C tenant isolation | C1/C2/C4/C5 PASS + C3 static-clean |
| D billing/entitlement | D1–D5 PASS |
| E injection/SSRF | E1, E3, E4 PASS · E2 server sinks PASS (pure DOM-XSS → release-gate DAST) |
| F workflow | F1–F4 PASS |

Suites: `validate-tenant-authz-coverage` (44) · `validate-billing-abuse-coverage` (33) · `validate-workflow-abuse-coverage` (35) · `validate-auth-coverage` (39) · `validate-injection-coverage` (53) + the reliability matrix.

**Remaining before declaring `Internal Web/API Security Verification — PASS`** (all need the real environment, fold into founder-controlled acceptance / RC):
1. A6 authenticated API UI smoke; B5 RS256 JWKS signature + live Microsoft OAuth exchange; pure DOM-XSS DAST (E1/E3 UI).
2. The reliability runtime deltas (R10–R13: load, chaos, live rollback drill) — `docs/RELIABILITY-VERIFICATION-MATRIX.md`.

## Sequencing

1. ✅ **Done (21 Jul):** the matrix + Nuclei public baseline + all six fixture/static suites — no findings.
2. **RC / founder-controlled acceptance (real env):** the release-gate items above, side-effect-safe, on the founder test tenants created at the go-live full-reset.
3. **Retest** every FAIL after fix; attach evidence.
4. Only when the release-gate items are PASS/NT-resolved with evidence → declare `Internal Web/API Security Verification — PASS`. **The fixture/static layer is already there; what remains is the real-environment smoke.**
5. Independent external pentest + retest remains a separate, later gate (see the cost-focused options recorded with the founder: scoped freelance app-sec test, or defer-with-honest-disclosure to post-controlled-beta).

Related: [[security-hardening-v2-closure-shipped]], [[full-repo-security-assurance]], [[m7-b2-b3-checkout-consent-portal]], [[data-minimization-discovery]].
