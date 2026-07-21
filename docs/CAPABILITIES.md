# CyberMeters — Capabilities & Limitations (canonical living register)

**This is the single source of truth for three questions:**
1. What does CyberMeters do **today**?
2. At what **evidence level** does it do it?
3. What does it **explicitly not do**, or has **not yet verified**?

It describes **verified present behaviour, not roadmap ambition.** It is a *current-state* register — not a timeline. Related documents, kept separate on purpose:
- **When something shipped** → [`CHANGELOG.md`](../CHANGELOG.md) (release timeline — never duplicated here).
- **Future work** → `docs/ROADMAP-TO-FIRST-PAYING-CUSTOMER.md` and episode/backlog docs.
- **Marketing-claim accuracy** → `docs/PUBLIC-CLAIMS-TRUTH-AUDIT.md`.

**Sensitive-information boundary:** this register states *customer truth*; it does **not** give an attacker a blueprint. It deliberately omits secret names, internal route maps, private table names, exact rate-limit thresholds, rollback-mechanism internals, and any implementation detail that would ease bypassing a control. Implementation lives in code and internal engineering docs, not here.

## Status labels (every capability carries exactly one)
- **Live — production-verified** — deployed and confirmed working against real production evidence.
- **Live — founder acceptance pending** — deployed and engineering-closed, but genuine live-event / founder acceptance is still outstanding.
- **Engineering complete — deployment pending** — merged and validated, not yet on the live Worker.
- **Partial / bounded coverage** — works within an explicit, honest boundary (not full coverage).
- **Planned** — not built.
- **Retired from customer-facing claims** — deliberately removed as a customer claim (underlying data may be preserved internally).

## Evidence language (never conflated)
- **Observed** — CyberMeters externally saw it directly.
- **Derived** — deterministically computed from an observation.
- **Correlated** — two or more independent signals deterministically linked.
- **Customer-declared** — the customer asserted it (not externally verified).
- **Inferred / unverified** — no conclusive evidence; stated as such, never as fact.

*Honesty rule:* "A sender IP was **observed** failing SPF in DMARC aggregate evidence" is valid. "An attacker modified your SPF" is **not** valid without evidence. *Verified/Confirmed* is reserved for what CyberMeters itself observed; *Attested* is the customer's word.

---

## Hard product boundaries (cross-cutting — referenced by every domain)
CyberMeters is external-observation, evidence-led. It is **not**, and does not claim to be:
- an endpoint agent · EDR · SIEM · NDR;
- LAN packet capture; internal DNS-tunneling detection; process or registry monitoring;
- dark-web / breach / stealer-log monitoring;
- a full active DAST;
- a substitute for an independent penetration test;
- a claim to cover **all** phishing or **all** supply-chain risk.

It has no visibility into internal networks, endpoints, employee devices, browser history, internal software inventory, internal identity events, full SaaS-licence data, or internal CASB data. Domain sections reference this section rather than repeating it.

---

## The eight canonical domains

> The model is **exactly eight** customer-facing domains. There is no ninth. Third-party / vendor technology signals are described under **Shadow IT**, not as a separate capability.

### 1. Email Protection
- **Observes:** SPF / DKIM / DMARC records; DMARC policy posture; DMARC aggregate (RUA) reports received on the reporting mailbox → per-source rollup (source IP, the report's own SPF/DKIM result).
- **Detects:** presence/absence and misconfiguration of SPF/DKIM/DMARC; a change to the published SPF record (catches unauthorised SPF-record tampering); DMARC posture changes.
- **Verifies (Observed):** the externally published email-authentication configuration and its changes over time.
- **Customer-declared inputs:** none required for observation; sender legitimacy classifications are customer-declared.
- **Alerts & managed workflows:** canonical email alerts; managed cases for email-authentication findings with honest verification.
- **Evidence sources:** live DNS; received DMARC aggregate reports.
- **Known limitations:** an SPF change hidden inside a provider's own `include:` chain is only caught once include-aware resolution is deployed (see maturity); a provider IP with no DNS or DMARC evidence cannot be known.
- **Explicitly does not do:** read mailbox contents or internal mail flow; assert an SPF-fail verdict it did not observe (it uses the DMARC report's own result). See **Hard boundaries**.
- **Current maturity:** core observation, DMARC-maturity scorecard, alerts and managed cases — **Live — founder acceptance pending**. Include-aware SPF authorisation-set resolution + RUA-corroborated "unauthorised sending source" signal — **Engineering complete — deployment pending**.
- **Canonical supporting docs:** `DMARC-MATURITY-SCORECARD.md`, `alerts-eight-domain-coverage.md`.

### 2. Brand Protection
- **Observes:** lookalike / typosquat candidate domains (TLD-swap, keyword permutations, passive Certificate Transparency); DNS + HTTPS + login-form enrichment on candidates.
- **Detects:** registered lookalikes; a candidate that resolves and hosts a login page (higher risk).
- **Verifies (Observed):** existence and enrichment signals of candidate domains.
- **Customer-declared inputs:** the protected brand / domain.
- **Alerts & managed workflows:** brand alerts; managed cases; takedown **preparation and tracking**.
- **Evidence sources:** DNS, Certificate Transparency, HTTP/TLS enrichment.
- **Known limitations:** cannot prove a lookalike owner's intent; discovery is signal-based, not exhaustive.
- **Explicitly does not do:** **execute** takedowns (prepares/tracks only — never "we took it down").
- **Current maturity:** **Live — founder acceptance pending** (full-chain acceptance needs a registered lookalike scenario; **Partial** until then).
- **Canonical supporting docs:** `alerts-eight-domain-coverage.md`.

### 3. Attack Surface
- **Observes:** externally reachable assets, subdomains, exposure signals.
- **Detects:** newly appearing/disappearing externally observable assets and exposures.
- **Verifies (Observed):** external reachability and exposure state; ASM verification of remediation.
- **Customer-declared inputs:** the domain(s) in scope.
- **Alerts & managed workflows:** ASM alerts; managed cases with verification.
- **Evidence sources:** external discovery and probing of customer-owned domains.
- **Known limitations:** only what is externally observable; not exhaustive of an org's true asset set.
- **Explicitly does not do:** internal-network or authenticated scanning; exploitation / penetration testing. See **Hard boundaries**.
- **Current maturity:** **Live — founder acceptance pending**.

### 4. Certificates & Trust
- **Observes:** certificate identity, expiry, Certificate Transparency.
- **Detects:** expiring/expired certificates; certificate replacement/identity changes; coverage gaps.
- **Verifies:** what CyberMeters externally re-observes (**Observed**). `external` verification = an independent third party certifies it — neither CyberMeters' observation nor the customer's word.
- **Customer-declared inputs:** none required for observation.
- **Alerts & managed workflows:** certificate alerts; managed lifecycle (identity / replacement / coverage).
- **Evidence sources:** live TLS observation, Certificate Transparency.
- **Known limitations:** an unexpired certificate is not a verified trust path.
- **Explicitly does not do:** confirm private-key security, internal keystore state, or full chain / trusted-root / OCSP / revocation unless supported by observed evidence — otherwise these remain `unknown`.
- **Current maturity:** **Live — founder acceptance pending**.

### 5. Cyber Essentials Readiness
- **Observes/assesses:** a 20-question readiness questionnaire (one shared set: public self-check + authenticated).
- **Detects:** readiness gaps against the externally assessable controls.
- **Verifies:** only the externally assessable evidence, never the control itself.
- **Customer-declared inputs:** questionnaire answers (**Customer-declared**), version-stamped.
- **Alerts & managed workflows:** CE readiness cases where externally assessable.
- **Evidence sources:** external observation for the assessable areas; customer attestation otherwise.
- **Known limitations:** **2 of 5** controls are externally assessable, and only partially; `access_control` and `malware_protection` are "Not externally assessable — self-attestation only".
- **Explicitly does not do:** certify Cyber Essentials (not a certification body); feed questionnaire answers into the Cyber Metrics Score or Business Risk Indicator.
- **Current maturity:** **Partial / bounded coverage** — Live within the 2-of-5 external boundary.

### 6. Website Security
- **Observes:** HTTPS, redirects, security headers, cookie-flag evidence, module completeness.
- **Detects:** missing/weak transport and header protections.
- **Verifies (Observed):** externally observable web-transport posture and its module completeness.
- **Customer-declared inputs:** the site/domain in scope.
- **Alerts & managed workflows:** website-security alerts; managed cases with re-check verification.
- **Evidence sources:** external HTTP/TLS observation.
- **Known limitations:** transport/header layer only; not application-logic testing.
- **Explicitly does not do:** run DAST / active application-security testing; test authenticated app internals. See **Hard boundaries**.
- **Current maturity:** **Live — founder acceptance pending**.

### 7. Identity Exposure
- **Observes:** public login surfaces and identity-facing entry points.
- **Detects:** externally visible identity/login exposure.
- **Verifies (Observed):** the externally observable identity-facing surface.
- **Customer-declared inputs:** the domain in scope.
- **Alerts & managed workflows:** identity-exposure alerts; managed workflow.
- **Evidence sources:** external observation.
- **Known limitations:** external surface only.
- **Explicitly does not do:** credential / breach / stealer-log / dark-web monitoring; see internal identity events. See **Hard boundaries**.
- **Current maturity:** **Live — founder acceptance pending**.

### 8. Shadow IT & Unmanaged Technology
- **Observes:** externally observed SaaS, vendors, third-party scripts and unmanaged-technology signals (this is where **third-party / vendor technology** lives — not a separate domain).
- **Detects:** newly observed third-party technology; approved-inventory deviations (**Correlated** where multiple signals align).
- **Verifies (Observed):** external observation of third-party technology.
- **Customer-declared inputs:** approved-inventory classifications (**Customer-declared**).
- **Alerts & managed workflows:** Shadow IT alerts; approved-inventory comparison + correlation; managed cases.
- **Evidence sources:** external observation from scan data.
- **Known limitations:** *externally observed* ≠ *customer approved*; `approved` ≠ secure; `rejected` ≠ removed; disappearance ≠ verified removal.
- **Explicitly does not do:** internal asset discovery; CASB; full SaaS-licence visibility. See **Hard boundaries**.
- **Current maturity:** **Live — founder acceptance pending**. The standalone "Vendor Risk" / "Supply Chain Score" customer surfaces are **Retired from customer-facing claims** (queued; the honest third-party signal folds in here — underlying data preserved).

---

## Cross-cutting capabilities

- **Managed alerts** — **Live — founder acceptance pending.** All eight domains alert through one canonical pipeline (email + in-app, tenant-safe deep links, dedupe). Genuine live-event acceptance still outstanding per domain. `alerts-eight-domain-coverage.md`.
- **Cases & lifecycle** — **Live — production-verified** (mechanism). A universal state machine governs every case transition, fail-closed: terminal states are immutable, illegal jumps are refused, and a completed scan or a customer note alone never marks a case *verified*.
- **Remediation registry** — **Live — production-verified.** One registry is the source of truth for title / impact / action / effort / owner-type / verification-method / evidence per finding. Unmapped findings stay explicit — no invented advice.
- **Related Changes** — **Live — founder acceptance pending.** Deterministic correlation of independent signal families on the same domain in the same period (manual case creation only).
- **Evidence & history** — **Live — production-verified.** Append-only history; historical evidence is never destructively overwritten (inactive / archived / superseded / soft-deleted instead).
- **Reports & Executive PDF** — **Live — founder acceptance pending.** One immutable per-scan eight-domain snapshot; Executive PDF with co-brand / white-label / fallback; renderers are snapshot-native.
- **Weekly Digest** — **Live — founder acceptance pending** (acceptance = the next real Monday digest). Semantic grouping; quiet wording gated on complete scan quality.
- **MSP Portfolio (per-domain state + trend)** — **Live — founder acceptance pending**, but **currently unreachable in production**: no entitled account exercises it, so it is not sellable or demoable yet.
- **Billing & entitlements** — states separated honestly: fail-closed pricing guard + webhook + entitlement resolution are **Live — production-verified** (checkout consent + portal-only plan changes accepted in sandbox with evidence); the **live-account cutover** (live keys, portal config, real-card checkout) is **Planned** (RC); commercial terms (refund/cancellation/VAT/legal) are **Planned**.
- **Tenant isolation** — **Live — production-verified.** Every workspace read/write is membership- and role-checked; cross-tenant access is refused (static + runtime-suite verified). `SECURITY-VERIFICATION-MATRIX.md`.
- **Release & acceptance status** — engineering-complete ≠ founder-accepted ≠ live-event-proven; this register uses the status labels above to keep those distinct. Assurance state: `SECURITY-VERIFICATION-MATRIX.md`, `RELIABILITY-VERIFICATION-MATRIX.md`.

---

## Governance
Any PR that **adds, removes, expands, narrows, or changes the customer language of** a capability updates this file in the same PR — or states in the PR description why no update is needed. Enforced as a **checklist + `validate-capabilities-doc.js` drift check** (eight-domain model intact, no ninth domain, retired claims stay retired, only the allowed status labels, hard-boundary section present, no release-timeline content) — **not** a crude "file unchanged → fail" gate. See the `cybermeters-docs-governance` skill.
