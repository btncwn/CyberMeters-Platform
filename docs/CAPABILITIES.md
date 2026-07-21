# CyberMeters — Capabilities & Limitations (living document)

**Purpose:** the single, honest source of truth for **what CyberMeters can and cannot do right now**. This is a *current-state* document, not a change log — the [CHANGELOG](../CHANGELOG.md) is the authoritative release timeline; this doc says what the product *is capable of today*. Kept honest per the product's core discipline (coverage-state honesty + external-scope honesty). **A stale capability doc is worse than none** — update it in the same PR whenever an episode adds/removes/changes a capability (governance hook: `cybermeters-docs-governance`).

**Status legend:** `Live` = built + deployed + observable · `Built — pending deploy` = merged, not yet on the live Worker · `Foundation live — completion planned` · `Unreachable in prod` = built but no entitled/real account exercises it yet.

**Verification vocabulary (canonical):** *Verified / Confirmed* = CyberMeters itself observed it. *Attested* = the customer asserted it; not externally verified. These are different states and are never conflated.

---

## The eight canonical customer-facing domains

### 1. Email Protection — `Live`
- **Observes:** SPF / DKIM / DMARC records; DMARC policy journey; DMARC aggregate (RUA) reports ingested on `reports.*` MX → sending-source rollup (source_ip, reported SPF/DKIM result); sender inventory; hosted-record maturity (DMARC L1/L2/L3 scorecard).
- **Verifies (CyberMeters-observed):** SPF/DKIM/DMARC presence and configuration; DMARC posture changes; a `email_spf_changed` root-record change (catches unauthorized SPF tampering, e.g. the classic spoofing-via-SPF-edit case).
- **Built — pending deploy (#251/#252, deploy founder-gated after M7):** *include-aware* SPF authorisation-set resolution (follows include/redirect/a/mx, RFC-7208 lookup + void limits, TempError fail-safe) → detects effective-authorisation changes even when the root record is unchanged; RUA-corroborated "unauthorised sending source" signal (uses the report's own SPF-fail result as authoritative).
- **Does NOT:** read mailbox contents or internal mail flow; guarantee it knows every provider IP with no DNS/DMARC evidence (external-scope honest); derive an SPF-fail verdict it did not observe.

### 2. Brand Protection — `Live` (founder full-chain acceptance outstanding)
- **Observes:** lookalike / typosquat candidate domains (TLD-swap, keyword permutations, passive Certificate Transparency); DNS + HTTPS + login-form enrichment on candidates (a resolving lookalike with a login page = higher risk).
- **Verifies:** existence and enrichment signals of candidate domains.
- **Does NOT:** *execute* takedowns — it **prepares/tracks** takedown submissions (never "we took it down"); confirm intent of a lookalike owner.

### 3. Attack Surface — `Live`
- **Observes:** externally reachable assets, subdomains, exposure signals; ASM verification.
- **Does NOT:** scan internal networks; perform authenticated/internal scanning; exploit or penetration-test; see assets that are not externally observable.

### 4. Certificates & Trust — `Live`
- **Observes:** certificate identity, expiry, Certificate Transparency; managed certificate lifecycle (identity / replacement / coverage).
- **Verifies (external-only):** what CyberMeters re-observes externally. `external` verification support = an independent third party certifies it (neither CyberMeters' observation nor the customer's word).
- **Does NOT:** confirm private-key security, internal keystore state, full chain/trusted-root/OCSP/revocation unless supported by observed evidence — these stay `unknown` otherwise. An unexpired cert ≠ verified trust path.

### 5. Cyber Essentials Readiness — `Live`
- **Observes/assesses:** the 20-question readiness questionnaire (one shared set, public self-check + authenticated); **2 of 5** CE controls are externally assessable (only partially).
- **Does NOT:** certify Cyber Essentials (not a certification body); externally assess `access_control` or `malware_protection` — these are "Not externally assessable — self-attestation only"; feed questionnaire answers into the Cyber Metrics Score / Business Risk Indicator.

### 6. Website Security — `Live`
- **Observes:** HTTPS, redirects, security headers, cookie-flag evidence, module completeness.
- **Does NOT:** run DAST / active application-security testing; test authenticated app internals.

### 7. Identity Exposure — `Live`
- **Observes:** public login surfaces and identity-facing entry points.
- **Does NOT:** credential / breach / stealer-log / dark-web monitoring (explicitly not that); see internal identity events.

### 8. Shadow IT & Unmanaged Technology — `Live`
- **Observes:** externally observed SaaS, vendors, third-party scripts and unmanaged-technology signals; approved-inventory comparison + correlation.
- **Boundary:** *externally observed* ≠ *customer approved*; `approved` ≠ secure; `rejected` ≠ removed; disappearance ≠ verified removal.
- **Does NOT:** internal asset discovery; CASB; full SaaS-licence visibility.
- **Note:** the standalone "Vendor Risk" / "Supply Chain Score" customer surfaces are **queued for retirement** — folding the honest signal here (`docs/EPISODE-vendor-supply-retirement.md`).

---

## Cross-cutting capabilities

- **Managed cases** — `Live`. Universal lifecycle across all eight domains; every transition goes through `canTransitionCase` (fail-closed state machine: terminal immutability, no illegal jump, system-only + verified-evidence rules). A completed scan or a customer note alone never marks a case *verified*.
- **Canonical remediation** — `Live`. One registry is the source of truth for title / impact / action / effort / owner-type / verification-method / evidence per finding. Unmapped findings stay explicit — no invented advice.
- **Alerts** — `Live`, 8/8 domains through the canonical pipeline (`docs/alerts-eight-domain-coverage.md`). Genuine live-event acceptance still outstanding per domain.
- **Reports** — `Live`. Immutable per-scan eight-domain snapshot; Executive PDF (co-brand / white-label / fallback). Renderers are snapshot-native.
- **MSP Portfolio (per-domain state + trend)** — `Unreachable in prod`. Built (mig 091) but no entitled account exercises it — not sellable/demoable yet.

## Hard boundaries (external-scope honesty — CyberMeters does NOT claim visibility into)
Internal networks · endpoints / employee devices · browser history · internal software inventory · leaked credentials / stealer logs / dark-web data · EDR / SIEM telemetry · internal identity events · full SaaS-licence visibility · internal CASB data. CyberMeters is external-observation, evidence-led — not a scanner/pentest/DAST/EDR/SIEM/CASB/dark-web platform.

## Assurance state (companion docs)
- Security: `docs/SECURITY-VERIFICATION-MATRIX.md` — internal Web/API verification fixture/code layer complete (A–F, no findings); release-gate items + independent pentest outstanding.
- Reliability: `docs/RELIABILITY-VERIFICATION-MATRIX.md` — code-layer delta closed; runtime (load/chaos/rollback drill) → RC.
- Claim honesty: `docs/PUBLIC-CLAIMS-TRUTH-AUDIT.md`.

## Recently changed (pointer, not a timeline)
Newest capability deltas — full detail and dates in the [CHANGELOG](../CHANGELOG.md):
- **Built — pending deploy:** Email include-aware SPF authorisation-change detection + RUA-corroborated unauthorised-source (#251/#252).
- Recently live: M7 pricing/billing lockstep (checkout consent + portal-only plan changes); eight-domain colour identity; A6 Related Changes; Shadow IT alert trust; Weekly Digest truth.

---
*Maintenance rule: any episode that adds, removes, or materially changes what the product can do updates this file in the same PR, and never claims more than the deployed, evidence-backed state (`Built — pending deploy` is not `Live`).*
