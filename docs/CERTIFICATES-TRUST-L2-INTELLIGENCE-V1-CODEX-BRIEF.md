# Codex Build Brief — Certificates & Trust: L2 Guided Trust Remediation v1

**Decision owner:** Turhan · **Queued:** 2026-07-13 · **Author of brief:** Claude (Lead Eng / review-integrate)
**Operating model:** Codex builds · Claude reviews + integrates + validates + deploys · Turhan decides
**Risk tier:** MEDIUM (additive migrations at most + new engine/routes/UI). Additive & reversible only.

---

## 0. Goal (L2 only)

Take Certificates & Trust from **Level 1 (CT-only monitoring)** to **Level 2 (Guided Trust
Remediation)**: turn today's free-text certificate signals into **explainable, evidence-backed
findings** with **renewal readiness**, an **honest trust-path assessment**, formalised
**issuer/SAN/wildcard/parallel-certificate anomalies**, **historical events**, and **evidence-based
remediation guidance** — all computed from what CyberMeters can actually observe (Certificate
Transparency + HTTP redirect + HSTS + expiry), never from data it does not have.

This brief is **L2 scope only**. Managed renewal, deployment verification, a live TLS prober, etc.
are explicitly **out of scope** (§3).

---

## 1. Current state — audited (file:line, verify before building)

**Hard constraint — CT-only, no TLS handshake.** `workers/scan-api/src/engines/ssl-scan.js:76-78`:
"Workers cannot inspect TLS handshake details on outbound fetch() calls, so we query crt.sh for the
most recently issued valid certificate." Sources: crt.sh (`ssl-scan.js:93`) + certspotter fallback;
on crt.sh failure the scan completes with cert data omitted (`ssl-scan.js:140`). **Consequence:
everything below is CT metadata + HTTP-level observation, NOT what the server actually serves in a
handshake.**

**Persistence.** `certificate_observations` (migration `031-certificate-intelligence-v2.sql:14`):
`id, workspace_id, domain_id, scan_id, certificate_key, subject, issuer, san_count, expires_at,
first_seen, last_seen, evidence_json`, `UNIQUE(workspace_id, domain_id, certificate_key)`, indexed on
`(ws,last_seen)`, `(ws,domain_id,last_seen)`, `(ws,issuer,first_seen)`. This is the cross-scan cert
timeline — a genuine L2 spine.

**Cross-scan anomaly events (already real).** `workers/scan-api/src/engines/cert-events.js` —
`upsertCertificateObservation` (`:131`) diffs the per-cert surrogate and emits `asset_events`:
`certificate_new_detected` (`:257`), `certificate_new_issuer_detected` (`:275`),
`certificate_new_san_detected` (`:294`). `insertCertificateEvents` (`:24`). CA-owner feeds vendor
risk. **Keep and formalise these — do not re-invent.**

**Intelligence + honesty discipline.** `workers/scan-api/src/engines/cert-intel.js` builds
`suspicious_certificate_signals` (`:134`): `no_https`, `certificate_expiring_critical/soon`,
`wildcard_dns_detected`, `shared_certificate_observed`, `sensitive_hosts_in_ct`,
`high_subdomain_growth`, `ct_source_discrepancy`, `ct_sources_unavailable`, plus a
`certificate_risk_level`. Absence of data reads as **"unknown", never "low"** — preserve this.
`cert-analysis.js`: `normalizeCertificateIssuer` (`:52`), `mapCertificateAuthorityOwner` (`:75`),
`buildCertificateLifecycleIntelligence` (`:149`, currently only a days→band mapper), CA-concentration.

**Routes.** `workers/scan-api/src/routes/attack-surface.js:754` `GET /api/workspaces/:id/certificates`
(latest cert intel per domain) and `:760` `GET /api/workspaces/:id/certificates/timeline` (cert
`asset_events`, last 90 days). Frontend: `frontend/src/pages/ws/CertificatesPage.jsx`.

**Honesty gaps to FIX by telling the truth (not by fabricating):**
- **Crypto metadata is structurally always "unknown".** `cert-analysis.js:119-124`
  `extractCertificateCryptoMetadata` reads `ssl.cert_key_algorithm` / `key_size_bits` /
  `signature_algorithm` — the CT-only scanner never sets those, so `unknownIfEmpty(...)` always
  yields `"unknown"` (surfaced at `cert-intel.js:263-265`, fallback `:301-307`). A repo-wide search
  finds **no code path that ever assigns a real value**. → L2 must keep these **"unknown"** and must
  NOT invent a weak-key/weak-signature finding (there is no key data). Only a future external TLS
  prober (out of scope) can populate them.
- **Chain validity / root trust / intermediate completeness / OCSP / revocation are absent** — no
  handshake, no chain. → keep **"unknown"**, never assert a `chain_valid` boolean.
- **Frontend implies a chain check it never does.** `CertificatesPage.jsx:26` `const valid =
  row.valid ?? row.chain_valid` — the backend never computes either, so it is always `undefined` →
  renders "Unknown" (`:29`), and the **"Broken HTTPS" stat is always 0** (`:160`), which *implies*
  we validate chains. → L2 must replace this fake boolean with an **honest structured trust-path
  posture** (what we DO know) and label the rest **"unknown"**.

---

## 2. Scope — IN (L2 Guided Trust Remediation v1)

1. **Explainable certificate findings** — a typed classification with evidence + reasons +
   confidence, replacing free-text signals.
2. **Renewal readiness** — real assessment, not just "N days left".
3. **Trust-path assessment** — honest, from observable signals only.
4. **Unexpected issuer / SAN / wildcard / parallel-certificate anomalies** — formalised from the CT
   history.
5. **Historical events** — the cert timeline, enriched for findings.
6. **Evidence-based remediation guidance** — platform-aware where knowable.
7. **Tenant isolation** on every read/write.
8. **Additive migrations** (only if persistence is needed) + **CI harnesses**.

## 3. Scope — OUT (do NOT build; hard exclusions)

- **External TLS prober** / any live TLS handshake.
- **Managed renewal**, **certificate deployment**, **edge consistency**, **revocation automation**.
- **Private-key handling** of any kind.
- Do NOT fabricate `key_size_bits`, `signature_algorithm`, chain validity, OCSP/revocation status, or
  any **live deployment** data. **A CT-observed certificate is NOT proof it is deployed/served** — do
  not present CT issuance as "the live certificate". Unsupported values are **`"unknown"`**, always.

Keep v1 tight. This is the honest-intelligence layer over CT + HTTP observation, not a TLS engine.

---

## 4. Data model

Prefer **compute-on-read** from `certificate_observations` + the fresh CT/HTTP scan data — no new
table is required for findings/renewal/trust-path. `certificate_observations.evidence_json` already
exists for enriched per-cert signals. **If** persistence is genuinely needed (e.g. to remember an
analyst/customer "acknowledged"/"expected issuer" decision so an anomaly stops re-alerting), add an
**additive** migration `078-...` (enum-in-code, NO CHECK, `WORKSPACE_PURGE_TABLES` updated
child→parent). Do not add columns for crypto/chain data that cannot be populated.

---

## 5. Engine work

Put new logic in `engines/cert-analysis.js` / `cert-intel.js` (or a new `engines/cert-findings.js`);
reuse `normalizeCertificateIssuer` / `mapCertificateAuthorityOwner` / the CT data. Every output
carries `{ status|level, confidence, reasons[], evidence[], observed_via }` and marks anything
unverifiable as `"unknown"`.

**a. Explainable findings** — a typed enum (in code, no CHECK):
`expiring_soon | expired | self_signed | unexpected_issuer | unexpected_san | unexpected_wildcard |
parallel_certificate | coverage_gap | ct_source_incomplete | unknown`. Each finding =
`{ type, severity, confidence, title, reasons[], evidence[], observed_via: "ct" | "http" | "history",
remediation[] }`. Do NOT emit `weak_key` / `weak_signature` / `untrusted_chain` / `revoked` — no data
source for them (they'd be fabrication). `hostname_mismatch` may only be asserted if a real observed
signal supports it (e.g. the SANs from CT do not cover the scanned host) — otherwise `unknown`.

**b. Renewal readiness** — `{ status: healthy|warning|critical|unknown, days_remaining,
auto_renew_observed: bool|null, ca_provider, recent_reissue_observed: bool, blockers[],
recommended_actions[] }`. Derive `auto_renew_observed`/`recent_reissue_observed` from the CT issuance
cadence already in `certificate_observations` (a fresh cert issued before the prior expired ⇒ renewal
observed). `ca_provider` from `mapCertificateAuthorityOwner`. Never claim auto-renew is configured —
only that a reissue **was observed** (or `null`).

**c. Trust-path assessment (honest)** — `{ https_reachable: bool|unknown, redirect_to_https:
bool|unknown, hsts_present: bool|unknown, expiry_ok: bool|unknown, chain_valid: "unknown",
root_trusted: "unknown", ocsp: "unknown", reasons[] }`. Populate the first four from what the scan
already observes (HTTP redirect check in `ssl-scan.js`, HSTS in `scoring.js`, expiry from CT);
`chain/root/ocsp` stay **`"unknown"`** with a one-line note that they require a live TLS handshake
(not performed). This directly replaces the frontend's fake `valid ?? chain_valid` boolean.

**d. Anomalies** — formalise the existing `certificate_new_issuer_detected` /
`certificate_new_san_detected` into `{ type: unexpected_issuer|unexpected_san|unexpected_wildcard|
parallel_certificate, confidence, evidence[], first_seen, prior }`, anchored on
`certificate_observations` history. ADD: **unexpected_wildcard** (a wildcard cert newly covering the
host) and **parallel_certificate** (≥2 currently-valid certs for the same host from **different
issuers** in CT — a real misissuance/impersonation signal, fully observable in CT). Label confidence
honestly; a new issuer alone is `suspicious`, not `confirmed`.

**e. Historical events** — reuse the `certificate_*` `asset_events` timeline (`cert-events.js`); the
findings reference the relevant events. No parallel event system.

**f. Remediation guidance** — evidence-based, platform-aware where the CA/host hints allow
(Let's Encrypt/ACME, Cloudflare, generic). Separate **observation** from **inference** in the copy;
never assert a cause we did not observe.

---

## 6. Routes + frontend

- Extend `GET /api/workspaces/:id/certificates` to return, per domain: `findings[]`,
  `renewal_readiness`, `trust_path`, `anomalies[]` (additive to the current payload — keep existing
  fields). Keep `/certificates/timeline`. Tenant-scoped + role-gated exactly as the current handler
  (`attack-surface.js:754+`).
- `CertificatesPage.jsx`: replace the misleading `valid ?? chain_valid` "Secure/Broken/Unknown" and
  the always-0 "Broken HTTPS" stat with the honest **trust-path posture** + a findings list +
  renewal-readiness + anomalies. Anything unverifiable renders a clear **"Unknown — requires live TLS
  inspection (not performed)"**, never a green "Secure" we can't back.

---

## 7. Guardrails (non-negotiable)

- **Honesty first:** unsupported = `"unknown"`; never fabricate key/chain/OCSP/deployment; CT ≠ live
  deployment. This is the whole point of L2 here.
- **Additive migrations only** (if any); enums in code (no CHECK); new tables (if any) in
  `WORKSPACE_PURGE_TABLES` child→parent.
- **Tenant isolation** on every query (`workspace_id` scoped + bound params).
- **Do not break** the existing cert inventory, `certificate_observations`, the cert `asset_events`,
  CA-concentration/vendor-risk feed, or DMARC/ASM/Brand. Customer-safe copy; `serverError`
  sanitisation.
- No new outbound source beyond the existing CT/HTTP the scanner already uses (no TLS handshake).

---

## 8. Validation (CI-blocking, Node 24+, mirror existing `validate-*.js`)

`validate-cert-trust-l2.js` proving:
1. Findings are typed + carry evidence/reasons/confidence; `weak_key`/`untrusted_chain`/`revoked` are
   **never** emitted (no data source).
2. Crypto + chain + OCSP fields are **`"unknown"`**, never a fabricated value.
3. Renewal readiness: expiry bands + `auto_renew_observed`/`recent_reissue_observed` derived from CT
   history; never claims configured auto-renew.
4. Trust-path: observable dims populated; `chain_valid`/`root_trusted`/`ocsp` = `"unknown"`.
5. Anomalies: new-issuer / new-SAN / unexpected-wildcard / parallel-certificate from history; a lone
   new issuer is `suspicious`, not `confirmed`.
6. Tenant isolation: foreign workspace cannot read another's certificate findings/timeline (extend
   `validate-tenant-isolation.js`).
7. Full gate green: regression, migrations (if any), pipeline, cron, frontend build/typecheck/test,
   `wrangler deploy --dry-run`. No regression to DMARC/ASM/Brand harnesses.

---

## 9. Definition of Done

For a real scanned domain, the customer sees: explainable cert findings (with evidence), an honest
renewal-readiness read, a trust-path posture that is **truthful about what is and isn't known**,
issuer/SAN/wildcard/parallel anomalies from history, and remediation guidance — with **every**
unverifiable dimension clearly labelled "unknown / requires live TLS inspection (not performed)", and
**no** fabricated key/chain/OCSP/deployment claim anywhere. Positioning after: **"Guided certificate
& trust remediation"** (not "managed" — no renewal/deployment).

---

## 10. Handoff

Codex builds on `feat/certificates-trust-l2-v1` off current main, opens a PR, and **does not deploy**.
Claude reviews (honesty rules first — no fabricated values; scope discipline; tenant isolation;
no DMARC/ASM/Brand regression), integrates, and deploys under the standing MEDIUM-risk delegation.
