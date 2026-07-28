# CyberMeters Detection Quality Roadmap (canonical)

**Status: CANONICAL FOUNDER DECISION (21 July 2026).** This is law. It governs how every customer-facing detection capability is judged, sequenced, released, and claimed. Where any other doc conflicts on detection quality, this wins. Companion audit: `docs/DETECTION-DEPTH-AUDIT.md`.

## The two gates (kept separate)
1. **Platform Security Gate** — can CyberMeters *itself* be exploited? (largely engineering-complete: 6 CI security suites, 204+ assertions, `docs/SECURITY-VERIFICATION-MATRIX.md`.)
2. **Detection Integrity Gate** — does CyberMeters actually catch a dangerous change on the customer's domain? (**the main work now**.)

**Honest boundary:** we cannot promise an absolute "nothing will ever be missed." We promise: **no *known* critical false-negative, silent monitoring loss, or unproven customer claim is left open before public beta.**

---

## Constitution — the Detection Depth Law
For the seven customer-facing domains (Cyber Essentials Readiness excluded — it is intentionally an assessment/readiness domain), **no module is complete merely by reading a record and rendering a score.** Every meaningful capability must prove the chain:

```
real-world external change → discovery → normalisation → dependency/effective-state
resolution → historical snapshot → meaningful diff → independent corroboration →
prioritisation → event → alert → remediation/case → report → honest customer wording
```

If any link is missing, the status is **not PASS** — it is `PARTIAL`, `FAIL`, `NOT TESTED`, or `OUT OF SCOPE`.

## Immutable engineering rules
1. **Every byte must earn a customer outcome.** An engine/module that connects to none of discovery, evidence, meaningful change, prioritisation, or remediation is not a completed capability.
2. **The root record is not enough.** Resolve the effective state behind it where possible (SPF: root TXT → include chain → effective IP/CIDR authorisation set → active use in RUA). Apply the same principle to every domain.
3. **A global "scan ran" is not enough.** Each signal carries its own evidence-completeness. A missing Website module must not silence a reliable SPF diff forever — and incomplete evidence must never produce a false alert. Target: **per-signal evidence completeness + global scan honesty.**
4. **Detection ≠ maliciousness.** "New certificate observed / IDN lookalike found / new SPF sender authorised" is sayable. "Attacker / phishing / compromise / malicious sender" requires additional evidence.
5. **Every critical capability passes four proofs:** deterministic fixture · mutation proof · end-to-end pipeline trace · founder-controlled live acceptance.
6. **Public copy states only the live-proven level.** `implemented` / `merged` / `deployed` / `live-accepted` are never conflated.

## Release & claim status ladder
Every capability is tagged with exactly one: `DISCOVERED` · `DESIGNED` · `IMPLEMENTED` · `CI-PROVEN` · `MERGED` · `DEPLOYED` · `LIVE-ACCEPTED` · `CUSTOMER-CLAIM-APPROVED`. **`MERGED` never substitutes for `LIVE-ACCEPTED`.** Public claims require `LIVE-ACCEPTED` (and `CUSTOMER-CLAIM-APPROVED` for marketing).

---

**Scenario-level feasibility (separate, founder-directed, post-backlog):**
`docs/SCENARIO-DETECTION-FEASIBILITY-PROGRAMME.md` — sensor inventory → phishing scenario feasibility →
ransomware entry-path feasibility → historical backtest → false-positive measurement → founder GO/NO-GO.
It obeys this Law: a missing link is PARTIAL/FAIL/NOT TESTED, never PASS, and NO-GO is a legitimate outcome.

## Phases

### Phase 0 — Detection Availability Foundation (P0/P1: Chronic Partial Scan) — ACTIVE
Find blackbullbarbers.co.uk's seven incomplete modules; explain why it has been `partial` since 2026-07-18 (budget headroom present); measure the real blast radius behind the complete-gate across other domains; verify how monitoring degradation is disclosed to the customer; fix any deterministic bug.
**Exit:** root cause proven · complete scans reproducible OR a safe per-signal design ready · monitoring never silently disappears · SPF production acceptance repeatable. **No other engine's "live" acceptance completes until this closes.**

### Phase 1 — Brand Protection Hardening
- **PR-A (IDN/Unicode homograph core):** IDNA/punycode round-trip · NFC · script detection · bounded UTS #39-inspired product-policy skeleton (not complete UTS #39) · mixed-script · brand skeleton comparison · legitimate-IDN FP guards · deterministic fixtures · mutation tests.
- **PR-B (discovery + prioritisation):** deterministic IDN candidate generation · passive CT/SAN punycode discovery · eTLD+1 · DNS/MX/HTTP/TLS activity · nested `login`/`password`/`m365`/`office365` · redirect/login-surface evidence · severity weighting · fail-honest copy.
- **PR-C (campaign + lifecycle):** infrastructure reuse · campaign clustering · reappearance · evidence history · alert/case/takedown lifecycle · report/PDF.
- **Exit gate — no strong claim until tested:** Cyrillic/Greek confusable · mixed-script · whole-script confusable · raw punycode input · CT-discovered IDN · DNS-active/HTTP-inactive · login-active lookalike · removed/reappeared lookalike · legitimate-international-domain FP control. (Design ready: `docs/DETECTION-DEPTH-AUDIT.md §15`.)

### Phase 2 — Attack Surface Integrity
Not "done" because takeover + KEV exist. Audit+implement: canonical asset identity · same-hostname IP/service change · DNS→IP→ASN/provider shift · origin exposure behind CDN/WAF · port open/close/reappearance · fingerprint confidence · version→CVE applicability · CVE→KEV correlation · admin/login surface · ephemeral assets · stale evidence · Cloudflare 52x/530 vs real exposure · multi-signal Related Changes.
**Exit gate:** every CVE claim carries fingerprint evidence, applicability confidence, evidence timestamp, and an FP boundary.

### Phase 3 — Certificates & Trust Integrity
CT monitoring confirmed to exist; now test the whole pipeline: unexpected issuer/SAN · wildcard expansion · parallel certificate · CAA drift · active-service↔CT correlation · old cert still served · renewal overlap/gap · churn · hostname mismatch · trust path · renewal remediation.
**Boundary:** no OCSP/revocation/full-chain claim unless validated.

### Phase 4 — Email Protection full depth
SPF is the reference model (deployed; live acceptance after Phase 0; controlled child-include fixture; RUA natural corroboration). Extend depth to **DKIM** (selector discovery/add/remove, key rotation, weak/missing key, same-selector key change, provider migration) · **DMARC** (policy weakening, `pct`, alignment, `rua`/`ruf` destination change, external reporting delegation, report volume/source behaviour, enforcement-vs-outcomes) · **MX/MTA-STS/TLS-RPT** (provider migration, MX priority, stale/unknown MX, MTA-STS weakening, TLS-RPT endpoint change, fetch failure, cross-signal correlation).
**Exit gate:** effective sender-and-policy change intelligence, not a "record exists" checker.

### Phase 5 — Website Security depth
No full-DAST claim; build real change intelligence: CSP dependency graph · third-party scripts · form actions · redirect chains · cookie scope · Secure/HttpOnly/SameSite · header weakening · mixed content · login/checkout/admin surfaces · JS dependency first-seen/reappeared · sensitive-page placement · Shadow IT correlation.

### Phase 6 — Shadow IT & Unmanaged Technology
Vendor Risk / Supply Chain stay retired as standalone claims, consolidated here. Depth: canonical vendor identity · exact source attribution · approved inventory · owner · purpose · first-seen/removed/reappeared · affected domain/page · sensitive surface · dependency category · evidence source · remediation lifecycle. **The Stripe owner-missing incident becomes a permanent regression fixture.**

### Phase 7 — Identity Exposure (highest overclaim risk)
Allowed: externally observable login/SSO surfaces · new/reappeared auth endpoint · provider/tenant change · forgotten auth hostname · certificate/DNS correlation · Brand-lookalike correlation · externally exposed identity config. **Forbidden without evidence:** leaked credentials · breached employees · dark-web exposure · account compromise · user monitoring.

### Phase 8 — Cross-Domain Correlation (the real moat)
Deterministic detection decides; AI only explains. Same-time-window is not causation. Expected/unexpected customer feedback kept separate. Correlation confidence shown. One event must not fan out into noise. (E.g. new IDN + CT cert + login surface + M365 keyword + same ASN = one high-priority Brand campaign Related Change.)

### Phase 9 — Adversarial Detection Test Lab
Systematise EngineTestLab per domain: golden/negative/false-positive fixtures · mutation corpus · live-safe controlled fixtures · competitor-inspired scenarios · historical regression · incomplete-evidence cases · timeout/dependency-failure cases. Mandatory mutations: disable dependency resolution → red · weaken normalisation → red · remove tenant attribution → red · corrupt completeness guard → red · raise severity → evidence-wording red · remove dedupe → duplicate-event red.

### Phase 10 — Competitor Parity Program
Ten competitors compared not by marketing page but by: their public evidence · our code evidence · fixture evidence · production deployment · live acceptance · SMB necessity · (if parity unneeded) the reason · our lifecycle advantage. Not to copy every feature — but **forbidden:** a competitor has a critical, common, harm-preventing capability we lack and the audit missed it.

---

## Aggressive implementation order
**Now:** 1) Chronic-partial root cause → 2) fix/deploy → 3) complete-scan restore → 4) SPF root-change acceptance → 5) SPF child-include live fixture.
**Then:** 6) Brand IDN PR-A → 7) PR-B → 8) Brand live acceptance.
**Three quality sprints:** 9) ASM depth → 10) Certificates depth → 11) Email remaining depth.
**Then:** 12) Website → 13) Shadow IT → 14) Identity → 15) cross-domain correlation → 16) competitor-parity closure → 17) pentest/retest → 18) go-live website conversion → 19) controlled first paying customer → 20) public beta.

*Web design is not forgotten — but we do not paint a weak, unproven product beautifully and sell it. Design advances alongside the detection-truth baseline.* New ideas do not arbitrarily reorder this; only a P0/P1 with proven wider customer harm jumps the queue.

## Mandatory before public beta
chronic-partial monitoring integrity · Brand IDN PR-A/B + live acceptance · ASM high-impact depth · Certificates CT/active-service lifecycle · Email effective-state change validation · Website sensitive-surface dependency changes · Shadow IT attribution/owner lifecycle · Identity bounded external-surface workflow · cross-domain dedupe/correlation · independent scoped pentest + retest · claims audit · first-customer end-to-end acceptance.

## Companion gate — Protocol Standards Conformance (canonical, 21 July 2026)
A distinct axis from detection depth: depth asks "do we catch the change?"; conformance asks "do we parse/evaluate the standard correctly per its MUST / MUST NOT / SHOULD?". **We may NOT stamp the product "RFC compliant" today.** Many modules are RFC-*aware*; full conformance is proven per module, per RFC clause, with fixtures + mutations. Honest per-module wording (e.g. "RFC 7208-aware SPF resolution", NOT "fully RFC 7208 compliant SPF evaluator") until proven.

**Per protocol-backed module, the audit answers:** (1) which RFC/standard applies; (2) which *current* version (watch for supersession); (3) which MUST/MUST-NOT/SHOULD apply to us; (4) what is deliberately out-of-scope; (5) golden fixtures? (6) malformed-input fixtures? (7) mutation tests? (8) parser↔customer-wording consistency; (9) a drift detector for when the standard updates; (10) exactly what level the claim states.

**Verified RFC baseline (confirm currency at audit time):**
| Area | Standard | Note |
|------|----------|------|
| SPF | RFC 7208 | resolver is 7208-*aware*; full evaluator conformance not yet proven |
| DKIM | RFC 6376 (+ updates) | v=DKIM1 position, empty `p=`(revoked), unknown-tag ignore, RSA length, **Ed25519**, TXT folding, selector rotation |
| **DMARC** | **RFC 9989 (core) + 9990 (aggregate) + 9991 (failure) — DMARCbis, published May 2026, OBSOLETES RFC 7489 + 9091** (verified) | **Concrete drift risk:** DMARCbis removed `pct` and moved org-domain discovery from PSL → DNS **tree walk**. Our parser likely reflects 7489 → **must re-audit** |
| MTA-STS | RFC 8461 | `_mta-sts` TXT, `v=STSv1`, policy file at `.well-known`, mode/mx/max_age, HTTPS+content-type, redirect, stale `id`, unavailable host |
| TLS-RPT | RFC 8460 | separate conformance audit |
| IDNA | RFC 5890–5895 (+ Unicode UTS-46/TR39 — a Unicode security standard, not an RFC) | A-label/U-label, invalid punycode, disallowed code points, bidi, normalisation, mixed-script, eTLD+1 |
| X.509 / CAA / CT / TLS | RFC 5280 etc. | we do CT/metadata analysis, NOT full path/chain/OCSP validation — never claim RFC 5280 full path validation |
| HTTP / security headers | RFC 9110 family (+ CSP/HSTS/cookie separate standards) | directive grammar + inheritance, not just "header present" |

**Two separate gates for protocol modules:** *protocol conformance* AND *detection accuracy* (a correctly-parsed banner with a wrong CVE mapping is still a product defect).

**Audit order:** 1) SPF RFC 7208 · 2) **DMARC RFC 9989/9990/9991 migration** · 3) DKIM RFC 6376 + updates · 4) MTA-STS RFC 8461 · 5) TLS-RPT RFC 8460 · 6) IDNA RFC 5890–5895 · 7) X.509/CAA/CT · 8) HTTP/security-header. Interleaves with the detection phases (each protocol audit sits alongside its domain phase; DMARCbis migration is a real Email-phase work item, not cosmetic).

## Founder gate — the report at every episode end
1. the real harm that could reach the customer;
2. whether CyberMeters catches it right now;
3. exactly where the pipeline breaks;
4. the small PR sequence + live acceptance needed to close it.
**"118 modules exist", "tests green", "engine present" are NOT, on their own, success.**

## Canonical founder decision
> CyberMeters ships **no** customer-facing domain (except Cyber Essentials Readiness) at a surface-only posture-checker level. Each domain must, where possible, provide dependency-aware effective-state resolution, historical change intelligence, independent corroboration, evidence-backed prioritisation, and managed remediation. No **known** critical false-negative, silent monitoring loss, or unproven security claim may be left open before public beta.

## Engineering oath
**Every byte must earn its customer outcome.**
