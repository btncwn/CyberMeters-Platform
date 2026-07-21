# Seven-Domain Detection-Depth & Competitor-Parity Audit

Read-only product-owner audit. No runtime/frontend/deploy/data changed. **Iteration 1** — this pass establishes the verified engine inventory, the depth law, a code-grounded L1/L2/L3 map, the *verified* gap register, a competitor-parity frame, and the remediation roadmap. The exhaustive ≥15-scenario-per-domain full-pipeline trace is explicitly marked as continuing work: fabricating traces not yet verified would violate this audit's own honesty rule. Where a capability is not traced end-to-end, it is recorded **NOT TESTED**, never assumed.

## 1. Executive truth summary
- **Verified engine inventory: 118 engine modules** (`workers/scan-api/src/engines/*.js`) — the earlier "26/27" figure is superseded.
- Two initial hypotheses were tested against the *full* module set (not a single file): **Brand IDN/Unicode-homograph detection — CONFIRMED GAP.** **Certificates CT-issuance monitoring — hypothesis DISPROVEN** (it exists in `cert-intel.js` / `cert-trust-l2.js` / `cert-events.js`; my first-pass claim over cert-analysis/lifecycle alone was wrong and is retracted).
- **Email Protection is the deepest domain** (SPF include-aware — engineering-complete/deploy-pending; DMARC change workflow; DKIM/MTA-STS/TLS-RPT). **No domain is "surface-only"**, but each has candidate L2/L3 deepenings.
- **The one confirmed customer-facing FAIL** this pass: a registered IDN homograph lookalike (e.g. Cyrillic `аpple.com` → `xn--pple-43d.com`) is missed by BOTH Brand paths. That is a real phishing blind spot.
- No P0 that makes the *current* production service actively harmful was found. (SPF include-aware is deploy-pending, correctly labelled, not a live over-claim.)

## 2. Verified engine/module inventory (118)
By area (representative, not exhaustive): **Email** email-analysis, email-intel, email-scan, dmarc-{state,impact,change-workflow,canonical-consumers}, hosted-dmarc, rua-routing, spf-resolver, spf-corroboration · **Brand** brand-{typosquat,protection,dns-enrichment,http-enrichment,passive-discovery,cases,case-machine} · **ASM** asset-{intel,inventory,alerts,alert-delivery,persistence}, discovery-scan, subdomains-scan, takeover-scan, tech-scan, dns-scan, whois-scan, reserved-scan, cloud-storage-scan, scan-budget · **Cert** cert-{analysis,intel,events,trust-l2}, certificate-{lifecycle,policy} · **Website** headers-scan, ssl-scan, website-security-{lifecycle,cases} · **Identity** identity-{scan,exposure,lifecycle,policy} · **Shadow IT** shadow-it-inventory (+ retired-internal vendor-{risk,signatures,relationship}, supply-chain) · **Cross-cutting** posture-events, related-changes(+rules,adapter), alerts/alert-{gate,occurrence,outcomes,consumers}, managed-case-model, case-workflow, remediation-registry, current-posture, posture-scoring, historical-scan.

## 3. Detection Depth Law
No capability is customer-ready merely for reading a first-layer record or rendering a score. Every capability is classified:
- **L1 — Surface observation:** record exists, port open, cert expiry, script observed.
- **L2 — Effective-state resolution:** dependency/include chains, canonical asset identity, CT/SAN relationships, redirect chains, service fingerprint, resolved authorisation set.
- **L3 — Corroborated behavioural/change intelligence:** resolved-set change + observed use, multi-signal campaign, reappearance, expected-vs-unexpected classification, managed remediation.
A domain holds mixed levels; each capability is judged on its own.

## 4. Seven-domain L1/L2/L3 map (code-grounded, first pass)
| Domain | L1 | L2 | L3 | Verdict |
|--------|----|----|----|---------|
| Email | SPF/DKIM/DMARC presence | SPF include-aware resolved set (deploy-pending); DMARC policy journey; MTA-STS/TLS-RPT | DMARC change workflow; SPF+RUA corroboration (deploy-pending) | **Deepest**; candidate gaps §6 |
| Brand | typosquat candidates | DNS/HTTP/login enrichment; passive CT discovery | reappearance; risk scoring | **L2**, one confirmed L2 gap (IDN) |
| ASM | subdomain/port/service presence | canonical asset identity; takeover (dangling DNS); tech fingerprint | KEV module; Related Changes | **L2/L3**; candidate gap: version→specific-CVE |
| Cert | expiry; self-signed | CT ingestion (crt.sh+certspotter); SAN/wildcard/issuer; coverage | unexpected-issuer/SAN/parallel-cert; managed lifecycle | **L2/L3**; honest limit: no OCSP/chain (disclaimed) |
| Website | header presence | CSP strength; HSTS/XFO/cookie flags | website-security lifecycle/cases | **L2**; candidate gap: third-party-script change graph |
| Identity | exposed login surface | OWA/VPN/RDP/SSO classification; impersonation infra | identity lifecycle | **L2**; candidate gap: new/reappeared-surface change intel |
| Shadow IT | observed vendor/SaaS/script | canonical item per product; classification/ownership | approved-inventory diff; first-seen/reappeared/removed lifecycle | **L2/L3**; candidate gaps: source attribution precision |

## 5. Scenario matrix (representative; full ≥15/domain is the deepening pass)
Format: scenario → verdict. **PASS** deterministic end-to-end · **PARTIAL** layers exist, customer outcome incomplete · **FAIL** realistic change missed · **NT** code suggests support, no fixture/live evidence traced this pass.
- **Email:** root SPF edit → PASS (live `email_spf_changed`); include-chain IP add (root unchanged) → PARTIAL (engine built, **deploy-pending**); DMARC p=reject→p=none weakening → NT (dmarc-change-workflow exists, not traced); DKIM selector/key rotation → NT; rua= reporting-destination change (hijack signal) → NT; MTA-STS/TLS-RPT downgrade → NT.
- **Brand:** ASCII typo (paypa1) → PASS; **IDN homograph (Cyrillic аpple / xn--) → FAIL** (§6.1); lookalike with MX (can-send-spoof) → PARTIAL (MX enrichment exists); nested credential host (office365-login.brand.co) → PASS (passive CT + generator); reappearance of a taken-down lookalike → NT.
- **ASM:** subdomain takeover (dangling CNAME) → PASS (takeover-scan, P1); disclosed server version → PASS (disclosure finding); **disclosed version → specific applicable CVE** → NT/candidate FAIL (§6.2); hostname constant, service/ASN changes → NT; new admin/login surface appears → NT.
- **Cert:** cert expiring → PASS; unexpected issuer on domain (CT) → PASS; unexpected wildcard/SAN → PASS; parallel/unknown cert in CT → PASS; revocation/OCSP/chain validity → OUT OF SCOPE (honestly disclaimed "requires live TLS").
- **Website:** CSP weakened to unsafe-inline/wildcard → PARTIAL (strength classified; change-over-time NT); new third-party script appears → NT/candidate; cookie scope/flag weakening → NT; HSTS removed → PARTIAL.
- **Identity:** exposed VPN/RDP/OWA present → PASS (classification); *newly* exposed login surface vs last scan → NT/candidate; SSO tenant/provider change → NT.
- **Shadow IT:** new SaaS/vendor observed → PASS; approved→reappeared-after-removed → PARTIAL (lifecycle exists); exact source attribution of a script → NT; sensitive-surface placement → NT.

## 6. Verified PASS/PARTIAL/FAIL register (this pass)
### 6.1 Brand — IDN/Unicode homograph — **FAIL (confirmed)**
- **Harm:** an attacker registers a visually-identical IDN lookalike (Cyrillic/Greek confusables) and phishes the customer's users; CyberMeters stays silent.
- **Code evidence:** `brand-typosquat.js` `TYPOSQUAT_HOMOGLYPHS` is ASCII-only (`l→1`, `o→0`); no `xn--`/punycode/Unicode-confusable generation. `brand-protection.js` `brandSimilarityScore` does `.replace(/[^a-z0-9]/g, "")` and never `toUnicode`-decodes punycode, so a CT-discovered `xn--pple-43d.com` scores as `xnppled` ≠ `apple` → not matched. Both the generator path and the passive-CT path miss it.
- **Missing link:** punycode decode + Unicode-confusable (whole-script + mixed-script) normalisation before matching; optional IDN candidate generation.
- **False-positive risk:** legitimate non-Latin brands; internationalised domains a customer legitimately owns → must exclude the customer's own registered IDNs and score confusable-distance, not raw presence.
- **Minimum defensible fix:** decode `xn--` in normalisation; a confusable-skeleton match (Unicode TR39) against the brand; flag only mixed-script or whole-script confusables above a distance floor.
- **Regression fixture / mutation:** fixture asserting `xn--pple-43d.com` matches brand `apple`; mutation = drop the punycode-decode → the match test reddens.
- **Live-acceptance:** founder registers/observes a benign IDN of a founder brand in CT; confirm a candidate is raised.
- **Public-claim boundary:** until fixed, do not claim "detects homograph/IDN lookalikes".

### 6.2 ASM — version→specific-CVE applicability — **candidate PARTIAL (NOT fully traced)**
- Version *disclosure* is detected and a KEV module exists, but this pass did **not** confirm the disclosed version string is matched to *specific applicable CVEs* (CPE/semver range). If absent, CyberMeters says "version exposed" where EASM competitors say "version X.Y is vulnerable to CVE-Z". **Marked NT** — verify `asset-intel.js` KEV correlation depth before ranking.

### 6.3 Certificates — CT-issuance monitoring — **PASS (hypothesis retracted)**
- `cert-intel.js`/`cert-trust-l2.js`/`cert-events.js` ingest CT (crt.sh + certspotter) and raise `unexpected_issuer`, `unexpected_san`, `unexpected_wildcard`, `parallel_certificate`, `ct_source_incomplete`. Unauthorised-issuance *signal* exists. Honest limit (disclaimed, not a gap): no OCSP/revocation/chain-path validity — "requires live TLS".

## 7. Ten-competitor parity matrix (first pass; "not publicly verified" where private)
Categories: broad EASM/ratings · email specialists · brand specialists · cert/CT specialists · SMB.
| # | Competitor | Category | Their documented strength | CyberMeters equivalent | Parity necessary for our SMB/MSP target? |
|---|-----------|----------|---------------------------|------------------------|------------------------------------------|
| 1 | UpGuard | broad EASM/ratings | continuous EASM + vendor risk + ratings | partial (external posture; no rating-as-product) | differentiate on lifecycle, not ratings |
| 2 | SecurityScorecard/Bitsight | ratings benchmark | third-party security ratings | intentionally not a rating product | not necessary (benchmark, not competitor) |
| 3 | Attaxion | EASM challenger | asset discovery breadth + CVE mapping | takeover+KEV yes; version→CVE depth NT | version→CVE matters (§6.2) |
| 4 | Intruder | SMB vuln scanning | authenticated+external vuln scans | external only (no auth vuln scan) | bounded — we are not a vuln scanner |
| 5 | Valimail | email specialist | full sender governance + SPF/DMARC enforcement + auto | detect/explain/correlate, not manage/rewrite | NOT parity — different product class |
| 6 | Red Sift (OnDMARC/Brand/Certs) | email+brand+cert | dynamic SPF, brand+CT monitoring | SPF change-intel (deploy-pending), CT yes | partial; IDN gap §6.1 |
| 7 | EasyDMARC/Dmarcian | SMB email | DMARC reporting + SPF/DKIM management | RUA ingest + change intel | close on detection; not on management |
| 8 | ZeroFox/Bolster/PhishLabs | brand/phishing | takedown execution + IDN/homograph + campaign | prepare/track takedown; IDN gap | IDN parity matters (§6.1); takedown-exec intentionally not us |
| 9 | Censys/Hardenize | cert/CT + host | CT + trust posture + config | CT + issuer/SAN/wildcard | reasonable parity; OCSP/chain is our disclaimed limit |
| 10 | Deepinfo / SURFACEMON | TR/EMEA EASM | surface discovery scoring | eight-domain lifecycle | differentiate on honest lifecycle |

*Do not read a blank cell as "competitor lacks it" — private implementation = "not publicly verified".*

## 8. False-negative risk register (highest first)
1. **Brand IDN homograph (confirmed).** 2. Email rua= reporting-destination change (hijack) — NT. 3. Email DKIM selector/key rotation — NT. 4. ASM version→specific-CVE — NT. 5. Website new third-party-script appearance — NT. 6. Identity newly-exposed login surface change — NT.

## 9. False-positive & evidence-completeness register
- IDN fix must exclude customer-owned IDNs + score confusable-distance (not raw non-Latin presence).
- Any "unauthorised" cert wording must stay corroborated (issuer/SAN unexpected ≠ proven malicious).
- Email change alerts must fail honest on TempError/partial resolution (already the SPF discipline).
- ASM version→CVE must gate on fingerprint confidence, never assert exploitability from a banner alone.

## 10. Existing fixture/mutation/live-acceptance coverage
Strong on security (6 CI suites, 204 assertions) + SPF (resolver 49, corroboration 31) + posture/related-changes/lifecycle validators. **Weak on detection-depth regression** for the candidates above — none has a "misses this real change" fixture yet. That is the gap this audit's roadmap fills.

## 11. P0/P1/P2 remediation roadmap
- **P0:** none confirmed this pass (no live active-harm/misrepresentation).
- **P1:** (a) **Brand IDN/homograph** (§6.1) — real phishing blind spot, parity-relevant. (b) **Verify ASM version→specific-CVE** (§6.2) — if absent, it is a P1 EASM-parity gap.
- **P2:** Email rua-destination-change + DKIM-rotation change intel; Website third-party-script change graph; Identity new-surface change intel; Shadow IT source-attribution precision.

## 12. Recommended first three implementation episodes
1. **Brand IDN/homograph detection** (punycode decode + Unicode-confusable matching + customer-IDN exclusion) — P1, self-contained, high phishing value.
2. **ASM version→CVE applicability verification, then (if absent) correlation** — confirm before build; P1 parity.
3. **Email reporting-destination + DKIM-rotation change intel** — extends the proven SPF change-intel pattern; P2 but cheap on the existing DMARC/DKIM engines.

## 13. Public-claim restrictions until proven
- No "homograph / IDN lookalike detection" until §6.1 ships.
- No "vulnerability/CVE identification" beyond version *disclosure* until §6.2 is confirmed/built.
- No "SPF include-aware / unauthorised-sender detection" as *live* until #251/#252 deploy.
- No "certificate chain / revocation validation" (disclaimed limit).
- Keep Brand bounded-wording; keep Vendor Risk/Supply Chain retired under Shadow IT.

## 14. Founder-controlled acceptance scenarios
- Brand IDN: register a benign IDN of a founder brand → expect a candidate (after fix).
- ASM: stand up a host disclosing a known-vulnerable version → expect specific-CVE wording (after §6.2).
- Email: change SPF root on blackbullbarbers.co.uk → expect live `email_spf_changed` (testable now); include-chain + rua-change after SPF deploy.
- Cert: observe an unexpected issuer/SAN in CT for a founder domain → expect a lifecycle finding (testable now).

---
`SEVEN-DOMAIN DETECTION-DEPTH AUDIT — ITERATION 1 COMPLETE / IMPLEMENTATION ROADMAP READY` (exhaustive ≥15-scenario per-domain trace = continuing deepening pass; no runtime code or deployment changed).
