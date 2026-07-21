# Seven-Domain Detection-Depth & Competitor-Parity Audit

Read-only product-owner audit. No runtime/frontend/deploy/data changed. **Iteration 1** — this pass establishes the verified engine inventory, the depth law, a code-grounded L1/L2/L3 map, the *verified* gap register, a competitor-parity frame, and the remediation roadmap. The exhaustive ≥15-scenario-per-domain full-pipeline trace is explicitly marked as continuing work: fabricating traces not yet verified would violate this audit's own honesty rule. Where a capability is not traced end-to-end, it is recorded **NOT TESTED**, never assumed.

## 1. Executive truth summary
- **Verified engine inventory: 118 engine modules** (`workers/scan-api/src/engines/*.js`) — the earlier "26/27" figure is superseded.
- Two initial hypotheses were tested against the *full* module set (not a single file): **Brand IDN/Unicode-homograph detection — CONFIRMED GAP.** **Certificates CT-issuance monitoring — hypothesis DISPROVEN** (it exists in `cert-intel.js` / `cert-trust-l2.js` / `cert-events.js`; my first-pass claim over cert-analysis/lifecycle alone was wrong and is retracted).
- **Email Protection is the deepest domain** (SPF include-aware — engineering-complete/deploy-pending; DMARC change workflow; DKIM/MTA-STS/TLS-RPT). **No domain is "surface-only"**, but each has candidate L2/L3 deepenings.
- **The one confirmed customer-facing FAIL** this pass: a registered IDN homograph lookalike (e.g. Cyrillic `аpple.com` → `xn--pple-43d.com`) is missed by BOTH Brand paths. That is a real phishing blind spot.
- No P0 that makes the *current* production service actively harmful was found. (SPF include-aware is deploy-pending, correctly labelled, not a live over-claim.)

## 1a. Corrections (later same day, 2026-07-21)
- **SPF include-aware is now DEPLOYED** (Worker `d1ad62b8`, tag `v2026.07.21-4`, rollback `bd33b028`) — every "deploy-pending" note below for SPF is superseded. **Live acceptance is BLOCKED, not by code, but by scan completeness:** the anchor domain `blackbullbarbers.co.uk` has produced only `partial` scans since 2026-07-18 (last complete `scan_ccc13a02`), and posture-diff events require both current+previous scans `complete`, so change events cannot fire for it. Root-causing the chronic-partial condition is a scan-engine reliability item (candidate **P1** — a chronically-partial domain silently receives no change alerts, though its scores are honestly shown "provisional"). Coverage-honesty is intact (`assessment-presentation.js` shows "Some checks were not completed. This score is provisional."), but change-DETECTION is disabled for such a domain.
- **"118" is the ENGINE-FILE count, not the count of active customer-facing capabilities.** Many of the 118 are cross-cutting/internal (posture, alerts, case-workflow, retired vendor/supply, helpers). Do not read 118 as "118 features."
- **Depth is per-capability, not per-domain.** The §4 table is a convenience; each capability carries its own level. Avoid blanket "domain X is deep/L3" statements.

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

## 15. DEEPENING PASS — Brand IDN / Unicode homograph (implementation-ready design)
Read-only design; no runtime code changed. Proves the §6.1 gap end-to-end and specifies the fix.

### 15.1 Brand candidate-ingestion paths (mapped)
| Path | Source | Enters via | IDN-aware? |
|------|--------|-----------|-----------|
| Deterministic generation | `brand-typosquat.js` `generateTyposquatCandidates` (8 ASCII strategies; `TYPOSQUAT_HOMOGLYPHS` = `l→1`,`o→0`) | direct | **No** — no Unicode/punycode variants generated |
| Passive CT/SAN discovery | `brand-passive-discovery.js` crt.sh brand-TOKEN search | `normalizeHostname` → `brandSimilarityScore` | **No** — token search is literal; `xn--…` never matches token "apple" |
| DNS-derived / nested host | `brand-dns-enrichment.js`, nested credential-host detection | same scorer | **No** |
| Stored-evidence reprocessing | candidate re-scoring | `scoreBrandCandidateRisk` | **No** — variant `homoglyph:25` is only set by the ASCII generator |
| Alert/campaign re-entry | `brand-cases.js` | reuses candidate rows | inherits the miss |

### 15.2 Hostname handling trace (the chokepoints)
- **Normalization:** `hostnames.js normalizeHostname` uses `new URL().hostname` → **keeps `xn--` punycode form**, never `toUnicode`-decodes. `normalizeDiscoveredHostname` lowercases + validates + root-scopes (customer-asset path, not brand).
- **Match chokepoint:** `brand-protection.js brandSimilarityScore` = Levenshtein on `String(x).toLowerCase().replace(/[^a-z0-9]/g,"").slice(0,100)`. **`replace(/[^a-z0-9]/g,"")` destroys the signal:** `xn--pple-43d` → `xnppled` (Levenshtein vs `apple` large → no match). No NFC, no punycode decode, no script/confusable awareness.
- **Confirmed at THREE points:** generation (no IDN candidates), discovery (CT token search can't surface a punycode host), scoring (strips/keeps punycode). Robust FAIL.

### 15.3 Scenario matrix (16)
| # | Scenario | Verdict | Why |
|---|----------|---------|-----|
| 1 | Cyrillic `а` vs Latin `a` | **FAIL** | not generated, not CT-matched, scorer strips |
| 2 | Greek omicron vs Latin `o` | **FAIL** | same |
| 3 | Mixed-script label | **FAIL** | no script detection |
| 4 | Whole-script confusable (all-Cyrillic) | **FAIL** | scorer strips to non-Latin→empty/mismatch |
| 5 | Punycode supplied directly (`xn--`) | **FAIL** | no decode; strips `--` |
| 6 | Unicode before IDNA encoding | **FAIL** (fragile accidental strip ≠ detection) | strip may drop a confusable and pseudo-match by omission — wrong reason, not reliable |
| 7 | Multiple confusable chars | **FAIL** | same |
| 8 | IDN TLD | **FAIL** | TLD not decoded |
| 9 | Nested credential host on IDN base | **FAIL** | base domain unmatched |
| 10 | Legitimate non-Latin internationalised domain | **OUT OF SCOPE** (correctly not flagged) | **the fix MUST preserve this** — FP control |
| 11 | Unrelated punycode domain | **OUT OF SCOPE** (correctly not flagged) | fix must not skeleton-match unrelated |
| 12 | CT cert, no active DNS | **FAIL** | not matched (would be low-severity candidate after fix) |
| 13 | Active DNS, no HTTP | **FAIL** | not matched |
| 14 | Active login surface (highest harm) | **FAIL** | still missed |
| 15 | Redirect to customer brand | **FAIL** | strong phishing signal missed |
| 16 | Reappeared IDN candidate | **FAIL** | never detected first time |

### 15.4 Safe detection design
1. **New pure module `engines/idn-homograph.js`:** punycode decode/encode round-trip (bundle a small pure-JS punycode; Workers `URL` gives toASCII only); Unicode **NFC** via `String.normalize('NFC')`; per-char **script detection** (Latin/Cyrillic/Greek/Armenian/… range map); **confusable skeleton** (bundled TR39-subset map, e.g. Cyrillic а→a, Greek ο→o); mixed-script + whole-script-confusable flags.
2. **Matching:** `skeleton(decodeIDN(candidate))` vs `skeleton(brand)`; a close skeleton match where the ORIGINAL contains non-ASCII/confusable = homograph. Keep the existing Levenshtein for ASCII typos; ADD the skeleton path — never replace.
3. **FP controls:** exclude the customer's own registered IDNs; require skeleton distance ≤ floor; a genuinely different-language legitimate IDN (no brand-skeleton match) is not flagged; unrelated punycode is not flagged.
4. **Corroboration tiers (separate concerns — never conflate):** *candidate discovery* (exists in CT/DNS) → *visual similarity* (skeleton/mixed-script) → *activity evidence* (DNS resolves, MX present, HTTP up) → *phishing-adjacent evidence* (login form, redirect-to-customer-brand) → **maliciousness must NOT be claimed without evidence**. Severity rises only with corroboration; bare CT presence = low.
5. **Fail-honest wording:** "visually-confusable (IDN homograph) lookalike"; with a login surface: "hosts a credential form"; never "malicious" unabsent evidence. Preserve the bounded Brand public-claim rule.

### 15.5 Exact files/functions to change
- **New:** `engines/idn-homograph.js` (decode, NFC, script detect, skeleton, confusables table) — pure.
- `brand-typosquat.js`: add IDN homograph candidate generation (brand → confusable substitutions → punycode); add `homoglyph_idn` variant.
- `brand-protection.js` `brandSimilarityScore` (or a new `brandSkeletonMatch`): add the decode→NFC→skeleton compare path; `scoreBrandCandidateRisk`: add `homoglyph_idn` weight (~28) + mixed-script bonus.
- `brand-passive-discovery.js`: decode punycode + skeleton-match CT hosts; broaden the CT query to the brand's confusable/punycode forms.
- Event/case wording (`brand-cases.js` / remediation copy): IDN-homograph tiers.

### 15.6 Fixtures / mutations / live-acceptance / regression / PR sequence
- **Fixtures:** `xn--pple-43d.com`(Cyrillic) matches `apple`; Greek-omicron variant matches; mixed-script flagged; **legitimate customer IDN excluded**; **unrelated punycode NOT matched**; punycode-direct AND unicode-input both handled; nested `login.xn--…` escalates with corroboration.
- **Mutations:** remove punycode decode → IDN-match test reddens; remove skeleton compare → homograph test reddens; remove customer-IDN exclusion → FP test reddens.
- **Regression (both paths):** deterministic generation emits ≥1 IDN candidate for a Latin brand; passive-CT skeleton-matches a punycode host.
- **Controlled live-acceptance:** founder registers a benign IDN of a founder brand (or observes one in CT) → a candidate is raised (requires a real IDN registration for full live proof; fixtures/mutations prove it deterministically meanwhile).
- **PR sequence:** **P1 PR-A** — `idn-homograph.js` + `brandSimilarityScore` skeleton path + fixtures/mutations (detection core). **P1 PR-B** — IDN candidate generation + CT skeleton-match (discovery) + risk weight + wording. **P2** — IDN campaign clustering + reappearance.
- **Public-copy restriction:** no "homograph / IDN lookalike detection" claim until PR-A + PR-B accepted.

---
`BRAND IDN DEPTH DESIGN COMPLETE / IMPLEMENTATION READY`

`SEVEN-DOMAIN DETECTION-DEPTH AUDIT — ITERATION 1 + BRAND-IDN DEEPENING / IMPLEMENTATION ROADMAP READY` (exhaustive ≥15-scenario per-domain trace = continuing deepening pass; no runtime code or deployment changed).

---

## 16. DMARC DMARCbis conformance audit (2026-07-21)
First protocol-conformance audit under the new gate. Read-only; no runtime change. Standard baseline: **DMARCbis — RFC 9989 (core) / 9990 (aggregate) / 9991 (failure), published May 2026, obsoletes RFC 7489 + 9091** (WebSearch-verified). Code: `email-analysis.js parseDmarcRecord` + policy journey; `rua-routing.js`.

### Detection Depth Law — the four things
1. **Real customer harm:** (a) `pct` — a customer with `pct=50; p=reject` is shown "Reject at 50%"; DMARCbis removed `pct`, so modern receivers ignore it and enforce at 100%. We **understate** their enforcement (safe direction — never overstates protection — but inaccurate). (b) `np` — a customer who set `np=reject` (policy for *non-existent* subdomains, a real anti-spoofing control added in DMARCbis) is invisible to us: we neither credit it nor detect a change/weakening to it.
2. **Do we catch it now:** `pct` handled on OLD (7489) semantics; `np` NOT parsed (invisible); `t` (testing) NOT parsed.
3. **Where the pipeline breaks:** `parseDmarcRecord` (email-analysis.js) — the `pct` block validates/applies a tag DMARCbis removed and emits "enforcement applies to X%" / "Reject at X%"; no `np`/`t` extraction. External-report auth and alignment are fine (below).
4. **Minimal PR sequence:** (a) treat `pct` as **deprecated** — parse it but replace the wording with "`pct` is deprecated in DMARCbis and ignored by modern receivers" instead of understating enforcement; (b) parse + surface **`np`** (non-existent-subdomain policy) and track its change/weakening; (c) parse `t=` testing; (d) fixtures: pct-deprecated-wording, np-present, np-weakened (reject→none), t-present, multiple-record→permerror; mutations: drop np-parse → np test reddens, restore old pct wording → deprecation test reddens; (e) live-acceptance: a founder DMARC record with `np=reject` is surfaced.

### Tag/behaviour conformance matrix
| Item | RFC 7489 (old) | DMARCbis (9989/90/91) | Our handling | Verdict |
|------|----------------|------------------------|--------------|---------|
| `v=DMARC1` | required | required | validated | **PASS** |
| `p` none/quarantine/reject | yes | yes | validated | **PASS** |
| `sp` subdomain policy | yes | yes | parsed + warns if absent | **PASS** |
| `pct` | applied (0–100) | **REMOVED / ignored** | validated + applied + "Reject at X%" | **FAIL (drift)** — P2 |
| `np` non-existent-subdomain policy | — | **ADDED** | **not parsed** | **PARTIAL/MISSING** — P2 |
| `t` testing | — | added (replaces some pct use) | not parsed | **PARTIAL** — P3 |
| `adkim`/`aspf` alignment | yes | yes | parsed, default `r` | **PASS** (policy-level) |
| `rua`/`ruf` | yes | yes | parsed (comma-split) | **PASS** |
| External report auth (`_report._dmarc`) | yes | yes (9990) | `ensureExternalReportAuthorization` implemented | **PASS** |
| Multiple records | permerror | permerror | warns + `valid=false` | **PASS** |
| Unknown tags | ignore | ignore | stored, not acted on (except pct) | **PASS** (except pct) |
| Org-domain discovery (PSL → **DNS tree-walk**) | PSL | **tree-walk** | not traced | **NOT TESTED** — lower immediate impact, but the policy-discovery path must be traced before it is marked OUT OF SCOPE (founder correction) |

*Severity refinement (founder): `pct` deprecated-wording = **P2**; `t` parsing = **P2/P3**; `np` policy visibility + change tracking = **P1 if the np change is fully lost from alert/remediation/report, else P2**; org-domain tree-walk = **NOT TESTED**.*

### Honest scope note
CyberMeters is a **policy reader / reporter**, not a mail receiver that *evaluates* DMARC on live messages. Alignment verdicts come from the RUA aggregate reports (computed by real receivers), so the PSL→tree-walk change has **lower immediate impact** for us. **But this does not close it:** if CyberMeters does any organizational-domain or inherited-policy discovery (e.g. how it reasons about `sp`/subdomain inheritance), the tree-walk behaviour still matters — so it is **NOT TESTED**, not out of scope, until that path is traced. We must not claim to *evaluate* DMARC alignment. `rua-routing.js` does a same-org test by label-drop (not PSL) adequate for its narrow inbound-routing purpose only.

### `pct` fix — the RIGHT behaviour (founder refinement)
Do **not** stop parsing `pct`. Instead: **observe it → mark legacy/deprecated → exclude from active enforcement semantics → bounded wording** ("Legacy `pct` tag observed; modern DMARC receivers may ignore it"). Data is preserved; no false policy effect is produced. (Supersedes the earlier "treat as deprecated" phrasing, which risked reading as drop-it.)

### Implementation design REQUIRED before any fix PR (founder)
Adding two tags to the parser is not enough. The DMARCbis-migration episode must first design: (1) how legacy `pct` is stored; (2) whether/how it is excluded from scoring; (3) backward-compatibility with existing snapshots; (4) how `np` **absent** is interpreted (inheritance from `sp`/`p`); (5) how `sp` / `p` / `np` precedence is shown; (6) whether the change event is an existing type or new; (7) reports/PDF wording; (8) false-diff risk between old and new scans.

### Sequencing (founder re-lock — this audit jumped the queue)
This audit is **recorded only**. **No runtime PR now.** The DMARC fix is a **separate later episode**, AFTER the **Phase 0 exit-gate**: **#263 chronic-partial fix is merged but NOT deployed (live Worker still `d1ad62b8`)** → it needs deploy preflight → controlled deploy → blackbullbarbers new scan → complete/partial result → downstream module/event availability check → per-signal SPF completeness if needed. Only then: DMARCbis implementation design → fix → deploy → founder live acceptance. Then SPF 7208 → DKIM → MTA-STS → TLS-RPT conformance audits.

### Verdict
`DMARC HANDLING = RFC 7489-BASED / DMARCbis DRIFT ON pct + np` — no catastrophic conformance failure (alignment, external-auth, multi-record, unknown-tags all fine); two real drifts (`pct` applied though removed; `np` unsupported); org-domain tree-walk NOT TESTED. Status: **DISCOVERED / DESIGN-PENDING** (not IMPLEMENTED). Public copy must not claim "DMARCbis / RFC 9989 compliant" until the migration episode closes with live acceptance.
