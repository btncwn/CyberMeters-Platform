# Item 14 — Founder Acceptance Master Runbook

**Status:** canonical runbook for Item 14 founder acceptance. **Nothing in this document has
been executed.** It defines *how* acceptance will be run; it records no result and grants no
acceptance. Authoring it touched no runtime code, migration, CI, schema or production
configuration, and started no acceptance, deployment or fixture action.

**Authority:** this document owns Item 14's execution procedure only. Item ordering and scope
remain owned by `docs/PRE-BETA-EXECUTION-BACKLOG.md`; release facts by `CHANGELOG.md`. It does
not renumber or redefine the frozen backlog.

**Invariants governing every section:**
```
Engineering deployed   ≠ live accepted        Merge ≠ deploy · deploy ≠ acceptance
Observed disappearance ≠ confirmed remediation
unknown ≠ healthy      customer assertion ≠ verification
one missing observation ≠ remediation         a gate with no evidence = NOT TESTED, never PASS
```

---

## 0. Structure — founder decisions (26 Jul 2026)

**Decision 1 — one canonical runbook, two independently gated tracks.**

```
Item 14 — Founder Acceptance
├── 14-S : canonical founder security acceptance   (defined by the frozen backlog)
│   ├── 14-S0  Founder Acceptance Package reconciliation   (governance entry gate)
│   └── 14-S1..S9  the canonical security steps
└── 14-D : deferred live detection acceptance      (batched from Items 7–10)
    ├── 14-D7  Item 7  DMARCbis deferred acceptance
    ├── 14-D8  Brand Protection full-chain + Item 8 IDN acceptance
    ├── 14-D9  Certificates & Trust / Item 9 acceptance
    ├── 14-D10 Attack Surface / Item 10 acceptance
    └── 14-DX  Cross-domain scan degradation & budget honesty

Item 5 CT-specific follow-ups  →  CT Provider Resilience interlock (R1–R3)
Item 7-I namespace cleanup     →  Item 13 (Dead code / cleanup)
```

- The two tracks **may run in separate founder sessions**.
- Each track has its **own entry gates, evidence bundle, verdict (PASS / PASS WITH BACKLOG /
  FAIL / BLOCKED), blocker list and closure record**.
- **Item 14 overall cannot close until BOTH tracks have an explicit recorded result.**
- **`14-S PASS` + `14-D BLOCKED` ≠ `Item 14 PASS`.** A blocked or untested 14-D must never
  inherit PASS from 14-S.
- 14-S must **not** be needlessly delayed because 14-D prerequisites are unfinished; its
  readiness is evaluated independently against its own gates (§1-S).

**Decision 2 — Item 7 acceptance debt assigned explicitly.**

| Residual | Owner | Rule |
| --- | --- | --- |
| **7-A … 7-H** | **14-D7** (this runbook, §7) | Live behaviour/acceptance scope |
| **7-F** second-tenant isolation | 14-D7 **and** executed alongside §8/X4 | May share the session, but **evidence ownership stays separate** — "passed in the shared test" must never erase Item 7 attribution |
| **7-D** Hosted-DMARC routing | 14-D7 | **Autopilot remains SUSPENDED.** Acceptance must not reactivate it; test only the currently authorised/manual or suggestion-only behaviour and routing reconciliation |
| **7-I** isolated-namespace cleanup | **Item 13 — Dead code / cleanup** (NOT Item 14 implementation) | Item 14 performs **no cleanup**; it only **verifies no customer-facing namespace drift remains** after Item 13 |

### 0.3 Acceptance-debt register — nothing closes by omission

Item 7's residuals were nearly lost because no item owned them. The same class exists
elsewhere. **Every row below must carry an explicit owner and an explicit result before Item 14
can close.** Rows marked *founder to confirm* are ones this draft cannot resolve from the
repository alone.

| Debt | Current recorded state | Owner | Action |
| --- | --- | --- | --- |
| 7-A … 7-H | live-pending | **14-D7** (§7) | Execute |
| 7-I namespace cleanup | live-pending | **Item 13** | Item 14 verifies only (`D7-I-verify`) |
| 8-A MSP parity | BLOCKED — no real entitled MSP account | **Item 16** (real entitled MSP) then re-check | Never inferred from a `401` |
| 8-B wider IDN/script/TLD matrix + shared-IP campaign | deferred (capacity) | 14-D8 backlog | Name explicitly on the decision line |
| 8-C confusable-map grade statement | pending record | 14-D8 | Record at declared grade (not UTS #39 / IDNA conformance) |
| Item 9 C9 non-Worker TLS probe feasibility | not measured | **14-D9** (§5, C9) | Measure; if the ceiling is fundamental, feed **Item 17** claims scoping |
| Item 10 A11 ~48 h removal-confirmation delay | by design, unobserved live | **14-D10** (§6, A11) | Confirm acceptable in the live product |
| CT Provider Resilience interlock R1–R3 | not started | **Interlock** (pre-Item-11) | Its own production completion-rate comparison — gates 14-D via `D-E4` |
| **Founder Manual Production Acceptance Package** (Brand PR-A/B/C · Shadow IT Alert Trust · Weekly Digest Truth · A6 Related Changes Phase 2) | `docs/FOUNDER-ACCEPTANCE-PACKAGE.md` still states *"NO acceptance below has been executed. Nothing here is PASS."* — while a 20 Jul founder session produced per-deliverable results | **14-S0** (§3.0) | Reconcile **line by line**; no blanket retroactive PASS |
| **Brand Protection full-chain acceptance** | CHANGELOG records Brand Protection as **PUBLIC-BETA BLOCKED until founder acceptance of a controlled scan exercising the full chain** | **14-D8** (§4) | Blocker stays **OPEN** unless exact founder-controlled full-chain evidence proves otherwise |
| **Item 5 follow-up — provider `429` + natural CT-blackout** | live-pending (controlled/simulated already passed) | **CT Provider Resilience interlock R1–R3** | Closes in the interlock's own production comparison pack |
| **Item 5 follow-up — real slow-TLS live fixture** | live-pending | **14-DX** (§8) | Does **not** belong to the CT interlock; non-blocking, but never a silent PASS |
| MSP portfolio customer acceptance | unreachable — no entitled MSP account exists in production | **Item 16** | Same gate as 8-A; do not mark PASS from route existence |

**Rule:** if a row here has no result at closure time, Item 14 is recorded as
`PASS WITH BACKLOG` naming that row, or `NOT CLOSED` — never a silent PASS.

---

## 1. Entry gates — per track

### §1-S — 14-S entry gates (evaluate independently; Items 9/10 deployment NOT required)

14-S exercises authentication, session, tenant, case-transition and report-access behaviour
that is **already live**. It therefore does not depend on the Item 9/10 deploys.

| # | Gate | Evidence | FAIL |
| --- | --- | --- | --- |
| S-E1 | Exact deployed build known and intended | `git rev-parse origin/main` + Cloudflare deployment message | Live message ≠ intended build |
| S-E2 | Live + rollback Worker IDs read **from Cloudflare, never from CHANGELOG** | `wrangler deployments status` for both Workers | Any ID sourced from a document |
| S-E3 | `workers_dev = true` reachable (SSO redirect + rollback path) | `/health` on the workers.dev host | workers.dev host unavailable |
| S-E4 | No unresolved P0/P1 on the auth / tenant / case / report surface | Open-issue review | Any open P0/P1 in scope |
| S-E5 | Baseline captured | Pre-session counts per workspace: sessions, tokens, invitations, cases, PDFs issued | No baseline → no before/after proof |
| S-E6 | Blast radius contained | All acceptance mail (invitations, resets) to a founder-controlled mailbox only | Any unrelated recipient reachable |
| S-E7 | Second founder-controlled workspace + identity available | Confirmed usable | Tenant checks cannot run → mark BLOCKED, do not skip |

**Build-binding rule (same principle as the Item-15 → Item-16 pentest re-validation folded in
via PR #307):** a 14-S verdict is valid **only for the exact build it was proven against**.
Record that build on the decision line. If a later deploy changes the auth, tenant,
case-transition or report-access surface, **14-S must be re-checked at Item 18** — a prior PASS
does not carry forward automatically.

### §1-D — 14-D entry gates (ALL required before any fixture spend)

| # | Gate | Evidence | FAIL |
| --- | --- | --- | --- |
| D-E1 | Every in-scope detection item is **ENGINEERING-COMPLETE and DEPLOYED** | Cloudflare deployment message contains the intended SHA | Any in-scope item not deployed |
| D-E2 | **Migration applied BEFORE the dependent code** | Deploy log: migration → then Worker | Code deployed before its migration |
| D-E3 | Migrations reconciled remotely | `pragma_table_info` / `sqlite_master` prove expected-applied and nothing unexpected | Repo holds an unapplied migration the deployed code needs |
| D-E4 | **CT Provider Resilience interlock (R1–R3) complete + measured** | Post-deploy completion-rate comparison recorded | Interlock unfinished → 14-D BLOCKED |
| D-E5 | Clean D1/R2 reconciliation | Snapshot SHA-256 = D1 `checksum_sha256`; no orphans either direction | Any mismatch |
| D-E6 | Baseline captured | Pre-session counts: scans, assets, events, alerts, cases, snapshots, aggregate reports | No baseline |
| D-E7 | Blast radius contained | All acceptance notifications to a founder-controlled mailbox only | Any unrelated recipient |
| D-E8 | Fixture capacity real | Genuine entitlement/workspace slots — **never fabricated in D1** | Synthetic entitlement |
| D-E9 | Item 13 complete for the 7-I check | Namespace cleanup landed, so §7 can verify drift-free surfaces | Verify-only step becomes untestable → mark NOT TESTED |

**State at drafting (re-verify at execution — these WILL be stale):** main `9347229d` · latest
repo migration `102-attack-surface-observation-lifecycle.sql` **NOT applied** · live scan-api
Worker `d3aa2ac0` (message: Item 8 PR-D `b8304cac`) · live email Worker `f4423b41` · **Items 9
and 10 NOT deployed** · CT interlock R1–R3 not started.

```
14-D : BLOCKED BY PREREQUISITES (D-E1, D-E2/E3 mig 102, D-E4 interlock)
14-S : readiness to be evaluated independently against §1-S
```

---

## 2. Irreversible-action & spend gates (primarily 14-D)

Each row needs an explicit, separate founder approval **immediately before** execution.

| Action | Irreversible? | Notes |
| --- | --- | --- |
| Domain registration (synthetic `.com` brand + IDN lookalikes) | Money spent; registrar/registry history permanent | Exact cart shown before purchase |
| Real subscription for fixture capacity | Recurring; cancellable | Entitlement must be REAL |
| **Public certificate issuance on a fixture host** | **CT entry PERMANENT — cannot be erased** | Neutral throwaway names only |
| DNS record create/change on a fixture zone | Reversible (restore RRset) | Capture exact before-RRset first |
| Controlled certificate renewal/replacement (14-D9) | CT entry permanent | Founder-owned host only |
| Controlled DMARC policy change (14-D7) | Reversible | Isolated acceptance namespace only |
| Worker/Pages deploy | Reversible via recorded rollback ID | IDs re-read from Cloudflare |
| Migration application | Additive; forward-only | Never a destructive down-migration |

**Hard exclusions (no approval path):** `cybermeters.com` DNS/TLS/CT changes · production apex
`blackbullbarbers.co.uk` records (`_dmarc`, MX, SPF, DKIM, website) · any third-party or
customer brand · any credential-collecting fixture page · direct D1 fixture injection · direct
case-status mutation · fabricated takedown/notification references · **reactivating
Hosted-DMARC autopilot**.

**Known dead ends (do not re-derive):** `.co.uk` IDN unregistrable (Nominet offers no IDNs); a
`.com` IDN of a `.co.uk` brand is out of discovery scope ⇒ Item 8 fixtures require a
**synthetic `.com` protected brand**.

---

## 3. Track 14-S — canonical founder security acceptance

### 3.0 · 14-S0 — Founder Acceptance Package reconciliation (governance entry gate)

**Run this before S1.** `docs/FOUNDER-ACCEPTANCE-PACKAGE.md` has drifted from reality: it still
carries the blanket statement *"NO acceptance below has been executed. Nothing here is PASS"*,
while a 20 July founder session produced per-deliverable results.

**Rules:**
- Reconcile **each delivery independently**. **No blanket retroactive PASS.**
- `Engineering merged/deployed ≠ founder live acceptance.`
- A row with no founder-controlled production evidence stays **NOT TESTED** or **BLOCKED**.
- The blanket *"Nothing here is PASS"* sentence may be removed **or converted to historical
  context only after** the line-by-line reconciliation is complete.

| Delivery | Reconcile with | Result |
| --- | --- | --- |
| Brand Protection (PR-A/B/C chain) | exact deployed SHA/deployment · founder-controlled production evidence · acceptance date · remaining blockers | PASS / PASS WITH BACKLOG / NOT TESTED / BLOCKED — **note: the full-chain acceptance itself is owned by 14-D8 (§4), not closed here** |
| Shadow IT Alert Trust | same | PASS / PASS WITH BACKLOG / NOT TESTED / BLOCKED |
| Weekly Digest Truth | same | PASS / PASS WITH BACKLOG / NOT TESTED / BLOCKED |
| A6 Related Changes Phase 2 | same | PASS / PASS WITH BACKLOG / NOT TESTED / BLOCKED |

Each row records: exact deployed SHA / deployment id · founder-controlled production evidence
(paths/hashes) · acceptance date · verdict · remaining blockers.

### 3.1 · 14-S1 … 14-S9 — canonical security steps

Product-path only; no direct DB mutation. Capture request/response (secrets redacted), UTC
timestamps and resulting audit rows for every step.

| # | Step | Expected honest result | FAIL |
| --- | --- | --- | --- |
| S1 | A6 production viewer spot-check | Viewer reads Related Changes; **every mutation refused**; `can_manage:false`; `available_transitions: []` | Viewer can mutate, or UI offers a transition the API refuses |
| S2 | Live Microsoft SSO | Sign-in succeeds; claims map to the correct workspace/role | Role/tenant mis-binding |
| S3 | MFA with SSO | MFA enforced on the SSO path | MFA bypassable via SSO |
| S4 | Password-reset revocation | Reset **invalidates existing sessions/tokens** | Old session still authorised |
| S5 | Invitation flows | Invite actually sent (fail-closed), accepted once, not replayable | Silent non-send or re-usable invite |
| S6 | Deleted-workspace behaviour | Soft-deleted workspace receives **no** scans/ingestion/events/alerts/cases; reads behave as nonexistent (non-enumerating) | Any post-delete work or existence oracle |
| S7 | API-token lifecycle | Create → scope-limited use → revoke → immediately unusable | Revoked token still works |
| S8 | Case ownership/transitions | Assign to an **active member only**; transitions via the canonical validator; `verify` refused to a customer actor (system-only) | Foreign/removed assignee accepted, or customer self-verifies |
| S9 | Branded PDF access | Only entitled workspace members retrieve it; object access tenant-scoped | Cross-tenant or unauthenticated retrieval |

---

## 4. 14-D8 · Brand Protection full-chain + Item 8 IDN acceptance

**Consolidated ownership (founder decision).** This one evidence pack covers BOTH the earlier
Brand PR-A/B/C production chain **and** the Item 8 IDN acceptance. Do not multiply it into two
separate debts, and do not conflate engineering deployment with live acceptance.

```
Brand engineering / deploy evidence        AVAILABLE
Brand full-chain founder acceptance        NOT COMPLETE
Public-beta blocker                        OPEN
Owner                                      14-D8
```

The CHANGELOG blocker (*"PUBLIC-BETA BLOCKED until founder acceptance of a controlled scan
exercising the full chain"*) **remains OPEN** unless exact founder-controlled full-chain
evidence proves otherwise. Item 14 must not close 14-D8 until a controlled full-chain scan has
actually run and produced its evidence pack.

### 4.1 Full-chain coverage (the earlier Brand PR-A/B/C production chain)

| # | Chain link | Expected honest result | FAIL |
| --- | --- | --- | --- |
| F1 | Generated / discovered candidate | Candidate produced by the real production path | Fixture not reachable by discovery |
| F2 | CT evidence | Certificate observed via the shared CT path (no duplicate lookup) | CT presence treated as live service |
| F3 | DNS / HTTP / TLS enrichment | Each enrichment stage recorded independently | One stage's failure fakes another |
| F4 | Recurrence / reappearance | Same identity, history preserved | New identity or lost history |
| F5 | Campaign linkage honesty | Only genuinely observed shared infrastructure links a campaign | Similarity infers common ownership |
| F6 | Tenant isolation | Second workspace denied with exact IDs | Any cross-tenant read |
| F7 | API / snapshot / report / PDF parity | One projection; renderers do not re-derive | Divergence |
| F8 | Wording | "lookalike signal, not proof of abuse" throughout | Any "confirmed phishing/malicious" claim |

### 4.2 Item 8 — IDN controlled-fixture acceptance

**Fixture model (settled):** synthetic neutral `.com` protected brand + IDN lookalikes taken
**only from the generator's own output** (Phase-0 preview first — never register a candidate
discovery cannot surface). Classify each fixture **TRANSIENT** (onboard → prove → archive) or
**PERSISTENT** (must stay linked across recurrence and shared-IP campaign proof).

| # | Step | Expected honest result | FAIL |
| --- | --- | --- | --- |
| B0 | Phase-0 generator preview (pure, no spend) | Exact A-label candidate set captured; fixtures chosen only from it | A fixture absent from `lookalikeBases` |
| B1 | Generation + canonicalisation | Unicode and A-label converge on **one** canonical candidate row | Duplicate rows |
| B2 | **Owned-IDN exclusion** | Founder-owned IDN excluded whether observed as Unicode or A-label; no alert, no case | Own domain surfaces as a lookalike |
| B3 | **CT-only rung** | `low`/unverified; `certificate_observed_not_yet_live`; **no** critical rating, **no** managed case | CT presence alone rated high/critical |
| B4 | DNS-only rung | Active but **below critical** (`idn_dns_only_not_critical`) | Critical without service evidence |
| B5 | HTTPS / inert login-shaped rung | Priority rises **only** with observed evidence; wording stays "lookalike signal, not proof of abuse" | Any "confirmed phishing/malicious" wording |
| B6 | Managed lifecycle | Case **manually** created (never auto-opened); canonical transitions only | Auto-opened case |
| B7 | Removal → re-add (recurrence) | "observed again"; recurrence increments; **history preserved**, same identity | New identity or lost history |
| B8 | **Campaign boundary** | Shared IP links a campaign **only when genuinely observed**; visual-only candidate gets **no** campaign id and no common-ownership claim | Campaign inferred from similarity |
| B9 | Surface parity | API · UI · alert · snapshot · PDF (· MSP if entitled) agree; A-label + Unicode context preserved | Any surface re-derives its own verdict |
| B10 | Tenant isolation | Second workspace cannot read the fixture candidate/case/events/snapshot **even with exact IDs** | Any cross-tenant read |

**Pre-approved Item 8 backlog (do not force into this session):** **8-A** MSP parity — BLOCKED
until a real entitled MSP account exists; **never infer PASS from a 401**. **8-B**
capacity-limited wider IDN/script/TLD matrix + shared-IP campaign live proof. **8-C** record the
confusable map at its declared grade (bounded product-policy subset — **not** UTS #39 or full
IDNA conformance; over-match bounded-not-zero; under-match deliberate).

---

## 5. 14-D9 · Item 9 — Certificates & Trust live acceptance

| # | Step | Expected honest result | FAIL |
| --- | --- | --- | --- |
| C1 | Baseline observation on a founder-owned host | Per-signal states independent (leaf/chain/SAN/issuer/expiry/CT/wildcard/parallel/active-service) | One incomplete signal collapses siblings |
| C2 | **Controlled renewal / replacement** | Replacement recorded append-only; old identity + replacement relationship preserved | History rewritten |
| C3 | **First replacement scan ≠ verified renewal** | Case stays `awaiting_verification`; NOT verified on first observation | First observation verifies |
| C4 | Customer asserts "renewed" | Recorded as **assertion**; `verification_status = not_verified` | Assertion closes the case |
| C5 | **Later complete live re-observation** | System-only verification closes the case from CyberMeters' own re-observation | Note/scan-completion alone verifies |
| C6 | Stale awaiting-verification | After the declared 21-day window the unverified replacement is surfaced (unacknowledged risk gets louder) | Sits silently forever |
| C7 | **Unknown trust signals stay unknown** | Chain validity / hostname-live / stapled OCSP / trust-store render **unknown/unavailable**, never healthy; missing OCSP degrades **only** revocation | Any unobservable signal shown healthy/verified |
| C8 | CT-only vs live-serving | Kept distinct on every surface | CT issuance presented as live service |
| C9 | **Non-Worker TLS probe feasibility (measurement, not a fix)** | On the founder host, measure how many honest `unknown`s a raw-TLS probe *could* convert to `observed`; record the number | Skipped → permanent unmeasured blind spot |
| C10 | Parallel vs replacement presentation | The same certificate pair yields **one** transition-context explanation | Contradictory narrative |

**C9 rationale:** Worker `fetch()` cannot observe peer chain, live hostname match, stapled OCSP
or trust-store validation. Consequence: a **real** live-TLS problem surfaces as `unknown`, not
as an issue — honest, but a coverage gap. If the ceiling is fundamental, **Item 17 public claims
must scope certificate trust as CT-issuance-observed, not live-TLS-verified.**

---

## 6. 14-D10 · Item 10 — Attack Surface live acceptance

| # | Step | Expected honest result | FAIL |
| --- | --- | --- | --- |
| A1 | New asset appears | `observed`; `new_asset_discovered`; identity stable | Missed or duplicated |
| A2 | Asset removed — **first** complete scan | `not_observed`, **NOT** `confirmed_removed`; legacy `status` unchanged; **no** `asset_no_longer_seen` | One scan confirms removal |
| A3 | **Confirmed-removal threshold** | `confirmed_removed` only after the declared policy: **3 qualifying complete observations · ≥24 h apart · ≥48 h first→third · active sources (DNS + HTTP) only** | Threshold short-circuited |
| A4 | **CT/passive cannot confirm removal** | crt.sh / CertSpotter evidence never advances the counter | Passive source advances removal |
| A5 | **Degraded scan cannot advance removal** | `unavailable` / `incomplete` / `not_assessed` leave counter and lifecycle untouched | Module failure produces removal |
| A6 | Asset returns | `reappeared` with the **same identity** and full history; counter resets | New row or lost history |
| A7 | DNS-only vs HTTP-only | Resolves-but-serves-nothing distinguished from serving | Conflated |
| A8 | Admin surface | Exposed admin surface surfaced **loudly** with honest wording | Buried under a cautious grade (false-negative) |
| A9 | Takeover candidate | Reported as **candidate**, never "confirmed takeover" | Overclaim |
| A10 | KEV signal | From the current authoritative catalogue with bounded, surfaced freshness | Stale catalogue presented as current |
| A11 | **~48 h trade-off observed** | A genuinely removed asset signals ~48 h later **by design**; confirm the delay is acceptable in the live product | Delay judged unacceptable → re-open the policy |

---

## 7. 14-D7 · Item 7 — DMARCbis deferred live acceptance (7-A … 7-H)

Executed on the **isolated founder-controlled acceptance namespace** (Item 7 used
`dmarc-test.blackbullbarbers.co.uk`). Production apex `_dmarc`, MX, SPF, DKIM and
`cybermeters.com` remain untouched. **Every step keeps its own Item 7 evidence attribution**,
even when it shares a session with §3 or §8.

| # | Residual | Step | Expected honest result | FAIL |
| --- | --- | --- | --- | --- |
| D7-A | **7-A** alert acceptance | Controlled policy regression on the isolated namespace | Only the **five approved actionable regressions** alert (`record_removed`, `record_became_malformed`, `multiple_records_detected`, `enforcement_weakened`, `external_rua_unauthorised`); one occurrence → one alert; replay adds none | Availability degradation alerts; duplicate alert; a sixth subtype alerts |
| D7-B | **7-B** managed-case lifecycle | Open a DMARC case from the stable condition, transition it canonically | Case **manually** created (never auto-opened); `createManagedCase`/`canTransitionCase` only; verification **system-only** (customer `verify` → refused); recurrence reopens the stable condition | Auto-opened case; customer self-verifies; new identity on recurrence |
| D7-C | **7-C** RUA destination authorisation | External destination with/without a valid authorisation record, plus a timeout case | `authorized` / `unauthorized` / **`unavailable` on timeout — never `unauthorized`**; any-valid-record authorises; second-hop override refused; conflicting overrides unresolved (no arbitrary pick) | Timeout mapped to unauthorised; arbitrary override selection; "reports confirmed delivered" |
| D7-D | **7-D** Hosted-DMARC routing + reconciliation | Verify the currently authorised/manual behaviour only | **Autopilot stays SUSPENDED**; remediation remains **suggestion-only** ("not applied by CyberMeters"); the RUA ingest routing rule is verified to exist for every advertised RUA token, and the known routing drift (DNS token advertised without a matching Email Routing rule → reports silently dropped) is reconciled; orphan rules identified | Autopilot reactivated; any DNS mutation by the product; drift left unreconciled |
| D7-E | **7-E** child / deep-label RFC 9989 | Existing child (inherits `sp`), nonexistent child (`np`, NXDOMAIN), deep-label tree walk | Correct inheritance provenance; `NXDOMAIN ≠ NODATA`; walk ≤8 queries with the shortcut; `t=y` lowers the requested policy one level (§4.7); legacy `pct` observed but **never applied** | Wrong provenance; NXDOMAIN/NODATA collapsed; >8 queries; `pct` affects policy |
| D7-F | **7-F** second-tenant isolation | Second workspace requests the DMARC observation/event/case/snapshot with **exact IDs** | Denied with the **same** response as nonexistent (non-enumerating) | Any cross-tenant read or existence oracle. **Record as Item 7 evidence even if executed within §8/X4** |
| D7-G | **7-G** presentation / UX | Walk the customer DMARC surfaces | Requested policy ≠ receiver enforcement wording; `absent ≠ unavailable`; no "full DMARC protection"/"enforcement proven"/"receivers are blocking" | Any prohibited claim; missing/incomplete rendered healthy |
| D7-H | **7-H** parity + reconciliation | Compare API · UI · alert · snapshot · Executive Report · PDF · technical appendix for one state | All agree on effective policy, source, inheritance, `t`, legacy `pct`, RUA states, completeness, Evidence Grade, methodology; D1/R2 hashes reconcile; historical snapshot byte-identical after rendering | Any divergence; renderer re-derives policy; historical bytes change |

**7-I (isolated-namespace cleanup) is NOT executed here.** Implementation owner is **Item 13 —
Dead code / cleanup**. Item 14's only duty:

| # | Verify-only | Expected | FAIL |
| --- | --- | --- | --- |
| D7-I-verify | After Item 13 has run, confirm **no customer-facing namespace drift remains** (no acceptance-fixture hostnames, RUA tokens, orphan routing rules or test artefacts visible on any customer surface, report, alert or PDF) | Clean customer-facing surfaces; retained history intact | Any fixture artefact visible to a customer. If Item 13 has not run → **NOT TESTED**, never PASS |

**Item 5 boundary preserved:** inbound RUA evidence stays **observational/non-authoritative** —
it cannot drive DNS truth, readiness, business risk, case verification or authoritative alerts,
regardless of what this session observes.

---

## 8. 14-DX · Cross-domain scan degradation & budget honesty

**Owner of the Item 5 slow-TLS live fixture** (which does **not** belong to the CT interlock).
Non-blocking by its current definition — **but it may never inherit PASS without execution or a
named residual-backlog result.**

| # | Step | Expected honest result | FAIL |
| --- | --- | --- | --- |
| DX1 | Real slow-TLS live fixture | The slow upstream degrades **only its own signal** | A slow TLS upstream marks sibling modules healthy |
| DX2 | Sibling isolation | Non-TLS sibling signals remain independently publishable | One slow upstream erases other reliable signals |
| DX3 | Deadline classification | The cut is classified correctly (`deadline_exceeded` / `incomplete` / `unavailable`), not silently "ok" | Misclassified or absent telemetry |
| DX4 | Partial-scan honesty | A partial scan **reads** partial to the customer — no "score 95 / excellent"-style wording without disclosing degraded monitoring | Partial presented as a clean result |
| DX5 | Envelope integrity | The 19-second whole-scan envelope holds; finalisation reserve untouched | Envelope breach or orphaned `running` scan |
| DX6 | Completion-rate record | Session complete/partial ratio recorded alongside the CT interlock's own comparison | No number recorded |

**Boundary:** the provider `429` observation and the **naturally observed** CT blackout are
**not** in 14-DX — they close inside the CT Provider Resilience interlock (R1–R3) production
comparison pack.

---

## 9. Cross-domain acceptance gates (apply to both tracks)

| # | Gate | Evidence | FAIL |
| --- | --- | --- | --- |
| X1 | **No false healthy** | No `unknown`/`unavailable`/`incomplete` renders healthy/passed on any surface | One instance |
| X2 | **No false remediation** | No disappearance, customer note, RUA report or bare scan completion closes a case | One instance |
| X3 | **No false negative buried** | Real exposures surface loudly; low confidence ≠ low visibility | A real issue visible only at a level nobody reads |
| X4 | No cross-tenant leakage | Second workspace denied identically to nonexistent, even with exact IDs (**also record per-item attribution — see D7-F, B10**) | Any leak or existence oracle |
| X5 | Snapshot/API/report/PDF parity | One projection; renderers do not re-derive verdicts; historical snapshots byte-identical (re-hash after rendering) | Divergence or historical mutation |
| X6 | Alert & case lifecycle | One occurrence → one alert → one case link; replay produces no duplicates; recurrence reopens the stable condition | Duplicate alert/case |
| X7 | Budget & completeness | 19 s envelope intact; no duplicate CT lookup; record the session's complete/partial ratio | Envelope breach |
| X8 | D1/R2 reconciliation | Snapshot hashes match; no orphans; no stuck `running` scan | Mismatch |
| X9 | **Rollback proof** | Rehearse rollback to the recorded Worker version; verify health/readiness; additive schema and append-only evidence retained | Rollback fails or destroys evidence |

---

## 10. Evidence bundle — one per track

Per step: UTC timestamp · operator · exact scan/observation/event/alert/case IDs · snapshot id
+ SHA-256 · R2 keys · authoritative DNS transcripts (before/after, all authoritative NS, TTLs)
· certificate fingerprint/serial/issuer + CT reference · API/UI/PDF captures (secrets redacted)
· Worker deployment IDs · module telemetry (durations, outcomes, provider states) · the exact
approval given for each irreversible action.

Store **outside** the product repository; record only hashes/paths in the canonical record.
**Keep the 14-S and 14-D bundles separate**, and inside 14-D keep per-item attribution
(14-D7 / 14-D8 / 14-D9 / 14-D10) so no item's evidence is absorbed by a shared test.

---

## 11. Decision templates

### 11.1 Track 14-S

```
ITEM 14-S — FOUNDER SECURITY ACCEPTANCE DECISION

Proven against build (exact):   ____________________   ← verdict is valid for THIS build only
scan-api live / rollback:       ____________ / ____________
email-ingest live / rollback:   ____________ / ____________

14-S0 Acceptance Package reconciliation (line by line — NO blanket retroactive PASS):
   Brand Protection (PR-A/B/C)   PASS | PASS WITH BACKLOG | NOT TESTED | BLOCKED
        (full-chain acceptance itself is owned by 14-D8 — not closed here)
   Shadow IT Alert Trust         PASS | PASS WITH BACKLOG | NOT TESTED | BLOCKED
   Weekly Digest Truth           PASS | PASS WITH BACKLOG | NOT TESTED | BLOCKED
   A6 Related Changes Phase 2    PASS | PASS WITH BACKLOG | NOT TESTED | BLOCKED
   "Nothing here is PASS" statement removed / historically qualified:  YES | NO
   (each row records: deployed SHA/deployment · production evidence · acceptance date · blockers)

S1 A6 viewer            PASS | FAIL | NOT TESTED
S2 Microsoft SSO        PASS | FAIL | NOT TESTED
S3 MFA with SSO         PASS | FAIL | NOT TESTED
S4 Reset revocation     PASS | FAIL | NOT TESTED
S5 Invitations          PASS | FAIL | NOT TESTED
S6 Deleted workspace    PASS | FAIL | NOT TESTED
S7 API-token lifecycle  PASS | FAIL | NOT TESTED
S8 Case ownership       PASS | FAIL | NOT TESTED
S9 Branded PDF access   PASS | FAIL | NOT TESTED

Blockers:                       ____________________
Accepted backlog:               ____________________
14-S RESULT:                    PASS | PASS WITH BACKLOG | FAIL
Re-validation required at Item 18 if the auth/tenant/case/report surface changes:  YES
```

### 11.2 Track 14-D

```
ITEM 14-D — DEFERRED DETECTION LIVE ACCEPTANCE DECISION

Proven against build (exact):   ____________________
Migrations applied:             ____________________
Interlock R1-R3 complete:       YES | NO   (NO ⇒ 14-D BLOCKED)
Scan completion rate observed:  ____ complete / ____ total

14-D7  Item 7  DMARCbis         PASS | PASS WITH BACKLOG | FAIL | BLOCKED | NOT TESTED
   7-A __ 7-B __ 7-C __ 7-D __ 7-E __ 7-F __ 7-G __ 7-H __
   7-I verify-only (Item 13 done?)  PASS | NOT TESTED
14-D8  Brand full-chain + Item 8 IDN   PASS | PASS WITH BACKLOG | FAIL | BLOCKED | NOT TESTED
   Full-chain controlled scan actually run (F1-F8):  YES | NO
   Public-beta blocker (CHANGELOG) now closed by evidence:  YES | NO — stays OPEN
   8-A MSP parity: BLOCKED unless a real entitled MSP account exists (never from a 401)
   8-B __ 8-C __
14-DX  Scan degradation & budget honesty  PASS | PASS WITH BACKLOG | FAIL | NOT TESTED
   DX1 slow-TLS live fixture executed:  YES | NO (non-blocking, but never a silent PASS)
   DX4 partial-scan reads partial to the customer:  YES | NO
14-D9  Item 9  Certificates     PASS | PASS WITH BACKLOG | FAIL | BLOCKED | NOT TESTED
   C9 non-Worker TLS probe:  MEASURED (n=__ unknowns convertible) | NOT MEASURED
14-D10 Item 10 Attack Surface   PASS | PASS WITH BACKLOG | FAIL | BLOCKED | NOT TESTED
   A11 ~48 h removal-confirmation delay acceptable:  YES | NO

Cross-domain X1-X9:             PASS | FAIL  (list failures)
Irreversible actions taken:     ____________________  (CT entries are permanent)
Blockers:                       ____________________
Accepted backlog (named):       ____________________
14-D RESULT:                    PASS | PASS WITH BACKLOG | FAIL | BLOCKED
```

### 11.3 Item 14 overall closure

```
ITEM 14 — OVERALL CLOSURE

14-S result:   ____________________  (build: __________)
14-D result:   ____________________  (build: __________)

Item 14 closes ONLY when both tracks carry an explicit result.
14-S PASS + 14-D BLOCKED/NOT TESTED  =>  Item 14 is NOT closed.

Acceptance-debt register (§0.3) — every row needs a result or a named backlog entry:
  7-A..7-H (14-D7) __            7-I (Item 13) __
  8-A (Item 16) __  8-B __  8-C __
  Item 9 C9 TLS-probe measurement (14-D9) __     Item 10 A11 48h delay (14-D10) __
  CT interlock R1-R3 (pre-Item-11) __
  14-S0 Acceptance Package reconciled line-by-line __
  Brand full-chain acceptance (14-D8) — public-beta blocker OPEN | CLOSED __
  Item 5: provider 429 + natural CT-blackout (CT interlock) __
  Item 5: slow-TLS live fixture (14-DX) __
  MSP portfolio acceptance (Item 16) __
Any row without a result  =>  PASS WITH BACKLOG naming it, or NOT CLOSED. Never a silent PASS.

ITEM 14 OVERALL:        PASS | PASS WITH BACKLOG | NOT CLOSED
Scope actually accepted (write it out):  ____________________
Item 15 (independent pentest) may start:  YES | NO
```

**Rules:** a gate with no evidence is **NOT TESTED**, never PASS. A blocked capability is
**BLOCKED**, never inferred from a `401`. `PASS WITH BACKLOG` requires every residual named
explicitly. Nothing here authorises describing the platform as live-accepted beyond the scope
written on the decision line.

---

## 12. Cleanup & disposition

Restore fixture DNS/HTTP to the captured baseline · revoke fixture certificates where
appropriate (**CT entries remain permanent — accepted at purchase time**) · disable fixture
schedules · restore notification settings · classify remaining fixture candidates through the
canonical audited workflow · **delete no evidence, no events, no snapshots, no case history** ·
cancel any temporary entitlement only after confirming retained evidence is still readable ·
record final Worker/Pages IDs and the exact restored RRsets.

**Namespace cleanup (7-I) is Item 13's work, not Item 14's** — Item 14 only records the
verify-only result from §7 (`D7-I-verify`).
