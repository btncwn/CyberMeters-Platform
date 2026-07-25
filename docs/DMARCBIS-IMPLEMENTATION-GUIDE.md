# CyberMeters Item 7 — DMARCbis implementation guide

Status: Design accepted in principle; implementation hold
Founder ruling: 25 July 2026
Canonical design baseline: `0d9881faf8eac248ed1c6b4e37670b1c1832dbc5`
Implementation authorised: No

This is the implementation-ready technical design for RFC 9989, RFC 9990, and
the deliberately limited RFC 9991 boundary. Decisions and founder rulings are in
[`ADR-004-dmarcbis.md`](adr/ADR-004-dmarcbis.md). Future live acceptance is in
[`DMARCBIS-ACCEPTANCE-GUIDE.md`](DMARCBIS-ACCEPTANCE-GUIDE.md).

## 1. Evidence markings and design laws

- **[REPOSITORY-VERIFIED]** — directly traced at the canonical baseline.
- **[RFC-VERIFIED]** — checked against primary RFC Editor text at the cited section.
- **[FOUNDER-RULING]** — settled by the founder directive dated 25 July 2026.
- **[DESIGN DECISION]** — required future behavior; not current production behavior.
- **[NOT DIRECTLY VERIFIED]** — not proven from the repository, primary RFC text,
  or production in this design-only episode.
- **[IMPLEMENTATION GATE]** — must pass after the hold is lifted.

The following product laws are unchanged:

- incomplete, unsupported, malformed, or unavailable evidence is not healthy;
- the frontend does not derive verdicts;
- all remediation resolves through the Canonical Remediation Registry;
- all managed cases use `createManagedCase(...)` and `canTransitionCase(...)`;
- a completed scan, note, or bare boolean cannot verify a fix;
- immutable historical evidence is not recomputed or rewritten;
- Item 5 source authority is independent of RFC 9990 destination authorisation;
- Item 6 Evidence Grade remains unchanged;
- Hosted-DMARC remains suggestion-only under suspended Gate 1/2.

## 2. Exact pre-change map

All repository statements in this table are **[REPOSITORY-VERIFIED]** at
`0d9881faf8eac248ed1c6b4e37670b1c1832dbc5`.

| Current path | Proven runtime behavior | RFC 7489-era assumption or gap | DMARCbis delta | Work class / compatibility risk |
| --- | --- | --- | --- | --- |
| `workers/scan-api/src/engines/scan-engine.js` | Calls `runEmailModule` in the normal Phase-1 parallel group under a 750 ms `email_security` cap. | DMARC shares one module race with SPF, BIMI, and a DKIM selector sweep. | Add a separate capped `dmarc_core` Phase-1 peer and merge its result into Email Protection after settlement. | Runtime/budget; critical. |
| `workers/scan-api/src/engines/email-scan.js` | Queries only `_dmarc.<input-domain>` through Cloudflare DoH; filters case-insensitively for `v=dmarc1`; chooses the first; semicolon-splits; duplicate tags overwrite. | Exact-only, first-record-wins, case-insensitive version, last-tag-wins. | Remove the legacy DMARC network decision from this module after the canonical caller is live; keep compatibility projection only. | Parser/integration; critical. |
| `workers/scan-api/src/engines/dns.js` | Supplies current DNS resolution helpers. | DMARC result does not retain the full rcode/TTL/chunks/truncation/error contract needed for `np`. | Add a raw observation adapter with exact NXDOMAIN, NODATA, response, and transport states. | Observation. |
| `workers/scan-api/src/engines/dns-scan.js` | Makes Cloudflare and Google DNS checks, including exact DMARC questions, but does not feed a canonical DMARC policy resolver. | Duplicate questions and no decisive-policy reconciliation. | Reuse one invocation cache; corroborate only the decisive record. | Observation/budget. |
| `workers/scan-api/src/engines/scan-budget.js` | Whole scan: 24,000 ms ceiling, 19,000 ms executable, 5,000 ms finalisation; module caps include DNS 750, Email 750, SSL 9,000, Subdomains 12,000, exposure 2,500, Phase 5 1,000. It also contains `SubrequestBudget`, `makeDnsCache`, and `dnsCacheKey`. | No separately guaranteed DMARC core; ordinary path does not share the cache across all DNS consumers. | Add 750 ms core allocation, 600 ms optional RUA allocation, shared question cache, exact accounting and deterministic launch refusal. | Runtime; critical. |
| `workers/scan-api/src/engines/reserved-scan.js` | Under reserved mode, root/www A plus eight critical-prefix A questions precede exposure; exposure consumes dynamic capacity before optional modules. | Email/DMARC can be skipped after exposure consumes capacity. | Run/reserve DMARC core before exposure; external RUA remains optional. | Runtime/capacity; critical. |
| `workers/scan-api/src/engines/ct-provider-cache.js` | Invocation-scoped CT cache stores in-flight provider work and shares it between SSL and subdomain consumers. | DNS consumers do not yet use the equivalent pattern end-to-end. | Use this as the concurrency/dedupe pattern for DNS questions. | Integration. |
| `workers/scan-api/src/engines/dmarc-state.js` | Defines nine percentage-era states, including partial/full quarantine and reject. | `pct` participates in current strength semantics; no inheritance or `t`. | Keep only as a legacy adapter; canonical state derives `p/sp/np/t`. | Derivation; critical. |
| `workers/scan-api/src/engines/email-intel.js` | Enriches current exact DMARC state and participates in Phase 5. | Can derive a second compatibility interpretation. | Consume canonical DMARC evidence; never independently reinterpret it. | Derivation/presentation. |
| `workers/scan-api/src/engines/dmarc-canonical-consumers.js` | Maps reject-era states to healthy/fully protected presentation. | Published preference is presented too much like receiver action. | Use requested-policy wording and stored provenance/limits. | Presentation; high. |
| WHOIS/Hosted/Brand root helpers | WHOIS has UK-oriented registered-domain logic; `rua-routing.js` has a provisioning suffix heuristic; Related Changes has a registrable-root key. | These can be mistaken for a DMARC organisational-domain authority. | Do not reuse or modify them. DMARC uses RFC 9989; Related Changes retains its old key. | Compatibility; critical. |
| `workers/scan-api/src/engines/rua-routing.js` | `ensureExternalReportAuthorization` is a provisioning mutation for CyberMeters' own inbound route. | Hosted routing verification can be confused with general RFC 9990 authorisation. | Add a new read-only resolver; never call the provisioning mutation from scanning. | Trust/lifecycle; critical. |
| Hosted-DMARC paths | Can verify that a CyberMeters RUA string is present; historic policy-ramp and DNS mutation helpers exist, but automation is ineligible under Gate 1/2. | Hosted `verified` does not mean general external authorisation or DMARCbis compliance. | Preserve existing status; add read-only interpretation only. | Lifecycle; critical. |
| `workers/scan-api/src/lib/dmarc-ingest.js` | Accepts old/new XML namespaces but extracts legacy `p/sp/pct` metadata and source-scoped ingest state. | Namespace acceptance is not full RFC 9990 persistence. | Parse/preserve namespace, version, discovery method, `np`, `fo`, and testing; authority remains unchanged. | Parser/persistence/trust. |
| `database/migrations/054-dmarc-sender-intelligence.sql` | Stores aggregate `policy_p`, `policy_sp`, and `policy_pct`. | No RFC 9990 discovery/testing fields. | Add nullable columns only; retain `policy_pct`. | Additive schema. |
| `database/migrations/100-aggregate-report-ingest-state.sql` | Adds atomic aggregate ingest claiming. | None requiring a replacement. | Reuse unchanged. | Compatibility. |
| `workers/scan-api/src/engines/report-snapshot.js` | Writes immutable outer schema-v1 snapshots, R2-first, with append-only supersession. Current DMARC assertions are exact-lookup scoped. | No lookup chain or DMARCbis effective-policy block. | Add nested `protocol_evidence.dmarc`; keep outer v1 and old bytes. | Persistence/history; critical. |
| Finding persistence in `scan-engine.js` | Findings get scan-random row IDs; remediation IDs include publish, enforce, reporting, single-record, and valid-record identities. | Random finding IDs are not occurrence identities. | Use deterministic DMARC condition IDs in lifecycle detail; preserve compatible remediation identities. | Lifecycle. |
| `database/migrations/088-email-protection-lifecycle.sql` | Creates the single append-only `email_protection_events` source. Row ID is occurrence identity; `created_at` is condition start. | DMARC DNS conditions are not yet a record family. | Add `record_type=dmarc_policy_condition` in application vocabulary; no table. | Lifecycle reuse; critical. |
| `workers/scan-api/src/engines/alert-occurrence.js` | `LIFECYCLE_EVENT_SOURCES.email_protection` already points to `email_protection_events`; exact workspace/record/recurrence lookup returns the latest occurrence. | None requiring a DMARC domain key or table. | Keep `domain_key=email_protection`; use a disjoint deterministic record ID. | Lifecycle reuse. |
| `database/migrations/089-website-security-lifecycle.sql` | Adds a condition/event pair only because Website Security had no stable continuity. Warns against a second occurrence clock. | Prior Item 7 design copied this pair despite Email already owning one source. | Do not copy it. A future projection needs measured proof and separate approval. | Schema/historical integrity. |
| `database/migrations/082-universal-managed-cases.sql` | Extends the shared managed-case substrate. | No DMARC-specific case storage needed. | Manual case eligibility links through the shared model. | Lifecycle. |
| Historical/posture event path | Coarse `email_dmarc_policy_changed` compares simple `p`/absence with 24-hour `event_type:hostname` dedupe. | A failed lookup can look like removal; no source or immutable evidence pair. | Add subtype predicates, before/after evidence, completeness suppression, and fingerprint dedupe. | Lifecycle; critical. |
| `workers/scan-api/src/engines/related-changes-adapter.js` | Maps the coarse event into existing bounded, non-causal correlation. | New protocol boundary could churn cluster identity if reused as a root. | Add eligible subtype mapping only; retain registrable-root correlation identity. | Lifecycle. |
| Scan/report/Email APIs | Expose exact-record statuses and fields including `policy`, `sp`, `pct`, `rua`, `record`, and `record_count`. | Existing names cannot safely carry inherited semantics. | Keep every legacy field; add one nested contract. | API; high. |
| Email/dashboard/report surfaces | `WorkspaceEmailProtectionPage.jsx`, `ScanDetail.jsx`, `IntelligencePage.jsx`, `ExecutiveReportV2.jsx`, and PDF paths contain percentage/enforcement/protection wording. | Published preference is presented as proven blocking/protection. | Render stored requested policy, provenance, completeness, and historical notice. | Presentation; high. |
| Monitoring | DMARC failure can be hidden by whole-email-module success. | Missing evidence can appear healthy. | Add component completeness and DMARC monitoring state. | Monitoring; critical. |

Runtime reachability conclusions:

- `np`, `t`, and `psd` names do not prove current derivation; no canonical
  derivation exists.
- Current XML namespace acceptance does not prove RFC 9990 fields are stored.
- Hosted route verification is not RFC 9990 authorisation.
- Current resolver-disagreement helpers are not on the production DMARC
  decision path.
- Current non-enumerable `dmarc_state` is not durable report evidence.
- No generic observation/condition table exists; domain lifecycle storage is
  deliberately domain-specific.

## 3. Canonical component architecture

The minimum stack is:

1. `DNS observation adapter` — bounded raw DNS results.
2. `DNS question cache` — invocation-scoped in-flight and completed dedupe.
3. `A-label canonicaliser` — exactly pinned `tr46@6.0.0`.
4. `Policy-record parser` — pure RFC 9989 policy candidate parser.
5. `Authorisation-record parser` — separate RFC 9990 rules.
6. `Tree-walk planner/resolver` — policy and organisational-domain discovery.
7. `Existence resolver` — NXDOMAIN versus NODATA when `np` applicability matters.
8. `Effective-policy resolver` — declared and testing-adjusted requested policy.
9. `External destination resolver` — per-URI RFC 9990 state.
10. `Evidence adapter` — unchanged Item 6 fields and grade.
11. `Legacy adapter` — exact-record compatibility only.
12. `R2/snapshot writer` — one raw/derived protocol evidence source.
13. `Email lifecycle adapter` — stable condition identities in migration 088's
    existing event table.

The canonical data flow is:

`DNS -> raw observation -> parse -> discovery -> derivation -> Evidence Grade -> R2 report -> canonical snapshot -> API/readers -> lifecycle/presentation`

RUA ingestion is a separate observational flow:

`inbound report -> source/trust gate -> bounded XML parse -> D1 aggregate metadata/records -> observational sender intelligence`

It does not flow backward into DNS truth.

## 4. Parser-freeze RFC checklist

P1 may not freeze until a reviewer opens the primary RFC text and records a pass
for each row. This checklist is not satisfied by this document alone.

| Clause | Required implementation meaning | Primary source | Current design check |
| --- | --- | --- | --- |
| RFC 9989 §4.7 | `v` first and case-sensitive; `p/sp/np/t/psd`; `t` default and exact testing mapping. | [§4.7](https://www.rfc-editor.org/rfc/rfc9989.html#section-4.7) | **[RFC-VERIFIED]** on 25 Jul 2026. |
| RFC 9989 §4.8 | Formal grammar; unknown tags ignored; syntax errors use defined defaults or are ignored. | [§4.8](https://www.rfc-editor.org/rfc/rfc9989.html#section-4.8) | **[RFC-VERIFIED]** on 25 Jul 2026. |
| RFC 9989 §4.10 | Eight-query maximum, deep-label shortcut, multiplicity, `psd` stop. | [§4.10](https://www.rfc-editor.org/rfc/rfc9989.html#section-4.10) | **[RFC-VERIFIED]** on 25 Jul 2026. |
| RFC 9989 §4.10.1 | Exact/org/PSD precedence; `p/sp/np`; invalid-policy plus valid-RUA fallback. | [§4.10.1](https://www.rfc-editor.org/rfc/rfc9989.html#section-4.10.1) | **[RFC-VERIFIED]** on 25 Jul 2026. |
| RFC 9989 §4.10.2 | Organisational-domain selection by `psd=n`, `psd=y`, highest valid record, then initial target. | [§4.10.2](https://www.rfc-editor.org/rfc/rfc9989.html#section-4.10.2) | **[RFC-VERIFIED]** on 25 Jul 2026. |
| RFC 9989 Appendix A.4 | Any RR means exists; NXDOMAIN means nonexistent; NODATA means existing name/no queried RR type. | [Appendix A.4](https://www.rfc-editor.org/rfc/rfc9989.html#appendix-A.4) | **[RFC-VERIFIED]** on 25 Jul 2026. |
| RFC 9989 Appendix A.6 | `pct` removed; `t=y/n` analogous to old `pct=0/100`, not a retained percentage. | [Appendix A.6](https://www.rfc-editor.org/rfc/rfc9989.html#appendix-A.6) | **[RFC-VERIFIED]** on 25 Jul 2026. |
| RFC 9990 §4 | External destination comparison, constructed name, A-label, temporary error, at-least-one-valid rule, same-host override. | [§4](https://www.rfc-editor.org/rfc/rfc9990.html#section-4) | **[RFC-VERIFIED]** on 25 Jul 2026. |
| RFC 9990 §§3–3.5 | New XML namespace/metadata, duplicate/report transport semantics, forged-data risk. | [§3](https://www.rfc-editor.org/rfc/rfc9990.html#section-3) | **[RFC-VERIFIED]** at design level. |
| RFC 9991 §§5, 7 | Optional, privacy-sensitive, externally authorised, rate-limited failure reports. | [§5](https://www.rfc-editor.org/rfc/rfc9991.html#section-5), [§7](https://www.rfc-editor.org/rfc/rfc9991.html#section-7) | **[RFC-VERIFIED]** for the exclusion boundary. |

Erratum 8995 is **[NOT DIRECTLY VERIFIED]** as accepted normative text. The
conservative decision does not depend on its status: retain NXDOMAIN/NODATA and
DNSSEC flags, but make no authenticated-denial claim.

## 5. Canonical DNS name and raw observation contract

### 5.1 A-label conversion

The future parser uses exactly pinned `tr46@6.0.0`, non-transitional processing:

- `checkBidi=true`;
- `checkHyphens=true`;
- `checkJoiners=true`;
- `useSTD3ASCIIRules=true`;
- `verifyDNSLength=true`;
- `transitionalProcessing=false`;
- `ignoreInvalidPunycode=false`.

Processing order:

1. Preserve the submitted Unicode/raw form.
2. Trim surrounding presentation whitespace only at the API boundary.
3. Remove one DNS root trailing dot for canonical comparison while recording it.
4. Reject empty labels, embedded root labels, IP literals where a DNS host is
   required, invalid Unicode, and invalid A-labels.
5. Convert through `tr46`.
6. Lower-case the resulting A-label.
7. Validate label and full-name wire limits again after constructed labels such
   as `_dmarc` and `_report._dmarc` are added.

No Unicode display name is used as a DNS cache key or lifecycle identity.

### 5.2 Raw DNS result

Every question returns:

- canonical qname and qtype;
- resolver identity;
- requested DNSSEC profile;
- issued/completed timestamps and elapsed time;
- transport status;
- DNS rcode;
- answer and authority sections needed for classification;
- TTL and negative TTL when available;
- ordered TXT RR objects, each retaining ordered character-string chunks and
  the concatenated value;
- truncation/TC status and retry status;
- malformed-response diagnostics;
- cache disposition (`miss`, `in_flight_hit`, `completed_hit`);
- whether the result was logically required, prefetched, decisive, or
  corroborating.

Outcome enum:

- `success`;
- `nodata`;
- `nxdomain`;
- `servfail`;
- `refused`;
- `timeout`;
- `transport_error`;
- `malformed_response`;
- `truncated_unresolved`;
- `cancelled_deadline`;
- `not_issued_budget`.

Only `success`, `nodata`, and `nxdomain` are definitive DNS outcomes. Temporary,
malformed, truncated, cancelled, and non-issued states are unavailable/incomplete,
never absent.

### 5.3 Invocation cache

The cache key is:

`resolver|a-label-qname|QTYPE|dnssec-profile`

The producer inserts the promise before awaiting it. Concurrent consumers receive
the same promise. Completed failures are cached with their exact failure type.
The cache is destroyed with the scan invocation. Observed TTLs are evidence, not
permission for cross-scan reuse.

The cache owns a scan-global `unique_question_issued` callback. Exactly the first
miss increments the global capacity/outbound ledger; cache hits record consumer
diagnostics but do not spend again. The module whose miss created the provider
request owns its per-module outbound attempt. This prevents both a hidden
subrequest and double accounting when DNS posture and DMARC core race for the
same question.

## 6. RFC 9989 discovery algorithm

### 6.1 Logical walk

For author domain `D`:

1. Plan the RFC sequence of no more than eight `_dmarc.<target>` names.
2. Logical ordinal 1 is always `_dmarc.D`.
3. At each target, preserve every TXT RR.
4. A policy candidate is a record whose first tag is exact, case-sensitive
   `v=DMARC1`.
5. Ignore non-current TXT for policy selection but keep it in evidence.
6. If more than one current-version candidate exists, mark the target
   `multiple` and discard all candidates at that target.
7. If the sole candidate contains `psd=y` or `psd=n`, stop logical evaluation.
8. For fewer than eight labels, the next target removes the leftmost label.
9. For eight or more labels, the second target jumps to seven labels; later
   targets remove one leftmost label.
10. Stop when the RFC condition is reached or no labels remain.

Operational scheduling may prefetch planned parent questions inside the 500 ms
primary sub-budget. The evidence must retain both planned ordinal and
`logically_used`. A result after the first normative stop:

- is marked `prefetched_not_logically_required`;
- cannot affect records, organisational domain, policy, findings, events, or
  Evidence Grade;
- still counts against the eight-question cap and subrequest accounting.

This scheduling optimisation does not change the RFC evaluation order.

### 6.2 Policy source precedence

After a complete logical walk:

1. a valid record at the author domain wins;
2. otherwise the organisational-domain record wins;
3. otherwise the PSD record wins;
4. otherwise no DMARC mechanism applies.

An exact valid record determines the policy source but does not by itself always
determine the organisational domain.

### 6.3 Organisational-domain selection

Process domains with valid records from longest to shortest:

1. the first valid `psd=n` domain is the organisational domain;
2. a `psd=y` above the walk start makes the domain one label below it the
   organisational domain;
3. otherwise choose the valid-record domain with the fewest labels;
4. if none is found, return the initial target with
   `provenance=fallback_initial_target`.

The fallback is not labelled “registered domain” and is not a registration claim.

### 6.4 Existence

An existence question is needed only when `np` might be applicable. Reuse a
complete cached A/AAAA/other scan observation when it proves the author name's
existence; otherwise issue one bounded A question.

- NXDOMAIN → `nonexistent`;
- NODATA/NOERROR → `exists`;
- any RR at the name → `exists`;
- temporary/malformed/truncated result → `unknown`.

Unknown existence prevents `np` versus `sp/p` selection. It does not default to
either branch.

### 6.5 Decisive corroboration

The primary resolver supplies the canonical walk. The secondary resolver checks
the decisive policy TXT name only.

- same candidate set → `corroborated`;
- definitive contradictory set → `resolver_disagreement`, withhold policy and
  lifecycle conclusions;
- temporary secondary failure → retain the primary raw/derived result but mark
  corroboration and policy completeness incomplete, cap customer publication to
  the allowed Evidence Grade, and suppress risk lifecycle output.

No second complete tree walk is required.

## 7. Strict parsing and deterministic multiplicity

### 7.1 Policy records

- Concatenate TXT chunks in DNS order; preserve chunks and concatenated value.
- Exact `v=DMARC1` must be first and case-sensitive.
- Duplicate tags invalidate the tag list.
- Unknown tags are preserved and ignored.
- Missing `p` defaults to `none`.
- Invalid `p`, `sp`, or `np` plus at least one syntactically valid `rua` URI uses
  the RFC 9989 §4.10.1 fallback `p=none`.
- Invalid policy without a valid `rua` means no DMARC processing.
- `pct` is preserved as an unknown legacy tag and is never applied.
- Obsolete URI `!size` syntax is preserved and ignored.
- Unsupported URI schemes are preserved and ignored by CyberMeters.
- No parser truncation is allowed.

### 7.2 Candidate-set table

| Candidate set at one target | Raw state | Policy treatment |
| --- | --- | --- |
| No current-version candidate | `absent` or `non_dmarc_txt_only` | Continue. |
| One valid candidate | `single_valid` | Eligible. |
| One candidate with RFC-defined defaults | `single_valid_with_defaults` | Apply defaults; retain diagnostics. |
| One fatal candidate | `single_invalid` | Not usable at this target; continue. |
| Two valid-looking candidates | `multiple` | Discard both; continue. |
| One valid plus one malformed current-version candidate | `multiple_mixed` | Discard both; continue. |
| One valid plus unrelated TXT | `single_valid_with_non_dmarc_txt` | Use valid candidate. |
| Several malformed current-version candidates | `multiple_invalid` | Discard all; continue. |
| Duplicate tag in sole candidate | `single_invalid_duplicate_tag` | Do not use. |
| Oversized or unresolved truncation | `incomplete_oversized` or `truncated_unresolved` | No policy conclusion. |

Policy-record multiplicity is not reused for RFC 9990 authorisation records.

### 7.3 URI operational limits

Approved beta support limits:

- 10 raw report URI entries;
- 5 unique external destination hosts;
- 2,048 characters per URI;
- 64 KiB per concatenated TXT RR;
- 256 KiB aggregate DMARC DNS evidence per scan.

These are product limits, not RFC-invalidity claims. Over-bound values are counted
and safely diagnosed. The unprocessed set makes the affected completeness
`incomplete`; no prefix may be described as the whole set.

## 8. Effective requested policy

Canonical fields:

- `declared_policy` — selected `p`, `sp`, or `np` before `t`;
- `declared_policy_tag`;
- `declared_policy_source_domain`;
- `testing` — `y`, `n`, defaulted `n`, invalid, or absent/raw;
- `effective_requested_policy`;
- `testing_adjustment`;
- `inheritance_reason`;
- component completeness and provenance.

### 8.1 `t` rule

**[RFC-VERIFIED]** RFC 9989 §4.7 says the expected applied policy under `t=y`
is “one level below the specified policy” and explicitly gives:

| Declared selected policy | `t` | Effective requested policy |
| --- | --- | --- |
| `none` | `y` | `none` |
| `quarantine` | `y` | `none` |
| `reject` | `y` | `quarantine` |
| any valid policy | absent/default `n` | unchanged |

This ladder is RFC behavior, not a CyberMeters policy. It does not prove a
receiver used that treatment. `t` does not affect reporting.

### 8.2 Outcome table

| Situation | Raw observation | Effective result/provenance | Customer state | Alert/remediation permission |
| --- | --- | --- | --- | --- |
| Exact valid record | Preserve exact RR/tags. | Exact `p`, default `none` if absent, then `t`. | `published_exact_policy` | Findings allowed by strength; no change alert without complete previous evidence. |
| Existing child, no exact, org/PSD record | Exact definitive absence plus source. | `sp`, else source `p`. | `inherited_existing_subdomain` | Weak-policy remediation may be suggested. |
| Nonexistent child, no exact, org/PSD record | Exact NXDOMAIN plus source. | `np`, else `sp`, else `p`. | `inherited_nonexistent_subdomain` | Same; provenance mandatory. |
| `t=y` | Raw `t=y`. | RFC ladder applied. | `testing_adjusted` | Disclose declared and effective requested policy. |
| Complete walk, no policy | All required results definitive. | `null`. | `no_applicable_policy` | Missing-policy finding/remediation allowed. |
| Exact malformed/multiple, valid parent | Exact defect plus complete source. | Inherited source policy. | `inherited_with_exact_configuration_error` | Defect finding plus inherited explanation; alert only on approved regression. |
| Invalid policy plus valid `rua` | Invalid tag retained. | RFC fallback `none`. | `policy_error_fallback_none` | Actionable configuration remediation. |
| Invalid policy without valid `rua` | Fatal record retained. | `null`. | `no_dmarc_processing_invalid_policy` | Malformed finding, never missing. |
| Required primary DNS temporary failure | Error evidence. | `null`. | `policy_unavailable` | Monitoring limitation only. |
| Decisive resolver contradiction | Both answers retained. | `null`. | `resolver_disagreement` | Monitoring limitation only. |
| Secondary corroboration unavailable | Primary answer retained. | Derived result with incomplete corroboration. | `policy_incomplete_corroboration` | No alert/case verification or authoritative healthy claim. |

`p=none` is rendered “no-action policy”. It does not by itself prove the broader
RFC Monitoring Mode conditions.

## 9. Two-tier budget contract

### 9.1 Whole-scan proof

**[REPOSITORY-VERIFIED]** Existing maximum serialized caps are:

- Phase 1: maximum peer cap 12,000 ms;
- takeover: 750 ms;
- asset exposure: 2,500 ms;
- Phase 5: 1,000 ms;
- cloud discovery: 500 ms.

The new core is a 750 ms Phase-1 peer, so it does not increase the 12,000 ms
Phase-1 maximum. The optional 600 ms external phase is serialized only when
launch gates pass.

Normal-path ordering is exact: parallel Phase 1 (including core), takeover,
asset exposure, Phase 5, optional external-RUA gate/phase, cloud discovery, then
the existing finalisation path. Reserved mode executes/reserves core before its
dynamic exposure calculation; its external phase is still attempted only at the
post-Phase-5 gate.

Exact cap map:

| Signal/module | Wall-clock cap | Existing reserved-mode subrequest estimate or new exact reservation |
| --- | ---: | ---: |
| DNS posture | 750 ms | 18 |
| DNS brute-force | 750 ms | 24 |
| Existing Email signals (SPF/BIMI/DKIM after canonical DMARC extraction) | 750 ms | 24 retained conservatively |
| **New DMARC core** | **750 ms, Phase-1 parallel peer** | **10 exact logical maximum** |
| Technology detection | 500 ms | 4 |
| WHOIS intelligence | 2,000 ms | 4 |
| Headers | 1,200 ms | 6 |
| SSL | 9,000 ms | 6 |
| Subdomains | 12,000 ms | 6 |
| Subdomain takeover | 750 ms | 12 |
| Asset exposure | 2,500 ms | Live-metered; existing two-unit projection per admitted host |
| CVE intelligence | Shared 1,000 ms Phase-5 race | 4 |
| KEV intelligence | Shared 1,000 ms Phase-5 race | 4 |
| Email intelligence | Shared 1,000 ms Phase-5 race | 4 |
| **External RUA authorisation** | **600 ms optional phase** | **11 exact maximum per fully admitted host** |
| Cloud storage discovery | 500 ms | 12 |

The non-DMARC subrequest numbers are the existing conservative
`MODULE_SUBREQUEST_COST` contract, not newly claimed measurements. Core and
external figures are hard reservations. The default path uses completed outbound
accounting at the external gate; reserved mode uses its existing capacity ledger.
If accounting is incomplete because a module was abandoned or uninstrumented,
the external phase does not launch.

For the normal path, optional capacity is computed from the configured
`resolveScanCapacity` limit and safety margin minus scan-global unique outbound
attempts observed through the gate. P2 does not retroactively apply reserved-mode
gating to existing normal-path modules. If those modules have already exhausted
the conservative optional capacity, external authorisation is explicitly
incomplete and issues no question.

`12,000 + 750 + 2,500 + 1,000 + 600 + 500 = 17,350 ms`

That is 1,650 ms below the 19,000 ms executable ceiling and leaves the existing
5,000 ms finalisation reserve untouched.

### 9.2 Core allocation

| Core work | Wall-clock allocation | Logical question allocation |
| --- | ---: | ---: |
| Primary RFC 9989 exact/tree-walk batch | ≤500 ms | ≤8 TXT |
| Author-domain existence | Inside the same ≤500 ms batch | ≤1 DNS question |
| Secondary decisive-record corroboration | ≤150 ms | ≤1 TXT |
| A-label, planning, parsing, derivation, serialization | 25 ms engineering target | 0 |
| Guard/cancellation/final merge | 75 ms | 0 |
| **Hard total** | **750 ms** | **≤10** |

“Always deliver core” means every scan returns a structured core object within
the cap. A provider timeout returns `unavailable`/`incomplete`; it does not promise
that the network always yields a policy.

Against the traced normal-path DNS questions, the conservative worst incremental
physical total is eight because the exact primary TXT and author-domain A question
already exist in the current DNS set and become shared cache entries. This reuse is
an optimisation, not permission to budget fewer than ten logical questions.

Other Email signals retain their existing separate 750 ms / 24 estimated
subrequest cap. The legacy exact DMARC question is removed from `email-scan.js`
only when the canonical result is wired, preventing a third lookup.

### 9.3 Reserved-mode allocation

**[REPOSITORY-VERIFIED]** Reserved mode has a 50-class limit, 5-question safety
margin, and 45 usable units. Its deterministic initial discovery is root/www A
plus eight critical prefixes.

Future order:

1. create shared DNS cache and ledger;
2. root/www A discovery;
3. reserve all 10 logical core questions;
4. execute and account for the core;
5. critical-prefix discovery;
6. compute exposure capacity from actual unique spend after preserving the core
   guarantee;
7. run exposure and existing budget-gated modules;
8. attempt external RUA only if the complete host reservation fits.

Worst projected pre-exposure reservation is `2 + 10 + 8 = 20`, leaving 25 of 45
projected units, or 12 hosts under the existing two-unit projection. The
deterministic root/www/critical candidate set contains at most 10 hosts, so the
core reservation does not remove those candidates under that projection.
Existing redirect-tail/safety assumptions remain governed by the reserved-mode
work; Item 7 does not redesign them.

### 9.4 External RUA allocation

For each admitted unique external destination host, reserve the complete
worst-case host unit before issuing any question:

| Per-host work | Questions |
| --- | ---: |
| Primary destination organisational-domain walk | ≤8 TXT |
| Secondary decisive destination record | ≤1 TXT |
| Primary RFC 9990 authorisation name | 1 TXT |
| Secondary decisive authorisation name | 1 TXT |
| **Per-host reservation** | **≤11** |

Per-host/time schedule inside the optional 600 ms phase:

- A-label/plan: 25 ms target;
- primary destination walk batch: ≤300 ms;
- decisive destination corroboration: ≤100 ms;
- primary and secondary authorisation checks: ≤125 ms;
- parse/derive/guard: 50 ms;
- total hard cap: 600 ms.

Unique hosts are considered in first appearance order after URI normalisation.
The system reserves 11 units atomically for a host. If the reservation cannot be
made, that host and all later unadmitted hosts receive
`not_assessed_budget`, and overall RUA authorisation is incomplete. Same-domain
results may release unused authorisation units only after the relationship is
proven; launch decisions never rely on optimistic release.

Launch requires all of:

- core policy and organisational-domain dependencies sufficient for comparison;
- `deadline.canRun(600)`;
- complete outbound accounting up to the gate;
- enough remaining configured capacity for the entire next host;
- no scan cancellation;
- destination/URI bounds not exceeded.

Full external RUA on every scan is explicitly deferred to scan-architecture
capacity work. Item 7 never takes time or capacity from the finalisation reserve.

### 9.5 Deadline fixtures

| Fixture | Injected clock/provider behavior | Required result | Prohibited result | Required mutation |
| --- | --- | --- | --- | --- |
| `budget_complete` | Core primary settles by 300 ms; corroboration by 80 ms; external gate has ≥600 ms and ≥11 units; host settles by 500 ms. | Core complete ≤750 ms; admitted RUA complete ≤600 ms; total envelope ≤17,350 ms. | A new 15 s phase or finalisation-reserve use. | Raise core/external cap or remove global `canRun`; validator red. |
| `budget_core_only_degraded` | Core completes; external gate has 599 ms or fewer than 11 units. | No external DNS question issued; `rua_authorisation_completeness=incomplete`; reason `deadline_budget` or `subrequest_budget`; global scan may remain complete while DMARC authorisation monitoring is degraded. | Empty destination array interpreted as all authorised/healthy. | Allow one auth query before full reservation; validator red. |
| `budget_provider_timeout` | Required primary core batch reaches 500 ms cap. | Structured core within 750 ms; required component unavailable; effective policy null; external dependency skipped; no missing/removed/weakened event. | Scan overrun, false absence, `p=none`, or false healthy. | Convert timeout to empty answer; validator red. |

### 9.6 Scan-quality effect

- A core deadline/provider failure sets the DMARC required component incomplete
  and prevents an authoritative Email/DMARC healthy conclusion. The existing
  scan-quality resolver must see the required incomplete state.
- A complete core plus a budget-refused external phase does not turn every
  otherwise complete scan globally partial. It sets
  `rua_authorisation_completeness=incomplete`,
  `monitoring_state=monitoring_degraded` for that component, and suppresses every
  authorisation-dependent conclusion.
- Neither state can produce an empty-success RUA array, “all authorised”, a
  missing-policy conclusion, or a risk lifecycle event from unavailable data.

## 10. External aggregate-report authorisation

For each syntactically supported `rua`:

1. Preserve raw URI and parse status.
2. Extract and A-label-normalise the destination host.
3. Derive policy-source and destination organisational domains with the canonical
   tree-walk resolver.
4. If equal, return `not_required_same_organisational_domain`.
5. Otherwise construct:
   `<policy-source-domain>._report._dmarc.<destination-host>`.
6. If the constructed name exceeds DNS limits, make no positive determination.
7. Query TXT using the primary resolver and decisive corroboration.
8. Parse each returned TXT RR independently.
9. Discard authorisation RRs without first, exact `v=DMARC1`.
10. At least one valid RR authorises; several valid RRs remain authorised.
11. Preserve a valid same-host `rua` override.
12. If an override changes host, neither original nor override is usable.
13. Preserve conflicting valid same-host overrides but select none arbitrarily.

Per-URI status:

- `uri_parse_status`;
- `same_organisational_domain`;
- `authorization_query_name`;
- `authorization_record_state`;
- `authorization_status`;
- `authorized_destination`;
- `lookup_completeness`;
- `trusted_ingestion_status`;
- `limits`.

`authorization_record_state`:

- `absent`;
- `single_valid`;
- `multiple_valid`;
- `mixed`;
- `malformed`;
- `unavailable`;
- `timeout`;
- `resolver_disagreement`;
- `name_too_long`;
- `not_assessed_budget`;
- `not_assessed_limit`.

`authorization_status`:

- `not_required_same_organisational_domain`;
- `authorized`;
- `unauthorized`;
- `malformed`;
- `unavailable`;
- `not_assessed_unsupported_scheme`;
- `not_assessed_malformed_uri`;
- `not_assessed_limit_exceeded`;
- `not_assessed_budget`;
- `not_applicable`.

Authorisation and trust remain independent:

| DNS outcome | Authorisation | Inbound RUA trust |
| --- | --- | --- |
| Same organisational domain | Not required | Item 5 source-specific state. |
| At least one valid authorisation RR | Authorised | Still observational by default. |
| Definitive zero valid RRs | Unauthorised/malformed | Cannot become authoritative. |
| Timeout/SERVFAIL | Unavailable | Unknown; not unauthorised. |
| Unsupported/malformed/over-bound URI | Not assessed | No host guess and no authority expansion. |

## 11. RFC 9990 aggregate ingestion and RFC 9991 boundary

New aggregate-report parser output preserves:

- XML namespace;
- report format version;
- policy domain;
- `discovery_method` (`psl`, `treewalk`, unknown/raw);
- `p`;
- `sp`;
- `np`;
- `fo`;
- `adkim`;
- `aspf`;
- `testing`;
- schema-conformance diagnostics;
- parser version.

The report policy is evidence of what its generator evaluated for that reporting
period. It cannot overwrite current DNS truth. Policy/current-DNS differences
during propagation are retained with timestamps.

Mail-stream alignment required by RFC 9990 reduces but does not eliminate forged
report risk. Item 5 authority gates remain unchanged.

Policy-record `ruf` and `fo` are parsed/preserved. No RFC 9991 failure report is
accepted, decompressed, parsed, indexed, surfaced, or used in Item 7.

## 12. Additive data model

### 12.1 R2 canonical protocol object

New report state uses `dmarc_policy_evidence` with schema
`dmarc-policy.v2`. The canonical snapshot stores the same object at
`protocol_evidence.dmarc`.

| Group | Required contents |
| --- | --- |
| Identity | Workspace/domain/scan IDs, submitted and A-label author domain, timestamps. |
| Method | Methodology, parser, resolver, IDNA library/profile, schema versions. |
| Raw DNS | Ordered questions/results, chunks, concatenated RRs, rcode, TTL, resolver, cache use, truncation/errors. |
| Parsing | Candidate counts, validity, ordered tags, unknown/duplicate tags, URI diagnostics. |
| Discovery | Organisational domain/provenance, policy source/kind, stop reason, `psd` evidence. |
| Existence | Exists/nonexistent/unknown/not-required plus question provenance. |
| Policy | Raw/defaulted `p/sp/np/t`, declared policy, effective requested policy, testing adjustment, inheritance. |
| Legacy | Raw/numeric `pct`, legacy semantics, `applied=false`. |
| Reporting | Every bounded `rua`/`ruf`, per-RUA authorisation, unassessed entries and reasons. |
| Monitoring | Component completeness, provider state, corroboration, degradation reason. |
| Evidence | Full unchanged Item 6 contract. |
| Limits | Every query/time/URI/byte/destination limit encountered. |

Raw and derived values are never stored in one ambiguous field.

### 12.2 D1 architecture note: zero new DMARC tables

The proposed `dmarc_policy_observations` and `dmarc_policy_conditions` tables are
withdrawn.

Proof that migration 088 can express the identity:

| Need | Existing expression |
| --- | --- |
| Tenant | `email_protection_events.workspace_id`. |
| Email domain | Existing `domain_key=email_protection` adapter. |
| DMARC family | `record_type=dmarc_policy_condition`; diagnostic and queryable. |
| Stable condition | Deterministic `record_id` from domain, condition type, and canonical subject. |
| Occurrence identity | Append-only event row `id`. |
| Condition start | Append-only event `created_at`. |
| Recurrence | A later `monitoring_changed` row has a new ID and time for the same stable record. |
| Alert resolver | Existing indexed exact workspace/record/event/recurrence lookup. |
| Baseline flood guard | Non-occurrence `dmarc_domain_baseline_established` and `baseline_established` events. |
| Availability history | Non-occurrence `dmarc_monitoring_degraded`; no recurrence type. |
| Raw evidence | R2 report and immutable canonical snapshot; referenced by scan/snapshot ID and fingerprint. |
| Before/after | Previous/current immutable snapshots, not a mutable condition row. |
| Case entity | Deterministic record ID plus snapshot/event evidence. |

No new `LIFECYCLE_EVENT_SOURCES` entry is added. A `dmarc` entry would create a
ninth domain and conflict with the one-source-per-domain law. DMARC uses the
existing `email_protection` entry.

Stable identity:

`dmarc:<domain_id>:<condition_type>:<sha256(canonical_subject_key)>`

Condition types and subject keys:

| Condition type | Canonical subject key |
| --- | --- |
| `missing` | A-label author domain. |
| `malformed` | Exact/source `_dmarc` DNS name containing the defect. |
| `multiple` | Exact/source `_dmarc` DNS name containing the candidates. |
| `weak` | A-label author domain plus applicable policy source/tag in event detail; identity remains author-domain scoped. |
| `unauthorised_rua` | Normalised RFC 9990 authorisation DNS name. |

The full subject is stored in `detail_json`; the hash is identity material, not
the only customer evidence. Event detail also contains:

- domain ID and author domain;
- condition type and subject key;
- before/current scan and snapshot IDs;
- before/current evidence fingerprints;
- methodology;
- from/to monitoring status, recurrence type, and band;
- exact subtype;
- completeness;
- limits;
- case linkage when applicable.

Only `monitoring_changed` with a non-null `to_recurrence_type` is an alert
occurrence. Baseline, informational policy changes, authorisation availability,
condition no-longer-observed history, evidence uncertainty, and case linkage use
non-occurrence event types.

No raw DNS RRset or protocol JSON is copied to D1. Event detail contains bounded
references/fingerprints and customer-safe transition facts.

### 12.3 When a current-condition projection could be reconsidered

`email_protection_conditions` is deferred. It may be proposed only if measured
production evidence shows at least one:

- immutable-snapshot comparison cannot meet the scan atomicity contract;
- exact event lookups cannot meet a defined latency target;
- manual case eligibility needs a bounded current-state query not expressible
  from the current scan/snapshot;
- concurrency creates a demonstrated duplicate transition that existing claim
  mechanisms cannot prevent.

The separate proposal must:

- mirror migration 089 naming/workspace/soft-delete/purge rules;
- keep `email_protection_events` as the only occurrence source;
- omit occurrence ID, occurrence counter, and condition-start timestamp copies;
- use additive schema and application-only rollback;
- include tenant and anti-orphan tests.

### 12.4 Aggregate-report columns

At P2, recheck current main. If still absent, use the next free numbered additive
migration to add nullable columns to `dmarc_aggregate_reports`:

- `report_format_version TEXT`;
- `xml_namespace TEXT`;
- `discovery_method TEXT`;
- `policy_np TEXT`;
- `policy_testing TEXT`;
- `policy_fo TEXT`;
- `schema_conformance TEXT`;
- `parser_version TEXT`.

No table is added. Existing `policy_pct` remains untouched. Existing workspace
purge and tenant scope are reused and revalidated.

## 13. API contract

Add `dmarc_policy_evidence` to new scan/report/snapshot/Email Protection technical
responses. Existing routes and fields remain.

### 13.1 Core fields

| Field | Type/enum | Presence rule |
| --- | --- | --- |
| `schema` | `dmarc-policy.v2` | Required in new object. |
| `methodology_version` | Version string | Required. |
| `parser_version`, `resolver_profile`, `idna_profile` | Version strings/objects | Required. |
| `author_domain` | A-label | Required. |
| `submitted_domain` | String | Required/customer-safe. |
| `observed_at` | Timestamp | Required. |
| `observation_state` | `absent`, `present_valid`, `present_valid_with_defaults`, `present_invalid`, `multiple`, `unavailable`, `incomplete_oversized`, `resolver_disagreement` | Required. |
| `record_validity` | `valid`, `valid_with_defaults`, `invalid`, `indeterminate`, `not_applicable` | Required. |
| `raw_records` | Ordered array | Empty only after a complete zero-record result. |
| `parsed_tags` | Ordered raw/normalised array | Required. |
| `lookup_path` | Ordered result objects | Required for new observations. |
| `organisational_domain` | String or null | Null means unresolved, never guessed. |
| `organisational_domain_provenance` | `psd_n`, `below_psd_y`, `highest_valid_record`, `exact_shortcut`, `fallback_initial_target`, `unresolved` | Required. |
| `policy_source_domain` | String or null | Null when unresolved/not applicable. |
| `policy_source_kind` | `exact`, `organisational`, `psd`, `none`, `unknown` | Required. |
| `declared_policy` | `none`, `quarantine`, `reject`, null | Before `t`. |
| `effective_requested_policy` | Same | After `t`; null if unavailable/not applicable. |
| `effective_policy_tag` | `p`, `sp`, `np`, null | Required provenance. |
| `inheritance_reason` | `exact_p`, `organisational_p`, `organisational_sp`, `organisational_np`, `psd_p`, `psd_sp`, `psd_np`, `invalid_policy_fallback_none`, `none`, `unknown` | Required. |
| `p`, `sp`, `np`, `t`, `psd` | Raw/normalised/validity/default objects | Keys required; values nullable. |
| `domain_existence` | `exists`, `nonexistent`, `unknown`, `not_required` | Required. |
| `legacy_pct` | Observation/raw/numeric/semantics/applied object | Required; `applied=false`. |
| `rua_destinations`, `ruf_destinations` | Ordered arrays | Empty only when parsing is complete and no URI exists. |
| `policy_completeness`, `organisational_domain_completeness`, `existence_completeness`, `rua_authorisation_completeness` | `complete`, `incomplete`, `unavailable`, `not_applicable` | Required. |
| `monitoring_state` | Existing canonical monitoring enum | Required. |
| `provider_state` | Resolver availability without risk inference | Required. |
| `evidence_grade` | Full Item 6 contract | Required. |
| `limits` | Applied limits and reasons | Required. |

### 13.2 Null, absent, and empty

- An absent `dmarc_policy_evidence` means legacy scan/snapshot.
- Keys inside a new object are present.
- `null` means unknown, unresolved, or not derivable.
- `not_applicable` is not `unknown`.
- Empty array means a complete observation of zero items.
- Unavailable work never produces an empty array standing for “none”.
- Unknown enum values fail closed in readers.

### 13.3 Compatibility

Keep without rename, deletion, or changed meaning:

- `dmarc`;
- `dmarc_detail`;
- `policy`;
- `sp`;
- `pct`;
- `rua`;
- `record`;
- `record_count`;
- existing route `status`;
- existing hosted `verified`.

Legacy `policy` continues to mean exact-record `p`; never inherited effective
policy. Legacy `pct` remains raw legacy evidence. Hosted `verified` continues to
mean the CyberMeters routing string was observed, not RFC 9990 authorisation.

Customer-safe fields include customer-domain raw records, parsed tags,
diagnostics, lookup domains, policy/org provenance, requested policy,
per-destination authorisation, Evidence Grade, and limits.

Technical-only fields include provider transport bodies, stack traces, binding
identifiers, secrets, retry internals, and unbounded raw attachments.

## 14. Snapshot and historical compatibility

The outer canonical snapshot stays version 1. New snapshots add the nested
`protocol_evidence.dmarc` block and increment the builder version.

Writer rules:

1. Write legacy exact projection and v2 protocol block from one canonical result.
2. Keep raw and derived values separate.
3. Record methodology/parser/resolver/IDNA versions and every applied limit.
4. Make referenced evidence durable under the existing R2-first completion law.
5. Hash the canonical protocol object and carry its fingerprint into lifecycle
   references.

Reader rules:

1. Prefer the v2 block when present.
2. If absent, render stored legacy conclusions under their captured methodology.
3. Never recompute an old conclusion with current rules.
4. Old clients ignore additive fields.
5. Unknown new values fail closed.

Historical rules:

- old snapshot bytes do not change;
- old `pct`, exact policy, events, and wording retain historical meaning;
- the renderer adds the approved historical-methodology notice;
- report regeneration uses stored conclusions;
- no old event becomes a new subtype;
- no old `pct` becomes `t`;
- no old “enforced” label becomes proof of receiver enforcement;
- a future current reinterpretation must be a separate timestamped artifact and
  is excluded from Item 7.

## 15. Evidence-Grade contract

**[FOUNDER-RULING]** Item 6's L0–L5 law is unchanged:

- L0 — assertion only;
- L1 — direct raw observation;
- L2 — durable append-only raw evidence with method/source/time/version;
- L3 — resolved state with explicit provenance;
- L4 — standards-clause validation, fixtures/mutations, and later
  re-observation;
- L5 — L4 plus per-instance validation/custody/tamper/time/limits/guard evidence.

Grade does not grant authority. A well-preserved inbound RUA report can remain
observational.

Every customer-visible DMARC assertion carries:

- `observable_ceiling`;
- `beta_target`;
- `minimum_publishable`;
- `degrade_behavior`;
- `required_corroboration`;
- actual `grade`;
- `source_type`;
- `basis`;
- `limits`;
- `repeat_confirmed`.

| Assertion | Ceiling / beta / minimum | Degrade behavior | Corroboration | Source/basis | Grade limits and repeat |
| --- | --- | --- | --- | --- | --- |
| Record presence | L5 / L4 / L1 | Lookup failure is unavailable, not absent. | Decisive resolver for complete beta conclusion. | Named DNS TXT observation. | TTL/truncation/resolver retained; repeat only after later observation. |
| Record validity | L5 / L4 / L3 | Truncation/ambiguity is indeterminate. | RFC fixtures/mutations. | Raw RR plus parser diagnostics. | Parser/version/byte limit required. |
| Exact-domain policy | L5 / L4 / L3 | Required primary failure yields null; unavailable corroboration limits completeness. | Decisive-record check. | Exact TXT/defaults/`t`. | Requested policy only. |
| Inherited organisational policy | L5 / L4 / L3 | Incomplete walk yields null. | Full logical path and decisive record. | RFC 9989 §§4.10–4.10.2. | Protocol boundary, not registration proof. |
| `sp` | L5 / L4 / L1 raw, L3 applied | Unknown source/existence prevents application. | Source record. | Existing-subdomain inheritance. | Applicability provenance required. |
| `np` | L5 / L4 / L1 raw, L3 applied | Unknown existence prevents application. | NXDOMAIN/NODATA evidence. | Nonexistent-subdomain inheritance. | No authenticated-denial claim. |
| `t` | L5 / L4 / L1 raw, L3 applied | Invalid/default state diagnosed. | Source record and §4.7 fixtures. | Testing adjustment. | No reporting or receiver-action claim. |
| Legacy `pct` | L5 / L3 / L1 | Invalid remains raw; never applied. | None. | Legacy DNS/report evidence. | `applied=false` permanently. |
| Effective requested policy | L5 / L4 / L3 | Required unresolved component yields null or explicitly incomplete primary-only state. | Parse/path/existence/`t`/decisive record. | Derived DNS state. | Never receiver enforcement. |
| External RUA authorisation | L5 / L4 / L3 | Timeout/budget is unavailable/incomplete; no valid record is not authorised. | Destination org walk plus auth query. | RFC 9990 DNS. | Per URI; no ingestion-authority implication. |
| RUA ingestion/corroboration | L4 observational; L5 only with separately approved custody / L2 / L1 | Parse/trust failure stays raw/quarantined. | Existing Item 5 trust source plus independent DNS for authority uses. | Inbound email/signed upload/approved source. | Ordinary inbound remains non-authoritative. |
| Policy-change event | L5 / L4 / L3 | Suppress if either relevant side is incomplete. | Two immutable complete observations. | Before/after fingerprints. | Repeat not inferred from different states. |
| Requested-strength change | L5 / L4 / L3 | Suppress on unresolved applicability/`t`. | Complete before/after effective state. | `none < quarantine < reject`. | Use requested-policy wording. |
| Monitoring degraded | L4 / L3 / L2 | Publish limitation; infer no security regression. | Provider/error evidence. | Component transport/completeness. | No `monitoring_recovered`. |

Signal-by-signal progression:

- Presence progresses L0 assertion → L1 named TXT result → L2 immutable
  raw/metadata → L3 complete discovery interpretation → L4 RFC
  fixture/mutation plus later re-observation → L5 custody/time/guard evidence.
- Validity progresses only when raw RR, chunks, parser version, diagnostic, and
  standards basis are retained; a parser label without the RR cannot reach L3.
- Exact policy reaches L3 when exact precedence, defaults, `t`, and decisive
  resolver state are explicit.
- Inherited policy cannot exceed L2 until the full logically required path and
  source provenance are complete; L4 additionally needs standards validation and
  later re-observation.
- `sp` raw may be L1/L2; applicability reaches L3 only with source and existing
  target evidence.
- `np` raw may be L1/L2; applicability reaches L3 only with source and
  NXDOMAIN/NODATA evidence.
- `t` raw may be L1/L2; the testing-adjusted policy reaches L3 only through the
  direct §4.7 mapping and complete selected policy.
- Legacy `pct` may reach high grade as proof that a value was observed, but its
  current-policy contribution stays permanently nonexistent.
- Effective requested policy reaches L3 only when every required parser,
  precedence, existence, testing, and corroboration component permits it.
- External authorisation reaches L3 only after destination organisational-domain
  comparison and the required RFC 9990 query are complete.
- RUA ingestion may progress in observational preservation, but authority remains
  capped by the separate Item 5 trust source.
- Policy/strength change reaches L3 only with two immutable complete states; L4
  additionally requires validator/mutation evidence and a real later observation.
- Monitoring degradation may reach L3 as a resolved provider/component
  limitation; it never becomes proof of a DNS security regression.

## 16. Lifecycle, alerts, cases, and Related Changes

### 16.1 Event evidence and dedupe

Every policy transition requires:

- immutable previous/current scan and snapshot IDs;
- complete relevant components on both sides;
- before/after evidence fingerprints;
- methodology versions;
- exact predicate;
- no decisive resolver contradiction.

Posture-event dedupe identity:

`workspace_id|domain_id|methodology_version|subtype|subject_key|before_snapshot_id|after_snapshot_id|before_fingerprint|after_fingerprint`

The lifecycle occurrence identity is the `email_protection_events.id`, not that
fingerprint. Compatible subtypes from one observation pair group into one alert
occurrence to prevent a single DNS edit from creating an alert storm.

The DMARC lifecycle writer derives the event primary key as
`epe-<sha256(the full dedupe identity)>` and uses a conflict-safe insert. A replay
of the same immutable observation pair therefore resolves to the same event row.
A later real recurrence has different snapshot identities and gets a new event
row even when the policy values repeat. This deterministic row ID is not a
second occurrence identifier: the stored `email_protection_events.id` remains
the sole occurrence identity and its stored `created_at` remains the sole start
time.

### 16.2 Stable subtype taxonomy

Shared prohibitions: no compromise, malicious-activity, receiver-enforcement,
absolute spoof-prevention, causality, or recovery claim.

| Subtype | Exact before/after evidence | Completeness | Alert | Manual case eligibility | Related Changes | Customer wording |
| --- | --- | --- | --- | --- | --- | --- |
| `record_created` | Exact current-version count 0 → one usable. | Exact complete both. | No. | No default. | Yes. | “A DMARC record was newly observed.” |
| `record_removed` | Usable exact → definitive zero exact. | Exact complete; current unavailable excluded. | Only without equal/stronger inheritance. | Yes when actionable. | Yes. | “The previously observed exact record is no longer present.” |
| `record_became_malformed` | Usable exact → one fatal current-version record. | Candidate set complete both. | Yes. | Yes. | Yes. | “The observed record changed into a form that cannot be used.” |
| `multiple_records_detected` | Non-multiple → at least two current-version candidates. | Candidate set complete both. | Yes. | Yes. | Yes. | “Multiple policy records are now present.” |
| `policy_changed` | Declared/effective value changes not fully represented by a stronger subtype. | Policy complete both. | Only if one of the approved actionable regressions. | Only with actionable condition. | Yes. | “The published requested policy changed.” |
| `policy_inherited` | Exact source → inherited source. | Policy/source complete both. | Only with approved gap/weakening. | Same. | Yes. | “The domain now relies on an inherited policy.” |
| `inheritance_source_changed` | Inherited source domain/tag A → B. | Source complete both. | Only if effective policy weakens. | Same. | Yes. | “The source of the applicable policy changed.” |
| `organisational_domain_changed` | Derived organisational domain A → B. | Org complete both. | No. | No automatic case. | Yes. | “RFC 9989 discovery now identifies a different organisational-policy boundary.” |
| `subdomain_policy_changed` | Applicable source `sp` changes. | Source/existence complete. | Only if effective policy weakens or becomes invalid. | Same. | Yes. | “The published subdomain preference changed.” |
| `non_existent_subdomain_policy_changed` | Applicable source `np` changes for proven nonexistent target. | Source/existence complete. | Only if effective policy weakens or becomes invalid. | Same. | Yes. | “The preference for nonexistent subdomains changed.” |
| `enforcement_strengthened` | Effective ordinal rises. | Effective complete both. | No risk alert. | No risk case. | Yes. | “The requested policy became stronger.” |
| `enforcement_weakened` | Effective ordinal falls. | Effective complete both. | Yes. | Yes. | Yes. | “The requested policy became less restrictive.” |
| `legacy_pct_observed` | Raw legacy value appears/changes. | Exact complete. | No. | No. | No. | “A legacy `pct` value was observed and was not applied.” |
| `external_rua_added` | URI absent → present. | URI set complete. | Only if definitively unauthorised and actionable. | Same. | Yes. | “An aggregate-report destination was added.” |
| `external_rua_removed` | URI present → absent. | URI set complete both. | Only when resulting state is an approved actionable regression. | Same. | Yes. | “An aggregate-report destination was removed.” |
| `external_rua_authorised` | Definitive unauthorised → authorised. | Auth complete both. | No. | No risk case. | Yes. | “The destination now publishes valid authorisation.” |
| `external_rua_unauthorised` | Authorised → definitive no valid authorisation. | Auth complete both. | Yes. | Yes. | Yes. | “Valid external destination authorisation is no longer present.” |
| `external_rua_authorisation_unavailable` | Complete auth → evidenced temporary/unavailable. | Availability observation complete. | No. | No risk case. | No. | “Authorisation could not be checked.” |
| `monitoring_degraded` | Current relevant component loses completeness. | Limitation evidenced. | No. | No risk case. | No. | “DMARC monitoring was incomplete for this scan.” |
| `monitoring_recovered` | Excluded. | Not applicable. | No. | No. | No. | Prohibited. |

The taxonomy name `enforcement_*` is retained for stable subtype compatibility,
but customer wording always says “requested policy strength”; it never claims
receiver enforcement.

Dedupe subject map:

| Subtype family | Dedupe subject |
| --- | --- |
| Record created/removed/malformed/multiple | Exact `_dmarc` DNS name. |
| Policy changed | Author domain plus effective source. |
| Policy inherited | Author domain. |
| Inheritance source changed | Author domain plus ordered source chain. |
| Organisational domain changed | Author domain. |
| `sp` change | Source domain plus `sp`. |
| `np` change | Source domain plus target domain plus `np`. |
| Strengthened/weakened | Author domain. |
| Legacy `pct` | Exact DNS name plus raw value. |
| External RUA added/removed/authorised/unauthorised | Normalised URI. |
| External authorisation unavailable | Normalised URI plus provider. |
| Monitoring degraded | DMARC component plus provider. |

### 16.3 Baseline and availability construction

- First DMARCbis evaluation writes `dmarc_domain_baseline_established`.
- Conditions present on that first complete evaluation write
  `baseline_established`; they cannot alert.
- A current complete condition after an incomplete predecessor is current
  evidence but not proven new; it does not create a risk occurrence.
- Availability degradation uses `dmarc_monitoring_degraded`, not
  `monitoring_changed`, and carries no `to_recurrence_type`.
- A later complete scan may permit current publication but does not emit
  `monitoring_recovered`.
- A resolved condition can be recorded as `condition_no_longer_observed` only
  after complete relevant evidence; this is history, not a recovery alert.

### 16.4 Alerts

Only founder-approved definitive regressions are activated:

- malformed;
- multiple;
- weakened effective requested policy;
- exact record loss without equal/stronger inheritance;
- a newly added external RUA that is definitively unauthorised, or an authorised
  external RUA becoming definitively unauthorised.

Availability, budget skips, provider disagreement, strengthened policy, record
creation, inheritance alone, and legacy `pct` cannot issue a risk alert.

### 16.5 Managed cases

Cases are manual/case-eligible, never automatically opened. Manual creation:

1. requires a current complete actionable condition;
2. uses deterministic DMARC record ID as stable source identity;
3. uses `domain_key=email_protection`;
4. calls `createManagedCase(...)`;
5. uses existing `managed_cases`/migration 082;
6. records a non-occurrence `case_linked` event;
7. validates every status change through `canTransitionCase(...)`;
8. verifies only from a later complete CyberMeters DNS re-observation.

A note, customer assertion, scan completion alone, or RUA report cannot verify.

### 16.6 Canonical remediation

Preserve compatible identities:

- `email.dmarc.publish`;
- `email.dmarc.enforce`;
- `email.dmarc.reporting`;
- `email.dmarc.single_record`;
- `email.dmarc.valid_record`.

A new `email.dmarc.external_rua_authorization` identity may be added only after
Canonical Remediation Registry review. Unknown mappings fail honestly.

All DNS text is a suggestion/evidence attachment. CyberMeters does not apply it.
Owner assignment precedes “in progress”. Customer-applied assertions remain
separate from later product verification.

### 16.7 Related Changes

Eligible material DMARC events enter the existing adapter only when:

- DMARC evidence is complete;
- an independent evidence family exists;
- the existing registrable-root key matches;
- the existing bounded time window matches;
- contradictions remain visible;
- cluster and recurrence identities remain stable.

RFC-derived organisational domain is evidence metadata, not the correlation root.
A DMARC event cannot independently corroborate another DMARC event. RUA cannot
corroborate DNS authority without existing Item 5 authority.

Approved wording:

> These changes were observed close together and may be related. CyberMeters has
> not established that one caused the other or that they indicate compromise.

## 17. Customer wording contract

### 17.1 Canonical phrases

| State | Approved wording |
| --- | --- |
| Exact record | “A DMARC record was observed at `_dmarc.example.com`.” |
| Inherited existing child | “No applicable record was found at the exact subdomain. RFC 9989 discovery found a policy at `example.com`; its `sp=quarantine` preference applies to this existing subdomain.” |
| Nonexistent child | “The subdomain did not exist in DNS when checked. The organisational policy's `np=reject` preference therefore applied.” |
| Complete no policy | “CyberMeters completed the DMARC policy lookup and found no applicable policy.” |
| Lookup unavailable | “CyberMeters could not determine the current DMARC policy because a required DNS lookup timed out. This is not a missing-record result.” |
| Malformed | “A DMARC-looking record was observed, but its syntax prevents it from being used as a valid policy.” |
| Multiple | “Multiple DMARC policy records were observed at the same DNS name. RFC 9989 does not allow CyberMeters to select one as authoritative.” |
| `p=none` | “The domain publishes a no-action DMARC policy.” |
| Quarantine | “The published policy requests quarantine treatment for messages that fail DMARC. Receivers retain final handling discretion.” |
| Reject | “The published policy requests rejection of messages that fail DMARC. This does not prove every receiver applied that request.” |
| Testing reject | “The record declares `p=reject` with `t=y`; RFC 9989 makes the effective requested policy quarantine while testing.” |
| Legacy `pct` | “Legacy `pct=25` was observed. RFC 9989 no longer applies this value to the current effective policy.” |
| Same-domain RUA | “This reporting destination is within the same organisational domain; external authorisation is not required.” |
| Authorised external RUA | “The external reporting destination published a valid DMARC authorisation record.” |
| Unauthorised external RUA | “CyberMeters found no valid authorisation for this external aggregate-report destination.” |
| External auth unavailable/budgeted | “External destination authorisation could not be determined for this scan.” |
| RUA observed | “Aggregate reports have been observed for this domain.” |
| Suggestion | “Suggested DNS change — not applied by CyberMeters.” |
| Later verification | “CyberMeters observed the expected DNS state in a later complete scan.” |
| Monitoring degraded | “DMARC monitoring was incomplete for this scan. CyberMeters has not inferred a configuration change from the incomplete result.” |
| Historical report | “This report preserves the DMARC methodology and conclusions used when the scan completed.” |

### 17.2 Surface rules

Dashboard:

- separate observed exact record from effective requested policy;
- show source domain and exact/inherited/PSD provenance;
- show declared policy and `t` adjustment;
- label `pct` legacy/non-operative;
- show each external URI independently;
- show DMARC component completeness independently of whole Email health.

Findings/observations:

- name the configuration fact, not an attack outcome;
- distinguish missing, malformed, multiple, weak, inherited, unavailable, and
  unauthorised;
- do not issue missing from unavailable;
- show exact defect and inherited protection together where both are true;
- observations may expose bounded technical evidence with method/time/limits.

Alerts/cases/remediation:

- describe exact complete transition and before/current times;
- say “requested policy”;
- separate customer assertion from CyberMeters verification;
- never state CyberMeters applied DNS;
- use canonical remediation only.

Executive Report/PDF:

- use snapshot-derived requested policy, inheritance, operational gap, Evidence
  Grade, and limitations;
- never independently derive policy;
- keep resolver internals in the technical appendix;
- render historical methodology notice for old snapshots.

Technical appendix:

- ordered lookup plan and logical-use flags;
- raw RRs/chunks where customer-safe;
- parsed tags and diagnostics;
- org/policy-source provenance;
- declared/effective policy, `t`, legacy `pct`;
- per-URI authorisation;
- methodology, Evidence Grade, provider and limits.

Prohibited current-methodology wording:

- “full DMARC protection”;
- “DMARC enforcement is proven”;
- “receivers are blocking spoofed email”;
- “attackers cannot spoof this domain”;
- “fully RFC compliant” without required evidence;
- “malicious activity” from DMARC failure alone;
- “CyberMeters changed/applied your DNS”;
- “external reporting is working” from publication or authorisation alone;
- “monitoring recovered”;
- “authorised RUA evidence is authoritative” from DNS authorisation alone;
- “RFC Monitoring Mode” from `p=none` alone.

## 18. Deterministic fixture and mutation matrix

All complete derived fixtures expect an L3 runtime assertion. Passing standards
fixtures contributes to the methodology's L4 target but does not manufacture a
later real re-observation or `repeat_confirmed=true`.

Every fixture records:

- DNS inputs;
- ordered logical lookup path and issued questions;
- raw state;
- effective requested policy/provenance;
- Evidence Grade;
- API fields;
- customer wording;
- event/alert/manual-case behavior;
- prohibited result;
- one mutation that must turn the validator red.

### 18.1 Discovery and effective-policy fixtures

| Fixture / DNS input | Expected path, raw/effective/grade/API | Wording and lifecycle | Prohibited result | Red mutation |
| --- | --- | --- | --- | --- |
| Exact organisational record: `_dmarc.example.test "v=DMARC1; p=reject; psd=n"` | Exact first; stop; single valid; org/source exact; declared/effective reject; complete/corroborated; L3. | “Publishes a reject preference”; baseline only. | Proven receiver blocking. | Change source to inherited. |
| Exact subdomain record | Exact wins; org walk evidence retained as required; effective exact `p`. | Exact wording; no initial event. | Parent `sp` overriding exact. | Delete exact precedence. |
| Subdomain without record | Exact NODATA; parent valid; exact absent; source organisational. | Inherited wording/source. | Exact record present. | Stop on NODATA. |
| Inherited `p` | Existing child; parent `p=quarantine`, no `sp`. | Effective quarantine/tag `p`, L3. | `np` provenance. | Expect tag `sp`. |
| Inherited `sp` | Existing child; parent `p=none; sp=reject`. | Effective reject/tag `sp`. | Parent `p=none`. | Swap expected to none. |
| Inherited `np` | Child NXDOMAIN; parent `np=reject`. | Nonexistent, effective reject/tag `np`. | Treat NXDOMAIN as NODATA. | Return exists. |
| RFC `t=y` direct clause | Exact `v=DMARC1; p=reject; t=y`. | Declared reject; effective requested quarantine; `testing_adjustment=one_level_below`; cite §4.7. | Reject unchanged or all testing collapsed to none. | Either mapping; validator red. |
| RFC `t=y` quarantine | Exact `p=quarantine; t=y`. | Declared quarantine; effective none. | Effective quarantine/reject. | Remove one-level step. |
| RFC `t=y` none | Exact `p=none; t=y`. | Effective none; reporting unchanged. | Null policy or reporting disabled. | Give `t` an effect on reporting. |
| `t` default | Exact `p=reject`, no `t`. | `t` default n; effective reject. | Implicit testing. | Default to y. |
| Standard org walk | Valid records at several levels, no explicit `psd`. | Highest/shortest valid record determines org per §4.10.2; source separately recorded. | PSL-derived org. | Skip a required logical target. |
| Deep-label walk | More than eight labels. | Exact, jump to seven labels, remove one thereafter; ≤8 logical TXT questions. | Nine questions or intermediate skipped-label query. | Insert the forbidden intermediate. |
| Nonexistent subdomain | Exact NXDOMAIN and inherited `np`. | Explicit nonexistent wording. | “Missing” without inheritance. | Convert rcode to NOERROR. |
| NXDOMAIN/NODATA pair | Same parent `np=reject; sp=quarantine`; child A NXDOMAIN, B NODATA. | A reject/`np`; B quarantine/`sp`. | Same effective result. | Collapse both to absent. |
| Required timeout/SERVFAIL | Exact or required parent temporary failure. | Effective null; unavailable; monitoring only. | Missing/none/healthy or change event. | Map error to empty RRset. |
| Public suffix `psd=y` | Sole valid PSD record with `psd=y`. | Stop; org one label below. | PSD itself as org or continued logical use. | Ignore stop. |
| `psd=n` | Sole valid record with `psd=n`. | Record domain is org; stop. | Continue to root. | Remove stop. |
| Complete no-policy walk | Every required target definitive zero candidates. | Effective null; `no_applicable_policy`; missing remediation allowed. | Default `p=none`. | Expect none. |
| Invalid policy plus valid RUA | Invalid selected policy and one valid URI. | RFC fallback none; invalid diagnostic. | No processing. | Remove fallback. |
| Invalid policy without valid RUA | Invalid selected policy and no valid URI. | Effective null; malformed/no processing. | Fallback none. | Treat malformed URI as valid. |
| Exact malformed, parent valid | Exact fatal; parent usable. | Show exact defect and inherited effective policy. | Malformed-only or healthy-only. | Suppress either fact. |
| Exact multiple, parent valid | Two exact current candidates; parent usable. | Exact multiple plus inherited policy. | Select first exact. | Count parsed-valid only. |
| Parent unavailable after exact absent | Exact definitive absence; parent timeout. | Effective null/incomplete. | Missing/removed. | Emit record_removed. |
| No-action policy | Complete `p=none`. | “No-action policy”; not RFC Monitoring Mode. | “Full Monitoring Mode.” | Infer mode from `p` alone. |
| Quarantine/reject pair | Complete policies. | “Requests quarantine/rejection”; L3. | Receiver enforcement/protection absolute. | Use “is blocking”. |

### 18.2 Parser, legacy, and external-RUA fixtures

| Fixture / input | Expected raw/effective/API | Wording/lifecycle | Prohibited result | Red mutation |
| --- | --- | --- | --- | --- |
| Legacy `pct` | `p=reject; pct=25`; raw/numeric legacy; `applied=false`; effective reject subject to `t`. | Informational `legacy_pct_observed`; no alert/case. | Partial reject semantics. | Apply percentage. |
| Two valid policy records | `multiple`; both discarded; parent may apply. | Multiple finding/event. | First wins. | Expect first. |
| Valid + malformed current record | `multiple_mixed`; both discarded. | Multiple wording. | Sole valid selected. | Count successful parses only. |
| Valid + unrelated TXT | Unrelated retained/ignored; sole policy valid. | Normal valid wording. | Multiple DMARC. | Count unrelated TXT. |
| Multiple malformed current records | `multiple_invalid`; all discarded. | Multiple/malformed. | Least-malformed selected. | Select any. |
| Duplicate tag | `v=DMARC1; p=none; p=reject`; fatal duplicate. | Malformed. | Last-value-wins reject. | Accept duplicate. |
| Unknown tag | Valid plus `x-foo=bar`; retained/ignored. | No alarm for unknown alone. | Fatal/apply unknown. | Reject unknown. |
| Version not first | `p=reject; v=DMARC1`. | Not usable current policy. | Accept. | Permit later `v`. |
| Wrong-case version | `v=dmarc1; p=reject`. | Not current version. | Case-insensitive accept. | Lowercase before compare. |
| TXT chunks | One RR with ordered chunks. | Preserve and concatenate in order. | Separate records/reversed chunks. | Reverse order. |
| Excess/truncation | Byte cap or unresolved TC. | Incomplete; no policy. | Parse prefix. | Permit prefix conclusion. |
| IDNA Unicode host | Valid Unicode domain with known A-label vector. | Canonical A-label query; raw Unicode preserved. | Hand-built lossy conversion. | Disable bidi/joiner/length check. |
| Invalid A-label | Invalid `xn--` or overlong label. | Parser/name error; no guessed query. | Truncated/normalised guess. | `ignoreInvalidPunycode=true`. |
| Same-org RUA | Destination org equals policy-source org. | `not_required_same_organisational_domain`; no auth query. | Require/claim external auth. | Issue auth TXT. |
| Authorised external | External destination, at least one valid auth RR. | Authorised; trust still observational. | Inbound becomes authoritative. | Set authority true. |
| Unauthorised external | Definitive zero valid auth RRs. | “No valid authorisation”; approved condition only on definitive regression. | Reports delivered/authorised. | Treat NODATA as authorised. |
| Auth unavailable | Timeout/SERVFAIL/budget refusal. | Unavailable/incomplete; no risk alert. | Unauthorised. | Map timeout to unauthorised. |
| Multiple valid auth records | Two valid first-version RRs. | `authorized`, `multiple_valid`. | Policy multiplicity invalidation. | Require exactly one. |
| Mixed auth records | One valid, one malformed. | Authorised, raw `mixed`. | Discard all. | Apply policy-record rule. |
| Malformed auth only | TXT present, no valid first version. | Malformed; no positive auth. | Substring authorisation. | Case-insensitive contains check. |
| Multiple RUA destinations | Same, authorised, unsupported, unauthorised, budgeted. | Ordered per-URI states; aggregate incomplete if any unassessed. | One aggregate boolean. | Drop entry. |
| Unsupported scheme | Preserved; `not_assessed_unsupported_scheme`. | Product-support wording. | RFC-invalid or mailto coercion. | Coerce scheme. |
| Malformed URI | Raw preserved; no host. | Malformed destination. | Host guessing. | Regex-extract guessed host. |
| Obsolete `!size` | Preserve/ignore. | Legacy technical note. | Current negotiated-size semantics. | Apply size filter. |
| URI over 2,048 | Safe diagnostic; incomplete. | Product-limit wording. | Silent truncation/RFC-invalid claim. | Parse truncated prefix. |
| >10 URI or >5 hosts | Count all; overflow unassessed; overall incomplete. | “Some destinations were not assessed due to stated limit.” | “All authorised.” | Ignore overflow. |
| Same-host override | Valid override retains original host. | Preserve authorised override. | Second host. | Accept host change. |
| Conflicting same-host overrides | Relationship authorised; override unresolved. | Conflict diagnostic. | First/last selected. | Choose one. |
| Second external hop | Override host changes. | Neither URI usable. | Follow redirect. | Accept different host. |
| Auth name too long | No query; no positive determination. | DNS-limit wording. | Truncate or authorise. | Truncate name. |

### 18.3 Budget, lifecycle, snapshot, and dedupe fixtures

| Fixture | Expected API/evidence | Lifecycle/customer result | Prohibited result | Red mutation |
| --- | --- | --- | --- | --- |
| Budget complete | See §9.5. | Complete core and admitted RUA within caps. | >17,350 ms envelope. | Remove cap. |
| Core-only degraded | Core complete, RUA incomplete/budget reason. | No RUA risk claim; global scan may otherwise complete. | All authorised/healthy. | Launch partial host. |
| Provider timeout | Core structured unavailable within 750 ms. | Monitoring limitation only. | False absence/change. | Timeout→empty. |
| Strengthened | Complete none→quarantine/reject. | `enforcement_strengthened`; no risk alert/case. | Receiver behavior claim. | Emit weakened. |
| Weakened | Complete reject→quarantine/none. | One approved occurrence/alert; manual case eligible. | Suppressed or auto-case. | Reverse ordinal or auto-open. |
| Record removed | Valid exact→definitive zero; evaluate inheritance. | Alert only without equal/stronger inherited result. | Alert from timeout or despite stronger inheritance. | Remove inheritance guard. |
| Record created | Zero→one usable. | Informational timeline, no risk alert. | Risk case. | Make alert eligible. |
| Became malformed | Usable→fatal candidate. | One occurrence/alert; manual case eligible. | Missing classification. | Treat malformed as absent. |
| Multiple detected | Non-multiple→multiple. | One occurrence/alert; manual case eligible. | Arbitrary selection. | Drop candidate count. |
| Inheritance source changed | Complete source A→B. | Event; alert only if effective weakens. | Causality. | Ignore source fingerprint. |
| Org domain changed | Complete org A→B. | Informational/Related eligible. | Registration-owner claim/root-key change. | Use PSL/correlation key. |
| `sp` changed | Complete and applicable. | Event; risk only on effective weakening/invalidity. | Alert non-applicable tag. | Ignore applicability. |
| `np` changed | Proven nonexistent target. | Event; same risk rule. | Apply to existing target. | Collapse existence. |
| Complete pair | Relevant sides complete/corroborated. | Event with immutable pointers. | Missing evidence pointers. | Remove completeness guard. |
| Previous complete/current incomplete | Current required question fails. | Suppress removal/weakening; monitoring-degraded history. | Risk transition. | Permit incomplete current. |
| Previous incomplete/current complete | Current publishable. | No `monitoring_recovered`; no newly-proven regression alert. | Recovery/new alert. | Enable recovered. |
| First DMARCbis scan with conditions | No earlier methodology baseline. | Baseline events only; no backlog alert. | Flood alert. | Treat baseline as new. |
| Existing condition re-observed | Same deterministic record/status/fingerprint. | No new `monitoring_changed`; same occurrence. | Hourly re-alert. | Include scan ID in record identity. |
| Resolved and recurred | Later complete absence, then complete reappearance. | Same stable record; new append-only occurrence ID. | New condition identity/counter. | Add occurrence counter as authority. |
| Old RFC 7489 snapshot | No v2 block; stored old values. | Historical notice; no recompute. | New inheritance/pct semantics. | Derive with current resolver. |
| New v2 snapshot | Legacy exact plus protocol block. | New reader v2; old reader legacy. | Legacy policy filled from inheritance. | Copy effective into legacy. |
| No duplicate alert | Replay same occurrence/event pair. | One event/alert; manual case link remains one. | Duplicate notification/case. | Remove occurrence from dedupe. |
| RUA duplicate report | Same source/report identity retransmitted. | One source-scoped ingest occurrence. | Double count. | Remove existing dedupe. |
| Propagation divergence | Aggregate report shows earlier policy; current DNS later policy. | Both retained with times. | Report overwrites DNS. | Use report as current policy. |
| Resolver disagreement | Decisive primary/secondary differ. | Withhold risk conclusion; monitoring degraded. | Pick preferred resolver. | Ignore contradiction. |
| Manual case verification | Suggested change then later complete matching DNS. | Verification eligible through shared transition law. | Note/scan completion/RUA verifies. | Allow note-only. |
| Cross-tenant record collision | Same subject in two workspaces. | Workspace-scoped events/cases/reads. | Other tenant occurrence. | Remove workspace predicate. |

### 18.4 Required mutation families

- policy candidate-count mutation;
- duplicate-tag last-wins mutation;
- case-insensitive/later-version mutation;
- tree-walk order/deep-label/query-cap mutation;
- `psd` stop mutation;
- NXDOMAIN/NODATA collapse;
- `np/sp/p` precedence;
- direct-clause `t` ladder mutation;
- `pct` application;
- temporary-error-to-absence;
- decisive-disagreement selection;
- cache key resolver/type/DNSSEC omission;
- missing in-flight promise dedupe;
- external any-valid-versus-exactly-one;
- partial-host budget launch;
- destination overflow completeness;
- second-hop override;
- RUA trust-authority expansion;
- snapshot recomputation;
- incomplete transition;
- deterministic record ID/occurrence dedupe;
- auto-case creation;
- receiver-enforcement wording;
- tenant-scope removal.

## 19. Six-PR implementation sequence

No PR is authorised while the hold remains.

### P1 — Pure parser, tree walk, derivation, and external resolver

Scope:

- exact-pinned `tr46@6.0.0` dependency and vet gates;
- pure policy and authorisation parsers;
- URI diagnostics;
- injected DNS interface;
- RFC 9989 planner/walk/org/existence/effective derivation;
- RFC 9990 external authorisation resolver;
- no production caller.

Likely modules:

- focused new modules under `workers/scan-api/src/engines/`;
- Worker `package.json`/lock only for the reviewed dependency;
- focused deterministic validators.

Schema: none.

Fixtures/mutations: parser, IDNA, tree walk, `p/sp/np/t/psd/pct`, every RUA state,
query limits, direct-clause `t`, and trust non-expansion.

Acceptance boundary: pure fixture DNS only; no live resolver, persistence, API,
event, alert, case, UI, report, or mutation.

Rollback: code/dependency revert.

Dependencies: revised design approval and parser-freeze RFC review.

Deferred: every production caller and all customer behavior.

### P2 — Production observation, lifecycle reuse, and budget

Scope:

- shared invocation DNS question cache;
- new 750 ms Phase-1 `dmarc_core`;
- remove duplicate legacy exact DMARC decision only after canonical wiring;
- optional 600 ms external phase and full reservation gate;
- default/reserved deadline and subrequest accounting;
- component completeness and monitoring;
- R2 report evidence;
- legacy exact adapter;
- deterministic `dmarc_policy_condition` family in
  `email_protection_events`;
- baseline/occurrence construction with existing
  `LIFECYCLE_EVENT_SOURCES.email_protection`;
- RFC 9990 aggregate parser/persistence additions if baseline recheck confirms
  the nullable-column gap.

Likely modules:

- `scan-engine.js`;
- `scan-budget.js`;
- `reserved-scan.js`;
- `dns.js`;
- `dns-scan.js`;
- `email-scan.js`;
- `dmarc-state.js`;
- `email-intel.js`;
- `dmarc-ingest.js`;
- `email-protection-lifecycle.js`;
- purge/tenant validators only as affected;
- next numbered migration only for nullable aggregate-report columns.

Schema: zero new tables; at most one additive migration for existing aggregate
report columns.

Fixtures/mutations: all three deadline modes, ≤10 core questions, ≤11 per admitted
host, cache dedupe, reserved capacity, scan finalisation, tenant/soft-delete/purge,
baseline flood guard, occurrence identity, old/new aggregate report and Item 5
trust.

Acceptance boundary: technical production observation and existing lifecycle
substrate work; no public API contract, Related Changes, alerts, cases, or customer
surfaces.

Rollback: Worker code rollback; nullable columns remain.

Dependencies: P1.

Deferred: snapshot/API readers, posture timeline, alerts/cases, presentation.

### P3 — Snapshot and additive API dual readers

Scope:

- outer-v1 nested DMARC protocol block;
- writer/reader compatibility;
- old snapshot preservation and historical notice metadata;
- additive API object;
- Email/report/snapshot read adapters;
- D1/R2/snapshot fingerprint reconciliation;
- read-only Hosted-DMARC compatibility projection.

Likely modules:

- `report-snapshot.js`;
- scan/report/snapshot routes;
- Email Protection routes;
- serializers;
- read-only hosted status path.

Schema: none.

Fixtures/mutations: old/new snapshots, absent block, null/empty, unknown enum,
legacy client, inherited-not-in-legacy, immutable bytes, R2 reconciliation.

Acceptance boundary: technical contracts are consumable; no timeline/alert/case
activation or customer rendering.

Rollback: code rollback.

Dependencies: P2.

Deferred: posture events, Related Changes, alerts, cases, presentation.

### P4 — Posture events and Related Changes

Scope:

- complete subtype taxonomy;
- before/after evidence pointers and fingerprints;
- completeness/disagreement suppression;
- stable dedupe;
- existing Related Changes adapter mapping;
- unchanged registrable-root correlation identity and non-causal wording.

Likely modules:

- historical/posture event derivation;
- `email-protection-lifecycle.js`;
- `related-changes-adapter.js`;
- exposure metadata/rules where an additive subtype mapping is required.

Schema: none expected; uses migration 088.

Fixtures/mutations: every subtype, baseline/incomplete pairs, contradiction,
fingerprint dedupe, no `monitoring_recovered`, independence and root-key
preservation.

Acceptance boundary: timeline and Related Changes only.

Rollback: code rollback.

Dependencies: P3.

Deferred: risk alert activation, manual cases/remediation, customer surfaces.

### P5 — Narrow alerts, manual cases, and canonical remediation

Scope:

- activate only founder-approved actionable regressions;
- occurrence resolution through existing Email source;
- manual/case-eligible creation only;
- shared case factory/transition validator;
- canonical remediation review;
- later-complete-DNS verification;
- alert/case-link dedupe.

Likely modules:

- canonical alert pipeline;
- `alert-occurrence.js` validators/comments only if needed, not a new source;
- `email-protection-cases.js`;
- managed case routes;
- remediation registry;
- occurrence/dedupe modules.

Schema: none expected.

Fixtures/mutations: five eligible regressions, availability exclusion, recurrence,
one alert, no auto-case, one manual case link, note/RUA/incomplete verification
rejection, tenant isolation.

Acceptance boundary: managed lifecycle technically complete and still
suggestion-only.

Rollback: Worker code rollback.

Dependencies: P4.

Deferred: UI/report rendering and all DNS mutation.

### P6 — Customer surfaces, Executive Report, and PDF

Scope:

- Email dashboard, scan detail, intelligence surfaces;
- finding/observation/alert/case/remediation wording;
- Executive Report/PDF;
- technical appendix;
- historical methodology notice;
- API/UI/report/PDF parity.

Likely modules:

- `frontend/src/pages/ws/WorkspaceEmailProtectionPage.jsx`;
- `frontend/src/pages/ScanDetail.jsx`;
- `frontend/src/pages/IntelligencePage.jsx`;
- `frontend/src/components/ExecutiveReportV2.jsx`;
- canonical Executive/PDF snapshot renderers;
- focused DMARC presentation components.

Schema: none.

Fixtures/mutations: all customer states, `p/sp/np/t/pct`, each RUA state,
incomplete/budgeted output, old report, wording guard, accessibility, frontend
coverage/build.

Acceptance boundary: ready for founder-controlled live acceptance, not yet
LIVE-ACCEPTED.

Rollback: Pages and Worker renderer rollback identities.

Dependencies: P3 and P5.

Deferred: broad redesign, homepage, service labels, automation, Item 8.

### Acceptance gate — no feature PR

After P6, execute the separate acceptance guide only with founder-designated
zones, report generator, workspace, timing, and side-effect authority. Item 7
closes only on explicit founder live acceptance.

## 20. Risks and unresolved implementation gates

| Risk/gate | Treatment |
| --- | --- |
| Exact acceptance names are not designated. | **[FOUNDER-RULING]** Do not assume them; founder supplies two zones, generator, workspace. |
| `tr46` Worker bundling not run. | P1 blocks on exact-pin lock review, audit/SBOM, dry-run, bundle inspection, and Worker vectors. |
| Repository may advance before hold lifts. | Rebase/retrace from then-latest main; do not reuse migration number blindly; reopen only directly conflicting findings. |
| Secondary DNS unavailable | Publish only within the lower completeness/grade contract; suppress risk lifecycle. |
| Full external RUA often cannot fit | Explicit incomplete state; later scan-architecture decision, not a global-ceiling increase. |
| Reserved mode interaction | Core is reserved before exposure; external remains optional; existing reserved-mode governance is not redesigned. |
| Snapshot/lifecycle atomicity | R2-first durability and deterministic event claim must fail closed; no event may reference missing evidence. |
| No mutable condition projection | Snapshot pair plus exact event identity is the default. Measured proof and founder review are required before a projection table. |
| Erratum 8995 status | **[NOT DIRECTLY VERIFIED]**; no authenticated-denial claim regardless. |
| Aggregate-report data can be forged | Item 5 trust boundary unchanged; RFC 9990 authorisation is not report authority. |
| Customer wording regressions | Dedicated wording mutations across API/UI/Executive/PDF. |

## 21. Hold and stop

This guide does not authorise code, generated code, dependency installation,
migration, commit, PR, deployment, DNS change, production scan, report injection,
case/alert side effect, Hosted-DMARC automation, PR #232 change, governance
document change, or Item 8 work.

Implementation P1 begins only after Claude review and explicit founder approval
of the revised three-document design.
