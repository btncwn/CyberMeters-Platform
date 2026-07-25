# ADR-004: DMARCbis adoption under an implementation hold

Status: Accepted in principle; implementation hold
Founder ruling: 25 July 2026
Canonical design baseline: `0d9881faf8eac248ed1c6b4e37670b1c1832dbc5`
Protocols: RFC 9989, RFC 9990, RFC 9991
Companion documents:

- [`docs/DMARCBIS-IMPLEMENTATION-GUIDE.md`](../DMARCBIS-IMPLEMENTATION-GUIDE.md)
- [`docs/DMARCBIS-ACCEPTANCE-GUIDE.md`](../DMARCBIS-ACCEPTANCE-GUIDE.md)

## 1. Status and evidence markings

This ADR replaces the decision portions of the 2,175-line Item 7 design report. It
does not authorize implementation.

The following markings are normative for all three Item 7 design documents:

- **[REPOSITORY-VERIFIED]** — directly traced at the canonical baseline.
- **[RFC-VERIFIED]** — checked against primary RFC Editor text at the cited section.
- **[FOUNDER-RULING]** — settled by the founder directive dated 25 July 2026.
- **[EXTERNAL-PACKAGE-VERIFIED]** — checked against the named package's primary
  registry/source metadata on 25 July 2026.
- **[DESIGN DECISION]** — the approved-in-principle future implementation contract;
  it is not current production behavior.
- **[NOT DIRECTLY VERIFIED]** — not proven from the repository, primary RFC text, or
  a production exercise in this design-only episode.
- **[IMPLEMENTATION GATE]** — must pass after the hold is lifted and before the
  affected PR can freeze or merge.

**[FOUNDER-RULING]** Items 5 and 6 are LIVE-ACCEPTED and are immutable production
baseline. PR #307 backlog refinements are merged. `MERGED` does not mean
`LIVE-ACCEPTED`.

## 2. Context

**[REPOSITORY-VERIFIED]** The current production DMARC path is an exact-domain,
RFC 7489-era interpretation:

1. `scan-engine.js` invokes `email-scan.js`.
2. `email-scan.js` makes one Cloudflare DoH TXT request at
   `_dmarc.<input-domain>`.
3. It selects the first string beginning case-insensitively with `v=dmarc1`,
   splits it at semicolons, and applies last-value-wins tag assignment.
4. `dmarc-state.js` and `email-intel.js` derive percentage-era policy states.
5. The enumerable report is written to R2; the richer in-process `dmarc_state`
   is non-enumerable.
6. Findings, the coarse `email_dmarc_policy_changed` event, reports, APIs,
   dashboards, Executive Report, and PDF consume different projections of that
   result.

**[REPOSITORY-VERIFIED]** The production path does not implement RFC 9989
organisational-domain discovery, `np`, `t`, `psd`, general RFC 9990 external RUA
authorisation, or an immutable DMARCbis protocol block.

**[RFC-VERIFIED]** RFC 9989 replaces PSL-based DMARC organisational-domain
discovery with the bounded DNS tree walk in
[§4.10](https://www.rfc-editor.org/rfc/rfc9989.html#section-4.10).
Policy precedence is defined in
[§4.10.1](https://www.rfc-editor.org/rfc/rfc9989.html#section-4.10.1), and
organisational-domain selection in
[§4.10.2](https://www.rfc-editor.org/rfc/rfc9989.html#section-4.10.2).

The prior design correctly identified the protocol and product deltas, but four
parts required revision:

1. Its 15-second DMARC phase did not fit the whole-scan deadline.
2. Its `t=y` reduction rule needed a verbatim primary-text check.
3. Its proposed two-table DMARC persistence duplicated the existing Email
   Protection occurrence substrate.
4. Its eight-PR sequence was larger than necessary.

## 3. Decision summary

### D1. Use one additive DMARCbis protocol model

**[DESIGN DECISION]** New scans use one canonical stack:

- strict RFC 9989 policy parser;
- separate RFC 9990 authorisation-record parser;
- injected DNS observation interface;
- bounded DNS tree-walk resolver;
- domain-existence resolver;
- effective-policy derivation for `p`, `sp`, `np`, and `t`;
- budget-gated external RUA authorisation;
- unchanged Item 6 Evidence-Grade adapter;
- legacy exact-record compatibility adapter;
- immutable R2 protocol evidence;
- existing Email Protection lifecycle occurrence source.

No frontend, renderer, alert engine, case route, or report builder may derive
DMARC policy independently.

### D2. Split the scan into guaranteed core and optional external authorisation

**[FOUNDER-RULING]** The previous 15-second phase is rejected. The global scan
ceiling must not increase.

**[REPOSITORY-VERIFIED]** `scan-budget.js` sets:

- `totalCeilingMs = 24_000`;
- `budgetMs = 19_000`;
- `finalizationReserveMs = 5_000`;
- `maxBudgetMs = 19_000`.

**[DESIGN DECISION]** DMARC work has two tiers:

1. **Core** — a new 750 ms capped Phase-1 peer. It always returns a structured
   result, even when that result is honestly `unavailable`. It performs at most:
   eight primary policy TXT questions, one author-domain existence question, and
   one decisive-record corroboration question.
2. **External RUA authorisation** — a separate optional 600 ms phase. It launches
   only after the core is complete and only when the global deadline, complete
   outbound accounting, and remaining subrequest capacity can reserve the entire
   admitted host cost. It never starts a partial host walk.

The external phase has no guaranteed slot. A launch refusal or destination bound
produces `rua_authorisation_completeness=incomplete` with a reason. It never
produces an empty-success, healthy, or “all authorised” result.

The maximum scheduled wall-clock envelope becomes:

| Serialized scan portion | Maximum |
| --- | ---: |
| Existing Phase 1, including the new parallel core peer | 12,000 ms |
| Existing takeover | 750 ms |
| Existing asset exposure | 2,500 ms |
| Existing Phase 5 intelligence | 1,000 ms |
| Optional external RUA authorisation | 600 ms |
| Existing cloud discovery | 500 ms |
| **Executable envelope** | **17,350 ms** |
| Remaining inside the 19,000 ms executable budget | **1,650 ms** |
| Existing finalisation reserve | **5,000 ms** |

This is a cap proof, not a latency prediction. Provider work may return earlier.
No DMARC query may extend its owning cap.

**[DESIGN DECISION]** Full external authorisation on every scan is not promised by
Item 7. Guaranteeing it is a later scan-architecture decision involving reserved
mode and the separately governed Item 2 / Item 13 capacity work.

### D3. Share DNS questions inside one scan

**[REPOSITORY-VERIFIED]** `scan-budget.js` has an invocation-scoped DNS cache
primitive, but the normal scan path does not currently pass one shared cache
through the DNS, Email, and proposed DMARC paths. `ct-provider-cache.js` already
demonstrates the required Item 5 pattern: store an in-flight promise immediately
so concurrent consumers share one provider request.

**[DESIGN DECISION]** The scan engine creates one invocation-scoped DNS question
cache and passes it to all participating DNS consumers. Its key is:

`resolver | lower-case A-label qname | upper-case qtype | DNSSEC-request profile`

The value preserves the in-flight promise and the completed raw observation.
NXDOMAIN, NODATA, SERVFAIL, timeout, truncation, and malformed responses are
cached as their exact outcome; errors are never collapsed into an empty answer.
There is no cross-scan reuse in Item 7.

### D4. RFC 9989, not a product invention, defines `t=y`

**[RFC-VERIFIED]** RFC 9989 §4.7 defines `t` as optional, default `n`, without a
report-generation effect and without an effect when the selected policy is
`none`. For `t=y`, the exact controlling clause says:

> “has an expectation that the policy applied to any failing messages will be one
> level below the specified policy.”

Source:
[RFC 9989 §4.7](https://www.rfc-editor.org/rfc/rfc9989.html#section-4.7).

The next sentence explicitly defines:

- `quarantine + t=y` → `none`;
- `reject + t=y` → `quarantine`;
- `none + t=y` → `none` because `t` has no effect on `none`.

**[DESIGN DECISION]** Store both `declared_policy` and
`effective_requested_policy`. Apply the RFC-defined ladder exactly. This remains
a domain-owner request; it is not evidence that a receiver applied that handling.

### D5. RFC 9989 tree walk is the DMARC organisational-domain authority

**[DESIGN DECISION]** The DMARC resolver no longer uses a PSL or a registrable-root
heuristic for policy discovery. The walk:

- starts at the author domain;
- makes no more than eight policy TXT questions;
- discards non-current-version candidates for policy purposes while preserving
  them as raw evidence;
- discards all current-version policy records at a target when more than one is
  present;
- stops on the sole record's `psd=y` or `psd=n`;
- uses the deep-label shortcut required by RFC 9989 §4.10;
- derives exact, organisational, and PSD precedence under §4.10.1;
- derives the organisational boundary under §4.10.2.

**[REPOSITORY-VERIFIED]** There is no current DMARC PSL resolver to retire. UK
registered-domain and suffix heuristics used by WHOIS, Hosted-DMARC provisioning,
Brand, or Related Changes are separate systems and remain unchanged.

### D6. Preserve `pct`; never apply it to new effective policy

**[RFC-VERIFIED]** RFC 9989 removed `pct`; Appendix A.6 explains its replacement
by `t`:
[RFC 9989 Appendix A.6](https://www.rfc-editor.org/rfc/rfc9989.html#appendix-A.6).

**[DESIGN DECISION]** Historical and newly observed `pct` values remain raw legacy
evidence:

- store the raw value;
- parse a numeric value only for display diagnostics;
- mark `semantics=rfc7489_legacy`;
- mark `applied_to_effective_policy=false`;
- keep legacy API projections;
- never map `pct` to `t`;
- never rewrite old snapshots, events, or conclusions.

### D7. Create zero DMARC observation or condition tables

**[REPOSITORY-VERIFIED]** Migration 088 created
`email_protection_events` as the one append-only occurrence source for the
`email_protection` domain. It states that:

- the event row ID is the occurrence identity;
- `created_at` is when the condition began;
- a second occurrence timestamp or counter would drift;
- one domain key can map to only one lifecycle event source.

**[REPOSITORY-VERIFIED]** `alert-occurrence.js` already maps:

`email_protection -> email_protection_events`

and resolves the latest `monitoring_changed` row whose
`detail.to_recurrence_type` matches the current recurrence.

**[REPOSITORY-VERIFIED]** Migration 089 created a condition/event pair for Website
Security because that domain lacked continuity. Email Protection already has
continuity. Migration 082 already extends the universal `managed_cases` substrate.

**[DESIGN DECISION]** The initial Item 7 implementation creates:

- no `dmarc_policy_observations` table;
- no `dmarc_policy_conditions` table;
- no `email_protection_conditions` table;
- no ninth customer domain key named `dmarc`.

Raw DMARC evidence lives once in the immutable R2 scan report and canonical
snapshot under `protocol_evidence.dmarc`. DMARC lifecycle conditions use:

- `domain_key=email_protection`;
- `record_type=dmarc_policy_condition`;
- a deterministic, disjoint `record_id`;
- `monitoring_changed` only for a real actionable occurrence;
- non-occurrence event types for baseline and availability history.

The initial stable condition types are:

- `missing`;
- `malformed`;
- `multiple`;
- `weak`;
- `unauthorised_rua`.

The deterministic record identity is:

`dmarc:<domain_id>:<condition_type>:<sha256(canonical_subject_key)>`

The full canonical subject key is retained in event detail. The subject is the
author domain or exact DNS name for policy conditions and the normalised RFC 9990
authorisation DNS name for an unauthorised destination. It never includes a scan
ID. The `dmarc:` namespace is disjoint from the existing `hd-` and `esender_`
families.

Previous/current state comparison reads immutable canonical snapshots. It does
not need a mutable D1 current-condition projection. The exact deterministic
record ID permits the existing occurrence resolver to use its indexed
workspace-and-record lookup without an N+1 enumeration.

An `email_protection_conditions` projection may be proposed later only if measured
production query behavior proves that snapshot comparison plus exact event lookup
cannot meet a defined read or atomicity requirement. Such a proposal is a separate
founder-reviewed migration. It must mirror migration 089 and must never duplicate
occurrence identity or condition-start time.

### D8. Use only additive aggregate-report columns

**[REPOSITORY-VERIFIED]** Migration 054 stores RFC 7489-era aggregate fields
`policy_p`, `policy_sp`, and `policy_pct`. Migration 100 adds atomic ingest
claiming. No new table is needed for RFC 9990 report metadata.

**[DESIGN DECISION]** If the P2 repository recheck still shows the same gap, one
additive migration adds nullable metadata columns to `dmarc_aggregate_reports`:

- `report_format_version`;
- `xml_namespace`;
- `discovery_method`;
- `policy_np`;
- `policy_testing`;
- `policy_fo`;
- `schema_conformance`;
- `parser_version`.

`policy_pct` remains permanently. Existing rows remain valid. Rollback is code
rollback; additive nullable columns remain.

### D9. Preserve immutable snapshots through dual readers

**[FOUNDER-RULING]** Keep outer canonical snapshot schema v1 and add a versioned
nested block.

**[DESIGN DECISION]** New writers add:

- `protocol_evidence.dmarc.schema = dmarc-policy.v2`;
- methodology/parser/resolver versions;
- raw lookup chain;
- parsed records and diagnostics;
- organisational and policy-source provenance;
- declared and effective requested policy;
- `sp`, `np`, `t`, and legacy `pct`;
- per-destination external authorisation;
- component completeness;
- unchanged Evidence-Grade contract;
- applied limits and evidence fingerprint.

Legacy exact-record fields retain exact-record meaning. An inherited policy is
never written into the legacy `policy` field.

Old snapshots remain byte-for-byte unchanged. New readers use the nested block
when present and otherwise render stored legacy conclusions. They do not run new
logic over old evidence.

**[FOUNDER-RULING]** Historical surfaces add the renderer-owned notice:

> This report preserves the DMARC methodology and conclusions used when the scan
> completed.

### D10. Keep external RUA authorisation separate from RUA trust

**[RFC-VERIFIED]** RFC 9990 §4 requires an external authorisation check when the
policy-source organisational domain differs from the destination-host
organisational domain:
[RFC 9990 §4](https://www.rfc-editor.org/rfc/rfc9990.html#section-4).
At least one valid authorisation record is sufficient; multiple valid records do
not invoke the policy-record multiplicity rule.

**[DESIGN DECISION]** Each URI has separate parse, same-domain, authorisation,
completeness, authorised-destination, and ingestion-trust states. Unsupported URI
schemes and product limits are operational support outcomes, not RFC-invalidity
claims.

**[FOUNDER-RULING]** Item 5's trust boundary remains unchanged. DNS
authorisation does not make an inbound report authoritative. Forged,
unauthorised, or ordinary inbound RUA evidence remains observational unless the
existing source-specific trust requirements are independently satisfied. It
cannot drive DNS truth, readiness, BRI, case verification, authoritative alerts,
or recovery.

### D11. Parse RFC 9991 policy tags but do not ingest failure reports

**[FOUNDER-RULING]** Parse and preserve `ruf` and `fo`. Item 7 does not add
RFC 9991 failure-report ingestion. Any future failure-report processing requires a
separate founder gate.

### D12. Use `tr46@6.0.0` for A-label conversion

**[DESIGN DECISION]** The named library is `tr46@6.0.0`, pinned exactly in the
Worker package when P1 is authorised. Domain canonicalisation will not be
hand-built.

Design-time package vet:

| Check | Result |
| --- | --- |
| Primary source | **[EXTERNAL-PACKAGE-VERIFIED]** `jsdom/tr46`, release 6.0.0, source git head `7f1eb920768c794be40962a4f0cbad670a398d04`. |
| Purpose | **[EXTERNAL-PACKAGE-VERIFIED]** JavaScript implementation of Unicode UTS #46 IDNA compatibility processing. |
| License | **[EXTERNAL-PACKAGE-VERIFIED]** MIT. |
| Runtime shape | **[EXTERNAL-PACKAGE-VERIFIED]** JavaScript 100%; CommonJS entry; seven package files; 228,404 unpacked bytes. |
| Runtime dependencies | **[EXTERNAL-PACKAGE-VERIFIED]** One: `punycode ^2.3.1`. |
| Install hooks | **[EXTERNAL-PACKAGE-VERIFIED]** No `preinstall`, `install`, or `postinstall` hook in the 6.0.0 registry manifest. |
| Source behavior | **[EXTERNAL-PACKAGE-VERIFIED]** Entry uses local data/regex modules, `punycode`, standard strings/arrays/normalisation; no filesystem, network, child process, native addon, or dynamic evaluation was observed in the published entry. |
| Vulnerability spot-check | **[EXTERNAL-PACKAGE-VERIFIED]** OSV package/version queries returned no records for `tr46@6.0.0` or `punycode@2.3.1` on 25 July 2026. This is not proof of absence. |
| Current repository | **[REPOSITORY-VERIFIED]** The Worker has no runtime dependency on `tr46`; the frontend lock contains a transitive `tr46` 5.x dependency, which is not a Worker implementation. |
| Worker compatibility | **[NOT DIRECTLY VERIFIED]** The package declares Node `>=20` and is CommonJS. Its APIs appear bundle-compatible, but no dependency was installed and no Wrangler build was run because implementation is on hold. |

The approved conversion profile is non-transitional processing with bidi,
hyphen, joiner, STD3, invalid-Punycode, and DNS-length checks enabled. The
submitted Unicode form is preserved separately from the lower-case A-label.

**[IMPLEMENTATION GATE]** Before parser freeze, P1 must verify the exact tarball
integrity
`sha512-bLVMLPtstlZ4iMQHpFHTR7GAGj2jxi8Dg0s2h2MafAE4uSWF98FC/3MomU51iQAMf8/qDUbKWf5GxuvvVcXEhw==`,
review the lockfile delta and transitive dependency, run audit/SBOM checks, run
Wrangler dry-run without Node compatibility polyfills, and pass Unicode/ASCII,
bidi, joiner, invalid `xn--`, empty-label, 63-octet-label, and 253-octet-name
fixtures. Any failure reopens the library choice before parser code freezes.

### D13. Keep lifecycle activation narrow and manual

**[FOUNDER-RULING]** Only these definitive actionable regressions may activate
risk alerts:

- record becomes malformed;
- multiple current-version policy records appear;
- effective requested policy weakens;
- an exact record is lost without equal or stronger inheritance;
- an external RUA destination is newly introduced without definitive
  authorisation, or a previously authorised destination becomes definitively
  unauthorised.

Availability degradation is non-risk monitoring evidence.

**[FOUNDER-RULING]** Eligible conditions do not auto-open managed cases. Case
creation is manual/case-eligible and must use `createManagedCase(...)`; every
transition must use `canTransitionCase(...)`.

**[FOUNDER-RULING]** `monitoring_recovered` is excluded from Item 7.

### D14. Preserve Related Changes identity

**[FOUNDER-RULING]** RFC-derived organisational domain does not replace the
existing Related Changes registrable-root correlation key. Eligible DMARC events
enter the existing correlation model only with complete evidence, an independent
evidence family, bounded time, contradiction preservation, and:

> These changes were observed close together and may be related. CyberMeters has
> not established that one caused the other or that they indicate compromise.

### D15. Hosted-DMARC stays suggestion-only

**[FOUNDER-RULING]** Hosted-DMARC Gate 1/2 remains suspended. Item 7:

- does not reactivate autopilot;
- does not mutate customer DNS;
- does not redesign suspended automation;
- does not absorb or reopen the separately recorded RUA-routing drift;
- may expose only future integration boundaries;
- uses “Suggested DNS change — not applied by CyberMeters.”

## 4. Founder choices: settled record

| Decision | Founder ruling applied |
| --- | --- |
| DNS budget | Two tier: guaranteed bounded core, optional budget-gated external authorisation; no global ceiling increase. |
| Reserved mode | Publish complete core and explicit incomplete RUA state when capacity is insufficient. |
| Resolver policy | Primary resolver plus decisive-record corroboration; withhold on disagreement. |
| IDNA | Pin and vet `tr46@6.0.0`; do not hand-build. |
| Historical banner | Renderer notice approved; snapshot bytes untouched. |
| Alert activation | Only the five definitive actionable regressions in D13. |
| Case creation | Manual/case-eligible; never auto-open. |
| `monitoring_recovered` | Excluded. |
| DNSSEC erratum 8995 | Keep NXDOMAIN/NODATA semantics; retain DNSSEC flags as limits; claim no authenticated denial. Erratum status remains **[NOT DIRECTLY VERIFIED]**. |
| URI limits | Product support limits only; never RFC-invalidity claims. |
| RFC 9991 | Preserve `ruf`/`fo`; no failure-report ingestion. |
| Acceptance namespace | Founder will designate two zones, report generator, and workspace; no values are assumed. |
| Snapshot | Outer v1 plus nested versioned DMARC block. |
| Destination bound | Overflow makes RUA authorisation incomplete and prohibits “all authorised”. |
| Monitoring wording | “No-action policy”; never infer “RFC Monitoring Mode” from `p=none` alone. |
| Remediation IDs | Preserve compatible existing IDs; external-RUA ID only after registry review. |
| Related Changes | Keep the existing registrable-root correlation key. |

## 5. Consequences

### Positive

- The core RFC 9989 conclusion has a bounded place inside the existing scan.
- External variability cannot consume the whole scan or masquerade as success.
- Policy, organisational boundary, existence, RUA authorisation, and RUA trust
  remain separate.
- Historical evidence remains immutable and readable.
- Email Protection retains one occurrence clock and one occurrence source.
- The six-PR sequence separates pure protocol correctness, production
  integration, contracts, lifecycle, managed action, and presentation.

### Costs and risks

- Core discovery adds up to ten logical DNS questions, although shared-cache
  reuse makes the worst incremental default-path total no more than eight against
  the traced current DNS set.
- Reserved mode must spend core capacity before exposure and will therefore
  reduce the dynamic exposure host cap.
- External authorisation will often be incomplete under tight capacity. That is
  an accepted honest limitation, not a defect to hide.
- CommonJS bundling for `tr46` is not yet runtime-proven.
- Snapshot-to-snapshot condition derivation must remain atomic with lifecycle
  event append or fail closed.
- A future stable-condition projection might become necessary, but only measured
  evidence can justify it.

## 6. Implementation sequence decision

No PR is authorised. After explicit founder approval, the maximum feature
sequence is:

1. **P1** — pure parser, tree walk, effective derivation, and external
   authorisation resolver with injected DNS; no production caller.
2. **P2** — production observation integration, shared cache, two-tier budget,
   lifecycle reuse, and additive RFC 9990 aggregate columns if still required.
3. **P3** — immutable snapshot and additive API dual readers.
4. **P4** — DMARC posture events and Related Changes.
5. **P5** — narrow alerts, manual managed cases, canonical remediation.
6. **P6** — customer surfaces, Executive Report, and PDF.

The founder-controlled acceptance gate is not a feature PR.

## 7. Non-goals

- Hosted-DMARC autopilot reactivation.
- Automatic customer DNS mutation.
- Redesign of Item 5 or Item 6.
- Unrelated Email Protection work.
- Brand, Certificates & Trust, or Attack Surface implementation.
- New governance systems.
- Destructive migration.
- Historical snapshot rewriting.
- Broad UI redesign.
- PR #232 changes.
- Founder governance-document changes.
- Item 8 or later backlog work.

## 8. Hold statement

This ADR is design documentation only.

No source code, generated code, migration, commit, pull request, deployment,
production mutation, customer DNS change, Hosted-DMARC automation change, PR #232
change, founder governance-document change, or Item 8 work is authorised.

Item 7 remains **ACCEPTED IN PRINCIPLE · IMPLEMENTATION HOLD** until Claude review
and explicit founder approval of this three-document revision.
