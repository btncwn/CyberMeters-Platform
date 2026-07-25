# CyberMeters Item 7 — DMARCbis acceptance guide

Status: Design only; implementation hold
Founder ruling: 25 July 2026
Canonical design baseline: `0d9881faf8eac248ed1c6b4e37670b1c1832dbc5`
Production acceptance authorised now: No

This guide is the future founder-controlled acceptance plan for the design in:

- [`adr/ADR-004-dmarcbis.md`](adr/ADR-004-dmarcbis.md)
- [`DMARCBIS-IMPLEMENTATION-GUIDE.md`](DMARCBIS-IMPLEMENTATION-GUIDE.md)

It does not authorise DNS changes, deployment, scans, report ingestion, alerts,
cases, or customer side effects. `MERGED` does not mean `LIVE-ACCEPTED`.

## 1. Evidence markings

- **[REPOSITORY-VERIFIED]** — directly traced at the canonical design baseline.
- **[RFC-VERIFIED]** — checked against primary RFC Editor text.
- **[FOUNDER-RULING]** — settled by the 25 July 2026 directive.
- **[ACCEPTANCE REQUIREMENT]** — future evidence needed for a pass.
- **[NOT DIRECTLY VERIFIED]** — not proven during this design-only episode.

All live outcomes in this document are **[NOT DIRECTLY VERIFIED]** until the
future acceptance run records them.

## 2. Authority and safety boundary

**[FOUNDER-RULING]** The founder will designate:

- the founder-controlled policy-test DNS zone;
- a second founder-controlled external RUA destination zone;
- a founder-controlled RFC 9990 aggregate report generator;
- a founder-controlled CyberMeters workspace.

No domain, generator, or workspace value is assumed in this guide.

Future acceptance may use only:

- those designated zones and workspace;
- reversible RRsets;
- founder-approved scan timing;
- founder-approved alert/case/report side effects;
- founder-approved deployment and rollback identities;
- isolated notification recipients;
- raw evidence that contains no unrelated customer data.

It must not:

- modify an unrelated customer workspace, case, alert, report, or DNS zone;
- send email or reports to unrelated recipients;
- mutate a third-party destination without explicit authority;
- claim success from a `401`, deployment, merge, or fixture pass alone;
- reactivate Hosted-DMARC autopilot;
- modify PR #232 or founder governance documents;
- start Item 8.

## 3. Required acceptance identities

Before a production run, create a founder-approved run manifest outside immutable
historical artifacts containing:

- acceptance run ID;
- approved scenario IDs;
- designated workspace/domain IDs;
- both DNS zone IDs and authoritative nameservers;
- report generator identity;
- notification sink;
- pre-deploy live Worker version;
- pre-deploy rollback Worker version;
- pre-deploy Pages deployment and rollback identity, if affected;
- candidate Worker/Pages versions;
- migration number and application identity, if P2 adds nullable RFC 9990
  columns;
- code commit/release tag;
- operator and founder approval timestamps;
- scenario-specific DNS mutation and rollback IDs.

No secret, API token, or provider credential belongs in the evidence bundle.

## 4. Pre-change capture

Before every controlled scenario:

1. Export the complete current RRsets for every name that will change.
2. Record authoritative nameserver names and addresses.
3. Capture zone SOA, serial, negative TTL, and affected positive TTLs.
4. Capture raw authoritative `+norecurse` TXT responses from every nameserver.
5. Capture author-domain existence responses that distinguish NXDOMAIN and
   NODATA, including authority sections.
6. Capture the current external-authorisation query response where applicable.
7. Capture public recursive answers as secondary corroboration only.
8. Record the latest production scan ID for the designated domain.
9. Record the current R2 scan-report object key/hash.
10. Record the current canonical snapshot ID/hash.
11. Capture current API, dashboard, finding/observation, Executive Report, PDF,
    and technical appendix output.
12. Capture current related-change, alert-occurrence, and managed-case state.
13. Confirm unrelated notifications and report deliveries are disabled.
14. Confirm Hosted-DMARC Gate 1/2 remains ineligible.

The pre-change bundle is incomplete if any affected RRset cannot be restored
exactly.

## 5. DNS mutation and propagation procedure

For each reversible change:

1. Record the provider change ID, exact before/after RRset, operator, and UTC time.
2. Do not shorten an existing TTL and immediately treat the new TTL as the
   propagation bound; wait using the previous TTL.
3. Wait at least the previous TTL plus measured propagation margin.
4. Query every authoritative nameserver independently with recursion disabled.
5. Capture raw packet/text output, qname/qtype, rcode, answer, authority, TTL,
   truncation, and DNSSEC flags where available.
6. Require the authoritative servers to agree before triggering a CyberMeters
   scan, except in a scenario deliberately testing disagreement.
7. Query at least two independent public recursive oracles as corroboration.
8. Record cached disagreement; do not substitute a recursive result for
   authoritative state.
9. Trigger the production scan only after the scenario's authoritative
   precondition is met.
10. Record scan ID, R2 object/hash, snapshot ID/hash, event/occurrence ID, alert
    ID, Related Changes cluster ID, and manual case ID where applicable.

DNSSEC flags are evidence/limits. This acceptance does not claim authenticated
denial.

## 6. Layered pass gates

Acceptance is split into six independently evidenced gates. A later gate cannot
repair a failed earlier gate.

### Gate A — Parser and derivation

#### Controlled scenarios

Use founder-designated names to prove:

1. exact organisational-domain record with `psd=n`;
2. exact subdomain record;
3. subdomain without an exact record;
4. inherited `p`;
5. inherited `sp`;
6. inherited `np`;
7. exact `p=reject;t=y`;
8. exact `p=quarantine;t=y`;
9. absent `t` default;
10. standard organisational-domain tree walk;
11. deep-label eight-question shortcut;
12. existent NODATA child;
13. nonexistent NXDOMAIN child;
14. complete no-policy walk;
15. malformed exact record with usable inheritance;
16. multiple exact records with usable inheritance;
17. duplicate tag;
18. unknown tag;
19. legacy `pct=25`;
20. no-action policy;
21. quarantine;
22. reject;
23. `psd=y` stop;
24. invalid policy plus valid `rua` fallback;
25. invalid policy without valid `rua`;
26. reversible SERVFAIL/timeout through an isolated delegated name;
27. decisive resolver disagreement, if it can be created without weakening other
    production traffic;
28. Unicode author/destination names from the approved IDNA vector set.

#### RFC `t` proof

**[RFC-VERIFIED]** The expected result must be tied directly to RFC 9989 §4.7:

> “has an expectation that the policy applied to any failing messages will be one
> level below the specified policy.”

Acceptance fails if:

- `p=reject;t=y` remains effective `reject`;
- `p=reject;t=y` becomes effective `none`;
- `p=quarantine;t=y` remains `quarantine`;
- `t` changes reporting semantics;
- wording claims observed receiver behavior.

#### Budget scenarios

Run deterministic clock/provider acceptance before live DNS:

| Mode | Injected condition | Required result |
| --- | --- | --- |
| Complete | Primary core ≤300 ms, corroboration ≤80 ms, external has ≥600 ms and ≥11 units. | Core complete ≤750 ms; external admitted/complete ≤600 ms; whole scheduled envelope ≤17,350 ms. |
| Core-only degraded | Core complete; external has 599 ms or 10 units. | No external question; explicit incomplete/budget reason; no “all authorised”; no global false-partial caused solely by the optional skip. |
| Provider timeout | Required primary core work reaches 500 ms. | Structured core ≤750 ms; unavailable policy; external skipped; no missing/removal/weakening event. |

Live telemetry must then show:

- core allocation no more than 750 ms;
- no more than eight primary policy TXT questions;
- no more than one existence question;
- no more than one decisive policy corroboration question;
- cache in-flight dedupe for overlapping DNS/Email questions;
- other Email signals retain their own cap;
- no finalisation-reserve use;
- no orphaned `running` scan.

#### Real-world core-completion-rate measurement

**[ACCEPTANCE REQUIREMENT]** Gate A must measure the core completion rate in P7;
the 500 ms primary-walk allocation and 750 ms core cap are not assumed to be
operationally sufficient merely because deterministic fixtures pass.

The founder-approved run manifest must define a bounded domain cohort containing:

- ordinary-label founder-controlled domains;
- founder-controlled deep-label names whose planned walk exercises the
  eight-question shortcut;
- founder-controlled names delegated through the approved slow-resolver
  scenario without affecting unrelated traffic.

For the whole cohort and separately for each stratum, record:

- `eligible_core_scans`;
- `core_complete_scans`;
- `core_incomplete_scans` grouped by exact reason;
- `core_completion_rate = core_complete_scans / eligible_core_scans`;
- primary-walk, existence, corroboration, and total-core elapsed-time
  distributions, including p50, p95, p99, and maximum;
- planned, issued, cache-hit, timed-out, and cancelled question counts;
- resolver/provider identity and the observed disagreement rate;
- whether any scan used the finalisation reserve or remained orphaned.

A core result counts as complete only when every logically required discovery,
existence, and decisive-corroboration component needed for that result is
complete under the implementation guide. A structured but unavailable result
meets the bounded-return contract but does not count as core complete.

No completion-rate threshold is invented by this guide. P7 records the measured
rates and distributions, and the founder makes the explicit acceptance decision.
The evidence bundle must not relabel an incomplete result as success or omit
slow/deep-label results from the denominator.

#### Gate A evidence

For each scenario, preserve:

- authoritative DNS before/after/rollback;
- planned and issued lookup path;
- logical-use/prefetch flags;
- raw resolver observations;
- candidate records/chunks;
- parser diagnostics;
- organisational domain and provenance;
- policy source and provenance;
- existence state;
- declared and effective requested policy;
- `p/sp/np/t/psd` objects;
- legacy `pct` object;
- Evidence Grade and all limits;
- provider/corroboration state;
- API and snapshot parity.

#### Gate A pass criteria

- RFC query order, stop, and eight-question maximum are correct.
- NXDOMAIN and NODATA produce different applicability where required.
- Temporary failure is never absence.
- Multiple/malformed candidates are never arbitrarily selected.
- `t` follows the direct RFC clause.
- `pct` has no current effective-policy effect.
- Core fits the approved whole-scan envelope.
- No receiver-enforcement or false-healthy wording appears.
- Every required mutation from the implementation guide turns its validator red.

### Gate B — External RUA authorisation

#### Controlled scenarios

1. same-organisational-domain `rua`;
2. external authorised `rua`;
3. external definitive unauthorised `rua`;
4. malformed authorisation RR only;
5. multiple valid authorisation RRs;
6. mixed valid/malformed authorisation RRs;
7. temporary authorisation timeout/SERVFAIL;
8. decisive authorisation resolver disagreement;
9. multiple destinations with mixed results;
10. same-host override;
11. conflicting valid same-host overrides;
12. prohibited second-host override;
13. constructed DNS name over the DNS limit;
14. unsupported URI scheme;
15. malformed URI;
16. obsolete `!size`;
17. URI over the product bound;
18. more than 10 URIs;
19. more than 5 unique external hosts;
20. budget sufficient for one host but not the next.

#### Gate B evidence

- raw policy `rua` list in source order;
- normalised destination host;
- source/destination organisational-domain walks;
- exact constructed authorisation qname;
- every raw authorisation RR;
- primary/corroborating result;
- per-URI parse, same-domain, record, authorisation, destination, completeness,
  and trust states;
- reservation decision and remaining time/subrequest evidence;
- no question for an unadmitted host;
- aggregate completeness calculation;
- unchanged Item 5 authority eligibility.

#### Gate B pass criteria

- same-domain destination does not require external authorisation;
- at least one valid RR authorises, including multiple/mixed sets;
- no valid RR is not authorised;
- timeout/budget/disagreement is unavailable/incomplete, not unauthorised;
- no partial-host work is issued;
- overflow prohibits “all destinations authorised”;
- different-host override makes both destinations unusable;
- authorisation never proves delivery or grants RUA authority;
- only a newly introduced definitively unauthorised destination or an
  authorised→definitively unauthorised regression is risk-alert eligible.

### Gate C — RUA ingestion

Use only a founder-controlled generator and inbox/source:

1. valid RFC 9990 `urn:ietf:params:xml:ns:dmarc-2.0` report;
2. old RFC 7489-era report;
3. duplicate with the same source/report identity;
4. report whose policy differs from current DNS during a controlled propagation
   interval;
5. malformed XML/archive;
6. oversized archive;
7. report with `discovery_method=treewalk`;
8. report with `np`, `fo`, and `testing`;
9. report with an unknown extension;
10. source that fails the existing Item 5 trust requirement.

Capture:

- transport/source type;
- message authentication result where available;
- namespace and format version;
- report generator/report ID and period;
- discovery method;
- `p/sp/np/fo/testing`;
- raw policy metadata;
- parser/schema-conformance version/state;
- atomic ingest claim identity;
- duplicate suppression;
- aggregate/source row counts;
- source trust and authority eligibility.

Gate C passes only if:

- old and new reports coexist;
- nullable RFC 9990 columns preserve new metadata;
- `policy_pct` remains legacy evidence;
- duplicate report data is not double-counted;
- current DNS is not overwritten by report policy;
- malformed/oversized input fails safely;
- unknown extensions do not invent semantics;
- inbound email remains observational under Item 5;
- no RFC 9991 failure-report ingestion path exists.

### Gate D — Policy-change lifecycle

#### Controlled sequence

Starting from a complete baseline:

1. establish no-action policy;
2. change to quarantine;
3. change to reject;
4. set `t=y`;
5. remove exact record while retaining equal/stronger inheritance;
6. remove exact record without equal/stronger inheritance;
7. introduce one malformed current-version record;
8. introduce multiple current-version records;
9. restore the original valid record;
10. authorise an external RUA;
11. remove that authorisation definitively;
12. replay an already processed before/after pair;
13. run an intentionally incomplete current observation;
14. re-establish complete evidence after the incomplete observation;
15. resolve and later recur an actionable condition.

#### Lifecycle proof

For each step:

- previous/current snapshots are immutable and relevant components complete;
- deterministic condition `record_id` excludes scan ID;
- `record_type=dmarc_policy_condition`;
- `domain_key=email_protection`;
- no new `dmarc` domain key/table exists;
- baseline rows are structurally non-alertable;
- one actionable transition appends one `monitoring_changed` row;
- that row's ID is the occurrence identity;
- that row's `created_at` is condition start;
- replaying the same before/current snapshot pair resolves to the same
  deterministic event primary key;
- same state does not append another occurrence;
- recurrence appends a new occurrence for the same stable condition;
- availability uses a non-occurrence event and no recurrence type.

#### Alert and case proof

Alerts:

- only malformed, multiple, weakened effective policy, unprotected record loss,
  and newly introduced or newly changed definitive unauthorised RUA are eligible;
- strengthened policy, creation, availability, budget skip, legacy `pct`, and
  inheritance without weakening do not alert;
- one occurrence creates at most one alert;
- replay creates no duplicate alert.

Cases:

- no case opens automatically;
- an eligible condition is available for explicit manual creation;
- manual creation uses `createManagedCase(...)`;
- every transition uses `canTransitionCase(...)`;
- one occurrence/condition has at most one intended case link;
- a note/customer assertion does not verify;
- RUA evidence does not verify;
- an incomplete scan does not verify;
- only a later complete matching CyberMeters DNS observation may verify;
- recurrence preserves case and event history.

Related Changes:

- only complete material DMARC events are eligible;
- an independent family is required;
- existing temporal-window behavior is retained;
- existing registrable-root key is unchanged;
- RFC organisational domain remains metadata;
- contradiction remains visible;
- wording says related, not necessarily caused;
- no compromise claim appears.

Gate D fails on any duplicate alert, auto-opened case, event from incomplete
evidence, `monitoring_recovered`, causal wording, or second occurrence clock.

### Gate E — API, dashboard, Executive Report, and PDF

For every material state, compare:

- R2 scan report protocol object;
- canonical snapshot;
- scan API;
- Email Protection API;
- dashboard;
- finding;
- observation;
- posture timeline;
- alert;
- managed case;
- remediation;
- Related Changes;
- Executive Report;
- PDF;
- technical appendix.

All applicable surfaces must agree on:

- exact record observation;
- record validity;
- lookup path;
- organisational domain and provenance;
- policy source and kind;
- declared policy;
- effective requested policy;
- inheritance reason;
- `p/sp/np/t/psd`;
- legacy `pct`;
- each RUA authorisation;
- component completeness;
- provider/corroboration state;
- Evidence Grade;
- methodology and limits.

Historical proof uses an old RFC 7489-era snapshot:

- snapshot bytes and hash unchanged;
- no new protocol block inserted;
- old conclusion not recomputed;
- legacy `pct` not mapped to `t`;
- inherited policy not manufactured;
- historical-methodology notice rendered;
- regenerated Executive Report/PDF uses stored legacy meaning.

Wording guards must find none of:

- proven receiver enforcement;
- absolute spoof protection;
- full RFC compliance without complete evidence;
- malicious activity from DMARC failure;
- CyberMeters-applied DNS;
- delivery/working reports from RUA publication or authorisation;
- RFC Monitoring Mode from `p=none`;
- monitoring recovered.

Gate E also requires legacy clients to keep their exact-record fields and new
clients to interpret null/empty/absent distinctly.

### Gate F — Hosted-DMARC suggestion-only

Prove:

- Gate 1/2 remains ineligible;
- no Cloudflare/customer DNS mutation call occurs;
- no automatic policy ramp occurs;
- no automatic `pct` or `t` change occurs;
- no hosted provider route is silently created;
- existing hosted `verified` meaning remains unchanged;
- DMARCbis can show a suggestion without execution;
- UI/case/remediation says “suggested, not applied”;
- existing RUA-routing drift is not modified, absorbed, reopened, or
  reclassified;
- no future integration boundary is represented as active automation.

Any observed mutation call is an immediate acceptance failure and rollback
trigger.

## 7. D1/R2 and immutable-snapshot reconciliation

The accepted zero-new-table architecture changes the original reconciliation
plan.

Required:

- exactly one canonical DMARC protocol object per new scan report;
- its canonical hash matches `protocol_evidence.dmarc` in the corresponding
  snapshot;
- legacy exact projection and v2 block derive from the same in-memory canonical
  result;
- no D1 raw DMARC observation table or duplicate protocol JSON exists;
- aggregate-report rows contain only their intended RFC 9990 metadata/records;
- every DMARC lifecycle event references existing scan/snapshot identities and
  evidence fingerprints;
- no lifecycle event refers to a missing R2 report/snapshot;
- one actionable transition has one append-only occurrence row;
- no duplicate alert occurrence;
- no duplicate manual case link;
- no cross-tenant event, aggregate report, snapshot, report, alert, or case read;
- soft-deleted workspace receives no scan, event, alert, case, or ingestion;
- purge removes workspace-scoped D1 event/report rows in existing order while
  respecting immutable artifact retention policy.

The D1 event row is occurrence evidence, not a copy of raw DNS.

## 8. Regression and mutation gate

Before any production deployment:

- P1 RFC parser/tree-walk/IDNA validators green;
- every required parser/derivation mutation red;
- deadline complete/core-only/provider-timeout validators green;
- cap/removal/partial-host mutations red;
- shared-cache in-flight dedupe validator green;
- default and reserved scan-budget validators green;
- anti-orphan/finalisation validators green;
- external authorisation and second-hop validators green;
- Item 5 trust-expansion mutation red;
- old/new aggregate report and duplicate-ingest tests green;
- tenant-isolation, soft-delete, and purge tests green;
- old/new snapshot and API compatibility tests green;
- every lifecycle subtype/completeness test green;
- baseline flood, recurrence, occurrence, and dedupe mutations red;
- auto-case and note-only-verification mutations red;
- Related Changes root/independence/contradiction tests green;
- customer wording mutation red;
- frontend tests/coverage/build green;
- Worker syntax and Wrangler dry-run green;
- `git diff --check` and full CI green.

Deployment is not validation. A green fixture suite is not production acceptance.

## 9. Future deployment and propagation-aware checks

When founder approval authorises the candidate:

1. Recheck latest main, release tag, migrations, live Worker and rollback IDs.
2. Confirm the candidate contains only the approved Item 7 PR sequence.
3. Apply only the reviewed additive aggregate columns, if P2 required them.
4. Deploy Worker and Pages with recorded rollback identities.
5. Run no-op smoke proving authentication, tenant isolation, scan finalisation,
   R2 snapshot durability, and absence of DNS mutation calls.
6. Run Gate A before enabling lifecycle exposure.
7. Run Gate B/C with the founder-controlled second zone/generator.
8. Run Gate D only with founder-approved alert/manual-case side effects.
9. Run Gate E/F.
10. Reconcile D1/R2 and all identities.
11. Record pass/fail per gate; do not average failures into an overall percentage.

An implementation can be:

- merged but not deployed;
- deployed but not accepted;
- technically accepted in fixtures but not live-accepted;
- live-accepted only after the founder records a pass.

## 10. Rollback

### Runtime

- Restore the recorded pre-deploy Worker version.
- Restore the recorded Pages deployment when presentation changed.
- Disable Item 7 read/activation flags if the approved rollout design includes
  them.
- Preserve additive nullable columns and append-only events; do not destructively
  roll them back.
- Confirm no new Item 7 event/alert/case processing continues after rollback.

### DNS

- Restore exact exported RRsets, not reconstructed approximations.
- Record provider rollback IDs and UTC times.
- Wait the pre-rollback TTL plus propagation margin.
- Query every authoritative nameserver.
- Capture public recursive corroboration.
- Trigger a post-rollback scan only after authoritative state is stable.
- Prove restored canonical snapshot/API/customer output.

### RUA/reporting

- Stop the founder-controlled generator.
- Restore/remove only the controlled authorisation RRsets.
- Preserve accepted ingest evidence and duplicate claims; do not delete history
  to make a rerun look clean.
- Confirm no report goes to an unrelated destination.

### Rollback triggers

Immediate rollback/hold if any occurs:

- scan orphan or finalisation-reserve breach;
- core exceeds 750 ms cap;
- unbounded/partial external host work;
- false healthy/missing/enforcement claim;
- arbitrary multiple-record selection;
- incorrect `t` mapping;
- `pct` applied;
- Item 5 authority expansion;
- duplicate alert;
- auto-created DMARC case;
- verification from note/RUA/incomplete scan;
- cross-tenant exposure;
- historical snapshot mutation/recomputation;
- any Hosted-DMARC/customer DNS mutation;
- unrelated customer side effect.

## 11. Acceptance record and closure

The final founder acceptance record must include:

- exact code/release and deployment identities;
- migration identity/result, if any;
- designated zone/generator/workspace identities;
- every pre-change, mutation, propagation, and rollback evidence bundle;
- production scan IDs;
- R2 report keys/hashes;
- canonical snapshot IDs/hashes;
- Email event/occurrence IDs;
- alert IDs;
- manual case IDs;
- Related Changes cluster IDs;
- API/UI/Executive/PDF parity captures;
- D1/R2 reconciliation result;
- mutation/regression result;
- rollback rehearsal result;
- residual limitations, especially incomplete external RUA coverage;
- explicit founder `PASS` or `FAIL`.

Item 7 remains open if any required gate is incomplete. Engineering completion,
merge, migration, or deployment cannot substitute for founder live acceptance.

## 12. Current hold statement

No acceptance action described here has started.

No code, generated code, dependency installation, migration, PR, deployment,
production scan, production mutation, DNS change, report injection, alert, case,
or rollback was performed while producing this guide.

PR #232 and founder governance documents were not touched. Hosted-DMARC
automation was not reactivated. Item 8 was not started.

STOP pending Claude review and explicit founder approval of the revised
three-document design.
