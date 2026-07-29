# Scan Deadline Fallback Contract Inventory

## Audit identity

- Audited main SHA: `da8b1f3e259ecca88ada8c8e1ec124f146d637c1`
- Audit date: 29 July 2026
- Canonical path: the default (`SCAN_CAPACITY_MODE=legacy`) `runScanEngine(...)`
  path
- Normal audit budget: `SCAN_DEADLINE_MS=19000`
- Product behaviour changed by this audit: none
- Producer count: **26 reachable producer entry points**
- Logical result contexts: **16**

This is an evidence inventory, not implementation authority. It does not add,
remove, reorder or renumber any item in the frozen execution backlog.

## Executive result

| Verdict | Logical contexts |
| --- | ---: |
| `CRASH` | 1 |
| `FABRICATES` | 5 |
| `SAFE` | 1 |
| `UNVERIFIED` | 9 |
| **Total** | **16** |

Only DNS qualifies as `SAFE`. It has a committed, engine-bound proof on the
audited main through PR #348. Static review, shape compatibility and helper-only
fixtures were not used to upgrade any other result to `SAFE`.

The primary email result is the known `CRASH`. Its focused correction is in
progress elsewhere and is deliberately not duplicated here.

Three Phase 5 results share one hard-cap race. When that race expires, the CVE
and KEV zero-shaped fallbacks are consumed as assessed zeroes and the report
publishes an unqualified `Low` risk narrative, `excellent` report risk level and
score `100`. In the same path, the email-intelligence fallback becomes false
MTA-STS and TLS-RPT absence detail. SSL and headers independently manufacture
canonical-URL consistency scores and, for SSL, the statement `HTTPS unavailable`
from unassessed evidence.

## Frozen verdict and status vocabulary

The only verdicts used in this inventory are:

- `CRASH`
- `FABRICATES`
- `SAFE`
- `UNVERIFIED`

The only disposition statuses used are:

- `KNOWN — FOCUSED FIX IN PROGRESS`
- `NEW — REQUIRES SEPARATE AUTHORISATION`
- `UNVERIFIED — REQUIRES FAITHFUL TRACE`
- `SAFE — ENGINE-BOUND PROOF EXISTS`

## Method

### Source enumeration

The audit started from the exact SHA above and followed the default
`runScanEngine(...)` path from producer to terminal report, D1 persistence,
eight-domain state resolution and managed lifecycle evaluation.

The count is syntactic producer entry points, not merely distinct object shapes:

| Producer family | Entry points |
| --- | ---: |
| Explicit `markDeadlineDeferred(...)` call sites in `scan-engine.js` | 18 |
| Custom DMARCbis deadline/unavailable producer call sites | 8 |
| **Total** | **26** |

The 18 explicit call sites are:

1. CT subdomain fallback factory — `scan-engine.js:552`
2. DNS core launch/hard-cap fallback — `scan-engine.js:572`
3. SSL/HTTPS core launch/hard-cap fallback — `scan-engine.js:578`
4. headers core launch/hard-cap fallback — `scan-engine.js:579`
5. primary email core launch/hard-cap fallback — `scan-engine.js:580`
6. technology core launch/hard-cap fallback — `scan-engine.js:591`
7. WHOIS/RDAP core launch/hard-cap fallback — `scan-engine.js:592`
8. DNS brute-force core launch/hard-cap fallback — `scan-engine.js:593`
9. subdomain-takeover launch/hard-cap fallback — `scan-engine.js:677`
10. asset-exposure launch/hard-cap fallback — `scan-engine.js:717`
11. CVE Phase 5 launch-gate fallback — `scan-engine.js:904`
12. KEV Phase 5 launch-gate fallback — `scan-engine.js:905`
13. email-intelligence Phase 5 launch-gate fallback — `scan-engine.js:906`
14. CVE Phase 5 shared hard-cap fallback — `scan-engine.js:947`
15. KEV Phase 5 shared hard-cap fallback — `scan-engine.js:948`
16. email-intelligence Phase 5 shared hard-cap fallback — `scan-engine.js:949`
17. cloud-storage launch-gate fallback — `scan-engine.js:1187`
18. cloud-storage hard-cap fallback — `scan-engine.js:1194`

The eight custom DMARCbis entry points are:

1. DMARC core outer launch/hard-cap fallback — `scan-engine.js:582`
2. DMARC core rejected-run substitution — `scan-engine.js:639`
3. DMARC core inner deadline — `dmarcbis-production.js:365`
4. DMARC core inner provider error — `dmarcbis-production.js:368`
5. external-RUA initial gate refusal — `scan-engine.js:1046`
6. external-RUA prebuilt hard-cap/provider-timeout fallback —
   `scan-engine.js:1061`
7. external-RUA post-wrapper launch refusal — `scan-engine.js:1095`
8. external-RUA inner deadline/provider-error fallback —
   `dmarcbis-production.js:466`

Two internal module timeouts were inspected but are not counted as customer-
reachable producer entry points. CT discovery's internal 15-second fallback is
dominated by the engine's 12-second cap. DNS brute force's internal 6-second
fallback is dominated by the engine's 750 ms cap. Their late values are
discarded by `raceModuleDeadline(...)`.

The `not_applicable` return at `dmarcbis-production.js:435` is also excluded:
the canonical engine handles an empty RUA set before calling the external
phase, so this entry is not reachable from the audited path as a deadline or
unavailable result.

### Budget and reachability model

`scan-budget.js:109-141` defines a 24,000 ms ceiling, a 5,000 ms finalisation
reserve and a clamped executable budget of 19,000 ms. The per-module caps are:

| Context | Hard cap / phase budget |
| --- | ---: |
| DNS | 750 ms |
| DNS brute force | 750 ms |
| primary email | 750 ms |
| DMARC core | 750 ms outer cap |
| DMARC external RUA | 600 ms |
| technology detection | 500 ms |
| WHOIS/RDAP | 2,000 ms |
| headers | 1,200 ms |
| SSL/HTTPS | 9,000 ms |
| CT subdomains | 12,000 ms |
| subdomain takeover | 750 ms |
| asset exposure | 2,500 ms |
| Phase 5 CVE/KEV/email trio | 1,000 ms shared |
| cloud storage | 500 ms |

`runCappedModule(...)` at `scan-engine.js:433-460` produces the same supplied
fallback from either its pre-launch `canRun(...)` gate or its
`raceModuleDeadline(...)` hard cap. Later sequential phases also have explicit
launch gates. Every listed producer is therefore reachable under the normal
19,000 ms budget: the Phase 1 modules can hit their own hard caps; later phases
can hit either their launch gate or their hard cap after earlier elapsed time.

### Proof discipline

The following proof classes were used:

1. Existing committed engine-bound validators, where they drive the real
   `runScanEngine(...)` path.
2. Temporary, uncommitted, local scratch traces outside the repository:
   real engine, real schema plus migrations in an in-memory SQLite D1 adapter,
   R2 shim, fully mocked network, one intentionally stalled dependency, and
   `SCAN_DEADLINE_MS=19000`.
3. Static producer-to-consumer tracing and existing focused validators as
   supporting evidence only.

No scratch harness contacted production. Scratch files and temporary dependency
links were removed after execution. Because those harnesses were intentionally
not committed, their trace identifiers and full observed outputs are recorded
below. This limits independent replay and is why untraced contexts remain
`UNVERIFIED`.

## Exact fallback contracts

Except for DMARCbis, each `markDeadlineDeferred(base)` result is exactly the
listed base object with this common envelope appended:

```json
{
  "executed": false,
  "incomplete": true,
  "outcome": "deadline_exceeded",
  "reason": "scan_deadline_exhausted"
}
```

The spread order means the envelope overrides conflicting `executed`,
`incomplete`, `outcome` or `reason` keys in `base`.

| Context and producer path | Exact base shape before the common envelope | Canonical successful top-level contract expected by direct consumers |
| --- | --- | --- |
| DNS — one shared launch/hard-cap producer | `{resolves:null,resolves_any:null,resolution_assessed:null,resolution_observation_state:"not_assessed",incomplete_reason:"dns_not_executed",has_ipv6:null,has_mx:null,nameservers:[],a_records:[],aaaa_records:[],mx_records:[],source:"dns"}` | `resolves,resolves_any,resolution_assessed,[incomplete,incomplete_reason],has_ipv6,has_mx,nameservers,a_records,aaaa_records,mx_records,caa,dnssec,operational_resilience,cross_checks` (`dns-scan.js:190-233`) |
| SSL/HTTPS — one shared launch/hard-cap producer | `{http_redirect_chain:{original_url:null,final_url:null,redirect_count:0,http_redirect_validated:false,observation_state:"not_assessed",observation_reason:"deadline_deferred",observation_completeness:"not_assessed",hop_observations:[]},https_available:null,https_probe_executed:false,https_observation_state:"not_assessed",https_observation_reason:"deadline_deferred",https_observation_completeness:"not_assessed",https_origin_status:null,https_endpoint_observations:[],incomplete:true,incomplete_reason:"https_probe_not_executed",source:"tls_probe"}` | `https_available,https_probe_executed,https_observation_state,https_observation_reason,https_observation_completeness,https_origin_status,[incomplete,incomplete_reason],https_endpoint_observations,http_redirects_to_https,http_redirect_chain,www_fallback_used,cert_expiry_days,cert_age_days,cert_not_before,cert_not_after,cert_issuer,cert_subject,cert_san_count,cert_raw_san_count,cert_wildcard_san_count,cert_shared_san_count,cert_san_names,ct_sources,certificate_evidence` (`ssl-scan.js:352-455` and continuation) |
| headers — one shared launch/hard-cap producer | `{headers:{},source:"http_headers"}` | `accessible,[incomplete,incomplete_reason],headers_assessed,status_code,original_url,response_url,redirect_count,final_https,validation_uncertain,bot_protection_signals,raw_capture,checked_paths,present,missing,values,set_cookie_raw,header_strength` (`headers-scan.js:345-376`) |
| primary email — one shared launch/hard-cap producer | `{spf:{},dmarc:{},dkim:{},source:"email_security"}` | `spf,dmarc,dkim,spf_detail,dmarc_detail,dkim_detail,bimi_readiness,policy_journey,remediation_actions`, plus non-enumerable `dmarc_state,_bimi_record,spf_evidence_status,dkim_evidence_status` (`email-scan.js:182-232`) |
| CT subdomains — factory used by one shared launch/hard-cap producer | `{count:0,items:[],sensitive:[],source:"certificate_transparency_multi_source",sources:{crt_sh:{count:0,error:"module deadline exceeded"},certspotter:{count:0,error:"module deadline exceeded"}},wildcard_dns:false,wildcard_dns_addresses:[],wildcard_test_host:null,wildcard_warning:null}` | `count,items,sensitive,source,sources,wildcard_dns,wildcard_dns_addresses,wildcard_test_host,wildcard_warning,[incomplete,incomplete_reason],error` (`subdomains-scan.js:263-277`) |
| technology — one shared launch/hard-cap producer | `{technologies:[],info_findings:[],source:"technology_detection"}` | `final_url,status_code,server,x_powered_by,content_type,strict_transport_security,content_security_policy,x_frame_options,x_content_type_options,external_scripts,technologies,info_findings` (`tech-scan.js:120-133`) |
| WHOIS/RDAP — one shared launch/hard-cap producer | `{source:"rdap"}` | `domain,registrar,creation_date,updated_date,expiration_date,domain_age_days,days_until_expiry,name_servers,registration_status,risk_level,findings,recommendations,source` (`whois-scan.js:272-286`) |
| DNS brute force — one shared launch/hard-cap producer | `{checked:0,found:0,items:[],source:"dns_bruteforce"}` | `checked,found,items,source,error` (`subdomains-scan.js:378-384`) |
| takeover — one shared launch/hard-cap producer | `{checked:0,potential_risks:0,risks:[],cname_observations:[],source:"subdomain_cname_fingerprint"}` | `checked,potential_risks,risks,cname_observations,checked_hosts,lookup_failed_hosts,unconfirmed,source,error` (`takeover-scan.js:392-403`) |
| asset exposure — one shared launch/hard-cap producer | `{checked:0,reachable:0,assets:[],removal_observations:unavailableRemovalObservations(knownAssetHosts,"asset_exposure_deadline"),source:"http_probe"}` | `checked,reachable,assets,removal_observations,source,error,[incomplete,incomplete_reason,not_assessed_count,notice]` (`asset-intel.js:589-603`) |
| CVE — separate launch-gate and shared hard-cap producers | `{technologies_checked:[],results:{},total_cves:0,critical_count:0,high_count:0,source:"nvd_api"}` | `technologies_checked,lookup_statuses,results,total_cves,critical_count,high_count,source` (`vuln-intel.js:202-210`) |
| KEV — separate launch-gate and shared hard-cap producers | `{matches:[],checked:0,matched:0,source:"cisa_kev"}` | `matches,checked,matched,source,catalogue_source,catalogue_stale` (`vuln-intel.js:335-342`) |
| email intelligence — separate launch-gate and shared hard-cap producers | `{source:"email_intelligence"}` | `domain,spf,dkim,dmarc,mta_sts,tls_rpt,starttls,email_security_score,email_score_breakdown,rating,business_email_risk,strengths,findings,business_impacts` (`email-intel.js:582-604`) |
| cloud storage — separate launch-gate and hard-cap producers | `{total:0,checked:0,findings:[]}` | `checked,candidates,total,findings,assets,source,error` (`cloud-storage-scan.js:390-398`) |

### DMARC core custom shape

All four DMARC-core unavailable entry points return the exact
`unavailableDmarcbisCore(...)` object at
`dmarcbis-production.js:244-303`:

```text
schema="dmarc-policy.v2"
methodology_version=<DMARCBIS_METHODOLOGY_VERSION>
author_domain=<normalised domain or null>
submitted_domain=<input or "">
observed_at=<timestamp>
observation_state="unavailable"
record_validity="indeterminate"
raw_records=null
parsed_tags=null
lookup_path=[]
organisational_domain=null
organisational_domain_provenance="unresolved"
organisational_domain_completeness="unavailable"
policy_source_domain=null
policy_source_kind="unknown"
declared_policy=null
effective_requested_policy=null
effective_policy_tag=null
inheritance_reason="unknown"
domain_existence="unknown"
existence_completeness="unavailable"
p=null
sp=null
np=null
t=null
psd=null
legacy_pct={
  observed:false, raw:null, numeric:null,
  semantics:"rfc7489_legacy", applied_to_effective_policy:false
}
rua_destinations=null
ruf_destinations=null
policy_completeness="unavailable"
rua_authorisation_completeness="incomplete"
corroboration_state="unavailable"
monitoring_state="monitoring_degraded"
provider_state=<producer reason>
receiver_enforcement_observed=false
core_completeness="unavailable"
executed=true
incomplete=true
outcome="unavailable"
reason=<producer reason>
evidence_grade=<evidenceGradeForCore(null, observed_at)>
limits={
  maximum_core_ms:<DMARCBIS_CORE_BUDGET_MS>,
  maximum_primary_ms:<DMARCBIS_PRIMARY_BUDGET_MS>,
  maximum_corroboration_deadline_ms:<DMARCBIS_CORROBORATION_DEADLINE_MS>,
  maximum_logical_questions:10
}
```

The successful contract is the resolved policy object plus
`observed_at,rua_authorisation_completeness,external_rua_authorisation,
core_completeness,executed,outcome,evidence_grade,limits` and optional
`incomplete` (`dmarcbis-production.js:375-400`). The fallback's
`executed:true` is inconsistent with an outer launch refusal even though its
other state fields explicitly say unavailable.

### DMARC external-RUA custom shape

The four external-RUA producer entry points call
`budgetRefusedDmarcbisExternal(...)` or return its provider-timeout/error
projection. The exact result is the resolver's per-destination result with:

```text
rua_authorisation_completeness="not_applicable" or "incomplete"
assessment_reason=<not_applicable | core_dependency_unavailable |
  deadline_budget | outbound_accounting_incomplete | subrequest_budget |
  provider_timeout | provider_error>
evidence_grade=<external evidence grade>
```

For inner provider timeout/error, every returned destination whose
`authorization_status` begins `not_assessed` is rewritten to:

```text
authorization_status="unavailable"
authorization_record_state="unavailable"
lookup_completeness="incomplete"
```

The engine then adds the exact `launch_gate` block at
`scan-engine.js:1144-1159` and attaches the result to the DMARC core object.
The successful contract is the resolver result from
`resolveDmarcbisExternalRuaAuthorizations(...)`, graded by
`withExternalEvidenceGrades(...)`, with complete per-destination
authorisation observations.

## Common direct-consumer and guard map

The table below records the direct post-fallback consumers reached by the
engine. Context-specific consequences are recorded in the evidence sections.

| Consumer | Modules consumed | Guard behaviour |
| --- | --- | --- |
| `isEmailApplicable(...)` (`scan-engine.js:795`) | DNS | Reads DNS evidence; the caller does not check `executed`, `incomplete`, outcome, skipped or error first. |
| `computeScore(...)` (`scan-engine.js:802`) | DNS, SSL, headers, primary email, subdomains, takeover, exposure, technology and related derived inputs | Module-specific checks vary. There is no common pre-score guard for `executed:false`, `incomplete:true`, deadline outcome, skipped, unavailable or error. Optional/defaulted reads prevent many exceptions but can turn missing fields into zero/false/absent. |
| technology info-finding append (`scan-engine.js:805-813`) | technology | Checks the same module for existence, `!error` and an array. It does not check `executed`, `incomplete`, outcome or skipped. |
| merged discovery and exposure target construction (`scan-engine.js:656-667`) | CT subdomains, DNS brute force | Uses `items` directly; no completeness-state guard. |
| takeover and exposure inputs (`scan-engine.js:676-735`) | CT subdomains, brute force, takeover | Empty fallback arrays become empty downstream target/evidence sets. Exposure annotation is skipped when exposure says `incomplete`; upstream discovery incompleteness is not separately checked there. |
| Phase 5 input (`scan-engine.js:932-938`) | technology, primary email, DNS | Passes fallback objects to CVE, KEV and email intelligence; no common same-module completeness guard. |
| email compatibility enrichment (`scan-engine.js:990-997`) | primary email and email intelligence | The guard checks only email intelligence `!error`, `!skipped` and applicability. It does not recognise its `executed:false`, `incomplete:true` or deadline outcome; it then mutates primary email. It also does not guard primary-email completeness before remediation generation. |
| external-RUA gate and compatibility projection (`scan-engine.js:1004-1168`) | DMARC core and upstream accounting | Recognises non-array RUA, incomplete core and capacity/deadline conditions, but the custom core object says `executed:true` even on an outer launch refusal. |
| `runRiskModule(...)` (`scan-engine.js:1173`; `asset-intel.js:899-956`) | findings, CVE, KEV | Uses `matches || []` and count fields defaulted to zero. It does not check `executed`, `incomplete`, deadline outcome, skipped, error or unavailable before publishing a risk level and narrative. |
| `runRemediationModule(...)` (`scan-engine.js:1174-1178`) | findings, KEV, takeover | Receives zero/empty fallback arrays without a completeness guard. |
| cloud finding append (`scan-engine.js:1224`) | cloud storage | Iterates `findings || []`; no completeness-state guard, but no absence claim is made at this direct append. |
| canonical URL profile (`scan-engine.js:1238-1354`) | SSL, headers | Uses optional/defaulted reads, but tests `ssl.https_available === true`; all other states, including `null`, become “not available”. It never checks either consumed module's `executed`, `incomplete`, deadline outcome, skipped, error or unavailable state. |
| admin-surface and attack-surface completeness derivation (`scan-engine.js:1357-1361`) | exposure, takeover, discovery | Derived resolvers receive full modules. Guard quality varies; no wrapper-level same-module guard precedes the calls. |
| domain-security enrichment (`scan-engine.js:1371`) | DNS, headers | Receives fallback shapes directly. The call is protected only by a broad `try/catch`; its catch object itself contains absence-like values. |
| `buildScanQuality(...)` (`scan-engine.js:1389`) | all modules | Correctly recognises `incomplete:true`; every `markDeadlineDeferred` result makes the scan partial. It does not independently require `executed:false` or deadline outcome because `incomplete` is present. |
| monitoring and eight-domain state resolvers (`scan-engine.js:1395`, `1622-1638`) | all relevant modules | `cyber-mot-domains.js:170-184` recognises error, skipped and `incomplete:true`, and the global partial state. It does not separately inspect `executed:false` or deadline outcome; the envelope's incomplete flag is load-bearing. |
| vendor, third-party, SaaS, certificate and identity derivations (`scan-engine.js:1415` onward) | DNS, SSL, headers, email, technology, subdomains, brute force, takeover, exposure | These consume optional/defaulted result fields. Global scan quality is available to later canonical state presentation, but not every raw derived object has a same-module execution guard. |
| report, findings and remediation persistence (`scan-engine.js:1481` onward, `1641-1676`) | all | The raw report preserves fallback and derived objects. Findings/recommendations generated earlier are persisted without a second completeness filter. |
| managed cases and lifecycle (`scan-engine.js:1716-1724`, `1867-1875`) | findings, modules, scan quality | `moduleCompletionGate(...)` at `asm-cases.js:477-496` recognises the same module's `error`/`incomplete` and the global partial scan. This prevents verification progression where that canonical gate is used. |

## Summary matrix

| Logical context | Producer entry points | Normal-budget reachability | Proof | Verdict | Disposition | Backlog evidence ID |
| --- | ---: | --- | --- | --- | --- | --- |
| DNS | 1 | hard cap and launch gate | committed real-engine trace | `SAFE` | `SAFE — ENGINE-BOUND PROOF EXISTS` | — |
| SSL/HTTPS | 1 | hard cap and launch gate | isolated real-engine trace | `FABRICATES` | `NEW — REQUIRES SEPARATE AUTHORISATION` | `SDFCI-NP2-SSL-PROFILE` |
| headers | 1 | hard cap and launch gate | isolated real-engine trace | `FABRICATES` | `NEW — REQUIRES SEPARATE AUTHORISATION` | `SDFCI-NP2-HEADERS-PROFILE` |
| primary email | 1 | hard cap and launch gate | isolated real-engine trace | `CRASH` | `KNOWN — FOCUSED FIX IN PROGRESS` | `SDFCI-KP1-EMAIL-PRIMARY` |
| DMARC core | 4 | outer/inner cap, launch refusal, provider error | static + focused helper validator only | `UNVERIFIED` | `UNVERIFIED — REQUIRES FAITHFUL TRACE` | `SDFCI-U-DMARC-CORE` |
| CT subdomains | 1 | hard cap and launch gate | static + deadline validator only | `UNVERIFIED` | `UNVERIFIED — REQUIRES FAITHFUL TRACE` | `SDFCI-U-CT-SUBDOMAINS` |
| technology detection | 1 | hard cap and launch gate | static + deadline validator only | `UNVERIFIED` | `UNVERIFIED — REQUIRES FAITHFUL TRACE` | `SDFCI-U-TECHNOLOGY` |
| WHOIS/RDAP | 1 | hard cap and launch gate | static + deadline validator only | `UNVERIFIED` | `UNVERIFIED — REQUIRES FAITHFUL TRACE` | `SDFCI-U-WHOIS` |
| DNS brute force | 1 | hard cap and launch gate | static + deadline validator only | `UNVERIFIED` | `UNVERIFIED — REQUIRES FAITHFUL TRACE` | `SDFCI-U-DNS-BRUTEFORCE` |
| subdomain takeover | 1 | hard cap and launch gate | static + deadline validator only | `UNVERIFIED` | `UNVERIFIED — REQUIRES FAITHFUL TRACE` | `SDFCI-U-TAKEOVER` |
| asset exposure | 1 | hard cap and launch gate | static + focused evidence validators only | `UNVERIFIED` | `UNVERIFIED — REQUIRES FAITHFUL TRACE` | `SDFCI-U-ASSET-EXPOSURE` |
| CVE intelligence | 2 | shared hard cap and Phase 5 launch gate | real-engine shared-phase trace | `FABRICATES` | `NEW — REQUIRES SEPARATE AUTHORISATION` | `SDFCI-NP1-PHASE5-FALSE-HEALTH` |
| KEV intelligence | 2 | shared hard cap and Phase 5 launch gate | real-engine shared-phase trace | `FABRICATES` | `NEW — REQUIRES SEPARATE AUTHORISATION` | `SDFCI-NP1-PHASE5-FALSE-HEALTH` |
| email security intelligence | 2 | shared hard cap and Phase 5 launch gate | real-engine shared-phase trace | `FABRICATES` | `NEW — REQUIRES SEPARATE AUTHORISATION` | `SDFCI-NP1-PHASE5-FALSE-HEALTH` |
| DMARC external RUA | 4 | 600 ms outer/inner cap plus deadline/capacity/accounting gates | static + focused helper validator only | `UNVERIFIED` | `UNVERIFIED — REQUIRES FAITHFUL TRACE` | `SDFCI-U-DMARC-EXTERNAL-RUA` |
| cloud-storage discovery | 2 | hard cap and launch gate | static + deadline validator only | `UNVERIFIED` | `UNVERIFIED — REQUIRES FAITHFUL TRACE` | `SDFCI-U-CLOUD-STORAGE` |

## Evidence by fallback context

### 1. DNS

**Producer and trigger.** `scan-engine.js:572`; the one fallback is used for
both the Phase 1 launch gate and the 750 ms module race.

**Consumer/guard result.** The fallback supplies explicit tri-state
not-assessed fields. `computeScore(...)` does not turn `resolves:null` into a
non-resolution finding. `buildScanQuality(...)` recognises `incomplete:true`;
the eight-domain resolver remains non-healthy; and `moduleCompletionGate(...)`
blocks verification. Missing `caa`, `dnssec`, resilience and cross-check fields
remain a compatibility delta, but the faithful trace covered the terminal
customer and lifecycle outcomes.

**Proof.** `scripts/validate-dns-absence-as-evidence.js:215-334`, delivered on
main by PR #348. It runs real `runScanEngine(...)` with the normal 19,000 ms
budget, stalls DNS beyond its real 750 ms hard cap, keeps sibling email evidence
available, asserts a completed partial report, asserts no false DNS finding or
score penalty, asserts no healthy domain verdict, and asserts a seeded case
remains `awaiting_verification`.

**Verdict.** `SAFE`

**Disposition.** `SAFE — ENGINE-BOUND PROOF EXISTS`

**Residual uncertainty.** None material to this exact fallback contract on the
audited SHA. This does not certify unrelated DNS error paths.

### 2. SSL/HTTPS

**Producer and trigger.** `scan-engine.js:578`; one fallback for both the Phase
1 launch gate and 9,000 ms hard cap.

**Consumer/guard result.** Scoring correctly withholds the former false
`HTTPS Not Available` finding and lifecycle verification fails closed. However,
`buildCanonicalUrlProfile(...)` checks only `https_available === true`, does not
recognise any fallback state, deducts for “no HTTPS”, an invalid HTTP redirect,
low confidence and no canonical URL, and emits an absence statement.

**Proof.** Temporary trace `SDFT-SSL-2026-07-29`: real engine, normal 19,000 ms
budget, only the first HTTPS `HEAD` held beyond the real 9,000 ms cap, all other
dependencies mocked fast. Observed:

```json
{
  "scan_status": "completed",
  "scan_quality": "partial",
  "canonical_url": null,
  "canonical_confidence": "low",
  "canonical_consistency_score": 30,
  "profile_complete": false,
  "https_variant_note": "HTTPS unavailable",
  "seeded_case_after": "awaiting_verification"
}
```

The exact SSL fallback was present in the report, no false SSL finding was
created, sibling evidence survived, and the case did not progress. The
fabricated canonical-profile claim is nevertheless sufficient for this verdict.
`scripts/validate-https-observation-deadline-lifecycle.js` supplies additional
zero-budget and lifecycle evidence but is not the basis for `SAFE`.

**Verdict.** `FABRICATES`

**Disposition.** `NEW — REQUIRES SEPARATE AUTHORISATION`

**Backlog evidence ID.** `SDFCI-NP2-SSL-PROFILE`

**Residual risk.** The raw canonical-profile score and note are durable in the
report. This audit does not authorise an inline fix.

### 3. Headers

**Producer and trigger.** `scan-engine.js:579`; one fallback for both the Phase
1 launch gate and 1,200 ms hard cap.

**Consumer/guard result.** The fallback does not match the successful headers
schema: it nests `headers:{}` and omits every successful evidence field.
Optional/defaulted consumers avoid a direct throw and scan quality becomes
partial. `buildCanonicalUrlProfile(...)`, however, does not recognise that
headers were unexecuted and computes an evidence-like consistency score from
the omissions.

**Proof.** Temporary trace `SDFT-HEADERS-2026-07-29`: real engine, normal
19,000 ms budget, only the first HTTPS `GET` held beyond the real 1,200 ms cap,
SSL and all other dependencies mocked fast. The scan completed partial with no
header finding, while the persisted canonical profile contained
`canonical_consistency_score:70`, `canonical_url:null` and
`profile_complete:false`.

**Verdict.** `FABRICATES`

**Disposition.** `NEW — REQUIRES SEPARATE AUTHORISATION`

**Backlog evidence ID.** `SDFCI-NP2-HEADERS-PROFILE`

**Residual risk.** The derived profile looks measured even though the headers
contract was not assessed. No runtime correction is included here.

### 4. Primary email security

**Producer and trigger.** `scan-engine.js:580`; one fallback for the Phase 1
launch gate and 750 ms hard cap.

**Consumer/guard result.** The fallback omits the completed contract's
`spf_detail`, `dmarc_detail`, `dkim_detail`, `bimi_readiness`,
`policy_journey` and remediation data. The later guard at
`scan-engine.js:990` checks `email_security_intelligence`, not the primary email
module it later consumes. `buildEmailRemediationActions(...)` then dereferences
absent detail fields in `email-analysis.js:357-363`.

**Proof.** Temporary trace `SDFT-EMAIL-PRIMARY-2026-07-29`: real engine, normal
19,000 ms budget, all DKIM selector TXT queries held beyond the real 750 ms
primary-email cap, all unrelated dependencies mocked fast. Observed:

```json
{
  "db_status": "failed",
  "scan_quality": null,
  "report_status": "failed",
  "report_error": "Cannot read properties of undefined (reading 'raw')",
  "findings": []
}
```

**Verdict.** `CRASH`

**Disposition.** `KNOWN — FOCUSED FIX IN PROGRESS`

**Backlog evidence ID.** `SDFCI-KP1-EMAIL-PRIMARY`

**Historical honesty.** No historical production failed scan has been causally
attributed to this defect. The eight historical failed scans remain
`UNATTRIBUTED`.

**Residual risk.** The focused Email Deadline → Whole-Scan Failure P1 is in
progress elsewhere. This inventory neither modifies nor duplicates it.

### 5. DMARC core

**Producers and triggers.** Four entry points: outer launch/hard-cap fallback
(`scan-engine.js:582`), rejected-run substitution (`scan-engine.js:639`),
inner core deadline (`dmarcbis-production.js:365`) and inner provider error
(`dmarcbis-production.js:368`). The outer budget is 750 ms; the inner limits are
reported in the result.

**Consumer/guard result.** The custom object is explicitly unavailable,
indeterminate and incomplete, so the email compatibility and eight-domain
consumers have fail-closed state available. The external-RUA gate recognises a
non-array RUA set as a core dependency failure. The unresolved inconsistency is
`executed:true` on the outer launch-refused path. Consumers generally key on
completeness rather than execution, but not every report, baseline, posture and
compatibility consumer has an engine-bound trace for this result.

**Proof.** Static path analysis plus
`node scripts/validate-dmarcbis-p2.js` (`109/109`) as supporting evidence. The
validator proves focused DMARCbis contracts but does not faithfully drive each
actual outer and inner fallback through terminal `runScanEngine(...)` at
19,000 ms.

**Verdict.** `UNVERIFIED`

**Disposition.** `UNVERIFIED — REQUIRES FAITHFUL TRACE`

**Backlog evidence ID.** `SDFCI-U-DMARC-CORE`

**Residual uncertainty.** No one-at-a-time real-engine trace proves report
finalisation, customer projections and lifecycle non-progression for all four
entry points.

### 6. CT subdomain discovery

**Producer and trigger.** The factory at `scan-engine.js:552` is supplied to
one Phase 1 `runCappedModule(...)` call and is reached through the launch gate or
12,000 ms hard cap.

**Consumer/guard result.** The fallback honestly identifies both CT sources as
deadline-failed and marks itself incomplete. Merged host construction,
takeover, exposure, inventory and several derived surfaces nevertheless consume
`items:[]` without a same-module execution guard. Global scan quality and case
verification fail closed, but no faithful trace proves that all raw and derived
customer surfaces avoid a zero/absence claim while sibling evidence survives.

**Proof.** Static path analysis and the general
`scripts/validate-scan-deadline.js` (`95/95`) only.

**Verdict.** `UNVERIFIED`

**Disposition.** `UNVERIFIED — REQUIRES FAITHFUL TRACE`

**Backlog evidence ID.** `SDFCI-U-CT-SUBDOMAINS`

**Residual uncertainty.** The 12-second cap makes a dedicated trace relatively
expensive and it was not produced within this bounded inventory.

### 7. Technology detection

**Producer and trigger.** `scan-engine.js:591`; launch gate or 500 ms hard cap.

**Consumer/guard result.** The info-finding append checks the same module for
`!error` and an array but ignores execution/completeness; the empty fallback
therefore produces no information finding. CVE, KEV, vendor, third-party and
SaaS consumers also receive `technologies:[]`. Global scan quality is partial,
but no engine-bound trace proves those derived surfaces do not interpret this
as “none detected”.

**Proof.** Static path analysis and the general deadline validator only.

**Verdict.** `UNVERIFIED`

**Disposition.** `UNVERIFIED — REQUIRES FAITHFUL TRACE`

**Backlog evidence ID.** `SDFCI-U-TECHNOLOGY`

**Residual uncertainty.** Missing successful fields such as status, server,
headers and external scripts broaden the compatibility gap.

### 8. WHOIS/RDAP intelligence

**Producer and trigger.** `scan-engine.js:592`; launch gate or 2,000 ms hard
cap.

**Consumer/guard result.** The fallback has only `source:"rdap"` plus the common
deadline envelope; all successful identity, age, expiry, findings,
recommendations and risk fields are absent. Optional reads avoid an obvious
throw, and global scan quality becomes partial, but customer/report
interpretation of the omitted risk and registration fields lacks faithful
proof.

**Proof.** Static path analysis and the general deadline validator only.

**Verdict.** `UNVERIFIED`

**Disposition.** `UNVERIFIED — REQUIRES FAITHFUL TRACE`

**Backlog evidence ID.** `SDFCI-U-WHOIS`

**Residual uncertainty.** No isolated engine trace covered the raw module,
derived intelligence and terminal presentation.

### 9. DNS brute force

**Producer and trigger.** `scan-engine.js:593`; launch gate or 750 ms hard cap.

**Consumer/guard result.** The result marks itself incomplete but supplies
`checked:0`, `found:0` and `items:[]`. CT/brute merge, takeover, exposure,
inventory and certificate consumers receive the empty set without a local
execution guard. Global scan quality and canonical lifecycle gates fail closed.

**Proof.** Static path analysis and the general deadline validator only.

**Verdict.** `UNVERIFIED`

**Disposition.** `UNVERIFIED — REQUIRES FAITHFUL TRACE`

**Backlog evidence ID.** `SDFCI-U-DNS-BRUTEFORCE`

**Residual uncertainty.** No faithful trace proves every derived asset/count
surface distinguishes “not attempted” from “zero found”.

### 10. Subdomain takeover

**Producer and trigger.** `scan-engine.js:677`; launch gate or 750 ms hard cap.

**Consumer/guard result.** `potential_risks:0`, `risks:[]` and
`cname_observations:[]` are passed to exposure annotation, remediation,
certificate/cloud derivation, inventory and lifecycle code. The successful
contract's `checked_hosts`, `lookup_failed_hosts` and `unconfirmed` fields are
missing. Global scan quality and case verification recognise incompleteness,
but the zero result remains ambiguous on raw and derived customer surfaces.

**Proof.** Static path analysis and the general deadline validator only.

**Verdict.** `UNVERIFIED`

**Disposition.** `UNVERIFIED — REQUIRES FAITHFUL TRACE`

**Backlog evidence ID.** `SDFCI-U-TAKEOVER`

**Residual uncertainty.** A seeded takeover lifecycle trace and raw report/API
assertions are still required.

### 11. Asset exposure

**Producer and trigger.** `scan-engine.js:717`; launch gate or 2,500 ms hard
cap.

**Consumer/guard result.** The result retains explicitly unavailable removal
observations and skips annotation/deduplication because it is incomplete.
Admin-surface, attack-surface completeness, inventory, risk/remediation and
managed lifecycle consumers then receive zero counts and empty assets. The
canonical lifecycle gate should prevent verification, but the complete
customer-facing chain has no one-module real-engine trace.

**Proof.** Static path analysis plus supporting
`scripts/validate-probe-evidence-honesty.js` (`84/84`) and
`scripts/validate-app-probe-reliability.js` (`72/72`). Neither is a faithful,
isolated 19,000 ms trace of this engine fallback.

**Verdict.** `UNVERIFIED`

**Disposition.** `UNVERIFIED — REQUIRES FAITHFUL TRACE`

**Backlog evidence ID.** `SDFCI-U-ASSET-EXPOSURE`

**Residual uncertainty.** Terminal report, asset inventory and seeded
attack-surface lifecycle behaviour need a single faithful trace.

### 12. CVE intelligence

**Producers and triggers.** Launch-gate assignment at `scan-engine.js:904` and
shared Phase 5 hard-cap assignment at `scan-engine.js:947`; 1,000 ms shared
phase budget.

**Consumer/guard result.** `runRiskModule(...)` reads
`critical_count || 0`, `high_count || 0` and `total_cves` without checking
execution, incompleteness, deadline outcome, skipped, error or unavailable
state. Unassessed CVE evidence therefore participates as measured zero in the
published low-risk conclusion.

**Proof.** Temporary trace `SDFT-PHASE5-HEALTHY-2026-07-29`: real engine,
normal 19,000 ms budget, only the NVD request held beyond the real shared
1,000 ms cap, all other network dependencies mocked fast. The actual shared
fallback necessarily replaced all three Phase 5 results. The scan completed
`partial`; the CVE fallback was exact; and `risk_intelligence` published:

```json
{
  "overall_risk_level": "Low",
  "narrative": "No critical or high-severity issues detected. Continue security monitoring and address any low-severity findings in the next maintenance cycle.",
  "finding_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0}
}
```

The same report contained `cyber_metrics_score:100` and
`risk_level:"excellent"`.

**Verdict.** `FABRICATES`

**Disposition.** `NEW — REQUIRES SEPARATE AUTHORISATION`

**Backlog evidence ID.** `SDFCI-NP1-PHASE5-FALSE-HEALTH`

**Residual risk.** The shared race prevents isolating the three fallback
objects at runtime; direct consumer tracing distinguishes this CVE zero-count
path from the email compatibility path.

### 13. Known-exploited-vulnerability intelligence

**Producers and triggers.** Launch-gate assignment at `scan-engine.js:905` and
shared Phase 5 hard-cap assignment at `scan-engine.js:948`; 1,000 ms shared
phase budget.

**Consumer/guard result.** `runRiskModule(...)` reads `matches || []` without
checking fallback state; `runRemediationModule(...)` receives the same empty
array. An unassessed KEV catalogue match is therefore treated as no match in the
unqualified low-risk narrative and remediation roadmap.

**Proof.** The same faithful `SDFT-PHASE5-HEALTHY-2026-07-29` trace. The report
contained the exact KEV fallback:

```json
{
  "matches": [],
  "checked": 0,
  "matched": 0,
  "source": "cisa_kev",
  "executed": false,
  "incomplete": true,
  "outcome": "deadline_exceeded",
  "reason": "scan_deadline_exhausted"
}
```

It simultaneously published the unqualified `Low` narrative, `excellent`
report risk level and score `100`.

**Verdict.** `FABRICATES`

**Disposition.** `NEW — REQUIRES SEPARATE AUTHORISATION`

**Backlog evidence ID.** `SDFCI-NP1-PHASE5-FALSE-HEALTH`

**Residual risk.** As above, the shared race is the canonical trigger and all
three module fallbacks are necessarily produced together.

### 14. Email security intelligence

**Producers and triggers.** Launch-gate assignment at `scan-engine.js:906` and
shared Phase 5 hard-cap assignment at `scan-engine.js:949`; 1,000 ms shared
phase budget.

**Consumer/guard result.** The guard at `scan-engine.js:990` checks this module
only for `error` and `skipped`; it ignores `executed:false`,
`incomplete:true` and the deadline outcome. `buildEmailTransportDetails(...)`
then defaults absent MTA-STS/TLS-RPT input into negative details and mutates the
otherwise trustworthy primary-email module.

**Proof.** Temporary trace `SDFT-PHASE5-2026-07-29`: real engine, normal
19,000 ms budget, NVD held beyond the real shared cap, unrelated dependencies
mocked fast. The exact fallback became:

```json
{
  "source": "email_intelligence",
  "executed": false,
  "incomplete": true,
  "outcome": "deadline_exceeded",
  "reason": "scan_deadline_exhausted"
}
```

The completed partial report's primary email object was then mutated to include
`mta_sts_detail.policy_found:false`,
`tls_rpt_detail.record_found:false`, and a warning that an MTA-STS policy file
was not confirmed. No MTA-STS or TLS-RPT evidence had executed.

**Verdict.** `FABRICATES`

**Disposition.** `NEW — REQUIRES SEPARATE AUTHORISATION`

**Backlog evidence ID.** `SDFCI-NP1-PHASE5-FALSE-HEALTH`

**Residual risk.** The wrong-module primary-email guard is separately
responsible for the known primary-email crash; its correction is out of scope
here.

### 15. DMARC external RUA

**Producers and triggers.** Four entry points: initial dependency/deadline/
capacity/accounting refusal (`scan-engine.js:1046`), prebuilt outer hard-cap
fallback (`scan-engine.js:1061`), wrapper-level launch refusal
(`scan-engine.js:1095`) and inner provider timeout/error
(`dmarcbis-production.js:466`). The phase budget is 600 ms.

**Consumer/guard result.** The custom contract explicitly identifies
incompleteness and reason, preserves the already-observed core evidence, grades
external evidence and rewrites timed-out destination observations to
unavailable. The result is attached to the DMARC core and projected into email.
This is designed to retain trustworthy sibling core evidence, but no faithful
real-engine trace proved every refusal/timeout entry through report, domain
state, occurrence and case behaviour.

**Proof.** Static path analysis plus
`node scripts/validate-dmarcbis-p2.js` (`109/109`) only.

**Verdict.** `UNVERIFIED`

**Disposition.** `UNVERIFIED — REQUIRES FAITHFUL TRACE`

**Backlog evidence ID.** `SDFCI-U-DMARC-EXTERNAL-RUA`

**Residual uncertainty.** A real-engine trace needs a complete core record with
an external RUA destination, one fallback trigger at a time, and seeded
lifecycle state.

### 16. Cloud-storage discovery

**Producers and triggers.** Explicit sequential launch gate at
`scan-engine.js:1187` and `runCappedModule(...)` hard-cap fallback at
`scan-engine.js:1194`; 500 ms phase budget.

**Consumer/guard result.** The engine appends `findings || []`, persists the raw
module and feeds asset/inventory/report consumers. `buildScanQuality(...)`
recognises incompleteness, but the fallback omits successful `candidates`,
`assets`, `source` and `error` fields and supplies assessed-looking zero counts.
No faithful trace proves all customer surfaces distinguish unexecuted from
zero-found.

**Proof.** Static path analysis and the general deadline validator only.

**Verdict.** `UNVERIFIED`

**Disposition.** `UNVERIFIED — REQUIRES FAITHFUL TRACE`

**Backlog evidence ID.** `SDFCI-U-CLOUD-STORAGE`

**Residual uncertainty.** The launch-gate and hard-cap paths have identical
fallback shape but different telemetry; both require terminal engine proof.

## New evidence items

These identifiers are local evidence handles for separately authorised
follow-up. They do not alter the frozen execution backlog.

| Evidence ID | Provisional priority | Exact evidence | Authority |
| --- | --- | --- | --- |
| `SDFCI-NP1-PHASE5-FALSE-HEALTH` | P1 | A real normal-budget Phase 5 hard-cap trace completed partial while publishing unqualified `Low` risk, `excellent` report risk level, score `100`, and false MTA-STS/TLS-RPT absence detail from unassessed CVE, KEV and email-intelligence fallbacks. | `NEW — REQUIRES SEPARATE AUTHORISATION` |
| `SDFCI-NP2-SSL-PROFILE` | P2 | A real SSL hard-cap trace persisted canonical consistency score `30` and the statement `HTTPS unavailable` although HTTPS was explicitly not assessed. | `NEW — REQUIRES SEPARATE AUTHORISATION` |
| `SDFCI-NP2-HEADERS-PROFILE` | P2 | A real headers hard-cap trace persisted canonical consistency score `70` from an unexecuted, schema-incompatible fallback. | `NEW — REQUIRES SEPARATE AUTHORISATION` |

No new P0 was found. The primary-email P1 is pre-existing and already has a
focused correction in progress.

## Limitations and residual audit risk

1. A faithful actual-path proof is mandatory for `SAFE`; consequently nine
   contexts remain `UNVERIFIED` even where static design appears fail-closed.
2. The scratch traces are recorded as evidence here but were not committed, as
   required by the bounded docs-only scope.
3. The Phase 5 hard cap is intentionally one race for three modules; the runtime
   cannot emit only one of those three hard-cap fallbacks. Direct consumer
   mapping was used to distinguish their separate fabricated consequences.
4. This audit evaluates exact main code, not production. The merged HTTPS and
   redirect corrections were not deployed at audit time.
5. A completed partial scan can preserve trustworthy sibling evidence. That
   alone is not sufficient for `SAFE`; every customer claim and lifecycle
   consumer must also be proven.
6. This audit made no causal claim about historical production failures.

## Validation record

Focused supporting validators run from the exact audited SHA:

| Command | Result |
| --- | --- |
| `node scripts/validate-dns-absence-as-evidence.js` | `75/75`; `8/8` mutants killed |
| `node scripts/validate-https-observation-deadline-lifecycle.js` | `28/28`; `3/3` mutants killed |
| `node scripts/validate-scan-deadline.js` | `95/95` |
| `node scripts/validate-dmarcbis-p2.js` | `109/109` |
| `node scripts/validate-probe-evidence-honesty.js` | `84/84` |
| `node scripts/validate-app-probe-reliability.js` | `72/72` |

These validators did not modify committed files. The final docs-only branch
validation is recorded in the pull request.

## Scope confirmation

- Runtime code changed: no
- Runtime tests or validators changed: no
- CI/configuration/closure metadata changed: no
- Schema or migration changed/applied: no
- Production or historical data contacted or mutated: no
- Worker or Pages deployment: no
- Release tag: no
- `CHANGELOG.md`: unchanged
- Active Email P1 implementation files: untouched
- PR-B, CT-R1 P2, CT-R2/R3, Item 11, Item 14 and Item 19: not started
- PRs #341 and #346: untouched
