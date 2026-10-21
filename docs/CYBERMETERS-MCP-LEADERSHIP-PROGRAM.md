# CyberMeters MCP Leadership Program

**Program status:** ACTIVE — isolated synthetic staging OAuth and two-tenant reads passed a three-window bounded reliability check; an earlier intermittent failure remains unexplained. MCP-06 named-client and content checks and MCP-07 customer-release gates remain open.

**Founder direction:** 15 October 2026

**Source baseline:** `d1e4c4f8555735e3c3173d67866495de0741bceb` (`origin/main` when the worktree was created)

**Program branch:** `feat/mcp-leadership`

**Coordinator:** Codex Desktop — Integration & Release Engineer

**Executors:** Claude CLI (Platform & Data lane) and Codex CLI (Runtime lane)

This is a founder-directed, isolated engineering program. It does not lift the repository's current HOLD, change the canonical pre-beta backlog, or claim that MCP is customer-ready or accepted. An isolated, synthetic staging deployment exists; production customer MCP access remains disabled. The core product launch keeps its existing release gates and priority; MCP acceptance is not a prerequisite and MCP work must not delay it. The target is a customer-ready, read-only beta for the first pilot customers expected in roughly three to four weeks, subject to the remaining gates. As of 16 October 2026, focused MCP tests, typecheck, and relevant validators run locally; the full validation suite runs in GitHub CI after push. Failed CI checks are fixed and pushed again. Merging requires founder approval.

## 1. Mission

CyberMeters will provide a secure remote Model Context Protocol (MCP) interface that lets eligible customers use CyberMeters evidence with Anthropic Claude, OpenAI ChatGPT and Codex, and Google Gemini clients. The interface must serve both:

- a business with one domain, where the customer explicitly approves that workspace during OAuth consent and can then ask plain questions without repeatedly selecting it or learning CyberMeters' internal model; and
- an MSP or multi-tenant operator, where portfolio questions are explicit, every workspace boundary is enforced on the server, and the answer explains which tenants need attention and why.

MCP is a transport and tool contract, not the intelligence itself. CyberMeters' advantage must come from trustworthy evidence, eight-domain coverage, tenant-safe portfolio operations, remediation tracking, and useful explanations grounded in measured data. An AI Classifier and AI-generated summaries are separate product capabilities; connecting an MCP client does not create either one. The beta explanation tool uses measured CyberMeters evidence and versioned Field Guide guidance, with observation and advice kept distinct.

## 2. What “number one” means

The program succeeds only when the following are demonstrated with repeatable tests and evidence:

| Outcome | Acceptance measure |
| --- | --- |
| Tenant safety | Zero cross-workspace disclosure across the complete two-tenant negative test matrix. |
| Evidence honesty | Every security conclusion carries measurement time, evidence/coverage state, and material limits. Unsupported conclusions are represented as unavailable, incomplete, or not assessed. |
| Useful for one-domain customers | The default connection can answer the benchmark without asking the user to choose their only workspace repeatedly. |
| Useful for MSPs | In Release 1B, an entitled user can find critical items across its currently authorised workspaces with clear tenant attribution and bounded pagination. Release 1C adds ranked portfolio overview and comparison without mixing tenant evidence. |
| Auditable | Every successful tool call has a durable bounded audit record, and denials are durably recorded while the audit store is available. If an audit write fails, access does not succeed: the client receives a safe error and a content-free outage metric is emitted. No bearer token, arguments, response body, secret, or customer free text enters the audit record. |
| Interoperable | The pinned protocol version and tool contracts pass controlled Anthropic, OpenAI, and Google client checks for each supported surface before that surface is advertised to customers. |
| Predictable | Inputs, pagination, execution time, and result size are bounded; unknown tools and arbitrary paths, URLs, or SQL are rejected. |
| Actionable | Benchmark users can move from portfolio or posture question to the relevant CyberMeters page, finding, scan, or managed case without inventing evidence. |

The program will not compete by publishing the largest tool count. A small, well-scoped tool set that gives correct, traceable answers is a stronger product than dozens of overlapping or overpowered tools.

## 3. Product differentiation

1. **Evidence-grade answers.** Results preserve CyberMeters' authoritative/provisional/insufficient states, timestamps, verification state, and coverage limits. The AI client must not turn “not measured” into “secure.”
2. **One-domain simplicity.** Single-workspace customers get a direct security overview and plain-English explanation with no MSP vocabulary forced into their journey.
3. **MSP portfolio intelligence.** Explicitly entitled users can rank workspaces by measured risk, stale evidence, critical cases, and failed verification, then drill down without crossing tenant boundaries.
4. **Eight-domain consistency.** MCP uses the same canonical CyberMeters domains and scoring/evidence definitions as the web application: Email Protection, Brand Protection, Attack Surface, Certificates & Trust, Cyber Essentials Readiness, Website Security, Identity Exposure, and Shadow IT & Unmanaged Technology. It does not create a second product vocabulary.
5. **Remediation lifecycle.** CyberMeters connects findings to managed cases, verification, and related changes. The first release is read-only; later approved actions will extend the same lifecycle.
6. **Field Guide integration.** Tool responses can link to the relevant CyberMeters page and Field Guide topic. Guidance explains what a result means and what to check next; it does not claim the AI fixed the problem.
7. **Visible safety.** Customers can see which workspace, role, scope, and evidence time underlie an answer. Every access is revocable and auditable.

## 4. Non-negotiable product and security rules

- The server resolves access from authenticated identity, token scope, current membership, role, workspace state, and entitlement. A model-supplied workspace ID is never authority.
- No session-sticky “current workspace” exists in MCP. Every call is authorised independently. The one-domain shortcut is available only when the credential itself is bound to that workspace; it is never inferred merely because a user currently has one membership.
- The public MCP Worker has no D1, R2, Queue, probe, billing, or scan-execution binding.
- Business logic stays in the existing authoritative backend. The MCP layer performs protocol validation and minimal output projection; it is not a second data-access implementation.
- Stored website text, case text, report text, and finding text are untrusted data. They are never interpreted as tool instructions.
- No arbitrary URL fetch, arbitrary API proxy, free-form SQL, filesystem access, raw report export, or generic mutation tool is permitted.
- Tool results expose the minimum fields required for the customer task. Secrets, authentication material, owner identifiers, private notes, audit metadata, raw snapshots, and unnecessary PII are excluded.
- Domain posture comes from the canonical server-side security domain resolver, including its domain state and fixed limitation text. The state vocabulary is `assessed_healthy`, `issue_detected`, `provisional`, `degraded`, `unavailable`, `not_configured`, `customer_input_required`, `monitoring_only`, `not_yet_assessed`, and `evidence_insufficient`. A score-only projection is forbidden.
- Scan projections keep `assessment.quality`, `assessment.authoritative`, `assessment.provisional`, and `assessment.comparable` separate from lifecycle `status` and stored `scan_quality`. A completed scan is not described as authoritative unless the canonical assessment presentation says it is.
- MSP rankings use only proven-current Business Risk Score (BRS) values and return `brs_state` and `brs_state_reason`. `latest_incomplete`, `basis_unproven`, and `current_not_assessed` workspaces go into an explicit unranked/not-assessed group; they are never averaged or ranked as zero. Every portfolio aggregate carries `portfolio_score_state`, including `partial`.
- Feature/plan gates are explicit structured outcomes such as `plan_feature_required`; they are never flattened into “no data,” “no findings,” or a zero. Every count states its time window and scope.
- Read-only tools ship before write tools. A `readOnlyHint` is descriptive metadata, not an authorization control; the backend still enforces the boundary.
- Rate limiting is per credential and workspace, atomic, and fail-closed for the MCP admission path. Edge limits provide a second layer.
- Every credential is revocable. Customer beta credentials are expiring and audience/route constrained.
- Production claims, customer rollout, merge, and deployment remain gated by the operating model and release authority.

## 5. Target architecture

### 5.1 Remote MCP gateway

Create a separate Cloudflare Worker for `mcp.cybermeters.com` using the current Cloudflare Agents handler API (`createMcpHandler`) and Streamable HTTP. Pin the Agents SDK, MCP SDK, protocol version, and compatibility date that pass the repository's local test matrix.

The Worker has three jobs only:

1. validate the MCP transport, method, tool name, and strict JSON input schema;
2. call a fixed internal CyberMeters route through a Cloudflare service binding; and
3. return a bounded, documented MCP result with no direct storage access.

This isolates protocol parsing and MCP traffic from the existing Worker that owns sign-in, scans, queues, cron work, and customer data. It also provides independent rollback, rate limits, logs, metrics, and hostname policy.

### 5.2 Authoritative backend admission

The existing scan API remains authoritative. A small MCP admission boundary must:

- authenticate the credential;
- require the exact MCP read scope and allowed audience/route;
- require a current, non-deleted user and workspace membership;
- enforce role and entitlement;
- enforce single-workspace or explicitly granted portfolio scope;
- apply a per-token/workspace budget;
- generate a request ID and awaited audit event; and
- call an existing read service that independently repeats tenant and authorization checks.

The MCP Worker must not receive D1 credentials and must not trust a positive admission response as permission to skip route-level authorization.

### 5.3 Authentication stages

The current Microsoft sign-in flow authenticates users to the CyberMeters web application. It is not an MCP OAuth authorization server.

- **Internal engineering trial:** an expiring, explicitly workspace-bound, read-only CyberMeters credential may be used only in controlled local/dev tests. Unbound, non-expiring, write-scoped, or general API credentials are rejected.
- **Remote customer beta:** implement and verify authorization-code/PKCE, protected-resource metadata, bounded dynamic client registration, consent, refresh/revocation, audience, and client compatibility contracts for Anthropic, OpenAI, and Google clients. MCP access tokens have a distinct MCP audience and cannot be replayed against the wider API. Hosted Claude, ChatGPT, and Gemini connector tests require a reachable HTTPS test URL; localhost proves only local clients.
- **MSP access in the customer beta:** require separate `portfolio:read` consent and entitlement before any cross-workspace read. Consent records the customer's explicitly selected workspace IDs; there is no default all-workspaces grant. On every request, the server intersects that recorded selection with current membership, workspace state, and beta entitlement. Newly joined workspaces never enter an existing grant automatically, and a token's workspace argument cannot widen it. Dedicated portfolio ranking tools can follow as Release 1C, but an entitled MSP must already be able to ask for critical findings and a bounded summary across the selected workspaces through the Release 1B contract.

OAuth architecture is a focused R1 decision. It requires its own threat model, negative-path tests, and independent targeted review before remote customer use.

### 5.4 Client compatibility and eligibility

One remote MCP endpoint and customer authorization flow serve the three ecosystems. Compatibility is verified per product surface because local CLIs and hosted applications have different network, OAuth, account, admin, and regional requirements.

| Ecosystem | Local development proof | Hosted customer proof and limit |
| --- | --- | --- |
| Anthropic | Claude Code connects to the local Streamable HTTP endpoint and completes OAuth discovery, consent, tool discovery, and a tenant-safe read. | Claude.ai and Claude Desktop custom connector tests use staging HTTPS; Team/Enterprise setup may require an administrator. |
| OpenAI | Codex CLI connects locally with its MCP OAuth login and performs the same safe read. | ChatGPT web custom MCP setup uses staging HTTPS and an eligible plan/developer-mode or workspace-admin path. A local Codex configuration does not establish ChatGPT web access. |
| Google | Gemini CLI connects locally using Streamable HTTP, OAuth discovery, dynamic client registration, and a tenant-safe read. | Gemini app custom connectors are currently restricted by Google to eligible US personal accounts with its stated activity, age, and language conditions; Gemini Enterprise has a separate confidential-client setup. An unsupported account or region is a client eligibility limit, not an MCP server pass. |

The beta may advertise only surfaces with completed hands-on staging evidence. A successful protocol simulator does not establish end-user compatibility.

**Customer setup after the beta gate:** The planned customer URL is `https://mcp.cybermeters.com/mcp`; the controlled test URL is `https://mcp-staging.cybermeters.com/mcp`. Neither URL is a claim that a route is live today. A customer adds the approved URL in the client's remote MCP/custom connector settings, signs in through CyberMeters OAuth, reviews the named client and workspace, then enables the connector. CyberMeters accepts only the granted read scope and the currently authorised workspace; the customer can remove the connection in account settings.

- **Claude:** In Claude.ai or Claude Desktop, use *Customize → Connectors → Add custom connector*, enter the MCP URL, choose the detected OAuth method (Claude's published identity/CIMD, automatic registration, or a preconfigured client), and sign in. Claude's hosted service calls the public HTTPS endpoint. Free accounts currently allow one custom connector; Team/Enterprise administration may control connector setup. [Anthropic setup](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp), [availability](https://support.claude.com/en/articles/11176164-use-connectors-to-extend-claude-s-capabilities).
- **OpenAI:** Codex CLI/Desktop and ChatGPT web are separate client checks. An eligible ChatGPT administrator or authorised developer creates a *private custom MCP app*, enters the URL, completes OAuth, scans tools, and enables the draft for the permitted users. Public plugin-directory submission is a later, separate distribution process. OpenAI's OIDC UserInfo `email` and `email_verified` contract enables Enterprise workspace domain restrictions; its documentation does not make that contract a prerequisite for a private custom MCP connection. This beta must not claim Enterprise domain restriction support without it. [Private app setup](https://help.openai.com/en/articles/12584461-developer-mode-and-full-mcp-connectors-in-chatgpt), [OAuth requirements](https://developers.openai.com/plugins/build/auth), [public submission distinction](https://developers.openai.com/plugins/deploy/app-review).
- **Google:** Gemini CLI can run the local OAuth/DCR proof. The consumer Gemini app accepts custom MCP URLs only for Google's currently eligible US, adult, personal accounts with Keep Activity enabled and English availability; a UK or work/school account cannot be counted as a consumer-hosted pass. Gemini Enterprise uses a separate administrator-created Streamable HTTP connector with a pre-registered OAuth client ID and secret. [Gemini app eligibility](https://support.google.com/gemini/answer/17209137), [Gemini Enterprise setup](https://support.google.com/g/answer/17106276).

**Gemini Enterprise operator setup, after the staging gate:** Obtain the administrator's exact Google redirect URI (`https://vertexaisearch.cloud.google.com/oauth-redirect`) and create a confidential `client_secret_basic` OAuth client with that sole redirect URI through a restricted operator path using Cloudflare `OAuthHelpers.createClient()`. This is a pre-registered client in the authorization server's KV namespace, not an open registration endpoint. Deliver the generated client ID and one-time secret directly to that administrator through the approved secret channel; never put either in the repository, logs, or a ticket. In Gemini Enterprise, create a *Custom MCP Server* data store with Streamable HTTP URL `https://mcp-staging.cybermeters.com/mcp`, authorization URL `https://api-staging.cybermeters.com/authorize`, token URL `https://api-staging.cybermeters.com/oauth/token`, scope `mcp:read`, PKCE enabled, and the provisioned client ID/secret. Include the exact staging MCP resource as the authorization `resource` parameter using Google's Authorization URL Parameters field. Google must allow outbound FQDNs for both MCP and API hosts. After *Verify Auth*, enable only the currently reviewed read actions and perform a tenant-safe staging call. Repeat provisioning with production URLs only after the release decision; staging client credentials must not be accepted as production proof. The current implementation has no restricted operator provisioning command, so Gemini Enterprise integration remains blocked until that command and its local tests exist. [Google setup and redirect](https://docs.cloud.google.com/gemini/enterprise/docs/connectors/custom-mcp-server/set-up-custom-mcp-server), [Cloudflare pre-registration API](https://github.com/cloudflare/workers-oauth-provider/blob/main/docs/authorization-server.md#pre-registered-clients).

No hosted Claude, ChatGPT, or Gemini account has yet completed a hands-on CyberMeters staging connection; the local protocol and Worker tests provide engineering evidence only.

## 6. Capability releases

### Release 1A — internal engineering slice, read-only, one workspace

This is the first implementation target, not the complete customer beta. It proves transport, projection, admission, audit, limits, and tenant safety without write access.

| Tool | Customer job | Initial source contract | Output boundary |
| --- | --- | --- | --- |
| `cybermeters_list_workspaces` | Establish the permitted context. | `GET /api/workspaces` | Workspace ID, display name, current role. The initial credential yields exactly one bound workspace. |
| `cybermeters_get_workspace_summary` | Answer “How are we doing?” | `GET /api/workspaces/:id/summary` | Bounded counts, score state, latest measurement time, coverage state. |
| `cybermeters_get_workspace_posture` | Show the eight-domain posture. | `GET /api/workspaces/:id/security-domains` | All eight canonical domains from the server resolver, stable state, evidence strength, measurement time, fixed limitations, and internal UI link. The scorecard may be supplementary KPI input but is not the domain-state source. |
| `cybermeters_list_recent_scans` | Show recent measurement activity. | `GET /api/scans?workspace_id=:id` | Fixed small page; scan ID, domain, lifecycle status, `assessment.quality`, `authoritative`, `provisional`, `comparable`, measurement time, and score availability. No report body. |
| `cybermeters_get_scan_status` | Explain whether a scan is usable. | `GET /api/scans/:id` | Lifecycle status and the separate canonical assessment quality/authority/comparability fields, score availability, measurement time, and relevant UI link. |
| `cybermeters_list_managed_cases` | Show remediation work. | `GET /api/workspaces/:id/cases` | Fixed small page; case ID, canonical domain, phase, severity, verification support, and dates. No owner ID, notes, or free text in 1A. |

Every mapping is provisional until the route-purity and projection tests prove that a GET has no state mutation and the response contains no excluded fields.

### Release 1B — first read-only customer beta

The first customer beta must cover the ten founder-selected customer jobs below for both a single-domain business and an entitled MSP. Release 1A's six tools are an internal implementation slice; its completion alone cannot justify customer access. A job may need more than one narrowly scoped MCP tool, but every job must work end to end before its capability is advertised. Each read uses the current credential, role, scope, entitlement, workspace state, and route-level tenant check; every successful call requires an awaited audit record. Missing canonical backend projections block the affected tool rather than inviting raw report access or invented results.

| Customer job | Proposed MCP contract and beta boundary |
| --- | --- |
| 1. List workspaces | `cybermeters_list_workspaces`; show only currently authorised workspaces. A workspace-bound single-domain credential yields its one workspace; an entitled MSP gets a bounded, paginated current set. |
| 2. List domains | `cybermeters_list_domains`; bounded list of verified/managed domains in one authorised workspace, with relevant state and measurement time. |
| 3. Get security posture summary | `cybermeters_get_workspace_summary` and `cybermeters_get_workspace_posture`; preserve all eight canonical domain states, coverage, freshness, and limitations. |
| 4. Get critical findings | `cybermeters_list_findings`; severity-filtered and bounded, with source evidence state and no private notes or raw payloads. An entitled MSP can request a bounded, paginated view across its server-derived authorised workspace set; every item carries its workspace ID, and a partial page is never presented as the whole portfolio. |
| 5. Explain a finding's evidence and remedy | `cybermeters_explain_finding`; authorise the finding's workspace, then separate observation, evidence, limitation, Field Guide guidance, and next step. |
| 6. Get certificate and TLS status | `cybermeters_get_tls_posture`; expose expiry and measured TLS/certificate state only where canonical evidence exists. |
| 7. Get email security status | `cybermeters_get_email_posture`; expose measured DMARC/SPF and related email state with coverage and freshness. |
| 8. Get scan status and recent results | `cybermeters_get_scan_status` and `cybermeters_list_recent_scans`; distinguish lifecycle status from authoritative assessment quality. |
| 9. List open managed cases | `cybermeters_list_managed_cases`; bounded open-case view with canonical status and verification support. |
| 10. Get executive report summary | `cybermeters_get_report_summary`; return an authorised, bounded summary of an existing report, not a raw export or a new report-generation action. |

All ten jobs remain read-only. DNS changes, domain deletion, user invitations, automatic policy changes, scan requests, case creation, and report generation have no beta tool. Customer-facing access also requires the separate OAuth, client compatibility, consent, revocation, tenant-isolation, audit, rate-limit, privacy, and rollback gates below. A tool's `readOnlyHint` cannot substitute for backend enforcement.

### Release 1C — private MSP portfolio expansion

Only explicitly entitled portfolio users receive these additional aggregate and ranking tools:

| Tool | Customer job | Required boundary |
| --- | --- | --- |
| `cybermeters_get_portfolio_overview` | Summarise tenant posture and evidence freshness. | Server-derived accessible workspace set; bounded aggregates with `portfolio_score_state`; unassessed workspaces remain a separate count; no tenant blending. |
| `cybermeters_list_at_risk_workspaces` | Rank the tenants needing attention. | Proven-current BRS only, with `brs_state`, `brs_state_reason`, transparent ranking factors and timestamps; no hidden AI score and no zero substitution. |
| `cybermeters_compare_workspaces` | Compare a small selected set. | Maximum selection size; each workspace independently authorised; same evidence window shown. |

The one-domain journey remains the default. Portfolio language and tools appear only when the account actually has multiple accessible workspaces and the required entitlement.

### Release 2 — further evidence-grounded investigation

Additional investigation depth is considered only after the ten Release 1B customer jobs work through canonical minimal backend projections and independent review. Explanations must be produced from a versioned CyberMeters guidance contract and measured fields. They must separate observation, interpretation, limitation, and next step. Free-form model output is never stored as authoritative evidence.

### Release 3 — bounded actions

No write tool enters the program until the read-only beta passes its security and usefulness gates. The first possible actions are narrowly typed operations such as requesting an already-authorised scan, creating a managed case from an existing finding, or producing an existing report format. Each action requires explicit user confirmation in the client, idempotency, current authorization, audit, rollback/retry semantics, and a dry-run or preview where applicable.

The following remain excluded until a separate founder-approved program: DNS changes, certificate changes, user invitations, role or workspace administration, billing, API-token management, evidence deletion, case deletion, arbitrary notification, and bulk remediation.

## 7. Threat model and required controls

| Threat | Required control and proof |
| --- | --- |
| Cross-tenant access | Two-tenant matrix covering foreign workspace/domain/scan/case IDs, removed member, role downgrade, soft-deleted workspace, and nonexistent IDs. Foreign and nonexistent objects must not provide an enumeration oracle. |
| Token theft or replay | Expiry, revocation, MCP audience, route restriction, PKCE for OAuth clients, no token in URL/log/audit, and documented key rotation. |
| Confused deputy | Server-derived workspace set, fixed tool-to-route map, route-level authorization repeated, no arbitrary proxy parameters. |
| Prompt injection in customer evidence | Minimal structured fields; untrusted text labelled as data; no instruction execution; no URL following; injection fixtures in every tool that can return text. |
| Data exfiltration | Field allowlists, output size caps, pagination limits, no raw reports or snapshots, no secrets/PII/private notes, redaction tests. |
| Resource exhaustion | Request, batch, depth, pagination, result, time, and concurrency bounds; atomic fail-closed admission budget; edge rate limit. |
| Stale authorization | Current membership, role, workspace status, token status, and entitlement checked on every call. |
| Missing audit | Awaited audit write before success; explicit safe failure policy; metrics for accepted, denied, failed, and timed-out calls. |
| SDK/protocol drift | Pinned versions, protocol negotiation tests, dependency review, and controlled client compatibility matrix. |

## 8. CLI execution model

The two CLIs work on disjoint file sets. Neither CLI merges, deploys, changes production data, or decides release status.

### Claude CLI — Platform & Data lane

Owns:

- the scan-api MCP admission and authorization boundary;
- reuse of current authentication, membership, RBAC, entitlement, rate-limit, audit, and redaction helpers;
- minimal backend response projections needed by the allowlisted tools;
- focused tenant/auth negative tests and any later reviewed OAuth data migration; and
- evidence-state wording and single-domain/MSP response contracts with the Field Guide vocabulary.

Initial proposed file boundary:

- `workers/scan-api/src/routes/mcp-authz.js`
- the smallest required dispatch change in `workers/scan-api/src/index.js`
- focused tests/validators named for MCP admission and tenant isolation
- a later, separately approved OAuth migration if required

### Codex CLI — Runtime lane

Owns:

- `workers/mcp-server/**`;
- Cloudflare Worker and service-binding configuration for the MCP gateway;
- MCP handler, strict schemas, fixed tool registry, projection boundary, response caps, metrics, and protocol errors;
- protocol/unit/contract tests and Wrangler dry-run; and
- a local compatibility harness that uses fixtures, never production customer data.

The MCP Worker receives no direct database or object-storage binding. Codex CLI does not edit Claude CLI's backend files.

### Codex Desktop — coordination and release integration

Owns:

- one canonical program and task ledger;
- bounded prompts, owned-file checks, and stop conditions for both CLIs;
- integration review of every diff and test result;
- the single CI/local-gate wiring change, if required;
- independent R1 review coordination; and
- branch, commit, pull-request, release-evidence, and rollback preparation.

Claude Desktop retains the Executive role defined by the repository operating model, including merge/deploy sequencing. The founder retains all authority described there.

## 9. Work packages and stop conditions

| ID | Owner | Deliverable | Stop condition |
| --- | --- | --- | --- |
| MCP-00 | Coordinator + both CLIs | Source inventory, trust boundaries, product journeys, and this program. | Baseline recorded; no code or production change. |
| MCP-01 | Claude CLI | Read-only, workspace-bound admission contract plus negative tests. | Local focused tests pass; no OAuth migration; no production credential. |
| MCP-02 | Codex CLI | Stateless MCP Worker skeleton with one fixture-backed tool and protocol tests. | No data bindings; local tests and dry-run pass; no public route/deploy. |
| MCP-03 | Coordinator | Join gateway to admission through local/dev service contract. | Two-tenant and denied-path matrix passes; audit and limit behavior proven. |
| MCP-04 | Both CLIs, disjoint files | Implement and verify the six Release 1A internal tools. | Tool schema snapshot, projection, mutation-free GET, privacy, and injection tests pass; no customer access. |
| MCP-04B | Both CLIs, disjoint files | Complete the ten Release 1B read-only customer jobs with canonical minimal backend projections, including the bounded MSP critical-findings view. | Every job has bounded outputs, route-level authorisation, mutation-free read proof, privacy/injection tests, and two-tenant isolation evidence. |
| MCP-04C | Platform/Data lane with independent review | Implement the selected clients' customer OAuth/PKCE, audience, consent, expiry, refresh, and revocation contracts. | Negative-path and compatibility tests pass; no general API credential can substitute for an MCP customer token. |
| MCP-05 | Independent reviewer | Focused R1 review of auth, tenant, audit, rate limit, and protocol boundaries. | All material findings resolved or explicitly block beta. |
| MCP-06 | Coordinator | Controlled Claude, OpenAI, and Gemini compatibility evidence and rollback package. | Local CLI matrix passes and each advertised hosted surface has a separate eligible staging proof; no production/customer rollout. |
| MCP-07 | Founder/Executive decision | Approve or reject a named, read-only customer beta; assess additional Release 1C MSP portfolio tools separately. | No merge/deploy without the applicable authority and existing release gates; core product launch stays independent. |

Each CLI task must include the exact baseline SHA, owned files, forbidden files, acceptance tests, dangerous negative path, required output, and explicit stop condition. If either CLI finds it needs the other lane's file, it stops and reports the dependency to the coordinator rather than editing across the boundary.

## 10. Local acceptance gates

### Focused gates for every change

- formatting/lint and type or syntax checks for touched code;
- pure MCP schema and serialization tests;
- strict unknown-tool, malformed JSON-RPC, oversized input, batch, depth, pagination, timeout, and result-size tests;
- missing, revoked, expired, unbound, wrong-audience, wrong-scope, and write-scope credential tests;
- removed user, viewer role, role downgrade, soft-deleted workspace, foreign tenant object, and entitlement-denial tests;
- route-purity test proving no state mutation for every read tool;
- prompt-injection and output-redaction fixtures;
- rate-store outage and audit-write outage behavior;
- no secret/PII/token in logs, metrics, audit metadata, or returned errors; and
- Worker bundle/dry-run with the exact configuration intended for review.

### Integration gates for the MCP pull request

- Before each push, run focused MCP tests, frontend typecheck, and relevant validators for touched surfaces, including auth, tenant isolation, route/entry-point inventory, and Worker contracts where applicable.
- Check owned files and generated artifacts, and run `git diff --check`.
- Push the reviewed branch and let GitHub CI run the full validation suite. Fix any red check, repeat the focused local checks, and push again until CI is green.
- Obtain the independent Claude security review through the pull request; close its findings before customer enablement.
- Do not merge without founder approval.

The focused local evidence and GitHub CI results are both part of the pull request handoff.

## 11. Beta benchmark

The compatibility harness must evaluate at least these questions with fixed fixtures and expected structured evidence:

### One-domain customer

1. “What is my current security posture?”
2. “Which areas were not fully assessed?”
3. “Has my TLS posture changed since the last usable scan?”
4. “Which open case should I handle first, and what measured evidence supports that?”
5. “Where in CyberMeters can I verify this answer and learn what it means?”

### MSP operator — Release 1B customer beta

1. “Across my authorised customers, which critical findings need attention today?”
2. “Which workspaces do those findings belong to, and when was each measured?”
3. “Which authorised workspaces have incomplete or stale evidence, and what can be concluded from that?”
4. “Show open managed cases for one selected tenant without exposing another tenant.”
5. “Explain a selected finding using its measured evidence and Field Guide guidance.”

### MSP operator — Release 1C portfolio expansion

1. “Which workspaces need attention first, and why?”
2. “Which rankings are based on stale or incomplete evidence?”
3. “Compare these three authorised workspaces using the same evidence window.”
4. “Explain why a workspace moved in the ranking and link to the relevant CyberMeters evidence.”

Each answer is scored for authorization, evidence correctness, limitation disclosure, tenant attribution, actionability, bounded size, and absence of unsupported claims. A fluent answer with incorrect or mixed evidence fails.

## 12. Observability and customer control

Required metrics include calls by tool and outcome, authorization denials by bounded reason, latency, timeouts, capped responses, rate-limit decisions, backend failures, protocol errors, and client/protocol version. Labels must be low-cardinality and contain no customer domain, workspace name, token, arguments, or result text.

Customers must be able to view and revoke MCP access, see the selected workspaces and scopes, see the last-use time, and understand the customer-facing statement: “Your AI assistant can read your CyberMeters data (beta, read-only).” It cannot verify or fix issues. The beta must document retention for MCP audit records and client-side data handling without making claims CyberMeters cannot verify.

## 13. Release and rollback gates

1. **Design gate:** program, tool allowlist, schemas, auth boundary, threat model, and ownership accepted.
2. **Local engineering gate:** Release 1A passes all focused and integration tests with fixture data.
3. **Customer capability and OAuth gate:** all ten Release 1B customer jobs, selected-client OAuth/PKCE, consent, refresh/revocation, and two-tenant negative paths pass. An MSP cohort also requires explicit selected-workspace `portfolio:read` consent, plus bounded portfolio summary and cross-workspace critical-findings proofs. The six-tool internal slice earns no customer-release credit by itself.
4. **R1 gate:** independent review of the completed customer capability and OAuth paths confirms tenant, auth, audit, limit, and output boundaries.
5. **Controlled compatibility gate:** Claude Code, Codex CLI, and Gemini CLI pass locally using the actual customer credential flow; each advertised hosted Claude, ChatGPT, or Gemini surface passes separately on staging HTTPS with an eligible account.
6. **Private customer beta gate:** explicit Founder/Executive release decision, named beta workspaces, reversible canary, monitoring, revocation, and rollback package. This gate does not enter the core product launch checklist.
7. **MSP portfolio expansion gate:** the additional Release 1C aggregate/ranking tools require separate approval after portfolio entitlement, consent, ranking, and cross-workspace isolation tests pass.
8. **General availability gate:** benchmark, reliability, support, privacy, documentation, and existing platform release gates pass.

Rollback disables the MCP route or hostname, revokes beta credentials, and leaves the scan API and customer web application functional. No migration may make the existing product dependent on MCP availability.

The staged enablement checklist, named canary controls, evidence requirements, and rollback steps are in the [MCP beta rollout runbook](MCP-BETA-ROLLOUT.md).

## 14. Phase 0 execution record

- A clean worktree was created from exact upstream branch baseline `d1e4c4f8555735e3c3173d67866495de0741bceb`.
- Codex CLI completed a read-only architecture and security inventory. It confirmed reusable workspace/RBAC/token, audit, rate-limit, scorecard, scan, and managed-case foundations, and identified that current Microsoft login is not an MCP authorization server.
- Claude CLI completed a separate read-only customer/MSP journey and product-contract review. Its corrections now require canonical eight-domain states and limitations, authoritative scan-assessment fields, proven-current BRS ranking, explicit unassessed buckets, non-sticky workspace authorisation, structured plan gates, and time windows on counts.
- Claude CLI implemented the pure fail-closed MCP-01A admission contract and validator. Coordinator review corrected the role vocabulary to `viewer`/`analyst`/`admin`/`owner` and required a proven zero-member workspace for legacy-owner fallback. The focused validator passes.
- Codex CLI implemented the MCP-02A stateless SDK v2 Worker skeleton, strict fixture-backed tool, protocol/projection tests, and fail-closed deployed entrypoint. The coordinator stopped an unbounded package-source investigation, completed the local validation, and added the repository's `sharp` 0.35.5 security override.
- MCP-02A local evidence: 10/10 Node tests pass; Wrangler 4.148.0 dry-run bundles with no bindings; pinned packages are `agents` 0.28.1, `@modelcontextprotocol/server` 2.3.1, and Zod 4.6.7; npm reports zero known vulnerabilities after the override.
- Cross-lane R1 review completed: Codex CLI reviewed MCP-01A and Claude CLI reviewed MCP-02A. The review closed strict expiry/deletion-state tests, evidence/coverage consistency, untrusted text labelling, backend deadline/abort, metric classification, explicit preview-URL disablement, and documentation accuracy. Both packages now pass for their local-only scope.
- No source code, database, GitHub setting, production service, customer workspace, or external MCP client was changed during discovery.
- MCP-03 joined the gateway to the scan API through a named private Worker service binding. The gateway has no data binding or enablement variable in its deployment config; the scan API's named entrypoint requires an exact trial token/workspace allowlist, current D1 token and membership facts, an atomic fail-closed budget, and an awaited audit before returning a deliberately unassessed summary.
- MCP-03 local proof: gateway 17/17 and backend 6/6 tests pass. A repeatable two-Worker workerd/D1 trial with two synthetic tenants proves own access, foreign and nonexistent denial, 30 successful reads, the 31st rate denial, and durable success/denial audit rows without bearer or caller-supplied workspace in denial metadata. Existing auth/tenant, entry-point inventory, route, OpenAPI, and both Worker dry-run gates pass. A separate targeted R1 review found no material P0/P1 issue in the changed MCP paths.
- MCP-03 is local engineering evidence only. The branch was pushed to GitHub after local gates passed, but no MCP hostname, enablement variable, OAuth audience, live score projection, customer credential, deploy, or PR has been enabled. Gateway rejections before RPC have no backend audit row; that boundary and customer-facing auth remain for later release work.
- MCP-04 added six bounded Release 1A read tools: the trial-bound workspace list, workspace summary, canonical eight-domain posture, recent scans, one scan's lifecycle and assessment state, and managed cases. The gateway sends only bearer and bounded IDs through the named private RPC; the backend uses fresh token, user, membership, and workspace facts for every call. Lists are capped at ten and disclose `has_more`; report reads are capped per object and request. No MCP read dispatches the public GET routes that may repair state.
- MCP-04 local evidence: admission 6/6, backend projection 6/6, gateway 26/26, and the two-Worker workerd/D1 two-tenant integration proof pass. The latter exercises all six tools, foreign and missing tenant denials, a shared 30-read budget with the 31st denied, and durable success/denial audit rows. Existing authorization properties, tenant isolation and coverage, route wiring, OpenAPI, static tenant-query audit, entry-point inventory, and both Worker dry-runs pass. The gateway's dry-run lists only the private service binding and no data binding.
- MCP-04 independent R1 review found and closed incomplete-page signalling, report budget bypasses in the Cyber Essentials path, an unused long-lived subscription method, and slow or oversized request-body cancellation paths. Targeted regressions now cover each boundary. Claude CLI was not authenticated for this package, so a coordinated backend executor owned that lane while Codex CLI owned the gateway lane; their work received cross-lane independent review.
- At the MCP-04 checkpoint, the implementation remained an internal six-tool trial with an exact token/workspace allowlist and no public route. The subsequent customer engineering work below is separate from that trial; the core product launch remains independent.
- At the MCP-04B/04C checkpoint, customer engineering had a separate twelve-tool, read-only gateway and private customer backend entrypoint, bounded canonical projections, live tenant and entitlement checks, OAuth authorization-code/PKCE with consent and revocation, pre-RPC denial audit, and a fail-closed edge abuse gate. Focused local tests and Worker dry-runs passed. The customer route remained disabled by default, and those results did not authorize staging or customer access.
- A data-free loopback workerd fixture passed the resource-server protected-resource metadata, `401` challenge, audience/expiry/PAT denial, MCP tool list, and safe read checks. With isolated temporary settings and a synthetic bearer, the installed Claude Code CLI reported *Connected* and sent `tools/list`; Gemini CLI reported *Connected* and sent `initialize`. Codex CLI accepted a temporary server URL in its configuration, but its status/handshake was not run because this version merged pre-existing user servers and the temporary overrides could not safely isolate them. These checks do not prove the actual OAuth consent flow or hosted Claude, ChatGPT, or Gemini integration.
- The MCP-04C local OAuth fixture proves authorization-code/PKCE, token refresh, two-tenant separation, a real issued-token backend read, revocation, and durable audit rollback/retry with a workerd D1/KV runtime. Token body/deadline and per-IP abuse bounds, the customer entry inventory, and route wiring pass. Independent MCP-05 R1 review found no remaining material P0/P1 in the reviewed OAuth, gateway, and customer-read paths.
- A separate local workerd chain fixture exercises DCR, authorization-code/PKCE, two real issued tokens, the gateway's customer handler, both named private service bindings, D1 tenant reads, cross-tenant denials, revocation, and durable audit with synthetic data. It uses test-only entrypoints and a local hostname shim, so it does not prove the deployed gateway configuration or any hosted client.
- A staging configuration generator requires distinct D1, OAuth KV, R2, and edge-rate resources, fixed staging hosts, staging-only private service targets, and disabled customer flags. Its 14-check local validator includes fake-resource dry-runs of both Workers and a scan-dispatch failure proof with no Queue binding. The dedicated resources and fixed staging hostnames were then checked against Cloudflare inventory, deployed, and verified live without production data.
- Further isolated client probes confirmed Codex CLI can complete local DCR/PKCE consent and discover twelve tools, but its data read failed because that disposable localhost fixture used a different resource audience from the canonical staging backend. Claude Code generated a valid authorization URL with PKCE under a temporary profile; its token exchange and read were not completed. Gemini CLI initialized the temporary MCP connection but did not complete OAuth or tool discovery. None of these partial probes is a customer compatibility pass. A safe Codex configuration-isolation probe is retained; the browser-opening exploratory runner was removed and its temporary server stopped.
- MCP-06 historical staging proof completed on 15 October 2026: the separate Pages app, API, and MCP gateway served HTTPS with staging-only bindings. Two `example.invalid` accounts in separate workspaces completed hosted DCR and PKCE consent, discovered twelve read-only tools, read only their own summaries, received cross-tenant `403`, and lost access after grant revocation (`401`). Durable read and denial audit rows were recorded. A later guarded run failed at its first `tools/list` response after two grants; the next run with a reusable synthetic DCR client passed. A stricter check then passed in three separate minute windows, with six new grants, repeated discovery and 30 audited own-workspace reads. The earlier intermittent failure remains unexplained; preserve status telemetry and rollback during a pilot. After the final check, both Workers were restored to disabled maintenance configurations, both beta rows were paused, and no active OAuth connection or session remained. A local macOS DNS lookup lag for the new app hostname required a temporary exact-host Cloudflare IP override in the test process; TLS validation remained active. These runs prove protocol, tenant behavior and bounded repeatability, not any named AI client or content-rich answer quality.
- MCP-06/07 remain open for real Claude Code/Claude.ai, Codex CLI/ChatGPT, and Gemini client OAuth/read/revoke checks; exact hosted callback registration; edge abuse controls; customer retention and third-party AI notice; content-rich benchmarks; operational rollback and monitoring; and the Founder/Executive beta decision. No production customer route or credential is enabled by this record.

## 15. Reference points

- Cloudflare Agents — MCP Handler API: <https://developers.cloudflare.com/agents/model-context-protocol/apis/handler-api/>
- Cloudflare Agents — securing MCP servers: <https://developers.cloudflare.com/agents/model-context-protocol/guides/securing-mcp-server/>
- Model Context Protocol specification: <https://modelcontextprotocol.io/specification/>
- Claude remote connector and OAuth requirements: <https://claude.com/docs/connectors/building/authentication>
- Codex MCP client setup: <https://learn.chatgpt.com/docs/extend/mcp?surface=cli>
- OpenAI custom MCP server developer guide: <https://developers.openai.com/plugins/build/app-quickstart>
- OpenAI ChatGPT MCP eligibility: <https://help.openai.com/en/articles/12584461-developer-mode-and-full-mcp-connectors-in-chatgpt>
- Gemini CLI MCP setup: <https://geminicli.com/docs/tools/mcp-server/>
- Gemini app custom connector eligibility: <https://support.google.com/gemini/answer/17209137>
- Gemini Enterprise custom MCP setup: <https://docs.cloud.google.com/gemini/enterprise/docs/connectors/custom-mcp-server/set-up-custom-mcp-server>
