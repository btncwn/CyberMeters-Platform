# CyberMeters MCP Leadership Program

**Program status:** ACTIVE — Phase 0 and MCP-01A through MCP-03 accepted locally; MCP-04 is next

**Founder direction:** 15 October 2026

**Source baseline:** `d1e4c4f8555735e3c3173d67866495de0741bceb` (`origin/main` when the worktree was created)

**Program branch:** `feat/mcp-leadership`

**Coordinator:** Codex Desktop — Integration & Release Engineer

**Executors:** Claude CLI (Platform & Data lane) and Codex CLI (Runtime lane)

This is a founder-directed, isolated engineering program. It does not lift the repository's current HOLD, change the canonical pre-beta backlog, or claim that MCP is deployed, customer-ready, or accepted. All required checks run locally before any push or pull request. GitHub Actions remains enabled as a secondary signal and is not manually rerun.

## 1. Mission

CyberMeters will provide a secure remote Model Context Protocol (MCP) interface that lets customers use CyberMeters evidence inside approved AI clients such as Claude and ChatGPT. The interface must serve both:

- a business with one domain, where the only workspace is selected automatically and the customer can ask plain questions without learning CyberMeters' internal model; and
- an MSP or multi-tenant operator, where portfolio questions are explicit, every workspace boundary is enforced on the server, and the answer explains which tenants need attention and why.

MCP is a transport and tool contract, not the intelligence itself. CyberMeters' advantage must come from trustworthy evidence, eight-domain coverage, tenant-safe portfolio operations, remediation tracking, and useful explanations grounded in measured data.

## 2. What “number one” means

The program succeeds only when the following are demonstrated with repeatable tests and evidence:

| Outcome | Acceptance measure |
| --- | --- |
| Tenant safety | Zero cross-workspace disclosure across the complete two-tenant negative test matrix. |
| Evidence honesty | Every security conclusion carries measurement time, evidence/coverage state, and material limits. Unsupported conclusions are represented as unavailable, incomplete, or not assessed. |
| Useful for one-domain customers | The default connection can answer the benchmark without asking the user to choose their only workspace repeatedly. |
| Useful for MSPs | An entitled portfolio user can identify at-risk workspaces, explain the ranking, and drill into one workspace without mixing tenant evidence. |
| Auditable | Every successful tool call has a durable bounded audit record, and denials are durably recorded while the audit store is available. If an audit write fails, access does not succeed: the client receives a safe error and a content-free outage metric is emitted. No bearer token, arguments, response body, secret, or customer free text enters the audit record. |
| Interoperable | The pinned protocol version and tool contracts pass controlled Claude and ChatGPT client checks before customer beta. |
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
- Domain posture comes from the canonical server-side Cyber MOT domain resolver, including its domain state and fixed limitation text. The state vocabulary is `assessed_healthy`, `issue_detected`, `provisional`, `degraded`, `unavailable`, `not_configured`, `customer_input_required`, `monitoring_only`, `not_yet_assessed`, and `evidence_insufficient`. A score-only projection is forbidden.
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
- **Remote customer beta:** implement and verify the authorization-code/PKCE, protected-resource metadata, consent, refresh/revocation, audience, and client compatibility contracts required by the selected Claude and ChatGPT clients. MCP access tokens have a distinct MCP audience and cannot be replayed against the wider API.
- **MSP portfolio beta:** add a separate `portfolio:read` consent and entitlement. The server derives the current accessible workspace set on every request; no token contains a permanent, trusted copy of tenant membership.

OAuth architecture is a focused R1 decision. It requires its own threat model, negative-path tests, and independent targeted review before remote customer use.

## 6. Capability releases

### Release 1A — internal, read-only, one workspace

This is the first implementation target. It proves transport, projection, admission, audit, limits, and tenant safety without write access.

| Tool | Customer job | Initial source contract | Output boundary |
| --- | --- | --- | --- |
| `cybermeters_list_workspaces` | Establish the permitted context. | `GET /api/workspaces` | Workspace ID, display name, current role. The initial credential yields exactly one bound workspace. |
| `cybermeters_get_workspace_summary` | Answer “How are we doing?” | `GET /api/workspaces/:id/summary` | Bounded counts, score state, latest measurement time, coverage state. |
| `cybermeters_get_workspace_posture` | Show the eight-domain posture. | `GET /api/workspaces/:id/cyber-mot-domains` | All eight canonical domains from the server resolver, stable state, evidence strength, measurement time, fixed limitations, and internal UI link. The scorecard may be supplementary KPI input but is not the domain-state source. |
| `cybermeters_list_recent_scans` | Show recent measurement activity. | `GET /api/scans?workspace_id=:id` | Fixed small page; scan ID, domain, lifecycle status, `assessment.quality`, `authoritative`, `provisional`, `comparable`, measurement time, and score availability. No report body. |
| `cybermeters_get_scan_status` | Explain whether a scan is usable. | `GET /api/scans/:id` | Lifecycle status and the separate canonical assessment quality/authority/comparability fields, score availability, measurement time, and relevant UI link. |
| `cybermeters_list_managed_cases` | Show remediation work. | `GET /api/workspaces/:id/cases` | Fixed small page; case ID, canonical domain, phase, severity, verification support, and dates. No owner ID, notes, or free text in 1A. |

Every mapping is provisional until the route-purity and projection tests prove that a GET has no state mutation and the response contains no excluded fields.

### Release 1B — private MSP portfolio beta

Only explicitly entitled portfolio users receive these tools:

| Tool | Customer job | Required boundary |
| --- | --- | --- |
| `cybermeters_get_portfolio_overview` | Summarise tenant posture and evidence freshness. | Server-derived accessible workspace set; bounded aggregates with `portfolio_score_state`; unassessed workspaces remain a separate count; no tenant blending. |
| `cybermeters_list_at_risk_workspaces` | Rank the tenants needing attention. | Proven-current BRS only, with `brs_state`, `brs_state_reason`, transparent ranking factors and timestamps; no hidden AI score and no zero substitution. |
| `cybermeters_compare_workspaces` | Compare a small selected set. | Maximum selection size; each workspace independently authorised; same evidence window shown. |

The one-domain journey remains the default. Portfolio language and tools appear only when the account actually has multiple accessible workspaces and the required entitlement.

### Release 2 — evidence-grounded investigation

Add the following only after a canonical minimal backend projection exists and is independently reviewed:

- `cybermeters_list_findings`
- `cybermeters_explain_finding`
- `cybermeters_get_tls_posture`
- `cybermeters_get_email_posture`
- `cybermeters_get_report_summary`

Explanations must be produced from a versioned CyberMeters guidance contract and measured fields. They must separate observation, interpretation, limitation, and next step. Free-form model output is never stored as authoritative evidence.

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
| MCP-04 | Both CLIs, disjoint files | Implement and verify the six Release 1A tools. | Tool schema snapshot, projection, mutation-free GET, privacy, and injection tests pass. |
| MCP-05 | Independent reviewer | Focused R1 review of auth, tenant, audit, rate limit, and protocol boundaries. | All material findings resolved or explicitly block beta. |
| MCP-06 | Coordinator | Controlled Claude/ChatGPT compatibility evidence and rollback package. | Both selected clients pass pinned matrix; no production/customer rollout. |
| MCP-07 | Founder/Executive decision | Approve or reject private beta and later OAuth/MSP release package. | No merge/deploy without the applicable authority and existing release gates. |

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

### Integration gates before any push or PR

- the repository's relevant auth, authorization-property, tenant-isolation, route/entry-point inventory, OpenAPI/contract, and Worker validation commands;
- the full local CI-equivalent suite required by `AGENTS.md` for the touched surfaces;
- an owned-file and generated-artifact check;
- clean `git diff --check` and clean worktree after commit; and
- one independent targeted R1 review after tests pass.

GitHub Actions may run after a push but is not accepted as a substitute for the local evidence package.

## 11. Beta benchmark

The compatibility harness must evaluate at least these questions with fixed fixtures and expected structured evidence:

### One-domain customer

1. “What is my current security posture?”
2. “Which areas were not fully assessed?”
3. “Has my TLS posture changed since the last usable scan?”
4. “Which open case should I handle first, and what measured evidence supports that?”
5. “Where in CyberMeters can I verify this answer and learn what it means?”

### MSP operator

1. “Which workspaces need attention today?”
2. “Which rankings are based on stale or incomplete evidence?”
3. “Compare these three authorised workspaces using the same evidence window.”
4. “Show critical managed cases for one selected tenant without exposing another tenant.”
5. “Explain why a workspace moved in the ranking and link to the relevant CyberMeters evidence.”

Each answer is scored for authorization, evidence correctness, limitation disclosure, tenant attribution, actionability, bounded size, and absence of unsupported claims. A fluent answer with incorrect or mixed evidence fails.

## 12. Observability and customer control

Required metrics include calls by tool and outcome, authorization denials by bounded reason, latency, timeouts, capped responses, rate-limit decisions, backend failures, protocol errors, and client/protocol version. Labels must be low-cardinality and contain no customer domain, workspace name, token, arguments, or result text.

Customers must be able to view and revoke MCP access, see the granted workspace and scopes, see the last-use time, and understand that connecting an AI client allows that client to read the approved CyberMeters fields. The beta must document retention for MCP audit records and client-side data handling without making claims CyberMeters cannot verify.

## 13. Release and rollback gates

1. **Design gate:** program, tool allowlist, schemas, auth boundary, threat model, and ownership accepted.
2. **Local engineering gate:** Release 1A passes all focused and integration tests with fixture data.
3. **R1 gate:** independent review confirms tenant, auth, audit, limit, and output boundaries.
4. **Controlled compatibility gate:** selected Claude and ChatGPT clients pass in a non-production environment.
5. **Private beta gate:** explicit Founder/Executive release decision, named beta workspaces, reversible canary, monitoring, revocation, and rollback package.
6. **MSP/OAuth gate:** separate approval after OAuth and portfolio consent tests pass.
7. **General availability gate:** benchmark, reliability, support, privacy, documentation, and existing platform release gates pass.

Rollback disables the MCP route or hostname, revokes beta credentials, and leaves the scan API and customer web application functional. No migration may make the existing product dependent on MCP availability.

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
- MCP-03 is local engineering evidence only. No MCP hostname, enablement variable, OAuth audience, live score projection, customer credential, deploy, push, or PR has been enabled. Gateway rejections before RPC have no backend audit row; that boundary and customer-facing auth remain for later release work.

## 15. Reference points

- Cloudflare Agents — MCP Handler API: <https://developers.cloudflare.com/agents/model-context-protocol/apis/handler-api/>
- Cloudflare Agents — securing MCP servers: <https://developers.cloudflare.com/agents/model-context-protocol/guides/securing-mcp-server/>
- Model Context Protocol specification: <https://modelcontextprotocol.io/specification/>
- OpenAI full MCP connectors and developer mode: <https://help.openai.com/en/articles/12584461-developer-mode-and-full-mcp-connectors-in-chatgpt>
