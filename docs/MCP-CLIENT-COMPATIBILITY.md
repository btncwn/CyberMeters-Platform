# Read-only MCP: client compatibility

**Updated:** 21 October 2026. **State:** production customer MCP is live at `https://mcp.cybermeters.com/mcp` (issuer `https://api.cybermeters.com`) and open to trial and paid customers since #720 (`MCP_CUSTOMER_ACCESS = "customers"`; see [rollout](MCP-BETA-ROLLOUT.md)). **Proven live against production:** the Claude.ai hosted connector, Claude Code and Codex CLI. Every other surface below is unproven: do not advertise it until a live connection, a real read, revocation and reconnect are recorded here.

For the current 14-tool catalogue, sign-in, client setup steps and revocation,
see [MCP setup](MCP-SETUP.md). Public OAuth discovery was rechecked on 21 October:
resource/issuer and S256 PKCE match production; unauthenticated tools/list is 401.
No additional named-client acceptance is claimed by that read-only check.

## Proven live

| Client | When | How it registers | Evidence |
| --- | --- | --- | --- |
| Claude.ai / Claude Desktop (hosted connector) | 20 Oct 2026, 02:17 | DCR with `token_endpoint_auth_method: client_secret_post`; callback `https://claude.ai/api/mcp/auth_callback`, an exact string in `MCP_OAUTH_DCR_ALLOWED_REDIRECT_URIS` | Connected and returned real workspace data after #718. The refusal log before that fix named exactly this method and callback host. Team/Enterprise organisation-owner setup is not yet tested. |
| Claude Code | 19 Oct 2026, 18:48 | DCR, loopback `http://localhost:<port>/callback`, `none` + PKCE S256 | The founder's live `cybermeters_get_tls_posture` call returned the workspace's TLS evidence. |
| Codex CLI | 19–20 Oct 2026 (founder-confirmed) | DCR, loopback callback, `none` + PKCE S256 | Founder confirmed a live connection and read; production logs show the Codex MCP client reading OAuth discovery. Its OAuth identity differs from ChatGPT web. |

## Not yet proven

| Client surface | Vendor capability and account condition | CyberMeters status |
| --- | --- | --- |
| ChatGPT web | A custom HTTPS `/mcp` server can be added as a private plugin; account and workspace policies apply. [OpenAI connection guide](https://developers.openai.com/plugins/deploy/connect-chatgpt) | **Live read/revoke/reconnect pending.** The exact official callback `https://chatgpt.com/connector_platform_oauth_redirect` is allow-listed since #794. Production DCR accepted that URI (201) and refused its trailing-slash variant (400) on 21 Oct; no grant or consent was issued. Registration admission does not prove a named-client connection. |
| Gemini CLI | Streamable HTTP MCP, OAuth discovery and DCR are supported. Local browser callback is `/oauth/callback` on a variable port. [Google Gemini CLI guide](https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md) | **Supported in principle; CLI test pending.** A Gemini API key can authenticate Gemini CLI to Google, but CyberMeters still requires its own user OAuth consent. |
| Gemini API Interactions | Google documents remote Streamable HTTP MCP with request `headers` for the server's bearer token. [Google Gemini API guide](https://ai.google.dev/gemini-api/docs/function-calling) | **Developer integration prototype only; no hosted API call accepted yet.** The founder's Gemini API key alone does not authorize CyberMeters. A user-delegated CyberMeters token and safe renewal/secret handling are required before customer guidance. |
| Gemini consumer web/mobile custom app | Google's current custom-app feature requires a US adult with a personal Google account, Keep Activity enabled and English. It is not currently a UK founder acceptance path. [Google Gemini Apps Help](https://support.google.com/gemini/answer/17209137?co=GENIE.Platform%3DAndroid&hl=en-GB) | **Region blocked for the UK founder; do not advertise UK Gemini web access.** Recheck Google's availability before any region-specific claim. |
| Gemini Enterprise | A custom MCP data store supports HTTPS Streamable HTTP and OAuth, but an administrator must provision a client ID and secret and enable PKCE. [Google Cloud setup](https://docs.cloud.google.com/gemini/enterprise/docs/connectors/custom-mcp-server/set-up-custom-mcp-server) | **Separate future integration.** CyberMeters uses guarded DCR, with CIMD disabled in production; it has no operator-provisioned confidential client for this flow. A Gemini API key does not grant Enterprise access. |

## OAuth identity and callbacks

Production advertises issuer `https://api.cybermeters.com` and resource `https://mcp.cybermeters.com/mcp` (staging uses the `-staging` hosts). The API requires S256 PKCE and the exact resource. CIMD is off in production (`MCP_OAUTH_CIMD_ENABLED = "false"`); clients register through DCR. A DCR registration is accepted when every redirect is either a bounded loopback callback (public client, `none`) or an exact string in `MCP_OAUTH_DCR_ALLOWED_REDIRECT_URIS`; only an allow-listed hosted callback may use `client_secret_post`. Missing `grant_types`, `response_types` and `token_endpoint_auth_method` take RFC 7591 defaults (`authorization_code`, `code`, `none`). Every refusal writes one PII-free log line `{"event":"mcp_dcr_rejected", rule, field, value, redirect_host}`; read it with a filtered `wrangler tail` before changing any list. [OpenAI OAuth requirements](https://developers.openai.com/plugins/build/auth) · [Claude OAuth requirements](https://claude.com/docs/connectors/building/authentication).

| Flow | Identity and redirect |
| --- | --- |
| Claude hosted (web/Desktop) | **Observed:** DCR with `client_secret_post` and redirect `https://claude.ai/api/mcp/auth_callback` (allow-listed, exact). |
| Claude Code | **Observed:** loopback DCR, `none` + PKCE. |
| Codex CLI | **Observed:** loopback DCR, `none` + PKCE. Its documented CIMD identity (`https://chatgpt.com/oauth/codex/client.json`) is unused while CIMD is off. |
| ChatGPT web | **Exact callback admitted; client acceptance pending.** `https://chatgpt.com/connector_platform_oauth_redirect` is allow-listed by #794 and production DCR admission was verified on 21 Oct. CIMD (`https://chatgpt.com/oauth/client.json`) remains disabled. Any different callback shown in the client UI needs separate exact review; no wildcard is accepted. [OpenAI](https://developers.openai.com/plugins/build/auth) |
| Gemini CLI | Variable-port `http://localhost:<port>/oauth/callback` (or its configured exact redirect). The documented automatic flow uses DCR; inspect its registration and issuer validation. [Google](https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md) |
| Gemini consumer / Enterprise / API | Consumer: record the callback from an eligible US account's DCR connection before any allowlist entry. Enterprise: pre-register `https://vertexaisearch.cloud.google.com/oauth-redirect` for a confidential client, then enable PKCE; no such client exists yet. API: no browser callback in the `headers` bearer-token path. [Consumer](https://support.google.com/gemini/answer/17209137?co=GENIE.Platform%3DAndroid&hl=en-GB) · [Enterprise](https://docs.cloud.google.com/gemini/enterprise/docs/connectors/custom-mcp-server/set-up-custom-mcp-server) · [API](https://ai.google.dev/gemini-api/docs/function-calling) |

**ChatGPT-specific acceptance check:** the current gateway protects the entire MCP server and returns protected-resource metadata plus an HTTP `401 WWW-Authenticate` challenge before tool discovery; this is a legitimate server-wide OAuth path, with no known tool-metadata blocker. Its tools declare read-only annotations but no explicit per-tool `securitySchemes`. OpenAI requires `securitySchemes` and `_meta["mcp/www_authenticate"]` when triggering **tool-level** sign-in, and says omitted tool schemes inherit the server default. Test the actual private-plugin connection, sign-in, one read and reauthorization after revocation before claiming ChatGPT web support. If that client flow reveals a tool-level requirement, the pinned MCP server package must first be checked for a way to serialize the scheme; simply adding a `securitySchemes` field to the current `registerTool` config would be ignored. [OpenAI OAuth guide](https://developers.openai.com/plugins/build/auth).

For every surface advertised to customers, record account/region eligibility, the exact client ID and callback observed, OAuth consent, a real read-only tool result, cross-tenant denial, revocation and reconnect. A protocol simulator result is not a named-client result.

Revoke a connection at [Account → MCP connections](https://app.cybermeters.com/account/mcp) using **Remove access**. The next fresh tool call must be refused or require reconnection; reconnect and complete a fresh read before recording client acceptance.
