# Connect an AI assistant to CyberMeters

Checked 21 October 2026 against production discovery and the customer tool catalogue.
The remote, read-only beta endpoint is **https://mcp.cybermeters.com/mcp**.
An eligible trial or paid workspace and current membership are required. Client
account, region and administrator restrictions still apply. See the
[client compatibility record](MCP-CLIENT-COMPATIBILITY.md) for measured client acceptance.

## Sign in and approve a connection

1. Add the remote URL in a compatible client's MCP connection settings. Choose
   OAuth/sign-in and automatic client registration (DCR), rather than a static
   bearer header or a published-identity/CIMD option.
2. Follow the browser sign-in to CyberMeters. Check that the authorization host is
   `api.cybermeters.com` and the consent page is on `app.cybermeters.com`.
3. Select an eligible workspace and review the read permission before approving.
   Portfolio reads need separate consent and an eligible plan; select the exact
   workspaces to share. New workspaces are never included automatically.
4. Ask the assistant to list your authorized workspaces, then summarize one.
   Unknown, incomplete and unassessed results remain explicit. A connection does
   not start scans, edit DNS, change cases, or independently verify or fix issues.

The server advertises issuer `https://api.cybermeters.com`, S256 PKCE,
`mcp:read`, and authorization-code/refresh-token grants. `portfolio:read` is
separate. The client handles tokens; do not paste access tokens or your account
password into a chat or a setup file. Discovery without authorization returns 401.

## Claude

In **Customize → Connectors → + Add → Add custom connector**, name it
CyberMeters and enter the remote URL above. Choose sign-in and **Register
automatically** if the client asks how to identify itself. Finish setup, select
**Connect**, sign in to CyberMeters, and approve the workspace read permission.
Enable the connector in the conversation. An organization owner may need to add
it first in **Organization settings → Connectors → Add → Custom → Web**.

The hosted Claude connector and Claude Code have recorded live reads; organization
owner provisioning is not separately accepted. For Claude Code:

```sh
claude mcp add --transport http cybermeters https://mcp.cybermeters.com/mcp
```

Open `/mcp` in Claude Code and authenticate the CyberMeters server. This uses the
client's browser callback; no manual token header is needed.

## ChatGPT

In ChatGPT web, open **Plugins → + → Add custom MCP server**, enter the remote
URL, choose **OAuth**, and use automatic registration/DCR if offered. Review the
connection permission and follow CyberMeters sign-in/consent. Install or enable
the resulting private plugin before asking it to read a workspace. Some account
surfaces still label connections **Apps**; access depends on workspace policy.

**Current production limitation:** ChatGPT web is not yet accepted. Its hosted
OAuth callback is not in the current exact allowlist, so registration can be
refused before sign-in. These are the client setup steps, not a claim that the
current server will complete the flow. If it is refused, contact support with
the client name and time; never send tokens or passwords. The operator must
inspect the actual refusal and review any exact callback change. This docs
update does not change authorization configuration. A successful Codex CLI
connection is not proof of ChatGPT web compatibility.

## Gemini CLI

Add the HTTP server (command syntax checked against the installed CLI):

```sh
gemini mcp add --scope user --transport http cybermeters https://mcp.cybermeters.com/mcp
```

Start Gemini CLI and use `/mcp auth cybermeters`, then complete CyberMeters
sign-in and workspace consent in the browser. `/mcp list` shows connection
status. OAuth discovery/DCR and a variable-port loopback callback are the
expected path. The CLI's own model login does not authorize CyberMeters data.
This is a documented configuration path; a complete production Gemini CLI
read/revoke/reconnect has not yet been recorded. It does not establish Gemini
web, mobile or API compatibility.

## Current read tools

| Tool | What it reads |
| --- | --- |
| `cybermeters_list_workspaces` | Authorized workspaces, in bounded pages |
| `cybermeters_get_workspace_summary` | Workspace summary and evidence quality |
| `cybermeters_get_workspace_posture` | Eight security-domain states and limits |
| `cybermeters_list_recent_scans` | Recent stored scan states |
| `cybermeters_get_scan_status` | One scan's lifecycle and assessment state |
| `cybermeters_list_managed_cases` | Managed case phases |
| `cybermeters_get_managed_case` | One authorized case |
| `cybermeters_list_domains` | Domains and evidence freshness |
| `cybermeters_list_findings` | High/critical findings; portfolio needs separate consent |
| `cybermeters_explain_finding` | Measured evidence, limitations and guidance |
| `cybermeters_get_tls_posture` | Certificate and TLS evidence |
| `cybermeters_get_email_posture` | DMARC, SPF and email evidence |
| `cybermeters_get_report_summary` | An existing report's summary |
| `cybermeters_get_portfolio_summary` | Only the portfolio workspaces selected at consent |

Scope and current membership are checked on every call. Tool visibility alone
does not authorize a portfolio read. Scan IDs, case IDs and finding IDs must come
from authorized results. Follow returned pagination cursors rather than assuming
the first page is complete.

## Remove access and reconnect

Open **https://app.cybermeters.com/account/mcp**, locate the connection, and
select **Remove access**. This stops future CyberMeters reads for that connection.
Also remove/disable the connection in the client. It cannot erase data already
received or retained by that client under its own terms. Reconnecting requires
a fresh CyberMeters sign-in and consent. Test the workspace list after reconnect;
never treat a cached answer as proof that a revoked connection still works.

## Sources and verification

- [ChatGPT custom MCP connection](https://developers.openai.com/api/docs/guides/custom-mcp-server)
- [Claude custom connector setup](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp)
- [Gemini CLI MCP/OAuth](https://geminicli.com/docs/tools/mcp-server/)
- Public discovery: `https://mcp.cybermeters.com/.well-known/oauth-protected-resource/mcp`
  and `https://api.cybermeters.com/.well-known/oauth-authorization-server`.
- Production route and callback configuration: `workers/{mcp-server,scan-api}/wrangler.toml`.
  Customer tool catalogue: `workers/mcp-server/src/customer-mcp.js`.

No sign-in, consent, revocation or customer data read was performed as part of
this documentation check. Protocol support and named-client acceptance remain
separate claims.
