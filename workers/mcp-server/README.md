# CyberMeters read-only MCP server

The production customer endpoint is **https://mcp.cybermeters.com/mcp**.
It uses user OAuth consent through `https://api.cybermeters.com`, a private
backend binding, and 14 bounded read tools. It is not a scan or mutation API.

See [connection steps and current tool list](../../docs/MCP-SETUP.md),
[client acceptance and callback limits](../../docs/MCP-CLIENT-COMPATIBILITY.md),
and [rollout/rollback controls](../../docs/MCP-BETA-ROLLOUT.md).
Remove access at **https://app.cybermeters.com/account/mcp**.

## Customer gateway

`src/index.js` selects the customer gateway when `MCP_CUSTOMER_ENABLED` is
exactly `true`. The production configuration declares the custom hostname and
private `McpOAuthAuthorizationService`/`McpCustomerReadService` bindings. A
missing or disabled binding/flag closes the endpoint. OAuth metadata and
server-wide 401 discovery lead clients through sign-in and explicit workspace
consent. Portfolio reads require separate consent and the selected workspace set.
Current membership, revocation, plan eligibility, limits and audit are checked
by the backend on each read. No customer bearer is accepted from a URL or logged.

The tools expose stored evidence and its quality limits. They do not start scans,
edit DNS, mutate managed cases or send customer reports. Client retention is
outside CyberMeters control; revocation stops future reads, not prior copies.

## Local engineering paths

The older MCP-04 internal gateway remains a local-only engineering path, guarded
by `MCP_INTERNAL_ENABLED` and the six named `McpReadService` methods. Its trial
API token and six-tool catalogue are not customer connection instructions. The
injected `createLocalTestWorker` is a fixture, not a public endpoint.

Install locked dependencies before validating:

```sh
node scripts/install-governed-dependencies.js --root workers/scan-api
cd workers/mcp-server
npm ci --ignore-scripts
npm test
npm run dry-run
```

These commands test/build locally; they do not deploy. The joint runtime test
uses disposable local state and synthetic tenants. Public hosted OAuth tests
have separate explicit staging controls; do not use production credentials for
local fixtures. Never loosen an origin or callback allowlist to make a client
setup example appear to work.
