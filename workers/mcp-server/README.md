# CyberMeters MCP-02A local Worker

From this directory: `npm ci`, `npm test`, and `npm run dry-run`.

The deployed Worker entrypoint always returns `503 {"error":"mcp_not_configured"}`. The only working MCP handler requires an injected backend through `createLocalTestWorker`; it accepts only exact `POST /mcp` requests on `http://localhost` or `http://127.0.0.1` with matching Host and, when present, Origin. It rejects Cloudflare requests. It uses SDK v2 stateless JSON responses and rejects legacy `initialize` traffic. No session, storage, runtime, data, or service binding is configured. Metrics are a content-free callback seam, not durable audit. Customer-controlled display names and limitations are projected as explicitly labelled untrusted data, and backend calls have a bounded abortable deadline.

The owned boundary is `workers/mcp-server/**`. Fixture data lives only in `test/`. The backend interface is `getWorkspaceSummary({ workspaceId, signal })`; it has no production implementation or authentication contract yet.

**Not deployed / not customer-ready / no deployment authorised.** MCP-03 must define and test authenticated admission, current workspace authorization, rate limits, awaited audit, and the service contract before this entrypoint can be enabled.
