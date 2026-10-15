import { WorkerEntrypoint } from "cloudflare:workers";
import { getWorkspaceSummaryForMcp } from "./mcp-service.js";

// Only a Worker with an explicit binding to this named entrypoint can call it.
// The default public fetch handler does not dispatch MCP RPC methods.
export class McpReadService extends WorkerEntrypoint {
  async getWorkspaceSummary(input) {
    return getWorkspaceSummaryForMcp(this.env, input);
  }
}
