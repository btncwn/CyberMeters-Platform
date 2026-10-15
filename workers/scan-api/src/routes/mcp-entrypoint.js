import { WorkerEntrypoint } from "cloudflare:workers";
import {
  listWorkspacesForMcp, getWorkspaceSummaryForMcp,
  getWorkspacePostureForMcp, listRecentScansForMcp,
  getScanStatusForMcp, listManagedCasesForMcp,
} from "./mcp-service.js";

// Only a Worker with an explicit binding to this named entrypoint can call it.
// The default public fetch handler does not dispatch MCP RPC methods.
export class McpReadService extends WorkerEntrypoint {
  async listWorkspaces(input) {
    return listWorkspacesForMcp(this.env, input);
  }

  async getWorkspaceSummary(input) {
    return getWorkspaceSummaryForMcp(this.env, input);
  }

  async getWorkspacePosture(input) {
    return getWorkspacePostureForMcp(this.env, input);
  }

  async listRecentScans(input) {
    return listRecentScansForMcp(this.env, input);
  }

  async getScanStatus(input) {
    return getScanStatusForMcp(this.env, input);
  }

  async listManagedCases(input) {
    return listManagedCasesForMcp(this.env, input);
  }
}
