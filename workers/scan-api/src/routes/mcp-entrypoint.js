import { WorkerEntrypoint } from "cloudflare:workers";
import {
  listWorkspacesForMcp, getWorkspaceSummaryForMcp,
  getWorkspacePostureForMcp, listRecentScansForMcp,
  getScanStatusForMcp, listManagedCasesForMcp,
} from "./mcp-service.js";
import { customerMcpReads, recordMcpGatewayDenial } from "./mcp-customer-service.js";

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

// Customer OAuth never reaches the trial-token entrypoint above. Each RPC
// repeats the token, current tenant, budget and durable audit gates.
export class McpCustomerReadService extends WorkerEntrypoint {
  async recordGatewayDenial(input) { return recordMcpGatewayDenial(this.env, input); }
  async listWorkspaces(input) { return customerMcpReads.listWorkspaces(this.env, input); }
  async getWorkspaceSummary(input) { return customerMcpReads.getWorkspaceSummary(this.env, input); }
  async getWorkspacePosture(input) { return customerMcpReads.getWorkspacePosture(this.env, input); }
  async listRecentScans(input) { return customerMcpReads.listRecentScans(this.env, input); }
  async getScanStatus(input) { return customerMcpReads.getScanStatus(this.env, input); }
  async listManagedCases(input) { return customerMcpReads.listManagedCases(this.env, input); }
  async getManagedCase(input) { return customerMcpReads.getManagedCase(this.env, input); }
  async listDomains(input) { return customerMcpReads.listDomains(this.env, input); }
  async listFindings(input) { return customerMcpReads.listFindings(this.env, input); }
  async explainFinding(input) { return customerMcpReads.explainFinding(this.env, input); }
  async getTlsPosture(input) { return customerMcpReads.getTlsPosture(this.env, input); }
  async getEmailPosture(input) { return customerMcpReads.getEmailPosture(this.env, input); }
  async getReportSummary(input) { return customerMcpReads.getReportSummary(this.env, input); }
  async getPortfolioSummary(input) { return customerMcpReads.getPortfolioSummary(this.env, input); }
}
