import { WorkerEntrypoint } from "cloudflare:workers";
import { validateMcpOAuthToken } from "./mcp-oauth-server.js";

// Private Service Binding target. It never exposes token validation over HTTP.
export class McpOAuthAuthorizationService extends WorkerEntrypoint {
  async validateToken(resource, token) {
    return validateMcpOAuthToken(this.env, resource, token);
  }
}
