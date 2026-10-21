import PublicSiteHeader from '../components/PublicSiteHeader'
import PublicSiteFooter from '../components/PublicSiteFooter'

export default function SupportPage() {
  return (
    <div className="min-h-screen bg-gray-50">
      <PublicSiteHeader />
      <main className="max-w-3xl mx-auto px-6 py-12">
        <section className="mt-6 bg-white border border-gray-100 rounded-2xl shadow-card p-8">
          <h1 className="text-3xl font-bold text-gray-900">Support</h1>
          <p className="text-gray-600 mt-3 leading-relaxed">
            Need help getting started or understanding a report? Email us about setup, account access or billing for your business or agency workspace.
          </p>
          <a href="mailto:hello@cybermeters.com" className="mt-6 inline-flex items-center gap-2 btn-primary">
            hello@cybermeters.com
          </a>
          <p className="text-sm text-gray-600 mt-5 leading-relaxed">
            Support is by email. Tell us what you were trying to do and what happened so we can help with the next step.
          </p>
        </section>
        <section id="mcp" aria-labelledby="mcp-help-title" className="mt-8 bg-white border border-gray-100 rounded-2xl p-8 space-y-5 text-gray-700">
          <h2 id="mcp-help-title" className="text-2xl font-bold text-gray-900">Connect your AI assistant</h2>
          <p>CyberMeters offers read-only MCP access for eligible workspaces. Your assistant can read approved evidence and explain its limits; it cannot start scans, change settings or fix issues.</p>
          <p>Add this remote server URL in your client and choose OAuth sign-in:</p>
          <code className="block break-all rounded bg-gray-50 p-3">https://mcp.cybermeters.com/mcp</code>
          <p>Sign in to CyberMeters, choose your workspace and approve read access. Portfolio access needs separate consent for the workspaces you select. Your client account and administrator settings may limit availability.</p>
          <h3 className="text-lg font-semibold text-gray-900">Claude</h3>
          <p>Open Customize → Connectors → Add custom connector. Enter the URL, choose sign-in and Register automatically if asked, then Connect and approve the CyberMeters permission. An organization owner may need to add the connector first.</p>
          <h3 className="text-lg font-semibold text-gray-900">ChatGPT</h3>
          <p>In ChatGPT web, open Plugins → + → Add custom MCP server, enter the URL and choose OAuth with automatic registration if offered. Some accounts label connections Apps. The hosted sign-in callback is not currently enabled for CyberMeters, so registration may be refused. Contact support if this happens; a completed ChatGPT web connection is not yet confirmed.</p>
          <h3 className="text-lg font-semibold text-gray-900">Gemini CLI</h3>
          <pre className="overflow-x-auto rounded bg-gray-50 p-3 text-sm"><code>gemini mcp add --scope user --transport http cybermeters https://mcp.cybermeters.com/mcp</code></pre>
          <p>Start Gemini CLI, enter <code>/mcp auth cybermeters</code>, then complete CyberMeters sign-in and workspace consent. Use <code>/mcp list</code> to inspect the result. These setup steps have not yet been confirmed by a complete live read and reconnect test.</p>
          <h3 className="text-lg font-semibold text-gray-900">What the connection can read</h3>
          <p>Authorized workspaces, domains, security posture, high and critical findings, evidence explanations, recent scans, managed cases, certificate and email posture, and existing report summaries. Portfolio summaries include only separately approved workspaces. Unknown and incomplete evidence stays explicit.</p>
          <h3 className="text-lg font-semibold text-gray-900">Remove access</h3>
          <p>At <a className="text-brand-700 underline" href="https://app.cybermeters.com/account/mcp">MCP connections in your account</a>, select Remove access for the connection. This stops future CyberMeters reads. Also remove the connection in your client. The client may retain data already received under its own terms; removing access cannot erase those copies. Reconnecting requires fresh sign-in and consent.</p>
          <p className="text-sm">Never paste passwords or access tokens into a chat or send them to support.</p>
        </section>
      </main>
      <PublicSiteFooter />
    </div>
  )
}
