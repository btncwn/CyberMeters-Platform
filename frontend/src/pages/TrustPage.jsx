import { Link } from 'react-router-dom'
import PublicSiteHeader from '../components/PublicSiteHeader'
import PublicSiteFooter from '../components/PublicSiteFooter'

function Section({ title, children }) {
  return <section className="mt-8">
    <h2 className="text-lg font-bold text-gray-900 border-b border-gray-100 pb-2 mb-4">{title}</h2>
    <div className="space-y-3 text-sm text-gray-600 leading-relaxed">{children}</div>
  </section>
}
function Item({ children }) {
  return <li className="flex items-start gap-2"><span className="mt-1.5 w-1.5 h-1.5 rounded-full bg-brand-500 shrink-0" /><span>{children}</span></li>
}

// Dated, operator-published observation; deliberately not a live trust badge.
// Evidence: the separately authorised owned-domain scan completed
// 2026-10-14T11:16:05.640Z. Its score and incomplete checks remain provisional.
export default function TrustPage() {
  return <div className="min-h-screen bg-gray-50">
      <PublicSiteHeader />
    <main className="max-w-3xl mx-auto px-5 sm:px-6 py-10 sm:py-12">
      <article className="bg-white border border-gray-100 rounded-2xl shadow-xs p-6 sm:p-10">
        <h1 className="text-3xl font-bold text-gray-900">Trust &amp; Security</h1>
        <p className="text-sm text-gray-600 mt-4 leading-relaxed">CyberMeters is built and operated by Turhan Acar, a sole trader. Here is what we have checked, how the product handles evidence and where assurance remains limited.</p>
        <Link to="/status" className="mt-5 inline-flex items-center gap-2 rounded-full border border-gray-200 bg-gray-50 px-4 py-2 text-sm font-semibold text-gray-700">System status</Link>

        <Section title="We use CyberMeters on our own domain">
          <p>This is a summary published by the operator from a real CyberMeters scan of <strong className="text-gray-900">cybermeters.com</strong>, completed <time dateTime="2026-10-14T11:16:05.640Z">14 October 2026 at 11:16:05 UTC</time>. It is a dated observation of our Cloudflare edge endpoints, not a live status or an independent audit.</p>
          <dl className="rounded-xl border border-gray-200 divide-y divide-gray-100">
            <div className="p-4 flex flex-col sm:flex-row sm:justify-between gap-1"><dt className="font-medium text-gray-800">Reported score</dt><dd>Score available after a complete scan</dd></div>
            <div className="p-4 flex flex-col sm:flex-row sm:justify-between gap-1"><dt className="font-medium text-gray-800">Live TLS evidence</dt><dd>4 Cloudflare edge endpoints</dd></div>
            <div className="p-4 flex flex-col sm:flex-row sm:justify-between gap-1"><dt className="font-medium text-gray-800">Scan and TLS coverage</dt><dd>Partial</dd></div>
          </dl>
          <p><strong className="text-gray-800">Why provisional?</strong> The TLS assessment completed 162 of 2,024 planned check outcomes; 346 were uncertain, 212 could not execute and 1,216 were outside this scan budget. Exposed-content coverage was also partial. No final score or assessment band was established.</p>
          <p><strong className="text-gray-800">Special checks.</strong> The separately permitted Heartbleed, ROBOT and OpenSSL CCS tests ran on the recorded endpoints. ROBOT and CCS were not observed in their four TLS 1.2 tests; Heartbleed remained inconclusive because a heartbeat response was unavailable. These observations do not establish safety for other endpoints or later dates.</p>
          <p><strong className="text-gray-800">TLS limits.</strong> The endpoint assessment records offered certificate-chain and stapled-OCSP evidence where available. A missing staple does not establish revocation status; no external revocation lookup was performed. These TCP checks do not assess QUIC or the origin behind Cloudflare.</p>
          <p>This result is not a clean bill of health, a guarantee against vulnerabilities or proof of complete security. The example.co.uk sample on our home page is a separate, clearly labelled illustration.</p>
        </Section>

        <Section title="How the service runs">
          <p>CyberMeters uses Cloudflare Workers, Containers, D1, R2 and Pages for application processing, bounded probes, storage and the web app. External checks run without installing an agent on your devices.</p>
          <p>Checks have declared scope and limits. Unavailable sources, timeouts and unmeasured controls remain visible rather than becoming successful results.</p>
        </Section>
        <Section title="Account and workspace protection">
          <ul className="space-y-2">
            <Item>The web application and API use HTTPS. Passwords are hashed, and multi-factor authentication and Microsoft sign-in are supported.</Item>
            <Item>Access to workspace operations is checked against the current account, role and relevant plan. Automated tests exercise rejected as well as permitted requests.</Item>
            <Item>Customers can manage separate workspaces and roles. An agency’s access to one client does not grant access to another client’s workspace.</Item>
          </ul>
        </Section>
        <Section title="What our development checks mean">
          <p>Development includes source review, automated security and regression checks, controlled product testing and AI-assisted review. These are internal engineering checks. AI-assisted review is not an independent third-party penetration test.</p>
          <p>We do not claim a completed independent third-party penetration test, SOC 2 attestation or ISO 27001 certification. Cyber Essentials readiness indicators are not Cyber Essentials certification.</p>
        </Section>
        <Section title="Recovery and release checks">
          <p>A controlled Cloudflare recovery exercise restored a production database backup into a separate test database and recovered a report object in an isolated location. That verifies the exercised recovery path; it does not establish an off-provider backup or guarantee a recovery time.</p>
          <p>Release checks include recorded deployment identities, rollback preparation and controlled checks of the customer flow. The <Link to="/status" className="text-brand-700 underline">status page</Link> describes service availability separately from security-assessment results.</p>
        </Section>
        <Section title="Data and service providers">
          <p>Turhan Acar, trading as CyberMeters, operates the service. Our <Link to="/privacy" className="text-brand-700 underline">Privacy Policy</Link>, <Link to="/dpa" className="text-brand-700 underline">Data Processing Addendum</Link> and <Link to="/cookies" className="text-brand-700 underline">Cookie Policy</Link> explain data handling and your available controls.</p>
          <p>Providers include Cloudflare for infrastructure, Stripe for payments, Resend for transactional email and Microsoft for optional sign-in.</p>
        </Section>
        <Section title="Report a security concern">
          <p>Email <a href="mailto:hello@cybermeters.com" className="text-brand-700 underline">hello@cybermeters.com</a> about a suspected issue. Tell us what you tested, what you found and how to reproduce it. We welcome good-faith research and will not pursue researchers who act responsibly. Only assess systems and activity for which you have permission.</p>
          <p>Security tools can read the same contact details from our <a href="/.well-known/security.txt" className="text-brand-700 underline">security.txt file</a>, a standard plain-text file (RFC 9116).</p>
        </Section>
        <nav aria-label="Trust page links" className="mt-10 pt-6 border-t border-gray-100 flex flex-wrap gap-x-5 gap-y-2 text-xs text-gray-500"><Link to="/about">About CyberMeters</Link><Link to="/privacy">Privacy</Link><Link to="/terms">Terms</Link><Link to="/dpa">DPA</Link><Link to="/support">Support</Link></nav>
      </article>
    </main>
    <PublicSiteFooter />
  </div>
}
