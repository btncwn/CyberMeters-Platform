import { Link } from 'react-router-dom'
import {
  Shield, Lock, Server, Users, Code2, Database,
  Activity, Mail, FileCheck, ArrowRight,
} from 'lucide-react'

// ─────────────────────────────────────────────────────────────────────────────
// Public Trust Center. Answers the first question a security buyer asks in 2026:
// "why should I trust you?". Every claim here is deliberately conservative — it
// states only what is genuinely true of the platform today. Anything not yet
// done (third-party pentest, SOC 2) is described as planned, never as achieved.
// ─────────────────────────────────────────────────────────────────────────────

function Section({ icon: Icon, title, children }) {
  return (
    <section className="mt-8">
      <h2 className="flex items-center gap-2 text-lg font-bold text-gray-900 border-b border-gray-100 pb-2 mb-4">
        <Icon className="w-4.5 h-4.5 text-brand-600" strokeWidth={2.2} />
        {title}
      </h2>
      <div className="space-y-3 text-sm text-gray-600 leading-relaxed">{children}</div>
    </section>
  )
}

function Item({ children }) {
  return (
    <li className="flex items-start gap-2">
      <span className="mt-1.5 w-1.5 h-1.5 rounded-full bg-brand-500 flex-shrink-0" />
      <span>{children}</span>
    </li>
  )
}

export default function TrustPage() {
  return (
    <div className="min-h-screen bg-gray-50">
      <main className="max-w-3xl mx-auto px-6 py-12">
        <Link to="/" className="inline-flex items-center gap-2 group mb-8">
          <div className="w-7 h-7 rounded-md bg-brand-600 flex items-center justify-center">
            <Shield className="w-4 h-4 text-white" strokeWidth={2.5} />
          </div>
          <span className="font-bold text-gray-900 text-sm group-hover:text-brand-700 transition-colors">CyberMeters</span>
        </Link>

        <article className="bg-white border border-gray-100 rounded-2xl shadow-sm p-8 sm:p-10">
          <h1 className="text-3xl font-bold text-gray-900">Trust &amp; Security</h1>
          <p className="text-sm text-gray-500 mt-4 leading-relaxed">
            CyberMeters helps UK businesses and their IT providers see their externally
            visible cyber risk. We hold ourselves to the standard we measure others by:
            the practices below describe how we build, run, and protect the platform.
          </p>

          {/* Live status badge → status page */}
          <Link
            to="/status"
            className="mt-5 inline-flex items-center gap-2 rounded-full border border-gray-200 bg-gray-50 px-4 py-2 text-sm font-semibold text-gray-700 hover:border-brand-300 hover:text-brand-700 transition-colors"
          >
            <Activity className="w-4 h-4 text-brand-600" />
            System status
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>

          <Section icon={Server} title="Infrastructure">
            <p>CyberMeters runs entirely on <strong className="text-gray-800">Cloudflare&rsquo;s</strong> global edge platform — Workers (application), D1 (database), R2 (report storage), and Pages (web app). There are no long-lived servers to patch and no customer-managed agents installed on your systems: our assessment is <strong className="text-gray-800">outside-in</strong>, using only what is publicly visible about a domain.</p>
          </Section>

          <Section icon={Lock} title="Encryption &amp; transport security">
            <ul className="space-y-2">
              <Item>All traffic is served over HTTPS with <strong className="text-gray-800">HSTS</strong> (<code>max-age</code> one year, <code>includeSubDomains</code>).</Item>
              <Item>A strict <strong className="text-gray-800">Content-Security-Policy</strong>, <code>X-Frame-Options: DENY</code>, <code>X-Content-Type-Options: nosniff</code> and a scoped CORS policy are enforced on every response.</Item>
              <Item>Data at rest in Cloudflare D1 and R2 is encrypted by the platform.</Item>
              <Item>Passwords are stored <strong className="text-gray-800">hashed</strong>, never in plaintext. Multi-factor authentication and Microsoft SSO are supported.</Item>
            </ul>
          </Section>

          <Section icon={Users} title="Tenant isolation">
            <p>CyberMeters is multi-tenant by design. Every record is scoped to a workspace, and access is enforced by role on each request. Cross-tenant access is treated as a first-class risk and is covered by a dedicated automated test matrix that runs on every change (read, write, delete, and existence-probe paths across multiple actor roles).</p>
          </Section>

          <Section icon={Code2} title="Secure development">
            <ul className="space-y-2">
              <Item>Static analysis (SAST) runs on every change and blocks the merge on any finding.</Item>
              <Item>Dependencies are audited continuously, inventoried as a <strong className="text-gray-800">Software Bill of Materials (SBOM)</strong>, and gated by a license policy; CI actions are pinned to exact versions.</Item>
              <Item>We maintain a <strong className="text-gray-800">STRIDE threat model</strong> of our critical flows and an <strong className="text-gray-800">OWASP ASVS Level 2</strong> gap assessment.</Item>
              <Item>Every security or reliability fix ships with an automated regression test that locks it in — the platform is guarded by a large suite of merge-blocking checks.</Item>
              <Item>Secrets are managed outside the codebase and are automatically redacted from logs.</Item>
            </ul>
          </Section>

          <Section icon={Activity} title="Availability &amp; operations">
            <ul className="space-y-2">
              <Item>Health and readiness endpoints let us and our monitoring see &ldquo;process up&rdquo; versus &ldquo;dependencies healthy&rdquo; separately.</Item>
              <Item>A daily automated self-check watches for silent failures and alerts our team.</Item>
              <Item>Backups are taken and <strong className="text-gray-800">restore has been drill-tested</strong>, with recovery objectives recorded.</Item>
              <Item>We follow a documented incident-response plan and a release checklist with fast rollback.</Item>
              <Item>Live component status is published on our <Link to="/status" className="text-brand-600 hover:underline">status page</Link>.</Item>
            </ul>
          </Section>

          <Section icon={Database} title="Data protection &amp; privacy">
            <p>We process personal data under the UK GDPR and the Data Protection Act 2018. We collect only what the service needs, and workspace and domain data can be deleted on request — deletions are completed through a soft-delete then permanent-purge lifecycle. See our <Link to="/privacy" className="text-brand-600 hover:underline">Privacy Policy</Link>, <Link to="/dpa" className="text-brand-600 hover:underline">Data Processing Addendum</Link>, and <Link to="/cookies" className="text-brand-600 hover:underline">Cookie Policy</Link>.</p>
            <p className="mt-2"><strong className="text-gray-800">Subprocessors.</strong> We rely on a small set of trusted providers: <strong>Cloudflare</strong> (infrastructure), <strong>Stripe</strong> (payments), <strong>Resend</strong> (transactional email), and <strong>Microsoft</strong> (optional single sign-on). We do not sell customer data.</p>
          </Section>

          <Section icon={FileCheck} title="Compliance &amp; assurance">
            <p>Our findings map to the UK <strong className="text-gray-800">Cyber Essentials</strong> control set, so customers can see where they stand against it. Our own assurance posture is honest about where we are:</p>
            <ul className="space-y-2 mt-2">
              <Item>UK GDPR / DPA 2018-aligned data handling — <span className="text-green-600 font-medium">in place</span>.</Item>
              <Item>Internal security testing and red-team review — <span className="text-green-600 font-medium">ongoing</span>.</Item>
              <Item>Independent third-party penetration test — <span className="text-amber-600 font-medium">planned before commercial general availability</span>.</Item>
              <Item>SOC 2 / ISO 27001 — <span className="text-gray-500 font-medium">on our roadmap</span>; we are not certified today and do not claim to be.</Item>
            </ul>
          </Section>

          <Section icon={Mail} title="Reporting a vulnerability">
            <p>If you believe you have found a security issue in CyberMeters, please tell us at <a href="mailto:security@cybermeters.com" className="text-brand-600 hover:underline">security@cybermeters.com</a>. Our machine-readable policy is published at <a href="/.well-known/security.txt" className="text-brand-600 hover:underline">/.well-known/security.txt</a> (RFC 9116). We welcome good-faith research and will not pursue researchers who act responsibly.</p>
          </Section>

          <p className="mt-10 pt-6 border-t border-gray-100 text-xs text-gray-400">
            This page describes CyberMeters&rsquo; security practices as of the current release and may evolve as the platform matures. For security or compliance questions, contact <a href="mailto:security@cybermeters.com" className="text-brand-600 hover:underline">security@cybermeters.com</a>.
          </p>
        </article>
      </main>
    </div>
  )
}
