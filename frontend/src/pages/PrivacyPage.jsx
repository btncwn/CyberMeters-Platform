import { Link } from 'react-router-dom'
import { Shield } from 'lucide-react'

function Section({ title, children }) {
  return (
    <section className="mt-8">
      <h2 className="text-lg font-bold text-gray-900 border-b border-gray-100 pb-2 mb-4">{title}</h2>
      <div className="space-y-3 text-sm text-gray-600 leading-relaxed">{children}</div>
    </section>
  )
}

export default function PrivacyPage() {
  return (
    <div className="min-h-screen bg-gray-50">
      <main className="max-w-3xl mx-auto px-6 py-12">

        {/* Brand */}
        <Link to="/" className="inline-flex items-center gap-2 group mb-8">
          <div className="w-7 h-7 rounded-md bg-brand-600 flex items-center justify-center">
            <Shield className="w-4 h-4 text-white" strokeWidth={2.5} />
          </div>
          <span className="font-bold text-gray-900 text-sm group-hover:text-brand-700 transition-colors">CyberMeters</span>
        </Link>

        <article className="bg-white border border-gray-100 rounded-2xl shadow-sm p-8 sm:p-10">
          <h1 className="text-3xl font-bold text-gray-900">Privacy Policy</h1>
          <p className="text-sm text-gray-400 mt-2">Last updated: July 2026 — Version 1.1</p>
          <p className="text-sm text-gray-500 mt-4 leading-relaxed">
            CyberMeters ("<strong>we</strong>", "<strong>us</strong>", "<strong>our</strong>") is committed to protecting the personal data of our customers and the individuals associated with them. This Privacy Policy explains what data we collect, how we use it, and your rights in relation to it.
          </p>
          <p className="text-sm text-gray-500 mt-3 leading-relaxed">
            CyberMeters is a trading name of <strong>Turhan Acar</strong>, a sole trader in the United Kingdom, who is the data controller responsible for the personal data processed in connection with your CyberMeters account. Contact: <a href="mailto:hello@cybermeters.com" className="text-brand-600 hover:underline">hello@cybermeters.com</a>.
          </p>
          <p className="text-sm text-gray-500 mt-3 leading-relaxed">
            CyberMeters operates primarily for UK and European business customers. We process personal data in accordance with the UK General Data Protection Regulation (UK GDPR), the Data Protection Act 2018, and where applicable, the EU GDPR.
          </p>

          <Section title="1. Who We Are">
            <p>CyberMeters provides an Attack Surface Management (ASM) platform, Security Posture Management (SPM) tools, and executive security reporting services delivered as a Software-as-a-Service (SaaS) product.</p>
            <p>For questions about this policy or to exercise your rights, contact us at: <a href="mailto:privacy@cybermeters.com" className="text-brand-600 hover:underline">privacy@cybermeters.com</a></p>
          </Section>

          <Section title="2. Data We Collect">
            <p><strong className="text-gray-800">Account data.</strong> When you create an account, we collect your name, email address, and hashed password. We do not store passwords in plaintext.</p>
            <p><strong className="text-gray-800">Workspace and domain data.</strong> We store the domain names and workspace configurations you add to the platform. This includes any metadata you provide when setting up workspaces, such as workspace names and assigned members.</p>
            <p><strong className="text-gray-800">Scan data.</strong> When you initiate a scan, we collect and store the results produced by our external assessment engine. This includes DNS records, SSL certificate data, security header analysis, subdomain discovery results, and related technical findings. Scan targets are domains you own or are authorised to assess.</p>
            <p><strong className="text-gray-800">Audit log data.</strong> We maintain an audit trail of actions performed within the platform, including authentication events, workspace changes, report generation, and API access. Audit events are associated with your user account and workspace.</p>
            <p><strong className="text-gray-800">Authentication session data.</strong> We issue session tokens to authenticate your access. Session tokens are stored server-side and expire on logout or after a configurable period of inactivity.</p>
            <p><strong className="text-gray-800">Billing data.</strong> Subscription and payment processing is handled by Stripe, Inc. CyberMeters receives subscription status, plan tier, and billing cycle metadata from Stripe. We do not store payment card numbers or bank account details.</p>
            <p><strong className="text-gray-800">Usage data.</strong> We collect operational metrics such as scan counts and report generation events to enforce subscription plan limits and to improve the service.</p>
          </Section>

          <Section title="3. How We Use Your Data">
            <p>We process your personal data for the following purposes:</p>
            <ul className="list-disc pl-5 space-y-2">
              <li>To provision and operate your account and workspaces.</li>
              <li>To run security assessments on domains you submit and return findings to you.</li>
              <li>To send transactional communications, including scan completion notifications, password reset emails, and workspace invitation emails.</li>
              <li>To process subscription payments through Stripe and manage plan entitlements.</li>
              <li>To maintain audit logs for security and compliance purposes.</li>
              <li>To enforce acceptable use policies and platform limits.</li>
              <li>To investigate and respond to security incidents.</li>
            </ul>
            <p>We do not sell your personal data. We do not use your scan data for advertising purposes.</p>
          </Section>

          <Section title="4. Legal Basis for Processing (UK GDPR)">
            <p>We rely on the following legal bases:</p>
            <ul className="list-disc pl-5 space-y-2">
              <li><strong className="text-gray-800">Contract performance</strong> — to provide the services you have subscribed to.</li>
              <li><strong className="text-gray-800">Legitimate interests</strong> — to operate, secure, and improve the platform; to maintain audit logs for security purposes; to detect and prevent misuse.</li>
              <li><strong className="text-gray-800">Legal obligation</strong> — where we are required to retain or disclose data to comply with applicable law.</li>
            </ul>
          </Section>

          <Section title="5. Data Retention">
            <p>We retain your data for as long as your account is active or as required to fulfil the purposes described in this policy.</p>
            <ul className="list-disc pl-5 space-y-2">
              <li><strong className="text-gray-800">Account data</strong> — retained for the life of your account plus 30 days following account deletion.</li>
              <li><strong className="text-gray-800">Scan data and reports</strong> — retained for the duration of your subscription plus 90 days, unless you request earlier deletion.</li>
              <li><strong className="text-gray-800">Audit logs</strong> — retained for 12 months from the date of the event.</li>
              <li><strong className="text-gray-800">Billing metadata</strong> — retained for 7 years to meet financial record-keeping obligations.</li>
              <li><strong className="text-gray-800">Session tokens</strong> — expired and deleted on logout or after inactivity. All sessions are invalidated on password reset.</li>
            </ul>
          </Section>

          <Section title="6. Security Controls">
            <p>We apply the following technical controls to protect personal data:</p>
            <ul className="list-disc pl-5 space-y-2">
              <li>Passwords are hashed using PBKDF2-SHA256 with 100,000 iterations. Passwords are never stored in plaintext.</li>
              <li>TOTP-based multi-factor authentication (MFA) is available and recommended for all accounts.</li>
              <li>All API communication is encrypted in transit using TLS.</li>
              <li>Data is stored on Cloudflare D1 (SQLite) and Cloudflare R2 (object storage), both of which provide encryption at rest.</li>
              <li>Access to workspaces and audit logs is controlled by role-based access control (RBAC). Workspace data is tenant-isolated by design.</li>
              <li>API tokens are scoped and expire according to customer configuration.</li>
              <li>All authentication events and workspace actions are recorded in an immutable audit log.</li>
            </ul>
          </Section>

          <Section title="7. Sub-Processors and Third Parties">
            <p>We share data with the following third-party sub-processors where necessary to provide the service:</p>
            <div className="overflow-x-auto mt-2">
              <table className="w-full text-sm border border-gray-200 rounded-lg overflow-hidden">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase">Processor</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase">Purpose</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase">Location</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  <tr>
                    <td className="px-4 py-2.5 font-medium text-gray-800">Cloudflare, Inc.</td>
                    <td className="px-4 py-2.5 text-gray-600">Hosting, compute (Workers), database (D1), object storage (R2), CDN</td>
                    <td className="px-4 py-2.5 text-gray-500">US / Global edge network</td>
                  </tr>
                  <tr>
                    <td className="px-4 py-2.5 font-medium text-gray-800">Stripe, Inc.</td>
                    <td className="px-4 py-2.5 text-gray-600">Payment processing, subscription management</td>
                    <td className="px-4 py-2.5 text-gray-500">US / EU</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <p className="mt-3">We do not share your personal data with any other third parties for commercial or marketing purposes.</p>
          </Section>

          <Section title="8. International Data Transfers">
            <p>Your data may be processed outside the UK by our sub-processors. Where such transfers occur, we rely on appropriate safeguards including the UK International Data Transfer Agreement (IDTA) or Standard Contractual Clauses (SCCs) as applicable.</p>
          </Section>

          <Section title="9. Your Rights">
            <p>Under UK GDPR, you have the following rights in relation to your personal data:</p>
            <ul className="list-disc pl-5 space-y-2">
              <li><strong className="text-gray-800">Right of access</strong> — to receive a copy of the personal data we hold about you.</li>
              <li><strong className="text-gray-800">Right to rectification</strong> — to have inaccurate data corrected.</li>
              <li><strong className="text-gray-800">Right to erasure</strong> — to request deletion of your data in certain circumstances.</li>
              <li><strong className="text-gray-800">Right to restriction</strong> — to request that we limit processing of your data.</li>
              <li><strong className="text-gray-800">Right to data portability</strong> — to receive your data in a structured, machine-readable format.</li>
              <li><strong className="text-gray-800">Right to object</strong> — to object to processing based on legitimate interests.</li>
            </ul>
            <p className="mt-3">To exercise any of these rights, email <a href="mailto:privacy@cybermeters.com" className="text-brand-600 hover:underline">privacy@cybermeters.com</a>. We will respond within 30 days. If you are not satisfied with our response, you have the right to lodge a complaint with the Information Commissioner's Office (ICO) at <a href="https://ico.org.uk" target="_blank" rel="noopener noreferrer" className="text-brand-600 hover:underline">ico.org.uk</a>.</p>
          </Section>

          <Section title="10. Cookies">
            <p>We use essential cookies for authentication and session management. We do not use tracking or advertising cookies. For full details, see our <Link to="/cookies" className="text-brand-600 hover:underline">Cookie Policy</Link>.</p>
          </Section>

          <Section title="11. Changes to This Policy">
            <p>We may update this Privacy Policy from time to time. Material changes will be communicated to customers by email or in-platform notification at least 14 days before they take effect. The "Last updated" date at the top of this page always reflects the current version.</p>
          </Section>

          <Section title="12. Contact">
            <p>For all privacy-related queries or to exercise your data subject rights:</p>
            <p><a href="mailto:privacy@cybermeters.com" className="text-brand-600 hover:underline font-medium">privacy@cybermeters.com</a></p>
          </Section>
        </article>

        {/* Footer links */}
        <div className="mt-8 flex flex-wrap gap-4 text-xs text-gray-400 justify-center">
          <Link to="/terms"   className="hover:text-gray-700">Terms of Service</Link>
          <Link to="/dpa"     className="hover:text-gray-700">DPA</Link>
          <Link to="/cookies" className="hover:text-gray-700">Cookie Policy</Link>
          <Link to="/support" className="hover:text-gray-700">Support</Link>
        </div>
      </main>
    </div>
  )
}
