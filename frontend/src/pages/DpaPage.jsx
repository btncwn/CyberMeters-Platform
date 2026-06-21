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

export default function DpaPage() {
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
          <h1 className="text-3xl font-bold text-gray-900">Data Processing Addendum</h1>
          <p className="text-sm text-gray-400 mt-2">Last updated: June 2026 — Version 1.0</p>
          <p className="text-sm text-gray-500 mt-4 leading-relaxed">
            This Data Processing Addendum ("<strong>DPA</strong>") supplements and forms part of the CyberMeters Terms of Service between CyberMeters ("<strong>Processor</strong>") and the customer ("<strong>Controller</strong>"). It governs the processing of personal data by CyberMeters on behalf of the Controller in connection with the provision of the Services.
          </p>
          <p className="text-sm text-gray-500 mt-3 leading-relaxed">
            This DPA is entered into to satisfy the requirements of Article 28 of the UK GDPR and, where applicable, the EU GDPR. In the event of a conflict between this DPA and the Terms of Service, this DPA shall prevail with respect to data protection matters.
          </p>

          <Section title="1. Definitions">
            <p>For the purposes of this DPA, the following terms have the meanings given to them under the UK GDPR:</p>
            <ul className="list-disc pl-5 space-y-2">
              <li><strong className="text-gray-800">Controller</strong> — the customer who determines the purposes and means of processing personal data.</li>
              <li><strong className="text-gray-800">Processor</strong> — CyberMeters, which processes personal data on behalf of the Controller.</li>
              <li><strong className="text-gray-800">Personal Data</strong> — any information relating to an identified or identifiable natural person processed in connection with the Services.</li>
              <li><strong className="text-gray-800">Processing</strong> — any operation performed on personal data, including collection, storage, retrieval, use, disclosure, or deletion.</li>
              <li><strong className="text-gray-800">Sub-Processor</strong> — any third party engaged by CyberMeters to process personal data on behalf of the Controller.</li>
            </ul>
          </Section>

          <Section title="2. Scope and Nature of Processing">
            <p><strong className="text-gray-800">Subject matter.</strong> The Processor provides external attack surface management, security posture monitoring, and reporting services as described in the Terms of Service.</p>
            <p><strong className="text-gray-800">Duration.</strong> Personal data is processed for the duration of the customer's subscription and for such additional periods as required by applicable law or as agreed in writing.</p>
            <p><strong className="text-gray-800">Nature and purpose.</strong> The Processor processes personal data to: operate user accounts and workspace access; run security assessments; generate reports; deliver notifications; maintain audit logs; and fulfil billing obligations.</p>
            <p><strong className="text-gray-800">Types of personal data.</strong> Name, email address, authentication credentials (hashed), usage activity, IP addresses, audit event records, and any personal data contained within scan targets or metadata provided by the Controller.</p>
            <p><strong className="text-gray-800">Categories of data subjects.</strong> Employees, administrators, and other authorised users of the Controller's CyberMeters account.</p>
          </Section>

          <Section title="3. Processor Obligations">
            <p>CyberMeters shall, in its capacity as Processor:</p>
            <ul className="list-disc pl-5 space-y-2">
              <li>Process personal data only on documented instructions from the Controller, including those set out in these Terms and the DPA, unless required to do so by applicable law.</li>
              <li>Ensure that persons authorised to process personal data have committed to confidentiality obligations or are under an appropriate statutory obligation of confidentiality.</li>
              <li>Implement and maintain appropriate technical and organisational security measures as described in Section 5 of this DPA.</li>
              <li>Inform the Controller without undue delay if, in the Processor's opinion, an instruction infringes applicable data protection law.</li>
              <li>Not engage new Sub-Processors without prior notification to the Controller in accordance with Section 4.</li>
              <li>Assist the Controller in fulfilling obligations to respond to requests from data subjects exercising their rights, taking into account the nature of the processing.</li>
              <li>Assist the Controller in meeting obligations related to security of processing, data breach notification, data protection impact assessments, and prior consultation with supervisory authorities.</li>
              <li>At the Controller's choice, delete or return all personal data on termination of the Services, and delete existing copies unless applicable law requires continued retention.</li>
              <li>Make available all information necessary to demonstrate compliance with this DPA and permit audits or inspections conducted by the Controller or a mandated auditor, on reasonable prior notice and during normal business hours.</li>
            </ul>
          </Section>

          <Section title="4. Sub-Processors">
            <p>The Controller grants the Processor general authorisation to engage Sub-Processors. The following Sub-Processors are currently authorised:</p>
            <div className="overflow-x-auto mt-2">
              <table className="w-full text-sm border border-gray-200 rounded-lg overflow-hidden">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase">Sub-Processor</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase">Service</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase">Location</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  <tr>
                    <td className="px-4 py-2.5 font-medium text-gray-800">Cloudflare, Inc.</td>
                    <td className="px-4 py-2.5 text-gray-600">Compute (Workers), database (D1), storage (R2), CDN delivery (Pages)</td>
                    <td className="px-4 py-2.5 text-gray-500">US / Global edge</td>
                  </tr>
                  <tr>
                    <td className="px-4 py-2.5 font-medium text-gray-800">Stripe, Inc.</td>
                    <td className="px-4 py-2.5 text-gray-600">Payment processing and subscription management</td>
                    <td className="px-4 py-2.5 text-gray-500">US / EU</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <p className="mt-3">The Processor shall notify the Controller of any intended changes to Sub-Processors (additions or replacements) with at least 14 days' notice, giving the Controller the opportunity to object. Objections must be raised within 14 days of notification and must be based on reasonable grounds related to data protection. If the parties cannot resolve an objection, either party may terminate the affected portion of the Services.</p>
          </Section>

          <Section title="5. Security Measures">
            <p>CyberMeters implements and maintains the following technical and organisational measures to protect personal data:</p>
            <p><strong className="text-gray-800">Access control.</strong> Role-based access control (RBAC) restricts user access to workspace data on a need-to-know basis. Tenant data isolation is enforced at the database query level. API tokens are scoped and time-limited.</p>
            <p><strong className="text-gray-800">Authentication.</strong> Passwords are hashed using PBKDF2-SHA256 with 100,000 iterations. Multi-factor authentication (TOTP) is available and recommended. All authentication events are logged.</p>
            <p><strong className="text-gray-800">Data in transit.</strong> All data transmitted between clients and the Services is encrypted using TLS 1.2 or higher.</p>
            <p><strong className="text-gray-800">Data at rest.</strong> Data stored in Cloudflare D1 and R2 is encrypted at rest by Cloudflare's infrastructure in accordance with their security commitments.</p>
            <p><strong className="text-gray-800">Audit logging.</strong> All account and workspace actions are recorded in an immutable audit log retained for 12 months.</p>
            <p><strong className="text-gray-800">Incident response.</strong> Security incidents are assessed and documented. The Controller will be notified of a personal data breach without undue delay and in any event within 72 hours of becoming aware of it, where feasible.</p>
          </Section>

          <Section title="6. International Transfers">
            <p>Where personal data is transferred to a country outside the UK that does not benefit from an adequacy decision, such transfers will be subject to appropriate safeguards in accordance with UK GDPR Chapter V, including the UK International Data Transfer Agreement (IDTA) or Standard Contractual Clauses where applicable.</p>
          </Section>

          <Section title="7. Data Subject Rights">
            <p>Where the Processor receives a request directly from a data subject in relation to personal data processed on behalf of the Controller, the Processor shall promptly forward the request to the Controller and shall not respond to the data subject directly unless expressly authorised to do so by the Controller.</p>
            <p>The Processor shall provide reasonable assistance to the Controller in responding to data subject requests, including access, rectification, erasure, restriction, portability, and objection, within the timeframes required by applicable law.</p>
          </Section>

          <Section title="8. Data Retention and Deletion">
            <p>On termination or expiry of the customer's subscription:</p>
            <ul className="list-disc pl-5 space-y-2">
              <li>Personal data will be retained for 30 days to enable the Controller to request a data export.</li>
              <li>After 30 days, personal data will be deleted unless applicable law requires continued retention.</li>
              <li>Billing metadata may be retained for up to 7 years to comply with financial record-keeping obligations.</li>
              <li>Anonymised or aggregated data that cannot reasonably be used to identify any individual may be retained for platform analytics purposes.</li>
            </ul>
          </Section>

          <Section title="9. Contact">
            <p>For data protection queries relating to this DPA, contact CyberMeters at: <a href="mailto:dpa@cybermeters.com" className="text-brand-600 hover:underline font-medium">dpa@cybermeters.com</a></p>
          </Section>
        </article>

        {/* Footer links */}
        <div className="mt-8 flex flex-wrap gap-4 text-xs text-gray-400 justify-center">
          <Link to="/privacy" className="hover:text-gray-700">Privacy Policy</Link>
          <Link to="/terms"   className="hover:text-gray-700">Terms of Service</Link>
          <Link to="/cookies" className="hover:text-gray-700">Cookie Policy</Link>
          <Link to="/support" className="hover:text-gray-700">Support</Link>
        </div>
      </main>
    </div>
  )
}
