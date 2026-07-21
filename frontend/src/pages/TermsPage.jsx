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

export default function TermsPage() {
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
          <h1 className="text-3xl font-bold text-gray-900">Terms of Service</h1>
          <p className="text-sm text-gray-400 mt-2">Last updated: July 2026 — Version 1.1</p>
          <p className="text-sm text-gray-500 mt-4 leading-relaxed">
            These Terms of Service ("<strong>Terms</strong>") govern your access to and use of the CyberMeters platform and related services ("<strong>Services</strong>") provided by CyberMeters ("<strong>we</strong>", "<strong>us</strong>", "<strong>our</strong>").
          </p>
          <p className="text-sm text-gray-500 mt-3 leading-relaxed">
            CyberMeters is a trading name of <strong>Turhan Acar</strong>, a sole trader in the United Kingdom. References to "CyberMeters", "we", "us" or "our" mean Turhan Acar trading as CyberMeters. You can contact us at <a href="mailto:hello@cybermeters.com" className="text-brand-600 hover:underline">hello@cybermeters.com</a>.
          </p>
          <p className="text-sm text-gray-500 mt-3 leading-relaxed">
            By creating an account or using the Services, you agree to be bound by these Terms. If you are accepting on behalf of an organisation, you represent that you have authority to bind that organisation.
          </p>

          <div className="mt-6 bg-amber-50 border border-amber-100 rounded-xl p-4 text-sm text-amber-800">
            <strong>Beta Notice.</strong> CyberMeters is currently in public beta. The Services are provided on an "as available" basis. Features, pricing, and terms may change. We will provide advance notice of material changes.
          </div>

          <Section title="1. Service Description">
            <p>CyberMeters provides an Attack Surface Management (ASM) platform that enables customers to discover, inventory, and monitor the external security posture of their digital infrastructure. The Services include:</p>
            <ul className="list-disc pl-5 space-y-2">
              <li>Automated external scanning of customer-owned or authorised domains.</li>
              <li>Security posture scoring, reporting, and executive dashboards.</li>
              <li>Portfolio monitoring across multiple workspaces.</li>
              <li>Scheduled scanning and alerting.</li>
              <li>API access for integration with third-party tooling.</li>
            </ul>
          </Section>

          <Section title="2. Eligibility and Account Registration">
            <p>To use the Services, you must: (a) be at least 18 years of age; (b) provide accurate registration information; and (c) maintain the security of your account credentials.</p>
            <p>You are responsible for all activity that occurs under your account. You must notify us immediately at <a href="mailto:support@cybermeters.com" className="text-brand-600 hover:underline">support@cybermeters.com</a> if you suspect unauthorised access to your account.</p>
          </Section>

          <Section title="3. Acceptable Use">
            <p>You may only use the Services to scan domains and infrastructure that you own, operate, or have explicit written authorisation to assess. Scanning third-party assets without authorisation is a violation of these Terms and may constitute unlawful computer access.</p>
            <p>You must not use the Services to:</p>
            <ul className="list-disc pl-5 space-y-2">
              <li>Scan or probe systems you do not own or are not authorised to assess.</li>
              <li>Conduct denial-of-service attacks or deliberately disrupt third-party infrastructure.</li>
              <li>Attempt to circumvent plan limits, authentication controls, or access controls within the platform.</li>
              <li>Use the platform to process, store, or transmit unlawful content.</li>
              <li>Attempt to reverse-engineer or extract proprietary components of the platform.</li>
              <li>Resell or sublicence access to the Services without our written consent.</li>
            </ul>
            <p>We reserve the right to suspend or terminate accounts that violate these acceptable use requirements, with or without prior notice depending on severity.</p>
          </Section>

          <Section title="4. Customer Responsibilities">
            <p>You are responsible for:</p>
            <ul className="list-disc pl-5 space-y-2">
              <li>Ensuring all domains added to the platform are owned by you or your organisation, or that you hold valid written authorisation to scan them.</li>
              <li>Maintaining appropriate access controls for users within your workspaces.</li>
              <li>Keeping your account credentials and API tokens secure and confidential.</li>
              <li>Complying with all applicable laws in your jurisdiction when using the Services.</li>
              <li>Reviewing and acting on security findings produced by the platform in a timely manner.</li>
            </ul>
          </Section>

          <Section title="5. Subscription and Billing">
            <p>Access to the Services is subject to a subscription plan. Subscriptions are billed on a recurring basis (monthly or annually depending on your plan). All fees are stated in pounds sterling (GBP). CyberMeters (Turhan Acar) is not currently registered for VAT; no VAT is charged on subscriptions and invoices do not show a VAT line. If CyberMeters becomes VAT-registered in future, fees and invoices will be updated accordingly and you will be notified.</p>
            <p>Payment processing is handled by Stripe, Inc. By providing a payment method, you authorise us to charge the applicable subscription fees to that method at the start of each billing period.</p>
            <p>If a payment fails, we will attempt to notify you. Continued failure may result in suspension of the Services. Subscriptions may be cancelled at any time through your account settings; cancellation takes effect at the end of the current billing period.</p>
            <p>We reserve the right to change subscription pricing with at least 30 days' advance notice to existing customers. Price changes will not apply to the current billing period.</p>
          </Section>

          <Section title="6. Intellectual Property">
            <p><strong className="text-gray-800">Our IP.</strong> The CyberMeters platform, software, documentation, scoring models, and all related materials are owned by CyberMeters and protected by applicable intellectual property laws. These Terms do not grant you any rights to our trademarks, patents, or source code.</p>
            <p><strong className="text-gray-800">Your IP.</strong> You retain all rights to domain names, infrastructure data, and any other proprietary information you submit to the platform. By submitting data to the Services, you grant us a limited, non-exclusive licence to process that data solely to provide the Services to you.</p>
            <p><strong className="text-gray-800">Scan output.</strong> Security reports and findings generated by the platform from your domains are owned by you. We retain aggregate, anonymised statistical data for the purpose of improving the accuracy and performance of our scanning engine.</p>
          </Section>

          <Section title="7. Limitation of Liability">
            <p>To the maximum extent permitted by applicable law:</p>
            <ul className="list-disc pl-5 space-y-2">
              <li>The Services are provided "as is" and "as available" without warranties of any kind, express or implied, including warranties of merchantability, fitness for a particular purpose, or non-infringement.</li>
              <li>We do not warrant that the Services will be uninterrupted, error-free, or that scan results will be complete or accurate in all circumstances.</li>
              <li>Our total aggregate liability arising out of or in connection with these Terms or the Services shall not exceed the total fees paid by you to us in the three months preceding the event giving rise to the claim.</li>
              <li>We shall not be liable for any indirect, incidental, special, consequential, or punitive damages, including loss of profits, loss of data, or business interruption.</li>
            </ul>
            <p>Nothing in these Terms limits or excludes liability that cannot be limited or excluded under applicable law, including liability for fraud or death or personal injury caused by negligence.</p>
          </Section>

          <Section title="8. Data Processing">
            <p>Where you process personal data using the Services, you act as the data controller and CyberMeters acts as a data processor. Our Data Processing Addendum (DPA), available at <Link to="/dpa" className="text-brand-600 hover:underline">/dpa</Link>, forms part of these Terms and governs such processing.</p>
          </Section>

          <Section title="9. Confidentiality">
            <p>Each party agrees to treat the other's non-public information as confidential and not to disclose it to third parties without the other's prior written consent, except as required by law. Scan results and security findings relating to your infrastructure are treated as your confidential information.</p>
          </Section>

          <Section title="10. Termination">
            <p><strong className="text-gray-800">By you.</strong> You may terminate your account at any time by contacting us or through account settings. Termination does not entitle you to a refund of any prepaid subscription fees, except where required by law.</p>
            <p><strong className="text-gray-800">By us.</strong> We may suspend or terminate your access immediately if: (a) you materially breach these Terms; (b) you use the Services for unlawful purposes; (c) continued provision would expose us or third parties to legal or security risk.</p>
            <p><strong className="text-gray-800">Effect of termination.</strong> On termination, your right to use the Services ceases. We will retain your data for 30 days post-termination to allow you to request an export, after which it will be deleted in accordance with our Privacy Policy.</p>
          </Section>

          <Section title="11. Changes to These Terms">
            <p>We may update these Terms from time to time. We will provide at least 14 days' notice of material changes via email or in-platform notification. Your continued use of the Services after the effective date of the updated Terms constitutes acceptance of the new Terms.</p>
          </Section>

          <Section title="12. Governing Law and Disputes">
            <p>These Terms are governed by and construed in accordance with the law of Scotland. Any dispute arising out of or in connection with these Terms shall be subject to the exclusive jurisdiction of the Scottish courts. Nothing in this clause removes any mandatory consumer-protection rights available to you under the law of the country in which you live.</p>
          </Section>

          <Section title="13. Contact">
            <p>For questions about these Terms, contact us at: <a href="mailto:legal@cybermeters.com" className="text-brand-600 hover:underline font-medium">legal@cybermeters.com</a></p>
          </Section>
        </article>

        {/* Footer links */}
        <div className="mt-8 flex flex-wrap gap-4 text-xs text-gray-400 justify-center">
          <Link to="/privacy" className="hover:text-gray-700">Privacy Policy</Link>
          <Link to="/dpa"     className="hover:text-gray-700">DPA</Link>
          <Link to="/cookies" className="hover:text-gray-700">Cookie Policy</Link>
          <Link to="/support" className="hover:text-gray-700">Support</Link>
        </div>
      </main>
    </div>
  )
}
