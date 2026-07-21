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

export default function CookiePolicyPage() {
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
          <h1 className="text-3xl font-bold text-gray-900">Cookie Policy</h1>
          <p className="text-sm text-gray-400 mt-2">Last updated: June 2026 — Version 1.0</p>
          <p className="text-sm text-gray-500 mt-4 leading-relaxed">
            This Cookie Policy explains how CyberMeters ("<strong>we</strong>", "<strong>us</strong>") uses cookies and similar technologies when you access the CyberMeters platform at <strong>app.cybermeters.com</strong>.
          </p>

          <Section title="1. What Are Cookies?">
            <p>Cookies are small text files placed on your device by a website when you visit it. They allow the website to recognise your device, maintain your session, and remember preferences across page loads.</p>
            <p>We also use <strong>localStorage</strong> — a browser storage mechanism that functions similarly to cookies but is not transmitted with every HTTP request. It is used exclusively for client-side session management.</p>
          </Section>

          <Section title="2. Cookies We Use">
            <p>CyberMeters uses only essential cookies. We do not use tracking cookies, advertising cookies, or third-party analytics cookies. We do not set or read cookies for cross-site tracking.</p>

            <div className="overflow-x-auto mt-3">
              <table className="w-full text-sm border border-gray-200 rounded-lg overflow-hidden">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase">Name / Key</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase">Type</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase">Purpose</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase">Expiry</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  <tr>
                    <td className="px-4 py-2.5 font-mono text-xs text-gray-800">cybermeters_auth_token</td>
                    <td className="px-4 py-2.5 text-gray-600">localStorage (essential)</td>
                    <td className="px-4 py-2.5 text-gray-600">Stores your authentication session token to keep you signed in across page loads. This token is sent with every API request to authenticate your identity.</td>
                    <td className="px-4 py-2.5 text-gray-500">Until logout or session expiry</td>
                  </tr>
                  <tr>
                    <td className="px-4 py-2.5 font-mono text-xs text-gray-800">cybermeters_workspace_id</td>
                    <td className="px-4 py-2.5 text-gray-600">localStorage (essential)</td>
                    <td className="px-4 py-2.5 text-gray-600">Remembers which workspace you last selected so the workspace context is preserved when you navigate within the platform.</td>
                    <td className="px-4 py-2.5 text-gray-500">Until cleared or logout</td>
                  </tr>
                  <tr>
                    <td className="px-4 py-2.5 font-mono text-xs text-gray-800">cybermeters_workspace_name</td>
                    <td className="px-4 py-2.5 text-gray-600">localStorage (essential)</td>
                    <td className="px-4 py-2.5 text-gray-600">Stores the display name of the selected workspace to avoid an additional API call on each page load.</td>
                    <td className="px-4 py-2.5 text-gray-500">Until cleared or logout</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </Section>

          <Section title="3. Third-Party Cookies">
            <p><strong className="text-gray-800">Cloudflare.</strong> Our platform is hosted on Cloudflare Pages and served via the Cloudflare global network. Cloudflare may set technical cookies as part of its DDoS protection and bot management infrastructure. These are essential for service security and delivery. See <a href="https://www.cloudflare.com/privacypolicy/" target="_blank" rel="noopener noreferrer" className="text-brand-600 hover:underline">Cloudflare's privacy policy</a> for details.</p>
            <p><strong className="text-gray-800">Stripe.</strong> Our pricing and checkout pages embed elements from Stripe, Inc. for payment processing. Stripe may set cookies on these pages to prevent fraud and authenticate payment sessions. These are only active on pages where you initiate a subscription checkout. See <a href="https://stripe.com/privacy" target="_blank" rel="noopener noreferrer" className="text-brand-600 hover:underline">Stripe's privacy policy</a> for details.</p>
          </Section>

          <Section title="4. What We Do NOT Use Cookies For">
            <p>We do not use cookies or browser storage for:</p>
            <ul className="list-disc pl-5 space-y-2">
              <li>Advertising or marketing targeting of any kind.</li>
              <li>Tracking your activity across other websites.</li>
              <li>Selling your data to data brokers or advertisers.</li>
              <li>Profiling your behaviour for algorithmic recommendations outside of the Services.</li>
              <li>Analytics platforms that track individual user journeys across sessions (e.g. Google Analytics is not installed on the platform).</li>
            </ul>
          </Section>

          <Section title="5. Your Choices">
            <p><strong className="text-gray-800">Browser settings.</strong> You can configure your browser to block or delete cookies and localStorage at any time. Blocking essential cookies will prevent you from signing in to the platform, as the authentication token cannot be stored.</p>
            <p><strong className="text-gray-800">Logging out.</strong> Signing out of the platform via the account menu clears your authentication token from localStorage and invalidates your session server-side.</p>
            <p><strong className="text-gray-800">Incognito / private mode.</strong> Using your browser in private mode will clear localStorage on window close. You will need to sign in again in each new private session.</p>
            <p>Because all cookies and storage we use are strictly necessary for the operation of the platform, they are exempt from opt-in consent requirements under the UK PECR (Privacy and Electronic Communications Regulations).</p>
          </Section>

          <Section title="6. Changes to This Policy">
            <p>If we introduce new cookies or storage mechanisms, we will update this Cookie Policy and notify customers via email or in-platform notification before the change takes effect.</p>
          </Section>

          <Section title="7. Contact">
            <p>For questions about this Cookie Policy, contact us at: <a href="mailto:hello@cybermeters.com" className="text-brand-600 hover:underline font-medium">hello@cybermeters.com</a></p>
          </Section>
        </article>

        {/* Footer links */}
        <div className="mt-8 flex flex-wrap gap-4 text-xs text-gray-400 justify-center">
          <Link to="/privacy" className="hover:text-gray-700">Privacy Policy</Link>
          <Link to="/terms"   className="hover:text-gray-700">Terms of Service</Link>
          <Link to="/dpa"     className="hover:text-gray-700">DPA</Link>
          <Link to="/support" className="hover:text-gray-700">Support</Link>
        </div>
      </main>
    </div>
  )
}
