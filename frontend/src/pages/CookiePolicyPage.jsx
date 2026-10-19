import { Link } from 'react-router-dom'
import PublicSiteHeader from '../components/PublicSiteHeader'
import PublicSiteFooter from '../components/PublicSiteFooter'

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
      <PublicSiteHeader />
      <main className="max-w-3xl mx-auto px-6 py-12">


        <article className="bg-white border border-gray-100 rounded-2xl shadow-xs p-8 sm:p-10">
          <h1 className="text-3xl font-bold text-gray-900">Cookie Policy</h1>
          <p className="text-sm text-gray-400 mt-2">Last updated: 20 October 2026 — Version 1.4</p>
          <p className="text-sm text-gray-500 mt-4 leading-relaxed">
            This Cookie Policy explains how CyberMeters ("<strong>we</strong>", "<strong>us</strong>") uses cookies and browser storage on <strong>cybermeters.com</strong> and <strong>app.cybermeters.com</strong>, including the free scan and the free tools.
          </p>

          <Section title="1. What Are Cookies and Browser Storage?">
            <p>Cookies are small text files a website places on your device. Browser storage (<strong>localStorage</strong> and <strong>sessionStorage</strong>) is similar, but stays in your browser and is not sent with every request. sessionStorage is cleared when you close the tab.</p>
            <p>CyberMeters uses browser storage to keep you signed in, remember the workspace you are working in and remember a few small preferences. It sets one short-lived cookie, only while you connect an AI assistant.</p>
          </Section>

          <Section title="2. What We Store in Your Browser">
            <p>Everything below is essential to how the site works or a preference you chose. None of it is used for advertising or to follow you across other sites.</p>
            <ul className="mt-3 divide-y divide-gray-100 border-y border-gray-100">
              <li className="py-3">
                <p className="font-mono text-xs text-gray-800 break-all">cybermeters_auth_token</p>
                <p className="text-xs text-gray-500 mt-1">localStorage · Kept: Until you sign out or the session expires</p>
                <p className="mt-1">Keeps you signed in: your session token, sent with each request to the API.</p>
              </li>
              <li className="py-3">
                <p className="font-mono text-xs text-gray-800 break-all">cybermeters_auth_user</p>
                <p className="text-xs text-gray-500 mt-1">localStorage · Kept: Until you sign out</p>
                <p className="mt-1">Your name, email and plan, so the app can show them before it has asked the server.</p>
              </li>
              <li className="py-3">
                <p className="font-mono text-xs text-gray-800 break-all">cybermeters_workspace_id, cybermeters_workspace_name</p>
                <p className="text-xs text-gray-500 mt-1">localStorage · Kept: Until you sign out or switch account</p>
                <p className="mt-1">The workspace you are working in. Cleared when you sign out or another account signs in, and checked against your own workspaces each time the app loads.</p>
              </li>
              <li className="py-3">
                <p className="font-mono text-xs text-gray-800 break-all">cybermeters_pending_invite</p>
                <p className="text-xs text-gray-500 mt-1">localStorage · Kept: Until you accept or dismiss it</p>
                <p className="mt-1">An invitation you opened, so it is still offered after you sign up and verify your email.</p>
              </li>
              <li className="py-3">
                <p className="font-mono text-xs text-gray-800 break-all">cybermeters_joined_via_invite</p>
                <p className="text-xs text-gray-500 mt-1">localStorage · Kept: Until you sign out</p>
                <p className="mt-1">Shows the short welcome for people who joined through an invitation.</p>
              </li>
              <li className="py-3">
                <p className="font-mono text-xs text-gray-800 break-all">cybermeters_onboarding_dismissed, cybermeters_team_onboarding_dismissed, cybermeters_results_guide_dismissed</p>
                <p className="text-xs text-gray-500 mt-1">localStorage · Kept: Until you clear your browser storage</p>
                <p className="mt-1">Remembers that you closed a setup hint, so it does not come back.</p>
              </li>
              <li className="py-3">
                <p className="font-mono text-xs text-gray-800 break-all">cybermeters_invite_dismissed</p>
                <p className="text-xs text-gray-500 mt-1">sessionStorage · Kept: Until you close the tab</p>
                <p className="mt-1">Hides an invitation banner you chose “Not now” on.</p>
              </li>
              <li className="py-3">
                <p className="font-mono text-xs text-gray-800 break-all">cm_billing_interval</p>
                <p className="text-xs text-gray-500 mt-1">localStorage · Kept: Until you clear your browser storage</p>
                <p className="mt-1">Remembers whether you were looking at monthly or annual prices.</p>
              </li>
              <li className="py-3">
                <p className="font-mono text-xs text-gray-800 break-all">cm_pending_domain</p>
                <p className="text-xs text-gray-500 mt-1">localStorage · Kept: Until setup uses it</p>
                <p className="mt-1">The domain you typed before creating an account, so setup can start with it.</p>
              </li>
              <li className="py-3">
                <p className="font-mono text-xs text-gray-800 break-all">cybermeters_scan_duration_samples</p>
                <p className="text-xs text-gray-500 mt-1">localStorage · Kept: Until you clear your browser storage</p>
                <p className="mt-1">How long your recent scans took, read from reports you already opened, to estimate how long a running scan will take.</p>
              </li>
              <li className="py-3">
                <p className="font-mono text-xs text-gray-800 break-all">cm_ms_login_bindings</p>
                <p className="text-xs text-gray-500 mt-1">localStorage · Kept: 15 minutes</p>
                <p className="mt-1">Ties a Microsoft sign-in to the browser that started it, so a sign-in link cannot be used from another browser.</p>
              </li>
              <li className="py-3">
                <p className="font-mono text-xs text-gray-800 break-all">cm_ms_mcp_continuation</p>
                <p className="text-xs text-gray-500 mt-1">sessionStorage · Kept: 15 minutes, or when the tab closes</p>
                <p className="mt-1">While you connect an AI assistant and sign in with Microsoft, remembers where to return.</p>
              </li>
              <li className="py-3">
                <p className="font-mono text-xs text-gray-800 break-all">cybermeters_chunk_reload_at</p>
                <p className="text-xs text-gray-500 mt-1">sessionStorage · Kept: Until you close the tab</p>
                <p className="mt-1">After an update, stops the page reloading itself more than once.</p>
              </li>
              <li className="py-3">
                <p className="font-mono text-xs text-gray-800 break-all">__Host-cm-mcp-auth</p>
                <p className="text-xs text-gray-500 mt-1">Cookie (essential, HttpOnly, Secure) · Kept: 10 minutes</p>
                <p className="mt-1">Set only while you connect an AI assistant to CyberMeters, to link the approval to your signed-in session.</p>
              </li>
            </ul>
          </Section>

          <Section title="3. Third Parties">
            <p data-testid="cookieless-analytics"><strong className="text-gray-800">Visit counting (Cloudflare Web Analytics).</strong> Our hosting provider counts page visits on cybermeters.com and app.cybermeters.com with cookieless analytics. It sets no cookies, stores nothing in your browser and does not track you across sites.</p>
            <p><strong className="text-gray-800">Cloudflare.</strong> The site is hosted on Cloudflare Pages and served through the Cloudflare network. Cloudflare may set technical cookies for security and bot protection. See <a href="https://www.cloudflare.com/privacypolicy/" target="_blank" rel="noopener noreferrer" className="text-brand-700 hover:underline">Cloudflare's privacy policy</a>.</p>
            <p><strong className="text-gray-800">Robot check on the free tools (Cloudflare Turnstile).</strong> Before a free tool runs, a short check in your browser tells people apart from automated abuse. It is loaded only on the free tool pages.</p>
            <p><strong className="text-gray-800">Stripe.</strong> Checkout uses Stripe for payment. Stripe may set cookies on the checkout pages to prevent fraud. See <a href="https://stripe.com/privacy" target="_blank" rel="noopener noreferrer" className="text-brand-700 hover:underline">Stripe's privacy policy</a>.</p>
          </Section>

          <Section title="4. The Free Scan and the Free Tools">
            <p>The free scan and the free tools read only public information about the domain you enter, such as DNS records and the website's public response. What is kept:</p>
            <ul className="list-disc pl-5 space-y-2">
              <li><strong className="text-gray-800">No report.</strong> The result is shown in your browser. No scan report or monitoring history is saved.</li>
              <li><strong className="text-gray-800">Rate-limit records.</strong> To prevent misuse we count checks per connection and per domain. The records hold a one-way hash of the IP address or domain, never the address or domain itself, and are deleted about a day after their counting window ends.</li>
              <li><strong className="text-gray-800">A short result cache for the free tools.</strong> The same public result may be reused for 10 minutes so the same domain is not looked up again. It is keyed by a hash of the domain.</li>
              <li><strong className="text-gray-800">Share links.</strong> A free-tool share link carries the result itself, signed so it cannot be changed, after the <code>#</code> in the address. Nothing is stored for it on our side, and the link expires after 7 days.</li>
              <li><strong className="text-gray-800">Email me the result.</strong> Only if the free tools are paused at capacity, you can choose to leave an email address for that one result. We keep the address and the domain until the result is sent, and delete them after 72 hours at most, sent or not.</li>
            </ul>
          </Section>

          <Section title="5. What We Do Not Use Cookies or Storage For">
            <ul className="list-disc pl-5 space-y-2">
              <li>Advertising or marketing targeting of any kind.</li>
              <li>Tracking your activity across other websites.</li>
              <li>Selling your data to data brokers or advertisers.</li>
              <li>Profiling your behaviour for recommendations outside the service.</li>
              <li>Analytics that follow an individual across sessions.</li>
            </ul>
          </Section>

          <Section title="6. Your Choices">
            <p><strong className="text-gray-800">Browser settings.</strong> You can block or delete cookies and browser storage at any time. Without browser storage you cannot stay signed in, because the session token cannot be kept.</p>
            <p><strong className="text-gray-800">Signing out.</strong> Signing out clears your session token, your account details and your active workspace from the browser and ends the session on our side.</p>
            <p><strong className="text-gray-800">Private browsing.</strong> In a private window, browser storage is cleared when the window closes, so you sign in again each time.</p>
            <p>Because everything we store is strictly necessary for the service or a preference you set, it does not need opt-in consent under the UK PECR (Privacy and Electronic Communications Regulations). If we add anything that does, we will update this policy and ask first.</p>
          </Section>

          <Section title="7. Contact">
            <p>For questions about this Cookie Policy, contact us at: <a href="mailto:hello@cybermeters.com" className="text-brand-700 hover:underline font-medium">hello@cybermeters.com</a></p>
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
      <PublicSiteFooter />
    </div>
  )
}
