import { Link } from 'react-router-dom'
import PublicSiteHeader from '../components/PublicSiteHeader'
import PublicSiteFooter from '../components/PublicSiteFooter'

export default function AboutPage() {
  return <div className="min-h-screen bg-gray-50 text-gray-900">
      <PublicSiteHeader />
    <main className="max-w-3xl mx-auto px-5 sm:px-6 py-10 sm:py-12">
      <article className="bg-white border border-gray-100 rounded-2xl shadow-xs p-6 sm:p-10 space-y-8">
        <header>
          <p className="eyebrow">About CyberMeters</p>
          <h1 className="text-3xl sm:text-4xl font-bold mt-3 tracking-tight">Built to show what anyone can see of your business from the outside.</h1>
          <p className="text-gray-600 mt-4 leading-relaxed">CyberMeters helps you understand your external security, choose the next useful action and keep a record of what changed.</p>
        </header>
        <section className="space-y-3" aria-labelledby="founder-heading">
          <h2 id="founder-heading" className="text-xl font-bold">The founder: Turhan Acar</h2>
          <p className="text-sm text-gray-600 leading-relaxed">Turhan Acar holds CompTIA Security+ and CySA+. Before CyberMeters, Turhan worked in airport security on document and fraud checks.</p>
          <p className="text-sm text-gray-600 leading-relaxed">Turhan built CyberMeters to show small businesses and MSPs what is visible about them from the outside, with the evidence behind every finding.</p>
        </section>
        <section className="space-y-3" aria-labelledby="approach-heading">
          <h2 id="approach-heading" className="text-xl font-bold">Clear evidence, practical next steps</h2>
          <p className="text-sm text-gray-600 leading-relaxed">You need to know what was observed, why it matters and what to do next. CyberMeters keeps missing evidence visible, separates an attempted fix from a verified outcome and lets agencies manage clients in separate workspaces.</p>
          <p className="text-sm text-gray-600 leading-relaxed">We use CyberMeters on our own domain. The dated result and its limitations are published on our Trust &amp; Security page, including the checks that could not be completed.</p>
          <Link to="/trust" className="inline-flex items-center gap-2 text-brand-700 font-semibold text-sm">See our own-domain check</Link>
        </section>
        <section className="space-y-3" aria-labelledby="contact-heading">
          <h2 id="contact-heading" className="text-xl font-bold">Get in touch</h2>
          <p className="text-sm text-gray-600 leading-relaxed">Questions about CyberMeters or whether it fits your business? Contact <a href="mailto:hello@cybermeters.com" className="text-brand-700 underline">hello@cybermeters.com</a>.</p>
          <div className="flex flex-wrap gap-3"><Link to="/free-scan" className="btn-primary">Try the free preview</Link><Link to="/support" className="btn-secondary">Support</Link></div>
        </section>
        <nav aria-label="About page links" className="flex flex-wrap gap-x-5 gap-y-2 text-xs text-gray-500 border-t border-gray-100 pt-5"><Link to="/">Home</Link><Link to="/trust">Trust &amp; Security</Link><Link to="/privacy">Privacy</Link><Link to="/terms">Terms</Link><Link to="/dpa">DPA</Link></nav>
      </article>
    </main>
    <PublicSiteFooter />
  </div>
}
