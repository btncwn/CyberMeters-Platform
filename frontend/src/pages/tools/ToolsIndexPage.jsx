import { Link } from 'react-router-dom'
import PublicSiteFooter from '../../components/PublicSiteFooter'
import PublicSiteHeader from '../../components/PublicSiteHeader'

const TOOLS = [
  {
    to: '/tools/dmarc-checker',
    name: 'DMARC checker',
    summary: 'Whether your domain asks receivers to refuse forged email that uses it, where your reports go, and the next record to publish on the way to p=reject.',
    checks: ['RFC 9989 (DMARCbis) policy discovery, including sp and np', 'Alignment and every tag explained', 'Authorisation of report addresses outside your domain'],
  },
  {
    to: '/tools/spf-checker',
    name: 'SPF checker',
    summary: 'The full include tree, the 10-lookup limit, and a corrected record when something breaks SPF.',
    checks: ['DNS lookups and lookups with no answer, against the limits', 'Duplicate records, includes that point at nothing, loops', 'What +all, ?all, ~all and -all mean for you'],
  },
  {
    to: '/tools/security-headers-checker',
    name: 'Security headers checker',
    summary: 'Which of the six browser security headers your website sends, what each one protects against, and the lines to add.',
    checks: ['HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy', 'Weak values, judged by the same rules as the full scan', 'Ready-to-paste lines for nginx, Apache and Cloudflare'],
  },
  {
    to: '/tools/ssl-checker',
    name: 'SSL/TLS certificate checker',
    summary: 'The certificate your website presents: who issued it, when it expires, which names it covers and whether browsers trust it.',
    checks: ['Expiry, with a warning two weeks ahead', 'Name match and browser trust', 'Plainly says it does not check revocation'],
  },
  {
    to: '/tools/lookalike-domain-checker',
    name: 'Lookalike domain checker',
    summary: 'Which close variants of your domain are registered, point at a server or can receive email.',
    checks: ['Typos, look-alike letters and letters from other alphabets', 'Your name with words such as login, and on other endings', 'Registered, points at a server, receives email: what DNS shows, nothing more'],
  },
  {
    to: '/cyber-essentials-readiness',
    name: 'Cyber Essentials self-check',
    summary: 'Twenty questions across the five Cyber Essentials control areas, showing where your business may need work before you apply.',
    checks: ['Firewalls, secure configuration, user access, malware protection and security updates', 'The gaps to review first, area by area', 'Readiness guidance only: it is not a certificate, and your answers are not saved'],
  },
]

export default function ToolsIndexPage() {
  return (
    <div className="min-h-screen bg-gray-50 text-gray-900">
      <PublicSiteHeader />
      <main className="max-w-4xl mx-auto px-4 sm:px-6 py-10 sm:py-12 space-y-8">
        <header className="space-y-3">
          <p className="eyebrow">Free tools</p>
          <h1 className="text-3xl sm:text-4xl font-bold tracking-tight">Free security checks</h1>
          <p className="text-gray-600 leading-relaxed max-w-2xl">Each tool checks one thing properly from public information, says plainly what it could not check, and gives you the exact record or lines to fix it. No sign-up, and the domain you check is not saved.</p>
        </header>
        <ul className="grid md:grid-cols-2 gap-5">
          {TOOLS.map((tool) => (
            <li key={tool.to} className="rounded-2xl border border-gray-100 bg-white shadow-xs p-6 flex flex-col gap-4">
              <div className="space-y-2">
                <h2 className="text-xl font-bold"><Link to={tool.to} className="cm-rowlink">{tool.name}</Link></h2>
                <p className="text-sm text-gray-600 leading-relaxed">{tool.summary}</p>
              </div>
              <ul className="list-disc pl-5 text-sm text-gray-700 space-y-1">{tool.checks.map((c) => <li key={c}>{c}</li>)}</ul>
              <Link to={tool.to} className="btn-primary self-start mt-auto">Open the {tool.name}</Link>
            </li>
          ))}
        </ul>
        <section className="rounded-2xl border border-gray-100 bg-white p-6 space-y-3">
          <h2 className="text-lg font-bold">Want the whole picture?</h2>
          <p className="text-sm text-gray-600">The free check looks at your domain's DNS, HTTPS, website headers, email authentication and technology signals in one go.</p>
          <Link to="/free-scan" className="btn-secondary inline-flex">Run the free check</Link>
        </section>
      </main>
      <PublicSiteFooter />
    </div>
  )
}
