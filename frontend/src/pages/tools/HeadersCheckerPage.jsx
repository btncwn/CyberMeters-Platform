import FreeToolPage from '../../components/tools/FreeToolPage'
import HeadersDetails from '../../components/tools/HeadersDetails'

const ABOUT = (
  <section aria-labelledby="headers-about-heading" className="rounded-2xl border border-gray-100 bg-white p-5 sm:p-6 space-y-3 text-sm text-gray-700 leading-relaxed">
    <h2 id="headers-about-heading" className="text-lg font-bold text-gray-900">How this check works</h2>
    <p>It requests your home page once over HTTPS, the way a browser does, and reads only the response headers. It never reads the page itself, never logs in and never sends anything to your forms.</p>
    <p>Each header is judged by the same rules as the CyberMeters full scan: HSTS needs at least 180 days, X-Content-Type-Options must be nosniff, a Content-Security-Policy with unsafe-inline, unsafe-eval or * for scripts counts as weak, and frame-ancestors in the CSP counts in place of X-Frame-Options.</p>
    <p>If the site answers with a bot check, a consent page or an error, those are not your site's real headers, so the result says it could not check rather than calling them missing.</p>
  </section>
)

export default function HeadersCheckerPage() {
  return (
    <FreeToolPage
      tool="headers"
      toolName="security headers"
      title="Security headers checker"
      intro="See which of the six browser security headers your website sends, what each one protects against, and the exact lines to add for nginx, Apache or Cloudflare."
      Details={HeadersDetails}
      about={ABOUT}
    />
  )
}
