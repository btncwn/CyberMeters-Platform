import FreeToolPage from '../../components/tools/FreeToolPage'
import SslDetails from '../../components/tools/SslDetails'

const ABOUT = (
  <section aria-labelledby="ssl-about-heading" className="rounded-2xl border border-gray-100 bg-white p-5 sm:p-6 space-y-3 text-sm text-gray-700 leading-relaxed">
    <h2 id="ssl-about-heading" className="text-lg font-bold text-gray-900">How this check works</h2>
    <p>It looks up your domain, picks one public address and makes one secure connection to port 443, the way a browser does. It records the certificate the server presents, whether it covers your name, whether it chains to an authority browsers trust, and which TLS version was agreed.</p>
    <p>It does not check whether the certificate has been revoked, and the chain it shows is the one it built from its own trust store, not necessarily what your server sends. It makes no other connections and sends nothing to your site.</p>
    <p>If nothing answers, or the checker is busy, the result says so and concludes nothing about your certificate.</p>
  </section>
)

export default function SslCheckerPage() {
  return (
    <FreeToolPage
      tool="ssl"
      toolName="SSL/TLS"
      title="SSL/TLS certificate checker"
      intro="See the certificate your website presents: who issued it, when it expires, which names it covers, and whether browsers trust it."
      Details={SslDetails}
      about={ABOUT}
    />
  )
}
