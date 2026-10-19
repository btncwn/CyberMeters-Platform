import DmarcDetails from '../../components/tools/DmarcDetails'
import FreeToolPage from '../../components/tools/FreeToolPage'

const ABOUT = (
  <section aria-labelledby="dmarc-about-heading" className="rounded-2xl border border-gray-100 bg-white p-5 sm:p-6 space-y-3 text-sm text-gray-700 leading-relaxed">
    <h2 id="dmarc-about-heading" className="text-lg font-bold text-gray-900">How this check works</h2>
    <p>It follows RFC 9989, the current DMARC standard (DMARCbis). When a subdomain has no record of its own it walks up the DNS tree to the organisational domain, then applies sp, or np for a subdomain that does not exist.</p>
    <p>It reads every tag, explains the defaults, and flags pct, which RFC 9989 removed. For each aggregate-report address outside your domain it checks the authorisation record that the receiving side must publish; without it, receivers following the standard do not send the reports.</p>
    <p>It never treats a lookup that failed as a missing record, and it confirms the answer with a second DNS resolver where it can.</p>
  </section>
)

export default function DmarcCheckerPage() {
  return (
    <FreeToolPage
      tool="dmarc"
      toolName="DMARC"
      title="DMARC checker"
      intro="Check whether your domain tells receiving mail servers to refuse forged email that uses your name, where your DMARC reports go, and the exact record to publish next."
      Details={DmarcDetails}
      about={ABOUT}
    />
  )
}
