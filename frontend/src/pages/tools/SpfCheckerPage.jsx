import FreeToolPage from '../../components/tools/FreeToolPage'
import SpfDetails from '../../components/tools/SpfDetails'

const ABOUT = (
  <section aria-labelledby="spf-about-heading" className="rounded-2xl border border-gray-100 bg-white p-5 sm:p-6 space-y-3 text-sm text-gray-700 leading-relaxed">
    <h2 id="spf-about-heading" className="text-lg font-bold text-gray-900">How this check works</h2>
    <p>It evaluates your record the way RFC 7208 says a receiving server does: it follows every include and redirect, counts the DNS lookups against the limit of 10 and the lookups with no answer against the limit of 2, and stops where a receiver would stop.</p>
    <p>It finds duplicate records, includes that point at nothing, loops, and +all or ?all, and writes a corrected record you can paste. When a fix needs your judgement, such as which service to drop to get under 10 lookups, it shows the cost of each include instead of guessing.</p>
    <p>Parts of a record that depend on each message (exists, ptr, macros) cannot be resolved in advance; the result says so rather than counting them as checked.</p>
  </section>
)

export default function SpfCheckerPage() {
  return (
    <FreeToolPage
      tool="spf"
      toolName="SPF"
      title="SPF checker"
      intro="See the full include tree behind your SPF record, how many of the 10 DNS lookups it uses, and a corrected record if anything breaks it."
      Details={SpfDetails}
      about={ABOUT}
    />
  )
}
