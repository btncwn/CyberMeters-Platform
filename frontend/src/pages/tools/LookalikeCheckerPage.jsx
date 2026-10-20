import FreeToolPage from '../../components/tools/FreeToolPage'
import LookalikeDetails from '../../components/tools/LookalikeDetails'

const ABOUT = (
  <section aria-labelledby="lookalike-about-heading" className="rounded-2xl border border-gray-100 bg-white p-5 sm:p-6 space-y-3 text-sm text-gray-700 leading-relaxed">
    <h2 id="lookalike-about-heading" className="text-lg font-bold text-gray-900">How this check works</h2>
    <p>It makes the same close variants of your name that CyberMeters Brand Protection watches: one letter missing, doubled or swapped, a neighbouring key, look-alike characters and letters from other alphabets, your name with words such as login or support, and your name on other endings such as .com, .co.uk or .io.</p>
    <p>For each one it asks public DNS three things: does the name exist, does it point at a server, and does it accept email. It opens no website and sends no email.</p>
    <p>A registered lookalike is not proof of anything. Many are parked, held by resellers, or registered by the business itself to protect its name. The result says what DNS shows and leaves the judgement to you.</p>
  </section>
)

export default function LookalikeCheckerPage() {
  return (
    <FreeToolPage
      tool="lookalike"
      toolName="lookalike domains"
      title="Lookalike domain checker"
      intro="See which close variants of your domain are registered, which point at a server and which can receive email: the names someone could use to look like you."
      Details={LookalikeDetails}
      about={ABOUT}
    />
  )
}
