import { Link, useSearchParams } from 'react-router-dom'
import { CheckCircle2, CreditCard } from 'lucide-react'

export default function CheckoutSuccessPage() {
  const [params] = useSearchParams()
  const sessionId = params.get('session_id')

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
      <div className="max-w-lg w-full bg-white border border-gray-100 rounded-2xl shadow-card-md p-8 text-center">
        <div className="w-12 h-12 rounded-full bg-green-50 flex items-center justify-center mx-auto mb-5">
          <CheckCircle2 className="w-7 h-7 text-green-600" />
        </div>
        <h1 className="text-2xl font-bold text-gray-900">Checkout complete</h1>
        <p className="text-sm text-gray-500 mt-3">
          Stripe is confirming your subscription. Your plan will update once the billing webhook has synchronized.
        </p>
        {sessionId && (
          <p className="mt-4 text-xs text-gray-400 font-mono break-all">Session: {sessionId}</p>
        )}
        <div className="mt-7 flex flex-col sm:flex-row gap-3 justify-center">
          <Link to="/billing" className="btn-primary justify-center">
            <CreditCard className="w-4 h-4" />
            View Billing
          </Link>
          <Link to="/dashboard" className="btn-secondary justify-center">Go to Dashboard</Link>
        </div>
      </div>
    </div>
  )
}
