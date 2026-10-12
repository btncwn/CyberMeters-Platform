import { Link, useSearchParams } from 'react-router-dom'

export default function CheckoutSuccessPage() {
  const [params] = useSearchParams()
  const sessionId = params.get('session_id')

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
      <div className="max-w-lg w-full bg-white border border-gray-100 rounded-2xl shadow-card-md p-8 text-center">
        <h1 className="text-2xl font-bold text-gray-900">Checkout complete</h1>
        <p className="text-sm text-gray-500 mt-3">
          Stripe is confirming your subscription. Your plan will update once the billing webhook has synchronized.
        </p>
        {sessionId && (
          <p className="mt-4 text-xs text-gray-400 font-mono break-all">Session: {sessionId}</p>
        )}
        <div className="mt-7 flex flex-col sm:flex-row gap-3 justify-center">
          <Link to="/billing" className="btn-primary justify-center">
            View Billing
          </Link>
          <Link to="/dashboard" className="btn-secondary justify-center">Go to Dashboard</Link>
        </div>
      </div>
    </div>
  )
}
