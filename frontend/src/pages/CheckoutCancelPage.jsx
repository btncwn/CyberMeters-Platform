import { Link } from 'react-router-dom'

export default function CheckoutCancelPage() {
  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
      <div className="max-w-lg w-full bg-white border border-gray-100 rounded-2xl shadow-card-md p-8 text-center">
        <h1 className="text-2xl font-bold text-gray-900">Checkout cancelled</h1>
        <p className="text-sm text-gray-500 mt-3">
          No changes were made to your subscription. You can restart checkout when you are ready.
        </p>
        <div className="mt-7 flex flex-col sm:flex-row gap-3 justify-center">
          <Link to="/pricing" className="btn-primary justify-center">Back to Pricing</Link>
          <Link to="/billing" className="btn-secondary justify-center">View Billing</Link>
        </div>
      </div>
    </div>
  )
}
