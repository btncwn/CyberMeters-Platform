import { AlertCircle } from 'lucide-react'

export default function ErrorAlert({ message, onRetry }) {
  return (
    <div className="rounded-xl border border-red-100 bg-red-50 p-4 flex items-start gap-3">
      <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
      <div className="flex-1 min-w-0">
        <p className="text-red-800 text-sm font-bold">Request failed</p>
        <p className="text-red-500 text-xs mt-0.5 mono">{message}</p>
      </div>
      {onRetry && (
        <button
          onClick={onRetry}
          className="text-xs text-red-600 hover:text-red-800 font-semibold underline underline-offset-2 flex-shrink-0"
        >
          Retry
        </button>
      )}
    </div>
  )
}
