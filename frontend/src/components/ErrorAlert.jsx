export default function ErrorAlert({ message, title = 'Something went wrong', onRetry, retryLabel = 'Retry' }) {
  return (
    // Column on mobile so the action never crowds/overlaps the wrapped message;
    // row on larger screens keeps the action aligned to the top-right.
    <div className="rounded-xl border border-red-100 bg-red-50 p-4 flex flex-col sm:flex-row sm:items-start gap-3">
      <div className="flex items-start gap-3 flex-1 min-w-0">
        <div className="min-w-0">
          <p className="text-red-800 text-sm font-bold">{title}</p>
          {message && <p className="text-red-600 text-xs mt-0.5 wrap-break-word">{message}</p>}
        </div>
      </div>
      {onRetry && (
        <button
          onClick={onRetry}
          className="self-start sm:self-auto shrink-0 text-xs text-red-700 hover:text-red-900 font-semibold underline underline-offset-2"
        >
          {retryLabel}
        </button>
      )}
    </div>
  )
}
