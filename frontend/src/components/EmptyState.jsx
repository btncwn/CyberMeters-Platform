export default function EmptyState({ title, description, action }) {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-center px-6">
      <h3 className="text-gray-900 font-bold text-base mb-1">{title}</h3>
      {description && <p className="text-gray-400 text-sm mb-5 max-w-xs leading-relaxed">{description}</p>}
      {action}
    </div>
  )
}
